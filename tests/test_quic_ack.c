/*
 * Copyright (C) 2026 the ssh3-c authors
 */

/*
 * D3 unit tests of the ack layer: the ACK ranges bookkeeping, the
 * frame removal and congestion accounting on ACK, and the loss
 * detection retransmitting crypto data on the time threshold
 * (porting map 1.7)
 */

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/ssl.h>

#include <s3_quic.h>
#include <s3_quic_connection.h>
#include <s3_quic_output.h>
#include <s3_quic_ack.h>
#include <s3_quic_frames.h>

#define S3_TEST_TLS_NO_LOCKSTEP
#define S3_TEST_TLS_NO_CLIENT
#define S3_TEST_TLS_NO_CERT
#include "s3_quic_tls_helper.h"
#include "s3_test.h"

typedef struct {
    s3_pool_t            *pool;
    s3_event_ctx_t        ctx;
    s3_quic_conf_t        conf;
    s3_connection_t      *conn;
    s3_quic_connection_t *qc;
    s3_fd_t               peer_fd;
} s3_test_ack_env_t;

static s3_fd_t
s3_test_udp_socket(struct sockaddr_in *sa)
{
    s3_fd_t fd;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        return -1;
    }

    s3_memzero(sa, sizeof(*sa));
    sa->sin_family = AF_INET;
    sa->sin_port = 0;
    sa->sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(fd, (struct sockaddr *)sa, sizeof(*sa)) == -1) {
        close(fd);
        return -1;
    }

    return fd;
}

static s3_int_t
s3_test_env_init(s3_test_ack_env_t *env)
{
    s3_str_t           alpn;
    s3_uint_t          i;
    socklen_t          slen;
    struct sockaddr_in sa, conn_sa;

    s3_memzero(env, sizeof(s3_test_ack_env_t));

    s3_test_tls_log_init();

    env->pool = s3_create_pool((size_t)S3_DEFAULT_POOL_SIZE, &s3_test_tls_log);
    if (env->pool == NULL) {
        return S3_ERROR;
    }

    s3_memzero(&env->ctx, sizeof(s3_event_ctx_t));
    env->ctx.log = &s3_test_tls_log;
    env->ctx.pool = env->pool;
    s3_queue_init(&env->ctx.posted_events);

    if (s3_event_timer_init(&env->ctx) != S3_OK) {
        return S3_ERROR;
    }

    alpn.data = (u_char *)"\x04ssh3";
    alpn.len = 5;

    env->conf.ssl = s3_ssl_client_create(&s3_test_tls_log, &alpn);
    if (env->conf.ssl == NULL) {
        return S3_ERROR;
    }

    env->conf.ctx = &env->ctx;
    env->conf.handshake_timeout = 10000;
    env->conf.idle_timeout = 60000;
    env->conf.stream_buffer_size = 16384;
    env->conf.max_concurrent_streams_bidi = 16;
    env->conf.max_concurrent_streams_uni = 16;
    env->conf.active_connection_id_limit = 8;
    env->conf.max_datagram_frame_size = 1200;

    for (i = 0; i < S3_QUIC_AV_KEY_LEN; i++) {
        env->conf.av_token_key[i] = (u_char)(0xc0 + i);
        env->conf.sr_token_key[i] = (u_char)(0xd0 + i);
    }

    env->peer_fd = s3_test_udp_socket(&sa);
    if (env->peer_fd == -1) {
        return S3_ERROR;
    }

    slen = sizeof(sa);

    if (getsockname(env->peer_fd, (struct sockaddr *)&sa, &slen) == -1) {
        return S3_ERROR;
    }

    env->conn = s3_get_connection(&env->ctx, s3_test_udp_socket(&conn_sa));
    if (env->conn == NULL || env->conn->fd == -1) {
        return S3_ERROR;
    }

    env->conn->pool = s3_create_pool((size_t)S3_DEFAULT_POOL_SIZE, &s3_test_tls_log);
    if (env->conn->pool == NULL) {
        return S3_ERROR;
    }

    env->conn->sockaddr = (struct sockaddr *)s3_palloc(env->conn->pool, sizeof(sa));
    if (env->conn->sockaddr == NULL) {
        return S3_ERROR;
    }

    s3_memcpy(env->conn->sockaddr, &sa, sizeof(sa));
    env->conn->socklen = sizeof(sa);

    return S3_OK;
}

static void
s3_test_env_done(s3_test_ack_env_t *env)
{
    s3_quic_connection_t *qc;

    qc = (env->conn != NULL) ? s3_quic_get_connection(env->conn) : NULL;

    if (qc != NULL) {

        if (qc->close.timer_set) {
            s3_event_del_timer(&qc->close);
        }

        if (qc->push.timer_set) {
            s3_event_del_timer(&qc->push);
        }

        if (qc->pto.timer_set) {
            s3_event_del_timer(&qc->pto);
        }

        if (qc->push.posted) {
            s3_delete_posted_event(&qc->push);
        }

        if (qc->key_update.posted) {
            s3_delete_posted_event(&qc->key_update);
        }

        s3_quic_close_sockets(env->conn);

        if (env->conn->ssl != NULL) {
            SSL_free(env->conn->ssl->connection);
            env->conn->ssl = NULL;
        }

        s3_quic_keys_cleanup(qc->keys);

        s3_close_connection(env->conn);
    }

    if (env->conf.ssl != NULL) {
        s3_ssl_free(env->conf.ssl);
        env->conf.ssl = NULL;
    }

    if (env->peer_fd != -1) {
        (void)close(env->peer_fd);
    }

    if (env->pool != NULL) {
        s3_destroy_pool(env->pool);
        env->pool = NULL;
    }
}

/*
 * seeds the application write keys that a real handshake would
 * derive: the unit test has no server
 */
static void
s3_test_seed_app(s3_test_ack_env_t *env)
{
    static uint8_t secret[32];
    s3_uint_t      i;

    for (i = 0; i < 32; i++) {
        secret[i] = (uint8_t)(0x11 * (i + 1));
    }

    S3_ASSERT(s3_quic_keys_set_encryption_secret(&s3_test_tls_log, 1, env->qc->keys,
                                                 S3_QUIC_ENCRYPTION_APPLICATION,
                                                 TLS1_3_CK_AES_128_GCM_SHA256, secret,
                                                 sizeof(secret)) == S3_OK);
}

/*
 * an ACK frame with a single range [largest - first_range, largest]
 */
static s3_int_t
s3_test_ack_frame(uint64_t largest, uint64_t first_range, uint64_t delay, s3_quic_frame_t *frame)
{
    u_char buf[256];

    s3_memzero(frame, sizeof(s3_quic_frame_t));

    frame->type = S3_QUIC_FT_ACK;
    frame->u.ack.largest = largest;
    frame->u.ack.delay = delay;
    frame->u.ack.range_count = 0;
    frame->u.ack.first_range = first_range;

    frame->len = (ssize_t)s3_quic_create_frame(buf, frame);

    return frame->len > 0 ? S3_OK : S3_ERROR;
}

static int
test_ack_ranges(void)
{
    s3_test_ack_env_t    env;
    s3_quic_frame_t     *f, ack;
    s3_quic_header_t     pkt;
    s3_quic_send_ctx_t  *ctx;
    uint64_t             pnums[5];
    size_t               in_flight;
    s3_uint_t            i;

    S3_ASSERT(s3_test_env_init(&env) == S3_OK);
    S3_ASSERT(s3_quic_connect(env.conn, &env.conf) == S3_OK);

    env.qc = s3_quic_get_connection(env.conn);
    ctx = &env.qc->send_ctx[2];

    /* flush the handshake flight */
    S3_ASSERT(s3_quic_output(env.conn) == S3_OK);

    s3_test_seed_app(&env);

    in_flight = env.qc->congestion.in_flight;

    /*
     * send five packets with pnum 0..4 in the application space via
     * the single-frame sendto path
     */
    for (i = 0; i < 5; i++) {
        f = s3_quic_alloc_frame(env.conn);
        S3_ASSERT(f != NULL);

        f->level = S3_QUIC_ENCRYPTION_APPLICATION;
        f->type = S3_QUIC_FT_PING;

        S3_ASSERT(s3_quic_frame_sendto(env.conn, f, 0, env.qc->path) == S3_OK);

        pnums[i] = ctx->pnum - 1;
    }

    S3_ASSERT(env.qc->congestion.in_flight > 0);

    /* ack the even packet numbers: an out-of-order ACK bookkeeping */
    for (i = 1; i < 5; i += 2) {

        s3_memzero(&pkt, sizeof(s3_quic_header_t));
        pkt.log = &s3_test_tls_log;
        pkt.level = S3_QUIC_ENCRYPTION_APPLICATION;

        S3_ASSERT(s3_test_ack_frame(pnums[i], 0, 0, &ack) == S3_OK);
        S3_ASSERT(s3_quic_handle_ack_frame(env.conn, &pkt, &ack) == S3_OK);
    }

    /* the acked frames left the sent queue */
    S3_ASSERT(s3_queue_empty(&ctx->sent) == 0);

    /* the largest acknowledged packet number moved */
    S3_ASSERT(ctx->largest_ack == pnums[3]);

    /* an RTT sample was taken on the new largest ack */
    S3_ASSERT(env.qc->min_rtt != S3_TIMER_INFINITE);

    /* ack the remaining packets */
    for (i = 0; i < 5; i += 2) {

        s3_memzero(&pkt, sizeof(s3_quic_header_t));
        pkt.log = &s3_test_tls_log;
        pkt.level = S3_QUIC_ENCRYPTION_APPLICATION;

        S3_ASSERT(s3_test_ack_frame(pnums[i], 0, 0, &ack) == S3_OK);
        S3_ASSERT(s3_quic_handle_ack_frame(env.conn, &pkt, &ack) == S3_OK);
    }

    /* everything is ack'ed: the queue is empty, the window is back to
     * the pre-PING level (the unacked handshake flight is still
     * accounted) */
    S3_ASSERT(s3_queue_empty(&ctx->sent));
    S3_ASSERT(env.qc->congestion.in_flight == in_flight);

    /* an ACK for a packet that was never sent is a protocol violation */
    s3_memzero(&pkt, sizeof(s3_quic_header_t));
    pkt.log = &s3_test_tls_log;
    pkt.level = S3_QUIC_ENCRYPTION_APPLICATION;

    S3_ASSERT(s3_test_ack_frame(ctx->pnum + 10, 0, 0, &ack) == S3_OK);
    S3_ASSERT(s3_quic_handle_ack_frame(env.conn, &pkt, &ack) == S3_ERROR);
    S3_ASSERT(env.qc->error == S3_QUIC_ERR_PROTOCOL_VIOLATION);

    s3_test_env_done(&env);

    return s3_test_failures;
}

static int
test_loss_retransmit(void)
{
    s3_test_ack_env_t   env;
    s3_quic_header_t    pkt;
    s3_quic_send_ctx_t *ctx;
    ssize_t             n, crypto_bytes;
    uint64_t            base_pnum;
    u_char              buf[S3_QUIC_MAX_UDP_PAYLOAD_SIZE];

    S3_ASSERT(s3_test_env_init(&env) == S3_OK);
    S3_ASSERT(s3_quic_connect(env.conn, &env.conf) == S3_OK);

    env.qc = s3_quic_get_connection(env.conn);
    ctx = &env.qc->send_ctx[0]; /* the initial space */

    /*
     * the ClientHello CRYPTO frame is pending; send it, then pretend
     * the datagram was lost by rewinding the send time before the
     * time threshold
     */
    S3_ASSERT(!s3_queue_empty(&ctx->frames));
    S3_ASSERT(s3_quic_output(env.conn) == S3_OK);

    S3_ASSERT(!s3_queue_empty(&ctx->sent));

    base_pnum = ctx->pnum;

    crypto_bytes = 0;

    {
        s3_queue_t      *q;
        s3_quic_frame_t *qf;

        for (q = s3_queue_head(&ctx->sent); q != s3_queue_sentinel(&ctx->sent);
             q = s3_queue_next(q)) {
            qf = s3_queue_data(q, s3_quic_frame_t, queue);
            crypto_bytes += (ssize_t)qf->plen;
        }
    }

    S3_ASSERT(crypto_bytes > 0);

    /* the datagram was lost: the send time is far in the past */
    {
        s3_queue_t      *q;
        s3_quic_frame_t *qf;

        for (q = s3_queue_head(&ctx->sent); q != s3_queue_sentinel(&ctx->sent);
             q = s3_queue_next(q)) {
            qf = s3_queue_data(q, s3_quic_frame_t, queue);
            qf->send_time -= 60000;
        }
    }

    /*
     * a real loss detection always runs after an ACK of the peer: the
     * largest acknowledged packet number and an RTT sample are needed
     * for the time threshold; simulate the covering ACK
     */
    ctx->largest_ack = base_pnum - 1;
    env.qc->first_rtt = s3_current_msec - 1000;

    /* the loss detection moves the frame back into the send queue:
     * the lost timer is armed immediately and its handler runs the
     * detection */
    s3_quic_set_lost_timer(env.conn);
    S3_ASSERT(env.qc->pto.timer_set == 1);
    S3_ASSERT(env.qc->pto.handler != NULL);

    env.qc->pto.handler(&env.qc->pto);

    S3_ASSERT(!s3_queue_empty(&ctx->frames));

    /* drop the original flight, then the retransmission goes out */
    do {
        n = recv(env.peer_fd, buf, sizeof(buf), MSG_DONTWAIT);
    } while (n > 0);

    S3_ASSERT(s3_quic_output(env.conn) == S3_OK);

    n = recv(env.peer_fd, buf, sizeof(buf), MSG_DONTWAIT);
    S3_ASSERT(n == S3_QUIC_MIN_INITIAL_SIZE);

    s3_memzero(&pkt, sizeof(s3_quic_header_t));
    pkt.log = &s3_test_tls_log;
    pkt.data = buf;
    pkt.len = (size_t)n;
    pkt.flags = buf[0];
    pkt.raw = &(s3_buf_t){.temporary = 1, .pos = buf + 1, .last = buf + n};

    S3_ASSERT(s3_quic_parse_packet(&pkt) == S3_OK);
    S3_ASSERT(pkt.level == S3_QUIC_ENCRYPTION_INITIAL);

    /*
     * the packet number is header-protection masked before the
     * decryption, so only the fresh packet number in the send context
     * proves the retransmission
     */
    S3_ASSERT(ctx->pnum > base_pnum);
    S3_ASSERT(!s3_queue_empty(&ctx->sent));

    s3_test_env_done(&env);

    return s3_test_failures;
}

static int
s3_test_quic_ack(void)
{
    test_ack_ranges();
    test_loss_retransmit();

    OPENSSL_cleanup();

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_quic_ack)
