/*
 * Copyright (C) 2026 the ssh3-c authors
 */

/*
 * D3 unit tests of the output layer: packet build/parse roundtrip on
 * a real UDP socket pair, the Initial datagram padding, the GSO
 * segmentation (or its fallback) and the DATAGRAM need_ack=0
 * invariant (porting map 3.3.1)
 */

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/ssl.h>

#include <s3_nonblocking.h>
#include <s3_quic.h>
#include <s3_quic_connection.h>
#include <s3_quic_output.h>
#include <s3_quic_frames.h>
#include <s3_quic_transport.h>
#include <s3_quic_protection.h>

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
    s3_fd_t               peer_fd; /* the socket the output is sent to */
} s3_test_out_env_t;

static s3_fd_t
s3_test_udp_socket(struct sockaddr_in *sa)
{
    s3_fd_t fd;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        return -1;
    }

    if (s3_nonblocking(fd) != S3_OK) {
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
s3_test_env_init(s3_test_out_env_t *env)
{
    s3_str_t           alpn;
    s3_uint_t          i;
    socklen_t          slen;
    struct sockaddr_in sa, conn_sa;

    s3_memzero(env, sizeof(s3_test_out_env_t));

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

    /* the client role: the ssl object is created in s3_quic_connect() */
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

    /* the peer (server) socket */
    env->peer_fd = s3_test_udp_socket(&sa);
    if (env->peer_fd == -1) {
        return S3_ERROR;
    }

    slen = sizeof(sa);

    if (getsockname(env->peer_fd, (struct sockaddr *)&sa, &slen) == -1) {
        return S3_ERROR;
    }

    /* the connection socket is bound to its own port */
    env->conn = s3_get_connection(&env->ctx, s3_test_udp_socket(&conn_sa));
    if (env->conn == NULL || env->conn->fd == -1) {
        return S3_ERROR;
    }

    env->conn->pool = s3_create_pool((size_t)S3_DEFAULT_POOL_SIZE, &s3_test_tls_log);
    if (env->conn->pool == NULL) {
        return S3_ERROR;
    }

    /* the peer address the output is sent to */
    env->conn->sockaddr = (struct sockaddr *)s3_palloc(env->conn->pool, sizeof(sa));
    if (env->conn->sockaddr == NULL) {
        return S3_ERROR;
    }

    s3_memcpy(env->conn->sockaddr, &sa, sizeof(sa));
    env->conn->socklen = sizeof(sa);

    return S3_OK;
}

static void
s3_test_env_done(s3_test_out_env_t *env)
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
 * seeds the application write keys and the peer datagram limit that
 * a real handshake would deliver: the unit test has no server
 */
static void
s3_test_seed_app(s3_test_out_env_t *env)
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

    env->qc->ctp.max_datagram_frame_size = 1200;
}

/*
 * parses the first packet of a received datagram; the raw cursor
 * starts after the flags byte, like s3_quic_handle_datagram() does
 */
static s3_int_t
s3_test_parse(u_char *buf, ssize_t n, s3_quic_header_t *pkt)
{
    s3_memzero(pkt, sizeof(s3_quic_header_t));

    pkt->log = &s3_test_tls_log;
    pkt->data = buf;
    pkt->len = (size_t)n;
    pkt->flags = buf[0];
    pkt->raw = &(s3_buf_t){.temporary = 1, .pos = buf + 1, .last = buf + n};

    return s3_quic_parse_packet(pkt);
}

static int
test_datagram_roundtrip(void)
{
    s3_test_out_env_t env;
    ssize_t           n;
    u_char            buf[S3_QUIC_MAX_UDP_PAYLOAD_SIZE];
    u_char            payload[7] = "dg-test";
    s3_quic_header_t  pkt;

    S3_ASSERT(s3_test_env_init(&env) == S3_OK);
    S3_ASSERT(s3_quic_connect(env.conn, &env.conf) == S3_OK);

    env.qc = s3_quic_get_connection(env.conn);
    S3_ASSERT(env.qc != NULL);

    /* flush the pending ClientHello into packets */
    S3_ASSERT(s3_quic_output(env.conn) == S3_OK);

    S3_ASSERT(env.qc->send_ctx[0].pnum >= 1);

    s3_test_seed_app(&env);

    n = recv(env.peer_fd, buf, sizeof(buf), MSG_DONTWAIT);
    S3_ASSERT(n == S3_QUIC_MIN_INITIAL_SIZE);
    S3_ASSERT(s3_test_parse(buf, n, &pkt) == S3_OK);
    S3_ASSERT(pkt.level == S3_QUIC_ENCRYPTION_INITIAL);

    /* the rest of the handshake flight */
    do {
        n = recv(env.peer_fd, buf, sizeof(buf), MSG_DONTWAIT);
    } while (n > 0);

    /* the DATAGRAM frame goes out in a 1-RTT packet */
    S3_ASSERT(s3_quic_send_datagram(env.conn, payload, sizeof(payload)) == S3_OK);
    S3_ASSERT(s3_quic_output(env.conn) == S3_OK);

    /* the queued frame is gone */
    S3_ASSERT(s3_queue_empty(&env.qc->send_ctx[2].frames));

    n = recv(env.peer_fd, buf, sizeof(buf), MSG_DONTWAIT);
    S3_ASSERT(n > 0);
    S3_ASSERT(s3_test_parse(buf, n, &pkt) == S3_OK);
    S3_ASSERT(pkt.level == S3_QUIC_ENCRYPTION_APPLICATION);
    /* the frame overhead (type + varint length) plus the payload */
    S3_ASSERT(n >= (ssize_t)(sizeof(payload) + 4));

    s3_test_env_done(&env);

    return s3_test_failures;
}

static int
test_need_ack_not_tracked(void)
{
    s3_test_out_env_t env;
    s3_quic_frame_t  *f;
    size_t            in_flight;
    u_char            payload[4] = {1, 2, 3, 4};

    S3_ASSERT(s3_test_env_init(&env) == S3_OK);
    S3_ASSERT(s3_quic_connect(env.conn, &env.conf) == S3_OK);

    env.qc = s3_quic_get_connection(env.conn);

    /* flush the handshake flight first */
    S3_ASSERT(s3_quic_output(env.conn) == S3_OK);

    s3_test_seed_app(&env);

    in_flight = env.qc->congestion.in_flight;

    /* the DATAGRAM frame is not ack-eliciting */
    S3_ASSERT(s3_quic_send_datagram(env.conn, payload, sizeof(payload)) == S3_OK);
    S3_ASSERT(s3_quic_output(env.conn) == S3_OK);

    /*
     * porting map 3.3.1: a frame with need_ack == 0 is freed on commit,
     * it does not live in ctx->sent and is not counted in_flight
     */
    S3_ASSERT(s3_queue_empty(&env.qc->send_ctx[2].sent));
    S3_ASSERT(env.qc->congestion.in_flight == in_flight);

    /* an ack-eliciting PING is tracked */
    f = s3_quic_alloc_frame(env.conn);
    S3_ASSERT(f != NULL);

    f->level = S3_QUIC_ENCRYPTION_APPLICATION;
    f->type = S3_QUIC_FT_PING;

    s3_quic_queue_frame(env.qc, f);
    S3_ASSERT(s3_quic_output(env.conn) == S3_OK);

    S3_ASSERT(!s3_queue_empty(&env.qc->send_ctx[2].sent));
    S3_ASSERT(env.qc->congestion.in_flight > 0);

    s3_test_env_done(&env);

    return s3_test_failures;
}

static int
test_gso_segments(void)
{
    s3_test_out_env_t env;
    s3_uint_t         i;
    ssize_t           n, total;
    uint64_t          in_flight;
    u_char            buf[65536];

    S3_ASSERT(s3_test_env_init(&env) == S3_OK);
    S3_ASSERT(s3_quic_connect(env.conn, &env.conf) == S3_OK);

    env.qc = s3_quic_get_connection(env.conn);
#if (S3_HAVE_UDP_SEGMENT)
    env.qc->conf->gso_enabled = 1;
#endif

    /* flush and drop the handshake flight */
    S3_ASSERT(s3_quic_output(env.conn) == S3_OK);

    s3_test_seed_app(&env);

    do {
        n = recv(env.peer_fd, buf, sizeof(buf), MSG_DONTWAIT);
    } while (n > 0);

    /*
     * queue enough application frames to satisfy the batching
     * threshold (~3 mtu) and lift the congestion window, like a bulk
     * send after path validation
     */
    env.qc->congestion.window = (size_t)-1 >> 1;

    for (i = 0; i < 3000; i++) {
        s3_quic_frame_t *f = s3_quic_alloc_frame(env.conn);
        S3_ASSERT(f != NULL);

        f->level = S3_QUIC_ENCRYPTION_APPLICATION;
        f->type = S3_QUIC_FT_PING;

        s3_quic_queue_frame(env.qc, f);
    }

    in_flight = env.qc->congestion.in_flight;

    S3_ASSERT(s3_quic_output(env.conn) == S3_OK);

    /* the frames moved through sending into sent */
    S3_ASSERT(!s3_queue_empty(&env.qc->send_ctx[2].sent));
    S3_ASSERT(s3_queue_empty(&env.qc->send_ctx[2].frames));
    S3_ASSERT(env.qc->send_ctx[2].pnum >= 3);

    /* the bytes arrived at the peer */
    total = 0;

    do {
        n = recv(env.peer_fd, buf, sizeof(buf), MSG_DONTWAIT);

        if (n > 0) {
            total += n;
        }

    } while (n > 0);

    S3_ASSERT(total == (ssize_t)(env.qc->congestion.in_flight - in_flight));

    s3_test_env_done(&env);

    return s3_test_failures;
}

static int
s3_test_quic_output(void)
{
    test_datagram_roundtrip();
    test_need_ack_not_tracked();
    test_gso_segments();

    OPENSSL_cleanup();

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_quic_output)
