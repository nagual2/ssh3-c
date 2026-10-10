/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#if (S3_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#if (S3_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#endif
#endif
#include <unistd.h>

#define S3_TEST_TLS_NO_LOCKSTEP
#include "s3_quic_tls_helper.h"

#include <s3_nonblocking.h>

/*
 * D2 unit tests of the quic core: s3_quic_run() on a crafted, valid
 * Initial packet carrying a real ClientHello, the DATAGRAM frame
 * delivery and the CONNECTION_CLOSE draining semantics on a 1-RTT
 * packet
 */

static const u_char s3_test_dcid[16] = "s3-dcid-1234567"; /* 16 bytes, no NUL */
static const u_char s3_test_scid[8] = {0x9a, 0x5b, 0x1c, 0xf0, 0x33, 0x44, 0x55, 0x66};
static const u_char s3_test_dg_payload[4] = {0xde, 0xad, 0xbe, 0xef};

static u_char        s3_test_dg_data[64];
static size_t        s3_test_dg_len;
static const u_char *s3_test_dg_ptr;
static size_t        s3_test_dg_links;
static size_t        s3_test_dg_link_size;

static void
s3_test_datagram_handler(s3_connection_t *c, s3_chain_t *data)
{
    s3_chain_t *cl;
    size_t      len;

    (void)c;

    /* record the chain geometry the library handed over */

    s3_test_dg_ptr = data->buf->pos;
    s3_test_dg_link_size = s3_buf_size(data->buf);

    s3_test_dg_links = 0;
    len = 0;

    for (cl = data; cl != NULL; cl = cl->next) {
        s3_memcpy(s3_test_dg_data + len, cl->buf->pos, s3_buf_size(cl->buf));
        len += s3_buf_size(cl->buf);
        s3_test_dg_links++;
    }

    s3_test_dg_len = len;
}

typedef struct {
    s3_pool_t         *pool;
    s3_pool_t         *conn_pool;
    s3_event_ctx_t     ctx;
    s3_quic_conf_t     conf;
    s3_connection_t   *conn;
    s3_test_tls_side_t cli;
    SSL               *client;
    SSL_CTX           *client_ctx;
} s3_test_core_env_t;

static s3_fd_t
s3_test_udp_socket(void)
{
    s3_fd_t            fd;
    struct sockaddr_in sa;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == (s3_fd_t) -1) {
        return -1;
    }

    if (s3_nonblocking(fd) != S3_OK) {
        return -1;
    }

    s3_memzero(&sa, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = 0;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
        s3_test_close(fd);
        return -1;
    }

    return fd;
}

/*
 * the peer address of the connection: the bound loopback address of
 * its own socket, so that the packets the quic layer sends land
 * nowhere instead of failing with EDESTADDRREQ
 */

static s3_int_t
s3_test_core_peer_addr(s3_test_core_env_t *env)
{
    struct sockaddr_in sa;
    socklen_t          len;

    len = sizeof(sa);

    if (getsockname(env->conn->fd, (struct sockaddr *)&sa, &len) == -1) {
        return S3_ERROR;
    }

    env->conn->sockaddr = s3_palloc(env->conn->pool, len);
    if (env->conn->sockaddr == NULL) {
        return S3_ERROR;
    }

    s3_memcpy(env->conn->sockaddr, &sa, len);
    env->conn->socklen = len;

    return S3_OK;
}

static s3_int_t
s3_test_core_env_init(s3_test_core_env_t *env, const u_char *cert, size_t cert_len,
                      const u_char *key, size_t key_len)
{
    s3_str_t  alpn;
    s3_uint_t i;

    s3_memzero(env, sizeof(s3_test_core_env_t));

    env->pool = s3_create_pool((size_t)S3_DEFAULT_POOL_SIZE, &s3_test_tls_log);
    if (env->pool == NULL) {
        return S3_ERROR;
    }

    /* the event context: the posted queue and the timer rbtree */
    s3_memzero(&env->ctx, sizeof(s3_event_ctx_t));
    env->ctx.log = &s3_test_tls_log;
    env->ctx.pool = env->pool;
    s3_queue_init(&env->ctx.posted_events);

    if (s3_event_timer_init(&env->ctx) != S3_OK) {
        return S3_ERROR;
    }

    alpn.data = (u_char *)"\x04ssh3";
    alpn.len = 5;

    env->conf.ssl = s3_ssl_create(&s3_test_tls_log, (const char *)cert, cert_len, (const char *)key,
                                  key_len, &alpn);
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
    env->conf.datagram_handler = s3_test_datagram_handler;

    for (i = 0; i < S3_QUIC_AV_KEY_LEN; i++) {
        env->conf.av_token_key[i] = (u_char)(0xc0 + i);
        env->conf.sr_token_key[i] = (u_char)(0xd0 + i);
    }

    /* the connection with its own pool and a real (unused) socket */
    env->conn_pool = s3_create_pool((size_t)S3_DEFAULT_POOL_SIZE, &s3_test_tls_log);
    if (env->conn_pool == NULL) {
        return S3_ERROR;
    }

    env->conn = s3_get_connection(&env->ctx, s3_test_udp_socket());
    if (env->conn == NULL) {
        return S3_ERROR;
    }

    env->conn->pool = env->conn_pool;

    /*
     * the packets are injected into c->buffer directly, so the peer
     * address is set by hand: s3_quic_new_path() takes it from the
     * connection, as the udp layer does before s3_quic_run().  The
     * loopback address of the socket itself is enough, a real peer
     * reads nothing here
     */

    if (s3_test_core_peer_addr(env) != S3_OK) {
        return S3_ERROR;
    }

    return S3_OK;
}

static void
s3_test_core_env_done(s3_test_core_env_t *env)
{
    if (env->client != NULL) {
        SSL_free(env->client);
        env->client = NULL;
    }

    if (env->client_ctx != NULL) {
        SSL_CTX_free(env->client_ctx);
        env->client_ctx = NULL;
    }

    if (env->conf.ssl != NULL) {
        s3_ssl_free(env->conf.ssl);
        env->conf.ssl = NULL;
    }

    /* the server connection ssl is pooled; free the openssl object */
    if (env->conn != NULL && env->conn->ssl != NULL) {
        SSL_free(env->conn->ssl->connection);
        env->conn->ssl = NULL;
    }

    /*
     * the connection is still draining (the close timer is armed), so
     * the quic cleanup that s3_quic_close_connection() would run is
     * done here before the pools die
     */
    if (env->conn != NULL && env->conn->udp != NULL) {
        s3_quic_connection_t *qc = s3_quic_get_connection(env->conn);

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

            s3_quic_keys_cleanup(qc->keys);
        }
    }

    if (env->conn != NULL && env->conn->fd != (s3_fd_t)-1) {
        s3_close_connection(env->conn); /* destroys conn_pool */
        env->conn = NULL;
    }

    if (env->pool != NULL) {
        s3_destroy_pool(env->pool);
        env->pool = NULL;
    }
}

/*
 * a datagram buffer for c->buffer over a ready-made packet
 */
static s3_buf_t *
s3_test_datagram_buf(s3_pool_t *pool, u_char *data, size_t len)
{
    s3_buf_t *b;

    b = s3_pcalloc(pool, sizeof(s3_buf_t));
    if (b == NULL) {
        return NULL;
    }

    b->temporary = 1;
    b->pos = data;
    b->last = data + len;

    return b;
}

/*
 * encrypts a client packet: the protection layer seals packets with
 * the server secret slot, so the client secrets are written there
 */
static s3_int_t
s3_test_seal_packet(s3_quic_header_t *pkt, s3_quic_keys_t *pkt_keys, s3_uint_t level,
                    const uint8_t *secret, size_t secret_len, u_char *res, size_t res_size,
                    size_t *pkt_len)
{
    s3_str_t r;

    s3_memzero(pkt_keys, sizeof(s3_quic_keys_t));

    if (s3_quic_keys_set_encryption_secret(&s3_test_tls_log, 1, pkt_keys, level,
                                           TLS1_3_CK_AES_128_GCM_SHA256, secret,
                                           secret_len) != S3_OK) {
        return S3_ERROR;
    }

    pkt->keys = pkt_keys;

    r.data = res;
    r.len = res_size;

    if (s3_quic_encrypt(pkt, &r) != S3_OK) {
        s3_quic_keys_cleanup(pkt_keys);
        return S3_ERROR;
    }

    *pkt_len = r.len;

    /* the test key material is throwaway */
    s3_quic_keys_cleanup(pkt_keys);

    return S3_OK;
}

static int
test_run_and_close(void)
{
    u_char                cert[4096] = {0}, key[4096] = {0}, tp[64], res[2048], res2[2048];
    u_char                frame_buf[2048], cli_secret[32];
    size_t                cert_len = 0, key_len = 0, tp_len, frame_len, dg_len, pkt_len;
    ssize_t               size;
    s3_str_t              alpn, reason, secret;
    int                   n;
    s3_quic_keys_t        pkt_keys;
    s3_quic_header_t      pkt;
    s3_quic_frame_t       frame;
    s3_chain_t            chain;
    s3_buf_t             *b;
    s3_quic_connection_t *qc;
    s3_quic_socket_t     *qsock;
    s3_quic_send_ctx_t   *ctx;
    static uint8_t        app_secret[32];

    static s3_test_core_env_t env;

    s3_test_tls_log_init();

    S3_ASSERT(s3_test_tls_gen_cert(cert, &cert_len, key, &key_len) == 0);
    S3_ASSERT(s3_test_core_env_init(&env, cert, cert_len, key, key_len) == S3_OK);

    /* the harness client produces a real ClientHello */

    tp_len = s3_test_client_tp(tp, s3_test_scid, sizeof(s3_test_scid));

    alpn.data = (u_char *)"\x04ssh3";
    alpn.len = 5;

    env.client = s3_test_tls_client(&env.cli, &alpn, tp, tp_len, &env.client_ctx);
    S3_ASSERT(env.client != NULL);

    n = SSL_do_handshake(env.client);
    S3_ASSERT(n <= 0 && SSL_get_error(env.client, n) == SSL_ERROR_WANT_READ);
    S3_ASSERT(env.cli.out_len[0] > 0);

    /* build the CRYPTO frame with the ClientHello */

    s3_memzero(&frame, sizeof(s3_quic_frame_t));
    s3_memzero(&chain, sizeof(s3_chain_t));

    chain.buf = &(s3_buf_t){
        .temporary = 1, .pos = env.cli.out[0], .last = env.cli.out[0] + env.cli.out_len[0]};
    frame.type = S3_QUIC_FT_CRYPTO;
    frame.data = &chain;
    frame.u.crypto.offset = 0;
    frame.u.crypto.length = env.cli.out_len[0];

    frame_len = s3_quic_create_frame(frame_buf, &frame);
    S3_ASSERT(frame_len > 0);

    /* the Initial packet sealed with the client initial secret */

    s3_memzero(&pkt_keys, sizeof(s3_quic_keys_t));

    secret.data = (u_char *)s3_test_dcid;
    secret.len = sizeof(s3_test_dcid);

    S3_ASSERT(s3_quic_keys_set_initial_secret(&pkt_keys, &secret, &s3_test_tls_log) == S3_OK);

    /*
     * a client seals its Initial with the client initial secret; the
     * harness below seeds it as the write direction of a server-role
     * key set, so the packet is protected from the server slot
     */
    s3_memcpy(cli_secret, pkt_keys.secrets[S3_QUIC_ENCRYPTION_INITIAL].client.secret.data,
              sizeof(cli_secret));

    s3_quic_keys_cleanup(&pkt_keys);

    s3_memzero(&pkt, sizeof(s3_quic_header_t));
    pkt.log = &s3_test_tls_log;
    pkt.flags = 0xc0; /* long, fixed, Initial, pn len 1 */
    pkt.version = 1;
    pkt.level = S3_QUIC_ENCRYPTION_INITIAL;
    pkt.number = 0;
    pkt.num_len = 1;
    pkt.trunc = 0;
    pkt.dcid.data = (u_char *)s3_test_dcid;
    pkt.dcid.len = sizeof(s3_test_dcid);
    pkt.scid.data = (u_char *)s3_test_scid;
    pkt.scid.len = sizeof(s3_test_scid);
    pkt.payload.data = frame_buf;
    pkt.payload.len = frame_len;

    S3_ASSERT(s3_test_seal_packet(&pkt, &pkt_keys, S3_QUIC_ENCRYPTION_INITIAL, cli_secret,
                                  sizeof(cli_secret), res, sizeof(res), &pkt_len) == S3_OK);

    size = (ssize_t)pkt_len;

    /* the first datagram goes into c->buffer, like the udp layer does */

    b = s3_test_datagram_buf(env.conn->pool, res, (size_t)size);
    S3_ASSERT(b != NULL);

    env.conn->buffer = b;

    s3_quic_run(env.conn, &env.conf);

    /* the quic connection exists now */

    qc = s3_quic_get_connection(env.conn);
    S3_ASSERT(qc != NULL);

    qsock = s3_quic_get_socket(env.conn);
    S3_ASSERT(qsock != NULL);
    S3_ASSERT(qsock->sid.seqnum == 0);
    S3_ASSERT(qc->nsockets == 2); /* the primary socket + the temporary dcid socket */

    /* the transport parameters were applied */
    /*
     * client_tp_done implies the apply check passed: initial_scid from
     * the client parameters matches the path client id; the string
     * fields of ctp point into the ssl internal buffer and are not
     * kept
     */
    S3_ASSERT(qc->client_tp_done == 1);
    S3_ASSERT(qc->ctp.initial_scid.len == sizeof(s3_test_scid));
    S3_ASSERT(qc->ctp.active_connection_id_limit == 8);

    /* our own transport parameters */
    S3_ASSERT(qc->tp.original_dcid.len == sizeof(s3_test_dcid));
    S3_ASSERT(s3_memcmp(qc->tp.original_dcid.data, s3_test_dcid, sizeof(s3_test_dcid)) == 0);
    S3_ASSERT(qc->tp.initial_scid.len == qsock->sid.len);
    S3_ASSERT(s3_memcmp(qc->tp.initial_scid.data, qsock->sid.id, qsock->sid.len) == 0);

    /* the initial keys */
    S3_ASSERT(s3_quic_keys_available(qc->keys, S3_QUIC_ENCRYPTION_INITIAL, 0) == 1);
    S3_ASSERT(s3_quic_keys_available(qc->keys, S3_QUIC_ENCRYPTION_INITIAL, 1) == 1);

    /* the server flight is queued: ServerHello in the initial space,
     * the encrypted extensions in the handshake space */
    ctx = s3_quic_get_send_ctx(qc, S3_QUIC_ENCRYPTION_INITIAL);
    S3_ASSERT(!s3_queue_empty(&ctx->frames));

    ctx = s3_quic_get_send_ctx(qc, S3_QUIC_ENCRYPTION_HANDSHAKE);
    S3_ASSERT(!s3_queue_empty(&ctx->frames));
    S3_ASSERT(s3_quic_keys_available(qc->keys, S3_QUIC_ENCRYPTION_HANDSHAKE, 1) == 1);

    /* the crypto_send callback posted the output event */
    S3_ASSERT(qc->push.posted == 1);

    /* the idle and handshake timers are armed */
    S3_ASSERT(env.conn->read->timer_set == 1);
    S3_ASSERT(qc->close.timer_set == 1);

    S3_ASSERT(qc->error == 0);
    S3_ASSERT(qc->draining == 0);
    S3_ASSERT(qc->closing == 0);

    /*
     * part 2: a 1-RTT packet with a DATAGRAM frame and
     * CONNECTION_CLOSE_APP drains the connection; the application
     * secrets are seeded, as the ssl layer yields them on the
     * handshake completion
     *
     * the connection is a server one: is_write selects the tls
     * direction, and the keys of that direction land in the server
     * slot (RFC 9001, 5.1).  The draining timer below is armed only
     * while the write keys of some level are present, so is_write is 1
     * here
     */

    for (n = 0; n < 32; n++) {
        app_secret[n] = (uint8_t)(0x11 * (n + 1));
    }

    /*
     * the connection is a server one and the material is synthetic:
     * the ssl layer yields the real application secrets on the
     * handshake completion.  Both directions get the same bytes, as
     * the packet below is sealed by the helper from the server slot
     * (the zeroed key set of the helper is a server-role one) while
     * the connection opens it with the client slot (RFC 9001, 5.1).
     * The write direction is also what arms the draining timer.
     *
     * the ssl layer has already installed the application read secret
     * of the handshake, and the protection layer replaces a slot in
     * place, so the level is discarded before the reseed
     */

    s3_quic_keys_discard(qc->keys, S3_QUIC_ENCRYPTION_APPLICATION);

    S3_ASSERT(s3_quic_keys_set_encryption_secret(
                  &s3_test_tls_log, 0, qc->keys, S3_QUIC_ENCRYPTION_APPLICATION,
                  TLS1_3_CK_AES_128_GCM_SHA256, app_secret, sizeof(app_secret)) == S3_OK);

    S3_ASSERT(s3_quic_keys_set_encryption_secret(
                  &s3_test_tls_log, 1, qc->keys, S3_QUIC_ENCRYPTION_APPLICATION,
                  TLS1_3_CK_AES_128_GCM_SHA256, app_secret, sizeof(app_secret)) == S3_OK);

    /* the DATAGRAM frame */

    s3_memzero(&frame, sizeof(s3_quic_frame_t));
    s3_memzero(&chain, sizeof(s3_chain_t));

    chain.buf = &(s3_buf_t){.temporary = 1,
                            .pos = (u_char *)s3_test_dg_payload,
                            .last = (u_char *)s3_test_dg_payload + sizeof(s3_test_dg_payload)};
    frame.type = S3_QUIC_FT_DATAGRAM_WITH_LENGTH;
    frame.data = &chain;
    frame.u.datagram.length = sizeof(s3_test_dg_payload);

    frame_len = s3_quic_create_frame(frame_buf, &frame);
    S3_ASSERT(frame_len == 1 + 1 + 4);
    dg_len = frame_len;

    /* the CONNECTION_CLOSE frame after it */

    s3_memzero(&frame, sizeof(s3_quic_frame_t));

    reason.data = (u_char *)"bye";
    reason.len = 3;

    frame.type = S3_QUIC_FT_CONNECTION_CLOSE_APP;
    frame.u.close.error_code = S3_QUIC_ERR_NO_ERROR;
    frame.u.close.frame_type = 0;
    frame.u.close.reason = reason;

    frame_len = s3_quic_create_frame(frame_buf + dg_len, &frame);
    S3_ASSERT(frame_len > 0);

    dg_len += frame_len;

    /* the 1-RTT packet */

    s3_memzero(&pkt, sizeof(s3_quic_header_t));
    pkt.log = &s3_test_tls_log;
    pkt.flags = 0x40; /* short, fixed, key phase 0, pn len 1 */
    pkt.version = 1;
    pkt.level = S3_QUIC_ENCRYPTION_APPLICATION;
    pkt.number = 0;
    pkt.num_len = 1;
    pkt.trunc = 0;
    pkt.dcid.data = qsock->sid.id;
    pkt.dcid.len = qsock->sid.len;
    pkt.payload.data = frame_buf;
    pkt.payload.len = dg_len;

    S3_ASSERT(s3_test_seal_packet(&pkt, &pkt_keys, S3_QUIC_ENCRYPTION_APPLICATION, app_secret,
                                  sizeof(app_secret), res2, sizeof(res2), &pkt_len) == S3_OK);

    b = s3_test_datagram_buf(env.conn->pool, res2, pkt_len);
    S3_ASSERT(b != NULL);

    env.conn->buffer = b;

    s3_quic_run(env.conn, &env.conf);

    /* the DATAGRAM frame reached the handler */

    S3_ASSERT(s3_test_dg_len == 4);
    S3_ASSERT(s3_memcmp(s3_test_dg_data, s3_test_dg_payload, 4) == 0);

    /*
     * zero copy: the handler gets the chain the parser built, a view
     * over the decrypted packet, not a block assembled for it.  a
     * flattened handler would see a single anonymous block instead
     */

    S3_ASSERT(s3_test_dg_links == 1);
    S3_ASSERT(s3_test_dg_link_size == 4);

    /* the view is writable by nobody but carries the payload verbatim */

    S3_ASSERT(s3_test_dg_ptr != NULL);
    S3_ASSERT(s3_memcmp(s3_test_dg_ptr, s3_test_dg_payload, 4) == 0);

    /* the CONNECTION_CLOSE frame drains the connection */

    S3_ASSERT(qc->draining == 1);
    S3_ASSERT(qc->close.posted == 1);

    /* the close event is queued; process it like the event loop does */

    s3_event_process_posted(&env.ctx, &env.ctx.posted_events);

    S3_ASSERT(qc->closing == 1);
    S3_ASSERT(qc->close.timer_set == 1); /* the draining period is armed */

    s3_test_core_env_done(&env);

    return s3_test_failures;
}

/*
 * the input handler must drain the socket, the way ngx_quic_recvmsg()
 * loops on recvmsg() until the socket reports EAGAIN: one epoll wakeup
 * has to cost one recv per datagram, not one epoll_wait per datagram
 */

#define S3_TEST_DRAIN_DATAGRAMS 3

static s3_uint_t s3_test_drain_calls;
static u_char    s3_test_drain_pkt[S3_TEST_TLS_BUF];
static size_t    s3_test_drain_pkt_len;

static ssize_t
s3_test_drain_recv(s3_connection_t *c, u_char *buf, size_t size)
{
    size_t len;

    (void)c;

    if (s3_test_drain_calls == S3_TEST_DRAIN_DATAGRAMS) {
        return (ssize_t)S3_AGAIN;
    }

    s3_test_drain_calls++;

    len = s3_min(s3_test_drain_pkt_len, size);

    s3_memcpy(buf, s3_test_drain_pkt, len);

    return (ssize_t)len;
}

static int
test_input_handler_drains_socket(void)
{
    u_char                cert[4096] = {0}, key[4096] = {0}, tp[64], res[2048], sealed[2048];
    u_char                cli_secret[32];
    size_t                cert_len = 0, key_len = 0, tp_len, frame_len, pkt_len;
    s3_str_t              alpn, secret;
    int                   n;
    s3_quic_keys_t        pkt_keys;
    s3_quic_header_t      pkt;
    s3_quic_frame_t       frame;
    s3_chain_t            chain;
    s3_buf_t             *b;
    s3_quic_connection_t *qc;

    static s3_test_core_env_t env;

    s3_test_tls_log_init();

    S3_ASSERT(s3_test_tls_gen_cert(cert, &cert_len, key, &key_len) == 0);
    S3_ASSERT(s3_test_core_env_init(&env, cert, cert_len, key, key_len) == S3_OK);

    /* drive one Initial through, so that the quic connection exists */

    tp_len = s3_test_client_tp(tp, s3_test_scid, sizeof(s3_test_scid));

    alpn.data = (u_char *)"\x04ssh3";
    alpn.len = 5;

    env.client = s3_test_tls_client(&env.cli, &alpn, tp, tp_len, &env.client_ctx);
    S3_ASSERT(env.client != NULL);

    n = SSL_do_handshake(env.client);
    S3_ASSERT(n <= 0 && SSL_get_error(env.client, n) == SSL_ERROR_WANT_READ);

    s3_memzero(&frame, sizeof(s3_quic_frame_t));
    s3_memzero(&chain, sizeof(s3_chain_t));

    chain.buf = &(s3_buf_t){
        .temporary = 1, .pos = env.cli.out[0], .last = env.cli.out[0] + env.cli.out_len[0]};
    frame.type = S3_QUIC_FT_CRYPTO;
    frame.data = &chain;
    frame.u.crypto.offset = 0;
    frame.u.crypto.length = env.cli.out_len[0];

    frame_len = s3_quic_create_frame(res, &frame);
    S3_ASSERT(frame_len > 0);

    s3_memzero(&pkt_keys, sizeof(s3_quic_keys_t));

    secret.data = (u_char *)s3_test_dcid;
    secret.len = sizeof(s3_test_dcid);

    S3_ASSERT(s3_quic_keys_set_initial_secret(&pkt_keys, &secret, &s3_test_tls_log) == S3_OK);

    s3_memcpy(cli_secret, pkt_keys.secrets[S3_QUIC_ENCRYPTION_INITIAL].client.secret.data,
              sizeof(cli_secret));

    s3_quic_keys_cleanup(&pkt_keys);

    s3_memzero(&pkt, sizeof(s3_quic_header_t));
    pkt.log = &s3_test_tls_log;
    pkt.flags = 0xc0;
    pkt.version = 1;
    pkt.level = S3_QUIC_ENCRYPTION_INITIAL;
    pkt.number = 0;
    pkt.num_len = 1;
    pkt.trunc = 0;
    pkt.dcid.data = (u_char *)s3_test_dcid;
    pkt.dcid.len = sizeof(s3_test_dcid);
    pkt.scid.data = (u_char *)s3_test_scid;
    pkt.scid.len = sizeof(s3_test_scid);
    pkt.payload.data = res;
    pkt.payload.len = frame_len;

    S3_ASSERT(s3_test_seal_packet(&pkt, &pkt_keys, S3_QUIC_ENCRYPTION_INITIAL, cli_secret,
                                  sizeof(cli_secret), sealed, sizeof(sealed), &pkt_len) == S3_OK);

    b = s3_test_datagram_buf(env.conn->pool, sealed, pkt_len);
    S3_ASSERT(b != NULL);

    env.conn->buffer = b;

    s3_quic_run(env.conn, &env.conf);

    qc = s3_quic_get_connection(env.conn);
    S3_ASSERT(qc != NULL);

    /*
     * the packets below replay the Initial the connection has already
     * processed: a duplicate frame is dropped by the quic layer, which
     * is what keeps the connection alive while the socket is drained
     */

    s3_memcpy(s3_test_drain_pkt, sealed, pkt_len);
    s3_test_drain_pkt_len = pkt_len;
    s3_test_drain_calls = 0;

    env.conn->recv = s3_test_drain_recv;

    env.conn->read->handler(env.conn->read);

    S3_ASSERT(s3_test_drain_calls == S3_TEST_DRAIN_DATAGRAMS);

    s3_test_core_env_done(&env);

    return s3_test_failures;
}

static int
s3_test_quic_core(void)
{
    test_run_and_close();
    test_input_handler_drains_socket();

    /* release the one-time openssl allocations for the leak check */
    OPENSSL_cleanup();

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_quic_core)
