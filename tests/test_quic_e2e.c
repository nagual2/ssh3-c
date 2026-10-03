/*
 * Copyright (C) 2026 the ssh3-c authors
 */

/*
 * the D3 end-to-end test: our client and our server on the loopback
 * in one process.  The server listens through the D3 quic listener
 * (dcid-keyed rbtree), the client dials with s3_quic_connect(); the
 * handshake runs over real UDP datagrams pumped through the event
 * loop.  When the handshake completes, a DATAGRAM roundtrip
 * client -> server -> client is checked through conf->datagram_handler
 */

#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/ssl.h>

#include <s3_nonblocking.h>
#include <s3_quic.h>
#include <s3_quic_connection.h>
#include <s3_quic_output.h>
#include <s3_quic_frames.h>

#define S3_TEST_TLS_NO_LOCKSTEP
#define S3_TEST_TLS_NO_CLIENT
#include "s3_quic_tls_helper.h"
#include "s3_test.h"

#define S3_TEST_PUMP_LIMIT 5000

static u_char s3_test_cli_received[64];
static size_t s3_test_cli_received_len;
static u_char s3_test_srv_received[64];
static size_t s3_test_srv_received_len;

typedef struct {
    s3_pool_t     *pool;
    s3_event_ctx_t ctx;

    s3_fd_t          listen_fd;
    s3_connection_t *listener;
    s3_udp_listen_t  ul;
    s3_quic_conf_t   srv_conf;

    s3_fd_t          cli_fd;
    s3_connection_t *cli;
    s3_quic_conf_t   cli_conf;

    struct sockaddr_in sa;
    socklen_t          sa_len;

    s3_connection_t *server;
    int              accepts;
} s3_test_e2e_env_t;

static s3_test_e2e_env_t s3_test_e2e;

static void
s3_test_client_datagram(s3_connection_t *c, s3_chain_t *data)
{
    s3_chain_t *cl;
    size_t      len;

    (void)c;

    len = 0;

    for (cl = data; cl != NULL; cl = cl->next) {
        s3_memcpy(s3_test_cli_received + len, cl->buf->pos, s3_buf_size(cl->buf));
        len += s3_buf_size(cl->buf);
    }

    s3_test_cli_received_len = len;
}

static void
s3_test_server_datagram(s3_connection_t *c, s3_chain_t *data)
{
    s3_chain_t           *cl;
    size_t                len;
    s3_quic_connection_t *qc;

    /* the chain is valid for the call only: copy what we echo back */

    len = 0;

    for (cl = data; cl != NULL; cl = cl->next) {
        s3_memcpy(s3_test_srv_received + len, cl->buf->pos, s3_buf_size(cl->buf));
        len += s3_buf_size(cl->buf);
    }

    s3_test_srv_received_len = len;

    qc = s3_quic_get_connection(c);

    if (qc != NULL && !qc->closing) {
        (void)s3_quic_send_datagram(c, s3_test_srv_received, len);
    }
}

static void
s3_test_accept(s3_connection_t *c)
{
    s3_test_e2e.accepts++;

    /* the first quic connection of the test */
    s3_test_e2e.server = c;

    s3_quic_run(c, &s3_test_e2e.srv_conf);
}

static s3_int_t
s3_test_env_init(s3_test_e2e_env_t *env)
{
    s3_str_t  alpn;
    s3_uint_t i;

    s3_memzero(env, sizeof(s3_test_e2e_env_t));

    s3_test_tls_log_init();

    env->listen_fd = -1;
    env->cli_fd = -1;

    env->pool = s3_create_pool((size_t)S3_DEFAULT_POOL_SIZE, &s3_test_tls_log);
    if (env->pool == NULL) {
        return S3_ERROR;
    }

    if (s3_event_ctx_init(&env->ctx, &s3_test_tls_log) != S3_OK) {
        return S3_ERROR;
    }

    alpn.data = (u_char *)"\x04ssh3";
    alpn.len = 5;

    /* the server side */

    env->listen_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (env->listen_fd == -1) {
        return S3_ERROR;
    }

    if (s3_nonblocking(env->listen_fd) != S3_OK) {
        return S3_ERROR;
    }

    s3_memzero(&env->sa, sizeof(env->sa));
    env->sa.sin_family = AF_INET;
    env->sa.sin_port = 0;
    env->sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(env->listen_fd, (struct sockaddr *)&env->sa, sizeof(env->sa)) == -1) {
        return S3_ERROR;
    }

    env->sa_len = sizeof(env->sa);

    if (getsockname(env->listen_fd, (struct sockaddr *)&env->sa, &env->sa_len) == -1) {
        return S3_ERROR;
    }

    env->listener = s3_get_connection(&env->ctx, env->listen_fd);
    if (env->listener == NULL) {
        return S3_ERROR;
    }

    env->listener->sockaddr = (struct sockaddr *)s3_palloc(env->pool, env->sa_len);
    if (env->listener->sockaddr == NULL) {
        return S3_ERROR;
    }

    s3_memcpy(env->listener->sockaddr, &env->sa, env->sa_len);
    env->listener->socklen = env->sa_len;

    {
        u_char cert[4096] = {0}, key[4096] = {0};
        size_t cert_len = 0, key_len = 0;

        if (s3_test_tls_gen_cert(cert, &cert_len, key, &key_len) != 0) {
            return S3_ERROR;
        }

        env->srv_conf.ssl = s3_ssl_create(&s3_test_tls_log, (const char *)cert, cert_len,
                                          (const char *)key, key_len, &alpn);
    }

    if (env->srv_conf.ssl == NULL) {
        return S3_ERROR;
    }

    env->srv_conf.ctx = &env->ctx;
    env->srv_conf.handshake_timeout = 30000;
    env->srv_conf.idle_timeout = 60000;
    env->srv_conf.stream_buffer_size = 16384;
    env->srv_conf.max_concurrent_streams_bidi = 16;
    env->srv_conf.max_concurrent_streams_uni = 16;
    env->srv_conf.active_connection_id_limit = 8;
    env->srv_conf.max_datagram_frame_size = 1200;
    env->srv_conf.datagram_handler = s3_test_server_datagram;

    for (i = 0; i < S3_QUIC_AV_KEY_LEN; i++) {
        env->srv_conf.av_token_key[i] = (u_char)(0xa0 + i);
        env->srv_conf.sr_token_key[i] = (u_char)(0xb0 + i);
    }

    /* the quic listener: the rbtree is keyed by the packet dcid */

    s3_memzero(&env->ul, sizeof(env->ul));
    env->ul.connection = env->listener;
    env->ul.ctx = &env->ctx;
    env->ul.handler = s3_test_accept;
    env->ul.quic = 1;
    s3_rbtree_init(&env->ul.rbtree, &env->ul.sentinel, s3_quic_rbtree_insert_socket);

    env->listener->data = &env->ul;
    env->listener->read->handler = s3_event_recvmsg;

    if (s3_event_actions.add_event(env->listener->read, S3_READ_EVENT, 0) != S3_OK) {
        return S3_ERROR;
    }

    /* the client side */

    env->cli_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (env->cli_fd == -1) {
        return S3_ERROR;
    }

    if (s3_nonblocking(env->cli_fd) != S3_OK) {
        return S3_ERROR;
    }

    env->cli = s3_get_connection(&env->ctx, env->cli_fd);
    if (env->cli == NULL) {
        return S3_ERROR;
    }

    env->cli->pool = s3_create_pool((size_t)S3_DEFAULT_POOL_SIZE, &s3_test_tls_log);
    if (env->cli->pool == NULL) {
        return S3_ERROR;
    }

    env->cli->sockaddr = (struct sockaddr *)s3_palloc(env->pool, env->sa_len);
    if (env->cli->sockaddr == NULL) {
        return S3_ERROR;
    }

    s3_memcpy(env->cli->sockaddr, &env->sa, env->sa_len);
    env->cli->socklen = env->sa_len;

    env->cli_conf.ssl = s3_ssl_client_create(&s3_test_tls_log, &alpn);
    if (env->cli_conf.ssl == NULL) {
        return S3_ERROR;
    }

    env->cli_conf.ctx = &env->ctx;
    env->cli_conf.handshake_timeout = 30000;
    env->cli_conf.idle_timeout = 60000;
    env->cli_conf.stream_buffer_size = 16384;
    env->cli_conf.max_concurrent_streams_bidi = 16;
    env->cli_conf.max_concurrent_streams_uni = 16;
    env->cli_conf.active_connection_id_limit = 8;
    env->cli_conf.max_datagram_frame_size = 1200;
    env->cli_conf.datagram_handler = s3_test_client_datagram;

    for (i = 0; i < S3_QUIC_AV_KEY_LEN; i++) {
        env->cli_conf.av_token_key[i] = (u_char)(0xc0 + i);
        env->cli_conf.sr_token_key[i] = (u_char)(0xd0 + i);
    }

    if (s3_event_actions.add_event(env->cli->read, S3_READ_EVENT, 0) != S3_OK) {
        return S3_ERROR;
    }

    return S3_OK;
}

static void
s3_test_env_done(s3_test_e2e_env_t *env)
{
    if (env->server != NULL && env->server->udp != NULL) {
        s3_quic_connection_t *qc = s3_quic_get_connection(env->server);

        if (qc != NULL && !qc->closing) {
            s3_quic_close_connection(env->server, S3_ABORT);
        }
    }

    if (env->cli != NULL && env->cli->udp != NULL) {
        s3_quic_connection_t *qc = s3_quic_get_connection(env->cli);

        if (qc != NULL && !qc->closing) {
            s3_quic_close_connection(env->cli, S3_ABORT);
        }
    }

    if (env->cli_conf.ssl != NULL) {
        s3_ssl_free(env->cli_conf.ssl);
        env->cli_conf.ssl = NULL;
    }

    if (env->srv_conf.ssl != NULL) {
        s3_ssl_free(env->srv_conf.ssl);
        env->srv_conf.ssl = NULL;
    }

    if (env->cli_fd != -1) {
        (void)close(env->cli_fd);
        env->cli_fd = -1;
    }

    if (env->listen_fd != -1) {
        (void)close(env->listen_fd);
        env->listen_fd = -1;
    }

    if (env->pool != NULL) {
        s3_destroy_pool(env->pool);
        env->pool = NULL;
    }
}

static int
s3_test_quic_e2e_run(void)
{
    s3_test_e2e_env_t    *env = &s3_test_e2e;
    int                   i, dg_sent;
    u_char                payload[13] = "ping-datagram";
    s3_quic_connection_t *qc;

    s3_test_cli_received_len = 0;
    s3_test_srv_received_len = 0;

    S3_ASSERT(s3_test_env_init(env) == S3_OK);

    /* the client dials the server */
    S3_ASSERT(s3_quic_connect(env->cli, &env->cli_conf) == S3_OK);

    qc = s3_quic_get_connection(env->cli);
    S3_ASSERT(qc != NULL);
    S3_ASSERT(qc->client == 1);

    /*
     * the pump: both sockets live in one event context; the handshake
     * and the datagram exchange run over real UDP datagrams.  the
     * posted queue is drained before the epoll wait, like the worker
     * loop does after its previous iteration
     */
    dg_sent = 0;

    for (i = 0; i < S3_TEST_PUMP_LIMIT; i++) {

        /* the DATAGRAM frame is sent once the handshake keys are ready */
        if (!dg_sent && env->cli->ssl != NULL && env->cli->ssl->handshaked) {
            S3_ASSERT(s3_quic_send_datagram(env->cli, payload, sizeof(payload)) == S3_OK);
            dg_sent = 1;
        }

        if (dg_sent && s3_test_cli_received_len == sizeof(payload) &&
            s3_memcmp(s3_test_cli_received, payload, sizeof(payload)) == 0) {
            break;
        }

        s3_event_process_posted(&env->ctx, &env->ctx.posted_events);

        s3_process_events_and_timers(&env->ctx);
    }

    S3_ASSERT(dg_sent == 1);
    S3_ASSERT(i < S3_TEST_PUMP_LIMIT);

    /* the handshake completed on both sides */
    S3_ASSERT(env->accepts == 1);
    S3_ASSERT(env->server != NULL);
    S3_ASSERT(env->cli->ssl != NULL && env->cli->ssl->handshaked == 1);
    S3_ASSERT(env->server->ssl != NULL && env->server->ssl->handshaked == 1);

    /* the DATAGRAM frame reached the server and was echoed back */
    S3_ASSERT(s3_test_srv_received_len == sizeof(payload));
    S3_ASSERT(s3_memcmp(s3_test_srv_received, payload, sizeof(payload)) == 0);

    S3_ASSERT(s3_test_cli_received_len == sizeof(payload));
    S3_ASSERT(s3_memcmp(s3_test_cli_received, payload, sizeof(payload)) == 0);

    /* the client saw the transport parameters of the server */
    S3_ASSERT(qc->client_tp_done == 1);
    S3_ASSERT(qc->ctp.max_datagram_frame_size == 1200);

    /*
     * DPLPMTUD: probe PING packets ride the application-level ACK path;
     * the doubling schedule starts PATH_MTU_DELAY after path validation,
     * so a short pump either confirms the first probe or the discovery
     * confirmation is dead
     */
    {
        s3_msec_t deadline = s3_current_msec + 1500;

        while (qc->path->mtu <= S3_QUIC_MIN_INITIAL_SIZE && s3_current_msec < deadline) {
            s3_event_process_posted(&env->ctx, &env->ctx.posted_events);
            s3_process_events_and_timers(&env->ctx);
        }

        S3_ASSERT(qc->path->mtu > S3_QUIC_MIN_INITIAL_SIZE);
    }

    s3_test_env_done(env);

    return s3_test_failures;
}

static int
s3_test_quic_e2e(void)
{
    (void)s3_test_quic_e2e_run();

    OPENSSL_cleanup();

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_quic_e2e)
