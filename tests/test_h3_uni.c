/*
 * Copyright (C) 2026 the ssh3-c authors
 */

/*
 * the P3 wave-2 test: the h3 uni streams and the session lifecycle
 * over the real loopback quic connection (the test_quic_e2e.c shape:
 * our client and our server in one process, real UDP datagrams).  The
 * sessions exchange SETTINGS, the six known streams converge on both
 * sides, the GOAWAY dance is eaten by the peers and the sessions close
 * cleanly without the idle timeouts
 */

#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/ssl.h>

#include <s3_h3.h>
#include <s3_h3_uni.h>
#include <s3_nonblocking.h>
#include <s3_quic.h>
#include <s3_quic_connection.h>

#define S3_TEST_TLS_NO_LOCKSTEP
#define S3_TEST_TLS_NO_CLIENT
#include "s3_quic_tls_helper.h"
#include "s3_test.h"

#define S3_TEST_PUMP_LIMIT 5000

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
} s3_test_env_t;

static s3_test_env_t s3_test_h3;

/*
 * the accepted streams, both roles: the h3 session layer arms every
 * stream (uni streams are parsed and registered, the bidi request
 * streams belong to the request layer)
 */
static void
s3_test_stream_accept(s3_connection_t *c, s3_quic_stream_t *qs)
{
    (void)qs;

    s3_h3_init_stream(c);
}

static void
s3_test_accept(s3_connection_t *c)
{
    s3_test_h3.server = c;

    s3_quic_run(c, &s3_test_h3.srv_conf);
}

static s3_int_t
s3_test_env_init(s3_test_env_t *env)
{
    s3_str_t  alpn;
    s3_uint_t i;

    s3_memzero(env, sizeof(s3_test_env_t));

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
    env->srv_conf.stream_handler = s3_test_stream_accept;

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
    env->cli_conf.stream_handler = s3_test_stream_accept;

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
s3_test_env_done(s3_test_env_t *env)
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

static void
s3_test_pump(s3_test_env_t *env)
{
    /*
     * the posted queue is drained before the epoll wait, like the
     * worker loop does after its previous iteration
     *
     * ssh3-c: the wait is bounded to a millisecond.  s3_process_events
     * _and_timers() passes s3_event_find_timer() to epoll_wait(), and
     * with no timer armed that is an unbounded wait — once the peers
     * stop owing each other packets the test would park there instead
     * of reaching its loop limit and failing.
     */

    s3_time_update();
    (void) s3_event_actions.process_events(&env->ctx, 1, S3_UPDATE_TIME);

    s3_event_expire_timers(&env->ctx);
    s3_event_process_posted(&env->ctx, &env->ctx.posted_events);
}

static int
s3_test_h3_uni(void)
{
    int                   i, k, converged;
    off_t                 cli_total, srv_total;
    s3_uint_t             u;
    s3_connection_t      *cli, *server;
    s3_h3_session_t      *h3c_cli, *h3c_srv;
    s3_quic_connection_t *qc_cli, *qc_srv;
    s3_test_env_t        *env = &s3_test_h3;

    S3_ASSERT(s3_test_env_init(env) == S3_OK);

    /* the client dials the server */

    S3_ASSERT(s3_quic_connect(env->cli, &env->cli_conf) == S3_OK);

    qc_cli = s3_quic_get_connection(env->cli);
    S3_ASSERT(qc_cli != NULL);
    S3_ASSERT(qc_cli->client == 1);

    /* the pump: the handshake completes on both sides */

    for (i = 0; i < S3_TEST_PUMP_LIMIT; i++) {
        s3_test_pump(env);

        if (env->server != NULL && env->server->ssl != NULL
            && env->server->ssl->handshaked && env->cli->ssl != NULL
            && env->cli->ssl->handshaked)
        {
            break;
        }
    }

    S3_ASSERT(i < S3_TEST_PUMP_LIMIT);
    S3_ASSERT(env->server != NULL);
    S3_ASSERT(env->server->ssl != NULL && env->server->ssl->handshaked == 1);
    S3_ASSERT(env->cli->ssl != NULL && env->cli->ssl->handshaked == 1);

    server = env->server;
    cli = env->cli;

    qc_srv = s3_quic_get_connection(server);
    S3_ASSERT(qc_srv != NULL);
    S3_ASSERT(qc_srv->client == 0);

    /*
     * the sessions: both roles allocate the h3 session and open the
     * three uni streams of the role (control, encoder, decoder) with
     * the zero-capacity settings announcement
     */
    S3_ASSERT(s3_h3_init_session(server) == S3_OK);
    S3_ASSERT(s3_h3_init_session(cli) == S3_OK);

    h3c_cli = s3_h3_get_session(cli);
    h3c_srv = s3_h3_get_session(server);

    S3_ASSERT(h3c_cli != NULL && h3c_srv != NULL);

    /* the event context is wired for the table layer posts */

    S3_ASSERT(h3c_cli->ctx == &env->ctx);
    S3_ASSERT(h3c_srv->ctx == &env->ctx);

    /*
     * 1. the control stream of each role is created by init_session():
     *    the client-initiated streams occupy the CLIENT_* slots, the
     *    server-initiated the SERVER_* ones, on both sides
     *
     * created_streams is the mask of the streams the *peer* created —
     * it is raised in s3_h3_register_uni_stream(), so the streams opened
     * locally by init_session() are visible in known_streams[] alone
     */
    S3_ASSERT(h3c_cli->known_streams[S3_H3_STREAM_CLIENT_CONTROL] != NULL);
    S3_ASSERT(h3c_srv->known_streams[S3_H3_STREAM_SERVER_CONTROL] != NULL);
    S3_ASSERT(h3c_cli->created_streams == 0);
    S3_ASSERT(h3c_srv->created_streams == 0);

    /*
     * 2. the known streams converge: the settings and the stream type
     *    bytes of both roles are parsed by the peer without a
     *    connection error
     */
    converged = 0;

    for (i = 0; i < S3_TEST_PUMP_LIMIT; i++) {
        s3_test_pump(env);

        converged = 1;

        for (k = 0; k < S3_H3_MAX_KNOWN_STREAM; k++) {
            if (h3c_cli->known_streams[k] == NULL || h3c_srv->known_streams[k] == NULL) {
                converged = 0;
                break;
            }
        }

        if (converged) {
            break;
        }
    }

    S3_ASSERT(converged == 1);

    for (u = 0; u < S3_H3_MAX_KNOWN_STREAM; u++) {
        S3_ASSERT(h3c_cli->known_streams[u] != NULL);
        S3_ASSERT(h3c_srv->known_streams[u] != NULL);
    }

    /* both roles registered the three streams of the peer */

    S3_ASSERT((h3c_cli->created_streams & (1u << S3_H3_STREAM_SERVER_CONTROL)) != 0);
    S3_ASSERT((h3c_srv->created_streams & (1u << S3_H3_STREAM_CLIENT_CONTROL)) != 0);

    S3_ASSERT(h3c_cli->total_bytes > 0);
    S3_ASSERT(h3c_srv->total_bytes > 0);
    S3_ASSERT(h3c_cli->payload_bytes == 0);
    S3_ASSERT(qc_cli->closing == 0 && qc_srv->closing == 0);

    /*
     * 3. the goaway dance: the client announces the shutdown, the
     *    server machine eats the GOAWAY frame (the session stays
     *    alive) and answers with its own goaway
     */
    srv_total = h3c_srv->total_bytes;

    S3_ASSERT(s3_h3_send_goaway(cli, h3c_cli->next_request_id) == S3_OK);
    S3_ASSERT(h3c_cli->goaway == 1);

    for (i = 0; i < S3_TEST_PUMP_LIMIT; i++) {
        s3_test_pump(env);

        if (h3c_srv->total_bytes > srv_total) {
            break;
        }
    }

    S3_ASSERT(i < S3_TEST_PUMP_LIMIT);
    S3_ASSERT(qc_cli->closing == 0 && qc_srv->closing == 0);

    cli_total = h3c_cli->total_bytes;

    S3_ASSERT(s3_h3_send_goaway(server, h3c_srv->next_request_id) == S3_OK);
    S3_ASSERT(h3c_srv->goaway == 1);

    for (i = 0; i < S3_TEST_PUMP_LIMIT; i++) {
        s3_test_pump(env);

        if (h3c_cli->total_bytes > cli_total) {
            break;
        }
    }

    S3_ASSERT(i < S3_TEST_PUMP_LIMIT);
    S3_ASSERT(qc_cli->closing == 0 && qc_srv->closing == 0);

    /*
     * 4. the clean close: the client finalizes with NO_ERROR, both
     *    quic connections complete the teardown without the idle
     *    timeouts (c->udp is reset when the quic close completes)
     */
    s3_quic_finalize_connection(cli, S3_H3_ERR_NO_ERROR, "test done");

    for (i = 0; i < S3_TEST_PUMP_LIMIT; i++) {
        s3_test_pump(env);

        if (cli->udp == NULL && server->udp == NULL) {
            break;
        }
    }

    S3_ASSERT(i < S3_TEST_PUMP_LIMIT);

    s3_test_env_done(env);

    OPENSSL_cleanup();

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_h3_uni)
