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

#if (S3_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#endif
#include <string.h>
#include <unistd.h>

#include <openssl/ssl.h>

#include <s3_nonblocking.h>
#include <s3_quic.h>
#include <s3_quic_connection.h>
#include <s3_quic_output.h>
#include <s3_quic_frames.h>
#include <s3_quic_streams.h>

#define S3_TEST_TLS_NO_LOCKSTEP
#define S3_TEST_TLS_NO_CLIENT
#include "s3_quic_tls_helper.h"
#include "s3_test.h"

#define S3_TEST_PUMP_LIMIT        5000
#define S3_TEST_STREAM_PUMP_LIMIT 50000

/*
 * the stream echo regression payload: many flow control windows deep,
 * so the writer parks on the window and lives or dies by the posted
 * write events the library re-arms on the peer ACKs and grants
 */
#define S3_TEST_ECHO_TOTAL (256 * 1024)
#define S3_TEST_ECHO_BUF   (512 * 1024)

static u_char s3_test_cli_received[64];
static size_t s3_test_cli_received_len;
static u_char s3_test_srv_received[64];
static size_t s3_test_srv_received_len;

/* the echo state of the stream regression (one stream at a time) */

static u_char           s3_test_echo_buf[S3_TEST_ECHO_BUF];
static size_t           s3_test_echo_off;
static size_t           s3_test_echo_len;
static int              s3_test_echo_fin;
static s3_connection_t *s3_test_echo_sc;

/* the client side of the stream regression */

static size_t           s3_test_cli_sent;
static size_t           s3_test_cli_got;
static int              s3_test_cli_fin_in;
static int              s3_test_cli_done;
static s3_connection_t *s3_test_cli_sc;

static u_char
s3_test_echo_byte(size_t pos)
{
    return (u_char)(pos * 31 + 7);
}

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

/*
 * the event-driven echo of the stream regression: the pending tail
 * drains in place (the consumed head advances, no per-send compaction)
 * and after a partial send the handler returns, trusting the library
 * to re-post the write event when the window reopens
 */

static void
s3_test_echo_drain(void)
{
    s3_connection_t *sc = s3_test_echo_sc;
    ssize_t          m;

    while (s3_test_echo_len > 0) {

        m = s3_quic_stream_send(sc, s3_test_echo_buf + s3_test_echo_off, s3_test_echo_len);

        if (m == (ssize_t)S3_AGAIN) {
            return;
        }

        if (m <= 0) {
            s3_test_echo_len = 0;
            s3_test_echo_off = 0;
            return;
        }

        s3_test_echo_off += (size_t)m;
        s3_test_echo_len -= (size_t)m;
    }

    s3_test_echo_off = 0;

    if (s3_test_echo_fin) {
        (void)s3_quic_shutdown_stream(sc, S3_WRITE_SHUTDOWN);
    }
}

static void
s3_test_echo_write(s3_event_t *ev)
{
    (void)ev;

    s3_test_echo_drain();
}

static void
s3_test_echo_read(s3_event_t *ev)
{
    s3_connection_t *sc;
    ssize_t          n, m;

    sc = ev->data;

    for (;;) {

        if (s3_test_echo_off + s3_test_echo_len == sizeof(s3_test_echo_buf)) {

            s3_memmove(s3_test_echo_buf, s3_test_echo_buf + s3_test_echo_off, s3_test_echo_len);
            s3_test_echo_off = 0;
        }

        n = sc->recv(sc, s3_test_echo_buf + s3_test_echo_off + s3_test_echo_len,
                     sizeof(s3_test_echo_buf) - s3_test_echo_off - s3_test_echo_len);

        if (n == (ssize_t)S3_AGAIN || n < 0) {
            break;
        }

        if (n == 0) {
            s3_test_echo_fin = 1;
            break;
        }

        s3_test_echo_len += (size_t)n;

        m = s3_quic_stream_send(sc, s3_test_echo_buf + s3_test_echo_off, s3_test_echo_len);

        if (m == (ssize_t)S3_AGAIN) {
            continue;
        }

        if (m <= 0) {
            s3_test_echo_len = 0;
            s3_test_echo_off = 0;
            break;
        }

        s3_test_echo_off += (size_t)m;
        s3_test_echo_len -= (size_t)m;
    }

    if (s3_test_echo_fin && s3_test_echo_len == 0) {
        s3_test_echo_off = 0;
        (void)s3_quic_shutdown_stream(sc, S3_WRITE_SHUTDOWN);
    }
}

static void
s3_test_stream_accept(s3_connection_t *c, s3_quic_stream_t *qs)
{
    s3_event_t *rev, *wev;

    (void)c;

    s3_test_echo_sc = qs->connection;
    s3_test_echo_off = 0;
    s3_test_echo_len = 0;
    s3_test_echo_fin = 0;

    rev = qs->connection->read;
    wev = qs->connection->write;

    rev->handler = s3_test_echo_read;
    rev->data = qs->connection;
    rev->active = 1;

    wev->handler = s3_test_echo_write;
    wev->data = qs->connection;
    wev->active = 1;

    if (rev->ready) {
        rev->handler(rev);
    }
}

/* the client writer: one initial post, the library must re-arm the rest */

static void
s3_test_cli_writer(s3_event_t *ev)
{
    s3_connection_t *sc = ev->data;
    u_char           chunk[16384];
    ssize_t          m;

    while (s3_test_cli_sent < S3_TEST_ECHO_TOTAL) {

        size_t len = sizeof(chunk);
        size_t j;

        if (s3_test_cli_sent + len > S3_TEST_ECHO_TOTAL) {
            len = S3_TEST_ECHO_TOTAL - s3_test_cli_sent;
        }

        for (j = 0; j < len; j++) {
            chunk[j] = s3_test_echo_byte(s3_test_cli_sent + j);
        }

        m = s3_quic_stream_send(sc, chunk, len);

        if (m == (ssize_t)S3_AGAIN) {
            return; /* the window is full: only the posted events go on */
        }

        if (m <= 0) {
            return;
        }

        s3_test_cli_sent += (size_t)m;
    }

    if (s3_test_cli_sent == S3_TEST_ECHO_TOTAL && !s3_test_cli_fin_in) {
        (void)s3_quic_shutdown_stream(sc, S3_WRITE_SHUTDOWN);
        s3_test_cli_fin_in = 1;
    }
}

static void
s3_test_cli_reader(s3_event_t *ev)
{
    s3_connection_t *sc = ev->data;
    u_char           chunk[4096];
    ssize_t          n;

    for (;;) {

        n = sc->recv(sc, chunk, sizeof(chunk));

        if (n == (ssize_t)S3_AGAIN || n < 0) {
            return;
        }

        if (n == 0) {
            /* the server fin after the full echo */
            if (s3_test_cli_got == S3_TEST_ECHO_TOTAL) {
                s3_test_cli_done = 1;
            }

            return;
        }

        {
            ssize_t j;

            for (j = 0; j < n; j++) {
                if (chunk[j] != s3_test_echo_byte(s3_test_cli_got + (size_t)j)) {
                    s3_test_cli_done = 0;
                    return;
                }
            }
        }

        s3_test_cli_got += (size_t)n;
    }
}

/*
 * the stream retire regression: sequential session channels ride one
 * connection, every channel ends with the full fin exchange and the
 * app drops the stream connection - the pool cleanup runs the quic
 * stream cleanup, the retire lifts the open limit and queues
 * MAX_STREAMS.  Without the retire the 17th open hits the initial
 * max_concurrent_streams_bidi credit and fails (the P7.1 CM defect:
 * 15 mux sessions then "too many client bidi streams")
 */

#define S3_TEST_RETIRE_SESSIONS 20
#define S3_TEST_RETIRE_LEN      24

static u_char           s3_test_retire_out[S3_TEST_RETIRE_LEN];
static size_t           s3_test_retire_out_len;
static s3_connection_t *s3_test_retire_srv_sc;

static size_t s3_test_retire_sent;
static size_t s3_test_retire_got;
static int    s3_test_retire_cli_done;

static void
s3_test_retire_read(s3_event_t *ev)
{
    s3_connection_t *sc = ev->data;
    ssize_t          n;

    for (;;) {

        n = sc->recv(sc, s3_test_retire_out + s3_test_retire_out_len,
                     sizeof(s3_test_retire_out) - s3_test_retire_out_len);

        if (n == (ssize_t)S3_AGAIN || n < 0) {
            return;
        }

        if (n == 0) {

            ssize_t m;

            /* the peer fin: the echo rides out, the send side shuts
               and the stream conn retires like the session servers
               do on the drained channel */

            m = s3_quic_stream_send(sc, s3_test_retire_out, s3_test_retire_out_len);
            S3_ASSERT(m == (ssize_t)s3_test_retire_out_len);

            (void)s3_quic_shutdown_stream(sc, S3_WRITE_SHUTDOWN);

            s3_close_connection(sc);
            s3_test_retire_srv_sc = NULL;

            return;
        }

        s3_test_retire_out_len += (size_t)n;
    }
}

static void
s3_test_retire_accept(s3_connection_t *c, s3_quic_stream_t *qs)
{
    s3_event_t *rev;

    (void)c;

    S3_ASSERT(s3_test_retire_srv_sc == NULL);

    s3_test_retire_srv_sc = qs->connection;
    s3_test_retire_out_len = 0;

    rev = qs->connection->read;
    rev->handler = s3_test_retire_read;
    rev->data = qs->connection;
    rev->active = 1;

    if (rev->ready) {
        rev->handler(rev);
    }
}

static void
s3_test_retire_cli_read(s3_event_t *ev)
{
    s3_connection_t *sc = ev->data;
    u_char           chunk[64];
    ssize_t          n;

    for (;;) {

        n = sc->recv(sc, chunk, sizeof(chunk));

        if (n == (ssize_t)S3_AGAIN || n < 0) {
            return;
        }

        if (n == 0) {
            /* the server fin after the echo */
            s3_test_retire_cli_done = 1;
            return;
        }

        {
            ssize_t j;

            for (j = 0; j < n; j++) {
                S3_ASSERT(chunk[j] == s3_test_echo_byte(s3_test_retire_got + (size_t)j));
            }
        }

        s3_test_retire_got += (size_t)n;
    }
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
    if (env->listen_fd == (s3_fd_t)-1) {
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
    if (env->cli_fd == (s3_fd_t)-1) {
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

    if (env->cli_fd != (s3_fd_t)-1) {
        (void)s3_test_close(env->cli_fd);
        env->cli_fd = -1;
    }

    if (env->listen_fd != (s3_fd_t)-1) {
        (void)s3_test_close(env->listen_fd);
        env->listen_fd = -1;
    }

    if (env->pool != NULL) {
        s3_destroy_pool(env->pool);
        env->pool = NULL;
    }

    /*
     * the pool of the event context: the next case re-initializes the
     * context, and the overwritten pool would be a leak (the receive
     * buffers live there)
     */

    if (env->ctx.pool != NULL) {
        s3_destroy_pool(env->ctx.pool);
        env->ctx.pool = NULL;
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

    /*
     * the stream echo over the same connection: the client writes many
     * windows deep through the posted write events only (one initial
     * post, then the library re-arms), the server echoes the same way.
     * This pins the writer wake chain - a partial send parks the writer
     * on wev->ready=0 and only the re-posted events (the ACK and the
     * MAX_STREAM_DATA paths) may finish the transfer; a lost wake would
     * hit the pump limit here
     */
    {
        s3_connection_t *sc;

        env->srv_conf.stream_handler = s3_test_stream_accept;

        sc = s3_quic_open_stream(env->cli, 1);
        S3_ASSERT(sc != NULL);

        s3_test_cli_sc = sc;

        sc->read->handler = s3_test_cli_reader;
        sc->read->data = sc;

        sc->write->handler = s3_test_cli_writer;
        sc->write->data = sc;

        /* the single initial post: everything after must ride the library */

        s3_post_event(sc->write, &env->ctx.posted_events);

        for (i = 0; i < S3_TEST_STREAM_PUMP_LIMIT && !s3_test_cli_done; i++) {
            s3_event_process_posted(&env->ctx, &env->ctx.posted_events);
            s3_process_events_and_timers(&env->ctx);
        }

        S3_ASSERT(s3_test_cli_done == 1);
        S3_ASSERT(s3_test_cli_sent == S3_TEST_ECHO_TOTAL);
        S3_ASSERT(s3_test_cli_got == S3_TEST_ECHO_TOTAL);
    }

    /*
     * the stream retire regression: 20 sequential channels against the
     * 16-stream initial credit, each with a full fin exchange and the
     * app-level drop of the stream conn on both ends; the open credit
     * must come back with every retire, the 17th open included
     */
    {
        s3_connection_t *sc;
        u_char           payload[S3_TEST_RETIRE_LEN];
        ssize_t          m;
        int              i, j;

        s3_test_retire_sent = 0;
        s3_test_retire_got = 0;

        env->srv_conf.stream_handler = s3_test_retire_accept;

        for (i = 0; i < S3_TEST_RETIRE_SESSIONS; i++) {

            sc = s3_quic_open_stream(env->cli, 1);

            if (sc == NULL) {
                S3_ASSERT(0); /* the open credit never came back */
                break;
            }

            for (j = 0; j < S3_TEST_RETIRE_LEN; j++) {
                payload[j] = s3_test_echo_byte(s3_test_retire_sent + (size_t)j);
            }

            m = s3_quic_stream_send(sc, payload, sizeof(payload));
            S3_ASSERT(m == (ssize_t)sizeof(payload));

            s3_test_retire_sent += sizeof(payload);

            S3_ASSERT(s3_quic_shutdown_stream(sc, S3_WRITE_SHUTDOWN) == S3_OK);

            s3_test_retire_cli_done = 0;

            sc->read->handler = s3_test_retire_cli_read;
            sc->read->data = sc;
            sc->read->active = 1;

            for (j = 0; j < S3_TEST_STREAM_PUMP_LIMIT && !s3_test_retire_cli_done; j++) {
                s3_event_process_posted(&env->ctx, &env->ctx.posted_events);
                s3_process_events_and_timers(&env->ctx);
            }

            S3_ASSERT(s3_test_retire_cli_done == 1);
            S3_ASSERT(s3_test_retire_got == s3_test_retire_sent);

            /* the app drops the stream conn: the cleanup retires the
               quic stream and the ack lifts the open credit */

            s3_close_connection(sc);

            for (j = 0; j < S3_TEST_STREAM_PUMP_LIMIT; j++) {

                if (qc->streams.client_max_streams_bidi >= (uint64_t)(17 + i)) {
                    break;
                }

                s3_event_process_posted(&env->ctx, &env->ctx.posted_events);
                s3_process_events_and_timers(&env->ctx);
            }

            S3_ASSERT(qc->streams.client_max_streams_bidi == (uint64_t)(17 + i));
        }

        /*
         * every server-side stream retired too: each retire queues
         * MAX_STREAMS, so the client sees its peer-initiated open
         * credit grow from 16 by the session count (the echo stream
         * from the scenario above legitimately stays in the tree)
         */

        for (j = 0; j < S3_TEST_STREAM_PUMP_LIMIT; j++) {

            if (qc->streams.server_max_streams_bidi >= (uint64_t)(16 + S3_TEST_RETIRE_SESSIONS)) {
                break;
            }

            s3_event_process_posted(&env->ctx, &env->ctx.posted_events);
            s3_process_events_and_timers(&env->ctx);
        }

        S3_ASSERT(qc->streams.server_max_streams_bidi == (uint64_t)(16 + S3_TEST_RETIRE_SESSIONS));
    }

    s3_test_env_done(env);

    return s3_test_failures;
}

/*
 * the idle close regression: both endpoints idle out, the close path
 * must drain every timer from the tree.  a stale node here is walked
 * by the next s3_event_expire_timers() pass and dereferenced after
 * the pool is gone (0xC0000005 in the walk, the 2026-10-15 client
 * crash at offset 0xbbd3)
 */

static int
s3_test_quic_e2e_idle_close(void)
{
    s3_test_e2e_env_t *env = &s3_test_e2e;
    int                i;

    s3_test_cli_received_len = 0;
    s3_test_srv_received_len = 0;

    /*
     * the env must be the global s3_test_e2e: the listener accept
     * handler carries no env and reads the global srv_conf, a local
     * copy leaves the handler a stale (ssl-less) conf — the server
     * rejects the Initial, the client times out and the pump loops
     * block on epoll_wait with no timers left (the 2026-10-16 hang)
     */

    s3_memzero(env, sizeof(*env));

    S3_ASSERT(s3_test_env_init(env) == S3_OK);

    /*
     * compressed timeouts: the handshake must complete well inside
     * handshake_timeout, the idle timeout must fire while both sides
     * are idle
     */

    env->cli_conf.handshake_timeout = 2000;
    env->cli_conf.idle_timeout = 300;
    env->srv_conf.handshake_timeout = 2000;
    env->srv_conf.idle_timeout = 300;

    S3_ASSERT(s3_quic_connect(env->cli, &env->cli_conf) == S3_OK);

    /* pump the handshake */

    for (i = 0; i < 500; i++) {
        s3_event_process_posted(&env->ctx, &env->ctx.posted_events);
        s3_process_events_and_timers(&env->ctx);

        if (env->cli->ssl != NULL && env->cli->ssl->handshaked) {
            break;
        }
    }

    S3_ASSERT(env->cli->ssl->handshaked);

    /*
     * idle out: the idle timers fire, both sides close and destroy
     * their pools.  every expire pass after a handler must find the
     * tree consistent; the loop ends only on a drained tree — a stale
     * node either traps under the sanitizer or keeps the tree
     * non-empty, which fails the assert below
     */

    for (i = 0; i < 300; i++) {
        s3_event_process_posted(&env->ctx, &env->ctx.posted_events);
        s3_process_events_and_timers(&env->ctx);

        if (s3_event_find_timer(&env->ctx) == S3_TIMER_INFINITE) {
            break;
        }
    }

    S3_ASSERT(s3_event_find_timer(&env->ctx) == S3_TIMER_INFINITE);

    /* both pools were destroyed by the idle close */

    env->cli = NULL;
    env->server = NULL;

    s3_test_env_done(env);

    return s3_test_failures;
}

/*
 * the "no limit" regression: an idle timeout of 0 means "no limit"
 * (RFC 9000, 10.1), so the connection must survive the idle period.
 * The reference arms a 0 timer, which closes the connection on the
 * first event loop pass — the handshake never completes there.
 */

static void
s3_test_guard_handler(s3_event_t *ev)
{
    int *fired = (int *)ev->data;

    *fired = 1;
}

static int
s3_test_quic_e2e_idle_zero(void)
{
    s3_test_e2e_env_t *env = &s3_test_e2e;
    s3_event_t         guard;
    int                i, guard_fired;

    s3_test_cli_received_len = 0;
    s3_test_srv_received_len = 0;

    s3_memzero(env, sizeof(*env));

    S3_ASSERT(s3_test_env_init(env) == S3_OK);

    env->cli_conf.handshake_timeout = 2000;
    env->cli_conf.idle_timeout = 0;
    env->srv_conf.handshake_timeout = 2000;
    env->srv_conf.idle_timeout = 0;

    /*
     * the guard keeps the pump bounded: with an empty timer tree
     * epoll_wait() blocks forever, and a connection that dies early
     * leaves the tree empty
     */

    guard_fired = 0;
    s3_memzero(&guard, sizeof(guard));
    guard.data = &guard_fired;
    guard.handler = s3_test_guard_handler;
    guard.log = &s3_test_tls_log;

    s3_event_add_timer(&guard, 1000);

    S3_ASSERT(s3_quic_connect(env->cli, &env->cli_conf) == S3_OK);

    /* pump the handshake */

    for (i = 0; i < 5000 && !guard_fired; i++) {
        s3_event_process_posted(&env->ctx, &env->ctx.posted_events);
        s3_process_events_and_timers(&env->ctx);

        if (env->cli->ssl != NULL && env->cli->ssl->handshaked) {
            break;
        }
    }

    /* the guard must not have fired: the handshake is quick */

    S3_ASSERT(!guard_fired);
    S3_ASSERT(env->cli->ssl != NULL && env->cli->ssl->handshaked);

    if (guard.timer_set) {
        s3_event_del_timer(&guard);
    }

    /* the idle connection must stay alive: nothing closes it */

    guard_fired = 0;
    s3_event_add_timer(&guard, 200);

    for (i = 0; i < 5000 && !guard_fired; i++) {
        s3_event_process_posted(&env->ctx, &env->ctx.posted_events);
        s3_process_events_and_timers(&env->ctx);
    }

    /* the idle period passed and the connection is still alive */

    S3_ASSERT(guard_fired);
    S3_ASSERT(env->cli->ssl != NULL && env->cli->ssl->handshaked);

    if (guard.timer_set) {
        s3_event_del_timer(&guard);
    }

    s3_test_env_done(env);

    return s3_test_failures;
}

static int
s3_test_quic_e2e(void)
{
    (void)s3_test_quic_e2e_run();
    (void)s3_test_quic_e2e_idle_close();
    (void)s3_test_quic_e2e_idle_zero();

    OPENSSL_cleanup();

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_quic_e2e)
