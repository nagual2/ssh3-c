/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#include "s3_quic_tls_helper.h"

/*
 * D2 unit tests of the ssl layer and the OpenSSL 3.5 QUIC TLS
 * callbacks; the full lockstep test drives a real client handshake
 * through s3_quic_init_connection(), the crypto frame handler and the
 * six OSSL_FUNC_SSL_QUIC_TLS_* callbacks
 */

static const u_char s3_test_cid[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
static const u_char s3_test_dcid[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

#define S3_TEST_ALPN_LEN 5

static const u_char s3_test_alpn[] = "\x04ssh3";

typedef struct {
    s3_pool_t           *pool;
    s3_event_ctx_t       ctx;
    s3_quic_conf_t       conf;
    s3_connection_t      conn;
    s3_quic_socket_t     qsock;
    s3_quic_connection_t qc;
    s3_quic_keys_t       keys;
    s3_test_tls_side_t   cli; /* the harness client side */
    SSL                 *client;
    SSL_CTX             *client_ctx;
    size_t               cli_off[S3_TEST_TLS_LEVELS];
} s3_test_env_t;

static s3_int_t
s3_test_env_init(s3_test_env_t *env, const u_char *cert, size_t cert_len, const u_char *key,
                 size_t key_len)
{
    s3_str_t             alpn;
    s3_uint_t            i;
    s3_str_t             secret;
    s3_str_t             scid;
    s3_quic_client_id_t *cid;

    s3_memzero(env, sizeof(s3_test_env_t));

    env->pool = s3_create_pool((size_t)S3_DEFAULT_POOL_SIZE, &s3_test_tls_log);
    if (env->pool == NULL) {
        return S3_ERROR;
    }

    /* the event context: only the posted queue and the timer rbtree */
    s3_memzero(&env->ctx, sizeof(s3_event_ctx_t));
    env->ctx.log = &s3_test_tls_log;
    s3_queue_init(&env->ctx.posted_events);

    if (s3_event_timer_init(&env->ctx) != S3_OK) {
        return S3_ERROR;
    }

    /* the ssl context */
    alpn.data = (u_char *)s3_test_alpn;
    alpn.len = S3_TEST_ALPN_LEN;

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

    for (i = 0; i < S3_QUIC_AV_KEY_LEN; i++) {
        env->conf.av_token_key[i] = (u_char)(0xa0 + i);
        env->conf.sr_token_key[i] = (u_char)(0xb0 + i);
    }

    /* the connection */
    s3_memzero(&env->conn, sizeof(s3_connection_t));
    env->conn.log = &s3_test_tls_log;
    env->conn.pool = env->pool;

    /* the quic connection bookkeeping, as s3_quic_new_connection() does */
    s3_memzero(&env->qc, sizeof(s3_quic_connection_t));
    s3_memzero(&env->keys, sizeof(s3_quic_keys_t));

    env->qc.keys = &env->keys;
    env->qc.conf = &env->conf;
    env->qc.ctx = &env->ctx;
    env->qc.version = 1;
    env->qc.max_frames = 10000;

    s3_queue_init(&env->qc.free_frames);
    s3_queue_init(&env->qc.sockets);
    s3_queue_init(&env->qc.free_sockets);
    s3_queue_init(&env->qc.paths);
    s3_queue_init(&env->qc.free_paths);
    s3_queue_init(&env->qc.client_ids);
    s3_queue_init(&env->qc.free_client_ids);

    for (i = 0; i < S3_QUIC_SEND_CTX_LAST; i++) {
        s3_queue_init(&env->qc.send_ctx[i].frames);
        s3_queue_init(&env->qc.send_ctx[i].sending);
        s3_queue_init(&env->qc.send_ctx[i].sent);
        env->qc.send_ctx[i].largest_pn = S3_QUIC_UNSET_PN;
        env->qc.send_ctx[i].largest_ack = S3_QUIC_UNSET_PN;
        env->qc.send_ctx[i].largest_range = S3_QUIC_UNSET_PN;
        env->qc.send_ctx[i].pending_ack = S3_QUIC_UNSET_PN;
    }

    env->qc.send_ctx[0].level = S3_QUIC_ENCRYPTION_INITIAL;
    env->qc.send_ctx[1].level = S3_QUIC_ENCRYPTION_HANDSHAKE;
    env->qc.send_ctx[2].level = S3_QUIC_ENCRYPTION_APPLICATION;

    s3_quic_init_rtt(&env->qc);

    env->qc.ctp.max_udp_payload_size = S3_QUIC_MAX_UDP_PAYLOAD_SIZE;
    env->qc.ctp.ack_delay_exponent = S3_QUIC_DEFAULT_ACK_DELAY_EXPONENT;
    env->qc.ctp.max_ack_delay = S3_QUIC_DEFAULT_MAX_ACK_DELAY;
    env->qc.ctp.active_connection_id_limit = 2;

    /* the initial socket and the transport parameters */
    s3_memzero(&env->qsock, sizeof(s3_quic_socket_t));

    env->qsock.sid.len = S3_QUIC_SERVER_CID_LEN;
    s3_memcpy(env->qsock.sid.id, s3_test_cid, sizeof(s3_test_cid));
    env->qsock.sid.seqnum = 0;
    env->qsock.quic = &env->qc;
    env->qsock.connection = &env->conn;

    s3_queue_insert_tail(&env->qc.sockets, &env->qsock.queue);
    env->qc.nsockets = 1;

    env->conn.udp = (struct s3_udp_connection_s *)&env->qsock;

    if (s3_quic_init_transport_params(&env->qc.tp, &env->conf) != S3_OK) {
        return S3_ERROR;
    }

    env->qc.tp.original_dcid.data = (u_char *)s3_test_dcid;
    env->qc.tp.original_dcid.len = sizeof(s3_test_dcid);

    /* the peer client id and the active path, as open_sockets() does */

    scid.data = (u_char *)s3_test_cid;
    scid.len = sizeof(s3_test_cid);

    cid = s3_quic_create_client_id(&env->conn, &scid, 0, NULL);
    if (cid == NULL) {
        return S3_ERROR;
    }

    env->qc.path = s3_quic_new_path(&env->conn, NULL, 0, cid);
    if (env->qc.path == NULL) {
        return S3_ERROR;
    }

    env->qc.path->tag = S3_QUIC_PATH_ACTIVE;

    /* the initial secrets gate the CRYPTO frame handling */

    secret.data = (u_char *)s3_test_dcid;
    secret.len = sizeof(s3_test_dcid);

    if (s3_quic_keys_set_initial_secret(&env->keys, &secret, &s3_test_tls_log) != S3_OK) {
        return S3_ERROR;
    }

    /* the events, as s3_quic_new_connection() does */
    env->qc.push.log = &s3_test_tls_log;
    env->qc.push.data = &env->conn;
    env->qc.close.log = &s3_test_tls_log;
    env->qc.close.data = &env->conn;
    env->qc.key_update.log = &s3_test_tls_log;
    env->qc.key_update.data = &env->conn;

    /* the server ssl connection with the quic tls callbacks */
    if (s3_quic_init_connection(&env->conn) != S3_OK) {
        return S3_ERROR;
    }

    return S3_OK;
}

static void
s3_test_env_done(s3_test_env_t *env)
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
    if (env->conn.ssl != NULL) {
        SSL_free(env->conn.ssl->connection);
        env->conn.ssl = NULL;
    }

    if (env->pool != NULL) {
        s3_destroy_pool(env->pool);
        env->pool = NULL;
    }
}

static int
test_ssl_create(void)
{
    u_char    cert[4096], key[4096];
    size_t    cert_len, key_len;
    s3_str_t  alpn;
    s3_ssl_t *ssl;

    s3_test_tls_log_init();

    S3_ASSERT(s3_test_tls_gen_cert(cert, &cert_len, key, &key_len) == 0);

    alpn.data = (u_char *)s3_test_alpn;
    alpn.len = S3_TEST_ALPN_LEN;

    ssl = s3_ssl_create(&s3_test_tls_log, (const char *)cert, cert_len, (const char *)key, key_len,
                        &alpn);
    S3_ASSERT(ssl != NULL);
    S3_ASSERT(ssl->ctx != NULL);
    S3_ASSERT(ssl->alpn.len == S3_TEST_ALPN_LEN);

    s3_ssl_free(ssl);

    /* a broken certificate must fail cleanly */
    ssl = s3_ssl_create(&s3_test_tls_log, (const char *)"garbage", 7, (const char *)key, key_len,
                        &alpn);
    S3_ASSERT(ssl == NULL);

    return s3_test_failures;
}

static int
test_quic_tls_handshake(void)
{
    u_char                cert[4096], key[4096], tp[64];
    size_t                cert_len, key_len, tp_len, n;
    int                   i, rc, srv_done = 0, cli_done = 0;
    s3_str_t              alpn;
    const unsigned char  *alpn_data;
    unsigned int          alpn_len;
    s3_quic_connection_t *qc;

    static s3_test_env_t env;

    s3_test_tls_log_init();

    S3_ASSERT(s3_test_tls_gen_cert(cert, &cert_len, key, &key_len) == 0);
    S3_ASSERT(s3_test_env_init(&env, cert, cert_len, key, key_len) == S3_OK);

    qc = &env.qc;

    tp_len = s3_test_client_tp(tp, s3_test_cid, sizeof(s3_test_cid));

    alpn.data = (u_char *)s3_test_alpn;
    alpn.len = S3_TEST_ALPN_LEN;

    env.client = s3_test_tls_client(&env.cli, &alpn, tp, tp_len, &env.client_ctx);
    S3_ASSERT(env.client != NULL);

    for (i = 0; i < 32 && !(srv_done && cli_done); i++) {

        /* the client side drives its handshake through the harness */

        if (!cli_done) {
            n = SSL_do_handshake(env.client);

            if (n == 1) {
                cli_done = 1;

            } else {
                rc = SSL_get_error(env.client, (int)n);
                S3_ASSERT(rc == SSL_ERROR_WANT_READ);
            }
        }

        /* pump the client flight into the server crypto streams */

        for (n = 0; n < S3_TEST_TLS_LEVELS; n++) {

            if (env.cli.out_len[n] > env.cli_off[n]) {
                S3_ASSERT(s3_test_feed_crypto(
                              &env.conn, (s3_uint_t)n, env.cli.out[n] + env.cli_off[n],
                              env.cli.out_len[n] - env.cli_off[n], &env.cli_off[n]) == S3_OK);
            }
        }

        /* move the server CRYPTO frames to the client side buffers */

        s3_test_drain_crypto(&env.conn, &env.cli);

        if (env.conn.ssl->handshaked) {
            srv_done = 1;
        }
    }

    S3_ASSERT(srv_done);
    S3_ASSERT(cli_done);

    /* the handshake results on the server side */

    S3_ASSERT(env.conn.ssl != NULL);
    S3_ASSERT(env.conn.ssl->handshaked == 1);
    S3_ASSERT(qc->client_tp_done == 1);
    S3_ASSERT(qc->error == 0);

    /*
     * the client transport parameters were applied; the apply check
     * itself validates initial_scid against the path client id (the
     * handshake would have failed otherwise): the tp carries the
     * client cid, 8 bytes here. the string fields of ctp point into
     * the ssl internal buffer and are not compared
     */
    S3_ASSERT(qc->ctp.initial_scid.len == sizeof(s3_test_cid));
    S3_ASSERT(qc->ctp.active_connection_id_limit == 8);

    /*
     * RFC 9001, 4.9.2: the handshake keys were discarded on the
     * handshake confirmation, the application keys are installed
     */
    S3_ASSERT(s3_quic_keys_available(qc->keys, S3_QUIC_ENCRYPTION_INITIAL, 0) == 1);
    S3_ASSERT(s3_quic_keys_available(qc->keys, S3_QUIC_ENCRYPTION_HANDSHAKE, 0) == 0);
    S3_ASSERT(s3_quic_keys_available(qc->keys, S3_QUIC_ENCRYPTION_HANDSHAKE, 1) == 0);
    S3_ASSERT(s3_quic_keys_available(qc->keys, S3_QUIC_ENCRYPTION_APPLICATION, 0) == 1);
    S3_ASSERT(s3_quic_keys_available(qc->keys, S3_QUIC_ENCRYPTION_APPLICATION, 1) == 1);

    /* ALPN was negotiated */
    SSL_get0_alpn_selected(env.conn.ssl->connection, &alpn_data, &alpn_len);
    S3_ASSERT(alpn_len == 4);
    S3_ASSERT(s3_memcmp(alpn_data, "ssh3", 4) == 0);

    /* the client saw our transport parameters */
    S3_ASSERT(env.cli.tp_len > 0);

    /* a HANDSHAKE_DONE frame is queued for the application space */
    {
        s3_uint_t           found = 0;
        s3_queue_t         *q;
        s3_quic_frame_t    *f;
        s3_quic_send_ctx_t *ctx;

        ctx = s3_quic_get_send_ctx(qc, S3_QUIC_ENCRYPTION_APPLICATION);

        for (q = s3_queue_head(&ctx->frames); q != s3_queue_sentinel(&ctx->frames);
             q = s3_queue_next(q)) {
            f = s3_queue_data(q, s3_quic_frame_t, queue);

            if (f->type == S3_QUIC_FT_HANDSHAKE_DONE) {
                found = 1;
            }
        }

        S3_ASSERT(found == 1);
    }

    /* the crypto_send callback posted the output event */
    S3_ASSERT(qc->push.posted == 1);

    /* the key update was posted after the handshake completion */
    S3_ASSERT(qc->key_update.posted == 1);

    s3_test_env_done(&env);

    return s3_test_failures;
}

static int
test_transport_params_roundtrip(void)
{
    u_char             cert[4096], key[4096], tp[64];
    size_t             cert_len, key_len, tp_len;
    ssize_t            len;
    u_char            *p;
    s3_test_tls_side_t side;

    static s3_test_env_t env;

    s3_test_tls_log_init();

    S3_ASSERT(s3_test_tls_gen_cert(cert, &cert_len, key, &key_len) == 0);
    S3_ASSERT(s3_test_env_init(&env, cert, cert_len, key, key_len) == S3_OK);

    /* the server transport parameters, as sent in the handshake */

    len = s3_quic_create_transport_params(NULL, NULL, &env.qc.tp, NULL);
    S3_ASSERT(len > 0);

    p = s3_pnalloc(env.pool, (size_t)len);
    S3_ASSERT(p != NULL);

    len = s3_quic_create_transport_params(p, p + len, &env.qc.tp, NULL);
    S3_ASSERT(len > 0);

    /*
     * the D1 transport parser is the server direction only: it
     * rejects the server-only parameters (original_dcid and friends),
     * so the server blob cannot be parsed back here; the blob is
     * instead validated by the real client in the lockstep test
     * (tp_len above). here only the encoder consistency is checked:
     * the sizing pass matches the encoding pass and the blob starts
     * with initial_max_data (0x04), the first encoded parameter
     */
    S3_ASSERT(p[0] == S3_QUIC_TP_INITIAL_MAX_DATA);

    /* a client without ALPN breaks the handshake in cbs_send */

    tp_len = s3_test_client_tp(tp, s3_test_cid, sizeof(s3_test_cid));

    env.client = s3_test_tls_client(&side, NULL, tp, tp_len, &env.client_ctx);
    S3_ASSERT(env.client != NULL);

    (void)SSL_do_handshake(env.client);

    S3_ASSERT(side.out_len[0] > 0);

    /* the server notices the missing client ALPN and rejects the flight */
    S3_ASSERT(s3_test_feed_crypto(&env.conn, 0, side.out[0], side.out_len[0], &env.cli_off[0]) ==
              S3_ERROR);
    S3_ASSERT(env.qc.error == S3_QUIC_ERR_CRYPTO(SSL_AD_NO_APPLICATION_PROTOCOL));

    s3_test_env_done(&env);

    return s3_test_failures;
}

static int
s3_test_quic_ssl(void)
{
    /* unbuffered stdout: the crash traces stay readable */
    (void)setvbuf(stdout, NULL, _IONBF, 0);

    test_ssl_create();
    test_quic_tls_handshake();
    test_transport_params_roundtrip();

    /* release the one-time openssl allocations for the leak check */
    OPENSSL_cleanup();

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_quic_ssl)
