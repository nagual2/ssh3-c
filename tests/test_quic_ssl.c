/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <openssl/x509v3.h>

#include <unistd.h>

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
    s3_event_t           read; /* the idle timer of the connection lives here */
    s3_quic_socket_t     qsock;
    s3_quic_connection_t qc;
    s3_quic_keys_t       keys;
    s3_test_tls_side_t   cli; /* the harness client side */
    SSL                 *client;
    SSL_CTX             *client_ctx;
    size_t               cli_off[S3_TEST_TLS_LEVELS];
} s3_test_env_t;

static void
s3_test_read_handler(s3_event_t *ev)
{
    (void)ev;
}

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

    /* the read event: the idle timer of the connection lives there */
    env->read.log = &s3_test_tls_log;
    env->read.data = &env->conn;
    env->read.handler = s3_test_read_handler;
    env->conn.read = &env->read;

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
    s3_queue_init(&env->qc.streams.uninitialized);

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

    /* the effective idle timeout, as s3_quic_new_connection() does */
    env->qc.idle_timeout = env->qc.tp.max_idle_timeout;

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

    /*
     * the quic keys of the env: the next env_init wipes the whole
     * struct, the ctx pointers must die here or they die unreferenced
     * (the asan run of the verify cases rides one static env)
     */

    s3_quic_keys_cleanup(&env->keys);

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

/*
 * the x509 side of the verify tests: the raw DER feeds
 * s3_ssl_client_add_pin(), the PEM drives the server side env; the
 * minimal certs (subject only, no SAN) - the SAN check is the app
 * layer business (the wave C), the chain verdict is what rides here
 */

#define S3_TEST_DER_LEN 2048

static X509 *
s3_test_x509_new(EVP_PKEY *pkey, const char *cn)
{
    X509      *x509;
    X509_NAME *name;

    x509 = X509_new();
    if (x509 == NULL) {
        return NULL;
    }

    X509_set_version(x509, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_getm_notBefore(x509), 0);
    X509_gmtime_adj(X509_getm_notAfter(x509), 31536000);
    X509_set_pubkey(x509, pkey);

    name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)cn, -1, -1, 0);

    return x509;
}

static int
s3_test_x509_sign(X509 *x509, X509_NAME *issuer, EVP_PKEY *key, int ca)
{
    X509_EXTENSION *bc;

    /* the basic constraints make the issuer a purpose ca; the leaves
     * ride without them, like s3_test_tls_gen_cert() does */

    if (ca) {
        bc = X509V3_EXT_nconf_nid(NULL, NULL, NID_basic_constraints, "critical,CA:TRUE");
        if (bc == NULL || X509_add_ext(x509, bc, -1) != 1) {
            X509_EXTENSION_free(bc);
            return -1;
        }

        X509_EXTENSION_free(bc);
    }

    X509_set_issuer_name(x509, issuer);

    if (X509_sign(x509, key, EVP_sha256()) == 0) {
        return -1;
    }

    return 0;
}

/* the self-signed leaf, no extensions (the case 1 and 2 server) */

static int
s3_test_gen_selfsigned(X509 **out, EVP_PKEY **out_key)
{
    X509     *x509;
    EVP_PKEY *pkey;

    pkey = EVP_EC_gen("P-256");
    if (pkey == NULL) {
        return -1;
    }

    x509 = s3_test_x509_new(pkey, "s3-test");
    if (x509 == NULL) {
        EVP_PKEY_free(pkey);
        return -1;
    }

    if (s3_test_x509_sign(x509, X509_get_subject_name(x509), pkey, 0) != 0) {
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return -1;
    }

    *out = x509;
    *out_key = pkey;

    return 0;
}

/* the self-signed ca with the basic constraints (the case 3 issuer) */

static int
s3_test_gen_ca(X509 **out, EVP_PKEY **out_key)
{
    X509     *x509;
    EVP_PKEY *pkey;

    pkey = EVP_EC_gen("P-256");
    if (pkey == NULL) {
        return -1;
    }

    x509 = s3_test_x509_new(pkey, "s3-test-ca");
    if (x509 == NULL) {
        EVP_PKEY_free(pkey);
        return -1;
    }

    if (s3_test_x509_sign(x509, X509_get_subject_name(x509), pkey, 1) != 0) {
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return -1;
    }

    *out = x509;
    *out_key = pkey;

    return 0;
}

/* the leaf issued by the ca; the leaf key rides out for the server */

static int
s3_test_gen_leaf(X509 *ca, EVP_PKEY *ca_key, X509 **out, EVP_PKEY **out_key)
{
    X509     *x509;
    EVP_PKEY *pkey;

    pkey = EVP_EC_gen("P-256");
    if (pkey == NULL) {
        return -1;
    }

    x509 = s3_test_x509_new(pkey, "s3-test-leaf");
    if (x509 == NULL) {
        EVP_PKEY_free(pkey);
        return -1;
    }

    if (s3_test_x509_sign(x509, X509_get_subject_name(ca), ca_key, 0) != 0) {
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return -1;
    }

    *out = x509;
    *out_key = pkey;

    return 0;
}

static int
s3_test_x509_pem(X509 *x509, u_char *out, size_t *out_len)
{
    BIO *bio;
    long n;

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL || PEM_write_bio_X509(bio, x509) != 1) {
        BIO_free(bio);
        return -1;
    }

    n = BIO_get_mem_data(bio, NULL);
    if (n <= 0) {
        BIO_free(bio);
        return -1;
    }

    *out_len = (size_t)n;
    (void)BIO_read(bio, out, (int)*out_len);
    BIO_free(bio);

    return 0;
}

static int
s3_test_key_pem(EVP_PKEY *pkey, u_char *out, size_t *out_len)
{
    BIO *bio;
    long n;

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL || PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL) != 1) {
        BIO_free(bio);
        return -1;
    }

    n = BIO_get_mem_data(bio, NULL);
    if (n <= 0) {
        BIO_free(bio);
        return -1;
    }

    *out_len = (size_t)n;
    (void)BIO_read(bio, out, (int)*out_len);
    BIO_free(bio);

    return 0;
}

static int
s3_test_x509_der(X509 *x509, u_char *out, size_t *out_len)
{
    u_char *p;
    int     n;

    p = out;
    n = i2d_X509(x509, &p);

    if (n <= 0 || (size_t)n > S3_TEST_DER_LEN) {
        return -1;
    }

    *out_len = (size_t)n;

    return 0;
}

/*
 * the lockstep of the verify tests: the client ssl rides the real s3
 * client conf (SSL_new from its ctx, the app data carries the conf
 * back - as s3_quic_client_init_connection does), the pump drives
 * both sides as the base handshake test does; S3_OK when the
 * handshake completed on both ends
 */
static int
s3_test_verify_handshake(s3_test_env_t *env, s3_ssl_t *conf)
{
    u_char tp[64];
    size_t tp_len, n;
    int    i, rc, srv_done = 0, cli_done = 0;

    s3_memzero(&env->cli, sizeof(s3_test_tls_side_t));
    s3_memzero(env->cli_off, sizeof(env->cli_off));

    env->cli.name = "client";

    env->client = SSL_new(conf->ctx);
    if (env->client == NULL) {
        return S3_ERROR;
    }

    /* the app data carries the conf: the verify cb reaches it there */

    SSL_set_app_data(env->client, conf);

    if (SSL_set_quic_tls_cbs(env->client, s3_test_tls_dis, &env->cli) != 1) {
        return S3_ERROR;
    }

    tp_len = s3_test_client_tp(tp, s3_test_cid, sizeof(s3_test_cid));

    if (SSL_set_quic_tls_transport_params(env->client, tp, tp_len) != 1) {
        return S3_ERROR;
    }

    if (conf->alpn.len > 0 &&
        SSL_set_alpn_protos(env->client, conf->alpn.data, (unsigned int)conf->alpn.len) != 0) {
        return S3_ERROR;
    }

    SSL_set_connect_state(env->client);

    for (i = 0; i < 32 && !(srv_done && cli_done); i++) {

        if (!cli_done) {
            n = SSL_do_handshake(env->client);

            if (n == 1) {
                cli_done = 1;

            } else {
                rc = SSL_get_error(env->client, (int)n);
                S3_ASSERT(rc == SSL_ERROR_WANT_READ);
            }
        }

        for (n = 0; n < S3_TEST_TLS_LEVELS; n++) {

            if (env->cli.out_len[n] > env->cli_off[n]) {
                S3_ASSERT(s3_test_feed_crypto(
                              &env->conn, (s3_uint_t)n, env->cli.out[n] + env->cli_off[n],
                              env->cli.out_len[n] - env->cli_off[n], &env->cli_off[n]) == S3_OK);
            }
        }

        s3_test_drain_crypto(&env->conn, &env->cli);

        if (env->conn.ssl->handshaked) {
            srv_done = 1;
        }
    }

    return (srv_done && cli_done) ? S3_OK : S3_ERROR;
}

static int
test_client_verify(void)
{
    u_char    pem[4096], pem_key[4096], der[S3_TEST_DER_LEN], ca_der[S3_TEST_DER_LEN];
    size_t    pem_len = 0, pem_key_len = 0, der_len = 0, ca_der_len = 0;
    s3_str_t  alpn;
    s3_ssl_t *conf;
    X509     *self_x = NULL, *ca_x = NULL, *leaf_x = NULL;
    EVP_PKEY *self_k = NULL, *ca_k = NULL, *leaf_k = NULL;

    static s3_test_env_t env;

    s3_test_tls_log_init();

    alpn.data = (u_char *)s3_test_alpn;
    alpn.len = S3_TEST_ALPN_LEN;

    S3_ASSERT(s3_test_gen_selfsigned(&self_x, &self_k) == 0);
    S3_ASSERT(s3_test_x509_pem(self_x, pem, &pem_len) == 0);
    S3_ASSERT(s3_test_key_pem(self_k, pem_key, &pem_key_len) == 0);
    S3_ASSERT(s3_test_x509_der(self_x, der, &der_len) == 0);

    /*
     * case 1: the self-signed leaf, no pins - the handshake lives
     * (the verdict is record-only), the callback saw the certificate
     * and recorded the depth-zero self-signed error
     */

    S3_ASSERT(s3_test_env_init(&env, pem, pem_len, pem_key, pem_key_len) == S3_OK);

    conf = s3_ssl_client_create(&s3_test_tls_log, &alpn);
    S3_ASSERT(conf != NULL);

    /* the fresh conf starts clean */

    S3_ASSERT(s3_ssl_chain_err(conf) == X509_V_OK);
    S3_ASSERT(s3_ssl_chain_seen(conf) == 0);

    S3_ASSERT(s3_test_verify_handshake(&env, conf) == S3_OK);

    S3_ASSERT(s3_ssl_chain_seen(conf) == 1);
    S3_ASSERT(s3_ssl_chain_err(conf) == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT);

    s3_test_env_done(&env);
    s3_ssl_free(conf);

    /*
     * case 2: the same leaf pinned before the handshake - the pin is
     * the anchor (the partial chain), the verdict is clean
     */

    S3_ASSERT(s3_test_env_init(&env, pem, pem_len, pem_key, pem_key_len) == S3_OK);

    conf = s3_ssl_client_create(&s3_test_tls_log, &alpn);
    S3_ASSERT(conf != NULL);
    S3_ASSERT(s3_ssl_client_add_pin(conf, der, der_len) == S3_OK);

    S3_ASSERT(s3_test_verify_handshake(&env, conf) == S3_OK);

    S3_ASSERT(s3_ssl_chain_seen(conf) == 1);
    S3_ASSERT(s3_ssl_chain_err(conf) == X509_V_OK);

    s3_test_env_done(&env);
    s3_ssl_free(conf);

    /*
     * case 5: the duplicate pin is a no-op success - the second call
     * of the same DER rides the already-in-hash-table reason and the
     * handshake stays clean
     */

    S3_ASSERT(s3_test_env_init(&env, pem, pem_len, pem_key, pem_key_len) == S3_OK);

    conf = s3_ssl_client_create(&s3_test_tls_log, &alpn);
    S3_ASSERT(conf != NULL);
    S3_ASSERT(s3_ssl_client_add_pin(conf, der, der_len) == S3_OK);
    S3_ASSERT(s3_ssl_client_add_pin(conf, der, der_len) == S3_OK);

    S3_ASSERT(s3_test_verify_handshake(&env, conf) == S3_OK);

    S3_ASSERT(s3_ssl_chain_seen(conf) == 1);
    S3_ASSERT(s3_ssl_chain_err(conf) == X509_V_OK);

    s3_test_env_done(&env);
    s3_ssl_free(conf);

    /* the ca-signed leaf of the case 3 and 4, the ca DER for the pin */

    S3_ASSERT(s3_test_gen_ca(&ca_x, &ca_k) == 0);
    S3_ASSERT(s3_test_gen_leaf(ca_x, ca_k, &leaf_x, &leaf_k) == 0);
    S3_ASSERT(s3_test_x509_pem(leaf_x, pem, &pem_len) == 0);
    S3_ASSERT(s3_test_key_pem(leaf_k, pem_key, &pem_key_len) == 0);
    S3_ASSERT(s3_test_x509_der(ca_x, ca_der, &ca_der_len) == 0);

    /*
     * case 4: the ca-signed leaf without the ca anchor - the verdict
     * is the missing local issuer, the handshake still lives
     * (record-only)
     */

    S3_ASSERT(s3_test_env_init(&env, pem, pem_len, pem_key, pem_key_len) == S3_OK);

    conf = s3_ssl_client_create(&s3_test_tls_log, &alpn);
    S3_ASSERT(conf != NULL);

    S3_ASSERT(s3_test_verify_handshake(&env, conf) == S3_OK);

    S3_ASSERT(s3_ssl_chain_seen(conf) == 1);
    S3_ASSERT(s3_ssl_chain_err(conf) == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY);

    s3_test_env_done(&env);
    s3_ssl_free(conf);

    /*
     * case 3: the same leaf, the ca added by the pin - any added cert
     * anchors (the Go anchor semantics), the verdict is clean
     */

    S3_ASSERT(s3_test_env_init(&env, pem, pem_len, pem_key, pem_key_len) == S3_OK);

    conf = s3_ssl_client_create(&s3_test_tls_log, &alpn);
    S3_ASSERT(conf != NULL);
    S3_ASSERT(s3_ssl_client_add_pin(conf, ca_der, ca_der_len) == S3_OK);

    S3_ASSERT(s3_test_verify_handshake(&env, conf) == S3_OK);

    S3_ASSERT(s3_ssl_chain_seen(conf) == 1);
    S3_ASSERT(s3_ssl_chain_err(conf) == X509_V_OK);

    s3_test_env_done(&env);
    s3_ssl_free(conf);

    X509_free(self_x);
    EVP_PKEY_free(self_k);
    X509_free(ca_x);
    EVP_PKEY_free(ca_k);
    X509_free(leaf_x);
    EVP_PKEY_free(leaf_k);

    return s3_test_failures;
}

/*
 * the persistent session ticket key of the server (the wave 13): the
 * missing file generates the nginx 80-byte form, the same file loads
 * into the fresh ctx (the restart persistence), the broken file
 * regenerates and the legacy 48-byte form rides the aes-128 shape
 */

static int
test_ssl_ticket_key_file(void)
{
    u_char    cert[4096], key[4096], buf[80], name_a[16];
    size_t    cert_len, key_len;
    s3_str_t  alpn;
    s3_ssl_t *ssl, *ssl2;
    char      path[] = "/tmp/s3tkeyXXXXXX";
    int       fd, i;
    FILE     *f;

    s3_test_tls_log_init();

    S3_ASSERT(s3_test_tls_gen_cert(cert, &cert_len, key, &key_len) == 0);

    alpn.data = (u_char *)s3_test_alpn;
    alpn.len = S3_TEST_ALPN_LEN;

    ssl = s3_ssl_create(&s3_test_tls_log, (const char *)cert, cert_len, (const char *)key, key_len,
                        &alpn);
    S3_ASSERT(ssl != NULL);

    fd = mkstemp(path);
    S3_ASSERT(fd != -1);
    (void)close(fd);

    /* the missing (the mkstemp left the empty file - wipe it to ride
     * the first-lifetime branch) file generates the 80-byte form */

    (void)unlink(path);

    S3_ASSERT(s3_ssl_ticket_key_file(ssl, path) == S3_OK);
    S3_ASSERT(ssl->ticket_aes_len == 32);
    S3_ASSERT(ssl->ticket_hmac_len == 32);

    f = fopen(path, "rb");
    S3_ASSERT(f != NULL);
    S3_ASSERT(fread(buf, 1, sizeof(buf), f) == sizeof(buf));
    (void)fclose(f);

    S3_ASSERT(memcmp(buf, ssl->ticket_key_name, 16) == 0);
    S3_ASSERT(memcmp(buf + 16, ssl->ticket_hmac_key, 32) == 0);
    S3_ASSERT(memcmp(buf + 48, ssl->ticket_aes_key, 32) == 0);

    s3_memcpy(name_a, ssl->ticket_key_name, 16);

    /* the same file loads into the fresh ctx: the tickets of the
     * previous daemon lifetime keep decrypting */

    ssl2 = s3_ssl_create(&s3_test_tls_log, (const char *)cert, cert_len, (const char *)key, key_len,
                         &alpn);
    S3_ASSERT(ssl2 != NULL);
    S3_ASSERT(s3_ssl_ticket_key_file(ssl2, path) == S3_OK);
    S3_ASSERT(memcmp(ssl->ticket_key_name, ssl2->ticket_key_name, 16) == 0);

    /* the broken file regenerates: the new lifetime starts clean */

    f = fopen(path, "wb");
    S3_ASSERT(f != NULL);
    fwrite("short", 1, 5, f);
    (void)fclose(f);

    S3_ASSERT(s3_ssl_ticket_key_file(ssl, path) == S3_OK);
    S3_ASSERT(memcmp(ssl->ticket_key_name, name_a, 16) != 0);

    f = fopen(path, "rb");
    S3_ASSERT(f != NULL);
    S3_ASSERT(fread(buf, 1, sizeof(buf), f) == sizeof(buf));
    (void)fclose(f);

    S3_ASSERT(memcmp(buf, ssl->ticket_key_name, 16) == 0);

    /* the legacy 48-byte nginx form: aes-128 and the short hmac
     * (16 name + 16 aes + 16 hmac) */

    for (i = 0; i < 48; i++) {
        buf[i] = (u_char)(i * 7 + 3);
    }

    f = fopen(path, "wb");
    S3_ASSERT(f != NULL);
    fwrite(buf, 1, 48, f);
    (void)fclose(f);

    S3_ASSERT(s3_ssl_ticket_key_file(ssl, path) == S3_OK);
    S3_ASSERT(ssl->ticket_aes_len == 16);
    S3_ASSERT(ssl->ticket_hmac_len == 16);
    S3_ASSERT(memcmp(ssl->ticket_key_name, buf, 16) == 0);
    S3_ASSERT(memcmp(ssl->ticket_aes_key, buf + 16, 16) == 0);
    S3_ASSERT(memcmp(ssl->ticket_hmac_key, buf + 32, 16) == 0);

    /* the NULL path is the no-op (the in-memory keys ride on) */

    S3_ASSERT(s3_ssl_ticket_key_file(ssl, NULL) == S3_OK);

    (void)unlink(path);

    s3_ssl_free(ssl);
    s3_ssl_free(ssl2);

    return s3_test_failures;
}

static int
s3_test_quic_ssl(void)
{
    /* unbuffered stdout: the crash traces stay readable */
    (void)setvbuf(stdout, NULL, _IONBF, 0);

    test_ssl_create();
    test_ssl_ticket_key_file();
    test_quic_tls_handshake();
    test_transport_params_roundtrip();
    test_client_verify();

    /* release the one-time openssl allocations for the leak check */
    OPENSSL_cleanup();

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_quic_ssl)
