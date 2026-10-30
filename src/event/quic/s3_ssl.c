/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include <s3_ssl.h>
#include <s3_string.h>

static int s3_ssl_alpn_select_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                                 const unsigned char *in, unsigned int inlen, void *arg);

/*
 * the interop probe: TLS secrets on stderr in the NSS keylog format,
 * enabled by the S3_KEYLOG environment variable
 */
static void
s3_ssl_keylog_cb(const SSL *ssl, const char *line)
{
    static int enabled = -1;

    (void)ssl;

    if (enabled < 0) {
        enabled = (getenv("S3_KEYLOG") != NULL);
    }

    if (enabled) {
        fprintf(stderr, "KEYLOG %s\n", line);
    }
}

/*
 * the keylog of the file set by s3_ssl_set_keylog_file(): the s3 conf
 * rides the ctx app data, every secret line appends and flushes (a
 * reader may follow the file while the handshake runs)
 */
static void
s3_ssl_keylog_file_cb(const SSL *ssl, const char *line)
{
    s3_ssl_t *ssl_conf;
    FILE     *file;

    ssl_conf = SSL_CTX_get_app_data(SSL_get_SSL_CTX((SSL *)ssl));

    file = ssl_conf != NULL ? ssl_conf->keylog_file : NULL;

    if (file == NULL) {
        return;
    }

    (void)fputs(line, file);
    (void)fputc('\n', file);
    (void)fflush(file);
}

s3_ssl_t *
s3_ssl_create(s3_log_t *log, const char *cert, size_t cert_len, const char *key, size_t key_len,
              const s3_str_t *alpn)
{
    BIO      *bio;
    X509     *x509;
    EVP_PKEY *pkey;
    s3_ssl_t *ssl;

    ssl = s3_alloc(sizeof(s3_ssl_t), log);
    if (ssl == NULL) {
        return NULL;
    }

    s3_memzero(ssl, sizeof(s3_ssl_t));

    ssl->log = log;

    if (alpn != NULL && alpn->len > 0) {
        ssl->alpn.data = s3_alloc(alpn->len, log);
        if (ssl->alpn.data == NULL) {
            s3_free(ssl);
            return NULL;
        }

        s3_memcpy(ssl->alpn.data, alpn->data, alpn->len);
        ssl->alpn.len = alpn->len;
    }

    ssl->ctx = SSL_CTX_new(TLS_server_method());
    if (ssl->ctx == NULL) {
        s3_ssl_error(log, 0, "SSL_CTX_new() failed");
        goto failed;
    }

    SSL_CTX_set_min_proto_version(ssl->ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ssl->ctx, TLS1_3_VERSION);

    bio = BIO_new_mem_buf(cert, (int)cert_len);
    if (bio == NULL) {
        s3_ssl_error(log, 0, "BIO_new_mem_buf(cert) failed");
        goto failed;
    }

    x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (x509 == NULL) {
        s3_ssl_error(log, 0, "PEM_read_bio_X509() failed");
        goto failed;
    }

    if (SSL_CTX_use_certificate(ssl->ctx, x509) != 1) {
        s3_ssl_error(log, 0, "SSL_CTX_use_certificate() failed");
        X509_free(x509);
        goto failed;
    }

    X509_free(x509);

    bio = BIO_new_mem_buf(key, (int)key_len);
    if (bio == NULL) {
        s3_ssl_error(log, 0, "BIO_new_mem_buf(key) failed");
        goto failed;
    }

    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (pkey == NULL) {
        s3_ssl_error(log, 0, "PEM_read_bio_PrivateKey() failed");
        goto failed;
    }

    if (SSL_CTX_use_PrivateKey(ssl->ctx, pkey) != 1) {
        s3_ssl_error(log, 0, "SSL_CTX_use_PrivateKey() failed");
        EVP_PKEY_free(pkey);
        goto failed;
    }

    EVP_PKEY_free(pkey);

    if (ssl->alpn.len > 0) {
        SSL_CTX_set_alpn_select_cb(ssl->ctx, s3_ssl_alpn_select_cb, ssl);
    }

    /*
     * the session resumption groundwork of the 0-RTT stage 1: the
     * tickets ride the internal server cache, the early-data
     * advertisement arms the per-SSL enable hook of
     * s3_quic_init_connection - the client attempts the early flight,
     * the 425 gate of the CONNECT keeps the auth out of the replay
     * window (RFC 8470)
     */

    SSL_CTX_set_session_cache_mode(ssl->ctx, SSL_SESS_CACHE_SERVER);
    SSL_CTX_set_max_early_data(ssl->ctx, 16384);

    return ssl;

failed:

    s3_ssl_free(ssl);

    return NULL;
}

void
s3_ssl_free(s3_ssl_t *ssl)
{
    if (ssl == NULL) {
        return;
    }

    if (ssl->ctx != NULL) {
        SSL_CTX_free(ssl->ctx);
    }

    if (ssl->keylog_file != NULL) {
        (void)fclose(ssl->keylog_file);
    }

    if (ssl->alpn.data != NULL) {
        s3_free(ssl->alpn.data);
    }

    s3_free(ssl);
}

static int
s3_ssl_client_new_session_cb(SSL *ssl, SSL_SESSION *session)
{
    s3_ssl_t *ssl_conf;

    /* the newest ticket wins: the per-process store of the single
     * host the CLI dials (the Control Master connections reuse it),
     * the persistence across the runs lands with the 0-RTT stage 2 */

    ssl_conf = SSL_get_app_data(ssl);

    if (ssl_conf == NULL) {
        SSL_SESSION_free(session);
        return 0;
    }

    if (ssl_conf->stored_session != NULL) {
        SSL_SESSION_free(ssl_conf->stored_session);
    }

    ssl_conf->stored_session = session;

    return 1;
}

s3_ssl_t *
s3_ssl_client_create(s3_log_t *log, const s3_str_t *alpn)
{
    s3_ssl_t *ssl;

    ssl = s3_alloc(sizeof(s3_ssl_t), log);
    if (ssl == NULL) {
        return NULL;
    }

    s3_memzero(ssl, sizeof(s3_ssl_t));

    ssl->log = log;

    if (alpn != NULL && alpn->len > 0) {
        ssl->alpn.data = s3_alloc(alpn->len, log);
        if (ssl->alpn.data == NULL) {
            s3_free(ssl);
            return NULL;
        }

        s3_memcpy(ssl->alpn.data, alpn->data, alpn->len);
        ssl->alpn.len = alpn->len;
    }

    ssl->ctx = SSL_CTX_new(TLS_client_method());
    if (ssl->ctx == NULL) {
        s3_ssl_error(log, 0, "SSL_CTX_new() failed");
        s3_ssl_free(ssl);
        return NULL;
    }

    SSL_CTX_set_min_proto_version(ssl->ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ssl->ctx, TLS1_3_VERSION);

    /* the interop probe accepts any peer certificate for now */
    SSL_CTX_set_verify(ssl->ctx, SSL_VERIFY_NONE, NULL);

    SSL_CTX_set_keylog_callback(ssl->ctx, s3_ssl_keylog_cb);

    /* the client keeps no internal session cache: the tickets land in
     * the new-session callback (the store of s3_ssl_t) */

    SSL_CTX_set_session_cache_mode(ssl->ctx,
                                   SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
    SSL_CTX_sess_set_new_cb(ssl->ctx, s3_ssl_client_new_session_cb);

    return ssl;
}

s3_int_t
s3_ssl_set_keylog_file(s3_ssl_t *ssl, const char *path)
{
    FILE *file;

    if (ssl == NULL || ssl->ctx == NULL) {
        return S3_ERROR;
    }

    if (path == NULL) {

        /* the clear: the default probe callback comes back */

        ssl->keylog_file = NULL;
        SSL_CTX_set_keylog_callback(ssl->ctx, s3_ssl_keylog_cb);

        return S3_OK;
    }

    file = fopen(path, "a");

    if (file == NULL) {
        s3_ssl_error(ssl->log, 0, "fopen(\"%s\") failed", path);
        return S3_ERROR;
    }

    ssl->keylog_file = file;

    /* the callback resolves the conf (and the file) through the ctx */

    SSL_CTX_set_app_data(ssl->ctx, ssl);
    SSL_CTX_set_keylog_callback(ssl->ctx, s3_ssl_keylog_file_cb);

    return S3_OK;
}

static int
s3_ssl_alpn_select_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                      const unsigned char *in, unsigned int inlen, void *arg)
{
    s3_ssl_t *ssl_conf = arg;
    int       rc;

    (void)ssl;

    rc = SSL_select_next_proto((unsigned char **)out, outlen, ssl_conf->alpn.data,
                               (unsigned int)ssl_conf->alpn.len, in, inlen);

    if (rc != OPENSSL_NPN_NEGOTIATED) {
        /*
         * no overlap: leave the selection empty, the quic layer
         * breaks the handshake in the crypto_send callback
         */
        return SSL_TLSEXT_ERR_NOACK;
    }

    return SSL_TLSEXT_ERR_OK;
}

s3_int_t
s3_ssl_create_connection(s3_ssl_t *ssl, s3_connection_t *c)
{
    s3_ssl_conn_t *ssl_conn;

    ssl_conn = s3_pcalloc(c->pool, sizeof(s3_ssl_conn_t));
    if (ssl_conn == NULL) {
        return S3_ERROR;
    }

    ssl_conn->connection = SSL_new(ssl->ctx);
    if (ssl_conn->connection == NULL) {
        s3_ssl_error(c->log, 0, "SSL_new() failed");
        return S3_ERROR;
    }

    SSL_set_accept_state(ssl_conn->connection);

    c->ssl = ssl_conn;

    return S3_OK;
}

s3_int_t
s3_ssl_shutdown(s3_connection_t *c)
{
    int            n, sslerr, mode;
    s3_ssl_conn_t *ssl_conn;

    ssl_conn = c->ssl;

    if (ssl_conn == NULL || ssl_conn->connection == NULL) {
        return S3_OK;
    }

    /* the quic layer does not wait for the peer close_notify */
    mode =
        ssl_conn->no_wait_shutdown ? SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN : SSL_SENT_SHUTDOWN;

    SSL_set_quiet_shutdown(ssl_conn->connection, 1);
    SSL_set_shutdown(ssl_conn->connection, mode);

    if (ssl_conn->no_wait_shutdown) {
        SSL_free(ssl_conn->connection);
        c->ssl = NULL;
        return S3_OK;
    }

    n = SSL_shutdown(ssl_conn->connection);

    if (n == 1) {
        SSL_free(ssl_conn->connection);
        c->ssl = NULL;
        return S3_OK;
    }

    sslerr = SSL_get_error(ssl_conn->connection, n);

    if (sslerr == SSL_ERROR_WANT_READ || sslerr == SSL_ERROR_WANT_WRITE) {
        return S3_AGAIN;
    }

    s3_ssl_error(c->log, 0, "SSL_shutdown() failed");

    SSL_free(ssl_conn->connection);
    c->ssl = NULL;

    return S3_ERROR;
}

void
s3_ssl_error(s3_log_t *log, s3_err_t err, const char *fmt, ...)
{
    va_list       args;
    u_char       *p, *last;
    u_char        buf[S3_MAX_ERROR_STR];
    u_char        str[S3_MAX_ERROR_STR];
    size_t        n;
    unsigned long e;

    last = buf + sizeof(buf);

    p = s3_cpymem(buf, "ssl ", sizeof("ssl ") - 1);

    va_start(args, fmt);
    p = s3_vslprintf(p, last, fmt, args);
    va_end(args);

    if (p > last - 2) {
        p = last - 2;
    }

    for (;;) {

        e = ERR_get_error();

        if (e == 0) {
            break;
        }

        if (p > last - 2) {
            break;
        }

        *p++ = ':';
        *p++ = ' ';

        ERR_error_string_n(e, (char *)str, sizeof(str));

        n = s3_strlen(str);

        if (p + n > last - 2) {
            n = (size_t)(last - 2 - p);
        }

        p = s3_cpymem(p, str, n);
    }

    if (p > last - 1) {
        p = last - 1;
    }

    *p++ = '\0';

    s3_log_error(S3_LOG_ALERT, log, err, "%s", buf);
}
