/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <stdarg.h>

#include <s3_ssl.h>
#include <s3_string.h>

static int s3_ssl_alpn_select_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                                 const unsigned char *in, unsigned int inlen, void *arg);

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

    if (ssl->alpn.data != NULL) {
        s3_free(ssl->alpn.data);
    }

    s3_free(ssl);
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

    return ssl;
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
