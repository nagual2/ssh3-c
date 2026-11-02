/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

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
     * tickets ride the internal server cache.  NO early-data
     * advertisement here (B21): SSL_CTX_set_max_early_data() leaks
     * into the NewSessionTicket as the TLS-level max_early_data_size,
     * and the strict QUIC clients (rustls) reject any value but 0 /
     * 0xffffffff there - in QUIC the 0-RTT limit rides the transport
     * parameter (RFC 9001 4.5), the advertisement comes back with the
     * real early-data wave
     */

    SSL_CTX_set_session_cache_mode(ssl->ctx, SSL_SESS_CACHE_SERVER);

    return ssl;

failed:

    s3_ssl_free(ssl);

    return NULL;
}

/* the hex of the DER form: the ticket is small, the form is plain */

static int
s3_ssl_ticket_hex(char *dst, size_t dst_cap, const u_char *src, size_t len)
{
    static const char digits[] = "0123456789abcdef";

    size_t i;

    if (dst_cap < len * 2 + 1) {
        return 0;
    }

    for (i = 0; i < len; i++) {
        dst[i * 2] = digits[src[i] >> 4];
        dst[i * 2 + 1] = digits[src[i] & 0xf];
    }

    dst[len * 2] = '\0';

    return 1;
}

static int
s3_ssl_ticket_unhex(u_char *dst, size_t *len, const char *src)
{
    size_t n, i;
    int    hi, lo;

    n = strlen(src);

    if (n == 0 || n % 2 != 0) {
        return 0;
    }

    for (i = 0; i < n; i += 2) {

        hi = src[i];
        lo = src[i + 1];

        if (hi >= '0' && hi <= '9') {
            hi -= '0';

        } else if (hi >= 'a' && hi <= 'f') {
            hi -= 'a' - 10;

        } else {
            return 0;
        }

        if (lo >= '0' && lo <= '9') {
            lo -= '0';

        } else if (lo >= 'a' && lo <= 'f') {
            lo -= 'a' - 10;

        } else {
            return 0;
        }

        dst[i / 2] = (u_char)(hi * 16 + lo);
    }

    *len = n / 2;

    return 1;
}

/*
 * the ticket cache line of the key: the whole file rewrites on every
 * store, the other hosts' lines ride through (the tmp+rename swap,
 * the owner-only mode)
 */

void
s3_ssl_ticket_persist(s3_ssl_t *ssl, SSL_SESSION *session)
{
    u_char  der[2048];
    u_char *p;
    char    hex[sizeof(der) * 2 + 1];
    char    line[1024 + sizeof(hex) + 2];
    char    body[16384];
    char    tmp[1100];
    int     len, fd, n;
    FILE   *src;

    len = i2d_SSL_SESSION(session, NULL);

    if (len <= 0 || (size_t)len > sizeof(der)) {
        return;
    }

    p = der;
    len = i2d_SSL_SESSION(session, &p);

    if (len <= 0 || !s3_ssl_ticket_hex(hex, sizeof(hex), der, (size_t)len)) {
        return;
    }

    n = snprintf(line, sizeof(line), "%s %s\n", ssl->ticket_key, hex);

    if (n <= 0 || (size_t)n >= sizeof(line)) {
        return;
    }

    /* the other lines ride through the rewrite */

    body[0] = '\0';

    src = fopen(ssl->ticket_path, "r");

    if (src != NULL) {

        while (fgets(line, sizeof(line), src) != NULL) {

            line[strcspn(line, "\n")] = '\0';

            if (strncmp(line, ssl->ticket_key, strlen(ssl->ticket_key)) == 0 &&
                line[strlen(ssl->ticket_key)] == ' ') {
                continue; /* our old line, the new one replaces it */
            }

            if (strlen(body) + strlen(line) + 2 < sizeof(body)) {
                strcat(body, line);
                strcat(body, "\n");
            }
        }

        fclose(src);
    }

    snprintf(tmp, sizeof(tmp), "%s.tmp", ssl->ticket_path);

    /* the .ssh3 directory may not exist yet (a run without the pin
     * writes never made it); the home above it may be missing too -
     * mkdir is not recursive, the two levels go one by one */

    {
        char        dir[1024], parent[1024];
        const char *slash = strrchr(ssl->ticket_path, '/');
        size_t      dlen = slash != NULL ? (size_t)(slash - ssl->ticket_path) : 0;

        if (dlen > 0 && dlen < sizeof(dir)) {

            memcpy(dir, ssl->ticket_path, dlen);
            dir[dlen] = '\0';

            if (mkdir(dir, 0700) != 0 && errno == ENOENT) {

                const char *up = strrchr(dir, '/');
                size_t      plen = up != NULL ? (size_t)(up - dir) : 0;

                if (plen > 0 && plen < sizeof(parent)) {

                    memcpy(parent, dir, plen);
                    parent[plen] = '\0';

                    (void)mkdir(parent, 0700);
                    (void)mkdir(dir, 0700);
                }
            }
        }
    }

    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);

    if (fd == -1) {
        return;
    }

    {
        ssize_t w;
        int     ok = 1;

        /* the key-hex line (the same form the load reads) */

        w = write(fd, body, strlen(body));
        ok = ok && w >= 0;

        w = write(fd, line, strlen(line));
        ok = ok && w >= 0;

        (void)close(fd);

        /* the failed tmp dies, the old file (if any) stays */

        if (!ok) {
            (void)unlink(tmp);
            return;
        }
    }

    (void)rename(tmp, ssl->ticket_path);
}

/*
 * the load side: the line of the key, the hex back to the DER, the
 * expiry of the ticket honors the session timeout; the failures are
 * silent - a cold cache is a plain 1-RTT dial
 */

void
s3_ssl_ticket_load(s3_ssl_t *ssl)
{
    u_char       der[2048];
    u_char      *p;
    size_t       dlen;
    char         line[2048];
    const char  *hex;
    long         age;
    SSL_SESSION *session;
    FILE        *src;

    src = fopen(ssl->ticket_path, "r");

    if (src == NULL) {
        return;
    }

    while (fgets(line, sizeof(line), src) != NULL) {

        line[strcspn(line, "\n")] = '\0';

        if (strncmp(line, ssl->ticket_key, strlen(ssl->ticket_key)) != 0 ||
            line[strlen(ssl->ticket_key)] != ' ') {
            continue;
        }

        hex = line + strlen(ssl->ticket_key) + 1;

        if (!s3_ssl_ticket_unhex(der, &dlen, hex) || dlen == 0) {
            break;
        }

        p = der;
        session = d2i_SSL_SESSION(NULL, (const unsigned char **)&p, (long)dlen);

        if (session == NULL) {
            ERR_clear_error();
            break;
        }

        /* the expired ticket rides no 0-RTT: drop it silently */

        age = (long)time(NULL) - (long)SSL_SESSION_get_time_ex(session);

        if (age > (long)SSL_SESSION_get_timeout(session)) {
            SSL_SESSION_free(session);
            break;
        }

        ssl->stored_session = session;

        break;
    }

    fclose(src);
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

    /*
     * the stored ticket of the resumption (the new-session callback
     * hands the ownership over): the wave 2 tickets really arrive, an
     * unfreed session died with the report of the sanitizers
     */

    if (ssl->stored_session != NULL) {
        SSL_SESSION_free(ssl->stored_session);
        ssl->stored_session = NULL;
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

    /* the persistence of the 0-RTT stage 2: the cache file rides */

    if (ssl_conf->ticket_path[0] != '\0') {
        s3_ssl_ticket_persist(ssl_conf, session);
    }

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
