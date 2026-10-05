/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the minimal HTTP/1.1 client over an OpenSSL BIO: one blocking
 * request, the response read to the Connection: close EOF, the body
 * handed out as an s3_alloc()ed view; the OIDC fetcher of the
 * discovery/JWKS/token endpoints (no curl in the product)
 */

#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <s3_https_fetch.h>

/* the response cap, a bigger body is a wiring mistake */

#define S3_HTTPS_RESPONSE_MAX (4 * 1024 * 1024)

/* the blocking socket timeout of one phase (connect, handshake, read) */

#define S3_HTTPS_TIMEOUT_SEC 15

static s3_int_t
s3_https_url_split(const char *url, unsigned *tls, char *host, size_t host_max, char *port,
                   size_t port_max, const char **path)
{
    const char *p, *slash;
    char       *colon;
    size_t      n;

    if (s3_strncmp(url, "https://", 8) == 0) {
        *tls = 1;
        p = url + 8;

    } else if (s3_strncmp(url, "http://", 7) == 0) {
        *tls = 0;
        p = url + 7;

    } else {
        return S3_ERROR;
    }

    slash = strchr(p, '/');

    if (slash == NULL) {
        *path = "/";
        n = s3_strlen(p);

    } else {
        *path = slash;
        n = (size_t)(slash - p);
    }

    if (n == 0 || n + 1 > host_max) {
        return S3_ERROR;
    }

    s3_memcpy(host, p, n);
    host[n] = '\0';

    colon = strrchr(host, ':');

    /* the bare host or an unbracketed IPv6 is not the fetcher shape */

    if (colon != NULL && strchr(host, ':') == colon) {

        if (s3_strlen(colon + 1) + 1 > port_max) {
            return S3_ERROR;
        }

        s3_memcpy(port, colon + 1, s3_strlen(colon + 1) + 1);
        *colon = '\0';

    } else {
        snprintf(port, port_max, "%s", *tls ? "443" : "80");
    }

    return S3_OK;
}

static void
s3_https_socket_timeout(int fd)
{
    struct timeval tv;

    tv.tv_sec = S3_HTTPS_TIMEOUT_SEC;
    tv.tv_usec = 0;

    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

/* the connected (and handshaked for https) BIO; the ctx out lives
 * until the caller freed the bio chain, the ssl does not own it */

static BIO *
s3_https_connect(const char *host, const char *port, unsigned tls, const char *ca_file,
                 SSL_CTX **ctx_out)
{
    SSL_CTX *ctx;
    SSL     *ssl;
    BIO     *bio;
    int      fd;

    *ctx_out = NULL;

    bio = BIO_new_connect(host);

    if (bio == NULL) {
        return NULL;
    }

    BIO_set_conn_port(bio, port);

    if (BIO_do_connect(bio) != 1) {
        BIO_free_all(bio);
        return NULL;
    }

    fd = BIO_get_fd(bio, NULL);

    if (fd >= 0) {
        s3_https_socket_timeout(fd);
    }

    if (!tls) {
        return bio;
    }

    ctx = SSL_CTX_new(TLS_client_method());

    if (ctx == NULL) {
        BIO_free_all(bio);
        return NULL;
    }

    if (ca_file != NULL) {

        /* the verified mode: the pinned trust store, the hostname match */

        if (SSL_CTX_load_verify_locations(ctx, ca_file, NULL) != 1) {
            SSL_CTX_free(ctx);
            BIO_free_all(bio);
            return NULL;
        }

        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    } else {

        /* the loopback test issuers ship a self-signed certificate */

        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }

    ssl = SSL_new(ctx);

    if (ssl == NULL) {
        SSL_CTX_free(ctx);
        BIO_free_all(bio);
        return NULL;
    }

    if (ca_file != NULL) {
        SSL_set1_host(ssl, host);
    }

    SSL_set_tlsext_host_name(ssl, host);

    bio = BIO_push(BIO_new(BIO_f_ssl()), bio);

    if (bio == NULL) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return NULL;
    }

    BIO_set_ssl(bio, ssl, BIO_CLOSE);

    if (BIO_do_handshake(bio) != 1) {
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return NULL;
    }

    *ctx_out = ctx;

    return bio;
}

/*
 * the request is one write, the response is read to the EOF; the
 * header block ends at CRLFCRLF, the body is what remains (no
 * chunked, the OIDC endpoints answer Content-Length bodies)
 */

static s3_int_t
s3_https_read_response(BIO *bio, unsigned *status, s3_str_t *response)
{
    u_char *buf, *hdr_end, *p, *grown;
    size_t  n, cap, body;
    int     got;
    long    code;

    cap = 8192;
    n = 0;

    buf = s3_alloc(cap, NULL);

    if (buf == NULL) {
        return S3_ERROR;
    }

    for (;;) {

        if (n == cap) {

            if (cap >= S3_HTTPS_RESPONSE_MAX) {
                s3_free(buf);
                return S3_ERROR;
            }

            cap = s3_min(cap * 2, (size_t)S3_HTTPS_RESPONSE_MAX);

            grown = realloc(buf, cap);

            if (grown == NULL) {
                s3_free(buf);
                return S3_ERROR;
            }

            buf = grown;
        }

        got = BIO_read(bio, buf + n, (int)(cap - n));

        if (got > 0) {
            n += (size_t)got;
            continue;
        }

        if (got == 0) {
            /* the Connection: close EOF ends the response */
            break;
        }

        if (BIO_should_retry(bio)) {
            continue;
        }

        s3_free(buf);
        return S3_ERROR;
    }

    if (n < 16 || s3_memcmp(buf, "HTTP/", 5) != 0) {
        s3_free(buf);
        return S3_ERROR;
    }

    code = strtol((const char *)buf + 9, NULL, 10);

    if (code < 100 || code > 599) {
        s3_free(buf);
        return S3_ERROR;
    }

    hdr_end = NULL;

    for (p = buf; (size_t)(p - buf) + 4 <= n; p++) {

        if (p[0] == '\r' && p[1] == '\n' && p[2] == '\r' && p[3] == '\n') {
            hdr_end = p + 4;
            break;
        }
    }

    if (hdr_end == NULL) {
        /* the response ran out without the empty line */
        s3_free(buf);
        return S3_ERROR;
    }

    body = n - (size_t)(hdr_end - buf);

    if (body > 0) {
        s3_memmove(buf, hdr_end, body);
    }

    response->data = buf;
    response->len = body;

    if (status != NULL) {
        *status = (unsigned)code;
    }

    return S3_OK;
}

s3_int_t
s3_https_fetch(const char *url, const char *method, const s3_str_t *body, const char *content_type,
               const char *ca_file, unsigned *status, s3_str_t *response)
{
    char        host[256], port[8], req[8192];
    unsigned    tls;
    SSL_CTX    *ctx;
    BIO        *bio;
    size_t      blen, req_len;
    int         req_n;
    s3_int_t    rc;
    s3_str_t    out, path;
    const char *slash;

    s3_str_null(&out);

    if (s3_https_url_split(url, &tls, host, sizeof(host), port, sizeof(port), &slash) != S3_OK) {
        return S3_ERROR;
    }

    bio = s3_https_connect(host, port, tls, ca_file, &ctx);

    if (bio == NULL) {
        return S3_ERROR;
    }

    blen = (body != NULL) ? body->len : 0;

    path.data = (u_char *)slash;
    path.len = s3_strlen(slash);

    /* the path rides the request line, the 8k request cap holds the
     * OIDC urls and forms with room to spare */

    if (path.len > sizeof(req) - 1024) {
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return S3_ERROR;
    }

    req_n = snprintf(req, sizeof(req),
                     "%s %.*s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "User-Agent: ssh3-c\r\n"
                     "Accept: application/json\r\n"
                     "Connection: close\r\n",
                     method, (int)path.len, path.data, host);

    if (req_n <= 0 || (size_t)req_n + blen + 128 > sizeof(req)) {
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return S3_ERROR;
    }

    req_len = (size_t)req_n;

    if (blen > 0) {

        req_n = snprintf(
            req + req_len, sizeof(req) - req_len,
            "Content-Type: %s\r\n"
            "Content-Length: %zu\r\n\r\n",
            (content_type != NULL) ? content_type : "application/x-www-form-urlencoded", blen);

        if (req_n <= 0) {
            BIO_free_all(bio);
            SSL_CTX_free(ctx);
            return S3_ERROR;
        }

        req_len += (size_t)req_n;

        s3_memcpy(req + req_len, body->data, blen);
        req_len += blen;

    } else {
        s3_memcpy(req + req_len, "\r\n", 2);
        req_len += 2;
    }

    if (BIO_write(bio, req, (int)req_len) != (int)req_len) {
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return S3_ERROR;
    }

    rc = s3_https_read_response(bio, status, &out);

    BIO_free_all(bio);
    SSL_CTX_free(ctx);

    if (rc != S3_OK) {
        return S3_ERROR;
    }

    *response = out;

    return S3_OK;
}
