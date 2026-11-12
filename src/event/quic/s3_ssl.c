/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

/*
 * the ticket key callback rides the nginx shape - the shape of the
 * SSL_CTX_set_tlsext_ticket_key_cb man page sample: HMAC_Init_ex is
 * deprecated since 3.0 but the callback contract hands the HMAC_CTX
 * in, the suppression is scoped to this translation unit
 */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#if (S3_WIN32)
#include <direct.h>
#endif

#include <s3_errno.h>
#include <s3_ssl.h>
#include <s3_string.h>

static int s3_ssl_alpn_select_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                                 const unsigned char *in, unsigned int inlen, void *arg);
static int s3_ssl_client_verify_cb(int ok, X509_STORE_CTX *sctx);
static int s3_ssl_ticket_key_cb(SSL *ssl, unsigned char name[], unsigned char iv[],
                                EVP_CIPHER_CTX *ectx, HMAC_CTX *hctx, int enc);

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

    /*
     * the leaf rides SSL_CTX_use_certificate(), the rest of the PEM
     * chain rides the extra chain stack: the handshake must present
     * the full chain, a leaf-only server side is unverifiable for
     * the client (the intermediates are not in its trust store)
     */
    x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (x509 == NULL) {
        BIO_free(bio);
        s3_ssl_error(log, 0, "PEM_read_bio_X509() failed");
        goto failed;
    }

    if (SSL_CTX_use_certificate(ssl->ctx, x509) != 1) {
        s3_ssl_error(log, 0, "SSL_CTX_use_certificate() failed");
        X509_free(x509);
        BIO_free(bio);
        goto failed;
    }

    X509_free(x509);

    while ((x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
        if (SSL_CTX_add_extra_chain_cert(ssl->ctx, x509) != 1) {
            s3_ssl_error(log, 0, "SSL_CTX_add_extra_chain_cert() failed");
            X509_free(x509);
            BIO_free(bio);
            goto failed;
        }

        /* the ownership of x509 moved to the ctx - no X509_free */
    }

    /* the EOF read of the PEM trail sets an error - clear it */
    ERR_clear_error();

    BIO_free(bio);

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

    /*
     * the ticket flight of the wave 13: one ticket per handshake (the
     * smaller flight lands before a fast-close exec run tears the
     * connection down) and the explicit lifetime (the silent OpenSSL
     * default is short, the client cache drops the expired lines and
     * the warm dial honestly goes 1-RTT); the key material itself
     * rides s3_ssl_ticket_key_file() - the OpenSSL default keys live
     * in the process memory only and die with the daemon
     */

    SSL_CTX_set_app_data(ssl->ctx, ssl);
    SSL_CTX_set_num_tickets(ssl->ctx, 1);
    SSL_CTX_set_timeout(ssl->ctx, 43200);

    /*
     * the stateless tickets of the wave 13: the built-in anti-replay
     * window forces the stateful tickets (the cache index only - the
     * restart kills the cache and every ticket with it, the wave-13
     * mystery), the ssh3 layer owns the replay business instead (the
     * 425/401 retry contract, the auth rides outside the early
     * window) - the tickets carry the full session state and the
     * persistent key file decrypts them after the restart
     */

    SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_ANTI_REPLAY);

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

/* the portable mkdir of the cache directory: the mode rides the
 * unix leg, the win one takes the single-argument form (direct.h) */

static int
s3_ssl_mkdir(const char *dir)
{
#if (S3_WIN32)
    return _mkdir(dir);
#else
    return mkdir(dir, 0700);
#endif
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
    char    newline[1024 + sizeof(hex) + 2];
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

    /* the newline buffer: the dedupe read below rides `line`, the
     * fresh record must survive it (the stale line of the old file
     * kept winning the rewrite, the flag never reached the cache) */

    n = snprintf(newline, sizeof(newline), "%s %s %s\n", ssl->ticket_key, ssl->server_c ? "c" : "-",
                 hex);

    if (n <= 0 || (size_t)n >= sizeof(newline)) {
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
        char dir[1024], parent[1024];

        /* the win home rides the backslash form, the unix one the
         * slash - the split takes the last separator of either */

        const char *s1 = strrchr(ssl->ticket_path, '/');
        const char *s2 = strrchr(ssl->ticket_path, '\\');
        const char *slash = (s1 > s2) ? s1 : s2;
        size_t      dlen = slash != NULL ? (size_t)(slash - ssl->ticket_path) : 0;

        if (dlen > 0 && dlen < sizeof(dir)) {

            memcpy(dir, ssl->ticket_path, dlen);
            dir[dlen] = '\0';

            if (s3_ssl_mkdir(dir) != 0 && errno == ENOENT) {

                const char *u1 = strrchr(dir, '/');
                const char *u2 = strrchr(dir, '\\');
                const char *up = (u1 > u2) ? u1 : u2;
                size_t      plen = up != NULL ? (size_t)(up - dir) : 0;

                if (plen > 0 && plen < sizeof(parent)) {

                    memcpy(parent, dir, plen);
                    parent[plen] = '\0';

                    (void)s3_ssl_mkdir(parent);
                    (void)s3_ssl_mkdir(dir);
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

        /* the key-flag-hex line (the same form the load reads) */

        w = write(fd, body, strlen(body));
        ok = ok && w >= 0;

        w = write(fd, newline, strlen(newline));
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

s3_int_t
s3_ssl_ticket_load(s3_ssl_t *ssl, const char **reason)
{
    u_char  der[2048];
    u_char *p;
    size_t  dlen;
    /* the record cap rides the persist side (the stateless ticket
     * of the wave 13 carries the full session state - 1162 B and
     * counting, the old 2048 line cut the hex mid-way) */
    char         line[1024 + sizeof(der) * 2 + 2];
    const char  *hex;
    long         age;
    SSL_SESSION *session;
    FILE        *src;
    s3_int_t     rc = S3_DECLINED;

    if (reason != NULL) {
        *reason = "the cache file is missing";
    }

    src = fopen(ssl->ticket_path, "r");

    if (src == NULL) {
        return rc;
    }

    while (fgets(line, sizeof(line), src) != NULL) {

        line[strcspn(line, "\n")] = '\0';

        if (strncmp(line, ssl->ticket_key, strlen(ssl->ticket_key)) != 0 ||
            line[strlen(ssl->ticket_key)] != ' ') {
            continue;
        }

        /*
         * the v2 form: key, the retry-contract flag (c = the ssh3-c
         * server, - = anything else), the hex; the flag of the line
         * gates the early flight.  the flag sits right behind the
         * key (the field width of one), the hex rides two positions
         * behind the key terminator
         */

        {
            size_t klen = strlen(ssl->ticket_key);

            if (line[klen + 1] == 'c' && line[klen + 2] == ' ') {
                ssl->server_c = 1;
                hex = line + klen + 3;
            } else if (line[klen + 1] == '-' && line[klen + 2] == ' ') {
                ssl->server_c = 0;
                hex = line + klen + 3;
            } else {
                if (reason != NULL) {
                    *reason = "the cache line is damaged";
                }
                break; /* an unknown form: no flight this dial */
            }
        }

        if (!s3_ssl_ticket_unhex(der, &dlen, hex) || dlen == 0) {
            if (reason != NULL) {
                *reason = "the cache line is damaged";
            }
            break;
        }

        p = der;
        session = d2i_SSL_SESSION(NULL, (const unsigned char **)&p, (long)dlen);

        if (session == NULL) {
            ERR_clear_error();
            if (reason != NULL) {
                *reason = "the cache line is damaged";
            }
            break;
        }

        /* the expired ticket rides no 0-RTT: drop it silently */

        age = (long)time(NULL) - (long)SSL_SESSION_get_time_ex(session);

        if (age > (long)SSL_SESSION_get_timeout(session)) {
            SSL_SESSION_free(session);
            if (reason != NULL) {
                *reason = "the cached ticket expired";
            }
            break;
        }

        ssl->stored_session = session;
        rc = S3_OK;

        if (reason != NULL) {
            *reason = NULL;
        }

        break;
    }

    fclose(src);

    if (rc != S3_OK && reason != NULL && *reason == NULL) {
        *reason = "the cache holds no line for this host";
    }

    return rc;
}

/*
 * the binary open of the win build rides the text translation off
 * (the key bytes carry 0x0a freely, the CRT default would corrupt
 * them both ways)
 */

#if (S3_WIN32)
#define S3_SSL_OPEN_BINARY O_BINARY
#else
#define S3_SSL_OPEN_BINARY 0
#endif

static int
s3_ssl_ticket_key_cb(SSL *ssl_conn, unsigned char name[], unsigned char iv[], EVP_CIPHER_CTX *ectx,
                     HMAC_CTX *hctx, int enc)
{
    s3_ssl_t         *ssl_conf;
    const EVP_CIPHER *cipher;

    ssl_conf = SSL_CTX_get_app_data(SSL_get_SSL_CTX(ssl_conn));

    if (ssl_conf == NULL || ssl_conf->ticket_aes_len == 0) {
        return 0; /* the keys never landed: no tickets this ctx */
    }

    cipher = ssl_conf->ticket_aes_len == 16 ? EVP_aes_128_cbc() : EVP_aes_256_cbc();

    if (enc == 1) {

        /* the encrypt side: the fresh iv, the current key signs and
         * seals, the name rides the ticket head */

        if (RAND_bytes(iv, EVP_CIPHER_iv_length(cipher)) != 1) {
            s3_ssl_error(ssl_conf->log, 0, "RAND_bytes() failed");
            return -1;
        }

        if (EVP_EncryptInit_ex(ectx, cipher, NULL, ssl_conf->ticket_aes_key, iv) != 1) {
            s3_ssl_error(ssl_conf->log, 0, "EVP_EncryptInit_ex() failed");
            return -1;
        }

        if (HMAC_Init_ex(hctx, ssl_conf->ticket_hmac_key, (int)ssl_conf->ticket_hmac_len,
                         EVP_sha256(), NULL) != 1) {
            s3_ssl_error(ssl_conf->log, 0, "HMAC_Init_ex() failed");
            return -1;
        }

        s3_memcpy(name, ssl_conf->ticket_key_name, 16);

        return 1;
    }

    /* the decrypt side: the name miss is a plain 1-RTT handshake,
     * not an error (the OpenSSL default keys of the previous daemon
     * lifetime ride this road) */

    if (s3_memcmp(name, ssl_conf->ticket_key_name, 16) != 0) {
        return 0;
    }

    if (HMAC_Init_ex(hctx, ssl_conf->ticket_hmac_key, (int)ssl_conf->ticket_hmac_len, EVP_sha256(),
                     NULL) != 1) {
        s3_ssl_error(ssl_conf->log, 0, "HMAC_Init_ex() failed");
        return -1;
    }

    if (EVP_DecryptInit_ex(ectx, cipher, NULL, ssl_conf->ticket_aes_key, iv) != 1) {
        s3_ssl_error(ssl_conf->log, 0, "EVP_DecryptInit_ex() failed");
        return -1;
    }

    /* the nginx shape: the TLS 1.3 ticket renews in place */

    if (SSL_version(ssl_conn) == TLS1_3_VERSION) {
        return 2;
    }

    return 1;
}

s3_int_t
s3_ssl_ticket_key_file_new(const char *path, s3_log_t *log)
{
    u_char   buf[80];
    s3_err_t err;
    int      fd, n;

    if (path == NULL || path[0] == '\0') {
        return S3_ERROR;
    }

    if (RAND_bytes(buf, (int)sizeof(buf)) != 1) {
        s3_ssl_error(log, 0, "RAND_bytes() failed");
        return S3_ERROR;
    }

    /* the same 80-byte layout the server arm reads (16 name + 32
     * hmac + 32 aes), the owner-only mode */

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | S3_SSL_OPEN_BINARY, 0600);

    if (fd == -1) {
        err = s3_errno;
        s3_log_error(S3_LOG_ERR, log, err, "open() \"%s\" failed", path);
        return S3_ERROR;
    }

    n = (int)write(fd, buf, sizeof(buf));
    (void)close(fd);

    if (n != (int)sizeof(buf)) {
        s3_log_error(S3_LOG_ERR, log, 0, "write() \"%s\" returned %d", path, n);
        return S3_ERROR;
    }

    s3_memzero(buf, sizeof(buf));

    return S3_OK;
}

static s3_int_t
s3_ssl_ticket_key_generate(s3_ssl_t *ssl, const char *path)
{
    u_char   buf[80];
    s3_err_t err;
    int      fd, n;

    if (RAND_bytes(buf, (int)sizeof(buf)) != 1) {
        s3_ssl_error(ssl->log, 0, "RAND_bytes() failed");
        return S3_ERROR;
    }

    /* the nginx 80-byte layout: 16 name + 32 hmac + 32 aes, the
     * owner-only mode (the file is the plain-text of every ticket
     * the daemon ever issued) */

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | S3_SSL_OPEN_BINARY, 0600);

    if (fd == -1) {
        err = s3_errno;
        s3_log_error(S3_LOG_ERR, ssl->log, err, "open() \"%s\" failed", path);
        return S3_ERROR;
    }

    n = (int)write(fd, buf, sizeof(buf));
    (void)close(fd);

    if (n != (int)sizeof(buf)) {
        s3_log_error(S3_LOG_ERR, ssl->log, 0, "write() \"%s\" returned %d", path, n);
        return S3_ERROR;
    }

    s3_memcpy(ssl->ticket_key_name, buf, 16);
    s3_memcpy(ssl->ticket_hmac_key, buf + 16, 32);
    s3_memcpy(ssl->ticket_aes_key, buf + 48, 32);
    ssl->ticket_hmac_len = 32;
    ssl->ticket_aes_len = 32;

    s3_memzero(buf, sizeof(buf));

    return S3_OK;
}

s3_int_t
s3_ssl_ticket_key_file(s3_ssl_t *ssl, const char *path)
{
    u_char   buf[80];
    s3_err_t err;
    int      fd, n;

    if (ssl == NULL || ssl->ctx == NULL) {
        return S3_ERROR;
    }

    if (path == NULL) {
        return S3_OK;
    }

    fd = open(path, O_RDONLY | S3_SSL_OPEN_BINARY);

    if (fd == -1) {

        err = s3_errno;

        if (err != S3_ENOENT) {
            s3_log_error(S3_LOG_ERR, ssl->log, err, "open() \"%s\" failed", path);
            return S3_ERROR;
        }

        /* the first lifetime of the key: generate and arm */

        if (s3_ssl_ticket_key_generate(ssl, path) != S3_OK) {
            return S3_ERROR;
        }

        s3_log_error(S3_LOG_INFO, ssl->log, 0, "session ticket key %s generated", path);

        SSL_CTX_set_app_data(ssl->ctx, ssl);
        SSL_CTX_set_tlsext_ticket_key_cb(ssl->ctx, s3_ssl_ticket_key_cb);

        return S3_OK;
    }

    n = (int)read(fd, buf, sizeof(buf));
    (void)close(fd);

    if (n < 0) {
        err = s3_errno;
        s3_log_error(S3_LOG_ERR, ssl->log, err, "read() \"%s\" failed", path);
        return S3_ERROR;
    }

    if (n == 80) {

        s3_memcpy(ssl->ticket_key_name, buf, 16);
        s3_memcpy(ssl->ticket_hmac_key, buf + 16, 32);
        s3_memcpy(ssl->ticket_aes_key, buf + 48, 32);
        ssl->ticket_hmac_len = 32;
        ssl->ticket_aes_len = 32;

    } else if (n == 48) {

        /* the legacy nginx form: aes-128 and the short hmac */

        s3_memcpy(ssl->ticket_key_name, buf, 16);
        s3_memset(ssl->ticket_hmac_key, 0, 32);
        s3_memcpy(ssl->ticket_hmac_key, buf + 32, 16);
        s3_memcpy(ssl->ticket_aes_key, buf + 16, 16);
        ssl->ticket_hmac_len = 16;
        ssl->ticket_aes_len = 16;

    } else {

        /* the broken file rides the regeneration: the old tickets
         * die, the new lifetime starts clean */

        s3_log_error(S3_LOG_WARN, ssl->log, 0, "session ticket key %s is %d bytes, regenerating",
                     path, n);

        if (s3_ssl_ticket_key_generate(ssl, path) != S3_OK) {
            return S3_ERROR;
        }
    }

    s3_memzero(buf, sizeof(buf));

    SSL_CTX_set_app_data(ssl->ctx, ssl);
    SSL_CTX_set_tlsext_ticket_key_cb(ssl->ctx, s3_ssl_ticket_key_cb);

    return S3_OK;
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
    ssl_conf->tickets_n++;

    /* the persistence of the 0-RTT stage 2: the cache file rides */

    if (ssl_conf->ticket_path[0] != '\0') {
        s3_ssl_ticket_persist(ssl_conf, session);
    }

    return 1;
}

/*
 * the record-only verify of the client ctx: the chain is checked
 * against the system store and the pinned anchors on every handshake,
 * the first fatal x509 error rides the conf and the handshake never
 * aborts here - the ssh3 layer enforces the verdict before any
 * credential rides (CERT-VERIFICATION-CANON.md 2.2, the B17 order)
 */
static int
s3_ssl_client_verify_cb(int ok, X509_STORE_CTX *sctx)
{
    /* reach the s3_ssl_t: X509_STORE_CTX -> SSL (ex-data idx) ->
     * app_data (s3_quic_client_init_connection stores the s3_ssl_t
     * there) */

    SSL      *ssl_conn;
    s3_ssl_t *s;

    ssl_conn = X509_STORE_CTX_get_ex_data(sctx, SSL_get_ex_data_X509_STORE_CTX_idx());

    s = ssl_conn != NULL ? SSL_get_app_data(ssl_conn) : NULL;

    if (s != NULL) {
        s->chain_seen = 1;

        if (!ok && s->chain_err == X509_V_OK) {
            s->chain_err = X509_STORE_CTX_get_error(sctx);
        }
    }

    /* the verdict rides the ssh3 layer, the handshake stays alive */

    return 1;
}

s3_ssl_t *
s3_ssl_client_create(s3_log_t *log, const s3_str_t *alpn)
{
    X509_VERIFY_PARAM *param;
    s3_ssl_t          *ssl;

    ssl = s3_alloc(sizeof(s3_ssl_t), log);
    if (ssl == NULL) {
        return NULL;
    }

    s3_memzero(ssl, sizeof(s3_ssl_t));

    ssl->log = log;

    ssl->chain_err = X509_V_OK;
    ssl->chain_seen = 0;

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

    /*
     * the system trust store rides the anchors of every handshake
     * (canon 2.2: the pins of the target sit on top of it); the call
     * honors SSL_CERT_FILE/SSL_CERT_DIR.  the bundled win build ships
     * no default cert dir - a failure here degrades the anchors to
     * the pins only, the verdict enforcement stays with the ssh3
     * layer
     */

    if (SSL_CTX_set_default_verify_paths(ssl->ctx) != 1) {
        ERR_clear_error();
    }

    /*
     * any pinned certificate is a trust anchor on its own (the Go
     * anchor semantics): not only the self-signed roots
     */

    param = SSL_CTX_get0_param(ssl->ctx);
    X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_PARTIAL_CHAIN);

    /*
     * the chain is verified against the system store and the pinned
     * anchors on every handshake; the callback records the first
     * fatal error and never aborts - the ssh3 layer enforces the
     * verdict before any credential rides (CERT-VERIFICATION-CANON.md
     * 2.2, the B17 order)
     */

    SSL_CTX_set_verify(ssl->ctx, SSL_VERIFY_PEER, s3_ssl_client_verify_cb);

    /* the release client carries no keylog callback (canon 3.3); the
     * env hook is the debug build's switch */

    if (getenv("S3_KEYLOG") != NULL) {
        SSL_CTX_set_keylog_callback(ssl->ctx, s3_ssl_keylog_cb);
    }

    /* the client keeps no internal session cache: the tickets land in
     * the new-session callback (the store of s3_ssl_t) */

    SSL_CTX_set_session_cache_mode(ssl->ctx,
                                   SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
    SSL_CTX_sess_set_new_cb(ssl->ctx, s3_ssl_client_new_session_cb);

    return ssl;
}

/*
 * the pin of the target (canon 2.2): the raw DER of the leaf
 * certificate rides the client store next to the system CAs
 */
s3_int_t
s3_ssl_client_add_pin(s3_ssl_t *ssl, const u_char *der, size_t len)
{
    const u_char *p;
    X509         *x509;
    X509_STORE   *store;

    if (ssl == NULL || ssl->ctx == NULL || der == NULL || len == 0) {
        return S3_ERROR;
    }

    /* d2i advances the pointer, the caller's der stays untouched */

    p = der;

    x509 = d2i_X509(NULL, &p, (long)len);
    if (x509 == NULL) {
        s3_ssl_error(ssl->log, 0, "d2i_X509() failed");
        return S3_ERROR;
    }

    store = SSL_CTX_get_cert_store(ssl->ctx);
    if (store == NULL) {
        s3_ssl_error(ssl->log, 0, "SSL_CTX_get_cert_store() failed");
        X509_free(x509);
        return S3_ERROR;
    }

    /* any pinned cert anchors on its own (the Go anchor semantics) */

    X509_VERIFY_PARAM_set_flags(SSL_CTX_get0_param(ssl->ctx), X509_V_FLAG_PARTIAL_CHAIN);

    if (X509_STORE_add_cert(store, x509) != 1) {

        /* the duplicate of an already added pin is a no-op success */

        if (ERR_GET_REASON(ERR_peek_error()) == X509_R_CERT_ALREADY_IN_HASH_TABLE) {
            ERR_clear_error();
            X509_free(x509);
            return S3_OK;
        }

        s3_ssl_error(ssl->log, 0, "X509_STORE_add_cert() failed");
        X509_free(x509);
        return S3_ERROR;
    }

    X509_free(x509);

    return S3_OK;
}

/*
 * the verdict of the last handshake on this ssl: X509_V_OK when the
 * chain verified clean, the first fatal X509_V_ERR_* otherwise - the
 * ssh3 layer reads it before any credential rides (the B17 order)
 */
long
s3_ssl_chain_err(s3_ssl_t *ssl)
{
    if (ssl == NULL) {
        return X509_V_ERR_UNSPECIFIED;
    }

    return ssl->chain_err;
}

/*
 * whether the verify callback ran on this ssl (the server certificate
 * arrived): the 0-RTT early window checks it before the verdict
 */
unsigned
s3_ssl_chain_seen(s3_ssl_t *ssl)
{
    if (ssl == NULL) {
        return 0;
    }

    return ssl->chain_seen;
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
