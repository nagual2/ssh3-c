/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_QUIC_TLS_HELPER_H_INCLUDED_
#define _S3_QUIC_TLS_HELPER_H_INCLUDED_

/*
 * the shared harness of the D2 quic tests: a real OpenSSL client SSL
 * driven in lockstep with the s3_quic server machinery, plus the
 * environment boilerplate (pool, event ctx, conf, ssl context)
 *
 * the crypto data of a side is kept per level, like the QUIC CRYPTO
 * streams: out[] holds the records the side sends (the test pumps
 * them to the peer), in[] holds the records it receives; the OSSL
 * record protection levels match the S3_QUIC_ENCRYPTION_* constants
 */

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <string.h>

#include <s3_quic.h>
#include <s3_quic_connection.h>
#include <s3_quic_frames.h>

#include "s3_test.h"

#define S3_TEST_TLS_BUF    65536
#define S3_TEST_TLS_LEVELS 4

typedef struct {
    u_char      out[S3_TEST_TLS_LEVELS][S3_TEST_TLS_BUF];
    size_t      out_len[S3_TEST_TLS_LEVELS];
    u_char      in[S3_TEST_TLS_LEVELS][S3_TEST_TLS_BUF];
    size_t      in_len[S3_TEST_TLS_LEVELS];
    size_t      in_off[S3_TEST_TLS_LEVELS];
    int         read_level;
    int         write_level;
    size_t      tp_len;
    const char *name;
} s3_test_tls_side_t;

static s3_log_t s3_test_tls_log;

static int
s3_test_tls_send(SSL *ssl, const unsigned char *data, size_t len, size_t *consumed, void *arg)
{
    s3_test_tls_side_t *self = arg;
    int                 lvl = self->write_level;

    (void)ssl;

    if (self->out_len[lvl] + len > S3_TEST_TLS_BUF) {
        return 0;
    }

    s3_memcpy(self->out[lvl] + self->out_len[lvl], data, len);
    self->out_len[lvl] += len;
    *consumed = len;

    return 1;
}

static int
s3_test_tls_recv_rcd(SSL *ssl, const unsigned char **data, size_t *bytes_read, void *arg)
{
    s3_test_tls_side_t *self = arg;
    int                 lvl = self->read_level;

    (void)ssl;

    if (self->in_off[lvl] >= self->in_len[lvl]) {
        *data = NULL;
        *bytes_read = 0;
        return 1;
    }

    *data = self->in[lvl] + self->in_off[lvl];
    *bytes_read = self->in_len[lvl] - self->in_off[lvl];

    return 1;
}

static int
s3_test_tls_release_rcd(SSL *ssl, size_t bytes_read, void *arg)
{
    s3_test_tls_side_t *self = arg;

    (void)ssl;

    self->in_off[self->read_level] += bytes_read;

    return 1;
}

static int
s3_test_tls_yield_secret(SSL *ssl, uint32_t level, int direction, const unsigned char *secret,
                         size_t secret_len, void *arg)
{
    s3_test_tls_side_t *self = arg;

    (void)ssl;
    (void)secret;
    (void)secret_len;

    if (direction) {
        self->write_level = (int)level;

    } else {
        self->read_level = (int)level;
    }

    return 1;
}

static int
s3_test_tls_got_tp(SSL *ssl, const unsigned char *params, size_t params_len, void *arg)
{
    s3_test_tls_side_t *self = arg;

    (void)ssl;
    (void)params;

    self->tp_len = params_len;

    return 1;
}

static int
s3_test_tls_alert(SSL *ssl, unsigned char alert, void *arg)
{
    (void)ssl;
    (void)arg;

    printf("tls alert %d\n", (int)alert);

    return 1;
}

static const OSSL_DISPATCH s3_test_tls_dis[] = {
    {OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND, (void (*)(void))s3_test_tls_send},
    {OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RECV_RCD, (void (*)(void))s3_test_tls_recv_rcd},
    {OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RELEASE_RCD, (void (*)(void))s3_test_tls_release_rcd},
    {OSSL_FUNC_SSL_QUIC_TLS_YIELD_SECRET, (void (*)(void))s3_test_tls_yield_secret},
    {OSSL_FUNC_SSL_QUIC_TLS_GOT_TRANSPORT_PARAMS, (void (*)(void))s3_test_tls_got_tp},
    {OSSL_FUNC_SSL_QUIC_TLS_ALERT, (void (*)(void))s3_test_tls_alert},
    {0, NULL}};

/*
 * generates a self-signed EC certificate and returns the PEM strings
 */
#ifndef S3_TEST_TLS_NO_CERT

static int
s3_test_tls_gen_cert(u_char *cert, size_t *cert_len, u_char *key, size_t *key_len)
{
    EVP_PKEY  *pkey;
    X509      *x509;
    X509_NAME *name;
    BIO       *bio;
    long       n;

    pkey = EVP_EC_gen("P-256");
    if (pkey == NULL) {
        return -1;
    }

    x509 = X509_new();
    if (x509 == NULL) {
        EVP_PKEY_free(pkey);
        return -1;
    }

    X509_set_version(x509, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_getm_notBefore(x509), 0);
    X509_gmtime_adj(X509_getm_notAfter(x509), 31536000);
    X509_set_pubkey(x509, pkey);

    name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)"s3-test", -1, -1,
                               0);
    X509_set_issuer_name(x509, name);

    if (X509_sign(x509, pkey, EVP_sha256()) == 0) {
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return -1;
    }

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL || PEM_write_bio_X509(bio, x509) != 1) {
        return -1;
    }

    n = BIO_get_mem_data(bio, NULL);
    if (n <= 0) {
        return -1;
    }

    *cert_len = (size_t)n;
    BIO_read(bio, cert, (int)*cert_len);
    BIO_free(bio);

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL || PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL) != 1) {
        return -1;
    }

    n = BIO_get_mem_data(bio, NULL);
    if (n <= 0) {
        return -1;
    }

    *key_len = (size_t)n;
    BIO_read(bio, key, (int)*key_len);
    BIO_free(bio);

    X509_free(x509);
    EVP_PKEY_free(pkey);

    return 0;
}

#endif /* S3_TEST_TLS_NO_CERT */

static void
s3_test_tls_log_init(void)
{
    s3_test_tls_log.log_level = S3_LOG_INFO;
    s3_test_tls_log.fd = S3_INVALID_FILE;
}

/*
 * a new client role SSL with the harness callbacks; alpn is the
 * wire-format protocol list; the caller owns *out_ctx and must free
 * it with SSL_CTX_free() after SSL_free()
 */
#ifndef S3_TEST_TLS_NO_CLIENT

static SSL *
s3_test_tls_client(s3_test_tls_side_t *side, const s3_str_t *alpn, const u_char *tp, size_t tp_len,
                   SSL_CTX **out_ctx)
{
    SSL_CTX *ctx;
    SSL     *ssl;

    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        return NULL;
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        SSL_CTX_free(ctx);
        return NULL;
    }

    memset(side, 0, sizeof(s3_test_tls_side_t));
    side->name = "client";

    if (SSL_set_quic_tls_cbs(ssl, s3_test_tls_dis, side) != 1) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (tp != NULL && SSL_set_quic_tls_transport_params(ssl, tp, tp_len) != 1) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (alpn != NULL && SSL_set_alpn_protos(ssl, alpn->data, (unsigned int)alpn->len) != 0) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return NULL;
    }

    SSL_set_connect_state(ssl);

    *out_ctx = ctx;

    return ssl;
}

/*
 * encodes one transport parameter with a one-byte varint value
 * (the only form used by the tests)
 */
static size_t
s3_test_tp_put(u_char *p, uint64_t id, uint64_t value)
{
    *p++ = (u_char)id;
    *p++ = 1; /* varint length */
    *p++ = (u_char)value;

    return 3;
}

/*
 * the minimal client transport parameters the server side requires:
 * initial_source_connection_id and active_connection_id_limit
 */
static size_t
s3_test_client_tp(u_char *buf, const u_char *scid, size_t scid_len)
{
    u_char *p = buf;

    *p++ = (u_char)S3_QUIC_TP_INITIAL_SCID;
    *p++ = (u_char)scid_len;
    p = s3_cpymem(p, scid, scid_len);

    p += s3_test_tp_put(p, S3_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT, 8);

    return (size_t)(p - buf);
}

#endif /* S3_TEST_TLS_NO_CLIENT */

#ifndef S3_TEST_TLS_NO_LOCKSTEP

/*
 * moves the queued server CRYPTO frames into the incoming buffers of
 * the client side; non-crypto frames stay queued
 */
static void
s3_test_drain_crypto(s3_connection_t *c, s3_test_tls_side_t *dst)
{
    s3_uint_t             i, lvl;
    s3_queue_t           *q, *next;
    s3_quic_frame_t      *f;
    s3_chain_t           *cl;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    for (i = 0; i < S3_QUIC_SEND_CTX_LAST; i++) {
        s3_quic_send_ctx_t *ctx = &qc->send_ctx[i];

        q = s3_queue_head(&ctx->frames);

        while (q != s3_queue_sentinel(&ctx->frames)) {
            next = s3_queue_next(q);
            f = s3_queue_data(q, s3_quic_frame_t, queue);

            if (f->type == S3_QUIC_FT_CRYPTO) {
                lvl = f->level;

                for (cl = f->data; cl != NULL; cl = cl->next) {
                    s3_memcpy(dst->in[lvl] + dst->in_len[lvl], cl->buf->pos,
                              (size_t)s3_buf_size(cl->buf));
                    dst->in_len[lvl] += (size_t)s3_buf_size(cl->buf);
                }

                s3_queue_remove(&f->queue);
                s3_quic_free_frame(c, f);
            }

            q = next;
        }
    }
}

/*
 * feeds one flight of crypto data into the server through the real
 * s3_quic_handle_crypto_frame() path; offset is the running per level
 * crypto offset
 */
static s3_int_t
s3_test_feed_crypto(s3_connection_t *c, s3_uint_t level, const u_char *data, size_t len,
                    size_t *offset)
{
    s3_buf_t         buf;
    s3_chain_t       chain;
    s3_quic_frame_t  frame;
    s3_quic_header_t pkt;

    s3_memzero(&pkt, sizeof(s3_quic_header_t));
    pkt.log = c->log;
    pkt.level = level;

    s3_memzero(&buf, sizeof(s3_buf_t));
    buf.temporary = 1;
    buf.pos = (u_char *)data;
    buf.last = (u_char *)data + len;

    chain.buf = &buf;
    chain.next = NULL;

    s3_memzero(&frame, sizeof(s3_quic_frame_t));
    frame.type = S3_QUIC_FT_CRYPTO;
    frame.level = level;
    frame.data = &chain;
    frame.u.crypto.offset = *offset;
    frame.u.crypto.length = len;

    *offset += len;

    return s3_quic_handle_crypto_frame(c, &pkt, &frame);
}

#endif /* S3_TEST_TLS_NO_LOCKSTEP */

#endif /* _S3_QUIC_TLS_HELPER_H_INCLUDED_ */
