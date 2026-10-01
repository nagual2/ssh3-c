/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_SSL_H_INCLUDED_
#define _S3_SSL_H_INCLUDED_

#include <openssl/ssl.h>

#include <s3_base.h>
#include <s3_connection.h>
#include <s3_log.h>
#include <s3_str.h>

typedef struct s3_ssl_s      s3_ssl_t;
typedef struct s3_ssl_conn_s s3_ssl_conn_t;

/*
 * the per-connection ssl state; the ssh3-c counterpart of the
 * ngx_ssl_connection_t fields the quic layer reads
 * (porting map 4.4)
 */
struct s3_ssl_conn_s {
    SSL *connection;

    unsigned handshaked : 1;
    unsigned no_wait_shutdown : 1;
    unsigned handshake_rejected : 1;
};

/*
 * the SSL_CTX holder configured by the ssh3-c configurator
 * (cert/key/ALPN/early-data); the nginx ngx_ssl_t counterpart
 */
struct s3_ssl_s {
    SSL_CTX  *ctx;
    s3_str_t  alpn; /* the wire-format protocol list */
    s3_log_t *log;
};

/*
 * the PEM strings may be file contents or in-memory certificates;
 * alpn is the wire-format list, like for SSL_set_alpn_protos()
 */
s3_ssl_t *s3_ssl_create(s3_log_t *log, const char *cert, size_t cert_len, const char *key,
                        size_t key_len, const s3_str_t *alpn);
void      s3_ssl_free(s3_ssl_t *ssl);

s3_int_t s3_ssl_create_connection(s3_ssl_t *ssl, s3_connection_t *c);
s3_int_t s3_ssl_shutdown(s3_connection_t *c);

/* logs the openssl error stack after fmt */
void s3_ssl_error(s3_log_t *log, s3_err_t err, const char *fmt, ...);

#endif /* _S3_SSL_H_INCLUDED_ */
