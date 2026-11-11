/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_SSL_H_INCLUDED_
#define _S3_SSL_H_INCLUDED_

#include <stdio.h>

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

    /*
     * the NSS keylog file of the client debug (s3_ssl_set_keylog_file),
     * the callback of the ctx writes the secrets there; the file is
     * closed by s3_ssl_free()
     */
    FILE *keylog_file;

    /*
     * the newest session ticket of the client (the 0-RTT stage 1):
     * the new-session callback stores it per process (the Control
     * Master connections reuse it), SSL_set_session rides it on the
     * next dial; the persistence across the runs lands with the
     * stage 2 (the CONNECT-in-0-RTT flight)
     */
    SSL_SESSION *stored_session;

    /*
     * the ticket persistence of the 0-RTT stage 2: the cache file
     * (~/.ssh3/tickets) and the host:port identity of the line; both
     * empty = the run keeps the ticket in the process memory only
     */

    char     ticket_path[1024];
    char     ticket_key[300];
    unsigned server_c; /* the peer speaks the ssh3-c retry contract */

    /*
     * the session ticket key of the server (s3_ssl_ticket_key_file):
     * the nginx 80-byte form rides the 32/32 lens, the 48-byte legacy
     * file rides 16/16 (aes-128 + the short hmac); the zero aes_len
     * keeps the keys in the OpenSSL process memory (the restart
     * loses them, the pre-wave-13 shape)
     */
    u_char ticket_key_name[16];
    u_char ticket_hmac_key[32];
    u_char ticket_aes_key[32];
    size_t ticket_hmac_len;
    size_t ticket_aes_len;

    /*
     * the record-only verify verdict of the last handshake (the
     * client role): the callback stores the first fatal x509 error
     * and never aborts - the ssh3 layer enforces the verdict before
     * any credential rides (CERT-VERIFICATION-CANON.md 2.2, the B17
     * order)
     */
    long chain_err;

    /* the verify callback ran at least once on this ssl: the server
     * certificate arrived (the 0-RTT early window checks it before
     * consulting the verdict) */
    unsigned chain_seen;
};

void s3_ssl_ticket_load(s3_ssl_t *ssl);
void s3_ssl_ticket_persist(s3_ssl_t *ssl, SSL_SESSION *session);

/*
 * the persistent session ticket key of the server (the nginx-form
 * file, 80 bytes: 16 name + 32 hmac + 32 aes; the 48-byte legacy
 * 16/16/16 rides too): the missing or the broken file regenerates
 * with the fresh random key (the 0600 mode), the tickets issued by
 * the previous daemon lifetime keep decrypting - the warm 0-RTT
 * reconnect survives the restart.  NULL path is a no-op (the
 * in-memory keys of the OpenSSL process ride on).  Returns
 * S3_OK / S3_ERROR (the caller rides on with the in-memory keys).
 */
s3_int_t s3_ssl_ticket_key_file(s3_ssl_t *ssl, const char *path);

/*
 * the PEM strings may be file contents or in-memory certificates;
 * alpn is the wire-format list, like for SSL_set_alpn_protos()
 */
s3_ssl_t *s3_ssl_create(s3_log_t *log, const char *cert, size_t cert_len, const char *key,
                        size_t key_len, const s3_str_t *alpn);
void      s3_ssl_free(s3_ssl_t *ssl);

/*
 * the client role context (TLS_client_method, no certificate); the
 * chain is verified against the system store and the pinned anchors
 * on every handshake, the verdict rides s3_ssl_chain_err() - the
 * ssh3 layer enforces it (CERT-VERIFICATION-CANON.md 2.2)
 */
s3_ssl_t *s3_ssl_client_create(s3_log_t *log, const s3_str_t *alpn);

/*
 * adds a pinned leaf certificate (raw DER) as a trust anchor of the
 * client store: d2i_X509 + X509_STORE_add_cert into
 * SSL_CTX_get_cert_store().  A duplicate DER is a no-op success
 * (X509_R_CERT_ALREADY_IN_HASH_TABLE).  The first call sets
 * X509_V_FLAG_PARTIAL_CHAIN on the ctx verify param - the Go anchor
 * semantics (any pinned cert anchors, not only self-signed roots).
 * Returns S3_OK / S3_ERROR.
 */
s3_int_t s3_ssl_client_add_pin(s3_ssl_t *ssl, const u_char *der, size_t len);

/*
 * the recorded first fatal x509 error of the last handshake on this
 * ssl (X509_V_OK when the chain verified clean; X509_V_ERR_*
 * constants otherwise)
 */
long s3_ssl_chain_err(s3_ssl_t *ssl);

/*
 * whether the verify callback ran (the server certificate arrived):
 * the 0-RTT early window checks this before consulting the verdict
 */
unsigned s3_ssl_chain_seen(s3_ssl_t *ssl);

/*
 * the NSS keylog file for the Wireshark/Tshark decoding of the TLS
 * secrets: the file opens in the append mode, the keylog callback of
 * the ctx appends every secret line to it (flushed per line); the
 * file rides on the ssl conf and closes in s3_ssl_free(), NULL
 * restores the default probe callback
 */
s3_int_t s3_ssl_set_keylog_file(s3_ssl_t *ssl, const char *path);

s3_int_t s3_ssl_create_connection(s3_ssl_t *ssl, s3_connection_t *c);
s3_int_t s3_ssl_shutdown(s3_connection_t *c);

/* logs the openssl error stack after fmt */
void s3_ssl_error(s3_log_t *log, s3_err_t err, const char *fmt, ...);

#endif /* _S3_SSL_H_INCLUDED_ */
