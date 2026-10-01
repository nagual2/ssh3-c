/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_QUIC_PROTECTION_H_INCLUDED_
#define _S3_QUIC_PROTECTION_H_INCLUDED_

#include <openssl/evp.h>

#include <s3_quic.h>
#include <s3_quic_transport.h>

/* RFC 5116, 5.1/5.3 and RFC 8439, 2.3/2.5 for all supported ciphers */
#define S3_QUIC_IV_LEN  12
#define S3_QUIC_TAG_LEN 16

/* largest hash used in TLS is SHA-384 */
#define S3_QUIC_MAX_MD_SIZE 48

/*
 * only the OpenSSL (>= 3.5) path is carried over: EVP_CIPHER-based
 * AEAD; the BoringSSL EVP_AEAD branches of the reference are cut
 */
typedef struct {
    size_t len;
    u_char data[S3_QUIC_MAX_MD_SIZE];
} s3_quic_md_t;

typedef struct {
    size_t len;
    u_char data[S3_QUIC_IV_LEN];
} s3_quic_iv_t;

typedef struct {
    s3_quic_md_t    secret;
    s3_quic_iv_t    iv;
    s3_quic_md_t    hp;
    EVP_CIPHER_CTX *ctx;
    EVP_CIPHER_CTX *hp_ctx;
} s3_quic_secret_t;

typedef struct {
    s3_quic_secret_t client;
    s3_quic_secret_t server;
} s3_quic_secrets_t;

struct s3_quic_keys_s {
    s3_quic_secrets_t secrets[S3_QUIC_ENCRYPTION_LAST];
    s3_quic_secrets_t next_key;
    s3_uint_t         cipher; /* TLS cipher suite id, like SSL_CIPHER_get_id() */
};

typedef struct {
    const EVP_CIPHER *c;
    const EVP_CIPHER *hp;
    const EVP_MD     *d;
} s3_quic_ciphers_t;

typedef struct {
    size_t  out_len;
    u_char *out;

    size_t         prk_len;
    const uint8_t *prk;

    size_t        label_len;
    const u_char *label;
} s3_quic_hkdf_t;

#define s3_quic_hkdf_set(seq, _label, _out, _prk)                                                  \
    (seq)->out_len = (_out)->len;                                                                  \
    (seq)->out = (_out)->data;                                                                     \
    (seq)->prk_len = (_prk)->len, (seq)->prk = (_prk)->data,                                       \
    (seq)->label_len = (sizeof(_label) - 1);                                                       \
    (seq)->label = (u_char *)(_label);

/*
 * D1 adaptation: the reference takes a const SSL_CIPHER * from the ssl
 * layer and converts it with SSL_CIPHER_get_id(); here the TLS cipher
 * suite id (TLS1_3_CK_*) is passed directly, so D1 links libcrypto only
 */
s3_int_t s3_quic_keys_set_initial_secret(s3_quic_keys_t *keys, s3_str_t *secret, s3_log_t *log);
s3_int_t s3_quic_keys_set_encryption_secret(s3_log_t *log, s3_uint_t is_write, s3_quic_keys_t *keys,
                                            s3_uint_t level, uint32_t cipher, const uint8_t *secret,
                                            size_t secret_len);
s3_uint_t s3_quic_keys_available(s3_quic_keys_t *keys, s3_uint_t level, s3_uint_t is_write);
void      s3_quic_keys_discard(s3_quic_keys_t *keys, s3_uint_t level);
void      s3_quic_keys_switch(s3_quic_keys_t *keys);
s3_int_t  s3_quic_keys_update(s3_quic_keys_t *keys, s3_log_t *log);
void      s3_quic_keys_cleanup(s3_quic_keys_t *keys);
s3_int_t  s3_quic_encrypt(s3_quic_header_t *pkt, s3_str_t *res);
s3_int_t  s3_quic_decrypt(s3_quic_header_t *pkt, uint64_t *largest_pn);
void      s3_quic_compute_nonce(u_char *nonce, size_t len, uint64_t pn);
s3_int_t  s3_quic_ciphers(s3_uint_t id, s3_quic_ciphers_t *ciphers);
s3_int_t  s3_quic_crypto_init(const EVP_CIPHER *cipher, s3_quic_secret_t *s, s3_quic_md_t *key,
                              s3_int_t enc, s3_log_t *log);
/*
 * the reference keeps ngx_quic_crypto_open() static; ssh3-c exposes it
 * for the unit tests and the future ssl layer
 */
s3_int_t s3_quic_crypto_open(s3_quic_secret_t *s, s3_str_t *out, const u_char *nonce, s3_str_t *in,
                             s3_str_t *ad, s3_log_t *log);
s3_int_t s3_quic_crypto_seal(s3_quic_secret_t *s, s3_str_t *out, const u_char *nonce, s3_str_t *in,
                             s3_str_t *ad, s3_log_t *log);
void     s3_quic_crypto_cleanup(s3_quic_secret_t *s);
s3_int_t s3_quic_hkdf_expand(s3_quic_hkdf_t *hkdf, const EVP_MD *digest, s3_log_t *log);

#endif /* _S3_QUIC_PROTECTION_H_INCLUDED_ */
