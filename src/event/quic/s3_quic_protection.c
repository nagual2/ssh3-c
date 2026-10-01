/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>
#include <openssl/tls1.h>

#include <s3_quic.h>
#include <s3_quic_protection.h>

/* RFC 9001, 5.4.1.  Header Protection Application: 5-byte mask */
#define S3_QUIC_HP_LEN 5

#define S3_QUIC_AES_128_KEY_LEN 16

#define S3_QUIC_INITIAL_CIPHER TLS1_3_CK_AES_128_GCM_SHA256

#define s3_quic_md(str)                                                                            \
    {                                                                                              \
        sizeof(str) - 1, str                                                                       \
    }

static void     s3_quic_ssl_error(unsigned level, s3_log_t *log, const char *fmt, ...);
static s3_int_t s3_hkdf_expand(u_char *out_key, size_t out_len, const EVP_MD *digest,
                               const u_char *prk, size_t prk_len, const u_char *info,
                               size_t info_len);
static s3_int_t s3_hkdf_extract(u_char *out_key, size_t *out_len, const EVP_MD *digest,
                                const u_char *secret, size_t secret_len, const u_char *salt,
                                size_t salt_len);

static uint64_t s3_quic_parse_pn(u_char **pos, s3_int_t len, u_char *mask, uint64_t *largest_pn);

static s3_int_t s3_quic_crypto_common(s3_quic_secret_t *s, s3_str_t *out, const u_char *nonce,
                                      s3_str_t *in, s3_str_t *ad, s3_log_t *log);

static s3_int_t s3_quic_crypto_hp_init(const EVP_CIPHER *cipher, s3_quic_secret_t *s,
                                       s3_log_t *log);
static s3_int_t s3_quic_crypto_hp(s3_quic_secret_t *s, u_char *out, u_char *in, s3_log_t *log);
static void     s3_quic_crypto_hp_cleanup(s3_quic_secret_t *s);

static s3_int_t s3_quic_create_packet(s3_quic_header_t *pkt, s3_str_t *res);
static s3_int_t s3_quic_create_retry_packet(
    s3_quic_header_t *pkt,
    s3_str_t         *res); /*
                     * D1 has no ssl layer yet; this is the nginx ngx_ssl_error() core
                     * reduced to the OpenSSL error queue, D2 moves it to s3_ssl
                     */
static void
s3_quic_ssl_error(unsigned level, s3_log_t *log, const char *fmt, ...)
{
    u_char       *p, *last;
    va_list       args;
    u_char        errstr[S3_MAX_ERROR_STR];
    u_char        sslerr[256];
    unsigned long e;

    last = errstr + S3_MAX_ERROR_STR - 1;

    va_start(args, fmt);
    p = s3_vslprintf(errstr, last, fmt, args);
    va_end(args);

    while ((e = ERR_get_error()) != 0) {
        ERR_error_string_n(e, (char *)sslerr, sizeof(sslerr));

        if (p > last - (sizeof("  (SSL: )") + sizeof(sslerr))) {
            break;
        }

        p = s3_slprintf(p, last, " (SSL: %s)", sslerr);
    }

    ERR_clear_error();

    if (log == NULL || log->log_level < level) {
        return;
    }

    *p = '\0';

    s3_log_error_core(level, log, 0, "%s", errstr);
}

s3_int_t
s3_quic_ciphers(s3_uint_t id, s3_quic_ciphers_t *ciphers)
{
    s3_int_t len;

    switch (id) {

    case TLS1_3_CK_AES_128_GCM_SHA256:
        ciphers->c = EVP_aes_128_gcm();
        ciphers->hp = EVP_aes_128_ctr();
        ciphers->d = EVP_sha256();
        len = 16;
        break;

    case TLS1_3_CK_AES_256_GCM_SHA384:
        ciphers->c = EVP_aes_256_gcm();
        ciphers->hp = EVP_aes_256_ctr();
        ciphers->d = EVP_sha384();
        len = 32;
        break;

    case TLS1_3_CK_CHACHA20_POLY1305_SHA256:
        ciphers->c = EVP_chacha20_poly1305();
        ciphers->hp = EVP_chacha20();
        ciphers->d = EVP_sha256();
        len = 32;
        break;

    case TLS1_3_CK_AES_128_CCM_SHA256:
        ciphers->c = EVP_aes_128_ccm();
        ciphers->hp = EVP_aes_128_ctr();
        ciphers->d = EVP_sha256();
        len = 16;
        break;

    default:
        return S3_ERROR;
    }

    return len;
}

s3_int_t
s3_quic_keys_set_initial_secret(s3_quic_keys_t *keys, s3_str_t *secret, s3_log_t *log)
{
    size_t            is_len;
    uint8_t           is[SHA256_DIGEST_LENGTH];
    s3_str_t          iss;
    s3_uint_t         i;
    const EVP_MD     *digest;
    s3_quic_md_t      client_key, server_key;
    s3_quic_hkdf_t    seq[8];
    s3_quic_secret_t *client, *server;
    s3_quic_ciphers_t ciphers;

    static const uint8_t salt[20] = {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
                                     0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a};

    client = &keys->secrets[S3_QUIC_ENCRYPTION_INITIAL].client;
    server = &keys->secrets[S3_QUIC_ENCRYPTION_INITIAL].server;

    /*
     * RFC 9001, section 5.  Packet Protection
     *
     * Initial packets use AEAD_AES_128_GCM.  The hash function
     * for HKDF when deriving initial secrets and keys is SHA-256.
     */

    digest = EVP_sha256();
    is_len = SHA256_DIGEST_LENGTH;

    if (s3_hkdf_extract(is, &is_len, digest, secret->data, secret->len, salt, sizeof(salt)) !=
        S3_OK) {
        return S3_ERROR;
    }

    iss.len = is_len;
    iss.data = is;

    s3_log_debug0(S3_LOG_DEBUG_EVENT, log, 0, "quic s3_quic_keys_set_initial_secret");

    client->secret.len = SHA256_DIGEST_LENGTH;
    server->secret.len = SHA256_DIGEST_LENGTH;

    client_key.len = S3_QUIC_AES_128_KEY_LEN;
    server_key.len = S3_QUIC_AES_128_KEY_LEN;

    client->hp.len = S3_QUIC_AES_128_KEY_LEN;
    server->hp.len = S3_QUIC_AES_128_KEY_LEN;

    client->iv.len = S3_QUIC_IV_LEN;
    server->iv.len = S3_QUIC_IV_LEN;

    /* labels per RFC 9001, 5.1. Packet Protection Keys */
    s3_quic_hkdf_set(&seq[0], "tls13 client in", &client->secret, &iss);
    s3_quic_hkdf_set(&seq[1], "tls13 quic key", &client_key, &client->secret);
    s3_quic_hkdf_set(&seq[2], "tls13 quic iv", &client->iv, &client->secret);
    s3_quic_hkdf_set(&seq[3], "tls13 quic hp", &client->hp, &client->secret);
    s3_quic_hkdf_set(&seq[4], "tls13 server in", &server->secret, &iss);
    s3_quic_hkdf_set(&seq[5], "tls13 quic key", &server_key, &server->secret);
    s3_quic_hkdf_set(&seq[6], "tls13 quic iv", &server->iv, &server->secret);
    s3_quic_hkdf_set(&seq[7], "tls13 quic hp", &server->hp, &server->secret);

    for (i = 0; i < (sizeof(seq) / sizeof(seq[0])); i++) {
        if (s3_quic_hkdf_expand(&seq[i], digest, log) != S3_OK) {
            return S3_ERROR;
        }
    }

    if (s3_quic_ciphers(S3_QUIC_INITIAL_CIPHER, &ciphers) == S3_ERROR) {
        return S3_ERROR;
    }

    if (s3_quic_crypto_init(ciphers.c, client, &client_key, 0, log) == S3_ERROR) {
        return S3_ERROR;
    }

    if (s3_quic_crypto_init(ciphers.c, server, &server_key, 1, log) == S3_ERROR) {
        goto failed;
    }

    if (s3_quic_crypto_hp_init(ciphers.hp, client, log) == S3_ERROR) {
        goto failed;
    }

    if (s3_quic_crypto_hp_init(ciphers.hp, server, log) == S3_ERROR) {
        goto failed;
    }

    return S3_OK;

failed:

    s3_quic_keys_cleanup(keys);

    return S3_ERROR;
}

s3_int_t
s3_quic_hkdf_expand(s3_quic_hkdf_t *h, const EVP_MD *digest, s3_log_t *log)
{
    size_t   info_len;
    uint8_t *p;
    uint8_t  info[20];

    info_len = 2 + 1 + h->label_len + 1;

    info[0] = 0;
    info[1] = h->out_len;
    info[2] = h->label_len;

    p = s3_cpymem(&info[3], h->label, h->label_len);
    *p = '\0';

    if (s3_hkdf_expand(h->out, h->out_len, digest, h->prk, h->prk_len, info, info_len) != S3_OK) {
        s3_quic_ssl_error(S3_LOG_INFO, log, "s3_hkdf_expand(%*s) failed", h->label_len, h->label);
        return S3_ERROR;
    }

    return S3_OK;
}

static s3_int_t
s3_hkdf_expand(u_char *out_key, size_t out_len, const EVP_MD *digest, const uint8_t *prk,
               size_t prk_len, const u_char *info, size_t info_len)
{
    EVP_PKEY_CTX *pctx;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (pctx == NULL) {
        return S3_ERROR;
    }

    if (EVP_PKEY_derive_init(pctx) <= 0) {
        goto failed;
    }

    if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) <= 0) {
        goto failed;
    }

    if (EVP_PKEY_CTX_set_hkdf_md(pctx, digest) <= 0) {
        goto failed;
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, prk, prk_len) <= 0) {
        goto failed;
    }

    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, info_len) <= 0) {
        goto failed;
    }

    if (EVP_PKEY_derive(pctx, out_key, &out_len) <= 0) {
        goto failed;
    }

    EVP_PKEY_CTX_free(pctx);

    return S3_OK;

failed:

    EVP_PKEY_CTX_free(pctx);

    return S3_ERROR;
}

static s3_int_t
s3_hkdf_extract(u_char *out_key, size_t *out_len, const EVP_MD *digest, const u_char *secret,
                size_t secret_len, const u_char *salt, size_t salt_len)
{
    EVP_PKEY_CTX *pctx;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (pctx == NULL) {
        return S3_ERROR;
    }

    if (EVP_PKEY_derive_init(pctx) <= 0) {
        goto failed;
    }

    if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) <= 0) {
        goto failed;
    }

    if (EVP_PKEY_CTX_set_hkdf_md(pctx, digest) <= 0) {
        goto failed;
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, secret_len) <= 0) {
        goto failed;
    }

    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, salt_len) <= 0) {
        goto failed;
    }

    if (EVP_PKEY_derive(pctx, out_key, out_len) <= 0) {
        goto failed;
    }

    EVP_PKEY_CTX_free(pctx);

    return S3_OK;

failed:

    EVP_PKEY_CTX_free(pctx);

    return S3_ERROR;
}

s3_int_t
s3_quic_crypto_init(const EVP_CIPHER *cipher, s3_quic_secret_t *s, s3_quic_md_t *key, s3_int_t enc,
                    s3_log_t *log)
{
    EVP_CIPHER_CTX *ctx;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        s3_quic_ssl_error(S3_LOG_INFO, log, "EVP_CIPHER_CTX_new() failed");
        return S3_ERROR;
    }

    if (EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, enc) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        s3_quic_ssl_error(S3_LOG_INFO, log, "EVP_CipherInit_ex() failed");
        return S3_ERROR;
    }

    if (EVP_CIPHER_mode(cipher) == EVP_CIPH_CCM_MODE &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, S3_QUIC_TAG_LEN, NULL) == 0) {
        EVP_CIPHER_CTX_free(ctx);
        s3_quic_ssl_error(S3_LOG_INFO, log, "EVP_CIPHER_CTX_ctrl(EVP_CTRL_AEAD_SET_TAG) failed");
        return S3_ERROR;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, s->iv.len, NULL) == 0) {
        EVP_CIPHER_CTX_free(ctx);
        s3_quic_ssl_error(S3_LOG_INFO, log, "EVP_CIPHER_CTX_ctrl(EVP_CTRL_AEAD_SET_IVLEN) failed");
        return S3_ERROR;
    }

    if (EVP_CipherInit_ex(ctx, NULL, NULL, key->data, NULL, enc) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        s3_quic_ssl_error(S3_LOG_INFO, log, "EVP_CipherInit_ex() failed");
        return S3_ERROR;
    }

    s->ctx = ctx;

    return S3_OK;
}

s3_int_t
s3_quic_crypto_open(s3_quic_secret_t *s, s3_str_t *out, const u_char *nonce, s3_str_t *in,
                    s3_str_t *ad, s3_log_t *log)
{
    return s3_quic_crypto_common(s, out, nonce, in, ad, log);
}

s3_int_t
s3_quic_crypto_seal(s3_quic_secret_t *s, s3_str_t *out, const u_char *nonce, s3_str_t *in,
                    s3_str_t *ad, s3_log_t *log)
{
    return s3_quic_crypto_common(s, out, nonce, in, ad, log);
}

static s3_int_t
s3_quic_crypto_common(s3_quic_secret_t *s, s3_str_t *out, const u_char *nonce, s3_str_t *in,
                      s3_str_t *ad, s3_log_t *log)
{
    int             len, enc;
    EVP_CIPHER_CTX *ctx;

    ctx = s->ctx;
    enc = EVP_CIPHER_CTX_encrypting(ctx);

    if (EVP_CipherInit_ex(ctx, NULL, NULL, NULL, nonce, enc) != 1) {
        s3_quic_ssl_error(S3_LOG_INFO, log, "EVP_CipherInit_ex() failed");
        return S3_ERROR;
    }

    if (enc == 0) {
        in->len -= S3_QUIC_TAG_LEN;

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, S3_QUIC_TAG_LEN, in->data + in->len) ==
            0) {
            s3_quic_ssl_error(S3_LOG_INFO, log,
                              "EVP_CIPHER_CTX_ctrl(EVP_CTRL_AEAD_SET_TAG) failed");
            return S3_ERROR;
        }
    }

    if (EVP_CIPHER_mode(EVP_CIPHER_CTX_cipher(ctx)) == EVP_CIPH_CCM_MODE &&
        EVP_CipherUpdate(ctx, NULL, &len, NULL, in->len) != 1) {
        s3_quic_ssl_error(S3_LOG_INFO, log, "EVP_CipherUpdate() failed");
        return S3_ERROR;
    }

    if (EVP_CipherUpdate(ctx, NULL, &len, ad->data, ad->len) != 1) {
        s3_quic_ssl_error(S3_LOG_INFO, log, "EVP_CipherUpdate() failed");
        return S3_ERROR;
    }

    if (EVP_CipherUpdate(ctx, out->data, &len, in->data, in->len) != 1) {
        s3_quic_ssl_error(S3_LOG_INFO, log, "EVP_CipherUpdate() failed");
        return S3_ERROR;
    }

    out->len = len;

    if (EVP_CipherFinal_ex(ctx, out->data + out->len, &len) <= 0) {
        s3_quic_ssl_error(S3_LOG_INFO, log, "EVP_CipherFinal_ex failed");
        return S3_ERROR;
    }

    out->len += len;

    if (enc == 1) {
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, S3_QUIC_TAG_LEN,
                                out->data + out->len) == 0) {
            s3_quic_ssl_error(S3_LOG_INFO, log,
                              "EVP_CIPHER_CTX_ctrl(EVP_CTRL_AEAD_GET_TAG) failed");
            return S3_ERROR;
        }

        out->len += S3_QUIC_TAG_LEN;
    }

    return S3_OK;
}

void
s3_quic_crypto_cleanup(s3_quic_secret_t *s)
{
    if (s->ctx) {
        EVP_CIPHER_CTX_free(s->ctx);
        s->ctx = NULL;
    }
}

static s3_int_t
s3_quic_crypto_hp_init(const EVP_CIPHER *cipher, s3_quic_secret_t *s, s3_log_t *log)
{
    EVP_CIPHER_CTX *ctx;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        s3_quic_ssl_error(S3_LOG_INFO, log, "EVP_CIPHER_CTX_new() failed");
        return S3_ERROR;
    }

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, s->hp.data, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        s3_quic_ssl_error(S3_LOG_INFO, log, "EVP_EncryptInit_ex() failed");
        return S3_ERROR;
    }

    s->hp_ctx = ctx;

    return S3_OK;
}

static s3_int_t
s3_quic_crypto_hp(s3_quic_secret_t *s, u_char *out, u_char *in, s3_log_t *log)
{
    int             outlen;
    EVP_CIPHER_CTX *ctx;

    static const u_char zero[S3_QUIC_HP_LEN];

    ctx = s->hp_ctx;

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, in) != 1) {
        s3_quic_ssl_error(S3_LOG_INFO, log, "EVP_EncryptInit_ex() failed");
        return S3_ERROR;
    }

    if (!EVP_EncryptUpdate(ctx, out, &outlen, zero, S3_QUIC_HP_LEN)) {
        s3_quic_ssl_error(S3_LOG_INFO, log, "EVP_EncryptUpdate() failed");
        return S3_ERROR;
    }

    if (!EVP_EncryptFinal_ex(ctx, out + S3_QUIC_HP_LEN, &outlen)) {
        s3_quic_ssl_error(S3_LOG_INFO, log, "EVP_EncryptFinal_Ex() failed");
        return S3_ERROR;
    }

    return S3_OK;
}

static void
s3_quic_crypto_hp_cleanup(s3_quic_secret_t *s)
{
    if (s->hp_ctx) {
        EVP_CIPHER_CTX_free(s->hp_ctx);
        s->hp_ctx = NULL;
    }
}

s3_int_t
s3_quic_keys_set_encryption_secret(s3_log_t *log, s3_uint_t is_write, s3_quic_keys_t *keys,
                                   s3_uint_t level, uint32_t cipher, const uint8_t *secret,
                                   size_t secret_len)
{
    s3_int_t          key_len;
    s3_str_t          secret_str;
    s3_uint_t         i;
    s3_quic_md_t      key;
    s3_quic_hkdf_t    seq[3];
    s3_quic_secret_t *peer_secret;
    s3_quic_ciphers_t ciphers;

    peer_secret = is_write ? &keys->secrets[level].server : &keys->secrets[level].client;

    keys->cipher = cipher;

    key_len = s3_quic_ciphers(keys->cipher, &ciphers);

    if (key_len == S3_ERROR) {
        s3_quic_ssl_error(S3_LOG_INFO, log, "unexpected cipher");
        return S3_ERROR;
    }

    if (sizeof(peer_secret->secret.data) < secret_len) {
        s3_log_error(S3_LOG_ALERT, log, 0, "unexpected secret len: %uz", secret_len);
        return S3_ERROR;
    }

    peer_secret->secret.len = secret_len;
    s3_memcpy(peer_secret->secret.data, secret, secret_len);

    key.len = key_len;
    peer_secret->iv.len = S3_QUIC_IV_LEN;
    peer_secret->hp.len = key_len;

    secret_str.len = secret_len;
    secret_str.data = (u_char *)secret;

    s3_quic_hkdf_set(&seq[0], "tls13 quic key", &key, &secret_str);
    s3_quic_hkdf_set(&seq[1], "tls13 quic iv", &peer_secret->iv, &secret_str);
    s3_quic_hkdf_set(&seq[2], "tls13 quic hp", &peer_secret->hp, &secret_str);

    for (i = 0; i < (sizeof(seq) / sizeof(seq[0])); i++) {
        if (s3_quic_hkdf_expand(&seq[i], ciphers.d, log) != S3_OK) {
            return S3_ERROR;
        }
    }

    if (s3_quic_crypto_init(ciphers.c, peer_secret, &key, is_write, log) == S3_ERROR) {
        return S3_ERROR;
    }

    if (s3_quic_crypto_hp_init(ciphers.hp, peer_secret, log) == S3_ERROR) {
        return S3_ERROR;
    }

    OPENSSL_cleanse(key.data, key.len);

    return S3_OK;
}

s3_uint_t
s3_quic_keys_available(s3_quic_keys_t *keys, s3_uint_t level, s3_uint_t is_write)
{
    if (is_write == 0) {
        return keys->secrets[level].client.ctx != NULL;
    }

    return keys->secrets[level].server.ctx != NULL;
}

void
s3_quic_keys_discard(s3_quic_keys_t *keys, s3_uint_t level)
{
    s3_quic_secret_t *client, *server;

    client = &keys->secrets[level].client;
    server = &keys->secrets[level].server;

    s3_quic_crypto_cleanup(client);
    s3_quic_crypto_cleanup(server);

    s3_quic_crypto_hp_cleanup(client);
    s3_quic_crypto_hp_cleanup(server);

    if (client->secret.len) {
        OPENSSL_cleanse(client->secret.data, client->secret.len);
        client->secret.len = 0;
    }

    if (server->secret.len) {
        OPENSSL_cleanse(server->secret.data, server->secret.len);
        server->secret.len = 0;
    }
}

void
s3_quic_keys_switch(s3_quic_keys_t *keys)
{
    s3_quic_secrets_t *current, *next, tmp;

    current = &keys->secrets[S3_QUIC_ENCRYPTION_APPLICATION];
    next = &keys->next_key;

    s3_quic_crypto_cleanup(&current->client);
    s3_quic_crypto_cleanup(&current->server);

    tmp = *current;
    *current = *next;
    *next = tmp;
}

/*
 * D1 adaptation: the reference works on the connection event and calls
 * s3_quic_close_connection() on failure; the caller owns that part
 */
s3_int_t
s3_quic_keys_update(s3_quic_keys_t *keys, s3_log_t *log)
{
    s3_int_t           key_len;
    s3_uint_t          i;
    s3_quic_md_t       client_key, server_key;
    s3_quic_hkdf_t     seq[6];
    s3_quic_ciphers_t  ciphers;
    s3_quic_secrets_t *current, *next;

    current = &keys->secrets[S3_QUIC_ENCRYPTION_APPLICATION];
    next = &keys->next_key;

    s3_log_debug0(S3_LOG_DEBUG_EVENT, log, 0, "quic key update");

    key_len = s3_quic_ciphers(keys->cipher, &ciphers);

    if (key_len == S3_ERROR) {
        goto failed;
    }

    client_key.len = key_len;
    server_key.len = key_len;

    next->client.secret.len = current->client.secret.len;
    next->client.iv.len = S3_QUIC_IV_LEN;
    next->client.hp = current->client.hp;
    next->client.hp_ctx = current->client.hp_ctx;

    next->server.secret.len = current->server.secret.len;
    next->server.iv.len = S3_QUIC_IV_LEN;
    next->server.hp = current->server.hp;
    next->server.hp_ctx = current->server.hp_ctx;

    s3_quic_hkdf_set(&seq[0], "tls13 quic ku", &next->client.secret, &current->client.secret);
    s3_quic_hkdf_set(&seq[1], "tls13 quic key", &client_key, &next->client.secret);
    s3_quic_hkdf_set(&seq[2], "tls13 quic iv", &next->client.iv, &next->client.secret);
    s3_quic_hkdf_set(&seq[3], "tls13 quic ku", &next->server.secret, &current->server.secret);
    s3_quic_hkdf_set(&seq[4], "tls13 quic key", &server_key, &next->server.secret);
    s3_quic_hkdf_set(&seq[5], "tls13 quic iv", &next->server.iv, &next->server.secret);

    for (i = 0; i < (sizeof(seq) / sizeof(seq[0])); i++) {
        if (s3_quic_hkdf_expand(&seq[i], ciphers.d, log) != S3_OK) {
            goto failed;
        }
    }

    if (s3_quic_crypto_init(ciphers.c, &next->client, &client_key, 0, log) == S3_ERROR) {
        goto failed;
    }

    if (s3_quic_crypto_init(ciphers.c, &next->server, &server_key, 1, log) == S3_ERROR) {
        goto failed;
    }

    OPENSSL_cleanse(current->client.secret.data, current->client.secret.len);
    OPENSSL_cleanse(current->server.secret.data, current->server.secret.len);

    current->client.secret.len = 0;
    current->server.secret.len = 0;

    OPENSSL_cleanse(client_key.data, client_key.len);
    OPENSSL_cleanse(server_key.data, server_key.len);

    return S3_OK;

failed:

    return S3_ERROR;
}

void
s3_quic_keys_cleanup(s3_quic_keys_t *keys)
{
    s3_uint_t          i;
    s3_quic_secrets_t *next;

    for (i = 0; i < S3_QUIC_ENCRYPTION_LAST; i++) {
        s3_quic_keys_discard(keys, i);
    }

    next = &keys->next_key;

    s3_quic_crypto_cleanup(&next->client);
    s3_quic_crypto_cleanup(&next->server);

    if (next->client.secret.len) {
        OPENSSL_cleanse(next->client.secret.data, next->client.secret.len);
        next->client.secret.len = 0;
    }

    if (next->server.secret.len) {
        OPENSSL_cleanse(next->server.secret.data, next->server.secret.len);
        next->server.secret.len = 0;
    }
}

static s3_int_t
s3_quic_create_packet(s3_quic_header_t *pkt, s3_str_t *res)
{
    u_char           *pnp, *sample;
    s3_str_t          ad, out;
    s3_uint_t         i;
    s3_quic_secret_t *secret;
    u_char            nonce[S3_QUIC_IV_LEN], mask[S3_QUIC_HP_LEN];

    ad.data = res->data;
    ad.len = s3_quic_create_header(pkt, ad.data, &pnp);

    out.len = pkt->payload.len + S3_QUIC_TAG_LEN;
    out.data = res->data + ad.len;

    secret = &pkt->keys->secrets[pkt->level].server;

    s3_memcpy(nonce, secret->iv.data, secret->iv.len);
    s3_quic_compute_nonce(nonce, sizeof(nonce), pkt->number);

    if (s3_quic_crypto_seal(secret, &out, nonce, &pkt->payload, &ad, pkt->log) != S3_OK) {
        return S3_ERROR;
    }

    sample = &out.data[4 - pkt->num_len];
    if (s3_quic_crypto_hp(secret, mask, sample, pkt->log) != S3_OK) {
        return S3_ERROR;
    }

    /* RFC 9001, 5.4.1.  Header Protection Application */
    ad.data[0] ^= mask[0] & s3_quic_pkt_hp_mask(pkt->flags);

    for (i = 0; i < pkt->num_len; i++) {
        pnp[i] ^= mask[i + 1];
    }

    res->len = ad.len + out.len;

    return S3_OK;
}

static s3_int_t
s3_quic_create_retry_packet(s3_quic_header_t *pkt, s3_str_t *res)
{
    u_char           *start;
    s3_str_t          ad, itag;
    s3_quic_secret_t  secret;
    s3_quic_ciphers_t ciphers;

    /* 5.8.  Retry Packet Integrity */
    static s3_quic_md_t key =
        s3_quic_md("\xbe\x0c\x69\x0b\x9f\x66\x57\x5a\x1d\x76\x6b\x54\xe3\x68\xc8\x4e");
    static const u_char nonce[S3_QUIC_IV_LEN] = {0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63,
                                                 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb};
    static s3_str_t     in = s3_string("");

    ad.data = res->data;
    ad.len = s3_quic_create_retry_itag(pkt, ad.data, &start);

    itag.data = ad.data + ad.len;
    itag.len = S3_QUIC_TAG_LEN;

    if (s3_quic_ciphers(S3_QUIC_INITIAL_CIPHER, &ciphers) == S3_ERROR) {
        return S3_ERROR;
    }

    secret.iv.len = S3_QUIC_IV_LEN;

    if (s3_quic_crypto_init(ciphers.c, &secret, &key, 1, pkt->log) == S3_ERROR) {
        return S3_ERROR;
    }

    if (s3_quic_crypto_seal(&secret, &itag, nonce, &in, &ad, pkt->log) != S3_OK) {
        s3_quic_crypto_cleanup(&secret);
        return S3_ERROR;
    }

    s3_quic_crypto_cleanup(&secret);

    res->len = itag.data + itag.len - start;
    res->data = start;

    return S3_OK;
}

s3_int_t
s3_quic_derive_key(s3_log_t *log, const char *label, s3_str_t *secret, s3_str_t *salt, u_char *out,
                   size_t len)
{
    size_t        is_len, info_len;
    uint8_t      *p;
    const EVP_MD *digest;

    uint8_t is[SHA256_DIGEST_LENGTH];
    uint8_t info[20];

    digest = EVP_sha256();
    is_len = SHA256_DIGEST_LENGTH;

    if (s3_hkdf_extract(is, &is_len, digest, secret->data, secret->len, salt->data, salt->len) !=
        S3_OK) {
        s3_quic_ssl_error(S3_LOG_INFO, log, "s3_hkdf_extract(%s) failed", label);
        return S3_ERROR;
    }

    info[0] = 0;
    info[1] = len;
    info[2] = s3_strlen(label);

    info_len = 2 + 1 + info[2] + 1;

    if (info_len >= 20) {
        s3_log_error(S3_LOG_INFO, log, 0, "s3_quic_derive_key label \"%s\" too long", label);
        return S3_ERROR;
    }

    p = s3_cpymem(&info[3], label, info[2]);
    *p = '\0';

    if (s3_hkdf_expand(out, len, digest, is, is_len, info, info_len) != S3_OK) {
        s3_quic_ssl_error(S3_LOG_INFO, log, "s3_hkdf_expand(%s) failed", label);
        return S3_ERROR;
    }

    return S3_OK;
}

static uint64_t
s3_quic_parse_pn(u_char **pos, s3_int_t len, u_char *mask, uint64_t *largest_pn)
{
    u_char  *p;
    uint64_t truncated_pn, expected_pn, candidate_pn;
    uint64_t pn_nbits, pn_win, pn_hwin, pn_mask;

    pn_nbits = s3_min(len * 8, 62);

    p = *pos;
    truncated_pn = *p++ ^ *mask++;

    while (--len) {
        truncated_pn = (truncated_pn << 8) + (*p++ ^ *mask++);
    }

    *pos = p;

    expected_pn = *largest_pn + 1;
    pn_win = 1ULL << pn_nbits;
    pn_hwin = pn_win / 2;
    pn_mask = pn_win - 1;

    candidate_pn = (expected_pn & ~pn_mask) | truncated_pn;

    if ((int64_t)candidate_pn <= (int64_t)(expected_pn - pn_hwin) &&
        candidate_pn < (1ULL << 62) - pn_win) {
        candidate_pn += pn_win;

    } else if (candidate_pn > expected_pn + pn_hwin && candidate_pn >= pn_win) {
        candidate_pn -= pn_win;
    }

    *largest_pn = s3_max((int64_t)*largest_pn, (int64_t)candidate_pn);

    return candidate_pn;
}

void
s3_quic_compute_nonce(u_char *nonce, size_t len, uint64_t pn)
{
    nonce[len - 8] ^= (pn >> 56) & 0x3f;
    nonce[len - 7] ^= (pn >> 48) & 0xff;
    nonce[len - 6] ^= (pn >> 40) & 0xff;
    nonce[len - 5] ^= (pn >> 32) & 0xff;
    nonce[len - 4] ^= (pn >> 24) & 0xff;
    nonce[len - 3] ^= (pn >> 16) & 0xff;
    nonce[len - 2] ^= (pn >> 8) & 0xff;
    nonce[len - 1] ^= pn & 0xff;
}

s3_int_t
s3_quic_encrypt(s3_quic_header_t *pkt, s3_str_t *res)
{
    if (s3_quic_pkt_retry(pkt->flags)) {
        return s3_quic_create_retry_packet(pkt, res);
    }

    return s3_quic_create_packet(pkt, res);
}

s3_int_t
s3_quic_decrypt(s3_quic_header_t *pkt, uint64_t *largest_pn)
{
    u_char           *p, *sample;
    size_t            len;
    uint64_t          pn, lpn;
    s3_int_t          pnl;
    s3_str_t          in, ad;
    s3_uint_t         key_phase;
    s3_quic_secret_t *secret;
    uint8_t           nonce[S3_QUIC_IV_LEN], mask[S3_QUIC_HP_LEN];

    secret = &pkt->keys->secrets[pkt->level].client;

    p = pkt->raw->pos;
    len = pkt->data + pkt->len - p;

    /*
     * RFC 9001, 5.4.2. Header Protection Sample
     *           5.4.3. AES-Based Header Protection
     *           5.4.4. ChaCha20-Based Header Protection
     *
     * the Packet Number field is assumed to be 4 bytes long
     * AES and ChaCha20 algorithms sample 16 bytes
     */

    if (len < S3_QUIC_TAG_LEN + 4) {
        return S3_DECLINED;
    }

    sample = p + 4;

    /* header protection */

    if (s3_quic_crypto_hp(secret, mask, sample, pkt->log) != S3_OK) {
        return S3_DECLINED;
    }

    pkt->flags ^= mask[0] & s3_quic_pkt_hp_mask(pkt->flags);

    if (s3_quic_short_pkt(pkt->flags)) {
        key_phase = (pkt->flags & S3_QUIC_PKT_KPHASE) != 0;

        if (key_phase != pkt->key_phase) {
            if (pkt->keys->next_key.client.ctx != NULL) {
                secret = &pkt->keys->next_key.client;
                pkt->key_update = 1;

            } else {
                /*
                 * RFC 9001,  6.3. Timing of Receive Key Generation.
                 *
                 * Trial decryption to avoid timing side-channel.
                 */
                s3_log_debug0(S3_LOG_DEBUG_EVENT, pkt->log, 0, "quic next key missing");
            }
        }
    }

    lpn = *largest_pn;

    pnl = (pkt->flags & 0x03) + 1;
    pn = s3_quic_parse_pn(&p, pnl, &mask[1], &lpn);

    pkt->pn = pn;

    s3_log_debug1(S3_LOG_DEBUG_EVENT, pkt->log, 0, "quic packet rx clearflags:%xd", pkt->flags);
    s3_log_debug2(S3_LOG_DEBUG_EVENT, pkt->log, 0, "quic packet rx number:%uL len:%xi", pn, pnl);

    /* packet protection */

    in.data = p;
    in.len = len - pnl;

    ad.len = p - pkt->data;
    ad.data = pkt->plaintext;

    s3_memcpy(ad.data, pkt->data, ad.len);
    ad.data[0] = pkt->flags;

    do {
        ad.data[ad.len - pnl] = pn >> (8 * (pnl - 1)) % 256;
    } while (--pnl);

    s3_memcpy(nonce, secret->iv.data, secret->iv.len);
    s3_quic_compute_nonce(nonce, sizeof(nonce), pn);

    pkt->payload.len = in.len - S3_QUIC_TAG_LEN;
    pkt->payload.data = pkt->plaintext + ad.len;

    if (s3_quic_crypto_open(secret, &pkt->payload, nonce, &in, &ad, pkt->log) != S3_OK) {
        return S3_DECLINED;
    }

    if (pkt->payload.len == 0) {
        /*
         * RFC 9000, 12.4.  Frames and Frame Types
         *
         * An endpoint MUST treat receipt of a packet containing no
         * frames as a connection error of type PROTOCOL_VIOLATION.
         */
        s3_log_error(S3_LOG_INFO, pkt->log, 0, "quic zero-length packet");
        pkt->error = S3_QUIC_ERR_PROTOCOL_VIOLATION;
        return S3_ERROR;
    }

    if (pkt->flags & s3_quic_pkt_rb_mask(pkt->flags)) {
        /*
         * RFC 9000, Reserved Bits
         *
         * An endpoint MUST treat receipt of a packet that has
         * a non-zero value for these bits, after removing both
         * packet and header protection, as a connection error
         * of type PROTOCOL_VIOLATION.
         */
        s3_log_error(S3_LOG_INFO, pkt->log, 0, "quic reserved bit set in packet");
        pkt->error = S3_QUIC_ERR_PROTOCOL_VIOLATION;
        return S3_ERROR;
    }

    *largest_pn = lpn;

    return S3_OK;
}
