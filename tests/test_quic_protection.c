/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <openssl/tls1.h>

#include <s3_quic.h>
#include <s3_quic_protection.h>

#include "s3_test.h"

/*
 * RFC 9001, A.1.  Initial Secrets: DCID 0x8394c8f03e515708
 */
static const u_char a1_dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};

static const u_char a1_client_secret[32] = {
    0xc0, 0x0c, 0xf1, 0x51, 0xca, 0x5b, 0xe0, 0x75, 0xed, 0x0e, 0xbf, 0xb5, 0xc8, 0x03, 0x23, 0xc4,
    0x2d, 0x6b, 0x7d, 0xb6, 0x78, 0x81, 0x28, 0x9a, 0xf4, 0x00, 0x8f, 0x1f, 0x6c, 0x35, 0x7a, 0xea};

static const u_char a1_client_iv[12] = {0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3,
                                        0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c};

static const u_char a1_client_hp[16] = {0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10,
                                        0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2};

static const u_char a1_server_secret[32] = {
    0x3c, 0x19, 0x98, 0x28, 0xfd, 0x13, 0x9e, 0xfd, 0x21, 0x6c, 0x15, 0x5a, 0xd8, 0x44, 0xcc, 0x81,
    0xfb, 0x82, 0xfa, 0x8d, 0x74, 0x46, 0xfa, 0x7d, 0x78, 0xbe, 0x80, 0x3a, 0xcd, 0xda, 0x95, 0x1b};

static const u_char a1_server_iv[12] = {0x0a, 0xc1, 0x49, 0x3c, 0xa1, 0x90,
                                        0x58, 0x53, 0xb0, 0xbb, 0xa0, 0x3e};

static const u_char a1_server_hp[16] = {0xc2, 0x06, 0xb8, 0xd9, 0xb9, 0xf0, 0xf3, 0x76,
                                        0x44, 0x43, 0x0b, 0x49, 0x0e, 0xea, 0xa3, 0x14};

static s3_log_t s3_test_log;

static int
test_initial_secrets(void)
{
    s3_quic_keys_t    keys;
    s3_str_t          secret;
    s3_quic_secret_t *c, *s;

    s3_memzero(&keys, sizeof(s3_quic_keys_t));

    secret.len = sizeof(a1_dcid);
    secret.data = (u_char *)a1_dcid;

    S3_ASSERT(s3_quic_keys_set_initial_secret(&keys, &secret, &s3_test_log) == S3_OK);

    c = &keys.secrets[S3_QUIC_ENCRYPTION_INITIAL].client;
    s = &keys.secrets[S3_QUIC_ENCRYPTION_INITIAL].server;

    S3_ASSERT(c->secret.len == 32);
    S3_ASSERT(s3_memcmp(c->secret.data, a1_client_secret, 32) == 0);
    S3_ASSERT(c->iv.len == 12);
    S3_ASSERT(s3_memcmp(c->iv.data, a1_client_iv, 12) == 0);
    S3_ASSERT(c->hp.len == 16);
    S3_ASSERT(s3_memcmp(c->hp.data, a1_client_hp, 16) == 0);

    S3_ASSERT(s->secret.len == 32);
    S3_ASSERT(s3_memcmp(s->secret.data, a1_server_secret, 32) == 0);
    S3_ASSERT(s->iv.len == 12);
    S3_ASSERT(s3_memcmp(s->iv.data, a1_server_iv, 12) == 0);
    S3_ASSERT(s->hp.len == 16);
    S3_ASSERT(s3_memcmp(s->hp.data, a1_server_hp, 16) == 0);

    S3_ASSERT(s3_quic_keys_available(&keys, S3_QUIC_ENCRYPTION_INITIAL, 0) == 1);
    S3_ASSERT(s3_quic_keys_available(&keys, S3_QUIC_ENCRYPTION_INITIAL, 1) == 1);
    S3_ASSERT(s3_quic_keys_available(&keys, S3_QUIC_ENCRYPTION_APPLICATION, 0) == 0);

    s3_quic_keys_cleanup(&keys);

    S3_ASSERT(s3_quic_keys_available(&keys, S3_QUIC_ENCRYPTION_INITIAL, 0) == 0);
    S3_ASSERT(keys.secrets[S3_QUIC_ENCRYPTION_INITIAL].client.secret.len == 0);

    return s3_test_failures;
}

static int
test_ciphers(void)
{
    s3_quic_ciphers_t ciphers;

    S3_ASSERT(s3_quic_ciphers(TLS1_3_CK_AES_128_GCM_SHA256, &ciphers) == 16);
    S3_ASSERT(ciphers.d == EVP_sha256());

    S3_ASSERT(s3_quic_ciphers(TLS1_3_CK_AES_256_GCM_SHA384, &ciphers) == 32);
    S3_ASSERT(ciphers.d == EVP_sha384());

    S3_ASSERT(s3_quic_ciphers(TLS1_3_CK_CHACHA20_POLY1305_SHA256, &ciphers) == 32);
    S3_ASSERT(s3_quic_ciphers(TLS1_3_CK_AES_128_CCM_SHA256, &ciphers) == 16);

    S3_ASSERT(s3_quic_ciphers(0xdeadbeef, &ciphers) == S3_ERROR);

    return s3_test_failures;
}

static int
test_seal_open(void)
{
    s3_quic_md_t     key;
    s3_quic_secret_t enc, dec;
    u_char           keybuf[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    u_char   nonce[12] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc};
    u_char   plain[13] = "quic payload";
    u_char   ad[5] = {0xc0, 0x00, 0x00, 0x01, 0x00};
    u_char   ct[64], rt[64];
    s3_str_t in, out, a;

    key.len = 16;
    s3_memcpy(key.data, keybuf, 16);

    s3_memzero(&enc, sizeof(s3_quic_secret_t));
    s3_memzero(&dec, sizeof(s3_quic_secret_t));

    enc.iv.len = 12;
    dec.iv.len = 12;

    S3_ASSERT(s3_quic_crypto_init(EVP_aes_128_gcm(), &enc, &key, 1, &s3_test_log) == S3_OK);
    S3_ASSERT(s3_quic_crypto_init(EVP_aes_128_gcm(), &dec, &key, 0, &s3_test_log) == S3_OK);

    in.len = sizeof(plain);
    in.data = plain;
    a.len = sizeof(ad);
    a.data = ad;

    out.len = sizeof(plain) + S3_QUIC_TAG_LEN;
    out.data = ct;

    S3_ASSERT(s3_quic_crypto_seal(&enc, &out, nonce, &in, &a, &s3_test_log) == S3_OK);
    S3_ASSERT(out.len == sizeof(plain) + S3_QUIC_TAG_LEN);

    /* decrypt roundtrip */

    in.len = out.len;
    in.data = ct;

    out.len = sizeof(rt);
    out.data = rt;

    S3_ASSERT(s3_quic_crypto_open(&dec, &out, nonce, &in, &a, &s3_test_log) == S3_OK);
    S3_ASSERT(out.len == sizeof(plain));
    S3_ASSERT(s3_memcmp(rt, plain, sizeof(plain)) == 0);

    /* broken ciphertext fails authentication */

    ct[0] ^= 0xff;

    in.len = sizeof(plain) + S3_QUIC_TAG_LEN;
    in.data = ct;
    out.len = sizeof(rt);
    out.data = rt;

    S3_ASSERT(s3_quic_crypto_open(&dec, &out, nonce, &in, &a, &s3_test_log) == S3_ERROR);

    ct[0] ^= 0xff;

    /* broken associated data fails authentication */

    ad[0] ^= 0xff;

    in.len = sizeof(plain) + S3_QUIC_TAG_LEN;
    in.data = ct;
    out.len = sizeof(rt);
    out.data = rt;

    S3_ASSERT(s3_quic_crypto_open(&dec, &out, nonce, &in, &a, &s3_test_log) == S3_ERROR);

    s3_quic_crypto_cleanup(&enc);
    s3_quic_crypto_cleanup(&dec);

    return s3_test_failures;
}

static int
test_encryption_secret(void)
{
    s3_quic_keys_t keys;
    uint8_t        tls_secret[32];
    size_t         i;

    for (i = 0; i < 32; i++) {
        tls_secret[i] = (uint8_t)(0xa0 + i);
    }

    s3_memzero(&keys, sizeof(s3_quic_keys_t));

    S3_ASSERT(s3_quic_keys_set_encryption_secret(
                  &s3_test_log, 1, &keys, S3_QUIC_ENCRYPTION_APPLICATION,
                  TLS1_3_CK_AES_128_GCM_SHA256, tls_secret, sizeof(tls_secret)) == S3_OK);

    S3_ASSERT(keys.cipher == TLS1_3_CK_AES_128_GCM_SHA256);
    S3_ASSERT(s3_quic_keys_available(&keys, S3_QUIC_ENCRYPTION_APPLICATION, 1) == 1);
    S3_ASSERT(s3_quic_keys_available(&keys, S3_QUIC_ENCRYPTION_APPLICATION, 0) == 0);

    S3_ASSERT(keys.secrets[S3_QUIC_ENCRYPTION_APPLICATION].server.secret.len == 32);
    S3_ASSERT(s3_memcmp(keys.secrets[S3_QUIC_ENCRYPTION_APPLICATION].server.secret.data, tls_secret,
                        32) == 0);
    S3_ASSERT(keys.secrets[S3_QUIC_ENCRYPTION_APPLICATION].server.iv.len == S3_QUIC_IV_LEN);
    S3_ASSERT(keys.secrets[S3_QUIC_ENCRYPTION_APPLICATION].server.hp.len == 16);

    /* wrong cipher suite id fails */

    S3_ASSERT(s3_quic_keys_set_encryption_secret(&s3_test_log, 1, &keys,
                                                 S3_QUIC_ENCRYPTION_APPLICATION, 0xdeadbeef,
                                                 tls_secret, 32) == S3_ERROR);

    s3_quic_keys_discard(&keys, S3_QUIC_ENCRYPTION_APPLICATION);

    S3_ASSERT(s3_quic_keys_available(&keys, S3_QUIC_ENCRYPTION_APPLICATION, 1) == 0);
    S3_ASSERT(keys.secrets[S3_QUIC_ENCRYPTION_APPLICATION].server.secret.len == 0);

    return s3_test_failures;
}

static int
test_keys_update_switch(void)
{
    s3_quic_keys_t  keys;
    uint8_t         tls_secret[32];
    size_t          i;
    EVP_CIPHER_CTX *client_ctx, *server_ctx;

    for (i = 0; i < 32; i++) {
        tls_secret[i] = (uint8_t)(0x40 + i);
    }

    s3_memzero(&keys, sizeof(s3_quic_keys_t));

    /* client (read) and server (write) application secrets */

    S3_ASSERT(s3_quic_keys_set_encryption_secret(
                  &s3_test_log, 0, &keys, S3_QUIC_ENCRYPTION_APPLICATION,
                  TLS1_3_CK_AES_128_GCM_SHA256, tls_secret, sizeof(tls_secret)) == S3_OK);

    tls_secret[0] ^= 0xff;

    S3_ASSERT(s3_quic_keys_set_encryption_secret(
                  &s3_test_log, 1, &keys, S3_QUIC_ENCRYPTION_APPLICATION,
                  TLS1_3_CK_AES_128_GCM_SHA256, tls_secret, sizeof(tls_secret)) == S3_OK);

    /* key update fills next_key */

    S3_ASSERT(s3_quic_keys_update(&keys, &s3_test_log) == S3_OK);
    S3_ASSERT(keys.next_key.client.ctx != NULL);
    S3_ASSERT(keys.next_key.server.ctx != NULL);
    S3_ASSERT(keys.next_key.client.iv.len == S3_QUIC_IV_LEN);

    client_ctx = keys.next_key.client.ctx;
    server_ctx = keys.next_key.server.ctx;

    /* the switch rotates next_key into place */

    s3_quic_keys_switch(&keys);

    S3_ASSERT(keys.secrets[S3_QUIC_ENCRYPTION_APPLICATION].client.ctx == client_ctx);
    S3_ASSERT(keys.secrets[S3_QUIC_ENCRYPTION_APPLICATION].server.ctx == server_ctx);
    S3_ASSERT(s3_quic_keys_available(&keys, S3_QUIC_ENCRYPTION_APPLICATION, 0) == 1);
    S3_ASSERT(s3_quic_keys_available(&keys, S3_QUIC_ENCRYPTION_APPLICATION, 1) == 1);

    s3_quic_keys_cleanup(&keys);

    return s3_test_failures;
}

static int
test_initial_packet_roundtrip(void)
{
    s3_quic_keys_t   keys, rxkeys;
    s3_quic_header_t pkt, rx;
    s3_str_t         secret, res;
    u_char           scid[5] = {0x85, 0x4f, 0x5b, 0x6a, 0x3c};
    u_char           payload[4] = {S3_QUIC_FT_PING, 0x00, 0x00, 0x00};
    u_char           resbuf[128], scratch[128];
    uint64_t         largest;

    s3_memzero(&keys, sizeof(s3_quic_keys_t));
    s3_memzero(&rxkeys, sizeof(s3_quic_keys_t));

    secret.len = sizeof(a1_dcid);
    secret.data = (u_char *)a1_dcid;

    S3_ASSERT(s3_quic_keys_set_initial_secret(&keys, &secret, &s3_test_log) == S3_OK);

    /*
     * the receiving side: the peer write secrets (server) become our
     * read secrets (client), like the ssl layer does in D2
     */
    S3_ASSERT(s3_quic_keys_set_encryption_secret(
                  &s3_test_log, 0, &rxkeys, S3_QUIC_ENCRYPTION_INITIAL,
                  TLS1_3_CK_AES_128_GCM_SHA256,
                  keys.secrets[S3_QUIC_ENCRYPTION_INITIAL].server.secret.data,
                  keys.secrets[S3_QUIC_ENCRYPTION_INITIAL].server.secret.len) == S3_OK);

    /* encrypt a server Initial packet */

    s3_memzero(&pkt, sizeof(s3_quic_header_t));
    pkt.log = &s3_test_log;
    pkt.flags = 0xc0; /* long, fixed, Initial */
    pkt.version = 1;
    pkt.level = S3_QUIC_ENCRYPTION_INITIAL;
    pkt.keys = &keys;
    pkt.number = 0;
    pkt.num_len = 1;
    pkt.trunc = 0;
    pkt.dcid.len = sizeof(a1_dcid);
    pkt.dcid.data = (u_char *)a1_dcid;
    pkt.scid.len = sizeof(scid);
    pkt.scid.data = scid;
    pkt.payload.len = sizeof(payload);
    pkt.payload.data = payload;

    res.len = sizeof(resbuf);
    res.data = resbuf;

    S3_ASSERT(s3_quic_encrypt(&pkt, &res) == S3_OK);
    S3_ASSERT(res.len == 23 + sizeof(payload) + S3_QUIC_TAG_LEN);

    /* decrypt as the client; raw->pos points at the packet number */

    s3_memzero(&rx, sizeof(s3_quic_header_t));
    rx.log = &s3_test_log;
    rx.flags = resbuf[0];
    rx.raw = &(s3_buf_t){.pos = resbuf + 22, .last = resbuf + res.len};
    rx.data = resbuf;
    rx.len = res.len;
    rx.level = S3_QUIC_ENCRYPTION_INITIAL;
    rx.keys = &rxkeys;
    rx.plaintext = scratch;

    largest = S3_QUIC_UNSET_PN;

    S3_ASSERT(s3_quic_decrypt(&rx, &largest) == S3_OK);
    S3_ASSERT(rx.pn == 0);
    S3_ASSERT(largest == 0);
    S3_ASSERT(rx.payload.len == (ssize_t)sizeof(payload));
    S3_ASSERT(s3_memcmp(rx.payload.data, payload, sizeof(payload)) == 0);

    /* tampered ciphertext is declined */

    resbuf[res.len - 1] ^= 0xff;

    rx.flags = resbuf[0];
    rx.raw->pos = resbuf + 1;
    largest = S3_QUIC_UNSET_PN;

    S3_ASSERT(s3_quic_decrypt(&rx, &largest) == S3_DECLINED);

    resbuf[res.len - 1] ^= 0xff;

    /* tampered header (associated data) is declined */

    resbuf[2] ^= 0x01;

    rx.flags = resbuf[0];
    rx.raw->pos = resbuf + 1;
    largest = S3_QUIC_UNSET_PN;

    S3_ASSERT(s3_quic_decrypt(&rx, &largest) == S3_DECLINED);

    resbuf[2] ^= 0x01;

    /* packet number larger than one byte still roundtrips */

    s3_memzero(&pkt, sizeof(s3_quic_header_t));
    pkt.log = &s3_test_log;
    pkt.flags = 0xc1; /* pn len 2 */
    pkt.version = 1;
    pkt.level = S3_QUIC_ENCRYPTION_INITIAL;
    pkt.keys = &keys;
    pkt.number = 300;
    pkt.num_len = 2;
    pkt.trunc = 300;
    pkt.dcid.len = sizeof(a1_dcid);
    pkt.dcid.data = (u_char *)a1_dcid;
    pkt.scid.len = sizeof(scid);
    pkt.scid.data = scid;
    pkt.payload.len = sizeof(payload);
    pkt.payload.data = payload;

    res.len = sizeof(resbuf);
    res.data = resbuf;

    S3_ASSERT(s3_quic_encrypt(&pkt, &res) == S3_OK);

    s3_memzero(&rx, sizeof(s3_quic_header_t));
    rx.log = &s3_test_log;
    rx.flags = resbuf[0];
    rx.raw = &(s3_buf_t){.pos = resbuf + 22, .last = resbuf + res.len};
    rx.data = resbuf;
    rx.len = res.len;
    rx.level = S3_QUIC_ENCRYPTION_INITIAL;
    rx.keys = &rxkeys;
    rx.plaintext = scratch;

    largest = 299;

    S3_ASSERT(s3_quic_decrypt(&rx, &largest) == S3_OK);
    S3_ASSERT(rx.pn == 300);

    s3_quic_keys_cleanup(&keys);
    s3_quic_keys_cleanup(&rxkeys);

    return s3_test_failures;
}

static int
s3_test_quic_protection(void)
{
    s3_test_log.log_level = S3_LOG_ALERT;
    s3_test_log.fd = S3_INVALID_FILE;

    test_initial_secrets();
    test_ciphers();
    test_seal_open();
    test_encryption_secret();
    test_keys_update_switch();
    test_initial_packet_roundtrip();

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_quic_protection)
