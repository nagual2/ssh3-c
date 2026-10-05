/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the OIDC module: the base64url codec, the flat-JSON scanner, the
 * JWKS parse of the RSA and the EC keys, the id_token verification
 * (the happy path and the reject table: tamper, exp, iss, aud,
 * nonce, kid, alg) and the kid rotation of the key cache; the keys
 * and the tokens mint in the test over OpenSSL; the verifier
 * behaviours (the unknown-kid schedule with the stampede guard, the
 * ttl rotation with the grace) ride the fetch seam, the scripted
 * hook counts the attempts without the network
 */

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <string.h>
#include <time.h>

#include <s3_ssh3_oidc.h>

#include "s3_test.h"

#define T_ISSUER "https://issuer.example"
#define T_AUD    "ssh3-c-cli"
#define T_NONCE  "n-abc-123"

static EVP_PKEY *t_rsa1;
static EVP_PKEY *t_rsa2;
static EVP_PKEY *t_ec;

/* ------------------------------------------------------------------ */
/* the helpers: the JWK json, the jwt mint                             */
/* ------------------------------------------------------------------ */

static size_t
t_b64url(const u_char *in, size_t len, void *out)
{
    return s3_ssh3_oidc_b64url_encode(in, len, out);
}

static int
t_jwk_rsa(EVP_PKEY *key, const char *kid, char *buf, size_t max)
{
    BIGNUM *n = NULL, *e = NULL;
    u_char  nb[512], eb[8];
    char    nb64[1024], eb64[32];
    int     n_len, e_len;
    size_t  nn, en;

    if (EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_N, &n) != 1 ||
        EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_E, &e) != 1) {
        BN_free(n);
        BN_free(e);
        return -1;
    }

    n_len = BN_num_bytes(n);
    e_len = BN_num_bytes(e);

    if (n_len < 0 || (size_t)n_len > sizeof(nb)) {
        BN_free(n);
        BN_free(e);
        return -1;
    }

    BN_bn2bin(n, nb);
    BN_bn2bin(e, eb);

    BN_free(n);
    BN_free(e);

    nn = t_b64url(nb, (size_t)n_len, nb64);
    en = t_b64url(eb, (size_t)e_len, eb64);

    return snprintf(buf, max, "{\"kty\":\"RSA\",\"kid\":\"%s\",\"n\":\"%.*s\",\"e\":\"%.*s\"}", kid,
                    (int)nn, nb64, (int)en, eb64);
}

static int
t_jwk_ec(EVP_PKEY *key, const char *kid, char *buf, size_t max)
{
    BIGNUM *x = NULL, *y = NULL;
    u_char  xb[128], yb[128];
    size_t  xn, yn;

    if (EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_PUB_X, &x) != 1 ||
        EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_PUB_Y, &y) != 1) {
        BN_free(x);
        BN_free(y);
        return -1;
    }

    /* the coordinates ride fixed width, the leading zeros count */

    if (BN_bn2binpad(x, xb, 32) != 32 || BN_bn2binpad(y, yb, 32) != 32) {
        BN_free(x);
        BN_free(y);
        return -1;
    }

    BN_free(x);
    BN_free(y);

    xn = t_b64url(xb, 32, xb + 40);
    yn = t_b64url(yb, 32, yb + 40);

    return snprintf(buf, max,
                    "{\"kty\":\"EC\",\"kid\":\"%s\",\"crv\":\"P-256\",\"x\":\"%.*s\","
                    "\"y\":\"%.*s\"}",
                    kid, (int)xn, xb + 40, (int)yn, yb + 40);
}

/* the key set document of one or two jwk jsons */

static void
t_jwks_doc(char *doc, size_t max, const char *jwk1, const char *jwk2)
{
    if (jwk2 == NULL) {
        snprintf(doc, max, "{\"keys\":[%s]}", jwk1);

    } else {
        snprintf(doc, max, "{\"keys\":[%s,%s]}", jwk1, jwk2);
    }
}

/*
 * the mint of one id_token: the fixed header (the alg and the kid),
 * the payload json as given, the signature over header.payload; the
 * ES256 signature converts through the DER form like the provider
 * libraries do
 */

static int
t_mint(EVP_PKEY *key, int ec, const char *kid, const char *payload, char *out, size_t out_max)
{
    const char *alg = ec ? "ES256" : "RS256";
    char        hdr[128];
    u_char      sig[512], raw[64];
    size_t      hdr_raw, pay_raw, sig_len, off;
    EVP_MD_CTX *md;
    int         n;

    n = snprintf(hdr, sizeof(hdr), "{\"alg\":\"%s\",\"typ\":\"JWT\",\"kid\":\"%s\"}", alg, kid);

    if (n <= 0) {
        return -1;
    }

    hdr_raw = t_b64url((const u_char *)hdr, (size_t)n, out);

    if (hdr_raw + 1 >= out_max) {
        return -1;
    }

    out[hdr_raw] = '.';
    off = hdr_raw + 1;

    pay_raw = t_b64url((const u_char *)payload, s3_strlen(payload), out + off);

    if (off + pay_raw + 1 >= out_max) {
        return -1;
    }

    out[off + pay_raw] = '.';

    md = EVP_MD_CTX_new();

    if (md == NULL) {
        return -1;
    }

    sig_len = sizeof(sig);

    if (EVP_DigestSignInit(md, NULL, EVP_sha256(), NULL, key) != 1 ||
        EVP_DigestSign(md, sig, &sig_len, (const u_char *)out, off + pay_raw) != 1) {
        EVP_MD_CTX_free(md);
        return -1;
    }

    EVP_MD_CTX_free(md);

    if (ec) {

        /* the JWS carries the raw r||s, the signer speaks DER */

        if (s3_ssh3_oidc_ecdsa_der_to_raw(sig, sig_len, raw, 32) != S3_OK) {
            return -1;
        }

        sig_len = 64;
        s3_memcpy(sig, raw, sig_len);
    }

    if (off + pay_raw + 1 + t_b64url(sig, sig_len, (u_char *)out + off + pay_raw + 1) + 1 >
        out_max) {
        return -1;
    }

    /* the mint owns the envelope: terminate for the strlen of the
     * module (the compact JWS carries no padding) */

    off += pay_raw + 1;
    off += t_b64url(sig, sig_len, (u_char *)out + off);
    out[off] = '\0';

    return 0;
}

static int
t_payload(char *buf, size_t max, const char *iss, const char *aud, long long exp, const char *nonce)
{
    if (nonce == NULL) {
        return snprintf(buf, max,
                        "{\"iss\":\"%s\",\"sub\":\"user\",\"aud\":\"%s\",\"exp\":%lld,"
                        "\"iat\":%lld}",
                        iss, aud, exp, (long long)time(NULL));
    }

    return snprintf(buf, max,
                    "{\"iss\":\"%s\",\"sub\":\"user\",\"aud\":\"%s\",\"exp\":%lld,"
                    "\"iat\":%lld,\"nonce\":\"%s\"}",
                    iss, aud, exp, (long long)time(NULL), nonce);
}

/* ------------------------------------------------------------------ */
/* the sections                                                        */
/* ------------------------------------------------------------------ */

static int
s3_test_b64url(void)
{
    static const struct {
        const char *in;
        const char *out;
    } vecs[] = {{"", ""},           {"f", "Zg"},          {"fo", "Zm8"},         {"foo", "Zm9v"},
                {"foob", "Zm9vYg"}, {"fooba", "Zm9vYmE"}, {"foobar", "Zm9vYmFy"}};

    u_char dec[64];
    char   enc[128];
    size_t n, i;

    for (i = 0; i < sizeof(vecs) / sizeof(vecs[0]); i++) {

        n = t_b64url((const u_char *)vecs[i].in, s3_strlen(vecs[i].in), enc);

        S3_ASSERT(n == s3_strlen(vecs[i].out));
        S3_ASSERT(s3_memcmp(enc, vecs[i].out, n) == 0);

        S3_ASSERT(s3_ssh3_oidc_b64url_decode((const u_char *)vecs[i].out, n, dec, &n) == S3_OK);
        S3_ASSERT(n == s3_strlen(vecs[i].in));
        S3_ASSERT(s3_memcmp(dec, vecs[i].in, n) == 0);
    }

    /* the padded form decodes, the alien alphabet dies, the lone
     * sextet dies */

    S3_ASSERT(s3_ssh3_oidc_b64url_decode((const u_char *)"Zm8=", 4, dec, &n) == S3_OK);
    S3_ASSERT(n == 2 && s3_memcmp(dec, "fo", 2) == 0);

    S3_ASSERT(s3_ssh3_oidc_b64url_decode((const u_char *)"Zm/v", 4, dec, &n) == S3_ERROR);
    S3_ASSERT(s3_ssh3_oidc_b64url_decode((const u_char *)"Z", 1, dec, &n) == S3_ERROR);

    /* the url-safe alphabet: -_ decodes like the JWS payloads do */

    S3_ASSERT(s3_ssh3_oidc_b64url_decode((const u_char *)"-_", 2, dec, &n) == S3_OK);
    S3_ASSERT(n == 1 && dec[0] == 0xfb);

    return s3_test_failures;
}

static int
s3_test_json(void)
{
    char              buf[128];
    s3_str_t          obj, value;
    int64_t           num;
    static const char doc[] =
        "{\"a\":1,\"str\":\"plain\",\"esc\":\"x\\n\\u0041y\",\"nested\":{\"str\":\"inner\"},"
        "\"arr\":[\"one\",\"two\"],\"neg\":-42}";

    obj.data = (u_char *)doc;
    obj.len = sizeof(doc) - 1;

    S3_ASSERT(s3_ssh3_oidc_json_string(&obj, "str", buf, sizeof(buf)) == S3_OK &&
              s3_strcmp(buf, "plain") == 0);

    /* the escapes decode: \n and the \u0041 unicode escape */

    S3_ASSERT(s3_ssh3_oidc_json_string(&obj, "esc", buf, sizeof(buf)) == S3_OK &&
              s3_strcmp(buf, "x\nAy") == 0);

    /* the nested member never leaks through the flat scan */

    S3_ASSERT(s3_ssh3_oidc_json_string(&obj, "nested", buf, sizeof(buf)) == S3_DECLINED);

    S3_ASSERT(s3_ssh3_oidc_json_find(&obj, "nested", &value) == S3_OK &&
              value.len == s3_strlen("{\"str\":\"inner\"}") &&
              s3_memcmp(value.data, "{\"str\":\"inner\"}", value.len) == 0);

    S3_ASSERT(s3_ssh3_oidc_json_int(&obj, "a", &num) == S3_OK && num == 1);
    S3_ASSERT(s3_ssh3_oidc_json_int(&obj, "neg", &num) == S3_OK && num == -42);
    S3_ASSERT(s3_ssh3_oidc_json_int(&obj, "absent", &num) == S3_DECLINED);
    S3_ASSERT(s3_ssh3_oidc_json_int(&obj, "str", &num) == S3_DECLINED);

    /* the aud forms: the single string and the array member */

    {
        static const char aud_str[] = "{\"aud\":\"cli\",\"x\":2}";
        static const char aud_arr[] = "{\"aud\":[\"other\",\"cli\"]}";
        static const char aud_none[] = "{\"sub\":\"cli\"}";

        s3_str_t a;

        a.data = (u_char *)aud_str;
        a.len = sizeof(aud_str) - 1;
        S3_ASSERT(s3_ssh3_oidc_json_aud_contains(&a, "cli") == S3_OK);
        S3_ASSERT(s3_ssh3_oidc_json_aud_contains(&a, "other") == S3_DECLINED);

        a.data = (u_char *)aud_arr;
        a.len = sizeof(aud_arr) - 1;
        S3_ASSERT(s3_ssh3_oidc_json_aud_contains(&a, "cli") == S3_OK);
        S3_ASSERT(s3_ssh3_oidc_json_aud_contains(&a, "two") == S3_DECLINED);

        a.data = (u_char *)aud_none;
        a.len = sizeof(aud_none) - 1;
        S3_ASSERT(s3_ssh3_oidc_json_aud_contains(&a, "cli") == S3_DECLINED);
    }

    /* the broken json dies */

    {
        static const char broken[] = "{\"a\":}";

        s3_str_t b;

        b.data = (u_char *)broken;
        b.len = sizeof(broken) - 1;

        S3_ASSERT(s3_ssh3_oidc_json_find(&b, "a", &value) == S3_ERROR);
    }

    return s3_test_failures;
}

static int
s3_test_jwks_parse(void)
{
    char                rsa_jwk[1024], ec_jwk[512], doc[2048];
    s3_ssh3_oidc_jwks_t jwks;

    S3_ASSERT(t_jwk_rsa(t_rsa1, "rsa1", rsa_jwk, sizeof(rsa_jwk)) > 0);
    S3_ASSERT(t_jwk_ec(t_ec, "ec1", ec_jwk, sizeof(ec_jwk)) > 0);

    s3_memzero(&jwks, sizeof(jwks));

    t_jwks_doc(doc, sizeof(doc), rsa_jwk, ec_jwk);

    S3_ASSERT(s3_ssh3_oidc_jwks_parse(&jwks, (const u_char *)doc, s3_strlen(doc)) == S3_OK);
    S3_ASSERT(jwks.nkeys == 2);
    S3_ASSERT(s3_strcmp(jwks.keys[0].kid, "rsa1") == 0 && !jwks.keys[0].ec);
    S3_ASSERT(s3_strcmp(jwks.keys[1].kid, "ec1") == 0 && jwks.keys[1].ec);

    s3_ssh3_oidc_jwks_clear(&jwks);

    /* the malformed sets die: no keys member, the keyless object */

    S3_ASSERT(s3_ssh3_oidc_jwks_parse(&jwks, (const u_char *)"{\"kty\":\"RSA\"}", 13) == S3_ERROR);

    S3_ASSERT(s3_ssh3_oidc_jwks_parse(&jwks, (const u_char *)"{\"keys\":[{\"kty\":\"RSA\"}]}",
                                      25) == S3_ERROR);

    s3_ssh3_oidc_jwks_clear(&jwks);

    return s3_test_failures;
}

static int
s3_test_verify_happy(void)
{
    char                doc[2048], rsa_jwk[1024], ec_jwk[512];
    char                payload[512], token[4096];
    long long           exp;
    s3_ssh3_oidc_jwks_t jwks;

    exp = (long long)time(NULL) + 600;

    s3_memzero(&jwks, sizeof(jwks));

    /* the RS256 happy path with the conversation nonce */

    S3_ASSERT(t_jwk_rsa(t_rsa1, "rsa1", rsa_jwk, sizeof(rsa_jwk)) > 0);
    t_jwks_doc(doc, sizeof(doc), rsa_jwk, NULL);
    S3_ASSERT(s3_ssh3_oidc_jwks_parse(&jwks, (const u_char *)doc, s3_strlen(doc)) == S3_OK);

    S3_ASSERT(t_payload(payload, sizeof(payload), T_ISSUER, T_AUD, exp, T_NONCE) > 0);
    S3_ASSERT(t_mint(t_rsa1, 0, "rsa1", payload, token, sizeof(token)) == 0);

    S3_ASSERT(s3_ssh3_oidc_verify(&jwks, T_ISSUER, T_AUD, token, T_NONCE, time(NULL)) == S3_OK);

    /* the empty expected nonce skips the gate, the reference shape */

    S3_ASSERT(s3_ssh3_oidc_verify(&jwks, T_ISSUER, T_AUD, token, "", time(NULL)) == S3_OK);

    /* the ES256 happy path */

    s3_ssh3_oidc_jwks_clear(&jwks);

    S3_ASSERT(t_jwk_ec(t_ec, "ec1", ec_jwk, sizeof(ec_jwk)) > 0);
    t_jwks_doc(doc, sizeof(doc), ec_jwk, NULL);
    S3_ASSERT(s3_ssh3_oidc_jwks_parse(&jwks, (const u_char *)doc, s3_strlen(doc)) == S3_OK);

    S3_ASSERT(t_mint(t_ec, 1, "ec1", payload, token, sizeof(token)) == 0);

    S3_ASSERT(s3_ssh3_oidc_verify(&jwks, T_ISSUER, T_AUD, token, T_NONCE, time(NULL)) == S3_OK);

    s3_ssh3_oidc_jwks_clear(&jwks);

    return s3_test_failures;
}

static int
s3_test_verify_rejects(void)
{
    char                doc[2048], rsa_jwk[1024], ec_jwk[512];
    char                payload[512], token[4096], alt[4096], tok2[4096], hdr[128];
    long long           exp;
    size_t              hlen;
    char               *dot1, *dot2;
    s3_int_t            rc;
    s3_ssh3_oidc_jwks_t jwks, jwks2;

    exp = (long long)time(NULL) + 600;

    s3_memzero(&jwks, sizeof(jwks));

    S3_ASSERT(t_jwk_rsa(t_rsa1, "rsa1", rsa_jwk, sizeof(rsa_jwk)) > 0);
    t_jwks_doc(doc, sizeof(doc), rsa_jwk, NULL);
    S3_ASSERT(s3_ssh3_oidc_jwks_parse(&jwks, (const u_char *)doc, s3_strlen(doc)) == S3_OK);

    S3_ASSERT(t_payload(payload, sizeof(payload), T_ISSUER, T_AUD, exp, T_NONCE) > 0);
    S3_ASSERT(t_mint(t_rsa1, 0, "rsa1", payload, token, sizeof(token)) == 0);

    dot1 = strchr(token, '.');
    dot2 = strchr(dot1 + 1, '.');

    S3_ASSERT(dot1 != NULL && dot2 != NULL);

    /* the tampered signature: the valid claims, the broken sig (the
     * first char of the segment decides the first decoded byte) */

    S3_ASSERT(t_mint(t_rsa1, 0, "rsa1", payload, token, sizeof(token)) == 0);

    dot1 = strchr(token, '.');
    dot2 = strchr(dot1 + 1, '.');

    S3_ASSERT(dot1 != NULL && dot2 != NULL);

    dot2[1] = (dot2[1] == 'A') ? 'B' : 'A';

    S3_ASSERT(s3_ssh3_oidc_verify(&jwks, T_ISSUER, T_AUD, token, T_NONCE, time(NULL)) ==
              S3_SSH3_OIDC_ESIG);

    /* the tampered payload: the byte of the segment flips, some
     * claim gate rejects the result (the en/decode stays in shape) */

    S3_ASSERT(t_mint(t_rsa1, 0, "rsa1", payload, token, sizeof(token)) == 0);

    dot1 = strchr(token, '.');

    dot1[1] = (dot1[1] == 'A') ? 'B' : 'A';

    rc = s3_ssh3_oidc_verify(&jwks, T_ISSUER, T_AUD, token, T_NONCE, time(NULL));

    S3_ASSERT(rc != S3_OK);

    /* the envelope rejects: the missing parts, the extra dot */

    S3_ASSERT(s3_ssh3_oidc_verify(&jwks, T_ISSUER, T_AUD, "a.b", NULL, time(NULL)) ==
              S3_SSH3_OIDC_EFORM);
    S3_ASSERT(s3_ssh3_oidc_verify(&jwks, T_ISSUER, T_AUD, "a.b.c.d", NULL, time(NULL)) ==
              S3_SSH3_OIDC_EFORM);
    S3_ASSERT(s3_ssh3_oidc_verify(&jwks, T_ISSUER, T_AUD, ".b.c", NULL, time(NULL)) ==
              S3_SSH3_OIDC_EFORM);
    S3_ASSERT(s3_ssh3_oidc_verify(&jwks, T_ISSUER, T_AUD, "a..c", NULL, time(NULL)) ==
              S3_SSH3_OIDC_EFORM);

    /* the exp gate: the expired token */

    exp = (long long)time(NULL) - 10;

    S3_ASSERT(t_payload(payload, sizeof(payload), T_ISSUER, T_AUD, exp, T_NONCE) > 0);
    S3_ASSERT(t_mint(t_rsa1, 0, "rsa1", payload, token, sizeof(token)) == 0);
    S3_ASSERT(s3_ssh3_oidc_verify(&jwks, T_ISSUER, T_AUD, token, T_NONCE, time(NULL)) ==
              S3_SSH3_OIDC_EEXP);

    /* the future nbf rides the exp code, the go-oidc leeway shape */

    {
        char npayload[512];

        snprintf(npayload, sizeof(npayload),
                 "{\"iss\":\"%s\",\"aud\":\"%s\",\"exp\":%lld,\"nbf\":%lld}", T_ISSUER, T_AUD,
                 (long long)time(NULL) + 600, (long long)time(NULL) + 3600);

        S3_ASSERT(t_mint(t_rsa1, 0, "rsa1", npayload, token, sizeof(token)) == 0);
        S3_ASSERT(s3_ssh3_oidc_verify(&jwks, T_ISSUER, T_AUD, token, NULL, time(NULL)) ==
                  S3_SSH3_OIDC_EEXP);
    }

    /* the iss gate: the signature holds, the claim does not */

    exp = (long long)time(NULL) + 600;

    S3_ASSERT(t_payload(payload, sizeof(payload), "https://evil.example", T_AUD, exp, T_NONCE) > 0);
    S3_ASSERT(t_mint(t_rsa1, 0, "rsa1", payload, token, sizeof(token)) == 0);
    S3_ASSERT(s3_ssh3_oidc_verify(&jwks, T_ISSUER, T_AUD, token, T_NONCE, time(NULL)) ==
              S3_SSH3_OIDC_EISS);

    /* the aud gate */

    S3_ASSERT(t_payload(payload, sizeof(payload), T_ISSUER, "other-client", exp, T_NONCE) > 0);
    S3_ASSERT(t_mint(t_rsa1, 0, "rsa1", payload, token, sizeof(token)) == 0);
    S3_ASSERT(s3_ssh3_oidc_verify(&jwks, T_ISSUER, T_AUD, token, T_NONCE, time(NULL)) ==
              S3_SSH3_OIDC_EAUD);

    /* the nonce gate */

    S3_ASSERT(t_payload(payload, sizeof(payload), T_ISSUER, T_AUD, exp, "n-other") > 0);
    S3_ASSERT(t_mint(t_rsa1, 0, "rsa1", payload, token, sizeof(token)) == 0);
    S3_ASSERT(s3_ssh3_oidc_verify(&jwks, T_ISSUER, T_AUD, token, T_NONCE, time(NULL)) ==
              S3_SSH3_OIDC_ENONCE);

    /* the unknown kid */

    S3_ASSERT(t_payload(payload, sizeof(payload), T_ISSUER, T_AUD, exp, T_NONCE) > 0);
    S3_ASSERT(t_mint(t_rsa1, 0, "rsa-other", payload, token, sizeof(token)) == 0);
    S3_ASSERT(s3_ssh3_oidc_verify(&jwks, T_ISSUER, T_AUD, token, T_NONCE, time(NULL)) ==
              S3_SSH3_OIDC_EKID);

    /* the alg outside the allowlist: the HS256 header swaps in, the
     * check fires before the key (RFC 8725 the algorithm confusion);
     * the scratch token rides alt, the payload stays the claims */

    S3_ASSERT(t_mint(t_rsa1, 0, "rsa1", payload, token, sizeof(token)) == 0);

    dot1 = strchr(token, '.');

    S3_ASSERT(dot1 != NULL);

    memcpy(alt, dot1, s3_strlen(dot1) + 1); /* the .payload.sig tail */

    hlen = snprintf(hdr, sizeof(hdr), "{\"alg\":\"HS256\",\"typ\":\"JWT\",\"kid\":\"rsa1\"}");
    hlen = t_b64url((const u_char *)hdr, hlen, (u_char *)tok2);

    s3_memcpy(tok2 + hlen, alt, s3_strlen(alt) + 1);

    S3_ASSERT(s3_ssh3_oidc_verify(&jwks, T_ISSUER, T_AUD, tok2, T_NONCE, time(NULL)) ==
              S3_SSH3_OIDC_EALG);

    /* the alg off the key type: the RS256 token under the EC kid */

    s3_memzero(&jwks2, sizeof(jwks2));

    S3_ASSERT(t_jwk_ec(t_ec, "ec1", ec_jwk, sizeof(ec_jwk)) > 0);
    t_jwks_doc(doc, sizeof(doc), ec_jwk, NULL);
    S3_ASSERT(s3_ssh3_oidc_jwks_parse(&jwks2, (const u_char *)doc, s3_strlen(doc)) == S3_OK);

    S3_ASSERT(t_mint(t_rsa1, 0, "ec1", payload, token, sizeof(token)) == 0);
    S3_ASSERT(s3_ssh3_oidc_verify(&jwks2, T_ISSUER, T_AUD, token, T_NONCE, time(NULL)) ==
              S3_SSH3_OIDC_EALG);

    s3_ssh3_oidc_jwks_clear(&jwks2);
    s3_ssh3_oidc_jwks_clear(&jwks);

    return s3_test_failures;
}

static int
s3_test_rotation(void)
{
    char                doc[2048], jwk_a[1024], jwk_b[1024];
    char                payload[512], token_a[4096], token_b[4096];
    long long           exp;
    s3_ssh3_oidc_jwks_t jwks;

    exp = (long long)time(NULL) + 600;

    S3_ASSERT(t_jwk_rsa(t_rsa1, "rsa1", jwk_a, sizeof(jwk_a)) > 0);
    S3_ASSERT(t_jwk_rsa(t_rsa2, "rsa2", jwk_b, sizeof(jwk_b)) > 0);

    S3_ASSERT(t_payload(payload, sizeof(payload), T_ISSUER, T_AUD, exp, T_NONCE) > 0);
    S3_ASSERT(t_mint(t_rsa1, 0, "rsa1", payload, token_a, sizeof(token_a)) == 0);
    S3_ASSERT(t_mint(t_rsa2, 0, "rsa2", payload, token_b, sizeof(token_b)) == 0);

    /* the stale cache of the kid rsa1: the token of rsa2 declines */

    s3_memzero(&jwks, sizeof(jwks));

    t_jwks_doc(doc, sizeof(doc), jwk_a, NULL);
    S3_ASSERT(s3_ssh3_oidc_jwks_parse(&jwks, (const u_char *)doc, s3_strlen(doc)) == S3_OK);

    S3_ASSERT(s3_ssh3_oidc_verify(&jwks, T_ISSUER, T_AUD, token_a, T_NONCE, time(NULL)) == S3_OK);
    S3_ASSERT(s3_ssh3_oidc_verify(&jwks, T_ISSUER, T_AUD, token_b, T_NONCE, time(NULL)) ==
              S3_SSH3_OIDC_EKID);

    /* the parse adds the rotated kid: both tokens live */

    t_jwks_doc(doc, sizeof(doc), jwk_b, NULL);
    S3_ASSERT(s3_ssh3_oidc_jwks_parse(&jwks, (const u_char *)doc, s3_strlen(doc)) == S3_OK);
    S3_ASSERT(jwks.nkeys == 2);

    S3_ASSERT(s3_ssh3_oidc_verify(&jwks, T_ISSUER, T_AUD, token_a, T_NONCE, time(NULL)) == S3_OK);
    S3_ASSERT(s3_ssh3_oidc_verify(&jwks, T_ISSUER, T_AUD, token_b, T_NONCE, time(NULL)) == S3_OK);

    /* the fetch form replaces the set: the stale kid dies */

    s3_ssh3_oidc_jwks_clear(&jwks);
    S3_ASSERT(s3_ssh3_oidc_jwks_parse(&jwks, (const u_char *)doc, s3_strlen(doc)) == S3_OK);
    S3_ASSERT(jwks.nkeys == 1);

    S3_ASSERT(s3_ssh3_oidc_verify(&jwks, T_ISSUER, T_AUD, token_a, T_NONCE, time(NULL)) ==
              S3_SSH3_OIDC_EKID);
    S3_ASSERT(s3_ssh3_oidc_verify(&jwks, T_ISSUER, T_AUD, token_b, T_NONCE, time(NULL)) == S3_OK);

    /* the same kid replaces its key, the set stays one */

    S3_ASSERT(t_jwk_rsa(t_rsa1, "rsa2", jwk_a, sizeof(jwk_a)) > 0);
    t_jwks_doc(doc, sizeof(doc), jwk_a, NULL);
    S3_ASSERT(s3_ssh3_oidc_jwks_parse(&jwks, (const u_char *)doc, s3_strlen(doc)) == S3_OK);
    S3_ASSERT(jwks.nkeys == 1);

    s3_ssh3_oidc_jwks_clear(&jwks);

    return s3_test_failures;
}

static int
s3_test_verifier_offline(void)
{
    char                    doc[2048], jwk[1024];
    char                    payload[512], token[4096];
    long long               exp;
    s3_ssh3_oidc_verifier_t v;

    exp = (long long)time(NULL) + 600;

    S3_ASSERT(t_jwk_rsa(t_rsa1, "rsa1", jwk, sizeof(jwk)) > 0);
    t_jwks_doc(doc, sizeof(doc), jwk, NULL);

    S3_ASSERT(t_payload(payload, sizeof(payload), T_ISSUER, T_AUD, exp, T_NONCE) > 0);
    S3_ASSERT(t_mint(t_rsa1, 0, "rsa1", payload, token, sizeof(token)) == 0);

    /* the offline verifier: no network, the keys parse in by hand */

    S3_ASSERT(s3_ssh3_oidc_verifier_init_offline(&v, T_ISSUER) == S3_OK);
    S3_ASSERT(s3_ssh3_oidc_jwks_parse(&v.jwks, (const u_char *)doc, s3_strlen(doc)) == S3_OK);

    S3_ASSERT(s3_ssh3_oidc_verifier_verify(&v, T_AUD, token, T_NONCE, time(NULL)) == S3_OK);
    S3_ASSERT(s3_ssh3_oidc_verifier_verify(&v, "other", token, T_NONCE, time(NULL)) ==
              S3_SSH3_OIDC_EAUD);

    s3_ssh3_oidc_verifier_clear(&v);

    return s3_test_failures;
}

/* ------------------------------------------------------------------ */
/* the fetch seam: the scripted refresh of the verifier                 */
/* ------------------------------------------------------------------ */

static int         t_fetch_calls;
static int         t_fetch_fail;
static const char *t_fetch_doc;

static s3_int_t
t_fetch_hook(const s3_ssh3_oidc_provider_t *provider, const char *ca_file,
             s3_ssh3_oidc_jwks_t *jwks)
{
    (void)provider;
    (void)ca_file;

    t_fetch_calls++;

    if (t_fetch_fail) {
        return S3_ERROR;
    }

    /* the fetch replaces the whole set, like the built-in form */

    s3_ssh3_oidc_jwks_clear(jwks);

    return s3_ssh3_oidc_jwks_parse(jwks, (const u_char *)t_fetch_doc, s3_strlen(t_fetch_doc));
}

/*
 * the stampede guard of the unknown kid: the first verify schedules
 * exactly one background fetch, the verifies during the schedule (and
 * inside the cooldown window) schedule nothing, the fetch cycle of
 * the wiring timer closes the episode
 */

static int
s3_test_verifier_kid_refetch(void)
{
    char                    doc[2048], jwk[1024];
    char                    payload[512], token[4096];
    long long               exp;
    time_t                  t0 = 1700000000;
    s3_ssh3_oidc_verifier_t v;

    exp = t0 + 600;

    S3_ASSERT(t_payload(payload, sizeof(payload), T_ISSUER, T_AUD, exp, T_NONCE) > 0);
    S3_ASSERT(t_mint(t_rsa2, 0, "rsa-other", payload, token, sizeof(token)) == 0);

    /* the offline verifier rides the fetch seam: the uri rides in so
     * the unknown-kid path schedules, the cache of rsa1 is good at t0 */

    S3_ASSERT(s3_ssh3_oidc_verifier_init_offline(&v, T_ISSUER) == S3_OK);
    snprintf(v.provider.jwks_uri, sizeof(v.provider.jwks_uri), "http://127.0.0.1:1/jwks");

    S3_ASSERT(t_jwk_rsa(t_rsa1, "rsa1", jwk, sizeof(jwk)) > 0);
    t_jwks_doc(doc, sizeof(doc), jwk, NULL);
    S3_ASSERT(s3_ssh3_oidc_jwks_parse(&v.jwks, (const u_char *)doc, s3_strlen(doc)) == S3_OK);

    v.jwks_time = t0;
    v.fetch_fn = t_fetch_hook;

    t_fetch_calls = 0;
    t_fetch_fail = 0;
    t_fetch_doc = doc;

    /* the good set owes nothing till the ttl ends */

    S3_ASSERT(s3_ssh3_oidc_verifier_fetch_timer(&v, t0 + 1) > 0);

    /* the unknown kid: the schedule of one fetch, the retryable kid
     * reject answers the request itself */

    S3_ASSERT(s3_ssh3_oidc_verifier_verify(&v, T_AUD, token, T_NONCE, t0 + 1) == S3_SSH3_OIDC_EKID);
    S3_ASSERT(v.fetch_due == 1);

    /* the request during the schedule: no second episode */

    S3_ASSERT(s3_ssh3_oidc_verifier_verify(&v, T_AUD, token, T_NONCE, t0 + 2) == S3_SSH3_OIDC_EKID);
    S3_ASSERT(v.fetch_due == 1);

    /* the wiring timer closes the schedule: exactly one fetch cycle */

    S3_ASSERT(s3_ssh3_oidc_verifier_fetch_timer(&v, t0 + 2) == 0);
    S3_ASSERT(s3_ssh3_oidc_verifier_fetch(&v, t0 + 3) == S3_OK);
    S3_ASSERT(t_fetch_calls == 1);
    S3_ASSERT(v.fetch_due == 0);

    /* the retry inside the cooldown window schedules nothing */

    S3_ASSERT(s3_ssh3_oidc_verifier_verify(&v, T_AUD, token, T_NONCE, t0 + 4) == S3_SSH3_OIDC_EKID);
    S3_ASSERT(v.fetch_due == 0);
    S3_ASSERT(t_fetch_calls == 1);

    /* the window out: the next episode may schedule again */

    S3_ASSERT(s3_ssh3_oidc_verifier_verify(&v, T_AUD, token, T_NONCE, t0 + 9) == S3_SSH3_OIDC_EKID);
    S3_ASSERT(v.fetch_due == 1);

    S3_ASSERT(s3_ssh3_oidc_verifier_fetch(&v, t0 + 10) == S3_OK);
    S3_ASSERT(t_fetch_calls == 2);

    s3_ssh3_oidc_verifier_clear(&v);

    return s3_test_failures;
}

/*
 * the ttl of the key set: the request path serves the stale set past
 * the ttl (the rotation rides the timer only), the failed rotation
 * keeps the old set (the grace) and rides the retry cadence, the
 * landed rotation replaces the set
 */

static int
s3_test_verifier_ttl(void)
{
    char                    doc_a[2048], doc_b[2048], jwk_a[1024], jwk_b[1024];
    char                    payload[512], token_a[4096], token_b[4096];
    long long               exp;
    time_t                  t0 = 1700000000;
    s3_ssh3_oidc_verifier_t v;

    exp = t0 + 600;

    S3_ASSERT(t_jwk_rsa(t_rsa1, "rsa1", jwk_a, sizeof(jwk_a)) > 0);
    S3_ASSERT(t_jwk_rsa(t_rsa2, "rsa2", jwk_b, sizeof(jwk_b)) > 0);
    t_jwks_doc(doc_a, sizeof(doc_a), jwk_a, NULL);
    t_jwks_doc(doc_b, sizeof(doc_b), jwk_b, NULL);

    S3_ASSERT(t_payload(payload, sizeof(payload), T_ISSUER, T_AUD, exp, T_NONCE) > 0);
    S3_ASSERT(t_mint(t_rsa1, 0, "rsa1", payload, token_a, sizeof(token_a)) == 0);
    S3_ASSERT(t_mint(t_rsa2, 0, "rsa2", payload, token_b, sizeof(token_b)) == 0);

    S3_ASSERT(s3_ssh3_oidc_verifier_init_offline(&v, T_ISSUER) == S3_OK);
    snprintf(v.provider.jwks_uri, sizeof(v.provider.jwks_uri), "http://127.0.0.1:1/jwks");

    s3_ssh3_oidc_verifier_set_ttl(&v, 10);

    S3_ASSERT(s3_ssh3_oidc_jwks_parse(&v.jwks, (const u_char *)doc_a, s3_strlen(doc_a)) == S3_OK);

    v.jwks_time = t0;
    v.fetch_fn = t_fetch_hook;

    t_fetch_calls = 0;
    t_fetch_fail = 0;
    t_fetch_doc = doc_b;

    /* the delay till the rotation: the ttl decides */

    S3_ASSERT(s3_ssh3_oidc_verifier_fetch_timer(&v, t0 + 1) == (s3_msec_t)9 * 1000);

    /* the stale set serves past the ttl: the request path never
     * fetches, the timer owes the rotation */

    S3_ASSERT(s3_ssh3_oidc_verifier_verify(&v, T_AUD, token_a, T_NONCE, t0 + 11) == S3_OK);
    S3_ASSERT(t_fetch_calls == 0);
    S3_ASSERT(s3_ssh3_oidc_verifier_fetch_timer(&v, t0 + 11) == 0);

    /* the failed rotation keeps the old set, the retry rides the
     * failure cadence */

    t_fetch_fail = 1;

    S3_ASSERT(s3_ssh3_oidc_verifier_fetch(&v, t0 + 11) == S3_ERROR);
    S3_ASSERT(t_fetch_calls == 1);
    S3_ASSERT(v.jwks.nkeys == 1);

    S3_ASSERT(s3_ssh3_oidc_verifier_verify(&v, T_AUD, token_a, T_NONCE, t0 + 12) == S3_OK);
    S3_ASSERT(s3_ssh3_oidc_verifier_fetch_timer(&v, t0 + 13) == (s3_msec_t)58 * 1000);

    /* the retried rotation lands: the new kid lives, the old one
     * rotates out, the ttl window restarts */

    t_fetch_fail = 0;

    S3_ASSERT(s3_ssh3_oidc_verifier_fetch(&v, t0 + 71) == S3_OK);
    S3_ASSERT(v.jwks_time == t0 + 71);

    S3_ASSERT(s3_ssh3_oidc_verifier_verify(&v, T_AUD, token_b, T_NONCE, t0 + 72) == S3_OK);
    S3_ASSERT(s3_ssh3_oidc_verifier_verify(&v, T_AUD, token_a, T_NONCE, t0 + 72) ==
              S3_SSH3_OIDC_EKID);
    S3_ASSERT(s3_ssh3_oidc_verifier_fetch_timer(&v, t0 + 72) == (s3_msec_t)9 * 1000);

    s3_ssh3_oidc_verifier_clear(&v);

    return s3_test_failures;
}

/* the built-in fetch: the dead endpoint keeps the old key set */

static int
s3_test_jwks_fetch_grace(void)
{
    char                    doc[2048], jwk[1024];
    s3_ssh3_oidc_provider_t provider;
    s3_ssh3_oidc_jwks_t     jwks;

    s3_memzero(&provider, sizeof(provider));
    snprintf(provider.jwks_uri, sizeof(provider.jwks_uri), "http://127.0.0.1:1/jwks");

    S3_ASSERT(t_jwk_rsa(t_rsa1, "rsa1", jwk, sizeof(jwk)) > 0);
    t_jwks_doc(doc, sizeof(doc), jwk, NULL);

    s3_memzero(&jwks, sizeof(jwks));
    S3_ASSERT(s3_ssh3_oidc_jwks_parse(&jwks, (const u_char *)doc, s3_strlen(doc)) == S3_OK);

    S3_ASSERT(s3_ssh3_oidc_jwks_fetch(&provider, NULL, &jwks) == S3_ERROR);
    S3_ASSERT(jwks.nkeys == 1);

    s3_ssh3_oidc_jwks_clear(&jwks);

    return s3_test_failures;
}

static int
s3_test_ssh3_oidc(void)
{
    /* the fixtures live through the run, the EVP frees them */

    t_rsa1 = EVP_RSA_gen(2048);
    t_rsa2 = EVP_RSA_gen(2048);
    t_ec = EVP_EC_gen("P-256");

    S3_ASSERT(t_rsa1 != NULL);
    S3_ASSERT(t_rsa2 != NULL);
    S3_ASSERT(t_ec != NULL);

    if (t_rsa1 == NULL || t_rsa2 == NULL || t_ec == NULL) {
        return s3_test_failures;
    }

    (void)s3_test_b64url();
    (void)s3_test_json();
    (void)s3_test_jwks_parse();
    (void)s3_test_verify_happy();
    (void)s3_test_verify_rejects();
    (void)s3_test_rotation();
    (void)s3_test_verifier_offline();
    (void)s3_test_verifier_kid_refetch();
    (void)s3_test_verifier_ttl();
    (void)s3_test_jwks_fetch_grace();

    EVP_PKEY_free(t_rsa1);
    EVP_PKEY_free(t_rsa2);
    EVP_PKEY_free(t_ec);

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_ssh3_oidc)
