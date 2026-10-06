/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the Bearer JWT pubkey verifier (docs/P4-WIRE.md 7): the token
 * signature against the authorized_keys blobs (ed25519, P-256, RSA)
 * and the reference claim set (iss/sub/aud/client_id/jti/exp/iat/nbf)
 */

#include <s3_core.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>

#include <string.h>
#include <time.h>
#include <unistd.h>

#include <s3_ssh3_auth_jwt.h>

#include "s3_test.h"

/* the fixed conversation id of the fixtures, 32 bytes like the exporter */

static const u_char s3_tj_conv[32] = {0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
                                      11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                                      22, 23, 24, 25, 26, 27, 28, 29, 30, 31};

/* the base64url of a JWT segment, the raw unpadded shape, NUL is for
 * the snprintf callers, the length excludes it */

static size_t
s3_tj_b64url(const u_char *in, size_t len, char *out)
{
    static const char alpha[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    size_t o, i;

    for (o = 0, i = 0; i + 3 <= len; i += 3) {

        unsigned v = ((unsigned)in[i] << 16) | ((unsigned)in[i + 1] << 8) | in[i + 2];

        out[o++] = alpha[(v >> 18) & 63];
        out[o++] = alpha[(v >> 12) & 63];
        out[o++] = alpha[(v >> 6) & 63];
        out[o++] = alpha[v & 63];
    }

    if (len - i == 1) {

        unsigned v = (unsigned)in[i] << 16;

        out[o++] = alpha[(v >> 18) & 63];
        out[o++] = alpha[(v >> 12) & 63];

    } else if (len - i == 2) {

        unsigned v = ((unsigned)in[i] << 16) | ((unsigned)in[i + 1] << 8);

        out[o++] = alpha[(v >> 18) & 63];
        out[o++] = alpha[(v >> 12) & 63];
        out[o++] = alpha[(v >> 6) & 63];
    }

    out[o] = '\0';

    return o;
}

/* the standard base64: padding optional (raw), the authorized_keys
 * blob shape; padded when pad is set (the jti form of the reference) */

static size_t
s3_tj_b64std(const u_char *in, size_t len, char *out, unsigned pad)
{
    static const char alpha[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    size_t o, i;

    for (o = 0, i = 0; i + 3 <= len; i += 3) {

        unsigned v = ((unsigned)in[i] << 16) | ((unsigned)in[i + 1] << 8) | in[i + 2];

        out[o++] = alpha[(v >> 18) & 63];
        out[o++] = alpha[(v >> 12) & 63];
        out[o++] = alpha[(v >> 6) & 63];
        out[o++] = alpha[v & 63];
    }

    if (len - i == 1) {

        unsigned v = (unsigned)in[i] << 16;

        out[o++] = alpha[(v >> 18) & 63];
        out[o++] = alpha[(v >> 12) & 63];

        if (pad) {
            out[o++] = '=';
            out[o++] = '=';
        }

    } else if (len - i == 2) {

        unsigned v = ((unsigned)in[i] << 16) | ((unsigned)in[i + 1] << 8);

        out[o++] = alpha[(v >> 18) & 63];
        out[o++] = alpha[(v >> 12) & 63];
        out[o++] = alpha[(v >> 6) & 63];

        if (pad) {
            out[o++] = '=';
        }
    }

    out[o] = '\0';

    return o;
}

/* the key fixtures: ed25519, P-256, RSA-2048 */

static EVP_PKEY *
s3_tj_gen_ed25519(void)
{
    EVP_PKEY_CTX *ctx;
    EVP_PKEY     *key = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);

    S3_ASSERT(ctx != NULL);

    if (ctx == NULL) {
        return NULL;
    }

    S3_ASSERT(EVP_PKEY_keygen_init(ctx) == 1);
    S3_ASSERT(EVP_PKEY_generate(ctx, &key) == 1);

    EVP_PKEY_CTX_free(ctx);

    return key;
}

static EVP_PKEY *
s3_tj_gen_ec256(void)
{
    EVP_PKEY_CTX *ctx;
    EVP_PKEY     *key = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);

    S3_ASSERT(ctx != NULL);

    if (ctx == NULL) {
        return NULL;
    }

    S3_ASSERT(EVP_PKEY_keygen_init(ctx) == 1);
    S3_ASSERT(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) > 0);
    S3_ASSERT(EVP_PKEY_generate(ctx, &key) == 1);

    EVP_PKEY_CTX_free(ctx);

    return key;
}

static EVP_PKEY *
s3_tj_gen_rsa2048(void)
{
    EVP_PKEY_CTX *ctx;
    EVP_PKEY     *key = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);

    S3_ASSERT(ctx != NULL);

    if (ctx == NULL) {
        return NULL;
    }

    S3_ASSERT(EVP_PKEY_keygen_init(ctx) == 1);
    S3_ASSERT(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) > 0);
    S3_ASSERT(EVP_PKEY_generate(ctx, &key) == 1);

    EVP_PKEY_CTX_free(ctx);

    return key;
}

/* the SSH wire primitives of the blob builders */

static u_char *
s3_tj_put_string(u_char *p, const u_char *data, size_t len)
{
    p[0] = (u_char)((len >> 24) & 0xff);
    p[1] = (u_char)((len >> 16) & 0xff);
    p[2] = (u_char)((len >> 8) & 0xff);
    p[3] = (u_char)(len & 0xff);

    if (len > 0) {
        memcpy(p + 4, data, len);
    }

    return p + 4 + len;
}

static u_char *
s3_tj_put_name(u_char *p, const char *name)
{
    return s3_tj_put_string(p, (const u_char *)name, strlen(name));
}

static u_char *
s3_tj_put_mpint(u_char *p, const BIGNUM *bn)
{
    u_char buf[512];
    int    n;

    n = BN_bn2bin(bn, buf);

    S3_ASSERT(n >= 0 && (size_t)n <= sizeof(buf));

    if (n > 0 && (buf[0] & 0x80)) {

        /* the positive mpint carries the sign guard byte */

        u_char guarded[513];

        guarded[0] = 0;
        memcpy(guarded + 1, buf, (size_t)n);

        return s3_tj_put_string(p, guarded, (size_t)n + 1);
    }

    return s3_tj_put_string(p, buf, (size_t)n);
}

static size_t
s3_tj_blob_ed25519(EVP_PKEY *key, u_char *buf)
{
    u_char raw[64];
    size_t n = sizeof(raw), total;

    S3_ASSERT(EVP_PKEY_get_raw_public_key(key, raw, &n) == 1);
    S3_ASSERT(n == 32);

    total = 4 + 11 + 4 + 32;

    (void)s3_tj_put_name(buf, "ssh-ed25519");
    (void)s3_tj_put_string(buf + 4 + 11, raw, n);

    return total;
}

static size_t
s3_tj_blob_ec256(EVP_PKEY *key, u_char *buf)
{
    u_char q[128];
    size_t n = sizeof(q), total;

    S3_ASSERT(EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, q, sizeof(q), &n) == 1);

    total = 4 + 19 + 4 + 8 + 4 + n;

    (void)s3_tj_put_name(buf, "ecdsa-sha2-nistp256");
    (void)s3_tj_put_name(buf + 4 + 19, "nistp256");
    (void)s3_tj_put_string(buf + 4 + 19 + 4 + 8, q, n);

    return total;
}

static size_t
s3_tj_blob_rsa(EVP_PKEY *key, u_char *buf)
{
    BIGNUM *e = NULL, *n = NULL;
    u_char *p;

    S3_ASSERT(EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_E, &e) == 1);
    S3_ASSERT(EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_N, &n) == 1);

    p = s3_tj_put_name(buf, "ssh-rsa");
    p = s3_tj_put_mpint(p, e);
    p = s3_tj_put_mpint(p, n);

    BN_free(e);
    BN_free(n);

    return (size_t)(p - buf);
}

/* the JWT signature bytes for the alg over the signing input */

static size_t
s3_tj_sign(EVP_PKEY *key, const char *alg, const u_char *msg, size_t msglen, u_char *sig,
           size_t sig_cap)
{
    EVP_MD_CTX *ctx;
    size_t      siglen = 0;
    u_char      der[512];

    ctx = EVP_MD_CTX_new();

    S3_ASSERT(ctx != NULL);

    if (ctx == NULL) {
        return 0;
    }

    if (strcmp(alg, "EdDSA") == 0) {

        S3_ASSERT(EVP_DigestSignInit(ctx, NULL, NULL, NULL, key) == 1);

        /* the one-shot form takes the buffer size in *siglen */

        siglen = sig_cap;

        S3_ASSERT(EVP_DigestSign(ctx, sig, &siglen, msg, msglen) == 1);

    } else if (strcmp(alg, "ES256") == 0) {

        const unsigned char *derp;
        ECDSA_SIG           *s;
        const BIGNUM        *r, *rb;

        S3_ASSERT(EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, key) == 1);

        siglen = sizeof(der);

        S3_ASSERT(EVP_DigestSign(ctx, der, &siglen, msg, msglen) == 1);

        derp = der;
        s = d2i_ECDSA_SIG(NULL, &derp, (long)siglen);

        S3_ASSERT(s != NULL);

        ECDSA_SIG_get0(s, &r, &rb);

        S3_ASSERT(BN_bn2binpad(r, sig, 32) == 32);
        S3_ASSERT(BN_bn2binpad(rb, sig + 32, 32) == 32);

        ECDSA_SIG_free(s);

        siglen = 64;

    } else if (strcmp(alg, "RS256") == 0) {

        S3_ASSERT(EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, key) == 1);

        siglen = sizeof(der);

        S3_ASSERT(EVP_DigestSign(ctx, sig, &siglen, msg, msglen) == 1);

    } else {

        /*
         * the unknown names (the HS256 fixture) carry a dummy blob:
         * the module rejects them by the allowlist before any verify,
         * no mac key exists on this path
         */

        memset(sig, 0xaa, 32);

        siglen = 32;
    }

    EVP_MD_CTX_free(ctx);

    return siglen;
}

/* the compact token: b64url(header) . b64url(payload) . b64url(sig) */

static void
s3_tj_token(char *out, size_t cap, const char *alg, const char *payload, EVP_PKEY *key,
            unsigned no_sig)
{
    char   hb[128];
    u_char sig[512], msg[1600];
    size_t hlen, mlen, slen = 0;
    char  *p;

    S3_ASSERT(strlen(alg) < sizeof(hb) - 32);

    hlen = (size_t)snprintf(hb, sizeof(hb), "{\"alg\":\"%s\",\"typ\":\"JWT\"}", alg);

    /* the signing input is the two segments joined by the dot */

    mlen = s3_tj_b64url((const u_char *)hb, hlen, (char *)msg);

    S3_ASSERT(mlen + 1 < sizeof(msg));

    msg[mlen++] = '.';

    mlen += s3_tj_b64url((const u_char *)payload, strlen(payload), (char *)msg + mlen);

    S3_ASSERT(mlen < cap);

    memcpy(out, msg, mlen);

    p = out + mlen;

    if (!no_sig) {

        slen = s3_tj_sign(key, alg, msg, mlen, sig, sizeof(sig));

        S3_ASSERT(slen > 0 && slen <= sizeof(sig));

        /* the second dot joins the signature segment */

        *p++ = '.';

        p += s3_tj_b64url(sig, slen, p);
    }

    *p = '\0';
}

/* the claims payload, the zero values omit the claim */

static void
s3_tj_claims(char *out, size_t cap, const char *iss, const char *sub, const char *aud,
             const char *client_id, const char *jti, long long iat, long long exp, long long nbf)
{
    int n;

    n = snprintf(out, cap,
                 "{\"iss\":\"%s\",\"sub\":\"%s\",\"aud\":%s,\"client_id\":\"%s\","
                 "\"jti\":\"%s\"",
                 iss, sub, aud != NULL ? aud : "null", client_id, jti);

    S3_ASSERT(n > 0 && (size_t)n < cap);

    if (iat != 0) {
        n += snprintf(out + n, cap - (size_t)n, ",\"iat\":%lld", iat);
        S3_ASSERT(n > 0 && (size_t)n < cap);
    }

    if (exp != 0) {
        n += snprintf(out + n, cap - (size_t)n, ",\"exp\":%lld", exp);
        S3_ASSERT(n > 0 && (size_t)n < cap);
    }

    if (nbf != 0) {
        n += snprintf(out + n, cap - (size_t)n, ",\"nbf\":%lld", nbf);
        S3_ASSERT(n > 0 && (size_t)n < cap);
    }

    n += snprintf(out + n, cap - (size_t)n, "}");
    S3_ASSERT(n > 0 && (size_t)n < cap);
}

/* the fixture keys file, the mkstemp path lands in path */

static void
s3_tj_keysfile(char *path, const char *content)
{
    int     fd;
    ssize_t n = (ssize_t)strlen(content);

    strcpy(path, "/tmp/s3jwtXXXXXX");

    fd = mkstemp(path);

    S3_ASSERT(fd >= 0);
    S3_ASSERT(write(fd, content, (size_t)n) == n);
    S3_ASSERT(close(fd) == 0);
}

/* one verdict expectation */

static void
s3_tj_case(const char *name, const char *token, const char *user, const char *keysfile,
           const u_char *convid, size_t convid_len, s3_int_t expect)
{
    s3_str_t header, u;
    char     hdr[2200];
    s3_int_t rc;

    snprintf(hdr, sizeof(hdr), "Bearer %s", token);

    header.data = (u_char *)hdr;
    header.len = strlen(hdr);

    u.data = (u_char *)user;
    u.len = strlen(user);

    rc = s3_ssh3_auth_jwt_verify(&header, &u, keysfile, convid, convid_len);

    if (rc != expect) {
        printf("FAIL case %s: rc=%d expect=%d\n", name, (int)rc, (int)expect);
        s3_test_failures++;
    }
}

static void
s3_tj_flip(char *token, size_t zone)
{
    /* zone 0: the payload tail, zone 1: the signature head */

    char *second = strchr(token, '.'), *third = second != NULL ? strchr(second + 1, '.') : NULL;

    S3_ASSERT(second != NULL && third != NULL);

    if (zone == 0 && third > token + 1) {
        third[-1] = (third[-1] == 'A') ? 'B' : 'A';

    } else if (zone == 1 && third[1] != '\0') {
        third[1] = (third[1] == 'A') ? 'B' : 'A';
    }
}

static int
s3_test_ssh3_auth_jwt(void)
{
    char      path_a[32], path_ec[32], path_rsa[32], path_multi[32], path_idents[32];
    char      path_raw[32], path_stale[32];
    char      content[4096], blob[512], blob_b64[800], jti[64], claims[1024];
    char      token[2200];
    long long now = (long long)time(NULL);
    EVP_PKEY *ed, *foreign, *ec, *rsa;
    size_t    blob_len;

    ed = s3_tj_gen_ed25519();
    foreign = s3_tj_gen_ed25519();
    ec = s3_tj_gen_ec256();
    rsa = s3_tj_gen_rsa2048();

    S3_ASSERT(ed != NULL && foreign != NULL && ec != NULL && rsa != NULL);

    if (ed == NULL || foreign == NULL || ec == NULL || rsa == NULL) {
        return s3_test_failures;
    }

    (void)s3_tj_b64std(s3_tj_conv, sizeof(s3_tj_conv), jti, 1);

    /* the keys files: the plain ed25519, the ecdsa, the rsa and the
     * decorated multi-line one */

    blob_len = s3_tj_blob_ed25519(ed, (u_char *)blob);
    (void)s3_tj_b64std((const u_char *)blob, blob_len, blob_b64, 0);
    snprintf(content, sizeof(content), "ssh-ed25519 %s s3-tj-key-a\n", blob_b64);
    s3_tj_keysfile(path_a, content);

    blob_len = s3_tj_blob_ec256(ec, (u_char *)blob);
    (void)s3_tj_b64std((const u_char *)blob, blob_len, blob_b64, 0);
    snprintf(content, sizeof(content), "ecdsa-sha2-nistp256 %s s3-tj-key-ec\n", blob_b64);
    s3_tj_keysfile(path_ec, content);

    blob_len = s3_tj_blob_rsa(rsa, (u_char *)blob);
    (void)s3_tj_b64std((const u_char *)blob, blob_len, blob_b64, 0);
    snprintf(content, sizeof(content), "ssh-rsa %s s3-tj-key-rsa\n", blob_b64);
    s3_tj_keysfile(path_rsa, content);

    blob_len = s3_tj_blob_ed25519(ed, (u_char *)blob);
    (void)s3_tj_b64std((const u_char *)blob, blob_len, blob_b64, 0);
    snprintf(content, sizeof(content),
             "# the comment line\n"
             "\n"
             "no-pty ssh-ed25519 %s decorated\n"
             "cert-authority ssh-ed25519 foreign-blob-not-base64-safe\n",
             blob_b64);
    s3_tj_keysfile(path_multi, content);

    /* the identities shape of the fork (the authorized_identities
     * file): the directive lines are not keys, the walk skips them
     * and the key behind them still decides (the reference logs and
     * continues over an unparsable identity line) */

    snprintf(content, sizeof(content),
             "# the identities fixture\n"
             "\n"
             "plugin:some-plugin some-option\n"
             "oidc https://issuer.example client_id user@example.org\n"
             "\n"
             "no-pty ssh-ed25519 %s identities\n",
             blob_b64);
    s3_tj_keysfile(path_idents, content);

    /* the raw-key line shape of the P7.3 incident: the base64 of the
     * bare 32-byte key (no ssh wire framing) parses as base64 but the
     * blob walker reads no keytype string out of it, the line skips
     * and the verdict stays closed - the reference
     * ParseAuthorizedIdentitiesFile ignores the unparsable identity
     * the same way, a raw-key publisher gets the 401, not a session */

    char foreign_b64[800], raw_b64[128];

    blob_len = s3_tj_blob_ed25519(foreign, (u_char *)blob);
    (void)s3_tj_b64std((const u_char *)blob, blob_len, foreign_b64, 0);

    {
        u_char raw[64];
        size_t n = sizeof(raw);

        S3_ASSERT(EVP_PKEY_get_raw_public_key(ed, raw, &n) == 1);
        S3_ASSERT(n == 32);
        (void)s3_tj_b64std(raw, n, raw_b64, 0);
    }

    snprintf(content, sizeof(content), "ssh-ed25519 %s raw-key-no-wire\n", raw_b64);
    s3_tj_keysfile(path_raw, content);

    /* the stale file of the same incident: the foreign keys of the
     * earlier runs and the raw-key line sit ahead of the fresh key -
     * the walk rides over the mismatches and the unparsable line and
     * the fresh key still decides (the files merge, one dead line
     * never hides the next one) */

    snprintf(content, sizeof(content),
             "ssh-ed25519 %s stale-from-earlier-run\n"
             "ssh-ed25519 %s raw-key-no-wire\n"
             "ssh-ed25519 %s s3-tj-fresh\n",
             foreign_b64, raw_b64, blob_b64);
    s3_tj_keysfile(path_stale, content);

    /* the happy paths, one per allowlisted algorithm */

    /* the fresh clock: the whole suite runs over 10s under
     * valgrind, a now captured up front expires the tokens */
    now = (long long)time(NULL);
    s3_tj_claims(claims, sizeof(claims), "bob", "ssh3", "\"unused\"", "ssh3-bob", jti, now,
                 now + 10, 0);
    s3_tj_token(token, sizeof(token), "EdDSA", claims, ed, 0);
    s3_tj_case("ed25519 happy", token, "bob", path_a, s3_tj_conv, sizeof(s3_tj_conv), S3_OK);

    s3_tj_token(token, sizeof(token), "ES256", claims, ec, 0);
    s3_tj_case("es256 happy", token, "bob", path_ec, s3_tj_conv, sizeof(s3_tj_conv), S3_OK);

    s3_tj_token(token, sizeof(token), "RS256", claims, rsa, 0);
    s3_tj_case("rs256 happy", token, "bob", path_rsa, s3_tj_conv, sizeof(s3_tj_conv), S3_OK);

    /* the decorated file: comments, empty lines, the options prefix
     * and the trailing malformed line behind the good key */

    s3_tj_token(token, sizeof(token), "EdDSA", claims, ed, 0);
    s3_tj_case("decorated keys file", token, "bob", path_multi, s3_tj_conv, sizeof(s3_tj_conv),
               S3_OK);

    /* the identities directives before the key: the walk skips them */

    s3_tj_case("identities directives skip", token, "bob", path_idents, s3_tj_conv,
               sizeof(s3_tj_conv), S3_OK);

    /* the raw-key line of the P7.3 incident: unparsable blob, the
     * verdict stays closed */

    s3_tj_case("raw key blob line", token, "bob", path_raw, s3_tj_conv, sizeof(s3_tj_conv),
               S3_DECLINED);

    /* the stale keys and the raw-key line ahead of the fresh key: the
     * walk rides over them and the fresh key decides */

    s3_tj_case("stale keys then fresh", token, "bob", path_stale, s3_tj_conv, sizeof(s3_tj_conv),
               S3_OK);

    /* the aud array form carries the audience in a member */

    /* the fresh clock: the whole suite runs over 10s under
     * valgrind, a now captured up front expires the tokens */
    now = (long long)time(NULL);
    s3_tj_claims(claims, sizeof(claims), "bob", "ssh3", "[\"wrong\",\"unused\"]", "ssh3-bob", jti,
                 now, now + 10, 0);
    s3_tj_token(token, sizeof(token), "EdDSA", claims, ed, 0);
    s3_tj_case("aud array", token, "bob", path_a, s3_tj_conv, sizeof(s3_tj_conv), S3_OK);

    /* the tampered tokens: the payload byte and the signature byte */

    /* the fresh clock: the whole suite runs over 10s under
     * valgrind, a now captured up front expires the tokens */
    now = (long long)time(NULL);
    s3_tj_claims(claims, sizeof(claims), "bob", "ssh3", "\"unused\"", "ssh3-bob", jti, now,
                 now + 10, 0);
    s3_tj_token(token, sizeof(token), "EdDSA", claims, ed, 0);
    s3_tj_flip(token, 0);
    s3_tj_case("tampered payload", token, "bob", path_a, s3_tj_conv, sizeof(s3_tj_conv),
               S3_DECLINED);

    s3_tj_token(token, sizeof(token), "EdDSA", claims, ed, 0);
    s3_tj_flip(token, 1);
    s3_tj_case("tampered signature", token, "bob", path_a, s3_tj_conv, sizeof(s3_tj_conv),
               S3_DECLINED);

    /* the claim verdicts */

    /* the fresh clock: the whole suite runs over 10s under
     * valgrind, a now captured up front expires the tokens */
    now = (long long)time(NULL);
    s3_tj_claims(claims, sizeof(claims), "bob", "ssh3", "\"unused\"", "ssh3-bob", jti, now,
                 now - 10, 0);
    s3_tj_token(token, sizeof(token), "EdDSA", claims, ed, 0);
    s3_tj_case("expired", token, "bob", path_a, s3_tj_conv, sizeof(s3_tj_conv), S3_DECLINED);

    /* the fresh clock: the whole suite runs over 10s under
     * valgrind, a now captured up front expires the tokens */
    now = (long long)time(NULL);
    s3_tj_claims(claims, sizeof(claims), "bob", "ssh3", "\"unused\"", "ssh3-bob", jti, now, 0, 0);
    s3_tj_token(token, sizeof(token), "EdDSA", claims, ed, 0);
    s3_tj_case("exp missing", token, "bob", path_a, s3_tj_conv, sizeof(s3_tj_conv), S3_DECLINED);

    /* the fresh clock: the whole suite runs over 10s under
     * valgrind, a now captured up front expires the tokens */
    now = (long long)time(NULL);
    s3_tj_claims(claims, sizeof(claims), "bob", "ssh3", "\"unused\"", "ssh3-bob", jti, now,
                 now + 10, now + 3600);
    s3_tj_token(token, sizeof(token), "EdDSA", claims, ed, 0);
    s3_tj_case("nbf future", token, "bob", path_a, s3_tj_conv, sizeof(s3_tj_conv), S3_DECLINED);

    /* the fresh clock: the whole suite runs over 10s under
     * valgrind, a now captured up front expires the tokens */
    now = (long long)time(NULL);
    s3_tj_claims(claims, sizeof(claims), "bob", "ssh3", "\"unused\"", "ssh3-bob", jti, now + 3600,
                 now + 10, 0);
    s3_tj_token(token, sizeof(token), "EdDSA", claims, ed, 0);
    s3_tj_case("iat future", token, "bob", path_a, s3_tj_conv, sizeof(s3_tj_conv), S3_DECLINED);

    /* the fresh clock: the whole suite runs over 10s under
     * valgrind, a now captured up front expires the tokens */
    now = (long long)time(NULL);
    s3_tj_claims(claims, sizeof(claims), "bob", "wrong", "\"unused\"", "ssh3-bob", jti, now,
                 now + 10, 0);
    s3_tj_token(token, sizeof(token), "EdDSA", claims, ed, 0);
    s3_tj_case("wrong sub", token, "bob", path_a, s3_tj_conv, sizeof(s3_tj_conv), S3_DECLINED);

    /* the fresh clock: the whole suite runs over 10s under
     * valgrind, a now captured up front expires the tokens */
    now = (long long)time(NULL);
    s3_tj_claims(claims, sizeof(claims), "bob", "ssh3", "\"wrong\"", "ssh3-bob", jti, now, now + 10,
                 0);
    s3_tj_token(token, sizeof(token), "EdDSA", claims, ed, 0);
    s3_tj_case("wrong aud", token, "bob", path_a, s3_tj_conv, sizeof(s3_tj_conv), S3_DECLINED);

    /* the fresh clock: the whole suite runs over 10s under
     * valgrind, a now captured up front expires the tokens */
    now = (long long)time(NULL);
    s3_tj_claims(claims, sizeof(claims), "bob", "ssh3", NULL, "ssh3-bob", jti, now, now + 10, 0);
    s3_tj_token(token, sizeof(token), "EdDSA", claims, ed, 0);
    s3_tj_case("aud missing", token, "bob", path_a, s3_tj_conv, sizeof(s3_tj_conv), S3_DECLINED);

    /* the fresh clock: the whole suite runs over 10s under
     * valgrind, a now captured up front expires the tokens */
    now = (long long)time(NULL);
    s3_tj_claims(claims, sizeof(claims), "alice", "ssh3", "\"unused\"", "ssh3-alice", jti, now,
                 now + 10, 0);
    s3_tj_token(token, sizeof(token), "EdDSA", claims, ed, 0);
    s3_tj_case("wrong user", token, "bob", path_a, s3_tj_conv, sizeof(s3_tj_conv), S3_DECLINED);

    /* the fresh clock: the whole suite runs over 10s under
     * valgrind, a now captured up front expires the tokens */
    now = (long long)time(NULL);
    s3_tj_claims(claims, sizeof(claims), "bob", "ssh3", "\"unused\"", "ssh3-alice", jti, now,
                 now + 10, 0);
    s3_tj_token(token, sizeof(token), "EdDSA", claims, ed, 0);
    s3_tj_case("wrong client_id", token, "bob", path_a, s3_tj_conv, sizeof(s3_tj_conv),
               S3_DECLINED);

    /* the fresh clock: the whole suite runs over 10s under
     * valgrind, a now captured up front expires the tokens */
    now = (long long)time(NULL);
    s3_tj_claims(claims, sizeof(claims), "bob", "ssh3", "\"unused\"", "ssh3-bob", "wrong-jti", now,
                 now + 10, 0);
    s3_tj_token(token, sizeof(token), "EdDSA", claims, ed, 0);
    s3_tj_case("wrong jti", token, "bob", path_a, s3_tj_conv, sizeof(s3_tj_conv), S3_DECLINED);

    /* the jti binding is skipped without the conversation id but the
     * claim itself stays required, like the reference checks */

    /* the fresh clock: the whole suite runs over 10s under
     * valgrind, a now captured up front expires the tokens */
    now = (long long)time(NULL);
    s3_tj_claims(claims, sizeof(claims), "bob", "ssh3", "\"unused\"", "ssh3-bob", jti, now,
                 now + 10, 0);
    s3_tj_token(token, sizeof(token), "EdDSA", claims, ed, 0);
    s3_tj_case("convid absent", token, "bob", path_a, NULL, 0, S3_OK);

    /* the fresh clock: the whole suite runs over 10s under
     * valgrind, a now captured up front expires the tokens */
    now = (long long)time(NULL);
    s3_tj_claims(claims, sizeof(claims), "bob", "ssh3", "\"unused\"", "ssh3-bob", "", now, now + 10,
                 0);
    s3_tj_token(token, sizeof(token), "EdDSA", claims, ed, 0);
    s3_tj_case("jti missing", token, "bob", path_a, NULL, 0, S3_DECLINED);

    /* the foreign key and the algorithm/key mismatch */

    /* the fresh clock: the whole suite runs over 10s under
     * valgrind, a now captured up front expires the tokens */
    now = (long long)time(NULL);
    s3_tj_claims(claims, sizeof(claims), "bob", "ssh3", "\"unused\"", "ssh3-bob", jti, now,
                 now + 10, 0);
    s3_tj_token(token, sizeof(token), "EdDSA", claims, foreign, 0);
    s3_tj_case("foreign key", token, "bob", path_a, s3_tj_conv, sizeof(s3_tj_conv), S3_DECLINED);

    s3_tj_token(token, sizeof(token), "ES256", claims, ec, 0);
    s3_tj_case("alg-key mismatch", token, "bob", path_a, s3_tj_conv, sizeof(s3_tj_conv),
               S3_DECLINED);

    /* the rejected headers: none, the unknown scheme, the shape */

    /* the fresh clock: the whole suite runs over 10s under
     * valgrind, a now captured up front expires the tokens */
    now = (long long)time(NULL);
    s3_tj_claims(claims, sizeof(claims), "bob", "ssh3", "\"unused\"", "ssh3-bob", jti, now,
                 now + 10, 0);
    s3_tj_token(token, sizeof(token), "none", claims, ed, 1);
    s3_tj_case("alg none", token, "bob", path_a, s3_tj_conv, sizeof(s3_tj_conv), S3_DECLINED);

    s3_tj_token(token, sizeof(token), "HS256", claims, ed, 0);
    s3_tj_case("unknown alg", token, "bob", path_a, s3_tj_conv, sizeof(s3_tj_conv), S3_DECLINED);

    s3_tj_case("not bearer", "dGVzdA==", "bob", path_a, s3_tj_conv, sizeof(s3_tj_conv),
               S3_DECLINED);

    s3_tj_case("two segments", "aaaa.bbbb", "bob", path_a, s3_tj_conv, sizeof(s3_tj_conv),
               S3_DECLINED);

    s3_tj_case("empty user", "aaaa.bbbb.cccc", "", path_a, s3_tj_conv, sizeof(s3_tj_conv),
               S3_DECLINED);

    /* the unreadable keys file is S3_ERROR, not a rejection */

    /* the fresh clock: the whole suite runs over 10s under
     * valgrind, a now captured up front expires the tokens */
    now = (long long)time(NULL);
    s3_tj_claims(claims, sizeof(claims), "bob", "ssh3", "\"unused\"", "ssh3-bob", jti, now,
                 now + 10, 0);
    s3_tj_token(token, sizeof(token), "EdDSA", claims, ed, 0);
    s3_tj_case("missing keys file", token, "bob", "/tmp/s3jwt-missing-file", s3_tj_conv,
               sizeof(s3_tj_conv), S3_ERROR);

    /* the fixtures leave no trace (ASan clean) */

    S3_ASSERT(unlink(path_a) == 0);
    S3_ASSERT(unlink(path_ec) == 0);
    S3_ASSERT(unlink(path_rsa) == 0);
    S3_ASSERT(unlink(path_multi) == 0);
    S3_ASSERT(unlink(path_idents) == 0);
    S3_ASSERT(unlink(path_raw) == 0);
    S3_ASSERT(unlink(path_stale) == 0);

    EVP_PKEY_free(ed);
    EVP_PKEY_free(foreign);
    EVP_PKEY_free(ec);
    EVP_PKEY_free(rsa);

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_ssh3_auth_jwt)
