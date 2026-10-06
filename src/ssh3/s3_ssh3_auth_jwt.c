/*",
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the Bearer JWT pubkey verifier of the reference
 * auth/plugins/pubkey_authentication/server (docs/P4-WIRE.md 7): the
 * compact token decodes into the header, the claims and the
 * signature, the signature verifies against the authorized_keys
 * blobs converted into the OpenSSL keys and the claim set answers the
 * reference BuildJWTBearerToken()/Verify() pair.  The verdict runs
 * once per CONNECT, the OpenSSL objects live for the call - the
 * per-message hot path never lands here
 */

#include <s3_core.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/param_build.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>

#include <stdio.h>
#include <string.h>
#include <time.h>

#include <s3_ssh3_auth_jwt.h>
#include <s3_ssh3_auth_srv.h>

/* the segment and fixture caps, a bigger token is garbage */

#define S3_SSH3_JWT_HDR_MAX     512
#define S3_SSH3_JWT_PAYLOAD_MAX 4096
#define S3_SSH3_JWT_SIG_MAX     1024
#define S3_SSH3_JWT_FILE_MAX    (1024 * 1024)

/* the plain session username cap of the harness path */

#define S3_SSH3_JWT_USER_MAX 128

/* the ES256 signature is the raw r||s pair, 32 bytes each */

#define S3_SSH3_JWT_ES256_HALF 32

typedef struct {
    s3_str_t  iss, sub, client_id, jti;
    s3_str_t  aud;       /* the string form or the matching array member */
    unsigned  aud_array; /* the aud claim arrived as an array */
    unsigned  jti_present;
    unsigned  bad; /* a required claim ended in the wrong type */
    long long exp, iat, nbf;
    unsigned  exp_present, iat_present, nbf_present;
} s3_ssh3_jwt_claims_t;

static s3_int_t s3_ssh3_jwt_b64_decode(u_char *data, size_t len, size_t *dlen, unsigned url);
static size_t   s3_ssh3_jwt_b64_std_encode(const u_char *in, size_t len, u_char *out);
static s3_int_t s3_ssh3_json_ws(u_char **pos, u_char *end);
static s3_int_t s3_ssh3_json_string(u_char **pos, u_char *end, s3_str_t *out);
static s3_int_t s3_ssh3_json_number(u_char **pos, u_char *end, long long *out);
static s3_int_t s3_ssh3_json_skip(u_char **pos, u_char *end, unsigned depth);
static s3_int_t s3_ssh3_jwt_scan(u_char *pos, u_char *end, s3_str_t *alg, s3_ssh3_jwt_claims_t *cl);
static s3_int_t s3_ssh3_jwt_wire_string(const u_char **pos, const u_char *end, s3_str_t *out);
static EVP_PKEY *s3_ssh3_jwt_key_ed25519(const u_char **pos, const u_char *end);
static EVP_PKEY *s3_ssh3_jwt_key_ec256(const u_char **pos, const u_char *end);
static EVP_PKEY *s3_ssh3_jwt_key_rsa(const u_char **pos, const u_char *end);
static EVP_PKEY *s3_ssh3_jwt_blob_key(const u_char *blob, size_t len);
static s3_int_t  s3_ssh3_jwt_sig_verify(const s3_str_t *alg, EVP_PKEY *key, const u_char *msg,
                                        size_t msglen, const u_char *sig, size_t siglen);
static s3_int_t  s3_ssh3_jwt_keys_file(const char *path, const s3_str_t *alg, const u_char *msg,
                                       size_t msglen, const u_char *sig, size_t siglen);

/*
 * the base64 of the token segments and the authorized_keys blobs: the
 * url form is the raw unpadded JWT shape (the padding and the
 * standard alphabet are garbage), the standard form takes the
 * optional trailing padding like the Go StdEncoding decoder of the
 * reference does; the result lands in place, the output never
 * overruns the input position
 */

static s3_int_t
s3_ssh3_jwt_sextet(u_char c, unsigned url, s3_uint_t *value)
{
    if (c >= 'A' && c <= 'Z') {
        *value = (s3_uint_t)(c - 'A');
        return S3_OK;
    }

    if (c >= 'a' && c <= 'z') {
        *value = (s3_uint_t)(c - 'a') + 26;
        return S3_OK;
    }

    if (c >= '0' && c <= '9') {
        *value = (s3_uint_t)(c - '0') + 52;
        return S3_OK;
    }

    if (url) {

        if (c == '-') {
            *value = 62;
            return S3_OK;
        }

        if (c == '_') {
            *value = 63;
            return S3_OK;
        }

        return S3_ERROR;
    }

    if (c == '+') {
        *value = 62;
        return S3_OK;
    }

    if (c == '/') {
        *value = 63;
        return S3_OK;
    }

    return S3_ERROR;
}

static s3_int_t
s3_ssh3_jwt_b64_decode(u_char *data, size_t len, size_t *dlen, unsigned url)
{
    s3_uint_t v[4];
    size_t    body, tail, n, i, out, pad;
    u_char    c;

    /* the quantum shape: the lone sextet is garbage in both forms */

    if (len == 0 || len % 4 == 1) {
        return S3_ERROR;
    }

    body = len - len % 4;
    tail = len % 4;

    out = 0;

    for (n = 0; n < body; n += 4) {

        pad = 0;

        for (i = 0; i < 4; i++) {

            c = data[n + i];

            if (c == '=') {

                /* the padding lives at the tail of the final quantum,
                 * the url form takes none */

                if (url || n + 4 != len || i < 2) {
                    return S3_ERROR;
                }

                pad++;
                v[i] = 0;
                continue;
            }

            if (pad > 0) {
                /* the data behind the padding */
                return S3_ERROR;
            }

            if (s3_ssh3_jwt_sextet(c, url, &v[i]) != S3_OK) {
                return S3_ERROR;
            }
        }

        data[out++] = (u_char)((v[0] << 2) | (v[1] >> 4));

        if (pad < 2) {
            data[out++] = (u_char)(((v[1] & 0xf) << 4) | (v[2] >> 2));
        }

        if (pad < 1) {
            data[out++] = (u_char)(((v[2] & 0x3) << 6) | v[3]);
        }
    }

    if (tail > 0) {

        /* the ragged tail of the raw form, two or three sextets */

        v[2] = 0;
        v[3] = 0;

        for (i = 0; i < tail; i++) {

            if (s3_ssh3_jwt_sextet(data[body + i], url, &v[i]) != S3_OK) {
                return S3_ERROR;
            }
        }

        data[out++] = (u_char)((v[0] << 2) | (v[1] >> 4));

        if (tail == 3) {
            data[out++] = (u_char)(((v[1] & 0xf) << 4) | (v[2] >> 2));
        }
    }

    *dlen = out;

    return S3_OK;
}

/* the padded standard base64 of the jti claim, the reference
 * base64.StdEncoding.EncodeToString() shape */

static size_t
s3_ssh3_jwt_b64_std_encode(const u_char *in, size_t len, u_char *out)
{
    static const u_char alpha[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                  "abcdefghijklmnopqrstuvwxyz0123456789+/";

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
        out[o++] = '=';
        out[o++] = '=';

    } else if (len - i == 2) {

        unsigned v = ((unsigned)in[i] << 16) | ((unsigned)in[i + 1] << 8);

        out[o++] = alpha[(v >> 18) & 63];
        out[o++] = alpha[(v >> 12) & 63];
        out[o++] = alpha[(v >> 6) & 63];
        out[o++] = '=';
    }

    return o;
}

/*
 * the minimal JSON scanner of the token header and the claims object:
 * the keys this module speaks extract, the other values skip past
 * (the depth cap keeps a crafted nesting bounded); the string views
 * stay raw - an escape sequence rides the scan and the view compares
 * fail-closed against the plain claim values
 */

static s3_int_t
s3_ssh3_json_ws(u_char **pos, u_char *end)
{
    u_char *p = *pos;

    while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) {
        p++;
    }

    *pos = p;

    return S3_OK;
}

static s3_int_t
s3_ssh3_json_string(u_char **pos, u_char *end, s3_str_t *out)
{
    u_char *p = *pos, *start;

    if (p >= end || *p != '"') {
        return S3_ERROR;
    }

    p++;
    start = p;

    while (p < end) {

        if (*p == '\\') {

            /* the escape rides the scan, the raw view stays */

            if (p + 1 >= end) {
                return S3_ERROR;
            }

            p += 2;
            continue;
        }

        if (*p == '"') {

            out->data = start;
            out->len = (size_t)(p - start);

            *pos = p + 1;

            return S3_OK;
        }

        p++;
    }

    return S3_ERROR;
}

static s3_int_t
s3_ssh3_json_number(u_char **pos, u_char *end, long long *out)
{
    u_char   *p = *pos;
    long long v = 0;
    unsigned  neg = 0;

    if (p < end && *p == '-') {
        neg = 1;
        p++;
    }

    if (p >= end || *p < '0' || *p > '9') {
        return S3_ERROR;
    }

    while (p < end && *p >= '0' && *p <= '9') {

        v = v * 10 + (*p - '0');
        p++;
    }

    /* the fraction floor of the NumericDate never moves the verdict,
     * the exponent suffix rides past - a scaled value parses short
     * and fails closed on every time check */

    if (p < end && *p == '.') {

        p++;

        if (p >= end || *p < '0' || *p > '9') {
            return S3_ERROR;
        }

        while (p < end && *p >= '0' && *p <= '9') {
            p++;
        }
    }

    if (p < end && (*p == 'e' || *p == 'E')) {

        p++;

        if (p < end && (*p == '+' || *p == '-')) {
            p++;
        }

        if (p >= end || *p < '0' || *p > '9') {
            return S3_ERROR;
        }

        while (p < end && *p >= '0' && *p <= '9') {
            p++;
        }
    }

    *out = neg ? -v : v;

    *pos = p;

    return S3_OK;
}

static s3_int_t
s3_ssh3_json_skip(u_char **pos, u_char *end, unsigned depth)
{
    s3_str_t  sink_str;
    long long sink_num;
    u_char   *p = *pos;

    if (depth == 0) {
        return S3_ERROR;
    }

    if (p < end && *p == '"') {
        return s3_ssh3_json_string(pos, end, &sink_str);
    }

    if (p < end && *p == '{') {

        p++;

        if (s3_ssh3_json_ws(&p, end) != S3_OK) {
            return S3_ERROR;
        }

        if (p < end && *p == '}') {
            *pos = p + 1;
            return S3_OK;
        }

        for (;;) {

            if (s3_ssh3_json_string(&p, end, &sink_str) != S3_OK) {
                return S3_ERROR;
            }

            if (s3_ssh3_json_ws(&p, end) != S3_OK || p >= end || *p != ':') {
                return S3_ERROR;
            }

            p++;

            if (s3_ssh3_json_ws(&p, end) != S3_OK ||
                s3_ssh3_json_skip(&p, end, depth - 1) != S3_OK) {
                return S3_ERROR;
            }

            if (s3_ssh3_json_ws(&p, end) != S3_OK || p >= end) {
                return S3_ERROR;
            }

            if (*p == '}') {
                *pos = p + 1;
                return S3_OK;
            }

            if (*p != ',') {
                return S3_ERROR;
            }

            p++;
        }
    }

    if (p < end && *p == '[') {

        p++;

        if (s3_ssh3_json_ws(&p, end) != S3_OK) {
            return S3_ERROR;
        }

        if (p < end && *p == ']') {
            *pos = p + 1;
            return S3_OK;
        }

        for (;;) {

            if (s3_ssh3_json_ws(&p, end) != S3_OK ||
                s3_ssh3_json_skip(&p, end, depth - 1) != S3_OK) {
                return S3_ERROR;
            }

            if (s3_ssh3_json_ws(&p, end) != S3_OK || p >= end) {
                return S3_ERROR;
            }

            if (*p == ']') {
                *pos = p + 1;
                return S3_OK;
            }

            if (*p != ',') {
                return S3_ERROR;
            }

            p++;
        }
    }

    if (end - p >= 5 && s3_memcmp(p, "false", 5) == 0) {
        *pos = p + 5;
        return S3_OK;
    }

    if (end - p >= 4 && (s3_memcmp(p, "true", 4) == 0 || s3_memcmp(p, "null", 4) == 0)) {
        *pos = p + 4;
        return S3_OK;
    }

    return s3_ssh3_json_number(pos, end, &sink_num);
}

/*
 * the object scan: the alg of the header and the claims of the
 * payload extract in one pass, the last occurrence of a key decides
 * like the reference map claims do; a required claim that ends in the
 * wrong type marks the whole token bad
 */

static s3_int_t
s3_ssh3_jwt_scan(u_char *pos, u_char *end, s3_str_t *alg, s3_ssh3_jwt_claims_t *cl)
{
    static s3_str_t k_iss = s3_string("iss");
    static s3_str_t k_sub = s3_string("sub");
    static s3_str_t k_aud = s3_string("aud");
    static s3_str_t k_exp = s3_string("exp");
    static s3_str_t k_iat = s3_string("iat");
    static s3_str_t k_nbf = s3_string("nbf");
    static s3_str_t k_alg = s3_string("alg");
    static s3_str_t k_cid = s3_string("client_id");
    static s3_str_t k_jti = s3_string("jti");
    static s3_str_t v_unused = s3_string("unused");

    s3_str_t key;
    u_char  *p = pos;

    if (s3_ssh3_json_ws(&p, end) != S3_OK || p >= end || *p != '{') {
        return S3_ERROR;
    }

    p++;

    for (;;) {

        if (s3_ssh3_json_ws(&p, end) != S3_OK) {
            return S3_ERROR;
        }

        if (p >= end) {
            return S3_ERROR;
        }

        if (*p == '}') {
            return S3_OK;
        }

        if (s3_ssh3_json_string(&p, end, &key) != S3_OK) {
            return S3_ERROR;
        }

        if (s3_ssh3_json_ws(&p, end) != S3_OK || p >= end || *p != ':') {
            return S3_ERROR;
        }

        p++;

        if (s3_ssh3_json_ws(&p, end) != S3_OK) {
            return S3_ERROR;
        }

        if (key.len == k_alg.len && s3_memcmp(key.data, k_alg.data, key.len) == 0) {

            /* the wrong type leaves the alg unset, the allowlist
             * rejects the token */

            alg->len = 0;

            if (s3_ssh3_json_string(&p, end, alg) != S3_OK &&
                s3_ssh3_json_skip(&p, end, 8) != S3_OK) {
                return S3_ERROR;
            }

        } else if (key.len == k_iss.len && s3_memcmp(key.data, k_iss.data, key.len) == 0) {

            cl->iss.len = 0;

            if (s3_ssh3_json_string(&p, end, &cl->iss) != S3_OK) {

                cl->bad = 1;

                if (s3_ssh3_json_skip(&p, end, 8) != S3_OK) {
                    return S3_ERROR;
                }
            }

        } else if (key.len == k_sub.len && s3_memcmp(key.data, k_sub.data, key.len) == 0) {

            cl->sub.len = 0;

            if (s3_ssh3_json_string(&p, end, &cl->sub) != S3_OK) {

                cl->bad = 1;

                if (s3_ssh3_json_skip(&p, end, 8) != S3_OK) {
                    return S3_ERROR;
                }
            }

        } else if (key.len == k_cid.len && s3_memcmp(key.data, k_cid.data, key.len) == 0) {

            cl->client_id.len = 0;

            if (s3_ssh3_json_string(&p, end, &cl->client_id) != S3_OK) {

                cl->bad = 1;

                if (s3_ssh3_json_skip(&p, end, 8) != S3_OK) {
                    return S3_ERROR;
                }
            }

        } else if (key.len == k_jti.len && s3_memcmp(key.data, k_jti.data, key.len) == 0) {

            cl->jti.len = 0;
            cl->jti_present = 0;

            if (s3_ssh3_json_string(&p, end, &cl->jti) == S3_OK) {
                cl->jti_present = 1;

            } else {

                cl->bad = 1;

                if (s3_ssh3_json_skip(&p, end, 8) != S3_OK) {
                    return S3_ERROR;
                }
            }

        } else if (key.len == k_aud.len && s3_memcmp(key.data, k_aud.data, key.len) == 0) {

            cl->aud.len = 0;
            cl->aud_array = 0;

            if (p < end && *p == '[') {

                /* the array form: one member must carry the audience,
                 * the matching member lands in the aud view */

                u_char  *q = p + 1;
                unsigned match = 0;

                cl->aud_array = 1;

                for (;;) {

                    if (s3_ssh3_json_ws(&q, end) != S3_OK) {
                        return S3_ERROR;
                    }

                    if (q >= end) {
                        return S3_ERROR;
                    }

                    if (*q == ']') {
                        p = q + 1;
                        break;
                    }

                    if (match == 0 && s3_ssh3_json_string(&q, end, &cl->aud) == S3_OK) {

                        if (cl->aud.len != v_unused.len ||
                            s3_memcmp(cl->aud.data, v_unused.data, cl->aud.len) != 0) {
                            cl->aud.len = 0;

                        } else {
                            match = 1;
                        }

                    } else {

                        if (s3_ssh3_json_skip(&q, end, 8) != S3_OK) {
                            return S3_ERROR;
                        }

                        if (match == 0) {
                            cl->aud.len = 0;
                        }
                    }

                    if (s3_ssh3_json_ws(&q, end) != S3_OK) {
                        return S3_ERROR;
                    }

                    if (q >= end) {
                        return S3_ERROR;
                    }

                    if (*q == ',') {
                        q++;
                        continue;
                    }

                    if (*q != ']') {
                        return S3_ERROR;
                    }

                    p = q + 1;
                    break;
                }

            } else if (s3_ssh3_json_string(&p, end, &cl->aud) != S3_OK) {

                cl->bad = 1;

                if (s3_ssh3_json_skip(&p, end, 8) != S3_OK) {
                    return S3_ERROR;
                }
            }

        } else if ((key.len == k_exp.len && s3_memcmp(key.data, k_exp.data, key.len) == 0) ||
                   (key.len == k_iat.len && s3_memcmp(key.data, k_iat.data, key.len) == 0) ||
                   (key.len == k_nbf.len && s3_memcmp(key.data, k_nbf.data, key.len) == 0)) {

            unsigned is_exp = (s3_memcmp(key.data, k_exp.data, key.len) == 0);
            unsigned is_iat = (s3_memcmp(key.data, k_iat.data, key.len) == 0);

            long long v = 0;
            s3_int_t  rc;

            if (is_exp) {
                cl->exp_present = 0;

            } else if (is_iat) {
                cl->iat_present = 0;

            } else {
                cl->nbf_present = 0;
            }

            rc = s3_ssh3_json_number(&p, end, &v);

            if (rc != S3_OK) {

                cl->bad = 1;

                if (s3_ssh3_json_skip(&p, end, 8) != S3_OK) {
                    return S3_ERROR;
                }

            } else if (is_exp) {
                cl->exp = v;
                cl->exp_present = 1;

            } else if (is_iat) {
                cl->iat = v;
                cl->iat_present = 1;

            } else {
                cl->nbf = v;
                cl->nbf_present = 1;
            }

        } else {

            if (s3_ssh3_json_skip(&p, end, 8) != S3_OK) {
                return S3_ERROR;
            }
        }

        if (s3_ssh3_json_ws(&p, end) != S3_OK) {
            return S3_ERROR;
        }

        if (p >= end) {
            return S3_ERROR;
        }

        if (*p == ',') {
            p++;
            continue;
        }

        if (*p == '}') {
            return S3_OK;
        }

        return S3_ERROR;
    }
}

/* the SSH wire string of the key blob, the strict length bounds */

static s3_int_t
s3_ssh3_jwt_wire_string(const u_char **pos, const u_char *end, s3_str_t *out)
{
    const u_char *p = *pos;
    uint32_t      len;

    if ((size_t)(end - p) < 4) {
        return S3_ERROR;
    }

    len = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];

    p += 4;

    if ((size_t)(end - p) < len) {
        return S3_ERROR;
    }

    out->data = (u_char *)p;
    out->len = len;

    *pos = p + len;

    return S3_OK;
}

/* the ssh-ed25519 blob: string keytype + string raw key (32 bytes) */

static EVP_PKEY *
s3_ssh3_jwt_key_ed25519(const u_char **pos, const u_char *end)
{
    s3_str_t raw;

    if (s3_ssh3_jwt_wire_string(pos, end, &raw) != S3_OK || raw.len != 32) {
        return NULL;
    }

    return EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, raw.data, raw.len);
}

/* the ecdsa-sha2-nistp256 blob: string keytype + string "nistp256" +
 * string uncompressed point, into the provider key */

static EVP_PKEY *
s3_ssh3_jwt_key_ec256(const u_char **pos, const u_char *end)
{
    static s3_str_t curve = s3_string("nistp256");

    OSSL_PARAM    params[3];
    EVP_PKEY_CTX *ctx;
    EVP_PKEY     *key = NULL;
    s3_str_t      name, q;

    if (s3_ssh3_jwt_wire_string(pos, end, &name) != S3_OK || name.len != curve.len ||
        s3_memcmp(name.data, curve.data, curve.len) != 0) {
        return NULL;
    }

    if (s3_ssh3_jwt_wire_string(pos, end, &q) != S3_OK || q.len == 0 || q.data[0] != 0x04) {
        return NULL;
    }

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);

    if (ctx == NULL) {
        return NULL;
    }

    params[0] =
        OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *)"prime256v1", 0);
    /* the EC "pub" param carries the uncompressed point octets */

    params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void *)q.data, q.len);
    params[2] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_fromdata_init(ctx) != 1 ||
        EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_PUBLIC_KEY, params) != 1) {
        key = NULL;
    }

    EVP_PKEY_CTX_free(ctx);

    return key;
}

/* the ssh-rsa blob: string keytype + mpint e + mpint n, into the
 * provider key through the param builder (the plain construct_BN
 * takes the native endianness, the wire mpint is big-endian) */

static EVP_PKEY *
s3_ssh3_jwt_key_rsa(const u_char **pos, const u_char *end)
{
    OSSL_PARAM_BLD *bld;
    OSSL_PARAM     *params = NULL;
    EVP_PKEY_CTX   *ctx;
    EVP_PKEY       *key = NULL;
    BIGNUM         *e, *n;
    s3_str_t        e_str, n_str;

    if (s3_ssh3_jwt_wire_string(pos, end, &e_str) != S3_OK ||
        s3_ssh3_jwt_wire_string(pos, end, &n_str) != S3_OK) {
        return NULL;
    }

    /* the mpint sign guard byte rides out with the BIGNUM convert */

    e = BN_bin2bn(e_str.data, (int)e_str.len, NULL);
    n = BN_bin2bn(n_str.data, (int)n_str.len, NULL);

    if (e == NULL || n == NULL) {
        BN_free(e);
        BN_free(n);
        return NULL;
    }

    bld = OSSL_PARAM_BLD_new();

    if (bld != NULL) {

        if (OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e) == 1 &&
            OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n) == 1 &&
            (params = OSSL_PARAM_BLD_to_param(bld)) != NULL) {

            ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);

            if (ctx != NULL) {

                if (EVP_PKEY_fromdata_init(ctx) == 1) {
                    (void)EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_PUBLIC_KEY, params);
                }

                EVP_PKEY_CTX_free(ctx);
            }
        }

        OSSL_PARAM_BLD_free(bld);
    }

    OSSL_PARAM_free(params);

    BN_free(e);
    BN_free(n);

    return key;
}

/*
 * the authorized_keys blob of a line into the provider key: the
 * keytype string decides the shape, an unsupported line answers NULL
 * and the walker skips it (the reference plugin logs and continues)
 */

static EVP_PKEY *
s3_ssh3_jwt_blob_key(const u_char *blob, size_t len)
{
    static s3_str_t t_ed = s3_string("ssh-ed25519");
    static s3_str_t t_ec = s3_string("ecdsa-sha2-nistp256");
    static s3_str_t t_rsa = s3_string("ssh-rsa");

    const u_char *pos = blob, *end = blob + len;
    s3_str_t      keytype;

    if (s3_ssh3_jwt_wire_string(&pos, end, &keytype) != S3_OK) {
        return NULL;
    }

    if (keytype.len == t_ed.len && s3_memcmp(keytype.data, t_ed.data, t_ed.len) == 0) {
        return s3_ssh3_jwt_key_ed25519(&pos, end);
    }

    if (keytype.len == t_ec.len && s3_memcmp(keytype.data, t_ec.data, t_ec.len) == 0) {
        return s3_ssh3_jwt_key_ec256(&pos, end);
    }

    if (keytype.len == t_rsa.len && s3_memcmp(keytype.data, t_rsa.data, t_rsa.len) == 0) {
        return s3_ssh3_jwt_key_rsa(&pos, end);
    }

    return NULL;
}

/*
 * the signature of the token against the key, the algorithm decides
 * the shape: the EdDSA is the one-shot PureEdDSA verify, the ES256
 * takes the raw r||s pair into the DER ECDSA_SIG, the RS256 is the
 * PKCS#1 v1.5 SHA-256; the key type guards keep the algorithm
 * confusion away
 */

static s3_int_t
s3_ssh3_jwt_sig_verify(const s3_str_t *alg, EVP_PKEY *key, const u_char *msg, size_t msglen,
                       const u_char *sig, size_t siglen)
{
    static s3_str_t a_ed = s3_string("EdDSA");
    static s3_str_t a_es = s3_string("ES256");
    static s3_str_t a_rs = s3_string("RS256");

    EVP_MD_CTX *ctx;
    s3_int_t    rc = S3_DECLINED;
    int         m;

    ctx = EVP_MD_CTX_new();

    if (ctx == NULL) {
        return S3_ERROR;
    }

    if (alg->len == a_ed.len && s3_memcmp(alg->data, a_ed.data, a_ed.len) == 0) {

        if (EVP_PKEY_get_id(key) == EVP_PKEY_ED25519 &&
            EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) == 1) {

            m = EVP_DigestVerify(ctx, sig, siglen, msg, msglen);

            if (m == 1) {
                rc = S3_OK;

            } else if (m < 0) {
                rc = S3_ERROR;
            }
        }

    } else if (alg->len == a_es.len && s3_memcmp(alg->data, a_es.data, a_es.len) == 0) {

        if (EVP_PKEY_get_id(key) == EVP_PKEY_EC && siglen == 2 * S3_SSH3_JWT_ES256_HALF) {

            BIGNUM    *r, *s;
            ECDSA_SIG *esig;
            u_char    *der = NULL;
            int        der_len;

            r = BN_bin2bn(sig, S3_SSH3_JWT_ES256_HALF, NULL);
            s = BN_bin2bn(sig + S3_SSH3_JWT_ES256_HALF, S3_SSH3_JWT_ES256_HALF, NULL);
            esig = ECDSA_SIG_new();

            if (r == NULL || s == NULL || esig == NULL || ECDSA_SIG_set0(esig, r, s) != 1) {

                /* the failed set0 leaves the numbers with the caller */

                BN_free(r);
                BN_free(s);
                ECDSA_SIG_free(esig);
                EVP_MD_CTX_free(ctx);

                return S3_DECLINED;
            }

            /* the numbers belong to the sig now */

            der_len = i2d_ECDSA_SIG(esig, &der);

            ECDSA_SIG_free(esig);

            if (der_len > 0 && EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, key) == 1) {

                m = EVP_DigestVerify(ctx, der, (size_t)der_len, msg, msglen);

                if (m == 1) {
                    rc = S3_OK;

                } else if (m < 0) {
                    rc = S3_ERROR;
                }

                OPENSSL_free(der);
            }
        }

    } else if (alg->len == a_rs.len && s3_memcmp(alg->data, a_rs.data, a_rs.len) == 0) {

        if (EVP_PKEY_get_id(key) == EVP_PKEY_RSA &&
            EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, key) == 1) {

            m = EVP_DigestVerify(ctx, sig, siglen, msg, msglen);

            if (m == 1) {
                rc = S3_OK;

            } else if (m < 0) {
                rc = S3_ERROR;
            }
        }
    }

    EVP_MD_CTX_free(ctx);

    return rc;
}

/*
 * the authorized_keys walk: one line at a time through the iterator,
 * the blob decodes in place and the first key that verifies the
 * signature wins; a malformed line skips to the next one (the
 * reference ParseAuthorizedIdentitiesFile() logs and continues over
 * an unparsable identity - the directive lines of the fork's
 * authorized_identities file, the plugin: and oidc shapes, ride the
 * same skip), the unreadable file is S3_ERROR
 */

static s3_int_t
s3_ssh3_jwt_keys_file(const char *path, const s3_str_t *alg, const u_char *msg, size_t msglen,
                      const u_char *sig, size_t siglen)
{
    u_char  *buf;
    size_t   dlen;
    long     size;
    FILE    *f;
    s3_int_t rc, line;

    f = fopen(path, "rb");

    if (f == NULL) {
        return S3_ERROR;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return S3_ERROR;
    }

    size = ftell(f);

    if (size < 0 || size > S3_SSH3_JWT_FILE_MAX) {
        fclose(f);
        return S3_ERROR;
    }

    rewind(f);

    buf = s3_alloc((size_t)size + 1, NULL);

    if (buf == NULL) {
        fclose(f);
        return S3_ERROR;
    }

    if (size > 0 && fread(buf, 1, (size_t)size, f) != (size_t)size) {
        s3_free(buf);
        fclose(f);
        return S3_ERROR;
    }

    fclose(f);

    rc = S3_DECLINED;

    {

        const u_char *pos = buf, *end = buf + size;
        s3_str_t      keytype, b64;

        line = s3_ssh3_auth_authorized_keys_next(&pos, end, &keytype, &b64);

        while (rc == S3_DECLINED && line != S3_DONE) {

            if (line == S3_OK) {

                EVP_PKEY *key;

                if (s3_ssh3_jwt_b64_decode(b64.data, b64.len, &dlen, 0) == S3_OK) {

                    key = s3_ssh3_jwt_blob_key(b64.data, dlen);

                    if (key != NULL) {

                        if (s3_ssh3_jwt_sig_verify(alg, key, msg, msglen, sig, siglen) == S3_OK) {
                            rc = S3_OK;
                        }

                        EVP_PKEY_free(key);
                    }
                }

            } else {

                /* the iterator stays on the malformed line: the walk
                 * skips past it and the rest of the file decides */

                const u_char *nl = memchr(pos, '\n', (size_t)(end - pos));

                pos = (nl != NULL) ? nl + 1 : end;
            }

            line = s3_ssh3_auth_authorized_keys_next(&pos, end, &keytype, &b64);
        }
    }

    s3_free(buf);

    return rc;
}

s3_int_t
s3_ssh3_auth_jwt_bearer(const s3_str_t *header)
{
    static s3_str_t scheme = s3_string("Bearer ");

    size_t i;

    if (header->len < scheme.len) {
        return S3_DECLINED;
    }

    /* the case-insensitive prefix, like the reference EqualFold */

    for (i = 0; i < scheme.len; i++) {

        u_char a = header->data[i], b = scheme.data[i];

        if (a >= 'A' && a <= 'Z') {
            a = (u_char)(a - 'A' + 'a');
        }

        if (b >= 'A' && b <= 'Z') {
            b = (u_char)(b - 'A' + 'a');
        }

        if (a != b) {
            return S3_DECLINED;
        }
    }

    return S3_OK;
}

s3_int_t
s3_ssh3_auth_jwt_verify(const s3_str_t *header, const s3_str_t *user, const char *keys_path,
                        const u_char *convid, size_t convid_len)
{
    static s3_str_t sub_required = s3_string("ssh3");

    s3_ssh3_jwt_claims_t cl, hdr_cl;
    s3_str_t             alg = s3_string(""), dead_alg = s3_string("");
    const u_char        *token, *dot1, *dot2, *token_end;
    size_t               token_len, hlen, plen, slen, dlen, mlen;
    u_char               hdr[S3_SSH3_JWT_HDR_MAX];
    u_char               payload[S3_SSH3_JWT_PAYLOAD_MAX];
    u_char               sig[S3_SSH3_JWT_SIG_MAX];
    u_char               jti[64];
    u_char               cid[S3_SSH3_JWT_USER_MAX + 16];
    long long            now;

    if (user == NULL || user->len == 0 || user->len > S3_SSH3_JWT_USER_MAX) {
        return S3_DECLINED;
    }

    if (s3_ssh3_auth_jwt_bearer(header) != S3_OK) {
        return S3_DECLINED;
    }

    token = header->data + 7;
    token_len = header->len - 7;
    token_end = token + token_len;

    /* the three segments: the dots split, none may be empty */

    dot1 = memchr(token, '.', token_len);

    if (dot1 == NULL || dot1 == token || (size_t)(token_end - dot1) < 2) {
        return S3_DECLINED;
    }

    dot2 = memchr(dot1 + 1, '.', (size_t)(token_end - dot1 - 1));

    if (dot2 == NULL || dot2 == dot1 + 1 || dot2 + 1 == token_end) {
        return S3_DECLINED;
    }

    hlen = (size_t)(dot1 - token);
    plen = (size_t)(dot2 - dot1) - 1;
    slen = (size_t)(token_end - dot2) - 1;

    if (hlen > sizeof(hdr) || plen > sizeof(payload) || slen > sizeof(sig)) {
        return S3_DECLINED;
    }

    memcpy(hdr, token, hlen);
    memcpy(payload, dot1 + 1, plen);
    memcpy(sig, dot2 + 1, slen);

    if (s3_ssh3_jwt_b64_decode(hdr, hlen, &dlen, 1) != S3_OK) {
        return S3_DECLINED;
    }

    /* the header carries the alg, its claim keys are dead weight - the
     * claims of the token live in the payload only */

    s3_memzero(&hdr_cl, sizeof(hdr_cl));

    if (s3_ssh3_jwt_scan(hdr, hdr + dlen, &alg, &hdr_cl) != S3_OK) {
        return S3_DECLINED;
    }

    if (s3_ssh3_jwt_b64_decode(payload, plen, &dlen, 1) != S3_OK) {
        return S3_DECLINED;
    }

    s3_memzero(&cl, sizeof(cl));

    if (s3_ssh3_jwt_scan(payload, payload + dlen, &dead_alg, &cl) != S3_OK) {
        return S3_DECLINED;
    }

    if (s3_ssh3_jwt_b64_decode(sig, slen, &dlen, 1) != S3_OK) {
        return S3_DECLINED;
    }

    slen = dlen;

    /* the algorithm allowlist of the reference, the keyfunc and the
     * WithValidMethods pair: EdDSA, ES256, RS256 - none and the macs
     * fall through */

    if (alg.len != 5 ||
        (s3_memcmp(alg.data, "EdDSA", 5) != 0 && s3_memcmp(alg.data, "ES256", 5) != 0 &&
         s3_memcmp(alg.data, "RS256", 5) != 0)) {
        return S3_DECLINED;
    }

    now = (long long)time(NULL);

    /* the claim verdict of the reference: the exp required and fresh,
     * the iat/nbf not in the future, the identity claims exact */

    if (cl.bad || !cl.exp_present || cl.exp < now) {
        return S3_DECLINED;
    }

    if ((cl.iat_present && cl.iat > now) || (cl.nbf_present && cl.nbf > now)) {
        return S3_DECLINED;
    }

    if (cl.iss.len != user->len || s3_memcmp(cl.iss.data, user->data, user->len) != 0) {
        return S3_DECLINED;
    }

    if (cl.sub.len != sub_required.len ||
        s3_memcmp(cl.sub.data, sub_required.data, cl.sub.len) != 0) {
        return S3_DECLINED;
    }

    if (cl.aud.len != 6 || s3_memcmp(cl.aud.data, "unused", 6) != 0) {
        return S3_DECLINED;
    }

    mlen = (size_t)snprintf((char *)cid, sizeof(cid), "ssh3-%.*s", (int)user->len,
                            (const char *)user->data);

    if (mlen >= sizeof(cid) || cl.client_id.len != mlen ||
        s3_memcmp(cl.client_id.data, cid, mlen) != 0) {
        return S3_DECLINED;
    }

    /* the jti binding: the claim must be present and non-empty, the
     * equality binds when the harness hands the exporter bytes */

    if (!cl.jti_present || cl.jti.len == 0) {
        return S3_DECLINED;
    }

    if (convid != NULL) {

        if (convid_len == 0 || convid_len > 48) {
            return S3_ERROR;
        }

        dlen = s3_ssh3_jwt_b64_std_encode(convid, convid_len, jti);

        if (cl.jti.len != dlen || s3_memcmp(cl.jti.data, jti, dlen) != 0) {
            return S3_DECLINED;
        }
    }

    /* the signature over the signing input against the keys file, the
     * claim checks ran first so a garbage token never loads a file */

    return s3_ssh3_jwt_keys_file(keys_path, &alg, token, (size_t)(dot2 - token), sig, slen);
}
