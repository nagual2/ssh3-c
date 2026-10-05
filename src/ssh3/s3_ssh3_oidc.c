/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the OIDC token verification of the reference server_auth/ chain:
 * the provider discovery, the JWKS fetch with the kid cache, the
 * id_token verification (the provider-key signature of the RS256 and
 * the ES256 allowlist, iss, aud, exp and the conversation nonce); the
 * JSON needs of the OIDC documents are covered by the flat-object
 * scanner below (no JSON library in the product)
 */

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/ssl.h>

#include <stdio.h>

#include <s3_https_fetch.h>
#include <s3_ssh3_oidc.h>

/* the envelope and the claim caps of one id_token */

#define S3_SSH3_OIDC_TOKEN_MAX   16384
#define S3_SSH3_OIDC_HDR_MAX     512
#define S3_SSH3_OIDC_PAYLOAD_MAX 4096
#define S3_SSH3_OIDC_SIG_MAX     1024
#define S3_SSH3_OIDC_JWK_NUM_MAX 1024

/* the nbf clock skew, the go-oidc leeway */

#define S3_SSH3_OIDC_NBF_LEEWAY 300

/* the JSON nesting cap of the scanner, the OIDC documents sit shallow */

#define S3_JSON_DEPTH_MAX 8

/* ------------------------------------------------------------------ */
/* the base64url (RFC 4648 section 5, the JWS alphabet)                */
/* ------------------------------------------------------------------ */

static s3_int_t
s3_oidc_b64url_sextet(u_char c, s3_uint_t *value)
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

size_t
s3_ssh3_oidc_b64url_encode(const u_char *in, size_t len, u_char *out)
{
    static const u_char digits[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                   "abcdefghijklmnopqrstuvwxyz"
                                   "0123456789-_";

    size_t    n, out_n;
    s3_uint_t v;

    out_n = 0;

    for (n = 0; n + 3 <= len; n += 3) {

        v = ((s3_uint_t)in[n] << 16) | ((s3_uint_t)in[n + 1] << 8) | in[n + 2];

        out[out_n++] = digits[(v >> 18) & 0x3f];
        out[out_n++] = digits[(v >> 12) & 0x3f];
        out[out_n++] = digits[(v >> 6) & 0x3f];
        out[out_n++] = digits[v & 0x3f];
    }

    switch (len - n) {

    case 1:
        v = (s3_uint_t)in[n] << 16;
        out[out_n++] = digits[(v >> 18) & 0x3f];
        out[out_n++] = digits[(v >> 12) & 0x3f];
        break;

    case 2:
        v = ((s3_uint_t)in[n] << 16) | ((s3_uint_t)in[n + 1] << 8);
        out[out_n++] = digits[(v >> 18) & 0x3f];
        out[out_n++] = digits[(v >> 12) & 0x3f];
        out[out_n++] = digits[(v >> 6) & 0x3f];
        break;

    default:
        break;
    }

    return out_n;
}

s3_int_t
s3_ssh3_oidc_b64url_decode(const u_char *in, size_t len, u_char *out, size_t *dlen)
{
    s3_uint_t v[4];
    size_t    n, i, out_n, pad;

    /* the JWS form carries no padding, the padded form decodes too */

    while (len > 0 && in[len - 1] == '=') {
        len--;
    }

    out_n = 0;

    for (n = 0; n < len; n += 4) {

        pad = len - n;

        if (pad == 1) {
            /* the lone sextet never happens in the JWS alphabet */
            return S3_ERROR;
        }

        for (i = 0; i < 4; i++) {

            if (i >= pad) {
                v[i] = 0;
                continue;
            }

            if (s3_oidc_b64url_sextet(in[n + i], &v[i]) != S3_OK) {
                return S3_ERROR;
            }
        }

        out[out_n++] = (u_char)((v[0] << 2) | (v[1] >> 4));

        if (pad > 2) {
            out[out_n++] = (u_char)(((v[1] & 0xf) << 4) | (v[2] >> 2));
        }

        if (pad > 3) {
            out[out_n++] = (u_char)(((v[2] & 0x3) << 6) | v[3]);
        }
    }

    *dlen = out_n;

    return S3_OK;
}

/* ------------------------------------------------------------------ */
/* the ECDSA raw <-> DER forms (the JWS carries r||s, OpenSSL the DER) */
/* ------------------------------------------------------------------ */

static size_t
s3_oidc_der_int(const u_char *half, size_t half_len, u_char *out)
{
    const u_char *start, *end;
    size_t        n;

    /* the minimal INTEGER payload: the leading zeros die, the high
     * bit adds the zero octet (RFC 8017 4.1.2 shape) */

    start = half;

    while (start < half + half_len && *start == 0) {
        start++;
    }

    end = half + half_len;

    if (start == end) {
        out[0] = 0x02;
        out[1] = 0x01;
        out[2] = 0x00;
        return 3;
    }

    n = (size_t)(end - start);
    out[0] = 0x02;
    out[1] = (u_char)n;

    if (*start & 0x80) {
        out[1]++;
        out[2] = 0x00;
        s3_memcpy(out + 3, start, n);
        return n + 3;
    }

    s3_memcpy(out + 2, start, n);

    return n + 2;
}

static s3_int_t
s3_oidc_ecdsa_raw_to_der(const u_char *raw, size_t coord_len, u_char *der, size_t *der_len)
{
    u_char *p;
    size_t  rn, sn;

    if (coord_len == 0 || coord_len > 66) {
        return S3_ERROR;
    }

    /* the two INTEGER bodies start behind the SEQUENCE header */

    p = der + 2;

    rn = s3_oidc_der_int(raw, coord_len, p);
    p += rn;

    sn = s3_oidc_der_int(raw + coord_len, coord_len, p);
    p += sn;

    der[0] = 0x30;
    der[1] = (u_char)(rn + sn);

    *der_len = (size_t)(p - der);

    return S3_OK;
}

s3_int_t
s3_ssh3_oidc_ecdsa_der_to_raw(const u_char *der, size_t der_len, u_char *raw, size_t coord_len)
{
    const u_char *p, *end;
    size_t        half;

    p = der;
    end = der + der_len;

    /* SEQUENCE { INTEGER r, INTEGER s }, the minimal DER of the
     * signer: two coordinate halves left-padded with zeros */

    if (der_len < 8 || p[0] != 0x30) {
        return S3_ERROR;
    }

    p += 2;

    for (half = 0; half < 2; half++) {

        size_t n, z;
        u_char lead;

        if ((size_t)(end - p) < 2 || p[0] != 0x02) {
            return S3_ERROR;
        }

        n = p[1];
        p += 2;

        if (n == 0 || n > coord_len + 1 || (size_t)(end - p) < n) {
            return S3_ERROR;
        }

        lead = p[0];

        if (lead == 0 && n == coord_len + 1) {

            /* the sign octet of the positive minimal INTEGER: the
             * data behind it may carry the high bit */

            p++;
            n--;
        }

        if ((lead & 0x80 && n == coord_len + 1) || n > coord_len) {
            /* the unpadded high bit is the negative shape */
            return S3_ERROR;
        }

        z = coord_len - n;

        s3_memzero(raw + half * coord_len, z);
        s3_memcpy(raw + half * coord_len + z, p, n);

        p += n;
    }

    return S3_OK;
}

/* ------------------------------------------------------------------ */
/* the flat-JSON scanner (the OIDC documents sit one level deep)        */
/* ------------------------------------------------------------------ */

typedef struct {
    const u_char *pos;
    const u_char *end;
} s3_json_t;

static void
s3_json_ws(s3_json_t *j)
{
    while (j->pos < j->end &&
           (*j->pos == ' ' || *j->pos == '\t' || *j->pos == '\n' || *j->pos == '\r')) {
        j->pos++;
    }
}

static s3_int_t
s3_json_string_span(s3_json_t *j, s3_str_t *span)
{
    const u_char *p;

    if (j->pos >= j->end || *j->pos != '"') {
        return S3_ERROR;
    }

    j->pos++;

    p = j->pos;

    while (p < j->end) {

        if (*p == '"') {
            span->data = (u_char *)j->pos;
            span->len = (size_t)(p - j->pos);
            j->pos = p + 1;
            return S3_OK;
        }

        if (*p == '\\' && p + 1 < j->end) {
            p++;
        }

        p++;
    }

    return S3_ERROR;
}

/* the composite of the depth: the members of the object and the
 * elements of the array, one level shallower on the recursion */

static s3_int_t s3_json_skip_value(s3_json_t *j, unsigned depth);

static s3_int_t
s3_json_skip_composite(s3_json_t *j, u_char close, unsigned depth)
{
    s3_str_t key;
    unsigned first = 1;

    for (;;) {

        s3_json_ws(j);

        if (j->pos >= j->end) {
            return S3_ERROR;
        }

        if (*j->pos == close) {
            j->pos++;
            return S3_OK;
        }

        if (!first) {

            if (*j->pos != ',') {
                return S3_ERROR;
            }

            j->pos++;

            s3_json_ws(j);

            if (j->pos >= j->end || *j->pos == close) {
                /* no trailing comma */
                return S3_ERROR;
            }
        }

        first = 0;

        if (close == '}') {

            /* the member name and the colon ride before the value */

            if (*j->pos != '"' || s3_json_string_span(j, &key) != S3_OK) {
                return S3_ERROR;
            }

            s3_json_ws(j);

            if (j->pos >= j->end || *j->pos != ':') {
                return S3_ERROR;
            }

            j->pos++;
        }

        if (depth <= 1 || s3_json_skip_value(j, depth - 1) != S3_OK) {
            return S3_ERROR;
        }
    }
}

static s3_int_t
s3_json_skip_value(s3_json_t *j, unsigned depth)
{
    s3_str_t      span;
    const u_char *start;

    if (depth == 0) {
        return S3_ERROR;
    }

    s3_json_ws(j);

    if (j->pos >= j->end) {
        return S3_ERROR;
    }

    switch (*j->pos) {

    case '"':
        return s3_json_string_span(j, &span);

    case '{':
        j->pos++;
        return s3_json_skip_composite(j, '}', depth);

    case '[':
        j->pos++;
        return s3_json_skip_composite(j, ']', depth);

    default:

        /* the bare token: number, true, false, null */

        start = j->pos;

        while (j->pos < j->end && *j->pos != ',' && *j->pos != '}' && *j->pos != ']' &&
               *j->pos != ' ' && *j->pos != '\t' && *j->pos != '\n' && *j->pos != '\r') {
            j->pos++;
        }

        return (j->pos > start) ? S3_OK : S3_ERROR;
    }
}

/*
 * the top-level member of the flat object: the scan stays at the
 * depth one, the nested objects ride past wholesale (the skip does
 * not descend into the members)
 */

s3_int_t
s3_ssh3_oidc_json_find(const s3_str_t *obj, const char *name, s3_str_t *value)
{
    s3_json_t j;
    s3_str_t  key, span;
    size_t    nlen;

    nlen = s3_strlen(name);

    j.pos = obj->data;
    j.end = obj->data + obj->len;

    s3_json_ws(&j);

    if (j.pos >= j.end || *j.pos != '{') {
        return S3_ERROR;
    }

    j.pos++;

    for (;;) {

        s3_json_ws(&j);

        if (j.pos >= j.end) {
            return S3_ERROR;
        }

        if (*j.pos == '}') {
            return S3_DECLINED;
        }

        if (*j.pos != '"') {
            return S3_ERROR;
        }

        if (s3_json_string_span(&j, &key) != S3_OK) {
            return S3_ERROR;
        }

        s3_json_ws(&j);

        if (j.pos >= j.end || *j.pos != ':') {
            return S3_ERROR;
        }

        j.pos++;

        s3_json_ws(&j);

        /* the value span: from here to the end of the one value */

        span.data = (u_char *)j.pos;

        if (s3_json_skip_value(&j, S3_JSON_DEPTH_MAX) != S3_OK) {
            return S3_ERROR;
        }

        span.len = (size_t)(j.pos - span.data);

        if (key.len == nlen && s3_memcmp(key.data, name, nlen) == 0) {

            *value = span;

            return S3_OK;
        }

        /* the next member rides behind the comma, the closing brace
         * answers the declined at the loop top */

        s3_json_ws(&j);

        if (j.pos < j.end && *j.pos == ',') {
            j.pos++;
        }
    }
}

/* the plain member copy: the JSON escapes decode into the buffer */

static int
s3_json_hex4(const u_char *p, unsigned *out)
{
    unsigned v, i;

    v = 0;

    for (i = 0; i < 4; i++) {

        v <<= 4;

        if (p[i] >= '0' && p[i] <= '9') {
            v |= (unsigned)(p[i] - '0');

        } else if (p[i] >= 'a' && p[i] <= 'f') {
            v |= (unsigned)(p[i] - 'a') + 10;

        } else if (p[i] >= 'A' && p[i] <= 'F') {
            v |= (unsigned)(p[i] - 'A') + 10;

        } else {
            return -1;
        }
    }

    *out = v;

    return 0;
}

static size_t
s3_json_utf8(unsigned cp, u_char *out)
{
    if (cp < 0x80) {
        out[0] = (u_char)cp;
        return 1;
    }

    if (cp < 0x800) {
        out[0] = (u_char)(0xc0 | (cp >> 6));
        out[1] = (u_char)(0x80 | (cp & 0x3f));
        return 2;
    }

    if (cp < 0x10000) {
        out[0] = (u_char)(0xe0 | (cp >> 12));
        out[1] = (u_char)(0x80 | ((cp >> 6) & 0x3f));
        out[2] = (u_char)(0x80 | (cp & 0x3f));
        return 3;
    }

    out[0] = (u_char)(0xf0 | (cp >> 18));
    out[1] = (u_char)(0x80 | ((cp >> 12) & 0x3f));
    out[2] = (u_char)(0x80 | ((cp >> 6) & 0x3f));
    out[3] = (u_char)(0x80 | (cp & 0x3f));

    return 4;
}

static s3_int_t
s3_json_decode_string(const s3_str_t *quoted, u_char *buf, size_t max, size_t *out_len)
{
    const u_char *p, *end;
    size_t        n;
    unsigned      cp, low;

    /* quoted spans exclude the quotes (s3_json_string_span) */

    p = quoted->data;
    end = quoted->data + quoted->len;
    n = 0;

    while (p < end) {

        u_char ch = *p;

        if (ch != '\\') {
            buf[n++] = ch;
            p++;
            continue;
        }

        if (p + 1 >= end || n + 8 > max) {
            return S3_ERROR;
        }

        switch (p[1]) {

        case '"':
        case '\\':
        case '/':
            buf[n++] = p[1];
            p += 2;
            continue;

        case 'b':
            buf[n++] = '\b';
            p += 2;
            continue;

        case 'f':
            buf[n++] = '\f';
            p += 2;
            continue;

        case 'n':
            buf[n++] = '\n';
            p += 2;
            continue;

        case 'r':
            buf[n++] = '\r';
            p += 2;
            continue;

        case 't':
            buf[n++] = '\t';
            p += 2;
            continue;

        case 'u':
            break;

        default:
            return S3_ERROR;
        }

        if (p + 6 > end || s3_json_hex4(p + 2, &cp) != 0) {
            return S3_ERROR;
        }

        p += 6;

        if (cp >= 0xd800 && cp <= 0xdbff) {

            /* the surrogate pair */

            if (p + 6 > end || p[0] != '\\' || p[1] != 'u' || s3_json_hex4(p + 2, &low) != 0 ||
                low < 0xdc00 || low > 0xdfff) {
                return S3_ERROR;
            }

            cp = 0x10000 + ((cp - 0xd800) << 10) + (low - 0xdc00);
            p += 6;
        }

        n += s3_json_utf8(cp, buf + n);
    }

    *out_len = n;

    return S3_OK;
}

s3_int_t
s3_ssh3_oidc_json_string(const s3_str_t *obj, const char *name, char *buf, size_t max)
{
    s3_str_t value, inner;
    size_t   n;

    if (s3_ssh3_oidc_json_find(obj, name, &value) != S3_OK) {
        return S3_DECLINED;
    }

    if (value.len < 2 || value.data[0] != '"' || value.data[value.len - 1] != '"') {
        return S3_DECLINED;
    }

    inner.data = value.data + 1;
    inner.len = value.len - 2;

    if (s3_json_decode_string(&inner, (u_char *)buf, max, &n) != S3_OK) {
        return S3_ERROR;
    }

    buf[n] = '\0';

    return S3_OK;
}

s3_int_t
s3_ssh3_oidc_json_int(const s3_str_t *obj, const char *name, int64_t *out)
{
    s3_str_t      value;
    const u_char *p, *end;
    int64_t       v;
    unsigned      neg;

    if (s3_ssh3_oidc_json_find(obj, name, &value) != S3_OK) {
        return S3_DECLINED;
    }

    p = value.data;
    end = value.data + value.len;

    neg = 0;

    if (p < end && *p == '-') {
        neg = 1;
        p++;
    }

    if (p == end) {
        return S3_DECLINED;
    }

    v = 0;

    for (; p < end; p++) {

        if (*p < '0' || *p > '9') {
            /* the exponent or the fraction is not the claim shape */
            return S3_DECLINED;
        }

        if (v > (INT64_MAX - 9) / 10) {
            return S3_DECLINED;
        }

        v = v * 10 + (*p - '0');
    }

    *out = neg ? -v : v;

    return S3_OK;
}

s3_int_t
s3_ssh3_oidc_json_aud_contains(const s3_str_t *claims, const char *want)
{
    s3_json_t j;
    s3_str_t  value, elem;
    char      buf[256];
    size_t    n, wlen;

    if (s3_ssh3_oidc_json_find(claims, "aud", &value) != S3_OK) {
        return S3_DECLINED;
    }

    wlen = s3_strlen(want);

    if (value.len >= 2 && value.data[0] == '"') {

        /* the single-string form */

        if (value.data[value.len - 1] != '"' || value.len - 2 != wlen ||
            s3_memcmp(value.data + 1, want, wlen) != 0) {
            return S3_DECLINED;
        }

        return S3_OK;
    }

    /* the array form: the elements are the plain strings (the aud
     * values of the wire are url-safe tokens, the escapes decode
     * through the same path) */

    if (value.len < 2 || value.data[0] != '[' || value.data[value.len - 1] != ']') {
        return S3_DECLINED;
    }

    j.pos = value.data + 1;
    j.end = value.data + value.len - 1;

    for (;;) {

        s3_json_ws(&j);

        if (j.pos >= j.end) {
            return S3_DECLINED;
        }

        if (s3_json_string_span(&j, &elem) != S3_OK) {
            return S3_DECLINED;
        }

        if (elem.len <= sizeof(buf) &&
            s3_json_decode_string(&elem, (u_char *)buf, sizeof(buf) - 1, &n) == S3_OK &&
            n == wlen && s3_memcmp(buf, want, wlen) == 0) {
            return S3_OK;
        }

        s3_json_ws(&j);

        if (j.pos < j.end && *j.pos == ',') {
            j.pos++;
            continue;
        }

        return S3_DECLINED;
    }
}

/* ------------------------------------------------------------------ */
/* the discovery                                                       */
/* ------------------------------------------------------------------ */

s3_int_t
s3_ssh3_oidc_discover(const char *issuer_url, const char *ca_file, s3_ssh3_oidc_provider_t *out)
{
    char     url[2 * S3_SSH3_OIDC_URL_MAX];
    s3_str_t body, doc;
    unsigned status;
    size_t   n;
    s3_int_t rc;

    n = s3_strlen(issuer_url);

    while (n > 0 && issuer_url[n - 1] == '/') {
        n--;
    }

    if (n == 0 || n + sizeof("/.well-known/openid-configuration") + 1 > sizeof(url)) {
        return S3_ERROR;
    }

    s3_memcpy(url, issuer_url, n);
    s3_memcpy(url + n, "/.well-known/openid-configuration",
              sizeof("/.well-known/openid-configuration"));

    if (s3_https_fetch(url, "GET", NULL, NULL, ca_file, &status, &body) != S3_OK) {
        return S3_ERROR;
    }

    if (status != 200) {
        s3_free(body.data);
        return S3_ERROR;
    }

    doc.data = body.data;
    doc.len = body.len;

    rc = s3_ssh3_oidc_json_string(&doc, "issuer", out->issuer, sizeof(out->issuer));

    if (rc == S3_OK) {
        rc = s3_ssh3_oidc_json_string(&doc, "authorization_endpoint", out->authorization_endpoint,
                                      sizeof(out->authorization_endpoint));
    }

    if (rc == S3_OK) {
        rc = s3_ssh3_oidc_json_string(&doc, "token_endpoint", out->token_endpoint,
                                      sizeof(out->token_endpoint));
    }

    if (rc == S3_OK) {
        rc = s3_ssh3_oidc_json_string(&doc, "jwks_uri", out->jwks_uri, sizeof(out->jwks_uri));
    }

    s3_free(body.data);

    if (rc != S3_OK) {
        return S3_ERROR;
    }

    /* the go-oidc provider check: the document issuer must match */

    if (s3_strcmp(out->issuer, issuer_url) != 0) {
        return S3_DECLINED;
    }

    return S3_OK;
}

/* ------------------------------------------------------------------ */
/* the JWK -> EVP_PKEY (the RSA n/e and the EC P-256 crv/x/y)          */
/* ------------------------------------------------------------------ */

static EVP_PKEY *
s3_oidc_jwk_rsa_key(const u_char *n, size_t n_len, const u_char *e, size_t e_len)
{
    OSSL_PARAM_BLD *bld;
    OSSL_PARAM     *params;
    EVP_PKEY_CTX   *ctx;
    EVP_PKEY       *pkey;
    BIGNUM         *bn_n, *bn_e;

    bn_n = BN_bin2bn(n, (int)n_len, NULL);
    bn_e = BN_bin2bn(e, (int)e_len, NULL);

    if (bn_n == NULL || bn_e == NULL) {
        BN_free(bn_n);
        BN_free(bn_e);
        return NULL;
    }

    bld = OSSL_PARAM_BLD_new();

    if (bld == NULL) {
        BN_free(bn_n);
        BN_free(bn_e);
        return NULL;
    }

    if (OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, bn_n) != 1 ||
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, bn_e) != 1) {
        OSSL_PARAM_BLD_free(bld);
        BN_free(bn_n);
        BN_free(bn_e);
        return NULL;
    }

    params = OSSL_PARAM_BLD_to_param(bld);

    OSSL_PARAM_BLD_free(bld);
    BN_free(bn_n);
    BN_free(bn_e);

    if (params == NULL) {
        return NULL;
    }

    pkey = NULL;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);

    if (ctx != NULL && EVP_PKEY_fromdata_init(ctx) == 1 &&
        EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) == 1) {
        EVP_PKEY_CTX_free(ctx);
        OSSL_PARAM_free(params);

        return pkey;
    }

    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);

    return NULL;
}

static EVP_PKEY *
s3_oidc_jwk_ec_key(const u_char *x, size_t x_len, const u_char *y, size_t y_len)
{
    OSSL_PARAM_BLD *bld;
    OSSL_PARAM     *params;
    EVP_PKEY_CTX   *ctx;
    EVP_PKEY       *pkey;
    u_char          point[1 + 66];

    if (x_len != 32 || y_len != 32 || 1 + x_len + y_len > sizeof(point)) {
        return NULL;
    }

    point[0] = 0x04;
    s3_memcpy(point + 1, x, x_len);
    s3_memcpy(point + 1 + x_len, y, y_len);

    bld = OSSL_PARAM_BLD_new();

    if (bld == NULL) {
        return NULL;
    }

    if (OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0) != 1 ||
        OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, point, 1 + x_len + y_len) !=
            1) {
        OSSL_PARAM_BLD_free(bld);
        return NULL;
    }

    params = OSSL_PARAM_BLD_to_param(bld);

    OSSL_PARAM_BLD_free(bld);

    if (params == NULL) {
        return NULL;
    }

    pkey = NULL;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);

    if (ctx != NULL && EVP_PKEY_fromdata_init(ctx) == 1 &&
        EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) == 1) {
        EVP_PKEY_CTX_free(ctx);
        OSSL_PARAM_free(params);

        return pkey;
    }

    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);

    return NULL;
}

static void
s3_oidc_key_clear(s3_ssh3_oidc_key_t *key)
{
    s3_memzero(key->kid, sizeof(key->kid));
    key->ec = 0;

    if (key->pkey != NULL) {
        EVP_PKEY_free(key->pkey);
        key->pkey = NULL;
    }
}

void
s3_ssh3_oidc_jwks_clear(s3_ssh3_oidc_jwks_t *jwks)
{
    size_t i;

    for (i = 0; i < jwks->nkeys; i++) {
        s3_oidc_key_clear(&jwks->keys[i]);
    }

    jwks->nkeys = 0;
}

/* the quoted member value of the jwk object decodes as the base64url
 * payload (the json_find span carries the quotes) */

static s3_int_t
s3_oidc_jwk_b64url(const s3_str_t *jwk, const char *name, u_char *out, size_t out_max,
                   size_t *out_len)
{
    s3_str_t value;
    s3_int_t rc;

    rc = s3_ssh3_oidc_json_find(jwk, name, &value);

    if (rc != S3_OK) {
        return rc;
    }

    if (value.len < 2 || value.data[0] != '"' || value.data[value.len - 1] != '"') {
        return S3_ERROR;
    }

    /* the exact worst-case output of the quantum shape bounds the
     * buffer (43 chars decode into 32 bytes) */

    {
        size_t enc = value.len - 2;
        size_t worst = (enc / 4) * 3;

        if (enc % 4 == 1) {
            return S3_ERROR;
        }

        worst += (enc % 4 == 2) ? 1 : (enc % 4 == 3) ? 2 : 0;

        if (worst > out_max) {
            return S3_ERROR;
        }
    }

    return s3_ssh3_oidc_b64url_decode(value.data + 1, value.len - 2, out, out_len);
}

static s3_int_t
s3_oidc_jwk_add(s3_ssh3_oidc_jwks_t *jwks, const s3_str_t *jwk)
{
    s3_ssh3_oidc_key_t key;
    char               kty[8], crv[16];
    u_char             bn_buf[S3_SSH3_OIDC_JWK_NUM_MAX];
    size_t             bn_len;

    s3_memzero(&key, sizeof(key));

    if (s3_ssh3_oidc_json_string(jwk, "kid", key.kid, sizeof(key.kid)) != S3_OK ||
        key.kid[0] == '\0') {
        return S3_ERROR;
    }

    if (s3_ssh3_oidc_json_string(jwk, "kty", kty, sizeof(kty)) != S3_OK) {
        return S3_ERROR;
    }

    if (s3_strcmp(kty, "RSA") == 0) {

        key.ec = 0;

        if (s3_oidc_jwk_b64url(jwk, "n", bn_buf, sizeof(bn_buf), &bn_len) != S3_OK || bn_len == 0) {
            return S3_ERROR;
        }

        /* the modulus rides the decode buffer only until the key
         * exists, the same buffer carries the exponent below */

        {
            u_char e_buf[16];
            size_t e_len;

            if (s3_oidc_jwk_b64url(jwk, "e", e_buf, sizeof(e_buf), &e_len) != S3_OK || e_len == 0) {
                return S3_ERROR;
            }

            key.pkey = s3_oidc_jwk_rsa_key(bn_buf, bn_len, e_buf, e_len);
        }

    } else if (s3_strcmp(kty, "EC") == 0) {

        key.ec = 1;

        if (s3_ssh3_oidc_json_string(jwk, "crv", crv, sizeof(crv)) != S3_OK ||
            s3_strcmp(crv, "P-256") != 0) {
            return S3_ERROR;
        }

        {
            u_char x[32], y[32];
            size_t x_len, y_len;

            if (s3_oidc_jwk_b64url(jwk, "x", x, sizeof(x), &x_len) != S3_OK || x_len != sizeof(x) ||
                s3_oidc_jwk_b64url(jwk, "y", y, sizeof(y), &y_len) != S3_OK || y_len != sizeof(y)) {
                return S3_ERROR;
            }

            key.pkey = s3_oidc_jwk_ec_key(x, x_len, y, y_len);
        }

    } else {
        return S3_ERROR;
    }

    if (key.pkey == NULL) {
        return S3_ERROR;
    }

    /* the same kid replaces its key, a new kid appends */

    {
        size_t i;

        for (i = 0; i < jwks->nkeys; i++) {

            if (s3_strcmp(jwks->keys[i].kid, key.kid) == 0) {
                s3_oidc_key_clear(&jwks->keys[i]);
                jwks->keys[i] = key;
                return S3_OK;
            }
        }
    }

    if (jwks->nkeys >= S3_SSH3_OIDC_KEYS_MAX) {
        s3_oidc_key_clear(&key);
        return S3_ERROR;
    }

    jwks->keys[jwks->nkeys++] = key;

    return S3_OK;
}

s3_int_t
s3_ssh3_oidc_jwks_parse(s3_ssh3_oidc_jwks_t *jwks, const u_char *json, size_t len)
{
    s3_str_t  doc, keys, elem;
    s3_json_t it;

    doc.data = (u_char *)json;
    doc.len = len;

    if (s3_ssh3_oidc_json_find(&doc, "keys", &keys) != S3_OK) {
        return S3_ERROR;
    }

    if (keys.len < 2 || keys.data[0] != '[' || keys.data[keys.len - 1] != ']') {
        return S3_ERROR;
    }

    it.pos = keys.data + 1;
    it.end = keys.data + keys.len - 1;

    for (;;) {

        s3_json_ws(&it);

        if (it.pos >= it.end) {
            return S3_OK;
        }

        if (*it.pos != '{') {
            return S3_ERROR;
        }

        elem.data = (u_char *)it.pos;

        if (s3_json_skip_value(&it, S3_JSON_DEPTH_MAX) != S3_OK) {
            return S3_ERROR;
        }

        elem.len = (size_t)(it.pos - elem.data);

        if (s3_oidc_jwk_add(jwks, &elem) != S3_OK) {
            return S3_ERROR;
        }

        s3_json_ws(&it);

        if (it.pos < it.end && *it.pos == ',') {
            it.pos++;
            continue;
        }
    }
}

s3_int_t
s3_ssh3_oidc_jwks_fetch(const s3_ssh3_oidc_provider_t *provider, const char *ca_file,
                        s3_ssh3_oidc_jwks_t *jwks)
{
    s3_str_t body;
    unsigned status;
    s3_int_t rc;

    if (provider->jwks_uri[0] == '\0') {
        return S3_ERROR;
    }

    if (s3_https_fetch(provider->jwks_uri, "GET", NULL, NULL, ca_file, &status, &body) != S3_OK) {
        return S3_ERROR;
    }

    if (status != 200) {
        s3_free(body.data);
        return S3_ERROR;
    }

    /* the fetch replaces the whole set: the provider key rotation */

    s3_ssh3_oidc_jwks_clear(jwks);

    rc = s3_ssh3_oidc_jwks_parse(jwks, body.data, body.len);

    s3_free(body.data);

    if (rc != S3_OK) {
        s3_ssh3_oidc_jwks_clear(jwks);
        return S3_ERROR;
    }

    return S3_OK;
}

/* ------------------------------------------------------------------ */
/* the id_token verification                                           */
/* ------------------------------------------------------------------ */

static const s3_ssh3_oidc_key_t *
s3_oidc_keyset_find(const s3_ssh3_oidc_jwks_t *jwks, const char *kid)
{
    size_t i;

    for (i = 0; i < jwks->nkeys; i++) {

        if (s3_strcmp(jwks->keys[i].kid, kid) == 0) {
            return &jwks->keys[i];
        }
    }

    return NULL;
}

s3_int_t
s3_ssh3_oidc_verify(const s3_ssh3_oidc_jwks_t *jwks, const char *issuer, const char *audience,
                    const char *token, const char *nonce, time_t now)
{
    u_char                    hdr[S3_SSH3_OIDC_HDR_MAX], payload[S3_SSH3_OIDC_PAYLOAD_MAX];
    u_char                    sig[S3_SSH3_OIDC_SIG_MAX], der[3 + 2 * 66 + 2];
    char                      alg[S3_SSH3_OIDC_ALG_MAX], kid[S3_SSH3_OIDC_KID_MAX];
    char                      iss[S3_SSH3_OIDC_URL_MAX], token_nonce[128];
    s3_str_t                  claims;
    const char               *dot1, *dot2, *p, *end;
    const s3_ssh3_oidc_key_t *key;
    size_t                    hdr_len, payload_len, sig_len, der_len = 0, tbs_len;
    int64_t                   exp, nbf;
    EVP_MD_CTX               *md;
    int                       r;

    if (token == NULL) {
        return S3_SSH3_OIDC_EFORM;
    }

    p = token;
    end = token + s3_strlen(token);

    if ((size_t)(end - token) > S3_SSH3_OIDC_TOKEN_MAX) {
        return S3_SSH3_OIDC_EFORM;
    }

    /* the compact JWS: header.payload.signature, exactly two dots */

    dot1 = NULL;
    dot2 = NULL;

    for (; p < end; p++) {

        if (*p == '.') {

            if (dot1 == NULL) {
                dot1 = p;

            } else {
                dot2 = p;
                p++;
                break;
            }
        }
    }

    if (dot1 == NULL || dot2 == NULL || dot2 == dot1 + 1 || dot1 == token || p >= end ||
        memchr(p, '.', (size_t)(end - p)) != NULL) {
        return S3_SSH3_OIDC_EFORM;
    }

    if (s3_ssh3_oidc_b64url_decode((const u_char *)token, (size_t)(dot1 - token), hdr, &hdr_len) !=
        S3_OK) {
        return S3_SSH3_OIDC_EFORM;
    }

    if (s3_ssh3_oidc_b64url_decode((const u_char *)dot1 + 1, (size_t)(dot2 - dot1 - 1), payload,
                                   &payload_len) != S3_OK) {
        return S3_SSH3_OIDC_EFORM;
    }

    if (s3_ssh3_oidc_b64url_decode((const u_char *)dot2 + 1, (size_t)(end - dot2 - 1), sig,
                                   &sig_len) != S3_OK) {
        return S3_SSH3_OIDC_EFORM;
    }

    claims.data = payload;
    claims.len = payload_len;

    /* the header: the alg allowlist and the kid */

    {
        s3_str_t h;

        h.data = hdr;
        h.len = hdr_len;

        if (s3_ssh3_oidc_json_string(&h, "alg", alg, sizeof(alg)) != S3_OK ||
            s3_ssh3_oidc_json_string(&h, "kid", kid, sizeof(kid)) != S3_OK) {
            return S3_SSH3_OIDC_EFORM;
        }
    }

    if (s3_strcmp(alg, "RS256") != 0 && s3_strcmp(alg, "ES256") != 0) {
        /* the allowlist of the port: the provider-key families only */
        return S3_SSH3_OIDC_EALG;
    }

    /* the cheap claim gates first, like the go-oidc Verify */

    if (s3_ssh3_oidc_json_string(&claims, "iss", iss, sizeof(iss)) != S3_OK ||
        s3_strcmp(iss, issuer) != 0) {
        return S3_SSH3_OIDC_EISS;
    }

    if (s3_ssh3_oidc_json_aud_contains(&claims, audience) != S3_OK) {
        return S3_SSH3_OIDC_EAUD;
    }

    if (s3_ssh3_oidc_json_int(&claims, "exp", &exp) != S3_OK || (time_t)exp < now) {
        return S3_SSH3_OIDC_EEXP;
    }

    if (s3_ssh3_oidc_json_int(&claims, "nbf", &nbf) == S3_OK &&
        (int64_t)(now + S3_SSH3_OIDC_NBF_LEEWAY) < nbf) {
        return S3_SSH3_OIDC_EEXP;
    }

    if (nonce != NULL && nonce[0] != '\0') {

        if (s3_ssh3_oidc_json_string(&claims, "nonce", token_nonce, sizeof(token_nonce)) != S3_OK ||
            s3_strcmp(token_nonce, nonce) != 0) {
            return S3_SSH3_OIDC_ENONCE;
        }
    }

    /* the signature against the kid key closes */

    key = s3_oidc_keyset_find(jwks, kid);

    if (key == NULL) {
        return S3_SSH3_OIDC_EKID;
    }

    if ((key->ec && s3_strcmp(alg, "ES256") != 0) || (!key->ec && s3_strcmp(alg, "RS256") != 0)) {
        return S3_SSH3_OIDC_EALG;
    }

    if (key->ec) {

        if (sig_len != 64) {
            return S3_SSH3_OIDC_ESIG;
        }

        if (s3_oidc_ecdsa_raw_to_der(sig, 32, der, &der_len) != S3_OK) {
            return S3_SSH3_OIDC_ESIG;
        }
    }

    tbs_len = (size_t)(dot2 - token);

    md = EVP_MD_CTX_new();

    if (md == NULL) {
        return S3_ERROR;
    }

    r = EVP_DigestVerifyInit(md, NULL, EVP_sha256(), NULL, key->pkey);

    if (r == 1) {

        if (key->ec) {
            r = EVP_DigestVerify(md, der, der_len, (const u_char *)token, tbs_len);

        } else {
            r = EVP_DigestVerify(md, sig, sig_len, (const u_char *)token, tbs_len);
        }
    }

    EVP_MD_CTX_free(md);

    if (r != 1) {
        return S3_SSH3_OIDC_ESIG;
    }

    return S3_OK;
}

/* ------------------------------------------------------------------ */
/* the verifier (the discovery + the JWKS cache with the rotation)     */
/* ------------------------------------------------------------------ */

s3_int_t
s3_ssh3_oidc_verifier_init(s3_ssh3_oidc_verifier_t *v, const char *issuer, const char *ca_file)
{
    s3_memzero(v, sizeof(*v));

    if (issuer == NULL || s3_strlen(issuer) + 1 > sizeof(v->issuer)) {
        return S3_ERROR;
    }

    s3_memcpy(v->issuer, issuer, s3_strlen(issuer) + 1);

    if (ca_file != NULL && s3_strlen(ca_file) + 1 <= sizeof(v->ca_file)) {
        s3_memcpy(v->ca_file, ca_file, s3_strlen(ca_file) + 1);
    }

    return S3_OK;
}

s3_int_t
s3_ssh3_oidc_verifier_init_offline(s3_ssh3_oidc_verifier_t *v, const char *issuer)
{
    s3_int_t rc;

    rc = s3_ssh3_oidc_verifier_init(v, issuer, NULL);

    if (rc != S3_OK) {
        return rc;
    }

    /* the tests parse the key sets in by hand: no network */

    v->provider_ready = 1;

    return S3_OK;
}

static s3_int_t
s3_oidc_verifier_bootstrap(s3_ssh3_oidc_verifier_t *v)
{
    if (v->provider_ready) {
        return S3_OK;
    }

    if (v->issuer[0] == '\0') {
        return S3_ERROR;
    }

    if (s3_ssh3_oidc_discover(v->issuer, v->ca_file, &v->provider) != S3_OK) {
        return S3_ERROR;
    }

    if (s3_ssh3_oidc_jwks_fetch(&v->provider, v->ca_file, &v->jwks) != S3_OK) {
        return S3_ERROR;
    }

    v->provider_ready = 1;

    return S3_OK;
}

s3_int_t
s3_ssh3_oidc_verifier_verify(s3_ssh3_oidc_verifier_t *v, const char *audience, const char *token,
                             const char *nonce, time_t now)
{
    s3_int_t rc;

    rc = s3_oidc_verifier_bootstrap(v);

    if (rc != S3_OK) {
        return rc;
    }

    rc = s3_ssh3_oidc_verify(&v->jwks, v->issuer, audience, token, nonce, now);

    if (rc == S3_SSH3_OIDC_EKID && v->provider.jwks_uri[0] != '\0') {

        /* the unknown kid: one refresh picks the rotated provider key */

        if (s3_ssh3_oidc_jwks_fetch(&v->provider, v->ca_file, &v->jwks) == S3_OK) {
            rc = s3_ssh3_oidc_verify(&v->jwks, v->issuer, audience, token, nonce, now);
        }
    }

    return rc;
}

void
s3_ssh3_oidc_verifier_clear(s3_ssh3_oidc_verifier_t *v)
{
    s3_ssh3_oidc_jwks_clear(&v->jwks);
}

/* ------------------------------------------------------------------ */
/* the conversation nonce (the reference ConversationID)               */
/* ------------------------------------------------------------------ */

s3_int_t
s3_ssh3_oidc_conversation_nonce(SSL *ssl, char *out)
{
    u_char raw[32];
    int    n;

    /* the same exporter the fork GenerateConversationID() rides */

    if (SSL_export_keying_material(ssl, raw, sizeof(raw), "EXPORTER-SSH3",
                                   sizeof("EXPORTER-SSH3") - 1, NULL, 0, 0) != 1) {
        return S3_ERROR;
    }

    n = EVP_EncodeBlock((unsigned char *)out, raw, sizeof(raw));

    if (n != 44) {
        return S3_ERROR;
    }

    out[n] = '\0';

    return S3_OK;
}
