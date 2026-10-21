/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the ssh3 version-string parser and the support verdict, the port of
 * the reference version.go (ParseVersionString, ParseProtocolVersion,
 * ParseSoftwareVersion, IsVersionSupported)
 */

#include <s3_core.h>

#include <string.h>

#include <s3_ssh3_version.h>

#include <s3_ssh3_compress.h>

/*
 * the component numbers are digits only, no sign latitude (the
 * reference Atoi accepts "-1"; a negative version component is
 * nonsense, the strict parse rejects the field as a whole)
 */

#define S3_SSH3_VERSION_COMPONENT_MAX_DIGITS 5
#define S3_SSH3_VERSION_FIELDS_MAX           8

static const u_char s3_ssh3_legacy_implementation[] = "francoismichel/ssh3";

static s3_uint_t
s3_ssh3_version_digits(const u_char *data, size_t len, unsigned *value)
{
    size_t n;

    if (len == 0 || len > S3_SSH3_VERSION_COMPONENT_MAX_DIGITS) {
        return 0;
    }

    *value = 0;

    for (n = 0; n < len; n++) {

        if (data[n] < '0' || data[n] > '9') {
            return 0;
        }

        *value = *value * 10 + (unsigned)(data[n] - '0');
    }

    return 1;
}

/* exactly two numeric components: "major.minor" */

static s3_int_t
s3_ssh3_version_split_dot2(const u_char *data, size_t len, unsigned *major, unsigned *minor)
{
    const u_char *dot;

    dot = memchr(data, '.', len);

    if (dot == NULL || memchr(dot + 1, '.', len - (dot - data) - 1) != NULL) {
        return S3_ERROR;
    }

    if (!s3_ssh3_version_digits(data, dot - data, major)) {
        return S3_ERROR;
    }

    if (!s3_ssh3_version_digits(dot + 1, len - (dot - data) - 1, minor)) {
        return S3_ERROR;
    }

    return S3_OK;
}

/*
 * the protocol field: "major.minor" or "major.minor_<spec>"; the spec
 * part carries no further underscore (the reference splits on all of
 * them and rejects three-part results), an empty spec is rejected
 * (stricter than the reference, which reads "3.0_" as no spec)
 */
static s3_int_t
s3_ssh3_version_protocol(const u_char *data, size_t len, s3_ssh3_version_t *v)
{
    const u_char *underscore;
    size_t        plen;

    underscore = memchr(data, '_', len);

    if (underscore != NULL) {

        plen = underscore - data;

        if (plen + 1 == len) { /* the spec itself is empty */
            return S3_ERROR;
        }

        if (memchr(underscore + 1, '_', len - plen - 1) != NULL) {
            return S3_ERROR;
        }

        v->spec_version.data = (u_char *)underscore + 1;
        v->spec_version.len = len - plen - 1;

    } else {
        plen = len;
    }

    return s3_ssh3_version_split_dot2(data, plen, &v->protocol_major, &v->protocol_minor);
}

/* exactly three numeric components: "major.minor.patch" */

static s3_int_t
s3_ssh3_version_software(const u_char *data, size_t len, s3_ssh3_version_t *v)
{
    const u_char *dot, *next;
    size_t        left;

    dot = memchr(data, '.', len);

    if (dot == NULL) {
        return S3_ERROR;
    }

    if (!s3_ssh3_version_digits(data, dot - data, &v->software_major)) {
        return S3_ERROR;
    }

    left = len - (dot - data) - 1;

    next = memchr(dot + 1, '.', left);

    if (next == NULL) {
        return S3_ERROR;
    }

    if (!s3_ssh3_version_digits(dot + 1, next - dot - 1, &v->software_minor)) {
        return S3_ERROR;
    }

    left = len - (next - data) - 1;

    if (memchr(next + 1, '.', left) != NULL) {
        return S3_ERROR;
    }

    if (!s3_ssh3_version_digits(next + 1, left, &v->software_patch)) {
        return S3_ERROR;
    }

    return S3_OK;
}

s3_int_t
s3_ssh3_version_parse(const u_char *data, size_t len, s3_ssh3_version_t *v)
{
    const u_char *p, *end, *field[S3_SSH3_VERSION_FIELDS_MAX];
    size_t        flen[S3_SSH3_VERSION_FIELDS_MAX], n, nfield;
    s3_str_t      extra;

    static const s3_str_t spec_key = s3_string("experimental_spec_version=");
    static const s3_str_t compress_key = s3_string(S3_SSH3_COMPRESS_KEY);

    p = data;
    end = data + len;

    nfield = 0;

    v->compress_mask = 0;

    while (p < end && nfield < S3_SSH3_VERSION_FIELDS_MAX) {

        while (p < end && (*p == ' ' || *p == '\t')) {
            p++;
        }

        if (p == end) {
            break;
        }

        field[nfield] = p;

        while (p < end && *p != ' ' && *p != '\t') {
            p++;
        }

        flen[nfield] = p - field[nfield];
        nfield++;
    }

    /*
     * the fields beyond the cap are dropped: only
     * experimental_spec_version matters among the extras, and a peer
     * sending eight-plus fields is already off-spec
     */

    if (nfield < 4) {
        return S3_ERROR;
    }

    /* the protocol name is announced but not matched: the reference
     * notes the name is subject to change */

    if (s3_ssh3_version_protocol(field[1], flen[1], v) != S3_OK) {
        return S3_ERROR;
    }

    v->implementation.data = (u_char *)field[2];
    v->implementation.len = flen[2];

    if (s3_ssh3_version_software(field[3], flen[3], v) != S3_OK) {
        return S3_ERROR;
    }

    for (n = 4; n < nfield; n++) {

        extra.data = (u_char *)field[n];
        extra.len = flen[n];

        if (extra.len > spec_key.len &&
            s3_memcmp(extra.data, spec_key.data, spec_key.len) == 0) {

            v->spec_version.data = extra.data + spec_key.len;
            v->spec_version.len = extra.len - spec_key.len;

            continue;
        }

        /*
         * the compression capability (PLAN.md 9, B8): the peer tells
         * which algorithms it can decode with, and the field rides the
         * version string, whose unknown fields every peer skips
         */

        if (extra.len > compress_key.len &&
            s3_memcmp(extra.data, compress_key.data, compress_key.len) == 0) {

            v->compress_mask = s3_ssh3_compress_parse(extra.data + compress_key.len,
                                                       extra.len - compress_key.len);
        }
    }

    return S3_OK;
}

size_t
s3_ssh3_version_string(u_char *buf, size_t cap)
{
    static const char *base = S3_SSH3_VERSION_STRING;

    size_t   len = s3_strlen(base);
    u_char   cap_buf[64];
    size_t   cap_len;

    if (cap < len) {
        return 0;
    }

    s3_memcpy(buf, base, len);

    /* the capability field: the runtime form, the list depends on the
     * compiled-in codecs; a build without a codec announces nothing and
     * the field is omitted */

    cap_len = s3_ssh3_compress_capability(cap_buf, sizeof(cap_buf));

    if (cap_len == 0) {
        return len;
    }

    if (cap < len + 1 + sizeof(S3_SSH3_COMPRESS_KEY) - 1 + cap_len) {
        return len;
    }

    buf[len++] = ' ';
    s3_memcpy(buf + len, S3_SSH3_COMPRESS_KEY, sizeof(S3_SSH3_COMPRESS_KEY) - 1);
    len += sizeof(S3_SSH3_COMPRESS_KEY) - 1;
    s3_memcpy(buf + len, cap_buf, cap_len);
    len += cap_len;

    return len;
}

s3_int_t
s3_ssh3_version_supported(const s3_ssh3_version_t *v)
{
    /* strict protocol version checking */

    if (v->protocol_major != S3_SSH3_PROTOCOL_MAJOR ||
        v->protocol_minor != S3_SSH3_PROTOCOL_MINOR) {
        return S3_DECLINED;
    }

    /*
     * the legacy reference releases announce no spec version: accept
     * francoismichel/ssh3 0.1.3..0.1.5 and nothing else without one
     */

    if (v->spec_version.len == 0) {

        if (v->implementation.len != s3_strlen(s3_ssh3_legacy_implementation) ||
            s3_memcmp(v->implementation.data, s3_ssh3_legacy_implementation,
                      v->implementation.len) != 0) {
            return S3_DECLINED;
        }

        if (v->software_major != 0 || v->software_minor != 1 || v->software_patch > 5) {
            return S3_DECLINED;
        }

        return (v->software_patch >= 3) ? S3_OK : S3_DECLINED;
    }

    /* this endpoint speaks exactly one experimental spec version */

    if (v->spec_version.len != s3_strlen(S3_SSH3_SPEC_VERSION) ||
        s3_memcmp(v->spec_version.data, S3_SSH3_SPEC_VERSION, v->spec_version.len) != 0) {
        return S3_DECLINED;
    }

    return S3_OK;
}
