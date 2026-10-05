/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the ssh3 wire primitives, the reference util/wire.go
 */

#include <s3_core.h>

#include <string.h>

#include <s3_ssh3_wire.h>

#define S3_SSH3_VARINT_1_MAX 63ULL
#define S3_SSH3_VARINT_2_MAX 16383ULL
#define S3_SSH3_VARINT_4_MAX 1073741823ULL
#define S3_SSH3_VARINT_8_MAX 4611686018427387903ULL

size_t
s3_ssh3_varint_size(uint64_t value)
{
    if (value <= S3_SSH3_VARINT_1_MAX) {
        return 1;
    }

    if (value <= S3_SSH3_VARINT_2_MAX) {
        return 2;
    }

    if (value <= S3_SSH3_VARINT_4_MAX) {
        return 4;
    }

    /* the encoding itself caps at 62 bits: the two high bits of the
     * first byte are the length marker */

    return 8;
}

u_char *
s3_ssh3_encode_varint(u_char *p, uint64_t value)
{
    if (value <= S3_SSH3_VARINT_1_MAX) {
        *p++ = (u_char)value;

    } else if (value <= S3_SSH3_VARINT_2_MAX) {
        *p++ = (u_char)((value >> 8) | 0x40);
        *p++ = (u_char)value;

    } else if (value <= S3_SSH3_VARINT_4_MAX) {
        *p++ = (u_char)((value >> 24) | 0x80);
        *p++ = (u_char)(value >> 16);
        *p++ = (u_char)(value >> 8);
        *p++ = (u_char)value;

    } else {
        *p++ = (u_char)((value >> 56) | 0xc0);
        *p++ = (u_char)(value >> 48);
        *p++ = (u_char)(value >> 40);
        *p++ = (u_char)(value >> 32);
        *p++ = (u_char)(value >> 24);
        *p++ = (u_char)(value >> 16);
        *p++ = (u_char)(value >> 8);
        *p++ = (u_char)value;
    }

    return p;
}

s3_int_t
s3_ssh3_parse_varint(const u_char **pos, const u_char *end, uint64_t *value)
{
    const u_char *p = *pos;
    size_t        form, len;
    uint64_t      v;

    if (end - p < 1) {
        return S3_ERROR;
    }

    form = (size_t)1 << ((*p & 0xc0) >> 6);

    if ((size_t)(end - p) < form) {
        return S3_ERROR;
    }

    len = form;
    v = (uint64_t)(*p++ & 0x3f);

    while (--len > 0) {
        v = (v << 8) | (uint64_t)*p++;
    }

    /* the canonical form only: a value that fits a shorter encoding
     * is a wire violation, the reference Go encoder never produces
     * it (quicvarint.Append) and QUIC makes the shortest encoding a
     * MUST for frame types (RFC 9000, 12.4) */

    if (form > s3_ssh3_varint_size(v)) {
        return S3_ERROR;
    }

    *pos = p;
    *value = v;

    return S3_OK;
}

size_t
s3_ssh3_sshstring_size(size_t len)
{
    return s3_ssh3_varint_size((uint64_t)len) + len;
}

u_char *
s3_ssh3_encode_sshstring(u_char *p, const void *data, size_t len)
{
    p = s3_ssh3_encode_varint(p, (uint64_t)len);

    if (len > 0) {
        p = (u_char *)s3_cpymem(p, data, len);
    }

    return p;
}

s3_int_t
s3_ssh3_parse_sshstring(const u_char **pos, const u_char *end, s3_str_t *out)
{
    const u_char *p = *pos;
    uint64_t      len;

    if (s3_ssh3_parse_varint(&p, end, &len) != S3_OK) {
        return S3_ERROR;
    }

    if ((uint64_t)(end - p) < len) {
        return S3_ERROR;
    }

    out->data = (u_char *)p;
    out->len = (size_t)len;

    *pos = p + len;

    return S3_OK;
}
