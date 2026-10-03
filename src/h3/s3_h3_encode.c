
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <s3_h3_encode.h>

static size_t s3_h3_huff_encode(u_char *data, size_t len, u_char *dst, s3_uint_t lower);
static void   s3_h3_strlow(u_char *dst, u_char *src, size_t n);

/*
 * ssh3-c: the huffman encoder is out of the P3 minimum scope; the stub
 * keeps the reference control flow and forces the literal (raw)
 * encoding, which is always a valid QPACK encoding
 */
static size_t
s3_h3_huff_encode(u_char *data, size_t len, u_char *dst, s3_uint_t lower)
{
    (void)data;
    (void)len;
    (void)dst;
    (void)lower;

    return 0;
}

/* ssh3-c: ngx_strlow() equivalent, the kernel has no string helper */
static void
s3_h3_strlow(u_char *dst, u_char *src, size_t n)
{
    while (n) {
        *dst++ = (u_char)((*src >= 'A' && *src <= 'Z') ? (*src | 0x20) : *src);
        src++;
        n--;
    }
}

uintptr_t
s3_h3_encode_varlen_int(u_char *p, uint64_t value)
{
    if (value <= 63) {
        if (p == NULL) {
            return 1;
        }

        *p++ = value;
        return (uintptr_t)p;
    }

    if (value <= 16383) {
        if (p == NULL) {
            return 2;
        }

        *p++ = 0x40 | (value >> 8);
        *p++ = value;
        return (uintptr_t)p;
    }

    if (value <= 1073741823) {
        if (p == NULL) {
            return 4;
        }

        *p++ = 0x80 | (value >> 24);
        *p++ = (value >> 16);
        *p++ = (value >> 8);
        *p++ = value;
        return (uintptr_t)p;
    }

    if (p == NULL) {
        return 8;
    }

    *p++ = 0xc0 | (value >> 56);
    *p++ = (value >> 48);
    *p++ = (value >> 40);
    *p++ = (value >> 32);
    *p++ = (value >> 24);
    *p++ = (value >> 16);
    *p++ = (value >> 8);
    *p++ = value;
    return (uintptr_t)p;
}

uintptr_t
s3_h3_encode_prefix_int(u_char *p, uint64_t value, s3_uint_t prefix)
{
    s3_uint_t thresh, n;

    thresh = (1 << prefix) - 1;

    if (value < thresh) {
        if (p == NULL) {
            return 1;
        }

        *p++ |= value;
        return (uintptr_t)p;
    }

    value -= thresh;

    if (p == NULL) {
        for (n = 2; value >= 128; n++) {
            value >>= 7;
        }

        return n;
    }

    *p++ |= thresh;

    while (value >= 128) {
        *p++ = 0x80 | value;
        value >>= 7;
    }

    *p++ = value;

    return (uintptr_t)p;
}

uintptr_t
s3_h3_encode_field_section_prefix(u_char *p, s3_uint_t insert_count, s3_uint_t sign,
                                  s3_uint_t delta_base)
{
    if (p == NULL) {
        return s3_h3_encode_prefix_int(NULL, insert_count, 8) +
               s3_h3_encode_prefix_int(NULL, delta_base, 7);
    }

    *p = 0;
    p = (u_char *)s3_h3_encode_prefix_int(p, insert_count, 8);

    *p = sign ? 0x80 : 0;
    p = (u_char *)s3_h3_encode_prefix_int(p, delta_base, 7);

    return (uintptr_t)p;
}

uintptr_t
s3_h3_encode_field_ri(u_char *p, s3_uint_t dynamic, s3_uint_t index)
{
    /* Indexed Field Line */

    if (p == NULL) {
        return s3_h3_encode_prefix_int(NULL, index, 6);
    }

    *p = dynamic ? 0x80 : 0xc0;

    return s3_h3_encode_prefix_int(p, index, 6);
}

uintptr_t
s3_h3_encode_field_lri(u_char *p, s3_uint_t dynamic, s3_uint_t index, u_char *data, size_t len)
{
    size_t  hlen;
    u_char *p1, *p2;

    /* Literal Field Line With Name Reference */

    if (p == NULL) {
        return s3_h3_encode_prefix_int(NULL, index, 4) + s3_h3_encode_prefix_int(NULL, len, 7) +
               len;
    }

    *p = dynamic ? 0x40 : 0x50;
    p = (u_char *)s3_h3_encode_prefix_int(p, index, 4);

    p1 = p;
    *p = 0;
    p = (u_char *)s3_h3_encode_prefix_int(p, len, 7);

    if (data) {
        p2 = p;
        hlen = s3_h3_huff_encode(data, len, p, 0);

        if (hlen) {
            p = p1;
            *p = 0x80;
            p = (u_char *)s3_h3_encode_prefix_int(p, hlen, 7);

            if (p != p2) {
                s3_memmove(p, p2, hlen);
            }

            p += hlen;

        } else {
            p = s3_cpymem(p, data, len);
        }
    }

    return (uintptr_t)p;
}

uintptr_t
s3_h3_encode_field_l(u_char *p, s3_str_t *name, s3_str_t *value)
{
    size_t  hlen;
    u_char *p1, *p2;

    /* Literal Field Line With Literal Name */

    if (p == NULL) {
        return s3_h3_encode_prefix_int(NULL, name->len, 3) + name->len +
               s3_h3_encode_prefix_int(NULL, value->len, 7) + value->len;
    }

    p1 = p;
    *p = 0x20;
    p = (u_char *)s3_h3_encode_prefix_int(p, name->len, 3);

    p2 = p;
    hlen = s3_h3_huff_encode(name->data, name->len, p, 1);

    if (hlen) {
        p = p1;
        *p = 0x28;
        p = (u_char *)s3_h3_encode_prefix_int(p, hlen, 3);

        if (p != p2) {
            s3_memmove(p, p2, hlen);
        }

        p += hlen;

    } else {
        s3_h3_strlow(p, name->data, name->len);
        p += name->len;
    }

    p1 = p;
    *p = 0;
    p = (u_char *)s3_h3_encode_prefix_int(p, value->len, 7);

    p2 = p;
    hlen = s3_h3_huff_encode(value->data, value->len, p, 0);

    if (hlen) {
        p = p1;
        *p = 0x80;
        p = (u_char *)s3_h3_encode_prefix_int(p, hlen, 7);

        if (p != p2) {
            s3_memmove(p, p2, hlen);
        }

        p += hlen;

    } else {
        p = s3_cpymem(p, value->data, value->len);
    }

    return (uintptr_t)p;
}

uintptr_t
s3_h3_encode_field_pbi(u_char *p, s3_uint_t index)
{
    /* Indexed Field Line With Post-Base Index */

    if (p == NULL) {
        return s3_h3_encode_prefix_int(NULL, index, 4);
    }

    *p = 0x10;

    return s3_h3_encode_prefix_int(p, index, 4);
}

uintptr_t
s3_h3_encode_field_lpbi(u_char *p, s3_uint_t index, u_char *data, size_t len)
{
    size_t  hlen;
    u_char *p1, *p2;

    /* Literal Field Line With Post-Base Name Reference */

    if (p == NULL) {
        return s3_h3_encode_prefix_int(NULL, index, 3) + s3_h3_encode_prefix_int(NULL, len, 7) +
               len;
    }

    *p = 0;
    p = (u_char *)s3_h3_encode_prefix_int(p, index, 3);

    p1 = p;
    *p = 0;
    p = (u_char *)s3_h3_encode_prefix_int(p, len, 7);

    if (data) {
        p2 = p;
        hlen = s3_h3_huff_encode(data, len, p, 0);

        if (hlen) {
            p = p1;
            *p = 0x80;
            p = (u_char *)s3_h3_encode_prefix_int(p, hlen, 7);

            if (p != p2) {
                s3_memmove(p, p2, hlen);
            }

            p += hlen;

        } else {
            p = s3_cpymem(p, data, len);
        }
    }

    return (uintptr_t)p;
}
