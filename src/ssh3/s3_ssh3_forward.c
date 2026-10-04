/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the target address extension of the direct and forwarded channel
 * headers (docs/P4-WIRE.md 2.1), the reference channel.go
 * buildForwardingChannelAdditionalBytes/parseForwardingHeader
 */

#include <s3_core.h>

#include <s3_ssh3_forward.h>
#include <s3_ssh3_wire.h>

#define S3_SSH3_FORWARD_IPV4_LEN 4
#define S3_SSH3_FORWARD_IPV6_LEN 16

size_t
s3_ssh3_forward_target_size(const s3_ssh3_forward_target_t *t)
{
    return s3_ssh3_varint_size((uint64_t)t->family) + t->ip_len + 2;
}

u_char *
s3_ssh3_forward_build_target(u_char *p, const s3_ssh3_forward_target_t *t)
{
    p = s3_ssh3_encode_varint(p, (uint64_t)t->family);
    p = s3_cpymem(p, t->ip, t->ip_len);

    /* the port is the uint16 big-endian */

    *p++ = (u_char)(t->port >> 8);
    *p++ = (u_char)t->port;

    return p;
}

s3_int_t
s3_ssh3_forward_parse_target(const u_char **pos, const u_char *end, s3_ssh3_forward_target_t *t)
{
    const u_char *p = *pos;
    uint64_t      family;
    size_t        ip_len;

    if (s3_ssh3_parse_varint(&p, end, &family) != S3_OK) {
        return S3_ERROR;
    }

    /* the family is the only length promise on the wire: the ip is 4
     * or 16 raw bytes, anything else does not exist */

    if (family == 4) {
        ip_len = S3_SSH3_FORWARD_IPV4_LEN;

    } else if (family == 6) {
        ip_len = S3_SSH3_FORWARD_IPV6_LEN;

    } else {
        return S3_ERROR;
    }

    /* the ip and the two port bytes must fit into the buffer */

    if ((size_t)(end - p) < ip_len + 2) {
        return S3_ERROR;
    }

    t->family = (unsigned)family;
    t->ip_len = ip_len;

    /* s3_cpymem() returns the destination advanced: the cursor is the
     * source here, so the plain copy and the manual step */

    s3_memcpy(t->ip, p, ip_len);
    p += ip_len;

    t->port = (uint16_t)(((unsigned)p[0] << 8) | p[1]);
    p += 2;

    *pos = p;

    return S3_OK;
}
