/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the target address extension of the direct and forwarded channel
 * headers (docs/P4-WIRE.md 2.1): varint addressFamily, the raw IP of
 * 4 or 16 bytes, the uint16 big-endian port
 */

#include <s3_core.h>

#include <string.h>

#include <s3_ssh3_forward.h>
#include <s3_ssh3_wire.h>

#include "s3_test.h"

static int
s3_test_forward_build(void)
{
    /* 127.0.0.1:19999, the known bytes of the wire form */

    static const u_char ipv4[] = {0x04, 0x7f, 0x00, 0x00, 0x01, 0x4e, 0x1f};

    /* [::1]:53, 15 zero bytes then the 1 */

    static const u_char ipv6[] = {0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x35};

    u_char                   buf[32];
    u_char                  *p;
    s3_ssh3_forward_target_t t;

    s3_memzero(&t, sizeof(t));

    t.family = 4;
    t.ip[0] = 127;
    t.ip[3] = 1;
    t.ip_len = 4;
    t.port = 19999;

    /* the size is the varint family, the ip and the two port bytes */

    S3_ASSERT(s3_ssh3_forward_target_size(&t) == 7);
    S3_ASSERT(s3_ssh3_forward_target_size(&t) == sizeof(ipv4));

    s3_memzero(buf, sizeof(buf));
    p = s3_ssh3_forward_build_target(buf, &t);

    S3_ASSERT(p == buf + 7);
    S3_ASSERT(p == buf + s3_ssh3_forward_target_size(&t));
    S3_ASSERT(s3_memcmp(buf, ipv4, sizeof(ipv4)) == 0);

    s3_memzero(&t, sizeof(t));

    t.family = 6;
    t.ip[15] = 1; /* ::1 */
    t.ip_len = 16;
    t.port = 53;

    S3_ASSERT(s3_ssh3_forward_target_size(&t) == 19);
    S3_ASSERT(s3_ssh3_forward_target_size(&t) == sizeof(ipv6));

    s3_memzero(buf, sizeof(buf));
    p = s3_ssh3_forward_build_target(buf, &t);

    S3_ASSERT(p == buf + 19);
    S3_ASSERT(p == buf + s3_ssh3_forward_target_size(&t));
    S3_ASSERT(s3_memcmp(buf, ipv6, sizeof(ipv6)) == 0);

    return s3_test_failures;
}

static int
s3_test_forward_parse_roundtrip(void)
{
    u_char                   buf[32];
    u_char                  *p;
    const u_char            *pos, *end;
    s3_ssh3_forward_target_t t, out;
    size_t                   len;

    /* 192.0.2.1:8080, the parse stops at the port, the sentinel byte
     * past the parsed region stays untouched */

    s3_memzero(&t, sizeof(t));

    t.family = 4;
    t.ip[0] = 192;
    t.ip[1] = 0;
    t.ip[2] = 2;
    t.ip[3] = 1;
    t.ip_len = 4;
    t.port = 8080;

    len = s3_ssh3_forward_target_size(&t);

    S3_ASSERT(len == 7);

    p = s3_ssh3_forward_build_target(buf, &t);

    S3_ASSERT(p == buf + len);

    buf[len] = 0xa5;

    s3_memzero(&out, sizeof(out));

    pos = buf;
    end = buf + len + 1;

    S3_ASSERT(s3_ssh3_forward_parse_target(&pos, end, &out) == S3_OK);
    S3_ASSERT(out.family == 4);
    S3_ASSERT(out.ip_len == 4);
    S3_ASSERT(s3_memcmp(out.ip, t.ip, 4) == 0);
    S3_ASSERT(out.port == 8080);
    S3_ASSERT(pos == buf + len);
    S3_ASSERT(buf[len] == 0xa5);

    /* [2001:db8::1]:443, the 16-byte ip and the port survive too */

    s3_memzero(&t, sizeof(t));

    t.family = 6;
    t.ip[0] = 0x20;
    t.ip[1] = 0x01;
    t.ip[2] = 0x0d;
    t.ip[3] = 0xb8;
    t.ip[15] = 1;
    t.ip_len = 16;
    t.port = 443;

    len = s3_ssh3_forward_target_size(&t);

    S3_ASSERT(len == 19);

    p = s3_ssh3_forward_build_target(buf, &t);

    S3_ASSERT(p == buf + len);

    buf[len] = 0xa5;

    s3_memzero(&out, sizeof(out));

    pos = buf;
    end = buf + len + 1;

    S3_ASSERT(s3_ssh3_forward_parse_target(&pos, end, &out) == S3_OK);
    S3_ASSERT(out.family == 6);
    S3_ASSERT(out.ip_len == 16);
    S3_ASSERT(s3_memcmp(out.ip, t.ip, 16) == 0);
    S3_ASSERT(out.port == 443);
    S3_ASSERT(pos == buf + len);
    S3_ASSERT(buf[len] == 0xa5);

    return s3_test_failures;
}

static int
s3_test_forward_parse_family(void)
{
    u_char                   buf[32];
    const u_char            *pos, *end;
    s3_ssh3_forward_target_t out;

    s3_memzero(buf, sizeof(buf));

    /* the family 5 does not exist on the wire, the cursor stays put
     * even though the rest of the target follows */

    s3_memcpy(buf, "\x05\x7f\x00\x00\x01\x4e\x1f", 7);
    pos = buf;
    end = buf + 7;

    S3_ASSERT(s3_ssh3_forward_parse_target(&pos, end, &out) == S3_ERROR);
    S3_ASSERT(pos == buf);

    /* the same with nothing but the family byte in the buffer */

    pos = buf;
    end = buf + 1;

    S3_ASSERT(s3_ssh3_forward_parse_target(&pos, end, &out) == S3_ERROR);
    S3_ASSERT(pos == buf);

    /* the family 6 promises 16 ip bytes, the 4-byte buffer lies */

    s3_memcpy(buf, "\x06\x7f\x00\x00\x01", 5);
    pos = buf;
    end = buf + 5;

    S3_ASSERT(s3_ssh3_forward_parse_target(&pos, end, &out) == S3_ERROR);
    S3_ASSERT(pos == buf);

    return s3_test_failures;
}

static int
s3_test_forward_parse_truncated(void)
{
    u_char                   buf[32];
    const u_char            *pos, *end;
    s3_ssh3_forward_target_t t, out;
    size_t                   len, i;

    /* the full ipv4 target is 7 bytes: every shorter prefix must fail
     * without moving the cursor */

    s3_memzero(&t, sizeof(t));

    t.family = 4;
    t.ip[0] = 192;
    t.ip[1] = 0;
    t.ip[2] = 2;
    t.ip[3] = 1;
    t.ip_len = 4;
    t.port = 8080;

    len = s3_ssh3_forward_target_size(&t);

    S3_ASSERT(len == 7);

    (void)s3_ssh3_forward_build_target(buf, &t);

    for (i = 0; i < len; i++) {
        pos = buf;
        end = buf + i;

        S3_ASSERT(s3_ssh3_forward_parse_target(&pos, end, &out) == S3_ERROR);
        S3_ASSERT(pos == buf);
    }

    /* the full ipv6 target is 19 bytes, the same every-prefix walk */

    s3_memzero(&t, sizeof(t));

    t.family = 6;
    t.ip[15] = 1;
    t.ip_len = 16;
    t.port = 53;

    len = s3_ssh3_forward_target_size(&t);

    S3_ASSERT(len == 19);

    (void)s3_ssh3_forward_build_target(buf, &t);

    for (i = 0; i < len; i++) {
        pos = buf;
        end = buf + i;

        S3_ASSERT(s3_ssh3_forward_parse_target(&pos, end, &out) == S3_ERROR);
        S3_ASSERT(pos == buf);
    }

    return s3_test_failures;
}

static int
s3_test_ssh3_forward(void)
{
    (void)s3_test_forward_build();
    (void)s3_test_forward_parse_roundtrip();
    (void)s3_test_forward_parse_family();
    (void)s3_test_forward_parse_truncated();

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_ssh3_forward)
