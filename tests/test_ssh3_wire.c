/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the ssh3 wire primitives: the QUIC varint (RFC 9000, 16) and the
 * SSHString (varint length + raw bytes), the reference util/wire.go
 */

#include <s3_core.h>

#include <string.h>

#include <s3_ssh3_wire.h>

#include "s3_test.h"

static int
s3_test_varint_roundtrip(void)
{
    static const struct {
        uint64_t      value;
        const u_char *bytes;
        size_t        len;
    } vec[] = {
        {0, (const u_char *)"\x00", 1},
        {63, (const u_char *)"\x3f", 1},
        {64, (const u_char *)"\x40\x40", 2},
        {16383, (const u_char *)"\x7f\xff", 2},
        {16384, (const u_char *)"\x80\x00\x40\x00", 4},
        {1073741823, (const u_char *)"\xbf\xff\xff\xff", 4},
        {1073741824, (const u_char *)"\xc0\x00\x00\x00\x40\x00\x00\x00", 8},
        {4611686018427387903ULL, (const u_char *)"\xff\xff\xff\xff\xff\xff\xff\xff", 8},
    };

    u_char       buf[8];
    u_char      *p;
    const u_char *pos, *end;
    uint64_t     value;
    size_t       i;

    for (i = 0; i < sizeof(vec) / sizeof(vec[0]); i++) {

        /* the encoded size is announced before the value is written */

        S3_ASSERT(s3_ssh3_varint_size(vec[i].value) == vec[i].len);

        p = s3_ssh3_encode_varint(buf, vec[i].value);

        S3_ASSERT(p == buf + vec[i].len);
        S3_ASSERT(s3_memcmp(buf, vec[i].bytes, vec[i].len) == 0);

        pos = buf;
        end = buf + vec[i].len;

        S3_ASSERT(s3_ssh3_parse_varint(&pos, end, &value) == S3_OK);
        S3_ASSERT(value == vec[i].value);
        S3_ASSERT(pos == end);
    }

    return s3_test_failures;
}

static int
s3_test_varint_truncated(void)
{
    u_char        buf[8];
    const u_char *pos, *end;
    uint64_t      value;

    /* the length prefix promises more bytes than the buffer holds */

    s3_memcpy(buf, "\x40", 1); /* 2-byte form, 0 payload bytes */
    pos = buf;
    end = buf + 1;

    S3_ASSERT(s3_ssh3_parse_varint(&pos, end, &value) == S3_ERROR);

    s3_memcpy(buf, "\x80\x40", 2); /* 4-byte form, 1 payload byte */
    pos = buf;
    end = buf + 2;

    S3_ASSERT(s3_ssh3_parse_varint(&pos, end, &value) == S3_ERROR);

    s3_memcpy(buf, "\xc0\x40\x00\x00", 4); /* 8-byte form, 3 payload bytes */
    pos = buf;
    end = buf + 4;

    S3_ASSERT(s3_ssh3_parse_varint(&pos, end, &value) == S3_ERROR);

    /* the empty buffer has no length prefix at all */

    pos = buf;
    end = buf;

    S3_ASSERT(s3_ssh3_parse_varint(&pos, end, &value) == S3_ERROR);

    /* the failed parse must not advance the cursor */

    s3_memcpy(buf, "\x40\x40", 2);
    pos = buf;
    end = buf + 1;

    S3_ASSERT(s3_ssh3_parse_varint(&pos, end, &value) == S3_ERROR);
    S3_ASSERT(pos == buf);

    return s3_test_failures;
}

static int
s3_test_sshstring(void)
{
    u_char        buf[64];
    u_char       *p;
    const u_char *pos, *end;
    s3_str_t      out;

    /* a plain string: varint length then the raw bytes */

    p = s3_ssh3_encode_sshstring(buf, "ssh3-c", 6);

    S3_ASSERT(p == buf + 7);
    S3_ASSERT(buf[0] == 6);
    S3_ASSERT(s3_memcmp(buf + 1, "ssh3-c", 6) == 0);

    pos = buf;
    end = p;

    S3_ASSERT(s3_ssh3_parse_sshstring(&pos, end, &out) == S3_OK);
    S3_ASSERT(out.len == 6);
    S3_ASSERT(s3_memcmp(out.data, "ssh3-c", 6) == 0);
    S3_ASSERT(pos == end);

    /* the empty string is one zero byte, the view is zero-length */

    p = s3_ssh3_encode_sshstring(buf, "", 0);

    S3_ASSERT(p == buf + 1);
    S3_ASSERT(buf[0] == 0);

    pos = buf;
    end = p;

    S3_ASSERT(s3_ssh3_parse_sshstring(&pos, end, &out) == S3_OK);
    S3_ASSERT(out.len == 0);

    /* the encoded size matches s3_ssh3_sshstring_size() */

    S3_ASSERT(s3_ssh3_sshstring_size(6) == 7);
    S3_ASSERT(s3_ssh3_sshstring_size(0) == 1);
    S3_ASSERT(s3_ssh3_sshstring_size(200) == 202); /* the 2-byte varint form */

    /* binary payloads survive the round-trip */

    s3_memset(buf + 1, 0xa5, 40);

    p = s3_ssh3_encode_sshstring(buf, buf + 1, 40);

    S3_ASSERT(p == buf + 41);

    pos = buf;
    end = p;

    S3_ASSERT(s3_ssh3_parse_sshstring(&pos, end, &out) == S3_OK);
    S3_ASSERT(out.len == 40);
    S3_ASSERT(out.data[0] == 0xa5 && out.data[39] == 0xa5);

    return s3_test_failures;
}

static int
s3_test_sshstring_truncated(void)
{
    u_char        buf[16];
    const u_char *pos, *end;
    s3_str_t      out;

    /* the length prefix promises more bytes than the buffer holds */

    s3_memcpy(buf, "\xc8", 1); /* 200 promised, nothing follows */
    pos = buf;
    end = buf + 1;

    S3_ASSERT(s3_ssh3_parse_sshstring(&pos, end, &out) == S3_ERROR);

    s3_memcpy(buf, "\xc8\x61\x62", 3); /* 200 promised, 2 bytes follow */
    pos = buf;
    end = buf + 3;

    S3_ASSERT(s3_ssh3_parse_sshstring(&pos, end, &out) == S3_ERROR);

    /* no length prefix at all */

    pos = buf;
    end = buf;

    S3_ASSERT(s3_ssh3_parse_sshstring(&pos, end, &out) == S3_ERROR);

    return s3_test_failures;
}

static int
s3_test_ssh3_wire(void)
{
    (void) s3_test_varint_roundtrip();
    (void) s3_test_varint_truncated();
    (void) s3_test_sshstring();
    (void) s3_test_sshstring_truncated();

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_ssh3_wire)
