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

    u_char        buf[8];
    u_char       *p;
    const u_char *pos, *end;
    uint64_t      value;
    size_t        i;

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

    /* the whole buffer is zeroed first: gcc cannot prove the opaque
     * parse reads only the live prefix and warns on the untouched tail
     * otherwise (-Wmaybe-uninitialized, gcc 13.3 false positive) */

    s3_memzero(buf, sizeof(buf));

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

/*
 * the receiver rejects over-long varint encodings: every form must
 * carry the smallest value its length marker admits, the canonical
 * ranges are 0..63 for 1 byte, 64..16383 for 2 bytes, 16384..2^30-1
 * for 4 bytes and 2^30..2^62-1 for 8 bytes (the reference Go encoder
 * always emits the minimal form, see quicvarint.Append)
 */

static int
s3_test_varint_canonical(void)
{
    static const struct {
        const u_char *bytes;
        size_t        len;
        s3_int_t      want; /* S3_OK: canonical, S3_ERROR: over-long */
    } vec[] = {
        /* the 1-byte form is always canonical */
        {(const u_char *)"\x00", 1, S3_OK},
        {(const u_char *)"\x2a", 1, S3_OK},
        {(const u_char *)"\x3f", 1, S3_OK},

        /* the 2-byte form is canonical from 64 up */
        {(const u_char *)"\x40\x00", 2, S3_ERROR}, /* 0 padded */
        {(const u_char *)"\x40\x3f", 2, S3_ERROR}, /* 63 padded */
        {(const u_char *)"\x40\x40", 2, S3_OK},    /* 64, the first 2-byte value */
        {(const u_char *)"\x5f\xff", 2, S3_OK},    /* 8191 */
        {(const u_char *)"\x7f\xff", 2, S3_OK},    /* 16383 */

        /* the 4-byte form is canonical from 2^14 up */
        {(const u_char *)"\x80\x00\x00\x00", 4, S3_ERROR}, /* 0 padded */
        {(const u_char *)"\x80\x00\x3f\xff", 4, S3_ERROR}, /* 16383 padded */
        {(const u_char *)"\x80\x00\x40\x00", 4, S3_OK},    /* 16384 */
        {(const u_char *)"\xbf\xff\xff\xff", 4, S3_OK},    /* 2^30-1 */

        /* the 8-byte form is canonical from 2^30 up */
        {(const u_char *)"\xc0\x00\x00\x00\x00\x00\x00\x00", 8, S3_ERROR}, /* 0 padded */
        {(const u_char *)"\xc0\x00\x00\x00\x00\x00\x00\x01", 8, S3_ERROR}, /* 1 padded */
        {(const u_char *)"\xc0\x00\x00\x00\x3f\xff\xff\xff", 8, S3_ERROR}, /* 2^30-1 padded */
        {(const u_char *)"\xc0\x00\x00\x00\x40\x00\x00\x00", 8, S3_OK},    /* 2^30 */
        {(const u_char *)"\xff\xff\xff\xff\xff\xff\xff\xff", 8, S3_OK},    /* 2^62-1 */
    };

    u_char        buf[8];
    const u_char *pos, *end;
    uint64_t      value;
    size_t        i;

    s3_memzero(buf, sizeof(buf));

    for (i = 0; i < sizeof(vec) / sizeof(vec[0]); i++) {

        s3_memcpy(buf, vec[i].bytes, vec[i].len);

        pos = buf;
        end = buf + vec[i].len;

        S3_ASSERT(s3_ssh3_parse_varint(&pos, end, &value) == vec[i].want);

        if (vec[i].want == S3_OK) {
            S3_ASSERT(pos == end);
        }
    }

    /* a truncated buffer stays an error before the form is judged */

    s3_memcpy(buf, "\x40", 1); /* the 2-byte form cut to 1 byte */
    pos = buf;
    end = buf + 1;

    S3_ASSERT(s3_ssh3_parse_varint(&pos, end, &value) == S3_ERROR);

    s3_memcpy(buf, "\x80\x00\x40", 3); /* the 4-byte form cut to 3 bytes */
    pos = buf;
    end = buf + 3;

    S3_ASSERT(s3_ssh3_parse_varint(&pos, end, &value) == S3_ERROR);

    s3_memcpy(buf, "\xc0\x00\x00\x00\x40\x00\x00", 7); /* the 8-byte cut to 7 */
    pos = buf;
    end = buf + 7;

    S3_ASSERT(s3_ssh3_parse_varint(&pos, end, &value) == S3_ERROR);

    /* the over-long reject must not advance the cursor either */

    s3_memcpy(buf, "\x40\x00", 2);
    pos = buf;
    end = buf + 2;

    S3_ASSERT(s3_ssh3_parse_varint(&pos, end, &value) == S3_ERROR);
    S3_ASSERT(pos == buf);

    return s3_test_failures;
}

/*
 * the SSHString length goes through the same varint rules: the
 * canonical form parses, the padded length prefix is rejected
 */

static int
s3_test_sshstring_canonical(void)
{
    u_char        buf[202];
    u_char        src[200];
    u_char       *p;
    const u_char *pos, *end;
    s3_str_t      out;

    s3_memzero(buf, sizeof(buf));

    /* zero length padded to the 2-byte form */

    s3_memcpy(buf, "\x40\x00", 2);
    pos = buf;
    end = buf + 2;

    S3_ASSERT(s3_ssh3_parse_sshstring(&pos, end, &out) == S3_ERROR);

    /* six bytes of payload padded to the 2-byte length form */

    s3_memcpy(buf, "\x40\x06ssh3-c", 8);
    pos = buf;
    end = buf + 8;

    S3_ASSERT(s3_ssh3_parse_sshstring(&pos, end, &out) == S3_ERROR);

    /* the minimal 2-byte length form of 200 still parses */

    s3_memset(src, 0xa5, sizeof(src));
    p = s3_ssh3_encode_sshstring(buf, src, sizeof(src));

    S3_ASSERT(p == buf + 202);

    pos = buf;
    end = p;

    S3_ASSERT(s3_ssh3_parse_sshstring(&pos, end, &out) == S3_OK);
    S3_ASSERT(out.len == 200);
    S3_ASSERT(out.data[0] == 0xa5 && out.data[199] == 0xa5);

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

    s3_memzero(buf, sizeof(buf)); /* the -Wmaybe-uninitialized calm-down */

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
    (void)s3_test_varint_roundtrip();
    (void)s3_test_varint_truncated();
    (void)s3_test_varint_canonical();
    (void)s3_test_sshstring();
    (void)s3_test_sshstring_canonical();
    (void)s3_test_sshstring_truncated();

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_ssh3_wire)
