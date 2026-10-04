/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the ssh3 channel datagram codec (docs/P4-WIRE.md 3.2): varint
 * controlStreamID, varint channelID, the raw UDP payload without any
 * framing
 */

#include <s3_core.h>

#include <string.h>

#include <s3_ssh3_dgram.h>

#include "s3_test.h"

static int
s3_test_prefix_size(void)
{
    /* the 1-byte varints */

    S3_ASSERT(s3_ssh3_dgram_prefix_size(0, 0) == 2);
    S3_ASSERT(s3_ssh3_dgram_prefix_size(4, 8) == 2);

    /* the mixed forms: 1-byte + 2-byte (64 is the first 2-byte value) */

    S3_ASSERT(s3_ssh3_dgram_prefix_size(63, 64) == 3);

    /* both ids land in the 4-byte form: 16384 is the first value
     * above the 2-byte ceiling, 30000 is past it too */

    S3_ASSERT(s3_ssh3_dgram_prefix_size(16384, 30000) == 8);

    return s3_test_failures;
}

static int
s3_test_encode(void)
{
    u_char  buf[16];
    u_char *p;

    /* the prefix then the raw payload bytes */

    p = s3_ssh3_dgram_encode(buf, 4, 8, (const u_char *)"abcd", 4);

    S3_ASSERT(p == buf + 6);
    S3_ASSERT(s3_memcmp(buf, "\x04\x08\x61\x62\x63\x64", 6) == 0);

    /* data may be NULL when len is 0 */

    p = s3_ssh3_dgram_encode(buf, 4, 8, NULL, 0);

    S3_ASSERT(p == buf + 2);
    S3_ASSERT(buf[0] == 0x04 && buf[1] == 0x08);

    /* the 4-byte varint forms are written in full */

    p = s3_ssh3_dgram_encode(buf, 16384, 30000, NULL, 0);

    S3_ASSERT(p == buf + 8);
    S3_ASSERT(s3_memcmp(buf, "\x80\x00\x40\x00\x80\x00\x75\x30", 8) == 0);

    return s3_test_failures;
}

static int
s3_test_parse_roundtrip(void)
{
    static const u_char payload[] = {0x00, 0xa5, 0xff, 0x7f, 0x01};

    u_char        buf[32];
    u_char       *p;
    const u_char *pos, *end;
    uint64_t      control, channel;
    s3_str_t      out;

    /* the binary payload survives byte for byte, the view points
     * into the receive buffer and the cursor lands on end */

    p = s3_ssh3_dgram_encode(buf, 1073741824, 16384, payload, sizeof(payload));

    pos = buf;
    end = p;

    S3_ASSERT(s3_ssh3_dgram_parse(&pos, end, &control, &channel, &out) == S3_OK);
    S3_ASSERT(control == 1073741824);
    S3_ASSERT(channel == 16384);
    S3_ASSERT(out.len == sizeof(payload));
    S3_ASSERT(s3_memcmp(out.data, payload, sizeof(payload)) == 0);
    S3_ASSERT(pos == end);

    /* the empty payload is the prefix alone */

    p = s3_ssh3_dgram_encode(buf, 4, 8, NULL, 0);

    pos = buf;
    end = p;

    S3_ASSERT(s3_ssh3_dgram_parse(&pos, end, &control, &channel, &out) == S3_OK);
    S3_ASSERT(control == 4);
    S3_ASSERT(channel == 8);
    S3_ASSERT(out.len == 0);
    S3_ASSERT(pos == end);

    return s3_test_failures;
}

static int
s3_test_parse_payload_view(void)
{
    u_char        buf[32];
    u_char       *p;
    const u_char *pos, *end;
    uint64_t      control, channel;
    s3_str_t      out;

    /* the datagram is unframed: everything past the prefix is the
     * payload, extra bytes are not forbidden */

    p = s3_ssh3_dgram_encode(buf, 4, 8, (const u_char *)"hello", 5);

    pos = buf;
    end = p;

    S3_ASSERT(s3_ssh3_dgram_parse(&pos, end, &control, &channel, &out) == S3_OK);
    S3_ASSERT(out.len == 5);
    S3_ASSERT(s3_memcmp(out.data, "hello", 5) == 0);
    S3_ASSERT(pos == end);

    return s3_test_failures;
}

static int
s3_test_parse_truncated(void)
{
    u_char        buf[32];
    const u_char *pos, *end;
    uint64_t      control, channel;
    s3_str_t      out;
    size_t        i;

    s3_memzero(buf, sizeof(buf)); /* the -Wmaybe-uninitialized calm-down */

    /* the 8-byte prefix of {16384, 30000}: every short prefix is a
     * truncated buffer (the raw payload is unframed, only the prefix
     * can be told broken), the cursor stays put */

    (void)s3_ssh3_dgram_encode(buf, 16384, 30000, (const u_char *)"xyz", 3);

    for (i = 0; i < 8; i++) {
        pos = buf;
        end = buf + i;

        S3_ASSERT(s3_ssh3_dgram_parse(&pos, end, &control, &channel, &out) == S3_ERROR);
        S3_ASSERT(pos == buf);
    }

    /* the 2-byte prefix of {4, 8} truncates at lengths 0 and 1 */

    (void)s3_ssh3_dgram_encode(buf, 4, 8, NULL, 0);

    for (i = 0; i < 2; i++) {
        pos = buf;
        end = buf + i;

        S3_ASSERT(s3_ssh3_dgram_parse(&pos, end, &control, &channel, &out) == S3_ERROR);
        S3_ASSERT(pos == buf);
    }

    /* the empty buffer has no prefix at all */

    pos = buf;
    end = buf;

    S3_ASSERT(s3_ssh3_dgram_parse(&pos, end, &control, &channel, &out) == S3_ERROR);
    S3_ASSERT(pos == buf);

    return s3_test_failures;
}

static int
s3_test_ssh3_dgram(void)
{
    (void)s3_test_prefix_size();
    (void)s3_test_encode();
    (void)s3_test_parse_roundtrip();
    (void)s3_test_parse_payload_view();
    (void)s3_test_parse_truncated();

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_ssh3_dgram)
