/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the ssh3 channel header (docs/P4-WIRE.md 2.1) and the data chunk
 * accounting, the reference channel.go buildHeader/parseHeader/WriteData
 */

#include <s3_core.h>

#include <string.h>

#include <s3_ssh3_channel.h>
#include <s3_ssh3_wire.h>

#include "s3_test.h"

static void
s3_channel_init(s3_ssh3_channel_t *ch, const char *type, uint64_t conversation_stream_id,
                uint64_t max_packet_size)
{
    s3_memzero(ch, sizeof(*ch));

    /* s3_str_set() is the literal-only sizeof form, the parameter
     * needs the runtime strlen */

    ch->type.len = s3_strlen(type);
    ch->type.data = (u_char *)type;

    ch->conversation_stream_id = conversation_stream_id;
    ch->max_packet_size = max_packet_size;
}

static int
s3_test_channel_build(void)
{
    /* varint 0xaf3627e6 is the 8-byte form (2940133862 > 2^30 - 1),
     * varint 0 and the "session" length are the 1-byte forms, varint
     * 30000 is the 4-byte form: 8 + 1 + 8 + 4 = 21 bytes */

    static const u_char wire[] = "\xc0\x00\x00\x00\xaf\x36\x27\xe6" /* the frame type */
                                 "\x00"                             /* stream id 0 */
                                 "\x07session"                      /* the type */
                                 "\x80\x00\x75\x30";                /* max packet 30000 */

    /* the varint forms follow the written values: a 2-byte stream id
     * and a 2-byte max packet size shrink the header to 17 bytes */

    static const u_char wire2[] = "\xc0\x00\x00\x00\xaf\x36\x27\xe6" /* the frame type */
                                  "\x7f\xff"                         /* stream id 16383 */
                                  "\x04sftp"                         /* the type */
                                  "\x40\x40";                        /* max packet 64 */

    s3_ssh3_channel_t ch;
    u_char            buf[64];
    u_char           *p;

    s3_channel_init(&ch, "session", 0, 30000);

    S3_ASSERT(s3_ssh3_varint_size(S3_SSH3_FRAME_TYPE) == 8);
    S3_ASSERT(s3_ssh3_channel_header_size(&ch) == sizeof(wire) - 1);
    S3_ASSERT(sizeof(wire) - 1 == 21);

    p = s3_ssh3_channel_build_header(buf, &ch);

    S3_ASSERT(p == buf + sizeof(wire) - 1);
    S3_ASSERT(s3_memcmp(buf, wire, sizeof(wire) - 1) == 0);

    s3_channel_init(&ch, "sftp", 16383, 64);

    S3_ASSERT(s3_ssh3_channel_header_size(&ch) == sizeof(wire2) - 1);
    S3_ASSERT(sizeof(wire2) - 1 == 17);

    p = s3_ssh3_channel_build_header(buf, &ch);

    S3_ASSERT(p == buf + sizeof(wire2) - 1);
    S3_ASSERT(s3_memcmp(buf, wire2, sizeof(wire2) - 1) == 0);

    return s3_test_failures;
}

static int
s3_test_channel_parse_roundtrip(void)
{
    static const u_char wire[] = "\xc0\x00\x00\x00\xaf\x36\x27\xe6" /* the frame type */
                                 "\x44\xd2"                         /* stream id 1234 */
                                 "\x07session"                      /* the type */
                                 "\x80\x00\x75\x30";                /* max packet 30000 */

    s3_ssh3_channel_t ch;
    u_char            buf[64];
    const u_char     *pos, *end;

    /* the literal bytes parse back into the channel fields */

    s3_channel_init(&ch, "direct-tcp", 0, 0); /* the sentinels */
    ch.channel_id = 7;

    pos = wire;
    end = wire + sizeof(wire) - 1;

    S3_ASSERT(s3_ssh3_channel_parse_header(&pos, end, &ch) == S3_OK);
    S3_ASSERT(pos == end);
    S3_ASSERT(ch.conversation_stream_id == 1234);
    S3_ASSERT(ch.max_packet_size == 30000);
    S3_ASSERT(ch.type.len == 7);
    S3_ASSERT(s3_memcmp(ch.type.data, "session", 7) == 0);
    /* the type is a zero-copy view into the receive buffer */
    S3_ASSERT(ch.type.data >= wire && ch.type.data < end);
    /* the parser does not touch channel_id, the transport owns it */
    S3_ASSERT(ch.channel_id == 7);

    /* the build/parse round-trip over another set of fields */

    s3_channel_init(&ch, "sftp", 16383, 64);
    end = s3_ssh3_channel_build_header(buf, &ch);

    s3_memzero(&ch, sizeof(ch));
    ch.channel_id = 4242;

    pos = buf;

    S3_ASSERT(s3_ssh3_channel_parse_header(&pos, end, &ch) == S3_OK);
    S3_ASSERT(pos == end);
    S3_ASSERT(ch.conversation_stream_id == 16383);
    S3_ASSERT(ch.max_packet_size == 64);
    S3_ASSERT(ch.type.len == 4);
    S3_ASSERT(s3_memcmp(ch.type.data, "sftp", 4) == 0);
    S3_ASSERT(ch.type.data >= buf && ch.type.data < end);
    S3_ASSERT(ch.channel_id == 4242);

    return s3_test_failures;
}

static int
s3_test_channel_parse_errors(void)
{
    s3_ssh3_channel_t ch;
    u_char            buf[64];
    const u_char     *pos, *end;
    size_t            len;

    s3_channel_init(&ch, "session", 0, 30000);
    end = s3_ssh3_channel_build_header(buf, &ch);
    len = (size_t)(end - buf);

    S3_ASSERT(len == 21);

    /* a foreign first varint (a non-ssh3 stream) is an error and
     * neither the cursor nor the channel move */

    s3_channel_init(&ch, "sentinel", 0xaaaa, 0xbbbb);

    buf[0] = 0x01;
    pos = buf;

    S3_ASSERT(s3_ssh3_channel_parse_header(&pos, buf + 21, &ch) == S3_ERROR);
    S3_ASSERT(pos == buf);
    S3_ASSERT(ch.conversation_stream_id == 0xaaaa);
    S3_ASSERT(ch.max_packet_size == 0xbbbb);
    S3_ASSERT(ch.type.len == 8);

    /* a wrong value inside the 8-byte frame type form too */

    buf[0] = 0xc0;
    buf[7] = 0xe7; /* ...e6 -> ...e7 */
    pos = buf;

    S3_ASSERT(s3_ssh3_channel_parse_header(&pos, buf + 21, &ch) == S3_ERROR);
    S3_ASSERT(pos == buf);

    /* a truncated buffer at every prefix length is an error, the
     * cursor and the channel stay untouched */

    buf[0] = 0xc0;
    buf[7] = 0xe6;

    for (len = 0; len < 21; len++) {
        pos = buf;

        S3_ASSERT(s3_ssh3_channel_parse_header(&pos, buf + len, &ch) == S3_ERROR);
        S3_ASSERT(pos == buf);
    }

    S3_ASSERT(ch.conversation_stream_id == 0xaaaa);
    S3_ASSERT(ch.max_packet_size == 0xbbbb);
    S3_ASSERT(ch.type.len == 8);
    S3_ASSERT(s3_memcmp(ch.type.data, "sentinel", 8) == 0);

    return s3_test_failures;
}

static int
s3_test_channel_chunk_size(void)
{
    static const struct {
        uint64_t max_packet_size;
        unsigned extended;
        size_t   chunk;
    } vec[] = {
        /* the reference WriteData() subtracts the emptyMsgLen: the
         * frame with an empty string. varint(94) takes the 2-byte
         * form (94 > 63), so the plain overhead is 2 + 1 = 3 and the
         * extended one is 2 + 1 + 1 = 4 (stderr = 1); only the
         * written frame numbers count, the max_packet_size form
         * does not matter */

        {30000, 0, 29997}, {30000, 1, 29996}, {16384, 0, 16381}, /* a 4-byte max packet size changes
                                                                    nothing */
        {16384, 1, 16380}, {64, 0, 61},       {64, 1, 60},       {4, 0, 1},
        {4, 1, 0},         {3, 0, 0}, /* exactly the overhead: nothing fits */
        {3, 1, 0},         {2, 0, 0},         {1, 0, 0},         {1, 1, 0},
        {0, 0, 0},         {0, 1, 0},
    };

    size_t i;

    for (i = 0; i < sizeof(vec) / sizeof(vec[0]); i++) {
        S3_ASSERT(s3_ssh3_channel_chunk_size(vec[i].max_packet_size, vec[i].extended) ==
                  vec[i].chunk);
    }

    return s3_test_failures;
}

static int
s3_test_ssh3_channel(void)
{
    (void)s3_test_channel_build();
    (void)s3_test_channel_parse_roundtrip();
    (void)s3_test_channel_parse_errors();
    (void)s3_test_channel_chunk_size();

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_ssh3_channel)
