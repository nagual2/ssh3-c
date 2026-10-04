/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the ssh3 channel message codecs: the message type constants, the
 * known-bytes vectors, the measure mode, round-trips, truncated input
 * and the zero-copy views into the receive buffer
 */

#include <s3_core.h>

#include <string.h>

#include <s3_ssh3_message.h>

#include "s3_test.h"

static int
s3_test_msg_constants(void)
{
    /* the wire values are fixed by the reference message/message.go */

    S3_ASSERT(S3_SSH3_MSG_CHANNEL_OPEN_CONFIRMATION == 91);
    S3_ASSERT(S3_SSH3_MSG_CHANNEL_OPEN_FAILURE == 92);
    S3_ASSERT(S3_SSH3_MSG_CHANNEL_DATA == 94);
    S3_ASSERT(S3_SSH3_MSG_CHANNEL_EXTENDED_DATA == 95);
    S3_ASSERT(S3_SSH3_MSG_CHANNEL_REQUEST == 98);

    S3_ASSERT(S3_SSH3_EXTENDED_DATA_NONE == 0);
    S3_ASSERT(S3_SSH3_EXTENDED_DATA_STDERR == 1);

    return s3_test_failures;
}

static int
s3_test_msg_open_confirmation(void)
{
    u_char                          buf[16];
    u_char                         *p;
    const u_char                   *pos, *end;
    uintptr_t                       size;
    s3_ssh3_msg_open_confirmation_t m, out;

    /* 32768 takes the 4-byte varint form */

    m.max_packet_size = 32768;

    size = s3_ssh3_msg_encode_open_confirmation(NULL, &m);

    S3_ASSERT(size == 4);

    s3_memzero(buf, sizeof(buf));
    p = (u_char *)s3_ssh3_msg_encode_open_confirmation(buf, &m);

    S3_ASSERT((uintptr_t)(p - buf) == size);
    S3_ASSERT(s3_memcmp(buf, "\x80\x00\x80\x00", 4) == 0);

    pos = buf;
    end = p;

    S3_ASSERT(s3_ssh3_msg_parse_open_confirmation(&pos, end, &out) == S3_OK);
    S3_ASSERT(out.max_packet_size == 32768);
    S3_ASSERT(pos == end);

    /* 64 takes the 2-byte varint form */

    m.max_packet_size = 64;
    p = (u_char *)s3_ssh3_msg_encode_open_confirmation(buf, &m);

    S3_ASSERT(p == buf + 2);
    S3_ASSERT(s3_memcmp(buf, "\x40\x40", 2) == 0);

    pos = buf;
    end = buf + 2;

    S3_ASSERT(s3_ssh3_msg_parse_open_confirmation(&pos, end, &out) == S3_OK);
    S3_ASSERT(out.max_packet_size == 64);
    S3_ASSERT(pos == end);

    return s3_test_failures;
}

static int
s3_test_msg_open_confirmation_truncated(void)
{
    u_char                          buf[8];
    const u_char                   *pos, *end;
    s3_ssh3_msg_open_confirmation_t out;

    s3_memzero(buf, sizeof(buf));

    /* the 4-byte varint needs all of its bytes */

    s3_memcpy(buf, "\x80\x00\x80", 3);
    pos = buf;
    end = buf + 3;

    S3_ASSERT(s3_ssh3_msg_parse_open_confirmation(&pos, end, &out) == S3_ERROR);
    S3_ASSERT(pos == buf);

    /* the empty buffer has no length prefix at all */

    pos = buf;
    end = buf;

    S3_ASSERT(s3_ssh3_msg_parse_open_confirmation(&pos, end, &out) == S3_ERROR);
    S3_ASSERT(pos == buf);

    return s3_test_failures;
}

static int
s3_test_msg_open_failure(void)
{
    u_char                     buf[32];
    u_char                    *p;
    const u_char              *pos, *end;
    uintptr_t                  size;
    s3_ssh3_msg_open_failure_t m, out;

    m.reason_code = 1;
    s3_str_set(&m.error_message, "denied");
    s3_str_set(&m.language_tag, "en");

    /* the reason varint, then the two SSHStrings */

    size = s3_ssh3_msg_encode_open_failure(NULL, &m);

    S3_ASSERT(size == 11);

    s3_memzero(buf, sizeof(buf));
    p = (u_char *)s3_ssh3_msg_encode_open_failure(buf, &m);

    S3_ASSERT((uintptr_t)(p - buf) == size);
    S3_ASSERT(s3_memcmp(buf,
                        "\x01"
                        "\x06"
                        "denied"
                        "\x02"
                        "en",
                        11) == 0);

    pos = buf;
    end = p;

    S3_ASSERT(s3_ssh3_msg_parse_open_failure(&pos, end, &out) == S3_OK);
    S3_ASSERT(out.reason_code == 1);
    S3_ASSERT(out.error_message.len == 6);
    S3_ASSERT(out.error_message.data == buf + 2);
    S3_ASSERT(s3_memcmp(out.error_message.data, "denied", 6) == 0);
    S3_ASSERT(out.language_tag.len == 2);
    S3_ASSERT(out.language_tag.data == buf + 9);
    S3_ASSERT(s3_memcmp(out.language_tag.data, "en", 2) == 0);
    S3_ASSERT(pos == end);

    /* the empty strings stay one zero byte each */

    m.reason_code = 2;
    m.error_message.len = 0;
    m.error_message.data = NULL;
    m.language_tag.len = 0;
    m.language_tag.data = NULL;

    p = (u_char *)s3_ssh3_msg_encode_open_failure(buf, &m);

    S3_ASSERT(p == buf + 3);
    S3_ASSERT(s3_memcmp(buf, "\x02\x00\x00", 3) == 0);

    pos = buf;
    end = p;

    S3_ASSERT(s3_ssh3_msg_parse_open_failure(&pos, end, &out) == S3_OK);
    S3_ASSERT(out.reason_code == 2);
    S3_ASSERT(out.error_message.len == 0);
    S3_ASSERT(out.error_message.data == buf + 2);
    S3_ASSERT(out.language_tag.len == 0);
    S3_ASSERT(out.language_tag.data == buf + 3);
    S3_ASSERT(pos == end);

    return s3_test_failures;
}

static int
s3_test_msg_open_failure_truncated(void)
{
    u_char                     buf[16];
    const u_char              *pos, *end;
    s3_ssh3_msg_open_failure_t out;

    s3_memzero(buf, sizeof(buf));

    /* nothing at all */

    pos = buf;
    end = buf;

    S3_ASSERT(s3_ssh3_msg_parse_open_failure(&pos, end, &out) == S3_ERROR);
    S3_ASSERT(pos == buf);

    /* the reason without the message string */

    s3_memcpy(buf, "\x01", 1);
    pos = buf;
    end = buf + 1;

    S3_ASSERT(s3_ssh3_msg_parse_open_failure(&pos, end, &out) == S3_ERROR);
    S3_ASSERT(pos == buf);

    /* a message length promising more than the buffer holds */

    s3_memcpy(buf,
              "\x01"
              "\x06"
              "den",
              5);
    pos = buf;
    end = buf + 5;

    S3_ASSERT(s3_ssh3_msg_parse_open_failure(&pos, end, &out) == S3_ERROR);
    S3_ASSERT(pos == buf);

    /* the language tag truncated */

    s3_memcpy(buf,
              "\x01"
              "\x06"
              "denied"
              "\x02"
              "e",
              10);
    pos = buf;
    end = buf + 10;

    S3_ASSERT(s3_ssh3_msg_parse_open_failure(&pos, end, &out) == S3_ERROR);
    S3_ASSERT(pos == buf);

    return s3_test_failures;
}

static int
s3_test_msg_data(void)
{
    u_char             buf[16];
    u_char            *p;
    const u_char      *pos, *end;
    uintptr_t          size;
    s3_ssh3_msg_data_t m, out;

    s3_str_set(&m.data, "hello");

    /* the plain data message is a single SSHString */

    size = s3_ssh3_msg_encode_data(NULL, &m);

    S3_ASSERT(size == 6);

    s3_memzero(buf, sizeof(buf));
    p = (u_char *)s3_ssh3_msg_encode_data(buf, &m);

    S3_ASSERT((uintptr_t)(p - buf) == size);
    S3_ASSERT(s3_memcmp(buf,
                        "\x05"
                        "hello",
                        6) == 0);

    pos = buf;
    end = p;

    S3_ASSERT(s3_ssh3_msg_parse_data(&pos, end, &out) == S3_OK);
    S3_ASSERT(out.data.len == 5);
    S3_ASSERT(out.data.data == buf + 1);
    S3_ASSERT(s3_memcmp(out.data.data, "hello", 5) == 0);
    S3_ASSERT(pos == end);

    /* the empty payload is one zero byte */

    m.data.len = 0;
    m.data.data = NULL;

    p = (u_char *)s3_ssh3_msg_encode_data(buf, &m);

    S3_ASSERT(p == buf + 1);
    S3_ASSERT(buf[0] == 0);

    pos = buf;
    end = p;

    S3_ASSERT(s3_ssh3_msg_parse_data(&pos, end, &out) == S3_OK);
    S3_ASSERT(out.data.len == 0);
    S3_ASSERT(out.data.data == end);

    return s3_test_failures;
}

static int
s3_test_msg_data_truncated(void)
{
    u_char             buf[8];
    const u_char      *pos, *end;
    s3_ssh3_msg_data_t out;

    s3_memzero(buf, sizeof(buf));

    /* the length prefix promises more than the buffer holds; unlike
     * the reference, which tolerates io.EOF here, the parse is strict */

    s3_memcpy(buf,
              "\x05"
              "hel",
              4);
    pos = buf;
    end = buf + 4;

    S3_ASSERT(s3_ssh3_msg_parse_data(&pos, end, &out) == S3_ERROR);
    S3_ASSERT(pos == buf);

    /* a long-form length with no payload behind it */

    s3_memcpy(buf, "\x85", 1);
    pos = buf;
    end = buf + 1;

    S3_ASSERT(s3_ssh3_msg_parse_data(&pos, end, &out) == S3_ERROR);
    S3_ASSERT(pos == buf);

    /* nothing at all */

    pos = buf;
    end = buf;

    S3_ASSERT(s3_ssh3_msg_parse_data(&pos, end, &out) == S3_ERROR);
    S3_ASSERT(pos == buf);

    return s3_test_failures;
}

static int
s3_test_msg_extended_data(void)
{
    u_char                      buf[16];
    u_char                     *p;
    const u_char               *pos, *end;
    uintptr_t                   size;
    s3_ssh3_msg_extended_data_t m, out;

    /* the stderr payload: the data type varint, then the SSHString */

    m.data_type = S3_SSH3_EXTENDED_DATA_STDERR;
    s3_str_set(&m.data, "err");

    size = s3_ssh3_msg_encode_extended_data(NULL, &m);

    S3_ASSERT(size == 5);

    s3_memzero(buf, sizeof(buf));
    p = (u_char *)s3_ssh3_msg_encode_extended_data(buf, &m);

    S3_ASSERT((uintptr_t)(p - buf) == size);
    S3_ASSERT(s3_memcmp(buf,
                        "\x01"
                        "\x03"
                        "err",
                        5) == 0);

    pos = buf;
    end = p;

    S3_ASSERT(s3_ssh3_msg_parse_extended_data(&pos, end, &out) == S3_OK);
    S3_ASSERT(out.data_type == S3_SSH3_EXTENDED_DATA_STDERR);
    S3_ASSERT(out.data.len == 3);
    S3_ASSERT(out.data.data == buf + 2);
    S3_ASSERT(s3_memcmp(out.data.data, "err", 3) == 0);
    S3_ASSERT(pos == end);

    /* the plain data type rides the same shape */

    m.data_type = S3_SSH3_EXTENDED_DATA_NONE;

    size = s3_ssh3_msg_encode_extended_data(NULL, &m);

    S3_ASSERT(size == 5);

    p = (u_char *)s3_ssh3_msg_encode_extended_data(buf, &m);

    S3_ASSERT((uintptr_t)(p - buf) == size);
    S3_ASSERT(s3_memcmp(buf,
                        "\x00"
                        "\x03"
                        "err",
                        5) == 0);

    pos = buf;
    end = p;

    S3_ASSERT(s3_ssh3_msg_parse_extended_data(&pos, end, &out) == S3_OK);
    S3_ASSERT(out.data_type == S3_SSH3_EXTENDED_DATA_NONE);
    S3_ASSERT(pos == end);

    return s3_test_failures;
}

static int
s3_test_msg_extended_data_truncated(void)
{
    u_char                      buf[8];
    const u_char               *pos, *end;
    s3_ssh3_msg_extended_data_t out;

    s3_memzero(buf, sizeof(buf));

    /* the data type without the payload string */

    s3_memcpy(buf, "\x01", 1);
    pos = buf;
    end = buf + 1;

    S3_ASSERT(s3_ssh3_msg_parse_extended_data(&pos, end, &out) == S3_ERROR);
    S3_ASSERT(pos == buf);

    /* the payload string truncated */

    s3_memcpy(buf,
              "\x01"
              "\x03"
              "er",
              3);
    pos = buf;
    end = buf + 3;

    S3_ASSERT(s3_ssh3_msg_parse_extended_data(&pos, end, &out) == S3_ERROR);
    S3_ASSERT(pos == buf);

    return s3_test_failures;
}

static int
s3_test_msg_request(void)
{
    u_char                buf[32];
    u_char               *p;
    const u_char         *pos, *end;
    uintptr_t             size;
    s3_ssh3_msg_request_t m, out;
    static const u_char   ls_body[] = "\x02"
                                      "ls";

    /* the shell request carries an empty body */

    s3_str_set(&m.request_type, "shell");
    m.want_reply = 0;
    m.body.len = 0;
    m.body.data = NULL;

    size = s3_ssh3_msg_encode_request(NULL, &m);

    S3_ASSERT(size == 7);

    s3_memzero(buf, sizeof(buf));
    p = (u_char *)s3_ssh3_msg_encode_request(buf, &m);

    S3_ASSERT((uintptr_t)(p - buf) == size);
    S3_ASSERT(s3_memcmp(buf,
                        "\x05"
                        "shell"
                        "\x00",
                        7) == 0);

    pos = buf;
    end = p;

    S3_ASSERT(s3_ssh3_msg_parse_request(&pos, end, &out) == S3_OK);
    S3_ASSERT(out.request_type.len == 5);
    S3_ASSERT(out.request_type.data == buf + 1);
    S3_ASSERT(s3_memcmp(out.request_type.data, "shell", 5) == 0);
    S3_ASSERT(out.want_reply == 0);
    S3_ASSERT(out.body.len == 0);
    S3_ASSERT(out.body.data == end);
    S3_ASSERT(pos == end);

    /* the exec request carries the raw request body after wantReply */

    s3_str_set(&m.request_type, "exec");
    m.want_reply = 1;
    m.body.len = sizeof(ls_body) - 1;
    m.body.data = (u_char *)ls_body;

    size = s3_ssh3_msg_encode_request(NULL, &m);

    S3_ASSERT(size == 9);

    p = (u_char *)s3_ssh3_msg_encode_request(buf, &m);

    S3_ASSERT((uintptr_t)(p - buf) == size);
    S3_ASSERT(s3_memcmp(buf,
                        "\x04"
                        "exec"
                        "\x01"
                        "\x02"
                        "ls",
                        9) == 0);

    pos = buf;
    end = p;

    S3_ASSERT(s3_ssh3_msg_parse_request(&pos, end, &out) == S3_OK);
    S3_ASSERT(out.request_type.len == 4);
    S3_ASSERT(out.request_type.data == buf + 1);
    S3_ASSERT(s3_memcmp(out.request_type.data, "exec", 4) == 0);
    S3_ASSERT(out.want_reply == 1);
    S3_ASSERT(out.body.len == 3);
    S3_ASSERT(out.body.data == buf + 6);
    S3_ASSERT(s3_memcmp(out.body.data,
                        "\x02"
                        "ls",
                        3) == 0);
    S3_ASSERT(pos == end);

    return s3_test_failures;
}

static int
s3_test_msg_request_truncated(void)
{
    u_char                buf[16];
    const u_char         *pos, *end;
    s3_ssh3_msg_request_t out;

    s3_memzero(buf, sizeof(buf));

    /* the request type string truncated */

    s3_memcpy(buf,
              "\x05"
              "shel",
              5);
    pos = buf;
    end = buf + 5;

    S3_ASSERT(s3_ssh3_msg_parse_request(&pos, end, &out) == S3_ERROR);
    S3_ASSERT(pos == buf);

    /* the wantReply byte missing after the request type */

    s3_memcpy(buf,
              "\x05"
              "shell",
              6);
    pos = buf;
    end = buf + 6;

    S3_ASSERT(s3_ssh3_msg_parse_request(&pos, end, &out) == S3_ERROR);
    S3_ASSERT(pos == buf);

    return s3_test_failures;
}

static int
s3_test_ssh3_message(void)
{
    (void)s3_test_msg_constants();
    (void)s3_test_msg_open_confirmation();
    (void)s3_test_msg_open_confirmation_truncated();
    (void)s3_test_msg_open_failure();
    (void)s3_test_msg_open_failure_truncated();
    (void)s3_test_msg_data();
    (void)s3_test_msg_data_truncated();
    (void)s3_test_msg_extended_data();
    (void)s3_test_msg_extended_data_truncated();
    (void)s3_test_msg_request();
    (void)s3_test_msg_request_truncated();

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_ssh3_message)
