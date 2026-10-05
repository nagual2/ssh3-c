/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the libFuzzer harness of the ssh3 channel message decoders: every
 * public parser walks the input body by body, every parsed message
 * re-encodes through the public encoder and must parse back to the
 * same fields, the measure mode must agree with the write mode, and
 * a body the canonical form sizes exactly must re-encode byte for
 * byte
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include <s3_core.h>

#include <s3_ssh3_message.h>
#include <s3_ssh3_wire.h>

#include "s3_fuzz.h"

/* a round-trip buffer the callers would not hold skips the
 * re-encode, the harness stays allocation-light on hostile sizes */

#define S3_FUZZ_MSG_ROUNDTRIP_MAX (1 << 20)

static u_char *
s3_fuzz_rt_buf(size_t size)
{
    if (size == 0 || size > S3_FUZZ_MSG_ROUNDTRIP_MAX) {
        return NULL;
    }

    return malloc(size);
}

static void
s3_fuzz_rt_open_confirmation(const s3_ssh3_msg_open_confirmation_t *m, const u_char *start,
                             size_t consumed)
{
    u_char                          buf[8];
    const u_char                   *pos, *end;
    s3_ssh3_msg_open_confirmation_t out;
    size_t                          size;

    size = s3_ssh3_msg_encode_open_confirmation(NULL, m);

    if (size > sizeof(buf)) {
        s3_fuzz_trap();
    }

    end = (u_char *)s3_ssh3_msg_encode_open_confirmation(buf, m);

    if ((size_t)(end - buf) != size) {
        s3_fuzz_trap();
    }

    pos = buf;

    if (s3_ssh3_msg_parse_open_confirmation(&pos, end, &out) != S3_OK || pos != end ||
        out.max_packet_size != m->max_packet_size) {
        s3_fuzz_trap();
    }

    /* a body the canonical form sizes exactly is the canonical
     * encoding itself */

    if (consumed == size && s3_memcmp(buf, start, size) != 0) {
        s3_fuzz_trap();
    }
}

static void
s3_fuzz_rt_open_failure(const s3_ssh3_msg_open_failure_t *m, const u_char *start, size_t consumed)
{
    u_char                    *buf;
    const u_char              *pos, *end;
    s3_ssh3_msg_open_failure_t out;
    size_t                     size;

    size = s3_ssh3_msg_encode_open_failure(NULL, m);

    buf = s3_fuzz_rt_buf(size);

    if (buf == NULL) {
        return;
    }

    end = (u_char *)s3_ssh3_msg_encode_open_failure(buf, m);

    if ((size_t)(end - buf) != size) {
        s3_fuzz_trap();
    }

    pos = buf;

    if (s3_ssh3_msg_parse_open_failure(&pos, end, &out) != S3_OK || pos != end ||
        out.reason_code != m->reason_code || out.error_message.len != m->error_message.len ||
        out.language_tag.len != m->language_tag.len) {
        s3_fuzz_trap();
    }

    if (out.error_message.len > 0 &&
        s3_memcmp(out.error_message.data, m->error_message.data, out.error_message.len) != 0) {
        s3_fuzz_trap();
    }

    if (out.language_tag.len > 0 &&
        s3_memcmp(out.language_tag.data, m->language_tag.data, out.language_tag.len) != 0) {
        s3_fuzz_trap();
    }

    if (consumed == size && s3_memcmp(buf, start, size) != 0) {
        s3_fuzz_trap();
    }

    free(buf);
}

static void
s3_fuzz_rt_data(const s3_ssh3_msg_data_t *m, const u_char *start, size_t consumed)
{
    u_char            *buf;
    const u_char      *pos, *end;
    s3_ssh3_msg_data_t out;
    size_t             size;

    size = s3_ssh3_msg_encode_data(NULL, m);

    buf = s3_fuzz_rt_buf(size);

    if (buf == NULL) {
        return;
    }

    end = (u_char *)s3_ssh3_msg_encode_data(buf, m);

    if ((size_t)(end - buf) != size) {
        s3_fuzz_trap();
    }

    pos = buf;

    if (s3_ssh3_msg_parse_data(&pos, end, &out) != S3_OK || pos != end ||
        out.data.len != m->data.len) {
        s3_fuzz_trap();
    }

    if (out.data.len > 0 && s3_memcmp(out.data.data, m->data.data, out.data.len) != 0) {
        s3_fuzz_trap();
    }

    if (consumed == size && s3_memcmp(buf, start, size) != 0) {
        s3_fuzz_trap();
    }

    free(buf);
}

static void
s3_fuzz_rt_extended_data(const s3_ssh3_msg_extended_data_t *m, const u_char *start, size_t consumed)
{
    u_char                     *buf;
    const u_char               *pos, *end;
    s3_ssh3_msg_extended_data_t out;
    size_t                      size;

    size = s3_ssh3_msg_encode_extended_data(NULL, m);

    buf = s3_fuzz_rt_buf(size);

    if (buf == NULL) {
        return;
    }

    end = (u_char *)s3_ssh3_msg_encode_extended_data(buf, m);

    if ((size_t)(end - buf) != size) {
        s3_fuzz_trap();
    }

    pos = buf;

    if (s3_ssh3_msg_parse_extended_data(&pos, end, &out) != S3_OK || pos != end ||
        out.data_type != m->data_type || out.data.len != m->data.len) {
        s3_fuzz_trap();
    }

    if (out.data.len > 0 && s3_memcmp(out.data.data, m->data.data, out.data.len) != 0) {
        s3_fuzz_trap();
    }

    if (consumed == size && s3_memcmp(buf, start, size) != 0) {
        s3_fuzz_trap();
    }

    free(buf);
}

static void
s3_fuzz_rt_request(const s3_ssh3_msg_request_t *m, const u_char *start, size_t consumed)
{
    u_char               *buf;
    const u_char         *pos, *end;
    s3_ssh3_msg_request_t out;
    size_t                size;

    size = s3_ssh3_msg_encode_request(NULL, m);

    buf = s3_fuzz_rt_buf(size);

    if (buf == NULL) {
        return;
    }

    end = (u_char *)s3_ssh3_msg_encode_request(buf, m);

    if ((size_t)(end - buf) != size) {
        s3_fuzz_trap();
    }

    pos = buf;

    if (s3_ssh3_msg_parse_request(&pos, end, &out) != S3_OK || pos != end ||
        out.want_reply != m->want_reply || out.request_type.len != m->request_type.len ||
        out.body.len != m->body.len) {
        s3_fuzz_trap();
    }

    if (out.request_type.len > 0 &&
        s3_memcmp(out.request_type.data, m->request_type.data, out.request_type.len) != 0) {
        s3_fuzz_trap();
    }

    if (out.body.len > 0 && s3_memcmp(out.body.data, m->body.data, out.body.len) != 0) {
        s3_fuzz_trap();
    }

    if (consumed == size && s3_memcmp(buf, start, size) != 0) {
        s3_fuzz_trap();
    }

    free(buf);
}

static void
s3_fuzz_rt_request_envelope(const s3_ssh3_msg_request_t *m, const u_char *start, size_t consumed)
{
    u_char               *buf;
    u_char               *p;
    const u_char         *pos, *end;
    s3_ssh3_msg_request_t out;
    size_t                size;

    /* the envelope alone is the type string plus the raw wantReply
     * byte, the body stays behind for the request module */

    size = s3_ssh3_sshstring_size(m->request_type.len) + 1;

    buf = s3_fuzz_rt_buf(size);

    if (buf == NULL) {
        return;
    }

    p = s3_ssh3_encode_sshstring(buf, m->request_type.data, m->request_type.len);
    *p++ = (u_char)m->want_reply;
    end = p;

    if ((size_t)(end - buf) != size) {
        s3_fuzz_trap();
    }

    pos = buf;

    if (s3_ssh3_msg_parse_request_envelope(&pos, end, &out) != S3_OK || pos != end ||
        out.want_reply != m->want_reply || out.request_type.len != m->request_type.len ||
        out.body.len != 0) {
        s3_fuzz_trap();
    }

    if (out.request_type.len > 0 &&
        s3_memcmp(out.request_type.data, m->request_type.data, out.request_type.len) != 0) {
        s3_fuzz_trap();
    }

    if (consumed == size && s3_memcmp(buf, start, size) != 0) {
        s3_fuzz_trap();
    }

    free(buf);
}

static void
s3_fuzz_walk_open_confirmation(const u_char *pos, const u_char *end)
{
    s3_ssh3_msg_open_confirmation_t m;
    const u_char                   *start;

    for (;;) {
        start = pos;

        if (s3_ssh3_msg_parse_open_confirmation(&pos, end, &m) != S3_OK) {
            break;
        }

        s3_fuzz_sink(m.max_packet_size);
        s3_fuzz_rt_open_confirmation(&m, start, (size_t)(pos - start));
    }
}

static void
s3_fuzz_walk_open_failure(const u_char *pos, const u_char *end)
{
    s3_ssh3_msg_open_failure_t m;
    const u_char              *start;

    for (;;) {
        start = pos;

        if (s3_ssh3_msg_parse_open_failure(&pos, end, &m) != S3_OK) {
            break;
        }

        s3_fuzz_sink(m.reason_code);
        s3_fuzz_sink(m.error_message.len);
        s3_fuzz_sink(m.language_tag.len);
        s3_fuzz_rt_open_failure(&m, start, (size_t)(pos - start));
    }
}

static void
s3_fuzz_walk_data(const u_char *pos, const u_char *end)
{
    s3_ssh3_msg_data_t m;
    const u_char      *start;

    for (;;) {
        start = pos;

        if (s3_ssh3_msg_parse_data(&pos, end, &m) != S3_OK) {
            break;
        }

        s3_fuzz_sink(m.data.len);
        s3_fuzz_rt_data(&m, start, (size_t)(pos - start));
    }
}

static void
s3_fuzz_walk_extended_data(const u_char *pos, const u_char *end)
{
    s3_ssh3_msg_extended_data_t m;
    const u_char               *start;

    for (;;) {
        start = pos;

        if (s3_ssh3_msg_parse_extended_data(&pos, end, &m) != S3_OK) {
            break;
        }

        s3_fuzz_sink(m.data_type);
        s3_fuzz_sink(m.data.len);
        s3_fuzz_rt_extended_data(&m, start, (size_t)(pos - start));
    }
}

static void
s3_fuzz_walk_request(const u_char *pos, const u_char *end)
{
    s3_ssh3_msg_request_t m;
    const u_char         *start;

    /* the request body rides to the end of the buffer, so one parse
     * eats the whole walk */

    for (;;) {
        start = pos;

        if (s3_ssh3_msg_parse_request(&pos, end, &m) != S3_OK) {
            break;
        }

        s3_fuzz_sink(m.want_reply);
        s3_fuzz_sink(m.request_type.len);
        s3_fuzz_sink(m.body.len);
        s3_fuzz_rt_request(&m, start, (size_t)(pos - start));
    }
}

static void
s3_fuzz_walk_request_envelope(const u_char *pos, const u_char *end)
{
    s3_ssh3_msg_request_t m;
    const u_char         *start;

    /* the envelope leaves the body in place, so the walk re-parses
     * the tail as the next envelope, like a request-less stream */

    for (;;) {
        start = pos;

        if (s3_ssh3_msg_parse_request_envelope(&pos, end, &m) != S3_OK) {
            break;
        }

        s3_fuzz_sink(m.want_reply);
        s3_fuzz_sink(m.request_type.len);
        s3_fuzz_rt_request_envelope(&m, start, (size_t)(pos - start));
    }
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    const u_char *pos, *end;

    pos = (const u_char *)data;
    end = pos + size;

    /* the callers strip the message type byte before the body parse,
     * so the same chunk may ride as any body and several bodies of
     * one shape in a row; every parser walks the input on its own */

    s3_fuzz_walk_open_confirmation(pos, end);
    s3_fuzz_walk_open_failure(pos, end);
    s3_fuzz_walk_data(pos, end);
    s3_fuzz_walk_extended_data(pos, end);
    s3_fuzz_walk_request(pos, end);
    s3_fuzz_walk_request_envelope(pos, end);

    s3_fuzz_sink(size);

    return 0;
}
