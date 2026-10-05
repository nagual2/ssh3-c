/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the libFuzzer harness of the ssh3 wire primitives: the QUIC varint
 * and the SSHString readers eat the whole input element by element,
 * every parsed value re-encodes canonically and must parse back to
 * itself, and the encoded size must match the parse consumption
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include <s3_core.h>

#include <s3_ssh3_wire.h>

#include "s3_fuzz.h"

#define S3_FUZZ_STRING_ROUNDTRIP_MAX 4096

static void
s3_fuzz_varint(const u_char **pos, const u_char *end)
{
    const u_char *back;
    u_char        buf[8];
    uint64_t      value, back_value;
    s3_int_t      rc;

    rc = s3_ssh3_parse_varint(pos, end, &value);

    if (rc != S3_OK) {
        return;
    }

    s3_fuzz_sink(value);

    /* the canonical re-encode of a parsed value parses back to the
     * same value in the byte count the size helper announces */

    if (s3_ssh3_varint_size(value) > sizeof(buf)) {
        s3_fuzz_trap();
    }

    back = buf;

    s3_ssh3_encode_varint(buf, value);

    rc = s3_ssh3_parse_varint(&back, buf + sizeof(buf), &back_value);

    if (rc != S3_OK || back_value != value || (size_t)(back - buf) != s3_ssh3_varint_size(value)) {
        s3_fuzz_trap();
    }
}

static void
s3_fuzz_sshstring(const u_char **pos, const u_char *end)
{
    const u_char *back;
    u_char       *buf;
    s3_str_t      out;
    size_t        i, len, size;
    s3_int_t      rc;

    rc = s3_ssh3_parse_sshstring(pos, end, &out);

    if (rc != S3_OK) {
        return;
    }

    s3_fuzz_sink(out.len);

    for (i = 0; i < out.len; i++) {
        s3_fuzz_sink(out.data[i]);
    }

    /* the re-encode of a parsed string parses back to the same view
     * length in exactly the announced size; a length the stack pool
     * of a caller would not hold skips the round-trip */

    len = out.len;
    size = s3_ssh3_sshstring_size(len);

    if (len > S3_FUZZ_STRING_ROUNDTRIP_MAX) {
        return;
    }

    buf = malloc(size);

    if (buf == NULL) {
        return;
    }

    s3_ssh3_encode_sshstring(buf, out.data, len);

    back = buf;

    rc = s3_ssh3_parse_sshstring(&back, buf + size, &out);

    if (rc != S3_OK || out.len != len || (size_t)(back - buf) != size) {
        s3_fuzz_trap();
    }

    free(buf);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    const u_char *pos, *end, *prev;

    pos = (const u_char *)data;
    end = pos + size;

    /* the varints first, then the strings from the same walk; both
     * readers refuse a byte, the walk steps over it and moves on */

    while (pos < end) {
        prev = pos;

        s3_fuzz_varint(&pos, end);
        s3_fuzz_sshstring(&pos, end);

        if (pos == prev) {
            pos++;
        }
    }

    s3_fuzz_sink((size_t)(pos - (const u_char *)data));

    return 0;
}
