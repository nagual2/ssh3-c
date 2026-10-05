/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the libFuzzer harness of the forward target extension: the parser
 * walks the input target by target, every parsed target re-encodes
 * through the size/build pair and must parse back to itself, the
 * contract the channel header builders rely on
 */

#include <stddef.h>
#include <stdint.h>

#include <s3_core.h>

#include <s3_ssh3_forward.h>

#include "s3_fuzz.h"

#define S3_FUZZ_TARGET_BUF_MAX 64

static void
s3_fuzz_target_roundtrip(const s3_ssh3_forward_target_t *t)
{
    u_char                   buf[S3_FUZZ_TARGET_BUF_MAX];
    const u_char            *pos, *end;
    u_char                  *p;
    size_t                   size;
    s3_ssh3_forward_target_t back;
    s3_int_t                 rc;

    size = s3_ssh3_forward_target_size(t);

    if (size > sizeof(buf)) {
        s3_fuzz_trap();
    }

    p = s3_ssh3_forward_build_target(buf, t);

    if ((size_t)(p - buf) != size) {
        s3_fuzz_trap();
    }

    pos = buf;
    end = buf + size;

    rc = s3_ssh3_forward_parse_target(&pos, end, &back);

    if (rc != S3_OK || back.family != t->family || back.ip_len != t->ip_len ||
        back.port != t->port || (size_t)(pos - buf) != size) {
        s3_fuzz_trap();
    }

    s3_fuzz_sink(size);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    const u_char            *pos, *end;
    s3_ssh3_forward_target_t t;
    s3_int_t                 rc;

    pos = (const u_char *)data;
    end = pos + size;

    for (;;) {
        rc = s3_ssh3_forward_parse_target(&pos, end, &t);

        if (rc != S3_OK) {
            break;
        }

        s3_fuzz_sink(t.family);
        s3_fuzz_sink(t.ip_len);
        s3_fuzz_sink(t.port);

        s3_fuzz_target_roundtrip(&t);
    }

    s3_fuzz_sink((size_t)(pos - (const u_char *)data));

    return 0;
}
