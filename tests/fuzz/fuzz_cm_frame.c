/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the libFuzzer harness of the ControlMaster codec: the frame layer
 * eats the whole input, every parsed frame runs through the strict
 * payload decoder of its type, and the MasterStatus JSON emitter is
 * driven by attacker-shaped values with the measure/write size
 * contract enforced (the callers reserve exactly the measure size)
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include <s3_core.h>

#include <s3_ssh3_cm.h>

#include "s3_fuzz.h"

#define S3_FUZZ_CM_PATH_MAX 256

static void
s3_fuzz_cm_payload(const s3_ssh3_cm_frame_t *f)
{
    s3_ssh3_cm_open_session_t req;
    u_char                    token[S3_SSH3_CM_TOKEN_LEN];
    uint8_t                   kind;
    uint64_t                  code;
    uint32_t                  i;
    s3_str_t                  op;

    switch (f->type) {

    case S3_SSH3_CM_MSG_OPEN_SESSION:

        if (s3_ssh3_cm_decode_open_session(&f->payload, &req) != S3_OK) {
            return;
        }

        s3_fuzz_sink(req.ncommand);
        s3_fuzz_sink(req.nenv);
        s3_fuzz_sink(req.forward_agent);

        for (i = 0; i < req.ncommand; i++) {
            s3_fuzz_sink(req.command[i].len);
        }

        for (i = 0; i < req.nenv; i++) {
            s3_fuzz_sink(req.env[i].len);
        }

        return;

    case S3_SSH3_CM_MSG_ATTACH:

        if (s3_ssh3_cm_decode_attach(&f->payload, token, &kind) != S3_OK) {
            return;
        }

        s3_fuzz_sink(kind + token[0]);

        return;

    case S3_SSH3_CM_MSG_EXIT_STATUS:

        if (s3_ssh3_cm_decode_exit_status(&f->payload, &code) != S3_OK) {
            return;
        }

        s3_fuzz_sink((size_t)code);

        return;

    case S3_SSH3_CM_MSG_CONTROL_OP:

        if (s3_ssh3_cm_decode_control_op(&f->payload, &op) != S3_OK) {
            return;
        }

        s3_fuzz_sink(op.len);

        return;

    default:

        /* HELLO, EXIT, OK, ERROR and the types v0 does not parse
         * carry the payload the dispatch above refuses; the bytes
         * still ride the view */

        s3_fuzz_sink(f->payload.len);

        return;
    }
}

/*
 * the status JSON emitter: the snapshot fields come from the input,
 * the path is the input as a bounded C string; the emitter must
 * agree with its own measure mode, the reply path reserves exactly
 * s3_ssh3_cm_encode_status_json(NULL, &st) bytes
 */

static void
s3_fuzz_cm_status_json(const uint8_t *data, size_t size)
{
    u_char              path[S3_FUZZ_CM_PATH_MAX];
    s3_ssh3_cm_status_t st;
    size_t              path_len;
    uintptr_t           measured, written;
    u_char             *buf, *p;

    s3_memzero(path, sizeof(path));

    path_len = size < S3_FUZZ_CM_PATH_MAX - 1 ? size : S3_FUZZ_CM_PATH_MAX - 1;
    s3_memcpy(path, data, path_len);

    s3_memzero(&st, sizeof(st));

    st.path = (const char *)path;
    st.pid = (int)(((uint32_t)path[0] << 20) | ((uint32_t)path[1] << 10) | (uint32_t)path[2]);
    st.protocol = 1 + path[3] % 3;
    st.uptime_s = (double)path[4];
    st.sessions = path[5] % (S3_SSH3_CM_SRV_SESSIONS + 1);
    st.forwards = path[6] % 64;

    measured = s3_ssh3_cm_encode_status_json(NULL, &st);

    if (measured == 0) {
        return;
    }

    buf = malloc(measured);

    if (buf == NULL) {
        return;
    }

    p = (u_char *)s3_ssh3_cm_encode_status_json(buf, &st);
    written = (uintptr_t)(p - buf);

    if (written != measured) {
        s3_fuzz_trap();
    }

    s3_fuzz_sink(measured);

    free(buf);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    const u_char      *pos, *end;
    s3_ssh3_cm_frame_t f;
    s3_int_t           rc;

    pos = (const u_char *)data;
    end = pos + size;

    for (;;) {
        rc = s3_ssh3_cm_frame(&pos, end, &f);

        if (rc != S3_OK) {
            break;
        }

        s3_fuzz_sink(f.type);
        s3_fuzz_sink(f.payload.len);

        s3_fuzz_cm_payload(&f);
    }

    s3_fuzz_cm_status_json(data, size);
    s3_fuzz_sink((size_t)(pos - (const u_char *)data));

    return 0;
}
