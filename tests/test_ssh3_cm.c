/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the ControlMaster codec and state machines: the literal wire
 * vectors hand-derived from the Go reference client/cm (WriteFrame,
 * OpenSession.Encode, Attach.Encode) as the byte-compat proof, the
 * strictness of every decoder, the frame layer edge cases and the
 * master/slave loops against canned peers
 */

#include <s3_core.h>

#include <s3_ssh3_cm.h>

#include "s3_test.h"

#include <string.h>

#define S3_TEST_CMDS_CAP 8

typedef struct {
    unsigned open_called;
    unsigned bridge_called;
    unsigned status_called;
    int      open_rc;
    u_char   token_base; /* the first byte of the generated token */

    u_char bridge_token[S3_SSH3_CM_TOKEN_LEN];

    /* the parsed request, copied inside the callback: the views die
       with the receive tail shift */
    uint32_t ncommand;
    char     command[S3_TEST_CMDS_CAP][32];
    uint32_t nenv;
    char     env[S3_TEST_CMDS_CAP][32];
    unsigned forward_agent;
} s3_test_srv_ctx_t;

typedef struct {
    u_char  token[S3_SSH3_CM_TOKEN_LEN];
    uint8_t kind;
} s3_test_attach_out_t;

#define S3_TEST_STR(buf, n) (&(s3_str_t){.len = (n), .data = (u_char *)(buf)})

static int s3_test_literals(void);
static int s3_test_frame_layer(void);
static int s3_test_open_session(void);
static int s3_test_status_json(void);
static int s3_test_srv(void);
static int s3_test_cli(void);

static s3_int_t s3_test_open_session_cb(void *ctx, const s3_ssh3_cm_open_session_t *req,
                                        u_char token[S3_SSH3_CM_TOKEN_LEN], const char **err);

static void s3_test_bridge_cb(void *ctx, const u_char token[S3_SSH3_CM_TOKEN_LEN]);

static s3_int_t s3_test_status_cb(void *ctx, s3_ssh3_cm_status_t *st);

static void s3_test_srv_feed(s3_ssh3_cm_srv_t *t, const u_char *data, size_t len, u_char *out,
                             size_t *out_len);
static void s3_test_cli_feed(s3_ssh3_cm_cli_t *t, const u_char *data, size_t len, u_char *out,
                             size_t *out_len);

static void s3_test_attach_frame(u_char *frame, u_char base, uint8_t kind);

static void s3_test_prefix_sweep(s3_int_t (*decode)(const void *body, void *out), void *out,
                                 const u_char *body, size_t len, unsigned trailing_must_fail);

static s3_int_t s3_test_decode_open(const void *body, void *out);
static s3_int_t s3_test_decode_attach(const void *body, void *out);
static s3_int_t s3_test_decode_exit_status(const void *body, void *out);
static s3_int_t s3_test_decode_control_op(const void *body, void *out);

/*
 * the wire vectors, byte by byte from the Go encoder: WriteFrame puts
 * the magic 'S3CM', the version 1, the type byte and the big-endian
 * payload length; OpenSession.Encode appends the command list, the
 * env list, the pty flag 0 and the agent byte
 */

static const u_char s3_test_hello[] = {
    'S', '3', 'C', 'M', 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
};

static const u_char s3_test_ok[] = {
    'S', '3', 'C', 'M', 0x01, 0x06, 0x00, 0x00, 0x00, 0x00,
};

static const u_char s3_test_exit[] = {
    'S', '3', 'C', 'M', 0x01, 0x05, 0x00, 0x00, 0x00, 0x00,
};

/* Error "boom": the raw text payload Call surfaces as an error */
static const u_char s3_test_error[] = {
    'S', '3', 'C', 'M', 0x01, 0x07, 0x00, 0x00, 0x00, 0x04, 'b', 'o', 'o', 'm',
};

/* ExitStatus 3, the 8-byte big-endian uint64 of messages.go */
static const u_char s3_test_exit_status[] = {
    'S',  '3',  'C',  'M',  0x01, 0x09, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
};

/* OpenSession {["ls", "-l"], ["A=B"], no pty, no agent}, 29 bytes of payload */
static const u_char
    s3_test_open_frame[] =
        {
            'S',  '3',  'C',  'M',  0x01, 0x02, 0x00, 0x00,
            0x00, 0x1D, 0x00, 0x00, 0x00, 0x02, /* 2 commands */
            0x00, 0x00, 0x00, 0x02, 'l',  's',  0x00, 0x00,
            0x00, 0x02, '-',  'l',  0x00, 0x00, 0x00, 0x01, /* 1 env */
            0x00, 0x00, 0x00, 0x03, 'A',  '=',  'B',  0x00, /* no pty */
            0x00,                                           /* no agent */
};

/* OpenSession {["true"], [], no pty, ForwardAgent}, 18 bytes of payload */
static const u_char s3_test_open_agent_frame[] = {
    'S',  '3',  'C',  'M',  0x01, 0x02, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x04, 't',  'r',  'u',  'e',  0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
};

/* Attach with the token 00..0f, the io stream */
static const u_char s3_test_attach_io[] = {
    'S',  '3',  'C',  'M',  0x01, 0x08, 0x00, 0x00, 0x00, 0x11, 0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00,
};

/* the same token, the stderr stream */
static const u_char s3_test_attach_stderr[] = {
    'S',  '3',  'C',  'M',  0x01, 0x08, 0x00, 0x00, 0x00, 0x11, 0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x01,
};

/* ControlOp "check", the length-prefixed op name of control.go */
static const u_char s3_test_control_check[] = {
    'S',  '3',  'C',  'M',  0x01, 0x0C, 0x00, 0x00, 0x00, 0x09,
    0x00, 0x00, 0x00, 0x05, 'c',  'h',  'e',  'c',  'k',
};

/* the OK(token) reply of a successful OpenSession, the test token a0..af */
static const u_char s3_test_ok_token[] = {
    'S',  '3',  'C',  'M',  0x01, 0x06, 0x00, 0x00, 0x00, 0x10, 0xa0, 0xa1, 0xa2,
    0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
};

static s3_int_t
s3_test_open_session_cb(void *ctx, const s3_ssh3_cm_open_session_t *req,
                        u_char token[S3_SSH3_CM_TOKEN_LEN], const char **err)
{
    s3_test_srv_ctx_t *c = ctx;
    uint32_t           i;
    size_t             n;

    c->open_called++;

    if (c->open_rc != S3_OK) {
        *err = "refused by the test";
        return S3_ERROR;
    }

    c->ncommand = req->ncommand < S3_TEST_CMDS_CAP ? req->ncommand : S3_TEST_CMDS_CAP;

    for (i = 0; i < c->ncommand; i++) {
        n = req->command[i].len < sizeof(c->command[0]) ? req->command[i].len
                                                        : sizeof(c->command[0]) - 1;
        s3_memcpy(c->command[i], req->command[i].data, n);
        c->command[i][n] = '\0';
    }

    c->nenv = req->nenv < S3_TEST_CMDS_CAP ? req->nenv : S3_TEST_CMDS_CAP;

    for (i = 0; i < c->nenv; i++) {
        n = req->env[i].len < sizeof(c->env[0]) ? req->env[i].len : sizeof(c->env[0]) - 1;
        s3_memcpy(c->env[i], req->env[i].data, n);
        c->env[i][n] = '\0';
    }

    c->forward_agent = req->forward_agent;

    for (i = 0; i < S3_SSH3_CM_TOKEN_LEN; i++) {
        token[i] = (u_char)(c->token_base + i);
    }

    return S3_OK;
}

static void
s3_test_bridge_cb(void *ctx, const u_char token[S3_SSH3_CM_TOKEN_LEN])
{
    s3_test_srv_ctx_t *c = ctx;

    c->bridge_called++;
    s3_memcpy(c->bridge_token, token, S3_SSH3_CM_TOKEN_LEN);
}

static s3_int_t
s3_test_status_cb(void *ctx, s3_ssh3_cm_status_t *st)
{
    s3_test_srv_ctx_t *c = ctx;

    c->status_called++;

    st->path = "/run/ssh3-cm-test.sock";
    st->pid = 4242;
    st->protocol = 1;
    st->uptime_s = 1.5;
    st->sessions = 2;
    st->forwards = 0;

    return S3_OK;
}

static void
s3_test_srv_feed(s3_ssh3_cm_srv_t *t, const u_char *data, size_t len, u_char *out, size_t *out_len)
{
    ssize_t n;

    S3_ASSERT(s3_ssh3_cm_srv_input(t, data, len) == S3_OK);

    n = s3_ssh3_cm_srv_output(t, out, 4096);

    S3_ASSERT(n >= 0);

    *out_len = (size_t)n;
}

static void
s3_test_cli_feed(s3_ssh3_cm_cli_t *t, const u_char *data, size_t len, u_char *out, size_t *out_len)
{
    ssize_t n;

    S3_ASSERT(s3_ssh3_cm_cli_input(t, data, len) == S3_OK);

    n = s3_ssh3_cm_cli_output(t, out, 4096);

    S3_ASSERT(n >= 0);

    *out_len = (size_t)n;
}

/*
 * every proper prefix of a strict payload is an error and so is the
 * trailing garbage; the control op tolerates the trailing bytes (the
 * Go decodeControlOp contract), the sweep copies the body so the
 * trailing case reads the spare byte
 */

static void
s3_test_prefix_sweep(s3_int_t (*decode)(const void *body, void *out), void *out, const u_char *body,
                     size_t len, unsigned trailing_must_fail)
{
    u_char   buf[128];
    s3_str_t b;
    size_t   i;

    S3_ASSERT(len + 1 <= sizeof(buf));

    s3_memcpy(buf, body, len);
    buf[len] = 'x';

    for (i = 0; i < len; i++) {
        b.data = buf;
        b.len = i;

        S3_ASSERT(decode(&b, out) == S3_ERROR);
    }

    b.data = buf;
    b.len = len + 1;

    if (trailing_must_fail) {
        S3_ASSERT(decode(&b, out) == S3_ERROR);
    }
}

static s3_int_t
s3_test_decode_open(const void *body, void *out)
{
    return s3_ssh3_cm_decode_open_session(body, out);
}

static s3_int_t
s3_test_decode_attach(const void *body, void *out)
{
    s3_test_attach_out_t *a = out;

    return s3_ssh3_cm_decode_attach(body, a->token, &a->kind);
}

static s3_int_t
s3_test_decode_exit_status(const void *body, void *out)
{
    return s3_ssh3_cm_decode_exit_status(body, out);
}

static s3_int_t
s3_test_decode_control_op(const void *body, void *out)
{
    return s3_ssh3_cm_decode_control_op(body, out);
}

/*
 * the attach request for the session with the token base..base+15,
 * built by the encoder under test (the literals above prove the wire
 * bytes, the flows need the tokens of the registered sessions)
 */

static void
s3_test_attach_frame(u_char *frame, u_char base, uint8_t kind)
{
    u_char payload[S3_SSH3_CM_TOKEN_LEN + 1];
    size_t i;

    for (i = 0; i < S3_SSH3_CM_TOKEN_LEN; i++) {
        payload[i] = (u_char)(base + i);
    }

    payload[S3_SSH3_CM_TOKEN_LEN] = kind;

    (void)s3_ssh3_cm_encode_frame(frame, S3_SSH3_CM_MSG_ATTACH,
                                  S3_TEST_STR(payload, S3_SSH3_CM_TOKEN_LEN + 1));
}

/*
 * the byte-compat proof: every literal above must come back byte for
 * byte from the C encoders
 */

static int
s3_test_literals(void)
{
    u_char                    payload[64];
    u_char                    frame[128];
    s3_str_t                  p;
    s3_ssh3_cm_open_session_t req;
    u_char                    token[S3_SSH3_CM_TOKEN_LEN];
    uintptr_t                 n;
    uint32_t                  i;

    /* Hello, OK, Exit: the empty payloads */

    S3_ASSERT(s3_ssh3_cm_encode_frame(NULL, S3_SSH3_CM_MSG_HELLO, NULL) == sizeof(s3_test_hello));
    S3_ASSERT(s3_ssh3_cm_encode_frame(frame, S3_SSH3_CM_MSG_HELLO, NULL) ==
              (uintptr_t)(frame + sizeof(s3_test_hello)));
    S3_ASSERT(memcmp(frame, s3_test_hello, sizeof(s3_test_hello)) == 0);

    p.len = 0;
    p.data = NULL;

    S3_ASSERT(s3_ssh3_cm_encode_frame(frame, S3_SSH3_CM_MSG_OK, &p) ==
              (uintptr_t)(frame + sizeof(s3_test_ok)));
    S3_ASSERT(memcmp(frame, s3_test_ok, sizeof(s3_test_ok)) == 0);

    S3_ASSERT(s3_ssh3_cm_encode_frame(frame, S3_SSH3_CM_MSG_EXIT, NULL) ==
              (uintptr_t)(frame + sizeof(s3_test_exit)));
    S3_ASSERT(memcmp(frame, s3_test_exit, sizeof(s3_test_exit)) == 0);

    /* Error "boom" */

    p.len = 4;
    p.data = (u_char *)"boom";

    S3_ASSERT(s3_ssh3_cm_encode_frame(frame, S3_SSH3_CM_MSG_ERROR, &p) ==
              (uintptr_t)(frame + sizeof(s3_test_error)));
    S3_ASSERT(memcmp(frame, s3_test_error, sizeof(s3_test_error)) == 0);

    /* ExitStatus 3 */

    S3_ASSERT(s3_ssh3_cm_encode_exit_status(NULL, 3) == 8);
    S3_ASSERT(s3_ssh3_cm_encode_exit_status(payload, 3) == (uintptr_t)(payload + 8));

    S3_ASSERT(s3_ssh3_cm_encode_frame(NULL, S3_SSH3_CM_MSG_EXIT_STATUS, S3_TEST_STR(payload, 8)) ==
              sizeof(s3_test_exit_status));
    S3_ASSERT(s3_ssh3_cm_encode_frame(frame, S3_SSH3_CM_MSG_EXIT_STATUS, S3_TEST_STR(payload, 8)) ==
              (uintptr_t)(frame + sizeof(s3_test_exit_status)));
    S3_ASSERT(memcmp(frame, s3_test_exit_status, sizeof(s3_test_exit_status)) == 0);

    /* OpenSession without the agent */

    s3_memzero(&req, sizeof(req));

    req.ncommand = 2;
    req.command[0].data = (u_char *)"ls";
    req.command[0].len = 2;
    req.command[1].data = (u_char *)"-l";
    req.command[1].len = 2;
    req.nenv = 1;
    req.env[0].data = (u_char *)"A=B";
    req.env[0].len = 3;

    S3_ASSERT(s3_ssh3_cm_encode_open_session(NULL, &req) == 29);

    n = s3_ssh3_cm_encode_open_session(payload, &req);
    S3_ASSERT(n == (uintptr_t)(payload + 29));

    S3_ASSERT(s3_ssh3_cm_encode_frame(NULL, S3_SSH3_CM_MSG_OPEN_SESSION,
                                      S3_TEST_STR(payload, 29)) == sizeof(s3_test_open_frame));
    S3_ASSERT(
        s3_ssh3_cm_encode_frame(frame, S3_SSH3_CM_MSG_OPEN_SESSION, S3_TEST_STR(payload, 29)) ==
        (uintptr_t)(frame + sizeof(s3_test_open_frame)));
    S3_ASSERT(memcmp(frame, s3_test_open_frame, sizeof(s3_test_open_frame)) == 0);

    /* OpenSession with ForwardAgent */

    s3_memzero(&req, sizeof(req));

    req.ncommand = 1;
    req.command[0].data = (u_char *)"true";
    req.command[0].len = 4;
    req.forward_agent = 1;

    S3_ASSERT(s3_ssh3_cm_encode_open_session(NULL, &req) == 18);

    n = s3_ssh3_cm_encode_open_session(payload, &req);
    S3_ASSERT(n == (uintptr_t)(payload + 18));

    S3_ASSERT(
        s3_ssh3_cm_encode_frame(frame, S3_SSH3_CM_MSG_OPEN_SESSION, S3_TEST_STR(payload, 18)) ==
        (uintptr_t)(frame + sizeof(s3_test_open_agent_frame)));
    S3_ASSERT(memcmp(frame, s3_test_open_agent_frame, sizeof(s3_test_open_agent_frame)) == 0);

    /* Attach, both stream kinds */

    for (i = 0; i < S3_SSH3_CM_TOKEN_LEN; i++) {
        token[i] = (u_char)i;
    }

    S3_ASSERT(s3_ssh3_cm_encode_attach(NULL, token, S3_SSH3_CM_STREAM_IO) == 17);

    n = s3_ssh3_cm_encode_attach(payload, token, S3_SSH3_CM_STREAM_IO);
    S3_ASSERT(n == (uintptr_t)(payload + 17));

    S3_ASSERT(s3_ssh3_cm_encode_frame(frame, S3_SSH3_CM_MSG_ATTACH, S3_TEST_STR(payload, 17)) ==
              (uintptr_t)(frame + sizeof(s3_test_attach_io)));
    S3_ASSERT(memcmp(frame, s3_test_attach_io, sizeof(s3_test_attach_io)) == 0);

    n = s3_ssh3_cm_encode_attach(payload, token, S3_SSH3_CM_STREAM_STDERR);
    S3_ASSERT(n == (uintptr_t)(payload + 17));

    S3_ASSERT(s3_ssh3_cm_encode_frame(frame, S3_SSH3_CM_MSG_ATTACH, S3_TEST_STR(payload, 17)) ==
              (uintptr_t)(frame + sizeof(s3_test_attach_stderr)));
    S3_ASSERT(memcmp(frame, s3_test_attach_stderr, sizeof(s3_test_attach_stderr)) == 0);

    /* ControlOp "check" */

    S3_ASSERT(s3_ssh3_cm_encode_control_op(NULL, S3_TEST_STR("check", 5)) == 9);

    n = s3_ssh3_cm_encode_control_op(payload, S3_TEST_STR("check", 5));
    S3_ASSERT(n == (uintptr_t)(payload + 9));

    S3_ASSERT(s3_ssh3_cm_encode_frame(frame, S3_SSH3_CM_MSG_CONTROL_OP, S3_TEST_STR(payload, 9)) ==
              (uintptr_t)(frame + sizeof(s3_test_control_check)));
    S3_ASSERT(memcmp(frame, s3_test_control_check, sizeof(s3_test_control_check)) == 0);

    /* the payload cap: the measure pass refuses above 1 MiB */

    S3_ASSERT(s3_ssh3_cm_encode_frame(NULL, S3_SSH3_CM_MSG_OK,
                                      S3_TEST_STR(NULL, S3_SSH3_CM_MAX_FRAME + 1)) == 0);

    return s3_test_failures;
}

static int
s3_test_frame_layer(void)
{
    static u_char      big[S3_SSH3_CM_HEADER_LEN + S3_SSH3_CM_MAX_FRAME];
    u_char             buf[64];
    const u_char      *pos, *end;
    s3_ssh3_cm_frame_t f;
    size_t             i;

    s3_memcpy(buf, s3_test_attach_io, sizeof(s3_test_attach_io));

    /* every proper prefix needs more bytes, the position never moves */

    for (i = 0; i < sizeof(s3_test_attach_io); i++) {
        pos = buf;
        end = buf + i;

        S3_ASSERT(s3_ssh3_cm_frame(&pos, end, &f) == S3_AGAIN);
        S3_ASSERT(pos == buf);
    }

    pos = buf;
    end = buf + sizeof(s3_test_attach_io);

    S3_ASSERT(s3_ssh3_cm_frame(&pos, end, &f) == S3_OK);
    S3_ASSERT(f.type == S3_SSH3_CM_MSG_ATTACH);
    S3_ASSERT(f.payload.len == 17);
    S3_ASSERT(f.payload.data == buf + S3_SSH3_CM_HEADER_LEN);
    S3_ASSERT(pos == end);

    /* the stream ends exactly at the frame: one more read wants more */

    S3_ASSERT(s3_ssh3_cm_frame(&pos, end, &f) == S3_AGAIN);

    /* the byte behind the frame stays in the buffer unconsumed: the
       strictness of the payload decoders, not of the frame layer */

    buf[sizeof(s3_test_attach_io)] = 'x';

    pos = buf;
    end = buf + sizeof(s3_test_attach_io) + 1;

    S3_ASSERT(s3_ssh3_cm_frame(&pos, end, &f) == S3_OK);
    S3_ASSERT(pos == buf + sizeof(s3_test_attach_io));

    /* the bad magic dies at every position of the tag */

    for (i = 0; i < 4; i++) {
        s3_memcpy(buf, s3_test_attach_io, sizeof(s3_test_attach_io));
        buf[i] ^= 0xff;

        pos = buf;
        end = buf + sizeof(s3_test_attach_io);

        S3_ASSERT(s3_ssh3_cm_frame(&pos, end, &f) == S3_ERROR);
    }

    /* the version mismatch, both directions */

    for (i = 0; i < 2; i++) {
        s3_memcpy(buf, s3_test_attach_io, sizeof(s3_test_attach_io));
        buf[4] = i == 0 ? 0 : 2;

        pos = buf;
        end = buf + sizeof(s3_test_attach_io);

        S3_ASSERT(s3_ssh3_cm_frame(&pos, end, &f) == S3_ERROR);
    }

    /* the oversize length dies before the payload arrives */

    s3_memcpy(buf, s3_test_attach_io, sizeof(s3_test_attach_io));
    buf[6] = (u_char)(S3_SSH3_CM_MAX_FRAME >> 24);
    buf[7] = (u_char)((S3_SSH3_CM_MAX_FRAME >> 16) + 1);

    pos = buf;
    end = buf + S3_SSH3_CM_HEADER_LEN;

    S3_ASSERT(s3_ssh3_cm_frame(&pos, end, &f) == S3_ERROR);

    /* the boundary: exactly 1 MiB of payload parses */

    s3_memzero(big, sizeof(big));

    big[0] = 'S';
    big[1] = '3';
    big[2] = 'C';
    big[3] = 'M';
    big[4] = S3_SSH3_CM_VERSION;
    big[5] = S3_SSH3_CM_MSG_OK;
    big[7] = (u_char)(S3_SSH3_CM_MAX_FRAME >> 16);

    pos = big;
    end = big + sizeof(big);

    S3_ASSERT(s3_ssh3_cm_frame(&pos, end, &f) == S3_OK);
    S3_ASSERT(f.payload.len == S3_SSH3_CM_MAX_FRAME);
    S3_ASSERT(pos == end);

    /* the type byte is not policed at the frame layer, the peer
       dispatch refuses the unknown ones */

    s3_memcpy(buf, s3_test_hello, sizeof(s3_test_hello));
    buf[5] = 200;

    pos = buf;
    end = buf + sizeof(s3_test_hello);

    S3_ASSERT(s3_ssh3_cm_frame(&pos, end, &f) == S3_OK);
    S3_ASSERT(f.type == 200);

    return s3_test_failures;
}

static int
s3_test_open_session(void)
{
    u_char                    payload[64];
    u_char                    token[S3_SSH3_CM_TOKEN_LEN];
    uint8_t                   kind;
    s3_str_t                  body;
    s3_ssh3_cm_open_session_t req;
    s3_test_attach_out_t      att;
    uint64_t                  code;
    uintptr_t                 n;

    /* the roundtrip of the vector payload */

    body.data = (u_char *)s3_test_open_frame + S3_SSH3_CM_HEADER_LEN;
    body.len = sizeof(s3_test_open_frame) - S3_SSH3_CM_HEADER_LEN;

    s3_memzero(&req, sizeof(req));

    S3_ASSERT(s3_ssh3_cm_decode_open_session(&body, &req) == S3_OK);
    S3_ASSERT(req.ncommand == 2);
    S3_ASSERT(req.command[0].len == 2 && req.command[0].data[0] == 'l');
    S3_ASSERT(req.command[1].len == 2 && req.command[1].data[0] == '-');
    S3_ASSERT(req.nenv == 1);
    S3_ASSERT(req.env[0].len == 3);
    S3_ASSERT(req.forward_agent == 0);

    /* the views point into the caller buffer, zero-copy */

    S3_ASSERT(req.command[0].data == body.data + 8);

    /* the agent roundtrip */

    body.data = (u_char *)s3_test_open_agent_frame + S3_SSH3_CM_HEADER_LEN;
    body.len = sizeof(s3_test_open_agent_frame) - S3_SSH3_CM_HEADER_LEN;

    s3_memzero(&req, sizeof(req));

    S3_ASSERT(s3_ssh3_cm_decode_open_session(&body, &req) == S3_OK);
    S3_ASSERT(req.ncommand == 1);
    S3_ASSERT(req.nenv == 0);
    S3_ASSERT(req.forward_agent == 1);

    /* encode what was decoded, the same bytes come back */

    n = s3_ssh3_cm_encode_open_session(payload, &req);

    S3_ASSERT(n == (uintptr_t)(payload + 18));
    S3_ASSERT(memcmp(payload, body.data, 18) == 0);

    /* the empty env list roundtrip */

    s3_memzero(&req, sizeof(req));
    req.ncommand = 1;
    req.command[0].data = (u_char *)"sh";
    req.command[0].len = 2;

    n = s3_ssh3_cm_encode_open_session(payload, &req);
    S3_ASSERT(n == (uintptr_t)(payload + 16));

    body.data = payload;
    body.len = 16;

    s3_memzero(&req, sizeof(req));
    S3_ASSERT(s3_ssh3_cm_decode_open_session(&body, &req) == S3_OK);
    S3_ASSERT(req.ncommand == 1);
    S3_ASSERT(req.command[0].len == 2);
    S3_ASSERT(req.nenv == 0);
    S3_ASSERT(req.forward_agent == 0);

    /* the strictness: the prefix sweep plus the pty refusal */

    s3_test_prefix_sweep(s3_test_decode_open, &req, s3_test_open_frame + S3_SSH3_CM_HEADER_LEN,
                         sizeof(s3_test_open_frame) - S3_SSH3_CM_HEADER_LEN, 1);

    /* the pty flag 1 is the v1+ request, refused in v0: the flag byte
       sits right before the agent byte */

    s3_memzero(&req, sizeof(req));
    req.ncommand = 1;
    req.command[0].data = (u_char *)"sh";
    req.command[0].len = 2;

    n = s3_ssh3_cm_encode_open_session(payload, &req);
    S3_ASSERT(n == (uintptr_t)(payload + 16));

    payload[14] = 1;

    S3_ASSERT(s3_ssh3_cm_decode_open_session(S3_TEST_STR(payload, 16), &req) == S3_ERROR);

    /* the hostile counts: above the cap and above the remaining bytes */

    payload[0] = 0;
    payload[1] = 0;
    payload[2] = 0;
    payload[3] = (u_char)(S3_SSH3_CM_LIST_MAX + 1);

    S3_ASSERT(s3_ssh3_cm_decode_open_session(S3_TEST_STR(payload, 4), &req) == S3_ERROR);

    payload[3] = 0xff;

    S3_ASSERT(s3_ssh3_cm_decode_open_session(S3_TEST_STR(payload, 4), &req) == S3_ERROR);

    /* the attach strictness and the roundtrip, both kinds */

    s3_test_prefix_sweep(s3_test_decode_attach, &att, s3_test_attach_io + S3_SSH3_CM_HEADER_LEN,
                         sizeof(s3_test_attach_io) - S3_SSH3_CM_HEADER_LEN, 1);

    body.data = (u_char *)s3_test_attach_io + S3_SSH3_CM_HEADER_LEN;
    body.len = 17;

    S3_ASSERT(s3_ssh3_cm_decode_attach(&body, token, &kind) == S3_OK);
    S3_ASSERT(kind == S3_SSH3_CM_STREAM_IO);

    for (n = 0; n < S3_SSH3_CM_TOKEN_LEN; n++) {
        S3_ASSERT(token[n] == n);
    }

    body.data = (u_char *)s3_test_attach_stderr + S3_SSH3_CM_HEADER_LEN;

    S3_ASSERT(s3_ssh3_cm_decode_attach(&body, token, &kind) == S3_OK);
    S3_ASSERT(kind == S3_SSH3_CM_STREAM_STDERR);

    /* the unknown stream kind is an error */

    s3_memcpy(payload, s3_test_attach_io + S3_SSH3_CM_HEADER_LEN, 17);
    payload[16] = 9;

    S3_ASSERT(s3_ssh3_cm_decode_attach(S3_TEST_STR(payload, 17), token, &kind) == S3_ERROR);

    /* the exit status */

    body.data = (u_char *)s3_test_exit_status + S3_SSH3_CM_HEADER_LEN;
    body.len = 8;

    S3_ASSERT(s3_ssh3_cm_decode_exit_status(&body, &code) == S3_OK);
    S3_ASSERT(code == 3);

    s3_test_prefix_sweep(s3_test_decode_exit_status, &code,
                         s3_test_exit_status + S3_SSH3_CM_HEADER_LEN, 8, 1);

    S3_ASSERT(s3_ssh3_cm_encode_exit_status(payload, 0) == (uintptr_t)(payload + 8));
    S3_ASSERT(s3_ssh3_cm_decode_exit_status(S3_TEST_STR(payload, 8), &code) == S3_OK);
    S3_ASSERT(code == 0);

    /* the control op: the truncated length prefix is an error, the
       trailing bytes are ignored like the Go decodeControlOp */

    s3_memcpy(payload, s3_test_control_check + S3_SSH3_CM_HEADER_LEN, 9);
    payload[9] = 'x';

    S3_ASSERT(s3_ssh3_cm_decode_control_op(S3_TEST_STR(payload, 10), &body) == S3_OK);
    S3_ASSERT(body.len == 5);
    S3_ASSERT(memcmp(body.data, "check", 5) == 0);

    s3_test_prefix_sweep(s3_test_decode_control_op, &body,
                         s3_test_control_check + S3_SSH3_CM_HEADER_LEN, 9, 0);

    return s3_test_failures;
}

static int
s3_test_status_json(void)
{
    static const char   want[] = "{\"path\":\"/run/ssh3-cm-test.sock\",\"pid\":4242,\"protocol\":1,"
                                 "\"uptime_s\":1.500,\"sessions\":2,\"forwards\":0}";
    u_char              buf[512];
    s3_ssh3_cm_status_t st;
    uintptr_t           n;

    st.path = "/run/ssh3-cm-test.sock";
    st.pid = 4242;
    st.protocol = 1;
    st.uptime_s = 1.5;
    st.sessions = 2;
    st.forwards = 0;

    S3_ASSERT(s3_ssh3_cm_encode_status_json(NULL, &st) == sizeof(want) - 1);
    S3_ASSERT(s3_ssh3_cm_encode_status_json(buf, &st) == (uintptr_t)(buf + sizeof(want) - 1));
    S3_ASSERT(memcmp(buf, want, sizeof(want) - 1) == 0);

    /* the escaping of the quote and the backslash in the path */

    st.path = "a\"b\\c";

    n = sizeof("{\"path\":\"a\\\"b\\\\c\",\"pid\":4242,\"protocol\":1,"
               "\"uptime_s\":1.500,\"sessions\":2,\"forwards\":0}") -
        1;

    S3_ASSERT(s3_ssh3_cm_encode_status_json(buf, &st) == (uintptr_t)(buf + n));

    /* the empty path and the zero uptime */

    st.path = "";
    st.pid = 1;
    st.uptime_s = 0.0;

    n = sizeof("{\"path\":\"\",\"pid\":1,\"protocol\":1,\"uptime_s\":0.000,"
               "\"sessions\":2,\"forwards\":0}") -
        1;

    S3_ASSERT(s3_ssh3_cm_encode_status_json(buf, &st) == (uintptr_t)(buf + n));

    return s3_test_failures;
}

static int
s3_test_srv(void)
{
    u_char                out[4096];
    size_t                out_len;
    s3_pool_t            *pool;
    s3_log_t              log;
    s3_ssh3_cm_sessions_t sessions;
    s3_ssh3_cm_srv_t      srv, srv2, srv3;
    s3_ssh3_cm_srv_cbs_t  cbs;
    s3_test_srv_ctx_t     ctx;
    u_char                req_payload[16];
    u_char                req_frame[64];
    u_char                att_frame[32];

    log.log_level = S3_LOG_ALERT;
    log.fd = S3_INVALID_FILE;

    pool = s3_create_pool(S3_DEFAULT_POOL_SIZE, &log);

    S3_ASSERT(pool != NULL);
    S3_ASSERT(s3_ssh3_cm_sessions_init(&sessions, pool) == S3_OK);

    s3_memzero(&cbs, sizeof(cbs));
    cbs.open_session = s3_test_open_session_cb;
    cbs.bridge = s3_test_bridge_cb;
    cbs.status = s3_test_status_cb;

    s3_memzero(&ctx, sizeof(ctx));
    ctx.open_rc = S3_OK;
    ctx.token_base = 0xa0;

    /* the first connection: hello, open session */

    S3_ASSERT(s3_ssh3_cm_srv_init(&srv, pool, &sessions, &cbs, &ctx) == S3_OK);
    S3_ASSERT(s3_ssh3_cm_srv_done(&srv) == 0);
    S3_ASSERT(s3_ssh3_cm_srv_shutdown(&srv) == 0);

    /* the handshake: the literal OK comes back */

    s3_test_srv_feed(&srv, s3_test_hello, sizeof(s3_test_hello), out, &out_len);
    S3_ASSERT(out_len == sizeof(s3_test_ok));
    S3_ASSERT(memcmp(out, s3_test_ok, sizeof(s3_test_ok)) == 0);

    /* the session open: the app callback fires with the parsed views
       and the OK(token) literal comes back */

    s3_test_srv_feed(&srv, s3_test_open_frame, sizeof(s3_test_open_frame), out, &out_len);

    S3_ASSERT(ctx.open_called == 1);
    S3_ASSERT(ctx.ncommand == 2);
    S3_ASSERT(strcmp(ctx.command[0], "ls") == 0);
    S3_ASSERT(strcmp(ctx.command[1], "-l") == 0);
    S3_ASSERT(ctx.nenv == 1);
    S3_ASSERT(strcmp(ctx.env[0], "A=B") == 0);
    S3_ASSERT(ctx.forward_agent == 0);

    S3_ASSERT(out_len == sizeof(s3_test_ok_token));
    S3_ASSERT(memcmp(out, s3_test_ok_token, sizeof(s3_test_ok_token)) == 0);
    S3_ASSERT(sessions.count == 1);

    /* the attachment runs over a second connection sharing the table:
       the stderr first, the io second, then the bridge starts */

    S3_ASSERT(s3_ssh3_cm_srv_init(&srv2, pool, &sessions, &cbs, &ctx) == S3_OK);

    s3_test_srv_feed(&srv2, s3_test_hello, sizeof(s3_test_hello), out, &out_len);
    S3_ASSERT(out_len == sizeof(s3_test_ok));

    s3_test_attach_frame(att_frame, 0xa0, S3_SSH3_CM_STREAM_STDERR);
    s3_test_srv_feed(&srv2, att_frame, S3_SSH3_CM_HEADER_LEN + 17, out, &out_len);
    S3_ASSERT(out_len == sizeof(s3_test_ok));
    S3_ASSERT(ctx.bridge_called == 0);

    s3_test_attach_frame(att_frame, 0xa0, S3_SSH3_CM_STREAM_IO);
    s3_test_srv_feed(&srv2, att_frame, S3_SSH3_CM_HEADER_LEN + 17, out, &out_len);
    S3_ASSERT(out_len == sizeof(s3_test_ok));
    S3_ASSERT(ctx.bridge_called == 1);
    S3_ASSERT(ctx.bridge_token[0] == 0xa0);
    S3_ASSERT(ctx.bridge_token[15] == 0xaf);

    /* the check op over a third connection, the JSON literal */

    S3_ASSERT(s3_ssh3_cm_srv_init(&srv3, pool, &sessions, &cbs, &ctx) == S3_OK);

    s3_test_srv_feed(&srv3, s3_test_hello, sizeof(s3_test_hello), out, &out_len);
    S3_ASSERT(out_len == sizeof(s3_test_ok));

    s3_test_srv_feed(&srv3, s3_test_control_check, sizeof(s3_test_control_check), out, &out_len);

    S3_ASSERT(ctx.status_called == 1);
    S3_ASSERT(out_len ==
              S3_SSH3_CM_HEADER_LEN +
                  sizeof("{\"path\":\"/run/ssh3-cm-test.sock\",\"pid\":4242,\"protocol\":1,"
                         "\"uptime_s\":1.500,\"sessions\":2,\"forwards\":0}") -
                  1);
    S3_ASSERT(memcmp(out + S3_SSH3_CM_HEADER_LEN,
                     "{\"path\":\"/run/ssh3-cm-test.sock\",\"pid\":4242,\"protocol\":1,"
                     "\"uptime_s\":1.500,\"sessions\":2,\"forwards\":0}",
                     out_len - S3_SSH3_CM_HEADER_LEN) == 0);

    /* the stop op: OK, the shutdown signal, the connection done */

    (void)s3_ssh3_cm_encode_control_op(req_payload, S3_TEST_STR("stop", 4));
    s3_ssh3_cm_encode_frame(req_frame, S3_SSH3_CM_MSG_CONTROL_OP, S3_TEST_STR(req_payload, 8));

    s3_test_srv_feed(&srv3, req_frame, S3_SSH3_CM_HEADER_LEN + 8, out, &out_len);

    S3_ASSERT(out_len == sizeof(s3_test_ok));
    S3_ASSERT(memcmp(out, s3_test_ok, sizeof(s3_test_ok)) == 0);
    S3_ASSERT(s3_ssh3_cm_srv_shutdown(&srv3) == 1);
    S3_ASSERT(s3_ssh3_cm_srv_done(&srv3) == 1);

    /* the exit message shuts the master down like master.go */

    S3_ASSERT(s3_ssh3_cm_srv_init(&srv3, pool, &sessions, &cbs, &ctx) == S3_OK);

    s3_test_srv_feed(&srv3, s3_test_hello, sizeof(s3_test_hello), out, &out_len);
    s3_test_srv_feed(&srv3, s3_test_exit, sizeof(s3_test_exit), out, &out_len);

    S3_ASSERT(out_len == sizeof(s3_test_ok));
    S3_ASSERT(s3_ssh3_cm_srv_shutdown(&srv3) == 1);
    S3_ASSERT(s3_ssh3_cm_srv_done(&srv3) == 1);

    /* the second session for the hostile attach cases */

    ctx.token_base = 0xb0;

    s3_test_srv_feed(&srv, s3_test_open_frame, sizeof(s3_test_open_frame), out, &out_len);

    S3_ASSERT(ctx.open_called == 2);
    S3_ASSERT(out_len == sizeof(s3_test_ok_token));
    S3_ASSERT(out[10] == 0xb0);
    S3_ASSERT(out[25] == 0xbf);
    S3_ASSERT(sessions.count == 2);

    /* io before stderr closes the connection */

    S3_ASSERT(s3_ssh3_cm_srv_init(&srv3, pool, &sessions, &cbs, &ctx) == S3_OK);
    s3_test_srv_feed(&srv3, s3_test_hello, sizeof(s3_test_hello), out, &out_len);

    s3_test_attach_frame(att_frame, 0xb0, S3_SSH3_CM_STREAM_IO);
    s3_test_srv_feed(&srv3, att_frame, S3_SSH3_CM_HEADER_LEN + 17, out, &out_len);

    S3_ASSERT(out_len > S3_SSH3_CM_HEADER_LEN);
    S3_ASSERT(out[5] == S3_SSH3_CM_MSG_ERROR);
    S3_ASSERT(s3_ssh3_cm_srv_done(&srv3) == 1);

    /* the unknown token closes the connection */

    S3_ASSERT(s3_ssh3_cm_srv_init(&srv3, pool, &sessions, &cbs, &ctx) == S3_OK);
    s3_test_srv_feed(&srv3, s3_test_hello, sizeof(s3_test_hello), out, &out_len);

    s3_test_attach_frame(att_frame, 0x00, S3_SSH3_CM_STREAM_IO);
    s3_test_srv_feed(&srv3, att_frame, S3_SSH3_CM_HEADER_LEN + 17, out, &out_len);

    S3_ASSERT(out[5] == S3_SSH3_CM_MSG_ERROR);
    S3_ASSERT(s3_ssh3_cm_srv_done(&srv3) == 1);

    /* the double stderr attach closes the connection */

    S3_ASSERT(s3_ssh3_cm_srv_init(&srv3, pool, &sessions, &cbs, &ctx) == S3_OK);
    s3_test_srv_feed(&srv3, s3_test_hello, sizeof(s3_test_hello), out, &out_len);

    s3_test_attach_frame(att_frame, 0xb0, S3_SSH3_CM_STREAM_STDERR);
    s3_test_srv_feed(&srv3, att_frame, S3_SSH3_CM_HEADER_LEN + 17, out, &out_len);
    S3_ASSERT(out[5] == S3_SSH3_CM_MSG_OK);
    S3_ASSERT(s3_ssh3_cm_srv_done(&srv3) == 0);

    s3_test_srv_feed(&srv3, att_frame, S3_SSH3_CM_HEADER_LEN + 17, out, &out_len);

    S3_ASSERT(out[5] == S3_SSH3_CM_MSG_ERROR);
    S3_ASSERT(s3_ssh3_cm_srv_done(&srv3) == 1);

    /* the unknown message type (the v1 forward) is refused */

    S3_ASSERT(s3_ssh3_cm_srv_init(&srv3, pool, &sessions, &cbs, &ctx) == S3_OK);
    s3_test_srv_feed(&srv3, s3_test_hello, sizeof(s3_test_hello), out, &out_len);

    s3_memcpy(out, s3_test_hello, sizeof(s3_test_hello));
    out[5] = S3_SSH3_CM_MSG_OPEN_FORWARD_TCP;

    s3_test_srv_feed(&srv3, out, sizeof(s3_test_hello), out, &out_len);

    S3_ASSERT(out[5] == S3_SSH3_CM_MSG_ERROR);
    S3_ASSERT(s3_ssh3_cm_srv_done(&srv3) == 1);

    /* the hello-less dialer gets the reference refusal, the session
       callback never fires */

    S3_ASSERT(s3_ssh3_cm_srv_init(&srv3, pool, &sessions, &cbs, &ctx) == S3_OK);
    s3_test_srv_feed(&srv3, s3_test_open_frame, sizeof(s3_test_open_frame), out, &out_len);

    S3_ASSERT(ctx.open_called == 2);
    S3_ASSERT(out_len > S3_SSH3_CM_HEADER_LEN);
    S3_ASSERT(out[5] == S3_SSH3_CM_MSG_ERROR);
    S3_ASSERT(s3_ssh3_cm_srv_done(&srv3) == 1);

    /* the unknown op is refused but the connection stays usable */

    S3_ASSERT(s3_ssh3_cm_srv_init(&srv3, pool, &sessions, &cbs, &ctx) == S3_OK);
    s3_test_srv_feed(&srv3, s3_test_hello, sizeof(s3_test_hello), out, &out_len);

    (void)s3_ssh3_cm_encode_control_op(req_payload, S3_TEST_STR("flurb", 5));
    s3_ssh3_cm_encode_frame(req_frame, S3_SSH3_CM_MSG_CONTROL_OP, S3_TEST_STR(req_payload, 9));

    s3_test_srv_feed(&srv3, req_frame, S3_SSH3_CM_HEADER_LEN + 9, out, &out_len);

    S3_ASSERT(out[5] == S3_SSH3_CM_MSG_ERROR);
    S3_ASSERT(s3_ssh3_cm_srv_done(&srv3) == 0);
    S3_ASSERT(s3_ssh3_cm_srv_shutdown(&srv3) == 0);

    /* the refused open session keeps the connection too */

    ctx.open_rc = S3_ERROR;

    s3_test_srv_feed(&srv3, s3_test_open_frame, sizeof(s3_test_open_frame), out, &out_len);

    S3_ASSERT(ctx.open_called == 3);
    S3_ASSERT(out[5] == S3_SSH3_CM_MSG_ERROR);
    S3_ASSERT(s3_ssh3_cm_srv_done(&srv3) == 0);
    S3_ASSERT(sessions.count == 2);

    ctx.open_rc = S3_OK;

    /* the chunked feed: the frame split across the input calls */

    S3_ASSERT(s3_ssh3_cm_srv_init(&srv3, pool, &sessions, &cbs, &ctx) == S3_OK);

    s3_test_srv_feed(&srv3, s3_test_hello, 3, out, &out_len);
    S3_ASSERT(out_len == 0);

    s3_test_srv_feed(&srv3, s3_test_hello + 3, 4, out, &out_len);
    S3_ASSERT(out_len == 0);

    s3_test_srv_feed(&srv3, s3_test_hello + 7, sizeof(s3_test_hello) - 7, out, &out_len);
    S3_ASSERT(out_len == sizeof(s3_test_ok));

    s3_destroy_pool(pool);

    return s3_test_failures;
}

static int
s3_test_cli(void)
{
    u_char                    out[4096];
    size_t                    out_len;
    s3_pool_t                *pool;
    s3_log_t                  log;
    s3_ssh3_cm_cli_t          cli;
    s3_ssh3_cm_open_session_t req;
    s3_str_t                  payload, reply;
    unsigned                  is_error;
    s3_int_t                  rc;

    log.log_level = S3_LOG_ALERT;
    log.fd = S3_INVALID_FILE;

    pool = s3_create_pool(S3_DEFAULT_POOL_SIZE, &log);

    S3_ASSERT(pool != NULL);
    S3_ASSERT(s3_ssh3_cm_cli_init(&cli, pool) == S3_OK);

    /* no reply yet: S3_AGAIN, awaiting or not */

    rc = s3_ssh3_cm_cli_reply(&cli, &reply, &is_error);
    S3_ASSERT(rc == S3_AGAIN);

    /* the handshake call */

    S3_ASSERT(s3_ssh3_cm_cli_call(&cli, S3_SSH3_CM_MSG_HELLO, NULL) == S3_OK);

    s3_test_cli_feed(&cli, NULL, 0, out, &out_len);
    S3_ASSERT(out_len == sizeof(s3_test_hello));
    S3_ASSERT(memcmp(out, s3_test_hello, sizeof(s3_test_hello)) == 0);

    S3_ASSERT(s3_ssh3_cm_cli_reply(&cli, &reply, &is_error) == S3_AGAIN);

    /* the canned master answers OK */

    s3_test_cli_feed(&cli, s3_test_ok, sizeof(s3_test_ok), out, &out_len);
    S3_ASSERT(out_len == 0);

    S3_ASSERT(s3_ssh3_cm_cli_reply(&cli, &reply, &is_error) == S3_OK);
    S3_ASSERT(is_error == 0);
    S3_ASSERT(reply.len == 0);

    /* the open session call with the literal vector request */

    s3_memzero(&req, sizeof(req));

    req.ncommand = 2;
    req.command[0].data = (u_char *)"ls";
    req.command[0].len = 2;
    req.command[1].data = (u_char *)"-l";
    req.command[1].len = 2;
    req.nenv = 1;
    req.env[0].data = (u_char *)"A=B";
    req.env[0].len = 3;

    S3_ASSERT(s3_ssh3_cm_encode_open_session(out, &req) == (uintptr_t)(out + 29));

    payload.len = 29;
    payload.data = out;

    S3_ASSERT(s3_ssh3_cm_cli_call(&cli, S3_SSH3_CM_MSG_OPEN_SESSION, &payload) == S3_OK);

    /* the nested call is refused: the client is strictly serial */

    S3_ASSERT(s3_ssh3_cm_cli_call(&cli, S3_SSH3_CM_MSG_EXIT, NULL) == S3_ERROR);

    s3_test_cli_feed(&cli, NULL, 0, out, &out_len);

    S3_ASSERT(out_len == sizeof(s3_test_open_frame));
    S3_ASSERT(memcmp(out, s3_test_open_frame, sizeof(s3_test_open_frame)) == 0);

    /* the token reply, the payload survives the input tail shift */

    s3_test_cli_feed(&cli, s3_test_ok_token, sizeof(s3_test_ok_token), out, &out_len);

    S3_ASSERT(s3_ssh3_cm_cli_reply(&cli, &reply, &is_error) == S3_OK);
    S3_ASSERT(is_error == 0);
    S3_ASSERT(reply.len == S3_SSH3_CM_TOKEN_LEN);
    S3_ASSERT(reply.data[0] == 0xa0);
    S3_ASSERT(reply.data[15] == 0xaf);

    /* the refusal of the master comes back as the error text */

    payload.len = 5;
    payload.data = (u_char *)"check";

    S3_ASSERT(s3_ssh3_cm_cli_call(&cli, S3_SSH3_CM_MSG_CONTROL_OP, &payload) == S3_OK);
    s3_test_cli_feed(&cli, NULL, 0, out, &out_len);
    s3_test_cli_feed(&cli, s3_test_error, sizeof(s3_test_error), out, &out_len);

    S3_ASSERT(s3_ssh3_cm_cli_reply(&cli, &reply, &is_error) == S3_OK);
    S3_ASSERT(is_error == 1);
    S3_ASSERT(reply.len == 4);
    S3_ASSERT(memcmp(reply.data, "boom", 4) == 0);

    /* the unsolicited frame is a protocol violation */

    s3_test_cli_feed(&cli, s3_test_ok, sizeof(s3_test_ok), out, &out_len);

    S3_ASSERT(s3_ssh3_cm_cli_protocol_error(&cli) == 1);
    S3_ASSERT(s3_ssh3_cm_cli_reply(&cli, &reply, &is_error) == S3_ERROR);

    /* the non-reply frame kills the connection state */

    S3_ASSERT(s3_ssh3_cm_cli_init(&cli, pool) == S3_OK);
    S3_ASSERT(s3_ssh3_cm_cli_call(&cli, S3_SSH3_CM_MSG_HELLO, NULL) == S3_OK);

    s3_memcpy(out, s3_test_hello, sizeof(s3_test_hello));
    out[5] = S3_SSH3_CM_MSG_OPEN_SESSION;

    s3_test_cli_feed(&cli, out, sizeof(s3_test_hello), out, &out_len);

    S3_ASSERT(s3_ssh3_cm_cli_protocol_error(&cli) == 1);

    /* the oversized reply length is a protocol violation */

    S3_ASSERT(s3_ssh3_cm_cli_init(&cli, pool) == S3_OK);
    S3_ASSERT(s3_ssh3_cm_cli_call(&cli, S3_SSH3_CM_MSG_HELLO, NULL) == S3_OK);

    s3_memcpy(out, s3_test_hello, sizeof(s3_test_hello));
    out[6] = (u_char)(S3_SSH3_CM_MAX_FRAME >> 24);
    out[7] = (u_char)((S3_SSH3_CM_MAX_FRAME >> 16) + 1);

    s3_test_cli_feed(&cli, out, sizeof(s3_test_hello), out, &out_len);

    S3_ASSERT(s3_ssh3_cm_cli_protocol_error(&cli) == 1);

    s3_destroy_pool(pool);

    return s3_test_failures;
}

int
test_ssh3_cm(void)
{
    if (s3_test_literals() != 0) {
        return s3_test_failures;
    }

    if (s3_test_frame_layer() != 0) {
        return s3_test_failures;
    }

    if (s3_test_open_session() != 0) {
        return s3_test_failures;
    }

    if (s3_test_status_json() != 0) {
        return s3_test_failures;
    }

    if (s3_test_srv() != 0) {
        return s3_test_failures;
    }

    if (s3_test_cli() != 0) {
        return s3_test_failures;
    }

    return s3_test_failures;
}

S3_TEST_MAIN(test_ssh3_cm)
