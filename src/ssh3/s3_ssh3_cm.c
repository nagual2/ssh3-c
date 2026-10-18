/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the ControlMaster control channel: the frame layer of the
 * reference client/cm/framing.go, the strict zero-copy payload
 * decoders and the measure-mode encoders of messages.go, the master
 * connection loop of client/master.go and the serial Call client of
 * protocol.go; nothing is allocated beyond the caller's pool, the
 * parsed strings stay views into the receive buffers
 */

#include <s3_core.h>

#include <s3_ssh3_cm.h>

#include <stdio.h>
#include <string.h>

#define S3_SSH3_CM_BUF_INIT 4096

/* the MasterStatus JSON keys, the struct order of client/control.go */

#define S3_CM_JSON_HEAD "{\"path\":"
#define S3_CM_JSON_PID  ",\"pid\":"
#define S3_CM_JSON_PROT ",\"protocol\":"
#define S3_CM_JSON_UP   ",\"uptime_s\":"
#define S3_CM_JSON_SESS ",\"sessions\":"
#define S3_CM_JSON_FWD  ",\"forwards\":"
#define S3_CM_JSON_TAIL "}"

static s3_inline uint32_t s3_cm_get_u32(const u_char *p);
static s3_inline uint64_t s3_cm_get_u64(const u_char *p);
static s3_inline u_char  *s3_cm_put_u32(u_char *p, uint32_t v);
static u_char            *s3_cm_put_string(u_char *p, const s3_str_t *s);
static void               s3_cm_put_head(u_char *p, uint8_t type, uint32_t len);
static s3_int_t           s3_cm_get_count(const u_char **pos, const u_char *end, uint32_t *n);
static s3_int_t           s3_cm_get_str(const u_char **pos, const u_char *end, s3_str_t *s);
static uintptr_t          s3_cm_int_size(long v);
static u_char            *s3_cm_put_int(u_char *p, long v);
static uint64_t           s3_cm_uptime_ms(const s3_ssh3_cm_status_t *st);
static uintptr_t          s3_cm_json_str_size(const char *s);
static u_char            *s3_cm_json_str_put(u_char *p, const char *s);
static s3_int_t           s3_cm_buf_append(u_char **buf, size_t *len, size_t *cap, s3_pool_t *pool,
                                           const u_char *data, size_t n);
static u_char            *s3_cm_buf_reserve(u_char **buf, size_t len, size_t *cap, s3_pool_t *pool,
                                            size_t need);
static s3_int_t           s3_cm_output(u_char *src, size_t *len, u_char *dst, size_t size);
static unsigned           s3_cm_op_is(const s3_str_t *op, const char *name);
static s3_ssh3_cm_sess_t *s3_srv_sess_find(s3_ssh3_cm_srv_t *t,
                                           const u_char      token[S3_SSH3_CM_TOKEN_LEN]);
static s3_ssh3_cm_sess_t *s3_srv_sess_alloc(s3_ssh3_cm_srv_t *t);
static s3_int_t s3_srv_reply(s3_ssh3_cm_srv_t *t, uint8_t type, const u_char *payload, size_t len);
static s3_int_t s3_srv_error(s3_ssh3_cm_srv_t *t, const char *msg);
static s3_int_t s3_srv_error_done(s3_ssh3_cm_srv_t *t, const char *msg);
static s3_int_t s3_srv_dispatch(s3_ssh3_cm_srv_t *t, s3_ssh3_cm_frame_t *f);
static s3_int_t s3_srv_open_session(s3_ssh3_cm_srv_t *t, const s3_str_t *payload);
static s3_int_t s3_srv_attach(s3_ssh3_cm_srv_t *t, const s3_str_t *payload);
static s3_int_t s3_srv_control_op(s3_ssh3_cm_srv_t *t, const s3_str_t *payload);

static const char s3_cm_hex[] = "0123456789abcdef";

/* the big-endian scalars, the wire order of the reference */

static s3_inline uint32_t
s3_cm_get_u32(const u_char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static s3_inline uint64_t
s3_cm_get_u64(const u_char *p)
{
    return ((uint64_t)s3_cm_get_u32(p) << 32) | (uint64_t)s3_cm_get_u32(p + 4);
}

static s3_inline u_char *
s3_cm_put_u32(u_char *p, uint32_t v)
{
    p[0] = (u_char)(v >> 24);
    p[1] = (u_char)(v >> 16);
    p[2] = (u_char)(v >> 8);
    p[3] = (u_char)v;

    return p + 4;
}

static u_char *
s3_cm_put_string(u_char *p, const s3_str_t *s)
{
    p = s3_cm_put_u32(p, (uint32_t)s->len);

    if (s->len != 0) {
        p = s3_cpymem(p, s->data, s->len);
    }

    return p;
}

static void
s3_cm_put_head(u_char *p, uint8_t type, uint32_t len)
{
    p[0] = 'S';
    p[1] = '3';
    p[2] = 'C';
    p[3] = 'M';
    p[4] = S3_SSH3_CM_VERSION;
    p[5] = type;

    (void)s3_cm_put_u32(p + 6, len);
}

/* the count prefix, the readCount of messages.go: each item costs at
   least the 4-byte length, so the count above the remaining bytes is
   already malformed */

static s3_int_t
s3_cm_get_count(const u_char **pos, const u_char *end, uint32_t *n)
{
    uint32_t v;

    if ((size_t)(end - *pos) < 4) {
        return S3_ERROR;
    }

    v = s3_cm_get_u32(*pos);
    *pos += 4;

    if (v > (uint32_t)((size_t)(end - *pos) / 4)) {
        return S3_ERROR;
    }

    *n = v;

    return S3_OK;
}

static s3_int_t
s3_cm_get_str(const u_char **pos, const u_char *end, s3_str_t *s)
{
    uint32_t len;

    if ((size_t)(end - *pos) < 4) {
        return S3_ERROR;
    }

    len = s3_cm_get_u32(*pos);
    *pos += 4;

    if ((size_t)(end - *pos) < len) {
        return S3_ERROR;
    }

    s->data = (u_char *)*pos;
    s->len = len;
    *pos += len;

    return S3_OK;
}

/* the frame layer, the Go ReadFrame checks in the same order */

s3_int_t
s3_ssh3_cm_frame(const u_char **pos, const u_char *end, s3_ssh3_cm_frame_t *f)
{
    const u_char *p;
    uint32_t      len;

    if (pos == NULL || *pos == NULL || end == NULL || f == NULL) {
        return S3_ERROR;
    }

    p = *pos;

    if ((size_t)(end - p) < S3_SSH3_CM_HEADER_LEN) {
        return S3_AGAIN;
    }

    if (p[0] != 'S' || p[1] != '3' || p[2] != 'C' || p[3] != 'M') {
        return S3_ERROR;
    }

    if (p[4] != S3_SSH3_CM_VERSION) {
        return S3_ERROR;
    }

    len = s3_cm_get_u32(p + 6);

    if (len > S3_SSH3_CM_MAX_FRAME) {
        return S3_ERROR;
    }

    if ((size_t)(end - p) - S3_SSH3_CM_HEADER_LEN < len) {
        return S3_AGAIN;
    }

    f->type = p[5];
    f->payload.data = (u_char *)p + S3_SSH3_CM_HEADER_LEN;
    f->payload.len = len;

    *pos = p + S3_SSH3_CM_HEADER_LEN + len;

    return S3_OK;
}

/* the payload decoders, strict like the reference */

s3_int_t
s3_ssh3_cm_decode_open_session(const s3_str_t *body, s3_ssh3_cm_open_session_t *req)
{
    const u_char *pos, *end;
    uint32_t      n, i;

    if (body == NULL || body->data == NULL || req == NULL) {
        return S3_ERROR;
    }

    s3_memzero(req, sizeof(*req));

    pos = body->data;
    end = body->data + body->len;

    if (s3_cm_get_count(&pos, end, &n) != S3_OK || n > S3_SSH3_CM_LIST_MAX) {
        return S3_ERROR;
    }

    req->ncommand = n;

    for (i = 0; i < n; i++) {
        if (s3_cm_get_str(&pos, end, &req->command[i]) != S3_OK) {
            return S3_ERROR;
        }
    }

    if (s3_cm_get_count(&pos, end, &n) != S3_OK || n > S3_SSH3_CM_LIST_MAX) {
        return S3_ERROR;
    }

    req->nenv = n;

    for (i = 0; i < n; i++) {
        if (s3_cm_get_str(&pos, end, &req->env[i]) != S3_OK) {
            return S3_ERROR;
        }
    }

    /* the pty flag: the arm is on the wire of every version, the
       value 1 is the pty request v0 refuses */

    if (pos == end || *pos == 1) {
        return S3_ERROR;
    }

    pos++;

    if (pos == end) {
        return S3_ERROR;
    }

    req->forward_agent = (*pos == 1);
    pos++;

    return pos == end ? S3_OK : S3_ERROR;
}

s3_int_t
s3_ssh3_cm_decode_attach(const s3_str_t *body, u_char token[S3_SSH3_CM_TOKEN_LEN], uint8_t *kind)
{
    if (body == NULL || body->data == NULL || token == NULL || kind == NULL ||
        body->len != S3_SSH3_CM_TOKEN_LEN + 1) {
        return S3_ERROR;
    }

    s3_memcpy(token, body->data, S3_SSH3_CM_TOKEN_LEN);

    *kind = body->data[S3_SSH3_CM_TOKEN_LEN];

    if (*kind != S3_SSH3_CM_STREAM_IO && *kind != S3_SSH3_CM_STREAM_STDERR) {
        return S3_ERROR;
    }

    return S3_OK;
}

s3_int_t
s3_ssh3_cm_decode_exit_status(const s3_str_t *body, uint64_t *code)
{
    if (body == NULL || body->data == NULL || code == NULL || body->len != 8) {
        return S3_ERROR;
    }

    *code = s3_cm_get_u64(body->data);

    return S3_OK;
}

/* the control op ignores the trailing bytes so a newer client may
   extend the payload (the Go decodeControlOp contract) */

s3_int_t
s3_ssh3_cm_decode_control_op(const s3_str_t *body, s3_str_t *op)
{
    const u_char *pos, *end;
    uint32_t      len;

    if (body == NULL || body->data == NULL || op == NULL) {
        return S3_ERROR;
    }

    pos = body->data;
    end = body->data + body->len;

    if ((size_t)(end - pos) < 4) {
        return S3_ERROR;
    }

    len = s3_cm_get_u32(pos);
    pos += 4;

    if ((size_t)(end - pos) < len) {
        return S3_ERROR;
    }

    op->data = (u_char *)pos;
    op->len = len;

    return S3_OK;
}

/* the measure-mode encoders */

uintptr_t
s3_ssh3_cm_encode_frame(u_char *p, uint8_t type, const s3_str_t *payload)
{
    size_t len;

    len = payload != NULL ? payload->len : 0;

    if (len > S3_SSH3_CM_MAX_FRAME) {
        return 0;
    }

    if (p == NULL) {
        return S3_SSH3_CM_HEADER_LEN + len;
    }

    s3_cm_put_head(p, type, (uint32_t)len);

    if (len != 0) {
        s3_memcpy(p + S3_SSH3_CM_HEADER_LEN, payload->data, len);
    }

    return (uintptr_t)(p + S3_SSH3_CM_HEADER_LEN + len);
}

uintptr_t
s3_ssh3_cm_encode_open_session(u_char *p, const s3_ssh3_cm_open_session_t *req)
{
    uintptr_t size;
    uint32_t  i;

    if (req == NULL) {
        return 0;
    }

    size = 4;

    for (i = 0; i < req->ncommand; i++) {
        size += 4 + req->command[i].len;
    }

    size += 4;

    for (i = 0; i < req->nenv; i++) {
        size += 4 + req->env[i].len;
    }

    /* the pty flag 0 and the agent byte */

    size += 2;

    if (p == NULL) {
        return size;
    }

    p = s3_cm_put_u32(p, req->ncommand);

    for (i = 0; i < req->ncommand; i++) {
        p = s3_cm_put_string(p, &req->command[i]);
    }

    p = s3_cm_put_u32(p, req->nenv);

    for (i = 0; i < req->nenv; i++) {
        p = s3_cm_put_string(p, &req->env[i]);
    }

    *p++ = 0; /* no pty in v0 */
    *p++ = req->forward_agent ? 1 : 0;

    return (uintptr_t)p;
}

uintptr_t
s3_ssh3_cm_encode_attach(u_char *p, const u_char token[S3_SSH3_CM_TOKEN_LEN], uint8_t kind)
{
    if (p == NULL) {
        return S3_SSH3_CM_TOKEN_LEN + 1;
    }

    p = s3_cpymem(p, token, S3_SSH3_CM_TOKEN_LEN);
    *p++ = kind;

    return (uintptr_t)p;
}

uintptr_t
s3_ssh3_cm_encode_exit_status(u_char *p, uint64_t code)
{
    if (p == NULL) {
        return 8;
    }

    p = s3_cm_put_u32(p, (uint32_t)(code >> 32));

    p = s3_cm_put_u32(p, (uint32_t)code);

    return (uintptr_t)p;
}

uintptr_t
s3_ssh3_cm_encode_control_op(u_char *p, const s3_str_t *op)
{
    if (op == NULL) {
        return 0;
    }

    if (p == NULL) {
        return 4 + op->len;
    }

    p = s3_cm_put_string(p, op);

    return (uintptr_t)p;
}

/* the MasterStatus JSON, the decimal forms the reference marshaler
   also emits; any JSON number parses back, the shape is ours */

static uintptr_t
s3_cm_int_size(long v)
{
    uintptr_t n;

    n = 1;

    while (v / 10 != 0) {
        n++;
        v /= 10;
    }

    return n;
}

static u_char *
s3_cm_put_int(u_char *p, long v)
{
    u_char tmp[24];
    size_t n;

    n = 0;

    do {
        tmp[n++] = (u_char)('0' + v % 10);
        v /= 10;
    } while (v > 0);

    while (n > 0) {
        *p++ = tmp[--n];
    }

    return p;
}

static uintptr_t
s3_cm_json_str_size(const char *s)
{
    uintptr_t     n;
    const u_char *p;

    n = 2;

    if (s == NULL) {
        return n;
    }

    for (p = (const u_char *)s; *p != '\0'; p++) {

        if (*p == '"' || *p == '\\') {
            n += 2;

        } else if (*p < 0x20) {
            n += 6; /* \u00XX */

        } else {
            n += 1;
        }
    }

    return n;
}

static u_char *
s3_cm_json_str_put(u_char *p, const char *s)
{
    const u_char *q;

    *p++ = '"';

    if (s != NULL) {

        for (q = (const u_char *)s; *q != '\0'; q++) {

            if (*q == '"' || *q == '\\') {
                *p++ = '\\';
                *p++ = (u_char)*q;

            } else if (*q < 0x20) {
                *p++ = '\\';
                *p++ = 'u';
                *p++ = '0';
                *p++ = '0';
                *p++ = (u_char)s3_cm_hex[(*q >> 4) & 0xf];
                *p++ = (u_char)s3_cm_hex[*q & 0xf];

            } else {
                *p++ = (u_char)*q;
            }
        }
    }

    *p++ = '"';

    return p;
}

/* the uptime seconds, the millisecond form "s.fff" of the emitter */

static uint64_t
s3_cm_uptime_ms(const s3_ssh3_cm_status_t *st)
{
    return (uint64_t)(st->uptime_s * 1000.0 + 0.5);
}

uintptr_t
s3_ssh3_cm_encode_status_json(u_char *p, const s3_ssh3_cm_status_t *st)
{
    uint64_t  ms;
    uintptr_t size;

    if (st == NULL) {
        return 0;
    }

    ms = s3_cm_uptime_ms(st);

    size = (sizeof(S3_CM_JSON_HEAD) - 1) + s3_cm_json_str_size(st->path) +
           (sizeof(S3_CM_JSON_PID) - 1) + s3_cm_int_size(st->pid) + (sizeof(S3_CM_JSON_PROT) - 1) +
           s3_cm_int_size(st->protocol) + (sizeof(S3_CM_JSON_UP) - 1) +
           s3_cm_int_size((long)(ms / 1000)) + 4 /* the .fff */
           + (sizeof(S3_CM_JSON_SESS) - 1) + s3_cm_int_size(st->sessions) +
           (sizeof(S3_CM_JSON_FWD) - 1) + s3_cm_int_size(st->forwards) +
           (sizeof(S3_CM_JSON_TAIL) - 1);

    if (p == NULL) {
        return size;
    }

    p = s3_cpymem(p, S3_CM_JSON_HEAD, sizeof(S3_CM_JSON_HEAD) - 1);
    p = s3_cm_json_str_put(p, st->path);

    p = s3_cpymem(p, S3_CM_JSON_PID, sizeof(S3_CM_JSON_PID) - 1);
    p = s3_cm_put_int(p, st->pid);

    p = s3_cpymem(p, S3_CM_JSON_PROT, sizeof(S3_CM_JSON_PROT) - 1);
    p = s3_cm_put_int(p, st->protocol);

    p = s3_cpymem(p, S3_CM_JSON_UP, sizeof(S3_CM_JSON_UP) - 1);
    p = s3_cm_put_int(p, (long)(ms / 1000));
    *p++ = '.';
    *p++ = (u_char)('0' + (ms / 100) % 10);
    *p++ = (u_char)('0' + (ms / 10) % 10);
    *p++ = (u_char)('0' + ms % 10);

    p = s3_cpymem(p, S3_CM_JSON_SESS, sizeof(S3_CM_JSON_SESS) - 1);
    p = s3_cm_put_int(p, st->sessions);

    p = s3_cpymem(p, S3_CM_JSON_FWD, sizeof(S3_CM_JSON_FWD) - 1);
    p = s3_cm_put_int(p, st->forwards);

    p = s3_cpymem(p, S3_CM_JSON_TAIL, sizeof(S3_CM_JSON_TAIL) - 1);

    return (uintptr_t)p;
}

/* the pool buffers, the growth of the sftp server shapes */

static s3_int_t
s3_cm_buf_append(u_char **buf, size_t *len, size_t *cap, s3_pool_t *pool, const u_char *data,
                 size_t n)
{
    u_char *grown;
    size_t  want;

    if (*cap - *len < n) {

        want = *cap != 0 ? *cap : S3_SSH3_CM_BUF_INIT;

        while (want - *len < n) {
            want *= 2;
        }

        grown = s3_pnalloc(pool, want);

        if (grown == NULL) {
            return S3_ERROR;
        }

        if (*len > 0) {
            s3_memcpy(grown, *buf, *len);
        }

        *buf = grown;
        *cap = want;
    }

    if (n > 0) {
        s3_memcpy(*buf + *len, data, n);
    }

    *len += n;

    return S3_OK;
}

static u_char *
s3_cm_buf_reserve(u_char **buf, size_t len, size_t *cap, s3_pool_t *pool, size_t need)
{
    u_char *grown;
    size_t  want;

    if (*cap - len < need) {

        want = *cap != 0 ? *cap : S3_SSH3_CM_BUF_INIT;

        while (want - len < need) {
            want *= 2;
        }

        grown = s3_pnalloc(pool, want);

        if (grown == NULL) {
            return NULL;
        }

        if (len > 0) {
            s3_memcpy(grown, *buf, len);
        }

        *buf = grown;
        *cap = want;
    }

    return *buf + len;
}

static s3_int_t
s3_cm_output(u_char *src, size_t *len, u_char *dst, size_t size)
{
    size_t n;

    if (dst == NULL || size == 0) {
        return 0;
    }

    n = *len < size ? *len : size;

    if (n > 0) {
        s3_memcpy(dst, src, n);
        *len -= n;

        if (*len > 0) {
            s3_memmove(src, src + n, *len);
        }
    }

    return (s3_int_t)n;
}

/* the master side */

s3_int_t
s3_ssh3_cm_sessions_init(s3_ssh3_cm_sessions_t *t, s3_pool_t *pool)
{
    if (t == NULL || pool == NULL) {
        return S3_ERROR;
    }

    s3_memzero(t, sizeof(*t));

    t->pool = pool;

    return S3_OK;
}

/*
 * the release of a finished session: the whole slot clears here so
 * the next alloc reuses it without the flag leaks an app-side
 * cleanup used to leak into the reused slots
 */

s3_int_t
s3_ssh3_cm_sessions_release(s3_ssh3_cm_sessions_t *t, const u_char token[S3_SSH3_CM_TOKEN_LEN])
{
    uint32_t i;

    if (t == NULL || token == NULL) {
        return S3_ERROR;
    }

    for (i = 0; i < S3_SSH3_CM_SRV_SESSIONS; i++) {

        if (t->sessions[i].used &&
            s3_memcmp(t->sessions[i].token, token, S3_SSH3_CM_TOKEN_LEN) == 0) {
            s3_memzero(&t->sessions[i], sizeof(t->sessions[i]));
            t->count--;

            return S3_OK;
        }
    }

    return S3_ERROR;
}

s3_int_t
s3_ssh3_cm_srv_init(s3_ssh3_cm_srv_t *t, s3_pool_t *pool, s3_ssh3_cm_sessions_t *sessions,
                    const s3_ssh3_cm_srv_cbs_t *cbs, void *cb_ctx)
{
    if (t == NULL || pool == NULL || sessions == NULL || cbs == NULL) {
        return S3_ERROR;
    }

    s3_memzero(t, sizeof(*t));

    t->pool = pool;
    t->sessions = sessions;
    t->cbs = *cbs;
    t->cb_ctx = cb_ctx;

    return S3_OK;
}

static s3_ssh3_cm_sess_t *
s3_srv_sess_find(s3_ssh3_cm_srv_t *t, const u_char token[S3_SSH3_CM_TOKEN_LEN])
{
    s3_ssh3_cm_sess_t *s;
    uint32_t           i;

    for (i = 0; i < S3_SSH3_CM_SRV_SESSIONS; i++) {
        s = &t->sessions->sessions[i];

        if (s->used && s3_memcmp(s->token, token, S3_SSH3_CM_TOKEN_LEN) == 0) {
            return s;
        }
    }

    return NULL;
}

static s3_ssh3_cm_sess_t *
s3_srv_sess_alloc(s3_ssh3_cm_srv_t *t)
{
    s3_ssh3_cm_sess_t *s;
    uint32_t           i;

    for (i = 0; i < S3_SSH3_CM_SRV_SESSIONS; i++) {
        s = &t->sessions->sessions[i];

        if (!s->used) {
            return s;
        }
    }

    return NULL;
}

static s3_int_t
s3_srv_reply(s3_ssh3_cm_srv_t *t, uint8_t type, const u_char *payload, size_t len)
{
    u_char *p;

    p = s3_cm_buf_reserve(&t->out, t->out_len, &t->out_cap, t->pool, S3_SSH3_CM_HEADER_LEN + len);

    if (p == NULL) {
        return S3_ERROR;
    }

    s3_cm_put_head(p, type, (uint32_t)len);

    if (len > 0) {
        s3_memcpy(p + S3_SSH3_CM_HEADER_LEN, payload, len);
    }

    t->out_len += S3_SSH3_CM_HEADER_LEN + len;

    return S3_OK;
}

static s3_int_t
s3_srv_error(s3_ssh3_cm_srv_t *t, const char *msg)
{
    return s3_srv_reply(t, S3_SSH3_CM_MSG_ERROR, (const u_char *)msg, strlen(msg));
}

static s3_int_t
s3_srv_error_done(s3_ssh3_cm_srv_t *t, const char *msg)
{
    t->done = 1;

    return s3_srv_error(t, msg);
}

/*
 * the op match is length-exact on purpose (I-1): the control-op
 * decoder tolerates the trailing bytes of a newer client, this
 * comparison is the one refusing them - a prefix test or a first-byte
 * switch here would accept "check" + garbage; when the op set grows,
 * keep the (length, s3_strncmp) shape per op, never a prefix dispatch
 */
static unsigned
s3_cm_op_is(const s3_str_t *op, const char *name)
{
    size_t n;

    n = strlen(name);

    return op->len == n && s3_memcmp(op->data, name, n) == 0;
}

static s3_int_t
s3_srv_dispatch(s3_ssh3_cm_srv_t *t, s3_ssh3_cm_frame_t *f)
{
    char msg[32];

    /* the first frame of every connection is the version handshake
       (handleMasterConn) */

    if (!t->hello_done) {

        if (f->type == S3_SSH3_CM_MSG_HELLO) {
            t->hello_done = 1;

            return s3_srv_reply(t, S3_SSH3_CM_MSG_OK, NULL, 0);
        }

        return s3_srv_error_done(t, "expected HELLO");
    }

    switch (f->type) {

    case S3_SSH3_CM_MSG_OPEN_SESSION:
        return s3_srv_open_session(t, &f->payload);

    case S3_SSH3_CM_MSG_ATTACH:
        return s3_srv_attach(t, &f->payload);

    case S3_SSH3_CM_MSG_CONTROL_OP:
        return s3_srv_control_op(t, &f->payload);

    case S3_SSH3_CM_MSG_EXIT:

        /* the exit of the reference shuts the master down */

        t->shutdown = 1;
        t->done = 1;

        return s3_srv_reply(t, S3_SSH3_CM_MSG_OK, NULL, 0);

    default:

        /* the v1 forwards and the interactions land here in v0 */

        (void)snprintf(msg, sizeof(msg), "unexpected message %u", (unsigned)f->type);

        return s3_srv_error_done(t, msg);
    }
}

static s3_int_t
s3_srv_open_session(s3_ssh3_cm_srv_t *t, const s3_str_t *payload)
{
    s3_ssh3_cm_open_session_t req;
    s3_ssh3_cm_sess_t        *s;
    u_char                    token[S3_SSH3_CM_TOKEN_LEN];
    const char               *err;

    if (t->shutdown) {
        return s3_srv_error(t, "the control master is shutting down");
    }

    s3_memzero(&req, sizeof(req));

    if (s3_ssh3_cm_decode_open_session(payload, &req) != S3_OK) {
        return s3_srv_error(t, "malformed OPEN_SESSION");
    }

    if (t->cbs.open_session == NULL) {
        return s3_srv_error(t, "sessions are not served");
    }

    err = NULL;

    if (t->cbs.open_session(t->cb_ctx, &req, token, &err) != S3_OK) {
        return s3_srv_error(t, err != NULL ? err : "session refused");
    }

    s = s3_srv_sess_alloc(t);

    if (s == NULL) {
        return s3_srv_error(t, "too many sessions");
    }

    s3_memcpy(s->token, token, S3_SSH3_CM_TOKEN_LEN);

    s->used = 1;

    t->sessions->count++;

    return s3_srv_reply(t, S3_SSH3_CM_MSG_OK, token, S3_SSH3_CM_TOKEN_LEN);
}

static s3_int_t
s3_srv_attach(s3_ssh3_cm_srv_t *t, const s3_str_t *payload)
{
    s3_ssh3_cm_sess_t *s;
    u_char             token[S3_SSH3_CM_TOKEN_LEN];
    uint8_t            kind;
    s3_int_t           rc;

    if (s3_ssh3_cm_decode_attach(payload, token, &kind) != S3_OK) {
        return s3_srv_error_done(t, "malformed ATTACH");
    }

    s = s3_srv_sess_find(t, token);

    if (s == NULL) {
        return s3_srv_error_done(t, "unknown session token");
    }

    switch (kind) {

    case S3_SSH3_CM_STREAM_STDERR:

        if (s->started || s->stderr_attached) {
            return s3_srv_error_done(t, "stderr stream already attached");
        }

        s->stderr_attached = 1;

        rc = s3_srv_reply(t, S3_SSH3_CM_MSG_OK, NULL, 0);

        if (rc != S3_OK) {
            return rc;
        }

        /* the stderr bridge owns the stream, the master has already
           acknowledged the attach */

        if (t->cbs.bridge_stderr != NULL) {
            t->cbs.bridge_stderr(t->cb_ctx, token);
        }

        return S3_OK;

    case S3_SSH3_CM_STREAM_IO:

        if (s->started) {
            return s3_srv_error_done(t, "session already started");
        }

        if (!s->stderr_attached) {
            return s3_srv_error_done(t, "the stderr stream must attach before the io stream");
        }

        s->started = 1;

        rc = s3_srv_reply(t, S3_SSH3_CM_MSG_OK, NULL, 0);

        if (rc != S3_OK) {
            return rc;
        }

        /* the bridge owns the io stream now, the master has already
           acknowledged the attach */

        if (t->cbs.bridge != NULL) {
            t->cbs.bridge(t->cb_ctx, token);
        }

        return S3_OK;

    default:
        return s3_srv_error_done(t, "unknown stream kind");
    }
}

static s3_int_t
s3_srv_control_op(s3_ssh3_cm_srv_t *t, const s3_str_t *payload)
{
    s3_str_t            op;
    s3_ssh3_cm_status_t st;
    u_char             *p;
    uintptr_t           n;

    if (s3_ssh3_cm_decode_control_op(payload, &op) != S3_OK) {
        return s3_srv_error(t, "malformed control operation");
    }

    if (s3_cm_op_is(&op, S3_SSH3_CM_OP_CHECK)) {

        if (t->cbs.status == NULL) {
            return s3_srv_error(t, "status is not served");
        }

        s3_memzero(&st, sizeof(st));

        if (t->cbs.status(t->cb_ctx, &st) != S3_OK) {
            return s3_srv_error(t, "status failed");
        }

        n = s3_ssh3_cm_encode_status_json(NULL, &st);

        p = s3_cm_buf_reserve(&t->out, t->out_len, &t->out_cap, t->pool, S3_SSH3_CM_HEADER_LEN + n);

        if (p == NULL) {
            return S3_ERROR;
        }

        s3_cm_put_head(p, S3_SSH3_CM_MSG_OK, (uint32_t)n);
        s3_ssh3_cm_encode_status_json(p + S3_SSH3_CM_HEADER_LEN, &st);

        t->out_len += S3_SSH3_CM_HEADER_LEN + n;

        return S3_OK;
    }

    if (s3_cm_op_is(&op, S3_SSH3_CM_OP_STOP) || s3_cm_op_is(&op, S3_SSH3_CM_OP_EXIT)) {
        t->shutdown = 1;
        t->done = 1;

        return s3_srv_reply(t, S3_SSH3_CM_MSG_OK, NULL, 0);
    }

    /* refused but the connection stays, the caller may retry with an
       operation this master does know */

    return s3_srv_error(t, "unknown control operation");
}

s3_int_t
s3_ssh3_cm_srv_input(s3_ssh3_cm_srv_t *t, const u_char *data, size_t len)
{
    const u_char      *pos, *end;
    s3_ssh3_cm_frame_t f;
    size_t             consumed;
    s3_int_t           rc;

    if (t == NULL || t->pool == NULL || (len > 0 && data == NULL)) {
        return S3_ERROR;
    }

    if (t->done || len == 0) {
        return S3_OK;
    }

    if (s3_cm_buf_append(&t->pend, &t->pend_len, &t->pend_cap, t->pool, data, len) != S3_OK) {
        return S3_ERROR;
    }

    /* the empty tail has no frame to pull, the parser wants bytes */

    if (t->pend_len == 0) {
        return S3_OK;
    }

    for (;;) {

        pos = t->pend;
        end = t->pend + t->pend_len;

        rc = s3_ssh3_cm_frame(&pos, end, &f);

        if (rc == S3_AGAIN) {
            return S3_OK;
        }

        if (rc != S3_OK) {

            /* the hostile stream dies before its body arrives */

            t->done = 1;

            return S3_OK;
        }

        consumed = (size_t)(pos - t->pend);

        rc = s3_srv_dispatch(t, &f);

        /* the views die with the shift of the tail */

        t->pend_len -= consumed;

        if (t->pend_len > 0) {
            s3_memmove(t->pend, t->pend + consumed, t->pend_len);
        }

        if (rc != S3_OK) {
            return S3_ERROR;
        }

        if (t->done) {
            return S3_OK;
        }
    }
}

ssize_t
s3_ssh3_cm_srv_output(s3_ssh3_cm_srv_t *t, u_char *buf, size_t size)
{
    if (t == NULL) {
        return 0;
    }

    return (ssize_t)s3_cm_output(t->out, &t->out_len, buf, size);
}

unsigned
s3_ssh3_cm_srv_done(const s3_ssh3_cm_srv_t *t)
{
    return t != NULL ? t->done : 1;
}

unsigned
s3_ssh3_cm_srv_shutdown(const s3_ssh3_cm_srv_t *t)
{
    return t != NULL ? t->shutdown : 0;
}

/* the slave side */

s3_int_t
s3_ssh3_cm_cli_init(s3_ssh3_cm_cli_t *t, s3_pool_t *pool)
{
    if (t == NULL || pool == NULL) {
        return S3_ERROR;
    }

    s3_memzero(t, sizeof(*t));

    t->pool = pool;

    return S3_OK;
}

s3_int_t
s3_ssh3_cm_cli_call(s3_ssh3_cm_cli_t *t, uint8_t type, const s3_str_t *payload)
{
    u_char  *p;
    s3_str_t empty;

    if (t == NULL || t->pool == NULL) {
        return S3_ERROR;
    }

    if (t->protocol_error || t->awaiting) {
        return S3_ERROR;
    }

    empty.len = 0;
    empty.data = NULL;

    p = s3_cm_buf_reserve(&t->out, t->out_len, &t->out_cap, t->pool,
                          S3_SSH3_CM_HEADER_LEN + (payload != NULL ? payload->len : 0));

    if (p == NULL) {
        return S3_ERROR;
    }

    (void)s3_ssh3_cm_encode_frame(p, type, payload != NULL ? payload : &empty);

    t->out_len += S3_SSH3_CM_HEADER_LEN + (payload != NULL ? payload->len : 0);

    t->awaiting = 1;
    t->has_reply = 0;
    t->is_error = 0;

    return S3_OK;
}

s3_int_t
s3_ssh3_cm_cli_input(s3_ssh3_cm_cli_t *t, const u_char *data, size_t len)
{
    const u_char      *pos, *end;
    s3_ssh3_cm_frame_t f;
    size_t             consumed;
    s3_int_t           rc;

    if (t == NULL || t->pool == NULL || (len > 0 && data == NULL)) {
        return S3_ERROR;
    }

    if (t->protocol_error) {
        return S3_OK;
    }

    if (len > 0 &&
        s3_cm_buf_append(&t->pend, &t->pend_len, &t->pend_cap, t->pool, data, len) != S3_OK) {
        return S3_ERROR;
    }

    /* the empty tail has no frame to pull, the parser wants bytes */

    if (t->pend_len == 0) {
        return S3_OK;
    }

    for (;;) {

        pos = t->pend;
        end = t->pend + t->pend_len;

        rc = s3_ssh3_cm_frame(&pos, end, &f);

        if (rc == S3_AGAIN) {
            return S3_OK;
        }

        if (rc != S3_OK) {
            t->protocol_error = 1;

            return S3_OK;
        }

        /* the Call stream is strictly serial: one reply to the one
           request, a desynchronized peer dies here */

        if (!t->awaiting || (f.type != S3_SSH3_CM_MSG_OK && f.type != S3_SSH3_CM_MSG_ERROR)) {
            t->protocol_error = 1;

            return S3_OK;
        }

        consumed = (size_t)(pos - t->pend);

        /* the reply outlives the tail shift: one copy per reply, the
           control channel is not the data path */

        t->reply_len = 0;

        if (f.payload.len > 0 && s3_cm_buf_append(&t->reply, &t->reply_len, &t->reply_cap, t->pool,
                                                  f.payload.data, f.payload.len) != S3_OK) {
            return S3_ERROR;
        }

        t->awaiting = 0;
        t->has_reply = 1;
        t->is_error = f.type == S3_SSH3_CM_MSG_ERROR;

        t->pend_len -= consumed;

        if (t->pend_len > 0) {
            s3_memmove(t->pend, t->pend + consumed, t->pend_len);
        }
    }
}

ssize_t
s3_ssh3_cm_cli_output(s3_ssh3_cm_cli_t *t, u_char *buf, size_t size)
{
    if (t == NULL) {
        return 0;
    }

    return (ssize_t)s3_cm_output(t->out, &t->out_len, buf, size);
}

s3_int_t
s3_ssh3_cm_cli_reply(s3_ssh3_cm_cli_t *t, s3_str_t *payload, unsigned *is_error)
{
    if (t == NULL || payload == NULL || is_error == NULL) {
        return S3_ERROR;
    }

    if (t->protocol_error) {
        return S3_ERROR;
    }

    if (!t->has_reply) {
        return S3_AGAIN;
    }

    payload->data = t->reply;
    payload->len = t->reply_len;
    *is_error = t->is_error;

    return S3_OK;
}

unsigned
s3_ssh3_cm_cli_protocol_error(const s3_ssh3_cm_cli_t *t)
{
    return t != NULL ? t->protocol_error : 1;
}
