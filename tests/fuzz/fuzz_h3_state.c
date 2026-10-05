/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the stateful libFuzzer harness of the h3 layer (P6.3): one session
 * per exec, the qpack dynamic table and the uni/control parse
 * machines live across the steps of the input, so the mutated
 * instructions act on the state the earlier steps built up.  the
 * input is a sequence of [op:1][len:1][payload:len] steps, the ops
 * drive the encoder/decoder/control uni machines, the request-stream
 * header and data machines, the table capacity and the blocked
 * streams directly, plus the round-trip invariants: a field section
 * the encoders build must decode to the same field, and the encoded
 * varlen ints must parse back to themselves
 */

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

#include <s3_core.h>

#include <s3_h3.h>

#include "s3_fuzz.h"

/*
 * the parse layer caps the field lines at 8k (the fixed
 * large_client_header_buffers size of s3_h3_parse.c); the round-trip
 * frame buffer is sized so the guard below makes the stack bound
 * provable without trusting that constant
 */
#define S3_FUZZ_MAX_FIELD_SIZE 8192

/* the per-exec cap of the blocked-stream connections, one pool each */
#define S3_FUZZ_MAX_STREAMS 16

/* the steps */
#define S3_FUZZ_OP_ENCODER  0x00
#define S3_FUZZ_OP_DECODER  0x01
#define S3_FUZZ_OP_CONTROL  0x02
#define S3_FUZZ_OP_HEADERS  0x03
#define S3_FUZZ_OP_DYNREF   0x04
#define S3_FUZZ_OP_DATA     0x05
#define S3_FUZZ_OP_RAW      0x06
#define S3_FUZZ_OP_CAPACITY 0x07
#define S3_FUZZ_OP_BLOCK    0x08
#define S3_FUZZ_OP_VARLEN   0x09
#define S3_FUZZ_OP_STATIC   0x0a
#define S3_FUZZ_OP_HUFF     0x0b

typedef struct {
    s3_event_ctx_t   ctx;
    s3_fd_t          fd;
    s3_connection_t *c;  /* the request/control stream carrier */
    s3_connection_t *dc; /* the peer decoder stream (the ack sink) */
    s3_h3_session_t *h3c;
    s3_pool_t       *streams[S3_FUZZ_MAX_STREAMS];
    int              nstreams;
} s3_fuzz_env_t;

/*
 * the parse machines of one exec: the uni machines are the
 * sequential state machines of the three stream kinds plus a fully
 * fuzzed one, the headers/data machines walk the request stream, the
 * rt machine re-parses the sections the encoders build; the huffman
 * state carries across the steps
 */
typedef struct {
    s3_h3_parse_uni_t     enc;
    s3_h3_parse_uni_t     dec;
    s3_h3_parse_uni_t     ctrl;
    s3_h3_parse_uni_t     raw;
    s3_h3_parse_uni_t     vlen;
    s3_h3_parse_headers_t hdr;
    s3_h3_parse_headers_t rt;
    s3_h3_parse_data_t    data;
    u_char                huffstate;
    u_char                huff_tail;
    s3_uint_t             enc_started;
    s3_uint_t             dec_started;
    s3_uint_t             ctrl_started;
    s3_uint_t             raw_started;
} s3_fuzz_machines_t;

static s3_log_t s3_fuzz_h3_log = {0, S3_INVALID_FILE};

/* the ack decoder-stream sink, reset per exec */
static u_char s3_fuzz_dec_sink[65536];
static size_t s3_fuzz_dec_sink_len;

static unsigned s3_fuzz_unblocked;

/* lazily probed static table size */
static s3_uint_t s3_fuzz_static_nelts;

static void
s3_fuzz_dummy_read(s3_event_t *ev)
{
    (void)ev;

    s3_fuzz_unblocked++;
}

/*
 * the fake stream send: consumes the chain into the ack sink like the
 * quic stream send copies into its output buffers
 */
static s3_chain_t *
s3_fuzz_send_chain(s3_connection_t *c, s3_chain_t *in, off_t limit)
{
    s3_chain_t *cl;
    size_t      n;

    (void)c;
    (void)limit;

    for (cl = in; cl != NULL; cl = cl->next) {
        n = (size_t)(cl->buf->last - cl->buf->pos);

        if (s3_fuzz_dec_sink_len + n <= sizeof(s3_fuzz_dec_sink)) {
            s3_memcpy(s3_fuzz_dec_sink + s3_fuzz_dec_sink_len, cl->buf->pos, n);
        }

        s3_fuzz_dec_sink_len += n;
        cl->buf->pos = cl->buf->last;
    }

    return NULL;
}

static s3_int_t
s3_fuzz_env_init(s3_fuzz_env_t *e)
{
    struct sockaddr_in sa;

    s3_memzero(e, sizeof(s3_fuzz_env_t));

    e->fd = -1;

    if (s3_event_ctx_init(&e->ctx, &s3_fuzz_h3_log) != S3_OK) {
        return S3_ERROR;
    }

    e->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (e->fd == -1) {
        return S3_ERROR;
    }

    s3_memzero(&sa, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = 0;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(e->fd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
        return S3_ERROR;
    }

    /* the request stream carrier: the pool of the context, the
     * session on c->data, like the unit-test scene of test_h3_qpack */

    e->c = s3_get_connection(&e->ctx, e->fd);
    if (e->c == NULL) {
        return S3_ERROR;
    }

    e->c->pool = e->ctx.pool;
    e->c->read->handler = s3_fuzz_dummy_read;

    e->h3c = s3_pcalloc(e->ctx.pool, sizeof(s3_h3_session_t));
    if (e->h3c == NULL) {
        return S3_ERROR;
    }

    s3_queue_init(&e->h3c->blocked);

    e->h3c->ctx = &e->ctx;

    e->h3c->table.send_insert_count.log = e->c->log;
    e->h3c->table.send_insert_count.data = e->c;
    e->h3c->table.send_insert_count.handler = s3_h3_inc_insert_count_handler;

    e->c->data = e->h3c;

    /* the peer decoder stream: the insert count acks go through its
     * send_chain, like the SERVER_DECODER wiring of the table layer */

    e->dc = s3_get_connection(&e->ctx, e->fd);
    if (e->dc == NULL) {
        return S3_ERROR;
    }

    e->dc->pool = e->ctx.pool;
    e->dc->data = e->h3c;
    e->dc->read->handler = s3_fuzz_dummy_read;
    e->dc->send_chain = s3_fuzz_send_chain;

    e->h3c->known_streams[S3_H3_STREAM_SERVER_DECODER] = e->dc;

    return S3_OK;
}

static void
s3_fuzz_env_done(s3_fuzz_env_t *e)
{
    while (e->nstreams > 0) {
        s3_destroy_pool(e->streams[--e->nstreams]);
    }

    s3_destroy_pool(e->ctx.pool);

    (void)close(e->fd);
}

static s3_uint_t
s3_fuzz_static_size(s3_connection_t *c)
{
    s3_str_t  name, value;
    s3_uint_t i;

    if (s3_fuzz_static_nelts != 0) {
        return s3_fuzz_static_nelts;
    }

    for (i = 0; i < 4096; i++) {
        if (s3_h3_lookup_static(c, i, &name, &value) != S3_OK) {
            break;
        }
    }

    s3_fuzz_static_nelts = i;

    return i;
}

/*
 * the field name comparison: the literal encoder lowercases the
 * names (the s3_h3_strlow contract of the encode layer), so the
 * round-trip equality is ASCII case-insensitive; the values are
 * byte-exact
 */
static unsigned
s3_fuzz_name_eq(const u_char *a, const u_char *b, size_t len)
{
    u_char ca, cb;
    size_t i;

    for (i = 0; i < len; i++) {

        ca = a[i];
        cb = b[i];

        if (ca >= 'A' && ca <= 'Z') {
            ca = (u_char)(ca | 0x20);
        }

        if (cb >= 'A' && cb <= 'Z') {
            cb = (u_char)(cb | 0x20);
        }

        if (ca != cb) {
            return 0;
        }
    }

    return 1;
}

/*
 * the round-trip invariant of the field lines: the section the
 * encoders build from a decoded (name, value) must parse back to the
 * same pair with the DONE result, whatever the table state is (the
 * section prefix is the zero insert count, the field is a literal
 * with a literal name and touches no table entry)
 */
static void
s3_fuzz_field_roundtrip(s3_fuzz_env_t *e, s3_fuzz_machines_t *m, s3_str_t *name, s3_str_t *value)
{
    u_char               section[2 * S3_FUZZ_MAX_FIELD_SIZE + 160];
    u_char               frame[2 * S3_FUZZ_MAX_FIELD_SIZE + 192];
    u_char              *p, *q;
    size_t               section_len;
    s3_buf_t             b;
    s3_int_t             rc;
    s3_h3_parse_field_t *f;

    if (name->len > S3_FUZZ_MAX_FIELD_SIZE || value->len > S3_FUZZ_MAX_FIELD_SIZE) {
        return;
    }

    /* the section goes to the scratch first, then in front of the
     * copy the frame header, so the parse buffer is contiguous */

    p = (u_char *)s3_h3_encode_field_section_prefix(section, 0, 0, 0);
    p = (u_char *)s3_h3_encode_field_l(p, name, value);

    section_len = (size_t)(p - section);

    frame[0] = S3_H3_FRAME_HEADERS;
    q = (u_char *)s3_h3_encode_varlen_int(frame + 1, section_len);
    s3_memcpy(q, section, section_len);

    s3_memzero(&m->rt, sizeof(s3_h3_parse_headers_t));

    s3_memzero(&b, sizeof(s3_buf_t));
    b.memory = 1;
    b.pos = frame;
    b.last = q + section_len;

    rc = s3_h3_parse_headers(e->c, &m->rt, &b);

    if (rc != S3_DONE) {
        s3_fuzz_trap();
    }

    f = &m->rt.field_rep.field;

    if (f->name.len != name->len || f->value.len != value->len) {
        s3_fuzz_trap();
    }

    if (name->len != 0 && !s3_fuzz_name_eq(f->name.data, name->data, name->len)) {
        s3_fuzz_trap();
    }

    if (value->len != 0 && s3_memcmp(f->value.data, value->data, value->len) != 0) {
        s3_fuzz_trap();
    }

    s3_fuzz_sink(f->name.len + f->value.len);
}

/*
 * the uni machine feed: the first chunk of a dedicated machine goes
 * out with the stream type prepended (the raw machine fuzzer picks
 * the type itself); a terminal protocol error means the connection
 * close of the real session, the harness restarts the machine and
 * keeps the session state for the next steps
 */
static void
s3_fuzz_uni_step(s3_connection_t *c, s3_h3_parse_uni_t *st, s3_uint_t *started, u_char type,
                 unsigned prepend, u_char *chunk, size_t len)
{
    u_char   feed[256];
    s3_buf_t b;
    s3_int_t rc;

    if (prepend && !*started) {
        feed[0] = type;
        s3_memcpy(feed + 1, chunk, len);

        len += 1;
        chunk = feed;
        *started = 1;
    }

    s3_memzero(&b, sizeof(s3_buf_t));
    b.memory = 1;
    b.pos = chunk;
    b.last = chunk + len;

    rc = s3_h3_parse_uni(c, st, &b);

    s3_fuzz_sink((size_t)rc + (size_t)(b.last - b.pos));

    switch (rc) {

    case S3_AGAIN:
    case S3_OK:
    case S3_DONE:
    case S3_BUSY:
        break;

    default:
        s3_memzero(st, sizeof(s3_h3_parse_uni_t));
        *started = 0;
    }
}

/*
 * the request-stream headers step: the payload is the raw field
 * section, wrapped into a complete HEADERS frame; a DONE section
 * must round-trip through the encoders
 */
static void
s3_fuzz_headers_step(s3_fuzz_env_t *e, s3_fuzz_machines_t *m, u_char *chunk, size_t len)
{
    u_char   frame[280];
    u_char  *p;
    s3_buf_t b;
    s3_int_t rc;

    frame[0] = S3_H3_FRAME_HEADERS;
    p = (u_char *)s3_h3_encode_varlen_int(frame + 1, len);
    s3_memcpy(p, chunk, len);

    s3_memzero(&b, sizeof(s3_buf_t));
    b.memory = 1;
    b.pos = frame;
    b.last = p + len;

    rc = s3_h3_parse_headers(e->c, &m->hdr, &b);

    s3_fuzz_sink((size_t)rc + (size_t)(b.last - b.pos));

    if (rc == S3_DONE) {
        s3_fuzz_field_roundtrip(e, m, &m->hdr.field_rep.field.name, &m->hdr.field_rep.field.value);

        return;
    }

    switch (rc) {

    case S3_AGAIN:
    case S3_OK:
        break;

    default:
        /* the BUSY blocked stream and the terminal errors restart
         * the machine; the block stays queued on the session */
        s3_memzero(&m->hdr, sizeof(s3_h3_parse_headers_t));
    }
}

/*
 * the dynamic reference round-trip: a section the encoders build
 * against the live table (the required insert count encodes the
 * current base+nelts, the field references a live entry by the
 * relative index) must decode to exactly the looked-up entry
 */
static void
s3_fuzz_dynref_step(s3_fuzz_env_t *e, s3_fuzz_machines_t *m, u_char *chunk)
{
    u_char                 frame[64];
    u_char                *p;
    s3_str_t               name, value;
    size_t                 n, a, rel;
    s3_buf_t               b;
    s3_int_t               rc;
    s3_h3_parse_field_t   *f;
    s3_h3_dynamic_table_t *dt;

    dt = &e->h3c->table;

    n = (size_t)(dt->base + dt->nelts);

    if (n == 0 || dt->nelts == 0 || dt->elts == NULL) {
        return;
    }

    a = (size_t)dt->base + (size_t)(chunk[0] % dt->nelts);

    if (s3_h3_lookup(e->c, (s3_uint_t)a, &name, &value) != S3_OK) {
        return;
    }

    rel = n - 1 - a;

    /*
     * the required insert count encodes as (n & 0xff) + 1: the
     * QPACK 4.5.1.1 windowing of s3_h3_decode_insert_count() maps it
     * back to exactly n for every table state; the section sits
     * directly behind the one-byte frame header
     */
    p = (u_char *)s3_h3_encode_field_section_prefix(frame + 2, (s3_uint_t)((n & 0xff) + 1), 0, 0);
    p = (u_char *)s3_h3_encode_field_ri(p, 1, (s3_uint_t)rel);

    if ((size_t)(p - frame) > 65 || (size_t)(p - (frame + 2)) > 63) {
        return;
    }

    frame[0] = S3_H3_FRAME_HEADERS;
    frame[1] = (u_char)(p - (frame + 2));

    s3_memzero(&m->rt, sizeof(s3_h3_parse_headers_t));

    s3_memzero(&b, sizeof(s3_buf_t));
    b.memory = 1;
    b.pos = frame;
    b.last = p;

    rc = s3_h3_parse_headers(e->c, &m->rt, &b);

    if (rc != S3_DONE) {
        s3_fuzz_trap();
    }

    f = &m->rt.field_rep.field;

    if (f->name.len != name.len || f->value.len != value.len ||
        s3_memcmp(f->name.data, name.data, name.len) != 0 ||
        s3_memcmp(f->value.data, value.data, value.len) != 0) {
        s3_fuzz_trap();
    }

    s3_fuzz_sink(f->name.len + f->value.len);
}

/*
 * the static reference round-trip: the section prefix is the zero
 * insert count, the indexed field line resolves through the static
 * table, the encoder and the decoder must agree on every index
 */
static void
s3_fuzz_static_step(s3_fuzz_env_t *e, s3_fuzz_machines_t *m, u_char *chunk)
{
    u_char               frame[64];
    u_char              *p;
    s3_str_t             name, value;
    s3_uint_t            idx;
    size_t               section_len;
    s3_buf_t             b;
    s3_int_t             rc;
    s3_h3_parse_field_t *f;

    idx = (s3_uint_t)(chunk[0] % s3_fuzz_static_size(e->c));

    if (s3_h3_lookup_static(e->c, idx, &name, &value) != S3_OK) {
        return;
    }

    /* the section directly behind the one-byte frame header: the
     * prefix and the indexed line stay within the 63-byte varlen */

    p = (u_char *)s3_h3_encode_field_section_prefix(frame + 2, 0, 0, 0);
    p = (u_char *)s3_h3_encode_field_ri(p, 0, idx);

    section_len = (size_t)(p - (frame + 2));

    if (section_len > 63) {
        return;
    }

    frame[0] = S3_H3_FRAME_HEADERS;
    frame[1] = (u_char)section_len;

    s3_memzero(&m->rt, sizeof(s3_h3_parse_headers_t));

    s3_memzero(&b, sizeof(s3_buf_t));
    b.memory = 1;
    b.pos = frame;
    b.last = p;

    rc = s3_h3_parse_headers(e->c, &m->rt, &b);

    if (rc != S3_DONE) {
        s3_fuzz_trap();
    }

    f = &m->rt.field_rep.field;

    if (f->name.len != name.len || f->value.len != value.len ||
        s3_memcmp(f->name.data, name.data, name.len) != 0 ||
        s3_memcmp(f->value.data, value.data, value.len) != 0) {
        s3_fuzz_trap();
    }

    s3_fuzz_sink(f->name.len + f->value.len);
}

/*
 * the varlen round-trip: the encoded int feeds a fresh uni machine
 * as the stream type, an unknown type is swallowed and leaves the
 * parsed value and the exact consumption observable
 */
static void
s3_fuzz_varlen_step(s3_fuzz_env_t *e, s3_fuzz_machines_t *m, u_char *chunk, size_t len)
{
    u_char   buf[8];
    u_char  *end;
    uint64_t value;
    size_t   i, take, n;
    s3_buf_t b;
    s3_int_t rc;

    take = len < 8 ? len : 8;

    if (take == 0) {
        return;
    }

    value = 0;

    for (i = 0; i < take; i++) {
        value = (value << 8) | chunk[i];
    }

    value &= 0x3fffffffffffffffULL;

    /* the encoder returns the end pointer over the buffer */
    end = (u_char *)s3_h3_encode_varlen_int(buf, value);
    n = (size_t)(end - buf);

    s3_memzero(&m->vlen, sizeof(s3_h3_parse_uni_t));

    s3_memzero(&b, sizeof(s3_buf_t));
    b.memory = 1;
    b.pos = buf;
    b.last = buf + n;

    rc = s3_h3_parse_uni(e->c, &m->vlen, &b);

    if (value <= 3) {
        /* the real stream types dispatch into the sub-machines */
        return;
    }

    if (rc != S3_AGAIN || m->vlen.vlint.value != value || b.pos != b.last) {
        s3_fuzz_trap();
    }

    s3_fuzz_sink((size_t)m->vlen.vlint.value);
}

static void
s3_fuzz_huff_step(s3_fuzz_env_t *e, s3_fuzz_machines_t *m, u_char *chunk, size_t len)
{
    u_char   out[512];
    u_char  *p;
    s3_int_t rc;

    (void)e;

    p = out;

    m->huff_tail ^= 1;

    rc = s3_h3_huff_decode(&m->huffstate, chunk, len, &p, m->huff_tail, &s3_fuzz_h3_log);

    /* the exact-size output is the asan guard of the decoder: at
     * most one symbol per nibble, so 2 * len can never overflow */
    s3_fuzz_sink((size_t)rc + (size_t)(p - out));
}

static void
s3_fuzz_data_step(s3_fuzz_env_t *e, s3_fuzz_machines_t *m, u_char *chunk, size_t len)
{
    s3_buf_t b;
    s3_int_t rc;

    s3_memzero(&b, sizeof(s3_buf_t));
    b.memory = 1;
    b.pos = chunk;
    b.last = chunk + len;

    rc = s3_h3_parse_data(e->c, &m->data, &b);

    s3_fuzz_sink((size_t)rc + (size_t)(b.last - b.pos) + m->data.length);

    switch (rc) {

    case S3_AGAIN:
    case S3_OK:
    case S3_DONE:
        break;

    default:
        s3_memzero(&m->data, sizeof(s3_h3_parse_data_t));
    }
}

/*
 * the blocked-stream step: a stream-like connection of its own pool
 * asks for an insert count above the live one, which parks it in the
 * session blocked queue until a new entry unblocks it
 */
static void
s3_fuzz_block_step(s3_fuzz_env_t *e, u_char *chunk)
{
    s3_connection_t       *bc;
    s3_h3_dynamic_table_t *dt;
    size_t                 n;
    s3_int_t               rc;

    if (e->nstreams == S3_FUZZ_MAX_STREAMS) {
        return;
    }

    bc = s3_get_connection(&e->ctx, e->fd);
    if (bc == NULL) {
        return;
    }

    bc->pool = s3_create_pool((size_t)S3_DEFAULT_POOL_SIZE, e->ctx.log);
    if (bc->pool == NULL) {
        return;
    }

    bc->data = e->h3c;
    bc->read->handler = s3_fuzz_dummy_read;

    dt = &e->h3c->table;

    n = (size_t)(dt->base + dt->nelts) + 1 + chunk[0];

    rc = s3_h3_check_insert_count(bc, (s3_uint_t)n);

    s3_fuzz_sink((size_t)rc + e->h3c->nblocked);

    if (rc == S3_BUSY) {
        /* the pool lives until the end of the exec: the cleanup
         * handler unblocks the queue on the teardown */
        e->streams[e->nstreams++] = bc->pool;

        return;
    }

    s3_destroy_pool(bc->pool);
}

static void
s3_fuzz_step(s3_fuzz_env_t *e, s3_fuzz_machines_t *m, u_char op, u_char *chunk, size_t len)
{
    switch (op) {

    case S3_FUZZ_OP_ENCODER:
        s3_fuzz_uni_step(e->c, &m->enc, &m->enc_started, S3_H3_STREAM_ENCODER, 1, chunk, len);
        break;

    case S3_FUZZ_OP_DECODER:
        s3_fuzz_uni_step(e->c, &m->dec, &m->dec_started, S3_H3_STREAM_DECODER, 1, chunk, len);
        break;

    case S3_FUZZ_OP_CONTROL:
        s3_fuzz_uni_step(e->c, &m->ctrl, &m->ctrl_started, S3_H3_STREAM_CONTROL, 1, chunk, len);
        break;

    case S3_FUZZ_OP_RAW:
        s3_fuzz_uni_step(e->c, &m->raw, &m->raw_started, 0, 0, chunk, len);
        break;

    case S3_FUZZ_OP_HEADERS:
        if (len != 0) {
            s3_fuzz_headers_step(e, m, chunk, len);
        }
        break;

    case S3_FUZZ_OP_DYNREF:
        if (len != 0) {
            s3_fuzz_dynref_step(e, m, chunk);
        }
        break;

    case S3_FUZZ_OP_DATA:
        s3_fuzz_data_step(e, m, chunk, len);
        break;

    case S3_FUZZ_OP_CAPACITY:
        if (len != 0) {
            s3_uint_t cap;

            cap = chunk[0];

            if (len > 1) {
                cap |= (s3_uint_t)chunk[1] << 8;
            }

            s3_fuzz_sink((size_t)s3_h3_set_capacity(e->c, cap % (S3_H3_MAX_TABLE_CAPACITY + 1)));
        }
        break;

    case S3_FUZZ_OP_BLOCK:
        if (len != 0) {
            s3_fuzz_block_step(e, chunk);
        }
        break;

    case S3_FUZZ_OP_VARLEN:
        s3_fuzz_varlen_step(e, m, chunk, len);
        break;

    case S3_FUZZ_OP_STATIC:
        if (len != 0) {
            s3_fuzz_static_step(e, m, chunk);
        }
        break;

    case S3_FUZZ_OP_HUFF:
        s3_fuzz_huff_step(e, m, chunk, len);
        break;

    default:
        /* the unknown op is a step of one zero byte */
        s3_fuzz_sink(op);
    }
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    s3_fuzz_env_t      e;
    s3_fuzz_machines_t m;
    const u_char      *pos, *end;
    u_char             chunk[256];
    size_t             len;
    u_char             op;

    if (size < 2) {
        return 0;
    }

    if (s3_fuzz_env_init(&e) != S3_OK) {
        if (e.fd != -1) {
            (void)close(e.fd);
        }

        if (e.ctx.pool != NULL) {
            s3_destroy_pool(e.ctx.pool);
        }

        return 0;
    }

    s3_fuzz_dec_sink_len = 0;
    s3_fuzz_unblocked = 0;

    s3_memzero(&m, sizeof(s3_fuzz_machines_t));

    pos = (const u_char *)data;
    end = pos + size;

    while (pos + 2 <= end) {

        op = *pos++;
        len = *pos++;

        if ((size_t)(end - pos) < len) {
            len = (size_t)(end - pos);
        }

        s3_memcpy(chunk, pos, len);
        pos += len;

        s3_fuzz_step(&e, &m, op, chunk, len);

        /* the posted queue: the insert count acks and the unblock
         * events of the table layer run here, like the worker loop */
        s3_event_process_posted(&e.ctx, &e.ctx.posted_events);
    }

    s3_event_process_posted(&e.ctx, &e.ctx.posted_events);

    s3_fuzz_sink(s3_fuzz_dec_sink_len + s3_fuzz_unblocked);

    s3_fuzz_env_done(&e);

    return 0;
}
