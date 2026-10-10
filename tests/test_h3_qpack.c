
/*
 * Copyright (C) 2026 the ssh3-c authors
 */

/*
 * the QPACK unit tests: the varint/prefix/field encoders against
 * byte-exact vectors (RFC 9000 varint, RFC 9204 prefix integers and
 * field line representations) and the static/dynamic tables on a
 * minimal fake scene: an event context, a udp socket connection with
 * the h3 session on c->data (the P3 integration scene)
 */

#if (S3_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#if (S3_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#endif
#endif
#include <string.h>
#include <unistd.h>

#include <s3_core.h>
#include <s3_h3.h>

#include "s3_test.h"

typedef struct {
    uint64_t value;
    size_t   len;
    u_char   wire[8];
} s3_test_varlen_t;

typedef struct {
    uint64_t  value;
    s3_uint_t prefix;
    u_char    preset; /* the byte ORed into buf[0] before the call */
    size_t    len;
    u_char    wire[4];
} s3_test_prefix_t;

typedef struct {
    s3_event_ctx_t   ctx;
    s3_fd_t          fd;
    s3_connection_t *c;
    s3_connection_t *bc; /* the blocked stream connection */
    s3_h3_session_t *h3c;
    s3_pool_t       *pools[24]; /* destroyed at the end of the test */
    int              npools;
} s3_test_env_t;

static s3_log_t s3_test_h3_log;

static u_char s3_test_dec_sink[64];
static size_t s3_test_dec_sink_len;

static int s3_test_unblocked;

static void
s3_test_dummy_read(s3_event_t *ev)
{
    (void)ev;

    s3_test_unblocked++;
}

/*
 * the fake stream send: consumes the chain into the sink, like the
 * quic stream send copies the data into its output buffers
 */
static s3_chain_t *
s3_test_send_chain(s3_connection_t *c, s3_chain_t *in, off_t limit)
{
    s3_chain_t *cl;

    (void)c;
    (void)limit;

    for (cl = in; cl != NULL; cl = cl->next) {
        s3_memcpy(s3_test_dec_sink + s3_test_dec_sink_len, cl->buf->pos,
                  (size_t)(cl->buf->last - cl->buf->pos));
        s3_test_dec_sink_len += cl->buf->last - cl->buf->pos;
        cl->buf->pos = cl->buf->last;
    }

    return NULL;
}

static s3_connection_t *
s3_test_new_connection(s3_test_env_t *e)
{
    s3_connection_t *c;

    c = s3_get_connection(&e->ctx, e->fd);
    if (c == NULL) {
        return NULL;
    }

    c->pool = e->ctx.pool;
    c->read->handler = s3_test_dummy_read;

    return c;
}

/*
 * a stream-like connection with its own pool: the blocked-stream
 * cleanup blocks are looked up in c->pool->cleanup, so every blocked
 * stream carries its own pool, like the nginx stream connections
 */
static s3_connection_t *
s3_test_new_stream(s3_test_env_t *e)
{
    s3_connection_t *c;

    c = s3_get_connection(&e->ctx, e->fd);
    if (c == NULL) {
        return NULL;
    }

    c->pool = s3_create_pool((size_t)S3_DEFAULT_POOL_SIZE, &s3_test_h3_log);
    e->pools[e->npools++] = c->pool;
    c->data = e->h3c;
    c->read->handler = s3_test_dummy_read;

    return c;
}

static s3_int_t
s3_test_env_init(s3_test_env_t *e)
{
    struct sockaddr_in sa;

    s3_memzero(e, sizeof(s3_test_env_t));

    s3_test_h3_log.log_level = S3_LOG_ALERT;
    s3_test_h3_log.fd = S3_INVALID_FILE;

    if (s3_event_ctx_init(&e->ctx, &s3_test_h3_log) != S3_OK) {
        return S3_ERROR;
    }

    e->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (e->fd == (s3_fd_t)-1) {
        return S3_ERROR;
    }

    s3_memzero(&sa, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = 0;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(e->fd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
        return S3_ERROR;
    }

    e->c = s3_test_new_connection(e);
    e->bc = s3_test_new_connection(e);

    if (e->c == NULL || e->bc == NULL) {
        return S3_ERROR;
    }

    /* the h3 session hangs on the connection, like the session layer */
    e->h3c = s3_pcalloc(e->ctx.pool, sizeof(s3_h3_session_t));
    if (e->h3c == NULL) {
        return S3_ERROR;
    }

    s3_queue_init(&e->h3c->blocked);

    e->h3c->ctx = &e->ctx;

    e->h3c->table.send_insert_count.log = e->c->log;
    e->h3c->table.send_insert_count.data = e->c;
    e->h3c->table.send_insert_count.handler = s3_h3_inc_insert_count_handler;

    /* every connection passed to the table functions carries the session */
    e->c->data = e->h3c;
    e->bc->data = e->h3c;

    return S3_OK;
}

static void
s3_test_varlen(void)
{
    s3_test_varlen_t vectors[] = {
        {0, 1, {0x00}},
        {63, 1, {0x3f}},
        {127, 2, {0x40, 0x7f}},
        {128, 2, {0x40, 0x80}},
        {16383, 2, {0x7f, 0xff}},
        {16384, 4, {0x80, 0x00, 0x40, 0x00}},
        {0x0fffffff, 4, {0x8f, 0xff, 0xff, 0xff}},
        {0x10000000, 4, {0x90, 0x00, 0x00, 0x00}},
        {0x3fffffff, 4, {0xbf, 0xff, 0xff, 0xff}},
        {0x40000000, 8, {0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00}},
        {0x1234567890ab, 8, {0xc0, 0x00, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab}},
    };

    u_char    buf[8];
    u_char   *end;
    uintptr_t n;
    s3_uint_t i;

    for (i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
        n = s3_h3_encode_varlen_int(NULL, vectors[i].value);
        S3_ASSERT(n == vectors[i].len);

        s3_memzero(buf, sizeof(buf));
        end = (u_char *)s3_h3_encode_varlen_int(buf, vectors[i].value);

        S3_ASSERT((uintptr_t)(end - buf) == vectors[i].len);
        S3_ASSERT(s3_memcmp(buf, vectors[i].wire, vectors[i].len) == 0);
    }
}

static void
s3_test_prefix(void)
{
    s3_test_prefix_t vectors[] = {
        {126, 7, 0x00, 1, {0x7e}},
        {127, 7, 0x00, 2, {0x7f, 0x00}},
        {128, 7, 0x00, 2, {0x7f, 0x01}},
        {245, 7, 0x00, 2, {0x7f, 0x76}},
        {24576, 7, 0x00, 4, {0x7f, 0x81, 0xbf, 0x01}},
        {14, 4, 0x00, 1, {0x0e}},
        {15, 4, 0x00, 2, {0x0f, 0x00}},
        {1000, 4, 0x00, 3, {0x0f, 0xd9, 0x07}},
        {10, 6, 0xc0, 1, {0xca}},
        {17, 4, 0x50, 2, {0x5f, 0x02}},
    };

    u_char    buf[11];
    u_char   *end;
    uintptr_t n;
    s3_uint_t i;

    for (i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
        n = s3_h3_encode_prefix_int(NULL, vectors[i].value, vectors[i].prefix);
        S3_ASSERT(n == vectors[i].len);

        s3_memzero(buf, sizeof(buf));
        buf[0] = vectors[i].preset;
        end = (u_char *)s3_h3_encode_prefix_int(buf, vectors[i].value, vectors[i].prefix);

        S3_ASSERT((uintptr_t)(end - buf) == vectors[i].len);
        S3_ASSERT(s3_memcmp(buf, vectors[i].wire, vectors[i].len) == 0);
    }
}

static void
s3_test_encoders(void)
{
    u_char    buf[64];
    u_char   *end;
    s3_str_t  name, value;
    uintptr_t n;

    /* field section prefix: insert_count 3, sign 0, delta_base 5 */
    s3_memzero(buf, sizeof(buf));
    end = (u_char *)s3_h3_encode_field_section_prefix(buf, 3, 0, 5);
    S3_ASSERT((uintptr_t)(end - buf) == 2);
    S3_ASSERT(buf[0] == 0x03 && buf[1] == 0x05);

    /* the sign bit goes into the delta_base prefix byte */
    s3_memzero(buf, sizeof(buf));
    end = (u_char *)s3_h3_encode_field_section_prefix(buf, 3, 1, 5);
    S3_ASSERT((uintptr_t)(end - buf) == 2);
    S3_ASSERT(buf[0] == 0x03 && buf[1] == 0x85);

    /* insert_count 300 overflows the 8-bit prefix: ff 2d, delta 00 */
    s3_memzero(buf, sizeof(buf));
    end = (u_char *)s3_h3_encode_field_section_prefix(buf, 300, 0, 0);
    S3_ASSERT((uintptr_t)(end - buf) == 3);
    S3_ASSERT(s3_memcmp(buf, "\xff\x2d\x00", 3) == 0);

    n = s3_h3_encode_field_section_prefix(NULL, 300, 1, 0);
    S3_ASSERT(n == 3);

    /* indexed field line, static index 5: c0 | 5 */
    s3_memzero(buf, sizeof(buf));
    end = (u_char *)s3_h3_encode_field_ri(buf, 0, 5);
    S3_ASSERT((uintptr_t)(end - buf) == 1);
    S3_ASSERT(buf[0] == 0xc5);

    /* indexed field line, dynamic index 5: 80 | 5 */
    s3_memzero(buf, sizeof(buf));
    end = (u_char *)s3_h3_encode_field_ri(buf, 1, 5);
    S3_ASSERT((uintptr_t)(end - buf) == 1);
    S3_ASSERT(buf[0] == 0x85);

    /* indexed field line, static index 100: ff, 37 */
    s3_memzero(buf, sizeof(buf));
    end = (u_char *)s3_h3_encode_field_ri(buf, 0, 100);
    S3_ASSERT((uintptr_t)(end - buf) == 2);
    S3_ASSERT(s3_memcmp(buf, "\xff\x25", 2) == 0);

    n = s3_h3_encode_field_ri(NULL, 0, 100);
    S3_ASSERT(n == 2);

    /*
     * literal with static name reference: :method (17), value "ssh3";
     * 5f 02 | 04 | "ssh3"
     */
    value.data = (u_char *)"ssh3";
    value.len = 4;

    s3_memzero(buf, sizeof(buf));
    end = (u_char *)s3_h3_encode_field_lri(buf, 0, 17, value.data, value.len);
    S3_ASSERT((uintptr_t)(end - buf) == 7);
    S3_ASSERT(s3_memcmp(buf, "\x5f\x02\x04ssh3", 7) == 0);

    /* literal with dynamic name reference 0, value "ab" */
    s3_memzero(buf, sizeof(buf));
    end = (u_char *)s3_h3_encode_field_lri(buf, 1, 0, (u_char *)"ab", 2);
    S3_ASSERT((uintptr_t)(end - buf) == 4);
    S3_ASSERT(s3_memcmp(buf,
                        "\x40\x02"
                        "ab",
                        4) == 0);

    /* literal with name reference, no value data */
    s3_memzero(buf, sizeof(buf));
    end = (u_char *)s3_h3_encode_field_lri(buf, 0, 3, NULL, 0);
    S3_ASSERT((uintptr_t)(end - buf) == 2);
    S3_ASSERT(s3_memcmp(buf, "\x53\x00", 2) == 0);

    n = s3_h3_encode_field_lri(NULL, 0, 17, value.data, value.len);
    S3_ASSERT(n == 7);

    /* literal with literal name: "x-h3": "v1" */
    name.data = (u_char *)"x-h3";
    name.len = 4;
    value.data = (u_char *)"v1";
    value.len = 2;

    s3_memzero(buf, sizeof(buf));
    end = (u_char *)s3_h3_encode_field_l(buf, &name, &value);
    S3_ASSERT((uintptr_t)(end - buf) == 8);
    S3_ASSERT(s3_memcmp(buf, "\x24x-h3\x02v1", 8) == 0);

    /*
     * the name is lowercased on the literal path ("User-Agent" with
     * the 3-bit prefix overflowing: 27 03)
     */
    name.data = (u_char *)"User-Agent";
    name.len = 10;
    value.data = (u_char *)"t";
    value.len = 1;

    s3_memzero(buf, sizeof(buf));
    end = (u_char *)s3_h3_encode_field_l(buf, &name, &value);
    S3_ASSERT((uintptr_t)(end - buf) == 14);
    S3_ASSERT(s3_memcmp(buf, "\x27\x03user-agent\x01t", 14) == 0);

    n = s3_h3_encode_field_l(NULL, &name, &value);
    S3_ASSERT(n == 14);

    /* indexed post-base: 10 | 5 */
    s3_memzero(buf, sizeof(buf));
    end = (u_char *)s3_h3_encode_field_pbi(buf, 5);
    S3_ASSERT((uintptr_t)(end - buf) == 1);
    S3_ASSERT(buf[0] == 0x15);

    n = s3_h3_encode_field_pbi(NULL, 5);
    S3_ASSERT(n == 1);

    /* literal post-base with name reference 3, value "abc" */
    s3_memzero(buf, sizeof(buf));
    end = (u_char *)s3_h3_encode_field_lpbi(buf, 3, (u_char *)"abc", 3);
    S3_ASSERT((uintptr_t)(end - buf) == 5);
    S3_ASSERT(s3_memcmp(buf,
                        "\x03\x03"
                        "abc",
                        5) == 0);

    n = s3_h3_encode_field_lpbi(NULL, 3, (u_char *)"abc", 3);
    S3_ASSERT(n == 5);
}

static void
s3_test_static_table(s3_test_env_t *e)
{
    s3_str_t name, value;

    /* RFC 9204 static table anchors */
    S3_ASSERT(s3_h3_lookup_static(e->c, 0, &name, &value) == S3_OK);
    S3_ASSERT(name.len == 10 && s3_memcmp(name.data, ":authority", 10) == 0);
    S3_ASSERT(value.len == 0);

    S3_ASSERT(s3_h3_lookup_static(e->c, 1, &name, &value) == S3_OK);
    S3_ASSERT(name.len == 5 && s3_memcmp(name.data, ":path", 5) == 0);
    S3_ASSERT(value.len == 1 && value.data[0] == '/');

    S3_ASSERT(s3_h3_lookup_static(e->c, 17, &name, &value) == S3_OK);
    S3_ASSERT(name.len == 7 && s3_memcmp(name.data, ":method", 7) == 0);
    S3_ASSERT(value.len == 3 && s3_memcmp(value.data, "GET", 3) == 0);

    S3_ASSERT(s3_h3_lookup_static(e->c, 25, &name, &value) == S3_OK);
    S3_ASSERT(name.len == 7 && s3_memcmp(name.data, ":status", 7) == 0);
    S3_ASSERT(value.len == 3 && s3_memcmp(value.data, "200", 3) == 0);

    /* the value pointer is optional */
    S3_ASSERT(s3_h3_lookup_static(e->c, 1, &name, NULL) == S3_OK);
    S3_ASSERT(name.len == 5);

    /* out of bounds */
    S3_ASSERT(s3_h3_lookup_static(e->c, 1000, &name, &value) == S3_ERROR);
}

static void
s3_test_dynamic_table(s3_test_env_t *e)
{
    s3_buf_t        *ib, *ib2;
    s3_connection_t *bc2, *bc3;
    s3_int_t         rc;
    s3_str_t         name, value;
    s3_uint_t        i;

    /* capacity setup */
    S3_ASSERT(s3_h3_set_capacity(e->c, 512) == S3_OK);
    S3_ASSERT(e->h3c->table.capacity == 512);
    S3_ASSERT(e->h3c->table.elts != NULL);

    /* the fixed limit rejects larger capacities */
    S3_ASSERT(s3_h3_set_capacity(e->c, S3_H3_MAX_TABLE_CAPACITY + 1) ==
              S3_H3_ERR_ENCODER_STREAM_ERROR);

    /* empty dynamic table lookup */
    S3_ASSERT(s3_h3_lookup(e->c, 0, &name, &value) == S3_ERROR);

    /* the stream blocks until an entry arrives */
    rc = s3_h3_check_insert_count(e->c, 1);
    S3_ASSERT(rc == S3_BUSY);
    S3_ASSERT(e->h3c->nblocked == 1);

    /* insert "alpha": "one" */
    name.data = (u_char *)"alpha";
    name.len = 5;
    value.data = (u_char *)"one";
    value.len = 3;

    S3_ASSERT(s3_h3_insert(e->c, &name, &value) == S3_OK);
    S3_ASSERT(e->h3c->table.insert_count == 1);

    /* insert "beta": "two"; both inserts batch into one posted event */
    name.data = (u_char *)"beta";
    name.len = 4;
    value.data = (u_char *)"two";
    value.len = 3;

    S3_ASSERT(s3_h3_insert(e->c, &name, &value) == S3_OK);
    S3_ASSERT(e->h3c->table.insert_count == 2);
    S3_ASSERT(e->h3c->table.size == 40 + 39);

    /* the decoder stream answers the batched insert count increment */
    e->h3c->known_streams[S3_H3_STREAM_SERVER_DECODER] = s3_test_new_connection(e);
    e->h3c->known_streams[S3_H3_STREAM_SERVER_DECODER]->send_chain = s3_test_send_chain;

    s3_event_process_posted(&e->ctx, &e->ctx.posted_events);

    S3_ASSERT(s3_test_unblocked == 1);
    S3_ASSERT(e->h3c->nblocked == 0);
    S3_ASSERT(s3_test_dec_sink_len == 1);
    S3_ASSERT(s3_test_dec_sink[0] == 0x02);
    S3_ASSERT(e->h3c->table.ack_insert_count == 2);

    /* the stream proceeds */
    S3_ASSERT(s3_h3_check_insert_count(e->c, 2) == S3_OK);

    /* lookups by absolute index */
    S3_ASSERT(s3_h3_lookup(e->c, 0, &name, &value) == S3_OK);
    S3_ASSERT(name.len == 5 && s3_memcmp(name.data, "alpha", 5) == 0);
    S3_ASSERT(value.len == 3 && s3_memcmp(value.data, "one", 3) == 0);

    S3_ASSERT(s3_h3_lookup(e->c, 1, &name, &value) == S3_OK);
    S3_ASSERT(name.len == 4 && s3_memcmp(name.data, "beta", 4) == 0);

    S3_ASSERT(s3_h3_lookup(e->c, 2, &name, &value) == S3_ERROR);

    /* duplicate of the relative index 0 ("beta": "two") */
    S3_ASSERT(s3_h3_duplicate(e->c, 0) == S3_OK);
    S3_ASSERT(e->h3c->table.insert_count == 3);
    S3_ASSERT(s3_h3_lookup(e->c, 2, &name, &value) == S3_OK);
    S3_ASSERT(name.len == 4 && s3_memcmp(name.data, "beta", 4) == 0);
    S3_ASSERT(value.len == 3 && s3_memcmp(value.data, "two", 3) == 0);

    S3_ASSERT(s3_h3_duplicate(e->c, 100) == S3_H3_ERR_ENCODER_STREAM_ERROR);

    /* ref insert through the static table (":method" at 17) */
    value.data = (u_char *)"v1";
    value.len = 2;

    S3_ASSERT(s3_h3_ref_insert(e->c, 0, 17, &value) == S3_OK);
    S3_ASSERT(e->h3c->table.insert_count == 4);
    S3_ASSERT(s3_h3_lookup(e->c, 3, &name, &value) == S3_OK);
    S3_ASSERT(name.len == 7 && s3_memcmp(name.data, ":method", 7) == 0);
    S3_ASSERT(value.len == 2 && s3_memcmp(value.data, "v1", 2) == 0);

    S3_ASSERT(s3_h3_ref_insert(e->c, 0, 1000, &value) == S3_H3_ERR_ENCODER_STREAM_ERROR);

    /* ref insert through the dynamic table (relative index 0) */
    value.data = (u_char *)"v2";
    value.len = 2;

    S3_ASSERT(s3_h3_ref_insert(e->c, 1, 0, &value) == S3_OK);
    S3_ASSERT(e->h3c->table.insert_count == 5);
    S3_ASSERT(s3_h3_lookup(e->c, 4, &name, &value) == S3_OK);
    S3_ASSERT(name.len == 7 && s3_memcmp(name.data, ":method", 7) == 0);
    S3_ASSERT(value.len == 2 && s3_memcmp(value.data, "v2", 2) == 0);

    S3_ASSERT(s3_h3_ref_insert(e->c, 1, 10, &value) == S3_H3_ERR_ENCODER_STREAM_ERROR);

    /*
     * shrinking the capacity evicts the oldest entries: 200 bytes
     * down to 41, four entries dropped
     */
    S3_ASSERT(s3_h3_set_capacity(e->c, 64) == S3_OK);
    S3_ASSERT(e->h3c->table.base == 4);
    S3_ASSERT(e->h3c->table.nelts == 1);
    S3_ASSERT(e->h3c->table.size == 41);
    S3_ASSERT(e->h3c->table.insert_count == 5);
    S3_ASSERT(e->h3c->table.ack_insert_count == 2);

    S3_ASSERT(s3_h3_lookup(e->c, 3, &name, &value) == S3_ERROR);
    S3_ASSERT(s3_h3_lookup(e->c, 4, &name, &value) == S3_OK);
    S3_ASSERT(value.len == 2 && s3_memcmp(value.data, "v2", 2) == 0);

    /* an entry larger than the capacity is rejected */
    name.data = (u_char *)"n";
    name.len = 40;
    value.data = (u_char *)"v";
    value.len = 40;

    S3_ASSERT(s3_h3_insert(e->c, &name, &value) == S3_H3_ERR_ENCODER_STREAM_ERROR);

    /* the decoder stream feedback is not used */
    S3_ASSERT(s3_h3_ack_section(e->c, 0) == S3_H3_ERR_DECODER_STREAM_ERROR);
    S3_ASSERT(s3_h3_inc_insert_count(e->c, 1) == S3_H3_ERR_DECODER_STREAM_ERROR);

    /* QPACK 4.5.1.1 required insert count decoding */
    i = 0;
    S3_ASSERT(s3_h3_decode_insert_count(e->c, &i) == S3_OK);
    S3_ASSERT(i == 0);

    i = 5;
    S3_ASSERT(s3_h3_decode_insert_count(e->c, &i) == S3_OK);
    S3_ASSERT(i == 4);

    i = 134;
    S3_ASSERT(s3_h3_decode_insert_count(e->c, &i) == S3_OK);
    S3_ASSERT(i == 133);

    i = 135;
    S3_ASSERT(s3_h3_decode_insert_count(e->c, &i) == S3_H3_ERR_DECOMPRESSION_FAILED);

    i = 300;
    S3_ASSERT(s3_h3_decode_insert_count(e->c, &i) == S3_H3_ERR_DECOMPRESSION_FAILED);

    /* the manual ack only moves the counter forward */
    s3_h3_ack_insert_count(e->c, 1);
    S3_ASSERT(e->h3c->table.ack_insert_count == 2);
    s3_h3_ack_insert_count(e->c, 3);
    S3_ASSERT(e->h3c->table.ack_insert_count == 3);

    /* settings parameters are accepted */
    S3_ASSERT(s3_h3_set_param(e->c, S3_H3_PARAM_MAX_TABLE_CAPACITY, 4096) == S3_OK);
    S3_ASSERT(s3_h3_set_param(e->c, S3_H3_PARAM_BLOCKED_STREAMS, 100) == S3_OK);
    S3_ASSERT(s3_h3_set_param(e->c, 0x1234, 5) == S3_OK);

    /*
     * the blocked streams limit: every stream connection carries its
     * own pool and adds one block, the 17th is rejected
     */
    for (i = 0; i < 16; i++) {
        bc2 = s3_test_new_stream(e);
        S3_ASSERT(bc2 != NULL);

        rc = s3_h3_check_insert_count(bc2, 999);
        S3_ASSERT(rc == S3_BUSY);
    }

    S3_ASSERT(e->h3c->nblocked == 16);

    bc3 = s3_test_new_stream(e);
    S3_ASSERT(bc3 != NULL);

    rc = s3_h3_check_insert_count(bc3, 999);
    S3_ASSERT(rc == S3_H3_ERR_DECOMPRESSION_FAILED);
    S3_ASSERT(e->h3c->nblocked == 16);

    /* the insert buffer is created once and reset per call */
    ib = s3_h3_get_insert_buffer(e->c);
    S3_ASSERT(ib != NULL);
    S3_ASSERT((size_t)(ib->end - ib->start) == (size_t)S3_H3_MAX_TABLE_CAPACITY);

    ib->last = ib->pos + 10;

    ib2 = s3_h3_get_insert_buffer(e->c);
    S3_ASSERT(ib2 == ib);
    S3_ASSERT(ib2->last == ib2->pos);
}

/*
 * the empty field value on the insert path: the QPACK INR/ILN
 * instructions with a zero length used to leave value.data NULL and
 * trip the nonnull memcpy here; the parse parks "" now (the fuzz
 * harness replays its minimized repro against the wire path), this
 * pins the table contract the parser feeds
 */

static void
s3_test_empty_value(s3_test_env_t *e)
{
    u_char  *base;
    s3_str_t name, value;

    name.data = (u_char *)"alpha";
    name.len = 5;
    value.data = (u_char *)"";
    value.len = 0;

    base = (u_char *)(uintptr_t)e->h3c->table.insert_count;

    S3_ASSERT(s3_h3_insert(e->c, &name, &value) == S3_OK);
    S3_ASSERT(e->h3c->table.insert_count == (uint64_t)(uintptr_t)base + 1);

    S3_ASSERT(s3_h3_lookup(e->c, (uint64_t)(uintptr_t)base, &name, &value) == S3_OK);
    S3_ASSERT(name.len == 5 && s3_memcmp(name.data, "alpha", 5) == 0);
    S3_ASSERT(value.len == 0);
}

static int
s3_test_h3_qpack(void)
{
    /* static like the other test envs: the event ctx pool outlives main */
    static s3_test_env_t e;

    s3_test_varlen();
    s3_test_prefix();
    s3_test_encoders();

    if (s3_test_env_init(&e) != S3_OK) {
        printf("FAIL env init\n");
        return ++s3_test_failures;
    }

    s3_test_static_table(&e);
    s3_test_dynamic_table(&e);
    s3_test_empty_value(&e);

    s3_test_close(e.fd);

    while (e.npools > 0) {
        s3_destroy_pool(e.pools[--e.npools]);
    }

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_h3_qpack)
