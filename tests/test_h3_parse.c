/*
 * Copyright (C) 2026 the ssh3-c authors
 */

/*
 * HTTP/3 parser state machine tests, P3 wave 1: the dynamic table
 * (s3_h3_table.c) is a stub returning S3_ERROR, so table-dependent
 * branches are exercised only up to the stub call; the mapped error
 * codes and the parser state left behind are asserted as documented
 * stub behavior. Full glue is on wave 2.
 */

#include <s3_core.h>
#include <s3_h3.h>
#include <string.h>

#include "s3_test.h"

/*
 * the huffman decoder is public in s3_h3_parse.c (as the nginx
 * original is) but is not promoted to the frozen s3_h3_parse.h yet
 */
s3_int_t s3_h3_huff_decode(u_char *state, u_char *src, size_t len, u_char **dst, s3_uint_t last,
                           s3_log_t *log);

static s3_log_t s3_test_log = {0, S3_INVALID_FILE};

static s3_buf_t
s3_test_buf(u_char *data, size_t len)
{
    s3_buf_t b;

    s3_memzero(&b, sizeof(s3_buf_t));
    b.pos = data;
    b.last = data + len;

    return b;
}

static s3_connection_t *
s3_test_conn(s3_pool_t *pool)
{
    static s3_connection_t c;
    static s3_h3_session_t h3c;

    s3_memzero(&c, sizeof(s3_connection_t));
    s3_memzero(&h3c, sizeof(s3_h3_session_t));

    c.log = &s3_test_log;
    c.pool = pool;

    /*
     * the real QPACK table dereferences the session; the wave-1 parse
     * tests run against zeroed table state
     */
    c.data = &h3c;

    return &c;
}

/*
 * varlen int, via the uni stream type: an unknown stream type is
 * swallowed and the machine waits for more data (S3_AGAIN), leaving
 * st->vlint.value observable
 */
static void
s3_test_varlen(s3_connection_t *c)
{
    u_char            buf[8];
    s3_buf_t          b;
    s3_int_t          rc;
    s3_h3_parse_uni_t st;

    /* 1 byte: 0x25 = 37 (RFC 9000 16) */
    s3_memzero(&st, sizeof(s3_h3_parse_uni_t));
    buf[0] = 0x25;
    b = s3_test_buf(buf, 1);
    rc = s3_h3_parse_uni(c, &st, &b);
    S3_ASSERT(rc == S3_AGAIN);
    S3_ASSERT(st.vlint.value == 37);

    /* 2 bytes: 0x7bbd = 15293 */
    s3_memzero(&st, sizeof(s3_h3_parse_uni_t));
    buf[0] = 0x7b;
    buf[1] = 0xbd;
    b = s3_test_buf(buf, 2);
    rc = s3_h3_parse_uni(c, &st, &b);
    S3_ASSERT(rc == S3_AGAIN);
    S3_ASSERT(st.vlint.value == 15293);

    /* 4 bytes: 0x9d7f3e7d = 494878333 */
    s3_memzero(&st, sizeof(s3_h3_parse_uni_t));
    buf[0] = 0x9d;
    buf[1] = 0x7f;
    buf[2] = 0x3e;
    buf[3] = 0x7d;
    b = s3_test_buf(buf, 4);
    rc = s3_h3_parse_uni(c, &st, &b);
    S3_ASSERT(rc == S3_AGAIN);
    S3_ASSERT(st.vlint.value == 494878333);

    /* 8 bytes: 0xc2197c5eff14e88c, high bits masked to 62 bits */
    s3_memzero(&st, sizeof(s3_h3_parse_uni_t));
    buf[0] = 0xc2;
    buf[1] = 0x19;
    buf[2] = 0x7c;
    buf[3] = 0x5e;
    buf[4] = 0xff;
    buf[5] = 0x14;
    buf[6] = 0xe8;
    buf[7] = 0x8c;
    b = s3_test_buf(buf, 8);
    rc = s3_h3_parse_uni(c, &st, &b);
    S3_ASSERT(rc == S3_AGAIN);
    S3_ASSERT(st.vlint.value == (0xc2197c5eff14e88cULL & 0x3fffffffffffffffULL));

    /* truncated mid-sequence */
    s3_memzero(&st, sizeof(s3_h3_parse_uni_t));
    buf[0] = 0x9d;
    buf[1] = 0x7f;
    b = s3_test_buf(buf, 2);
    rc = s3_h3_parse_uni(c, &st, &b);
    S3_ASSERT(rc == S3_AGAIN);

    /* the 2 upper bits of an 8-byte int are masked off */
    s3_memzero(&st, sizeof(s3_h3_parse_uni_t));
    buf[0] = 0xc0;
    buf[1] = 0xff;
    buf[2] = 0xff;
    buf[3] = 0xff;
    buf[4] = 0xff;
    buf[5] = 0xff;
    buf[6] = 0xff;
    buf[7] = 0xff;
    b = s3_test_buf(buf, 8);
    rc = s3_h3_parse_uni(c, &st, &b);
    S3_ASSERT(rc == S3_AGAIN);
    S3_ASSERT(st.vlint.value == 0x00ffffffffffffffULL);
}

/*
 * prefix int, via the headers field section prefix: the 8-bit request
 * insert count and the 7-bit delta base are observable in the state;
 * s3_h3_decode_insert_count() is a wave-1 stub returning S3_ERROR
 */
static void
s3_test_prefix_int(s3_connection_t *c)
{
    u_char                buf[16];
    s3_buf_t              b;
    s3_int_t              rc;
    s3_h3_parse_headers_t st;

    /* single-byte values: insert_count = 0, sign = 0, delta_base = 5 */
    s3_memzero(&st, sizeof(s3_h3_parse_headers_t));
    buf[0] = 0x01; /* HEADERS frame */
    buf[1] = 0x02; /* frame length */
    buf[2] = 0x00; /* insert count */
    buf[3] = 0x05; /* sign | delta base */
    b = s3_test_buf(buf, 4);
    rc = s3_h3_parse_headers(c, &st, &b);
    /* a section without field lines is a frame error (reference semantics) */
    S3_ASSERT(rc == S3_H3_ERR_FRAME_ERROR);
    S3_ASSERT(st.prefix.insert_count == 0);
    S3_ASSERT(st.prefix.sign == 0);
    S3_ASSERT(st.prefix.delta_base == 5);
    S3_ASSERT(st.length == 0);

    /* 8-bit continuation: insert count 512 = 0xff 0x81 0x02, sign = 1 */
    s3_memzero(&st, sizeof(s3_h3_parse_headers_t));
    buf[0] = 0x01;
    buf[1] = 0x04;
    buf[2] = 0xff;
    buf[3] = 0x81;
    buf[4] = 0x02;
    buf[5] = 0x85;
    b = s3_test_buf(buf, 6);
    rc = s3_h3_parse_headers(c, &st, &b);
    /* insert count 512 exceeds the full range (2 * 4096/32) */
    S3_ASSERT(rc == S3_H3_ERR_DECOMPRESSION_FAILED);
    S3_ASSERT(st.prefix.insert_count == 512);
    S3_ASSERT(st.prefix.sign == 1);
    S3_ASSERT(st.prefix.delta_base == 5);

    /* integer size limit: 9 continuation bytes with the high bit set */
    s3_memzero(&st, sizeof(s3_h3_parse_headers_t));
    buf[0] = 0x01;
    buf[1] = 0x0a;
    buf[2] = 0xff;
    buf[3] = 0x80;
    buf[4] = 0x80;
    buf[5] = 0x80;
    buf[6] = 0x80;
    buf[7] = 0x80;
    buf[8] = 0x80;
    buf[9] = 0x80;
    buf[10] = 0x80;
    buf[11] = 0x80;
    b = s3_test_buf(buf, 12);
    rc = s3_h3_parse_headers(c, &st, &b);
    S3_ASSERT(rc == S3_H3_ERR_EXCESSIVE_LOAD);

    /* chunked feed: the frame header alone leaves the machine waiting */
    s3_memzero(&st, sizeof(s3_h3_parse_headers_t));
    buf[0] = 0x01;
    buf[1] = 0x02;
    b = s3_test_buf(buf, 2);
    rc = s3_h3_parse_headers(c, &st, &b);
    S3_ASSERT(rc == S3_AGAIN);

    buf[0] = 0x00;
    buf[1] = 0x07;
    b = s3_test_buf(buf, 2);
    rc = s3_h3_parse_headers(c, &st, &b);
    /* a section without field lines is a frame error (reference semantics) */
    S3_ASSERT(rc == S3_H3_ERR_FRAME_ERROR);
    S3_ASSERT(st.prefix.insert_count == 0);
    S3_ASSERT(st.prefix.delta_base == 7);
}

static void
s3_test_headers_frames(s3_connection_t *c)
{
    u_char                buf[16];
    s3_buf_t              b;
    s3_int_t              rc;
    s3_h3_parse_headers_t st;

    /* DATA frame on a request stream */
    s3_memzero(&st, sizeof(s3_h3_parse_headers_t));
    buf[0] = 0x00;
    buf[1] = 0x00;
    b = s3_test_buf(buf, 2);
    rc = s3_h3_parse_headers(c, &st, &b);
    S3_ASSERT(rc == S3_H3_ERR_FRAME_UNEXPECTED);

    /* reserved v2 frame type */
    s3_memzero(&st, sizeof(s3_h3_parse_headers_t));
    buf[0] = 0x02;
    buf[1] = 0x00;
    b = s3_test_buf(buf, 2);
    rc = s3_h3_parse_headers(c, &st, &b);
    S3_ASSERT(rc == S3_H3_ERR_FRAME_UNEXPECTED);

    /* zero-length HEADERS frame */
    s3_memzero(&st, sizeof(s3_h3_parse_headers_t));
    buf[0] = 0x01;
    buf[1] = 0x00;
    b = s3_test_buf(buf, 2);
    rc = s3_h3_parse_headers(c, &st, &b);
    S3_ASSERT(rc == S3_H3_ERR_FRAME_ERROR);

    /* an unknown frame type is skipped, the machine waits for the next */
    s3_memzero(&st, sizeof(s3_h3_parse_headers_t));
    buf[0] = 0x33;
    buf[1] = 0x02;
    buf[2] = 0xde;
    buf[3] = 0xad;
    b = s3_test_buf(buf, 4);
    rc = s3_h3_parse_headers(c, &st, &b);
    S3_ASSERT(rc == S3_AGAIN);
    S3_ASSERT(st.type == 0x33);
}

/*
 * Insert With Literal Name / Insert With Name Reference: both literal
 * machines bind to the dynamic table insert buffer through
 * s3_h3_get_insert_buffer() before parsing anything, and that is a
 * wave-1 stub returning NULL - assert that documented behavior
 */
static void
s3_test_literal(s3_connection_t *c)
{
    u_char            buf[4];
    s3_buf_t          b;
    s3_int_t          rc;
    s3_h3_parse_uni_t st;

    /* Insert With Literal Name on the encoder stream */
    s3_memzero(&st, sizeof(s3_h3_parse_uni_t));
    buf[0] = 0x02; /* uni: encoder stream */
    buf[1] = 0x60; /* ILN, Huffman name */
    buf[2] = 0x01;
    buf[3] = 0x00;
    b = s3_test_buf(buf, 4);
    rc = s3_h3_parse_uni(c, &st, &b);
    S3_ASSERT(rc == S3_ERROR); /* the insert buffer stub is NULL */
    S3_ASSERT(st.u.encoder.field.name.len == 0);
    S3_ASSERT(st.u.encoder.field.name.data == NULL);

    /* Insert With Name Reference behaves the same way */
    s3_memzero(&st, sizeof(s3_h3_parse_uni_t));
    buf[0] = 0x02;
    buf[1] = 0x80; /* INR, dynamic name reference */
    buf[2] = 0x00; /* empty literal value completes the instruction */
    b = s3_test_buf(buf, 3);
    rc = s3_h3_parse_uni(c, &st, &b);
    /* a dynamic ref insert on an empty table fails the encoder stream */
    S3_ASSERT(rc == S3_H3_ERR_ENCODER_STREAM_ERROR);
    S3_ASSERT(st.u.encoder.field.name.len == 0);
}

/*
 * the Huffman decoder itself: RFC 7541 appendix B vectors, verified
 * against the nginx encode table; s3_h3_huff_decode() is public for
 * these tests (the nginx original is public as well)
 */
static void
s3_test_huffman(void)
{
    u_char   out[64];
    u_char  *p;
    u_char   state;
    s3_int_t rc;

    static u_char www[] = {0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff};
    static u_char ck[] = {0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f};
    static u_char cv[] = {0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf};
    static u_char nc[] = {0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf};
    static u_char ih[] = {0x60, 0xd5, 0x48, 0x5f, 0x2b, 0xce, 0x9a, 0x68};
    static u_char bad[] = {0x00};
    static u_char eos[] = {0xff, 0xff, 0xff, 0xff};

    /* "www.example.com", RFC 7541 C.4.1 */
    state = 0;
    p = out;
    rc = s3_h3_huff_decode(&state, www, sizeof(www), &p, 1, &s3_test_log);
    S3_ASSERT(rc == S3_OK);
    S3_ASSERT(state == 0);
    S3_ASSERT(p - out == 15);
    S3_ASSERT(s3_memcmp(out, "www.example.com", 15) == 0);

    /* "custom-key" and "custom-value", RFC 7541 C.6.3 */
    state = 0;
    p = out;
    rc = s3_h3_huff_decode(&state, ck, sizeof(ck), &p, 1, &s3_test_log);
    S3_ASSERT(rc == S3_OK);
    S3_ASSERT(p - out == 10);
    S3_ASSERT(s3_memcmp(out, "custom-key", 10) == 0);

    state = 0;
    p = out;
    rc = s3_h3_huff_decode(&state, cv, sizeof(cv), &p, 1, &s3_test_log);
    S3_ASSERT(rc == S3_OK);
    S3_ASSERT(p - out == 12);
    S3_ASSERT(s3_memcmp(out, "custom-value", 12) == 0);

    /* "no-cache", RFC 7541 C.4.2, and "/index.html" */
    state = 0;
    p = out;
    rc = s3_h3_huff_decode(&state, nc, sizeof(nc), &p, 1, &s3_test_log);
    S3_ASSERT(rc == S3_OK);
    S3_ASSERT(p - out == 8);
    S3_ASSERT(s3_memcmp(out, "no-cache", 8) == 0);

    state = 0;
    p = out;
    rc = s3_h3_huff_decode(&state, ih, sizeof(ih), &p, 1, &s3_test_log);
    S3_ASSERT(rc == S3_OK);
    S3_ASSERT(p - out == 11);
    S3_ASSERT(s3_memcmp(out, "/index.html", 11) == 0);

    /* an incomplete code at the end of the field is rejected */
    state = 0;
    p = out;
    rc = s3_h3_huff_decode(&state, bad, sizeof(bad), &p, 1, &s3_test_log);
    S3_ASSERT(rc == S3_ERROR);

    /* 32 EOS one-bits overflow the 30-bit EOS code */
    state = 0;
    p = out;
    rc = s3_h3_huff_decode(&state, eos, sizeof(eos), &p, 0, &s3_test_log);
    S3_ASSERT(rc == S3_ERROR);

    /* the state carries across chunk boundaries */
    state = 0;
    p = out;
    rc = s3_h3_huff_decode(&state, www, 5, &p, 0, &s3_test_log);
    S3_ASSERT(rc == S3_OK);
    rc = s3_h3_huff_decode(&state, www + 5, sizeof(www) - 5, &p, 1, &s3_test_log);
    S3_ASSERT(rc == S3_OK);
    S3_ASSERT(p - out == 15);
    S3_ASSERT(s3_memcmp(out, "www.example.com", 15) == 0);
}

static void
s3_test_encoder_decoder(s3_connection_t *c)
{
    u_char            buf[8];
    s3_buf_t          b;
    s3_int_t          rc;
    s3_h3_parse_uni_t st;

    /* Set Dynamic Table Capacity, 5-bit single byte: 30 */
    s3_memzero(&st, sizeof(s3_h3_parse_uni_t));
    buf[0] = 0x02;
    buf[1] = 0x3e;
    b = s3_test_buf(buf, 2);
    rc = s3_h3_parse_uni(c, &st, &b);
    /* the instruction is accepted, the machine waits for the next one */
    S3_ASSERT(rc == S3_AGAIN);

    /* 5-bit continuation: 31 + 1 + 256 = 288 */
    s3_memzero(&st, sizeof(s3_h3_parse_uni_t));
    buf[0] = 0x02;
    buf[1] = 0x3f;
    buf[2] = 0x81;
    buf[3] = 0x02;
    b = s3_test_buf(buf, 4);
    rc = s3_h3_parse_uni(c, &st, &b);
    /* the instruction is accepted, the machine waits for the next one */
    S3_ASSERT(rc == S3_AGAIN);

    /* Section Acknowledgment, 7-bit continuation: 128 */
    s3_memzero(&st, sizeof(s3_h3_parse_uni_t));
    buf[0] = 0x03;
    buf[1] = 0xff;
    buf[2] = 0x80;
    buf[3] = 0x01;
    b = s3_test_buf(buf, 4);
    rc = s3_h3_parse_uni(c, &st, &b);
    /* the server decoder does not track dynamic sections */
    S3_ASSERT(rc == S3_H3_ERR_DECODER_STREAM_ERROR);

    /* Insert Count Increment, 6-bit: 5 */
    s3_memzero(&st, sizeof(s3_h3_parse_uni_t));
    buf[0] = 0x03;
    buf[1] = 0x05;
    b = s3_test_buf(buf, 2);
    rc = s3_h3_parse_uni(c, &st, &b);
    /* the server decoder does not track dynamic sections */
    S3_ASSERT(rc == S3_H3_ERR_DECODER_STREAM_ERROR);

    /*
     * Stream Cancellation is parsed and ignored on wave 1: the request
     * layer (nginx ngx_http_v3_cancel_stream) is not ported yet
     */
    s3_memzero(&st, sizeof(s3_h3_parse_uni_t));
    buf[0] = 0x03;
    buf[1] = 0x40;
    b = s3_test_buf(buf, 2);
    rc = s3_h3_parse_uni(c, &st, &b);
    S3_ASSERT(rc == S3_AGAIN); /* one instruction done, waiting for the next */
    S3_ASSERT(st.u.decoder.pint.value == 0);
}

static void
s3_test_control(s3_connection_t *c)
{
    u_char            buf[16];
    s3_buf_t          b;
    s3_int_t          rc;
    s3_h3_parse_uni_t st;

    /* an empty SETTINGS frame is legal, the machine waits for the next */
    s3_memzero(&st, sizeof(s3_h3_parse_uni_t));
    buf[0] = 0x00; /* uni: control stream */
    buf[1] = 0x04; /* SETTINGS */
    buf[2] = 0x00;
    b = s3_test_buf(buf, 3);
    rc = s3_h3_parse_uni(c, &st, &b);
    S3_ASSERT(rc == S3_AGAIN);

    /*
     * SETTINGS with one parameter: the capacity parameter is accepted
     * and the machine waits for the next frame
     */
    s3_memzero(&st, sizeof(s3_h3_parse_uni_t));
    buf[0] = 0x00;
    buf[1] = 0x04;
    buf[2] = 0x03;
    buf[3] = 0x01; /* QPACK_MAX_TABLE_CAPACITY */
    buf[4] = 0x7f; /* value 16383 */
    buf[5] = 0xff;
    b = s3_test_buf(buf, 6);
    rc = s3_h3_parse_uni(c, &st, &b);
    S3_ASSERT(rc == S3_AGAIN);

    /* the first control frame must be SETTINGS */
    s3_memzero(&st, sizeof(s3_h3_parse_uni_t));
    buf[0] = 0x00;
    buf[1] = 0x01; /* HEADERS */
    buf[2] = 0x00;
    b = s3_test_buf(buf, 3);
    rc = s3_h3_parse_uni(c, &st, &b);
    S3_ASSERT(rc == S3_H3_ERR_MISSING_SETTINGS);

    /* SETTINGS twice */
    s3_memzero(&st, sizeof(s3_h3_parse_uni_t));
    buf[0] = 0x00;
    buf[1] = 0x04;
    buf[2] = 0x00;
    buf[3] = 0x04;
    buf[4] = 0x00;
    b = s3_test_buf(buf, 5);
    rc = s3_h3_parse_uni(c, &st, &b);
    S3_ASSERT(rc == S3_H3_ERR_FRAME_UNEXPECTED);

    /* reserved v2 frame type on a control stream */
    s3_memzero(&st, sizeof(s3_h3_parse_uni_t));
    buf[0] = 0x00;
    buf[1] = 0x04;
    buf[2] = 0x00;
    buf[3] = 0x06;
    buf[4] = 0x00;
    b = s3_test_buf(buf, 5);
    rc = s3_h3_parse_uni(c, &st, &b);
    S3_ASSERT(rc == S3_H3_ERR_FRAME_UNEXPECTED);

    /* DATA frame on a control stream */
    s3_memzero(&st, sizeof(s3_h3_parse_uni_t));
    buf[0] = 0x00;
    buf[1] = 0x04;
    buf[2] = 0x00;
    buf[3] = 0x00;
    buf[4] = 0x00;
    b = s3_test_buf(buf, 5);
    rc = s3_h3_parse_uni(c, &st, &b);
    S3_ASSERT(rc == S3_H3_ERR_FRAME_UNEXPECTED);

    /* CANCEL_PUSH is an id error */
    s3_memzero(&st, sizeof(s3_h3_parse_uni_t));
    buf[0] = 0x00;
    buf[1] = 0x04;
    buf[2] = 0x00;
    buf[3] = 0x03;
    buf[4] = 0x00;
    b = s3_test_buf(buf, 5);
    rc = s3_h3_parse_uni(c, &st, &b);
    S3_ASSERT(rc == S3_H3_ERR_ID_ERROR);

    /* truncated frame type varlen int */
    s3_memzero(&st, sizeof(s3_h3_parse_uni_t));
    buf[0] = 0x00;
    buf[1] = 0xc0;
    b = s3_test_buf(buf, 2);
    rc = s3_h3_parse_uni(c, &st, &b);
    S3_ASSERT(rc == S3_AGAIN);

    /*
     * an unknown frame is skipped and the next frame type stays
     * aligned: CANCEL_PUSH after the skip gives the id error
     */
    s3_memzero(&st, sizeof(s3_h3_parse_uni_t));
    buf[0] = 0x00;
    buf[1] = 0x04;
    buf[2] = 0x00;
    buf[3] = 0x21; /* unknown type */
    buf[4] = 0x02;
    buf[5] = 0xde;
    buf[6] = 0xad;
    buf[7] = 0x03; /* CANCEL_PUSH */
    buf[8] = 0x00;
    b = s3_test_buf(buf, 9);
    rc = s3_h3_parse_uni(c, &st, &b);
    S3_ASSERT(rc == S3_H3_ERR_ID_ERROR);
}

static void
s3_test_data(s3_connection_t *c)
{
    u_char             buf[16];
    s3_buf_t           b;
    s3_int_t           rc;
    s3_h3_parse_data_t st;

    /* a DATA frame header: the payload is left to the caller */
    s3_memzero(&st, sizeof(s3_h3_parse_data_t));
    buf[0] = 0x00;
    buf[1] = 0x04;
    b = s3_test_buf(buf, 2);
    rc = s3_h3_parse_data(c, &st, &b);
    S3_ASSERT(rc == S3_OK);
    S3_ASSERT(st.type == 0);
    S3_ASSERT(st.length == 4);
    S3_ASSERT(b.pos == buf + 2);

    /* payload consumption by the caller, then trailers (HEADERS) */
    s3_memzero(&st, sizeof(s3_h3_parse_data_t));
    buf[0] = 0x00;
    buf[1] = 0x04;
    buf[2] = 'A';
    buf[3] = 'B';
    buf[4] = 'C';
    buf[5] = 'D';
    buf[6] = 0x01; /* HEADERS: trailers */
    buf[7] = 0x00;
    b = s3_test_buf(buf, 8);
    rc = s3_h3_parse_data(c, &st, &b);
    S3_ASSERT(rc == S3_OK);
    b.pos += 4; /* the caller skips the DATA payload */
    rc = s3_h3_parse_data(c, &st, &b);
    S3_ASSERT(rc == S3_DONE);

    /* reserved v2 frame type */
    s3_memzero(&st, sizeof(s3_h3_parse_data_t));
    buf[0] = 0x02;
    buf[1] = 0x00;
    b = s3_test_buf(buf, 2);
    rc = s3_h3_parse_data(c, &st, &b);
    S3_ASSERT(rc == S3_H3_ERR_FRAME_UNEXPECTED);

    /* SETTINGS on a request stream */
    s3_memzero(&st, sizeof(s3_h3_parse_data_t));
    buf[0] = 0x04;
    buf[1] = 0x00;
    b = s3_test_buf(buf, 2);
    rc = s3_h3_parse_data(c, &st, &b);
    S3_ASSERT(rc == S3_H3_ERR_FRAME_UNEXPECTED);

    /* an unknown frame is skipped, then a DATA frame is parsed */
    s3_memzero(&st, sizeof(s3_h3_parse_data_t));
    buf[0] = 0x21;
    buf[1] = 0x02;
    buf[2] = 0xde;
    buf[3] = 0xad;
    buf[4] = 0x00;
    buf[5] = 0x01;
    b = s3_test_buf(buf, 6);
    rc = s3_h3_parse_data(c, &st, &b);
    S3_ASSERT(rc == S3_OK);
    S3_ASSERT(st.length == 1);

    /* truncated length varlen int */
    s3_memzero(&st, sizeof(s3_h3_parse_data_t));
    buf[0] = 0x00;
    b = s3_test_buf(buf, 1);
    rc = s3_h3_parse_data(c, &st, &b);
    S3_ASSERT(rc == S3_AGAIN);
}

static void
s3_test_uni(s3_connection_t *c)
{
    u_char            buf[8];
    s3_buf_t          b;
    s3_int_t          rc;
    s3_h3_parse_uni_t st;

    /* truncated stream type varlen int */
    s3_memzero(&st, sizeof(s3_h3_parse_uni_t));
    buf[0] = 0xc0;
    b = s3_test_buf(buf, 1);
    rc = s3_h3_parse_uni(c, &st, &b);
    S3_ASSERT(rc == S3_AGAIN);

    /* an unknown uni stream type is tolerated and swallowed */
    s3_memzero(&st, sizeof(s3_h3_parse_uni_t));
    buf[0] = 0x63;
    buf[1] = 0x11;
    buf[2] = 0x22;
    b = s3_test_buf(buf, 3);
    rc = s3_h3_parse_uni(c, &st, &b);
    S3_ASSERT(rc == S3_AGAIN);
    S3_ASSERT(b.pos == b.last);

    /* the control stream type dispatches to the control machine */
    s3_memzero(&st, sizeof(s3_h3_parse_uni_t));
    buf[0] = 0x00; /* control */
    buf[1] = 0x04; /* SETTINGS */
    buf[2] = 0x00;
    b = s3_test_buf(buf, 3);
    rc = s3_h3_parse_uni(c, &st, &b);
    S3_ASSERT(rc == S3_AGAIN);
    S3_ASSERT(st.u.control.type == S3_H3_FRAME_SETTINGS);
}

/*
 * the lifetime of the field values (PLAN.md 9, B1): the parse hands
 * out the name and the value of a field line, and the pre-auth
 * verdict reads them after the parse - the receive buffer is recycled
 * by the next read, so a view into it would dangle.
 *
 * the literals are allocated off the connection pool (s3_h3_parse.c
 * copies them), and this pins that: the buffer is scribbled over and
 * the value must stay intact
 */
static void
s3_test_field_lifetime(s3_connection_t *c)
{
    u_char                buf[512];
    u_char               *p;
    u_char               *sec;
    size_t                sec_len;
    s3_buf_t              b;
    s3_int_t              rc;
    s3_h3_parse_headers_t st;
    s3_str_t              name = s3_string("authorization");
    s3_str_t              value = s3_string("Bearer the-token-of-the-pre-auth-request");

    /* the section: the zero prefix and one literal field line */

    sec = buf + 2; /* the frame header takes the first two bytes */
    p = (u_char *)s3_h3_encode_field_section_prefix(sec, 0, 0, 0);
    p = (u_char *)s3_h3_encode_field_l(p, &name, &value);
    sec_len = (size_t)(p - sec);

    buf[0] = 0x01; /* the HEADERS frame */
    buf[1] = (u_char)sec_len; /* the frame length (the one-byte varint) */

    s3_memzero(&st, sizeof(st));
    b = s3_test_buf(buf, 2 + sec_len);
    rc = s3_h3_parse_headers(c, &st, &b);

    /* the last field line of a section lands together with the section
     * end (the DONE), the earlier ones answer S3_OK */

    S3_ASSERT(rc == S3_DONE || rc == S3_OK);

    /* the parsed field line */

    S3_ASSERT(st.field_rep.field.name.len == name.len);
    S3_ASSERT(s3_memcmp(st.field_rep.field.name.data, name.data, name.len) == 0);
    S3_ASSERT(st.field_rep.field.value.len == value.len);
    S3_ASSERT(s3_memcmp(st.field_rep.field.value.data, value.data, value.len) == 0);

    /* the value does not point into the receive buffer */

    S3_ASSERT(st.field_rep.field.value.data < buf ||
              st.field_rep.field.value.data >= buf + 2 + sec_len);

    /* the proof by the scribble: the buffer is overwritten and the
     * value must stay intact */

    s3_memzero(buf, 2 + sec_len);

    S3_ASSERT(st.field_rep.field.value.len == value.len);
    S3_ASSERT(s3_memcmp(st.field_rep.field.value.data, value.data, value.len) == 0);
}

static int
s3_test_h3_parse(void)
{
    s3_pool_t       *pool;
    s3_connection_t *c;

    pool = s3_create_pool(S3_DEFAULT_POOL_SIZE, &s3_test_log);
    if (pool == NULL) {
        printf("FAIL %s:%d: s3_create_pool\n", __FILE__, __LINE__);
        return ++s3_test_failures;
    }

    c = s3_test_conn(pool);

    s3_test_varlen(c);
    s3_test_prefix_int(c);
    s3_test_headers_frames(c);
    s3_test_literal(c);
    s3_test_field_lifetime(c);
    s3_test_huffman();
    s3_test_encoder_decoder(c);
    s3_test_control(c);
    s3_test_data(c);
    s3_test_uni(c);

    s3_destroy_pool(pool);

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_h3_parse)
