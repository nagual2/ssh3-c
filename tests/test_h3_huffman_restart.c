/*
 * Copyright (C) 2026 the ssh3-c authors
 */
/*
 * FZ2 regression pin (security pass 4, §3.4/§3.5): the literal's countdown
 * is spent when the byte is consumed, not after the decode.
 *
 * s3_h3_parse_literal()'s sw_value spends the countdown only after the
 * huffman decode has succeeded:
 *
 *     ch = *b->pos++;
 *     if (st->huffman) {
 *         if (s3_h3_huff_decode(...) != S3_OK) { return S3_ERROR; }
 *     }
 *     if (--st->length) { break; }
 *
 * A decode that fails has still consumed the input byte and may already
 * have written to the output - s3_h3_huff_decode() decodes the high nibble
 * (which can emit) before it rejects the low one, and it emits for every
 * complete code it finds before the trailing bits turn out to be an
 * incomplete code.  The countdown therefore stays where it was while the
 * write pointer has moved on, and the caller keeps its own state after the
 * hard error (s3_h3_parse_field_l() stays in sw_name, so the literal stays
 * in sw_value): feeding the parser again - what the fuzz driver does with
 * its replay rounds, and what a caller does with any remaining window -
 * decodes more bytes against a countdown that never moves.  The
 * n * 8 / 5 + 1 reservation of sw_start bounds one pass only, so the
 * re-entered literal writes past it: the FZ2 heap-buffer-overflow WRITE of
 * size 1 at src/h3/s3_h3_parse.c:4299 (s3_h3_huff_decode_bits) through
 * parse_literal:4875 and parse_field_l:5098 that the 1 000 000-input
 * campaign reported after FZ1 was fixed.
 *
 * The pin is the shape of the FZ1 pin (tests/test_h3_literal_restart.c):
 * park the pool cursor so the literal's two-byte reservation is the last
 * two bytes of the first 16 KiB block, drive one HEADERS frame whose only
 * field line is a huffman literal name of length 1 holding 0x00 - its
 * five-bit code '00000' emits '0' and the three bits left over start the
 * code of the next symbol, so the final-byte check fails with a byte
 * already emitted - then replay the failing byte into the same state.
 *
 * At the unpatched tree the ASan build aborts on the first replay with
 * "0 bytes after 16384-byte region" at s3_h3_huff_decode_bits, and the
 * release build fails the assertion that the countdown was spent.  With
 * the countdown spent by the consumed byte the replay has nothing left to
 * charge, the literal completes inside its reservation and the pool
 * cursor never leaves the block.
 */
#include <s3_core.h>
#include <s3_h3.h>
#include <string.h>

#include "s3_test.h"

static s3_log_t s3_test_log = {0, S3_INVALID_FILE};

/* the frame bytes after the failing literal: they keep the parse's frame
 * window non-empty, so every replay still has a byte to consume.  56 is
 * arbitrary and well inside the one-byte frame length. */
#define S3_TEST_HUFF_PAD 56

/* more replays than the two-byte reservation can absorb */
#define S3_TEST_HUFF_REPLAYS 24

/*
 * park the pool cursor so that exactly `want` bytes are left in the
 * current block: the next allocation of `want` bytes then ends on the
 * block boundary, and a write past the reservation is a
 * heap-buffer-overflow at the block boundary rather than a silent write
 * into the slack of the block
 */
static void
s3_test_park(s3_pool_t *pool, size_t want)
{
    size_t rem;

    for (;;) {
        rem = (size_t)(pool->d.end - pool->d.last);

        if (rem > pool->max + 4) {
            if (s3_pnalloc(pool, pool->max) == NULL) {
                return;
            }

            continue;
        }

        if (rem > want && s3_pnalloc(pool, rem - want) == NULL) {
            return;
        }

        return;
    }
}

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
    /* the zeroed session is the empty QPACK table: no field line of this
     * pin reaches a lookup, but the session has to be there */
    c.data = &h3c;

    return &c;
}

static int
s3_test_huffman_restart(void)
{
    u_char                buf[2 + 2 + 2 + S3_TEST_HUFF_PAD];
    u_char               *p;
    u_char               *sec;
    size_t                sec_len;
    s3_buf_t              b;
    s3_int_t              rc;
    s3_uint_t             i;
    s3_uint_t             spent;
    s3_pool_t            *pool;
    s3_connection_t      *c;
    s3_h3_parse_headers_t st;

    pool = s3_create_pool(S3_DEFAULT_POOL_SIZE, &s3_test_log);
    if (pool == NULL) {
        printf("FAIL %s:%d: s3_create_pool\n", __FILE__, __LINE__);
        return ++s3_test_failures;
    }

    c = s3_test_conn(pool);

    /*
     * one HEADERS frame carrying one field line: the literal-name pattern
     * with the huffman flag and a three-bit name length of one (0x29),
     * then the single huffman byte 0x00, then bytes the first pass never
     * reaches
     */
    sec = buf + 2; /* the frame header takes the first two bytes */
    p = (u_char *) s3_h3_encode_field_section_prefix(sec, 0, 0, 0);
    *p++ = 0x29;
    *p++ = 0x00;
    s3_memzero(p, S3_TEST_HUFF_PAD);
    p += S3_TEST_HUFF_PAD;
    sec_len = (size_t)(p - sec);

    buf[0] = 0x01;            /* the HEADERS frame */
    buf[1] = (u_char)sec_len; /* the frame length (the one-byte varint) */

    /* the reservation of a one-byte literal is n + 1 = 2 bytes */
    s3_test_park(pool, 2);
    S3_ASSERT((size_t)(pool->d.end - pool->d.last) == 2);

    s3_memzero(&st, sizeof(st));
    b = s3_test_buf(buf, 2 + sec_len);

    rc = s3_h3_parse_headers(c, &st, &b);
    /* the byte is consumed, the decode emits one byte and then fails on
     * the trailing three bits of the incomplete code */
    S3_ASSERT(rc == S3_ERROR);

    /* the countdown after the first pass: spent by the consumed byte
     * (patched) or still at one (unpatched) */
    spent = st.field_rep.field.literal.length;

    /*
     * the replay: the same state, one byte at a time.  the caller kept
     * its state after the hard error, so every call re-enters the literal
     * in sw_value
     */
    for (i = 0; i < S3_TEST_HUFF_REPLAYS; i++) {
        b = s3_test_buf(sec + 3, 1);

        (void) s3_h3_parse_headers(c, &st, &b);
    }

    /*
     * the byte that was consumed was charged for: the literal cannot
     * write more than its reservation whatever state it is re-entered in
     */
    S3_ASSERT(spent == 0);
    S3_ASSERT(pool->d.last <= pool->d.end);

    s3_destroy_pool(pool);

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_huffman_restart)
