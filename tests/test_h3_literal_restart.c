/*
 * Copyright (C) 2026 the ssh3-c authors
 */
/*
 * FZ1 regression pin (security pass 4, §3.3): a literal never writes more
 * than the reservation it just took, whatever state it is entered in.
 *
 * s3_h3_parse_literal() counts the value bytes down with a pre-decrement
 * on an unsigned counter:
 *
 *     if (--st->length) { break; }
 *
 * s3_h3_parse_field_lpbi() finishes the value literal - which resets the
 * literal machine to sw_start and leaves the counter at zero - and then
 * fails the post-base table lookup WITHOUT restoring its own state.  A
 * caller that feeds the parser again therefore re-enters the literal with
 * a zero counter: the pre-decrement underflows to the type maximum and
 * every remaining byte of the window is written past a one-byte
 * s3_pnalloc.
 *
 * the pool cursor is parked so that one-byte allocation sits on the last
 * byte of the first 16 KiB block, which is exactly the shape the nightly
 * fuzz artifact of 2026-10-30 reported: "heap-buffer-overflow WRITE of
 * size 1 ... 0 bytes after 16384-byte region".
 *
 * the pin is preset-independent on purpose: the replayed parse answers
 * S3_H3_ERR_DECOMPRESSION_FAILED once the literal is bounded, and
 * S3_H3_ERR_FRAME_ERROR at the unpatched tree (the runaway literal eats
 * the whole window and comes back S3_AGAIN), so the release build fails
 * the assertion as well as the ASan build aborting.
 */
#include <s3_core.h>
#include <s3_h3.h>
#include <string.h>

#include "s3_test.h"

static s3_log_t s3_test_log = {0, S3_INVALID_FILE};

/* the frame bytes left after the field line: they keep the replay's
 * window non-empty, so the runaway literal has something to overrun
 * with.  16 is arbitrary and well inside the one-byte frame length. */
#define S3_TEST_LITERAL_PAD 16

/*
 * park the pool cursor: after this the next one-byte s3_pnalloc returns
 * the last byte of the first block, so a one-byte overrun is a
 * heap-buffer-overflow at the block boundary rather than a silent write
 * into the slack of the block
 */
static void
s3_test_park(s3_pool_t *pool)
{
    size_t    rem;
    s3_uint_t i;

    for (i = 0; i < 16; i++) {
        rem = (size_t)(pool->d.end - pool->d.last);

        if (rem > pool->max + 4) {
            if (s3_pnalloc(pool, pool->max) == NULL) {
                return;
            }

            continue;
        }

        if (rem > 1 && s3_pnalloc(pool, rem - 1) == NULL) {
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
    /* the zeroed session is the empty QPACK table: the post-base lookup
     * of the field line below cannot succeed */
    c.data = &h3c;

    return &c;
}

static int
s3_test_literal_restart(void)
{
    u_char                buf[64];
    u_char               *p;
    u_char               *sec;
    size_t                sec_len;
    s3_buf_t              b;
    s3_int_t              rc;
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
     * one HEADERS frame carrying one literal field line with a post-base
     * name reference (0x00), a 7-bit value length of 4 (0x04) and "aaaa",
     * followed by S3_TEST_LITERAL_PAD bytes the parse never reaches
     */
    sec = buf + 2; /* the frame header takes the first two bytes */
    p = (u_char *) s3_h3_encode_field_section_prefix(sec, 0, 0, 0);
    *p++ = 0x00;
    *p++ = 0x04;
    *p++ = 'a';
    *p++ = 'a';
    *p++ = 'a';
    *p++ = 'a';
    s3_memzero(p, S3_TEST_LITERAL_PAD);
    p += S3_TEST_LITERAL_PAD;
    sec_len = (size_t)(p - sec);

    buf[0] = 0x01;            /* the HEADERS frame */
    buf[1] = (u_char)sec_len; /* the frame length (the one-byte varint) */

    s3_test_park(pool);
    S3_ASSERT((size_t)(pool->d.end - pool->d.last) == 1);

    s3_memzero(&st, sizeof(st));
    b = s3_test_buf(buf, 2 + sec_len);

    rc = s3_h3_parse_headers(c, &st, &b);
    /* the value literal completes, the post-base lookup then fails and
     * the field machine is left in sw_value with a zero countdown */
    S3_ASSERT(rc == S3_H3_ERR_DECOMPRESSION_FAILED);

    /* the replay: the same state, the same bytes */
    b = s3_test_buf(buf, 2 + sec_len);

    rc = s3_h3_parse_headers(c, &st, &b);

    /*
     * the zero-length literal must complete at sw_start: the reservation
     * is one byte and the parse reports the same lookup failure.  without
     * the guard the countdown underflows, the literal consumes the whole
     * window and answers S3_AGAIN - a frame error - after writing past
     * the block
     */
    S3_ASSERT(rc == S3_H3_ERR_DECOMPRESSION_FAILED);
    S3_ASSERT(st.field_rep.field.value.len == 0);
    S3_ASSERT(pool->d.last <= pool->d.end);

    s3_destroy_pool(pool);

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_literal_restart)
