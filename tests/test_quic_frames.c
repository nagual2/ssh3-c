/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <s3_quic.h>
#include <s3_quic_frames.h>

#include "s3_test.h"

static s3_log_t             s3_test_log;
static s3_pool_t           *s3_test_pool;
static s3_connection_t      s3_test_conn;
static s3_quic_connection_t s3_test_qc;

static void
setup(void)
{
    s3_uint_t i;

    s3_memzero(&s3_test_conn, sizeof(s3_connection_t));
    s3_memzero(&s3_test_qc, sizeof(s3_quic_connection_t));

    s3_test_conn.log = &s3_test_log;
    s3_test_conn.pool = s3_test_pool;
    s3_test_conn.data = &s3_test_qc;

    s3_queue_init(&s3_test_qc.free_frames);
    s3_test_qc.free_bufs = NULL;
    s3_test_qc.free_shadow_bufs = NULL;
    s3_test_qc.nframes = 0;
    s3_test_qc.max_frames = 128;

    for (i = 0; i < S3_QUIC_SEND_CTX_LAST; i++) {
        s3_queue_init(&s3_test_qc.send_ctx[i].frames);
        s3_queue_init(&s3_test_qc.send_ctx[i].sending);
        s3_queue_init(&s3_test_qc.send_ctx[i].sent);
    }

    s3_queue_init(&s3_test_qc.client_ids);
    s3_queue_init(&s3_test_qc.free_client_ids);
}

static s3_chain_t *
input_chain(const u_char *data, size_t len)
{
    s3_buf_t   *b;
    s3_chain_t *cl;

    b = s3_create_temp_buf(s3_test_pool, len);
    if (b == NULL) {
        return NULL;
    }

    s3_memcpy(b->start, data, len);
    b->last = b->start + len;

    cl = s3_alloc_chain_link(s3_test_pool);
    if (cl == NULL) {
        return NULL;
    }

    cl->buf = b;
    cl->next = NULL;

    return cl;
}

static int
test_read_write(void)
{
    s3_quic_buffer_t qb;
    s3_chain_t      *in, *out;
    u_char           data[] = "hello world";
    size_t           len = 11;

    s3_memzero(&qb, sizeof(s3_quic_buffer_t));

    in = input_chain(data, len);
    S3_ASSERT(in != NULL);

    /* full write; the write leaves a trailing hole after the data */

    out = s3_quic_write_buffer(&s3_test_conn, &qb, in, len, 0);
    S3_ASSERT(out == NULL); /* fully consumed */
    S3_ASSERT(qb.size == len);
    S3_ASSERT(qb.chain != NULL);
    S3_ASSERT(qb.chain->buf->sync == 0);
    S3_ASSERT(qb.chain->next != NULL && qb.chain->next->buf->sync == 1);

    /* full read returns the data, the trailing hole stays queued */

    out = s3_quic_read_buffer(&s3_test_conn, &qb, len);
    S3_ASSERT(out != NULL);
    S3_ASSERT(out->next == NULL);
    S3_ASSERT(qb.offset == len);
    S3_ASSERT(s3_buf_size(out->buf) == (off_t)len);
    S3_ASSERT(s3_memcmp(out->buf->pos, data, len) == 0);

    s3_quic_free_chain(&s3_test_conn, out);
    s3_quic_free_buffer(&s3_test_conn, &qb);

    /* the recycled buffer is back on the freelist */

    S3_ASSERT(s3_test_qc.free_bufs != NULL);
    S3_ASSERT(s3_test_qc.free_bufs->shadow == NULL);

    return s3_test_failures;
}

static int
test_shadow_refcount(void)
{
    s3_quic_buffer_t qb;
    s3_chain_t      *in, *head, *rest;
    s3_buf_t        *clone_buf, *head_buf;
    u_char           data[] = "0123456789a";
    size_t           len = 11;

    s3_memzero(&qb, sizeof(s3_quic_buffer_t));

    in = input_chain(data, len);
    S3_ASSERT(in != NULL);

    S3_ASSERT(s3_quic_write_buffer(&s3_test_conn, &qb, in, len, 0) == NULL);
    S3_ASSERT(qb.size == len);

    /*
     * a partial read cuts the chain in the middle: the tail is a
     * shadow clone of the head buf; the clone count of the head buf
     * holds one reference for itself plus one per clone (the trailing
     * write hole and the read tail)
     */
    head = s3_quic_read_buffer(&s3_test_conn, &qb, 5);
    S3_ASSERT(head != NULL);
    S3_ASSERT(head->next == NULL);
    S3_ASSERT(s3_buf_size(head->buf) == 5);
    S3_ASSERT(s3_memcmp(head->buf->pos, data, 5) == 0);
    S3_ASSERT(head->buf->shadow == head->buf);
    S3_ASSERT(head->buf->shadow->num == 3);

    head_buf = head->buf;

    /* the remainder is the read clone, still referencing the data */

    rest = s3_quic_read_buffer(&s3_test_conn, &qb, 6);
    S3_ASSERT(rest != NULL);
    S3_ASSERT(rest->buf != head_buf);
    S3_ASSERT(rest->buf->shadow == head_buf);
    S3_ASSERT(s3_buf_size(rest->buf) == 6);
    S3_ASSERT(s3_memcmp(rest->buf->pos, data + 5, 6) == 0);

    clone_buf = rest->buf;

    /* the trailing write hole goes first, then the clones */

    s3_quic_free_buffer(&s3_test_conn, &qb);
    S3_ASSERT(head_buf->shadow->num == 2);

    s3_quic_free_chain(&s3_test_conn, rest);

    S3_ASSERT(s3_test_qc.free_shadow_bufs == clone_buf);
    S3_ASSERT(head_buf->shadow->num == 1);
    S3_ASSERT(s3_buf_size(head_buf) == 5); /* still readable */

    /* the last free recycles the shared memory */

    s3_quic_free_chain(&s3_test_conn, head);

    S3_ASSERT(s3_test_qc.free_bufs == head_buf);
    S3_ASSERT(s3_test_qc.free_bufs->shadow == NULL);
    S3_ASSERT(s3_test_qc.free_shadow_bufs == clone_buf);

    return s3_test_failures;
}

static int
test_hole_and_skip(void)
{
    s3_quic_buffer_t qb;
    s3_chain_t      *in, *out;
    u_char           a[] = "AAAA";
    u_char           b[] = "BBBB";

    s3_memzero(&qb, sizeof(s3_quic_buffer_t));

    in = input_chain(a, 4);
    S3_ASSERT(in != NULL);
    S3_ASSERT(s3_quic_write_buffer(&s3_test_conn, &qb, in, 4, 0) == NULL);

    in = input_chain(b, 4);
    S3_ASSERT(in != NULL);
    S3_ASSERT(s3_quic_write_buffer(&s3_test_conn, &qb, in, 4, 100) == NULL);

    /* the gap became a hole, size counts only the real data */
    S3_ASSERT(qb.size == 8);
    S3_ASSERT(qb.chain->buf->sync == 0);

    /* a read stops at the hole */
    out = s3_quic_read_buffer(&s3_test_conn, &qb, 8);
    S3_ASSERT(out != NULL);
    S3_ASSERT(s3_memcmp(out->buf->pos, a, 4) == 0);
    S3_ASSERT(out->next == NULL);
    s3_quic_free_chain(&s3_test_conn, out);

    /* skipping to the hole end keeps the far data intact */
    s3_quic_skip_buffer(&s3_test_conn, &qb, 100);
    S3_ASSERT(qb.offset == 100);

    out = s3_quic_read_buffer(&s3_test_conn, &qb, 8);
    S3_ASSERT(out != NULL);
    S3_ASSERT(s3_buf_size(out->buf) == 4);
    S3_ASSERT(s3_memcmp(out->buf->pos, b, 4) == 0);
    s3_quic_free_chain(&s3_test_conn, out);

    s3_quic_free_buffer(&s3_test_conn, &qb);

    /* skipping everything: the offset moves past the data */

    s3_memzero(&qb, sizeof(s3_quic_buffer_t));
    in = input_chain(a, 4);
    S3_ASSERT(in != NULL);
    S3_ASSERT(s3_quic_write_buffer(&s3_test_conn, &qb, in, 4, 0) == NULL);

    s3_quic_skip_buffer(&s3_test_conn, &qb, 200);
    S3_ASSERT(qb.offset == 200);
    s3_quic_free_buffer(&s3_test_conn, &qb);

    return s3_test_failures;
}

static int
test_copy_buffer(void)
{
    s3_chain_t *out;
    u_char      data[40];
    size_t      i;

    for (i = 0; i < sizeof(data); i++) {
        data[i] = (u_char)i;
    }

    out = s3_quic_copy_buffer(&s3_test_conn, data, sizeof(data));
    S3_ASSERT(out != NULL && out != S3_CHAIN_ERROR);
    S3_ASSERT(s3_memcmp(out->buf->pos, data, sizeof(data)) == 0);

    s3_quic_free_chain(&s3_test_conn, out);

    return s3_test_failures;
}

static int
test_split_frame(void)
{
    s3_queue_t       head;
    s3_quic_frame_t *f, *nf;
    s3_chain_t      *cl;

    s3_queue_init(&head);

    f = s3_quic_alloc_frame(&s3_test_conn);
    S3_ASSERT(f != NULL);

    f->level = S3_QUIC_ENCRYPTION_HANDSHAKE;
    f->type = S3_QUIC_FT_CRYPTO;
    f->u.ord.offset = 16; /* one-byte varint keeps the arithmetic simple */
    f->u.ord.length = 10;

    cl = s3_quic_copy_buffer(&s3_test_conn, (u_char *)"0123456789", 10);
    S3_ASSERT(cl != NULL && cl != S3_CHAIN_ERROR);
    f->data = cl;

    f->len = s3_quic_create_frame(NULL, f);
    S3_ASSERT(f->len == 13);

    s3_queue_insert_tail(&head, &f->queue);

    /* CRYPTO splits at 6 bytes */

    S3_ASSERT(s3_quic_split_frame(&s3_test_conn, f, 6) == S3_OK);
    S3_ASSERT(f->len == 6);
    S3_ASSERT(f->u.ord.offset == 16);
    S3_ASSERT(f->u.ord.length == 3);
    S3_ASSERT(s3_buf_size(f->data->buf) == 3);
    S3_ASSERT(s3_memcmp(f->data->buf->pos, "012", 3) == 0);

    /* the tail frame is inserted right after the head one */

    nf = s3_queue_data(s3_queue_next(s3_queue_head(&head)), s3_quic_frame_t, queue);
    S3_ASSERT(nf == s3_queue_data(s3_queue_next(&f->queue), s3_quic_frame_t, queue));
    S3_ASSERT(nf->type == S3_QUIC_FT_CRYPTO);
    S3_ASSERT(nf->u.ord.offset == 19);
    S3_ASSERT(nf->u.ord.length == 7);
    S3_ASSERT(nf->len == 10);
    S3_ASSERT(s3_buf_size(nf->data->buf) == 7);
    S3_ASSERT(s3_memcmp(nf->data->buf->pos, "3456789", 7) == 0);

    s3_quic_free_frames(&s3_test_conn, &head);

    /* a no-op split when the frame already fits */

    s3_queue_init(&head);

    f = s3_quic_alloc_frame(&s3_test_conn);
    S3_ASSERT(f != NULL);
    f->level = S3_QUIC_ENCRYPTION_HANDSHAKE;
    f->type = S3_QUIC_FT_CRYPTO;
    f->u.ord.offset = 0;
    f->u.ord.length = 3;

    cl = s3_quic_copy_buffer(&s3_test_conn, (u_char *)"abc", 3);
    S3_ASSERT(cl != NULL && cl != S3_CHAIN_ERROR);
    f->data = cl;
    f->len = s3_quic_create_frame(NULL, f);
    s3_queue_insert_tail(&head, &f->queue);

    S3_ASSERT(s3_quic_split_frame(&s3_test_conn, f, f->len) == S3_OK);
    S3_ASSERT(s3_queue_next(&f->queue) == s3_queue_sentinel(&head));

    s3_quic_free_frames(&s3_test_conn, &head);

    /* DATAGRAM must never be cut (porting map 3.5.6) */

    f = s3_quic_alloc_frame(&s3_test_conn);
    S3_ASSERT(f != NULL);
    f->level = S3_QUIC_ENCRYPTION_APPLICATION;
    f->type = S3_QUIC_FT_DATAGRAM;
    f->u.datagram.length = 3;

    cl = s3_quic_copy_buffer(&s3_test_conn, (u_char *)"xyz", 3);
    S3_ASSERT(cl != NULL && cl != S3_CHAIN_ERROR);
    f->data = cl;
    f->len = s3_quic_create_frame(NULL, f);

    S3_ASSERT(s3_quic_split_frame(&s3_test_conn, f, 1) == S3_DECLINED);

    s3_quic_free_frame(&s3_test_conn, f);

    return s3_test_failures;
}

static int
test_alloc_queue(void)
{
    s3_queue_t       head;
    s3_quic_frame_t *f1, *f2, *f3, *q;
    s3_chain_t      *cl;

    /* frame reuse and flood protection */

    f1 = s3_quic_alloc_frame(&s3_test_conn);
    f2 = s3_quic_alloc_frame(&s3_test_conn);
    f3 = s3_quic_alloc_frame(&s3_test_conn);
    S3_ASSERT(f1 != NULL && f2 != NULL && f3 != NULL);
    S3_ASSERT(s3_test_qc.nframes == 3);

    s3_quic_free_frame(&s3_test_conn, f1);
    s3_quic_free_frame(&s3_test_conn, f2);
    S3_ASSERT(s3_test_qc.nframes == 3);

    q = s3_quic_alloc_frame(&s3_test_conn);
    S3_ASSERT(q == f2); /* LIFO reuse */
    S3_ASSERT(s3_test_qc.nframes == 3);

    s3_quic_free_frame(&s3_test_conn, f3);
    s3_quic_free_frame(&s3_test_conn, q);

    /*
     * flood: a fresh connection with an exhausted frame budget does
     * not allocate (frames already on the free queue are reused first,
     * like in nginx)
     */
    setup();
    s3_test_qc.max_frames = 0;
    S3_ASSERT(s3_quic_alloc_frame(&s3_test_conn) == NULL);

    /* restore the budget for the queue_frame part */
    setup();

    /* queue_frame lands in the right packet number space */

    s3_queue_init(&head);

    f1 = s3_quic_alloc_frame(&s3_test_conn);
    S3_ASSERT(f1 != NULL);
    f1->level = S3_QUIC_ENCRYPTION_INITIAL;
    f1->type = S3_QUIC_FT_PING;

    s3_quic_queue_frame(&s3_test_qc, f1);
    S3_ASSERT(f1->len == 1);
    S3_ASSERT(s3_queue_head(&s3_test_qc.send_ctx[0].frames) == &f1->queue);

    f2 = s3_quic_alloc_frame(&s3_test_conn);
    S3_ASSERT(f2 != NULL);
    f2->level = S3_QUIC_ENCRYPTION_APPLICATION;
    f2->type = S3_QUIC_FT_CRYPTO;
    f2->u.crypto.offset = 0;
    f2->u.crypto.length = 2;

    cl = s3_quic_copy_buffer(&s3_test_conn, (u_char *)"\x01\x02", 2);
    S3_ASSERT(cl != NULL && cl != S3_CHAIN_ERROR);
    f2->data = cl;

    s3_quic_queue_frame(&s3_test_qc, f2);
    S3_ASSERT(f2->len == 5); /* ft + offset + length + data */

    s3_quic_free_frames(&s3_test_conn, &s3_test_qc.send_ctx[0].frames);
    s3_quic_free_frames(&s3_test_conn, &s3_test_qc.send_ctx[2].frames);
    S3_ASSERT(s3_queue_empty(&s3_test_qc.send_ctx[0].frames));
    S3_ASSERT(s3_queue_empty(&s3_test_qc.send_ctx[2].frames));

    return s3_test_failures;
}

static int
s3_test_quic_frames(void)
{
    s3_test_log.log_level = S3_LOG_ALERT;
    s3_test_log.fd = S3_INVALID_FILE;

    s3_test_pool = s3_create_pool(16 * 1024, &s3_test_log);
    S3_ASSERT(s3_test_pool != NULL);

    setup();

    test_read_write();
    test_shadow_refcount();
    test_hole_and_skip();
    test_copy_buffer();
    test_split_frame();
    test_alloc_queue();

    s3_destroy_pool(s3_test_pool);

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_quic_frames)
