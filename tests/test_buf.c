/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <s3_core.h>

#include "s3_test.h"

static int
s3_test_buf(void)
{
    s3_log_t     log;
    s3_pool_t   *pool;
    s3_buf_t    *b, *b2;
    s3_chain_t  *free, *busy, *out, *cl, *cl2, *copy;
    s3_buf_tag_t tag = (s3_buf_tag_t)&s3_test_buf;
    s3_int_t     rc;

    log.log_level = S3_LOG_ALERT;
    log.fd = S3_INVALID_FILE;

    pool = s3_create_pool(4096, &log);
    S3_ASSERT(pool != NULL);

    /* create_temp_buf */

    b = s3_create_temp_buf(pool, 128);
    S3_ASSERT(b != NULL);
    S3_ASSERT(b->temporary == 1);
    S3_ASSERT(b->pos == b->start);
    S3_ASSERT(b->last == b->start);
    S3_ASSERT(b->end == b->start + 128);
    S3_ASSERT(s3_buf_in_memory(b));
    S3_ASSERT(s3_buf_in_memory_only(b));
    S3_ASSERT(!s3_buf_special(b));
    S3_ASSERT(s3_buf_size(b) == 0);

    /* empty chain ops are no-ops */

    free = NULL;
    busy = NULL;
    out = NULL;

    s3_chain_update_chains(pool, &free, &busy, &out, tag);
    S3_ASSERT(free == NULL && busy == NULL && out == NULL);

    /* free/busy cycle by tag */

    cl = s3_chain_get_free_buf(pool, &free);
    S3_ASSERT(cl != NULL);
    S3_ASSERT(cl->buf != NULL);
    S3_ASSERT(cl->next == NULL);

    /* the fresh buf comes from s3_calloc_buf: flag-only, without memory;
     * point it at a pool block first, start + N on a NULL start is UB */

    cl->buf->start = s3_pnalloc(pool, 128);
    S3_ASSERT(cl->buf->start != NULL);
    cl->buf->end = cl->buf->start + 128;

    /* the caller tags the recycled buf and marks it writable */

    cl->buf->tag = tag;
    cl->buf->temporary = 1;
    cl->buf->pos = cl->buf->start;
    cl->buf->last = cl->buf->start + 16;

    out = cl;
    s3_chain_update_chains(pool, &free, &busy, &out, tag);

    S3_ASSERT(out == NULL);
    S3_ASSERT(busy == cl);
    S3_ASSERT(free == NULL);

    /* buffer fully consumed: buf goes back to the free list */

    cl->buf->pos = cl->buf->last;
    s3_chain_update_chains(pool, &free, &busy, &out, tag);

    S3_ASSERT(busy == NULL);
    S3_ASSERT(free == cl);
    S3_ASSERT(cl->buf->pos == cl->buf->start);
    S3_ASSERT(cl->buf->last == cl->buf->start);

    /* foreign tag: chain link is released to the pool, not the free list */

    cl2 = s3_chain_get_free_buf(pool, &free);
    S3_ASSERT(cl2 == cl);

    cl2->buf->tag = (s3_buf_tag_t)1;
    out = cl2;
    s3_chain_update_chains(pool, &free, &busy, &out, tag);

    S3_ASSERT(out == NULL);
    S3_ASSERT(busy == NULL);
    S3_ASSERT(free == NULL);

    cl2 = s3_alloc_chain_link(pool);
    S3_ASSERT(cl2 == cl);

    /* pending data with our tag stays in busy */

    cl->buf->tag = tag;
    cl->buf->last = cl->buf->start + 4;
    out = cl;
    s3_chain_update_chains(pool, &free, &busy, &out, tag);

    S3_ASSERT(busy == cl);
    S3_ASSERT(free == NULL);

    /* chain_link_copy duplicates the link list, not the bufs */

    b2 = s3_calloc_buf(pool);
    S3_ASSERT(b2 != NULL);

    cl2 = s3_alloc_chain_link(pool);
    S3_ASSERT(cl2 != NULL);
    cl2->buf = b2;
    cl2->next = NULL;
    cl->next = cl2;

    copy = NULL;
    rc = s3_chain_link_copy(pool, &copy, cl);
    S3_ASSERT(rc == S3_OK);
    S3_ASSERT(copy != NULL && copy != cl);
    S3_ASSERT(copy->buf == cl->buf);
    S3_ASSERT(copy->next != NULL && copy->next->buf == b2);
    S3_ASSERT(copy->next->next == NULL);

    /* special bufs: flag-only, without memory or file content */

    b2 = s3_calloc_buf(pool);
    b2->sync = 1;
    S3_ASSERT(s3_buf_special(b2));
    S3_ASSERT(s3_buf_sync_only(b2));
    S3_ASSERT(s3_buf_size(b2) == 0);

    b2 = s3_calloc_buf(pool);
    b2->flush = 1;
    S3_ASSERT(s3_buf_special(b2));
    S3_ASSERT(!s3_buf_sync_only(b2));

    s3_destroy_pool(pool);

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_buf)
