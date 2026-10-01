/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <s3_core.h>

#include "s3_test.h"

static int s3_test_cleanup_calls = 0;

static void
s3_test_cleanup_handler(void *data)
{
    (void)data;

    s3_test_cleanup_calls++;
}

static int
s3_test_pool(void)
{
    s3_log_t           log;
    s3_pool_t         *pool;
    u_char            *p1, *p2, *large;
    int                i;
    s3_int_t           rc;
    s3_pool_cleanup_t *c;

    log.log_level = S3_LOG_ALERT;
    log.fd = S3_INVALID_FILE;

    /* bump allocation */

    pool = s3_create_pool(1024, &log);
    S3_ASSERT(pool != NULL);
    S3_ASSERT(pool->max == 1024 - sizeof(s3_pool_t));
    S3_ASSERT(pool->current == pool);

    p1 = s3_palloc(pool, 100);
    S3_ASSERT(p1 != NULL);
    S3_ASSERT(((uintptr_t)p1 & (S3_POOL_ALIGNMENT - 1)) == 0);

    p2 = s3_pcalloc(pool, 77);
    S3_ASSERT(p2 != NULL);
    S3_ASSERT(p2 != p1);
    for (i = 0; i < 77; i++) {
        S3_ASSERT(p2[i] == 0);
    }

    /* size 0 is a valid small allocation */

    p2 = s3_palloc(pool, 0);
    S3_ASSERT(p2 != NULL);

    /* large allocation beyond pool->max */

    large = s3_palloc(pool, (size_t)pool->max + 1);
    S3_ASSERT(large != NULL);

    rc = s3_pfree(pool, large);
    S3_ASSERT(rc == S3_OK);
    rc = s3_pfree(pool, large);
    S3_ASSERT(rc == S3_DECLINED);

    /* pfree of a pool-internal pointer is declined */

    rc = s3_pfree(pool, p1);
    S3_ASSERT(rc == S3_DECLINED);

    /* cleanup handlers run on destroy, NULL handlers are skipped */

    c = s3_pool_cleanup_add(pool, 0);
    S3_ASSERT(c != NULL);
    c->handler = s3_test_cleanup_handler;

    c = s3_pool_cleanup_add(pool, 8);
    S3_ASSERT(c != NULL);
    c->handler = s3_test_cleanup_handler;

    c = s3_pool_cleanup_add(pool, 0);
    S3_ASSERT(c != NULL);
    c->handler = NULL;

    s3_test_cleanup_calls = 0;
    s3_destroy_pool(pool);
    S3_ASSERT(s3_test_cleanup_calls == 2);

    /* reset_pool resets the bump pointer and frees large blocks */

    pool = s3_create_pool(4096, &log);
    S3_ASSERT(pool != NULL);

    p1 = s3_pnalloc(pool, 32);
    S3_ASSERT(p1 != NULL);

    large = s3_palloc(pool, 100000);
    S3_ASSERT(large != NULL);

    s3_reset_pool(pool);
    S3_ASSERT(pool->large == NULL);
    S3_ASSERT(pool->current == pool);

    p2 = s3_pnalloc(pool, 32);
    S3_ASSERT(p2 == p1);

    s3_destroy_pool(pool);

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_pool)
