/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the ssh3 conversation: the channel registry (rbtree keyed by
 * ChannelID == StreamID), the accept queue of the incoming channels
 * and the per-channelID datagram store (the dangling queues of the
 * reference resources_manager.go)
 */

#include <s3_core.h>

#include <string.h>

#include <s3_ssh3_conversation.h>

#include "s3_test.h"

static s3_pool_t *
s3_test_make_pool(s3_log_t *log)
{
    log->log_level = S3_LOG_ALERT;
    log->fd = S3_INVALID_FILE;

    return s3_create_pool(S3_DEFAULT_POOL_SIZE, log);
}

static s3_ssh3_channel_t *
s3_test_make_channel(s3_pool_t *pool, uint64_t channel_id)
{
    s3_ssh3_channel_t *ch;

    ch = s3_pcalloc(pool, sizeof(s3_ssh3_channel_t));
    if (ch == NULL) {
        return NULL;
    }

    ch->channel_id = channel_id;

    return ch;
}

static int
s3_test_registry(void)
{
    s3_log_t               log;
    s3_pool_t             *pool;
    s3_ssh3_conversation_t conv;
    s3_ssh3_channel_t     *c0, *c4, *c8;

    pool = s3_test_make_pool(&log);
    S3_ASSERT(pool != NULL);

    S3_ASSERT(s3_ssh3_conversation_init(&conv, pool, 12) == S3_OK);
    S3_ASSERT(conv.control_stream_id == 12);
    S3_ASSERT(conv.pool == pool);

    /* the empty registry and the empty accept queue answer nothing */

    S3_ASSERT(s3_ssh3_conversation_find_channel(&conv, 0) == NULL);
    S3_ASSERT(s3_ssh3_conversation_dequeue_accept(&conv) == NULL);

    c0 = s3_test_make_channel(pool, 0);
    c4 = s3_test_make_channel(pool, 4);
    c8 = s3_test_make_channel(pool, 8);

    S3_ASSERT(c0 != NULL && c4 != NULL && c8 != NULL);

    s3_ssh3_conversation_link_channel(&conv, c0);
    s3_ssh3_conversation_link_channel(&conv, c4);
    s3_ssh3_conversation_link_channel(&conv, c8);

    S3_ASSERT(s3_ssh3_conversation_find_channel(&conv, 0) == c0);
    S3_ASSERT(s3_ssh3_conversation_find_channel(&conv, 4) == c4);
    S3_ASSERT(s3_ssh3_conversation_find_channel(&conv, 8) == c8);
    S3_ASSERT(s3_ssh3_conversation_find_channel(&conv, 3) == NULL);

    /* the unlinked channel leaves the registry, the others stay */

    s3_ssh3_conversation_unlink_channel(&conv, c4);

    S3_ASSERT(s3_ssh3_conversation_find_channel(&conv, 4) == NULL);
    S3_ASSERT(s3_ssh3_conversation_find_channel(&conv, 0) == c0);
    S3_ASSERT(s3_ssh3_conversation_find_channel(&conv, 8) == c8);

    s3_destroy_pool(pool);

    return s3_test_failures;
}

static int
s3_test_accept_queue(void)
{
    s3_log_t               log;
    s3_pool_t             *pool;
    s3_ssh3_conversation_t conv;
    s3_ssh3_channel_t     *c0, *c4, *c8;

    pool = s3_test_make_pool(&log);
    S3_ASSERT(pool != NULL);

    S3_ASSERT(s3_ssh3_conversation_init(&conv, pool, 4) == S3_OK);

    c0 = s3_test_make_channel(pool, 0);
    c4 = s3_test_make_channel(pool, 4);
    c8 = s3_test_make_channel(pool, 8);

    S3_ASSERT(c0 != NULL && c4 != NULL && c8 != NULL);

    /* the incoming channels come out in the arrival order */

    s3_ssh3_conversation_enqueue_accept(&conv, c0);
    s3_ssh3_conversation_enqueue_accept(&conv, c4);
    s3_ssh3_conversation_enqueue_accept(&conv, c8);

    S3_ASSERT(s3_ssh3_conversation_dequeue_accept(&conv) == c0);
    S3_ASSERT(s3_ssh3_conversation_dequeue_accept(&conv) == c4);
    S3_ASSERT(s3_ssh3_conversation_dequeue_accept(&conv) == c8);
    S3_ASSERT(s3_ssh3_conversation_dequeue_accept(&conv) == NULL);

    s3_destroy_pool(pool);

    return s3_test_failures;
}

static int
s3_test_dgram_store_fifo(void)
{
    s3_log_t               log;
    s3_pool_t             *pool;
    s3_ssh3_conversation_t conv;
    s3_str_t               out;

    pool = s3_test_make_pool(&log);
    S3_ASSERT(pool != NULL);

    S3_ASSERT(s3_ssh3_conversation_init(&conv, pool, 4) == S3_OK);

    /* nothing was queued for any channel yet */

    S3_ASSERT(s3_ssh3_conversation_pop_datagram(&conv, 7, &out) == S3_AGAIN);
    S3_ASSERT(s3_ssh3_conversation_pop_datagram(&conv, 99, &out) == S3_AGAIN);

    /* the payloads come out per channel in the arrival order */

    S3_ASSERT(s3_ssh3_conversation_push_datagram(&conv, 7, (const u_char *)"aaa", 3) == S3_OK);
    S3_ASSERT(s3_ssh3_conversation_push_datagram(&conv, 7, (const u_char *)"bbbb", 4) == S3_OK);
    S3_ASSERT(s3_ssh3_conversation_push_datagram(&conv, 7, (const u_char *)"cc", 2) == S3_OK);

    S3_ASSERT(s3_ssh3_conversation_pop_datagram(&conv, 7, &out) == S3_OK);
    S3_ASSERT(out.len == 3);
    S3_ASSERT(s3_memcmp(out.data, "aaa", 3) == 0);

    S3_ASSERT(s3_ssh3_conversation_pop_datagram(&conv, 7, &out) == S3_OK);
    S3_ASSERT(out.len == 4);
    S3_ASSERT(s3_memcmp(out.data, "bbbb", 4) == 0);

    S3_ASSERT(s3_ssh3_conversation_pop_datagram(&conv, 7, &out) == S3_OK);
    S3_ASSERT(out.len == 2);
    S3_ASSERT(s3_memcmp(out.data, "cc", 2) == 0);

    S3_ASSERT(s3_ssh3_conversation_pop_datagram(&conv, 7, &out) == S3_AGAIN);

    /* the stores of different channels do not mix */

    S3_ASSERT(s3_ssh3_conversation_push_datagram(&conv, 8, (const u_char *)"x", 1) == S3_OK);
    S3_ASSERT(s3_ssh3_conversation_push_datagram(&conv, 9, (const u_char *)"y", 1) == S3_OK);

    S3_ASSERT(s3_ssh3_conversation_pop_datagram(&conv, 8, &out) == S3_OK);
    S3_ASSERT(out.len == 1 && out.data[0] == 'x');

    S3_ASSERT(s3_ssh3_conversation_pop_datagram(&conv, 9, &out) == S3_OK);
    S3_ASSERT(out.len == 1 && out.data[0] == 'y');

    /* the zero-length payload round-trips (data may be NULL) */

    S3_ASSERT(s3_ssh3_conversation_push_datagram(&conv, 10, NULL, 0) == S3_OK);

    S3_ASSERT(s3_ssh3_conversation_pop_datagram(&conv, 10, &out) == S3_OK);
    S3_ASSERT(out.len == 0);
    S3_ASSERT(s3_ssh3_conversation_pop_datagram(&conv, 10, &out) == S3_AGAIN);

    s3_destroy_pool(pool);

    return s3_test_failures;
}

static int
s3_test_dgram_store_overflow(void)
{
    s3_log_t               log;
    s3_pool_t             *pool;
    s3_ssh3_conversation_t conv;
    s3_str_t               out;
    u_char                 vals[S3_SSH3_DGRAM_QUEUE_MAX];
    uint64_t               i;

    pool = s3_test_make_pool(&log);
    S3_ASSERT(pool != NULL);

    S3_ASSERT(s3_ssh3_conversation_init(&conv, pool, 4) == S3_OK);

    /* the queue fills up to S3_SSH3_DGRAM_QUEUE_MAX entries */

    for (i = 0; i < S3_SSH3_DGRAM_QUEUE_MAX; i++) {
        vals[i] = (u_char)i;

        S3_ASSERT(s3_ssh3_conversation_push_datagram(&conv, 10, vals + i, 1) == S3_OK);
    }

    /* the next payload is dropped with S3_BUSY and the queue stays
     * whole: the stored order survives below */

    S3_ASSERT(s3_ssh3_conversation_push_datagram(&conv, 10, (const u_char *)"x", 1) == S3_BUSY);

    for (i = 0; i < S3_SSH3_DGRAM_QUEUE_MAX; i++) {
        S3_ASSERT(s3_ssh3_conversation_pop_datagram(&conv, 10, &out) == S3_OK);
        S3_ASSERT(out.len == 1 && out.data[0] == vals[i]);
    }

    S3_ASSERT(s3_ssh3_conversation_pop_datagram(&conv, 10, &out) == S3_AGAIN);

    s3_destroy_pool(pool);

    return s3_test_failures;
}

static int
s3_test_dgram_store_outlives_channel(void)
{
    s3_log_t               log;
    s3_pool_t             *pool;
    s3_ssh3_conversation_t conv;
    s3_ssh3_channel_t     *c4;
    s3_str_t               out;

    pool = s3_test_make_pool(&log);
    S3_ASSERT(pool != NULL);

    S3_ASSERT(s3_ssh3_conversation_init(&conv, pool, 4) == S3_OK);

    c4 = s3_test_make_channel(pool, 4);
    S3_ASSERT(c4 != NULL);

    s3_ssh3_conversation_link_channel(&conv, c4);

    /* the store is keyed by channel id only: payloads pushed while
     * the channel was linked and after its unlink sit in the same
     * queue and the channel lookup answers nothing */

    S3_ASSERT(s3_ssh3_conversation_push_datagram(&conv, 4, (const u_char *)"one", 3) == S3_OK);

    s3_ssh3_conversation_unlink_channel(&conv, c4);

    S3_ASSERT(s3_ssh3_conversation_find_channel(&conv, 4) == NULL);
    S3_ASSERT(s3_ssh3_conversation_push_datagram(&conv, 4, (const u_char *)"two", 3) == S3_OK);

    S3_ASSERT(s3_ssh3_conversation_pop_datagram(&conv, 4, &out) == S3_OK);
    S3_ASSERT(out.len == 3);
    S3_ASSERT(s3_memcmp(out.data, "one", 3) == 0);

    S3_ASSERT(s3_ssh3_conversation_pop_datagram(&conv, 4, &out) == S3_OK);
    S3_ASSERT(out.len == 3);
    S3_ASSERT(s3_memcmp(out.data, "two", 3) == 0);

    S3_ASSERT(s3_ssh3_conversation_pop_datagram(&conv, 4, &out) == S3_AGAIN);

    s3_destroy_pool(pool);

    return s3_test_failures;
}

static int
s3_test_ssh3_conversation(void)
{
    (void)s3_test_registry();
    (void)s3_test_accept_queue();
    (void)s3_test_dgram_store_fifo();
    (void)s3_test_dgram_store_overflow();
    (void)s3_test_dgram_store_outlives_channel();

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_ssh3_conversation)
