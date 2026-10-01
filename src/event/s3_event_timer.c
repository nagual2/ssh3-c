/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <s3_core.h>

/*
 * the rbtree of the current event context; s3_event_add_timer() and
 * s3_event_del_timer() have no context argument, so the rbtree is
 * registered by s3_event_timer_init(), like the nginx globals
 */
static s3_rbtree_t *s3_event_timer_rbtree = NULL;

/*
 * the event timer rbtree may contain the duplicate keys, however,
 * it should not be a problem, because we use the rbtree to find
 * a minimum timer value only
 */

s3_int_t
s3_event_timer_init(s3_event_ctx_t *ctx)
{
    s3_event_timer_rbtree = &ctx->timer_rbtree;

    s3_rbtree_init(&ctx->timer_rbtree, &ctx->timer_sentinel, s3_rbtree_insert_timer_value);

    return S3_OK;
}

s3_msec_t
s3_event_find_timer(s3_event_ctx_t *ctx)
{
    s3_msec_int_t     timer;
    s3_rbtree_node_t *node, *root, *sentinel;

    if (ctx->timer_rbtree.root == &ctx->timer_sentinel) {
        return S3_TIMER_INFINITE;
    }

    root = ctx->timer_rbtree.root;
    sentinel = ctx->timer_rbtree.sentinel;

    node = s3_rbtree_min(root, sentinel);

    timer = (s3_msec_int_t)(node->key - s3_current_msec);

    return (s3_msec_t)(timer > 0 ? timer : 0);
}

void
s3_event_expire_timers(s3_event_ctx_t *ctx)
{
    s3_event_t       *ev;
    s3_rbtree_node_t *node, *root, *sentinel;

    sentinel = ctx->timer_rbtree.sentinel;

    for (;;) {
        root = ctx->timer_rbtree.root;

        if (root == sentinel) {
            return;
        }

        node = s3_rbtree_min(root, sentinel);

        /* node->key > s3_current_msec */

        if ((s3_msec_int_t)(node->key - s3_current_msec) > 0) {
            return;
        }

        ev = (s3_event_t *)((u_char *)node - offsetof(s3_event_t, timer));

        s3_rbtree_delete(&ctx->timer_rbtree, &ev->timer);

        ev->timer_set = 0;

        ev->timedout = 1;

        ev->handler(ev);
    }
}

void
s3_event_del_timer(s3_event_t *ev)
{
    if (s3_event_timer_rbtree == NULL) {
        return;
    }

    s3_rbtree_delete(s3_event_timer_rbtree, &ev->timer);

    ev->timer_set = 0;
}

void
s3_event_add_timer(s3_event_t *ev, s3_msec_t timer)
{
    s3_msec_t     key;
    s3_msec_int_t diff;

    if (s3_event_timer_rbtree == NULL) {
        return;
    }

    key = s3_current_msec + timer;

    if (ev->timer_set) {

        /*
         * use a previous timer value if difference between it and a new
         * value is less than S3_TIMER_LAZY_DELAY milliseconds: this allows
         * to minimize the rbtree operations for fast connections
         */

        diff = (s3_msec_int_t)(key - ev->timer.key);

        if ((diff < 0 ? -diff : diff) < S3_TIMER_LAZY_DELAY) {
            return;
        }

        s3_event_del_timer(ev);
    }

    ev->timer.key = key;
    ev->timer.data = ev;

    s3_rbtree_insert(s3_event_timer_rbtree, &ev->timer);

    ev->timer_set = 1;
}
