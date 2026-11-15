/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <s3_core.h>
#include <stdio.h>

/*
 * the rbtree of the current event context; s3_event_add_timer() and
 * s3_event_del_timer() have no context argument, so the rbtree is
 * registered by s3_event_timer_init(), like the nginx globals
 */
static s3_rbtree_t *s3_event_timer_rbtree = NULL;

static int
s3_timer_dump_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        enabled = (getenv("S3_TIMER_DUMP") != NULL);
    }

    return enabled;
}

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
    s3_event_t         *ev;
    s3_event_handler_pt handler;
    s3_rbtree_node_t   *node, *root, *sentinel;

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

        handler = ev->handler;

        handler(ev);

        /*
         * the wave-14 mingw isolation: the tree state after a handler
         * ran - a close inside the handler may leave the nodes of the
         * destroyed pool behind, the next min() then dereferences the
         * freed event
         */

        if (s3_timer_dump_enabled()) {
            fprintf(stderr, "TIMER-TREE after-handler=%p\n", (void *)(uintptr_t)handler);

            s3_event_timer_tree_dump(NULL, "expire");
        }
    }
}

static void
s3_timer_dump_walk(s3_rbtree_node_t *node, s3_rbtree_node_t *sentinel, const void *owner,
                   unsigned *count)
{
    s3_event_t *ev;

    if (node == sentinel || *count >= 64) {
        return;
    }

    s3_timer_dump_walk(node->left, sentinel, owner, count);

    ev = (s3_event_t *)((u_char *)node - offsetof(s3_event_t, timer));

    fprintf(stderr,
            "  node=%p ev=%p rel=%lld ts=%d cl=%d ac=%d po=%d to=%d wr=%d"
            " handler=%p data=%p own=%d\n",
            (void *)node, (void *)ev, (long long)((s3_msec_int_t)(node->key - s3_current_msec)),
            (int)ev->timer_set, (int)ev->closed, (int)ev->active, (int)ev->posted,
            (int)ev->timedout, (int)ev->write, (void *)(uintptr_t)ev->handler, ev->data,
            (owner != NULL && ev->data == owner));

    (*count)++;

    s3_timer_dump_walk(node->right, sentinel, owner, count);
}

void
s3_event_timer_tree_dump(const void *owner, const char *label)
{
    unsigned count = 0;

    if (!s3_timer_dump_enabled() || s3_event_timer_rbtree == NULL) {
        return;
    }

    fprintf(stderr, "TIMER-TREE %s\n", label);

    s3_timer_dump_walk(s3_event_timer_rbtree->root, s3_event_timer_rbtree->sentinel, owner, &count);

    fprintf(stderr, "TIMER-TREE %s nodes=%u\n", label, count);
}

void
s3_event_timer_close_audit(s3_connection_t *c, s3_fd_t fd)
{
    if (!s3_timer_dump_enabled()) {
        return;
    }

    /*
     * the wave-14 mingw isolation: the tree is dumped BEFORE the
     * connection pool dies - the own=1 nodes (the events owned by
     * this connection or its quic connection) are the entries that
     * will dangle if this close bypasses the quic timer cleanup
     */

    fprintf(stderr, "TIMER-TREE close c=%p fd=%d shared=%d\n", (void *)c, (int)fd, (int)c->shared);

    s3_event_timer_tree_dump(c, "pre-close");
}

void
s3_event_timer_close_site(const char *site)
{
    if (!s3_timer_dump_enabled()) {
        return;
    }

    fprintf(stderr, "TIMER-TREE close-site %s\n", site);
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
