/*
 * Copyright (C) 2026 the ssh3-c authors
 */

/*
 * tests for the event core: context, timers, posted events
 */

#include <s3_core.h>

#include "s3_test.h"

typedef struct {
    s3_event_t ev;
    int        fired;
    int        seq; /* the fire sequence number */
} s3_test_timer_t;

static int s3_test_seq;

static void
s3_test_timer_handler(s3_event_t *ev)
{
    s3_test_timer_t *t = (s3_test_timer_t *)ev->data;

    t->fired++;
    t->seq = ++s3_test_seq;
}

static void
s3_test_timer_init(s3_test_timer_t *t)
{
    s3_memzero(t, sizeof(s3_test_timer_t));

    t->ev.data = t;
    t->ev.handler = s3_test_timer_handler;
    t->ev.log = &s3_stderr_log;
}

/* runs the event loop until the flag is set or the iteration limit hits */

static void
s3_test_run_until(s3_event_ctx_t *ctx, int *flag)
{
    int n;

    for (n = 0; n < 1000 && !*flag; n++) {
        s3_process_events_and_timers(ctx);
    }
}

static int
s3_test_ctx_init(s3_event_ctx_t *ctx)
{
    int failures = 0;

    S3_ASSERT(s3_event_ctx_init(ctx, &s3_stderr_log) == S3_OK);
    S3_ASSERT(ctx->pool != NULL);
    S3_ASSERT(ctx->impl != NULL);
    S3_ASSERT(s3_event_find_timer(ctx) == S3_TIMER_INFINITE);
    S3_ASSERT(s3_current_msec != 0);

    return failures;
}

static int
s3_test_single_timer(s3_event_ctx_t *ctx)
{
    int             failures = 0;
    s3_test_timer_t t, done;

    s3_test_timer_init(&t);

    s3_event_add_timer(&t.ev, 30);

    S3_ASSERT(t.ev.timer_set == 1);
    S3_ASSERT(s3_event_find_timer(ctx) <= 30);

    s3_test_run_until(ctx, &t.fired);

    S3_ASSERT(t.fired == 1);
    S3_ASSERT(t.ev.timer_set == 0);
    S3_ASSERT(t.ev.timedout == 1);

    /* the timer must not fire again */

    s3_test_timer_init(&done);
    s3_event_add_timer(&done.ev, 60);

    s3_test_run_until(ctx, &done.fired);

    S3_ASSERT(done.fired == 1);
    S3_ASSERT(t.fired == 1);

    return failures;
}

static int
s3_test_timer_order(s3_event_ctx_t *ctx)
{
    int             failures = 0;
    s3_test_timer_t a, b, done;

    s3_test_timer_init(&a);
    s3_test_timer_init(&b);

    s3_event_add_timer(&a.ev, 40);
    s3_event_add_timer(&b.ev, 10);

    S3_ASSERT(s3_event_find_timer(ctx) <= 10);

    /* a terminator bounds the loop if a timer is lost */

    s3_test_timer_init(&done);
    s3_event_add_timer(&done.ev, 120);

    s3_test_run_until(ctx, &done.fired);

    S3_ASSERT(a.fired == 1);
    S3_ASSERT(b.fired == 1);
    S3_ASSERT(b.seq < a.seq); /* the shorter timer fires first */
    S3_ASSERT(done.seq > a.seq);

    return failures;
}

static int
s3_test_del_timer(s3_event_ctx_t *ctx)
{
    int             failures = 0;
    s3_test_timer_t t, done;

    s3_test_timer_init(&t);

    s3_event_add_timer(&t.ev, 30);
    S3_ASSERT(t.ev.timer_set == 1);

    s3_event_del_timer(&t.ev);
    S3_ASSERT(t.ev.timer_set == 0);

    s3_test_timer_init(&done);
    s3_event_add_timer(&done.ev, 60);

    s3_test_run_until(ctx, &done.fired);

    S3_ASSERT(done.fired == 1);
    S3_ASSERT(t.fired == 0);

    return failures;
}

static int
s3_test_posted(s3_event_ctx_t *ctx)
{
    int             failures = 0;
    s3_test_timer_t e1, e2, e3;

    s3_test_timer_init(&e1);
    s3_test_timer_init(&e2);
    s3_test_timer_init(&e3);

    s3_post_event(&e1.ev, &ctx->posted_events);
    s3_post_event(&e2.ev, &ctx->posted_events);
    s3_post_event(&e3.ev, &ctx->posted_events);

    /* posting the same event again must not duplicate it */

    s3_post_event(&e2.ev, &ctx->posted_events);

    S3_ASSERT(e1.ev.posted == 1);
    S3_ASSERT(e2.ev.posted == 1);
    S3_ASSERT(e3.ev.posted == 1);

    s3_event_process_posted(ctx, &ctx->posted_events);

    S3_ASSERT(e1.fired == 1);
    S3_ASSERT(e2.fired == 1);
    S3_ASSERT(e3.fired == 1);
    S3_ASSERT(e2.seq == e1.seq + 1); /* fifo */
    S3_ASSERT(e3.seq == e2.seq + 1);

    S3_ASSERT(e1.ev.posted == 0);
    S3_ASSERT(e2.ev.posted == 0);
    S3_ASSERT(e3.ev.posted == 0);

    /* the queue is empty now, nothing fires again */

    s3_event_process_posted(ctx, &ctx->posted_events);

    S3_ASSERT(e1.fired == 1);
    S3_ASSERT(e2.fired == 1);
    S3_ASSERT(e3.fired == 1);

    return failures;
}

static int
s3_test_timer_wraparound(s3_event_ctx_t *ctx)
{
    int             failures = 0;
    s3_test_timer_t t1, t2;

    /* the timer keys wrap around uint32; the signed difference of the
       keys must order the timers across the wrap point */

    s3_current_msec = 0xFFFFFF00;

    s3_test_timer_init(&t1);
    s3_test_timer_init(&t2);

    s3_event_add_timer(&t1.ev, 254); /* key: 0xFFFFFFFE */
    s3_event_add_timer(&t2.ev, 261); /* key: 0x00000005, wrapped */

    S3_ASSERT(t1.ev.timer.key == 0xFFFFFFFE);
    S3_ASSERT(t2.ev.timer.key == 0x00000005);

    /* the wrapped key sorts after 0xFFFFFFFE and before the overflow */

    S3_ASSERT(s3_event_find_timer(ctx) == 254);

    s3_current_msec = 0xFFFFFFFF;

    s3_event_expire_timers(ctx);

    S3_ASSERT(t1.fired == 1);
    S3_ASSERT(t2.fired == 0);
    S3_ASSERT(s3_event_find_timer(ctx) == 6);

    s3_current_msec = 0x100000005;

    s3_event_expire_timers(ctx);

    S3_ASSERT(t2.fired == 1);
    S3_ASSERT(s3_event_find_timer(ctx) == S3_TIMER_INFINITE);

    return failures;
}

int
s3_test_event(void)
{
    int            failures;
    s3_event_ctx_t ctx;

    failures = 0;

    failures += s3_test_ctx_init(&ctx);

    failures += s3_test_single_timer(&ctx);
    failures += s3_test_timer_order(&ctx);
    failures += s3_test_del_timer(&ctx);
    failures += s3_test_posted(&ctx);

    failures += s3_test_timer_wraparound(&ctx);

    s3_destroy_pool(ctx.pool);

    return failures;
}

S3_TEST_MAIN(s3_test_event)
