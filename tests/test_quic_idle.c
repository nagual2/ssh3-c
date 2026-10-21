/*
 * Copyright (C) 2026 the ssh3-c authors
 */

/*
 * tests for the QUIC idle timeout: the effective value (RFC 9000, 10.1)
 * and the arming of the timer (a 0 timeout means "no limit", not "fire
 * now" — the reference arms a 0 timer, which closes the connection on
 * the next event loop pass)
 */

#include <s3_core.h>
#include <s3_quic.h>

#include "s3_test.h"

typedef struct {
    s3_event_t ev;
    int        fired;
} s3_test_idle_t;

static void
s3_test_idle_handler(s3_event_t *ev)
{
    s3_test_idle_t *t = (s3_test_idle_t *)ev->data;

    t->fired++;
}

static void
s3_test_idle_init(s3_test_idle_t *t)
{
    s3_memzero(t, sizeof(s3_test_idle_t));

    t->ev.data = t;
    t->ev.handler = s3_test_idle_handler;
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

/*
 * the effective value: the minimum of the two advertised ones, and a 0
 * means "no limit", so a 0 never wins the minimum
 */

static int
s3_test_idle_value(void)
{
    S3_ASSERT(s3_quic_idle_timeout(60000, 30000) == 30000);
    S3_ASSERT(s3_quic_idle_timeout(30000, 60000) == 30000);
    S3_ASSERT(s3_quic_idle_timeout(60000, 60000) == 60000);

    /* a 0 side is "no limit": the other side decides */

    S3_ASSERT(s3_quic_idle_timeout(0, 30000) == 30000);
    S3_ASSERT(s3_quic_idle_timeout(30000, 0) == 30000);
    S3_ASSERT(s3_quic_idle_timeout(0, 0) == 0);

    return s3_test_failures;
}

/* a 0 timeout must not arm the timer at all */

static int
s3_test_idle_no_limit(s3_event_ctx_t *ctx)
{
    s3_test_idle_t t, done;

    s3_test_idle_init(&t);

    s3_quic_arm_idle_timer(&t.ev, 0);

    S3_ASSERT(t.ev.timer_set == 0);

    /* the terminator bounds the loop: the idle timer must stay silent */

    s3_test_idle_init(&done);
    s3_event_add_timer(&done.ev, 100);

    s3_test_run_until(ctx, &done.fired);

    S3_ASSERT(done.fired == 1);
    S3_ASSERT(t.fired == 0);

    return s3_test_failures;
}

/* a real timeout fires, and a 0 timeout clears an armed timer */

static int
s3_test_idle_arm(s3_event_ctx_t *ctx)
{
    s3_test_idle_t t, done;

    s3_test_idle_init(&t);

    s3_quic_arm_idle_timer(&t.ev, 30);

    S3_ASSERT(t.ev.timer_set == 1);

    s3_test_idle_init(&done);
    s3_event_add_timer(&done.ev, 200);

    s3_test_run_until(ctx, &done.fired);

    S3_ASSERT(done.fired == 1);
    S3_ASSERT(t.fired == 1);

    /* a 0 timeout disarms the timer */

    s3_test_idle_init(&t);
    s3_quic_arm_idle_timer(&t.ev, 30);
    S3_ASSERT(t.ev.timer_set == 1);

    s3_quic_arm_idle_timer(&t.ev, 0);
    S3_ASSERT(t.ev.timer_set == 0);

    s3_test_idle_init(&done);
    s3_event_add_timer(&done.ev, 200);

    s3_test_run_until(ctx, &done.fired);

    S3_ASSERT(done.fired == 1);
    S3_ASSERT(t.fired == 0);

    return s3_test_failures;
}

static int
s3_test_quic_idle(void)
{
    s3_event_ctx_t ctx;

    S3_ASSERT(s3_event_ctx_init(&ctx, &s3_stderr_log) == S3_OK);

    (void)s3_test_idle_value();
    (void)s3_test_idle_no_limit(&ctx);
    (void)s3_test_idle_arm(&ctx);

    s3_destroy_pool(ctx.pool);

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_quic_idle)
