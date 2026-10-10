/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <s3_core.h>

#include <time.h>

/* current monotonic time in milliseconds */
s3_msec_t s3_current_msec;

#if (S3_WIN32)
void
s3_time_update(void)
{
    /* the monotonic millisecond counter since the boot, never wraps */
    s3_current_msec = (s3_msec_t)GetTickCount64();
}
#else
void
s3_time_update(void)
{
    struct timespec ts;

    (void)clock_gettime(CLOCK_MONOTONIC, &ts);

    s3_current_msec = (s3_msec_t)ts.tv_sec * 1000 + (s3_msec_t)ts.tv_nsec / 1000000;
}
#endif

s3_int_t
s3_event_ctx_init(s3_event_ctx_t *ctx, s3_log_t *log)
{
    s3_memzero(ctx, sizeof(s3_event_ctx_t));

    ctx->log = log;

    ctx->pool = s3_create_pool((size_t)S3_DEFAULT_POOL_SIZE, log);
    if (ctx->pool == NULL) {
        return S3_ERROR;
    }

    if (s3_event_timer_init(ctx) != S3_OK) {
        return S3_ERROR;
    }

    s3_queue_init(&ctx->posted_events);

    s3_time_update();

    if (s3_event_actions.init(ctx) != S3_OK) {
        return S3_ERROR;
    }

    return S3_OK;
}

void
s3_event_ctx_shutdown(s3_event_ctx_t *ctx)
{
    if (s3_event_actions.done != NULL) {
        s3_event_actions.done(ctx);
    }

    if (ctx->pool != NULL) {
        s3_destroy_pool(ctx->pool);
        ctx->pool = NULL;
    }
}

void
s3_process_events_and_timers(s3_event_ctx_t *ctx)
{
    s3_uint_t flags;
    s3_msec_t timer;

    s3_time_update();

    timer = s3_event_find_timer(ctx);

    flags = S3_UPDATE_TIME;

    (void)s3_event_actions.process_events(ctx, timer, flags);

    s3_event_expire_timers(ctx);

    s3_event_process_posted(ctx, &ctx->posted_events);
}
