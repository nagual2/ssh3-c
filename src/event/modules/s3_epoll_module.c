/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <s3_core.h>

#include <sys/epoll.h>
#include <unistd.h>

#define S3_EPOLL_EVENTS 512

static s3_int_t s3_epoll_init(s3_event_ctx_t *ctx);
static void     s3_epoll_done(s3_event_ctx_t *ctx);
static s3_int_t s3_epoll_add_event(s3_event_t *ev, s3_int_t event, s3_uint_t flags);
static s3_int_t s3_epoll_del_event(s3_event_t *ev, s3_int_t event, s3_uint_t flags);
static s3_int_t s3_epoll_add_connection(s3_event_ctx_t *ctx, s3_connection_t *c);
static s3_int_t s3_epoll_del_connection(s3_event_ctx_t *ctx, s3_connection_t *c);
static s3_int_t s3_epoll_process_events(s3_event_ctx_t *ctx, s3_msec_t timer, s3_uint_t flags);

static int                 s3_ep = -1;
static struct epoll_event *s3_event_list = NULL;

s3_event_actions_t s3_event_actions = {
    s3_epoll_init,           s3_epoll_add_event,      s3_epoll_del_event, s3_epoll_add_connection,
    s3_epoll_del_connection, s3_epoll_process_events, s3_epoll_done,
};

static s3_int_t
s3_epoll_init(s3_event_ctx_t *ctx)
{
    if (s3_ep == -1) {
        s3_ep = epoll_create(S3_EPOLL_EVENTS / 2);

        if (s3_ep == -1) {
            s3_log_error(S3_LOG_EMERG, ctx->log, s3_errno, "epoll_create() failed");
            return S3_ERROR;
        }

        s3_event_list =
            (struct epoll_event *)s3_alloc(sizeof(struct epoll_event) * S3_EPOLL_EVENTS, ctx->log);

        if (s3_event_list == NULL) {
            return S3_ERROR;
        }
    }

    s3_event_flags = 0;

    ctx->impl = (void *)(intptr_t)s3_ep;

    return S3_OK;
}

/*
 * the exit counterpart of init(): the descriptor and the wait array
 * are process globals here, one context owns them by construction
 * (the second ctx_init() reuses them); nothing may poll epoll_wait()
 * after the call
 */

static void
s3_epoll_done(s3_event_ctx_t *ctx)
{
    (void)ctx;

    if (s3_ep != -1) {
        (void)close(s3_ep);
        s3_ep = -1;
    }

    if (s3_event_list != NULL) {
        s3_free(s3_event_list);
        s3_event_list = NULL;
    }
}

static s3_int_t
s3_epoll_add_event(s3_event_t *ev, s3_int_t event, s3_uint_t flags)
{
    int                op;
    uint32_t           events, prev;
    s3_event_t        *e;
    s3_connection_t   *c;
    struct epoll_event ee;

    c = (s3_connection_t *)ev->data;

    if (event == S3_READ_EVENT) {
        e = c->write;
        prev = EPOLLOUT;
        events = EPOLLIN | EPOLLRDHUP;

    } else {
        e = c->read;
        prev = EPOLLIN | EPOLLRDHUP;
        events = EPOLLOUT;
    }

    if (e->active) {
        op = EPOLL_CTL_MOD;
        events |= prev;

    } else {
        op = EPOLL_CTL_ADD;
    }

    ee.events = events | (uint32_t)flags;
    ee.data.ptr = (void *)((uintptr_t)c | ev->instance);

    s3_log_debug3(S3_LOG_DEBUG_EVENT, ev->log, 0, "epoll add event: fd:%d op:%d ev:%uD", c->fd, op,
                  ee.events);

    if (epoll_ctl(s3_ep, op, c->fd, &ee) == -1) {
        s3_log_error(S3_LOG_ALERT, ev->log, s3_errno, "epoll_ctl(%d, %d) failed", op, c->fd);
        return S3_ERROR;
    }

    ev->active = 1;

    return S3_OK;
}

static s3_int_t
s3_epoll_del_event(s3_event_t *ev, s3_int_t event, s3_uint_t flags)
{
    int                op;
    uint32_t           prev;
    s3_event_t        *e;
    s3_connection_t   *c;
    struct epoll_event ee;

    /*
     * when the file descriptor is closed, epoll automatically deletes
     * it from its queue, so we do not need to delete explicitly the
     * event before the closing the file descriptor
     */

    if (flags & S3_CLOSE_EVENT) {
        ev->active = 0;
        return S3_OK;
    }

    c = (s3_connection_t *)ev->data;

    if (event == S3_READ_EVENT) {
        e = c->write;
        prev = EPOLLOUT;

    } else {
        e = c->read;
        prev = EPOLLIN | EPOLLRDHUP;
    }

    if (e->active) {
        op = EPOLL_CTL_MOD;
        ee.events = prev | (uint32_t)flags;
        ee.data.ptr = (void *)((uintptr_t)c | ev->instance);

    } else {
        op = EPOLL_CTL_DEL;
        ee.events = 0;
        ee.data.ptr = NULL;
    }

    s3_log_debug3(S3_LOG_DEBUG_EVENT, ev->log, 0, "epoll del event: fd:%d op:%d ev:%uD", c->fd, op,
                  ee.events);

    if (epoll_ctl(s3_ep, op, c->fd, &ee) == -1) {
        s3_log_error(S3_LOG_ALERT, ev->log, s3_errno, "epoll_ctl(%d, %d) failed", op, c->fd);
        return S3_ERROR;
    }

    ev->active = 0;

    return S3_OK;
}

static s3_int_t
s3_epoll_add_connection(s3_event_ctx_t *ctx, s3_connection_t *c)
{
    struct epoll_event ee;

    (void)ctx;

    ee.events = EPOLLIN | EPOLLOUT | EPOLLET | EPOLLRDHUP;
    ee.data.ptr = (void *)((uintptr_t)c | c->read->instance);

    s3_log_debug2(S3_LOG_DEBUG_EVENT, c->log, 0, "epoll add connection: fd:%d ev:%uD", c->fd,
                  ee.events);

    if (epoll_ctl(s3_ep, EPOLL_CTL_ADD, c->fd, &ee) == -1) {
        s3_log_error(S3_LOG_ALERT, c->log, s3_errno, "epoll_ctl(EPOLL_CTL_ADD, %d) failed", c->fd);
        return S3_ERROR;
    }

    c->read->active = 1;
    c->write->active = 1;

    return S3_OK;
}

static s3_int_t
s3_epoll_del_connection(s3_event_ctx_t *ctx, s3_connection_t *c)
{
    struct epoll_event ee;

    (void)ctx;

    s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "epoll del connection: fd:%d", c->fd);

    ee.events = 0;
    ee.data.ptr = NULL;

    if (epoll_ctl(s3_ep, EPOLL_CTL_DEL, c->fd, &ee) == -1) {
        s3_log_error(S3_LOG_ALERT, c->log, s3_errno, "epoll_ctl(%d, %d) failed", EPOLL_CTL_DEL,
                     c->fd);
        return S3_ERROR;
    }

    c->read->active = 0;
    c->write->active = 0;

    return S3_OK;
}

static s3_int_t
s3_epoll_process_events(s3_event_ctx_t *ctx, s3_msec_t timer, s3_uint_t flags)
{
    int              events;
    uint32_t         revents;
    s3_int_t         instance, i;
    s3_err_t         err;
    s3_event_t      *rev, *wev;
    s3_queue_t      *queue;
    s3_connection_t *c;

    /* S3_TIMER_INFINITE == -1 */

    events = epoll_wait(s3_ep, s3_event_list, (int)S3_EPOLL_EVENTS, (int)timer);

    err = (events == -1) ? s3_errno : 0;

    if (flags & S3_UPDATE_TIME) {
        s3_time_update();
    }

    if (err) {
        if (err == S3_EINTR) {
            s3_log_error(S3_LOG_INFO, ctx->log, err, "epoll_wait() failed");
        } else {
            s3_log_error(S3_LOG_ALERT, ctx->log, err, "epoll_wait() failed");
        }

        return S3_ERROR;
    }

    if (events == 0) {
        if (timer != S3_TIMER_INFINITE) {
            return S3_OK;
        }

        s3_log_error(S3_LOG_ALERT, ctx->log, 0, "epoll_wait() returned no events without timeout");

        return S3_ERROR;
    }

    for (i = 0; i < events; i++) {
        c = (s3_connection_t *)s3_event_list[i].data.ptr;

        instance = (s3_int_t)((uintptr_t)c & 1);
        c = (s3_connection_t *)((uintptr_t)c & (uintptr_t)~1);

        rev = c->read;

        if (c->fd == -1 || rev->instance != instance) {

            /*
             * the stale event from a file descriptor
             * that was just closed in this iteration
             */

            s3_log_debug1(S3_LOG_DEBUG_EVENT, ctx->log, 0, "epoll: stale event %p", (void *)c);
            continue;
        }

        revents = s3_event_list[i].events;

        s3_log_debug3(S3_LOG_DEBUG_EVENT, ctx->log, 0, "epoll: fd:%d ev:%04XD d:%p", c->fd, revents,
                      s3_event_list[i].data.ptr);

        if (revents & (EPOLLERR | EPOLLHUP)) {
            s3_log_debug2(S3_LOG_DEBUG_EVENT, ctx->log, 0, "epoll_wait() error on fd:%d ev:%04XD",
                          c->fd, revents);

            /*
             * if the error events were returned, add EPOLLIN and EPOLLOUT
             * to handle the events at least in one active handler
             */

            revents |= EPOLLIN | EPOLLOUT;
        }

        if ((revents & EPOLLIN) && rev->active) {

            if (revents & EPOLLRDHUP) {
                rev->pending_eof = 1;
            }

            rev->ready = 1;

            if (flags & S3_POST_EVENTS) {
                queue = &ctx->posted_events;

                s3_post_event(rev, queue);

            } else {
                rev->handler(rev);
            }
        }

        wev = c->write;

        if ((revents & EPOLLOUT) && wev->active) {

            if (c->fd == -1 || wev->instance != instance) {

                /*
                 * the stale event from a file descriptor
                 * that was just closed in this iteration
                 */

                s3_log_debug1(S3_LOG_DEBUG_EVENT, ctx->log, 0, "epoll: stale event %p", (void *)c);
                continue;
            }

            wev->ready = 1;

            if (flags & S3_POST_EVENTS) {
                s3_post_event(wev, &ctx->posted_events);

            } else {
                wev->handler(wev);
            }
        }
    }

    return S3_OK;
}
