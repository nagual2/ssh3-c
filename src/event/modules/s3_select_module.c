/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <s3_core.h>

#include <s3_socket.h>

/*
 * the win32 select event module, the mirror of the unix epoll module
 * over the ngx_win32_select_module(): level-triggered, the interest
 * sets are process globals owned by one context by construction
 *
 * Winsock select() is capped by FD_SETSIZE (64 by default), the
 * client does not come close; a many-connection path needs the IOCP
 * backend (S3_USE_IOCP, P9 backlog)
 */

#define S3_SELECT_INVALID_INDEX ((s3_uint_t) - 1)

/* the wait without descriptors: the win32 signal-cap convention */
#define S3_SELECT_IDLE_SLEEP 500

static s3_int_t s3_select_init(s3_event_ctx_t *ctx);
static void     s3_select_done(s3_event_ctx_t *ctx);
static s3_int_t s3_select_add_event(s3_event_t *ev, s3_int_t event, s3_uint_t flags);
static s3_int_t s3_select_del_event(s3_event_t *ev, s3_int_t event, s3_uint_t flags);
static s3_int_t s3_select_add_connection(s3_event_ctx_t *ctx, s3_connection_t *c);
static s3_int_t s3_select_del_connection(s3_event_ctx_t *ctx, s3_connection_t *c);
static s3_int_t s3_select_process_events(s3_event_ctx_t *ctx, s3_msec_t timer, s3_uint_t flags);
static void     s3_select_repair_fd_sets(s3_event_ctx_t *ctx);
static s3_int_t s3_select_grow_index(s3_log_t *log);

static fd_set master_read_fd_set;
static fd_set master_write_fd_set;
static fd_set work_read_fd_set;
static fd_set work_write_fd_set;
static fd_set work_except_fd_set;

static s3_uint_t max_read;
static s3_uint_t max_write;
static s3_uint_t nevents;
static s3_uint_t events_alloc;

static s3_event_t **event_index;

s3_event_actions_t s3_event_actions = {
    s3_select_init,           s3_select_add_event,      s3_select_del_event,
    s3_select_add_connection, s3_select_del_connection, s3_select_process_events,
    s3_select_done,
};

static s3_int_t
s3_select_grow_index(s3_log_t *log)
{
    s3_uint_t    nalloc;
    s3_event_t **index;

    /* the log argument matches the s3_alloc() contract, unused there */

    (void)log;

    if (nevents < events_alloc) {
        return S3_OK;
    }

    nalloc = (events_alloc == 0) ? 512 : events_alloc * 2;

    index = (s3_event_t **)s3_alloc(sizeof(s3_event_t *) * nalloc, log);
    if (index == NULL) {
        return S3_ERROR;
    }

    if (event_index != NULL) {
        s3_memcpy(index, event_index, sizeof(s3_event_t *) * nevents);
        s3_free(event_index);
    }

    event_index = index;
    events_alloc = nalloc;

    return S3_OK;
}

static s3_int_t
s3_select_init(s3_event_ctx_t *ctx)
{
    if (event_index == NULL) {
        FD_ZERO(&master_read_fd_set);
        FD_ZERO(&master_write_fd_set);
        nevents = 0;
    }

    /*
     * the descriptors wait through the ctx pool lifetime, the index
     * grows on demand and outlives the pool in the process globals
     * (the epoll module keeps its descriptor the same way)
     */

    if (s3_select_grow_index(ctx->log) != S3_OK) {
        return S3_ERROR;
    }

    s3_event_flags = 0;

    ctx->impl = NULL;

    return S3_OK;
}

/*
 * the exit counterpart of init(): the interest sets and the index
 * are process globals here, one context owns them by construction
 * (the second ctx_init() reuses them); nothing may poll select()
 * after the call
 */

static void
s3_select_done(s3_event_ctx_t *ctx)
{
    (void)ctx;

    if (event_index != NULL) {
        s3_free(event_index);
        event_index = NULL;
        events_alloc = 0;
    }

    nevents = 0;
    max_read = 0;
    max_write = 0;

    FD_ZERO(&master_read_fd_set);
    FD_ZERO(&master_write_fd_set);
}

static s3_int_t
s3_select_add_event(s3_event_t *ev, s3_int_t event, s3_uint_t flags)
{
    s3_connection_t *c;

    (void)flags;

    c = (s3_connection_t *)ev->data;

    if ((event == S3_READ_EVENT && ev->write) || (event == S3_WRITE_EVENT && !ev->write)) {
        s3_log_error(S3_LOG_ALERT, ev->log, 0, "invalid select %s event fd:%d",
                     ev->write ? "write" : "read", c->fd);
        return S3_ERROR;
    }

    if ((event == S3_READ_EVENT && max_read >= FD_SETSIZE) ||
        (event == S3_WRITE_EVENT && max_write >= FD_SETSIZE)) {
        s3_log_error(S3_LOG_ERR, ev->log, 0,
                     "maximum number of descriptors "
                     "supported by select() is %d",
                     FD_SETSIZE);
        return S3_ERROR;
    }

    if (event == S3_READ_EVENT) {
        FD_SET((SOCKET)c->fd, &master_read_fd_set);
        max_read++;

    } else {
        FD_SET((SOCKET)c->fd, &master_write_fd_set);
        max_write++;
    }

    ev->active = 1;

    if (s3_select_grow_index(ev->log) != S3_OK) {
        return S3_ERROR;
    }

    event_index[nevents++] = ev;

    return S3_OK;
}

static s3_int_t
s3_select_del_event(s3_event_t *ev, s3_int_t event, s3_uint_t flags)
{
    s3_uint_t        i;
    s3_connection_t *c;

    c = (s3_connection_t *)ev->data;

    /*
     * level-triggered sets: the interest is dropped here, there is no
     * S3_CLOSE_EVENT shortcut like epoll's -- an already closed
     * descriptor is repaired by repair_fd_sets()
     */

    (void)flags;

    if ((event == S3_READ_EVENT && max_read > 0)) {
        FD_CLR((SOCKET)c->fd, &master_read_fd_set);
        max_read--;

    } else if (event == S3_WRITE_EVENT && max_write > 0) {
        FD_CLR((SOCKET)c->fd, &master_write_fd_set);
        max_write--;
    }

    ev->active = 0;

    for (i = 0; i < nevents; i++) {

        if (event_index[i] != ev) {
            continue;
        }

        /* the swap remove, the epoll module keeps no index at all */

        nevents--;
        event_index[i] = event_index[nevents];

        return S3_OK;
    }

    return S3_OK;
}

static s3_int_t
s3_select_add_connection(s3_event_ctx_t *ctx, s3_connection_t *c)
{
    (void)ctx;

    FD_SET((SOCKET)c->fd, &master_read_fd_set);
    FD_SET((SOCKET)c->fd, &master_write_fd_set);

    max_read++;
    max_write++;

    c->read->active = 1;
    c->write->active = 1;

    if (s3_select_grow_index(c->log) != S3_OK) {
        return S3_ERROR;
    }

    event_index[nevents++] = c->read;
    event_index[nevents++] = c->write;

    return S3_OK;
}

static s3_int_t
s3_select_del_connection(s3_event_ctx_t *ctx, s3_connection_t *c)
{
    s3_uint_t i, left;

    (void)ctx;

    FD_CLR((SOCKET)c->fd, &master_read_fd_set);
    FD_CLR((SOCKET)c->fd, &master_write_fd_set);

    if (max_read > 0) {
        max_read--;
    }

    if (max_write > 0) {
        max_write--;
    }

    /* the swap remove of both connection events */

    left = nevents;
    i = 0;

    while (i < left) {

        if (event_index[i] != c->read && event_index[i] != c->write) {
            i++;
            continue;
        }

        left--;
        event_index[i] = event_index[left];
    }

    nevents = left;

    c->read->active = 0;
    c->write->active = 0;

    return S3_OK;
}

static void
s3_select_repair_fd_sets(s3_event_ctx_t *ctx)
{
    u_int          i;
    socklen_t      len;
    int            n;
    s3_err_t       err;
    s3_socket_t    s;
    struct fd_set *sets[2];
    s3_uint_t      k;

    sets[0] = &master_read_fd_set;
    sets[1] = &master_write_fd_set;

    for (k = 0; k < 2; k++) {

        for (i = 0; i < sets[k]->fd_count; i++) {

            s = sets[k]->fd_array[i];
            len = sizeof(int);

            if (getsockopt(s, SOL_SOCKET, SO_TYPE, (char *)&n, &len) == SOCKET_ERROR) {
                err = s3_socket_errno;

                s3_log_error(S3_LOG_ALERT, ctx->log, err, "invalid descriptor #%ud in fd_set",
                             (s3_uint_t)i);

                FD_CLR(s, sets[k]);
            }
        }
    }
}

static s3_int_t
s3_select_process_events(s3_event_ctx_t *ctx, s3_msec_t timer, s3_uint_t flags)
{
    int              ready, nready;
    s3_err_t         err;
    s3_uint_t        i, found;
    s3_event_t      *ev;
    s3_queue_t      *queue;
    struct timeval   tv, *tp;
    s3_connection_t *c;

    if (timer == S3_TIMER_INFINITE) {
        tp = NULL;

    } else {
        tv.tv_sec = (long)(timer / 1000);
        tv.tv_usec = (long)((timer % 1000) * 1000);
        tp = &tv;
    }

    work_read_fd_set = master_read_fd_set;
    work_write_fd_set = master_write_fd_set;
    work_except_fd_set = master_write_fd_set;

    if (max_read || max_write) {
        ready = select(0, &work_read_fd_set, &work_write_fd_set, &work_except_fd_set, tp);

    } else {

        /*
         * Winsock select() requires that at least one descriptor set
         * must be non-null, and any non-null descriptor set must
         * contain at least one handle to a socket; otherwise select()
         * returns WSAEINVAL -- the timers are waited out with a sleep
         * capped at the idle slice
         */

        Sleep((DWORD)((timer == S3_TIMER_INFINITE) ? S3_SELECT_IDLE_SLEEP : timer));

        ready = 0;
    }

    err = (ready == -1) ? s3_socket_errno : 0;

    if (flags & S3_UPDATE_TIME) {
        s3_time_update();
    }

    if (err) {

        if (err == S3_EINTR) {
            s3_log_error(S3_LOG_INFO, ctx->log, err, "select() failed");

        } else {
            s3_log_error(S3_LOG_ALERT, ctx->log, err, "select() failed");
        }

        if (err == WSAENOTSOCK) {
            s3_select_repair_fd_sets(ctx);
        }

        return S3_ERROR;
    }

    if (ready == 0) {
        if (timer != S3_TIMER_INFINITE) {
            return S3_OK;
        }

        s3_log_error(S3_LOG_ALERT, ctx->log, 0, "select() returned no events without timeout");

        return S3_ERROR;
    }

    nready = 0;

    for (i = 0; i < nevents; i++) {

        ev = event_index[i];
        c = (s3_connection_t *)ev->data;

        if (c->fd == (s3_fd_t)-1) {

            /* the connection was closed in an earlier handler */

            continue;
        }

        found = 0;

        if (ev->write) {
            if (FD_ISSET((SOCKET)c->fd, &work_write_fd_set)) {
                found++;
            }

            if (FD_ISSET((SOCKET)c->fd, &work_except_fd_set)) {
                found++;
            }

        } else {
            if (FD_ISSET((SOCKET)c->fd, &work_read_fd_set)) {
                found++;
            }
        }

        if (found) {
            ev->ready = 1;

            queue = &ctx->posted_events;

            s3_post_event(ev, queue);

            nready += found;
        }
    }

    if (ready != nready) {
        s3_log_error(S3_LOG_ALERT, ctx->log, 0, "select ready != events: %d:%d", ready, nready);

        s3_select_repair_fd_sets(ctx);
    }

    return S3_OK;
}
