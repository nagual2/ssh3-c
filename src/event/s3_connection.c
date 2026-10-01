/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <s3_core.h>

#include <unistd.h>

s3_connection_t *
s3_get_connection(s3_event_ctx_t *ctx, s3_fd_t fd)
{
    s3_connection_t *c;
    s3_event_t      *rev, *wev;

    c = (s3_connection_t *)s3_pcalloc(ctx->pool, sizeof(s3_connection_t));
    if (c == NULL) {
        return NULL;
    }

    rev = (s3_event_t *)s3_pcalloc(ctx->pool, sizeof(s3_event_t));
    wev = (s3_event_t *)s3_pcalloc(ctx->pool, sizeof(s3_event_t));

    if (rev == NULL || wev == NULL) {
        return NULL;
    }

    /*
     * set by s3_pcalloc():
     *
     *     c->data = NULL;
     *     c->recv = NULL;
     *     c->send_chain = NULL;
     *     c->sent = 0;
     *     c->pool = NULL;
     *     c->sockaddr = NULL;
     *     c->socklen = 0;
     *     c->local_sockaddr = NULL;
     *     c->local_socklen = 0;
     *     c->udp = NULL;
     *     c->shared = 0;
     *     and the event flags
     */

    c->read = rev;
    c->write = wev;
    c->fd = fd;
    c->log = ctx->log;

    rev->data = c;
    wev->data = c;

    rev->instance = 1;
    wev->instance = 1;

    wev->write = 1;

    rev->log = ctx->log;
    wev->log = ctx->log;

    return c;
}

void
s3_close_connection(s3_connection_t *c)
{
    s3_fd_t fd;

    if (c->fd == -1) {
        s3_log_error(S3_LOG_ALERT, c->log, 0, "connection already closed");
        return;
    }

    if (c->read->timer_set) {
        s3_event_del_timer(c->read);
    }

    if (c->write->timer_set) {
        s3_event_del_timer(c->write);
    }

    if (c->read->posted) {
        s3_delete_posted_event(c->read);
    }

    if (c->write->posted) {
        s3_delete_posted_event(c->write);
    }

    c->read->closed = 1;
    c->write->closed = 1;

    c->read->active = 0;
    c->write->active = 0;

    fd = c->fd;
    c->fd = -1;

    /*
     * the kernel drops the descriptor from the event method on close(),
     * an explicit del_connection() is not needed; a shared connection
     * (an udp pseudo connection) must not close the listening socket
     */

    if (!c->shared && close(fd) == -1) {
        s3_log_error(S3_LOG_CRIT, c->log, s3_socket_errno, "close() fd:%d failed", fd);
    }

    if (c->pool != NULL) {
        s3_destroy_pool(c->pool); /* runs the cleanup handlers */
    }
}
