/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <s3_core.h>

#include <s3_udp_recv.h>

ssize_t
s3_udp_recv(s3_connection_t *c, u_char *buf, size_t size)
{
    ssize_t     n;
    s3_err_t    err;
    s3_event_t *rev;

    rev = c->read;

    do {
        n = recv((SOCKET)c->fd, (char *)buf, (int)size, 0);

        s3_log_debug3(S3_LOG_DEBUG_EVENT, c->log, 0, "recv: fd:%d %z of %uz", c->fd, n, size);

        if (n >= 0) {
            return n;
        }

        err = s3_socket_errno;

        if (err == S3_EAGAIN || err == S3_EINTR) {
            s3_log_debug0(S3_LOG_DEBUG_EVENT, c->log, err, "recv() not ready");
            n = (ssize_t)S3_AGAIN;

        } else {
            rev->error = 1;
            rev->ready = 0;
            s3_log_error(S3_LOG_ERR, c->log, err, "recv() failed");

            return (ssize_t)S3_ERROR;
        }

    } while (err == S3_EINTR);

    rev->ready = 0;

    return n;
}
