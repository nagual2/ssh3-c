/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <s3_core.h>

#include <fcntl.h>

#include <s3_nonblocking.h>

/*
 * the non-blocking flag setup of ngx_nonblocking()
 * (src/os/unix/ngx_files.c)
 *
 * every socket the event loop waits on must be non-blocking: a
 * connection is registered with EPOLLET (s3_epoll_add_connection()),
 * and an edge is delivered once per batch of arrivals, so the read
 * handler has to drain the socket down to EAGAIN.  Without the flag
 * the drain blocks in recv() instead, and the queued datagrams stay
 * unread until a retransmit timer happens to fire.
 *
 * the caller logs the failure: this is called before the log
 * destination of a connection exists, and from tests that have none
 */

s3_int_t
s3_nonblocking(s3_fd_t fd)
{
    int flags;

    flags = fcntl(fd, F_GETFL, 0);

    if (flags == -1) {
        return S3_ERROR;
    }

    return (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) ? S3_ERROR : S3_OK;
}