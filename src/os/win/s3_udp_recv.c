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

#if (S3_USE_IOCP)

/*
 * the iocp cycle of the dial socket (the reference
 * ngx_udp_overlapped_wsarecv): the read handler runs by a
 * completion, c->recv consumes the completed datagram and the next
 * call arms the following receive; the add_event kick (a completion
 * with no bytes) arms the first one.  the inline completion still
 * returns S3_AGAIN: the socket is bound to the port, the status is
 * delivered through it.  the sends stay synchronous under both
 * backends, the overlapped path is receive-only.
 *
 * the receive is armed into the event carrier buffer, not into the
 * caller buffer: the completion writes it long after the call and the
 * caller buffers are shared statics, another connection handler would
 * overwrite a datagram in flight (the reference posts into the
 * per-connection c->buffer, the s3 recv contract has no buffer arg)
 */

/* the maximum udp datagram size, the armed receive always reads it all */
#define S3_UDP_RECV_O_SIZE 65535

    if (rev->complete) {
        rev->complete = 0;

        if (rev->ovlp.error != 0) {
            rev->error = 1;
            rev->ready = 0;

            s3_log_error(S3_LOG_ERR, c->log, rev->ovlp.error, "WSARecv() failed");

            return (ssize_t)S3_ERROR;
        }

        if (rev->available > 0) {
            n = (ssize_t)s3_min((size_t)rev->available, size);

            s3_memcpy(buf, rev->ovlp.data, (size_t)n);

            s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "WSARecv ovlp: %z", n);

            return n;
        }

        /* the kick: no datagram yet, arm the receive below */
    }

    if (!rev->ready) {
        s3_log_error(S3_LOG_ALERT, c->log, 0, "second wsa post");

        return (ssize_t)S3_AGAIN;
    }

    if (rev->ovlp.data == NULL) {

        if (c->pool == NULL) {
            rev->error = 1;

            s3_log_error(S3_LOG_ALERT, c->log, 0, "no pool for the overlapped receive");

            return (ssize_t)S3_ERROR;
        }

        rev->ovlp.data = (u_char *)s3_palloc(c->pool, S3_UDP_RECV_O_SIZE);

        if (rev->ovlp.data == NULL) {
            rev->error = 1;

            return (ssize_t)S3_ERROR;
        }
    }

    s3_memzero(&rev->ovlp.ovlp, sizeof(WSAOVERLAPPED));
    rev->ovlp.event = rev;
    rev->ovlp.error = 0;

    {
        DWORD  bytes, flags;
        WSABUF wbuf;
        int    rc;

        wbuf.buf = (char *)rev->ovlp.data;
        wbuf.len = S3_UDP_RECV_O_SIZE;

        bytes = 0;
        flags = 0;

        rc = WSARecv((SOCKET)c->fd, &wbuf, 1, &bytes, &flags, &rev->ovlp.ovlp, NULL);

        if (rc != 0) {
            err = (s3_err_t)WSAGetLastError();

            if (err == WSA_IO_PENDING) {
                rev->active = 1;

                s3_log_debug0(S3_LOG_DEBUG_EVENT, c->log, err, "WSARecv() posted");

                return (ssize_t)S3_AGAIN;
            }

            rev->error = 1;
            rev->ready = 0;

            s3_log_error(S3_LOG_ERR, c->log, err, "WSARecv() failed");

            return (ssize_t)S3_ERROR;
        }

        rev->active = 1;

        return (ssize_t)S3_AGAIN;
    }

#else

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

#endif
}
