/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <s3_core.h>

#include <s3_udp_msg.h>

ssize_t
s3_udp_recvmsg(s3_fd_t fd, s3_udp_msg_t *msg)
{
    WSABUF  wbuf;
    DWORD   bytes, flags;
    ssize_t n;
    int     rc;

    if (msg->msg_iovlen != 1) {
        WSASetLastError(WSAEINVAL);
        return (ssize_t)-1;
    }

    wbuf.buf = (char *)msg->msg_iov[0].iov_base;
    wbuf.len = (ULONG)msg->msg_iov[0].iov_len;

    bytes = 0;
    flags = 0;

    rc = WSARecvFrom((SOCKET)fd, &wbuf, 1, &bytes, &flags, (struct sockaddr *)msg->msg_name,
                     (int *)&msg->msg_namelen, NULL, NULL);

    if (rc != 0) {
        /* the caller reads s3_socket_errno, the recvmsg() contract */
        return (ssize_t)-1;
    }

    n = (ssize_t)bytes;

    s3_log_debug1(S3_LOG_DEBUG_EVENT, &s3_stderr_log, 0, "WSARecvFrom: %uz", n);

    return n;
}

#if (S3_USE_IOCP)

/*
 * the overlapped arm of the receive shim, the iocp path of the
 * s3_event_recvmsg() seam (the reference ngx_udp_overlapped_wsarecv):
 *
 *   !ev->complete -- the receive is posted into msg->msg_iov[0] and
 *   S3_AGAIN is returned, the completion re-enters the seam with
 *   ev->complete set by the iocp module;
 *
 *   ev->complete  -- the datagram is already in msg->msg_iov[0] (the
 *   static post buffer), ev->available holds the byte count and the
 *   from address is copied out of the post holder;
 *
 * an inline completion still returns S3_AGAIN: the socket is bound to
 * the completion port, the status is delivered through it anyway
 * (the reference comment on the WSARecv() inline case).
 *
 * the kernel writes the from address at completion time, so the post
 * holder must outlive the completion; the event loop is single
 * threaded and one post is in flight across the process (the static
 * datagram buffer of s3_event_recvmsg() is shared the same way), the
 * module static holder mirrors that lifetime.  a multi-listener iocp
 * path needs per-event holders, it is not in scope here.
 *
 * the second post of an in-flight receive cannot happen: the seam only
 * posts from a handler entry without a completion or after a consumed
 * one, and the handler is entered by a completion of exactly the one
 * post in flight.
 */

ssize_t
s3_udp_recvmsg_o(s3_fd_t fd, s3_udp_msg_t *msg, s3_event_t *ev)
{
    static struct sockaddr_storage from;
    static INT                     from_len;

    int     rc;
    DWORD   bytes, flags;
    WSABUF  wbuf;
    ssize_t n;

    if (msg->msg_iovlen != 1) {
        WSASetLastError(WSAEINVAL);
        return (ssize_t)-1;
    }

    if (ev->complete) {
        ev->complete = 0;

        if (ev->ovlp.error != 0) {
            return (ssize_t)-1;
        }

        if (msg->msg_name != NULL) {
            size_t len;

            len = (size_t)from_len;

            if (len > sizeof(struct sockaddr_storage)) {
                len = sizeof(struct sockaddr_storage);
            }

            s3_memcpy(msg->msg_name, &from, len);
        }

        msg->msg_namelen = (socklen_t)from_len;

        n = ev->available;

        s3_log_debug1(S3_LOG_DEBUG_EVENT, ev->log, 0, "WSARecvFrom ovlp: %uz", n);

        return n;
    }

    s3_memzero(&ev->ovlp.ovlp, sizeof(WSAOVERLAPPED));
    ev->ovlp.event = ev;
    ev->ovlp.error = 0;

    wbuf.buf = (char *)msg->msg_iov[0].iov_base;
    wbuf.len = (ULONG)msg->msg_iov[0].iov_len;

    /*
     * the capacity, the kernel writes the actual length back; the
     * msg_namelen of the caller is an in-out field already polluted by
     * a consume, the capacity is always the full holder
     */
    from_len = (INT)sizeof(struct sockaddr_storage);

    bytes = 0;
    flags = 0;

    rc = WSARecvFrom((SOCKET)fd, &wbuf, 1, &bytes, &flags, (struct sockaddr *)&from, &from_len,
                     &ev->ovlp.ovlp, NULL);

    if (rc != 0) {
        int err;

        err = WSAGetLastError();

        if (err == WSA_IO_PENDING) {
            ev->active = 1;

            s3_log_debug0(S3_LOG_DEBUG_EVENT, ev->log, (s3_err_t)err, "WSARecvFrom() posted");

            return (ssize_t)S3_AGAIN;
        }

        s3_log_error(S3_LOG_ALERT, ev->log, (s3_err_t)err, "WSARecvFrom() failed");

        WSASetLastError(err);

        return (ssize_t)-1;
    }

    /*
     * if a socket was bound with the completion port then
     * GetQueuedCompletionStatus() would anyway return its status
     * despite that WSARecvFrom() was already complete
     */

    ev->active = 1;

    return (ssize_t)S3_AGAIN;
}

#endif /* S3_USE_IOCP */
