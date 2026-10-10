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
