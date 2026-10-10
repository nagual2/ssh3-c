/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <winsock2.h>

#include <s3_base.h>
#include <s3_nonblocking.h>

/*
 * the win32 variant of the unix s3_nonblocking(): FIONBIO is the only
 * mode switch WinSock has; the drain-to-EAGAIN contract of the event
 * loop (see the unix variant) applies verbatim
 *
 * the caller logs the failure: this is called before the log
 * destination of a connection exists, and from tests that have none
 */

s3_int_t
s3_nonblocking(s3_fd_t fd)
{
    u_long flags;

    flags = 1;

    return (ioctlsocket((SOCKET)fd, FIONBIO, &flags) != 0) ? S3_ERROR : S3_OK;
}
