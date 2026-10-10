/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_ERRNO_H_INCLUDED_
#define _S3_ERRNO_H_INCLUDED_

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <windows.h>

#include <s3_base.h>

/*
 * the win32 mirror of the unix s3_errno.h: the POSIX-named codes are
 * compile-time mappings, the code above the os layer stays
 * platform-independent
 */

#define S3_EPERM        ERROR_ACCESS_DENIED
#define S3_ENOENT       ERROR_FILE_NOT_FOUND
#define S3_ENOPATH      ERROR_PATH_NOT_FOUND
#define S3_ESRCH        ERROR_NOT_FOUND
#define S3_EINTR        WSAEINTR
#define S3_ECHILD       ERROR_NOT_FOUND
#define S3_ENOMEM       ERROR_NOT_ENOUGH_MEMORY
#define S3_EACCES       ERROR_ACCESS_DENIED
#define S3_EBUSY        ERROR_BUSY
#define S3_EEXIST       ERROR_ALREADY_EXISTS
#define S3_EXDEV        ERROR_NOT_SAME_DEVICE
#define S3_ENOTDIR      ERROR_PATH_NOT_FOUND
#define S3_EISDIR       ERROR_CANNOT_MAKE
#define S3_EINVAL       WSAEINVAL
#define S3_ENFILE       WSAEMFILE
#define S3_EMFILE       WSAEMFILE
#define S3_ENOSPC       ERROR_DISK_FULL
#define S3_EPIPE        ERROR_BROKEN_PIPE
#define S3_EINPROGRESS  WSAEINPROGRESS
#define S3_ENOPROTOOPT  WSAENOPROTOOPT
#define S3_EOPNOTSUPP   WSAEOPNOTSUPP
#define S3_EADDRINUSE   WSAEADDRINUSE
#define S3_ECONNABORTED WSAECONNABORTED
#define S3_ECONNRESET   WSAECONNRESET
#define S3_ENOTCONN     WSAENOTCONN
#define S3_ETIMEDOUT    WSAETIMEDOUT
#define S3_ECONNREFUSED WSAECONNREFUSED
#define S3_ENAMETOOLONG ERROR_BAD_PATHNAME
#define S3_ENETDOWN     WSAENETDOWN
#define S3_ENETUNREACH  WSAENETUNREACH
#define S3_EHOSTUNREACH WSAEHOSTUNREACH
#define S3_ENOSYS       ERROR_NOT_SUPPORTED
#define S3_ECANCELED    ERROR_OPERATION_ABORTED
#define S3_ELOOP        0
#define S3_EBADF        WSAEBADF
#define S3_EMSGSIZE     WSAEMSGSIZE

#define S3_EAGAIN WSAEWOULDBLOCK

#define s3_errno                 GetLastError()
#define s3_socket_errno          WSAGetLastError()
#define s3_set_errno(err)        SetLastError(err)
#define s3_set_socket_errno(err) WSASetLastError(err)

u_char *s3_strerror(s3_err_t err, u_char *errbuf, size_t len);

#endif /* _S3_ERRNO_H_INCLUDED_ */
