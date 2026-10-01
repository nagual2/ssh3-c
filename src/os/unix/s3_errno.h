/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_ERRNO_H_INCLUDED_
#define _S3_ERRNO_H_INCLUDED_

#include <errno.h>

#include <s3_base.h>

#define S3_EPERM        EPERM
#define S3_ENOENT       ENOENT
#define S3_ENOPATH      ENOENT
#define S3_ESRCH        ESRCH
#define S3_EINTR        EINTR
#define S3_ECHILD       ECHILD
#define S3_ENOMEM       ENOMEM
#define S3_EACCES       EACCES
#define S3_EBUSY        EBUSY
#define S3_EEXIST       EEXIST
#define S3_EXDEV        EXDEV
#define S3_ENOTDIR      ENOTDIR
#define S3_EISDIR       EISDIR
#define S3_EINVAL       EINVAL
#define S3_ENFILE       ENFILE
#define S3_EMFILE       EMFILE
#define S3_ENOSPC       ENOSPC
#define S3_EPIPE        EPIPE
#define S3_EINPROGRESS  EINPROGRESS
#define S3_ENOPROTOOPT  ENOPROTOOPT
#define S3_EOPNOTSUPP   EOPNOTSUPP
#define S3_EADDRINUSE   EADDRINUSE
#define S3_ECONNABORTED ECONNABORTED
#define S3_ECONNRESET   ECONNRESET
#define S3_ENOTCONN     ENOTCONN
#define S3_ETIMEDOUT    ETIMEDOUT
#define S3_ECONNREFUSED ECONNREFUSED
#define S3_ENAMETOOLONG ENAMETOOLONG
#define S3_ENETDOWN     ENETDOWN
#define S3_ENETUNREACH  ENETUNREACH
#define S3_EHOSTUNREACH EHOSTUNREACH
#define S3_ENOSYS       ENOSYS
#define S3_ECANCELED    ECANCELED
#define S3_ELOOP        ELOOP
#define S3_EBADF        EBADF
#define S3_EMSGSIZE     EMSGSIZE

#define S3_EAGAIN EAGAIN

#define s3_errno                 errno
#define s3_socket_errno          errno
#define s3_set_errno(err)        errno = err
#define s3_set_socket_errno(err) errno = err

/*
 * the XSI variant of strerror_r() (int return) is used, enforced by
 * building without _GNU_SOURCE and with _POSIX_C_SOURCE >= 200112L
 */
u_char *s3_strerror(s3_err_t err, u_char *errbuf, size_t len);

#endif /* _S3_ERRNO_H_INCLUDED_ */
