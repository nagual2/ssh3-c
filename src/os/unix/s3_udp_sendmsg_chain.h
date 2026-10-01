/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_UDP_SENDMSG_CHAIN_H_INCLUDED_
#define _S3_UDP_SENDMSG_CHAIN_H_INCLUDED_

#include <sys/socket.h>
#include <sys/uio.h>

#include <s3_base.h>
#include <s3_connection.h>
#include <s3_palloc.h>

#define S3_IOVS_PREALLOCATE 16

#define S3_MAX_SIZE_T_VALUE ((size_t) - 1)

typedef struct {
    struct iovec *iovs;
    s3_uint_t     count;
    size_t        size;
    s3_uint_t     nalloc;
} s3_iovec_t;

s3_chain_t *s3_udp_sendmsg_chain(s3_connection_t *c, s3_chain_t *in, off_t limit);

ssize_t s3_sendmsg(s3_connection_t *c, struct msghdr *msg, int flags);

#endif /* _S3_UDP_SENDMSG_CHAIN_H_INCLUDED_ */
