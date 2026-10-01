/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_UDP_RECV_H_INCLUDED_
#define _S3_UDP_RECV_H_INCLUDED_

#include <s3_base.h>
#include <s3_connection.h>

ssize_t s3_udp_recv(s3_connection_t *c, u_char *buf, size_t size);

#endif /* _S3_UDP_RECV_H_INCLUDED_ */
