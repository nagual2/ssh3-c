/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_CONNECTION_H_INCLUDED_
#define _S3_CONNECTION_H_INCLUDED_

#include <sys/socket.h>

#include <s3_base.h>
#include <s3_event.h>

typedef ssize_t (*s3_recv_pt)(s3_connection_t *c, u_char *buf, size_t size);

typedef s3_chain_t *(*s3_send_chain_pt)(s3_connection_t *c, s3_chain_t *in, off_t limit);

struct s3_connection_s {
    void       *data;
    s3_event_t *read;
    s3_event_t *write;

    s3_fd_t fd;

    /* the polymorphic I/O methods, set by the protocol layer */
    s3_recv_pt       recv;
    s3_send_chain_pt send_chain;

    off_t sent;

    s3_log_t *log;

    s3_pool_t *pool;

    struct sockaddr *sockaddr;
    socklen_t        socklen;

    struct sockaddr *local_sockaddr;
    socklen_t        local_socklen;

    /* the udp pseudo connection for shared listening sockets */
    struct s3_udp_connection_s *udp;

    /* the socket is shared between connections (a udp listening socket) */
    unsigned shared : 1;
};

s3_connection_t *s3_get_connection(s3_event_ctx_t *ctx, s3_fd_t fd);
void             s3_close_connection(s3_connection_t *c);

#endif /* _S3_CONNECTION_H_INCLUDED_ */
