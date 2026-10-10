/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_UDP_MSG_H_INCLUDED_
#define _S3_UDP_MSG_H_INCLUDED_

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/uio.h>

/*
 * the POSIX names stay as they are; the win32 mirror defines its own
 * s3_udp_msg_t/s3_udp_iov_t and a WSARecvFrom shim behind the same
 * names, the udp event path is written against these
 */

typedef struct iovec  s3_udp_iov_t;
typedef struct msghdr s3_udp_msg_t;

#define s3_udp_recvmsg(fd, msg) recvmsg(fd, msg, 0)

#endif /* _S3_UDP_MSG_H_INCLUDED_ */
