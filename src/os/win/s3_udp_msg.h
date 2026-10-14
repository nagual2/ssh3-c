/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_UDP_MSG_H_INCLUDED_
#define _S3_UDP_MSG_H_INCLUDED_

#include <winsock2.h>
#include <ws2tcpip.h>

#include <s3_base.h>

/*
 * the win32 mirror of the POSIX msghdr/iovec the udp event path uses;
 * there is no recvmsg() on Windows, s3_udp_recvmsg() is a WSARecvFrom
 * shim; the control data (the local address cmsg) is not supported on
 * the win bootstrap (S3_HAVE_ADDRINFO_CMSG is off)
 */

struct iovec {
    void  *iov_base;
    size_t iov_len;
};

typedef struct iovec s3_udp_iov_t;

typedef struct s3_udp_msg_s {
    void         *msg_name;
    socklen_t     msg_namelen;
    struct iovec *msg_iov;
    size_t        msg_iovlen;
} s3_udp_msg_t;

ssize_t s3_udp_recvmsg(s3_fd_t fd, s3_udp_msg_t *msg);

#if (S3_USE_IOCP)

/*
 * the overlapped arm of the receive shim for the iocp backend: the
 * s3_event_recvmsg() seam posts the receive and consumes the completed
 * one through it, the event carries the completion state (s3_event.h);
 * the holder is the per-listener receive storage of s3_udp_listen_t
 * (s3_udp_recv_t: the datagram buffer and the from address the kernel
 * writes at completion time), one process-wide holder would cross the
 * listeners
 */
typedef struct s3_event_s s3_event_t;
struct s3_udp_recv_s;

ssize_t s3_udp_recvmsg_o(s3_fd_t fd, s3_udp_msg_t *msg, s3_event_t *ev,
                         struct s3_udp_recv_s *holder);

#endif

#endif /* _S3_UDP_MSG_H_INCLUDED_ */
