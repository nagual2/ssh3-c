/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_CMSG_H_INCLUDED_
#define _S3_CMSG_H_INCLUDED_

#include <sys/socket.h>
#include <netinet/in.h>

#include <s3_base.h>

/*
 * the local address ancillary data of the reference
 * (NGX_HAVE_ADDRINFO_CMSG); the CMake build defines the macro when
 * IP_PKTINFO/IPV6_RECVPKTINFO are available (porting map 4.5.11)
 */
#if (S3_HAVE_ADDRINFO_CMSG)

typedef struct {
    struct in_pktinfo pktinfo;
#if defined(IPV6_RECVPKTINFO)
    struct in6_pktinfo pktinfo6;
#endif
} s3_addrinfo_t;

/*
 * reads the received packet local address into sockaddr and returns
 * the consumed control data size (0 when the cmsg is a different one)
 */
size_t s3_get_srcaddr_cmsg(struct cmsghdr *cmsg, struct sockaddr *sockaddr);

/*
 * writes sockaddr into the control data and returns the size to add
 * to msg_controllen (0 when the address family is not supported)
 */
size_t s3_set_srcaddr_cmsg(struct cmsghdr *cmsg, struct sockaddr *sockaddr);

#endif /* S3_HAVE_ADDRINFO_CMSG */

#endif /* _S3_CMSG_H_INCLUDED_ */
