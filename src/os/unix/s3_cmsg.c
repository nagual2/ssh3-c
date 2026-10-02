/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <s3_cmsg.h>

#if (S3_HAVE_ADDRINFO_CMSG)

size_t
s3_get_srcaddr_cmsg(struct cmsghdr *cmsg, struct sockaddr *sockaddr)
{
#if defined(IPV6_RECVPKTINFO)
    struct in6_pktinfo *pktinfo6;
    struct sockaddr_in6 *sin6;
#endif
    struct in_pktinfo   *pktinfo;
    struct sockaddr_in  *sin;

    if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_PKTINFO
        && sockaddr->sa_family == AF_INET)
    {
        pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsg);

        sin = (struct sockaddr_in *)sockaddr;
        sin->sin_addr = pktinfo->ipi_addr;

        return CMSG_SPACE(sizeof(struct in_pktinfo));
    }

#if defined(IPV6_RECVPKTINFO)

    if (cmsg->cmsg_level == SOL_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO
        && sockaddr->sa_family == AF_INET6)
    {
        pktinfo6 = (struct in6_pktinfo *)CMSG_DATA(cmsg);

        sin6 = (struct sockaddr_in6 *)sockaddr;
        sin6->sin6_addr = pktinfo6->ipi6_addr;

        return CMSG_SPACE(sizeof(struct in6_pktinfo));
    }

#endif

    (void)sockaddr;

    return 0;
}

size_t
s3_set_srcaddr_cmsg(struct cmsghdr *cmsg, struct sockaddr *sockaddr)
{
#if defined(IPV6_RECVPKTINFO)
    struct in6_pktinfo   *pktinfo6;
    struct sockaddr_in6  *sin6;
#endif
    struct in_pktinfo    *pktinfo;
    struct sockaddr_in   *sin;

    if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_PKTINFO
        && sockaddr->sa_family == AF_INET)
    {
        sin = (struct sockaddr_in *)sockaddr;

        cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
        pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsg);

        s3_memzero(pktinfo, sizeof(struct in_pktinfo));
        pktinfo->ipi_spec_dst = sin->sin_addr;

        return CMSG_SPACE(sizeof(struct in_pktinfo));
    }

#if defined(IPV6_RECVPKTINFO)

    if (cmsg->cmsg_level == SOL_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO
        && sockaddr->sa_family == AF_INET6)
    {
        sin6 = (struct sockaddr_in6 *)sockaddr;

        cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
        pktinfo6 = (struct in6_pktinfo *)CMSG_DATA(cmsg);

        s3_memzero(pktinfo6, sizeof(struct in6_pktinfo));
        pktinfo6->ipi6_addr = sin6->sin6_addr;
        pktinfo6->ipi6_ifindex = sin6->sin6_scope_id;

        return CMSG_SPACE(sizeof(struct in6_pktinfo));
    }

#endif

    (void)sockaddr;

    return 0;
}

#endif /* S3_HAVE_ADDRINFO_CMSG */
