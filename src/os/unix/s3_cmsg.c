/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <arpa/inet.h>

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

    /*
     * the family of the local address decides the control message, and
     * the level and the type are set here: the caller only reserves
     * the space (the reference decides the same way, the level and
     * the type are its own, src/os/unix/ngx_udp_sendmsg_chain.c)
     */

    if (sockaddr->sa_family == AF_INET) {
        sin = (struct sockaddr_in *)sockaddr;

        cmsg->cmsg_level = SOL_IP;
        cmsg->cmsg_type = IP_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
        pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsg);

        s3_memzero(pktinfo, sizeof(struct in_pktinfo));
        pktinfo->ipi_spec_dst = sin->sin_addr;

        return CMSG_SPACE(sizeof(struct in_pktinfo));
    }

#if defined(IPV6_RECVPKTINFO)

    if (sockaddr->sa_family == AF_INET6) {
        sin6 = (struct sockaddr_in6 *)sockaddr;

        cmsg->cmsg_level = SOL_IPV6;
        cmsg->cmsg_type = IPV6_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
        pktinfo6 = (struct in6_pktinfo *)CMSG_DATA(cmsg);

        s3_memzero(pktinfo6, sizeof(struct in6_pktinfo));
        pktinfo6->ipi6_addr = sin6->sin6_addr;
        pktinfo6->ipi6_ifindex = sin6->sin6_scope_id;

        return CMSG_SPACE(sizeof(struct in6_pktinfo));
    }

#endif

    (void)cmsg;

    return 0;
}

s3_int_t
s3_enable_pktinfo(int fd, struct sockaddr *sockaddr)
{
    int value;

    /*
     * the local address ancillary data of a wildcard datagram socket:
     * without the option the kernel never delivers the pktinfo control
     * message and the local address of a packet stays unknown (the
     * reference sets the option in the listening socket setup,
     * src/core/ngx_connection.c)
     */

    value = 1;

    if (sockaddr->sa_family == AF_INET) {

        struct sockaddr_in *sin = (struct sockaddr_in *)sockaddr;

        if (sin->sin_addr.s_addr != htonl(INADDR_ANY)) {
            /* not a wildcard: the local address is known already */
            return S3_OK;
        }

        if (setsockopt(fd, SOL_IP, IP_PKTINFO, &value, sizeof(value)) == -1) {
            return S3_ERROR;
        }

        return S3_OK;
    }

#if defined(IPV6_RECVPKTINFO)

    if (sockaddr->sa_family == AF_INET6) {

        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sockaddr;

        if (!IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)) {
            /* not a wildcard: the local address is known already */
            return S3_OK;
        }

        if (setsockopt(fd, SOL_IPV6, IPV6_RECVPKTINFO, &value, sizeof(value)) == -1) {
            return S3_ERROR;
        }

        return S3_OK;
    }

#endif

    return S3_OK;
}

#endif /* S3_HAVE_ADDRINFO_CMSG */
