/*
 * Copyright (C) 2026 the ssh3-c authors
 */

/*
 * tests for the local address ancillary data: the control message the
 * send path writes and the receive path reads, and the socket option
 * that makes the kernel deliver it at all
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <s3_base.h>
#include <s3_cmsg.h>

#include "s3_test.h"

union s3_test_cmsg_u {
    struct cmsghdr cmsg;
    uint64_t       align;
    u_char buf[CMSG_SPACE(sizeof(struct in_pktinfo)) + CMSG_SPACE(sizeof(struct in6_pktinfo))];
};

/*
 * the send path: the family of the local address decides the control
 * message, and the level and the type belong to the message itself
 */

static int
s3_test_cmsg_set_v4(void)
{
    union s3_test_cmsg_u u;
    struct sockaddr_in   sin;
    struct in_pktinfo   *pktinfo;
    size_t               len;

    s3_memzero(&sin, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(443);
    sin.sin_addr.s_addr = htonl(0x7f000001);

    s3_memzero(&u, sizeof(u));

    len = s3_set_srcaddr_cmsg(&u.cmsg, (struct sockaddr *)&sin);

    S3_ASSERT(len == CMSG_SPACE(sizeof(struct in_pktinfo)));
    S3_ASSERT(u.cmsg.cmsg_level == SOL_IP);
    S3_ASSERT(u.cmsg.cmsg_type == IP_PKTINFO);
    S3_ASSERT(u.cmsg.cmsg_len == CMSG_LEN(sizeof(struct in_pktinfo)));

    pktinfo = (struct in_pktinfo *)CMSG_DATA(&u.cmsg);
    S3_ASSERT(pktinfo->ipi_spec_dst.s_addr == sin.sin_addr.s_addr);

    /*
     * the receive path reads the local address of the arrived packet:
     * the kernel fills ipi_addr (the address the packet was sent to),
     * the send path above fills ipi_spec_dst (the source address to
     * use) — the two fields are not the same
     */

    s3_memzero(&u, sizeof(u));
    u.cmsg.cmsg_level = SOL_IP;
    u.cmsg.cmsg_type = IP_PKTINFO;
    u.cmsg.cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));

    pktinfo = (struct in_pktinfo *)CMSG_DATA(&u.cmsg);
    pktinfo->ipi_addr.s_addr = htonl(0x7f000001);

    s3_memzero(&sin, sizeof(sin));
    sin.sin_family = AF_INET;

    S3_ASSERT(s3_get_srcaddr_cmsg(&u.cmsg, (struct sockaddr *)&sin) != 0);
    S3_ASSERT(sin.sin_addr.s_addr == htonl(0x7f000001));

    return s3_test_failures;
}

static int
s3_test_cmsg_set_v6(void)
{
#if defined(IPV6_RECVPKTINFO)
    union s3_test_cmsg_u u;
    struct sockaddr_in6  sin6;
    struct in6_pktinfo  *pktinfo6;
    size_t               len;

    s3_memzero(&sin6, sizeof(sin6));
    sin6.sin6_family = AF_INET6;
    sin6.sin6_port = htons(443);
    sin6.sin6_addr = in6addr_loopback;

    s3_memzero(&u, sizeof(u));

    len = s3_set_srcaddr_cmsg(&u.cmsg, (struct sockaddr *)&sin6);

    S3_ASSERT(len == CMSG_SPACE(sizeof(struct in6_pktinfo)));
    S3_ASSERT(u.cmsg.cmsg_level == SOL_IPV6);
    S3_ASSERT(u.cmsg.cmsg_type == IPV6_PKTINFO);
    S3_ASSERT(u.cmsg.cmsg_len == CMSG_LEN(sizeof(struct in6_pktinfo)));

    pktinfo6 = (struct in6_pktinfo *)CMSG_DATA(&u.cmsg);
    S3_ASSERT(IN6_IS_ADDR_LOOPBACK(&pktinfo6->ipi6_addr));

    /* the receive path reads the address back */

    s3_memzero(&sin6, sizeof(sin6));
    sin6.sin6_family = AF_INET6;

    S3_ASSERT(s3_get_srcaddr_cmsg(&u.cmsg, (struct sockaddr *)&sin6) != 0);
    S3_ASSERT(IN6_IS_ADDR_LOOPBACK(&sin6.sin6_addr));
#endif

    return s3_test_failures;
}

/*
 * the socket option: without it the kernel never delivers the pktinfo
 * control message and the local address of a packet stays unknown
 */

static int
s3_test_cmsg_pktinfo(void)
{
    int                fd, snd, n, found;
    struct sockaddr_in sin, peer;
    struct msghdr      msg;
    struct iovec       iov;
    struct cmsghdr    *cmsg;
    socklen_t          sl;
    u_char             buf[64];
    u_char control[CMSG_SPACE(sizeof(struct in_pktinfo)) + CMSG_SPACE(sizeof(struct in6_pktinfo))];

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    S3_ASSERT(fd != -1);

    s3_memzero(&sin, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = 0;

    S3_ASSERT(bind(fd, (struct sockaddr *)&sin, sizeof(sin)) == 0);

    sl = sizeof(sin);
    S3_ASSERT(getsockname(fd, (struct sockaddr *)&sin, &sl) == 0);

    /* the wildcard socket needs the option */

    S3_ASSERT(s3_enable_pktinfo(fd, (struct sockaddr *)&sin) == S3_OK);

    snd = socket(AF_INET, SOCK_DGRAM, 0);
    S3_ASSERT(snd != -1);

    peer = sin;
    peer.sin_addr.s_addr = htonl(0x7f000001);

    S3_ASSERT(sendto(snd, "x", 1, 0, (struct sockaddr *)&peer, sizeof(peer)) == 1);

    s3_memzero(&msg, sizeof(msg));
    s3_memzero(control, sizeof(control));

    iov.iov_base = buf;
    iov.iov_len = sizeof(buf);

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    n = recvmsg(fd, &msg, 0);
    S3_ASSERT(n == 1);

    found = 0;

    for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_PKTINFO) {
            found = 1;
            break;
        }
    }

    S3_ASSERT(found);

    (void)close(snd);
    (void)close(fd);

    return s3_test_failures;
}

/* a socket bound to a specific address needs no option */

static int
s3_test_cmsg_pktinfo_specific(void)
{
    int                fd;
    struct sockaddr_in sin;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    S3_ASSERT(fd != -1);

    s3_memzero(&sin, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(0x7f000001);
    sin.sin_port = 0;

    S3_ASSERT(s3_enable_pktinfo(fd, (struct sockaddr *)&sin) == S3_OK);

    (void)close(fd);

    return s3_test_failures;
}

/*
 * the send path on the wire: the source address of the datagram must
 * be the one the control message names (the loopback answers with the
 * address of the sender otherwise)
 */

static int
s3_test_cmsg_send(void)
{
    int                fd, snd, n;
    struct sockaddr_in sin, peer, from;
    struct msghdr      msg;
    struct iovec       iov;
    socklen_t          sl;
    size_t             len;
    u_char             buf[64];
    u_char             control[CMSG_SPACE(sizeof(struct in_pktinfo))];

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    S3_ASSERT(fd != -1);

    s3_memzero(&sin, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(0x7f000001);
    sin.sin_port = 0;

    S3_ASSERT(bind(fd, (struct sockaddr *)&sin, sizeof(sin)) == 0);

    sl = sizeof(sin);
    S3_ASSERT(getsockname(fd, (struct sockaddr *)&sin, &sl) == 0);

    snd = socket(AF_INET, SOCK_DGRAM, 0);
    S3_ASSERT(snd != -1);

    /* the sender sits on another loopback address */

    s3_memzero(&peer, sizeof(peer));
    peer.sin_family = AF_INET;
    peer.sin_addr.s_addr = htonl(0x7f000002);
    peer.sin_port = 0;

    S3_ASSERT(bind(snd, (struct sockaddr *)&peer, sizeof(peer)) == 0);

    /* the datagram must leave with the third loopback address */

    s3_memzero(control, sizeof(control));

    peer.sin_addr.s_addr = htonl(0x7f000003);

    len = s3_set_srcaddr_cmsg((struct cmsghdr *)control, (struct sockaddr *)&peer);
    S3_ASSERT(len != 0);

    /* the destination is the receiver */

    peer.sin_addr.s_addr = htonl(0x7f000001);
    peer.sin_port = sin.sin_port;

    s3_memzero(&msg, sizeof(msg));

    iov.iov_base = buf;
    iov.iov_len = 1;

    msg.msg_name = &peer;
    msg.msg_namelen = sizeof(peer);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = len;

    n = sendmsg(snd, &msg, 0);
    S3_ASSERT(n == 1);

    s3_memzero(&from, sizeof(from));
    sl = sizeof(from);

    n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &sl);
    S3_ASSERT(n == 1);
    S3_ASSERT(from.sin_addr.s_addr == htonl(0x7f000003));

    (void)close(snd);
    (void)close(fd);

    return s3_test_failures;
}

static int
s3_test_cmsg(void)
{
    (void)s3_test_cmsg_set_v4();
    (void)s3_test_cmsg_set_v6();
    (void)s3_test_cmsg_pktinfo();
    (void)s3_test_cmsg_pktinfo_specific();
    (void)s3_test_cmsg_send();

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_cmsg)
