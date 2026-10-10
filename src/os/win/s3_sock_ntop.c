/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <winsock2.h>
#include <ws2tcpip.h>

#include <s3_base.h>
#include <s3_sock_ntop.h>
#include <s3_string.h>

size_t
s3_sock_ntop(struct sockaddr *sa, socklen_t socklen, u_char *text, size_t len, s3_uint_t port)
{
    size_t               n;
    u_char              *p;
    struct sockaddr_in  *sin;
    struct sockaddr_in6 *sin6;

    (void)socklen;

    switch (sa->sa_family) {

    case AF_INET:

        sin = (struct sockaddr_in *)sa;
        p = (u_char *)&sin->sin_addr;

        if (port) {
            p = s3_snprintf(text, len, "%ud.%ud.%ud.%ud:%d", p[0], p[1], p[2], p[3],
                            ntohs(sin->sin_port));

        } else {
            p = s3_snprintf(text, len, "%ud.%ud.%ud.%ud", p[0], p[1], p[2], p[3]);
        }

        return (size_t)(p - text);

    case AF_INET6:

        sin6 = (struct sockaddr_in6 *)sa;

        n = 0;

        if (port) {
            text[n++] = '[';
        }

        n = s3_inet6_ntop(sin6->sin6_addr.s6_addr, &text[n], len - n);

        if (n == 0) {
            return 0;
        }

        if (port) {
            n = s3_snprintf(&text[1 + n], len - (1 + n), "]:%d", ntohs(sin6->sin6_port)) - text;
        }

        return n;

    default:

        /* the unix domain and other families are not ported */
        return 0;
    }
}

/*
 * the compressed form of an IPv6 address, including the
 * IPv4-mapped "::ffff:1.2.3.4" notation (ngx_inet6_ntop())
 */
size_t
s3_inet6_ntop(u_char *p, u_char *text, size_t len)
{
    u_char   *dst;
    size_t    max, n;
    s3_uint_t i, zero, last;

    if (len < S3_INET6_ADDRSTRLEN) {
        return 0;
    }

    zero = (s3_uint_t)-1;
    last = (s3_uint_t)-1;
    max = 1;
    n = 0;

    for (i = 0; i < 16; i += 2) {

        if (p[i] || p[i + 1]) {

            if (max < n) {
                zero = last;
                max = n;
            }

            n = 0;
            continue;
        }

        if (n++ == 0) {
            last = i;
        }
    }

    if (max < n) {
        zero = last;
        max = n;
    }

    dst = text;
    n = 16;

    if (zero == 0) {

        if ((max == 5 && p[10] == 0xff && p[11] == 0xff) || (max == 6) ||
            (max == 7 && p[14] != 0 && p[15] != 1)) {
            n = 12;
        }

        *dst++ = ':';
    }

    for (i = 0; i < n; i += 2) {

        if (i == zero) {
            *dst++ = ':';
            i += (max - 1) * 2;
            continue;
        }

        dst = s3_sprintf(dst, "%xd", p[i] * 256 + p[i + 1]);

        if (i < 14) {
            *dst++ = ':';
        }
    }

    if (n == 12) {
        dst = s3_sprintf(dst, "%ud.%ud.%ud.%ud", p[12], p[13], p[14], p[15]);
    }

    return dst - text;
}
