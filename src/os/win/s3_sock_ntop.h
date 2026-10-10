/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_SOCK_NTOP_H_INCLUDED_
#define _S3_SOCK_NTOP_H_INCLUDED_

#include <winsock2.h>
#include <ws2tcpip.h>

#include <s3_base.h>

/*
 * the minimal AF_INET/AF_INET6 subset of ngx_sock_ntop()
 * (src/core/ngx_inet.c); the unix domain and CIDR helpers
 * are not ported
 */
#define S3_INET6_ADDRSTRLEN INET6_ADDRSTRLEN

#define S3_SOCKADDR_STRLEN (S3_INET6_ADDRSTRLEN + sizeof("[]:65535"))

size_t s3_sock_ntop(struct sockaddr *sa, socklen_t socklen, u_char *text, size_t len,
                    s3_uint_t port);
size_t s3_inet6_ntop(u_char *p, u_char *text, size_t len);

#endif /* _S3_SOCK_NTOP_H_INCLUDED_ */
