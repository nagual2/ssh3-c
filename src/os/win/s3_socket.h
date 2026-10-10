/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_SOCKET_H_INCLUDED_
#define _S3_SOCKET_H_INCLUDED_

#include <winsock2.h>
#include <ws2tcpip.h>

#include <s3_base.h>

/*
 * the win32 mirror of ngx_socket.h, the AF_INET/AF_INET6 subset the
 * port needs: sockets are created ready for overlapped I/O so the
 * S3_USE_IOCP switch (P9) needs no call-site changes
 */

#define S3_WRITE_SHUTDOWN SD_SEND
#define S3_READ_SHUTDOWN  SD_RECEIVE
#define S3_RDWR_SHUTDOWN  SD_BOTH

#define S3_INVALID_SOCKET INVALID_SOCKET

typedef SOCKET s3_socket_t;

#define s3_socket(af, type, proto) WSASocketW(af, type, proto, NULL, 0, WSA_FLAG_OVERLAPPED)

#define s3_close_socket      closesocket
#define s3_close_socket_n    "closesocket()"
#define s3_shutdown_socket   shutdown
#define s3_shutdown_socket_n "shutdown()"

#endif /* _S3_SOCKET_H_INCLUDED_ */
