/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <string.h>

#include <s3_core.h>
#include <s3_nonblocking.h>
#include <s3_os_init.h>
#include <s3_sock_ntop.h>
#include <s3_socket.h>

#include "s3_test.h"

static void
s3_test_errno_map(void)
{
    /* the POSIX-named codes are compile-time mappings over the win32
       codes, the mirror of the unix s3_errno.h */
    S3_ASSERT(S3_EAGAIN == WSAEWOULDBLOCK);
    S3_ASSERT(S3_ECONNRESET == WSAECONNRESET);
    S3_ASSERT(S3_ECONNREFUSED == WSAECONNREFUSED);
    S3_ASSERT(S3_ETIMEDOUT == WSAETIMEDOUT);
    S3_ASSERT(S3_ENOENT == ERROR_FILE_NOT_FOUND);
    S3_ASSERT(S3_EPIPE == ERROR_BROKEN_PIPE);
}

static void
s3_test_os_init(void)
{
    S3_ASSERT(s3_os_init() == S3_OK);
}

static void
s3_test_nonblocking(void)
{
    s3_socket_t s;

    s = s3_socket(AF_INET, SOCK_STREAM, 0);
    S3_ASSERT(s != S3_INVALID_SOCKET);

    /* the mode switch is idempotent and fails on a foreign fd */
    S3_ASSERT(s3_nonblocking((s3_fd_t)s) == S3_OK);
    S3_ASSERT(s3_nonblocking((s3_fd_t)s) == S3_OK);
    S3_ASSERT(s3_nonblocking((s3_fd_t)S3_INVALID_SOCKET) == S3_ERROR);

    S3_ASSERT(s3_close_socket(s) == 0);
}

static void
s3_test_sock_ntop(void)
{
    u_char              text[S3_SOCKADDR_STRLEN];
    struct sockaddr_in  sin;
    struct sockaddr_in6 sin6;
    u_char              mapped[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4};
    size_t              len;

    s3_memzero(&sin, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(8080);
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    len = s3_sock_ntop((struct sockaddr *)&sin, sizeof(sin), text, sizeof(text), 1);
    S3_ASSERT(len == s3_strlen("127.0.0.1:8080"));
    S3_ASSERT(s3_memcmp(text, "127.0.0.1:8080", len) == 0);

    len = s3_sock_ntop((struct sockaddr *)&sin, sizeof(sin), text, sizeof(text), 0);
    S3_ASSERT(len == s3_strlen("127.0.0.1"));
    S3_ASSERT(s3_memcmp(text, "127.0.0.1", len) == 0);

    s3_memzero(&sin6, sizeof(sin6));
    sin6.sin6_family = AF_INET6;
    sin6.sin6_port = htons(443);
    sin6.sin6_addr = in6addr_loopback;

    len = s3_sock_ntop((struct sockaddr *)&sin6, sizeof(sin6), text, sizeof(text), 1);
    S3_ASSERT(len == s3_strlen("[::1]:443"));
    S3_ASSERT(s3_memcmp(text, "[::1]:443", len) == 0);

    /* the IPv4-mapped compressed form */
    len = s3_inet6_ntop(mapped, text, sizeof(text));
    S3_ASSERT(len == s3_strlen("::ffff:1.2.3.4"));
    S3_ASSERT(s3_memcmp(text, "::ffff:1.2.3.4", len) == 0);
}

static void
s3_test_strerror(void)
{
    u_char  buf[S3_MAX_ERROR_STR];
    u_char *p;
    size_t  n;

    p = s3_strerror(ERROR_FILE_NOT_FOUND, buf, sizeof(buf));
    n = p - buf;

    S3_ASSERT(n > 0 && n < sizeof(buf));
    S3_ASSERT(buf[n - 1] != CR);
    S3_ASSERT(buf[n - 1] != LF);

    /* an unknown code maps to the language-independent stub */
    p = s3_strerror(0x7ffffff0, buf, sizeof(buf));
    n = p - buf;

    S3_ASSERT(n == s3_strlen("Unknown error"));
    S3_ASSERT(s3_memcmp(buf, "Unknown error", n) == 0);
}

static int
s3_test_os_win(void)
{
    s3_test_errno_map();
    s3_test_os_init();
    s3_test_nonblocking();
    s3_test_sock_ntop();
    s3_test_strerror();

    s3_os_done();

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_os_win)
