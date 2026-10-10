/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <s3_core.h>

/*
 * unlike the unix variant there is no strerror_r: FormatMessageA is
 * invoked per call (error paths only, never the data path); the
 * trailing newline it appends is stripped, the log format adds its
 * own linefeed
 */

u_char *
s3_strerror(s3_err_t err, u_char *errbuf, size_t len)
{
    char   buf[512];
    char  *msg;
    DWORD  n;
    size_t k;

    n = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, err,
                       MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buf, sizeof(buf) - 1, NULL);

    if (n == 0) {
        msg = "Unknown error";
        k = s3_strlen(msg);

    } else {

        while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' || buf[n - 1] == ' ')) {
            buf[--n] = '\0';
        }

        msg = buf;
        k = n;
    }

    if (k > len) {
        k = len;
    }

    return (u_char *)s3_cpymem(errbuf, msg, k);
}
