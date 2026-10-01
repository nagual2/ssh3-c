/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <s3_core.h>

u_char *
s3_strerror(s3_err_t err, u_char *errbuf, size_t len)
{
    char        buf[256];
    const char *msg;
    size_t      n;

    /*
     * the XSI strerror_r() is async-signal-safe on glibc 2.32+ via
     * strerrordesc_np() only; here it is used for its portability
     * (no _GNU_SOURCE, no global buffer)
     */

    buf[0] = '\0';

    if (strerror_r(err, buf, sizeof(buf)) != 0) {
        msg = "Unknown error";

    } else {
        msg = buf;
    }

    n = s3_strlen(msg);

    if (n > len) {
        n = len;
    }

    return (u_char *)s3_cpymem(errbuf, msg, n);
}
