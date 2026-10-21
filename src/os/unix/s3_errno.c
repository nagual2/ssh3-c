/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <s3_core.h>

u_char *
s3_strerror(s3_err_t err, u_char *errbuf, size_t len)
{
    const char *msg;
    size_t      n;

#if defined(__GLIBC__) && __GLIBC_PREREQ(2, 32)

    /*
     * strerrordesc_np() is a table lookup: it is async-signal-safe and
     * returns a static string, so the errno text costs neither a
     * buffer nor a global state.  The build uses the GNU feature set
     * (the reference does too, auto/os/linux: the BSD structures of
     * the local address ancillary data live behind it), and the GNU
     * variant of strerror_r() is neither of the two.
     */

    msg = strerrordesc_np(err);

#else

    char buf[256];

    /* the XSI strerror_r() (int return, musl and the old glibc) */

    buf[0] = '\0';

    if (strerror_r(err, buf, sizeof(buf)) != 0) {
        msg = "Unknown error";

    } else {
        msg = buf;
    }

#endif

    if (msg == NULL) {
        msg = "Unknown error";
    }

    n = s3_strlen(msg);

    if (n > len) {
        n = len;
    }

    return (u_char *)s3_cpymem(errbuf, msg, n);
}
