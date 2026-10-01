/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <s3_core.h>

#include <unistd.h>

static s3_str_t s3_err_levels[] = {s3_null_string,      s3_string("emerg"), s3_string("alert"),
                                   s3_string("crit"),   s3_string("error"), s3_string("warn"),
                                   s3_string("notice"), s3_string("info"),  s3_string("debug")};

s3_log_t s3_stderr_log = {S3_LOG_INFO, S3_INVALID_FILE};

void
s3_log_error_core(unsigned level, s3_log_t *log, s3_err_t err, const char *fmt, ...)
{
    int      fd;
    unsigned lv;
    ssize_t  n;
    u_char  *p, *last;
    va_list  args;
    u_char   errstr[S3_MAX_ERROR_STR];

    lv = (level <= S3_LOG_DEBUG) ? level : S3_LOG_DEBUG;

    last = errstr + S3_MAX_ERROR_STR;

    p = s3_slprintf(errstr, last, "[%V] ", &s3_err_levels[lv]);

    va_start(args, fmt);
    p = s3_vslprintf(p, last, fmt, args);
    va_end(args);

    if (err) {
        p = s3_log_errno(p, last, err);
    }

    if (p > last - S3_LINEFEED_SIZE) {
        p = last - S3_LINEFEED_SIZE;
    }

    *p++ = LF;

    fd = (log != NULL && log->fd != S3_INVALID_FILE) ? log->fd : STDERR_FILENO;

    n = write(fd, errstr, p - errstr);
    (void)n;
}

u_char *
s3_log_errno(u_char *buf, u_char *last, s3_err_t err)
{
    if (buf > last - 50) {

        /* leave a space for an error code */

        buf = last - 50;
        *buf++ = '.';
        *buf++ = '.';
        *buf++ = '.';
    }

    buf = s3_slprintf(buf, last, " (%d: ", err);

    buf = s3_strerror(err, buf, last - buf);

    if (buf < last) {
        *buf++ = ')';
    }

    return buf;
}
