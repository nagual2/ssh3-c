/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_LOG_H_INCLUDED_
#define _S3_LOG_H_INCLUDED_

#include <s3_base.h>

/*
 * simplified nginx log handle: no cycle, no file objects; fd is the
 * destination descriptor or S3_INVALID_FILE meaning stderr
 */
typedef struct {
    unsigned log_level;
    int      fd;
} s3_log_t;

extern s3_log_t s3_stderr_log;

/*
 * the core function does no level gating; the macros below are the
 * interface
 */
void s3_log_error_core(unsigned level, s3_log_t *log, s3_err_t err, const char *fmt, ...);

u_char *s3_log_errno(u_char *buf, u_char *last, s3_err_t err);

#define s3_log_error(level, log, ...)                                                              \
    if ((log)->log_level >= level)                                                                 \
    s3_log_error_core(level, log, __VA_ARGS__)

#define s3_log_debug(level, log, ...)                                                              \
    if ((log)->log_level & level)                                                                  \
    s3_log_error_core(S3_LOG_DEBUG, log, __VA_ARGS__)

/*
 * debug messages go out only when (log)->log_level has the level bit;
 * use S3_LOG_DEBUG_EVENT (or S3_LOG_DEBUG_ALL) as the debug mask
 */
#define s3_log_debug0(level, log, err, fmt) s3_log_debug(level, log, err, fmt)

#define s3_log_debug1(level, log, err, fmt, a1) s3_log_debug(level, log, err, fmt, a1)

#define s3_log_debug2(level, log, err, fmt, a1, a2) s3_log_debug(level, log, err, fmt, a1, a2)

#define s3_log_debug3(level, log, err, fmt, a1, a2, a3)                                            \
    s3_log_debug(level, log, err, fmt, a1, a2, a3)

#define s3_log_debug4(level, log, err, fmt, a1, a2, a3, a4)                                        \
    s3_log_debug(level, log, err, fmt, a1, a2, a3, a4)

#define s3_log_debug5(level, log, err, fmt, a1, a2, a3, a4, a5)                                    \
    s3_log_debug(level, log, err, fmt, a1, a2, a3, a4, a5)

#define s3_log_debug6(level, log, err, fmt, a1, a2, a3, a4, a5, a6)                                \
    s3_log_debug(level, log, err, fmt, a1, a2, a3, a4, a5, a6)

#endif /* _S3_LOG_H_INCLUDED_ */
