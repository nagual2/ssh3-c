/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_STRING_H_INCLUDED_
#define _S3_STRING_H_INCLUDED_

#include <stdarg.h>

#include <s3_base.h>
#include <s3_str.h>

/*
 * supported conversion subset of nginx vslprintf:
 *
 *    %s               null-terminated string (u_char *)
 *    %*[x]s           length (size_t) and string
 *    %V               s3_str_t *
 *    %d               int / u_int (with 'u')
 *    %i               s3_int_t / s3_uint_t (with 'u')
 *    %z               ssize_t / size_t (with 'u')
 *    %D               int32_t / uint32_t (with 'u')
 *    %L               int64_t / uint64_t (with 'u')
 *    %p               void *
 *    %c               char
 *    %Z               '\0'
 *    %N               '\n'
 *    %%               '%'
 *
 *    %[0][width]      zero or space padding, field width
 *    %[x|X]           lowercase/uppercase hexadecimal (numbers and %V/%s)
 */
u_char *s3_vslprintf(u_char *buf, u_char *last, const char *fmt, va_list args);

u_char *s3_sprintf(u_char *buf, const char *fmt, ...);
u_char *s3_snprintf(u_char *buf, size_t max, const char *fmt, ...);
u_char *s3_slprintf(u_char *buf, u_char *last, const char *fmt, ...);

#define s3_vsnprintf(buf, max, fmt, args) s3_vslprintf(buf, buf + (max), fmt, args)

/*
 * the JSON string escape (P2-4): quotes, backslashes and the control
 * characters go over their \", \\ or \u00xx forms; returns the escaped
 * length, or -1 when cap (the NUL included) does not hold it
 */
s3_int_t s3_json_escape(const u_char *src, size_t len, u_char *dst, size_t cap);

/*
 * the constant-time comparison (P2-2): no early exit, the verdict is
 * the folded xor (0 = equal); the call site handling secret-derived
 * bytes prefers this over s3_memcmp, which short-circuits
 */
s3_int_t s3_memcmp_ct(const u_char *a, const u_char *b, size_t n);

#endif /* _S3_STRING_H_INCLUDED_ */
