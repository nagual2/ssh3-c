/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_BASE_H_INCLUDED_
#define _S3_BASE_H_INCLUDED_

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

typedef unsigned char u_char;

typedef intptr_t  s3_int_t;
typedef uintptr_t s3_uint_t;

typedef int32_t  s3_int32_t;
typedef uint32_t s3_uint32_t;
typedef int64_t  s3_int64_t;
typedef uint64_t s3_uint64_t;

typedef s3_uint_t s3_msec_t;
typedef s3_int_t  s3_msec_int_t;

typedef int s3_fd_t;
typedef int s3_err_t;

#define S3_OK       0
#define S3_ERROR    -1
#define S3_AGAIN    -2
#define S3_BUSY     -3
#define S3_ABORT    -4
#define S3_DECLINED -5

#define S3_INVALID_FILE -1

#define S3_LOG_STDERR 0
#define S3_LOG_EMERG  1
#define S3_LOG_ALERT  2
#define S3_LOG_CRIT   3
#define S3_LOG_ERR    4
#define S3_LOG_WARN   5
#define S3_LOG_NOTICE 6
#define S3_LOG_INFO   7
#define S3_LOG_DEBUG  8

#define S3_LOG_DEBUG_CORE  0x010
#define S3_LOG_DEBUG_ALLOC 0x020
#define S3_LOG_DEBUG_EVENT 0x080

#define S3_LOG_DEBUG_FIRST S3_LOG_DEBUG_CORE
#define S3_LOG_DEBUG_LAST  S3_LOG_DEBUG_EVENT
#define S3_LOG_DEBUG_ALL   0x7ffffff0

#define S3_MAX_ERROR_STR 2048

#define S3_INT32_LEN (sizeof("-2147483648") - 1)
#define S3_INT64_LEN (sizeof("-9223372036854775808") - 1)
#define S3_INT_T_LEN (S3_INT64_LEN + 2)

#define LF '\n'
#define CR '\r'

#define S3_LINEFEED_SIZE 1

#define s3_inline inline

#define s3_min(val1, val2) ((val1 > val2) ? (val2) : (val1))
#define s3_max(val1, val2) ((val1 < val2) ? (val2) : (val1))

#define s3_align(d, a) (((d) + ((a) - 1)) & ~((a) - 1))

#define s3_align_ptr(p, a)                                                                         \
    (u_char *)(((uintptr_t)(p) + ((uintptr_t)(a) - 1)) & ~((uintptr_t)(a) - 1))

/*
 * msvc and gcc compile memset()/memcpy() to the inline instructions
 * for small blocks
 */
#define s3_memzero(buf, n)   (void)memset(buf, 0, n)
#define s3_memset(buf, c, n) (void)memset(buf, c, n)

#define s3_memcpy(dst, src, n) (void)memcpy(dst, src, n)
#define s3_cpymem(dst, src, n) (((u_char *)memcpy(dst, src, n)) + (n))

#define s3_memmove(dst, src, n) (void)memmove(dst, src, n)
#define s3_movemem(dst, src, n) (((u_char *)memmove(dst, src, n)) + (n))

#define s3_memcmp(s1, s2, n) memcmp(s1, s2, n)

#define s3_strlen(s)          strlen((const char *)s)
#define s3_strcmp(s1, s2)     strcmp((const char *)s1, (const char *)s2)
#define s3_strncmp(s1, s2, n) strncmp((const char *)s1, (const char *)s2, n)

/*
 * allocation primitives; the log argument is reserved for future
 * allocation-failure reporting and is intentionally unused now
 */
#define s3_alloc(size, log) malloc(size)
#define s3_free(p)          free(p)

#endif /* _S3_BASE_H_INCLUDED_ */
