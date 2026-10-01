/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <s3_core.h>
#include <string.h>

#include "s3_test.h"

static size_t
s3_test_format(u_char *buf, size_t max, const char *fmt, ...)
{
    u_char *p;
    va_list args;

    va_start(args, fmt);
    p = s3_vsnprintf(buf, max, fmt, args);
    va_end(args);

    return p - buf;
}

static void
s3_test_expect(u_char *buf, size_t len, const char *expected)
{
    S3_ASSERT(len == s3_strlen(expected));
    S3_ASSERT(s3_memcmp(buf, expected, len) == 0);
}

static int
s3_test_string(void)
{
    u_char   buf[128];
    size_t   len;
    s3_str_t v;
    u_char  *p;

    /* %d */

    len = s3_test_format(buf, sizeof(buf), "num=%d", -42);
    s3_test_expect(buf, len, "num=-42");

    len = s3_test_format(buf, sizeof(buf), "int_min=%d", -2147483647 - 1);
    s3_test_expect(buf, len, "int_min=-2147483648");

    /* %i with s3_int_t */

    len = s3_test_format(buf, sizeof(buf), "i=%i", (s3_int_t)-5);
    s3_test_expect(buf, len, "i=-5");

    len = s3_test_format(buf, sizeof(buf), "ui=%ui", (s3_uint_t)7);
    s3_test_expect(buf, len, "ui=7");

    /* %z (signed ssize_t) and %uz */

    len = s3_test_format(buf, sizeof(buf), "z=%z", (ssize_t)-4096);
    s3_test_expect(buf, len, "z=-4096");

    len = s3_test_format(buf, sizeof(buf), "uz=%uz", (size_t)4096);
    s3_test_expect(buf, len, "uz=4096");

    /* %L and %uL */

    len = s3_test_format(buf, sizeof(buf), "L=%L", (int64_t)-1);
    s3_test_expect(buf, len, "L=-1");

    len = s3_test_format(buf, sizeof(buf), "uL=%uL", (uint64_t)18446744073709551615ULL);
    s3_test_expect(buf, len, "uL=18446744073709551615");

    /* %uD and %uX */

    len = s3_test_format(buf, sizeof(buf), "uD=%uD", (uint32_t)4294967295U);
    s3_test_expect(buf, len, "uD=4294967295");

    len = s3_test_format(buf, sizeof(buf), "x=%uxD", (uint32_t)0x00ff10);
    s3_test_expect(buf, len, "x=ff10");

    len = s3_test_format(buf, sizeof(buf), "X=%08XD", (uint32_t)0x00ff10);
    s3_test_expect(buf, len, "X=0000FF10");

    /* %s */

    len = s3_test_format(buf, sizeof(buf), "s=%s", "abc");
    s3_test_expect(buf, len, "s=abc");

    /* %V with len/data */

    v.len = 5;
    v.data = (u_char *)"hello";
    len = s3_test_format(buf, sizeof(buf), "[%V]", &v);
    s3_test_expect(buf, len, "[hello]");

    v.len = 0;
    v.data = NULL;
    len = s3_test_format(buf, sizeof(buf), "[%V]", &v);
    s3_test_expect(buf, len, "[]");

    /* %*s: explicit length */

    len = s3_test_format(buf, sizeof(buf), "%V%*s", &v, (size_t)3, "abcdef");
    s3_test_expect(buf, len, "abc");

    /* width and zero padding */

    len = s3_test_format(buf, sizeof(buf), "%05d", 42);
    s3_test_expect(buf, len, "00042");

    len = s3_test_format(buf, sizeof(buf), "%5d", 42);
    s3_test_expect(buf, len, "   42");

    /* %p renders a fixed-width hex pointer */

    p = s3_slprintf(buf, buf + sizeof(buf), "%p", (void *)0x1234);
    len = p - buf;
    S3_ASSERT(len == 2 * sizeof(void *));

    /* %c, %%, %Z, %N */

    len = s3_test_format(buf, sizeof(buf), "%c%c", 'o', 'k');
    s3_test_expect(buf, len, "ok");

    len = s3_test_format(buf, sizeof(buf), "100%%");
    s3_test_expect(buf, len, "100%");

    len = s3_test_format(buf, sizeof(buf), "a%Zb");
    S3_ASSERT(len == 3);
    S3_ASSERT(s3_memcmp(buf, "a\0b", 3) == 0);

    len = s3_test_format(buf, sizeof(buf), "a%Nb");
    S3_ASSERT(len == 3);
    S3_ASSERT(buf[0] == 'a' && buf[1] == LF && buf[2] == 'b');

    /* truncation: output stops at last, no overflow */

    s3_memset(buf, 'A', sizeof(buf));
    p = s3_slprintf(buf, buf + 8, "truncated-%s", "string");
    S3_ASSERT(p == buf + 8);
    S3_ASSERT(s3_memcmp(buf, "truncate", 8) == 0);
    S3_ASSERT(buf[8] == 'A'); /* byte after last is untouched */

    /* empty format */

    len = s3_test_format(buf, sizeof(buf), "");
    S3_ASSERT(len == 0);

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_string)
