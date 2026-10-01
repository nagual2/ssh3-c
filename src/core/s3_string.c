/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <s3_core.h>

static u_char *s3_sprintf_num(u_char *buf, u_char *last, uint64_t ui64, u_char zero,
                              s3_uint_t hexadecimal, s3_uint_t width);
static u_char *s3_sprintf_str(u_char *buf, u_char *last, u_char *src, size_t len,
                              s3_uint_t hexadecimal);

u_char *
s3_sprintf(u_char *buf, const char *fmt, ...)
{
    u_char *p;
    va_list args;

    va_start(args, fmt);
    p = s3_vslprintf(buf, (u_char *)-1, fmt, args);
    va_end(args);

    return p;
}

u_char *
s3_snprintf(u_char *buf, size_t max, const char *fmt, ...)
{
    u_char *p;
    va_list args;

    va_start(args, fmt);
    p = s3_vslprintf(buf, buf + max, fmt, args);
    va_end(args);

    return p;
}

u_char *
s3_slprintf(u_char *buf, u_char *last, const char *fmt, ...)
{
    u_char *p;
    va_list args;

    va_start(args, fmt);
    p = s3_vslprintf(buf, last, fmt, args);
    va_end(args);

    return p;
}

u_char *
s3_vslprintf(u_char *buf, u_char *last, const char *fmt, va_list args)
{
    u_char   *p, zero;
    int       d;
    int64_t   i64;
    uint64_t  ui64;
    size_t    slen;
    s3_uint_t width, sign, hex;
    s3_str_t *v;

    while (*fmt && buf < last) {

        /*
         * "buf < last" means that we could copy at least one character:
         * the plain character, "%%", "%c", and minus without the checking
         */

        if (*fmt == '%') {

            i64 = 0;
            ui64 = 0;

            zero = (u_char)((*++fmt == '0') ? '0' : ' ');
            width = 0;
            sign = 1;
            hex = 0;
            slen = (size_t)-1;

            while (*fmt >= '0' && *fmt <= '9') {
                width = width * 10 + (*fmt++ - '0');
            }

            for (;;) {
                switch (*fmt) {

                case 'u':
                    sign = 0;
                    fmt++;
                    continue;

                case 'x':
                    hex = 1;
                    sign = 0;
                    fmt++;
                    continue;

                case 'X':
                    hex = 2;
                    sign = 0;
                    fmt++;
                    continue;

                case '*':
                    slen = va_arg(args, size_t);
                    fmt++;
                    continue;

                default:
                    break;
                }

                break;
            }

            /* the z/i/d/D/L cases look alike but each pulls its own
               va_arg type; the clone warning is a false positive here */
            // NOLINTNEXTLINE(bugprone-branch-clone)
            switch (*fmt) {

            case 'V':
                v = va_arg(args, s3_str_t *);

                buf = s3_sprintf_str(buf, last, v->data, v->len, hex);
                fmt++;

                continue;

            case 's':
                p = va_arg(args, u_char *);

                buf = s3_sprintf_str(buf, last, p, slen, hex);
                fmt++;

                continue;

            /* each of z/i/d/D/L pulls its own va_arg type; the clone
               warning is a false positive here */
            // NOLINTNEXTLINE(bugprone-branch-clone)
            case 'z':
                if (sign) {
                    i64 = (int64_t)va_arg(args, ssize_t);

                } else {
                    ui64 = (uint64_t)va_arg(args, size_t);
                }

                break;

            case 'i':
                if (sign) {
                    i64 = (int64_t)va_arg(args, s3_int_t);

                } else {
                    ui64 = (uint64_t)va_arg(args, s3_uint_t);
                }

                break;

            case 'd':
                if (sign) {
                    i64 = (int64_t)va_arg(args, int);

                } else {
                    ui64 = (uint64_t)va_arg(args, unsigned int);
                }

                break;

            case 'D':
                if (sign) {
                    i64 = (int64_t)va_arg(args, int32_t);

                } else {
                    ui64 = (uint64_t)va_arg(args, uint32_t);
                }

                break;

            case 'L':
                if (sign) {
                    i64 = (int64_t)va_arg(args, int64_t);

                } else {
                    ui64 = (uint64_t)va_arg(args, uint64_t);
                }

                break;

            case 'p':
                ui64 = (uintptr_t)va_arg(args, void *);
                hex = 2;
                sign = 0;
                zero = '0';
                width = 2 * sizeof(void *);

                break;

            case 'c':
                d = va_arg(args, int);
                *buf++ = (u_char)(d & 0xff);
                fmt++;

                continue;

            case 'Z':
                *buf++ = '\0';
                fmt++;

                continue;

            case 'N':
                *buf++ = LF;
                fmt++;

                continue;

            case '%':
                *buf++ = '%';
                fmt++;

                continue;

            default:
                *buf++ = *fmt++;

                continue;
            }

            if (sign) {
                if (i64 < 0) {
                    *buf++ = '-';
                    ui64 = (uint64_t)-i64;

                } else {
                    ui64 = (uint64_t)i64;
                }
            }

            buf = s3_sprintf_num(buf, last, ui64, zero, hex, width);

            fmt++;

        } else {
            *buf++ = *fmt++;
        }
    }

    return buf;
}

static u_char *
s3_sprintf_num(u_char *buf, u_char *last, uint64_t ui64, u_char zero, s3_uint_t hexadecimal,
               s3_uint_t width)
{
    u_char       *p, temp[S3_INT64_LEN + 1];
    size_t        len;
    uint32_t      ui32;
    static u_char hex[] = "0123456789abcdef";
    static u_char HEX[] = "0123456789ABCDEF";

    p = temp + S3_INT64_LEN;

    if (hexadecimal == 0) {

        if (ui64 <= (uint64_t)UINT32_MAX) {

            /*
             * to divide 64-bit numbers and to find remainders on the x86
             * platform gcc calls the libc functions [u]divdi3() and
             * [u]moddi3(); for 32-bit numbers and some divisors gcc uses
             * an inlined multiplication and shifts, for example, the
             * unsigned "i32 / 10" is compiled to
             *
             *     (i32 * 0xCCCCCCCD) >> 35
             */

            ui32 = (uint32_t)ui64;

            do {
                *--p = (u_char)(ui32 % 10 + '0');
            } while (ui32 /= 10);

        } else {
            do {
                *--p = (u_char)(ui64 % 10 + '0');
            } while (ui64 /= 10);
        }

    } else if (hexadecimal == 1) {

        do {
            *--p = hex[(uint32_t)(ui64 & 0xf)];

        } while (ui64 >>= 4);

    } else { /* hexadecimal == 2 */

        do {
            *--p = HEX[(uint32_t)(ui64 & 0xf)];

        } while (ui64 >>= 4);
    }

    /* zero or space padding */

    len = (temp + S3_INT64_LEN) - p;

    while (len++ < width && buf < last) {
        *buf++ = zero;
    }

    /* number safe copy */

    len = (temp + S3_INT64_LEN) - p;

    if (buf + len > last) {
        len = last - buf;
    }

    return s3_cpymem(buf, p, len);
}

static u_char *
s3_sprintf_str(u_char *buf, u_char *last, u_char *src, size_t len, s3_uint_t hexadecimal)
{
    static u_char hex[] = "0123456789abcdef";
    static u_char HEX[] = "0123456789ABCDEF";

    if (hexadecimal == 0) {

        if (len == (size_t)-1) {
            while (*src && buf < last) {
                *buf++ = *src++;
            }

        } else {
            len = s3_min((size_t)(last - buf), len);
            if (len) {
                buf = s3_cpymem(buf, src, len);
            }
        }

    } else if (hexadecimal == 1) {

        if (len == (size_t)-1) {

            while (*src && buf < last - 1) {
                *buf++ = hex[*src >> 4];
                *buf++ = hex[*src++ & 0xf];
            }

        } else {

            while (len-- && buf < last - 1) {
                *buf++ = hex[*src >> 4];
                *buf++ = hex[*src++ & 0xf];
            }
        }

    } else { /* hexadecimal == 2 */

        if (len == (size_t)-1) {

            while (*src && buf < last - 1) {
                *buf++ = HEX[*src >> 4];
                *buf++ = HEX[*src++ & 0xf];
            }

        } else {

            while (len-- && buf < last - 1) {
                *buf++ = HEX[*src >> 4];
                *buf++ = HEX[*src++ & 0xf];
            }
        }
    }

    return buf;
}
