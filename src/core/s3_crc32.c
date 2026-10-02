/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <s3_crc32.h>

/*
 * the slice-by-one table of the reference is replaced with the plain
 * per-byte table computed on the first use; the event loop is
 * single-threaded, no locking is required
 */
static s3_uint32_t s3_crc32_table[256];
static s3_uint_t   s3_crc32_table_ready = 0;

s3_uint32_t
s3_crc32_long(u_char *p, size_t len)
{
    s3_uint32_t crc;
    size_t      i, n;

    if (!s3_crc32_table_ready) {

        for (i = 0; i < 256; i++) {
            crc = (s3_uint32_t)i;

            for (n = 0; n < 8; n++) {
                crc = (crc >> 1) ^ (0xEDB88320u & -(crc & 1));
            }

            s3_crc32_table[i] = crc;
        }

        s3_crc32_table_ready = 1;
    }

    crc = 0xffffffff;

    for (i = 0; i < len; i++) {
        crc = s3_crc32_table[(crc ^ p[i]) & 0xff] ^ (crc >> 8);
    }

    return crc ^ 0xffffffff;
}
