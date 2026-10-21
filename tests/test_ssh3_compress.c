/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the channel-body compression (PLAN.md 9, B8): the codecs, the
 * capability token of the version string and the compressed frame
 */

#include <s3_core.h>

#include <string.h>

#include <s3_ssh3_compress.h>
#include <s3_ssh3_message.h>
#include <s3_ssh3_version.h>

#include "s3_test.h"

/*
 * a payload with a compressible part and a noisy tail: the noisy part
 * keeps the cutoff honest, the compressible part makes the round-trip
 * meaningful
 */

static size_t
s3_compress_payload(u_char *buf, size_t cap, size_t noise_len)
{
    size_t   n = 0;
    size_t   i;
    uint32_t seed = 0x12345678u;

    while (n + 64 < cap) {
        for (i = 0; i < 64; i++) {
            buf[n++] = (u_char)('a' + (i % 26));
        }
    }

    for (i = 0; i < noise_len && n < cap; i++) {
        seed = seed * 1103515245u + 12345u;
        buf[n++] = (u_char)(seed >> 16);
    }

    return n;
}

static int
s3_test_compress_capability(void)
{
    u_char cap_buf[64];
    size_t cap_len;
    uint32_t available;
    uint32_t parsed;

    available = s3_ssh3_compress_available();

    cap_len = s3_ssh3_compress_capability(cap_buf, sizeof(cap_buf));

    /* the capability of a build without a codec is empty */

    if (available == 0) {
        S3_ASSERT(cap_len == 0);
    } else {
        S3_ASSERT(cap_len > 0);
        S3_ASSERT(cap_len < sizeof(cap_buf));
    }

    parsed = s3_ssh3_compress_parse(cap_buf, cap_len);

    S3_ASSERT(parsed == available);

    /* the unknown names are skipped, not fatal */

    {
        static const u_char list[] = "deflate,nosuch,zstd";

        parsed = s3_ssh3_compress_parse(list, s3_strlen(list));
    }

    S3_ASSERT((parsed & S3_SSH3_COMPRESS_M_DEFLATE) != 0);
    S3_ASSERT((parsed & S3_SSH3_COMPRESS_M_ZSTD) != 0);

    /* an empty value is the zero mask */

    S3_ASSERT(s3_ssh3_compress_parse((const u_char *)"", 0) == 0);

    return s3_test_failures;
}

static int
s3_test_compress_choose(void)
{
    uint32_t available = s3_ssh3_compress_available();

    /* an empty peer mask gives no compression at all */

    S3_ASSERT(s3_ssh3_compress_choose(0) == S3_SSH3_COMPRESS_NONE);

    /* a peer mask with nothing in common gives no compression */

    S3_ASSERT(s3_ssh3_compress_choose(0x80000000u) == S3_SSH3_COMPRESS_NONE);

    /* the choice is one of the common algorithms */

    if (available != 0) {
        uint32_t chosen = s3_ssh3_compress_choose(available);

        S3_ASSERT(chosen != S3_SSH3_COMPRESS_NONE);
    }

    return s3_test_failures;
}

static int
s3_test_compress_roundtrip(void)
{
    u_char   payload[8192];
    u_char   packed[16384];
    u_char   plain[16384];
    size_t   payload_len;
    size_t   packed_len;
    size_t   plain_len;
    uint32_t available = s3_ssh3_compress_available();
    uint32_t alg;

    payload_len = s3_compress_payload(payload, sizeof(payload), 512);

    for (alg = 1; alg <= 3; alg++) {

        uint32_t bit = 0;

        if (alg == S3_SSH3_COMPRESS_DEFLATE) {
            bit = S3_SSH3_COMPRESS_M_DEFLATE;
        } else if (alg == S3_SSH3_COMPRESS_LZ4) {
            bit = S3_SSH3_COMPRESS_M_LZ4;
        } else {
            bit = S3_SSH3_COMPRESS_M_ZSTD;
        }

        if ((available & bit) == 0) {
            continue;
        }

        packed_len = 0;

        S3_ASSERT(s3_ssh3_compress_encode(packed, sizeof(packed), &packed_len, alg, payload,
                                          payload_len) == S3_OK);
        S3_ASSERT(packed_len > 0);

        /* the compressible payload really shrinks: the cutoff does not
         * throw the gain away */

        S3_ASSERT(packed_len < payload_len);

        plain_len = 0;

        S3_ASSERT(s3_ssh3_compress_decode(plain, sizeof(plain), &plain_len, alg, packed,
                                          packed_len) == S3_OK);
        S3_ASSERT(plain_len == payload_len);
        S3_ASSERT(memcmp(plain, payload, payload_len) == 0);

        /* the bound is the worst case of the compressed size */

        S3_ASSERT(s3_ssh3_compress_bound(alg, payload_len) >= packed_len);
    }

    return s3_test_failures;
}

static int
s3_test_compress_cutoff(void)
{
    u_char   payload[4096];
    u_char   packed[8192];
    size_t   payload_len;
    size_t   packed_len;
    uint32_t available = s3_ssh3_compress_available();
    uint32_t alg;
    uint32_t seed = 0xdeadbeefu;
    size_t   i;

    /* a purely noisy payload does not compress: the cutoff keeps it as
     * it is (the codec declines, or the compressed form is not
     * smaller) */

    for (i = 0; i < sizeof(payload); i++) {
        seed = seed * 1103515245u + 12345u;
        payload[i] = (u_char)(seed >> 16);
    }

    payload_len = sizeof(payload);

    for (alg = 1; alg <= 3; alg++) {

        uint32_t bit = 0;
        s3_int_t rc;

        if (alg == S3_SSH3_COMPRESS_DEFLATE) {
            bit = S3_SSH3_COMPRESS_M_DEFLATE;
        } else if (alg == S3_SSH3_COMPRESS_LZ4) {
            bit = S3_SSH3_COMPRESS_M_LZ4;
        } else {
            bit = S3_SSH3_COMPRESS_M_ZSTD;
        }

        if ((available & bit) == 0) {
            continue;
        }

        packed_len = 0;

        rc = s3_ssh3_compress_encode(packed, sizeof(packed), &packed_len, alg, payload, payload_len);

        if (rc == S3_DECLINED) {
            continue; /* the codec refused: the frame travels as it is */
        }

        S3_ASSERT(rc == S3_OK);

        /* the caller sends the payload as it is when the compressed
         * form is not smaller */

        S3_ASSERT(packed_len >= payload_len);
    }

    return s3_test_failures;
}

static int
s3_test_compress_bomb(void)
{
    u_char   payload[8192];
    u_char   packed[16384];
    u_char   plain[64];
    size_t   payload_len;
    size_t   packed_len;
    size_t   plain_len;
    uint32_t available = s3_ssh3_compress_available();
    uint32_t alg;

    payload_len = s3_compress_payload(payload, sizeof(payload), 0);

    for (alg = 1; alg <= 3; alg++) {

        uint32_t bit = 0;

        if (alg == S3_SSH3_COMPRESS_DEFLATE) {
            bit = S3_SSH3_COMPRESS_M_DEFLATE;
        } else if (alg == S3_SSH3_COMPRESS_LZ4) {
            bit = S3_SSH3_COMPRESS_M_LZ4;
        } else {
            bit = S3_SSH3_COMPRESS_M_ZSTD;
        }

        if ((available & bit) == 0) {
            continue;
        }

        packed_len = 0;

        S3_ASSERT(s3_ssh3_compress_encode(packed, sizeof(packed), &packed_len, alg, payload,
                                          payload_len) == S3_OK);

        /* a frame that wants more room than the buffer has is refused:
         * the bomb limit */

        plain_len = 0;

        S3_ASSERT(s3_ssh3_compress_decode(plain, sizeof(plain), &plain_len, alg, packed,
                                          packed_len) == S3_ERROR);
    }

    return s3_test_failures;
}

static int
s3_test_compress_frame(void)
{
    s3_ssh3_msg_compressed_data_t m;
    s3_ssh3_msg_compressed_data_t parsed;
    u_char                       buf[256];
    u_char                       wire[256];
    const u_char                *pos;
    size_t                       len;

    s3_memzero(&m, sizeof(m));

    m.algorithm = S3_SSH3_COMPRESS_ZSTD;
    m.data.len = 5;
    m.data.data = (u_char *)"hello";

    len = (size_t)s3_ssh3_msg_encode_compressed_data(NULL, &m);

    S3_ASSERT(len > 0);
    S3_ASSERT(len <= sizeof(wire));

    s3_ssh3_msg_encode_compressed_data(wire, &m);

    pos = wire;

    S3_ASSERT(s3_ssh3_msg_parse_compressed_data(&pos, wire + len, &parsed) == S3_OK);
    S3_ASSERT(parsed.algorithm == S3_SSH3_COMPRESS_ZSTD);
    S3_ASSERT(parsed.data.len == 5);
    S3_ASSERT(memcmp(parsed.data.data, "hello", 5) == 0);
    S3_ASSERT(pos == wire + len);

    /* a truncated body is refused and leaves the cursor untouched */

    pos = wire;

    S3_ASSERT(s3_ssh3_msg_parse_compressed_data(&pos, wire + 1, &parsed) == S3_ERROR);
    S3_ASSERT(pos == wire);

    (void)buf;

    return s3_test_failures;
}

static int
s3_test_compress_version(void)
{
    u_char          version[128];
    size_t          len;
    s3_ssh3_version_t v;

    len = s3_ssh3_version_string(version, sizeof(version));

    S3_ASSERT(len > 0);
    S3_ASSERT(len < sizeof(version));

    s3_memzero(&v, sizeof(v));

    S3_ASSERT(s3_ssh3_version_parse(version, len, &v) == S3_OK);
    S3_ASSERT(v.compress_mask == s3_ssh3_compress_available());
    S3_ASSERT(s3_ssh3_version_supported(&v) == S3_OK);

    /* an old peer (no capability field) gives the zero mask */

    {
        static const u_char old[] = "SSH 3.0 ssh3-c 0.5.2 experimental_spec_version=alpha-00";

        s3_memzero(&v, sizeof(v));

        S3_ASSERT(s3_ssh3_version_parse(old, s3_strlen(old), &v) == S3_OK);
        S3_ASSERT(v.compress_mask == 0);
    }

    return s3_test_failures;
}

int
s3_test_ssh3_compress(void)
{
    s3_test_compress_capability();
    s3_test_compress_choose();
    s3_test_compress_roundtrip();
    s3_test_compress_cutoff();
    s3_test_compress_bomb();
    s3_test_compress_frame();
    s3_test_compress_version();

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_ssh3_compress)
