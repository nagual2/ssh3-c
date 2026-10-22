/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the channel-body compression (PLAN.md 9, B8): the codecs, the
 * capability token of the version string and the compressed frame
 */

#include <s3_core.h>

#include <string.h>

#include <s3_ssh3_compress.h>
#include <s3_ssh3_frame.h>
#include <s3_ssh3_message.h>
#include <s3_ssh3_version.h>
#include <s3_ssh3_wire.h>

#include "s3_test.h"

#if (S3_HAVE_LZ4)
#include <lz4.h>
#endif

#if (S3_HAVE_ZSTD)
#include <zstd.h>
#endif

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
    char   cap_text[65];
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

    /* the list names the codecs of the build: the zstd and the lz4 ride
     * the token when the codecs are compiled in */

    s3_memcpy(cap_text, cap_buf, cap_len);
    cap_text[cap_len] = '\0';

#if (S3_HAVE_ZSTD)
    S3_ASSERT(strstr(cap_text, "zstd") != NULL);
#endif

#if (S3_HAVE_LZ4)
    S3_ASSERT(strstr(cap_text, "lz4") != NULL);
#endif

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

/*
 * the names of the codecs: the word of the flag and the word of the
 * capability list are the same
 */

static int
s3_test_compress_names(void)
{
    S3_ASSERT(s3_ssh3_compress_by_name((const u_char *)"zstd", 4) == S3_SSH3_COMPRESS_ZSTD);
    S3_ASSERT(s3_ssh3_compress_by_name((const u_char *)"deflate", 7) == S3_SSH3_COMPRESS_DEFLATE);
    S3_ASSERT(s3_ssh3_compress_by_name((const u_char *)"lz4", 3) == S3_SSH3_COMPRESS_LZ4);

    /* the case does not matter */

    S3_ASSERT(s3_ssh3_compress_by_name((const u_char *)"ZSTD", 4) == S3_SSH3_COMPRESS_ZSTD);

    /* the plain id of the wire rides the name too */

    S3_ASSERT(s3_ssh3_compress_by_name((const u_char *)"3", 1) == S3_SSH3_COMPRESS_ZSTD);
    S3_ASSERT(s3_ssh3_compress_by_name((const u_char *)"1", 1) == S3_SSH3_COMPRESS_DEFLATE);
    S3_ASSERT(s3_ssh3_compress_by_name((const u_char *)"2", 1) == S3_SSH3_COMPRESS_LZ4);

    /* an unknown name is no codec at all */

    S3_ASSERT(s3_ssh3_compress_by_name((const u_char *)"nosuch", 5) == S3_SSH3_COMPRESS_NONE);
    S3_ASSERT(s3_ssh3_compress_by_name((const u_char *)"", 0) == S3_SSH3_COMPRESS_NONE);
    S3_ASSERT(s3_ssh3_compress_by_name((const u_char *)"4", 1) == S3_SSH3_COMPRESS_NONE);

    /* the name back: the table of the capability list */

    S3_ASSERT(strcmp(s3_ssh3_compress_name(S3_SSH3_COMPRESS_ZSTD), "zstd") == 0);
    S3_ASSERT(strcmp(s3_ssh3_compress_name(S3_SSH3_COMPRESS_DEFLATE), "deflate") == 0);
    S3_ASSERT(strcmp(s3_ssh3_compress_name(S3_SSH3_COMPRESS_LZ4), "lz4") == 0);
    S3_ASSERT(s3_ssh3_compress_name(S3_SSH3_COMPRESS_NONE)[0] == '\0');

    /* the bit of the capability: the bit of the name */

    S3_ASSERT(s3_ssh3_compress_bit(S3_SSH3_COMPRESS_ZSTD) == S3_SSH3_COMPRESS_M_ZSTD);
    S3_ASSERT(s3_ssh3_compress_bit(S3_SSH3_COMPRESS_DEFLATE) == S3_SSH3_COMPRESS_M_DEFLATE);
    S3_ASSERT(s3_ssh3_compress_bit(S3_SSH3_COMPRESS_LZ4) == S3_SSH3_COMPRESS_M_LZ4);
    S3_ASSERT(s3_ssh3_compress_bit(S3_SSH3_COMPRESS_NONE) == 0);

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

    /*
     * the preference order: zstd (the best ratio per cpu), deflate
     * (the zlib of the ZFS gzip), lz4 (the fastest)
     */

    S3_ASSERT(s3_ssh3_compress_prefer(S3_SSH3_COMPRESS_M_ZSTD) == S3_SSH3_COMPRESS_ZSTD);
    S3_ASSERT(s3_ssh3_compress_prefer(S3_SSH3_COMPRESS_M_DEFLATE) == S3_SSH3_COMPRESS_DEFLATE);
    S3_ASSERT(s3_ssh3_compress_prefer(S3_SSH3_COMPRESS_M_LZ4) == S3_SSH3_COMPRESS_LZ4);

    S3_ASSERT(s3_ssh3_compress_prefer(S3_SSH3_COMPRESS_M_ZSTD | S3_SSH3_COMPRESS_M_DEFLATE
                                       | S3_SSH3_COMPRESS_M_LZ4)
           == S3_SSH3_COMPRESS_ZSTD);
    S3_ASSERT(s3_ssh3_compress_prefer(S3_SSH3_COMPRESS_M_DEFLATE | S3_SSH3_COMPRESS_M_LZ4)
           == S3_SSH3_COMPRESS_DEFLATE);
    S3_ASSERT(s3_ssh3_compress_prefer(S3_SSH3_COMPRESS_M_ZSTD | S3_SSH3_COMPRESS_M_LZ4)
           == S3_SSH3_COMPRESS_ZSTD);
    S3_ASSERT(s3_ssh3_compress_prefer(0) == S3_SSH3_COMPRESS_NONE);

    /* the negotiation takes the best of the peer mask and the build */

    S3_ASSERT(s3_ssh3_compress_choose(0xffffffffu)
               == s3_ssh3_compress_prefer(0xffffffffu & available));

    /* the zstd wins the negotiation when the peer has it */

    if ((available & S3_SSH3_COMPRESS_M_ZSTD) != 0) {
        S3_ASSERT(s3_ssh3_compress_choose(S3_SSH3_COMPRESS_M_ZSTD | S3_SSH3_COMPRESS_M_LZ4)
                   == S3_SSH3_COMPRESS_ZSTD);
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

static int
s3_test_compress_ctx(void)
{
    u_char                    payload[512];
    u_char                    compressed[4096];
    u_char                    plain[4096];
    size_t                    payload_len;
    size_t                    packed = 0;
    size_t                    packed_two = 0;
    size_t                    plain_len = 0;
    uint32_t                  available = s3_ssh3_compress_available();
    uint32_t                  codecs[3] = { S3_SSH3_COMPRESS_ZSTD, S3_SSH3_COMPRESS_DEFLATE,
                                            S3_SSH3_COMPRESS_LZ4 };
    size_t                    i;

    /* the contexts of the audit fix wave: the codec state is created
     * once per channel and reset per frame */

    S3_ASSERT(s3_ssh3_compress_ctx_create(S3_SSH3_COMPRESS_NONE, 0) == NULL);
    S3_ASSERT(s3_ssh3_compress_ctx_algorithm(NULL) == S3_SSH3_COMPRESS_NONE);

    s3_ssh3_compress_ctx_destroy(NULL); /* the no-op form */

    payload_len = s3_compress_payload(payload, sizeof(payload), 64);

    for (i = 0; i < 3; i++) {

        s3_ssh3_compress_ctx_t *enc;
        s3_ssh3_compress_ctx_t *dec;

        if ((available & s3_ssh3_compress_bit(codecs[i])) == 0) {
            continue;
        }

        enc = s3_ssh3_compress_ctx_create(codecs[i], 0);
        dec = s3_ssh3_compress_ctx_create(codecs[i], 1);

        S3_ASSERT(enc != NULL);
        S3_ASSERT(dec != NULL);
        S3_ASSERT(s3_ssh3_compress_ctx_algorithm(enc) == codecs[i]);

        /* the reuse: two frames ride the same context back to back */

        S3_ASSERT(s3_ssh3_compress_ctx_encode(enc, compressed, sizeof(compressed), &packed,
                                              payload, payload_len) == S3_OK);
        S3_ASSERT(s3_ssh3_compress_ctx_encode(enc, compressed, sizeof(compressed), &packed_two,
                                              payload, payload_len) == S3_OK);
        S3_ASSERT(packed == packed_two);

        S3_ASSERT(s3_ssh3_compress_ctx_decode(dec, plain, sizeof(plain), &plain_len, compressed,
                                              packed) == S3_OK);
        S3_ASSERT(plain_len == payload_len);
        S3_ASSERT(memcmp(plain, payload, payload_len) == 0);

        /* the halves do not cross: the decode context cannot encode */

        S3_ASSERT(s3_ssh3_compress_ctx_encode(dec, compressed, sizeof(compressed), &packed,
                                              payload, payload_len) == S3_ERROR);

        s3_ssh3_compress_ctx_destroy(enc);
        s3_ssh3_compress_ctx_destroy(dec);
    }

    return s3_test_failures;
}

static int
s3_test_compress_frame_gate(void)
{
    s3_ssh3_msg_compressed_data_t m;
    u_char                        payload[512];
    u_char                        frame[8192];
    u_char                        scratch[8192];
    size_t                        payload_len;
    size_t                        frame_len = 0;
    size_t                        wire_len = 0;
    const u_char                 *pos;
    s3_str_t                      out;
    uint32_t                      available = s3_ssh3_compress_available();
    s3_ssh3_compress_ctx_t       *enc;

    payload_len = s3_compress_payload(payload, sizeof(payload), 64);

    /* the NULL context builds the plain frame and refuses the
     * compressed one (the fail-closed gate of the audit fix wave) */

    /* the NULL context decodes the legal frame through the one-shot
     * form; the refusal rides the mask, not the context */

    S3_ASSERT(s3_ssh3_frame_data_build(frame, sizeof(frame), &frame_len, NULL, payload,
                                       payload_len, &wire_len) == S3_OK);
    S3_ASSERT(wire_len == payload_len);

    s3_memzero(&m, sizeof(m));

    m.algorithm = S3_SSH3_COMPRESS_ZSTD;
    m.data.len = 5;
    m.data.data = (u_char *)"hello";

    {
        u_char             msg[64];
        u_char            *p;
        size_t             len;
        const u_char      *pt;
        uint64_t           t;

        len = (size_t)s3_ssh3_msg_encode_compressed_data(NULL, &m);
        S3_ASSERT(len > 0 && len <= sizeof(msg));
        s3_ssh3_msg_encode_compressed_data(msg, &m);

        /* the type varint of the compressed frame rides first */

        p = frame;
        p = (u_char *)s3_ssh3_encode_varint(p, S3_SSH3_MSG_CHANNEL_DATA_COMPRESSED);
        memcpy(p, msg, len);

        /* the seam reads past the type varint, like the callers do */

        pt = frame;

        S3_ASSERT(s3_ssh3_parse_varint(&pt, frame + (size_t)(p - frame) + len, &t) == S3_OK);
        S3_ASSERT(t == S3_SSH3_MSG_CHANNEL_DATA_COMPRESSED);

        /* the mask of zero (the build without codecs, the peer that
         * announced nothing) refuses the frame outright - the refusal
         * rides before any decode, so the placeholder body is fine */

        pt = frame;

        S3_ASSERT(s3_ssh3_frame_data_parse(&pt, frame + (size_t)(p - frame) + len, t, 0, NULL,
                                           scratch, sizeof(scratch), &out) == S3_DECLINED);

        /* an id outside the announced mask is a protocol violation */

        m.algorithm = 7;

        len = (size_t)s3_ssh3_msg_encode_compressed_data(NULL, &m);
        S3_ASSERT(len > 0 && len <= sizeof(msg));
        s3_ssh3_msg_encode_compressed_data(msg, &m);

        p = frame;
        p = (u_char *)s3_ssh3_encode_varint(p, S3_SSH3_MSG_CHANNEL_DATA_COMPRESSED);
        memcpy(p, msg, len);

        pt = frame;

        S3_ASSERT(s3_ssh3_parse_varint(&pt, frame + (size_t)(p - frame) + len, &t) == S3_OK);
        S3_ASSERT(s3_ssh3_frame_data_parse(&pt, frame + (size_t)(p - frame) + len, t,
                                           s3_ssh3_compress_available(), NULL, scratch,
                                           sizeof(scratch), &out) == S3_DECLINED);
    }

    if (available == 0) {
        /* a build without a codec has nothing else to probe */
        return s3_test_failures;
    }

    /* the negotiated codec round-trips through the seam */

    enc = s3_ssh3_compress_ctx_create(S3_SSH3_COMPRESS_ZSTD, 0);

    if (enc == NULL) {
        /* the zstd is not in the build: the deflate and the lz4 ride
         * the same gate, one codec of the build proves the shape */

        enc = s3_ssh3_compress_ctx_create(S3_SSH3_COMPRESS_DEFLATE, 0);
    }

    if (enc == NULL) {
        enc = s3_ssh3_compress_ctx_create(S3_SSH3_COMPRESS_LZ4, 0);
    }

    S3_ASSERT(enc != NULL);

    S3_ASSERT(s3_ssh3_frame_data_build(frame, sizeof(frame), &frame_len, enc, payload, payload_len,
                                       &wire_len) == S3_OK);
    S3_ASSERT(wire_len < payload_len); /* the compressible payload rides the 192 */

    {
        s3_ssh3_compress_ctx_t *dec =
            s3_ssh3_compress_ctx_create(s3_ssh3_compress_ctx_algorithm(enc), 1);
        uint64_t                t;

        pos = frame;

        S3_ASSERT(dec != NULL);
        S3_ASSERT(s3_ssh3_parse_varint(&pos, frame + frame_len, &t) == S3_OK);
        S3_ASSERT(s3_ssh3_frame_data_parse(&pos, frame + frame_len, t, s3_ssh3_compress_available(),
                                           dec, scratch, sizeof(scratch), &out) == S3_OK);
        S3_ASSERT(out.len == payload_len);
        S3_ASSERT(memcmp(out.data, payload, payload_len) == 0);

        /* the NULL context decodes the same legal frame through the
         * one-shot form: the refusal rides the mask, not the context */

        pos = frame;

        S3_ASSERT(s3_ssh3_parse_varint(&pos, frame + frame_len, &t) == S3_OK);

        S3_ASSERT(s3_ssh3_frame_data_parse(&pos, frame + frame_len, t, s3_ssh3_compress_available(),
                                           NULL, scratch, sizeof(scratch), &out) == S3_OK);
        S3_ASSERT(out.len == payload_len);
        S3_ASSERT(memcmp(out.data, payload, payload_len) == 0);

        /* the id of the wire must sit in the announced mask: a frame
         * on a side that announced nothing is a protocol violation
         * even with a context */

        {
            uint64_t t2;

            pos = frame;

            S3_ASSERT(s3_ssh3_parse_varint(&pos, frame + frame_len, &t2) == S3_OK);
            S3_ASSERT(s3_ssh3_frame_data_parse(&pos, frame + frame_len, t2, 0, dec, scratch,
                                               sizeof(scratch), &out) == S3_DECLINED);
        }

        s3_ssh3_compress_ctx_destroy(dec);
    }

    /* the >32-bit id on the wire is refused before the truncation */

    s3_memzero(&m, sizeof(m));

    m.algorithm = 0x100000001ull + S3_SSH3_COMPRESS_ZSTD;
    m.data.len = 5;
    m.data.data = (u_char *)"hello";

    {
        u_char        msg[64];
        u_char       *p;
        size_t        len;
        const u_char *pt;
        uint64_t      t;
        s3_ssh3_compress_ctx_t *dec;

        len = (size_t)s3_ssh3_msg_encode_compressed_data(NULL, &m);
        S3_ASSERT(len > 0 && len <= sizeof(msg));
        s3_ssh3_msg_encode_compressed_data(msg, &m);

        p = frame;
        p = (u_char *)s3_ssh3_encode_varint(p, S3_SSH3_MSG_CHANNEL_DATA_COMPRESSED);
        memcpy(p, msg, len);

        dec = s3_ssh3_compress_ctx_create(S3_SSH3_COMPRESS_ZSTD, 1);

        if (dec != NULL) {

            pt = frame;

            S3_ASSERT(s3_ssh3_parse_varint(&pt, frame + (size_t)(p - frame) + len, &t) == S3_OK);
            S3_ASSERT(s3_ssh3_frame_data_parse(&pt, frame + (size_t)(p - frame) + len, t,
                                               s3_ssh3_compress_available(), dec, scratch,
                                               sizeof(scratch), &out) == S3_DECLINED);
        }

        s3_ssh3_compress_ctx_destroy(dec);
    }

    s3_ssh3_compress_ctx_destroy(enc);

    return s3_test_failures;
}

int
s3_test_ssh3_compress(void)
{
    s3_test_compress_capability();
    s3_test_compress_names();
    s3_test_compress_choose();
    s3_test_compress_roundtrip();
    s3_test_compress_cutoff();
    s3_test_compress_bomb();
    s3_test_compress_ctx();
    s3_test_compress_frame();
    s3_test_compress_frame_gate();
    s3_test_compress_version();

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_ssh3_compress)
