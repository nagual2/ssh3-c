/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the channel-body compression (PLAN.md 9, B8): the codecs and the
 * capability token
 */

#include <s3_core.h>

#include <string.h>

#include <s3_ssh3_compress.h>

#if (S3_HAVE_ZLIB)
#include <zlib.h>
#endif

#if (S3_HAVE_ZSTD)
#include <zstd.h>
#endif

#if (S3_HAVE_LZ4)
#include <lz4.h>
#endif

uint32_t
s3_ssh3_compress_available(void)
{
    uint32_t mask = 0;

#if (S3_HAVE_ZLIB)
    mask |= S3_SSH3_COMPRESS_M_DEFLATE;
#endif

#if (S3_HAVE_LZ4)
    mask |= S3_SSH3_COMPRESS_M_LZ4;
#endif

#if (S3_HAVE_ZSTD)
    mask |= S3_SSH3_COMPRESS_M_ZSTD;
#endif

    return mask;
}

/*
 * the names of the algorithms in the capability list, in the order the
 * token writes them; the order is also the preference order of the
 * negotiation
 */

static const struct {
    const char *name;
    size_t      len;
    uint32_t    bit;
    uint32_t    algorithm;
} s3_compress_algorithms[] = {
    {"zstd", 4, S3_SSH3_COMPRESS_M_ZSTD, S3_SSH3_COMPRESS_ZSTD},
    {"deflate", 7, S3_SSH3_COMPRESS_M_DEFLATE, S3_SSH3_COMPRESS_DEFLATE},
    {"lz4", 3, S3_SSH3_COMPRESS_M_LZ4, S3_SSH3_COMPRESS_LZ4},
};

#define S3_COMPRESS_ALGORITHMS (sizeof(s3_compress_algorithms) / sizeof(s3_compress_algorithms[0]))

/*
 * the case-insensitive comparison of the name with the table entry
 */

static int
s3_compress_name_eq(const u_char *name, size_t len, const char *want, size_t want_len)
{
    size_t i;

    if (len != want_len) {
        return 0;
    }

    for (i = 0; i < len; i++) {

        u_char c = name[i];

        if (c >= 'A' && c <= 'Z') {
            c = (u_char)(c - 'A' + 'a');
        }

        if (c != (u_char)want[i]) {
            return 0;
        }
    }

    return 1;
}

uint32_t
s3_ssh3_compress_by_name(const u_char *name, size_t len)
{
    size_t   i;
    uint32_t value = 0;
    size_t   digits = 0;

    /* the plain id of the algorithm ("3", "1", "2") is accepted too:
     * the ids of the wire are the numbers of the table below */

    for (i = 0; i < len; i++) {

        if (name[i] < '0' || name[i] > '9') {
            break;
        }

        value = value * 10 + (uint32_t)(name[i] - '0');
        digits++;
    }

    if (digits == len && digits > 0) {

        for (i = 0; i < S3_COMPRESS_ALGORITHMS; i++) {
            if (s3_compress_algorithms[i].algorithm == value) {
                return value;
            }
        }

        return S3_SSH3_COMPRESS_NONE;
    }

    for (i = 0; i < S3_COMPRESS_ALGORITHMS; i++) {
        if (s3_compress_name_eq(name, len, s3_compress_algorithms[i].name,
                                s3_compress_algorithms[i].len)) {
            return s3_compress_algorithms[i].algorithm;
        }
    }

    return S3_SSH3_COMPRESS_NONE;
}

const char *
s3_ssh3_compress_name(uint32_t algorithm)
{
    size_t i;

    for (i = 0; i < S3_COMPRESS_ALGORITHMS; i++) {
        if (s3_compress_algorithms[i].algorithm == algorithm) {
            return s3_compress_algorithms[i].name;
        }
    }

    return "";
}

uint32_t
s3_ssh3_compress_bit(uint32_t algorithm)
{
    size_t i;

    for (i = 0; i < S3_COMPRESS_ALGORITHMS; i++) {
        if (s3_compress_algorithms[i].algorithm == algorithm) {
            return s3_compress_algorithms[i].bit;
        }
    }

    return 0;
}

uint32_t
s3_ssh3_compress_parse(const u_char *data, size_t len)
{
    uint32_t mask = 0;
    size_t   pos = 0;

    /* the value is a comma-separated list of the algorithm names; an
     * unknown name is skipped (a newer peer may announce more) */

    while (pos < len) {

        size_t   start = pos;
        size_t   n;
        size_t   i;
        uint32_t bit = 0;

        while (pos < len && data[pos] != S3_SSH3_COMPRESS_SEP) {
            pos++;
        }

        n = pos - start;

        for (i = 0; i < S3_COMPRESS_ALGORITHMS; i++) {
            if (s3_compress_algorithms[i].len == n &&
                s3_memcmp(data + start, s3_compress_algorithms[i].name, n) == 0) {
                bit = s3_compress_algorithms[i].bit;
                break;
            }
        }

        if (bit != 0) {
            mask |= bit;
        }

        if (pos < len) {
            pos++; /* the separator */
        }
    }

    return mask;
}

size_t
s3_ssh3_compress_capability(u_char *buf, size_t cap)
{
    uint32_t available = s3_ssh3_compress_available();
    size_t   len = 0;
    size_t   i;

    for (i = 0; i < S3_COMPRESS_ALGORITHMS; i++) {

        const char *name;
        size_t      name_len;

        if ((available & s3_compress_algorithms[i].bit) == 0) {
            continue;
        }

        name = s3_compress_algorithms[i].name;
        name_len = s3_compress_algorithms[i].len;

        if (len > 0) {
            if (len + 1 > cap) {
                break;
            }
            buf[len++] = S3_SSH3_COMPRESS_SEP;
        }

        if (len + name_len > cap) {
            break;
        }

        s3_memcpy(buf + len, name, name_len);
        len += name_len;
    }

    return len;
}

uint32_t
s3_ssh3_compress_prefer(uint32_t mask)
{
    size_t i;

    for (i = 0; i < S3_COMPRESS_ALGORITHMS; i++) {
        if ((mask & s3_compress_algorithms[i].bit) != 0) {
            return s3_compress_algorithms[i].algorithm;
        }
    }

    return S3_SSH3_COMPRESS_NONE;
}

uint32_t
s3_ssh3_compress_choose(uint32_t peer_mask)
{
    return s3_ssh3_compress_prefer(peer_mask & s3_ssh3_compress_available());
}

size_t
s3_ssh3_compress_bound(uint32_t algorithm, size_t in_len)
{
    size_t bound = 0;

    /* a codec-less build (the windows-core cross) has no case below
     * to consume in_len - the cast keeps the parameter named */

    (void)in_len;

    switch (algorithm) {

#if (S3_HAVE_ZLIB)
    case S3_SSH3_COMPRESS_DEFLATE:
        bound = (size_t)compressBound((uLong)in_len);
        break;
#endif

#if (S3_HAVE_LZ4)
    case S3_SSH3_COMPRESS_LZ4:
        bound = (size_t)LZ4_COMPRESSBOUND((int)in_len);
        break;
#endif

#if (S3_HAVE_ZSTD)
    case S3_SSH3_COMPRESS_ZSTD:
        bound = ZSTD_compressBound(in_len);
        break;
#endif

    default:
        break;
    }

    return bound;
}

/*
 * the channel codec context: the algorithm, the side and the resident
 * state of the codec (the zlib stream or the zstd context); the audit
 * fix wave of the 2026-10-22 review moved the state here from the
 * per-frame init/free of the one-shot forms
 */

struct s3_ssh3_compress_ctx_s {
    uint32_t algorithm;
    unsigned decode; /* 0 = the encode side, 1 = the decode side */

#if (S3_HAVE_ZLIB)
    z_stream z;
    int      z_live; /* the deflateInit2/inflateInit2 is out */
#endif

#if (S3_HAVE_ZSTD)
    void *zstd; /* ZSTD_CCtx (encode) or ZSTD_DCtx (decode) */
#endif
};

s3_ssh3_compress_ctx_t *
s3_ssh3_compress_ctx_create(uint32_t algorithm, unsigned decode)
{
    s3_ssh3_compress_ctx_t *ctx;

    switch (algorithm) {

#if (S3_HAVE_ZLIB)
    case S3_SSH3_COMPRESS_DEFLATE:
#endif

#if (S3_HAVE_LZ4)
    case S3_SSH3_COMPRESS_LZ4:
#endif

#if (S3_HAVE_ZSTD)
    case S3_SSH3_COMPRESS_ZSTD:
#endif
        break;

    default:
        return NULL;
    }

    ctx = malloc(sizeof(*ctx));

    if (ctx == NULL) {
        return NULL;
    }

    s3_memzero(ctx, sizeof(*ctx));

    ctx->algorithm = algorithm;
    ctx->decode = decode;

#if (S3_HAVE_ZLIB)

    if (algorithm == S3_SSH3_COMPRESS_DEFLATE) {

        /* the raw deflate form (windowBits -15): the algorithm id on
         * the wire tells the peer the stream carries no zlib header,
         * which saves the six bytes of it on every frame */

        int rc = decode ? inflateInit2(&ctx->z, -15)
                        : deflateInit2(&ctx->z, S3_SSH3_COMPRESS_DEFLATE_LEVEL, Z_DEFLATED,
                                       -15, 8, Z_DEFAULT_STRATEGY);

        if (rc != Z_OK) {
            free(ctx);
            return NULL;
        }

        ctx->z_live = 1;
    }

#endif

#if (S3_HAVE_ZSTD)

    if (algorithm == S3_SSH3_COMPRESS_ZSTD) {

        ctx->zstd = decode ? (void *) ZSTD_createDCtx() : (void *) ZSTD_createCCtx();

        if (ctx->zstd == NULL) {
            free(ctx);
            return NULL;
        }
    }

#endif

    return ctx;
}

uint32_t
s3_ssh3_compress_ctx_algorithm(const s3_ssh3_compress_ctx_t *ctx)
{
    return (ctx != NULL) ? ctx->algorithm : S3_SSH3_COMPRESS_NONE;
}

void
s3_ssh3_compress_ctx_destroy(s3_ssh3_compress_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

#if (S3_HAVE_ZLIB)

    if (ctx->z_live) {

        if (ctx->decode) {
            (void) inflateEnd(&ctx->z);
        } else {
            (void) deflateEnd(&ctx->z);
        }
    }

#endif

#if (S3_HAVE_ZSTD)

    if (ctx->zstd != NULL) {

        if (ctx->decode) {
            (void) ZSTD_freeDCtx(ctx->zstd);
        } else {
            (void) ZSTD_freeCCtx(ctx->zstd);
        }
    }

#endif

    free(ctx);
}

s3_int_t
s3_ssh3_compress_ctx_encode(s3_ssh3_compress_ctx_t *ctx, u_char *out, size_t cap, size_t *out_len,
                            const u_char *in, size_t in_len)
{
    /* a codec-less build has no case below to consume the buffer */

    (void)out;
    (void)cap;
    (void)out_len;
    (void)in;
    (void)in_len;

    if (ctx == NULL || ctx->decode) {
        /* the resident state belongs to the decode side, the wrong
         * side would hand the decompressor to the compressor */

        return S3_ERROR;
    }

    switch (ctx->algorithm) {

#if (S3_HAVE_ZLIB)
    case S3_SSH3_COMPRESS_DEFLATE: {
        int rc;

        /* the reset rewinds the state on the resident allocation: the
         * per-frame init/free of the one-shot form never runs here */

        if (deflateReset(&ctx->z) != Z_OK) {
            return S3_ERROR;
        }

        ctx->z.next_in = (Bytef *) in;
        ctx->z.avail_in = (uInt) in_len;
        ctx->z.next_out = out;
        ctx->z.avail_out = (uInt) cap;

        rc = deflate(&ctx->z, Z_FINISH);

        if (rc != Z_STREAM_END) {
            return S3_ERROR;
        }

        *out_len = (size_t) ctx->z.total_out;

        return S3_OK;
    }
#endif

#if (S3_HAVE_LZ4)
    case S3_SSH3_COMPRESS_LZ4: {
        int n;

        n = LZ4_compress_default((const char *) in, (char *) out, (int) in_len, (int) cap);

        if (n == 0) {
            /* the codec refuses the payload: the compressed form does
             * not fit the bound, so the frame travels as it is (the
             * ZFS cutoff) */

            return S3_DECLINED;
        }

        if (n < 0) {
            return S3_ERROR;
        }

        *out_len = (size_t) n;

        return S3_OK;
    }
#endif

#if (S3_HAVE_ZSTD)
    case S3_SSH3_COMPRESS_ZSTD: {
        size_t n;

        n = ZSTD_compressCCtx(ctx->zstd, out, cap, in, in_len, S3_SSH3_COMPRESS_ZSTD_LEVEL);

        if (ZSTD_isError(n)) {
            return S3_ERROR;
        }

        *out_len = n;

        return S3_OK;
    }
#endif

    default:
        return S3_ERROR;
    }
}

s3_int_t
s3_ssh3_compress_ctx_decode(s3_ssh3_compress_ctx_t *ctx, u_char *out, size_t cap, size_t *out_len,
                            const u_char *in, size_t in_len)
{
    /* a codec-less build has no case below to consume the buffer
     * (cap rides the bomb limit below) */

    (void)out;
    (void)out_len;
    (void)in;
    (void)in_len;

    if (ctx == NULL || !ctx->decode) {
        /* the encode-side state never decodes */

        return S3_ERROR;
    }

    /* the bomb limit: the output buffer never exceeds the channel
     * packet limit, whatever the frame claims */

    if (cap > S3_SSH3_COMPRESS_MAX_OUTPUT) {
        cap = S3_SSH3_COMPRESS_MAX_OUTPUT;
    }

    switch (ctx->algorithm) {

#if (S3_HAVE_ZLIB)
    case S3_SSH3_COMPRESS_DEFLATE: {
        int rc;

        if (inflateReset(&ctx->z) != Z_OK) {
            return S3_ERROR;
        }

        ctx->z.next_in = (Bytef *) in;
        ctx->z.avail_in = (uInt) in_len;
        ctx->z.next_out = out;
        ctx->z.avail_out = (uInt) cap;

        rc = inflate(&ctx->z, Z_FINISH);

        if (rc != Z_STREAM_END) {
            /* the frame is truncated, corrupt, or wants more room than
             * the limit allows (Z_BUF_ERROR) */

            return S3_ERROR;
        }

        *out_len = (size_t) ctx->z.total_out;

        return S3_OK;
    }
#endif

#if (S3_HAVE_LZ4)
    case S3_SSH3_COMPRESS_LZ4: {
        int n;

        n = LZ4_decompress_safe((const char *) in, (char *) out, (int) in_len, (int) cap);

        if (n < 0) {
            return S3_ERROR;
        }

        *out_len = (size_t) n;

        return S3_OK;
    }
#endif

#if (S3_HAVE_ZSTD)
    case S3_SSH3_COMPRESS_ZSTD: {
        unsigned long long size;
        size_t             n;

        size = ZSTD_getFrameContentSize(in, in_len);

        if (size == ZSTD_CONTENTSIZE_ERROR || size == ZSTD_CONTENTSIZE_UNKNOWN) {
            /* the frame does not carry its size: the decoder cannot
             * bound it, so the frame is refused */

            return S3_ERROR;
        }

        if (size > cap) {
            return S3_ERROR;
        }

        n = ZSTD_decompressDCtx(ctx->zstd, out, cap, in, in_len);

        if (ZSTD_isError(n)) {
            return S3_ERROR;
        }

        *out_len = n;

        return S3_OK;
    }
#endif

    default:
        return S3_ERROR;
    }
}

s3_int_t
s3_ssh3_compress_encode(u_char *out, size_t cap, size_t *out_len, uint32_t algorithm,
                        const u_char *in, size_t in_len)
{
    /* a codec-less build has no case below to consume the buffer */

    (void)out;
    (void)cap;
    (void)out_len;
    (void)in;
    (void)in_len;

    switch (algorithm) {

#if (S3_HAVE_ZLIB)
    case S3_SSH3_COMPRESS_DEFLATE: {
        z_stream s;

        s3_memzero(&s, sizeof(s));

        /* the raw deflate form (windowBits -15): the algorithm id on
         * the wire tells the peer the stream carries no zlib header,
         * which saves the six bytes of it on every frame */

        if (deflateInit2(&s, S3_SSH3_COMPRESS_DEFLATE_LEVEL, Z_DEFLATED, -15, 8,
                         Z_DEFAULT_STRATEGY) != Z_OK) {
            return S3_ERROR;
        }

        s.next_in = (Bytef *)in;
        s.avail_in = (uInt)in_len;
        s.next_out = out;
        s.avail_out = (uInt)cap;

        if (deflate(&s, Z_FINISH) != Z_STREAM_END) {
            deflateEnd(&s);
            return S3_ERROR;
        }

        *out_len = (size_t)s.total_out;

        deflateEnd(&s);

        return S3_OK;
    }
#endif

#if (S3_HAVE_LZ4)
    case S3_SSH3_COMPRESS_LZ4: {
        int n;

        n = LZ4_compress_default((const char *)in, (char *)out, (int)in_len, (int)cap);

        if (n == 0) {
            /* the codec refuses the payload: the compressed form does
             * not fit the bound, so the frame travels as it is (the
             * ZFS cutoff) */

            return S3_DECLINED;
        }

        if (n < 0) {
            return S3_ERROR;
        }

        *out_len = (size_t)n;

        return S3_OK;
    }
#endif

#if (S3_HAVE_ZSTD)
    case S3_SSH3_COMPRESS_ZSTD: {
        size_t n;

        n = ZSTD_compress(out, cap, in, in_len, S3_SSH3_COMPRESS_ZSTD_LEVEL);

        if (ZSTD_isError(n)) {
            return S3_ERROR;
        }

        *out_len = n;

        return S3_OK;
    }
#endif

    default:
        return S3_ERROR;
    }
}

s3_int_t
s3_ssh3_compress_decode(u_char *out, size_t cap, size_t *out_len, uint32_t algorithm,
                        const u_char *in, size_t in_len)
{
    /* a codec-less build has no case below to consume the buffer
     * (cap rides the bomb limit below) */

    (void)out;
    (void)out_len;
    (void)in;
    (void)in_len;

    /* the bomb limit: the output buffer never exceeds the channel
     * packet limit, whatever the frame claims */

    if (cap > S3_SSH3_COMPRESS_MAX_OUTPUT) {
        cap = S3_SSH3_COMPRESS_MAX_OUTPUT;
    }

    switch (algorithm) {

#if (S3_HAVE_ZLIB)
    case S3_SSH3_COMPRESS_DEFLATE: {
        z_stream s;
        int      rc;

        s3_memzero(&s, sizeof(s));

        if (inflateInit2(&s, -15) != Z_OK) {
            return S3_ERROR;
        }

        s.next_in = (Bytef *)in;
        s.avail_in = (uInt)in_len;
        s.next_out = out;
        s.avail_out = (uInt)cap;

        rc = inflate(&s, Z_FINISH);

        if (rc != Z_STREAM_END) {
            /* the frame is truncated, corrupt, or wants more room than
             * the limit allows (Z_BUF_ERROR) */

            inflateEnd(&s);
            return S3_ERROR;
        }

        *out_len = (size_t)s.total_out;

        inflateEnd(&s);

        return S3_OK;
    }
#endif

#if (S3_HAVE_LZ4)
    case S3_SSH3_COMPRESS_LZ4: {
        int n;

        n = LZ4_decompress_safe((const char *)in, (char *)out, (int)in_len, (int)cap);

        if (n < 0) {
            return S3_ERROR;
        }

        *out_len = (size_t)n;

        return S3_OK;
    }
#endif

#if (S3_HAVE_ZSTD)
    case S3_SSH3_COMPRESS_ZSTD: {
        unsigned long long size;
        size_t          n;

        size = ZSTD_getFrameContentSize(in, in_len);

        if (size == ZSTD_CONTENTSIZE_ERROR || size == ZSTD_CONTENTSIZE_UNKNOWN) {
            /* the frame does not carry its size: the decoder cannot
             * bound it, so the frame is refused */

            return S3_ERROR;
        }

        if (size > cap) {
            return S3_ERROR;
        }

        n = ZSTD_decompress(out, cap, in, in_len);

        if (ZSTD_isError(n)) {
            return S3_ERROR;
        }

        *out_len = n;

        return S3_OK;
    }
#endif

    default:
        return S3_ERROR;
    }
}
