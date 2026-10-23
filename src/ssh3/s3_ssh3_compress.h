/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the channel-body compression (PLAN.md 9, B8): the codecs, the
 * capability token of the version string and the one-shot frame codec
 *
 * the negotiation rides the version string: the endpoint announces the
 * algorithms it can decode with a "compress=<list>" field, and the
 * other side may use only the algorithms the peer announced.  Both
 * version parsers skip the unknown fields (the reference logs "skipping
 * custom version field", the port ignores everything but the spec
 * version), so an old peer simply advertises nothing and no compressed
 * frame ever reaches it
 *
 * the frame unit is one channel-data message: the payload is
 * compressed independently, so a plain frame and a compressed frame may
 * share the channel in any order and a lost frame never desynchronises
 * the decoder.  the price is a slightly worse ratio than one continuous
 * stream - the accepted trade-off of the independent units
 *
 * the cutoff follows the ZFS "fast" levels: a frame whose compressed
 * form is not smaller travels as it is, so the already-compressed data
 * is not compressed twice
 */

#ifndef _S3_SSH3_COMPRESS_H_INCLUDED_
#define _S3_SSH3_COMPRESS_H_INCLUDED_

#include <s3_base.h>

/* the algorithm ids on the wire (the body of the compressed frame) */

#define S3_SSH3_COMPRESS_NONE    0
#define S3_SSH3_COMPRESS_DEFLATE 1
#define S3_SSH3_COMPRESS_LZ4     2
#define S3_SSH3_COMPRESS_ZSTD    3

/* the capability mask bits (the version string token) */

#define S3_SSH3_COMPRESS_M_DEFLATE 0x01u
#define S3_SSH3_COMPRESS_M_LZ4     0x02u
#define S3_SSH3_COMPRESS_M_ZSTD    0x04u

/* the token key in the version string and the separator of the list */

#define S3_SSH3_COMPRESS_KEY "compress="
#define S3_SSH3_COMPRESS_SEP ','

/*
 * the bomb limit: a compressed frame may not expand beyond the channel
 * packet limit (16 MiB) - the decoder refuses a frame whose output
 * would cross it, so a hostile peer cannot make the receiver allocate
 * more than one channel packet
 */

#define S3_SSH3_COMPRESS_MAX_OUTPUT (16u << 20)

/* the deflate level: the gzip-6 of ZFS, the middle of the zlib range */

#define S3_SSH3_COMPRESS_DEFLATE_LEVEL 6

/* the zstd level: the ZFS default (the level map of the OpenZFS
 * module), the best ratio per cpu among the zstd levels */

#define S3_SSH3_COMPRESS_ZSTD_LEVEL 3

/*
 * the algorithms the local build can decode with: the mask of the
 * codecs compiled in (the availability is a build property, the peer
 * learns it from the capability token)
 */

uint32_t s3_ssh3_compress_available(void);

/*
 * parses the value of the capability token ("deflate,lz4,zstd") into
 * the mask; an unknown name is skipped, an empty value is the zero mask
 */

uint32_t s3_ssh3_compress_parse(const u_char *data, size_t len);

/*
 * the algorithm of the name ("zstd", "deflate", "lz4", the case does
 * not matter); the plain id of the algorithm ("3", "1", "2") is
 * accepted too.  S3_SSH3_COMPRESS_NONE when the name is unknown
 */

uint32_t s3_ssh3_compress_by_name(const u_char *name, size_t len);

/*
 * the name of the algorithm ("zstd", "deflate", "lz4"); the empty
 * string for an unknown id
 */

const char *s3_ssh3_compress_name(uint32_t algorithm);

/*
 * the capability bit of the algorithm; zero for an unknown id
 */

uint32_t s3_ssh3_compress_bit(uint32_t algorithm);

/*
 * writes the value of the capability token of the local build into
 * buf ("deflate,zstd"), returns the length; an empty string means the
 * build has no codec at all
 */

size_t s3_ssh3_compress_capability(u_char *buf, size_t cap);

/*
 * picks the algorithm for the peer: the best of the intersection of the
 * peer's mask and the local build, S3_SSH3_COMPRESS_NONE when the
 * intersection is empty.  the preference order is zstd (the best ratio
 * per cpu), deflate (the zlib of the ZFS gzip), lz4 (the fastest)
 */

uint32_t s3_ssh3_compress_choose(uint32_t peer_mask);

/*
 * the preferred algorithm of the mask (the same order, no intersection
 * with the local build): S3_SSH3_COMPRESS_NONE for an empty mask
 */

uint32_t s3_ssh3_compress_prefer(uint32_t mask);

/*
 * the reusable codec context of a channel (the audit fix wave of the
 * 2026-10-22 review): the deflate and the zstd state is created once
 * per channel and reset per frame - the per-frame init/free of the
 * one-shot encode/decode is the hot-path allocation the zero-copy
 * rule of the project forbids.  lz4 carries no state, the context is
 * a placeholder there
 */

typedef struct s3_ssh3_compress_ctx_s s3_ssh3_compress_ctx_t;

/*
 * creates the context of the algorithm (S3_SSH3_COMPRESS_NONE and an
 * unknown id give NULL); decode selects the decompress side, the
 * deflate and the zstd states of the two sides are not interchangeable.
 * NULL on the allocation or the codec init failure
 */

s3_ssh3_compress_ctx_t *s3_ssh3_compress_ctx_create(uint32_t algorithm, unsigned decode);

/*
 * the algorithm the context carries; S3_SSH3_COMPRESS_NONE for NULL
 */

uint32_t s3_ssh3_compress_ctx_algorithm(const s3_ssh3_compress_ctx_t *ctx);

/*
 * releases the codec state and the context itself; NULL is a no-op
 */

void s3_ssh3_compress_ctx_destroy(s3_ssh3_compress_ctx_t *ctx);

/*
 * the frame codec over a channel context: the same contracts as the
 * one-shot forms above, the codec state stays resident between the
 * frames
 */

s3_int_t s3_ssh3_compress_ctx_encode(s3_ssh3_compress_ctx_t *ctx, u_char *out, size_t cap,
                                     size_t *out_len, const u_char *in, size_t in_len);

s3_int_t s3_ssh3_compress_ctx_decode(s3_ssh3_compress_ctx_t *ctx, u_char *out, size_t cap,
                                     size_t *out_len, const u_char *in, size_t in_len);

/*
 * compresses the frame payload; on S3_OK out_len carries the compressed
 * length, which may be not smaller than the input - the caller then
 * sends the payload as it is (the ZFS cutoff).  S3_DECLINED means the
 * codec refused the payload (the LZ4 bound), S3_ERROR a hard failure
 */

s3_int_t s3_ssh3_compress_encode(u_char *out, size_t cap, size_t *out_len, uint32_t algorithm,
                                 const u_char *in, size_t in_len);

/*
 * decompresses the frame payload; on S3_OK out_len carries the plain
 * length.  the output never crosses S3_SSH3_COMPRESS_MAX_OUTPUT, and a
 * frame that would cross it is refused (S3_ERROR)
 */

s3_int_t s3_ssh3_compress_decode(u_char *out, size_t cap, size_t *out_len, uint32_t algorithm,
                                 const u_char *in, size_t in_len);

/*
 * the worst case of the compressed size: the caller sizes the output
 * buffer with it (zero when the algorithm is unknown)
 */

size_t s3_ssh3_compress_bound(uint32_t algorithm, size_t in_len);

#endif /* _S3_SSH3_COMPRESS_H_INCLUDED_ */
