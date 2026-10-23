/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the channel data frame: the plain form (94) and the compressed form
 * (192, PLAN.md 9, B8)
 *
 * the helper is the seam of the compression: the caller hands the
 * payload and the negotiated algorithm, and gets the frame bytes; the
 * reading side gets the plain payload back, decompressing it into the
 * scratch buffer of the caller when the frame is the compressed one
 */

#ifndef _S3_SSH3_FRAME_H_INCLUDED_
#define _S3_SSH3_FRAME_H_INCLUDED_

#include <s3_base.h>

#include <s3_ssh3_compress.h>

/*
 * builds the frame of the payload into buf (the caller sizes the
 * buffer on the channel invariants - the S3_*_FWD_FRAME constants and
 * the peer max packet bound; the sizing helper of the earlier shape
 * turned out dead and left with the B15 audit tail):
 *
 * - the compressed frame (192) when the codec context is set, the
 *   compressed form fits the buffer and is smaller than the payload
 *   (the ZFS cutoff: the not-smaller form travels as it is);
 * - the plain frame (94) otherwise (a NULL context is the no-codec
 *   channel and always rides plain).
 *
 * on S3_OK frame_len carries the frame length and wire_len the
 * payload bytes on the wire (the compressed size, or the plain size
 * when the frame is the plain one - a wire_len below the payload
 * length means the frame was compressed)
 */

s3_int_t s3_ssh3_frame_data_build(u_char *buf, size_t cap, size_t *frame_len,
                                  s3_ssh3_compress_ctx_t *ctx, const u_char *payload,
                                  size_t payload_len, size_t *wire_len);

/*
 * reads the payload of a data frame: the plain frame gives a view into
 * the receive buffer, the compressed frame is decoded into the scratch
 * buffer of the caller (the scratch must hold the plain size of the
 * payload).  the type is the message type of the frame; decode_mask is
 * the set of codecs THIS side announced (the sender may pick any of
 * them), the context is the fast path of the expected codec
 *
 * S3_ERROR means the frame is incomplete (the caller waits for the
 * rest), S3_DECLINED that the frame is whole but is refused: the
 * payload does not decode, or the frame violates the negotiation - a
 * compressed frame on a side that announced no codec, or with an id
 * outside the announced mask (an unknown id, an id past 32 bits), is
 * a protocol violation and the caller tears the channel down
 * (SPEC-wire.md 15.2, fail-closed)
 */

s3_int_t s3_ssh3_frame_data_parse(const u_char **pos, const u_char *end, uint64_t type,
                                  uint32_t decode_mask, s3_ssh3_compress_ctx_t *ctx, u_char *scratch,
                                  size_t scratch_cap, s3_str_t *payload);

#endif /* _S3_SSH3_FRAME_H_INCLUDED_ */
