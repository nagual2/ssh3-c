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

/*
 * the buffer size the frame of the payload needs: the plain frame
 * (the overhead of the type and of the string length) plus the room
 * for the compressed form of the worst case
 */

size_t s3_ssh3_frame_data_bound(size_t payload_len);

/*
 * builds the frame of the payload into buf (the size comes from
 * s3_ssh3_frame_data_bound):
 *
 * - the compressed frame (192) when the algorithm is set, the
 *   compressed form fits the buffer and is smaller than the payload
 *   (the ZFS cutoff: the not-smaller form travels as it is);
 * - the plain frame (94) otherwise.
 *
 * on S3_OK frame_len carries the frame length and wire_len the
 * payload bytes on the wire (the compressed size, or the plain size
 * when the frame is the plain one - a wire_len below the payload
 * length means the frame was compressed)
 */

s3_int_t s3_ssh3_frame_data_build(u_char *buf, size_t cap, size_t *frame_len, uint32_t algorithm,
                                  const u_char *payload, size_t payload_len, size_t *wire_len);

/*
 * reads the payload of a data frame: the plain frame gives a view into
 * the receive buffer, the compressed frame is decoded into the scratch
 * buffer of the caller (the scratch must hold the plain size of the
 * payload).  the type is the message type of the frame
 *
 * S3_ERROR means the frame is incomplete (the caller waits for the
 * rest), S3_DECLINED that the frame is whole but the payload does not
 * decode (a protocol violation)
 */

s3_int_t s3_ssh3_frame_data_parse(const u_char **pos, const u_char *end, uint64_t type,
                                  u_char *scratch, size_t scratch_cap, s3_str_t *payload);

#endif /* _S3_SSH3_FRAME_H_INCLUDED_ */
