/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_SSH3_DGRAM_H_INCLUDED_
#define _S3_SSH3_DGRAM_H_INCLUDED_

#include <s3_base.h>

/*
 * the ssh3 channel datagram codec (docs/P4-WIRE.md 3.2): one QUIC
 * datagram carries varint controlStreamID, varint channelID and the
 * raw UDP payload without any framing; the H3 datagram layer stays
 * out of the way (the reference turns it off, two readers would split
 * the datagrams)
 */

/*
 * the wire size of the datagram prefix for the given ids
 */

size_t s3_ssh3_dgram_prefix_size(uint64_t control_stream_id, uint64_t channel_id);

/*
 * writes the prefix and the payload at p, returns the past-the-end
 * pointer; data may be NULL when len is 0
 */

u_char *s3_ssh3_dgram_encode(u_char *p, uint64_t control_stream_id, uint64_t channel_id,
                             const u_char *data, size_t len);

/*
 * parses one datagram at *pos against end; on S3_OK the payload view
 * points into the receive buffer and *pos advances past the datagram;
 * a truncated buffer leaves *pos untouched and returns S3_ERROR
 */

s3_int_t s3_ssh3_dgram_parse(const u_char **pos, const u_char *end, uint64_t *control_stream_id,
                             uint64_t *channel_id, s3_str_t *payload);

#endif /* _S3_SSH3_DGRAM_H_INCLUDED_ */
