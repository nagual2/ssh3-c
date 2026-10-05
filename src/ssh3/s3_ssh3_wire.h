/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_SSH3_WIRE_H_INCLUDED_
#define _S3_SSH3_WIRE_H_INCLUDED_

#include <s3_base.h>

/*
 * the ssh3 wire primitives, the reference util/wire.go: every integer
 * on the wire is a QUIC varint (RFC 9000, 16 — 1/2/4/8 bytes, the two
 * high bits of the first byte encode the length) and an SSHString is
 * a varint length followed by the raw bytes (not the uint32-be form
 * of SSH2)
 */

/* the encoded size of the varint form of the value */

size_t s3_ssh3_varint_size(uint64_t value);

/*
 * writes the varint form of the value at p, returns the past-the-end
 * pointer; values above 2^62-1 do not exist on the wire (the two
 * length bits are part of the encoding)
 */
u_char *s3_ssh3_encode_varint(u_char *p, uint64_t value);

/*
 * parses one varint at *pos against end; advances *pos past it on
 * S3_OK and leaves it untouched on S3_ERROR (a truncated buffer or
 * an over-long, non-canonical encoding of the value)
 */
s3_int_t s3_ssh3_parse_varint(const u_char **pos, const u_char *end, uint64_t *value);

/* the encoded size of a len-byte SSHString */

size_t s3_ssh3_sshstring_size(size_t len);

/*
 * writes the varint length and the bytes at p, returns the
 * past-the-end pointer; data may be NULL when len is 0
 */
u_char *s3_ssh3_encode_sshstring(u_char *p, const void *data, size_t len);

/*
 * parses one SSHString at *pos against end; on S3_OK the view points
 * into the receive buffer (zero-copy, valid while the buffer lives)
 * and *pos advances past the string; a truncated buffer leaves *pos
 * untouched and returns S3_ERROR
 */
s3_int_t s3_ssh3_parse_sshstring(const u_char **pos, const u_char *end, s3_str_t *out);

#endif /* _S3_SSH3_WIRE_H_INCLUDED_ */
