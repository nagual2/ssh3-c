/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_SSH3_FORWARD_H_INCLUDED_
#define _S3_SSH3_FORWARD_H_INCLUDED_

#include <s3_base.h>

/*
 * the target address extension of the direct and forwarded channel
 * types (docs/P4-WIRE.md 2.1, the reference channel.go build/parse of
 * the additional bytes): varint addressFamily (4 or 6), the raw IP of
 * 4 or 16 bytes, the uint16 big-endian port; the extension rides in
 * the channel header right after maxPacketSize
 */

typedef struct {
    unsigned family; /* 4 or 6 */
    u_char   ip[16];
    size_t   ip_len; /* 4 or 16, follows the family */
    uint16_t port;
} s3_ssh3_forward_target_t;

/* the encoded size of the extension for the target */

size_t s3_ssh3_forward_target_size(const s3_ssh3_forward_target_t *t);

/*
 * writes the extension at p, returns the past-the-end pointer; the
 * family and the ip_len must agree, S3-style: a mismatched pair is a
 * caller bug, the size/build pair asserts it in the tests
 */

u_char *s3_ssh3_forward_build_target(u_char *p, const s3_ssh3_forward_target_t *t);

/*
 * parses the extension at *pos; on S3_OK the family, the ip bytes and
 * the port are filled and *pos advances; a wrong family, a truncated
 * buffer or an ip_len other than the family promises leaves *pos
 * untouched and returns S3_ERROR
 */

s3_int_t s3_ssh3_forward_parse_target(const u_char **pos, const u_char *end,
                                      s3_ssh3_forward_target_t *t);

#endif /* _S3_SSH3_FORWARD_H_INCLUDED_ */
