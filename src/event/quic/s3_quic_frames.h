/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_QUIC_FRAMES_H_INCLUDED_
#define _S3_QUIC_FRAMES_H_INCLUDED_

#include <s3_quic.h>
#include <s3_quic_transport.h>

typedef s3_int_t (*s3_quic_frame_handler_pt)(s3_connection_t *c, s3_quic_frame_t *frame,
                                             void *data);

s3_quic_frame_t *s3_quic_alloc_frame(s3_connection_t *c);
void             s3_quic_free_frame(s3_connection_t *c, s3_quic_frame_t *frame);
void             s3_quic_free_frames(s3_connection_t *c, s3_queue_t *frames);
void             s3_quic_queue_frame(s3_quic_connection_t *qc, s3_quic_frame_t *frame);
s3_int_t         s3_quic_split_frame(s3_connection_t *c, s3_quic_frame_t *f, size_t len);

s3_chain_t *s3_quic_alloc_chain(s3_connection_t *c);
void        s3_quic_free_chain(s3_connection_t *c, s3_chain_t *in);

s3_chain_t *s3_quic_copy_buffer(s3_connection_t *c, u_char *data, size_t len);
s3_chain_t *s3_quic_read_buffer(s3_connection_t *c, s3_quic_buffer_t *qb, uint64_t limit);
s3_chain_t *s3_quic_write_buffer(s3_connection_t *c, s3_quic_buffer_t *qb, s3_chain_t *in,
                                 uint64_t limit, uint64_t offset);
void        s3_quic_skip_buffer(s3_connection_t *c, s3_quic_buffer_t *qb, uint64_t offset);
void        s3_quic_free_buffer(s3_connection_t *c, s3_quic_buffer_t *qb);

/*
 * the nginx ngx_quic_log_frame() dump is not ported: ssh3-c has no
 * NGX_DEBUG builds and no slprintf %f-family coverage it relied on
 */

#endif /* _S3_QUIC_FRAMES_H_INCLUDED_ */
