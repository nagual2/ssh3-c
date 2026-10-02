/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_QUIC_OUTPUT_H_INCLUDED_
#define _S3_QUIC_OUTPUT_H_INCLUDED_

#include <s3_quic.h>
#include <s3_quic_transport.h>

s3_int_t  s3_quic_output(s3_connection_t *c);

s3_int_t  s3_quic_negotiate_version(s3_connection_t *c, s3_quic_header_t *inpkt);

s3_int_t  s3_quic_send_stateless_reset(s3_connection_t *c, s3_quic_conf_t *conf,
                                       s3_quic_header_t *pkt);
s3_int_t  s3_quic_send_cc(s3_connection_t *c);
s3_int_t  s3_quic_send_early_cc(s3_connection_t *c, s3_quic_header_t *inpkt, s3_uint_t err,
                                const char *reason);

s3_int_t  s3_quic_send_retry(s3_connection_t *c, s3_quic_conf_t *conf, s3_quic_header_t *pkt);
s3_int_t  s3_quic_send_new_token(s3_connection_t *c, s3_quic_path_t *path);

s3_int_t  s3_quic_send_ack(s3_connection_t *c, s3_quic_send_ctx_t *ctx);
s3_int_t  s3_quic_send_ack_range(s3_connection_t *c, s3_quic_send_ctx_t *ctx, uint64_t smallest,
                                 uint64_t largest);

s3_int_t  s3_quic_frame_sendto(s3_connection_t *c, s3_quic_frame_t *frame, size_t min,
                               s3_quic_path_t *path);
size_t    s3_quic_path_limit(s3_connection_t *c, s3_quic_path_t *path, size_t size);

/* RFC 9221: the public datagram send API (porting map 3.4.2) */
s3_int_t  s3_quic_send_datagram(s3_connection_t *c, const u_char *data, size_t len);

#endif /* _S3_QUIC_OUTPUT_H_INCLUDED_ */
