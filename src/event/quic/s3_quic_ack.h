/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_QUIC_ACK_H_INCLUDED_
#define _S3_QUIC_ACK_H_INCLUDED_

#include <s3_quic.h>
#include <s3_quic_transport.h>

s3_int_t  s3_quic_handle_ack_frame(s3_connection_t *c, s3_quic_header_t *pkt, s3_quic_frame_t *f);

void      s3_quic_congestion_ack(s3_connection_t *c, s3_quic_frame_t *frame);
void      s3_quic_congestion_idle(s3_connection_t *c, s3_uint_t idle);
void      s3_quic_resend_frames(s3_connection_t *c, s3_quic_send_ctx_t *ctx);
void      s3_quic_set_lost_timer(s3_connection_t *c);
void      s3_quic_pto_handler(s3_event_t *ev);
s3_msec_t s3_quic_pto(s3_connection_t *c, s3_quic_send_ctx_t *ctx);

s3_int_t  s3_quic_ack_packet(s3_connection_t *c, s3_quic_header_t *pkt);
s3_int_t  s3_quic_generate_ack(s3_connection_t *c, s3_quic_send_ctx_t *ctx);

#endif /* _S3_QUIC_ACK_H_INCLUDED_ */
