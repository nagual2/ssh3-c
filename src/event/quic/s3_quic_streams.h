/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_QUIC_STREAMS_H_INCLUDED_
#define _S3_QUIC_STREAMS_H_INCLUDED_

#include <s3_quic.h>
#include <s3_quic_transport.h>

/*
 * the stream state machines, RFC 9000, 3.  Stream States (the nginx
 * ngx_quic_stream_send_state_e / ngx_quic_stream_recv_state_e)
 */
typedef enum {
    S3_QUIC_STREAM_SEND_READY = 0,
    S3_QUIC_STREAM_SEND_SEND,
    S3_QUIC_STREAM_SEND_DATA_SENT,
    S3_QUIC_STREAM_SEND_DATA_RECVD,
    S3_QUIC_STREAM_SEND_RESET_SENT,
    S3_QUIC_STREAM_SEND_RESET_RECVD
} s3_quic_stream_send_state_e;

typedef enum {
    S3_QUIC_STREAM_RECV_RECV = 0,
    S3_QUIC_STREAM_RECV_SIZE_KNOWN,
    S3_QUIC_STREAM_RECV_DATA_RECVD,
    S3_QUIC_STREAM_RECV_DATA_READ,
    S3_QUIC_STREAM_RECV_RESET_RECVD,
    S3_QUIC_STREAM_RECV_RESET_READ
} s3_quic_stream_recv_state_e;

/*
 * the s3_quic_shutdown_stream() how argument; bit flags, like the
 * nginx NGX_*_SHUTDOWN constants of ngx_connection.h
 */
#define S3_RDWR_SHUTDOWN  1
#define S3_WRITE_SHUTDOWN 2
#define S3_READ_SHUTDOWN  4

/*
 * the frame handlers wired into s3_quic_handle_frames()
 * (s3_quic.c); the STREAM frame family shares one handler
 */
s3_int_t s3_quic_handle_stream_frame(s3_connection_t *c, s3_quic_header_t *pkt,
                                     s3_quic_frame_t *frame);
void     s3_quic_handle_stream_ack(s3_connection_t *c, s3_quic_frame_t *f);
s3_int_t s3_quic_handle_max_data_frame(s3_connection_t *c, s3_quic_max_data_frame_t *f);
s3_int_t s3_quic_handle_streams_blocked_frame(s3_connection_t *c, s3_quic_header_t *pkt,
                                              s3_quic_streams_blocked_frame_t *f);
s3_int_t s3_quic_handle_data_blocked_frame(s3_connection_t *c, s3_quic_header_t *pkt,
                                           s3_quic_data_blocked_frame_t *f);
s3_int_t s3_quic_handle_stream_data_blocked_frame(s3_connection_t *c, s3_quic_header_t *pkt,
                                                  s3_quic_stream_data_blocked_frame_t *f);
s3_int_t s3_quic_handle_max_stream_data_frame(s3_connection_t *c, s3_quic_header_t *pkt,
                                              s3_quic_max_stream_data_frame_t *f);
s3_int_t s3_quic_handle_reset_stream_frame(s3_connection_t *c, s3_quic_header_t *pkt,
                                           s3_quic_reset_stream_frame_t *f);
s3_int_t s3_quic_handle_stop_sending_frame(s3_connection_t *c, s3_quic_header_t *pkt,
                                           s3_quic_stop_sending_frame_t *f);
s3_int_t s3_quic_handle_max_streams_frame(s3_connection_t *c, s3_quic_header_t *pkt,
                                          s3_quic_max_streams_frame_t *f);

s3_int_t          s3_quic_init_streams(s3_connection_t *c);
void              s3_quic_rbtree_insert_stream(s3_rbtree_node_t *temp, s3_rbtree_node_t *node,
                                               s3_rbtree_node_t *sentinel);
s3_quic_stream_t *s3_quic_find_stream(s3_rbtree_t *rbtree, uint64_t id);
s3_int_t          s3_quic_close_streams(s3_connection_t *c, s3_quic_connection_t *qc);

/*
 * the send method of a stream pseudo connection; s3_connection_t has
 * no send slot (unlike ngx_connection_t), the ssh3 layer calls it
 * directly
 */
ssize_t s3_quic_stream_send(s3_connection_t *c, u_char *buf, size_t size);

#endif /* _S3_QUIC_STREAMS_H_INCLUDED_ */
