/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_QUIC_CONNID_H_INCLUDED_
#define _S3_QUIC_CONNID_H_INCLUDED_

#include <s3_quic.h>
#include <s3_quic_transport.h>

s3_int_t s3_quic_create_server_id(s3_connection_t *c, u_char *id);

s3_int_t s3_quic_handle_new_connection_id_frame(s3_connection_t *c, s3_quic_new_conn_id_frame_t *f);

s3_int_t s3_quic_handle_retire_connection_id_frame(s3_connection_t            *c,
                                                   s3_quic_retire_cid_frame_t *f);

s3_quic_client_id_t *s3_quic_create_client_id(s3_connection_t *c, s3_str_t *id, uint64_t seqnum,
                                              u_char *token);
s3_quic_client_id_t *s3_quic_next_client_id(s3_connection_t *c);
s3_int_t             s3_quic_free_client_id(s3_connection_t *c, s3_quic_client_id_t *cid);

/* the socket bookkeeping it depends on lives in s3_quic.c until D3 */
s3_int_t s3_quic_create_sockets(s3_connection_t *c);

#endif /* _S3_QUIC_CONNID_H_INCLUDED_ */
