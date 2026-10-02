/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_QUIC_MIGRATION_H_INCLUDED_
#define _S3_QUIC_MIGRATION_H_INCLUDED_

#include <s3_quic.h>
#include <s3_quic_transport.h>

#define S3_QUIC_PATH_MTU_DELAY     100
#define S3_QUIC_PATH_MTU_PRECISION 16

#define s3_quic_path_dbg(c, msg, path)                                                             \
    s3_log_debug6(S3_LOG_DEBUG_EVENT, (c)->log, 0,                                                 \
                  "quic path seq:%uL %s tx:%L rx:%L valid:%d mtu:%uz", (path)->seqnum, msg,        \
                  (int64_t)(path)->sent, (int64_t)(path)->received, (int)(path)->validated,        \
                  (path)->mtu);

s3_quic_path_t *s3_quic_new_path(s3_connection_t *c, struct sockaddr *sockaddr, socklen_t socklen,
                                 s3_quic_client_id_t *cid);
s3_int_t        s3_quic_free_path(s3_connection_t *c, s3_quic_path_t *path);

s3_int_t s3_quic_handle_path_challenge_frame(s3_connection_t *c, s3_quic_header_t *pkt,
                                             s3_quic_path_challenge_frame_t *f);
s3_int_t s3_quic_handle_path_response_frame(s3_connection_t *c, s3_quic_path_challenge_frame_t *f);

s3_int_t s3_quic_set_path(s3_connection_t *c, s3_quic_header_t *pkt);
s3_int_t s3_quic_handle_migration(s3_connection_t *c, s3_quic_header_t *pkt);

void s3_quic_path_handler(s3_event_t *ev);

void     s3_quic_discover_path_mtu(s3_connection_t *c, s3_quic_path_t *path);
s3_int_t s3_quic_handle_path_mtu(s3_connection_t *c, s3_quic_path_t *path, uint64_t min,
                                 uint64_t max);

#endif /* _S3_QUIC_MIGRATION_H_INCLUDED_ */
