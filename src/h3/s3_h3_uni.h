/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_H3_UNI_H_INCLUDED_
#define _S3_H3_UNI_H_INCLUDED_

#include <s3_core.h>
#include <s3_connection.h>

void     s3_h3_init_uni_stream(s3_connection_t *c);
s3_int_t s3_h3_register_uni_stream(s3_connection_t *c, uint64_t type);

s3_int_t s3_h3_cancel_stream(s3_connection_t *c, s3_uint_t stream_id);

s3_connection_t *s3_h3_get_uni_stream(s3_connection_t *c, s3_uint_t type);
s3_int_t         s3_h3_send_settings(s3_connection_t *c);
s3_int_t         s3_h3_send_goaway(s3_connection_t *c, uint64_t id);
s3_int_t         s3_h3_send_ack_section(s3_connection_t *c, s3_uint_t stream_id);
s3_int_t         s3_h3_send_cancel_stream(s3_connection_t *c, s3_uint_t stream_id);
s3_int_t         s3_h3_send_inc_insert_count(s3_connection_t *c, s3_uint_t inc);

/*
 * the session lifecycle (the reference keeps these in ngx_http_v3.c)
 */
void     s3_h3_init_stream(s3_connection_t *c);
void     s3_h3_reset_stream(s3_connection_t *c);
s3_int_t s3_h3_init_session(s3_connection_t *c);
s3_int_t s3_h3_check_flood(s3_connection_t *c);

#endif /* _S3_H3_UNI_H_INCLUDED_ */
