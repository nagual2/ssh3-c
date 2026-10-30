
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_H3_TABLE_H_INCLUDED_
#define _S3_H3_TABLE_H_INCLUDED_

#include <s3_core.h>
#include <s3_connection.h>
#include <s3_event.h>

typedef struct s3_h3_session_s s3_h3_session_t;

typedef struct {
    s3_str_t name;
    s3_str_t value;
} s3_h3_field_t;

typedef struct {
    s3_h3_field_t **elts;
    s3_uint_t       nelts;
    s3_uint_t       base;
    size_t          size;
    size_t          capacity;
    uint64_t        insert_count;
    uint64_t        ack_insert_count;
    s3_event_t      send_insert_count;
    s3_buf_t       *insert_buffer;
} s3_h3_dynamic_table_t;

void      s3_h3_inc_insert_count_handler(s3_event_t *ev);
void      s3_h3_cleanup_table(s3_h3_session_t *h3c);
s3_buf_t *s3_h3_get_insert_buffer(s3_connection_t *c);
s3_int_t  s3_h3_ref_insert(s3_connection_t *c, s3_uint_t dynamic, s3_uint_t index, s3_str_t *value);
s3_int_t  s3_h3_insert(s3_connection_t *c, s3_str_t *name, s3_str_t *value);
s3_int_t  s3_h3_set_capacity(s3_connection_t *c, s3_uint_t capacity);
s3_int_t  s3_h3_duplicate(s3_connection_t *c, s3_uint_t index);
s3_int_t  s3_h3_ack_section(s3_connection_t *c, s3_uint_t stream_id);
s3_int_t  s3_h3_inc_insert_count(s3_connection_t *c, s3_uint_t inc);
s3_int_t  s3_h3_lookup_static(s3_connection_t *c, s3_uint_t index, s3_str_t *name, s3_str_t *value);
s3_int_t  s3_h3_lookup(s3_connection_t *c, s3_uint_t index, s3_str_t *name, s3_str_t *value);
s3_int_t  s3_h3_decode_insert_count(s3_connection_t *c, s3_uint_t *insert_count);
s3_int_t  s3_h3_check_insert_count(s3_connection_t *c, s3_uint_t insert_count);
void      s3_h3_ack_insert_count(s3_connection_t *c, uint64_t insert_count);
s3_int_t  s3_h3_set_param(s3_connection_t *c, uint64_t id, uint64_t value);

/*
 * ssh3-c (F2): the encoder side of the dynamic table - the capacity
 * arrives with the peer SETTINGS (QPACK_MAX_TABLE_CAPACITY), the
 * field lines ride the acked entries or fall back to the literals
 * (the measure/write convention of the encode primitives does not
 * apply: s3_h3_enc_field writes only, the state mutation must not
 * run twice)
 */
s3_int_t  s3_h3_enc_capacity(s3_connection_t *c, s3_uint_t capacity);
u_char   *s3_h3_enc_field(s3_connection_t *c, u_char *p, s3_str_t *name, s3_str_t *value);

#endif /* _S3_H3_TABLE_H_INCLUDED_ */
