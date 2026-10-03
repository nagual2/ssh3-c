/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

/*
 * P3 wave-1 placeholder: replaced by the reference port
 * (temp/ssh3-c/refs/nginx/src/http/v3/ngx_http_v3_table.c)
 */

#include <s3_h3.h>

void
s3_h3_inc_insert_count_handler(s3_event_t *ev)
{
    (void)ev;
}

void
s3_h3_cleanup_table(s3_h3_session_t *h3c)
{
    (void)h3c;
}

s3_buf_t *
s3_h3_get_insert_buffer(s3_connection_t *c)
{
    (void)c;

    return NULL;
}

s3_int_t
s3_h3_ref_insert(s3_connection_t *c, s3_uint_t dynamic, s3_uint_t index,
    s3_str_t *value)
{
    (void)c;
    (void)dynamic;
    (void)index;
    (void)value;

    return S3_ERROR;
}

s3_int_t
s3_h3_insert(s3_connection_t *c, s3_str_t *name, s3_str_t *value)
{
    (void)c;
    (void)name;
    (void)value;

    return S3_ERROR;
}

s3_int_t
s3_h3_set_capacity(s3_connection_t *c, s3_uint_t capacity)
{
    (void)c;
    (void)capacity;

    return S3_ERROR;
}

s3_int_t
s3_h3_duplicate(s3_connection_t *c, s3_uint_t index)
{
    (void)c;
    (void)index;

    return S3_ERROR;
}

s3_int_t
s3_h3_ack_section(s3_connection_t *c, s3_uint_t stream_id)
{
    (void)c;
    (void)stream_id;

    return S3_ERROR;
}

s3_int_t
s3_h3_inc_insert_count(s3_connection_t *c, s3_uint_t inc)
{
    (void)c;
    (void)inc;

    return S3_ERROR;
}

s3_int_t
s3_h3_lookup_static(s3_connection_t *c, s3_uint_t index, s3_str_t *name,
    s3_str_t *value)
{
    (void)c;
    (void)index;
    (void)name;
    (void)value;

    return S3_ERROR;
}

s3_int_t
s3_h3_lookup(s3_connection_t *c, s3_uint_t index, s3_str_t *name,
    s3_str_t *value)
{
    (void)c;
    (void)index;
    (void)name;
    (void)value;

    return S3_ERROR;
}

s3_int_t
s3_h3_decode_insert_count(s3_connection_t *c, s3_uint_t *insert_count)
{
    (void)c;
    (void)insert_count;

    return S3_ERROR;
}

s3_int_t
s3_h3_check_insert_count(s3_connection_t *c, s3_uint_t insert_count)
{
    (void)c;
    (void)insert_count;

    return S3_ERROR;
}

void
s3_h3_ack_insert_count(s3_connection_t *c, uint64_t insert_count)
{
    (void)c;
    (void)insert_count;
}

s3_int_t
s3_h3_set_param(s3_connection_t *c, uint64_t id, uint64_t value)
{
    (void)c;
    (void)id;
    (void)value;

    return S3_ERROR;
}
