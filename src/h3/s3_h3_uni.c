/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

/*
 * P3 wave-2 placeholder: replaced by the reference port
 * (temp/ssh3-c/refs/nginx/src/http/v3/ngx_http_v3_uni.c and
 * the session lifecycle of ngx_http_v3.c)
 */

#include <s3_h3.h>
#include <s3_h3_uni.h>

void
s3_h3_init_uni_stream(s3_connection_t *c)
{
    (void)c;
}

s3_int_t
s3_h3_register_uni_stream(s3_connection_t *c, uint64_t type)
{
    (void)c;
    (void)type;

    return S3_ERROR;
}

s3_int_t
s3_h3_cancel_stream(s3_connection_t *c, s3_uint_t stream_id)
{
    (void)c;
    (void)stream_id;

    return S3_ERROR;
}

s3_connection_t *
s3_h3_get_uni_stream(s3_connection_t *c, s3_uint_t type)
{
    (void)c;
    (void)type;

    return NULL;
}

s3_int_t
s3_h3_send_settings(s3_connection_t *c)
{
    (void)c;

    return S3_ERROR;
}

s3_int_t
s3_h3_send_goaway(s3_connection_t *c, uint64_t id)
{
    (void)c;
    (void)id;

    return S3_ERROR;
}

s3_int_t
s3_h3_send_ack_section(s3_connection_t *c, s3_uint_t stream_id)
{
    (void)c;
    (void)stream_id;

    return S3_ERROR;
}

s3_int_t
s3_h3_send_cancel_stream(s3_connection_t *c, s3_uint_t stream_id)
{
    (void)c;
    (void)stream_id;

    return S3_ERROR;
}

s3_int_t
s3_h3_send_inc_insert_count(s3_connection_t *c, s3_uint_t inc)
{
    (void)c;
    (void)inc;

    return S3_ERROR;
}

void
s3_h3_init_stream(s3_connection_t *c)
{
    (void)c;
}

void
s3_h3_reset_stream(s3_connection_t *c)
{
    (void)c;
}

s3_int_t
s3_h3_init_session(s3_connection_t *c)
{
    (void)c;

    return S3_ERROR;
}

s3_int_t
s3_h3_check_flood(s3_connection_t *c)
{
    (void)c;

    return S3_ERROR;
}
