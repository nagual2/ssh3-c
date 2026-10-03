/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

/*
 * P3 wave-1 placeholder: replaced by the reference port
 * (temp/ssh3-c/refs/nginx/src/http/v3/ngx_http_v3_parse.c)
 */

#include <s3_h3.h>

s3_int_t
s3_h3_parse_headers(s3_connection_t *c, s3_h3_parse_headers_t *st,
    s3_buf_t *b)
{
    (void)c;
    (void)st;
    (void)b;
    return S3_ERROR;
}

s3_int_t
s3_h3_parse_data(s3_connection_t *c, s3_h3_parse_data_t *st, s3_buf_t *b)
{
    (void)c;
    (void)st;
    (void)b;
    return S3_ERROR;
}

s3_int_t
s3_h3_parse_uni(s3_connection_t *c, s3_h3_parse_uni_t *st, s3_buf_t *b)
{
    (void)c;
    (void)st;
    (void)b;
    return S3_ERROR;
}
