/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

/*
 * P3 wave-1 placeholder: replaced by the reference port
 * (temp/ssh3-c/refs/nginx/src/http/v3/ngx_http_v3_encode.c)
 */

#include <s3_h3_encode.h>

uintptr_t
s3_h3_encode_varlen_int(u_char *p, uint64_t value)
{
    (void)p;
    (void)value;

    return 0;
}

uintptr_t
s3_h3_encode_prefix_int(u_char *p, uint64_t value, s3_uint_t prefix)
{
    (void)p;
    (void)value;
    (void)prefix;

    return 0;
}

uintptr_t
s3_h3_encode_field_section_prefix(u_char *p, s3_uint_t insert_count,
    s3_uint_t sign, s3_uint_t delta_base)
{
    (void)p;
    (void)insert_count;
    (void)sign;
    (void)delta_base;

    return 0;
}

uintptr_t
s3_h3_encode_field_ri(u_char *p, s3_uint_t dynamic, s3_uint_t index)
{
    (void)p;
    (void)dynamic;
    (void)index;

    return 0;
}

uintptr_t
s3_h3_encode_field_lri(u_char *p, s3_uint_t dynamic, s3_uint_t index,
    u_char *data, size_t len)
{
    (void)p;
    (void)dynamic;
    (void)index;
    (void)data;
    (void)len;

    return 0;
}

uintptr_t
s3_h3_encode_field_l(u_char *p, s3_str_t *name, s3_str_t *value)
{
    (void)p;
    (void)name;
    (void)value;

    return 0;
}

uintptr_t
s3_h3_encode_field_pbi(u_char *p, s3_uint_t index)
{
    (void)p;
    (void)index;

    return 0;
}

uintptr_t
s3_h3_encode_field_lpbi(u_char *p, s3_uint_t index, u_char *data, size_t len)
{
    (void)p;
    (void)index;
    (void)data;
    (void)len;

    return 0;
}
