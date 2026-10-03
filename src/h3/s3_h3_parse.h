
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */


#ifndef _S3_H3_PARSE_H_INCLUDED_
#define _S3_H3_PARSE_H_INCLUDED_


#include <s3_core.h>
#include <s3_connection.h>


typedef struct {
    s3_uint_t                      state;
    uint64_t                        value;
} s3_h3_parse_varlen_int_t;


typedef struct {
    s3_uint_t                      state;
    s3_uint_t                      shift;
    uint64_t                        value;
} s3_h3_parse_prefix_int_t;


typedef struct {
    s3_uint_t                      state;
    uint64_t                        id;
    s3_h3_parse_varlen_int_t  vlint;
} s3_h3_parse_settings_t;


typedef struct {
    s3_uint_t                      state;
    s3_uint_t                      insert_count;
    s3_uint_t                      delta_base;
    s3_uint_t                      sign;
    s3_uint_t                      base;
    s3_h3_parse_prefix_int_t  pint;
} s3_h3_parse_field_section_prefix_t;


typedef struct {
    s3_uint_t                      state;
    s3_uint_t                      length;
    s3_uint_t                      huffman;
    s3_str_t                       value;
    u_char                         *last;
    u_char                          huffstate;
    s3_buf_t                      *buf;
} s3_h3_parse_literal_t;


typedef struct {
    s3_uint_t                      state;
    s3_uint_t                      index;
    s3_uint_t                      base;
    s3_uint_t                      dynamic;

    s3_str_t                       name;
    s3_str_t                       value;

    s3_h3_parse_prefix_int_t  pint;
    s3_h3_parse_literal_t     literal;
} s3_h3_parse_field_t;


typedef struct {
    s3_uint_t                      state;
    s3_h3_parse_field_t       field;
} s3_h3_parse_field_rep_t;


typedef struct {
    s3_uint_t                      state;
    s3_uint_t                      type;
    s3_uint_t                      length;
    s3_h3_parse_varlen_int_t  vlint;
    s3_h3_parse_field_section_prefix_t  prefix;
    s3_h3_parse_field_rep_t   field_rep;
} s3_h3_parse_headers_t;


typedef struct {
    s3_uint_t                      state;
    s3_h3_parse_field_t       field;
    s3_h3_parse_prefix_int_t  pint;
} s3_h3_parse_encoder_t;


typedef struct {
    s3_uint_t                      state;
    s3_h3_parse_prefix_int_t  pint;
} s3_h3_parse_decoder_t;


typedef struct {
    s3_uint_t                      state;
    s3_uint_t                      type;
    s3_uint_t                      length;
    s3_h3_parse_varlen_int_t  vlint;
    s3_h3_parse_settings_t    settings;
} s3_h3_parse_control_t;


typedef struct {
    s3_uint_t                      state;
    s3_h3_parse_varlen_int_t  vlint;
    union {
        s3_h3_parse_encoder_t  encoder;
        s3_h3_parse_decoder_t  decoder;
        s3_h3_parse_control_t  control;
    } u;
} s3_h3_parse_uni_t;


typedef struct {
    s3_uint_t                      state;
    s3_uint_t                      type;
    s3_uint_t                      length;
    s3_h3_parse_varlen_int_t  vlint;
} s3_h3_parse_data_t;


/*
 * Parse functions return codes:
 *   NGX_DONE - parsing done
 *   NGX_OK - sub-element done
 *   NGX_AGAIN - more data expected
 *   NGX_BUSY - waiting for external event
 *   NGX_ERROR - internal error
 *   S3_H3_ERROR_XXX - HTTP/3 or QPACK error
 */

s3_int_t s3_h3_parse_headers(s3_connection_t *c,
    s3_h3_parse_headers_t *st, s3_buf_t *b);
s3_int_t s3_h3_parse_data(s3_connection_t *c,
    s3_h3_parse_data_t *st, s3_buf_t *b);
s3_int_t s3_h3_parse_uni(s3_connection_t *c,
    s3_h3_parse_uni_t *st, s3_buf_t *b);


#endif /* _S3_H3_PARSE_H_INCLUDED_ */
