
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_H3_ENCODE_H_INCLUDED_
#define _S3_H3_ENCODE_H_INCLUDED_

#include <s3_core.h>

uintptr_t s3_h3_encode_varlen_int(u_char *p, uint64_t value);
uintptr_t s3_h3_encode_prefix_int(u_char *p, uint64_t value, s3_uint_t prefix);

uintptr_t s3_h3_encode_field_section_prefix(u_char *p, s3_uint_t insert_count, s3_uint_t sign,
                                            s3_uint_t delta_base);
uintptr_t s3_h3_encode_field_ri(u_char *p, s3_uint_t dynamic, s3_uint_t index);
uintptr_t s3_h3_encode_field_lri(u_char *p, s3_uint_t dynamic, s3_uint_t index, u_char *data,
                                 size_t len);
uintptr_t s3_h3_encode_field_l(u_char *p, s3_str_t *name, s3_str_t *value);
uintptr_t s3_h3_encode_field_pbi(u_char *p, s3_uint_t index);
uintptr_t s3_h3_encode_field_lpbi(u_char *p, s3_uint_t index, u_char *data, size_t len);

#endif /* _S3_H3_ENCODE_H_INCLUDED_ */
