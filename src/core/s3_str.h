/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_STR_H_INCLUDED_
#define _S3_STR_H_INCLUDED_

#include <s3_base.h>

/*
 * zero-copy string: a view into a foreign buffer (packet, header, buf),
 * no NUL terminator
 */
typedef struct {
    size_t  len;
    u_char *data;
} s3_str_t;

#define s3_string(str)                                                                             \
    {                                                                                              \
        sizeof(str) - 1, (u_char *)str                                                             \
    }
#define s3_null_string                                                                             \
    {                                                                                              \
        0, NULL                                                                                    \
    }

#define s3_str_set(str, text)                                                                      \
    (str)->len = sizeof(text) - 1;                                                                 \
    (str)->data = (u_char *)text
#define s3_str_null(str)                                                                           \
    (str)->len = 0;                                                                                \
    (str)->data = NULL

#endif /* _S3_STR_H_INCLUDED_ */
