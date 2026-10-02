/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_CRC32_H_INCLUDED_
#define _S3_CRC32_H_INCLUDED_

#include <s3_base.h>

/*
 * the standard IEEE 802.3 CRC-32, the ssh3-c counterpart of
 * ngx_crc32_long(); used by the udp listener DCID lookup
 */
s3_uint32_t s3_crc32_long(u_char *p, size_t len);

#endif /* _S3_CRC32_H_INCLUDED_ */
