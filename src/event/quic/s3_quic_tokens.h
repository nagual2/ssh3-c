/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_QUIC_TOKENS_H_INCLUDED_
#define _S3_QUIC_TOKENS_H_INCLUDED_

#include <s3_quic.h>
#include <s3_quic_transport.h>

#define S3_QUIC_MAX_TOKEN_SIZE 64
/* SHA-1(addr)=20 + sizeof(time_t) + retry(1) + odcid.len(1) + odcid */

#define S3_QUIC_AES_256_GCM_IV_LEN  12
#define S3_QUIC_AES_256_GCM_TAG_LEN 16

#define S3_QUIC_TOKEN_BUF_SIZE                                                                     \
    (S3_QUIC_AES_256_GCM_IV_LEN + S3_QUIC_MAX_TOKEN_SIZE + S3_QUIC_AES_256_GCM_TAG_LEN)

/*
 * the nginx address hash lives in ngx_event_quic.c; here it is kept
 * next to its only D1 consumer (tokens.c)
 */
void s3_quic_address_hash(struct sockaddr *sockaddr, socklen_t socklen, s3_uint_t no_port,
                          u_char *salt, size_t saltlen, u_char buf[20]);

s3_int_t s3_quic_new_sr_token(s3_connection_t *c, s3_str_t *cid, u_char *secret, u_char *token);
s3_int_t s3_quic_new_token(s3_log_t *log, struct sockaddr *sockaddr, socklen_t socklen, u_char *key,
                           s3_str_t *token, s3_str_t *odcid, time_t expires, s3_uint_t is_retry);
s3_int_t s3_quic_validate_token(s3_connection_t *c, u_char *key, s3_quic_header_t *pkt);

#endif /* _S3_QUIC_TOKENS_H_INCLUDED_ */
