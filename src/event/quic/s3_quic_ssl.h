/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_QUIC_SSL_H_INCLUDED_
#define _S3_QUIC_SSL_H_INCLUDED_

#include <s3_quic.h>
#include <s3_quic_transport.h>

s3_int_t s3_quic_init_connection(s3_connection_t *c);

/* the client role ssl setup (s3_quic_connect) */
s3_int_t s3_quic_client_init_connection(s3_connection_t *c);

/*
 * drives SSL_do_handshake(); the CRYPTO records produced by the
 * callbacks are queued as CRYPTO frames
 */
s3_int_t s3_quic_handshake(s3_connection_t *c);

s3_int_t s3_quic_handle_crypto_frame(s3_connection_t *c, s3_quic_header_t *pkt,
                                     s3_quic_frame_t *frame);

#endif /* _S3_QUIC_SSL_H_INCLUDED_ */
