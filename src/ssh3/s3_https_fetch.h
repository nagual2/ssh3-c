/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_HTTPS_FETCH_H_INCLUDED_
#define _S3_HTTPS_FETCH_H_INCLUDED_

#include <s3_base.h>
#include <s3_str.h>

/*
 * the minimal HTTP/1.1 client of the OIDC layer: one blocking
 * request/response over an OpenSSL BIO (https://) or a plain socket
 * (http://, the loopback test issuers), Connection: close, no
 * redirects, no chunked responses (the OIDC endpoints answer
 * Content-Length bodies); no curl/libcurl in the product
 */

/*
 * url:            "https://host[:port]/path" or "http://..."
 * method:         "GET" or "POST"
 * body:           the request body view, NULL for GET
 * content_type:   the entity header for a body, NULL defaults to
 *                 application/x-www-form-urlencoded
 * ca_file:        the PEM trust store for the https peer, NULL
 *                 disables the peer verification (the loopback test
 *                 issuers ship a self-signed certificate)
 * status:         the response status code, may be NULL
 * response:       S3_OK fills the view over an s3_alloc()ed buffer,
 *                 the caller s3_free()s response->data; S3_ERROR on
 *                 any transport, TLS or HTTP framing failure
 */

s3_int_t s3_https_fetch(const char *url, const char *method, const s3_str_t *body,
                        const char *content_type, const char *ca_file, unsigned *status,
                        s3_str_t *response);

#endif /* _S3_HTTPS_FETCH_H_INCLUDED_ */
