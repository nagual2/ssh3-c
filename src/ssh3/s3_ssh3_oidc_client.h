/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_SSH3_OIDC_CLIENT_H_INCLUDED_
#define _S3_SSH3_OIDC_CLIENT_H_INCLUDED_

#include <s3_core.h>

#include <s3_ssh3_oidc.h>

/*
 * the client OIDC flow of the reference auth/oidc/openid_connect.go
 * Connect(): the discovery feeds the authorization endpoint, the
 * loopback listener takes the redirect (state checked, the PKCE
 * S256 challenge rides both legs), the code exchanges at the token
 * endpoint and the id_token verifies against the provider keys with
 * the conversation nonce - the same gate the server runs
 */

#define S3_SSH3_OIDC_CLI_CODE_MAX  512
#define S3_SSH3_OIDC_CLI_TOKEN_MAX 8192
#define S3_SSH3_OIDC_CLI_URL_MAX   2048

typedef struct {
    int  listen_fd; /* the loopback redirect listener, closed by wait_code */
    int  port;
    char state[65];    /* the hex of 32 random bytes */
    char nonce[65];    /* the conversation nonce of the flow */
    char verifier[87]; /* the base64url of 32 random bytes */
    char redirect_uri[64];
    char authorize_url[S3_SSH3_OIDC_CLI_URL_MAX];
} s3_ssh3_oidc_flow_t;

/*
 * binds the loopback listener and builds the authorize url (the
 * openid scope, the S256 challenge, the nonce the caller derived
 * from the conversation); S3_ERROR on the socket or the size failure
 */

s3_int_t s3_ssh3_oidc_flow_init(s3_ssh3_oidc_flow_t *f, const char *authorization_endpoint,
                                const char *client_id, const char *nonce);

/*
 * serves one redirect: accepts, checks the state, hands out the code
 * and answers "you can now close this tab" like the reference; the
 * listener closes on every return; S3_DECLINED on the state mismatch
 */

s3_int_t s3_ssh3_oidc_flow_wait_code(s3_ssh3_oidc_flow_t *f, char *code, size_t code_max);

/*
 * exchanges the code (the verifier rides the form) and verifies the
 * id_token (the signature, iss, aud=client_id, exp, the flow nonce);
 * S3_OK fills token
 */

s3_int_t s3_ssh3_oidc_client_token(const char *issuer_url, const char *client_id,
                                   const char *ca_file, const s3_ssh3_oidc_flow_t *f,
                                   const char *code, char *token, size_t token_max);

#endif /* _S3_SSH3_OIDC_CLIENT_H_INCLUDED_ */
