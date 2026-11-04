/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef S3_SSH3_AGENT_CLIENT_H_INCLUDED
#define S3_SSH3_AGENT_CLIENT_H_INCLUDED

#include <s3_core.h>
#include <s3_string.h>

/*
 * the client side of the ssh agent protocol (draft-miller-ssh-agent):
 * the identity list, the signature request and the wire parsing.  the
 * agent rides SSH_AUTH_SOCK (the unix domain socket); the server sees
 * the ordinary JWT, the agent never crosses the wire of the session.
 *
 * the signature of the agent arrives as the ssh wire blob (the algo
 * string + the bytes); the module unwraps it into the raw JWS form and
 * names the JOSE alg (EdDSA for ssh-ed25519, RS256 for rsa-sha2-256 -
 * the rsa requests always carry the SHA-256 flag, the legacy ssh-rsa
 * hash never rides).
 */

/* the pubkey file of the authorized_keys shape: the base64 blob of the
 * first key line lands in blob, the byte form the agent matches on */

s3_int_t s3_ssh3_agent_cli_pubkey_file(const char *path, u_char *blob, size_t cap,
                                       size_t *blen);

/* the REQUEST_IDENTITIES message into p (5 bytes), the written size
 * comes back */

size_t s3_ssh3_agent_cli_req_identities(u_char *p);

/* the SIGN_REQUEST message: the key blob names the key, the data is
 * the signing string; the rsa blobs set the SHA-256 flag themselves */

size_t s3_ssh3_agent_cli_req_sign(u_char *p, const u_char *blob, size_t blen,
                                  const u_char *data, size_t dlen);

/* the IDENTITIES_ANSWER parse: the key blobs ride as the zero-copy
 * views of reply; nblobs takes the count, cap bounds the array */

s3_int_t s3_ssh3_agent_cli_parse_identities(const u_char *reply, size_t len,
                                            s3_str_t *blobs, size_t *nblobs,
                                            size_t cap);

/* the SIGN_RESPONSE parse: the wire sig blob unwraps into the raw
 * signature bytes and the JOSE alg ("EdDSA" | "RS256"); a FAILURE
 * reply (the agent does not hold the key) and the truncated frames
 * refuse */

s3_int_t s3_ssh3_agent_cli_parse_sign(const u_char *reply, size_t len,
                                      u_char *sig, size_t sig_cap,
                                      size_t *sig_len, char *alg, size_t alg_cap);

/* the full flow over SSH_AUTH_SOCK: connect, sign, unwrap; the sock
 * argument overrides the environment (the tests) */

s3_int_t s3_ssh3_agent_cli_sign(const char *sock, const u_char *blob, size_t blen,
                                const u_char *data, size_t dlen,
                                u_char *sig, size_t sig_cap, size_t *sig_len,
                                char *alg, size_t alg_cap);

#endif
