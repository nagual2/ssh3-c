/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_SSH3_AUTH_JWT_H_INCLUDED_
#define _S3_SSH3_AUTH_JWT_H_INCLUDED_

#include <s3_base.h>

/*
 * the Bearer JWT pubkey authentication of the reference
 * auth/plugins/pubkey_authentication/server/server_plugin.go
 * (docs/P4-WIRE.md 7): the client signs the CONNECT with a private
 * key whose public half lives in an sshd authorized_keys file.  The
 * algorithm allowlist and the claim set follow the reference pair
 * (BuildJWTBearerToken() of client_auth.go and PubkeyJWTIdentityVerifier::
 * Verify()): EdDSA / ES256 / RS256 signatures only, iss = the session
 * username, sub = "ssh3", aud = "unused", client_id = "ssh3-<user>",
 * jti = the base64 of the TLS exporter bytes ("EXPORTER-SSH3", the
 * conversation id), exp fresh, iat/nbf not in the future
 */

/*
 * the case-insensitive "Bearer " prefix test of the reference
 * server_auth.ParseBearerAuth(): S3_OK when the header carries the
 * scheme, S3_DECLINED otherwise
 */

s3_int_t s3_ssh3_auth_jwt_bearer(const s3_str_t *header);

/*
 * the jti replay cache reset (P2-3): the ring empties; the test suite
 * calls it between the fixture cases (they ride one prepared token),
 * the daemon restart resets it by construction
 */

void s3_ssh3_jwt_replay_reset(void);

/*
 * the full verdict: the token of the authorization header verifies
 * against the keys of the authorized_keys file for the requested
 * session username; convid is the TLS exporter material the harness
 * derives from the connection (NULL skips the jti binding).  S3_OK
 * when the token verifies, S3_DECLINED on every rejection (bad
 * scheme, malformed token, unknown algorithm, tampered signature,
 * stale or missing claims, foreign key), S3_ERROR when the keys file
 * itself is unreadable; the verdict is a once-per-CONNECT event, the
 * per-key OpenSSL objects live for the call only
 */

s3_int_t s3_ssh3_auth_jwt_verify(const s3_str_t *header, const s3_str_t *user,
                                 const char *keys_path, const u_char *convid, size_t convid_len);

#endif /* _S3_SSH3_AUTH_JWT_H_INCLUDED_ */
