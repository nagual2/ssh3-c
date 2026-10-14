/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_SSH3_AUTH_SRV_H_INCLUDED_
#define _S3_SSH3_AUTH_SRV_H_INCLUDED_

#include <s3_base.h>

/*
 * the server auth chain of the reference server_auth/ (docs/P4-WIRE.md
 * 7), the wire-level steps only: the version and the 0-RTT gates live
 * in the h3 layer (P3).  The reference pubkey/JWT verification lives
 * in s3_ssh3_auth_jwt.h; this module covers the
 * username extraction, the Basic credentials, the sshd authorized
 * keys file shape and the unix shadow check (the second password
 * backend, PLAN.md 8.2), the wiring picks the checks it speaks
 */

/*
 * the Authorization header of the Basic scheme: "Basic <base64 of
 * user:pass>"; S3_OK fills the zero-copy views into the header
 * buffer, S3_DECLINED when the scheme is not Basic, S3_ERROR on a
 * malformed payload (no colon, bad base64)
 */

s3_int_t s3_ssh3_auth_basic_decode(const s3_str_t *header, s3_str_t *user, s3_str_t *pass);

/*
 * the username of the CONNECT target: "/ssh3-term?user=bob" carries
 * it in the user query parameter (the reference r.URL.Query()); the
 * value stays raw (no percent-decoding); S3_DECLINED when absent
 */

s3_int_t s3_ssh3_auth_user_from_path(const s3_str_t *path, s3_str_t *user);

/*
 * the default identities chain of the session user, the reference
 * DefaultIdentitiesFileNames() (server_auth/authorized_identities.go):
 * $home/.ssh3/authorized_identities first, $home/.ssh/authorized_keys
 * second, the home from the user database (getpwnam(3), the verdict
 * process reads the target user's files).  The names land in buf as
 * zero-terminated strings and paths[] points into it; S3_OK fills *n
 * (always S3_SSH3_AUTH_CHAIN_MAX), S3_ERROR on an unusable username
 * (outside the plain-name charset, unknown in the user database, no
 * room in buf).  The file existence is the caller's concern: the
 * reference opens both and tolerates the missing one
 */

#define S3_SSH3_AUTH_CHAIN_MAX 2

s3_int_t s3_ssh3_auth_default_chain(const s3_str_t *user, char *buf, size_t size,
                                    const char *paths[S3_SSH3_AUTH_CHAIN_MAX], unsigned *n);

/*
 * the harness credential file: one "user:secret" per line, '#'
 * comments and empty lines skip; S3_OK on a match, S3_DECLINED when
 * the user or the secret does not match, S3_ERROR on an unreadable
 * file; the plaintext fixture form only - the unix shadow check needs
 * root and stays with the deployment wiring
 */

s3_int_t s3_ssh3_auth_password_file_check(const char *path, const s3_str_t *user,
                                          const s3_str_t *pass);

/*
 * the crypt(3) check of one stored password record (the pw_passwd /
 * sp_pwdp shape): the non-password records refuse first - the empty
 * field, the "x" of a hash that lives in the shadow file and was not
 * fetched, the "*" of the disabled login and the "!" prefix of the
 * locked one; behind that the password rides crypt_r (the reentrant
 * form, the state buffer stays on the stack) with the stored record
 * as the salt and the verdict is the equal-length comparison;
 * S3_OK on a match, S3_DECLINED otherwise (the wrong password, the
 * unusable record, a key over the internal cap).  A build without
 * crypt_r never matches - the fail-closed shape, the deployment
 * keeps the file backend
 */

s3_int_t s3_ssh3_auth_password_hash_check(const s3_str_t *pass, const char *hash);

/*
 * the system account verifier (the shadow step, PLAN.md 8.2, the
 * parity of the fork 0.1.34 password login): the session user
 * resolves through getpwnam(3), the hash comes from the shadow entry
 * (getspnam(3)) with the passwd field as the fallback of the
 * shadow-less systems, the match rides the crypt check above; the
 * verifier answers only under the euid 0 - an unprivileged daemon
 * cannot read the shadow and every attempt declines (the fail-closed
 * shape, the wiring warns at the startup); S3_OK on a match,
 * S3_DECLINED otherwise (the unknown user, the unusable record, the
 * wrong password, the missing privilege)
 */

s3_int_t s3_ssh3_auth_password_system_check(const s3_str_t *user, const s3_str_t *pass);

/*
 * the presence probe of the system account database: the booking gate
 * of the brute-force lockout (the passfile probe of the daemon serves
 * the file backend the same way, only the accounts the backend
 * resolves accumulate toward the lockout); S3_OK when getpwnam(3)
 * resolves the name, S3_DECLINED otherwise (the unknown name, the
 * name outside the plain-name charset)
 */

s3_int_t s3_ssh3_auth_system_user_known(const s3_str_t *user);

/*
 * the authorized_keys iterator (the sshd format): skips empty lines
 * and '#' comments, tolerates the option prefix before the keytype;
 * on S3_OK the keytype and the base64 blob are views into the buffer
 * and *pos advances past the line; S3_DONE at the end of the block
 */

s3_int_t s3_ssh3_auth_authorized_keys_next(const u_char **pos, const u_char *end, s3_str_t *keytype,
                                           s3_str_t *b64);

#endif /* _S3_SSH3_AUTH_SRV_H_INCLUDED_ */
