/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_SSH3_CA_H_INCLUDED_
#define _S3_SSH3_CA_H_INCLUDED_

#include <s3_core.h>

/*
 * the own certification authority of the wave 19 (PLAN.md 19): the
 * root, the index and the CRL live in one state directory, the
 * issuance rides the CSR of the caller, the client side verifies the
 * issued pair with the mechanics of the PLAN 14 phase 3 (the anchors
 * of the server certs pin as usual, the client certs map through
 * SAN/CN)
 *
 * the state layout of one directory:
 *
 *     ca.key   the root private key, 0600 (ed25519)
 *     ca.pem   the self-signed root, 10 years, CN=ssh3-ca
 *     index    one line per issued cert:
 *              serial|type|subject|notafter|status (V live, R revoked)
 *     crl.pem  appears after the first revoke, signed by the root
 *
 * the rotate backs the whole directory aside (dir.old.<epoch>) and
 * rides init again: the certs of the old root need a re-issuance
 * (the other issuer), the tool prints the count
 */

#define S3_SSH3_CA_SERVER 0
#define S3_SSH3_CA_CLIENT 1

typedef struct s3_ssh3_ca_s s3_ssh3_ca_t;

/* the fresh state: the root key, the root cert and the index land in
 * dir (created); an existing ca.key declines - the state never
 * overwrites silently */

s3_int_t s3_ssh3_ca_init(const char *dir, s3_log_t *log);

/* the loaded state for the operations: the root key and the cert
 * read into the pool of the caller */

s3_int_t s3_ssh3_ca_open(const char *dir, s3_pool_t *pool, s3_log_t *log, s3_ssh3_ca_t **ca);

/* the issuance of one CSR: is_client picks the EKU and the lifetime,
 * user overrides the CN of the subject (the client mapping), the
 * result lands PEM in out_path as leaf + root (the chain the daemon
 * reads directly); serial_hex receives the serial of the issued cert
 * (nul-terminated hex, the index key of the revoke) */

s3_int_t s3_ssh3_ca_sign(s3_ssh3_ca_t *ca, const char *csr_path, const char *out_path,
                         s3_uint_t is_client, const char *user, char *serial_hex,
                         size_t serial_len);

/* the revocation: spec is the serial hex from sign or the path of
 * the issued cert file; the index marks R and the CRL regenerates;
 * an unknown serial declines */

s3_int_t s3_ssh3_ca_revoke(s3_ssh3_ca_t *ca, const char *spec);

/* the rotation: the state directory backs aside as dir.old.<epoch>
 * and a fresh init rides; the retired cert count returns through
 * *retired (the re-issuance the operator owes) */

s3_int_t s3_ssh3_ca_rotate(const char *dir, s3_log_t *log, size_t *retired);

#endif /* _S3_SSH3_CA_H_INCLUDED_ */
