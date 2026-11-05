/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_SSH3_HOSTKEY_H_INCLUDED_
#define _S3_SSH3_HOSTKEY_H_INCLUDED_

#include <s3_core.h>

/* pin status of a presented leaf against the pins known for the target */

typedef enum {
    S3_HOSTKEY_UNKNOWN = 0, /* no pin recorded for the target yet */
    S3_HOSTKEY_MATCHES,     /* the leaf equals a pinned DER */
    S3_HOSTKEY_CHANGED      /* pins exist and none matches */
} s3_hostkey_pin_t;

/* StrictHostKeyChecking policy (the OpenSSH value set; ask is the default) */

typedef enum {
    S3_HOSTKEY_SHK_ASK = 0,
    S3_HOSTKEY_SHK_YES,
    S3_HOSTKEY_SHK_NO,
    S3_HOSTKEY_SHK_ACCEPT_NEW
} s3_hostkey_shk_t;

/* the verdict machine output */

typedef enum {
    S3_HOSTKEY_ACCEPT = 0, /* connect */
    S3_HOSTKEY_ACCEPT_PIN, /* connect and write/update the pin */
    S3_HOSTKEY_ASK,        /* the console prompt decides (app I/O) */
    S3_HOSTKEY_DECLINE     /* refused: MITM shape or policy */
} s3_hostkey_verdict_t;

/*
 * The CERT-VERIFICATION-CANON.md 2.3-2.5 decision matrix. Inputs:
 * pin          - classification against the known_hosts pins of the target;
 * chain_err    - the recorded first fatal X509 verify error (X509_V_OK = the
 *                chain verified against the system CAs or a pinned anchor);
 * self_signed  - the leaf signs itself (X509_self_signed);
 * san_ok       - the certificate SAN covers the target (X509_check_host /
 *                X509_check_ip, app-side);
 * sshfp_*      - the VerifyHostKeyDNS verdict (0/0 when disabled).
 * The machine never prompts and never writes: I/O rides the caller.
 */

s3_hostkey_verdict_t
s3_hostkey_decide(s3_hostkey_pin_t pin, long chain_err, unsigned self_signed,
                  unsigned san_ok, s3_hostkey_shk_t shk,
                  unsigned sshfp_verified, unsigned sshfp_mismatch);

#endif /* _S3_SSH3_HOSTKEY_H_INCLUDED_ */
