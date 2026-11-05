/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <s3_ssh3_hostkey.h>

/*
 * the host key verdict machine: the pure shape of the
 * CERT-VERIFICATION-CANON.md 2.3-2.5 matrix.  The ssl layer records
 * the chain facts (s3_ssl_chain_seen/chain_err), the app classifies
 * the pins, the SAN and the SSHFP zone; this module folds the facts
 * into one verdict and stays free of I/O -- the prompt and the pin
 * store ride the caller, so the whole matrix is unit-testable
 */

s3_hostkey_verdict_t
s3_hostkey_decide(s3_hostkey_pin_t pin, long chain_err, unsigned self_signed,
                  unsigned san_ok, s3_hostkey_shk_t shk,
                  unsigned sshfp_verified, unsigned sshfp_mismatch)
{
    /* the SSHFP gate runs first, whatever the pin row: a published
     * zone that vouches for another key is the MITM shape itself
     * (canon 2.5); the explicit "no" warns and rides into the matrix,
     * like the Go SSHFPRejectsHost shape does */

    if (sshfp_mismatch && shk != S3_HOSTKEY_SHK_NO) {
        return S3_HOSTKEY_DECLINE;
    }

    switch (pin) {

    case S3_HOSTKEY_MATCHES:

        /* the leaf equals a pinned DER: with a clean chain the pin
         * anchored the verification (canon 2.2) and the session
         * rides; a broken chain on the matched pin (an expired pin
         * as a stale anchor) refuses -- the Go crypto-error form --
         * except the explicit "no", the insecure ride */

        if (chain_err == 0) {
            return S3_HOSTKEY_ACCEPT;
        }

        return (shk == S3_HOSTKEY_SHK_NO) ? S3_HOSTKEY_ACCEPT
                                          : S3_HOSTKEY_DECLINE;

    case S3_HOSTKEY_CHANGED:

        if (chain_err == 0) {

            if (san_ok) {

                /* the renewal (canon 2.4): the CA vouches for the
                 * new leaf and its SAN covers this target, the
                 * rotation is legitimate -- re-pin under any policy
                 * but "no", which connects without touching the
                 * store */

                return (shk == S3_HOSTKEY_SHK_NO) ? S3_HOSTKEY_ACCEPT
                                                  : S3_HOSTKEY_ACCEPT_PIN;
            }

            /* the chain is CA-valid but the SAN misses this target:
             * not a renewal of this pin (a leaf of another name),
             * the "no" rides, the rest refuse */

            return (shk == S3_HOSTKEY_SHK_NO) ? S3_HOSTKEY_ACCEPT
                                              : S3_HOSTKEY_DECLINE;
        }

        if (self_signed) {

            /* the self-signed rotation goes only through SSHFP
             * (canon 2.4): a zone match makes the re-pin verifiable,
             * the "no" connects without the store, the rest refuse */

            if (sshfp_verified) {
                return S3_HOSTKEY_ACCEPT_PIN;
            }

            return (shk == S3_HOSTKEY_SHK_NO) ? S3_HOSTKEY_ACCEPT
                                              : S3_HOSTKEY_DECLINE;
        }

        /* a CA-signed leaf the pins do not know and the system does
         * not verify: the MITM shape, the "no" rides */

        return (shk == S3_HOSTKEY_SHK_NO) ? S3_HOSTKEY_ACCEPT
                                          : S3_HOSTKEY_DECLINE;

    case S3_HOSTKEY_UNKNOWN:
    default:

        if (chain_err == 0) {

            if (san_ok) {

                /* the first contact with a CA-valid leaf (canon 2.3):
                 * the system store is the anchor, every policy
                 * connects; only accept-new records the pin */

                return (shk == S3_HOSTKEY_SHK_ACCEPT_NEW) ? S3_HOSTKEY_ACCEPT_PIN
                                                          : S3_HOSTKEY_ACCEPT;
            }

            /* CA-valid but the SAN misses this target: the "no"
             * rides, the rest refuse (the Go shape: not self-signed
             * after capture -> refuse) */

            return (shk == S3_HOSTKEY_SHK_NO) ? S3_HOSTKEY_ACCEPT
                                              : S3_HOSTKEY_DECLINE;
        }

        if (self_signed) {

            /* the TOFU self-signed first contact (canon 2.3): "yes"
             * refuses, accept-new and "no" pin (the Go shape pins
             * under "no"), "ask" hands the decision to the console
             * prompt of the caller */

            switch (shk) {

            case S3_HOSTKEY_SHK_ACCEPT_NEW:
            case S3_HOSTKEY_SHK_NO:
                return S3_HOSTKEY_ACCEPT_PIN;

            case S3_HOSTKEY_SHK_ASK:
                return S3_HOSTKEY_ASK;

            case S3_HOSTKEY_SHK_YES:
            default:
                return S3_HOSTKEY_DECLINE;
            }
        }

        /* a CA-signed leaf with a broken chain and no pins: the
         * "no" rides without the store, the rest refuse */

        return (shk == S3_HOSTKEY_SHK_NO) ? S3_HOSTKEY_ACCEPT
                                          : S3_HOSTKEY_DECLINE;
    }
}
