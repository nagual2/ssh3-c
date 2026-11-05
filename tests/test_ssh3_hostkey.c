/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the host key verdict machine: every row of the
 * CERT-VERIFICATION-CANON.md 2.3-2.5 matrix rides the
 * StrictHostKeyChecking values and the SSHFP combinations; the
 * machine is pure, the whole matrix is table asserts
 */

#include <s3_core.h>

#include <s3_ssh3_hostkey.h>

#include "s3_test.h"

static int
s3_tf_matches_clean(void)
{
    /* row 1: MATCHES + clean chain = the pin anchored the verify,
     * every policy connects; the SSHFP verdict never flips it */

    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_MATCHES, 0, 0, 0, S3_HOSTKEY_SHK_ASK, 0, 0) ==
              S3_HOSTKEY_ACCEPT);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_MATCHES, 0, 1, 0, S3_HOSTKEY_SHK_YES, 0, 0) ==
              S3_HOSTKEY_ACCEPT);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_MATCHES, 0, 0, 1, S3_HOSTKEY_SHK_NO, 0, 0) ==
              S3_HOSTKEY_ACCEPT);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_MATCHES, 0, 1, 1, S3_HOSTKEY_SHK_ACCEPT_NEW, 0, 0) ==
              S3_HOSTKEY_ACCEPT);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_MATCHES, 0, 1, 1, S3_HOSTKEY_SHK_ASK, 1, 0) ==
              S3_HOSTKEY_ACCEPT);

    /* the SSHFP gate: a mismatching zone refuses, "no" warns and
     * rides, a verified record does not promote the matched pin */

    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_MATCHES, 0, 1, 1, S3_HOSTKEY_SHK_ASK, 0, 1) ==
              S3_HOSTKEY_DECLINE);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_MATCHES, 0, 1, 1, S3_HOSTKEY_SHK_ACCEPT_NEW, 0, 1) ==
              S3_HOSTKEY_DECLINE);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_MATCHES, 0, 1, 1, S3_HOSTKEY_SHK_NO, 0, 1) ==
              S3_HOSTKEY_ACCEPT);

    /* row 2: MATCHES + broken chain (a stale/expired pin): refuse,
     * "no" connects */

    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_MATCHES, 20, 1, 0, S3_HOSTKEY_SHK_ASK, 0, 0) ==
              S3_HOSTKEY_DECLINE);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_MATCHES, 20, 1, 1, S3_HOSTKEY_SHK_YES, 0, 0) ==
              S3_HOSTKEY_DECLINE);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_MATCHES, 20, 0, 1, S3_HOSTKEY_SHK_ACCEPT_NEW, 0, 0) ==
              S3_HOSTKEY_DECLINE);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_MATCHES, 20, 1, 1, S3_HOSTKEY_SHK_NO, 0, 0) ==
              S3_HOSTKEY_ACCEPT);

    return s3_test_failures;
}

static int
s3_tf_changed_chain_valid(void)
{
    /* row 3: CHANGED + clean chain + SAN covers = the renewal
     * (canon 2.4): re-pin under any policy but "no" (no store ride) */

    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_CHANGED, 0, 0, 1, S3_HOSTKEY_SHK_ASK, 0, 0) ==
              S3_HOSTKEY_ACCEPT_PIN);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_CHANGED, 0, 0, 1, S3_HOSTKEY_SHK_YES, 0, 0) ==
              S3_HOSTKEY_ACCEPT_PIN);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_CHANGED, 0, 1, 1, S3_HOSTKEY_SHK_ACCEPT_NEW, 0, 0) ==
              S3_HOSTKEY_ACCEPT_PIN);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_CHANGED, 0, 0, 1, S3_HOSTKEY_SHK_NO, 0, 0) ==
              S3_HOSTKEY_ACCEPT);

    /* the SSHFP gate rides before the renewal */

    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_CHANGED, 0, 0, 1, S3_HOSTKEY_SHK_ASK, 0, 1) ==
              S3_HOSTKEY_DECLINE);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_CHANGED, 0, 0, 1, S3_HOSTKEY_SHK_NO, 0, 1) ==
              S3_HOSTKEY_ACCEPT);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_CHANGED, 0, 0, 1, S3_HOSTKEY_SHK_ASK, 1, 0) ==
              S3_HOSTKEY_ACCEPT_PIN);

    /* row 4: CHANGED + clean chain + SAN misses: not a renewal, "no"
     * rides, the rest refuse */

    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_CHANGED, 0, 0, 0, S3_HOSTKEY_SHK_NO, 0, 0) ==
              S3_HOSTKEY_ACCEPT);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_CHANGED, 0, 0, 0, S3_HOSTKEY_SHK_ASK, 0, 0) ==
              S3_HOSTKEY_DECLINE);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_CHANGED, 0, 0, 0, S3_HOSTKEY_SHK_YES, 0, 0) ==
              S3_HOSTKEY_DECLINE);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_CHANGED, 0, 1, 0, S3_HOSTKEY_SHK_ACCEPT_NEW, 0, 0) ==
              S3_HOSTKEY_DECLINE);

    return s3_test_failures;
}

static int
s3_tf_changed_chain_broken(void)
{
    /* row 5: CHANGED + broken chain + self-signed = the rotation goes
     * only through SSHFP (canon 2.4): a verified record re-pins,
     * "no" connects without the store, the rest refuse */

    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_CHANGED, 20, 1, 0, S3_HOSTKEY_SHK_ASK, 1, 0) ==
              S3_HOSTKEY_ACCEPT_PIN);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_CHANGED, 20, 1, 1, S3_HOSTKEY_SHK_YES, 1, 0) ==
              S3_HOSTKEY_ACCEPT_PIN);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_CHANGED, 20, 1, 0, S3_HOSTKEY_SHK_NO, 1, 0) ==
              S3_HOSTKEY_ACCEPT_PIN);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_CHANGED, 20, 1, 1, S3_HOSTKEY_SHK_ACCEPT_NEW, 1, 0) ==
              S3_HOSTKEY_ACCEPT_PIN);

    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_CHANGED, 20, 1, 1, S3_HOSTKEY_SHK_NO, 0, 0) ==
              S3_HOSTKEY_ACCEPT);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_CHANGED, 20, 1, 1, S3_HOSTKEY_SHK_ASK, 0, 0) ==
              S3_HOSTKEY_DECLINE);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_CHANGED, 20, 1, 1, S3_HOSTKEY_SHK_YES, 0, 0) ==
              S3_HOSTKEY_DECLINE);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_CHANGED, 20, 1, 1, S3_HOSTKEY_SHK_ACCEPT_NEW, 0, 0) ==
              S3_HOSTKEY_DECLINE);

    /* the mismatching zone refuses through the gate, "no" warns into
     * the row and rides without the store */

    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_CHANGED, 20, 1, 1, S3_HOSTKEY_SHK_ASK, 0, 1) ==
              S3_HOSTKEY_DECLINE);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_CHANGED, 20, 1, 1, S3_HOSTKEY_SHK_NO, 0, 1) ==
              S3_HOSTKEY_ACCEPT);

    /* row 6: CHANGED + broken chain + CA-signed = the MITM shape,
     * "no" rides, the rest refuse */

    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_CHANGED, 20, 0, 1, S3_HOSTKEY_SHK_NO, 0, 0) ==
              S3_HOSTKEY_ACCEPT);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_CHANGED, 20, 0, 1, S3_HOSTKEY_SHK_ASK, 0, 0) ==
              S3_HOSTKEY_DECLINE);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_CHANGED, 20, 0, 0, S3_HOSTKEY_SHK_YES, 0, 0) ==
              S3_HOSTKEY_DECLINE);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_CHANGED, 20, 0, 1, S3_HOSTKEY_SHK_ACCEPT_NEW, 0, 0) ==
              S3_HOSTKEY_DECLINE);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_CHANGED, 20, 0, 1, S3_HOSTKEY_SHK_ASK, 1, 0) ==
              S3_HOSTKEY_DECLINE);

    return s3_test_failures;
}

static int
s3_tf_unknown_chain_valid(void)
{
    /* row 7: UNKNOWN + clean chain + SAN covers = the first contact
     * with the CA as the anchor (canon 2.3): every policy connects,
     * accept-new records the pin */

    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_UNKNOWN, 0, 0, 1, S3_HOSTKEY_SHK_ASK, 0, 0) ==
              S3_HOSTKEY_ACCEPT);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_UNKNOWN, 0, 0, 1, S3_HOSTKEY_SHK_YES, 0, 0) ==
              S3_HOSTKEY_ACCEPT);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_UNKNOWN, 0, 1, 1, S3_HOSTKEY_SHK_NO, 0, 0) ==
              S3_HOSTKEY_ACCEPT);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_UNKNOWN, 0, 0, 1, S3_HOSTKEY_SHK_ACCEPT_NEW, 0, 0) ==
              S3_HOSTKEY_ACCEPT_PIN);

    /* the SSHFP gate rides first */

    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_UNKNOWN, 0, 0, 1, S3_HOSTKEY_SHK_ASK, 0, 1) ==
              S3_HOSTKEY_DECLINE);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_UNKNOWN, 0, 0, 1, S3_HOSTKEY_SHK_ACCEPT_NEW, 0, 1) ==
              S3_HOSTKEY_DECLINE);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_UNKNOWN, 0, 0, 1, S3_HOSTKEY_SHK_NO, 0, 1) ==
              S3_HOSTKEY_ACCEPT);

    /* row 8: UNKNOWN + clean chain + SAN misses: "no" rides, the
     * rest refuse */

    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_UNKNOWN, 0, 0, 0, S3_HOSTKEY_SHK_NO, 0, 0) ==
              S3_HOSTKEY_ACCEPT);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_UNKNOWN, 0, 0, 0, S3_HOSTKEY_SHK_ASK, 0, 0) ==
              S3_HOSTKEY_DECLINE);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_UNKNOWN, 0, 1, 0, S3_HOSTKEY_SHK_YES, 0, 0) ==
              S3_HOSTKEY_DECLINE);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_UNKNOWN, 0, 0, 0, S3_HOSTKEY_SHK_ACCEPT_NEW, 0, 0) ==
              S3_HOSTKEY_DECLINE);

    return s3_test_failures;
}

static int
s3_tf_unknown_chain_broken(void)
{
    /* row 9: UNKNOWN + broken chain + self-signed = the TOFU first
     * contact (canon 2.3): "yes" refuses, accept-new and "no" pin,
     * "ask" hands over to the console prompt */

    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_UNKNOWN, 20, 1, 0, S3_HOSTKEY_SHK_YES, 0, 0) ==
              S3_HOSTKEY_DECLINE);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_UNKNOWN, 20, 1, 1, S3_HOSTKEY_SHK_ACCEPT_NEW, 0, 0) ==
              S3_HOSTKEY_ACCEPT_PIN);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_UNKNOWN, 20, 1, 0, S3_HOSTKEY_SHK_NO, 0, 0) ==
              S3_HOSTKEY_ACCEPT_PIN);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_UNKNOWN, 20, 1, 1, S3_HOSTKEY_SHK_ASK, 0, 0) ==
              S3_HOSTKEY_ASK);

    /* the SSHFP gate: the mismatching zone refuses through the
     * policies that would connect; "no" warns into the row; a
     * verified record never flips the "ask" handover */

    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_UNKNOWN, 20, 1, 1, S3_HOSTKEY_SHK_ASK, 0, 1) ==
              S3_HOSTKEY_DECLINE);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_UNKNOWN, 20, 1, 1, S3_HOSTKEY_SHK_ACCEPT_NEW, 0, 1) ==
              S3_HOSTKEY_DECLINE);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_UNKNOWN, 20, 1, 1, S3_HOSTKEY_SHK_YES, 0, 1) ==
              S3_HOSTKEY_DECLINE);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_UNKNOWN, 20, 1, 1, S3_HOSTKEY_SHK_NO, 0, 1) ==
              S3_HOSTKEY_ACCEPT_PIN);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_UNKNOWN, 20, 1, 1, S3_HOSTKEY_SHK_ASK, 1, 0) ==
              S3_HOSTKEY_ASK);

    /* row 10: UNKNOWN + broken chain + CA-signed: "no" rides without
     * the store, the rest refuse */

    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_UNKNOWN, 20, 0, 1, S3_HOSTKEY_SHK_NO, 0, 0) ==
              S3_HOSTKEY_ACCEPT);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_UNKNOWN, 20, 0, 1, S3_HOSTKEY_SHK_ASK, 0, 0) ==
              S3_HOSTKEY_DECLINE);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_UNKNOWN, 20, 0, 1, S3_HOSTKEY_SHK_YES, 0, 0) ==
              S3_HOSTKEY_DECLINE);
    S3_ASSERT(s3_hostkey_decide(S3_HOSTKEY_UNKNOWN, 20, 0, 0, S3_HOSTKEY_SHK_ACCEPT_NEW, 0, 0) ==
              S3_HOSTKEY_DECLINE);

    return s3_test_failures;
}

static int
s3_tf_all(void)
{
    (void)s3_tf_matches_clean();

    if (s3_test_failures > 0) {
        return s3_test_failures;
    }

    (void)s3_tf_changed_chain_valid();
    (void)s3_tf_changed_chain_broken();
    (void)s3_tf_unknown_chain_valid();
    (void)s3_tf_unknown_chain_broken();

    return s3_test_failures;
}

S3_TEST_MAIN(s3_tf_all)
