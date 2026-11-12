/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_TRUST_STORE_H_INCLUDED_
#define _S3_TRUST_STORE_H_INCLUDED_

#include <openssl/ssl.h>

#include <s3_core.h>

/*
 * The trust store of the wave 14 (PLAN.md 14, phase 1a): one builder
 * of the client (and, later, the server) anchor store over two
 * policies:
 *
 *   own    - the browser model: the embedded root certificates plus
 *            the user bundle files; the platform store stays out
 *   system - the platform store plus the own set (the union: the
 *            client is never worse than the system store alone, the
 *            browser semantics; the empty platform store rides the
 *            own set with a warning)
 *
 * The pins (known_hosts) are the separate trust channel: the host
 * key verdict machine rides above the CA anchors whatever the
 * policy is - they never enter this store.
 *
 * The default policy of the phase 1 is own; the switch to system
 * rides after the live acceptance of the platform bridges (PLAN.md
 * 14, the owner's decision of 2026-11-12).
 */

typedef enum {
    S3_TRUST_POLICY_OWN = 0,   /* the embedded roots + the user bundles */
    S3_TRUST_POLICY_SYSTEM = 1 /* the platform paths + the own set */
} s3_trust_policy_t;

/*
 * the ASCII case-insensitive parse of the policy text ("own",
 * "system"); 0 fills *policy, non-zero refuses the unknown text
 */

int s3_trust_policy_parse(const char *text, s3_trust_policy_t *policy);

/* the canonical name of the policy (the logs, the error texts) */

const char *s3_trust_policy_name(s3_trust_policy_t policy);

/*
 * the anchor store build: pours the policy set into the cert store
 * of the ctx (the store of a fresh ctx; an existing store gains the
 * anchors, the duplicates ride as no-ops).  Never fatal on a
 * missing or broken source - the remaining sources carry the trust,
 * the warning names the loss.  Returns S3_OK / S3_ERROR (the error
 * is the ssl-layer failure, not the missing files)
 */

s3_int_t s3_trust_store_build(SSL_CTX *ctx, s3_trust_policy_t policy, s3_log_t *log);

/*
 * the test hook: points the bundle overlay (~/.ssh3/trust-bundle.pem
 * of the product) at an explicit path; NULL restores the default.
 * The user bundle (SSH3_CA_BUNDLE / ~/.ssh3/ca-bundle.pem) rides its
 * own hook of the bootstrap
 */

void s3_trust_store_set_bundle_path(const char *path);

/*
 * the trust update of the wave 14 phase 1c (the scheduler calls the
 * product shape `ssh3 --trust-update` once a day): fetch the bundle
 * body over the neutral fetch infra, validate it (every PEM block
 * a certificate, the count floor), land it atomically
 * (tmp+rename, 0600) into the state dir as trust-bundle.pem and
 * write the manifest (the source url line, the sha256 line) next to
 * it.  S3_OK lands a fresh bundle; any failure leaves the previous
 * copy untouched - the stale bundle is the plain shape of the
 * offline scheduler run
 */

typedef s3_int_t (*s3_trust_fetch_pt)(const char *url, s3_str_t *out);

s3_int_t s3_trust_update_run(const char *url, s3_log_t *log);

/* the test hooks: the fetch body (NULL rides the https transport),
 * the landing dir (NULL rides ~/.ssh3), the count floor (0 rides
 * the product floor of 30 certificates) */

void s3_trust_update_set_fetch(s3_trust_fetch_pt fn);
void s3_trust_update_set_dir(const char *dir);
void s3_trust_update_set_min_certs(unsigned n);

/* the path the last run landed (or would land) the bundle at; the
 * build reads the same file - the update and the dial share one
 * name */

const char *s3_trust_bundle_path_get(void);

#endif /* _S3_TRUST_STORE_H_INCLUDED_ */
