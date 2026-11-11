/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_SSH3_AIA_H_INCLUDED_
#define _S3_SSH3_AIA_H_INCLUDED_

#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <s3_core.h>

/*
 * The trust bootstrap and the AIA chase of the client (PLAN.md 10,
 * CERT-VERIFICATION-CANON.md 2.6, the mirror of the Go cmd/aia.go and
 * cmd/cabundle.go):
 *
 * T1 - the CA-bundle bootstrap: the embedded ISRG roots (the generated
 *      s3_ssh3_trust_roots.c) plus an optional user bundle file ride the
 *      client anchors next to the system paths.  The win build ships no
 *      default cert dir, the embedded roots are what gives the LE chains
 *      their anchors there.  Never fatal: a missing or broken source
 *      degrades to the remaining ones.
 *
 * T2 - the AIA chase: the handshake of the record-only client records the
 *      chain error without aborting; when the error class is the missing
 *      issuer and the leaf is not self-signed, the missing intermediates
 *      are fetched through the caIssuers URLs (RFC 5280 4.2.2.1) of the
 *      presented certificates, recursively up.  The fetched certificates
 *      never enter the trust store - they ride the untrusted intermediates
 *      of an offline X509_STORE_CTX verification (the gate), so a machine-
 *      in-the-middle substitution of the caIssuers answer is neutralized
 *      and stale cache material never verifies.  The cache (PEM, 0600,
 *      keyed by the SHA-256 of the URL) keeps the warm dials off the
 *      network; the unavailable network rides the stale cache.
 *
 * The verdicts of the host key machine (2.3-2.5) ride the AIA-completed
 * connection unchanged: the caller re-reads the chain verdict after a
 * successful chase and the ssh3 layer enforces it as usual.
 */

/* the caps of the chase (canon 2.6) */

#define S3_AIA_DEPTH_MAX         8
#define S3_AIA_FETCH_BYTES_MAX   (256 * 1024)
#define S3_AIA_FETCH_TIMEOUT_SEC 5
#define S3_AIA_BUDGET_SEC        20

/* the user bundle: the env wins, the default rides next to known_hosts */

#define S3_AIA_BUNDLE_ENV   "SSH3_CA_BUNDLE"
#define S3_AIA_BUNDLE_FILE  "ca-bundle.pem"
#define S3_AIA_CACHE_SUBDIR "aia-cache"

/* the URL bookkeeping of one chase (one usable url per depth level,
 * the self-referential AIA rides out through the seen check) */

#define S3_AIA_URL_MAX      768
#define S3_AIA_URL_SEEN_MAX 16

/*
 * the transport of one caIssuers GET: S3_OK fills body over an
 * s3_alloc()ed buffer (the caller s3_free()s it), S3_ERROR on any
 * transport, framing or status failure (only 200 carries a body). The
 * hook rides the chase struct so the tests inject it - no network in
 * the unit tests
 */

typedef s3_int_t (*s3_ssh3_aia_fetch_pt)(const char *url, s3_str_t *body);

typedef struct {
    X509_STORE          *anchors;   /* the trust the chase must land in, never mutated */
    const char          *cache_dir; /* NULL rides no cache */
    unsigned long        deadline;  /* time(NULL) + S3_AIA_BUDGET_SEC at init */
    s3_ssh3_aia_fetch_pt fetch;     /* the default rides s3_https_fetch_to() */
    char                 seen[S3_AIA_URL_SEEN_MAX][S3_AIA_URL_MAX];
    unsigned             nseen;
} s3_ssh3_aia_chase_t;

/* T1: the client trust bootstrap (the embedded roots + the user bundle) */

s3_int_t s3_ssh3_aia_trust_bootstrap(SSL_CTX *ctx, s3_log_t *log);
s3_int_t s3_ssh3_aia_bundle_path(char *buf, size_t cap);

/* T2: the post-handshake chase of one connection.  S3_OK when the presented
 * chain now verifies against the anchors of the connection store (either it
 * already did, or the chase completed it), S3_DECLINED when the trigger does
 * not ride (the error class, the self-signed leaf) or the chase did not
 * complete the chain */

s3_int_t s3_ssh3_aia_complete(SSL *conn, long chain_err, s3_log_t *log);

/* the process-wide fetch override of the chase: the tests inject the hook
 * (no network in the units), NULL restores the default transport */

void s3_ssh3_aia_set_fetch(s3_ssh3_aia_fetch_pt fn);

/* the testable core below: the chase machinery, free of the ssl layer */

void s3_ssh3_aia_chase_init(s3_ssh3_aia_chase_t *ch, X509_STORE *anchors, const char *cache_dir);

/* the first caIssuers URI of the certificate, S3_DECLINED when it carries
 * none (or none over a URI) */

s3_int_t s3_ssh3_aia_caissuers_url(X509 *cert, char *buf, size_t cap);

/* the caIssuers answer body: the DER form first, the PEM block second,
 * NULL on anything else (the cap rides here too) */

X509 *s3_ssh3_aia_parse_body(const u_char *body, size_t len);

/* the gate: does leaf build a chain into the anchors through the untrusted
 * stack (the presented intermediates and the fetched ones)?  The purpose
 * rides the caller: X509_PURPOSE_ANY for the loop control (a CA cert of a
 * server-auth-only chain must not false-negative), X509_PURPOSE_SSL_SERVER
 * for the authoritative leaf check */

unsigned s3_ssh3_aia_gate(X509 *leaf, STACK_OF(X509) * untrusted, X509_STORE *anchors, int purpose);

/* one issuer fetch: the cache first (a warm entry that issues the child
 * keeps the dial off the network), the fetch behind it; every parsed
 * answer lands in the cache before the issuer check (a poisoned entry
 * falls through on the next dial and gets rewritten) */

X509 *s3_ssh3_aia_fetch_issuer(s3_ssh3_aia_chase_t *ch, X509 *child, const char *url,
                               unsigned allow_cache);

/* one chase pass: walks up from the top presented certificate to the depth
 * cap, gates the result.  S3_OK hands the fetched intermediates over (the
 * caller owns and frees the stack), S3_DECLINED leaves nothing behind */

s3_int_t s3_ssh3_aia_chase_once(s3_ssh3_aia_chase_t *ch, STACK_OF(X509) * presented,
                                unsigned             allow_cache, STACK_OF(X509) * *out_fetched);

/* the cache of the chase state (~/.ssh3/aia-cache/, the dir argument is
 * explicit so the tests point it at their work tree) */

s3_int_t s3_ssh3_aia_cache_dir(char *buf, size_t cap);
s3_int_t s3_ssh3_aia_cache_path(const char *dir, const char *url, char *buf, size_t cap);
s3_int_t s3_ssh3_aia_cache_store(const char *dir, const char *url, X509 *cert);
X509    *s3_ssh3_aia_cache_load(const char *dir, const char *url);

#endif /* _S3_SSH3_AIA_H_INCLUDED_ */
