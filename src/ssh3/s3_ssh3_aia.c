/*
 * Copyright (C) 2026 the ssh3-c authors
 */

/*
 * the trust bootstrap and the AIA chase (PLAN.md 10, T1 + T2,
 * CERT-VERIFICATION-CANON.md 2.6): the file header of s3_ssh3_aia.h
 * carries the design.  The hard rule of the canon rides everywhere in
 * this unit: fetched trust never anchors itself - the fetched
 * certificates walk the untrusted side of the gate only, the anchors
 * stay the store the connection was built with.
 */

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#if (S3_WIN32)
#include <direct.h>
#endif

#include <s3_https_fetch.h>
#include <s3_ssh3_aia.h>

/* the generated PEM of the ISRG roots (scripts/gen-trust-roots.py) */

extern const unsigned char s3_ssh3_trust_roots_pem[];
extern const size_t        s3_ssh3_trust_roots_pem_len;

static s3_int_t s3_ssh3_aia_default_fetch(const char *url, s3_str_t *body);

/* the binary open of the win build rides the text translation off
 * (the same shape the ticket cache uses) */

#if (S3_WIN32)
#define S3_AIA_OPEN_BINARY O_BINARY
#else
#define S3_AIA_OPEN_BINARY 0
#endif

/* the portable mkdir of the cache directory: the mode rides the unix
 * leg, the win one takes the single-argument form */

s3_int_t
s3_ssh3_aia_mkdir(const char *dir)
{
#if (S3_WIN32)
    return _mkdir(dir);
#else
    return mkdir(dir, 0700);
#endif
}

/* the home of the client state: the win profile rides the backslash
 * form, the unix one the slash - the same shape the known_hosts path
 * of the app takes */

static const char *
s3_ssh3_aia_home(void)
{
#if (S3_WIN32)
    return getenv("USERPROFILE");
#else
    return getenv("HOME");
#endif
}

/*
 * the T1 bootstrap: the embedded ISRG roots and the user bundle ride
 * the client store next to the system paths.  The merged store is a
 * strict superset of the old system-only one, so the bootstrap only
 * ever adds trust; every missing or broken source degrades to a log
 * line, never to a refusal - the remaining sources carry the trust
 * (the Go buildClientCAPool shape)
 */

static int
s3_ssh3_aia_pem_walk(BIO *bio, X509_STORE *store)
{
    X509    *x509;
    unsigned added = 0;

    while ((x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {

        if (X509_STORE_add_cert(store, x509) != 1) {

            /* the duplicate of a bootstrap re-run is a no-op success */

            if (ERR_GET_REASON(ERR_peek_error()) != X509_R_CERT_ALREADY_IN_HASH_TABLE) {
                X509_free(x509);
                return -1;
            }

            ERR_clear_error();
        }

        added++;
        X509_free(x509);
    }

    /* the EOF read of the PEM trail sets an error - clear it */

    ERR_clear_error();

    return (int)added;
}

s3_int_t
s3_ssh3_aia_trust_bootstrap(SSL_CTX *ctx, s3_log_t *log)
{
    X509_STORE *store;
    BIO        *bio;
    char        path[1024];
    int         added;

    if (ctx == NULL) {
        return S3_ERROR;
    }

    /* the client state dir of the first contact: the pin store, the
     * ticket cache and the aia-cache all write under $HOME/.ssh3, the
     * fresh home carries none of it yet (the mkdir is best effort, a
     * missing source degrades the writes behind it, never the dial) */

    {
        const char *home = s3_ssh3_aia_home();

        if (home != NULL && home[0] != '\0') {

#if (S3_WIN32)
            int n = snprintf(path, sizeof(path), "%s\\.ssh3", home);
#else
            int n = snprintf(path, sizeof(path), "%s/.ssh3", home);
#endif

            if (n > 0 && (size_t)n < sizeof(path) && s3_ssh3_aia_mkdir(path) != 0 &&
                errno == ENOENT) {

                /* the home itself may be missing (the first run of a
                 * fresh profile): the two levels go one by one, the
                 * same shape the ticket persist takes */

                char parent[1024];
                int  i;

                for (i = (int)strlen(path) - 1; i >= 0; i--) {
                    if (path[i] == '/' || path[i] == '\\') {
                        break;
                    }
                }

                if (i > 0 && i < (int)sizeof(parent)) {

                    memcpy(parent, path, (size_t)i);
                    parent[i] = '\0';

                    (void)s3_ssh3_aia_mkdir(parent);
                    (void)s3_ssh3_aia_mkdir(path);
                }
            }
        }
    }

    store = SSL_CTX_get_cert_store(ctx);

    if (store == NULL) {

        /* a fresh ctx carries the store; the leg only keeps the
         * bootstrap honest if the ssl lib changed under us */

        store = X509_STORE_new();

        if (store == NULL) {
            return S3_ERROR;
        }

        SSL_CTX_set_cert_store(ctx, store);
    }

    /* the embedded ISRG roots (T1): the byte-exact snapshots of the
     * publicly published certificates - legitimate anchors under the
     * canon, the embedded trust does not anchor itself, it anchors
     * these well-known roots */

    bio = BIO_new_mem_buf(s3_ssh3_trust_roots_pem, (int)s3_ssh3_trust_roots_pem_len);

    if (bio == NULL) {
        return S3_ERROR;
    }

    added = s3_ssh3_aia_pem_walk(bio, store);

    BIO_free(bio);

    if (added < 0) {
        s3_log_error(S3_LOG_WARN, log, 0, "the embedded ISRG roots rode not the store: ssl error");
        ERR_clear_error();

    } else {
        s3_log_error(S3_LOG_INFO, log, 0, "the embedded ISRG roots ride the store (%d added)",
                     added);
    }

    /* the user bundle (T1): the SSH3_CA_BUNDLE env wins, the default
     * rides next to known_hosts; the absent file is the plain shape,
     * the broken one only loses the trust it carried */

    if (s3_ssh3_aia_bundle_path(path, sizeof(path)) != S3_OK) {
        return S3_OK;
    }

    {
        FILE *probe = fopen(path, "r");

        if (probe == NULL) {
            return S3_OK;
        }

        fclose(probe);
    }

    if (SSL_CTX_load_verify_locations(ctx, path, NULL) != 1) {
        s3_log_error(S3_LOG_WARN, log, 0, "the CA bundle \"%s\" did not load, riding without it",
                     path);
        ERR_clear_error();

        return S3_OK;
    }

    s3_log_error(S3_LOG_INFO, log, 0, "the CA bundle \"%s\" rides the store", path);

    return S3_OK;
}

s3_int_t
s3_ssh3_aia_state_dir(char *buf, size_t cap)
{
    const char *home;
    int         n;

    if (buf == NULL || cap == 0) {
        return S3_ERROR;
    }

    home = s3_ssh3_aia_home();

    if (home == NULL || home[0] == '\0') {
        return S3_ERROR;
    }

#if (S3_WIN32)
    n = snprintf(buf, cap, "%s\\.ssh3", home);
#else
    n = snprintf(buf, cap, "%s/.ssh3", home);
#endif

    if (n <= 0 || (size_t)n >= cap) {
        return S3_ERROR;
    }

    return S3_OK;
}

s3_int_t
s3_ssh3_aia_bundle_path(char *buf, size_t cap)
{
    const char *home, *override;
    int         n;

    if (buf == NULL || cap == 0) {
        return S3_ERROR;
    }

    /* the env override first (the e2e hook rides it too) */

    override = getenv(S3_AIA_BUNDLE_ENV);

    if (override != NULL && override[0] != '\0') {

        if (strlen(override) + 1 > cap) {
            return S3_ERROR;
        }

        memcpy(buf, override, strlen(override) + 1);

        return S3_OK;
    }

    home = s3_ssh3_aia_home();

    if (home == NULL || home[0] == '\0') {
        return S3_ERROR;
    }

#if (S3_WIN32)
    n = snprintf(buf, cap, "%s\\.ssh3\\" S3_AIA_BUNDLE_FILE, home);
#else
    n = snprintf(buf, cap, "%s/.ssh3/" S3_AIA_BUNDLE_FILE, home);
#endif

    if (n <= 0 || (size_t)n >= cap) {
        return S3_ERROR;
    }

    return S3_OK;
}

/*
 * the T2 chase core
 */

/* the process-wide fetch override (the tests inject; NULL rides the
 * default transport) */

static s3_ssh3_aia_fetch_pt s3_ssh3_aia_fetch_hook;

void
s3_ssh3_aia_set_fetch(s3_ssh3_aia_fetch_pt fn)
{
    s3_ssh3_aia_fetch_hook = fn;
}

void
s3_ssh3_aia_chase_init(s3_ssh3_aia_chase_t *ch, X509_STORE *anchors, const char *cache_dir)
{
    if (ch == NULL) {
        return;
    }

    s3_memzero(ch, sizeof(*ch));

    ch->anchors = anchors;
    ch->cache_dir = cache_dir;
    ch->deadline = (unsigned long)time(NULL) + S3_AIA_BUDGET_SEC;
    ch->fetch = s3_ssh3_aia_fetch_hook != NULL ? s3_ssh3_aia_fetch_hook : s3_ssh3_aia_default_fetch;
}

/*
 * the default transport: the one blocking GET of the neutral fetch
 * infra, the 5s per-fetch cap of the canon; both schemes ride (plain
 * http is the common caIssuers shape, the gate neutralizes a
 * substituted answer whatever it rode)
 */

static s3_int_t
s3_ssh3_aia_default_fetch(const char *url, s3_str_t *body)
{
    unsigned status = 0;
    s3_str_t out;

    s3_str_null(&out);

    if (s3_https_fetch_to(url, "GET", NULL, NULL, NULL, S3_AIA_FETCH_TIMEOUT_SEC, &status, &out) !=
        S3_OK) {
        return S3_ERROR;
    }

    if (status != 200) {
        s3_free(out.data);
        return S3_ERROR;
    }

    if (out.len > S3_AIA_FETCH_BYTES_MAX) {
        s3_free(out.data);
        return S3_ERROR;
    }

    *body = out;

    return S3_OK;
}

s3_int_t
s3_ssh3_aia_caissuers_url(X509 *cert, char *buf, size_t cap)
{
    AUTHORITY_INFO_ACCESS *aia;
    s3_int_t               rc = S3_DECLINED;
    int                    i, n;

    if (cert == NULL || buf == NULL || cap == 0) {
        return S3_ERROR;
    }

    aia = X509_get_ext_d2i(cert, NID_info_access, NULL, NULL);

    if (aia == NULL) {
        ERR_clear_error();
        return S3_DECLINED;
    }

    n = sk_ACCESS_DESCRIPTION_num(aia);

    for (i = 0; i < n; i++) {

        ACCESS_DESCRIPTION *ad = sk_ACCESS_DESCRIPTION_value(aia, i);

        /* the caIssuers method over a URI (RFC 5280 4.2.2.1); the
         * dNSName and the dirName locations of the same field ride
         * past (no resolver for them in this chase) */

        if (OBJ_obj2nid(ad->method) != NID_ad_ca_issuers || ad->location == NULL ||
            ad->location->type != GEN_URI) {
            continue;
        }

        {
            ASN1_IA5STRING *uri = ad->location->d.uniformResourceIdentifier;
            size_t          len = (size_t)uri->length;

            /* the oversized url rides past: one more URI may still
             * fit, the chase refuses nothing on the oversized alone */

            if (len == 0 || len >= cap) {
                continue;
            }

            memcpy(buf, uri->data, len);
            buf[len] = '\0';

            rc = S3_OK;
            break;
        }
    }

    AUTHORITY_INFO_ACCESS_free(aia);

    return rc;
}

X509 *
s3_ssh3_aia_parse_body(const u_char *body, size_t len)
{
    X509 *cert;

    if (body == NULL || len == 0 || len > S3_AIA_FETCH_BYTES_MAX) {
        return NULL;
    }

    /* the DER form first (the RFC 5280 answer), the PEM block second
     * (the servers in the wild serve both, the browser semantics) */

    if (body[0] == 0x30) {

        const u_char *p = body;

        cert = d2i_X509(NULL, &p, (long)len);

        if (cert != NULL) {
            return cert;
        }

        ERR_clear_error();
    }

    {
        BIO *bio = BIO_new_mem_buf(body, (int)len);

        if (bio == NULL) {
            return NULL;
        }

        cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);

        BIO_free(bio);

        if (cert == NULL) {
            ERR_clear_error();
        }
    }

    return cert;
}

unsigned
s3_ssh3_aia_gate(X509 *leaf, STACK_OF(X509) * untrusted, X509_STORE *anchors, int purpose)
{
    X509_STORE_CTX *sctx;
    unsigned        ok;

    if (leaf == NULL || anchors == NULL) {
        return 0;
    }

    sctx = X509_STORE_CTX_new();

    if (sctx == NULL) {
        return 0;
    }

    if (X509_STORE_CTX_init(sctx, anchors, leaf, untrusted) != 1) {
        X509_STORE_CTX_free(sctx);
        ERR_clear_error();
        return 0;
    }

    /*
     * the client semantics of the offline gate: the pinned
     * intermediates anchor on their own (the PARTIAL_CHAIN the client
     * ctx rides), the purpose mirrors the handshake requirement or
     * rides any (the loop control on a CA cert); the fetched
     * certificates walk the untrusted side, the anchors of the store
     * never grow here
     */

    {
        X509_VERIFY_PARAM *param = X509_STORE_CTX_get0_param(sctx);

        X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_PARTIAL_CHAIN);
        X509_VERIFY_PARAM_set_purpose(param, purpose);
    }

    ok = X509_verify_cert(sctx) == 1;

    /* the failed probe of a wrong shape pushes x509 errors - the gate
     * is a probe, the queue must not poison the checks behind it */

    ERR_clear_error();

    X509_STORE_CTX_free(sctx);

    return ok;
}

/* the issuer check of one answer: the name must match and the child
 * must verify against the issuer public key (the Go CheckSignatureFrom
 * shape - a certificate that did not issue the child never enters the
 * chase, whatever it signed) */

static unsigned
s3_ssh3_aia_issued_by(X509 *child, X509 *issuer)
{
    EVP_PKEY *pkey;
    unsigned  ok;

    if (child == NULL || issuer == NULL) {
        return 0;
    }

    if (X509_name_cmp(X509_get_issuer_name(child), X509_get_subject_name(issuer)) != 0) {
        return 0;
    }

    pkey = X509_get0_pubkey(issuer);

    if (pkey == NULL) {
        ERR_clear_error();
        return 0;
    }

    ok = X509_verify(child, pkey) == 1;

    ERR_clear_error();

    return ok;
}

s3_int_t
s3_ssh3_aia_cache_dir(char *buf, size_t cap)
{
    const char *home;
    int         n;

    if (buf == NULL || cap == 0) {
        return S3_ERROR;
    }

    home = s3_ssh3_aia_home();

    if (home == NULL || home[0] == '\0') {
        return S3_ERROR;
    }

#if (S3_WIN32)
    n = snprintf(buf, cap, "%s\\.ssh3\\" S3_AIA_CACHE_SUBDIR, home);
#else
    n = snprintf(buf, cap, "%s/.ssh3/" S3_AIA_CACHE_SUBDIR, home);
#endif

    if (n <= 0 || (size_t)n >= cap) {
        return S3_ERROR;
    }

    return S3_OK;
}

s3_int_t
s3_ssh3_aia_cache_path(const char *dir, const char *url, char *buf, size_t cap)
{
    u_char   md[EVP_MAX_MD_SIZE];
    unsigned md_len;
    char     hex[EVP_MAX_MD_SIZE * 2 + 1];
    int      n, i;

    if (dir == NULL || url == NULL || buf == NULL) {
        return S3_ERROR;
    }

    /* the SHA-256 of the URL keeps the file names bounded and
     * injective enough for the cache (the Go aiaCacheFilePath shape) */

    if (!EVP_Digest(url, strlen(url), md, &md_len, EVP_sha256(), NULL)) {
        ERR_clear_error();
        return S3_ERROR;
    }

    for (i = 0; (unsigned)i < md_len; i++) {
        sprintf(hex + i * 2, "%02x", md[i]);
    }

    n = snprintf(buf, cap, "%s/%s.pem", dir, hex);

    if (n <= 0 || (size_t)n >= cap) {
        return S3_ERROR;
    }

    return S3_OK;
}

s3_int_t
s3_ssh3_aia_cache_store(const char *dir, const char *url, X509 *cert)
{
    char    path[1200];
    BIO    *bio;
    u_char *pem = NULL;
    long    pem_len;
    int     fd;

    if (dir == NULL || url == NULL || cert == NULL) {
        return S3_ERROR;
    }

    if (s3_ssh3_aia_cache_path(dir, url, path, sizeof(path)) != S3_OK) {
        return S3_ERROR;
    }

    /* the directory may not exist yet (the first chase of a run
     * without the pin writes); mkdir is not recursive, the two levels
     * go one by one - the same shape the ticket persist takes */

    if (s3_ssh3_aia_mkdir(dir) != 0 && errno == ENOENT) {

        char parent[1100];
        int  i;

        for (i = (int)strlen(dir) - 1; i >= 0; i--) {
            if (dir[i] == '/' || dir[i] == '\\') {
                break;
            }
        }

        if (i > 0 && i < (int)sizeof(parent)) {

            memcpy(parent, dir, (size_t)i);
            parent[i] = '\0';

            (void)s3_ssh3_aia_mkdir(parent);
            (void)s3_ssh3_aia_mkdir(dir);
        }
    }

    bio = BIO_new(BIO_s_mem());

    if (bio == NULL) {
        return S3_ERROR;
    }

    if (PEM_write_bio_X509(bio, cert) != 1) {
        BIO_free(bio);
        ERR_clear_error();
        return S3_ERROR;
    }

    pem_len = BIO_get_mem_data(bio, &pem);

    if (pem_len <= 0 || pem == NULL) {
        BIO_free(bio);
        return S3_ERROR;
    }

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | S3_AIA_OPEN_BINARY, 0600);

    if (fd == -1) {
        BIO_free(bio);
        return S3_ERROR;
    }

    {
        ssize_t w = write(fd, pem, (size_t)pem_len);
        int     ok = (w == pem_len);

        (void)close(fd);

        BIO_free(bio);

        if (!ok) {
            (void)unlink(path);
            return S3_ERROR;
        }
    }

    return S3_OK;
}

X509 *
s3_ssh3_aia_cache_load(const char *dir, const char *url)
{
    char  path[1200];
    BIO  *bio;
    X509 *cert;

    if (dir == NULL || url == NULL) {
        return NULL;
    }

    if (s3_ssh3_aia_cache_path(dir, url, path, sizeof(path)) != S3_OK) {
        return NULL;
    }

    bio = BIO_new_file(path, "r");

    if (bio == NULL) {
        ERR_clear_error();
        return NULL;
    }

    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);

    BIO_free(bio);

    /* the broken file is a plain miss: the entry falls through to the
     * fetch and gets rewritten behind it */

    if (cert == NULL) {
        ERR_clear_error();
    }

    return cert;
}

X509 *
s3_ssh3_aia_fetch_issuer(s3_ssh3_aia_chase_t *ch, X509 *child, const char *url,
                         unsigned allow_cache)
{
    X509 *issuer;

    if (ch == NULL || child == NULL || url == NULL || url[0] == '\0') {
        return NULL;
    }

    /* the warm cache rides first: a hit that issues the child keeps
     * the dial off the network entirely (canon 2.6); the stale or
     * poisoned entry falls through to the fetch and gets rewritten
     * behind it */

    if (allow_cache && ch->cache_dir != NULL) {

        issuer = s3_ssh3_aia_cache_load(ch->cache_dir, url);

        if (issuer != NULL && s3_ssh3_aia_issued_by(child, issuer)) {
            return issuer;
        }

        X509_free(issuer);
    }

    if ((unsigned long)time(NULL) >= ch->deadline) {
        return NULL;
    }

    if (ch->fetch == NULL) {
        return NULL;
    }

    {
        s3_str_t body;
        X509    *fresh;

        s3_str_null(&body);

        if (ch->fetch(url, &body) != S3_OK) {
            return NULL;
        }

        fresh = s3_ssh3_aia_parse_body(body.data, body.len);

        s3_free(body.data);

        if (fresh == NULL) {
            return NULL;
        }

        /* every parsed answer lands in the cache: a poisoned entry
         * fails the issuer check of the next dial and falls through
         * to the network - the cache must never wedge the client */

        if (ch->cache_dir != NULL) {
            (void)s3_ssh3_aia_cache_store(ch->cache_dir, url, fresh);
        }

        if (!s3_ssh3_aia_issued_by(child, fresh)) {
            X509_free(fresh);
            return NULL;
        }

        return fresh;
    }
}

s3_int_t
s3_ssh3_aia_chase_once(s3_ssh3_aia_chase_t *ch, STACK_OF(X509) * presented, unsigned allow_cache,
                       STACK_OF(X509) * *out_fetched)
{
    STACK_OF(X509) * fetched;
    X509    *top;
    unsigned depth;

    *out_fetched = NULL;

    if (ch == NULL || ch->anchors == NULL || presented == NULL || sk_X509_num(presented) < 1) {
        return S3_ERROR;
    }

    /* the seen urls reset per pass: the network-forced pass re-walks
     * the same urls on purpose (the Go chaseOnce shape) */

    ch->nseen = 0;

    fetched = sk_X509_new_null();

    if (fetched == NULL) {
        return S3_ERROR;
    }

    top = sk_X509_value(presented, sk_X509_num(presented) - 1);

    for (depth = 0; depth < S3_AIA_DEPTH_MAX; depth++) {

        char     url[S3_AIA_URL_MAX];
        X509    *issuer;
        unsigned u;

        /* the loop control: the top already chains into the anchors
         * through the fetched intermediates - the purpose rides any,
         * a CA cert of a server-auth-only chain must not
         * false-negative (the authoritative leaf gate runs below) */

        if (s3_ssh3_aia_gate(top, fetched, ch->anchors, X509_PURPOSE_ANY)) {
            break;
        }

        /* nothing above a self-signed top: an unknown self-signed
         * root is no anchor, the gate decides (canon 2.6) */

        if (X509_self_signed(top, 1) == 1) {
            break;
        }

        if ((unsigned long)time(NULL) >= ch->deadline) {
            break;
        }

        if (s3_ssh3_aia_caissuers_url(top, url, sizeof(url)) != S3_OK) {
            break;
        }

        for (u = 0; u < ch->nseen; u++) {
            if (strcmp(ch->seen[u], url) == 0) {
                break;
            }
        }

        if (u < ch->nseen) {
            break; /* the self-referential AIA: the walk rides out */
        }

        if (ch->nseen < S3_AIA_URL_SEEN_MAX) {
            s3_memcpy(ch->seen[ch->nseen], url, strlen(url) + 1);
            ch->nseen++;
        }

        issuer = s3_ssh3_aia_fetch_issuer(ch, top, url, allow_cache);

        if (issuer == NULL) {
            break;
        }

        (void)sk_X509_push(fetched, issuer);

        top = issuer;
    }

    if (sk_X509_num(fetched) == 0) {
        sk_X509_pop_free(fetched, X509_free);
        return S3_DECLINED;
    }

    /*
     * the authoritative gate: the leaf must build a chain into the
     * anchors through the presented intermediates and the fetched
     * ones (the Go aiaVerifyPresentedChain shape) - a chase is either
     * a verified completion or nothing, the gate failure drops the
     * whole fetch.  The union stack rides the pointers only: the
     * certificates live on the presented and the fetched stacks, the
     * stack of the union frees without the certs
     */

    {
        STACK_OF(X509) *untrusted = sk_X509_new_null();
        int      i, n = sk_X509_num(presented), f = sk_X509_num(fetched);
        unsigned ok;

        if (untrusted == NULL) {
            sk_X509_pop_free(fetched, X509_free);
            return S3_ERROR;
        }

        for (i = 1; i < n; i++) {
            (void)sk_X509_push(untrusted, sk_X509_value(presented, i));
        }

        for (i = 0; i < f; i++) {
            (void)sk_X509_push(untrusted, sk_X509_value(fetched, i));
        }

        ok = s3_ssh3_aia_gate(sk_X509_value(presented, 0), untrusted, ch->anchors,
                              X509_PURPOSE_SSL_SERVER);

        sk_X509_free(untrusted);

        if (!ok) {
            sk_X509_pop_free(fetched, X509_free);
            return S3_DECLINED;
        }
    }

    *out_fetched = fetched;

    return S3_OK;
}

/*
 * the post-handshake entry: the missing-issuer class of the recorded
 * chain error walks the caIssuers urls and rebuilds the chain.  No
 * retry handshake rides here - the C client verified record-only (the
 * B-ver wave), the ssh3 layer re-reads the verdict the caller holds
 * after S3_OK and enforces it as usual
 */

s3_int_t
s3_ssh3_aia_complete(SSL *conn, long chain_err, s3_log_t *log)
{
    STACK_OF(X509) * chain, *presented, *untrusted, *fetched = NULL;
    s3_ssh3_aia_chase_t ch;
    X509               *leaf;
    X509_STORE         *store;
    char                dir[1024];
    s3_int_t            rc = S3_DECLINED;
    int                 i, n;

    /* the trigger: the missing-issuer class only - an expired or a
     * host-mismatched chain is nothing a chase can fix (canon 2.6) */

    switch (chain_err) {
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
    case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
        break;

    default:
        return S3_DECLINED;
    }

    if (conn == NULL || log == NULL) {
        return S3_ERROR;
    }

    leaf = SSL_get1_peer_certificate(conn);

    if (leaf == NULL) {
        return S3_DECLINED;
    }

    /* the self-signed leaf owns nothing above it - the TOFU flows of
     * 2.3 keep it (the canon trigger) */

    if (X509_self_signed(leaf, 1) == 1) {
        X509_free(leaf);
        return S3_DECLINED;
    }

    store = SSL_CTX_get_cert_store(SSL_get_SSL_CTX(conn));

    if (store == NULL) {
        X509_free(leaf);
        return S3_DECLINED;
    }

    /* the presented chain: the leaf plus the intermediates of the
     * handshake (the client view of SSL_get_peer_cert_chain excludes
     * the leaf, it rides SSL_get1_peer_certificate) */

    chain = SSL_get_peer_cert_chain(conn);

    presented = sk_X509_new_null();

    if (presented == NULL) {
        X509_free(leaf);
        return S3_ERROR;
    }

    untrusted = sk_X509_new_null();

    if (untrusted == NULL) {
        sk_X509_free(presented);
        X509_free(leaf);
        return S3_ERROR;
    }

    X509_up_ref(leaf);
    (void)sk_X509_push(presented, leaf);

    n = chain != NULL ? sk_X509_num(chain) : 0;

    for (i = 0; i < n; i++) {

        X509 *c = sk_X509_value(chain, i);

        X509_up_ref(c);
        (void)sk_X509_push(presented, c);
        X509_up_ref(c);
        (void)sk_X509_push(untrusted, c);
    }

    /* already verifying? the idempotent shape (the chase of a chain
     * the store actually anchors rides out untouched) */

    if (s3_ssh3_aia_gate(leaf, untrusted, store, X509_PURPOSE_SSL_SERVER)) {
        rc = S3_OK;
        goto done;
    }

    /* the cache dir: the missing home rides no cache, the chase still
     * walks the network */

    if (s3_ssh3_aia_cache_dir(dir, sizeof(dir)) != S3_OK) {
        dir[0] = '\0';
    }

    s3_ssh3_aia_chase_init(&ch, store, dir[0] != '\0' ? dir : NULL);

    /* pass one cache-first (the warm cache keeps the whole pass off
     * the network), pass two network-forced - a stale or poisoned
     * cache entry must not wedge the client (canon 2.6) */

    if (s3_ssh3_aia_chase_once(&ch, presented, 1, &fetched) == S3_OK) {

        rc = S3_OK;

        s3_log_error(S3_LOG_INFO, log, 0,
                     "the AIA chase completed the chain, cache-first pass (%d intermediates)",
                     sk_X509_num(fetched));

    } else if (s3_ssh3_aia_chase_once(&ch, presented, 0, &fetched) == S3_OK) {

        rc = S3_OK;

        s3_log_error(S3_LOG_INFO, log, 0,
                     "the AIA chase completed the chain, network-forced pass (%d intermediates)",
                     sk_X509_num(fetched));

    } else {
        s3_log_error(S3_LOG_INFO, log, 0,
                     "the AIA chase did not complete the chain to an anchor, the verdict rides");
    }

done:

    if (fetched != NULL) {
        sk_X509_pop_free(fetched, X509_free);
    }

    sk_X509_pop_free(untrusted, X509_free);
    sk_X509_pop_free(presented, X509_free);

    X509_free(leaf);

    return rc;
}
