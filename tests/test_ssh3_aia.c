/*
 * Copyright (C) 2026 the ssh3-c authors
 */

/*
 * the AIA chase units (PLAN.md 10, T1 + T2, canon 2.6): the caIssuers
 * extraction, the answer parsing, the offline gate, the cache round
 * trip, the chase walk (success, two fetches, depth cap, budget,
 * rogue answers), the stale and the poisoned cache shapes and the T1
 * bootstrap of the embedded roots plus the user bundle.
 *
 * The network rides the fetch hook - the unit tests never dial out:
 * the hook answers from the in-memory PEM of the fixture certificates,
 * and the "zero network" legs arm the hook to fail on any call (a
 * call would fail the leg, the canon warm-cache semantics is what
 * rides the assertion).
 */

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <s3_ssh3_aia.h>
#include "s3_test.h"

#if (S3_WIN32)
#include <direct.h>
#endif

#if (S3_WIN32)
#define s3_aia_setenv(k, v) _putenv_s(k, v)
#else
#define s3_aia_setenv(k, v) setenv(k, v, 1)
#endif

static s3_log_t s3_aia_test_log;

/*
 * the fixture: the anchor root, the intermediate, the leaf, a wrong
 * certificate (signed by the root, no usable caIssuers URI), a rogue
 * self-signed CA, a self-signed leaf, the two-fetch chain (leafA <-
 * b1 <- b2 <- root) and the deep chain for the depth cap (leaf2 <-
 * c1 <- ... <- c9 <- rogue, the top rides outside the anchors)
 */

static EVP_PKEY *fx_root_key;
static X509     *fx_root;

static EVP_PKEY *fx_i1_key;
static X509     *fx_i1;

static EVP_PKEY *fx_leaf_key;
static X509     *fx_leaf;

static EVP_PKEY *fx_wrong_key;
static X509     *fx_wrong;

static EVP_PKEY *fx_rogue_key;
static X509     *fx_rogue;

static EVP_PKEY *fx_self_key;
static X509     *fx_self;

static EVP_PKEY *fx_la_key, *fx_b1_key, *fx_b2_key;
static X509     *fx_la, *fx_b1, *fx_b2;

#define S3_AIA_CHAIN_N 10 /* leaf2 + 9 intermediates */

static EVP_PKEY *fx_chain_key[S3_AIA_CHAIN_N];
static X509     *fx_chain[S3_AIA_CHAIN_N];

/* the PEM texts of the hook answers (the caIssuers bodies) */

static char fx_pem_i1[2048], fx_pem_rogue[2048], fx_pem_b1[2048], fx_pem_b2[2048],
    fx_pem_chain[S3_AIA_CHAIN_N][2048];

/* the urls the fixture AIA extensions announce */

static const char *fx_url_i1 = "http://127.0.0.1:48080/inter.pem";
static const char *fx_url_b1 = "http://127.0.0.1:48080/chain-a.pem";
static const char *fx_url_b2 = "http://127.0.0.1:48080/chain-b.pem";
static char        fx_url_chain[S3_AIA_CHAIN_N][64];

/* the work tree of the cache legs (the HOME of the run) */

static char s3_aia_work[1024];

/* the fetch hook: the url map of the caIssuers answers, the call
 * counter and the forced failure of the offline legs */

typedef struct {
    const char *url;
    const char *pem;
} s3_aia_hook_entry_t;

static s3_aia_hook_entry_t s3_aia_hook_map[16];
static unsigned            s3_aia_hook_n;
static int                 s3_aia_hook_calls;
static int                 s3_aia_hook_fail;

static void
s3_aia_hook_reset(void)
{
    s3_aia_hook_n = 0;
    s3_aia_hook_calls = 0;
    s3_aia_hook_fail = 0;
}

static void
s3_aia_hook_add(const char *url, const char *pem)
{
    if (s3_aia_hook_n < sizeof(s3_aia_hook_map) / sizeof(s3_aia_hook_map[0])) {
        s3_aia_hook_map[s3_aia_hook_n].url = url;
        s3_aia_hook_map[s3_aia_hook_n].pem = pem;
        s3_aia_hook_n++;
    }
}

static s3_int_t
s3_aia_hook_fetch(const char *url, s3_str_t *body)
{
    unsigned i;

    s3_aia_hook_calls++;

    if (s3_aia_hook_fail) {
        return S3_ERROR;
    }

    for (i = 0; i < s3_aia_hook_n; i++) {

        size_t len;

        if (strcmp(s3_aia_hook_map[i].url, url) != 0) {
            continue;
        }

        len = strlen(s3_aia_hook_map[i].pem);
        body->data = s3_alloc(len, NULL);

        if (body->data == NULL) {
            return S3_ERROR;
        }

        memcpy(body->data, s3_aia_hook_map[i].pem, len);
        body->len = len;

        return S3_OK;
    }

    return S3_ERROR;
}

/* the DER SHA-256 of a certificate as hex (the fingerprint compare of
 * the cache round trip and the embedded roots) */

static int
s3_aia_der_sha256(X509 *cert, char *hex, size_t cap)
{
    u_char  *der = NULL;
    int      der_len;
    u_char   md[EVP_MAX_MD_SIZE];
    unsigned md_len;
    size_t   i;

    der_len = i2d_X509(cert, &der);

    if (der_len <= 0 || !EVP_Digest(der, (size_t)der_len, md, &md_len, EVP_sha256(), NULL)) {
        OPENSSL_free(der);
        ERR_clear_error();
        return -1;
    }

    OPENSSL_free(der);

    if (cap < (size_t)md_len * 2 + 1) {
        return -1;
    }

    for (i = 0; i < md_len; i++) {
        sprintf(hex + i * 2, "%02x", md[i]);
    }

    return 0;
}

static int
s3_aia_der_equal(X509 *a, X509 *b)
{
    u_char *da = NULL, *db = NULL;
    int     la, lb, eq;

    la = i2d_X509(a, &da);
    lb = i2d_X509(b, &db);

    eq = la > 0 && la == lb && memcmp(da, db, (size_t)la) == 0;

    OPENSSL_free(da);
    OPENSSL_free(db);

    return eq;
}

static char *
s3_aia_pem_of(X509 *cert, char *buf, size_t cap)
{
    BIO    *bio;
    u_char *p = NULL;
    long    len;

    bio = BIO_new(BIO_s_mem());

    if (bio == NULL || PEM_write_bio_X509(bio, cert) != 1) {
        BIO_free(bio);
        ERR_clear_error();
        return NULL;
    }

    len = BIO_get_mem_data(bio, &p);

    if (len <= 0 || (size_t)len >= cap) {
        BIO_free(bio);
        return NULL;
    }

    memcpy(buf, p, (size_t)len);
    buf[len] = '\0';

    BIO_free(bio);

    return buf;
}

/* the certificate factory: the subject CN, the issuer (NULL = self),
 * the CA flag, the SAN and the AIA ext text; the EC P-256 keys keep
 * the fixture fast */

static long s3_aia_serial = 100;

static int
s3_aia_cert_make(EVP_PKEY **out_key, X509 **out_cert, const char *cn, X509 *issuer,
                 EVP_PKEY *issuer_key, int ca, const char *san, const char *aia)
{
    EVP_PKEY       *pkey;
    X509           *x;
    X509_NAME      *name;
    X509_EXTENSION *ext;

    pkey = EVP_EC_gen("P-256");

    if (pkey == NULL) {
        return -1;
    }

    x = X509_new();

    if (x == NULL) {
        EVP_PKEY_free(pkey);
        return -1;
    }

    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), (int)s3_aia_serial++);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 31536000);
    X509_set_pubkey(x, pkey);

    name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)cn, -1, -1, 0);

    if (ca) {
        ext = X509V3_EXT_nconf_nid(NULL, NULL, NID_basic_constraints, "critical,CA:TRUE");

        if (ext == NULL || X509_add_ext(x, ext, -1) != 1) {
            X509_EXTENSION_free(ext);
            X509_free(x);
            EVP_PKEY_free(pkey);
            ERR_clear_error();
            return -1;
        }

        X509_EXTENSION_free(ext);
    }

    if (san != NULL) {
        ext = X509V3_EXT_nconf_nid(NULL, NULL, NID_subject_alt_name, san);

        if (ext == NULL || X509_add_ext(x, ext, -1) != 1) {
            X509_EXTENSION_free(ext);
            X509_free(x);
            EVP_PKEY_free(pkey);
            ERR_clear_error();
            return -1;
        }

        X509_EXTENSION_free(ext);
    }

    if (aia != NULL) {
        ext = X509V3_EXT_nconf_nid(NULL, NULL, NID_info_access, aia);

        if (ext == NULL || X509_add_ext(x, ext, -1) != 1) {
            X509_EXTENSION_free(ext);
            X509_free(x);
            EVP_PKEY_free(pkey);
            ERR_clear_error();
            return -1;
        }

        X509_EXTENSION_free(ext);
    }

    /* the self-signed form rides the subject as the issuer */

    X509_set_issuer_name(x, issuer != NULL ? X509_get_subject_name(issuer) : name);

    if (X509_sign(x, issuer_key != NULL ? issuer_key : pkey, EVP_sha256()) == 0) {
        X509_free(x);
        EVP_PKEY_free(pkey);
        ERR_clear_error();
        return -1;
    }

    *out_key = pkey;
    *out_cert = x;

    return 0;
}

static X509_STORE *
s3_aia_store_root(void)
{
    X509_STORE *store = X509_STORE_new();

    if (store == NULL) {
        return NULL;
    }

    if (X509_STORE_add_cert(store, fx_root) != 1) {
        X509_STORE_free(store);
        ERR_clear_error();
        return NULL;
    }

    return store;
}

/* the count of the store certificates matching the subject needle */

static int
s3_aia_store_count(X509_STORE *store, const char *needle)
{
    STACK_OF(X509_OBJECT) * objs;
    int n, i, hits = 0;

    if (store == NULL) {
        return -1;
    }

    objs = X509_STORE_get0_objects(store);
    n = sk_X509_OBJECT_num(objs);

    for (i = 0; i < n; i++) {

        X509_OBJECT *o = sk_X509_OBJECT_value(objs, i);
        char         buf[256];

        if (X509_OBJECT_get_type(o) != X509_LU_X509) {
            continue;
        }

        X509_NAME_oneline(X509_get_subject_name(X509_OBJECT_get0_X509(o)), buf, sizeof(buf));

        if (strstr(buf, needle) != NULL) {
            hits++;
        }
    }

    return hits;
}

static void
s3_aia_work_reset(void)
{
    DIR           *dir;
    struct dirent *e;
    char           path[1300]; /* the work (1024) + the separator + the d_name (255) */

    dir = opendir(s3_aia_work);

    if (dir != NULL) {

        while ((e = readdir(dir)) != NULL) {

            if (e->d_name[0] == '.') {
                continue;
            }

            snprintf(path, sizeof(path), "%s/%s", s3_aia_work, e->d_name);
            (void)unlink(path);
        }

        closedir(dir);
    }
}

/* the plain TLS 1.3 handshake over a BIO pair: the client carries the
 * store of the anchors (the complete() gate reads it), the server
 * presents the certificate alone (leaf-only) */

static SSL *
s3_aia_client_ssl(SSL_CTX **ctx_out, SSL_CTX **srv_ctx_out, SSL **srv_out, X509 *leaf,
                  EVP_PKEY *leaf_key, X509 *anchor)
{
    SSL_CTX *cctx, *sctx;
    SSL     *cli, *srv;
    BIO     *b1, *b2;
    int      done_c = 0, done_s = 0, iter;

    cctx = SSL_CTX_new(TLS_client_method());
    sctx = SSL_CTX_new(TLS_server_method());

    if (cctx == NULL || sctx == NULL) {
        SSL_CTX_free(cctx);
        SSL_CTX_free(sctx);
        ERR_clear_error();
        return NULL;
    }

    /* the record-only shape: the handshake never aborts on the chain,
     * the store carries the anchors for the chase gate */

    SSL_CTX_set_verify(cctx, SSL_VERIFY_NONE, NULL);

    if (X509_STORE_add_cert(SSL_CTX_get_cert_store(cctx), anchor) != 1 ||
        SSL_CTX_use_certificate(sctx, leaf) != 1 || SSL_CTX_use_PrivateKey(sctx, leaf_key) != 1) {
        ERR_clear_error();
        SSL_CTX_free(cctx);
        SSL_CTX_free(sctx);
        return NULL;
    }

    cli = SSL_new(cctx);
    srv = SSL_new(sctx);

    b1 = BIO_new(BIO_s_bio());
    b2 = BIO_new(BIO_s_bio());

    if (cli == NULL || srv == NULL || b1 == NULL || b2 == NULL || BIO_make_bio_pair(b1, b2) != 1) {
        SSL_free(cli);
        SSL_free(srv);
        BIO_free(b1);
        BIO_free(b2);
        SSL_CTX_free(cctx);
        SSL_CTX_free(sctx);
        ERR_clear_error();
        return NULL;
    }

    SSL_set_bio(cli, b1, b1);
    SSL_set_bio(srv, b2, b2);

    SSL_set_connect_state(cli);
    SSL_set_accept_state(srv);

    for (iter = 0; iter < 100 && !(done_c && done_s); iter++) {

        if (!done_c) {
            int rc = SSL_connect(cli);

            if (rc == 1) {
                done_c = 1;

            } else {
                int err = SSL_get_error(cli, rc);

                if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                    goto failed;
                }
            }
        }

        if (!done_s) {
            int rc = SSL_accept(srv);

            if (rc == 1) {
                done_s = 1;

            } else {
                int err = SSL_get_error(srv, rc);

                if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                    goto failed;
                }
            }
        }
    }

    if (!(done_c && done_s)) {
        goto failed;
    }

    *ctx_out = cctx;
    *srv_ctx_out = sctx;
    *srv_out = srv;

    return cli;

failed:

    ERR_clear_error();
    SSL_free(cli);
    SSL_free(srv);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);

    return NULL;
}

/*
 * the legs
 */

static int
test_caissuers_url(void)
{
    char url[S3_AIA_URL_MAX];

    /* the leaf announces the caIssuers URI of its issuer */

    S3_ASSERT(s3_ssh3_aia_caissuers_url(fx_leaf, url, sizeof(url)) == S3_OK);
    S3_ASSERT(strcmp(url, fx_url_i1) == 0);

    /* the root carries no AIA at all */

    S3_ASSERT(s3_ssh3_aia_caissuers_url(fx_root, url, sizeof(url)) == S3_DECLINED);

    /* the non-URI locations ride past (the registeredID shape) */

    S3_ASSERT(s3_ssh3_aia_caissuers_url(fx_wrong, url, sizeof(url)) == S3_DECLINED);

    /* the oversized url refuses (the buffer bound) */

    S3_ASSERT(s3_ssh3_aia_caissuers_url(fx_leaf, url, 8) == S3_DECLINED);

    /* the argument guards */

    S3_ASSERT(s3_ssh3_aia_caissuers_url(NULL, url, sizeof(url)) == S3_ERROR);

    return s3_test_failures;
}

static int
test_parse_body(void)
{
    X509   *cert;
    u_char *der = NULL;
    int     der_len;

    /* the PEM form (the servers in the wild serve it) */

    cert = s3_ssh3_aia_parse_body((const u_char *)fx_pem_i1, strlen(fx_pem_i1));
    S3_ASSERT(cert != NULL);
    S3_ASSERT(s3_aia_der_equal(cert, fx_i1));
    X509_free(cert);

    /* the DER form (the RFC 5280 answer) */

    der_len = i2d_X509(fx_i1, &der);
    S3_ASSERT(der_len > 0);

    cert = s3_ssh3_aia_parse_body(der, (size_t)der_len);
    S3_ASSERT(cert != NULL);
    S3_ASSERT(s3_aia_der_equal(cert, fx_i1));
    X509_free(cert);
    OPENSSL_free(der);

    /* the garbage refuses */

    S3_ASSERT(s3_ssh3_aia_parse_body((const u_char *)"hello", 5) == NULL);
    S3_ASSERT(s3_ssh3_aia_parse_body(NULL, 5) == NULL);
    S3_ASSERT(s3_ssh3_aia_parse_body((const u_char *)fx_pem_i1, 0) == NULL);

    /* the body cap rides the parse too */

    {
        u_char *big = malloc(S3_AIA_FETCH_BYTES_MAX + 1);

        if (big != NULL) {
            memset(big, 0x30, S3_AIA_FETCH_BYTES_MAX + 1);
            S3_ASSERT(s3_ssh3_aia_parse_body(big, S3_AIA_FETCH_BYTES_MAX + 1) == NULL);
            free(big);
        }
    }

    return s3_test_failures;
}

static int
test_gate(void)
{
    X509_STORE *store = s3_aia_store_root();
    STACK_OF(X509) * untrusted;
    X509    *rogue_leaf;
    unsigned ok;

    S3_ASSERT(store != NULL);

    /* the complete chain: the leaf through the intermediate into the
     * anchor of the store */

    untrusted = sk_X509_new_null();
    sk_X509_push(untrusted, fx_i1);

    ok = s3_ssh3_aia_gate(fx_leaf, untrusted, store, X509_PURPOSE_SSL_SERVER);
    S3_ASSERT(ok == 1);

    sk_X509_free(untrusted);

    /* the missing intermediate: the gate refuses */

    ok = s3_ssh3_aia_gate(fx_leaf, NULL, store, X509_PURPOSE_SSL_SERVER);
    S3_ASSERT(ok == 0);

    /* the rogue chain: the leaf of the rogue CA builds nothing into
     * the anchor store - the fetched material rides the untrusted
     * side only, this is what neutralizes a MITM answer */

    {
        EVP_PKEY *rl_key;

        S3_ASSERT(s3_aia_cert_make(&rl_key, &rogue_leaf, "aia-test-rogue-leaf", fx_rogue,
                                   fx_rogue_key, 0, NULL, NULL) == 0);

        untrusted = sk_X509_new_null();
        sk_X509_push(untrusted, fx_rogue);

        ok = s3_ssh3_aia_gate(rogue_leaf, untrusted, store, X509_PURPOSE_SSL_SERVER);
        S3_ASSERT(ok == 0);

        sk_X509_free(untrusted);
        X509_free(rogue_leaf);
        EVP_PKEY_free(rl_key);
    }

    /* the anchors are the argument of the guard */

    S3_ASSERT(s3_ssh3_aia_gate(fx_leaf, NULL, NULL, X509_PURPOSE_SSL_SERVER) == 0);

    X509_STORE_free(store);

    return s3_test_failures;
}

static int
test_cache(void)
{
    char  path[1200];
    X509 *cert;

    /* the path form: the SHA-256 of the url, the .pem suffix */

    S3_ASSERT(s3_ssh3_aia_cache_path(s3_aia_work, fx_url_i1, path, sizeof(path)) == S3_OK);
    S3_ASSERT(strncmp(path, s3_aia_work, strlen(s3_aia_work)) == 0);

    {
        const char *file = strrchr(path, '/');

        S3_ASSERT(file != NULL);
        file++;

        S3_ASSERT(strlen(file) == 64 + 4);
        S3_ASSERT(strcmp(file + 64, ".pem") == 0);
    }

    /* the round trip: the stored certificate rides back identical */

    S3_ASSERT(s3_ssh3_aia_cache_store(s3_aia_work, fx_url_i1, fx_i1) == S3_OK);

    cert = s3_ssh3_aia_cache_load(s3_aia_work, fx_url_i1);
    S3_ASSERT(cert != NULL);
    S3_ASSERT(s3_aia_der_equal(cert, fx_i1));
    X509_free(cert);

    /* the miss of an unrecorded url */

    S3_ASSERT(s3_ssh3_aia_cache_load(s3_aia_work, "http://127.0.0.1:48080/none.pem") == NULL);

    /* the poisoned file is a plain miss, not a crash */

    {
        FILE *f = fopen(path, "w");

        S3_ASSERT(f != NULL);
        fputs("poisoned", f);
        fclose(f);

        S3_ASSERT(s3_ssh3_aia_cache_load(s3_aia_work, fx_url_i1) == NULL);
    }

    /* the argument guards */

    S3_ASSERT(s3_ssh3_aia_cache_store(NULL, fx_url_i1, fx_i1) == S3_ERROR);
    S3_ASSERT(s3_ssh3_aia_cache_load(NULL, fx_url_i1) == NULL);
    S3_ASSERT(s3_ssh3_aia_cache_path(NULL, fx_url_i1, path, sizeof(path)) == S3_ERROR);

    return s3_test_failures;
}

static int
test_chase_once(void)
{
    X509_STORE *store = s3_aia_store_root();
    STACK_OF(X509) * presented, *fetched = NULL;
    s3_ssh3_aia_chase_t ch;

    S3_ASSERT(store != NULL);

    /* the plain walk: the leaf-only presentation, the hook serves the
     * intermediate, the gate lands the chain in the anchor */

    s3_aia_hook_reset();
    s3_aia_hook_add(fx_url_i1, fx_pem_i1);

    s3_ssh3_aia_chase_init(&ch, store, NULL);
    ch.fetch = s3_aia_hook_fetch;

    presented = sk_X509_new_null();
    sk_X509_push(presented, fx_leaf);

    S3_ASSERT(s3_ssh3_aia_chase_once(&ch, presented, 0, &fetched) == S3_OK);
    S3_ASSERT(fetched != NULL);
    S3_ASSERT(sk_X509_num(fetched) == 1);
    S3_ASSERT(s3_aia_der_equal(sk_X509_value(fetched, 0), fx_i1));
    S3_ASSERT(s3_aia_hook_calls == 1);

    sk_X509_pop_free(fetched, X509_free);
    sk_X509_free(presented);

    /* the two-fetch walk: leafA <- b1 <- b2 <- root, the intermediate
     * and its issuer both ride the caIssuers answers */

    s3_aia_hook_reset();

    s3_aia_hook_add(fx_url_b1, fx_pem_b1);
    s3_aia_hook_add(fx_url_b2, fx_pem_b2);

    s3_ssh3_aia_chase_init(&ch, store, NULL);
    ch.fetch = s3_aia_hook_fetch;

    presented = sk_X509_new_null();
    sk_X509_push(presented, fx_la);

    S3_ASSERT(s3_ssh3_aia_chase_once(&ch, presented, 0, &fetched) == S3_OK);
    S3_ASSERT(fetched != NULL);
    S3_ASSERT(sk_X509_num(fetched) == 2);
    S3_ASSERT(s3_aia_der_equal(sk_X509_value(fetched, 0), fx_b1));
    S3_ASSERT(s3_aia_der_equal(sk_X509_value(fetched, 1), fx_b2));
    S3_ASSERT(s3_aia_hook_calls == 2);

    sk_X509_pop_free(fetched, X509_free);
    sk_X509_free(presented);

    /* the rogue answer: the certificate that did not issue the child
     * never enters the chase */

    s3_aia_hook_reset();
    s3_aia_hook_add(fx_url_i1, fx_pem_rogue);

    s3_ssh3_aia_chase_init(&ch, store, NULL);
    ch.fetch = s3_aia_hook_fetch;

    presented = sk_X509_new_null();
    sk_X509_push(presented, fx_leaf);

    S3_ASSERT(s3_ssh3_aia_chase_once(&ch, presented, 0, &fetched) == S3_DECLINED);
    S3_ASSERT(fetched == NULL);
    S3_ASSERT(s3_aia_hook_calls == 1);

    sk_X509_free(presented);

    /* the self-referential AIA: the answer is the child itself, the
     * issuer check refuses and the walk stops (the anchors here are
     * the rogue, so the loop control does not pass early) */

    s3_aia_hook_reset();
    s3_aia_hook_add(fx_url_i1, fx_pem_i1);

    {
        X509_STORE *rogue_store = X509_STORE_new();

        S3_ASSERT(rogue_store != NULL);
        S3_ASSERT(X509_STORE_add_cert(rogue_store, fx_rogue) == 1);

        s3_ssh3_aia_chase_init(&ch, rogue_store, NULL);
        ch.fetch = s3_aia_hook_fetch;

        presented = sk_X509_new_null();
        sk_X509_push(presented, fx_i1);

        S3_ASSERT(s3_ssh3_aia_chase_once(&ch, presented, 0, &fetched) == S3_DECLINED);
        S3_ASSERT(fetched == NULL);
        S3_ASSERT(s3_aia_hook_calls == 1);

        sk_X509_free(presented);
        X509_STORE_free(rogue_store);
    }

    X509_STORE_free(store);

    return s3_test_failures;
}

static int
test_chase_cache(void)
{
    X509_STORE *store = s3_aia_store_root();
    STACK_OF(X509) * presented, *fetched = NULL;
    s3_ssh3_aia_chase_t ch;

    S3_ASSERT(store != NULL);

    /* the warm cache keeps the pass off the network entirely: the
     * hook is armed to fail on any call, a call would fail the leg */

    s3_aia_work_reset();
    s3_aia_hook_reset();
    s3_aia_hook_fail = 1;

    S3_ASSERT(s3_ssh3_aia_cache_store(s3_aia_work, fx_url_i1, fx_i1) == S3_OK);

    s3_ssh3_aia_chase_init(&ch, store, s3_aia_work);
    ch.fetch = s3_aia_hook_fetch;

    presented = sk_X509_new_null();
    sk_X509_push(presented, fx_leaf);

    S3_ASSERT(s3_ssh3_aia_chase_once(&ch, presented, 1, &fetched) == S3_OK);
    S3_ASSERT(fetched != NULL);
    S3_ASSERT(sk_X509_num(fetched) == 1);
    S3_ASSERT(s3_aia_hook_calls == 0); /* zero network, the canon 2.6 warm shape */

    sk_X509_pop_free(fetched, X509_free);
    sk_X509_free(presented);

    /* the stale entry (a certificate that does not issue the child)
     * falls through to the network and gets rewritten behind it */

    s3_aia_work_reset();
    s3_aia_hook_reset();

    S3_ASSERT(s3_ssh3_aia_cache_store(s3_aia_work, fx_url_i1, fx_wrong) == S3_OK);
    s3_aia_hook_add(fx_url_i1, fx_pem_i1);

    s3_ssh3_aia_chase_init(&ch, store, s3_aia_work);
    ch.fetch = s3_aia_hook_fetch;

    presented = sk_X509_new_null();
    sk_X509_push(presented, fx_leaf);

    S3_ASSERT(s3_ssh3_aia_chase_once(&ch, presented, 1, &fetched) == S3_OK);
    S3_ASSERT(fetched != NULL);
    S3_ASSERT(s3_aia_hook_calls == 1);

    sk_X509_pop_free(fetched, X509_free);
    sk_X509_free(presented);

    {
        X509 *cert = s3_ssh3_aia_cache_load(s3_aia_work, fx_url_i1);

        S3_ASSERT(cert != NULL);
        S3_ASSERT(s3_aia_der_equal(cert, fx_i1)); /* the fresh answer behind the stale one */
        X509_free(cert);
    }

    /* the poisoned entry and the offline network: the passes decline
     * and never wedge (the canon stale/poisoned shape) */

    s3_aia_work_reset();
    s3_aia_hook_reset();
    s3_aia_hook_fail = 1;

    S3_ASSERT(s3_ssh3_aia_cache_store(s3_aia_work, fx_url_i1, fx_wrong) == S3_OK);

    s3_ssh3_aia_chase_init(&ch, store, s3_aia_work);
    ch.fetch = s3_aia_hook_fetch;

    presented = sk_X509_new_null();
    sk_X509_push(presented, fx_leaf);

    S3_ASSERT(s3_ssh3_aia_chase_once(&ch, presented, 1, &fetched) == S3_DECLINED);
    S3_ASSERT(s3_ssh3_aia_chase_once(&ch, presented, 0, &fetched) == S3_DECLINED);
    S3_ASSERT(fetched == NULL);

    sk_X509_free(presented);

    X509_STORE_free(store);

    return s3_test_failures;
}

static int
test_chase_caps(void)
{
    X509_STORE *store = s3_aia_store_root();
    STACK_OF(X509) * presented, *fetched = NULL;
    s3_ssh3_aia_chase_t ch;
    unsigned            i;

    S3_ASSERT(store != NULL);

    /* the depth cap: the chain runs 9 intermediates deep with the top
     * riding outside the anchors, the walk stops at 8 fetches and the
     * incomplete chain declines */

    s3_aia_hook_reset();

    for (i = 0; i + 1 < (unsigned)S3_AIA_CHAIN_N; i++) {
        s3_aia_hook_add(fx_url_chain[i], fx_pem_chain[i + 1]);
    }

    s3_ssh3_aia_chase_init(&ch, store, NULL);
    ch.fetch = s3_aia_hook_fetch;

    presented = sk_X509_new_null();
    sk_X509_push(presented, fx_chain[0]);

    S3_ASSERT(s3_ssh3_aia_chase_once(&ch, presented, 0, &fetched) == S3_DECLINED);
    S3_ASSERT(fetched == NULL);
    S3_ASSERT(s3_aia_hook_calls == S3_AIA_DEPTH_MAX);

    sk_X509_free(presented);

    /* the budget: the expired deadline stops the walk before any
     * fetch */

    s3_aia_hook_reset();

    s3_ssh3_aia_chase_init(&ch, store, NULL);
    ch.fetch = s3_aia_hook_fetch;
    ch.deadline = (unsigned long)time(NULL) - 1;

    presented = sk_X509_new_null();
    sk_X509_push(presented, fx_leaf);

    S3_ASSERT(s3_ssh3_aia_chase_once(&ch, presented, 0, &fetched) == S3_DECLINED);
    S3_ASSERT(fetched == NULL);
    S3_ASSERT(s3_aia_hook_calls == 0);

    sk_X509_free(presented);

    /* the argument guards */

    s3_ssh3_aia_chase_init(&ch, store, NULL);
    ch.fetch = s3_aia_hook_fetch;

    presented = sk_X509_new_null();
    sk_X509_push(presented, fx_leaf);

    S3_ASSERT(s3_ssh3_aia_chase_once(&ch, NULL, 0, &fetched) == S3_ERROR);
    S3_ASSERT(s3_ssh3_aia_chase_once(NULL, presented, 0, &fetched) == S3_ERROR);

    sk_X509_free(presented);

    X509_STORE_free(store);

    return s3_test_failures;
}

static int
test_bootstrap(void)
{
    SSL_CTX    *ctx;
    X509_STORE *store;
    char        path[1100], hex[128];
    FILE       *f;

    s3_aia_work_reset();
    s3_aia_setenv("SSH3_CA_BUNDLE", "");

    /* the plain bootstrap: the two embedded ISRG roots ride the store,
     * no bundle file around; the DER fingerprints pin the
     * byte-exactness of the generated snapshot */

    ctx = SSL_CTX_new(TLS_client_method());
    S3_ASSERT(ctx != NULL);

    S3_ASSERT(s3_ssh3_aia_trust_bootstrap(ctx, &s3_aia_test_log) == S3_OK);

    store = SSL_CTX_get_cert_store(ctx);
    S3_ASSERT(s3_aia_store_count(store, "ISRG Root X1") == 1);
    S3_ASSERT(s3_aia_store_count(store, "ISRG Root X2") == 1);
    S3_ASSERT(s3_aia_store_count(store, "ISRG Root") == 2);

    SSL_CTX_free(ctx);

    /* the user bundle next to known_hosts (the default path of the
     * HOME): the test CA rides in */

    snprintf(path, sizeof(path), "%s/.ssh3", s3_aia_work);
#if (S3_WIN32)
    (void)_mkdir(path);
#else
    (void)mkdir(path, 0700);
#endif

    snprintf(path, sizeof(path), "%s/.ssh3/ca-bundle.pem", s3_aia_work);

    f = fopen(path, "w");
    S3_ASSERT(f != NULL);
    fputs(fx_pem_i1, f); /* any usable PEM certificate rides the bundle */
    fclose(f);

    ctx = SSL_CTX_new(TLS_client_method());
    S3_ASSERT(ctx != NULL);

    S3_ASSERT(s3_ssh3_aia_trust_bootstrap(ctx, &s3_aia_test_log) == S3_OK);
    S3_ASSERT(s3_aia_store_count(SSL_CTX_get_cert_store(ctx), "ISRG Root") == 2);
    S3_ASSERT(s3_aia_store_count(SSL_CTX_get_cert_store(ctx), "CN=aia-test-i1") == 1);

    SSL_CTX_free(ctx);

    /* the env override: the broken file loses only its own trust, the
     * roots stay (the Go buildClientCAPool shape, never fatal) */

    snprintf(path, sizeof(path), "%s/broken.pem", s3_aia_work);

    f = fopen(path, "w");
    S3_ASSERT(f != NULL);
    fputs("not a bundle", f);
    fclose(f);

    s3_aia_setenv("SSH3_CA_BUNDLE", path);

    ctx = SSL_CTX_new(TLS_client_method());
    S3_ASSERT(ctx != NULL);

    S3_ASSERT(s3_ssh3_aia_trust_bootstrap(ctx, &s3_aia_test_log) == S3_OK);
    S3_ASSERT(s3_aia_store_count(SSL_CTX_get_cert_store(ctx), "ISRG Root") == 2);
    S3_ASSERT(s3_aia_store_count(SSL_CTX_get_cert_store(ctx), "CN=aia-test-i1") == 0);

    SSL_CTX_free(ctx);

    /* the bundle path form: the env wins, the default rides the home */

    {
        char bp[1100];

        s3_aia_setenv("SSH3_CA_BUNDLE", "/tmp/override.pem");
        S3_ASSERT(s3_ssh3_aia_bundle_path(bp, sizeof(bp)) == S3_OK);
        S3_ASSERT(strcmp(bp, "/tmp/override.pem") == 0);

        s3_aia_setenv("SSH3_CA_BUNDLE", "");
        S3_ASSERT(s3_ssh3_aia_bundle_path(bp, sizeof(bp)) == S3_OK);
        S3_ASSERT(strstr(bp, "ca-bundle.pem") != NULL);
        S3_ASSERT(strstr(bp, ".ssh3") != NULL);
    }

    s3_aia_setenv("SSH3_CA_BUNDLE", "");

    /* the fingerprint pin of the embedded roots (the DER SHA-256 the
     * generator verified, the same pair the Go fork pins) */

    {
        const char *x1 = "96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6";
        const char *x2 = "69729b8e15a86efc177a57afb7171dfc64add28c2fca8cf1507e34453ccb1470";

        ctx = SSL_CTX_new(TLS_client_method());
        S3_ASSERT(ctx != NULL);
        S3_ASSERT(s3_ssh3_aia_trust_bootstrap(ctx, &s3_aia_test_log) == S3_OK);

        store = SSL_CTX_get_cert_store(ctx);

        {
            STACK_OF(X509_OBJECT) *objs = X509_STORE_get0_objects(store);
            int n = sk_X509_OBJECT_num(objs), seen = 0, i;

            for (i = 0; i < n; i++) {

                X509_OBJECT *o = sk_X509_OBJECT_value(objs, i);
                X509        *cert;

                if (X509_OBJECT_get_type(o) != X509_LU_X509) {
                    continue;
                }

                cert = X509_OBJECT_get0_X509(o);

                if (s3_aia_der_sha256(cert, hex, sizeof(hex)) != 0) {
                    continue;
                }

                if (strcmp(hex, x1) == 0 || strcmp(hex, x2) == 0) {
                    seen++;
                }
            }

            S3_ASSERT(seen == 2);
        }

        SSL_CTX_free(ctx);
    }

    return s3_test_failures;
}

static int
test_complete(void)
{
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL     *srv = NULL, *cli;

    s3_aia_work_reset();

    /* the trigger classes ride before any connection state: the
     * expired chain is nothing a chase can fix, the clean verdict
     * does not chase */

    S3_ASSERT(s3_ssh3_aia_complete(NULL, X509_V_ERR_CERT_HAS_EXPIRED, &s3_aia_test_log) ==
              S3_DECLINED);
    S3_ASSERT(s3_ssh3_aia_complete(NULL, X509_V_OK, &s3_aia_test_log) == S3_DECLINED);

    s3_aia_hook_reset();

    /* the fetch hook rides the process-wide override: the complete()
     * builds its own chase struct, the units never dial out */

    s3_ssh3_aia_set_fetch(s3_aia_hook_fetch);

    /* the plain leg: the leaf-only server, the hook serves the
     * intermediate, the chase completes the chain against the anchor
     * store of the connection ctx */

    s3_aia_hook_add(fx_url_i1, fx_pem_i1);

    cli = s3_aia_client_ssl(&cctx, &sctx, &srv, fx_leaf, fx_leaf_key, fx_root);
    S3_ASSERT(cli != NULL);

    /* the peer certificate of the handshake (the get1 ref frees) */

    {
        X509 *peer = SSL_get1_peer_certificate(cli);

        S3_ASSERT(peer != NULL);
        X509_free(peer);
    }

    S3_ASSERT(s3_ssh3_aia_complete(cli, X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
                                   &s3_aia_test_log) == S3_OK);
    S3_ASSERT(s3_aia_hook_calls == 1);

    /* the cache of the chase state holds the fetched intermediate
     * (the chase wrote under the HOME of the run) */

    {
        char  cdir[1024];
        X509 *cert;

        S3_ASSERT(s3_ssh3_aia_cache_dir(cdir, sizeof(cdir)) == S3_OK);

        cert = s3_ssh3_aia_cache_load(cdir, fx_url_i1);
        S3_ASSERT(cert != NULL);
        S3_ASSERT(s3_aia_der_equal(cert, fx_i1));
        X509_free(cert);
    }

    SSL_free(srv);
    SSL_free(cli);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    /* the self-signed leaf: the TOFU territory of 2.3, the chase
     * stays out (no hook call) */

    s3_aia_hook_reset();

    cli = s3_aia_client_ssl(&cctx, &sctx, &srv, fx_self, fx_self_key, fx_root);
    S3_ASSERT(cli != NULL);

    S3_ASSERT(s3_ssh3_aia_complete(cli, X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
                                   &s3_aia_test_log) == S3_DECLINED);
    S3_ASSERT(s3_aia_hook_calls == 0);

    SSL_free(srv);
    SSL_free(cli);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    /* the default transport rides back (the last leg ran hookless) */

    s3_ssh3_aia_set_fetch(NULL);

    return s3_test_failures;
}

static int
test_chase_dir(void)
{
    char dir[1024];

    /* the HOME of the run rides the work tree */

    S3_ASSERT(s3_ssh3_aia_cache_dir(dir, sizeof(dir)) == S3_OK);
    S3_ASSERT(strstr(dir, ".ssh3") != NULL);
    S3_ASSERT(strstr(dir, "aia-cache") != NULL);

    return s3_test_failures;
}

/* the fixture release: the sanitizer legs demand the free */

static void
s3_aia_fixture_free(void)
{
    unsigned i;

    X509_free(fx_root);
    EVP_PKEY_free(fx_root_key);
    X509_free(fx_i1);
    EVP_PKEY_free(fx_i1_key);
    X509_free(fx_leaf);
    EVP_PKEY_free(fx_leaf_key);
    X509_free(fx_wrong);
    EVP_PKEY_free(fx_wrong_key);
    X509_free(fx_rogue);
    EVP_PKEY_free(fx_rogue_key);
    X509_free(fx_self);
    EVP_PKEY_free(fx_self_key);

    X509_free(fx_la);
    EVP_PKEY_free(fx_la_key);
    X509_free(fx_b1);
    EVP_PKEY_free(fx_b1_key);
    X509_free(fx_b2);
    EVP_PKEY_free(fx_b2_key);

    for (i = 0; i < (unsigned)S3_AIA_CHAIN_N; i++) {
        X509_free(fx_chain[i]);
        EVP_PKEY_free(fx_chain_key[i]);
    }
}

int
test_ssh3_aia(void)
{
    char leaf_aia[128];

    s3_aia_serial = 100;

    /* the work tree of the cache legs: the TMPDIR of the run */

    {
        const char *tmp = getenv("TMPDIR");

        if (tmp == NULL || tmp[0] == '\0') {
            tmp = getenv("TEMP");
        }

        if (tmp == NULL || tmp[0] == '\0') {
            tmp = getenv("TMP");
        }

        if (tmp == NULL || tmp[0] == '\0') {
            tmp = ".";
        }

        snprintf(s3_aia_work, sizeof(s3_aia_work), "%s/ssh3-aia-test", tmp);

#if (S3_WIN32)
        (void)_mkdir(s3_aia_work);
#else
        (void)mkdir(s3_aia_work, 0700);
#endif
        s3_aia_work_reset();
    }

    /* the HOME of the module: the cache dir and the bundle default
     * ride the work tree of the run */

    s3_aia_setenv("HOME", s3_aia_work);
    s3_aia_setenv("USERPROFILE", s3_aia_work);
    s3_aia_setenv("SSH3_CA_BUNDLE", "");

    /* the fixture of the run */

    S3_ASSERT(
        s3_aia_cert_make(&fx_root_key, &fx_root, "aia-test-root", NULL, NULL, 1, NULL, NULL) == 0);
    S3_ASSERT(s3_aia_cert_make(&fx_i1_key, &fx_i1, "aia-test-i1", fx_root, fx_root_key, 1, NULL,
                               "caIssuers;URI:http://127.0.0.1:48080/inter.pem") == 0);

    snprintf(leaf_aia, sizeof(leaf_aia), "caIssuers;URI:%s", fx_url_i1);
    S3_ASSERT(s3_aia_cert_make(&fx_leaf_key, &fx_leaf, "aia-test-leaf", fx_i1, fx_i1_key, 0,
                               "DNS:localhost,IP:127.0.0.1", leaf_aia) == 0);

    /* the wrong certificate: signed by the root, announces only the
     * registeredID location (no usable caIssuers URI) */

    S3_ASSERT(s3_aia_cert_make(&fx_wrong_key, &fx_wrong, "aia-test-wrong", fx_root, fx_root_key, 0,
                               NULL, "caIssuers;RID:1.2.3.4") == 0);

    S3_ASSERT(s3_aia_cert_make(&fx_rogue_key, &fx_rogue, "aia-test-rogue", NULL, NULL, 1, NULL,
                               NULL) == 0);

    S3_ASSERT(
        s3_aia_cert_make(&fx_self_key, &fx_self, "aia-test-self", NULL, NULL, 0, NULL, NULL) == 0);

    /* the two-fetch chain: leafA <- b1 <- b2 <- root */

    S3_ASSERT(s3_aia_cert_make(&fx_b2_key, &fx_b2, "aia-test-b2", fx_root, fx_root_key, 1, NULL,
                               NULL) == 0);
    S3_ASSERT(s3_aia_cert_make(&fx_b1_key, &fx_b1, "aia-test-b1", fx_b2, fx_b2_key, 1, NULL,
                               "caIssuers;URI:http://127.0.0.1:48080/chain-b.pem") == 0);
    snprintf(leaf_aia, sizeof(leaf_aia), "caIssuers;URI:%s", fx_url_b1);
    S3_ASSERT(s3_aia_cert_make(&fx_la_key, &fx_la, "aia-test-leafA", fx_b1, fx_b1_key, 0, NULL,
                               leaf_aia) == 0);

    /* the deep chain of the depth cap: leaf2 <- c1 <- ... <- c9, the
     * top rides outside the anchor store (the rogue signs it) */

    {
        int i;

        for (i = S3_AIA_CHAIN_N - 1; i >= 0; i--) {

            X509     *issuer = (i == S3_AIA_CHAIN_N - 1) ? fx_rogue : fx_chain[i + 1];
            EVP_PKEY *ikey = (i == S3_AIA_CHAIN_N - 1) ? fx_rogue_key : fx_chain_key[i + 1];
            char      aia[96];

            if (i < S3_AIA_CHAIN_N - 2) {
                snprintf(fx_url_chain[i], sizeof(fx_url_chain[i]), "http://127.0.0.1:48080/c%d.pem",
                         i + 1);
                snprintf(aia, sizeof(aia), "caIssuers;URI:%s", fx_url_chain[i]);

            } else {
                aia[0] = '\0';
            }

            S3_ASSERT(s3_aia_cert_make(&fx_chain_key[i], &fx_chain[i],
                                       i == 0 ? "aia-test-leaf2" : "aia-test-cn", issuer, ikey,
                                       i != 0, NULL, i < S3_AIA_CHAIN_N - 2 ? aia : NULL) == 0);
        }
    }

    S3_ASSERT(s3_aia_pem_of(fx_i1, fx_pem_i1, sizeof(fx_pem_i1)) != NULL);
    S3_ASSERT(s3_aia_pem_of(fx_rogue, fx_pem_rogue, sizeof(fx_pem_rogue)) != NULL);
    S3_ASSERT(s3_aia_pem_of(fx_b1, fx_pem_b1, sizeof(fx_pem_b1)) != NULL);
    S3_ASSERT(s3_aia_pem_of(fx_b2, fx_pem_b2, sizeof(fx_pem_b2)) != NULL);

    {
        int i;

        for (i = 0; i < S3_AIA_CHAIN_N; i++) {
            S3_ASSERT(s3_aia_pem_of(fx_chain[i], fx_pem_chain[i], sizeof(fx_pem_chain[i])) != NULL);
        }
    }

    (void)test_chase_dir();
    (void)test_caissuers_url();
    (void)test_parse_body();
    (void)test_gate();
    (void)test_cache();
    (void)test_chase_once();
    (void)test_chase_cache();
    (void)test_chase_caps();
    (void)test_bootstrap();
    (void)test_complete();

    s3_aia_fixture_free();

    return s3_test_failures;
}

S3_TEST_MAIN(test_ssh3_aia)
