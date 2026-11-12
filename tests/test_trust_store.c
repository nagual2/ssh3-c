/*
 * Copyright (C) 2026 the ssh3-c authors
 */

/*
 * the trust store of the wave 14 (PLAN.md 14, phase 1a): the policy
 * parse, the own build (the embedded roots + the bundle overlays),
 * the system build (the platform paths + the own set, the union
 * never worse than the system alone), the test bundle path hook
 */

#include <openssl/x509.h>

#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if (S3_WIN32)
#include <direct.h>
#endif

#include <s3_core.h>
#include <s3_trust_store.h>

/* the cert fixture and the log of the harness only: the client and
 * the lockstep machines stay out (the unused statics of -Werror) */

#define S3_TEST_TLS_NO_CLIENT
#define S3_TEST_TLS_NO_LOCKSTEP

#include "s3_quic_tls_helper.h"

/* the env write of the test (the CRT of the windows leg carries no
 * setenv): the SSL_CERT_FILE mechanics of the system union test */

static void
s3_test_env_set(const char *key, const char *val)
{
#if (S3_WIN32)
    (void)_putenv_s(key, val);
#else
    (void)setenv(key, val, 1);
#endif
}

static void
s3_test_dir_make(const char *dir)
{
#if (S3_WIN32)
    (void)_mkdir(dir);
#else
    (void)mkdir(dir, 0700);
#endif
}

static int
test_policy_parse(void)
{
    s3_trust_policy_t p = S3_TRUST_POLICY_OWN;

    S3_ASSERT(s3_trust_policy_parse("own", &p) == 0 && p == S3_TRUST_POLICY_OWN);
    S3_ASSERT(s3_trust_policy_parse("OWN", &p) == 0 && p == S3_TRUST_POLICY_OWN);
    S3_ASSERT(s3_trust_policy_parse("system", &p) == 0 && p == S3_TRUST_POLICY_SYSTEM);
    S3_ASSERT(s3_trust_policy_parse("System", &p) == 0 && p == S3_TRUST_POLICY_SYSTEM);
    S3_ASSERT(s3_trust_policy_parse("bogus", &p) != 0);
    S3_ASSERT(s3_trust_policy_parse("", &p) != 0);
    S3_ASSERT(s3_trust_policy_parse(NULL, &p) != 0);

    /* the names ride back (the error messages and the logs) */

    S3_ASSERT(strcmp(s3_trust_policy_name(S3_TRUST_POLICY_OWN), "own") == 0);
    S3_ASSERT(strcmp(s3_trust_policy_name(S3_TRUST_POLICY_SYSTEM), "system") == 0);

    return s3_test_failures;
}

static unsigned
s3_store_certs(SSL_CTX *ctx)
{
    return sk_X509_OBJECT_num(X509_STORE_get0_objects(SSL_CTX_get_cert_store(ctx)));
}

static int
test_build_own(void)
{
    SSL_CTX *ctx;

    s3_test_tls_log_init();

    ctx = SSL_CTX_new(TLS_client_method());
    S3_ASSERT(ctx != NULL);

    /* the own policy: the embedded ISRG pair rides, the absent
     * bundle files ride quiet (the plain fresh-home shape) */

    S3_ASSERT(s3_trust_store_build(ctx, S3_TRUST_POLICY_OWN, &s3_test_tls_log) == S3_OK);
    S3_ASSERT(s3_store_certs(ctx) >= 2);

    SSL_CTX_free(ctx);

    /* the second build rides the duplicates as no-ops (the re-dial
     * of the same process re-runs the bootstrap) */

    ctx = SSL_CTX_new(TLS_client_method());
    S3_ASSERT(ctx != NULL);
    S3_ASSERT(s3_trust_store_build(ctx, S3_TRUST_POLICY_OWN, &s3_test_tls_log) == S3_OK);
    S3_ASSERT(s3_store_certs(ctx) >= 2);
    SSL_CTX_free(ctx);

    return s3_test_failures;
}

static int
test_build_system_union(void)
{
    SSL_CTX *ctx_own, *ctx_sys;
    unsigned own_n, sys_n;
    char     path[] = "/tmp/s3tscpXXXXXX";
    int      fd;
    FILE    *f;

    s3_test_tls_log_init();

    ctx_own = SSL_CTX_new(TLS_client_method());
    ctx_sys = SSL_CTX_new(TLS_client_method());
    S3_ASSERT(ctx_own != NULL && ctx_sys != NULL);

    S3_ASSERT(s3_trust_store_build(ctx_own, S3_TRUST_POLICY_OWN, &s3_test_tls_log) == S3_OK);

    own_n = s3_store_certs(ctx_own);

    /* the deterministic platform set: SSL_CERT_FILE is read by
     * set_default_verify_paths at the call time - one generated
     * certificate rides the system side and the union contract
     * shows its strict part without any host guarantee */

    {
        u_char cert[4096], key[4096];
        size_t cert_len = 0, key_len = 0;

        S3_ASSERT(s3_test_tls_gen_cert(cert, &cert_len, key, &key_len) == 0);

        fd = mkstemp(path);
        S3_ASSERT(fd != -1);

        f = fopen(path, "wb");
        S3_ASSERT(f != NULL);
        fwrite(cert, 1, cert_len, f);
        (void)fclose(f);
    }

    s3_test_env_set("SSL_CERT_FILE", path);

    S3_ASSERT(s3_trust_store_build(ctx_sys, S3_TRUST_POLICY_SYSTEM, &s3_test_tls_log) == S3_OK);

    sys_n = s3_store_certs(ctx_sys);

    /* the union contract: at least the own set, strictly more with
     * the platform certificate present (the unix strict part rides
     * the SSL_CERT_FILE fixture; the win strict part rides the
     * machine stores - the assert rides the unix leg only) */

    S3_ASSERT(sys_n >= own_n);

#if !(S3_WIN32)
    S3_ASSERT(sys_n == own_n + 1);
#endif

    s3_test_env_set("SSL_CERT_FILE", "");
    (void)unlink(path);

    SSL_CTX_free(ctx_own);
    SSL_CTX_free(ctx_sys);

    return s3_test_failures;
}

/*
 * the trust update of the wave 14 phase 1c: the fetched bundle body
 * validates (every PEM block a certificate, the count floor), the
 * landing is atomic (tmp+rename) into the state dir, the manifest
 * names the source and the sha256; the fetch hook carries the
 * fixture (zero network)
 */

static char        s3_update_dir[1024];
static s3_str_t    s3_update_body;
static const char *s3_update_hook_url;

static s3_int_t
s3_test_update_fetch(const char *url, s3_str_t *out)
{
    s3_update_hook_url = url;

    out->data = s3_alloc(s3_update_body.len + 1, &s3_test_tls_log);
    memcpy(out->data, s3_update_body.data, s3_update_body.len);
    out->len = s3_update_body.len;

    return S3_OK;
}

static int
test_update(void)
{
    char        line[160], cmd[1100];
    u_char      cert[4096], key[4096];
    size_t      cert_len = 0, key_len = 0;
    FILE       *f;
    const char *bundle;

    s3_test_tls_log_init();

    snprintf(s3_update_dir, sizeof(s3_update_dir), "/tmp/s3tup%d", (int)getpid());
    s3_test_dir_make(s3_update_dir);

    /* the fixture: the two generated PEM certificates glued (the
     * count floor of the product rides 30, the test hook points
     * lower) */

    S3_ASSERT(s3_test_tls_gen_cert(cert, &cert_len, key, &key_len) == 0);

    s3_update_body.len = cert_len * 2;
    s3_update_body.data = s3_alloc(s3_update_body.len, &s3_test_tls_log);
    memcpy(s3_update_body.data, cert, cert_len);
    memcpy(s3_update_body.data + cert_len, cert, cert_len);

    s3_trust_update_set_dir(s3_update_dir);
    s3_trust_update_set_min_certs(2);
    s3_trust_update_set_fetch(s3_test_update_fetch);

    S3_ASSERT(s3_trust_update_run("https://trust.example/bundle.pem", &s3_test_tls_log) == S3_OK);
    S3_ASSERT(strcmp(s3_update_hook_url, "https://trust.example/bundle.pem") == 0);

    bundle = s3_trust_bundle_path_get();
    S3_ASSERT(bundle != NULL);

    f = fopen(bundle, "rb");
    S3_ASSERT(f != NULL);
    S3_ASSERT(fgets(line, sizeof(line), f) != NULL);
    S3_ASSERT(strncmp(line, "-----BEGIN CERTIFICATE-----", 27) == 0);
    (void)fclose(f);

    /* the manifest names the source and the sha256 of the body */

    {
        char mpath[1200];

        snprintf(mpath, sizeof(mpath), "%s/trust-bundle.pem.man", s3_update_dir);

        f = fopen(mpath, "rb");
        S3_ASSERT(f != NULL);
        S3_ASSERT(fgets(line, sizeof(line), f) != NULL);
        S3_ASSERT(strstr(line, "https://trust.example/bundle.pem") == line);
        S3_ASSERT(fgets(line, sizeof(line), f) != NULL);
        S3_ASSERT(strlen(line) == 65); /* the sha256 hex + the newline */
        (void)fclose(f);
    }

    /* the invalid body refuses: the truncated pem block never
     * lands (the store copy of the previous run stays) */

    s3_update_body.len = 40;
    memcpy(s3_update_body.data, "-----BEGIN CERTIFICATE-----\nnot-a-cert\n", 40);

    S3_ASSERT(s3_trust_update_run("https://trust.example/bad.pem", &s3_test_tls_log) != S3_OK);

    /* the count floor refuses the single-cert body */

    s3_trust_update_set_min_certs(30);

    S3_ASSERT(s3_test_tls_gen_cert(cert, &cert_len, key, &key_len) == 0);
    memcpy(s3_update_body.data, cert, cert_len);
    s3_update_body.len = cert_len;

    S3_ASSERT(s3_trust_update_run("https://trust.example/one.pem", &s3_test_tls_log) != S3_OK);

    s3_trust_update_set_min_certs(0);
    s3_trust_update_set_fetch(NULL);
    s3_trust_update_set_dir(NULL);

    snprintf(cmd, sizeof(cmd), "rm -rf %s", s3_update_dir);

    if (system(cmd) != 0) {
        /* the wipe of the test dir is best effort */
    }

    return s3_test_failures;
}

static int
test_bundle_overlay(void)
{
    SSL_CTX *ctx;
    char     path[] = "/tmp/s3tbndXXXXXX";
    int      fd;
    FILE    *f;
    unsigned before, after;

    s3_test_tls_log_init();

    /* the generated self-signed certificate rides the overlay
     * fixture (the content of the file is arbitrary trust, the
     * store counts it) */

    {
        u_char cert[4096], key[4096];
        size_t cert_len = 0, key_len = 0;

        S3_ASSERT(s3_test_tls_gen_cert(cert, &cert_len, key, &key_len) == 0);

        fd = mkstemp(path);
        S3_ASSERT(fd != -1);
        (void)close(fd);

        f = fopen(path, "wb");
        S3_ASSERT(f != NULL);
        fwrite(cert, 1, cert_len, f);
        (void)fclose(f);
    }

    ctx = SSL_CTX_new(TLS_client_method());
    S3_ASSERT(ctx != NULL);

    S3_ASSERT(s3_trust_store_build(ctx, S3_TRUST_POLICY_OWN, &s3_test_tls_log) == S3_OK);
    before = s3_store_certs(ctx);

    /* the overlay hook points the build at the fixture (the test
     * twin of ~/.ssh3/trust-bundle.pem) */

    s3_trust_store_set_bundle_path(path);

    S3_ASSERT(s3_trust_store_build(ctx, S3_TRUST_POLICY_OWN, &s3_test_tls_log) == S3_OK);
    after = s3_store_certs(ctx);

    /* the self-signed fixture is a duplicate of nothing: the count
     * grows by the overlay entry */

    S3_ASSERT(after == before + 1);

    /* the NULL restores the default path */

    s3_trust_store_set_bundle_path(NULL);

    (void)unlink(path);
    SSL_CTX_free(ctx);

    return s3_test_failures;
}

static int
test_trust_store(void)
{
    (void)setvbuf(stdout, NULL, _IONBF, 0);

    test_policy_parse();
    test_build_own();
    test_build_system_union();
    test_bundle_overlay();
    test_update();

    OPENSSL_cleanup();

    return s3_test_failures;
}

S3_TEST_MAIN(test_trust_store)
