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

#include <stdio.h>
#include <string.h>
#include <unistd.h>

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
    SSL_CTX  *ctx;

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
    SSL_CTX  *ctx_own, *ctx_sys;
    unsigned  own_n, sys_n;
    char      path[] = "/tmp/s3tscpXXXXXX";
    int       fd;
    FILE     *f;

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
     * the platform certificate present */

    S3_ASSERT(sys_n >= own_n);
    S3_ASSERT(sys_n == own_n + 1);

    s3_test_env_set("SSL_CERT_FILE", "");
    (void)unlink(path);

    SSL_CTX_free(ctx_own);
    SSL_CTX_free(ctx_sys);

    return s3_test_failures;
}

static int
test_bundle_overlay(void)
{
    SSL_CTX  *ctx;
    char      path[] = "/tmp/s3tbndXXXXXX";
    int       fd;
    FILE     *f;
    unsigned  before, after;

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

    OPENSSL_cleanup();

    return s3_test_failures;
}

S3_TEST_MAIN(test_trust_store)
