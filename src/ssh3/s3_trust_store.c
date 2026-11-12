/*
 * Copyright (C) 2026 the ssh3-c authors
 */

/*
 * the trust store build over the two policies (the file header of
 * s3_trust_store.h carries the design).  The thin builder rides the
 * bootstrap of the AIA unit (the embedded roots + the user bundle)
 * and adds the two things the policies need: the bundle overlay
 * file and the platform paths of the system policy
 */

#include <openssl/err.h>

#include <stdio.h>
#include <string.h>

#include <s3_ssh3_aia.h>
#include <s3_trust_store.h>

static const char *s3_trust_bundle_override;

int
s3_trust_policy_parse(const char *text, s3_trust_policy_t *policy)
{
    if (text == NULL || policy == NULL) {
        return -1;
    }

    if (strcmp(text, "own") == 0 || strcmp(text, "OWN") == 0 ||
        strcmp(text, "Own") == 0) {
        *policy = S3_TRUST_POLICY_OWN;
        return 0;
    }

    if (strcmp(text, "system") == 0 || strcmp(text, "SYSTEM") == 0 ||
        strcmp(text, "System") == 0) {
        *policy = S3_TRUST_POLICY_SYSTEM;
        return 0;
    }

    return -1;
}

const char *
s3_trust_policy_name(s3_trust_policy_t policy)
{
    switch (policy) {
    case S3_TRUST_POLICY_SYSTEM:
        return "system";
    case S3_TRUST_POLICY_OWN:
    default:
        return "own";
    }
}

void
s3_trust_store_set_bundle_path(const char *path)
{
    s3_trust_bundle_override = path;
}

/* one bundle file into the store: the absent file is the plain
 * shape (the fresh home), the broken one loses only its trust */

static s3_int_t
s3_trust_store_bundle(SSL_CTX *ctx, const char *path, s3_log_t *log)
{
    FILE *probe;

    if (path == NULL || path[0] == '\0') {
        return S3_OK;
    }

    probe = fopen(path, "r");

    if (probe == NULL) {
        return S3_OK;
    }

    (void)fclose(probe);

    if (SSL_CTX_load_verify_locations(ctx, path, NULL) != 1) {
        s3_log_error(S3_LOG_WARN, log, 0, "the trust bundle \"%s\" did not load, riding without it",
                     path);
        ERR_clear_error();

        return S3_OK;
    }

    s3_log_error(S3_LOG_INFO, log, 0, "the trust bundle \"%s\" rides the store", path);

    return S3_OK;
}

s3_int_t
s3_trust_store_build(SSL_CTX *ctx, s3_trust_policy_t policy, s3_log_t *log)
{
    char path[1024];
    int  system_paths = 0;

    if (ctx == NULL || log == NULL) {
        return S3_ERROR;
    }

    /* the embedded roots + the user bundle ride both policies (the
     * union contract of the plan: the system build is never worse
     * than the own one); the bootstrap of the AIA unit carries the
     * pair (the ISRG PEM walk, the SSH3_CA_BUNDLE env, the
     * ~/.ssh3/ca-bundle.pem file, the first-contact mkdir) */

    if (s3_ssh3_aia_trust_bootstrap(ctx, log) != S3_OK) {
        return S3_ERROR;
    }

    /* the bundle overlay (the phase 1c feeds it, the file may ride
     * already): the default path lives next to the other client
     * state, the test hook points it elsewhere */

    if (s3_trust_bundle_override != NULL) {

        if (strlen(s3_trust_bundle_override) < sizeof(path)) {
            memcpy(path, s3_trust_bundle_override, strlen(s3_trust_bundle_override) + 1);

            (void)s3_trust_store_bundle(ctx, path, log);
        }

    } else if (s3_ssh3_aia_state_dir(path, sizeof(path)) == S3_OK) {

        {
            size_t len = strlen(path);

#if (S3_WIN32)
            if (len + 2 + sizeof("trust-bundle.pem") <= sizeof(path)) {
                path[len] = '\\';
#else
            if (len + 2 + sizeof("trust-bundle.pem") <= sizeof(path)) {
                path[len] = '/';
#endif
                memcpy(path + len + 1, "trust-bundle.pem", sizeof("trust-bundle.pem"));

                (void)s3_trust_store_bundle(ctx, path, log);
            }
        }
    }

    if (policy != S3_TRUST_POLICY_SYSTEM) {
        return S3_OK;
    }

    /* the platform paths of the system policy: unix rides the
     * default cert dir/file of the OpenSSL build; the win build of
     * the phase 1 carries no platform bridge yet - the empty result
     * is the warning, the own set already rides (the union never
     * refuses the dial) */

    system_paths = SSL_CTX_set_default_verify_paths(ctx);

    if (system_paths == 1) {
        s3_log_error(S3_LOG_INFO, log, 0, "the system certificate store rides the anchors");

    } else {
        ERR_clear_error();
        s3_log_error(S3_LOG_WARN, log, 0,
                     "the system certificate store is not available, riding the own set");
    }

    return S3_OK;
}
