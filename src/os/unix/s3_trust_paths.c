/*
 * Copyright (C) 2026 the ssh3-c authors
 */

/*
 * the unix leg of the system store bridge (s3_trust_store.h): the
 * default verify paths of the OpenSSL build — the ca-certificates
 * of the distro (the /etc/ssl/certs canon). The SSL_CERT_FILE /
 * SSL_CERT_DIR env overrides ride the OpenSSL reading of the
 * paths, the test hooks pin them
 */

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <s3_trust_store.h>

s3_int_t
s3_trust_system_paths_apply(SSL_CTX *ctx, s3_log_t *log)
{
    if (ctx == NULL) {
        return S3_ERROR;
    }

    /* the distro store: the return value carries the availability
     * (the paths configured at the openssl build time), the empty
     * distro store rides DECLINED - the caller warns and the own
     * set carries the anchors (the union contract) */

    if (SSL_CTX_set_default_verify_paths(ctx) == 1) {
        s3_log_error(S3_LOG_INFO, log, 0, "the system certificate paths ride the anchors");
        return S3_OK;
    }

    ERR_clear_error();

    s3_log_error(S3_LOG_WARN, log, 0, "the system certificate paths are not available");

    return S3_DECLINED;
}
