/*
 * Copyright (C) 2026 the ssh3-c authors
 */

/*
 * ssh3-cert - the PKI utility of the ssh3-c set (PLAN.md 14, the
 * split decision of the owner): the one-shot operations of the
 * certificate life live here, NOT in the daemon - the OpenWrt
 * flash and the resident memory of the always-running ssh3-server
 * stay clean of the phase 3/4 code (the client certificates, the
 * ssh3-ca). The daemon consumes the ready files this utility
 * prepares (the cert/key pair, the session ticket key, the anchor
 * bundles); the rotation rides the reopen channel.
 *
 * The commands of the phase 1 skeleton:
 *
 *   trust-update  fetch the trust bundle, validate and land it
 *                 atomically as ~/.ssh3/trust-bundle.pem (the
 *                 scheduler surface, moved off the client of the
 *                 wave 14; the exit 0 fresh / 255 stale)
 *   ticket-key f  generate a session ticket key file (the nginx
 *                 80-byte form the daemon reads; the pre-seeded
 *                 key survives the first daemon lifetime)
 *
 * The phase 3/4 commands (the keygen/selfsign/csr/ca chain) ride
 * their own waves - the stubs refuse with the phase note.
 *
 * The audit of the system PKI utilities (PLAN.md 14): the openssl
 * CLI is not guaranteed on OpenWrt (the openssl-util is an
 * optional package), the Windows certutil/PowerShell shapes are
 * not portable and miss the ed25519 - the utility rides the
 * already-linked libcrypto, no new dependency.
 */

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <stdio.h>
#include <string.h>

#if (S3_WIN32)
#include <winsock2.h>
#include <windows.h>
#endif

#include <s3_errno.h>
#if (S3_WIN32)
#include <s3_os_init.h>
#endif
#ifndef S3_CERT_NO_TICKETKEY
#include <s3_ssl.h>
#endif
#include <s3_trust_store.h>

/* the default source of the trust bundle update (the Mozilla set
 * of the curl distribution, the PEM form) */

#define S3_CERT_TRUST_UPDATE_URL "https://curl.se/ca/cacert.pem"

static void
s3_cert_usage(const char *prog)
{
    fprintf(stderr,
            "usage: %s <command> [args]\n"
            "\n"
            "the PKI utility of the ssh3-c set (the certificate life\n"
            "outside the always-running daemon):\n"
            "\n"
            "  trust-update [--trust-update-url url]\n"
            "              fetch the trust bundle, validate and land it\n"
            "              atomically as ~/.ssh3/trust-bundle.pem (the manifest\n"
            "              next to it names the source and the sha256; the\n"
            "              previous copy stays on any failure) - the scheduler\n"
            "              calls this once a day, exit 0 fresh / 255 stale\n"
            "  ticket-key file\n"
            "              generate a session ticket key file (the nginx\n"
            "              80-byte form the daemon reads: 16 name + 32 hmac\n"
            "              + 32 aes, 0600) - the pre-seeded key survives the\n"
            "              first daemon lifetime\n"
            "\n"
            "the phase 3/4 commands (the client certificates, the ssh3-ca):\n"
            "\n"
            "  keygen | selfsign | csr | sign\n"
            "              riding their own waves (PLAN.md 14)\n"
            "\n"
            "the instrument:\n"
            "\n"
            "  probe        print the openssl version and the trust set\n"
            "              counters (own / system) - no dial, no network\n",
            prog);
}

int
main(int argc, char **argv)
{
    s3_log_t log;

    log.fd = 2;
    log.log_level = S3_LOG_INFO;

#if (S3_WIN32)
    /* the winsock bootstrap of the fetch transport (the unix build
     * carries no init; the trust-update talks https) */

    if (s3_os_init() != S3_OK) {
        fprintf(stderr, "ssh3-cert: the net bootstrap failed\n");
        return 255;
    }
#endif

    if (argc < 2 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        s3_cert_usage(argv[0]);
        return argc < 2 ? 255 : 0;
    }

    if (strcmp(argv[1], "probe") == 0 || strcmp(argv[1], "--probe") == 0) {

        /* the trust matrix instrument (the phase 2 acceptance): the
         * openssl version, the own set, the system build - four
         * lines, no dial, no network; the machine classes of the
         * wave-14 matrix read this */

        SSL_CTX *ctx;

        printf("PROBE openssl=%s\n", OpenSSL_version(OPENSSL_VERSION));

        ctx = SSL_CTX_new(TLS_client_method());

        if (ctx == NULL) {
            fprintf(stderr, "PROBE ctx failed\n");
            return 255;
        }

        if (s3_trust_store_build(ctx, S3_TRUST_POLICY_OWN, &log) == S3_OK) {

            STACK_OF(X509_OBJECT) *objs =
                X509_STORE_get0_objects(SSL_CTX_get_cert_store(ctx));

            printf("PROBE own=%d\n", sk_X509_OBJECT_num(objs));
        }

        SSL_CTX_free(ctx);

        ctx = SSL_CTX_new(TLS_client_method());

        if (ctx == NULL) {
            fprintf(stderr, "PROBE ctx failed\n");
            return 255;
        }

        {
            s3_int_t              rc = s3_trust_store_build(ctx, S3_TRUST_POLICY_SYSTEM, &log);
            STACK_OF(X509_OBJECT) *objs =
                X509_STORE_get0_objects(SSL_CTX_get_cert_store(ctx));

            printf("PROBE system-rc=%ld system=%d\n", (long)rc, sk_X509_OBJECT_num(objs));
        }

        SSL_CTX_free(ctx);

        return 0;
    }

    if (strcmp(argv[1], "trust-update") == 0 || strcmp(argv[1], "--trust-update") == 0) {

        const char *url = S3_CERT_TRUST_UPDATE_URL;
        int         i;

        for (i = 2; i < argc; i++) {

            if (strcmp(argv[i], "--trust-update-url") == 0 && i + 1 < argc) {
                url = argv[i + 1];
                i++;
                continue;
            }

            fprintf(stderr, "ssh3-cert: trust-update takes only --trust-update-url url\n");
            return 255;
        }

        return s3_trust_update_run(url, &log) == S3_OK ? 0 : 255;
    }

#ifndef S3_CERT_NO_TICKETKEY

    if (strcmp(argv[1], "ticket-key") == 0 || strcmp(argv[1], "--ticket-key") == 0) {

        if (argc != 3) {
            fprintf(stderr, "ssh3-cert: ticket-key wants the file argument\n");
            return 255;
        }

        return s3_ssl_ticket_key_file_new(argv[2], &log) == S3_OK ? 0 : 255;
    }

#endif /* S3_CERT_NO_TICKETKEY (the probe build: the ssl unit stays
        * out, the ticket-key command rides the full build) */

    if (strcmp(argv[1], "keygen") == 0 || strcmp(argv[1], "selfsign") == 0 ||
        strcmp(argv[1], "csr") == 0 || strcmp(argv[1], "sign") == 0) {

        fprintf(stderr,
                "ssh3-cert: %s rides the phase 3/4 wave (PLAN.md 14: the client\n"
                "certificates, the ssh3-ca) - the stub refuses for now\n",
                argv[1]);

        return 255;
    }

    fprintf(stderr, "ssh3-cert: the command \"%s\" is not supported\n", argv[1]);
    s3_cert_usage(argv[0]);

    return 255;
}
