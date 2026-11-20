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
#include <openssl/x509v3.h>

#include <stdio.h>
#include <string.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

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
            "the ca flow commands (the wave 19: the client side signs\n"
            "the CSR with ssh3-ca):\n"
            "\n"
            "  keygen out.key [rsa]\n"
            "              generate the private key (ed25519, or rsa2048), 0600\n"
            "  csr key.pem out.csr cn [san]\n"
            "              build the CSR: the CN rides the subject, the optional\n"
            "              san takes dns:/ip:/email: forms separated by commas\n"
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

            STACK_OF(X509_OBJECT) *objs = X509_STORE_get0_objects(SSL_CTX_get_cert_store(ctx));

            printf("PROBE own=%d\n", sk_X509_OBJECT_num(objs));
        }

        SSL_CTX_free(ctx);

        ctx = SSL_CTX_new(TLS_client_method());

        if (ctx == NULL) {
            fprintf(stderr, "PROBE ctx failed\n");
            return 255;
        }

        {
            s3_int_t rc = s3_trust_store_build(ctx, S3_TRUST_POLICY_SYSTEM, &log);
            STACK_OF(X509_OBJECT) *objs = X509_STORE_get0_objects(SSL_CTX_get_cert_store(ctx));

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

#endif /* S3_CERT_NO_TICKETKEY (the probe build: the ssl unit stays                                \
        * out, the ticket-key command rides the full build) */

    if (strcmp(argv[1], "keygen") == 0 && argc >= 3) {

        /* the client-side key of the ca flow: ed25519 by default,
         * rsa2048 rides the "rsa" argument; the file lands 0600 */

        EVP_PKEY     *key = NULL;
        EVP_PKEY_CTX *kctx = NULL;
        int           fd;
        FILE         *f;
        BIO          *bio;
        int           rc = 255;

        if (argc >= 4 && strcmp(argv[3], "rsa") == 0) {
            kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);

            if (kctx == NULL || EVP_PKEY_keygen_init(kctx) <= 0 ||
                EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048) <= 0) {
                fprintf(stderr, "ssh3-cert: the rsa keygen failed\n");
                goto keygen_done;
            }
        } else {
            kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);

            if (kctx == NULL || EVP_PKEY_keygen_init(kctx) <= 0) {
                fprintf(stderr, "ssh3-cert: the ed25519 keygen failed\n");
                goto keygen_done;
            }
        }

        if (EVP_PKEY_generate(kctx, &key) <= 0) {
            fprintf(stderr, "ssh3-cert: the key generation failed\n");
            goto keygen_done;
        }

#ifdef S3_WIN32
        fd = _open(argv[2], _O_WRONLY | _O_CREAT | _O_TRUNC | _O_BINARY, _S_IREAD);
#else
        fd = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0600);
#endif

        if (fd == -1) {
            fprintf(stderr, "ssh3-cert: %s does not open for the key\n", argv[2]);
            goto keygen_done;
        }

        f = fdopen(fd, "wb");

        if (f == NULL) {
#ifdef S3_WIN32
            (void)_close(fd);
#else
            (void)close(fd);
#endif
            fprintf(stderr, "ssh3-cert: the stream of %s does not open\n", argv[2]);
            goto keygen_done;
        }

        bio = BIO_new_fp(f, BIO_NOCLOSE);

        if (bio == NULL || PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL) != 1) {
            fprintf(stderr, "ssh3-cert: the key of %s did not write\n", argv[2]);
        } else {
            printf("the key rides: %s (%s)\n", argv[2],
                   argc >= 4 && strcmp(argv[3], "rsa") == 0 ? "rsa2048" : "ed25519");
            rc = 0;
        }

        if (bio != NULL) {
            BIO_free(bio);
        }

        (void)fclose(f);

    keygen_done:

        if (kctx != NULL) {
            EVP_PKEY_CTX_free(kctx);
        }

        if (key != NULL) {
            EVP_PKEY_free(key);
        }

        return rc;
    }

    if (strcmp(argv[1], "csr") == 0 && argc >= 5) {

        /* the CSR of the ca flow: the key of the caller, the subject
         * CN, the optional SAN list of the dns:/ip:/email: forms */

        const char     *san_form = NULL;
        char            san[512];
        EVP_PKEY       *key;
        BIO            *in, *out;
        X509_REQ       *req = NULL;
        X509_NAME      *name;
        X509V3_CTX      vctx;
        X509_EXTENSION *ext = NULL;
        STACK_OF(X509_EXTENSION) * exts;
        int rc = 255;

        key = NULL;
        in = BIO_new_file(argv[2], "rb");

        if (in == NULL) {
            fprintf(stderr, "ssh3-cert: the key of %s does not open\n", argv[2]);
            return 255;
        }

        key = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL);
        BIO_free(in);

        if (key == NULL) {
            fprintf(stderr, "ssh3-cert: the key of %s does not read\n", argv[2]);
            return 255;
        }

        req = X509_REQ_new();

        if (req == NULL || X509_REQ_set_version(req, 0) != 1) {
            fprintf(stderr, "ssh3-cert: the request does not build\n");
            goto csr_done;
        }

        name = X509_REQ_get_subject_name(req);

        if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const u_char *)argv[4], -1, -1,
                                       0) != 1) {
            fprintf(stderr, "ssh3-cert: the subject does not build\n");
            goto csr_done;
        }

        if (argc >= 6) {

            /* the san list of the cert: the dns:/ip:/email: prefixes
             * translate to the openssl forms */

            const char *v = argv[5];

            if (strncmp(v, "dns:", 4) == 0 || strncmp(v, "ip:", 3) == 0 ||
                strncmp(v, "email:", 6) == 0) {
                size_t i, o = 0;

                for (i = 0; v[i] != '\0' && o + 8 < sizeof(san); i++) {

                    /* the openssl san form reads DNS:/IP:/email: - the
                     * lowercase prefixes fold in place, the comma
                     * separators of the operator input stay untouched */

                    if (strncmp(v + i, "dns:", 4) == 0) {
                        san[o++] = 'D';
                        san[o++] = 'N';
                        san[o++] = 'S';
                        san[o++] = ':';
                        i += 3;
                        continue;
                    }

                    if (strncmp(v + i, "ip:", 3) == 0) {
                        san[o++] = 'I';
                        san[o++] = 'P';
                        san[o++] = ':';
                        i += 2;
                        continue;
                    }

                    if (strncmp(v + i, "email:", 6) == 0) {
                        san[o++] = 'e';
                        san[o++] = 'm';
                        san[o++] = 'a';
                        san[o++] = 'i';
                        san[o++] = 'l';
                        san[o++] = ':';
                        i += 5;
                        continue;
                    }

                    san[o++] = v[i];
                }

                san[o] = '\0';
                san_form = san;
            }
        }

        if (X509_REQ_set_pubkey(req, key) != 1) {
            fprintf(stderr, "ssh3-cert: the public key does not set\n");
            goto csr_done;
        }

        if (san_form != NULL) {
            X509V3_set_ctx(&vctx, NULL, NULL, NULL, NULL, 0);
            ext = X509V3_EXT_conf_nid(NULL, &vctx, NID_subject_alt_name, san_form);

            if (ext == NULL) {
                fprintf(stderr, "ssh3-cert: the san of %s does not build\n", san_form);
                goto csr_done;
            }

            exts = sk_X509_EXTENSION_new_null();
            (void)sk_X509_EXTENSION_push(exts, ext);
            (void)X509_REQ_add_extensions(req, exts);
            sk_X509_EXTENSION_free(exts);
            X509_EXTENSION_free(ext);
        }

        if (X509_REQ_sign(req, key, NULL) <= 0) {
            fprintf(stderr, "ssh3-cert: the request does not sign\n");
            goto csr_done;
        }

        out = BIO_new_file(argv[3], "w");

        if (out == NULL || PEM_write_bio_X509_REQ(out, req) != 1) {
            fprintf(stderr, "ssh3-cert: the csr of %s did not write\n", argv[3]);
        } else {
            printf("the csr rides: %s (CN=%s%s%s)\n", argv[3], argv[4],
                   san_form != NULL ? ", SAN " : "", san_form != NULL ? san_form : "");
            rc = 0;
        }

        if (out != NULL) {
            BIO_free(out);
        }

    csr_done:

        if (req != NULL) {
            X509_REQ_free(req);
        }

        if (key != NULL) {
            EVP_PKEY_free(key);
        }

        return rc;
    }

    fprintf(stderr, "ssh3-cert: the command \"%s\" is not supported\n", argv[1]);
    s3_cert_usage(argv[0]);

    return 255;
}
