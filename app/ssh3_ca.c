/*
 * Copyright (C) 2026 the ssh3-c authors
 */

/*
 * the CLI of the own certification authority (the wave 19, PLAN.md
 * 19): init / sign-server / sign-client / revoke / rotate over the
 * state directory of s3_ssh3_ca
 *
 * the state directory resolves SSH3_CA_DIR first, then ~/.ssh3/ca -
 * the same shape the daemon and the client ride for their ssh3 home
 */

#include <s3_core.h>
#include <s3_palloc.h>
#include <s3_ssh3_ca.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if (S3_WIN32)
#include <direct.h>
#else
#include <pwd.h>
#include <unistd.h>
#endif

static s3_log_t s3_ca_log = {0, S3_INVALID_FILE};

static void
usage(FILE *out)
{
    fprintf(out, "usage: ssh3-ca <command> [args]\n\n"
                 "the own certification authority of the ssh3-c set (the root,\n"
                 "the issuance and the revocation of the state directory):\n\n"
                 "  init <dir>\n"
                 "              generate the root (ed25519, 10 years) and the\n"
                 "              state index; an existing state declines\n"
                 "  sign-server <csr> <out>\n"
                 "              issue the server cert of the CSR (the SAN of\n"
                 "              the request, 825 days, chain + root in out)\n"
                 "  sign-client <csr> <out> <user>\n"
                 "              issue the client cert, the CN rides the user\n"
                 "              (the mapping of the server auth)\n"
                 "  revoke <serial|cert.pem>\n"
                 "              mark the cert revoked, regenerate crl.pem\n"
                 "  rotate\n"
                 "              back the state aside, fresh root; the old\n"
                 "              certs need the re-issuance\n\n"
                 "the state directory: SSH3_CA_DIR or ~/.ssh3/ca\n");
}

/* the state directory: the env rides first, the home second */

static int
s3_ca_dir(char *buf, size_t len)
{
    const char *env = getenv("SSH3_CA_DIR");

    if (env != NULL && env[0] != '\0') {
        (void)snprintf(buf, len, "%s", env);
        return 0;
    }

#if (S3_WIN32)
    {
        const char *home = getenv("USERPROFILE");

        if (home == NULL || home[0] == '\0') {
            return -1;
        }

        (void)snprintf(buf, len, "%s\\.ssh3\\ca", home);
    }
#else
    {
        const char *home = getenv("HOME");

        if (home == NULL || home[0] == '\0') {
            struct passwd *pw = getpwuid(getuid());

            if (pw == NULL || pw->pw_dir == NULL) {
                return -1;
            }

            home = pw->pw_dir;
        }

        (void)snprintf(buf, len, "%s/.ssh3/ca", home);
    }
#endif

    return 0;
}

int
main(int argc, char **argv)
{
    char dir[512];

    if (argc < 2 || strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        usage(stdout);
        return argc < 2 ? 1 : 0;
    }

    if (s3_ca_dir(dir, sizeof(dir)) != 0) {
        fprintf(stderr, "ssh3-ca: the state directory is unresolved (no "
                        "SSH3_CA_DIR, no home)\n");
        return 1;
    }

    if (strcmp(argv[1], "init") == 0) {

        const char *target = argc >= 3 ? argv[2] : dir;

        if (s3_ssh3_ca_init(target, NULL) != S3_OK) {
            fprintf(stderr,
                    "ssh3-ca: the state of %s was not created (an "
                    "existing ca.key declines)\n",
                    target);
            return 1;
        }

        printf("the CA state of %s rides: ca.key + ca.pem + index\n", target);

        return 0;
    }

    if (strcmp(argv[1], "sign-server") == 0 || strcmp(argv[1], "sign-client") == 0) {

        s3_pool_t    *pool;
        s3_ssh3_ca_t *ca = NULL;
        const char   *csr, *out, *user;
        char          serial[64];

        if (strcmp(argv[1], "sign-server") == 0) {
            if (argc != 4) {
                usage(stderr);
                return 1;
            }

            csr = argv[2];
            out = argv[3];
            user = NULL;
        } else {
            if (argc != 5) {
                usage(stderr);
                return 1;
            }

            csr = argv[2];
            out = argv[3];
            user = argv[4];
        }

        pool = s3_create_pool(4096, &s3_ca_log);

        if (pool == NULL || s3_ssh3_ca_open(dir, pool, NULL, &ca) != S3_OK) {
            fprintf(stderr,
                    "ssh3-ca: the state of %s is unreadable (run "
                    "init first)\n",
                    dir);
            return 1;
        }

        memset(serial, 0, sizeof(serial));

        if (s3_ssh3_ca_sign(ca, csr, out,
                            strcmp(argv[1], "sign-client") == 0 ? S3_SSH3_CA_CLIENT
                                                                : S3_SSH3_CA_SERVER,
                            user, serial, sizeof(serial)) != S3_OK) {
            fprintf(stderr,
                    "ssh3-ca: the CSR of %s did not issue (the body "
                    "is unreadable or the signature is broken)\n",
                    csr);
            return 1;
        }

        printf("%s issued: %s (serial %s)\n", argv[1], out, serial);

        return 0;
    }

    if (strcmp(argv[1], "revoke") == 0) {

        s3_pool_t    *pool;
        s3_ssh3_ca_t *ca = NULL;

        if (argc != 3) {
            usage(stderr);
            return 1;
        }

        pool = s3_create_pool(4096, &s3_ca_log);

        if (pool == NULL || s3_ssh3_ca_open(dir, pool, NULL, &ca) != S3_OK) {
            fprintf(stderr,
                    "ssh3-ca: the state of %s is unreadable (run "
                    "init first)\n",
                    dir);
            return 1;
        }

        if (s3_ssh3_ca_revoke(ca, argv[2]) == S3_OK) {
            printf("revoked: %s (crl.pem regenerated)\n", argv[2]);

            return 0;
        }

        fprintf(stderr,
                "ssh3-ca: the revoke of %s declined (the serial is "
                "unknown or the state is frozen)\n",
                argv[2]);

        return 1;
    }

    if (strcmp(argv[1], "rotate") == 0) {

        size_t retired = 0;

        if (s3_ssh3_ca_rotate(dir, NULL, &retired) != S3_OK) {
            fprintf(stderr,
                    "ssh3-ca: the rotation of %s failed (the backup "
                    "rename or the fresh init)\n",
                    dir);
            return 1;
        }

        printf("the CA rotated: the old state backs aside, %zu cert(s) "
               "need the re-issuance\n",
               retired);

        return 0;
    }

    fprintf(stderr, "ssh3-ca: unknown command %s\n", argv[1]);
    usage(stderr);

    return 1;
}
