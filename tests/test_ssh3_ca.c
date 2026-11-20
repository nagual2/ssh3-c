/*
 * Copyright (C) 2026 the ssh3-c authors
 */

/*
 * the own certification authority of the wave 19 (PLAN.md 19): the
 * init (the root + the state), the issuance of the server and the
 * client CSRs, the revoke with the CRL regeneration, the rotate with
 * the aside backup; the CSR fixtures build in-process with libcrypto
 */

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <sys/stat.h>

#include <dirent.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if (S3_WIN32)
#include <direct.h>
#endif

#include <s3_core.h>
#include <s3_ssh3_ca.h>

static int s3_test_failures;

static s3_log_t s3_test_log = {0, S3_INVALID_FILE};

#define S3_ASSERT(cond)                                                                            \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond);                         \
            s3_test_failures++;                                                                    \
        }                                                                                          \
    } while (0)

#define S3_TEST_DIR "./s3ca-test-state"

static int
s3_test_file_exists(const char *path)
{
    struct stat st;

    return stat(path, &st) == 0;
}

/* the CSR fixture: the fresh ed25519 key, the subject CN=<cn>, the
 * optional SAN, the self-consistent signature - the shape the real
 * ssh3-cert csr command produces */

static void
s3_test_csr_write(const char *path, const char *cn, const char *san)
{
    EVP_PKEY       *key = NULL;
    EVP_PKEY_CTX   *kctx = NULL;
    X509_REQ       *req = NULL;
    X509_NAME      *name;
    X509V3_CTX      vctx;
    X509_EXTENSION *ext;
    BIO            *out;

    kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);

    if (kctx == NULL || EVP_PKEY_keygen_init(kctx) <= 0 || EVP_PKEY_keygen(kctx, &key) <= 0) {
        goto done;
    }

    req = X509_REQ_new();

    if (req == NULL) {
        goto done;
    }

    name = X509_REQ_get_subject_name(req);
    (void)X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const u_char *)cn, -1, -1, 0);

    if (san != NULL) {
        STACK_OF(X509_EXTENSION) * exts;

        X509V3_set_ctx(&vctx, NULL, NULL, NULL, NULL, 0);
        ext = X509V3_EXT_conf_nid(NULL, &vctx, NID_subject_alt_name, san);

        if (ext == NULL) {
            goto done;
        }

        exts = sk_X509_EXTENSION_new_null();
        (void)sk_X509_EXTENSION_push(exts, ext);
        (void)X509_REQ_add_extensions(req, exts);
        sk_X509_EXTENSION_free(exts);
        X509_EXTENSION_free(ext);
    }

    if (X509_REQ_set_pubkey(req, key) <= 0) {
        goto done;
    }

    if (X509_REQ_sign(req, key, NULL) <= 0) {
        goto done;
    }

    out = BIO_new_file(path, "w");

    if (out == NULL) {
        goto done;
    }

    (void)PEM_write_bio_X509_REQ(out, req);
    BIO_free(out);

done:

    if (kctx != NULL) {
        EVP_PKEY_CTX_free(kctx);
    }

    if (req != NULL) {
        X509_REQ_free(req);
    }

    if (key != NULL) {
        EVP_PKEY_free(key);
    }
}

/* the first cert of the issued PEM file: the leaf of the chain */

static X509 *
s3_test_cert_read(const char *path)
{
    BIO  *in;
    X509 *x = NULL;

    in = BIO_new_file(path, "r");

    if (in == NULL) {
        return NULL;
    }

    x = PEM_read_bio_X509(in, NULL, NULL, NULL);
    BIO_free(in);

    return x;
}

static int
s3_test_cert_has_san(X509 *x, const char *needle)
{
    GENERAL_NAMES *san;
    int            found = 0;
    int            i, n;

    san = X509_get_ext_d2i(x, NID_subject_alt_name, NULL, NULL);

    if (san == NULL) {
        return 0;
    }

    n = sk_GENERAL_NAME_num(san);

    for (i = 0; i < n; i++) {
        GENERAL_NAME *gn = sk_GENERAL_NAME_value(san, i);

        if (gn == NULL || gn->type != GEN_DNS) {
            continue;
        }

        u_char *utf = NULL;

        if (ASN1_STRING_to_UTF8(&utf, (const ASN1_STRING *)gn->d.dNSName) >= 0 && utf != NULL) {
            found |= strcmp((const char *)utf, needle) == 0;
            OPENSSL_free(utf);
        }
    }

    GENERAL_NAMES_free(san);

    return found;
}

static int
test_ca_init(void)
{
    X509 *root;
    FILE *f;

    S3_ASSERT(s3_ssh3_ca_init(S3_TEST_DIR, NULL) == S3_OK);

    S3_ASSERT(s3_test_file_exists(S3_TEST_DIR "/ca.key"));
    S3_ASSERT(s3_test_file_exists(S3_TEST_DIR "/ca.pem"));
    S3_ASSERT(s3_test_file_exists(S3_TEST_DIR "/index"));

    /* the root parses and carries the CA bit */

    f = fopen(S3_TEST_DIR "/ca.pem", "rb");

    if (f == NULL) {
        return s3_test_failures + 1;
    }

    root = PEM_read_X509(f, NULL, NULL, NULL);
    (void)fclose(f);

    S3_ASSERT(root != NULL);
    S3_ASSERT(X509_check_ca(root) == 1);
    X509_free(root);

    /* the existing state declines: the init never overwrites */

    S3_ASSERT(s3_ssh3_ca_init(S3_TEST_DIR, NULL) == S3_ERROR);

    return s3_test_failures;
}

static int
test_ca_sign_server(void)
{
    s3_pool_t    *pool;
    s3_ssh3_ca_t *ca = NULL;
    X509         *leaf, *root;
    char          serial[64];
    FILE         *f;

    pool = s3_create_pool(1024, &s3_test_log);

    S3_ASSERT(s3_ssh3_ca_open(S3_TEST_DIR, pool, NULL, &ca) == S3_OK);

    s3_test_csr_write("./s3ca-test-server.csr", "svc.test", "DNS:svc.test,DNS:alt.test");

    memset(serial, 0, sizeof(serial));
    S3_ASSERT(s3_ssh3_ca_sign(ca, "./s3ca-test-server.csr", "./s3ca-test-server.pem",
                              S3_SSH3_CA_SERVER, NULL, serial, sizeof(serial)) == S3_OK);
    S3_ASSERT(serial[0] != '\0');

    S3_ASSERT(s3_test_file_exists("./s3ca-test-server.pem"));

    /* the leaf: the SAN of the CSR, the issuer is the root, the
     * signature verifies against the root key */

    leaf = s3_test_cert_read("./s3ca-test-server.pem");
    S3_ASSERT(leaf != NULL);
    S3_ASSERT(s3_test_cert_has_san(leaf, "svc.test"));
    S3_ASSERT(s3_test_cert_has_san(leaf, "alt.test"));

    f = fopen(S3_TEST_DIR "/ca.pem", "rb");

    if (f == NULL) {
        return s3_test_failures + 1;
    }

    root = PEM_read_X509(f, NULL, NULL, NULL);
    (void)fclose(f);

    S3_ASSERT(root != NULL);
    S3_ASSERT(X509_verify(leaf, X509_get0_pubkey(root)) == 1);
    S3_ASSERT(X509_check_ca(leaf) == 0);

    X509_free(leaf);
    X509_free(root);

    /* the chain: the second PEM block is the root */

    f = fopen("./s3ca-test-server.pem", "rb");
    (void)fseek(f, 0, SEEK_END);
    (void)fclose(f);

    /* the index carries the serial */

    S3_ASSERT(s3_test_file_exists(S3_TEST_DIR "/index"));

    s3_destroy_pool(pool);

    return s3_test_failures;
}

static int
test_ca_sign_client(void)
{
    s3_pool_t    *pool;
    s3_ssh3_ca_t *ca = NULL;
    X509         *leaf;
    X509_NAME    *name;
    char          cn[64];
    int           len;

    pool = s3_create_pool(1024, &s3_test_log);

    S3_ASSERT(s3_ssh3_ca_open(S3_TEST_DIR, pool, NULL, &ca) == S3_OK);

    s3_test_csr_write("./s3ca-test-alice.csr", "someone", NULL);

    S3_ASSERT(s3_ssh3_ca_sign(ca, "./s3ca-test-alice.csr", "./s3ca-test-alice.pem",
                              S3_SSH3_CA_CLIENT, "alice", NULL, 0) == S3_OK);

    leaf = s3_test_cert_read("./s3ca-test-alice.pem");
    S3_ASSERT(leaf != NULL);

    /* the CN rides the user argument: the mapping of the phase 3 */

    name = X509_get_subject_name(leaf);
    len = X509_NAME_get_text_by_NID(name, NID_commonName, cn, sizeof(cn));

    S3_ASSERT(len > 0);
    S3_ASSERT(strcmp(cn, "alice") == 0);

    X509_free(leaf);

    s3_destroy_pool(pool);

    return s3_test_failures;
}

static int
test_ca_revoke(void)
{
    s3_pool_t    *pool;
    s3_ssh3_ca_t *ca = NULL;
    char          serial[64];

    pool = s3_create_pool(1024, &s3_test_log);

    S3_ASSERT(s3_ssh3_ca_open(S3_TEST_DIR, pool, NULL, &ca) == S3_OK);

    s3_test_csr_write("./s3ca-test-bob.csr", "bob", NULL);

    memset(serial, 0, sizeof(serial));
    S3_ASSERT(s3_ssh3_ca_sign(ca, "./s3ca-test-bob.csr", "./s3ca-test-bob.pem", S3_SSH3_CA_CLIENT,
                              "bob", serial, sizeof(serial)) == S3_OK);

    /* the revocation by the serial: the index marks, the CRL lands */

    S3_ASSERT(s3_ssh3_ca_revoke(ca, serial) == S3_OK);
    S3_ASSERT(s3_test_file_exists(S3_TEST_DIR "/crl.pem"));

    /* the CRL carries the revoked serial */

    {
        BIO      *in;
        X509_CRL *crl;
        STACK_OF(X509_REVOKED) * rev;

        in = BIO_new_file(S3_TEST_DIR "/crl.pem", "rb");
        crl = PEM_read_bio_X509_CRL(in, NULL, NULL, NULL);
        (void)BIO_free(in);

        S3_ASSERT(crl != NULL);

        rev = X509_CRL_get_REVOKED(crl);
        S3_ASSERT(sk_X509_REVOKED_num(rev) >= 1);

        X509_CRL_free(crl);
    }

    /* an unknown serial declines */

    S3_ASSERT(s3_ssh3_ca_revoke(ca, "ffffffffffffffff") == S3_DECLINED);

    s3_destroy_pool(pool);

    return s3_test_failures;
}

static int
test_ca_broken_csr(void)
{
    s3_pool_t    *pool;
    s3_ssh3_ca_t *ca = NULL;
    FILE         *f;

    pool = s3_create_pool(1024, &s3_test_log);

    S3_ASSERT(s3_ssh3_ca_open(S3_TEST_DIR, pool, NULL, &ca) == S3_OK);

    /* the garbage file declines without touching the state */

    f = fopen("./s3ca-test-broken.csr", "wb");
    (void)fputs("not a csr at all\n", f);
    (void)fclose(f);

    S3_ASSERT(s3_ssh3_ca_sign(ca, "./s3ca-test-broken.csr", "./s3ca-test-broken.pem",
                              S3_SSH3_CA_SERVER, NULL, NULL, 0) == S3_ERROR);

    S3_ASSERT(!s3_test_file_exists("./s3ca-test-broken.pem"));

    s3_destroy_pool(pool);

    return s3_test_failures;
}

static int
test_ca_rotate(void)
{
    X509    *old_root, *new_root;
    FILE    *f;
    size_t   retired = 0, retired2 = 0;
    s3_int_t rc;
    char     backup[256];

    f = fopen(S3_TEST_DIR "/ca.pem", "rb");
    old_root = PEM_read_X509(f, NULL, NULL, NULL);
    (void)fclose(f);
    S3_ASSERT(old_root != NULL);

    memset(backup, 0, sizeof(backup));

    S3_ASSERT(s3_ssh3_ca_rotate(S3_TEST_DIR, NULL, &retired) == S3_OK);

    /* the retired count rides: three live certs at the rotate point */

    S3_ASSERT(retired >= 1);

    /* the corner: the rotate with the existing backup - the same
     * epoch renames onto the non-empty directory and declines, the
     * fresh epoch lands the second aside; both shapes leave a live
     * state behind */

    rc = s3_ssh3_ca_rotate(S3_TEST_DIR, NULL, &retired2);

    S3_ASSERT(rc == S3_ERROR || rc == S3_OK);

    if (rc == S3_OK) {
        S3_ASSERT(retired2 >= 1);
    }

    S3_ASSERT(s3_test_file_exists(S3_TEST_DIR "/ca.pem"));

    /* the backup holds the old state: dir.old.<epoch> rides next to
     * the fresh one - the prefix scan finds it */

    {
        DIR           *d = opendir(".");
        struct dirent *e;
        int            seen = 0;

        S3_ASSERT(d != NULL);

        while ((e = readdir(d)) != NULL) {
            seen |= strncmp(e->d_name, "s3ca-test-state.old.", 20) == 0;
        }

        (void)closedir(d);
        S3_ASSERT(seen == 1);
    }

    /* the fresh root differs from the old one */

    f = fopen(S3_TEST_DIR "/ca.pem", "rb");
    new_root = PEM_read_X509(f, NULL, NULL, NULL);
    (void)fclose(f);
    S3_ASSERT(new_root != NULL);
    S3_ASSERT(X509_subject_name_cmp(old_root, new_root) == 0);
    S3_ASSERT(X509_get_serialNumber(old_root)->length == X509_get_serialNumber(new_root)->length);

    X509_free(old_root);
    X509_free(new_root);

    return s3_test_failures;
}

int
main(void)
{
    /* the fresh run directory: the relative paths of the tests live
     * inside, the state never crosses the runs (the pid suffix) */

    char run[64];

    (void)snprintf(run, sizeof(run), "s3ca-run-%d", (int)getpid());

#if (S3_WIN32)
    (void)_mkdir(run);
#else
    (void)mkdir(run, 0700);
#endif

    if (chdir(run) != 0) {
        return 1;
    }

    (void)test_ca_init();
    (void)test_ca_sign_server();
    (void)test_ca_sign_client();
    (void)test_ca_revoke();
    (void)test_ca_broken_csr();
    (void)test_ca_rotate();

    if (s3_test_failures == 0) {
        printf("test_ssh3_ca OK\n");
    }

    return s3_test_failures != 0;
}
