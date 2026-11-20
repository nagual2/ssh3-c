/*
 * Copyright (C) 2026 the ssh3-c authors
 */

/*
 * the own certification authority of the wave 19 (PLAN.md 19): the
 * root, the index and the CRL of one state directory, the issuance
 * rides the CSR of the caller.  the libcrypto X509 machinery only -
 * the module owns no transport, the CLI of app/ssh3_ca.c wires it
 */

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <fcntl.h>
#include <sys/stat.h>

#if (S3_WIN32)
#include <direct.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <s3_ssh3_ca.h>

/* the lifetimes of the wave 19: the root decade, the server the
 * 825-day shape of the public web, the client the 398-day shape */

#define S3_CA_ROOT_DAYS   3650
#define S3_CA_SERVER_DAYS 825
#define S3_CA_CLIENT_DAYS 398
#define S3_CA_CRL_DAYS    30

#define S3_CA_SERIAL_BYTES 8

#define S3_CA_PATH_MAX 512

struct s3_ssh3_ca_s {
    s3_pool_t *pool;
    s3_log_t  *log;
    char       dir[S3_CA_PATH_MAX];
    EVP_PKEY  *key;  /* the root private key */
    X509      *cert; /* the root certificate */
};

static s3_int_t s3_ca_index_append(s3_ssh3_ca_t *ca, const char *serial, char type,
                                   const char *subject, long notafter);
static s3_int_t s3_ca_index_mark_revoke(s3_ssh3_ca_t *ca, const char *serial);
static s3_int_t s3_ca_crl_rebuild(s3_ssh3_ca_t *ca);
static s3_int_t s3_ca_key_write(const char *path, EVP_PKEY *key);
static s3_int_t s3_ca_cert_write(const char *path, X509 *x);
static void     s3_ca_serial_hex(const ASN1_INTEGER *serial, char *buf, size_t len);

/* the private key lands 0600: the plain BIO_new_file would create
 * the world-readable form of the root */

static s3_int_t
s3_ca_key_write(const char *path, EVP_PKEY *key)
{
    int   fd;
    FILE *f;
    BIO  *bio;
    int   rc;

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);

    if (fd == -1) {
        return S3_ERROR;
    }

    f = fdopen(fd, "wb");

    if (f == NULL) {
        (void)close(fd);
        return S3_ERROR;
    }

    bio = BIO_new_fp(f, BIO_NOCLOSE);

    if (bio == NULL) {
        (void)fclose(f);
        return S3_ERROR;
    }

    rc = PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL) == 1 ? S3_OK : S3_ERROR;

    BIO_free(bio);
    (void)fclose(f);

    return rc;
}

static s3_int_t
s3_ca_cert_write(const char *path, X509 *x)
{
    BIO *bio;
    int  rc;

    bio = BIO_new_file(path, "w");

    if (bio == NULL) {
        return S3_ERROR;
    }

    rc = PEM_write_bio_X509(bio, x) == 1 ? S3_OK : S3_ERROR;

    BIO_free(bio);

    return rc;
}

static void
s3_ca_serial_hex(const ASN1_INTEGER *serial, char *buf, size_t len)
{
    BIGNUM *bn;
    u_char  raw[64];
    int     n;
    size_t  i;

    if (len == 0) {
        return;
    }

    buf[0] = '\0';

    if (serial == NULL) {
        return;
    }

    bn = ASN1_INTEGER_to_BN(serial, NULL);

    if (bn == NULL) {
        return;
    }

    n = BN_num_bytes(bn);

    if (n <= 0 || (size_t)n > sizeof(raw) || (size_t)(n * 2) + 1 > len) {
        BN_free(bn);
        return;
    }

    (void)BN_bn2bin(bn, raw);
    BN_free(bn);

    for (i = 0; (size_t)i < (size_t)n; i++) {
        (void)snprintf(buf + i * 2, 3, "%02x", raw[i]);
    }
}

/* the serial of the new cert: S3_CA_SERIAL_BYTES random bytes, the
 * top bit cleared so the ASN.1 integer stays positive */

static s3_int_t
s3_ca_serial_new(ASN1_INTEGER *out)
{
    u_char   raw[S3_CA_SERIAL_BYTES];
    BIGNUM  *bn;
    s3_int_t rc;

    if (RAND_bytes(raw, sizeof(raw)) != 1) {
        return S3_ERROR;
    }

    raw[0] &= 0x7f;

    if (raw[0] == 0) {
        raw[0] = 1;
    }

    bn = BN_bin2bn(raw, sizeof(raw), NULL);

    if (bn == NULL) {
        return S3_ERROR;
    }

    rc = BN_to_ASN1_INTEGER(bn, out) != NULL ? S3_OK : S3_ERROR;
    BN_free(bn);

    return rc;
}

/* the extension of the issued cert by the openssl conf form; the
 * ctx carries the issuer and the subject so the AKI rides */

static X509_EXTENSION *
s3_ca_ext(X509 *issuer, X509 *subject, const char *form)
{
    X509V3_CTX  vctx;
    const char *eq = strchr(form, '=');
    char        name[128];
    size_t      n;

    if (eq == NULL || (size_t)(eq - form) >= sizeof(name)) {
        return NULL;
    }

    /* the form splits at the first equality: the name resolves
     * through the nconf walker, the value rides whole */

    n = (size_t)(eq - form);
    (void)memcpy(name, form, n);
    name[n] = 0;

    X509V3_set_ctx(&vctx, issuer, subject, NULL, NULL, 0);

    return X509V3_EXT_nconf(NULL, &vctx, name, eq + 1);
}

static s3_int_t
s3_ca_ext_add(X509 *x, X509_EXTENSION *ext, int critical)
{
    if (ext == NULL) {
        return S3_ERROR;
    }

    if (critical) {
        (void)X509_EXTENSION_set_critical(ext, 1);
    }

    if (X509_add_ext(x, ext, -1) != 1) {
        X509_EXTENSION_free(ext);
        return S3_ERROR;
    }

    X509_EXTENSION_free(ext);

    return S3_OK;
}

s3_int_t
s3_ssh3_ca_init(const char *dir, s3_log_t *log)
{
    EVP_PKEY     *key = NULL;
    EVP_PKEY_CTX *kctx = NULL;
    X509         *x = NULL;
    X509_NAME    *name;
    char          path[S3_CA_PATH_MAX + 16];
    FILE         *index;
    s3_int_t      rc = S3_ERROR;

    (void)log;

    if (dir == NULL || strlen(dir) >= sizeof(path) - 32) {
        return S3_ERROR;
    }

    /* the state never overwrites silently */

    (void)snprintf(path, sizeof(path), "%s/ca.key", dir);

    if (access(path, F_OK) == 0) {
        return S3_ERROR;
    }

#if (S3_WIN32)
    (void)_mkdir(dir);
#else
    if (mkdir(dir, 0700) == -1 && errno != EEXIST) {
        return S3_ERROR;
    }
#endif

    /* the root key: ed25519 */

    kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);

    if (kctx == NULL || EVP_PKEY_keygen_init(kctx) <= 0 || EVP_PKEY_keygen(kctx, &key) <= 0) {
        goto done;
    }

    /* the self-signed root: 10 years, the CA bit critical */

    x = X509_new();

    if (x == NULL || X509_set_version(x, 2) != 1) {
        goto done;
    }

    if (s3_ca_serial_new(X509_get_serialNumber(x)) != S3_OK) {
        goto done;
    }

    name = X509_get_subject_name(x);

    if (X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const u_char *)"ssh3-c", -1, -1, 0) !=
            1 ||
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const u_char *)"ssh3-ca", -1, -1,
                                   0) != 1) {
        goto done;
    }

    if (X509_set_issuer_name(x, name) != 1 || X509_set_pubkey(x, key) != 1) {
        goto done;
    }

    {
        long now = (long)time(NULL);

        if (ASN1_TIME_set(X509_getm_notBefore(x), now) == NULL ||
            ASN1_TIME_set(X509_getm_notAfter(x), now + S3_CA_ROOT_DAYS * 86400) == NULL) {
            goto done;
        }
    }

    if (s3_ca_ext_add(x, s3_ca_ext(NULL, x, "basicConstraints=critical,CA:TRUE"), 1) != S3_OK ||
        s3_ca_ext_add(x, s3_ca_ext(NULL, x, "keyUsage=critical,keyCertSign,cRLSign"), 1) != S3_OK ||
        s3_ca_ext_add(x, s3_ca_ext(NULL, x, "subjectKeyIdentifier=hash"), 0) != S3_OK) {
        goto done;
    }

    if (X509_sign(x, key, NULL) <= 0) {
        goto done;
    }

    (void)snprintf(path, sizeof(path), "%s/ca.key", dir);

    if (s3_ca_key_write(path, key) != S3_OK) {
        goto done;
    }

    (void)snprintf(path, sizeof(path), "%s/ca.pem", dir);

    if (s3_ca_cert_write(path, x) != S3_OK) {
        goto done;
    }

    (void)snprintf(path, sizeof(path), "%s/index", dir);
    index = fopen(path, "w");

    if (index == NULL) {
        goto done;
    }

    (void)fclose(index);

    rc = S3_OK;

done:

    if (kctx != NULL) {
        EVP_PKEY_CTX_free(kctx);
    }

    if (key != NULL) {
        EVP_PKEY_free(key);
    }

    if (x != NULL) {
        X509_free(x);
    }

    return rc;
}

static void
s3_ca_state_cleanup(void *data)
{
    s3_ssh3_ca_t *ca = data;

    if (ca->key != NULL) {
        EVP_PKEY_free(ca->key);
        ca->key = NULL;
    }

    if (ca->cert != NULL) {
        X509_free(ca->cert);
        ca->cert = NULL;
    }
}

s3_int_t
s3_ssh3_ca_open(const char *dir, s3_pool_t *pool, s3_log_t *log, s3_ssh3_ca_t **ca)
{
    s3_ssh3_ca_t *state;
    BIO          *bio;
    char          path[S3_CA_PATH_MAX + 16];
    FILE         *f;

    if (dir == NULL || pool == NULL || ca == NULL || strlen(dir) >= sizeof(state->dir)) {
        return S3_ERROR;
    }

    state = s3_pcalloc(pool, sizeof(s3_ssh3_ca_t));

    if (state == NULL) {
        return S3_ERROR;
    }

    state->pool = pool;
    state->log = log;
    (void)snprintf(state->dir, sizeof(state->dir), "%s", dir);

    (void)snprintf(path, sizeof(path), "%s/ca.key", dir);
    f = fopen(path, "rb");

    if (f == NULL) {
        return S3_ERROR;
    }

    state->key = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    (void)fclose(f);

    if (state->key == NULL) {
        return S3_ERROR;
    }

    (void)snprintf(path, sizeof(path), "%s/ca.pem", dir);
    bio = BIO_new_file(path, "rb");

    if (bio == NULL) {
        return S3_ERROR;
    }

    state->cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (state->cert == NULL) {
        return S3_ERROR;
    }

    *ca = state;

    /* the libcrypto objects of the state: the pool cleanup frees
     * them at the destroy (the EVP/X509 live outside the arena) */

    {
        s3_pool_cleanup_t *cln = s3_pool_cleanup_add(pool, 0);

        if (cln == NULL) {
            return S3_ERROR;
        }

        cln->handler = s3_ca_state_cleanup;
        cln->data = state;
    }

    return S3_OK;
}

/* the SAN extension of the CSR copies onto the issued cert: the
 * server names ride what the operator asked in the request */

static s3_int_t
s3_ca_copy_req_san(X509 *x, X509_REQ *req)
{
    STACK_OF(X509_EXTENSION) * exts;
    int i, n;

    exts = X509_REQ_get_extensions(req);

    if (exts == NULL) {
        return S3_OK; /* no extensions: nothing to copy */
    }

    n = sk_X509_EXTENSION_num(exts);

    for (i = 0; i < n; i++) {
        X509_EXTENSION *ext = sk_X509_EXTENSION_value(exts, i);
        X509_EXTENSION *copy;

        if (ext == NULL || OBJ_obj2nid(X509_EXTENSION_get_object(ext)) != NID_subject_alt_name) {
            continue;
        }

        copy = X509_EXTENSION_dup(ext);

        if (copy == NULL) {
            sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
            return S3_ERROR;
        }

        if (X509_add_ext(x, copy, -1) != 1) {
            X509_EXTENSION_free(copy);
            sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
            return S3_ERROR;
        }

        X509_EXTENSION_free(copy);
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

        return S3_OK;
    }

    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

    return S3_OK;
}

s3_int_t
s3_ssh3_ca_sign(s3_ssh3_ca_t *ca, const char *csr_path, const char *out_path, s3_uint_t is_client,
                const char *user, char *serial_hex, size_t serial_len)
{
    BIO      *in;
    X509_REQ *req = NULL;
    EVP_PKEY *req_key;
    X509     *x = NULL;
    char      subject[512];
    char      serial[64];
    long      now = (long)time(NULL);
    long      days = is_client ? S3_CA_CLIENT_DAYS : S3_CA_SERVER_DAYS;
    s3_int_t  rc = S3_ERROR;
    FILE     *out;

    if (ca == NULL || csr_path == NULL || out_path == NULL) {
        return S3_ERROR;
    }

    in = BIO_new_file(csr_path, "rb");

    if (in == NULL) {
        return S3_ERROR;
    }

    req = PEM_read_bio_X509_REQ(in, NULL, NULL, NULL);
    BIO_free(in);

    if (req == NULL) {
        return S3_ERROR;
    }

    req_key = X509_REQ_get0_pubkey(req);

    if (req_key == NULL || X509_REQ_verify(req, req_key) <= 0) {

        /* the self-consistency of the request: the broken body never
         * reaches the issuance */

        X509_REQ_free(req);
        return S3_ERROR;
    }

    x = X509_new();

    if (x == NULL || X509_set_version(x, 2) != 1 ||
        s3_ca_serial_new(X509_get_serialNumber(x)) != S3_OK ||
        X509_set_issuer_name(x, X509_get_subject_name(ca->cert)) != 1 ||
        X509_set_subject_name(x, X509_REQ_get_subject_name(req)) != 1) {
        goto done;
    }

    if (is_client && user != NULL && user[0] != '\0') {

        /* the CN override: the mapping of the phase 3 reads the user
         * from the CN (and the SAN spki/email) of the client cert */

        int pos = X509_NAME_get_index_by_NID(X509_get_subject_name(x), NID_commonName, -1);

        if (pos >= 0) {

            /* the delete leaves the entry to the caller: the copy of
             * the request subject dies here, the fresh CN rides last */

            X509_NAME_ENTRY *ne = X509_NAME_get_entry(X509_get_subject_name(x), pos);

            (void)X509_NAME_delete_entry(X509_get_subject_name(x), pos);

            if (ne != NULL) {
                X509_NAME_ENTRY_free(ne);
            }
        }

        (void)X509_NAME_add_entry_by_txt(X509_get_subject_name(x), "CN", MBSTRING_ASC,
                                         (const u_char *)user, -1, -1, 0);
    }

    if (X509_set_pubkey(x, req_key) != 1) {
        goto done;
    }

    {
        long notafter = now + days * 86400;

        if (ASN1_TIME_set(X509_getm_notBefore(x), now - 3600) == NULL ||
            ASN1_TIME_set(X509_getm_notAfter(x), notafter) == NULL) {
            goto done;
        }
    }

    if (s3_ca_ext_add(x, s3_ca_ext(ca->cert, x, "basicConstraints=critical,CA:FALSE"), 1) !=
            S3_OK ||
        s3_ca_ext_add(x, s3_ca_ext(ca->cert, x, "keyUsage=digitalSignature"), 1) != S3_OK ||
        s3_ca_ext_add(
            x,
            s3_ca_ext(ca->cert, x,
                      is_client ? "extendedKeyUsage=clientAuth" : "extendedKeyUsage=serverAuth"),
            0) != S3_OK ||
        s3_ca_ext_add(x, s3_ca_ext(ca->cert, x, "authorityKeyIdentifier=keyid"), 0) != S3_OK) {
        goto done;
    }

    if (s3_ca_copy_req_san(x, req) != S3_OK) {
        goto done;
    }

    if (X509_sign(x, ca->key, NULL) <= 0) {
        goto done;
    }

    /* the chain file: the leaf + the root, the daemon reads it
     * directly as its cert source */

    out = fopen(out_path, "wb");

    if (out == NULL) {
        goto done;
    }

    {
        int ok = PEM_write_X509(out, x) == 1 && PEM_write_X509(out, ca->cert) == 1;
        (void)fclose(out);

        if (!ok) {
            goto done;
        }
    }

    s3_ca_serial_hex(X509_get_serialNumber(x), serial, sizeof(serial));

    (void)snprintf(subject, sizeof(subject), "%s", "");
    {
        char *oneline = X509_NAME_oneline(X509_get_subject_name(x), NULL, 0);

        if (oneline != NULL) {
            (void)snprintf(subject, sizeof(subject), "%s", oneline);
            OPENSSL_free(oneline);
        }
    }

    if (s3_ca_index_append(ca, serial, is_client ? 'C' : 'S', subject, now + days * 86400) !=
        S3_OK) {
        goto done;
    }

    if (serial_hex != NULL && serial_len > 0) {
        (void)snprintf(serial_hex, serial_len, "%s", serial);
    }

    rc = S3_OK;

done:

    if (req != NULL) {
        X509_REQ_free(req);
    }

    if (x != NULL) {
        X509_free(x);
    }

    return rc;
}

/* the index of the issued certs: one line
 * serial|type|subject|notafter|status - the append of one issuance */

static s3_int_t
s3_ca_index_append(s3_ssh3_ca_t *ca, const char *serial, char type, const char *subject,
                   long notafter)
{
    char  path[S3_CA_PATH_MAX + 16];
    FILE *f;

    (void)snprintf(path, sizeof(path), "%s/index", ca->dir);
    f = fopen(path, "a");

    if (f == NULL) {
        return S3_ERROR;
    }

    if (fprintf(f, "%s|%c|%s|%ld|V\n", serial, type, subject, notafter) < 0) {
        (void)fclose(f);
        return S3_ERROR;
    }

    (void)fclose(f);

    return S3_OK;
}

/* the index walk of the revoke: the line of the serial marks R in
 * place; the count of the marks returns, zero declines */

static s3_int_t
s3_ca_index_mark_revoke(s3_ssh3_ca_t *ca, const char *serial)
{
    char   path[S3_CA_PATH_MAX + 16];
    char   tmp[S3_CA_PATH_MAX + 24];
    FILE  *in, *out;
    char   line[1024];
    int    marked = 0;
    size_t slen;

    (void)snprintf(path, sizeof(path), "%s/index", ca->dir);
    (void)snprintf(tmp, sizeof(tmp), "%s.tmp", path);

    in = fopen(path, "r");

    if (in == NULL) {
        return S3_ERROR;
    }

    out = fopen(tmp, "w");

    if (out == NULL) {
        (void)fclose(in);
        return S3_ERROR;
    }

    slen = strlen(serial);

    while (fgets(line, sizeof(line), in) != NULL) {

        char  *first = strchr(line, '|');
        size_t serial_len;

        if (first == NULL) {
            (void)fputs(line, out);
            continue;
        }

        serial_len = (size_t)(first - line);

        if (serial_len == slen && strncmp(line, serial, slen) == 0 && first[1] != '\0' &&
            line[strlen(line) - 2] == 'V') {

            /* the live line of this serial: the V before the newline
             * flips to R */

            line[strlen(line) - 2] = 'R';
            marked = 1;
        }

        (void)fputs(line, out);
    }

    (void)fclose(in);
    (void)fclose(out);

    if (marked && rename(tmp, path) != 0) {
        (void)unlink(tmp);
        return S3_ERROR;
    }

    if (!marked) {
        (void)unlink(tmp);
        return S3_DECLINED;
    }

    return S3_OK;
}

/* the CRL of the revoked serials: the index walk collects the R
 * lines, the entries sign with the root, crl.pem lands atomically */

static s3_int_t
s3_ca_crl_rebuild(s3_ssh3_ca_t *ca)
{
    char          path[S3_CA_PATH_MAX + 16];
    char          tmp[S3_CA_PATH_MAX + 24];
    FILE         *in;
    BIO          *out;
    X509_CRL     *crl = NULL;
    X509_REVOKED *rev;
    ASN1_INTEGER *serial;
    char          line[1024];
    int           ok;
    s3_int_t      rc = S3_ERROR;
    long          now = (long)time(NULL);

    (void)snprintf(path, sizeof(path), "%s/index", ca->dir);

    in = fopen(path, "r");

    if (in == NULL) {
        return S3_ERROR;
    }

    crl = X509_CRL_new();

    if (crl == NULL || X509_CRL_set_version(crl, 2) != 1 ||
        X509_CRL_set_issuer_name(crl, X509_get_subject_name(ca->cert)) != 1) {
        (void)fclose(in);
        goto done;
    }

    {
        ASN1_TIME *last = ASN1_TIME_set(NULL, now);
        ASN1_TIME *next = ASN1_TIME_set(NULL, now + S3_CA_CRL_DAYS * 86400);
        int        ok = last != NULL && next != NULL && X509_CRL_set1_lastUpdate(crl, last) == 1 &&
                 X509_CRL_set1_nextUpdate(crl, next) == 1;

        if (last != NULL) {
            ASN1_TIME_free(last);
        }

        if (next != NULL) {
            ASN1_TIME_free(next);
        }

        if (!ok) {
            (void)fclose(in);
            goto done;
        }
    }

    while (fgets(line, sizeof(line), in) != NULL) {

        char  *first;
        char   serial_buf[128];
        size_t serial_len;

        if (strlen(line) < 6 || line[strlen(line) - 2] != 'R') {
            continue; /* the live line */
        }

        first = strchr(line, '|');

        if (first == NULL) {
            continue;
        }

        serial_len = (size_t)(first - line);

        if (serial_len == 0 || serial_len >= sizeof(serial_buf)) {
            continue;
        }

        (void)memcpy(serial_buf, line, serial_len);
        serial_buf[serial_len] = '\0';

        rev = X509_REVOKED_new();

        if (rev == NULL) {
            (void)fclose(in);
            goto done;
        }

        /* the hex serial back into the integer: the BN path */

        {
            BIGNUM *bn = NULL;

            (void)BN_hex2bn(&bn, serial_buf);

            if (bn == NULL) {
                X509_REVOKED_free(rev);
                continue;
            }

            serial = BN_to_ASN1_INTEGER(bn, NULL);
            BN_free(bn);

            if (serial == NULL) {
                X509_REVOKED_free(rev);
                continue;
            }

            {
                ASN1_TIME *rev_at = ASN1_TIME_set(NULL, now);

                ok = rev_at != NULL && X509_REVOKED_set_serialNumber(rev, serial) == 1 &&
                     X509_REVOKED_set_revocationDate(rev, rev_at) == 1;

                if (rev_at != NULL) {
                    ASN1_TIME_free(rev_at);
                }
            }

            ASN1_INTEGER_free(serial);

            if (!ok) {
                X509_REVOKED_free(rev);
                continue;
            }
        }

        if (X509_CRL_add0_revoked(crl, rev) != 1) {
            X509_REVOKED_free(rev);
            continue;
        }
    }

    (void)fclose(in);

    if (X509_CRL_sign(crl, ca->key, NULL) <= 0) {
        goto done;
    }

    (void)snprintf(tmp, sizeof(tmp), "%s.tmp", path);

    /* the crl.pem of the same directory: the atomic landing via the
     * tmp + rename of the trust-store shape */

    (void)snprintf(tmp, sizeof(tmp), "%s/crl.pem.tmp", ca->dir);

    out = BIO_new_file(tmp, "w");

    if (out == NULL) {
        goto done;
    }

    if (PEM_write_bio_X509_CRL(out, crl) != 1) {
        BIO_free(out);
        (void)unlink(tmp);
        goto done;
    }

    BIO_free(out);

    (void)snprintf(path, sizeof(path), "%s/crl.pem", ca->dir);

    if (rename(tmp, path) != 0) {
        (void)unlink(tmp);
        goto done;
    }

    rc = S3_OK;

done:

    if (crl != NULL) {
        X509_CRL_free(crl);
    }

    return rc;
}

s3_int_t
s3_ssh3_ca_revoke(s3_ssh3_ca_t *ca, const char *spec)
{
    char serial[64];

    if (ca == NULL || spec == NULL || spec[0] == '\0') {
        return S3_ERROR;
    }

    /* the cert file path: the serial reads out of the file; the
     * otherwise the spec is the hex serial itself */

    if (access(spec, F_OK) == 0) {
        BIO  *in = BIO_new_file(spec, "rb");
        X509 *x;

        if (in == NULL) {
            return S3_ERROR;
        }

        x = PEM_read_bio_X509(in, NULL, NULL, NULL);
        BIO_free(in);

        if (x == NULL) {
            return S3_ERROR;
        }

        s3_ca_serial_hex(X509_get_serialNumber(x), serial, sizeof(serial));
        X509_free(x);

        if (serial[0] == '\0') {
            return S3_ERROR;
        }
    } else {
        (void)snprintf(serial, sizeof(serial), "%s", spec);
    }

    if (s3_ca_index_mark_revoke(ca, serial) != S3_OK) {
        return S3_DECLINED;
    }

    return s3_ca_crl_rebuild(ca);
}

/* the rotation: the whole state backs aside as dir.old.<epoch>, a
 * fresh init rides, the retired count returns for the operator */

s3_int_t
s3_ssh3_ca_rotate(const char *dir, s3_log_t *log, size_t *retired)
{
    char   backup[S3_CA_PATH_MAX];
    char   path[S3_CA_PATH_MAX + 16];
    FILE  *f;
    char   line[1024];
    size_t live = 0;
    long   epoch = (long)time(NULL);

    (void)log;

    if (dir == NULL || strlen(dir) >= sizeof(path) - 64) {
        return S3_ERROR;
    }

    /* the live count of the old state: the operator owes the
     * re-issuance of exactly this many certs */

    (void)snprintf(path, sizeof(path), "%s/index", dir);
    f = fopen(path, "r");

    if (f != NULL) {

        while (fgets(line, sizeof(line), f) != NULL) {

            size_t len = strlen(line);

            if (len >= 2 && line[len - 2] == 'V') {
                live++;
            }
        }

        (void)fclose(f);
    }

    (void)snprintf(backup, sizeof(backup), "%s.old.%ld", dir, epoch);

    if (rename(dir, backup) != 0) {
        return S3_ERROR;
    }

    if (s3_ssh3_ca_init(dir, log) != S3_OK) {

        /* the fresh init failed: the old state rides back */

        (void)rename(backup, dir);
        return S3_ERROR;
    }

    if (retired != NULL) {
        *retired = live;
    }

    return S3_OK;
}
