/*
 * Copyright (C) 2026 the ssh3-c authors
 */

/*
 * the win leg of the system store bridge (s3_trust_store.h): the
 * Crypt32 enumeration of the machine/user certificate stores -
 *
 *   ROOT       the trusted roots: the anchors of the store
 *   CA         the intermediates: the anchors too (the OpenSSL
 *              store is flat, the anchor-of-a-chain shape)
 *   Disallowed the deny list: the roots the system distrusted
 *              (the auto-update moved them out) never enter the
 *              store - the exact DER compare rides the filter
 *
 * The certificates the SChannel auto-update keeps fresh (the
 * system-wide root program): the bridge reads the result of that
 * update - no fetch rides here.
 */

#include <openssl/err.h>
#include <openssl/x509.h>

#include <s3_core.h>

#include <wincrypt.h>

#include <s3_trust_store.h>

/* the disallowed DER list of the deny filter: the exact byte
 * compare of the certificate encodings */

typedef struct {
    u_char *der;
    size_t  len;
} s3_trust_disallow_t;

typedef struct {
    s3_trust_disallow_t *items;
    unsigned             n;
    unsigned             cap;
} s3_trust_disallows_t;

static int
s3_trust_disallows_hit(const s3_trust_disallows_t *dis, const u_char *der, size_t len)
{
    unsigned i;

    for (i = 0; i < dis->n; i++) {

        if (dis->items[i].len == len && memcmp(dis->items[i].der, der, len) == 0) {
            return 1;
        }
    }

    return 0;
}

static void
s3_trust_disallows_free(s3_trust_disallows_t *dis)
{
    unsigned i;

    for (i = 0; i < dis->n; i++) {
        s3_free(dis->items[i].der);
    }

    s3_free(dis->items);

    dis->items = NULL;
    dis->n = 0;
    dis->cap = 0;
}

static int
s3_trust_disallows_push(s3_trust_disallows_t *dis, PCCERT_CONTEXT ctx)
{
    s3_trust_disallow_t *grown;
    u_char              *der;

    if (dis->n == dis->cap) {

        dis->cap = dis->cap != 0 ? dis->cap * 2 : 32;

        grown = realloc(dis->items, dis->cap * sizeof(s3_trust_disallow_t));

        if (grown == NULL) {
            return -1;
        }

        dis->items = grown;
    }

    der = s3_alloc(ctx->cbCertEncoded, NULL);

    if (der == NULL) {
        return -1;
    }

    memcpy(der, ctx->pbCertEncoded, ctx->cbCertEncoded);

    dis->items[dis->n].der = der;
    dis->items[dis->n].len = ctx->cbCertEncoded;
    dis->n++;

    return 0;
}

/* one Crypt32 store into the OpenSSL store: the exact-DER deny
 * filter rides first, the d2i view carries the certificate */

static unsigned
s3_trust_store_walk(HCERTSTORE wstore, X509_STORE *store, const s3_trust_disallows_t *dis,
                    unsigned *skipped)
{
    PCCERT_CONTEXT ctx = NULL;
    unsigned       added = 0;

    while ((ctx = CertEnumCertificatesInStore(wstore, ctx)) != NULL) {

        const u_char *der;
        X509         *x509;

        if (dis->n != 0 && s3_trust_disallows_hit(dis, ctx->pbCertEncoded,
                                                  (size_t)ctx->cbCertEncoded)) {
            (*skipped)++;
            continue;
        }

        der = ctx->pbCertEncoded;

        x509 = d2i_X509(NULL, &der, (long)ctx->cbCertEncoded);

        if (x509 == NULL) {
            ERR_clear_error();
            (*skipped)++;
            continue;
        }

        /* the duplicate of a previous walk is a no-op success */

        if (X509_STORE_add_cert(store, x509) != 1) {

            if (ERR_GET_REASON(ERR_peek_error()) != X509_R_CERT_ALREADY_IN_HASH_TABLE) {
                X509_free(x509);
                ERR_clear_error();
                (*skipped)++;
                continue;
            }

            ERR_clear_error();
        }

        X509_free(x509);
        added++;
    }

    return added;
}

static void
s3_trust_store_disallowed_walk(HCERTSTORE wstore, s3_trust_disallows_t *dis)
{
    PCCERT_CONTEXT ctx = NULL;

    while ((ctx = CertEnumCertificatesInStore(wstore, ctx)) != NULL) {
        (void)s3_trust_disallows_push(dis, ctx);
    }
}

s3_int_t
s3_trust_system_paths_apply(SSL_CTX *ctx, s3_log_t *log)
{
    HCERTSTORE            wstore;
    s3_trust_disallows_t  dis;
    X509_STORE           *store;
    unsigned              added = 0, skipped = 0;
    static const wchar_t *names[] = { L"ROOT", L"CA" };
    unsigned              i;

    if (ctx == NULL) {
        return S3_ERROR;
    }

    memset(&dis, 0, sizeof(dis));

    /* the deny list first: the exact-DER set the filter rides */

    wstore = CertOpenSystemStoreW(0, L"Disallowed");

    if (wstore != NULL) {
        s3_trust_store_disallowed_walk(wstore, &dis);
        CertCloseStore(wstore, 0);

        if (dis.n != 0) {
            s3_log_error(S3_LOG_INFO, log, 0, "the system deny list carries %ui entries",
                         (s3_uint_t)dis.n);
        }
    }

    store = SSL_CTX_get_cert_store(ctx);

    if (store == NULL) {
        s3_trust_disallows_free(&dis);
        return S3_ERROR;
    }

    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {

        wstore = CertOpenSystemStoreW(0, names[i]);

        if (wstore == NULL) {
            s3_log_error(S3_LOG_WARN, log, (s3_err_t)GetLastError(),
                         "CertOpenSystemStoreW(\"%ls\") failed", names[i]);
            continue;
        }

        added += s3_trust_store_walk(wstore, store, &dis, &skipped);

        CertCloseStore(wstore, 0);
    }

    s3_trust_disallows_free(&dis);

    if (added != 0) {

        s3_log_error(S3_LOG_INFO, log, 0,
                     "the system certificate stores ride the anchors (%ui added, %ui skipped)",
                     (s3_uint_t)added, (s3_uint_t)skipped);

        return S3_OK;
    }

    /* the empty machine (the stripped SKU, the no-store build): the
     * caller warns and the own set carries the anchors */

    s3_log_error(S3_LOG_WARN, log, 0, "the system certificate stores carry no certificates");

    return S3_DECLINED;
}
