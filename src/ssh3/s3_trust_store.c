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
#include <openssl/evp.h>

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#if (S3_WIN32)
#include <direct.h>
#define S3_TRUST_OPEN_BINARY O_BINARY
#else
#define S3_TRUST_OPEN_BINARY 0
#endif

#include <s3_https_fetch.h>
#include <s3_ssh3_aia.h>
#include <s3_trust_store.h>

/* the update caps of the canon (the phase 1c): the fetch timeout
 * of the bundle (the ~200 KiB body over a slow link), the body
 * cap, the certificate count floor (the Mozilla set carries ~110) */

#define S3_TRUST_UPDATE_TIMEOUT_SEC 30
#define S3_TRUST_UPDATE_BODY_MAX    (4 * 1024 * 1024)
#define S3_TRUST_UPDATE_FLOOR       30

static const char *s3_trust_bundle_override;

int
s3_trust_policy_parse(const char *text, s3_trust_policy_t *policy)
{
    if (text == NULL || policy == NULL) {
        return -1;
    }

    if (strcmp(text, "own") == 0 || strcmp(text, "OWN") == 0 || strcmp(text, "Own") == 0) {
        *policy = S3_TRUST_POLICY_OWN;
        return 0;
    }

    if (strcmp(text, "system") == 0 || strcmp(text, "SYSTEM") == 0 || strcmp(text, "System") == 0) {
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

/*
 * the trust update (the phase 1c): the scheduler surface.  The
 * validation walk rides PEM_read_bio_X509 to the end of the body -
 * every block must parse, the floor counts (the product floor 30,
 * the Mozilla set carries ~110); the landing is the tmp+rename
 * swap the ticket cache uses, the manifest names the source and
 * the sha256.  Any failure keeps the previous copy - the offline
 * scheduler run is the plain shape
 */

static s3_trust_fetch_pt s3_update_fetch_hook;
static char              s3_update_dir_override[1024];
static unsigned          s3_update_min_certs;
static char              s3_bundle_last[1024];

void
s3_trust_update_set_fetch(s3_trust_fetch_pt fn)
{
    s3_update_fetch_hook = fn;
}

void
s3_trust_update_set_dir(const char *dir)
{
    if (dir != NULL && strlen(dir) < sizeof(s3_update_dir_override)) {
        memcpy(s3_update_dir_override, dir, strlen(dir) + 1);
    } else {
        s3_update_dir_override[0] = '\0';
    }
}

void
s3_trust_update_set_min_certs(unsigned n)
{
    s3_update_min_certs = n;
}

const char *
s3_trust_bundle_path_get(void)
{
    return s3_bundle_last[0] != '\0' ? s3_bundle_last : NULL;
}

/* the landing file of the bundle: the dir override of the tests or
 * the state dir of the product + the fixed name */

static s3_int_t
s3_trust_bundle_file(char *buf, size_t cap)
{
    size_t len;

    if (s3_update_dir_override[0] != '\0') {
        len = strlen(s3_update_dir_override);

        if (len + 2 + sizeof("trust-bundle.pem") > cap) {
            return S3_ERROR;
        }

        memcpy(buf, s3_update_dir_override, len);
        buf[len] = '/';
        memcpy(buf + len + 1, "trust-bundle.pem", sizeof("trust-bundle.pem"));

        return S3_OK;
    }

    if (s3_ssh3_aia_state_dir(buf, cap) != S3_OK) {
        return S3_ERROR;
    }

    len = strlen(buf);

    if (len + 2 + sizeof("trust-bundle.pem") > cap) {
        return S3_ERROR;
    }

    buf[len] = '/';
    memcpy(buf + len + 1, "trust-bundle.pem", sizeof("trust-bundle.pem"));

    return S3_OK;
}

static s3_int_t
s3_trust_update_default_fetch(const char *url, s3_str_t *out)
{
    unsigned status = 0;
    s3_str_t body;

    s3_str_null(&body);

    if (s3_https_fetch_to(url, "GET", NULL, NULL, NULL, S3_TRUST_UPDATE_TIMEOUT_SEC, &status,
                          &body) != S3_OK) {
        return S3_ERROR;
    }

    if (status != 200) {
        s3_free(body.data);
        return S3_ERROR;
    }

    if (body.len == 0 || body.len > S3_TRUST_UPDATE_BODY_MAX) {
        s3_free(body.data);
        return S3_ERROR;
    }

    *out = body;

    return S3_OK;
}

s3_int_t
s3_trust_update_run(const char *url, s3_log_t *log)
{
    char     path[1200], tmp[1300], man[1300], line[128];
    u_char   md[EVP_MAX_MD_SIZE];
    unsigned md_len;
    s3_str_t body;
    X509    *x509;
    BIO     *bio;
    unsigned count = 0, floor;
    s3_int_t fd, ok;
    int      n, i;
    ssize_t  w;

    if (url == NULL || url[0] == '\0') {
        return S3_ERROR;
    }

    if (s3_trust_bundle_file(path, sizeof(path)) != S3_OK) {
        return S3_ERROR;
    }

    /* the state dir may not exist yet (the fresh home rides the
     * scheduler before any pin write): the two levels go one by
     * one - the same shape the aia cache takes */

    {
        char dir[1024];

        if (s3_ssh3_aia_state_dir(dir, sizeof(dir)) == S3_OK) {

            if (s3_ssh3_aia_mkdir(dir) != 0 && errno == ENOENT) {

                char parent[1024];
                int  i;

                for (i = (int)strlen(dir) - 1; i >= 0; i--) {
                    if (dir[i] == '/' || dir[i] == '\\') {
                        break;
                    }
                }

                if (i > 0 && i < (int)sizeof(parent)) {

                    memcpy(parent, dir, (size_t)i);
                    parent[i] = '\0';

                    (void)s3_ssh3_aia_mkdir(parent);
                    (void)s3_ssh3_aia_mkdir(dir);
                }
            }
        }
    }

    /* the fetch: the test hook or the https transport */

    s3_str_null(&body);

    if (s3_update_fetch_hook != NULL) {

        if (s3_update_fetch_hook(url, &body) != S3_OK) {
            return S3_ERROR;
        }

    } else {

        if (s3_trust_update_default_fetch(url, &body) != S3_OK) {
            s3_log_error(S3_LOG_WARN, log, 0, "the trust bundle fetch of %s failed", url);
            return S3_ERROR;
        }
    }

    /* the validation walk: every PEM block parses, the floor
     * counts (the truncated tail stops the walk short of the
     * floor - the store copy stays) */

    floor = s3_update_min_certs != 0 ? s3_update_min_certs : S3_TRUST_UPDATE_FLOOR;

    bio = BIO_new_mem_buf(body.data, (int)body.len);

    if (bio == NULL) {
        s3_free(body.data);
        return S3_ERROR;
    }

    for (;;) {

        x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);

        if (x509 == NULL) {
            break;
        }

        count++;
        X509_free(x509);
    }

    BIO_free(bio);
    ERR_clear_error();

    if (count < floor) {
        s3_log_error(S3_LOG_WARN, log, 0,
                     "the trust bundle of %s carries %ui certificates, the floor is %ui - riding "
                     "without the update",
                     url, (s3_uint_t)count, (s3_uint_t)floor);
        s3_free(body.data);
        return S3_ERROR;
    }

    /* the atomic landing: the tmp swap of the ticket cache shape,
     * the manifest names the source and the sha256 */

    n = snprintf(tmp, sizeof(tmp), "%s.tmp", path);

    if (n <= 0 || (size_t)n >= sizeof(tmp)) {
        s3_free(body.data);
        return S3_ERROR;
    }

    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | S3_TRUST_OPEN_BINARY, 0600);

    if (fd == -1) {
        s3_free(body.data);
        return S3_ERROR;
    }

    w = write(fd, body.data, body.len);
    ok = (w == (ssize_t)body.len);
    (void)close(fd);

    if (!ok) {
        (void)unlink(tmp);
        s3_free(body.data);
        return S3_ERROR;
    }

    if (rename(tmp, path) != 0) {
        (void)unlink(tmp);
        s3_free(body.data);
        return S3_ERROR;
    }

    {
        size_t plen = strlen(path);

        if (plen < sizeof(s3_bundle_last)) {
            memcpy(s3_bundle_last, path, plen + 1);
        }
    }

    /* the manifest: the source url line, the sha256 of the body */

    if (!EVP_Digest(body.data, body.len, md, &md_len, EVP_sha256(), NULL)) {
        ERR_clear_error();
        s3_free(body.data);
        return S3_ERROR;
    }

    for (i = 0; (unsigned)i < md_len; i++) {
        sprintf(line + i * 2, "%02x", md[i]);
    }
    line[md_len * 2] = '\0';

    n = snprintf(man, sizeof(man), "%s.man", path);

    if (n > 0 && (size_t)n < sizeof(man)) {

        fd = open(man, O_WRONLY | O_CREAT | O_TRUNC | S3_TRUST_OPEN_BINARY, 0600);

        if (fd != -1) {
            ssize_t mw = 0;
            int     mok = 1;

            mw = write(fd, url, strlen(url));
            mok = mok && mw >= 0;
            mw = write(fd, "\n", 1);
            mok = mok && mw >= 0;
            mw = write(fd, line, strlen(line));
            mok = mok && mw >= 0;
            mw = write(fd, "\n", 1);
            mok = mok && mw >= 0;
            (void)close(fd);

            if (!mok) {
                (void)unlink(man); /* the broken manifest dies */
            }
        }
    }

    s3_log_error(S3_LOG_INFO, log, 0, "the trust bundle of %s landed (%ui certificates, sha256 %s)",
                 url, (s3_uint_t)count, line);

    s3_free(body.data);

    return S3_OK;
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
    char     path[1024];
    s3_int_t system_paths;

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

    /* the platform paths of the system policy: the os-layer bridge
     * (the unix leg rides the default cert dir/file of the OpenSSL
     * build, the win leg rides the Crypt32 ROOT/CA enumeration with
     * the Disallowed deny filter - the SChannel auto-update keeps
     * the stores fresh); the empty result is the warning, the own
     * set already rides (the union never refuses the dial) */

    system_paths = s3_trust_system_paths_apply(ctx, log);

    if (system_paths == S3_OK) {
        s3_log_error(S3_LOG_INFO, log, 0, "the system certificate store rides the anchors");

    } else {
        s3_log_error(S3_LOG_WARN, log, 0,
                     "the system certificate store is not available, riding the own set");
    }

    return S3_OK;
}
