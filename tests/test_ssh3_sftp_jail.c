/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the sftp chroot jail helpers: the jail root resolution (the -H
 * override against the session home, the realpath canonicalization,
 * the daemon identity fallback), the sshd writability gate and the
 * non-root fail-closed guard; the enter() success path is a
 * process-wide chroot and rides the e2e stand instead
 */

/*
 * the resolution legs call realpath() directly: the declaration
 * hides behind __USE_MISC (the build pins _POSIX_C_SOURCE on the
 * command line, the optimized runs only see it through the fortify
 * wrapper), the definition lives in the file so only this TU pays
 * for the extra surface
 */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif

#include <s3_core.h>

#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <s3_ssh3_sftp_jail.h>

#include "s3_test.h"

/* the jail of mkdtemp is short, the composite paths keep the headroom */

#define S3_TEST_JAIL_CAP 1024

#define S3_TEST_NAME_CAP 128

static void
s3_test_rmtree(const char *dir)
{
    char cmd[S3_TEST_JAIL_CAP + 16];

    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);

    if (system(cmd) != 0) {
        /* the wipe rides the /tmp sweep, a failure stays silent */
    }
}

static int
s3_test_make_dir(char *dir)
{
    snprintf(dir, S3_TEST_JAIL_CAP, "/tmp/s3jail-XXXXXX");

    return mkdtemp(dir) == NULL ? -1 : 0;
}

static int
s3_test_chmod(const char *path, unsigned mode)
{
    return chmod(path, (mode_t)mode);
}

static int
s3_test_jail_is(const char *jail, const char *want)
{
    size_t n = strlen(want);

    return jail != NULL && strlen(jail) == n && s3_memcmp(jail, want, n) == 0;
}

static int
test_check(void)
{
    char  dir[S3_TEST_JAIL_CAP];
    char  file[S3_TEST_JAIL_CAP + 64];
    FILE *f;

    if (s3_test_make_dir(dir) != 0) {
        printf("FAIL %s:%d: mkdtemp\n", __FILE__, __LINE__);
        s3_test_failures++;

        return s3_test_failures;
    }

    snprintf(file, sizeof(file), "%s/f", dir);

    f = fopen(file, "w");

    if (f != NULL) {
        fclose(f);
    }

    /* a private directory is a lawful jail root */

    (void)s3_test_chmod(dir, 0755);
    S3_ASSERT(s3_ssh3_sftp_jail_check(dir) == S3_OK);

    /* the sshd rule: the group and the world must not write */

    (void)s3_test_chmod(dir, 0777);
    S3_ASSERT(s3_ssh3_sftp_jail_check(dir) == S3_DECLINED);

    (void)s3_test_chmod(dir, 0770);
    S3_ASSERT(s3_ssh3_sftp_jail_check(dir) == S3_DECLINED);

    (void)s3_test_chmod(dir, 0755);

    /* not a directory, missing paths and empty names are errors */

    S3_ASSERT(s3_ssh3_sftp_jail_check(file) == S3_ERROR);
    S3_ASSERT(s3_ssh3_sftp_jail_check("/tmp/s3jail-no-such-path") == S3_ERROR);
    S3_ASSERT(s3_ssh3_sftp_jail_check("") == S3_ERROR);
    S3_ASSERT(s3_ssh3_sftp_jail_check(NULL) == S3_ERROR);

    s3_test_rmtree(dir);

    return s3_test_failures;
}

static int
test_resolve_override(void)
{
    char     dir[S3_TEST_JAIL_CAP];
    char     link[S3_TEST_JAIL_CAP + 8];
    char     jail[S3_TEST_JAIL_CAP];
    char     name[S3_TEST_NAME_CAP];
    char     want[S3_TEST_JAIL_CAP];
    char    *real;
    uint32_t uid, gid;

    if (s3_test_make_dir(dir) != 0) {
        printf("FAIL %s:%d: mkdtemp\n", __FILE__, __LINE__);
        s3_test_failures++;

        return s3_test_failures;
    }

    /* the override serves verbatim (already canonical here), the
     * unresolvable session name falls back to the daemon identity */

    real = realpath(dir, NULL);
    S3_ASSERT(real != NULL);

    if (real == NULL) {
        printf("FAIL %s:%d: realpath\n", __FILE__, __LINE__);
        s3_test_failures++;
        s3_test_rmtree(dir);

        return s3_test_failures;
    }

    snprintf(want, sizeof(want), "%s", real);
    free(real);

    S3_ASSERT(s3_ssh3_sftp_jail_resolve(dir, "s3jail-nobody-xyz", jail, sizeof(jail), name,
                                        sizeof(name), &uid, &gid) == S3_OK);
    S3_ASSERT(s3_test_jail_is(jail, want));
    S3_ASSERT(name[0] == '\0');
    S3_ASSERT(uid == (uint32_t)getuid());
    S3_ASSERT(gid == (uint32_t)getgid());

    /* the symlinked override resolves to the canonical jail root */

    snprintf(link, sizeof(link), "%s.lnk", dir);

    S3_ASSERT(symlink(dir, link) == 0);

    memset(jail, 0, sizeof(jail));
    S3_ASSERT(s3_ssh3_sftp_jail_resolve(link, "s3jail-nobody-xyz", jail, sizeof(jail), name,
                                        sizeof(name), &uid, &gid) == S3_OK);
    S3_ASSERT(s3_test_jail_is(jail, want));

    unlink(link);
    s3_test_rmtree(dir);

    return s3_test_failures;
}

static int
test_resolve_home(void)
{
    char           jail[S3_TEST_JAIL_CAP];
    char           name[S3_TEST_NAME_CAP];
    char           want[S3_TEST_JAIL_CAP];
    char          *real;
    struct passwd *pw;
    uint32_t       uid, gid;

    pw = getpwuid(geteuid());

    if (pw == NULL || pw->pw_dir == NULL || *pw->pw_dir == '\0') {
        /* no passwd entry of the runner: the home leg cannot run */

        return s3_test_failures;
    }

    real = realpath(pw->pw_dir, NULL);

    if (real == NULL) {
        /* the home is gone (a deleted service user): nothing to pin */

        return s3_test_failures;
    }

    snprintf(want, sizeof(want), "%s", real);
    free(real);

    /* the session home serves the jail, the identity rides the entry */

    S3_ASSERT(s3_ssh3_sftp_jail_resolve(NULL, pw->pw_name, jail, sizeof(jail), name, sizeof(name),
                                        &uid, &gid) == S3_OK);
    S3_ASSERT(s3_test_jail_is(jail, want));
    S3_ASSERT(s3_test_jail_is(name, pw->pw_name));
    S3_ASSERT(uid == (uint32_t)pw->pw_uid);
    S3_ASSERT(gid == (uint32_t)pw->pw_gid);

    return s3_test_failures;
}

static int
test_resolve_refusals(void)
{
    char     jail[S3_TEST_JAIL_CAP];
    char     name[S3_TEST_NAME_CAP];
    uint32_t uid, gid;

    /* no override and an unknown user: the root daemon refuses */

    S3_ASSERT(s3_ssh3_sftp_jail_resolve(NULL, "s3jail-nobody-xyz", jail, sizeof(jail), name,
                                        sizeof(name), &uid, &gid) == S3_DECLINED);

    /* a missing override path is an error, not a refusal */

    S3_ASSERT(s3_ssh3_sftp_jail_resolve("/tmp/s3jail-no-such-path", "s3jail-nobody-xyz", jail,
                                        sizeof(jail), name, sizeof(name), &uid, &gid) == S3_ERROR);

    return s3_test_failures;
}

static int
test_enter_guard(void)
{
    char     dir[S3_TEST_JAIL_CAP];
    uint32_t uid, gid;

    if (geteuid() == 0) {
        /* the guard is unreachable under root: the e2e stand rides it */

        return s3_test_failures;
    }

    if (s3_test_make_dir(dir) != 0) {
        printf("FAIL %s:%d: mkdtemp\n", __FILE__, __LINE__);
        s3_test_failures++;

        return s3_test_failures;
    }

    uid = (uint32_t)getuid();
    gid = (uint32_t)getgid();

    /* a chroot request without the privilege fails closed */

    S3_ASSERT(s3_ssh3_sftp_jail_enter(dir, "", uid, gid) == S3_PERM);
    S3_ASSERT(s3_ssh3_sftp_jail_enter("/tmp/s3jail-no-such-path", "", uid, gid) == S3_PERM);

    s3_test_rmtree(dir);

    return s3_test_failures;
}

int
test_ssh3_sftp_jail(void)
{
    (void)test_check();
    (void)test_resolve_override();
    (void)test_resolve_home();
    (void)test_resolve_refusals();
    (void)test_enter_guard();

    return s3_test_failures;
}

S3_TEST_MAIN(test_ssh3_sftp_jail)
