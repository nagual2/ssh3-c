/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the kernel-enforced sftp jail, the sshd model (the reference
 * cmd/internal_sftp.go of the F-04 fix): the lexical prefix jail of
 * the engine follows symlinks, so a privileged server hands root
 * files out of the home through one; this module carries the jail
 * resolution, the writability gate and the enter sequence, the
 * caller forks a child that enters and drops before any user path
 * opens - after the chroot the path confinement is the kernel's
 *
 * the parents never touch anything inside the jail: only the jail
 * root itself is resolved (realpath) and inspected (stat)
 */

/*
 * the kernel gate of this module needs the BSD surface: initgroups()
 * hides behind __USE_MISC and chroot() behind _DEFAULT_SOURCE, the
 * build pins _POSIX_C_SOURCE on the command line; the definition
 * lives in the file so only the jail TU pays for the extra surface
 */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif

#include <s3_core.h>

#include <s3_ssh3_sftp_jail.h>

#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* the sshd writability mask: the group and the other write bits */

#define S3_SSH3_SFTP_JAIL_WR_BITS 022

static s3_int_t s3_ssh3_sftp_jail_copy(char *dst, size_t cap, const char *src);

/*
 * the bounded copy of the lookup results: a truncated jail or name
 * is an error, never a silent cut (the truncated path would jail
 * somewhere else)
 */

static s3_int_t
s3_ssh3_sftp_jail_copy(char *dst, size_t cap, const char *src)
{
    int n;

    if (dst == NULL || cap == 0 || src == NULL) {
        return S3_ERROR;
    }

    n = snprintf(dst, cap, "%s", src);

    if (n < 0 || (size_t)n >= cap) {
        return S3_ERROR;
    }

    return S3_OK;
}

s3_int_t
s3_ssh3_sftp_jail_resolve(const char *override, const char *username, char *jail, size_t jail_cap,
                          char *name, size_t name_cap, uint32_t *uid, uint32_t *gid)
{
    struct passwd *pw;
    char          *real;
    s3_int_t       rc;

    if (jail == NULL || jail_cap == 0 || name == NULL || name_cap == 0 || uid == NULL ||
        gid == NULL) {
        return S3_ERROR;
    }

    name[0] = '\0';

    /* the daemon identity is the fallback drop (nothing escalates,
     * the run-as parity of the session spawn) */

    *uid = (uint32_t)getuid();
    *gid = (uint32_t)getgid();

    /* the session identity: the entry is a static buffer, the fields
     * that outlive the next lookup copy out at once */

    pw = (username != NULL && *username != '\0') ? getpwnam(username) : NULL;

    if (pw != NULL && (pw->pw_dir == NULL || *pw->pw_dir == '\0')) {

        /* a user without a home cannot seed the jail: the same
         * no-jail rule the refusal below carries */

        pw = NULL;
    }

    if (override != NULL && *override != '\0') {

        /* the -H override wins over the session home */

        rc = s3_ssh3_sftp_jail_copy(jail, jail_cap, override);

    } else if (pw != NULL) {

        rc = s3_ssh3_sftp_jail_copy(jail, jail_cap, pw->pw_dir);

    } else {

        /* a root daemon without an override and a resolvable user is
         * refused (fail closed, never the daemon home as the jail) */

        return S3_DECLINED;
    }

    if (rc != S3_OK) {
        return rc;
    }

    if (pw != NULL) {

        if (pw->pw_name != NULL && s3_ssh3_sftp_jail_copy(name, name_cap, pw->pw_name) != S3_OK) {
            return S3_ERROR;
        }

        *uid = (uint32_t)pw->pw_uid;
        *gid = (uint32_t)pw->pw_gid;
    }

    /* the canonical jail root: the symlinked home spelling dies here,
     * the enter() and the writability gate see one path */

    real = realpath(jail, NULL);

    if (real == NULL) {
        return S3_ERROR;
    }

    rc = s3_ssh3_sftp_jail_copy(jail, jail_cap, real);

    free(real);

    return rc;
}

s3_int_t
s3_ssh3_sftp_jail_check(const char *jail)
{
    struct stat st;

    if (jail == NULL || *jail == '\0') {
        return S3_ERROR;
    }

    if (stat(jail, &st) != 0) {
        return S3_ERROR;
    }

    if (!S_ISDIR(st.st_mode)) {
        return S3_ERROR;
    }

    /* the sshd rule, adapted (the Go F-04): a group/world-writable
     * jail root lets another identity plant content at the served
     * root, the owner bit stays lawful - after the drop nothing
     * privileged remains inside */

    if (st.st_mode & S3_SSH3_SFTP_JAIL_WR_BITS) {
        return S3_DECLINED;
    }

    return S3_OK;
}

s3_int_t
s3_ssh3_sftp_jail_enter(const char *jail, const char *name, uint32_t uid, uint32_t gid)
{
    if (jail == NULL || *jail != '/') {
        return S3_ERROR;
    }

    /* the chroot is the root-only call: a child without the
     * privilege refuses rather than serving unjailed (fail closed) */

    if (geteuid() != 0) {
        return S3_PERM;
    }

    /* the supplementary groups ride before the chroot: initgroups
     * reads /etc/group and the jail carries no /etc inside (the
     * OpenSSH in_chroot order); the kernel confinement is unaffected
     * - the chroot below still runs with the full privilege */

    if (name != NULL && *name != '\0' && initgroups(name, (gid_t)gid) != 0) {
        return S3_ERROR;
    }

    if (chdir(jail) != 0 || chroot(jail) != 0 || chdir("/") != 0) {
        return S3_ERROR;
    }

    /* the drop removes every privilege before the first path opens */

    if (setgid((gid_t)gid) != 0 || setuid((uid_t)uid) != 0) {
        return S3_ERROR;
    }

    return S3_OK;
}
