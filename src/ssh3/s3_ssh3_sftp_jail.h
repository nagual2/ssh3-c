/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_SSH3_SFTP_JAIL_H_INCLUDED_
#define _S3_SSH3_SFTP_JAIL_H_INCLUDED_

#include <s3_core.h>

#include <stddef.h>
#include <stdint.h>

/*
 * the kernel-enforced sftp jail, the sshd model (the reference
 * cmd/internal_sftp.go of the F-04 fix): the lexical prefix jail of
 * the engine follows symlinks, so a privileged server hands root
 * files out of the home through one; these helpers carry the jail
 * resolution and the kernel gate instead, the caller forks a child
 * that enters the jail and drops before any user path opens
 *
 * the parents never touch anything inside the jail: only the jail
 * root itself is resolved and inspected
 */

/*
 * resolves the jail root and the drop identity; override (-H) wins
 * over the session home, the home of username (getpwnam) seeds the
 * jail otherwise; a user that does not resolve falls back to the
 * daemon identity (nothing escalates, the run-as parity) and without
 * an override answers S3_DECLINED - the caller refuses; the jail
 * string leaves canonicalized (realpath), the buffers are the
 * caller's; S3_OK, S3_DECLINED (no jail source), S3_ERROR (a
 * truncated copy or a dead path)
 */

s3_int_t s3_ssh3_sftp_jail_resolve(const char *override, const char *username, char *jail,
                                   size_t jail_cap, char *name, size_t name_cap, uint32_t *uid,
                                   uint32_t *gid);

/*
 * the sshd writability gate, adapted (the Go F-04): the jail root
 * must be an existing directory and must not be group/world-writable
 * (another identity must not plant content at the served root); the
 * owner-writable bit stays lawful - after the drop nothing privileged
 * remains inside; S3_OK, S3_DECLINED (writable), S3_ERROR (not a
 * directory or stat failed)
 */

s3_int_t s3_ssh3_sftp_jail_check(const char *jail);

/*
 * enters the jail, the child side only: the supplementary groups
 * first (initgroups reads /etc/group, the jail carries no /etc
 * inside - the OpenSSH in_chroot order), then chdir/chroot/chdir("/"),
 * then the setgid/setuid drop; a request without the root privilege
 * answers S3_PERM - the caller fails closed (_exit) instead of
 * serving unjailed; S3_OK or the error codes above
 */

s3_int_t s3_ssh3_sftp_jail_enter(const char *jail, const char *name, uint32_t uid, uint32_t gid);

#endif /* _S3_SSH3_SFTP_JAIL_H_INCLUDED_ */
