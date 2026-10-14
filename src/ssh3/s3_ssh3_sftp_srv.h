/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_SSH3_SFTP_SRV_H_INCLUDED_
#define _S3_SSH3_SFTP_SRV_H_INCLUDED_

#include <s3_core.h>

#include <s3_ssh3_sftp.h>

/*
 * the server side of the "sftp" channel, the port of the reference
 * cmd/sftp_subsystem.go over pkg/sftp: one per channel, the SFTP v3
 * request loop jailed to the session user's home directory; the
 * module owns the filesystem side only - the channel framing stays
 * in the caller (the same split as s3_ssh3_session_srv)
 *
 * the jail (the reference resolveJailed): jail-relative paths
 * ("docs/f", "/docs/f") resolve under home; server-absolute paths
 * already living inside home are honored verbatim; absolute paths
 * outside the jail are SSH_FX_PERMISSION_DENIED
 *
 * every created inode is chowned back to (uid, gid): the server may
 * run as root while the files belong to the user (the reference
 * chownToUser)
 *
 * the replies are built synchronously inside input() into the
 * output buffer (the OpenSSH sftp-server shape); the file syscalls
 * block, the harness accepts it for one channel
 */

#define S3_SSH3_SFTP_SRV_HANDLES 64 /* the open files and dirs, hard cap */

typedef struct {
    int    fd;    /* the open file, -1 when the slot is free */
    void  *dir;   /* the DIR * of an open directory */
    u_char id[8]; /* the handle bytes on the wire */
} s3_ssh3_sftp_srv_handle_t;

typedef struct s3_ssh3_sftp_srv_s s3_ssh3_sftp_srv_t;

struct s3_ssh3_sftp_srv_s {
    s3_pool_t *pool;

    s3_str_t home; /* the jail root, absolute */
    uint32_t uid;
    uint32_t gid;

    uint64_t next_handle; /* the monotonically growing handle value */

    s3_ssh3_sftp_srv_handle_t handles[S3_SSH3_SFTP_SRV_HANDLES];

    /* the receive tail: the bytes of an incomplete frame */

    u_char *pend;
    size_t  pend_len;
    size_t  pend_cap;

    /* the pending replies, drained by output() */

    u_char *out;
    size_t  out_len;
    size_t  out_cap;

    /* the scratch READ buffer: the requests ride one at a time, the
       single reuse keeps the pool flat (a per-READ block piles up to
       the payload size over one transfer) */

    u_char *read_buf;
    size_t  read_cap;

    unsigned negotiated : 1;     /* the INIT exchange done */
    unsigned protocol_error : 1; /* a hostile frame killed the loop */
};

/*
 * prepares the server for one channel; home must be absolute (the
 * caller resolves it from getpwnam); S3_OK, S3_ERROR when home is
 * not absolute or the pool is exhausted
 */

s3_int_t s3_ssh3_sftp_srv_init(s3_ssh3_sftp_srv_t *t, s3_pool_t *pool, const s3_str_t *home,
                               uint32_t uid, uint32_t gid);

/*
 * feeds one received channel chunk; the frames are dispatched and
 * the replies appended to the output buffer; S3_OK including a
 * partial frame tail, S3_ERROR on an internal failure (the pool);
 * a hostile frame (length above the cap) sets protocol_error and
 * the caller tears the channel down
 */

s3_int_t s3_ssh3_sftp_srv_input(s3_ssh3_sftp_srv_t *t, const u_char *data, size_t len);

/*
 * drains the pending replies: the byte count copied, 0 when nothing
 * is pending
 */

ssize_t s3_ssh3_sftp_srv_output(s3_ssh3_sftp_srv_t *t, u_char *buf, size_t size);

/* the protocol_error verdict: the caller closes the channel */

unsigned s3_ssh3_sftp_srv_protocol_error(const s3_ssh3_sftp_srv_t *t);

#endif /* _S3_SSH3_SFTP_SRV_H_INCLUDED_ */
