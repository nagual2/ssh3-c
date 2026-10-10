/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_SSH3_SFTP_CLI_H_INCLUDED_
#define _S3_SSH3_SFTP_CLI_H_INCLUDED_

#include <s3_core.h>

#include <s3_ssh3_sftp.h>

/*
 * the client driver of the "sftp" channel, the port of the reference
 * cmd/sftp_client.go: the scp-style transfer engine speaking SFTP v3
 * over the caller's channel byte stream - the framing stays in the
 * channel layer, the module owns the state machine (the id-matched
 * request/reply pipeline) and the local filesystem side
 *
 * one operation runs at a time: put/get (a single file) or their -r
 * recursions (the reference uploadDir/downloadDir); the transfer
 * chunking follows the channel maxPacketSize, the resume (--continue)
 * continues from the size of the existing side and errors when that
 * side is the larger one, the equal sizes skip only when the mtimes
 * agree too - the source mtime rides the peer after every written
 * transfer (SETSTAT on the put, the local stamp on the get), so a
 * same-size rewrite can no longer hide behind its length (R7), the
 * checksum verification (the verify flag or the automatic threshold
 * above 32 MiB, the reference checksumAutoThreshold) re-reads both
 * sides through SHA-256
 */

#define S3_SSH3_SFTP_CLI_CHECKSUM_AUTO_THRESHOLD (32 * 1024 * 1024)

/* the transfer chunk, the reference copyWithOffset() buffer */

#define S3_SSH3_SFTP_CLI_CHUNK (32 * 1024)

/*
 * the reply bound reserve: a READ request never asks for more than
 * maxPacketSize - this, so the DATA reply (the 94 frame plus the
 * SFTP DATA header) stays under the channel maxPacketSize this side
 * announced and a dialect server never truncates the reply (the
 * harness readChunk() caps at the same maxPacketSize - 512)
 */

#define S3_SSH3_SFTP_CLI_PACKET_RESERVE 512

/*
 * the request window of the streaming phases: the WRITE and READ
 * trains keep up to this many requests in flight, the replies ride
 * the channel byte stream in request order (the SFTP server answers
 * sequentially), so the driver pins the oldest outstanding id
 */

#define S3_SSH3_SFTP_CLI_INFLIGHT 32

typedef enum {
    S3_SSH3_SFTP_CLI_IDLE = 0,
    S3_SSH3_SFTP_CLI_RUN,  /* an operation is in flight */
    S3_SSH3_SFTP_CLI_DONE, /* the operation finished, the verdict is status */
    S3_SSH3_SFTP_CLI_FAIL  /* the local (or protocol) failure, the verdict is status */
} s3_ssh3_sftp_cli_state_t;

typedef struct s3_ssh3_sftp_cli_s s3_ssh3_sftp_cli_t;

typedef void (*s3_ssh3_sftp_cli_progress_pt)(void *arg, uint64_t sent, uint64_t total);

struct s3_ssh3_sftp_cli_s {
    s3_pool_t *pool;

    s3_ssh3_sftp_cli_state_t state;
    uint32_t                 status; /* the last SSH_FX_* verdict, FX_OK on DONE */

    uint32_t next_id; /* the growing request id */

    /*
     * the READ request bound on the wire: S3_SSH3_SFTP_CLI_CHUNK
     * until the channel maxPacketSize of this side is announced (the
     * 91 confirmation carries it), then the bound that keeps every
     * DATA reply under that maxPacketSize
     */

    uint32_t read_bound;

    /* the receive tail: the bytes of an incomplete frame */

    u_char *pend;
    size_t  pend_len;
    size_t  pend_cap;

    /* the pending requests, drained by output() */

    u_char *out;
    size_t  out_len;
    size_t  out_cap;

    /* the opaque operation context, owned by s3_ssh3_sftp_cli.c */

    void *op;

    /* the INIT/VERSION exchange of the first operation */

    unsigned negotiated : 1;

    s3_ssh3_sftp_cli_progress_pt progress;
    void                        *progress_arg;
};

/*
 * prepares the driver; the progress callback (nullable) fires on the
 * payload milestones of the running operation
 */

s3_int_t s3_ssh3_sftp_cli_init(s3_ssh3_sftp_cli_t *t, s3_pool_t *pool,
                               s3_ssh3_sftp_cli_progress_pt progress, void *progress_arg);

/*
 * announces the channel maxPacketSize this side declared in the
 * channel open (the driver reads are bounded to keep the DATA
 * replies of the peer under it); a value at or under the reply
 * reserve keeps the default chunk
 */

void s3_ssh3_sftp_cli_channel_max_packet(s3_ssh3_sftp_cli_t *t, uint64_t max_packet);

/*
 * starts one upload (local file to remote path) or download; the -r
 * forms recurse over the local or the remote directory tree; the
 * driver must be IDLE or DONE (a finished op resets the state),
 * S3_BUSY otherwise; S3_ERROR on an immediate local failure (the
 * local file is missing, the local walk cannot start)
 */

s3_int_t s3_ssh3_sftp_cli_put(s3_ssh3_sftp_cli_t *t, const char *local_path,
                              const char *remote_path, unsigned resume, unsigned verify);

s3_int_t s3_ssh3_sftp_cli_get(s3_ssh3_sftp_cli_t *t, const char *remote_path,
                              const char *local_path, unsigned resume, unsigned verify);

s3_int_t s3_ssh3_sftp_cli_put_r(s3_ssh3_sftp_cli_t *t, const char *local_path,
                                const char *remote_path, unsigned resume, unsigned verify);

s3_int_t s3_ssh3_sftp_cli_get_r(s3_ssh3_sftp_cli_t *t, const char *remote_path,
                                const char *local_path, unsigned resume, unsigned verify);

/*
 * feeds one received channel chunk; S3_OK even on a partial frame,
 * S3_ERROR on a protocol violation (a reply id mismatch after the
 * retransmission-free pipeline, a hostile frame)
 */

s3_int_t s3_ssh3_sftp_cli_input(s3_ssh3_sftp_cli_t *t, const u_char *data, size_t len);

/* drains the pending requests: the byte count copied, 0 when none */

ssize_t s3_ssh3_sftp_cli_output(s3_ssh3_sftp_cli_t *t, u_char *buf, size_t size);

/* nonzero once the operation left the RUN state */

unsigned s3_ssh3_sftp_cli_finished(const s3_ssh3_sftp_cli_t *t);

/* the verdict of the finished operation: SSH_FX_OK or the status code */

uint32_t s3_ssh3_sftp_cli_status(const s3_ssh3_sftp_cli_t *t);

#endif /* _S3_SSH3_SFTP_CLI_H_INCLUDED_ */
