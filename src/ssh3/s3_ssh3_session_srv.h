/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_SSH3_SESSION_SRV_H_INCLUDED_
#define _S3_SSH3_SESSION_SRV_H_INCLUDED_

#include <s3_core.h>

/*
 * the server-side session of an ssh3 channel, the port of the
 * reference cmd/ssh3-server.go runningSession (docs/P4-WIRE.md 6):
 * the module owns the process and its terminals only - the channel
 * framing (94/95/98 on the wire) stays in the caller, the pumps move
 * bytes through the file descriptors exposed below
 *
 * the state machine: LARVAL until shell/exec spawns the process, then
 * OPEN; pty-req and window-change are legal in both states, data and
 * signal only in OPEN (the reference loop errors otherwise)
 */

#define S3_SSH3_SESSION_INVALID_FD -1

/* the envp frame cap of spawn: the inherited environment plus extras */

#define S3_SSH3_SESSION_ENVP_MAX 128

typedef struct s3_ssh3_session_srv_s s3_ssh3_session_srv_t;

struct s3_ssh3_session_srv_s {
    s3_pool_t *pool;

    int pid;        /* the child, 0 before spawn */
    int stdin_fd;   /* the write side the caller feeds */
    int stdout_fd;  /* the read side of the process output */
    int stderr_fd;  /* -1 when a pty (stderr merges into the pty) */
    int pty_master; /* the pty master, S3_SSH3_SESSION_INVALID_FD when pipes */

    /* the extra environment entries, "NAME=VALUE", the pool owns them */

    char **env;
    size_t env_len;
    size_t env_cap;

    unsigned pty : 1;
    unsigned open : 1; /* LARVAL : OPEN */
    unsigned exited : 1;
};

/*
 * prepares an empty LARVAL session; fds start at
 * S3_SSH3_SESSION_INVALID_FD
 */

s3_int_t s3_ssh3_session_srv_init(s3_ssh3_session_srv_t *s, s3_pool_t *pool);

/*
 * quotes one extra environment entry to the child (the reference
 * setupEnv: the agent forwarding path adds SSH_AUTH_SOCK, the
 * session harness adds HOME/SHELL); the entries ride on top of the
 * inherited environment, a repeated name keeps the last one;
 * S3_DECLINED once the process spawned, S3_ERROR when the pool is
 * exhausted
 */

s3_int_t s3_ssh3_session_srv_env(s3_ssh3_session_srv_t *s, const char *name, const char *value);

/*
 * the channel requests (the 98 bodies, s3_ssh3_request_t); shell and
 * exec spawn the process through shell_path - the reference always
 * runs $SHELL, exec appends "-c command"; pty-req allocates the pty
 * and applies the size; window-change re-applies it (pty only);
 * signal delivers SIG<name> to the process (OPEN only)
 *
 * S3_OK, S3_DECLINED when the request is illegal in the current
 * state (data-like), S3_ERROR on the syscall failures
 */

s3_int_t s3_ssh3_session_srv_pty_req(s3_ssh3_session_srv_t *s, const s3_str_t *term, uint64_t width,
                                     uint64_t height, uint64_t pixel_width, uint64_t pixel_height,
                                     const s3_str_t *modes);

s3_int_t s3_ssh3_session_srv_shell(s3_ssh3_session_srv_t *s, const char *shell_path);

s3_int_t s3_ssh3_session_srv_exec(s3_ssh3_session_srv_t *s, const char *shell_path,
                                  const s3_str_t *command);

s3_int_t s3_ssh3_session_srv_window_change(s3_ssh3_session_srv_t *s, uint64_t width,
                                           uint64_t height, uint64_t pixel_width,
                                           uint64_t pixel_height);

s3_int_t s3_ssh3_session_srv_signal(s3_ssh3_session_srv_t *s, const s3_str_t *name);

/*
 * the data path: input goes to the process stdin (OPEN only, the pty
 * master when a pty is set), close_input closes it (the FIN of the
 * peer); output reads one chunk from the pty master, stdout or
 * stderr; S3_AGAIN must be treated as EAGAIN semantics by the caller
 */

s3_int_t s3_ssh3_session_srv_input(s3_ssh3_session_srv_t *s, const u_char *data, size_t len);

s3_int_t s3_ssh3_session_srv_close_input(s3_ssh3_session_srv_t *s);

ssize_t s3_ssh3_session_srv_read_output(s3_ssh3_session_srv_t *s, u_char *buf, size_t size);

ssize_t s3_ssh3_session_srv_read_stderr(s3_ssh3_session_srv_t *s, u_char *buf, size_t size);

/*
 * non-blocking reap: S3_OK with the verdict once the child exited
 * (exit_status is the code or 0, signal_name is "TERM"-style without
 * the SIG prefix or empty), S3_AGAIN while it still runs
 */

s3_int_t s3_ssh3_session_srv_reap(s3_ssh3_session_srv_t *s, uint64_t *exit_status,
                                  s3_str_t *signal_name, unsigned *core_dumped);

#endif /* _S3_SSH3_SESSION_SRV_H_INCLUDED_ */
