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

/*
 * the env allow-list gate of the session children (I-2): the only
 * names the server quotes into a child environment are the fixed ones
 * of the list below - the peer never names an entry (no env request
 * exists on the wire), the gate keeps that property explicit so a
 * second consumer of the quoting path cannot bypass it; the TERM of
 * the pty-req, the identity fields of the run-as transition (USER,
 * LOGNAME, HOME, SHELL), the SSH_AUTH_SOCK of the agent forwarding
 * and the LANG of the envp locale fallback; LC_* and the rest of the
 * daemon locale never ride the quoting path, they reach the child
 * through the wholesale inherited environ only
 *
 * S3_OK when the pair may be quoted; S3_DECLINED for a name outside
 * the list, a broken argument and a TERM value outside the 1..64
 * pty-req bound
 */

s3_int_t s3_ssh3_env_admit(const char *name, const char *value);

/* the pump entry of the caller, the watch handler runs it on any readiness */

typedef void (*s3_ssh3_session_pump_pt)(void *ctx);

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

    /*
     * the per-session identity transition (P7.3): the privileged
     * server resolves the authenticated name before the spawn, the
     * child drops onto it right before the exec (initgroups, setgid,
     * setuid, chdir to the home); a NULL name keeps the daemon
     * identity - the unprivileged run and the CONNECTs without a
     * session username ride it
     */
    char *run_as_name;  /* the authenticated name, the pool owns it */
    char *run_as_home;  /* pw_dir of the resolved user, NULL when empty */
    char *run_as_shell; /* pw_shell of the resolved user, NULL when empty */
    uid_t run_as_uid;
    gid_t run_as_gid;

    unsigned pty : 1;
    unsigned open : 1; /* LARVAL : OPEN */
    unsigned exited : 1;

    /*
     * the event-driven pump state (P7.2): the watch connections ride
     * a process-wide free list, the drain buffer is a pool-owned read
     * window reused across the reads (no per-message allocation), the
     * verdict is cached for the retry of a failed exit sink
     */
    s3_connection_t        *out_watch; /* the stdout/pty master watch */
    s3_connection_t        *err_watch; /* the stderr watch, NULL on a pty */
    s3_log_t               *watch_log;
    s3_ssh3_session_pump_pt pump_cb;
    void                   *pump_ctx;
    s3_event_t              reap_timer; /* the verdict watchdog, never a transport tick */
    uint64_t                exit_code;
    u_char                 *drain;
    unsigned                verdict_sent : 1;
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
 * the identity transition of the session (P7.3): resolves the
 * authenticated name through the passwd database and quotes the
 * reference env block on top of the inherited environment (HOME,
 * SHELL, USER, LOGNAME of the resolved user, the setupEnv shape);
 * the spawn drops the child onto the identity before the exec
 *
 * S3_OK once resolved; S3_DECLINED for the NULL or the empty name,
 * a name outside the plain guard (the alphanumerics, ".", "_", "-",
 * no leading dot - the session name of the reference), an unknown
 * user and a live session (the spawn already happened); S3_PERM
 * without the privilege to drop (the daemon euid is not 0) - the
 * lookup runs first, so the unprivileged caller still sees the
 * unknown-user refusal of the same rule; S3_ERROR when the pool is
 * exhausted
 */

s3_int_t s3_ssh3_session_srv_run_as(s3_ssh3_session_srv_t *s, const char *username);

/*
 * the login shell of the resolved user (pw_shell), the spawn program
 * of the shell/exec requests when the transition is set; NULL keeps
 * the caller's shell choice (the $SHELL of the daemon identity)
 */

const char *s3_ssh3_session_srv_login_shell(const s3_ssh3_session_srv_t *s);

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

/*
 * the event-driven pump core (P7.2): the module owns the fd watches
 * and the drain, the wire framing stays with the caller through the
 * io sinks; a sink answers S3_OK (sent), S3_BUSY (the peer window is
 * full, the frame is queued in the sink - the pump stops reading the
 * fds until the queue drains, the B19b backpressure) or S3_ERROR
 * (the hard failure)
 */

typedef s3_int_t (*s3_ssh3_session_sink_pt)(void *ctx, const u_char *data, size_t len);

typedef struct {
    void                   *ctx;
    s3_ssh3_session_sink_pt output;             /* the 94 direction, the pty merges into it */
    s3_ssh3_session_sink_pt err;                /* the 95 direction, NULL keeps it dropped */
    s3_int_t (*exit)(void *ctx, uint64_t code); /* the verdict, once */
} s3_ssh3_session_srv_io_t;

/*
 * one pump pass: drains the readable output and the stderr pipe into
 * the sinks, reaps the verdict and reports it once through io->exit;
 * S3_AGAIN while the process runs, S3_OK once the verdict went out,
 * S3_BUSY when a sink queued the chunk (the unread pipe bytes wait
 * for the next pass), S3_ERROR when a sink failed (a retry answers
 * with the cached code)
 */

s3_int_t s3_ssh3_session_srv_pump(s3_ssh3_session_srv_t *s, const s3_ssh3_session_srv_io_t *io);

/*
 * registers the read watches over the process fds (the stdout/pty
 * master and the stderr pipe, when it exists); the watch connections
 * live in a process-wide free list, the fd close stays with the
 * teardown; the pump runs from the event machine context
 */

s3_int_t s3_ssh3_session_srv_watch(s3_ssh3_session_srv_t *s, s3_pool_t *watch_pool, s3_log_t *log,
                                   s3_ssh3_session_pump_pt pump, void *pump_ctx);

/*
 * disarms the watches: the posted wake-ups leave the queue, the
 * closed flag stops the stale ones; must run before the watch pool
 * and the session fds die
 */

void s3_ssh3_session_srv_unwatch(s3_ssh3_session_srv_t *s);

#endif /* _S3_SSH3_SESSION_SRV_H_INCLUDED_ */
