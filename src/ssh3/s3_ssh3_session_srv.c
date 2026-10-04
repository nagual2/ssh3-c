/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the server-side session of an ssh3 channel, the port of the
 * reference runningSession (docs/P4-WIRE.md 6): the module owns the
 * process and its terminals, the channel framing (94/95/98 on the
 * wire) stays in the caller
 *
 * the spawn shape of the reference execCmdInBackground(): the pty
 * sessions run the shell with the slave as the controlling terminal,
 * the pipe sessions wire three os.Pipe() pairs; every parent-side fd
 * goes non-blocking, the reads answer the S3_AGAIN semantics
 */

/*
 * the XSI surface of this module: ptsname() rides behind __USE_XOPEN,
 * the build pins _POSIX_C_SOURCE on the command line; the definition
 * lives in the file so only the pty TU pays for the extra surface
 */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#include <s3_core.h>

#include <s3_ssh3_session_srv.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include <pty.h>

/*
 * the signal names of the wire (docs/P4-WIRE.md 6) without the SIG
 * prefix, the table of the reference Process.Signal(SIG<name>)
 */
static const struct {
    const char *name;
    int         number;
} s3_ssh3_session_signals[] = {
    {"HUP", SIGHUP},   {"INT", SIGINT},   {"QUIT", SIGQUIT}, {"KILL", SIGKILL},
    {"USR1", SIGUSR1}, {"USR2", SIGUSR2}, {"TERM", SIGTERM},
};

#define S3_SSH3_SESSION_NIGNALS                                                                    \
    (sizeof(s3_ssh3_session_signals) / sizeof(s3_ssh3_session_signals[0]))

static const char *
s3_ssh3_session_signal_name(int number)
{
    size_t i;

    for (i = 0; i < S3_SSH3_SESSION_NIGNALS; i++) {

        if (s3_ssh3_session_signals[i].number == number) {
            return s3_ssh3_session_signals[i].name;
        }
    }

    return NULL;
}

extern char **environ;

s3_int_t
s3_ssh3_session_srv_init(s3_ssh3_session_srv_t *s, s3_pool_t *pool)
{
    if (s == NULL || pool == NULL) {
        return S3_ERROR;
    }

    s3_memzero(s, sizeof(s3_ssh3_session_srv_t));

    s->pool = pool;

    s->pid = 0;
    s->stdin_fd = S3_SSH3_SESSION_INVALID_FD;
    s->stdout_fd = S3_SSH3_SESSION_INVALID_FD;
    s->stderr_fd = S3_SSH3_SESSION_INVALID_FD;
    s->pty_master = S3_SSH3_SESSION_INVALID_FD;

    return S3_OK;
}

static s3_int_t
s3_ssh3_session_nonblock(int fd)
{
    int flags;

    flags = fcntl(fd, F_GETFL, 0);

    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        return S3_ERROR;
    }

    return S3_OK;
}

s3_int_t
s3_ssh3_session_srv_env(s3_ssh3_session_srv_t *s, const char *name, const char *value)
{
    size_t n, vn;
    char  *entry, **grown;

    if (s == NULL || s->pid != 0 || name == NULL || value == NULL) {
        return S3_DECLINED;
    }

    n = s3_strlen(name);
    vn = s3_strlen(value);

    if (s->env_len == s->env_cap) {

        size_t cap = s->env_cap ? s->env_cap * 2 : 4;

        grown = s3_palloc(s->pool, cap * sizeof(char *));

        if (grown == NULL) {
            return S3_ERROR;
        }

        if (s->env != NULL) {
            s3_memcpy(grown, s->env, s->env_len * sizeof(char *));
        }

        s->env = grown;
        s->env_cap = cap;
    }

    entry = s3_palloc(s->pool, n + 1 + vn + 1);

    if (entry == NULL) {
        return S3_ERROR;
    }

    s3_memcpy(entry, name, n);
    entry[n] = '=';
    s3_memcpy(entry + n + 1, value, vn);
    entry[n + 1 + vn] = '\0';

    s->env[s->env_len++] = entry;

    return S3_OK;
}

/*
 * the envp of the child: the inherited environment plus the quoted
 * extras; the array lives in the caller frame, the child execs
 * before the frame dies
 */

static char **
s3_ssh3_session_envp(s3_ssh3_session_srv_t *s, char **envp, size_t cap)
{
    size_t i, n = 0;

    for (i = 0; environ[i] != NULL; i++) {

        if (n == cap - 1) {
            return NULL;
        }

        envp[n++] = environ[i];
    }

    for (i = 0; i < s->env_len; i++) {

        if (n == cap - 1) {
            return NULL;
        }

        envp[n++] = s->env[i];
    }

    envp[n] = NULL;

    return envp;
}

/* closes every parent-side fd once, the pty fds may alias each other */

static void
s3_ssh3_session_close_fds(s3_ssh3_session_srv_t *s)
{
    int in = s->stdin_fd, out = s->stdout_fd, err = s->stderr_fd, master = s->pty_master;

    if (in != S3_SSH3_SESSION_INVALID_FD) {
        (void)close(in);
    }

    if (out != S3_SSH3_SESSION_INVALID_FD && out != in) {
        (void)close(out);
    }

    if (err != S3_SSH3_SESSION_INVALID_FD && err != in && err != out) {
        (void)close(err);
    }

    if (master != S3_SSH3_SESSION_INVALID_FD && master != in && master != out && master != err) {
        (void)close(master);
    }

    s->stdin_fd = s->stdout_fd = s->stderr_fd = s->pty_master = S3_SSH3_SESSION_INVALID_FD;
}

/*
 * the fork+exec core of both spawn requests: the child leaves the
 * server process group (setpgid, the group waves of a terminal miss
 * the session), the signal() of the module still reaches the process
 * itself - kill(pid) is targeted at the leader, never at the group
 */
static s3_int_t
s3_ssh3_session_spawn(s3_ssh3_session_srv_t *s, char *const argv[])
{
    int     in_pipe[2], out_pipe[2], err_pipe[2];
    int     master;
    pid_t   pid;
    char   *envp[S3_SSH3_SESSION_ENVP_MAX];
    char  **env;

    env = s->env_len ? s3_ssh3_session_envp(s, envp, S3_SSH3_SESSION_ENVP_MAX) : NULL;

    if (s->env_len && env == NULL) {
        return S3_ERROR;
    }

    master = s->pty_master;

    if (!s->pty) {

        if (pipe(in_pipe) != 0) {
            return S3_ERROR;
        }

        if (pipe(out_pipe) != 0) {
            (void)close(in_pipe[0]);
            (void)close(in_pipe[1]);
            return S3_ERROR;
        }

        if (pipe(err_pipe) != 0) {
            (void)close(in_pipe[0]);
            (void)close(in_pipe[1]);
            (void)close(out_pipe[0]);
            (void)close(out_pipe[1]);
            return S3_ERROR;
        }
    }

    pid = fork();

    if (pid < 0) {

        if (!s->pty) {
            (void)close(in_pipe[0]);
            (void)close(in_pipe[1]);
            (void)close(out_pipe[0]);
            (void)close(out_pipe[1]);
            (void)close(err_pipe[0]);
            (void)close(err_pipe[1]);
        }

        return S3_ERROR;
    }

    if (pid == 0) {

        /* the child: the exec failure answers 127 like the shells do */

        if (s->pty) {

            char        path[128];
            const char *named;
            int         slave;

            /*
             * setsid() alone detaches the child from the server
             * session AND makes it the new group leader - a prior
             * setpgid(0, 0) would keep pid == pgid and setsid() would
             * answer EPERM, leaving the shell in the server session
             * (the SIGTTIN stop of the first run taught this)
             */
            (void)setsid();

            /*
             * the slave reopens by name: the master keeps the pty
             * alive from the pty-req to here, no statics needed
             */
            named = ptsname(master);

            if (named == NULL || s3_strlen(named) >= sizeof(path) ||
                (slave = open(named, O_RDWR)) < 0) {
                _exit(127);
            }

            /* the controlling terminal: the job control of an
             * interactive shell works, the terminal signals route
             * into the session (the open above usually acquires it
             * for the fresh session leader already) */
            (void)ioctl(slave, TIOCSCTTY, NULL);

            (void)dup2(slave, 0);
            (void)dup2(slave, 1);
            (void)dup2(slave, 2);

            if (slave > 2) {
                (void)close(slave);
            }

            (void)close(master);

        } else {

            /* the pipes leave the server process group so the group
             * waves of a terminal miss the session; kill(pid) of the
             * module is targeted at the process, never the group */

            (void)setpgid(0, 0);

            (void)dup2(in_pipe[0], 0);
            (void)dup2(out_pipe[1], 1);
            (void)dup2(err_pipe[1], 2);

            if (in_pipe[0] > 2) {
                (void)close(in_pipe[0]);
            }

            if (in_pipe[1] > 2) {
                (void)close(in_pipe[1]);
            }

            if (out_pipe[0] > 2) {
                (void)close(out_pipe[0]);
            }

            if (out_pipe[1] > 2) {
                (void)close(out_pipe[1]);
            }

            if (err_pipe[0] > 2) {
                (void)close(err_pipe[0]);
            }

            if (err_pipe[1] > 2) {
                (void)close(err_pipe[1]);
            }
        }

        if (env != NULL) {
            execve(argv[0], argv, env);
        } else {
            execv(argv[0], argv);
        }

        _exit(127);
    }

    /* the parent keeps one end per stream, all non-blocking */

    if (s->pty) {

        (void)s3_ssh3_session_nonblock(master);

        s->stdin_fd = master;
        s->stdout_fd = master;
        s->stderr_fd = S3_SSH3_SESSION_INVALID_FD;

    } else {

        (void)close(in_pipe[0]);
        (void)close(out_pipe[1]);
        (void)close(err_pipe[1]);

        (void)s3_ssh3_session_nonblock(in_pipe[1]);
        (void)s3_ssh3_session_nonblock(out_pipe[0]);
        (void)s3_ssh3_session_nonblock(err_pipe[0]);

        s->stdin_fd = in_pipe[1];
        s->stdout_fd = out_pipe[0];
        s->stderr_fd = err_pipe[0];
    }

    s->pid = (int)pid;
    s->open = 1;

    return S3_OK;
}

s3_int_t
s3_ssh3_session_srv_pty_req(s3_ssh3_session_srv_t *s, const s3_str_t *term, uint64_t width,
                            uint64_t height, uint64_t pixel_width, uint64_t pixel_height,
                            const s3_str_t *modes)
{
    struct winsize ws;
    int            master, slave;

    /*
     * the term and the modes are accepted and ignored: the reference
     * keeps TERM for the child environment, the wire contract here
     * needs nothing from either field
     */
    (void)term;
    (void)modes;

    /* one pty per session, the second request is the state error */

    if (s->pty || s->pid != 0) {
        return S3_DECLINED;
    }

    if (openpty(&master, &slave, NULL, NULL, NULL) != 0) {
        return S3_ERROR;
    }

    /* the slave side is done: it reopens by name inside the child */

    (void)close(slave);

    s3_memzero(&ws, sizeof(ws));

    ws.ws_col = (unsigned short)width;
    ws.ws_row = (unsigned short)height;
    ws.ws_xpixel = (unsigned short)pixel_width;
    ws.ws_ypixel = (unsigned short)pixel_height;

    if (ioctl(master, TIOCSWINSZ, &ws) != 0) {
        (void)close(master);
        return S3_ERROR;
    }

    s->pty_master = master;
    s->pty = 1;

    return S3_OK;
}

s3_int_t
s3_ssh3_session_srv_shell(s3_ssh3_session_srv_t *s, const char *shell_path)
{
    char *argv[2];

    /* one process per session */

    if (s->open || s->pid != 0 || shell_path == NULL || *shell_path == '\0') {
        return S3_DECLINED;
    }

    /* the reference runs $SHELL plainly, no -l: the login-shell form
     * of the contract (docs/P4-WIRE.md 6, newCommand(login_shell)) */

    argv[0] = (char *)shell_path;
    argv[1] = NULL;

    return s3_ssh3_session_spawn(s, argv);
}

s3_int_t
s3_ssh3_session_srv_exec(s3_ssh3_session_srv_t *s, const char *shell_path, const s3_str_t *command)
{
    char  *argv[4];
    char  *cmd;
    size_t n;

    if (s->open || s->pid != 0 || shell_path == NULL || *shell_path == '\0') {
        return S3_DECLINED;
    }

    if (command == NULL || (command->data == NULL && command->len > 0)) {
        return S3_DECLINED;
    }

    /* the command is not NUL-terminated on the wire, the exec argv
     * needs the copy (the pool owns it, the session outlives the run) */

    n = command->len;

    cmd = s3_palloc(s->pool, n + 1);

    if (cmd == NULL) {
        return S3_ERROR;
    }

    s3_memcpy(cmd, command->data, n);
    cmd[n] = '\0';

    /* the reference always runs the command through the shell */

    argv[0] = (char *)shell_path;
    argv[1] = "-c";
    argv[2] = cmd;
    argv[3] = NULL;

    return s3_ssh3_session_spawn(s, argv);
}

s3_int_t
s3_ssh3_session_srv_window_change(s3_ssh3_session_srv_t *s, uint64_t width, uint64_t height,
                                  uint64_t pixel_width, uint64_t pixel_height)
{
    struct winsize ws;

    /* the resize needs the pty, the pipe sessions have no size */

    if (!s->pty || s->pty_master == S3_SSH3_SESSION_INVALID_FD) {
        return S3_DECLINED;
    }

    s3_memzero(&ws, sizeof(ws));

    ws.ws_col = (unsigned short)width;
    ws.ws_row = (unsigned short)height;
    ws.ws_xpixel = (unsigned short)pixel_width;
    ws.ws_ypixel = (unsigned short)pixel_height;

    if (ioctl(s->pty_master, TIOCSWINSZ, &ws) != 0) {
        return S3_ERROR;
    }

    return S3_OK;
}

s3_int_t
s3_ssh3_session_srv_signal(s3_ssh3_session_srv_t *s, const s3_str_t *name)
{
    size_t      i;
    const char *text;
    int         number = 0;

    /* the reference signals in OPEN with a live process only */

    if (!s->open || s->pid <= 0) {
        return S3_DECLINED;
    }

    if (name == NULL || name->data == NULL) {
        return S3_DECLINED;
    }

    for (i = 0; i < S3_SSH3_SESSION_NIGNALS; i++) {

        text = s3_ssh3_session_signals[i].name;

        if (name->len == s3_strlen(text) && s3_memcmp(name->data, text, name->len) == 0) {
            number = s3_ssh3_session_signals[i].number;
            break;
        }
    }

    if (number == 0) {
        return S3_DECLINED;
    }

    /* the process itself, never the group: setpgid(0, 0) in the child
     * keeps the group waves of a terminal away from the session */

    if (kill((pid_t)s->pid, number) != 0) {
        return S3_ERROR;
    }

    return S3_OK;
}

s3_int_t
s3_ssh3_session_srv_input(s3_ssh3_session_srv_t *s, const u_char *data, size_t len)
{
    sigset_t block, old;
    ssize_t  n;

    /* the data-like messages are OPEN-only, the LARVAL drops them */

    if (!s->open || s->stdin_fd == S3_SSH3_SESSION_INVALID_FD) {
        return S3_DECLINED;
    }

    if (len == 0) {
        return S3_OK;
    }

    /*
     * the dead child answers EPIPE with the SIGPIPE wave: blocked
     * around the write so the module stays self-contained (no global
     * signal dispositions)
     */

    sigemptyset(&block);
    sigaddset(&block, SIGPIPE);

    if (sigprocmask(SIG_BLOCK, &block, &old) != 0) {
        return S3_ERROR;
    }

    for (;;) {

        n = write(s->stdin_fd, data, len);

        if (n > 0) {

            data += n;
            len -= (size_t)n;

            if (len == 0) {
                break;
            }

            continue;
        }

        if (n < 0 && s3_socket_errno == S3_EINTR) {
            continue;
        }

        break;
    }

    (void)sigprocmask(SIG_SETMASK, &old, NULL);

    /*
     * a partial write behind an EAGAIN reports S3_AGAIN: the caller
     * resends, the harness volumes never split (the pipe buffer is
     * larger than the channel max packet)
     */

    if (n < 0) {
        return s3_socket_errno == S3_EAGAIN ? (s3_int_t)S3_AGAIN : (s3_int_t)S3_ERROR;
    }

    return S3_OK;
}

s3_int_t
s3_ssh3_session_srv_close_input(s3_ssh3_session_srv_t *s)
{
    /* the data-like FIN is OPEN-only, like the input */

    if (!s->open) {
        return S3_DECLINED;
    }

    if (s->stdin_fd == S3_SSH3_SESSION_INVALID_FD) {
        /* the idempotent second FIN */
        return S3_OK;
    }

    if (s->pty) {

        /*
         * CONTRACT: the FIN of a pty peer must not close the master -
         * the process output still flows over it and the reads would
         * die with it; only the input side is done, stdin_fd drops
         * without the close and the process ends by its signal/exit
         */
        s->stdin_fd = S3_SSH3_SESSION_INVALID_FD;

        return S3_OK;
    }

    (void)close(s->stdin_fd);
    s->stdin_fd = S3_SSH3_SESSION_INVALID_FD;

    return S3_OK;
}

/*
 * one read of a session stream: the byte count, the EOF zero, the
 * EAGAIN as S3_AGAIN and the failures as S3_ERROR; the invalid fd
 * answers the EOF zero too (a reaped session or the merged pty
 * stderr), so the caller pumps may drain without the state checks
 */
static ssize_t
s3_ssh3_session_read_fd(int fd, int is_master, u_char *buf, size_t size)
{
    ssize_t n;

    if (fd == S3_SSH3_SESSION_INVALID_FD || size == 0) {
        return 0;
    }

    for (;;) {

        n = read(fd, buf, size);

        if (n > 0) {
            return n;
        }

        if (n == 0) {
            return 0;
        }

        if (s3_socket_errno == S3_EINTR) {
            continue;
        }

        if (s3_socket_errno == S3_EAGAIN) {
            return (ssize_t)S3_AGAIN;
        }

        /*
         * the Linux pty master answers EIO once the slave side is
         * gone: the EOF shape of a pty, not a failure
         */
        if (is_master && s3_socket_errno == EIO) {
            return 0;
        }

        return (ssize_t)S3_ERROR;
    }
}

ssize_t
s3_ssh3_session_srv_read_output(s3_ssh3_session_srv_t *s, u_char *buf, size_t size)
{
    return s3_ssh3_session_read_fd(s->stdout_fd, s->pty, buf, size);
}

ssize_t
s3_ssh3_session_srv_read_stderr(s3_ssh3_session_srv_t *s, u_char *buf, size_t size)
{
    return s3_ssh3_session_read_fd(s->stderr_fd, 0, buf, size);
}

s3_int_t
s3_ssh3_session_srv_reap(s3_ssh3_session_srv_t *s, uint64_t *exit_status, s3_str_t *signal_name,
                         unsigned *core_dumped)
{
    int      status;
    pid_t    rc;
    uint64_t code = 0;
    unsigned core = 0;
    s3_str_t name;

    s3_str_null(&name);

    /* the verdict answers once, the second reap is the caller bug */

    if (s->exited) {
        return S3_ERROR;
    }

    if (s->pid <= 0) {
        return S3_AGAIN;
    }

    rc = waitpid((pid_t)s->pid, &status, WNOHANG);

    if (rc == 0) {
        return S3_AGAIN;
    }

    if (rc < 0) {
        return S3_ERROR;
    }

    if (WIFEXITED(status)) {
        code = (uint64_t)WEXITSTATUS(status);

    } else if (WIFSIGNALED(status)) {

        const char *text;

        /*
         * the reference sends the exit-status only (docs/P4-WIRE.md 6,
         * the exit-signal body is unused), the wire code carries the
         * 128 + signum shell form
         */
        code = (uint64_t)(128 + WTERMSIG(status));

        text = s3_ssh3_session_signal_name(WTERMSIG(status));

        if (text != NULL) {

            size_t  len = s3_strlen(text);
            u_char *p = s3_palloc(s->pool, len);

            if (p != NULL) {
                s3_memcpy(p, text, len);
                name.data = p;
                name.len = len;
            }
        }

#ifdef WCOREDUMP
        core = WCOREDUMP(status) ? 1 : 0;
#endif

    } else {
        /* neither exited nor killed: unreachable without WUNTRACED */
        return S3_ERROR;
    }

    /* the parent-side fds die with the verdict, no leaks */

    s3_ssh3_session_close_fds(s);

    s->pid = 0;
    s->exited = 1;

    if (exit_status != NULL) {
        *exit_status = code;
    }

    if (signal_name != NULL) {
        *signal_name = name;
    }

    if (core_dumped != NULL) {
        *core_dumped = core;
    }

    return S3_OK;
}
