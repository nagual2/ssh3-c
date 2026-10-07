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

/*
 * the identity drop of the session (P7.3) needs the BSD surface of
 * <grp.h>: initgroups() hides behind __USE_MISC, the build pins
 * _POSIX_C_SOURCE on the command line
 */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif

#include <s3_core.h>

#include <s3_ssh3_session_srv.h>

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
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

/* the read window of the pump drain, pool-owned and reused */

#define S3_SSH3_SESSION_DRAIN_SIZE 16384

/*
 * the verdict watchdog: when every process fd hit the eof before the
 * child exited, no readiness wake carries the reap any more, this
 * slow timer delivers it; the transport path never waits for it
 */

#define S3_SSH3_SESSION_REAP_WATCHDOG_MS 100

/*
 * the watch connection of the pump: the connection rides first so
 * the connection pointer casts back to the watch, the free list
 * below recycles them without a per-session allocation; the instance
 * flips on every reuse and the stale wake-ups of the old fd die on
 * the epoll check
 */
typedef struct s3_ssh3_session_watch_s s3_ssh3_session_watch_t;

struct s3_ssh3_session_watch_s {
    s3_connection_t          conn; /* the cast anchor, must stay first */
    s3_event_t               rev;
    s3_event_t               wev;
    s3_ssh3_session_watch_t *next; /* the free list */
};

static s3_ssh3_session_watch_t *s3_ssh3_session_watch_free;

static void s3_ssh3_session_unwatch_fd(s3_connection_t **watch, int fd);
static void s3_ssh3_session_reap_timer(s3_event_t *ev);

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

    /* the pump drain: one read window per session, reused across the reads */

    s->drain = s3_pnalloc(pool, S3_SSH3_SESSION_DRAIN_SIZE);

    if (s->drain == NULL) {
        return S3_ERROR;
    }

    s3_memzero(&s->reap_timer, sizeof(s3_event_t));

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

const char *
s3_ssh3_session_srv_login_shell(const s3_ssh3_session_srv_t *s)
{
    if (s == NULL) {
        return NULL;
    }

    return s->run_as_shell;
}

/*
 * the identity transition of the session (P7.3): the authenticated
 * name resolves here, before any pty or spawn, the spawn drops the
 * child onto it; the refusal order is the contract - the name shapes
 * and the passwd lookup first (the 401 of the server verdict is the
 * earlier answer of the same unknown-user rule), the privilege check
 * second, so an unprivileged caller still sees which rule refused
 */
s3_int_t
s3_ssh3_session_srv_run_as(s3_ssh3_session_srv_t *s, const char *username)
{
    struct passwd *pw;
    size_t         i, n;

    if (s == NULL || s->pid != 0 || username == NULL || *username == '\0') {
        return S3_DECLINED;
    }

    /* the plain session name of the reference: the alphanumerics,
     * ".", "_" and "-", no leading dot (the traversal guard) */

    n = s3_strlen(username);

    if (username[0] == '.') {
        return S3_DECLINED;
    }

    for (i = 0; i < n; i++) {

        u_char c = (u_char)username[i];

        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '.' || c == '_' || c == '-')) {
            return S3_DECLINED;
        }
    }

    pw = getpwnam(username);

    if (pw == NULL) {
        return S3_DECLINED;
    }

    if (geteuid() != 0) {
        return S3_PERM;
    }

    /* the passwd entry is a static buffer: the pool copies outlive
     * the lookup and ride the child spawn */

    s->run_as_name = s3_palloc(s->pool, n + 1);

    if (s->run_as_name == NULL) {
        return S3_ERROR;
    }

    s3_memcpy(s->run_as_name, username, n + 1);

    s->run_as_uid = pw->pw_uid;
    s->run_as_gid = pw->pw_gid;

    if (pw->pw_dir != NULL && *pw->pw_dir != '\0') {

        size_t len = s3_strlen(pw->pw_dir);

        s->run_as_home = s3_palloc(s->pool, len + 1);

        if (s->run_as_home == NULL) {
            return S3_ERROR;
        }

        s3_memcpy(s->run_as_home, pw->pw_dir, len + 1);
    }

    if (pw->pw_shell != NULL && *pw->pw_shell != '\0') {

        size_t len = s3_strlen(pw->pw_shell);

        s->run_as_shell = s3_palloc(s->pool, len + 1);

        if (s->run_as_shell == NULL) {
            return S3_ERROR;
        }

        s3_memcpy(s->run_as_shell, pw->pw_shell, len + 1);
    }

    /*
     * the env block of the reference setupEnv: the identity fields
     * ride on top of the inherited environment (a repeated name
     * keeps the last one); the child must not exec with the daemon
     * HOME, so a failed quote refuses the whole transition
     */

    if (s3_ssh3_session_srv_env(s, "USER", s->run_as_name) != S3_OK ||
        s3_ssh3_session_srv_env(s, "LOGNAME", s->run_as_name) != S3_OK ||
        (s->run_as_home != NULL && s3_ssh3_session_srv_env(s, "HOME", s->run_as_home) != S3_OK) ||
        (s->run_as_shell != NULL &&
         s3_ssh3_session_srv_env(s, "SHELL", s->run_as_shell) != S3_OK)) {

        s->run_as_name = s->run_as_home = s->run_as_shell = NULL;

        return S3_ERROR;
    }

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
    int    in_pipe[2], out_pipe[2], err_pipe[2];
    int    master;
    pid_t  pid;
    char  *envp[S3_SSH3_SESSION_ENVP_MAX];
    char **env;

    env = s->env_len ? s3_ssh3_session_envp(s, envp, S3_SSH3_SESSION_ENVP_MAX) : NULL;

    if (s->env_len && env == NULL) {
        return S3_ERROR;
    }

    master = s->pty_master;

    /*
     * the slave of a root-opened pty belongs to the daemon identity
     * (the devpts owner is the opener of the master): the child
     * opens it by name after the drop, the chown hands the device to
     * the session user first (the OpenSSH pty ownership); the master
     * side of the caller stays untouched
     */

    if (s->pty && s->run_as_name != NULL) {

        char        path[128];
        const char *named;

        named = ptsname(master);

        if (named == NULL || s3_strlen(named) >= sizeof(path) ||
            chown(named, s->run_as_uid, s->run_as_gid) != 0) {
            return S3_ERROR;
        }
    }

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

        /*
         * the identity drop of the session (P7.3) goes FIRST, before
         * any fd of the user namespace is wired: the pty slave node
         * carries the chown of the parent (the session user, mode
         * 620), and a capped root - the systemd bounding set keeps
         * only chown/setgid/setuid/dac_read_search, no
         * cap_dac_override - opens it through the plain DAC check as
         * a non-owner other.  the supplementary groups first
         * (initgroups needs the root euid), the group and the user
         * next; the 126 verdict is the shell convention of a found
         * but not executable command - the drop failure is the same
         * class, the shell cannot run under the requested identity
         */
        if (s->run_as_name != NULL && (initgroups(s->run_as_name, s->run_as_gid) != 0 ||
                                       setgid(s->run_as_gid) != 0 || setuid(s->run_as_uid) != 0)) {
            _exit(126);
        }

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

            /* the same stdio guard as the pipes: with the master
             * raised at the open this never fires on a stdio slot,
             * the guard keeps the child honest if a caller hands one
             * in */

            if (master > 2) {
                (void)close(master);
            }

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

        /*
         * the home of the session user (the OpenSSH chdir), after the
         * wiring so a failure message rides the session stream (the
         * pty or the 95 pipe); a failed chdir is not fatal, the shell
         * starts from the root
         */
        if (s->run_as_name != NULL && s->run_as_home != NULL && chdir(s->run_as_home) != 0) {
            int root_chdir;

            fprintf(stderr, "ssh3-server: chdir(%s) failed\n", s->run_as_home);

            root_chdir = chdir("/");

            /* nothing to fall back to: the parent cwd serves */

            (void)root_chdir;
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

    /*
     * the session context runs with the stdio slots vacant (the
     * connection fork closes them): an openpty master under 3 lands
     * on a stdio slot and the child close of the inherited master
     * then kills the fresh dup2 of the slave - the shell would start
     * with a dead stdio and answer a silent exit 0.  the master is
     * raised out of the stdio range the same way the exec pipes guard
     * their ends
     */

    if (master < 3) {
        int raised = fcntl(master, F_DUPFD, 3);

        if (raised < 0) {
            (void)close(master);
            (void)close(slave);
            return S3_ERROR;
        }

        (void)close(master);
        master = raised;
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

/*
 * the event-driven pump (P7.2): the process fds are watched in the
 * event context, the readiness runs the pump of the caller, the eof
 * disarms the watch - no polling timer rides the session any more,
 * the output answers within one event loop pass
 */

/* the stale wake-up of a disarmed watch: the closed flag stops it */

static void
s3_ssh3_session_watch_ready(s3_event_t *ev)
{
    s3_connection_t       *c = ev->data;
    s3_ssh3_session_srv_t *s;

    if (c->read->closed) {
        return;
    }

    s = c->data;

    if (s->pump_cb != NULL) {
        s->pump_cb(s->pump_ctx);
    }
}

/*
 * the verdict watchdog: the fds are gone but the child still runs,
 * the pump of the caller reaps it on this slow beat; the pump rearms
 * while the verdict is pending
 */

static void
s3_ssh3_session_reap_timer(s3_event_t *ev)
{
    s3_ssh3_session_srv_t *s = ev->data;

    ev->timedout = 0;

    if (s->verdict_sent || s->pump_cb == NULL) {
        return;
    }

    s->pump_cb(s->pump_ctx);
}

static s3_connection_t *
s3_ssh3_session_watch_conn(s3_ssh3_session_srv_t *s)
{
    s3_ssh3_session_watch_t *w;
    s3_connection_t         *c;
    s3_event_t              *rev, *wev;

    w = s3_ssh3_session_watch_free;

    if (w != NULL) {
        s3_ssh3_session_watch_free = w->next;

        /*
         * the reuse flips the instances, the stale epoll entries of
         * the previous fd epoch die on the instance check
         */

        w->conn.read->instance ^= 1;
        w->conn.write->instance ^= 1;

    } else {
        w = (s3_ssh3_session_watch_t *)s3_alloc(sizeof(s3_ssh3_session_watch_t), s->watch_log);

        if (w == NULL) {
            return NULL;
        }

        s3_memzero(w, sizeof(s3_ssh3_session_watch_t));
    }

    c = &w->conn;
    rev = &w->rev;
    wev = &w->wev;

    /*
     * the field shape of s3_get_connection(): the watch connection is
     * not ctx-owned, the fd close stays with the session teardown
     */

    c->read = rev;
    c->write = wev;
    c->fd = s->stdout_fd;
    c->data = s;
    c->log = s->watch_log;

    rev->data = c;
    wev->data = c;

    wev->write = 1;

    rev->log = s->watch_log;
    wev->log = s->watch_log;

    rev->handler = s3_ssh3_session_watch_ready;

    /*
     * the transient flags of the previous epoch leave: the fresh fd
     * rides EPOLL_CTL_ADD (active 0), the closed flag of the unwatch
     * must not silence the next handler, the readiness bits and the
     * parked post of the old fd are stale by definition
     */

    rev->active = 0;
    wev->active = 0;

    rev->closed = 0;
    wev->closed = 0;

    rev->ready = 0;
    wev->ready = 0;

    rev->pending_eof = 0;
    rev->eof = 0;
    rev->error = 0;
    rev->timedout = 0;
    rev->posted = 0;

    wev->pending_eof = 0;
    wev->eof = 0;
    wev->error = 0;
    wev->timedout = 0;
    wev->posted = 0;

    return c;
}

static void
s3_ssh3_session_unwatch_fd(s3_connection_t **watch, int fd)
{
    s3_connection_t         *c = *watch;
    s3_ssh3_session_watch_t *w;

    if (c == NULL) {
        return;
    }

    *watch = NULL;

    /* the wake-ups parked in the posted queue leave before the pool */

    if (c->read->posted) {
        s3_delete_posted_event(c->read);
    }

    if (c->write->posted) {
        s3_delete_posted_event(c->write);
    }

    /*
     * the still-open fd keeps its kernel interest: an eof-ed pipe
     * stays readable forever and would spin the loop, the filter
     * leaves explicitly; the closed fd needs nothing, the kernel
     * dropped the interest on the close; the closed flag stops the
     * wake-ups already parked in this event batch
     */

    if (c->read->active && fd != S3_SSH3_SESSION_INVALID_FD) {
        (void)s3_event_actions.del_event(c->read, S3_READ_EVENT, 0);
    }

    c->read->closed = 1;
    c->write->closed = 1;

    w = (s3_ssh3_session_watch_t *)c;
    w->next = s3_ssh3_session_watch_free;
    s3_ssh3_session_watch_free = w;
}

/* the verdict watchdog arms only when no readiness wake can come */

static void
s3_ssh3_session_watchdog_arm(s3_ssh3_session_srv_t *s)
{
    if (s->verdict_sent || s->pump_cb == NULL || s->reap_timer.timer_set) {
        return;
    }

    if (s->out_watch != NULL || s->err_watch != NULL) {
        return;
    }

    if (s->reap_timer.data == NULL) {
        s->reap_timer.data = s;
        s->reap_timer.log = s->watch_log;
        s->reap_timer.handler = s3_ssh3_session_reap_timer;
    }

    s3_event_add_timer(&s->reap_timer, S3_SSH3_SESSION_REAP_WATCHDOG_MS);
}

s3_int_t
s3_ssh3_session_srv_watch(s3_ssh3_session_srv_t *s, s3_pool_t *watch_pool, s3_log_t *log,
                          s3_ssh3_session_pump_pt pump, void *pump_ctx)
{
    if (s == NULL || watch_pool == NULL || log == NULL || pump == NULL) {
        return S3_ERROR;
    }

    s->watch_log = log;
    s->pump_cb = pump;
    s->pump_ctx = pump_ctx;

    if (s->stdout_fd != S3_SSH3_SESSION_INVALID_FD && s->out_watch == NULL) {

        s->out_watch = s3_ssh3_session_watch_conn(s);

        if (s->out_watch == NULL ||
            s3_event_actions.add_event(s->out_watch->read, S3_READ_EVENT, 0) != S3_OK) {
            /* the watch recycles, the session stays unwatched */

            s3_ssh3_session_unwatch_fd(&s->out_watch, s->stdout_fd);
            return S3_ERROR;
        }
    }

    if (s->stderr_fd != S3_SSH3_SESSION_INVALID_FD && s->err_watch == NULL) {

        s->err_watch = s3_ssh3_session_watch_conn(s);

        if (s->err_watch == NULL) {
            return S3_ERROR;
        }

        s->err_watch->fd = s->stderr_fd;

        if (s3_event_actions.add_event(s->err_watch->read, S3_READ_EVENT, 0) != S3_OK) {
            s3_ssh3_session_unwatch_fd(&s->err_watch, s->stderr_fd);
            return S3_ERROR;
        }
    }

    /* a verdict already pending without any fd ride rearms the watchdog */

    s3_ssh3_session_watchdog_arm(s);

    return S3_OK;
}

void
s3_ssh3_session_srv_unwatch(s3_ssh3_session_srv_t *s)
{
    if (s == NULL) {
        return;
    }

    if (s->reap_timer.timer_set) {
        s3_event_del_timer(&s->reap_timer);
    }

    s3_ssh3_session_unwatch_fd(&s->out_watch, s->stdout_fd);
    s3_ssh3_session_unwatch_fd(&s->err_watch, s->stderr_fd);
}

s3_int_t
s3_ssh3_session_srv_pump(s3_ssh3_session_srv_t *s, const s3_ssh3_session_srv_io_t *io)
{
    ssize_t n;

    if (s == NULL || io == NULL || io->output == NULL || io->exit == NULL) {
        return S3_ERROR;
    }

    /* the stdout rides as 94, the pty merges everything into it */

    for (;;) {

        n = s3_ssh3_session_read_fd(s->stdout_fd, s->pty, s->drain, S3_SSH3_SESSION_DRAIN_SIZE);

        if (n > 0) {

            if (io->output(io->ctx, s->drain, (size_t)n) != S3_OK) {
                s3_ssh3_session_watchdog_arm(s);
                return S3_ERROR;
            }

            continue;
        }

        if (n == 0) {
            /* the eof: the watch leaves, the child may still run */

            s3_ssh3_session_unwatch_fd(&s->out_watch, s->stdout_fd);
        }

        /* S3_AGAIN or a read error: the verdict still answers below */
        break;
    }

    /* the stderr pipe of the pipe sessions, 95 with dataType 1 */

    for (;;) {

        n = s3_ssh3_session_read_fd(s->stderr_fd, 0, s->drain, S3_SSH3_SESSION_DRAIN_SIZE);

        if (n > 0) {

            if (io->err != NULL && io->err(io->ctx, s->drain, (size_t)n) != S3_OK) {
                s3_ssh3_session_watchdog_arm(s);
                return S3_ERROR;
            }

            continue;
        }

        if (n == 0) {
            s3_ssh3_session_unwatch_fd(&s->err_watch, s->stderr_fd);
        }

        break;
    }

    /* the verdict, once: the code is cached for the retry of a failed sink */

    if (!s->verdict_sent) {

        uint64_t code;
        s3_str_t name;
        unsigned core;

        s3_str_null(&name);

        if (!s->exited) {

            s3_int_t rc = s3_ssh3_session_srv_reap(s, &code, &name, &core);

            if (rc != S3_OK) {

                /*
                 * S3_AGAIN: the process still runs, the eof-ed fds
                 * carry no wake any more, the slow watchdog rearms
                 * until the verdict is out
                 */

                s3_ssh3_session_watchdog_arm(s);

                return rc;
            }

            s->exit_code = code;
        }

        if (io->exit(io->ctx, s->exit_code) != S3_OK) {
            /* the cached code rides the watchdog rearms to the retry */

            s3_ssh3_session_watchdog_arm(s);
            return S3_ERROR;
        }

        s->verdict_sent = 1;

        if (s->reap_timer.timer_set) {
            s3_event_del_timer(&s->reap_timer);
        }

        /* the transport is over, the watches leave with the fds */
        s3_ssh3_session_unwatch_fd(&s->out_watch, s->stdout_fd);
        s3_ssh3_session_unwatch_fd(&s->err_watch, s->stderr_fd);
    }

    return S3_OK;
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
