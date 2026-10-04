/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the server-side session (docs/P4-WIRE.md 6): the LARVAL/OPEN state
 * machine, the fork+exec through the shell, the pty with the resize,
 * the signals and the non-blocking reap; every test runs a real
 * process against the module fds, every read polls with a deadline so
 * a wedged child cannot hang the suite
 */

#include <s3_core.h>

#include <signal.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <s3_ssh3_session_srv.h>

#include "s3_test.h"

#define S3_TEST_DEADLINE_MS 3000
#define S3_TEST_REAP_MS     2000

/* nanosleep: usleep is off the POSIX 2008 surface the build pins */

static void
s3_test_sleep_ms(int ms)
{
    struct timespec ts;

    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;

    (void)nanosleep(&ts, NULL);
}

static s3_pool_t *
s3_test_make_pool(s3_log_t *log)
{
    log->log_level = S3_LOG_ALERT;
    log->fd = S3_INVALID_FILE;

    return s3_create_pool(S3_DEFAULT_POOL_SIZE, log);
}

/*
 * the reap with the deadline: S3_AGAIN while the child still runs,
 * the exit code (or 128 + the terminating signal) once it is over;
 * a wedged child is killed so the suite never leaks a process
 */
static int
s3_test_reap_wait(s3_ssh3_session_srv_t *s, uint64_t *code, s3_str_t *name, unsigned *core)
{
    int ms;

    for (ms = 0; ms < S3_TEST_REAP_MS; ms += 10) {

        if (s3_ssh3_session_srv_reap(s, code, name, core) == S3_OK) {
            return 0;
        }

        s3_test_sleep_ms(10);
    }

    /* the deadline hit: the verdict is lost, stop the process */

    if (s->pid > 0) {
        (void)kill((pid_t)s->pid, SIGKILL);
        (void)waitpid((pid_t)s->pid, NULL, 0);
    }

    return -1;
}

/*
 * polls read_output() until the needle shows up in the accumulated
 * bytes or the deadline passes; answers whether it was found
 */
static int
s3_test_read_until(s3_ssh3_session_srv_t *s, const char *needle)
{
    u_char buf[512];
    u_char acc[4096];
    size_t len = 0;
    size_t n;
    int    ms;

    n = s3_strlen(needle);

    for (ms = 0; ms < S3_TEST_DEADLINE_MS; ms += 10) {

        ssize_t r = s3_ssh3_session_srv_read_output(s, buf, sizeof(buf));

        if (r > 0) {

            if (len + (size_t)r > sizeof(acc) - 1) {
                len = 0; /* the needle is expected early, keep the tail */
            }

            s3_memcpy(acc + len, buf, (size_t)r);
            len += (size_t)r;
            acc[len] = '\0';

            if (len >= n && strstr((const char *)acc, needle) != NULL) {
                return 1;
            }
        }

        s3_test_sleep_ms(10);
    }

    return 0;
}

/* the EOF wait: read_output() must answer 0 once the child is over */

static int
s3_test_read_eof(s3_ssh3_session_srv_t *s)
{
    u_char buf[64];
    int    ms;

    for (ms = 0; ms < S3_TEST_DEADLINE_MS; ms += 10) {

        ssize_t r = s3_ssh3_session_srv_read_output(s, buf, sizeof(buf));

        if (r == 0) {
            return 1;
        }

        if (r == (ssize_t)S3_ERROR) {
            return 0;
        }

        s3_test_sleep_ms(10);
    }

    return 0;
}

static int
s3_test_str_is(const s3_str_t *name, const char *text)
{
    if (name->len != s3_strlen(text)) {
        return 0;
    }

    return name->data == NULL ? text[0] == '\0' : s3_memcmp(name->data, text, name->len) == 0;
}

/* init: the invalid fields and the LARVAL restrictions of the brief */

static int
s3_test_session_larval(void)
{
    s3_log_t              log;
    s3_pool_t            *pool;
    s3_ssh3_session_srv_t s;
    static const s3_str_t modes = s3_string("");
    static const s3_str_t term = s3_string("xterm");
    uint64_t              code;
    s3_str_t              name;
    unsigned              core;
    u_char                byte = 'x';

    pool = s3_test_make_pool(&log);
    S3_ASSERT(pool != NULL);

    S3_ASSERT(s3_ssh3_session_srv_init(&s, pool) == S3_OK);

    S3_ASSERT(s.pool == pool);
    S3_ASSERT(s.pid == 0);
    S3_ASSERT(s.stdin_fd == S3_SSH3_SESSION_INVALID_FD);
    S3_ASSERT(s.stdout_fd == S3_SSH3_SESSION_INVALID_FD);
    S3_ASSERT(s.stderr_fd == S3_SSH3_SESSION_INVALID_FD);
    S3_ASSERT(s.pty_master == S3_SSH3_SESSION_INVALID_FD);
    S3_ASSERT(s.pty == 0);
    S3_ASSERT(s.open == 0);
    S3_ASSERT(s.exited == 0);

    /* nothing data-like is legal before the process exists */

    S3_ASSERT(s3_ssh3_session_srv_input(&s, &byte, 1) == S3_DECLINED);
    S3_ASSERT(s3_ssh3_session_srv_close_input(&s) == S3_DECLINED);
    S3_ASSERT(s3_ssh3_session_srv_signal(&s, &term) == S3_DECLINED);

    /* window-change needs the pty, there is none yet */

    S3_ASSERT(s3_ssh3_session_srv_window_change(&s, 80, 24, 0, 0) == S3_DECLINED);

    /* the pty request is fine but the sizes apply at spawn */

    S3_ASSERT(s3_ssh3_session_srv_pty_req(&s, &term, 80, 24, 0, 0, &modes) == S3_OK);
    S3_ASSERT(s.pty == 1);
    S3_ASSERT(s.pty_master != S3_SSH3_SESSION_INVALID_FD);

    /* the second pty on the same session is the state error */

    S3_ASSERT(s3_ssh3_session_srv_pty_req(&s, &term, 80, 24, 0, 0, &modes) == S3_DECLINED);

    /* a window-change is legal in LARVAL once the pty exists */

    S3_ASSERT(s3_ssh3_session_srv_window_change(&s, 100, 40, 0, 0) == S3_OK);

    /* the input is still declined, the fds belong to the master */

    S3_ASSERT(s3_ssh3_session_srv_input(&s, &byte, 1) == S3_DECLINED);

    /* reap before the spawn: the child can not be reaped yet */

    S3_ASSERT(s3_ssh3_session_srv_reap(&s, &code, &name, &core) == S3_AGAIN);

    s3_destroy_pool(pool);

    return s3_test_failures;
}

/* the exec through the shell without a pty: pipes on all three fds */

static int
s3_test_session_exec_pipe(void)
{
    s3_log_t              log;
    s3_pool_t            *pool;
    s3_ssh3_session_srv_t s;
    static const s3_str_t cmd = s3_string("printf s3-ok");
    uint64_t              code;
    s3_str_t              name;
    unsigned              core;
    u_char                byte = 'x';

    pool = s3_test_make_pool(&log);
    S3_ASSERT(pool != NULL);

    S3_ASSERT(s3_ssh3_session_srv_init(&s, pool) == S3_OK);
    S3_ASSERT(s3_ssh3_session_srv_exec(&s, "/bin/sh", &cmd) == S3_OK);

    S3_ASSERT(s.open == 1);
    S3_ASSERT(s.pty == 0);
    S3_ASSERT(s.pid > 0);
    S3_ASSERT(s.stdin_fd != S3_SSH3_SESSION_INVALID_FD);
    S3_ASSERT(s.stdout_fd != S3_SSH3_SESSION_INVALID_FD);
    S3_ASSERT(s.stderr_fd != S3_SSH3_SESSION_INVALID_FD);
    S3_ASSERT(s.pty_master == S3_SSH3_SESSION_INVALID_FD);

    /* the shell echoes the marker on the stdout pipe */

    S3_ASSERT(s3_test_read_until(&s, "s3-ok") == 1);

    /* the second spawn on the live session is the state error */

    S3_ASSERT(s3_ssh3_session_srv_exec(&s, "/bin/sh", &cmd) == S3_DECLINED);

    /* the FIN of the peer: the stdin pipe closes, the next one declines */

    S3_ASSERT(s3_ssh3_session_srv_close_input(&s) == S3_OK);
    S3_ASSERT(s.stdin_fd == S3_SSH3_SESSION_INVALID_FD);
    S3_ASSERT(s3_ssh3_session_srv_close_input(&s) == S3_OK); /* idempotent */
    S3_ASSERT(s3_ssh3_session_srv_input(&s, &byte, 1) == S3_DECLINED);

    /* the process runs to its own end: the exit status 0 */

    code = 1;
    S3_ASSERT(s3_test_reap_wait(&s, &code, &name, &core) == 0);
    S3_ASSERT(code == 0);
    S3_ASSERT(name.len == 0);
    S3_ASSERT(core == 0);
    S3_ASSERT(s.exited == 1);
    S3_ASSERT(s.pid == 0);

    /* the reap closed the parent-side fds, the reads answer the EOF */

    S3_ASSERT(s.stdin_fd == S3_SSH3_SESSION_INVALID_FD);
    S3_ASSERT(s.stdout_fd == S3_SSH3_SESSION_INVALID_FD);
    S3_ASSERT(s.stderr_fd == S3_SSH3_SESSION_INVALID_FD);
    S3_ASSERT(s3_ssh3_session_srv_read_output(&s, &byte, 1) == 0);

    s3_destroy_pool(pool);

    return s3_test_failures;
}

/* the exit codes ride through the reap, the unknown signals decline */

static int
s3_test_session_exit_code(void)
{
    s3_log_t              log;
    s3_pool_t            *pool;
    s3_ssh3_session_srv_t s;
    static const s3_str_t cmd = s3_string("exit 7");
    static const s3_str_t bogus = s3_string("BOGUS");
    uint64_t              code;
    s3_str_t              name;
    unsigned              core;

    pool = s3_test_make_pool(&log);
    S3_ASSERT(pool != NULL);

    S3_ASSERT(s3_ssh3_session_srv_init(&s, pool) == S3_OK);
    S3_ASSERT(s3_ssh3_session_srv_exec(&s, "/bin/sh", &cmd) == S3_OK);

    /* the window-change without a pty declines in OPEN too */

    S3_ASSERT(s3_ssh3_session_srv_window_change(&s, 80, 24, 0, 0) == S3_DECLINED);

    /* the unknown names decline before any kill syscall happens */

    S3_ASSERT(s3_ssh3_session_srv_signal(&s, &bogus) == S3_DECLINED);

    code = 0;
    S3_ASSERT(s3_test_reap_wait(&s, &code, &name, &core) == 0);

    S3_ASSERT(code == 7);
    S3_ASSERT(name.len == 0);
    S3_ASSERT(core == 0);

    /* the read on the reaped session answers the EOF, not an error */

    S3_ASSERT(s3_ssh3_session_srv_read_stderr(&s, (u_char *)&code, 1) == 0);

    s3_destroy_pool(pool);

    return s3_test_failures;
}

/* the TERM delivery: 143 = 128 + SIGTERM (the brief's signal run) */

static int
s3_test_session_signal_term(void)
{
    s3_log_t              log;
    s3_pool_t            *pool;
    s3_ssh3_session_srv_t s;
    static const s3_str_t cmd = s3_string("sleep 30");
    static const s3_str_t term = s3_string("TERM");
    uint64_t              code;
    s3_str_t              name;
    unsigned              core;

    pool = s3_test_make_pool(&log);
    S3_ASSERT(pool != NULL);

    S3_ASSERT(s3_ssh3_session_srv_init(&s, pool) == S3_OK);
    S3_ASSERT(s3_ssh3_session_srv_exec(&s, "/bin/sh", &cmd) == S3_OK);

    S3_ASSERT(s3_ssh3_session_srv_signal(&s, &term) == S3_OK);

    /* sh -c is not interactive, the default TERM kills the process */

    code = 0;
    S3_ASSERT(s3_test_reap_wait(&s, &code, &name, &core) == 0);
    S3_ASSERT(code == 143);
    S3_ASSERT(s3_test_str_is(&name, "TERM"));
    S3_ASSERT(core == 0);

    s3_destroy_pool(pool);

    return s3_test_failures;
}

/*
 * the pty run of the brief: the echo, the resize with the stty probe
 * and the clean exit; the shell on a pty is interactive and the
 * interactive shells ignore SIGTERM, so the TERM leg of the brief
 * rides in the exec run above and in the pty exec run below
 */
static int
s3_test_session_pty_shell(void)
{
    s3_log_t              log;
    s3_pool_t            *pool;
    s3_ssh3_session_srv_t s;
    static const s3_str_t term = s3_string("xterm");
    static const s3_str_t modes = s3_string("");
    u_char                probe[64];
    size_t                probe_len;

    probe_len = (size_t)snprintf((char *)probe, sizeof(probe), "echo s3-pty-$((40+2))\n");

    pool = s3_test_make_pool(&log);
    S3_ASSERT(pool != NULL);

    S3_ASSERT(s3_ssh3_session_srv_init(&s, pool) == S3_OK);

    S3_ASSERT(s3_ssh3_session_srv_pty_req(&s, &term, 80, 24, 0, 0, &modes) == S3_OK);
    S3_ASSERT(s.pty == 1);
    S3_ASSERT(s.pty_master != S3_SSH3_SESSION_INVALID_FD);
    S3_ASSERT(s.stderr_fd == S3_SSH3_SESSION_INVALID_FD);

    S3_ASSERT(s3_ssh3_session_srv_shell(&s, "/bin/sh") == S3_OK);

    /* the pty merges the three streams on the master */

    S3_ASSERT(s.open == 1);
    S3_ASSERT(s.stdin_fd == s.pty_master);
    S3_ASSERT(s.stdout_fd == s.pty_master);
    S3_ASSERT(s.stderr_fd == S3_SSH3_SESSION_INVALID_FD);

    /* the second spawn is the state error */

    S3_ASSERT(s3_ssh3_session_srv_shell(&s, "/bin/sh") == S3_DECLINED);

    S3_ASSERT(s3_ssh3_session_srv_input(&s, probe, probe_len) == S3_OK);
    S3_ASSERT(s3_test_read_until(&s, "s3-pty-42") == 1);

    /* the resize, then the size probe answers rows columns */

    S3_ASSERT(s3_ssh3_session_srv_window_change(&s, 100, 40, 0, 0) == S3_OK);

    probe_len = (size_t)snprintf((char *)probe, sizeof(probe), "stty size\n");

    S3_ASSERT(s3_ssh3_session_srv_input(&s, probe, probe_len) == S3_OK);
    S3_ASSERT(s3_test_read_until(&s, "40 100") == 1);

    /* the exit closes the slave: the master reads the EOF */

    probe_len = (size_t)snprintf((char *)probe, sizeof(probe), "exit\n");

    S3_ASSERT(s3_ssh3_session_srv_input(&s, probe, probe_len) == S3_OK);

    /* the FIN of a pty peer must not close the master: the output
     * still flows over it, only the input side is done */

    S3_ASSERT(s3_ssh3_session_srv_close_input(&s) == S3_OK);
    S3_ASSERT(s.stdin_fd == S3_SSH3_SESSION_INVALID_FD);
    S3_ASSERT(s.pty_master != S3_SSH3_SESSION_INVALID_FD);
    S3_ASSERT(s3_test_read_eof(&s) == 1);

    /* the shell quits itself: the clean zero */

    {
        uint64_t code = 1;
        s3_str_t name;
        unsigned core;

        S3_ASSERT(s3_test_reap_wait(&s, &code, &name, &core) == 0);
        S3_ASSERT(code == 0);
        S3_ASSERT(name.len == 0);
    }

    /* the reap closed the master */

    S3_ASSERT(s.pty_master == S3_SSH3_SESSION_INVALID_FD);
    S3_ASSERT(s3_ssh3_session_srv_read_output(&s, probe, 1) == 0);

    s3_destroy_pool(pool);

    return s3_test_failures;
}

/* the signal leg on a pty: exec stays non-interactive, TERM = 143 */

static int
s3_test_session_pty_exec_signal(void)
{
    s3_log_t              log;
    s3_pool_t            *pool;
    s3_ssh3_session_srv_t s;
    static const s3_str_t term = s3_string("xterm");
    static const s3_str_t modes = s3_string("");
    static const s3_str_t cmd = s3_string("sleep 30");
    static const s3_str_t sig = s3_string("TERM");
    uint64_t              code;
    s3_str_t              name;
    unsigned              core;

    pool = s3_test_make_pool(&log);
    S3_ASSERT(pool != NULL);

    S3_ASSERT(s3_ssh3_session_srv_init(&s, pool) == S3_OK);
    S3_ASSERT(s3_ssh3_session_srv_pty_req(&s, &term, 80, 24, 0, 0, &modes) == S3_OK);
    S3_ASSERT(s3_ssh3_session_srv_exec(&s, "/bin/sh", &cmd) == S3_OK);

    S3_ASSERT(s.stdin_fd == s.pty_master);

    /* the resize is legal in OPEN with the pty */

    S3_ASSERT(s3_ssh3_session_srv_window_change(&s, 100, 40, 0, 0) == S3_OK);

    S3_ASSERT(s3_ssh3_session_srv_signal(&s, &sig) == S3_OK);

    code = 0;
    S3_ASSERT(s3_test_reap_wait(&s, &code, &name, &core) == 0);
    S3_ASSERT(code == 143);
    S3_ASSERT(s3_test_str_is(&name, "TERM"));

    s3_destroy_pool(pool);

    return s3_test_failures;
}

static int
s3_test_ssh3_session_srv(void)
{
    (void)s3_test_session_larval();
    (void)s3_test_session_exec_pipe();
    (void)s3_test_session_exit_code();
    (void)s3_test_session_signal_term();
    (void)s3_test_session_pty_shell();
    (void)s3_test_session_pty_exec_signal();

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_ssh3_session_srv)
