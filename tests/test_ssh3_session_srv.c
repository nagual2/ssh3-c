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
#include <stdlib.h>
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

    s3_test_sleep_ms(300); /* the valgrind child lingers pre-exec, the early TERM is swallowed */

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
/* the pty master must stay out of the stdio range: the connection
 * fork runs with the stdio slots closed, a master on such a slot is
 * closed by the child after the dup2 and the shell starts with a dead
 * stdio (the silent exit 0 of the setuid e2e pty leg) */

static int
s3_test_session_pty_master_above_stdio(void)
{
    s3_log_t              log;
    s3_pool_t            *pool;
    s3_ssh3_session_srv_t s;
    static const s3_str_t modes = s3_string("");
    static const s3_str_t term = s3_string("xterm");
    int                   saved0, saved1, saved2;
    int                   rc, master;

    pool = s3_test_make_pool(&log);
    S3_ASSERT(pool != NULL);

    S3_ASSERT(s3_ssh3_session_srv_init(&s, pool) == S3_OK);

    saved0 = dup(0);
    saved1 = dup(1);
    saved2 = dup(2);
    S3_ASSERT(saved0 >= 0 && saved1 >= 0 && saved2 >= 0);

    /* the connection-fork shape: the stdio slots are vacant */

    S3_ASSERT(close(0) == 0);
    S3_ASSERT(close(1) == 0);
    S3_ASSERT(close(2) == 0);

    rc = s3_ssh3_session_srv_pty_req(&s, &term, 80, 24, 0, 0, &modes);
    master = s.pty_master;

    /* the stdio back before any assertion output rides it */

    S3_ASSERT(dup2(saved0, 0) == 0);
    S3_ASSERT(dup2(saved1, 1) == 1);
    S3_ASSERT(dup2(saved2, 2) == 2);
    S3_ASSERT(close(saved0) == 0);
    S3_ASSERT(close(saved1) == 0);
    S3_ASSERT(close(saved2) == 0);

    S3_ASSERT(rc == S3_OK);
    S3_ASSERT(s.pty == 1);

    /* the master must not share a stdio slot: the child closes the
     * inherited master by number after the dup2 of the slave */

    S3_ASSERT(master > 2);

    S3_ASSERT(close(master) == 0);
    s.pty_master = S3_SSH3_SESSION_INVALID_FD;
    s.pty = 0;

    s3_destroy_pool(pool);

    return s3_test_failures;
}

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

/*
 * the event-driven pump rig: the io sinks collect the streams and the
 * verdict, the pump callback counts the wake-ups - the timer must
 * never take part, the counters answer the "the events replaced the
 * transport tick" question
 */
typedef struct {
    s3_ssh3_session_srv_t   *s;
    u_char                   out[4096];
    size_t                   out_len;
    u_char                   err[1024];
    size_t                   err_len;
    unsigned                 pump_count;
    unsigned                 exit_count;
    uint64_t                 exit_code;
    s3_ssh3_session_srv_io_t io;
} s3_test_pump_env_t;

static s3_int_t
s3_test_pump_sink(u_char *acc, size_t *len, size_t cap, const u_char *data, size_t n)
{
    if (*len + n > cap) {
        return S3_ERROR;
    }

    s3_memcpy(acc + *len, data, n);
    *len += n;

    return S3_OK;
}

static s3_int_t
s3_test_pump_out(void *ctx, const u_char *data, size_t len)
{
    s3_test_pump_env_t *env = ctx;

    return s3_test_pump_sink(env->out, &env->out_len, sizeof(env->out), data, len);
}

static s3_int_t
s3_test_pump_err(void *ctx, const u_char *data, size_t len)
{
    s3_test_pump_env_t *env = ctx;

    return s3_test_pump_sink(env->err, &env->err_len, sizeof(env->err), data, len);
}

static s3_int_t
s3_test_pump_exit(void *ctx, uint64_t code)
{
    s3_test_pump_env_t *env = ctx;

    env->exit_code = code;
    env->exit_count++;

    return S3_OK;
}

/* the watch wake-up: the pump runs from the event, no timer around */

static void
s3_test_pump_run(void *ctx)
{
    s3_test_pump_env_t *env = ctx;

    env->pump_count++;

    (void)s3_ssh3_session_srv_pump(env->s, &env->io);
}

static int
s3_test_pump_accumulated(const u_char *acc, size_t len, const char *needle)
{
    size_t n = s3_strlen(needle);

    if (len < n) {
        return 0;
    }

    return s3_memcmp(acc + len - n, needle, n) == 0;
}

/*
 * the monotonic milliseconds of the run: the event answer must land
 * far under the 50 ms transport tick of the polling pump
 */
static int64_t
s3_test_now_ms(void)
{
    struct timespec ts;

    (void)clock_gettime(CLOCK_MONOTONIC, &ts);

    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/*
 * runs the event machine until stop() answers true or the deadline
 * passes; each cycle waits at most slice_ms inside the epoll, the
 * timers expire and the posted queue drains like the server loops do
 */
static void
s3_test_pump_loop(s3_event_ctx_t *ctx, s3_test_pump_env_t *env, int (*stop)(s3_test_pump_env_t *),
                  int deadline_ms)
{
    int64_t start = s3_test_now_ms();

    env->io.ctx = env;
    env->io.output = s3_test_pump_out;
    env->io.err = s3_test_pump_err;
    env->io.exit = s3_test_pump_exit;

    while (s3_test_now_ms() - start < deadline_ms) {

        s3_time_update();
        (void)s3_event_actions.process_events(ctx, 10, S3_UPDATE_TIME);
        s3_event_expire_timers(ctx);
        s3_event_process_posted(ctx, &ctx->posted_events);

        if (stop(env)) {
            return;
        }
    }
}

static int
s3_test_pump_got_exit(s3_test_pump_env_t *env)
{
    return env->exit_count > 0;
}

static int
s3_test_pump_got_err(s3_test_pump_env_t *env, const char *needle)
{
    return s3_test_pump_accumulated(env->err, env->err_len, needle);
}

/* the pty stream carries the echo and the CR-LF, the probe rides anywhere */

static int
s3_test_pump_contains(const u_char *acc, size_t len, const char *needle)
{
    size_t n = s3_strlen(needle);
    size_t i;

    if (len < n) {
        return 0;
    }

    for (i = 0; i + n <= len; i++) {

        if (s3_memcmp(acc + i, needle, n) == 0) {
            return 1;
        }
    }

    return 0;
}

static int
s3_test_pump_got_pty_probe(s3_test_pump_env_t *env)
{
    return s3_test_pump_contains(env->out, env->out_len, "s3-pty-ev");
}

static int
s3_test_pump_got_ev_probe(s3_test_pump_env_t *env)
{
    return s3_test_pump_contains(env->out, env->out_len, "s3-ev");
}

/*
 * the core of the P7.2 wave: the output of `printf` must reach the
 * sink through the fd watch alone - no timer armed, the epoll slice
 * is 10 ms, so anything above ~45 ms would mean a transport tick is
 * still in the way; the verdict rides the eof wake of the same watch
 */
static int
s3_test_session_pump_events(void)
{
    s3_log_t              log;
    s3_pool_t            *pool;
    s3_event_ctx_t        ctx;
    s3_ssh3_session_srv_t s;
    s3_test_pump_env_t    env;
    static const s3_str_t cmd = s3_string("printf s3-ev");
    int64_t               t0, dt;

    pool = s3_test_make_pool(&log);
    S3_ASSERT(pool != NULL);
    S3_ASSERT(s3_event_ctx_init(&ctx, &log) == S3_OK);

    s3_memzero(&env, sizeof(env));

    S3_ASSERT(s3_ssh3_session_srv_init(&s, pool) == S3_OK);
    S3_ASSERT(s3_ssh3_session_srv_exec(&s, "/bin/sh", &cmd) == S3_OK);

    env.s = &s;

    S3_ASSERT(s3_ssh3_session_srv_watch(&s, pool, &log, s3_test_pump_run, &env) == S3_OK);
    S3_ASSERT(s.out_watch != NULL);
    S3_ASSERT(s.err_watch != NULL);

    /*
     * the transport answer: the output must land through the fd watch
     * alone and far under the 50 ms tick of the polling pump; the
     * spawn and the reap ride the same loop but the latency contract
     * of the wave is about the data, the verdict gets the deadline
     */

    t0 = s3_test_now_ms();
    s3_test_pump_loop(&ctx, &env, s3_test_pump_got_ev_probe, S3_TEST_DEADLINE_MS);
    dt = s3_test_now_ms() - t0;

    S3_ASSERT(env.pump_count > 0);
    S3_ASSERT(s3_test_pump_contains(env.out, env.out_len, "s3-ev"));
    S3_ASSERT(dt < 45);

    s3_test_pump_loop(&ctx, &env, s3_test_pump_got_exit, S3_TEST_DEADLINE_MS);

    S3_ASSERT(env.exit_count == 1);
    S3_ASSERT(env.exit_code == 0);

    /* the watch disarms with the verdict, the second pump is silent */

    S3_ASSERT(s.out_watch == NULL);
    S3_ASSERT(s.err_watch == NULL);
    S3_ASSERT(s3_ssh3_session_srv_pump(&s, &env.io) == S3_OK);
    S3_ASSERT(env.exit_count == 1);

    s3_ssh3_session_srv_unwatch(&s);
    s3_destroy_pool(ctx.pool);
    s3_destroy_pool(pool);

    return s3_test_failures;
}

/* the stderr pipe rides the 95 sink through its own watch */

static int
s3_test_session_pump_stderr(void)
{
    s3_log_t              log;
    s3_pool_t            *pool;
    s3_event_ctx_t        ctx;
    s3_ssh3_session_srv_t s;
    s3_test_pump_env_t    env;
    static const s3_str_t cmd = s3_string("printf s3-er >&2");

    pool = s3_test_make_pool(&log);
    S3_ASSERT(pool != NULL);
    S3_ASSERT(s3_event_ctx_init(&ctx, &log) == S3_OK);

    s3_memzero(&env, sizeof(env));

    S3_ASSERT(s3_ssh3_session_srv_init(&s, pool) == S3_OK);
    S3_ASSERT(s3_ssh3_session_srv_exec(&s, "/bin/sh", &cmd) == S3_OK);

    env.s = &s;

    S3_ASSERT(s3_ssh3_session_srv_watch(&s, pool, &log, s3_test_pump_run, &env) == S3_OK);

    s3_test_pump_loop(&ctx, &env, s3_test_pump_got_exit, S3_TEST_DEADLINE_MS);

    S3_ASSERT(s3_test_pump_got_err(&env, "s3-er"));
    S3_ASSERT(env.exit_count == 1);
    S3_ASSERT(env.exit_code == 0);

    s3_ssh3_session_srv_unwatch(&s);
    s3_destroy_pool(ctx.pool);
    s3_destroy_pool(pool);

    return s3_test_failures;
}

/* the pty merges the streams on the master, the watch answers it too */

static int
s3_test_session_pump_pty(void)
{
    s3_log_t              log;
    s3_pool_t            *pool;
    s3_event_ctx_t        ctx;
    s3_ssh3_session_srv_t s;
    s3_test_pump_env_t    env;
    static const s3_str_t term = s3_string("xterm");
    static const s3_str_t modes = s3_string("");
    u_char                probe[64];
    size_t                probe_len;

    probe_len = (size_t)snprintf((char *)probe, sizeof(probe), "echo s3-pty-ev\n");

    pool = s3_test_make_pool(&log);
    S3_ASSERT(pool != NULL);
    S3_ASSERT(s3_event_ctx_init(&ctx, &log) == S3_OK);

    s3_memzero(&env, sizeof(env));

    S3_ASSERT(s3_ssh3_session_srv_init(&s, pool) == S3_OK);
    S3_ASSERT(s3_ssh3_session_srv_pty_req(&s, &term, 80, 24, 0, 0, &modes) == S3_OK);
    S3_ASSERT(s3_ssh3_session_srv_shell(&s, "/bin/sh") == S3_OK);

    env.s = &s;

    /* a pty has no stderr pipe: the watch rides the master alone */

    S3_ASSERT(s3_ssh3_session_srv_watch(&s, pool, &log, s3_test_pump_run, &env) == S3_OK);
    S3_ASSERT(s.out_watch != NULL);
    S3_ASSERT(s.err_watch == NULL);

    S3_ASSERT(s3_ssh3_session_srv_input(&s, probe, probe_len) == S3_OK);

    /*
     * the pty echoes the input back and translates the newline, so
     * the probe rides anywhere in the stream, the suffix checks of
     * the pipe runs do not fit here
     */

    s3_test_pump_loop(&ctx, &env, s3_test_pump_got_pty_probe, S3_TEST_DEADLINE_MS);

    S3_ASSERT(s3_test_pump_contains(env.out, env.out_len, "s3-pty-ev"));

    /* the shell quits itself: the verdict rides the eof of the same watch */

    probe_len = (size_t)snprintf((char *)probe, sizeof(probe), "exit\n");

    S3_ASSERT(s3_ssh3_session_srv_input(&s, probe, probe_len) == S3_OK);

    s3_test_pump_loop(&ctx, &env, s3_test_pump_got_exit, S3_TEST_DEADLINE_MS);

    S3_ASSERT(env.exit_count == 1);
    S3_ASSERT(env.exit_code == 0);

    s3_ssh3_session_srv_unwatch(&s);
    s3_destroy_pool(ctx.pool);
    s3_destroy_pool(pool);

    return s3_test_failures;
}

/*
 * the refusal branches of the per-session identity transition (P7.3):
 * the suite never runs privileged, so only the refusals are proven
 * here - the unknown user, the unparsable name, the missing privilege
 * and the post-spawn call; the full drop (the child runs as the
 * resolved user) rides the privileged e2e of the harness
 */

static int
s3_test_session_run_as_refusal(void)
{
    s3_log_t              log;
    s3_pool_t            *pool;
    s3_ssh3_session_srv_t s;
    static const s3_str_t cmd = s3_string("id -u");
    u_char                buf[32];
    ssize_t               n;
    int                   ms;

    pool = s3_test_make_pool(&log);
    S3_ASSERT(pool != NULL);

    S3_ASSERT(s3_ssh3_session_srv_init(&s, pool) == S3_OK);

    /* no transition resolved yet: no login shell comes from the module */

    S3_ASSERT(s3_ssh3_session_srv_login_shell(&s) == NULL);

    /* the absent and the empty names decline before any lookup */

    S3_ASSERT(s3_ssh3_session_srv_run_as(&s, NULL) == S3_DECLINED);
    S3_ASSERT(s3_ssh3_session_srv_run_as(&s, "") == S3_DECLINED);

    /* the traversal shapes stay outside the plain-name guard */

    S3_ASSERT(s3_ssh3_session_srv_run_as(&s, "../root") == S3_DECLINED);
    S3_ASSERT(s3_ssh3_session_srv_run_as(&s, ".hidden") == S3_DECLINED);
    S3_ASSERT(s3_ssh3_session_srv_run_as(&s, "bad name") == S3_DECLINED);

    /*
     * the unknown user is refused before any spawn - the 401 of the
     * server verdict is the earlier answer of the same rule
     */

    S3_ASSERT(s3_ssh3_session_srv_run_as(&s, "s3-no-such-user-xz") == S3_DECLINED);
    S3_ASSERT(s.pid == 0);
    S3_ASSERT(s.open == 0);

    /*
     * a resolving name under a non-privileged daemon: the refusal of
     * the missing privilege; conditional so the branch stays proven
     * without the root assumption of the suite
     */

    if (geteuid() != 0) {
        S3_ASSERT(s3_ssh3_session_srv_run_as(&s, "root") == S3_PERM);
        S3_ASSERT(s.pid == 0);
        S3_ASSERT(s.open == 0);
    }

    /* the refusals leave no state: the spawn still runs as the daemon
     * user (the unprivileged warning path, the identity is unchanged) */

    S3_ASSERT(s3_ssh3_session_srv_exec(&s, "/bin/sh", &cmd) == S3_OK);

    /* the second run_as of a live session declines */

    S3_ASSERT(s3_ssh3_session_srv_run_as(&s, "root") == S3_DECLINED);
    S3_ASSERT(s3_ssh3_session_srv_login_shell(&s) == NULL);

    /* the uid of the child: the pipe read polls with the deadline of
     * the suite, a wedged child cannot hang it */

    for (n = 0, ms = 0; n <= 0 && ms < S3_TEST_DEADLINE_MS; ms += 10) {

        n = s3_ssh3_session_srv_read_output(&s, buf, sizeof(buf) - 1);

        if (n == (ssize_t)S3_AGAIN || n == (ssize_t)S3_ERROR) {
            n = 0;
        }

        if (n == 0) {
            s3_test_sleep_ms(10);
        }
    }

    S3_ASSERT(n > 0);

    buf[n] = '\0';

    S3_ASSERT((uid_t)atoi((const char *)buf) == getuid());

    {
        uint64_t code = 1;
        s3_str_t name;
        unsigned core;

        S3_ASSERT(s3_test_reap_wait(&s, &code, &name, &core) == 0);
        S3_ASSERT(code == 0);
    }

    s3_destroy_pool(pool);

    return s3_test_failures;
}

/*
 * the child that leaves no transport at all (the stdout and the
 * stderr closed, the process alive): both watches disarm on the eof,
 * the readiness can wake nothing any more and the verdict watchdog
 * takes over - no spin, no loss, no transport tick
 */
static int
s3_test_session_pump_no_eof_verdict(void)
{
    s3_log_t              log;
    s3_pool_t            *pool;
    s3_event_ctx_t        ctx;
    s3_ssh3_session_srv_t s;
    s3_test_pump_env_t    env;
    static const s3_str_t cmd = s3_string("exec 1>&- 2>&-; sleep 1");

    pool = s3_test_make_pool(&log);
    S3_ASSERT(pool != NULL);
    S3_ASSERT(s3_event_ctx_init(&ctx, &log) == S3_OK);

    s3_memzero(&env, sizeof(env));

    S3_ASSERT(s3_ssh3_session_srv_init(&s, pool) == S3_OK);
    S3_ASSERT(s3_ssh3_session_srv_exec(&s, "/bin/sh", &cmd) == S3_OK);

    env.s = &s;

    S3_ASSERT(s3_ssh3_session_srv_watch(&s, pool, &log, s3_test_pump_run, &env) == S3_OK);

    /* the eof of both fds arrives fast, the process still sleeps */

    s3_test_pump_loop(&ctx, &env, s3_test_pump_got_exit, 300);

    S3_ASSERT(env.pump_count > 0);
    S3_ASSERT(env.exit_count == 0);
    S3_ASSERT(s.out_watch == NULL);
    S3_ASSERT(s.err_watch == NULL);

    /* the watchdog delivers the verdict on its slow beat, no fd wake
     * exists any more - the loop must answer without a manual pump */

    s3_test_pump_loop(&ctx, &env, s3_test_pump_got_exit, S3_TEST_DEADLINE_MS);

    S3_ASSERT(env.exit_count == 1);
    S3_ASSERT(env.exit_code == 0);

    s3_ssh3_session_srv_unwatch(&s);
    s3_destroy_pool(ctx.pool);
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
    (void)s3_test_session_pty_master_above_stdio();
    (void)s3_test_session_pty_exec_signal();
    (void)s3_test_session_run_as_refusal();
    (void)s3_test_session_pump_events();
    (void)s3_test_session_pump_stderr();
    (void)s3_test_session_pump_pty();
    (void)s3_test_session_pump_no_eof_verdict();

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_ssh3_session_srv)
