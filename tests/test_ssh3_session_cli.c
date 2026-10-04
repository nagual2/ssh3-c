/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the client-side session (docs/P4-WIRE.md 6): the 91 confirmation
 * gating, the 94/95 payloads and the 98 exit-status through the
 * caller-installed sinks, the partial messages reassembled across
 * the chunk boundaries; the tty helpers decline on the non-tty fds
 */

#include <s3_core.h>

#include <fcntl.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include <s3_ssh3_session_cli.h>
#include <s3_ssh3_wire.h>

#include "s3_test.h"

/* the sink accumulators: the payloads are views into the pending
 * buffer, the sinks copy before the buffer moves under them */

typedef struct {
    u_char buf[16384];
    size_t len;
} s3_test_sink_t;

typedef struct {
    uint64_t code;
    unsigned calls;
} s3_test_exit_t;

static void
s3_test_sink_collect(void *arg, const s3_str_t *data)
{
    s3_test_sink_t *sink = arg;

    s3_memcpy(sink->buf + sink->len, data->data, data->len);
    sink->len += data->len;
}

static void
s3_test_sink_exit(void *arg, uint64_t code)
{
    s3_test_exit_t *verdict = arg;

    verdict->code = code;
    verdict->calls++;
}

static s3_pool_t *
s3_test_make_pool(s3_log_t *log)
{
    log->log_level = S3_LOG_ALERT;
    log->fd = S3_INVALID_FILE;

    return s3_create_pool(S3_DEFAULT_POOL_SIZE, log);
}

/* the session fixture: the accumulators, the NULL sides stay NULL */

static void
s3_test_session_open(s3_ssh3_session_cli_t *s, s3_pool_t *pool, s3_test_sink_t *out,
                     s3_test_sink_t *err, s3_test_exit_t *verdict)
{
    S3_ASSERT(s3_ssh3_session_cli_init(s, pool, out ? s3_test_sink_collect : NULL, out,
                                       err ? s3_test_sink_collect : NULL, err,
                                       verdict ? s3_test_sink_exit : NULL, verdict) == S3_OK);
}

static u_char *
s3_test_write_confirm(u_char *p, uint64_t max_packet)
{
    p = s3_ssh3_encode_varint(p, 91);

    return s3_ssh3_encode_varint(p, max_packet);
}

static u_char *
s3_test_write_data(u_char *p, const void *data, size_t len)
{
    p = s3_ssh3_encode_varint(p, 94);

    return s3_ssh3_encode_sshstring(p, data, len);
}

static u_char *
s3_test_write_stderr(u_char *p, const void *data, size_t len)
{
    p = s3_ssh3_encode_varint(p, 95);
    p = s3_ssh3_encode_varint(p, 1); /* the stderr dataType of the pin */

    return s3_ssh3_encode_sshstring(p, data, len);
}

/* the server exit-status of docs/P4-WIRE.md 6 step 12: the request
 * envelope, the want_reply byte, then the varint code */

static u_char *
s3_test_write_exit_status(u_char *p, uint64_t code)
{
    p = s3_ssh3_encode_varint(p, 98);
    p = s3_ssh3_encode_sshstring(p, "exit-status", 11);
    *p++ = 0;

    return s3_ssh3_encode_varint(p, code);
}

/* the brief's happy stream: the 91 (30000), the 94 "hi", the 95/1
 * "oops" and the 98 exit-status 7 */

static size_t
s3_test_happy_stream(u_char *buf, size_t cap)
{
    u_char *p = buf;

    p = s3_test_write_confirm(p, 30000);
    p = s3_test_write_data(p, "hi", 2);
    p = s3_test_write_stderr(p, "oops", 4);
    p = s3_test_write_exit_status(p, 7);

    S3_ASSERT((size_t)(p - buf) <= cap);

    return (size_t)(p - buf);
}

/* the verdict of the happy stream, shared by the chunked runs */

static void
s3_test_expect_happy(s3_ssh3_session_cli_t *s, s3_test_sink_t *out, s3_test_sink_t *err,
                     s3_test_exit_t *verdict)
{
    S3_ASSERT(out->len == 2 && s3_memcmp(out->buf, "hi", 2) == 0);
    S3_ASSERT(err->len == 4 && s3_memcmp(err->buf, "oops", 4) == 0);
    S3_ASSERT(verdict->calls == 1);
    S3_ASSERT(verdict->code == 7);
    S3_ASSERT(s3_ssh3_session_cli_exit_code(s) == 7);
    S3_ASSERT(s->confirmed == 1);
    S3_ASSERT(s->exited == 1);

    /* the whole stream parsed: nothing waits in the buffer */

    S3_ASSERT(s->pend_len == 0);
}

/* init zeroes the state, the code reads 0 before the first feed */

static int
s3_test_session_cli_init(void)
{
    s3_log_t              log;
    s3_pool_t            *pool;
    s3_ssh3_session_cli_t s;

    pool = s3_test_make_pool(&log);
    S3_ASSERT(pool != NULL);

    S3_ASSERT(s3_ssh3_session_cli_init(&s, pool, NULL, NULL, NULL, NULL, NULL, NULL) == S3_OK);

    S3_ASSERT(s.pool == pool);
    S3_ASSERT(s.confirmed == 0);
    S3_ASSERT(s.exited == 0);
    S3_ASSERT(s.out == NULL && s.out_arg == NULL);
    S3_ASSERT(s.err == NULL && s.err_arg == NULL);
    S3_ASSERT(s.exit_cb == NULL && s.exit_arg == NULL);
    S3_ASSERT(s.pend == NULL);
    S3_ASSERT(s.pend_len == 0 && s.pend_cap == 0);

    /* the verdict reads 0 until the exit-status ran */

    S3_ASSERT(s3_ssh3_session_cli_exit_code(&s) == 0);

    s3_destroy_pool(pool);

    return s3_test_failures;
}

/* the happy path in one chunk */

static int
s3_test_session_cli_happy(void)
{
    s3_log_t              log;
    s3_pool_t            *pool;
    s3_ssh3_session_cli_t s;
    s3_test_sink_t        out, err;
    s3_test_exit_t        verdict;
    u_char                buf[128];
    size_t                len;

    pool = s3_test_make_pool(&log);
    S3_ASSERT(pool != NULL);

    s3_memzero(&out, sizeof(out));
    s3_memzero(&err, sizeof(err));
    s3_memzero(&verdict, sizeof(verdict));

    s3_test_session_open(&s, pool, &out, &err, &verdict);

    len = s3_test_happy_stream(buf, sizeof(buf));

    S3_ASSERT(s3_ssh3_session_cli_input(&s, buf, len) == S3_OK);

    s3_test_expect_happy(&s, &out, &err, &verdict);

    s3_destroy_pool(pool);

    return s3_test_failures;
}

/* the same stream in 1..3-byte chunks: every feed answers S3_OK on
 * the partial tails and the verdict is identical, the loop walks
 * every boundary of the stream */

static int
s3_test_session_cli_split(void)
{
    s3_log_t              log;
    s3_pool_t            *pool;
    s3_ssh3_session_cli_t s;
    s3_test_sink_t        out, err;
    s3_test_exit_t        verdict;
    u_char                buf[128];
    size_t                len, chunk, off, n;

    len = s3_test_happy_stream(buf, sizeof(buf));

    for (chunk = 1; chunk <= 3; chunk++) {

        pool = s3_test_make_pool(&log);
        S3_ASSERT(pool != NULL);

        s3_memzero(&out, sizeof(out));
        s3_memzero(&err, sizeof(err));
        s3_memzero(&verdict, sizeof(verdict));

        s3_test_session_open(&s, pool, &out, &err, &verdict);

        for (off = 0; off < len; off += chunk) {
            n = len - off < chunk ? len - off : chunk;

            S3_ASSERT(s3_ssh3_session_cli_input(&s, buf + off, n) == S3_OK);
        }

        s3_test_expect_happy(&s, &out, &err, &verdict);

        s3_destroy_pool(pool);
    }

    return s3_test_failures;
}

/* the pending buffer grows by doubling from one page: a 10000-byte
 * payload fed in 100-byte chunks reassembles intact */

static int
s3_test_session_cli_growth(void)
{
    s3_log_t              log;
    s3_pool_t            *pool;
    s3_ssh3_session_cli_t s;
    s3_test_sink_t        out, err;
    s3_test_exit_t        verdict;
    u_char                buf[64], payload[10000];
    u_char               *p;
    size_t                i, off, n;

    for (i = 0; i < sizeof(payload); i++) {
        payload[i] = (u_char)(i & 0xff);
    }

    pool = s3_test_make_pool(&log);
    S3_ASSERT(pool != NULL);

    s3_memzero(&out, sizeof(out));
    s3_memzero(&err, sizeof(err));
    s3_memzero(&verdict, sizeof(verdict));

    s3_test_session_open(&s, pool, &out, &err, &verdict);

    /* the confirmation completes, then the data header waits for its
     * payload across the feeds */

    p = buf;
    p = s3_test_write_confirm(p, 30000);

    S3_ASSERT(s3_ssh3_session_cli_input(&s, buf, (size_t)(p - buf)) == S3_OK);

    p = buf;
    p = s3_ssh3_encode_varint(p, 94);
    p = s3_ssh3_encode_varint(p, sizeof(payload));

    S3_ASSERT(s3_ssh3_session_cli_input(&s, buf, (size_t)(p - buf)) == S3_OK);

    for (off = 0; off < sizeof(payload); off += 100) {
        n = sizeof(payload) - off < 100 ? sizeof(payload) - off : 100;

        S3_ASSERT(s3_ssh3_session_cli_input(&s, payload + off, n) == S3_OK);
    }

    S3_ASSERT(out.len == sizeof(payload));
    S3_ASSERT(out.buf[0] == 0 && out.buf[1] == 1 && out.buf[255] == 255);
    S3_ASSERT(out.buf[4096] == 0 && out.buf[4097] == 1);
    S3_ASSERT(out.buf[9999] == 15);

    /* the exit-status after the big payload closes the stream */

    p = buf;
    p = s3_test_write_exit_status(p, 0);

    S3_ASSERT(s3_ssh3_session_cli_input(&s, buf, (size_t)(p - buf)) == S3_OK);
    S3_ASSERT(s3_ssh3_session_cli_exit_code(&s) == 0);
    S3_ASSERT(s.pend_len == 0);

    s3_destroy_pool(pool);

    return s3_test_failures;
}

/* the server may still drain the output after the exit-status: the
 * 94 rides through the out sink, the verdict stands */

static int
s3_test_session_cli_tail_after_exit(void)
{
    s3_log_t              log;
    s3_pool_t            *pool;
    s3_ssh3_session_cli_t s;
    s3_test_sink_t        out, err;
    s3_test_exit_t        verdict;
    u_char                buf[128];
    u_char               *p;

    pool = s3_test_make_pool(&log);
    S3_ASSERT(pool != NULL);

    s3_memzero(&out, sizeof(out));
    s3_memzero(&err, sizeof(err));
    s3_memzero(&verdict, sizeof(verdict));

    s3_test_session_open(&s, pool, &out, &err, &verdict);

    p = buf;
    p = s3_test_write_confirm(p, 30000);
    p = s3_test_write_exit_status(p, 7);
    p = s3_test_write_data(p, "tail", 4);
    p = s3_test_write_data(p, "more", 4);

    S3_ASSERT(s3_ssh3_session_cli_input(&s, buf, (size_t)(p - buf)) == S3_OK);

    S3_ASSERT(out.len == 8 && s3_memcmp(out.buf, "tailmore", 8) == 0);
    S3_ASSERT(verdict.calls == 1);
    S3_ASSERT(verdict.code == 7);
    S3_ASSERT(s3_ssh3_session_cli_exit_code(&s) == 7);
    S3_ASSERT(s.exited == 1);

    s3_destroy_pool(pool);

    return s3_test_failures;
}

/* the repeated exit-status drops silently: the first one wins, the
 * callback never fires twice */

static int
s3_test_session_cli_repeat_exit(void)
{
    s3_log_t              log;
    s3_pool_t            *pool;
    s3_ssh3_session_cli_t s;
    s3_test_sink_t        out, err;
    s3_test_exit_t        verdict;
    u_char                buf[128];
    u_char               *p;

    pool = s3_test_make_pool(&log);
    S3_ASSERT(pool != NULL);

    s3_memzero(&out, sizeof(out));
    s3_memzero(&err, sizeof(err));
    s3_memzero(&verdict, sizeof(verdict));

    s3_test_session_open(&s, pool, &out, &err, &verdict);

    p = buf;
    p = s3_test_write_confirm(p, 30000);
    p = s3_test_write_exit_status(p, 7);
    p = s3_test_write_exit_status(p, 9);
    p = s3_test_write_data(p, "late", 4);

    S3_ASSERT(s3_ssh3_session_cli_input(&s, buf, (size_t)(p - buf)) == S3_OK);

    S3_ASSERT(verdict.calls == 1);
    S3_ASSERT(verdict.code == 7);
    S3_ASSERT(s3_ssh3_session_cli_exit_code(&s) == 7);
    S3_ASSERT(out.len == 4 && s3_memcmp(out.buf, "late", 4) == 0);

    s3_destroy_pool(pool);

    return s3_test_failures;
}

/*
 * the protocol violations of the pin: the 94 before the 91, the 95
 * with the dataType other than 1, the request other than the
 * exit-status, the unknown type; one error ends the session, the
 * state is not required to recover after it
 */

static int
s3_test_session_cli_errors(void)
{
    s3_log_t              log;
    s3_pool_t            *pool;
    s3_ssh3_session_cli_t s;
    s3_test_sink_t        out, err;
    s3_test_exit_t        verdict;
    u_char                buf[64];
    u_char               *p;
    size_t                len;

    /* the 94 before the 91: the session opens with the confirmation */

    pool = s3_test_make_pool(&log);
    S3_ASSERT(pool != NULL);

    s3_memzero(&out, sizeof(out));
    s3_memzero(&err, sizeof(err));
    s3_memzero(&verdict, sizeof(verdict));

    s3_test_session_open(&s, pool, &out, &err, &verdict);

    len = (size_t)(s3_test_write_data(buf, "early", 5) - buf);

    S3_ASSERT(s3_ssh3_session_cli_input(&s, buf, len) == S3_ERROR);
    S3_ASSERT(s.confirmed == 0);

    s3_destroy_pool(pool);

    /* the 95 with the dataType 0: the server pipes the stderr only */

    pool = s3_test_make_pool(&log);
    S3_ASSERT(pool != NULL);

    s3_test_session_open(&s, pool, &out, &err, &verdict);

    p = buf;
    p = s3_test_write_confirm(p, 30000);
    p = s3_ssh3_encode_varint(p, 95);
    p = s3_ssh3_encode_varint(p, 0);
    p = s3_ssh3_encode_sshstring(p, "stdout", 6);

    S3_ASSERT(s3_ssh3_session_cli_input(&s, buf, (size_t)(p - buf)) == S3_ERROR);

    s3_destroy_pool(pool);

    /* the 98 with a request other than the exit-status: the
     * window-change is not boundable in the server direction */

    pool = s3_test_make_pool(&log);
    S3_ASSERT(pool != NULL);

    s3_test_session_open(&s, pool, &out, &err, &verdict);

    p = buf;
    p = s3_test_write_confirm(p, 30000);
    p = s3_ssh3_encode_varint(p, 98);
    p = s3_ssh3_encode_sshstring(p, "window-change", 13);
    *p++ = 0;

    S3_ASSERT(s3_ssh3_session_cli_input(&s, buf, (size_t)(p - buf)) == S3_ERROR);

    s3_destroy_pool(pool);

    /* the type 96 rides through no pin of this module: an unknown
     * type can not be bounded on the wire and must not hang it */

    pool = s3_test_make_pool(&log);
    S3_ASSERT(pool != NULL);

    s3_test_session_open(&s, pool, &out, &err, &verdict);

    p = buf;
    p = s3_test_write_confirm(p, 30000);
    p = s3_ssh3_encode_varint(p, 96);

    S3_ASSERT(s3_ssh3_session_cli_input(&s, buf, (size_t)(p - buf)) == S3_ERROR);

    s3_destroy_pool(pool);

    return s3_test_failures;
}

/* the NULL sinks drop the payloads of their sides, the exit verdict
 * is recorded even without the callback */

static int
s3_test_session_cli_null_sinks(void)
{
    s3_log_t              log;
    s3_pool_t            *pool;
    s3_ssh3_session_cli_t s;
    s3_test_sink_t        out, err;
    s3_test_exit_t        verdict;
    u_char                buf[128];
    u_char               *p;

    /* the out sink is NULL: the 94 drops, the 95 and the exit work */

    pool = s3_test_make_pool(&log);
    S3_ASSERT(pool != NULL);

    s3_memzero(&out, sizeof(out));
    s3_memzero(&err, sizeof(err));
    s3_memzero(&verdict, sizeof(verdict));

    s3_test_session_open(&s, pool, NULL, &err, &verdict);

    p = buf;
    p = s3_test_write_confirm(p, 30000);
    p = s3_test_write_data(p, "dropped", 7);
    p = s3_test_write_stderr(p, "e", 1);
    p = s3_test_write_exit_status(p, 3);

    S3_ASSERT(s3_ssh3_session_cli_input(&s, buf, (size_t)(p - buf)) == S3_OK);

    S3_ASSERT(out.len == 0);
    S3_ASSERT(err.len == 1 && err.buf[0] == 'e');
    S3_ASSERT(verdict.calls == 1);
    S3_ASSERT(verdict.code == 3);

    s3_destroy_pool(pool);

    /* the err sink is NULL: the 95 drops, the 94 works */

    pool = s3_test_make_pool(&log);
    S3_ASSERT(pool != NULL);

    s3_memzero(&out, sizeof(out));
    s3_memzero(&err, sizeof(err));
    s3_memzero(&verdict, sizeof(verdict));

    s3_test_session_open(&s, pool, &out, NULL, &verdict);

    p = buf;
    p = s3_test_write_confirm(p, 30000);
    p = s3_test_write_stderr(p, "dropped", 7);
    p = s3_test_write_data(p, "keep", 4);

    S3_ASSERT(s3_ssh3_session_cli_input(&s, buf, (size_t)(p - buf)) == S3_OK);

    S3_ASSERT(out.len == 4 && s3_memcmp(out.buf, "keep", 4) == 0);
    S3_ASSERT(err.len == 0);

    s3_destroy_pool(pool);

    /* the exit callback is NULL: the code still lands in the
     * structure and reads through the accessor */

    pool = s3_test_make_pool(&log);
    S3_ASSERT(pool != NULL);

    s3_memzero(&out, sizeof(out));
    s3_memzero(&err, sizeof(err));
    s3_memzero(&verdict, sizeof(verdict));

    s3_test_session_open(&s, pool, &out, &err, NULL);

    p = buf;
    p = s3_test_write_confirm(p, 30000);
    p = s3_test_write_exit_status(p, 5);

    S3_ASSERT(s3_ssh3_session_cli_input(&s, buf, (size_t)(p - buf)) == S3_OK);

    S3_ASSERT(s3_ssh3_session_cli_exit_code(&s) == 5);
    S3_ASSERT(s.exited == 1);

    s3_destroy_pool(pool);

    return s3_test_failures;
}

/*
 * the tty helpers decline on the non-tty fds: the pipe and the
 * /dev/null node; tty_restore() declines the same way tty_raw()
 * does, the test pins that symmetry
 */

static int
s3_test_session_cli_tty(void)
{
    struct termios saved;
    uint64_t       width, height;
    int            fds[2], null_fd;

    S3_ASSERT(pipe(fds) == 0);

    S3_ASSERT(s3_ssh3_session_cli_tty_raw(fds[0], &saved) == S3_DECLINED);
    S3_ASSERT(s3_ssh3_session_cli_tty_restore(fds[0], &saved) == S3_DECLINED);
    S3_ASSERT(s3_ssh3_session_cli_tty_winsize(fds[0], &width, &height) == S3_DECLINED);

    S3_ASSERT(s3_ssh3_session_cli_tty_raw(fds[1], NULL) == S3_DECLINED);
    S3_ASSERT(s3_ssh3_session_cli_tty_winsize(fds[1], NULL, NULL) == S3_DECLINED);

    (void)close(fds[0]);
    (void)close(fds[1]);

    /* the character device is not a tty either */

    null_fd = open("/dev/null", O_RDWR);
    S3_ASSERT(null_fd >= 0);

    S3_ASSERT(s3_ssh3_session_cli_tty_raw(null_fd, &saved) == S3_DECLINED);
    S3_ASSERT(s3_ssh3_session_cli_tty_restore(null_fd, &saved) == S3_DECLINED);
    S3_ASSERT(s3_ssh3_session_cli_tty_winsize(null_fd, &width, &height) == S3_DECLINED);

    (void)close(null_fd);

    return s3_test_failures;
}

static int
s3_test_ssh3_session_cli(void)
{
    (void)s3_test_session_cli_init();
    (void)s3_test_session_cli_happy();
    (void)s3_test_session_cli_split();
    (void)s3_test_session_cli_growth();
    (void)s3_test_session_cli_tail_after_exit();
    (void)s3_test_session_cli_repeat_exit();
    (void)s3_test_session_cli_errors();
    (void)s3_test_session_cli_null_sinks();
    (void)s3_test_session_cli_tty();

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_ssh3_session_cli)
