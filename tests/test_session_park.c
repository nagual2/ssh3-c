/*
 * Copyright (C) 2026 the ssh3-c authors
 */

/*
 * the session parking lot units (the wave 16): the park/take
 * round-trip over a live pty shell (the child survives the park, the
 * same pid answers after the re-attach), the token match, the lazy
 * expiry sweep, the cap eviction and the disabled lot
 */

#include <openssl/rand.h>

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include <s3_core.h>
#include <s3_ssh3_session_srv.h>
#include <s3_ssh3_session_park.h>
#include "s3_test.h"

#define PARK_DEADLINE_MS 4000

static s3_log_t s3_park_log;

static s3_pool_t *
s3_park_make_pool(void)
{
    s3_pool_t *pool = s3_create_pool(4096, &s3_park_log);

    return pool;
}

/* the alive probe: kill(pid, 0) answers 0 when the child is still there */

static int
s3_park_child_alive(int pid)
{
    return pid > 0 && kill((pid_t)pid, 0) == 0;
}

/* the poll helper: the accumulated read_output until the needle */

static int
s3_park_read_until(s3_ssh3_session_srv_t *s, const char *needle)
{
    u_char buf[512];
    u_char acc[4096];
    size_t len = 0;
    size_t n;
    int    ms;

    n = strlen(needle);

    for (ms = 0; ms < PARK_DEADLINE_MS; ms += 10) {

        ssize_t r = s3_ssh3_session_srv_read_output(s, buf, sizeof(buf));

        if (r > 0) {

            if (len + (size_t)r > sizeof(acc) - 1) {
                len = 0;
            }

            memcpy(acc + len, buf, (size_t)r);
            len += (size_t)r;
            acc[len] = '\0';

            if (len >= n && strstr((const char *)acc, needle) != NULL) {
                return 1;
            }
        }

        usleep(10 * 1000);
    }

    return 0;
}

/*
 * spawns an interactive /bin/sh on a pty (the parked-session shape),
 * waits for the first prompt bytes so the ring carries something
 */
static s3_int_t
s3_park_spawn_shell(s3_pool_t *pool, s3_ssh3_session_srv_t *s)
{
    static const s3_str_t term = s3_string("xterm-256color");

    if (s3_ssh3_session_srv_init(s, pool) != S3_OK) {
        return S3_ERROR;
    }

    if (s3_ssh3_session_srv_pty_req(s, &term, 80, 24, 0, 0, NULL) != S3_OK) {
        return S3_ERROR;
    }

    if (s3_ssh3_session_srv_shell(s, "/bin/sh") != S3_OK) {
        return S3_ERROR;
    }

    return S3_OK;
}

static int
s3_test_park_roundtrip(void)
{
    s3_pool_t              *pool, *watch_pool;
    s3_event_ctx_t          ctx;
    s3_ssh3_session_srv_t   s;
    s3_ssh3_session_park_t *rec;
    s3_pool_t              *back_pool = NULL;
    s3_ssh3_session_srv_t  *back_sess = NULL;
    s3_uint_t               back_alg = 0;
    char                    back_agent[256];
    time_t                  now = time(NULL);

    pool = s3_park_make_pool();
    S3_ASSERT(pool != NULL);

    watch_pool = s3_park_make_pool();
    S3_ASSERT(watch_pool != NULL);
    S3_ASSERT(s3_event_ctx_init(&ctx, &s3_park_log) == S3_OK);

    s3_ssh3_session_park_setup(4, 60);

    S3_ASSERT(s3_park_spawn_shell(pool, &s) == S3_OK);
    S3_ASSERT(s.pid > 0);
    S3_ASSERT(s3_park_child_alive(s.pid));

    /* the token must match both halves: the wrong token and the wrong
     * user find nothing */

    rec = s3_ssh3_session_park_add(watch_pool, &s3_park_log, pool, &s, "tester", "deadbeef", NULL,
                                   0, now);
    S3_ASSERT(rec != NULL);
    S3_ASSERT(s3_park_child_alive(s.pid));

    S3_ASSERT(s3_ssh3_session_park_find("tester", "ffffffff", now + 1) == NULL);
    S3_ASSERT(s3_ssh3_session_park_find("other", "deadbeef", now + 1) == NULL);

    /* the drain while parked: the shell banner/prompt landed in the
     * ring, the take hands the ownership back with the same child */

    s3_ssh3_session_park_drain(rec);

    back_agent[0] = '\0';
    s3_ssh3_session_park_take(rec, &back_pool, &back_sess, back_agent, sizeof(back_agent),
                              &back_alg);

    /* the attach contract re-arms the watch over the channel pump -
     * the test drops the parked watch first (the unwatch recycles
     * the watch connection into the free list) */

    s3_ssh3_session_srv_unwatch(&s);

    S3_ASSERT(back_pool == pool);
    S3_ASSERT(back_sess == &s);
    S3_ASSERT(s3_park_child_alive(s.pid));

    /* the parked-and-attached shell is the same live process: it
     * answers the input (the old session state, the wave complaint) */

    S3_ASSERT(s3_ssh3_session_srv_input(&s, (const u_char *)"echo PARK1\n", 11) == S3_OK);
    S3_ASSERT(s3_park_read_until(&s, "PARK1"));

    /* the table slot is free after the take */

    S3_ASSERT(s3_ssh3_session_park_find("tester", "deadbeef", now + 2) == NULL);

    (void)kill((pid_t)s.pid, SIGKILL);
    (void)waitpid((pid_t)s.pid, NULL, 0);
    s3_destroy_pool(pool);
    s3_destroy_pool(watch_pool);
    s3_event_ctx_shutdown(&ctx);

    return s3_test_failures;
}

static int
s3_test_park_expiry(void)
{
    s3_pool_t              *pool;
    s3_event_ctx_t          ctx;
    s3_ssh3_session_srv_t   s;
    s3_ssh3_session_park_t *rec;
    int                     pid;

    pool = s3_park_make_pool();
    S3_ASSERT(pool != NULL);
    S3_ASSERT(s3_event_ctx_init(&ctx, &s3_park_log) == S3_OK);

    s3_ssh3_session_park_setup(4, 1); /* the one-second lifetime */

    S3_ASSERT(s3_park_spawn_shell(pool, &s) == S3_OK);
    pid = s.pid;

    rec = s3_ssh3_session_park_add(pool, &s3_park_log, pool, &s, "tester", "cafe", NULL, 0,
                                   time(NULL));
    S3_ASSERT(rec != NULL);

    usleep(1200 * 1000); /* 1.2 s > the lifetime */

    /* the lazy sweep rides the find: the expired child is killed and
     * reaped, the lookup answers nothing */

    S3_ASSERT(s3_ssh3_session_park_find("tester", "cafe", time(NULL)) == NULL);
    S3_ASSERT(!s3_park_child_alive(pid));

    /* the pool died with the record: the lot owns it since the add */

    s3_event_ctx_shutdown(&ctx);

    return s3_test_failures;
}

static int
s3_test_park_cap_eviction(void)
{
    s3_pool_t              *pools[3];
    s3_event_ctx_t          ctx;
    s3_ssh3_session_srv_t   ss[3];
    int                     pids[3];
    s3_ssh3_session_park_t *rec;
    int                     i;
    char                    token[33];

    S3_ASSERT(s3_event_ctx_init(&ctx, &s3_park_log) == S3_OK);

    s3_ssh3_session_park_setup(2, 60); /* the two-slot cap */

    for (i = 0; i < 3; i++) {

        pools[i] = s3_park_make_pool();
        S3_ASSERT(pools[i] != NULL);

        S3_ASSERT(s3_park_spawn_shell(pools[i], &ss[i]) == S3_OK);
        pids[i] = ss[i].pid;

        snprintf(token, sizeof(token), "tok%02d", i);

        rec = s3_ssh3_session_park_add(pools[i], &s3_park_log, pools[i], &ss[i], "tester", token,
                                       NULL, 0, time(NULL));
        S3_ASSERT(rec != NULL);
    }

    /* the oldest (tok00) evicted and killed, the two fresh ride */

    S3_ASSERT(!s3_park_child_alive(pids[0]));
    S3_ASSERT(s3_park_child_alive(pids[1]));
    S3_ASSERT(s3_park_child_alive(pids[2]));

    S3_ASSERT(s3_ssh3_session_park_find("tester", "tok00", time(NULL)) == NULL);
    S3_ASSERT(s3_ssh3_session_park_find("tester", "tok01", time(NULL)) != NULL);
    S3_ASSERT(s3_ssh3_session_park_find("tester", "tok02", time(NULL)) != NULL);

    /* the teardown sweep: everything in the lot dies */

    s3_ssh3_session_park_teardown();

    S3_ASSERT(!s3_park_child_alive(pids[1]));
    S3_ASSERT(!s3_park_child_alive(pids[2]));

    /* the pools died with the evicted and the swept records */

    s3_event_ctx_shutdown(&ctx);

    return s3_test_failures;
}

static int
s3_test_park_disabled(void)
{
    s3_pool_t            *pool;
    s3_ssh3_session_srv_t s;

    pool = s3_park_make_pool();
    S3_ASSERT(pool != NULL);

    s3_ssh3_session_park_setup(0, 0); /* the disabled lot */

    S3_ASSERT(s3_park_spawn_shell(pool, &s) == S3_OK);
    S3_ASSERT(s3_ssh3_session_park_add(pool, &s3_park_log, pool, &s, "tester", "beef", NULL, 0,
                                       time(NULL)) == NULL);

    (void)kill((pid_t)s.pid, SIGKILL);
    (void)waitpid((pid_t)s.pid, NULL, 0);
    s3_destroy_pool(pool);

    return s3_test_failures;
}

static int
test_session_park(void)
{
    (void)s3_test_park_roundtrip();
    (void)s3_test_park_expiry();
    (void)s3_test_park_cap_eviction();
    (void)s3_test_park_disabled();

    return s3_test_failures;
}

S3_TEST_MAIN(test_session_park)
