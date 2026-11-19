/*
 * Copyright (C) 2026 the ssh3-c authors
 */

/*
 * the session parking lot (s3_ssh3_session_park.h): the detached
 * pty sessions of the dead connections, the bounded ring of their
 * output, the lazy expiry and the token+user re-attach lookup.
 * The parked drain rides a periodic timer (the 250 ms of the
 * sess_timer shape): the recycled watch connections of a detached
 * session do not deliver the readiness reliably (the instance and
 * the closed flags of the previous life), the timer is dumb and
 * cheap - the parked sessions are few
 */

#include <s3_core.h>
#include <s3_ssh3_session_park.h>

#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define S3_PARK_USER_MAX 128
#define S3_PARK_TIMER_MS 500

struct s3_ssh3_session_park_s {
    s3_pool_t             *sess_pool; /* owns the session struct */
    s3_ssh3_session_srv_t *sess;
    char                   user[S3_PARK_USER_MAX];
    char                   token[S3_SSH3_PARK_TOKEN_LEN + 1];
    char                   agent_path[256];
    s3_uint_t              compress_alg;

    /* the output ring of the parked life (the drop-oldest on full) */

    u_char ring[S3_SSH3_PARK_RING_SIZE];
    size_t ring_head; /* the read position */
    size_t ring_len;

    time_t     parked_at;
    s3_event_t park_timer; /* the periodic drain */
    unsigned   used : 1;
};

static s3_ssh3_session_park_t **s3_park_table;
static unsigned                 s3_park_max;
static unsigned                 s3_park_lifetime;
static unsigned                 s3_park_count;

static void s3_park_kill_locked(s3_ssh3_session_park_t *p);
static void s3_park_drain_cb(void *ctx);

void
s3_ssh3_session_park_setup(unsigned max, unsigned lifetime_sec)
{
    s3_park_lifetime = lifetime_sec;

    if (max == s3_park_max) {
        return;
    }

    /* the live records die on any re-setup (the tests and the daemon
     * reload shape); the production rides one setup at the main */

    if (s3_park_table != NULL) {
        unsigned i;

        for (i = 0; i < s3_park_max; i++) {
            if (s3_park_table[i] != NULL) {
                s3_park_kill_locked(s3_park_table[i]);
            }
        }

        free(s3_park_table);
        s3_park_table = NULL;
        s3_park_count = 0;
    }

    s3_park_max = max;

    if (s3_park_max > 0) {
        s3_park_table = calloc(s3_park_max, sizeof(s3_ssh3_session_park_t *));
    }
}

unsigned
s3_ssh3_session_park_count(void)
{
    return s3_park_count;
}

/*
 * the parked pump callback of the session watchdog: the reap timer
 * of the module re-arms itself through this callback and the ring
 * holds the shell output for the re-attach replay (the fresh event
 * timer of the first shape never expired in the daemon context)
 */

static void
s3_park_drain_cb(void *ctx)
{
    s3_ssh3_session_park_t *p = ctx;

    s3_ssh3_session_park_drain(p);
}

static void
s3_park_kill_locked(s3_ssh3_session_park_t *p)
{
    s3_ssh3_session_srv_t *s = p->sess;

    if (s != NULL) {

        s->pump_cb = NULL;
        s->pump_ctx = NULL;

        s3_ssh3_session_srv_unwatch(s);

        if (s->pid > 0) {
            (void)kill((pid_t)s->pid, SIGKILL);
            (void)waitpid((pid_t)s->pid, NULL, 0);
        }
    }

    if (p->sess_pool != NULL) {
        s3_destroy_pool(p->sess_pool);
    }

    free(p);
}

s3_ssh3_session_park_t *
s3_ssh3_session_park_add(s3_pool_t *watch_pool, s3_log_t *log, s3_pool_t *sess_pool,
                         s3_ssh3_session_srv_t *sess, const char *user, const char *token,
                         const char *agent_path, s3_uint_t compress_alg, time_t now)
{
    s3_ssh3_session_park_t *p, *victim = NULL;
    unsigned                i, victim_age = 0;

    if (s3_park_max == 0 || s3_park_table == NULL || sess_pool == NULL || sess == NULL ||
        user == NULL || token == NULL) {
        return NULL;
    }

    s3_ssh3_session_park_sweep(now);

    if (s3_park_count >= s3_park_max) {

        /* the oldest record dies for the fresh entry */

        for (i = 0; i < s3_park_max; i++) {
            if (s3_park_table[i] == NULL) {
                continue;
            }

            if (victim == NULL || (unsigned)s3_park_table[i]->parked_at < victim_age) {
                victim_age = (unsigned)s3_park_table[i]->parked_at;
                victim = s3_park_table[i];
            }
        }

        if (victim == NULL) {
            return NULL;
        }

        s3_park_kill_locked(victim);
        s3_park_count--;

        for (i = 0; i < s3_park_max; i++) {
            if (s3_park_table[i] == victim) {
                s3_park_table[i] = NULL;
                break;
            }
        }
    }

    p = calloc(1, sizeof(s3_ssh3_session_park_t));

    if (p == NULL) {
        return NULL;
    }

    strncpy(p->user, user, sizeof(p->user) - 1);
    strncpy(p->token, token, sizeof(p->token) - 1);
    strncpy(p->agent_path, agent_path != NULL ? agent_path : "", sizeof(p->agent_path) - 1);
    p->compress_alg = compress_alg;
    p->sess_pool = sess_pool;
    p->sess = sess;
    (void)log;
    (void)watch_pool;
    p->parked_at = now;
    p->used = 1;

    /*
     * the parked drain takes the seat of the old channel pump: the
     * reap watchdog of the module (100 ms, re-arms itself through
     * the callback) keeps draining the pty into the ring - the
     * markers of the parked shell hold for the re-attach replay
     */

    sess->pump_cb = s3_park_drain_cb;
    sess->pump_ctx = p;

    for (i = 0; i < s3_park_max; i++) {

        if (s3_park_table[i] != NULL) {
            continue;
        }

        s3_park_table[i] = p;
        s3_park_count++;

        /* the session watch stays alive across the park: the fd
         * readiness wakes the parked drain (and the reap watchdog
         * ticks as the backstop) */

        s3_ssh3_session_park_drain(p);

        return p;
    }

    free(p);

    return NULL;
}

void
s3_ssh3_session_park_sweep(time_t now)
{
    unsigned i;

    if (s3_park_table == NULL) {
        return;
    }

    for (i = 0; i < s3_park_max; i++) {

        s3_ssh3_session_park_t *p = s3_park_table[i];

        if (p == NULL) {
            continue;
        }

        if ((unsigned long)now >= (unsigned long)p->parked_at + s3_park_lifetime) {
            s3_park_table[i] = NULL;
            s3_park_count--;
            s3_park_kill_locked(p);
        }
    }
}

s3_ssh3_session_park_t *
s3_ssh3_session_park_find(const char *user, const char *token, time_t now)
{
    unsigned i;

    /* the NULL user is the legitimate token-only lookup (the
     * ghost-identity sessions run under the daemon identity) */

    if (s3_park_table == NULL || token == NULL) {
        return NULL;
    }

    s3_ssh3_session_park_sweep(now);

    for (i = 0; i < s3_park_max; i++) {

        s3_ssh3_session_park_t *p = s3_park_table[i];

        if (p == NULL) {
            continue;
        }

        if (getenv("S3_PARK_DIAG") != NULL) {
            fprintf(stderr, "PARK-DIAG find rec-user=%s rec-token=%s vs user=%s token=%s\n",
                    p->user, p->token, user != NULL ? user : "NULL", token);
            fflush(stderr);
        }

        if (strcmp(p->token, token) == 0 &&
            (p->user[0] == '\0' || (user != NULL && strcmp(p->user, user) == 0))) {
            return p;
        }
    }

    return NULL;
}

void
s3_ssh3_session_park_take(s3_ssh3_session_park_t *p, s3_pool_t **sess_pool,
                          s3_ssh3_session_srv_t **sess, char *agent_path, size_t agent_cap,
                          s3_uint_t *compress_alg)
{
    unsigned i;

    /* the parked drain stops: the timer dies, the attaching channel
     * re-arms the fd watches of the live pump */

    if (p->sess != NULL) {
        p->sess->pump_cb = NULL;
        p->sess->pump_ctx = NULL;
    }

    *sess_pool = p->sess_pool;
    *sess = p->sess;
    *compress_alg = p->compress_alg;

    if (agent_path != NULL && agent_cap > 0) {
        strncpy(agent_path, p->agent_path, agent_cap - 1);
        agent_path[agent_cap - 1] = '\0';
    }

    if (s3_park_table != NULL) {

        for (i = 0; i < s3_park_max; i++) {

            if (s3_park_table[i] == p) {
                s3_park_table[i] = NULL;
                break;
            }
        }
    }

    if (s3_park_count > 0) {
        s3_park_count--;
    }

    free(p);
}

void
s3_ssh3_session_park_drain(s3_ssh3_session_park_t *p)
{
    s3_ssh3_session_srv_t *s = p->sess;
    u_char                 buf[4096];
    ssize_t                r;
    uint64_t               code;
    s3_str_t               name;
    unsigned               core;

    if (s == NULL) {
        return;
    }

    for (;;) {

        r = s3_ssh3_session_srv_read_output(s, buf, sizeof(buf));

        /* the stderr pipe of the pipe-shaped sessions (the exec runs
         * without a pty) drains into the same ring */

        {
            ssize_t e = s3_ssh3_session_srv_read_stderr(s, buf, sizeof(buf));

            if (e > 0) {

                if ((size_t)e >= sizeof(p->ring)) {
                    e = sizeof(p->ring);
                }

                if (p->ring_len + (size_t)e > sizeof(p->ring)) {
                    size_t drop = p->ring_len + (size_t)e - sizeof(p->ring);

                    p->ring_head = (p->ring_head + drop) % sizeof(p->ring);
                    p->ring_len -= drop;
                }

                for (ssize_t k = 0; k < e; k++) {
                    p->ring[(p->ring_head + p->ring_len) % sizeof(p->ring)] = buf[k];
                    p->ring_len++;
                }
            }
        }

        if (getenv("S3_PARK_DIAG") != NULL) {
            fprintf(stderr, "PARK-DIAG drain r=%zd\n", r);
            fflush(stderr);
        }

        if (r <= 0) {
            break;
        }

        /* the ring append, the drop-oldest on the full ring */

        if ((size_t)r >= sizeof(p->ring)) {
            r = sizeof(p->ring);
        }

        if (p->ring_len + (size_t)r > sizeof(p->ring)) {
            size_t drop = p->ring_len + (size_t)r - sizeof(p->ring);

            p->ring_head = (p->ring_head + drop) % sizeof(p->ring);
            p->ring_len -= drop;
        }

        for (ssize_t k = 0; k < r; k++) {
            p->ring[(p->ring_head + p->ring_len) % sizeof(p->ring)] = buf[k];
            p->ring_len++;
        }
    }

    /* the parked child may exit while parked: the verdict rides the
     * re-attach pump pass, the fds close here */

    if (s3_ssh3_session_srv_reap(s, &code, &name, &core) == S3_OK) {
        s->exited = 1;
    }
}

size_t
s3_ssh3_session_park_ring_take(s3_ssh3_session_park_t *p, u_char *out, size_t cap)
{
    size_t n = p->ring_len < cap ? p->ring_len : cap;
    size_t i;

    for (i = 0; i < n; i++) {
        out[i] = p->ring[(p->ring_head + i) % sizeof(p->ring)];
    }

    p->ring_head = (p->ring_head + n) % sizeof(p->ring);
    p->ring_len -= n;

    return n;
}

s3_pool_t *
s3_ssh3_session_park_pool(s3_ssh3_session_park_t *p)
{
    return p->sess_pool;
}

void
s3_ssh3_session_park_kill(s3_ssh3_session_park_t *p)
{
    unsigned i;

    if (s3_park_table != NULL) {

        for (i = 0; i < s3_park_max; i++) {

            if (s3_park_table[i] == p) {
                s3_park_table[i] = NULL;
                break;
            }
        }
    }

    if (s3_park_count > 0) {
        s3_park_count--;
    }

    s3_park_kill_locked(p);
}

void
s3_ssh3_session_park_teardown(void)
{
    unsigned i;

    if (s3_park_table == NULL) {
        return;
    }

    for (i = 0; i < s3_park_max; i++) {

        if (s3_park_table[i] != NULL) {
            s3_park_kill_locked(s3_park_table[i]);
            s3_park_table[i] = NULL;
        }
    }

    s3_park_count = 0;
}
