/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the DoS guards of the auth phase (the reference
 * server_auth/dos_guard.go): the unauthenticated-conversation cap
 * with its release semantics (F-03) and the per-user password
 * brute-force lockout with the expiry window
 */

#include <s3_core.h>

#include <stdio.h>
#include <string.h>

#include <s3_ssh3_dos_guard.h>

#include "s3_test.h"

static s3_str_t
s3_test_user(const char *name)
{
    s3_str_t u;

    u.data = (u_char *)name;
    u.len = strlen(name);

    return u;
}

static int
s3_test_defaults(void)
{
    /* the knobs of the reference (server_auth/dos_guard.go) */

    S3_ASSERT(S3_DOS_UNAUTH_MAX_DEFAULT == 100);
    S3_ASSERT(S3_DOS_PW_FAILURES_MAX_DEFAULT == 10);
    S3_ASSERT(S3_DOS_PW_LOCKOUT_MSEC_DEFAULT == 60000);

    S3_ASSERT(s3_dos_unauth_limit() == S3_DOS_UNAUTH_MAX_DEFAULT);

    return s3_test_failures;
}

static int
s3_test_unauth_cap(void)
{
    unsigned saved;

    saved = s3_dos_unauth_limit();
    s3_dos_unauth_set_limit(3);

    /* the slots under the cap admit, the one over it refuses */

    S3_ASSERT(s3_dos_unauth_try_acquire() == S3_OK);
    S3_ASSERT(s3_dos_unauth_try_acquire() == S3_OK);
    S3_ASSERT(s3_dos_unauth_try_acquire() == S3_OK);
    S3_ASSERT(s3_dos_unauth_count() == 3);
    S3_ASSERT(s3_dos_unauth_try_acquire() == S3_BUSY);
    S3_ASSERT(s3_dos_unauth_count() == 3);

    /* one verdict releases its slot and the cap reopens */

    s3_dos_unauth_release();
    S3_ASSERT(s3_dos_unauth_count() == 2);
    S3_ASSERT(s3_dos_unauth_try_acquire() == S3_OK);
    S3_ASSERT(s3_dos_unauth_count() == 3);

    /* the drain: every acquired slot goes back */

    s3_dos_unauth_release();
    s3_dos_unauth_release();
    s3_dos_unauth_release();
    S3_ASSERT(s3_dos_unauth_count() == 0);

    s3_dos_unauth_set_limit(saved);

    return s3_test_failures;
}

static int
s3_test_unauth_release_clamp(void)
{
    /* the over-release clamps at zero, the counter never wraps
     * (the reference ReleaseUnauthenticatedConversation) */

    S3_ASSERT(s3_dos_unauth_count() == 0);

    s3_dos_unauth_release();
    s3_dos_unauth_release();
    S3_ASSERT(s3_dos_unauth_count() == 0);

    S3_ASSERT(s3_dos_unauth_try_acquire() == S3_OK);
    S3_ASSERT(s3_dos_unauth_count() == 1);

    s3_dos_unauth_release();
    S3_ASSERT(s3_dos_unauth_count() == 0);

    return s3_test_failures;
}

static int
s3_test_pw_lockout_window(void)
{
    s3_str_t bob = s3_test_user("bob");
    s3_str_t alice = s3_test_user("alice");

    s3_dos_pw_set_limits(3, 1000);

    S3_ASSERT(s3_dos_pw_locked(&bob, 100000) == 0);

    /* the failures under the max keep the account open */

    s3_dos_pw_failure(&bob, 100000);
    s3_dos_pw_failure(&bob, 100001);
    S3_ASSERT(s3_dos_pw_locked(&bob, 100002) == 0);

    /* the Nth failure starts the lockout until now + duration
     * (100002 + 1000 = 101002) */

    s3_dos_pw_failure(&bob, 100002);
    S3_ASSERT(s3_dos_pw_locked(&bob, 100003) == 1);

    /* the window is per user, alice never books */

    S3_ASSERT(s3_dos_pw_locked(&alice, 100003) == 0);

    /* the window holds until the duration dies ... */

    S3_ASSERT(s3_dos_pw_locked(&bob, 101001) == 1);
    S3_ASSERT(s3_dos_pw_locked(&bob, 101002) == 0);

    /* ... and the expired record cleared: the failures restart
     * from zero, the next one does not lock */

    s3_dos_pw_failure(&bob, 101003);
    S3_ASSERT(s3_dos_pw_locked(&bob, 101004) == 0);

    return s3_test_failures;
}

static int
s3_test_pw_locked_not_extending(void)
{
    s3_str_t carl = s3_test_user("carl");

    s3_dos_pw_set_limits(2, 1000);

    s3_dos_pw_failure(&carl, 50000);
    s3_dos_pw_failure(&carl, 50001);
    S3_ASSERT(s3_dos_pw_locked(&carl, 50002) == 1);

    /* a failure during the lockout never reached the backend, the
     * window does not extend (the reference PasswordAuthFailure) */

    s3_dos_pw_failure(&carl, 50002);
    S3_ASSERT(s3_dos_pw_locked(&carl, 51001) == 0);

    return s3_test_failures;
}

static int
s3_test_pw_success_clears(void)
{
    s3_str_t dan = s3_test_user("dan");
    s3_str_t nobody = s3_test_user("nobody");

    s3_dos_pw_set_limits(3, 1000);

    s3_dos_pw_failure(&dan, 1000);
    s3_dos_pw_failure(&dan, 1001);

    /* the success clears the bookkeeping: the fresh failures do
     * not resurrect the old ones */

    s3_dos_pw_success(&dan);
    S3_ASSERT(s3_dos_pw_locked(&dan, 1002) == 0);

    s3_dos_pw_failure(&dan, 1003);
    s3_dos_pw_failure(&dan, 1004);
    S3_ASSERT(s3_dos_pw_locked(&dan, 1005) == 0);

    /* the success of an unknown user is a no-op */

    s3_dos_pw_success(&nobody);

    return s3_test_failures;
}

static int
s3_test_pw_overlength_user(void)
{
    char     name[S3_DOS_USER_NAME_MAX + 8];
    s3_str_t u;
    unsigned i;

    /* the name of the bound length still books and locks */

    for (i = 0; i < S3_DOS_USER_NAME_MAX - 1; i++) {
        name[i] = 'a';
    }
    name[S3_DOS_USER_NAME_MAX - 1] = '\0';

    u = s3_test_user(name);

    s3_dos_pw_set_limits(2, 1000);

    s3_dos_pw_failure(&u, 1000);
    s3_dos_pw_failure(&u, 1001);
    S3_ASSERT(s3_dos_pw_locked(&u, 1002) == 1);

    /* the name over the bound is never tracked: no booking, no
     * lockout, no truncation aliasing (S3_DOS_USER_NAME_MAX + 4
     * failures in a row stay unbooked) */

    for (i = 0; i < S3_DOS_USER_NAME_MAX + 4; i++) {
        name[i] = 'b';
    }
    name[S3_DOS_USER_NAME_MAX + 4] = '\0';

    u = s3_test_user(name);

    s3_dos_pw_failure(&u, 2000);
    s3_dos_pw_failure(&u, 2001);
    s3_dos_pw_failure(&u, 2002);
    S3_ASSERT(s3_dos_pw_locked(&u, 2003) == 0);

    /* the empty name is not tracked either */

    u = s3_test_user("");

    s3_dos_pw_failure(&u, 3000);
    S3_ASSERT(s3_dos_pw_locked(&u, 3001) == 0);

    return s3_test_failures;
}

static int
s3_test_pw_table_bound(void)
{
    char     name[32];
    s3_str_t u;
    unsigned i;

    s3_dos_pw_set_limits(1, 60000);

    /* a live lockout must survive the flood of the counter names */

    u = s3_test_user("victim");
    s3_dos_pw_failure(&u, 5000);
    S3_ASSERT(s3_dos_pw_locked(&u, 5001) == 1);

    /* the flood of one-failure names past the table bound: the
     * overflow bookings drop without harm */

    s3_dos_pw_set_limits(10, 1000);

    for (i = 0; i < S3_DOS_PW_RECORDS_MAX + 16; i++) {
        (void)snprintf(name, sizeof(name), "flood%u", i);
        u = s3_test_user(name);
        s3_dos_pw_failure(&u, 6000 + i);
    }

    /* the live lockout of the victim stayed (the insert only
     * reclaims the entries without an active lockout) ... */

    u = s3_test_user("victim");
    S3_ASSERT(s3_dos_pw_locked(&u, 6100) == 1);

    /* ... and the tracked flood names simply carry their counter,
     * the untracked ones are gone - nothing crashed, nothing grew */

    u = s3_test_user("flood0");
    S3_ASSERT(s3_dos_pw_locked(&u, 6101) == 0);

    s3_dos_pw_set_limits(S3_DOS_PW_FAILURES_MAX_DEFAULT, S3_DOS_PW_LOCKOUT_MSEC_DEFAULT);

    return s3_test_failures;
}

/*
 * the kill-switch: the cap of zero refuses every conversation (the
 * --max-unauth-conversations 0 shape of the daemon)
 */
static int
s3_test_unauth_kill_switch(void)
{
    unsigned saved;

    saved = s3_dos_unauth_limit();
    s3_dos_unauth_set_limit(0);

    S3_ASSERT(s3_dos_unauth_try_acquire() == S3_BUSY);
    S3_ASSERT(s3_dos_unauth_count() == 0);
    S3_ASSERT(s3_dos_unauth_try_acquire() == S3_BUSY);
    S3_ASSERT(s3_dos_unauth_count() == 0);

    s3_dos_unauth_set_limit(saved);

    return s3_test_failures;
}

/*
 * the cap of one: the second conversation waits for the first verdict
 */
static int
s3_test_unauth_cap_one(void)
{
    unsigned saved;

    saved = s3_dos_unauth_limit();
    s3_dos_unauth_set_limit(1);

    S3_ASSERT(s3_dos_unauth_try_acquire() == S3_OK);
    S3_ASSERT(s3_dos_unauth_count() == 1);
    S3_ASSERT(s3_dos_unauth_try_acquire() == S3_BUSY);
    S3_ASSERT(s3_dos_unauth_count() == 1);

    s3_dos_unauth_release();
    S3_ASSERT(s3_dos_unauth_count() == 0);
    S3_ASSERT(s3_dos_unauth_try_acquire() == S3_OK);
    s3_dos_unauth_release();

    s3_dos_unauth_set_limit(saved);

    return s3_test_failures;
}

/*
 * the overflow of the cap: the counter never passes the limit, no
 * matter how many conversations arrive, and the drain returns it to
 * zero
 */
static int
s3_test_unauth_flood(void)
{
    unsigned saved;
    unsigned i;

    saved = s3_dos_unauth_limit();
    s3_dos_unauth_set_limit(8);

    for (i = 0; i < 64; i++) {
        (void)s3_dos_unauth_try_acquire();
    }

    S3_ASSERT(s3_dos_unauth_count() == 8);

    for (i = 0; i < 8; i++) {
        s3_dos_unauth_release();
    }

    S3_ASSERT(s3_dos_unauth_count() == 0);

    s3_dos_unauth_set_limit(saved);

    return s3_test_failures;
}

/*
 * the clock that jumps back: the lockout window stays (the nginx
 * signed-diff style, the record is not freed by a backwards clock)
 */
static int
s3_test_pw_clock_back(void)
{
    s3_str_t eve = s3_test_user("eve");

    s3_dos_pw_set_limits(2, 1000);

    s3_dos_pw_failure(&eve, 100000);
    s3_dos_pw_failure(&eve, 100001);
    S3_ASSERT(s3_dos_pw_locked(&eve, 100002) == 1);

    /* the clock steps back: the window is still open (the signed
     * difference of the nginx timers) */

    S3_ASSERT(s3_dos_pw_locked(&eve, 99999) == 1);

    /* and the forward expiry still ends it (the window closed at
     * 100001 + 1000) */

    S3_ASSERT(s3_dos_pw_locked(&eve, 101000) == 1);
    S3_ASSERT(s3_dos_pw_locked(&eve, 101001) == 0);

    return s3_test_failures;
}

/*
 * the table grows on demand: the account beyond the old fixed bound
 * of 256 still books and locks (a starved table is a brute-force
 * protection that silently stops working)
 */
static int
s3_test_pw_table_growth(void)
{
    char     name[32];
    s3_str_t u;
    unsigned i;

    s3_dos_pw_set_limits(1, 1000);

    for (i = 0; i < 300; i++) {
        (void)snprintf(name, sizeof(name), "grow%u", i);
        u = s3_test_user(name);
        s3_dos_pw_failure(&u, 1000 + i);
    }

    /* the three hundredth account is tracked and locked */

    u = s3_test_user("grow299");
    S3_ASSERT(s3_dos_pw_locked(&u, 2000) == 1);

    s3_dos_pw_set_limits(S3_DOS_PW_FAILURES_MAX_DEFAULT, S3_DOS_PW_LOCKOUT_MSEC_DEFAULT);

    return s3_test_failures;
}

static int
s3_test_ssh3_dos_guard(void)
{
    (void)s3_test_defaults();
    (void)s3_test_unauth_cap();
    (void)s3_test_unauth_release_clamp();
    (void)s3_test_unauth_kill_switch();
    (void)s3_test_unauth_cap_one();
    (void)s3_test_unauth_flood();
    (void)s3_test_pw_lockout_window();
    (void)s3_test_pw_locked_not_extending();
    (void)s3_test_pw_success_clears();
    (void)s3_test_pw_overlength_user();
    (void)s3_test_pw_clock_back();
    (void)s3_test_pw_table_growth();
    (void)s3_test_pw_table_bound();

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_ssh3_dos_guard)
