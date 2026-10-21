/*
 * Copyright (C) 2026 the ssh3-c authors
 */

/*
 * the DoS guards of the auth phase, the port of the reference
 * server_auth/dos_guard.go (docs in s3_ssh3_dos_guard.h)
 */

#include <s3_core.h>

#include <string.h>

#include <s3_ssh3_dos_guard.h>

/*
 * the lockout table is a bounded array, not a tree: the keys are
 * attacker-controlled, the array is the hard memory bound (no
 * per-name allocation for a flood of random usernames - the exact
 * pressure a DoS guard must not create) and the linear scan runs
 * once per failed CONNECT, noise next to the password-file read it
 * guards
 *
 * the array grows on demand (the daemon books the accounts the
 * password backends know, so the population is the real accounts):
 * a fixed table starved the bookkeeping of a host with many accounts,
 * and a starved table is a brute-force protection that silently stops
 * working.  the hard ceiling stays, so the invented-name flood (a
 * future wiring that books unknown users) cannot grow the memory
 * past it
 */

typedef struct s3_dos_pw_record_s s3_dos_pw_record_t;

struct s3_dos_pw_record_s {
    char      user[S3_DOS_USER_NAME_MAX];
    unsigned  user_len;
    unsigned  failures;
    s3_msec_t locked_until; /* 0 = no lockout booked */
    unsigned  used;
};

/* the growth step of the table: the records are appended in blocks */

#define S3_DOS_PW_TABLE_GROW 64

static unsigned s3_dos_unauth_max = S3_DOS_UNAUTH_MAX_DEFAULT;
static unsigned s3_dos_unauth_n;

static unsigned           s3_dos_pw_failures_max = S3_DOS_PW_FAILURES_MAX_DEFAULT;
static s3_msec_t          s3_dos_pw_lockout_ms = S3_DOS_PW_LOCKOUT_MSEC_DEFAULT;
static s3_dos_pw_record_t *s3_dos_pw_table;
static unsigned           s3_dos_pw_table_n;  /* the records in use */
static unsigned           s3_dos_pw_table_cap; /* the records allocated */

static s3_dos_pw_record_t *s3_dos_pw_find(const s3_str_t *user, s3_msec_t now);
static s3_dos_pw_record_t *s3_dos_pw_slot(const s3_str_t *user, s3_msec_t now);

static int
s3_dos_pw_name_ok(const s3_str_t *user)
{
    return user != NULL && user->data != NULL && user->len > 0 && user->len < S3_DOS_USER_NAME_MAX;
}

s3_int_t
s3_dos_unauth_try_acquire(void)
{
    if (s3_dos_unauth_n >= s3_dos_unauth_max) {
        return S3_BUSY;
    }

    s3_dos_unauth_n++;

    return S3_OK;
}

void
s3_dos_unauth_release(void)
{
    if (s3_dos_unauth_n > 0) {
        s3_dos_unauth_n--;
    }
}

unsigned
s3_dos_unauth_count(void)
{
    return s3_dos_unauth_n;
}

unsigned
s3_dos_unauth_limit(void)
{
    return s3_dos_unauth_max;
}

void
s3_dos_unauth_set_limit(unsigned max_conversations)
{
    s3_dos_unauth_max = max_conversations;
}

/*
 * the record of the user with the lazy expiry: an expired lockout
 * clears the entry on the touch (the failures restart from zero,
 * the reference deletes the record the same way); NULL when the name
 * is untrackable or unknown
 */

static s3_dos_pw_record_t *
s3_dos_pw_find(const s3_str_t *user, s3_msec_t now)
{
    size_t i;

    if (!s3_dos_pw_name_ok(user)) {
        return NULL;
    }

    for (i = 0; i < s3_dos_pw_table_n; i++) {

        s3_dos_pw_record_t *r = &s3_dos_pw_table[i];

        if (r->used && r->user_len == user->len && s3_memcmp(r->user, user->data, user->len) == 0) {

            /*
             * the signed-diff expiry of the nginx timers: safe
             * across the s3_msec_t wrap
             */

            if (r->locked_until != 0 && (s3_msec_int_t)(now - r->locked_until) >= 0) {

                s3_memzero(r, sizeof(s3_dos_pw_record_t));
                return NULL;
            }

            return r;
        }
    }

    return NULL;
}

/*
 * the entry for a fresh booking: an unused slot first (a success or
 * an expired window freed it), then the table grows while the hard
 * ceiling allows it, and only a table at the ceiling reclaims an
 * entry without an active lockout (a bare failure counter or an
 * expired window carries no protection and yields); NULL when every
 * record locks - the booking drops, the live lockouts stay
 */

static s3_dos_pw_record_t *
s3_dos_pw_slot(const s3_str_t *user, s3_msec_t now)
{
    unsigned i;

    if (!s3_dos_pw_name_ok(user)) {
        return NULL;
    }

    for (i = 0; i < s3_dos_pw_table_n; i++) {

        if (!s3_dos_pw_table[i].used) {
            return &s3_dos_pw_table[i];
        }
    }

    /* the table grows: the records are appended in blocks, so the
     * reallocation copies amortize */

    if (s3_dos_pw_table_n < s3_dos_pw_table_cap) {

        /* a free slot inside the allocated block (the records are
         * zeroed at the allocation) */

        s3_dos_pw_record_t *r = &s3_dos_pw_table[s3_dos_pw_table_n];

        s3_dos_pw_table_n++;

        return r;
    }

    if (s3_dos_pw_table_cap < S3_DOS_PW_RECORDS_MAX) {

        unsigned cap = s3_dos_pw_table_cap + S3_DOS_PW_TABLE_GROW;

        if (cap > S3_DOS_PW_RECORDS_MAX) {
            cap = S3_DOS_PW_RECORDS_MAX;
        }

        s3_dos_pw_record_t *grown =
            realloc(s3_dos_pw_table, cap * sizeof(s3_dos_pw_record_t));

        if (grown == NULL) {
            return NULL;
        }

        s3_dos_pw_table = grown;
        s3_dos_pw_table_cap = cap;

        /* the fresh records of the block start zeroed */

        s3_memzero(&s3_dos_pw_table[s3_dos_pw_table_n],
                   (cap - s3_dos_pw_table_n) * sizeof(s3_dos_pw_record_t));

        s3_dos_pw_record_t *r = &s3_dos_pw_table[s3_dos_pw_table_n];

        s3_dos_pw_table_n++;

        return r;
    }

    for (i = 0; i < s3_dos_pw_table_n; i++) {

        s3_dos_pw_record_t *r = &s3_dos_pw_table[i];

        if (r->locked_until == 0 || (s3_msec_int_t)(now - r->locked_until) >= 0) {
            return r;
        }
    }

    return NULL;
}

s3_int_t
s3_dos_pw_locked(const s3_str_t *user, s3_msec_t now)
{
    s3_dos_pw_record_t *r;

    r = s3_dos_pw_find(user, now);

    if (r == NULL || r->locked_until == 0) {
        return 0;
    }

    return ((s3_msec_int_t)(now - r->locked_until) < 0);
}

void
s3_dos_pw_failure(const s3_str_t *user, s3_msec_t now)
{
    s3_dos_pw_record_t *r;

    r = s3_dos_pw_find(user, now);

    if (r == NULL) {

        r = s3_dos_pw_slot(user, now);

        if (r == NULL) {
            /* the table is full of live lockouts: the booking drops */
            return;
        }

        s3_memcpy(r->user, user->data, user->len);
        r->user[user->len] = '\0';
        r->user_len = user->len;
        r->failures = 0;
        r->locked_until = 0;
        r->used = 1;
    }

    if (r->locked_until != 0 && (s3_msec_int_t)(now - r->locked_until) < 0) {

        /* the account is already locked: the failure never reached
         * the backend, the window does not extend */
        return;
    }

    r->failures++;

    if (r->failures >= s3_dos_pw_failures_max) {
        r->locked_until = now + s3_dos_pw_lockout_ms;
    }
}

void
s3_dos_pw_success(const s3_str_t *user)
{
    size_t i;

    if (!s3_dos_pw_name_ok(user)) {
        return;
    }

    for (i = 0; i < s3_dos_pw_table_n; i++) {

        s3_dos_pw_record_t *r = &s3_dos_pw_table[i];

        if (r->used && r->user_len == user->len && s3_memcmp(r->user, user->data, user->len) == 0) {

            s3_memzero(r, sizeof(s3_dos_pw_record_t));
            return;
        }
    }
}

void
s3_dos_pw_set_limits(unsigned max_failures, s3_msec_t lockout_ms)
{
    s3_dos_pw_failures_max = max_failures;
    s3_dos_pw_lockout_ms = lockout_ms;
}
