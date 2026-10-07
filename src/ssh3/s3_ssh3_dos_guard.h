/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_SSH3_DOS_GUARD_H_INCLUDED_
#define _S3_SSH3_DOS_GUARD_H_INCLUDED_

#include <s3_base.h>

/*
 * the DoS guards of the auth phase, the port of the reference
 * server_auth/dos_guard.go (CTO_TASK 4.1):
 *
 *   - the unauthenticated-conversation cap (the MaxStartups analog):
 *     a CONNECT holds one slot from the arrival to the verdict, the
 *     request over the cap is refused before any per-request work
 *     worth protecting (the user lookup, the identity-file reads,
 *     the signature verifications);
 *   - the password brute-force lockout: the failed password verdicts
 *     book per user, the Nth failure inside the window locks the
 *     password backend for the account for the lockout duration; the
 *     wiring answers the locked attempt with 429 without touching
 *     the backend and clears the record on a success.
 *
 * the clock comes in from the caller (s3_current_msec of the event
 * loop, the unit tests pass synthetic values), the module keeps no
 * event-layer dependency.  The state sits in the module statics: the
 * daemon event loop is single-threaded, the API carries no locks.
 */

/*
 * the defaults of the reference (dos_guard.go), overridable with
 * --max-unauth-conversations / --max-password-failures /
 * --password-lockout-seconds and the SSH3_* env counterparts
 */

#define S3_DOS_UNAUTH_MAX_DEFAULT      100
#define S3_DOS_PW_FAILURES_MAX_DEFAULT 10
#define S3_DOS_PW_LOCKOUT_MSEC_DEFAULT 60000

/*
 * the bound of a tracked name: the lockout records store the name in
 * a fixed field, an over-bound name is never tracked (no booking, no
 * lockout) instead of being truncated - a truncated alias could let
 * one account's failures poison another's lockout.  The bound sits
 * under the CONNECT username cap of the daemon (128), so the tracked
 * names are the names the deployment can actually resolve
 */

#define S3_DOS_USER_NAME_MAX 64

/*
 * the hard memory ceiling of the lockout bookkeeping: the keys are
 * attacker-controlled and the table - not a tree - is the bound, a
 * flood of invented usernames cannot grow the memory past this
 * shape (256 x ~72 bytes, static)
 */

#define S3_DOS_PW_RECORDS_MAX 256

/*
 * the unauthenticated-conversation cap: S3_OK admits the request and
 * takes one slot, S3_BUSY refuses when the count sits at the limit;
 * the release gives the slot back, releasing more than acquired
 * clamps at zero.  The wiring takes the slot right after the
 * version/early-data gates and releases it unconditionally once the
 * verdict status is out - the slot never survives a successful
 * authentication (the reference F-03)
 */

s3_int_t s3_dos_unauth_try_acquire(void);
void     s3_dos_unauth_release(void);

/* the live counter and the cap, for the refusal log and the tests */

unsigned s3_dos_unauth_count(void);
unsigned s3_dos_unauth_limit(void);
void     s3_dos_unauth_set_limit(unsigned max_conversations);

/*
 * the password brute-force lockout of one account: s3_dos_pw_locked
 * answers 1 while the account sits in the lockout window (an expired
 * window clears the record lazily), s3_dos_pw_failure books one
 * failed verdict - the Nth starts the lockout for the duration, a
 * failure arriving during an active lockout leaves the window alone
 * (the attempt never reached the backend) - and s3_dos_pw_success
 * clears the record.  A name that is empty or over
 * S3_DOS_USER_NAME_MAX is never tracked
 */

s3_int_t s3_dos_pw_locked(const s3_str_t *user, s3_msec_t now);
void     s3_dos_pw_failure(const s3_str_t *user, s3_msec_t now);
void     s3_dos_pw_success(const s3_str_t *user);

/* the lockout knobs, the CLI/env wiring of the daemon */

void s3_dos_pw_set_limits(unsigned max_failures, s3_msec_t lockout_ms);

#endif /* _S3_SSH3_DOS_GUARD_H_INCLUDED_ */
