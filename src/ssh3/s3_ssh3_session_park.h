/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_SSH3_SESSION_PARK_H_INCLUDED_
#define _S3_SSH3_SESSION_PARK_H_INCLUDED_

#include <s3_core.h>
#include <s3_ssh3_session_srv.h>

/*
 * the server-side parking lot of interactive sessions (the wave 16):
 * when the QUIC connection dies mid-session, the pty child does not
 * have to die with it - the lot detaches the session from its
 * channel, drains the output into a bounded ring and holds the child
 * for the re-attach of the next authenticated dial of the same user
 * carrying the same session token.  The expired records are killed
 * and reaped (the lazy sweep of the dos-guard shape), the table is
 * bounded (the oldest eviction).
 *
 * the ownership: park_add() moves sess_pool+sess into the lot, the
 * take() hands them back to the attaching channel, the kill() ends
 * the record (the expiry, the cap eviction, the teardown sweep)
 */

#define S3_SSH3_PARK_TOKEN_LEN 32 /* the hex of the 16-byte client token */
#define S3_SSH3_PARK_RING_SIZE (32 * 1024)

typedef struct s3_ssh3_session_park_s s3_ssh3_session_park_t;

/*
 * the knob setup: max = 0 disables the lot (the strict openssh
 * compat, the teardown kills the child as before); lifetime_sec is
 * the parked-child grace window
 */

void s3_ssh3_session_park_setup(unsigned max, unsigned lifetime_sec);

unsigned s3_ssh3_session_park_count(void);

/*
 * moves the session into the lot: the record takes over the pool and
 * the session pointers, arms the parked drain (the pty master keeps
 * feeding the ring - the shell would block on a full pty otherwise)
 * and returns it; NULL when the lot is disabled, full (the oldest is
 * evicted only for the fresh entries) or the arguments are broken
 */

s3_ssh3_session_park_t *s3_ssh3_session_park_add(s3_pool_t *watch_pool, s3_log_t *log,
                                                 s3_pool_t *sess_pool, s3_ssh3_session_srv_t *sess,
                                                 const char *user, const char *token,
                                                 const char *agent_path, s3_uint_t compress_alg,
                                                 time_t now);

/*
 * the lookup with the lazy expiry sweep of the whole lot; NULL when
 * the user or the token does not match or the record expired
 */

s3_ssh3_session_park_t *s3_ssh3_session_park_find(const char *user, const char *token, time_t now);

/*
 * hands the ownership back to the attaching channel: the record
 * leaves the lot, the pool/sess pointers ride the out parameters,
 * the ring stays readable until the take (the replay rides before
 * the take through ring_take)
 */

void s3_ssh3_session_park_take(s3_ssh3_session_park_t *p, s3_pool_t **sess_pool,
                               s3_ssh3_session_srv_t **sess, char *agent_path, size_t agent_cap,
                               s3_uint_t *compress_alg);

/*
 * the parked output: one drain pass of the pty master (and the
 * stderr pipe) into the ring, the drop-oldest on the full ring; the
 * production pump callback wraps this, the units call it by hand
 */

void s3_ssh3_session_park_drain(s3_ssh3_session_park_t *p);

/*
 * the replay read: up to cap bytes of the ring from the head, the
 * consumed part leaves the ring
 */

size_t s3_ssh3_session_park_ring_take(s3_ssh3_session_park_t *p, u_char *out, size_t cap);

/*
 * the pool the record owns (the sess pool): the re-attach replay
 * buffer rides it - the pool lives until the attached channel ends
 */

s3_pool_t *s3_ssh3_session_park_pool(s3_ssh3_session_park_t *p);

/* the kill+reap+free of one record (the expiry, the eviction) */

void s3_ssh3_session_park_kill(s3_ssh3_session_park_t *p);

/* the lazy sweep of the whole lot at the given moment */

void s3_ssh3_session_park_sweep(time_t now);

/* the teardown sweep: every parked child dies (the daemon exit) */

void s3_ssh3_session_park_teardown(void);

#endif /* _S3_SSH3_SESSION_PARK_H_INCLUDED_ */
