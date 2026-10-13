/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <s3_core.h>

/*
 * the win32 iocp event module, the port of ngx_iocp_module over the
 * s3_event_actions_t contract (S3_USE_IOCP): every event socket is
 * associated with one completion port, the loop waits with a single
 * GetQueuedCompletionStatus() per iteration and runs the handlers
 * inline, the completions are never posted
 *
 * deviations from the reference:
 *
 *   - the nginx timer thread is not ported: GetQueuedCompletionStatus()
 *     takes the timer wait directly, like the select module timeout,
 *     the timers are expired by the common s3_process_events_and_timers()
 *     tail
 *
 *   - the io completions carry one key (S3_IOCP_IO): the port has no
 *     AcceptEx/ConnectEx, so the ACCEPT/CONNECT keys do not exist
 *
 *   - the overlapped path is receive-only: the sends stay synchronous
 *     under both backends (s3_udp_sendmsg_chain), the udp receive is
 *     armed by the s3_event_recvmsg() seam through s3_udp_recvmsg_o()
 */

/* the io completion key, the only one this module posts and associates */
#define S3_IOCP_IO 1

static s3_int_t s3_iocp_init(s3_event_ctx_t *ctx);
static void     s3_iocp_done(s3_event_ctx_t *ctx);
static s3_int_t s3_iocp_add_event(s3_event_t *ev, s3_int_t event, s3_uint_t flags);
static s3_int_t s3_iocp_del_event(s3_event_t *ev, s3_int_t event, s3_uint_t flags);
static s3_int_t s3_iocp_add_connection(s3_event_ctx_t *ctx, s3_connection_t *c);
static s3_int_t s3_iocp_del_connection(s3_event_ctx_t *ctx, s3_connection_t *c);
static s3_int_t s3_iocp_process_events(s3_event_ctx_t *ctx, s3_msec_t timer, s3_uint_t flags);

static HANDLE iocp;

s3_event_actions_t s3_event_actions = {
    s3_iocp_init,           s3_iocp_add_event,      s3_iocp_del_event, s3_iocp_add_connection,
    s3_iocp_del_connection, s3_iocp_process_events, s3_iocp_done,
};

static s3_int_t
s3_iocp_init(s3_event_ctx_t *ctx)
{
    /*
     * the re-init reuses the port, like the select module reuses the
     * interest sets; the concurrent threads count 0 means the default,
     * the loop is single-threaded anyway
     */

    if (iocp == NULL) {
        iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    }

    if (iocp == NULL) {
        s3_log_error(S3_LOG_ALERT, ctx->log, s3_errno, "CreateIoCompletionPort() failed");
        return S3_ERROR;
    }

    s3_event_flags = S3_USE_IOCP_EVENT;

    ctx->impl = &iocp;

    return S3_OK;
}

/*
 * the exit counterpart of init(): the port is a process global here,
 * one context owns it by construction (the second ctx_init() reuses
 * it); the owners close their sockets first, the completions of the
 * aborted operations die with the port
 */

static void
s3_iocp_done(s3_event_ctx_t *ctx)
{
    if (iocp != NULL) {
        if (CloseHandle(iocp) == 0) {
            s3_log_error(S3_LOG_ALERT, ctx->log, s3_errno, "iocp CloseHandle() failed");
        }

        iocp = NULL;
    }
}

static s3_int_t
s3_iocp_add_event(s3_event_t *ev, s3_int_t event, s3_uint_t flags)
{
    s3_connection_t *c;

    (void)flags;

    c = (s3_connection_t *)ev->data;

    /* the association is per socket, both events of the socket ride it */

    c->read->active = 1;
    c->write->active = 1;

    if (CreateIoCompletionPort((HANDLE)c->fd, iocp, (ULONG_PTR)S3_IOCP_IO, 0) == NULL) {
        s3_log_error(S3_LOG_ALERT, ev->log, s3_errno, "CreateIoCompletionPort() failed");
        return S3_ERROR;
    }

    if (event == S3_READ_EVENT) {

        /*
         * the synthetic first completion: the seam is entered once and
         * arms the first overlapped receive; the kick carries no bytes,
         * the seam treats it as a post request, not as a datagram
         */

        s3_memzero(&ev->ovlp, sizeof(s3_event_ovlp_t));
        ev->ovlp.event = ev;

        if (PostQueuedCompletionStatus(iocp, 0, (ULONG_PTR)S3_IOCP_IO, &ev->ovlp.ovlp) == 0) {
            s3_log_error(S3_LOG_ALERT, ev->log, s3_errno, "PostQueuedCompletionStatus() failed");
            return S3_ERROR;
        }
    }

    return S3_OK;
}

static s3_int_t
s3_iocp_del_event(s3_event_t *ev, s3_int_t event, s3_uint_t flags)
{
    /*
     * there is nothing to remove: the association is per socket and
     * dies with the descriptor, the in-flight operation completes with
     * ERROR_OPERATION_ABORTED and is skipped by process_events()
     */

    (void)ev;
    (void)event;
    (void)flags;

    return S3_OK;
}

static s3_int_t
s3_iocp_add_connection(s3_event_ctx_t *ctx, s3_connection_t *c)
{
    /* the association happens in add_event() */

    (void)ctx;
    (void)c;

    return S3_OK;
}

static s3_int_t
s3_iocp_del_connection(s3_event_ctx_t *ctx, s3_connection_t *c)
{
    /*
     * like the reference: no CancelIo(), the closing descriptor aborts
     * the in-flight operations and the completions are skipped
     */

    (void)ctx;
    (void)c;

    return S3_OK;
}

static s3_int_t
s3_iocp_process_events(s3_event_ctx_t *ctx, s3_msec_t timer, s3_uint_t flags)
{
    int              rc;
    u_long           bytes;
    ULONG_PTR        key;
    s3_err_t         err;
    s3_event_t      *ev;
    s3_event_ovlp_t *ovlp;

    if (timer == S3_TIMER_INFINITE) {
        timer = INFINITE;
    }

    rc = GetQueuedCompletionStatus(iocp, &bytes, &key, (LPOVERLAPPED *)&ovlp, (DWORD)timer);

    err = (rc == 0) ? s3_errno : 0;

    if (flags & S3_UPDATE_TIME) {
        s3_time_update();
    }

    if (err != 0 && ovlp == NULL) {

        /* the wait itself failed or timed out, no operation to deliver */

        if (err == WAIT_TIMEOUT) {
            return S3_OK;
        }

        s3_log_error(S3_LOG_ALERT, ctx->log, err, "GetQueuedCompletionStatus() failed");

        return S3_ERROR;
    }

    if (ovlp == NULL) {
        s3_log_error(S3_LOG_ALERT, ctx->log, 0,
                     "GetQueuedCompletionStatus() returned no operation");

        return S3_ERROR;
    }

    if (err != 0) {
        ovlp->error = err;
    }

    ev = ovlp->event;

    if (err == ERROR_NETNAME_DELETED /* the socket was closed */
        || err == ERROR_OPERATION_ABORTED /* the operation was canceled */) {
        /* the completion of an operation on a closed descriptor */

        return S3_OK;
    }

    if (err != 0) {
        s3_log_error(S3_LOG_ALERT, ctx->log, err,
                     "GetQueuedCompletionStatus() returned operation error");
    }

    /* the io completion key, the only one: no AcceptEx/ConnectEx here */

    ev->complete = 1;
    ev->ready = 1;
    ev->available = (ssize_t)bytes;

    ev->handler(ev);

    return S3_OK;
}
