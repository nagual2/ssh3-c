/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <openssl/rand.h>

#include <s3_quic.h>
#include <s3_quic_connection.h>
#include <s3_quic_migration.h>
#include <s3_quic_frames.h>
#include <s3_quic_output.h>
#include <s3_quic_ack.h>

#include <s3_sock_ntop.h>
#include <s3_errno.h>

static void     s3_quic_set_connection_path(s3_connection_t *c, s3_quic_path_t *path);
static s3_int_t s3_quic_validate_path(s3_connection_t *c, s3_quic_path_t *path);
static s3_int_t s3_quic_send_path_challenge(s3_connection_t *c, s3_quic_path_t *path);
static void     s3_quic_set_path_timer(s3_connection_t *c);
static s3_int_t s3_quic_expire_path_validation(s3_connection_t *c, s3_quic_path_t *path);
static s3_int_t s3_quic_expire_path_mtu_delay(s3_connection_t *c, s3_quic_path_t *path);
static s3_int_t s3_quic_expire_path_mtu_discovery(s3_connection_t *c, s3_quic_path_t *path);
static s3_int_t s3_quic_cmp_sockaddr(struct sockaddr *sa1, socklen_t len1, struct sockaddr *sa2,
                                     socklen_t len2, s3_uint_t flag);
static s3_quic_path_t *s3_quic_get_path(s3_connection_t *c, s3_uint_t tag);
static s3_int_t        s3_quic_send_path_mtu_probe(s3_connection_t *c, s3_quic_path_t *path);

s3_int_t
s3_quic_handle_path_challenge_frame(s3_connection_t *c, s3_quic_header_t *pkt,
                                    s3_quic_path_challenge_frame_t *f)
{
    size_t                min;
    s3_quic_frame_t      *fp;
    s3_quic_connection_t *qc;

    if (pkt->level != S3_QUIC_ENCRYPTION_APPLICATION || pkt->path_challenged) {
        s3_log_debug0(S3_LOG_DEBUG_EVENT, c->log, 0, "quic ignoring PATH_CHALLENGE");
        return S3_OK;
    }

    pkt->path_challenged = 1;

    qc = s3_quic_get_connection(c);

    fp = s3_quic_alloc_frame(c);
    if (fp == NULL) {
        return S3_ERROR;
    }

    fp->level = S3_QUIC_ENCRYPTION_APPLICATION;
    fp->type = S3_QUIC_FT_PATH_RESPONSE;
    fp->u.path_response = *f;

    /*
     * RFC 9000, 8.2.2.  Path Validation Responses
     *
     * A PATH_RESPONSE frame MUST be sent on the network path where the
     * PATH_CHALLENGE frame was received.
     */

    /*
     * An endpoint MUST expand datagrams that contain a PATH_RESPONSE frame
     * to at least the smallest allowed maximum datagram size of 1200 bytes.
     * ...
     * However, an endpoint MUST NOT expand the datagram containing the
     * PATH_RESPONSE if the resulting data exceeds the anti-amplification limit.
     */

    min = (s3_quic_path_limit(c, pkt->path, 1200) < 1200) ? 0 : 1200;

    if (s3_quic_frame_sendto(c, fp, min, pkt->path) == S3_ERROR) {
        return S3_ERROR;
    }

    if (pkt->path == qc->path) {
        /*
         * RFC 9000, 9.3.3.  Off-Path Packet Forwarding
         *
         * An endpoint that receives a PATH_CHALLENGE on an active path SHOULD
         * send a non-probing packet in response.
         */

        fp = s3_quic_alloc_frame(c);
        if (fp == NULL) {
            return S3_ERROR;
        }

        fp->level = S3_QUIC_ENCRYPTION_APPLICATION;
        fp->type = S3_QUIC_FT_PING;

        s3_quic_queue_frame(qc, fp);
    }

    return S3_OK;
}

s3_int_t
s3_quic_handle_path_response_frame(s3_connection_t *c, s3_quic_path_challenge_frame_t *f)
{
    s3_uint_t             rst;
    s3_queue_t           *q;
    s3_quic_path_t       *path, *prev;
    s3_quic_send_ctx_t   *ctx;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    /*
     * RFC 9000, 8.2.3.  Successful Path Validation
     *
     * A PATH_RESPONSE frame received on any network path validates the path
     * on which the PATH_CHALLENGE was sent.
     */

    for (q = s3_queue_head(&qc->paths); q != s3_queue_sentinel(&qc->paths); q = s3_queue_next(q)) {
        path = s3_queue_data(q, s3_quic_path_t, queue);

        if (path->state != S3_QUIC_PATH_VALIDATING) {
            continue;
        }

        if (s3_memcmp(path->challenge[0], f->data, sizeof(f->data)) == 0 ||
            s3_memcmp(path->challenge[1], f->data, sizeof(f->data)) == 0) {
            goto valid;
        }
    }

    s3_log_debug0(S3_LOG_DEBUG_EVENT, c->log, 0, "quic stale PATH_RESPONSE ignored");

    return S3_OK;

valid:

    /*
     * RFC 9000, 9.4.  Loss Detection and Congestion Control
     *
     * On confirming a peer's ownership of its new address,
     * an endpoint MUST immediately reset the congestion controller
     * and round-trip time estimator for the new path to initial values
     * unless the only change in the peer's address is its port number.
     */

    rst = 1;

    prev = s3_quic_get_path(c, S3_QUIC_PATH_BACKUP);

    if (prev != NULL) {

        if (s3_quic_cmp_sockaddr(prev->sockaddr, prev->socklen, path->sockaddr, path->socklen, 0) ==
            S3_OK) {
            /* address did not change */
            rst = 0;

            path->mtu = prev->mtu;
            path->max_mtu = prev->max_mtu;
            path->mtu_unvalidated = 0;
        }
    }

    if (rst) {
        /* prevent old path packets contribution to congestion control */

        ctx = s3_quic_get_send_ctx(qc, S3_QUIC_ENCRYPTION_APPLICATION);
        qc->rst_pnum = ctx->pnum;

        s3_memzero(&qc->congestion, sizeof(s3_quic_congestion_t));

        qc->congestion.window =
            s3_min(10 * S3_QUIC_MIN_INITIAL_SIZE, s3_max(2 * S3_QUIC_MIN_INITIAL_SIZE, 14720));
        qc->congestion.ssthresh = (size_t)-1;
        qc->congestion.mtu = S3_QUIC_MIN_INITIAL_SIZE;
        qc->congestion.recovery_start = s3_current_msec - 1;

        s3_quic_init_rtt(qc);
    }

    path->validated = 1;

    s3_quic_set_connection_path(c, path);

    if (path->mtu_unvalidated) {
        path->mtu_unvalidated = 0;
        return s3_quic_validate_path(c, path);
    }

    /*
     * RFC 9000, 9.3.  Responding to Connection Migration
     *
     *  After verifying a new client address, the server SHOULD
     *  send new address validation tokens (Section 8) to the client;
     * a client never issues address validation tokens
     */

    if (!qc->client && s3_quic_send_new_token(c, path) != S3_OK) {
        return S3_ERROR;
    }

    s3_log_error(S3_LOG_INFO, c->log, 0, "quic path seq:%uL addr:%V successfully validated",
                 path->seqnum, &path->addr_text);

    s3_quic_path_dbg(c, "is validated", path);

    s3_quic_discover_path_mtu(c, path);

    return S3_OK;
}

s3_quic_path_t *
s3_quic_new_path(s3_connection_t *c, struct sockaddr *sockaddr, socklen_t socklen,
                 s3_quic_client_id_t *cid)
{
    s3_queue_t           *q;
    s3_quic_path_t       *path;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    if (!s3_queue_empty(&qc->free_paths)) {

        q = s3_queue_head(&qc->free_paths);
        path = s3_queue_data(q, s3_quic_path_t, queue);

        s3_queue_remove(&path->queue);

        s3_memzero(path, sizeof(s3_quic_path_t));

    } else {

        path = s3_pcalloc(c->pool, sizeof(s3_quic_path_t));
        if (path == NULL) {
            return NULL;
        }
    }

    s3_queue_insert_tail(&qc->paths, &path->queue);

    path->cid = cid;
    cid->used = 1;

    path->seqnum = qc->path_seqnum++;

    if (sockaddr != NULL && socklen > 0 && socklen <= (socklen_t)sizeof(struct sockaddr_storage)) {

        path->sockaddr = (struct sockaddr *)&path->sa;
        path->socklen = socklen;
        s3_memcpy(path->sockaddr, sockaddr, socklen);

        path->addr_text.data = path->text;
        path->addr_text.len = s3_sock_ntop(sockaddr, socklen, path->text, S3_SOCKADDR_STRLEN, 1);
    }

    path->mtu = S3_QUIC_MIN_INITIAL_SIZE;

    s3_log_debug2(S3_LOG_DEBUG_EVENT, c->log, 0, "quic path seq:%uL created addr:%V", path->seqnum,
                  &path->addr_text);

    return path;
}

static s3_quic_path_t *
s3_quic_get_path(s3_connection_t *c, s3_uint_t tag)
{
    s3_queue_t           *q;
    s3_quic_path_t       *path;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    for (q = s3_queue_head(&qc->paths); q != s3_queue_sentinel(&qc->paths); q = s3_queue_next(q)) {
        path = s3_queue_data(q, s3_quic_path_t, queue);

        if (path->tag == tag) {
            return path;
        }
    }

    return NULL;
}

s3_int_t
s3_quic_set_path(s3_connection_t *c, s3_quic_header_t *pkt)
{
    off_t                 len;
    s3_queue_t           *q;
    s3_quic_path_t       *path, *probe;
    s3_quic_socket_t     *qsock;
    s3_quic_send_ctx_t   *ctx;
    s3_quic_client_id_t  *cid;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);
    qsock = s3_quic_get_socket(c);

    len = pkt->raw->last - pkt->raw->start;

    /*
     * the reference tells the first ever packet by the missing staged
     * datagram in c->udp->buffer; in ssh3-c the buffer is consumed by
     * the recv handler, while the per-datagram peer address is not:
     * it is only set by the listener delivery (s3_quic_deliver()),
     * so the zero length marks the first datagram
     */
    if (qsock->socklen == 0) {
        /* first ever packet in connection, path already exists  */
        path = qc->path;
        goto update;
    }

    probe = NULL;

    for (q = s3_queue_head(&qc->paths); q != s3_queue_sentinel(&qc->paths); q = s3_queue_next(q)) {
        path = s3_queue_data(q, s3_quic_path_t, queue);

        if (s3_quic_cmp_sockaddr((struct sockaddr *)&qsock->sockaddr, qsock->socklen,
                                 path->sockaddr, path->socklen, 1) == S3_OK) {
            goto update;
        }

        if (path->tag == S3_QUIC_PATH_PROBE) {
            probe = path;
        }
    }

    /* packet from new path, drop current probe, if any */

    ctx = s3_quic_get_send_ctx(qc, pkt->level);

    /*
     * only accept highest-numbered packets to prevent connection id
     * exhaustion by excessive probing packets from unknown paths
     */
    if (pkt->pn != ctx->largest_pn) {
        /*
         * stop processing of this datagram; the reference returns
         * NGX_DONE here, the ssh3-c marker is S3_ABORT
         * (see s3_quic_negotiate_version())
         */
        return S3_ABORT;
    }

    if (probe && s3_quic_free_path(c, probe) != S3_OK) {
        return S3_ERROR;
    }

    /* new path requires new client id */
    cid = s3_quic_next_client_id(c);
    if (cid == NULL) {
        s3_log_error(S3_LOG_INFO, c->log, 0, "quic no available client ids for new path");
        /* stop processing of this datagram */
        return S3_ABORT;
    }

    path = s3_quic_new_path(c, (struct sockaddr *)&qsock->sockaddr, qsock->socklen, cid);
    if (path == NULL) {
        return S3_ERROR;
    }

    path->tag = S3_QUIC_PATH_PROBE;

    /*
     * client arrived using new path and previously seen DCID,
     * this indicates NAT rebinding (or bad client)
     */
    if (qsock->used) {
        pkt->rebound = 1;
    }

update:

    qsock->used = 1;
    pkt->path = path;

    /* TODO: this may be too late in some cases;
     *       for example, if error happens during decrypt(), we cannot
     *       send CC, if error happens in 1st packet, due to amplification
     *       limit, because path->received = 0
     *
     *       should we account garbage as received or only decrypting packets?
     */
    path->received += len;

    s3_log_debug3(S3_LOG_DEBUG_EVENT, c->log, 0, "quic packet len:%L via sock seq:%L path seq:%uL",
                  (int64_t)len, (int64_t)qsock->sid.seqnum, path->seqnum);
    s3_quic_path_dbg(c, "status", path);

    return S3_OK;
}

s3_int_t
s3_quic_free_path(s3_connection_t *c, s3_quic_path_t *path)
{
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    s3_queue_remove(&path->queue);
    s3_queue_insert_head(&qc->free_paths, &path->queue);

    /*
     * invalidate CID that is no longer usable for any other path;
     * this also requests new CIDs from client
     */
    if (path->cid) {
        if (s3_quic_free_client_id(c, path->cid) != S3_OK) {
            return S3_ERROR;
        }
    }

    s3_log_debug2(S3_LOG_DEBUG_EVENT, c->log, 0, "quic path seq:%uL addr:%V retired", path->seqnum,
                  &path->addr_text);

    return S3_OK;
}

static void
s3_quic_set_connection_path(s3_connection_t *c, s3_quic_path_t *path)
{
    void *sa;

    /*
     * the nginx c->addr_text and c->listening->addr_text_max_len do not
     * exist; the address text lives in the path only; the accepted
     * sockaddr may be smaller than a migrated one, it is reallocated
     */
    if (path->socklen > c->socklen) {
        sa = s3_palloc(c->pool, path->socklen);
        if (sa == NULL) {
            /* keep the current connection address, the output layer
             * uses path->sockaddr anyway */
            goto done;
        }

        c->sockaddr = sa;
    }

    c->socklen = path->socklen;
    s3_memcpy(c->sockaddr, path->sockaddr, path->socklen);

done:

    s3_log_debug2(S3_LOG_DEBUG_EVENT, c->log, 0, "quic send path set to seq:%uL addr:%V",
                  path->seqnum, &path->addr_text);
}

s3_int_t
s3_quic_handle_migration(s3_connection_t *c, s3_quic_header_t *pkt)
{
    s3_quic_path_t       *next, *bkp;
    s3_quic_send_ctx_t   *ctx;
    s3_quic_connection_t *qc;

    /* got non-probing packet via non-active path */

    qc = s3_quic_get_connection(c);

    if (qc->client) {
        /*
         * the reference runs a server only; a migration of the peer
         * (the server side) towards the client is out of scope, the
         * client keeps sending to its validated path
         */
        s3_log_debug0(S3_LOG_DEBUG_EVENT, c->log, 0, "quic client ignores peer migration");
        return S3_OK;
    }

    ctx = s3_quic_get_send_ctx(qc, pkt->level);

    /*
     * RFC 9000, 9.3.  Responding to Connection Migration
     *
     * An endpoint only changes the address to which it sends packets in
     * response to the highest-numbered non-probing packet.
     */
    if (pkt->pn != ctx->largest_pn) {
        return S3_OK;
    }

    next = pkt->path;

    /*
     * RFC 9000, 9.3.3:
     *
     * In response to an apparent migration, endpoints MUST validate the
     * previously active path using a PATH_CHALLENGE frame.
     */
    if (pkt->rebound) {

        /* NAT rebinding: client uses new path with old SID */
        if (s3_quic_validate_path(c, qc->path) != S3_OK) {
            return S3_ERROR;
        }
    }

    if (qc->path->validated) {

        if (next->tag != S3_QUIC_PATH_BACKUP) {
            /* can delete backup path, if any */
            bkp = s3_quic_get_path(c, S3_QUIC_PATH_BACKUP);

            if (bkp && s3_quic_free_path(c, bkp) != S3_OK) {
                return S3_ERROR;
            }
        }

        qc->path->tag = S3_QUIC_PATH_BACKUP;
        s3_quic_path_dbg(c, "is now backup", qc->path);

    } else {
        if (s3_quic_free_path(c, qc->path) != S3_OK) {
            return S3_ERROR;
        }
    }

    /* switch active path to migrated */
    qc->path = next;
    qc->path->tag = S3_QUIC_PATH_ACTIVE;

    if (next->validated) {
        s3_quic_set_connection_path(c, next);

    } else if (next->state != S3_QUIC_PATH_VALIDATING) {
        if (s3_quic_validate_path(c, next) != S3_OK) {
            return S3_ERROR;
        }
    }

    s3_log_error(S3_LOG_INFO, c->log, 0, "quic migrated to path seq:%uL addr:%V", qc->path->seqnum,
                 &qc->path->addr_text);

    s3_quic_path_dbg(c, "is now active", qc->path);

    return S3_OK;
}

static s3_int_t
s3_quic_validate_path(s3_connection_t *c, s3_quic_path_t *path)
{
    s3_msec_t             pto;
    s3_quic_send_ctx_t   *ctx;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "quic initiated validation of path seq:%uL",
                  path->seqnum);

    path->tries = 0;

    if (RAND_bytes((u_char *)path->challenge, sizeof(path->challenge)) != 1) {
        return S3_ERROR;
    }

    (void)s3_quic_send_path_challenge(c, path);

    ctx = s3_quic_get_send_ctx(qc, S3_QUIC_ENCRYPTION_APPLICATION);
    pto = s3_max(s3_quic_pto(c, ctx), 1000);

    path->expires = s3_current_msec + pto;
    path->state = S3_QUIC_PATH_VALIDATING;

    s3_quic_set_path_timer(c);

    return S3_OK;
}

static s3_int_t
s3_quic_send_path_challenge(s3_connection_t *c, s3_quic_path_t *path)
{
    size_t           min;
    s3_uint_t        n;
    s3_quic_frame_t *frame;

    s3_log_debug2(S3_LOG_DEBUG_EVENT, c->log, 0, "quic path seq:%uL send path_challenge tries:%ui",
                  path->seqnum, path->tries);

    for (n = 0; n < 2; n++) {

        frame = s3_quic_alloc_frame(c);
        if (frame == NULL) {
            return S3_ERROR;
        }

        frame->level = S3_QUIC_ENCRYPTION_APPLICATION;
        frame->type = S3_QUIC_FT_PATH_CHALLENGE;

        s3_memcpy(frame->u.path_challenge.data, path->challenge[n], 8);

        /*
         * RFC 9000, 8.2.1.  Initiating Path Validation
         *
         * An endpoint MUST expand datagrams that contain a PATH_CHALLENGE frame
         * to at least the smallest allowed maximum datagram size of 1200 bytes,
         * unless the anti-amplification limit for the path does not permit
         * sending a datagram of this size.
         */

        if (path->mtu_unvalidated || s3_quic_path_limit(c, path, 1200) < 1200) {
            min = 0;
            path->mtu_unvalidated = 1;

        } else {
            min = 1200;
        }

        if (s3_quic_frame_sendto(c, frame, min, path) == S3_ERROR) {
            return S3_ERROR;
        }
    }

    return S3_OK;
}

void
s3_quic_discover_path_mtu(s3_connection_t *c, s3_quic_path_t *path)
{
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    if (path->max_mtu) {
        if (path->max_mtu - path->mtu <= S3_QUIC_PATH_MTU_PRECISION) {
            path->state = S3_QUIC_PATH_IDLE;
            s3_quic_set_path_timer(c);
            return;
        }

        path->mtud = (path->mtu + path->max_mtu) / 2;

    } else {
        path->mtud = path->mtu * 2;

        if (path->mtud >= qc->ctp.max_udp_payload_size) {
            path->mtud = qc->ctp.max_udp_payload_size;
            path->max_mtu = qc->ctp.max_udp_payload_size;
        }
    }

    path->state = S3_QUIC_PATH_WAITING;
    path->expires = s3_current_msec + S3_QUIC_PATH_MTU_DELAY;

    s3_log_debug2(S3_LOG_DEBUG_EVENT, c->log, 0, "quic path seq:%uL schedule mtu:%uz", path->seqnum,
                  path->mtud);

    s3_quic_set_path_timer(c);
}

static void
s3_quic_set_path_timer(s3_connection_t *c)
{
    s3_msec_t             now;
    s3_queue_t           *q;
    s3_msec_int_t         left, next;
    s3_quic_path_t       *path;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    now = s3_current_msec;
    next = -1;

    for (q = s3_queue_head(&qc->paths); q != s3_queue_sentinel(&qc->paths); q = s3_queue_next(q)) {
        path = s3_queue_data(q, s3_quic_path_t, queue);

        if (path->state == S3_QUIC_PATH_IDLE) {
            continue;
        }

        left = path->expires - now;
        left = s3_max(left, 1);

        if (next == -1 || left < next) {
            next = left;
        }
    }

    if (next != -1) {
        s3_event_add_timer(&qc->path_validation, next);

    } else if (qc->path_validation.timer_set) {
        s3_event_del_timer(&qc->path_validation);
    }
}

void
s3_quic_path_handler(s3_event_t *ev)
{
    s3_msec_t             now;
    s3_queue_t           *q;
    s3_msec_int_t         left;
    s3_quic_path_t       *path;
    s3_connection_t      *c;
    s3_quic_connection_t *qc;

    c = ev->data;
    qc = s3_quic_get_connection(c);

    now = s3_current_msec;

    q = s3_queue_head(&qc->paths);

    while (q != s3_queue_sentinel(&qc->paths)) {

        path = s3_queue_data(q, s3_quic_path_t, queue);
        q = s3_queue_next(q);

        if (path->state == S3_QUIC_PATH_IDLE) {
            continue;
        }

        left = path->expires - now;

        if (left > 0) {
            continue;
        }

        switch (path->state) {
        case S3_QUIC_PATH_VALIDATING:
            if (s3_quic_expire_path_validation(c, path) != S3_OK) {
                goto failed;
            }

            break;

        case S3_QUIC_PATH_WAITING:
            if (s3_quic_expire_path_mtu_delay(c, path) != S3_OK) {
                goto failed;
            }

            break;

        case S3_QUIC_PATH_MTUD:
            if (s3_quic_expire_path_mtu_discovery(c, path) != S3_OK) {
                goto failed;
            }

            break;

        default:
            break;
        }
    }

    s3_quic_set_path_timer(c);

    return;

failed:

    s3_quic_close_connection(c, S3_ERROR);
}

static s3_int_t
s3_quic_expire_path_validation(s3_connection_t *c, s3_quic_path_t *path)
{
    s3_msec_int_t         pto;
    s3_quic_path_t       *bkp;
    s3_quic_send_ctx_t   *ctx;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);
    ctx = s3_quic_get_send_ctx(qc, S3_QUIC_ENCRYPTION_APPLICATION);

    if (++path->tries < S3_QUIC_PATH_RETRIES) {
        pto = s3_max(s3_quic_pto(c, ctx), 1000) << path->tries;
        path->expires = s3_current_msec + pto;

        (void)s3_quic_send_path_challenge(c, path);

        return S3_OK;
    }

    s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "quic path seq:%uL validation failed",
                  path->seqnum);

    /* found expired path */

    path->validated = 0;

    /* RFC 9000, 9.3.2.  On-Path Address Spoofing
     *
     * To protect the connection from failing due to such a spurious
     * migration, an endpoint MUST revert to using the last validated
     * peer address when validation of a new peer address fails.
     */

    if (qc->path == path) {
        /* active path validation failed */

        bkp = s3_quic_get_path(c, S3_QUIC_PATH_BACKUP);

        if (bkp == NULL) {
            qc->error = S3_QUIC_ERR_NO_VIABLE_PATH;
            qc->error_reason = "no viable path";
            return S3_ERROR;
        }

        qc->path = bkp;
        qc->path->tag = S3_QUIC_PATH_ACTIVE;

        s3_log_error(S3_LOG_INFO, c->log, 0, "quic path seq:%uL addr:%V is restored from backup",
                     qc->path->seqnum, &qc->path->addr_text);

        s3_quic_path_dbg(c, "is active", qc->path);
    }

    return s3_quic_free_path(c, path);
}

static s3_int_t
s3_quic_expire_path_mtu_delay(s3_connection_t *c, s3_quic_path_t *path)
{
    s3_int_t              rc;
    s3_uint_t             i;
    s3_msec_t             pto;
    s3_quic_send_ctx_t   *ctx;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);
    ctx = s3_quic_get_send_ctx(qc, S3_QUIC_ENCRYPTION_APPLICATION);

    path->tries = 0;

    for (;;) {

        for (i = 0; i < S3_QUIC_PATH_RETRIES; i++) {
            path->mtu_pnum[i] = S3_QUIC_UNSET_PN;
        }

        rc = s3_quic_send_path_mtu_probe(c, path);

        if (rc == S3_ERROR) {
            return S3_ERROR;
        }

        if (rc == S3_OK) {
            pto = s3_quic_pto(c, ctx);
            path->expires = s3_current_msec + pto;
            path->state = S3_QUIC_PATH_MTUD;
            return S3_OK;
        }

        /* rc == S3_DECLINED */

        path->max_mtu = path->mtud;

        if (path->max_mtu - path->mtu <= S3_QUIC_PATH_MTU_PRECISION) {
            path->state = S3_QUIC_PATH_IDLE;
            return S3_OK;
        }

        path->mtud = (path->mtu + path->max_mtu) / 2;
    }
}

static s3_int_t
s3_quic_expire_path_mtu_discovery(s3_connection_t *c, s3_quic_path_t *path)
{
    s3_int_t              rc;
    s3_msec_int_t         pto;
    s3_quic_send_ctx_t   *ctx;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);
    ctx = s3_quic_get_send_ctx(qc, S3_QUIC_ENCRYPTION_APPLICATION);

    if (++path->tries < S3_QUIC_PATH_RETRIES) {
        rc = s3_quic_send_path_mtu_probe(c, path);

        if (rc == S3_ERROR) {
            return S3_ERROR;
        }

        if (rc == S3_OK) {
            pto = s3_quic_pto(c, ctx) << path->tries;
            path->expires = s3_current_msec + pto;
            return S3_OK;
        }

        /* rc == S3_DECLINED */
    }

    s3_log_debug2(S3_LOG_DEBUG_EVENT, c->log, 0, "quic path seq:%uL expired mtu:%uz", path->seqnum,
                  path->mtud);

    path->max_mtu = path->mtud;

    s3_quic_discover_path_mtu(c, path);

    return S3_OK;
}

static s3_int_t
s3_quic_send_path_mtu_probe(s3_connection_t *c, s3_quic_path_t *path)
{
    size_t                mtu;
    uint64_t              pnum;
    s3_int_t              rc;
    s3_quic_frame_t      *frame;
    s3_quic_send_ctx_t   *ctx;
    s3_quic_connection_t *qc;

    frame = s3_quic_alloc_frame(c);
    if (frame == NULL) {
        return S3_ERROR;
    }

    frame->level = S3_QUIC_ENCRYPTION_APPLICATION;
    frame->type = S3_QUIC_FT_PING;
    frame->ignore_loss = 1;
    frame->ignore_congestion = 1;

    qc = s3_quic_get_connection(c);
    ctx = s3_quic_get_send_ctx(qc, S3_QUIC_ENCRYPTION_APPLICATION);
    pnum = ctx->pnum;

    s3_log_debug4(S3_LOG_DEBUG_EVENT, c->log, 0,
                  "quic path seq:%uL send probe mtu:%uz pnum:%uL tries:%ui", path->seqnum,
                  path->mtud, ctx->pnum, path->tries);

    mtu = path->mtu;
    path->mtu = path->mtud;

    rc = s3_quic_frame_sendto(c, frame, path->mtud, path);

    path->mtu = mtu;

    if (rc == S3_OK) {
        path->mtu_pnum[path->tries] = pnum;
        return S3_OK;
    }

    s3_log_debug2(S3_LOG_DEBUG_EVENT, c->log, 0, "quic path seq:%uL rejected mtu:%uz", path->seqnum,
                  path->mtud);

    if (rc < 0) {
        /*
         * the reference tells the EMSGSIZE rejection by the
         * c->write->error flag set in its send path (with c->log_error
         * quieting the log); s3_quic_send() does not set the flag and
         * the log level is fixed, the socket errno is read instead -
         * the error returns straight from sendmsg, nothing clobbers
         * errno on the way out of s3_quic_frame_sendto()
         */
        if (s3_socket_errno == S3_EMSGSIZE) {
            return S3_DECLINED;
        }

        return S3_ERROR;
    }

    return S3_OK;
}

s3_int_t
s3_quic_handle_path_mtu(s3_connection_t *c, s3_quic_path_t *path, uint64_t min, uint64_t max)
{
    uint64_t  pnum;
    s3_uint_t i;

    if (path->state != S3_QUIC_PATH_MTUD) {
        return S3_OK;
    }

    for (i = 0; i < S3_QUIC_PATH_RETRIES; i++) {
        pnum = path->mtu_pnum[i];

        if (pnum == S3_QUIC_UNSET_PN) {
            continue;
        }

        if (pnum < min || pnum > max) {
            continue;
        }

        path->mtu = path->mtud;

        s3_log_debug2(S3_LOG_DEBUG_EVENT, c->log, 0, "quic path seq:%uL ack mtu:%uz", path->seqnum,
                      path->mtu);

        s3_quic_discover_path_mtu(c, path);

        break;
    }

    return S3_OK;
}

static s3_int_t
s3_quic_cmp_sockaddr(struct sockaddr *sa1, socklen_t len1, struct sockaddr *sa2, socklen_t len2,
                     s3_uint_t flag)
{
    struct sockaddr_in  *sin1, *sin2;
    struct sockaddr_in6 *sin61, *sin62;

    if (sa1 == NULL || sa2 == NULL || len1 != len2) {
        return S3_DECLINED;
    }

    if (sa1->sa_family != sa2->sa_family) {
        return S3_DECLINED;
    }

    switch (sa1->sa_family) {

    case AF_INET:

        sin1 = (struct sockaddr_in *)sa1;
        sin2 = (struct sockaddr_in *)sa2;

        if (sin1->sin_addr.s_addr != sin2->sin_addr.s_addr) {
            return S3_DECLINED;
        }

        if (flag && sin1->sin_port != sin2->sin_port) {
            return S3_DECLINED;
        }

        return S3_OK;

    case AF_INET6:

        sin61 = (struct sockaddr_in6 *)sa1;
        sin62 = (struct sockaddr_in6 *)sa2;

        if (s3_memcmp(&sin61->sin6_addr, &sin62->sin6_addr, sizeof(struct in6_addr)) != 0) {
            return S3_DECLINED;
        }

        if (flag && sin61->sin6_port != sin62->sin6_port) {
            return S3_DECLINED;
        }

        return S3_OK;

    default:

        /* the unknown families are compared byte-wise */
        return s3_memcmp(sa1, sa2, len1) == 0 ? S3_OK : S3_DECLINED;
    }
}
