/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <s3_quic.h>
#include <s3_quic_connection.h>
#include <s3_quic_output.h>
#include <s3_quic_ack.h>
#include <s3_quic_frames.h>
#include <s3_quic_migration.h>
#include <s3_quic_streams.h>

#define S3_QUIC_MAX_ACK_GAP 2

/* RFC 9002, 6.1.1. Packet Threshold: kPacketThreshold */
#define S3_QUIC_PKT_THR 3 /* packets */

/* RFC 9002, 6.1.2. Time Threshold: kGranularity */
#define S3_QUIC_TIME_GRANULARITY 1 /* ms */

/* RFC 9002, 7.6.1. Duration: kPersistentCongestionThreshold */
#define S3_QUIC_PERSISTENT_CONGESTION_THR 3

/* CUBIC parameters x10 */
#define S3_QUIC_CUBIC_BETA 7
#define S3_QUIC_CUBIC_C    4

#define S3_QUIC_MAX_SIZE_T ((size_t) - 1)

/* send time of ACK'ed packets */
typedef struct {
    s3_msec_t max_pn;
    s3_msec_t oldest;
    s3_msec_t newest;
} s3_quic_ack_stat_t;

static inline s3_msec_t s3_quic_time_threshold(s3_quic_connection_t *qc);
static uint64_t         s3_quic_packet_threshold(s3_quic_send_ctx_t *ctx);
static void      s3_quic_rtt_sample(s3_connection_t *c, s3_quic_ack_frame_t *ack, s3_uint_t level,
                                    s3_msec_t send_time);
static s3_int_t  s3_quic_handle_ack_frame_range(s3_connection_t *c, s3_quic_send_ctx_t *ctx,
                                                uint64_t min, uint64_t max, s3_quic_ack_stat_t *st);
static size_t    s3_quic_congestion_cubic(s3_connection_t *c);
static void      s3_quic_drop_ack_ranges(s3_connection_t *c, s3_quic_send_ctx_t *ctx, uint64_t pn);
static s3_int_t  s3_quic_detect_lost(s3_connection_t *c, s3_quic_ack_stat_t *st);
static s3_msec_t s3_quic_congestion_cubic_time(s3_connection_t *c);
static s3_msec_t s3_quic_pcg_duration(s3_connection_t *c);
static void      s3_quic_persistent_congestion(s3_connection_t *c);
static s3_msec_t s3_quic_oldest_sent_packet(s3_connection_t *c);
static void      s3_quic_congestion_lost(s3_connection_t *c, s3_quic_frame_t *frame);
static void      s3_quic_lost_handler(s3_event_t *ev);

/* RFC 9002, 6.1.2. Time Threshold: kTimeThreshold, kGranularity */
static inline s3_msec_t
s3_quic_time_threshold(s3_quic_connection_t *qc)
{
    s3_msec_t thr;

    thr = s3_max(qc->latest_rtt, qc->avg_rtt);
    thr += thr >> 3;

    return s3_max(thr, S3_QUIC_TIME_GRANULARITY);
}

static uint64_t
s3_quic_packet_threshold(s3_quic_send_ctx_t *ctx)
{
    uint64_t         pkt_thr;
    s3_queue_t      *q;
    s3_quic_frame_t *f;

    if (s3_queue_empty(&ctx->sent)) {
        return S3_QUIC_PKT_THR;
    }

    q = s3_queue_head(&ctx->sent);
    f = s3_queue_data(q, s3_quic_frame_t, queue);
    pkt_thr = (ctx->pnum - f->pnum) / 2;

    if (pkt_thr <= S3_QUIC_PKT_THR) {
        return S3_QUIC_PKT_THR;
    }

    return pkt_thr;
}

s3_int_t
s3_quic_handle_ack_frame(s3_connection_t *c, s3_quic_header_t *pkt, s3_quic_frame_t *f)
{
    ssize_t               n;
    u_char               *pos, *end;
    uint64_t              min, max, gap, range;
    s3_uint_t             i;
    s3_quic_ack_stat_t    send_time;
    s3_quic_send_ctx_t   *ctx;
    s3_quic_ack_frame_t  *ack;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    ctx = s3_quic_get_send_ctx(qc, pkt->level);

    s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "quic handle ack frame level:%ui", pkt->level);

    ack = &f->u.ack;

    /*
     * RFC 9000, 19.3.1.  ACK Ranges
     *
     *  If any computed packet number is negative, an endpoint MUST
     *  generate a connection error of type FRAME_ENCODING_ERROR.
     */

    if (ack->first_range > ack->largest) {
        qc->error = S3_QUIC_ERR_FRAME_ENCODING_ERROR;
        s3_log_error(S3_LOG_INFO, c->log, 0, "quic invalid first range in ack frame");
        return S3_ERROR;
    }

    min = ack->largest - ack->first_range;
    max = ack->largest;

    send_time.oldest = S3_TIMER_INFINITE;
    send_time.newest = S3_TIMER_INFINITE;

    if (s3_quic_handle_ack_frame_range(c, ctx, min, max, &send_time) != S3_OK) {
        return S3_ERROR;
    }

    /* RFC 9000, 13.2.4.  Limiting Ranges by Tracking ACK Frames */
    if (ctx->largest_ack < max || ctx->largest_ack == S3_QUIC_UNSET_PN) {
        ctx->largest_ack = max;
        s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "quic updated largest received ack:%uL", max);

        /*
         * RFC 9002, 5.1.  Generating RTT Samples
         *
         *  An endpoint generates an RTT sample on receiving an
         *  ACK frame that meets the following two conditions:
         *
         *  - the largest acknowledged packet number is newly acknowledged
         *  - at least one of the newly acknowledged packets was ack-eliciting.
         */

        if (send_time.max_pn != S3_TIMER_INFINITE) {
            s3_quic_rtt_sample(c, ack, pkt->level, send_time.max_pn);
        }
    }

    if (f->data != NULL) {
        pos = f->data->buf->pos;
        end = f->data->buf->last;

    } else {
        pos = NULL;
        end = NULL;
    }

    for (i = 0; i < ack->range_count; i++) {

        n = s3_quic_parse_ack_range(pkt->log, pos, end, &gap, &range);
        if (n == S3_ERROR) {
            return S3_ERROR;
        }
        pos += n;

        if (gap + 2 > min) {
            qc->error = S3_QUIC_ERR_FRAME_ENCODING_ERROR;
            s3_log_error(S3_LOG_INFO, c->log, 0, "quic invalid range:%ui in ack frame", i);
            return S3_ERROR;
        }

        max = min - gap - 2;

        if (range > max) {
            qc->error = S3_QUIC_ERR_FRAME_ENCODING_ERROR;
            s3_log_error(S3_LOG_INFO, c->log, 0, "quic invalid range:%ui in ack frame", i);
            return S3_ERROR;
        }

        min = max - range;

        if (s3_quic_handle_ack_frame_range(c, ctx, min, max, &send_time) != S3_OK) {
            return S3_ERROR;
        }
    }

    return s3_quic_detect_lost(c, &send_time);
}

static void
s3_quic_rtt_sample(s3_connection_t *c, s3_quic_ack_frame_t *ack, s3_uint_t level,
                   s3_msec_t send_time)
{
    s3_msec_t             latest_rtt, ack_delay, adjusted_rtt, rttvar_sample;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    latest_rtt = s3_current_msec - send_time;
    qc->latest_rtt = latest_rtt;

    if (qc->min_rtt == S3_TIMER_INFINITE) {
        qc->min_rtt = latest_rtt;
        qc->avg_rtt = latest_rtt;
        qc->rttvar = latest_rtt / 2;
        qc->first_rtt = s3_current_msec;

    } else {
        qc->min_rtt = s3_min(qc->min_rtt, latest_rtt);

        ack_delay = (ack->delay << qc->ctp.ack_delay_exponent) / 1000;

        if (level == S3_QUIC_ENCRYPTION_APPLICATION && c->ssl != NULL && c->ssl->handshaked) {
            ack_delay = s3_min(ack_delay, qc->ctp.max_ack_delay);
        }

        adjusted_rtt = latest_rtt;

        if (qc->min_rtt + ack_delay < latest_rtt) {
            adjusted_rtt -= ack_delay;
        }

        rttvar_sample = (s3_msec_t)s3_abs((s3_msec_int_t)(qc->avg_rtt - adjusted_rtt));
        qc->rttvar += (rttvar_sample >> 2) - (qc->rttvar >> 2);
        qc->avg_rtt += (adjusted_rtt >> 3) - (qc->avg_rtt >> 3);
    }

    s3_log_debug4(S3_LOG_DEBUG_EVENT, c->log, 0,
                  "quic rtt sample latest:%uL min:%uL avg:%uL var:%uL", latest_rtt, qc->min_rtt,
                  qc->avg_rtt, qc->rttvar);
}

static s3_int_t
s3_quic_handle_ack_frame_range(s3_connection_t *c, s3_quic_send_ctx_t *ctx, uint64_t min,
                               uint64_t max, s3_quic_ack_stat_t *st)
{
    s3_uint_t             found;
    s3_queue_t           *q;
    s3_quic_frame_t      *f;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    if (ctx->level == S3_QUIC_ENCRYPTION_APPLICATION) {
        if (s3_quic_handle_path_mtu(c, qc->path, min, max) != S3_OK) {
            return S3_ERROR;
        }
    }

    st->max_pn = S3_TIMER_INFINITE;
    found = 0;

    q = s3_queue_head(&ctx->sent);

    while (q != s3_queue_sentinel(&ctx->sent)) {

        f = s3_queue_data(q, s3_quic_frame_t, queue);
        q = s3_queue_next(q);

        if (f->pnum > max) {
            break;
        }

        if (f->pnum >= min) {
            s3_quic_congestion_ack(c, f);

            switch (f->type) {
            case S3_QUIC_FT_ACK:
            case S3_QUIC_FT_ACK_ECN:
                s3_quic_drop_ack_ranges(c, ctx, f->u.ack.largest);
                break;

            case S3_QUIC_FT_STREAM:
            case S3_QUIC_FT_RESET_STREAM:
                s3_quic_handle_stream_ack(c, f);
                break;
            }

            if (f->pnum == max) {
                st->max_pn = f->send_time;
            }

            /* save earliest and latest send times of frames ack'ed */
            if (st->oldest == S3_TIMER_INFINITE || f->send_time < st->oldest) {
                st->oldest = f->send_time;
            }

            if (st->newest == S3_TIMER_INFINITE || f->send_time > st->newest) {
                st->newest = f->send_time;
            }

            s3_queue_remove(&f->queue);
            s3_quic_free_frame(c, f);
            found = 1;
        }
    }

    if (!found) {

        if (max < ctx->pnum) {
            /* duplicate ACK or ACK for non-ack-eliciting frame */
            return S3_OK;
        }

        s3_log_error(S3_LOG_INFO, c->log, 0, "quic ACK for the packet not sent");

        qc->error = S3_QUIC_ERR_PROTOCOL_VIOLATION;
        qc->error_ftype = S3_QUIC_FT_ACK;
        qc->error_reason = "unknown packet number";

        return S3_ERROR;
    }

    if (!qc->push.timer_set) {
        s3_post_event(&qc->push, &qc->ctx->posted_events);
    }

    qc->pto_count = 0;

    return S3_OK;
}

void
s3_quic_congestion_ack(s3_connection_t *c, s3_quic_frame_t *f)
{
    size_t                w_cubic;
    s3_uint_t             blocked;
    s3_msec_t             now, timer;
    s3_quic_congestion_t *cg;
    s3_quic_connection_t *qc;

    if (f->plen == 0) {
        return;
    }

    qc = s3_quic_get_connection(c);
    cg = &qc->congestion;

    if (f->pnum < qc->rst_pnum) {
        return;
    }

    now = s3_current_msec;

    blocked = (cg->in_flight >= cg->window) ? 1 : 0;

    cg->in_flight -= f->plen;

    /* prevent recovery_start from wrapping */

    timer = now - cg->recovery_start;

    if ((s3_msec_int_t)timer < 0) {
        cg->recovery_start = s3_quic_oldest_sent_packet(c) - 1;
    }

    timer = f->send_time - cg->recovery_start;

    if ((s3_msec_int_t)timer <= 0) {
        s3_log_debug3(S3_LOG_DEBUG_EVENT, c->log, 0, "quic congestion ack rec t:%uL win:%uz if:%uz",
                      now, cg->window, cg->in_flight);

        goto done;
    }

    if (cg->idle) {
        s3_log_debug3(S3_LOG_DEBUG_EVENT, c->log, 0,
                      "quic congestion ack idle t:%uL win:%uz if:%uz", now, cg->window,
                      cg->in_flight);

        goto done;
    }

    if (cg->window < cg->ssthresh) {
        cg->window += f->plen;

        s3_log_debug4(S3_LOG_DEBUG_EVENT, c->log, 0,
                      "quic congestion ack ss t:%uL win:%uz ss:%uz if:%uz", now, cg->window,
                      cg->ssthresh, cg->in_flight);

    } else {

        /* RFC 9438, 4.2. Window Increase Function */

        w_cubic = s3_quic_congestion_cubic(c);

        if (cg->window < cg->w_prior) {
            cg->w_est += (uint64_t)cg->mtu * f->plen * 3 * (10 - S3_QUIC_CUBIC_BETA) /
                         (10 + S3_QUIC_CUBIC_BETA) / cg->window;

        } else {
            cg->w_est += (uint64_t)cg->mtu * f->plen / cg->window;
        }

        if (w_cubic < cg->w_est) {
            cg->window = cg->w_est;

            s3_log_debug4(S3_LOG_DEBUG_EVENT, c->log, 0,
                          "quic congestion ack reno t:%uL win:%uz c:%uz if:%uz", now, cg->window,
                          w_cubic, cg->in_flight);

        } else if (w_cubic > cg->window) {

            if (w_cubic >= cg->window * 3 / 2) {
                cg->window += cg->mtu / 2;

            } else {
                cg->window += (uint64_t)cg->mtu * (w_cubic - cg->window) / cg->window;
            }

            s3_log_debug4(S3_LOG_DEBUG_EVENT, c->log, 0,
                          "quic congestion ack cubic t:%uL win:%uz c:%uz if:%uz", now, cg->window,
                          w_cubic, cg->in_flight);

        } else {
            s3_log_debug4(S3_LOG_DEBUG_EVENT, c->log, 0,
                          "quic congestion ack skip t:%uL win:%uz c:%uz if:%uz", now, cg->window,
                          w_cubic, cg->in_flight);
        }
    }

done:

    if (blocked && cg->in_flight < cg->window) {
        s3_post_event(&qc->push, &qc->ctx->posted_events);
    }
}

static size_t
s3_quic_congestion_cubic(s3_connection_t *c)
{
    int64_t               w, t, cc;
    s3_msec_t             now;
    s3_quic_congestion_t *cg;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);
    cg = &qc->congestion;

    s3_quic_congestion_idle(c, cg->idle);

    now = s3_current_msec;
    t = (s3_msec_int_t)(now - cg->k);

    if (t > 1000000) {
        w = (int64_t)S3_QUIC_MAX_SIZE_T;
        goto done;
    }

    if (t < -1000000) {
        w = 0;
        goto done;
    }

    /*
     * RFC 9438, Figure 1
     *
     *   w_cubic = C * (t_msec / 1000) ^ 3 * mtu + w_max
     */

    cc = 10000000000ll / (int64_t)cg->mtu / S3_QUIC_CUBIC_C;
    w = t * t * t / cc + (int64_t)cg->w_max;

    if ((uint64_t)w > S3_QUIC_MAX_SIZE_T) {
        w = (int64_t)S3_QUIC_MAX_SIZE_T;
    }

    if (w < 0) {
        w = 0;
    }

done:

    s3_log_debug3(S3_LOG_DEBUG_EVENT, c->log, 0, "quic cubic t:%L w:%L wm:%uz", t, w, cg->w_max);

    return (size_t)w;
}

void
s3_quic_congestion_idle(s3_connection_t *c, s3_uint_t idle)
{
    s3_msec_t             now;
    s3_quic_congestion_t *cg;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);
    cg = &qc->congestion;

    s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "quic congestion idle:%ui", idle);

    if (cg->window >= cg->ssthresh) {
        /* RFC 9438, 5.8. Behavior for Application-Limited Flows */

        now = s3_current_msec;

        if (cg->idle) {
            cg->k += now - cg->idle_start;
        }

        cg->idle_start = now;
    }

    cg->idle = idle;
}

static void
s3_quic_drop_ack_ranges(s3_connection_t *c, s3_quic_send_ctx_t *ctx, uint64_t pn)
{
    uint64_t             base;
    s3_uint_t            i, smallest, largest;
    s3_quic_ack_range_t *r;

    s3_log_debug4(S3_LOG_DEBUG_EVENT, c->log, 0,
                  "quic drop ack ranges pn:%uL largest:%uL fr:%uL nranges:%ui", pn,
                  ctx->largest_range, ctx->first_range, ctx->nranges);

    base = ctx->largest_range;

    if (base == S3_QUIC_UNSET_PN) {
        return;
    }

    if (ctx->pending_ack != S3_QUIC_UNSET_PN && pn >= ctx->pending_ack) {
        ctx->pending_ack = S3_QUIC_UNSET_PN;
    }

    largest = base;
    smallest = largest - ctx->first_range;

    if (pn >= largest) {
        ctx->largest_range = S3_QUIC_UNSET_PN;
        ctx->first_range = 0;
        ctx->nranges = 0;
        return;
    }

    if (pn >= smallest) {
        ctx->first_range = largest - pn - 1;
        ctx->nranges = 0;
        return;
    }

    for (i = 0; i < ctx->nranges; i++) {
        r = &ctx->ranges[i];

        largest = smallest - r->gap - 2;
        smallest = largest - r->range;

        if (pn >= largest) {
            ctx->nranges = i;
            return;
        }
        if (pn >= smallest) {
            r->range = largest - pn - 1;
            ctx->nranges = i + 1;
            return;
        }
    }
}

static s3_int_t
s3_quic_detect_lost(s3_connection_t *c, s3_quic_ack_stat_t *st)
{
    uint64_t              pkt_thr;
    s3_uint_t             i, nlost;
    s3_msec_t             now, wait, thr, oldest, newest;
    s3_queue_t           *q;
    s3_quic_frame_t      *start;
    s3_quic_send_ctx_t   *ctx;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);
    now = s3_current_msec;
    thr = s3_quic_time_threshold(qc);

    oldest = now;
    newest = now;

    nlost = 0;

    for (i = 0; i < S3_QUIC_SEND_CTX_LAST; i++) {

        ctx = &qc->send_ctx[i];

        if (ctx->largest_ack == S3_QUIC_UNSET_PN) {
            continue;
        }

        pkt_thr = s3_quic_packet_threshold(ctx);

        while (!s3_queue_empty(&ctx->sent)) {

            q = s3_queue_head(&ctx->sent);
            start = s3_queue_data(q, s3_quic_frame_t, queue);

            if (start->pnum > ctx->largest_ack) {
                break;
            }

            wait = start->send_time + thr - now;

            s3_log_debug5(S3_LOG_DEBUG_EVENT, c->log, 0,
                          "quic detect_lost pnum:%uL thr:%uL pthr:%uL wait:%L level:%ui",
                          start->pnum, thr, pkt_thr, (s3_int64_t)wait, start->level);

            if ((s3_msec_int_t)wait > 0 && ctx->largest_ack - start->pnum < pkt_thr) {
                break;
            }

            if ((s3_msec_int_t)(start->send_time - qc->first_rtt) > 0) {

                if (nlost == 0 || (s3_msec_int_t)(start->send_time - oldest) < 0) {
                    oldest = start->send_time;
                }

                if (nlost == 0 || (s3_msec_int_t)(start->send_time - newest) > 0) {
                    newest = start->send_time;
                }

                nlost++;
            }

            s3_quic_resend_frames(c, ctx);
        }
    }

    /* RFC 9002, 7.6.2.  Establishing Persistent Congestion */

    /*
     * Once acknowledged, packets are no longer tracked. Thus no send time
     * information is available for such packets. This limits persistent
     * congestion algorithm to packets mentioned within ACK ranges of the
     * latest ACK frame.
     */

    if (st && nlost >= 2 &&
        ((s3_msec_int_t)(st->newest - oldest) < 0 || (s3_msec_int_t)(st->oldest - newest) > 0)) {
        if (newest - oldest > s3_quic_pcg_duration(c)) {
            s3_quic_persistent_congestion(c);
        }
    }

    s3_quic_set_lost_timer(c);

    return S3_OK;
}

static s3_msec_t
s3_quic_pcg_duration(s3_connection_t *c)
{
    s3_msec_t             duration;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    duration = qc->avg_rtt;
    duration += s3_max(4 * qc->rttvar, (s3_msec_t)S3_QUIC_TIME_GRANULARITY);
    duration += qc->ctp.max_ack_delay;
    duration *= S3_QUIC_PERSISTENT_CONGESTION_THR;

    return duration;
}

static void
s3_quic_persistent_congestion(s3_connection_t *c)
{
    s3_quic_congestion_t *cg;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);
    cg = &qc->congestion;

    cg->mtu = qc->path->mtu;
    cg->recovery_start = s3_quic_oldest_sent_packet(c) - 1;
    cg->window = cg->mtu * 2;

    s3_log_debug2(S3_LOG_DEBUG_EVENT, c->log, 0, "quic congestion persistent t:%uL win:%uz",
                  s3_current_msec, cg->window);
}

static s3_msec_t
s3_quic_oldest_sent_packet(s3_connection_t *c)
{
    s3_msec_t             oldest;
    s3_uint_t             i;
    s3_queue_t           *q;
    s3_quic_frame_t      *start;
    s3_quic_send_ctx_t   *ctx;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);
    oldest = s3_current_msec;

    for (i = 0; i < S3_QUIC_SEND_CTX_LAST; i++) {
        ctx = &qc->send_ctx[i];

        if (!s3_queue_empty(&ctx->sent)) {
            q = s3_queue_head(&ctx->sent);
            start = s3_queue_data(q, s3_quic_frame_t, queue);

            if ((s3_msec_int_t)(start->send_time - oldest) < 0) {
                oldest = start->send_time;
            }
        }
    }

    return oldest;
}

void
s3_quic_resend_frames(s3_connection_t *c, s3_quic_send_ctx_t *ctx)
{
    uint64_t              pnum;
    s3_queue_t           *q;
    s3_quic_frame_t      *f, *start;
    s3_quic_stream_t     *qs;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);
    q = s3_queue_head(&ctx->sent);
    start = s3_queue_data(q, s3_quic_frame_t, queue);
    pnum = start->pnum;

    s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "quic resend packet pnum:%uL", start->pnum);

    s3_quic_congestion_lost(c, start);

    do {
        f = s3_queue_data(q, s3_quic_frame_t, queue);

        if (f->pnum != pnum) {
            break;
        }

        q = s3_queue_next(q);

        s3_queue_remove(&f->queue);

        switch (f->type) {
        case S3_QUIC_FT_ACK:
        case S3_QUIC_FT_ACK_ECN:
            if (ctx->level == S3_QUIC_ENCRYPTION_APPLICATION) {
                /* force generation of most recent acknowledgment */
                ctx->send_ack = S3_QUIC_MAX_ACK_GAP;
            }

            s3_quic_free_frame(c, f);
            break;

        case S3_QUIC_FT_PING:
        case S3_QUIC_FT_PATH_CHALLENGE:
        case S3_QUIC_FT_PATH_RESPONSE:
        case S3_QUIC_FT_CONNECTION_CLOSE:
            s3_quic_free_frame(c, f);
            break;

        case S3_QUIC_FT_MAX_DATA:
            f->u.max_data.max_data = qc->streams.recv_max_data;
            s3_quic_queue_frame(qc, f);
            break;

        case S3_QUIC_FT_MAX_STREAMS:
        case S3_QUIC_FT_MAX_STREAMS2:
            f->u.max_streams.limit = f->u.max_streams.bidi ? qc->streams.client_max_streams_bidi
                                                           : qc->streams.client_max_streams_uni;
            s3_quic_queue_frame(qc, f);
            break;

        case S3_QUIC_FT_MAX_STREAM_DATA:
            qs = s3_quic_find_stream(&qc->streams.tree, f->u.max_stream_data.id);
            if (qs == NULL) {
                s3_quic_free_frame(c, f);
                break;
            }

            f->u.max_stream_data.limit = qs->recv_max_data;
            s3_quic_queue_frame(qc, f);
            break;

        case S3_QUIC_FT_STREAM:
            qs = s3_quic_find_stream(&qc->streams.tree, f->u.stream.stream_id);

            if (qs == NULL || qs->send_state == S3_QUIC_STREAM_SEND_RESET_SENT ||
                qs->send_state == S3_QUIC_STREAM_SEND_RESET_RECVD) {
                s3_quic_free_frame(c, f);
                break;
            }

            /* fall through */

        default:
            s3_queue_insert_tail(&ctx->frames, &f->queue);
        }

    } while (q != s3_queue_sentinel(&ctx->sent));

    if (qc->closing) {
        return;
    }

    s3_post_event(&qc->push, &qc->ctx->posted_events);
}

static void
s3_quic_congestion_lost(s3_connection_t *c, s3_quic_frame_t *f)
{
    s3_uint_t             blocked;
    s3_msec_t             now, timer;
    s3_quic_congestion_t *cg;
    s3_quic_connection_t *qc;

    if (f->plen == 0) {
        return;
    }

    qc = s3_quic_get_connection(c);
    cg = &qc->congestion;

    if (f->pnum < qc->rst_pnum) {
        return;
    }

    blocked = (cg->in_flight >= cg->window) ? 1 : 0;

    cg->in_flight -= f->plen;
    f->plen = 0;

    timer = f->send_time - cg->recovery_start;

    now = s3_current_msec;

    if ((s3_msec_int_t)timer <= 0) {
        s3_log_debug3(S3_LOG_DEBUG_EVENT, c->log, 0,
                      "quic congestion lost rec t:%uL win:%uz if:%uz", now, cg->window,
                      cg->in_flight);

        goto done;
    }

    if (f->ignore_loss) {
        s3_log_debug3(S3_LOG_DEBUG_EVENT, c->log, 0,
                      "quic congestion lost ignore t:%uL win:%uz if:%uz", now, cg->window,
                      cg->in_flight);

        goto done;
    }

    /* RFC 9438, 4.6. Multiplicative Decrease */

    cg->mtu = qc->path->mtu;
    cg->recovery_start = now;
    cg->w_prior = cg->window;
    /* RFC 9438, 4.7. Fast Convergence */
    cg->w_max = (cg->window < cg->w_max) ? cg->window * (10 + S3_QUIC_CUBIC_BETA) / 20 : cg->window;
    cg->ssthresh = cg->in_flight * S3_QUIC_CUBIC_BETA / 10;
    cg->window = s3_max(cg->ssthresh, cg->mtu * 2);
    cg->w_est = cg->window;
    cg->k = now + s3_quic_congestion_cubic_time(c);
    cg->idle_start = now;

    s3_log_debug3(S3_LOG_DEBUG_EVENT, c->log, 0, "quic congestion lost t:%uL win:%uz if:%uz", now,
                  cg->window, cg->in_flight);

done:

    if (blocked && cg->in_flight < cg->window) {
        s3_post_event(&qc->push, &qc->ctx->posted_events);
    }
}

static s3_msec_t
s3_quic_congestion_cubic_time(s3_connection_t *c)
{
    int64_t               v, x, d, cc;
    s3_uint_t             n;
    s3_quic_congestion_t *cg;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);
    cg = &qc->congestion;

    /*
     * RFC 9438, Figure 2
     *
     *   k_msec = ((w_max - cwnd_epoch) / C / mtu) ^ 1/3 * 1000
     */

    if (cg->w_max <= cg->window) {
        return 0;
    }

    cc = 10000000000ll / (int64_t)cg->mtu / S3_QUIC_CUBIC_C;
    v = (int64_t)(cg->w_max - cg->window) * cc;

    /*
     * Newton-Raphson method for x ^ 3 = v:
     *
     *   x_next = (2 * x_prev + v / x_prev ^ 2) / 3
     */

    x = 5000;

    for (n = 1; n <= 10; n++) {
        d = (v / x / x - x) / 3;
        x += d;

        if (s3_abs(d) <= 100) {
            break;
        }
    }

    if ((uint64_t)x > S3_QUIC_MAX_SIZE_T) {
        return (s3_msec_t)S3_QUIC_MAX_SIZE_T;
    }

    s3_log_debug2(S3_LOG_DEBUG_EVENT, c->log, 0, "quic cubic time:%L n:%ui", x, n);

    return (s3_msec_t)x;
}

void
s3_quic_set_lost_timer(s3_connection_t *c)
{
    uint64_t              pkt_thr;
    s3_uint_t             i;
    s3_msec_t             now;
    s3_queue_t           *q;
    s3_msec_int_t         lost, pto, w;
    s3_quic_frame_t      *f;
    s3_quic_send_ctx_t   *ctx;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);
    now = s3_current_msec;

    lost = -1;
    pto = -1;

    for (i = 0; i < S3_QUIC_SEND_CTX_LAST; i++) {
        ctx = &qc->send_ctx[i];

        if (s3_queue_empty(&ctx->sent)) {
            continue;
        }

        if (ctx->largest_ack != S3_QUIC_UNSET_PN) {
            q = s3_queue_head(&ctx->sent);
            f = s3_queue_data(q, s3_quic_frame_t, queue);
            w = (s3_msec_int_t)(f->send_time + s3_quic_time_threshold(qc) - now);

            if (f->pnum <= ctx->largest_ack) {
                pkt_thr = s3_quic_packet_threshold(ctx);

                if (w < 0 || ctx->largest_ack - f->pnum >= pkt_thr) {
                    w = 0;
                }

                if (lost == -1 || w < lost) {
                    lost = w;
                }
            }
        }

        q = s3_queue_last(&ctx->sent);
        f = s3_queue_data(q, s3_quic_frame_t, queue);
        w = (s3_msec_int_t)(f->send_time + (s3_quic_pto(c, ctx) << qc->pto_count) - now);

        if (w < 0) {
            w = 0;
        }

        if (pto == -1 || w < pto) {
            pto = w;
        }
    }

    if (qc->pto.timer_set) {
        s3_event_del_timer(&qc->pto);
    }

    if (lost != -1) {
        s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "quic lost timer lost:%L", lost);

        qc->pto.handler = s3_quic_lost_handler;
        s3_event_add_timer(&qc->pto, lost);
        return;
    }

    if (pto != -1) {
        s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "quic lost timer pto:%L", pto);

        qc->pto.handler = s3_quic_pto_handler;
        s3_event_add_timer(&qc->pto, pto);
        return;
    }

    s3_log_debug0(S3_LOG_DEBUG_EVENT, c->log, 0, "quic lost timer unset");
}

s3_msec_t
s3_quic_pto(s3_connection_t *c, s3_quic_send_ctx_t *ctx)
{
    s3_msec_t             duration;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    /* RFC 9002, Appendix A.8.  Setting the Loss Detection Timer */

    duration = qc->avg_rtt;
    duration += s3_max(4 * qc->rttvar, (s3_msec_t)S3_QUIC_TIME_GRANULARITY);

    if (ctx->level == S3_QUIC_ENCRYPTION_APPLICATION && c->ssl != NULL && c->ssl->handshaked) {
        duration += qc->ctp.max_ack_delay;
    }

    return duration;
}

static void
s3_quic_lost_handler(s3_event_t *ev)
{
    s3_connection_t *c;

    s3_log_debug0(S3_LOG_DEBUG_EVENT, ev->log, 0, "quic lost timer");

    c = ev->data;

    if (s3_quic_detect_lost(c, NULL) != S3_OK) {
        s3_quic_close_connection(c, S3_ERROR);
        return;
    }
}

void
s3_quic_pto_handler(s3_event_t *ev)
{
    s3_uint_t             i, n;
    s3_msec_t             now;
    s3_queue_t           *q;
    s3_msec_int_t         w;
    s3_connection_t      *c;
    s3_quic_frame_t      *f;
    s3_quic_send_ctx_t   *ctx;
    s3_quic_connection_t *qc;

    s3_log_debug0(S3_LOG_DEBUG_EVENT, ev->log, 0, "quic pto timer");

    c = ev->data;
    qc = s3_quic_get_connection(c);
    now = s3_current_msec;

    for (i = 0; i < S3_QUIC_SEND_CTX_LAST; i++) {

        ctx = &qc->send_ctx[i];

        if (s3_queue_empty(&ctx->sent)) {
            continue;
        }

        q = s3_queue_last(&ctx->sent);
        f = s3_queue_data(q, s3_quic_frame_t, queue);
        w = (s3_msec_int_t)(f->send_time + (s3_quic_pto(c, ctx) << qc->pto_count) - now);

        if (f->pnum <= ctx->largest_ack && ctx->largest_ack != S3_QUIC_UNSET_PN) {
            continue;
        }

        if (w > 0) {
            continue;
        }

        s3_log_debug2(S3_LOG_DEBUG_EVENT, c->log, 0, "quic pto %s pto_count:%ui",
                      s3_quic_level_name(ctx->level), qc->pto_count);

        for (n = 0; n < 2; n++) {

            f = s3_quic_alloc_frame(c);
            if (f == NULL) {
                goto failed;
            }

            f->level = ctx->level;
            f->type = S3_QUIC_FT_PING;
            f->ignore_congestion = 1;

            if (s3_quic_frame_sendto(c, f, 0, qc->path) == S3_ERROR) {
                goto failed;
            }
        }
    }

    qc->pto_count++;

    /*
     * the dead-path guard: the probes without a single ack in a row
     * mean the peer is gone (a client that died before its CC, a cut
     * path).  The sixth probe backs off 64x the base rto - a live
     * path of any real rto answers long before the cap; the cap keeps
     * the connection (its pools, its codec contexts) from riding the
     * idle timeout the transport parameters agreed on - the zombie
     * shape of the bench stands: the daemon kept such connections
     * alive for the full idle window and the fresh sessions starved
     */

    if (qc->pto_count > 6) {
        s3_log_error(S3_LOG_INFO, c->log, 0, "quic dead path: %ui probes without an ack, closing",
                     qc->pto_count);

        s3_quic_close_connection(c, S3_ERROR);
        return;
    }

    s3_quic_set_lost_timer(c);

    return;

failed:

    s3_quic_close_connection(c, S3_ERROR);
    return;
}

s3_int_t
s3_quic_ack_packet(s3_connection_t *c, s3_quic_header_t *pkt)
{
    uint64_t              base, largest, smallest, gs, ge, gap, range, pn;
    uint64_t              prev_pending;
    s3_uint_t             i, nr;
    s3_quic_send_ctx_t   *ctx;
    s3_quic_ack_range_t  *r;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    ctx = s3_quic_get_send_ctx(qc, pkt->level);

    s3_log_debug4(S3_LOG_DEBUG_EVENT, c->log, 0,
                  "quic ack packet pn:%uL largest %L fr:%uL nranges:%ui", pkt->pn,
                  (s3_int64_t)ctx->largest_range, ctx->first_range, ctx->nranges);

    if (!s3_quic_keys_available(qc->keys, ctx->level, 1)) {
        return S3_OK;
    }

    prev_pending = ctx->pending_ack;

    if (pkt->need_ack) {

        s3_post_event(&qc->push, &qc->ctx->posted_events);

        if (ctx->send_ack == 0) {
            ctx->ack_delay_start = s3_current_msec;
        }

        ctx->send_ack++;

        if (ctx->pending_ack == S3_QUIC_UNSET_PN || ctx->pending_ack < pkt->pn) {
            ctx->pending_ack = pkt->pn;
        }
    }

    base = ctx->largest_range;
    pn = pkt->pn;

    if (base == S3_QUIC_UNSET_PN) {
        ctx->largest_range = pn;
        ctx->largest_received = pkt->received;
        return S3_OK;
    }

    if (base == pn) {
        return S3_OK;
    }

    largest = base;
    smallest = largest - ctx->first_range;

    if (pn > base) {

        if (pn - base == 1) {
            ctx->first_range++;
            ctx->largest_range = pn;
            ctx->largest_received = pkt->received;

            return S3_OK;

        } else {
            /* new gap in front of current largest */

            /* no place for new range, send current range as is */
            if (ctx->nranges == S3_QUIC_MAX_RANGES) {

                if (prev_pending != S3_QUIC_UNSET_PN) {
                    if (s3_quic_send_ack(c, ctx) != S3_OK) {
                        return S3_ERROR;
                    }
                }

                if (prev_pending == ctx->pending_ack || !pkt->need_ack) {
                    ctx->pending_ack = S3_QUIC_UNSET_PN;
                }
            }

            gap = pn - base - 2;
            range = ctx->first_range;
            ctx->first_range = 0;
            ctx->largest_range = pn;
            ctx->largest_received = pkt->received;

            /* packet is out of order, force send */
            if (pkt->need_ack) {
                ctx->send_ack = S3_QUIC_MAX_ACK_GAP;
            }

            i = 0;

            goto insert;
        }
    }

    /*  pn < base, perform lookup in existing ranges */

    /* packet is out of order */
    if (pkt->need_ack) {
        ctx->send_ack = S3_QUIC_MAX_ACK_GAP;
    }

    if (pn >= smallest && pn <= largest) {
        return S3_OK;
    }

    r = NULL;

    for (i = 0; i < ctx->nranges; i++) {
        r = &ctx->ranges[i];

        ge = smallest - 1;
        gs = ge - r->gap;

        if (pn >= gs && pn <= ge) {

            if (gs == ge) {
                /* gap size is exactly one packet, now filled */

                /* data moves to previous range, current is removed */

                if (i == 0) {
                    ctx->first_range += r->range + 2;

                } else {
                    ctx->ranges[i - 1].range += r->range + 2;
                }

                nr = ctx->nranges - i - 1;
                if (nr) {
                    s3_memmove(&ctx->ranges[i], &ctx->ranges[i + 1],
                               sizeof(s3_quic_ack_range_t) * nr);
                }

                ctx->nranges--;

            } else if (pn == gs) {
                /* current gap shrinks from tail (current range grows) */
                r->gap--;
                r->range++;

            } else if (pn == ge) {
                /* current gap shrinks from head (previous range grows) */
                r->gap--;

                if (i == 0) {
                    ctx->first_range++;

                } else {
                    ctx->ranges[i - 1].range++;
                }

            } else {
                /* current gap is split into two parts */

                gap = ge - pn - 1;
                range = 0;

                if (ctx->nranges == S3_QUIC_MAX_RANGES) {
                    if (prev_pending != S3_QUIC_UNSET_PN) {
                        if (s3_quic_send_ack(c, ctx) != S3_OK) {
                            return S3_ERROR;
                        }
                    }

                    if (prev_pending == ctx->pending_ack || !pkt->need_ack) {
                        ctx->pending_ack = S3_QUIC_UNSET_PN;
                    }
                }

                r->gap = pn - gs - 1;
                goto insert;
            }

            return S3_OK;
        }

        largest = smallest - r->gap - 2;
        smallest = largest - r->range;

        if (pn >= smallest && pn <= largest) {
            /* this packet number is already known */
            return S3_OK;
        }
    }

    if (pn == smallest - 1) {
        /* extend first or last range */

        if (i == 0) {
            ctx->first_range++;

        } else {
            r->range++;
        }

        return S3_OK;
    }

    /* nothing found, add new range at the tail  */

    if (ctx->nranges == S3_QUIC_MAX_RANGES) {
        /* packet is too old to keep it */

        if (pkt->need_ack) {
            return s3_quic_send_ack_range(c, ctx, pn, pn);
        }

        return S3_OK;
    }

    gap = smallest - 2 - pn;
    range = 0;

insert:

    if (ctx->nranges < S3_QUIC_MAX_RANGES) {
        ctx->nranges++;
    }

    s3_memmove(&ctx->ranges[i + 1], &ctx->ranges[i],
               sizeof(s3_quic_ack_range_t) * (ctx->nranges - i - 1));

    ctx->ranges[i].gap = gap;
    ctx->ranges[i].range = range;

    return S3_OK;
}

s3_int_t
s3_quic_generate_ack(s3_connection_t *c, s3_quic_send_ctx_t *ctx)
{
    s3_msec_t             delay;
    s3_quic_connection_t *qc;

    if (!ctx->send_ack) {
        return S3_OK;
    }

    if (ctx->level == S3_QUIC_ENCRYPTION_APPLICATION) {

        delay = s3_current_msec - ctx->ack_delay_start;
        qc = s3_quic_get_connection(c);

        if (s3_queue_empty(&ctx->frames) && ctx->send_ack < S3_QUIC_MAX_ACK_GAP &&
            delay < qc->tp.max_ack_delay) {
            if (!qc->push.timer_set && !qc->closing) {
                s3_event_add_timer(&qc->push, qc->tp.max_ack_delay - delay);
            }

            return S3_OK;
        }
    }

    if (s3_quic_send_ack(c, ctx) != S3_OK) {
        return S3_ERROR;
    }

    ctx->send_ack = 0;

    return S3_OK;
}
