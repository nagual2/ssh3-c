/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <openssl/rand.h>

#include <s3_quic.h>
#include <s3_quic_connection.h>
#include <s3_quic_output.h>
#include <s3_quic_frames.h>
#include <s3_quic_ack.h>

#include <s3_udp_sendmsg_chain.h>
#include <s3_cmsg.h>
#include <s3_errno.h>

#include <time.h>

#define S3_QUIC_MAX_UDP_SEGMENT_BUF 65487 /* 65K - IPv6 header */
#define S3_QUIC_MAX_SEGMENTS        64    /* UDP_MAX_SEGMENTS */

#define S3_QUIC_RETRY_TOKEN_LIFETIME 3   /* seconds */
#define S3_QUIC_NEW_TOKEN_LIFETIME   600 /* seconds */
#define S3_QUIC_RETRY_BUFFER_SIZE    256
/* 1 flags + 4 version + 3 x (1 + 20) s/o/dcid + itag + token(64) */

/*
 * RFC 9000, 10.3.  Stateless Reset
 *
 * Endpoints MUST discard packets that are too small to be valid QUIC
 * packets.  With the set of AEAD functions defined in [QUIC-TLS],
 * short header packets that are smaller than 21 bytes are never valid.
 */
#define S3_QUIC_MIN_PKT_LEN 41 /* 21 + 20 (server cid length) */

#define S3_QUIC_MIN_SR_PACKET 43   /* 5 rand + 16 srt + 22 padding */
#define S3_QUIC_MAX_SR_PACKET 1200

#define S3_QUIC_CC_MIN_INTERVAL 1000 /* 1s */

#define S3_QUIC_SOCKET_RETRY_DELAY 10 /* ms, for S3_AGAIN on write */

#define s3_quic_log_packet(log, pkt)                                                               \
    s3_log_debug6(S3_LOG_DEBUG_EVENT, log, 0,                                                      \
                  "quic packet tx %s bytes:%ui need_ack:%d number:%L encoded nl:%d trunc:0x%xD",    \
                  s3_quic_level_name((pkt)->level), (s3_uint_t)(pkt)->payload.len,                  \
                  (s3_int_t)(pkt)->need_ack, (int64_t)(pkt)->number, (s3_int_t)(pkt)->num_len,      \
                  (s3_uint32_t)(pkt)->trunc)

#if (S3_HAVE_ADDRINFO_CMSG)
static s3_udp_listen_t *s3_quic_socket_listener(s3_connection_t *c);
#endif
static s3_int_t         s3_quic_create_datagrams(s3_connection_t *c);
static void             s3_quic_commit_send(s3_connection_t *c);
static void             s3_quic_revert_send(s3_connection_t *c,
                                            uint64_t preserved_pnum[S3_QUIC_SEND_CTX_LAST]);
#if (S3_HAVE_UDP_SEGMENT)
static s3_uint_t s3_quic_allow_segmentation(s3_connection_t *c);
static s3_int_t  s3_quic_create_segments(s3_connection_t *c);
static ssize_t   s3_quic_send_segments(s3_connection_t *c, u_char *buf, size_t len,
                                       struct sockaddr *sockaddr, socklen_t socklen,
                                       size_t segment);
#endif
static ssize_t   s3_quic_output_packet(s3_connection_t *c, s3_quic_send_ctx_t *ctx, u_char *data,
                                       size_t max, size_t min, s3_uint_t ack_only);
static void      s3_quic_init_packet(s3_connection_t *c, s3_quic_send_ctx_t *ctx,
                                     s3_quic_header_t *pkt, s3_quic_path_t *path);
static s3_uint_t s3_quic_get_padding_level(s3_connection_t *c);
static ssize_t   s3_quic_send(s3_connection_t *c, u_char *buf, size_t len,
                               struct sockaddr *sockaddr, socklen_t socklen);
static void      s3_quic_set_packet_number(s3_quic_header_t *pkt, s3_quic_send_ctx_t *ctx);
static s3_int_t  s3_quic_stateless_reset_filter(s3_connection_t *c);

/*
 * the nginx c->listening link does not exist; the quic socket keeps
 * the listener backlink from the registration instead
 * (porting map 4.3.6)
 */
#if (S3_HAVE_ADDRINFO_CMSG)
static s3_udp_listen_t *
s3_quic_socket_listener(s3_connection_t *c)
{
    s3_quic_socket_t *qsock;

    qsock = s3_quic_get_socket(c);

    return (qsock != NULL) ? qsock->listen : NULL;
}
#endif

s3_int_t
s3_quic_output(s3_connection_t *c)
{
    size_t                in_flight;
    s3_int_t              rc;
    s3_quic_congestion_t *cg;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);
    cg = &qc->congestion;

    in_flight = cg->in_flight;

#if (S3_HAVE_UDP_SEGMENT)
    if (s3_quic_allow_segmentation(c)) {
        rc = s3_quic_create_segments(c);
    } else
#endif
    {
        rc = s3_quic_create_datagrams(c);
    }

    if (rc != S3_OK) {
        return S3_ERROR;
    }

    if (in_flight == cg->in_flight || qc->closing) {
        /* no ack-eliciting data was sent or we are done */
        return S3_OK;
    }

    if (!qc->send_timer_set) {
        qc->send_timer_set = 1;
        s3_event_add_timer(c->read, qc->tp.max_idle_timeout);
    }

    s3_quic_set_lost_timer(c);

    return S3_OK;
}

static s3_int_t
s3_quic_create_datagrams(s3_connection_t *c)
{
    size_t                 len, min;
    ssize_t                n;
    u_char                *p;
    uint64_t               preserved_pnum[S3_QUIC_SEND_CTX_LAST];
    s3_uint_t              i, pad;
    s3_quic_path_t        *path;
    s3_quic_send_ctx_t    *ctx;
    s3_quic_congestion_t  *cg;
    s3_quic_connection_t  *qc;
    static u_char          dst[S3_QUIC_MAX_UDP_PAYLOAD_SIZE];

    qc = s3_quic_get_connection(c);
    cg = &qc->congestion;
    path = qc->path;

    s3_memzero(preserved_pnum, sizeof(preserved_pnum));

    do {
        p = dst;

        len = s3_quic_path_limit(c, path, path->mtu);

        /*
         * the padding level depends on what the initial level will
         * emit, and its ack is only generated inside the loop below;
         * the call is idempotent (ctx->send_ack is cleared), so the
         * client padding rule sees the pending initial ack
         */
        if (s3_quic_generate_ack(c, &qc->send_ctx[S3_QUIC_ENCRYPTION_INITIAL]) != S3_OK) {
            return S3_ERROR;
        }

        pad = s3_quic_get_padding_level(c);

        for (i = 0; i < S3_QUIC_SEND_CTX_LAST; i++) {

            ctx = &qc->send_ctx[i];

            preserved_pnum[i] = ctx->pnum;

            if (s3_quic_generate_ack(c, ctx) != S3_OK) {
                return S3_ERROR;
            }

            min = (i == pad && p - dst < S3_QUIC_MIN_INITIAL_SIZE)
                  ? S3_QUIC_MIN_INITIAL_SIZE - (p - dst) : 0;

            if (min > len) {
                /* padding can't be applied - avoid sending the packet */
                s3_quic_revert_send(c, preserved_pnum);
                return S3_OK;
            }

            n = s3_quic_output_packet(c, ctx, p, len, min, cg->in_flight >= cg->window);
            if (n == S3_ERROR) {
                return S3_ERROR;
            }

            p += n;
            len -= n;
        }

        len = p - dst;
        if (len == 0) {
            break;
        }

        n = s3_quic_send(c, dst, len, path->sockaddr, path->socklen);

        if (n == (ssize_t)S3_ERROR) {
            return S3_ERROR;
        }

        if (n == (ssize_t)S3_AGAIN) {
            s3_quic_revert_send(c, preserved_pnum);
            s3_event_add_timer(&qc->push, S3_QUIC_SOCKET_RETRY_DELAY);
            break;
        }

        s3_quic_commit_send(c);

        path->sent += len;

    } while (cg->in_flight < cg->window);

    return S3_OK;
}

static void
s3_quic_commit_send(s3_connection_t *c)
{
    s3_uint_t              i, idle;
    s3_queue_t            *q;
    s3_quic_frame_t       *f;
    s3_quic_send_ctx_t    *ctx;
    s3_quic_congestion_t  *cg;
    s3_quic_connection_t  *qc;

    qc = s3_quic_get_connection(c);
    cg = &qc->congestion;

    idle = 1;

    for (i = 0; i < S3_QUIC_SEND_CTX_LAST; i++) {
        ctx = &qc->send_ctx[i];

        if (!s3_queue_empty(&ctx->frames)) {
            idle = 0;
        }

        while (!s3_queue_empty(&ctx->sending)) {

            q = s3_queue_head(&ctx->sending);
            f = s3_queue_data(q, s3_quic_frame_t, queue);

            s3_queue_remove(q);

            if (f->pkt_need_ack && !qc->closing) {
                s3_queue_insert_tail(&ctx->sent, q);

                cg->in_flight += f->plen;

            } else {
                s3_quic_free_frame(c, f);
            }
        }
    }

    s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "quic congestion send if:%uz", cg->in_flight);

    s3_quic_congestion_idle(c, idle);
}

static void
s3_quic_revert_send(s3_connection_t *c, uint64_t pnum[S3_QUIC_SEND_CTX_LAST])
{
    s3_uint_t              i;
    s3_queue_t            *q;
    s3_quic_send_ctx_t    *ctx;
    s3_quic_connection_t  *qc;

    qc = s3_quic_get_connection(c);

    for (i = 0; i < S3_QUIC_SEND_CTX_LAST; i++) {
        ctx = &qc->send_ctx[i];

        if (s3_queue_empty(&ctx->sending)) {
            continue;
        }

        do {
            q = s3_queue_last(&ctx->sending);
            s3_queue_remove(q);
            s3_queue_insert_head(&ctx->frames, q);
        } while (!s3_queue_empty(&ctx->sending));

        ctx->pnum = pnum[i];
    }

    s3_quic_congestion_idle(c, 1);
}

#if (S3_HAVE_UDP_SEGMENT)

static s3_uint_t
s3_quic_allow_segmentation(s3_connection_t *c)
{
    size_t                 bytes, len;
    s3_queue_t            *q;
    s3_quic_frame_t       *f;
    s3_quic_send_ctx_t    *ctx;
    s3_quic_connection_t  *qc;

    qc = s3_quic_get_connection(c);

    if (!qc->conf->gso_enabled) {
        return 0;
    }

    if (!qc->path->validated) {
        /* don't even try to be faster on non-validated paths */
        return 0;
    }

    ctx = s3_quic_get_send_ctx(qc, S3_QUIC_ENCRYPTION_INITIAL);
    if (!s3_queue_empty(&ctx->frames)) {
        return 0;
    }

    ctx = s3_quic_get_send_ctx(qc, S3_QUIC_ENCRYPTION_HANDSHAKE);
    if (!s3_queue_empty(&ctx->frames)) {
        return 0;
    }

    ctx = s3_quic_get_send_ctx(qc, S3_QUIC_ENCRYPTION_APPLICATION);

    bytes = 0;
    len = s3_min(qc->path->mtu, S3_QUIC_MAX_UDP_SEGMENT_BUF);

    for (q = s3_queue_head(&ctx->frames); q != s3_queue_sentinel(&ctx->frames);
         q = s3_queue_next(q))
    {
        f = s3_queue_data(q, s3_quic_frame_t, queue);

        bytes += f->len;

        if (qc->congestion.in_flight + bytes >= qc->congestion.window) {
            return 0;
        }

        if (bytes > len * 3) {
            /* require at least ~3 full packets to batch */
            return 1;
        }
    }

    return 0;
}

static s3_int_t
s3_quic_create_segments(s3_connection_t *c)
{
    size_t                 len, segsize;
    ssize_t                n;
    u_char                *p, *end;
    s3_uint_t              nseg, level;
    s3_quic_path_t        *path;
    s3_quic_send_ctx_t    *ctx;
    s3_quic_congestion_t  *cg;
    s3_quic_connection_t  *qc;
    static u_char          dst[S3_QUIC_MAX_UDP_SEGMENT_BUF];
    static uint64_t        preserved_pnum[S3_QUIC_SEND_CTX_LAST];

    qc = s3_quic_get_connection(c);
    cg = &qc->congestion;
    path = qc->path;

    ctx = s3_quic_get_send_ctx(qc, S3_QUIC_ENCRYPTION_APPLICATION);

    if (s3_quic_generate_ack(c, ctx) != S3_OK) {
        return S3_ERROR;
    }

    segsize = s3_min(path->mtu, S3_QUIC_MAX_UDP_SEGMENT_BUF);
    p = dst;
    end = dst + sizeof(dst);

    nseg = 0;

    level = ctx - qc->send_ctx;
    preserved_pnum[level] = ctx->pnum;

    for (;;) {

        len = s3_min(segsize, (size_t)(end - p));

        if (len && cg->in_flight + (p - dst) < cg->window) {

            n = s3_quic_output_packet(c, ctx, p, len, len, 0);
            if (n == (ssize_t)S3_ERROR) {
                return S3_ERROR;
            }

            if (n) {
                p += n;
                nseg++;
            }

        } else {
            n = 0;
        }

        if (p == dst) {
            break;
        }

        if (n == 0 || nseg == S3_QUIC_MAX_SEGMENTS) {
            n = s3_quic_send_segments(c, dst, p - dst, path->sockaddr, path->socklen, segsize);
            if (n == (ssize_t)S3_ERROR) {
                return S3_ERROR;
            }

            if (n == (ssize_t)S3_AGAIN) {
                s3_quic_revert_send(c, preserved_pnum);
                s3_event_add_timer(&qc->push, S3_QUIC_SOCKET_RETRY_DELAY);
                break;
            }

            s3_quic_commit_send(c);

            path->sent += n;

            p = dst;
            nseg = 0;
            preserved_pnum[level] = ctx->pnum;
        }
    }

    return S3_OK;
}

static ssize_t
s3_quic_send_segments(s3_connection_t *c, u_char *buf, size_t len, struct sockaddr *sockaddr,
                      socklen_t socklen, size_t segment)
{
    size_t          clen;
    ssize_t         n;
    uint16_t       *valp;
    struct iovec    iov;
    struct msghdr   msg;
    struct cmsghdr *cmsg;

#if (S3_HAVE_ADDRINFO_CMSG)
    char            msg_control[CMSG_SPACE(sizeof(uint16_t)) + CMSG_SPACE(sizeof(s3_addrinfo_t))];
#else
    char            msg_control[CMSG_SPACE(sizeof(uint16_t))];
#endif

    s3_memzero(&msg, sizeof(struct msghdr));
    s3_memzero(msg_control, sizeof(msg_control));

    iov.iov_len = len;
    iov.iov_base = (void *)buf;

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    msg.msg_name = sockaddr;
    msg.msg_namelen = socklen;

    msg.msg_control = msg_control;
    msg.msg_controllen = sizeof(msg_control);

    cmsg = CMSG_FIRSTHDR(&msg);

    cmsg->cmsg_level = SOL_UDP;
    cmsg->cmsg_type = UDP_SEGMENT;
    cmsg->cmsg_len = CMSG_LEN(sizeof(uint16_t));

    clen = CMSG_SPACE(sizeof(uint16_t));

    valp = (void *)CMSG_DATA(cmsg);
    *valp = segment;

#if (S3_HAVE_ADDRINFO_CMSG)
    if (s3_quic_socket_listener(c) != NULL && s3_quic_socket_listener(c)->wildcard
        && c->local_sockaddr)
    {
        cmsg = CMSG_NXTHDR(&msg, cmsg);
        clen += s3_set_srcaddr_cmsg(cmsg, c->local_sockaddr);
    }
#endif

    msg.msg_controllen = clen;

    n = s3_sendmsg(c, &msg, 0);
    if (n < 0) {
        return n;
    }

    c->sent += n;

    return n;
}

#endif /* S3_HAVE_UDP_SEGMENT */

static s3_uint_t
s3_quic_get_padding_level(s3_connection_t *c)
{
    s3_uint_t              i;
    s3_queue_t            *q;
    s3_quic_frame_t       *f;
    s3_quic_send_ctx_t    *ctx;
    s3_quic_connection_t  *qc;

    /*
     * RFC 9000, 14.1.  Initial Datagram Size
     *
     * Similarly, a server MUST expand the payload of all UDP datagrams
     * carrying ack-eliciting Initial packets to at least the smallest
     * allowed maximum datagram size of 1200 bytes.
     */

    qc = s3_quic_get_connection(c);
    ctx = s3_quic_get_send_ctx(qc, S3_QUIC_ENCRYPTION_INITIAL);

    for (q = s3_queue_head(&ctx->frames); q != s3_queue_sentinel(&ctx->frames);
         q = s3_queue_next(q))
    {
        f = s3_queue_data(q, s3_quic_frame_t, queue);

        /*
         * a client expands every datagram carrying an Initial packet,
         * a server only the ack-eliciting ones.  The reference only runs
         * a server and so never needed the client side of the rule
         */
        if (f->need_ack || qc->client) {
            for (i = 0; i + 1 < S3_QUIC_SEND_CTX_LAST; i++) {
                ctx = &qc->send_ctx[i + 1];

                if (s3_queue_empty(&ctx->frames)) {
                    break;
                }
            }

            return i;
        }
    }

    return S3_QUIC_SEND_CTX_LAST;
}

static ssize_t
s3_quic_output_packet(s3_connection_t *c, s3_quic_send_ctx_t *ctx, u_char *data, size_t max,
                      size_t min, s3_uint_t ack_only)
{
    size_t                 len, pad, min_payload, max_payload;
    u_char                *p;
    ssize_t                flen;
    s3_str_t               res;
    s3_int_t               rc;
    s3_uint_t              nframes;
    s3_msec_t              now;
    s3_queue_t            *q;
    s3_quic_frame_t       *f;
    s3_quic_header_t       pkt;
    s3_quic_connection_t  *qc;
    static u_char          src[S3_QUIC_MAX_UDP_PAYLOAD_SIZE];

    if (s3_queue_empty(&ctx->frames)) {
        return 0;
    }

    s3_log_debug3(S3_LOG_DEBUG_EVENT, c->log, 0, "quic output %s packet max:%uz min:%uz",
                  s3_quic_level_name(ctx->level), max, min);

    qc = s3_quic_get_connection(c);

    if (!s3_quic_keys_available(qc->keys, ctx->level, 1)) {
        s3_log_error(S3_LOG_ALERT, c->log, 0, "quic %s write keys discarded",
                     s3_quic_level_name(ctx->level));

        while (!s3_queue_empty(&ctx->frames)) {
            q = s3_queue_head(&ctx->frames);
            s3_queue_remove(q);

            f = s3_queue_data(q, s3_quic_frame_t, queue);
            s3_quic_free_frame(c, f);
        }

        return 0;
    }

    s3_quic_init_packet(c, ctx, &pkt, qc->path);

    min_payload = s3_quic_payload_size(&pkt, min);
    max_payload = s3_quic_payload_size(&pkt, max);

    /* RFC 9001, 5.4.2.  Header Protection Sample */
    pad = 4 - pkt.num_len;
    min_payload = s3_max(min_payload, pad);

    if (min_payload > max_payload) {
        return 0;
    }

    now = s3_current_msec;
    nframes = 0;
    p = src;
    len = 0;

    for (q = s3_queue_head(&ctx->frames); q != s3_queue_sentinel(&ctx->frames);
         q = s3_queue_next(q))
    {
        f = s3_queue_data(q, s3_quic_frame_t, queue);

        if (ack_only && f->type != S3_QUIC_FT_ACK) {
            break;
        }

        if (len >= max_payload) {
            break;
        }

        if (len + f->len > max_payload) {
            rc = s3_quic_split_frame(c, f, max_payload - len);

            if (rc == S3_ERROR) {
                return S3_ERROR;
            }

            if (rc == S3_DECLINED) {
                break;
            }
        }

        if (f->need_ack) {
            pkt.need_ack = 1;
        }

        f->pnum = ctx->pnum;
        f->send_time = now;
        f->plen = 0;

        flen = s3_quic_create_frame(p, f);
        if (flen == -1) {
            return S3_ERROR;
        }

        len += flen;
        p += flen;

        nframes++;
    }

    if (nframes == 0) {
        return 0;
    }

    if (len < min_payload) {
        s3_memset(p, S3_QUIC_FT_PADDING, min_payload - len);
        len = min_payload;
    }

    pkt.payload.data = src;
    pkt.payload.len = len;

    pkt.client = s3_quic_get_connection(c)->client;

    res.data = data;

    s3_quic_log_packet(c->log, &pkt);

    if (s3_quic_encrypt(&pkt, &res) != S3_OK) {
        return S3_ERROR;
    }

    ctx->pnum++;

    if (pkt.need_ack) {
        q = s3_queue_head(&ctx->frames);
        f = s3_queue_data(q, s3_quic_frame_t, queue);

        f->plen = res.len;
    }

    while (nframes--) {
        q = s3_queue_head(&ctx->frames);
        f = s3_queue_data(q, s3_quic_frame_t, queue);

        f->pkt_need_ack = pkt.need_ack;

        s3_queue_remove(q);
        s3_queue_insert_tail(&ctx->sending, q);
    }

    return res.len;
}

static void
s3_quic_init_packet(s3_connection_t *c, s3_quic_send_ctx_t *ctx, s3_quic_header_t *pkt,
                    s3_quic_path_t *path)
{
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    s3_memzero(pkt, sizeof(s3_quic_header_t));

    pkt->flags = S3_QUIC_PKT_FIXED_BIT;

    if (ctx->level == S3_QUIC_ENCRYPTION_INITIAL) {
        pkt->flags |= S3_QUIC_PKT_LONG | S3_QUIC_PKT_INITIAL;

    } else if (ctx->level == S3_QUIC_ENCRYPTION_HANDSHAKE) {
        pkt->flags |= S3_QUIC_PKT_LONG | S3_QUIC_PKT_HANDSHAKE;

    } else {
        if (qc->key_phase) {
            pkt->flags |= S3_QUIC_PKT_KPHASE;
        }
    }

    pkt->dcid.data = path->cid->id;
    pkt->dcid.len = path->cid->len;

    pkt->scid = qc->tp.initial_scid;

    pkt->version = qc->version;
    pkt->log = c->log;
    pkt->level = ctx->level;

    pkt->keys = qc->keys;

    s3_quic_set_packet_number(pkt, ctx);
}

static ssize_t
s3_quic_send(s3_connection_t *c, u_char *buf, size_t len, struct sockaddr *sockaddr,
             socklen_t socklen)
{
    ssize_t         n;
    struct iovec    iov;
    struct msghdr   msg;
#if (S3_HAVE_ADDRINFO_CMSG)
    struct cmsghdr *cmsg;
    char            msg_control[CMSG_SPACE(sizeof(s3_addrinfo_t))];
#endif

    s3_memzero(&msg, sizeof(struct msghdr));

    iov.iov_len = len;
    iov.iov_base = (void *)buf;

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    msg.msg_name = sockaddr;
    msg.msg_namelen = socklen;

#if (S3_HAVE_ADDRINFO_CMSG)
    if (s3_quic_socket_listener(c) != NULL && s3_quic_socket_listener(c)->wildcard
        && c->local_sockaddr)
    {

        msg.msg_control = msg_control;
        msg.msg_controllen = sizeof(msg_control);
        s3_memzero(msg_control, sizeof(msg_control));

        cmsg = CMSG_FIRSTHDR(&msg);

        msg.msg_controllen = s3_set_srcaddr_cmsg(cmsg, c->local_sockaddr);
    }
#endif

    n = s3_sendmsg(c, &msg, 0);
    if (n < 0) {
        return n;
    }

    c->sent += n;

    return n;
}

static void
s3_quic_set_packet_number(s3_quic_header_t *pkt, s3_quic_send_ctx_t *ctx)
{
    uint64_t delta;

    delta = ctx->pnum - ctx->largest_ack;
    pkt->number = ctx->pnum;

    if (delta <= 0x7F) {
        pkt->num_len = 1;
        pkt->trunc = ctx->pnum & 0xff;

    } else if (delta <= 0x7FFF) {
        pkt->num_len = 2;
        pkt->flags |= 0x1;
        pkt->trunc = ctx->pnum & 0xffff;

    } else if (delta <= 0x7FFFFF) {
        pkt->num_len = 3;
        pkt->flags |= 0x2;
        pkt->trunc = ctx->pnum & 0xffffff;

    } else {
        pkt->num_len = 4;
        pkt->flags |= 0x3;
        pkt->trunc = ctx->pnum & 0xffffffff;
    }
}

s3_int_t
s3_quic_negotiate_version(s3_connection_t *c, s3_quic_header_t *inpkt)
{
    size_t           len;
    s3_quic_header_t pkt;
    static u_char    buf[S3_QUIC_MAX_UDP_PAYLOAD_SIZE];

    s3_log_debug0(S3_LOG_DEBUG_EVENT, c->log, 0, "sending version negotiation packet");

    pkt.log = c->log;
    pkt.flags = S3_QUIC_PKT_LONG | S3_QUIC_PKT_FIXED_BIT;
    pkt.dcid = inpkt->scid;
    pkt.scid = inpkt->dcid;

    len = s3_quic_create_version_negotiation(&pkt, buf);

#ifdef S3_QUIC_DEBUG_PACKETS
    s3_log_debug3(S3_LOG_DEBUG_EVENT, c->log, 0, "quic vnego packet to send len:%uz %*xs", len, len,
                  buf);
#endif

    (void)s3_quic_send(c, buf, len, c->sockaddr, c->socklen);

    /*
     * the reference returns NGX_DONE here; the ssh3-c event loop uses
     * S3_ABORT as the "packet handled, the datagram is finished"
     * marker of s3_quic_handle_datagram()
     */
    return S3_ABORT;
}

s3_int_t
s3_quic_send_stateless_reset(s3_connection_t *c, s3_quic_conf_t *conf, s3_quic_header_t *pkt)
{
    u_char    *token;
    size_t     len, max;
    uint16_t   rndbytes;
    s3_int_t   rc;
    u_char     buf[S3_QUIC_MAX_SR_PACKET];

    s3_log_debug0(S3_LOG_DEBUG_EVENT, c->log, 0, "quic handle stateless reset output");

    if (pkt->len <= S3_QUIC_MIN_PKT_LEN) {
        return S3_DECLINED;
    }

    rc = s3_quic_stateless_reset_filter(c);
    if (rc != S3_OK) {
        return rc;
    }

    if (pkt->len <= S3_QUIC_MIN_SR_PACKET) {
        len = pkt->len - 1;

    } else {
        max = s3_min(S3_QUIC_MAX_SR_PACKET, pkt->len);

        if (RAND_bytes((u_char *)&rndbytes, sizeof(rndbytes)) != 1) {
            return S3_ERROR;
        }

        len = (rndbytes % (max - S3_QUIC_MIN_SR_PACKET)) + S3_QUIC_MIN_SR_PACKET;
    }

    if (RAND_bytes(buf, len - S3_QUIC_SR_TOKEN_LEN) != 1) {
        return S3_ERROR;
    }

    buf[0] &= ~S3_QUIC_PKT_LONG;
    buf[0] |= S3_QUIC_PKT_FIXED_BIT;

    token = &buf[len - S3_QUIC_SR_TOKEN_LEN];

    if (s3_quic_new_sr_token(c, &pkt->dcid, conf->sr_token_key, token) != S3_OK) {
        return S3_ERROR;
    }

#ifdef S3_QUIC_DEBUG_PACKETS
    s3_log_debug2(S3_LOG_DEBUG_EVENT, c->log, 0, "quic stateless reset to send len:%uz %*xs", len,
                  len, buf);
#endif

    (void)s3_quic_send(c, buf, len, c->sockaddr, c->socklen);

    return S3_DECLINED;
}

static s3_int_t
s3_quic_stateless_reset_filter(s3_connection_t *c)
{
    time_t      now;
    u_char      salt;
    s3_uint_t   i, n, m, hit;
    u_char      hash[20];

    static time_t   t;
    static u_char   rndbyte;
    static uint8_t  bitmap[65536];

    now = time(NULL);

    if (t != now) {
        t = now;

        if (RAND_bytes(&rndbyte, 1) != 1) {
            return S3_ERROR;
        }

        s3_memzero(bitmap, sizeof(bitmap));
    }

    hit = 0;

    for (i = 0; i < 3; i++) {
        salt = rndbyte + i;

        s3_quic_address_hash(c->sockaddr, c->socklen, 0, &salt, 1, hash);

        n = hash[0] | hash[1] << 8;
        m = 1 << hash[2] % 8;

        if (!(bitmap[n] & m)) {
            bitmap[n] |= m;

        } else {
            hit++;
        }
    }

    if (hit == 3) {
        return S3_DECLINED;
    }

    return S3_OK;
}

s3_int_t
s3_quic_send_cc(s3_connection_t *c)
{
    s3_quic_frame_t      *frame;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    if (qc->draining) {
        return S3_OK;
    }

    if (qc->closing && s3_current_msec - qc->last_cc < S3_QUIC_CC_MIN_INTERVAL) {
        /* dot not send CC too often */
        return S3_OK;
    }

    frame = s3_quic_alloc_frame(c);
    if (frame == NULL) {
        return S3_ERROR;
    }

    frame->level = qc->error_level;
    frame->type = qc->error_app ? S3_QUIC_FT_CONNECTION_CLOSE_APP : S3_QUIC_FT_CONNECTION_CLOSE;
    frame->u.close.error_code = qc->error;
    frame->u.close.frame_type = qc->error_ftype;

    if (qc->error_reason) {
        frame->u.close.reason.len = s3_strlen(qc->error_reason);
        frame->u.close.reason.data = (u_char *)qc->error_reason;
    }

    frame->ignore_congestion = 1;

    qc->last_cc = s3_current_msec;

    return s3_quic_frame_sendto(c, frame, 0, qc->path);
}

s3_int_t
s3_quic_send_early_cc(s3_connection_t *c, s3_quic_header_t *inpkt, s3_uint_t err,
                      const char *reason)
{
    ssize_t          len;
    s3_str_t         res;
    s3_quic_keys_t   keys;
    s3_quic_frame_t  frame;
    s3_quic_header_t pkt;

    static u_char    src[S3_QUIC_MAX_UDP_PAYLOAD_SIZE];
    static u_char    dst[S3_QUIC_MAX_UDP_PAYLOAD_SIZE];

    s3_memzero(&frame, sizeof(s3_quic_frame_t));
    s3_memzero(&pkt, sizeof(s3_quic_header_t));

    frame.level = inpkt->level;
    frame.type = S3_QUIC_FT_CONNECTION_CLOSE;
    frame.u.close.error_code = err;

    frame.u.close.reason.data = (u_char *)reason;
    frame.u.close.reason.len = s3_strlen(reason);

    len = s3_quic_create_frame(NULL, &frame);
    if (len > (ssize_t)S3_QUIC_MAX_UDP_PAYLOAD_SIZE) {
        return S3_ERROR;
    }

    len = s3_quic_create_frame(src, &frame);
    if (len == -1) {
        return S3_ERROR;
    }

    s3_memzero(&keys, sizeof(s3_quic_keys_t));

    pkt.keys = &keys;

    if (s3_quic_keys_set_initial_secret(pkt.keys, &inpkt->dcid, c->log) != S3_OK) {
        return S3_ERROR;
    }

    pkt.flags = S3_QUIC_PKT_FIXED_BIT | S3_QUIC_PKT_LONG | S3_QUIC_PKT_INITIAL;

    pkt.num_len = 1;
    /*
     * pkt.num = 0;
     * pkt.trunc = 0;
     */

    pkt.version = inpkt->version;
    pkt.log = c->log;
    pkt.level = inpkt->level;
    pkt.dcid = inpkt->scid;
    pkt.scid = inpkt->dcid;
    pkt.payload.data = src;
    pkt.payload.len = len;

    res.data = dst;

    s3_quic_log_packet(c->log, &pkt);

    if (s3_quic_encrypt(&pkt, &res) != S3_OK) {
        s3_quic_keys_cleanup(pkt.keys);
        return S3_ERROR;
    }

    if (s3_quic_send(c, res.data, res.len, c->sockaddr, c->socklen) < 0) {
        s3_quic_keys_cleanup(pkt.keys);
        return S3_ERROR;
    }

    s3_quic_keys_cleanup(pkt.keys);

    /* see s3_quic_negotiate_version() for the S3_ABORT marker */
    return S3_ABORT;
}

s3_int_t
s3_quic_send_retry(s3_connection_t *c, s3_quic_conf_t *conf, s3_quic_header_t *inpkt)
{
    time_t           expires;
    ssize_t          len;
    s3_str_t         res, token;
    s3_quic_header_t pkt;

    u_char           buf[S3_QUIC_RETRY_BUFFER_SIZE];
    u_char           dcid[S3_QUIC_SERVER_CID_LEN];
    u_char           tbuf[S3_QUIC_TOKEN_BUF_SIZE];

    expires = time(NULL) + S3_QUIC_RETRY_TOKEN_LIFETIME;

    token.data = tbuf;
    token.len = S3_QUIC_TOKEN_BUF_SIZE;

    if (s3_quic_new_token(c->log, c->sockaddr, c->socklen, conf->av_token_key, &token, &inpkt->dcid,
                          expires, 1) != S3_OK)
    {
        return S3_ERROR;
    }

    s3_memzero(&pkt, sizeof(s3_quic_header_t));
    pkt.flags = S3_QUIC_PKT_FIXED_BIT | S3_QUIC_PKT_LONG | S3_QUIC_PKT_RETRY;
    pkt.version = inpkt->version;
    pkt.log = c->log;

    pkt.odcid = inpkt->dcid;
    pkt.dcid = inpkt->scid;

    if (RAND_bytes(dcid, S3_QUIC_SERVER_CID_LEN) != 1) {
        return S3_ERROR;
    }

    pkt.scid.len = S3_QUIC_SERVER_CID_LEN;
    pkt.scid.data = dcid;

    pkt.token = token;

    res.data = buf;

    if (s3_quic_encrypt(&pkt, &res) != S3_OK) {
        return S3_ERROR;
    }

#ifdef S3_QUIC_DEBUG_PACKETS
    s3_log_debug2(S3_LOG_DEBUG_EVENT, c->log, 0, "quic packet to send len:%uz %xV", res.len, &res);
#endif

    len = s3_quic_send(c, res.data, res.len, c->sockaddr, c->socklen);
    if (len < 0) {
        return S3_ERROR;
    }

    s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "quic retry packet sent to %xV", &pkt.dcid);

    /*
     * RFC 9000, 17.2.5.1.  Sending a Retry Packet
     *
     * A server MUST NOT send more than one Retry
     * packet in response to a single UDP datagram.
     * S3_ABORT will stop quic_input() from processing further
     * (the ssh3-c marker, see s3_quic_negotiate_version())
     */
    return S3_ABORT;
}

s3_int_t
s3_quic_send_new_token(s3_connection_t *c, s3_quic_path_t *path)
{
    time_t                expires;
    s3_str_t              token;
    s3_chain_t           *out;
    s3_quic_frame_t      *frame;
    s3_quic_connection_t *qc;

    u_char                tbuf[S3_QUIC_TOKEN_BUF_SIZE];

    qc = s3_quic_get_connection(c);

    expires = time(NULL) + S3_QUIC_NEW_TOKEN_LIFETIME;

    token.data = tbuf;
    token.len = S3_QUIC_TOKEN_BUF_SIZE;

    if (s3_quic_new_token(c->log, path->sockaddr, path->socklen, qc->conf->av_token_key, &token,
                          NULL, expires, 0) != S3_OK)
    {
        return S3_ERROR;
    }

    out = s3_quic_copy_buffer(c, token.data, token.len);
    if (out == S3_CHAIN_ERROR) {
        return S3_ERROR;
    }

    frame = s3_quic_alloc_frame(c);
    if (frame == NULL) {
        return S3_ERROR;
    }

    frame->level = S3_QUIC_ENCRYPTION_APPLICATION;
    frame->type = S3_QUIC_FT_NEW_TOKEN;
    frame->data = out;
    frame->u.token.length = token.len;

    s3_quic_queue_frame(qc, frame);

    return S3_OK;
}

s3_int_t
s3_quic_send_ack(s3_connection_t *c, s3_quic_send_ctx_t *ctx)
{
    size_t                len, left;
    uint64_t              ack_delay;
    s3_buf_t             *b;
    s3_uint_t             i;
    s3_chain_t           *cl, **ll;
    s3_quic_frame_t      *frame;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    ack_delay = s3_current_msec - ctx->largest_received;
    ack_delay *= 1000;
    ack_delay >>= qc->tp.ack_delay_exponent;

    frame = s3_quic_alloc_frame(c);
    if (frame == NULL) {
        return S3_ERROR;
    }

    ll = &frame->data;
    b = NULL;

    for (i = 0; i < ctx->nranges; i++) {
        len = s3_quic_create_ack_range(NULL, ctx->ranges[i].gap, ctx->ranges[i].range);

        left = b ? b->end - b->last : 0;

        if (left < len) {
            cl = s3_quic_alloc_chain(c);
            if (cl == NULL) {
                return S3_ERROR;
            }

            *ll = cl;
            ll = &cl->next;

            b = cl->buf;
            left = b->end - b->last;

            if (left < len) {
                return S3_ERROR;
            }
        }

        b->last += s3_quic_create_ack_range(b->last, ctx->ranges[i].gap, ctx->ranges[i].range);

        frame->u.ack.ranges_length += len;
    }

    *ll = NULL;

    frame->level = ctx->level;
    frame->type = S3_QUIC_FT_ACK;
    frame->u.ack.largest = ctx->largest_range;
    frame->u.ack.delay = ack_delay;
    frame->u.ack.range_count = ctx->nranges;
    frame->u.ack.first_range = ctx->first_range;
    frame->len = s3_quic_create_frame(NULL, frame);

    s3_queue_insert_head(&ctx->frames, &frame->queue);

    return S3_OK;
}

s3_int_t
s3_quic_send_ack_range(s3_connection_t *c, s3_quic_send_ctx_t *ctx, uint64_t smallest,
                       uint64_t largest)
{
    s3_quic_frame_t      *frame;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    frame = s3_quic_alloc_frame(c);
    if (frame == NULL) {
        return S3_ERROR;
    }

    frame->level = ctx->level;
    frame->type = S3_QUIC_FT_ACK;
    frame->u.ack.largest = largest;
    frame->u.ack.delay = 0;
    frame->u.ack.range_count = 0;
    frame->u.ack.first_range = largest - smallest;

    s3_quic_queue_frame(qc, frame);

    return S3_OK;
}

s3_int_t
s3_quic_frame_sendto(s3_connection_t *c, s3_quic_frame_t *frame, size_t min, s3_quic_path_t *path)
{
    size_t                 max, max_payload, min_payload, pad;
    ssize_t                len, sent;
    s3_str_t               res;
    s3_msec_t              now;
    s3_quic_header_t       pkt;
    s3_quic_send_ctx_t    *ctx;
    s3_quic_congestion_t  *cg;
    s3_quic_connection_t  *qc;

    static u_char          src[S3_QUIC_MAX_UDP_PAYLOAD_SIZE];
    static u_char          dst[S3_QUIC_MAX_UDP_PAYLOAD_SIZE];

    qc = s3_quic_get_connection(c);
    cg = &qc->congestion;
    ctx = s3_quic_get_send_ctx(qc, frame->level);

    now = s3_current_msec;

    max = s3_quic_path_limit(c, path, path->mtu);

    /*
     * RFC 9000, 14.1.  a client expands every datagram carrying an
     * Initial packet, not only the ack-eliciting ones; the standalone
     * packets sent here (PTO probes, path validation) need the same
     * floor as the coalesced ones in s3_quic_create_datagrams()
     */
    if (qc->client && frame->level == S3_QUIC_ENCRYPTION_INITIAL) {
        min = s3_max(min, S3_QUIC_MIN_INITIAL_SIZE);
    }

    s3_log_debug3(S3_LOG_DEBUG_EVENT, c->log, 0, "quic sendto %s packet max:%uz min:%uz",
                  s3_quic_level_name(ctx->level), max, min);

    if (cg->in_flight >= cg->window && !frame->ignore_congestion) {
        s3_quic_free_frame(c, frame);
        return S3_AGAIN;
    }

    s3_quic_init_packet(c, ctx, &pkt, path);

    min_payload = s3_quic_payload_size(&pkt, min);
    max_payload = s3_quic_payload_size(&pkt, max);

    /* RFC 9001, 5.4.2.  Header Protection Sample */
    pad = 4 - pkt.num_len;
    min_payload = s3_max(min_payload, pad);

    if (min_payload > max_payload) {
        s3_quic_free_frame(c, frame);
        return S3_AGAIN;
    }

    len = s3_quic_create_frame(NULL, frame);
    if ((size_t)len > max_payload) {
        s3_quic_free_frame(c, frame);
        return S3_AGAIN;
    }

    len = s3_quic_create_frame(src, frame);
    if (len == -1) {
        s3_quic_free_frame(c, frame);
        return S3_ERROR;
    }

    if (len < (ssize_t)min_payload) {
        s3_memset(src + len, S3_QUIC_FT_PADDING, min_payload - len);
        len = min_payload;
    }

    pkt.payload.data = src;
    pkt.payload.len = len;

    pkt.client = s3_quic_get_connection(c)->client;

    res.data = dst;

    s3_quic_log_packet(c->log, &pkt);

    if (s3_quic_encrypt(&pkt, &res) != S3_OK) {
        s3_quic_free_frame(c, frame);
        return S3_ERROR;
    }

    frame->pnum = ctx->pnum;
    frame->send_time = now;
    frame->plen = res.len;

    ctx->pnum++;

    sent = s3_quic_send(c, res.data, res.len, path->sockaddr, path->socklen);
    if (sent < 0) {
        s3_quic_free_frame(c, frame);
        return sent;
    }

    path->sent += sent;

    if (frame->need_ack && !qc->closing) {
        s3_queue_insert_tail(&ctx->sent, &frame->queue);

        cg->in_flight += frame->plen;

    } else {
        s3_quic_free_frame(c, frame);
        return S3_OK;
    }

    s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "quic congestion send if:%uz", cg->in_flight);

    if (!qc->send_timer_set) {
        qc->send_timer_set = 1;
        s3_event_add_timer(c->read, qc->tp.max_idle_timeout);
    }

    s3_quic_set_lost_timer(c);

    return S3_OK;
}

size_t
s3_quic_path_limit(s3_connection_t *c, s3_quic_path_t *path, size_t size)
{
    off_t max;

    (void)c;

    if (!path->validated) {
        max = path->received * 3;
        max = (path->sent >= max) ? 0 : max - path->sent;

        if ((off_t)size > max) {
            return max;
        }
    }

    return size;
}

s3_int_t
s3_quic_send_datagram(s3_connection_t *c, const u_char *data, size_t len)
{
    s3_chain_t           *out;
    s3_quic_frame_t      *frame;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    /*
     * RFC 9221, 5.  Datagram Handlers: the frame size is limited by
     * the peer transport parameter; the conf value of 0 disables
     * datagrams entirely (porting map 3.4.2)
     */
    if (qc->conf->max_datagram_frame_size == 0
        || (s3_uint_t)len > qc->ctp.max_datagram_frame_size
        || qc->ctp.max_datagram_frame_size == 0)
    {
        s3_log_error(S3_LOG_INFO, c->log, 0, "quic datagram of size %uz is too large", len);
        return S3_ERROR;
    }

    out = s3_quic_copy_buffer(c, (u_char *)data, len);
    if (out == S3_CHAIN_ERROR) {
        return S3_ERROR;
    }

    frame = s3_quic_alloc_frame(c);
    if (frame == NULL) {
        s3_quic_free_chain(c, out);
        return S3_ERROR;
    }

    frame->level = S3_QUIC_ENCRYPTION_APPLICATION;
    frame->type = S3_QUIC_FT_DATAGRAM_WITH_LENGTH;
    frame->data = out;
    frame->u.datagram.length = len;

    s3_quic_queue_frame(qc, frame);

    return S3_OK;
}
