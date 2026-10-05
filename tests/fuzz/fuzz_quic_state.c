/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the first stateful libFuzzer harness: one QUIC connection context
 * lives across the packets of an input, every record is decoded by
 * s3_quic_parse_frame() and fed to the public frame handlers, so the
 * ack ranges, the congestion window, the flow-control limits and the
 * stream table mutate in sequence (the earlier targets fuzzed pure
 * decoders)
 *
 * covered: the frame decoder plus s3_quic_handle_ack_frame(),
 * s3_quic_handle_stream_frame() and the flow-control handler family
 * of s3_quic_streams.c, the s3_quic_ack_packet() range bookkeeping
 * and the stream recv-buffer reads
 * not covered: header protection and decryption (the TLS handshake is
 * not raised, the secrets are seeded directly like test_quic_ack.c
 * does), the packet-level dispatch of s3_quic.c and the static
 * handlers (CONNECTION_CLOSE, NEW_CONNECTION_ID, PATH_*, CRYPTO,
 * DATAGRAM), and the send path (the harness never sends, pkt->need_ack
 * is held at 0 so no ack frame is scheduled)
 */

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/ssl.h>

#include <stdint.h>
#include <stdlib.h>

#include <s3_core.h>

#include <s3_nonblocking.h>

#include <s3_quic.h>
#include <s3_quic_connection.h>
#include <s3_quic_ack.h>
#include <s3_quic_frames.h>
#include <s3_quic_streams.h>

#include "s3_fuzz.h"

/*
 * the record is [meta][pn:2][len:2][payload:len]: the meta low bits
 * pick the packet protection flags (the frame permission table keys
 * off them), pn is the synthetic packet number of the ack bookkeeping
 * and the payload is a run of QUIC frames
 */

#define S3_FUZZ_QUIC_REC_HDR 5
#define S3_FUZZ_QUIC_REC_MAX 2048
#define S3_FUZZ_QUIC_ENC_MAX 16384
#define S3_FUZZ_QUIC_NSEEDS  4
#define S3_FUZZ_QUIC_PLEN    1200

#define S3_FUZZ_QUIC_SEL_SHORT   0
#define S3_FUZZ_QUIC_SEL_INITIAL 1
#define S3_FUZZ_QUIC_SEL_HS      2
#define S3_FUZZ_QUIC_SEL_ZRTT    3
#define S3_FUZZ_QUIC_SEL_LAST    4

typedef struct {
    s3_pool_t            *pool;
    s3_event_ctx_t        ctx;
    s3_log_t              log;
    s3_quic_conf_t        conf;
    s3_fd_t               fd;
    s3_connection_t      *conn;
    s3_quic_connection_t *qc;
} s3_fuzz_quic_env_t;

static s3_fuzz_quic_env_t s3_fuzz_quic_env;

static const uint8_t s3_fuzz_quic_flags[S3_FUZZ_QUIC_SEL_LAST] = {
    0x40, /* short header, 1-RTT */
    0xC0, /* long header, Initial */
    0xE0, /* long header, Handshake */
    0xD0, /* long header, 0-RTT */
};

static const s3_uint_t s3_fuzz_quic_level[S3_FUZZ_QUIC_SEL_LAST] = {
    S3_QUIC_ENCRYPTION_APPLICATION, S3_QUIC_ENCRYPTION_INITIAL, S3_QUIC_ENCRYPTION_HANDSHAKE,
    S3_QUIC_ENCRYPTION_APPLICATION, /* 0-RTT shares the app space */
};

static void
s3_fuzz_env_done(s3_fuzz_quic_env_t *env)
{
    s3_queue_t *q;
    s3_event_t *ev;

    if (env->qc != NULL) {
        (void)s3_quic_close_streams(env->conn, env->qc);

        if (env->qc->push.timer_set) {
            s3_event_del_timer(&env->qc->push);
        }

        if (env->qc->pto.timer_set) {
            s3_event_del_timer(&env->qc->pto);
        }

        if (env->qc->close.timer_set) {
            s3_event_del_timer(&env->qc->close);
        }

        if (env->qc->path_validation.timer_set) {
            s3_event_del_timer(&env->qc->path_validation);
        }

        if (env->qc->key_update.timer_set) {
            s3_event_del_timer(&env->qc->key_update);
        }

        s3_quic_keys_cleanup(env->qc->keys);
    }

    /* the events still linked into the posted queue are unlinked, the
     * handlers never run outside the event loop the harness has not */

    while (!s3_queue_empty(&env->ctx.posted_events)) {
        q = s3_queue_head(&env->ctx.posted_events);
        ev = s3_queue_data(q, s3_event_t, queue);

        s3_delete_posted_event(ev);
    }

    if (env->conn != NULL) {
        s3_close_connection(env->conn); /* destroys the connection pool */
    }

    if (env->fd != -1) {
        (void)close(env->fd);
    }

    if (env->pool != NULL) {
        s3_destroy_pool(env->pool);
    }

    s3_memzero(env, sizeof(s3_fuzz_quic_env_t));

    env->fd = -1;
}

/*
 * the minimal connection context of the unit test factory (the
 * s3_quic_new_connection() shape without the sockets and the crypto):
 * realistic transport parameters, congestion window, path mtu and the
 * seeded secrets, so the handlers work on the state they see in
 * production
 */

static s3_int_t
s3_fuzz_env_init(s3_fuzz_quic_env_t *env)
{
    static uint8_t         secret[32];
    struct sockaddr_in     sa;
    socklen_t              slen;
    s3_quic_socket_t      *qsock;
    s3_quic_path_t        *path;
    s3_quic_tp_t          *ctp;
    s3_uint_t              i, level;
    static const s3_uint_t levels[3] = {
        S3_QUIC_ENCRYPTION_INITIAL,
        S3_QUIC_ENCRYPTION_HANDSHAKE,
        S3_QUIC_ENCRYPTION_APPLICATION,
    };

    s3_memzero(env, sizeof(s3_fuzz_quic_env_t));

    env->fd = -1;

    env->pool = s3_create_pool((size_t)S3_DEFAULT_POOL_SIZE, &env->log);
    if (env->pool == NULL) {
        return S3_ERROR;
    }

    s3_memzero(&env->ctx, sizeof(s3_event_ctx_t));
    env->ctx.log = &env->log;
    env->ctx.pool = env->pool;
    s3_queue_init(&env->ctx.posted_events);

    if (s3_event_timer_init(&env->ctx) != S3_OK) {
        return S3_ERROR;
    }

    env->conf.ctx = &env->ctx;
    env->conf.handshake_timeout = 10000;
    env->conf.idle_timeout = 60000;
    env->conf.stream_buffer_size = 16384;
    env->conf.max_concurrent_streams_bidi = 16;
    env->conf.max_concurrent_streams_uni = 16;
    env->conf.active_connection_id_limit = 8;
    env->conf.max_datagram_frame_size = 1200;
    env->conf.stream_reject_code_uni = S3_QUIC_ERR_CONNECTION_REFUSED;
    env->conf.stream_reject_code_bidi = S3_QUIC_ERR_CONNECTION_REFUSED;

    env->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (env->fd == -1) {
        return S3_ERROR;
    }

    if (s3_nonblocking(env->fd) != S3_OK) {
        return S3_ERROR;
    }

    s3_memzero(&sa, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(env->fd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
        return S3_ERROR;
    }

    env->conn = s3_get_connection(&env->ctx, env->fd);
    if (env->conn == NULL) {
        return S3_ERROR;
    }

    env->conn->pool = s3_create_pool((size_t)S3_DEFAULT_POOL_SIZE, &env->log);
    if (env->conn->pool == NULL) {
        return S3_ERROR;
    }

    slen = sizeof(sa);

    if (getsockname(env->fd, (struct sockaddr *)&sa, &slen) == -1) {
        return S3_ERROR;
    }

    env->conn->sockaddr = (struct sockaddr *)s3_palloc(env->conn->pool, sizeof(sa));
    if (env->conn->sockaddr == NULL) {
        return S3_ERROR;
    }

    s3_memcpy(env->conn->sockaddr, &sa, sizeof(sa));
    env->conn->socklen = sizeof(sa);

    env->qc = s3_pcalloc(env->conn->pool, sizeof(s3_quic_connection_t));
    if (env->qc == NULL) {
        return S3_ERROR;
    }

    env->qc->keys = s3_pcalloc(env->conn->pool, sizeof(s3_quic_keys_t));
    if (env->qc->keys == NULL) {
        return S3_ERROR;
    }

    env->qc->keys->is_client = 0;

    s3_rbtree_init(&env->qc->streams.tree, &env->qc->streams.sentinel,
                   s3_quic_rbtree_insert_stream);

    s3_queue_init(&env->qc->streams.uninitialized);
    s3_queue_init(&env->qc->streams.free);

    for (i = 0; i < S3_QUIC_SEND_CTX_LAST; i++) {
        s3_queue_init(&env->qc->send_ctx[i].frames);
        s3_queue_init(&env->qc->send_ctx[i].sending);
        s3_queue_init(&env->qc->send_ctx[i].sent);

        env->qc->send_ctx[i].largest_pn = S3_QUIC_UNSET_PN;
        env->qc->send_ctx[i].largest_ack = S3_QUIC_UNSET_PN;
        env->qc->send_ctx[i].largest_range = S3_QUIC_UNSET_PN;
        env->qc->send_ctx[i].pending_ack = S3_QUIC_UNSET_PN;
    }

    env->qc->send_ctx[0].level = S3_QUIC_ENCRYPTION_INITIAL;
    env->qc->send_ctx[1].level = S3_QUIC_ENCRYPTION_HANDSHAKE;
    env->qc->send_ctx[2].level = S3_QUIC_ENCRYPTION_APPLICATION;

    s3_queue_init(&env->qc->free_frames);

    s3_quic_init_rtt(env->qc);

    env->qc->ctx = &env->ctx;

    /*
     * the event handlers are left NULL: the harness runs no event
     * loop, the events are only posted and timed, never fired
     */

    env->qc->pto.log = env->conn->log;
    env->qc->pto.data = env->conn;

    env->qc->push.log = env->conn->log;
    env->qc->push.data = env->conn;

    env->qc->close.log = env->conn->log;
    env->qc->close.data = env->conn;

    env->qc->path_validation.log = env->conn->log;
    env->qc->path_validation.data = env->conn;

    env->qc->key_update.log = env->conn->log;
    env->qc->key_update.data = env->conn;

    env->qc->conf = &env->conf;

    if (s3_quic_init_transport_params(&env->qc->tp, &env->conf) != S3_OK) {
        return S3_ERROR;
    }

    ctp = &env->qc->ctp;

    ctp->max_udp_payload_size = S3_QUIC_MAX_UDP_PAYLOAD_SIZE;
    ctp->ack_delay_exponent = S3_QUIC_DEFAULT_ACK_DELAY_EXPONENT;
    ctp->max_ack_delay = S3_QUIC_DEFAULT_MAX_ACK_DELAY;
    ctp->active_connection_id_limit = 2;

    env->qc->streams.recv_max_data = env->qc->tp.initial_max_data;
    env->qc->streams.recv_window = env->qc->streams.recv_max_data;
    env->qc->streams.client_max_streams_uni = env->qc->tp.initial_max_streams_uni;
    env->qc->streams.client_max_streams_bidi = env->qc->tp.initial_max_streams_bidi;

    env->qc->congestion.window =
        s3_min(10 * S3_QUIC_MIN_INITIAL_SIZE, s3_max(2 * S3_QUIC_MIN_INITIAL_SIZE, 14720));
    env->qc->congestion.ssthresh = (size_t)-1;
    env->qc->congestion.mtu = S3_QUIC_MIN_INITIAL_SIZE;
    env->qc->congestion.recovery_start = s3_current_msec - 1;

    env->qc->max_frames = 10000;

    path = s3_pcalloc(env->conn->pool, sizeof(s3_quic_path_t));
    if (path == NULL) {
        return S3_ERROR;
    }

    s3_queue_init(&path->queue);

    path->mtu = S3_QUIC_MIN_INITIAL_SIZE;
    path->mtud = 1472;
    path->max_mtu = S3_QUIC_MAX_UDP_PAYLOAD_SIZE;

    for (i = 0; i < S3_QUIC_PATH_RETRIES; i++) {
        path->mtu_pnum[i] = S3_QUIC_UNSET_PN;
    }

    env->qc->path = path;

    qsock = s3_pcalloc(env->conn->pool, sizeof(s3_quic_socket_t));
    if (qsock == NULL) {
        return S3_ERROR;
    }

    qsock->quic = env->qc;
    env->conn->udp = (struct s3_udp_connection_s *)qsock;

    /*
     * the secrets a handshake would derive, both directions of every
     * space: s3_quic_ack_packet() passes its keys gate, the
     * ack-range bookkeeping runs for real
     */

    for (i = 0; i < 32; i++) {
        secret[i] = (uint8_t)(0x11 * (i + 1));
    }

    for (level = 0; level < 3; level++) {
        for (i = 0; i < 2; i++) {
            if (s3_quic_keys_set_encryption_secret(&env->log, (s3_int_t)i, env->qc->keys,
                                                   levels[level], TLS1_3_CK_AES_128_GCM_SHA256,
                                                   secret, sizeof(secret)) != S3_OK) {
                return S3_ERROR;
            }
        }
    }

    /*
     * the packets the ack frames can acknowledge: a few sent pings in
     * every number space, the in-flight accounting kept consistent
     * with the send path
     */

    for (i = 0; i < S3_QUIC_SEND_CTX_LAST; i++) {
        s3_quic_frame_t    *f;
        s3_quic_send_ctx_t *ctx = &env->qc->send_ctx[i];
        s3_uint_t           j;

        for (j = 0; j < S3_FUZZ_QUIC_NSEEDS; j++) {

            f = s3_quic_alloc_frame(env->conn);
            if (f == NULL) {
                return S3_ERROR;
            }

            f->level = ctx->level;
            f->type = S3_QUIC_FT_PING;
            f->pnum = j;
            f->plen = S3_FUZZ_QUIC_PLEN;
            f->send_time = 0;

            s3_queue_insert_tail(&ctx->sent, &f->queue);

            env->qc->congestion.in_flight += S3_FUZZ_QUIC_PLEN;
        }

        ctx->pnum = S3_FUZZ_QUIC_NSEEDS;
    }

    return S3_OK;
}

/*
 * the encode/decode contract on the parsed frame: the re-encode
 * parses back in exactly the announced size with the same fields
 * (the PADDING, ACK_ECN and NEW_TOKEN types have no wire encoder on
 * the library side and are skipped, like the STREAM off/len coding
 * bits the encoder normalizes)
 */

static void
s3_fuzz_roundtrip(s3_quic_header_t *pkt, s3_quic_frame_t *f)
{
    s3_buf_t        buf;
    s3_chain_t      chain;
    s3_quic_frame_t f2;
    u_char         *out;
    ssize_t         len, n;

    switch (f->type) {
    case S3_QUIC_FT_PADDING:
    case S3_QUIC_FT_ACK_ECN:
    case S3_QUIC_FT_NEW_TOKEN:
        return;
    }

    len = s3_quic_create_frame(NULL, f);

    if (len <= 0 || len > S3_FUZZ_QUIC_ENC_MAX) {
        return;
    }

    out = malloc((size_t)len);
    if (out == NULL) {
        return;
    }

    if (s3_quic_create_frame(out, f) != len) {
        s3_fuzz_trap();
    }

    s3_memzero(&f2, sizeof(s3_quic_frame_t));
    s3_memzero(&buf, sizeof(s3_buf_t));
    buf.temporary = 1;

    chain.buf = &buf;
    chain.next = NULL;
    f2.data = &chain;

    n = s3_quic_parse_frame(pkt, out, out + len, &f2);

    if (n != len) {
        s3_fuzz_trap();
    }

    if (f2.type != f->type) {
        s3_fuzz_trap();
    }

    switch (f->type) {

    case S3_QUIC_FT_ACK:
        if (f2.u.ack.largest != f->u.ack.largest || f2.u.ack.delay != f->u.ack.delay ||
            f2.u.ack.range_count != f->u.ack.range_count ||
            f2.u.ack.first_range != f->u.ack.first_range) {
            s3_fuzz_trap();
        }

        break;

    case S3_QUIC_FT_CRYPTO:
        if (f2.u.crypto.offset != f->u.crypto.offset || f2.u.crypto.length != f->u.crypto.length) {
            s3_fuzz_trap();
        }

        break;

    case S3_QUIC_FT_STREAM:
        if (f2.u.stream.stream_id != f->u.stream.stream_id ||
            f2.u.stream.offset != f->u.stream.offset || f2.u.stream.length != f->u.stream.length ||
            f2.u.stream.fin != f->u.stream.fin) {
            s3_fuzz_trap();
        }

        break;

    case S3_QUIC_FT_NEW_CONNECTION_ID:
        if (f2.u.ncid.seqnum != f->u.ncid.seqnum || f2.u.ncid.retire != f->u.ncid.retire ||
            f2.u.ncid.len != f->u.ncid.len ||
            s3_memcmp(f2.u.ncid.cid, f->u.ncid.cid, f->u.ncid.len) != 0 ||
            s3_memcmp(f2.u.ncid.srt, f->u.ncid.srt, S3_QUIC_SR_TOKEN_LEN) != 0) {
            s3_fuzz_trap();
        }

        break;

    case S3_QUIC_FT_CONNECTION_CLOSE:
        if (f2.u.close.error_code != f->u.close.error_code ||
            f2.u.close.frame_type != f->u.close.frame_type ||
            f2.u.close.reason.len != f->u.close.reason.len) {
            s3_fuzz_trap();
        }

        break;

    case S3_QUIC_FT_CONNECTION_CLOSE_APP:
        if (f2.u.close.error_code != f->u.close.error_code ||
            f2.u.close.reason.len != f->u.close.reason.len) {
            s3_fuzz_trap();
        }

        break;

    case S3_QUIC_FT_PATH_CHALLENGE:
    case S3_QUIC_FT_PATH_RESPONSE:
        if (s3_memcmp(f2.u.path_challenge.data, f->u.path_challenge.data, 8) != 0) {
            s3_fuzz_trap();
        }

        break;

    case S3_QUIC_FT_DATAGRAM:
    case S3_QUIC_FT_DATAGRAM_WITH_LENGTH:
        if (f2.u.datagram.length != f->u.datagram.length) {
            s3_fuzz_trap();
        }

        break;

    default:
        /* the scalar frames: the limit or id field of the union
         * overlaps at offset 0 in every remaining family */

        if (f2.u.max_data.max_data != f->u.max_data.max_data) {
            s3_fuzz_trap();
        }

        break;
    }

    free(out);
}

static s3_int_t
s3_fuzz_frame_dispatch(s3_fuzz_quic_env_t *env, s3_quic_header_t *pkt, s3_quic_frame_t *f)
{
    switch (f->type) {

    case S3_QUIC_FT_ACK:
    case S3_QUIC_FT_ACK_ECN:
        return s3_quic_handle_ack_frame(env->conn, pkt, f);

    case S3_QUIC_FT_STREAM:
        return s3_quic_handle_stream_frame(env->conn, pkt, f);

    case S3_QUIC_FT_MAX_DATA:
        return s3_quic_handle_max_data_frame(env->conn, &f->u.max_data);

    case S3_QUIC_FT_MAX_STREAM_DATA:
        return s3_quic_handle_max_stream_data_frame(env->conn, pkt, &f->u.max_stream_data);

    case S3_QUIC_FT_MAX_STREAMS:
    case S3_QUIC_FT_MAX_STREAMS2:
        return s3_quic_handle_max_streams_frame(env->conn, pkt, &f->u.max_streams);

    case S3_QUIC_FT_DATA_BLOCKED:
        return s3_quic_handle_data_blocked_frame(env->conn, pkt, &f->u.data_blocked);

    case S3_QUIC_FT_STREAM_DATA_BLOCKED:
        return s3_quic_handle_stream_data_blocked_frame(env->conn, pkt, &f->u.stream_data_blocked);

    case S3_QUIC_FT_STREAMS_BLOCKED:
    case S3_QUIC_FT_STREAMS_BLOCKED2:
        return s3_quic_handle_streams_blocked_frame(env->conn, pkt, &f->u.streams_blocked);

    case S3_QUIC_FT_RESET_STREAM:
        return s3_quic_handle_reset_stream_frame(env->conn, pkt, &f->u.reset_stream);

    case S3_QUIC_FT_STOP_SENDING:
        return s3_quic_handle_stop_sending_frame(env->conn, pkt, &f->u.stop_sending);

    default:
        /* the frames handled statically by s3_quic.c or carrying no
         * state: PADDING, PING, CRYPTO, NEW_TOKEN, NEW_CONNECTION_ID,
         * RETIRE_CONNECTION_ID, PATH_CHALLENGE/RESPONSE,
         * CONNECTION_CLOSE, HANDSHAKE_DONE, DATAGRAM */

        break;
    }

    return S3_OK;
}

/*
 * the application reads the stream data back: the recv buffer and its
 * shadow-refcount machinery under the real read path
 */

static void
s3_fuzz_drain_streams(s3_fuzz_quic_env_t *env)
{
    s3_rbtree_t      *tree;
    s3_rbtree_node_t *node;
    s3_quic_stream_t *qs;
    s3_chain_t       *out;

    tree = &env->qc->streams.tree;

    if (tree->root == tree->sentinel) {
        return;
    }

    node = s3_rbtree_min(tree->root, tree->sentinel);

    while (node) {
        qs = (s3_quic_stream_t *)node;
        node = s3_rbtree_next(tree, node);

        if (qs->recv.size != 0) {
            out = s3_quic_read_buffer(env->conn, &qs->recv, qs->recv.size);

            if (out != NULL) {
                s3_fuzz_sink(s3_buf_size(out->buf));
                s3_quic_free_chain(env->conn, out);
            }
        }

        s3_fuzz_sink((size_t)qs->recv.offset + (size_t)qs->recv.last_offset);
    }
}

static s3_int_t
s3_fuzz_process_record(s3_fuzz_quic_env_t *env, s3_quic_header_t *pkt, u_char *start, u_char *end)
{
    s3_buf_t        buf;
    s3_chain_t      chain;
    s3_quic_frame_t frame;
    ssize_t         len;
    u_char         *p;

    p = start;

    while (p < end) {

        s3_memzero(&frame, sizeof(s3_quic_frame_t));
        s3_memzero(&buf, sizeof(s3_buf_t));
        buf.temporary = 1;

        chain.buf = &buf;
        chain.next = NULL;
        frame.data = &chain;

        len = s3_quic_parse_frame(pkt, p, end, &frame);

        if (len == S3_ERROR) {
            /* a decode failure closes the connection in the real
             * dispatch, this input is over */

            return S3_ERROR;
        }

        s3_fuzz_roundtrip(pkt, &frame);

        if (s3_fuzz_frame_dispatch(env, pkt, &frame) != S3_OK) {
            return S3_ERROR;
        }

        p += len;
    }

    return S3_OK;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    s3_fuzz_quic_env_t *env = &s3_fuzz_quic_env;
    const u_char       *pos, *end;
    s3_quic_header_t    pkt;
    size_t              len;
    uint32_t            meta, pn, sel;

    if (s3_fuzz_env_init(env) != S3_OK) {
        s3_fuzz_env_done(env);

        return 0;
    }

    pos = (const u_char *)data;
    end = pos + size;

    while (end - pos >= S3_FUZZ_QUIC_REC_HDR) {

        meta = pos[0];
        pn = ((uint32_t)pos[1] << 8) | pos[2];
        len = ((size_t)pos[3] << 8) | pos[4];
        pos += S3_FUZZ_QUIC_REC_HDR;

        if (len > S3_FUZZ_QUIC_REC_MAX || (size_t)(end - pos) < len) {
            break;
        }

        sel = meta & 3u;

        s3_memzero(&pkt, sizeof(s3_quic_header_t));
        pkt.log = &env->log;
        pkt.flags = s3_fuzz_quic_flags[sel];
        pkt.level = s3_fuzz_quic_level[sel];
        pkt.pn = pn;
        pkt.need_ack = 0; /* the send path stays out of the harness */
        pkt.client = 0;   /* the server role, like s3_quic_run() */

        if (s3_fuzz_process_record(env, &pkt, (u_char *)pos, (u_char *)pos + len) != S3_OK) {
            break;
        }

        s3_fuzz_drain_streams(env);

        /* the per-packet ack bookkeeping: the range state of the
         * record space mutates, the zero need_ack keeps it clear of
         * the ack scheduling */

        (void)s3_quic_ack_packet(env->conn, &pkt);

        pos += len;
    }

    s3_fuzz_sink((size_t)env->qc->error + (size_t)env->qc->nframes);

    s3_fuzz_env_done(env);

    return 0;
}
