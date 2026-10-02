/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <s3_quic.h>
#include <s3_quic_connection.h>

#define S3_QUIC_STREAM_GONE (void *)-1

static s3_int_t          s3_quic_do_reset_stream(s3_quic_stream_t *qs, s3_uint_t err);
static s3_int_t          s3_quic_shutdown_stream_send(s3_connection_t *c);
static s3_int_t          s3_quic_shutdown_stream_recv(s3_connection_t *c);
static s3_quic_stream_t *s3_quic_get_stream(s3_connection_t *c, uint64_t id);
static s3_int_t          s3_quic_reject_stream(s3_connection_t *c, uint64_t id);
static void              s3_quic_init_stream_handler(s3_event_t *ev);
static s3_int_t          s3_quic_do_init_streams(s3_connection_t *c);
static s3_quic_stream_t *s3_quic_create_stream(s3_connection_t *c, uint64_t id);
static void              s3_quic_empty_handler(s3_event_t *ev);
static ssize_t           s3_quic_stream_recv(s3_connection_t *c, u_char *buf, size_t size);
static s3_chain_t       *s3_quic_stream_send_chain(s3_connection_t *c, s3_chain_t *in, off_t limit);
static s3_int_t          s3_quic_stream_flush(s3_quic_stream_t *qs);
static void              s3_quic_stream_cleanup_handler(void *data);
static s3_int_t          s3_quic_close_stream(s3_quic_stream_t *qs);
static s3_int_t          s3_quic_can_shutdown(s3_connection_t *c);
static s3_int_t          s3_quic_control_flow(s3_quic_stream_t *qs, uint64_t last);
static s3_int_t          s3_quic_update_flow(s3_quic_stream_t *qs, uint64_t last);
static s3_int_t          s3_quic_update_max_stream_data(s3_quic_stream_t *qs);
static s3_int_t          s3_quic_update_max_data(s3_connection_t *c);
static void              s3_quic_set_event(s3_quic_connection_t *qc, s3_event_t *ev);

s3_connection_t *
s3_quic_open_stream(s3_connection_t *c, s3_uint_t bidi)
{
    uint64_t              id;
    s3_connection_t      *pc, *sc;
    s3_quic_stream_t     *qs;
    s3_quic_connection_t *qc;

    /*
     * the reference resolves the stream pseudo connection through
     * c->quic (porting map 4.3.2: here the stream lives in c->data);
     * a main quic connection is recognized by c->udp
     */
    pc = c;

    if (s3_quic_get_connection(c) == NULL && c->data != NULL) {
        pc = ((s3_quic_stream_t *)c->data)->parent;
    }

    qc = s3_quic_get_connection(pc);

    if (qc->closing) {
        return NULL;
    }

    if (bidi) {

        if (qc->client) {

            if (qc->streams.client_streams_bidi >= qc->streams.client_max_streams_bidi) {
                s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0,
                              "quic too many client bidi streams:%uL",
                              qc->streams.client_streams_bidi);
                return NULL;
            }

            id = (qc->streams.client_streams_bidi << 2);

            s3_log_debug3(S3_LOG_DEBUG_EVENT, c->log, 0,
                          "quic creating client bidi stream streams:%uL max:%uL id:0x%xL",
                          qc->streams.client_streams_bidi, qc->streams.client_max_streams_bidi, id);

            qc->streams.client_streams_bidi++;

        } else {

            if (qc->streams.server_streams_bidi >= qc->streams.server_max_streams_bidi) {
                s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0,
                              "quic too many server bidi streams:%uL",
                              qc->streams.server_streams_bidi);
                return NULL;
            }

            id = (qc->streams.server_streams_bidi << 2) | S3_QUIC_STREAM_SERVER_INITIATED;

            s3_log_debug3(S3_LOG_DEBUG_EVENT, c->log, 0,
                          "quic creating server bidi stream streams:%uL max:%uL id:0x%xL",
                          qc->streams.server_streams_bidi, qc->streams.server_max_streams_bidi, id);

            qc->streams.server_streams_bidi++;
        }

    } else {

        if (qc->client) {

            if (qc->streams.client_streams_uni >= qc->streams.client_max_streams_uni) {
                s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "quic too many client uni streams:%uL",
                              qc->streams.client_streams_uni);
                return NULL;
            }

            id = (qc->streams.client_streams_uni << 2) | S3_QUIC_STREAM_UNIDIRECTIONAL;

            s3_log_debug3(S3_LOG_DEBUG_EVENT, c->log, 0,
                          "quic creating client uni stream streams:%uL max:%uL id:0x%xL",
                          qc->streams.client_streams_uni, qc->streams.client_max_streams_uni, id);

            qc->streams.client_streams_uni++;

        } else {

            if (qc->streams.server_streams_uni >= qc->streams.server_max_streams_uni) {
                s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "quic too many server uni streams:%uL",
                              qc->streams.server_streams_uni);
                return NULL;
            }

            id = (qc->streams.server_streams_uni << 2) | S3_QUIC_STREAM_SERVER_INITIATED |
                 S3_QUIC_STREAM_UNIDIRECTIONAL;

            s3_log_debug3(S3_LOG_DEBUG_EVENT, c->log, 0,
                          "quic creating server uni stream streams:%uL max:%uL id:0x%xL",
                          qc->streams.server_streams_uni, qc->streams.server_max_streams_uni, id);

            qc->streams.server_streams_uni++;
        }
    }

    qs = s3_quic_create_stream(pc, id);
    if (qs == NULL) {
        return NULL;
    }

    sc = qs->connection;

    sc->write->active = 1;
    sc->write->ready = 1;

    if (bidi) {
        sc->read->active = 1;
    }

    return sc;
}

void
s3_quic_rbtree_insert_stream(s3_rbtree_node_t *temp, s3_rbtree_node_t *node,
                             s3_rbtree_node_t *sentinel)
{
    s3_rbtree_node_t **p;
    s3_quic_stream_t  *qn, *qnt;

    for (;;) {
        qn = (s3_quic_stream_t *)node;
        qnt = (s3_quic_stream_t *)temp;

        p = (qn->id < qnt->id) ? &temp->left : &temp->right;

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    s3_rbt_red(node);
}

s3_quic_stream_t *
s3_quic_find_stream(s3_rbtree_t *rbtree, uint64_t id)
{
    s3_rbtree_node_t *node, *sentinel;
    s3_quic_stream_t *qn;

    node = rbtree->root;
    sentinel = rbtree->sentinel;

    while (node != sentinel) {
        qn = (s3_quic_stream_t *)node;

        if (id == qn->id) {
            return qn;
        }

        node = (id < qn->id) ? node->left : node->right;
    }

    return NULL;
}

s3_int_t
s3_quic_close_streams(s3_connection_t *c, s3_quic_connection_t *qc)
{
    s3_queue_t       *q, posted_events;
    s3_rbtree_t      *tree;
    s3_connection_t  *sc;
    s3_rbtree_node_t *node;
    s3_quic_stream_t *qs;

    while (!s3_queue_empty(&qc->streams.uninitialized)) {
        q = s3_queue_head(&qc->streams.uninitialized);
        s3_queue_remove(q);

        qs = s3_queue_data(q, s3_quic_stream_t, queue);

        /*
         * unlike the reference, s3_close_connection() destroys the
         * stream pool itself and runs the cleanup handler
         */
        s3_close_connection(qs->connection);
    }

    tree = &qc->streams.tree;

    if (tree->root == tree->sentinel) {
        return S3_OK;
    }

    s3_queue_init(&posted_events);

    node = s3_rbtree_min(tree->root, tree->sentinel);

    while (node) {
        qs = (s3_quic_stream_t *)node;
        node = s3_rbtree_next(tree, node);
        sc = qs->connection;

        qs->recv_state = S3_QUIC_STREAM_RECV_RESET_RECVD;
        qs->send_state = S3_QUIC_STREAM_SEND_RESET_SENT;

        if (sc == NULL) {
            (void)s3_quic_close_stream(qs);
            continue;
        }

        sc->read->error = 1;
        sc->read->ready = 1;
        sc->write->error = 1;
        sc->write->ready = 1;

        /* the reference sets sc->close here; s3_connection_t has no
         * close flag, the ssh3 layer learns the state through the
         * event error/eof flags */

        if (sc->read->posted) {
            s3_delete_posted_event(sc->read);
        }

        s3_post_event(sc->read, &posted_events);
    }

    s3_event_process_posted(qc->ctx, &posted_events);

    if (tree->root == tree->sentinel) {
        return S3_OK;
    }

    s3_log_debug0(S3_LOG_DEBUG_EVENT, c->log, 0, "quic connection has active streams");

    return S3_AGAIN;
}

s3_int_t
s3_quic_reset_stream(s3_connection_t *c, s3_uint_t err)
{
    return s3_quic_do_reset_stream((s3_quic_stream_t *)c->data, err);
}

static s3_int_t
s3_quic_do_reset_stream(s3_quic_stream_t *qs, s3_uint_t err)
{
    s3_connection_t      *pc;
    s3_quic_frame_t      *frame;
    s3_quic_connection_t *qc;

    if (qs->send_state == S3_QUIC_STREAM_SEND_DATA_RECVD ||
        qs->send_state == S3_QUIC_STREAM_SEND_RESET_SENT ||
        qs->send_state == S3_QUIC_STREAM_SEND_RESET_RECVD) {
        return S3_OK;
    }

    qs->send_state = S3_QUIC_STREAM_SEND_RESET_SENT;
    qs->send_final_size = qs->send_offset;

    if (qs->connection) {
        qs->connection->write->error = 1;
    }

    pc = qs->parent;
    qc = s3_quic_get_connection(pc);

    s3_log_debug1(S3_LOG_DEBUG_EVENT, pc->log, 0, "quic stream id:0x%xL reset", qs->id);

    frame = s3_quic_alloc_frame(pc);
    if (frame == NULL) {
        return S3_ERROR;
    }

    frame->level = S3_QUIC_ENCRYPTION_APPLICATION;
    frame->type = S3_QUIC_FT_RESET_STREAM;
    frame->u.reset_stream.id = qs->id;
    frame->u.reset_stream.error_code = err;
    frame->u.reset_stream.final_size = qs->send_offset;

    s3_quic_queue_frame(qc, frame);

    s3_quic_free_buffer(pc, &qs->send);

    return S3_OK;
}

s3_int_t
s3_quic_shutdown_stream(s3_connection_t *c, int how)
{
    if (how == S3_RDWR_SHUTDOWN || how == S3_WRITE_SHUTDOWN) {
        if (s3_quic_shutdown_stream_send(c) != S3_OK) {
            return S3_ERROR;
        }
    }

    if (how == S3_RDWR_SHUTDOWN || how == S3_READ_SHUTDOWN) {
        if (s3_quic_shutdown_stream_recv(c) != S3_OK) {
            return S3_ERROR;
        }
    }

    return S3_OK;
}

static s3_int_t
s3_quic_shutdown_stream_send(s3_connection_t *c)
{
    s3_quic_stream_t *qs;

    qs = c->data;

    if (qs->send_state != S3_QUIC_STREAM_SEND_READY && qs->send_state != S3_QUIC_STREAM_SEND_SEND) {
        return S3_OK;
    }

    qs->send_state = S3_QUIC_STREAM_SEND_SEND;
    qs->send_final_size = (uint64_t)c->sent;

    s3_log_debug1(S3_LOG_DEBUG_EVENT, qs->parent->log, 0, "quic stream id:0x%xL send shutdown",
                  qs->id);

    return s3_quic_stream_flush(qs);
}

static s3_int_t
s3_quic_shutdown_stream_recv(s3_connection_t *c)
{
    s3_connection_t      *pc;
    s3_quic_frame_t      *frame;
    s3_quic_stream_t     *qs;
    s3_quic_connection_t *qc;

    qs = c->data;

    if (qs->recv_state != S3_QUIC_STREAM_RECV_RECV &&
        qs->recv_state != S3_QUIC_STREAM_RECV_SIZE_KNOWN) {
        return S3_OK;
    }

    pc = qs->parent;
    qc = s3_quic_get_connection(pc);

    if (qc->conf->stream_close_code == 0) {
        return S3_OK;
    }

    frame = s3_quic_alloc_frame(pc);
    if (frame == NULL) {
        return S3_ERROR;
    }

    s3_log_debug1(S3_LOG_DEBUG_EVENT, pc->log, 0, "quic stream id:0x%xL recv shutdown", qs->id);

    frame->level = S3_QUIC_ENCRYPTION_APPLICATION;
    frame->type = S3_QUIC_FT_STOP_SENDING;
    frame->u.stop_sending.id = qs->id;
    frame->u.stop_sending.error_code = (uint64_t)qc->conf->stream_close_code;

    s3_quic_queue_frame(qc, frame);

    return S3_OK;
}

static s3_quic_stream_t *
s3_quic_get_stream(s3_connection_t *c, uint64_t id)
{
    uint64_t              min_id;
    s3_event_t           *rev;
    s3_quic_stream_t     *qs;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    qs = s3_quic_find_stream(&qc->streams.tree, id);

    if (qs) {
        return qs;
    }

    if (qc->shutdown || qc->closing) {
        return S3_QUIC_STREAM_GONE;
    }

    s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "quic stream id:0x%xL is missing", id);

    if (id & S3_QUIC_STREAM_UNIDIRECTIONAL) {

        if (id & S3_QUIC_STREAM_SERVER_INITIATED) {
            if ((id >> 2) < qc->streams.server_streams_uni) {
                return S3_QUIC_STREAM_GONE;
            }

            qc->error = S3_QUIC_ERR_STREAM_STATE_ERROR;
            return NULL;
        }

        if ((id >> 2) < qc->streams.client_streams_uni) {
            return S3_QUIC_STREAM_GONE;
        }

        if ((id >> 2) >= qc->streams.client_max_streams_uni) {
            qc->error = S3_QUIC_ERR_STREAM_LIMIT_ERROR;
            return NULL;
        }

        min_id = (qc->streams.client_streams_uni << 2) | S3_QUIC_STREAM_UNIDIRECTIONAL;
        qc->streams.client_streams_uni = (id >> 2) + 1;

    } else {

        if (id & S3_QUIC_STREAM_SERVER_INITIATED) {
            if ((id >> 2) < qc->streams.server_streams_bidi) {
                return S3_QUIC_STREAM_GONE;
            }

            qc->error = S3_QUIC_ERR_STREAM_STATE_ERROR;
            return NULL;
        }

        if ((id >> 2) < qc->streams.client_streams_bidi) {
            return S3_QUIC_STREAM_GONE;
        }

        if ((id >> 2) >= qc->streams.client_max_streams_bidi) {
            qc->error = S3_QUIC_ERR_STREAM_LIMIT_ERROR;
            return NULL;
        }

        min_id = (qc->streams.client_streams_bidi << 2);
        qc->streams.client_streams_bidi = (id >> 2) + 1;
    }

    /*
     * RFC 9000, 2.1.  Stream Types and Identifiers
     *
     * successive streams of each type are created with numerically increasing
     * stream IDs.  A stream ID that is used out of order results in all
     * streams of that type with lower-numbered stream IDs also being opened.
     */

    qs = NULL;

    for (; min_id <= id; min_id += 0x04) {

        qs = s3_quic_create_stream(c, min_id);

        if (qs == NULL) {
            if (s3_quic_reject_stream(c, min_id) != S3_OK) {
                return NULL;
            }

            continue;
        }

        s3_queue_insert_tail(&qc->streams.uninitialized, &qs->queue);

        rev = qs->connection->read;
        rev->handler = s3_quic_init_stream_handler;

        if (qc->streams.initialized) {
            s3_post_event(rev, &qc->ctx->posted_events);

            if (qc->push.posted) {
                /*
                 * The posted stream can produce output immediately.
                 * By postponing the push event, we coalesce the stream
                 * output with queued frames in one UDP datagram.
                 */

                s3_delete_posted_event(&qc->push);
                s3_post_event(&qc->push, &qc->ctx->posted_events);
            }
        }
    }

    if (qs == NULL) {
        return S3_QUIC_STREAM_GONE;
    }

    return qs;
}

static s3_int_t
s3_quic_reject_stream(s3_connection_t *c, uint64_t id)
{
    uint64_t              code;
    s3_quic_frame_t      *frame;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    code = (id & S3_QUIC_STREAM_UNIDIRECTIONAL) ? (uint64_t)qc->conf->stream_reject_code_uni
                                                : (uint64_t)qc->conf->stream_reject_code_bidi;

    if (code == 0) {
        return S3_DECLINED;
    }

    s3_log_debug2(S3_LOG_DEBUG_EVENT, c->log, 0, "quic stream id:0x%xL reject err:0x%xL", id, code);

    frame = s3_quic_alloc_frame(c);
    if (frame == NULL) {
        return S3_ERROR;
    }

    frame->level = S3_QUIC_ENCRYPTION_APPLICATION;
    frame->type = S3_QUIC_FT_RESET_STREAM;
    frame->u.reset_stream.id = id;
    frame->u.reset_stream.error_code = code;
    frame->u.reset_stream.final_size = 0;

    s3_quic_queue_frame(qc, frame);

    frame = s3_quic_alloc_frame(c);
    if (frame == NULL) {
        return S3_ERROR;
    }

    frame->level = S3_QUIC_ENCRYPTION_APPLICATION;
    frame->type = S3_QUIC_FT_STOP_SENDING;
    frame->u.stop_sending.id = id;
    frame->u.stop_sending.error_code = code;

    s3_quic_queue_frame(qc, frame);

    return S3_OK;
}

static void
s3_quic_init_stream_handler(s3_event_t *ev)
{
    s3_connection_t      *c;
    s3_quic_stream_t     *qs;
    s3_quic_connection_t *qc;

    c = ev->data;
    qs = c->data;
    qc = s3_quic_get_connection(qs->parent);

    s3_log_debug0(S3_LOG_DEBUG_EVENT, c->log, 0, "quic init stream");

    if ((qs->id & S3_QUIC_STREAM_UNIDIRECTIONAL) == 0) {
        c->write->active = 1;
        c->write->ready = 1;
    }

    c->read->active = 1;

    s3_queue_remove(&qs->queue);

    /*
     * the reference hands the stream to the application through
     * c->listening->handler(c) (porting map 4.3.6); ssh3-c has no
     * listening sockets on streams and calls the conf->stream_handler
     * hook instead.  Without the hook the stream is rejected the way
     * the reference rejects a stream it cannot serve
     * (conf->stream_reject_code_*)
     */
    if (qc->conf->stream_handler != NULL) {
        qc->conf->stream_handler(c, qs);

    } else {
        (void)s3_quic_reject_stream(qs->parent, qs->id);
    }
}

s3_int_t
s3_quic_init_streams(s3_connection_t *c)
{
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    if (qc->streams.initialized) {
        return S3_OK;
    }

    /*
     * the reference validates the certificate chain here
     * (ngx_ssl_ocsp_validate()) and defers the initialization through
     * c->ssl->handler; ssh3-c has no ocsp layer, the streams are
     * initialized right away
     */

    return s3_quic_do_init_streams(c);
}

static s3_int_t
s3_quic_do_init_streams(s3_connection_t *c)
{
    s3_queue_t           *q;
    s3_quic_stream_t     *qs;
    s3_quic_connection_t *qc;

    s3_log_debug0(S3_LOG_DEBUG_EVENT, c->log, 0, "quic init streams");

    qc = s3_quic_get_connection(c);

    if (qc->conf->init) {
        if (qc->conf->init(c) != S3_OK) {
            return S3_ERROR;
        }
    }

    for (q = s3_queue_head(&qc->streams.uninitialized);
         q != s3_queue_sentinel(&qc->streams.uninitialized); q = s3_queue_next(q)) {
        qs = s3_queue_data(q, s3_quic_stream_t, queue);
        s3_post_event(qs->connection->read, &qc->ctx->posted_events);
    }

    qc->streams.initialized = 1;

    if (!qc->closing && qc->close.timer_set) {
        s3_event_del_timer(&qc->close);
    }

    return S3_OK;
}

static s3_quic_stream_t *
s3_quic_create_stream(s3_connection_t *c, uint64_t id)
{
    s3_pool_t            *pool;
    s3_queue_t           *q;
    struct sockaddr      *sockaddr;
    s3_connection_t      *sc;
    s3_uint_t             reusable;
    s3_quic_stream_t     *qs;
    s3_pool_cleanup_t    *cln;
    s3_quic_connection_t *qc;

    s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "quic stream id:0x%xL create", id);

    qc = s3_quic_get_connection(c);

    if (!s3_queue_empty(&qc->streams.free)) {
        q = s3_queue_head(&qc->streams.free);
        qs = s3_queue_data(q, s3_quic_stream_t, queue);
        s3_queue_remove(&qs->queue);

    } else {
        /*
         * the number of streams is limited by transport
         * parameters and application requirements
         */

        qs = s3_palloc(c->pool, sizeof(s3_quic_stream_t));
        if (qs == NULL) {
            return NULL;
        }
    }

    s3_memzero(qs, sizeof(s3_quic_stream_t));

    qs->node.key = (s3_rbtree_key_t)id;
    qs->parent = c;
    qs->id = id;
    qs->send_final_size = (uint64_t)-1;
    qs->recv_final_size = (uint64_t)-1;

    pool = s3_create_pool(S3_DEFAULT_POOL_SIZE, c->log);
    if (pool == NULL) {
        s3_queue_insert_tail(&qc->streams.free, &qs->queue);
        return NULL;
    }

    /*
     * the reference copies the parent log object into the stream pool
     * and sets the connection number in it; s3_log_t carries no
     * connection number and the stream connections use the parent log
     */

    sockaddr = s3_palloc(pool, c->socklen);
    if (sockaddr == NULL) {
        s3_destroy_pool(pool);
        s3_queue_insert_tail(&qc->streams.free, &qs->queue);
        return NULL;
    }

    s3_memcpy(sockaddr, c->sockaddr, c->socklen);

    /* the reference drops the reusable flag while the stream
     * connection is created (ngx_reusable_connection(c, 0)); the flag
     * lives in qc->reusable (porting map 4.3.9) */

    reusable = qc->reusable;
    qc->reusable = 0;

    sc = s3_get_connection(qc->ctx, c->fd);
    if (sc == NULL) {
        s3_destroy_pool(pool);
        s3_queue_insert_tail(&qc->streams.free, &qs->queue);
        qc->reusable = reusable;
        return NULL;
    }

    qs->connection = sc;

    sc->data = qs; /* the stream, the reference sc->quic */

    sc->shared = 1; /* do not close the parent descriptor */
    sc->pool = pool;
    sc->ssl = c->ssl;
    sc->sockaddr = sockaddr;
    sc->socklen = c->socklen;
    sc->local_sockaddr = c->local_sockaddr;
    sc->local_socklen = c->local_socklen;

    /* the address text and the connection counter do not exist in
     * s3_connection_t (porting map 4.3.7, 4.3.8) */

    sc->recv = s3_quic_stream_recv;

    /* s3_connection_t has no send method: the ssh3 layer calls
     * s3_quic_stream_send() directly */
    sc->send_chain = s3_quic_stream_send_chain;

    sc->log = c->log;
    sc->read->log = c->log;
    sc->write->log = c->log;

    sc->read->handler = s3_quic_empty_handler;
    sc->write->handler = s3_quic_empty_handler;

    if (id & S3_QUIC_STREAM_UNIDIRECTIONAL) {
        if (id & S3_QUIC_STREAM_SERVER_INITIATED) {
            qs->send_max_data = qc->ctp.initial_max_stream_data_uni;
            qs->recv_state = S3_QUIC_STREAM_RECV_DATA_READ;
            qs->send_state = S3_QUIC_STREAM_SEND_READY;

        } else {
            qs->recv_max_data = qc->tp.initial_max_stream_data_uni;
            qs->recv_state = S3_QUIC_STREAM_RECV_RECV;
            qs->send_state = S3_QUIC_STREAM_SEND_DATA_RECVD;
        }

    } else {
        if (id & S3_QUIC_STREAM_SERVER_INITIATED) {
            qs->send_max_data = qc->ctp.initial_max_stream_data_bidi_remote;
            qs->recv_max_data = qc->tp.initial_max_stream_data_bidi_local;

        } else {
            qs->send_max_data = qc->ctp.initial_max_stream_data_bidi_local;
            qs->recv_max_data = qc->tp.initial_max_stream_data_bidi_remote;
        }

        qs->recv_state = S3_QUIC_STREAM_RECV_RECV;
        qs->send_state = S3_QUIC_STREAM_SEND_READY;
    }

    qs->recv_window = qs->recv_max_data;

    cln = s3_pool_cleanup_add(pool, 0);
    if (cln == NULL) {
        /* runs the cleanup handler, the pool is destroyed inside */
        s3_close_connection(sc);
        s3_queue_insert_tail(&qc->streams.free, &qs->queue);
        qc->reusable = reusable;
        return NULL;
    }

    cln->handler = s3_quic_stream_cleanup_handler;
    cln->data = sc;

    s3_rbtree_insert(&qc->streams.tree, &qs->node);

    return qs;
}

void
s3_quic_cancelable_stream(s3_connection_t *c)
{
    s3_connection_t      *pc;
    s3_quic_stream_t     *qs;
    s3_quic_connection_t *qc;

    qs = c->data;
    pc = qs->parent;
    qc = s3_quic_get_connection(pc);

    if (!qs->cancelable) {
        qs->cancelable = 1;

        if (s3_quic_can_shutdown(pc) == S3_OK) {
            qc->reusable = 1;

            if (qc->shutdown) {
                s3_quic_shutdown_quic(pc);
            }
        }
    }
}

static void
s3_quic_empty_handler(s3_event_t *ev)
{
    (void)ev;
}

static ssize_t
s3_quic_stream_recv(s3_connection_t *c, u_char *buf, size_t size)
{
    ssize_t           len;
    s3_buf_t         *b;
    s3_chain_t       *cl, *in;
    s3_event_t       *rev;
    s3_connection_t  *pc;
    s3_quic_stream_t *qs;

    qs = c->data;
    pc = qs->parent;
    rev = c->read;

    if (qs->recv_state == S3_QUIC_STREAM_RECV_RESET_RECVD ||
        qs->recv_state == S3_QUIC_STREAM_RECV_RESET_READ) {
        qs->recv_state = S3_QUIC_STREAM_RECV_RESET_READ;
        return S3_ERROR;
    }

    s3_log_debug2(S3_LOG_DEBUG_EVENT, pc->log, 0, "quic stream id:0x%xL recv buf:%uz", qs->id,
                  size);

    if (size == 0) {
        return 0;
    }

    in = s3_quic_read_buffer(pc, &qs->recv, size);
    if (in == S3_CHAIN_ERROR) {
        return S3_ERROR;
    }

    len = 0;

    for (cl = in; cl; cl = cl->next) {
        b = cl->buf;
        len += b->last - b->pos;
        buf = s3_cpymem(buf, b->pos, b->last - b->pos);
    }

    s3_quic_free_chain(pc, in);

    if (len == 0) {
        rev->ready = 0;

        if (qs->recv_state == S3_QUIC_STREAM_RECV_DATA_RECVD &&
            qs->recv_offset == qs->recv_final_size) {
            qs->recv_state = S3_QUIC_STREAM_RECV_DATA_READ;
        }

        if (qs->recv_state == S3_QUIC_STREAM_RECV_DATA_READ) {
            rev->eof = 1;
            return 0;
        }

        s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "quic stream id:0x%xL recv() not ready",
                      qs->id);
        return S3_AGAIN;
    }

    s3_log_debug2(S3_LOG_DEBUG_EVENT, c->log, 0, "quic stream id:0x%xL recv len:%z", qs->id, len);

    if (s3_quic_update_flow(qs, qs->recv_offset + len) != S3_OK) {
        return S3_ERROR;
    }

    return len;
}

ssize_t
s3_quic_stream_send(s3_connection_t *c, u_char *buf, size_t size)
{
    s3_buf_t   b;
    s3_chain_t cl;

    s3_memzero(&b, sizeof(s3_buf_t));

    b.memory = 1;
    b.pos = buf;
    b.last = buf + size;

    cl.buf = &b;
    cl.next = NULL;

    if (s3_quic_stream_send_chain(c, &cl, 0) == S3_CHAIN_ERROR) {
        return S3_ERROR;
    }

    if (b.pos == buf) {
        return S3_AGAIN;
    }

    return b.pos - buf;
}

static s3_chain_t *
s3_quic_stream_send_chain(s3_connection_t *c, s3_chain_t *in, off_t limit)
{
    uint64_t              n, flow;
    s3_event_t           *wev;
    s3_connection_t      *pc;
    s3_quic_stream_t     *qs;
    s3_quic_connection_t *qc;

    qs = c->data;
    pc = qs->parent;
    qc = s3_quic_get_connection(pc);
    wev = c->write;

    if (qs->send_state != S3_QUIC_STREAM_SEND_READY && qs->send_state != S3_QUIC_STREAM_SEND_SEND) {
        wev->error = 1;
        return S3_CHAIN_ERROR;
    }

    qs->send_state = S3_QUIC_STREAM_SEND_SEND;

    flow = qs->acked + qc->conf->stream_buffer_size - qs->sent;

    if (flow == 0) {
        wev->ready = 0;
        return in;
    }

    if (limit == 0 || limit > (off_t)flow) {
        limit = (off_t)flow;
    }

    n = qs->send.size;

    in = s3_quic_write_buffer(pc, &qs->send, in, limit, qs->sent);
    if (in == S3_CHAIN_ERROR) {
        return S3_CHAIN_ERROR;
    }

    n = qs->send.size - n;
    c->sent += n;
    qs->sent += n;
    qc->streams.sent += n;

    if (flow == n) {
        wev->ready = 0;
    }

    s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "quic send_chain sent:%uL", n);

    if (s3_quic_stream_flush(qs) != S3_OK) {
        return S3_CHAIN_ERROR;
    }

    return in;
}

static s3_int_t
s3_quic_stream_flush(s3_quic_stream_t *qs)
{
    off_t                 limit, len;
    s3_uint_t             last;
    s3_chain_t           *out;
    s3_quic_frame_t      *frame;
    s3_connection_t      *pc;
    s3_quic_connection_t *qc;

    if (qs->send_state != S3_QUIC_STREAM_SEND_SEND) {
        return S3_OK;
    }

    pc = qs->parent;
    qc = s3_quic_get_connection(pc);

    if (qc->streams.send_max_data == 0) {
        qc->streams.send_max_data = qc->ctp.initial_max_data;
    }

    limit = (off_t)s3_min(qc->streams.send_max_data - qc->streams.send_offset,
                          qs->send_max_data - qs->send_offset);

    s3_log_debug2(S3_LOG_DEBUG_EVENT, pc->log, 0, "quic stream id:0x%xL flush limit:%L", qs->id,
                  (int64_t)limit);

    len = (off_t)qs->send.offset;

    out = s3_quic_read_buffer(pc, &qs->send, limit);
    if (out == S3_CHAIN_ERROR) {
        return S3_ERROR;
    }

    len = (off_t)qs->send.offset - len;
    last = 0;

    if (qs->send_final_size != (uint64_t)-1 && qs->send_final_size == qs->send.offset) {
        qs->send_state = S3_QUIC_STREAM_SEND_DATA_SENT;
        last = 1;
    }

    if (len == 0 && !last) {
        return S3_OK;
    }

    frame = s3_quic_alloc_frame(pc);
    if (frame == NULL) {
        return S3_ERROR;
    }

    frame->level = S3_QUIC_ENCRYPTION_APPLICATION;
    frame->type = S3_QUIC_FT_STREAM;
    frame->data = out;

    frame->u.stream.off = 1;
    frame->u.stream.len = 1;
    frame->u.stream.fin = last;

    frame->u.stream.stream_id = qs->id;
    frame->u.stream.offset = qs->send_offset;
    frame->u.stream.length = len;

    s3_quic_queue_frame(qc, frame);

    qs->send_offset += len;
    qc->streams.send_offset += len;

    s3_log_debug3(S3_LOG_DEBUG_EVENT, pc->log, 0, "quic stream id:0x%xL flush len:%L last:%ui",
                  qs->id, (int64_t)len, last);

    if (qs->connection == NULL) {
        return s3_quic_close_stream(qs);
    }

    return S3_OK;
}

static void
s3_quic_stream_cleanup_handler(void *data)
{
    s3_connection_t      *qc_conn = data;
    s3_quic_stream_t     *qs;
    s3_quic_connection_t *qc;

    qs = qc_conn->data;

    s3_log_debug1(S3_LOG_DEBUG_EVENT, qs->parent->log, 0, "quic stream id:0x%xL cleanup", qs->id);

    if (s3_quic_shutdown_stream(qc_conn, S3_RDWR_SHUTDOWN) != S3_OK) {
        qs->connection = NULL;
        goto failed;
    }

    qs->connection = NULL;

    if (s3_quic_close_stream(qs) != S3_OK) {
        goto failed;
    }

    return;

failed:

    qc = s3_quic_get_connection(qs->parent);
    qc->error = S3_QUIC_ERR_INTERNAL_ERROR;

    s3_post_event(&qc->close, &qc->ctx->posted_events);
}

static s3_int_t
s3_quic_close_stream(s3_quic_stream_t *qs)
{
    s3_connection_t      *pc;
    s3_quic_frame_t      *frame;
    s3_quic_connection_t *qc;

    pc = qs->parent;
    qc = s3_quic_get_connection(pc);

    if (!qc->closing) {
        /* make sure everything is sent and final size is received */

        if (qs->recv_state == S3_QUIC_STREAM_RECV_RECV) {
            return S3_OK;
        }

        if (qs->send_state != S3_QUIC_STREAM_SEND_DATA_RECVD &&
            qs->send_state != S3_QUIC_STREAM_SEND_RESET_RECVD) {
            return S3_OK;
        }
    }

    s3_log_debug1(S3_LOG_DEBUG_EVENT, pc->log, 0, "quic stream id:0x%xL close", qs->id);

    s3_quic_free_buffer(pc, &qs->send);
    s3_quic_free_buffer(pc, &qs->recv);

    s3_rbtree_delete(&qc->streams.tree, &qs->node);
    s3_queue_insert_tail(&qc->streams.free, &qs->queue);

    if (qc->closing) {
        /* schedule handler call to continue s3_quic_close_connection() */
        s3_post_event(&qc->close, &qc->ctx->posted_events);
        return S3_OK;
    }

    if (!qc->reusable && s3_quic_can_shutdown(pc) == S3_OK) {
        qc->reusable = 1;
    }

    if (qc->shutdown) {
        s3_quic_shutdown_quic(pc);
        return S3_OK;
    }

    if ((qs->id & S3_QUIC_STREAM_SERVER_INITIATED) == 0) {
        frame = s3_quic_alloc_frame(pc);
        if (frame == NULL) {
            return S3_ERROR;
        }

        frame->level = S3_QUIC_ENCRYPTION_APPLICATION;
        frame->type = S3_QUIC_FT_MAX_STREAMS;

        if (qs->id & S3_QUIC_STREAM_UNIDIRECTIONAL) {
            frame->u.max_streams.limit = ++qc->streams.client_max_streams_uni;
            frame->u.max_streams.bidi = 0;

        } else {
            frame->u.max_streams.limit = ++qc->streams.client_max_streams_bidi;
            frame->u.max_streams.bidi = 1;
        }

        s3_quic_queue_frame(qc, frame);
    }

    return S3_OK;
}

static s3_int_t
s3_quic_can_shutdown(s3_connection_t *c)
{
    s3_rbtree_t          *tree;
    s3_rbtree_node_t     *node;
    s3_quic_stream_t     *qs;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    tree = &qc->streams.tree;

    if (tree->root != tree->sentinel) {
        for (node = s3_rbtree_min(tree->root, tree->sentinel); node;
             node = s3_rbtree_next(tree, node)) {
            qs = (s3_quic_stream_t *)node;

            if (!qs->cancelable) {
                return S3_DECLINED;
            }
        }
    }

    return S3_OK;
}

s3_int_t
s3_quic_handle_stream_frame(s3_connection_t *c, s3_quic_header_t *pkt, s3_quic_frame_t *frame)
{
    uint64_t                last;
    s3_quic_stream_t       *qs;
    s3_quic_connection_t   *qc;
    s3_quic_stream_frame_t *f;

    qc = s3_quic_get_connection(c);
    f = &frame->u.stream;

    (void)pkt;

    if ((f->stream_id & S3_QUIC_STREAM_UNIDIRECTIONAL) &&
        (f->stream_id & S3_QUIC_STREAM_SERVER_INITIATED)) {
        qc->error = S3_QUIC_ERR_STREAM_STATE_ERROR;
        return S3_ERROR;
    }

    /* no overflow since both values are 62-bit */
    last = f->offset + f->length;

    qs = s3_quic_get_stream(c, f->stream_id);

    if (qs == NULL) {
        return S3_ERROR;
    }

    if (qs == S3_QUIC_STREAM_GONE) {
        return S3_OK;
    }

    if (qs->recv_final_size != (uint64_t)-1 &&
        (qs->recv_final_size < last || (qs->recv_final_size > last && f->fin))) {
        qc->error = S3_QUIC_ERR_FINAL_SIZE_ERROR;
        return S3_ERROR;
    }

    if (qs->recv_last > last && f->fin) {
        qc->error = S3_QUIC_ERR_FINAL_SIZE_ERROR;
        return S3_ERROR;
    }

    if (qs->recv_state != S3_QUIC_STREAM_RECV_RECV &&
        qs->recv_state != S3_QUIC_STREAM_RECV_SIZE_KNOWN) {
        return S3_OK;
    }

    if (s3_quic_control_flow(qs, last) != S3_OK) {
        return S3_ERROR;
    }

    if (last < qs->recv_offset) {
        return S3_OK;
    }

    if (f->fin) {
        qs->recv_final_size = last;
        qs->recv_state = S3_QUIC_STREAM_RECV_SIZE_KNOWN;
    }

    if (s3_quic_write_buffer(c, &qs->recv, frame->data, f->length, f->offset) == S3_CHAIN_ERROR) {
        return S3_ERROR;
    }

    if (qs->recv_state == S3_QUIC_STREAM_RECV_SIZE_KNOWN && qs->recv.size == qs->recv_final_size) {
        qs->recv_state = S3_QUIC_STREAM_RECV_DATA_RECVD;
    }

    if (qs->connection == NULL) {
        return s3_quic_close_stream(qs);
    }

    if (f->offset <= qs->recv_offset) {
        s3_quic_set_event(qc, qs->connection->read);
    }

    return S3_OK;
}

s3_int_t
s3_quic_handle_max_data_frame(s3_connection_t *c, s3_quic_max_data_frame_t *f)
{
    s3_rbtree_t          *tree;
    s3_rbtree_node_t     *node;
    s3_quic_stream_t     *qs;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);
    tree = &qc->streams.tree;

    if (f->max_data <= qc->streams.send_max_data) {
        return S3_OK;
    }

    if (tree->root == tree->sentinel || qc->streams.send_offset < qc->streams.send_max_data) {
        /* not blocked on MAX_DATA */
        qc->streams.send_max_data = f->max_data;
        return S3_OK;
    }

    qc->streams.send_max_data = f->max_data;
    node = s3_rbtree_min(tree->root, tree->sentinel);

    while (node && qc->streams.send_offset < qc->streams.send_max_data) {

        qs = (s3_quic_stream_t *)node;
        node = s3_rbtree_next(tree, node);

        if (s3_quic_stream_flush(qs) != S3_OK) {
            return S3_ERROR;
        }
    }

    return S3_OK;
}

s3_int_t
s3_quic_handle_streams_blocked_frame(s3_connection_t *c, s3_quic_header_t *pkt,
                                     s3_quic_streams_blocked_frame_t *f)
{
    (void)c;
    (void)pkt;
    (void)f;

    return S3_OK;
}

s3_int_t
s3_quic_handle_data_blocked_frame(s3_connection_t *c, s3_quic_header_t *pkt,
                                  s3_quic_data_blocked_frame_t *f)
{
    (void)pkt;
    (void)f;

    return s3_quic_update_max_data(c);
}

s3_int_t
s3_quic_handle_stream_data_blocked_frame(s3_connection_t *c, s3_quic_header_t *pkt,
                                         s3_quic_stream_data_blocked_frame_t *f)
{
    s3_quic_stream_t     *qs;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    (void)pkt;

    if ((f->id & S3_QUIC_STREAM_UNIDIRECTIONAL) && (f->id & S3_QUIC_STREAM_SERVER_INITIATED)) {
        qc->error = S3_QUIC_ERR_STREAM_STATE_ERROR;
        return S3_ERROR;
    }

    qs = s3_quic_get_stream(c, f->id);

    if (qs == NULL) {
        return S3_ERROR;
    }

    if (qs == S3_QUIC_STREAM_GONE) {
        return S3_OK;
    }

    return s3_quic_update_max_stream_data(qs);
}

s3_int_t
s3_quic_handle_max_stream_data_frame(s3_connection_t *c, s3_quic_header_t *pkt,
                                     s3_quic_max_stream_data_frame_t *f)
{
    s3_quic_stream_t     *qs;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    (void)pkt;

    if ((f->id & S3_QUIC_STREAM_UNIDIRECTIONAL) && (f->id & S3_QUIC_STREAM_SERVER_INITIATED) == 0) {
        qc->error = S3_QUIC_ERR_STREAM_STATE_ERROR;
        return S3_ERROR;
    }

    qs = s3_quic_get_stream(c, f->id);

    if (qs == NULL) {
        return S3_ERROR;
    }

    if (qs == S3_QUIC_STREAM_GONE) {
        return S3_OK;
    }

    if (f->limit <= qs->send_max_data) {
        return S3_OK;
    }

    if (qs->send_offset < qs->send_max_data) {
        /* not blocked on MAX_STREAM_DATA */
        qs->send_max_data = f->limit;
        return S3_OK;
    }

    qs->send_max_data = f->limit;

    /* the reference wakes the application writer here as well */

    s3_quic_set_event(qc, qs->connection->write);

    return s3_quic_stream_flush(qs);
}

s3_int_t
s3_quic_handle_reset_stream_frame(s3_connection_t *c, s3_quic_header_t *pkt,
                                  s3_quic_reset_stream_frame_t *f)
{
    s3_event_t           *rev;
    s3_quic_stream_t     *qs;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    (void)pkt;

    if ((f->id & S3_QUIC_STREAM_UNIDIRECTIONAL) && (f->id & S3_QUIC_STREAM_SERVER_INITIATED)) {
        qc->error = S3_QUIC_ERR_STREAM_STATE_ERROR;
        return S3_ERROR;
    }

    qs = s3_quic_get_stream(c, f->id);

    if (qs == NULL) {
        return S3_ERROR;
    }

    if (qs == S3_QUIC_STREAM_GONE) {
        return S3_OK;
    }

    if (qs->recv_final_size != (uint64_t)-1 && qs->recv_final_size != f->final_size) {
        qc->error = S3_QUIC_ERR_FINAL_SIZE_ERROR;
        return S3_ERROR;
    }

    if (qs->recv_last > f->final_size) {
        qc->error = S3_QUIC_ERR_FINAL_SIZE_ERROR;
        return S3_ERROR;
    }

    if (qs->recv_state == S3_QUIC_STREAM_RECV_RESET_RECVD ||
        qs->recv_state == S3_QUIC_STREAM_RECV_RESET_READ) {
        return S3_OK;
    }

    if (s3_quic_control_flow(qs, f->final_size) != S3_OK) {
        return S3_ERROR;
    }

    qs->recv_final_size = f->final_size;
    qs->recv_state = S3_QUIC_STREAM_RECV_RESET_RECVD;

    if (s3_quic_update_flow(qs, qs->recv_final_size) != S3_OK) {
        return S3_ERROR;
    }

    if (qs->connection == NULL) {
        return s3_quic_close_stream(qs);
    }

    rev = qs->connection->read;
    rev->error = 1;

    s3_quic_set_event(qc, rev);

    return S3_OK;
}

s3_int_t
s3_quic_handle_stop_sending_frame(s3_connection_t *c, s3_quic_header_t *pkt,
                                  s3_quic_stop_sending_frame_t *f)
{
    s3_quic_stream_t     *qs;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    (void)pkt;

    if ((f->id & S3_QUIC_STREAM_UNIDIRECTIONAL) && (f->id & S3_QUIC_STREAM_SERVER_INITIATED) == 0) {
        qc->error = S3_QUIC_ERR_STREAM_STATE_ERROR;
        return S3_ERROR;
    }

    qs = s3_quic_get_stream(c, f->id);

    if (qs == NULL) {
        return S3_ERROR;
    }

    if (qs == S3_QUIC_STREAM_GONE) {
        return S3_OK;
    }

    if (s3_quic_do_reset_stream(qs, f->error_code) != S3_OK) {
        return S3_ERROR;
    }

    if (qs->connection == NULL) {
        return s3_quic_close_stream(qs);
    }

    s3_quic_set_event(qc, qs->connection->write);

    return S3_OK;
}

s3_int_t
s3_quic_handle_max_streams_frame(s3_connection_t *c, s3_quic_header_t *pkt,
                                 s3_quic_max_streams_frame_t *f)
{
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    (void)pkt;

    if (f->bidi) {
        if (qc->streams.server_max_streams_bidi < f->limit) {
            qc->streams.server_max_streams_bidi = f->limit;

            s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "quic max_streams_bidi:%uL", f->limit);
        }

    } else {
        if (qc->streams.server_max_streams_uni < f->limit) {
            qc->streams.server_max_streams_uni = f->limit;

            s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "quic max_streams_uni:%uL", f->limit);
        }
    }

    return S3_OK;
}

void
s3_quic_handle_stream_ack(s3_connection_t *c, s3_quic_frame_t *f)
{
    uint64_t              acked;
    s3_quic_stream_t     *qs;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    switch (f->type) {

    case S3_QUIC_FT_RESET_STREAM:

        qs = s3_quic_find_stream(&qc->streams.tree, f->u.reset_stream.id);
        if (qs == NULL) {
            return;
        }

        qs->send_state = S3_QUIC_STREAM_SEND_RESET_RECVD;

        s3_log_debug2(S3_LOG_DEBUG_EVENT, c->log, 0,
                      "quic stream id:0x%xL ack reset final_size:%uL", qs->id,
                      f->u.reset_stream.final_size);

        break;

    case S3_QUIC_FT_STREAM:

        qs = s3_quic_find_stream(&qc->streams.tree, f->u.stream.stream_id);
        if (qs == NULL) {
            return;
        }

        acked = qs->acked;
        qs->acked += f->u.stream.length;

        if (f->u.stream.fin) {
            qs->fin_acked = 1;
        }

        if (qs->send_state == S3_QUIC_STREAM_SEND_DATA_SENT && qs->acked == qs->sent &&
            qs->fin_acked) {
            qs->send_state = S3_QUIC_STREAM_SEND_DATA_RECVD;
        }

        s3_log_debug4(S3_LOG_DEBUG_EVENT, c->log, 0,
                      "quic stream id:0x%xL ack len:%uL fin:%d unacked:%uL", qs->id,
                      f->u.stream.length, f->u.stream.fin, qs->sent - qs->acked);

        if (qs->connection && qs->sent - acked == qc->conf->stream_buffer_size &&
            f->u.stream.length > 0) {
            s3_quic_set_event(qc, qs->connection->write);
        }

        break;

    default:
        return;
    }

    if (qs->connection == NULL) {
        (void)s3_quic_close_stream(qs);
    }
}

static s3_int_t
s3_quic_control_flow(s3_quic_stream_t *qs, uint64_t last)
{
    uint64_t              len;
    s3_connection_t      *pc;
    s3_quic_connection_t *qc;

    pc = qs->parent;
    qc = s3_quic_get_connection(pc);

    if (last <= qs->recv_last) {
        return S3_OK;
    }

    len = last - qs->recv_last;

    s3_log_debug5(S3_LOG_DEBUG_EVENT, pc->log, 0,
                  "quic stream id:0x%xL flow control msd:%uL/%uL md:%uL/%uL", qs->id, last,
                  qs->recv_max_data, qc->streams.recv_last + len, qc->streams.recv_max_data);

    qs->recv_last += len;

    if (qs->recv_state == S3_QUIC_STREAM_RECV_RECV && qs->recv_last > qs->recv_max_data) {
        qc->error = S3_QUIC_ERR_FLOW_CONTROL_ERROR;
        return S3_ERROR;
    }

    qc->streams.recv_last += len;

    if (qc->streams.recv_last > qc->streams.recv_max_data) {
        qc->error = S3_QUIC_ERR_FLOW_CONTROL_ERROR;
        return S3_ERROR;
    }

    return S3_OK;
}

static s3_int_t
s3_quic_update_flow(s3_quic_stream_t *qs, uint64_t last)
{
    uint64_t              len;
    s3_connection_t      *pc;
    s3_quic_connection_t *qc;

    pc = qs->parent;
    qc = s3_quic_get_connection(pc);

    if (last <= qs->recv_offset) {
        return S3_OK;
    }

    len = last - qs->recv_offset;

    s3_log_debug2(S3_LOG_DEBUG_EVENT, pc->log, 0, "quic stream id:0x%xL flow update %uL", qs->id,
                  last);

    qs->recv_offset += len;

    if (qs->recv_max_data <= qs->recv_offset + qs->recv_window / 2) {
        if (s3_quic_update_max_stream_data(qs) != S3_OK) {
            return S3_ERROR;
        }
    }

    qc->streams.recv_offset += len;

    if (qc->streams.recv_max_data <= qc->streams.recv_offset + qc->streams.recv_window / 2) {
        if (s3_quic_update_max_data(pc) != S3_OK) {
            return S3_ERROR;
        }
    }

    return S3_OK;
}

static s3_int_t
s3_quic_update_max_stream_data(s3_quic_stream_t *qs)
{
    uint64_t              recv_max_data;
    s3_connection_t      *pc;
    s3_quic_frame_t      *frame;
    s3_quic_connection_t *qc;

    pc = qs->parent;
    qc = s3_quic_get_connection(pc);

    if (qs->recv_state != S3_QUIC_STREAM_RECV_RECV) {
        return S3_OK;
    }

    recv_max_data = qs->recv_offset + qs->recv_window;

    if (qs->recv_max_data == recv_max_data) {
        return S3_OK;
    }

    qs->recv_max_data = recv_max_data;

    s3_log_debug2(S3_LOG_DEBUG_EVENT, pc->log, 0, "quic stream id:0x%xL flow update msd:%uL",
                  qs->id, qs->recv_max_data);

    frame = s3_quic_alloc_frame(pc);
    if (frame == NULL) {
        return S3_ERROR;
    }

    frame->level = S3_QUIC_ENCRYPTION_APPLICATION;
    frame->type = S3_QUIC_FT_MAX_STREAM_DATA;
    frame->u.max_stream_data.id = qs->id;
    frame->u.max_stream_data.limit = qs->recv_max_data;

    s3_quic_queue_frame(qc, frame);

    return S3_OK;
}

static s3_int_t
s3_quic_update_max_data(s3_connection_t *c)
{
    uint64_t              recv_max_data;
    s3_quic_frame_t      *frame;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    recv_max_data = qc->streams.recv_offset + qc->streams.recv_window;

    if (qc->streams.recv_max_data == recv_max_data) {
        return S3_OK;
    }

    qc->streams.recv_max_data = recv_max_data;

    s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "quic flow update md:%uL",
                  qc->streams.recv_max_data);

    frame = s3_quic_alloc_frame(c);
    if (frame == NULL) {
        return S3_ERROR;
    }

    frame->level = S3_QUIC_ENCRYPTION_APPLICATION;
    frame->type = S3_QUIC_FT_MAX_DATA;
    frame->u.max_data.max_data = qc->streams.recv_max_data;

    s3_quic_queue_frame(qc, frame);

    return S3_OK;
}

static void
s3_quic_set_event(s3_quic_connection_t *qc, s3_event_t *ev)
{
    ev->ready = 1;

    if (ev->active) {
        s3_post_event(ev, &qc->ctx->posted_events);
    }
}
