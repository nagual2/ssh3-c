/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <openssl/rand.h>

#include <s3_crc32.h>
#include <s3_quic.h>
#include <s3_quic_connection.h>
#include <s3_quic_frames.h>
#include <s3_quic_output.h>
#include <s3_quic_ack.h>

/*
 * the s3_errno map is not pulled by s3_quic.h
 */
#include <s3_errno.h>

#include <s3_udp_recv.h>

static s3_quic_connection_t *s3_quic_new_connection(s3_connection_t *c, s3_quic_conf_t *conf,
                                                    s3_quic_header_t *pkt);
static s3_int_t s3_quic_handle_stateless_reset(s3_connection_t *c, s3_quic_header_t *pkt);
static void     s3_quic_input_handler(s3_event_t *rev);
static void     s3_quic_close_handler(s3_event_t *ev);

static s3_int_t s3_quic_handle_datagram(s3_connection_t *c, s3_buf_t *b, s3_quic_conf_t *conf);
static s3_int_t s3_quic_handle_packet(s3_connection_t *c, s3_quic_conf_t *conf,
                                      s3_quic_header_t *pkt);
static s3_int_t s3_quic_handle_payload(s3_connection_t *c, s3_quic_header_t *pkt);
static s3_int_t s3_quic_check_csid(s3_quic_connection_t *qc, s3_quic_header_t *pkt);
static s3_int_t s3_quic_handle_frames(s3_connection_t *c, s3_quic_header_t *pkt);
static s3_int_t s3_quic_handle_datagram_frame(s3_connection_t *c, s3_quic_frame_t *frame);
static s3_int_t s3_quic_handle_hs_done(s3_connection_t *c);

static void s3_quic_push_handler(s3_event_t *ev);
static void s3_quic_key_update_handler(s3_event_t *ev);

static s3_int_t s3_quic_cmp_sockaddr(struct sockaddr *sa1, socklen_t len1, struct sockaddr *sa2,
                                     socklen_t len2);

static s3_int_t s3_quic_memn2cmp(u_char *s1, u_char *s2, size_t n1, size_t n2);

s3_int_t
s3_quic_apply_transport_params(s3_connection_t *c, s3_quic_tp_t *ctp)
{
    s3_str_t              scid;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    scid.data = qc->path->cid->id;
    scid.len = qc->path->cid->len;

    if (scid.len != ctp->initial_scid.len ||
        s3_memcmp(scid.data, ctp->initial_scid.data, scid.len) != 0) {
        qc->error = S3_QUIC_ERR_TRANSPORT_PARAMETER_ERROR;
        qc->error_reason = "invalid initial_source_connection_id";

        s3_log_error(S3_LOG_INFO, c->log, 0, "quic client initial_source_connection_id mismatch");
        return S3_ERROR;
    }

    if (ctp->max_udp_payload_size < S3_QUIC_MIN_INITIAL_SIZE ||
        ctp->max_udp_payload_size > S3_QUIC_MAX_UDP_PAYLOAD_SIZE) {
        qc->error = S3_QUIC_ERR_TRANSPORT_PARAMETER_ERROR;
        qc->error_reason = "invalid maximum packet size";

        s3_log_error(S3_LOG_INFO, c->log, 0, "quic maximum packet size is invalid");
        return S3_ERROR;
    }

    if (ctp->active_connection_id_limit < 2) {
        qc->error = S3_QUIC_ERR_TRANSPORT_PARAMETER_ERROR;
        qc->error_reason = "invalid active_connection_id_limit";

        s3_log_error(S3_LOG_INFO, c->log, 0, "quic active_connection_id_limit is invalid");
        return S3_ERROR;
    }

    if (ctp->ack_delay_exponent > 20) {
        qc->error = S3_QUIC_ERR_TRANSPORT_PARAMETER_ERROR;
        qc->error_reason = "invalid ack_delay_exponent";

        s3_log_error(S3_LOG_INFO, c->log, 0, "quic ack_delay_exponent is invalid");
        return S3_ERROR;
    }

    if (ctp->max_ack_delay >= 16384) {
        qc->error = S3_QUIC_ERR_TRANSPORT_PARAMETER_ERROR;
        qc->error_reason = "invalid max_ack_delay";

        s3_log_error(S3_LOG_INFO, c->log, 0, "quic max_ack_delay is invalid");
        return S3_ERROR;
    }

    if (ctp->max_idle_timeout > 0 && ctp->max_idle_timeout < qc->tp.max_idle_timeout) {
        qc->tp.max_idle_timeout = ctp->max_idle_timeout;
    }

    qc->streams.server_max_streams_bidi = ctp->initial_max_streams_bidi;
    qc->streams.server_max_streams_uni = ctp->initial_max_streams_uni;

    s3_memcpy(&qc->ctp, ctp, sizeof(s3_quic_tp_t));

    return S3_OK;
}

void
s3_quic_run(s3_connection_t *c, s3_quic_conf_t *conf)
{
    s3_int_t              rc;
    s3_quic_connection_t *qc;

    s3_log_debug0(S3_LOG_DEBUG_EVENT, c->log, 0, "quic run");

    if (c->buffer == NULL || conf == NULL || conf->ssl == NULL || conf->ctx == NULL) {
        s3_log_error(S3_LOG_INFO, c->log, 0, "quic run: invalid configuration");
        s3_quic_close_connection(c, S3_ERROR);
        return;
    }

    rc = s3_quic_handle_datagram(c, c->buffer, conf);
    if (rc != S3_OK) {
        s3_quic_close_connection(c, rc);
        return;
    }

    /* quic connection is now created */
    qc = s3_quic_get_connection(c);

    /*
     * the subsequent datagrams of the connection are delivered by the
     * listener through the quic socket (porting map 4.3.3)
     */
    c->recv = s3_quic_shared_recv;

    s3_event_add_timer(c->read, qc->tp.max_idle_timeout);

    if (!qc->streams.initialized) {
        s3_event_add_timer(&qc->close, qc->conf->handshake_timeout);
    }

    c->read->handler = s3_quic_input_handler;

    return;
}

static s3_quic_connection_t *
s3_quic_new_connection(s3_connection_t *c, s3_quic_conf_t *conf, s3_quic_header_t *pkt)
{
    s3_uint_t             i;
    s3_quic_tp_t         *ctp;
    s3_quic_connection_t *qc;

    qc = s3_pcalloc(c->pool, sizeof(s3_quic_connection_t));
    if (qc == NULL) {
        return NULL;
    }

    qc->keys = s3_pcalloc(c->pool, sizeof(s3_quic_keys_t));
    if (qc->keys == NULL) {
        return NULL;
    }

    /* the reference accepts client Initial packets only, so the role is
     * a server one; qc->client is already 0 from s3_pcalloc() */

    qc->keys->is_client = 0;

    qc->version = pkt->version;

    /*
     * the reference uses s3_quic_rbtree_insert_stream() here
     * (D4, s3_quic_streams.c); the tree is empty until then
     */
    s3_rbtree_init(&qc->streams.tree, &qc->streams.sentinel, s3_rbtree_insert_value);

    for (i = 0; i < S3_QUIC_SEND_CTX_LAST; i++) {
        s3_queue_init(&qc->send_ctx[i].frames);
        s3_queue_init(&qc->send_ctx[i].sending);
        s3_queue_init(&qc->send_ctx[i].sent);
        qc->send_ctx[i].largest_pn = S3_QUIC_UNSET_PN;
        qc->send_ctx[i].largest_ack = S3_QUIC_UNSET_PN;
        qc->send_ctx[i].largest_range = S3_QUIC_UNSET_PN;
        qc->send_ctx[i].pending_ack = S3_QUIC_UNSET_PN;
    }

    qc->send_ctx[0].level = S3_QUIC_ENCRYPTION_INITIAL;
    qc->send_ctx[1].level = S3_QUIC_ENCRYPTION_HANDSHAKE;
    qc->send_ctx[2].level = S3_QUIC_ENCRYPTION_APPLICATION;

    s3_queue_init(&qc->free_frames);

    s3_quic_init_rtt(qc);

    qc->ctx = conf->ctx;

    /*
     * the pto event doubles as the loss detection timer
     * (s3_quic_ack.c: s3_quic_set_lost_timer())
     */
    qc->pto.log = c->log;
    qc->pto.data = c;
    qc->pto.handler = s3_quic_pto_handler;

    qc->push.log = c->log;
    qc->push.data = c;
    qc->push.handler = s3_quic_push_handler;

    qc->close.log = c->log;
    qc->close.data = c;
    qc->close.handler = s3_quic_close_handler;

    /*
     * the path validation handler lives in s3_quic_migration.c (D4)
     */
    qc->path_validation.log = c->log;
    qc->path_validation.data = c;
    qc->path_validation.handler = NULL;

    qc->key_update.log = c->log;
    qc->key_update.data = c;
    qc->key_update.handler = s3_quic_key_update_handler;

    qc->conf = conf;

    if (s3_quic_init_transport_params(&qc->tp, conf) != S3_OK) {
        return NULL;
    }

    ctp = &qc->ctp;

    /* defaults to be used before actual client parameters are received */
    ctp->max_udp_payload_size = S3_QUIC_MAX_UDP_PAYLOAD_SIZE;
    ctp->ack_delay_exponent = S3_QUIC_DEFAULT_ACK_DELAY_EXPONENT;
    ctp->max_ack_delay = S3_QUIC_DEFAULT_MAX_ACK_DELAY;
    ctp->active_connection_id_limit = 2;

    s3_queue_init(&qc->streams.uninitialized);
    s3_queue_init(&qc->streams.free);

    qc->streams.recv_max_data = qc->tp.initial_max_data;
    qc->streams.recv_window = qc->streams.recv_max_data;

    qc->streams.client_max_streams_uni = qc->tp.initial_max_streams_uni;
    qc->streams.client_max_streams_bidi = qc->tp.initial_max_streams_bidi;

    qc->congestion.window =
        s3_min(10 * S3_QUIC_MIN_INITIAL_SIZE, s3_max(2 * S3_QUIC_MIN_INITIAL_SIZE, 14720));
    qc->congestion.ssthresh = (size_t)-1;
    qc->congestion.mtu = S3_QUIC_MIN_INITIAL_SIZE;
    qc->congestion.recovery_start = s3_current_msec - 1;

    qc->max_frames = (conf->max_concurrent_streams_uni + conf->max_concurrent_streams_bidi) *
                     conf->stream_buffer_size / 2000;
    qc->max_frames = s3_max(qc->max_frames, 10000);

    if (pkt->validated && pkt->retried) {
        qc->tp.retry_scid.len = pkt->dcid.len;

        qc->tp.retry_scid.data = s3_pnalloc(c->pool, pkt->dcid.len);
        if (qc->tp.retry_scid.data == NULL) {
            return NULL;
        }

        s3_memcpy(qc->tp.retry_scid.data, pkt->dcid.data, pkt->dcid.len);
    }

    if (s3_quic_keys_set_initial_secret(qc->keys, &pkt->dcid, c->log) != S3_OK) {
        return NULL;
    }

    qc->validated = pkt->validated;

    if (s3_quic_open_sockets(c, qc, pkt) != S3_OK) {
        s3_quic_keys_cleanup(qc->keys);
        return NULL;
    }

    qc->reusable = 1;

    s3_log_debug0(S3_LOG_DEBUG_EVENT, c->log, 0, "quic connection created");

    return qc;
}

s3_int_t
s3_quic_open_sockets(s3_connection_t *c, s3_quic_connection_t *qc, s3_quic_header_t *pkt)
{
    s3_quic_socket_t    *qsock, *tmp;
    s3_quic_client_id_t *cid;

    /*
     * qc->path = NULL
     *
     * qc->nclient_ids = 0
     * qc->nsockets = 0
     * qc->max_retired_seqnum = 0
     * qc->client_seqnum = 0
     */

    s3_queue_init(&qc->sockets);
    s3_queue_init(&qc->free_sockets);

    s3_queue_init(&qc->paths);
    s3_queue_init(&qc->free_paths);

    s3_queue_init(&qc->client_ids);
    s3_queue_init(&qc->free_client_ids);

    qc->tp.original_dcid.len = pkt->odcid.len;

    qc->tp.original_dcid.data = s3_pnalloc(c->pool, pkt->odcid.len);
    if (qc->tp.original_dcid.data == NULL) {
        return S3_ERROR;
    }

    s3_memcpy(qc->tp.original_dcid.data, pkt->odcid.data, pkt->odcid.len);

    /* socket to use for further processing (id auto-generated) */
    qsock = s3_quic_create_socket(c, qc);
    if (qsock == NULL) {
        return S3_ERROR;
    }

    /* socket is listening at new server id */
    if (s3_quic_listen(c, qc, qsock) != S3_OK) {
        return S3_ERROR;
    }

    qsock->used = 1;

    qc->tp.initial_scid.len = qsock->sid.len;

    qc->tp.initial_scid.data = s3_pnalloc(c->pool, qsock->sid.len);
    if (qc->tp.initial_scid.data == NULL) {
        goto failed;
    }

    s3_memcpy(qc->tp.initial_scid.data, qsock->sid.id, qsock->sid.len);

    /* for all packets except first, this is set at udp layer */
    c->udp = (struct s3_udp_connection_s *)qsock;

    /* ngx_quic_get_connection(c) macro is now usable */

    /* we have a client identified by scid */
    cid = s3_quic_create_client_id(c, &pkt->scid, 0, NULL);
    if (cid == NULL) {
        goto failed;
    }

    /* path of the first packet is our initial active path */
    qc->path = s3_quic_new_path(c, c->sockaddr, c->socklen, cid);
    if (qc->path == NULL) {
        goto failed;
    }

    qc->path->tag = S3_QUIC_PATH_ACTIVE;

    if (pkt->validated) {
        qc->path->validated = 1;
    }

    tmp = s3_pcalloc(c->pool, sizeof(s3_quic_socket_t));
    if (tmp == NULL) {
        goto failed;
    }

    tmp->sid.seqnum = S3_QUIC_UNSET_PN; /* temporary socket */

    s3_memcpy(tmp->sid.id, pkt->dcid.data, pkt->dcid.len);
    tmp->sid.len = pkt->dcid.len;

    if (s3_quic_listen(c, qc, tmp) != S3_OK) {
        goto failed;
    }

    /* the listener backlink was consumed by the socket registrations */
    c->data = NULL;

    return S3_OK;

failed:

    /* the socket may be registered in the listener rbtree already */
    if (qsock->listen != NULL) {
        s3_rbtree_delete(&qsock->listen->rbtree, &qsock->node);
    }

    c->data = NULL;
    c->udp = NULL;

    return S3_ERROR;
}

s3_quic_socket_t *
s3_quic_create_socket(s3_connection_t *c, s3_quic_connection_t *qc)
{
    s3_queue_t       *q;
    s3_quic_socket_t *sock;

    if (!s3_queue_empty(&qc->free_sockets)) {

        q = s3_queue_head(&qc->free_sockets);
        sock = s3_queue_data(q, s3_quic_socket_t, queue);

        s3_queue_remove(&sock->queue);

        s3_memzero(sock, sizeof(s3_quic_socket_t));

    } else {

        sock = s3_pcalloc(c->pool, sizeof(s3_quic_socket_t));
        if (sock == NULL) {
            return NULL;
        }
    }

    sock->sid.len = S3_QUIC_SERVER_CID_LEN;
    if (s3_quic_create_server_id(c, sock->sid.id) != S3_OK) {
        return NULL;
    }

    sock->sid.seqnum = qc->server_seqnum++;

    return sock;
}

void
s3_quic_close_socket(s3_connection_t *c, s3_quic_socket_t *qsock)
{
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    s3_queue_remove(&qsock->queue);
    s3_queue_insert_head(&qc->free_sockets, &qsock->queue);

    if (qsock->listen != NULL) {
        s3_rbtree_delete(&qsock->listen->rbtree, &qsock->node);
        qsock->listen = NULL;
    }

    qc->nsockets--;

    s3_log_debug2(S3_LOG_DEBUG_EVENT, c->log, 0, "quic socket seq:%L closed nsock:%ui",
                  (int64_t)qsock->sid.seqnum, qc->nsockets);
}

s3_int_t
s3_quic_listen(s3_connection_t *c, s3_quic_connection_t *qc, s3_quic_socket_t *qsock)
{
    s3_str_t             id;
    s3_quic_server_id_t *sid;

    sid = &qsock->sid;

    id.data = sid->id;
    id.len = sid->len;

    qsock->connection = c;

    /*
     * the quic socket is registered in the listener rbtree: the node
     * key is the crc32 of the id, the lookup compares the sid bytes
     * (the reference ngx_quic_listen() + ngx_event_quic_udp.c); the
     * client role has no listener and keeps the socket unregistered
     */
    qsock->listen = (s3_udp_listen_t *)c->data;

    if (qsock->listen != NULL) {
        qsock->node.key = s3_crc32_long(id.data, id.len);

        s3_rbtree_insert(&qsock->listen->rbtree, &qsock->node);
    }

    s3_queue_insert_tail(&qc->sockets, &qsock->queue);

    qc->nsockets++;
    qsock->quic = qc;

    s3_log_debug3(S3_LOG_DEBUG_EVENT, c->log, 0,
                  "quic socket seq:%L listening at sid:%xV nsock:%ui", (int64_t)sid->seqnum, &id,
                  qc->nsockets);

    return S3_OK;
}

void
s3_quic_close_sockets(s3_connection_t *c)
{
    s3_queue_t           *q;
    s3_quic_socket_t     *qsock;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    while (!s3_queue_empty(&qc->sockets)) {
        q = s3_queue_head(&qc->sockets);
        qsock = s3_queue_data(q, s3_quic_socket_t, queue);

        s3_quic_close_socket(c, qsock);
    }
}

s3_quic_socket_t *
s3_quic_find_socket(s3_connection_t *c, uint64_t seqnum)
{
    s3_queue_t           *q;
    s3_quic_socket_t     *qsock;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    for (q = s3_queue_head(&qc->sockets); q != s3_queue_sentinel(&qc->sockets);
         q = s3_queue_next(q)) {
        qsock = s3_queue_data(q, s3_quic_socket_t, queue);

        if (qsock->sid.seqnum == seqnum) {
            return qsock;
        }
    }

    return NULL;
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

    if (sockaddr != NULL && socklen > 0 && socklen <= sizeof(struct sockaddr_storage)) {

        path->sockaddr = (struct sockaddr *)&path->sa;
        path->socklen = socklen;
        s3_memcpy(path->sockaddr, sockaddr, socklen);
    }

    /*
     * addr_text is filled in D4 together with s3_sock_ntop()
     * (porting map 4.5.6); the path logs use the seqnum until then
     */

    path->mtu = S3_QUIC_MIN_INITIAL_SIZE;

    s3_log_debug2(S3_LOG_DEBUG_EVENT, c->log, 0, "quic path seq:%uL created mtu:%uz", path->seqnum,
                  path->mtu);

    return path;
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

    s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "quic path seq:%uL retired", path->seqnum);

    return S3_OK;
}

static s3_int_t
s3_quic_handle_stateless_reset(s3_connection_t *c, s3_quic_header_t *pkt)
{
    u_char               *tail, ch;
    s3_uint_t             i;
    s3_queue_t           *q;
    s3_quic_client_id_t  *cid;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    /* A stateless reset uses an entire UDP datagram */
    if (!pkt->first) {
        return S3_DECLINED;
    }

    tail = pkt->raw->last - S3_QUIC_SR_TOKEN_LEN;

    for (q = s3_queue_head(&qc->client_ids); q != s3_queue_sentinel(&qc->client_ids);
         q = s3_queue_next(q)) {
        cid = s3_queue_data(q, s3_quic_client_id_t, queue);

        if (cid->seqnum == 0 || !cid->used) {
            /*
             * No stateless reset token in initial connection id.
             * Don't accept a token from an unused connection id.
             */
            continue;
        }

        /* constant time comparison */

        for (ch = 0, i = 0; i < S3_QUIC_SR_TOKEN_LEN; i++) {
            ch |= tail[i] ^ cid->sr_token[i];
        }

        if (ch == 0) {
            return S3_OK;
        }
    }

    return S3_DECLINED;
}

static void
s3_quic_input_handler(s3_event_t *rev)
{
    ssize_t               n;
    s3_int_t              rc;
    s3_buf_t              b;
    s3_connection_t      *c;
    s3_quic_connection_t *qc;

    static u_char buffer[S3_QUIC_MAX_UDP_PAYLOAD_SIZE];

    s3_log_debug0(S3_LOG_DEBUG_EVENT, rev->log, 0, "quic input handler");

    c = rev->data;
    qc = s3_quic_get_connection(c);

    if (rev->timedout) {
        s3_log_error(S3_LOG_INFO, c->log, S3_ETIMEDOUT, "quic client timed out");
        s3_quic_close_connection(c, S3_ABORT);
        return;
    }

    /*
     * the nginx c->close / ngx_exiting block is not ported: the ssh3-c
     * worker lifecycle does not exist yet, connections are closed
     * through s3_quic_finalize_connection()
     */

    if (c->recv == NULL || qc == NULL) {
        /* the first datagram of a server connection goes through c->buffer */
        return;
    }

    /*
     * the datagram was staged by the listener into the quic socket
     * (or read from the client socket); the per-datagram peer address
     * is kept in qsock->sockaddr by the listener
     */

    n = c->recv(c, buffer, sizeof(buffer));
    if (n <= 0) {
        return;
    }

    s3_memzero(&b, sizeof(s3_buf_t));

    b.temporary = 1;
    b.pos = buffer;
    b.last = buffer + n;

    rc = s3_quic_handle_datagram(c, &b, qc->conf);

    if (rc == S3_ERROR) {
        s3_quic_close_connection(c, S3_ERROR);
        return;
    }

    if (rc == S3_ABORT) {
        return;
    }

    /* rc == S3_OK */

    qc->send_timer_set = 0;
    s3_event_add_timer(rev, qc->tp.max_idle_timeout);
}

void
s3_quic_close_connection(s3_connection_t *c, s3_int_t rc)
{
    s3_uint_t             i;
    s3_quic_send_ctx_t   *ctx;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    if (qc == NULL) {
        s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0,
                      "quic packet rejected rc:%i, cleanup connection", rc);
        goto quic_done;
    }

    s3_log_debug2(S3_LOG_DEBUG_EVENT, c->log, 0, "quic close %s rc:%i",
                  qc->closing ? "resumed" : "initiated", rc);

    if (!qc->closing) {

        /* drop packets from retransmit queues, no ack is expected */
        for (i = 0; i < S3_QUIC_SEND_CTX_LAST; i++) {
            s3_quic_free_frames(c, &qc->send_ctx[i].frames);
            s3_quic_free_frames(c, &qc->send_ctx[i].sent);
        }

        if (qc->close.timer_set) {
            s3_event_del_timer(&qc->close);
        }

        if (rc == S3_ABORT) {

            /*
             * RFC 9000, 10.1.  Idle Timeout
             *
             *  If a max_idle_timeout is specified by either endpoint in its
             *  transport parameters (Section 18.2), the connection is silently
             *  closed and its state is discarded when it remains idle
             */

            /* this case also handles some errors from s3_quic_run() */

            s3_log_debug2(S3_LOG_DEBUG_EVENT, c->log, 0, "quic close silent drain:%d timedout:%d",
                          qc->draining, c->read->timedout);

        } else {

            /*
             * RFC 9000, 10.2.  Immediate Close
             *
             *  An endpoint sends a CONNECTION_CLOSE frame (Section 19.19)
             *  to terminate the connection immediately.
             */

            if (qc->error == 0 && rc == S3_ERROR) {
                qc->error = S3_QUIC_ERR_INTERNAL_ERROR;
                qc->error_app = 0;
            }

            s3_log_debug5(S3_LOG_DEBUG_EVENT, c->log, 0,
                          "quic close immediate term:%d drain:%d %serror:%ui \"%s\"",
                          rc == S3_ERROR ? 1 : 0, qc->draining, qc->error_app ? "app " : "",
                          qc->error, qc->error_reason ? qc->error_reason : "");

            for (i = 0; i < S3_QUIC_SEND_CTX_LAST; i++) {
                ctx = &qc->send_ctx[i];

                if (!s3_quic_keys_available(qc->keys, ctx->level, 1)) {
                    continue;
                }

                qc->error_level = ctx->level;

                (void)s3_quic_send_cc(c);

                if (rc == S3_OK) {
                    s3_event_add_timer(&qc->close, 3 * s3_quic_pto(c, ctx));
                }
            }
        }

        qc->closing = 1;
    }

    if (rc == S3_ERROR && qc->close.timer_set) {
        /* do not wait for timer in case of fatal error */
        s3_event_del_timer(&qc->close);
    }

    /*
     * the reference waits for the streams to close here
     * (D4, s3_quic_streams.c: s3_quic_close_streams() == S3_AGAIN)
     */

    if (qc->push.timer_set) {
        s3_event_del_timer(&qc->push);
    }

    if (qc->pto.timer_set) {
        s3_event_del_timer(&qc->pto);
    }

    if (qc->path_validation.timer_set) {
        s3_event_del_timer(&qc->path_validation);
    }

    if (qc->push.posted) {
        s3_delete_posted_event(&qc->push);
    }

    if (qc->key_update.posted) {
        s3_delete_posted_event(&qc->key_update);
    }

    if (qc->close.timer_set) {
        return;
    }

    if (qc->close.posted) {
        s3_delete_posted_event(&qc->close);
    }

    s3_quic_close_sockets(c);

    s3_quic_keys_cleanup(qc->keys);

    s3_log_debug0(S3_LOG_DEBUG_EVENT, c->log, 0, "quic close completed");

    /* may be tested from SSL callback during SSL shutdown */
    c->udp = NULL;

quic_done:

    if (c->ssl) {
        (void)s3_ssl_shutdown(c);
    }

    if (c->read->timer_set) {
        s3_event_del_timer(c->read);
    }

    /* destroys the connection pool with the quic connection in it */
    s3_close_connection(c);
}

void
s3_quic_finalize_connection(s3_connection_t *c, s3_uint_t err, const char *reason)
{
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    if (qc->closing) {
        return;
    }

    qc->error = err;
    qc->error_reason = reason;
    qc->error_app = 1;
    qc->error_ftype = 0;

    s3_post_event(&qc->close, &qc->ctx->posted_events);
}

void
s3_quic_shutdown_connection(s3_connection_t *c, s3_uint_t err, const char *reason)
{
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);
    qc->shutdown = 1;
    qc->shutdown_code = err;
    qc->shutdown_reason = reason;

    s3_quic_shutdown_quic(c);
}

static void
s3_quic_close_handler(s3_event_t *ev)
{
    s3_connection_t *c;

    s3_log_debug0(S3_LOG_DEBUG_EVENT, ev->log, 0, "quic close handler");

    c = ev->data;

    s3_quic_close_connection(c, S3_OK);
}

static s3_int_t
s3_quic_handle_datagram(s3_connection_t *c, s3_buf_t *b, s3_quic_conf_t *conf)
{
    size_t                size;
    u_char               *p, *start;
    s3_int_t              rc;
    s3_uint_t             good;
    s3_quic_path_t       *path;
    s3_quic_header_t      pkt;
    s3_quic_connection_t *qc;

    good = 0;
    path = NULL;

    size = b->last - b->pos;

    p = start = b->pos;

    while (p < b->last) {

        s3_memzero(&pkt, sizeof(s3_quic_header_t));
        pkt.raw = b;
        pkt.data = p;
        pkt.len = b->last - p;
        pkt.log = c->log;
        pkt.first = (p == start) ? 1 : 0;
        pkt.path = path;
        pkt.flags = p[0];
        pkt.raw->pos++;

        rc = s3_quic_handle_packet(c, conf, &pkt);

        if (rc == S3_ERROR || rc == S3_ABORT) {
            return rc;
        }

        if (rc == S3_OK) {
            good = 1;
        }

        path = pkt.path; /* preserve packet path from 1st packet */

        /* S3_OK || S3_DECLINED */

        /*
         * we get S3_DECLINED when there are no keys [yet] available
         * to decrypt packet.
         * Instead of queueing it, we ignore it and rely on the sender's
         * retransmission:
         *
         * RFC 9000, 12.2.  Coalescing Packets
         *
         * For example, if decryption fails (because the keys are
         * not available or for any other reason), the receiver MAY either
         * discard or buffer the packet for later processing and MUST
         * attempt to process the remaining packets.
         *
         * We also skip packets that don't match connection state
         * or cannot be parsed properly.
         */

        /* b->pos is at header end, adjust by actual packet length */
        b->pos = pkt.data + pkt.len;

        p = b->pos;
    }

    if (!good) {
        return S3_ABORT;
    }

    qc = s3_quic_get_connection(c);

    if (qc) {
        /*
         * RFC 9000, 8.1.  Preventing Amplification Attacks:
         *
         * An endpoint MUST limit the number of bytes it sends to three
         * times the number of bytes it has received; the whole datagram
         * is accounted once, which is what the reference does in its
         * set_path() (D4 repeats the accounting for a path discovered
         * later, s3_quic_migration.c)
         */

        if (path) {
            path->received += (off_t)size;
        } else {
            qc->path->received += (off_t)size;
        }

        qc->received += (off_t)size;

        if ((uint64_t)(c->sent + qc->received) / 8 >
            (qc->streams.sent + qc->streams.recv_last) + 1048576) {
            s3_log_error(S3_LOG_INFO, c->log, 0, "quic flood detected");

            qc->error = S3_QUIC_ERR_NO_ERROR;
            qc->error_reason = "QUIC flood detected";
            return S3_ERROR;
        }
    }

    return S3_OK;
}

static s3_int_t
s3_quic_handle_packet(s3_connection_t *c, s3_quic_conf_t *conf, s3_quic_header_t *pkt)
{
    s3_int_t              rc;
    s3_quic_socket_t     *qsock;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    /*
     * the local role is needed by the parser itself: the RFC 9000, 14.1
     * minimum size of a datagram carrying an Initial packet is enforced
     * by the endpoint which is amplification limited, that is a server;
     * a client has to accept short datagrams, a bare Initial ACK from
     * the server is far below the 1200 bytes
     */

    pkt->client = (qc && qc->client) ? 1 : 0;

    rc = s3_quic_parse_packet(pkt);

    if (rc == S3_ERROR) {
        return S3_DECLINED;
    }

    pkt->parsed = 1;

    s3_log_debug2(S3_LOG_DEBUG_EVENT, c->log, 0, "quic packet rx dcid len:%uz %xV", pkt->dcid.len,
                  &pkt->dcid);

    if (qc) {

        if (rc == S3_DECLINED) {
            /* unsupported version: the packet is long-header and safe to answer */
            s3_log_error(S3_LOG_INFO, c->log, 0, "quic unsupported version: 0x%xD", pkt->version);
            return s3_quic_negotiate_version(c, pkt);
        }

        if (pkt->level != S3_QUIC_ENCRYPTION_APPLICATION) {

            if (pkt->version != qc->version) {
                s3_log_error(S3_LOG_INFO, c->log, 0, "quic version mismatch: 0x%xD", pkt->version);
                return S3_DECLINED;
            }

            if (qc->client) {

                /*
                 * RFC 9000, 7.2.  Negotiating Connection IDs:
                 * the client moves to the scid of the first Initial
                 * packet of the server; the transport parameter check
                 * then matches against it
                 */
                if (pkt->level == S3_QUIC_ENCRYPTION_INITIAL && pkt->scid.len > 0 &&
                    pkt->scid.len <= S3_QUIC_CID_LEN_MAX &&
                    (qc->path->cid->len != pkt->scid.len ||
                     s3_memcmp(qc->path->cid->id, pkt->scid.data, pkt->scid.len) != 0)) {
                    s3_memcpy(qc->path->cid->id, pkt->scid.data, pkt->scid.len);
                    qc->path->cid->len = pkt->scid.len;

                    s3_log_debug0(S3_LOG_DEBUG_EVENT, c->log, 0,
                                  "quic client adopted the peer scid");
                }

            } else {

                if (pkt->first) {
                    qsock = s3_quic_get_socket(c);

                    if (qsock->socklen != 0 && qc->path->socklen != 0 &&
                        s3_quic_cmp_sockaddr((struct sockaddr *)&qsock->sockaddr, qsock->socklen,
                                             qc->path->sockaddr, qc->path->socklen) != S3_OK) {
                        /* packet comes from unknown path, possibly migration */
                        s3_log_debug0(S3_LOG_DEBUG_EVENT, c->log, 0,
                                      "quic too early migration attempt");
                        return S3_ABORT;
                    }
                }

                if (s3_quic_check_csid(qc, pkt) != S3_OK) {
                    return S3_DECLINED;
                }
            }
        }

        rc = s3_quic_handle_payload(c, pkt);

        if (rc == S3_DECLINED && pkt->level == S3_QUIC_ENCRYPTION_APPLICATION) {

            if (s3_quic_handle_stateless_reset(c, pkt) == S3_OK) {
                s3_log_error(S3_LOG_INFO, c->log, 0, "quic stateless reset packet detected");

                qc->draining = 1;
                s3_post_event(&qc->close, &qc->ctx->posted_events);

                return S3_OK;
            }
        }

        return rc;
    }

    /* packet does not belong to a connection */

    if (rc == S3_DECLINED) {
        return s3_quic_negotiate_version(c, pkt);
    }

    if (pkt->level == S3_QUIC_ENCRYPTION_APPLICATION) {
        return s3_quic_send_stateless_reset(c, conf, pkt);
    }

    if (pkt->level != S3_QUIC_ENCRYPTION_INITIAL) {
        s3_log_debug0(S3_LOG_DEBUG_EVENT, c->log, 0, "quic expected initial, got handshake");
        return S3_ERROR;
    }

    if (pkt->dcid.len < S3_QUIC_CID_LEN_MIN) {
        /* RFC 9000, 7.2.  Negotiating Connection IDs */
        s3_log_error(S3_LOG_INFO, c->log, 0, "quic too short dcid in initial packet: len:%i",
                     (s3_int_t)pkt->dcid.len);
        return S3_ERROR;
    }

    /* process retry and initialize connection IDs */

    if (pkt->token.len) {

        rc = s3_quic_validate_token(c, conf->av_token_key, pkt);

        if (rc == S3_ERROR) {
            /* internal error */
            return S3_ERROR;

        } else if (rc == S3_ABORT) {
            /* token cannot be decrypted */
            return s3_quic_send_early_cc(c, pkt, S3_QUIC_ERR_INVALID_TOKEN, "invalid token");

        } else if (rc == S3_DECLINED) {
            /* token is invalid */

            if (pkt->retried) {
                return s3_quic_send_early_cc(c, pkt, S3_QUIC_ERR_INVALID_TOKEN, "stale token");
            }

            if (conf->retry) {
                return s3_quic_send_retry(c, conf, pkt);
            }
        }

        /* S3_OK */

    } else if (conf->retry) {
        /* no address validation token yet: RFC 9000, 17.2.5.1, the
         * client repeats the Initial with the retry token */
        return s3_quic_send_retry(c, conf, pkt);

    } else {
        pkt->odcid = pkt->dcid;
    }

    /*
     * the reference answers with a retry while the worker terminates
     * (ngx_terminate/ngx_exiting); the ssh3-c lifecycle does not exist
     * yet
     */

    qc = s3_quic_new_connection(c, conf, pkt);
    if (qc == NULL) {
        return S3_ERROR;
    }

    return s3_quic_handle_payload(c, pkt);
}

static s3_int_t
s3_quic_handle_payload(s3_connection_t *c, s3_quic_header_t *pkt)
{
    s3_int_t              rc;
    s3_quic_send_ctx_t   *ctx;
    s3_quic_connection_t *qc;
    static u_char         buf[S3_QUIC_MAX_UDP_PAYLOAD_SIZE];

    qc = s3_quic_get_connection(c);

    qc->error = 0;
    qc->error_reason = NULL;

    if (!s3_quic_keys_available(qc->keys, pkt->level, 0)) {
        s3_log_error(S3_LOG_INFO, c->log, 0, "quic no %s keys, ignoring packet",
                     s3_quic_level_name(pkt->level));
        return S3_DECLINED;
    }

    pkt->keys = qc->keys;
    pkt->key_phase = qc->key_phase;
    pkt->plaintext = buf;
    pkt->client = qc->client;

    ctx = s3_quic_get_send_ctx(qc, pkt->level);

    rc = s3_quic_decrypt(pkt, &ctx->largest_pn);
    if (rc != S3_OK) {
        qc->error = pkt->error;
        qc->error_reason = "failed to decrypt packet";
        return rc;
    }

    pkt->decrypted = 1;

    if (pkt->path == NULL) {
        /*
         * the reference resolves the packet path here
         * (D4, s3_quic_migration.c: s3_quic_set_path()); until the
         * migration machinery arrives every packet belongs to the
         * initial active path
         */
        pkt->path = qc->path;
    }

    if (c->ssl == NULL) {
        if (s3_quic_init_connection(c) != S3_OK) {
            return S3_ERROR;
        }
    }

    if (pkt->level == S3_QUIC_ENCRYPTION_HANDSHAKE) {
        /*
         * RFC 9001, 4.9.1.  Discarding Initial Keys
         *
         * The successful use of Handshake packets indicates
         * that no more Initial packets need to be exchanged
         */
        s3_quic_discard_ctx(c, S3_QUIC_ENCRYPTION_INITIAL);

        if (!qc->path->validated) {
            qc->path->validated = 1;
            s3_post_event(&qc->push, &qc->ctx->posted_events);
        }
    }

    if (pkt->level == S3_QUIC_ENCRYPTION_APPLICATION) {
        /*
         * RFC 9001, 4.9.3.  Discarding 0-RTT Keys
         *
         * After receiving a 1-RTT packet, servers MUST discard
         * 0-RTT keys within a short time
         */
        s3_quic_keys_discard(qc->keys, S3_QUIC_ENCRYPTION_EARLY_DATA);
    }

    if (qc->closing) {
        /*
         * RFC 9000, 10.2.  Immediate Close
         *
         * ... delayed or reordered packets are properly discarded.
         *
         *  In the closing state, an endpoint retains only enough information
         *  to generate a packet containing a CONNECTION_CLOSE frame and to
         *  identify packets as belonging to the connection.
         */

        qc->error_level = pkt->level;
        qc->error = S3_QUIC_ERR_NO_ERROR;
        qc->error_reason = "connection is closing, packet discarded";
        qc->error_ftype = 0;
        qc->error_app = 0;

        (void)s3_quic_send_cc(c);

        return S3_OK;
    }

    pkt->received = s3_current_msec;

    if (pkt->level != S3_QUIC_ENCRYPTION_APPLICATION) {
        return s3_quic_handle_frames(c, pkt);
    }

    if (!pkt->key_update) {
        return s3_quic_handle_frames(c, pkt);
    }

    /* switch keys and generate next on Key Phase change */

    qc->key_phase ^= 1;
    s3_quic_keys_switch(qc->keys);

    rc = s3_quic_handle_frames(c, pkt);
    if (rc != S3_OK) {
        return rc;
    }

    s3_post_event(&qc->key_update, &qc->ctx->posted_events);

    return S3_OK;
}

void
s3_quic_discard_ctx(s3_connection_t *c, s3_uint_t level)
{
    s3_queue_t           *q;
    s3_quic_frame_t      *f;
    s3_quic_socket_t     *qsock;
    s3_quic_send_ctx_t   *ctx;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    if (!s3_quic_keys_available(qc->keys, level, 0) &&
        !s3_quic_keys_available(qc->keys, level, 1)) {
        return;
    }

    s3_quic_keys_discard(qc->keys, level);

    qc->pto_count = 0;

    ctx = s3_quic_get_send_ctx(qc, level);

    s3_quic_free_buffer(c, &ctx->crypto);

    while (!s3_queue_empty(&ctx->sent)) {
        q = s3_queue_head(&ctx->sent);
        s3_queue_remove(q);

        f = s3_queue_data(q, s3_quic_frame_t, queue);

        /* the frames were not ack'ed, give the bytes back */
        s3_quic_congestion_ack(c, f);

        s3_quic_free_frame(c, f);
    }

    while (!s3_queue_empty(&ctx->frames)) {
        q = s3_queue_head(&ctx->frames);
        s3_queue_remove(q);

        f = s3_queue_data(q, s3_quic_frame_t, queue);
        s3_quic_free_frame(c, f);
    }

    if (level == S3_QUIC_ENCRYPTION_INITIAL) {
        /* close temporary listener with initial dcid */
        qsock = s3_quic_find_socket(c, S3_QUIC_UNSET_PN);
        if (qsock) {
            s3_quic_close_socket(c, qsock);
        }
    }

    ctx->send_ack = 0;

    s3_quic_set_lost_timer(c);
}

static s3_int_t
s3_quic_check_csid(s3_quic_connection_t *qc, s3_quic_header_t *pkt)
{
    s3_queue_t          *q;
    s3_quic_client_id_t *cid;

    for (q = s3_queue_head(&qc->client_ids); q != s3_queue_sentinel(&qc->client_ids);
         q = s3_queue_next(q)) {
        cid = s3_queue_data(q, s3_quic_client_id_t, queue);

        if (pkt->scid.len == cid->len && s3_memcmp(pkt->scid.data, cid->id, cid->len) == 0) {
            return S3_OK;
        }
    }

    s3_log_error(S3_LOG_INFO, pkt->log, 0, "quic unexpected quic scid");
    return S3_ERROR;
}

static s3_int_t
s3_quic_handle_frames(s3_connection_t *c, s3_quic_header_t *pkt)
{
    u_char               *end, *p;
    ssize_t               len;
    s3_buf_t              buf;
    s3_uint_t             do_close, nonprobing;
    s3_chain_t            chain;
    s3_quic_frame_t       frame;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    if (qc == NULL) {
        /* unreachable: the callers guarantee the connection */
        return S3_ERROR;
    }

    p = pkt->payload.data;
    end = p + pkt->payload.len;

    do_close = 0;
    nonprobing = 0;

    while (p < end) {

        s3_memzero(&frame, sizeof(s3_quic_frame_t));
        s3_memzero(&buf, sizeof(s3_buf_t));
        buf.temporary = 1;

        chain.buf = &buf;
        chain.next = NULL;
        frame.data = &chain;

        len = s3_quic_parse_frame(pkt, p, end, &frame);

        if (len < 0) {
            qc->error = pkt->error;
            return S3_ERROR;
        }

        p += len;

        /* the clone warning is a false positive here */
        // NOLINTNEXTLINE(bugprone-branch-clone)
        switch (frame.type) {
        /* probing frames */
        case S3_QUIC_FT_PADDING:
        case S3_QUIC_FT_PATH_CHALLENGE:
        case S3_QUIC_FT_PATH_RESPONSE:
        case S3_QUIC_FT_NEW_CONNECTION_ID:
            break;

        /* non-probing frames */
        default:
            nonprobing = 1;
            break;
        }

        switch (frame.type) {

        case S3_QUIC_FT_ACK:
        case S3_QUIC_FT_ACK_ECN:

            if (s3_quic_handle_ack_frame(c, pkt, &frame) != S3_OK) {
                return S3_ERROR;
            }

            continue;

        case S3_QUIC_FT_PADDING:
            continue;

        case S3_QUIC_FT_CONNECTION_CLOSE:
        case S3_QUIC_FT_CONNECTION_CLOSE_APP:
            do_close = 1;
            continue;

        default:
            break;
        }

        /* got there with ack-eliciting packet */
        pkt->need_ack = 1;

        switch (frame.type) {

        case S3_QUIC_FT_CRYPTO:

            if (s3_quic_handle_crypto_frame(c, pkt, &frame) != S3_OK) {
                return S3_ERROR;
            }

            break;

        case S3_QUIC_FT_PING:
            break;

        case S3_QUIC_FT_NEW_CONNECTION_ID:

            if (s3_quic_handle_new_connection_id_frame(c, &frame.u.ncid) != S3_OK) {
                return S3_ERROR;
            }

            break;

        case S3_QUIC_FT_HANDSHAKE_DONE:

            if (s3_quic_handle_hs_done(c) != S3_OK) {
                return S3_ERROR;
            }

            break;

        case S3_QUIC_FT_RETIRE_CONNECTION_ID:

            if (s3_quic_handle_retire_connection_id_frame(c, &frame.u.retire_cid) != S3_OK) {
                return S3_ERROR;
            }

            break;

        case S3_QUIC_FT_DATAGRAM:
        case S3_QUIC_FT_DATAGRAM_WITH_LENGTH:

            if (s3_quic_handle_datagram_frame(c, &frame) != S3_OK) {
                return S3_ERROR;
            }

            break;

            /*
             * the reference handles the stream and flow control frames here
             * (D4, s3_quic_streams.c) and the path frames in the migration
             * module (D4, s3_quic_migration.c); until then they are
             * accepted and ignored: a full handler set cannot be answered
             * anyway, there is no output until D3
             */

        case S3_QUIC_FT_STREAM:
        case S3_QUIC_FT_STREAM1:
        case S3_QUIC_FT_STREAM2:
        case S3_QUIC_FT_STREAM3:
        case S3_QUIC_FT_STREAM4:
        case S3_QUIC_FT_STREAM5:
        case S3_QUIC_FT_STREAM6:
        case S3_QUIC_FT_STREAM7:
        case S3_QUIC_FT_MAX_DATA:
        case S3_QUIC_FT_MAX_STREAM_DATA:
        case S3_QUIC_FT_MAX_STREAMS:
        case S3_QUIC_FT_MAX_STREAMS2:
        case S3_QUIC_FT_DATA_BLOCKED:
        case S3_QUIC_FT_STREAM_DATA_BLOCKED:
        case S3_QUIC_FT_STREAMS_BLOCKED:
        case S3_QUIC_FT_STREAMS_BLOCKED2:
        case S3_QUIC_FT_RESET_STREAM:
        case S3_QUIC_FT_STOP_SENDING:
        case S3_QUIC_FT_PATH_CHALLENGE:
        case S3_QUIC_FT_PATH_RESPONSE:
            s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "quic frame type:%ui ignored until D3/D4",
                          frame.type);
            break;

        default:
            s3_log_debug0(S3_LOG_DEBUG_EVENT, c->log, 0, "quic missing frame handler");
            return S3_ERROR;
        }
    }

    if (p != end) {
        s3_log_error(S3_LOG_INFO, c->log, 0, "quic trailing garbage in payload:%ui bytes",
                     (s3_uint_t)(end - p));

        qc->error = S3_QUIC_ERR_FRAME_ENCODING_ERROR;
        return S3_ERROR;
    }

    if (do_close) {
        qc->draining = 1;
        s3_post_event(&qc->close, &qc->ctx->posted_events);
    }

    if (pkt->path != qc->path && nonprobing) {

        /*
         * RFC 9000, 9.2.  Initiating Connection Migration
         *
         * An endpoint can migrate a connection to a new local
         * address by sending packets containing non-probing frames
         * from that address.
         *
         * handled in D4 (s3_quic_migration.c:
         * s3_quic_handle_migration()); the initial path is the only
         * one until then, so the condition cannot fire
         */
    }

    /*
     * the received packet number is queued for acknowledgement
     * (RFC 9000, 13.2.1.  Sending Acknowledgments)
     */
    if (s3_quic_ack_packet(c, pkt) != S3_OK) {
        return S3_ERROR;
    }

    return S3_OK;
}

static s3_int_t
s3_quic_handle_hs_done(s3_connection_t *c)
{
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    if (!qc->client) {
        /* only a server may send it, s3_quic_frame_allowed() filters the rest */

        qc->error = S3_QUIC_ERR_PROTOCOL_VIOLATION;
        qc->error_reason = "HANDSHAKE_DONE from a client";

        return S3_ERROR;
    }

    /*
     * RFC 9001, 4.1.2.  Handshake Complete
     *
     * the handshake is confirmed at 1-RTT: the handshake keys may be
     * discarded and the loss detection state is reset, an endpoint
     * confirms a handshake for sending as soon as the handshake
     * completes
     */

    if (qc->handshake_confirmed) {
        return S3_OK;
    }

    qc->handshake_confirmed = 1;

    s3_quic_discard_ctx(c, S3_QUIC_ENCRYPTION_HANDSHAKE);

    return S3_OK;
}

static s3_int_t
s3_quic_handle_datagram_frame(s3_connection_t *c, s3_quic_frame_t *frame)
{
    u_char               *buf, *p;
    size_t                len;
    s3_chain_t           *cl;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    if (qc->conf->datagram_handler == NULL) {
        s3_log_debug0(S3_LOG_DEBUG_EVENT, c->log, 0, "quic datagram dropped: no handler");
        return S3_OK;
    }

    len = 0;

    for (cl = frame->data; cl != NULL; cl = cl->next) {
        len += s3_buf_size(cl->buf);
    }

    if (len == 0) {
        return S3_OK;
    }

    /* the frame data is a chain; the handler takes one contiguous block */

    buf = s3_palloc(c->pool, len);
    if (buf == NULL) {
        return S3_ERROR;
    }

    p = buf;

    for (cl = frame->data; cl != NULL; cl = cl->next) {
        p = s3_cpymem(p, cl->buf->pos, s3_buf_size(cl->buf));
    }

    /*
     * D5 adds the receive accounting of RFC 9221 here: the per
     * connection queue limit, the drop policy and the
     * datagrams_in_flight bookkeeping on the send side
     */
    qc->conf->datagram_handler(c, buf, len);

    (void)s3_pfree(c->pool, buf);

    return S3_OK;
}

static void
s3_quic_push_handler(s3_event_t *ev)
{
    s3_connection_t *c;

    s3_log_debug0(S3_LOG_DEBUG_EVENT, ev->log, 0, "quic push handler");

    c = ev->data;

    if (s3_quic_output(c) != S3_OK) {
        s3_quic_close_connection(c, S3_ERROR);
    }
}

static void
s3_quic_key_update_handler(s3_event_t *ev)
{
    s3_connection_t      *c;
    s3_quic_connection_t *qc;

    c = ev->data;
    qc = s3_quic_get_connection(c);

    if (qc == NULL) {
        /* already closed on handshake failure */
        return;
    }

    if (s3_quic_keys_update(qc->keys, c->log) != S3_OK) {
        s3_quic_close_connection(c, S3_ERROR);
    }
}

void
s3_quic_shutdown_quic(s3_connection_t *c)
{
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    if (qc->reusable) {
        s3_quic_finalize_connection(c, qc->shutdown_code, qc->shutdown_reason);
    }
}

static s3_int_t
s3_quic_cmp_sockaddr(struct sockaddr *sa1, socklen_t len1, struct sockaddr *sa2, socklen_t len2)
{
    struct sockaddr_in  *sin1, *sin2;
    struct sockaddr_in6 *sin61, *sin62;

    if (sa1 == NULL || sa2 == NULL || len1 != len2) {
        return S3_ERROR;
    }

    if (sa1->sa_family != sa2->sa_family) {
        return S3_ERROR;
    }

    switch (sa1->sa_family) {

    case AF_INET:

        sin1 = (struct sockaddr_in *)sa1;
        sin2 = (struct sockaddr_in *)sa2;

        if (sin1->sin_addr.s_addr != sin2->sin_addr.s_addr || sin1->sin_port != sin2->sin_port) {
            return S3_ERROR;
        }

        return S3_OK;

    case AF_INET6:

        sin61 = (struct sockaddr_in6 *)sa1;
        sin62 = (struct sockaddr_in6 *)sa2;

        if (s3_memcmp(&sin61->sin6_addr, &sin62->sin6_addr, sizeof(struct in6_addr)) != 0 ||
            sin61->sin6_port != sin62->sin6_port) {
            return S3_ERROR;
        }

        return S3_OK;

    default:

        /* the unknown families are compared byte-wise */
        return s3_memcmp(sa1, sa2, len1) == 0 ? S3_OK : S3_ERROR;
    }
}

static s3_int_t
s3_quic_memn2cmp(u_char *s1, u_char *s2, size_t n1, size_t n2)
{
    size_t   n;
    s3_int_t rc;

    n = (n1 <= n2) ? n1 : n2;

    rc = (s3_int_t)s3_memcmp(s1, s2, n);

    if (rc != 0 || n1 == n2) {
        return rc;
    }

    return (n1 < n2) ? -1 : 1;
}

void
s3_quic_rbtree_insert_socket(s3_rbtree_node_t *temp, s3_rbtree_node_t *node,
                             s3_rbtree_node_t *sentinel)
{
    s3_int_t           rc;
    s3_rbtree_node_t **p;
    s3_quic_socket_t  *qsock, *qsockt;

    for (;;) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            qsock = (s3_quic_socket_t *)node;
            qsockt = (s3_quic_socket_t *)temp;

            rc = s3_quic_memn2cmp(qsock->sid.id, qsockt->sid.id, qsock->sid.len, qsockt->sid.len);

            p = (rc < 0) ? &temp->left : &temp->right;
        }

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

s3_connection_t *
s3_quic_lookup_connection(s3_udp_listen_t *ul, s3_str_t *key)
{
    s3_int_t          rc;
    s3_connection_t  *c;
    s3_rbtree_node_t *node, *sentinel;
    s3_quic_socket_t *qsock;
    s3_uint32_t       hash;

    if (key->len == 0) {
        return NULL;
    }

    node = ul->rbtree.root;
    sentinel = ul->rbtree.sentinel;

    hash = s3_crc32_long(key->data, key->len);

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        qsock = (s3_quic_socket_t *)node;

        c = qsock->connection;

        rc = s3_quic_memn2cmp(key->data, qsock->sid.id, key->len, qsock->sid.len);

        if (rc == 0) {
            return c;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}

ssize_t
s3_quic_shared_recv(s3_connection_t *c, u_char *buf, size_t size)
{
    ssize_t           n;
    s3_quic_socket_t *qsock;

    qsock = s3_quic_get_socket(c);

    if (qsock == NULL || qsock->buffer == NULL) {
        return (ssize_t)S3_AGAIN;
    }

    n = (ssize_t)s3_min(qsock->len, size);

    s3_memcpy(buf, qsock->buffer, n);

    qsock->buffer = NULL;
    qsock->len = 0;

    c->read->ready = 0;
    c->read->active = 1;

    return n;
}

s3_int_t
s3_quic_connect(s3_connection_t *c, s3_quic_conf_t *conf)
{
    s3_uint_t             i;
    s3_str_t              dcid;
    s3_quic_tp_t         *ctp;
    s3_quic_client_id_t  *cid;
    s3_quic_socket_t     *qsock;
    s3_quic_connection_t *qc;

    /*
     * RFC 9000, 17.2.  Constant Size of Connection IDs
     *
     * the short header carries no length field for the destination
     * connection id: both peers have to agree on it beforehand, so the
     * parser reads S3_QUIC_SERVER_CID_LEN bytes unconditionally and
     * both sides have to emit a cid of exactly that length
     */

    u_char dcid_buf[S3_QUIC_SERVER_CID_LEN];
    u_char scid_buf[S3_QUIC_SERVER_CID_LEN];

    s3_log_debug0(S3_LOG_DEBUG_EVENT, c->log, 0, "quic connect");

    if (c->sockaddr == NULL || conf == NULL || conf->ssl == NULL || conf->ctx == NULL) {
        s3_log_error(S3_LOG_INFO, c->log, 0, "quic connect: invalid configuration");
        return S3_ERROR;
    }

    qc = s3_pcalloc(c->pool, sizeof(s3_quic_connection_t));
    if (qc == NULL) {
        return S3_ERROR;
    }

    qc->keys = s3_pcalloc(c->pool, sizeof(s3_quic_keys_t));
    if (qc->keys == NULL) {
        return S3_ERROR;
    }

    qc->client = 1;
    qc->keys->is_client = 1;
    qc->version = S3_QUIC_VERSION;

    s3_queue_init(&qc->sockets);
    s3_queue_init(&qc->free_sockets);

    s3_queue_init(&qc->paths);
    s3_queue_init(&qc->free_paths);

    s3_queue_init(&qc->client_ids);
    s3_queue_init(&qc->free_client_ids);

    s3_rbtree_init(&qc->streams.tree, &qc->streams.sentinel, s3_rbtree_insert_value);

    for (i = 0; i < S3_QUIC_SEND_CTX_LAST; i++) {
        s3_queue_init(&qc->send_ctx[i].frames);
        s3_queue_init(&qc->send_ctx[i].sending);
        s3_queue_init(&qc->send_ctx[i].sent);
        qc->send_ctx[i].largest_pn = S3_QUIC_UNSET_PN;
        qc->send_ctx[i].largest_ack = S3_QUIC_UNSET_PN;
        qc->send_ctx[i].largest_range = S3_QUIC_UNSET_PN;
        qc->send_ctx[i].pending_ack = S3_QUIC_UNSET_PN;
    }

    qc->send_ctx[0].level = S3_QUIC_ENCRYPTION_INITIAL;
    qc->send_ctx[1].level = S3_QUIC_ENCRYPTION_HANDSHAKE;
    qc->send_ctx[2].level = S3_QUIC_ENCRYPTION_APPLICATION;

    s3_queue_init(&qc->free_frames);

    s3_quic_init_rtt(qc);

    qc->ctx = conf->ctx;

    qc->pto.log = c->log;
    qc->pto.data = c;
    qc->pto.handler = s3_quic_pto_handler;

    qc->push.log = c->log;
    qc->push.data = c;
    qc->push.handler = s3_quic_push_handler;

    qc->close.log = c->log;
    qc->close.data = c;
    qc->close.handler = s3_quic_close_handler;

    qc->path_validation.log = c->log;
    qc->path_validation.data = c;
    qc->path_validation.handler = NULL;

    qc->key_update.log = c->log;
    qc->key_update.data = c;
    qc->key_update.handler = s3_quic_key_update_handler;

    qc->conf = conf;

    if (s3_quic_init_transport_params(&qc->tp, conf) != S3_OK) {
        return S3_ERROR;
    }

    ctp = &qc->ctp;

    /* defaults to be used before actual server parameters are received */
    ctp->max_udp_payload_size = S3_QUIC_MAX_UDP_PAYLOAD_SIZE;
    ctp->ack_delay_exponent = S3_QUIC_DEFAULT_ACK_DELAY_EXPONENT;
    ctp->max_ack_delay = S3_QUIC_DEFAULT_MAX_ACK_DELAY;
    ctp->active_connection_id_limit = 2;

    s3_queue_init(&qc->streams.uninitialized);
    s3_queue_init(&qc->streams.free);

    qc->streams.recv_max_data = qc->tp.initial_max_data;
    qc->streams.recv_window = qc->streams.recv_max_data;

    qc->streams.client_max_streams_uni = qc->tp.initial_max_streams_uni;
    qc->streams.client_max_streams_bidi = qc->tp.initial_max_streams_bidi;

    qc->congestion.window =
        s3_min(10 * S3_QUIC_MIN_INITIAL_SIZE, s3_max(2 * S3_QUIC_MIN_INITIAL_SIZE, 14720));
    qc->congestion.ssthresh = (size_t)-1;
    qc->congestion.mtu = S3_QUIC_MIN_INITIAL_SIZE;
    qc->congestion.recovery_start = s3_current_msec - 1;

    qc->max_frames = (conf->max_concurrent_streams_uni + conf->max_concurrent_streams_bidi) *
                     conf->stream_buffer_size / 2000;
    qc->max_frames = s3_max(qc->max_frames, 10000);

    /*
     * RFC 9000, 7.2.  Negotiating Connection IDs:
     * the client generates the dcid the first Initial packet is sent
     * to and its own scid
     */

    if (RAND_bytes(dcid_buf, sizeof(dcid_buf)) != 1) {
        goto failed;
    }

    if (RAND_bytes(scid_buf, sizeof(scid_buf)) != 1) {
        goto failed;
    }

    dcid.data = dcid_buf;
    dcid.len = sizeof(dcid_buf);

    if (s3_quic_keys_set_initial_secret(qc->keys, &dcid, c->log) != S3_OK) {
        goto failed;
    }

    /* the anchor socket: our side of the connection (unregistered) */
    qsock = s3_pcalloc(c->pool, sizeof(s3_quic_socket_t));
    if (qsock == NULL) {
        goto failed;
    }

    qsock->sid.seqnum = qc->server_seqnum++;
    qsock->sid.len = sizeof(scid_buf);
    s3_memcpy(qsock->sid.id, scid_buf, sizeof(scid_buf));

    if (s3_quic_listen(c, qc, qsock) != S3_OK) {
        goto failed;
    }

    qsock->used = 1;

    qc->tp.initial_scid.len = qsock->sid.len;
    qc->tp.initial_scid.data = s3_pnalloc(c->pool, qsock->sid.len);
    if (qc->tp.initial_scid.data == NULL) {
        goto failed;
    }

    s3_memcpy(qc->tp.initial_scid.data, qsock->sid.id, qsock->sid.len);

    c->udp = (struct s3_udp_connection_s *)qsock;

    /* the peer id the path is addressed by until the server answers */
    cid = s3_quic_create_client_id(c, &dcid, 0, NULL);
    if (cid == NULL) {
        goto failed;
    }

    qc->path = s3_quic_new_path(c, c->sockaddr, c->socklen, cid);
    if (qc->path == NULL) {
        goto failed;
    }

    qc->path->tag = S3_QUIC_PATH_ACTIVE;

    /* the client is not subject to the amplification limit */
    qc->path->validated = 1;

    qc->reusable = 1;

    if (s3_quic_client_init_connection(c) != S3_OK) {
        goto failed;
    }

    c->recv = s3_udp_recv;

    s3_event_add_timer(c->read, qc->tp.max_idle_timeout);
    s3_event_add_timer(&qc->close, qc->conf->handshake_timeout);

    c->read->handler = s3_quic_input_handler;

    /* the ClientHello goes out with the first output */
    if (s3_quic_handshake(c) != S3_OK) {
        s3_quic_close_connection(c, S3_ERROR);
        return S3_ERROR;
    }

    return S3_OK;

failed:

    s3_quic_keys_cleanup(qc->keys);

    return S3_ERROR;
}
