/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <openssl/rand.h>

#include <s3_quic.h>
#include <s3_quic_connection.h>
#include <s3_quic_connid.h>
#include <s3_quic_frames.h>

#define S3_QUIC_BPF 0

/* the number of server ids the quic layer is willing to issue */
#define S3_QUIC_MAX_SERVER_IDS 8

#if (S3_QUIC_BPF)
static s3_int_t s3_quic_bpf_attach_id(s3_connection_t *c, u_char *id);
#endif
static s3_int_t             s3_quic_retire_client_id(s3_connection_t *c, s3_quic_client_id_t *cid);
static s3_int_t             s3_quic_send_server_id(s3_connection_t *c, s3_quic_server_id_t *sid);
static s3_quic_client_id_t *s3_quic_alloc_client_id(s3_connection_t *c, s3_quic_connection_t *qc);

s3_int_t
s3_quic_create_server_id(s3_connection_t *c, u_char *id)
{
    /* the connection is used by the BPF branch only */
    (void)c;

    if (RAND_bytes(id, S3_QUIC_SERVER_CID_LEN) != 1) {
        return S3_ERROR;
    }

#if (S3_QUIC_BPF)
    if (s3_quic_bpf_attach_id(c, id) != S3_OK) {
        s3_log_error(S3_LOG_ERR, c->log, 0, "quic bpf failed to generate socket key");
        return S3_ERROR;
    }
#endif

    return S3_OK;
}

#if (S3_QUIC_BPF)

/*
 * not compiled in D1: the BPF socket-group machinery depends on the
 * nginx cycle and is not ported (porting map 1.15); the stub body is
 * kept for the reference
 */
static s3_int_t
s3_quic_bpf_attach_id(s3_connection_t *c, u_char *id)
{
    uint64_t key;
    s3_int_t rc;

    rc = s3_quic_bpf_get_worker_key(c, &key);

    if (rc == S3_DECLINED) {
        /* BPF not applicable for this listener, leave DCID as random */
        return S3_OK;
    }

    if (rc != S3_OK) {
        return S3_ERROR;
    }

    s3_quic_dcid_encode_key(id, key);

    return S3_OK;
}

#endif

s3_int_t
s3_quic_handle_new_connection_id_frame(s3_connection_t *c, s3_quic_new_conn_id_frame_t *f)
{
    s3_str_t              id;
    s3_queue_t           *q;
    s3_quic_frame_t      *frame;
    s3_quic_client_id_t  *cid, *item;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    if (f->seqnum < qc->max_retired_seqnum) {
        /*
         * RFC 9000, 19.15.  NEW_CONNECTION_ID Frame
         *
         *  An endpoint that receives a NEW_CONNECTION_ID frame with
         *  a sequence number smaller than the Retire Prior To field
         *  of a previously received NEW_CONNECTION_ID frame MUST send
         *  a corresponding RETIRE_CONNECTION_ID frame that retires
         *  the newly received connection ID, unless it has already
         *  done so for that sequence number.
         */

        frame = s3_quic_alloc_frame(c);
        if (frame == NULL) {
            return S3_ERROR;
        }

        frame->level = S3_QUIC_ENCRYPTION_APPLICATION;
        frame->type = S3_QUIC_FT_RETIRE_CONNECTION_ID;
        frame->u.retire_cid.sequence_number = f->seqnum;

        s3_quic_queue_frame(qc, frame);

        goto retire;
    }

    cid = NULL;

    for (q = s3_queue_head(&qc->client_ids); q != s3_queue_sentinel(&qc->client_ids);
         q = s3_queue_next(q)) {
        item = s3_queue_data(q, s3_quic_client_id_t, queue);

        if (item->seqnum == f->seqnum) {
            cid = item;
            break;
        }
    }

    if (cid) {
        /*
         * Transmission errors, timeouts, and retransmissions might cause the
         * same NEW_CONNECTION_ID frame to be received multiple times.
         */

        if (cid->len != f->len || s3_strncmp(cid->id, f->cid, f->len) != 0 ||
            s3_strncmp(cid->sr_token, f->srt, S3_QUIC_SR_TOKEN_LEN) != 0) {
            /*
             * ..if a sequence number is used for different connection IDs,
             * the endpoint MAY treat that receipt as a connection error
             * of type PROTOCOL_VIOLATION.
             */
            qc->error = S3_QUIC_ERR_PROTOCOL_VIOLATION;
            qc->error_reason = "seqnum refers to different connection id/token";
            return S3_ERROR;
        }

    } else {

        id.data = f->cid;
        id.len = f->len;

        if (s3_quic_create_client_id(c, &id, f->seqnum, f->srt) == NULL) {
            return S3_ERROR;
        }
    }

retire:

    if (qc->max_retired_seqnum && f->retire <= qc->max_retired_seqnum) {
        /*
         * Once a sender indicates a Retire Prior To value, smaller values sent
         * in subsequent NEW_CONNECTION_ID frames have no effect.  A receiver
         * MUST ignore any Retire Prior To fields that do not increase the
         * largest received Retire Prior To value.
         */
        goto done;
    }

    qc->max_retired_seqnum = f->retire;

    q = s3_queue_head(&qc->client_ids);

    while (q != s3_queue_sentinel(&qc->client_ids)) {

        cid = s3_queue_data(q, s3_quic_client_id_t, queue);
        q = s3_queue_next(q);

        if (cid->seqnum >= f->retire) {
            continue;
        }

        if (s3_quic_retire_client_id(c, cid) != S3_OK) {
            return S3_ERROR;
        }
    }

done:

    if (qc->nclient_ids > qc->tp.active_connection_id_limit) {
        /*
         * RFC 9000, 5.1.1.  Issuing Connection IDs
         *
         * After processing a NEW_CONNECTION_ID frame and
         * adding and retiring active connection IDs, if the number of active
         * connection IDs exceeds the value advertised in its
         * active_connection_id_limit transport parameter, an endpoint MUST
         * close the connection with an error of type CONNECTION_ID_LIMIT_ERROR.
         */
        qc->error = S3_QUIC_ERR_CONNECTION_ID_LIMIT_ERROR;
        qc->error_reason = "too many connection ids received";
        return S3_ERROR;
    }

    return S3_OK;
}

static s3_int_t
s3_quic_retire_client_id(s3_connection_t *c, s3_quic_client_id_t *cid)
{
    s3_queue_t           *q;
    s3_quic_path_t       *path;
    s3_quic_client_id_t  *new_cid;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    if (!cid->used) {
        return s3_quic_free_client_id(c, cid);
    }

    /* we are going to retire client id which is in use */

    q = s3_queue_head(&qc->paths);

    while (q != s3_queue_sentinel(&qc->paths)) {

        path = s3_queue_data(q, s3_quic_path_t, queue);
        q = s3_queue_next(q);

        if (path->cid != cid) {
            continue;
        }

        if (path == qc->path) {
            /* this is the active path: update it with new CID */
            new_cid = s3_quic_next_client_id(c);
            if (new_cid == NULL) {
                return S3_ERROR;
            }

            qc->path->cid = new_cid;
            new_cid->used = 1;

            return s3_quic_free_client_id(c, cid);
        }

        return s3_quic_free_path(c, path);
    }

    return S3_OK;
}

static s3_quic_client_id_t *
s3_quic_alloc_client_id(s3_connection_t *c, s3_quic_connection_t *qc)
{
    s3_queue_t          *q;
    s3_quic_client_id_t *cid;

    if (!s3_queue_empty(&qc->free_client_ids)) {

        q = s3_queue_head(&qc->free_client_ids);
        cid = s3_queue_data(q, s3_quic_client_id_t, queue);

        s3_queue_remove(&cid->queue);

        s3_memzero(cid, sizeof(s3_quic_client_id_t));

    } else {

        cid = s3_pcalloc(c->pool, sizeof(s3_quic_client_id_t));
        if (cid == NULL) {
            return NULL;
        }
    }

    return cid;
}

s3_quic_client_id_t *
s3_quic_create_client_id(s3_connection_t *c, s3_str_t *id, uint64_t seqnum, u_char *token)
{
    s3_quic_client_id_t  *cid;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    cid = s3_quic_alloc_client_id(c, qc);
    if (cid == NULL) {
        return NULL;
    }

    cid->seqnum = seqnum;

    cid->len = id->len;
    s3_memcpy(cid->id, id->data, id->len);

    if (token) {
        s3_memcpy(cid->sr_token, token, S3_QUIC_SR_TOKEN_LEN);
    }

    s3_queue_insert_tail(&qc->client_ids, &cid->queue);
    qc->nclient_ids++;

    if (seqnum > qc->client_seqnum) {
        qc->client_seqnum = seqnum;
    }

    s3_log_debug5(S3_LOG_DEBUG_EVENT, c->log, 0, "quic cid seq:%uL received id:%uz:%xV:%*xs",
                  cid->seqnum, id->len, id, (size_t)S3_QUIC_SR_TOKEN_LEN, cid->sr_token);

    return cid;
}

s3_quic_client_id_t *
s3_quic_next_client_id(s3_connection_t *c)
{
    s3_queue_t           *q;
    s3_quic_client_id_t  *cid;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    for (q = s3_queue_head(&qc->client_ids); q != s3_queue_sentinel(&qc->client_ids);
         q = s3_queue_next(q)) {
        cid = s3_queue_data(q, s3_quic_client_id_t, queue);

        if (!cid->used) {
            return cid;
        }
    }

    return NULL;
}

s3_int_t
s3_quic_free_client_id(s3_connection_t *c, s3_quic_client_id_t *cid)
{
    s3_quic_frame_t      *frame;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    frame = s3_quic_alloc_frame(c);
    if (frame == NULL) {
        return S3_ERROR;
    }

    frame->level = S3_QUIC_ENCRYPTION_APPLICATION;
    frame->type = S3_QUIC_FT_RETIRE_CONNECTION_ID;
    frame->u.retire_cid.sequence_number = cid->seqnum;

    s3_quic_queue_frame(qc, frame);

    /* we are no longer going to use this client id */

    s3_queue_remove(&cid->queue);
    s3_queue_insert_head(&qc->free_client_ids, &cid->queue);

    if (qc->nclient_ids > 0) {
        qc->nclient_ids--;
    }

    return S3_OK;
}

s3_int_t
s3_quic_handle_retire_connection_id_frame(s3_connection_t *c, s3_quic_retire_cid_frame_t *f)
{
    s3_quic_socket_t     *qsock;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    if (f->sequence_number >= qc->server_seqnum) {
        /*
         * RFC 9000, 19.16.
         *
         *  Receipt of a RETIRE_CONNECTION_ID frame containing a sequence
         *  number greater than any previously sent to the peer MUST be
         *  treated as a connection error of type PROTOCOL_VIOLATION.
         */
        qc->error = S3_QUIC_ERR_PROTOCOL_VIOLATION;
        qc->error_reason = "sequence number of id to retire was never issued";

        return S3_ERROR;
    }

    qsock = s3_quic_get_socket(c);

    if (qsock->sid.seqnum == f->sequence_number) {

        /*
         * RFC 9000, 19.16.
         *
         * The sequence number specified in a RETIRE_CONNECTION_ID frame MUST
         * NOT refer to the Destination Connection ID field of the packet in
         * which the frame is contained.  The peer MAY treat this as a
         * connection error of type PROTOCOL_VIOLATION.
         */

        qc->error = S3_QUIC_ERR_PROTOCOL_VIOLATION;
        qc->error_reason = "sequence number of id to retire refers DCID";

        return S3_ERROR;
    }

    qsock = s3_quic_find_socket(c, f->sequence_number);
    if (qsock == NULL) {
        return S3_OK;
    }

    s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "quic socket seq:%uL is retired",
                  qsock->sid.seqnum);

    s3_quic_close_socket(c, qsock);

    /* restore socket count up to a limit after deletion */
    if (s3_quic_create_sockets(c) != S3_OK) {
        return S3_ERROR;
    }

    return S3_OK;
}

static s3_int_t
s3_quic_send_server_id(s3_connection_t *c, s3_quic_server_id_t *sid)
{
    s3_str_t              dcid;
    s3_quic_frame_t      *frame;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    dcid.len = sid->len;
    dcid.data = sid->id;

    frame = s3_quic_alloc_frame(c);
    if (frame == NULL) {
        return S3_ERROR;
    }

    frame->level = S3_QUIC_ENCRYPTION_APPLICATION;
    frame->type = S3_QUIC_FT_NEW_CONNECTION_ID;
    frame->u.ncid.seqnum = sid->seqnum;
    frame->u.ncid.retire = 0;
    frame->u.ncid.len = S3_QUIC_SERVER_CID_LEN;
    s3_memcpy(frame->u.ncid.cid, sid->id, S3_QUIC_SERVER_CID_LEN);

    if (s3_quic_new_sr_token(c, &dcid, qc->conf->sr_token_key, frame->u.ncid.srt) != S3_OK) {
        return S3_ERROR;
    }

    s3_quic_queue_frame(qc, frame);

    return S3_OK;
}

s3_int_t
s3_quic_create_sockets(s3_connection_t *c)
{
    s3_uint_t             n;
    s3_quic_socket_t     *qsock;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    n = s3_min(S3_QUIC_MAX_SERVER_IDS, qc->ctp.active_connection_id_limit);

    s3_log_debug2(S3_LOG_DEBUG_EVENT, c->log, 0, "quic create sockets has:%ui max:%ui",
                  qc->nsockets, n);

    while (qc->nsockets < n) {

        qsock = s3_quic_create_socket(c, qc);
        if (qsock == NULL) {
            return S3_ERROR;
        }

        if (s3_quic_listen(c, qc, qsock) != S3_OK) {
            return S3_ERROR;
        }

        if (s3_quic_send_server_id(c, &qsock->sid) != S3_OK) {
            return S3_ERROR;
        }
    }

    return S3_OK;
}
