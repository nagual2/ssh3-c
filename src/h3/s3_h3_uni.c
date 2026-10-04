/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

/*
 * the HTTP/3 uni streams and the session lifecycle, the reference
 * ngx_http_v3_uni.c and the lifecycle part of ngx_http_v3.c
 *
 * ssh3-c: the stream pseudo connections keep c->data pointing to the
 * quic stream (the s3_quic_stream_t) for the whole stream life — the
 * quic stream recv/send and the stream cleanup handler read it.  The
 * per-stream h3 state hangs on the event data pointers instead (the
 * application slot of rev->data/wev->data, the reference sc->data),
 * and the parent connection is carried in the state, the reference
 * resolves it through c->quic->parent (porting map 4.3.2)
 */

#include <s3_h3.h>
#include <s3_h3_uni.h>
#include <s3_quic_connection.h>

typedef struct {
    s3_h3_parse_uni_t parse;

    /* the quic parent connection holding the session */
    s3_connection_t *parent;

    /* the stream pseudo connection (the handlers read it) */
    s3_connection_t *c;

    /*
     * the known_streams[] slot; -1 for the unknown stream types, the
     * reference ngx_http_v3_uni_stream_t
     */
    s3_int_t index;

    /* the stream type is parsed and registered */
    unsigned registered : 1;
} s3_h3_uni_stream_t;

/*
 * the stream type state of s3_h3_parse_uni() (its sw_type); the uni
 * stream registration runs once the parser has left it — the wave-1
 * parse layer tolerates the unknown stream types and defers the
 * registration to the integration (s3_h3_parse_uni(), sw_type)
 */
#define S3_H3_UNI_PARSE_TYPE_STATE 1

static void             s3_h3_close_uni_stream(s3_connection_t *c);
static void             s3_h3_uni_read_handler(s3_event_t *rev);
static void             s3_h3_uni_dummy_read_handler(s3_event_t *rev);
static void             s3_h3_uni_dummy_write_handler(s3_event_t *wev);
static void             s3_h3_cleanup_session(void *data);
static s3_int_t         s3_h3_uni_index(s3_connection_t *pc, uint64_t type, unsigned incoming);
static s3_connection_t *s3_h3_uni_parent(s3_connection_t *c);
static s3_h3_session_t *s3_h3_uni_get_session(s3_connection_t *c);

static s3_connection_t *
s3_h3_uni_parent(s3_connection_t *c)
{
    s3_quic_stream_t *qs;

    /*
     * the main quic connection carries the quic socket in c->udp; a
     * stream pseudo connection resolves through c->data, like
     * s3_quic_open_stream() (porting map 4.3.2)
     */
    if (s3_quic_get_connection(c) != NULL) {
        return c;
    }

    qs = c->data;

    return (qs != NULL) ? qs->parent : NULL;
}

static s3_h3_session_t *
s3_h3_uni_get_session(s3_connection_t *c)
{
    c = s3_h3_uni_parent(c);

    return (c != NULL) ? s3_h3_get_session(c) : NULL;
}

/*
 * the known_streams[] slot of a uni stream type: the client-initiated
 * streams occupy the CLIENT_* slots, the server-initiated the SERVER_*
 * ones; the reference is server-only and hardcodes the mapping
 * (the incoming streams are the client's), the ssh3-c roles flip it
 */
static s3_int_t
s3_h3_uni_index(s3_connection_t *pc, uint64_t type, unsigned incoming)
{
    unsigned              base, client_initiated;
    s3_quic_connection_t *qc;

    switch (type) {

    case S3_H3_STREAM_CONTROL:
        base = S3_H3_STREAM_CLIENT_CONTROL;
        break;

    case S3_H3_STREAM_ENCODER:
        base = S3_H3_STREAM_CLIENT_ENCODER;
        break;

    case S3_H3_STREAM_DECODER:
        base = S3_H3_STREAM_CLIENT_DECODER;
        break;

    default:
        return -1;
    }

    qc = s3_quic_get_connection(pc);

    if (incoming) {
        client_initiated = (qc->client == 0); /* the peer initiated it */

    } else {
        client_initiated = (qc->client != 0);
    }

    return (s3_int_t)(base + (client_initiated ? 0 : 1));
}

void
s3_h3_init_uni_stream(s3_connection_t *c)
{
    uint64_t            n;
    s3_connection_t    *pc;
    s3_quic_stream_t   *qs;
    s3_h3_uni_stream_t *us;

    qs = c->data;
    pc = qs->parent;

    s3_log_debug0(S3_LOG_DEBUG_EVENT, c->log, 0, "http3 init uni stream");

    n = qs->id >> 2;

    if (n >= S3_H3_MAX_UNI_STREAMS) {
        s3_quic_finalize_connection(pc, S3_H3_ERR_STREAM_CREATION_ERROR,
                                    "reached maximum number of uni streams");
        s3_close_connection(c);
        return;
    }

    s3_quic_cancelable_stream(c);

    us = s3_pcalloc(c->pool, sizeof(s3_h3_uni_stream_t));
    if (us == NULL) {
        s3_quic_finalize_connection(pc, S3_H3_ERR_INTERNAL_ERROR, "memory allocation error");
        s3_close_connection(c);
        return;
    }

    us->index = -1;
    us->parent = pc;
    us->c = c;

    c->read->data = us;
    c->write->data = us;

    c->read->handler = s3_h3_uni_read_handler;
    c->write->handler = s3_h3_uni_dummy_write_handler;

    /*
     * the app-level read arming, the s3 analog of the reference
     * ngx_handle_read_event(): the quic layer posts the stream events
     * only while they stay active (s3_quic_set_event())
     */
    c->read->active = 1;
    c->write->active = 1;

    /*
     * the first STREAM frame ran before this handler: its data sits
     * in the receive buffer with ready raised
     */
    s3_h3_uni_read_handler(c->read);
}

static void
s3_h3_close_uni_stream(s3_connection_t *c)
{
    s3_h3_uni_stream_t *us;

    s3_log_debug0(S3_LOG_DEBUG_EVENT, c->log, 0, "http3 close stream");

    /*
     * the h3 state hangs on the event data (the quic stream owns
     * c->data); the stream was registered once the state is armed and
     * carries a known_streams[] slot
     */
    us = c->read->data;

    if (us != NULL && us->index >= 0) {
        s3_h3_get_session(us->parent)->known_streams[us->index] = NULL;
    }

    /*
     * ssh3-c: the reference clears c->destroyed, closes the
     * connection and destroys the pool separately; s3_close_connection()
     * destroys the pool and the pool cleanup runs the quic stream
     * shutdown (s3_quic_stream_cleanup_handler())
     */
    s3_close_connection(c);
}

s3_int_t
s3_h3_register_uni_stream(s3_connection_t *c, uint64_t type)
{
    s3_int_t            index;
    s3_uint_t           streams;
    s3_connection_t    *pc;
    s3_h3_session_t    *h3c;
    s3_h3_uni_stream_t *us;

    pc = s3_h3_uni_parent(c);
    h3c = s3_h3_get_session(pc);

    us = c->read->data;

    switch (type) {

    case S3_H3_STREAM_ENCODER:

        s3_log_debug0(S3_LOG_DEBUG_EVENT, c->log, 0, "http3 encoder stream");
        index = s3_h3_uni_index(pc, S3_H3_STREAM_ENCODER, 1);
        break;

    case S3_H3_STREAM_DECODER:

        s3_log_debug0(S3_LOG_DEBUG_EVENT, c->log, 0, "http3 decoder stream");
        index = s3_h3_uni_index(pc, S3_H3_STREAM_DECODER, 1);
        break;

    case S3_H3_STREAM_CONTROL:

        s3_log_debug0(S3_LOG_DEBUG_EVENT, c->log, 0, "http3 control stream");
        index = s3_h3_uni_index(pc, S3_H3_STREAM_CONTROL, 1);
        break;

    default:

        s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "http3 stream 0x%02xL", type);

        /*
         * the mandatory streams of the peer: no other uni stream type
         * may arrive before they are all created
         */
        streams = (1u << s3_h3_uni_index(pc, S3_H3_STREAM_CONTROL, 1)) |
                  (1u << s3_h3_uni_index(pc, S3_H3_STREAM_ENCODER, 1)) |
                  (1u << s3_h3_uni_index(pc, S3_H3_STREAM_DECODER, 1));

        if ((h3c->created_streams & streams) != streams) {
            s3_log_error(S3_LOG_INFO, c->log, 0, "missing mandatory stream");
            return S3_H3_ERR_STREAM_CREATION_ERROR;
        }

        index = -1;
    }

    if (index >= 0) {
        if (h3c->created_streams & (1u << index)) {
            s3_log_error(S3_LOG_INFO, c->log, 0, "stream already created");
            return S3_H3_ERR_STREAM_CREATION_ERROR;
        }

        h3c->known_streams[index] = c;
        h3c->created_streams |= 1u << index;

        if (us != NULL) {
            us->index = index;
        }
    }

    return S3_OK;
}

static void
s3_h3_uni_read_handler(s3_event_t *rev)
{
    u_char              buf[128];
    ssize_t             n;
    s3_buf_t            b;
    s3_int_t            rc;
    s3_connection_t    *c;
    s3_h3_session_t    *h3c;
    s3_h3_uni_stream_t *us;

    us = rev->data;
    c = us->c;

    s3_log_debug0(S3_LOG_DEBUG_EVENT, c->log, 0, "http3 read handler");

    /*
     * the reference checks c->close, set by the quic layer when the
     * stream is reset; the ssh3 layer learns the state through the
     * event error flag (s3_quic_close_streams())
     */
    if (rev->error) {
        s3_h3_close_uni_stream(c);
        return;
    }

    s3_memzero(&b, sizeof(s3_buf_t));

    while (rev->ready) {

        n = c->recv(c, buf, sizeof(buf));

        if (n == S3_ERROR) {
            rc = S3_H3_ERR_INTERNAL_ERROR;
            goto failed;
        }

        if (n == 0) {
            if (us->index >= 0) {
                rc = S3_H3_ERR_CLOSED_CRITICAL_STREAM;
                goto failed;
            }

            s3_log_debug0(S3_LOG_DEBUG_EVENT, c->log, 0, "http3 read eof");
            s3_h3_close_uni_stream(c);
            return;
        }

        if (n == S3_AGAIN) {
            break;
        }

        b.pos = buf;
        b.last = buf + n;

        h3c = s3_h3_get_session(us->parent);
        h3c->total_bytes += n;

        if (s3_h3_check_flood(us->parent) != S3_OK) {
            s3_h3_close_uni_stream(c);
            return;
        }

        /*
         * the h3 layers reach the session through c->data, so the
         * parent connection is the one the parser has to see — c is
         * the stream pseudo connection and its data is the quic
         * stream
         */
        rc = s3_h3_parse_uni(us->parent, &us->parse, &b);

        if (rc == S3_DONE) {
            s3_log_debug0(S3_LOG_DEBUG_EVENT, c->log, 0, "http3 read done");
            s3_h3_close_uni_stream(c);
            return;
        }

        if (rc > 0) {
            goto failed;
        }

        if (rc != S3_AGAIN) {
            rc = S3_H3_ERR_GENERAL_PROTOCOL_ERROR;
            goto failed;
        }

        /*
         * ssh3-c: the registration of the uni stream runs once the
         * parser has left the type state (S3_H3_UNI_PARSE_TYPE_STATE);
         * the wave-1 parse layer tolerates the unknown stream types
         * and defers the registration to the integration
         */
        if (!us->registered && us->parse.state > S3_H3_UNI_PARSE_TYPE_STATE) {

            rc = s3_h3_register_uni_stream(c, us->parse.vlint.value);
            if (rc != S3_OK) {
                /* rc carries the h3 error code */
                goto failed;
            }

            us->registered = 1;
        }
    }

    /*
     * the reference re-arms the read event here
     * (ngx_handle_read_event()); the ssh3 analog is the active flag
     * armed in s3_h3_init_uni_stream(), the quic layer posts the
     * event while it stays active
     */

    return;

failed:

    s3_quic_finalize_connection(us->parent, rc, "stream error");
    s3_h3_close_uni_stream(c);
}

static void
s3_h3_uni_dummy_read_handler(s3_event_t *rev)
{
    u_char              ch;
    s3_connection_t    *c;
    s3_h3_uni_stream_t *us;

    us = rev->data;
    c = us->c;

    s3_log_debug0(S3_LOG_DEBUG_EVENT, c->log, 0, "http3 dummy read handler");

    if (rev->error) {
        s3_h3_close_uni_stream(c);
        return;
    }

    /*
     * the peer must not send anything on the uni streams we opened
     */
    if (rev->ready) {
        if (c->recv(c, &ch, 1) != 0) {
            s3_quic_finalize_connection(us->parent, S3_H3_ERR_NO_ERROR, NULL);
            s3_h3_close_uni_stream(c);
            return;
        }
    }

    /* the read event stays armed, see s3_h3_get_uni_stream() */
}

static void
s3_h3_uni_dummy_write_handler(s3_event_t *wev)
{
    /*
     * the reference re-arms the write event here
     * (ngx_handle_write_event()); the ssh3 write event stays armed
     * and the quic layer posts it, nothing to do
     */

    (void)wev;
}

s3_connection_t *
s3_h3_get_uni_stream(s3_connection_t *c, s3_uint_t type)
{
    u_char              buf[S3_H3_VARLEN_INT_LEN];
    size_t              n;
    s3_int_t            index;
    ssize_t             m;
    s3_connection_t    *pc, *sc;
    s3_h3_session_t    *h3c;
    s3_h3_uni_stream_t *us;

    pc = s3_h3_uni_parent(c);
    h3c = s3_h3_get_session(pc);

    index = s3_h3_uni_index(pc, type, 0);

    if (index >= 0 && h3c->known_streams[index] != NULL) {
        return h3c->known_streams[index];
    }

    sc = s3_quic_open_stream(pc, 0);
    if (sc == NULL) {
        goto failed;
    }

    s3_quic_cancelable_stream(sc);

    s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "http3 create uni stream, type:%ui", type);

    us = s3_pcalloc(sc->pool, sizeof(s3_h3_uni_stream_t));
    if (us == NULL) {
        goto failed;
    }

    us->index = index;
    us->parent = pc;
    us->c = sc;

    sc->read->data = us;
    sc->write->data = us;

    sc->read->handler = s3_h3_uni_dummy_read_handler;
    sc->write->handler = s3_h3_uni_dummy_write_handler;

    sc->read->active = 1;
    sc->write->active = 1;

    if (index >= 0) {
        h3c->known_streams[index] = sc;
    }

    /* the encoder returns the past-the-end pointer, like the reference */
    n = (size_t)(s3_h3_encode_varlen_int(buf, type) - (uintptr_t)buf);

    h3c->total_bytes += n;

    m = s3_quic_stream_send(sc, buf, n);

    if (m != (ssize_t)n) {
        goto failed;
    }

    if (h3c->ctx != NULL) {
        s3_post_event(sc->read, &h3c->ctx->posted_events);
    }

    return sc;

failed:

    s3_log_error(S3_LOG_ERR, c->log, 0, "failed to create uni stream");

    s3_quic_finalize_connection(pc, S3_H3_ERR_STREAM_CREATION_ERROR, "failed to create uni stream");

    if (sc != NULL) {
        s3_h3_close_uni_stream(sc);
    }

    return NULL;
}

s3_int_t
s3_h3_send_settings(s3_connection_t *c)
{
    u_char          *p, buf[S3_H3_VARLEN_INT_LEN * 6];
    size_t           n;
    ssize_t          m;
    s3_connection_t *pc, *cc;
    s3_h3_session_t *h3c;

    s3_log_debug0(S3_LOG_DEBUG_EVENT, c->log, 0, "http3 send settings");

    pc = s3_h3_uni_parent(c);

    cc = s3_h3_get_uni_stream(pc, S3_H3_STREAM_CONTROL);
    if (cc == NULL) {
        return S3_ERROR;
    }

    h3c = s3_h3_get_session(pc);

    /*
     * ssh3-c: the reference sends h3scf->max_table_capacity and
     * h3scf->max_blocked_streams; the server branch carries no dynamic
     * tables (s3_h3_set_param() logs the capacity), both are zero
     */

    n = (size_t)s3_h3_encode_varlen_int(NULL, S3_H3_PARAM_MAX_TABLE_CAPACITY);
    n += (size_t)s3_h3_encode_varlen_int(NULL, 0);
    n += (size_t)s3_h3_encode_varlen_int(NULL, S3_H3_PARAM_BLOCKED_STREAMS);
    n += (size_t)s3_h3_encode_varlen_int(NULL, 0);

    p = (u_char *)s3_h3_encode_varlen_int(buf, S3_H3_FRAME_SETTINGS);
    p = (u_char *)s3_h3_encode_varlen_int(p, n);
    p = (u_char *)s3_h3_encode_varlen_int(p, S3_H3_PARAM_MAX_TABLE_CAPACITY);
    p = (u_char *)s3_h3_encode_varlen_int(p, 0);
    p = (u_char *)s3_h3_encode_varlen_int(p, S3_H3_PARAM_BLOCKED_STREAMS);
    p = (u_char *)s3_h3_encode_varlen_int(p, 0);
    n = (size_t)(p - buf);

    h3c->total_bytes += n;

    m = s3_quic_stream_send(cc, buf, n);

    if (m != (ssize_t)n) {
        goto failed;
    }

    return S3_OK;

failed:

    s3_log_error(S3_LOG_ERR, c->log, 0, "failed to send settings");

    s3_quic_finalize_connection(pc, S3_H3_ERR_EXCESSIVE_LOAD, "failed to send settings");
    s3_h3_close_uni_stream(cc);

    return S3_ERROR;
}

s3_int_t
s3_h3_send_goaway(s3_connection_t *c, uint64_t id)
{
    u_char          *p, buf[S3_H3_VARLEN_INT_LEN * 3];
    size_t           n;
    ssize_t          m;
    s3_connection_t *pc, *cc;
    s3_h3_session_t *h3c;

    pc = s3_h3_uni_parent(c);

    s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "http3 send goaway %uL", id);

    cc = s3_h3_get_uni_stream(pc, S3_H3_STREAM_CONTROL);
    if (cc == NULL) {
        return S3_ERROR;
    }

    h3c = s3_h3_get_session(pc);

    n = (size_t)s3_h3_encode_varlen_int(NULL, id);
    p = (u_char *)s3_h3_encode_varlen_int(buf, S3_H3_FRAME_GOAWAY);
    p = (u_char *)s3_h3_encode_varlen_int(p, n);
    p = (u_char *)s3_h3_encode_varlen_int(p, id);
    n = (size_t)(p - buf);

    h3c->total_bytes += n;

    m = s3_quic_stream_send(cc, buf, n);

    if (m != (ssize_t)n) {
        goto failed;
    }

    /*
     * ssh3-c: the reference marks the session in ngx_http_v3_shutdown()
     * before the goaway goes out; the request layer is the application
     * and send_goaway() is the session shutdown boundary here
     */
    h3c->goaway = 1;

    return S3_OK;

failed:

    s3_log_error(S3_LOG_ERR, c->log, 0, "failed to send goaway");

    s3_quic_finalize_connection(pc, S3_H3_ERR_EXCESSIVE_LOAD, "failed to send goaway");
    s3_h3_close_uni_stream(cc);

    return S3_ERROR;
}

s3_int_t
s3_h3_send_ack_section(s3_connection_t *c, s3_uint_t stream_id)
{
    u_char           buf[S3_H3_PREFIX_INT_LEN];
    size_t           n;
    ssize_t          m;
    s3_connection_t *pc, *dc;
    s3_h3_session_t *h3c;

    pc = s3_h3_uni_parent(c);

    s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "http3 send section acknowledgement %ui",
                  stream_id);

    dc = s3_h3_get_uni_stream(pc, S3_H3_STREAM_DECODER);
    if (dc == NULL) {
        return S3_ERROR;
    }

    h3c = s3_h3_get_session(pc);

    buf[0] = 0x80;
    n = (size_t)(s3_h3_encode_prefix_int(buf, stream_id, 7) - (uintptr_t)buf);

    h3c->total_bytes += n;

    m = s3_quic_stream_send(dc, buf, n);

    if (m != (ssize_t)n) {
        goto failed;
    }

    return S3_OK;

failed:

    s3_log_error(S3_LOG_ERR, c->log, 0, "failed to send section acknowledgement");

    s3_quic_finalize_connection(pc, S3_H3_ERR_EXCESSIVE_LOAD,
                                "failed to send section acknowledgement");
    s3_h3_close_uni_stream(dc);

    return S3_ERROR;
}

s3_int_t
s3_h3_send_cancel_stream(s3_connection_t *c, s3_uint_t stream_id)
{
    u_char           buf[S3_H3_PREFIX_INT_LEN];
    size_t           n;
    ssize_t          m;
    s3_connection_t *pc, *dc;
    s3_h3_session_t *h3c;

    pc = s3_h3_uni_parent(c);

    s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "http3 send stream cancellation %ui", stream_id);

    dc = s3_h3_get_uni_stream(pc, S3_H3_STREAM_DECODER);
    if (dc == NULL) {
        return S3_ERROR;
    }

    h3c = s3_h3_get_session(pc);

    buf[0] = 0x40;
    n = (size_t)(s3_h3_encode_prefix_int(buf, stream_id, 6) - (uintptr_t)buf);

    h3c->total_bytes += n;

    m = s3_quic_stream_send(dc, buf, n);

    if (m != (ssize_t)n) {
        goto failed;
    }

    return S3_OK;

failed:

    s3_log_error(S3_LOG_ERR, c->log, 0, "failed to send stream cancellation");

    s3_quic_finalize_connection(pc, S3_H3_ERR_EXCESSIVE_LOAD, "failed to send stream cancellation");
    s3_h3_close_uni_stream(dc);

    return S3_ERROR;
}

s3_int_t
s3_h3_send_inc_insert_count(s3_connection_t *c, s3_uint_t inc)
{
    u_char           buf[S3_H3_PREFIX_INT_LEN];
    size_t           n;
    ssize_t          m;
    s3_connection_t *pc, *dc;
    s3_h3_session_t *h3c;

    pc = s3_h3_uni_parent(c);

    s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "http3 send insert count increment %ui", inc);

    dc = s3_h3_get_uni_stream(pc, S3_H3_STREAM_DECODER);
    if (dc == NULL) {
        return S3_ERROR;
    }

    h3c = s3_h3_get_session(pc);

    buf[0] = 0;
    n = (size_t)(s3_h3_encode_prefix_int(buf, inc, 6) - (uintptr_t)buf);

    h3c->total_bytes += n;

    m = s3_quic_stream_send(dc, buf, n);

    if (m != (ssize_t)n) {
        goto failed;
    }

    return S3_OK;

failed:

    s3_log_error(S3_LOG_ERR, c->log, 0, "failed to send insert count increment");

    s3_quic_finalize_connection(pc, S3_H3_ERR_EXCESSIVE_LOAD,
                                "failed to send insert count increment");
    s3_h3_close_uni_stream(dc);

    return S3_ERROR;
}

s3_int_t
s3_h3_cancel_stream(s3_connection_t *c, s3_uint_t stream_id)
{
    s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "http3 cancel stream %ui", stream_id);

    /* we do not use dynamic tables */

    return S3_OK;
}

void
s3_h3_init_stream(s3_connection_t *c)
{
    s3_quic_stream_t *qs;

    /*
     * the accepted streams arrive through conf->stream_handler with
     * c->data pointing to the quic stream; the session layer arms the
     * uni streams, the bidi request streams belong to the request
     * layer
     */
    qs = c->data;

    if (qs->id & S3_QUIC_STREAM_UNIDIRECTIONAL) {
        s3_h3_init_uni_stream(c);
        return;
    }

    /*
     * ssh3-c: request layer is the app — the reference arms the
     * request stream here (ngx_http_v3_init_request_stream()), the
     * ssh3-c request layer owns the bidi streams
     */
}

void
s3_h3_reset_stream(s3_connection_t *c)
{
    s3_int_t          index;
    s3_connection_t  *pc;
    s3_h3_session_t  *h3c;
    s3_quic_stream_t *qs;

    qs = c->data;
    pc = qs->parent;
    h3c = s3_h3_get_session(pc);

    /*
     * the stream cancellation goes to the decoder stream of this role
     * once the peer can decode: the reference guards it with the
     * known decoder stream
     */
    index = s3_h3_uni_index(pc, S3_H3_STREAM_DECODER, 0);

    if (!c->read->eof && h3c->known_streams[index] != NULL &&
        (qs->id & S3_QUIC_STREAM_UNIDIRECTIONAL) == 0) {
        (void)s3_h3_send_cancel_stream(pc, qs->id);
    }

    /*
     * ssh3-c: the reference reads the request accounting
     * (c->timedout, c->close, c->requests); the ssh3 connection
     * carries the flags on the events and the request accounting
     * stays with the request layer
     */
    if (c->read->timedout || c->write->timedout) {
        (void)s3_quic_reset_stream(c, S3_H3_ERR_GENERAL_PROTOCOL_ERROR);

    } else if (c->read->error || c->write->error) {
        (void)s3_quic_reset_stream(c, S3_H3_ERR_REQUEST_REJECTED);
    }
}

s3_int_t
s3_h3_init_session(s3_connection_t *c)
{
    s3_pool_cleanup_t    *cln;
    s3_quic_connection_t *qc;
    s3_h3_session_t      *h3c;

    s3_log_debug0(S3_LOG_DEBUG_EVENT, c->log, 0, "http3 init session");

    qc = s3_quic_get_connection(c);

    if (qc == NULL) {
        s3_log_error(S3_LOG_ERR, c->log, 0, "failed to create http3 session");
        return S3_ERROR;
    }

    h3c = s3_pcalloc(c->pool, sizeof(s3_h3_session_t));
    if (h3c == NULL) {
        goto failed;
    }

    /*
     * ssh3-c: the event context of the parent connection; the table
     * layer posts the send_insert_count event there (nginx posts to
     * the global ngx_posted_events queue)
     */
    h3c->ctx = qc->ctx;

    s3_queue_init(&h3c->blocked);

    /*
     * ssh3-c: the reference links the http connection and arms the
     * session keepalive timer here; the request layer is the
     * application and the session carries no timer (the quic
     * conf->idle_timeout applies)
     */

    h3c->table.send_insert_count.log = c->log;
    h3c->table.send_insert_count.data = c;
    h3c->table.send_insert_count.handler = s3_h3_inc_insert_count_handler;

    cln = s3_pool_cleanup_add(c->pool, 0);
    if (cln == NULL) {
        goto failed;
    }

    cln->handler = s3_h3_cleanup_session;
    cln->data = h3c;

    c->data = h3c;

    /*
     * ssh3-c: the uni streams of the role are opened eagerly — the
     * reference creates the control stream in send_settings() and the
     * decoder stream when the table is configured (h3scf->
     * max_table_capacity > 0); the ssh3-c session bring-up owns the
     * three streams of the role and announces the zero-capacity
     * server branch in the settings
     */
    if (s3_h3_get_uni_stream(c, S3_H3_STREAM_CONTROL) == NULL) {
        return S3_ERROR;
    }

    if (s3_h3_get_uni_stream(c, S3_H3_STREAM_ENCODER) == NULL) {
        return S3_ERROR;
    }

    if (s3_h3_get_uni_stream(c, S3_H3_STREAM_DECODER) == NULL) {
        return S3_ERROR;
    }

    if (s3_h3_send_settings(c) != S3_OK) {
        return S3_ERROR;
    }

    return S3_OK;

failed:

    s3_log_error(S3_LOG_ERR, c->log, 0, "failed to create http3 session");
    return S3_ERROR;
}

static void
s3_h3_cleanup_session(void *data)
{
    s3_h3_session_t *h3c = data;

    s3_h3_cleanup_table(h3c);

    /*
     * ssh3-c: the reference deletes the keepalive timer here; the
     * session carries no timer, the posted table event is deleted
     */
    if (h3c->table.send_insert_count.posted) {
        s3_delete_posted_event(&h3c->table.send_insert_count);
    }
}

s3_int_t
s3_h3_check_flood(s3_connection_t *c)
{
    s3_h3_session_t *h3c;

    h3c = s3_h3_uni_get_session(c);

    if (h3c->total_bytes / 8 > h3c->payload_bytes + 1048576) {
        s3_log_error(S3_LOG_INFO, c->log, 0, "http3 flood detected");

        s3_quic_finalize_connection(s3_h3_uni_parent(c), S3_H3_ERR_NO_ERROR,
                                    "HTTP/3 flood detected");
        return S3_ERROR;
    }

    return S3_OK;
}
