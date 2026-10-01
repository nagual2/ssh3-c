/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <s3_quic.h>
#include <s3_quic_connection.h>
#include <s3_quic_frames.h>

#define S3_QUIC_BUFFER_SIZE 4096

/*
 * the shadow buf reference count lives in s3_buf_t.num (the only
 * change to the P0 base, see the porting map 4.5.1)
 */
#define s3_quic_buf_refs(b)        (b)->shadow->num
#define s3_quic_buf_inc_refs(b)    s3_quic_buf_refs(b)++
#define s3_quic_buf_dec_refs(b)    s3_quic_buf_refs(b)--
#define s3_quic_buf_set_refs(b, v) s3_quic_buf_refs(b) = v

static s3_buf_t *s3_quic_alloc_buf(s3_connection_t *c);
static void      s3_quic_free_buf(s3_connection_t *c, s3_buf_t *b);
static s3_buf_t *s3_quic_clone_buf(s3_connection_t *c, s3_buf_t *b);
static s3_int_t  s3_quic_split_chain(s3_connection_t *c, s3_chain_t *cl, off_t offset);

static s3_buf_t *
s3_quic_alloc_buf(s3_connection_t *c)
{
    u_char               *p;
    s3_buf_t             *b;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    b = qc->free_bufs;

    if (b) {
        qc->free_bufs = b->shadow;
        p = b->start;

    } else {
        b = qc->free_shadow_bufs;

        if (b) {
            qc->free_shadow_bufs = b->shadow;

        } else {
            b = s3_palloc(c->pool, sizeof(s3_buf_t));
            if (b == NULL) {
                return NULL;
            }
        }

        p = s3_pnalloc(c->pool, S3_QUIC_BUFFER_SIZE);
        if (p == NULL) {
            return NULL;
        }
    }

    s3_memzero(b, sizeof(s3_buf_t));

    b->tag = (s3_buf_tag_t)&s3_quic_alloc_buf;
    b->temporary = 1;
    b->shadow = b;

    b->start = p;
    b->pos = p;
    b->last = p;
    b->end = p + S3_QUIC_BUFFER_SIZE;

    s3_quic_buf_set_refs(b, 1);

    return b;
}

static void
s3_quic_free_buf(s3_connection_t *c, s3_buf_t *b)
{
    s3_buf_t             *shadow;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    s3_quic_buf_dec_refs(b);

    shadow = b->shadow;

    if (s3_quic_buf_refs(b) == 0) {
        shadow->shadow = qc->free_bufs;
        qc->free_bufs = shadow;
    }

    if (b != shadow) {
        b->shadow = qc->free_shadow_bufs;
        qc->free_shadow_bufs = b;
    }
}

static s3_buf_t *
s3_quic_clone_buf(s3_connection_t *c, s3_buf_t *b)
{
    s3_buf_t             *nb;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    nb = qc->free_shadow_bufs;

    if (nb) {
        qc->free_shadow_bufs = nb->shadow;

    } else {
        nb = s3_palloc(c->pool, sizeof(s3_buf_t));
        if (nb == NULL) {
            return NULL;
        }
    }

    *nb = *b;

    s3_quic_buf_inc_refs(b);

    return nb;
}

static s3_int_t
s3_quic_split_chain(s3_connection_t *c, s3_chain_t *cl, off_t offset)
{
    s3_buf_t   *b, *tb;
    s3_chain_t *tail;

    b = cl->buf;

    tail = s3_alloc_chain_link(c->pool);
    if (tail == NULL) {
        return S3_ERROR;
    }

    tb = s3_quic_clone_buf(c, b);
    if (tb == NULL) {
        return S3_ERROR;
    }

    tail->buf = tb;

    tb->pos += offset;

    b->last = tb->pos;
    b->last_buf = 0;

    tail->next = cl->next;
    cl->next = tail;

    return S3_OK;
}

s3_quic_frame_t *
s3_quic_alloc_frame(s3_connection_t *c)
{
    s3_queue_t           *q;
    s3_quic_frame_t      *frame;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    if (!s3_queue_empty(&qc->free_frames)) {

        q = s3_queue_head(&qc->free_frames);
        frame = s3_queue_data(q, s3_quic_frame_t, queue);

        s3_queue_remove(&frame->queue);

    } else if (qc->nframes < qc->max_frames) {
        frame = s3_palloc(c->pool, sizeof(s3_quic_frame_t));
        if (frame == NULL) {
            return NULL;
        }

        ++qc->nframes;

    } else {
        s3_log_error(S3_LOG_INFO, c->log, 0, "quic flood detected");
        return NULL;
    }

    s3_memzero(frame, sizeof(s3_quic_frame_t));

    return frame;
}

void
s3_quic_free_frame(s3_connection_t *c, s3_quic_frame_t *frame)
{
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    if (frame->data) {
        s3_quic_free_chain(c, frame->data);
    }

    s3_queue_insert_head(&qc->free_frames, &frame->queue);
}

void
s3_quic_free_chain(s3_connection_t *c, s3_chain_t *in)
{
    s3_chain_t *cl;

    while (in) {
        cl = in;
        in = in->next;

        s3_quic_free_buf(c, cl->buf);
        s3_free_chain(c->pool, cl);
    }
}

void
s3_quic_free_frames(s3_connection_t *c, s3_queue_t *frames)
{
    s3_queue_t      *q;
    s3_quic_frame_t *f;

    do {
        q = s3_queue_head(frames);

        if (q == s3_queue_sentinel(frames)) {
            break;
        }

        s3_queue_remove(q);

        f = s3_queue_data(q, s3_quic_frame_t, queue);

        s3_quic_free_frame(c, f);
    } while (1);
}

void
s3_quic_queue_frame(s3_quic_connection_t *qc, s3_quic_frame_t *frame)
{
    s3_quic_send_ctx_t *ctx;

    ctx = s3_quic_get_send_ctx(qc, frame->level);

    s3_queue_insert_tail(&ctx->frames, &frame->queue);

    frame->len = s3_quic_create_frame(NULL, frame);
    /* always succeeds */

    if (qc->closing) {
        return;
    }

    /*
     * the frames are packed into packets by s3_quic_output() (D3);
     * until then the push handler only marks the connection as
     * having pending frames
     */
    if (qc->ctx != NULL) {
        s3_post_event(&qc->push, &qc->ctx->posted_events);
    }
}

s3_int_t
s3_quic_split_frame(s3_connection_t *c, s3_quic_frame_t *f, size_t len)
{
    size_t                   shrink;
    s3_chain_t              *out;
    s3_quic_frame_t         *nf;
    s3_quic_buffer_t         qb;
    s3_quic_ordered_frame_t *of, *onf;

    switch (f->type) {
    case S3_QUIC_FT_CRYPTO:
    case S3_QUIC_FT_STREAM:
        break;

    default:
        return S3_DECLINED;
    }

    if ((size_t)f->len <= len) {
        return S3_OK;
    }

    shrink = f->len - len;

    s3_log_debug3(S3_LOG_DEBUG_EVENT, c->log, 0, "quic split frame now:%uz need:%uz shrink:%uz",
                  f->len, len, shrink);

    of = &f->u.ord;

    if (of->length <= shrink) {
        return S3_DECLINED;
    }

    of->length -= shrink;
    f->len = s3_quic_create_frame(NULL, f);

    if ((size_t)f->len > len) {
        s3_log_error(S3_LOG_ERR, c->log, 0, "could not split QUIC frame");
        return S3_ERROR;
    }

    s3_memzero(&qb, sizeof(s3_quic_buffer_t));
    qb.chain = f->data;

    out = s3_quic_read_buffer(c, &qb, of->length);
    if (out == S3_CHAIN_ERROR) {
        return S3_ERROR;
    }

    f->data = out;

    nf = s3_quic_alloc_frame(c);
    if (nf == NULL) {
        return S3_ERROR;
    }

    *nf = *f;
    onf = &nf->u.ord;
    onf->offset += of->length;
    onf->length = shrink;
    nf->len = s3_quic_create_frame(NULL, nf);
    nf->data = qb.chain;

    if (f->type == S3_QUIC_FT_STREAM) {
        f->u.stream.fin = 0;
    }

    s3_queue_insert_after(&f->queue, &nf->queue);

    return S3_OK;
}

s3_chain_t *
s3_quic_copy_buffer(s3_connection_t *c, u_char *data, size_t len)
{
    s3_buf_t         buf;
    s3_chain_t       cl, *out;
    s3_quic_buffer_t qb;

    s3_memzero(&buf, sizeof(s3_buf_t));

    buf.pos = data;
    buf.last = buf.pos + len;
    buf.temporary = 1;

    cl.buf = &buf;
    cl.next = NULL;

    s3_memzero(&qb, sizeof(s3_quic_buffer_t));

    if (s3_quic_write_buffer(c, &qb, &cl, len, 0) == S3_CHAIN_ERROR) {
        return S3_CHAIN_ERROR;
    }

    out = s3_quic_read_buffer(c, &qb, len);
    if (out == S3_CHAIN_ERROR) {
        return S3_CHAIN_ERROR;
    }

    s3_quic_free_buffer(c, &qb);

    return out;
}

s3_chain_t *
s3_quic_read_buffer(s3_connection_t *c, s3_quic_buffer_t *qb, uint64_t limit)
{
    uint64_t    n;
    s3_buf_t   *b;
    s3_chain_t *out, **ll;

    out = qb->chain;

    for (ll = &out; *ll; ll = &(*ll)->next) {
        b = (*ll)->buf;

        if (b->sync) {
            /* hole */
            break;
        }

        if (limit == 0) {
            break;
        }

        n = b->last - b->pos;

        if (n > limit) {
            if (s3_quic_split_chain(c, *ll, limit) != S3_OK) {
                return S3_CHAIN_ERROR;
            }

            n = limit;
        }

        limit -= n;
        qb->offset += n;
    }

    if (qb->offset >= qb->last_offset) {
        qb->last_chain = NULL;
    }

    qb->chain = *ll;
    *ll = NULL;

    return out;
}

void
s3_quic_skip_buffer(s3_connection_t *c, s3_quic_buffer_t *qb, uint64_t offset)
{
    size_t      n;
    s3_buf_t   *b;
    s3_chain_t *cl;

    while (qb->chain) {
        if (qb->offset >= offset) {
            break;
        }

        cl = qb->chain;
        b = cl->buf;
        n = b->last - b->pos;

        if (qb->offset + n > offset) {
            n = offset - qb->offset;
            b->pos += n;
            qb->offset += n;
            break;
        }

        qb->offset += n;
        qb->chain = cl->next;

        cl->next = NULL;
        s3_quic_free_chain(c, cl);
    }

    if (qb->chain == NULL) {
        qb->offset = offset;
    }

    if (qb->offset >= qb->last_offset) {
        qb->last_chain = NULL;
    }
}

s3_chain_t *
s3_quic_alloc_chain(s3_connection_t *c)
{
    s3_chain_t *cl;

    cl = s3_alloc_chain_link(c->pool);
    if (cl == NULL) {
        return NULL;
    }

    cl->buf = s3_quic_alloc_buf(c);
    if (cl->buf == NULL) {
        return NULL;
    }

    return cl;
}

s3_chain_t *
s3_quic_write_buffer(s3_connection_t *c, s3_quic_buffer_t *qb, s3_chain_t *in, uint64_t limit,
                     uint64_t offset)
{
    u_char     *p;
    uint64_t    n, base;
    s3_buf_t   *b;
    s3_chain_t *cl, **chain;

    if (qb->last_chain && offset >= qb->last_offset) {
        base = qb->last_offset;
        chain = &qb->last_chain;

    } else {
        base = qb->offset;
        chain = &qb->chain;
    }

    while (in && limit) {

        if (offset < base) {
            n = s3_min((uint64_t)(in->buf->last - in->buf->pos), s3_min(base - offset, limit));

            in->buf->pos += n;
            offset += n;
            limit -= n;

            if (in->buf->pos == in->buf->last) {
                in = in->next;
            }

            continue;
        }

        cl = *chain;

        if (cl == NULL) {
            cl = s3_quic_alloc_chain(c);
            if (cl == NULL) {
                return S3_CHAIN_ERROR;
            }

            cl->buf->last = cl->buf->end;
            cl->buf->sync = 1; /* hole */
            cl->next = NULL;
            *chain = cl;
        }

        b = cl->buf;
        n = b->last - b->pos;

        if (base + n <= offset) {
            base += n;
            chain = &cl->next;
            continue;
        }

        if (b->sync && offset > base) {
            if (s3_quic_split_chain(c, cl, offset - base) != S3_OK) {
                return S3_CHAIN_ERROR;
            }

            continue;
        }

        p = b->pos + (offset - base);

        while (in) {

            if (!s3_buf_in_memory(in->buf) || in->buf->pos == in->buf->last) {
                in = in->next;
                continue;
            }

            if (p == b->last || limit == 0) {
                break;
            }

            n = s3_min(b->last - p, in->buf->last - in->buf->pos);
            n = s3_min(n, limit);

            if (b->sync) {
                s3_memcpy(p, in->buf->pos, n);
                qb->size += n;
            }

            p += n;
            in->buf->pos += n;
            offset += n;
            limit -= n;
        }

        if (b->sync && p == b->last) {
            b->sync = 0;
            continue;
        }

        if (b->sync && p != b->pos) {
            if (s3_quic_split_chain(c, cl, p - b->pos) != S3_OK) {
                return S3_CHAIN_ERROR;
            }

            b->sync = 0;
        }
    }

    qb->last_offset = base;
    qb->last_chain = *chain;

    return in;
}

void
s3_quic_free_buffer(s3_connection_t *c, s3_quic_buffer_t *qb)
{
    s3_quic_free_chain(c, qb->chain);

    qb->chain = NULL;
    qb->last_chain = NULL;
}
