
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <s3_h3.h>

#define s3_h3_table_entry_size(n, v) ((n)->len + (v)->len + 32)

/*
 * ssh3-c: nginx reads the http3_max_blocked_streams server conf
 * (default 16); the configurable limit arrives with the session layer
 */
#define S3_H3_MAX_BLOCKED_STREAMS 16

static s3_int_t s3_h3_evict(s3_connection_t *c, size_t target);
static void     s3_h3_unblock(void *data);
static s3_int_t s3_h3_new_entry(s3_connection_t *c);
static s3_int_t s3_h3_send_inc_insert_count(s3_connection_t *c, s3_uint_t inc);

typedef struct {
    s3_queue_t       queue;
    s3_connection_t *connection;
    s3_uint_t       *nblocked;
} s3_h3_block_t;

static s3_h3_field_t s3_h3_static_table[] = {

    {s3_string(":authority"), s3_string("")},
    {s3_string(":path"), s3_string("/")},
    {s3_string("age"), s3_string("0")},
    {s3_string("content-disposition"), s3_string("")},
    {s3_string("content-length"), s3_string("0")},
    {s3_string("cookie"), s3_string("")},
    {s3_string("date"), s3_string("")},
    {s3_string("etag"), s3_string("")},
    {s3_string("if-modified-since"), s3_string("")},
    {s3_string("if-none-match"), s3_string("")},
    {s3_string("last-modified"), s3_string("")},
    {s3_string("link"), s3_string("")},
    {s3_string("location"), s3_string("")},
    {s3_string("referer"), s3_string("")},
    {s3_string("set-cookie"), s3_string("")},
    {s3_string(":method"), s3_string("CONNECT")},
    {s3_string(":method"), s3_string("DELETE")},
    {s3_string(":method"), s3_string("GET")},
    {s3_string(":method"), s3_string("HEAD")},
    {s3_string(":method"), s3_string("OPTIONS")},
    {s3_string(":method"), s3_string("POST")},
    {s3_string(":method"), s3_string("PUT")},
    {s3_string(":scheme"), s3_string("http")},
    {s3_string(":scheme"), s3_string("https")},
    {s3_string(":status"), s3_string("103")},
    {s3_string(":status"), s3_string("200")},
    {s3_string(":status"), s3_string("304")},
    {s3_string(":status"), s3_string("404")},
    {s3_string(":status"), s3_string("503")},
    {s3_string("accept"), s3_string("*/*")},
    {s3_string("accept"), s3_string("application/dns-message")},
    {s3_string("accept-encoding"), s3_string("gzip, deflate, br")},
    {s3_string("accept-ranges"), s3_string("bytes")},
    {s3_string("access-control-allow-headers"), s3_string("cache-control")},
    {s3_string("access-control-allow-headers"), s3_string("content-type")},
    {s3_string("access-control-allow-origin"), s3_string("*")},
    {s3_string("cache-control"), s3_string("max-age=0")},
    {s3_string("cache-control"), s3_string("max-age=2592000")},
    {s3_string("cache-control"), s3_string("max-age=604800")},
    {s3_string("cache-control"), s3_string("no-cache")},
    {s3_string("cache-control"), s3_string("no-store")},
    {s3_string("cache-control"), s3_string("public, max-age=31536000")},
    {s3_string("content-encoding"), s3_string("br")},
    {s3_string("content-encoding"), s3_string("gzip")},
    {s3_string("content-type"), s3_string("application/dns-message")},
    {s3_string("content-type"), s3_string("application/javascript")},
    {s3_string("content-type"), s3_string("application/json")},
    {s3_string("content-type"), s3_string("application/x-www-form-urlencoded")},
    {s3_string("content-type"), s3_string("image/gif")},
    {s3_string("content-type"), s3_string("image/jpeg")},
    {s3_string("content-type"), s3_string("image/png")},
    {s3_string("content-type"), s3_string("text/css")},
    {s3_string("content-type"), s3_string("text/html;charset=utf-8")},
    {s3_string("content-type"), s3_string("text/plain")},
    {s3_string("content-type"), s3_string("text/plain;charset=utf-8")},
    {s3_string("range"), s3_string("bytes=0-")},
    {s3_string("strict-transport-security"), s3_string("max-age=31536000")},
    {s3_string("strict-transport-security"), s3_string("max-age=31536000;includesubdomains")},
    {s3_string("strict-transport-security"),
     s3_string("max-age=31536000;includesubdomains;preload")},
    {s3_string("vary"), s3_string("accept-encoding")},
    {s3_string("vary"), s3_string("origin")},
    {s3_string("x-content-type-options"), s3_string("nosniff")},
    {s3_string("x-xss-protection"), s3_string("1;mode=block")},
    {s3_string(":status"), s3_string("100")},
    {s3_string(":status"), s3_string("204")},
    {s3_string(":status"), s3_string("206")},
    {s3_string(":status"), s3_string("302")},
    {s3_string(":status"), s3_string("400")},
    {s3_string(":status"), s3_string("403")},
    {s3_string(":status"), s3_string("421")},
    {s3_string(":status"), s3_string("425")},
    {s3_string(":status"), s3_string("500")},
    {s3_string("accept-language"), s3_string("")},
    {s3_string("access-control-allow-credentials"), s3_string("FALSE")},
    {s3_string("access-control-allow-credentials"), s3_string("TRUE")},
    {s3_string("access-control-allow-headers"), s3_string("*")},
    {s3_string("access-control-allow-methods"), s3_string("get")},
    {s3_string("access-control-allow-methods"), s3_string("get, post, options")},
    {s3_string("access-control-allow-methods"), s3_string("options")},
    {s3_string("access-control-expose-headers"), s3_string("content-length")},
    {s3_string("access-control-request-headers"), s3_string("content-type")},
    {s3_string("access-control-request-method"), s3_string("get")},
    {s3_string("access-control-request-method"), s3_string("post")},
    {s3_string("alt-svc"), s3_string("clear")},
    {s3_string("authorization"), s3_string("")},
    {s3_string("content-security-policy"),
     s3_string("script-src 'none';object-src 'none';base-uri 'none'")},
    {s3_string("early-data"), s3_string("1")},
    {s3_string("expect-ct"), s3_string("")},
    {s3_string("forwarded"), s3_string("")},
    {s3_string("if-range"), s3_string("")},
    {s3_string("origin"), s3_string("")},
    {s3_string("purpose"), s3_string("prefetch")},
    {s3_string("server"), s3_string("")},
    {s3_string("timing-allow-origin"), s3_string("*")},
    {s3_string("upgrade-insecure-requests"), s3_string("1")},
    {s3_string("user-agent"), s3_string("")},
    {s3_string("x-forwarded-for"), s3_string("")},
    {s3_string("x-frame-options"), s3_string("deny")},
    {s3_string("x-frame-options"), s3_string("sameorigin")}};

s3_buf_t *
s3_h3_get_insert_buffer(s3_connection_t *c)
{
    s3_h3_session_t       *h3c;
    s3_h3_dynamic_table_t *dt;

    h3c = s3_h3_get_session(c);
    dt = &h3c->table;

    if (dt->insert_buffer == NULL) {
        /*
         * ssh3-c: the h3 session hangs on the quic connection itself,
         * so the buffer comes from c->pool (nginx:
         * c->quic->parent->pool) and is sized with the fixed limit
         * (nginx: h3scf->max_table_capacity)
         */
        dt->insert_buffer = s3_create_temp_buf(c->pool, S3_H3_MAX_TABLE_CAPACITY);
        if (dt->insert_buffer == NULL) {
            return NULL;
        }
    }

    dt->insert_buffer->last = dt->insert_buffer->pos;

    return dt->insert_buffer;
}

s3_int_t
s3_h3_ref_insert(s3_connection_t *c, s3_uint_t dynamic, s3_uint_t index, s3_str_t *value)
{
    s3_str_t               name;
    s3_h3_session_t       *h3c;
    s3_h3_dynamic_table_t *dt;

    if (dynamic) {
        s3_log_debug2(S3_LOG_DEBUG_EVENT, c->log, 0, "http3 ref insert dynamic[%ui] \"%V\"", index,
                      value);

        h3c = s3_h3_get_session(c);
        dt = &h3c->table;

        if (dt->base + dt->nelts <= index) {
            return S3_H3_ERR_ENCODER_STREAM_ERROR;
        }

        index = dt->base + dt->nelts - 1 - index;

        if (s3_h3_lookup(c, index, &name, NULL) != S3_OK) {
            return S3_H3_ERR_ENCODER_STREAM_ERROR;
        }

    } else {
        s3_log_debug2(S3_LOG_DEBUG_EVENT, c->log, 0, "http3 ref insert static[%ui] \"%V\"", index,
                      value);

        if (s3_h3_lookup_static(c, index, &name, NULL) != S3_OK) {
            return S3_H3_ERR_ENCODER_STREAM_ERROR;
        }
    }

    return s3_h3_insert(c, &name, value);
}

s3_int_t
s3_h3_insert(s3_connection_t *c, s3_str_t *name, s3_str_t *value)
{
    u_char                *p;
    size_t                 size;
    s3_h3_field_t         *field;
    s3_h3_session_t       *h3c;
    s3_h3_dynamic_table_t *dt;

    size = s3_h3_table_entry_size(name, value);

    h3c = s3_h3_get_session(c);
    dt = &h3c->table;

    if (size > dt->capacity) {
        s3_log_error(S3_LOG_ERR, c->log, 0, "not enough dynamic table capacity");
        return S3_H3_ERR_ENCODER_STREAM_ERROR;
    }

    s3_log_debug4(S3_LOG_DEBUG_EVENT, c->log, 0, "http3 insert [%ui] \"%V\":\"%V\", size:%uz",
                  dt->base + dt->nelts, name, value, size);

    /*
     * ssh3-c: the entries live in the connection pool and die with it
     * (nginx: ngx_alloc, released per-entry in the table cleanup)
     */
    p = s3_palloc(c->pool, sizeof(s3_h3_field_t) + name->len + value->len);
    if (p == NULL) {
        return S3_ERROR;
    }

    field = (s3_h3_field_t *)p;

    field->name.data = p + sizeof(s3_h3_field_t);
    field->name.len = name->len;
    field->value.data = s3_cpymem(field->name.data, name->data, name->len);
    field->value.len = value->len;
    s3_memcpy(field->value.data, value->data, value->len);

    dt->elts[dt->nelts++] = field;
    dt->size += size;

    dt->insert_count++;

    if (s3_h3_evict(c, dt->capacity) != S3_OK) {
        return S3_ERROR;
    }

    /*
     * ssh3-c: nginx posts to the global ngx_posted_events queue; the
     * kernel uses per-context queues, so the h3 session carries the
     * event context (set by the session layer)
     */
    if (h3c->ctx != NULL) {
        s3_post_event(&dt->send_insert_count, &h3c->ctx->posted_events);
    }

    if (s3_h3_new_entry(c) != S3_OK) {
        return S3_ERROR;
    }

    return S3_OK;
}

void
s3_h3_inc_insert_count_handler(s3_event_t *ev)
{
    s3_connection_t       *c;
    s3_h3_session_t       *h3c;
    s3_h3_dynamic_table_t *dt;

    c = ev->data;

    s3_log_debug0(S3_LOG_DEBUG_EVENT, c->log, 0, "http3 inc insert count handler");

    h3c = s3_h3_get_session(c);
    dt = &h3c->table;

    if (dt->insert_count > dt->ack_insert_count) {
        if (s3_h3_send_inc_insert_count(c, (s3_uint_t)(dt->insert_count - dt->ack_insert_count)) !=
            S3_OK) {
            return;
        }

        dt->ack_insert_count = dt->insert_count;
    }
}

s3_int_t
s3_h3_set_capacity(s3_connection_t *c, s3_uint_t capacity)
{
    s3_uint_t              max, prev_max;
    s3_h3_field_t        **elts;
    s3_h3_session_t       *h3c;
    s3_h3_dynamic_table_t *dt;

    s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "http3 set capacity %ui", capacity);

    h3c = s3_h3_get_session(c);

    /*
     * ssh3-c: the limit is the fixed S3_H3_MAX_TABLE_CAPACITY constant
     * (nginx: h3scf->max_table_capacity); the configurable limit
     * arrives with the session layer
     */
    if (capacity > S3_H3_MAX_TABLE_CAPACITY) {
        s3_log_error(S3_LOG_INFO, c->log, 0, "client exceeded max table capacity limit");
        return S3_H3_ERR_ENCODER_STREAM_ERROR;
    }

    if (s3_h3_evict(c, capacity) != S3_OK) {
        return S3_H3_ERR_ENCODER_STREAM_ERROR;
    }

    dt = &h3c->table;
    max = capacity / 32;
    prev_max = dt->capacity / 32;

    if (max > prev_max) {
        /*
         * ssh3-c: the index array lives in the pool, the previous
         * array dies with it (nginx: ngx_alloc + ngx_free)
         */
        elts = s3_palloc(c->pool, (max + 1) * sizeof(void *));
        if (elts == NULL) {
            return S3_ERROR;
        }

        if (dt->elts) {
            s3_memcpy(elts, dt->elts, dt->nelts * sizeof(void *));
        }

        dt->elts = elts;
    }

    dt->capacity = capacity;

    return S3_OK;
}

void
s3_h3_cleanup_table(s3_h3_session_t *h3c)
{
    /*
     * ssh3-c: the entries and the index array live in the connection
     * pool (nginx frees the malloc'ed ones here); nothing to release
     */
    (void)h3c;
}

static s3_int_t
s3_h3_evict(s3_connection_t *c, size_t target)
{
    size_t                 size;
    s3_uint_t              n;
    s3_h3_field_t         *field;
    s3_h3_session_t       *h3c;
    s3_h3_dynamic_table_t *dt;

    h3c = s3_h3_get_session(c);
    dt = &h3c->table;
    n = 0;

    while (dt->size > target) {
        field = dt->elts[n++];
        size = s3_h3_table_entry_size(&field->name, &field->value);

        s3_log_debug4(S3_LOG_DEBUG_EVENT, c->log, 0, "http3 evict [%ui] \"%V\":\"%V\" size:%uz",
                      dt->base, &field->name, &field->value, size);

        /* ssh3-c: pool memory, no per-entry free (nginx: ngx_free) */
        dt->size -= size;
    }

    if (n) {
        dt->nelts -= n;
        dt->base += n;
        s3_memmove(dt->elts, &dt->elts[n], dt->nelts * sizeof(void *));
    }

    return S3_OK;
}

s3_int_t
s3_h3_duplicate(s3_connection_t *c, s3_uint_t index)
{
    s3_str_t               name, value;
    s3_h3_session_t       *h3c;
    s3_h3_dynamic_table_t *dt;

    s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "http3 duplicate %ui", index);

    h3c = s3_h3_get_session(c);
    dt = &h3c->table;

    if (dt->base + dt->nelts <= index) {
        return S3_H3_ERR_ENCODER_STREAM_ERROR;
    }

    index = dt->base + dt->nelts - 1 - index;

    if (s3_h3_lookup(c, index, &name, &value) != S3_OK) {
        return S3_H3_ERR_ENCODER_STREAM_ERROR;
    }

    return s3_h3_insert(c, &name, &value);
}

s3_int_t
s3_h3_ack_section(s3_connection_t *c, s3_uint_t stream_id)
{
    s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "http3 ack section %ui", stream_id);

    /* we do not use dynamic tables */

    return S3_H3_ERR_DECODER_STREAM_ERROR;
}

s3_int_t
s3_h3_inc_insert_count(s3_connection_t *c, s3_uint_t inc)
{
    s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "http3 increment insert count %ui", inc);

    /* we do not use dynamic tables */

    return S3_H3_ERR_DECODER_STREAM_ERROR;
}

s3_int_t
s3_h3_lookup_static(s3_connection_t *c, s3_uint_t index, s3_str_t *name, s3_str_t *value)
{
    s3_uint_t      nelts;
    s3_h3_field_t *field;

    nelts = sizeof(s3_h3_static_table) / sizeof(s3_h3_static_table[0]);

    if (index >= nelts) {
        s3_log_debug2(S3_LOG_DEBUG_EVENT, c->log, 0, "http3 static[%ui] lookup out of bounds: %ui",
                      index, nelts);
        return S3_ERROR;
    }

    field = &s3_h3_static_table[index];

    s3_log_debug3(S3_LOG_DEBUG_EVENT, c->log, 0, "http3 static[%ui] lookup \"%V\":\"%V\"", index,
                  &field->name, &field->value);

    if (name) {
        *name = field->name;
    }

    if (value) {
        *value = field->value;
    }

    return S3_OK;
}

s3_int_t
s3_h3_lookup(s3_connection_t *c, s3_uint_t index, s3_str_t *name, s3_str_t *value)
{
    s3_h3_field_t         *field;
    s3_h3_session_t       *h3c;
    s3_h3_dynamic_table_t *dt;

    h3c = s3_h3_get_session(c);
    dt = &h3c->table;

    if (index < dt->base || index - dt->base >= dt->nelts) {
        s3_log_debug3(S3_LOG_DEBUG_EVENT, c->log, 0,
                      "http3 dynamic[%ui] lookup out of bounds: [%ui,%ui]", index, dt->base,
                      dt->base + dt->nelts);
        return S3_ERROR;
    }

    field = dt->elts[index - dt->base];

    s3_log_debug3(S3_LOG_DEBUG_EVENT, c->log, 0, "http3 dynamic[%ui] lookup \"%V\":\"%V\"", index,
                  &field->name, &field->value);

    if (name) {
        *name = field->name;
    }

    if (value) {
        *value = field->value;
    }

    return S3_OK;
}

s3_int_t
s3_h3_decode_insert_count(s3_connection_t *c, s3_uint_t *insert_count)
{
    s3_uint_t              max_entries, full_range, max_value, max_wrapped, req_insert_count;
    s3_h3_session_t       *h3c;
    s3_h3_dynamic_table_t *dt;

    /* QPACK 4.5.1.1. Required Insert Count */

    if (*insert_count == 0) {
        return S3_OK;
    }

    h3c = s3_h3_get_session(c);
    dt = &h3c->table;

    /* ssh3-c: the fixed limit instead of h3scf->max_table_capacity */
    max_entries = S3_H3_MAX_TABLE_CAPACITY / 32;
    full_range = 2 * max_entries;

    if (*insert_count > full_range) {
        return S3_H3_ERR_DECOMPRESSION_FAILED;
    }

    max_value = dt->base + dt->nelts + max_entries;
    max_wrapped = (max_value / full_range) * full_range;
    req_insert_count = max_wrapped + *insert_count - 1;

    if (req_insert_count > max_value) {
        if (req_insert_count <= full_range) {
            return S3_H3_ERR_DECOMPRESSION_FAILED;
        }

        req_insert_count -= full_range;
    }

    if (req_insert_count == 0) {
        return S3_H3_ERR_DECOMPRESSION_FAILED;
    }

    s3_log_debug2(S3_LOG_DEBUG_EVENT, c->log, 0, "http3 decode insert_count %ui -> %ui",
                  *insert_count, req_insert_count);

    *insert_count = req_insert_count;

    return S3_OK;
}

s3_int_t
s3_h3_check_insert_count(s3_connection_t *c, s3_uint_t insert_count)
{
    size_t                 n;
    s3_pool_cleanup_t     *cln;
    s3_h3_block_t         *block;
    s3_h3_session_t       *h3c;
    s3_h3_dynamic_table_t *dt;

    h3c = s3_h3_get_session(c);
    dt = &h3c->table;

    n = dt->base + dt->nelts;

    s3_log_debug2(S3_LOG_DEBUG_EVENT, c->log, 0, "http3 check insert count req:%ui, have:%ui",
                  insert_count, n);

    if (n >= insert_count) {
        return S3_OK;
    }

    s3_log_debug0(S3_LOG_DEBUG_EVENT, c->log, 0, "http3 block stream");

    block = NULL;

    for (cln = c->pool->cleanup; cln; cln = cln->next) {
        if (cln->handler == s3_h3_unblock) {
            block = cln->data;
            break;
        }
    }

    if (block == NULL) {
        cln = s3_pool_cleanup_add(c->pool, sizeof(s3_h3_block_t));
        if (cln == NULL) {
            return S3_ERROR;
        }

        cln->handler = s3_h3_unblock;

        block = cln->data;
        block->queue.prev = NULL;
        block->connection = c;
        block->nblocked = &h3c->nblocked;
    }

    if (block->queue.prev == NULL) {
        if (h3c->nblocked == S3_H3_MAX_BLOCKED_STREAMS) {
            s3_log_error(S3_LOG_INFO, c->log, 0, "client exceeded max blocked streams limit");

            /*
             * ssh3-c: nginx finalizes the quic connection here; the h3
             * layer has no quic dependency, so the caller finalizes on
             * the returned error
             */
            return S3_H3_ERR_DECOMPRESSION_FAILED;
        }

        h3c->nblocked++;
        s3_queue_insert_tail(&h3c->blocked, &block->queue);
    }

    s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "http3 blocked:%ui", h3c->nblocked);

    return S3_BUSY;
}

void
s3_h3_ack_insert_count(s3_connection_t *c, uint64_t insert_count)
{
    s3_h3_session_t       *h3c;
    s3_h3_dynamic_table_t *dt;

    h3c = s3_h3_get_session(c);
    dt = &h3c->table;

    if (dt->ack_insert_count < insert_count) {
        dt->ack_insert_count = insert_count;
    }
}

static void
s3_h3_unblock(void *data)
{
    s3_h3_block_t *block = data;

    if (block->queue.prev) {
        s3_queue_remove(&block->queue);
        block->queue.prev = NULL;
        (*block->nblocked)--;
    }
}

static s3_int_t
s3_h3_new_entry(s3_connection_t *c)
{
    s3_queue_t      *q;
    s3_connection_t *bc;
    s3_h3_block_t   *block;
    s3_h3_session_t *h3c;

    h3c = s3_h3_get_session(c);

    s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "http3 new dynamic entry, blocked:%ui",
                  h3c->nblocked);

    while (!s3_queue_empty(&h3c->blocked)) {
        q = s3_queue_head(&h3c->blocked);
        block = (s3_h3_block_t *)q;
        bc = block->connection;

        s3_log_debug0(S3_LOG_DEBUG_EVENT, bc->log, 0, "http3 unblock stream");

        s3_h3_unblock(block);

        /* ssh3-c: per-context posted queue (nginx: ngx_posted_events) */
        if (h3c->ctx != NULL) {
            s3_post_event(bc->read, &h3c->ctx->posted_events);
        }
    }

    return S3_OK;
}

/*
 * ssh3-c: the reference sends the decoder instruction through the
 * uni-stream layer (ngx_http_v3_uni.c), which is wired by the P3
 * integration wave.  the instruction goes through the polymorphic
 * send_chain() of the known decoder stream; the stream send copies
 * the data into the quic output buffers, so the stack view is safe.
 * nginx is server-only and uses the SERVER decoder stream, the role
 * selection comes with the session layer; until a stream is wired the
 * delta stays pending (ack_insert_count is not advanced)
 */
static s3_int_t
s3_h3_send_inc_insert_count(s3_connection_t *c, s3_uint_t inc)
{
    u_char           buf[S3_H3_PREFIX_INT_LEN];
    size_t           n;
    s3_buf_t         b;
    s3_chain_t       cl;
    s3_connection_t *dc;
    s3_h3_session_t *h3c;

    h3c = s3_h3_get_session(c);

    dc = h3c->known_streams[S3_H3_STREAM_SERVER_DECODER];

    if (dc == NULL || dc->send_chain == NULL) {
        s3_log_debug0(S3_LOG_DEBUG_EVENT, c->log, 0,
                      "http3 no decoder stream, insert count is pending");
        return S3_ERROR;
    }

    s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "http3 send insert count increment %ui", inc);

    buf[0] = 0;
    n = (u_char *)s3_h3_encode_prefix_int(buf, inc, 6) - buf;

    h3c->total_bytes += n;

    s3_memzero(&b, sizeof(s3_buf_t));

    b.memory = 1;
    b.pos = buf;
    b.last = buf + n;

    cl.buf = &b;
    cl.next = NULL;

    if (dc->send_chain(dc, &cl, 0) == S3_CHAIN_ERROR || b.pos != b.last) {
        s3_log_error(S3_LOG_ERR, c->log, 0, "failed to send insert count increment");

        return S3_ERROR;
    }

    return S3_OK;
}

s3_int_t
s3_h3_set_param(s3_connection_t *c, uint64_t id, uint64_t value)
{
    switch (id) {

    case S3_H3_PARAM_MAX_TABLE_CAPACITY:
        s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "http3 param QPACK_MAX_TABLE_CAPACITY:%uL",
                      value);
        break;

    case S3_H3_PARAM_MAX_FIELD_SECTION_SIZE:
        s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0,
                      "http3 param SETTINGS_MAX_FIELD_SECTION_SIZE:%uL", value);
        break;

    case S3_H3_PARAM_BLOCKED_STREAMS:
        s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "http3 param QPACK_BLOCKED_STREAMS:%uL",
                      value);
        break;

    default:

        s3_log_debug2(S3_LOG_DEBUG_EVENT, c->log, 0, "http3 param #%uL:%uL", id, value);
    }

    return S3_OK;
}
