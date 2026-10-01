/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <s3_core.h>

s3_buf_t *
s3_create_temp_buf(s3_pool_t *pool, size_t size)
{
    s3_buf_t *b;

    b = s3_calloc_buf(pool);
    if (b == NULL) {
        return NULL;
    }

    b->start = s3_palloc(pool, size);
    if (b->start == NULL) {
        return NULL;
    }

    /*
     * set by s3_calloc_buf():
     *
     *     b->file_pos = 0;
     *     b->file_last = 0;
     *     b->shadow = NULL;
     *     b->tag = 0;
     *     and flags
     */

    b->pos = b->start;
    b->last = b->start;
    b->end = b->last + size;
    b->temporary = 1;

    return b;
}

s3_chain_t *
s3_alloc_chain_link(s3_pool_t *pool)
{
    s3_chain_t *cl;

    cl = pool->chain;

    if (cl) {
        pool->chain = cl->next;

        return cl;
    }

    cl = s3_palloc(pool, sizeof(s3_chain_t));
    if (cl == NULL) {
        return NULL;
    }

    return cl;
}

s3_int_t
s3_chain_link_copy(s3_pool_t *pool, s3_chain_t **chain, s3_chain_t *in)
{
    s3_chain_t *cl, **ll;

    ll = chain;

    for (cl = *chain; cl; cl = cl->next) {
        ll = &cl->next;
    }

    while (in) {
        cl = s3_alloc_chain_link(pool);
        if (cl == NULL) {
            *ll = NULL;

            return S3_ERROR;
        }

        cl->buf = in->buf;
        *ll = cl;
        ll = &cl->next;
        in = in->next;
    }

    *ll = NULL;

    return S3_OK;
}

s3_chain_t *
s3_chain_get_free_buf(s3_pool_t *p, s3_chain_t **free)
{
    s3_chain_t *cl;

    if (*free) {
        cl = *free;
        *free = cl->next;
        cl->next = NULL;

        return cl;
    }

    cl = s3_alloc_chain_link(p);
    if (cl == NULL) {
        return NULL;
    }

    cl->buf = s3_calloc_buf(p);
    if (cl->buf == NULL) {
        return NULL;
    }

    cl->next = NULL;

    return cl;
}

void
s3_chain_update_chains(s3_pool_t *p, s3_chain_t **free, s3_chain_t **busy, s3_chain_t **out,
                       s3_buf_tag_t tag)
{
    s3_chain_t *cl;

    if (*out) {
        if (*busy == NULL) {
            *busy = *out;

        } else {
            for (cl = *busy; cl->next; cl = cl->next) { /* void */
            }

            cl->next = *out;
        }

        *out = NULL;
    }

    while (*busy) {
        cl = *busy;

        if (cl->buf->tag != tag) {
            *busy = cl->next;
            s3_free_chain(p, cl);

            continue;
        }

        if (s3_buf_size(cl->buf) != 0) {
            break;
        }

        cl->buf->pos = cl->buf->start;
        cl->buf->last = cl->buf->start;

        *busy = cl->next;
        cl->next = *free;
        *free = cl;
    }
}
