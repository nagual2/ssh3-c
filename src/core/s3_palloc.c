/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <s3_core.h>

#include <stdlib.h>
#include <unistd.h>

static s3_inline void *s3_palloc_small(s3_pool_t *pool, size_t size, s3_uint_t align);
static void           *s3_palloc_block(s3_pool_t *pool, size_t size);
static void           *s3_palloc_large(s3_pool_t *pool, size_t size);

size_t s3_pagesize = 4096;

s3_pool_t *
s3_create_pool(size_t size, s3_log_t *log)
{
    s3_pool_t *p;
    static int pagesize_done = 0;
    long       n;

    if (!pagesize_done) {
        pagesize_done = 1;

        n = sysconf(_SC_PAGESIZE);
        if (n > 0) {
            s3_pagesize = (size_t)n;
        }
    }

    p = s3_memalign(S3_POOL_ALIGNMENT, size, log);
    if (p == NULL) {
        return NULL;
    }

    p->d.last = (u_char *)p + sizeof(s3_pool_t);
    p->d.end = (u_char *)p + size;
    p->d.next = NULL;
    p->d.failed = 0;

    size = size - sizeof(s3_pool_t);
    p->max = (size < S3_MAX_ALLOC_FROM_POOL) ? size : S3_MAX_ALLOC_FROM_POOL;

    p->current = p;
    p->chain = NULL;
    p->large = NULL;
    p->cleanup = NULL;
    p->log = log;

    return p;
}

void
s3_destroy_pool(s3_pool_t *pool)
{
    s3_pool_t         *p, *n;
    s3_pool_large_t   *l;
    s3_pool_cleanup_t *c;

    for (c = pool->cleanup; c; c = c->next) {
        if (c->handler) {
            s3_log_debug1(S3_LOG_DEBUG_ALLOC, pool->log, 0, "run cleanup: %p", c);
            c->handler(c->data);
        }
    }

    for (l = pool->large; l; l = l->next) {
        s3_log_debug1(S3_LOG_DEBUG_ALLOC, pool->log, 0, "free: %p", l->alloc);

        if (l->alloc) {
            s3_free(l->alloc);
        }
    }

    for (p = pool, n = pool->d.next; /* void */; p = n, n = n->d.next) {
        s3_free(p);

        if (n == NULL) {
            break;
        }
    }
}

void
s3_reset_pool(s3_pool_t *pool)
{
    s3_pool_t       *p;
    s3_pool_large_t *l;

    for (l = pool->large; l; l = l->next) {
        if (l->alloc) {
            s3_free(l->alloc);
        }
    }

    for (p = pool; p; p = p->d.next) {
        p->d.last = (u_char *)p + sizeof(s3_pool_t);
        p->d.failed = 0;
    }

    pool->current = pool;
    pool->chain = NULL;
    pool->large = NULL;
}

void *
s3_palloc(s3_pool_t *pool, size_t size)
{
    if (size <= pool->max) {
        return s3_palloc_small(pool, size, 1);
    }

    return s3_palloc_large(pool, size);
}

void *
s3_pnalloc(s3_pool_t *pool, size_t size)
{
    if (size <= pool->max) {
        return s3_palloc_small(pool, size, 0);
    }

    return s3_palloc_large(pool, size);
}

static s3_inline void *
s3_palloc_small(s3_pool_t *pool, size_t size, s3_uint_t align)
{
    u_char    *m;
    s3_pool_t *p;

    p = pool->current;

    do {
        m = p->d.last;

        if (align) {
            m = s3_align_ptr(m, S3_POOL_ALIGNMENT);
        }

        if ((size_t)(p->d.end - m) >= size) {
            p->d.last = m + size;

            return m;
        }

        p = p->d.next;

    } while (p);

    return s3_palloc_block(pool, size);
}

static void *
s3_palloc_block(s3_pool_t *pool, size_t size)
{
    u_char    *m;
    size_t     psize;
    s3_pool_t *p, *new_pool;

    psize = (size_t)(pool->d.end - (u_char *)pool);

    m = s3_memalign(S3_POOL_ALIGNMENT, psize, pool->log);
    if (m == NULL) {
        return NULL;
    }

    new_pool = (s3_pool_t *)m;

    new_pool->d.end = m + psize;
    new_pool->d.next = NULL;
    new_pool->d.failed = 0;

    m += sizeof(s3_pool_data_t);
    m = s3_align_ptr(m, S3_POOL_ALIGNMENT);
    new_pool->d.last = m + size;

    for (p = pool->current; p->d.next; p = p->d.next) {
        if (p->d.failed++ > 4) {
            pool->current = p->d.next;
        }
    }

    p->d.next = new_pool;

    return m;
}

static void *
s3_palloc_large(s3_pool_t *pool, size_t size)
{
    void            *p;
    s3_uint_t        n;
    s3_pool_large_t *large;

    p = s3_alloc(size, pool->log);
    if (p == NULL) {
        s3_log_error(S3_LOG_EMERG, pool->log, s3_errno, "malloc(%uz) failed", size);
        return NULL;
    }

    n = 0;

    for (large = pool->large; large; large = large->next) {
        if (large->alloc == NULL) {
            large->alloc = p;

            return p;
        }

        if (n++ > 3) {
            break;
        }
    }

    large = s3_palloc_small(pool, sizeof(s3_pool_large_t), 1);
    if (large == NULL) {
        s3_free(p);

        return NULL;
    }

    large->alloc = p;
    large->next = pool->large;
    pool->large = large;

    return p;
}

void *
s3_pmemalign(s3_pool_t *pool, size_t size, size_t alignment)
{
    void            *p;
    s3_pool_large_t *large;

    p = s3_memalign(alignment, size, pool->log);
    if (p == NULL) {
        return NULL;
    }

    large = s3_palloc_small(pool, sizeof(s3_pool_large_t), 1);
    if (large == NULL) {
        s3_free(p);

        return NULL;
    }

    large->alloc = p;
    large->next = pool->large;
    pool->large = large;

    return p;
}

s3_int_t
s3_pfree(s3_pool_t *pool, void *p)
{
    s3_pool_large_t *l;

    for (l = pool->large; l; l = l->next) {
        if (p == l->alloc) {
            s3_log_debug1(S3_LOG_DEBUG_ALLOC, pool->log, 0, "free: %p", l->alloc);
            s3_free(l->alloc);
            l->alloc = NULL;

            return S3_OK;
        }
    }

    return S3_DECLINED;
}

void *
s3_pcalloc(s3_pool_t *pool, size_t size)
{
    void *p;

    p = s3_palloc(pool, size);
    if (p) {
        s3_memzero(p, size);
    }

    return p;
}

s3_pool_cleanup_t *
s3_pool_cleanup_add(s3_pool_t *p, size_t size)
{
    s3_pool_cleanup_t *c;

    c = s3_palloc(p, sizeof(s3_pool_cleanup_t));
    if (c == NULL) {
        return NULL;
    }

    if (size) {
        c->data = s3_palloc(p, size);
        if (c->data == NULL) {
            return NULL;
        }

    } else {
        c->data = NULL;
    }

    c->handler = NULL;
    c->next = p->cleanup;

    p->cleanup = c;

    s3_log_debug1(S3_LOG_DEBUG_ALLOC, p->log, 0, "add cleanup: %p", c);

    return c;
}

void
s3_pool_run_cleanup_file(s3_pool_t *p, s3_fd_t fd)
{
    s3_pool_cleanup_t      *c;
    s3_pool_cleanup_file_t *cf;

    for (c = p->cleanup; c; c = c->next) {
        if (c->handler == s3_pool_cleanup_file) {

            cf = c->data;

            if (cf->fd == fd) {
                c->handler(cf);
                c->handler = NULL;

                return;
            }
        }
    }
}

void
s3_pool_cleanup_file(void *data)
{
    s3_pool_cleanup_file_t *c = data;

    s3_log_debug1(S3_LOG_DEBUG_ALLOC, c->log, 0, "file cleanup: fd:%d", c->fd);

    if (close(c->fd) == -1) {
        s3_log_error(S3_LOG_ALERT, c->log, s3_errno, "close() failed");
    }
}

void
s3_pool_delete_file(void *data)
{
    s3_err_t                err;
    s3_pool_cleanup_file_t *c = data;

    s3_log_debug2(S3_LOG_DEBUG_ALLOC, c->log, 0, "file cleanup: fd:%d %s", c->fd, c->name);

    if (unlink((char *)c->name) == -1) {
        err = s3_errno;

        if (err != S3_ENOENT) {
            s3_log_error(S3_LOG_CRIT, c->log, err, "unlink() \"%s\" failed", c->name);
        }
    }

    if (close(c->fd) == -1) {
        s3_log_error(S3_LOG_ALERT, c->log, s3_errno, "close() failed");
    }
}

void *
s3_memalign(size_t alignment, size_t size, s3_log_t *log)
{
    void *p;

    if (posix_memalign(&p, alignment, size) != 0) {
        s3_log_error(S3_LOG_EMERG, log, s3_errno, "posix_memalign(%uz, %uz) failed", alignment,
                     size);

        return NULL;
    }

    s3_log_debug3(S3_LOG_DEBUG_ALLOC, log, 0, "posix_memalign: %p:%uz aligned to %uz", p, size,
                  alignment);

    return p;
}
