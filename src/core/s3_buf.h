/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_BUF_H_INCLUDED_
#define _S3_BUF_H_INCLUDED_

#include <s3_base.h>
#include <s3_palloc.h>

typedef void *s3_buf_tag_t;

typedef struct s3_buf_s s3_buf_t;

struct s3_buf_s {
    u_char *pos;
    u_char *last;
    off_t   file_pos;
    off_t   file_last;

    u_char      *start; /* start of buffer */
    u_char      *end;   /* end of buffer */
    s3_buf_tag_t tag;
    s3_buf_t    *shadow;

    /* the buf's content could be changed */
    unsigned temporary : 1;

    /*
     * the buf's content is in a memory cache or in a read only memory
     * and must not be changed
     */
    unsigned memory : 1;

    /* the buf's content is mmap()ed and must not be changed */
    unsigned mmap : 1;

    unsigned recycled : 1;
    unsigned in_file : 1;
    unsigned flush : 1;
    unsigned sync : 1;
    unsigned last_buf : 1;
    unsigned last_in_chain : 1;

    unsigned last_shadow : 1;
    unsigned temp_file : 1;

    unsigned eof : 1;
    unsigned error : 1;
};

struct s3_chain_s {
    s3_buf_t   *buf;
    s3_chain_t *next;
};

#define S3_CHAIN_ERROR (s3_chain_t *)S3_ERROR

#define s3_buf_in_memory(b)      ((b)->temporary || (b)->memory || (b)->mmap)
#define s3_buf_in_memory_only(b) (s3_buf_in_memory(b) && !(b)->in_file)

#define s3_buf_special(b)                                                                          \
    (((b)->flush || (b)->last_buf || (b)->sync) && !s3_buf_in_memory(b) && !(b)->in_file)

#define s3_buf_sync_only(b)                                                                        \
    ((b)->sync && !s3_buf_in_memory(b) && !(b)->in_file && !(b)->flush && !(b)->last_buf)

#define s3_buf_size(b)                                                                             \
    (s3_buf_in_memory(b) ? (off_t)((b)->last - (b)->pos) : ((b)->file_last - (b)->file_pos))

s3_buf_t *s3_create_temp_buf(s3_pool_t *pool, size_t size);

#define s3_alloc_buf(pool)  s3_palloc(pool, sizeof(s3_buf_t))
#define s3_calloc_buf(pool) s3_pcalloc(pool, sizeof(s3_buf_t))

s3_chain_t *s3_alloc_chain_link(s3_pool_t *pool);

#define s3_free_chain(pool, cl)                                                                    \
    (cl)->next = (pool)->chain;                                                                    \
    (pool)->chain = (cl)

s3_int_t s3_chain_link_copy(s3_pool_t *pool, s3_chain_t **chain, s3_chain_t *in);

s3_chain_t *s3_chain_get_free_buf(s3_pool_t *p, s3_chain_t **free);

void s3_chain_update_chains(s3_pool_t *p, s3_chain_t **free, s3_chain_t **busy, s3_chain_t **out,
                            s3_buf_tag_t tag);

#endif /* _S3_BUF_H_INCLUDED_ */
