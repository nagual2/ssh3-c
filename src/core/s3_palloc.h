/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_PALLOC_H_INCLUDED_
#define _S3_PALLOC_H_INCLUDED_

#include <s3_base.h>
#include <s3_log.h>

typedef struct s3_chain_s s3_chain_t;

/*
 * page size, calibrated once on the first s3_create_pool() call;
 * S3_MAX_ALLOC_FROM_POOL should be (s3_pagesize - 1), i.e. 4095 on x86
 */
extern size_t s3_pagesize;

#define S3_MAX_ALLOC_FROM_POOL (s3_pagesize - 1)

#define S3_DEFAULT_POOL_SIZE (16 * 1024)

#define S3_POOL_ALIGNMENT 16

#define S3_MIN_POOL_SIZE                                                                           \
    s3_align((sizeof(s3_pool_t) + 2 * sizeof(s3_pool_large_t)), S3_POOL_ALIGNMENT)

typedef void (*s3_pool_cleanup_pt)(void *data);

typedef struct s3_pool_s s3_pool_t;

typedef struct s3_pool_cleanup_s s3_pool_cleanup_t;

struct s3_pool_cleanup_s {
    s3_pool_cleanup_pt handler;
    void              *data;
    s3_pool_cleanup_t *next;
};

typedef struct s3_pool_large_s s3_pool_large_t;

struct s3_pool_large_s {
    s3_pool_large_t *next;
    void            *alloc;
};

typedef struct {
    u_char    *last;
    u_char    *end;
    s3_pool_t *next;
    s3_uint_t  failed;
} s3_pool_data_t;

struct s3_pool_s {
    s3_pool_data_t     d;
    size_t             max;
    s3_pool_t         *current;
    s3_chain_t        *chain;
    s3_pool_large_t   *large;
    s3_pool_cleanup_t *cleanup;
    s3_log_t          *log;
};

typedef struct {
    s3_fd_t   fd;
    u_char   *name;
    s3_log_t *log;
} s3_pool_cleanup_file_t;

s3_pool_t *s3_create_pool(size_t size, s3_log_t *log);
void       s3_destroy_pool(s3_pool_t *pool);
void       s3_reset_pool(s3_pool_t *pool);

void    *s3_palloc(s3_pool_t *pool, size_t size);
void    *s3_pnalloc(s3_pool_t *pool, size_t size);
void    *s3_pcalloc(s3_pool_t *pool, size_t size);
void    *s3_pmemalign(s3_pool_t *pool, size_t size, size_t alignment);
s3_int_t s3_pfree(s3_pool_t *pool, void *p);

s3_pool_cleanup_t *s3_pool_cleanup_add(s3_pool_t *p, size_t size);
void               s3_pool_run_cleanup_file(s3_pool_t *p, s3_fd_t fd);
void               s3_pool_cleanup_file(void *data);
void               s3_pool_delete_file(void *data);

void *s3_memalign(size_t alignment, size_t size, s3_log_t *log);

#endif /* _S3_PALLOC_H_INCLUDED_ */
