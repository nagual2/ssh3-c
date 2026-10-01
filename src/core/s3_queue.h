/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_QUEUE_H_INCLUDED_
#define _S3_QUEUE_H_INCLUDED_

#include <s3_base.h>

typedef struct s3_queue_s s3_queue_t;

struct s3_queue_s {
    s3_queue_t *prev;
    s3_queue_t *next;
};

#define s3_queue_init(q)                                                                           \
    (q)->prev = q;                                                                                 \
    (q)->next = q

#define s3_queue_empty(h) (h == (h)->prev)

#define s3_queue_insert_head(h, x)                                                                 \
    (x)->next = (h)->next;                                                                         \
    (x)->next->prev = x;                                                                           \
    (x)->prev = h;                                                                                 \
    (h)->next = x

#define s3_queue_insert_after s3_queue_insert_head

#define s3_queue_insert_tail(h, x)                                                                 \
    (x)->prev = (h)->prev;                                                                         \
    (x)->prev->next = x;                                                                           \
    (x)->next = h;                                                                                 \
    (h)->prev = x

#define s3_queue_insert_before s3_queue_insert_tail

#define s3_queue_head(h) (h)->next

#define s3_queue_last(h) (h)->prev

#define s3_queue_sentinel(h) (h)

#define s3_queue_next(q) (q)->next

#define s3_queue_prev(q) (q)->prev

#define s3_queue_remove(x)                                                                         \
    (x)->next->prev = (x)->prev;                                                                   \
    (x)->prev->next = (x)->next

#define s3_queue_split(h, q, n)                                                                    \
    (n)->prev = (h)->prev;                                                                         \
    (n)->prev->next = n;                                                                           \
    (n)->next = q;                                                                                 \
    (h)->prev = (q)->prev;                                                                         \
    (h)->prev->next = h;                                                                           \
    (q)->prev = n;

#define s3_queue_add(h, n)                                                                         \
    (h)->prev->next = (n)->next;                                                                   \
    (n)->next->prev = (h)->prev;                                                                   \
    (h)->prev = (n)->prev;                                                                         \
    (h)->prev->next = h;

#define s3_queue_data(q, type, link) ((type *)((u_char *)q - offsetof(type, link)))

/*
 * find the middle queue element if the queue has odd number of elements
 * or the first element of the queue's second part otherwise
 */
static s3_inline s3_queue_t *
s3_queue_middle(s3_queue_t *queue)
{
    s3_queue_t *middle, *next;

    middle = s3_queue_head(queue);

    if (middle == s3_queue_last(queue)) {
        return middle;
    }

    next = s3_queue_head(queue);

    for (;;) {
        middle = s3_queue_next(middle);

        next = s3_queue_next(next);

        if (next == s3_queue_last(queue)) {
            return middle;
        }

        next = s3_queue_next(next);

        if (next == s3_queue_last(queue)) {
            return middle;
        }
    }
}

static s3_inline void
s3_queue_merge(s3_queue_t *queue, s3_queue_t *tail,
               s3_int_t (*cmp)(const s3_queue_t *, const s3_queue_t *))
{
    s3_queue_t *q1, *q2;

    q1 = s3_queue_head(queue);
    q2 = s3_queue_head(tail);

    for (;;) {
        if (q1 == s3_queue_sentinel(queue)) {
            s3_queue_add(queue, tail);
            break;
        }

        if (q2 == s3_queue_sentinel(tail)) {
            break;
        }

        if (cmp(q1, q2) <= 0) {
            q1 = s3_queue_next(q1);
            continue;
        }

        s3_queue_remove(q2);
        s3_queue_insert_before(q1, q2);

        q2 = s3_queue_head(tail);
    }
}

/* the stable merge sort */
static s3_inline void
s3_queue_sort(s3_queue_t *queue, s3_int_t (*cmp)(const s3_queue_t *, const s3_queue_t *))
{
    s3_queue_t *q, tail;

    q = s3_queue_head(queue);

    if (q == s3_queue_last(queue)) {
        return;
    }

    q = s3_queue_middle(queue);

    s3_queue_split(queue, q, &tail);

    s3_queue_sort(queue, cmp);
    s3_queue_sort(&tail, cmp);

    s3_queue_merge(queue, &tail, cmp);
}

#endif /* _S3_QUEUE_H_INCLUDED_ */
