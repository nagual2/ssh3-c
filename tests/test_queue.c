/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <s3_core.h>

#include "s3_test.h"

typedef struct {
    s3_queue_t queue;
    int        val;
} s3_test_queue_item_t;

static s3_int_t
s3_test_queue_cmp(const s3_queue_t *a, const s3_queue_t *b)
{
    return s3_queue_data(a, s3_test_queue_item_t, queue)->val -
           s3_queue_data(b, s3_test_queue_item_t, queue)->val;
}

static int
s3_test_queue(void)
{
    s3_queue_t           q, *node;
    s3_test_queue_item_t items[10], *item;
    int                  i, count, prev_val;

    /* intrusive list: no allocation at all */

    s3_queue_init(&q);
    S3_ASSERT(s3_queue_empty(&q));

    for (i = 0; i < 10; i++) {
        items[i].val = i;
        s3_queue_init(&items[i].queue);
    }

    /* insert_tail keeps order */

    {
        int order[10] = {5, 3, 9, 1, 7, 2, 8, 6, 4, 0};

        for (i = 0; i < 10; i++) {
            s3_queue_insert_tail(&q, &items[order[i]].queue);
        }

        S3_ASSERT(!s3_queue_empty(&q));
        S3_ASSERT(s3_queue_data(s3_queue_head(&q), s3_test_queue_item_t, queue)->val == 5);
        S3_ASSERT(s3_queue_data(s3_queue_last(&q), s3_test_queue_item_t, queue)->val == 0);

        /* middle: first element of the second part (10 elements) */

        node = s3_queue_middle(&q);
        S3_ASSERT(node == &items[2].queue);

        /* full forward walk */

        count = 0;
        for (node = s3_queue_head(&q); node != s3_queue_sentinel(&q); node = s3_queue_next(node)) {
            count++;
        }
        S3_ASSERT(count == 10);

        /* remove one element in the middle */

        s3_queue_remove(&items[9].queue); /* val 9 */

        count = 0;
        for (node = s3_queue_head(&q); node != s3_queue_sentinel(&q); node = s3_queue_next(node)) {
            S3_ASSERT(s3_queue_data(node, s3_test_queue_item_t, queue)->val != 9);
            count++;
        }
        S3_ASSERT(count == 9);

        /* stable merge sort */

        s3_queue_sort(&q, s3_test_queue_cmp);

        count = 0;
        prev_val = -1;
        for (node = s3_queue_head(&q); node != s3_queue_sentinel(&q); node = s3_queue_next(node)) {
            item = s3_queue_data(node, s3_test_queue_item_t, queue);

            S3_ASSERT(prev_val <= item->val);

            prev_val = item->val;
            count++;
        }
        S3_ASSERT(count == 9);
    }

    /* insert_head reverses, insert_before inserts at position */

    {
        s3_queue_t q2;

        s3_queue_init(&q2);

        s3_queue_insert_head(&q2, &items[0].queue);               /* 0 */
        s3_queue_insert_head(&q2, &items[1].queue);               /* 1, 0 */
        s3_queue_insert_before(&items[0].queue, &items[4].queue); /* 1, 4, 0 */

        S3_ASSERT(s3_queue_data(s3_queue_head(&q2), s3_test_queue_item_t, queue)->val == 1);
        S3_ASSERT(
            s3_queue_data(s3_queue_next(s3_queue_head(&q2)), s3_test_queue_item_t, queue)->val ==
            4);
        S3_ASSERT(s3_queue_data(s3_queue_last(&q2), s3_test_queue_item_t, queue)->val == 0);

        s3_queue_remove(&items[0].queue);
        s3_queue_remove(&items[1].queue);
        s3_queue_remove(&items[4].queue);
        S3_ASSERT(s3_queue_empty(&q2));
    }

    /* sort of a single-element queue is a no-op */

    {
        s3_queue_t q3;

        s3_queue_init(&q3);
        s3_queue_insert_head(&q3, &items[3].queue);

        s3_queue_sort(&q3, s3_test_queue_cmp);
        S3_ASSERT(s3_queue_head(&q3) == &items[3].queue);
        S3_ASSERT(s3_queue_last(&q3) == &items[3].queue);
    }

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_queue)
