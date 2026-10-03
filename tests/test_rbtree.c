/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <s3_core.h>
#include <stdlib.h>

#include "s3_test.h"

#define S3_TEST_RBTREE_NODES 10000

typedef struct {
    s3_rbtree_node_t node;
    int              val;
} s3_test_tree_item_t;

static int
s3_test_rbtree(void)
{
    s3_log_t             log;
    s3_pool_t           *pool;
    s3_rbtree_t          tree;
    s3_rbtree_node_t    *sentinel, *node, *prev;
    s3_test_tree_item_t *items;
    s3_rbtree_key_t      key, min_key, max_key;
    uint32_t             i, count;

    log.log_level = S3_LOG_ALERT;
    log.fd = S3_INVALID_FILE;

    pool = s3_create_pool(S3_DEFAULT_POOL_SIZE, &log);
    S3_ASSERT(pool != NULL);

    sentinel = s3_pcalloc(pool, sizeof(s3_rbtree_node_t));
    S3_ASSERT(sentinel != NULL);

    items = s3_pcalloc(pool, S3_TEST_RBTREE_NODES * sizeof(s3_test_tree_item_t));
    S3_ASSERT(items != NULL);

    s3_rbtree_init(&tree, sentinel, s3_rbtree_insert_value);

    /* 10000 random inserts, fixed seed */

    srand(42);

    for (i = 0; i < S3_TEST_RBTREE_NODES; i++) {
        items[i].node.key = (s3_rbtree_key_t)rand();
        items[i].val = (int)i;
        s3_rbtree_insert(&tree, &items[i].node);
    }

    S3_ASSERT(tree.root != sentinel);
    S3_ASSERT(tree.root->parent == NULL);
    S3_ASSERT(tree.root->color == 0);

    /* the in-order next() walk is sorted by key */

    count = 0;
    key = 0;

    for (node = s3_rbtree_min(tree.root, sentinel); node != NULL;
         node = s3_rbtree_next(&tree, node)) {
        if (count == 0) {
            min_key = node->key;
        }

        if (count > 0) {
            S3_ASSERT(node->key >= key);
        }

        key = node->key;
        count++;
    }

    S3_ASSERT(count == S3_TEST_RBTREE_NODES);

    /* the prev() walk from the maximum mirrors the next() walk */

    count = 0;
    max_key = 0;

    for (node = s3_rbtree_max(tree.root, sentinel); node != NULL;
         node = s3_rbtree_prev(&tree, node)) {
        if (count > 0) {
            S3_ASSERT(node->key <= max_key);
        }

        max_key = node->key;
        count++;
    }

    S3_ASSERT(count == S3_TEST_RBTREE_NODES);
    S3_ASSERT(max_key == min_key);

    /* container_of helper */

    node = s3_rbtree_min(tree.root, sentinel);
    S3_ASSERT(s3_rbtree_data(node, s3_test_tree_item_t, node)->val >= 0);

    /* delete all nodes in insertion order, the tree becomes empty */

    for (i = 0; i < S3_TEST_RBTREE_NODES; i++) {
        s3_rbtree_delete(&tree, &items[i].node);
    }

    S3_ASSERT(tree.root == sentinel);

    /* duplicate keys are allowed and kept */

    s3_rbtree_init(&tree, sentinel, s3_rbtree_insert_value);

    {
        s3_test_tree_item_t dups[5];

        for (i = 0; i < 5; i++) {
            dups[i].node.key = 777;
            s3_rbtree_insert(&tree, &dups[i].node);
        }

        count = 0;
        prev = NULL;

        for (node = s3_rbtree_min(tree.root, sentinel); node != NULL;
             node = s3_rbtree_next(&tree, node)) {
            S3_ASSERT(node->key == 777);
            S3_ASSERT(prev == NULL || s3_rbtree_next(&tree, prev) == node);
            prev = node;
            count++;
        }

        S3_ASSERT(count == 5);

        for (i = 0; i < 5; i++) {
            s3_rbtree_delete(&tree, &dups[i].node);
        }

        S3_ASSERT(tree.root == sentinel);
    }

    /* timer insert: wrap-around keys compare with overflow tolerance */

    s3_rbtree_init(&tree, sentinel, s3_rbtree_insert_timer_value);

    {
        s3_test_tree_item_t t1, t2;

        t1.node.key = (s3_rbtree_key_t)-16; /* 0xfffffff0, far future */
        t2.node.key = 10;                   /* wrapped past t1 */

        s3_rbtree_insert(&tree, &t1.node);
        s3_rbtree_insert(&tree, &t2.node);

        S3_ASSERT(s3_rbtree_min(tree.root, sentinel) == &t1.node);

        s3_rbtree_delete(&tree, &t1.node);
        s3_rbtree_delete(&tree, &t2.node);
        S3_ASSERT(tree.root == sentinel);
    }

    /* timer insert: keys more than 2^31 ms apart (24.8 days of uptime)
     * must keep their order; a signed-32 delta comparison misplaces the
     * far node as the tree minimum */

    s3_rbtree_init(&tree, sentinel, s3_rbtree_insert_timer_value);

    {
        s3_test_tree_item_t t1, t2;

        t1.node.key = 1000;
        t2.node.key = 1000 + 0x80001000ULL; /* over 2^31 ms later */

        s3_rbtree_insert(&tree, &t1.node);
        s3_rbtree_insert(&tree, &t2.node);

        S3_ASSERT(s3_rbtree_min(tree.root, sentinel) == &t1.node);

        s3_rbtree_delete(&tree, &t2.node);
        s3_rbtree_delete(&tree, &t1.node);
        S3_ASSERT(tree.root == sentinel);
    }

    s3_destroy_pool(pool);

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_rbtree)
