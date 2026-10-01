/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_RBTREE_H_INCLUDED_
#define _S3_RBTREE_H_INCLUDED_

#include <s3_base.h>

typedef uint32_t s3_rbtree_key_t;
typedef int64_t  s3_rbtree_key_int_t;

typedef struct s3_rbtree_node_s s3_rbtree_node_t;

struct s3_rbtree_node_s {
    s3_rbtree_key_t   key;
    s3_rbtree_node_t *left;
    s3_rbtree_node_t *right;
    s3_rbtree_node_t *parent;
    u_char            color;
    void             *data;
};

typedef struct s3_rbtree_s s3_rbtree_t;

typedef void (*s3_rbtree_insert_pt)(s3_rbtree_node_t *root, s3_rbtree_node_t *node,
                                    s3_rbtree_node_t *sentinel);

struct s3_rbtree_s {
    s3_rbtree_node_t   *root;
    s3_rbtree_node_t   *sentinel;
    s3_rbtree_insert_pt insert;
};

#define s3_rbtree_init(tree, s, i)                                                                 \
    s3_rbtree_sentinel_init(s);                                                                    \
    (tree)->root = s;                                                                              \
    (tree)->sentinel = s;                                                                          \
    (tree)->insert = i

#define s3_rbtree_data(node, type, link) ((type *)((u_char *)(node) - offsetof(type, link)))

void              s3_rbtree_insert(s3_rbtree_t *tree, s3_rbtree_node_t *node);
void              s3_rbtree_delete(s3_rbtree_t *tree, s3_rbtree_node_t *node);
void              s3_rbtree_insert_value(s3_rbtree_node_t *root, s3_rbtree_node_t *node,
                                         s3_rbtree_node_t *sentinel);
void              s3_rbtree_insert_timer_value(s3_rbtree_node_t *root, s3_rbtree_node_t *node,
                                               s3_rbtree_node_t *sentinel);
s3_rbtree_node_t *s3_rbtree_next(s3_rbtree_t *tree, s3_rbtree_node_t *node);
s3_rbtree_node_t *s3_rbtree_prev(s3_rbtree_t *tree, s3_rbtree_node_t *node);

#define s3_rbt_red(node)          ((node)->color = 1)
#define s3_rbt_black(node)        ((node)->color = 0)
#define s3_rbt_is_red(node)       ((node)->color)
#define s3_rbt_is_black(node)     (!s3_rbt_is_red(node))
#define s3_rbt_copy_color(n1, n2) (n1->color = n2->color)

/* a sentinel must be black */

#define s3_rbtree_sentinel_init(node) s3_rbt_black(node)

static s3_inline s3_rbtree_node_t *
s3_rbtree_min(s3_rbtree_node_t *node, s3_rbtree_node_t *sentinel)
{
    while (node->left != sentinel) {
        node = node->left;
    }

    return node;
}

static s3_inline s3_rbtree_node_t *
s3_rbtree_max(s3_rbtree_node_t *node, s3_rbtree_node_t *sentinel)
{
    while (node->right != sentinel) {
        node = node->right;
    }

    return node;
}

#endif /* _S3_RBTREE_H_INCLUDED_ */
