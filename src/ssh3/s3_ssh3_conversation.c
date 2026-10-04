/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the ssh3 conversation registry and the datagram store, the port of
 * the reference conversation.go and resources_manager.go
 */

#include <s3_core.h>

#include <s3_ssh3_conversation.h>

/*
 * one queued payload of a dangling queue; both the node and the copy
 * are carved from the conversation pool and die with it: nginx does
 * not free small blocks (s3_pfree() only returns large allocations),
 * a popped node is just unlinked and left to the pool
 */
typedef struct {
    s3_queue_t queue;   /* the payloads queue linkage */
    s3_str_t   payload; /* the payload copy in the conversation pool */
} s3_dgram_payload_t;

/*
 * the rbtree key is s3_rbtree_key_t (uintptr_t) and carries the full
 * 64-bit channel id on the supported 64-bit builds, the same choice
 * as the QUIC stream tree (qs->node.key = id, s3_quic_streams.c); a
 * 32-bit build would truncate the key exactly like the QUIC layer
 * already does, no high/low split is needed
 */
static s3_ssh3_dgram_queue_t *
s3_ssh3_find_dgram_queue(s3_ssh3_conversation_t *conv, uint64_t channel_id)
{
    s3_rbtree_node_t *node, *sentinel;

    node = conv->dangling.root;
    sentinel = conv->dangling.sentinel;

    while (node != sentinel) {

        if (channel_id == (uint64_t)node->key) {
            return s3_rbtree_data(node, s3_ssh3_dgram_queue_t, node);
        }

        node = (channel_id < (uint64_t)node->key) ? node->left : node->right;
    }

    return NULL;
}

s3_int_t
s3_ssh3_conversation_init(s3_ssh3_conversation_t *conv, s3_pool_t *pool, uint64_t control_stream_id)
{
    s3_rbtree_node_t *channels_sentinel, *dangling_sentinel;

    /* the trees own no sentinel field in the conversation struct, the
     * nodes come from the pool and die with it */

    channels_sentinel = s3_pcalloc(pool, sizeof(s3_rbtree_node_t));
    dangling_sentinel = s3_pcalloc(pool, sizeof(s3_rbtree_node_t));

    if (channels_sentinel == NULL || dangling_sentinel == NULL) {
        return S3_ERROR;
    }

    s3_rbtree_init(&conv->channels, channels_sentinel, s3_rbtree_insert_value);
    s3_rbtree_init(&conv->dangling, dangling_sentinel, s3_rbtree_insert_value);

    s3_queue_init(&conv->accept);

    conv->control_stream_id = control_stream_id;
    conv->pool = pool;

    return S3_OK;
}

void
s3_ssh3_conversation_link_channel(s3_ssh3_conversation_t *conv, s3_ssh3_channel_t *ch)
{
    ch->node.key = (s3_rbtree_key_t)ch->channel_id;

    s3_rbtree_insert(&conv->channels, &ch->node);
}

void
s3_ssh3_conversation_unlink_channel(s3_ssh3_conversation_t *conv, s3_ssh3_channel_t *ch)
{
    s3_rbtree_delete(&conv->channels, &ch->node);
}

s3_ssh3_channel_t *
s3_ssh3_conversation_find_channel(s3_ssh3_conversation_t *conv, uint64_t channel_id)
{
    s3_rbtree_node_t *node, *sentinel;

    node = conv->channels.root;
    sentinel = conv->channels.sentinel;

    while (node != sentinel) {

        if (channel_id == (uint64_t)node->key) {
            return s3_rbtree_data(node, s3_ssh3_channel_t, node);
        }

        node = (channel_id < (uint64_t)node->key) ? node->left : node->right;
    }

    return NULL;
}

void
s3_ssh3_conversation_enqueue_accept(s3_ssh3_conversation_t *conv, s3_ssh3_channel_t *ch)
{
    s3_queue_insert_tail(&conv->accept, &ch->queue);
}

s3_ssh3_channel_t *
s3_ssh3_conversation_dequeue_accept(s3_ssh3_conversation_t *conv)
{
    s3_queue_t *q;

    if (s3_queue_empty(&conv->accept)) {
        return NULL;
    }

    q = s3_queue_head(&conv->accept);

    s3_queue_remove(q);

    return s3_queue_data(q, s3_ssh3_channel_t, queue);
}

s3_int_t
s3_ssh3_conversation_push_datagram(s3_ssh3_conversation_t *conv, uint64_t channel_id,
                                   const u_char *data, size_t len)
{
    s3_ssh3_dgram_queue_t *dq;
    s3_dgram_payload_t    *item;
    u_char                *copy;

    dq = s3_ssh3_find_dgram_queue(conv, channel_id);

    if (dq == NULL) {
        dq = s3_pcalloc(conv->pool, sizeof(s3_ssh3_dgram_queue_t));
        if (dq == NULL) {
            return S3_ERROR;
        }

        dq->channel_id = channel_id;
        dq->node.key = (s3_rbtree_key_t)channel_id;

        s3_queue_init(&dq->payloads);

        s3_rbtree_insert(&conv->dangling, &dq->node);
    }

    /* the queue is full: the payload is dropped before anything is
     * allocated for it */

    if (dq->count >= S3_SSH3_DGRAM_QUEUE_MAX) {
        return S3_BUSY;
    }

    /* the node carries pointers and sizes: the aligned allocator,
     * unlike pnalloc, is mandatory for it (UBSan: misaligned member) */

    item = s3_palloc(conv->pool, sizeof(s3_dgram_payload_t));
    if (item == NULL) {
        return S3_ERROR;
    }

    copy = NULL;

    if (len > 0) {
        copy = s3_pnalloc(conv->pool, len);
        if (copy == NULL) {
            return S3_ERROR;
        }

        s3_memcpy(copy, data, len);
    }

    item->payload.data = copy;
    item->payload.len = len;

    s3_queue_insert_tail(&dq->payloads, &item->queue);
    dq->count++;

    return S3_OK;
}

s3_int_t
s3_ssh3_conversation_pop_datagram(s3_ssh3_conversation_t *conv, uint64_t channel_id, s3_str_t *out)
{
    s3_ssh3_dgram_queue_t *dq;
    s3_queue_t            *q;
    s3_dgram_payload_t    *item;

    dq = s3_ssh3_find_dgram_queue(conv, channel_id);

    if (dq == NULL || s3_queue_empty(&dq->payloads)) {
        return S3_AGAIN;
    }

    q = s3_queue_head(&dq->payloads);
    item = s3_queue_data(q, s3_dgram_payload_t, queue);

    s3_queue_remove(q);
    dq->count--;

    /* the view points into the conversation pool, the node itself is
     * left to the pool (see s3_dgram_payload_t) */

    *out = item->payload;

    return S3_OK;
}
