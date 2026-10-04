/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_SSH3_CONVERSATION_H_INCLUDED_
#define _S3_SSH3_CONVERSATION_H_INCLUDED_

#include <s3_core.h>

#include <s3_ssh3_channel.h>

/*
 * the ssh3 conversation, the port of the reference conversation.go
 * and resources_manager.go: one per QUIC connection, the control
 * stream id identifies it on the wire (the channel headers and the
 * datagram prefixes carry it), the channel map is keyed by ChannelID
 * (== StreamID); the reference leaks closed channels from its map —
 * the ssh3-c port unlinks them (docs/P4-WIRE.md 9.2)
 *
 * the datagram store keeps per-channelID queues for the payloads that
 * arrived before the channel was registered (the dangling queue of
 * the reference, 64 entries) and serves them FIFO after the channel
 * shows up; a full queue drops the payload (S3_BUSY)
 */

#define S3_SSH3_DGRAM_QUEUE_MAX 64

typedef struct {
    uint64_t         channel_id;
    s3_rbtree_node_t node;     /* the dangling rbtree, key = channel_id */
    s3_queue_t       payloads; /* the arrived payloads, FIFO */
    unsigned         count;
} s3_ssh3_dgram_queue_t;

typedef struct {
    uint64_t    control_stream_id;
    s3_pool_t  *pool;     /* the dangling payloads live here */
    s3_rbtree_t channels; /* s3_ssh3_channel_t.node */
    s3_queue_t  accept;   /* the incoming channels pending accept */
    s3_rbtree_t dangling; /* s3_ssh3_dgram_queue_t.node */
} s3_ssh3_conversation_t;

/*
 * binds the conversation to its control stream id; the pool owns the
 * datagram payloads, the channels belong to the caller
 */

s3_int_t s3_ssh3_conversation_init(s3_ssh3_conversation_t *conv, s3_pool_t *pool,
                                   uint64_t control_stream_id);

/* the registry: link on open/accept, unlink on close (never leaks) */

void s3_ssh3_conversation_link_channel(s3_ssh3_conversation_t *conv, s3_ssh3_channel_t *ch);

void s3_ssh3_conversation_unlink_channel(s3_ssh3_conversation_t *conv, s3_ssh3_channel_t *ch);

s3_ssh3_channel_t *s3_ssh3_conversation_find_channel(s3_ssh3_conversation_t *conv,
                                                     uint64_t                channel_id);

/* the accept queue of the incoming channels (docs/P4-WIRE.md 2.2) */

void s3_ssh3_conversation_enqueue_accept(s3_ssh3_conversation_t *conv, s3_ssh3_channel_t *ch);

s3_ssh3_channel_t *s3_ssh3_conversation_dequeue_accept(s3_ssh3_conversation_t *conv);

/*
 * stores one datagram payload for the channel: S3_OK, S3_BUSY when
 * the channel queue is already at S3_SSH3_DGRAM_QUEUE_MAX (the
 * payload is dropped, the reference drops the same way)
 */

s3_int_t s3_ssh3_conversation_push_datagram(s3_ssh3_conversation_t *conv, uint64_t channel_id,
                                            const u_char *data, size_t len);

/*
 * pops the oldest payload of the channel: S3_OK with the view into
 * the conversation pool, S3_AGAIN when nothing is queued
 */

s3_int_t s3_ssh3_conversation_pop_datagram(s3_ssh3_conversation_t *conv, uint64_t channel_id,
                                           s3_str_t *out);

#endif /* _S3_SSH3_CONVERSATION_H_INCLUDED_ */
