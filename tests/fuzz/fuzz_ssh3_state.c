/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the stateful libFuzzer harness of the ssh3 layer (P6): one
 * conversation per exec, the channel registry (the rbtree keyed by
 * ChannelID), the accept queue and the per-channelID datagram stores
 * live across the steps of the input, so the mutated instructions act
 * on the state the earlier steps built up.  the input is a sequence
 * of [op:1][len:1][payload:len] steps: the ops open and close the
 * channels (the header encode/parse pair in both directions), deliver
 * the channel messages (91/92/94/95/98) to the registered channels,
 * push and pop the datagrams through their controlStreamID|channelID
 * prefix, and probe the registry and the accept queue.  every
 * (encode, parse) pair the steps drive is pinned by a round-trip
 * gate, and the conversation integrity (the tree contents, the
 * accept queue and the datagram bookkeeping) is asserted after the
 * last step
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include <s3_core.h>

#include <s3_ssh3_channel.h>
#include <s3_ssh3_conversation.h>
#include <s3_ssh3_dgram.h>
#include <s3_ssh3_message.h>
#include <s3_ssh3_request.h>
#include <s3_ssh3_wire.h>

#include "s3_fuzz.h"

/*
 * the channel slots the steps address by index; the conversation
 * pool owns the channel objects, the harness only unlinks them
 */

#define S3_FUZZ_SSH3_MAX_CHANNELS 16

/* the cap of the raw channel type of the open step */

#define S3_FUZZ_SSH3_TYPE_MAX 64

/*
 * the conversation binds to a fixed control stream id, like one QUIC
 * connection of the real session
 */

#define S3_FUZZ_SSH3_CTRL_ID 4

/*
 * the canonical-form buffer: a step body is at most 254 bytes, the
 * widest canonical re-encode (the open failure, the varint plus two
 * full strings) stays well under 640
 */

#define S3_FUZZ_SSH3_CANON_MAX 640

/* the ops */

#define S3_FUZZ_OP_OPEN   0x00
#define S3_FUZZ_OP_CLOSE  0x01
#define S3_FUZZ_OP_MSG    0x02
#define S3_FUZZ_OP_DGRAM  0x03
#define S3_FUZZ_OP_POP    0x04
#define S3_FUZZ_OP_FIND   0x05
#define S3_FUZZ_OP_ACCEPT 0x06
#define S3_FUZZ_OP_RAWHDR 0x07

typedef struct {
    s3_pool_t             *pool;
    s3_ssh3_conversation_t conv;
    s3_ssh3_channel_t     *slots[S3_FUZZ_SSH3_MAX_CHANNELS];
    s3_uint_t              nchannels; /* the linked channels */
    uint64_t               pushes;    /* the payloads the store accepted */
    uint64_t               pops;      /* the payloads the reads removed */
} s3_fuzz_env_t;

static s3_log_t s3_fuzz_ssh3_log = {0, S3_INVALID_FILE};

static s3_int_t
s3_fuzz_env_init(s3_fuzz_env_t *env)
{
    s3_memzero(env, sizeof(s3_fuzz_env_t));

    env->pool = s3_create_pool((size_t)S3_DEFAULT_POOL_SIZE, &s3_fuzz_ssh3_log);
    if (env->pool == NULL) {
        return S3_ERROR;
    }

    if (s3_ssh3_conversation_init(&env->conv, env->pool, S3_FUZZ_SSH3_CTRL_ID) != S3_OK) {
        return S3_ERROR;
    }

    return S3_OK;
}

/*
 * the open step: the payload is [slot][flags][type sel] plus the
 * three varints (ChannelID, conversationStreamID, maxPacketSize) and
 * the raw type bytes of the selector 3; the descriptor feeds the
 * header encoder, the wire form must parse back to the same fields,
 * then the channel joins the registry (the low flag bit marks the
 * incoming side, its channel also enters the accept queue)
 */

static void
s3_fuzz_open_step(s3_fuzz_env_t *env, const u_char *chunk, size_t len)
{
    u_char             buf[S3_FUZZ_SSH3_CANON_MAX];
    u_char            *p;
    const u_char      *pos, *end, *rpos, *rend;
    s3_ssh3_channel_t  wire, parsed;
    s3_ssh3_channel_t *ch;
    uint64_t           channel_id, flags;
    s3_uint_t          slot, sel, incoming;

    if (len < 3) {
        return;
    }

    slot = (s3_uint_t)chunk[0] % S3_FUZZ_SSH3_MAX_CHANNELS;
    flags = chunk[1];
    sel = (s3_uint_t)chunk[2] & 3u;

    pos = chunk + 3;
    end = chunk + len;

    if (s3_ssh3_parse_varint(&pos, end, &channel_id) != S3_OK) {
        return;
    }

    /* the ChannelID is the StreamID of the stream that carries the
     * header: the transport never hands the conversation a second
     * channel of one id, the step keeps that guarantee (the registry
     * answers one object per id) */

    if (s3_ssh3_conversation_find_channel(&env->conv, channel_id) != NULL) {
        s3_fuzz_sink((size_t)channel_id);

        return;
    }

    s3_memzero(&wire, sizeof(s3_ssh3_channel_t));

    if (s3_ssh3_parse_varint(&pos, end, &wire.conversation_stream_id) != S3_OK) {
        return;
    }

    if (s3_ssh3_parse_varint(&pos, end, &wire.max_packet_size) != S3_OK) {
        return;
    }

    switch (sel) {

    case 0:
        wire.type.data = (u_char *)S3_SSH3_CHANNEL_TYPE_SESSION;
        wire.type.len = s3_strlen(S3_SSH3_CHANNEL_TYPE_SESSION);
        break;

    case 1:
        wire.type.data = (u_char *)S3_SSH3_CHANNEL_TYPE_DIRECT_TCP;
        wire.type.len = s3_strlen(S3_SSH3_CHANNEL_TYPE_DIRECT_TCP);
        break;

    case 2:
        wire.type.data = (u_char *)S3_SSH3_CHANNEL_TYPE_DIRECT_UDP;
        wire.type.len = s3_strlen(S3_SSH3_CHANNEL_TYPE_DIRECT_UDP);
        break;

    default:
        wire.type.data = (u_char *)pos;
        wire.type.len = (size_t)(end - pos);

        if (wire.type.len > S3_FUZZ_SSH3_TYPE_MAX) {
            return;
        }

        /* the type outlives the step: the copy moves into the
         * conversation pool */

        if (wire.type.len != 0) {
            p = s3_pnalloc(env->pool, wire.type.len);

            if (p == NULL) {
                return;
            }

            s3_memcpy(p, wire.type.data, wire.type.len);
            wire.type.data = p;
        }

        break;
    }

    /* the encode/parse contract of the header machine: the wire form
     * of the descriptor parses back to the same fields, consumes the
     * whole buffer and leaves the channel_id of the transport alone */

    if (s3_ssh3_channel_header_size(&wire) > sizeof(buf)) {
        return;
    }

    p = s3_ssh3_channel_build_header(buf, &wire);

    s3_memzero(&parsed, sizeof(s3_ssh3_channel_t));
    parsed.channel_id = (uint64_t)-1;

    rpos = buf;
    rend = p;

    if (s3_ssh3_channel_parse_header(&rpos, rend, &parsed) != S3_OK || rpos != rend ||
        parsed.conversation_stream_id != wire.conversation_stream_id ||
        parsed.max_packet_size != wire.max_packet_size || parsed.type.len != wire.type.len ||
        parsed.channel_id != (uint64_t)-1) {
        s3_fuzz_trap();
    }

    if (wire.type.len != 0 && s3_memcmp(parsed.type.data, wire.type.data, wire.type.len) != 0) {
        s3_fuzz_trap();
    }

    if (env->slots[slot] != NULL) {
        /* the slot is busy: the step is dropped, the close op frees
         * the slot first */

        s3_fuzz_sink((size_t)slot + (size_t)flags);

        return;
    }

    ch = s3_pcalloc(env->pool, sizeof(s3_ssh3_channel_t));
    if (ch == NULL) {
        return;
    }

    ch->channel_id = channel_id;
    ch->conversation_stream_id = wire.conversation_stream_id;
    ch->type = wire.type;
    ch->max_packet_size = wire.max_packet_size;

    incoming = (s3_uint_t)(flags & 1u);

    /* the opener has sent its lazy header, the incoming side is
     * usable right away (the 91 is a no-op for it) */

    ch->confirmed = (unsigned)incoming;
    ch->header_sent = (unsigned)(incoming != 0 ? 0u : 1u);

    s3_ssh3_conversation_link_channel(&env->conv, ch);

    if (incoming) {
        s3_ssh3_conversation_enqueue_accept(&env->conv, ch);
    }

    env->slots[slot] = ch;
    env->nchannels++;

    s3_fuzz_sink((size_t)ch->channel_id + (size_t)ch->max_packet_size + ch->type.len);
}

/*
 * the close step: the channel leaves the registry (the reference
 * leaks it, the ssh3-c port unlinks) and the payloads it never read
 * drain through the pop path
 */

static void
s3_fuzz_close_step(s3_fuzz_env_t *env, const u_char *chunk, size_t len)
{
    s3_ssh3_channel_t *ch;
    s3_str_t           out;
    s3_uint_t          slot;
    s3_int_t           rc;

    if (len < 1) {
        return;
    }

    slot = (s3_uint_t)chunk[0] % S3_FUZZ_SSH3_MAX_CHANNELS;

    ch = env->slots[slot];

    if (ch == NULL) {
        s3_fuzz_sink(slot);

        return;
    }

    s3_ssh3_conversation_unlink_channel(&env->conv, ch);

    for (;;) {
        rc = s3_ssh3_conversation_pop_datagram(&env->conv, ch->channel_id, &out);

        if (rc != S3_OK) {
            break;
        }

        env->pops++;

        s3_fuzz_sink(out.len);
    }

    s3_fuzz_sink((size_t)rc + slot);

    env->slots[slot] = NULL;
    env->nchannels--;
}

/*
 * the message step: [slot][type][body], the body the message codecs
 * parse per type; a body the parser consumes to the last byte must be
 * the canonical encoder output (fuzz_message.c pins the same pairs
 * statelessly, here they ride the live channels)
 */

static void
s3_fuzz_msg_step(s3_fuzz_env_t *env, const u_char *chunk, size_t len)
{
    u_char                          cbuf[S3_FUZZ_SSH3_CANON_MAX];
    u_char                         *cp;
    const u_char                   *pos, *end, *body, *wpos;
    s3_ssh3_channel_t              *ch;
    s3_ssh3_msg_open_confirmation_t oc;
    s3_ssh3_msg_open_failure_t      of;
    s3_ssh3_msg_data_t              d;
    s3_ssh3_msg_extended_data_t     ed;
    s3_ssh3_msg_request_t           rq, rq2;
    s3_ssh3_request_t               req, req2;
    size_t                          size, blen;
    s3_uint_t                       slot;
    u_char                          type;
    s3_int_t                        rc;

    if (len < 2) {
        return;
    }

    slot = (s3_uint_t)chunk[0] % S3_FUZZ_SSH3_MAX_CHANNELS;
    type = chunk[1];

    ch = env->slots[slot];

    if (ch == NULL) {
        s3_fuzz_sink(type);

        return;
    }

    body = chunk + 2;
    blen = len - 2;

    pos = body;
    end = body + blen;

    switch (type) {

    case S3_SSH3_MSG_CHANNEL_OPEN_CONFIRMATION:

        if (s3_ssh3_msg_parse_open_confirmation(&pos, end, &oc) != S3_OK) {
            break;
        }

        /* the 91 flips the opener side to confirmed */

        ch->confirmed = 1;

        size = s3_ssh3_msg_encode_open_confirmation(NULL, &oc);

        if (size == (size_t)(pos - body) && size <= sizeof(cbuf)) {
            cp = (u_char *)s3_ssh3_msg_encode_open_confirmation(cbuf, &oc);

            if ((size_t)(cp - cbuf) != size || s3_memcmp(cbuf, body, size) != 0) {
                s3_fuzz_trap();
            }
        }

        s3_fuzz_sink((size_t)oc.max_packet_size + ch->confirmed);

        return;

    case S3_SSH3_MSG_CHANNEL_OPEN_FAILURE:

        if (s3_ssh3_msg_parse_open_failure(&pos, end, &of) != S3_OK) {
            break;
        }

        size = s3_ssh3_msg_encode_open_failure(NULL, &of);

        if (size == (size_t)(pos - body) && size <= sizeof(cbuf)) {
            cp = (u_char *)s3_ssh3_msg_encode_open_failure(cbuf, &of);

            if ((size_t)(cp - cbuf) != size || s3_memcmp(cbuf, body, size) != 0) {
                s3_fuzz_trap();
            }
        }

        s3_fuzz_sink((size_t)of.reason_code + of.error_message.len + of.language_tag.len);

        return;

    case S3_SSH3_MSG_CHANNEL_DATA:

        if (s3_ssh3_msg_parse_data(&pos, end, &d) != S3_OK) {
            break;
        }

        size = s3_ssh3_msg_encode_data(NULL, &d);

        if (size == (size_t)(pos - body) && size <= sizeof(cbuf)) {
            cp = (u_char *)s3_ssh3_msg_encode_data(cbuf, &d);

            if ((size_t)(cp - cbuf) != size || s3_memcmp(cbuf, body, size) != 0) {
                s3_fuzz_trap();
            }
        }

        s3_fuzz_sink(d.data.len);

        return;

    case S3_SSH3_MSG_CHANNEL_EXTENDED_DATA:

        if (s3_ssh3_msg_parse_extended_data(&pos, end, &ed) != S3_OK) {
            break;
        }

        size = s3_ssh3_msg_encode_extended_data(NULL, &ed);

        if (size == (size_t)(pos - body) && size <= sizeof(cbuf)) {
            cp = (u_char *)s3_ssh3_msg_encode_extended_data(cbuf, &ed);

            if ((size_t)(cp - cbuf) != size || s3_memcmp(cbuf, body, size) != 0) {
                s3_fuzz_trap();
            }
        }

        s3_fuzz_sink((size_t)ed.data_type + ed.data.len);

        return;

    case S3_SSH3_MSG_CHANNEL_REQUEST:

        /* the channel requests ride the confirmed channels only */

        if (ch->confirmed == 0) {
            s3_fuzz_sink(blen);

            return;
        }

        if (s3_ssh3_msg_parse_request_envelope(&pos, end, &rq) != S3_OK) {
            break;
        }

        /* the whole-buffer variant answers the same envelope */

        wpos = body;

        if (s3_ssh3_msg_parse_request(&wpos, end, &rq2) != S3_OK ||
            rq2.want_reply != rq.want_reply || rq2.request_type.len != rq.request_type.len ||
            (rq.request_type.len != 0 &&
             s3_memcmp(rq2.request_type.data, rq.request_type.data, rq.request_type.len) != 0)) {
            s3_fuzz_trap();
        }

        rc = s3_ssh3_request_parse_body(&pos, end, &rq.request_type, &req);

        if (rc == S3_DECLINED) {
            /* the unknown request type: the envelope alone rides, the
             * body stays opaque for the caller */

            s3_fuzz_sink((size_t)rq.want_reply + rq.request_type.len + rq.body.len);

            return;
        }

        if (rc != S3_OK) {
            break;
        }

        /* the parsed body re-encodes byte for byte and parses back to
         * the same kind (the request bodies have no other fuzz
         * target) */

        size = s3_ssh3_request_encode_body(NULL, &req);

        if (size == rq.body.len && size != 0 && size <= sizeof(cbuf)) {

            cp = (u_char *)s3_ssh3_request_encode_body(cbuf, &req);

            if ((size_t)(cp - cbuf) != size || s3_memcmp(cbuf, rq.body.data, size) != 0) {
                s3_fuzz_trap();
            }

            pos = cbuf;

            s3_memzero(&req2, sizeof(s3_ssh3_request_t));

            if (s3_ssh3_request_parse_body(&pos, cp, &rq.request_type, &req2) != S3_OK ||
                pos != cp || req2.kind != req.kind) {
                s3_fuzz_trap();
            }
        }

        s3_fuzz_sink(size + (size_t)req.kind + rq.want_reply);

        return;
    }

    /* the parse error or the unknown type: the step ends here, the
     * conversation state survives like after a violation the caller
     * drops */

    s3_fuzz_sink((size_t)type + blen);
}

/*
 * the datagram step: the payload is the raw wire form, the prefix
 * varints controlStreamID|channelID and the unframed UDP payload; the
 * parse results must re-encode byte for byte (the prefix is the
 * canonical varint form), then the store takes the payload under the
 * channel id it carries, valid or foreign alike
 */

static void
s3_fuzz_dgram_step(s3_fuzz_env_t *env, const u_char *chunk, size_t len)
{
    u_char        buf[S3_FUZZ_SSH3_CANON_MAX];
    u_char       *p;
    const u_char *pos, *end;
    uint64_t      control_id, channel_id;
    s3_str_t      payload;
    s3_int_t      rc;

    pos = chunk;
    end = chunk + len;

    if (s3_ssh3_dgram_parse(&pos, end, &control_id, &channel_id, &payload) != S3_OK) {
        s3_fuzz_sink(len);

        return;
    }

    /* the parse always consumes the whole datagram: the re-encode of
     * the results is the input itself */

    p = s3_ssh3_dgram_encode(buf, control_id, channel_id, payload.data, payload.len);

    if ((size_t)(p - buf) != len || s3_memcmp(buf, chunk, len) != 0) {
        s3_fuzz_trap();
    }

    rc = s3_ssh3_conversation_push_datagram(&env->conv, channel_id, payload.data, payload.len);

    if (rc == S3_OK) {
        env->pushes++;
    }

    s3_fuzz_sink((size_t)rc + payload.len + (size_t)control_id);
}

static void
s3_fuzz_pop_step(s3_fuzz_env_t *env, const u_char *chunk, size_t len)
{
    const u_char *pos, *end;
    uint64_t      channel_id;
    s3_str_t      out;
    s3_int_t      rc;

    pos = chunk;
    end = chunk + len;

    if (s3_ssh3_parse_varint(&pos, end, &channel_id) != S3_OK) {
        s3_fuzz_sink(len);

        return;
    }

    rc = s3_ssh3_conversation_pop_datagram(&env->conv, channel_id, &out);

    if (rc == S3_OK) {
        env->pops++;

        s3_fuzz_sink(out.len + (out.len != 0 ? out.data[0] : 0));

        return;
    }

    s3_fuzz_sink((size_t)rc + (size_t)channel_id);
}

static void
s3_fuzz_find_step(s3_fuzz_env_t *env, const u_char *chunk, size_t len)
{
    s3_ssh3_channel_t *ch;
    const u_char      *pos, *end;
    uint64_t           channel_id;

    pos = chunk;
    end = chunk + len;

    if (s3_ssh3_parse_varint(&pos, end, &channel_id) != S3_OK) {
        s3_fuzz_sink(len);

        return;
    }

    ch = s3_ssh3_conversation_find_channel(&env->conv, channel_id);

    /* the registry answers the exact registered object per id */

    if (ch != NULL && ch->channel_id != channel_id) {
        s3_fuzz_trap();
    }

    s3_fuzz_sink((size_t)(ch != NULL) + (size_t)channel_id);
}

static void
s3_fuzz_accept_step(s3_fuzz_env_t *env)
{
    s3_ssh3_channel_t *ch;

    ch = s3_ssh3_conversation_dequeue_accept(&env->conv);

    s3_fuzz_sink(ch != NULL ? (size_t)ch->channel_id + 1 : (size_t)0);
}

/*
 * the raw header step: the payload walks the header parser directly,
 * the error paths (the foreign frame type, the truncation) must leave
 * the cursor untouched, the parsed type view must stay inside the
 * receive buffer
 */

static void
s3_fuzz_rawhdr_step(s3_fuzz_env_t *env, const u_char *chunk, size_t len)
{
    s3_ssh3_channel_t ch;
    const u_char     *pos, *end;
    s3_int_t          rc;

    (void)env;

    pos = chunk;
    end = chunk + len;

    s3_memzero(&ch, sizeof(s3_ssh3_channel_t));
    ch.channel_id = (uint64_t)-1;

    rc = s3_ssh3_channel_parse_header(&pos, end, &ch);

    if (rc != S3_OK) {
        if (pos != chunk) {
            s3_fuzz_trap();
        }

        s3_fuzz_sink((size_t)rc + len);

        return;
    }

    if (ch.type.data < chunk || ch.type.data + ch.type.len > end || ch.channel_id != (uint64_t)-1) {
        s3_fuzz_trap();
    }

    s3_fuzz_sink((size_t)ch.conversation_stream_id + (size_t)ch.max_packet_size + ch.type.len);
}

static void
s3_fuzz_step(s3_fuzz_env_t *env, u_char op, const u_char *chunk, size_t len)
{
    switch (op) {

    case S3_FUZZ_OP_OPEN:
        s3_fuzz_open_step(env, chunk, len);
        break;

    case S3_FUZZ_OP_CLOSE:
        if (len != 0) {
            s3_fuzz_close_step(env, chunk, len);
        }

        break;

    case S3_FUZZ_OP_MSG:
        if (len != 0) {
            s3_fuzz_msg_step(env, chunk, len);
        }

        break;

    case S3_FUZZ_OP_DGRAM:
        s3_fuzz_dgram_step(env, chunk, len);
        break;

    case S3_FUZZ_OP_POP:
        s3_fuzz_pop_step(env, chunk, len);
        break;

    case S3_FUZZ_OP_FIND:
        s3_fuzz_find_step(env, chunk, len);
        break;

    case S3_FUZZ_OP_ACCEPT:
        s3_fuzz_accept_step(env);
        break;

    case S3_FUZZ_OP_RAWHDR:
        s3_fuzz_rawhdr_step(env, chunk, len);
        break;

    default:
        /* the unknown op is a step of one zero byte */

        s3_fuzz_sink(op);
    }
}

/*
 * the conversation integrity: the channel tree holds exactly the
 * channels the harness tracks and answers every id with its object,
 * the dangling queues count their payloads honestly, and the store
 * holds exactly what went in and never came out
 */

static void
s3_fuzz_integrity(s3_fuzz_env_t *env)
{
    s3_ssh3_channel_t     *ch;
    s3_ssh3_dgram_queue_t *dq;
    s3_rbtree_t           *tree;
    s3_rbtree_node_t      *node;
    s3_queue_t            *q;
    size_t                 in_tree, in_dangling, payloads, queued, in_accept;

    tree = &env->conv.channels;
    in_tree = 0;

    if (tree->root != tree->sentinel) {
        /* the walk ends at NULL, the s3_rbtree_next of this port does
         * not route through the sentinel (fuzz_quic_state.c walks the
         * same way) */

        node = s3_rbtree_min(tree->root, tree->sentinel);

        while (node != NULL) {
            ch = s3_rbtree_data(node, s3_ssh3_channel_t, node);

            if (s3_ssh3_conversation_find_channel(&env->conv, ch->channel_id) != ch) {
                s3_fuzz_trap();
            }

            in_tree++;
            node = s3_rbtree_next(tree, node);
        }
    }

    if (in_tree != env->nchannels) {
        s3_fuzz_trap();
    }

    tree = &env->conv.dangling;
    in_dangling = 0;
    payloads = 0;

    if (tree->root != tree->sentinel) {
        node = s3_rbtree_min(tree->root, tree->sentinel);

        while (node != NULL) {
            dq = s3_rbtree_data(node, s3_ssh3_dgram_queue_t, node);

            queued = 0;

            for (q = s3_queue_head(&dq->payloads); q != s3_queue_sentinel(&dq->payloads);
                 q = s3_queue_next(q)) {
                queued++;
            }

            if (queued != dq->count) {
                s3_fuzz_trap();
            }

            payloads += queued;
            in_dangling++;
            node = s3_rbtree_next(tree, node);
        }
    }

    if (payloads != env->pushes - env->pops) {
        s3_fuzz_trap();
    }

    in_accept = 0;

    for (q = s3_queue_head(&env->conv.accept); q != s3_queue_sentinel(&env->conv.accept);
         q = s3_queue_next(q)) {
        in_accept++;
    }

    s3_fuzz_sink(in_tree + in_dangling + payloads + in_accept);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    s3_fuzz_env_t env;
    const u_char *pos, *end;
    u_char        chunk[256];
    size_t        len;
    u_char        op;

    if (s3_fuzz_env_init(&env) != S3_OK) {
        if (env.pool != NULL) {
            s3_destroy_pool(env.pool);
        }

        return 0;
    }

    pos = (const u_char *)data;
    end = pos + size;

    while (pos + 2 <= end) {

        op = *pos++;
        len = *pos++;

        if ((size_t)(end - pos) < len) {
            len = (size_t)(end - pos);
        }

        s3_memcpy(chunk, pos, len);
        pos += len;

        s3_fuzz_step(&env, op, chunk, len);
    }

    s3_fuzz_integrity(&env);

    s3_fuzz_sink((size_t)env.nchannels + env.pushes);

    s3_destroy_pool(env.pool);

    return 0;
}
