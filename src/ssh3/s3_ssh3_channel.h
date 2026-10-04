/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_SSH3_CHANNEL_H_INCLUDED_
#define _S3_SSH3_CHANNEL_H_INCLUDED_

#include <s3_core.h>

/*
 * the ssh3 channel, the port of the reference channel.go: a channel
 * is a QUIC bidirectional stream (ChannelID == StreamID), the first
 * block on it is the channel header and everything after it are the
 * channel messages (s3_ssh3_message)
 *
 * the header (docs/P4-WIRE.md 2.1): varint 0xaf3627e6, varint
 * conversationStreamID, SSHString channelType, varint maxPacketSize;
 * the address extension of the direct and forwarded channel types is
 * not part of wave 2
 */

#define S3_SSH3_FRAME_TYPE 0xaf3627e6ULL

#define S3_SSH3_CHANNEL_TYPE_SESSION "session"
#define S3_SSH3_CHANNEL_TYPE_DIRECT_TCP "direct-tcp"
#define S3_SSH3_CHANNEL_TYPE_DIRECT_UDP "direct-udp"

typedef struct s3_ssh3_channel_s s3_ssh3_channel_t;

struct s3_ssh3_channel_s {
    s3_queue_t       queue; /* the accept queue linkage */
    s3_rbtree_node_t node;  /* the conversation registry, key = channel_id */
    uint64_t         channel_id;
    uint64_t         conversation_stream_id;
    s3_str_t         type;
    uint64_t         max_packet_size;
    unsigned         header_sent : 1; /* the lazy header of the opener */
    unsigned         confirmed : 1;   /* the 91 seen on the opener side */
};

/*
 * the header size in the wire form of the channel
 */

size_t s3_ssh3_channel_header_size(const s3_ssh3_channel_t *ch);

/*
 * writes the header at p, returns the past-the-end pointer
 */
u_char *s3_ssh3_channel_build_header(u_char *p, const s3_ssh3_channel_t *ch);

/*
 * parses the header at *pos; on S3_OK the type view points into the
 * receive buffer and the conversation_stream_id and max_packet_size
 * fields are filled (the channel_id is the stream id, the transport
 * knows it, the header does not carry it); a wrong frame type or a
 * truncated buffer leaves *pos untouched and returns S3_ERROR
 */
s3_int_t s3_ssh3_channel_parse_header(const u_char **pos, const u_char *end, s3_ssh3_channel_t *ch);

/*
 * the payload bytes one 94/95 frame may carry under the channel
 * maxPacketSize: the frame overhead (the type varint plus the length
 * varint, one more varint for the extended data type) is subtracted
 * first, like the reference WriteData()
 */
size_t s3_ssh3_channel_chunk_size(uint64_t max_packet_size, unsigned extended);

#endif /* _S3_SSH3_CHANNEL_H_INCLUDED_ */
