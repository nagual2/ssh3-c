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

/*
 * the bound of the peer-advertised maxPacketSize (the F-01 tail, the
 * util.MaxSSHStringLen of the reference): the advertised size bounds
 * the data messages of the channel and is a second allocation knob
 * otherwise, a channel open advertising more is refused at the header
 * parse
 */
#define S3_SSH3_CHANNEL_MAX_PACKET_LIMIT (16u << 20)

/*
 * the floor of the peer-advertised maxPacketSize (F-1, the
 * minPeerMaxPacketSize of the reference channel.go): the frame
 * overhead eats 3-4 bytes of every data message, so an advertisement
 * below 4096 hands the sender 1-byte chunks (a 0-byte one for the
 * extended data) - the floor protects the sender from the peer-picked
 * chunk size; the header parse clamps a smaller advertisement up (the
 * clamp of the reference, not a refusal), the chunk helper clamps its
 * input into [MIN_PACKET_SIZE .. MAX_PACKET_LIMIT] so the invariant
 * holds for any future caller; the enforcement on the send/receive
 * data path itself stays with the send wiring
 */

#define S3_SSH3_CHANNEL_MIN_PACKET_SIZE 4096u

#define S3_SSH3_CHANNEL_TYPE_SESSION    "session"
#define S3_SSH3_CHANNEL_TYPE_DIRECT_TCP "direct-tcp"
#define S3_SSH3_CHANNEL_TYPE_DIRECT_UDP "direct-udp"

/*
 * the control channel of the reverse forward (the -R of the
 * reference, message/reverse_forward.go): the client opens it
 * towards the server and carries the bind request as the channel
 * data; the server binds and answers with the result as the channel
 * data too
 */

#define S3_SSH3_CHANNEL_TYPE_REVERSE_FORWARD "reverse-forward"

/*
 * the server-to-client channel types (the reverse forward, the -R of
 * the reference): the server opens one per accepted connection or
 * datagram of a bound -R listener, the header extension carries the
 * client-side target; a client opening them towards the server breaks
 * the role table and is refused on the inbound path (S2-03, the
 * pass-2 audit)
 */

#define S3_SSH3_CHANNEL_TYPE_FORWARDED_TCP "forwarded-tcp"
#define S3_SSH3_CHANNEL_TYPE_FORWARDED_UDP "forwarded-udp"

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
 * truncated buffer leaves *pos untouched and returns S3_ERROR; a
 * max_packet_size above the limit is refused, one below the floor is
 * clamped up to it (F-1, the clamp of the reference, not a refusal)
 */
s3_int_t s3_ssh3_channel_parse_header(const u_char **pos, const u_char *end, s3_ssh3_channel_t *ch);

/*
 * the payload bytes one 94/95 frame may carry under the channel
 * maxPacketSize: the input clamps into
 * [MIN_PACKET_SIZE .. MAX_PACKET_LIMIT] first (F-1), the frame
 * overhead (the type varint plus the length varint, one more varint
 * for the extended data type) is subtracted after, like the reference
 * WriteData()
 */
size_t s3_ssh3_channel_chunk_size(uint64_t max_packet_size, unsigned extended);

#endif /* _S3_SSH3_CHANNEL_H_INCLUDED_ */
