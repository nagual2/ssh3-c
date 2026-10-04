/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the ssh3 channel header (docs/P4-WIRE.md 2.1) and the data chunk
 * accounting, the reference channel.go buildHeader/parseHeader/WriteData
 */

#include <s3_core.h>

#include <string.h>

#include <s3_ssh3_channel.h>
#include <s3_ssh3_message.h>
#include <s3_ssh3_wire.h>

size_t
s3_ssh3_channel_header_size(const s3_ssh3_channel_t *ch)
{
    return s3_ssh3_varint_size(S3_SSH3_FRAME_TYPE) +
           s3_ssh3_varint_size(ch->conversation_stream_id) + s3_ssh3_sshstring_size(ch->type.len) +
           s3_ssh3_varint_size(ch->max_packet_size);
}

u_char *
s3_ssh3_channel_build_header(u_char *p, const s3_ssh3_channel_t *ch)
{
    p = s3_ssh3_encode_varint(p, S3_SSH3_FRAME_TYPE);
    p = s3_ssh3_encode_varint(p, ch->conversation_stream_id);
    p = s3_ssh3_encode_sshstring(p, ch->type.data, ch->type.len);
    p = s3_ssh3_encode_varint(p, ch->max_packet_size);

    return p;
}

s3_int_t
s3_ssh3_channel_parse_header(const u_char **pos, const u_char *end, s3_ssh3_channel_t *ch)
{
    const u_char *p = *pos;
    uint64_t      frame_type;
    uint64_t      conversation_stream_id;
    s3_str_t      type;
    uint64_t      max_packet_size;

    /* everything is parsed into the locals first: a wrong frame type
     * or a truncated buffer must leave both the cursor and the channel
     * untouched */

    if (s3_ssh3_parse_varint(&p, end, &frame_type) != S3_OK) {
        return S3_ERROR;
    }

    if (frame_type != S3_SSH3_FRAME_TYPE) {
        return S3_ERROR;
    }

    if (s3_ssh3_parse_varint(&p, end, &conversation_stream_id) != S3_OK) {
        return S3_ERROR;
    }

    if (s3_ssh3_parse_sshstring(&p, end, &type) != S3_OK) {
        return S3_ERROR;
    }

    if (s3_ssh3_parse_varint(&p, end, &max_packet_size) != S3_OK) {
        return S3_ERROR;
    }

    *pos = p;

    /* the channel_id is not on the wire: it is the StreamID of the
     * stream carrying the header and only the transport knows it */

    ch->conversation_stream_id = conversation_stream_id;
    ch->type = type;
    ch->max_packet_size = max_packet_size;

    return S3_OK;
}

size_t
s3_ssh3_channel_chunk_size(uint64_t max_packet_size, unsigned extended)
{
    uint64_t overhead;

    /* the reference WriteData() subtracts the emptyMsgLen: the length
     * of the frame with an empty string. varint(94) and varint(95)
     * take the 2-byte form (both are above 63), so the plain overhead
     * is 2 + 1 = 3 and the extended one is 2 + 1 + 1 = 4; the data
     * type is stderr (1), the only extended type on the wire */

    if (extended) {
        overhead = s3_ssh3_varint_size(S3_SSH3_MSG_CHANNEL_EXTENDED_DATA) +
                   s3_ssh3_varint_size(S3_SSH3_EXTENDED_DATA_STDERR) + s3_ssh3_varint_size(0);

    } else {
        overhead = s3_ssh3_varint_size(S3_SSH3_MSG_CHANNEL_DATA) + s3_ssh3_varint_size(0);
    }

    if (max_packet_size <= overhead) {
        return 0;
    }

    return (size_t)(max_packet_size - overhead);
}
