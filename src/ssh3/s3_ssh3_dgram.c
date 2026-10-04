/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the ssh3 channel datagram codec, the wire side of the reference
 * getDatagramSenderForChannel and Conversation.AddDatagram
 */

#include <s3_core.h>

#include <s3_ssh3_dgram.h>
#include <s3_ssh3_wire.h>

size_t
s3_ssh3_dgram_prefix_size(uint64_t control_stream_id, uint64_t channel_id)
{
    return s3_ssh3_varint_size(control_stream_id) + s3_ssh3_varint_size(channel_id);
}

u_char *
s3_ssh3_dgram_encode(u_char *p, uint64_t control_stream_id, uint64_t channel_id, const u_char *data,
                     size_t len)
{
    p = s3_ssh3_encode_varint(p, control_stream_id);
    p = s3_ssh3_encode_varint(p, channel_id);

    if (len > 0) {
        p = (u_char *)s3_cpymem(p, data, len);
    }

    return p;
}

s3_int_t
s3_ssh3_dgram_parse(const u_char **pos, const u_char *end, uint64_t *control_stream_id,
                    uint64_t *channel_id, s3_str_t *payload)
{
    const u_char *p = *pos;
    uint64_t      control, channel;

    if (s3_ssh3_parse_varint(&p, end, &control) != S3_OK) {
        return S3_ERROR;
    }

    if (s3_ssh3_parse_varint(&p, end, &channel) != S3_OK) {
        return S3_ERROR;
    }

    *control_stream_id = control;
    *channel_id = channel;

    /* the datagram is unframed: the whole remainder is the payload,
     * a zero-length view included */

    payload->data = (u_char *)p;
    payload->len = (size_t)(end - p);

    *pos = end;

    return S3_OK;
}
