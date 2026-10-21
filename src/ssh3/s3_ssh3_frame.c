/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the channel data frame: the plain form (94) and the compressed form
 * (192, PLAN.md 9, B8)
 */

#include <s3_core.h>

#include <string.h>

#include <s3_ssh3_compress.h>
#include <s3_ssh3_frame.h>
#include <s3_ssh3_message.h>
#include <s3_ssh3_wire.h>

/*
 * the header room the compressed frame reserves before the payload:
 * the type (two bytes), the algorithm (one) and the string length (up
 * to five) - the length of the compressed payload never crosses the
 * channel packet limit, so the varint of the length takes four bytes
 */

#define S3_SSH3_FRAME_COMPRESSED_ROOM 16

size_t
s3_ssh3_frame_data_bound(size_t payload_len)
{
    size_t plain;
    size_t compressed;

    plain = s3_ssh3_varint_size(S3_SSH3_MSG_CHANNEL_DATA) + s3_ssh3_sshstring_size(payload_len);

    compressed = s3_ssh3_compress_bound(S3_SSH3_COMPRESS_DEFLATE, payload_len);

    if (compressed < payload_len) {
        compressed = payload_len;
    }

    return plain + S3_SSH3_FRAME_COMPRESSED_ROOM + compressed;
}

s3_int_t
s3_ssh3_frame_data_build(u_char *buf, size_t cap, size_t *frame_len, uint32_t algorithm,
                         const u_char *payload, size_t payload_len, size_t *wire_len)
{
    size_t plain_len;
    size_t bound;
    size_t packed_len = 0;
    u_char *p;

    plain_len = s3_ssh3_varint_size(S3_SSH3_MSG_CHANNEL_DATA) + s3_ssh3_sshstring_size(payload_len);

    if (algorithm == S3_SSH3_COMPRESS_NONE || plain_len > cap) {
        goto plain;
    }

    bound = s3_ssh3_compress_bound(algorithm, payload_len);

    if (bound == 0 || bound + S3_SSH3_FRAME_COMPRESSED_ROOM > cap) {
        goto plain;
    }

    if (s3_ssh3_compress_encode(buf + S3_SSH3_FRAME_COMPRESSED_ROOM, cap - S3_SSH3_FRAME_COMPRESSED_ROOM,
                                &packed_len, algorithm, payload, payload_len) != S3_OK) {
        goto plain;
    }

    /* the cutoff: the compressed form that is not smaller travels as
     * the plain frame (the ZFS fast levels) */

    if (packed_len >= payload_len) {
        goto plain;
    }

    p = buf;
    p = (u_char *)s3_ssh3_encode_varint(p, S3_SSH3_MSG_CHANNEL_DATA_COMPRESSED);
    p = (u_char *)s3_ssh3_encode_varint(p, algorithm);
    p = (u_char *)s3_ssh3_encode_varint(p, packed_len);

    memmove(p, buf + S3_SSH3_FRAME_COMPRESSED_ROOM, packed_len);

    *frame_len = (size_t)(p - buf) + packed_len;

    if (wire_len != NULL) {
        *wire_len = packed_len;
    }

    return S3_OK;

plain:

    if (plain_len > cap) {
        return S3_ERROR;
    }

    p = buf;
    p = (u_char *)s3_ssh3_encode_varint(p, S3_SSH3_MSG_CHANNEL_DATA);
    p = (u_char *)s3_ssh3_encode_varint(p, payload_len);
    s3_memcpy(p, payload, payload_len);

    *frame_len = plain_len;

    if (wire_len != NULL) {
        *wire_len = payload_len;
    }

    return S3_OK;
}

s3_int_t
s3_ssh3_frame_data_parse(const u_char **pos, const u_char *end, uint64_t type, u_char *scratch,
                         size_t scratch_cap, s3_str_t *payload)
{
    if (type == S3_SSH3_MSG_CHANNEL_DATA) {

        s3_ssh3_msg_data_t data;

        if (s3_ssh3_msg_parse_data(pos, end, &data) != S3_OK) {
            return S3_ERROR;
        }

        *payload = data.data;

        return S3_OK;
    }

    if (type == S3_SSH3_MSG_CHANNEL_DATA_COMPRESSED) {

        s3_ssh3_msg_compressed_data_t msg;
        size_t                        plain_len = 0;

        if (s3_ssh3_msg_parse_compressed_data(pos, end, &msg) != S3_OK) {
            return S3_ERROR;
        }

        if (scratch == NULL) {
            return S3_DECLINED;
        }

        if (s3_ssh3_compress_decode(scratch, scratch_cap, &plain_len, (uint32_t)msg.algorithm,
                                    msg.data.data, msg.data.len) != S3_OK) {
            /* the frame is whole but the payload does not decode: a
             * protocol violation, not a partial frame */

            return S3_DECLINED;
        }

        payload->data = scratch;
        payload->len = plain_len;

        return S3_OK;
    }

    return S3_ERROR;
}
