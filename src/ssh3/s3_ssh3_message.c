/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the ssh3 channel messages, the reference message/message.go
 */

#include <s3_core.h>

#include <string.h>

#include <s3_ssh3_message.h>

#include <s3_ssh3_wire.h>

uintptr_t
s3_ssh3_msg_encode_open_confirmation(u_char *p, const s3_ssh3_msg_open_confirmation_t *m)
{
    if (p == NULL) {
        return s3_ssh3_varint_size(m->max_packet_size);
    }

    p = s3_ssh3_encode_varint(p, m->max_packet_size);

    return (uintptr_t)p;
}

uintptr_t
s3_ssh3_msg_encode_open_failure(u_char *p, const s3_ssh3_msg_open_failure_t *m)
{
    if (p == NULL) {
        return s3_ssh3_varint_size(m->reason_code) + s3_ssh3_sshstring_size(m->error_message.len) +
               s3_ssh3_sshstring_size(m->language_tag.len);
    }

    p = s3_ssh3_encode_varint(p, m->reason_code);
    p = s3_ssh3_encode_sshstring(p, m->error_message.data, m->error_message.len);
    p = s3_ssh3_encode_sshstring(p, m->language_tag.data, m->language_tag.len);

    return (uintptr_t)p;
}

uintptr_t
s3_ssh3_msg_encode_data(u_char *p, const s3_ssh3_msg_data_t *m)
{
    if (p == NULL) {
        return s3_ssh3_sshstring_size(m->data.len);
    }

    p = s3_ssh3_encode_sshstring(p, m->data.data, m->data.len);

    return (uintptr_t)p;
}

uintptr_t
s3_ssh3_msg_encode_extended_data(u_char *p, const s3_ssh3_msg_extended_data_t *m)
{
    if (p == NULL) {
        return s3_ssh3_varint_size(m->data_type) + s3_ssh3_sshstring_size(m->data.len);
    }

    p = s3_ssh3_encode_varint(p, m->data_type);
    p = s3_ssh3_encode_sshstring(p, m->data.data, m->data.len);

    return (uintptr_t)p;
}

uintptr_t
s3_ssh3_msg_encode_request(u_char *p, const s3_ssh3_msg_request_t *m)
{
    if (p == NULL) {
        return s3_ssh3_sshstring_size(m->request_type.len) + 1 + m->body.len;
    }

    p = s3_ssh3_encode_sshstring(p, m->request_type.data, m->request_type.len);

    /* the wantReply flag travels as one raw byte, the reference reads
     * it with binary.Read (message/channel_request.go) */

    *p++ = (u_char)m->want_reply;

    if (m->body.len > 0) {
        p = (u_char *)s3_cpymem(p, m->body.data, m->body.len);
    }

    return (uintptr_t)p;
}

s3_int_t
s3_ssh3_msg_parse_open_confirmation(const u_char **pos, const u_char *end,
                                    s3_ssh3_msg_open_confirmation_t *m)
{
    const u_char *p = *pos;
    uint64_t      max_packet_size;

    if (s3_ssh3_parse_varint(&p, end, &max_packet_size) != S3_OK) {
        return S3_ERROR;
    }

    m->max_packet_size = max_packet_size;
    *pos = p;

    return S3_OK;
}

s3_int_t
s3_ssh3_msg_parse_open_failure(const u_char **pos, const u_char *end, s3_ssh3_msg_open_failure_t *m)
{
    const u_char *p = *pos;
    s3_str_t      error_message, language_tag;
    uint64_t      reason_code;

    if (s3_ssh3_parse_varint(&p, end, &reason_code) != S3_OK) {
        return S3_ERROR;
    }

    if (s3_ssh3_parse_sshstring(&p, end, &error_message) != S3_OK) {
        return S3_ERROR;
    }

    if (s3_ssh3_parse_sshstring(&p, end, &language_tag) != S3_OK) {
        return S3_ERROR;
    }

    m->reason_code = reason_code;
    m->error_message = error_message;
    m->language_tag = language_tag;

    *pos = p;

    return S3_OK;
}

s3_int_t
s3_ssh3_msg_parse_data(const u_char **pos, const u_char *end, s3_ssh3_msg_data_t *m)
{
    const u_char *p = *pos;
    s3_str_t      data;

    /* the strict parse: unlike the reference, a truncated payload is
     * an error, not an io.EOF success */

    if (s3_ssh3_parse_sshstring(&p, end, &data) != S3_OK) {
        return S3_ERROR;
    }

    m->data = data;
    *pos = p;

    return S3_OK;
}

s3_int_t
s3_ssh3_msg_parse_extended_data(const u_char **pos, const u_char *end,
                                s3_ssh3_msg_extended_data_t *m)
{
    const u_char *p = *pos;
    s3_str_t      data;
    uint64_t      data_type;

    if (s3_ssh3_parse_varint(&p, end, &data_type) != S3_OK) {
        return S3_ERROR;
    }

    if (s3_ssh3_parse_sshstring(&p, end, &data) != S3_OK) {
        return S3_ERROR;
    }

    m->data_type = data_type;
    m->data = data;

    *pos = p;

    return S3_OK;
}

s3_int_t
s3_ssh3_msg_parse_request(const u_char **pos, const u_char *end, s3_ssh3_msg_request_t *m)
{
    const u_char *p = *pos;
    s3_str_t      request_type;

    if (s3_ssh3_parse_sshstring(&p, end, &request_type) != S3_OK) {
        return S3_ERROR;
    }

    if (end - p < 1) {
        return S3_ERROR;
    }

    m->request_type = request_type;
    m->want_reply = *p++;

    /* the rest of the buffer is the raw request body, possibly empty */

    m->body.data = (u_char *)p;
    m->body.len = (size_t)(end - p);

    *pos = end;

    return S3_OK;
}

s3_int_t
s3_ssh3_msg_parse_request_envelope(const u_char **pos, const u_char *end, s3_ssh3_msg_request_t *m)
{
    const u_char *p = *pos;
    s3_str_t      request_type;

    if (s3_ssh3_parse_sshstring(&p, end, &request_type) != S3_OK) {
        return S3_ERROR;
    }

    if (end - p < 1) {
        return S3_ERROR;
    }

    m->request_type = request_type;
    m->want_reply = *p++;

    /* the body stays where it starts: the caller parses it against
     * end with the request module, *pos lands on the first body byte */

    s3_memzero(&m->body, sizeof(s3_str_t));

    *pos = p;

    return S3_OK;
}
