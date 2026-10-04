/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_SSH3_MESSAGE_H_INCLUDED_
#define _S3_SSH3_MESSAGE_H_INCLUDED_

#include <s3_base.h>

/*
 * the ssh3 channel messages, the reference message/message.go; a
 * message body is what follows its varint message type, the type
 * itself is written and stripped by the calling layer; the parsed
 * strings are zero-copy views into the receive buffer; unlike the
 * reference, which tolerates a trailing EOF inside a data payload,
 * every parse here is strict: a truncated body is S3_ERROR
 */

/* the channel message types carried by this module */

#define S3_SSH3_MSG_CHANNEL_OPEN_CONFIRMATION 91
#define S3_SSH3_MSG_CHANNEL_OPEN_FAILURE      92
#define S3_SSH3_MSG_CHANNEL_DATA              94
#define S3_SSH3_MSG_CHANNEL_EXTENDED_DATA     95
#define S3_SSH3_MSG_CHANNEL_REQUEST           98

/* the data types of the channel extended data message */

#define S3_SSH3_EXTENDED_DATA_NONE   0
#define S3_SSH3_EXTENDED_DATA_STDERR 1

typedef struct {
    uint64_t max_packet_size;
} s3_ssh3_msg_open_confirmation_t;

typedef struct {
    uint64_t reason_code;
    s3_str_t error_message;
    s3_str_t language_tag;
} s3_ssh3_msg_open_failure_t;

typedef struct {
    s3_str_t data;
} s3_ssh3_msg_data_t;

typedef struct {
    uint64_t data_type;
    s3_str_t data;
} s3_ssh3_msg_extended_data_t;

/*
 * the envelope of the channel request message: the body stays a raw
 * view (its fields belong to s3_ssh3_request, a separate module) and
 * may be empty, e.g. the shell request
 */
typedef struct {
    s3_str_t request_type;
    unsigned want_reply;
    s3_str_t body;
} s3_ssh3_msg_request_t;

/*
 * the encoders write the message body at p and return the past-the-end
 * pointer, or return the encoded size when p is NULL (the measure
 * mode); the message type is not part of the body
 */

uintptr_t s3_ssh3_msg_encode_open_confirmation(u_char *p, const s3_ssh3_msg_open_confirmation_t *m);

uintptr_t s3_ssh3_msg_encode_open_failure(u_char *p, const s3_ssh3_msg_open_failure_t *m);

uintptr_t s3_ssh3_msg_encode_data(u_char *p, const s3_ssh3_msg_data_t *m);

uintptr_t s3_ssh3_msg_encode_extended_data(u_char *p, const s3_ssh3_msg_extended_data_t *m);

uintptr_t s3_ssh3_msg_encode_request(u_char *p, const s3_ssh3_msg_request_t *m);

/*
 * the parsers read one message body at *pos against end; on S3_OK *pos
 * advances past the message and the string fields point into the
 * receive buffer; a truncated body leaves *pos untouched and returns
 * S3_ERROR
 */

s3_int_t s3_ssh3_msg_parse_open_confirmation(const u_char **pos, const u_char *end,
                                             s3_ssh3_msg_open_confirmation_t *m);

s3_int_t s3_ssh3_msg_parse_open_failure(const u_char **pos, const u_char *end,
                                        s3_ssh3_msg_open_failure_t *m);

s3_int_t s3_ssh3_msg_parse_data(const u_char **pos, const u_char *end, s3_ssh3_msg_data_t *m);

s3_int_t s3_ssh3_msg_parse_extended_data(const u_char **pos, const u_char *end,
                                         s3_ssh3_msg_extended_data_t *m);

s3_int_t s3_ssh3_msg_parse_request(const u_char **pos, const u_char *end, s3_ssh3_msg_request_t *m);

#endif /* _S3_SSH3_MESSAGE_H_INCLUDED_ */
