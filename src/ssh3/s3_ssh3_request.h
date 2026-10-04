/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_SSH3_REQUEST_H_INCLUDED_
#define _S3_SSH3_REQUEST_H_INCLUDED_

#include <s3_base.h>

/*
 * the ssh3 channel-request bodies, the port of the reference
 * message/channel_request.go (ParsePtyRequest ... ParseX11Request):
 * the envelope (the SSHString request type, the wantReply byte)
 * belongs to the message module, the bodies after the wantReply byte
 * are parsed and encoded here
 *
 * every integer rides as a QUIC varint, every string as an SSHString
 * (see s3_ssh3_wire.h); the parsed strings are zero-copy views into
 * the receive buffer, valid while it lives
 */

typedef enum {
    S3_SSH3_REQ_PTY = 0,
    S3_SSH3_REQ_SHELL,
    S3_SSH3_REQ_EXEC,
    S3_SSH3_REQ_SUBSYSTEM,
    S3_SSH3_REQ_WINDOW_CHANGE,
    S3_SSH3_REQ_SIGNAL,
    S3_SSH3_REQ_EXIT_STATUS,
    S3_SSH3_REQ_EXIT_SIGNAL,
    S3_SSH3_REQ_X11
} s3_ssh3_request_kind_t;

typedef struct {
    s3_ssh3_request_kind_t kind;

    union {
        /* pty-req */
        struct {
            s3_str_t term;
            uint64_t width, height, pixel_width, pixel_height;
            s3_str_t modes; /* the opaque encoded terminal modes */
        } pty;

        /* exec */
        struct {
            s3_str_t command;
        } exec;

        /* subsystem */
        struct {
            s3_str_t name;
        } subsystem;

        /* window-change */
        struct {
            uint64_t width, height, pixel_width, pixel_height;
        } window_change;

        /* signal, the name rides without the SIG prefix */
        struct {
            s3_str_t name;
        } signal;

        /* exit-status */
        struct {
            uint64_t status;
        } exit_status;

        /* exit-signal */
        struct {
            s3_str_t name;
            unsigned core_dumped;
            s3_str_t error_message;
            s3_str_t language_tag;
        } exit_signal;

        /* x11-req */
        struct {
            unsigned single_connection;
            s3_str_t auth_proto;
            s3_str_t cookie;
            uint64_t screen;
        } x11;
    } u;
} s3_ssh3_request_t;

/*
 * parses the body dispatched by the request type string of the
 * envelope; an unknown type is S3_DECLINED, a truncated or a
 * not-fully-consumed body is S3_ERROR with the cursor left untouched,
 * S3_OK otherwise with the cursor past the body
 */
s3_int_t s3_ssh3_request_parse_body(const u_char **pos, const u_char *end, const s3_str_t *type,
                                    s3_ssh3_request_t *req);

/*
 * writes the body of the request at p and returns the past-the-end
 * pointer, or, with p == NULL (the measure mode), returns the encoded
 * size of the body
 */
uintptr_t s3_ssh3_request_encode_body(u_char *p, const s3_ssh3_request_t *req);

/* the canonical request type string of the kind, NULL when out of range */

const char *s3_ssh3_request_type_str(s3_ssh3_request_kind_t kind);

/* the kind of the request type string, S3_DECLINED when unknown */

s3_int_t s3_ssh3_request_kind_of(const s3_str_t *type, s3_ssh3_request_kind_t *kind);

#endif /* _S3_SSH3_REQUEST_H_INCLUDED_ */
