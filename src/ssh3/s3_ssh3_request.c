/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the ssh3 channel-request bodies, the port of the reference
 * message/channel_request.go (ParsePtyRequest ... ParseX11Request):
 * the envelope (the SSHString request type, the wantReply byte) is
 * the message module's business, the bodies after it live here
 */

#include <s3_core.h>

#include <s3_ssh3_wire.h>

#include <s3_ssh3_request.h>

/* the canonical request type strings, indexed by the kind */

static const char *const s3_ssh3_request_types[] = {
    "pty-req",       /* S3_SSH3_REQ_PTY */
    "shell",         /* S3_SSH3_REQ_SHELL */
    "exec",          /* S3_SSH3_REQ_EXEC */
    "subsystem",     /* S3_SSH3_REQ_SUBSYSTEM */
    "window-change", /* S3_SSH3_REQ_WINDOW_CHANGE */
    "signal",        /* S3_SSH3_REQ_SIGNAL */
    "exit-status",   /* S3_SSH3_REQ_EXIT_STATUS */
    "exit-signal",   /* S3_SSH3_REQ_EXIT_SIGNAL */
    "x11-req",       /* S3_SSH3_REQ_X11 */
};

#define S3_SSH3_REQUEST_NTYPES (sizeof(s3_ssh3_request_types) / sizeof(s3_ssh3_request_types[0]))

const char *
s3_ssh3_request_type_str(s3_ssh3_request_kind_t kind)
{
    if ((unsigned)kind >= S3_SSH3_REQUEST_NTYPES) {
        return NULL;
    }

    return s3_ssh3_request_types[kind];
}

s3_int_t
s3_ssh3_request_kind_of(const s3_str_t *type, s3_ssh3_request_kind_t *kind)
{
    const char *name;
    size_t      n;

    if (type == NULL || type->data == NULL) {
        return S3_DECLINED;
    }

    for (n = 0; n < S3_SSH3_REQUEST_NTYPES; n++) {
        name = s3_ssh3_request_types[n];

        if (type->len == s3_strlen(name) && s3_memcmp(type->data, name, type->len) == 0) {
            *kind = (s3_ssh3_request_kind_t)n;

            return S3_OK;
        }
    }

    return S3_DECLINED;
}

/* the encoded size of the body, the port of the reference Length() */

static size_t
s3_ssh3_request_body_size(const s3_ssh3_request_t *req)
{
    switch (req->kind) {

    case S3_SSH3_REQ_PTY:
        return s3_ssh3_sshstring_size(req->u.pty.term.len) + s3_ssh3_varint_size(req->u.pty.width) +
               s3_ssh3_varint_size(req->u.pty.height) +
               s3_ssh3_varint_size(req->u.pty.pixel_width) +
               s3_ssh3_varint_size(req->u.pty.pixel_height) +
               s3_ssh3_sshstring_size(req->u.pty.modes.len);

    case S3_SSH3_REQ_SHELL:
        return 0;

    case S3_SSH3_REQ_EXEC:
        return s3_ssh3_sshstring_size(req->u.exec.command.len);

    case S3_SSH3_REQ_SUBSYSTEM:
        return s3_ssh3_sshstring_size(req->u.subsystem.name.len);

    case S3_SSH3_REQ_WINDOW_CHANGE:
        return s3_ssh3_varint_size(req->u.window_change.width) +
               s3_ssh3_varint_size(req->u.window_change.height) +
               s3_ssh3_varint_size(req->u.window_change.pixel_width) +
               s3_ssh3_varint_size(req->u.window_change.pixel_height);

    case S3_SSH3_REQ_SIGNAL:
        return s3_ssh3_sshstring_size(req->u.signal.name.len);

    case S3_SSH3_REQ_EXIT_STATUS:
        return s3_ssh3_varint_size(req->u.exit_status.status);

    case S3_SSH3_REQ_EXIT_SIGNAL:
        return s3_ssh3_sshstring_size(req->u.exit_signal.name.len) + 1 +
               s3_ssh3_sshstring_size(req->u.exit_signal.error_message.len) +
               s3_ssh3_sshstring_size(req->u.exit_signal.language_tag.len);

    case S3_SSH3_REQ_X11:
        return 1 + s3_ssh3_sshstring_size(req->u.x11.auth_proto.len) +
               s3_ssh3_sshstring_size(req->u.x11.cookie.len) +
               s3_ssh3_varint_size(req->u.x11.screen);
    }

    /* an out-of-range kind has no body */

    return 0;
}

uintptr_t
s3_ssh3_request_encode_body(u_char *p, const s3_ssh3_request_t *req)
{
    size_t size;

    size = s3_ssh3_request_body_size(req);

    if (p == NULL) {
        return (uintptr_t)size;
    }

    switch (req->kind) {

    case S3_SSH3_REQ_PTY:
        p = s3_ssh3_encode_sshstring(p, req->u.pty.term.data, req->u.pty.term.len);
        p = s3_ssh3_encode_varint(p, req->u.pty.width);
        p = s3_ssh3_encode_varint(p, req->u.pty.height);
        p = s3_ssh3_encode_varint(p, req->u.pty.pixel_width);
        p = s3_ssh3_encode_varint(p, req->u.pty.pixel_height);
        p = s3_ssh3_encode_sshstring(p, req->u.pty.modes.data, req->u.pty.modes.len);
        break;

    case S3_SSH3_REQ_SHELL:
        break;

    case S3_SSH3_REQ_EXEC:
        p = s3_ssh3_encode_sshstring(p, req->u.exec.command.data, req->u.exec.command.len);
        break;

    case S3_SSH3_REQ_SUBSYSTEM:
        p = s3_ssh3_encode_sshstring(p, req->u.subsystem.name.data, req->u.subsystem.name.len);
        break;

    case S3_SSH3_REQ_WINDOW_CHANGE:
        p = s3_ssh3_encode_varint(p, req->u.window_change.width);
        p = s3_ssh3_encode_varint(p, req->u.window_change.height);
        p = s3_ssh3_encode_varint(p, req->u.window_change.pixel_width);
        p = s3_ssh3_encode_varint(p, req->u.window_change.pixel_height);
        break;

    case S3_SSH3_REQ_SIGNAL:
        p = s3_ssh3_encode_sshstring(p, req->u.signal.name.data, req->u.signal.name.len);
        break;

    case S3_SSH3_REQ_EXIT_STATUS:
        p = s3_ssh3_encode_varint(p, req->u.exit_status.status);
        break;

    case S3_SSH3_REQ_EXIT_SIGNAL:
        p = s3_ssh3_encode_sshstring(p, req->u.exit_signal.name.data, req->u.exit_signal.name.len);
        *p++ = req->u.exit_signal.core_dumped ? 1 : 0;
        p = s3_ssh3_encode_sshstring(p, req->u.exit_signal.error_message.data,
                                     req->u.exit_signal.error_message.len);
        p = s3_ssh3_encode_sshstring(p, req->u.exit_signal.language_tag.data,
                                     req->u.exit_signal.language_tag.len);
        break;

    case S3_SSH3_REQ_X11:
        *p++ = req->u.x11.single_connection ? 1 : 0;
        p = s3_ssh3_encode_sshstring(p, req->u.x11.auth_proto.data, req->u.x11.auth_proto.len);
        p = s3_ssh3_encode_sshstring(p, req->u.x11.cookie.data, req->u.x11.cookie.len);
        p = s3_ssh3_encode_varint(p, req->u.x11.screen);
        break;
    }

    return (uintptr_t)p;
}

s3_int_t
s3_ssh3_request_parse_body(const u_char **pos, const u_char *end, const s3_str_t *type,
                           s3_ssh3_request_t *req)
{
    s3_ssh3_request_kind_t kind;
    const u_char          *p;

    if (s3_ssh3_request_kind_of(type, &kind) != S3_OK) {
        return S3_DECLINED;
    }

    req->kind = kind;

    /* the cursor is committed only after the whole body has parsed */

    p = *pos;

    switch (kind) {

    case S3_SSH3_REQ_PTY:
        if (s3_ssh3_parse_sshstring(&p, end, &req->u.pty.term) != S3_OK ||
            s3_ssh3_parse_varint(&p, end, &req->u.pty.width) != S3_OK ||
            s3_ssh3_parse_varint(&p, end, &req->u.pty.height) != S3_OK ||
            s3_ssh3_parse_varint(&p, end, &req->u.pty.pixel_width) != S3_OK ||
            s3_ssh3_parse_varint(&p, end, &req->u.pty.pixel_height) != S3_OK ||
            s3_ssh3_parse_sshstring(&p, end, &req->u.pty.modes) != S3_OK) {
            return S3_ERROR;
        }

        break;

    case S3_SSH3_REQ_SHELL:
        break;

    case S3_SSH3_REQ_EXEC:
        if (s3_ssh3_parse_sshstring(&p, end, &req->u.exec.command) != S3_OK) {
            return S3_ERROR;
        }

        break;

    case S3_SSH3_REQ_SUBSYSTEM:
        if (s3_ssh3_parse_sshstring(&p, end, &req->u.subsystem.name) != S3_OK) {
            return S3_ERROR;
        }

        break;

    case S3_SSH3_REQ_WINDOW_CHANGE:
        if (s3_ssh3_parse_varint(&p, end, &req->u.window_change.width) != S3_OK ||
            s3_ssh3_parse_varint(&p, end, &req->u.window_change.height) != S3_OK ||
            s3_ssh3_parse_varint(&p, end, &req->u.window_change.pixel_width) != S3_OK ||
            s3_ssh3_parse_varint(&p, end, &req->u.window_change.pixel_height) != S3_OK) {
            return S3_ERROR;
        }

        break;

    case S3_SSH3_REQ_SIGNAL:
        if (s3_ssh3_parse_sshstring(&p, end, &req->u.signal.name) != S3_OK) {
            return S3_ERROR;
        }

        break;

    case S3_SSH3_REQ_EXIT_STATUS:
        if (s3_ssh3_parse_varint(&p, end, &req->u.exit_status.status) != S3_OK) {
            return S3_ERROR;
        }

        break;

    case S3_SSH3_REQ_EXIT_SIGNAL:
        if (s3_ssh3_parse_sshstring(&p, end, &req->u.exit_signal.name) != S3_OK || end - p < 1) {
            return S3_ERROR;
        }

        /* the boolean rides as one byte, any non-zero one is true */

        req->u.exit_signal.core_dumped = (*p++ != 0);

        if (s3_ssh3_parse_sshstring(&p, end, &req->u.exit_signal.error_message) != S3_OK ||
            s3_ssh3_parse_sshstring(&p, end, &req->u.exit_signal.language_tag) != S3_OK) {
            return S3_ERROR;
        }

        break;

    case S3_SSH3_REQ_X11:
        if (end - p < 1) {
            return S3_ERROR;
        }

        /* the boolean rides as one byte, any non-zero one is true */

        req->u.x11.single_connection = (*p++ != 0);

        if (s3_ssh3_parse_sshstring(&p, end, &req->u.x11.auth_proto) != S3_OK ||
            s3_ssh3_parse_sshstring(&p, end, &req->u.x11.cookie) != S3_OK ||
            s3_ssh3_parse_varint(&p, end, &req->u.x11.screen) != S3_OK) {
            return S3_ERROR;
        }

        break;
    }

    /* the body must be consumed to the last byte */

    if (p != end) {
        return S3_ERROR;
    }

    *pos = p;

    return S3_OK;
}
