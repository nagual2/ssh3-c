/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the client-side session of an ssh3 channel, the pump side of the
 * reference client/session_pump.go (docs/P4-WIRE.md 6): the module
 * consumes the channel bytes through the caller-installed sinks, the
 * framing stays in the channel layer
 *
 * the receive side accumulates the chunks in the pending buffer and
 * parses the whole messages out of it: the 91 confirmation must come
 * first, the 94/95 payloads land in the sinks, the 98 exit-status
 * records the verdict; the partial tail waits for the next chunk
 *
 * the strict pin of the reference: the server sends exactly one
 * exit-status request and pipes the stderr only, anything else can
 * not be bounded on the wire and is a protocol error here; one error
 * ends the session, the state is not required to recover after it
 */

/*
 * the BSD terminal surface of this module: cfmakeraw() rides behind
 * __USE_MISC, the winsize ioctl behind the kernel ioctls; the
 * definition lives in the file so only this TU pays for the extra
 * surface (the session_srv pattern)
 */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif

#include <s3_core.h>

#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#include <s3_ssh3_message.h>
#include <s3_ssh3_request.h>
#include <s3_ssh3_session_cli.h>
#include <s3_ssh3_wire.h>

/* the initial pending capacity, doubled on demand */

#define S3_SSH3_SESSION_CLI_PEND_INIT 4096

s3_int_t
s3_ssh3_session_cli_init(s3_ssh3_session_cli_t *s, s3_pool_t *pool, s3_ssh3_session_cli_sink_pt out,
                         void *out_arg, s3_ssh3_session_cli_sink_pt err, void *err_arg,
                         s3_ssh3_session_cli_exit_pt exit_cb, void *exit_arg)
{
    s3_memzero(s, sizeof(s3_ssh3_session_cli_t));

    s->pool = pool;

    /* the NULL sinks drop the payloads of their sides, the NULL exit
     * callback keeps the verdict readable through exit_code() */

    s->out = out;
    s->out_arg = out_arg;

    s->err = err;
    s->err_arg = err_arg;

    s->exit_cb = exit_cb;
    s->exit_arg = exit_arg;

    return S3_OK;
}

/*
 * appends the chunk to the pending buffer, growing it by doubling
 * from one page; the grown copies are pool memory and die with the
 * pool - nginx pfree does not return the pool blocks, freeing the
 * small buffers is not worth the bookkeeping
 */

static s3_int_t
s3_ssh3_session_cli_pend_append(s3_ssh3_session_cli_t *s, const u_char *data, size_t len)
{
    u_char *p;
    size_t  cap;

    if (len == 0) {
        return S3_OK;
    }

    cap = s->pend_cap ? s->pend_cap : S3_SSH3_SESSION_CLI_PEND_INIT;

    while (cap - s->pend_len < len) {

        if (cap > SIZE_MAX / 2) {
            return S3_ERROR;
        }

        cap *= 2;
    }

    if (cap != s->pend_cap) {
        p = s3_pnalloc(s->pool, cap);

        if (p == NULL) {
            return S3_ERROR;
        }

        if (s->pend_len > 0) {
            s3_memcpy(p, s->pend, s->pend_len);
        }

        s->pend = p;
        s->pend_cap = cap;
    }

    s3_memcpy(s->pend + s->pend_len, data, len);
    s->pend_len += len;

    return S3_OK;
}

s3_int_t
s3_ssh3_session_cli_input(s3_ssh3_session_cli_t *s, const u_char *data, size_t len)
{
    s3_ssh3_msg_request_t  req;
    s3_ssh3_request_kind_t kind;
    const u_char          *msg, *p, *end;
    s3_str_t               payload;
    uint64_t               type, value;

    if (s3_ssh3_session_cli_pend_append(s, data, len) != S3_OK) {
        return S3_ERROR;
    }

    p = s->pend;
    end = s->pend + s->pend_len;

    while (p < end) {

        /* the start of the message being parsed, the partial tail
         * rewinds here */

        msg = p;

        if (s3_ssh3_parse_varint(&p, end, &type) != S3_OK) {
            goto partial;
        }

        /* the session opens with the 91, nothing rides before it */

        if (!s->confirmed && type != S3_SSH3_MSG_CHANNEL_OPEN_CONFIRMATION) {
            return S3_ERROR;
        }

        switch (type) {

        case S3_SSH3_MSG_CHANNEL_OPEN_CONFIRMATION:

            /* the maxPacketSize is read and ignored: the flow
             * control stays in the channel layer */

            if (s3_ssh3_parse_varint(&p, end, &value) != S3_OK) {
                goto partial;
            }

            s->confirmed = 1;
            break;

        case S3_SSH3_MSG_CHANNEL_DATA:

            if (s3_ssh3_parse_sshstring(&p, end, &payload) != S3_OK) {
                goto partial;
            }

            if (s->out != NULL) {
                s->out(s->out_arg, &payload);
            }

            break;

        case S3_SSH3_MSG_CHANNEL_EXTENDED_DATA:

            if (s3_ssh3_parse_varint(&p, end, &value) != S3_OK) {
                goto partial;
            }

            /* the pin: the server pipes the stderr only */

            if (value != S3_SSH3_EXTENDED_DATA_STDERR) {
                return S3_ERROR;
            }

            if (s3_ssh3_parse_sshstring(&p, end, &payload) != S3_OK) {
                goto partial;
            }

            if (s->err != NULL) {
                s->err(s->err_arg, &payload);
            }

            break;

        case S3_SSH3_MSG_CHANNEL_REQUEST:

            /* the envelope lands the cursor on the first body byte */

            if (s3_ssh3_msg_parse_request_envelope(&p, end, &req) != S3_OK) {
                goto partial;
            }

            /* the pin: only the exit-status is bounded on the wire,
             * any other request can not be parsed safely */

            if (s3_ssh3_request_kind_of(&req.request_type, &kind) != S3_OK ||
                kind != S3_SSH3_REQ_EXIT_STATUS) {
                return S3_ERROR;
            }

            if (s3_ssh3_parse_varint(&p, end, &value) != S3_OK) {
                goto partial;
            }

            /* the first exit-status wins, the repeats drop silently:
             * the output tail may still follow before the FIN */

            if (!s->exited) {
                s->exited = 1;
                s->exit_code = value;

                if (s->exit_cb != NULL) {
                    s->exit_cb(s->exit_arg, value);
                }
            }

            break;

        default:

            /* an unknown type can not be bounded on the wire: the
             * parser must not hang on it, the session is over */

            return S3_ERROR;
        }
    }

    /* every byte parsed: the pending buffer drains */

    s->pend_len = 0;

    return S3_OK;

partial:

    /* the tail of the last incomplete message waits in the buffer
     * for the next chunk */

    s->pend_len = (size_t)(end - msg);

    if (msg != s->pend) {
        s3_memmove(s->pend, msg, s->pend_len);
    }

    return S3_OK;
}

uint64_t
s3_ssh3_session_cli_exit_code(const s3_ssh3_session_cli_t *s)
{
    return s->exit_code;
}

/*
 * the raw mode of the session lifetime: the previous state lands in
 * *saved for tty_restore(), the S3_DECLINED when the fd is not a tty
 */

s3_int_t
s3_ssh3_session_cli_tty_raw(int fd, struct termios *saved)
{
    struct termios t;

    if (!isatty(fd)) {
        return S3_DECLINED;
    }

    if (tcgetattr(fd, &t) != 0) {
        return S3_ERROR;
    }

    if (saved != NULL) {
        *saved = t;
    }

    cfmakeraw(&t);

    if (tcsetattr(fd, TCSANOW, &t) != 0) {
        return S3_ERROR;
    }

    return S3_OK;
}

/* the saved state back: the non-tty fd declines like tty_raw() */

s3_int_t
s3_ssh3_session_cli_tty_restore(int fd, const struct termios *saved)
{
    if (!isatty(fd)) {
        return S3_DECLINED;
    }

    if (tcsetattr(fd, TCSANOW, saved) != 0) {
        return S3_ERROR;
    }

    return S3_OK;
}

/* the window size for the window-change requests, the columns into
 * *width and the rows into *height */

s3_int_t
s3_ssh3_session_cli_tty_winsize(int fd, uint64_t *width, uint64_t *height)
{
    struct winsize ws;

    if (!isatty(fd)) {
        return S3_DECLINED;
    }

    if (ioctl(fd, TIOCGWINSZ, &ws) != 0) {
        return S3_ERROR;
    }

    if (width != NULL) {
        *width = ws.ws_col;
    }

    if (height != NULL) {
        *height = ws.ws_row;
    }

    return S3_OK;
}
