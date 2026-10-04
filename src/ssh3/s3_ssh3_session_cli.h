/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_SSH3_SESSION_CLI_H_INCLUDED_
#define _S3_SSH3_SESSION_CLI_H_INCLUDED_

#include <s3_base.h>

#include <stdio.h>

/* the terminal state of the tty helpers, defined in <termios.h> */

struct termios;

/*
 * the client-side session of an ssh3 channel, the pump side of the
 * reference client/session_pump.go: the module consumes the channel
 * bytes (the 91 confirmation, the 94/95 payloads, the 98 exit-status)
 * through the caller-installed sinks and leaves the local terminal
 * handling to the tty helpers - the framing stays in the channel layer
 *
 * the protocol pin (docs/P4-WIRE.md 6): the server sends exactly one
 * 98 exit-status and no other request; an unknown server request can
 * not be bounded on the wire and is a protocol error here, the
 * reference would panic on it instead
 */

typedef struct s3_ssh3_session_cli_s s3_ssh3_session_cli_t;

typedef void (*s3_ssh3_session_cli_sink_pt)(void *arg, const s3_str_t *data);

typedef void (*s3_ssh3_session_cli_exit_pt)(void *arg, uint64_t code);

struct s3_ssh3_session_cli_s {
    s3_pool_t *pool;

    unsigned confirmed; /* the 91 seen */
    unsigned exited;    /* the first exit-status won, the rest drop */
    uint64_t exit_code; /* the verdict of the winning exit-status */

    s3_ssh3_session_cli_sink_pt out;
    void                       *out_arg;

    s3_ssh3_session_cli_sink_pt err;
    void                       *err_arg;

    s3_ssh3_session_cli_exit_pt exit_cb;
    void                       *exit_arg;

    /* the partial tail of the last received chunk */

    u_char *pend;
    size_t  pend_len;
    size_t  pend_cap;
};

/*
 * the sinks must be installed before the first input(); NULL stdout
 * or stderr sink drops the payload of that side, a NULL exit callback
 * keeps the code readable through s.exit_code
 */

s3_int_t s3_ssh3_session_cli_init(s3_ssh3_session_cli_t *s, s3_pool_t *pool,
                                  s3_ssh3_session_cli_sink_pt out, void *out_arg,
                                  s3_ssh3_session_cli_sink_pt err, void *err_arg,
                                  s3_ssh3_session_cli_exit_pt exit_cb, void *exit_arg);

/*
 * feeds one received chunk; partial messages wait inside, the grown
 * pending buffer dies with the pool; S3_OK even on a partial tail,
 * S3_ERROR on a protocol violation (an unknown message type, a server
 * request other than exit-status, a 95 with a dataType other than 1)
 */

s3_int_t s3_ssh3_session_cli_input(s3_ssh3_session_cli_t *s, const u_char *data, size_t len);

/* the exit verdict of the exit-status, 0 until the callback ran */

uint64_t s3_ssh3_session_cli_exit_code(const s3_ssh3_session_cli_t *s);

/*
 * the local terminal helpers: raw mode for the session lifetime, the
 * window size for the window-change requests; S3_DECLINED when the fd
 * is not a tty (the tests and the pipe mode)
 */

s3_int_t s3_ssh3_session_cli_tty_raw(int fd, struct termios *saved);

s3_int_t s3_ssh3_session_cli_tty_restore(int fd, const struct termios *saved);

s3_int_t s3_ssh3_session_cli_tty_winsize(int fd, uint64_t *width, uint64_t *height);

#endif /* _S3_SSH3_SESSION_CLI_H_INCLUDED_ */
