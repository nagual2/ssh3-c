/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_SSH3_CM_H_INCLUDED_
#define _S3_SSH3_CM_H_INCLUDED_

#include <s3_core.h>

/*
 * the ControlMaster control channel, the port of the reference
 * client/cm (framing.go, messages.go, protocol.go) plus the server
 * loop of client/master.go: one versioned frame layer over the
 * control socket, the strict zero-copy payload decoders, the
 * measure-mode encoders and the two byte-level state machines
 *
 * the wire: the magic 'S3CM', the version 1, the type byte and the
 * big-endian payload length, one payload below 1 MiB; the scalars
 * are big-endian everywhere
 *
 * the master side is one s3_ssh3_cm_srv_t per connection; the
 * session table is shared by every connection of one master, so the
 * ATTACH frames arrive on their own connections and still find the
 * session opened over the control connection (the stderr stream
 * attaches before the io stream, like the reference)
 *
 * v0 scope: exec sessions only - the forward and interaction types
 * are declared for the shared dispatch but not parsed, and a pty
 * request (the flag byte 1 inside OPEN_SESSION) is a decode error
 *
 * nothing here touches a file descriptor: byte in, byte out, the
 * buffers grow in the caller's pool, the random tokens come from the
 * app through the open_session callback
 */

#define S3_SSH3_CM_VERSION    1
#define S3_SSH3_CM_MAX_FRAME  (1 << 20)
#define S3_SSH3_CM_HEADER_LEN 10
#define S3_SSH3_CM_TOKEN_LEN  16

/* the message types (framing.go MsgType) */

#define S3_SSH3_CM_MSG_HELLO            1
#define S3_SSH3_CM_MSG_OPEN_SESSION     2
#define S3_SSH3_CM_MSG_OPEN_FORWARD_TCP 3
#define S3_SSH3_CM_MSG_OPEN_FORWARD_UDP 4
#define S3_SSH3_CM_MSG_EXIT             5
#define S3_SSH3_CM_MSG_OK               6
#define S3_SSH3_CM_MSG_ERROR            7
#define S3_SSH3_CM_MSG_ATTACH           8
#define S3_SSH3_CM_MSG_EXIT_STATUS      9
#define S3_SSH3_CM_MSG_WINDOW_CHANGE    10
#define S3_SSH3_CM_MSG_SIGNAL           11
#define S3_SSH3_CM_MSG_CONTROL_OP       12

/* the stream kinds of ATTACH (messages.go StreamKind) */

#define S3_SSH3_CM_STREAM_IO     0
#define S3_SSH3_CM_STREAM_STDERR 1

/* the control op names (client/control.go) */

#define S3_SSH3_CM_OP_CHECK "check"
#define S3_SSH3_CM_OP_STOP  "stop"
#define S3_SSH3_CM_OP_EXIT  "exit"

/* the list caps of one OPEN_SESSION, the v0 decoder/encoder bound */

#define S3_SSH3_CM_LIST_MAX 64

typedef struct {
    uint8_t  type;
    s3_str_t payload; /* the view into the receive buffer */
} s3_ssh3_cm_frame_t;

/*
 * the OPEN_SESSION payload (messages.go OpenSession without the pty
 * arm of v0): both directions share the shape, the strings are views
 * into the payload on decode
 */

typedef struct {
    s3_str_t command[S3_SSH3_CM_LIST_MAX];
    uint32_t ncommand;
    s3_str_t env[S3_SSH3_CM_LIST_MAX];
    uint32_t nenv;
    unsigned forward_agent : 1;
} s3_ssh3_cm_open_session_t;

/* the check-op snapshot (client/control.go MasterStatus), the JSON
   reply payload; path stays app-owned and is read during the call */

typedef struct {
    const char *path;
    int         pid;
    int         protocol;
    double      uptime_s;
    int         sessions;
    int         forwards;
} s3_ssh3_cm_status_t;

/*
 * extracts one frame at *pos against end: on S3_OK the type and the
 * payload view are filled and *pos advances past the frame;
 * S3_AGAIN when the buffer ends inside a frame (the position stays,
 * the caller feeds the continuation and retries); S3_ERROR on a bad
 * magic, a version mismatch or a length above S3_SSH3_CM_MAX_FRAME,
 * the checks of the Go ReadFrame in the same order
 */

s3_int_t s3_ssh3_cm_frame(const u_char **pos, const u_char *end, s3_ssh3_cm_frame_t *f);

/*
 * the strict payload decoders: the views point into the body, the
 * truncation and (except the control op, like decodeControlOp) the
 * trailing bytes are S3_ERROR
 */

s3_int_t s3_ssh3_cm_decode_open_session(const s3_str_t *body, s3_ssh3_cm_open_session_t *req);

s3_int_t s3_ssh3_cm_decode_attach(const s3_str_t *body, u_char token[S3_SSH3_CM_TOKEN_LEN],
                                  uint8_t *kind);

s3_int_t s3_ssh3_cm_decode_exit_status(const s3_str_t *body, uint64_t *code);

s3_int_t s3_ssh3_cm_decode_control_op(const s3_str_t *body, s3_str_t *op);

/*
 * the encoders: written at p, the past-the-end pointer returned, or
 * the encoded size when p is NULL (the measure mode); the payload
 * and the destination must not overlap
 */

/* the whole frame: the header plus the payload (NULL means empty) */

uintptr_t s3_ssh3_cm_encode_frame(u_char *p, uint8_t type, const s3_str_t *payload);

/* the OPEN_SESSION payload: the lists, the pty flag 0, the agent */

uintptr_t s3_ssh3_cm_encode_open_session(u_char *p, const s3_ssh3_cm_open_session_t *req);

/* the ATTACH payload: the 16 token bytes plus the kind */

uintptr_t s3_ssh3_cm_encode_attach(u_char *p, const u_char token[S3_SSH3_CM_TOKEN_LEN],
                                   uint8_t kind);

/* the EXIT_STATUS payload, the 8-byte big-endian code */

uintptr_t s3_ssh3_cm_encode_exit_status(u_char *p, uint64_t code);

/* the CONTROL_OP payload: the uint32 length plus the op name */

uintptr_t s3_ssh3_cm_encode_control_op(u_char *p, const s3_str_t *op);

/* the check reply payload, the MasterStatus JSON of control.go */

uintptr_t s3_ssh3_cm_encode_status_json(u_char *p, const s3_ssh3_cm_status_t *st);

/*
 * the master side: the shared session table first, then one server
 * per connection
 */

#define S3_SSH3_CM_SRV_SESSIONS 16

typedef struct {
    u_char   token[S3_SSH3_CM_TOKEN_LEN];
    unsigned used : 1;
    unsigned stderr_attached : 1;
    unsigned started : 1;
} s3_ssh3_cm_sess_t;

typedef struct {
    s3_pool_t        *pool;
    s3_ssh3_cm_sess_t sessions[S3_SSH3_CM_SRV_SESSIONS];
    uint32_t          count;
} s3_ssh3_cm_sessions_t;

typedef struct {
    /*
     * the app opens the ssh3 session channel and generates the fresh
     * token; S3_ERROR refuses the session with *err (the default
     * text when NULL); the req views die when the callback returns
     */
    s3_int_t (*open_session)(void *ctx, const s3_ssh3_cm_open_session_t *req,
                             u_char token[S3_SSH3_CM_TOKEN_LEN], const char **err);

    /* the io attachment completed the session, the bridge starts;
       the master has already replied OK to the attach */
    void (*bridge)(void *ctx, const u_char token[S3_SSH3_CM_TOKEN_LEN]);

    /* the stderr attachment completed, the stderr bridge starts; the
       master has already replied OK to the attach */
    void (*bridge_stderr)(void *ctx, const u_char token[S3_SSH3_CM_TOKEN_LEN]);

    /* the check-op snapshot; S3_ERROR refuses the op */
    s3_int_t (*status)(void *ctx, s3_ssh3_cm_status_t *st);
} s3_ssh3_cm_srv_cbs_t;

typedef struct s3_ssh3_cm_srv_s s3_ssh3_cm_srv_t;

struct s3_ssh3_cm_srv_s {
    s3_pool_t             *pool;
    s3_ssh3_cm_sessions_t *sessions; /* shared by every connection */
    s3_ssh3_cm_srv_cbs_t   cbs;
    void                  *cb_ctx;

    /* the receive tail: the bytes of an incomplete frame */

    u_char *pend;
    size_t  pend_len;
    size_t  pend_cap;

    /* the pending replies, drained by output() */

    u_char *out;
    size_t  out_len;
    size_t  out_cap;

    unsigned hello_done : 1;
    unsigned done : 1;     /* the caller closes this connection */
    unsigned shutdown : 1; /* the master stops serving */
};

s3_int_t s3_ssh3_cm_sessions_init(s3_ssh3_cm_sessions_t *t, s3_pool_t *pool);

/*
 * releases the slot of the token: the whole slot clears and the count
 * drops, the slot is ready for reuse with no app-side cleanup;
 * S3_ERROR when no live slot matches the token
 */

s3_int_t s3_ssh3_cm_sessions_release(s3_ssh3_cm_sessions_t *t,
                                     const u_char           token[S3_SSH3_CM_TOKEN_LEN]);

/*
 * prepares one control or stream-attachment connection; the rules
 * of client/master.go handleMasterConn: the hello first, the open
 * session replies OK with the token, the stderr attach precedes the
 * io attach, the check op answers the status JSON, stop/exit and
 * the exit message signal the shutdown
 */

s3_int_t s3_ssh3_cm_srv_init(s3_ssh3_cm_srv_t *t, s3_pool_t *pool, s3_ssh3_cm_sessions_t *sessions,
                             const s3_ssh3_cm_srv_cbs_t *cbs, void *cb_ctx);

/*
 * feeds one received chunk; the frames are dispatched and the
 * replies appended to the output buffer; S3_OK including a partial
 * frame tail, S3_ERROR on an internal failure (the pool); after
 * done() the chunk bytes are ignored
 */

s3_int_t s3_ssh3_cm_srv_input(s3_ssh3_cm_srv_t *t, const u_char *data, size_t len);

/* drains the pending replies, 0 when nothing is pending */

ssize_t s3_ssh3_cm_srv_output(s3_ssh3_cm_srv_t *t, u_char *buf, size_t size);

/* the connection is finished: the caller closes it */

unsigned s3_ssh3_cm_srv_done(const s3_ssh3_cm_srv_t *t);

/* the master must stop serving (the stop/exit op, the exit message) */

unsigned s3_ssh3_cm_srv_shutdown(const s3_ssh3_cm_srv_t *t);

/*
 * the slave side: the strict serial Call of protocol.go - one
 * request frame out, one OK/Error reply back; the Call timeout is
 * the caller's event timer, the state machine only reports the
 * awaiting state through cli_reply() == S3_AGAIN
 */

typedef struct {
    s3_pool_t *pool;

    /* the receive tail: the bytes of an incomplete frame */

    u_char *pend;
    size_t  pend_len;
    size_t  pend_cap;

    /* the queued request frames, drained by output() */

    u_char *out;
    size_t  out_len;
    size_t  out_cap;

    /* the last reply payload, valid until the next call */

    u_char *reply;
    size_t  reply_len;
    size_t  reply_cap;

    unsigned awaiting : 1;
    unsigned has_reply : 1; /* a reply arrived since the last call */
    unsigned is_error : 1;  /* the reply was Error, the payload is the text */
    unsigned protocol_error : 1;
} s3_ssh3_cm_cli_t;

s3_int_t s3_ssh3_cm_cli_init(s3_ssh3_cm_cli_t *t, s3_pool_t *pool);

/*
 * queues the request frame (the handshake is the hello call with the
 * empty payload); one call at a time, S3_ERROR while awaiting
 */

s3_int_t s3_ssh3_cm_cli_call(s3_ssh3_cm_cli_t *t, uint8_t type, const s3_str_t *payload);

/*
 * feeds one received chunk; the first whole frame is the reply (OK
 * or Error), an unsolicited or non-reply frame is a protocol
 * violation; S3_OK including a partial tail, S3_ERROR on an
 * internal failure
 */

s3_int_t s3_ssh3_cm_cli_input(s3_ssh3_cm_cli_t *t, const u_char *data, size_t len);

/* drains the queued request frames, 0 when nothing is pending */

ssize_t s3_ssh3_cm_cli_output(s3_ssh3_cm_cli_t *t, u_char *buf, size_t size);

/*
 * S3_OK fills the reply view (the OK payload or the error text) and
 * is_error; S3_AGAIN while the reply has not arrived; S3_ERROR
 * after a protocol violation
 */

s3_int_t s3_ssh3_cm_cli_reply(s3_ssh3_cm_cli_t *t, s3_str_t *payload, unsigned *is_error);

/* the protocol violation verdict: the caller closes the connection */

unsigned s3_ssh3_cm_cli_protocol_error(const s3_ssh3_cm_cli_t *t);

#endif /* _S3_SSH3_CM_H_INCLUDED_ */
