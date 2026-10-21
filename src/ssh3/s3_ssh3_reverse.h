/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_SSH3_REVERSE_H_INCLUDED_
#define _S3_SSH3_REVERSE_H_INCLUDED_

#include <s3_base.h>

#include <s3_ssh3_forward.h>

/*
 * the reverse port forwarding (-R), the port of the reference
 * cmd/reverse_forward.go and message/reverse_forward.go: the client
 * opens one "reverse-forward" control channel per -R spec towards the
 * server and sends the bind request as its channel data; the server
 * binds the port (the permit-listen gate first), answers with the
 * bound port or the reason, and mirrors every accepted connection or
 * datagram back as a server-initiated "forwarded-tcp"/"forwarded-udp"
 * channel whose header extension carries the client-side target (the
 * same extension the direct-* channels ride, s3_ssh3_forward)
 *
 * the request and the reply travel as channel data, not as new
 * message-type ids: an older server treats the control channel as an
 * unknown session channel, refuses the unexpected data in its LARVAL
 * state and closes the channel, which surfaces on the client as a
 * graceful "unsupported by the server" refusal instead of a parse
 * panic on an unknown id
 */

/* the forwarding protocol numbers of the reference util/types.go */

#define S3_SSH3_REVERSE_PROTO_UDP 0
#define S3_SSH3_REVERSE_PROTO_TCP 1

/* the host text bounds of the spec (the dns name and the literal) */

#define S3_SSH3_REVERSE_HOST_MAX 255

/*
 * one parsed -R specification: the server binds bind_host:bind_port
 * (the empty host is the server loopback default, the "*" form maps
 * to the "::" wildcard here, like the reference parser) and forwards
 * to target_host:target_port, resolved on the client
 */

typedef struct {
    unsigned proto; /* S3_SSH3_REVERSE_PROTO_TCP or UDP */
    char     bind_host[S3_SSH3_REVERSE_HOST_MAX + 1];
    uint16_t bind_port; /* 0 asks the ephemeral bind of the server */
    char     target_host[S3_SSH3_REVERSE_HOST_MAX + 1];
    uint16_t target_port;
} s3_ssh3_reverse_spec_t;

/*
 * parses one -R specification, the reference shape
 * [bind_address:]bind_port[/tcp|/udp]:target_host:target_port; the
 * parts split on the colons outside the ipv6 brackets, the "*" bind
 * maps to "::"; the bind port may be 0 (the ephemeral bind), the
 * target host and port must not be empty or 0; the host texts carry
 * the printable characters only (the bind address rides the wire and
 * the server logs it as it stands)
 *
 * S3_OK fills the spec; S3_ERROR leaves it unspecified
 */

s3_int_t s3_ssh3_reverse_parse_spec(const char *text, s3_ssh3_reverse_spec_t *out);

/*
 * resolves the target of the spec locally, like the reference client
 * (the -R target resolves where the client runs): an ip literal comes
 * straight from inet_pton (an ipv6 literal answers the family 6), a
 * name rides getaddrinfo over AF_INET (the ipv4 canon of the direct
 * forward path); the canonical family/ip/port triple lands in the
 * direct-channel target shape, the channel headers and the local
 * sockets both take it
 *
 * the caller owns the family policy: the reverse bridge dials the
 * ipv4 targets only, so a family 6 result is a refusal for the
 * caller (the client refuses the spec before the request is sent)
 *
 * S3_OK fills the target; S3_ERROR leaves it unspecified
 */

s3_int_t s3_ssh3_reverse_resolve_target(const s3_ssh3_reverse_spec_t *spec,
                                        s3_ssh3_forward_target_t     *target);

/*
 * the bind request the client sends as the channel data of the
 * control channel; the strings are the wire texts, the bind address
 * is the spec host as the client spelled it ("" and "::" ride
 * verbatim), the target address is the canonical text of the
 * resolved target
 */

typedef struct {
    unsigned proto;
    s3_str_t bind_address;
    uint16_t bind_port;
    s3_str_t target_address;
    uint16_t target_port;
} s3_ssh3_reverse_request_t;

/* the encoded size of the request */

size_t s3_ssh3_reverse_request_size(const s3_ssh3_reverse_request_t *r);

/*
 * writes the request at p, returns the past-the-end pointer, NULL
 * when p does not carry the size above (caller bug)
 */

u_char *s3_ssh3_reverse_build_request(u_char *p, const s3_ssh3_reverse_request_t *r);

/*
 * parses one request at *pos against end; the string fields come back
 * as the zero-copy views into the receive buffer and *pos advances
 * past the request; an unknown protocol number, a truncated buffer
 * leaves *pos untouched and returns S3_ERROR
 */

s3_int_t s3_ssh3_reverse_parse_request(const u_char **pos, const u_char *end,
                                       s3_ssh3_reverse_request_t *out);

/*
 * the bind result the server answers on the control channel: the
 * empty error string means the bind succeeded (bound_port is the
 * actual bound port, which differs from the requested one when the
 * client asked for the ephemeral 0), otherwise it carries the
 * human-readable reason (the busy port, the policy refusal)
 */

typedef struct {
    uint16_t bound_port;
    s3_str_t error_utf8;
} s3_ssh3_reverse_reply_t;

/* the encoded size of the reply */

size_t s3_ssh3_reverse_reply_size(const s3_ssh3_reverse_reply_t *r);

/*
 * writes the reply at p, returns the past-the-end pointer, NULL when
 * p does not carry the size above (caller bug)
 */

u_char *s3_ssh3_reverse_build_reply(u_char *p, const s3_ssh3_reverse_reply_t *r);

/*
 * parses one reply at *pos against end; the error view points into
 * the receive buffer and *pos advances past the reply; a truncated
 * buffer leaves *pos untouched and returns S3_ERROR
 */

s3_int_t s3_ssh3_reverse_parse_reply(const u_char **pos, const u_char *end,
                                     s3_ssh3_reverse_reply_t *out);

/*
 * the success shape of the reply (the empty error string)
 */

unsigned s3_ssh3_reverse_reply_ok(const s3_ssh3_reverse_reply_t *r);

/*
 * the canonical text of a resolved target (the inet_ntop form, the
 * wire text of the bind request target address): S3_OK writes the
 * terminator, S3_ERROR when the family is unknown or buf is too
 * small
 */

s3_int_t s3_ssh3_reverse_target_ntop(const s3_ssh3_forward_target_t *t, char *buf, size_t len);

#endif /* _S3_SSH3_REVERSE_H_INCLUDED_ */
