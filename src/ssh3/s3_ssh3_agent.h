/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_SSH3_AGENT_H_INCLUDED_
#define _S3_SSH3_AGENT_H_INCLUDED_

#include <s3_core.h>

/*
 * the ssh-agent forwarding plumbing, the port of the reference
 * util/unix_util/agent.go (NewUnixSocketPath) plus the endpoint
 * halves of client/client.go (forwardAgent) and cmd/ssh3-server.go
 * (openAgentSocketAndForwardAgent): the module owns the unix domain
 * sockets only - the channel framing (the server-initiated
 * "agent-connection" channels and the 94 pumps over them) stays in
 * the caller, same split as s3_ssh3_session_srv
 *
 * the wire contract (docs/P4-WIRE.md 6, the reference flow): the
 * client writes the literal "forward-agent" data on the session
 * channel while it is LARVAL; the server creates the socket, quotes
 * it to the child as SSH_AUTH_SOCK and, per accepted connection,
 * opens one "agent-connection" channel towards the client; the
 * client, when forwarding was requested, dials its local
 * SSH_AUTH_SOCK and bridges the bytes both ways
 */

#define S3_SSH3_CHANNEL_TYPE_AGENT "agent-connection"
#define S3_SSH3_AGENT_TRIGGER      "forward-agent"

/* the opaque listener (the server half), defined in s3_ssh3_agent.c */

typedef struct s3_ssh3_agent_listener_s s3_ssh3_agent_listener_t;

/*
 * creates a fresh private directory under $TMPDIR (or /tmp) holding
 * the listening socket named agent.<pid> (the reference layout); the
 * socket path goes to path_out and the cleanup handler unlinks the
 * socket and removes the directory when the pool dies; the fd is
 * non-blocking
 *
 * S3_OK, S3_ERROR on the syscall failures (the path_out stays empty)
 */

s3_int_t s3_ssh3_agent_listen(s3_pool_t *pool, s3_ssh3_agent_listener_t **listener,
                              s3_str_t *path_out);

/* the listening fd of the listener (the caller polls it) */

int s3_ssh3_agent_listener_fd(const s3_ssh3_agent_listener_t *l);

/*
 * accepts one agent connection: the connected non-blocking fd, the
 * caller owns it and closes it; S3_AGAIN when nothing is pending,
 * S3_ERROR on a failed accept
 */

int s3_ssh3_agent_accept(s3_ssh3_agent_listener_t *l);

/*
 * the client half: dials the local agent at sock_path (the
 * SSH_AUTH_SOCK of the client machine, an SSHString view is fine);
 * the connected non-blocking fd, the caller owns it; S3_ERROR when
 * the variable is unset, the path is missing or the connect fails
 */

int s3_ssh3_agent_dial(s3_pool_t *pool, const s3_str_t *sock_path);

/*
 * closes one accepted or dialed fd and releases its nonblocking
 * state; -1 passes through silently
 */

void s3_ssh3_agent_close_fd(int fd);

#endif /* _S3_SSH3_AGENT_H_INCLUDED_ */
