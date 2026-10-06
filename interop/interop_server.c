/*
 * Copyright (C) 2026 the ssh3-c authors
 */

/*
 * the QUIC interop echo server: the standalone shape of the D3 e2e
 * test over a real UDP listener.  Peers: the quic-go harness
 * (interop/quic-go) and, at P3, the ssh3 client of the Go fork.
 *
 * stdout carries the machine-readable protocol of the runner:
 *   INTEROP-LISTEN port=N
 *   INTEROP-HANDSHAKE-OK
 * every received DATAGRAM is echoed back
 *
 * the -3 switch switches to the h3 mode (RFC 9220 extended CONNECT,
 * the ssh3 route): the uni streams are handed to the session port
 * (s3_h3_init_stream()), the first bidi stream runs the extended
 * CONNECT validator below and every later bidi stream is an ssh3
 * channel: the header is checked, 91 goes back and the channel
 * carries either the 94 echo or the server session (docs/P4-WIRE.md
 * 6) - the requests spawn a process through s3_ssh3_session_srv, the
 * process output rides back as 94/95 and the verdict is the 98
 * exit-status.  In this mode stdout additionally carries:
 *   INTEROP-H3-CONNECT-OK authlen=<len>
 *   INTEROP-AUTH-OK user=<name>  (the -P password or -K pubkey mode)
 *   INTEROP-H3-REJECT code=<400|401|403|425>
 *   INTEROP-CHANNEL-ACCEPT id=<stream id> type=<channel type>
 *   INTEROP-SESSION-PTY
 *   INTEROP-SESSION-SHELL
 *   INTEROP-SESSION-EXEC
 *   INTEROP-SESSION-EXIT code=<code>
 * the direct-tcp / direct-udp channels (docs/P4-WIRE.md 2.1, the
 * target extension rides the header) relay the traffic to the target
 * on the server side:
 *   INTEROP-FWD-TCP-OPEN target=IP:PORT
 *   INTEROP-FWD-UDP-OPEN target=IP:PORT
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <openssl/rand.h>

#include <s3_h3.h>
#include <s3_h3_uni.h>
#include <s3_nonblocking.h>
#include <s3_quic.h>
#include <s3_quic_connection.h>
#include <s3_quic_output.h>
#include <s3_quic_streams.h>
#include <s3_ssh3_agent.h>
#include <s3_ssh3_auth_jwt.h>
#include <s3_ssh3_auth_srv.h>
#include <s3_ssh3_channel.h>
#include <s3_ssh3_dgram.h>
#include <s3_ssh3_forward.h>
#include <s3_ssh3_message.h>
#include <s3_ssh3_oidc.h>
#include <s3_ssh3_request.h>
#include <s3_ssh3_session_srv.h>
#include <s3_ssh3_sftp_srv.h>
#include <s3_ssh3_version.h>
#include <s3_ssh3_wire.h>
#include <s3_ssl.h>

#define S3_INTEROP_TRACKED 64

/*
 * the channel maxPacketSize of the reference, 30000 on both sides
 * (docs/P4-WIRE.md 5); it caps what a peer may put into one 94
 */
#define S3_INTEROP_CHANNEL_MAX_PACKET 30000

static s3_log_t s3_interop_log;

static s3_quic_conf_t s3_interop_conf;

/* the accepted connections watched for the handshake completion */
static s3_connection_t *s3_interop_conns[S3_INTEROP_TRACKED];
static unsigned         s3_interop_reported[S3_INTEROP_TRACKED];
static unsigned         s3_interop_idle_reported[S3_INTEROP_TRACKED];
static s3_uint_t        s3_interop_nconns;

/* the h3 mode (-3): RFC 9220 extended CONNECT instead of the echo */
static unsigned s3_interop_h3_mode;

/*
 * the password file (-P): the CONNECT passes only with the correct
 * Basic credentials against its user:secret lines
 */
static const char *s3_interop_passfile;

/*
 * the authorized_keys file (-K): the CONNECT passes only with a
 * Bearer JWT signed by one of its keys; a %u token is the session
 * username (the sshd AuthorizedKeysFile shape), a path without it is
 * one file for every user
 */
static const char *s3_interop_keyfile;

/*
 * the synthetic 0-RTT probe (S3_H3_FORCE_EARLY): no shipped client
 * sends TLS 0-RTT early data yet (the server never advertises
 * max_early_data, the session resumption is not wired), so the RFC
 * 8470 425 gate has no natural trigger.  The env drives the gate
 * once — the first CONNECT draws the 425 and the retry after the
 * handshake lands on the normal chain, the e2e covers the verdict
 * shape and the client-side 425 handling
 */
static int s3_interop_force_early;

/*
 * the sftp jail override (-H): the harness scenarios point it into
 * their workdir so the runs do not touch the real home
 */
static char s3_interop_sftp_home[512];

/*
 * the OIDC issuer mode (--oidc-issuer): the CONNECT passes only with
 * the Bearer id_token of that provider, the audience is the client
 * id of the token, the nonce binds the token to the conversation
 * (the reference authorized_identities OpenIDConnectIdentity); the
 * verifier inits once at the startup, the first token bootstraps the
 * discovery and the key set (the harness keeps the lazy bootstrap),
 * the rotation and the unknown-kid refetch ride the timer below
 */
static const char             *s3_interop_oidc_issuer;
static char                    s3_interop_oidc_aud[128];
static time_t                  s3_interop_oidc_ttl;
static s3_ssh3_oidc_verifier_t s3_interop_oidc_ver;
static s3_event_t              s3_interop_oidc_timer;

static void
s3_interop_log_init(void)
{
    s3_interop_log.log_level = S3_LOG_INFO;
    s3_interop_log.fd = S3_INVALID_FILE;
}

static u_char *
s3_interop_read_file(const char *path, size_t *len)
{
    FILE   *f;
    u_char *buf;
    long    n;

    f = fopen(path, "rb");
    if (f == NULL) {
        fprintf(stderr, "interop-server: cannot open %s\n", path);
        return NULL;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }

    n = ftell(f);

    if (n <= 0 || n > 1024 * 1024) {
        fclose(f);
        return NULL;
    }

    rewind(f);

    buf = malloc((size_t)n + 1);
    if (buf == NULL) {
        fclose(f);
        return NULL;
    }

    if (fread(buf, 1, (size_t)n, f) != (size_t)n) {
        fclose(f);
        free(buf);
        return NULL;
    }

    fclose(f);

    /* convenience for text consumers, BIO_new_mem_buf() needs no NUL */
    buf[n] = '\0';
    *len = (size_t)n;

    return buf;
}

static s3_int_t
s3_interop_parse_addr(const char *text, struct sockaddr_in *sa)
{
    char           host[64];
    const char    *colon;
    size_t         n;
    unsigned       port;
    struct in_addr addr;

    colon = strchr(text, ':');
    if (colon == NULL) {
        return S3_ERROR;
    }

    n = (size_t)(colon - text);
    if (n == 0 || n >= sizeof(host)) {
        return S3_ERROR;
    }

    memcpy(host, text, n);
    host[n] = '\0';

    if (inet_pton(AF_INET, host, &addr) != 1) {
        return S3_ERROR;
    }

    port = (unsigned)atoi(colon + 1);
    if (port > 65535) {
        return S3_ERROR;
    }

    s3_memzero(sa, sizeof(struct sockaddr_in));

    sa->sin_family = AF_INET;
    sa->sin_port = htons((uint16_t)port);
    sa->sin_addr = addr;

    return S3_OK;
}

static void
s3_interop_alpn_wire(u_char *wire, const char *name)
{
    size_t n;

    n = strlen(name);

    if (n == 0 || n > 255) {
        fprintf(stderr, "interop-server: bad alpn name\n");
        exit(1);
    }

    wire[0] = (u_char)n;
    memcpy(wire + 1, name, n);
}

/*
 * the h3 channel, see the table below; the forward declaration lets
 * the datagram handler hold the direct-udp singleton
 */

typedef struct s3_interop_h3_channel_s s3_interop_h3_channel_t;

/*
 * the open direct-udp forward channel: the harness simplification,
 * one channel at a time, the datagram handler routes by its ids; NULL
 * when no direct-udp channel is open
 */
static s3_interop_h3_channel_t *s3_interop_h3_udp_fwd;

/* the forward branch lives below the channel table */

static void s3_interop_udp_fwd_datagram(s3_connection_t *c, const u_char *buf, size_t len);

static void
s3_interop_datagram_echo(s3_connection_t *c, s3_chain_t *data)
{
    u_char     *buf;
    size_t      len;
    s3_chain_t *cl;

    if (s3_interop_h3_udp_fwd != NULL) {

        /*
         * the direct-udp channel owns the datagrams prefixed with its
         * ids (docs/P4-WIRE.md 3.2), the rest falls through to the
         * plain echo; the flatten below is the rare fragmented path
         */
        len = 0;

        for (cl = data; cl != NULL; cl = cl->next) {
            len += s3_buf_size(cl->buf);
        }

        buf = s3_palloc(c->pool, len);

        if (buf != NULL) {

            u_char *p = buf;

            for (cl = data; cl != NULL; cl = cl->next) {
                p = s3_cpymem(p, cl->buf->pos, s3_buf_size(cl->buf));
            }

            s3_interop_udp_fwd_datagram(c, buf, len);

            (void)s3_pfree(c->pool, buf);
        }

        return;
    }

    /*
     * a datagram almost always lands in a single link of the receive
     * buffer: echo it straight from there, no intermediate block
     */

    if (data->next == NULL) {
        (void)s3_quic_send_datagram(c, data->buf->pos, s3_buf_size(data->buf));
        return;
    }

    /* a fragmented datagram: flatten it once, into the connection pool */

    len = 0;

    for (cl = data; cl != NULL; cl = cl->next) {
        len += s3_buf_size(cl->buf);
    }

    buf = s3_palloc(c->pool, len);
    if (buf == NULL) {
        return;
    }

    {
        u_char *p = buf;

        for (cl = data; cl != NULL; cl = cl->next) {
            p = s3_cpymem(p, cl->buf->pos, s3_buf_size(cl->buf));
        }
    }

    (void)s3_quic_send_datagram(c, buf, len);

    (void)s3_pfree(c->pool, buf);
}

/*
 * the stream echo: every accepted bidi stream reads until the peer
 * half-closes and sends the bytes back.  The send window of the
 * stream is a 16 KiB quantum, so the echo keeps a pending tail and
 * flushes it on the write events the library posts when the peer
 * opens the window (MAX_STREAM_DATA)
 */

/*
 * the pending tail is a heap buffer on purpose: the echo must keep
 * draining the peer no matter how far its read side lags behind our
 * send window, otherwise the two naive sides deadlock.  The consumed
 * head advances in place and the remainder compacts only when the
 * compaction reclaims at least what it moves: with the flow control
 * quanta of a large window the drain runs at a few tens of KiB per
 * wakeup, and a memmove of the whole tail per wakeup made every event
 * quadratic in the backlog, freezing the whole loop for seconds
 */
static u_char          *s3_interop_echo_buf;
static size_t           s3_interop_echo_cap;
static size_t           s3_interop_echo_off;
static size_t           s3_interop_echo_len;
static int              s3_interop_echo_fin;
static size_t           s3_interop_echo_read_total;
static int              s3_interop_echo_reads;
static s3_connection_t *s3_interop_echo_sc;

static void
s3_interop_stream_flush(void)
{
    s3_connection_t *sc = s3_interop_echo_sc;
    ssize_t          m;

    while (s3_interop_echo_len > 0) {

        m = s3_quic_stream_send(sc, s3_interop_echo_buf + s3_interop_echo_off, s3_interop_echo_len);

        if (m == (ssize_t)S3_AGAIN) {
            return;
        }

        if (m <= 0) {
            fprintf(stderr, "interop-server: stream send failed\n");
            s3_interop_echo_len = 0;
            s3_interop_echo_off = 0;
            return;
        }

        s3_interop_echo_off += (size_t)m;
        s3_interop_echo_len -= (size_t)m;
    }

    s3_interop_echo_off = 0;

    if (s3_interop_echo_fin) {
        (void)s3_quic_shutdown_stream(sc, S3_WRITE_SHUTDOWN);
    }
}

static void
s3_interop_stream_write(s3_event_t *ev)
{
    (void)ev;

    s3_interop_stream_flush();
}

static void
s3_interop_stream_read(s3_event_t *ev)
{
    s3_connection_t *sc;
    size_t           free_len;
    ssize_t          n, m;

    sc = ev->data;

    s3_interop_echo_reads++;

    for (;;) {

        free_len = s3_interop_echo_cap - s3_interop_echo_off - s3_interop_echo_len;

        if (free_len == 0) {

            /*
             * the compaction must reclaim at least what it moves, or the
             * drain degenerates back into a quadratic shuffle; a shallow
             * head with a deep tail grows the buffer instead, and the
             * cold start (cap == 0) always lands on the growth
             */
            if (s3_interop_echo_off > 0 && s3_interop_echo_off >= s3_interop_echo_len) {

                s3_memmove(s3_interop_echo_buf, s3_interop_echo_buf + s3_interop_echo_off,
                           s3_interop_echo_len);
                s3_interop_echo_off = 0;
                free_len = s3_interop_echo_cap - s3_interop_echo_len;
            }

            if (free_len == 0) {
                size_t  cap = s3_interop_echo_cap + 262144;
                u_char *grown = realloc(s3_interop_echo_buf, cap);

                if (grown == NULL) {
                    fprintf(stderr, "interop-server: echo buffer growth failed\n");
                    exit(1);
                }

                s3_interop_echo_buf = grown;
                s3_interop_echo_cap = cap;
                free_len = cap - s3_interop_echo_off - s3_interop_echo_len;
            }
        }

        n = sc->recv(sc, s3_interop_echo_buf + s3_interop_echo_off + s3_interop_echo_len, free_len);

        if (n > 0) {
            s3_interop_echo_read_total += (size_t)n;
        }

        if (n == (ssize_t)S3_AGAIN || n < 0) {
            break;
        }

        if (n == 0) {
            /* the peer fin: the echo completes after the tail drains */
            s3_interop_echo_fin = 1;
            break;
        }

        s3_interop_echo_len += (size_t)n;

        m = s3_quic_stream_send(sc, s3_interop_echo_buf + s3_interop_echo_off, s3_interop_echo_len);

        if (m == (ssize_t)S3_AGAIN) {
            continue; /* the window is full, the tail flushes on wev */
        }

        if (m <= 0) {
            fprintf(stderr, "interop-server: stream send failed\n");
            s3_interop_echo_len = 0;
            s3_interop_echo_off = 0;
            break;
        }

        s3_interop_echo_off += (size_t)m;
        s3_interop_echo_len -= (size_t)m;
    }

    if (s3_interop_echo_fin && s3_interop_echo_len == 0) {
        s3_interop_echo_off = 0;
        (void)s3_quic_shutdown_stream(sc, S3_WRITE_SHUTDOWN);
    }
}

/*
 * the h3 request side (-3): one bidi stream carries the RFC 9220
 * extended CONNECT, the uni streams belong to the session port.  The
 * harness drives a single request stream at a time, so the state below
 * is static.  The parsed field strings are pool copies (s3_h3_parse.c
 * allocates the literals off the connection pool), the buffers below
 * just snapshot them for the verdict.
 */

static s3_h3_parse_headers_t s3_interop_h3_parse;

static u_char *s3_interop_h3_buf;
static size_t  s3_interop_h3_cap;
static size_t  s3_interop_h3_len;

static s3_connection_t *s3_interop_h3_sc;
static s3_connection_t *s3_interop_h3_pc; /* the quic conn of the CONNECT */
static unsigned         s3_interop_h3_responded;

static u_char s3_interop_h3_method[32];
static size_t s3_interop_h3_method_len;
static u_char s3_interop_h3_protocol[32];
static size_t s3_interop_h3_protocol_len;
static u_char s3_interop_h3_path[256];
static size_t s3_interop_h3_path_len;
/*
 * the Authorization snapshot: the biggest Bearer the CONNECT carries
 * (an Ed25519 pubkey JWT is ~340 bytes, an RS256 one goes past 600,
 * an RS256 OIDC id_token rides ~1.2 KB), the 256-byte capture of the
 * Basic wave truncated it and the verdict failed on the tail
 */
static u_char s3_interop_h3_auth[4096];
static size_t s3_interop_h3_auth_len;
static u_char s3_interop_h3_ua[128];
static size_t s3_interop_h3_ua_len;
static u_char s3_interop_h3_authority[256];
static size_t s3_interop_h3_authority_len;
static u_char s3_interop_h3_scheme[16];
static size_t s3_interop_h3_scheme_len;

/* the response tail pending on the send window */
static u_char s3_interop_h3_out[512];
static size_t s3_interop_h3_out_len;

/*
 * the ssh3 session channels (-3): every bidi stream after the CONNECT
 * is a channel.  The pre-confirmation phase keeps a small per-channel
 * accumulator (the header and the first messages may arrive in
 * several recvs); after the 91 the channel runs either the echo or
 * the server session of docs/P4-WIRE.md 6
 */
struct s3_interop_h3_channel_s {
    s3_connection_t *sc;
    u_char          *buf;
    size_t           cap;
    size_t           len;
    unsigned         confirmed;

    /*
     * the session side: the pool owns the session struct and its
     * command copy, the 50 ms timer pumps the process fds between
     * the channel events (a channel that never speaks would stall
     * the output otherwise - the event ctx has no per-fd watches
     * outside the quic sockets)
     */
    s3_pool_t             *sess_pool;
    s3_ssh3_session_srv_t *sess;
    unsigned               sess_intent; /* a pty-req or an exec announced the session */
    unsigned               sess_exit_sent;
    unsigned               sess_peer_fin;
    s3_event_t             sess_timer;

    /*
     * the forward side (direct-tcp / direct-udp): fwd_fd is the
     * target socket (-1 when the channel is not a forward), the
     * pending buffers decouple the quic stream from the socket and
     * the 50 ms timer pumps the remaining directions - the same
     * harness scheme as the session pump above; the AGENT kind reuses
     * the tcp pump against the accepted agent socket
     */
    unsigned           fwd_kind; /* S3_INTEROP_FWD_NONE/TCP/UDP/AGENT */
    unsigned           fwd_eof;  /* the target socket saw the eof */
    int                fwd_fd;
    struct sockaddr_in fwd_sa;
    u_char            *fwd_in; /* the 94 payloads awaiting the socket send */
    size_t             fwd_in_cap;
    size_t             fwd_in_len;
    u_char            *fwd_out; /* the socket bytes awaiting the 94 send */
    size_t             fwd_out_cap;
    size_t             fwd_out_len;
    size_t             fwd_frame_sent; /* the partial 94 frame in flight */
    size_t             fwd_frame_total;
    s3_event_t         fwd_timer;

    /*
     * the sftp side ("sftp" channels): the pool owns the request
     * server, the 94 payloads feed s3_ssh3_sftp_srv_input and the 50
     * ms timer drains s3_ssh3_sftp_srv_output into the 94 direction
     */
    s3_pool_t          *sftp_pool;
    s3_ssh3_sftp_srv_t *sftp;

    /*
     * the agent side of a session channel: the listener appears on
     * the forward-agent LARVAL marker, the path rides the child env,
     * the timer accepts the connections and opens one server-initiated
     * "agent-connection" channel per socket
     */
    s3_pool_t                *agent_pool;
    s3_ssh3_agent_listener_t *agent_l;
    char                      agent_path[128];
    unsigned                  agent_requested;
    s3_event_t                agent_timer;
};

/* the kinds of the forward channels */

#define S3_INTEROP_FWD_NONE  0
#define S3_INTEROP_FWD_TCP   1
#define S3_INTEROP_FWD_UDP   2
#define S3_INTEROP_FWD_AGENT 3

/*
 * the frame buffer of the socket->channel direction: one 94 frame
 * carries up to the maxPacketSize chunk, the type and length varints
 * ride on top
 */
#define S3_INTEROP_FWD_FRAME 33000

/* the teardown of the session side, the channel free calls it first */
static void s3_interop_session_teardown(s3_interop_h3_channel_t *ch);

/* the sftp and the agent wiring of the wave 2, defined below */

static void s3_interop_sftp_pump(s3_interop_h3_channel_t *ch);

static void s3_interop_agent_accept_timer(s3_event_t *ev);

static s3_interop_h3_channel_t *s3_interop_h3_channel_alloc(s3_connection_t *sc);

static void s3_interop_h3_channel_read(s3_event_t *ev);

static s3_interop_h3_channel_t s3_interop_h3_channels[S3_INTEROP_TRACKED];

/* the StreamID of the CONNECT stream, the channels must quote it */
static uint64_t s3_interop_h3_conv_id;

/* one echo frame: varint 94 + SSHString, capped by the maxPacketSize */
static u_char s3_interop_h3_ch_out[32768];

static void
s3_interop_h3_store(u_char *dst, size_t size, size_t *len, s3_str_t *value)
{
    size_t n;

    n = value->len;

    if (n > size - 1) {
        n = size - 1;
    }

    s3_memcpy(dst, value->data, n);
    dst[n] = '\0';
    *len = n;
}

static void
s3_interop_h3_capture(s3_h3_parse_field_t *f)
{
    static s3_str_t method = s3_string(":method");
    static s3_str_t protocol = s3_string(":protocol");
    static s3_str_t path = s3_string(":path");
    static s3_str_t auth = s3_string("authorization");
    static s3_str_t ua = s3_string("user-agent");
    static s3_str_t authority = s3_string(":authority");
    static s3_str_t scheme = s3_string(":scheme");

    if (f->name.len == method.len && s3_memcmp(f->name.data, method.data, method.len) == 0) {
        s3_interop_h3_store(s3_interop_h3_method, sizeof(s3_interop_h3_method),
                            &s3_interop_h3_method_len, &f->value);

    } else if (f->name.len == protocol.len &&
               s3_memcmp(f->name.data, protocol.data, protocol.len) == 0) {
        s3_interop_h3_store(s3_interop_h3_protocol, sizeof(s3_interop_h3_protocol),
                            &s3_interop_h3_protocol_len, &f->value);

    } else if (f->name.len == path.len && s3_memcmp(f->name.data, path.data, path.len) == 0) {
        s3_interop_h3_store(s3_interop_h3_path, sizeof(s3_interop_h3_path), &s3_interop_h3_path_len,
                            &f->value);

    } else if (f->name.len == auth.len && s3_memcmp(f->name.data, auth.data, auth.len) == 0) {
        s3_interop_h3_store(s3_interop_h3_auth, sizeof(s3_interop_h3_auth), &s3_interop_h3_auth_len,
                            &f->value);

    } else if (f->name.len == ua.len && s3_memcmp(f->name.data, ua.data, ua.len) == 0) {
        s3_interop_h3_store(s3_interop_h3_ua, sizeof(s3_interop_h3_ua), &s3_interop_h3_ua_len,
                            &f->value);

    } else if (f->name.len == authority.len &&
               s3_memcmp(f->name.data, authority.data, authority.len) == 0) {
        s3_interop_h3_store(s3_interop_h3_authority, sizeof(s3_interop_h3_authority),
                            &s3_interop_h3_authority_len, &f->value);

    } else if (f->name.len == scheme.len && s3_memcmp(f->name.data, scheme.data, scheme.len) == 0) {
        s3_interop_h3_store(s3_interop_h3_scheme, sizeof(s3_interop_h3_scheme),
                            &s3_interop_h3_scheme_len, &f->value);
    }

    /* the other field lines are irrelevant to the verdict */
}

static u_char *
s3_interop_h3_put_status(u_char *p, unsigned code)
{
    s3_str_t name, value;
    u_char   digits[8];
    int      n;

    /*
     * the zero prefix: the static-table reference or a literal below,
     * the dynamic table is never referenced either way
     */
    p = (u_char *)s3_h3_encode_field_section_prefix(p, 0, 0, 0);

    if (code == 200) {
        /* RFC 9204 static table: 25 = ":status: 200" */
        return (u_char *)s3_h3_encode_field_ri(p, 0, 25);
    }

    n = snprintf((char *)digits, sizeof(digits), "%u", code);

    name.data = (u_char *)":status";
    name.len = 7;
    value.data = digits;
    value.len = (size_t)n;

    /* the errors are literals: one encoder path for any rejected code */
    return (u_char *)s3_h3_encode_field_l(p, &name, &value);
}

static void
s3_interop_h3_flush(void)
{
    s3_connection_t *sc = s3_interop_h3_sc;
    ssize_t          m;

    while (s3_interop_h3_out_len > 0) {

        m = s3_quic_stream_send(sc, s3_interop_h3_out, s3_interop_h3_out_len);

        if (m == (ssize_t)S3_AGAIN) {
            return;
        }

        if (m <= 0) {
            fprintf(stderr, "interop-server: h3 response send failed\n");
            s3_interop_h3_out_len = 0;
            return;
        }

        s3_memmove(s3_interop_h3_out, s3_interop_h3_out + m, s3_interop_h3_out_len - m);
        s3_interop_h3_out_len -= m;
    }
}

static void
s3_interop_h3_send_status(unsigned code)
{
    u_char  sec[512];
    u_char *p;
    size_t  sec_len, total;
    ssize_t m;

    /*
     * the section is built into the scratch buffer first: the HEADERS
     * frame header carries its exact length as the variable-length
     * int (the section grew past the one-byte form when the Server
     * field came in), the length encode lands behind the frame type
     * and the section follows it
     */
    p = sec;
    p = s3_interop_h3_put_status(p, code);

    if (code == 200) {

        /*
         * the Server field of the reference (w.Header().Set("Server",
         * GetCurrentVersionString())), the client parses it before it
         * opens the conversation
         */

        s3_str_t name = s3_string("server");
        s3_str_t value = s3_string(S3_SSH3_VERSION_STRING);

        p = (u_char *)s3_h3_encode_field_l(p, &name, &value);
    }

    sec_len = (size_t)(p - sec);

    s3_interop_h3_out[0] = S3_H3_FRAME_HEADERS;

    p = (u_char *)s3_h3_encode_varlen_int(s3_interop_h3_out + 1, sec_len);

    memcpy(p, sec, sec_len);

    total = (size_t)(p - s3_interop_h3_out) + sec_len;

    m = s3_quic_stream_send(s3_interop_h3_sc, s3_interop_h3_out, total);

    if (m == (ssize_t)S3_AGAIN) {
        /* the window opens on the write event, the tail is queued */
        s3_interop_h3_out_len = total;
        return;
    }

    if (m <= 0) {
        fprintf(stderr, "interop-server: h3 response send failed\n");
        return;
    }

    if ((size_t)m < total) {
        s3_memmove(s3_interop_h3_out, s3_interop_h3_out + m, total - m);
        s3_interop_h3_out_len = total - m;
    }
}

/*
 * the Basic verdict against the -P password file (docs/P4-WIRE.md 7,
 * the Basic step of the reference chain): the credentials decode from
 * the authorization header, the username comes from the CONNECT
 * target (?user=), the harness file answers the match
 */
static unsigned
s3_interop_h3_basic_verdict(void)
{
    s3_str_t header, path, basic_user, basic_pass, user;
    s3_int_t rc;

    header.data = s3_interop_h3_auth;
    header.len = s3_interop_h3_auth_len;

    s3_str_null(&basic_user);
    s3_str_null(&basic_pass);
    s3_str_null(&user);

    rc = s3_ssh3_auth_basic_decode(&header, &basic_user, &basic_pass);

    if (rc != S3_OK) {
        fprintf(stderr, "interop-server: basic auth: bad credentials rc=%d\n", (int)rc);
        return 401;
    }

    path.data = s3_interop_h3_path;
    path.len = s3_interop_h3_path_len;

    rc = s3_ssh3_auth_user_from_path(&path, &user);

    if (rc != S3_OK) {
        fprintf(stderr, "interop-server: basic auth: no user in the path\n");
        return 401;
    }

    rc = s3_ssh3_auth_password_file_check(s3_interop_passfile, &user, &basic_pass);

    if (rc != S3_OK) {
        fprintf(stderr, "interop-server: basic auth: user=%.*s rejected rc=%d\n", (int)user.len,
                (const char *)user.data, (int)rc);
        return 401;
    }

    printf("INTEROP-AUTH-OK user=%.*s\n", (int)user.len, (const char *)user.data);
    fflush(stdout);

    return 200;
}

/*
 * the OIDC verdict (the reference authorized_identities chain): the
 * Bearer scheme carries the id_token, the expected nonce derives
 * from the EXPORTER-SSH3 exporter of the live conversation (the
 * reference ConversationID), the issuer, the audience and the
 * provider signature decide; the first call bootstraps the
 * discovery and the JWKS cache (the lazy form of the harness), the
 * unknown kid only schedules the background refetch of the timer -
 * the verdict answers the retryable kid reject
 */

static void
s3_interop_oidc_timer_handler(s3_event_t *ev)
{
    time_t now = time(NULL);

    /*
     * the jwks timer: the scheduled unknown-kid refetch and the ttl
     * rotation run here; a failed cycle keeps the old key set (the
     * grace) and rides the retry cadence
     */

    if (s3_ssh3_oidc_verifier_fetch_timer(&s3_interop_oidc_ver, now) == 0 &&
        s3_ssh3_oidc_verifier_fetch(&s3_interop_oidc_ver, now) != S3_OK) {
        fprintf(stderr, "interop-server: oidc jwks fetch failed, %u stale key(s) serve on\n",
                (unsigned)s3_interop_oidc_ver.jwks.nkeys);
    }

    s3_event_add_timer(ev, s3_ssh3_oidc_verifier_fetch_timer(&s3_interop_oidc_ver, time(NULL)));
}

static unsigned
s3_interop_h3_oidc_verdict(s3_connection_t *pc)
{
    static const s3_str_t scheme = s3_string("Bearer ");

    const char *why;
    char        nonce[64];
    s3_str_t    token;
    s3_int_t    rc;

    token.data = s3_interop_h3_auth;
    token.len = s3_interop_h3_auth_len;

    if (token.len <= scheme.len || s3_memcmp(token.data, scheme.data, scheme.len) != 0) {
        fprintf(stderr, "interop-server: oidc auth: the scheme is not Bearer\n");
        return 401;
    }

    token.data += scheme.len;
    token.len -= scheme.len;

    if (pc->ssl == NULL || pc->ssl->connection == NULL ||
        s3_ssh3_oidc_conversation_nonce(pc->ssl->connection, nonce) != S3_OK) {
        fprintf(stderr, "interop-server: oidc auth: no conversation nonce\n");
        return 401;
    }

    rc = s3_ssh3_oidc_verifier_verify(&s3_interop_oidc_ver, s3_interop_oidc_aud,
                                      (const char *)token.data, nonce, time(NULL));

    switch (rc) {

    case S3_SSH3_OIDC_EFORM:
        why = " form";
        break;

    case S3_SSH3_OIDC_EALG:
        why = " alg";
        break;

    case S3_SSH3_OIDC_EKID:
        why = " kid";
        break;

    case S3_SSH3_OIDC_ESIG:
        why = " signature";
        break;

    case S3_SSH3_OIDC_EISS:
        why = " issuer";
        break;

    case S3_SSH3_OIDC_EAUD:
        why = " audience";
        break;

    case S3_SSH3_OIDC_EEXP:
        why = " expiry";
        break;

    case S3_SSH3_OIDC_ENONCE:
        why = " nonce";
        break;

    case S3_OK:
        why = "";
        break;

    default:
        why = " provider";
        break;
    }

    if (rc != S3_OK) {
        fprintf(stderr, "interop-server: oidc auth: rejected:%s rc=%d\n", why, (int)rc);
        return 401;
    }

    printf("INTEROP-AUTH-OK user=oidc iss=%s\n", s3_interop_oidc_issuer);

    fflush(stdout);

    return 200;
}

/*
 * the -K path of one user: a %u token is the session username (the
 * sshd AuthorizedKeysFile shape), the unknown directives stay
 * literal; the username passes the plain-name guard - no leading
 * dot, no separator - so the substitution cannot climb out of the
 * directory; S3_ERROR when the expanded path does not fit
 */

static s3_int_t
s3_interop_keyfile_user_path(const char *pattern, const s3_str_t *user, char *out, size_t size)
{
    const char *p;
    char       *o = out;
    size_t      left = size - 1, i;

    for (p = pattern; *p != '\0'; p++) {

        if (*p != '%') {

            if (left == 0) {
                return S3_ERROR;
            }

            *o++ = *p;
            left--;

            continue;
        }

        if (p[1] == 'u') {

            /* the traversal guard: the plain session names only */

            if (user->len == 0 || user->data[0] == '.') {
                return S3_ERROR;
            }

            for (i = 0; i < user->len; i++) {

                u_char c = user->data[i];

                if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                      c == '.' || c == '_' || c == '-')) {
                    return S3_ERROR;
                }
            }

            if (user->len > left) {
                return S3_ERROR;
            }

            memcpy(o, user->data, user->len);

            o += user->len;
            left -= user->len;
            p++;

            continue;
        }

        /* the lone percent or the unknown directive is literal */

        if (left < 2) {
            return S3_ERROR;
        }

        *o++ = '%';

        if (p[1] != '\0') {
            *o++ = p[1];
            p++;
        }

        left -= 2;
    }

    *o = '\0';

    return S3_OK;
}

/*
 * the Bearer JWT verdict against the -K authorized_keys file (the
 * pubkey step of the reference chain): the username comes from the
 * CONNECT target (?user=), the jti binding rides the TLS exporter
 * ("EXPORTER-SSH3", the conversation id the reference signs into the
 * token)
 */

static unsigned
s3_interop_h3_jwt_verdict(void)
{
    s3_str_t header, path, user;
    u_char   conv[32];
    char     keys[512];
    s3_int_t rc;

    header.data = s3_interop_h3_auth;
    header.len = s3_interop_h3_auth_len;

    path.data = s3_interop_h3_path;
    path.len = s3_interop_h3_path_len;

    s3_str_null(&user);

    rc = s3_ssh3_auth_user_from_path(&path, &user);

    if (rc != S3_OK) {
        fprintf(stderr, "interop-server: pubkey auth: no user in the path\n");
        return 401;
    }

    if (strchr(s3_interop_keyfile, '%') != NULL) {

        rc = s3_interop_keyfile_user_path(s3_interop_keyfile, &user, keys, sizeof(keys));

        if (rc != S3_OK) {
            fprintf(stderr, "interop-server: pubkey auth: bad keys path for user=%.*s\n",
                    (int)user.len, (const char *)user.data);
            return 401;
        }

    } else {

        snprintf(keys, sizeof(keys), "%s", s3_interop_keyfile);
    }

    if (s3_interop_h3_pc == NULL || s3_interop_h3_pc->ssl == NULL ||
        s3_interop_h3_pc->ssl->connection == NULL ||
        SSL_export_keying_material(s3_interop_h3_pc->ssl->connection, conv, sizeof(conv),
                                   "EXPORTER-SSH3", 13, NULL, 0, 0) != 1) {
        fprintf(stderr, "interop-server: pubkey auth: exporter failed\n");
        return 401;
    }

    rc = s3_ssh3_auth_jwt_verify(&header, &user, keys, conv, sizeof(conv));

    if (rc != S3_OK) {
        fprintf(stderr, "interop-server: pubkey auth: user=%.*s rejected rc=%d\n", (int)user.len,
                (const char *)user.data, (int)rc);
        return 401;
    }

    printf("INTEROP-AUTH-OK user=%.*s\n", (int)user.len, (const char *)user.data);
    fflush(stdout);

    return 200;
}

static void
s3_interop_h3_respond(s3_connection_t *pc)
{
    unsigned          code;
    s3_ssh3_version_t ver;

    if (s3_interop_h3_responded) {
        return;
    }

    /* RFC 9220: :protocol marks an extended CONNECT, ssh3 is our
     * route; the query part of the path carries the auth username
     * (docs/P4-WIRE.md 7 step 3) and does not affect the route */

    if (s3_interop_h3_method_len == 7 && s3_memcmp(s3_interop_h3_method, "CONNECT", 7) == 0 &&
        s3_interop_h3_protocol_len == 4 && s3_memcmp(s3_interop_h3_protocol, "ssh3", 4) == 0 &&
        s3_interop_h3_path_len >= 10 && s3_memcmp(s3_interop_h3_path, "/ssh3-term", 10) == 0 &&
        (s3_interop_h3_path_len == 10 || s3_interop_h3_path[10] == '?')) {

        /* RFC 9114, 4.4: the extended CONNECT carries :scheme and
         * :authority next to :method, :protocol and :path */

        if (s3_interop_h3_scheme_len == 0 || s3_interop_h3_authority_len == 0) {
            code = 400;

        } else if (s3_interop_h3_ua_len == 0 ||
                   s3_ssh3_version_parse(s3_interop_h3_ua, s3_interop_h3_ua_len, &ver) != S3_OK ||
                   s3_ssh3_version_supported(&ver) != S3_OK) {

            /* the reference rejects a bad user-agent before anything
             * else (go_server: 403 unsupported SSH3 version) */

            code = 403;

        } else if (pc->ssl == NULL || !pc->ssl->handshaked || s3_interop_force_early) {

            /* RFC 8470: a request that arrived in early data may be
             * replayed, the reference answers 425 until the handshake
             * is done (go_server: TLS handshake incomplete).  The
             * S3_H3_FORCE_EARLY probe spends itself on the first
             * CONNECT, the retry rides the normal chain */

            code = 425;
            s3_interop_force_early = 0;

        } else if (s3_interop_oidc_issuer != NULL) {

            /* the OIDC mode: the Bearer id_token of the provider
             * decides, the conversation nonce binds it */
            code = s3_interop_h3_oidc_verdict(pc);

        } else if (s3_interop_keyfile != NULL && s3_interop_h3_auth_len > 0) {

            s3_str_t header;

            header.data = s3_interop_h3_auth;
            header.len = s3_interop_h3_auth_len;

            if (s3_ssh3_auth_jwt_bearer(&header) == S3_OK) {

                /* the pubkey mode: the Bearer token decides */

                code = s3_interop_h3_jwt_verdict();

            } else if (s3_interop_passfile != NULL) {

                /* the Basic credentials still speak when -P rides along */

                code = s3_interop_h3_basic_verdict();

            } else {
                code = 401;
            }

        } else if (s3_interop_passfile == NULL) {
            code = s3_interop_h3_auth_len ? 200 : 401;

        } else {
            /* the password file mode: the Basic credentials decide */
            code = s3_interop_h3_basic_verdict();
        }

    } else {
        code = 400;
    }

    if (code == 200) {
        printf("INTEROP-H3-CONNECT-OK authlen=%zu\n", s3_interop_h3_auth_len);

    } else {
        printf("INTEROP-H3-REJECT code=%u\n", code);
    }

    fflush(stdout);

    s3_interop_h3_send_status(code);

    if (code != 200) {
        /* the rejected request stream closes right after the status */
        (void)s3_quic_shutdown_stream(s3_interop_h3_sc, S3_WRITE_SHUTDOWN);
    }

    s3_interop_h3_responded = 1;
}

static void
s3_interop_h3_request_read(s3_event_t *ev)
{
    s3_connection_t  *sc;
    s3_quic_stream_t *qs;
    s3_connection_t  *pc;
    s3_buf_t          b;
    u_char            scratch[4096];
    s3_int_t          rc;
    ssize_t           n;

    sc = ev->data;
    qs = sc->data;
    pc = qs->parent;

    for (;;) {

        if (s3_interop_h3_responded) {

            /*
             * the tunnel phase: the stream carries the ssh3 protocol
             * from here, the harness exchanges nothing before the
             * teardown, the bytes are drained and dropped
             */
            n = sc->recv(sc, scratch, sizeof(scratch));

            if (n > 0) {
                continue;
            }

            if (n == 0) {
                (void)s3_quic_shutdown_stream(sc, S3_WRITE_SHUTDOWN);
            }

            return;
        }

        if (s3_interop_h3_len == s3_interop_h3_cap) {
            size_t  cap = s3_interop_h3_cap + 262144;
            u_char *grown = realloc(s3_interop_h3_buf, cap);

            if (grown == NULL) {
                fprintf(stderr, "interop-server: h3 buffer growth failed\n");
                exit(1);
            }

            s3_interop_h3_buf = grown;
            s3_interop_h3_cap = cap;
        }

        n = sc->recv(sc, s3_interop_h3_buf + s3_interop_h3_len,
                     s3_interop_h3_cap - s3_interop_h3_len);

        if (n == (ssize_t)S3_AGAIN) {
            return;
        }

        if (n == 0) {
            /* the peer fin before a complete request: nothing to answer */
            (void)s3_quic_shutdown_stream(sc, S3_WRITE_SHUTDOWN);
            return;
        }

        if (n < 0) {
            fprintf(stderr, "interop-server: h3 request recv error\n");
            return;
        }

        s3_interop_h3_len += (size_t)n;

        b.pos = s3_interop_h3_buf;
        b.last = s3_interop_h3_buf + s3_interop_h3_len;

        for (;;) {

            /*
             * ssh3-c: the parent connection goes into the parser, the
             * frozen s3_h3_get_session() macro reads c->data and the
             * session hangs exactly there; the stream connection's
             * data is the s3_quic_stream_t (the reference sc->quic)
             */
            rc = s3_h3_parse_headers(pc, &s3_interop_h3_parse, &b);

            if (rc == S3_AGAIN || rc == S3_BUSY) {
                break;
            }

            if (rc == S3_OK) {
                /* one field line done, the section continues */
                s3_interop_h3_capture(&s3_interop_h3_parse.field_rep.field);
                continue;
            }

            if (rc == S3_DONE) {
                /* the last field line lands together with the section end */
                s3_interop_h3_capture(&s3_interop_h3_parse.field_rep.field);
                s3_interop_h3_respond(pc);
                break;
            }

            /* QPACK or HTTP/3 error: no useful answer exists */
            fprintf(stderr, "interop-server: h3 request parse error %d\n", (int)rc);
            (void)s3_quic_shutdown_stream(sc, S3_WRITE_SHUTDOWN);
            return;
        }

        /* the consumed bytes compact to the front of the receive buffer */
        s3_interop_h3_len = (size_t)(b.last - b.pos);
        s3_memmove(s3_interop_h3_buf, b.pos, s3_interop_h3_len);
    }
}

static void
s3_interop_h3_stream_write(s3_event_t *ev)
{
    (void)ev;

    s3_interop_h3_flush();
}

/*
 * the ssh3 session channels (-3): accept, the 91 confirmation and the
 * stateless 94 echo, the wire shape of docs/P4-WIRE.md 2 and 3.1
 */

static void
s3_interop_h3_channel_free(s3_interop_h3_channel_t *ch)
{
    /* the pump timers must leave the rbtree before the memory goes */

    if (ch->sess_timer.timer_set) {
        s3_event_del_timer(&ch->sess_timer);
    }

    if (ch->fwd_timer.timer_set) {
        s3_event_del_timer(&ch->fwd_timer);
    }

    if (ch->agent_timer.timer_set) {
        s3_event_del_timer(&ch->agent_timer);
    }

    s3_interop_session_teardown(ch);

    /* the agent listener dies with its pool: the cleanup unlinks the
     * socket and removes the private directory */

    if (ch->agent_pool != NULL) {
        s3_destroy_pool(ch->agent_pool);
        ch->agent_pool = NULL;
        ch->agent_l = NULL;
    }

    /* the sftp request server lives in its pool alone */

    if (ch->sftp_pool != NULL) {
        s3_destroy_pool(ch->sftp_pool);
        ch->sftp_pool = NULL;
        ch->sftp = NULL;
    }

    if (ch->fwd_fd >= 0) {
        (void)close(ch->fwd_fd);
    }

    if (ch == s3_interop_h3_udp_fwd) {
        s3_interop_h3_udp_fwd = NULL;
    }

    free(ch->buf);
    free(ch->fwd_in);
    free(ch->fwd_out);

    s3_memzero(ch, sizeof(*ch));
}

static s3_interop_h3_channel_t *
s3_interop_h3_channel_of(s3_connection_t *sc)
{
    unsigned i;

    for (i = 0; i < S3_INTEROP_TRACKED; i++) {

        if (s3_interop_h3_channels[i].sc == sc) {
            return &s3_interop_h3_channels[i];
        }
    }

    return NULL;
}

/*
 * the slot of a fresh channel (the accept path and the
 * server-initiated agent connections share it); NULL when the table
 * is full, the caller tears the stream down
 */

static s3_interop_h3_channel_t *
s3_interop_h3_channel_alloc(s3_connection_t *sc)
{
    unsigned i;

    for (i = 0; i < S3_INTEROP_TRACKED; i++) {

        if (s3_interop_h3_channels[i].sc == NULL) {
            s3_memzero(&s3_interop_h3_channels[i], sizeof(s3_interop_h3_channels[i]));
            s3_interop_h3_channels[i].sc = sc;
            s3_interop_h3_channels[i].fwd_fd = -1;
            return &s3_interop_h3_channels[i];
        }
    }

    return NULL;
}

static void
s3_interop_h3_channel_cancel(s3_interop_h3_channel_t *ch, const char *why)
{
    s3_quic_stream_t *qs = ch->sc->data;

    /* the reference answer to a bad channel is cancel(0) */

    fprintf(stderr, "interop-server: channel id=%llu %s\n", (unsigned long long)qs->id, why);

    (void)s3_quic_cancelable_stream(ch->sc);
    (void)s3_quic_shutdown_stream(ch->sc, S3_RDWR_SHUTDOWN);

    s3_interop_h3_channel_free(ch);
}

static s3_int_t
s3_interop_h3_channel_echo(s3_connection_t *sc, const u_char *data, size_t len)
{
    u_char *p;
    size_t  total;
    ssize_t m;

    total = s3_ssh3_varint_size(S3_SSH3_MSG_CHANNEL_DATA) + s3_ssh3_sshstring_size(len);

    if (total > sizeof(s3_interop_h3_ch_out)) {
        return S3_ERROR;
    }

    p = s3_interop_h3_ch_out;
    p = (u_char *)s3_ssh3_encode_varint(p, S3_SSH3_MSG_CHANNEL_DATA);
    p = (u_char *)s3_ssh3_encode_sshstring(p, data, len);

    m = s3_quic_stream_send(sc, s3_interop_h3_ch_out, total);

    /*
     * the scenario moves tens of bytes against a 16 KiB send window, a
     * stall cannot happen; a partial send would desync the message
     * stream, so any short write is a hard error here (the simpler
     * choice over the write-event retry)
     */
    if (m != (ssize_t)total) {
        return S3_ERROR;
    }

    return S3_OK;
}

/* the 95 frame of the stderr pipe (docs/P4-WIRE.md 3.1, dataType 1) */

static s3_int_t
s3_interop_h3_channel_send_extended(s3_connection_t *sc, const u_char *data, size_t len)
{
    u_char *p;
    size_t  total;
    ssize_t m;

    total = s3_ssh3_varint_size(S3_SSH3_MSG_CHANNEL_EXTENDED_DATA) +
            s3_ssh3_varint_size(S3_SSH3_EXTENDED_DATA_STDERR) + s3_ssh3_sshstring_size(len);

    if (total > sizeof(s3_interop_h3_ch_out)) {
        return S3_ERROR;
    }

    p = s3_interop_h3_ch_out;
    p = (u_char *)s3_ssh3_encode_varint(p, S3_SSH3_MSG_CHANNEL_EXTENDED_DATA);
    p = (u_char *)s3_ssh3_encode_varint(p, S3_SSH3_EXTENDED_DATA_STDERR);
    p = (u_char *)s3_ssh3_encode_sshstring(p, data, len);

    m = s3_quic_stream_send(sc, s3_interop_h3_ch_out, total);

    /* the same small-volume assumption as the 94 echo above */

    if (m != (ssize_t)total) {
        return S3_ERROR;
    }

    return S3_OK;
}

/*
 * the server session (docs/P4-WIRE.md 6): the channel requests drive
 * s3_ssh3_session_srv, the process fds are pumped by the channel read
 * handler and the 50 ms timer - the simple harness scheme, a general
 * server wants the fds watched in the event context
 */

/* the reference runs $SHELL (newCommand of the server flow) */

static const char *
s3_interop_session_shell(void)
{
    const char *shell = getenv("SHELL");

    return (shell != NULL && *shell != '\0') ? shell : "/bin/sh";
}

static s3_int_t
s3_interop_session_start(s3_interop_h3_channel_t *ch)
{
    if (ch->sess != NULL) {
        return S3_OK;
    }

    ch->sess_pool = s3_create_pool(S3_DEFAULT_POOL_SIZE, &s3_interop_log);

    if (ch->sess_pool == NULL) {
        return S3_ERROR;
    }

    ch->sess = s3_pcalloc(ch->sess_pool, sizeof(s3_ssh3_session_srv_t));

    if (ch->sess == NULL || s3_ssh3_session_srv_init(ch->sess, ch->sess_pool) != S3_OK) {
        s3_destroy_pool(ch->sess_pool);
        ch->sess_pool = NULL;
        return S3_ERROR;
    }

    /*
     * the agent path of the forward-agent marker rides the child env
     * (the reference setupEnv), the spawn is still ahead
     */

    if (ch->agent_l != NULL &&
        s3_ssh3_session_srv_env(ch->sess, "SSH_AUTH_SOCK", ch->agent_path) != S3_OK) {
        fprintf(stderr, "interop-server: SSH_AUTH_SOCK env failed\n");
    }

    return S3_OK;
}

static void
s3_interop_session_teardown(s3_interop_h3_channel_t *ch)
{
    s3_ssh3_session_srv_t *s = ch->sess;
    int                    in, out, err, master;

    if (s == NULL) {
        return;
    }

    /* the client may vanish mid-session: the process dies here */

    if (s->pid > 0) {
        (void)kill((pid_t)s->pid, SIGKILL);
        (void)waitpid((pid_t)s->pid, NULL, 0);
    }

    /* the reap usually closed the fds already, the leftovers die too */

    in = s->stdin_fd;
    out = s->stdout_fd;
    err = s->stderr_fd;
    master = s->pty_master;

    if (in != S3_SSH3_SESSION_INVALID_FD) {
        (void)close(in);
    }

    if (out != S3_SSH3_SESSION_INVALID_FD && out != in) {
        (void)close(out);
    }

    if (err != S3_SSH3_SESSION_INVALID_FD && err != in && err != out) {
        (void)close(err);
    }

    if (master != S3_SSH3_SESSION_INVALID_FD && master != in && master != out && master != err) {
        (void)close(master);
    }

    /* the pool owns the session struct, everything goes with it */

    s3_destroy_pool(ch->sess_pool);

    ch->sess = NULL;
    ch->sess_pool = NULL;
}

/*
 * the request bodies carry no length prefix (docs/P4-WIRE.md 6) and
 * the contract parser wants the body to end exactly at `end`; the
 * peers pipeline several requests in one stream write, so the body
 * boundary is walked here first and the exact span is validated
 * afterwards by s3_ssh3_request_parse_body()
 */
static const u_char *
s3_interop_request_body_end(s3_ssh3_request_kind_t kind, const u_char *pos, const u_char *end)
{
    s3_str_t str;
    uint64_t num;

    switch (kind) {

    case S3_SSH3_REQ_SHELL:
        return pos;

    case S3_SSH3_REQ_PTY:
        if (s3_ssh3_parse_sshstring(&pos, end, &str) != S3_OK ||
            s3_ssh3_parse_varint(&pos, end, &num) != S3_OK       /* width */
            || s3_ssh3_parse_varint(&pos, end, &num) != S3_OK    /* height */
            || s3_ssh3_parse_varint(&pos, end, &num) != S3_OK    /* pixel width */
            || s3_ssh3_parse_varint(&pos, end, &num) != S3_OK    /* pixel height */
            || s3_ssh3_parse_sshstring(&pos, end, &str) != S3_OK /* modes */
        ) {
            return NULL;
        }

        return pos;

    case S3_SSH3_REQ_EXEC:
    case S3_SSH3_REQ_SUBSYSTEM:
    case S3_SSH3_REQ_SIGNAL:
        return s3_ssh3_parse_sshstring(&pos, end, &str) == S3_OK ? pos : NULL;

    case S3_SSH3_REQ_WINDOW_CHANGE:
        return (s3_ssh3_parse_varint(&pos, end, &num) == S3_OK &&
                s3_ssh3_parse_varint(&pos, end, &num) == S3_OK &&
                s3_ssh3_parse_varint(&pos, end, &num) == S3_OK &&
                s3_ssh3_parse_varint(&pos, end, &num) == S3_OK)
                   ? pos
                   : NULL;

    case S3_SSH3_REQ_EXIT_STATUS:
        return s3_ssh3_parse_varint(&pos, end, &num) == S3_OK ? pos : NULL;

    case S3_SSH3_REQ_EXIT_SIGNAL:

        if (s3_ssh3_parse_sshstring(&pos, end, &str) != S3_OK || end - pos < 1) {
            return NULL;
        }

        pos++;

        return (s3_ssh3_parse_sshstring(&pos, end, &str) == S3_OK &&
                s3_ssh3_parse_sshstring(&pos, end, &str) == S3_OK)
                   ? pos
                   : NULL;

    case S3_SSH3_REQ_X11:

        if (end - pos < 1) {
            return NULL;
        }

        pos++;

        return (s3_ssh3_parse_sshstring(&pos, end, &str) == S3_OK &&
                s3_ssh3_parse_sshstring(&pos, end, &str) == S3_OK &&
                s3_ssh3_parse_varint(&pos, end, &num) == S3_OK)
                   ? pos
                   : NULL;
    }

    return NULL;
}

/* the 98 exit-status, the terminal message of the session flow */

static s3_int_t
s3_interop_session_send_exit(s3_connection_t *sc, uint64_t code)
{
    u_char                frame[64];
    u_char                body[16];
    u_char               *p;
    s3_ssh3_request_t     req;
    s3_ssh3_msg_request_t env;
    size_t                body_len, total;
    ssize_t               m;

    s3_memzero(&req, sizeof(req));

    req.kind = S3_SSH3_REQ_EXIT_STATUS;
    req.u.exit_status.status = code;

    body_len = s3_ssh3_request_encode_body(NULL, &req);
    (void)s3_ssh3_request_encode_body(body, &req);

    s3_memzero(&env, sizeof(env));

    env.request_type.data = (u_char *)s3_ssh3_request_type_str(S3_SSH3_REQ_EXIT_STATUS);
    env.request_type.len = s3_strlen(env.request_type.data);
    env.want_reply = 0;
    env.body.data = body;
    env.body.len = body_len;

    p = frame;
    p = (u_char *)s3_ssh3_encode_varint(p, S3_SSH3_MSG_CHANNEL_REQUEST);
    p = (u_char *)s3_ssh3_msg_encode_request(p, &env);

    total = (size_t)(p - frame);

    m = s3_quic_stream_send(sc, frame, total);

    if (m != (ssize_t)total) {
        return S3_ERROR;
    }

    return S3_OK;
}

static void
s3_interop_session_pump(s3_interop_h3_channel_t *ch)
{
    static u_char out[16384];

    s3_connection_t *sc;
    ssize_t          n;
    s3_int_t         rc;
    uint64_t         code;
    s3_str_t         name;
    unsigned         core;

    if (ch->sess == NULL) {
        return;
    }

    sc = ch->sc;

    /* the stdout rides as 94, the pty merges everything into it */

    for (;;) {

        n = s3_ssh3_session_srv_read_output(ch->sess, out, sizeof(out));

        if (n <= 0) {
            break;
        }

        if (s3_interop_h3_channel_echo(sc, out, (size_t)n) != S3_OK) {
            fprintf(stderr, "interop-server: session output send stalled\n");
            return;
        }
    }

    /* the stderr pipe of the pipe sessions, 95 with dataType 1 */

    if (ch->sess->stderr_fd != S3_SSH3_SESSION_INVALID_FD) {

        for (;;) {

            n = s3_ssh3_session_srv_read_stderr(ch->sess, out, sizeof(out));

            if (n <= 0) {
                break;
            }

            if (s3_interop_h3_channel_send_extended(sc, out, (size_t)n) != S3_OK) {
                fprintf(stderr, "interop-server: session stderr send stalled\n");
                return;
            }
        }
    }

    if (ch->sess_exit_sent) {
        return;
    }

    s3_str_null(&name);

    rc = s3_ssh3_session_srv_reap(ch->sess, &code, &name, &core);

    if (rc != S3_OK) {
        /* S3_AGAIN: the process still runs, the pump comes back */
        return;
    }

    if (s3_interop_session_send_exit(sc, code) != S3_OK) {
        fprintf(stderr, "interop-server: exit-status send failed\n");
        return;
    }

    /* the reference shuts the channel send side after the verdict */

    (void)s3_quic_shutdown_stream(sc, S3_WRITE_SHUTDOWN);

    ch->sess_exit_sent = 1;

    printf("INTEROP-SESSION-EXIT code=%u\n", (unsigned)code);
    fflush(stdout);
}

static void
s3_interop_session_timer(s3_event_t *ev)
{
    s3_interop_h3_channel_t *ch = ev->data;

    ev->timedout = 0;

    s3_interop_session_pump(ch);

    /* the timer disarms once the verdict is out, the flow ends by
     * the peer fin on the already drained stream */

    if (ch->sess != NULL && !ch->sess_exit_sent) {
        s3_event_add_timer(ev, 50);
    }
}

/* the timer arms at the spawn, the pump rides it until the verdict */

static void
s3_interop_session_arm(s3_interop_h3_channel_t *ch)
{
    if (ch->sess_timer.timer_set) {
        return;
    }

    ch->sess_timer.data = ch;
    ch->sess_timer.log = &s3_interop_log;
    ch->sess_timer.handler = s3_interop_session_timer;

    s3_event_add_timer(&ch->sess_timer, 50);
}

/*
 * the direct-tcp / direct-udp relay (docs/P4-WIRE.md 2.1, 3.1, 3.2):
 * the tcp channel pipes the 94 payloads into the target socket and
 * the socket bytes back as 94; the udp channel maps one QUIC datagram
 * (the controlStreamID + channelID prefix) onto one sendto() and the
 * replies back.  The pump rides the 50 ms timer like the session one
 * - the harness scheme, a general server wants the sockets watched in
 * the event context
 */

static unsigned
s3_interop_h3_type_is(const s3_str_t *type, const char *name)
{
    size_t n = strlen(name);

    return type->len == n && s3_memcmp(type->data, name, n) == 0;
}

static s3_int_t
s3_interop_fwd_append(u_char **buf, size_t *cap, size_t *len, const u_char *data, size_t n)
{
    if (*len + n > *cap) {

        size_t  grown_cap = *cap ? *cap : 16384;
        u_char *grown;

        while (grown_cap < *len + n) {
            grown_cap += 65536;
        }

        grown = realloc(*buf, grown_cap);

        if (grown == NULL) {
            return S3_ERROR;
        }

        *buf = grown;
        *cap = grown_cap;
    }

    s3_memcpy(*buf + *len, data, n);
    *len += n;

    return S3_OK;
}

/* the pending channel bytes ride the target socket */

static void
s3_interop_fwd_socket_flush(s3_interop_h3_channel_t *ch)
{
    while (ch->fwd_in_len > 0) {

        ssize_t m;

        if (ch->fwd_kind == S3_INTEROP_FWD_TCP || ch->fwd_kind == S3_INTEROP_FWD_AGENT) {
            m = send(ch->fwd_fd, ch->fwd_in, ch->fwd_in_len, 0);

        } else {
            m = sendto(ch->fwd_fd, ch->fwd_in, ch->fwd_in_len, 0,
                       (const struct sockaddr *)&ch->fwd_sa, sizeof(ch->fwd_sa));
        }

        if (m > 0) {
            s3_memmove(ch->fwd_in, ch->fwd_in + m, ch->fwd_in_len - (size_t)m);
            ch->fwd_in_len -= (size_t)m;
            continue;
        }

        if (m < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return;
        }

        /*
         * a broken tcp socket reports itself on the next recv, a udp
         * datagram loss stays a loss (RFC 768); the pump retries
         */
        return;
    }
}

/*
 * the pending socket bytes go out as 94 frames; a partial send parks
 * the frame tail (the stream is a byte stream, the offset tracking
 * rides the static frame buffer), the pump retries it
 */
static void
s3_interop_fwd_flush(s3_interop_h3_channel_t *ch)
{
    static u_char frame[S3_INTEROP_FWD_FRAME];
    size_t        chunk;
    ssize_t       m;

    for (;;) {

        if (ch->fwd_frame_sent == ch->fwd_frame_total) {

            if (ch->fwd_out_len == 0) {
                return;
            }

            /* a new frame: the payload copy rides the static buffer,
             * the pending bytes drop at once */

            chunk = s3_ssh3_channel_chunk_size(S3_INTEROP_CHANNEL_MAX_PACKET, 0);

            if (chunk > ch->fwd_out_len) {
                chunk = ch->fwd_out_len;
            }

            {
                u_char *p = frame;

                p = (u_char *)s3_ssh3_encode_varint(p, S3_SSH3_MSG_CHANNEL_DATA);
                p = (u_char *)s3_ssh3_encode_varint(p, chunk);
                s3_memcpy(p, ch->fwd_out, chunk);

                ch->fwd_frame_total = (size_t)(p - frame) + chunk;
            }

            ch->fwd_frame_sent = 0;

            s3_memmove(ch->fwd_out, ch->fwd_out + chunk, ch->fwd_out_len - chunk);
            ch->fwd_out_len -= chunk;
        }

        m = s3_quic_stream_send(ch->sc, frame + ch->fwd_frame_sent,
                                ch->fwd_frame_total - ch->fwd_frame_sent);

        if (getenv("S3SFTPSRV") != NULL) {

            size_t z;

            fprintf(stderr, "sftpsrv send %ld:", (long)(ch->fwd_frame_total - ch->fwd_frame_sent));

            for (z = ch->fwd_frame_sent; z < ch->fwd_frame_total && z < ch->fwd_frame_sent + 24;
                 z++) {
                fprintf(stderr, " %02x", frame[z]);
            }

            fprintf(stderr, "\n");
        }

        if (m == (ssize_t)S3_AGAIN) {
            /* the window reopens on the next pump tick */
            return;
        }

        if (m <= 0) {
            fprintf(stderr, "interop-server: forward send failed\n");
            s3_interop_h3_channel_free(ch);
            return;
        }

        ch->fwd_frame_sent += (size_t)m;
    }
}

/* the target reply rides the datagram prefix back to the client */

static void
s3_interop_fwd_udp_reply(s3_interop_h3_channel_t *ch, const u_char *data, size_t len)
{
    s3_quic_stream_t *qs = ch->sc->data;
    u_char            dg[2048];
    u_char           *p;

    /* the harness payloads fit one datagram, the bigger ones drop */

    if (len + 8 > sizeof(dg)) {
        return;
    }

    p = s3_ssh3_dgram_encode(dg, s3_interop_h3_conv_id, qs->id, data, len);

    (void)s3_quic_send_datagram(qs->parent, dg, (size_t)(p - dg));
}

static void
s3_interop_fwd_pump(s3_interop_h3_channel_t *ch)
{
    static u_char buf[16384];
    ssize_t       n;

    /* the pending channel bytes ride the socket first */
    s3_interop_fwd_socket_flush(ch);

    if (ch->fwd_kind == S3_INTEROP_FWD_TCP || ch->fwd_kind == S3_INTEROP_FWD_AGENT) {

        if (!ch->fwd_eof) {

            for (;;) {

                n = recv(ch->fwd_fd, buf, sizeof(buf), 0);

                if (getenv("S3AGENTDBG") != NULL && ch->fwd_kind == S3_INTEROP_FWD_AGENT) {
                    fprintf(stderr, "agdbg srv pump fd=%d n=%ld\n", ch->fwd_fd, (long)n);
                }

                if (n > 0) {

                    if (s3_interop_fwd_append(&ch->fwd_out, &ch->fwd_out_cap, &ch->fwd_out_len, buf,
                                              (size_t)n) != S3_OK) {
                        fprintf(stderr, "interop-server: forward buffer growth failed\n");
                        s3_interop_h3_channel_free(ch);
                        return;
                    }

                    continue;
                }

                if (n == 0) {
                    /* the target closed: the tail drains, the channel
                     * shuts down once the last byte is out */
                    ch->fwd_eof = 1;
                    break;
                }

                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    break;
                }

                fprintf(stderr, "interop-server: forward target read error\n");
                s3_interop_h3_channel_free(ch);
                return;
            }
        }

    } else {

        /* the udp replies: one datagram per recvfrom */

        for (;;) {

            n = recvfrom(ch->fwd_fd, buf, sizeof(buf), 0, NULL, NULL);

            if (n <= 0) {

                if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    fprintf(stderr, "interop-server: forward target read error\n");
                }

                break;
            }

            s3_interop_fwd_udp_reply(ch, buf, (size_t)n);
        }
    }

    s3_interop_fwd_flush(ch);

    if (ch->fwd_eof && ch->fwd_out_len == 0 && ch->fwd_frame_sent == ch->fwd_frame_total) {

        /* the relay is over: the fin goes out, the channel ends */

        (void)s3_quic_shutdown_stream(ch->sc, S3_WRITE_SHUTDOWN);
        s3_interop_h3_channel_free(ch);
    }
}

static void
s3_interop_fwd_timer(s3_event_t *ev)
{
    s3_interop_h3_channel_t *ch = ev->data;

    ev->timedout = 0;

    if (getenv("S3AGENTDBG") != NULL && ch->fwd_kind == S3_INTEROP_FWD_AGENT) {
        fprintf(stderr, "agdbg fwd tick eof=%u\n", (unsigned)ch->fwd_eof);
    }

    if (ch->sftp != NULL) {
        s3_interop_sftp_pump(ch);

    } else {
        s3_interop_fwd_pump(ch);
    }

    /* the pump stops once the channel is gone (the free zeroes the
     * struct), a live forward keeps ticking */

    if (ch->sc != NULL && (ch->fwd_kind != S3_INTEROP_FWD_NONE || ch->sftp != NULL)) {
        s3_event_add_timer(ev, 50);
    }
}

static void
s3_interop_fwd_arm(s3_interop_h3_channel_t *ch)
{
    if (ch->fwd_timer.timer_set) {
        return;
    }

    ch->fwd_timer.data = ch;
    ch->fwd_timer.log = &s3_interop_log;
    ch->fwd_timer.handler = s3_interop_fwd_timer;

    s3_event_add_timer(&ch->fwd_timer, 50);
}

/*
 * the sftp subsystem of the "sftp" channel (the wave 2): the request
 * server jails itself into the session user's home, the timer drains
 * the replies into the 94 direction
 */

static s3_int_t
s3_interop_sftp_start(s3_interop_h3_channel_t *ch)
{
    s3_str_t       home;
    struct passwd *pw;

    if (s3_interop_sftp_home[0] != '\0') {

        home.data = (u_char *)s3_interop_sftp_home;
        home.len = strlen(s3_interop_sftp_home);

    } else {

        pw = getpwuid(getuid());

        home.data = NULL;
        home.len = 0;

        if (pw != NULL && pw->pw_dir != NULL && *pw->pw_dir != '\0') {
            home.data = (u_char *)pw->pw_dir;
            home.len = strlen(pw->pw_dir);

        } else {

            const char *env_home = getenv("HOME");

            if (env_home == NULL || *env_home == '\0') {
                fprintf(stderr, "interop-server: sftp: no home directory\n");
                return S3_ERROR;
            }

            home.data = (u_char *)env_home;
            home.len = strlen(env_home);
        }
    }

    ch->sftp_pool = s3_create_pool(S3_DEFAULT_POOL_SIZE, &s3_interop_log);

    if (ch->sftp_pool == NULL) {
        return S3_ERROR;
    }

    ch->sftp = s3_pcalloc(ch->sftp_pool, sizeof(s3_ssh3_sftp_srv_t));

    if (ch->sftp == NULL ||
        s3_ssh3_sftp_srv_init(ch->sftp, ch->sftp_pool, &home, getuid(), getgid()) != S3_OK) {
        s3_destroy_pool(ch->sftp_pool);
        ch->sftp_pool = NULL;
        return S3_ERROR;
    }

    printf("INTEROP-SFTP-OPEN home=%.*s\n", (int)home.len, (const char *)home.data);
    fflush(stdout);

    s3_interop_fwd_arm(ch);

    return S3_OK;
}

/* one drained reply batch rides the pending 94 out-buffer */

static void
s3_interop_sftp_pump(s3_interop_h3_channel_t *ch)
{
    u_char  buf[16384];
    ssize_t n;

    if (ch->sftp == NULL) {
        return;
    }

    if (ch->sftp->protocol_error) {
        s3_interop_h3_channel_cancel(ch, "sftp protocol error");
        return;
    }

    for (;;) {

        n = s3_ssh3_sftp_srv_output(ch->sftp, buf, sizeof(buf));

        if (n <= 0) {
            break;
        }

        if (s3_interop_fwd_append(&ch->fwd_out, &ch->fwd_out_cap, &ch->fwd_out_len, buf,
                                  (size_t)n) != S3_OK) {
            fprintf(stderr, "interop-server: sftp reply buffer growth failed\n");
            s3_interop_h3_channel_free(ch);
            return;
        }
    }

    s3_interop_fwd_flush(ch);
}

/*
 * the agent bridge of the wave 2 (the reference cmd/ssh3-server.go
 * openAgentSocketAndForwardAgent): the forward-agent marker creates
 * the listening socket, every accepted connection opens one
 * server-initiated "agent-connection" channel towards the client
 */

static s3_int_t
s3_interop_agent_listen(s3_interop_h3_channel_t *ch)
{
    s3_str_t path;
    s3_int_t rc;

    if (ch->agent_l != NULL) {
        return S3_OK;
    }

    ch->agent_pool = s3_create_pool(S3_DEFAULT_POOL_SIZE, &s3_interop_log);

    if (ch->agent_pool == NULL) {
        return S3_ERROR;
    }

    rc = s3_ssh3_agent_listen(ch->agent_pool, &ch->agent_l, &path);

    if (rc != S3_OK) {
        s3_destroy_pool(ch->agent_pool);
        ch->agent_pool = NULL;
        ch->agent_l = NULL;
        return S3_ERROR;
    }

    if (path.len >= sizeof(ch->agent_path)) {
        s3_destroy_pool(ch->agent_pool);
        ch->agent_pool = NULL;
        ch->agent_l = NULL;
        return S3_ERROR;
    }

    s3_memcpy(ch->agent_path, path.data, path.len);
    ch->agent_path[path.len] = '\0';

    printf("INTEROP-AGENT-READY sock=%s\n", ch->agent_path);
    fflush(stdout);

    ch->agent_timer.data = ch;
    ch->agent_timer.log = &s3_interop_log;
    ch->agent_timer.handler = s3_interop_agent_accept_timer;

    s3_event_add_timer(&ch->agent_timer, 50);

    return S3_OK;
}

/*
 * one accepted agent socket rides a fresh server-initiated channel:
 * the header quotes the CONNECT stream id, the AGENT kind of the pump
 * relays the bytes both ways (the tcp pump against the socket fd)
 */

static void
s3_interop_agent_conn_open(s3_interop_h3_channel_t *sess_ch, int fd)
{
    s3_connection_t         *pc, *nsc;
    s3_interop_h3_channel_t *nch;
    s3_quic_stream_t        *qs;
    s3_ssh3_channel_t        hdr;
    u_char                   frame[64];
    u_char                  *p;
    size_t                   total;
    ssize_t                  m;
    s3_event_t              *rev;

    pc = ((s3_quic_stream_t *)sess_ch->sc->data)->parent;

    nsc = s3_quic_open_stream(pc, 1);

    if (nsc == NULL) {
        fprintf(stderr, "interop-server: agent channel open_stream failed\n");
        s3_ssh3_agent_close_fd(fd);
        return;
    }

    nch = s3_interop_h3_channel_alloc(nsc);

    if (nch == NULL) {
        fprintf(stderr, "interop-server: agent channel table is full\n");
        (void)s3_quic_cancelable_stream(nsc);
        (void)s3_quic_shutdown_stream(nsc, S3_RDWR_SHUTDOWN);
        s3_ssh3_agent_close_fd(fd);
        return;
    }

    /*
     * the opener side: no channel header comes back, the confirm step
     * of the read path must not run (the 91 of the acceptor rides the
     * message loop instead)
     */
    nch->confirmed = 1;

    nch->fwd_fd = fd;
    nch->fwd_kind = S3_INTEROP_FWD_AGENT;

    rev = nsc->read;
    rev->handler = s3_interop_h3_channel_read;
    rev->data = nsc;
    rev->active = 1;

    s3_memzero(&hdr, sizeof(hdr));

    hdr.conversation_stream_id = s3_interop_h3_conv_id;
    hdr.max_packet_size = S3_INTEROP_CHANNEL_MAX_PACKET;
    hdr.type.data = (u_char *)S3_SSH3_CHANNEL_TYPE_AGENT;
    hdr.type.len = strlen(S3_SSH3_CHANNEL_TYPE_AGENT);

    p = frame;
    p = (u_char *)s3_ssh3_channel_build_header(p, &hdr);
    total = (size_t)(p - frame);

    m = s3_quic_stream_send(nsc, frame, total);

    if (m != (ssize_t)total) {
        fprintf(stderr, "interop-server: agent channel header send failed\n");
        s3_interop_h3_channel_free(nch);
        return;
    }

    qs = nsc->data;

    printf("INTEROP-AGENT-CONN id=%llu\n", (unsigned long long)qs->id);
    fflush(stdout);

    s3_interop_fwd_arm(nch);
}

static void
s3_interop_agent_accept_timer(s3_event_t *ev)
{
    s3_interop_h3_channel_t *ch = ev->data;
    int                      fd;

    ev->timedout = 0;

    for (;;) {

        fd = s3_ssh3_agent_accept(ch->agent_l);

        if (fd < 0) {
            /* S3_AGAIN or a failed accept: the next tick retries */
            break;
        }

        s3_interop_agent_conn_open(ch, fd);
    }

    if (ch->sc != NULL && ch->agent_l != NULL) {
        s3_event_add_timer(ev, 50);
    }
}

/* the runner marker on the open target */

static void
s3_interop_fwd_report(const s3_ssh3_forward_target_t *t, const char *kind)
{
    char        ip[64];
    const char *text;

    text = inet_ntop(t->family == 6 ? AF_INET6 : AF_INET, t->ip, ip, sizeof(ip));

    if (text == NULL) {
        text = "?";
    }

    printf("INTEROP-FWD-%s-OPEN target=%s:%u\n", kind, text, (unsigned)t->port);
    fflush(stdout);
}

/*
 * the target connect of the direct-tcp channel: the harness runs
 * against the loopback echo services, the plain blocking connect
 * (a refusal on loopback is immediate) is enough and keeps the pump
 * simple, a general server wants a non-blocking connect
 */
static s3_int_t
s3_interop_fwd_tcp_open(s3_interop_h3_channel_t *ch, const s3_ssh3_forward_target_t *t)
{
    struct sockaddr_in sa;
    int                fd;

    if (t->family != 4) {
        fprintf(stderr, "interop-server: direct-tcp: only the ipv4 targets are supported\n");
        return S3_ERROR;
    }

    s3_memzero(&sa, sizeof(sa));

    sa.sin_family = AF_INET;
    s3_memcpy(&sa.sin_addr, t->ip, 4);
    sa.sin_port = htons(t->port);

    fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd == -1) {
        return S3_ERROR;
    }

    if (connect(fd, (const struct sockaddr *)&sa, sizeof(sa)) != 0) {
        (void)close(fd);
        return S3_ERROR;
    }

    if (s3_nonblocking(fd) != S3_OK) {
        (void)close(fd);
        return S3_ERROR;
    }

    ch->fwd_fd = fd;
    ch->fwd_kind = S3_INTEROP_FWD_TCP;
    ch->fwd_sa = sa;

    s3_interop_fwd_report(t, "TCP");

    return S3_OK;
}

/*
 * the target socket of the direct-udp channel; one channel at a time
 * (the harness simplification, the datagram routing holds a single
 * target)
 */
static s3_int_t
s3_interop_fwd_udp_open(s3_interop_h3_channel_t *ch, const s3_ssh3_forward_target_t *t)
{
    struct sockaddr_in sa;
    int                fd;

    if (t->family != 4) {
        fprintf(stderr, "interop-server: direct-udp: only the ipv4 targets are supported\n");
        return S3_ERROR;
    }

    if (s3_interop_h3_udp_fwd != NULL) {
        fprintf(stderr, "interop-server: a direct-udp channel is already forwarded\n");
        return S3_ERROR;
    }

    s3_memzero(&sa, sizeof(sa));

    sa.sin_family = AF_INET;
    s3_memcpy(&sa.sin_addr, t->ip, 4);
    sa.sin_port = htons(t->port);

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (fd == -1) {
        return S3_ERROR;
    }

    if (s3_nonblocking(fd) != S3_OK) {
        (void)close(fd);
        return S3_ERROR;
    }

    ch->fwd_fd = fd;
    ch->fwd_kind = S3_INTEROP_FWD_UDP;
    ch->fwd_sa = sa;

    s3_interop_h3_udp_fwd = ch;

    s3_interop_fwd_report(t, "UDP");

    return S3_OK;
}

/*
 * the datagram of the direct-udp channel (docs/P4-WIRE.md 3.2): the
 * prefix carries the control stream and the channel ids, a datagram
 * that does not belong to the forwarded channel (the plain echo runs)
 * echoes back unchanged
 */
static void
s3_interop_udp_fwd_datagram(s3_connection_t *c, const u_char *buf, size_t len)
{
    const u_char     *pos = buf, *end = buf + len;
    uint64_t          csid, chid;
    s3_str_t          payload;
    s3_quic_stream_t *qs;

    if (s3_ssh3_dgram_parse(&pos, end, &csid, &chid, &payload) != S3_OK) {
        (void)s3_quic_send_datagram(c, buf, len);
        return;
    }

    qs = s3_interop_h3_udp_fwd->sc->data;

    if (csid != s3_interop_h3_conv_id || chid != qs->id) {
        (void)s3_quic_send_datagram(c, buf, len);
        return;
    }

    if (payload.len > 0) {
        (void)sendto(s3_interop_h3_udp_fwd->fwd_fd, payload.data, payload.len, 0,
                     (const struct sockaddr *)&s3_interop_h3_udp_fwd->fwd_sa,
                     sizeof(s3_interop_h3_udp_fwd->fwd_sa));
    }
}

static s3_int_t
s3_interop_h3_channel_confirm(s3_interop_h3_channel_t *ch)
{
    s3_connection_t                *sc = ch->sc;
    s3_quic_stream_t               *qs = sc->data;
    s3_ssh3_channel_t               hdr;
    s3_ssh3_msg_open_confirmation_t conf;
    s3_ssh3_forward_target_t        target;
    const u_char                   *pos, *end;
    u_char                          out[32];
    u_char                         *p;
    size_t                          total;
    ssize_t                         m;
    unsigned                        fwd;

    s3_memzero(&hdr, sizeof(hdr));

    pos = ch->buf;
    end = ch->buf + ch->len;

    /*
     * the header is expected in the first block (the reference writes
     * it together with the first data); a truncated block is
     * indistinguishable from a wrong frame type at this API, both are
     * S3_ERROR and both cancel the stream
     */
    if (s3_ssh3_channel_parse_header(&pos, end, &hdr) != S3_OK) {
        s3_interop_h3_channel_cancel(ch, "bad channel header");
        return S3_ERROR;
    }

    /* the receiver must verify the conversation of the channel */

    if (hdr.conversation_stream_id != s3_interop_h3_conv_id) {
        s3_interop_h3_channel_cancel(ch, "conversation mismatch");
        return S3_ERROR;
    }

    /*
     * the direct-* channels carry the target extension right after
     * the header (docs/P4-WIRE.md 2.1), the other types end there
     */
    if (s3_interop_h3_type_is(&hdr.type, S3_SSH3_CHANNEL_TYPE_DIRECT_TCP) ||
        s3_interop_h3_type_is(&hdr.type, S3_SSH3_CHANNEL_TYPE_DIRECT_UDP)) {

        fwd = 1;

        if (s3_ssh3_forward_parse_target(&pos, end, &target) != S3_OK) {
            s3_interop_h3_channel_cancel(ch, "bad channel target");
            return S3_ERROR;
        }

    } else {
        fwd = 0;
    }

    /* the 91 with our own maxPacketSize, like confirmChannel() does */

    s3_memzero(&conf, sizeof(conf));
    conf.max_packet_size = S3_INTEROP_CHANNEL_MAX_PACKET;

    p = out;
    p = (u_char *)s3_ssh3_encode_varint(p, S3_SSH3_MSG_CHANNEL_OPEN_CONFIRMATION);
    p = (u_char *)s3_ssh3_msg_encode_open_confirmation(p, &conf);
    total = (size_t)(p - out);

    m = s3_quic_stream_send(sc, out, total);

    /* the same small-volume assumption as the echo above */
    if (m != (ssize_t)total) {
        s3_interop_h3_channel_cancel(ch, "confirmation send stalled");
        return S3_ERROR;
    }

    ch->confirmed = 1;

    if (fwd) {

        s3_int_t rc;

        /*
         * the 91 is out: the target opens here, a refusal cancels the
         * channel (the opener sees the reset and fails)
         */

        rc = s3_interop_h3_type_is(&hdr.type, S3_SSH3_CHANNEL_TYPE_DIRECT_TCP)
                 ? s3_interop_fwd_tcp_open(ch, &target)
                 : s3_interop_fwd_udp_open(ch, &target);

        if (rc != S3_OK) {
            s3_interop_h3_channel_cancel(ch, "the target is unreachable");
            return S3_ERROR;
        }

        s3_interop_fwd_arm(ch);

    } else if (s3_interop_h3_type_is(&hdr.type, S3_SSH3_CHANNEL_TYPE_SFTP)) {

        /*
         * the sftp subsystem: the request server jails into the home,
         * the replies ride the 94 direction through the pump timer
         */

        if (s3_interop_sftp_start(ch) != S3_OK) {
            s3_interop_h3_channel_cancel(ch, "sftp subsystem failed");
            return S3_ERROR;
        }
    }

    printf("INTEROP-CHANNEL-ACCEPT id=%llu type=%.*s\n", (unsigned long long)qs->id,
           (int)hdr.type.len, (const char *)hdr.type.data);
    fflush(stdout);

    /* the header bytes are consumed, the type view dies here */
    ch->len = (size_t)(end - pos);
    s3_memmove(ch->buf, pos, ch->len);

    return S3_OK;
}

static void
s3_interop_h3_channel_read(s3_event_t *ev)
{
    s3_connection_t         *sc;
    s3_interop_h3_channel_t *ch;
    const u_char            *pos, *end;
    ssize_t                  n;

    sc = ev->data;

    ch = s3_interop_h3_channel_of(sc);

    if (ch == NULL) {
        /* the slot was freed by a cancel, the tail events are noise */
        return;
    }

    for (;;) {

        if (ch->len == ch->cap) {
            size_t  cap = ch->cap + 262144;
            u_char *grown = realloc(ch->buf, cap);

            if (grown == NULL) {
                fprintf(stderr, "interop-server: channel buffer growth failed\n");
                exit(1);
            }

            ch->buf = grown;
            ch->cap = cap;
        }

        n = sc->recv(sc, ch->buf + ch->len, ch->cap - ch->len);

        if (n == (ssize_t)S3_AGAIN) {
            return;
        }

        if (n == 0) {

            if (ch->fwd_kind == S3_INTEROP_FWD_AGENT) {

                /* the client side of the agent bridge is gone */

                s3_interop_h3_channel_free(ch);
                return;
            }

            if (ch->fwd_kind != S3_INTEROP_FWD_NONE) {

                /*
                 * the fin of the opener: the tcp relay shuts the write
                 * side of the target socket (the echo service answers
                 * with its own eof and the pump ends the channel), the
                 * udp channel has no eof and just ends
                 */
                if (ch->fwd_kind == S3_INTEROP_FWD_TCP) {
                    (void)shutdown(ch->fwd_fd, SHUT_WR);
                    s3_interop_fwd_pump(ch);
                    return;
                }

                s3_interop_h3_channel_free(ch);
                return;
            }

            if (ch->sftp != NULL) {

                /* the transfer peer closed: the subsystem goes with it */

                printf("SFTP-SRV-DONE\n");
                fflush(stdout);

                s3_interop_h3_channel_free(ch);
                return;
            }

            if (ch->sess != NULL && !ch->sess_exit_sent) {

                /*
                 * the FIN of the peer is the EOF of the process
                 * stdin: the module closes its input side and the
                 * pump drains the tail - the verdict goes out from
                 * the pump once the process is over, the channel
                 * lives until then
                 */
                ch->sess_peer_fin = 1;

                if (s3_ssh3_session_srv_close_input(ch->sess) != S3_OK) {
                    fprintf(stderr, "interop-server: session close_input declined\n");
                }

                s3_interop_session_pump(ch);

                return;
            }

            if (ch->sess != NULL) {
                /* the verdict is out and the peer closed its side */
                s3_interop_h3_channel_free(ch);
                return;
            }

            /* the echo mode: the peer fin shuts the stream down */
            (void)s3_quic_shutdown_stream(sc, S3_WRITE_SHUTDOWN);
            s3_interop_h3_channel_free(ch);
            return;
        }

        if (n < 0) {
            s3_interop_h3_channel_cancel(ch, "recv error");
            return;
        }

        ch->len += (size_t)n;

        if (!ch->confirmed && s3_interop_h3_channel_confirm(ch) != S3_OK) {
            /* cancelled inside */
            return;
        }

        pos = ch->buf;
        end = ch->buf + ch->len;

        while (pos < end) {

            /*
             * the message start: a message may arrive split over the
             * recvs, a failed (partial) parse rewinds here so the
             * compaction below keeps the whole frame for the next recv
             */
            const u_char *msg = pos;

            uint64_t type;

            if (s3_ssh3_parse_varint(&pos, end, &type) != S3_OK) {
                /* a partial type varint, the next recv completes it */
                pos = msg;
                break;
            }

            if (type == S3_SSH3_MSG_CHANNEL_DATA) {
                s3_ssh3_msg_data_t msg_data;

                if (s3_ssh3_msg_parse_data(&pos, end, &msg_data) != S3_OK) {
                    pos = msg;
                    break;
                }

                if (ch->fwd_kind == S3_INTEROP_FWD_TCP || ch->fwd_kind == S3_INTEROP_FWD_AGENT) {

                    /* the relay: the payload rides the target socket
                     * (the tcp target or the accepted agent socket) */

                    if (s3_interop_fwd_append(&ch->fwd_in, &ch->fwd_in_cap, &ch->fwd_in_len,
                                              msg_data.data.data, msg_data.data.len) != S3_OK) {
                        fprintf(stderr, "interop-server: forward buffer growth failed\n");
                        s3_interop_h3_channel_free(ch);
                        return;
                    }

                    s3_interop_fwd_socket_flush(ch);

                    continue;
                }

                if (ch->fwd_kind == S3_INTEROP_FWD_UDP) {

                    /* the udp channels carry the datagram path only */
                    s3_interop_h3_channel_cancel(ch, "data on a direct-udp channel");
                    return;
                }

                if (ch->sftp != NULL) {

                    /* the sftp payloads feed the request server */

                    if (getenv("S3SFTPSRV") != NULL) {

                        size_t z;

                        fprintf(stderr, "sftpsrv in %zu:", msg_data.data.len);

                        for (z = 0; z < msg_data.data.len && z < 24; z++) {
                            fprintf(stderr, " %02x", msg_data.data.data[z]);
                        }

                        fprintf(stderr, "\n");
                    }

                    if (s3_ssh3_sftp_srv_input(ch->sftp, msg_data.data.data, msg_data.data.len) !=
                        S3_OK) {
                        fprintf(stderr, "interop-server: sftp input failed\n");
                    }

                    s3_interop_sftp_pump(ch);

                    if (ch->sc == NULL) {
                        /* the pump freed the channel (a protocol error) */
                        return;
                    }

                    continue;
                }

                if (!ch->sess_intent) {

                    /*
                     * the LARVAL data of a session channel: only the
                     * forward-agent marker is defined (the reference
                     * trigger, cmd/ssh3-server.go), the listener
                     * appears and the path rides the child env at the
                     * spawn; everything else falls through to the echo
                     * (the plain -C ping)
                     */

                    if (msg_data.data.len == strlen(S3_SSH3_AGENT_TRIGGER) &&
                        s3_memcmp(msg_data.data.data, S3_SSH3_AGENT_TRIGGER, msg_data.data.len) ==
                            0) {

                        if (s3_interop_agent_listen(ch) != S3_OK) {
                            fprintf(stderr, "interop-server: agent listen failed\n");
                        }

                        continue;
                    }
                }

                else if (ch->sess != NULL && ch->sess->open) {

                    if (s3_ssh3_session_srv_input(ch->sess, msg_data.data.data,
                                                  msg_data.data.len) != S3_OK) {
                        fprintf(stderr, "interop-server: session input failed\n");
                    }

                    continue;
                }

                else {
                    fprintf(stderr, "interop-server: session data before the spawn dropped\n");
                    continue;
                }

                /* the echo mode: the data goes back unchanged */

                if (s3_interop_h3_channel_echo(sc, msg_data.data.data, msg_data.data.len) !=
                    S3_OK) {
                    s3_interop_h3_channel_cancel(ch, "echo send stalled");
                    return;
                }

                continue;
            }

            if (type == S3_SSH3_MSG_CHANNEL_EXTENDED_DATA) {
                s3_ssh3_msg_extended_data_t xmsg;

                if (s3_ssh3_msg_parse_extended_data(&pos, end, &xmsg) != S3_OK) {
                    pos = msg;
                    break;
                }

                /* the stderr side is drained, nothing echoes back */
                continue;
            }

            if (type == S3_SSH3_MSG_CHANNEL_REQUEST) {

                if (ch->fwd_kind != S3_INTEROP_FWD_NONE) {

                    /* the forward channels carry no requests */
                    s3_interop_h3_channel_cancel(ch, "request on a forward channel");
                    return;
                }

                /*
                 * the envelope parses by the message module, the body
                 * boundary walks first (no length prefix on the wire,
                 * the peers pipeline requests in one write) and the
                 * exact span validates through the request module
                 */
                s3_ssh3_msg_request_t  env;
                s3_ssh3_request_t      req;
                const u_char          *bpos, *bend;
                s3_ssh3_request_kind_t kind;

                if (s3_ssh3_msg_parse_request_envelope(&pos, end, &env) != S3_OK) {
                    /* a partial envelope, the next recv completes it */
                    pos = msg;
                    break;
                }

                if (s3_ssh3_request_kind_of(&env.request_type, &kind) != S3_OK) {

                    /*
                     * an unknown request type: its body has no
                     * boundary on the wire, the buffer tail drains
                     * (the known peers send none)
                     */
                    fprintf(stderr, "interop-server: unknown request type %.*s\n",
                            (int)env.request_type.len, (const char *)env.request_type.data);
                    pos = end;
                    continue;
                }

                bend = s3_interop_request_body_end(kind, pos, end);

                if (bend == NULL) {
                    /* a partial body, the next recv completes it */
                    pos = msg;
                    break;
                }

                bpos = pos;

                if (s3_ssh3_request_parse_body(&bpos, bend, &env.request_type, &req) != S3_OK) {
                    /* the walked span must parse, else the stream desynced */
                    s3_interop_h3_channel_cancel(ch, "bad request body");
                    return;
                }

                pos = bend;

                switch (kind) {

                case S3_SSH3_REQ_PTY:

                    if (s3_interop_session_start(ch) != S3_OK ||
                        s3_ssh3_session_srv_pty_req(ch->sess, &req.u.pty.term, req.u.pty.width,
                                                    req.u.pty.height, req.u.pty.pixel_width,
                                                    req.u.pty.pixel_height,
                                                    &req.u.pty.modes) != S3_OK) {
                        fprintf(stderr, "interop-server: pty-req failed\n");
                        break;
                    }

                    ch->sess_intent = 1;

                    printf("INTEROP-SESSION-PTY\n");
                    fflush(stdout);

                    break;

                case S3_SSH3_REQ_EXEC:

                    if (s3_interop_session_start(ch) != S3_OK ||
                        s3_ssh3_session_srv_exec(ch->sess, s3_interop_session_shell(),
                                                 &req.u.exec.command) != S3_OK) {
                        fprintf(stderr, "interop-server: exec failed\n");
                        break;
                    }

                    ch->sess_intent = 1;

                    printf("INTEROP-SESSION-EXEC\n");
                    fflush(stdout);

                    s3_interop_session_arm(ch);
                    s3_interop_session_pump(ch);

                    break;

                case S3_SSH3_REQ_SHELL:

                    /*
                     * the harness gate: a bare shell request stays in
                     * the echo mode (the ping channel of the runner
                     * lives on it), the session spawns once a pty-req
                     * or an exec announced the intent - the module
                     * itself spawns on any shell per the contract
                     */
                    if (!ch->sess_intent) {
                        fprintf(stderr, "interop-server: shell without the session intent\n");
                        break;
                    }

                    if (s3_interop_session_start(ch) != S3_OK ||
                        s3_ssh3_session_srv_shell(ch->sess, s3_interop_session_shell()) != S3_OK) {
                        fprintf(stderr, "interop-server: shell failed\n");
                        break;
                    }

                    printf("INTEROP-SESSION-SHELL\n");
                    fflush(stdout);

                    s3_interop_session_arm(ch);
                    s3_interop_session_pump(ch);

                    break;

                case S3_SSH3_REQ_WINDOW_CHANGE:

                    if (ch->sess == NULL ||
                        s3_ssh3_session_srv_window_change(
                            ch->sess, req.u.window_change.width, req.u.window_change.height,
                            req.u.window_change.pixel_width,
                            req.u.window_change.pixel_height) != S3_OK) {
                        fprintf(stderr, "interop-server: window-change declined\n");
                    }

                    break;

                case S3_SSH3_REQ_SIGNAL:

                    if (ch->sess == NULL ||
                        s3_ssh3_session_srv_signal(ch->sess, &req.u.signal.name) != S3_OK) {
                        fprintf(stderr, "interop-server: signal declined\n");
                    }

                    break;

                default:
                    /* subsystem/x11/exit-*: the server never runs them */
                    fprintf(stderr, "interop-server: request %.*s ignored\n",
                            (int)env.request_type.len, (const char *)env.request_type.data);
                    break;
                }

                continue;
            }

            if (type == S3_SSH3_MSG_CHANNEL_OPEN_CONFIRMATION &&
                ch->fwd_kind == S3_INTEROP_FWD_AGENT) {

                /*
                 * the 91 of the acceptor side on the server-initiated
                 * agent channels: consume and move on
                 */

                s3_ssh3_msg_open_confirmation_t conf;

                if (s3_ssh3_msg_parse_open_confirmation(&pos, end, &conf) != S3_OK) {
                    pos = msg;
                    break;
                }

                continue;
            }

            s3_interop_h3_channel_cancel(ch, "unknown channel message");
            return;
        }

        /* the consumed bytes compact to the front of the buffer */
        ch->len = (size_t)(end - pos);
        s3_memmove(ch->buf, pos, ch->len);

        /*
         * the session output rides along: the input just fed may have
         * woken the process, the pump answers with the fresh bytes
         * (the second trigger is the 50 ms timer armed at the spawn)
         */
        s3_interop_session_pump(ch);
    }
}

static void
s3_interop_h3_channel_accept(s3_connection_t *sc)
{
    s3_interop_h3_channel_t *ch;
    s3_event_t              *rev;
    unsigned                 i;

    ch = NULL;

    for (i = 0; i < S3_INTEROP_TRACKED; i++) {

        if (s3_interop_h3_channels[i].sc == NULL) {
            ch = &s3_interop_h3_channels[i];
            break;
        }
    }

    if (ch == NULL) {
        fprintf(stderr, "interop-server: channel table is full\n");
        (void)s3_quic_cancelable_stream(sc);
        (void)s3_quic_shutdown_stream(sc, S3_RDWR_SHUTDOWN);
        return;
    }

    s3_memzero(ch, sizeof(*ch));
    ch->sc = sc;
    ch->fwd_fd = -1;

    rev = sc->read;

    rev->handler = s3_interop_h3_channel_read;
    rev->data = sc;

    /*
     * the app-level read arming, the s3 analog of the reference
     * ngx_handle_read_event(): without it s3_quic_set_event() only
     * raises ready and never posts the data events
     */
    rev->active = 1;

    /*
     * the write side stays unarmed: the echo treats a send stall as a
     * hard error, no tail flushes on the write events
     */

    /*
     * the first STREAM frame ran before this handler: its data sits
     * in the receive buffer with ready raised, and the event was lost
     * on the not yet armed active flag; the reference app reads right
     * in the accept path (ngx_http_v3_wait_request_handler())
     */
    if (rev->ready) {
        rev->handler(rev);
    }
}

static void
s3_interop_h3_accept(s3_connection_t *c, s3_quic_stream_t *qs)
{
    s3_connection_t *sc, *pc;
    s3_event_t      *rev, *wev;

    /*
     * ssh3-c: the stream_handler receives the stream connection (its
     * data is the s3_quic_stream_t, the reference sc->quic); the h3
     * session hangs on the parent's data pointer, so the parent
     * resolves through qs
     */
    sc = c;
    pc = qs->parent;

    if (s3_h3_get_session(pc) == NULL) {

        /*
         * the first stream of the connection brings up the h3 session
         * once; the control stream with our SETTINGS goes out from
         * inside s3_h3_init_session()
         */
        if (s3_h3_init_session(pc) != S3_OK) {
            fprintf(stderr, "interop-server: h3 init_session failed\n");
            return;
        }
    }

    if (qs->id & 0x2) {

        /*
         * ssh3-c: the uni stream goes to the session port; the port
         * reads the stream connection's data as the s3_quic_stream_t
         * (the working brief said the parent, the landed port of
         * s3_h3_init_stream() expects the stream connection)
         */
        s3_h3_init_stream(sc);
        return;
    }

    if (s3_interop_h3_sc != NULL && pc == s3_interop_h3_pc) {

        /*
         * every bidi stream after the CONNECT is an ssh3 channel
         * (docs/P4-WIRE.md 1, the server dispatch rule); the pc
         * check keeps a SECOND client connection on the fresh
         * CONNECT path below - the harness serves them one after
         * another out of one process (the sftp put/get pair)
         */
        s3_interop_h3_channel_accept(sc);
        return;
    }

    s3_interop_h3_sc = sc;
    s3_interop_h3_pc = pc;
    s3_interop_h3_conv_id = qs->id;
    s3_interop_h3_responded = 0;
    s3_interop_h3_len = 0;
    s3_interop_h3_out_len = 0;
    s3_interop_h3_method_len = 0;
    s3_interop_h3_protocol_len = 0;
    s3_interop_h3_path_len = 0;
    s3_interop_h3_auth_len = 0;

    s3_memzero(&s3_interop_h3_parse, sizeof(s3_h3_parse_headers_t));

    rev = sc->read;
    wev = sc->write;

    rev->handler = s3_interop_h3_request_read;
    rev->data = sc;

    /*
     * the app-level read arming, the s3 analog of the reference
     * ngx_handle_read_event(): without it s3_quic_set_event() only
     * raises ready and never posts the data events
     */
    rev->active = 1;

    wev->handler = s3_interop_h3_stream_write;
    wev->data = sc;
    wev->active = 1;

    /*
     * the first STREAM frame ran before this handler: its data sits
     * in the receive buffer with ready raised, and the event was lost
     * on the not yet armed active flag; the reference app reads right
     * in the accept path (ngx_http_v3_wait_request_handler())
     */
    if (rev->ready) {
        rev->handler(rev);
    }
}

static void
s3_interop_stream_accept(s3_connection_t *c, s3_quic_stream_t *qs)
{
    s3_event_t *rev, *wev;

    if (s3_interop_h3_mode) {
        s3_interop_h3_accept(c, qs);
        return;
    }

    (void)c;

    s3_interop_echo_sc = qs->connection;
    s3_interop_echo_len = 0;
    s3_interop_echo_off = 0;
    s3_interop_echo_fin = 0;
    s3_interop_echo_read_total = 0;
    s3_interop_echo_reads = 0;

    rev = qs->connection->read;
    wev = qs->connection->write;

    rev->handler = s3_interop_stream_read;
    rev->data = qs->connection;

    /*
     * the app-level read arming, the s3 analog of the reference
     * ngx_handle_read_event(): without it s3_quic_set_event() only
     * raises ready and never posts the data events
     */
    rev->active = 1;

    wev->handler = s3_interop_stream_write;
    wev->data = qs->connection;
    wev->active = 1;

    /*
     * the first STREAM frame ran before this handler: its data sits
     * in the receive buffer with ready raised, and the event was lost
     * on the not yet armed active flag; the reference app reads right
     * in the accept path (ngx_http_v3_wait_request_handler())
     */
    if (rev->ready) {
        rev->handler(rev);
    }
}

static void
s3_interop_accept(s3_connection_t *c)
{
    if (s3_interop_nconns < S3_INTEROP_TRACKED) {
        s3_interop_conns[s3_interop_nconns] = c;
        s3_interop_reported[s3_interop_nconns] = 0;
        s3_interop_nconns++;
    }

    s3_quic_run(c, &s3_interop_conf);
}

static void
s3_interop_usage(const char *prog)
{
    fprintf(stderr,
            "usage: %s -l addr:port -c cert.pem -k key.pem [-3] [-A alpn] [-d dg_size]"
            " [-P pwfile] [-K keysfile] [-H dir]\n"
            "  -l  UDP listen address, port 0 picks an ephemeral one\n"
            "  -c  certificate PEM file\n"
            "  -k  private key PEM file\n"
            "  -3  h3 mode: RFC 9220 extended CONNECT (ssh3) instead of the echo\n"
            "  -A  ALPN name, default s3interop/1 (h3 in the -3 mode)\n"
            "  -d  max_datagram_frame_size transport parameter, default 1200\n"
            "  -P  password file: the CONNECT passes only with the Basic"
            " user:secret (h3 mode)\n"
            "  -K  authorized_keys file: the CONNECT passes only with a Bearer JWT"
            " signed by\n"
            "      one of its keys; %%u in the path is the session username"
            " (h3 mode)\n"
            "  -H  the sftp jail directory override, default the user's home"
            " (h3 mode)\n"
            "  --oidc-issuer url --oidc-audience id: the CONNECT passes only"
            " with the Bearer id_token of that provider (h3 mode, the"
            " S3_OIDC_CA_FILE env pins the https trust)\n"
            "  --oidc-jwks-ttl seconds: the key set lifetime of the oidc"
            " provider, default 3600 (h3 mode)\n",
            prog);
}

int
main(int argc, char **argv)
{
    char               opt;
    const char        *listen_text = NULL, *cert_path = NULL, *key_path = NULL;
    const char        *alpn_name = "s3interop/1";
    unsigned           dg_size = 1200, idle_ms = 60000;
    u_char            *cert, *key, alpn_wire[256];
    size_t             cert_len = 0, key_len = 0;
    s3_str_t           alpn;
    s3_int_t           rc;
    s3_uint_t          i;
    s3_fd_t            fd;
    struct sockaddr_in sa;
    socklen_t          sa_len;
    s3_event_ctx_t     ctx;
    s3_connection_t   *listener;
    s3_udp_listen_t    ul;

    s3_interop_log_init();

    s3_interop_force_early = (getenv("S3_H3_FORCE_EARLY") != NULL);

    /*
     * the OIDC options ride the long form (the daemon keeps the
     * names), the pre-scan pulls them out of argv before the short
     * getopt loop
     */

    {
        int   i, j, keep;
        char *value;

        for (i = 1; i < argc;) {

            keep = 1;
            value = NULL;

            if (strcmp(argv[i], "--oidc-issuer") == 0 && i + 1 < argc) {
                s3_interop_oidc_issuer = argv[i + 1];
                value = argv[i + 1];

            } else if (strcmp(argv[i], "--oidc-audience") == 0 && i + 1 < argc) {
                snprintf(s3_interop_oidc_aud, sizeof(s3_interop_oidc_aud), "%s", argv[i + 1]);
                value = argv[i + 1];

            } else if (strcmp(argv[i], "--oidc-jwks-ttl") == 0 && i + 1 < argc) {
                s3_interop_oidc_ttl = (time_t)atoi(argv[i + 1]);
                value = argv[i + 1];
            }

            if (value != NULL) {

                /* the option and its value leave the argv */

                for (j = i; j + 2 < argc; j++) {
                    argv[j] = argv[j + 2];
                }

                argc -= 2;
                keep = 0;
            }

            if (keep) {
                i++;
            }
        }
    }

    while ((opt = (char)getopt(argc, argv, "l:c:k:A:d:i:L:P:H:K:3h")) != -1) {

        switch (opt) {

        case 'l':
            listen_text = optarg;
            break;

        case 'c':
            cert_path = optarg;
            break;

        case 'k':
            key_path = optarg;
            break;

        case 'A':
            alpn_name = optarg;
            break;

        case 'd':
            dg_size = (unsigned)atoi(optarg);
            break;

        case 'i':
            idle_ms = (unsigned)atoi(optarg);
            break;

        case 'L':
            s3_interop_log.log_level =
                (strcmp(optarg, "all") == 0) ? S3_LOG_DEBUG_ALL : (s3_uint_t)atol(optarg);
            break;

        case 'P':
            s3_interop_passfile = optarg;
            break;

        case 'K':
            s3_interop_keyfile = optarg;
            break;

        case 'H':
            snprintf(s3_interop_sftp_home, sizeof(s3_interop_sftp_home), "%s", optarg);
            break;

        case '3':
            s3_interop_h3_mode = 1;
            break;

        default:
            s3_interop_usage(argv[0]);
            return 1;
        }
    }

    if (listen_text == NULL || cert_path == NULL || key_path == NULL) {
        s3_interop_usage(argv[0]);
        return 1;
    }

    /*
     * ssh3-c: the h3 peers negotiate the h3 ALPN (the Go harness pins
     * http3.NextProtoH3); an explicit -A still wins
     */
    if (s3_interop_h3_mode && strcmp(alpn_name, "s3interop/1") == 0) {
        alpn_name = "h3";
    }

    if (s3_interop_parse_addr(listen_text, &sa) != S3_OK) {
        fprintf(stderr, "interop-server: bad listen address %s\n", listen_text);
        return 1;
    }

    /* the verifier inits here: the timer below and the first token
     * share the ready state, the discovery stays lazy */

    if (s3_interop_oidc_issuer != NULL) {
        if (s3_ssh3_oidc_verifier_init(&s3_interop_oidc_ver, s3_interop_oidc_issuer,
                                       getenv("S3_OIDC_CA_FILE")) != S3_OK) {
            fprintf(stderr, "interop-server: oidc verifier init failed for issuer %s\n",
                    s3_interop_oidc_issuer);
            return 1;
        }

        s3_ssh3_oidc_verifier_set_ttl(&s3_interop_oidc_ver, s3_interop_oidc_ttl);
    }

    cert = s3_interop_read_file(cert_path, &cert_len);
    key = s3_interop_read_file(key_path, &key_len);

    if (cert == NULL || key == NULL) {
        return 1;
    }

    if (s3_event_ctx_init(&ctx, &s3_interop_log) != S3_OK) {
        fprintf(stderr, "interop-server: event ctx init failed\n");
        return 1;
    }

    /* the jwks timer: the ttl rotation and the unknown-kid refetch */

    if (s3_interop_oidc_issuer != NULL) {
        s3_memzero(&s3_interop_oidc_timer, sizeof(s3_interop_oidc_timer));
        s3_interop_oidc_timer.handler = s3_interop_oidc_timer_handler;
        s3_interop_oidc_timer.log = &s3_interop_log;

        s3_event_add_timer(&s3_interop_oidc_timer,
                           s3_ssh3_oidc_verifier_fetch_timer(&s3_interop_oidc_ver, time(NULL)));
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        perror("socket");
        return 1;
    }

    if (s3_nonblocking(fd) != S3_OK) {
        perror("fcntl(O_NONBLOCK)");
        return 1;
    }

    /*
     * the session children fork this socket: the exec closes it so
     * the shell commands of the scenarios never hold the listener
     * (the epoll fd of the ctx leaks into the children the same way,
     * harmless for the short-lived harness commands)
     */
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
        perror("fcntl(FD_CLOEXEC)");
        return 1;
    }

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
        perror("bind");
        return 1;
    }

    sa_len = sizeof(sa);

    if (getsockname(fd, (struct sockaddr *)&sa, &sa_len) == -1) {
        perror("getsockname");
        return 1;
    }

    printf("INTEROP-LISTEN port=%u\n", (unsigned)ntohs(sa.sin_port));
    fflush(stdout);

    listener = s3_get_connection(&ctx, fd);
    if (listener == NULL) {
        fprintf(stderr, "interop-server: connection alloc failed\n");
        return 1;
    }

    listener->sockaddr = (struct sockaddr *)s3_palloc(ctx.pool, sa_len);
    if (listener->sockaddr == NULL) {
        return 1;
    }

    s3_memcpy(listener->sockaddr, &sa, sa_len);
    listener->socklen = sa_len;

    s3_interop_alpn_wire(alpn_wire, alpn_name);

    alpn.data = alpn_wire;
    alpn.len = 1 + strlen(alpn_name);

    s3_memzero(&s3_interop_conf, sizeof(s3_quic_conf_t));

    s3_interop_conf.ssl = s3_ssl_create(&s3_interop_log, (const char *)cert, cert_len,
                                        (const char *)key, key_len, &alpn);

    /*
     * the pem buffers served their purpose: s3_ssl_create() loaded the
     * x509 and the key into the ssl ctx through read-only BIO views,
     * nothing retains the pointers - free them here, the long server
     * runs and the leak checks at exit stay silent
     */
    free(cert);
    free(key);

    if (s3_interop_conf.ssl == NULL) {
        fprintf(stderr, "interop-server: ssl init failed\n");
        return 1;
    }

    s3_interop_conf.gso_enabled = 1;
    s3_interop_conf.ctx = &ctx;
    s3_interop_conf.handshake_timeout = 30000;
    s3_interop_conf.idle_timeout = (s3_msec_t)idle_ms;
    s3_interop_conf.stream_buffer_size = 16384;
    s3_interop_conf.max_concurrent_streams_bidi = 16;
    s3_interop_conf.max_concurrent_streams_uni = 16;
    s3_interop_conf.active_connection_id_limit = 8;
    s3_interop_conf.max_datagram_frame_size = dg_size;
    s3_interop_conf.datagram_handler = s3_interop_datagram_echo;
    s3_interop_conf.stream_handler = s3_interop_stream_accept;

    if (RAND_bytes(s3_interop_conf.av_token_key, S3_QUIC_AV_KEY_LEN) != 1 ||
        RAND_bytes(s3_interop_conf.sr_token_key, S3_QUIC_SR_KEY_LEN) != 1) {
        fprintf(stderr, "interop-server: RAND_bytes failed\n");
        return 1;
    }

    /* the quic listener: the rbtree is keyed by the packet dcid */

    s3_memzero(&ul, sizeof(ul));

    ul.connection = listener;
    ul.ctx = &ctx;
    ul.handler = s3_interop_accept;
    ul.quic = 1;

    s3_rbtree_init(&ul.rbtree, &ul.sentinel, s3_quic_rbtree_insert_socket);

    listener->data = &ul;
    listener->read->handler = s3_event_recvmsg;

    rc = s3_event_actions.add_event(listener->read, S3_READ_EVENT, 0);
    if (rc != S3_OK) {
        fprintf(stderr, "interop-server: add_event failed\n");
        return 1;
    }

    for (;;) {
        s3_event_process_posted(&ctx, &ctx.posted_events);

        s3_process_events_and_timers(&ctx);

        for (i = 0; i < s3_interop_nconns; i++) {
            s3_connection_t *c = s3_interop_conns[i];

            if (!s3_interop_reported[i] && c->ssl != NULL && c->ssl->handshaked) {
                printf("INTEROP-HANDSHAKE-OK\n");
                fflush(stdout);

                s3_interop_reported[i] = 1;
            }

            /* the idle-timeout probe: the silent teardown is visible
             * as the quic socket vanishing from the connection */
            if (!s3_interop_idle_reported[i] && s3_interop_reported[i] && c->udp == NULL) {
                printf("INTEROP-IDLE-CLOSE\n");
                fflush(stdout);

                s3_interop_idle_reported[i] = 1;
            }
        }
    }
}
