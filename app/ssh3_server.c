/*
 * Copyright (C) 2026 the ssh3-c authors
 */

/*
 * the ssh3-server daemon (P6.5): the production shape of the ssh3
 * route over HTTP/3 (RFC 9220 extended CONNECT), wired from the same
 * s3core + ssh3 modules as the interop harness
 * (interop/interop_server.c, the wiring is duplicated by design, the
 * harness stays the runner-controlled peer of the matrix).
 *
 * the conversation wiring follows docs/P4-WIRE.md: the uni streams
 * are handed to the session port (s3_h3_init_stream()), the first
 * bidi stream runs the extended CONNECT validator below and every
 * later bidi stream is an ssh3 channel: the header is checked, 91
 * goes back and the channel carries either the 94 echo or the server
 * session - the requests spawn a process through s3_ssh3_session_srv,
 * the process output rides back as 94/95 and the verdict is the 98
 * exit-status.  The direct-tcp / direct-udp channels relay the
 * traffic to the target, "sftp" channels run the request server and
 * the forward-agent marker opens the agent bridge.
 *
 * the CONNECT verdict runs the auth chain of the reference
 * (cmd/ssh3-server.go): the OIDC id_token (--oidc-issuer, the
 * discovery and the JWKS bootstrap at the startup), the Bearer JWT
 * signed by an authorized_keys key (-K) or the Basic credentials
 * (-P); the 200 answer carries the Server field the Go client parses
 * before it opens the conversation
 *
 * production semantics:
 *   - the logs are s3_log one-liners on stderr (journald-friendly);
 *     the machine-readable runner markers ride stdout only under
 *     SSH3C_PROTO=1
 *   - SIGTERM/SIGINT start the graceful shutdown: new quic
 *     connections are answered with CONNECTION_CLOSE, the active
 *     conversations run up to SSH3_SHUTDOWN_DRAIN seconds (default
 *     5, 0 closes immediately, the fork parity), then the remaining
 *     ones are closed, the session children are killed and the
 *     daemon exits 0; a repeated signal closes everything at once
 *   - systemd socket activation (sd_listen_fds(3)): with the
 *     LISTEN_PID/LISTEN_FDS markers present the daemon serves the
 *     passed UDP socket (fd 3) and never binds -l, the .socket unit
 *     owns the port and the service runs unprivileged
 *
 * the env of the reference (cmd/ssh3-server.go): SSH3_LOG_LEVEL,
 * SSH3_LOG_FILE, SSH3_SHUTDOWN_DRAIN
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
#include <strings.h>
#include <sys/resource.h>
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
#include <s3_ssh3_dos_guard.h>
#include <s3_ssh3_forward.h>
#include <s3_ssh3_forward_policy.h>
#include <s3_ssh3_message.h>
#include <s3_ssh3_oidc.h>
#include <s3_ssh3_request.h>
#include <s3_ssh3_reverse.h>
#include <s3_ssh3_session_srv.h>
#include <s3_ssh3_sftp_jail.h>
#include <s3_ssh3_sftp_srv.h>
#include <s3_ssh3_version.h>
#include <s3_ssh3_wire.h>
#include <s3_ssl.h>

#define S3_SRV_TRACKED 64

/*
 * the channel maxPacketSize of the reference, 30000 on both sides
 * (docs/P4-WIRE.md 5); it caps what a peer may put into one 94
 */
#define S3_SRV_CHANNEL_MAX_PACKET 30000

/*
 * the accumulation bound of one channel stream (S2-01, the pass-2
 * audit): a peer trickling bytes that never complete a message must
 * not grow the receive buffer forever; the largest legit message is
 * the locally advertised maxPacketSize plus the header and frame
 * overheads, everything past the bound is a protocol violation
 */
#define S3_SRV_CHANNEL_BUF_MAX (S3_SRV_CHANNEL_MAX_PACKET + 1024)

/*
 * the same bound for the h3 request buffer: the CONNECT request with
 * its auth headers is a few KiB at worst, an endless request never
 * completes and is torn down instead of growing the heap
 */
#define S3_SRV_H3_BUF_MAX 65536

/*
 * the flush grace after the drain ends: the queued frames of the
 * finished channels (the 98 verdicts, the stream fins) ride the next
 * event passes before the CONNECTION_CLOSE goes out
 */
#define S3_SRV_FLUSH_GRACE 500

/*
 * the close grace after the drain timeout: the CONNECTION_CLOSE
 * frames of the force-closed connections ride the next event passes,
 * the bound keeps a stuck peer from holding the shutdown
 */
#define S3_SRV_CLOSE_GRACE 500

static s3_log_t s3_srv_log;

static s3_quic_conf_t s3_srv_conf;

/*
 * the tracked connections; the pool cleanup of a connection nulls
 * its slot when the quic pool dies, so the main loop never touches a
 * freed connection
 */
static s3_connection_t *s3_srv_conns[S3_SRV_TRACKED];
static unsigned         s3_srv_reported[S3_SRV_TRACKED];
static unsigned         s3_srv_idle_reported[S3_SRV_TRACKED];

/*
 * the graceful shutdown state: the signal handler only raises the
 * counter, the main loop does the work (the async-signal-safe
 * split); the counter above 2 means the operator repeated the signal
 * and the drain ends at once
 */
static volatile sig_atomic_t s3_srv_quit;
static unsigned              s3_srv_draining;
static s3_msec_t             s3_srv_drain_deadline;
static s3_msec_t             s3_srv_drain_ms = 5000;

/*
 * the drain deadline wake: the event-driven session pump removed the
 * periodic transport tick, a conversation can sit with no timers and
 * no socket events at all (a wedged exec writes nothing), the loop
 * would sleep in epoll past the deadline - this one-shot timer is
 * the wake the drain timeout check rides
 */
static s3_event_t s3_srv_drain_timer;

/*
 * the runner protocol markers (INTEROP-*) ride stdout under
 * SSH3C_PROTO=1 only; the production runs log one-liners instead
 */
static unsigned s3_srv_proto_mode;

/*
 * the password file (-P): the CONNECT passes only with the correct
 * Basic credentials against its user:secret lines; the password login
 * rides on by default (the PasswordAuthentication yes of the sshd
 * canon, the wave 1e; the enablePasswordLogin true of the fork), the
 * explicit off rides --enable-password-login off or
 * SSH3_ENABLE_PASSWORD_LOGIN=0
 */
static const char *s3_srv_passfile;
static unsigned    s3_srv_password_enabled = 1;

/*
 * the system account verifier (--password-system on|off, PLAN.md
 * 8.2, the parity of the fork 0.1.34 password login): the Basic
 * credentials verify against the unix accounts - getpwnam(3) for the
 * identity, the shadow entry for the hash, the crypt(3) check for
 * the verdict.  The default is on (the PasswordAuthentication yes of
 * the sshd canon, the wave 1e), the operator turns it off with the
 * explicit flag or SSH3_PASSWORD_SYSTEM=0: turning it off closes the
 * system accounts to the Basic brute-force surface (the lockout books
 * the same way as for the file backend); the chain order is the -P
 * file first, the system accounts second; the unprivileged daemon
 * cannot read the shadow - the flag warns at the startup and every
 * attempt fails closed
 */
static unsigned s3_srv_password_system = 1;

/*
 * the authorized_keys files (-K, repeatable): the CONNECT passes only
 * with a Bearer JWT signed by one of their keys; a %u token is the
 * session username (the sshd AuthorizedKeysFile shape), a path
 * without it is one file for every user; without any -K the Bearer
 * JWT verifies against the default chain of the session user
 * (~/.ssh3/authorized_identities then ~/.ssh/authorized_keys, the
 * reference DefaultIdentitiesFileNames())
 */
#define S3_SRV_KEYFILES_MAX 8

static const char *s3_srv_keyfiles[S3_SRV_KEYFILES_MAX];
static unsigned    s3_srv_keyfiles_n;

/*
 * the CONNECT route (--url-path): the reference -url-path default,
 * the query part after it carries the auth username
 */
static char   s3_srv_url_path[256] = "/ssh3-term";
static size_t s3_srv_url_path_len = sizeof("/ssh3-term") - 1;

/*
 * the per-session setuid mode (P7.3, --run-as-user on|off): the
 * privileged daemon drops every session with a resolvable CONNECT
 * username onto that identity (the OpenSSH/Go shape); on by default
 * for the euid 0, the unprivileged run keeps the daemon identity
 */
static unsigned s3_srv_run_as;
static unsigned s3_srv_run_as_set; /* the explicit on|off of the CLI */

/*
 * the authenticated username of the current CONNECT: the verdict
 * snapshot fills it (the resolution gate answers the 401 there), the
 * session channels spawn from it; empty keeps the daemon identity -
 * the CONNECTs without a session user (the harness shapes, the oidc
 * identity) ride it
 */
static char s3_srv_auth_user[128];

/*
 * the OIDC issuer mode (--oidc-issuer): the CONNECT passes only with
 * the Bearer id_token of that provider, the audience is the client
 * id of the token, the nonce binds the token to the conversation
 * (the reference authorized_identities OpenIDConnectIdentity); the
 * discovery and the first key set run once at the startup, before
 * the sockets open - the lazy fallback would run the blocking https
 * inside the event loop on the first CONNECT; the rotation and the
 * unknown-kid refetch ride the timer below, the request path never
 * fetches
 */
static const char             *s3_srv_oidc_issuer;
static char                    s3_srv_oidc_aud[128];
static time_t                  s3_srv_oidc_ttl;
static s3_ssh3_oidc_verifier_t s3_srv_oidc_ver;
static s3_event_t              s3_srv_oidc_timer;

/*
 * the sftp jail override (-H): the harness scenarios point it into
 * their workdir so the runs do not touch the real home
 */
static char s3_srv_sftp_home[512];

/*
 * the forward target policy (--permit-open / SSH3_PERMIT_OPEN, the
 * F-05 PermitOpen analog): the direct-tcp and direct-udp dials pass
 * only the targets it allows; the empty default keeps the historical
 * unrestricted dial (the zero policy of the module)
 */
static s3_ssh3_forward_policy_t s3_srv_fwd_policy;

/*
 * the sftp isolation mode (the F-04 fix, --sftp-jail chroot|lexical):
 * the chroot rides the sshd model - one forked child per channel
 * enters the jail and drops before any user path opens, the kernel
 * confines the paths; lexical keeps the historical in-process
 * engine.  The default is chroot, the unprivileged runs fold to
 * lexical at the startup (no chroot privilege, the harness shapes
 * stay untouched)
 */
static unsigned s3_srv_sftp_chroot = 1;

/*
 * the concurrent sftp sessions per authenticated user (S2-02, the
 * pass-2 audit, --max-sftp-sessions-per-user): every sftp channel
 * holds one slot of its user's budget for its lifetime (the chroot
 * child or the in-process engine alike), over the cap the channel is
 * refused before any fork.  0 disables the budget.  The per-user
 * table is small: the daemon serves one conversation at a time, the
 * extra entries exist for the shape only
 */
#define S3_SRV_SFTP_BUDGET_USERS 16
#define S3_SRV_SFTP_USER_MAX     127

static unsigned s3_srv_sftp_cap = 16;

typedef struct {
    char     user[S3_SRV_SFTP_USER_MAX + 1];
    unsigned n; /* the live sftp channels of the user */
} s3_srv_sftp_budget_t;

static s3_srv_sftp_budget_t s3_srv_sftp_budgets[S3_SRV_SFTP_BUDGET_USERS];

/* the CONNECTs without a user serve under the daemon identity, their
 * budget lives in its own counter (the empty key never occupies a
 * table slot) */

static unsigned s3_srv_sftp_budget_none;

/*
 * the concurrent QUIC connections (S2-06, --max-connections): over
 * the cap the new connection answers CONNECTION_CLOSE at once, 0
 * (the default) keeps the historical unbounded behavior
 */
static int s3_srv_max_conns = 0;

/*
 * the handshake timeout in ms (S2-06, --handshake-timeout-ms): the
 * LoginGraceTime 120 s of the sshd canon, the ssh2HandshakeTimeout
 * 120 s mirror of the fork (cmd/ssh3.go)
 */

static int s3_srv_hs_ms = 120000;

/*
 * the reverse forward (-R) DoS guards (S2-04, the pass-2 audit
 * grafted onto the new binds, the reference cmd/reverse_forward_server.go
 * maxForwardedChannelsPerConversation and maxReverseForwardsPerUser):
 *
 *   - at most S3_SRV_REVERSE_LISTENERS_MAX bound listeners ride one
 *     conversation (the reference books 10 per authenticated user
 *     across their conversations, the C daemon serves one
 *     conversation per bookkeeping slot, the denial shape is the
 *     same: the slot is taken after the policy passed, so a refused
 *     request never consumes one)
 *   - at most S3_SRV_REVERSE_FORWARDED_MAX server-initiated
 *     forwarded-* channels stay open per conversation, over the cap
 *     the accepted connection is dropped (the datagram the same)
 *
 * the reference carries both knobs behind flags/env (-max-reverse-
 * forwards, SSH3_MAX_REVERSE_FORWARDS); the C shape keeps the
 * per-conversation constant pinned and wires the per-user knob as
 * --max-reverse-forwards / SSH3_MAX_REVERSE_FORWARDS, the default 10
 * mirrors the fork (the wave 1d of the ssh2 canon), the explicit 0
 * stays unbounded, the conversation constant stays on top
 */

#define S3_SRV_REVERSE_LISTENERS_MAX 10
#define S3_SRV_REVERSE_FORWARDED_MAX 64

/*
 * the per-listener peer table of the udp listeners: one
 * forwarded-udp channel per remote peer, the map is fixed and the
 * peers over it drop their datagrams (the same lossy shape as the
 * direct-udp path)
 */

#define S3_SRV_REVERSE_UDP_PEERS_MAX 8

/*
 * the reverse forward (-R) state of the conversation: the listener
 * table fills on the "reverse-forward" control channel requests, the
 * listeners and their channels die with the conversation (the
 * conv-id change and the dead quic connection both tear the state
 * down, the ticks self-check)
 */

typedef struct s3_srv_reverse_peer_s s3_srv_reverse_peer_t;

struct s3_srv_reverse_peer_s {
    unsigned           used;
    s3_connection_t   *sc; /* the forwarded-udp channel */
    struct sockaddr_in from;
    socklen_t          from_len;
};

typedef struct {
    unsigned                 used;
    unsigned                 proto; /* S3_SSH3_REVERSE_PROTO_TCP/UDP */
    int                      fd;    /* the listening/bound socket */
    s3_event_t               timer; /* the accept / recvfrom tick */
    uint16_t                 bound_port;
    s3_ssh3_forward_target_t target; /* the client-side target */
    struct sockaddr_in       bind_sa;
    unsigned                 used_peers;
    s3_srv_reverse_peer_t    peers[S3_SRV_REVERSE_UDP_PEERS_MAX];
} s3_srv_reverse_listener_t;

static struct {
    uint64_t                  conv_id; /* the conversation of the state, 0 = empty */
    s3_connection_t          *pc;      /* its quic connection */
    unsigned                  listeners;
    unsigned                  forwarded; /* the live forwarded-* channels */
    s3_srv_reverse_listener_t listener[S3_SRV_REVERSE_LISTENERS_MAX];
    char budget_user[S3_SRV_SFTP_USER_MAX + 1]; /* the cap owner of the live listeners */
} s3_srv_reverse;

/*
 * the operator cap on the live reverse listeners of one user (the
 * reference maxReverseForwardsPerUser, --max-reverse-forwards /
 * SSH3_MAX_REVERSE_FORWARDS): every bound listener holds one slot of
 * its user's budget for its lifetime, over the cap the bind refuses
 * with the REVERSE-CAP-DENIED report before any socket().  The
 * default 10 mirrors the fork maxReverseForwardsPerUser, the explicit
 * 0 keeps the unbounded shape, the hard per-conversation budget of
 * S3_SRV_REVERSE_LISTENERS_MAX stays on top.  The table mirrors the
 * sftp budget: the daemon serves one conversation at a time, the
 * extra entries exist for the shape only
 */

#define S3_SRV_REVERSE_BUDGET_USERS 16

typedef struct {
    char     user[S3_SRV_SFTP_USER_MAX + 1];
    unsigned n; /* the live reverse listeners of the user */
} s3_srv_reverse_budget_t;

static s3_srv_reverse_budget_t s3_srv_reverse_budgets[S3_SRV_REVERSE_BUDGET_USERS];

/* the CONNECTs without a user serve under the daemon identity, their
 * budget lives in its own counter (the empty key never occupies a
 * table slot) */

static unsigned s3_srv_reverse_budget_none;

/*
 * the default mirrors the fork maxReverseForwardsPerUser = 10 (the
 * ssh2 wave 1d); the explicit 0 (--max-reverse-forwards 0 /
 * SSH3_MAX_REVERSE_FORWARDS=0) keeps the unlimited shape
 */

static unsigned s3_srv_reverse_cap = 10;

/*
 * the listen-side policy (--permit-listen / SSH3_PERMIT_LISTEN, the
 * S2-04 PermitListen analog): the server-side binds the -R requests
 * take pass only the entries it allows; the empty default keeps the
 * unrestricted bind, the gate runs on the post-GatewayPorts address
 * (the one actually bound) and before the budget slot
 */

static s3_ssh3_forward_policy_t s3_srv_listen_policy;

/*
 * the GatewayPorts policy of the reverse binds (--gateway-ports /
 * SSH3_GATEWAY_PORTS, the sshd_config semantics of the reference
 * resolveReverseForwardBind): "no" (the default) forces every
 * client-requested bind back to the loopback, "clientspecified"
 * honors the bind address the client asked for, "yes" binds the
 * wildcard address regardless of the request
 */

#define S3_SRV_GATEWAY_PORTS_NO              0
#define S3_SRV_GATEWAY_PORTS_CLIENTSPECIFIED 1
#define S3_SRV_GATEWAY_PORTS_YES             2

static unsigned s3_srv_gateway_ports = S3_SRV_GATEWAY_PORTS_NO;

/* the policy name of the logs and the refusal reasons */

static const char *
s3_srv_gateway_ports_name(void)
{
    switch (s3_srv_gateway_ports) {

    case S3_SRV_GATEWAY_PORTS_CLIENTSPECIFIED:
        return "clientspecified";

    case S3_SRV_GATEWAY_PORTS_YES:
        return "yes";

    default:
        return "no";
    }
}

/*
 * the policy parse of the env default, the --gateway-ports flag and
 * the -o GatewayPorts option: the sshd_config shape, the words
 * compare case-insensitively and the y|n single-letter aliases ride
 * with them; S3_OK sets the policy, S3_ERROR leaves the caller to
 * warn (the env keeps the default) or to refuse (the flags)
 */

static s3_int_t
s3_srv_gateway_ports_parse(const char *text)
{
    if (text == NULL) {
        return S3_ERROR;
    }

    if (strcasecmp(text, "no") == 0 || strcasecmp(text, "n") == 0) {
        s3_srv_gateway_ports = S3_SRV_GATEWAY_PORTS_NO;
        return S3_OK;
    }

    if (strcasecmp(text, "clientspecified") == 0) {
        s3_srv_gateway_ports = S3_SRV_GATEWAY_PORTS_CLIENTSPECIFIED;
        return S3_OK;
    }

    if (strcasecmp(text, "yes") == 0 || strcasecmp(text, "y") == 0) {
        s3_srv_gateway_ports = S3_SRV_GATEWAY_PORTS_YES;
        return S3_OK;
    }

    return S3_ERROR;
}

/*
 * the ParseBool of the reference (strconv.ParseBool, the wave 1e
 * shapes): 1/t/T/true/TRUE/True set 1, 0/f/F/false/FALSE/False set 0,
 * anything else declines - the caller keeps the default (the env) or
 * leaves the tokens to the getopt rejection (the flag)
 */

static s3_int_t
s3_srv_parse_bool(const char *text, unsigned *out)
{
    if (text == NULL || out == NULL) {
        return S3_ERROR;
    }

    if (strcmp(text, "1") == 0 || strcasecmp(text, "t") == 0 || strcasecmp(text, "true") == 0) {
        *out = 1;
        return S3_OK;
    }

    if (strcmp(text, "0") == 0 || strcasecmp(text, "f") == 0 || strcasecmp(text, "false") == 0) {
        *out = 0;
        return S3_OK;
    }

    return S3_ERROR;
}

/*
 * the zerolog-style level name of the reference SSH3_LOG_LEVEL; an
 * unknown name keeps the fallback (the default level)
 */
static unsigned
s3_srv_log_level(const char *name, unsigned fallback)
{
    if (name == NULL || *name == '\0') {
        return fallback;
    }

    if (strcmp(name, "trace") == 0 || strcmp(name, "debug") == 0) {
        return S3_LOG_DEBUG_ALL;
    }

    if (strcmp(name, "info") == 0) {
        return S3_LOG_INFO;
    }

    if (strcmp(name, "warn") == 0) {
        return S3_LOG_WARN;
    }

    if (strcmp(name, "error") == 0) {
        return S3_LOG_ERR;
    }

    if (strcmp(name, "fatal") == 0 || strcmp(name, "panic") == 0) {
        return S3_LOG_CRIT;
    }

    s3_log_error(S3_LOG_WARN, &s3_srv_log, 0, "invalid SSH3_LOG_LEVEL \"%s\", keeping the default",
                 name);

    return fallback;
}

/*
 * the log destination: stderr unless SSH3_LOG_FILE says otherwise; a
 * run under systemd (INVOCATION_ID set) stays on stderr in any case,
 * journald captures the one-liners (the reference skips the log file
 * there too)
 */
static void
s3_srv_log_init(void)
{
    const char *path;

    s3_srv_log.log_level = s3_srv_log_level(getenv("SSH3_LOG_LEVEL"), S3_LOG_INFO);
    s3_srv_log.fd = S3_INVALID_FILE;

    path = getenv("SSH3_LOG_FILE");

    if (path == NULL || *path == '\0' || getenv("INVOCATION_ID") != NULL) {
        return;
    }

    s3_srv_log.fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);

    if (s3_srv_log.fd == -1) {
        s3_srv_log.fd = S3_INVALID_FILE;
        s3_log_error(S3_LOG_ERR, &s3_srv_log, s3_errno, "open() \"%s\" failed", path);
        exit(1);
    }
}

/*
 * the runner protocol report: under SSH3C_PROTO=1 the line goes to
 * stdout verbatim (the machine-readable protocol of the interop
 * runner), otherwise the same text rides the s3_log one-liner
 */
static void
s3_srv_report(const char *fmt, ...)
{
    u_char  line[512];
    va_list args;
    int     n;

    va_start(args, fmt);
    n = vsnprintf((char *)line, sizeof(line), fmt, args);
    va_end(args);

    if (n <= 0) {
        return;
    }

    /* one report, one line: the core log appends its own LF */
    if (line[n - 1] == '\n') {
        line[--n] = '\0';
    }

    if (s3_srv_proto_mode) {
        printf("%s\n", (char *)line);
        fflush(stdout);
        return;
    }

    s3_log_error(S3_LOG_INFO, &s3_srv_log, 0, "%s", line);
}

/*
 * the shutdown signals: the handler only counts them, every real
 * action happens in the main loop between the event passes
 */
static void
s3_srv_signal_handler(int sig)
{
    /* every signal of the handler means the same: the shutdown */
    (void)sig;

    s3_srv_quit++;
}

/*
 * the slot bookkeeping: the cleanup runs inside the pool destroy of
 * a closing quic connection, the slot is dead exactly when the
 * pointer is NULL
 */
static void
s3_srv_conn_gone(void *data)
{
    s3_connection_t **slot = data;

    *slot = NULL;
}

static void
s3_srv_track(s3_connection_t *c)
{
    s3_pool_cleanup_t *cln;
    unsigned           i;

    for (i = 0; i < S3_SRV_TRACKED && s3_srv_conns[i] != NULL; i++)
        ;

    if (i == S3_SRV_TRACKED) {
        return;
    }

    cln = s3_pool_cleanup_add(c->pool, 0);

    if (cln == NULL) {
        return;
    }

    cln->data = &s3_srv_conns[i];
    cln->handler = s3_srv_conn_gone;

    s3_srv_conns[i] = c;
    s3_srv_reported[i] = 0;
    s3_srv_idle_reported[i] = 0;
}

/* the connections that are still alive */
static unsigned
s3_srv_active_conns(void)
{
    unsigned i, n = 0;

    for (i = 0; i < S3_SRV_TRACKED; i++) {

        if (s3_srv_conns[i] != NULL) {
            n++;
        }
    }

    return n;
}

/* the drain deadline expiry: the state machine between passes acts */

static void
s3_srv_drain_timer_handler(s3_event_t *ev)
{
    ev->timedout = 0;
}

static void
s3_srv_drain_start(void)
{
    s3_srv_draining = 1;
    s3_srv_drain_deadline = s3_current_msec + s3_srv_drain_ms;

    if (!s3_srv_drain_timer.timer_set) {

        if (s3_srv_drain_timer.data == NULL) {
            s3_srv_drain_timer.data = &s3_srv_drain_timer;
            s3_srv_drain_timer.log = &s3_srv_log;
            s3_srv_drain_timer.handler = s3_srv_drain_timer_handler;
        }

        s3_event_add_timer(&s3_srv_drain_timer, s3_srv_drain_ms);
    }

    s3_log_error(S3_LOG_INFO, &s3_srv_log, 0,
                 "shutdown signal received: no longer accepting new connections");

    s3_log_error(S3_LOG_INFO, &s3_srv_log, 0, "shutdown: draining active connections up to %uL ms",
                 (uint64_t)s3_srv_drain_ms);
}

/* the force close: CONNECTION_CLOSE to everyone, then the session
 * children die with the channels before the daemon exits */
static void
s3_srv_force_close(void)
{
    unsigned i;

    for (i = 0; i < S3_SRV_TRACKED; i++) {

        if (s3_srv_conns[i] != NULL) {
            s3_quic_finalize_connection(s3_srv_conns[i], 0, "server shutdown");
        }
    }
}

/*
 * one bounded event pass of the shutdown tail: the plain
 * s3_process_events_and_timers() may block in epoll_wait() up to the
 * idle timer (a minute with the departed peers), a shutdown pass
 * must not
 */
static void
s3_srv_event_pass(s3_event_ctx_t *ctx)
{
    s3_time_update();

    (void)s3_event_actions.process_events(ctx, 20, S3_UPDATE_TIME);

    s3_event_expire_timers(ctx);
    s3_event_process_posted(ctx, &ctx->posted_events);
}

/*
 * the exit drain of the close state: the immediate close of a quiet
 * peer parks on the 3*PTO close timer, the close grace above does not
 * cover it; the timer drops and the resumed close completes on the
 * passes below, the tracked connection pools die before the exit
 */
static void
s3_srv_close_drain(s3_event_ctx_t *ctx)
{
    s3_msec_t deadline;
    unsigned  i;

    for (i = 0; i < S3_SRV_TRACKED; i++) {
        s3_connection_t      *c = s3_srv_conns[i];
        s3_quic_connection_t *qc;

        if (c == NULL) {
            continue;
        }

        qc = s3_quic_get_connection(c);

        if (qc != NULL && qc->close.timer_set) {
            s3_event_del_timer(&qc->close);
            s3_post_event(&qc->close, &ctx->posted_events);
        }
    }

    deadline = s3_current_msec + S3_SRV_CLOSE_GRACE;

    while (s3_current_msec < deadline && s3_srv_active_conns() > 0) {
        s3_srv_event_pass(ctx);
    }
}

static u_char *
s3_srv_read_file(const char *path, size_t *len)
{
    FILE   *f;
    u_char *buf;
    long    n;

    f = fopen(path, "rb");
    if (f == NULL) {
        fprintf(stderr, "ssh3-server: cannot open %s\n", path);
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

/*
 * the -l address: "a.b.c.d:port" (IPv4) or "[v6]:port" (IPv6, the
 * bracket form of the reference -bind, whose default "[::]:443" is
 * the dual-stack wildcard); the v6 host may itself carry colons, so
 * the port splits at the colon behind the closing bracket; the
 * numeric forms only (inet_pton), the names resolve in the unit.
 * A bare address without the port part ("a.b.c.d", "[v6]") is the
 * sshd ListenAddress shape: the default_port rides in (the -p port
 * or the 443 of the reference)
 */
static s3_int_t
s3_srv_parse_addr(const char *text, struct sockaddr_storage *ss, socklen_t *sslen,
                  unsigned default_port)
{
    char        host[64];
    const char *colon, *end_bracket;
    size_t      n;
    unsigned    port;

    colon = strchr(text, ':');

    if (text[0] == '[') {

        /* the IPv6 bracket form */

        end_bracket = strchr(text, ']');

        if (end_bracket == NULL) {
            return S3_ERROR;
        }

        if (end_bracket[1] == ':') {

            port = (unsigned)atoi(end_bracket + 2);

        } else if (end_bracket[1] == '\0') {

            /* the bare [v6] form: the default port applies */

            port = default_port;

        } else {
            return S3_ERROR;
        }

        if (port > 65535) {
            return S3_ERROR;
        }

        n = (size_t)(end_bracket - text) - 1;

        if (n == 0 || n >= sizeof(host)) {
            return S3_ERROR;
        }

        memcpy(host, text + 1, n);
        host[n] = '\0';

        s3_memzero(ss, sizeof(*ss));

        ((struct sockaddr_in6 *)ss)->sin6_family = AF_INET6;
        ((struct sockaddr_in6 *)ss)->sin6_port = htons((uint16_t)port);

        if (inet_pton(AF_INET6, host, &((struct sockaddr_in6 *)ss)->sin6_addr) != 1) {
            return S3_ERROR;
        }

        *sslen = sizeof(struct sockaddr_in6);

        return S3_OK;
    }

    if (colon == NULL) {

        /* the bare a.b.c.d form: the default port applies (the sshd
         * ListenAddress shape) */

        n = strlen(text);

        if (n == 0 || n >= sizeof(host)) {
            return S3_ERROR;
        }

        memcpy(host, text, n);
        host[n] = '\0';

        port = default_port;

    } else {

        n = (size_t)(colon - text);

        if (n == 0 || n >= sizeof(host)) {
            return S3_ERROR;
        }

        memcpy(host, text, n);
        host[n] = '\0';

        port = (unsigned)atoi(colon + 1);
    }

    if (port > 65535) {
        return S3_ERROR;
    }

    s3_memzero(ss, sizeof(*ss));

    ((struct sockaddr_in *)ss)->sin_family = AF_INET;
    ((struct sockaddr_in *)ss)->sin_port = htons((uint16_t)port);

    if (inet_pton(AF_INET, host, &((struct sockaddr_in *)ss)->sin_addr) != 1) {
        return S3_ERROR;
    }

    *sslen = sizeof(struct sockaddr_in);

    return S3_OK;
}

/* the reference -bind default port: the bare -l address and the
 * default listener take it when no -p rides */

#define S3_SRV_DEFAULT_PORT 443

/*
 * the -p port of the sshd command line: the digits only, 1..65535
 * (the sshd "bad port" shape; the ephemeral 0 stays a -l addr:0 form)
 */

static s3_int_t
s3_srv_parse_port(const char *text, unsigned *port)
{
    size_t   n, i;
    unsigned v = 0;

    n = (text != NULL) ? strlen(text) : 0;

    if (n == 0 || n > 5) {
        return S3_ERROR;
    }

    for (i = 0; i < n; i++) {

        if (text[i] < '0' || text[i] > '9') {
            return S3_ERROR;
        }

        v = v * 10 + (unsigned)(text[i] - '0');
    }

    if (v == 0 || v > 65535) {
        return S3_ERROR;
    }

    *port = v;

    return S3_OK;
}

/*
 * the AuthorizedKeysFile paths of the -o option: the tokens split out
 * of the single argv string, the copies own their storage (the -K
 * slots keep their argv pointers, both walk the same table)
 */

static char s3_srv_ak_paths[S3_SRV_KEYFILES_MAX][512];

/*
 * the -o option of the sshd command line, the sshd_config subset the
 * daemon serves: "Key=Value", repeatable, the keys and the boolean
 * values case-insensitive.  S3_OK applies the value (the spec
 * pointers ride into the argv-owned strings, the keyfiles append to
 * the -K table, the guards take the knobs); S3_ERROR refuses the
 * unknown or malformed entry - the reason is logged here, the caller
 * stops the daemon (the config-error shape of the url-path check)
 */

static s3_int_t
s3_srv_o_option(const char *spec, const char **permit_open_arg, const char **permit_listen_arg,
                int *dos_unauth, int *chroot_warned)
{
    const char *eq, *value;
    size_t      key_len;
    int         k;

    eq = strchr(spec, '=');

    if (eq == NULL || eq == spec) {

        /* no key, or an empty key: the malformed entry, the same
         * refusal path as the unknown option below */

        fprintf(stderr, "ssh3-server: bad -o option \"%s\", the Key=Value form only\n", spec);
        return S3_ERROR;
    }

    key_len = (size_t)(eq - spec);
    value = eq + 1;

    if (key_len == 10 && strncasecmp(spec, "PermitOpen", key_len) == 0) {

        /* the dial policy: "any" is the unrestricted default (the
         * empty spec of the parser), "none" refuses everything (the
         * negated wildcard entry), the rest is the --permit-open
         * spec verbatim */

        if (strcasecmp(value, "any") == 0) {
            *permit_open_arg = "";

        } else if (strcasecmp(value, "none") == 0) {
            *permit_open_arg = "!*:*";

        } else {
            *permit_open_arg = value;
        }

        return S3_OK;
    }

    if (key_len == 12 && strncasecmp(spec, "PermitListen", key_len) == 0) {

        /* the reverse bind policy, the same shapes */

        if (strcasecmp(value, "any") == 0) {
            *permit_listen_arg = "";

        } else if (strcasecmp(value, "none") == 0) {
            *permit_listen_arg = "!*:*";

        } else {
            *permit_listen_arg = value;
        }

        return S3_OK;
    }

    if (key_len == 12 && strncasecmp(spec, "GatewayPorts", key_len) == 0) {

        if (s3_srv_gateway_ports_parse(value) != S3_OK) {
            fprintf(stderr,
                    "ssh3-server: bad -o GatewayPorts value \"%s\":"
                    " no|yes|clientspecified\n",
                    value);
            return S3_ERROR;
        }

        return S3_OK;
    }

    if (key_len == 11 && strncasecmp(spec, "MaxStartups", key_len) == 0) {

        /* the flat count of the --max-unauth-conversations validator
         * (the negative is the config error, 0 the kill-switch); the
         * start:rate:full form of sshd_config has no analog here */

        if (strchr(value, ':') != NULL) {
            fprintf(stderr,
                    "ssh3-server: the -o MaxStartups start:rate:full form \"%s\" is not"
                    " supported: the flat count only (the"
                    " --max-unauth-conversations analog)\n",
                    value);
            return S3_ERROR;
        }

        k = atoi(value);

        if (k < 0) {
            fprintf(stderr, "ssh3-server: bad -o MaxStartups \"%s\"\n", value);
            return S3_ERROR;
        }

        *dos_unauth = k;

        return S3_OK;
    }

    if (key_len == 18 && strncasecmp(spec, "AuthorizedKeysFile", key_len) == 0) {

        /* the paths split on the spaces and the tabs, each one joins
         * the -K chain in the given order; the %%u / %%h tokens
         * expand per session at the verdict */

        const char *p = value;
        unsigned    added = 0;

        while (*p != '\0') {

            const char *f;

            while (*p == ' ' || *p == '\t') {
                p++;
            }

            if (*p == '\0') {
                break;
            }

            f = p;

            while (*p != '\0' && *p != ' ' && *p != '\t') {
                p++;
            }

            if (s3_srv_keyfiles_n >= S3_SRV_KEYFILES_MAX) {
                fprintf(stderr,
                        "ssh3-server: too many AuthorizedKeysFile entries"
                        " (max %d)\n",
                        S3_SRV_KEYFILES_MAX);
                return S3_ERROR;
            }

            if ((size_t)(p - f) >= sizeof(s3_srv_ak_paths[0])) {
                fprintf(stderr, "ssh3-server: the AuthorizedKeysFile path is too long\n");
                return S3_ERROR;
            }

            memcpy(s3_srv_ak_paths[s3_srv_keyfiles_n], f, (size_t)(p - f));
            s3_srv_ak_paths[s3_srv_keyfiles_n][p - f] = '\0';

            s3_srv_keyfiles[s3_srv_keyfiles_n] = s3_srv_ak_paths[s3_srv_keyfiles_n];
            s3_srv_keyfiles_n++;
            added++;
        }

        if (added == 0) {
            fprintf(stderr, "ssh3-server: -o AuthorizedKeysFile needs at least one path\n");
            return S3_ERROR;
        }

        return S3_OK;
    }

    if (key_len == 15 && strncasecmp(spec, "ChrootDirectory", key_len) == 0) {

        if (*value == '\0') {
            fprintf(stderr, "ssh3-server: -o ChrootDirectory needs a directory\n");
            return S3_ERROR;
        }

        /* the sftp jail root override, the -H alias; the sshd option
         * is per-user Match-scoped, the daemon serves one global
         * value - the one-time warn says so */

        snprintf(s3_srv_sftp_home, sizeof(s3_srv_sftp_home), "%s", value);

        if (!*chroot_warned) {
            s3_log_error(S3_LOG_WARN, &s3_srv_log, 0,
                         "-o ChrootDirectory is simplified: single global value,"
                         " per-user Match is not supported");
            *chroot_warned = 1;
        }

        return S3_OK;
    }

    fprintf(stderr,
            "ssh3-server: unsupported -o option \"%.*s\": the supported set is"
            " PermitOpen, PermitListen, GatewayPorts, MaxStartups,"
            " AuthorizedKeysFile, ChrootDirectory\n",
            (int)key_len, spec);

    return S3_ERROR;
}

static void
s3_srv_alpn_wire(u_char *wire, const char *name)
{
    size_t n;

    n = strlen(name);

    if (n == 0 || n > 255) {
        fprintf(stderr, "ssh3-server: bad alpn name\n");
        exit(1);
    }

    wire[0] = (u_char)n;
    memcpy(wire + 1, name, n);
}

/*
 * the h3 channel, see the table below; the forward declaration lets
 * the datagram handler hold the direct-udp singleton
 */

typedef struct s3_srv_h3_channel_s s3_srv_h3_channel_t;

/*
 * the open direct-udp forward channel: the harness simplification,
 * one channel at a time, the datagram handler routes by its ids; NULL
 * when no direct-udp channel is open
 */
static s3_srv_h3_channel_t *s3_srv_h3_udp_fwd;

/* the forward branch lives below the channel table */

static void s3_srv_udp_fwd_datagram(s3_connection_t *c, const u_char *buf, size_t len);

/*
 * the reverse forward (-R) wiring, defined below the channel table:
 * the datagram router rides the echo handler (the first dispatcher of
 * a received datagram), the request handler the channel message loop
 */

static unsigned s3_srv_reverse_datagram_route(s3_connection_t *c, const u_char *buf, size_t len);

static void s3_srv_reverse_request(s3_srv_h3_channel_t *ch, const s3_str_t *payload);

static void
s3_srv_datagram_echo(s3_connection_t *c, s3_chain_t *data)
{
    u_char     *buf;
    size_t      len;
    s3_chain_t *cl;

    if (s3_srv_reverse.listeners == 0 && s3_srv_h3_udp_fwd == NULL) {

        /*
         * no udp channel is routed: a datagram almost always lands in
         * a single link of the receive buffer, echo it straight from
         * there, no intermediate block
         */

        if (data->next == NULL) {
            (void)s3_quic_send_datagram(c, data->buf->pos, s3_buf_size(data->buf));
            return;
        }
    }

    /* the routed shapes (the reverse -R peers, the direct-udp
     * channel) need the contiguous bytes: one flatten covers them */

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

    if (s3_srv_reverse_datagram_route(c, buf, len)) {
        (void)s3_pfree(c->pool, buf);
        return;
    }

    if (s3_srv_h3_udp_fwd != NULL) {
        s3_srv_udp_fwd_datagram(c, buf, len);
        (void)s3_pfree(c->pool, buf);
        return;
    }

    (void)s3_quic_send_datagram(c, buf, len);

    (void)s3_pfree(c->pool, buf);
}

/*
 * the plain stream echo of the harness is gone: the daemon speaks
 * the ssh3 route only, every bidi stream is the h3 request or an
 * ssh3 channel
 */

/*
 * the h3 request side (-3): one bidi stream carries the RFC 9220
 * extended CONNECT, the uni streams belong to the session port.  The
 * harness drives a single request stream at a time, so the state below
 * is static.  The parsed field strings are pool copies (s3_h3_parse.c
 * allocates the literals off the connection pool), the buffers below
 * just snapshot them for the verdict.
 */

static s3_h3_parse_headers_t s3_srv_h3_parse;

static u_char *s3_srv_h3_buf;
static size_t  s3_srv_h3_cap;
static size_t  s3_srv_h3_len;

static s3_connection_t *s3_srv_h3_sc;
static s3_connection_t *s3_srv_h3_pc; /* the quic conn of the CONNECT */
static unsigned         s3_srv_h3_responded;

static u_char s3_srv_h3_method[32];
static size_t s3_srv_h3_method_len;
static u_char s3_srv_h3_protocol[32];
static size_t s3_srv_h3_protocol_len;
static u_char s3_srv_h3_path[256];
static size_t s3_srv_h3_path_len;
/*
 * the Authorization snapshot: the biggest Bearer the CONNECT carries
 * (an Ed25519 pubkey JWT is ~340 bytes, an RS256 one goes past 600,
 * an RS256 OIDC id_token rides ~1.2 KB), the 256-byte capture of the
 * Basic wave truncated it and the verdict failed on the tail
 */
static u_char s3_srv_h3_auth[4096];
static size_t s3_srv_h3_auth_len;
static u_char s3_srv_h3_ua[128];
static size_t s3_srv_h3_ua_len;
static u_char s3_srv_h3_authority[256];
static size_t s3_srv_h3_authority_len;
static u_char s3_srv_h3_scheme[16];
static size_t s3_srv_h3_scheme_len;

/* the response tail pending on the send window */
static u_char s3_srv_h3_out[512];
static size_t s3_srv_h3_out_len;

/*
 * the ssh3 session channels (-3): every bidi stream after the CONNECT
 * is a channel.  The pre-confirmation phase keeps a small per-channel
 * accumulator (the header and the first messages may arrive in
 * several recvs); after the 91 the channel runs either the echo or
 * the server session of docs/P4-WIRE.md 6
 */
struct s3_srv_h3_channel_s {
    s3_connection_t *sc;

    /*
     * the conversation's quic connection, captured at the accept: the
     * drain counts the unfinished work through it without touching a
     * connection that may already be gone
     */
    s3_connection_t *pc;

    u_char  *buf;
    size_t   cap;
    size_t   len;
    unsigned confirmed;
    unsigned is_session; /* the type is "session", the requests ride it (S2-03) */

    /*
     * the session side: the pool owns the session struct and its
     * command copy, the process fds ride the event-driven pump of
     * s3_ssh3_session_srv_watch() - the readiness of the process
     * output runs the pump, the verdict watchdog covers the eof
     * without the child exit
     */
    s3_pool_t             *sess_pool;
    s3_ssh3_session_srv_t *sess;
    unsigned               sess_intent; /* a pty-req or an exec announced the session */
    unsigned               sess_exit_sent;
    unsigned               sess_peer_fin;

    /*
     * the authenticated username of the conversation (P7.3), the
     * snapshot of the CONNECT verdict: the session spawns with it
     * under the per-session setuid mode, empty keeps the daemon
     * identity (the request streams are serialized by the harness,
     * the same shape the static verdict buffers ride)
     */
    char sess_user[128];

    /*
     * the forward side (direct-tcp / direct-udp): fwd_fd is the
     * target socket (-1 when the channel is not a forward), the
     * pending buffers decouple the quic stream from the socket and
     * the 50 ms timer pumps the remaining directions - the same
     * harness scheme as the session pump above; the AGENT kind reuses
     * the tcp pump against the accepted agent socket, the reverse
     * (-R) channels ride the same shapes (the RCTRL control channel,
     * the RUDP per-peer datagram channel)
     */
    unsigned           fwd_kind; /* S3_SRV_FWD_NONE/TCP/UDP/AGENT/RCTRL/RUDP */
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
     * the server-initiated channels (the agent bridge, the reverse
     * forward): the 91 of the client answers the opener header (the
     * consume sits in the message loop), the reverse_fwd flag counts
     * the channel into the forwarded-* budget and clears its listener
     * peer on the free
     */
    unsigned opened_by_server : 1;
    unsigned reverse_fwd : 1;
    unsigned reverse_served : 1; /* the RCTRL request already handled */
    unsigned reverse_l;          /* the listener index of a RUDP channel */
    unsigned reverse_peer;       /* the peer index of a RUDP channel */

    /*
     * the sftp side ("sftp" channels): the pool owns the request
     * server, the 94 payloads feed s3_ssh3_sftp_srv_input and the 50
     * ms timer drains s3_ssh3_sftp_srv_output into the 94 direction;
     * the chroot mode (F-04) leaves these empty and rides the child
     * trio below instead
     */
    s3_pool_t          *sftp_pool;
    s3_ssh3_sftp_srv_t *sftp;

    /*
     * the chroot child of the sftp channel (the sshd model): the
     * child serves the engine behind chroot+drop, the parent pumps
     * the two pipes; the death of the child ends the channel
     */
    pid_t    sftp_pid;      /* the child process, 0 once reaped */
    int      sftp_in;       /* the stdin pipe of the child, -1 when unused */
    int      sftp_out;      /* the stdout pipe of the child, -1 when unused */
    unsigned sftp_budgeted; /* the per-user sftp budget slot is held (S2-02) */

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

#define S3_SRV_FWD_NONE  0
#define S3_SRV_FWD_TCP   1
#define S3_SRV_FWD_UDP   2
#define S3_SRV_FWD_AGENT 3
#define S3_SRV_FWD_SFTP  4 /* the chroot child pipes, no target socket */
#define S3_SRV_FWD_RCTRL 5 /* the reverse-forward control channel */
#define S3_SRV_FWD_RUDP  6 /* the per-peer forwarded-udp channel of a reverse listener */

/*
 * the frame buffer of the socket->channel direction: one 94 frame
 * carries up to the maxPacketSize chunk, the type and length varints
 * ride on top
 */
#define S3_SRV_FWD_FRAME 33000

/* the teardown of the session side, the channel free calls it first */
static void s3_srv_session_teardown(s3_srv_h3_channel_t *ch);

/* the sftp and the agent wiring of the wave 2, defined below */

static void s3_srv_sftp_pump(s3_srv_h3_channel_t *ch);

static void s3_srv_sftp_child_pump(s3_srv_h3_channel_t *ch);

static s3_int_t s3_srv_sftp_chroot_start(s3_srv_h3_channel_t *ch);

static unsigned s3_srv_sftp_budget_take(const char *user);

static void s3_srv_sftp_budget_give(const char *user);

static void s3_srv_agent_accept_timer(s3_event_t *ev);

/* the reverse forward (-R) wiring, defined below */

static void s3_srv_reverse_teardown(void);

static s3_srv_h3_channel_t *s3_srv_h3_channel_alloc(s3_connection_t *sc);

static void s3_srv_h3_channel_read(s3_event_t *ev);

static void s3_srv_h3_channel_free(s3_srv_h3_channel_t *ch);

static s3_srv_h3_channel_t s3_srv_h3_channels[S3_SRV_TRACKED];

/* the pointer is a slot of the tracked table, the comparison only */
static unsigned
s3_srv_conn_alive(const s3_connection_t *c)
{
    unsigned i;

    for (i = 0; i < S3_SRV_TRACKED; i++) {

        if (s3_srv_conns[i] == c) {
            return 1;
        }
    }

    return 0;
}

/*
 * the unfinished conversation work (the drain counts the channels,
 * the PLAN wording "финиш активных каналов"): a session still running
 * (the 98 verdict is out on sess_exit_sent), an sftp transfer, a live
 * forward.  A connection whose channels are all terminal carries no
 * work - the ssh3 conversation is its channels, the C interop client
 * leaves the quic connection to the idle timeout after the verdict
 */
static unsigned
s3_srv_busy_channels(void)
{
    unsigned i, n = 0;

    for (i = 0; i < S3_SRV_TRACKED; i++) {
        s3_srv_h3_channel_t *ch = &s3_srv_h3_channels[i];

        if (ch->sc == NULL || ch->pc == NULL || !s3_srv_conn_alive(ch->pc)) {
            continue;
        }

        if ((ch->sess != NULL && !ch->sess_exit_sent) || ch->sftp != NULL ||
            (ch->fwd_kind != S3_SRV_FWD_NONE && ch->fwd_kind != S3_SRV_FWD_RCTRL &&
             ch->fwd_kind != S3_SRV_FWD_RUDP && !ch->fwd_eof)) {
            n++;
        }
    }

    /* the reverse listeners are the unfinished work of their own: a
     * bound -R port serves until the conversation is over */

    n += s3_srv_reverse.listeners;

    return n;
}

/*
 * the shutdown hygiene: the sessions, pools and target sockets of the
 * channels that outlived the event loop, the daemon must not leave
 * the children or the agent sockets behind
 */
static void
s3_srv_teardown_channels(void)
{
    unsigned i;

    for (i = 0; i < S3_SRV_TRACKED; i++) {

        if (s3_srv_h3_channels[i].sc != NULL) {
            s3_srv_h3_channel_free(&s3_srv_h3_channels[i]);
        }
    }

    /* the -R listeners close with the daemon (the conversation shape
     * of the shutdown drain ends everything anyway) */

    s3_srv_reverse_teardown();
}

/* the StreamID of the CONNECT stream, the channels must quote it */
static uint64_t s3_srv_h3_conv_id;

/* one echo frame: varint 94 + SSHString, capped by the maxPacketSize */
static u_char s3_srv_h3_ch_out[32768];

static void
s3_srv_h3_store(u_char *dst, size_t size, size_t *len, s3_str_t *value)
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
s3_srv_h3_capture(s3_h3_parse_field_t *f)
{
    static s3_str_t method = s3_string(":method");
    static s3_str_t protocol = s3_string(":protocol");
    static s3_str_t path = s3_string(":path");
    static s3_str_t auth = s3_string("authorization");
    static s3_str_t ua = s3_string("user-agent");
    static s3_str_t authority = s3_string(":authority");
    static s3_str_t scheme = s3_string(":scheme");

    if (f->name.len == method.len && s3_memcmp(f->name.data, method.data, method.len) == 0) {
        s3_srv_h3_store(s3_srv_h3_method, sizeof(s3_srv_h3_method), &s3_srv_h3_method_len,
                        &f->value);

    } else if (f->name.len == protocol.len &&
               s3_memcmp(f->name.data, protocol.data, protocol.len) == 0) {
        s3_srv_h3_store(s3_srv_h3_protocol, sizeof(s3_srv_h3_protocol), &s3_srv_h3_protocol_len,
                        &f->value);

    } else if (f->name.len == path.len && s3_memcmp(f->name.data, path.data, path.len) == 0) {
        s3_srv_h3_store(s3_srv_h3_path, sizeof(s3_srv_h3_path), &s3_srv_h3_path_len, &f->value);

    } else if (f->name.len == auth.len && s3_memcmp(f->name.data, auth.data, auth.len) == 0) {
        s3_srv_h3_store(s3_srv_h3_auth, sizeof(s3_srv_h3_auth), &s3_srv_h3_auth_len, &f->value);

    } else if (f->name.len == ua.len && s3_memcmp(f->name.data, ua.data, ua.len) == 0) {
        s3_srv_h3_store(s3_srv_h3_ua, sizeof(s3_srv_h3_ua), &s3_srv_h3_ua_len, &f->value);

    } else if (f->name.len == authority.len &&
               s3_memcmp(f->name.data, authority.data, authority.len) == 0) {
        s3_srv_h3_store(s3_srv_h3_authority, sizeof(s3_srv_h3_authority), &s3_srv_h3_authority_len,
                        &f->value);

    } else if (f->name.len == scheme.len && s3_memcmp(f->name.data, scheme.data, scheme.len) == 0) {
        s3_srv_h3_store(s3_srv_h3_scheme, sizeof(s3_srv_h3_scheme), &s3_srv_h3_scheme_len,
                        &f->value);
    }

    /* the other field lines are irrelevant to the verdict */
}

static u_char *
s3_srv_h3_put_status(u_char *p, unsigned code)
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
s3_srv_h3_flush(void)
{
    s3_connection_t *sc = s3_srv_h3_sc;
    ssize_t          m;

    while (s3_srv_h3_out_len > 0) {

        m = s3_quic_stream_send(sc, s3_srv_h3_out, s3_srv_h3_out_len);

        if (m == (ssize_t)S3_AGAIN) {
            return;
        }

        if (m <= 0) {
            fprintf(stderr, "ssh3-server: h3 response send failed\n");
            s3_srv_h3_out_len = 0;
            return;
        }

        s3_memmove(s3_srv_h3_out, s3_srv_h3_out + m, s3_srv_h3_out_len - m);
        s3_srv_h3_out_len -= m;
    }
}

static void
s3_srv_h3_send_status(unsigned code)
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
    p = s3_srv_h3_put_status(p, code);

    /*
     * the Server field of the reference rides EVERY response: the
     * handler sets it before any verdict (w.Header().Set("Server",
     * GetCurrentVersionString()), server_auth/auth.go), so the client
     * parses a version string out of the refusals too - a missing
     * field reads as an empty version and the client reports the
     * misleading "bad SSH version fields" instead of the verdict
     */

    {
        s3_str_t name = s3_string("server");
        s3_str_t value = s3_string(S3_SSH3_VERSION_STRING);

        p = (u_char *)s3_h3_encode_field_l(p, &name, &value);
    }

    sec_len = (size_t)(p - sec);

    s3_srv_h3_out[0] = S3_H3_FRAME_HEADERS;

    p = (u_char *)s3_h3_encode_varlen_int(s3_srv_h3_out + 1, sec_len);

    memcpy(p, sec, sec_len);

    total = (size_t)(p - s3_srv_h3_out) + sec_len;

    m = s3_quic_stream_send(s3_srv_h3_sc, s3_srv_h3_out, total);

    if (m == (ssize_t)S3_AGAIN) {
        /* the window opens on the write event, the tail is queued */
        s3_srv_h3_out_len = total;
        return;
    }

    if (m <= 0) {
        fprintf(stderr, "ssh3-server: h3 response send failed\n");
        return;
    }

    if ((size_t)m < total) {
        s3_memmove(s3_srv_h3_out, s3_srv_h3_out + m, total - m);
        s3_srv_h3_out_len = total - m;
    }
}

/*
 * the identity gate of the CONNECT (P7.3): the authenticated name
 * must resolve through the passwd database before the CONNECT passes
 * - the 401 lands here, far before any spawn (the session module
 * refuses the unknown user the same way, this is the earlier verdict
 * of the same rule; the plain-name guard itself lives in the module,
 * the authoritative refusal of the spawn); S3_OK once the name is
 * snapshotted for the session channels
 */
static s3_int_t
s3_srv_auth_user_gate(const s3_str_t *user)
{
    s3_srv_auth_user[0] = '\0';

    if (user == NULL || user->data == NULL || user->len == 0 ||
        user->len >= sizeof(s3_srv_auth_user)) {
        return S3_DECLINED;
    }

    s3_memcpy(s3_srv_auth_user, user->data, user->len);
    s3_srv_auth_user[user->len] = '\0';

    if (getpwnam(s3_srv_auth_user) == NULL) {
        s3_srv_auth_user[0] = '\0';
        return S3_DECLINED;
    }

    return S3_OK;
}

/*
 * the presence probe of the passfile (the booking gate of the
 * brute-force lockout): the failed verdicts book only for the users
 * the password backend knows - a line carrying the name - so a flood
 * of invented usernames grows nothing and locks nobody (the anti
 * user-enumeration rule of the reference: the unknown user 401s at
 * the GetUser gate before the password backend is ever reached,
 * server_auth/auth.go)
 */
static s3_int_t
s3_srv_passfile_has_user(const char *path, const s3_str_t *user)
{
    u_char  *buf, *p, *end, *nl, *line_end, *colon;
    long     fsize;
    FILE    *f;
    s3_int_t rc = S3_DECLINED;

    f = fopen(path, "rb");

    if (f == NULL) {
        return S3_ERROR;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return S3_ERROR;
    }

    fsize = ftell(f);

    if (fsize < 0 || fsize > 1024 * 1024) {
        fclose(f);
        return S3_ERROR;
    }

    rewind(f);

    buf = s3_alloc((size_t)fsize + 1, NULL);

    if (buf == NULL) {
        fclose(f);
        return S3_ERROR;
    }

    if (fsize > 0 && fread(buf, 1, (size_t)fsize, f) != (size_t)fsize) {
        s3_free(buf);
        fclose(f);
        return S3_ERROR;
    }

    fclose(f);

    p = buf;
    end = buf + fsize;

    while (p < end) {

        nl = memchr(p, '\n', (size_t)(end - p));

        line_end = (nl != NULL) ? nl : end;

        if (line_end > p && line_end[-1] == '\r') {
            line_end--;
        }

        if (line_end > p && *p != '#') {

            colon = memchr(p, ':', (size_t)(line_end - p));

            if (colon != NULL && (size_t)(colon - p) == user->len &&
                s3_memcmp(p, user->data, user->len) == 0) {
                rc = S3_OK;
                break;
            }
        }

        p = (nl != NULL) ? nl + 1 : end;
    }

    s3_free(buf);

    return rc;
}

/*
 * the Basic verdict against the password backends (docs/P4-WIRE.md 7,
 * the Basic step of the reference chain): the credentials decode from
 * the authorization header, the username comes from the CONNECT
 * target (?user=), the -P file answers first and the system accounts
 * (--password-system, the shadow step of PLAN.md 8.2) second - both
 * serve when both are wired, the first S3_OK wins; the root account
 * never passes the Basic step (the PermitRootLogin prohibit-password
 * analog of the sshd canon, the wave 1e - the refusal rides before
 * the backends and before any lockout booking); the brute-force
 * lockout of the reference CheckBasicAuth sits in front of the
 * backends (429 without touching them), the failures of the known
 * users book (the passfile line or the passwd entry) and the success
 * clears
 */
static unsigned
s3_srv_h3_basic_verdict(void)
{
    s3_str_t header, path, basic_user, basic_pass, user;
    s3_int_t rc, known;

    header.data = s3_srv_h3_auth;
    header.len = s3_srv_h3_auth_len;

    s3_str_null(&basic_user);
    s3_str_null(&basic_pass);
    s3_str_null(&user);

    rc = s3_ssh3_auth_basic_decode(&header, &basic_user, &basic_pass);

    if (rc != S3_OK) {
        fprintf(stderr, "ssh3-server: basic auth: bad credentials rc=%d\n", (int)rc);
        return 401;
    }

    path.data = s3_srv_h3_path;
    path.len = s3_srv_h3_path_len;

    rc = s3_ssh3_auth_user_from_path(&path, &user);

    if (rc != S3_OK) {
        fprintf(stderr, "ssh3-server: basic auth: no user in the path\n");
        return 401;
    }

    /*
     * the root gate (the PermitRootLogin prohibit-password analog,
     * the wave 1e): the session username compares exactly, the
     * refusal rides before the lockout check, the backends and any
     * booking; the key and the JWT verdicts never pass here, the
     * root by key stays legitimate
     */

    if (user.len == 4 && memcmp(user.data, "root", 4) == 0) {
        s3_log_error(S3_LOG_WARN, &s3_srv_log, 0,
                     "password auth for root refused: the root account authenticates"
                     " by key only (PermitRootLogin prohibit-password)");

        return 401;
    }

    /* the locked account answers before the password file is read
     * (the reference refuses with 429 without touching shadow) */

    if (s3_dos_pw_locked(&user, s3_current_msec) == 1) {
        s3_log_error(S3_LOG_WARN, &s3_srv_log, 0,
                     "password auth for %.*s refused: the account is locked out", (int)user.len,
                     (const char *)user.data);
        return 429;
    }

    rc = S3_DECLINED;
    known = 0;

    if (s3_srv_passfile != NULL) {

        rc = s3_ssh3_auth_password_file_check(s3_srv_passfile, &user, &basic_pass);

        /* only the users the backend knows accumulate toward the
         * lockout; the unreadable file (S3_ERROR) is a server
         * misconfiguration, not an attempt of the account */

        if (rc == S3_DECLINED && s3_srv_passfile_has_user(s3_srv_passfile, &user) == S3_OK) {
            known = 1;
        }
    }

    if (rc != S3_OK && s3_srv_password_system) {

        /* the second backend of the chain: the system accounts, the
         * same booking gate - the names the passwd database resolves
         * book, the invented ones lock nobody (the anti
         * user-enumeration rule of the reference); the unprivileged
         * daemon rides the fail-closed decline of the verifier */

        rc = s3_ssh3_auth_password_system_check(&user, &basic_pass);

        if (rc == S3_DECLINED && s3_ssh3_auth_system_user_known(&user) == S3_OK) {
            known = 1;
        }
    }

    if (rc != S3_OK) {
        fprintf(stderr, "ssh3-server: basic auth: user=%.*s rejected rc=%d\n", (int)user.len,
                (const char *)user.data, (int)rc);

        if (known) {
            s3_dos_pw_failure(&user, s3_current_msec);
        }

        return 401;
    }

    s3_dos_pw_success(&user);

    /* the setuid gate of the session identity (P7.3): the name that
     * no passwd entry backs never spawns, the CONNECT refuses */

    if (s3_srv_run_as && s3_srv_auth_user_gate(&user) != S3_OK) {
        fprintf(stderr, "ssh3-server: run-as user=%.*s does not resolve\n", (int)user.len,
                (const char *)user.data);
        return 401;
    }

    s3_srv_report("INTEROP-AUTH-OK user=%.*s\n", (int)user.len, (const char *)user.data);

    return 200;
}

/*
 * the -K path of one user: a %u token is the session username and a
 * %h token its home directory (the sshd AuthorizedKeysFile shape),
 * the unknown directives stay literal; the username passes the
 * plain-name guard - no leading dot, no separator - so the
 * substitution cannot climb out of the directory; S3_ERROR when the
 * expanded path does not fit or the session user does not resolve
 */

static s3_int_t
s3_srv_keyfile_user_path(const char *pattern, const s3_str_t *user, char *out, size_t size)
{
    const char    *p;
    char          *o = out;
    size_t         left = size - 1, i;
    struct passwd *pw = NULL;

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

        if (p[1] == 'h') {

            /* the home of the session user: the passwd entry decides
             * (the getpwnam shape of the default identities chain),
             * the unknown or home-less user fails the path; the same
             * plain-name guard as %u fences the lookup key */

            char name[256];

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

            if (user->len >= sizeof(name)) {
                return S3_ERROR;
            }

            memcpy(name, user->data, user->len);
            name[user->len] = '\0';

            pw = getpwnam(name);

            if (pw == NULL || pw->pw_dir == NULL || pw->pw_dir[0] == '\0') {
                return S3_ERROR;
            }

            i = strlen(pw->pw_dir);

            if (i > left) {
                return S3_ERROR;
            }

            memcpy(o, pw->pw_dir, i);

            o += i;
            left -= i;
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
 * the Bearer JWT verdict against the -K authorized_keys files (the
 * pubkey step of the reference chain): the username comes from the
 * CONNECT target (?user=), the jti binding rides the TLS exporter
 * ("EXPORTER-SSH3", the conversation id the reference signs into the
 * token).  The files walk in order, the first key that verifies
 * wins; without any -K the default chain of the session user serves
 * (the reference GetAuthorizedIdentities(): both files merge, so a
 * file without the matching key never hides the next one - the walk
 * keeps going after a missing or unreadable file)
 */

static unsigned
s3_srv_h3_jwt_verdict(void)
{
    s3_str_t    header, path, user;
    u_char      conv[32];
    char        expanded[S3_SRV_KEYFILES_MAX][512];
    char        chain[1024];
    const char *files[S3_SRV_KEYFILES_MAX];
    unsigned    nfiles = 0, i;
    s3_int_t    rc;

    header.data = s3_srv_h3_auth;
    header.len = s3_srv_h3_auth_len;

    path.data = s3_srv_h3_path;
    path.len = s3_srv_h3_path_len;

    s3_str_null(&user);

    rc = s3_ssh3_auth_user_from_path(&path, &user);

    if (rc != S3_OK) {
        fprintf(stderr, "ssh3-server: pubkey auth: no user in the path\n");
        return 401;
    }

    if (s3_srv_keyfiles_n > 0) {

        for (i = 0; i < s3_srv_keyfiles_n; i++) {

            if (strchr(s3_srv_keyfiles[i], '%') != NULL) {

                rc = s3_srv_keyfile_user_path(s3_srv_keyfiles[i], &user, expanded[i],
                                              sizeof(expanded[i]));

                if (rc != S3_OK) {
                    fprintf(stderr, "ssh3-server: pubkey auth: bad keys path for user=%.*s\n",
                            (int)user.len, (const char *)user.data);
                    return 401;
                }

                files[nfiles++] = expanded[i];

            } else {
                files[nfiles++] = s3_srv_keyfiles[i];
            }
        }

    } else {

        rc = s3_ssh3_auth_default_chain(&user, chain, sizeof(chain), files, &nfiles);

        if (rc != S3_OK) {
            fprintf(stderr, "ssh3-server: pubkey auth: no default chain for user=%.*s\n",
                    (int)user.len, (const char *)user.data);
            return 401;
        }
    }

    if (s3_srv_h3_pc == NULL || s3_srv_h3_pc->ssl == NULL ||
        s3_srv_h3_pc->ssl->connection == NULL ||
        SSL_export_keying_material(s3_srv_h3_pc->ssl->connection, conv, sizeof(conv),
                                   "EXPORTER-SSH3", 13, NULL, 0, 0) != 1) {
        fprintf(stderr, "ssh3-server: pubkey auth: exporter failed\n");
        return 401;
    }

    rc = S3_DECLINED;

    for (i = 0; i < nfiles && rc != S3_OK; i++) {

        rc = s3_ssh3_auth_jwt_verify(&header, &user, files[i], conv, sizeof(conv));

        if (rc == S3_ERROR) {

            /* the unreadable file walks on: the reference skips the
             * missing one the same way, the remaining files decide */

            fprintf(stderr, "ssh3-server: pubkey auth: keys file %s unreadable\n", files[i]);

            rc = S3_DECLINED;
        }
    }

    if (rc != S3_OK) {
        fprintf(stderr, "ssh3-server: pubkey auth: user=%.*s rejected rc=%d\n", (int)user.len,
                (const char *)user.data, (int)rc);
        return 401;
    }

    /* the setuid gate of the session identity (P7.3), the Basic
     * verdict note applies verbatim */

    if (s3_srv_run_as && s3_srv_auth_user_gate(&user) != S3_OK) {
        fprintf(stderr, "ssh3-server: run-as user=%.*s does not resolve\n", (int)user.len,
                (const char *)user.data);
        return 401;
    }

    s3_srv_report("INTEROP-AUTH-OK user=%.*s\n", (int)user.len, (const char *)user.data);

    return 200;
}

/*
 * the OIDC verdict (the reference authorized_identities chain): the
 * Bearer scheme carries the id_token, the expected nonce derives
 * from the EXPORTER-SSH3 exporter of the live conversation (the
 * reference ConversationID), the issuer, the audience and the
 * provider signature decide; the discovery and the first key set ran
 * once at the startup, the unknown kid only schedules the background
 * refetch of the timer (the retryable kid reject answers the
 * request) - the verdict never blocks on the provider
 */

static void
s3_srv_oidc_timer_handler(s3_event_t *ev)
{
    time_t now = time(NULL);

    /*
     * the jwks timer: the scheduled unknown-kid refetch and the ttl
     * rotation run here, outside the request path; a failed cycle
     * keeps the old key set (the grace) and rides the retry cadence
     */

    if (s3_ssh3_oidc_verifier_fetch_timer(&s3_srv_oidc_ver, now) == 0 &&
        s3_ssh3_oidc_verifier_fetch(&s3_srv_oidc_ver, now) != S3_OK) {
        s3_log_error(S3_LOG_ERR, &s3_srv_log, 0, "oidc jwks fetch failed, %u stale key(s) serve on",
                     (s3_uint_t)s3_srv_oidc_ver.jwks.nkeys);
    }

    s3_event_add_timer(ev, s3_ssh3_oidc_verifier_fetch_timer(&s3_srv_oidc_ver, time(NULL)));
}

static unsigned
s3_srv_h3_oidc_verdict(s3_connection_t *pc)
{
    static const s3_str_t scheme = s3_string("Bearer ");

    const char *why;
    char        nonce[64];
    s3_str_t    token;
    s3_int_t    rc;

    token.data = s3_srv_h3_auth;
    token.len = s3_srv_h3_auth_len;

    if (token.len <= scheme.len || s3_memcmp(token.data, scheme.data, scheme.len) != 0) {
        fprintf(stderr, "ssh3-server: oidc auth: the scheme is not Bearer\n");
        return 401;
    }

    token.data += scheme.len;
    token.len -= scheme.len;

    if (pc->ssl == NULL || pc->ssl->connection == NULL ||
        s3_ssh3_oidc_conversation_nonce(pc->ssl->connection, nonce) != S3_OK) {
        fprintf(stderr, "ssh3-server: oidc auth: no conversation nonce\n");
        return 401;
    }

    rc = s3_ssh3_oidc_verifier_verify(&s3_srv_oidc_ver, s3_srv_oidc_aud, (const char *)token.data,
                                      nonce, time(NULL));

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
        fprintf(stderr, "ssh3-server: oidc auth: rejected:%s rc=%d\n", why, (int)rc);
        return 401;
    }

    s3_srv_report("INTEROP-AUTH-OK user=oidc iss=%s\n", s3_srv_oidc_issuer);

    return 200;
}

static void
s3_srv_h3_respond(s3_connection_t *pc)
{
    unsigned          code;
    unsigned          dos_slot = 0;
    s3_ssh3_version_t ver;

    if (s3_srv_h3_responded) {
        return;
    }

    /* the identity snapshot rides the verdicts that carry a session
     * username (the Basic and the pubkey gates); the oidc and the
     * no-auth shapes answer without one - the sessions keep the
     * daemon identity there */

    s3_srv_auth_user[0] = '\0';

    /* RFC 9220: :protocol marks an extended CONNECT, the :path route
     * is the configured --url-path (the reference -url-path); the
     * query part carries the auth username (docs/P4-WIRE.md 7 step 3)
     * and does not affect the route */

    if (s3_srv_h3_method_len == 7 && s3_memcmp(s3_srv_h3_method, "CONNECT", 7) == 0 &&
        s3_srv_h3_protocol_len == 4 && s3_memcmp(s3_srv_h3_protocol, "ssh3", 4) == 0 &&
        s3_srv_h3_path_len >= s3_srv_url_path_len &&
        s3_memcmp(s3_srv_h3_path, s3_srv_url_path, s3_srv_url_path_len) == 0 &&
        (s3_srv_h3_path_len == s3_srv_url_path_len || s3_srv_h3_path[s3_srv_url_path_len] == '?')) {

        /* RFC 9114, 4.4: the extended CONNECT carries :scheme and
         * :authority next to :method, :protocol and :path */

        if (s3_srv_h3_scheme_len == 0 || s3_srv_h3_authority_len == 0) {
            code = 400;

        } else if (s3_srv_h3_ua_len == 0 ||
                   s3_ssh3_version_parse(s3_srv_h3_ua, s3_srv_h3_ua_len, &ver) != S3_OK ||
                   s3_ssh3_version_supported(&ver) != S3_OK) {

            /* the reference rejects a bad user-agent before anything
             * else (go_server: 403 unsupported SSH3 version) */

            code = 403;

        } else if (pc->ssl == NULL || !pc->ssl->handshaked) {

            /* RFC 8470: a request that arrived in early data may be
             * replayed, the reference answers 425 until the handshake
             * is done (go_server: TLS handshake incomplete) */

            code = 425;

        } else if (s3_dos_unauth_try_acquire() != S3_OK) {

            /*
             * the MaxStartups analog of the reference (CTO_TASK 4.1):
             * the unauthenticated phase holds a DoS slot, the request
             * over the cap refuses before any per-request work worth
             * protecting - no user lookup, no identity-file read, no
             * signature verification runs (the reference F-06, the
             * slot lands here after the version and the early-data
             * gates, exactly where the go handler takes it)
             */

            s3_log_error(S3_LOG_WARN, &s3_srv_log, 0,
                         "too many unauthenticated conversations (%ui active),"
                         " the CONNECT is refused",
                         (s3_uint_t)s3_dos_unauth_count());

            code = 503;

        } else {

            /* the verdict chain of the reference runs under the DoS
             * slot: the OIDC mode lets the Bearer id_token of the
             * provider decide, the conversation nonce binds it */

            dos_slot = 1;

            s3_str_t header;

            header.data = s3_srv_h3_auth;
            header.len = s3_srv_h3_auth_len;

            if (s3_srv_oidc_issuer != NULL) {

                code = s3_srv_h3_oidc_verdict(pc);

            } else if (s3_srv_h3_auth_len > 0 && s3_ssh3_auth_jwt_bearer(&header) == S3_OK) {

                /* the pubkey step: the Bearer token verifies against
                 * the -K files, or against the default identities
                 * chain of the session user when none is given (the
                 * reference always runs it) */

                code = s3_srv_h3_jwt_verdict();

            } else if (s3_srv_passfile != NULL || s3_srv_password_system) {

                /* the Basic step: the password backends decide (the
                 * -P file, then the system accounts); the login is
                 * on by default (the PasswordAuthentication yes of
                 * the sshd canon, the wave 1e), the explicit off
                 * (--enable-password-login off) closes the step with
                 * 401 - the sshd PasswordAuthentication no shape */

                code = s3_srv_password_enabled ? s3_srv_h3_basic_verdict() : 401;

            } else if (s3_srv_keyfiles_n == 0) {

                /* the open harness mode: no auth mechanism is wired,
                 * any authorization header passes (the interop
                 * fixtures send a filler token) */

                code = s3_srv_h3_auth_len ? 200 : 401;

            } else {
                code = 401;
            }
        }

    } else {
        code = 400;
    }

    if (code == 200) {
        s3_srv_report("INTEROP-H3-CONNECT-OK authlen=%zu\n", s3_srv_h3_auth_len);

    } else {
        s3_srv_report("INTEROP-H3-REJECT code=%u\n", code);
    }

    s3_srv_h3_send_status(code);

    if (dos_slot) {

        /*
         * the slot is released when the auth phase ends, whatever the
         * verdict - it never survives a successful authentication,
         * or the logins would brick the server with 503s (the
         * reference F-03, the unconditional release of e61aca0)
         */

        s3_dos_unauth_release();
        dos_slot = 0;
    }

    if (code != 200) {
        /* the rejected request stream closes right after the status */
        (void)s3_quic_shutdown_stream(s3_srv_h3_sc, S3_WRITE_SHUTDOWN);
    }

    s3_srv_h3_responded = 1;
}

static void
s3_srv_h3_request_read(s3_event_t *ev)
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

        if (s3_srv_h3_responded) {

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

        if (s3_srv_h3_len == s3_srv_h3_cap) {
            size_t  cap;
            u_char *grown;

            /* the S2-01 bound on the request path: a full buffer with
             * no complete request inside is a peer trickling bytes,
             * the stream is torn down instead of growing */

            if (s3_srv_h3_cap >= S3_SRV_H3_BUF_MAX) {
                fprintf(stderr, "ssh3-server: h3 request overgrown\n");
                (void)s3_quic_cancelable_stream(sc);
                (void)s3_quic_shutdown_stream(sc, S3_RDWR_SHUTDOWN);
                return;
            }

            cap = s3_srv_h3_cap + 262144;

            if (cap > S3_SRV_H3_BUF_MAX) {
                cap = S3_SRV_H3_BUF_MAX;
            }

            grown = realloc(s3_srv_h3_buf, cap);

            if (grown == NULL) {
                fprintf(stderr, "ssh3-server: h3 buffer growth failed\n");
                exit(1);
            }

            s3_srv_h3_buf = grown;
            s3_srv_h3_cap = cap;
        }

        n = sc->recv(sc, s3_srv_h3_buf + s3_srv_h3_len, s3_srv_h3_cap - s3_srv_h3_len);

        if (n == (ssize_t)S3_AGAIN) {
            return;
        }

        if (n == 0) {
            /* the peer fin before a complete request: nothing to answer */
            (void)s3_quic_shutdown_stream(sc, S3_WRITE_SHUTDOWN);
            return;
        }

        if (n < 0) {
            fprintf(stderr, "ssh3-server: h3 request recv error\n");
            return;
        }

        s3_srv_h3_len += (size_t)n;

        b.pos = s3_srv_h3_buf;
        b.last = s3_srv_h3_buf + s3_srv_h3_len;

        for (;;) {

            /*
             * ssh3-c: the parent connection goes into the parser, the
             * frozen s3_h3_get_session() macro reads c->data and the
             * session hangs exactly there; the stream connection's
             * data is the s3_quic_stream_t (the reference sc->quic)
             */
            rc = s3_h3_parse_headers(pc, &s3_srv_h3_parse, &b);

            if (rc == S3_AGAIN || rc == S3_BUSY) {
                break;
            }

            if (rc == S3_OK) {
                /* one field line done, the section continues */
                s3_srv_h3_capture(&s3_srv_h3_parse.field_rep.field);
                continue;
            }

            if (rc == S3_DONE) {
                /* the last field line lands together with the section end */
                s3_srv_h3_capture(&s3_srv_h3_parse.field_rep.field);
                s3_srv_h3_respond(pc);
                break;
            }

            /* QPACK or HTTP/3 error: no useful answer exists */
            fprintf(stderr, "ssh3-server: h3 request parse error %d\n", (int)rc);
            (void)s3_quic_shutdown_stream(sc, S3_WRITE_SHUTDOWN);
            return;
        }

        /* the consumed bytes compact to the front of the receive buffer */
        s3_srv_h3_len = (size_t)(b.last - b.pos);
        s3_memmove(s3_srv_h3_buf, b.pos, s3_srv_h3_len);
    }
}

static void
s3_srv_h3_stream_write(s3_event_t *ev)
{
    (void)ev;

    s3_srv_h3_flush();
}

/*
 * the ssh3 session channels (-3): accept, the 91 confirmation and the
 * stateless 94 echo, the wire shape of docs/P4-WIRE.md 2 and 3.1
 */

static void
s3_srv_h3_channel_free(s3_srv_h3_channel_t *ch)
{
    /* the sftp budget slot dies with the channel that took it (S2-02) */

    if (ch->sftp_budgeted) {
        ch->sftp_budgeted = 0;
        s3_srv_sftp_budget_give(ch->sess_user);
    }

    /* the pump timers must leave the rbtree before the memory goes */

    if (ch->fwd_timer.timer_set) {
        s3_event_del_timer(&ch->fwd_timer);
    }

    if (ch->agent_timer.timer_set) {
        s3_event_del_timer(&ch->agent_timer);
    }

    s3_srv_session_teardown(ch);

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

    /* the chroot child of the sftp channel: the pipes first (the eof
     * ends the serve), then the process - the session teardown
     * shape; the pump reaps the exited child, the pid survives until
     * then */

    if (ch->sftp_in >= 0) {
        (void)close(ch->sftp_in);
    }

    if (ch->sftp_out >= 0) {
        (void)close(ch->sftp_out);
    }

    if (ch->sftp_pid > 0) {
        (void)kill(ch->sftp_pid, SIGKILL);
        (void)waitpid(ch->sftp_pid, NULL, 0);
    }

    if (ch->fwd_fd >= 0) {
        (void)close(ch->fwd_fd);
    }

    /* the reverse forward bookkeeping: the forwarded-* budget gives
     * the slot back, the udp peer entry clears (the listener keeps
     * serving the remaining peers) */

    if (ch->reverse_fwd) {

        if (s3_srv_reverse.forwarded > 0) {
            s3_srv_reverse.forwarded--;
        }

        if (ch->fwd_kind == S3_SRV_FWD_RUDP && ch->reverse_l < S3_SRV_REVERSE_LISTENERS_MAX) {

            s3_srv_reverse_listener_t *l = &s3_srv_reverse.listener[ch->reverse_l];

            if (l->used && ch->reverse_peer < S3_SRV_REVERSE_UDP_PEERS_MAX &&
                l->peers[ch->reverse_peer].sc == ch->sc) {

                l->peers[ch->reverse_peer].used = 0;
                l->peers[ch->reverse_peer].sc = NULL;

                if (l->used_peers > 0) {
                    l->used_peers--;
                }
            }
        }
    }

    if (ch == s3_srv_h3_udp_fwd) {
        s3_srv_h3_udp_fwd = NULL;
    }

    free(ch->buf);
    free(ch->fwd_in);
    free(ch->fwd_out);

    s3_memzero(ch, sizeof(*ch));
}

static s3_srv_h3_channel_t *
s3_srv_h3_channel_of(s3_connection_t *sc)
{
    unsigned i;

    for (i = 0; i < S3_SRV_TRACKED; i++) {

        if (s3_srv_h3_channels[i].sc == sc) {
            return &s3_srv_h3_channels[i];
        }
    }

    return NULL;
}

/*
 * the slot of a fresh channel (the accept path and the
 * server-initiated agent connections share it); NULL when the table
 * is full, the caller tears the stream down
 */

/*
 * the identity snapshot of the CONNECT (P7.3): the verdict serialized
 * the username, the session spawns from the channel copy - the static
 * verdict buffer may move on with the next CONNECT; the accept paths
 * (the channel alloc and the inline stream accept) ride it
 */
static void
s3_srv_channel_user_snapshot(s3_srv_h3_channel_t *ch)
{
    if (s3_srv_auth_user[0] != '\0') {
        snprintf(ch->sess_user, sizeof(ch->sess_user), "%s", s3_srv_auth_user);
    }
}

static s3_srv_h3_channel_t *
s3_srv_h3_channel_alloc(s3_connection_t *sc)
{
    unsigned i;

    for (i = 0; i < S3_SRV_TRACKED; i++) {

        if (s3_srv_h3_channels[i].sc == NULL) {
            s3_memzero(&s3_srv_h3_channels[i], sizeof(s3_srv_h3_channels[i]));
            s3_srv_h3_channels[i].sc = sc;
            s3_srv_h3_channels[i].fwd_fd = -1;
            s3_srv_h3_channels[i].sftp_in = -1;
            s3_srv_h3_channels[i].sftp_out = -1;

            s3_srv_channel_user_snapshot(&s3_srv_h3_channels[i]);

            return &s3_srv_h3_channels[i];
        }
    }

    return NULL;
}

static void
s3_srv_h3_channel_cancel(s3_srv_h3_channel_t *ch, const char *why)
{
    s3_quic_stream_t *qs = ch->sc->data;

    /* the reference answer to a bad channel is cancel(0) */

    fprintf(stderr, "ssh3-server: channel id=%llu %s\n", (unsigned long long)qs->id, why);

    (void)s3_quic_cancelable_stream(ch->sc);
    (void)s3_quic_shutdown_stream(ch->sc, S3_RDWR_SHUTDOWN);

    s3_srv_h3_channel_free(ch);
}

static s3_int_t
s3_srv_h3_channel_echo(s3_connection_t *sc, const u_char *data, size_t len)
{
    u_char *p;
    size_t  total;
    ssize_t m;

    total = s3_ssh3_varint_size(S3_SSH3_MSG_CHANNEL_DATA) + s3_ssh3_sshstring_size(len);

    if (total > sizeof(s3_srv_h3_ch_out)) {
        return S3_ERROR;
    }

    p = s3_srv_h3_ch_out;
    p = (u_char *)s3_ssh3_encode_varint(p, S3_SSH3_MSG_CHANNEL_DATA);
    p = (u_char *)s3_ssh3_encode_sshstring(p, data, len);

    m = s3_quic_stream_send(sc, s3_srv_h3_ch_out, total);

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
s3_srv_h3_channel_send_extended(s3_connection_t *sc, const u_char *data, size_t len)
{
    u_char *p;
    size_t  total;
    ssize_t m;

    total = s3_ssh3_varint_size(S3_SSH3_MSG_CHANNEL_EXTENDED_DATA) +
            s3_ssh3_varint_size(S3_SSH3_EXTENDED_DATA_STDERR) + s3_ssh3_sshstring_size(len);

    if (total > sizeof(s3_srv_h3_ch_out)) {
        return S3_ERROR;
    }

    p = s3_srv_h3_ch_out;
    p = (u_char *)s3_ssh3_encode_varint(p, S3_SSH3_MSG_CHANNEL_EXTENDED_DATA);
    p = (u_char *)s3_ssh3_encode_varint(p, S3_SSH3_EXTENDED_DATA_STDERR);
    p = (u_char *)s3_ssh3_encode_sshstring(p, data, len);

    m = s3_quic_stream_send(sc, s3_srv_h3_ch_out, total);

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
s3_srv_session_shell(void)
{
    const char *shell = getenv("SHELL");

    return (shell != NULL && *shell != '\0') ? shell : "/bin/sh";
}

/*
 * the spawn program of the session: the login shell of the resolved
 * user under the per-session setuid (the OpenSSH shape - the user's
 * passwd shell, not the daemon's), the $SHELL of the daemon identity
 * otherwise
 */
static const char *
s3_srv_session_shell_of(s3_srv_h3_channel_t *ch)
{
    const char *shell;

    if (ch->sess != NULL) {

        shell = s3_ssh3_session_srv_login_shell(ch->sess);

        if (shell != NULL) {
            return shell;
        }
    }

    return s3_srv_session_shell();
}

static s3_int_t
s3_srv_session_start(s3_srv_h3_channel_t *ch)
{
    if (ch->sess != NULL) {
        return S3_OK;
    }

    ch->sess_pool = s3_create_pool(S3_DEFAULT_POOL_SIZE, &s3_srv_log);

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
     * the per-session identity (P7.3): the authenticated name of the
     * conversation resolves before any pty or spawn - the pty of the
     * root-opened session gets its ownership and the child drops
     * onto the user at the spawn; a CONNECT without a session
     * username (the drain harness, the oidc identity) keeps the
     * daemon identity - the unprivileged shape of the run
     */

    if (s3_srv_run_as && ch->sess_user[0] != '\0' &&
        s3_ssh3_session_srv_run_as(ch->sess, ch->sess_user) != S3_OK) {
        fprintf(stderr, "ssh3-server: run-as %s refused\n", ch->sess_user);
        s3_destroy_pool(ch->sess_pool);
        ch->sess_pool = NULL;
        ch->sess = NULL;
        return S3_ERROR;
    }

    /*
     * the agent path of the forward-agent marker rides the child env
     * (the reference setupEnv), the spawn is still ahead
     */

    if (ch->agent_l != NULL &&
        s3_ssh3_session_srv_env(ch->sess, "SSH_AUTH_SOCK", ch->agent_path) != S3_OK) {
        fprintf(stderr, "ssh3-server: SSH_AUTH_SOCK env failed\n");
    }

    return S3_OK;
}

static void
s3_srv_session_teardown(s3_srv_h3_channel_t *ch)
{
    s3_ssh3_session_srv_t *s = ch->sess;
    int                    in, out, err, master;

    if (s == NULL) {
        return;
    }

    /* the watches and the verdict watchdog leave before the pool */

    s3_ssh3_session_srv_unwatch(s);

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
s3_srv_request_body_end(s3_ssh3_request_kind_t kind, const u_char *pos, const u_char *end)
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
s3_srv_session_send_exit(s3_connection_t *sc, uint64_t code)
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

/*
 * the io sinks of the event-driven pump: the wire framing stays here,
 * the module owns the fds and the drain; a stalled send loses the
 * chunk exactly like the polling pump did
 */

static s3_int_t
s3_srv_session_out_sink(void *ctx, const u_char *data, size_t len)
{
    s3_srv_h3_channel_t *ch = ctx;

    if (s3_srv_h3_channel_echo(ch->sc, data, len) != S3_OK) {
        fprintf(stderr, "ssh3-server: session output send stalled\n");
        return S3_ERROR;
    }

    return S3_OK;
}

static s3_int_t
s3_srv_session_err_sink(void *ctx, const u_char *data, size_t len)
{
    s3_srv_h3_channel_t *ch = ctx;

    if (s3_srv_h3_channel_send_extended(ch->sc, data, len) != S3_OK) {
        fprintf(stderr, "ssh3-server: session stderr send stalled\n");
        return S3_ERROR;
    }

    return S3_OK;
}

static s3_int_t
s3_srv_session_exit_sink(void *ctx, uint64_t code)
{
    s3_srv_h3_channel_t *ch = ctx;

    if (s3_srv_session_send_exit(ch->sc, code) != S3_OK) {
        fprintf(stderr, "ssh3-server: exit-status send failed\n");
        return S3_ERROR;
    }

    /* the reference shuts the channel send side after the verdict */

    (void)s3_quic_shutdown_stream(ch->sc, S3_WRITE_SHUTDOWN);

    ch->sess_exit_sent = 1;

    s3_srv_report("INTEROP-SESSION-EXIT code=%u\n", (unsigned)code);

    return S3_OK;
}

static void
s3_srv_session_pump(s3_srv_h3_channel_t *ch)
{
    s3_ssh3_session_srv_io_t io;

    if (ch->sess == NULL) {
        return;
    }

    io.ctx = ch;
    io.output = s3_srv_session_out_sink;
    io.err = s3_srv_session_err_sink;
    io.exit = s3_srv_session_exit_sink;

    (void)s3_ssh3_session_srv_pump(ch->sess, &io);

    if (ch->sess_exit_sent && ch->sess_peer_fin && ch->sc != NULL) {

        /*
         * the peer drained to fin before the verdict: the fin was the
         * last byte this channel carries, the drop runs the quic
         * stream cleanup (the retire queues MAX_STREAMS) and the slot
         * frees for the next session; the free stays out of the sinks
         * - the module pump still holds the session on its way back
         */
        s3_close_connection(ch->sc);
        ch->sc = NULL;

        s3_srv_h3_channel_free(ch);
    }
}

/* the watch entry of the module, the readiness runs this pump */

static void
s3_srv_session_pump_cb(void *ctx)
{
    s3_srv_session_pump((s3_srv_h3_channel_t *)ctx);
}

/* the fd watches arm at the spawn, the readiness pumps the session */

static void
s3_srv_session_arm(s3_srv_h3_channel_t *ch)
{
    if (s3_ssh3_session_srv_watch(ch->sess, ch->sess_pool, &s3_srv_log, s3_srv_session_pump_cb,
                                  ch) != S3_OK) {
        fprintf(stderr, "ssh3-server: session watch failed\n");
    }
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
s3_srv_h3_type_is(const s3_str_t *type, const char *name)
{
    size_t n = strlen(name);

    return type->len == n && s3_memcmp(type->data, name, n) == 0;
}

static s3_int_t
s3_srv_fwd_append(u_char **buf, size_t *cap, size_t *len, const u_char *data, size_t n)
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
s3_srv_fwd_socket_flush(s3_srv_h3_channel_t *ch)
{
    while (ch->fwd_in_len > 0) {

        ssize_t m;

        if (ch->fwd_kind == S3_SRV_FWD_TCP || ch->fwd_kind == S3_SRV_FWD_AGENT) {
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
s3_srv_fwd_flush(s3_srv_h3_channel_t *ch)
{
    static u_char frame[S3_SRV_FWD_FRAME];
    size_t        chunk;
    ssize_t       m;

    for (;;) {

        if (ch->fwd_frame_sent == ch->fwd_frame_total) {

            if (ch->fwd_out_len == 0) {
                return;
            }

            /* a new frame: the payload copy rides the static buffer,
             * the pending bytes drop at once */

            chunk = s3_ssh3_channel_chunk_size(S3_SRV_CHANNEL_MAX_PACKET, 0);

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
            fprintf(stderr, "ssh3-server: forward send failed\n");
            s3_srv_h3_channel_free(ch);
            return;
        }

        ch->fwd_frame_sent += (size_t)m;
    }
}

/* the target reply rides the datagram prefix back to the client */

static void
s3_srv_fwd_udp_reply(s3_srv_h3_channel_t *ch, const u_char *data, size_t len)
{
    s3_quic_stream_t *qs = ch->sc->data;
    u_char            dg[2048];
    u_char           *p;

    /* the harness payloads fit one datagram, the bigger ones drop */

    if (len + 8 > sizeof(dg)) {
        return;
    }

    p = s3_ssh3_dgram_encode(dg, s3_srv_h3_conv_id, qs->id, data, len);

    (void)s3_quic_send_datagram(qs->parent, dg, (size_t)(p - dg));
}

static void
s3_srv_fwd_pump(s3_srv_h3_channel_t *ch)
{
    static u_char buf[16384];
    ssize_t       n;

    /* the pending channel bytes ride the socket first */
    s3_srv_fwd_socket_flush(ch);

    if (ch->fwd_kind == S3_SRV_FWD_TCP || ch->fwd_kind == S3_SRV_FWD_AGENT) {

        if (!ch->fwd_eof) {

            for (;;) {

                n = recv(ch->fwd_fd, buf, sizeof(buf), 0);

                if (getenv("S3AGENTDBG") != NULL && ch->fwd_kind == S3_SRV_FWD_AGENT) {
                    fprintf(stderr, "agdbg srv pump fd=%d n=%ld\n", ch->fwd_fd, (long)n);
                }

                if (n > 0) {

                    if (s3_srv_fwd_append(&ch->fwd_out, &ch->fwd_out_cap, &ch->fwd_out_len, buf,
                                          (size_t)n) != S3_OK) {
                        fprintf(stderr, "ssh3-server: forward buffer growth failed\n");
                        s3_srv_h3_channel_free(ch);
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

                fprintf(stderr, "ssh3-server: forward target read error\n");
                s3_srv_h3_channel_free(ch);
                return;
            }
        }

    } else {

        /* the udp replies: one datagram per recvfrom */

        for (;;) {

            n = recvfrom(ch->fwd_fd, buf, sizeof(buf), 0, NULL, NULL);

            if (n <= 0) {

                if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    fprintf(stderr, "ssh3-server: forward target read error\n");
                }

                break;
            }

            s3_srv_fwd_udp_reply(ch, buf, (size_t)n);
        }
    }

    s3_srv_fwd_flush(ch);

    if (ch->fwd_eof && ch->fwd_out_len == 0 && ch->fwd_frame_sent == ch->fwd_frame_total) {

        /* the relay is over: the fin goes out, the channel ends */

        (void)s3_quic_shutdown_stream(ch->sc, S3_WRITE_SHUTDOWN);
        s3_srv_h3_channel_free(ch);
    }
}

static void
s3_srv_fwd_timer(s3_event_t *ev)
{
    s3_srv_h3_channel_t *ch = ev->data;

    ev->timedout = 0;

    if (getenv("S3AGENTDBG") != NULL && ch->fwd_kind == S3_SRV_FWD_AGENT) {
        fprintf(stderr, "agdbg fwd tick eof=%u\n", (unsigned)ch->fwd_eof);
    }

    if (ch->sftp != NULL) {
        s3_srv_sftp_pump(ch);

    } else if (ch->fwd_kind == S3_SRV_FWD_SFTP) {

        /* the chroot child: the pipes drain instead of the engine */

        s3_srv_sftp_child_pump(ch);

    } else {
        s3_srv_fwd_pump(ch);
    }

    /* the pump stops once the channel is gone (the free zeroes the
     * struct), a live forward keeps ticking */

    if (ch->sc != NULL && (ch->fwd_kind != S3_SRV_FWD_NONE || ch->sftp != NULL)) {
        s3_event_add_timer(ev, 50);
    }
}

static void
s3_srv_fwd_arm(s3_srv_h3_channel_t *ch)
{
    if (ch->fwd_timer.timer_set) {
        return;
    }

    ch->fwd_timer.data = ch;
    ch->fwd_timer.log = &s3_srv_log;
    ch->fwd_timer.handler = s3_srv_fwd_timer;

    s3_event_add_timer(&ch->fwd_timer, 50);
}

/*
 * the per-user sftp budget (S2-02): one slot per live sftp channel of
 * the user, the empty username (a CONNECT without a user) is a key of
 * its own.  The table is scanned linearly, its size is a constant and
 * the daemon serves one conversation at a time; a full table with no
 * entry of the user refuses (fail-closed, unreachable in the
 * single-conversation shape)
 */

static unsigned
s3_srv_sftp_budget_take(const char *user)
{
    size_t len = strlen(user);

    if (s3_srv_sftp_cap == 0) {
        return 1;
    }

    if (len == 0) {

        /* the daemon-identity CONNECTs, the key of their own */

        if (s3_srv_sftp_budget_none >= s3_srv_sftp_cap) {
            return 0;
        }

        s3_srv_sftp_budget_none++;
        return 1;
    }

    if (len > S3_SRV_SFTP_USER_MAX) {
        len = S3_SRV_SFTP_USER_MAX;
    }

    for (unsigned i = 0; i < S3_SRV_SFTP_BUDGET_USERS; i++) {

        s3_srv_sftp_budget_t *b = &s3_srv_sftp_budgets[i];

        if (b->user[0] != '\0' && strlen(b->user) == len && memcmp(b->user, user, len) == 0) {

            if (b->n >= s3_srv_sftp_cap) {
                return 0;
            }

            b->n++;
            return 1;
        }
    }

    for (unsigned i = 0; i < S3_SRV_SFTP_BUDGET_USERS; i++) {

        s3_srv_sftp_budget_t *b = &s3_srv_sftp_budgets[i];

        if (b->user[0] == '\0') {
            s3_memcpy(b->user, user, len);
            b->user[len] = '\0';
            b->n = 1;
            return 1;
        }
    }

    return 0;
}

static void
s3_srv_sftp_budget_give(const char *user)
{
    size_t len = strlen(user);

    if (len == 0) {

        if (s3_srv_sftp_budget_none > 0) {
            s3_srv_sftp_budget_none--;
        }

        return;
    }

    if (len > S3_SRV_SFTP_USER_MAX) {
        len = S3_SRV_SFTP_USER_MAX;
    }

    for (unsigned i = 0; i < S3_SRV_SFTP_BUDGET_USERS; i++) {

        s3_srv_sftp_budget_t *b = &s3_srv_sftp_budgets[i];

        if (b->user[0] != '\0' && strlen(b->user) == len && memcmp(b->user, user, len) == 0) {

            if (b->n > 0) {
                b->n--;
            }

            /* the empty entry frees the table slot */

            if (b->n == 0) {
                b->user[0] = '\0';
            }

            return;
        }
    }
}

/*
 * the sftp subsystem of the "sftp" channel (the wave 2): the chroot
 * mode forks the jailed child (the F-04, the sshd model), the
 * lexical mode keeps the historical in-process request server jailed
 * into the home, the timer drains the replies into the 94 direction
 */

static s3_int_t
s3_srv_sftp_start(s3_srv_h3_channel_t *ch)
{
    s3_str_t       home;
    struct passwd *pw;

    /* the S2-02 budget: the refusal cancels the channel below */

    if (!s3_srv_sftp_budget_take(ch->sess_user)) {
        s3_srv_report("SFTP-SRV-CAP-DENIED user=%s\n", ch->sess_user);
        return S3_ERROR;
    }

    ch->sftp_budgeted = 1;

    if (s3_srv_sftp_chroot) {
        return s3_srv_sftp_chroot_start(ch);
    }

    if (s3_srv_sftp_home[0] != '\0') {

        home.data = (u_char *)s3_srv_sftp_home;
        home.len = strlen(s3_srv_sftp_home);

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
                fprintf(stderr, "ssh3-server: sftp: no home directory\n");
                return S3_ERROR;
            }

            home.data = (u_char *)env_home;
            home.len = strlen(env_home);
        }
    }

    ch->sftp_pool = s3_create_pool(S3_DEFAULT_POOL_SIZE, &s3_srv_log);

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

    s3_srv_report("INTEROP-SFTP-OPEN home=%.*s\n", (int)home.len, (const char *)home.data);

    s3_srv_fwd_arm(ch);

    return S3_OK;
}

/* one drained reply batch rides the pending 94 out-buffer */

static void
s3_srv_sftp_pump(s3_srv_h3_channel_t *ch)
{
    u_char  buf[16384];
    ssize_t n;

    if (ch->sftp == NULL) {
        return;
    }

    if (ch->sftp->protocol_error) {
        s3_srv_h3_channel_cancel(ch, "sftp protocol error");
        return;
    }

    for (;;) {

        n = s3_ssh3_sftp_srv_output(ch->sftp, buf, sizeof(buf));

        if (n <= 0) {
            break;
        }

        if (s3_srv_fwd_append(&ch->fwd_out, &ch->fwd_out_cap, &ch->fwd_out_len, buf, (size_t)n) !=
            S3_OK) {
            fprintf(stderr, "ssh3-server: sftp reply buffer growth failed\n");
            s3_srv_h3_channel_free(ch);
            return;
        }
    }

    s3_srv_fwd_flush(ch);
}

/*
 * the chroot side (the F-04, the sshd internal-sftp model): the
 * network-facing daemon stops touching user paths at all - per sftp
 * channel it forks a child that enters the jail (chroot into the
 * session home, then the full drop) and serves the same request
 * engine over the stdio pair; after the chroot the confinement is
 * the kernel's: absolute symlinks and ".." cannot reach outside, no
 * lexical check is load-bearing anymore
 *
 * the child prep order: the pipes become fd 0 and 1, the daemon
 * descriptors leave (the listeners, the epfd, the other channels),
 * the signals reset, then the jail - any entrance failure is a
 * refused subsystem (_exit 1), never an unjailed serve
 */

static void
s3_srv_sftp_child_write(int fd, const u_char *buf, size_t len)
{
    while (len > 0) {

        ssize_t n = write(fd, buf, len);

        if (n < 0) {

            if (errno == EINTR) {
                continue;
            }

            /* a dead parent killed the pipe (SIGPIPE rides the
             * default here): the child has no work left in any case */

            _exit(1);
        }

        buf += n;
        len -= (size_t)n;
    }
}

/* the serve loop of the child: stdin feeds the engine, the engine
 * replies drain to stdout; the pipes are the blocking contract, one
 * transfer at a time rides them */

static void
s3_srv_sftp_child_main(int in_fd, int out_fd, const char *jail, const char *name, uint32_t uid,
                       uint32_t gid)
{
    s3_log_t            log;
    s3_pool_t          *pool;
    s3_ssh3_sftp_srv_t *t;
    s3_str_t            root;
    u_char              buf[16384];
    ssize_t             n, m;

    /*
     * the jail entrance is the verdict of the whole design: any
     * failure here is a refused subsystem, never an unjailed serve
     */

    if (s3_ssh3_sftp_jail_enter(jail, name, uid, gid) != S3_OK) {
        fprintf(stderr, "ssh3-server: sftp child: the jail entrance failed\n");
        _exit(1);
    }

    log.log_level = S3_LOG_ALERT;
    log.fd = S3_INVALID_FILE;

    pool = s3_create_pool(S3_DEFAULT_POOL_SIZE, &log);

    if (pool == NULL) {
        _exit(1);
    }

    t = s3_pcalloc(pool, sizeof(s3_ssh3_sftp_srv_t));

    root.data = (u_char *)"/";
    root.len = 1;

    /*
     * the served root is "/" now: the jail carries the home content
     * and every spelling lands inside it (the engine keeps the wire,
     * the kernel keeps the paths)
     */

    if (t == NULL || s3_ssh3_sftp_srv_init(t, pool, &root, uid, gid) != S3_OK) {
        _exit(1);
    }

    for (;;) {

        n = read(in_fd, buf, sizeof(buf));

        if (n < 0) {

            if (errno == EINTR) {
                continue;
            }

            _exit(1);
        }

        if (n == 0) {
            /* the parent closed its side: the tail replies ride out */
            break;
        }

        if (s3_ssh3_sftp_srv_input(t, buf, (size_t)n) != S3_OK || t->protocol_error) {
            _exit(1);
        }

        while ((m = s3_ssh3_sftp_srv_output(t, buf, sizeof(buf))) > 0) {
            s3_srv_sftp_child_write(out_fd, buf, (size_t)m);
        }
    }

    while ((m = s3_ssh3_sftp_srv_output(t, buf, sizeof(buf))) > 0) {
        s3_srv_sftp_child_write(out_fd, buf, (size_t)m);
    }

    _exit(0);
}

static s3_int_t
s3_srv_sftp_chroot_start(s3_srv_h3_channel_t *ch)
{
    char          jail[512];
    char          name[128];
    uint32_t      uid, gid;
    s3_int_t      rc;
    int           in_pipe[2], out_pipe[2];
    pid_t         pid;
    struct rlimit rl;
    int           i, max;

    /*
     * the jail resolution and the writability gate: the daemon
     * touches the jail root metadata only, no content and no
     * traversal inside; a refusal here answers the cancel before any
     * process exists
     */

    rc = s3_ssh3_sftp_jail_resolve(s3_srv_sftp_home[0] != '\0' ? s3_srv_sftp_home : NULL,
                                   ch->sess_user[0] != '\0' ? ch->sess_user : NULL, jail,
                                   sizeof(jail), name, sizeof(name), &uid, &gid);

    if (rc == S3_DECLINED) {

        s3_log_error(S3_LOG_ERR, &s3_srv_log, 0,
                     "sftp chroot: no resolvable session user and no -H override, refused");

        return S3_ERROR;
    }

    if (rc != S3_OK) {
        s3_log_error(S3_LOG_ERR, &s3_srv_log, 0, "sftp chroot: the jail path does not resolve");
        return S3_ERROR;
    }

    rc = s3_ssh3_sftp_jail_check(jail);

    if (rc == S3_DECLINED) {

        s3_log_error(S3_LOG_ERR, &s3_srv_log, 0,
                     "sftp chroot: the jail root is group/world-writable, refused");

        return S3_ERROR;
    }

    if (rc != S3_OK) {
        s3_log_error(S3_LOG_ERR, &s3_srv_log, 0, "sftp chroot: the jail root is not a directory");
        return S3_ERROR;
    }

    in_pipe[0] = in_pipe[1] = -1;
    out_pipe[0] = out_pipe[1] = -1;

    if (pipe(in_pipe) != 0 || pipe(out_pipe) != 0) {

        if (in_pipe[0] >= 0) {
            (void)close(in_pipe[0]);
        }

        if (in_pipe[1] >= 0) {
            (void)close(in_pipe[1]);
        }

        if (out_pipe[0] >= 0) {
            (void)close(out_pipe[0]);
        }

        if (out_pipe[1] >= 0) {
            (void)close(out_pipe[1]);
        }

        fprintf(stderr, "ssh3-server: sftp pipe() failed\n");

        return S3_ERROR;
    }

    pid = fork();

    if (pid < 0) {

        (void)close(in_pipe[0]);
        (void)close(in_pipe[1]);
        (void)close(out_pipe[0]);
        (void)close(out_pipe[1]);

        fprintf(stderr, "ssh3-server: sftp fork() failed\n");

        return S3_ERROR;
    }

    if (pid == 0) {

        /*
         * the child: the pipes become the stdio pair, the daemon
         * surface leaves, the signals reset, then the jail and the
         * serve - the body below never returns
         */

        (void)close(in_pipe[1]);
        (void)close(out_pipe[0]);

        if (dup2(in_pipe[0], STDIN_FILENO) < 0 || dup2(out_pipe[1], STDOUT_FILENO) < 0) {
            _exit(1);
        }

        if (in_pipe[0] != STDIN_FILENO) {
            (void)close(in_pipe[0]);
        }

        if (out_pipe[1] != STDOUT_FILENO) {
            (void)close(out_pipe[1]);
        }

        /*
         * the daemon descriptors go: the listeners (a surviving one
         * would hold the port), the epfd, the fds of the other
         * channels; the rlim sweep is the POSIX shape of closefrom,
         * an fd past an infinite cap stays an inert hold
         */

        if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {

            max = rl.rlim_cur == RLIM_INFINITY ? 65536 : (int)rl.rlim_cur;

            for (i = STDERR_FILENO + 1; i < max; i++) {
                (void)close(i);
            }
        }

        (void)signal(SIGPIPE, SIG_DFL);
        (void)signal(SIGHUP, SIG_DFL);
        (void)signal(SIGINT, SIG_DFL);
        (void)signal(SIGTERM, SIG_DFL);

        s3_srv_sftp_child_main(STDIN_FILENO, STDOUT_FILENO, jail, name, uid, gid);
    }

    /*
     * the parent keeps one end per direction, both non-blocking (the
     * 50 ms pump drains them, the fwd scheme); the served root
     * report keeps the lexical marker shape
     */

    (void)close(in_pipe[0]);
    (void)close(out_pipe[1]);

    (void)s3_nonblocking(in_pipe[1]);
    (void)s3_nonblocking(out_pipe[0]);

    ch->fwd_kind = S3_SRV_FWD_SFTP;
    ch->sftp_pid = pid;
    ch->sftp_in = in_pipe[1];
    ch->sftp_out = out_pipe[0];

    s3_srv_report("INTEROP-SFTP-OPEN home=%s\n", jail);

    s3_srv_fwd_arm(ch);

    return S3_OK;
}

/*
 * the byte relay of the chroot child: the pending channel payloads
 * ride the stdin pipe, the child replies ride the 94 out-buffer, the
 * child's death ends the channel (it surfaces as the stdout eof or
 * an EPIPE); the 50 ms timer drives it like the forward pump
 */

static void
s3_srv_sftp_child_pump(s3_srv_h3_channel_t *ch)
{
    static u_char buf[16384];
    ssize_t       n;

    /* the pending payloads ride the child stdin */

    while (ch->sftp_in >= 0 && ch->fwd_in_len > 0) {

        n = write(ch->sftp_in, ch->fwd_in, ch->fwd_in_len);

        if (n > 0) {
            s3_memmove(ch->fwd_in, ch->fwd_in + n, ch->fwd_in_len - (size_t)n);
            ch->fwd_in_len -= (size_t)n;
            continue;
        }

        if (n < 0 && errno == EINTR) {
            continue;
        }

        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;
        }

        /* EPIPE or a dead fd: the child is gone, the stdout eof (or
         * the end shape below) finishes the channel */

        (void)close(ch->sftp_in);
        ch->sftp_in = -1;
        break;
    }

    /* the child replies ride the pending 94 out-buffer */

    while (ch->sftp_out >= 0) {

        n = read(ch->sftp_out, buf, sizeof(buf));

        if (n > 0) {

            if (s3_srv_fwd_append(&ch->fwd_out, &ch->fwd_out_cap, &ch->fwd_out_len, buf,
                                  (size_t)n) != S3_OK) {
                fprintf(stderr, "ssh3-server: sftp reply buffer growth failed\n");
                s3_srv_h3_channel_free(ch);
                return;
            }

            continue;
        }

        if (n == 0) {

            /* the child served everything and left: the 94 tail
             * drains below, the channel shuts down with it */

            (void)close(ch->sftp_out);
            ch->sftp_out = -1;
            ch->fwd_eof = 1;
            break;
        }

        if (errno == EINTR) {
            continue;
        }

        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            break;
        }

        (void)close(ch->sftp_out);
        ch->sftp_out = -1;
        ch->fwd_eof = 1;
        break;
    }

    /* the reap of an exited child, the eof above is the usual way it
     * shows; WNOHANG keeps the pump event-safe */

    if (ch->sftp_pid > 0 && waitpid(ch->sftp_pid, NULL, WNOHANG) == (pid_t)ch->sftp_pid) {
        ch->sftp_pid = 0;
    }

    s3_srv_fwd_flush(ch);

    /* the end shape of the forward pump: the eof is in, the tail is
     * out - the channel ends */

    if (ch->sc != NULL && ch->fwd_eof && ch->fwd_out_len == 0 &&
        ch->fwd_frame_sent == ch->fwd_frame_total) {

        (void)s3_quic_shutdown_stream(ch->sc, S3_WRITE_SHUTDOWN);
        s3_srv_h3_channel_free(ch);
    }
}

/*
 * the agent bridge of the wave 2 (the reference cmd/ssh3-server.go
 * openAgentSocketAndForwardAgent): the forward-agent marker creates
 * the listening socket, every accepted connection opens one
 * server-initiated "agent-connection" channel towards the client
 */

static s3_int_t
s3_srv_agent_listen(s3_srv_h3_channel_t *ch)
{
    s3_str_t path;
    s3_int_t rc;

    if (ch->agent_l != NULL) {
        return S3_OK;
    }

    ch->agent_pool = s3_create_pool(S3_DEFAULT_POOL_SIZE, &s3_srv_log);

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

    s3_srv_report("INTEROP-AGENT-READY sock=%s\n", ch->agent_path);

    ch->agent_timer.data = ch;
    ch->agent_timer.log = &s3_srv_log;
    ch->agent_timer.handler = s3_srv_agent_accept_timer;

    s3_event_add_timer(&ch->agent_timer, 50);

    return S3_OK;
}

/*
 * one accepted agent socket rides a fresh server-initiated channel:
 * the header quotes the CONNECT stream id, the AGENT kind of the pump
 * relays the bytes both ways (the tcp pump against the socket fd)
 */

static void
s3_srv_agent_conn_open(s3_srv_h3_channel_t *sess_ch, int fd)
{
    s3_connection_t     *pc, *nsc;
    s3_srv_h3_channel_t *nch;
    s3_quic_stream_t    *qs;
    s3_ssh3_channel_t    hdr;
    u_char               frame[64];
    u_char              *p;
    size_t               total;
    ssize_t              m;
    s3_event_t          *rev;

    pc = ((s3_quic_stream_t *)sess_ch->sc->data)->parent;

    nsc = s3_quic_open_stream(pc, 1);

    if (nsc == NULL) {
        fprintf(stderr, "ssh3-server: agent channel open_stream failed\n");
        s3_ssh3_agent_close_fd(fd);
        return;
    }

    nch = s3_srv_h3_channel_alloc(nsc);

    if (nch == NULL) {
        fprintf(stderr, "ssh3-server: agent channel table is full\n");
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
    nch->pc = pc;

    nch->fwd_fd = fd;
    nch->fwd_kind = S3_SRV_FWD_AGENT;
    nch->opened_by_server = 1;

    rev = nsc->read;
    rev->handler = s3_srv_h3_channel_read;
    rev->data = nsc;
    rev->active = 1;

    s3_memzero(&hdr, sizeof(hdr));

    hdr.conversation_stream_id = s3_srv_h3_conv_id;
    hdr.max_packet_size = S3_SRV_CHANNEL_MAX_PACKET;
    hdr.type.data = (u_char *)S3_SSH3_CHANNEL_TYPE_AGENT;
    hdr.type.len = strlen(S3_SSH3_CHANNEL_TYPE_AGENT);

    p = frame;
    p = (u_char *)s3_ssh3_channel_build_header(p, &hdr);
    total = (size_t)(p - frame);

    m = s3_quic_stream_send(nsc, frame, total);

    if (m != (ssize_t)total) {
        fprintf(stderr, "ssh3-server: agent channel header send failed\n");
        s3_srv_h3_channel_free(nch);
        return;
    }

    qs = nsc->data;

    s3_srv_report("INTEROP-AGENT-CONN id=%llu\n", (unsigned long long)qs->id);

    s3_srv_fwd_arm(nch);
}

static void
s3_srv_agent_accept_timer(s3_event_t *ev)
{
    s3_srv_h3_channel_t *ch = ev->data;
    int                  fd;

    ev->timedout = 0;

    for (;;) {

        fd = s3_ssh3_agent_accept(ch->agent_l);

        if (fd < 0) {
            /* S3_AGAIN or a failed accept: the next tick retries */
            break;
        }

        s3_srv_agent_conn_open(ch, fd);
    }

    if (ch->sc != NULL && ch->agent_l != NULL) {
        s3_event_add_timer(ev, 50);
    }
}

/*
 * the reverse port forwarding (-R, the reference
 * cmd/reverse_forward_server.go): the "reverse-forward" control
 * channel carries the bind request, the server binds the port (the
 * GatewayPorts rewrite of --gateway-ports, then the permit-listen
 * gate and the budgets) and mirrors every accepted connection or
 * datagram back as a server-initiated forwarded-tcp/forwarded-udp
 * channel whose header extension carries the client-side target
 */

/* the reverse state died with its conversation: the ticks self-check */

static unsigned
s3_srv_reverse_live(void)
{
    return s3_srv_reverse.listeners > 0 && s3_srv_reverse.pc != NULL &&
           s3_srv_conn_alive(s3_srv_reverse.pc);
}

/*
 * the reverse listener budget (the shape of the sftp budget, the
 * reference maxReverseForwardsPerUser): one slot per live listener of
 * the user, the empty username (a CONNECT without a user) is a key of
 * its own.  The table is scanned linearly, its size is a constant and
 * the daemon serves one conversation at a time; a full table with no
 * entry of the user refuses (fail-closed, unreachable in the
 * single-conversation shape)
 */

static unsigned
s3_srv_reverse_budget_take(const char *user)
{
    size_t len = strlen(user);

    if (s3_srv_reverse_cap == 0) {
        return 1;
    }

    if (len == 0) {

        /* the daemon-identity CONNECTs, the key of their own */

        if (s3_srv_reverse_budget_none >= s3_srv_reverse_cap) {
            return 0;
        }

        s3_srv_reverse_budget_none++;
        return 1;
    }

    if (len > S3_SRV_SFTP_USER_MAX) {
        len = S3_SRV_SFTP_USER_MAX;
    }

    for (unsigned i = 0; i < S3_SRV_REVERSE_BUDGET_USERS; i++) {

        s3_srv_reverse_budget_t *b = &s3_srv_reverse_budgets[i];

        if (b->user[0] != '\0' && strlen(b->user) == len && memcmp(b->user, user, len) == 0) {

            if (b->n >= s3_srv_reverse_cap) {
                return 0;
            }

            b->n++;
            return 1;
        }
    }

    for (unsigned i = 0; i < S3_SRV_REVERSE_BUDGET_USERS; i++) {

        s3_srv_reverse_budget_t *b = &s3_srv_reverse_budgets[i];

        if (b->user[0] == '\0') {
            s3_memcpy(b->user, user, len);
            b->user[len] = '\0';
            b->n = 1;
            return 1;
        }
    }

    return 0;
}

static void
s3_srv_reverse_budget_give(const char *user, unsigned n)
{
    size_t len;

    if (s3_srv_reverse_cap == 0 || n == 0) {
        return;
    }

    len = strlen(user);

    if (len == 0) {

        while (n > 0 && s3_srv_reverse_budget_none > 0) {
            s3_srv_reverse_budget_none--;
            n--;
        }

        return;
    }

    if (len > S3_SRV_SFTP_USER_MAX) {
        len = S3_SRV_SFTP_USER_MAX;
    }

    for (unsigned i = 0; i < S3_SRV_REVERSE_BUDGET_USERS; i++) {

        s3_srv_reverse_budget_t *b = &s3_srv_reverse_budgets[i];

        if (b->user[0] != '\0' && strlen(b->user) == len && memcmp(b->user, user, len) == 0) {

            /* the give clamps at zero: a listener that outlived its
             * slot never invents a new one */

            b->n = (b->n > n) ? b->n - n : 0;

            /* the empty entry frees the table slot */

            if (b->n == 0) {
                b->user[0] = '\0';
            }

            return;
        }
    }
}

/*
 * the shared teardown: the listener sockets close, the timer leaves
 * the rbtree, the udp peer channels free through the channel table
 * (the free clears the peer entries back); safe to run on an empty
 * state, every caller either tears down or arms nothing after
 */

static void
s3_srv_reverse_teardown(void)
{
    unsigned i, j;

    for (i = 0; i < S3_SRV_REVERSE_LISTENERS_MAX; i++) {

        s3_srv_reverse_listener_t *l = &s3_srv_reverse.listener[i];

        if (!l->used) {
            continue;
        }

        if (l->timer.timer_set) {
            s3_event_del_timer(&l->timer);
        }

        if (l->fd >= 0) {
            (void)close(l->fd);
        }

        /* the udp peer channels ride the channel table: the free
         * clears the peer entries (the reverse_fwd walk) */

        for (j = 0; j < S3_SRV_REVERSE_UDP_PEERS_MAX; j++) {

            if (l->peers[j].used && l->peers[j].sc != NULL) {

                s3_srv_h3_channel_t *pch = s3_srv_h3_channel_of(l->peers[j].sc);

                if (pch != NULL) {
                    s3_srv_h3_channel_free(pch);
                }
            }
        }

        s3_memzero(l, sizeof(*l));
    }

    /* the cap slots of the live listeners ride back to the owner's
     * budget (the no-op of the unlimited default) */

    s3_srv_reverse_budget_give(s3_srv_reverse.budget_user, s3_srv_reverse.listeners);
    s3_srv_reverse.budget_user[0] = '\0';

    s3_srv_reverse.listeners = 0;
    s3_srv_reverse.pc = NULL;
    s3_srv_reverse.conv_id = 0;
}

/*
 * the reply of the bind result: one 94 data message on the control
 * channel, the shape of the reference writeReverseForwardReply
 */

static s3_int_t
s3_srv_reverse_reply(s3_srv_h3_channel_t *ch, const s3_ssh3_reverse_reply_t *r)
{
    u_char  replybuf[256];
    u_char  buf[512];
    u_char *rp;
    u_char *p;
    size_t  total;
    ssize_t m;

    rp = s3_ssh3_reverse_build_reply(replybuf, r);

    if (rp == NULL || (size_t)(rp - replybuf) + s3_ssh3_varint_size(S3_SSH3_MSG_CHANNEL_DATA) +
                              s3_ssh3_sshstring_size(rp - replybuf) >
                          sizeof(buf)) {
        return S3_ERROR;
    }

    /* the reply rides the channel data (the reference
     * writeReverseForwardReply): one 94 message, the payload is the
     * SSHString of the reply */

    p = buf;
    p = (u_char *)s3_ssh3_encode_varint(p, S3_SSH3_MSG_CHANNEL_DATA);
    p = (u_char *)s3_ssh3_encode_sshstring(p, replybuf, (size_t)(rp - replybuf));
    total = (size_t)(p - buf);

    m = s3_quic_stream_send(ch->sc, buf, total);

    /* the reply is a few dozen bytes, the window never stalls it
     * (the same small-volume assumption as the channel echo) */

    if (m != (ssize_t)total) {
        return S3_ERROR;
    }

    return S3_OK;
}

/*
 * the GatewayPorts rewrite of the reference resolveReverseForwardBind
 * (--gateway-ports / SSH3_GATEWAY_PORTS, the sshd_config semantics):
 * the "no" policy forces every client-requested bind back to the
 * loopback (the empty bind defaults to it, a loopback literal keeps),
 * the "clientspecified" policy honors the bind as the client spelled
 * it, the "yes" policy binds the wildcard regardless of the request
 * (the daemon never exposes a client -R bind without the operator's
 * say-so)
 */

static void
s3_srv_reverse_bind_rewrite(const s3_str_t *requested, char *out, size_t out_len,
                            unsigned *rewritten)
{
    struct in_addr  a4;
    struct in6_addr a6;

    *rewritten = 0;

    if (s3_srv_gateway_ports == S3_SRV_GATEWAY_PORTS_YES) {

        /* the yes policy returns the wildcard for every request (the
         * reference returns the empty bind, the net.Listen(":port")
         * shape); the v4 wildcard is what the v4-only listener
         * machinery binds */

        snprintf(out, out_len, "0.0.0.0");
        *rewritten = 1;
        return;
    }

    if (requested->len == 0) {
        snprintf(out, out_len, "127.0.0.1");
        *rewritten = 1;
        return;
    }

    if (inet_pton(AF_INET, (const char *)requested->data, &a4) == 1 &&
        (ntohl(a4.s_addr) >> 24) == 127) {
        snprintf(out, out_len, "%s", (const char *)requested->data);
        return;
    }

    if (inet_pton(AF_INET6, (const char *)requested->data, &a6) == 1 && IN6_IS_ADDR_LOOPBACK(&a6)) {
        snprintf(out, out_len, "%s", (const char *)requested->data);
        return;
    }

    if (s3_srv_gateway_ports == S3_SRV_GATEWAY_PORTS_CLIENTSPECIFIED) {

        /* the clientspecified policy honors the bind as the client
         * spelled it (the non-loopback literal, the v4 wildcard or
         * the v6 literal the family gate below answers); the address
         * may be a name the client resolved locally, the rewrite
         * passes it through */

        snprintf(out, out_len, "%s", (const char *)requested->data);
        return;
    }

    /* the no policy rides the non-loopback request back to the
     * loopback; the address may be a name the client sent, the
     * rewrite does not need to resolve it */

    snprintf(out, out_len, "127.0.0.1");
    *rewritten = 1;
}

/*
 * one server-initiated forwarded-* channel: the opener header (the
 * type plus the target extension) rides a fresh client bidi stream,
 * the confirm step of the read path must not run (the 91 of the
 * acceptor answers), the pump reuses the direct-tcp shapes
 */

static s3_srv_h3_channel_t *
s3_srv_reverse_channel_open(s3_srv_reverse_listener_t *l, const char *type)
{
    s3_connection_t     *nsc;
    s3_srv_h3_channel_t *nch;
    s3_quic_stream_t    *qs;
    s3_ssh3_channel_t    hdr;
    u_char               frame[96];
    u_char              *p;
    size_t               total;
    ssize_t              m;
    s3_event_t          *rev;

    if (s3_srv_reverse.forwarded >= S3_SRV_REVERSE_FORWARDED_MAX) {
        return NULL;
    }

    nsc = s3_quic_open_stream(s3_srv_reverse.pc, 1);

    if (nsc == NULL) {
        return NULL;
    }

    nch = s3_srv_h3_channel_alloc(nsc);

    if (nch == NULL) {
        (void)s3_quic_cancelable_stream(nsc);
        (void)s3_quic_shutdown_stream(nsc, S3_RDWR_SHUTDOWN);
        return NULL;
    }

    /*
     * the opener side: no channel header comes back to us, the
     * confirm step of the read path must not run (the 91 of the
     * acceptor rides the message loop instead)
     */

    nch->confirmed = 1;
    nch->pc = s3_srv_reverse.pc;
    nch->opened_by_server = 1;
    nch->reverse_fwd = 1;

    s3_memzero(&hdr, sizeof(hdr));

    hdr.conversation_stream_id = s3_srv_h3_conv_id;
    hdr.max_packet_size = S3_SRV_CHANNEL_MAX_PACKET;
    hdr.type.data = (u_char *)type;
    hdr.type.len = strlen(type);

    p = frame;
    p = (u_char *)s3_ssh3_channel_build_header(p, &hdr);
    p = s3_ssh3_forward_build_target(p, &l->target);
    total = (size_t)(p - frame);

    m = s3_quic_stream_send(nsc, frame, total);

    if (m != (ssize_t)total) {
        s3_srv_h3_channel_free(nch);
        return NULL;
    }

    if (strcmp(type, S3_SSH3_CHANNEL_TYPE_FORWARDED_UDP) == 0) {
        nch->fwd_kind = S3_SRV_FWD_RUDP;
    } else {
        nch->fwd_kind = S3_SRV_FWD_TCP;
    }

    rev = nsc->read;
    rev->handler = s3_srv_h3_channel_read;
    rev->data = nsc;
    rev->active = 1;

    qs = nsc->data;

    s3_srv_report("INTEROP-RFWD-CHANNEL kind=%s id=%llu\n", type, (unsigned long long)qs->id);

    s3_srv_reverse.forwarded++;

    if (nch->fwd_kind == S3_SRV_FWD_TCP) {
        s3_srv_fwd_arm(nch);
    }

    return nch;
}

/*
 * one accepted tcp connection of the reverse listener rides its own
 * forwarded-tcp channel (the bridge into the client-side target)
 */

static void
s3_srv_reverse_conn_open(s3_srv_reverse_listener_t *l, int fd)
{
    s3_srv_h3_channel_t *nch;

    nch = s3_srv_reverse_channel_open(l, S3_SSH3_CHANNEL_TYPE_FORWARDED_TCP);

    if (nch == NULL) {
        s3_ssh3_agent_close_fd(fd);
        return;
    }

    nch->fwd_fd = fd;
}

/* the accept tick of a bound tcp listener */

static void
s3_srv_reverse_tcp_timer(s3_event_t *ev)
{
    s3_srv_reverse_listener_t *l = ev->data;

    ev->timedout = 0;

    if (!s3_srv_reverse_live()) {

        /* the conversation is gone: the state tears down, the timers
         * stop (the live check covers the listener the timer rode) */

        s3_srv_reverse_teardown();
        return;
    }

    if (!l->used) {
        return;
    }

    for (;;) {

        int fd = accept(l->fd, NULL, NULL);

        if (fd < 0) {
            /* S3_AGAIN or a failed accept: the next tick retries */
            break;
        }

        if (s3_nonblocking(fd) != S3_OK) {
            (void)close(fd);
            continue;
        }

        s3_srv_reverse_conn_open(l, fd);
    }

    if (l->used) {
        s3_event_add_timer(ev, 50);
    }
}

/*
 * one datagram of a bound udp listener: the peer without a channel
 * gets one (the per-peer forwarded-udp), the datagram rides it with
 * the ids prefix (docs/P4-WIRE.md 3.2)
 */

static void
s3_srv_reverse_udp_datagram(s3_srv_reverse_listener_t *l, const u_char *buf, size_t len,
                            const struct sockaddr_in *from)
{
    s3_srv_reverse_peer_t *peer = NULL;
    unsigned               i;
    s3_quic_stream_t      *qs;
    u_char                 dg[1400];
    u_char                *p;

    /* the datagram path is lossy by design: a datagram over the QUIC
     * datagram limit of the path drops loudly (the reference shape) */

    if (len + 16 > sizeof(dg)) {
        s3_srv_report("INTEROP-RFWD-UDP-DROP bytes=%zu\n", len);
        return;
    }

    for (i = 0; i < S3_SRV_REVERSE_UDP_PEERS_MAX; i++) {

        s3_srv_reverse_peer_t *cand = &l->peers[i];

        if (!cand->used) {

            if (peer == NULL) {
                peer = cand; /* the free slot, taken below when new */
            }

            continue;
        }

        if (cand->from.sin_addr.s_addr == from->sin_addr.s_addr &&
            cand->from.sin_port == from->sin_port) {
            peer = cand;
            break;
        }
    }

    if (peer == NULL || !peer->used) {

        s3_srv_h3_channel_t *nch;

        if (peer == NULL || s3_srv_reverse.forwarded >= S3_SRV_REVERSE_FORWARDED_MAX) {
            s3_srv_report("INTEROP-RFWD-UDP-DROP bytes=%zu reason=peers\n", len);
            return; /* the peer table or the channel budget is full: the loss */
        }

        nch = s3_srv_reverse_channel_open(l, S3_SSH3_CHANNEL_TYPE_FORWARDED_UDP);

        if (nch == NULL) {
            return;
        }

        peer->used = 1;
        peer->sc = nch->sc;
        peer->from = *from;
        peer->from_len = sizeof(*from);

        nch->reverse_l = (unsigned)(l - s3_srv_reverse.listener);
        nch->reverse_peer = (unsigned)(peer - l->peers);
    }

    qs = peer->sc->data;

    p = s3_ssh3_dgram_encode(dg, s3_srv_h3_conv_id, qs->id, buf, len);

    if (s3_quic_send_datagram(qs->parent, dg, (size_t)(p - dg)) != S3_OK) {
        s3_srv_report("INTEROP-RFWD-UDP-DROP bytes=%zu reason=transport\n", len);
    }
}

/* the recvfrom tick of a bound udp listener */

static void
s3_srv_reverse_udp_timer(s3_event_t *ev)
{
    s3_srv_reverse_listener_t *l = ev->data;
    static u_char              buf[S3_UDP_DGRAM_SIZE];
    struct sockaddr_in         from;
    socklen_t                  from_len;
    ssize_t                    n;

    ev->timedout = 0;

    if (!s3_srv_reverse_live()) {

        s3_srv_reverse_teardown();
        return;
    }

    if (!l->used) {
        return;
    }

    for (;;) {

        from_len = sizeof(from);

        n = recvfrom(l->fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &from_len);

        if (n <= 0) {
            break; /* EAGAIN or the gone listener */
        }

        s3_srv_reverse_udp_datagram(l, buf, (size_t)n, &from);
    }

    if (l->used) {
        s3_event_add_timer(ev, 50);
    }
}

/*
 * the router side of the udp listeners: the datagrams prefixed with a
 * reverse channel id ride back to their peer, everything else falls
 * through to the direct-udp routing and the echo (the return value
 * says the datagram was consumed)
 */

static unsigned
s3_srv_reverse_datagram_route(s3_connection_t *c, const u_char *buf, size_t len)
{
    const u_char *pos = buf, *end = buf + len;
    uint64_t      csid, chid;
    s3_str_t      payload;
    unsigned      i, j;

    if (s3_srv_reverse.listeners == 0 ||
        s3_ssh3_dgram_parse(&pos, end, &csid, &chid, &payload) != S3_OK) {
        return 0;
    }

    if (csid != s3_srv_h3_conv_id) {

        return 0;
    }

    for (i = 0; i < S3_SRV_REVERSE_LISTENERS_MAX; i++) {

        s3_srv_reverse_listener_t *l = &s3_srv_reverse.listener[i];

        if (!l->used || l->proto != S3_SSH3_REVERSE_PROTO_UDP) {
            continue;
        }

        for (j = 0; j < S3_SRV_REVERSE_UDP_PEERS_MAX; j++) {

            s3_srv_reverse_peer_t *peer = &l->peers[j];
            s3_quic_stream_t      *qs;

            if (!peer->used || peer->sc == NULL) {
                continue;
            }

            qs = peer->sc->data;

            if (qs == NULL || qs->id != chid) {

                continue;
            }

            if (payload.len > 0) {
                (void)sendto(l->fd, payload.data, payload.len, 0,
                             (const struct sockaddr *)&peer->from, peer->from_len);
            }

            (void)c;

            return 1;
        }
    }

    return 0;
}

/*
 * the bind request on the control channel (the reference
 * handleReverseForwardChannel): the gate order is the target literal,
 * the GatewayPorts rewrite, the permit-listen policy, the listener
 * budget of the conversation and the user reverse cap, all before the
 * bind; every refusal answers with the reason and closes the control
 * channel (the reference shape)
 */

static void
s3_srv_reverse_request(s3_srv_h3_channel_t *ch, const s3_str_t *payload)
{
    const u_char              *pos = payload->data, *end = payload->data + payload->len;
    s3_ssh3_reverse_request_t  req;
    s3_ssh3_forward_target_t   target;
    char                       target_text[64];
    char                       bind_host[256] = {0};
    char                       reason[320];
    const char                *kind;
    s3_ssh3_reverse_reply_t    reply;
    s3_srv_reverse_listener_t *l = NULL;
    struct sockaddr_in         sa;
    int                        fd = -1;
    unsigned                   rewritten;
    unsigned                   booked = 0;
    unsigned                   i;

    /* the string views ride the channel accumulator: the next recv
     * may move it, everything needed copies before the handler runs */

    if (s3_ssh3_reverse_parse_request(&pos, end, &req) != S3_OK) {
        s3_srv_h3_channel_cancel(ch, "bad reverse forward request");
        return;
    }

    kind = (req.proto == S3_SSH3_REVERSE_PROTO_UDP) ? "udp" : "tcp";

    /* the target is the ip literal only (the reference net.ParseIP
     * gate, the client resolved the name locally) */

    {
        char taddr[S3_SSH3_REVERSE_HOST_MAX + 1];

        if (req.target_address.len == 0 || req.target_address.len > S3_SSH3_REVERSE_HOST_MAX) {
            s3_srv_h3_channel_cancel(ch, "bad reverse forward target");
            return;
        }

        s3_memcpy(taddr, req.target_address.data, req.target_address.len);
        taddr[req.target_address.len] = '\0';

        s3_memzero(&target, sizeof(target));

        if (inet_pton(AF_INET, taddr, &target.ip) == 1) {
            target.family = 4;
            target.ip_len = 4;

        } else if (inet_pton(AF_INET6, taddr, &target.ip) == 1) {
            target.family = 6;
            target.ip_len = 16;

        } else {
            snprintf(reason, sizeof(reason), "invalid target address %s", taddr);
            goto refuse;
        }

        target.port = req.target_port;

        if (s3_ssh3_reverse_target_ntop(&target, target_text, sizeof(target_text)) != S3_OK) {
            snprintf(reason, sizeof(reason), "invalid target address %s", taddr);
            goto refuse;
        }
    }

    /* the GatewayPorts=no rewrite: the bind text copies first, the
     * views die with the handler */

    {
        char     bind_text[S3_SSH3_REVERSE_HOST_MAX + 1];
        s3_str_t bind_str;

        if (req.bind_address.len > S3_SSH3_REVERSE_HOST_MAX) {
            s3_srv_h3_channel_cancel(ch, "bad reverse forward bind");
            return;
        }

        s3_memcpy(bind_text, req.bind_address.data, req.bind_address.len);
        bind_text[req.bind_address.len] = '\0';

        bind_str.data = (u_char *)bind_text;
        bind_str.len = req.bind_address.len;

        s3_srv_reverse_bind_rewrite(&bind_str, bind_host, sizeof(bind_host), &rewritten);

        if (rewritten && bind_text[0] != '\0') {
            s3_log_error(S3_LOG_INFO, &s3_srv_log, 0,
                         "reverse forward: the GatewayPorts=%s policy restricted the bind %s to %s",
                         s3_srv_gateway_ports_name(), bind_text, bind_host);
        }
    }

    /* the permit-listen gate (S2-04): the post-rewrite bind, before
     * the budget and before any socket() */

    if (s3_ssh3_forward_policy_check(&s3_srv_listen_policy, bind_host, req.bind_port) != S3_OK) {
        snprintf(reason, sizeof(reason), "%s listen on %s:%u denied by -permit-listen policy", kind,
                 bind_host, (unsigned)req.bind_port);
        goto refuse;
    }

    /* the listener budget of the conversation (S2-04) */

    if (s3_srv_reverse.listeners >= S3_SRV_REVERSE_LISTENERS_MAX) {
        snprintf(reason, sizeof(reason), "too many reverse forwards (limit %d)",
                 S3_SRV_REVERSE_LISTENERS_MAX);
        goto refuse;
    }

    /* the operator cap on the live reverse listeners of the user
     * (the reference maxReverseForwardsPerUser): the refusal rides
     * before any socket(), the slot books here and gives back on the
     * refuse paths below.  The user text stages into a fixed buffer:
     * the empty name (a CONNECT under the daemon identity) prints as
     * the "-" placeholder */

    {
        char ruser[S3_SRV_SFTP_USER_MAX + 2];

        if (ch->sess_user[0] != '\0') {
            snprintf(ruser, sizeof(ruser), "%s", ch->sess_user);

        } else {
            snprintf(ruser, sizeof(ruser), "-");
        }

        if (!s3_srv_reverse_budget_take(ch->sess_user)) {
            s3_srv_report("REVERSE-CAP-DENIED kind=%s user=%s bind=%s:%u limit=%u\n", kind, ruser,
                          bind_host, (unsigned)req.bind_port, (unsigned)s3_srv_reverse_cap);

            snprintf(reason, sizeof(reason), "too many reverse forwards for user %s (limit %d)",
                     ruser, s3_srv_reverse_cap);

            goto refuse;
        }

        booked = 1;

        /* the cap owner of the live listeners (the teardown rides it
         * back into the budget) */

        s3_memcpy(s3_srv_reverse.budget_user, ch->sess_user, sizeof(s3_srv_reverse.budget_user));
        s3_srv_reverse.budget_user[sizeof(s3_srv_reverse.budget_user) - 1] = '\0';
    }

    /* the bind text is a literal (the rewrite produced one), the
     * family follows it */

    s3_memzero(&sa, sizeof(sa));

    if (strcmp(bind_host, "::") == 0 || strchr(bind_host, ':') != NULL) {

        /* the ipv6 bind under the no policy is the rewritten loopback
         * only: the rewrite turns every non-loopback request into
         * 127.0.0.1 and the yes policy into 0.0.0.0, so a ":" here
         * means the clientspecified policy passed an ipv6 literal
         * through - the reverse listener machinery is v4-only, the
         * bind refuses fail-closed */

        snprintf(reason, sizeof(reason), "unsupported ipv6 bind %s", bind_host);
        goto refuse;
    }

    if (inet_pton(AF_INET, bind_host, &sa.sin_addr) != 1) {
        snprintf(reason, sizeof(reason), "invalid bind address %s", bind_host);
        goto refuse;
    }

    /* the conversation bookkeeping: a new conversation tears the old
     * listeners down (the single-conversation shape of the daemon).
     * The identity is the quic connection itself - the CONNECT stream
     * id restarts with every connection, an id-only comparison never
     * told the conversations apart and left the stale listeners of a
     * dead conversation riding under the fresh one (their live check
     * then tore the fresh listeners down with them).  The re-anchor
     * also covers the refused binds of a new conversation: they leave
     * listeners == 0 with the pc of the dead conversation riding */

    if (s3_srv_reverse.listeners > 0 && s3_srv_reverse.pc != ch->pc) {
        s3_srv_reverse_teardown();
    }

    if (s3_srv_reverse.pc != ch->pc) {
        s3_srv_reverse.conv_id = s3_srv_h3_conv_id;
        s3_srv_reverse.pc = ch->pc;
    }

    for (i = 0; i < S3_SRV_REVERSE_LISTENERS_MAX; i++) {

        if (!s3_srv_reverse.listener[i].used) {
            l = &s3_srv_reverse.listener[i];
            break;
        }
    }

    if (l == NULL) {
        snprintf(reason, sizeof(reason), "too many reverse forwards (limit %d)",
                 S3_SRV_REVERSE_LISTENERS_MAX);
        goto refuse;
    }

    sa.sin_family = AF_INET;
    sa.sin_port = htons(req.bind_port);

    fd = socket(AF_INET, (req.proto == S3_SSH3_REVERSE_PROTO_UDP) ? SOCK_DGRAM : SOCK_STREAM, 0);

    if (fd == -1) {
        snprintf(reason, sizeof(reason), "socket() failed");
        goto refuse;
    }

    {
        int on = 1;

        (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    }

    if (bind(fd, (const struct sockaddr *)&sa, sizeof(sa)) == -1 ||
        (req.proto == S3_SSH3_REVERSE_PROTO_TCP && listen(fd, SOMAXCONN) == -1) ||
        s3_nonblocking(fd) != S3_OK) {

        snprintf(reason, sizeof(reason), "bind %s:%u failed: %s", bind_host,
                 (unsigned)req.bind_port, strerror(errno));

        (void)close(fd);

        goto refuse;
    }

    {
        struct sockaddr_in got;
        socklen_t          got_len = sizeof(got);

        if (getsockname(fd, (struct sockaddr *)&got, &got_len) == -1) {
            snprintf(reason, sizeof(reason), "getsockname failed: %s", strerror(errno));
            (void)close(fd);
            goto refuse;
        }

        l->bound_port = ntohs(got.sin_port);
    }

    l->used = 1;
    l->proto = req.proto;
    l->fd = fd;
    l->bind_sa = sa;
    l->target = target;
    l->used_peers = 0;

    s3_memzero(l->peers, sizeof(l->peers));

    s3_srv_reverse.listeners++;

    s3_memzero(&reply, sizeof(reply));

    reply.bound_port = l->bound_port;
    reply.error_utf8.data = (u_char *)"";
    reply.error_utf8.len = 0;

    if (s3_srv_reverse_reply(ch, &reply) != S3_OK) {
        fprintf(stderr, "ssh3-server: reverse forward reply send failed\n");
        s3_srv_h3_channel_free(ch);
        return;
    }

    ch->reverse_served = 1;

    {
        char bip[INET_ADDRSTRLEN];

        (void)inet_ntop(AF_INET, &sa.sin_addr, bip, sizeof(bip));

        s3_srv_report("INTEROP-RFWD-OPEN kind=%s bind=%s:%u port=%u target=%s:%u\n", kind, bip,
                      (unsigned)req.bind_port, (unsigned)l->bound_port, target_text,
                      (unsigned)target.port);
    }

    /* the serve tick: the tcp accept loop or the udp recvfrom loop */

    l->timer.data = l;
    l->timer.log = &s3_srv_log;
    l->timer.handler = (req.proto == S3_SSH3_REVERSE_PROTO_TCP) ? s3_srv_reverse_tcp_timer
                                                                : s3_srv_reverse_udp_timer;

    s3_event_add_timer(&l->timer, 50);

    return;

refuse:

    /* the booked cap slot rides back when a refusal below the gate
     * killed the bind (the socket/getsockname failures) */

    if (booked) {
        s3_srv_reverse_budget_give(ch->sess_user, 1);
    }

    s3_memzero(&reply, sizeof(reply));

    reply.bound_port = 0;
    reply.error_utf8.data = (u_char *)reason;
    reply.error_utf8.len = strlen(reason);

    (void)s3_srv_reverse_reply(ch, &reply);

    s3_log_error(S3_LOG_WARN, &s3_srv_log, 0, "refusing reverse-forward bind: %s", reason);

    s3_srv_report("INTEROP-RFWD-DENIED kind=%s bind=%s:%u\n", kind, bind_host,
                  (unsigned)req.bind_port);

    /* the reference closes the control channel after the refusal */

    (void)s3_quic_shutdown_stream(ch->sc, S3_RDWR_SHUTDOWN);

    s3_srv_h3_channel_free(ch);
}

/* the runner marker on the open target */

static void
s3_srv_fwd_report(const s3_ssh3_forward_target_t *t, const char *kind)
{
    char        ip[64];
    const char *text;

    text = inet_ntop(t->family == 6 ? AF_INET6 : AF_INET, t->ip, ip, sizeof(ip));

    if (text == NULL) {
        text = "?";
    }

    s3_srv_report("INTEROP-FWD-%s-OPEN target=%s:%u\n", kind, text, (unsigned)t->port);
}

/*
 * the permit-open gate of the direct dials (F-05): the target rides
 * the wire as the raw ip, the canonical inet_ntop text is what the
 * patterns compare against (the dial as the client spelled it); the
 * refusal answers before any socket() and the channel dies through
 * the same cancel path as the unreachable target
 */
static s3_int_t
s3_srv_fwd_policy_gate(const s3_ssh3_forward_target_t *t, const char *kind)
{
    char        ip[64];
    const char *text;

    text = inet_ntop(t->family == 6 ? AF_INET6 : AF_INET, t->ip, ip, sizeof(ip));

    if (text == NULL) {
        text = "?";
    }

    if (s3_ssh3_forward_policy_check(&s3_srv_fwd_policy, text, t->port) == S3_OK) {
        return S3_OK;
    }

    s3_srv_report("INTEROP-FWD-%s-DENIED target=%s:%u\n", kind, text, (unsigned)t->port);

    return S3_ERROR;
}

/*
 * the target connect of the direct-tcp channel: the harness runs
 * against the loopback echo services, the plain blocking connect
 * (a refusal on loopback is immediate) is enough and keeps the pump
 * simple, a general server wants a non-blocking connect
 */
static s3_int_t
s3_srv_fwd_tcp_open(s3_srv_h3_channel_t *ch, const s3_ssh3_forward_target_t *t)
{
    struct sockaddr_in sa;
    int                fd;

    if (s3_srv_fwd_policy_gate(t, "TCP") != S3_OK) {
        return S3_ERROR;
    }

    if (t->family != 4) {
        fprintf(stderr, "ssh3-server: direct-tcp: only the ipv4 targets are supported\n");
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
    ch->fwd_kind = S3_SRV_FWD_TCP;
    ch->fwd_sa = sa;

    s3_srv_fwd_report(t, "TCP");

    return S3_OK;
}

/*
 * the target socket of the direct-udp channel; one channel at a time
 * (the harness simplification, the datagram routing holds a single
 * target)
 */
static s3_int_t
s3_srv_fwd_udp_open(s3_srv_h3_channel_t *ch, const s3_ssh3_forward_target_t *t)
{
    struct sockaddr_in sa;
    int                fd;

    if (s3_srv_fwd_policy_gate(t, "UDP") != S3_OK) {
        return S3_ERROR;
    }

    if (t->family != 4) {
        fprintf(stderr, "ssh3-server: direct-udp: only the ipv4 targets are supported\n");
        return S3_ERROR;
    }

    if (s3_srv_h3_udp_fwd != NULL) {
        fprintf(stderr, "ssh3-server: a direct-udp channel is already forwarded\n");
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
    ch->fwd_kind = S3_SRV_FWD_UDP;
    ch->fwd_sa = sa;

    s3_srv_h3_udp_fwd = ch;

    s3_srv_fwd_report(t, "UDP");

    return S3_OK;
}

/*
 * the datagram of the direct-udp channel (docs/P4-WIRE.md 3.2): the
 * prefix carries the control stream and the channel ids, a datagram
 * that does not belong to the forwarded channel (the plain echo runs)
 * echoes back unchanged
 */
static void
s3_srv_udp_fwd_datagram(s3_connection_t *c, const u_char *buf, size_t len)
{
    const u_char     *pos = buf, *end = buf + len;
    uint64_t          csid, chid;
    s3_str_t          payload;
    s3_quic_stream_t *qs;

    if (s3_ssh3_dgram_parse(&pos, end, &csid, &chid, &payload) != S3_OK) {
        (void)s3_quic_send_datagram(c, buf, len);
        return;
    }

    qs = s3_srv_h3_udp_fwd->sc->data;

    if (csid != s3_srv_h3_conv_id || chid != qs->id) {
        (void)s3_quic_send_datagram(c, buf, len);
        return;
    }

    if (payload.len > 0) {
        (void)sendto(s3_srv_h3_udp_fwd->fwd_fd, payload.data, payload.len, 0,
                     (const struct sockaddr *)&s3_srv_h3_udp_fwd->fwd_sa,
                     sizeof(s3_srv_h3_udp_fwd->fwd_sa));
    }
}

static s3_int_t
s3_srv_h3_channel_confirm(s3_srv_h3_channel_t *ch)
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
    unsigned                        is_session;

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
        s3_srv_h3_channel_cancel(ch, "bad channel header");
        return S3_ERROR;
    }

    /* the receiver must verify the conversation of the channel */

    if (hdr.conversation_stream_id != s3_srv_h3_conv_id) {
        s3_srv_h3_channel_cancel(ch, "conversation mismatch");
        return S3_ERROR;
    }

    /*
     * the role table (S2-03): the forwarded-* types are the
     * server-to-client half of the reverse forward, a client opening
     * them towards the server is refused before the confirmation -
     * the reference cancels the stream the same way
     */
    if (s3_srv_h3_type_is(&hdr.type, S3_SSH3_CHANNEL_TYPE_FORWARDED_TCP) ||
        s3_srv_h3_type_is(&hdr.type, S3_SSH3_CHANNEL_TYPE_FORWARDED_UDP)) {

        s3_srv_report("CHROLE-FORWARDED-DENIED id=%llu type=%.*s\n", (unsigned long long)qs->id,
                      (int)hdr.type.len, (const char *)hdr.type.data);

        s3_srv_h3_channel_cancel(ch, "server-to-client channel type refused");
        return S3_ERROR;
    }

    /*
     * the allow-list (P3-03): the client-role surface is exactly the
     * session, the two direct forwards, the sftp channel and the
     * reverse-forward control channel; any other string would take a
     * tracked slot and a 91 for a channel the server never meant to
     * serve (the pass-3 audit), the refusal sits before the
     * confirmation like the role table above
     */
    is_session = s3_srv_h3_type_is(&hdr.type, S3_SSH3_CHANNEL_TYPE_SESSION);

    if (!is_session && !s3_srv_h3_type_is(&hdr.type, S3_SSH3_CHANNEL_TYPE_SFTP) &&
        !s3_srv_h3_type_is(&hdr.type, S3_SSH3_CHANNEL_TYPE_DIRECT_TCP) &&
        !s3_srv_h3_type_is(&hdr.type, S3_SSH3_CHANNEL_TYPE_DIRECT_UDP) &&
        !s3_srv_h3_type_is(&hdr.type, S3_SSH3_CHANNEL_TYPE_REVERSE_FORWARD)) {

        s3_srv_report("CHROLE-UNKNOWN-DENIED id=%llu type=%.*s\n", (unsigned long long)qs->id,
                      (int)hdr.type.len, (const char *)hdr.type.data);

        s3_srv_h3_channel_cancel(ch, "unknown channel type refused");
        return S3_ERROR;
    }

    /*
     * the direct-* channels carry the target extension right after
     * the header (docs/P4-WIRE.md 2.1), the other types end there
     */
    if (s3_srv_h3_type_is(&hdr.type, S3_SSH3_CHANNEL_TYPE_DIRECT_TCP) ||
        s3_srv_h3_type_is(&hdr.type, S3_SSH3_CHANNEL_TYPE_DIRECT_UDP)) {

        fwd = 1;

        if (s3_ssh3_forward_parse_target(&pos, end, &target) != S3_OK) {
            s3_srv_h3_channel_cancel(ch, "bad channel target");
            return S3_ERROR;
        }

    } else {
        fwd = 0;
    }

    /* the 91 with our own maxPacketSize, like confirmChannel() does */

    s3_memzero(&conf, sizeof(conf));
    conf.max_packet_size = S3_SRV_CHANNEL_MAX_PACKET;

    p = out;
    p = (u_char *)s3_ssh3_encode_varint(p, S3_SSH3_MSG_CHANNEL_OPEN_CONFIRMATION);
    p = (u_char *)s3_ssh3_msg_encode_open_confirmation(p, &conf);
    total = (size_t)(p - out);

    m = s3_quic_stream_send(sc, out, total);

    /* the same small-volume assumption as the echo above */
    if (m != (ssize_t)total) {
        s3_srv_h3_channel_cancel(ch, "confirmation send stalled");
        return S3_ERROR;
    }

    ch->confirmed = 1;

    /* the role snapshot for the request gate below (S2-03) */

    ch->is_session = is_session;

    if (fwd) {

        s3_int_t rc;

        /*
         * the 91 is out: the target opens here, a refusal cancels the
         * channel (the opener sees the reset and fails)
         */

        rc = s3_srv_h3_type_is(&hdr.type, S3_SSH3_CHANNEL_TYPE_DIRECT_TCP)
                 ? s3_srv_fwd_tcp_open(ch, &target)
                 : s3_srv_fwd_udp_open(ch, &target);

        if (rc != S3_OK) {
            s3_srv_h3_channel_cancel(ch, "the target is unreachable");
            return S3_ERROR;
        }

        s3_srv_fwd_arm(ch);

    } else if (s3_srv_h3_type_is(&hdr.type, S3_SSH3_CHANNEL_TYPE_SFTP)) {

        /*
         * the sftp subsystem: the request server jails into the home,
         * the replies ride the 94 direction through the pump timer
         */

        if (s3_srv_sftp_start(ch) != S3_OK) {
            s3_srv_h3_channel_cancel(ch, "sftp subsystem failed");
            return S3_ERROR;
        }

    } else if (s3_srv_h3_type_is(&hdr.type, S3_SSH3_CHANNEL_TYPE_REVERSE_FORWARD)) {

        /* the reverse forward control channel (the -R): the bind
         * request arrives as the first data message, the serve loop
         * reads it there */

        ch->fwd_kind = S3_SRV_FWD_RCTRL;
    }

    s3_srv_report("INTEROP-CHANNEL-ACCEPT id=%llu type=%.*s\n", (unsigned long long)qs->id,
                  (int)hdr.type.len, (const char *)hdr.type.data);

    /* the header bytes are consumed, the type view dies here */
    ch->len = (size_t)(end - pos);
    s3_memmove(ch->buf, pos, ch->len);

    return S3_OK;
}

static void
s3_srv_h3_channel_read(s3_event_t *ev)
{
    s3_connection_t     *sc;
    s3_srv_h3_channel_t *ch;
    const u_char        *pos, *end;
    ssize_t              n;

    sc = ev->data;

    ch = s3_srv_h3_channel_of(sc);

    if (ch == NULL) {
        /* the slot was freed by a cancel, the tail events are noise */
        return;
    }

    for (;;) {

        if (ch->len == ch->cap) {
            size_t  cap;
            u_char *grown;

            /* the S2-01 bound: a full buffer with no complete message
             * inside is a peer trickling bytes past the advertised
             * maxPacketSize, the channel dies instead of growing */

            if (ch->cap >= S3_SRV_CHANNEL_BUF_MAX) {
                s3_srv_h3_channel_cancel(ch, "channel buffer overgrown");
                return;
            }

            cap = ch->cap + 262144;

            if (cap > S3_SRV_CHANNEL_BUF_MAX) {
                cap = S3_SRV_CHANNEL_BUF_MAX;
            }

            grown = realloc(ch->buf, cap);

            if (grown == NULL) {
                fprintf(stderr, "ssh3-server: channel buffer growth failed\n");
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

            if (ch->fwd_kind == S3_SRV_FWD_RCTRL) {

                /* the control channel of the reverse forward: the
                 * client closes it after the reply (the reference
                 * shape), the bind lives with the conversation */

                s3_srv_h3_channel_free(ch);
                return;
            }

            if (ch->fwd_kind == S3_SRV_FWD_RUDP) {

                /* the udp channels carry no eof, the channel ends */

                s3_srv_h3_channel_free(ch);
                return;
            }

            if (ch->fwd_kind == S3_SRV_FWD_AGENT) {

                /* the client side of the agent bridge is gone */

                s3_srv_h3_channel_free(ch);
                return;
            }

            if (ch->fwd_kind == S3_SRV_FWD_SFTP) {

                /* the transfer peer closed: the subsystem goes with
                 * it (the free kills and reaps the child) */

                s3_srv_report("SFTP-SRV-DONE\n");

                s3_srv_h3_channel_free(ch);
                return;
            }

            if (ch->fwd_kind != S3_SRV_FWD_NONE) {

                /*
                 * the fin of the opener: the tcp relay shuts the write
                 * side of the target socket (the echo service answers
                 * with its own eof and the pump ends the channel), the
                 * udp channel has no eof and just ends
                 */
                if (ch->fwd_kind == S3_SRV_FWD_TCP) {
                    (void)shutdown(ch->fwd_fd, SHUT_WR);
                    s3_srv_fwd_pump(ch);
                    return;
                }

                s3_srv_h3_channel_free(ch);
                return;
            }

            if (ch->sftp != NULL) {

                /* the transfer peer closed: the subsystem goes with it */

                s3_srv_report("SFTP-SRV-DONE\n");

                s3_srv_h3_channel_free(ch);
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
                    fprintf(stderr, "ssh3-server: session close_input declined\n");
                }

                s3_srv_session_pump(ch);

                return;
            }

            if (ch->sess != NULL) {

                /*
                 * the verdict is out and the peer closed its side: the
                 * recv drained to eof (that is why the read returned
                 * 0), the drop retires the quic stream - the MAX_STREAMS
                 * back to the peer lift its open credit
                 */
                s3_close_connection(ch->sc);
                ch->sc = NULL;

                s3_srv_h3_channel_free(ch);
                return;
            }

            /* the echo mode: the peer fin shuts the stream down */
            (void)s3_quic_shutdown_stream(sc, S3_WRITE_SHUTDOWN);
            s3_srv_h3_channel_free(ch);
            return;
        }

        if (n < 0) {
            s3_srv_h3_channel_cancel(ch, "recv error");
            return;
        }

        ch->len += (size_t)n;

        if (!ch->confirmed && s3_srv_h3_channel_confirm(ch) != S3_OK) {
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

                if (ch->fwd_kind == S3_SRV_FWD_RCTRL) {

                    /*
                     * the reverse forward control channel: the first
                     * data message is the bind request, the further
                     * ones are a protocol violation (the served
                     * channel stays open until the peer closes)
                     */

                    if (ch->reverse_served) {
                        s3_srv_h3_channel_cancel(ch, "data on a served reverse-forward channel");
                        return;
                    }

                    s3_srv_reverse_request(ch, &msg_data.data);

                    /* the refusal freed the channel, the bind stays */

                    if (ch->sc == NULL) {
                        return;
                    }

                    continue;
                }

                if (ch->fwd_kind == S3_SRV_FWD_TCP || ch->fwd_kind == S3_SRV_FWD_AGENT) {

                    /* the relay: the payload rides the target socket
                     * (the tcp target or the accepted agent socket) */

                    if (s3_srv_fwd_append(&ch->fwd_in, &ch->fwd_in_cap, &ch->fwd_in_len,
                                          msg_data.data.data, msg_data.data.len) != S3_OK) {
                        fprintf(stderr, "ssh3-server: forward buffer growth failed\n");
                        s3_srv_h3_channel_free(ch);
                        return;
                    }

                    s3_srv_fwd_socket_flush(ch);

                    continue;
                }

                if (ch->fwd_kind == S3_SRV_FWD_UDP || ch->fwd_kind == S3_SRV_FWD_RUDP) {

                    /* the udp channels carry the datagram path only */
                    s3_srv_h3_channel_cancel(ch, "data on a udp channel");
                    return;
                }

                if (ch->fwd_kind == S3_SRV_FWD_SFTP) {

                    /* the relay: the payload rides the chroot child
                     * stdin, the pump drains both directions */

                    if (s3_srv_fwd_append(&ch->fwd_in, &ch->fwd_in_cap, &ch->fwd_in_len,
                                          msg_data.data.data, msg_data.data.len) != S3_OK) {
                        fprintf(stderr, "ssh3-server: sftp buffer growth failed\n");
                        s3_srv_h3_channel_free(ch);
                        return;
                    }

                    s3_srv_sftp_child_pump(ch);

                    if (ch->sc == NULL) {
                        /* the pump freed the channel (a dead child) */
                        return;
                    }

                    continue;
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
                        fprintf(stderr, "ssh3-server: sftp input failed\n");
                    }

                    s3_srv_sftp_pump(ch);

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

                        if (s3_srv_agent_listen(ch) != S3_OK) {
                            fprintf(stderr, "ssh3-server: agent listen failed\n");
                        }

                        continue;
                    }
                }

                else if (ch->sess != NULL && ch->sess->open) {

                    if (s3_ssh3_session_srv_input(ch->sess, msg_data.data.data,
                                                  msg_data.data.len) != S3_OK) {
                        fprintf(stderr, "ssh3-server: session input failed\n");
                    }

                    continue;
                }

                else {
                    fprintf(stderr, "ssh3-server: session data before the spawn dropped\n");
                    continue;
                }

                /* the echo mode: the data goes back unchanged */

                if (s3_srv_h3_channel_echo(sc, msg_data.data.data, msg_data.data.len) != S3_OK) {
                    s3_srv_h3_channel_cancel(ch, "echo send stalled");
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

                if (ch->fwd_kind != S3_SRV_FWD_NONE || !ch->is_session) {

                    /*
                     * the role table (S2-03): the requests belong to
                     * the session channels only, the forward kinds and
                     * the unnamed types carry none
                     */
                    s3_srv_h3_channel_cancel(ch, "request on a non-session channel");
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
                    fprintf(stderr, "ssh3-server: unknown request type %.*s\n",
                            (int)env.request_type.len, (const char *)env.request_type.data);
                    pos = end;
                    continue;
                }

                bend = s3_srv_request_body_end(kind, pos, end);

                if (bend == NULL) {
                    /* a partial body, the next recv completes it */
                    pos = msg;
                    break;
                }

                bpos = pos;

                if (s3_ssh3_request_parse_body(&bpos, bend, &env.request_type, &req) != S3_OK) {
                    /* the walked span must parse, else the stream desynced */
                    s3_srv_h3_channel_cancel(ch, "bad request body");
                    return;
                }

                pos = bend;

                switch (kind) {

                case S3_SSH3_REQ_PTY:

                    if (s3_srv_session_start(ch) != S3_OK ||
                        s3_ssh3_session_srv_pty_req(ch->sess, &req.u.pty.term, req.u.pty.width,
                                                    req.u.pty.height, req.u.pty.pixel_width,
                                                    req.u.pty.pixel_height,
                                                    &req.u.pty.modes) != S3_OK) {
                        fprintf(stderr, "ssh3-server: pty-req failed\n");
                        break;
                    }

                    ch->sess_intent = 1;

                    s3_srv_report("INTEROP-SESSION-PTY\n");

                    break;

                case S3_SSH3_REQ_EXEC:

                    if (s3_srv_session_start(ch) != S3_OK ||
                        s3_ssh3_session_srv_exec(ch->sess, s3_srv_session_shell_of(ch),
                                                 &req.u.exec.command) != S3_OK) {
                        fprintf(stderr, "ssh3-server: exec failed\n");
                        break;
                    }

                    ch->sess_intent = 1;

                    s3_srv_report("INTEROP-SESSION-EXEC\n");

                    s3_srv_session_arm(ch);
                    s3_srv_session_pump(ch);

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
                        fprintf(stderr, "ssh3-server: shell without the session intent\n");
                        break;
                    }

                    if (s3_srv_session_start(ch) != S3_OK ||
                        s3_ssh3_session_srv_shell(ch->sess, s3_srv_session_shell_of(ch)) != S3_OK) {
                        fprintf(stderr, "ssh3-server: shell failed\n");
                        break;
                    }

                    s3_srv_report("INTEROP-SESSION-SHELL\n");

                    s3_srv_session_arm(ch);
                    s3_srv_session_pump(ch);

                    break;

                case S3_SSH3_REQ_WINDOW_CHANGE:

                    if (ch->sess == NULL ||
                        s3_ssh3_session_srv_window_change(
                            ch->sess, req.u.window_change.width, req.u.window_change.height,
                            req.u.window_change.pixel_width,
                            req.u.window_change.pixel_height) != S3_OK) {
                        fprintf(stderr, "ssh3-server: window-change declined\n");
                    }

                    break;

                case S3_SSH3_REQ_SIGNAL:

                    if (ch->sess == NULL ||
                        s3_ssh3_session_srv_signal(ch->sess, &req.u.signal.name) != S3_OK) {
                        fprintf(stderr, "ssh3-server: signal declined\n");
                    }

                    break;

                default:
                    /* subsystem/x11/exit-*: the server never runs them */
                    fprintf(stderr, "ssh3-server: request %.*s ignored\n",
                            (int)env.request_type.len, (const char *)env.request_type.data);
                    break;
                }

                continue;
            }

            if (type == S3_SSH3_MSG_CHANNEL_OPEN_CONFIRMATION && ch->opened_by_server) {

                /*
                 * the 91 of the acceptor side on the server-initiated
                 * channels (the agent bridge, the reverse forward
                 * bridges): consume and move on
                 */

                s3_ssh3_msg_open_confirmation_t conf;

                if (s3_ssh3_msg_parse_open_confirmation(&pos, end, &conf) != S3_OK) {
                    pos = msg;
                    break;
                }

                continue;
            }

            s3_srv_h3_channel_cancel(ch, "unknown channel message");
            return;
        }

        /* the consumed bytes compact to the front of the buffer */
        ch->len = (size_t)(end - pos);
        s3_memmove(ch->buf, pos, ch->len);

        /*
         * the session output rides along: the input just fed may have
         * woken the process, the pump answers with the fresh bytes
         * (the fd watches armed at the spawn answer the rest)
         */
        s3_srv_session_pump(ch);
    }
}

static void
s3_srv_h3_channel_accept(s3_connection_t *sc)
{
    s3_srv_h3_channel_t *ch;
    s3_event_t          *rev;
    unsigned             i;

    ch = NULL;

    for (i = 0; i < S3_SRV_TRACKED; i++) {

        if (s3_srv_h3_channels[i].sc == NULL) {
            ch = &s3_srv_h3_channels[i];
            break;
        }
    }

    if (ch == NULL) {
        fprintf(stderr, "ssh3-server: channel table is full\n");
        (void)s3_quic_cancelable_stream(sc);
        (void)s3_quic_shutdown_stream(sc, S3_RDWR_SHUTDOWN);
        return;
    }

    s3_memzero(ch, sizeof(*ch));
    ch->sc = sc;
    ch->pc = ((s3_quic_stream_t *)sc->data)->parent;

    /* the fd fields start closed: the memzero zeros turn into the
     * fd 0 closes of the free path (the stdin of the daemon died
     * with the first freed channel, the next socket() landed on it
     * and the next free closed the listener) */

    ch->fwd_fd = -1;
    ch->sftp_in = -1;
    ch->sftp_out = -1;

    /* the session identity of the conversation (P7.3) */

    s3_srv_channel_user_snapshot(ch);

    rev = sc->read;

    rev->handler = s3_srv_h3_channel_read;
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
s3_srv_h3_accept(s3_connection_t *c, s3_quic_stream_t *qs)
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
            fprintf(stderr, "ssh3-server: h3 init_session failed\n");
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

    if (s3_srv_h3_sc != NULL && pc == s3_srv_h3_pc) {

        /*
         * every bidi stream after the CONNECT is an ssh3 channel
         * (docs/P4-WIRE.md 1, the server dispatch rule); the pc
         * check keeps a SECOND client connection on the fresh
         * CONNECT path below - the harness serves them one after
         * another out of one process (the sftp put/get pair)
         */
        s3_srv_h3_channel_accept(sc);
        return;
    }

    s3_srv_h3_sc = sc;
    s3_srv_h3_pc = pc;
    s3_srv_h3_conv_id = qs->id;
    s3_srv_h3_responded = 0;
    s3_srv_h3_len = 0;
    s3_srv_h3_out_len = 0;
    s3_srv_h3_method_len = 0;
    s3_srv_h3_protocol_len = 0;
    s3_srv_h3_path_len = 0;
    s3_srv_h3_auth_len = 0;

    s3_memzero(&s3_srv_h3_parse, sizeof(s3_h3_parse_headers_t));

    rev = sc->read;
    wev = sc->write;

    rev->handler = s3_srv_h3_request_read;
    rev->data = sc;

    /*
     * the app-level read arming, the s3 analog of the reference
     * ngx_handle_read_event(): without it s3_quic_set_event() only
     * raises ready and never posts the data events
     */
    rev->active = 1;

    wev->handler = s3_srv_h3_stream_write;
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
s3_srv_stream_accept(s3_connection_t *c, s3_quic_stream_t *qs)
{
    /*
     * the daemon speaks the ssh3 route only: every bidi stream is
     * either the extended CONNECT or an ssh3 channel of the
     * conversation
     */
    s3_srv_h3_accept(c, qs);
}

static void
s3_srv_accept(s3_connection_t *c)
{
    /* the S2-06 cap counts the connections accepted before this
     * one, 0 (the default) keeps the unbounded behavior */

    unsigned prior = s3_srv_active_conns();

    /*
     * the tracking rides the pool cleanup: a closing connection
     * nulls its slot, the main loop never probes a freed connection
     */
    if (!s3_srv_draining) {
        s3_srv_track(c);
    }

    s3_quic_run(c, &s3_srv_conf);

    /* the refusal rides after the run (the drain shape below): the
     * engine had to create the connection to answer the Initial,
     * the CONNECTION_CLOSE goes out on the next pass */

    if (!s3_srv_draining && s3_srv_max_conns > 0 && prior >= (unsigned)s3_srv_max_conns) {
        s3_srv_report("CONN-CAP-DENIED\n");
        s3_quic_finalize_connection(c, 0, "too many connections");
        return;
    }

    if (s3_srv_draining && c->udp != NULL) {

        /*
         * no new conversations during the shutdown: the quic layer
         * had to create the connection to answer the Initial, the
         * CONNECTION_CLOSE (app, 0, "server shutdown") goes out on
         * the next pass, the established conversations keep the
         * socket
         */
        s3_quic_finalize_connection(c, 0, "server shutdown");
    }
}

/*
 * the systemd socket activation, the sd_listen_fds(3) protocol: the
 * passing process leaves the LISTEN_PID/LISTEN_FDS markers and the
 * ready listening sockets at fd 3 upward (SD_LISTEN_FDS_START).  The
 * claimed fds return ready for the listener table and the local
 * addresses ride sa[]/salen[] out (getsockname() doubles as the
 * family guard).  One or two datagram sockets serve: a bare
 * ListenDatagram=port hands over ONE dual-stack IPv6 socket
 * (BindIPv6Only=default), a v4+v6 unit pair hands over TWO - each fd
 * becomes its own listener, a connection stays on the fd it arrived
 * on.  Both families serve (the IPv4-only guard died with the
 * dual-stack bind of the reference).  A present but unusable fd is a
 * unit misconfiguration: the daemon stops instead of falling back to
 * -l - a silent second bind behind the unit's socket would only move
 * the failure from the startup to the first packet
 */
#define S3_SRV_SD_LISTEN_FDS 3 /* SD_LISTEN_FDS_START of sd_listen_fds(3) */
#define S3_SRV_SD_LISTEN_MAX 2
#define S3_SRV_LISTENERS_MAX S3_SRV_SD_LISTEN_MAX

/* the per-socket listener state, one slot per served fd */

static s3_udp_listen_t s3_srv_uls[S3_SRV_LISTENERS_MAX];

static int
s3_srv_sd_listen_fds(int                     fds[S3_SRV_SD_LISTEN_MAX],
                     struct sockaddr_storage sa[S3_SRV_SD_LISTEN_MAX],
                     socklen_t salen[S3_SRV_SD_LISTEN_MAX], unsigned *count)
{
    const char *pid, *nfds;
    int         type, v6only;
    socklen_t   sl;
    long        n;
    unsigned    i;

    *count = 0;

    pid = getenv("LISTEN_PID");

    if (pid == NULL || (pid_t)atoi(pid) != getpid()) {

        /* no markers or the activation belongs to another process */
        return -1;
    }

    nfds = getenv("LISTEN_FDS");

    if (nfds == NULL || (n = atol(nfds)) < 1) {
        return -1;
    }

    if (n > S3_SRV_SD_LISTEN_MAX) {
        s3_log_error(S3_LOG_ERR, &s3_srv_log, 0,
                     "socket activation passed %ld fds, at most %d serve", n, S3_SRV_SD_LISTEN_MAX);
        exit(1);
    }

    for (i = 0; i < (unsigned)n; i++) {

        fds[i] = S3_SRV_SD_LISTEN_FDS + (int)i;

        /* the guard: a datagram socket of either family */

        sl = sizeof(type);

        if (getsockopt(fds[i], SOL_SOCKET, SO_TYPE, &type, &sl) == -1) {
            s3_log_error(S3_LOG_ERR, &s3_srv_log, s3_socket_errno,
                         "getsockopt(SO_TYPE) of the socket-activated fd %d failed", fds[i]);
            exit(1);
        }

        if (type != SOCK_DGRAM) {
            s3_log_error(S3_LOG_ERR, &s3_srv_log, 0,
                         "socket-activated fd %d is not a datagram socket (type %d)", fds[i], type);
            exit(1);
        }

        sl = sizeof(sa[i]);

        if (getsockname(fds[i], (struct sockaddr *)&sa[i], &sl) == -1) {
            s3_log_error(S3_LOG_ERR, &s3_srv_log, s3_socket_errno,
                         "getsockname() of the socket-activated fd %d failed", fds[i]);
            exit(1);
        }

        salen[i] = sl;

        if (sa[i].ss_family != AF_INET && sa[i].ss_family != AF_INET6) {
            s3_log_error(S3_LOG_ERR, &s3_srv_log, 0,
                         "socket-activated fd %d has an unsupported family %d", fds[i],
                         (int)sa[i].ss_family);
            exit(1);
        }

        if (sa[i].ss_family == AF_INET6) {

            /* the unit owns the mode: both (the default) or v6-only,
             * the state is served as handed over and logged */

            v6only = 0;
            sl = sizeof(v6only);

            if (getsockopt(fds[i], IPPROTO_IPV6, IPV6_V6ONLY, &v6only, &sl) == -1) {
                s3_log_error(S3_LOG_ERR, &s3_srv_log, s3_socket_errno,
                             "getsockopt(IPV6_V6ONLY) of the socket-activated fd %d failed",
                             fds[i]);
                exit(1);
            }

            s3_log_error(S3_LOG_INFO, &s3_srv_log, 0, "socket-activated fd %d: IPv6 socket, %s",
                         fds[i], v6only ? "v6-only per the unit" : "dual-stack");
        }

        /*
         * the same listener hygiene as the -l path: nonblocking for
         * the event loop, close-on-exec so the session children never
         * hold the listening socket
         */
        if (s3_nonblocking(fds[i]) != S3_OK || fcntl(fds[i], F_SETFD, FD_CLOEXEC) == -1) {
            s3_log_error(S3_LOG_ERR, &s3_srv_log, s3_socket_errno,
                         "socket-activated fd %d: hygiene failed", fds[i]);
            exit(1);
        }

        s3_log_error(S3_LOG_INFO, &s3_srv_log, 0, "socket-activated: serving the UDP fd %d",
                     fds[i]);
    }

    /*
     * the markers go before anything forks: a session child must not
     * grow up thinking the fds are its own (sd_listen_fds(3) does the
     * same unsetenv once the fds are claimed)
     */
    (void)unsetenv("LISTEN_PID");
    (void)unsetenv("LISTEN_FDS");

    *count = (unsigned)n;

    return 0;
}

/* the host-order port of a listener address */

static in_port_t
s3_srv_port_of(const struct sockaddr_storage *ss)
{
    if (ss->ss_family == AF_INET) {
        return ntohs(((const struct sockaddr_in *)ss)->sin_port);
    }

    return ntohs(((const struct sockaddr_in6 *)ss)->sin6_port);
}

/* the printable form of a listener address: v6 rides in brackets */

static const char *
s3_srv_addr_text(const struct sockaddr_storage *ss, char *buf, size_t size)
{
    const void *addr;
    int         family = ss->ss_family;

    if (family == AF_INET) {
        addr = &((const struct sockaddr_in *)ss)->sin_addr;
    } else if (family == AF_INET6) {
        addr = &((const struct sockaddr_in6 *)ss)->sin6_addr;
    } else {
        snprintf(buf, size, "family-%d", family);
        return buf;
    }

    if (inet_ntop(family, addr, buf, (socklen_t)size) == NULL) {
        snprintf(buf, size, "unprintable");
    }

    return buf;
}

/*
 * one listening socket: the connection object, its local address and
 * the per-socket listener state (the rbtree of the quic sockets); a
 * connection stays on the fd it arrived on, so a v4+v6 pair runs two
 * independent listener states behind one accept handler
 */
static s3_connection_t *
s3_srv_listener_add(s3_event_ctx_t *ctx, s3_fd_t fd, const struct sockaddr_storage *sa,
                    socklen_t salen, unsigned idx)
{
    s3_connection_t *listener;
    s3_udp_listen_t *ul;
    s3_int_t         rc;

    listener = s3_get_connection(ctx, fd);

    if (listener == NULL) {
        s3_log_error(S3_LOG_ERR, &s3_srv_log, 0, "connection alloc failed");
        return NULL;
    }

    listener->sockaddr = (struct sockaddr *)s3_palloc(ctx->pool, salen);

    if (listener->sockaddr == NULL) {
        return NULL;
    }

    s3_memcpy(listener->sockaddr, sa, salen);
    listener->socklen = salen;

    ul = &s3_srv_uls[idx];

    s3_memzero(ul, sizeof(*ul));

    ul->connection = listener;
    ul->ctx = ctx;
    ul->handler = s3_srv_accept;
    ul->quic = 1;

    /* the quic listener: the rbtree is keyed by the packet dcid */

    s3_rbtree_init(&ul->rbtree, &ul->sentinel, s3_quic_rbtree_insert_socket);

    listener->data = ul;
    listener->read->handler = s3_event_recvmsg;

    rc = s3_event_actions.add_event(listener->read, S3_READ_EVENT, 0);

    if (rc != S3_OK) {
        s3_log_error(S3_LOG_ERR, &s3_srv_log, 0, "add_event failed");
        return NULL;
    }

    return listener;
}

static void
s3_srv_usage(FILE *out, const char *prog)
{
    fprintf(out,
            "usage: %s -c cert.pem (-h keyfile|-k keyfile) [-p port] [-o option]"
            " [-l addr[:port]]\n"
            "              [the ssh3 options]\n"
            "\n"
            "the sshd(8) shapes:\n"
            "  -h  host key file: the private key PEM (the sshd -h hostkey, the alias\n"
            "      of -k - the QUIC listener serves the TLS pair)\n"
            "  -c  certificate PEM file\n"
            "  -p  listen port: re-ports the default listener and the bare -l\n"
            "      addresses ([::]:443 -> [::]:port, -l addr -> addr:port); the\n"
            "      explicit port of -l addr:port wins; under the systemd socket\n"
            "      activation (LISTEN_FDS) the passed fd serves and -p is ignored\n"
            "  -o  sshd_config-style option, repeatable, the keys and the boolean\n"
            "      values case-insensitive:\n"
            "        PermitOpen=spec|any|none: the direct-tcp/udp dial policy (the\n"
            "          --permit-open spec shape, the entries host:port, the\n"
            "          wildcards, the !negation); any = unrestricted, none = the\n"
            "          every-dial refusal\n"
            "        PermitListen=spec|any|none: the reverse (-R) bind policy, the\n"
            "          same shapes\n"
            "        GatewayPorts=no|yes|clientspecified: the reverse bind policy\n"
            "          (the y|n aliases ride)\n"
            "        MaxStartups=n: the cap of the CONNECTs between the arrival\n"
            "          and the auth verdict (the --max-unauth-conversations\n"
            "          analog), 0 is the kill-switch; the start:rate:full form is\n"
            "          not supported\n"
            "        AuthorizedKeysFile=path [path...]: the authorized_keys chain,\n"
            "          the paths split on the spaces, the %%u token is the session\n"
            "          username, the %%h token its home directory (the files the\n"
            "          repeatable -K serves)\n"
            "        ChrootDirectory=dir: the sftp jail root override (the -H\n"
            "          alias); simplified: single global value, per-user Match is\n"
            "          not supported\n"
            "      an unknown option names the supported set and stops the daemon\n"
            "\n"
            "the ssh3 options:\n"
            "  -k  private key PEM file (the alias of -h)\n"
            "  -l  UDP listen address: a.b.c.d[:port] or [v6][:port]; a bare\n"
            "      address takes the -p port or the 443 default; the [::] bind\n"
            "      serves both families (the dual-stack shape of the reference\n"
            "      -bind default); port 0 picks an ephemeral one; omitted under\n"
            "      the systemd socket activation (LISTEN_FDS): the passed fd(s)\n"
            "      serve, no bind happens\n"
            "  -A  ALPN name, default h3 (RFC 9220 extended CONNECT, ssh3)\n"
            "  -d  max_datagram_frame_size transport parameter, default 1200\n"
    "  -i  quic idle timeout, milliseconds, default 86400000 (24 h, the\n"
    "      ssh2 idle canon: a silent session lives, the zombies die on the\n"
    "      transport error alone)\n"
    "  -L  log level: a name (debug|info|warn|error) or an s3 numeric\n"
    "  -P  password file: the CONNECT passes only with the Basic"
    " user:secret AND the\n"
    "      password login on (the default, the sshd"
    " PasswordAuthentication canon;\n"
    "      disable with --enable-password-login off or"
    " SSH3_ENABLE_PASSWORD_LOGIN=0);\n"
    "      the file backend answers before the system one when both are"
    " wired\n"
    "      (--password-system)\n"
            "  -K  authorized_keys file, repeatable: the CONNECT passes only with a"
            " Bearer JWT\n"
            "      signed by one of their keys; %%u in the path is the session"
            " username, %%h its\n"
            "      home directory; without -K the default chain of the session"
            " user serves\n"
            "      (~/.ssh3/authorized_identities then"
            " ~/.ssh/authorized_keys, the reference\n"
            "      DefaultIdentitiesFileNames)\n"
            "  --url-path p: the CONNECT route, default /ssh3-term (the reference"
            " -url-path)\n"
            "  -H  the sftp jail directory override, default the user's home\n"
            "  --sftp-jail chroot|lexical: the sftp isolation, default chroot: every\n"
            "      sftp channel forks a child that chroots into the jail root and\n"
            "      drops to the session identity before serving (the sshd shape,\n"
            "      the kernel confines the paths); lexical keeps the historical\n"
            "      in-process jail, the non-root runs fold to it; a group or\n"
            "      world-writable jail root is refused\n"
            "  --oidc-issuer url --oidc-audience id: the CONNECT passes only"
            " with the Bearer\n"
            "      id_token of that provider (the S3_OIDC_CA_FILE env pins"
            " the https trust)\n"
            "  --oidc-jwks-ttl seconds: the key set lifetime of the oidc"
            " provider, default\n"
            "      3600, the timer rotates the set in the background\n"
            "  --run-as-user on|off: the per-session setuid of the root"
            " daemon, default\n"
            "      on for the euid 0: every session with a resolvable"
            " CONNECT user drops\n"
            "      onto it (initgroups, setgid, setuid, the home"
            " chdir) before the spawn;\n"
            "      a user without a passwd entry answers 401 before any"
            " spawn, a CONNECT\n"
            "      without a user keeps the daemon identity\n"
            "  --max-unauth-conversations n: the cap of the CONNECTs"
            " sitting between the\n"
            "      arrival and the auth verdict (the MaxStartups"
            " analog), default 100,\n"
            "      over the cap the CONNECT answers 503 before any"
            " auth work, 0 refuses\n"
            "      every CONNECT\n"
            "  --max-password-failures n: the failed Basic verdicts"
            " that lock the account\n"
            "      out of the password backend, default 10\n"
            "  --password-lockout-seconds s: the lockout window of the"
            " failed accounts,\n"
            "      default 60, the locked account answers 429 without"
            " the password file\n"
            "  --permit-open spec: the forward target policy of the"
            " direct-tcp and\n"
            "      direct-udp dials (the sshd_config PermitOpen"
            " semantics): comma/space\n"
            "      separated host:port entries, the \"*\" wildcards"
            " (the whole host, the\n"
            "      \"*.suffix\" form, the port), the \"!\" negation,"
            " the bracketed ipv6\n"
            "      literal [v6]:port; an empty spec keeps the"
            " unrestricted default\n"
            "  --permit-listen spec: the listen policy of the reverse"
            " (-R) binds\n"
            "      (the sshd_config PermitListen semantics, the same"
            " entry shapes); the\n"
            "      gate runs on the post-GatewayPorts bind before any"
            " socket, an empty\n"
            "      spec keeps the unrestricted bind\n"
            "  --gateway-ports no|yes|clientspecified: the GatewayPorts"
            " policy of the\n"
            "      reverse (-R) binds (the sshd_config semantics): the"
            " default \"no\"\n"
            "      forces every client bind back to the loopback,"
            " \"clientspecified\"\n"
            "      honors the bind address the client asked for,"
            " \"yes\" binds the\n"
            "      wildcard address regardless of the request\n"
    "  --max-reverse-forwards n: the live reverse (-R) listeners"
    " of one user,\n"
    "      default 10 (the maxReverseForwardsPerUser mirror of the"
    " fork), 0 is the\n"
    "      explicit unlimited, the per-conversation budget of 10"
    " stays; over the\n"
    "      cap the bind refuses with the REVERSE-CAP-DENIED marker"
    " before any\n"
    "      socket\n"
            "  --max-sftp-sessions-per-user n: the concurrent sftp"
            " channels of one\n"
            "      user, default 16, 0 disables the budget (S2-02)\n"
            "  --max-connections n: the concurrent QUIC connections,"
            " default 0 (no\n"
            "      limit), over the cap the new connection is closed"
            " at once (S2-06)\n"
    "  --handshake-timeout-ms ms: the QUIC handshake timeout, the"
    " LoginGraceTime\n"
    "      canon, default 120000\n"
            "  --help  this summary on stdout, exit 0 (the help moved off the\n"
            "      short -h, the sshd host key owns it now)\n"
            "  -v  verbose logging (debug)\n"
            "  -V  print the version and exit\n"
            "env:  SSH3_LOG_LEVEL, SSH3_LOG_FILE, SSH3_SHUTDOWN_DRAIN (seconds,\n"
            "      default 5, 0 closes the connections immediately),\n"
            "      SSH3_MAX_UNAUTH_CONVERSATIONS,"
            " SSH3_MAX_PASSWORD_FAILURES,\n"
            "      SSH3_PASSWORD_LOCKOUT_SECONDS (the DoS guard knobs"
            " of the flags\n"
            "      above),\n"
            "      SSH3_MAX_SFTP_SESSIONS_PER_USER,"
            " SSH3_MAX_CONNECTIONS,\n"
            "      SSH3_HANDSHAKE_TIMEOUT_MS (the S2-02/S2-06 knobs"
            " of the flags\n"
            "      above),\n"
            "      SSH3_ENABLE_PASSWORD_LOGIN=on|off (the"
            " --enable-password-login\n"
            "      default, the ParseBool forms 1/true/t and"
            " 0/false/f ride),\n"
            "      SSH3_PERMIT_OPEN (the --permit-open default),\n"
            "      SSH3_PERMIT_LISTEN (the --permit-listen default),\n"
            "      SSH3_GATEWAY_PORTS=no|yes|clientspecified (the"
            " --gateway-ports default),\n"
            "      SSH3_MAX_REVERSE_FORWARDS (the"
            " --max-reverse-forwards default),\n"
            "      SSH3_SFTP_JAIL=chroot|lexical (the --sftp-jail flag overrides),\n"
            "      SSH3_PASSWORD_SYSTEM=on|off (the --password-system default),\n"
            "      SSH3C_PROTO=1 adds the runner protocol markers to stdout;\n"
            "      LISTEN_PID/LISTEN_FDS switch to systemd socket activation,"
            " the passed UDP\n"
            "      fd(s) serve and -l is not required; one dual-stack fd (the"
            " bare\n"
            "      ListenDatagram=port) or the v4+v6 pair serve\n",
            prog);
}

int
main(int argc, char **argv)
{
    char                    opt;
    const char             *listen_text = NULL, *cert_path = NULL, *key_path = NULL;
    const char             *alpn_name = "h3";
    const char             *url_path_arg = NULL, *permit_open_arg = NULL;
    const char             *permit_listen_arg = NULL;
    unsigned                dg_size = 1200;
    /* the 24 h idle of the ssh2 canon (ClientAliveInterval=0, the
     * ssh2IdleTimeout mirror of the fork cmd/ssh3.go), the -i flag
     * and the env overrides stay */
    unsigned                idle_ms = 86400000;
    u_char                 *cert, *key, alpn_wire[256];
    size_t                  cert_len = 0, key_len = 0;
    s3_str_t                alpn;
    s3_int_t                rc;
    s3_uint_t               i;
    int                     listen_fds[S3_SRV_LISTENERS_MAX];
    struct sockaddr_storage listen_sa[S3_SRV_LISTENERS_MAX];
    socklen_t               listen_salen[S3_SRV_LISTENERS_MAX];
    unsigned                listeners = 0, li;
    int                     dos_unauth = -1, dos_pw_failures = -1, dos_pw_secs = -1;
    unsigned                port_arg = 0;       /* the -p port, 0 = not given */
    unsigned                dport;              /* the effective bare-address port */
    int                     chroot_warned = 0;  /* the one-time -o warn flag */
    char                    default_listen[24]; /* the "[::]:port" text of the default */
    s3_event_ctx_t          ctx;
    struct sigaction        act;

    s3_srv_log_init();

    /*
     * the drain window of the reference (cmd/ssh3-server.go):
     * SSH3_SHUTDOWN_DRAIN in seconds, the default 5, 0 closes the
     * connections immediately, a negative or unparsable value falls
     * back to the default
     */
    if (getenv("SSH3_SHUTDOWN_DRAIN") != NULL) {
        int secs = atoi(getenv("SSH3_SHUTDOWN_DRAIN"));

        if (secs >= 0) {
            s3_srv_drain_ms = (s3_msec_t)secs * 1000;

        } else {
            s3_log_error(S3_LOG_WARN, &s3_srv_log, 0,
                         "invalid SSH3_SHUTDOWN_DRAIN \"%s\", using the default",
                         getenv("SSH3_SHUTDOWN_DRAIN"));
        }
    }

    if (getenv("SSH3C_PROTO") != NULL && strcmp(getenv("SSH3C_PROTO"), "1") == 0) {
        s3_srv_proto_mode = 1;
    }

    /*
     * the DoS guard knobs of the reference (server_auth/dos_guard.go):
     * the env defaults parse first, the flags of the pre-scan below
     * override, an unparsable value falls back to the default like
     * SSH3_SHUTDOWN_DRAIN
     */

    if (getenv("SSH3_MAX_UNAUTH_CONVERSATIONS") != NULL) {
        int n = atoi(getenv("SSH3_MAX_UNAUTH_CONVERSATIONS"));

        if (n >= 0) {
            dos_unauth = (unsigned)n;

        } else {
            s3_log_error(S3_LOG_WARN, &s3_srv_log, 0,
                         "invalid SSH3_MAX_UNAUTH_CONVERSATIONS \"%s\", using the default",
                         getenv("SSH3_MAX_UNAUTH_CONVERSATIONS"));
        }
    }

    if (getenv("SSH3_MAX_PASSWORD_FAILURES") != NULL) {
        int n = atoi(getenv("SSH3_MAX_PASSWORD_FAILURES"));

        if (n > 0) {
            dos_pw_failures = n;

        } else {
            s3_log_error(S3_LOG_WARN, &s3_srv_log, 0,
                         "invalid SSH3_MAX_PASSWORD_FAILURES \"%s\", using the default",
                         getenv("SSH3_MAX_PASSWORD_FAILURES"));
        }
    }

    if (getenv("SSH3_PASSWORD_LOCKOUT_SECONDS") != NULL) {
        int n = atoi(getenv("SSH3_PASSWORD_LOCKOUT_SECONDS"));

        if (n >= 0) {
            dos_pw_secs = n;

        } else {
            s3_log_error(S3_LOG_WARN, &s3_srv_log, 0,
                         "invalid SSH3_PASSWORD_LOCKOUT_SECONDS \"%s\", using the default",
                         getenv("SSH3_PASSWORD_LOCKOUT_SECONDS"));
        }
    }

    /*
     * the S2-02/S2-06 knobs: the env defaults parse first, the CLI
     * flags of the pre-scan below override, an unparsable value
     * falls back to the default like the DoS guard knobs above
     */

    if (getenv("SSH3_MAX_SFTP_SESSIONS_PER_USER") != NULL) {
        int n = atoi(getenv("SSH3_MAX_SFTP_SESSIONS_PER_USER"));

        if (n >= 0) {
            s3_srv_sftp_cap = (unsigned)n;

        } else {
            s3_log_error(S3_LOG_WARN, &s3_srv_log, 0,
                         "invalid SSH3_MAX_SFTP_SESSIONS_PER_USER \"%s\", using the default",
                         getenv("SSH3_MAX_SFTP_SESSIONS_PER_USER"));
        }
    }

    if (getenv("SSH3_MAX_REVERSE_FORWARDS") != NULL) {
        int n = atoi(getenv("SSH3_MAX_REVERSE_FORWARDS"));

        if (n >= 0) {
            s3_srv_reverse_cap = (unsigned)n;

        } else {
            s3_log_error(S3_LOG_WARN, &s3_srv_log, 0,
                         "invalid SSH3_MAX_REVERSE_FORWARDS \"%s\", using the default",
                         getenv("SSH3_MAX_REVERSE_FORWARDS"));
        }
    }

    if (getenv("SSH3_MAX_CONNECTIONS") != NULL) {
        int n = atoi(getenv("SSH3_MAX_CONNECTIONS"));

        if (n >= 0) {
            s3_srv_max_conns = n;

        } else {
            s3_log_error(S3_LOG_WARN, &s3_srv_log, 0,
                         "invalid SSH3_MAX_CONNECTIONS \"%s\", using the default",
                         getenv("SSH3_MAX_CONNECTIONS"));
        }
    }

    if (getenv("SSH3_HANDSHAKE_TIMEOUT_MS") != NULL) {
        int n = atoi(getenv("SSH3_HANDSHAKE_TIMEOUT_MS"));

        if (n > 0) {
            s3_srv_hs_ms = n;

        } else {
            s3_log_error(S3_LOG_WARN, &s3_srv_log, 0,
                         "invalid SSH3_HANDSHAKE_TIMEOUT_MS \"%s\", using the default",
                         getenv("SSH3_HANDSHAKE_TIMEOUT_MS"));
        }
    }

    /*
     * the sftp isolation of the reference (-sftp-jail): the env
     * default parses first, the CLI flag above overrides it, an
     * unknown value keeps the default (the chroot)
     */
    {
        const char *jail = getenv("SSH3_SFTP_JAIL");

        if (jail != NULL && *jail != '\0') {

            if (strcmp(jail, "chroot") == 0) {
                s3_srv_sftp_chroot = 1;

            } else if (strcmp(jail, "lexical") == 0) {
                s3_srv_sftp_chroot = 0;

            } else {
                s3_log_error(S3_LOG_WARN, &s3_srv_log, 0,
                             "invalid SSH3_SFTP_JAIL \"%s\", keeping the default", jail);
            }
        }
    }

    /*
     * the GatewayPorts policy of the reference (-gateway-ports): the
     * env default parses first, the flag of the pre-scan below
     * overrides, an unknown value keeps the default (the "no")
     */
    {
        const char *policy = getenv("SSH3_GATEWAY_PORTS");

        if (policy != NULL && *policy != '\0' && s3_srv_gateway_ports_parse(policy) != S3_OK) {
            s3_log_error(S3_LOG_WARN, &s3_srv_log, 0,
                         "invalid SSH3_GATEWAY_PORTS \"%s\", keeping the default", policy);
        }
    }

    /*
     * the system verifier env default (PLAN.md 8.2): the same
     * ParseBool forms of the reference, it parses here - before the
     * pre-scan - so the explicit --password-system on|off overrides
     * it either way (the pattern of the DoS guard knobs)
     */
    /*
     * the password defaults of the sshd canon (the wave 1e): both
     * env knobs parse before the pre-scan, the ParseBool forms of
     * the reference ride, an unparsable value warns and keeps the
     * on default; the explicit flags of the pre-scan below override
     * either way (the pattern of the DoS guard knobs)
     */
    {
        const char *env = getenv("SSH3_ENABLE_PASSWORD_LOGIN");
        unsigned    v;

        if (env != NULL && s3_srv_parse_bool(env, &v) == S3_OK) {
            s3_srv_password_enabled = v;

        } else if (env != NULL) {
            s3_log_error(S3_LOG_WARN, &s3_srv_log, 0,
                         "invalid SSH3_ENABLE_PASSWORD_LOGIN \"%s\", keeping the default", env);
        }
    }

    {
        const char *env = getenv("SSH3_PASSWORD_SYSTEM");
        unsigned    v;

        if (env != NULL && s3_srv_parse_bool(env, &v) == S3_OK) {
            s3_srv_password_system = v;

        } else if (env != NULL) {
            s3_log_error(S3_LOG_WARN, &s3_srv_log, 0,
                         "invalid SSH3_PASSWORD_SYSTEM \"%s\", keeping the default", env);
        }
    }

    /*
     * the OIDC options and the ssh3 routes ride the long form (the
     * daemon keeps the names of the reference), the pre-scan pulls
     * them out of argv before the short getopt loop
     */

    {
        int   n, m, keep, drop;
        char *value;

        for (n = 1; n < argc;) {

            keep = 1;
            drop = 0;
            value = NULL;

            if (strcmp(argv[n], "--help") == 0) {

                /* the summary of the sshd -h era moved here: the
                 * short key serves the host key now, the usage rides
                 * stdout and the exit is 0 */

                s3_srv_usage(stdout, argv[0]);
                return 0;

            } else if (strcmp(argv[n], "--oidc-issuer") == 0 && n + 1 < argc) {
                s3_srv_oidc_issuer = argv[n + 1];
                value = argv[n + 1];

            } else if (strcmp(argv[n], "--oidc-audience") == 0 && n + 1 < argc) {
                snprintf(s3_srv_oidc_aud, sizeof(s3_srv_oidc_aud), "%s", argv[n + 1]);
                value = argv[n + 1];

            } else if (strcmp(argv[n], "--oidc-jwks-ttl") == 0 && n + 1 < argc) {
                s3_srv_oidc_ttl = (time_t)atoi(argv[n + 1]);
                value = argv[n + 1];

            } else if (strcmp(argv[n], "--url-path") == 0 && n + 1 < argc) {
                url_path_arg = argv[n + 1];
                value = argv[n + 1];

            } else if (strcmp(argv[n], "--enable-password-login") == 0) {

                /*
                 * the PasswordAuthentication shape of the sshd canon
                 * (the wave 1e, the -enable-password-login mirror of
                 * the fork): the bare flag is the explicit on, the
                 * value form on|off|true|false|1|0 carries the
                 * verdict (the env default parsed above overrides
                 * either way); an unparsable value stays in the argv
                 * for the getopt loop to reject with the usage
                 */

                unsigned v;

                if (n + 1 >= argc || argv[n + 1][0] == '-') {

                    /* the bare form (no value, or the next token is
                     * another flag): the login rides on */

                    s3_srv_password_enabled = 1;
                    drop = 1;

                } else if (s3_srv_parse_bool(argv[n + 1], &v) == S3_OK) {
                    s3_srv_password_enabled = v;
                    value = argv[n + 1];
                }

            } else if (strcmp(argv[n], "--password-system") == 0 && n + 1 < argc) {

                /* the on|off form: anything else stays in the argv
                 * for the getopt loop to reject with the usage; the
                 * env default parsed above has already run, the
                 * explicit off kills the opt-in of the env too */

                if (strcmp(argv[n + 1], "on") == 0) {
                    s3_srv_password_system = 1;
                    value = argv[n + 1];

                } else if (strcmp(argv[n + 1], "off") == 0) {
                    s3_srv_password_system = 0;
                    value = argv[n + 1];
                }

            } else if (strcmp(argv[n], "--permit-open") == 0 && n + 1 < argc) {

                /* the spec form: the whole rest of the command line
                 * stays untouched, the parse rides after the env
                 * default below */

                permit_open_arg = argv[n + 1];
                value = argv[n + 1];

            } else if (strcmp(argv[n], "--permit-listen") == 0 && n + 1 < argc) {

                /* the reverse bind policy, the same spec shape */

                permit_listen_arg = argv[n + 1];
                value = argv[n + 1];

            } else if (strcmp(argv[n], "--gateway-ports") == 0 && n + 1 < argc) {

                /* the GatewayPorts policy (the on|off form): anything
                 * else stays in the argv for the getopt loop to
                 * reject with the usage, the sftp-jail shape */

                if (s3_srv_gateway_ports_parse(argv[n + 1]) == S3_OK) {
                    value = argv[n + 1];
                }

            } else if (strcmp(argv[n], "--max-reverse-forwards") == 0 && n + 1 < argc) {

                /* the reverse listener budget of the user: 0 is the
                 * legitimate unlimited (the per-conversation budget of
                 * 10 stays) */

                int k = atoi(argv[n + 1]);

                if (k < 0) {
                    s3_log_error(S3_LOG_ERR, &s3_srv_log, 0, "bad --max-reverse-forwards \"%s\"",
                                 argv[n + 1]);
                    return 1;
                }

                s3_srv_reverse_cap = (unsigned)k;
                value = argv[n + 1];

            } else if (strcmp(argv[n], "--run-as-user") == 0 && n + 1 < argc) {

                /* the on|off form: anything else stays in the argv
                 * for the getopt loop to reject with the usage */

                if (strcmp(argv[n + 1], "on") == 0) {
                    s3_srv_run_as = 1;
                    s3_srv_run_as_set = 1;
                    value = argv[n + 1];

                } else if (strcmp(argv[n + 1], "off") == 0) {
                    s3_srv_run_as = 0;
                    s3_srv_run_as_set = 1;
                    value = argv[n + 1];
                }

            } else if (strcmp(argv[n], "--max-unauth-conversations") == 0 && n + 1 < argc) {

                /* the DoS guard knobs (the reference
                 * -max-unauth-conversations and friends): a value the
                 * cap cannot carry is a config error, the daemon
                 * refuses to start; the cap of zero is the legitimate
                 * kill-switch (every CONNECT refuses with 503) */

                int k = atoi(argv[n + 1]);

                if (k < 0) {
                    s3_log_error(S3_LOG_ERR, &s3_srv_log, 0,
                                 "bad --max-unauth-conversations \"%s\"", argv[n + 1]);
                    return 1;
                }

                dos_unauth = (unsigned)k;
                value = argv[n + 1];

            } else if (strcmp(argv[n], "--max-password-failures") == 0 && n + 1 < argc) {

                int k = atoi(argv[n + 1]);

                if (k <= 0) {
                    s3_log_error(S3_LOG_ERR, &s3_srv_log, 0, "bad --max-password-failures \"%s\"",
                                 argv[n + 1]);
                    return 1;
                }

                dos_pw_failures = k;
                value = argv[n + 1];

            } else if (strcmp(argv[n], "--password-lockout-seconds") == 0 && n + 1 < argc) {

                int k = atoi(argv[n + 1]);

                if (k < 0) {
                    s3_log_error(S3_LOG_ERR, &s3_srv_log, 0,
                                 "bad --password-lockout-seconds \"%s\"", argv[n + 1]);
                    return 1;
                }

                dos_pw_secs = k;
                value = argv[n + 1];

            } else if (strcmp(argv[n], "--max-sftp-sessions-per-user") == 0 && n + 1 < argc) {

                /* the S2-02 budget: 0 is the legitimate unlimited */

                int k = atoi(argv[n + 1]);

                if (k < 0) {
                    s3_log_error(S3_LOG_ERR, &s3_srv_log, 0,
                                 "bad --max-sftp-sessions-per-user \"%s\"", argv[n + 1]);
                    return 1;
                }

                s3_srv_sftp_cap = (unsigned)k;
                value = argv[n + 1];

            } else if (strcmp(argv[n], "--max-connections") == 0 && n + 1 < argc) {

                /* the S2-06 cap: 0 keeps the unbounded behavior */

                int k = atoi(argv[n + 1]);

                if (k < 0) {
                    s3_log_error(S3_LOG_ERR, &s3_srv_log, 0, "bad --max-connections \"%s\"",
                                 argv[n + 1]);
                    return 1;
                }

                s3_srv_max_conns = k;
                value = argv[n + 1];

            } else if (strcmp(argv[n], "--handshake-timeout-ms") == 0 && n + 1 < argc) {

                int k = atoi(argv[n + 1]);

                if (k <= 0) {
                    s3_log_error(S3_LOG_ERR, &s3_srv_log, 0, "bad --handshake-timeout-ms \"%s\"",
                                 argv[n + 1]);
                    return 1;
                }

                s3_srv_hs_ms = k;
                value = argv[n + 1];

            } else if (strcmp(argv[n], "--sftp-jail") == 0 && n + 1 < argc) {

                /* the chroot|lexical form: anything else stays in
                 * the argv for the getopt loop to reject with the
                 * usage */

                if (strcmp(argv[n + 1], "chroot") == 0) {
                    s3_srv_sftp_chroot = 1;
                    value = argv[n + 1];

                } else if (strcmp(argv[n + 1], "lexical") == 0) {
                    s3_srv_sftp_chroot = 0;
                    value = argv[n + 1];
                }
            }

            if (value != NULL) {
                drop = 2;
            }

            if (drop > 0) {

                /* the option (and its value, when one rides) leaves
                 * the argv */

                for (m = n; m + drop < argc; m++) {
                    argv[m] = argv[m + drop];
                }

                argc -= drop;
                keep = 0;
            }

            if (keep) {
                n++;
            }
        }
    }

    while ((opt = (char)getopt(argc, argv, "l:c:k:h:A:d:i:L:P:H:K:3p:o:vV")) != -1) {

        switch (opt) {

        case 'l':
            listen_text = optarg;
            break;

        case 'c':
            cert_path = optarg;
            break;

        case 'k':
        case 'h':

            /* the private key PEM: the -h is the sshd host key shape,
             * the -k the project name - one key_path serves both */

            key_path = optarg;
            break;

        case 'p':

            /* the sshd -p port: the strict digits (the "bad port"
             * shape), the listener wiring rides after the getopt */

            if (s3_srv_parse_port(optarg, &port_arg) != S3_OK) {
                s3_log_error(S3_LOG_ERR, &s3_srv_log, 0, "bad -p port \"%s\"", optarg);
                return 1;
            }

            break;

        case 'o':

            if (s3_srv_o_option(optarg, &permit_open_arg, &permit_listen_arg, &dos_unauth,
                                &chroot_warned) != S3_OK) {
                return 1;
            }

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
            if (strcmp(optarg, "all") == 0) {
                s3_srv_log.log_level = S3_LOG_DEBUG_ALL;

            } else if (*optarg >= '0' && *optarg <= '9') {
                /* the numeric s3 level of the harness parity */
                s3_srv_log.log_level = (s3_uint_t)atol(optarg);

            } else {
                s3_srv_log.log_level = s3_srv_log_level(optarg, S3_LOG_INFO);
            }
            break;

        case 'P':
            s3_srv_passfile = optarg;
            break;

        case 'K':

            /* the repeatable -K: the files walk in the given order */

            if (s3_srv_keyfiles_n >= S3_SRV_KEYFILES_MAX) {
                s3_log_error(S3_LOG_ERR, &s3_srv_log, 0, "too many -K files (max %d)",
                             S3_SRV_KEYFILES_MAX);
                return 1;
            }

            s3_srv_keyfiles[s3_srv_keyfiles_n++] = optarg;
            break;

        case 'H':
            snprintf(s3_srv_sftp_home, sizeof(s3_srv_sftp_home), "%s", optarg);
            break;

        case 'v':
            s3_srv_log.log_level = S3_LOG_DEBUG_ALL;
            break;

        case 'V':
            printf("ssh3-server version %d.%d.%d\n", S3_SSH3_SOFTWARE_MAJOR, S3_SSH3_SOFTWARE_MINOR,
                   S3_SSH3_SOFTWARE_PATCH);
            return 0;

        case '3':
            /* the flag parity with the harness: the ssh3 route is the
             * only mode of the daemon */
            break;

        default:
            s3_srv_usage(stderr, argv[0]);
            return 1;
        }
    }

    /*
     * the knobs land on the guards once: the env defaults, the
     * pre-scan flags and the -o options met in the same locals, the
     * last writer of each wins (the flag overrides the env, the
     * untouched piece keeps the module default); the landing runs
     * after the getopt loop - the -o MaxStartups writes the same
     * local the pre-scan wrote
     */

    if (dos_unauth >= 0) {
        s3_dos_unauth_set_limit((unsigned)dos_unauth);
    }

    if (dos_pw_failures >= 0 || dos_pw_secs >= 0) {
        s3_dos_pw_set_limits(
            dos_pw_failures >= 0 ? (unsigned)dos_pw_failures : S3_DOS_PW_FAILURES_MAX_DEFAULT,
            dos_pw_secs >= 0 ? (s3_msec_t)dos_pw_secs * 1000 : S3_DOS_PW_LOCKOUT_MSEC_DEFAULT);
    }

    /*
     * the per-session setuid mode (P7.3): on by default for the root
     * daemon, the unprivileged run keeps the daemon identity - the
     * explicit --run-as-user on|off overrides both; a run-as request
     * without the privilege answers the warning of the flag parity
     * and serves as before
     */

    if (!s3_srv_run_as_set) {
        s3_srv_run_as = (geteuid() == 0);
    }

    if (s3_srv_run_as && geteuid() != 0) {

        s3_srv_run_as = 0;

        s3_log_error(S3_LOG_WARN, &s3_srv_log, 0,
                     "run-as-user requested without the root privilege,"
                     " sessions keep the daemon identity");

    } else if (s3_srv_run_as) {
        s3_log_error(S3_LOG_INFO, &s3_srv_log, 0, "per-session setuid enabled");
    }

    /*
     * the chroot without the privilege folds to the lexical jail at
     * the startup (the one-time log): the unprivileged daemon has no
     * privilege worth jailing and the unit shapes stay untouched
     */

    if (s3_srv_sftp_chroot && geteuid() != 0) {

        s3_srv_sftp_chroot = 0;

        s3_log_error(S3_LOG_WARN, &s3_srv_log, 0,
                     "sftp chroot jail without the root privilege, the lexical jail serves");

    } else if (s3_srv_sftp_chroot) {
        s3_log_error(S3_LOG_INFO, &s3_srv_log, 0, "sftp chroot jail enabled");
    }

    /*
     * the system verifier privilege check: the shadow is the root
     * read, the unprivileged daemon keeps the operator's opt-in
     * visible (no fold like the run-as and the jail) and answers the
     * one-time warning - the verifier declines every attempt before
     * the lookup (the fail-closed shape), the file backend serves as
     * usual
     */

    if (s3_srv_password_system && geteuid() != 0) {
        s3_log_error(S3_LOG_WARN, &s3_srv_log, 0,
                     "system password auth without the root privilege: the shadow is"
                     " unreadable, every Basic attempt against the system accounts"
                     " fails closed");

    } else if (s3_srv_password_system) {
        s3_log_error(S3_LOG_INFO, &s3_srv_log, 0, "system password auth enabled");
    }

    /*
     * the PermitRootLogin prohibit-password analog of the sshd canon
     * (the wave 1e, the fork root gate of server_auth/root_gate.go):
     * hardcoded, no flag - root never authenticates by password, the
     * key and the JWT verdicts serve as usual
     */

    s3_log_error(S3_LOG_INFO, &s3_srv_log, 0,
                 "PermitRootLogin prohibit-password: the root account authenticates"
                 " by key only");

    if (cert_path == NULL || key_path == NULL) {
        s3_srv_usage(stderr, argv[0]);
        return 1;
    }

    /* the route of the reference -url-path: a non-empty path with the
     * leading slash, the query stays out of the config */

    if (url_path_arg != NULL) {

        size_t n = strlen(url_path_arg);

        if (n == 0 || n >= sizeof(s3_srv_url_path) || url_path_arg[0] != '/') {
            s3_log_error(S3_LOG_ERR, &s3_srv_log, 0, "bad url path \"%s\"", url_path_arg);
            return 1;
        }

        memcpy(s3_srv_url_path, url_path_arg, n + 1);
        s3_srv_url_path_len = n;
    }

    /*
     * the forward target policy (F-05): the env default parses first,
     * the flag above has overridden it already (an empty env keeps
     * the unrestricted zero policy); a bad spec stops the daemon
     * before the sockets open, the config-error shape of the
     * url-path check
     */

    if (permit_open_arg == NULL) {
        permit_open_arg = getenv("SSH3_PERMIT_OPEN");
    }

    if (permit_open_arg != NULL &&
        s3_ssh3_forward_policy_parse(&s3_srv_fwd_policy, permit_open_arg) != S3_OK) {
        s3_log_error(S3_LOG_ERR, &s3_srv_log, 0, "bad permit-open spec \"%s\"", permit_open_arg);
        return 1;
    }

    /*
     * the reverse bind policy (--permit-listen, S2-04): the env
     * default parses first, the flag above has overridden it already;
     * a bad spec stops the daemon before the sockets open, the
     * config-error shape of the permit-open check
     */

    if (permit_listen_arg == NULL) {
        permit_listen_arg = getenv("SSH3_PERMIT_LISTEN");
    }

    if (permit_listen_arg != NULL &&
        s3_ssh3_forward_policy_parse(&s3_srv_listen_policy, permit_listen_arg) != S3_OK) {
        s3_log_error(S3_LOG_ERR, &s3_srv_log, 0, "bad permit-listen spec \"%s\"",
                     permit_listen_arg);
        return 1;
    }

    /*
     * the password login of the sshd canon (the wave 1e): the env
     * default parsed before the pre-scan, the flag has overridden it
     * already; the explicit off (the PasswordAuthentication no
     * shape) closes both backends at once - the system verifier no
     * longer opts the login in on its own, one verdict switch serves
     */

    if (s3_srv_passfile != NULL && !s3_srv_password_enabled) {
        s3_log_error(S3_LOG_WARN, &s3_srv_log, 0,
                     "the password file serves nothing: the password login is off,"
                     " re-enable with --enable-password-login on or"
                     " SSH3_ENABLE_PASSWORD_LOGIN=1");
    }

    /*
     * -l stays optional: the socket-activated daemon serves the passed
     * fd and binds nothing, and the sshd-canon default listener (the
     * dual-stack wildcard) serves when neither -l nor -p rode (the
     * check below runs before any use of listen_text).  A bare -l
     * address takes the -p port or the 443 of the reference
     */

    dport = port_arg ? port_arg : S3_SRV_DEFAULT_PORT;

    if (listen_text != NULL &&
        s3_srv_parse_addr(listen_text, &listen_sa[0], &listen_salen[0], dport) != S3_OK) {
        s3_log_error(S3_LOG_ERR, &s3_srv_log, 0, "bad listen address %s", listen_text);
        return 1;
    }

    /* the shutdown signals and the daemon hygiene */

    s3_memzero(&act, sizeof(act));

    act.sa_handler = s3_srv_signal_handler;

    if (sigaction(SIGTERM, &act, NULL) == -1 || sigaction(SIGINT, &act, NULL) == -1) {
        s3_log_error(S3_LOG_ERR, &s3_srv_log, s3_errno, "sigaction() failed");
        return 1;
    }

    (void)signal(SIGPIPE, SIG_IGN);

    cert = s3_srv_read_file(cert_path, &cert_len);
    key = s3_srv_read_file(key_path, &key_len);

    if (cert == NULL || key == NULL) {
        return 1;
    }

    /*
     * the OIDC bootstrap: the discovery and the first key set run
     * once here, before the sockets open - a provider that never
     * answers keeps the daemon from starting instead of stalling the
     * first CONNECT behind a blocking https inside the event loop;
     * the rotation and the unknown-kid refetch ride the timer below,
     * the request path never fetches
     */

    if (s3_srv_oidc_issuer != NULL) {
        const char *ca_file = getenv("S3_OIDC_CA_FILE");

        if (s3_ssh3_oidc_verifier_init(&s3_srv_oidc_ver, s3_srv_oidc_issuer, ca_file) != S3_OK) {
            s3_log_error(S3_LOG_ERR, &s3_srv_log, 0, "oidc verifier init failed for issuer %s",
                         s3_srv_oidc_issuer);
            return 1;
        }

        s3_ssh3_oidc_verifier_set_ttl(&s3_srv_oidc_ver, s3_srv_oidc_ttl);

        if (s3_ssh3_oidc_verifier_bootstrap(&s3_srv_oidc_ver, time(NULL)) != S3_OK) {
            s3_log_error(S3_LOG_ERR, &s3_srv_log, 0, "oidc bootstrap failed for issuer %s",
                         s3_srv_oidc_issuer);
            s3_ssh3_oidc_verifier_clear(&s3_srv_oidc_ver);
            return 1;
        }

        s3_log_error(S3_LOG_INFO, &s3_srv_log, 0, "oidc bootstrap complete: issuer %s, %u key(s)",
                     s3_srv_oidc_issuer, (s3_uint_t)s3_srv_oidc_ver.jwks.nkeys);
    }

    if (s3_event_ctx_init(&ctx, &s3_srv_log) != S3_OK) {
        s3_log_error(S3_LOG_ERR, &s3_srv_log, 0, "event ctx init failed");
        return 1;
    }

    /* the jwks timer: the ttl rotation and the unknown-kid refetch */

    if (s3_srv_oidc_issuer != NULL) {
        s3_memzero(&s3_srv_oidc_timer, sizeof(s3_srv_oidc_timer));
        s3_srv_oidc_timer.handler = s3_srv_oidc_timer_handler;
        s3_srv_oidc_timer.log = &s3_srv_log;

        s3_event_add_timer(&s3_srv_oidc_timer,
                           s3_ssh3_oidc_verifier_fetch_timer(&s3_srv_oidc_ver, time(NULL)));
    }

    rc = s3_srv_sd_listen_fds(listen_fds, listen_sa, listen_salen, &listeners);

    if (rc < 0) {

        int fd;

        if (listen_text == NULL) {

            /*
             * the sshd ListenAddress default: the dual-stack wildcard
             * listener, the -p port or the 443 of the reference - the
             * sockets open on it exactly like on the -l spec (the
             * V6ONLY=0 of the bind below serves both families)
             */

            s3_memzero(&listen_sa[0], sizeof(listen_sa[0]));

            listen_sa[0].ss_family = AF_INET6;
            ((struct sockaddr_in6 *)&listen_sa[0])->sin6_port = htons((uint16_t)dport);
            listen_salen[0] = sizeof(struct sockaddr_in6);

            snprintf(default_listen, sizeof(default_listen), "[::]:%u", dport);
            listen_text = default_listen;
        }

        fd = socket(listen_sa[0].ss_family, SOCK_DGRAM, 0);
        if (fd == -1) {
            s3_log_error(S3_LOG_ERR, &s3_srv_log, s3_socket_errno, "socket() failed");
            return 1;
        }

        if (listen_sa[0].ss_family == AF_INET6) {

            /*
             * the dual-stack bind of the reference ([::]:443): the
             * v4 clients ride the v4-mapped addresses, one socket
             * serves both families (the OpenSSH ListenAddress
             * default shape).  A kernel that refuses the dual mode
             * stops the daemon: a silent v6-only [::] bind would
             * move the v4 failure to the first packet
             */
            int v6only = 0;

            if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) == -1) {
                s3_log_error(S3_LOG_ERR, &s3_srv_log, s3_socket_errno,
                             "setsockopt(IPV6_V6ONLY) failed");
                return 1;
            }

            s3_log_error(S3_LOG_INFO, &s3_srv_log, 0,
                         "the [v6] bind serves both families (V6ONLY=0)");
        }

        if (s3_nonblocking(fd) != S3_OK) {
            s3_log_error(S3_LOG_ERR, &s3_srv_log, s3_socket_errno, "fcntl(O_NONBLOCK) failed");
            return 1;
        }

        /*
         * the session children fork this socket: the exec closes it so
         * the shell commands of the sessions never hold the listener
         * (the epoll fd of the ctx leaks into the children the same way,
         * harmless for the short-lived session commands)
         */
        if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
            s3_log_error(S3_LOG_ERR, &s3_srv_log, s3_socket_errno, "fcntl(FD_CLOEXEC) failed");
            return 1;
        }

        if (bind(fd, (struct sockaddr *)&listen_sa[0], listen_salen[0]) == -1) {
            s3_log_error(S3_LOG_ERR, &s3_srv_log, s3_socket_errno, "bind() %s failed", listen_text);
            return 1;
        }

        if (getsockname(fd, (struct sockaddr *)&listen_sa[0], &listen_salen[0]) == -1) {
            s3_log_error(S3_LOG_ERR, &s3_srv_log, s3_socket_errno, "getsockname() failed");
            return 1;
        }

        listen_fds[0] = fd;
        listeners = 1;

    } else {

        /*
         * the unit owns the port: the activated socket serves, a -l
         * the operator kept changes nothing (no second bind); the
         * claim already filled listen_sa[] and verified the family.
         * The -p port rides the same rule: the fd carries the port,
         * the flag would only re-port a bind that never happens
         */

        if (listen_text != NULL) {
            s3_log_error(S3_LOG_WARN, &s3_srv_log, 0, "socket-activated: -l %s ignored",
                         listen_text);
        }

        if (port_arg != 0) {
            s3_log_error(S3_LOG_WARN, &s3_srv_log, 0,
                         "socket-activated: -p %u ignored, the passed fd(s) serve", port_arg);
        }
    }

    for (li = 0; li < listeners; li++) {

        char addr_text[INET6_ADDRSTRLEN];

        s3_connection_t *listener =
            s3_srv_listener_add(&ctx, listen_fds[li], &listen_sa[li], listen_salen[li], li);

        if (listener == NULL) {
            return 1;
        }

        s3_log_error(S3_LOG_INFO, &s3_srv_log, 0,
                     "ssh3-server version %d.%d.%d listening on %s:%ui", S3_SSH3_SOFTWARE_MAJOR,
                     S3_SSH3_SOFTWARE_MINOR, S3_SSH3_SOFTWARE_PATCH,
                     s3_srv_addr_text(&listen_sa[li], addr_text, sizeof(addr_text)),
                     (s3_uint_t)s3_srv_port_of(&listen_sa[li]));

        /* the runner scripts pick the first listener by this line */

        s3_srv_report("INTEROP-LISTEN port=%u\n", (unsigned)s3_srv_port_of(&listen_sa[li]));
    }

    s3_srv_alpn_wire(alpn_wire, alpn_name);

    alpn.data = alpn_wire;
    alpn.len = 1 + strlen(alpn_name);

    s3_memzero(&s3_srv_conf, sizeof(s3_quic_conf_t));

    s3_srv_conf.ssl =
        s3_ssl_create(&s3_srv_log, (const char *)cert, cert_len, (const char *)key, key_len, &alpn);

    /*
     * the pem buffers served their purpose: s3_ssl_create() loaded the
     * x509 and the key into the ssl ctx through read-only BIO views,
     * nothing retains the pointers - free them here, the daemon runs
     * for weeks and the leak check at exit must stay silent
     */
    free(cert);
    free(key);

    if (s3_srv_conf.ssl == NULL) {
        s3_log_error(S3_LOG_ERR, &s3_srv_log, 0, "ssl init failed");
        return 1;
    }

    s3_srv_conf.gso_enabled = 1;
    s3_srv_conf.ctx = &ctx;
    s3_srv_conf.handshake_timeout = (s3_msec_t)s3_srv_hs_ms;
    s3_srv_conf.idle_timeout = (s3_msec_t)idle_ms;
    /* the bulk sftp credit: the client trains ride it (see the client conf) */
    s3_srv_conf.stream_buffer_size = 1 << 20;
    s3_srv_conf.max_concurrent_streams_bidi = 16;
    s3_srv_conf.max_concurrent_streams_uni = 16;
    s3_srv_conf.active_connection_id_limit = 8;
    s3_srv_conf.max_datagram_frame_size = dg_size;
    s3_srv_conf.datagram_handler = s3_srv_datagram_echo;
    s3_srv_conf.stream_handler = s3_srv_stream_accept;

    if (RAND_bytes(s3_srv_conf.av_token_key, S3_QUIC_AV_KEY_LEN) != 1 ||
        RAND_bytes(s3_srv_conf.sr_token_key, S3_QUIC_SR_KEY_LEN) != 1) {
        s3_log_error(S3_LOG_ERR, &s3_srv_log, 0, "RAND_bytes() failed");
        return 1;
    }

    for (;;) {
        s3_event_process_posted(&ctx, &ctx.posted_events);

        s3_process_events_and_timers(&ctx);

        /*
         * the shutdown state machine: the handlers only count the
         * signals, the work happens between the passes; the first
         * signal starts the drain, the repeated one ends it at once
         */
        if (s3_srv_quit == 1 && !s3_srv_draining) {
            s3_srv_drain_start();
            s3_srv_quit = 2;

        } else if (s3_srv_quit > 2) {
            s3_srv_drain_deadline = s3_current_msec;
        }

        if (s3_srv_draining) {
            unsigned busy = s3_srv_busy_channels();

            if (busy == 0) {

                if (s3_srv_active_conns() == 0) {
                    s3_log_error(S3_LOG_INFO, &s3_srv_log, 0, "shutdown: all connections finished");

                } else {
                    s3_log_error(S3_LOG_INFO, &s3_srv_log, 0,
                                 "shutdown: the active channels finished");
                }

                break;
            }

            if (s3_current_msec >= s3_srv_drain_deadline) {
                s3_log_error(S3_LOG_INFO, &s3_srv_log, 0,
                             "shutdown: drain timeout, closing %u busy channel(s)", busy);
                break;
            }
        }

        for (i = 0; i < S3_SRV_TRACKED; i++) {
            s3_connection_t *c = s3_srv_conns[i];

            if (c == NULL) {
                continue;
            }

            if (!s3_srv_reported[i] && c->ssl != NULL && c->ssl->handshaked) {
                s3_srv_report("INTEROP-HANDSHAKE-OK");

                s3_srv_reported[i] = 1;
            }
        }
    }

    /*
     * the shutdown tail: first the queued frames of the finished
     * channels (the 98 verdicts, the stream fins) flush on the
     * bounded passes, then the connections that outlived their
     * conversations (the C interop clients leave the quic connection
     * to the idle timeout) get the CONNECTION_CLOSE; the clean path
     * with no connections skips both
     */
    if (s3_srv_active_conns() > 0) {
        s3_msec_t deadline = s3_current_msec + S3_SRV_FLUSH_GRACE;

        while (s3_current_msec < deadline) {
            s3_srv_event_pass(&ctx);
        }

        s3_srv_force_close();

        deadline = s3_current_msec + S3_SRV_CLOSE_GRACE;

        while (s3_current_msec < deadline && s3_srv_active_conns() > 0) {
            s3_srv_event_pass(&ctx);
        }

        /*
         * the streams of a force-reset channel that a handler left
         * open wait for their posted events, the quic layer force
         * closes them inside the resumed close; a quiet peer parks on
         * the 3*PTO close timer, the drain below drops it and lets
         * every tracked pool complete its teardown before the exit
         */
        s3_srv_close_drain(&ctx);
    }

    s3_srv_teardown_channels();

    /* the provider keys of the OIDC verifier die with the daemon */

    s3_ssh3_oidc_verifier_clear(&s3_srv_oidc_ver);

    /*
     * the exit hygiene: the tracked pools died in the tail passes
     * above (the slot cleanup runs inside the pool destroy, the close
     * of every connection completes since the quic layer force-closes
     * the streams the handlers left open on the reset), what is left
     * here is the process-owned state - the ssl ctx, the h3 request
     * buffer and the event ctx with the connections and their events
     */

    s3_ssl_free(s3_srv_conf.ssl);

    free(s3_srv_h3_buf);

    s3_event_ctx_shutdown(&ctx);

    s3_log_error(S3_LOG_INFO, &s3_srv_log, 0, "shutdown complete");

    return 0;
}
