/*
 * Copyright (C) 2026 the ssh3-c authors
 */

/*
 * the product ssh3 client (P9 wave 3, stage A, Windows): the CLI
 * shape of the Go fork cmd/ssh3.go over the client modules the
 * interop harness proved -- dial+handshake, the h3 extended CONNECT
 * with the auth header, the session channel and the s3_ssh3_session_cli
 * pump.  One connection carries one interactive or exec session:
 *
 *   ssh3 [options] [user@]host[:port][/path] [command...]
 *
 * with a command the session is the exec request (the fin rides right
 * behind it, the remote stdout/stderr land on the local fds, the
 * exit-status becomes the process exit code); without one the session
 * is pty-req+shell over the console: the raw-mode stdin (the console
 * API twin of the termios branch), UTF-8 code pages, the real window
 * size in the pty-req and the window-change request on the resize.
 * When the stdin is not a console (a pipe), the pty-req rides anyway
 * with the 80x24 default (the RequestTTY=force shape): the C server
 * keeps a bare shell request in the harness echo mode, the pty-req is
 * the wire announcement of the session intent; the pipe pumps through
 * the remote line discipline, the pipe EOF closes the write side
 *
 * the server certificate pins TOFU-style: ~/.ssh3/known_hosts holds
 * "host:port/path x509-certificate <base64 DER>" lines (the Go client
 * format), an exact match connects, a mismatch refuses, an unknown
 * host asks on a console (a non-interactive session refuses, like the
 * reference ask mode)
 *
 * the auth rides the -i PEM key (the Bearer JWT, EdDSA/ES256/RS256)
 * or the -U user:pass (the Basic scheme); the harness kept the
 * test-token default, the product sends no header without an option
 *
 * the client logic is portable (docs/PLAN.md 8.1): the win32 legs keep
 * the console API, the named pipes and WinSock, the unix legs ride the
 * termios tty helpers of s3_ssh3_session_cli, the SIGINT/SIGTERM
 * shutdown flag and the SIGWINCH resize, and the UDS transports of the
 * local agent and the control master
 */

/*
 * the GNU getopt permutation (the [user@]host operand rides after the
 * options, the ssh shape) needs getopt.h: the bare _POSIX_C_SOURCE
 * pin of the build redirects unistd.h to the strict __posix_getopt,
 * which stops at the first non-option (_DEFAULT_SOURCE does not help,
 * the explicit _POSIX_C_SOURCE suppresses the implicit-POSIX path);
 * getopt.h defines _GETOPT_H and the redirect stays off
 */

#if !(S3_WIN32)
#include <getopt.h>
#endif

#if (S3_WIN32)

#include <fcntl.h>
#include <io.h>
#include <process.h>
#include <unistd.h>

#include <ws2tcpip.h>

#include <s3_os_init.h>

#else

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <termios.h>
#include <unistd.h>

#include <netinet/in.h>

/*
 * the unix twins of the winsock names the shared body rides: the raw
 * sockets are ints, the half-close constant and the BSD typedefs hide
 * behind _DEFAULT_SOURCE the build does not set
 */

typedef int            SOCKET;
typedef unsigned int   u_int;
typedef unsigned short u_short;

#define INVALID_SOCKET  (-1)
#define closesocket(fd) close(fd)
#define SD_SEND         SHUT_WR
#define _isatty         isatty

#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <s3_core.h>
#include <s3_h3.h>
#include <s3_h3_uni.h>
#include <s3_nonblocking.h>
#include <s3_quic.h>
#include <s3_quic_connection.h>
#include <s3_quic_output.h>
#include <s3_quic_streams.h>
#include <s3_ssh3_channel.h>
#include <s3_ssh3_agent.h>
#include <s3_ssh3_cm.h>
#include <s3_ssh3_dgram.h>
#include <s3_ssh3_forward.h>
#include <s3_ssh3_message.h>
#include <s3_ssh3_request.h>
#include <s3_ssh3_reverse.h>
#include <s3_ssh3_session_cli.h>
#include <s3_ssh3_sftp_cli.h>
#include <s3_ssh3_version.h>
#include <s3_ssh3_wire.h>
#include <s3_ssl.h>

/*
 * the platform shims of the shared body: the known_hosts label, the
 * raw fd write of the sinks and the control-plane handle (the sync
 * named pipe handle of the win master, the plain fd of the unix one)
 */

#if (S3_WIN32)
#define S3_CLI_KH_LABEL  "%USERPROFILE%\\.ssh3\\known_hosts"
#define S3_CLI_H_INVALID INVALID_HANDLE_VALUE
typedef HANDLE s3_cli_cm_h_t;
#define s3_cli_fd_write _write
#else
#define S3_CLI_KH_LABEL  "~/.ssh3/known_hosts"
#define S3_CLI_H_INVALID (-1)
typedef int s3_cli_cm_h_t;
#define s3_cli_fd_write  write
#endif

/*
 * the channel maxPacketSize of the reference, 30000 on both sides
 * (docs/P4-WIRE.md 5)
 */
#define S3_CLI_CHANNEL_MAX_PACKET 30000

/* the tick of the console pump, the keystroke latency bound */
#define S3_CLI_TICK_MS 30

/* the stdin ring of the reader thread, a power of two */
#define S3_CLI_RING_SIZE 8192
#define S3_CLI_RING_MASK (S3_CLI_RING_SIZE - 1)

/* the parked send tail of the channel (the 94 frames, the sftp shape) */
#define S3_CLI_OUTBOX 33000

/* the CONNECT response accumulator, the status section only */
#define S3_CLI_RESP_MAX 16384

/* the setup deadline after the dial: the handshake, the CONNECT and
 * the channel bring-up must complete inside it, the session itself
 * runs without a deadline (the long exec is legitimate) */
#define S3_CLI_SETUP_TIMEOUT 30000

/* the ssh exit code of the transport failures, the OpenSSH parity */
#define S3_CLI_EXIT_ERROR 255

/* the sftp op failure (the remote refused the transfer), the scp parity */
#define S3_CLI_EXIT_SFTP 1

/* the in-flight 94 frame of the sftp driver direction (the harness
 * shape: one frame below the channel maxPacketSize, a partial send
 * parks its tail) */
#define S3_CLI_SFTP_FRAME 33000

/* the receive accumulator cap of the sftp channel (the driver window
 * is 32 inflight requests, an endless stream is a peer bug) */
#define S3_CLI_SFTP_BUF_MAX (16 << 20)

#define S3_CLI_ES256_HALF 32

/* the fresh window of the Bearer JWT, the reference jwtExpiryMinutes
 * tightened to the session length */
#define S3_CLI_JWT_EXP_FRESH 600

/* the key file cap of the -i loader (the PEM and the OpenSSH armor
 * both, an identity is a few KiB) */
#define S3_CLI_KEY_FILE_MAX (64 * 1024)

/* the OpenSSH private key container magic (PROTOCOL.key of OpenSSH) */
#define S3_CLI_OSSH_MAGIC "openssh-key-v1"

#if (S3_WIN32)

/* the console input flags the raw mode drops and adds */
#ifndef ENABLE_VIRTUAL_TERMINAL_INPUT
#define ENABLE_VIRTUAL_TERMINAL_INPUT 0x0004
#endif
#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif

/*
 * the saved console mode masquerades as the termios state: the tty
 * helper signatures stay the module contract (the header forward
 * declares the struct), the win build completes it locally
 */
struct termios {
    DWORD mode;
};

#endif

enum { S3_CLI_AUTH_NONE = 0, S3_CLI_AUTH_BASIC, S3_CLI_AUTH_PUBKEY };

/* the session state machine of the main loop */

enum {
    S3_CLI_PH_DIAL = 0, /* the handshake in flight */
    S3_CLI_PH_CTRL,     /* the CONNECT in flight */
    S3_CLI_PH_SESSION   /* the channel lives */
};

static s3_log_t           s3_cli_log;
static s3_event_ctx_t     s3_cli_ctx;
static s3_connection_t   *s3_cli_conn; /* the udp connection */
static s3_connection_t   *s3_cli_ctrl; /* the CONNECT stream */
static s3_connection_t   *s3_cli_chan; /* the session channel */
static s3_quic_conf_t     s3_cli_conf;
static uint64_t           s3_cli_conv_id;
/* the dial peer, the family rides -4/-6 (the storage carries the v6
 * form, the socklen follows the family) */
static struct sockaddr_storage s3_cli_sa;
static socklen_t               s3_cli_sa_len;
static unsigned                s3_cli_phase;
static s3_msec_t               s3_cli_deadline;

/* the bring-up facts the main loop acts on */

static unsigned s3_cli_hs_done;
static unsigned s3_cli_req_sent;
static unsigned s3_cli_status_seen;
static unsigned s3_cli_status;
static unsigned s3_cli_ch_sent;
static unsigned s3_cli_verdict;

/* the verdict of the session: the winning 98 exit-status */

static uint64_t s3_cli_exit_code;

/* the options */

static unsigned    s3_cli_auth;
static char        s3_cli_user[128];
static char        s3_cli_host[256];
static unsigned    s3_cli_port;
static char        s3_cli_path[384];    /* the operand path, the default /ssh3-term */
static char        s3_cli_target[640];  /* the CONNECT :path with the ?user= */
static char        s3_cli_hostkey[768]; /* the known_hosts key, host:port/path */
static char        s3_cli_keyfile[1024];
static char        s3_cli_basic[512];
static char        s3_cli_bearer[2048];
static const char *s3_cli_auth_value;
static char       *s3_cli_cmd; /* the joined exec text, NULL = shell */

/*
 * the ssh(1)-canon option states (P8 wave 1): the "have" flags track
 * the explicit command-line sets, the -F config applies only to the
 * unset ones (the CLI wins); the pending note queue carries the
 * deprecated warnings so -q still silences them when it rides after
 * the deprecated flag in the argv
 */

static unsigned s3_cli_have_user;    /* -l, -o User= or the operand user@ */
static unsigned s3_cli_have_port;    /* -p or -o Port= */
static unsigned s3_cli_port_operand; /* the operand carried its own port */
static unsigned s3_cli_have_keyfile; /* -i or -o IdentityFile= */
static unsigned s3_cli_have_escape;  /* -e or -o EscapeChar= */
static unsigned s3_cli_have_strict;  /* -o strict-host-key-checking= */
static unsigned s3_cli_have_master;  /* -M or -o ControlMaster= */
static unsigned s3_cli_have_agent;   /* -A/-X or -o ForwardAgent= */
static unsigned s3_cli_have_jump;    /* -J jump or -o ProxyJump= */
static unsigned s3_cli_vcount;       /* the -v counter (1 info, 2 debug, 3+ all) */
static unsigned s3_cli_quiet;        /* -q seen */
static unsigned s3_cli_level_explicit; /* -v or --log-level seen, quiet yields */

static char s3_cli_login[128]; /* the -l user, the operand wins on a conflict */

/* the escape char of the interactive session, -1 disabled ("none") */

static int s3_cli_escape_ch = '~';

/* the address family of the dial, AF_INET default (the v4 shape of
 * this port, documented), -4 pins it, -6 rides the v6 dial */

static int s3_cli_family = AF_INET;

/* -N holds the forwards without the session channel, -n leaves the
 * stdin unpumped, the pty policy rides -t/-tt/-T (0 auto keeps the
 * stage-A behavior exact) */

static unsigned s3_cli_no_session;
static unsigned s3_cli_no_stdin;

enum {
    S3_CLI_PTY_AUTO = 0, /* the console pty, the pipe 80x24 force */
    S3_CLI_PTY_FORCE,    /* -t: a local tty is required */
    S3_CLI_PTY_FORCE_NOTTY, /* -tt: the pty rides even without a local one */
    S3_CLI_PTY_NEVER     /* -T: no pty-req at all */
};

static unsigned s3_cli_pty_mode;
static unsigned s3_cli_pty_tcount; /* -tt wins over the first -t */

/* the -F config file: NULL = the default path, empty text = disabled
 * (-F none, -F /dev/null) */

static char s3_cli_cfg_path[1024];
static unsigned s3_cli_cfg_off;
static unsigned s3_cli_cfg_explicit; /* the -F file rides, the default one may miss */

/* the subsystem name of -s: only "sftp" is served, the transfer
 * specifier then rides the first positional word */

static unsigned s3_cli_sftp_spec_mode;

/* the pending notes: the deprecated warnings queue here, the end of
 * the parse flushes them unless -q silenced the run */

#define S3_CLI_NOTES_MAX 16

static char *s3_cli_notes[S3_CLI_NOTES_MAX];
static unsigned s3_cli_notes_n;

/* the -J jump spec ([user@]host[:port], one hop) and the tunnel state
 * (the interop shape: the direct-udp channel of the jump conversation
 * bridges the inner datagrams through a loopback socket pair) */

#define S3_CLI_JUMP_INNER_MTU  1200
#define S3_CLI_JUMP_DGRAM_SIZE 1352
#define S3_CLI_JUMP_DGRAM_MIN  1202

static unsigned s3_cli_jump_on;
static char     s3_cli_jump_user[128];
static char     s3_cli_jump_host[256];
static unsigned s3_cli_jump_port; /* 0 asks the 443 default at the resolve */
static char     s3_cli_jump_target[384];
static char     s3_cli_jump_bearer[2048];
static const char *s3_cli_jump_auth; /* the jump CONNECT auth value */

static struct sockaddr_in s3_cli_jump_sa;

static s3_connection_t *s3_cli_jump_cli;    /* the jump udp connection */
static s3_quic_conf_t   s3_cli_jump_conf;
static s3_connection_t *s3_cli_jump_stream; /* the CONNECT stream */
static s3_connection_t *s3_cli_jump_channel;
static uint64_t         s3_cli_jump_conv_id;
static uint64_t         s3_cli_jump_ch_id;
static unsigned         s3_cli_jump_hs;
static unsigned         s3_cli_jump_req_sent;
static unsigned         s3_cli_jump_ch_sent;
static unsigned         s3_cli_jump_ch_confirmed;

/* the receive accumulator of the jump channel (the 91 confirmation) */

static u_char s3_cli_jump_ch_buf[64];
static size_t s3_cli_jump_ch_len;

/* the loopback socket pair: a is the inner quic fd, b is the tunnel
 * side the bridge reads */

static SOCKET            s3_cli_bridge_a = INVALID_SOCKET;
static SOCKET            s3_cli_bridge_b = INVALID_SOCKET;
static s3_connection_t  *s3_cli_bridge_bc;
static struct sockaddr_in s3_cli_bridge_sa;
static u_char            s3_cli_bridge_frame[2048];
static size_t            s3_cli_bridge_parked;

/*
 * the -o options (the backlog 7, the fork keys, case-insensitive):
 * the insecure run accepts any server certificate (the TLS layer
 * rides SSL_VERIFY_NONE already, the TOFU pin store is the check it
 * skips), the strict-host-key-checking picks the unknown-host policy
 * of the TOFU
 */

enum {
    S3_CLI_SHK_ACCEPT_NEW = 0, /* the default TOFU: accept and record */
    S3_CLI_SHK_YES,            /* the unknown host refuses at once */
    S3_CLI_SHK_NO              /* the unknown host accepts, no pin write */
};

static unsigned s3_cli_opt_insecure;
static unsigned s3_cli_opt_strict;

/* the sftp transfer mode of the -J form (the harness shape): the
 * channel type is "sftp", the scp-style driver of s3_ssh3_sftp_cli
 * runs over the 94 payloads, the verdict rides the driver state */

#define S3_CLI_SFTP_NONE 0
#define S3_CLI_SFTP_PUT  1
#define S3_CLI_SFTP_GET  2

static unsigned           s3_cli_sftp_mode;
static char              *s3_cli_sftp_local;
static char              *s3_cli_sftp_remote;
static unsigned           s3_cli_sftp_recursive;
static s3_pool_t         *s3_cli_sftp_pool;
static s3_ssh3_sftp_cli_t s3_cli_sftp;
static unsigned           s3_cli_sftp_started;
static unsigned           s3_cli_sftp_parked; /* the flush parks on the stream window */

/* the in-flight 94 frame (the tail parks, the write event retries) */

static u_char s3_cli_sftp_frame[S3_CLI_SFTP_FRAME];
static size_t s3_cli_sftp_frame_sent;
static size_t s3_cli_sftp_frame_total;

/* the pending driver bytes of the driver direction (the pool of the
 * out accum rides malloc, the transfer lives one session) */

static u_char *s3_cli_sftp_out;
static size_t  s3_cli_sftp_out_cap;
static size_t  s3_cli_sftp_out_len;

/* the receive accumulator of the sftp channel (the 91 and the 94) */

static u_char *s3_cli_sftp_buf;
static size_t  s3_cli_sftp_buf_cap;
static size_t  s3_cli_sftp_buf_len;

/* the 91 confirmation of the sftp channel (the channel reader and
 * the pump gate on it) */

static unsigned s3_cli_ch_confirmed;

/* === the -L forwards (the stage B): the local listeners bridge into
 * the direct-tcp/direct-udp channels of the CONNECT conversation === */

#define S3_CLI_FWD_TCP   1
#define S3_CLI_FWD_UDP   2
#define S3_CLI_FWD_SOCKS 3 /* the -D dynamic forward, the SOCKS listener */

/* the spec and the concurrent shapes the client budget allows */

#define S3_CLI_FWD_MAX         8
#define S3_CLI_FWD_TCP_CONNS   16
#define S3_CLI_FWD_UDP_SRCS    8
#define S3_CLI_FWD_UDP_PENDING 8

/* the in-flight 94 frame of one bridge (the sftp rationale: one
 * frame below the channel maxPacketSize) */

#define S3_CLI_FWD_FRAME 33000

/* the local read chunk and the parked caps of one bridge */

#define S3_CLI_FWD_CHUNK    16384
#define S3_CLI_FWD_PARK_MAX (512 * 1024)

/* the datagram budget: the transport parameter is 1352, the dgram
 * envelope (the two varints) rides on top */

#define S3_CLI_FWD_UDP_DATAGRAM 1200

typedef struct {
    unsigned kind;      /* S3_CLI_FWD_TCP, S3_CLI_FWD_UDP or S3_CLI_FWD_SOCKS */
    unsigned bind_family; /* AF_INET or AF_INET6, the listener socket */
    unsigned bind_addr; /* the network order ipv4 (AF_INET binds) */
    u_char   bind_v6[16];
    unsigned bind_port;
    unsigned target_addr; /* the network order ipv4 of the target */
    unsigned target_port;
    char     text[128]; /* the spec shape of the logs */
} s3_cli_fwd_spec_t;

static s3_cli_fwd_spec_t s3_cli_fwd_specs[S3_CLI_FWD_MAX];
static unsigned          s3_cli_fwd_count;
static unsigned          s3_cli_fwd_ready;

/* one local tcp connection of a tcp forward: the channel opens per
 * accepted socket, both directions park and drain on the tick */

/* the socks handshake states of the -D conn (the bridge arms after
 * the target request answers) */

#define S3_CLI_SOCKS_STEP_GREET 0
#define S3_CLI_SOCKS_STEP_REQ   1
#define S3_CLI_SOCKS_STEP_V4    2

typedef struct {
    unsigned         used;
    unsigned         dead;
    unsigned         spec;
    SOCKET           fd;
    s3_connection_t *evc;      /* the event connection of the fd */
    s3_connection_t *chan;     /* the quic stream, NULL until opened */
    unsigned         hdr_sent; /* the direct-tcp header parks until sent */
    unsigned         confirmed;
    unsigned         chan_fin;      /* the channel fin: the local write closes */
    unsigned         local_eof;     /* the local eof: the fin rides the channel */
    unsigned         chan_fin_sent; /* the fin waits for the park drain */
    u_char           hdr[64];       /* the parked direct-tcp header */
    size_t           hdr_len;
    u_char          *frame; /* the in-flight 94 frame */
    size_t           frame_sent;
    size_t           frame_total;
    u_char          *chan_acc; /* the channel stream accumulator (the 91, the 94) */
    size_t           chan_acc_len;
    size_t           chan_acc_cap;
    u_char          *to_chan; /* the parked channel bytes */
    size_t           to_chan_len;
    size_t           to_chan_cap;
    u_char          *to_local; /* the parked local bytes */
    size_t           to_local_len;
    size_t           to_local_cap;
    /* the -D socks leg: the per-conn handshake state and the per-conn
     * target (the request names it, the spec holds the listener) */
    unsigned socks;
    unsigned socks_step;
    unsigned t_addr;
    unsigned t_port;
    u_char   socks_buf[320];
    size_t   socks_len;
} s3_cli_fwd_tcp_conn_t;

static s3_cli_fwd_tcp_conn_t s3_cli_fwd_conns[S3_CLI_FWD_TCP_CONNS];

static SOCKET s3_cli_fwd_listen[S3_CLI_FWD_MAX]; /* INVALID_SOCKET when free */

/* one udp forward spec: one local socket, one direct-udp channel per
 * source address, the pre-91 datagrams park per source */

typedef struct {
    unsigned           used;
    s3_connection_t   *chan;
    uint64_t           chan_id;
    unsigned           confirmed;
    unsigned           hdr_sent;
    unsigned           pend_head;
    unsigned           pend_count;
    u_short            pend_len[S3_CLI_FWD_UDP_PENDING];
    u_char             pend[S3_CLI_FWD_UDP_PENDING][S3_CLI_FWD_UDP_DATAGRAM];
    struct sockaddr_in src;
    /* the parked direct-udp header (the tick retries it) and the
     * tiny accumulator of the 91 confirmation */
    u_char hdr_park[64];
    size_t hdr_len;
    u_char conf_acc[16];
    size_t conf_len;
} s3_cli_fwd_udp_src_t;

typedef struct {
    unsigned             used;
    SOCKET               fd;
    s3_connection_t     *evc;
    unsigned             src_count;
    s3_cli_fwd_udp_src_t srcs[S3_CLI_FWD_UDP_SRCS];
} s3_cli_fwd_udp_t;

static s3_cli_fwd_udp_t s3_cli_fwd_udp[S3_CLI_FWD_MAX];

/* === the reverse forwards (-R): the control channels of the specs,
 * the server binds the listeners; the server-initiated forwarded-*
 * channels bridge into the local targets (the -N hold shape of the
 * -L run) === */

#define S3_CLI_REV_MAX     16
#define S3_CLI_REV_BRIDGES 16

static s3_ssh3_reverse_spec_t   s3_cli_rspec[S3_CLI_REV_MAX];
static unsigned                 s3_cli_rspec_count;
static unsigned                 s3_cli_rev_ready;
static s3_ssh3_forward_target_t s3_cli_rtarget[S3_CLI_REV_MAX];
static char                     s3_cli_rtarget_text[S3_CLI_REV_MAX][64];

/* the control channel of one spec: the header and the bind request
 * ride one send, the 91 and the reply accumulate */

typedef struct {
    s3_connection_t *sc;
    u_char           frame[512]; /* the header + the bind request */
    size_t           frame_len;
    u_char           acc[512];
    size_t           acc_len;
    unsigned         replied;
    unsigned         ok;
} s3_cli_rev_ctrl_t;

static s3_cli_rev_ctrl_t s3_cli_rev_ctrl[S3_CLI_REV_MAX];

/* the park bound of the bridge buffers (the -L shapes) */

#define S3_CLI_REV_BUF_MAX (256 * 1024)

typedef struct {
    unsigned         used;
    unsigned         kind; /* S3_SSH3_REVERSE_PROTO_TCP or UDP */
    unsigned         spec;
    s3_connection_t *sc;
    uint64_t         ch_id;
    SOCKET           fd;
    unsigned         confirmed;
    unsigned         chan_fin;      /* the channel saw the fin */
    unsigned         local_eof;     /* the socket saw the eof */
    unsigned         chan_fin_sent; /* the channel fin rode once */
    u_char          *acc;           /* the channel payloads awaiting the socket */
    size_t           acc_len;       /* the total bytes (the ready + the tail) */
    size_t           acc_pay;       /* the ready bytes at the acc front */
    size_t           acc_cap;
    u_char          *to_chan; /* the socket bytes awaiting the 94 */
    size_t           to_chan_len;
    size_t           to_chan_cap;
    u_char          *frame; /* the in-flight 94 frame */
    size_t           frame_sent;
    size_t           frame_total;
} s3_cli_rev_bridge_t;

static s3_cli_rev_bridge_t s3_cli_rev_bridge[S3_CLI_REV_BRIDGES];

/*
 * the parked datagrams of the bridges not armed yet: the server
 * forwards the first datagrams while the channel header still parses
 * (the stream and the QUIC datagrams race), the park replays them
 * when the bridge arms
 */

#define S3_CLI_REV_PARK_MAX 16
#define S3_CLI_REV_PARK_DG  1300

typedef struct {
    unsigned used;
    uint64_t ch_id;
    size_t   len;
    u_char   dg[S3_CLI_REV_PARK_DG];
} s3_cli_rev_park_t;

static s3_cli_rev_park_t s3_cli_rev_park[S3_CLI_REV_PARK_MAX];

/* the per-accept header slots: the partial headers of the concurrent
 * server channels keep apart */

#define S3_CLI_REV_ACCEPTS 8

typedef struct {
    unsigned         used;
    s3_connection_t *sc;
    u_char           hdr[128];
    size_t           len;
} s3_cli_rev_acc_t;

static s3_cli_rev_acc_t s3_cli_rev_acc[S3_CLI_REV_ACCEPTS];

/* the ::ffff:0.0.0.0/96 prefix of the v4-mapped v6 form (the wire
 * shape of the fork forwarded-* headers, the net.IP.To16() shape) */

static const u_char s3_cli_rev_v4_mapped_prefix[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};

/* === the agent forwarding (-X) and the ControlMaster (-M/-U/-O,
 * the stage B): the UDS shapes of the reference live on the named
 * pipes of the Windows OpenSSH agent, byte mode, the first
 * instance semantics; the unix legs ride the plain stream sockets
 * (the SSH_AUTH_SOCK of the session, the $TMPDIR control socket) === */

#if (S3_WIN32)
#define S3_CLI_AGENT_PIPE_DEFAULT "\\\\.\\pipe\\openssh-ssh-agent"
#endif

/* the CM pipe cap and the conn shapes (the interop rationale) */

#define S3_CLI_CM_BUF_INIT  4096
#define S3_CLI_CM_FRAME_CAP 33000 /* the 94 frame park, the sftp shape */
#define S3_CLI_CM_TICK_MS   30

/* the in-flight 94 frame of the agent bridge (the tail parks) */

static unsigned s3_cli_agent_mode;
#if (S3_WIN32)
static HANDLE s3_cli_agent_pipe;
#else
static int s3_cli_agent_fd = -1;
#endif
static s3_pool_t       *s3_cli_agent_pool; /* the dial state of the agent module */
static unsigned         s3_cli_agent_bridged;
static s3_connection_t *s3_cli_agent_sc; /* the agent-connection channel */
static u_char           s3_cli_agent_hdr[64];
static size_t           s3_cli_agent_hdr_len;
static u_char          *s3_cli_agent_in; /* the channel bytes to the pipe */
static size_t           s3_cli_agent_in_len;
static size_t           s3_cli_agent_in_cap;
static u_char           s3_cli_agent_frame[S3_CLI_SFTP_FRAME];
static size_t           s3_cli_agent_frame_sent;
static size_t           s3_cli_agent_frame_total;

/* the reply accumulator of the pipe direction (the 94 frames build
 * from it under the channel maxPacketSize) */

static u_char s3_cli_agent_acc[16384];
static size_t s3_cli_agent_acc_len;

/* the channel stream accumulator of the agent bridge (the 91 and
 * the 94 parse before the pipe) */

static u_char *s3_cli_agent_chacc;
static size_t  s3_cli_agent_chacc_len;
static size_t  s3_cli_agent_chacc_cap;

/* the CM master: one control/attach pipe conn each, the shared
 * session table of the codec, one run per slave session */

#define S3_CLI_CM_CMD_MAX 768

enum { S3_CLI_CM_CONN_CONTROL = 0, S3_CLI_CM_CONN_IO = 1, S3_CLI_CM_CONN_STDERR = 2 };

typedef struct s3_cli_cm_conn_s s3_cli_cm_conn_t;
typedef struct s3_cli_cm_run_s  s3_cli_cm_run_t;

struct s3_cli_cm_conn_s {
    unsigned          used;
    unsigned          dead;
    unsigned          close_due; /* the ticks left before the done reply close */
    s3_cli_cm_h_t     h;         /* the connected pipe instance (sync) */
    u_char            rbuf[8192];
    s3_pool_t        *pool;
    s3_ssh3_cm_srv_t  srv;
    unsigned          kind;
    s3_cli_cm_run_t  *run;
    u_char           *out; /* the parked replies between the flushes */
    size_t            out_len;
    size_t            out_cap;
    s3_cli_cm_conn_t *next;
    s3_cli_cm_conn_t *grave_next; /* the dying list of the graveyard sweep */
};

struct s3_cli_cm_run_s {
    u_char            token[S3_SSH3_CM_TOKEN_LEN];
    unsigned          used : 1;
    unsigned          ch_confirmed : 1;
    unsigned          bridged : 1;
    unsigned          finalized : 1;
    unsigned          exit_queued : 1;
    uint64_t          exit_code;
    s3_connection_t  *chan;   /* the ssh3 session channel */
    u_char           *ch_buf; /* the channel parse accumulator */
    size_t            ch_len;
    size_t            ch_cap;
    u_char           *stdin_buf; /* the io bytes awaiting the 94 frames */
    size_t            stdin_len;
    size_t            stdin_cap;
    u_char           *pend_out; /* the session output before the attach */
    size_t            pend_out_len;
    size_t            pend_out_cap;
    u_char           *pend_err; /* the session stderr before the attach */
    size_t            pend_err_len;
    size_t            pend_err_cap;
    unsigned          pend_due_out : 1; /* the flush waits out the reply read */
    unsigned          pend_due_err : 1;
    unsigned          close_lag : 1; /* the conns close one tick after the drain */
    u_char            frame[S3_CLI_CM_FRAME_CAP];
    size_t            frame_sent;
    size_t            frame_total;
    s3_cli_cm_conn_t *control;
    s3_cli_cm_conn_t *io;
    s3_cli_cm_conn_t *err;
};

static unsigned              s3_cli_cm_master;
static char                  s3_cli_cm_path[256]; /* the pipe name */
static const char           *s3_cli_cm_op;        /* the -O op, NULL */
static char                 *s3_cli_cm_exec;      /* the -e command of the slave */
static s3_ssh3_cm_sessions_t s3_cli_cm_table;
static s3_cli_cm_run_t       s3_cli_cm_runs[S3_SSH3_CM_SRV_SESSIONS];
static s3_cli_cm_conn_t     *s3_cli_cm_conns;
static s3_cli_cm_conn_t     *s3_cli_cm_graveyard; /* the dying conns, the pools die on the tick */
static s3_cli_cm_conn_t     *s3_cli_cm_cur;       /* the conn whose srv_input runs */

/* the listening transport: the blocking ConnectNamedPipe lives in its
 * own accept thread on win (the sync server shape of the reference
 * mux, the tick drains the accepted handles); the unix master accepts
 * on the event loop and pumps the conns on the tick - the conn io is
 * the poll/read/write of the wrappers below in both shapes.  The
 * overlapped shape proved flaky across the mingw builds here */

#if (S3_WIN32)

#define S3_CLI_CM_ACC_QUEUE 8

static HANDLE           s3_cli_cm_listen_h; /* the thread sets, the teardown closes */
static HANDLE           s3_cli_cm_acc_thread;
static volatile LONG    s3_cli_cm_acc_run;    /* the thread lifetime flag */
static HANDLE           s3_cli_cm_acc_armed;  /* the first instance is up */
static volatile LONG    s3_cli_cm_acc_failed; /* the create error, the master refuses */
static HANDLE           s3_cli_cm_acc_queue[S3_CLI_CM_ACC_QUEUE];
static LONG             s3_cli_cm_acc_head;
static LONG             s3_cli_cm_acc_tail;
static CRITICAL_SECTION s3_cli_cm_acc_cs;
static unsigned         s3_cli_cm_acc_cs_init;

#else

static int              s3_cli_cm_listen_fd = -1; /* the accepted-on-event socket */
static s3_connection_t *s3_cli_cm_listen_c;

#endif

static unsigned  s3_cli_cm_listening;
static unsigned  s3_cli_cm_stop;
static unsigned  s3_cli_cm_stop_lag; /* the verdict waits the stop reply */
static unsigned  s3_cli_cm_pipe_name_called;
static s3_msec_t s3_cli_cm_started_ms;
static s3_msec_t s3_cli_cm_activity;

/* the slave and the control op: the sequential Call client over the
 * sync pipe handle, no quic state */

/* the h3 response side (the :status section, the ctrl read handler) */

static s3_h3_parse_headers_t s3_cli_h3parse;
static u_char                s3_cli_resp[S3_CLI_RESP_MAX];
static size_t                s3_cli_resp_len;

/* the session pump */

static s3_ssh3_session_cli_t s3_cli_sess;
static unsigned              s3_cli_closed; /* the channel fin seen */

/* the parked channel send (the stdin and window-change frames) */

static u_char s3_cli_outbox[S3_CLI_OUTBOX];
static size_t s3_cli_outbox_sent;
static size_t s3_cli_outbox_len;

/* the console side: the raw mode, the reader thread and the ring of
 * win (the console read is not selectable), the event-driven stdin of
 * unix; the pipe mode shares the eof flag */

#if (S3_WIN32)
static HANDLE s3_cli_in_h;
static HANDLE s3_cli_out_h;
static DWORD  s3_cli_in_saved;

static CRITICAL_SECTION s3_cli_ring_cs;
static u_char           s3_cli_ring[S3_CLI_RING_SIZE];
static size_t           s3_cli_ring_head;
static size_t           s3_cli_ring_tail;
static uintptr_t        s3_cli_thread;
#endif

static unsigned s3_cli_console; /* the stdin is a console */
static unsigned s3_cli_raw;     /* the raw mode is on */
static unsigned s3_cli_tty;     /* the pty was requested (a console) */

#if (S3_WIN32)
static unsigned s3_cli_stdin_eof;
static unsigned s3_cli_fin_sent;
static unsigned s3_cli_stop;
#else
static struct termios        s3_cli_saved_termios; /* the raw mode undoes */
static volatile sig_atomic_t s3_cli_winch;         /* SIGWINCH seen, the tick resizes */
static volatile sig_atomic_t s3_cli_stdin_eof;
static unsigned              s3_cli_fin_sent;
static volatile sig_atomic_t s3_cli_stop;
#endif

static uint64_t    s3_cli_win_w;
static uint64_t    s3_cli_win_h;
static s3_event_t *s3_cli_tick;

static unsigned s3_cli_rc;

static void     s3_cli_usage(const char *prog);
static unsigned s3_cli_escape_live(void);
static void      s3_cli_note(const char *fmt, ...);
static void      s3_cli_notes_flush(void);
static char     *s3_cli_join_words(char **argv, size_t first, size_t argc);
static s3_int_t  s3_cli_sftp_spec_parse(const char *rest);
static s3_int_t  s3_cli_jump_parse(const char *spec);
static s3_int_t  s3_cli_escape_parse(const char *arg);
static size_t    s3_cli_escape_feed(const u_char *src, size_t n, u_char *dst);
static void      s3_cli_escape_list_forwards(void);
static void      s3_cli_escape_suspend(void);
static void      s3_cli_escape_drop(void);
static s3_int_t  s3_cli_cfg_load(const char *host);
static s3_int_t  s3_cli_fwd_parse(const char *arg);
static s3_int_t  s3_cli_fwd_bind_parse(const char *host, size_t len, s3_cli_fwd_spec_t *spec);
static s3_int_t  s3_cli_socks_parse(const char *arg);
static int       s3_cli_streq_ci(const char *a, const char *b);
static void      s3_cli_note(const char *fmt, ...);
static unsigned  s3_cli_escape_live(void);
static s3_int_t  s3_cli_cfg_pattern_match(const char *pat, const char *host);
static unsigned  s3_cli_cfg_host_block(const char *patterns, const char *host);
static s3_int_t  s3_cli_cfg_apply(const char *key, const char *val);
static void      s3_cli_b64std(const u_char *src, size_t len, char *dst);
static void      s3_cli_b64url(const u_char *src, size_t len, char *dst);
static size_t    s3_cli_b64dec(const char *src, u_char *dst, size_t cap);
static void      s3_cli_sha256_fp(const u_char *der, size_t len, char *fp);
static s3_int_t  s3_cli_jwt_sign(EVP_PKEY *key, const char *alg, const u_char *msg, size_t msglen,
                                 u_char *sig, size_t *siglen);
static s3_int_t  s3_cli_ssh_u32(const u_char **pos, const u_char *end, uint32_t *val);
static s3_int_t  s3_cli_ssh_string(const u_char **pos, const u_char *end, s3_str_t *out);
static EVP_PKEY *s3_cli_ossh_ed25519(const u_char **pos, const u_char *end);
static EVP_PKEY *s3_cli_ossh_ec256(const u_char **pos, const u_char *end);
static EVP_PKEY *s3_cli_ossh_rsa(const u_char **pos, const u_char *end);
static EVP_PKEY *s3_cli_openssh_key(const char *buf);
static s3_int_t  s3_cli_jwt_build(SSL *ssl);
static uintptr_t s3_cli_h3_field_l(u_char *p, const char *name, const char *value);
static size_t    s3_cli_h3_section(u_char *p);
static s3_int_t  s3_cli_tofu_prepare(void);
static s3_int_t  s3_cli_cert_check(void);
static s3_int_t  s3_cli_opt_parse(const char *arg);
static u_char   *s3_cli_session_request(u_char *p, s3_ssh3_request_kind_t kind, unsigned want_reply,
                                        const s3_ssh3_request_t *body);
static void      s3_cli_chan_park(const u_char *buf, size_t len);
static void      s3_cli_outbox_flush(void);
static void      s3_cli_out_sink(void *arg, const s3_str_t *data);
static void      s3_cli_err_sink(void *arg, const s3_str_t *data);
static void      s3_cli_exit_cb(void *arg, uint64_t code);
static void      s3_cli_chan_read(s3_event_t *ev);
static void      s3_cli_ctrl_read(s3_event_t *ev);
static void      s3_cli_client_stream(s3_connection_t *c, s3_quic_stream_t *qs);
static void      s3_cli_datagram(s3_connection_t *c, s3_chain_t *data);
static s3_int_t  s3_cli_console_init(void);
static void      s3_cli_console_done(void);
static s3_int_t  s3_cli_console_winsize(uint64_t *width, uint64_t *height);
static s3_int_t  s3_cli_kh_path(char *buf, size_t cap);
static s3_int_t  s3_cli_kh_append(const char *kh_path, const char *body);
static const char *s3_cli_agent_open(void);
static void        s3_cli_msleep(unsigned ms);
static s3_int_t    s3_cli_net_init(void);
static void        s3_cli_net_cleanup(void);
static unsigned    s3_cli_pid(void);
#if (S3_WIN32)
static unsigned __stdcall s3_cli_reader(void *arg);
#else
static void s3_cli_stdin_read(s3_event_t *ev);
#endif
static void     s3_cli_tick_handler(s3_event_t *ev);
static void     s3_cli_teardown(void);
static void     s3_cli_tick_arm(void);
static s3_int_t s3_cli_sftp_append(const u_char *data, size_t n);
static void     s3_cli_sftp_finish(void);
static void     s3_cli_sftp_pump(void);
static void     s3_cli_sftp_write(s3_event_t *ev);
static void     s3_cli_sftp_start(void);
static void     s3_cli_sftp_read(s3_event_t *ev);
static s3_int_t s3_cli_fwd_parse(const char *arg);
static s3_int_t s3_cli_fwd_listeners_start(void);
static void     s3_cli_fwd_tcp_accept(s3_event_t *ev);
static void     s3_cli_fwd_socks_accept(s3_event_t *ev);
static void     s3_cli_fwd_socks_local_read(s3_event_t *ev);
static s3_int_t s3_cli_fwd_conn_open(s3_cli_fwd_tcp_conn_t *fc, unsigned t_addr, unsigned t_port);
static void     s3_cli_fwd_tcp_local_read(s3_event_t *ev);
static void     s3_cli_fwd_tcp_chan_read(s3_event_t *ev);
static void     s3_cli_fwd_tcp_flush(s3_cli_fwd_tcp_conn_t *fc);
static void     s3_cli_fwd_tcp_drop(s3_cli_fwd_tcp_conn_t *fc);
static void     s3_cli_fwd_udp_local_read(s3_event_t *ev);
static void     s3_cli_fwd_udp_chan_read(s3_event_t *ev);
static void     s3_cli_fwd_udp_pump(s3_cli_fwd_udp_t *uf);
static void     s3_cli_fwd_datagram(s3_chain_t *data);
static void     s3_cli_fwd_tick(void);
static s3_int_t s3_cli_rev_parse_spec(const char *arg);
static s3_int_t s3_cli_rev_open_pending(void);
static void     s3_cli_rev_accept(s3_connection_t *c);
static void     s3_cli_rev_accept_read(s3_event_t *ev);
static void     s3_cli_rev_stream_read(s3_event_t *ev);
static void     s3_cli_rev_ctrl_read(s3_event_t *ev);
static void     s3_cli_rev_pump(void);
static unsigned s3_cli_rev_datagram(s3_chain_t *data);
static void     s3_cli_rev_teardown(unsigned quic_alive);
static void     s3_cli_finalize(s3_connection_t *c);
static void     s3_cli_agent_accept(s3_connection_t *c);
static void     s3_cli_agent_read(s3_event_t *ev);
static void     s3_cli_agent_teardown(const char *why);
static void     s3_cli_agent_pump(void);
static void     s3_cli_jump_datagram(s3_connection_t *c, s3_chain_t *data);
static void     s3_cli_jump_bridge_read(s3_event_t *ev);
static void     s3_cli_jump_bridge_flush(void);
static s3_int_t s3_cli_jump_bridge_create(s3_event_ctx_t *ctx);
static void     s3_cli_jump_ch_read(s3_event_t *ev);
static size_t   s3_cli_jump_h3_section(u_char *p);
static s3_int_t s3_cli_jwt_build_user(SSL *ssl, const char *user, char *out, size_t cap);
static s3_int_t s3_cli_jump_dial(s3_event_ctx_t *ctx, s3_msec_t start, s3_msec_t timeout);
#if (S3_WIN32)
static void s3_cli_cm_acc_push(HANDLE h);
static unsigned __stdcall s3_cli_cm_accept_thread(void *arg);
#else
static void s3_cli_cm_accept_ev(s3_event_t *ev);
#endif
static void     s3_cli_cm_listen_open(void);
static void     s3_cli_cm_accepts_drain(void);
static void     s3_cli_cm_acc_thread_stop(void);
static int      s3_cli_cm_h_poll(s3_cli_cm_h_t h);
static ssize_t  s3_cli_cm_h_read(s3_cli_cm_h_t h, u_char *buf, size_t cap);
static ssize_t  s3_cli_cm_h_write(s3_cli_cm_h_t h, const u_char *data, size_t n);
static void     s3_cli_cm_h_close(s3_cli_cm_h_t h);
static unsigned s3_cli_cm_h_valid(s3_cli_cm_h_t h);
static void     s3_cli_cm_conn_new(s3_cli_cm_h_t h);
static void     s3_cli_cm_conn_feed(s3_cli_cm_conn_t *conn, const u_char *data, size_t n);
static void     s3_cli_cm_conn_flush(s3_cli_cm_conn_t *conn);
static void     s3_cli_cm_conn_send(s3_cli_cm_conn_t *conn, const u_char *data, size_t n);
static void     s3_cli_cm_conn_close(s3_cli_cm_conn_t *conn);
static void     s3_cli_cm_run_finalize(s3_cli_cm_run_t *run, uint64_t code);
static void s3_cli_cm_run_pend(s3_cli_cm_run_t *run, unsigned err, const u_char *data, size_t n);
static void s3_cli_cm_run_pend_flush(s3_cli_cm_run_t *run, unsigned err);
static void s3_cli_cm_run_stdin(s3_cli_cm_run_t *run, const u_char *data, size_t len);
static void s3_cli_cm_run_send_exit(s3_cli_cm_run_t *run, uint64_t code);
static void s3_cli_cm_shutdown(void);
static void s3_cli_cm_tick(void);
static int  s3_cli_cm_slave_run(void);
static int  s3_cli_cm_control_op(void);

/*
 * the usage: the stage-A option set (the keys the Go fork shares,
 * -i, -U, -v) plus the stage-B session shapes; the log level moved
 * to -l (the stage-B contract puts -L on the local forwards)
 */

static void
s3_cli_usage(const char *prog)
{
    fprintf(stderr,
            "usage: %s [options] [user@]host[:port][/path] [command...]\n"
            "\n the ssh(1) canon:\n"
            "  -4 | -6     the address family of the dial (the v4 default)\n"
            "  -A          the agent forwarding: the server-initiated\n"
            "              agent-connection channels bridge into the local agent\n"
#if (S3_WIN32)
            "              pipe (SSH_AUTH_SOCK when it names a pipe, the OpenSSH\n"
            "              for Windows agent pipe otherwise)\n"
#else
            "              socket (the SSH_AUTH_SOCK of the session)\n"
#endif
            "  -D [bind:]port  the dynamic (SOCKS5, SOCKS4 fallback) forward:\n"
            "              the local listener answers the CONNECT requests and\n"
            "              bridges every target into a direct-tcp channel\n"
            "              (repeatable, the bind defaults to 127.0.0.1)\n"
            "  -e char     the escape character of the interactive session\n"
            "              (the default ~, ^x is the control code, none is off;\n"
            "              at a line start: . drops, ^Z suspends, # lists the\n"
            "              forwards, V version, ? help, ~~ rides literal)\n"
            "  -F file     the ssh_config (the default ~/.ssh/config reads\n"
            "              when it exists; none or /dev/null disables; the\n"
            "              keys: HostName, Port, User, IdentityFile,\n"
            "              ForwardAgent, LocalForward, RemoteForward,\n"
            "              DynamicForward, ProxyJump, EscapeChar,\n"
            "              StrictHostKeyChecking, ControlMaster, ControlPath,\n"
            "              ControlPersist)\n"
            "  -i keyfile  pubkey auth: sign the Bearer JWT with the PEM private\n"
            "              key (ed25519, P-256 or RSA)\n"
            "  -J [user@]host[:port]  the proxy jump (one hop, the comma chain\n"
            "              refuses)\n"
            "  -l login    the login name (the operand user wins on a conflict)\n"
            "  -L [bind:]port:host:hostport  the local tcp forward: every\n"
            "              accepted connection rides a direct-tcp channel of\n"
            "              the same conversation to the target (repeatable,\n"
            "              the bind defaults to 127.0.0.1, the bracketed ipv6\n"
            "              bind rides)\n"
            "  -M          the control master: the control socket serves the\n"
            "              slaves and the ops, the sessions ride the same\n"
            "              connection\n"
            "  -n          the stdin stays /dev/null (no pump)\n"
            "  -N          no session, the forwards hold the run\n"
            "  -O check|stop|exit  the control op against the -S master\n"
            "  -p port     the port of the target (the default 443)\n"
            "  -q          quiet: the errors only\n"
            "  -R [bind:]port[/tcp|/udp]:host:port  the reverse forward: the\n"
            "              server binds the port and mirrors every accepted\n"
            "              connection or datagram back into the client-side\n"
            "              target (repeatable, the ephemeral 0 asks the\n"
            "              server-chosen port, the run holds like -L)\n"
            "  -s subsystem  only sftp is served: the put|get:local:remote\n"
            "              specifier rides the first word after the operand\n"
            "  -S path     the control master socket (the master, the slave\n"
            "              and the ops; the slave command rides the positional\n"
            "              words: %s -S path [words...])\n"
            "  -t | -tt    force the pty (-tt even without a local tty)\n"
            "  -T          never request the pty\n"
            "  -V          version\n"
            "  -h          this help\n"
            "  -v          verbose (repeatable: -vv debug, -vvv everything)\n"
            "  -o Key=Value  the client option (repeatable, case-insensitive):\n"
            "              insecure, strict-host-key-checking, forwardagent,\n"
            "              port, user, identityfile, localforward,\n"
            "              remoteforward, dynamicforward, proxyjump,\n"
            "              escapechar, controlmaster, controlpath,\n"
            "              controlpersist; the unknown key refuses with the\n"
            "              list (exit 255)\n"
            "  -x | -Y     accepted, ignored (no X11)\n"
            "\n the deprecated aliases (the legacy shapes ride):\n"
            "  -X          the agent forwarding (use -A)\n"
            "  -J put|get:local:remote  the sftp transfer (use --sftp)\n"
            "  -U path     the control master socket (use -S)\n"
            "  -L tcp://[bind:]port/host/port  the legacy local forward\n"
            "              (use -L port:host:hostport)\n"
            "\n the project extensions (no ssh2 twin):\n"
            "  -L udp://[bind:]port/host/port  the local udp forward over the\n"
            "              datagrams\n"
            "  -R ...[/tcp|/udp]  the reverse protocol infix (the tcp default)\n"
            "  -U user:pass  the Basic auth (RFC 7617), the ?user= of the\n"
            "              target (the HTTP spec keeps its own head)\n"
            "  -r          with the transfers: the recursive tree\n"
            "  --log-level 0..9|all  the s3 log level\n"
            "  --sftp put|get:local:remote  the transfer (get: local first)\n"
            "  --help      this help\n"
            "  -C          accepted, ignored (no compression)\n"
            " no command opens an interactive shell (pty on a console, the\n"
            " stdin pipe pumps without one), a command runs exec; the server\n"
            " certificate pins into %s\n",
            prog, prog, S3_CLI_KH_LABEL);
}

/*
 * the standard base64 of RFC 4648 with padding (the Basic scheme, the
 * known_hosts DER)
 */

static void
s3_cli_b64std(const u_char *src, size_t len, char *dst)
{
    static const char tab[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                "abcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t            i, o = 0;

    for (i = 0; i + 3 <= len; i += 3) {
        unsigned v = ((unsigned)src[i] << 16) | ((unsigned)src[i + 1] << 8) | src[i + 2];

        dst[o++] = tab[(v >> 18) & 0x3f];
        dst[o++] = tab[(v >> 12) & 0x3f];
        dst[o++] = tab[(v >> 6) & 0x3f];
        dst[o++] = tab[v & 0x3f];
    }

    if (len - i == 1) {
        unsigned v = (unsigned)src[i] << 16;

        dst[o++] = tab[(v >> 18) & 0x3f];
        dst[o++] = tab[(v >> 12) & 0x3f];
        dst[o++] = '=';
        dst[o++] = '=';

    } else if (len - i == 2) {
        unsigned v = ((unsigned)src[i] << 16) | ((unsigned)src[i + 1] << 8);

        dst[o++] = tab[(v >> 18) & 0x3f];
        dst[o++] = tab[(v >> 12) & 0x3f];
        dst[o++] = tab[(v >> 6) & 0x3f];
        dst[o++] = '=';
    }

    dst[o] = '\0';
}

/* the unpadded base64url of the JWT segments (RFC 7515) */

static void
s3_cli_b64url(const u_char *src, size_t len, char *dst)
{
    static const char tab[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                "abcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t            i, o = 0;

    for (i = 0; i + 3 <= len; i += 3) {
        unsigned v = ((unsigned)src[i] << 16) | ((unsigned)src[i + 1] << 8) | src[i + 2];

        dst[o++] = tab[(v >> 18) & 0x3f];
        dst[o++] = tab[(v >> 12) & 0x3f];
        dst[o++] = tab[(v >> 6) & 0x3f];
        dst[o++] = tab[v & 0x3f];
    }

    if (len - i == 1) {
        unsigned v = (unsigned)src[i] << 16;

        dst[o++] = tab[(v >> 18) & 0x3f];
        dst[o++] = tab[(v >> 12) & 0x3f];

    } else if (len - i == 2) {
        unsigned v = ((unsigned)src[i] << 16) | ((unsigned)src[i + 1] << 8);

        dst[o++] = tab[(v >> 18) & 0x3f];
        dst[o++] = tab[(v >> 12) & 0x3f];
        dst[o++] = tab[(v >> 6) & 0x3f];
    }

    dst[o] = '\0';
}

/*
 * the strict std base64 decode of the pins (RFC 4648): a wrong byte
 * or an overrun ends the decode, the answer is the bytes decoded so
 * far (the caller compares the length first)
 */

static size_t
s3_cli_b64dec(const char *src, u_char *dst, size_t cap)
{
    unsigned carry = 0;
    size_t   i, o = 0, n = strlen(src);

    for (i = 0; i < n; i++) {

        char     c = src[i];
        unsigned v;

        if (c >= 'A' && c <= 'Z') {
            v = (unsigned)(c - 'A');

        } else if (c >= 'a' && c <= 'z') {
            v = (unsigned)(c - 'a') + 26;

        } else if (c >= '0' && c <= '9') {
            v = (unsigned)(c - '0') + 52;

        } else if (c == '+') {
            v = 62;

        } else if (c == '/') {
            v = 63;

        } else if (c == '=') {
            break;

        } else {
            return 0;
        }

        carry = (carry << 6) | v;

        switch (i % 4) {

        case 0:
            /* the first sextet parks in the carry */
            break;

        case 1:
            if (o >= cap) {
                return 0;
            }

            dst[o++] = (u_char)((carry >> 4) & 0xff);
            carry &= 0xf;
            break;

        case 2:
            if (o >= cap) {
                return 0;
            }

            dst[o++] = (u_char)((carry >> 2) & 0xff);
            carry &= 0x3;
            break;

        default:
            if (o >= cap) {
                return 0;
            }

            dst[o++] = (u_char)(carry & 0xff);
            carry = 0;
            break;
        }
    }

    return o;
}

/* the OpenSSH-shape fingerprint, "SHA256:" + the unpadded base64 */

static void
s3_cli_sha256_fp(const u_char *der, size_t len, char *fp)
{
    u_char md[EVP_MAX_MD_SIZE];
    u_int  mdlen = 0;

    if (EVP_Digest(der, len, md, &mdlen, EVP_sha256(), NULL) != 1) {
        fp[0] = '\0';

        return;
    }

    memcpy(fp, "SHA256:", sizeof("SHA256:") - 1);
    s3_cli_b64url(md, mdlen, fp + sizeof("SHA256:") - 1);
}

/* === the platform primitives of the shared body: the net bootstrap,
 * the signal flags, the sleep and the pid of the sequential paths and
 * the known_helpers of the pin store === */

#if (S3_WIN32)

static s3_int_t
s3_cli_net_init(void)
{
    WSADATA wsd;

    if (WSAStartup(MAKEWORD(2, 2), &wsd) != 0) {
        fprintf(stderr, "ssh3: WSAStartup failed\n");
        return S3_ERROR;
    }

    return S3_OK;
}

static void
s3_cli_net_cleanup(void)
{
    WSACleanup();
}

static unsigned
s3_cli_pid(void)
{
    return (unsigned)GetCurrentProcessId();
}

static void
s3_cli_msleep(unsigned ms)
{
    Sleep(ms);
}

/*
 * the known_hosts path of the pin store: the profile home and the
 * backslash separators of the windows shape
 */

static s3_int_t
s3_cli_kh_path(char *buf, size_t cap)
{
    const char *home = getenv("USERPROFILE");

    if (home == NULL || home[0] == '\0') {
        return S3_ERROR;
    }

    snprintf(buf, cap, "%s\\.ssh3\\known_hosts", home);

    return S3_OK;
}

/* the pin appends, the .ssh3 dir creates on demand */

static s3_int_t
s3_cli_kh_append(const char *kh_path, const char *body)
{
    HANDLE kh;
    char   line[17408];
    int    len;
    DWORD  put = 0;

    {
        char        dir[1024];
        const char *slash = strrchr(kh_path, '\\');
        size_t      dlen = (size_t)(slash - kh_path);

        if (slash == NULL || dlen >= sizeof(dir)) {
            return S3_ERROR;
        }

        memcpy(dir, kh_path, dlen);
        dir[dlen] = '\0';

        CreateDirectoryA(dir, NULL);
    }

    kh = CreateFileA(kh_path, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS,
                     FILE_ATTRIBUTE_NORMAL, NULL);

    if (kh == INVALID_HANDLE_VALUE) {
        return S3_ERROR;
    }

    len = snprintf(line, sizeof(line), "%s\r\n", body);

    if (len < 0 || (size_t)len >= sizeof(line) || !WriteFile(kh, line, (DWORD)len, &put, NULL) ||
        put != (DWORD)len) {
        CloseHandle(kh);
        return S3_ERROR;
    }

    CloseHandle(kh);

    return S3_OK;
}

#else

static void
s3_cli_sig_stop(int sig)
{
    (void)sig;

    /* the async-signal-safe flag raise: the tick and the sequential
     * loops watch it, the teardown does the work (the server shape) */

    s3_cli_stop = 1;
}

static void
s3_cli_sig_winch(int sig)
{
    (void)sig;

    s3_cli_winch = 1;
}

static s3_int_t
s3_cli_net_init(void)
{
    struct sigaction act;

    /* the writes of the teardown must not die on the half-closed
     * sockets, the flags raise the shutdown and the resize */

    (void)signal(SIGPIPE, SIG_IGN);

    s3_memzero(&act, sizeof(act));

    act.sa_handler = s3_cli_sig_stop;

    if (sigaction(SIGINT, &act, NULL) == -1 || sigaction(SIGTERM, &act, NULL) == -1) {
        return S3_ERROR;
    }

    act.sa_handler = s3_cli_sig_winch;

    if (sigaction(SIGWINCH, &act, NULL) == -1) {
        return S3_ERROR;
    }

    return S3_OK;
}

static void
s3_cli_net_cleanup(void)
{
}

static unsigned
s3_cli_pid(void)
{
    return (unsigned)getpid();
}

static void
s3_cli_msleep(unsigned ms)
{
    struct timespec ts;

    ts.tv_sec = (time_t)(ms / 1000);
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;

    (void)nanosleep(&ts, NULL);
}

/*
 * the known_hosts path of the pin store: the home and the slash
 * separators of the unix shape
 */

static s3_int_t
s3_cli_kh_path(char *buf, size_t cap)
{
    const char *home = getenv("HOME");

    if (home == NULL || home[0] == '\0') {
        return S3_ERROR;
    }

    snprintf(buf, cap, "%s/.ssh3/known_hosts", home);

    return S3_OK;
}

/* the pin appends, the .ssh3 dir creates on demand (the owner only) */

static s3_int_t
s3_cli_kh_append(const char *kh_path, const char *body)
{
    char        line[17408];
    int         fd, len;
    char        dir[1024];
    const char *slash = strrchr(kh_path, '/');
    size_t      dlen = slash != NULL ? (size_t)(slash - kh_path) : 0;

    if (dlen > 0 && dlen < sizeof(dir)) {

        memcpy(dir, kh_path, dlen);
        dir[dlen] = '\0';

        (void)mkdir(dir, 0700);
    }

    fd = open(kh_path, O_WRONLY | O_CREAT | O_APPEND, 0600);

    if (fd < 0) {
        return S3_ERROR;
    }

    len = snprintf(line, sizeof(line), "%s\n", body);

    if (len < 0 || (size_t)len >= sizeof(line) || write(fd, line, (size_t)len) != (ssize_t)len) {
        close(fd);
        return S3_ERROR;
    }

    close(fd);

    return S3_OK;
}

#endif

/*
 * the signature over the signing input, the key type decides the
 * shape (the port of the harness s3_interop_jwt_sign): the ed25519
 * signs PureEdDSA one-shot, the P-256 signs ECDSA-SHA256 into the raw
 * r||s pair the server verifier expects, the RSA signs
 * RSASSA-PKCS1-v1_5-SHA256
 */

static s3_int_t
s3_cli_jwt_sign(EVP_PKEY *key, const char *alg, const u_char *msg, size_t msglen, u_char *sig,
                size_t *siglen)
{
    EVP_MD_CTX *md;
    s3_int_t    rc = S3_ERROR;

    md = EVP_MD_CTX_new();

    if (md == NULL) {
        return S3_ERROR;
    }

    if (strcmp(alg, "EdDSA") == 0) {

        if (EVP_DigestSignInit(md, NULL, NULL, NULL, key) != 1) {
            goto done;
        }

    } else {

        if (EVP_DigestSignInit(md, NULL, EVP_sha256(), NULL, key) != 1) {
            goto done;
        }
    }

    if (EVP_DigestSign(md, sig, siglen, msg, msglen) != 1) {
        goto done;
    }

    if (strcmp(alg, "ES256") == 0) {

        /* the DER ECDSA-SIG comes back, the verifier wants r||s */

        const unsigned char *der = sig;
        ECDSA_SIG           *ec = d2i_ECDSA_SIG(NULL, &der, (long)*siglen);
        const BIGNUM        *r, *s;

        if (ec == NULL) {
            goto done;
        }

        ECDSA_SIG_get0(ec, &r, &s);

        if (BN_bn2binpad(r, sig, S3_CLI_ES256_HALF) != S3_CLI_ES256_HALF ||
            BN_bn2binpad(s, sig + S3_CLI_ES256_HALF, S3_CLI_ES256_HALF) != S3_CLI_ES256_HALF) {
            ECDSA_SIG_free(ec);
            goto done;
        }

        ECDSA_SIG_free(ec);
        *siglen = 2 * S3_CLI_ES256_HALF;
    }

    rc = S3_OK;

done:

    EVP_MD_CTX_free(md);

    return rc;
}

/* the ssh wire primitives of the openssh container walk: the
 * big-endian uint32 and the length-prefixed string as a view over the
 * decode buffer (no intermediate allocations) */

static s3_int_t
s3_cli_ssh_u32(const u_char **pos, const u_char *end, uint32_t *val)
{
    if (end - *pos < 4) {
        return S3_ERROR;
    }

    *val = ((uint32_t)(*pos)[0] << 24) | ((uint32_t)(*pos)[1] << 16) | ((uint32_t)(*pos)[2] << 8) |
           (uint32_t)(*pos)[3];

    *pos += 4;

    return S3_OK;
}

static s3_int_t
s3_cli_ssh_string(const u_char **pos, const u_char *end, s3_str_t *out)
{
    uint32_t len;

    if (s3_cli_ssh_u32(pos, end, &len) != S3_OK || (size_t)(end - *pos) < len) {
        return S3_ERROR;
    }

    out->data = (u_char *)*pos;
    out->len = len;

    *pos += len;

    return S3_OK;
}

/* the ssh-ed25519 privkey: the 64-byte blob of seed||pub, the seed
 * rides the first half */

static EVP_PKEY *
s3_cli_ossh_ed25519(const u_char **pos, const u_char *end)
{
    s3_str_t pub, priv;

    if (s3_cli_ssh_string(pos, end, &pub) != S3_OK || s3_cli_ssh_string(pos, end, &priv) != S3_OK ||
        priv.len != 64) {
        return NULL;
    }

    return EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, priv.data, 32);
}

/*
 * the ecdsa-sha2-nistp256 privkey: string "nistp256", string point
 * (the 0x04 uncompressed form), mpint scalar, into the provider key
 * (the s3_ssh3_jwt_key_ec256 shape plus the private param); the param
 * builder takes the scalar, the plain construct_BN drops the private
 * half when the wire mpint carries its sign guard byte
 */

static EVP_PKEY *
s3_cli_ossh_ec256(const u_char **pos, const u_char *end)
{
    static s3_str_t curve = s3_string("nistp256");

    OSSL_PARAM_BLD *bld;
    OSSL_PARAM     *params = NULL;
    EVP_PKEY_CTX   *ctx;
    EVP_PKEY       *key = NULL;
    BIGNUM         *d = NULL;
    s3_str_t        name, q, priv;

    if (s3_cli_ssh_string(pos, end, &name) != S3_OK || name.len != curve.len ||
        s3_memcmp(name.data, curve.data, curve.len) != 0 ||
        s3_cli_ssh_string(pos, end, &q) != S3_OK || q.len == 0 || q.data[0] != 0x04 ||
        s3_cli_ssh_string(pos, end, &priv) != S3_OK || priv.len == 0 || priv.len > 66) {
        return NULL;
    }

    /* the mpint sign guard byte rides out with the BIGNUM convert */

    d = BN_bin2bn(priv.data, (int)priv.len, NULL);

    if (d == NULL) {
        return NULL;
    }

    bld = OSSL_PARAM_BLD_new();

    if (bld != NULL) {

        if (OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0) ==
                1 &&
            OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, q.data, q.len) == 1 &&
            OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, d) == 1 &&
            (params = OSSL_PARAM_BLD_to_param(bld)) != NULL) {

            ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);

            if (ctx != NULL) {

                if (EVP_PKEY_fromdata_init(ctx) == 1) {
                    (void)EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_KEYPAIR, params);
                }

                EVP_PKEY_CTX_free(ctx);
            }
        }

        OSSL_PARAM_BLD_free(bld);
    }

    OSSL_PARAM_free(params);
    BN_clear_free(d);

    return key;
}

/*
 * the ssh-rsa privkey: mpint n, e, d, iqmp, p, q in this order, into
 * the provider key through the param builder (the
 * s3_ssh3_jwt_key_rsa shape); the CRT exponents the wire omits derive
 * from the factors, the coefficient rides the blob
 */

static EVP_PKEY *
s3_cli_ossh_rsa(const u_char **pos, const u_char *end)
{
    OSSL_PARAM_BLD *bld;
    OSSL_PARAM     *params = NULL;
    EVP_PKEY_CTX   *ctx;
    EVP_PKEY       *key = NULL;
    BN_CTX         *bnctx = NULL;
    BIGNUM         *n, *e, *d, *iqmp, *p, *q, *pm1, *qm1, *dmp1, *dmq1;
    s3_str_t        n_s, e_s, d_s, iqmp_s, p_s, q_s;

    n = e = d = iqmp = p = q = pm1 = qm1 = dmp1 = dmq1 = NULL;

    if (s3_cli_ssh_string(pos, end, &n_s) != S3_OK || s3_cli_ssh_string(pos, end, &e_s) != S3_OK ||
        s3_cli_ssh_string(pos, end, &d_s) != S3_OK ||
        s3_cli_ssh_string(pos, end, &iqmp_s) != S3_OK ||
        s3_cli_ssh_string(pos, end, &p_s) != S3_OK || s3_cli_ssh_string(pos, end, &q_s) != S3_OK) {
        return NULL;
    }

    /* the mpint sign guard byte rides out with the BIGNUM convert */

    n = BN_bin2bn(n_s.data, (int)n_s.len, NULL);
    e = BN_bin2bn(e_s.data, (int)e_s.len, NULL);
    d = BN_bin2bn(d_s.data, (int)d_s.len, NULL);
    iqmp = BN_bin2bn(iqmp_s.data, (int)iqmp_s.len, NULL);
    p = BN_bin2bn(p_s.data, (int)p_s.len, NULL);
    q = BN_bin2bn(q_s.data, (int)q_s.len, NULL);

    if (n == NULL || e == NULL || d == NULL || iqmp == NULL || p == NULL || q == NULL) {
        goto done;
    }

    bnctx = BN_CTX_new();

    if (bnctx == NULL) {
        goto done;
    }

    pm1 = BN_new();
    qm1 = BN_new();
    dmp1 = BN_new();
    dmq1 = BN_new();

    if (pm1 == NULL || qm1 == NULL || dmp1 == NULL || dmq1 == NULL) {
        goto done;
    }

    /* dP = d mod (p-1), dQ = d mod (q-1): the wire keeps the factors
     * and the coefficient only */

    if (BN_sub(pm1, p, BN_value_one()) != 1 || BN_sub(qm1, q, BN_value_one()) != 1 ||
        BN_mod(dmp1, d, pm1, bnctx) != 1 || BN_mod(dmq1, d, qm1, bnctx) != 1) {
        goto done;
    }

    bld = OSSL_PARAM_BLD_new();

    if (bld != NULL) {

        if (OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n) == 1 &&
            OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e) == 1 &&
            OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_D, d) == 1 &&
            OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR1, p) == 1 &&
            OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR2, q) == 1 &&
            OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT1, dmp1) == 1 &&
            OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT2, dmq1) == 1 &&
            OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, iqmp) == 1 &&
            (params = OSSL_PARAM_BLD_to_param(bld)) != NULL) {

            ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);

            if (ctx != NULL) {

                if (EVP_PKEY_fromdata_init(ctx) == 1) {
                    (void)EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_KEYPAIR, params);
                }

                EVP_PKEY_CTX_free(ctx);
            }
        }

        OSSL_PARAM_BLD_free(bld);
    }

done:

    BN_clear_free(d);
    BN_clear_free(p);
    BN_clear_free(q);
    BN_free(n);
    BN_free(e);
    BN_free(iqmp);
    BN_free(pm1);
    BN_free(qm1);
    BN_clear_free(dmp1);
    BN_clear_free(dmq1);
    BN_CTX_free(bnctx);
    OSSL_PARAM_free(params);

    return key;
}

/*
 * the OpenSSH private key container (PROTOCOL.key of OpenSSH): the
 * armor wraps the base64 of
 *
 *   "openssh-key-v1\0" string ciphername string kdfname
 *   string kdfoptions uint32 nkeys string pubkey string privkey
 *
 * the unencrypted privkey (both "none") opens with the checkint
 * pair, then string alg, string pub, string priv, string comment,
 * the 1.. padding.  Only the single-key unencrypted container parses
 * here -- the Go fork behaviour; an encrypted one names the
 * ssh-keygen conversion instead of failing as "not a PEM private
 * key".  The buffer is the NUL-terminated key file text
 */

static EVP_PKEY *
s3_cli_openssh_key(const char *buf)
{
    static const char begin[] = "-----BEGIN OPENSSH PRIVATE KEY-----";
    static const char end[] = "-----END OPENSSH PRIVATE KEY-----";

    char          b64[S3_CLI_KEY_FILE_MAX];
    u_char        blob[S3_CLI_KEY_FILE_MAX];
    u_char        algname[64];
    const u_char *bpos, *bend;
    const char   *p, *stop;
    EVP_PKEY     *key = NULL;
    s3_str_t      cipher, kdf, kdfopt, pub, priv, algs;
    size_t        i, blen;
    uint32_t      check1, check2, nkeys;

    p = strstr(buf, begin);

    if (p == NULL) {
        return NULL;
    }

    p += sizeof(begin) - 1;

    stop = strstr(p, end);

    if (stop == NULL) {
        s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "%s ends inside the OpenSSH armor",
                     s3_cli_keyfile);
        return NULL;
    }

    /* the armor body rides as one line: the breaks (and the CR of a
     * windows-written file) drop before the decode */

    for (i = 0; p < stop && i + 1 < sizeof(b64); p++) {

        if (*p != '\r' && *p != '\n' && *p != ' ' && *p != '\t') {
            b64[i++] = *p;
        }
    }

    b64[i] = '\0';

    blen = s3_cli_b64dec(b64, blob, sizeof(blob));

    if (blen < sizeof(S3_CLI_OSSH_MAGIC) ||
        s3_memcmp(blob, S3_CLI_OSSH_MAGIC, sizeof(S3_CLI_OSSH_MAGIC) - 1) != 0) {
        s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "%s is not an openssh-key-v1 blob",
                     s3_cli_keyfile);
        return NULL;
    }

    /* the magic is the NUL-terminated 15 bytes, the walk starts
     * behind it */

    bpos = blob + sizeof(S3_CLI_OSSH_MAGIC);
    bend = blob + blen;

    if (s3_cli_ssh_string(&bpos, bend, &cipher) != S3_OK ||
        s3_cli_ssh_string(&bpos, bend, &kdf) != S3_OK ||
        s3_cli_ssh_string(&bpos, bend, &kdfopt) != S3_OK ||
        s3_cli_ssh_u32(&bpos, bend, &nkeys) != S3_OK ||
        s3_cli_ssh_string(&bpos, bend, &pub) != S3_OK) {
        s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "%s is a truncated openssh-key-v1 blob",
                     s3_cli_keyfile);
        return NULL;
    }

    if (cipher.len != 4 || s3_memcmp(cipher.data, "none", 4) != 0 || kdf.len != 4 ||
        s3_memcmp(kdf.data, "none", 4) != 0) {
        s3_log_error(S3_LOG_ERR, &s3_cli_log, 0,
                     "the key is passphrase-protected, convert:"
                     " ssh-keygen -p -m PEM -f %s -N \"\"",
                     s3_cli_keyfile);
        return NULL;
    }

    if (nkeys != 1) {
        s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the multi-key container of %s is not supported",
                     s3_cli_keyfile);
        return NULL;
    }

    if (s3_cli_ssh_string(&bpos, bend, &priv) != S3_OK) {
        s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "%s is a truncated openssh-key-v1 blob",
                     s3_cli_keyfile);
        return NULL;
    }

    bpos = priv.data;
    bend = priv.data + priv.len;

    if (s3_cli_ssh_u32(&bpos, bend, &check1) != S3_OK ||
        s3_cli_ssh_u32(&bpos, bend, &check2) != S3_OK || check1 != check2) {
        s3_log_error(S3_LOG_ERR, &s3_cli_log, 0,
                     "the checkint pair of %s does not match (a corrupt key)", s3_cli_keyfile);
        return NULL;
    }

    if (s3_cli_ssh_string(&bpos, bend, &algs) != S3_OK || algs.len == 0 ||
        algs.len >= sizeof(algname)) {
        s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "%s has no algorithm in the private section",
                     s3_cli_keyfile);
        return NULL;
    }

    memcpy(algname, algs.data, algs.len);
    algname[algs.len] = '\0';

    if (s3_memcmp(algname, "ssh-ed25519", sizeof("ssh-ed25519") - 1) == 0) {
        key = s3_cli_ossh_ed25519(&bpos, bend);

    } else if (s3_memcmp(algname, "ssh-rsa", sizeof("ssh-rsa") - 1) == 0) {
        key = s3_cli_ossh_rsa(&bpos, bend);

    } else if (s3_memcmp(algname, "ecdsa-sha2-nistp256", sizeof("ecdsa-sha2-nistp256") - 1) == 0) {
        key = s3_cli_ossh_ec256(&bpos, bend);

    } else {
        s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the unsupported openssh key type %s", algname);
        return NULL;
    }

    if (key == NULL) {
        s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the %s private section of %s did not parse",
                     algname, s3_cli_keyfile);
    }

    return key;
}

/*
 * the Bearer JWT of the -i mode, built once after the handshake (the
 * jti binds the live TLS exporter) and before the CONNECT; the claim
 * set is the reference BuildJWTBearerToken() (see the header contract
 * of s3_ssh3_auth_jwt)
 */

static s3_int_t
s3_cli_jwt_build_user(SSL *ssl, const char *user, char *out, size_t cap)
{
    static const char label[] = "EXPORTER-SSH3";

    char        header[64], payload[512], seg[1024], jti[64], tok[1200];
    u_char      conv[32], sig[1024];
    BIO        *bio;
    EVP_PKEY   *key = NULL;
    FILE       *kf;
    char       *buf;
    const char *ossh;
    size_t      len;
    unsigned    ok;
    const char *alg;
    long long   iat, exp;
    size_t      hlen, plen, tlen, siglen;

    /* the file loads once: the OpenSSH container takes its parser,
     * the PEM and PKCS#8 bodies stay with the OpenSSL reader */

    kf = fopen(s3_cli_keyfile, "rb");

    if (kf == NULL) {
        s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "cannot open key file %s", s3_cli_keyfile);
        return S3_ERROR;
    }

    buf = malloc(S3_CLI_KEY_FILE_MAX + 1);

    if (buf == NULL) {
        fclose(kf);
        s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the key file buffer failed");
        return S3_ERROR;
    }

    len = fread(buf, 1, S3_CLI_KEY_FILE_MAX, kf);
    ok = (ferror(kf) == 0);
    fclose(kf);

    if (!ok) {
        s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the key file %s read failed", s3_cli_keyfile);
        free(buf);
        return S3_ERROR;
    }

    buf[len] = '\0';

    ossh = strstr(buf, "-----BEGIN OPENSSH PRIVATE KEY-----");

    if (ossh != NULL) {
        key = s3_cli_openssh_key(buf);
        free(buf);

        /* the parser logs the specific reason, the generic line does
         * not repeat it */

        if (key == NULL) {
            return S3_ERROR;
        }

    } else {
        /* the mem BIO is a view: the buffer lives until the PEM
         * reader is done with it */

        bio = BIO_new_mem_buf(buf, (int)len);

        if (bio == NULL) {
            free(buf);
            s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the key file buffer failed");
            return S3_ERROR;
        }

        key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
        BIO_free(bio);
        free(buf);

        if (key == NULL) {
            s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "%s is not a PEM private key", s3_cli_keyfile);
            return S3_ERROR;
        }
    }

    switch (EVP_PKEY_get_base_id(key)) {

    case EVP_PKEY_ED25519:
        alg = "EdDSA";
        break;

    case EVP_PKEY_RSA:
        alg = "RS256";
        break;

    case EVP_PKEY_EC:

    {
        char grp[64];

        if (EVP_PKEY_get_group_name(key, grp, sizeof(grp), NULL) != 1 ||
            (strcmp(grp, "prime256v1") != 0 && strcmp(grp, "P-256") != 0)) {
            s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the EC key wants P-256");
            EVP_PKEY_free(key);
            return S3_ERROR;
        }
    }

        alg = "ES256";
        break;

    default:
        s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "unsupported key type");
        EVP_PKEY_free(key);
        return S3_ERROR;
    }

    if ((size_t)EVP_PKEY_get_size(key) > sizeof(sig)) {
        s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the key is too large");
        EVP_PKEY_free(key);
        return S3_ERROR;
    }

    if (ssl == NULL || SSL_export_keying_material(ssl, conv, sizeof(conv), label, sizeof(label) - 1,
                                                  NULL, 0, 0) != 1) {
        s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the exporter failed");
        EVP_PKEY_free(key);
        return S3_ERROR;
    }

    /* the jti of the reference: the base64.StdEncoding of the conv id */

    s3_cli_b64std(conv, sizeof(conv), jti);

    iat = (long long)time(NULL);
    exp = iat + S3_CLI_JWT_EXP_FRESH;

    hlen = (size_t)snprintf(header, sizeof(header), "{\"alg\":\"%s\",\"typ\":\"JWT\"}", alg);
    plen = (size_t)snprintf(payload, sizeof(payload),
                            "{\"iss\":\"%s\",\"iat\":%lld,\"exp\":%lld,\"sub\":\"ssh3\","
                            "\"aud\":\"unused\",\"client_id\":\"ssh3-%s\",\"jti\":\"%s\"}",
                            user, iat, exp, user, jti);

    if (hlen >= sizeof(header) || plen >= sizeof(payload)) {
        s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the claim buffers overflow");
        EVP_PKEY_free(key);
        return S3_ERROR;
    }

    /* the signing input: the two url segments joined by the dot */

    s3_cli_b64url((const u_char *)header, hlen, seg);
    tlen = strlen(seg);
    seg[tlen++] = '.';

    s3_cli_b64url((const u_char *)payload, plen, seg + tlen);
    tlen += strlen(seg + tlen);

    siglen = sizeof(sig);

    if (s3_cli_jwt_sign(key, alg, (const u_char *)seg, tlen, sig, &siglen) != S3_OK) {
        s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the signing failed (%s)", alg);
        EVP_PKEY_free(key);
        return S3_ERROR;
    }

    EVP_PKEY_free(key);

    if (tlen + 1 + siglen * 4 / 3 + 4 >= sizeof(tok)) {
        s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the token buffer overflow");
        return S3_ERROR;
    }

    if (strlen(tok) + strlen("Bearer ") + 1 > cap) {
        s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the bearer buffer overflow");
        return S3_ERROR;
    }

    snprintf(out, cap, "Bearer %s", tok);

    return S3_OK;
}

/* the main conversation wrapper: the JWT rides the live TLS exporter
 * and feeds the session auth value */

static s3_int_t
s3_cli_jwt_build(SSL *ssl)
{
    if (s3_cli_jwt_build_user(ssl, s3_cli_user, s3_cli_bearer, sizeof(s3_cli_bearer)) != S3_OK) {
        return S3_ERROR;
    }

    s3_cli_auth_value = s3_cli_bearer;

    return S3_OK;
}

static uintptr_t
s3_cli_h3_field_l(u_char *p, const char *name, const char *value)
{
    s3_str_t n, v;

    n.data = (u_char *)name;
    n.len = strlen(name);
    v.data = (u_char *)value;
    v.len = strlen(value);

    return s3_h3_encode_field_l(p, &n, &v);
}

/*
 * the extended CONNECT request section: a zero prefix plus the
 * literal field lines, it decodes against any peer QPACK state (the
 * harness shape); the :authority carries the real host:port, the
 * :path the ?user= target; the jump conversation reuses the same
 * shape with its own authority, target and auth (the bearer of the
 * jump exporter)
 */

static size_t
s3_cli_h3_section_ex(u_char *p, const char *authority, const char *target, const char *auth)
{
    u_char *start = p;

    if (p == NULL) {
        size_t n = (size_t)s3_h3_encode_field_section_prefix(NULL, 0, 0, 0);

        n += (size_t)s3_cli_h3_field_l(NULL, ":method", "CONNECT");
        n += (size_t)s3_cli_h3_field_l(NULL, ":protocol", "ssh3");
        n += (size_t)s3_cli_h3_field_l(NULL, ":scheme", "https");
        n += (size_t)s3_cli_h3_field_l(NULL, ":authority", authority);
        n += (size_t)s3_cli_h3_field_l(NULL, ":path", target);
        n += (size_t)s3_cli_h3_field_l(NULL, "user-agent", S3_SSH3_VERSION_STRING);

        if (auth != NULL) {
            n += (size_t)s3_cli_h3_field_l(NULL, "authorization", auth);
        }

        return n;
    }

    p = (u_char *)s3_h3_encode_field_section_prefix(p, 0, 0, 0);
    p = (u_char *)s3_cli_h3_field_l(p, ":method", "CONNECT");
    p = (u_char *)s3_cli_h3_field_l(p, ":protocol", "ssh3");
    p = (u_char *)s3_cli_h3_field_l(p, ":scheme", "https");
    p = (u_char *)s3_cli_h3_field_l(p, ":authority", authority);
    p = (u_char *)s3_cli_h3_field_l(p, ":path", target);
    p = (u_char *)s3_cli_h3_field_l(p, "user-agent", S3_SSH3_VERSION_STRING);

    if (auth != NULL) {
        p = (u_char *)s3_cli_h3_field_l(p, "authorization", auth);
    }

    return (size_t)(p - start);
}

static size_t
s3_cli_h3_section(u_char *p)
{
    char authority[320];

    snprintf(authority, sizeof(authority), "%s:%u", s3_cli_host, s3_cli_port);

    return s3_cli_h3_section_ex(p, authority, s3_cli_target, s3_cli_auth_value);
}

/* the jump CONNECT section: the jump host authority, the jump target
 * (?user= of the jump login) and the jump auth value */

static size_t
s3_cli_jump_h3_section(u_char *p)
{
    char authority[320];

    snprintf(authority, sizeof(authority), "%s:%u", s3_cli_jump_host, s3_cli_jump_port);

    return s3_cli_h3_section_ex(p, authority, s3_cli_jump_target, s3_cli_jump_auth);
}

/*
 * the ssh_config host pattern of the -F loader: the exact name, the
 * `*` and `?` wildcards, case-insensitive (the bracket classes stay
 * out, the common shapes cover); S3_OK on a match.  The recursion
 * rides the NUL-terminated pattern tail (the caller bound the copy)
 */

static s3_int_t
s3_cli_cfg_pattern_match(const char *pat, const char *host)
{
    size_t i, j = 0;

    for (i = 0; pat[i] != '\0'; i++) {

        char pc = pat[i], hc = host[j];

        if (pc >= 'A' && pc <= 'Z') {
            pc = (char)(pc - 'A' + 'a');
        }

        if (hc >= 'A' && hc <= 'Z') {
            hc = (char)(hc - 'A' + 'a');
        }

        if (pc == '*') {

            size_t k;

            if (pat[i + 1] == '\0') {
                return 1; /* the trailing star spans the rest */
            }

            for (k = j;; k++) {

                if (s3_cli_cfg_pattern_match(pat + i + 1, host + k) == 1) {
                    return 1;
                }

                if (host[k] == '\0') {
                    return 0;
                }
            }
        }

        if (hc == '\0') {
            return 0;
        }

        if (pc != '?' && pc != hc) {
            return 0;
        }

        j++;
    }

    return (host[j] == '\0');
}

/*
 * the -F config loader (the mini ssh_config): the Host blocks pick
 * the keys, the first obtained value wins per key (the ssh2 shape),
 * the command-line sets stay (the CLI wins), the forwards append;
 * the keys: HostName, Port, User, IdentityFile, ForwardAgent,
 * LocalForward, RemoteForward, DynamicForward, ProxyJump, EscapeChar,
 * StrictHostKeyChecking, ControlMaster, ControlPath, ControlPersist;
 * the unknown keys ignore silently.  The host name rides the operand
 * (the HostName substitution lands after the match)
 */

static unsigned
s3_cli_cfg_host_block(const char *patterns, const char *host)
{
    unsigned matched = 0, negated = 0;
    const char *p = patterns;

    while (*p != '\0') {

        const char *f = p;

        while (*p != '\0' && *p != ',' && *p != ' ' && *p != '\t') {
            p++;
        }

        if (p > f) {

            if (*f == '!') {
                negated |= (s3_cli_cfg_pattern_match(f + 1, host) == 1) ? 1u : 0u;
            } else {
                matched |= (s3_cli_cfg_pattern_match(f, host) == 1) ? 1u : 0u;
            }
        }

        while (*p == ',' || *p == ' ' || *p == '\t') {
            p++;
        }
    }

    return (matched && !negated) ? 1u : 0u;
}

static s3_int_t
s3_cli_cfg_apply(const char *key, const char *val)
{
    if (s3_cli_streq_ci(key, "hostname") == 0) {

        if (strlen(val) >= sizeof(s3_cli_host)) {
            fprintf(stderr, "ssh3: the config HostName is too long\n");
            return S3_ERROR;
        }

        snprintf(s3_cli_host, sizeof(s3_cli_host), "%s", val);

        return S3_OK;
    }

    if (s3_cli_streq_ci(key, "port") == 0) {

        unsigned v = (unsigned)atoi(val);

        if (v == 0 || v > 65535) {
            fprintf(stderr, "ssh3: the config Port wants 1..65535\n");
            return S3_ERROR;
        }

        if (!s3_cli_have_port && !s3_cli_port_operand) {
            s3_cli_port = v;
        }

        return S3_OK;
    }

    if (s3_cli_streq_ci(key, "user") == 0) {

        if (!s3_cli_have_user && strlen(val) < sizeof(s3_cli_user)) {
            snprintf(s3_cli_user, sizeof(s3_cli_user), "%s", val);
            s3_cli_have_user = 1;
        }

        return S3_OK;
    }

    if (s3_cli_streq_ci(key, "identityfile") == 0) {

        if (s3_cli_have_keyfile) {
            return S3_OK; /* the first identity wins */
        }

        if (strlen(val) >= sizeof(s3_cli_keyfile)) {
            fprintf(stderr, "ssh3: the config IdentityFile is too long\n");
            return S3_ERROR;
        }

        /* the ~/ head expands against the home (the ssh2 shape) */

        if (val[0] == '~' && (val[1] == '/' || val[1] == '\0')) {

#if (S3_WIN32)
            const char *home = getenv("USERPROFILE");
#else
            const char *home = getenv("HOME");
#endif

            if (home != NULL) {
                snprintf(s3_cli_keyfile, sizeof(s3_cli_keyfile), "%s%s", home, val + 1);
            } else {
                snprintf(s3_cli_keyfile, sizeof(s3_cli_keyfile), "%s", val + 1);
            }

        } else {
            snprintf(s3_cli_keyfile, sizeof(s3_cli_keyfile), "%s", val);
        }

        s3_cli_auth = S3_CLI_AUTH_PUBKEY;
        s3_cli_have_keyfile = 1;

        return S3_OK;
    }

    if (s3_cli_streq_ci(key, "forwardagent") == 0) {

        if (!s3_cli_have_agent &&
            (s3_cli_streq_ci(val, "yes") == 0 || s3_cli_streq_ci(val, "1") == 0)) {
            s3_cli_agent_mode = 1;
            s3_cli_have_agent = 1;
        }

        return S3_OK;
    }

    if (s3_cli_streq_ci(key, "localforward") == 0) {
        return s3_cli_fwd_parse(val);
    }

    if (s3_cli_streq_ci(key, "remoteforward") == 0) {
        return s3_cli_rev_parse_spec(val);
    }

    if (s3_cli_streq_ci(key, "dynamicforward") == 0) {
        return s3_cli_socks_parse(val);
    }

    if (s3_cli_streq_ci(key, "proxyjump") == 0) {

        if (s3_cli_have_jump) {
            return S3_OK;
        }

        if (s3_cli_streq_ci(val, "none") == 0) {
            s3_cli_jump_on = 0;
            s3_cli_have_jump = 1;
            return S3_OK;
        }

        return s3_cli_jump_parse(val);
    }

    if (s3_cli_streq_ci(key, "escapechar") == 0) {

        if (!s3_cli_have_escape) {
            return s3_cli_escape_parse(val);
        }

        return S3_OK;
    }

    if (s3_cli_streq_ci(key, "stricthostkeychecking") == 0) {

        if (s3_cli_have_strict) {
            return S3_OK;
        }

        if (s3_cli_streq_ci(val, "yes") == 0) {
            s3_cli_opt_strict = S3_CLI_SHK_YES;

        } else if (s3_cli_streq_ci(val, "no") == 0) {
            s3_cli_opt_strict = S3_CLI_SHK_NO;

        } else if (s3_cli_streq_ci(val, "accept-new") == 0) {
            s3_cli_opt_strict = S3_CLI_SHK_ACCEPT_NEW;
        }

        s3_cli_have_strict = 1;

        return S3_OK;
    }

    if (s3_cli_streq_ci(key, "controlmaster") == 0) {

        if (s3_cli_have_master) {
            return S3_OK;
        }

        if (s3_cli_streq_ci(val, "yes") == 0 || s3_cli_streq_ci(val, "auto") == 0 ||
            strcmp(val, "1") == 0) {

            if (s3_cli_streq_ci(val, "auto") == 0) {
                s3_cli_note("ssh3: ControlMaster=auto is not implemented yet, acting as yes");
            }

            s3_cli_cm_master = 1;
            s3_cli_have_master = 1;
        }

        return S3_OK;
    }

    if (s3_cli_streq_ci(key, "controlpath") == 0) {

        if (s3_cli_cm_path[0] != '\0') {
            return S3_OK;
        }

        if (strlen(val) >= sizeof(s3_cli_cm_path)) {
            fprintf(stderr, "ssh3: the config ControlPath is too long\n");
            return S3_ERROR;
        }

        snprintf(s3_cli_cm_path, sizeof(s3_cli_cm_path), "%s", val);
        s3_cli_cm_pipe_name_called = 1;

        return S3_OK;
    }

    if (s3_cli_streq_ci(key, "controlpersist") == 0) {

        if (s3_cli_streq_ci(val, "no") == 0 || strcmp(val, "0") == 0) {
            return S3_OK;
        }

        s3_cli_note("ssh3: control persist is not implemented yet, master dies with the session");

        return S3_OK;
    }

    /* the unknown key ignores silently (the ssh2 tolerance of the
     * newer keywords in the older clients) */

    return S3_OK;
}

static s3_int_t
s3_cli_cfg_load(const char *host)
{
    FILE   *f;
    char    line[2048];
    unsigned active = 0;

    f = fopen(s3_cli_cfg_path, "r");

    if (f == NULL) {

        /* the explicit -F wants the file (the ssh2 refusal), the
         * default path may not exist at all */

        if (s3_cli_cfg_explicit) {
            fprintf(stderr, "ssh3: cannot open the config %s\n", s3_cli_cfg_path);
            return S3_ERROR;
        }

        return S3_OK;
    }

    while (fgets(line, sizeof(line), f) != NULL) {

        char *p = line, *key, *val, *end;

        /* the trailing newline and the comment strip */

        end = line + strlen(line);

        while (end > line && (end[-1] == '\n' || end[-1] == '\r')) {
            *--end = '\0';
        }

        while (*p == ' ' || *p == '\t') {
            p++;
        }

        if (*p == '#' || *p == '\0' || *p == ';') {
            continue;
        }

        /* the inline comment (the space-hash) strips */

        {

            char *h = strchr(p, '#');

            if (h != NULL && h != p && (h[-1] == ' ' || h[-1] == '\t')) {
                *h = '\0';
            }
        }

        key = p;

        while (*p != '\0' && *p != ' ' && *p != '\t' && *p != '=') {
            p++;
        }

        if (*p == '=') {

            /* the Key=Value form (the ssh2 accepts both) */

            *p = '\0';
            p++;

            if (*p == ' ') {
                p++;
            }

        } else if (*p != '\0') {

            *p = '\0';
            p++;

            while (*p == ' ' || *p == '\t') {
                p++;
            }

        } else {
            continue; /* the key without a value */
        }

        val = p;

        while (*p == ' ' || *p == '\t') {
            p++;
        }

        val = p;

        end = val + strlen(val);

        while (end > val && (end[-1] == ' ' || end[-1] == '\t')) {
            *--end = '\0';
        }

        if (*val == '"') {

            char *q = strchr(val + 1, '"');

            if (q != NULL) {
                *q = '\0';
                val++;
            }
        }

        /* the end-of-line backslash continuation stays out (the
         * common single-line configs cover) */

        if (s3_cli_streq_ci(key, "host") == 0) {
            active = s3_cli_cfg_host_block(val, host);
            continue;
        }

        if (!active) {
            continue;
        }

        if (s3_cli_cfg_apply(key, val) != S3_OK) {
            fclose(f);
            return S3_ERROR;
        }
    }

    fclose(f);

    return S3_OK;
}

static const char s3_cli_opt_keys[] =
    "insecure, strict-host-key-checking, forwardagent, port, user, identityfile, localforward,"
    " remoteforward, dynamicforward, proxyjump, escapechar, controlmaster, controlpath,"
    " controlpersist";

/* the ASCII case-insensitive compare of the -o texts (the fork
 * accepts any case of the key and the value) */

static int
s3_cli_streq_ci(const char *a, const char *b)
{
    while (*a != '\0' && *b != '\0') {

        char ca = *a, cb = *b;

        if (ca >= 'A' && ca <= 'Z') {
            ca = (char)(ca - 'A' + 'a');
        }

        if (cb >= 'A' && cb <= 'Z') {
            cb = (char)(cb - 'A' + 'a');
        }

        if (ca != cb) {
            return 1;
        }

        a++;
        b++;
    }

    return (*a != *b);
}

/*
 * the pending note of the parse: the deprecated warnings queue here
 * (a fixed budget, the overflow drops), the end of the parse flushes
 * them to the stderr unless -q silenced the run
 */

static void
s3_cli_note(const char *fmt, ...)
{
    va_list ap;
    char    buf[512];

    if (s3_cli_notes_n >= S3_CLI_NOTES_MAX) {
        return;
    }

    va_start(ap, fmt);
    (void)vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    s3_cli_notes[s3_cli_notes_n++] = strdup(buf);
}

static void
s3_cli_notes_flush(void)
{
    unsigned i;

    for (i = 0; i < s3_cli_notes_n; i++) {
        fprintf(stderr, "%s\n", s3_cli_notes[i]);
        free(s3_cli_notes[i]);
        s3_cli_notes[i] = NULL;
    }

    s3_cli_notes_n = 0;
}

/* the trailing words join into one command text (the ssh shape), the
 * malloc rides the caller free (the exec text and the slave command
 * both live one process run) */

static char *
s3_cli_join_words(char **argv, size_t first, size_t argc)
{
    size_t i, cmdlen = 1;
    char  *cmd;

    for (i = first; i < argc; i++) {
        cmdlen += strlen(argv[i]) + 1;
    }

    cmd = malloc(cmdlen);

    if (cmd == NULL) {
        return NULL;
    }

    cmd[0] = '\0';

    for (i = first; i < argc; i++) {

        if (i > first) {
            strncat(cmd, " ", cmdlen - strlen(cmd) - 1);
        }

        strncat(cmd, argv[i], cmdlen - strlen(cmd) - 1);
    }

    return cmd;
}

/*
 * the transfer specifier put|get:local:remote (the -J legacy shape,
 * the --sftp and the -s sftp word share it): a colon right behind the
 * drive letter rides the path, the next one ends the local side (the
 * remote is the unix path of the server)
 */

static s3_int_t
s3_cli_sftp_spec_parse(const char *rest)
{
    const char *sep;
    size_t      len;

    if (strncmp(rest, "put:", 4) == 0) {
        s3_cli_sftp_mode = S3_CLI_SFTP_PUT;
        rest += 4;

    } else if (strncmp(rest, "get:", 4) == 0) {
        s3_cli_sftp_mode = S3_CLI_SFTP_GET;
        rest += 4;

    } else {
        fprintf(stderr, "ssh3: the transfer spec wants put|get:local:remote\n");
        return S3_ERROR;
    }

    sep = strchr(rest, ':');

    if (sep == rest + 1 &&
        ((rest[0] >= 'A' && rest[0] <= 'Z') || (rest[0] >= 'a' && rest[0] <= 'z'))) {
        sep = strchr(sep + 1, ':');
    }

    if (sep == NULL || sep == rest || sep[1] == '\0') {
        fprintf(stderr, "ssh3: the transfer spec wants put|get:local:remote\n");
        return S3_ERROR;
    }

    len = (size_t)(sep - rest);
    s3_cli_sftp_local = malloc(len + 1);

    if (s3_cli_sftp_local == NULL) {
        fprintf(stderr, "ssh3: out of memory\n");
        return S3_ERROR;
    }

    memcpy(s3_cli_sftp_local, rest, len);
    s3_cli_sftp_local[len] = '\0';

    len = strlen(sep + 1);
    s3_cli_sftp_remote = malloc(len + 1);

    if (s3_cli_sftp_remote == NULL) {
        fprintf(stderr, "ssh3: out of memory\n");
        return S3_ERROR;
    }

    memcpy(s3_cli_sftp_remote, sep + 1, len + 1);

    return S3_OK;
}

/*
 * the jump spec [user@]host[:port] (the ssh2 ProxyJump shape): one
 * hop, the comma chain refuses cleanly, the port defaults to 443 at
 * the resolve
 */

static s3_int_t
s3_cli_jump_parse(const char *spec)
{
    const char *s = spec, *at, *colon;
    size_t      len;

    /* the transfer spec of the legacy -J never lands here (the
     * caller forked it off), the comma chain is the rejected shape */

    if (strchr(spec, ',') != NULL) {
        fprintf(stderr, "ssh3: proxy chains are not supported (one jump hop rides)\n");
        return S3_ERROR;
    }

    at = strchr(s, '@');

    if (at != NULL) {

        if ((size_t)(at - s) >= sizeof(s3_cli_jump_user)) {
            fprintf(stderr, "ssh3: the jump user name is too long\n");
            return S3_ERROR;
        }

        memcpy(s3_cli_jump_user, s, (size_t)(at - s));
        s3_cli_jump_user[at - s] = '\0';
        s = at + 1;
    }

    colon = strchr(s, ':');

    if (colon != NULL) {

        s3_cli_jump_port = (unsigned)atoi(colon + 1);

        if (s3_cli_jump_port == 0 || s3_cli_jump_port > 65535) {
            fprintf(stderr, "ssh3: bad jump port in %s\n", spec);
            return S3_ERROR;
        }

        len = (size_t)(colon - s);

    } else {
        len = strlen(s);
    }

    if (len == 0 || len >= sizeof(s3_cli_jump_host)) {
        fprintf(stderr, "ssh3: bad jump host in %s\n", spec);
        return S3_ERROR;
    }

    memcpy(s3_cli_jump_host, s, len);
    s3_cli_jump_host[len] = '\0';

    s3_cli_jump_on = 1;
    s3_cli_have_jump = 1;

    return S3_OK;
}

/*
 * the escape character spec (the ssh2 -e shape): one character, the
 * ^x form is the control code, "none" disables the processor
 */

static s3_int_t
s3_cli_escape_parse(const char *arg)
{
    s3_cli_have_escape = 1;

    if (strcmp(arg, "none") == 0) {
        s3_cli_escape_ch = -1;
        return S3_OK;
    }

    if (strlen(arg) == 2 && arg[0] == '^') {

        if (arg[1] == '?') {
            s3_cli_escape_ch = 127;
            return S3_OK;
        }

        s3_cli_escape_ch = arg[1] & 0x1f;
        return S3_OK;
    }

    if (strlen(arg) != 1 || (u_char)arg[0] < 32 || (u_char)arg[0] > 126) {
        fprintf(stderr, "ssh3: -e wants one character, ^x or none\n");
        return S3_ERROR;
    }

    s3_cli_escape_ch = (u_char)arg[0];

    return S3_OK;
}

/* the escape processor lives in the interactive console shell only:
 * no exec, no pipe, no sftp, no master, a live escape char */

static unsigned
s3_cli_escape_live(void)
{
    return (s3_cli_escape_ch >= 0 && s3_cli_console && s3_cli_tty && s3_cli_cmd == NULL);
}

/* the escape processor state: the escape char is live at the start
 * of a line only, a hit waits for the command byte */

static unsigned s3_cli_esc_hit;
static unsigned s3_cli_esc_line_start = 1;

/* the local listeners of the forwards, the ~# listing */

static void
s3_cli_escape_list_forwards(void)
{
    unsigned i;

    for (i = 0; i < s3_cli_fwd_count; i++) {
        fprintf(stderr, "the forward %u: %s\n", (unsigned)i, s3_cli_fwd_specs[i].text);
    }

    for (i = 0; i < s3_cli_rspec_count; i++) {
        fprintf(stderr, "the reverse forward %u: %s -> %s\n", (unsigned)i,
                s3_cli_rspec[i].bind_host[0] ? s3_cli_rspec[i].bind_host : "*",
                s3_cli_rtarget_text[i]);
    }
}

/* the ~^Z suspend (the unix leg): the cooked terminal back, the
 * SIGTSTP to the process group, the raw mode on the return */

static void
s3_cli_escape_suspend(void)
{
#if !(S3_WIN32)

    if (s3_cli_raw) {
        (void)s3_ssh3_session_cli_tty_restore(0, &s3_cli_saved_termios);
        s3_cli_raw = 0;
    }

    (void)kill(0, SIGTSTP);

    /* the shell continued us: the raw mode of the session lifetime
     * rides again */

    if (s3_ssh3_session_cli_tty_raw(0, &s3_cli_saved_termios) == S3_OK) {
        s3_cli_raw = 1;
    }

#else
    fprintf(stderr, "ssh3: the suspend escape is unsupported on this platform\n");
#endif
}

/* the ~. drop: the graceful close of the session, the ssh exit code
 * 255 (the transport shape of the reference) */

static void
s3_cli_escape_drop(void)
{
    s3_cli_verdict = 1;
    s3_cli_exit_code = S3_CLI_EXIT_ERROR;
}

/*
 * the escape processor of the interactive console session: the bytes
 * filter into dst (the passed-through ones), the commands ride the
 * stderr and the session verdict; the caller gates the console+pty
 * shell shape and a live escape char
 */

static size_t
s3_cli_escape_feed(const u_char *src, size_t n, u_char *dst)
{
    size_t i, o = 0;

    for (i = 0; i < n; i++) {

        u_char b = src[i];

        if (s3_cli_esc_hit) {

            s3_cli_esc_hit = 0;

            if (b == (u_char)'.') {
                s3_cli_escape_drop();
                s3_cli_esc_line_start = 0;
                continue;
            }

            if (b == (u_char)s3_cli_escape_ch) {

                /* the doubled escape rides as the literal byte */

                s3_cli_esc_line_start = 0;
                dst[o++] = b;
                continue;
            }

            if (b == 0x1a) { /* ^Z */
                s3_cli_escape_suspend();
                s3_cli_esc_line_start = 0;
                continue;
            }

            if (b == '#') {
                s3_cli_escape_list_forwards();
                s3_cli_esc_line_start = 0;
                continue;
            }

            if (b == 'V') {
                fprintf(stderr, "ssh3 version %s\n", S3_SSH3_VERSION_STRING);
                s3_cli_esc_line_start = 0;
                continue;
            }

            /* the unknown and the ? both take the short help, the
             * bytes stay swallowed (the session keeps the line) */

            fprintf(stderr,
                    "ssh3 escape commands: %c. drop the session, %c%c suspend (unix),"
                    " %c# list the forwards, %cV version, %c? help, %c%c the literal"
                    " escape\n",
                    s3_cli_escape_ch, s3_cli_escape_ch, '^', s3_cli_escape_ch,
                    s3_cli_escape_ch, s3_cli_escape_ch, s3_cli_escape_ch,
                    s3_cli_escape_ch);

            s3_cli_esc_line_start = 0;
            continue;
        }

        if (s3_cli_esc_line_start && b == (u_char)s3_cli_escape_ch) {
            s3_cli_esc_hit = 1;
            continue;
        }

        s3_cli_esc_line_start = (b == LF || b == CR);
        dst[o++] = b;
    }

    return o;
}

static s3_int_t
s3_cli_opt_parse(const char *arg)
{
    char        key[64], val[1024];
    const char *eq;
    size_t      n;

    /* the bare boolean key (the -insecure and
     * -strict-host-key-checking flag shape of the fork) rides the
     * affirmative value; anything else wants Key=Value */

    if (arg != NULL && strchr(arg, '=') == NULL) {

        if (s3_cli_streq_ci(arg, "insecure") == 0) {
            s3_cli_opt_insecure = 1;
            return S3_OK;
        }

        if (s3_cli_streq_ci(arg, "strict-host-key-checking") == 0) {
            s3_cli_opt_strict = S3_CLI_SHK_YES;
            s3_cli_have_strict = 1;
            return S3_OK;
        }

        fprintf(stderr, "ssh3: -o wants Key=Value (the supported keys: %s)\n", s3_cli_opt_keys);
        return S3_ERROR;
    }

    if (arg == NULL || (eq = strchr(arg, '=')) == NULL) {
        fprintf(stderr, "ssh3: -o wants Key=Value (the supported keys: %s)\n", s3_cli_opt_keys);
        return S3_ERROR;
    }

    /* the key: bounded, lowercased in place (the fork accepts any
     * case); the value stays raw (the paths of the identity and the
     * control socket are case sensitive), the booleans compare
     * case-insensitively */

    n = (size_t)(eq - arg);

    if (n >= sizeof(key)) {
        fprintf(stderr, "ssh3: the -o key is too long (the supported keys: %s)\n", s3_cli_opt_keys);
        return S3_ERROR;
    }

    memcpy(key, arg, n);
    key[n] = '\0';

    {
        char *c;

        for (c = key; *c != '\0'; c++) {

            if (*c >= 'A' && *c <= 'Z') {
                *c = (char)(*c - 'A' + 'a');
            }
        }
    }

    n = strlen(eq + 1);

    if (n >= sizeof(val)) {
        fprintf(stderr, "ssh3: the -o value of %s is too long\n", key);
        return S3_ERROR;
    }

    memcpy(val, eq + 1, n + 1);

    if (strcmp(key, "insecure") == 0) {

        if (s3_cli_streq_ci(val, "yes") == 0 || s3_cli_streq_ci(val, "true") == 0 ||
            strcmp(val, "1") == 0) {
            s3_cli_opt_insecure = 1;

        } else if (s3_cli_streq_ci(val, "no") == 0 || s3_cli_streq_ci(val, "false") == 0 ||
                   strcmp(val, "0") == 0) {
            s3_cli_opt_insecure = 0;

        } else {
            fprintf(stderr, "ssh3: -o insecure wants yes|no|true|false|1|0\n");
            return S3_ERROR;
        }

        return S3_OK;
    }

    if (strcmp(key, "strict-host-key-checking") == 0) {

        if (s3_cli_streq_ci(val, "yes") == 0) {
            s3_cli_opt_strict = S3_CLI_SHK_YES;

        } else if (s3_cli_streq_ci(val, "no") == 0) {
            s3_cli_opt_strict = S3_CLI_SHK_NO;

        } else if (s3_cli_streq_ci(val, "accept-new") == 0) {
            s3_cli_opt_strict = S3_CLI_SHK_ACCEPT_NEW;

        } else {
            fprintf(stderr, "ssh3: -o strict-host-key-checking wants yes|no|accept-new\n");
            return S3_ERROR;
        }

        s3_cli_have_strict = 1;

        return S3_OK;
    }

    /* the ssh2 canon keys (the P8 wave): each maps onto the twin
     * short flag, the CLI-wins tracking rides along */

    if (strcmp(key, "port") == 0) {

        unsigned v = (unsigned)atoi(val);

        if (v == 0 || v > 65535) {
            fprintf(stderr, "ssh3: -o Port= wants a port 1..65535\n");
            return S3_ERROR;
        }

        s3_cli_port = v;
        s3_cli_have_port = 1;

        return S3_OK;
    }

    if (strcmp(key, "user") == 0) {

        if (strlen(val) >= sizeof(s3_cli_user)) {
            fprintf(stderr, "ssh3: -o User= is too long\n");
            return S3_ERROR;
        }

        snprintf(s3_cli_user, sizeof(s3_cli_user), "%s", val);
        s3_cli_have_user = 1;

        return S3_OK;
    }

    if (strcmp(key, "identityfile") == 0) {

        /* the ssh2 repeatable list carries one identity here, the
         * first wins and the rest note */

        if (s3_cli_have_keyfile) {
            s3_cli_note("ssh3: the additional IdentityFile rides ignored (one identity: %s)", val);
            return S3_OK;
        }

        if (strlen(val) >= sizeof(s3_cli_keyfile)) {
            fprintf(stderr, "ssh3: -o IdentityFile= is too long\n");
            return S3_ERROR;
        }

        snprintf(s3_cli_keyfile, sizeof(s3_cli_keyfile), "%s", val);
        s3_cli_auth = S3_CLI_AUTH_PUBKEY;
        s3_cli_have_keyfile = 1;

        return S3_OK;
    }

    if (strcmp(key, "forwardagent") == 0) {

        if (s3_cli_streq_ci(val, "yes") == 0 || strcmp(val, "1") == 0) {
            s3_cli_agent_mode = 1;

        } else if (s3_cli_streq_ci(val, "no") == 0 || strcmp(val, "0") == 0) {
            s3_cli_agent_mode = 0;

        } else {
            fprintf(stderr, "ssh3: -o ForwardAgent= wants yes|no\n");
            return S3_ERROR;
        }

        s3_cli_have_agent = 1;

        return S3_OK;
    }

    if (strcmp(key, "localforward") == 0) {
        return s3_cli_fwd_parse(val);
    }

    if (strcmp(key, "remoteforward") == 0) {
        return s3_cli_rev_parse_spec(val);
    }

    if (strcmp(key, "dynamicforward") == 0) {
        return s3_cli_socks_parse(val);
    }

    if (strcmp(key, "proxyjump") == 0) {

        if (s3_cli_streq_ci(val, "none") == 0) {
            s3_cli_jump_on = 0;
            s3_cli_have_jump = 1;
            return S3_OK;
        }

        return s3_cli_jump_parse(val);
    }

    if (strcmp(key, "escapechar") == 0) {
        return s3_cli_escape_parse(val);
    }

    if (strcmp(key, "controlmaster") == 0) {

        if (s3_cli_streq_ci(val, "yes") == 0 || strcmp(val, "1") == 0) {
            s3_cli_cm_master = 1;

        } else if (s3_cli_streq_ci(val, "auto") == 0) {

            /* the auto dial-probe mode lives in the interop harness
             * only, the product client rides the master branch with
             * the documented note */

            s3_cli_cm_master = 1;
            s3_cli_note("ssh3: ControlMaster=auto is not implemented yet, acting as yes");

        } else if (s3_cli_streq_ci(val, "no") == 0 || strcmp(val, "0") == 0) {
            s3_cli_cm_master = 0;

        } else {
            fprintf(stderr, "ssh3: -o ControlMaster= wants yes|no|auto\n");
            return S3_ERROR;
        }

        s3_cli_have_master = 1;

        return S3_OK;
    }

    if (strcmp(key, "controlpath") == 0) {

        if (strlen(val) >= sizeof(s3_cli_cm_path)) {
            fprintf(stderr, "ssh3: -o ControlPath= is too long\n");
            return S3_ERROR;
        }

        snprintf(s3_cli_cm_path, sizeof(s3_cli_cm_path), "%s", val);
        s3_cli_cm_pipe_name_called = 1;

        return S3_OK;
    }

    if (strcmp(key, "controlpersist") == 0) {

        if (s3_cli_streq_ci(val, "no") == 0 || strcmp(val, "0") == 0) {

            /* the default shape: the master dies with the client */

            return S3_OK;
        }

        /* yes or the seconds form: the detached master of the
         * harness lives there only, the documented lacuna notes */

        s3_cli_note("ssh3: control persist is not implemented yet, master dies with the session");

        return S3_OK;
    }

    fprintf(stderr, "ssh3: the -o key \"%s\" is not supported (the supported keys: %s)\n", key,
            s3_cli_opt_keys);

    return S3_ERROR;
}

/*
 * the known_hosts check of the DER: S3_OK when the certificate
 * matches a pin or was just accepted, S3_DECLINED when the host is
 * unknown and the user declined (or the session is not a console),
 * S3_ERROR on a changed certificate (the MITM shape) or a file error;
 * the line format is the Go client one; the -o insecure skips the
 * whole check, the -o strict-host-key-checking picks the unknown-host
 * policy (yes refuses at once, no accepts without a pin write,
 * accept-new is the default TOFU)
 */

static s3_int_t
s3_cli_tofu_prepare(void)
{
    snprintf(s3_cli_hostkey, sizeof(s3_cli_hostkey), "%s:%u%s", s3_cli_host, s3_cli_port,
             s3_cli_path);

    return S3_OK;
}

static s3_int_t
s3_cli_cert_check(void)
{
    char    line[17408], fp[64], pin[16384], kh_path[1024];
    u_char *der = NULL, dec[8192];
    size_t  derlen;
    int     matched = 0, pinned = 0;
    FILE   *f;

    /* the -o insecure: any certificate of the server rides (the TLS
     * layer never verified the chain, the TOFU pin store is skipped
     * with the whole question and the record) */

    if (s3_cli_opt_insecure) {
        return S3_OK;
    }

    /* the leaf of the handshake, the i2d form the pins store */

    {
        X509 *cert = SSL_get1_peer_certificate(s3_cli_conn->ssl->connection);

        if (cert == NULL) {
            s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the server presented no certificate");
            return S3_ERROR;
        }

        derlen = (size_t)i2d_X509(cert, &der);
        X509_free(cert);

        if (derlen == 0 || der == NULL) {
            return S3_ERROR;
        }

        /* the pin store is sized for the certificates of the real
         * peers, a leaf above the decode buffer refuses here */

        if (derlen > sizeof(dec)) {
            s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the certificate is too large to pin");
            OPENSSL_free(der);
            return S3_ERROR;
        }
    }

    s3_cli_sha256_fp(der, derlen, fp);

    if (s3_cli_kh_path(kh_path, sizeof(kh_path)) != S3_OK) {
        s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the home directory is not set, cannot pin");
        OPENSSL_free(der);
        return S3_ERROR;
    }

    /* the ANSI file surface: the getenv and the CRT open share the
     * codepage, the pins are ASCII */

    f = fopen(kh_path, "r");

    if (f != NULL) {

        while (fgets(line, sizeof(line), f) != NULL) {

            char  *sp1, *sp2, *nl;
            size_t dlen;

            nl = strchr(line, '\n');

            if (nl != NULL) {
                *nl = '\0';
            }

            sp1 = strchr(line, ' ');

            if (sp1 == NULL) {
                continue;
            }

            sp2 = strchr(sp1 + 1, ' ');

            if (sp2 == NULL) {
                continue;
            }

            *sp1 = '\0';
            *sp2 = '\0';

            if (strcmp(line, s3_cli_hostkey) != 0 || strcmp(sp1 + 1, "x509-certificate") != 0) {
                continue;
            }

            /* the pin compares on the raw DER bytes */

            dlen = s3_cli_b64dec(sp2 + 1, dec, sizeof(dec));

            pinned = 1;

            if (dlen == derlen && memcmp(dec, der, derlen) == 0) {
                matched = 1;
                break;
            }
        }

        fclose(f);
    }

    if (matched) {
        OPENSSL_free(der);

        return S3_OK;
    }

    if (pinned) {

        s3_log_error(S3_LOG_ERR, &s3_cli_log, 0,
                     "WARNING: the certificate of %s does not match the pin in known_hosts"
                     " (received %s): a machine-in-the-middle attack or a server change",
                     s3_cli_hostkey, fp);

        OPENSSL_free(der);
        return S3_ERROR;
    }

    /* the unknown host: the -o strict-host-key-checking policy first
     * (yes refuses at once, no accepts without the record), the
     * accept-new default runs the TOFU question on a console, a pipe
     * session refuses (the reference ask mode) */

    if (s3_cli_opt_strict == S3_CLI_SHK_YES) {

        s3_log_error(S3_LOG_ERR, &s3_cli_log, 0,
                     "the authenticity of %s cannot be established (certificate %s) and"
                     " strict-host-key-checking=yes refuses an unpinned host",
                     s3_cli_hostkey, fp);

        OPENSSL_free(der);
        return S3_DECLINED;
    }

    if (s3_cli_opt_strict == S3_CLI_SHK_NO) {

        s3_log_error(S3_LOG_INFO, &s3_cli_log, 0,
                     "the certificate of %s is accepted without a pin"
                     " (strict-host-key-checking=no, certificate %s)",
                     s3_cli_hostkey, fp);

        OPENSSL_free(der);
        return S3_OK;
    }

    if (!s3_cli_console) {
        s3_log_error(S3_LOG_ERR, &s3_cli_log, 0,
                     "the authenticity of %s cannot be established (certificate %s) and the"
                     " session is not interactive, aborting",
                     s3_cli_hostkey, fp);

        OPENSSL_free(der);
        return S3_DECLINED;
    }

    fprintf(stderr,
            "The authenticity of host %s cannot be established.\n"
            "Certificate fingerprint: %s\n"
            "Do you want to add this certificate to %s (yes/no)? ",
            s3_cli_hostkey, fp, S3_CLI_KH_LABEL);
    fflush(stderr);

    {
        char answer[16];

        if (fgets(answer, sizeof(answer), stdin) == NULL) {
            answer[0] = '\0';
        }

        answer[strcspn(answer, "\r\n")] = '\0';

        if (strcmp(answer, "yes") != 0 && strcmp(answer, "y") != 0) {
            fprintf(stderr, "Host key verification failed.\n");
            OPENSSL_free(der);
            return S3_DECLINED;
        }
    }

    /* the pin appends (the line terminator rides the platform helper) */

    s3_cli_b64std(der, derlen, pin);
    snprintf(line, sizeof(line), "%s x509-certificate %s", s3_cli_hostkey, pin);

    if (s3_cli_kh_append(kh_path, line) != S3_OK) {
        s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the known_hosts append failed");
        OPENSSL_free(der);
        return S3_ERROR;
    }

    fprintf(stderr, "Pinned %s (%s)\n", s3_cli_hostkey, fp);

    OPENSSL_free(der);

    return S3_OK;
}

/*
 * the 98 builder: the message type varint, the envelope and the
 * encoded body of the request, appended at p (the harness shape);
 * the encoded body parks in the connection pool, so an exec command
 * of any length rides
 */

static u_char *
s3_cli_session_request(u_char *p, s3_ssh3_request_kind_t kind, unsigned want_reply,
                       const s3_ssh3_request_t *body)
{
    s3_ssh3_msg_request_t env;
    u_char               *enc;
    size_t                n;
    const char           *type;

    p = (u_char *)s3_ssh3_encode_varint(p, S3_SSH3_MSG_CHANNEL_REQUEST);

    type = s3_ssh3_request_type_str(kind);

    n = (size_t)s3_ssh3_request_encode_body(NULL, body);

    enc = s3_pnalloc(s3_cli_conn->pool, n ? n : 1);

    if (enc == NULL) {
        s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "out of memory for the request body");
        exit(S3_CLI_EXIT_ERROR);
    }

    (void)s3_ssh3_request_encode_body(enc, body);

    memset(&env, 0, sizeof(env));

    env.request_type.data = (u_char *)type;
    env.request_type.len = strlen(type);
    env.want_reply = want_reply;
    env.body.data = enc;
    env.body.len = n;

    return (u_char *)s3_ssh3_msg_encode_request(p, &env);
}

/*
 * the parked channel send: the frame bytes copy into the outbox and
 * drain on the ticks; the caller builds one frame per call, the flush
 * below retries the tail (the byte stream keeps the offset)
 */

static void
s3_cli_chan_park(const u_char *buf, size_t len)
{
    if (s3_cli_outbox_len + len > sizeof(s3_cli_outbox)) {
        s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the channel outbox overflow");
        exit(S3_CLI_EXIT_ERROR);
    }

    memcpy(s3_cli_outbox + s3_cli_outbox_len, buf, len);
    s3_cli_outbox_len += len;

    s3_cli_outbox_flush();
}

static void
s3_cli_outbox_flush(void)
{
    while (s3_cli_outbox_sent < s3_cli_outbox_len) {

        ssize_t m = s3_quic_stream_send(s3_cli_chan, s3_cli_outbox + s3_cli_outbox_sent,
                                        s3_cli_outbox_len - s3_cli_outbox_sent);

        if (m == (ssize_t)S3_AGAIN) {
            /* the window reopens, the tick retries */
            return;
        }

        if (m <= 0) {
            s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the channel send failed");
            s3_cli_chan = NULL;
            s3_quic_finalize_connection(((s3_quic_stream_t *)s3_cli_ctrl->data)->parent, 0,
                                        "channel send failed");
            return;
        }

        s3_cli_outbox_sent += (size_t)m;
    }

    s3_cli_outbox_sent = 0;
    s3_cli_outbox_len = 0;
}

/* the stdout sink of the pump: the raw fd write, no stdio buffering */

static void
s3_cli_out_sink(void *arg, const s3_str_t *data)
{
    size_t off = 0;

    (void)arg;

    while (off < data->len) {

        ssize_t n = s3_cli_fd_write(1, data->data + off, data->len - off);

        if (n <= 0) {
            break;
        }

        off += (size_t)n;
    }
}

static void
s3_cli_err_sink(void *arg, const s3_str_t *data)
{
    size_t off = 0;

    (void)arg;

    while (off < data->len) {

        ssize_t n = s3_cli_fd_write(2, data->data + off, data->len - off);

        if (n <= 0) {
            break;
        }

        off += (size_t)n;
    }
}

static void
s3_cli_exit_cb(void *arg, uint64_t code)
{
    (void)arg;

    if (!s3_cli_verdict) {
        s3_cli_verdict = 1;
        s3_cli_exit_code = code;
    }
}

/*
 * the session channel reader: the chunks land in the pump, the sinks
 * take the payloads straight to the fds; the fin before the verdict
 * is the transport error, after it the session is complete
 */

static void
s3_cli_chan_read(s3_event_t *ev)
{
    s3_connection_t *sc = ev->data;
    u_char           buf[16384];

    for (;;) {

        ssize_t n = sc->recv(sc, buf, sizeof(buf));

        if (n == (ssize_t)S3_AGAIN) {
            return;
        }

        if (n == 0) {

            /* the server fin: after the verdict the session is
             * complete, before it the server broke the contract */

            s3_cli_closed = 1;

            if (!s3_cli_verdict) {
                s3_log_error(S3_LOG_ERR, &s3_cli_log, 0,
                             "the channel closed without an exit-status");
                s3_cli_rc = S3_CLI_EXIT_ERROR;
                s3_quic_finalize_connection(((s3_quic_stream_t *)sc->data)->parent, 0,
                                            "closed without exit-status");
            }

            return;
        }

        if (n < 0) {
            s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the channel recv failed");
            s3_cli_rc = S3_CLI_EXIT_ERROR;
            s3_quic_finalize_connection(((s3_quic_stream_t *)sc->data)->parent, 0,
                                        "channel recv error");
            return;
        }

        if (s3_ssh3_session_cli_input(&s3_cli_sess, buf, (size_t)n) != S3_OK) {
            s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the session protocol violation");
            s3_cli_rc = S3_CLI_EXIT_ERROR;
            s3_quic_finalize_connection(((s3_quic_stream_t *)sc->data)->parent, 0,
                                        "session protocol violation");
            return;
        }
    }
}

/*
 * the CONNECT response reader: the :status field of the first
 * section is the verdict (200 opens the channel, anything else ends
 * the run)
 */

static void
s3_cli_ctrl_read(s3_event_t *ev)
{
    s3_connection_t *sc = ev->data;
    s3_connection_t *pc;
    s3_buf_t         b;
    s3_int_t         rc;

    if (s3_cli_status_seen) {
        return;
    }

    pc = ((s3_quic_stream_t *)sc->data)->parent;

    for (;;) {

        ssize_t n =
            sc->recv(sc, s3_cli_resp + s3_cli_resp_len, sizeof(s3_cli_resp) - s3_cli_resp_len);

        if (n == (ssize_t)S3_AGAIN) {
            return;
        }

        if (n <= 0) {
            s3_log_error(S3_LOG_ERR, &s3_cli_log, 0,
                         "the response stream closed without a :status");
            s3_cli_rc = S3_CLI_EXIT_ERROR;
            s3_quic_finalize_connection(pc, 0, "closed without status");
            return;
        }

        s3_cli_resp_len += (size_t)n;

        b.pos = s3_cli_resp;
        b.last = s3_cli_resp + s3_cli_resp_len;

        for (;;) {

            rc = s3_h3_parse_headers(pc, &s3_cli_h3parse, &b);

            if (rc == S3_AGAIN || rc == S3_BUSY) {
                break;
            }

            if (rc == S3_OK || rc == S3_DONE) {

                s3_str_t *name = &s3_cli_h3parse.field_rep.field.name;
                s3_str_t *value = &s3_cli_h3parse.field_rep.field.value;

                if (name->len == 7 && memcmp(name->data, ":status", 7) == 0) {

                    unsigned code = 0;
                    size_t   i;

                    for (i = 0; i < value->len && i < 3; i++) {
                        code = code * 10 + (unsigned)(value->data[i] - '0');
                    }

                    s3_cli_status = code;
                    s3_cli_status_seen = 1;

                    if (code != 200) {
                        s3_log_error(S3_LOG_ERR, &s3_cli_log, 0,
                                     "the server refused the session (HTTP %ud)", code);
                        s3_cli_rc = S3_CLI_EXIT_ERROR;
                        s3_quic_finalize_connection(pc, 0, "connect refused");
                    }

                    return;
                }

                if (rc == S3_DONE) {
                    s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the response has no :status");
                    s3_cli_rc = S3_CLI_EXIT_ERROR;
                    s3_quic_finalize_connection(pc, 0, "no status");
                    return;
                }

                continue;
            }

            s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the response parse failed");
            s3_cli_rc = S3_CLI_EXIT_ERROR;
            s3_quic_finalize_connection(pc, 0, "response parse error");
            return;
        }

        /* the consumed bytes compact to the front */

        s3_cli_resp_len = (size_t)(b.last - b.pos);
        memmove(s3_cli_resp, b.pos, s3_cli_resp_len);
    }
}

/*
 * the peer streams: the uni ones belong to the h3 session port, the
 * bidi ones are the server-initiated channels (the agent connections,
 * out of the stage-A scope, refused)
 */

static void
s3_cli_client_stream(s3_connection_t *c, s3_quic_stream_t *qs)
{
    if ((qs->id & 0x3) == 0x1) {

        if (s3_cli_agent_mode && s3_cli_agent_sc == NULL) {

            /* the server-initiated agent-connection channel: the
             * bridge accepts it when -X asked for the forwarding */

            s3_cli_agent_accept(c);
            return;
        }

        if (s3_cli_rspec_count) {

            /* the server-initiated forwarded-* channel of the -R
             * run: the accept reader dispatches the types (the
             * unexpected ones refuse) */

            s3_cli_rev_accept(c);
            return;
        }

        (void)s3_quic_cancelable_stream(c);
        (void)s3_quic_shutdown_stream(c, S3_RDWR_SHUTDOWN);

        return;
    }

    if (s3_h3_get_session(qs->parent) == NULL && s3_h3_init_session(qs->parent) != S3_OK) {
        s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the lazy h3 init failed");
        return;
    }

    s3_h3_init_stream(c);
}

/* the datagrams: the reverse bridges route them first (the channel
 * ids of the -R never collide with the client-side ids of the -L),
 * the udp forwards next, the other runs drain */

static void
s3_cli_datagram(s3_connection_t *c, s3_chain_t *data)
{
    if (s3_cli_rev_datagram(data) == 1) {
        return;
    }

    if (s3_cli_fwd_count) {
        s3_cli_fwd_datagram(data);
    }

    (void)c;
}

/* === the sftp transfer mode (-J put|get, the stage B) === */

/*
 * the driver bytes of the cli direction: the requests of
 * s3_ssh3_sftp_cli drain here, the pump chunks them into the 94
 * frames under the channel maxPacketSize; the accum rides malloc
 * (the transfer lives one session, the process exits after it)
 */

static s3_int_t
s3_cli_sftp_append(const u_char *data, size_t n)
{
    if (s3_cli_sftp_out_len + n > s3_cli_sftp_out_cap) {

        size_t  cap = s3_cli_sftp_out_cap ? s3_cli_sftp_out_cap : 65536;
        u_char *grown;

        while (cap < s3_cli_sftp_out_len + n) {
            cap += 65536;
        }

        grown = realloc(s3_cli_sftp_out, cap);

        if (grown == NULL) {
            return S3_ERROR;
        }

        s3_cli_sftp_out = grown;
        s3_cli_sftp_out_cap = cap;
    }

    memcpy(s3_cli_sftp_out + s3_cli_sftp_out_len, data, n);
    s3_cli_sftp_out_len += n;

    return S3_OK;
}

/*
 * the verdict of the finished driver: FX_OK exits zero, anything
 * else the scp parity exit 1 (the transport failures exit 255)
 */

static void
s3_cli_sftp_finish(void)
{
    uint32_t status = s3_ssh3_sftp_cli_status(&s3_cli_sftp);

    if (s3_cli_verdict) {
        return;
    }

    s3_cli_verdict = 1;

    if (s3_ssh3_sftp_cli_finished(&s3_cli_sftp) && status == S3_SSH3_SFTP_FX_OK) {
        s3_cli_exit_code = 0;

    } else {
        s3_cli_exit_code = S3_CLI_EXIT_SFTP;
    }
}

/*
 * the cli direction: the drained requests chunk into the 94 frames
 * under the channel maxPacketSize (a 32 KiB WRITE body overflows one
 * frame), a partial send parks the tail on the static frame buffer;
 * the retry rides the write event and the tick.  The pump gates on
 * the 91: the INIT waits until the server confirmed the channel
 */

static void
s3_cli_sftp_pump(void)
{
    u_char  buf[65536];
    ssize_t n, m;
    size_t  chunk;

    if (s3_cli_chan == NULL || !s3_cli_ch_confirmed) {
        return;
    }

    for (;;) {

        n = s3_ssh3_sftp_cli_output(&s3_cli_sftp, buf, sizeof(buf));

        if (n <= 0) {
            break;
        }

        if (s3_cli_sftp_append(buf, (size_t)n) != S3_OK) {
            s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the sftp buffer growth failed");
            s3_cli_chan = NULL;
            s3_quic_finalize_connection(((s3_quic_stream_t *)s3_cli_ctrl->data)->parent, 0,
                                        "sftp buffer growth failed");
            return;
        }
    }

    while (s3_cli_sftp_out_len > 0 || s3_cli_sftp_frame_sent < s3_cli_sftp_frame_total) {

        if (s3_cli_sftp_frame_sent == s3_cli_sftp_frame_total) {

            u_char *p;

            chunk = s3_ssh3_channel_chunk_size(S3_CLI_CHANNEL_MAX_PACKET, 0);

            if (chunk > s3_cli_sftp_out_len) {
                chunk = s3_cli_sftp_out_len;
            }

            p = s3_cli_sftp_frame;
            p = (u_char *)s3_ssh3_encode_varint(p, S3_SSH3_MSG_CHANNEL_DATA);
            p = (u_char *)s3_ssh3_encode_varint(p, chunk);
            memcpy(p, s3_cli_sftp_out, chunk);

            s3_cli_sftp_frame_total = (size_t)(p - s3_cli_sftp_frame) + chunk;
            s3_cli_sftp_frame_sent = 0;

            memmove(s3_cli_sftp_out, s3_cli_sftp_out + chunk, s3_cli_sftp_out_len - chunk);
            s3_cli_sftp_out_len -= chunk;
        }

        m = s3_quic_stream_send(s3_cli_chan, s3_cli_sftp_frame + s3_cli_sftp_frame_sent,
                                s3_cli_sftp_frame_total - s3_cli_sftp_frame_sent);

        if (m == (ssize_t)S3_AGAIN) {

            /* the window closed: the write event and the short
             * tick retry the tail */

            s3_cli_sftp_parked = 1;

            return;
        }

        if (m <= 0) {
            s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the sftp channel send failed");
            s3_cli_chan = NULL;
            s3_quic_finalize_connection(((s3_quic_stream_t *)s3_cli_ctrl->data)->parent, 0,
                                        "sftp send failed");
            return;
        }

        s3_cli_sftp_frame_sent += (size_t)m;
    }

    s3_cli_sftp_parked = 0;
}

/*
 * the write readiness of the sftp channel: the quic layer posts this
 * when the peer reopens the stream window, the pump resumes there
 */

static void
s3_cli_sftp_write(s3_event_t *ev)
{
    ev->ready = 0;

    if (s3_cli_verdict) {
        return;
    }

    s3_cli_sftp_pump();
}

/* the driver bring-up: put/get or their -r forms, verify on (the
 * checksum tail proves the byte-exactness against the server side) */

static void
s3_cli_sftp_start(void)
{
    s3_int_t rc;

    s3_cli_sftp_pool = s3_create_pool(S3_DEFAULT_POOL_SIZE, &s3_cli_log);

    if (s3_cli_sftp_pool == NULL) {
        s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the sftp pool failed");
        s3_cli_rc = S3_CLI_EXIT_ERROR;
        s3_quic_finalize_connection(((s3_quic_stream_t *)s3_cli_ctrl->data)->parent, 0,
                                    "sftp pool failed");
        return;
    }

    if (s3_ssh3_sftp_cli_init(&s3_cli_sftp, s3_cli_sftp_pool, NULL, NULL) != S3_OK) {
        s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the sftp driver init failed");
        s3_cli_rc = S3_CLI_EXIT_ERROR;
        s3_quic_finalize_connection(((s3_quic_stream_t *)s3_cli_ctrl->data)->parent, 0,
                                    "sftp init failed");
        return;
    }

    /* the READ bound follows the channel maxPacketSize this side
     * announced: the DATA replies of the peer stay under it */

    s3_ssh3_sftp_cli_channel_max_packet(&s3_cli_sftp, S3_CLI_CHANNEL_MAX_PACKET);

    if (s3_cli_sftp_mode == S3_CLI_SFTP_PUT) {

        if (s3_cli_sftp_recursive) {
            rc = s3_ssh3_sftp_cli_put_r(&s3_cli_sftp, s3_cli_sftp_local, s3_cli_sftp_remote, 0, 1);

        } else {
            rc = s3_ssh3_sftp_cli_put(&s3_cli_sftp, s3_cli_sftp_local, s3_cli_sftp_remote, 0, 1);
        }

    } else {

        if (s3_cli_sftp_recursive) {
            rc = s3_ssh3_sftp_cli_get_r(&s3_cli_sftp, s3_cli_sftp_remote, s3_cli_sftp_local, 0, 1);

        } else {
            rc = s3_ssh3_sftp_cli_get(&s3_cli_sftp, s3_cli_sftp_remote, s3_cli_sftp_local, 0, 1);
        }
    }

    if (rc != S3_OK) {
        s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the sftp op start failed");
        s3_cli_rc = S3_CLI_EXIT_ERROR;
        s3_quic_finalize_connection(((s3_quic_stream_t *)s3_cli_ctrl->data)->parent, 0,
                                    "sftp start failed");
        return;
    }

    s3_cli_sftp_started = 1;
}

/*
 * the sftp channel reader: the 91 confirms the channel, the 94
 * payloads feed the driver; the verdict lands from the driver state,
 * the fin before it is the transport error
 */

static void
s3_cli_sftp_read(s3_event_t *ev)
{
    s3_connection_t *sc = ev->data;
    const u_char    *pos, *end;
    ssize_t          n;

    if (s3_cli_verdict) {
        return;
    }

    for (;;) {

        if (s3_cli_sftp_buf_len == s3_cli_sftp_buf_cap) {

            size_t  cap;
            u_char *grown;

            /* the accumulator bound: a full buffer with no complete
             * frame inside is a peer trickling bytes */

            if (s3_cli_sftp_buf_cap >= S3_CLI_SFTP_BUF_MAX) {
                s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the sftp channel buffer overgrown");
                s3_cli_rc = S3_CLI_EXIT_ERROR;
                s3_quic_finalize_connection(((s3_quic_stream_t *)sc->data)->parent, 0,
                                            "sftp buffer overgrown");
                return;
            }

            cap = s3_cli_sftp_buf_cap + 262144;

            if (cap > S3_CLI_SFTP_BUF_MAX) {
                cap = S3_CLI_SFTP_BUF_MAX;
            }

            grown = realloc(s3_cli_sftp_buf, cap);

            if (grown == NULL) {
                s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the sftp buffer growth failed");
                s3_cli_rc = S3_CLI_EXIT_ERROR;
                s3_quic_finalize_connection(((s3_quic_stream_t *)sc->data)->parent, 0,
                                            "sftp buffer growth failed");
                return;
            }

            s3_cli_sftp_buf = grown;
            s3_cli_sftp_buf_cap = cap;
        }

        n = sc->recv(sc, s3_cli_sftp_buf + s3_cli_sftp_buf_len,
                     s3_cli_sftp_buf_cap - s3_cli_sftp_buf_len);

        if (n == (ssize_t)S3_AGAIN) {
            return;
        }

        if (n <= 0) {
            s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the sftp channel closed early");
            s3_cli_rc = S3_CLI_EXIT_ERROR;
            s3_quic_finalize_connection(((s3_quic_stream_t *)sc->data)->parent, 0,
                                        "sftp channel closed");
            return;
        }

        s3_cli_sftp_buf_len += (size_t)n;

        pos = s3_cli_sftp_buf;
        end = s3_cli_sftp_buf + s3_cli_sftp_buf_len;

        while (pos < end) {

            const u_char *msg = pos;
            uint64_t      type;

            if (s3_ssh3_parse_varint(&pos, end, &type) != S3_OK) {
                pos = msg;
                break;
            }

            if (type == S3_SSH3_MSG_CHANNEL_OPEN_CONFIRMATION) {

                s3_ssh3_msg_open_confirmation_t conf;

                if (s3_ssh3_msg_parse_open_confirmation(&pos, end, &conf) != S3_OK) {
                    pos = msg;
                    break;
                }

                s3_cli_ch_confirmed = 1;

                /* the channel is confirmed: the parked INIT rides */

                s3_cli_sftp_pump();

                continue;
            }

            if (type == S3_SSH3_MSG_CHANNEL_DATA) {

                s3_ssh3_msg_data_t data;

                if (s3_ssh3_msg_parse_data(&pos, end, &data) != S3_OK) {
                    pos = msg;
                    break;
                }

                if (s3_ssh3_sftp_cli_input(&s3_cli_sftp, data.data.data, data.data.len) != S3_OK) {
                    s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the sftp protocol violation");
                    s3_cli_rc = S3_CLI_EXIT_ERROR;
                    s3_quic_finalize_connection(((s3_quic_stream_t *)sc->data)->parent, 0,
                                                "sftp protocol violation");
                    return;
                }

                if (s3_ssh3_sftp_cli_finished(&s3_cli_sftp)) {
                    s3_cli_sftp_finish();
                    continue;
                }

                /* the replies woke the driver: the next train rides
                 * out at once, not on the tick */

                s3_cli_sftp_pump();

                continue;
            }

            s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the sftp unexpected message %llu",
                         (unsigned long long)type);
            s3_cli_rc = S3_CLI_EXIT_ERROR;
            s3_quic_finalize_connection(((s3_quic_stream_t *)sc->data)->parent, 0,
                                        "sftp unexpected message");
            return;
        }

        s3_cli_sftp_buf_len = (size_t)(end - pos);
        memmove(s3_cli_sftp_buf, pos, s3_cli_sftp_buf_len);

        if (s3_cli_verdict) {
            return;
        }
    }
}

/* === the -L forwards (the stage B) === */

/*
 * the -L spec of the URL form: tcp://[bind:]port/host/port, udp
 * likewise; the bind defaults to the loopback (the OpenSSH shape),
 * the target is the raw ipv4 the server dials (the wire extension
 * carries no names)
 */

/*
 * the bind side of a forward spec: the v4 literal, the bracketed v6
 * literal or the "*" wildcard (the listener binds it, the wire never
 * carries it); the port rides the caller value
 */

static s3_int_t
s3_cli_fwd_bind_parse(const char *host, size_t len, s3_cli_fwd_spec_t *spec)
{
    char text[128];
    char colon6[64];

    if (len == 0 || len >= sizeof(text)) {
        return S3_ERROR;
    }

    memcpy(text, host, len);
    text[len] = '\0';

    /* the "*" wildcard rides the any-bind of both families */

    if (strcmp(text, "*") == 0) {
        spec->bind_family = AF_INET;
        spec->bind_addr = htonl(INADDR_ANY);
        return S3_OK;
    }

    /* the bracketed ipv6: [::1] shape, the brackets strip */

    if (text[0] == '[') {

        size_t n = strlen(text);

        if (n < 2 || text[n - 1] != ']' || n - 2 >= sizeof(colon6)) {
            return S3_ERROR;
        }

        memcpy(colon6, text + 1, n - 2);
        colon6[n - 2] = '\0';

        {
            u_char v6[16];

            if (inet_pton(AF_INET6, colon6, v6) != 1) {
                return S3_ERROR;
            }

            spec->bind_family = AF_INET6;
            memcpy(spec->bind_v6, v6, 16);
        }

        return S3_OK;
    }

    {
        struct in_addr a;

        if (inet_pton(AF_INET, text, &a) != 1) {
            return S3_ERROR;
        }

        spec->bind_family = AF_INET;
        spec->bind_addr = (unsigned)a.s_addr;
    }

    return S3_OK;
}

/*
 * the -L local forward spec: the ssh2 canon [bind_address:]port:host:
 * hostport (TCP, repeatable, the bracketed v6 bind), the tcp:// scheme
 * head is the deprecated legacy alias, the udp:// head stays the
 * project extension (the datagram forwards); the target host is a v4
 * literal or a name resolved AF_INET client-side (the direct-tcp
 * target extension carries the raw ipv4)
 */

static s3_int_t
s3_cli_fwd_parse(const char *arg)
{
    s3_cli_fwd_spec_t *spec;
    const char        *s = arg;
    unsigned           kind = S3_CLI_FWD_TCP;
    unsigned           port, tport;

    if (strncmp(s, "tcp://", 6) == 0) {
        /* the legacy shape rides the same finalize, deprecated */

        s3_cli_note("ssh3: -L tcp:// is deprecated, use [bind:]port:host:hostport");
        s += 6;

    } else if (strncmp(s, "udp://", 6) == 0) {

        /* the project extension keeps its shape */

        s += 6;
        kind = S3_CLI_FWD_UDP;
    }

    if (kind == S3_CLI_FWD_UDP) {

        /* the legacy udp shape: [bind:]port/host/port */

        const char *slash, *slash2;
        char        authority[128], host[128];
        char       *colon;

        slash = strchr(s, '/');

        if (slash == NULL || slash == s || (size_t)(slash - s) >= sizeof(authority)) {
            fprintf(stderr, "ssh3: -L wants udp://[bind:]port/host/port\n");
            return S3_ERROR;
        }

        memcpy(authority, s, (size_t)(slash - s));
        authority[slash - s] = '\0';

        s = slash + 1;
        slash2 = strchr(s, '/');

        if (slash2 == NULL || slash2 == s || (size_t)(slash2 - s) >= sizeof(host) ||
            strlen(slash2 + 1) == 0 || strlen(slash2 + 1) > 5) {
            fprintf(stderr, "ssh3: -L wants udp://[bind:]port/host/port\n");
            return S3_ERROR;
        }

        memcpy(host, s, (size_t)(slash2 - s));
        host[slash2 - s] = '\0';

        colon = strchr(authority, ':');

        if (s3_cli_fwd_count >= S3_CLI_FWD_MAX) {
            fprintf(stderr, "ssh3: too many -L forwards\n");
            return S3_ERROR;
        }

        spec = &s3_cli_fwd_specs[s3_cli_fwd_count];

        memset(spec, 0, sizeof(*spec));

        spec->kind = S3_CLI_FWD_UDP;

        if (colon != NULL) {
            *colon = '\0';

            if (colon == authority ||
                s3_cli_fwd_bind_parse(authority, (size_t)(colon - authority), spec) != S3_OK) {
                fprintf(stderr, "ssh3: -L bind %s is not an address\n", authority);
                return S3_ERROR;
            }

            port = (unsigned)atoi(colon + 1);

        } else {
            spec->bind_family = AF_INET;
            spec->bind_addr = htonl(INADDR_LOOPBACK);
            port = (unsigned)atoi(authority);
        }

        if (port == 0 || port > 65535) {
            fprintf(stderr, "ssh3: -L bad bind port in %s\n", arg);
            return S3_ERROR;
        }

        spec->bind_port = port;

        {
            struct in_addr a;

            if (inet_pton(AF_INET, host, &a) != 1) {
                fprintf(stderr, "ssh3: -L target %s:%s is not an ipv4 socket\n", host, slash2 + 1);
                return S3_ERROR;
            }

            spec->target_addr = (unsigned)a.s_addr;
        }

        tport = (unsigned)atoi(slash2 + 1);

        if (tport == 0 || tport > 65535) {
            fprintf(stderr, "ssh3: -L target %s:%s is not an ipv4 socket\n", host, slash2 + 1);
            return S3_ERROR;
        }

        spec->target_port = tport;
        snprintf(spec->text, sizeof(spec->text), "%s", arg);

        s3_cli_fwd_count++;

        return S3_OK;
    }

    /*
     * the canon (and the deprecated tcp:// through it): the colons
     * split outside the brackets, the bind side brackets v6
     */

    {

        const char *cpos[3];
        unsigned    ncol = 0;
        unsigned    in_brackets = 0;
        const char *p = s;
        const char *bind_f = NULL, *port_f, *host_f, *tport_f;
        size_t      bind_len = 0, port_len, host_len, tport_len;

        while (*p != '\0') {

            if (*p == '[') {
                in_brackets = 1;

            } else if (*p == ']') {
                in_brackets = 0;

            } else if (*p == ':' && !in_brackets) {

                if (ncol >= 3) {
                    fprintf(stderr, "ssh3: -L wants [bind:]port:host:hostport\n");
                    return S3_ERROR;
                }

                cpos[ncol++] = p;
            }

            p++;
        }

        if (ncol == 2) {

            /* port:host:hostport, the loopback bind implied */

            port_f = s;
            port_len = (size_t)(cpos[0] - s);
            host_f = cpos[0] + 1;
            host_len = (size_t)(cpos[1] - cpos[0] - 1);
            tport_f = cpos[1] + 1;
            tport_len = strlen(tport_f);

        } else if (ncol == 3) {

            /* bind:port:host:hostport */

            bind_f = s;
            bind_len = (size_t)(cpos[0] - s);
            port_f = cpos[0] + 1;
            port_len = (size_t)(cpos[1] - cpos[0] - 1);
            host_f = cpos[1] + 1;
            host_len = (size_t)(cpos[2] - cpos[1] - 1);
            tport_f = cpos[2] + 1;
            tport_len = strlen(tport_f);

        } else {
            fprintf(stderr, "ssh3: -L wants [bind:]port:host:hostport\n");
            return S3_ERROR;
        }

        /* the port fields: decimal digits only, the uint16 range */

        port = 0;

        {

            size_t k;

            for (k = 0; k < port_len; k++) {

                if (port_f[k] < '0' || port_f[k] > '9' || port > 6553) {
                    port = 0;
                    break;
                }

                port = port * 10 + (unsigned)(port_f[k] - '0');
            }

            if (k != port_len || port == 0 || port > 65535) {
                fprintf(stderr, "ssh3: -L bad bind port in %s\n", arg);
                return S3_ERROR;
            }
        }

        tport = 0;

        {

            size_t k;

            for (k = 0; k < tport_len; k++) {

                if (tport_f[k] < '0' || tport_f[k] > '9' || tport > 6553) {
                    tport = 0;
                    break;
                }

                tport = tport * 10 + (unsigned)(tport_f[k] - '0');
            }

            if (k != tport_len || tport == 0 || tport > 65535) {
                fprintf(stderr, "ssh3: -L bad target port in %s\n", arg);
                return S3_ERROR;
            }
        }

        if (s3_cli_fwd_count >= S3_CLI_FWD_MAX) {
            fprintf(stderr, "ssh3: too many -L forwards\n");
            return S3_ERROR;
        }

        spec = &s3_cli_fwd_specs[s3_cli_fwd_count];

        memset(spec, 0, sizeof(*spec));

        spec->kind = S3_CLI_FWD_TCP;

        /* the bind side: absent keeps the loopback */

        if (bind_f == NULL) {
            spec->bind_family = AF_INET;
            spec->bind_addr = htonl(INADDR_LOOPBACK);

        } else if (s3_cli_fwd_bind_parse(bind_f, bind_len, spec) != S3_OK) {
            fprintf(stderr, "ssh3: -L bind is not an address: %.*s\n", (int)bind_len, bind_f);
            return S3_ERROR;
        }

        spec->bind_port = port;

        /* the target host: a v4 literal or a name resolved AF_INET */

        {

            struct sockaddr_in sa;
            struct addrinfo    hints, *res = NULL;
            char               thtext[128];

            if (host_len == 0 || host_len >= sizeof(thtext)) {
                fprintf(stderr, "ssh3: -L bad target host in %s\n", arg);
                return S3_ERROR;
            }

            memcpy(thtext, host_f, host_len);
            thtext[host_len] = '\0';

            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_DGRAM;

            if (inet_pton(AF_INET, thtext, &sa.sin_addr) == 1) {
                spec->target_addr = (unsigned)sa.sin_addr.s_addr;

            } else if (getaddrinfo(thtext, NULL, &hints, &res) == 0 && res != NULL) {

                memcpy(&sa, res->ai_addr, sizeof(sa));
                spec->target_addr = (unsigned)sa.sin_addr.s_addr;

                freeaddrinfo(res);

            } else {
                fprintf(stderr, "ssh3: the -L target %s resolves nowhere\n", thtext);
                return S3_ERROR;
            }
        }

        spec->target_port = tport;
        snprintf(spec->text, sizeof(spec->text), "%s", arg);

        s3_cli_fwd_count++;
    }

    return S3_OK;
}

/*
 * the -D dynamic forward spec: [bind:]port, the bind defaults to the
 * loopback (the ssh2 shape, repeatable); the listener speaks the
 * SOCKS5 CONNECT (the SOCKS4 fallback) and bridges every request
 * target into the direct-tcp channels of the same conversation
 */

static s3_int_t
s3_cli_socks_parse(const char *arg)
{
    s3_cli_fwd_spec_t *spec;
    const char        *colon = NULL, *p = arg;
    unsigned           in_brackets = 0, port;

    while (*p != '\0') {

        if (*p == '[') {
            in_brackets = 1;

        } else if (*p == ']') {
            in_brackets = 0;

        } else if (*p == ':' && !in_brackets) {
            colon = p;
            break;
        }

        p++;
    }

    if (s3_cli_fwd_count >= S3_CLI_FWD_MAX) {
        fprintf(stderr, "ssh3: too many -D forwards\n");
        return S3_ERROR;
    }

    spec = &s3_cli_fwd_specs[s3_cli_fwd_count];

    memset(spec, 0, sizeof(*spec));

    spec->kind = S3_CLI_FWD_SOCKS;

    if (colon != NULL) {

        if (s3_cli_fwd_bind_parse(arg, (size_t)(colon - arg), spec) != S3_OK) {
            fprintf(stderr, "ssh3: -D bind is not an address: %.*s\n", (int)(colon - arg), arg);
            return S3_ERROR;
        }

        port = (unsigned)atoi(colon + 1);

    } else {
        spec->bind_family = AF_INET;
        spec->bind_addr = htonl(INADDR_LOOPBACK);
        port = (unsigned)atoi(arg);
    }

    if (port == 0 || port > 65535) {
        fprintf(stderr, "ssh3: -D bad port in %s\n", arg);
        return S3_ERROR;
    }

    spec->bind_port = port;

    snprintf(spec->text, sizeof(spec->text), "socks://%s", arg);

    s3_cli_fwd_count++;

    return S3_OK;
}

/*
 * the listeners of the -L specs: the tcp ones listen and register the
 * accept reads, the udp ones bind and register the datagram reads
 */

static s3_int_t
s3_cli_fwd_listeners_start(void)
{
    unsigned i;

    for (i = 0; i < s3_cli_fwd_count; i++) {

        s3_cli_fwd_spec_t *spec = &s3_cli_fwd_specs[i];
        SOCKET             fd;
        s3_connection_t   *c;
        unsigned           is_stream = (spec->kind != S3_CLI_FWD_UDP);
        int                af = (spec->bind_family == AF_INET6) ? AF_INET6 : AF_INET;

        fd = (is_stream) ? socket(af, SOCK_STREAM, 0) : socket(af, SOCK_DGRAM, 0);

        if (fd == INVALID_SOCKET) {
            s3_log_error(S3_LOG_ERR, &s3_cli_log, s3_socket_errno, "socket() failed for %s",
                         spec->text);
            return S3_ERROR;
        }

        if (af == AF_INET6) {

            struct sockaddr_in6 sa6;

            memset(&sa6, 0, sizeof(sa6));

            sa6.sin6_family = AF_INET6;
            sa6.sin6_port = htons((u_short)spec->bind_port);
            memcpy(&sa6.sin6_addr, spec->bind_v6, 16);

            if (bind(fd, (struct sockaddr *)&sa6, sizeof(sa6)) != 0) {
                s3_log_error(S3_LOG_ERR, &s3_cli_log, s3_socket_errno, "bind() failed for %s",
                             spec->text);
                closesocket(fd);
                return S3_ERROR;
            }

        } else {

            struct sockaddr_in sa;

            memset(&sa, 0, sizeof(sa));

            sa.sin_family = AF_INET;
            sa.sin_addr.s_addr = spec->bind_addr;
            sa.sin_port = htons((u_short)spec->bind_port);

            if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
                s3_log_error(S3_LOG_ERR, &s3_cli_log, s3_socket_errno, "bind() failed for %s",
                             spec->text);
                closesocket(fd);
                return S3_ERROR;
            }
        }

        if (is_stream && listen(fd, 8) != 0) {
            s3_log_error(S3_LOG_ERR, &s3_cli_log, s3_socket_errno, "listen() failed for %s",
                         spec->text);
            closesocket(fd);
            return S3_ERROR;
        }

        if (s3_nonblocking(fd) != S3_OK) {
            closesocket(fd);
            return S3_ERROR;
        }

        c = s3_get_connection(&s3_cli_ctx, fd);

        if (c == NULL) {
            closesocket(fd);
            return S3_ERROR;
        }

        c->read->handler = (spec->kind == S3_CLI_FWD_UDP)      ? s3_cli_fwd_udp_local_read
                           : (spec->kind == S3_CLI_FWD_SOCKS) ? s3_cli_fwd_socks_accept
                                                              : s3_cli_fwd_tcp_accept;
        c->read->data = c; /* the select module contract: data is the conn */

        /* the spec index rides the free data of the raw connection */

        c->data = (void *)(uintptr_t)i;

        c->read->active = 1;

        if (s3_event_actions.add_event(c->read, S3_READ_EVENT, 0) != S3_OK) {
            closesocket(fd);
            return S3_ERROR;
        }

        if (is_stream) {
            s3_cli_fwd_listen[i] = fd;

        } else {
            s3_cli_fwd_udp[i].used = 1;
            s3_cli_fwd_udp[i].fd = fd;
            s3_cli_fwd_udp[i].evc = c;
        }

        s3_log_error(S3_LOG_INFO, &s3_cli_log, 0, "forwarding %s", spec->text);
    }

    return S3_OK;
}

/* the parked buffer growth of the bridges (16 KiB steps) */

static s3_int_t
s3_cli_fwd_park_grow(u_char **buf, size_t *cap, size_t need)
{
    u_char *grown;
    size_t  want = *cap ? *cap : 16384;

    if (need <= *cap) {
        return S3_OK;
    }

    while (want < need) {
        want += 16384;
    }

    grown = realloc(*buf, want);

    if (grown == NULL) {
        return S3_ERROR;
    }

    *buf = grown;
    *cap = want;

    return S3_OK;
}

/* the full drop of one bridge: the socket and the channel go, the
 * slot returns to the accept budget */

static void
s3_cli_fwd_tcp_drop(s3_cli_fwd_tcp_conn_t *fc)
{
    if (fc->dead) {
        return;
    }

    fc->dead = 1;

    if (fc->evc != NULL) {
        s3_close_connection(fc->evc);
        fc->evc = NULL;
        fc->fd = INVALID_SOCKET; /* the close_connection owns the fd already */
    }

    if (fc->fd != INVALID_SOCKET) {
        closesocket(fc->fd);
        fc->fd = INVALID_SOCKET;
    }

    if (fc->chan != NULL) {

        /* the quic stream ops ride the live connection only: the
         * idle close tears the streams down first, the cleanup of
         * the dead stream state would deref it */

        if (s3_cli_conn != NULL && s3_quic_get_connection(s3_cli_conn) != NULL) {
            (void)s3_quic_shutdown_stream(fc->chan, S3_RDWR_SHUTDOWN);
            s3_close_connection(fc->chan);
        }

        fc->chan = NULL;
    }

    free(fc->frame);
    free(fc->chan_acc);
    free(fc->to_chan);
    free(fc->to_local);

    fc->used = 0;
}

/*
 * the parked drains of one bridge: the direct-tcp header first, the
 * 94 frame tail, the parked payload of the local direction; the tick
 * and the write events call it
 */

static void
s3_cli_fwd_tcp_flush(s3_cli_fwd_tcp_conn_t *fc)
{
    ssize_t m;

    if (fc->dead) {
        return;
    }

    /* the parked header of the channel */

    if (fc->chan != NULL && !fc->hdr_sent && fc->hdr_len > 0) {

        m = s3_quic_stream_send(fc->chan, fc->hdr, fc->hdr_len);

        if (m == (ssize_t)S3_AGAIN) {
            return;
        }

        if (m <= 0) {
            s3_cli_fwd_tcp_drop(fc);
            return;
        }

        fc->hdr_sent = 1;
    }

    /* the payload into the channel: the 94 frames under the channel
     * maxPacketSize, a partial send parks the tail; the frames ride
     * behind the 91 confirmation (the header goes at once) */

    while (fc->chan != NULL && fc->chan_fin == 0 && fc->confirmed &&
           (fc->to_chan_len > 0 || fc->frame_sent < fc->frame_total)) {

        if (fc->frame_sent == fc->frame_total) {

            u_char *p;
            size_t  chunk = s3_ssh3_channel_chunk_size(S3_CLI_CHANNEL_MAX_PACKET, 0);

            if (chunk > fc->to_chan_len) {
                chunk = fc->to_chan_len;
            }

            p = fc->frame;
            p = (u_char *)s3_ssh3_encode_varint(p, S3_SSH3_MSG_CHANNEL_DATA);
            p = (u_char *)s3_ssh3_encode_varint(p, chunk);
            memcpy(p, fc->to_chan, chunk);

            fc->frame_total = (size_t)(p - fc->frame) + chunk;
            fc->frame_sent = 0;

            memmove(fc->to_chan, fc->to_chan + chunk, fc->to_chan_len - chunk);
            fc->to_chan_len -= chunk;
        }

        m = s3_quic_stream_send(fc->chan, fc->frame + fc->frame_sent,
                                fc->frame_total - fc->frame_sent);

        if (m == (ssize_t)S3_AGAIN) {
            return;
        }

        if (m <= 0) {
            s3_cli_fwd_tcp_drop(fc);
            return;
        }

        fc->frame_sent += (size_t)m;
    }

    /* the local eof rides after the park: the fin cannot jump the
     * queued payload (the quic layer marks the stream DATA_SENT at
     * once, the parked bytes would die behind it) */

    if (fc->local_eof && !fc->chan_fin_sent && fc->chan != NULL && fc->to_chan_len == 0 &&
        fc->frame_sent == fc->frame_total) {
        (void)s3_quic_shutdown_stream(fc->chan, S3_WRITE_SHUTDOWN);
        fc->chan_fin_sent = 1;
    }

    /* the parked payload into the local socket */

    while (!fc->dead && fc->to_local_len > 0) {

        int n = (int)send(fc->fd, (const char *)fc->to_local, (int)fc->to_local_len, 0);

        if (n > 0) {
            memmove(fc->to_local, fc->to_local + n, fc->to_local_len - (size_t)n);
            fc->to_local_len -= (size_t)n;
            continue;
        }

        /* the local socket still blocks, the tick retries */

        break;
    }
}

/*
 * the channel reader of one bridge: the 91 confirms (the parked
 * payload rides), the 94 payloads go to the local socket; the fin
 * half-closes the local write side
 */

static void
s3_cli_fwd_tcp_chan_read(s3_event_t *ev)
{
    s3_cli_fwd_tcp_conn_t *fc = ev->data;

    if (fc->dead) {
        return;
    }

    for (;;) {

        ssize_t n;

        if (fc->chan_acc_len == fc->chan_acc_cap) {

            size_t  cap;
            u_char *grown;

            /* the accumulator bound: a full buffer with no complete
             * frame inside is a peer trickling bytes */

            if (fc->chan_acc_cap >= S3_CLI_FWD_PARK_MAX) {
                s3_cli_fwd_tcp_drop(fc);
                return;
            }

            cap = fc->chan_acc_cap + 262144;

            grown = realloc(fc->chan_acc, cap);

            if (grown == NULL) {
                s3_cli_fwd_tcp_drop(fc);
                return;
            }

            fc->chan_acc = grown;
            fc->chan_acc_cap = cap;
        }

        n = fc->chan->recv(fc->chan, fc->chan_acc + fc->chan_acc_len,
                           fc->chan_acc_cap - fc->chan_acc_len);

        if (n == (ssize_t)S3_AGAIN) {
            return;
        }

        if (n == 0) {

            /* the server fin: the target closed the write side, the
             * local write side closes (the half-close) */

            fc->chan_fin = 1;

            (void)shutdown(fc->fd, SD_SEND);

            if (fc->local_eof) {
                s3_cli_fwd_tcp_drop(fc);
            }

            return;
        }

        if (n < 0) {
            s3_cli_fwd_tcp_drop(fc);
            return;
        }

        fc->chan_acc_len += (size_t)n;

        {
            const u_char *pos = fc->chan_acc;
            const u_char *end = fc->chan_acc + fc->chan_acc_len;

            while (pos < end) {

                const u_char *msg = pos;
                uint64_t      type;

                if (s3_ssh3_parse_varint(&pos, end, &type) != S3_OK) {
                    pos = msg;
                    break;
                }

                if (type == S3_SSH3_MSG_CHANNEL_OPEN_CONFIRMATION) {

                    s3_ssh3_msg_open_confirmation_t conf;

                    if (fc->confirmed) {
                        s3_cli_fwd_tcp_drop(fc);
                        return;
                    }

                    if (s3_ssh3_msg_parse_open_confirmation(&pos, end, &conf) != S3_OK) {
                        pos = msg;
                        break;
                    }

                    fc->confirmed = 1;

                    /* the confirmation opens the pump: the parked
                     * payload rides at once */

                    s3_cli_fwd_tcp_flush(fc);

                    if (fc->dead) {
                        return;
                    }

                    continue;
                }

                if (type == S3_SSH3_MSG_CHANNEL_DATA) {

                    s3_ssh3_msg_data_t data;
                    size_t             off = 0;

                    if (!fc->confirmed) {
                        s3_cli_fwd_tcp_drop(fc);
                        return;
                    }

                    if (s3_ssh3_msg_parse_data(&pos, end, &data) != S3_OK) {
                        pos = msg;
                        break;
                    }

                    /* the payload parks or rides the local socket */

                    while (off < data.data.len) {

                        int m = (int)send(fc->fd, (const char *)data.data.data + off,
                                          (int)(data.data.len - off), 0);

                        if (m > 0) {
                            off += (size_t)m;
                            continue;
                        }

                        /* the local socket blocked: the rest parks */

                        if (fc->to_local_len + (data.data.len - off) > S3_CLI_FWD_PARK_MAX) {
                            s3_cli_fwd_tcp_drop(fc);
                            return;
                        }

                        if (s3_cli_fwd_park_grow(&fc->to_local, &fc->to_local_cap,
                                                 fc->to_local_len + (data.data.len - off)) !=
                            S3_OK) {
                            s3_cli_fwd_tcp_drop(fc);
                            return;
                        }

                        memcpy(fc->to_local + fc->to_local_len, data.data.data + off,
                               data.data.len - off);
                        fc->to_local_len += data.data.len - off;
                        off = data.data.len;
                    }

                    continue;
                }

                /* the other channel messages do not exist here */

                s3_cli_fwd_tcp_drop(fc);
                return;
            }

            fc->chan_acc_len = (size_t)(end - pos);
            memmove(fc->chan_acc, pos, fc->chan_acc_len);
        }

        if (fc->dead) {
            return;
        }
    }
}

/*
 * the local reader of one bridge: the socket bytes wrap into the 94
 * frames, the eof sends the channel fin (the half-close)
 */

static void
s3_cli_fwd_tcp_local_read(s3_event_t *ev)
{
    s3_connection_t       *c = ev->data;
    s3_cli_fwd_tcp_conn_t *fc = (s3_cli_fwd_tcp_conn_t *)c->data;
    u_char                 buf[S3_CLI_FWD_CHUNK];

    if (fc->dead || fc->local_eof) {
        return;
    }

    for (;;) {

        int n = recv(fc->fd, (char *)buf, sizeof(buf), 0);

        if (n > 0) {

            if (fc->to_chan_len + (size_t)n > S3_CLI_FWD_PARK_MAX) {
                s3_cli_fwd_tcp_drop(fc);
                return;
            }

            if (s3_cli_fwd_park_grow(&fc->to_chan, &fc->to_chan_cap, fc->to_chan_len + (size_t)n) !=
                S3_OK) {
                s3_cli_fwd_tcp_drop(fc);
                return;
            }

            memcpy(fc->to_chan + fc->to_chan_len, buf, (size_t)n);
            fc->to_chan_len += (size_t)n;

            s3_cli_fwd_tcp_flush(fc);

            if (fc->dead) {
                return;
            }

            continue;
        }

        if (n == 0 || s3_socket_errno != S3_EAGAIN) {

            /* the eof or a broken local socket: the fin rides the
             * channel when the parked payload drained (the quic fin
             * jumps the queue otherwise, the parked bytes die) */

            fc->local_eof = 1;

            (void)s3_event_actions.del_event(fc->evc->read, S3_READ_EVENT, 0);

            if (fc->chan != NULL && fc->to_chan_len == 0 && fc->frame_sent == fc->frame_total) {
                (void)s3_quic_shutdown_stream(fc->chan, S3_WRITE_SHUTDOWN);
                fc->chan_fin_sent = 1;
            }

            if (fc->chan_fin) {
                s3_cli_fwd_tcp_drop(fc);
            }

            return;
        }

        /* WSAEWOULDBLOCK: done for now */

        return;
    }
}

/*
 * the accept of a tcp listener: one bridge per accepted socket, the
 * direct-tcp header with the target extension rides at once
 */

/*
 * the direct-tcp channel open of one bridge conn: the header and the
 * target extension build once, the send parks on the write readiness
 * (the per-conn target: the -L spec names it, the -D socks request
 * does)
 */

static s3_int_t
s3_cli_fwd_conn_open(s3_cli_fwd_tcp_conn_t *fc, unsigned t_addr, unsigned t_port)
{
    s3_ssh3_channel_t        h;
    s3_ssh3_forward_target_t t;
    u_char                  *p;
    ssize_t                  m;

    fc->chan = s3_quic_open_stream(s3_cli_conn, 1);

    if (fc->chan == NULL) {
        return S3_ERROR;
    }

    fc->frame = malloc(S3_CLI_FWD_FRAME);

    if (fc->frame == NULL) {
        return S3_ERROR;
    }

    memset(&h, 0, sizeof(h));

    h.conversation_stream_id = s3_cli_conv_id;
    h.max_packet_size = S3_CLI_CHANNEL_MAX_PACKET;
    h.type.data = (u_char *)S3_SSH3_CHANNEL_TYPE_DIRECT_TCP;
    h.type.len = strlen(S3_SSH3_CHANNEL_TYPE_DIRECT_TCP);

    t.family = 4;
    t.ip_len = 4;
    memcpy(t.ip, &t_addr, 4);
    t.port = (uint16_t)t_port;

    p = fc->hdr;
    p = (u_char *)s3_ssh3_channel_build_header(p, &h);
    p = s3_ssh3_forward_build_target(p, &t);

    fc->hdr_len = (size_t)(p - fc->hdr);

    m = s3_quic_stream_send(fc->chan, fc->hdr, fc->hdr_len);

    if (m == (ssize_t)S3_AGAIN) {

        /* the tiny header parks, the flush retries */

    } else if (m <= 0) {
        return S3_ERROR;

    } else {
        fc->hdr_sent = 1;
    }

    return S3_OK;
}

static void
s3_cli_fwd_tcp_accept(s3_event_t *ev)
{
    s3_connection_t       *lc = ev->data;
    unsigned               spec = (unsigned)(uintptr_t)lc->data;
    s3_cli_fwd_tcp_conn_t *fc = NULL;
    unsigned               k;

    for (;;) {

        SOCKET             fd;
        struct sockaddr_in peer;
        socklen_t          plen = sizeof(peer);
        s3_connection_t   *c;

        fd = accept(s3_cli_fwd_listen[spec], (struct sockaddr *)&peer, &plen);

        if (fd == INVALID_SOCKET) {

            /* WSAEWOULDBLOCK or a transient: the next event retries */

            return;
        }

        for (k = 0; k < S3_CLI_FWD_TCP_CONNS; k++) {

            if (!s3_cli_fwd_conns[k].used) {
                fc = &s3_cli_fwd_conns[k];
                break;
            }
        }

        if (fc == NULL) {

            /* the bridge budget is out: the socket refuses */

            closesocket(fd);
            continue;
        }

        if (s3_nonblocking(fd) != S3_OK) {
            closesocket(fd);
            continue;
        }

        c = s3_get_connection(&s3_cli_ctx, fd);

        if (c == NULL) {
            closesocket(fd);
            continue;
        }

        memset(fc, 0, sizeof(*fc));

        fc->used = 1;
        fc->spec = spec;
        fc->fd = fd;
        fc->evc = c;

        if (s3_cli_fwd_conn_open(fc, s3_cli_fwd_specs[spec].target_addr,
                                 s3_cli_fwd_specs[spec].target_port) != S3_OK) {
            s3_cli_fwd_tcp_drop(fc);
            continue;
        }

        fc->chan->read->handler = s3_cli_fwd_tcp_chan_read;
        fc->chan->read->data = fc;
        fc->chan->read->active = 1;

        c->read->handler = s3_cli_fwd_tcp_local_read;
        c->read->data = c; /* the select module contract: data is the conn */
        c->data = fc;      /* the bridge rides the free data of the raw conn */
        c->read->active = 1;

        if (s3_event_actions.add_event(c->read, S3_READ_EVENT, 0) != S3_OK) {
            s3_cli_fwd_tcp_drop(fc);
            continue;
        }
    }
}

/*
 * the -D socks accept: the same conn budget and local setup as the
 * -L accept, the channel opens only after the SOCKS handshake names
 * the target (RFC 1928, the CONNECT command; the SOCKS4 request is
 * the fallback shape)
 */

static void
s3_cli_fwd_socks_accept(s3_event_t *ev)
{
    s3_connection_t       *lc = ev->data;
    unsigned               spec = (unsigned)(uintptr_t)lc->data;
    s3_cli_fwd_tcp_conn_t *fc = NULL;
    unsigned               k;

    for (;;) {

        SOCKET             fd;
        struct sockaddr_in peer;
        socklen_t          plen = sizeof(peer);
        s3_connection_t   *c;

        fd = accept(s3_cli_fwd_listen[spec], (struct sockaddr *)&peer, &plen);

        if (fd == INVALID_SOCKET) {
            return;
        }

        for (k = 0; k < S3_CLI_FWD_TCP_CONNS; k++) {

            if (!s3_cli_fwd_conns[k].used) {
                fc = &s3_cli_fwd_conns[k];
                break;
            }
        }

        if (fc == NULL) {
            closesocket(fd);
            continue;
        }

        if (s3_nonblocking(fd) != S3_OK) {
            closesocket(fd);
            continue;
        }

        c = s3_get_connection(&s3_cli_ctx, fd);

        if (c == NULL) {
            closesocket(fd);
            continue;
        }

        memset(fc, 0, sizeof(*fc));

        fc->used = 1;
        fc->spec = spec;
        fc->fd = fd;
        fc->evc = c;
        fc->socks = 1;
        fc->socks_step = S3_CLI_SOCKS_STEP_GREET;

        c->read->handler = s3_cli_fwd_socks_local_read;
        c->read->data = c;
        c->data = fc;
        c->read->active = 1;

        if (s3_event_actions.add_event(c->read, S3_READ_EVENT, 0) != S3_OK) {
            s3_cli_fwd_tcp_drop(fc);
            continue;
        }
    }
}

/* the socks failure reply of the v5 shape (the code rides the
 * RFC 1928 table), the conn drops after it */

static void
s3_cli_fwd_socks_fail(s3_cli_fwd_tcp_conn_t *fc, u_char code)
{
    u_char reply[8] = {5, 0, 0, 1, 0, 0, 0, 0};

    reply[1] = code;

    (void)send(fc->fd, reply, sizeof(reply), 0);
    fc->dead = 1;
}

/* the socks success reply: the v5 form rides a zero bind addr, the
 * v4 form the granted port and the target ip */

static void
s3_cli_fwd_socks_ok(s3_cli_fwd_tcp_conn_t *fc, unsigned v4)
{
    u_char reply[10];

    memset(reply, 0, sizeof(reply));

    reply[0] = 0;
    reply[1] = 0x5a;
    reply[2] = (u_char)((fc->t_port >> 8) & 0xff);
    reply[3] = (u_char)(fc->t_port & 0xff);
    reply[4] = (u_char)(v4 & 0xff);
    reply[5] = (u_char)((v4 >> 8) & 0xff);
    reply[6] = (u_char)((v4 >> 16) & 0xff);
    reply[7] = (u_char)((v4 >> 24) & 0xff);

    (void)send(fc->fd, reply, 8, 0);
}

/* the client-side resolve of the socks target (the wire rides the
 * raw ipv4, the names never cross the channel) */

static s3_int_t
s3_cli_fwd_socks_resolve(s3_cli_fwd_tcp_conn_t *fc, const char *host)
{
    struct addrinfo    hints, *res = NULL;
    struct sockaddr_in sa;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    if (inet_pton(AF_INET, host, &sa.sin_addr) == 1) {
        fc->t_addr = (unsigned)sa.sin_addr.s_addr;
        return S3_OK;
    }

    if (getaddrinfo(host, NULL, &hints, &res) != 0 || res == NULL) {
        return S3_ERROR;
    }

    memcpy(&sa, res->ai_addr, sizeof(sa));
    fc->t_addr = (unsigned)sa.sin_addr.s_addr;

    freeaddrinfo(res);

    return S3_OK;
}

/*
 * the socks handshake pump: the greeting and the request parse out
 * of the accumulated bytes, the bridge arms once the target names
 * (the direct-tcp channel rides the same conn_open the -L shapes)
 */

static void
s3_cli_fwd_socks_local_read(s3_event_t *ev)
{
    s3_connection_t *c = ev->data;
    s3_cli_fwd_tcp_conn_t *fc = c->data;

    for (;;) {

        ssize_t n;

        n = recv(fc->fd, fc->socks_buf + fc->socks_len,
                 sizeof(fc->socks_buf) - fc->socks_len, 0);

        if (n < 0) {

            if (s3_socket_errno == S3_EAGAIN) {
                return;
            }

            s3_cli_fwd_tcp_drop(fc);
            return;
        }

        if (n == 0) {
            s3_cli_fwd_tcp_drop(fc);
            return;
        }

        fc->socks_len += (size_t)n;

        if (fc->socks_step == S3_CLI_SOCKS_STEP_GREET) {

            /* the v5 greeting: VER NMETHODS METHODS, the no-auth
             * method answers; the v4 request (VER 4) skips straight
             * to the fallback parse */

            if (fc->socks_len < 2) {
                return;
            }

            if (fc->socks_buf[0] == 4) {
                fc->socks_step = S3_CLI_SOCKS_STEP_V4;
                continue;
            }

            if (fc->socks_buf[0] != 5) {
                s3_cli_fwd_socks_fail(fc, 1);
                s3_cli_fwd_tcp_drop(fc);
                return;
            }

            if (fc->socks_len < (size_t)(2 + fc->socks_buf[1])) {
                return;
            }

            {
                u_char reply[2] = {5, 0};

                (void)send(fc->fd, reply, sizeof(reply), 0);
            }

            fc->socks_len = 0;
            fc->socks_step = S3_CLI_SOCKS_STEP_REQ;
            return;

        } else if (fc->socks_step == S3_CLI_SOCKS_STEP_REQ) {

            /* the v5 request: VER CMD RSV ATYP ADDR PORT, the
             * CONNECT only; the ipv4, the domain and the ipv6 atyp
             * parse (the ipv6 target refuses, the wire rides v4) */

            u_char  atyp;
            size_t  need;
            char    host[64];
            u_short port;

            if (fc->socks_len < 4) {
                return;
            }

            if (fc->socks_buf[0] != 5) {
                s3_cli_fwd_socks_fail(fc, 1);
                s3_cli_fwd_tcp_drop(fc);
                return;
            }

            if (fc->socks_buf[1] != 1) {
                s3_cli_fwd_socks_fail(fc, 7); /* the command not supported */
                s3_cli_fwd_tcp_drop(fc);
                return;
            }

            atyp = fc->socks_buf[3];

            if (atyp == 1) {
                need = 4 + 4 + 2;

                if (fc->socks_len < need) {
                    return;
                }

                snprintf(host, sizeof(host), "%u.%u.%u.%u", (unsigned)fc->socks_buf[4],
                         (unsigned)fc->socks_buf[5], (unsigned)fc->socks_buf[6],
                         (unsigned)fc->socks_buf[7]);

            } else if (atyp == 3) {

                u_char dlen = fc->socks_buf[4];

                need = 4 + 1 + (size_t)dlen + 2;

                if (fc->socks_len < need) {
                    return;
                }

                if (dlen == 0 || dlen >= sizeof(host)) {
                    s3_cli_fwd_socks_fail(fc, 1);
                    s3_cli_fwd_tcp_drop(fc);
                    return;
                }

                memcpy(host, fc->socks_buf + 5, dlen);
                host[dlen] = '\0';

            } else if (atyp == 4) {

                /* the v6 target: the resolve stays v4 in this wave */

                s3_cli_fwd_socks_fail(fc, 8); /* the address not supported */
                s3_cli_fwd_tcp_drop(fc);
                return;

            } else {
                s3_cli_fwd_socks_fail(fc, 1);
                s3_cli_fwd_tcp_drop(fc);
                return;
            }

            {
                size_t tail = need;

                port = (u_short)((fc->socks_buf[tail - 2] << 8) | fc->socks_buf[tail - 1]);
            }

            if (port == 0) {
                s3_cli_fwd_socks_fail(fc, 1);
                s3_cli_fwd_tcp_drop(fc);
                return;
            }

            if (s3_cli_fwd_socks_resolve(fc, host) != S3_OK) {
                s3_cli_fwd_socks_fail(fc, 4); /* the host unreachable */
                s3_cli_fwd_tcp_drop(fc);
                return;
            }

            fc->t_port = port;

            (void)send(fc->fd, (u_char *)"\005\000\000\001\000\000\000\000\000\000", 10, 0);

            fc->socks_len = 0;
            fc->socks_step = 3; /* the bridged shape, no parse left */

            if (s3_cli_fwd_conn_open(fc, fc->t_addr, fc->t_port) != S3_OK) {
                s3_cli_fwd_tcp_drop(fc);
                return;
            }

            fc->chan->read->handler = s3_cli_fwd_tcp_chan_read;
            fc->chan->read->data = fc;
            fc->chan->read->active = 1;

            /* the local read hands over to the bridge pump */

            c->read->handler = s3_cli_fwd_tcp_local_read;
            c->read->active = 1;

            return;

        } else if (fc->socks_step == S3_CLI_SOCKS_STEP_V4) {

            /* the socks4 request: VER CMD PORT(2) ADDR(4) USERID NUL,
             * the CONNECT only, the 0.0.0.x remote-id form stays
             * out (the plain v4 fallback) */

            size_t i;

            if (fc->socks_len < 8) {
                return;
            }

            if (fc->socks_buf[1] != 1) {
                s3_cli_fwd_tcp_drop(fc);
                return;
            }

            /* the userid rides to the NUL (the len bound guards) */

            for (i = 4; i < fc->socks_len && i < sizeof(fc->socks_buf); i++) {

                if (fc->socks_buf[i] == 0) {
                    break;
                }
            }

            if (i >= fc->socks_len) {
                return; /* the NUL waits in the next read */
            }

            {
                unsigned port = (unsigned)((fc->socks_buf[2] << 8) | fc->socks_buf[3]);
                unsigned addr = ((unsigned)fc->socks_buf[7] << 24) |
                                ((unsigned)fc->socks_buf[6] << 16) |
                                ((unsigned)fc->socks_buf[5] << 8) | (unsigned)fc->socks_buf[4];
                struct in_addr a;

                a.s_addr = addr;

                if (addr == 0 || port == 0) {
                    s3_cli_fwd_tcp_drop(fc);
                    return;
                }

                fc->t_addr = (unsigned)a.s_addr;
                fc->t_port = port;

                s3_cli_fwd_socks_ok(fc, a.s_addr);

                fc->socks_len = 0;
                fc->socks_step = 3;

                if (s3_cli_fwd_conn_open(fc, fc->t_addr, fc->t_port) != S3_OK) {
                    s3_cli_fwd_tcp_drop(fc);
                    return;
                }

                fc->chan->read->handler = s3_cli_fwd_tcp_chan_read;
                fc->chan->read->data = fc;
                fc->chan->read->active = 1;

                c->read->handler = s3_cli_fwd_tcp_local_read;
                c->read->active = 1;

                return;
            }

        } else {

            /* the bridged conn landed here late: the bytes ride the
             * bridge pump once */

            c->read->handler = s3_cli_fwd_tcp_local_read;
            c->read->active = 1;

            s3_cli_fwd_tcp_local_read(ev);

            return;
        }
    }
}

/*
 * the local datagram read of one udp forward: the source finds its
 * channel (one direct-udp per source address), the datagram rides
 * the QUIC DATAGRAM frame with the (conversation, channel) envelope
 */

static void
s3_cli_fwd_udp_local_read(s3_event_t *ev)
{
    s3_connection_t      *c = ev->data;
    unsigned              spec = (unsigned)(uintptr_t)c->data;
    s3_cli_fwd_udp_t     *uf = &s3_cli_fwd_udp[spec];
    s3_cli_fwd_spec_t    *sp = &s3_cli_fwd_specs[spec];
    u_char                buf[S3_CLI_FWD_UDP_DATAGRAM];
    struct sockaddr_in    from;
    socklen_t             flen = sizeof(from);
    s3_cli_fwd_udp_src_t *src = NULL;
    unsigned              k;

    for (;;) {

        int n = recvfrom(uf->fd, (char *)buf, sizeof(buf), 0, (struct sockaddr *)&from, &flen);

        if (n < 0) {

#if (S3_WIN32)
            if (s3_socket_errno == WSAEMSGSIZE) {

                /* the oversized datagram drops (the udp semantics) */

                continue;
            }
#endif

            /* the transient errors retry on the next event */

            return;
        }

        if (n == 0) {
            return;
        }

        for (k = 0; k < S3_CLI_FWD_UDP_SRCS; k++) {

            s3_cli_fwd_udp_src_t *s = &uf->srcs[k];

            if (s->used && s->src.sin_addr.s_addr == from.sin_addr.s_addr &&
                s->src.sin_port == from.sin_port) {
                src = s;
                break;
            }
        }

        if (src == NULL) {

            for (k = 0; k < S3_CLI_FWD_UDP_SRCS; k++) {

                if (!uf->srcs[k].used) {
                    src = &uf->srcs[k];
                    break;
                }
            }

            if (src == NULL) {

                /* the source budget is out: the datagram drops */

                continue;
            }

            memset(src, 0, sizeof(*src));

            src->used = 1;
            src->src = from;
            uf->src_count++;

            /* the direct-udp channel of the source opens here: the
             * header parks, the tick (and the confirmation read)
             * carry it out */

            src->chan = s3_quic_open_stream(s3_cli_conn, 1);

            if (src->chan == NULL) {
                src->used = 0;
                uf->src_count--;
                continue;
            }

            src->chan_id = ((s3_quic_stream_t *)src->chan->data)->id;

            {
                s3_ssh3_channel_t        h;
                s3_ssh3_forward_target_t t;
                u_char                  *p;

                memset(&h, 0, sizeof(h));

                h.conversation_stream_id = s3_cli_conv_id;
                h.max_packet_size = S3_CLI_CHANNEL_MAX_PACKET;
                h.type.data = (u_char *)S3_SSH3_CHANNEL_TYPE_DIRECT_UDP;
                h.type.len = strlen(S3_SSH3_CHANNEL_TYPE_DIRECT_UDP);

                t.family = 4;
                t.ip_len = 4;
                memcpy(t.ip, &sp->target_addr, 4);
                t.port = (uint16_t)sp->target_port;

                p = src->hdr_park;
                p = (u_char *)s3_ssh3_channel_build_header(p, &h);
                p = s3_ssh3_forward_build_target(p, &t);

                src->hdr_len = (size_t)(p - src->hdr_park);
            }

            src->chan->read->handler = s3_cli_fwd_udp_chan_read;
            src->chan->read->data = src;
            src->chan->read->active = 1;
        }

        /* the datagram rides at once on a confirmed channel, the
         * pre-91 datagrams park */

        if (!src->confirmed) {

            if (src->pend_count >= S3_CLI_FWD_UDP_PENDING) {
                continue;
            }

            {
                unsigned tail = (src->pend_head + src->pend_count) % S3_CLI_FWD_UDP_PENDING;

                memcpy(src->pend[tail], buf, (size_t)n);
                src->pend_len[tail] = (u_short)n;
                src->pend_count++;
            }

            continue;
        }

        {
            u_char  dg[S3_CLI_FWD_UDP_DATAGRAM + 16];
            u_char *p;

            p = s3_ssh3_dgram_encode(dg, s3_cli_conv_id, src->chan_id, buf, (size_t)n);

            (void)s3_quic_send_datagram(s3_cli_conn, dg, (size_t)(p - dg));
        }
    }
}

/*
 * the channel reader of a udp source: the 91 confirms, the parked
 * datagrams ride; anything else on the stream is a violation
 */

static void
s3_cli_fwd_udp_chan_read(s3_event_t *ev)
{
    s3_cli_fwd_udp_src_t *src = ev->data;
    u_char                buf[64];

    if (!src->used || src->confirmed) {
        return;
    }

    for (;;) {

        ssize_t n = src->chan->recv(src->chan, buf, sizeof(buf));

        if (n == (ssize_t)S3_AGAIN) {
            return;
        }

        if (n <= 0) {

            /* the fin or the error: the source dies with its channel */

            src->used = 0;
            s3_close_connection(src->chan);
            src->chan = NULL;

            return;
        }

        if (src->conf_len + (size_t)n > sizeof(src->conf_acc)) {

            /* only the tiny 91 lives here, more is a violation */

            src->used = 0;
            s3_close_connection(src->chan);
            src->chan = NULL;

            return;
        }

        memcpy(src->conf_acc + src->conf_len, buf, (size_t)n);
        src->conf_len += (size_t)n;

        {
            const u_char *pos = src->conf_acc;
            const u_char *end = src->conf_acc + src->conf_len;
            uint64_t      type;

            if (s3_ssh3_parse_varint(&pos, end, &type) != S3_OK) {
                return; /* a split type varint waits for the next recv */
            }

            if (type != S3_SSH3_MSG_CHANNEL_OPEN_CONFIRMATION) {
                src->used = 0;
                s3_close_connection(src->chan);
                src->chan = NULL;
                return;
            }

            {
                s3_ssh3_msg_open_confirmation_t conf;

                if (s3_ssh3_msg_parse_open_confirmation(&pos, end, &conf) != S3_OK) {
                    return; /* a split body waits */
                }

                src->confirmed = 1;
            }
        }
    }
}

/*
 * the incoming datagrams of the udp forwards: the envelope names the
 * conversation and the channel, the payload rides the source socket
 */

static void
s3_cli_fwd_datagram(s3_chain_t *data)
{
    u_char        flat[S3_CLI_FWD_UDP_DATAGRAM + 16];
    u_char       *p;
    size_t        len = 0;
    s3_chain_t   *cl;
    const u_char *pos, *end;
    uint64_t      csid, chid;
    s3_str_t      payload;
    unsigned      i, k;

    for (cl = data; cl != NULL; cl = cl->next) {
        len += s3_buf_size(cl->buf);
    }

    if (len == 0 || len > sizeof(flat)) {
        return;
    }

    p = flat;

    for (cl = data; cl != NULL; cl = cl->next) {
        p = s3_cpymem(p, cl->buf->pos, s3_buf_size(cl->buf));
    }

    pos = flat;
    end = flat + len;

    if (s3_ssh3_dgram_parse(&pos, end, &csid, &chid, &payload) != S3_OK) {
        return;
    }

    if (csid != s3_cli_conv_id) {
        return;
    }

    for (i = 0; i < s3_cli_fwd_count; i++) {

        s3_cli_fwd_udp_t *uf = &s3_cli_fwd_udp[i];

        if (!uf->used) {
            continue;
        }

        for (k = 0; k < S3_CLI_FWD_UDP_SRCS; k++) {

            s3_cli_fwd_udp_src_t *s = &uf->srcs[k];

            if (s->used && s->confirmed && s->chan_id == chid) {
                (void)sendto(uf->fd, (const char *)payload.data, (int)payload.len, 0,
                             (struct sockaddr *)&s->src, sizeof(s->src));
                return;
            }
        }
    }
}

/* the parked drains of the udp forwards: the channel headers and the
 * pre-91 datagrams ride here (the tick) */

static void
s3_cli_fwd_udp_pump(s3_cli_fwd_udp_t *uf)
{
    unsigned k;

    for (k = 0; k < S3_CLI_FWD_UDP_SRCS; k++) {

        s3_cli_fwd_udp_src_t *src = &uf->srcs[k];

        if (!src->used) {
            continue;
        }

        if (!src->hdr_sent) {

            ssize_t m = s3_quic_stream_send(src->chan, src->hdr_park, src->hdr_len);

            if (m == (ssize_t)S3_AGAIN) {
                return;
            }

            if (m <= 0) {
                src->used = 0;
                (void)s3_quic_shutdown_stream(src->chan, S3_RDWR_SHUTDOWN);
                s3_close_connection(src->chan);
                src->chan = NULL;
                uf->src_count--;
                continue;
            }

            src->hdr_sent = 1;
        }

        while (src->confirmed && src->pend_count > 0) {

            u_char  dg[S3_CLI_FWD_UDP_DATAGRAM + 16];
            u_char *p;

            p = s3_ssh3_dgram_encode(dg, s3_cli_conv_id, src->chan_id, src->pend[src->pend_head],
                                     src->pend_len[src->pend_head]);

            if (s3_quic_send_datagram(s3_cli_conn, dg, (size_t)(p - dg)) != S3_OK) {
                return;
            }

            src->pend_head = (src->pend_head + 1) % S3_CLI_FWD_UDP_PENDING;
            src->pend_count--;
        }
    }
}

/* the tick of the forward run: the tcp bridges and the udp sources
 * drain their parked bytes */

static void
s3_cli_fwd_tick(void)
{
    unsigned i;

    for (i = 0; i < S3_CLI_FWD_TCP_CONNS; i++) {

        if (s3_cli_fwd_conns[i].used) {
            s3_cli_fwd_tcp_flush(&s3_cli_fwd_conns[i]);
        }
    }

    for (i = 0; i < s3_cli_fwd_count; i++) {

        if (s3_cli_fwd_udp[i].used) {
            s3_cli_fwd_udp_pump(&s3_cli_fwd_udp[i]);
        }
    }
}

/* === the reverse port forwarding (-R): the client opens one
 * "reverse-forward" control channel per spec, the bind request rides
 * the channel data, every server-initiated forwarded-tcp/udp channel
 * whose header target matches a resolved spec bridges into the local
 * target (the reference client/reverse_forward.go shape) === */

/*
 * the fatal protocol break of the reverse run: the connection
 * finalizes with the reason, the main loop picks the rc up on its
 * liveness check (the sftp shape)
 */

static void
s3_cli_finalize(s3_connection_t *c)
{
    if (c != NULL && s3_quic_get_connection(c) != NULL) {
        s3_quic_finalize_connection(c, 0, "the reverse forward failed");
    }
}

/*
 * the spec parse of one -R argument: the reference shape
 * [bind:]port[/tcp|/udp]:host:port; the target resolves where the
 * client runs (a bad target refuses before anything is sent), the
 * canonical text rides the bind request
 */

static s3_int_t
s3_cli_rev_parse_spec(const char *arg)
{
    s3_ssh3_reverse_spec_t *spec;
    char                    text[64];

    /* the bare port (no target colons) is the stdio forward request,
     * the ssh2 shape this client does not serve -- the clean refusal
     * beats the generic parse error */

    if (strchr(arg, ':') == NULL) {
        fprintf(stderr, "ssh3: stdio forward is not supported\n");
        return S3_ERROR;
    }

    if (s3_cli_rspec_count >= S3_CLI_REV_MAX) {
        fprintf(stderr, "ssh3: too many -R forwards (the bound is %u)\n", S3_CLI_REV_MAX);
        return S3_ERROR;
    }

    spec = &s3_cli_rspec[s3_cli_rspec_count];

    if (s3_ssh3_reverse_parse_spec(arg, spec) != S3_OK) {
        fprintf(stderr, "ssh3: bad -R spec: %s\n", arg);
        return S3_ERROR;
    }

    if (s3_ssh3_reverse_resolve_target(spec, &s3_cli_rtarget[s3_cli_rspec_count]) != S3_OK) {
        fprintf(stderr, "ssh3: the -R target resolves nowhere: %s:%u\n", spec->target_host,
                (unsigned)spec->target_port);
        return S3_ERROR;
    }

    if (s3_ssh3_reverse_target_ntop(&s3_cli_rtarget[s3_cli_rspec_count], text, sizeof(text)) !=
        S3_OK) {
        fprintf(stderr, "ssh3: the -R target of %s:%u has no canonical text\n", spec->target_host,
                (unsigned)spec->target_port);
        return S3_ERROR;
    }

    s3_memcpy(s3_cli_rtarget_text[s3_cli_rspec_count], text, strlen(text) + 1);
    s3_cli_rspec_count++;

    return S3_OK;
}

/* the control channel of a stream connection, NULL when none rides it */

static s3_cli_rev_ctrl_t *
s3_cli_rev_ctrl_of(s3_connection_t *sc)
{
    unsigned i;

    for (i = 0; i < s3_cli_rspec_count; i++) {

        if (s3_cli_rev_ctrl[i].sc == sc) {
            return &s3_cli_rev_ctrl[i];
        }
    }

    return NULL;
}

/* the bridge of a channel id, NULL when none rides it */

static s3_cli_rev_bridge_t *
s3_cli_rev_bridge_of(uint64_t ch_id)
{
    unsigned i;

    for (i = 0; i < S3_CLI_REV_BRIDGES; i++) {

        if (s3_cli_rev_bridge[i].used && s3_cli_rev_bridge[i].ch_id == ch_id) {
            return &s3_cli_rev_bridge[i];
        }
    }

    return NULL;
}

/* the bridge of a stream connection, NULL when none rides it */

static s3_cli_rev_bridge_t *
s3_cli_rev_bridge_of_sc(s3_connection_t *sc)
{
    unsigned i;

    for (i = 0; i < S3_CLI_REV_BRIDGES; i++) {

        if (s3_cli_rev_bridge[i].used && s3_cli_rev_bridge[i].sc == sc) {
            return &s3_cli_rev_bridge[i];
        }
    }

    return NULL;
}

/*
 * the -R spec of the resolved target: the allow-list of the incoming
 * forwarded-* channels (a compromised server must not reach the local
 * endpoints uninvited); returns the spec index, -1 when nothing
 * matches
 */

static int
s3_cli_rev_spec_of(unsigned proto, const s3_ssh3_forward_target_t *t)
{
    unsigned i;

    for (i = 0; i < s3_cli_rspec_count; i++) {

        const s3_ssh3_forward_target_t *rt = &s3_cli_rtarget[i];

        if (s3_cli_rspec[i].proto != proto || rt->port != t->port) {
            continue;
        }

        /* the exact ip of the resolution, or the v4-mapped form the
         * server sends in the forwarded-* headers (the
         * net.IP.To16() shape: every v4 target rides the 16-byte
         * ::ffff:a.b.c.d, family 6) */

        if (rt->family == t->family && rt->ip_len == t->ip_len &&
            s3_memcmp(rt->ip, t->ip, t->ip_len) == 0) {
            return (int)i;
        }

        if (t->family == 6 && t->ip_len == 16 && rt->family == 4 && rt->ip_len == 4 &&
            s3_memcmp(t->ip, s3_cli_rev_v4_mapped_prefix, 12) == 0 &&
            s3_memcmp(t->ip + 12, rt->ip, 4) == 0) {
            return (int)i;
        }

        /* the plain v4 zero (the unspecified 0.0.0.0) matches too */

        if (t->ip_len == (t->family == 6 ? 16u : 4u)) {

            size_t z;

            for (z = 0; z < t->ip_len; z++) {

                if (t->ip[z] != 0) {
                    break;
                }
            }

            if (z == t->ip_len) {
                return (int)i;
            }
        }
    }

    return -1;
}

/*
 * one bridge dies: the socket and the stream close, the buffers free;
 * quic_alive=0 skips the stream ops (the idle close already tore the
 * streams down, the shutdown would deref the freed state)
 */

static void
s3_cli_rev_bridge_kill(s3_cli_rev_bridge_t *b, const char *why)
{
    if (why != NULL) {
        s3_log_error(S3_LOG_INFO, &s3_cli_log, 0, "the reverse bridge down: %s", why);
    }

    if (b->fd != INVALID_SOCKET) {
        (void)closesocket(b->fd);
        b->fd = INVALID_SOCKET;
    }

    if (b->sc != NULL) {

        if (s3_cli_conn == NULL || s3_quic_get_connection(s3_cli_conn) == NULL) {
            b->sc = NULL; /* the stream is the idle-close loss, the ops ride dead */

        } else {
            (void)s3_quic_shutdown_stream(b->sc, S3_RDWR_SHUTDOWN);
            s3_close_connection(b->sc);
            b->sc = NULL;
        }
    }

    free(b->acc);
    free(b->to_chan);
    free(b->frame);

    b->acc = NULL;
    b->to_chan = NULL;
    b->frame = NULL;
    b->acc_len = 0;
    b->acc_pay = 0;
    b->to_chan_len = 0;
    b->frame_sent = b->frame_total = 0;
    b->used = 0;
}

/*
 * one server-initiated forwarded-* channel bridges: the 91 answers
 * the opener header, the local target dials, the pump rides the tick
 */

static void
s3_cli_rev_bridge_start(s3_connection_t *sc, unsigned spec_ix, unsigned proto, const u_char *tail,
                        size_t tail_len)
{
    s3_cli_rev_bridge_t *b;
    u_char               out[32];
    u_char              *p;
    size_t               total;
    ssize_t              m;

    b = &s3_cli_rev_bridge[0]; /* the take below fills it */

    {
        unsigned i;

        for (i = 0; i < S3_CLI_REV_BRIDGES; i++) {

            if (!s3_cli_rev_bridge[i].used) {
                b = &s3_cli_rev_bridge[i];
                break;
            }
        }

        if (b->used) {
            s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the reverse bridge table is full");
            (void)s3_quic_cancelable_stream(sc);
            (void)s3_quic_shutdown_stream(sc, S3_RDWR_SHUTDOWN);
            s3_close_connection(sc);
            return;
        }
    }

    s3_memzero(b, sizeof(*b));

    b->fd = INVALID_SOCKET;

    /* the 91 with our maxPacketSize, the shape of the server */

    {
        s3_ssh3_msg_open_confirmation_t conf;

        s3_memzero(&conf, sizeof(conf));
        conf.max_packet_size = S3_CLI_CHANNEL_MAX_PACKET;

        p = out;
        p = (u_char *)s3_ssh3_encode_varint(p, S3_SSH3_MSG_CHANNEL_OPEN_CONFIRMATION);
        p = (u_char *)s3_ssh3_msg_encode_open_confirmation(p, &conf);

        total = (size_t)(p - out);

        m = s3_quic_stream_send(sc, out, total);

        if (m != (ssize_t)total) {
            s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the reverse bridge confirmation send failed");
            (void)s3_quic_cancelable_stream(sc);
            (void)s3_quic_shutdown_stream(sc, S3_RDWR_SHUTDOWN);
            s3_close_connection(sc);
            return;
        }
    }

    /* the local half: the dial of the spec target (the ipv4 literal
     * or the v4-mapped form), the nonblocking socket */

    if (s3_cli_rtarget[spec_ix].family != 4) {
        s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the -R bridge bridges the ipv4 targets only");
        (void)s3_quic_cancelable_stream(sc);
        (void)s3_quic_shutdown_stream(sc, S3_RDWR_SHUTDOWN);
        s3_close_connection(sc);
        return;
    }

    {
        struct sockaddr_in sa;

        s3_memzero(&sa, sizeof(sa));

        sa.sin_family = AF_INET;
        s3_memcpy(&sa.sin_addr, s3_cli_rtarget[spec_ix].ip, 4);
        sa.sin_port = htons(s3_cli_rtarget[spec_ix].port);

        b->fd = socket(AF_INET, (proto == S3_SSH3_REVERSE_PROTO_UDP) ? SOCK_DGRAM : SOCK_STREAM, 0);

        if (b->fd == INVALID_SOCKET) {
            s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the reverse bridge socket failed");
            (void)s3_quic_cancelable_stream(sc);
            (void)s3_quic_shutdown_stream(sc, S3_RDWR_SHUTDOWN);
            s3_close_connection(sc);
            return;
        }

        if (connect(b->fd, (const struct sockaddr *)&sa, sizeof(sa)) != 0 ||
            s3_nonblocking(b->fd) != S3_OK) {
            s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the local -R target is unreachable");
            (void)closesocket(b->fd);
            b->fd = INVALID_SOCKET;
            (void)s3_quic_cancelable_stream(sc);
            (void)s3_quic_shutdown_stream(sc, S3_RDWR_SHUTDOWN);
            s3_close_connection(sc);
            return;
        }
    }

    b->used = 1;
    b->kind = proto;
    b->spec = spec_ix;
    b->sc = sc;
    b->ch_id = ((s3_quic_stream_t *)sc->data)->id;
    b->confirmed = 1;

    /* the parked datagrams of the startup race replay into the
     * socket at once (the router parked them while the header
     * parsed) */

    if (proto == S3_SSH3_REVERSE_PROTO_UDP) {

        unsigned k;

        for (k = 0; k < S3_CLI_REV_PARK_MAX; k++) {

            s3_cli_rev_park_t *pk = &s3_cli_rev_park[k];

            if (pk->used && pk->ch_id == b->ch_id) {
                (void)send(b->fd, (const char *)pk->dg, (int)pk->len, 0);
                pk->used = 0;
            }
        }
    }

    /* the header tail (the first bytes of the stream after the
     * header) rides the accumulator, the bridge never loses them */

    if (tail_len > 0) {

        b->acc_cap = tail_len + 16384;
        b->acc = malloc(b->acc_cap);

        if (b->acc == NULL) {
            s3_cli_rev_bridge_kill(b, "the bridge buffer growth failed");
            (void)s3_quic_cancelable_stream(sc);
            (void)s3_quic_shutdown_stream(sc, S3_RDWR_SHUTDOWN);
            s3_close_connection(sc);
            return;
        }

        s3_memcpy(b->acc, tail, tail_len);
        b->acc_len = tail_len;
    }

    s3_log_error(S3_LOG_INFO, &s3_cli_log, 0, "the reverse bridge armed: kind=%s spec=%u",
                 (proto == S3_SSH3_REVERSE_PROTO_UDP) ? "udp" : "tcp", spec_ix);

    /* the stream read: the 94 payloads ride the local socket, the
     * fin closes the write side (the half-close contract of the
     * relay) */

    sc->read->handler = s3_cli_rev_stream_read;
    sc->read->data = sc;
    sc->read->active = 1;

    if (sc->read->ready) {
        sc->read->handler(sc->read);
    }
}

/* the -R accept hook: the server-initiated stream arms the accept
 * reader (the header rides the slot table, the dispatch lands there) */

static void
s3_cli_rev_accept(s3_connection_t *c)
{
    c->read->handler = s3_cli_rev_accept_read;
    c->read->data = c;
    c->read->active = 1;

    /* the header may have landed before the arming */

    if (c->read->ready) {
        c->read->handler(c->read);
    }
}

/*
 * the accept reader of the server-initiated bidi streams: the
 * forwarded-* types bridge through the -R table, everything else
 * refuses (the allow-list of the client); the partial headers of the
 * concurrent channels keep apart in the accept slots
 */

static void
s3_cli_rev_accept_read(s3_event_t *ev)
{
    s3_connection_t  *sc = ev->data;
    s3_cli_rev_acc_t *a = NULL;
    const u_char     *pos, *end;
    s3_ssh3_channel_t hdr;
    ssize_t           n;
    unsigned          j;

    for (j = 0; j < S3_CLI_REV_ACCEPTS; j++) {

        if (s3_cli_rev_acc[j].used && s3_cli_rev_acc[j].sc == sc) {
            a = &s3_cli_rev_acc[j];
            break;
        }
    }

    if (a == NULL) {

        for (j = 0; j < S3_CLI_REV_ACCEPTS; j++) {

            if (!s3_cli_rev_acc[j].used) {
                s3_cli_rev_acc[j].used = 1;
                s3_cli_rev_acc[j].sc = sc;
                s3_cli_rev_acc[j].len = 0;
                a = &s3_cli_rev_acc[j];
                break;
            }
        }

        if (a == NULL) {
            s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the reverse accept table is full");
            (void)s3_quic_cancelable_stream(sc);
            (void)s3_quic_shutdown_stream(sc, S3_RDWR_SHUTDOWN);
            s3_close_connection(sc);
            return;
        }
    }

    for (;;) {

        if (a->len == sizeof(a->hdr)) {
            s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the server channel header is too big");
            s3_cli_rev_teardown(1);
            s3_cli_rc = S3_CLI_EXIT_ERROR;
            s3_cli_finalize(s3_cli_conn);
            return;
        }

        n = sc->recv(sc, a->hdr + a->len, sizeof(a->hdr) - a->len);

        if (n == (ssize_t)S3_AGAIN) {
            return;
        }

        if (n <= 0) {
            s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the server channel closed before the header");
            s3_cli_rev_teardown(1);
            s3_cli_rc = S3_CLI_EXIT_ERROR;
            s3_cli_finalize(s3_cli_conn);
            return;
        }

        a->len += (size_t)n;

        pos = a->hdr;
        end = a->hdr + a->len;

        if (s3_ssh3_channel_parse_header(&pos, end, &hdr) != S3_OK) {
            continue; /* the header tail waits for the next recv */
        }

        if (hdr.conversation_stream_id != s3_cli_conv_id) {
            s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the server channel conversation mismatch");
            s3_cli_rev_teardown(1);
            s3_cli_rc = S3_CLI_EXIT_ERROR;
            s3_cli_finalize(s3_cli_conn);
            return;
        }

        a->used = 0;
        a->sc = NULL;

        if (hdr.type.len == strlen(S3_SSH3_CHANNEL_TYPE_FORWARDED_TCP) &&
            s3_memcmp(hdr.type.data, S3_SSH3_CHANNEL_TYPE_FORWARDED_TCP, hdr.type.len) == 0) {

            s3_ssh3_forward_target_t target;
            int                      spec_ix;

            if (s3_ssh3_forward_parse_target(&pos, end, &target) != S3_OK) {
                s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "bad forwarded-tcp target");
                s3_cli_rev_teardown(1);
                s3_cli_rc = S3_CLI_EXIT_ERROR;
                s3_cli_finalize(s3_cli_conn);
                return;
            }

            spec_ix = s3_cli_rev_spec_of(S3_SSH3_REVERSE_PROTO_TCP, &target);

            if (spec_ix < 0) {

                /* the allow-list of the client (the S2-03 symmetry):
                 * a forwarded-* channel of a target no -R asked for
                 * refuses */

                s3_log_error(S3_LOG_ERR, &s3_cli_log, 0,
                             "rejecting an unexpected server channel towards the target "
                             "%u.%u.%u.%u:%u",
                             target.ip[0], target.ip[1], target.ip[2], target.ip[3],
                             (unsigned)target.port);

                (void)s3_quic_cancelable_stream(sc);
                (void)s3_quic_shutdown_stream(sc, S3_RDWR_SHUTDOWN);
                s3_close_connection(sc);
                return;
            }

            s3_cli_rev_bridge_start(sc, (unsigned)spec_ix, S3_SSH3_REVERSE_PROTO_TCP, pos,
                                    (size_t)(end - pos));
            return;
        }

        if (hdr.type.len == strlen(S3_SSH3_CHANNEL_TYPE_FORWARDED_UDP) &&
            s3_memcmp(hdr.type.data, S3_SSH3_CHANNEL_TYPE_FORWARDED_UDP, hdr.type.len) == 0) {

            s3_ssh3_forward_target_t target;
            int                      spec_ix;

            if (s3_ssh3_forward_parse_target(&pos, end, &target) != S3_OK) {
                s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "bad forwarded-udp target");
                s3_cli_rev_teardown(1);
                s3_cli_rc = S3_CLI_EXIT_ERROR;
                s3_cli_finalize(s3_cli_conn);
                return;
            }

            spec_ix = s3_cli_rev_spec_of(S3_SSH3_REVERSE_PROTO_UDP, &target);

            if (spec_ix < 0) {

                s3_log_error(S3_LOG_ERR, &s3_cli_log, 0,
                             "rejecting an unexpected server channel towards the target "
                             "%u.%u.%u.%u:%u",
                             target.ip[0], target.ip[1], target.ip[2], target.ip[3],
                             (unsigned)target.port);

                (void)s3_quic_cancelable_stream(sc);
                (void)s3_quic_shutdown_stream(sc, S3_RDWR_SHUTDOWN);
                s3_close_connection(sc);
                return;
            }

            s3_cli_rev_bridge_start(sc, (unsigned)spec_ix, S3_SSH3_REVERSE_PROTO_UDP, pos,
                                    (size_t)(end - pos));
            return;
        }

        /* the unexpected type: the refusal of the reference loop */

        s3_log_error(S3_LOG_ERR, &s3_cli_log, 0,
                     "rejecting an unexpected server channel of type %.*s", (int)hdr.type.len,
                     (const char *)hdr.type.data);

        (void)s3_quic_cancelable_stream(sc);
        (void)s3_quic_shutdown_stream(sc, S3_RDWR_SHUTDOWN);
        s3_close_connection(sc);

        return;
    }
}

/*
 * the channel side of a tcp bridge: the 94 payloads ride the local
 * socket, the fin of the peer closes the write side of the socket and
 * the drain finishes the bridge (the half-close contract)
 */

static void
s3_cli_rev_stream_read(s3_event_t *ev)
{
    s3_connection_t     *sc = ev->data;
    s3_cli_rev_bridge_t *b = s3_cli_rev_bridge_of_sc(sc);
    const u_char        *pos, *end;
    ssize_t              n;

    if (b == NULL) {
        return; /* the bridge died, the tail events are noise */
    }

    for (;;) {

        if (b->acc_len == b->acc_cap) {

            size_t  cap;
            u_char *grown;

            if (b->acc_cap >= S3_CLI_REV_BUF_MAX) {
                s3_cli_rev_bridge_kill(b, "the bridge buffer overgrown");
                return;
            }

            cap = b->acc_cap + 32768;

            if (cap > S3_CLI_REV_BUF_MAX) {
                cap = S3_CLI_REV_BUF_MAX;
            }

            grown = realloc(b->acc, cap);

            if (grown == NULL) {
                s3_cli_rev_bridge_kill(b, "the bridge buffer growth failed");
                return;
            }

            b->acc = grown;
            b->acc_cap = cap;
        }

        n = sc->recv(sc, b->acc + b->acc_len, b->acc_cap - b->acc_len);

        if (n == (ssize_t)S3_AGAIN) {
            return;
        }

        if (n == 0) {

            /* the channel fin: the local write side closes (the
             * half-close of the reference relay), the tick drains
             * the tail and ends the bridge */

            b->chan_fin = 1;

            if (b->fd != INVALID_SOCKET) {
                (void)shutdown(b->fd, SD_SEND);
            }

            return;
        }

        if (n < 0) {
            s3_cli_rev_bridge_kill(b, "the bridge stream recv error");
            return;
        }

        b->acc_len += (size_t)n;

        /*
         * the message walk with the write cursor: the payload of
         * every 94 compacts to the front (behind the bytes the pump
         * still owes the socket), the partial tail rides behind; the
         * udp bridge carries no stream payloads (the datagrams ride
         * the QUIC datagram path), a 94 there is a protocol break
         */

        {
            u_char *w = b->acc + b->acc_pay;

            pos = b->acc + b->acc_pay;
            end = b->acc + b->acc_len;

            while (pos < end) {

                const u_char *msg = pos;
                uint64_t      type;

                if (s3_ssh3_parse_varint(&pos, end, &type) != S3_OK) {
                    pos = msg;
                    break;
                }

                if (type == S3_SSH3_MSG_CHANNEL_OPEN_CONFIRMATION) {

                    s3_ssh3_msg_open_confirmation_t conf;

                    if (s3_ssh3_msg_parse_open_confirmation(&pos, end, &conf) != S3_OK) {
                        pos = msg;
                        break;
                    }

                    b->confirmed = 1;
                    continue;
                }

                if (type == S3_SSH3_MSG_CHANNEL_DATA) {

                    s3_ssh3_msg_data_t data;

                    if (!b->confirmed) {
                        s3_cli_rev_bridge_kill(b, "the bridge data before the confirmation");
                        return;
                    }

                    if (s3_ssh3_msg_parse_data(&pos, end, &data) != S3_OK) {
                        pos = msg;
                        break;
                    }

                    if (b->kind == S3_SSH3_REVERSE_PROTO_UDP) {
                        s3_cli_rev_bridge_kill(b, "the bridge udp stream data");
                        return;
                    }

                    if (data.data.len > 0) {
                        s3_memmove(w, data.data.data, data.data.len);
                        w += data.data.len;
                    }

                    continue;
                }

                s3_cli_rev_bridge_kill(b, "the bridge unexpected message");
                return;
            }

            /* the ready bytes and the unparsed tail ride the front */

            b->acc_pay = (size_t)(w - b->acc);

            if (pos < end) {
                s3_memmove(w, pos, (size_t)(end - pos));
                w += (size_t)(end - pos);
            }

            b->acc_len = (size_t)(w - b->acc);

            /*
             * the inline flush of the ready bytes: the read loop would
             * otherwise outrun the pump tick and overgrow the
             * accumulator (the probe writes back-to-back); the
             * loopback target sends drain at once, the EAGAIN case
             * waits for the pump tick
             */

            while (b->acc_pay > 0) {

                ssize_t m = send(b->fd, (const char *)b->acc, (int)b->acc_pay, 0);

                if (m > 0) {

                    size_t tail = b->acc_len - b->acc_pay;

                    s3_memmove(b->acc, b->acc + m, b->acc_pay - (size_t)m + tail);
                    b->acc_pay -= (size_t)m;
                    b->acc_len -= (size_t)m;

                    continue;
                }

                break; /* EAGAIN or error, the pump tick resumes */
            }
        }
    }
}

/*
 * the tick of the bridges: the channel payloads ride the sockets, the
 * socket bytes wrap into the 94 frames (the tail parks), the udp
 * bridges pump their datagrams
 */

static void
s3_cli_rev_pump(void)
{
    u_char   buf[16384];
    unsigned i;

    for (i = 0; i < S3_CLI_REV_BRIDGES; i++) {

        s3_cli_rev_bridge_t *b = &s3_cli_rev_bridge[i];

        if (!b->used) {
            continue;
        }

        if (b->kind == S3_SSH3_REVERSE_PROTO_UDP) {

            /* the udp bridge: the socket datagrams ride the channel
             * with the ids prefix (docs/P4-WIRE.md 3.2), the inbound
             * ones came through the datagram router */

            for (;;) {

                ssize_t n = recv(b->fd, (char *)buf, sizeof(buf), 0);
                u_char  dg[2048];
                u_char *p;

                if (n > 0 && (size_t)n + 16 > sizeof(dg)) {
                    continue; /* the datagram path is lossy by design */
                }

                if (n < 0 && s3_socket_errno == S3_EAGAIN) {
                    break;
                }

                if (n <= 0) {
                    s3_cli_rev_bridge_kill(b, "the local -R udp target closed");
                    break;
                }

                p = s3_ssh3_dgram_encode(dg, s3_cli_conv_id, b->ch_id, buf, (size_t)n);

                if (s3_quic_send_datagram(s3_cli_conn, dg, (size_t)(p - dg)) != S3_OK) {
                    break;
                }
            }

            continue;
        }

        /* the tcp bridge, the ready channel payloads first (the
         * partial tail stays behind them) */

        while (b->acc_pay > 0) {

            ssize_t m = send(b->fd, (const char *)b->acc, (int)b->acc_pay, 0);

            if (m > 0) {

                size_t tail = b->acc_len - b->acc_pay;

                s3_memmove(b->acc, b->acc + m, b->acc_pay - (size_t)m + tail);
                b->acc_pay -= (size_t)m;
                b->acc_len -= (size_t)m;

                continue;
            }

            if (m < 0 && s3_socket_errno == S3_EAGAIN) {
                break;
            }

            s3_cli_rev_bridge_kill(b, "the local -R target write failed");
            break;
        }

        if (!b->used) {
            continue;
        }

        /* the socket replies, the 94 frames under the maxPacketSize */

        if (!b->local_eof) {

            for (;;) {

                ssize_t n = recv(b->fd, (char *)buf, sizeof(buf), 0);

                if (n > 0) {

                    if (b->to_chan_len + (size_t)n > S3_CLI_REV_BUF_MAX) {
                        s3_cli_rev_bridge_kill(b, "the bridge buffer overgrown");
                        break;
                    }

                    if (b->to_chan_cap == 0) {
                        b->to_chan_cap = 16384;
                        b->to_chan = malloc(b->to_chan_cap);
                    }

                    while (b->to_chan_len + (size_t)n > b->to_chan_cap) {
                        u_char *grown = realloc(b->to_chan, b->to_chan_cap + 32768);

                        if (grown == NULL) {
                            s3_cli_rev_bridge_kill(b, "the bridge buffer growth failed");
                            break;
                        }

                        b->to_chan = grown;
                        b->to_chan_cap += 32768;
                    }

                    if (!b->used) {
                        break;
                    }

                    s3_memcpy(b->to_chan + b->to_chan_len, buf, (size_t)n);
                    b->to_chan_len += (size_t)n;

                    continue;
                }

                if (n == 0) {

                    /* the local target closed its write side: the
                     * channel fin rides once the tail drained (the
                     * half-close of the reference relay) */

                    b->local_eof = 1;
                    break;
                }

                if (s3_socket_errno == S3_EAGAIN) {
                    break;
                }

                s3_cli_rev_bridge_kill(b, "the local -R target read error");
                break;
            }

            if (!b->used) {
                continue;
            }
        }

        while (b->to_chan_len > 0 || b->frame_sent < b->frame_total) {

            if (b->frame_sent == b->frame_total) {

                u_char *p;
                size_t  chunk;

                chunk = s3_ssh3_channel_chunk_size(S3_CLI_CHANNEL_MAX_PACKET, 0);

                if (chunk > b->to_chan_len) {
                    chunk = b->to_chan_len;
                }

                if (b->frame == NULL) {
                    b->frame = malloc(S3_CLI_FWD_FRAME);

                    if (b->frame == NULL) {
                        s3_cli_rev_bridge_kill(b, "the bridge frame alloc failed");
                        break;
                    }
                }

                p = b->frame;
                p = (u_char *)s3_ssh3_encode_varint(p, S3_SSH3_MSG_CHANNEL_DATA);
                p = (u_char *)s3_ssh3_encode_varint(p, chunk);
                s3_memcpy(p, b->to_chan, chunk);

                b->frame_total = (size_t)(p - b->frame) + chunk;
                b->frame_sent = 0;

                s3_memmove(b->to_chan, b->to_chan + chunk, b->to_chan_len - chunk);
                b->to_chan_len -= chunk;
            }

            {
                ssize_t m = s3_quic_stream_send(b->sc, b->frame + b->frame_sent,
                                                b->frame_total - b->frame_sent);

                if (m == (ssize_t)S3_AGAIN) {
                    break; /* the window reopens on the next tick */
                }

                if (m <= 0) {
                    s3_cli_rev_bridge_kill(b, "the bridge stream send failed");
                    break;
                }

                b->frame_sent += (size_t)m;
            }
        }

        if (!b->used) {
            continue;
        }

        /* the local eof: the channel fin rides once the tail is out */

        if (b->local_eof && !b->chan_fin_sent && b->to_chan_len == 0 &&
            b->frame_sent == b->frame_total) {

            (void)s3_quic_shutdown_stream(b->sc, S3_WRITE_SHUTDOWN);
            b->chan_fin_sent = 1;
        }

        /* the both-sides-closed bridge ends (the partial tail is a
         * loss, the channel is closing) */

        if (b->chan_fin && b->local_eof && b->acc_pay == 0 && b->to_chan_len == 0 &&
            b->frame_sent == b->frame_total) {
            s3_cli_rev_bridge_kill(b, NULL);
            continue;
        }
    }
}

/*
 * the datagram router of the udp bridges: the datagrams prefixed with
 * a bridge channel id ride into the local socket; 1 rides back when
 * the datagram was consumed (the -L router then skips it)
 */

static unsigned
s3_cli_rev_datagram(s3_chain_t *data)
{
    u_char               flat[S3_CLI_FWD_UDP_DATAGRAM + 16];
    u_char              *p;
    size_t               len = 0;
    s3_chain_t          *cl;
    const u_char        *pos, *end;
    uint64_t             csid, chid;
    s3_str_t             payload;
    s3_cli_rev_bridge_t *b;

    if (s3_cli_rspec_count == 0) {
        return 0;
    }

    for (cl = data; cl != NULL; cl = cl->next) {
        len += s3_buf_size(cl->buf);
    }

    if (len > sizeof(flat)) {
        return 0;
    }

    p = flat;

    for (cl = data; cl != NULL; cl = cl->next) {
        p = s3_cpymem(p, cl->buf->pos, s3_buf_size(cl->buf));
    }

    pos = flat;
    end = flat + len;

    if (s3_ssh3_dgram_parse(&pos, end, &csid, &chid, &payload) != S3_OK) {
        return 0;
    }

    if (csid != s3_cli_conv_id) {
        return 0;
    }

    b = s3_cli_rev_bridge_of(chid);

    if (b == NULL || b->kind != S3_SSH3_REVERSE_PROTO_UDP) {

        /* the bridge not armed yet: the datagram parks for the
         * replay (the startup race); a datagram that matches a -L
         * source id is not ours, the -L router routes it */

        unsigned i, k;

        for (i = 0; i < s3_cli_fwd_count; i++) {

            for (k = 0; k < S3_CLI_FWD_UDP_SRCS; k++) {

                if (s3_cli_fwd_udp[i].srcs[k].used && s3_cli_fwd_udp[i].srcs[k].chan_id == chid) {
                    return 0;
                }
            }
        }

        for (i = 0; i < S3_CLI_REV_PARK_MAX; i++) {

            s3_cli_rev_park_t *pk = &s3_cli_rev_park[i];

            if (!pk->used) {

                if (payload.len <= S3_CLI_REV_PARK_DG) {

                    pk->used = 1;
                    pk->ch_id = chid;
                    pk->len = payload.len;
                    s3_memcpy(pk->dg, payload.data, payload.len);
                }

                break;
            }
        }

        return 1;
    }

    if (payload.len > 0 && send(b->fd, (const char *)payload.data, (int)payload.len, 0) < 0) {

        /* the udp loss stays a loss (RFC 768) */
    }

    return 1;
}

/*
 * the control channel of one -R spec: the header and the bind request
 * ride one send, the reply comes back as the channel data
 */

static s3_int_t
s3_cli_rev_ctrl_open(unsigned i)
{
    s3_cli_rev_ctrl_t        *rc = &s3_cli_rev_ctrl[i];
    s3_connection_t          *sc;
    s3_ssh3_channel_t         hdr;
    s3_ssh3_reverse_request_t req;
    s3_str_t                  bind, target;
    u_char                    reqbuf[256];
    u_char                   *rp;
    u_char                   *p;
    ssize_t                   m;

    if (rc->sc != NULL) {
        return S3_OK;
    }

    sc = s3_quic_open_stream(s3_cli_conn, 1);

    if (sc == NULL) {
        return S3_ERROR;
    }

    sc->read->handler = s3_cli_rev_ctrl_read;
    sc->read->data = sc;
    sc->read->active = 1;

    s3_memzero(&hdr, sizeof(hdr));

    hdr.conversation_stream_id = s3_cli_conv_id;
    hdr.max_packet_size = S3_CLI_CHANNEL_MAX_PACKET;
    hdr.type.data = (u_char *)S3_SSH3_CHANNEL_TYPE_REVERSE_FORWARD;
    hdr.type.len = strlen(S3_SSH3_CHANNEL_TYPE_REVERSE_FORWARD);

    bind.data = (u_char *)s3_cli_rspec[i].bind_host;
    bind.len = strlen(s3_cli_rspec[i].bind_host);

    target.data = (u_char *)s3_cli_rtarget_text[i];
    target.len = strlen(s3_cli_rtarget_text[i]);

    req.proto = s3_cli_rspec[i].proto;
    req.bind_address = bind;
    req.bind_port = s3_cli_rspec[i].bind_port;
    req.target_address = target;
    req.target_port = s3_cli_rspec[i].target_port;

    /* the request rides the channel data (the reference WriteData):
     * one 94 message, the payload is the SSHString of the request */

    rp = s3_ssh3_reverse_build_request(reqbuf, &req);

    if (rp == NULL) {
        s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the reverse request build failed");
        (void)s3_quic_cancelable_stream(sc);
        (void)s3_quic_shutdown_stream(sc, S3_RDWR_SHUTDOWN);
        s3_close_connection(sc);
        return S3_ERROR;
    }

    p = rc->frame;
    p = (u_char *)s3_ssh3_channel_build_header(p, &hdr);
    p = (u_char *)s3_ssh3_encode_varint(p, S3_SSH3_MSG_CHANNEL_DATA);
    p = (u_char *)s3_ssh3_encode_sshstring(p, reqbuf, (size_t)(rp - reqbuf));
    rc->frame_len = (size_t)(p - rc->frame);

    m = s3_quic_stream_send(sc, rc->frame, rc->frame_len);

    if (m != (ssize_t)rc->frame_len) {
        s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the reverse request send failed");
        (void)s3_quic_cancelable_stream(sc);
        (void)s3_quic_shutdown_stream(sc, S3_RDWR_SHUTDOWN);
        s3_close_connection(sc);
        return S3_ERROR;
    }

    rc->sc = sc;

    if (sc->read->ready) {
        sc->read->handler(sc->read);
    }

    return S3_OK;
}

/* the reply read of a control channel (the 91 rides first) */

static void
s3_cli_rev_ctrl_read(s3_event_t *ev)
{
    s3_connection_t   *sc = ev->data;
    s3_cli_rev_ctrl_t *rc = s3_cli_rev_ctrl_of(sc);
    const u_char      *pos, *end;
    ssize_t            n;
    unsigned           ix;

    if (rc == NULL) {
        return;
    }

    ix = (unsigned)(rc - s3_cli_rev_ctrl);

    for (;;) {

        if (rc->acc_len == sizeof(rc->acc)) {
            s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the reverse reply is too big");
            s3_cli_rev_teardown(1);
            s3_cli_rc = S3_CLI_EXIT_ERROR;
            s3_cli_finalize(s3_cli_conn);
            return;
        }

        n = sc->recv(sc, rc->acc + rc->acc_len, sizeof(rc->acc) - rc->acc_len);

        if (n == (ssize_t)S3_AGAIN) {
            return;
        }

        if (n == 0) {

            /* the server closed the control channel: a reply-less
             * close is the unsupported-server shape (the reference
             * comment), a post-reply close is the normal end */

            if (!rc->replied) {
                s3_log_error(S3_LOG_ERR, &s3_cli_log, 0,
                             "the server does not support reverse forwarding (the control "
                             "channel closed without a reply)");
                s3_cli_rev_teardown(1);
                s3_cli_rc = S3_CLI_EXIT_ERROR;
                s3_cli_finalize(s3_cli_conn);
                return;
            }

            rc->sc = NULL;
            return;
        }

        if (n < 0) {
            s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the reverse control channel recv error");
            s3_cli_rev_teardown(1);
            s3_cli_rc = S3_CLI_EXIT_ERROR;
            s3_cli_finalize(s3_cli_conn);
            return;
        }

        rc->acc_len += (size_t)n;

        pos = rc->acc;
        end = rc->acc + rc->acc_len;

        while (pos < end) {

            const u_char *msg = pos;
            uint64_t      type;

            if (s3_ssh3_parse_varint(&pos, end, &type) != S3_OK) {
                pos = msg;
                break;
            }

            if (type == S3_SSH3_MSG_CHANNEL_OPEN_CONFIRMATION) {

                s3_ssh3_msg_open_confirmation_t conf;

                if (s3_ssh3_msg_parse_open_confirmation(&pos, end, &conf) != S3_OK) {
                    pos = msg;
                    break;
                }

                continue;
            }

            if (type == S3_SSH3_MSG_CHANNEL_DATA) {

                s3_ssh3_msg_data_t      data;
                s3_ssh3_reverse_reply_t reply;

                if (s3_ssh3_msg_parse_data(&pos, end, &data) != S3_OK) {
                    pos = msg;
                    break;
                }

                {
                    const u_char *rpos = data.data.data;
                    const u_char *rend = data.data.data + data.data.len;

                    if (s3_ssh3_reverse_parse_reply(&rpos, rend, &reply) != S3_OK) {
                        s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the reverse reply parse failed");
                        s3_cli_rev_teardown(1);
                        s3_cli_rc = S3_CLI_EXIT_ERROR;
                        s3_cli_finalize(s3_cli_conn);
                        return;
                    }
                }

                rc->replied = 1;

                if (s3_ssh3_reverse_reply_ok(&reply)) {

                    rc->ok = 1;

                    s3_log_error(S3_LOG_INFO, &s3_cli_log, 0,
                                 "the reverse bind %u holds the port %u", ix,
                                 (unsigned)reply.bound_port);

                    /* the runner marker (the S3CLI-AGENT-BRIDGE
                     * shape): the e2e reads the bound port out of it */

                    printf("SSH3-RFWD-OK spec=%u port=%u\n", ix, (unsigned)reply.bound_port);
                    fflush(stdout);

                } else {

                    /* the refused bind fails the run (the -L listener
                     * bind failure shape) */

                    s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the reverse bind %u denied: %.*s", ix,
                                 (int)reply.error_utf8.len, (const char *)reply.error_utf8.data);

                    printf("SSH3-RFWD-DENIED spec=%u reason=%.*s\n", ix, (int)reply.error_utf8.len,
                           (const char *)reply.error_utf8.data);
                    fflush(stdout);

                    s3_cli_rev_teardown(1);
                    s3_cli_rc = S3_CLI_EXIT_ERROR;
                    s3_cli_finalize(s3_cli_conn);
                    return;
                }

                /* the reference client closes the control channel
                 * after the reply, the fin rides the write side */

                (void)s3_quic_shutdown_stream(sc, S3_WRITE_SHUTDOWN);

                continue;
            }

            s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the reverse control unexpected message %llu",
                         (unsigned long long)type);
            s3_cli_rev_teardown(1);
            s3_cli_rc = S3_CLI_EXIT_ERROR;
            s3_cli_finalize(s3_cli_conn);
            return;
        }

        rc->acc_len = (size_t)(end - pos);
        s3_memmove(rc->acc, pos, rc->acc_len);
    }
}

/* the next pending control channel opens, one per call */

static s3_int_t
s3_cli_rev_open_pending(void)
{
    static unsigned opened;

    while (opened < s3_cli_rspec_count) {

        if (s3_cli_rev_ctrl_open(opened) != S3_OK) {
            return S3_ERROR;
        }

        opened++;
    }

    return S3_OK;
}

/* the whole reverse state dies (the teardown and the fatal exits) */

static void
s3_cli_rev_teardown(unsigned quic_alive)
{
    unsigned i;

    for (i = 0; i < S3_CLI_REV_BRIDGES; i++) {

        if (s3_cli_rev_bridge[i].used) {
            s3_cli_rev_bridge_kill(&s3_cli_rev_bridge[i], NULL);
        }
    }

    for (i = 0; i < s3_cli_rspec_count; i++) {

        if (s3_cli_rev_ctrl[i].sc != NULL) {

            if (quic_alive) {
                (void)s3_quic_shutdown_stream(s3_cli_rev_ctrl[i].sc, S3_RDWR_SHUTDOWN);
                s3_close_connection(s3_cli_rev_ctrl[i].sc);
            }

            s3_cli_rev_ctrl[i].sc = NULL;
        }
    }

    for (i = 0; i < S3_CLI_REV_ACCEPTS; i++) {
        s3_cli_rev_acc[i].used = 0;
        s3_cli_rev_acc[i].sc = NULL;
    }
}

/*
 * the local half of the agent bridge: the named pipe of the Windows
 * OpenSSH agent on win (SSH_AUTH_SOCK when it names a pipe, the
 * default agent pipe otherwise), the SSH_AUTH_SOCK stream socket on
 * unix (the dial of s3_ssh3_agent, the nonblocking fd); NULL rides
 * back on success, the teardown reason otherwise
 */

static const char *
s3_cli_agent_open(void)
{
#if (S3_WIN32)
    const char *sock;
    wchar_t     wpipe[256];
    int         wn;

    /* the SSH_AUTH_SOCK when it names a pipe, the OpenSSH for
     * Windows agent pipe otherwise */

    sock = getenv("SSH_AUTH_SOCK");

    if (sock != NULL && strncmp(sock, "\\\\", 2) == 0) {
        wn = MultiByteToWideChar(CP_UTF8, 0, sock, -1, wpipe, 256);
    } else {
        wn = MultiByteToWideChar(CP_UTF8, 0, S3_CLI_AGENT_PIPE_DEFAULT, -1, wpipe, 256);
    }

    if (wn <= 0) {
        return "the agent pipe name failed";
    }

    s3_cli_agent_pipe =
        CreateFileW(wpipe, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

    if (s3_cli_agent_pipe == INVALID_HANDLE_VALUE) {
        s3_cli_agent_pipe = NULL;
        return "the local agent pipe is not open";
    }

    return NULL;
#else
    const char *sock = getenv("SSH_AUTH_SOCK");
    s3_str_t    path;

    if (sock == NULL || sock[0] == '\0') {
        return "SSH_AUTH_SOCK is unset";
    }

    if (s3_cli_agent_pool == NULL) {

        s3_cli_agent_pool = s3_create_pool(S3_DEFAULT_POOL_SIZE, &s3_cli_log);

        if (s3_cli_agent_pool == NULL) {
            return "the agent pool failed";
        }
    }

    path.data = (u_char *)sock;
    path.len = strlen(sock);

    s3_cli_agent_fd = s3_ssh3_agent_dial(s3_cli_agent_pool, &path);

    if (s3_cli_agent_fd < 0) {
        s3_cli_agent_fd = -1;
        return "the local agent socket is not open";
    }

    return NULL;
#endif
}

/* the channel bytes ride the transport: all of them on the sync win
 * pipe, the accepted prefix of the nonblocking unix socket (the tick
 * retries the tail, S3_AGAIN says the transport took nothing) */

static ssize_t
s3_cli_agent_send(const u_char *data, size_t n)
{
#if (S3_WIN32)
    DWORD put = 0;

    if (!WriteFile(s3_cli_agent_pipe, data, (DWORD)n, &put, NULL) || put == 0) {
        return -1;
    }

    return (ssize_t)put;
#else
    ssize_t m = send(s3_cli_agent_fd, data, n, 0);

    if (m > 0) {
        return m;
    }

    if (m < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
        return (ssize_t)S3_AGAIN;
    }

    return -1;
#endif
}

/* the transport replies: the arrived bytes, S3_AGAIN when the
 * transport is idle, -1 when it is gone */

static ssize_t
s3_cli_agent_recv(u_char *buf, size_t cap)
{
#if (S3_WIN32)
    DWORD avail = 0, got = 0;

    if (!PeekNamedPipe(s3_cli_agent_pipe, NULL, 0, NULL, &avail, NULL)) {
        return -1;
    }

    if (avail == 0) {
        return (ssize_t)S3_AGAIN;
    }

    if (avail > (DWORD)cap) {
        avail = (DWORD)cap;
    }

    if (!ReadFile(s3_cli_agent_pipe, buf, avail, &got, NULL) || got == 0) {
        return -1;
    }

    return (ssize_t)got;
#else
    ssize_t n = recv(s3_cli_agent_fd, buf, cap, 0);

    if (n > 0) {
        return n;
    }

    if (n == 0) {
        return -1; /* the orderly close of the agent */
    }

    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
        return (ssize_t)S3_AGAIN;
    }

    return -1;
#endif
}

static void
s3_cli_agent_teardown(const char *why)
{
    if (!s3_cli_agent_bridged && s3_cli_agent_sc == NULL) {
        return;
    }

    s3_log_error(S3_LOG_INFO, &s3_cli_log, 0, "the agent bridge down: %s", why);

#if (S3_WIN32)
    if (s3_cli_agent_pipe != NULL && s3_cli_agent_pipe != INVALID_HANDLE_VALUE) {
        CancelIoEx(s3_cli_agent_pipe, NULL);
        CloseHandle(s3_cli_agent_pipe);
        s3_cli_agent_pipe = NULL;
    }
#else
    if (s3_cli_agent_fd >= 0) {
        s3_ssh3_agent_close_fd(s3_cli_agent_fd);
        s3_cli_agent_fd = -1;
    }
#endif

    if (s3_cli_agent_sc != NULL) {
        (void)s3_quic_shutdown_stream(s3_cli_agent_sc, S3_RDWR_SHUTDOWN);
        s3_close_connection(s3_cli_agent_sc);
        s3_cli_agent_sc = NULL;
    }

    s3_cli_agent_bridged = 0;
    s3_cli_agent_in_len = 0;
    s3_cli_agent_frame_sent = s3_cli_agent_frame_total = 0;
    s3_cli_agent_hdr_len = 0;
}

/* the server-initiated bidi stream of the agent channel: the first
 * one bridges, the unexpected ones shut down */

static void
s3_cli_agent_accept(s3_connection_t *c)
{
    c->read->handler = s3_cli_agent_read;
    c->read->data = c;
    c->read->active = 1;

    /* the header may have landed before the arming */

    if (c->read->ready) {
        c->read->handler(c->read);
    }
}

static s3_int_t
s3_cli_agent_in_append(const u_char *data, size_t n)
{
    if (s3_cli_agent_in_len + n > s3_cli_agent_in_cap) {

        size_t  cap = s3_cli_agent_in_cap ? s3_cli_agent_in_cap : 16384;
        u_char *grown;

        while (cap < s3_cli_agent_in_len + n) {
            cap += 16384;
        }

        grown = realloc(s3_cli_agent_in, cap);

        if (grown == NULL) {
            return S3_ERROR;
        }

        s3_cli_agent_in = grown;
        s3_cli_agent_in_cap = cap;
    }

    memcpy(s3_cli_agent_in + s3_cli_agent_in_len, data, n);
    s3_cli_agent_in_len += n;

    return S3_OK;
}

/* the header phase of the accepted channel: the 90 checks, the 91
 * answers, the local agent pipe dials, the bridge lives */

static void
s3_cli_agent_read(s3_event_t *ev)
{
    s3_connection_t *sc = ev->data;
    const u_char    *pos, *end;
    ssize_t          n;

    if (s3_cli_agent_bridged) {
        return; /* the pump rides the tick */
    }

    n = sc->recv(sc, s3_cli_agent_hdr + s3_cli_agent_hdr_len,
                 sizeof(s3_cli_agent_hdr) - s3_cli_agent_hdr_len);

    if (n == (ssize_t)S3_AGAIN) {
        return;
    }

    if (n <= 0) {
        s3_cli_agent_teardown("closed before the header");
        return;
    }

    s3_cli_agent_hdr_len += (size_t)n;

    pos = s3_cli_agent_hdr;
    end = s3_cli_agent_hdr + s3_cli_agent_hdr_len;

    {
        s3_ssh3_channel_t hdr;

        if (s3_ssh3_channel_parse_header(&pos, end, &hdr) != S3_OK) {

            if (s3_cli_agent_hdr_len == sizeof(s3_cli_agent_hdr)) {
                s3_cli_agent_teardown("bad agent channel header");
            }

            return; /* the header tail waits for the next recv */
        }

        if (hdr.conversation_stream_id != s3_cli_conv_id ||
            hdr.type.len != strlen(S3_SSH3_CHANNEL_TYPE_AGENT) ||
            memcmp(hdr.type.data, S3_SSH3_CHANNEL_TYPE_AGENT, hdr.type.len) != 0) {
            s3_cli_agent_teardown("unexpected server channel");
            return;
        }
    }

    /* the 91 with our maxPacketSize, the shape of the server */

    {
        s3_ssh3_msg_open_confirmation_t conf;
        u_char                          out[32];
        u_char                         *p;
        size_t                          total;
        ssize_t                         m;

        memset(&conf, 0, sizeof(conf));
        conf.max_packet_size = S3_CLI_CHANNEL_MAX_PACKET;

        p = out;
        p = (u_char *)s3_ssh3_encode_varint(p, S3_SSH3_MSG_CHANNEL_OPEN_CONFIRMATION);
        p = (u_char *)s3_ssh3_msg_encode_open_confirmation(p, &conf);

        total = (size_t)(p - out);

        m = s3_quic_stream_send(sc, out, total);

        if (m != (ssize_t)total) {
            s3_cli_agent_teardown("confirmation send failed");
            return;
        }
    }

    /* the local half: the agent transport of the platform */

    {
        const char *why = s3_cli_agent_open();

        if (why != NULL) {
            s3_cli_agent_teardown(why);
            return;
        }
    }

    s3_cli_agent_sc = sc;
    s3_cli_agent_bridged = 1;

    printf("S3CLI-AGENT-BRIDGE\n");
    fflush(stdout);

    /* the header tail rides the channel parse (the 91 and the 94
     * of the bridge stream) */

    if (end - pos > 0) {

        size_t tail = (size_t)(end - pos);

        if (tail > s3_cli_agent_chacc_cap) {

            u_char *grown = realloc(s3_cli_agent_chacc, tail);

            if (grown == NULL) {
                s3_cli_agent_teardown("the agent buffer growth failed");
                return;
            }

            s3_cli_agent_chacc = grown;
            s3_cli_agent_chacc_cap = tail;
        }

        memcpy(s3_cli_agent_chacc, pos, tail);
        s3_cli_agent_chacc_len = tail;
    }

    s3_cli_agent_pump();
}

/* both directions: the channel payloads ride the pipe, the pipe
 * replies wrap into the 94 frames (the tail parks) */

static void
s3_cli_agent_pump(void)
{
    u_char buf[16384];

    if (!s3_cli_agent_bridged || s3_cli_agent_sc == NULL) {
        return;
    }

    for (;;) {

        ssize_t n;

        if (s3_cli_agent_chacc_len == s3_cli_agent_chacc_cap) {

            size_t  cap;
            u_char *grown;

            cap = s3_cli_agent_chacc_cap + 16384;
            grown = realloc(s3_cli_agent_chacc, cap);

            if (grown == NULL) {
                s3_cli_agent_teardown("the agent buffer growth failed");
                return;
            }

            s3_cli_agent_chacc = grown;
            s3_cli_agent_chacc_cap = cap;
        }

        n = s3_cli_agent_sc->recv(s3_cli_agent_sc, s3_cli_agent_chacc + s3_cli_agent_chacc_len,
                                  s3_cli_agent_chacc_cap - s3_cli_agent_chacc_len);

        if (n == (ssize_t)S3_AGAIN) {
            break;
        }

        if (n <= 0) {
            s3_cli_agent_teardown("the agent channel closed");
            return;
        }

        s3_cli_agent_chacc_len += (size_t)n;

        {
            const u_char *pos = s3_cli_agent_chacc;
            const u_char *end = s3_cli_agent_chacc + s3_cli_agent_chacc_len;

            while (pos < end) {

                const u_char *msg = pos;
                uint64_t      type;

                if (s3_ssh3_parse_varint(&pos, end, &type) != S3_OK) {
                    pos = msg;
                    break;
                }

                if (type == S3_SSH3_MSG_CHANNEL_OPEN_CONFIRMATION) {

                    s3_ssh3_msg_open_confirmation_t conf;

                    if (s3_ssh3_msg_parse_open_confirmation(&pos, end, &conf) != S3_OK) {
                        pos = msg;
                        break;
                    }

                    continue;
                }

                if (type == S3_SSH3_MSG_CHANNEL_DATA) {

                    s3_ssh3_msg_data_t data;

                    if (s3_ssh3_msg_parse_data(&pos, end, &data) != S3_OK) {
                        pos = msg;
                        break;
                    }

                    /* the probe bytes ride the pipe */

                    if (data.data.len > 0 &&
                        s3_cli_agent_in_append(data.data.data, data.data.len) != S3_OK) {
                        s3_cli_agent_teardown("the agent buffer growth failed");
                        return;
                    }

                    continue;
                }

                s3_cli_agent_teardown("the agent unexpected message");
                return;
            }

            s3_cli_agent_chacc_len = (size_t)(end - pos);
            memmove(s3_cli_agent_chacc, pos, s3_cli_agent_chacc_len);
        }
    }

    /* the channel bytes ride the transport (the tail parks for the
     * next tick when the nonblocking socket takes a prefix) */

    while (s3_cli_agent_in_len > 0) {

        ssize_t put = s3_cli_agent_send(s3_cli_agent_in, s3_cli_agent_in_len);

        if (put == (ssize_t)S3_AGAIN) {
            return; /* the transport took nothing, the tick retries */
        }

        if (put <= 0) {
            s3_cli_agent_teardown("the agent transport write failed");
            return;
        }

        memmove(s3_cli_agent_in, s3_cli_agent_in + put, s3_cli_agent_in_len - (size_t)put);
        s3_cli_agent_in_len -= (size_t)put;
    }

    /* the replies drain until the transport runs idle */

    for (;;) {

        ssize_t got = s3_cli_agent_recv(buf, sizeof(buf));
        ssize_t m;
        size_t  chunk;

        if (got == (ssize_t)S3_AGAIN) {
            break;
        }

        if (got <= 0) {
            s3_cli_agent_teardown("the agent transport read failed");
            return;
        }

        /* the reply bytes accumulate into the 94 frames under the
         * channel maxPacketSize, a partial send parks the tail */

        {
            size_t  piece = sizeof(s3_cli_agent_acc) - s3_cli_agent_acc_len;
            u_char *p;

            if (piece > (size_t)got) {
                piece = (size_t)got;
            }

            memcpy(s3_cli_agent_acc + s3_cli_agent_acc_len, buf, piece);
            s3_cli_agent_acc_len += piece;

            /* the byte stream sends whatever accumulated: a partial
             * frame is the wire shape, the wait would strand the
             * short answers of the agent */

            chunk = s3_ssh3_channel_chunk_size(S3_CLI_CHANNEL_MAX_PACKET, 0);

            if (chunk > s3_cli_agent_acc_len) {
                chunk = s3_cli_agent_acc_len;
            }

            p = s3_cli_agent_frame;
            p = (u_char *)s3_ssh3_encode_varint(p, S3_SSH3_MSG_CHANNEL_DATA);
            p = (u_char *)s3_ssh3_encode_varint(p, chunk);
            memcpy(p, s3_cli_agent_acc, chunk);

            s3_cli_agent_frame_total = (size_t)(p - s3_cli_agent_frame) + chunk;
            s3_cli_agent_frame_sent = 0;

            memmove(s3_cli_agent_acc, s3_cli_agent_acc + chunk, s3_cli_agent_acc_len - chunk);
            s3_cli_agent_acc_len -= chunk;
        }

        m = s3_quic_stream_send(s3_cli_agent_sc, s3_cli_agent_frame + s3_cli_agent_frame_sent,
                                s3_cli_agent_frame_total - s3_cli_agent_frame_sent);

        if (m == (ssize_t)S3_AGAIN) {
            return; /* the tick retries the parked tail */
        }

        if (m <= 0) {
            s3_cli_agent_teardown("the agent channel send failed");
            return;
        }

        s3_cli_agent_frame_sent += (size_t)m;
    }
}

/* === the proxy jump (-J [user@]host[:port], the tunnel and the
 * loopback bridge, the interop shape): phase 1 dials the jump host
 * byte-for-byte like the normal run, the direct-udp channel to the
 * inner server address tunnels the inner connection, the loopback
 * socket pair feeds it; the inner conn then dials against the tunnel
 * side with the path mtu pinned to the 1200 floor === */

/*
 * the datagram handler of the jump conversation: the tunnel frames
 * carry the prefix of the direct-udp channel, the payloads are the
 * raw quic packets of the inner connection, one send() into the
 * bridge socket b delivers them; a dropped datagram stays a loss the
 * inner connection recovers from (RFC 768, RFC 9002)
 */

static void
s3_cli_jump_datagram(s3_connection_t *c, s3_chain_t *data)
{
    u_char        flat[S3_CLI_JUMP_INNER_MTU + 16];
    u_char       *p;
    size_t        len = 0;
    s3_chain_t   *cl;
    const u_char *pos, *end;
    uint64_t      csid, chid;
    s3_str_t      payload;
    ssize_t       n;

    (void)c;

    if (s3_cli_bridge_b == INVALID_SOCKET) {
        return;
    }

    for (cl = data; cl != NULL; cl = cl->next) {
        len += s3_buf_size(cl->buf);
    }

    if (len > sizeof(flat)) {
        return;
    }

    p = flat;

    for (cl = data; cl != NULL; cl = cl->next) {
        p = s3_cpymem(p, cl->buf->pos, s3_buf_size(cl->buf));
    }

    pos = flat;
    end = flat + len;

    if (s3_ssh3_dgram_parse(&pos, end, &csid, &chid, &payload) != S3_OK) {
        return;
    }

    if (csid != s3_cli_jump_conv_id || chid != s3_cli_jump_ch_id) {
        return;
    }

    n = send(s3_cli_bridge_b, payload.data, payload.len, 0);

    (void)n; /* a short send is a loss the inner conn recovers from */
}

/*
 * the tunnel side of the bridge: the quic packets of the inner
 * connection recv straight behind the prefix (the payload bytes never
 * move), one datagram per send; the congested channel parks the
 * frame and puts the read event to sleep until the flush drains it
 */

static void
s3_cli_jump_bridge_read(s3_event_t *ev)
{
    size_t  pre;
    ssize_t n;

    if (s3_cli_bridge_parked > 0) {
        return;
    }

    pre = s3_ssh3_dgram_prefix_size(s3_cli_jump_conv_id, s3_cli_jump_ch_id);

    for (;;) {

        n = recv(s3_cli_bridge_b, s3_cli_bridge_frame + pre, sizeof(s3_cli_bridge_frame) - pre, 0);

        if (n < 0) {

            if (s3_socket_errno == S3_EAGAIN) {
                return;
            }

            /* the bridge socket died: the inner conn has no transport
             * left, the verdict ends the run */

            s3_cli_verdict = 1;
            s3_cli_exit_code = S3_CLI_EXIT_ERROR;

            return;
        }

        if (n == 0) {
            /* a zero-length datagram carries nothing */
            continue;
        }

        if ((size_t)n > S3_CLI_JUMP_INNER_MTU) {
            /* the inner packets are pinned to the cap, the rest drops */
            continue;
        }

        {
            u_char *p = s3_cli_bridge_frame;
            size_t  len;

            p = (u_char *)s3_ssh3_encode_varint(p, s3_cli_jump_conv_id);
            p = (u_char *)s3_ssh3_encode_varint(p, s3_cli_jump_ch_id);

            len = (size_t)(p - s3_cli_bridge_frame) + (size_t)n;

            if (s3_quic_send_datagram(s3_cli_jump_cli, s3_cli_bridge_frame, len) != S3_OK) {

                /* the channel is full: park the frame, the read
                 * event sleeps until the flush drains the queue */

                s3_cli_bridge_parked = len;

                (void)s3_event_actions.del_event(ev, S3_READ_EVENT, 0);

                return;
            }
        }
    }
}

/* the parked frame retries each pass, the read event wakes on success */

static void
s3_cli_jump_bridge_flush(void)
{
    if (s3_cli_bridge_parked == 0) {
        return;
    }

    if (s3_quic_send_datagram(s3_cli_jump_cli, s3_cli_bridge_frame, s3_cli_bridge_parked) != S3_OK) {
        /* still congested, the next pass retries */
        return;
    }

    s3_cli_bridge_parked = 0;

    (void)s3_event_actions.add_event(s3_cli_bridge_bc->read, S3_READ_EVENT, 0);
}

/*
 * the loopback socket pair: two udp sockets bound to 127.0.0.1:0 and
 * connected to each other, a becomes the fd of the inner quic
 * connection, b is the tunnel side the bridge reads
 */

static s3_int_t
s3_cli_jump_bridge_create(s3_event_ctx_t *ctx)
{
    struct sockaddr_in a, b;
    socklen_t          len;

    s3_memzero(&a, sizeof(a));
    s3_memzero(&b, sizeof(b));

    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    s3_cli_bridge_a = socket(AF_INET, SOCK_DGRAM, 0);
    s3_cli_bridge_b = socket(AF_INET, SOCK_DGRAM, 0);

    if (s3_cli_bridge_a == INVALID_SOCKET || s3_cli_bridge_b == INVALID_SOCKET) {
        return S3_ERROR;
    }

    if (s3_nonblocking((s3_fd_t)s3_cli_bridge_a) != S3_OK ||
        s3_nonblocking((s3_fd_t)s3_cli_bridge_b) != S3_OK) {
        return S3_ERROR;
    }

    if (bind(s3_cli_bridge_a, (struct sockaddr *)&a, sizeof(a)) != 0) {
        return S3_ERROR;
    }

    len = sizeof(a);

    if (getsockname(s3_cli_bridge_a, (struct sockaddr *)&a, &len) != 0) {
        return S3_ERROR;
    }

    b = a;
    b.sin_port = 0;

    if (bind(s3_cli_bridge_b, (struct sockaddr *)&b, sizeof(b)) != 0) {
        return S3_ERROR;
    }

    len = sizeof(b);

    if (getsockname(s3_cli_bridge_b, (struct sockaddr *)&b, &len) != 0) {
        return S3_ERROR;
    }

    s3_cli_bridge_sa = b;

    if (connect(s3_cli_bridge_a, (struct sockaddr *)&b, sizeof(b)) != 0 ||
        connect(s3_cli_bridge_b, (struct sockaddr *)&a, sizeof(a)) != 0) {
        return S3_ERROR;
    }

    s3_cli_bridge_bc = s3_get_connection(ctx, (s3_fd_t)s3_cli_bridge_b);

    if (s3_cli_bridge_bc == NULL) {
        return S3_ERROR;
    }

    s3_cli_bridge_bc->read->handler = s3_cli_jump_bridge_read;

    return s3_event_actions.add_event(s3_cli_bridge_bc->read, S3_READ_EVENT, 0);
}

/*
 * the jump channel reader: the direct-udp channel carries no stream
 * data, the tunnel lives once the 91 confirmation came back
 */

static void
s3_cli_jump_ch_read(s3_event_t *ev)
{
    s3_connection_t *sc;
    const u_char    *pos, *end;
    ssize_t          n;

    if (s3_cli_jump_ch_confirmed) {
        return;
    }

    sc = ev->data;

    n = sc->recv(sc, s3_cli_jump_ch_buf + s3_cli_jump_ch_len,
                 sizeof(s3_cli_jump_ch_buf) - s3_cli_jump_ch_len);

    if (n == (ssize_t)S3_AGAIN) {
        return;
    }

    if (n <= 0) {
        fprintf(stderr, "ssh3: the jump channel closed before the confirmation\n");
        s3_cli_verdict = 1;
        s3_cli_exit_code = S3_CLI_EXIT_ERROR;
        return;
    }

    s3_cli_jump_ch_len += (size_t)n;

    pos = s3_cli_jump_ch_buf;
    end = s3_cli_jump_ch_buf + s3_cli_jump_ch_len;

    while (pos < end) {

        const u_char *msg = pos;
        uint64_t      type;

        if (s3_ssh3_parse_varint(&pos, end, &type) != S3_OK) {
            /* a partial type varint, the next recv completes it */
            pos = msg;
            break;
        }

        if (type == S3_SSH3_MSG_CHANNEL_OPEN_CONFIRMATION) {

            s3_ssh3_msg_open_confirmation_t conf;

            if (s3_ssh3_msg_parse_open_confirmation(&pos, end, &conf) != S3_OK) {
                pos = msg;
                break;
            }

            s3_cli_jump_ch_confirmed = 1;
            continue;
        }

        fprintf(stderr, "ssh3: unexpected jump channel message %llu\n", (unsigned long long)type);
        s3_cli_verdict = 1;
        s3_cli_exit_code = S3_CLI_EXIT_ERROR;
        return;
    }

    /* the consumed bytes compact to the front of the accumulator */

    s3_cli_jump_ch_len = (size_t)(end - pos);
    s3_memmove(s3_cli_jump_ch_buf, pos, s3_cli_jump_ch_len);
}

/*
 * phase 1 of the proxy jump: the connection to the jump host runs the
 * normal h3 bring-up, the CONNECT answers 200 and the direct-udp
 * channel to the inner server address confirms; the jump connection
 * stays open for the whole run, its events ride the same loop the
 * inner connection uses below.  The -i mode builds the JWT of the
 * jump exporter (the bearer binds the live TLS session), the -U mode
 * rides the Basic string unchanged
 */

static s3_int_t
s3_cli_jump_dial(s3_event_ctx_t *ctx, s3_msec_t start, s3_msec_t timeout)
{
    u_char                alpn_wire[8];
    s3_str_t              alpn;
    s3_quic_conf_t       *conf = &s3_cli_jump_conf;
    s3_fd_t               fd;
    s3_quic_connection_t *qc;
    s3_uint_t             i;

    fd = (s3_fd_t)socket(AF_INET, SOCK_DGRAM, 0);

    if (fd == (s3_fd_t)INVALID_SOCKET) {
        fprintf(stderr, "ssh3: the jump socket failed\n");
        return S3_ERROR;
    }

    if (s3_nonblocking(fd) != S3_OK) {
        fprintf(stderr, "ssh3: the jump nonblocking mode failed\n");
        return S3_ERROR;
    }

    s3_cli_jump_cli = s3_get_connection(ctx, fd);

    if (s3_cli_jump_cli == NULL) {
        fprintf(stderr, "ssh3: the jump connection alloc failed\n");
        return S3_ERROR;
    }

    s3_cli_jump_cli->pool = s3_create_pool((size_t)S3_DEFAULT_POOL_SIZE, &s3_cli_log);

    if (s3_cli_jump_cli->pool == NULL) {
        return S3_ERROR;
    }

    s3_cli_jump_cli->sockaddr =
        (struct sockaddr *)s3_palloc(s3_cli_jump_cli->pool, sizeof(s3_cli_jump_sa));

    if (s3_cli_jump_cli->sockaddr == NULL) {
        return S3_ERROR;
    }

    s3_memcpy(s3_cli_jump_cli->sockaddr, &s3_cli_jump_sa, sizeof(s3_cli_jump_sa));
    s3_cli_jump_cli->socklen = sizeof(s3_cli_jump_sa);

    alpn_wire[0] = (u_char)2;
    alpn_wire[1] = 'h';
    alpn_wire[2] = '3';

    alpn.data = alpn_wire;
    alpn.len = 3;

    s3_memzero(conf, sizeof(s3_quic_conf_t));

    conf->ssl = s3_ssl_client_create(&s3_cli_log, &alpn);

    if (conf->ssl == NULL) {
        fprintf(stderr, "ssh3: the jump ssl init failed\n");
        return S3_ERROR;
    }

    conf->ctx = ctx;
    conf->handshake_timeout = timeout;
    conf->idle_timeout = 60000;
    conf->stream_buffer_size = 1 << 20;
    conf->max_concurrent_streams_bidi = 16;
    conf->max_concurrent_streams_uni = 16;
    conf->active_connection_id_limit = 8;

    /*
     * the tunnel frames carry the 1200-byte inner packets with the
     * prefix on top, the advertised acceptance must cover them
     */

    conf->max_datagram_frame_size = S3_CLI_JUMP_DGRAM_SIZE;
    conf->datagram_handler = s3_cli_jump_datagram;

    /* the server's uni streams go to the session port, like at home */

    conf->stream_handler = s3_cli_client_stream;

    for (i = 0; i < S3_QUIC_AV_KEY_LEN; i++) {
        conf->av_token_key[i] = (u_char)(0xa0 + i);
        conf->sr_token_key[i] = (u_char)(0xb0 + i);
    }

    if (s3_event_actions.add_event(s3_cli_jump_cli->read, S3_READ_EVENT, 0) != S3_OK) {
        return S3_ERROR;
    }

    if (s3_quic_connect(s3_cli_jump_cli, conf) != S3_OK) {
        fprintf(stderr, "ssh3: the jump connect failed\n");
        return S3_ERROR;
    }

    for (;;) {

        s3_event_process_posted(ctx, &ctx->posted_events);

        s3_process_events_and_timers(ctx);

        qc = s3_quic_get_connection(s3_cli_jump_cli);

        if (qc == NULL) {
            fprintf(stderr, "ssh3: the jump connection is gone\n");
            return S3_ERROR;
        }

        if (!s3_cli_jump_hs && s3_cli_jump_cli->ssl != NULL && s3_cli_jump_cli->ssl->handshaked) {

            s3_cli_jump_hs = 1;

            /* the h3 session first, the same the main run does */

            if (s3_h3_get_session(s3_cli_jump_cli) == NULL &&
                s3_h3_init_session(s3_cli_jump_cli) != S3_OK) {
                fprintf(stderr, "ssh3: the jump h3 session init failed\n");
                return S3_ERROR;
            }

            s3_cli_jump_stream = s3_quic_open_stream(s3_cli_jump_cli, 1);

            if (s3_cli_jump_stream == NULL) {
                fprintf(stderr, "ssh3: the jump stream open failed\n");
                return S3_ERROR;
            }

            s3_cli_jump_conv_id = ((s3_quic_stream_t *)s3_cli_jump_stream->data)->id;

            s3_cli_jump_stream->read->handler = s3_cli_ctrl_read;
            s3_cli_jump_stream->read->data = s3_cli_jump_stream;
            s3_cli_jump_stream->read->active = 1;

            /*
             * the transport parameters are final at the handshake: a
             * jump peer that cannot take the 1202-byte tunnel frames
             * is a configuration error, fail at once
             */

            if (qc->ctp.max_datagram_frame_size < S3_CLI_JUMP_DGRAM_MIN) {
                fprintf(stderr,
                        "ssh3: the jump peer max_datagram_frame_size %u is below the tunnel "
                        "need %u (the jump server wants -d 1352)\n",
                        (unsigned)qc->ctp.max_datagram_frame_size, (unsigned)S3_CLI_JUMP_DGRAM_MIN);
                return S3_ERROR;
            }

            /* the jump auth rides the same scheme: the JWT of the
             * jump exporter for the -i mode, the Basic string for
             * the -U mode */

            if (s3_cli_auth == S3_CLI_AUTH_PUBKEY) {

                if (s3_cli_jwt_build_user(s3_cli_jump_cli->ssl->connection, s3_cli_jump_user,
                                          s3_cli_jump_bearer, sizeof(s3_cli_jump_bearer)) != S3_OK) {
                    return S3_ERROR;
                }

                s3_cli_jump_auth = s3_cli_jump_bearer;

            } else if (s3_cli_auth == S3_CLI_AUTH_BASIC) {
                s3_cli_jump_auth = s3_cli_basic;
            }
        }

        if (s3_cli_jump_hs && !s3_cli_jump_req_sent) {

            u_char  frame[1024];
            u_char *p;
            size_t  sec_len, total;
            ssize_t m;

            sec_len = s3_cli_jump_h3_section(NULL);

            p = frame;
            p = (u_char *)s3_h3_encode_varlen_int(p, S3_H3_FRAME_HEADERS);
            p = (u_char *)s3_h3_encode_varlen_int(p, sec_len);
            sec_len = s3_cli_jump_h3_section(p);
            total = (size_t)(p - frame) + sec_len;

            m = s3_quic_stream_send(s3_cli_jump_stream, frame, total);

            if (m == (ssize_t)S3_AGAIN) {
                /* the window opens on the write event, retried next pass */
            } else if (m != (ssize_t)total) {
                fprintf(stderr, "ssh3: the jump request send failed\n");
                return S3_ERROR;

            } else {
                s3_cli_jump_req_sent = 1;
            }
        }

        if (s3_cli_status_seen && s3_cli_jump_channel == NULL) {

            /* the direct-udp channel comes up right after the 200:
             * the target extension carries the inner server address,
             * the 91 confirmation completes the tunnel */

            s3_cli_jump_channel = s3_quic_open_stream(s3_cli_jump_cli, 1);

            if (s3_cli_jump_channel == NULL) {
                fprintf(stderr, "ssh3: the jump channel open failed\n");
                return S3_ERROR;
            }

            s3_cli_jump_ch_id = ((s3_quic_stream_t *)s3_cli_jump_channel->data)->id;

            s3_cli_jump_channel->read->handler = s3_cli_jump_ch_read;
            s3_cli_jump_channel->read->data = s3_cli_jump_channel;
            s3_cli_jump_channel->read->active = 1;
        }

        if (s3_cli_status_seen && !s3_cli_jump_ch_sent) {

            u_char                   frame[1024];
            u_char                  *p;
            s3_ssh3_channel_t        hdr;
            s3_ssh3_forward_target_t target;
            size_t                   total;
            ssize_t                  m;

            s3_memzero(&hdr, sizeof(hdr));

            hdr.conversation_stream_id = s3_cli_jump_conv_id;
            hdr.max_packet_size = S3_CLI_CHANNEL_MAX_PACKET;
            hdr.type.data = (u_char *)S3_SSH3_CHANNEL_TYPE_DIRECT_UDP;
            hdr.type.len = strlen(S3_SSH3_CHANNEL_TYPE_DIRECT_UDP);

            p = frame;
            p = (u_char *)s3_ssh3_channel_build_header(p, &hdr);

            target.family = 4;
            target.ip_len = 4;

            {
                struct sockaddr_in in;

                memcpy(&in, &s3_cli_sa, sizeof(in));
                memcpy(target.ip, &in.sin_addr, 4);
                target.port = ntohs(in.sin_port);
            }

            p = s3_ssh3_forward_build_target(p, &target);

            total = (size_t)(p - frame);

            m = s3_quic_stream_send(s3_cli_jump_channel, frame, total);

            if (m == (ssize_t)S3_AGAIN) {
                /* the window opens on the write event, retried next pass */
            } else if (m != (ssize_t)total) {
                fprintf(stderr, "ssh3: the jump channel send failed\n");
                return S3_ERROR;

            } else {
                s3_cli_jump_ch_sent = 1;
            }
        }

        if (s3_cli_jump_ch_confirmed) {
            return S3_OK;
        }

        if (s3_current_msec - start > timeout) {
            fprintf(stderr,
                    "ssh3: the jump tunnel timed out (hs=%u req=%u status=%u ch=%u)\n",
                    s3_cli_jump_hs, s3_cli_jump_req_sent, s3_cli_status_seen, s3_cli_jump_ch_sent);
            return S3_ERROR;
        }
    }
}

/* === the ControlMaster (-M): the control plane rides the named
 * pipe instances of win and the stream sockets of unix, the session
 * channels ride the shared connection === */

/* the control endpoint name: the FNV of the home behind the pipe
 * namespace of win, the $TMPDIR socket of unix (the sun_path cap
 * guards the custom TMPDIR, the per-user hash keeps the uniqueness) */

static void
s3_cli_cm_pipe_name(char *out, size_t size)
{
#if (S3_WIN32)
    const char *home = getenv("USERPROFILE");
    const char *s = home != NULL ? home : "ssh3";
    uint64_t    h = 0xcbf29ce484222325ULL;

    while (*s != '\0') {
        h ^= (u_char)*s++;
        h *= 0x100000001b3ULL;
    }

    snprintf(out, size, "\\\\.\\pipe\\ssh3-cm-%08x%08x", (unsigned)(h >> 32), (unsigned)h);
#else
    const char *home = getenv("HOME");
    const char *s = home != NULL ? home : "ssh3";
    const char *tmp = getenv("TMPDIR");
    uint64_t    h = 0xcbf29ce484222325ULL;

    while (*s != '\0') {
        h ^= (u_char)*s++;
        h *= 0x100000001b3ULL;
    }

    if (tmp == NULL || strlen(tmp) + 26 >= sizeof(((struct sockaddr_un *)NULL)->sun_path)) {
        tmp = "/tmp";
    }

    snprintf(out, size, "%s/ssh3-cm-%08x%08x", tmp, (unsigned)(h >> 32), (unsigned)h);
#endif
}

/*
 * the control-plane transport primitives, the shape both the tick
 * pump of the master conns and the sequential slave client need: the
 * poll of the arrived bytes, the read and the write with the parked
 * tails, the plain close of the client half.  The win sync named pipe
 * and the unix stream socket answer the same three-state contract:
 * S3_AGAIN says "nothing yet, alive", the negative says "gone"
 */

static unsigned
s3_cli_cm_h_valid(s3_cli_cm_h_t h)
{
#if (S3_WIN32)
    return (h != NULL && h != INVALID_HANDLE_VALUE) ? 1u : 0u;
#else
    return h >= 0;
#endif
}

static int
s3_cli_cm_h_poll(s3_cli_cm_h_t h)
{
#if (S3_WIN32)
    DWORD avail = 0;

    if (!PeekNamedPipe(h, NULL, 0, NULL, &avail, NULL)) {
        return -1;
    }

    return avail > 0 ? 1 : 0;
#else
    struct pollfd pfd;
    int           r;

    pfd.fd = h;
    pfd.events = POLLIN | POLLHUP;
    pfd.revents = 0;

    r = poll(&pfd, 1, 0);

    if (r < 0) {
        return errno == EINTR ? 0 : -1;
    }

    return r > 0 ? 1 : 0;
#endif
}

static ssize_t
s3_cli_cm_h_read(s3_cli_cm_h_t h, u_char *buf, size_t cap)
{
#if (S3_WIN32)
    DWORD got = 0;

    if (!ReadFile(h, buf, (DWORD)cap, &got, NULL) || got == 0) {
        return 0; /* the eof shape of the pipe */
    }

    return (ssize_t)got;
#else
    ssize_t n = read(h, buf, cap);

    if (n > 0) {
        return n;
    }

    if (n == 0) {
        return 0; /* the peer closed */
    }

    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
        return (ssize_t)S3_AGAIN;
    }

    return -1;
#endif
}

static ssize_t
s3_cli_cm_h_write(s3_cli_cm_h_t h, const u_char *data, size_t n)
{
#if (S3_WIN32)
    DWORD put = 0;

    if (!WriteFile(h, data, (DWORD)n, &put, NULL) || put == 0) {
        return -1;
    }

    return (ssize_t)put;
#else
    ssize_t m = write(h, data, n);

    if (m > 0) {
        return m;
    }

    if (m < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
        return (ssize_t)S3_AGAIN;
    }

    return -1;
#endif
}

static void
s3_cli_cm_h_close(s3_cli_cm_h_t h)
{
#if (S3_WIN32)
    CloseHandle(h);
#else
    close(h);
#endif
}

#if (S3_WIN32)

/* the accept thread: the blocking ConnectNamedPipe loop, the
 * connected handles queue for the tick (the sync server shape; a
 * client that connected between the create and the connect answers
 * ERROR_PIPE_CONNECTED and rides the queue the same way) */

static void
s3_cli_cm_acc_push(HANDLE h)
{
    EnterCriticalSection(&s3_cli_cm_acc_cs);

    if (s3_cli_cm_acc_head - s3_cli_cm_acc_tail < S3_CLI_CM_ACC_QUEUE) {
        s3_cli_cm_acc_queue[s3_cli_cm_acc_head++ % S3_CLI_CM_ACC_QUEUE] = h;

    } else {
        CloseHandle(h); /* the queue overflow, the client retries */
    }

    LeaveCriticalSection(&s3_cli_cm_acc_cs);
}

static unsigned __stdcall s3_cli_cm_accept_thread(void *arg)
{
    wchar_t w[256];
    int     wn;
    DWORD   err;

    (void)arg;

    wn = MultiByteToWideChar(CP_UTF8, 0, s3_cli_cm_path, -1, w, 256);

    if (wn <= 0) {
        s3_cli_cm_acc_failed = 1;
        SetEvent(s3_cli_cm_acc_armed);
        return 0;
    }

    while (s3_cli_cm_acc_run) {

        s3_cli_cm_listen_h =
            CreateNamedPipeW(w, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                             PIPE_UNLIMITED_INSTANCES, 65536, 65536, 0, NULL);

        if (s3_cli_cm_listen_h == INVALID_HANDLE_VALUE) {
            s3_cli_cm_acc_failed = GetLastError();
            SetEvent(s3_cli_cm_acc_armed);
            break;
        }

        SetEvent(s3_cli_cm_acc_armed); /* the first instance is up */

        if (ConnectNamedPipe(s3_cli_cm_listen_h, NULL)) {
            s3_cli_cm_acc_push(s3_cli_cm_listen_h);

        } else {

            err = GetLastError();

            if (err == ERROR_PIPE_CONNECTED) {
                s3_cli_cm_acc_push(s3_cli_cm_listen_h);

            } else if (err == ERROR_OPERATION_ABORTED || !s3_cli_cm_acc_run) {
                CloseHandle(s3_cli_cm_listen_h);
                s3_cli_cm_listen_h = INVALID_HANDLE_VALUE;
                break;

            } else {

                /* the client died between the create and the
                 * connect: the instance re-arms */

                DisconnectNamedPipe(s3_cli_cm_listen_h);
                CloseHandle(s3_cli_cm_listen_h);
                s3_cli_cm_listen_h = INVALID_HANDLE_VALUE;
            }
        }

        s3_cli_cm_listen_h = INVALID_HANDLE_VALUE;
    }

    return 0;
}

#else

/* the unix accept: the listening socket rides the event loop, every
 * accepted fd becomes a tick-pumped conn at once (the backlog holds
 * the arrivals between the events, no thread and no queue) */

static void
s3_cli_cm_accept_ev(s3_event_t *ev)
{
    (void)ev;

    for (;;) {

        int cfd = accept(s3_cli_cm_listen_fd, NULL, NULL);

        if (cfd < 0) {

            /* EAGAIN or a transient: the next event retries */

            return;
        }

        s3_cli_cm_conn_new(cfd);
    }
}

#endif

static void
s3_cli_cm_listen_open(void)
{
    if (s3_cli_cm_pipe_name_called == 0) {
        s3_cli_cm_pipe_name(s3_cli_cm_path, sizeof(s3_cli_cm_path));
        s3_cli_cm_pipe_name_called = 1;
    }

#if (S3_WIN32)

    /* the win bring-up: the CS, the armed event and the accept thread
     * (the tick drains the connected handles it queues) */

    if (s3_cli_cm_acc_cs_init == 0) {
        InitializeCriticalSection(&s3_cli_cm_acc_cs);
        s3_cli_cm_acc_cs_init = 1;
    }

    s3_cli_cm_acc_armed = CreateEventW(NULL, TRUE, FALSE, NULL);

    if (s3_cli_cm_acc_armed == NULL) {
        s3_cli_rc = S3_CLI_EXIT_ERROR;
        s3_quic_finalize_connection(((s3_quic_stream_t *)s3_cli_ctrl->data)->parent, 0,
                                    "the control pipe failed");
        return;
    }

    s3_cli_cm_acc_run = 1;

    s3_cli_cm_acc_thread = (HANDLE)_beginthreadex(NULL, 0, s3_cli_cm_accept_thread, NULL, 0, NULL);

    if (s3_cli_cm_acc_thread == NULL) {
        s3_cli_cm_acc_run = 0;
        s3_cli_rc = S3_CLI_EXIT_ERROR;
        s3_quic_finalize_connection(((s3_quic_stream_t *)s3_cli_ctrl->data)->parent, 0,
                                    "the control pipe failed");
        return;
    }

    if (WaitForSingleObject(s3_cli_cm_acc_armed, 5000) != WAIT_OBJECT_0 || s3_cli_cm_acc_failed) {

        if (s3_cli_cm_acc_failed == ERROR_ACCESS_DENIED) {
            fprintf(stderr, "ssh3: a control master is already running on %s\n", s3_cli_cm_path);
        } else if (s3_cli_cm_acc_failed) {
            fprintf(stderr, "ssh3: CreateNamedPipeW(%s) failed (%lu)\n", s3_cli_cm_path,
                    (unsigned long)s3_cli_cm_acc_failed);
        } else {
            fprintf(stderr, "ssh3: the control pipe did not come up\n");
        }

        s3_cli_cm_acc_run = 0;
        CancelSynchronousIo(s3_cli_cm_acc_thread);
        WaitForSingleObject(s3_cli_cm_acc_thread, 2000);
        s3_cli_rc = S3_CLI_EXIT_ERROR;
        s3_quic_finalize_connection(((s3_quic_stream_t *)s3_cli_ctrl->data)->parent, 0,
                                    "the control pipe failed");
        return;
    }

#else

    /* the unix bring-up: the stream socket, the stale-socket probe
     * (a live master answers, a dead one unlinks) and the bind on the
     * event loop (the accepts ride the read events, no thread) */

    {
        struct sockaddr_un sa;
        s3_cli_cm_h_t      probe;
        s3_connection_t   *c;
        int                fd;

        fd = socket(AF_UNIX, SOCK_STREAM, 0);

        if (fd < 0) {
            fprintf(stderr, "ssh3: socket() failed for the control socket\n");
            s3_cli_rc = S3_CLI_EXIT_ERROR;
            s3_quic_finalize_connection(((s3_quic_stream_t *)s3_cli_ctrl->data)->parent, 0,
                                        "the control socket failed");
            return;
        }

        memset(&sa, 0, sizeof(sa));

        sa.sun_family = AF_UNIX;

        if (strlen(s3_cli_cm_path) >= sizeof(sa.sun_path)) {
            fprintf(stderr, "ssh3: the control socket path %s is too long\n", s3_cli_cm_path);
            close(fd);
            s3_cli_rc = S3_CLI_EXIT_ERROR;
            s3_quic_finalize_connection(((s3_quic_stream_t *)s3_cli_ctrl->data)->parent, 0,
                                        "the control socket failed");
            return;
        }

        memcpy(sa.sun_path, s3_cli_cm_path, strlen(s3_cli_cm_path));

        probe = socket(AF_UNIX, SOCK_STREAM, 0);

        if (probe >= 0) {

            if (connect(probe, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
                fprintf(stderr, "ssh3: a control master is already running on %s\n",
                        s3_cli_cm_path);
                close(probe);
                close(fd);
                s3_cli_rc = S3_CLI_EXIT_ERROR;
                s3_quic_finalize_connection(((s3_quic_stream_t *)s3_cli_ctrl->data)->parent, 0,
                                            "the control socket failed");
                return;
            }

            close(probe);

            /* the stale socket of a dead master: the bind replaces it */

            (void)unlink(s3_cli_cm_path);
        }

        if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0 || listen(fd, 16) != 0) {
            fprintf(stderr, "ssh3: the control socket %s failed (%s)\n", s3_cli_cm_path,
                    strerror(errno));
            close(fd);
            s3_cli_rc = S3_CLI_EXIT_ERROR;
            s3_quic_finalize_connection(((s3_quic_stream_t *)s3_cli_ctrl->data)->parent, 0,
                                        "the control socket failed");
            return;
        }

        (void)chmod(s3_cli_cm_path, 0600);

        if (s3_nonblocking((s3_fd_t)fd) != S3_OK) {
            close(fd);
            s3_cli_rc = S3_CLI_EXIT_ERROR;
            s3_quic_finalize_connection(((s3_quic_stream_t *)s3_cli_ctrl->data)->parent, 0,
                                        "the control socket failed");
            return;
        }

        c = s3_get_connection(&s3_cli_ctx, (s3_fd_t)fd);

        if (c == NULL) {
            close(fd);
            s3_cli_rc = S3_CLI_EXIT_ERROR;
            s3_quic_finalize_connection(((s3_quic_stream_t *)s3_cli_ctrl->data)->parent, 0,
                                        "the control socket failed");
            return;
        }

        c->read->handler = s3_cli_cm_accept_ev;
        c->read->data = c; /* the select module contract: data is the conn */
        c->read->active = 1;

        if (s3_event_actions.add_event(c->read, S3_READ_EVENT, 0) != S3_OK) {
            s3_close_connection(c);
            s3_cli_rc = S3_CLI_EXIT_ERROR;
            s3_quic_finalize_connection(((s3_quic_stream_t *)s3_cli_ctrl->data)->parent, 0,
                                        "the control socket failed");
            return;
        }

        s3_cli_cm_listen_fd = fd;
        s3_cli_cm_listen_c = c;
    }

#endif

    s3_cli_cm_listening = 1;
    s3_cli_cm_started_ms = s3_current_msec;
    s3_cli_cm_activity = s3_current_msec;

    printf("S3CM-MASTER-LISTEN path=%s\n", s3_cli_cm_path);
    fflush(stdout);
}

static s3_cli_cm_run_t *
s3_cli_cm_run_alloc(void)
{
    uint32_t i;

    for (i = 0; i < S3_SSH3_CM_SRV_SESSIONS; i++) {

        if (!s3_cli_cm_runs[i].used) {
            memset(&s3_cli_cm_runs[i], 0, sizeof(s3_cli_cm_runs[i]));
            s3_cli_cm_runs[i].used = 1;

            return &s3_cli_cm_runs[i];
        }
    }

    return NULL;
}

static s3_cli_cm_run_t *
s3_cli_cm_run_by_token(const u_char token[S3_SSH3_CM_TOKEN_LEN])
{
    uint32_t i;

    for (i = 0; i < S3_SSH3_CM_SRV_SESSIONS; i++) {

        if (s3_cli_cm_runs[i].used &&
            memcmp(s3_cli_cm_runs[i].token, token, S3_SSH3_CM_TOKEN_LEN) == 0) {
            return &s3_cli_cm_runs[i];
        }
    }

    return NULL;
}

static s3_cli_cm_run_t *
s3_cli_cm_run_by_chan(s3_connection_t *chan)
{
    uint32_t i;

    for (i = 0; i < S3_SSH3_CM_SRV_SESSIONS; i++) {

        if (s3_cli_cm_runs[i].used && s3_cli_cm_runs[i].chan == chan) {
            return &s3_cli_cm_runs[i];
        }
    }

    return NULL;
}

static unsigned
s3_cli_cm_runs_live(void)
{
    unsigned n = 0;
    uint32_t i;

    for (i = 0; i < S3_SSH3_CM_SRV_SESSIONS; i++) {
        n += s3_cli_cm_runs[i].used && !s3_cli_cm_runs[i].finalized;
    }

    return n;
}

/* the accept stop: the flag drops, the blocking connect cancels, the
 * pending instance and the queued handles close (the pipe name dies
 * with them, no stale file on the pipe shape); the unix listener
 * closes on the event loop, the socket path unlinks with it */

static void
s3_cli_cm_acc_thread_stop(void)
{
#if (S3_WIN32)
    LONG head, tail;

    if (s3_cli_cm_acc_thread == NULL) {
        return;
    }

    s3_cli_cm_acc_run = 0;

    if (s3_cli_cm_listen_h != NULL && s3_cli_cm_listen_h != INVALID_HANDLE_VALUE) {
        CancelIoEx(s3_cli_cm_listen_h, NULL);
        DisconnectNamedPipe(s3_cli_cm_listen_h);
        CloseHandle(s3_cli_cm_listen_h);
        s3_cli_cm_listen_h = INVALID_HANDLE_VALUE;
    }

    CancelSynchronousIo(s3_cli_cm_acc_thread);
    WaitForSingleObject(s3_cli_cm_acc_thread, 2000);
    CloseHandle(s3_cli_cm_acc_thread);
    s3_cli_cm_acc_thread = NULL;

    EnterCriticalSection(&s3_cli_cm_acc_cs);

    for (head = s3_cli_cm_acc_head, tail = s3_cli_cm_acc_tail; tail < head; tail++) {
        CloseHandle(s3_cli_cm_acc_queue[tail % S3_CLI_CM_ACC_QUEUE]);
    }

    s3_cli_cm_acc_head = s3_cli_cm_acc_tail = 0;

    LeaveCriticalSection(&s3_cli_cm_acc_cs);
#else
    if (s3_cli_cm_listen_c != NULL) {

        s3_close_connection(s3_cli_cm_listen_c); /* the fd goes with it */

        s3_cli_cm_listen_c = NULL;
        s3_cli_cm_listen_fd = -1;

        (void)unlink(s3_cli_cm_path);
    }
#endif
}

/* the master stops: the listening instance drops, the pipe name
 * dies with the handle (no stale file on the pipe shape) */

static void
s3_cli_cm_shutdown(void)
{
    if (s3_cli_cm_stop) {
        return;
    }

    s3_cli_cm_stop = 1;

    s3_cli_cm_acc_thread_stop();

    s3_cli_cm_listening = 0;
}

static s3_int_t
s3_cli_cm_out_append(s3_cli_cm_conn_t *conn, const u_char *data, size_t n)
{
    u_char *grown;
    size_t  want;

    if (conn->out_cap - conn->out_len < n) {

        want = conn->out_cap != 0 ? conn->out_cap : S3_CLI_CM_BUF_INIT;

        while (want - conn->out_len < n) {
            want *= 2;
        }

        grown = s3_pnalloc(conn->pool, want);

        if (grown == NULL) {
            return S3_ERROR;
        }

        if (conn->out_len > 0) {
            memcpy(grown, conn->out, conn->out_len);
        }

        conn->out = grown;
        conn->out_cap = want;
    }

    if (n > 0) {
        memcpy(conn->out + conn->out_len, data, n);
        conn->out_len += n;
    }

    return S3_OK;
}

/* the parked replies drain into the sync write (a control-plane
 * reply is under the pipe buffer, the write completes at once; the
 * partial send parks the tail for the next tick) */

static void
s3_cli_cm_conn_flush(s3_cli_cm_conn_t *conn)
{
    ssize_t put;

    if (conn->dead || conn->out_len == 0) {
        return;
    }

    put = s3_cli_cm_h_write(conn->h, conn->out, conn->out_len);

    if (put == (ssize_t)S3_AGAIN) {

        /* the unix socket took nothing, the tick retries */

        return;
    }

    if (put <= 0) {

        s3_cli_cm_conn_close(conn);
        return;
    }

    conn->out_len -= (size_t)put;

    if (conn->out_len > 0) {
        memmove(conn->out, conn->out + put, conn->out_len);
    }
}

static void
s3_cli_cm_conn_send(s3_cli_cm_conn_t *conn, const u_char *data, size_t n)
{
    if (conn == NULL || conn->dead || n == 0) {
        return;
    }

    if (s3_cli_cm_out_append(conn, data, n) != S3_OK) {
        s3_cli_cm_conn_close(conn);
        return;
    }

    s3_cli_cm_conn_flush(conn);
}

/* the conn close: the run pointers sweep, the handle drops, the
 * pool lives to the graveyard tick (the callers iterate) */

static void
s3_cli_cm_conn_close(s3_cli_cm_conn_t *conn)
{
    s3_cli_cm_conn_t **link;
    s3_cli_cm_run_t   *run = conn->run;

    if (conn->dead) {
        return;
    }

    conn->dead = 1;

    for (link = &s3_cli_cm_conns; *link != NULL; link = &(*link)->next) {

        if (*link == conn) {
            *link = conn->next;
            break;
        }
    }

    if (run != NULL) {

        if (run->control == conn) {
            run->control = NULL;

            if (!run->finalized) {

                /* the slave ended the control conn before the exit
                 * status: the session slot frees, the bridge closes */

                s3_cli_cm_run_finalize(run, 255);
            }
        }

        if (run->io == conn) {
            run->io = NULL;
        }

        if (run->err == conn) {
            run->err = NULL;
        }

        if (run->finalized && run->control == NULL && run->io == NULL && run->err == NULL) {

            /* the finished run whose conns all left */

            (void)s3_ssh3_cm_sessions_release(&s3_cli_cm_table, run->token);
            memset(run, 0, sizeof(*run));
        }
    }

    if (s3_cli_cm_h_valid(conn->h)) {
#if (S3_WIN32)
        DisconnectNamedPipe(conn->h); /* the server half answers the client */
#endif
        s3_cli_cm_h_close(conn->h);
        conn->h = S3_CLI_H_INVALID;
    }

    /* the pool lives to the graveyard sweep of the tick: the srv
     * under it may be mid-input in the caller's frame */

    conn->pool = NULL;

    if (s3_cli_cm_graveyard == NULL) {
        s3_cli_cm_graveyard = conn;
        conn->grave_next = NULL;

    } else {
        conn->grave_next = s3_cli_cm_graveyard;
        s3_cli_cm_graveyard = conn;
    }
}

/* the peer eof: the half-close semantics of the reference */

static void
s3_cli_cm_conn_eof(s3_cli_cm_conn_t *conn)
{
    if (conn->kind == S3_CLI_CM_CONN_IO && conn->run != NULL && conn->run->bridged) {

        if (conn->run->chan != NULL) {
            (void)s3_quic_shutdown_stream(conn->run->chan, S3_WRITE_SHUTDOWN);

        } else {
            s3_cli_cm_conn_close(conn);
        }

        return;
    }

    if (conn->kind == S3_CLI_CM_CONN_STDERR && conn->run != NULL) {

        if (conn->run->finalized) {
            s3_cli_cm_conn_close(conn);
        }

        /* else: the stderr conn waits for the session end */

        return;
    }

    s3_cli_cm_conn_close(conn);
}

/* the stdin direction: the io bytes chunk into the 94 frames, a
 * partial send parks the tail (the tick retries) */

static void
s3_cli_cm_run_stdin_pump(s3_cli_cm_run_t *run)
{
    u_char *p;
    size_t  chunk;
    ssize_t m;

    while (run->stdin_len > 0 || run->frame_sent < run->frame_total) {

        if (run->frame_sent == run->frame_total) {

            chunk = s3_ssh3_channel_chunk_size(S3_CLI_CHANNEL_MAX_PACKET, 0);

            if (chunk > run->stdin_len) {
                chunk = run->stdin_len;
            }

            p = run->frame;
            p = (u_char *)s3_ssh3_encode_varint(p, S3_SSH3_MSG_CHANNEL_DATA);
            p = (u_char *)s3_ssh3_encode_varint(p, chunk);
            memcpy(p, run->stdin_buf, chunk);

            run->frame_total = (size_t)(p - run->frame) + chunk;
            run->frame_sent = 0;

            memmove(run->stdin_buf, run->stdin_buf + chunk, run->stdin_len - chunk);
            run->stdin_len -= chunk;
        }

        m = s3_quic_stream_send(run->chan, run->frame + run->frame_sent,
                                run->frame_total - run->frame_sent);

        if (m == (ssize_t)S3_AGAIN) {
            return;
        }

        if (m <= 0) {
            s3_cli_cm_run_finalize(run, 255);
            return;
        }

        run->frame_sent += (size_t)m;
    }
}

static void
s3_cli_cm_run_stdin(s3_cli_cm_run_t *run, const u_char *data, size_t len)
{
    u_char *grown;
    size_t  cap;

    if (run->stdin_cap - run->stdin_len < len) {

        cap = run->stdin_cap != 0 ? run->stdin_cap : S3_CLI_CM_BUF_INIT;

        while (cap - run->stdin_len < len) {
            cap *= 2;
        }

        grown = realloc(run->stdin_buf, cap);

        if (grown == NULL) {
            s3_cli_cm_run_finalize(run, 255);
            return;
        }

        run->stdin_buf = grown;
        run->stdin_cap = cap;
    }

    memcpy(run->stdin_buf + run->stdin_len, data, len);
    run->stdin_len += len;

    s3_cli_cm_run_stdin_pump(run);
}

/* the exit status of the verdict, queued on the control conn */

/* the pre-attach session bytes: the exec output may beat the slave
 * attach conns, the buffers flush on the bridge */

static void
s3_cli_cm_run_pend(s3_cli_cm_run_t *run, unsigned err, const u_char *data, size_t n)
{
    u_char **buf = err ? &run->pend_err : &run->pend_out;
    size_t  *len = err ? &run->pend_err_len : &run->pend_out_len;
    size_t  *cap = err ? &run->pend_err_cap : &run->pend_out_cap;
    u_char  *grown;
    size_t   want;

    if (*cap - *len < n) {

        want = *cap != 0 ? *cap : S3_CLI_CM_BUF_INIT;

        while (want - *len < n) {
            want *= 2;
        }

        grown = realloc(*buf, want);

        if (grown == NULL) {
            s3_cli_cm_run_finalize(run, 255);
            return;
        }

        *buf = grown;
        *cap = want;
    }

    memcpy(*buf + *len, data, n);
    *len += n;
}

static void
s3_cli_cm_run_pend_flush(s3_cli_cm_run_t *run, unsigned err)
{
    u_char          **buf = err ? &run->pend_err : &run->pend_out;
    size_t           *len = err ? &run->pend_err_len : &run->pend_out_len;
    s3_cli_cm_conn_t *conn = err ? run->err : run->io;

    if (conn != NULL && *len > 0) {
        s3_cli_cm_conn_send(conn, *buf, *len);
    }

    free(*buf);
    *buf = NULL;
}

static void
s3_cli_cm_run_send_exit(s3_cli_cm_run_t *run, uint64_t code)
{
    u_char   es[8];
    u_char   fr[S3_SSH3_CM_HEADER_LEN + sizeof(es)];
    s3_str_t pl;
    u_char  *p;

    if (run->control == NULL || run->exit_queued) {
        return;
    }

    run->exit_queued = 1;

    pl.data = es;
    pl.len = sizeof(es);

    (void)s3_ssh3_cm_encode_exit_status(es, code);

    p = fr;
    p = (u_char *)s3_ssh3_cm_encode_frame(p, S3_SSH3_CM_MSG_EXIT_STATUS, &pl);

    s3_cli_cm_conn_send(run->control, fr, (size_t)(p - fr));
}

/* the session teardown: the verdict, the slot release, the channel
 * shut (the attach guards of the reference) */

static void
s3_cli_cm_run_finalize(s3_cli_cm_run_t *run, uint64_t code)
{
    if (run->finalized) {
        return;
    }

    run->finalized = 1;
    run->exit_code = code;

    if (run->bridged) {
        s3_cli_cm_run_send_exit(run, code);
        (void)s3_ssh3_cm_sessions_release(&s3_cli_cm_table, run->token);
    }

    if (run->chan != NULL) {

        /* the quic stream ops ride the live connection only */

        if (s3_cli_conn != NULL && s3_quic_get_connection(s3_cli_conn) != NULL) {
            (void)s3_quic_shutdown_stream(run->chan, S3_RDWR_SHUTDOWN);
            s3_close_connection(run->chan);
        }

        run->chan = NULL;
    }

    printf("S3CM-MASTER-SESSION-DONE exit=%llu\n", (unsigned long long)code);
    fflush(stdout);

    if (!run->bridged) {

        /* the attach is still ahead: the run, the token slot and
         * the control conn live until the bridge arrives or the
         * slave vanishes (the conn close paths answer both) */

        return;
    }

    if (run->control != NULL) {
        s3_cli_cm_conn_close(run->control);
    }

    if (run->io != NULL) {
        s3_cli_cm_conn_close(run->io);
    }

    if (run->err != NULL) {
        s3_cli_cm_conn_close(run->err);
    }

    if (run->used && run->finalized && run->control == NULL && run->io == NULL &&
        run->err == NULL) {

        (void)s3_ssh3_cm_sessions_release(&s3_cli_cm_table, run->token);
        memset(run, 0, sizeof(*run));
    }
}

/* the run channel reader: the 91, the 94 dispatch to the attached
 * conns, the 98 exit-status request of the server */

static void
s3_cli_cm_run_read(s3_event_t *ev)
{
    s3_connection_t *chan = ev->data;
    s3_cli_cm_run_t *run = s3_cli_cm_run_by_chan(chan);
    const u_char    *pos, *end;
    ssize_t          n;

    if (run == NULL || run->finalized) {
        /* the tail events of a finished session are noise */
        return;
    }

    for (;;) {

        if (run->ch_len == run->ch_cap) {

            size_t  cap;
            u_char *grown;

            /* the accumulator bound: a full buffer with no complete
             * frame inside is a peer trickling bytes */

            if (run->ch_cap >= S3_CLI_FWD_PARK_MAX) {
                s3_cli_cm_run_finalize(run, 255);
                return;
            }

            cap = run->ch_cap + 262144;

            grown = realloc(run->ch_buf, cap);

            if (grown == NULL) {
                s3_cli_cm_run_finalize(run, 255);
                return;
            }

            run->ch_buf = grown;
            run->ch_cap = cap;
        }

        n = chan->recv(chan, run->ch_buf + run->ch_len, run->ch_cap - run->ch_len);

        if (n == (ssize_t)S3_AGAIN) {
            return;
        }

        if (n <= 0) {

            /* the server fin before the exit status maps to 255 */

            fprintf(stderr, "ssh3-cm: the run channel %s (n=%d)\n", n == 0 ? "closed" : "errored",
                    (int)n);
            s3_cli_cm_run_finalize(run, 255);
            return;
        }

        run->ch_len += (size_t)n;

        pos = run->ch_buf;
        end = run->ch_buf + run->ch_len;

        while (pos < end) {

            uint64_t type;

            if (s3_ssh3_parse_varint(&pos, end, &type) != S3_OK) {
                break;
            }

            if (type == S3_SSH3_MSG_CHANNEL_OPEN_CONFIRMATION) {

                s3_ssh3_msg_open_confirmation_t conf;

                if (s3_ssh3_msg_parse_open_confirmation(&pos, end, &conf) != S3_OK) {
                    break;
                }

                run->ch_confirmed = 1;

                continue;
            }

            if (type == S3_SSH3_MSG_CHANNEL_DATA) {

                s3_ssh3_msg_data_t msg;

                if (!run->ch_confirmed) {
                    s3_cli_cm_run_finalize(run, 255);
                    return;
                }

                if (s3_ssh3_msg_parse_data(&pos, end, &msg) != S3_OK) {
                    break;
                }

                /* the session stdout rides the io attachment (the
                 * pre-attach bytes buffer) */

                if (run->io != NULL) {
                    s3_cli_cm_conn_send(run->io, msg.data.data, msg.data.len);
                } else {
                    s3_cli_cm_run_pend(run, 0, msg.data.data, msg.data.len);
                }

                continue;
            }

            if (type == S3_SSH3_MSG_CHANNEL_EXTENDED_DATA) {

                s3_ssh3_msg_extended_data_t xmsg;

                if (s3_ssh3_msg_parse_extended_data(&pos, end, &xmsg) != S3_OK) {
                    break;
                }

                /* the session stderr rides the stderr attachment
                 * (the pre-attach bytes buffer) */

                if (run->err != NULL) {
                    s3_cli_cm_conn_send(run->err, xmsg.data.data, xmsg.data.len);
                } else {
                    s3_cli_cm_run_pend(run, 1, xmsg.data.data, xmsg.data.len);
                }

                continue;
            }

            if (type == S3_SSH3_MSG_CHANNEL_REQUEST) {

                s3_ssh3_msg_request_t env;
                s3_ssh3_request_t     body;
                const u_char         *bpos;
                s3_int_t              rc;

                if (s3_ssh3_msg_parse_request_envelope(&pos, end, &env) != S3_OK) {

                    /* a partial envelope, the parse left pos untouched */

                    break;
                }

                bpos = pos;

                rc = s3_ssh3_request_parse_body(&bpos, end, &env.request_type, &body);

                if (rc == S3_OK) {

                    if (body.kind == S3_SSH3_REQ_EXIT_STATUS) {
                        s3_cli_cm_run_finalize(run, body.u.exit_status.status);
                        return;
                    }

                    /* the request replies without the verdict drain */

                    continue;
                }

                /* an unknown request type: its body has no length
                 * prefix, the buffer tail drains */

                pos = end;

                continue;
            }

            /* the open failure or the unknown message ends the session */

            s3_cli_cm_run_finalize(run, 255);

            return;
        }

        run->ch_len = (size_t)(end - pos);
        memmove(run->ch_buf, pos, run->ch_len);
    }
}

/* the srv callbacks; the codec dispatch runs inside the feed of the
 * current connection, s3_cli_cm_cur names it */

static s3_int_t
s3_cli_cm_cb_open_session(void *ctx, const s3_ssh3_cm_open_session_t *req,
                          u_char token[S3_SSH3_CM_TOKEN_LEN], const char **err)
{
    s3_cli_cm_run_t  *run;
    s3_connection_t  *chan;
    s3_ssh3_channel_t hdr;
    s3_ssh3_request_t exec;
    u_char            frame[2048];
    u_char           *p;
    char              cmd[S3_CLI_CM_CMD_MAX];
    size_t            cl, total;
    ssize_t           m;
    uint32_t          j;

    (void)ctx;

    /* the codec allocs the slot after this callback, the room
     * checks here */

    if (s3_cli_cm_table.count >= S3_SSH3_CM_SRV_SESSIONS) {
        *err = "too many sessions";

        return S3_ERROR;
    }

    if (req->ncommand == 0) {
        *err = "empty command";

        return S3_ERROR;
    }

    /* the command list joins with spaces, the reference strings.Join */

    cl = 0;

    for (j = 0; j < req->ncommand; j++) {

        if (cl + req->command[j].len + 2 > sizeof(cmd)) {
            *err = "command too long";

            return S3_ERROR;
        }

        memcpy(cmd + cl, req->command[j].data, req->command[j].len);
        cl += req->command[j].len;
        cmd[cl++] = ' ';
    }

    cmd[cl - 1] = '\0';

    run = s3_cli_cm_run_alloc();

    if (run == NULL) {
        *err = "too many sessions";

        return S3_ERROR;
    }

    if (RAND_bytes(token, S3_SSH3_CM_TOKEN_LEN) != 1) {
        *err = "token generation failed";
        memset(run, 0, sizeof(*run));

        return S3_ERROR;
    }

    /* the session channel of the shared connection: the header and
     * the exec request in one send */

    chan = s3_quic_open_stream(s3_cli_conn, 1);

    if (chan == NULL) {
        *err = "channel open failed";
        memset(run, 0, sizeof(*run));

        return S3_ERROR;
    }

    memset(&hdr, 0, sizeof(hdr));

    hdr.conversation_stream_id = s3_cli_conv_id;
    hdr.max_packet_size = S3_CLI_CHANNEL_MAX_PACKET;
    hdr.type.data = (u_char *)S3_SSH3_CHANNEL_TYPE_SESSION;
    hdr.type.len = strlen(S3_SSH3_CHANNEL_TYPE_SESSION);

    memset(&exec, 0, sizeof(exec));

    exec.kind = S3_SSH3_REQ_EXEC;
    exec.u.exec.command.data = (u_char *)cmd;
    exec.u.exec.command.len = strlen(cmd);

    p = frame;
    p = (u_char *)s3_ssh3_channel_build_header(p, &hdr);
    p = s3_cli_session_request(p, S3_SSH3_REQ_EXEC, 1, &exec);

    total = (size_t)(p - frame);

    m = s3_quic_stream_send(chan, frame, total);

    if (m != (ssize_t)total) {
        (void)s3_quic_shutdown_stream(chan, S3_RDWR_SHUTDOWN);
        *err = "channel send failed";
        memset(run, 0, sizeof(*run));

        return S3_ERROR;
    }

    chan->read->handler = s3_cli_cm_run_read;
    chan->read->data = chan;
    chan->read->active = 1;

    memcpy(run->token, token, S3_SSH3_CM_TOKEN_LEN);
    run->chan = chan;
    run->control = s3_cli_cm_cur;

    if (run->control != NULL) {
        run->control->run = run;
        run->control->kind = S3_CLI_CM_CONN_CONTROL;
    }

    return S3_OK;
}

static void
s3_cli_cm_cb_bridge(void *ctx, const u_char token[S3_SSH3_CM_TOKEN_LEN])
{
    s3_cli_cm_run_t *run = s3_cli_cm_run_by_token(token);

    (void)ctx;

    if (run == NULL) {
        return;
    }

    run->bridged = 1;

    if (s3_cli_cm_cur != NULL) {
        run->io = s3_cli_cm_cur;
        s3_cli_cm_cur->run = run;
        s3_cli_cm_cur->kind = S3_CLI_CM_CONN_IO;
    }

    /* the flush waits out the tick: the slave reads the attach
     * reply with the serial cli, the raw behind it in one chunk
     * would kill the parse */

    run->pend_due_out = 1;

    if (run->finalized) {

        /* the verdict beat the attach: the attach replies are on
         * the wire already, the exit status rides after them, the
         * run unwinds when the slave conns close */

        s3_cli_cm_run_send_exit(run, run->exit_code);
    }
}

static void
s3_cli_cm_cb_bridge_stderr(void *ctx, const u_char token[S3_SSH3_CM_TOKEN_LEN])
{
    s3_cli_cm_run_t *run = s3_cli_cm_run_by_token(token);

    (void)ctx;

    if (run == NULL) {
        return;
    }

    if (s3_cli_cm_cur != NULL && s3_cli_cm_cur->run == NULL) {
        run->err = s3_cli_cm_cur;
        s3_cli_cm_cur->run = run;
        s3_cli_cm_cur->kind = S3_CLI_CM_CONN_STDERR;
    }

    run->pend_due_err = 1;

    if (run->finalized) {
        s3_cli_cm_run_send_exit(run, run->exit_code);
    }
}

static s3_int_t
s3_cli_cm_cb_status(void *ctx, s3_ssh3_cm_status_t *st)
{
    (void)ctx;

    st->path = s3_cli_cm_path;
    st->pid = (int)s3_cli_pid();
    st->protocol = S3_SSH3_CM_VERSION;
    st->uptime_s = (double)(s3_current_msec - s3_cli_cm_started_ms) / 1000.0;
    st->sessions = (int)s3_cli_cm_table.count;
    st->forwards = 0;

    return S3_OK;
}

/* the per-conn feed: the codec pumps until the io or the stderr
 * bridge owns the attachment */

static void
s3_cli_cm_conn_feed(s3_cli_cm_conn_t *conn, const u_char *data, size_t n)
{
    u_char obuf[16384];
    size_t off = 0;

    while (off < n && !conn->dead) {

        size_t piece = n - off;

        if (piece > sizeof(obuf)) {
            piece = sizeof(obuf);
        }

        s3_cli_cm_activity = s3_current_msec;

        if (conn->kind != S3_CLI_CM_CONN_IO || conn->run == NULL || !conn->run->bridged) {

            s3_cli_cm_cur = conn;

            if (s3_ssh3_cm_srv_input(&conn->srv, data + off, piece) != S3_OK) {
                s3_cli_cm_cur = NULL;
                s3_cli_cm_conn_close(conn);
                return;
            }

            s3_cli_cm_cur = NULL;

            for (;;) {

                ssize_t m = s3_ssh3_cm_srv_output(&conn->srv, obuf, sizeof(obuf));

                if (m <= 0) {
                    break;
                }

                s3_cli_cm_conn_send(conn, obuf, (size_t)m);

                if (conn->dead) {
                    return;
                }
            }

            if (s3_ssh3_cm_srv_done(&conn->srv)) {

                if (s3_ssh3_cm_srv_shutdown(&conn->srv)) {
                    s3_cli_cm_shutdown();
                }

                /* the reply is on the wire: the close waits a few
                   ticks, the serial client reads it before the
                   disconnect */

                conn->close_due = 3;

                return;
            }

        } else if (conn->run->chan == NULL) {

            /* the verdict beat the attach: the late stdin drops */

        } else {

            /* the bridged io attachment feeds the session stdin */

            s3_cli_cm_run_stdin(conn->run, data + off, piece);

            if (conn->run->finalized) {
                return;
            }
        }

        off += piece;
    }
}

/* the new conn of one connected transport half (the pipe instance of
 * the accept queue on win, the accepted socket of the event loop on
 * unix, the tick pumps both) */

static void
s3_cli_cm_conn_new(s3_cli_cm_h_t h)
{
    static s3_ssh3_cm_srv_cbs_t cbs;
    s3_pool_t                  *pool;
    s3_cli_cm_conn_t           *conn;

    if (cbs.open_session == NULL) {
        cbs.open_session = s3_cli_cm_cb_open_session;
        cbs.bridge = s3_cli_cm_cb_bridge;
        cbs.bridge_stderr = s3_cli_cm_cb_bridge_stderr;
        cbs.status = s3_cli_cm_cb_status;
    }

#if (S3_WIN32)
#else
    /* the tick pump gates the reads on poll() and parks the partial
     * writes, the nonblocking fd makes both shapes honest */

    if (s3_nonblocking((s3_fd_t)h) != S3_OK) {
        close(h);
        return;
    }
#endif

    pool = s3_create_pool(S3_DEFAULT_POOL_SIZE, &s3_cli_log);

    if (pool == NULL) {
        s3_cli_cm_h_close(h);
        return;
    }

    conn = s3_pcalloc(pool, sizeof(*conn));

    if (conn == NULL) {
        s3_destroy_pool(pool);
        s3_cli_cm_h_close(h);
        return;
    }

    conn->h = h;
    conn->pool = pool;
    conn->kind = S3_CLI_CM_CONN_CONTROL;

    if (s3_ssh3_cm_srv_init(&conn->srv, pool, &s3_cli_cm_table, &cbs, NULL) != S3_OK) {
        s3_destroy_pool(pool);
        s3_cli_cm_h_close(h);
        return;
    }

    conn->next = s3_cli_cm_conns;
    s3_cli_cm_conns = conn;

    s3_cli_cm_activity = s3_current_msec;
}

/* the accepted handles of the accept thread drain into the conns (the
 * unix accepts land on the event loop, the drain is a no-op there) */

static void
s3_cli_cm_accepts_drain(void)
{
#if (S3_WIN32)
    LONG head, tail;

    if (s3_cli_cm_stop) {
        return;
    }

    EnterCriticalSection(&s3_cli_cm_acc_cs);

    for (head = s3_cli_cm_acc_head, tail = s3_cli_cm_acc_tail; tail < head; tail++) {

        HANDLE h = s3_cli_cm_acc_queue[tail % S3_CLI_CM_ACC_QUEUE];

        s3_cli_cm_acc_queue[tail % S3_CLI_CM_ACC_QUEUE] = NULL;

        LeaveCriticalSection(&s3_cli_cm_acc_cs);

        s3_cli_cm_conn_new(h);

        EnterCriticalSection(&s3_cli_cm_acc_cs);
    }

    s3_cli_cm_acc_tail = tail;

    LeaveCriticalSection(&s3_cli_cm_acc_cs);
#endif
}

/* the per-conn tick: the arrived bytes feed the codec, the reply
 * flushes, the shutdown drains */

static void
s3_cli_cm_conn_tick(s3_cli_cm_conn_t *conn)
{
    if (conn->dead) {
        return;
    }

    if (conn->close_due) {

        /* the done reply drained: the close waits out the counter,
           the client polls the pipe every tick */

        conn->close_due--;

        if (conn->close_due == 0) {
            s3_cli_cm_conn_close(conn);
        }

        return;
    }

    s3_cli_cm_conn_flush(conn);

    if (conn->dead) {
        return;
    }

    if (conn->out_len == 0 && s3_ssh3_cm_srv_shutdown(&conn->srv)) {

        /* the stop reply drained, the master closes with it */

        s3_cli_cm_shutdown();
        s3_cli_cm_conn_close(conn);
        return;
    }

    /* the arrived bytes feed the codec until the transport runs idle
     * (the eof of the peer rides the read of zero) */

    for (;;) {

        ssize_t n;

        if (s3_cli_cm_h_poll(conn->h) < 0) {
            s3_cli_cm_conn_eof(conn);
            return;
        }

        if (s3_cli_cm_h_poll(conn->h) == 0) {
            break;
        }

        n = s3_cli_cm_h_read(conn->h, conn->rbuf, sizeof(conn->rbuf));

        if (n == (ssize_t)S3_AGAIN) {
            break;
        }

        if (n <= 0) {
            s3_cli_cm_conn_eof(conn);
            return;
        }

        s3_cli_cm_conn_feed(conn, conn->rbuf, (size_t)n);

        if (conn->dead) {
            return;
        }
    }
}

/* the master tick: the accept drain, the conn pumps, the idle close
 * with no live sessions and no control traffic */

static void
s3_cli_cm_tick(void)
{
    uint32_t i;

    s3_cli_cm_accepts_drain();

    if (s3_cli_cm_stop) {
        return;
    }

    {
        s3_cli_cm_conn_t *conn = s3_cli_cm_conns;

        while (conn != NULL) {

            s3_cli_cm_conn_t *next = conn->next;

            s3_cli_cm_conn_tick(conn);

            conn = next;
        }
    }

    for (i = 0; i < S3_SSH3_CM_SRV_SESSIONS; i++) {

        s3_cli_cm_run_t *run = &s3_cli_cm_runs[i];

        if (!run->used) {
            continue;
        }

        if (run->pend_due_out && run->io != NULL) {
            run->pend_due_out = 0;
            s3_cli_cm_run_pend_flush(run, 0);
        }

        if (run->pend_due_err && run->err != NULL) {
            run->pend_due_err = 0;
            s3_cli_cm_run_pend_flush(run, 1);
        }

        if (run->bridged && !run->finalized &&
            (run->stdin_len > 0 || run->frame_sent < run->frame_total)) {
            s3_cli_cm_run_stdin_pump(run);
        }

        if (run->finalized && run->bridged && run->exit_queued && !run->pend_due_out &&
            !run->pend_due_err) {

            /* the verdict beat the bridge: the exit status is on the
               control conn, the pending output drained - one tick of
               grace for the slave reads, then the conns close and
               the slave sees the EOFs */

            if (run->close_lag) {

                if (run->control != NULL) {
                    s3_cli_cm_conn_close(run->control);
                }

                if (run->io != NULL) {
                    s3_cli_cm_conn_close(run->io);
                }

                if (run->err != NULL) {
                    s3_cli_cm_conn_close(run->err);
                }

                if (run->used && run->control == NULL && run->io == NULL && run->err == NULL) {
                    (void)s3_ssh3_cm_sessions_release(&s3_cli_cm_table, run->token);
                    memset(run, 0, sizeof(*run));
                }

            } else {
                run->close_lag = 1;
            }
        }
    }

    /* the graveyard: the dead conns' pools die here, a tick after
     * the close (the srv frames of the close may still unwind) */

    if (s3_cli_cm_graveyard != NULL) {

        s3_cli_cm_conn_t *grave = s3_cli_cm_graveyard;

        s3_cli_cm_graveyard = NULL;

        while (grave != NULL) {

            s3_cli_cm_conn_t *next_grave = grave->grave_next;

            if (grave->pool != NULL) {
                s3_destroy_pool(grave->pool);
            }

            grave = next_grave;
        }
    }

    if (s3_cli_cm_runs_live() == 0 && s3_current_msec - s3_cli_cm_activity >= 60000) {

        /* the idle master closes: the clean stop */

        s3_cli_cm_shutdown();
        s3_cli_verdict = 1;
        s3_cli_exit_code = 0;
    }
}

/* the dial of the slave and the control ops: the busy-pipe wait of
 * win, the backlog-retry connect of unix (the handle is sync for the
 * sequential client in both shapes) */

static s3_cli_cm_h_t
s3_cli_cm_dial(const char *path)
{
#if (S3_WIN32)
    wchar_t w[256];
    int     wn;

    wn = MultiByteToWideChar(CP_UTF8, 0, path, -1, w, 256);

    if (wn <= 0) {
        return S3_CLI_H_INVALID;
    }

    for (;;) {

        HANDLE h = CreateFileW(w, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

        if (h != INVALID_HANDLE_VALUE) {
            return h;
        }

        if (GetLastError() != ERROR_PIPE_BUSY) {
            return S3_CLI_H_INVALID;
        }

        if (!WaitNamedPipeW(w, 2000)) {
            return S3_CLI_H_INVALID;
        }
    }
#else
    struct sockaddr_un sa;
    s3_msec_t          deadline;
    int                fd;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);

    if (fd < 0) {
        return S3_CLI_H_INVALID;
    }

    memset(&sa, 0, sizeof(sa));

    sa.sun_family = AF_UNIX;

    if (strlen(path) >= sizeof(sa.sun_path)) {
        close(fd);
        return S3_CLI_H_INVALID;
    }

    memcpy(sa.sun_path, path, strlen(path));

    /* the full accept backlog of the master holds the connect for a
     * while: retry inside the wait window the win shape gives */

    deadline = s3_current_msec + 2000;

    for (;;) {

        if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
            return fd;
        }

        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR && errno != EPROTOTYPE) {
            close(fd);
            return S3_CLI_H_INVALID;
        }

        s3_time_update();

        if (s3_current_msec >= deadline) {
            close(fd);
            return S3_CLI_H_INVALID;
        }

        s3_cli_msleep(10);
    }
#endif
}

/* one sequential Call of the protocol: the frame out, the reply
 * back (the sync handle, the poll loop of the reference) */

static s3_int_t
s3_cli_cm_call(s3_cli_cm_h_t h, s3_ssh3_cm_cli_t *cli, uint8_t type, const s3_str_t *payload,
               s3_str_t *reply, unsigned *is_error, s3_msec_t deadline, const char *what)
{
    u_char  buf[8192];
    ssize_t m;

    if (s3_ssh3_cm_cli_call(cli, type, payload) != S3_OK) {
        fprintf(stderr, "ssh3: %s: the call queue failed\n", what);
        return S3_ERROR;
    }

    for (;;) {

        /* the requests drain (the sync write carries the frame) */

        for (;;) {

            ssize_t put;

            m = s3_ssh3_cm_cli_output(cli, buf, sizeof(buf));

            if (m <= 0) {
                break;
            }

            put = s3_cli_cm_h_write(h, buf, (size_t)m);

            if (put != (ssize_t)m) {
                fprintf(stderr, "ssh3: %s: the pipe write failed\n", what);
                return S3_ERROR;
            }
        }

        /* the reply poll: the arrived bytes feed the cli */

        for (;;) {

            ssize_t got;

            if (s3_cli_cm_h_poll(h) < 0) {
                fprintf(stderr, "ssh3: %s: the pipe closed\n", what);

                return S3_ERROR;
            }

            if (s3_cli_cm_h_poll(h) == 0) {
                break;
            }

            got = s3_cli_cm_h_read(h, buf, sizeof(buf));

            if (got <= 0 || got == (ssize_t)S3_AGAIN) {
                fprintf(stderr, "ssh3: %s: the pipe read failed\n", what);
                return S3_ERROR;
            }

            if (s3_ssh3_cm_cli_input(cli, buf, (size_t)got) != S3_OK) {
                fprintf(stderr, "ssh3: %s: the protocol input failed\n", what);
                return S3_ERROR;
            }
        }

        {
            s3_str_t r;
            unsigned err_flag;

            if (cli->has_reply) {

                /* the reply landed, possibly with the bridge tail of
                   an attach conn in the same chunk: the violation
                   flag then names the raw tail (it stays in the pend
                   for the raw pump), the call itself won */

                if (reply != NULL) {
                    reply->data = cli->reply;
                    reply->len = cli->reply_len;
                }

                if (is_error != NULL) {
                    *is_error = cli->is_error;
                }

                return S3_OK;
            }

            if (s3_ssh3_cm_cli_reply(cli, &r, &err_flag) == S3_OK) {

                if (reply != NULL) {
                    reply->data = r.data;
                    reply->len = r.len;
                }

                if (is_error != NULL) {
                    *is_error = err_flag;
                }

                return S3_OK;
            }
        }

        if (s3_ssh3_cm_cli_protocol_error(cli)) {
            fprintf(stderr, "ssh3: %s: the protocol violation\n", what);
            return S3_ERROR;
        }

        /* no event loop runs here, the clock ticks by hand */

        s3_time_update();

        if (s3_current_msec >= deadline) {
            fprintf(stderr, "ssh3: %s: timed out\n", what);
            return S3_ERROR;
        }

        s3_cli_msleep(10);
    }
}

/* one attach conn of the slave: the hello and the ATTACH of the
 * token (stderr first, like the reference) */

static s3_int_t
s3_cli_cm_attach(s3_cli_cm_h_t *h_out, const char *path, const u_char token[S3_SSH3_CM_TOKEN_LEN],
                 uint8_t kind, s3_msec_t deadline, u_char **leftover, size_t *leftover_len)
{
    s3_pool_t       *pool;
    s3_ssh3_cm_cli_t cli;
    u_char           enc[S3_SSH3_CM_TOKEN_LEN + 1];
    s3_str_t         pl, reply;
    unsigned         is_error;
    s3_cli_cm_h_t    h;

    pool = s3_create_pool(S3_DEFAULT_POOL_SIZE, &s3_cli_log);

    if (pool == NULL) {
        return S3_ERROR;
    }

    h = s3_cli_cm_dial(path);

    if (!s3_cli_cm_h_valid(h)) {
        fprintf(stderr, "ssh3: attach: could not reach the control master\n");
        s3_destroy_pool(pool);
        return S3_ERROR;
    }

    if (s3_ssh3_cm_cli_init(&cli, pool) != S3_OK) {
        s3_cli_cm_h_close(h);
        s3_destroy_pool(pool);
        return S3_ERROR;
    }

    if (s3_cli_cm_call(h, &cli, S3_SSH3_CM_MSG_HELLO, NULL, &reply, &is_error, deadline,
                       "attach hello") != S3_OK ||
        is_error) {
        s3_cli_cm_h_close(h);
        s3_destroy_pool(pool);
        return S3_ERROR;
    }

    memcpy(enc, token, S3_SSH3_CM_TOKEN_LEN);
    enc[S3_SSH3_CM_TOKEN_LEN] = kind;

    pl.data = enc;
    pl.len = sizeof(enc);

    if (s3_cli_cm_call(h, &cli, S3_SSH3_CM_MSG_ATTACH, &pl, &reply, &is_error, deadline,
                       "attach") != S3_OK ||
        is_error) {
        fprintf(stderr, "ssh3: attach refused: %.*s\n", is_error ? (int)reply.len : 0,
                is_error ? (const char *)reply.data : "");
        s3_cli_cm_h_close(h);
        s3_destroy_pool(pool);
        return S3_ERROR;
    }

    /* the pre-attach session bytes may ride behind the reply (the
     * master flushes the bridge at once): the cli leftover hands
     * them to the raw pump */

    *leftover = NULL;
    *leftover_len = 0;

    if (cli.pend_len > 0) {
        u_char *copy = malloc(cli.pend_len);

        if (copy != NULL) {
            memcpy(copy, cli.pend, cli.pend_len);
            *leftover = copy;
            *leftover_len = cli.pend_len;
        }
    }

    s3_destroy_pool(pool);

    *h_out = h;

    return S3_OK;
}

/* the slave (-U pipe -e cmd): the control conn carries the session
 * request and the exit status, the stderr and io attachments bridge
 * on their own connections (stderr first); the io rides fd 1, the
 * err rides fd 2 */

static int
s3_cli_cm_slave_run(void)
{
    s3_pool_t       *pool;
    s3_ssh3_cm_cli_t cli;
    s3_cli_cm_h_t    control = S3_CLI_H_INVALID, hio = S3_CLI_H_INVALID, herr = S3_CLI_H_INVALID;
    s3_ssh3_cm_open_session_t req;
    s3_str_t                  payload, reply;
    u_char                   *enc;
    unsigned                  is_error;
    u_char                   *out_buf = NULL, *err_buf = NULL;
    size_t                    out_len = 0, out_cap = 0, err_len = 0, err_cap = 0;
    s3_msec_t                 deadline;
    uint64_t                  code = 256;
    unsigned                  got_exit = 0, io_eof = 0, err_eof = 0;
    u_char                   *io_left = NULL, *err_left = NULL;
    size_t                    io_left_len = 0, err_left_len = 0;
    int                       rc_exit = 1;
    s3_ssh3_cm_frame_t        fr;
    s3_int_t                  rc;
    uintptr_t                 size;
    static u_char             tin[8192]; /* the control conn frame scanner */
    static size_t             tin_len;

    pool = s3_create_pool(S3_DEFAULT_POOL_SIZE, &s3_cli_log);

    if (pool == NULL) {
        return 1;
    }

    /* the sequential run starts cold: the monotonic clock never
     * ticked here, the deadlines ride the first update */

    s3_time_update();

    deadline = s3_current_msec + 30000;

    control = s3_cli_cm_dial(s3_cli_cm_path);

    if (!s3_cli_cm_h_valid(control)) {
        fprintf(stderr, "ssh3: no control master is listening on %s\n", s3_cli_cm_path);
        goto done;
    }

    if (s3_ssh3_cm_cli_init(&cli, pool) != S3_OK) {
        goto done;
    }

    /* the version handshake */

    if (s3_cli_cm_call(control, &cli, S3_SSH3_CM_MSG_HELLO, NULL, &reply, &is_error, deadline,
                       "hello") != S3_OK ||
        is_error) {
        fprintf(stderr, "ssh3: the peer on %s is not a control master\n", s3_cli_cm_path);
        goto done;
    }

    /* the session request: one command string, no env, no agent */

    memset(&req, 0, sizeof(req));

    req.ncommand = 1;
    req.command[0].data = (u_char *)s3_cli_cm_exec;
    req.command[0].len = strlen(s3_cli_cm_exec);

    size = s3_ssh3_cm_encode_open_session(NULL, &req);
    enc = s3_pnalloc(pool, size);

    if (enc == NULL) {
        goto done;
    }

    (void)s3_ssh3_cm_encode_open_session(enc, &req);

    payload.data = enc;
    payload.len = size;

    if (s3_cli_cm_call(control, &cli, S3_SSH3_CM_MSG_OPEN_SESSION, &payload, &reply, &is_error,
                       deadline, "open_session") != S3_OK) {
        goto done;
    }

    if (is_error) {
        fprintf(stderr, "ssh3: session refused: %.*s\n", (int)reply.len, (const char *)reply.data);
        goto done;
    }

    if (reply.len != S3_SSH3_CM_TOKEN_LEN) {
        fprintf(stderr, "ssh3: malformed session token reply (%zu bytes)\n", reply.len);
        goto done;
    }

    /* the stderr stream attaches before the io stream (the
     * reference order) */

    if (s3_cli_cm_attach(&herr, s3_cli_cm_path, reply.data, S3_SSH3_CM_STREAM_STDERR, deadline,
                         &err_left, &err_left_len) != S3_OK ||
        s3_cli_cm_attach(&hio, s3_cli_cm_path, reply.data, S3_SSH3_CM_STREAM_IO, deadline, &io_left,
                         &io_left_len) != S3_OK) {
        goto done;
    }

    /* the pre-read leftovers of the attach conns (the master may
     * flush the bridge behind the attach reply) */

    if (io_left_len > 0) {
        out_buf = realloc(out_buf, io_left_len);
        memcpy(out_buf, io_left, io_left_len);
        out_len = io_left_len;
        out_cap = io_left_len;
        free(io_left);
    }

    if (err_left_len > 0) {
        err_buf = realloc(err_buf, err_left_len);
        memcpy(err_buf, err_left, err_left_len);
        err_len = err_left_len;
        err_cap = err_left_len;
        free(err_left);
    }

    /* the control conn tail: the frames that rode behind the
       open_session reply stay in the cli pend, the exit scanner
       takes them before the pipe reads */

    if (cli.pend_len > 0 && cli.pend_len <= sizeof(tin)) {
        memcpy(tin + tin_len, cli.pend, cli.pend_len);
        tin_len += cli.pend_len;

        {
            const u_char *scan2 = tin;
            const u_char *end2 = tin + tin_len;

            while (scan2 < end2) {

                rc = s3_ssh3_cm_frame(&scan2, end2, &fr);

                if (rc == S3_AGAIN) {
                    break;
                }

                if (rc != S3_OK) {
                    goto done;
                }

                if (fr.type == S3_SSH3_CM_MSG_EXIT_STATUS &&
                    s3_ssh3_cm_decode_exit_status(&fr.payload, &code) == S3_OK) {
                    got_exit = 1;
                }
            }

            tin_len = (size_t)(end2 - scan2);
            memmove(tin, scan2, tin_len);
        }
    }

    while ((!got_exit || !io_eof || !err_eof) && !s3_cli_stop) {

        /* no event loop runs here, the clock ticks by hand */

        s3_time_update();

        if (s3_current_msec >= deadline) {
            fprintf(stderr, "ssh3: slave timed out\n");
            goto done;
        }

        /* the control conn: the exit status of the bridge */

        if (!got_exit) {

            int avail = s3_cli_cm_h_poll(control);

            if (avail < 0) {
                code = 255;
                got_exit = 1;
            }

            while (avail > 0) {

                u_char buf[8192];

                ssize_t got = s3_cli_cm_h_read(control, buf, sizeof(buf));

                if (got <= 0 || got == (ssize_t)S3_AGAIN) {
                    code = 255;
                    got_exit = 1;
                    break;
                }

                /* the session tail: the exit status frame */

                {
                    const u_char *scan2, *end2;

                    if (tin_len + got <= sizeof(tin)) {
                        memcpy(tin + tin_len, buf, got);
                        tin_len += got;
                    }

                    scan2 = tin;
                    end2 = tin + tin_len;

                    while (scan2 < end2) {

                        rc = s3_ssh3_cm_frame(&scan2, end2, &fr);

                        if (rc == S3_AGAIN) {
                            break;
                        }

                        if (rc != S3_OK) {
                            goto done;
                        }

                        if (fr.type == S3_SSH3_CM_MSG_EXIT_STATUS &&
                            s3_ssh3_cm_decode_exit_status(&fr.payload, &code) == S3_OK) {
                            got_exit = 1;
                        }
                    }

                    tin_len = (size_t)(end2 - scan2);
                    memmove(tin, scan2, tin_len);
                }

                avail = s3_cli_cm_h_poll(control);

                if (avail < 0) {
                    code = 255;
                    got_exit = 1;
                    break;
                }
            }
        }

        /* the io and err conns: the session streams */

        {
            struct {
                s3_cli_cm_h_t h;
                unsigned     *eof;
                u_char      **buf;
                size_t       *len;
                size_t       *cap;
                int           fd;
            } sides[2];

            unsigned k;

            sides[0].h = hio;
            sides[0].eof = &io_eof;
            sides[0].buf = &out_buf;
            sides[0].len = &out_len;
            sides[0].cap = &out_cap;
            sides[0].fd = 1;

            sides[1].h = herr;
            sides[1].eof = &err_eof;
            sides[1].buf = &err_buf;
            sides[1].len = &err_len;
            sides[1].cap = &err_cap;
            sides[1].fd = 2;

            for (k = 0; k < 2; k++) {

                int avail;

                if (*sides[k].eof) {
                    continue;
                }

                avail = s3_cli_cm_h_poll(sides[k].h);

                if (avail < 0) {
                    *sides[k].eof = 1;
                    continue;
                }

                while (avail > 0) {

                    u_char  sbuf[16384];
                    ssize_t got = s3_cli_cm_h_read(sides[k].h, sbuf, sizeof(sbuf));

                    if (got <= 0 || got == (ssize_t)S3_AGAIN) {
                        *sides[k].eof = 1;
                        break;
                    }

                    /* the stream bytes grow the side accum */

                    {
                        u_char *grown;
                        size_t  want = *sides[k].cap != 0 ? *sides[k].cap : S3_CLI_CM_BUF_INIT;

                        while (want - *sides[k].len < (size_t)got) {
                            want *= 2;
                        }

                        grown = realloc(*sides[k].buf, want);

                        if (grown == NULL) {
                            goto done;
                        }

                        *sides[k].buf = grown;
                        *sides[k].cap = want;
                    }

                    memcpy(*sides[k].buf + *sides[k].len, sbuf, (size_t)got);
                    *sides[k].len += (size_t)got;

                    avail = s3_cli_cm_h_poll(sides[k].h);

                    if (avail < 0) {
                        *sides[k].eof = 1;
                        break;
                    }
                }
            }
        }

        if (!got_exit || !io_eof || !err_eof) {
            s3_cli_msleep(5);
        }
    }

    /* the session verdict: the io to fd 1, the err to fd 2 */

    if (out_len > 0) {
        ssize_t put = s3_cli_fd_write(1, out_buf, out_len);

        (void)put; /* the verdict is out, the drain is best effort */
    }

    if (err_len > 0) {
        ssize_t put = s3_cli_fd_write(2, err_buf, err_len);

        (void)put;
    }

    rc_exit = (code == 0) ? 0 : (int)(code & 0xff);

    printf("S3CM-SLAVE-DONE exit=%llu\n", (unsigned long long)code);
    fflush(stdout);

done:

    if (s3_cli_cm_h_valid(control)) {
        s3_cli_cm_h_close(control);
    }

    if (s3_cli_cm_h_valid(hio)) {
        s3_cli_cm_h_close(hio);
    }

    if (s3_cli_cm_h_valid(herr)) {
        s3_cli_cm_h_close(herr);
    }

    free(out_buf);
    free(err_buf);
    s3_destroy_pool(pool);

    return rc_exit;
}

/* the control ops (-O check|stop|exit): the sequential client, the
 * check prints the status JSON, the stop/exit drain the reply */

static int
s3_cli_cm_control_op(void)
{
    s3_pool_t       *pool;
    s3_ssh3_cm_cli_t cli;
    s3_cli_cm_h_t    h;
    s3_str_t         op, reply;
    unsigned         is_error;
    s3_msec_t        deadline;
    int              rc = 1;

    pool = s3_create_pool(S3_DEFAULT_POOL_SIZE, &s3_cli_log);

    if (pool == NULL) {
        return 1;
    }

    /* the sequential run starts cold: the monotonic clock never
     * ticked here, the deadlines ride the first update */

    s3_time_update();

    deadline = s3_current_msec + 10000;

    h = s3_cli_cm_dial(s3_cli_cm_path);

    if (!s3_cli_cm_h_valid(h)) {
        fprintf(stderr, "ssh3: no control master is listening on %s\n", s3_cli_cm_path);
        s3_destroy_pool(pool);
        return 1;
    }

    if (s3_ssh3_cm_cli_init(&cli, pool) != S3_OK) {
        s3_destroy_pool(pool);
        return 1;
    }

    if (s3_cli_cm_call(h, &cli, S3_SSH3_CM_MSG_HELLO, NULL, &reply, &is_error, deadline, "hello") !=
            S3_OK ||
        is_error) {
        s3_destroy_pool(pool);
        return 1;
    }

    op.data = (u_char *)s3_cli_cm_op;
    op.len = strlen(s3_cli_cm_op);

    {
        /* the wire payload: the u32 length plus the op name */

        u_char   *enc;
        uintptr_t n = s3_ssh3_cm_encode_control_op(NULL, &op);
        s3_str_t  pl;

        enc = s3_pnalloc(pool, n);

        if (enc == NULL) {
            s3_destroy_pool(pool);
            return 1;
        }

        (void)s3_ssh3_cm_encode_control_op(enc, &op);

        pl.data = enc;
        pl.len = n;

        if (s3_cli_cm_call(h, &cli, S3_SSH3_CM_MSG_CONTROL_OP, &pl, &reply, &is_error, deadline,
                           s3_cli_cm_op) != S3_OK) {
            s3_destroy_pool(pool);
            return 1;
        }
    }

    if (is_error) {
        fprintf(stderr, "ssh3: %s refused: %.*s\n", s3_cli_cm_op, (int)reply.len,
                (const char *)reply.data);

    } else {
        printf("%.*s\n", (int)reply.len, (const char *)reply.data);
        rc = 0;
    }

    s3_cli_cm_h_close(h);
    s3_destroy_pool(pool);

    return rc;
}

/*
 * the pump tick of the session and of the sftp run: one timer event
 * on the ctx pool (it outlives the connection pool: the quic layer
 * closes the connection inside the event loop, a tick node freed with
 * the connection pool is walked by the next expire pass — the
 * 2026-10-15 0xC0000005 in s3_event_expire_timers), the handler
 * re-arms itself
 */

static void
s3_cli_tick_arm(void)
{
    if (s3_cli_tick != NULL) {
        return;
    }

    s3_cli_tick = s3_pnalloc(s3_cli_ctx.pool, sizeof(s3_event_t));

    if (s3_cli_tick == NULL) {
        fprintf(stderr, "ssh3: out of memory\n");
        return;
    }

    memset(s3_cli_tick, 0, sizeof(s3_event_t));

    s3_cli_tick->handler = s3_cli_tick_handler;
    s3_cli_tick->log = &s3_cli_log;

    s3_event_add_timer(s3_cli_tick, S3_CLI_TICK_MS);
}

/*
 * the console bring-up of the session: win drops the line, echo and
 * processed input, passes the VT escapes and parks the reader thread
 * on the console handle (the console read is not selectable); unix
 * rides the raw termios of the session_cli helper and hands the
 * selectable stdin to the event loop
 */

static s3_int_t
s3_cli_console_init(void)
{
#if (S3_WIN32)
    DWORD mode;

    s3_cli_in_h = GetStdHandle(STD_INPUT_HANDLE);
    s3_cli_out_h = GetStdHandle(STD_OUTPUT_HANDLE);

    if (s3_cli_console) {

        if (GetConsoleMode(s3_cli_in_h, &s3_cli_in_saved)) {

            mode = s3_cli_in_saved;
            mode &= ~(DWORD)(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT);
            mode |= ENABLE_WINDOW_INPUT | ENABLE_VIRTUAL_TERMINAL_INPUT;

            if (!SetConsoleMode(s3_cli_in_h, mode)) {
                return S3_ERROR;
            }

            if (s3_cli_out_h != INVALID_HANDLE_VALUE && GetConsoleMode(s3_cli_out_h, &mode)) {
                (void)SetConsoleMode(s3_cli_out_h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
            }

            (void)SetConsoleCP(65001);
            (void)SetConsoleOutputCP(65001);

            s3_cli_raw = 1;
        }
    }

    InitializeCriticalSection(&s3_cli_ring_cs);

    /* the -n run: the stdin stays unpumped (the EOF semantics of
     * /dev/null), no reader thread rides */

    if (s3_cli_no_stdin) {
        DeleteCriticalSection(&s3_cli_ring_cs);
        return S3_OK;
    }

    s3_cli_thread = _beginthreadex(NULL, 0, s3_cli_reader, NULL, 0, NULL);

    if (s3_cli_thread == 0) {
        DeleteCriticalSection(&s3_cli_ring_cs);
        return S3_ERROR;
    }

    return S3_OK;
#else
    s3_connection_t *c;

    if (s3_cli_console) {

        /* the raw mode of the session lifetime, the teardown restores */

        if (s3_ssh3_session_cli_tty_raw(0, &s3_cli_saved_termios) != S3_OK) {
            return S3_ERROR;
        }

        s3_cli_raw = 1;
    }

    /* the stdin rides the event loop: the handler chunks the bytes
     * into the channel frames directly (the ring of the win build
     * exists because the console read is not selectable there) */

    if (s3_cli_no_stdin) {
        return S3_OK;
    }

    if (s3_nonblocking((s3_fd_t)0) != S3_OK) {
        return S3_ERROR;
    }

    c = s3_get_connection(&s3_cli_ctx, (s3_fd_t)0);

    if (c == NULL) {
        return S3_ERROR;
    }

    c->read->handler = s3_cli_stdin_read;
    c->read->data = c; /* the select module contract: data is the conn */
    c->read->active = 1;

    if (s3_event_actions.add_event(c->read, S3_READ_EVENT, 0) != S3_OK) {
        return S3_ERROR;
    }

    return S3_OK;
#endif
}

/* the saved terminal state back (the thread of win joins first) */

static void
s3_cli_console_done(void)
{
#if (S3_WIN32)
    if (s3_cli_thread != 0) {

        s3_cli_stop = 1;

        /* the reader parks in ReadFile(); the console read wakes on
         * the input or the handle close, the pipe read wakes on the
         * writer close -- the main path reached the session end, the
         * cancel is best effort */

        CancelIoEx(s3_cli_in_h, NULL);

        WaitForSingleObject((HANDLE)s3_cli_thread, 1000);
        CloseHandle((HANDLE)s3_cli_thread);
        s3_cli_thread = 0;

        DeleteCriticalSection(&s3_cli_ring_cs);
    }

    if (s3_cli_raw) {
        (void)SetConsoleMode(s3_cli_in_h, s3_cli_in_saved);
        s3_cli_raw = 0;
    }
#else
    if (s3_cli_raw) {
        (void)s3_ssh3_session_cli_tty_restore(0, &s3_cli_saved_termios);
        s3_cli_raw = 0;
    }
#endif
}

#if (S3_WIN32)

/*
 * the reader thread: the stdin bytes land in the ring, the pipe EOF
 * arms the fin flag; the console read returns per keystroke in the
 * raw mode, the pipe read blocks until the data
 */

static unsigned __stdcall s3_cli_reader(void *arg)
{
    u_char buf[4096];

    (void)arg;

    for (;;) {

        DWORD n = 0;

        if (s3_cli_stop) {
            return 0;
        }

        if (!ReadFile(s3_cli_in_h, buf, sizeof(buf), &n, NULL)) {

            /* the cancelled or broken stdin: a pipe reports the
             * broken writer as an error, the semantics is the eof */

            EnterCriticalSection(&s3_cli_ring_cs);
            s3_cli_stdin_eof = 1;
            LeaveCriticalSection(&s3_cli_ring_cs);

            return 0;
        }

        if (n == 0) {

            EnterCriticalSection(&s3_cli_ring_cs);
            s3_cli_stdin_eof = 1;
            LeaveCriticalSection(&s3_cli_ring_cs);

            return 0;
        }

        EnterCriticalSection(&s3_cli_ring_cs);

        {
            DWORD i;

            for (i = 0; i < n; i++) {

                u_char b = buf[i];
                u_char filtered[8];
                size_t flen;

                /* the escape processor of the interactive console
                 * shell filters the bytes before the ring */

                if (s3_cli_escape_live()) {

                    flen = s3_cli_escape_feed(&b, 1, filtered);

                } else {
                    flen = 1;
                    filtered[0] = b;
                }

                for (size_t k = 0; k < flen; k++) {

                    size_t next = (s3_cli_ring_head + 1) & S3_CLI_RING_MASK;

                    if (next == s3_cli_ring_tail) {
                        /* the ring full drops the byte: the echo runs
                         * ahead of the window, the user keeps typing */
                        continue;
                    }

                    s3_cli_ring[s3_cli_ring_head] = filtered[k];
                    s3_cli_ring_head = next;
                }
            }
        }

        LeaveCriticalSection(&s3_cli_ring_cs);
    }
}

#else

/*
 * the stdin of the event loop: the bytes chunk into the 94 frames at
 * once (the ring of the win build exists because the console read is
 * not selectable there), the eof arms the fin flag of the tick; the
 * handler stops reading when the window is tight, the outbox of one
 * frame holds the parked tail
 */

static void
s3_cli_stdin_read(s3_event_t *ev)
{
    u_char chunk[4096];

    (void)ev;

    if (s3_cli_chan == NULL || s3_cli_stop || s3_cli_verdict) {
        return;
    }

    for (;;) {

        ssize_t n;
        u_char  frame[sizeof(chunk) + 8];
        u_char  filtered[sizeof(chunk)];
        u_char *src = chunk;
        size_t  len, overhead;
        u_char *p;

        if (s3_cli_fin_sent) {

            /* the write side is gone (the exec fin), the late stdin
             * has no transport to ride -- the win shape would fail
             * the channel send, the eof gate stays honest */

            return;
        }

        if (s3_cli_outbox_len > 0) {
            return; /* the window is tight, the tick drains first */
        }

        n = read(0, chunk, sizeof(chunk));

        if (n > 0) {

            len = (size_t)n;

            /* the escape processor of the interactive console shell
             * filters the bytes before they ride the channel */

            if (s3_cli_escape_live()) {
                len = s3_cli_escape_feed(chunk, len, filtered);
                src = filtered;
            }

            if (len == 0) {
                continue;
            }

            p = frame;
            p = (u_char *)s3_ssh3_encode_varint(p, S3_SSH3_MSG_CHANNEL_DATA);
            p = (u_char *)s3_ssh3_encode_varint(p, (uint64_t)len);
            memcpy(p, src, len);

            overhead = (size_t)(p - frame) + len;

            s3_cli_chan_park(frame, overhead);

            continue;
        }

        if (n == 0) {

            s3_cli_stdin_eof = 1;

            return;
        }

        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return; /* the buffer ran dry, the next event re-fires */
        }

        if (errno == EINTR) {
            continue;
        }

        /* the broken stdin reads like the eof */

        s3_cli_stdin_eof = 1;

        return;
    }
}

#endif

/*
 * the console window size for the pty-req and the window-change: the
 * visible window of the screen buffer on win (the size lives on the
 * output side), the tty helper of the session_cli on unix
 */

static s3_int_t
s3_cli_console_winsize(uint64_t *width, uint64_t *height)
{
#if (S3_WIN32)
    CONSOLE_SCREEN_BUFFER_INFO info;

    if (!s3_cli_console) {
        return S3_DECLINED;
    }

    if (s3_cli_out_h == INVALID_HANDLE_VALUE || !GetConsoleScreenBufferInfo(s3_cli_out_h, &info)) {
        return S3_ERROR;
    }

    *width = (uint64_t)(info.srWindow.Right - info.srWindow.Left + 1);
    *height = (uint64_t)(info.srWindow.Bottom - info.srWindow.Top + 1);

    return S3_OK;
#else

    /* the tty helper of the session_cli: the columns and the rows of
     * the window, S3_DECLINED on the non-tty like the win guard */

    if (!s3_cli_console) {
        return S3_DECLINED;
    }

    return s3_ssh3_session_cli_tty_winsize(0, width, height);
#endif
}

/*
 * the console tick: the ring drains into the 94 frames, the pipe eof
 * closes the write side, the resize rides the window-change request;
 * the tick re-arms itself for the session lifetime
 */

static void
s3_cli_tick_handler(s3_event_t *ev)
{
#if (S3_WIN32)
    u_char frame[S3_CLI_RING_SIZE + 8];
#endif

    if (s3_quic_get_connection(s3_cli_conn) == NULL) {

        /*
         * the quic layer closed the connection (the idle timeout, the
         * peer close, the error): the channels and the pools are gone
         * under this tick — no tick work, no re-arm; the main loop
         * picks the verdict up on its liveness check
         */

        return;
    }

    if (s3_cli_fwd_count || s3_cli_rspec_count) {

        /* the forward run: the parked drains ride the tick (the
         * local socket writes park rarely, the echo paths stay
         * hot); the console machinery stays off.  The -R run rides
         * the same shape (the -N hold): the bridges and the control
         * channels pump on the tick */

        if (s3_cli_fwd_count) {
            s3_cli_fwd_tick();
        }

        if (s3_cli_rspec_count) {
            s3_cli_rev_pump();
        }

        /* the signal stop ends the hold run (the verdict of the
         * master shape): the tick stops re-arming, the main loop
         * picks the verdict up */

        if (s3_cli_stop && !s3_cli_verdict) {
            s3_cli_verdict = 1;
            s3_cli_exit_code = 0;
        }

        if (!s3_cli_stop && !s3_cli_verdict) {
            s3_event_add_timer(ev, S3_CLI_TICK_MS);
        }

        return;
    }

    if (s3_cli_cm_master) {

        /* the control master run: the accept poll and the conn
         * pumps ride the tick, the stop and the idle close set the
         * verdict */

        s3_cli_cm_tick();

        if (s3_cli_cm_stop && !s3_cli_verdict) {

            /* the stop op reply is on the wire: the master lives a
               few ticks more, the serial stop client reads it
               before the process exit closes the pipe */

            if (s3_cli_cm_stop_lag == 0) {
                s3_cli_cm_stop_lag = 4;

            } else if (--s3_cli_cm_stop_lag == 0) {
                s3_cli_verdict = 1;
                s3_cli_exit_code = 0;
            }
        }

        if (!s3_cli_stop && !s3_cli_verdict) {
            s3_event_add_timer(ev, S3_CLI_CM_TICK_MS);
        }

        return;
    }

    if (s3_cli_sftp_mode) {

        /* the sftp run: the pump rides the tick (the window reopens
         * ride the write event earlier); the console machinery
         * stays off, no ring is initialized */

        if (s3_cli_chan == NULL || s3_cli_verdict) {
            return;
        }

        if (s3_cli_sftp_started) {
            s3_cli_sftp_pump();
        }

        if (!s3_cli_stop && !s3_cli_verdict) {
            s3_event_add_timer(ev, s3_cli_sftp_parked ? 2 : S3_CLI_TICK_MS);
        }

        return;
    }

    if (s3_cli_chan == NULL) {
        return;
    }

    /* the agent bridge pump rides the session tick */

    if (s3_cli_agent_bridged) {
        s3_cli_agent_pump();
    }

    /* the parked tail first: the window may have opened */

    if (s3_cli_outbox_len > 0) {
        s3_cli_outbox_flush();
    }

#if (S3_WIN32)

    /* the stdin ring into the data frames, one frame per tick keeps
     * the outbox bounded by the ring size (the unix build parks the
     * frames straight in the stdin read event); the -n run pumps no
     * stdin at all */

    if (!s3_cli_no_stdin) {

        for (;;) {

            u_char  chunk[S3_CLI_RING_SIZE];
            size_t  len = 0, overhead;
            u_char *p;

            EnterCriticalSection(&s3_cli_ring_cs);

            while (s3_cli_ring_tail != s3_cli_ring_head && len < sizeof(chunk)) {
                chunk[len++] = s3_cli_ring[s3_cli_ring_tail];
                s3_cli_ring_tail = (s3_cli_ring_tail + 1) & S3_CLI_RING_MASK;
            }

            LeaveCriticalSection(&s3_cli_ring_cs);

            if (len == 0) {
                break;
            }

            p = frame;
            p = (u_char *)s3_ssh3_encode_varint(p, S3_SSH3_MSG_CHANNEL_DATA);
            p = (u_char *)s3_ssh3_encode_varint(p, len);
            memcpy(p, chunk, len);

            overhead = (size_t)(p - frame) + len;

            s3_cli_chan_park(frame, overhead);

            if (s3_cli_outbox_len > 0) {
                /* the window is tight, the rest waits for the next tick */
                break;
            }
        }
    }

#endif

    /* the pipe eof: the fin lets the remote shell see the eof (the
     * console stdin never reports one, the gate rides the real stdin
     * kind, not the requested session shape) */

    if (!s3_cli_fin_sent && !s3_cli_console && s3_cli_outbox_len == 0 && s3_cli_stdin_eof) {

        if (s3_quic_shutdown_stream(s3_cli_chan, S3_WRITE_SHUTDOWN) == S3_OK) {
            s3_cli_fin_sent = 1;
        }
    }

    /* the resize: the geometry change rides the window-change request
     * (win polls the console every tick, unix rides the SIGWINCH) */

    if (s3_cli_tty) {

        unsigned changed = 0;
        uint64_t w = 0, h = 0;

#if (S3_WIN32)
        changed = 1; /* the console geometry polls every tick */
#else
        if (s3_cli_winch) {
            s3_cli_winch = 0;
            changed = 1;
        }
#endif

        if (changed && s3_cli_console_winsize(&w, &h) == S3_OK && w > 0 && h > 0 &&
            (w != s3_cli_win_w || h != s3_cli_win_h)) {

            s3_ssh3_request_t wc;
            u_char            req[128];
            u_char           *p;

            memset(&wc, 0, sizeof(wc));

            wc.kind = S3_SSH3_REQ_WINDOW_CHANGE;
            wc.u.window_change.width = w;
            wc.u.window_change.height = h;
            wc.u.window_change.pixel_width = 0;
            wc.u.window_change.pixel_height = 0;

            p = s3_cli_session_request(req, S3_SSH3_REQ_WINDOW_CHANGE, 0, &wc);

            s3_cli_chan_park(req, (size_t)(p - req));

            s3_cli_win_w = w;
            s3_cli_win_h = h;
        }
    }

    if (!s3_cli_stop) {
        s3_event_add_timer(ev, S3_CLI_TICK_MS);
    }
}

int
main(int argc, char **argv)
{
    int                   opt;
    char                 *operand = NULL;
    const char           *at, *colon, *slash;
    size_t                i;
    s3_str_t              alpn;
    u_char                alpn_wire[8];
    s3_fd_t               fd;
    s3_connection_t      *cli;
    s3_quic_connection_t *qc;
    struct addrinfo       hints, *res = NULL;

    /* the net bootstrap (the winsock startup of win, the signal flags
     * of unix) */

    if (s3_cli_net_init() != S3_OK) {
        fprintf(stderr, "ssh3: the net bootstrap failed\n");
        return S3_CLI_EXIT_ERROR;
    }

#if (S3_WIN32)
    /* the stdout/stderr in the binary mode: the channel bytes are
     * opaque (the remote pty owns the line discipline) */

    (void)_setmode(1, _O_BINARY);
    (void)_setmode(2, _O_BINARY);
#endif

    s3_cli_log.fd = S3_INVALID_FILE;
    s3_cli_log.log_level = S3_LOG_WARN;

    /*
     * the -privkey alias of the Go fork client (cmd/ssh3.go): the
     * muscle memory of the reference users maps onto -i
     */

    for (opt = 1; opt < argc; opt++) {

        if (strcmp(argv[opt], "-privkey") == 0) {
            argv[opt] = (char *)"-i";
        }
    }

    /*
     * the long forms ride the pre-scan before the short getopt (the
     * server shape): --log-level carries the s3 log level the -l
     * login key vacated, --help spells the usage, --sftp carries the
     * transfer spec the -J key gave back
     */

    {

        int n, m, keep, drop;
        char *value;

        for (n = 1; n < argc;) {

            keep = 1;
            drop = 0;
            value = NULL;

            if (strcmp(argv[n], "--log-level") == 0 && n + 1 < argc) {

                if (strcmp(argv[n + 1], "all") == 0) {
                    s3_cli_log.log_level = S3_LOG_DEBUG_ALL;
                    s3_cli_level_explicit = 1;
                    value = argv[n + 1];

                } else {

                    long lvl = atol(argv[n + 1]);
                    const char *t = argv[n + 1];

                    if (*t == '\0' || (lvl == 0 && strcmp(t, "0") != 0) || lvl < 0 || lvl > 9) {
                        fprintf(stderr, "ssh3: --log-level wants 0..9 or all\n");
                        s3_cli_net_cleanup();
                        return S3_CLI_EXIT_ERROR;
                    }

                    s3_cli_log.log_level = (s3_uint_t)lvl;
                    s3_cli_level_explicit = 1;
                    value = argv[n + 1];
                }

            } else if (strcmp(argv[n], "--help") == 0) {
                s3_cli_usage(argv[0]);
                s3_cli_net_cleanup();
                return 0;

            } else if (strcmp(argv[n], "--sftp") == 0 && n + 1 < argc) {

                if (s3_cli_sftp_spec_parse(argv[n + 1]) != S3_OK) {
                    s3_cli_net_cleanup();
                    return S3_CLI_EXIT_ERROR;
                }

                value = argv[n + 1];
            }

            if (value != NULL) {
                drop = 2;
            }

            if (drop > 0) {

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

    while ((opt = getopt(argc, argv, "46ACDe:F:i:J:l:L:MnNp:qS:s:tTo:VvxYU:R:O:h")) != -1) {

        switch (opt) {

        case 'i':

            if (!s3_cli_have_keyfile) {
                s3_cli_have_keyfile = 1;
                snprintf(s3_cli_keyfile, sizeof(s3_cli_keyfile), "%s", optarg);
                s3_cli_auth = S3_CLI_AUTH_PUBKEY;
            }

            break;

        case 'U': {

            /* the value shape decides: the control endpoint head
             * names the control master (the -S shape now, the -U
             * spelling deprecated), anything else is the Basic
             * user:pass (the HTTP spec carries no ssh2 twin) */

#if (S3_WIN32)
            if (optarg[0] == '\\' && optarg[1] == '\\') {
#else
            if (optarg[0] == '/') {
#endif

                s3_cli_note("ssh3: -U with a control path is deprecated, use -S");

                if (strlen(optarg) >= sizeof(s3_cli_cm_path)) {
                    fprintf(stderr, "ssh3: -S control path is too long\n");
                    return S3_CLI_EXIT_ERROR;
                }

                snprintf(s3_cli_cm_path, sizeof(s3_cli_cm_path), "%s", optarg);
                s3_cli_cm_pipe_name_called = 1;

                break;
            }

            {

                const char *sep = strchr(optarg, ':');
                size_t      ulen = strlen(optarg);

                if (sep == NULL || ulen > 300) {
                    fprintf(stderr, "ssh3: -U wants user:pass\n");
                    return S3_CLI_EXIT_ERROR;
                }

                memcpy(s3_cli_basic, "Basic ", sizeof("Basic ") - 1);
                s3_cli_b64std((const u_char *)optarg, ulen, s3_cli_basic + sizeof("Basic ") - 1);

                /* the username before the colon feeds the ?user= target */

                if ((size_t)(sep - optarg) >= sizeof(s3_cli_user)) {
                    fprintf(stderr, "ssh3: -U user is too long\n");
                    return S3_CLI_EXIT_ERROR;
                }

                memcpy(s3_cli_user, optarg, (size_t)(sep - optarg));
                s3_cli_user[sep - optarg] = '\0';

                s3_cli_auth = S3_CLI_AUTH_BASIC;
                s3_cli_auth_value = s3_cli_basic;
            }

            break;
        }

        case 'S':

            /* the control master path (the ssh2 ControlPath shape):
             * the master, the slave and the -O ops all ride it */

            if (strlen(optarg) >= sizeof(s3_cli_cm_path)) {
                fprintf(stderr, "ssh3: -S control path is too long\n");
                return S3_CLI_EXIT_ERROR;
            }

            snprintf(s3_cli_cm_path, sizeof(s3_cli_cm_path), "%s", optarg);
            s3_cli_cm_pipe_name_called = 1;

            break;

        case 'M':
            s3_cli_cm_master = 1;
            s3_cli_have_master = 1;
            break;

        case 'e':

            /* the escape character of the interactive session (the
             * ssh2 shape); the slave command moved to the positional
             * words of the -S run */

            if (s3_cli_escape_parse(optarg) != S3_OK) {
                return S3_CLI_EXIT_ERROR;
            }

            break;

        case 'O':
            s3_cli_cm_op = optarg;
            break;

        case 'A':
            s3_cli_agent_mode = 1;
            s3_cli_have_agent = 1;
            break;

        case 'X':
            s3_cli_note("ssh3: -X is deprecated, use -A");
            s3_cli_agent_mode = 1;
            s3_cli_have_agent = 1;
            break;

        case 'x':
        case 'Y':
            s3_cli_note("ssh3: X11 forwarding is not supported by ssh3, ignoring");
            break;

        case 'J': {

            /* the fork decision: the put|get head stays the legacy
             * transfer (deprecated), everything else is the ssh2
             * proxy jump spec */

            if (strncmp(optarg, "put:", 4) == 0 || strncmp(optarg, "get:", 4) == 0) {
                s3_cli_note("ssh3: -J transfer is deprecated, use --sftp");

                if (s3_cli_sftp_spec_parse(optarg) != S3_OK) {
                    return S3_CLI_EXIT_ERROR;
                }

                break;
            }

            if (s3_cli_jump_parse(optarg) != S3_OK) {
                return S3_CLI_EXIT_ERROR;
            }

            break;
        }

        case 's':

            /* the subsystem name: only the sftp driver is served,
             * the transfer spec rides the first positional word */

            if (strcmp(optarg, "sftp") != 0) {
                fprintf(stderr, "ssh3: only the sftp subsystem is supported\n");
                return S3_CLI_EXIT_ERROR;
            }

            s3_cli_sftp_spec_mode = 1;
            break;

        case 'L':

            if (s3_cli_fwd_parse(optarg) != S3_OK) {
                return S3_CLI_EXIT_ERROR;
            }

            break;

        case 'R':

            /* the reverse forward: the spec parses now, the control
             * channel opens after the 200 */

            if (s3_cli_rev_parse_spec(optarg) != S3_OK) {
                return S3_CLI_EXIT_ERROR;
            }

            break;

        case 'r':
            s3_cli_sftp_recursive = 1;
            break;

        case 'o':

            /* the client option: the unknown key or the bad value
             * exits 255 with the supported list */

            if (s3_cli_opt_parse(optarg) != S3_OK) {
                return S3_CLI_EXIT_ERROR;
            }

            break;

        case 'v':
            s3_cli_vcount++;
            s3_cli_level_explicit = 1;
            break;

        case 'l':

            /* the login name (the ssh2 shape); the numeric level of
             * the legacy -l refuses with the long form hint */

            {
                const char *t = optarg;
                unsigned    digits = (*t != '\0');

                for (; *t != '\0'; t++) {

                    if (*t < '0' || *t > '9') {
                        digits = 0;
                        break;
                    }
                }

                if (digits) {
                    fprintf(stderr, "ssh3: -l takes a login name now, use --log-level for "
                                    "the s3 log level\n");
                    return S3_CLI_EXIT_ERROR;
                }
            }

            if (strlen(optarg) >= sizeof(s3_cli_login)) {
                fprintf(stderr, "ssh3: the login name is too long\n");
                return S3_CLI_EXIT_ERROR;
            }

            snprintf(s3_cli_login, sizeof(s3_cli_login), "%s", optarg);
            s3_cli_have_user = 1;
            break;

        case 'p':

            /* the port of the target (the ssh2 shape), the operand
             * port yields */

            {
                unsigned v = (unsigned)atoi(optarg);

                if (v == 0 || v > 65535) {
                    fprintf(stderr, "ssh3: -p wants a port 1..65535\n");
                    return S3_CLI_EXIT_ERROR;
                }

                s3_cli_port = v;
                s3_cli_have_port = 1;
            }

            break;

        case '4':
            s3_cli_family = AF_INET;
            break;

        case '6':
            s3_cli_family = AF_INET6;
            break;

        case 'N':
            s3_cli_no_session = 1;
            break;

        case 'n':
            s3_cli_no_stdin = 1;
            break;

        case 't':
            s3_cli_pty_mode = (++s3_cli_pty_tcount >= 2) ? S3_CLI_PTY_FORCE_NOTTY : S3_CLI_PTY_FORCE;
            break;

        case 'T':
            s3_cli_pty_mode = S3_CLI_PTY_NEVER;
            s3_cli_pty_tcount = 0;
            break;

        case 'q':
            s3_cli_quiet = 1;
            break;

        case 'F':

            /* the config file: "none" and /dev/null disable the
             * whole config incl. the default read */

            if (strcmp(optarg, "none") == 0 || strcmp(optarg, "/dev/null") == 0) {
                s3_cli_cfg_off = 1;
                s3_cli_cfg_path[0] = '\0';

                break;
            }

            if (strlen(optarg) >= sizeof(s3_cli_cfg_path)) {
                fprintf(stderr, "ssh3: -F path is too long\n");
                return S3_CLI_EXIT_ERROR;
            }

            snprintf(s3_cli_cfg_path, sizeof(s3_cli_cfg_path), "%s", optarg);
            s3_cli_cfg_explicit = 1;
            break;

        case 'C':
            s3_cli_note("ssh3: compression is not supported by ssh3, ignoring");
            break;

        case 'V':
            printf("ssh3 version %s\n", S3_SSH3_VERSION_STRING);
            s3_cli_net_cleanup();
            return 0;

        case 'h':
            s3_cli_usage(argv[0]);
            s3_cli_net_cleanup();
            return 0;

        default:
            s3_cli_usage(argv[0]);
            s3_cli_net_cleanup();
            return S3_CLI_EXIT_ERROR;
        }
    }

    /* the slave and the control ops ride no server connection: the
     * control pipe serves them, the run returns before the dial */

    if (s3_cli_cm_op != NULL) {

        if (!s3_cli_cm_pipe_name_called) {
            fprintf(stderr, "ssh3: -O wants -S "
#if (S3_WIN32)
                            "\\\\pipe-name"
#else
                            "socket-path"
#endif
                            "\n");
            s3_cli_net_cleanup();
            return S3_CLI_EXIT_ERROR;
        }

        s3_cli_notes_flush();
        return s3_cli_cm_control_op();
    }

    /*
     * the slave of the control master (the ssh mux shape): a set
     * control path with no -M and no -O means the positional words
     * are the exec command of one session through the master
     */

    if (s3_cli_cm_path[0] != '\0' && !s3_cli_cm_master) {

        if (optind >= argc) {
            fprintf(stderr, "ssh3: the slave wants a command\n");
            s3_cli_net_cleanup();
            return S3_CLI_EXIT_ERROR;
        }

        s3_cli_cm_exec = s3_cli_join_words(argv, (size_t)optind, (size_t)argc);

        if (s3_cli_cm_exec == NULL) {
            fprintf(stderr, "ssh3: out of memory\n");
            s3_cli_net_cleanup();
            return S3_CLI_EXIT_ERROR;
        }

        s3_cli_notes_flush();

        return s3_cli_cm_slave_run();
    }

    if (optind >= argc) {
        s3_cli_usage(argv[0]);
        s3_cli_net_cleanup();
        return S3_CLI_EXIT_ERROR;
    }

    operand = argv[optind++];

    /* the operand: [user@]host[:port][/path], the defaults are the
     * 443 port and the /ssh3-term path (the Go fork parity); the
     * -p/-o Port= wins over the operand port, the operand user wins
     * over the -l login (the ssh2 conflict shape) */

    at = strchr(operand, '@');

    if (at != NULL) {

        if ((size_t)(at - operand) >= sizeof(s3_cli_user)) {
            fprintf(stderr, "ssh3: the user name is too long\n");
            return S3_CLI_EXIT_ERROR;
        }

        if (s3_cli_have_user) {
            s3_cli_note("ssh3: the operand user overrides the -l login");
        }

        memcpy(s3_cli_user, operand, (size_t)(at - operand));
        s3_cli_user[at - operand] = '\0';
        s3_cli_have_user = 1;

        operand = (char *)at + 1;
    }

    slash = strchr(operand, '/');

    if (slash != NULL) {

        unsigned oport;

        if (strlen(slash) >= sizeof(s3_cli_path)) {
            fprintf(stderr, "ssh3: the path is too long\n");
            return S3_CLI_EXIT_ERROR;
        }

        snprintf(s3_cli_path, sizeof(s3_cli_path), "%s", slash);
        colon = strchr(operand, ':');

        if (colon != NULL && colon < slash) {

            oport = (unsigned)atoi(colon + 1);

            if (oport == 0 || oport > 65535 ||
                (size_t)(colon - operand) >= sizeof(s3_cli_host)) {
                fprintf(stderr, "ssh3: bad port in %s\n", argv[optind - 1]);
                return S3_CLI_EXIT_ERROR;
            }

            s3_cli_port_operand = 1;

            if (!s3_cli_have_port) {
                s3_cli_port = oport;
            }

            memcpy(s3_cli_host, operand, (size_t)(colon - operand));
            s3_cli_host[colon - operand] = '\0';

        } else {

            if ((size_t)(slash - operand) >= sizeof(s3_cli_host)) {
                fprintf(stderr, "ssh3: the host is too long\n");
                return S3_CLI_EXIT_ERROR;
            }

            memcpy(s3_cli_host, operand, (size_t)(slash - operand));
            s3_cli_host[slash - operand] = '\0';
        }

    } else {

        colon = strchr(operand, ':');

        if (colon != NULL) {

            unsigned oport = (unsigned)atoi(colon + 1);

            if (oport == 0 || oport > 65535 ||
                (size_t)(colon - operand) >= sizeof(s3_cli_host)) {
                fprintf(stderr, "ssh3: bad port in %s\n", argv[optind - 1]);
                return S3_CLI_EXIT_ERROR;
            }

            s3_cli_port_operand = 1;

            if (!s3_cli_have_port) {
                s3_cli_port = oport;
            }

            memcpy(s3_cli_host, operand, (size_t)(colon - operand));
            s3_cli_host[colon - operand] = '\0';

        } else {

            if (strlen(operand) >= sizeof(s3_cli_host)) {
                fprintf(stderr, "ssh3: the host is too long\n");
                return S3_CLI_EXIT_ERROR;
            }

            snprintf(s3_cli_host, sizeof(s3_cli_host), "%s", operand);
        }

        snprintf(s3_cli_path, sizeof(s3_cli_path), "/ssh3-term");
    }

    if (s3_cli_host[0] == '\0') {
        s3_cli_usage(argv[0]);
        return S3_CLI_EXIT_ERROR;
    }

    /* the transfer spec of -s sftp rides the first positional word
     * after the operand, the rest refuses */

    if (s3_cli_sftp_spec_mode) {

        if (optind >= argc) {
            fprintf(stderr, "ssh3: -s sftp wants a put|get:local:remote specifier\n");
            return S3_CLI_EXIT_ERROR;
        }

        if (s3_cli_sftp_spec_parse(argv[optind++]) != S3_OK) {
            return S3_CLI_EXIT_ERROR;
        }
    }

    /* the console detection rides the -t check, the config question
     * and the session */

    s3_cli_console = _isatty(0) ? 1u : 0u;

    /* the -t force without a local tty is the ssh2 refusal */

    if (s3_cli_pty_mode == S3_CLI_PTY_FORCE && !s3_cli_console) {
        fprintf(stderr, "ssh3: no tty present, the -t force cannot ride\n");
        return S3_CLI_EXIT_ERROR;
    }

    /* the config file: the -F path wins, the default one reads when
     * it exists; the values land only on the options the command
     * line left unset, the forwards append */

    if (!s3_cli_cfg_off) {

        if (s3_cli_cfg_path[0] == '\0') {

#if (S3_WIN32)
            {
                const char *home = getenv("USERPROFILE");

                if (home != NULL) {
                    snprintf(s3_cli_cfg_path, sizeof(s3_cli_cfg_path), "%s\\.ssh\\config", home);
                }
            }
#else
            {
                const char *home = getenv("HOME");

                if (home != NULL) {
                    snprintf(s3_cli_cfg_path, sizeof(s3_cli_cfg_path), "%s/.ssh/config", home);
                }
            }
#endif
        }

        if (s3_cli_cfg_path[0] != '\0' && s3_cli_cfg_load(s3_cli_host) != S3_OK) {
            return S3_CLI_EXIT_ERROR;
        }
    }

    /* the port settles after the config: the -p and the operand port
     * both beat it, the 443 default stays the last resort */

    if (s3_cli_port == 0) {
        s3_cli_port = 443;
    }

    /* the -l login lands when neither the operand nor the -U Basic
     * head named a user (the -o User= and the config User write the
     * user buffer directly) */

    if (s3_cli_have_user && s3_cli_user[0] == '\0') {
        snprintf(s3_cli_user, sizeof(s3_cli_user), "%s", s3_cli_login);
    }

    /* the level of the run: the explicit -v/--log-level wins over
     * the -q, the quiet alone rides the errors */

    if (!s3_cli_level_explicit && s3_cli_quiet) {
        s3_cli_log.log_level = S3_LOG_ERR;

    } else if (s3_cli_level_explicit && !s3_cli_vcount) {

        /* the explicit --log-level keeps its value, an explicit -v
         * count overrides it below */
    }

    if (s3_cli_vcount >= 3) {
        s3_cli_log.log_level = S3_LOG_DEBUG_ALL;

    } else if (s3_cli_vcount == 2) {
        s3_cli_log.log_level = S3_LOG_DEBUG;

    } else if (s3_cli_vcount == 1) {
        s3_cli_log.log_level = S3_LOG_INFO;
    }

    s3_cli_notes_flush();

    /* the jump rides the v4 inner target of this wave: the direct-udp
     * extension carries the ipv4 form, the -6 dial refuses cleanly */

    if (s3_cli_jump_on && s3_cli_family != AF_INET) {
        fprintf(stderr, "ssh3: the proxy jump rides ipv4 in this wave, drop -6\n");
        return S3_CLI_EXIT_ERROR;
    }

    /* the mode interlocks of the stage B shapes */

    if (s3_cli_cm_master &&
        (s3_cli_sftp_mode || s3_cli_fwd_count || s3_cli_rspec_count || s3_cli_jump_on)) {
        fprintf(stderr, "ssh3: -M rides no -J, -L, -R, --sftp or a command\n");
        return S3_CLI_EXIT_ERROR;
    }

    if (s3_cli_cm_op != NULL &&
        (s3_cli_cm_master || s3_cli_sftp_mode || s3_cli_fwd_count || s3_cli_rspec_count ||
         s3_cli_jump_on)) {
        fprintf(stderr, "ssh3: -O rides no -M, -J, -L or -R\n");
        return S3_CLI_EXIT_ERROR;
    }

    /* the -N holds the forwards only: a command and the sftp driver
     * both refuse (the ssh2 shape) */

    if (s3_cli_no_session) {

        if (optind < argc) {
            fprintf(stderr, "ssh3: Cannot execute command with -N\n");
            return S3_CLI_EXIT_ERROR;
        }

        if (s3_cli_sftp_mode || s3_cli_cm_master) {
            fprintf(stderr, "ssh3: -N rides no --sftp and no -M\n");
            return S3_CLI_EXIT_ERROR;
        }
    }

    /* the sftp transfer and the forwards carry no exec words */

    if ((s3_cli_sftp_mode || s3_cli_fwd_count || s3_cli_cm_master || s3_cli_rspec_count) &&
        optind < argc) {
        fprintf(stderr, "ssh3: the transfers and the forwards take no command\n");
        return S3_CLI_EXIT_ERROR;
    }

    if (s3_cli_sftp_mode && (s3_cli_fwd_count || s3_cli_rspec_count)) {
        fprintf(stderr, "ssh3: the sftp transfer and the forwards do not ride one session\n");
        return S3_CLI_EXIT_ERROR;
    }

    /* the trailing words join into the exec command (the ssh shape) */

    if (optind < argc) {

        s3_cli_cmd = s3_cli_join_words(argv, (size_t)optind, (size_t)argc);

        if (s3_cli_cmd == NULL) {
            fprintf(stderr, "ssh3: out of memory\n");
            return S3_CLI_EXIT_ERROR;
        }
    }

    /* the auth consistency: the pubkey wants the bare username, the
     * Basic one carried its own; the JWT username validates like the
     * harness (the claim set embeds it verbatim) */

    if (s3_cli_auth == S3_CLI_AUTH_PUBKEY) {

        if (strchr(s3_cli_user, ':') != NULL) {
            fprintf(stderr, "ssh3: -i wants the bare user@ username\n");
            return S3_CLI_EXIT_ERROR;
        }

        for (i = 0; s3_cli_user[i] != '\0'; i++) {

            u_char ch = (u_char)s3_cli_user[i];

            if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                  (ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == '@' || ch == '-')) {
                fprintf(stderr, "ssh3: bad username byte %c for the JWT claim\n", ch);
                return S3_CLI_EXIT_ERROR;
            }
        }
    }

    if (s3_cli_user[0] != '\0') {
        snprintf(s3_cli_target, sizeof(s3_cli_target), "%s?user=%s", s3_cli_path, s3_cli_user);

    } else {
        snprintf(s3_cli_target, sizeof(s3_cli_target), "%s", s3_cli_path);
    }

    /* the jump target rides the default path with the jump login */

    if (s3_cli_jump_on) {

        if (s3_cli_jump_user[0] != '\0') {
            snprintf(s3_cli_jump_target, sizeof(s3_cli_jump_target), "%s?user=%s", "/ssh3-term",
                     s3_cli_jump_user);

        } else {
            snprintf(s3_cli_jump_target, sizeof(s3_cli_jump_target), "%s", "/ssh3-term");
        }
    }

    (void)s3_cli_tofu_prepare();

    /* the resolution first: the literal or the name; the family is
     * the v4 default of this port, -6 rides the v6 dial; the jump
     * run resolves the inner host v4 (the tunnel target extension) */

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = s3_cli_jump_on ? AF_INET : s3_cli_family;
    hints.ai_socktype = SOCK_DGRAM;

    if (getaddrinfo(s3_cli_host, NULL, &hints, &res) != 0 || res == NULL) {
        fprintf(stderr, "ssh3: cannot resolve %s\n", s3_cli_host);
        s3_cli_net_cleanup();
        return S3_CLI_EXIT_ERROR;
    }

    s3_cli_sa_len = res->ai_addrlen;
    memcpy(&s3_cli_sa, res->ai_addr, s3_cli_sa_len);

    if (s3_cli_sa.ss_family == AF_INET6) {
        ((struct sockaddr_in6 *)&s3_cli_sa)->sin6_port = htons((u_short)s3_cli_port);

    } else {
        ((struct sockaddr_in *)&s3_cli_sa)->sin_port = htons((u_short)s3_cli_port);
    }

    freeaddrinfo(res);

    if (s3_event_ctx_init(&s3_cli_ctx, &s3_cli_log) != S3_OK) {
        fprintf(stderr, "ssh3: the event context failed\n");
        s3_cli_net_cleanup();
        return S3_CLI_EXIT_ERROR;
    }

    /*
     * the jump phase: the tunnel to the inner server comes up first
     * (the jump dial runs its own loop on the same event context),
     * the inner conn then rides the bridge socket a
     */

    if (s3_cli_jump_on) {

        struct addrinfo jhints, *jres = NULL;

        if (s3_cli_jump_port == 0) {
            s3_cli_jump_port = 443;
        }

        memset(&jhints, 0, sizeof(jhints));
        jhints.ai_family = AF_INET;
        jhints.ai_socktype = SOCK_DGRAM;

        if (getaddrinfo(s3_cli_jump_host, NULL, &jhints, &jres) != 0 || jres == NULL) {
            fprintf(stderr, "ssh3: cannot resolve the jump host %s\n", s3_cli_jump_host);
            s3_cli_net_cleanup();
            return S3_CLI_EXIT_ERROR;
        }

        memcpy(&s3_cli_jump_sa, jres->ai_addr, sizeof(struct sockaddr_in));
        s3_cli_jump_sa.sin_family = AF_INET;
        s3_cli_jump_sa.sin_port = htons((u_short)s3_cli_jump_port);

        freeaddrinfo(jres);

        if (s3_cli_jump_dial(&s3_cli_ctx, s3_current_msec, (s3_msec_t)S3_CLI_SETUP_TIMEOUT) !=
            S3_OK) {
            s3_cli_net_cleanup();
            return S3_CLI_EXIT_ERROR;
        }

        /* the loopback bridge, a becomes the inner quic fd below; the
         * h3 globals the tunnel run touched reset for the inner phase
         * (the CONNECT and the :status replay clean) */

        if (s3_cli_jump_bridge_create(&s3_cli_ctx) != S3_OK) {
            fprintf(stderr, "ssh3: the jump bridge create failed\n");
            s3_cli_net_cleanup();
            return S3_CLI_EXIT_ERROR;
        }

        s3_cli_hs_done = 0;
        s3_cli_req_sent = 0;
        s3_cli_status_seen = 0;
        s3_cli_status = 0;
        s3_cli_resp_len = 0;
        s3_memzero(&s3_cli_h3parse, sizeof(s3_cli_h3parse));
    }

    if (s3_cli_jump_on) {

        /* the inner quic rides the bridge socket a, its peer is the
         * tunnel side b: the packets loop through the kernel and the
         * bridge wraps them into the jump channel datagrams */

        fd = (s3_fd_t)s3_cli_bridge_a;
        s3_cli_bridge_a = INVALID_SOCKET;

    } else {

        fd = (s3_fd_t)socket(s3_cli_family, SOCK_DGRAM, 0);

        if (fd == (s3_fd_t)INVALID_SOCKET) {
            fprintf(stderr, "ssh3: socket() failed\n");
            s3_cli_net_cleanup();
            return S3_CLI_EXIT_ERROR;
        }

        if (s3_nonblocking(fd) != S3_OK) {
            fprintf(stderr, "ssh3: the nonblocking mode failed\n");
            closesocket((SOCKET)fd);
            s3_cli_net_cleanup();
            return S3_CLI_EXIT_ERROR;
        }
    }

    cli = s3_get_connection(&s3_cli_ctx, fd);

    if (cli == NULL) {
        fprintf(stderr, "ssh3: the connection alloc failed\n");
        closesocket((SOCKET)fd);
        s3_cli_net_cleanup();
        return S3_CLI_EXIT_ERROR;
    }

    s3_cli_conn = cli;

    cli->pool = s3_create_pool((size_t)S3_DEFAULT_POOL_SIZE, &s3_cli_log);

    if (cli->pool == NULL) {
        s3_cli_teardown();
        return S3_CLI_EXIT_ERROR;
    }

    cli->sockaddr = s3_palloc(cli->pool, sizeof(s3_cli_sa));

    if (cli->sockaddr == NULL) {
        s3_cli_teardown();
        return S3_CLI_EXIT_ERROR;
    }

    if (s3_cli_jump_on) {
        memcpy(cli->sockaddr, &s3_cli_bridge_sa, sizeof(s3_cli_bridge_sa));
        cli->socklen = sizeof(s3_cli_bridge_sa);

    } else {
        memcpy(cli->sockaddr, &s3_cli_sa, s3_cli_sa_len);
        cli->socklen = s3_cli_sa_len;
    }

    alpn_wire[0] = (u_char)2;
    alpn_wire[1] = 'h';
    alpn_wire[2] = '3';

    alpn.data = alpn_wire;
    alpn.len = 3;

    memset(&s3_cli_conf, 0, sizeof(s3_cli_conf));

    s3_cli_conf.ssl = s3_ssl_client_create(&s3_cli_log, &alpn);

    if (s3_cli_conf.ssl == NULL) {
        fprintf(stderr, "ssh3: the ssl init failed\n");
        s3_cli_teardown();
        return S3_CLI_EXIT_ERROR;
    }

    s3_cli_conf.ctx = &s3_cli_ctx;
    s3_cli_conf.handshake_timeout = S3_CLI_SETUP_TIMEOUT;
    s3_cli_conf.idle_timeout = 60000;
    s3_cli_conf.stream_buffer_size = 1 << 20;
    s3_cli_conf.max_concurrent_streams_bidi = 16;
    s3_cli_conf.max_concurrent_streams_uni = 16;
    s3_cli_conf.active_connection_id_limit = 8;
    s3_cli_conf.max_datagram_frame_size = 1352;
    s3_cli_conf.datagram_handler = s3_cli_datagram;
    s3_cli_conf.stream_handler = s3_cli_client_stream;

    for (i = 0; i < S3_QUIC_AV_KEY_LEN; i++) {
        s3_cli_conf.av_token_key[i] = (u_char)(0xa0 + i);
        s3_cli_conf.sr_token_key[i] = (u_char)(0xb0 + i);
    }

    if (s3_event_actions.add_event(cli->read, S3_READ_EVENT, 0) != S3_OK) {
        s3_cli_teardown();
        return S3_CLI_EXIT_ERROR;
    }

    if (s3_quic_connect(cli, &s3_cli_conf) != S3_OK) {
        fprintf(stderr, "ssh3: the connect failed\n");
        s3_cli_teardown();
        return S3_CLI_EXIT_ERROR;
    }

    s3_cli_deadline = s3_current_msec + S3_CLI_SETUP_TIMEOUT;
    s3_cli_rc = 0;
    s3_cli_phase = S3_CLI_PH_DIAL;

    for (;;) {

        s3_event_process_posted(&s3_cli_ctx, &s3_cli_ctx.posted_events);

        s3_process_events_and_timers(&s3_cli_ctx);

        /* the jump tunnel: the parked frame retries, a dead jump
         * conversation strands the inner conn, the run ends */

        if (s3_cli_jump_on) {

            if (s3_quic_get_connection(s3_cli_jump_cli) == NULL) {
                fprintf(stderr, "ssh3: the jump connection is gone\n");
                s3_cli_rc = S3_CLI_EXIT_ERROR;
                break;
            }

            s3_cli_jump_bridge_flush();
        }

        qc = s3_quic_get_connection(cli);

        if (qc == NULL) {
            fprintf(stderr, "ssh3: the connection is gone\n");
            s3_cli_rc = S3_CLI_EXIT_ERROR;
            break;
        }

        /* the inner connection lives inside the jump tunnel: the path
         * mtu discovery pins at the 1200 floor, the escalating probes
         * would not fit the tunnel datagrams (the reference turns the
         * discovery off for its --proxy-jump the same way) */

        if (s3_cli_jump_on && qc->path != NULL && qc->path->max_mtu > S3_CLI_JUMP_INNER_MTU) {
            qc->path->max_mtu = S3_CLI_JUMP_INNER_MTU;
        }

        /* the handshake: the cert pins, the JWT signs, the h3
         * session and the CONNECT stream come up */

        if (!s3_cli_hs_done && cli->ssl != NULL && cli->ssl->handshaked) {

            s3_cli_hs_done = 1;

            if (s3_cli_cert_check() != S3_OK) {
                s3_cli_rc = S3_CLI_EXIT_ERROR;
                break;
            }

            if (s3_cli_auth == S3_CLI_AUTH_PUBKEY &&
                s3_cli_jwt_build(cli->ssl->connection) != S3_OK) {
                s3_cli_rc = S3_CLI_EXIT_ERROR;
                break;
            }

            if (s3_h3_get_session(cli) == NULL && s3_h3_init_session(cli) != S3_OK) {
                fprintf(stderr, "ssh3: the h3 session init failed\n");
                s3_cli_rc = S3_CLI_EXIT_ERROR;
                break;
            }

            memset(&s3_cli_h3parse, 0, sizeof(s3_cli_h3parse));

            s3_cli_ctrl = s3_quic_open_stream(cli, 1);

            if (s3_cli_ctrl == NULL) {
                fprintf(stderr, "ssh3: the stream open failed\n");
                s3_cli_rc = S3_CLI_EXIT_ERROR;
                break;
            }

            s3_cli_ctrl->read->handler = s3_cli_ctrl_read;
            s3_cli_ctrl->read->data = s3_cli_ctrl;
            s3_cli_ctrl->read->active = 1;
        }

        /* the CONNECT section rides the first writable pass */

        if (s3_cli_hs_done && !s3_cli_req_sent) {

            u_char  frame[1024];
            u_char *p;
            size_t  sec_len, total;
            ssize_t m;

            sec_len = s3_cli_h3_section(NULL);

            p = frame;
            p = (u_char *)s3_h3_encode_varlen_int(p, S3_H3_FRAME_HEADERS);
            p = (u_char *)s3_h3_encode_varlen_int(p, sec_len);
            sec_len = s3_cli_h3_section(p);
            total = (size_t)(p - frame) + sec_len;

            m = s3_quic_stream_send(s3_cli_ctrl, frame, total);

            if (m == (ssize_t)S3_AGAIN) {
                /* the window opens on the write event */
            } else if (m != (ssize_t)total) {
                fprintf(stderr, "ssh3: the CONNECT send failed\n");
                s3_cli_rc = S3_CLI_EXIT_ERROR;
                break;

            } else {
                s3_cli_req_sent = 1;
            }
        }

        /* the 200 brings the -L listeners up: the forward run carries
         * no session channel, the bridges live on the event loop */

        if (s3_cli_status_seen && s3_cli_status == 200 && s3_cli_fwd_count && !s3_cli_fwd_ready) {

            if (s3_cli_fwd_listeners_start() != S3_OK) {
                s3_cli_rc = S3_CLI_EXIT_ERROR;
                break;
            }

            s3_cli_fwd_ready = 1;
            s3_cli_phase = S3_CLI_PH_SESSION;

            s3_cli_tick_arm();

            if (s3_cli_tick == NULL) {
                s3_cli_rc = S3_CLI_EXIT_ERROR;
                break;
            }
        }

        /* the 200 opens the -R control channels: one per spec, the
         * bind request rides the channel data (the conversation of
         * the CONNECT stream rides the headers and the datagram
         * prefixes); the -R run carries no session channel, the run
         * holds like the -L one */

        if (s3_cli_status_seen && s3_cli_status == 200 && s3_cli_rspec_count && !s3_cli_rev_ready) {

            s3_cli_conv_id = ((s3_quic_stream_t *)s3_cli_ctrl->data)->id;

            if (s3_cli_rev_open_pending() != S3_OK) {
                s3_cli_rc = S3_CLI_EXIT_ERROR;
                break;
            }

            s3_cli_rev_ready = 1;
            s3_cli_phase = S3_CLI_PH_SESSION;

            s3_cli_tick_arm();

            if (s3_cli_tick == NULL) {
                s3_cli_rc = S3_CLI_EXIT_ERROR;
                break;
            }
        }

        /* the 200 opens the control pipe of the master: the sessions
         * of the slaves ride the same connection */

        if (s3_cli_status_seen && s3_cli_status == 200 && s3_cli_cm_master &&
            !s3_cli_cm_listening && !s3_cli_cm_stop) {

            s3_cli_cm_listen_open();

            if (s3_cli_rc != 0) {
                break;
            }

            s3_cli_phase = S3_CLI_PH_SESSION;

            s3_cli_tick_arm();

            if (s3_cli_tick == NULL) {
                s3_cli_rc = S3_CLI_EXIT_ERROR;
                break;
            }
        }

        /* the 200 opens the session channel (the forwards, the
         * reverse and the master carry no session of their own, the
         * -N holds the run without one) */

        if (s3_cli_status_seen && s3_cli_status == 200 && !s3_cli_fwd_count && !s3_cli_cm_master &&
            s3_cli_rspec_count == 0 && !s3_cli_no_session && s3_cli_chan == NULL) {

            s3_cli_chan = s3_quic_open_stream(cli, 1);

            if (s3_cli_chan == NULL) {
                fprintf(stderr, "ssh3: the channel open failed\n");
                s3_cli_rc = S3_CLI_EXIT_ERROR;
                break;
            }

            s3_cli_conv_id = ((s3_quic_stream_t *)s3_cli_ctrl->data)->id;

            if (s3_cli_sftp_mode) {
                s3_cli_chan->read->handler = s3_cli_sftp_read;

            } else {
                s3_cli_chan->read->handler = s3_cli_chan_read;
            }

            s3_cli_chan->read->data = s3_cli_chan;
            s3_cli_chan->read->active = 1;

            if (s3_cli_sftp_mode) {

                /* the pump rides the write readiness: the quic layer
                 * posts the write event when the peer reopens the
                 * stream window, the parked frame resumes there */

                s3_cli_chan->write->handler = s3_cli_sftp_write;
                s3_cli_chan->write->data = s3_cli_chan;
                s3_cli_chan->write->active = 1;
            }
        }

        /* the header plus the session requests ride one send */

        if (s3_cli_status_seen && s3_cli_status == 200 && !s3_cli_fwd_count && !s3_cli_cm_master &&
            s3_cli_rspec_count == 0 && !s3_cli_no_session && !s3_cli_ch_sent) {

            u_char            frame[2048];
            u_char           *p;
            s3_ssh3_channel_t hdr;
            size_t            total;
            ssize_t           m;

            memset(&hdr, 0, sizeof(hdr));

            hdr.conversation_stream_id = s3_cli_conv_id;
            hdr.max_packet_size = S3_CLI_CHANNEL_MAX_PACKET;

            if (s3_cli_sftp_mode) {

                /* the sftp transfer rides the "sftp" channel type,
                 * no session request follows the header */

                hdr.type.data = (u_char *)S3_SSH3_CHANNEL_TYPE_SFTP;
                hdr.type.len = strlen(S3_SSH3_CHANNEL_TYPE_SFTP);

            } else {
                hdr.type.data = (u_char *)S3_SSH3_CHANNEL_TYPE_SESSION;
                hdr.type.len = strlen(S3_SSH3_CHANNEL_TYPE_SESSION);
            }

            p = frame;
            p = (u_char *)s3_ssh3_channel_build_header(p, &hdr);

            if (s3_cli_sftp_mode) {

                /* the sftp channel: the header alone rides, the
                 * driver start follows the send */

            } else {

                /*
                 * the pty policy (the ssh2 shape): the shell wants
                 * the pty by default (the console with the real
                 * geometry, the pipe with the 80x24 force), -T drops
                 * it entirely; the exec rides without a pty unless
                 * -t/-tt force one.  The -X/-A mode announces the
                 * agent trigger on the LARVAL session first
                 */

                unsigned want_pty = 0;

                if (s3_cli_cmd != NULL) {
                    want_pty = (s3_cli_pty_mode == S3_CLI_PTY_FORCE ||
                                s3_cli_pty_mode == S3_CLI_PTY_FORCE_NOTTY);

                } else {
                    want_pty = (s3_cli_pty_mode != S3_CLI_PTY_NEVER);
                }

                if (s3_cli_agent_mode) {

                    static const char trigger[] = S3_SSH3_AGENT_TRIGGER;

                    s3_ssh3_msg_data_t marker;

                    memset(&marker, 0, sizeof(marker));

                    marker.data.data = (u_char *)trigger;
                    marker.data.len = sizeof(trigger) - 1;

                    p = (u_char *)s3_ssh3_encode_varint(p, S3_SSH3_MSG_CHANNEL_DATA);
                    p = (u_char *)s3_ssh3_msg_encode_data(p, &marker);
                }

                if (want_pty) {

                    s3_ssh3_request_t pty;

                    memset(&pty, 0, sizeof(pty));

                    pty.kind = S3_SSH3_REQ_PTY;
                    pty.u.pty.term.data = (u_char *)"xterm-256color";
                    pty.u.pty.term.len = strlen("xterm-256color");

                    if (s3_cli_console &&
                        s3_cli_console_winsize(&s3_cli_win_w, &s3_cli_win_h) == S3_OK &&
                        s3_cli_win_w != 0 && s3_cli_win_h != 0) {
                        /* the real geometry of the console */
                    } else {
                        s3_cli_win_w = 80;
                        s3_cli_win_h = 24;
                    }

                    pty.u.pty.width = s3_cli_win_w;
                    pty.u.pty.height = s3_cli_win_h;
                    pty.u.pty.pixel_width = 0;
                    pty.u.pty.pixel_height = 0;
                    pty.u.pty.modes.data = NULL;
                    pty.u.pty.modes.len = 0;

                    p = s3_cli_session_request(p, S3_SSH3_REQ_PTY, 1, &pty);

                    s3_cli_tty = 1;
                }

                if (s3_cli_cmd != NULL) {

                    /* the exec: the command with the reply wanted, the
                     * fin rides right behind it */

                    s3_ssh3_request_t exec;

                    memset(&exec, 0, sizeof(exec));

                    exec.kind = S3_SSH3_REQ_EXEC;
                    exec.u.exec.command.data = (u_char *)s3_cli_cmd;
                    exec.u.exec.command.len = strlen(s3_cli_cmd);

                    p = s3_cli_session_request(p, S3_SSH3_REQ_EXEC, 1, &exec);

                } else {

                    /* the shell request closes the header */

                    s3_ssh3_request_t shell;

                    memset(&shell, 0, sizeof(shell));
                    shell.kind = S3_SSH3_REQ_SHELL;

                    p = s3_cli_session_request(p, S3_SSH3_REQ_SHELL, 1, &shell);
                }
            }

            total = (size_t)(p - frame);

            m = s3_quic_stream_send(s3_cli_chan, frame, total);

            if (m == (ssize_t)S3_AGAIN) {
                /* retried on the write event */
            } else if (m != (ssize_t)total) {
                fprintf(stderr, "ssh3: the channel send failed\n");
                s3_cli_rc = S3_CLI_EXIT_ERROR;
                break;

            } else {
                s3_cli_ch_sent = 1;

                if (s3_cli_sftp_mode) {

                    /* the sftp driver: the INIT parks until the 91
                     * confirms the channel, the first pump pass
                     * rides the confirmation read */

                    s3_cli_sftp_start();

                    s3_cli_tick_arm();

                    if (s3_cli_tick == NULL) {
                        s3_cli_rc = S3_CLI_EXIT_ERROR;
                        break;
                    }

                    s3_cli_phase = S3_CLI_PH_SESSION;

                } else {

                    if (s3_cli_cmd != NULL &&
                        s3_quic_shutdown_stream(s3_cli_chan, S3_WRITE_SHUTDOWN) != S3_OK) {
                        fprintf(stderr, "ssh3: the channel fin failed\n");
                        s3_cli_rc = S3_CLI_EXIT_ERROR;
                        break;
                    }

                    /* the session pump lives on the console tick */

                    if (s3_ssh3_session_cli_init(&s3_cli_sess, cli->pool, s3_cli_out_sink, NULL,
                                                 s3_cli_err_sink, NULL, s3_cli_exit_cb,
                                                 NULL) != S3_OK) {
                        fprintf(stderr, "ssh3: the session init failed\n");
                        s3_cli_rc = S3_CLI_EXIT_ERROR;
                        break;
                    }

                    if (s3_cli_console_init() != S3_OK) {
                        fprintf(stderr, "ssh3: the console init failed\n");
                        s3_cli_rc = S3_CLI_EXIT_ERROR;
                        break;
                    }

                    s3_cli_tick_arm();

                    if (s3_cli_tick == NULL) {
                        s3_cli_rc = S3_CLI_EXIT_ERROR;
                        break;
                    }

                    s3_cli_phase = S3_CLI_PH_SESSION;
                }
            }
        }

        /* the -N hold: the session channel never comes, the event
         * pump keeps the conn alive until it dies (the verdict then
         * rides the gone-conn check at the loop head) */

        if (s3_cli_status_seen && s3_cli_status == 200 && s3_cli_no_session &&
            s3_cli_phase != S3_CLI_PH_SESSION) {

            s3_cli_phase = S3_CLI_PH_SESSION;

            s3_cli_tick_arm();

            if (s3_cli_tick == NULL) {
                s3_cli_rc = S3_CLI_EXIT_ERROR;
                break;
            }
        }

        if (s3_cli_verdict) {
            break;
        }

        /* the setup deadline guards the bring-up only; the session
         * runs without one (the long exec is legitimate) */

        if (s3_cli_phase != S3_CLI_PH_SESSION && s3_current_msec > s3_cli_deadline) {
            fprintf(stderr, "ssh3: the setup timed out (hs=%u req=%u status=%u ch=%u)\n",
                    s3_cli_hs_done, s3_cli_req_sent, s3_cli_status_seen, s3_cli_ch_sent);
            s3_cli_rc = S3_CLI_EXIT_ERROR;
            break;
        }
    }

    s3_cli_teardown();

    if (s3_cli_rc != 0) {
        return S3_CLI_EXIT_ERROR;
    }

    return (int)(s3_cli_exit_code & 0xff);
}

/*
 * the common teardown: the console restores first (the user keeps
 * the shell), then the harness-owned streams, the quic close and the
 * posted drain of the exit paths (the P7.2 shape)
 */

static void
s3_cli_teardown(void)
{
    s3_quic_connection_t *qc;
    unsigned              i;
    unsigned              quic_alive;

    s3_cli_console_done();

    /* the agent bridge and the control pipe close before the wire */

    s3_cli_agent_teardown("teardown");

    if (s3_cli_agent_pool != NULL) {
        s3_destroy_pool(s3_cli_agent_pool);
        s3_cli_agent_pool = NULL;
    }

    if (s3_cli_cm_master) {

        s3_cli_cm_conn_t *conn = s3_cli_cm_conns;

        s3_cli_cm_shutdown();

        while (conn != NULL) {

            s3_cli_cm_conn_t *next = conn->next;

            if (s3_cli_cm_h_valid(conn->h)) {
#if (S3_WIN32)
                DisconnectNamedPipe(conn->h);
#endif
                s3_cli_cm_h_close(conn->h);
                conn->h = S3_CLI_H_INVALID;
            }

            conn = next;
        }
    }

    /* the -L listeners and the bridges close before the wire; the
     * quic stream ops ride the live connection only (the idle close
     * already tore the streams down, the shutdown would deref the
     * freed state) */

    quic_alive = (s3_cli_conn != NULL && s3_quic_get_connection(s3_cli_conn) != NULL) ? 1u : 0u;

    if (s3_cli_fwd_ready) {

        unsigned k;

        for (k = 0; k < S3_CLI_FWD_TCP_CONNS; k++) {

            if (s3_cli_fwd_conns[k].used) {
                s3_cli_fwd_tcp_drop(&s3_cli_fwd_conns[k]);
            }
        }

        for (k = 0; k < s3_cli_fwd_count; k++) {

            unsigned j;

            if (s3_cli_fwd_listen[k] != INVALID_SOCKET) {
                closesocket(s3_cli_fwd_listen[k]);
                s3_cli_fwd_listen[k] = INVALID_SOCKET;
            }

            for (j = 0; j < S3_CLI_FWD_UDP_SRCS; j++) {

                s3_cli_fwd_udp_src_t *src = &s3_cli_fwd_udp[k].srcs[j];

                if (src->used && src->chan != NULL) {

                    if (quic_alive) {
                        (void)s3_quic_shutdown_stream(src->chan, S3_RDWR_SHUTDOWN);
                    }

                    s3_close_connection(src->chan);
                    src->chan = NULL;
                }

                src->used = 0;
            }

            if (s3_cli_fwd_udp[k].used) {

                if (s3_cli_fwd_udp[k].evc != NULL) {
                    s3_close_connection(s3_cli_fwd_udp[k].evc);
                    s3_cli_fwd_udp[k].fd = INVALID_SOCKET; /* the conn owns the fd */
                }

                if (s3_cli_fwd_udp[k].fd != INVALID_SOCKET && s3_cli_fwd_udp[k].fd != 0) {
                    closesocket(s3_cli_fwd_udp[k].fd);
                }

                s3_cli_fwd_udp[k].used = 0;
            }
        }
    }

    /* the -R bridges and the control channels close the same way
     * (the server-initiated streams ride the same liveness guard) */

    if (s3_cli_rspec_count) {
        s3_cli_rev_teardown(quic_alive);
        s3_cli_rev_ready = 0;
    }

    if (s3_cli_tick != NULL && s3_cli_tick->timer_set) {
        s3_event_del_timer(s3_cli_tick);
        s3_cli_tick = NULL;
    }

    if (s3_cli_ctrl != NULL) {
        s3_close_connection(s3_cli_ctrl);
        s3_cli_ctrl = NULL;
    }

    if (s3_cli_chan != NULL) {
        s3_close_connection(s3_cli_chan);
        s3_cli_chan = NULL;
    }

    if (s3_cli_conn != NULL) {
        (void)s3_quic_close_connection(s3_cli_conn, S3_ABORT);
    }

    /* the close parked on the drain timer drops and completes inside
     * the posted passes (the daemon shutdown tail trick) */

    if (s3_cli_conn != NULL) {

        qc = s3_quic_get_connection(s3_cli_conn);

        if (qc != NULL && qc->close.timer_set) {
            s3_event_del_timer(&qc->close);
            s3_post_event(&qc->close, &s3_cli_ctx.posted_events);
        }
    }

    for (i = 0; i < 64; i++) {

        if (s3_cli_conn == NULL || (s3_quic_get_connection(s3_cli_conn) == NULL &&
                                    s3_queue_empty(&s3_cli_ctx.posted_events))) {
            break;
        }

        s3_event_process_posted(&s3_cli_ctx, &s3_cli_ctx.posted_events);
    }

    if (s3_cli_conf.ssl != NULL) {
        s3_ssl_free(s3_cli_conf.ssl);
        s3_cli_conf.ssl = NULL;
    }

    if (s3_cli_conn != NULL) {
        closesocket((SOCKET)s3_cli_conn->fd);
        s3_cli_conn = NULL;
    }

    /* the jump tunnel: the jump conn and the bridge sockets close
     * with the wire (the pools ride the conn close) */

    if (s3_cli_jump_cli != NULL) {

        if (s3_cli_jump_conf.ssl != NULL) {
            s3_ssl_free(s3_cli_jump_conf.ssl);
            s3_cli_jump_conf.ssl = NULL;
        }

        closesocket((SOCKET)s3_cli_jump_cli->fd);
        s3_cli_jump_cli = NULL;
    }

    if (s3_cli_bridge_a != INVALID_SOCKET) {
        closesocket(s3_cli_bridge_a);
        s3_cli_bridge_a = INVALID_SOCKET;
    }

    if (s3_cli_bridge_b != INVALID_SOCKET) {
        closesocket(s3_cli_bridge_b);
        s3_cli_bridge_b = INVALID_SOCKET;
    }

    s3_event_ctx_shutdown(&s3_cli_ctx);

    free(s3_cli_cmd);
    s3_cli_cmd = NULL;

    free(s3_cli_cm_exec);
    s3_cli_cm_exec = NULL;

    free(s3_cli_sftp_out);
    s3_cli_sftp_out = NULL;

    free(s3_cli_sftp_buf);
    s3_cli_sftp_buf = NULL;

    free(s3_cli_sftp_local);
    s3_cli_sftp_local = NULL;

    free(s3_cli_sftp_remote);
    s3_cli_sftp_remote = NULL;

    s3_cli_net_cleanup();
}
