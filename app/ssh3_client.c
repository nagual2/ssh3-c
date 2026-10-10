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
 * the server certificate pins TOFU-style: %USERPROFILE%\.ssh3\known_hosts
 * holds "host:port/path x509-certificate <base64 DER>" lines (the Go
 * client format), an exact match connects, a mismatch refuses, an
 * unknown host asks on a console (a non-interactive session refuses,
 * like the reference ask mode)
 *
 * the auth rides the -i PEM key (the Bearer JWT, EdDSA/ES256/RS256)
 * or the -U user:pass (the Basic scheme); the harness kept the
 * test-token default, the product sends no header without an option
 *
 * the whole file is the win32 beachhead: the unix client target
 * deliberately does not exist yet (docs/PLAN.md P9)
 */

#if (S3_WIN32)

#include <fcntl.h>
#include <io.h>
#include <process.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <ws2tcpip.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include <s3_core.h>
#include <s3_h3.h>
#include <s3_h3_uni.h>
#include <s3_nonblocking.h>
#include <s3_os_init.h>
#include <s3_quic.h>
#include <s3_quic_connection.h>
#include <s3_quic_output.h>
#include <s3_quic_streams.h>
#include <s3_ssh3_channel.h>
#include <s3_ssh3_dgram.h>
#include <s3_ssh3_forward.h>
#include <s3_ssh3_message.h>
#include <s3_ssh3_request.h>
#include <s3_ssh3_session_cli.h>
#include <s3_ssh3_sftp_cli.h>
#include <s3_ssh3_version.h>
#include <s3_ssh3_wire.h>
#include <s3_ssl.h>

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
static struct sockaddr_in s3_cli_sa;
static unsigned           s3_cli_phase;
static s3_msec_t          s3_cli_deadline;

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
static unsigned    s3_cli_verbose;

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

#define S3_CLI_FWD_TCP 1
#define S3_CLI_FWD_UDP 2

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
    unsigned kind;      /* S3_CLI_FWD_TCP or S3_CLI_FWD_UDP */
    unsigned bind_addr; /* the network order ipv4 */
    unsigned bind_port;
    unsigned target_addr; /* the network order ipv4 of the target */
    unsigned target_port;
    char     text[128]; /* the tcp://bind:port/host:port shape of the logs */
} s3_cli_fwd_spec_t;

static s3_cli_fwd_spec_t s3_cli_fwd_specs[S3_CLI_FWD_MAX];
static unsigned          s3_cli_fwd_count;
static unsigned          s3_cli_fwd_ready;

/* one local tcp connection of a tcp forward: the channel opens per
 * accepted socket, both directions park and drain on the tick */

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

/* the console side: the raw mode, the reader thread, the ring, the
 * window tracking; the pipe mode shares the ring, the thread reads
 * the pipe the same way */

static HANDLE   s3_cli_in_h;
static HANDLE   s3_cli_out_h;
static DWORD    s3_cli_in_saved;
static unsigned s3_cli_console; /* the stdin is a console */
static unsigned s3_cli_raw;     /* the raw mode is on */
static unsigned s3_cli_tty;     /* the pty was requested (a console) */

static CRITICAL_SECTION s3_cli_ring_cs;
static u_char           s3_cli_ring[S3_CLI_RING_SIZE];
static size_t           s3_cli_ring_head;
static size_t           s3_cli_ring_tail;
static uintptr_t        s3_cli_thread;
static unsigned         s3_cli_stdin_eof;
static unsigned         s3_cli_fin_sent;
static unsigned         s3_cli_stop;

static uint64_t    s3_cli_win_w;
static uint64_t    s3_cli_win_h;
static s3_event_t *s3_cli_tick;

static unsigned s3_cli_rc;

static void      s3_cli_usage(const char *prog);
static void      s3_cli_b64std(const u_char *src, size_t len, char *dst);
static void      s3_cli_b64url(const u_char *src, size_t len, char *dst);
static size_t    s3_cli_b64dec(const char *src, u_char *dst, size_t cap);
static void      s3_cli_sha256_fp(const u_char *der, size_t len, char *fp);
static s3_int_t  s3_cli_jwt_sign(EVP_PKEY *key, const char *alg, const u_char *msg, size_t msglen,
                                 u_char *sig, size_t *siglen);
static s3_int_t  s3_cli_jwt_build(SSL *ssl);
static uintptr_t s3_cli_h3_field_l(u_char *p, const char *name, const char *value);
static size_t    s3_cli_h3_section(u_char *p);
static s3_int_t  s3_cli_tofu_prepare(void);
static s3_int_t  s3_cli_cert_check(void);
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
static unsigned __stdcall s3_cli_reader(void *arg);
static s3_int_t s3_cli_console_winsize(uint64_t *width, uint64_t *height);
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
static void     s3_cli_fwd_tcp_local_read(s3_event_t *ev);
static void     s3_cli_fwd_tcp_chan_read(s3_event_t *ev);
static void     s3_cli_fwd_tcp_flush(s3_cli_fwd_tcp_conn_t *fc);
static void     s3_cli_fwd_tcp_drop(s3_cli_fwd_tcp_conn_t *fc);
static void     s3_cli_fwd_udp_local_read(s3_event_t *ev);
static void     s3_cli_fwd_udp_chan_read(s3_event_t *ev);
static void     s3_cli_fwd_udp_pump(s3_cli_fwd_udp_t *uf);
static void     s3_cli_fwd_datagram(s3_chain_t *data);
static void     s3_cli_fwd_tick(void);

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
            "  -i keyfile  pubkey auth: sign the Bearer JWT with the PEM private\n"
            "              key (ed25519, P-256 or RSA); the username rides the\n"
            "              user@ part of the operand\n"
            "  -U user:pass  Basic auth (RFC 7617), the ?user= of the target\n"
            "  -J put|get:local:remote  the sftp transfer (get: local first);\n"
            "              with -r the -r forms recurse over the tree (a colon\n"
            "              beyond the Windows drive letter ends the paths)\n"
            "  -r          with -J: the recursive transfer\n"
            "  -L tcp://[bind:]port/host/port  the local tcp forward: every\n"
            "              accepted connection rides a direct-tcp channel of the\n"
            "              same conversation to the ipv4 target; udp:// likewise\n"
            "              over the datagrams (the bind defaults to 127.0.0.1)\n"
            "  -v          verbose logging\n"
            "  -l lvl      the s3 log level 0..9 or all\n"
            "  -V          version\n"
            "  -h          this help\n"
            " no command opens an interactive shell (pty on a console, the\n"
            " stdin pipe pumps without one), a command runs exec; the server\n"
            " certificate pins into %%USERPROFILE%%\\.ssh3\\known_hosts\n",
            prog);
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

/*
 * the Bearer JWT of the -i mode, built once after the handshake (the
 * jti binds the live TLS exporter) and before the CONNECT; the claim
 * set is the reference BuildJWTBearerToken() (see the header contract
 * of s3_ssh3_auth_jwt)
 */

static s3_int_t
s3_cli_jwt_build(SSL *ssl)
{
    static const char label[] = "EXPORTER-SSH3";

    char        header[64], payload[512], seg[1024], jti[64], tok[1200];
    u_char      conv[32], sig[1024];
    BIO        *bio;
    EVP_PKEY   *key = NULL;
    const char *alg;
    long long   iat, exp;
    size_t      hlen, plen, tlen, siglen;

    bio = BIO_new_file(s3_cli_keyfile, "r");

    if (bio == NULL) {
        s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "cannot open key file %s", s3_cli_keyfile);
        return S3_ERROR;
    }

    key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (key == NULL) {
        s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "%s is not a PEM private key", s3_cli_keyfile);
        return S3_ERROR;
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
                            s3_cli_user, iat, exp, s3_cli_user, jti);

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

    memcpy(tok, seg, tlen);
    tok[tlen++] = '.';
    s3_cli_b64url(sig, siglen, tok + tlen);

    snprintf(s3_cli_bearer, sizeof(s3_cli_bearer), "Bearer %s", tok);
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
 * :path the ?user= target
 */

static size_t
s3_cli_h3_section(u_char *p)
{
    u_char *start = p;
    char    authority[320];

    snprintf(authority, sizeof(authority), "%s:%u", s3_cli_host, s3_cli_port);

    if (p == NULL) {
        size_t n = (size_t)s3_h3_encode_field_section_prefix(NULL, 0, 0, 0);

        n += (size_t)s3_cli_h3_field_l(NULL, ":method", "CONNECT");
        n += (size_t)s3_cli_h3_field_l(NULL, ":protocol", "ssh3");
        n += (size_t)s3_cli_h3_field_l(NULL, ":scheme", "https");
        n += (size_t)s3_cli_h3_field_l(NULL, ":authority", authority);
        n += (size_t)s3_cli_h3_field_l(NULL, ":path", s3_cli_target);
        n += (size_t)s3_cli_h3_field_l(NULL, "user-agent", S3_SSH3_VERSION_STRING);

        if (s3_cli_auth_value != NULL) {
            n += (size_t)s3_cli_h3_field_l(NULL, "authorization", s3_cli_auth_value);
        }

        return n;
    }

    p = (u_char *)s3_h3_encode_field_section_prefix(p, 0, 0, 0);
    p = (u_char *)s3_cli_h3_field_l(p, ":method", "CONNECT");
    p = (u_char *)s3_cli_h3_field_l(p, ":protocol", "ssh3");
    p = (u_char *)s3_cli_h3_field_l(p, ":scheme", "https");
    p = (u_char *)s3_cli_h3_field_l(p, ":authority", authority);
    p = (u_char *)s3_cli_h3_field_l(p, ":path", s3_cli_target);
    p = (u_char *)s3_cli_h3_field_l(p, "user-agent", S3_SSH3_VERSION_STRING);

    if (s3_cli_auth_value != NULL) {
        p = (u_char *)s3_cli_h3_field_l(p, "authorization", s3_cli_auth_value);
    }

    return (size_t)(p - start);
}

/*
 * the known_hosts check of the DER: S3_OK when the certificate
 * matches a pin or was just accepted, S3_DECLINED when the host is
 * unknown and the user declined (or the session is not a console),
 * S3_ERROR on a changed certificate (the MITM shape) or a file error;
 * the line format is the Go client one
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
    char        line[4096], fp[64], pin[8200], kh_path[1024];
    u_char     *der = NULL, dec[8192];
    const char *home;
    size_t      derlen;
    int         matched = 0, pinned = 0, len;
    FILE       *f;
    HANDLE      kh;

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
    }

    s3_cli_sha256_fp(der, derlen, fp);

    home = getenv("USERPROFILE");

    if (home == NULL || home[0] == '\0') {
        s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "USERPROFILE is not set, cannot pin");
        OPENSSL_free(der);
        return S3_ERROR;
    }

    snprintf(kh_path, sizeof(kh_path), "%s\\.ssh3\\known_hosts", home);

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

    /* the unknown host: the TOFU question on a console, a pipe
     * session refuses (the reference ask mode) */

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
            "Do you want to add this certificate to %%USERPROFILE%%\\.ssh3\\known_hosts"
            " (yes/no)? ",
            s3_cli_hostkey, fp);
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

    /* the pin appends, the .ssh3 dir creates on demand */

    snprintf(line, sizeof(line), "%s\\.ssh3", home);
    CreateDirectoryA(line, NULL);

    kh = CreateFileA(kh_path, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS,
                     FILE_ATTRIBUTE_NORMAL, NULL);

    if (kh == INVALID_HANDLE_VALUE) {
        s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "cannot open known_hosts for append");
        OPENSSL_free(der);
        return S3_ERROR;
    }

    s3_cli_b64std(der, derlen, pin);
    len = snprintf(line, sizeof(line), "%s x509-certificate %s\r\n", s3_cli_hostkey, pin);

    {
        DWORD wrote = 0;

        if (!WriteFile(kh, line, (DWORD)len, &wrote, NULL) || wrote != (DWORD)len) {
            s3_log_error(S3_LOG_ERR, &s3_cli_log, 0, "the known_hosts append failed");
            CloseHandle(kh);
            OPENSSL_free(der);
            return S3_ERROR;
        }
    }

    CloseHandle(kh);

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

        int n = _write(1, data->data + off, (unsigned)(data->len - off));

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

        int n = _write(2, data->data + off, (unsigned)(data->len - off));

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

/* the datagrams: the udp forwards route them, the other runs drain */

static void
s3_cli_datagram(s3_connection_t *c, s3_chain_t *data)
{
    if (s3_cli_fwd_count) {
        s3_cli_fwd_datagram(data);
        return;
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

static s3_int_t
s3_cli_fwd_parse(const char *arg)
{
    s3_cli_fwd_spec_t *spec;
    const char        *s = arg, *slash, *slash2;
    char              *colon;
    char               authority[128], host[128];
    unsigned           kind, bind_port, target_port;
    struct in_addr     bind_addr, target_addr;

    if (strncmp(s, "tcp://", 6) == 0) {
        kind = S3_CLI_FWD_TCP;
        s += 6;

    } else if (strncmp(s, "udp://", 6) == 0) {
        kind = S3_CLI_FWD_UDP;
        s += 6;

    } else {
        fprintf(stderr, "ssh3: -L wants tcp://[bind:]port/host/port\n");
        return S3_ERROR;
    }

    slash = strchr(s, '/');

    if (slash == NULL || slash == s || (size_t)(slash - s) >= sizeof(authority)) {
        fprintf(stderr, "ssh3: -L wants tcp://[bind:]port/host/port\n");
        return S3_ERROR;
    }

    memcpy(authority, s, (size_t)(slash - s));
    authority[slash - s] = '\0';

    s = slash + 1;
    slash2 = strchr(s, '/');

    if (slash2 == NULL || slash2 == s || (size_t)(slash2 - s) >= sizeof(host) ||
        strlen(slash2 + 1) == 0 || strlen(slash2 + 1) > 5) {
        fprintf(stderr, "ssh3: -L wants tcp://[bind:]port/host/port\n");
        return S3_ERROR;
    }

    memcpy(host, s, (size_t)(slash2 - s));
    host[slash2 - s] = '\0';

    /* the authority: [bind:]port, the bind defaults to the loopback */

    colon = strchr(authority, ':');

    if (colon != NULL) {
        *colon = '\0';

        if (colon == authority || inet_pton(AF_INET, authority, &bind_addr) != 1) {
            fprintf(stderr, "ssh3: -L bind %s is not an ipv4 address\n", authority);
            return S3_ERROR;
        }

        bind_port = (unsigned)atoi(colon + 1);

    } else {
        bind_addr.s_addr = htonl(INADDR_LOOPBACK);
        bind_port = (unsigned)atoi(authority);
    }

    if (bind_port == 0 || bind_port > 65535) {
        fprintf(stderr, "ssh3: -L bad bind port in %s\n", arg);
        return S3_ERROR;
    }

    target_port = (unsigned)atoi(slash2 + 1);

    if (target_port == 0 || target_port > 65535 || inet_pton(AF_INET, host, &target_addr) != 1) {
        fprintf(stderr, "ssh3: -L target %s:%s is not an ipv4 socket\n", host, slash2 + 1);
        return S3_ERROR;
    }

    if (s3_cli_fwd_count >= S3_CLI_FWD_MAX) {
        fprintf(stderr, "ssh3: too many -L forwards\n");
        return S3_ERROR;
    }

    spec = &s3_cli_fwd_specs[s3_cli_fwd_count++];

    memset(spec, 0, sizeof(*spec));

    spec->kind = kind;
    spec->bind_addr = (unsigned)bind_addr.s_addr;
    spec->bind_port = bind_port;
    spec->target_addr = (unsigned)target_addr.s_addr;
    spec->target_port = target_port;
    snprintf(spec->text, sizeof(spec->text), "%s", arg);

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
        struct sockaddr_in sa;
        SOCKET             fd;
        s3_connection_t   *c;

        memset(&sa, 0, sizeof(sa));

        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = (ULONG)spec->bind_addr;
        sa.sin_port = htons((u_short)spec->bind_port);

        fd = (spec->kind == S3_CLI_FWD_TCP) ? socket(AF_INET, SOCK_STREAM, 0)
                                            : socket(AF_INET, SOCK_DGRAM, 0);

        if (fd == INVALID_SOCKET) {
            s3_log_error(S3_LOG_ERR, &s3_cli_log, s3_socket_errno, "socket() failed for %s",
                         spec->text);
            return S3_ERROR;
        }

        if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
            s3_log_error(S3_LOG_ERR, &s3_cli_log, s3_socket_errno, "bind() failed for %s",
                         spec->text);
            closesocket(fd);
            return S3_ERROR;
        }

        if (spec->kind == S3_CLI_FWD_TCP && listen(fd, 8) != 0) {
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

        c->read->handler =
            (spec->kind == S3_CLI_FWD_TCP) ? s3_cli_fwd_tcp_accept : s3_cli_fwd_udp_local_read;
        c->read->data = c; /* the select module contract: data is the conn */

        /* the spec index rides the free data of the raw connection */

        c->data = (void *)(uintptr_t)i;

        c->read->active = 1;

        if (s3_event_actions.add_event(c->read, S3_READ_EVENT, 0) != S3_OK) {
            closesocket(fd);
            return S3_ERROR;
        }

        if (spec->kind == S3_CLI_FWD_TCP) {
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
    }

    if (fc->fd != INVALID_SOCKET) {
        closesocket(fc->fd);
        fc->fd = INVALID_SOCKET;
    }

    if (fc->chan != NULL) {
        (void)s3_quic_shutdown_stream(fc->chan, S3_RDWR_SHUTDOWN);
        s3_close_connection(fc->chan);
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
        int                plen = sizeof(peer);
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
        fc->chan = s3_quic_open_stream(s3_cli_conn, 1);

        if (fc->chan == NULL) {
            s3_cli_fwd_tcp_drop(fc);
            continue;
        }

        fc->frame = malloc(S3_CLI_FWD_FRAME);

        if (fc->frame == NULL) {
            s3_cli_fwd_tcp_drop(fc);
            continue;
        }

        {
            s3_cli_fwd_spec_t       *sp = &s3_cli_fwd_specs[spec];
            s3_ssh3_channel_t        h;
            s3_ssh3_forward_target_t t;
            u_char                  *p;
            ssize_t                  m;

            memset(&h, 0, sizeof(h));

            h.conversation_stream_id = s3_cli_conv_id;
            h.max_packet_size = S3_CLI_CHANNEL_MAX_PACKET;
            h.type.data = (u_char *)S3_SSH3_CHANNEL_TYPE_DIRECT_TCP;
            h.type.len = strlen(S3_SSH3_CHANNEL_TYPE_DIRECT_TCP);

            t.family = 4;
            t.ip_len = 4;
            memcpy(t.ip, &sp->target_addr, 4);
            t.port = (uint16_t)sp->target_port;

            p = fc->hdr;
            p = (u_char *)s3_ssh3_channel_build_header(p, &h);
            p = s3_ssh3_forward_build_target(p, &t);

            fc->hdr_len = (size_t)(p - fc->hdr);

            m = s3_quic_stream_send(fc->chan, fc->hdr, fc->hdr_len);

            if (m == (ssize_t)S3_AGAIN) {

                /* the tiny header parks, the flush retries */

            } else if (m <= 0) {
                s3_cli_fwd_tcp_drop(fc);
                continue;

            } else {
                fc->hdr_sent = 1;
            }
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
    int                   flen = sizeof(from);
    s3_cli_fwd_udp_src_t *src = NULL;
    unsigned              k;

    for (;;) {

        int n = recvfrom(uf->fd, (char *)buf, sizeof(buf), 0, (struct sockaddr *)&from, &flen);

        if (n < 0) {

            if (s3_socket_errno == WSAEMSGSIZE) {

                /* the oversized datagram drops (the udp semantics) */

                continue;
            }

            /* WSAEWOULDBLOCK or a transient: the next event retries */

            return;
        }

        if (n == 0) {
            return;
        }

        for (k = 0; k < S3_CLI_FWD_UDP_SRCS; k++) {

            s3_cli_fwd_udp_src_t *s = &uf->srcs[k];

            if (s->used && s->src.sin_addr.S_un.S_addr == from.sin_addr.S_un.S_addr &&
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

/*
 * the pump tick of the session and of the sftp run: one timer event
 * on the connection pool, the handler re-arms itself
 */

static void
s3_cli_tick_arm(void)
{
    if (s3_cli_tick != NULL) {
        return;
    }

    s3_cli_tick = s3_pnalloc(s3_cli_conn->pool, sizeof(s3_event_t));

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
 * the console bring-up of the session: the raw input (the line,
 * echo and processed input drop, the VT input passes the escapes),
 * the VT output, the UTF-8 code pages; the reader thread lives from
 * here to the session end
 */

static s3_int_t
s3_cli_console_init(void)
{
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

    s3_cli_thread = _beginthreadex(NULL, 0, s3_cli_reader, NULL, 0, NULL);

    if (s3_cli_thread == 0) {
        DeleteCriticalSection(&s3_cli_ring_cs);
        return S3_ERROR;
    }

    return S3_OK;
}

/* the saved console mode back, the thread joins */

static void
s3_cli_console_done(void)
{
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
}

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

                size_t next = (s3_cli_ring_head + 1) & S3_CLI_RING_MASK;

                if (next == s3_cli_ring_tail) {
                    /* the ring full drops the byte: the echo runs
                     * ahead of the window, the user keeps typing */
                    continue;
                }

                s3_cli_ring[s3_cli_ring_head] = buf[i];
                s3_cli_ring_head = next;
            }
        }

        LeaveCriticalSection(&s3_cli_ring_cs);
    }
}

/*
 * the console window size for the pty-req and the window-change, the
 * visible window of the screen buffer (the fd-less shape: the size
 * lives on the output side)
 */

static s3_int_t
s3_cli_console_winsize(uint64_t *width, uint64_t *height)
{
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
}

/*
 * the console tick: the ring drains into the 94 frames, the pipe eof
 * closes the write side, the resize rides the window-change request;
 * the tick re-arms itself for the session lifetime
 */

static void
s3_cli_tick_handler(s3_event_t *ev)
{
    u_char frame[S3_CLI_RING_SIZE + 8];

    if (s3_cli_fwd_count) {

        /* the forward run: the parked drains ride the tick (the
         * local socket writes park rarely, the echo paths stay
         * hot); the console machinery stays off */

        s3_cli_fwd_tick();

        if (!s3_cli_stop && !s3_cli_verdict) {
            s3_event_add_timer(ev, S3_CLI_TICK_MS);
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

    /* the parked tail first: the window may have opened */

    if (s3_cli_outbox_len > 0) {
        s3_cli_outbox_flush();
    }

    /* the stdin ring into the data frames, one frame per tick keeps
     * the outbox bounded by the ring size */

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

    /* the pipe eof: the fin lets the remote shell see the eof (the
     * console stdin never reports one, the gate rides the real stdin
     * kind, not the requested session shape) */

    if (!s3_cli_fin_sent && !s3_cli_console) {

        EnterCriticalSection(&s3_cli_ring_cs);

        if (s3_cli_stdin_eof && s3_cli_outbox_len == 0) {
            LeaveCriticalSection(&s3_cli_ring_cs);

            if (s3_quic_shutdown_stream(s3_cli_chan, S3_WRITE_SHUTDOWN) == S3_OK) {
                s3_cli_fin_sent = 1;
            }

        } else {
            LeaveCriticalSection(&s3_cli_ring_cs);
        }
    }

    /* the resize: the geometry change rides the window-change request */

    if (s3_cli_tty) {

        uint64_t w = 0, h = 0;

        if (s3_cli_console_winsize(&w, &h) == S3_OK && w > 0 && h > 0 &&
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
    size_t                i, cmdlen;
    s3_str_t              alpn;
    u_char                alpn_wire[8];
    s3_fd_t               fd;
    s3_connection_t      *cli;
    s3_quic_connection_t *qc;
    struct addrinfo       hints, *res = NULL;
    WSADATA               wsd;

    if (WSAStartup(MAKEWORD(2, 2), &wsd) != 0) {
        fprintf(stderr, "ssh3: WSAStartup failed\n");
        return S3_CLI_EXIT_ERROR;
    }

    /* the stdout/stderr in the binary mode: the channel bytes are
     * opaque (the remote pty owns the line discipline) */

    (void)_setmode(1, _O_BINARY);
    (void)_setmode(2, _O_BINARY);

    s3_cli_log.fd = S3_INVALID_FILE;
    s3_cli_log.log_level = S3_LOG_WARN;

    while ((opt = getopt(argc, argv, "i:U:J:L:rvl:Vh")) != -1) {

        switch (opt) {

        case 'i':
            snprintf(s3_cli_keyfile, sizeof(s3_cli_keyfile), "%s", optarg);
            s3_cli_auth = S3_CLI_AUTH_PUBKEY;
            break;

        case 'U': {

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

            break;
        }

        case 'J': {

            const char *rest = optarg;
            const char *sep;
            size_t      len;

            if (strncmp(rest, "put:", 4) == 0) {
                s3_cli_sftp_mode = S3_CLI_SFTP_PUT;
                rest += 4;

            } else if (strncmp(rest, "get:", 4) == 0) {
                s3_cli_sftp_mode = S3_CLI_SFTP_GET;
                rest += 4;

            } else {
                fprintf(stderr, "ssh3: -J wants put|get:local:remote\n");
                return S3_CLI_EXIT_ERROR;
            }

            /* the local:remote split: a colon right behind the drive
             * letter rides the path, the next one ends the local
             * side (the remote is the unix path of the server) */

            sep = strchr(rest, ':');

            if (sep == rest + 1 &&
                ((rest[0] >= 'A' && rest[0] <= 'Z') || (rest[0] >= 'a' && rest[0] <= 'z'))) {
                sep = strchr(sep + 1, ':');
            }

            if (sep == NULL || sep == rest || sep[1] == '\0') {
                fprintf(stderr, "ssh3: -J wants put|get:local:remote\n");
                return S3_CLI_EXIT_ERROR;
            }

            len = (size_t)(sep - rest);
            s3_cli_sftp_local = malloc(len + 1);

            if (s3_cli_sftp_local == NULL) {
                fprintf(stderr, "ssh3: out of memory\n");
                return S3_CLI_EXIT_ERROR;
            }

            memcpy(s3_cli_sftp_local, rest, len);
            s3_cli_sftp_local[len] = '\0';

            len = strlen(sep + 1);
            s3_cli_sftp_remote = malloc(len + 1);

            if (s3_cli_sftp_remote == NULL) {
                fprintf(stderr, "ssh3: out of memory\n");
                return S3_CLI_EXIT_ERROR;
            }

            memcpy(s3_cli_sftp_remote, sep + 1, len + 1);

            break;
        }

        case 'L':

            if (s3_cli_fwd_parse(optarg) != S3_OK) {
                return S3_CLI_EXIT_ERROR;
            }

            break;

        case 'r':
            s3_cli_sftp_recursive = 1;
            break;

        case 'v':
            s3_cli_verbose = 1;
            s3_cli_log.log_level = S3_LOG_DEBUG_ALL;
            break;

        case 'l':
            s3_cli_log.log_level =
                (strcmp(optarg, "all") == 0) ? S3_LOG_DEBUG_ALL : (s3_uint_t)atol(optarg);
            break;

        case 'V':
            printf("ssh3 version %s\n", S3_SSH3_VERSION_STRING);
            WSACleanup();
            return 0;

        case 'h':
            s3_cli_usage(argv[0]);
            WSACleanup();
            return 0;

        default:
            s3_cli_usage(argv[0]);
            WSACleanup();
            return S3_CLI_EXIT_ERROR;
        }
    }

    if (optind >= argc) {
        s3_cli_usage(argv[0]);
        WSACleanup();
        return S3_CLI_EXIT_ERROR;
    }

    operand = argv[optind++];

    /* the operand: [user@]host[:port][/path], the defaults are the
     * 443 port and the /ssh3-term path (the Go fork parity) */

    at = strchr(operand, '@');

    if (at != NULL) {

        if ((size_t)(at - operand) >= sizeof(s3_cli_user)) {
            fprintf(stderr, "ssh3: the user name is too long\n");
            return S3_CLI_EXIT_ERROR;
        }

        memcpy(s3_cli_user, operand, (size_t)(at - operand));
        s3_cli_user[at - operand] = '\0';

        operand = (char *)at + 1;
    }

    slash = strchr(operand, '/');

    if (slash != NULL) {

        if (strlen(slash) >= sizeof(s3_cli_path)) {
            fprintf(stderr, "ssh3: the path is too long\n");
            return S3_CLI_EXIT_ERROR;
        }

        snprintf(s3_cli_path, sizeof(s3_cli_path), "%s", slash);
        colon = strchr(operand, ':');

        if (colon != NULL && colon < slash) {
            s3_cli_port = (unsigned)atoi(colon + 1);

            if (s3_cli_port == 0 || s3_cli_port > 65535 ||
                (size_t)(colon - operand) >= sizeof(s3_cli_host)) {
                fprintf(stderr, "ssh3: bad port in %s\n", argv[optind - 1]);
                return S3_CLI_EXIT_ERROR;
            }

            memcpy(s3_cli_host, operand, (size_t)(colon - operand));
            s3_cli_host[colon - operand] = '\0';

        } else {
            s3_cli_port = 443;

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
            s3_cli_port = (unsigned)atoi(colon + 1);

            if (s3_cli_port == 0 || s3_cli_port > 65535 ||
                (size_t)(colon - operand) >= sizeof(s3_cli_host)) {
                fprintf(stderr, "ssh3: bad port in %s\n", argv[optind - 1]);
                return S3_CLI_EXIT_ERROR;
            }

            memcpy(s3_cli_host, operand, (size_t)(colon - operand));
            s3_cli_host[colon - operand] = '\0';

        } else {

            s3_cli_port = 443;

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

    (void)s3_cli_tofu_prepare();

    /* the sftp transfer and the forwards carry no exec words */

    if ((s3_cli_sftp_mode || s3_cli_fwd_count) && optind < argc) {
        fprintf(stderr, "ssh3: -J and -L take no command\n");
        return S3_CLI_EXIT_ERROR;
    }

    if (s3_cli_sftp_mode && s3_cli_fwd_count) {
        fprintf(stderr, "ssh3: -J and -L do not ride one session\n");
        return S3_CLI_EXIT_ERROR;
    }

    /* the trailing words join into the exec command (the ssh shape) */

    if (optind < argc) {

        cmdlen = 1;

        for (i = optind; i < (size_t)argc; i++) {
            cmdlen += strlen(argv[i]) + 1;
        }

        s3_cli_cmd = malloc(cmdlen);

        if (s3_cli_cmd == NULL) {
            fprintf(stderr, "ssh3: out of memory\n");
            return S3_CLI_EXIT_ERROR;
        }

        s3_cli_cmd[0] = '\0';

        for (i = optind; i < (size_t)argc; i++) {

            if (i > (size_t)optind) {
                strncat(s3_cli_cmd, " ", cmdlen - strlen(s3_cli_cmd) - 1);
            }

            strncat(s3_cli_cmd, argv[i], cmdlen - strlen(s3_cli_cmd) - 1);
        }
    }

    /* the console detection rides the TOFU prompt and the session */

    s3_cli_console = _isatty(0) ? 1u : 0u;

    /* the resolution first: the literal or the name, AF_INET (the
     * QUIC listener of the server is a v4 socket in this port) */

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    if (getaddrinfo(s3_cli_host, NULL, &hints, &res) != 0 || res == NULL) {
        fprintf(stderr, "ssh3: cannot resolve %s\n", s3_cli_host);
        WSACleanup();
        return S3_CLI_EXIT_ERROR;
    }

    memcpy(&s3_cli_sa, res->ai_addr, sizeof(struct sockaddr_in));
    s3_cli_sa.sin_family = AF_INET;
    s3_cli_sa.sin_port = htons((u_short)s3_cli_port);

    freeaddrinfo(res);

    if (s3_event_ctx_init(&s3_cli_ctx, &s3_cli_log) != S3_OK) {
        fprintf(stderr, "ssh3: the event context failed\n");
        WSACleanup();
        return S3_CLI_EXIT_ERROR;
    }

    fd = (s3_fd_t)socket(AF_INET, SOCK_DGRAM, 0);

    if (fd == (s3_fd_t)INVALID_SOCKET) {
        fprintf(stderr, "ssh3: socket() failed\n");
        WSACleanup();
        return S3_CLI_EXIT_ERROR;
    }

    if (s3_nonblocking(fd) != S3_OK) {
        fprintf(stderr, "ssh3: the nonblocking mode failed\n");
        closesocket((SOCKET)fd);
        WSACleanup();
        return S3_CLI_EXIT_ERROR;
    }

    cli = s3_get_connection(&s3_cli_ctx, fd);

    if (cli == NULL) {
        fprintf(stderr, "ssh3: the connection alloc failed\n");
        closesocket((SOCKET)fd);
        WSACleanup();
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

    memcpy(cli->sockaddr, &s3_cli_sa, sizeof(s3_cli_sa));
    cli->socklen = sizeof(s3_cli_sa);

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

        qc = s3_quic_get_connection(cli);

        if (qc == NULL) {
            fprintf(stderr, "ssh3: the connection is gone\n");
            s3_cli_rc = S3_CLI_EXIT_ERROR;
            break;
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

        /* the 200 opens the session channel */

        if (s3_cli_status_seen && s3_cli_status == 200 && !s3_cli_fwd_count &&
            s3_cli_chan == NULL) {

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

        if (s3_cli_status_seen && s3_cli_status == 200 && !s3_cli_fwd_count && !s3_cli_ch_sent) {

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

            } else if (s3_cli_cmd != NULL) {

                /* the exec: the command with the reply wanted, the
                 * fin rides right behind it */

                s3_ssh3_request_t exec;

                memset(&exec, 0, sizeof(exec));

                exec.kind = S3_SSH3_REQ_EXEC;
                exec.u.exec.command.data = (u_char *)s3_cli_cmd;
                exec.u.exec.command.len = strlen(s3_cli_cmd);

                p = s3_cli_session_request(p, S3_SSH3_REQ_EXEC, 1, &exec);

            } else if (s3_cli_console) {

                /* the interactive shell: the pty with the real
                 * geometry, then the shell request */

                s3_ssh3_request_t pty, shell;

                memset(&pty, 0, sizeof(pty));

                pty.kind = S3_SSH3_REQ_PTY;
                pty.u.pty.term.data = (u_char *)"xterm-256color";
                pty.u.pty.term.len = strlen("xterm-256color");

                if (s3_cli_console_winsize(&s3_cli_win_w, &s3_cli_win_h) != S3_OK ||
                    s3_cli_win_w == 0 || s3_cli_win_h == 0) {
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

                memset(&shell, 0, sizeof(shell));
                shell.kind = S3_SSH3_REQ_SHELL;

                p = s3_cli_session_request(p, S3_SSH3_REQ_SHELL, 1, &shell);

                s3_cli_tty = 1;

            } else {

                /*
                 * the pipe shell: the pty-req with the default
                 * geometry announces the session intent anyway (the
                 * C server keeps a bare shell in the harness echo
                 * mode), the stdin pumps through the remote line
                 * discipline (the RequestTTY=force shape)
                 */

                s3_ssh3_request_t pty, shell;

                memset(&pty, 0, sizeof(pty));

                pty.kind = S3_SSH3_REQ_PTY;
                pty.u.pty.term.data = (u_char *)"xterm-256color";
                pty.u.pty.term.len = strlen("xterm-256color");
                pty.u.pty.width = 80;
                pty.u.pty.height = 24;
                pty.u.pty.pixel_width = 0;
                pty.u.pty.pixel_height = 0;
                pty.u.pty.modes.data = NULL;
                pty.u.pty.modes.len = 0;

                p = s3_cli_session_request(p, S3_SSH3_REQ_PTY, 1, &pty);

                memset(&shell, 0, sizeof(shell));
                shell.kind = S3_SSH3_REQ_SHELL;

                p = s3_cli_session_request(p, S3_SSH3_REQ_SHELL, 1, &shell);

                s3_cli_win_w = 80;
                s3_cli_win_h = 24;
                s3_cli_tty = 1;
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

    s3_cli_console_done();

    /* the -L listeners and the bridges close before the wire */

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
                    (void)s3_quic_shutdown_stream(src->chan, S3_RDWR_SHUTDOWN);
                    s3_close_connection(src->chan);
                    src->chan = NULL;
                }

                src->used = 0;
            }

            if (s3_cli_fwd_udp[k].used) {

                if (s3_cli_fwd_udp[k].evc != NULL) {
                    s3_close_connection(s3_cli_fwd_udp[k].evc);
                }

                if (s3_cli_fwd_udp[k].fd != INVALID_SOCKET && s3_cli_fwd_udp[k].fd != 0) {
                    closesocket(s3_cli_fwd_udp[k].fd);
                }

                s3_cli_fwd_udp[k].used = 0;
            }
        }
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

    s3_event_ctx_shutdown(&s3_cli_ctx);

    free(s3_cli_cmd);
    s3_cli_cmd = NULL;

    free(s3_cli_sftp_out);
    s3_cli_sftp_out = NULL;

    free(s3_cli_sftp_buf);
    s3_cli_sftp_buf = NULL;

    free(s3_cli_sftp_local);
    s3_cli_sftp_local = NULL;

    free(s3_cli_sftp_remote);
    s3_cli_sftp_remote = NULL;

    WSACleanup();
}

#else

/* the unix build keeps the client target out of the tree (P9 is the
 * win beachhead), the empty TU keeps the file listed in both CMake
 * branches harmless */

typedef int s3_cli_unix_placeholder_t;

#endif /* S3_WIN32 */
