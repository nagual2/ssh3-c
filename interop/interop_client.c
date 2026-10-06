/*
 * Copyright (C) 2026 the ssh3-c authors
 */

/*
 * the QUIC interop test client: dials a peer, completes the handshake
 * and either sends count datagrams of the requested size, verifying
 * the echoes byte for byte (-m sets a loss tolerance), or, with
 * -S, pumps count*size pattern bytes through a stream and verifies
 * the echo.  Peers: the quic-go harness (interop/quic-go) and, at P3,
 * the ssh3 server of the Go fork.
 *
 * the -3 switch switches to the h3 mode: after the handshake the h3
 * session comes up (SETTINGS on the control stream) and one bidi
 * stream carries the RFC 9220 extended CONNECT announcing ssh3; after
 * the 200 the next client bidi stream opens the ssh3 session channel
 * (the header, the shell request and the ping probe in one send), the
 * verdict is the echoed ping.
 *
 * with -C -S exec|pty|kill the session scenarios run instead of the
 * ping: exec sends "printf s3-exec-ok" with the fin right behind it and
 * reads the output plus the 98 exit-status; pty opens a pty at 80x24,
 * starts the shell, resizes to 100x40, probes the size with stty,
 * signals KILL once the resized geometry came back and waits for the
 * exit-status 137 (128 + SIGKILL); kill execs "sleep 30", keeps the
 * stream writable and signals KILL right after the 91 confirmation,
 * waiting for the same 137.
 *
 * -U user:pass switches the Authorization header to the Basic scheme
 * (RFC 7617, base64 of "user:pass" verbatim) instead of test-token.
 *
 * -F tcp=@port|udp=@port (with -3 -C) opens the direct-tcp or
 * direct-udp channel instead of the session one: the header carries
 * the target extension, the target is always 127.0.0.1@port on the
 * server side (the loopback echo services of the runner).  The tcp
 * run sends the "s3-fwd-hello" marker plus 64 KiB of the LCG pattern
 * as 94 and verifies the echo byte for byte; the udp run sends 20
 * numbered datagrams of 1024 bytes and verifies the echoes.
 *
 * -j jump-addr:port (with -3 -C) is the proxy jump: phase 1 dials the
 * jump host like a normal run and opens a direct-udp channel on its
 * conversation targeting the inner server (the -a argument); a
 * loopback udp socket pair bridges the channel to the inner quic
 * connection, so phase 2 is the byte-for-byte normal ssh3 run whose
 * datagrams happen to flow through the jump tunnel.  The inner
 * packets stay at 1200 bytes (the path mtu discovery is pinned), the
 * tunnel frames carry them with the two varints of the prefix on top,
 * so the jump peer must accept at least 1202 (-d 1352).  The verdict
 * is the inner scenario one plus INTEROP-PROXYJUMP-OK with the
 * tunnel datagram counters.
 *
 * stdout carries the machine-readable protocol of the runner:
 *   INTEROP-HANDSHAKE-OK
 *   INTEROP-DATAGRAM-OK sent=N recv=N
 *   INTEROP-STREAM-OK sent=N recv=N
 *   INTEROP-H3-STATUS <code>
 *   INTEROP-CHANNEL-OK len=<payload length>
 *   INTEROP-EXEC-OK exit=0 / INTEROP-EXEC-FAIL exit=<code>
 *   INTEROP-KILL-OK exit=137 / INTEROP-KILL-FAIL exit=<code>
 *   INTEROP-PTY-SIGNAL-OK exit=137 / INTEROP-PTY-SIGNAL-FAIL exit=<code>
 *   INTEROP-FWD-TCP-OK bytes=<n> / INTEROP-FWD-TCP-FAIL
 *   INTEROP-FWD-UDP-OK count=20 / INTEROP-FWD-UDP-FAIL got=<n>
 *   INTEROP-PROXYJUMP-OK inner-sent=<n> inner-recv=<n>
 * the exit code is 0 only when the mode's success line came back
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <time.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <s3_h3.h>
#include <s3_h3_uni.h>
#include <s3_nonblocking.h>

#include <s3_quic.h>
#include <s3_quic_connection.h>
#include <s3_quic_output.h>
#include <s3_quic_streams.h>
#include <s3_ssh3_agent.h>
#include <s3_ssh3_channel.h>
#include <s3_ssh3_cm.h>
#include <s3_ssh3_dgram.h>
#include <s3_ssh3_forward.h>
#include <s3_ssh3_message.h>
#include <s3_ssh3_oidc_client.h>
#include <s3_ssh3_request.h>
#include <s3_ssh3_sftp.h>
#include <s3_ssh3_sftp_cli.h>
#include <s3_ssh3_version.h>
#include <s3_ssh3_wire.h>
#include <s3_ssl.h>

/*
 * the channel maxPacketSize of the reference, 30000 on both sides
 * (docs/P4-WIRE.md 5)
 */
#define S3_INTEROP_CHANNEL_MAX_PACKET 30000

static s3_log_t s3_interop_log;

static u_char *s3_interop_expected;
static u_char *s3_interop_got;

static size_t s3_interop_count;
static size_t s3_interop_size;
static size_t s3_interop_received;

/* the stream echo state */
static u_char           s3_interop_sbuf[16384];
static size_t           s3_interop_stotal;
static size_t           s3_interop_ssent;
static size_t           s3_interop_srecv;
static unsigned         s3_interop_sfin;
static int              s3_interop_streams_mode;
static s3_connection_t *s3_interop_stream;

/*
 * the h3 state (-3): after the handshake the session comes up on the
 * parent connection and one bidi stream carries the RFC 9220 extended
 * CONNECT; the verdict is the response :status
 */
static int              s3_interop_h3_mode;
static s3_connection_t *s3_interop_h3_stream;
static unsigned         s3_interop_h3_req_sent;
static unsigned         s3_interop_h3_status_seen;
static unsigned         s3_interop_h3_status;

/*
 * the ssh3 session channel (-3 -C): opened right after the 200 on the
 * next client bidi stream (ChannelID == its StreamID), one send
 * carries the channel header, the shell request and the ping probe;
 * the verdict is the echoed ping.  The phase is opt-in: the quic-go
 * h3-server harness tears the connection down on any extra bidi
 * stream, so the plain -3 runs stay untouched
 */
static int              s3_interop_h3_channel_mode;
static s3_connection_t *s3_interop_h3_channel;
static unsigned         s3_interop_h3_ch_sent;
static unsigned         s3_interop_h3_ch_confirmed;
static unsigned         s3_interop_h3_ch_ok;

/*
 * the session scenarios (-3 -C -S exec|pty|kill): the channel carries
 * the request/response runs instead of the ping echo, no shell request
 * or ping goes out; the verdict comes with the 98 exit-status
 */
enum {
    S3_INTEROP_SESSION_NONE = 0,
    S3_INTEROP_SESSION_EXEC,
    S3_INTEROP_SESSION_PTY,
    S3_INTEROP_SESSION_KILL
};

static unsigned s3_interop_h3_session_mode;
static u_char  *s3_interop_h3_sess_out; /* the stdout accumulator */
static size_t   s3_interop_h3_sess_out_cap;
static size_t   s3_interop_h3_sess_out_len;
static unsigned s3_interop_h3_sess_signal_pending; /* the resized geometry came back */
static unsigned s3_interop_h3_sess_signal_sent;

/*
 * the forward modes (-3 -C -F tcp=@port|udp=@port): the channel is a
 * direct-tcp or direct-udp one, the target is always 127.0.0.1 on the
 * server side.  The tcp verdict is the byte-exact echo of the hello
 * plus the 64 KiB LCG pattern, the udp verdict is the echo of the 20
 * numbered datagrams
 */
#define S3_INTEROP_FWD_NONE 0
#define S3_INTEROP_FWD_TCP  1
#define S3_INTEROP_FWD_UDP  2

#define S3_INTEROP_FWD_UDP_COUNT 20
#define S3_INTEROP_FWD_UDP_SIZE  1024

/*
 * the frame buffer of the tcp run: one 94 frame carries up to the
 * maxPacketSize chunk, the type and length varints ride on top
 */
#define S3_INTEROP_FWD_FRAME 33000

static int      s3_interop_fwd_mode;
static unsigned s3_interop_fwd_port;

/* the ids of the opened forward channel and its conversation */
static uint64_t s3_interop_fwd_conv_id;
static uint64_t s3_interop_fwd_channel_id;

/* the tcp payload: the hello marker plus the pattern, compared byte
 * for byte as the echo comes back; the frame buffer holds the 94
 * frame in flight (a partial send parks its tail) */
static u_char  *s3_interop_fwd_payload;
static size_t   s3_interop_fwd_payload_len;
static size_t   s3_interop_fwd_sent;
static size_t   s3_interop_fwd_recv;
static u_char   s3_interop_fwd_frame[S3_INTEROP_FWD_FRAME];
static size_t   s3_interop_fwd_frame_sent;
static size_t   s3_interop_fwd_frame_total;
static unsigned s3_interop_fwd_fin_sent;

/* the udp round: the expected datagrams with the index in the head */
static u_char   s3_interop_fwd_udp_expected[S3_INTEROP_FWD_UDP_COUNT][S3_INTEROP_FWD_UDP_SIZE];
static unsigned s3_interop_fwd_udp_got[S3_INTEROP_FWD_UDP_COUNT];
static size_t   s3_interop_fwd_udp_recv;
static unsigned s3_interop_fwd_udp_sent;

/*
 * the agent forwarding (-3 -C -S exec -X): the forward-agent marker
 * rides the session burst before the exec, the server answers with
 * server-initiated "agent-connection" channels per accepted socket
 * and this side bridges them to the local SSH_AUTH_SOCK
 */
static int s3_interop_agent_mode;

/* the exec command override (-S exec -e cmd, the agent_probe runs) */
static const char *s3_interop_exec_cmd;

/*
 * the sftp transfer mode (-3 -J put:local:remote|get:local:remote):
 * the channel type is "sftp", the scp-style driver of s3_ssh3_sftp_cli
 * runs over the 94 payloads; the verdict is the driver state
 */
#define S3_INTEROP_SFTP_NONE 0
#define S3_INTEROP_SFTP_PUT  1
#define S3_INTEROP_SFTP_GET  2

static int                s3_interop_sftp_mode;
static const char        *s3_interop_sftp_local;
static const char        *s3_interop_sftp_remote;
static s3_pool_t         *s3_interop_sftp_pool;
static s3_ssh3_sftp_cli_t s3_interop_sftp_cli;
static unsigned           s3_interop_sftp_started;
static s3_event_t         s3_interop_sftp_timer;

/* the in-flight 94 frame of the cli driver direction (a partial send
 * parks its tail, the timer retries) */
static u_char s3_interop_sftp_frame[S3_INTEROP_FWD_FRAME];
static size_t s3_interop_sftp_frame_sent;
static size_t s3_interop_sftp_frame_total;

/* the receive accumulator of the sftp channel (the 91 and the 94) */
static u_char *s3_interop_sftp_buf;
static size_t  s3_interop_sftp_buf_cap;
static size_t  s3_interop_sftp_buf_len;

/*
 * the agent bridge: one accepted server-initiated channel rides a
 * local SSH_AUTH_SOCK connection, the 50 ms timer pumps the socket
 * side, the read handler pumps the stream side
 */
static s3_pool_t       *s3_interop_agent_pool;
static int              s3_interop_agent_fd = -1;
static s3_connection_t *s3_interop_agent_sc;
static unsigned         s3_interop_agent_hdr_len; /* the header accumulation */
static u_char           s3_interop_agent_hdr[128];
static u_char          *s3_interop_agent_in; /* the 94 payloads awaiting the fd */
static size_t           s3_interop_agent_in_cap;
static size_t           s3_interop_agent_in_len;
static u_char           s3_interop_agent_frame[S3_INTEROP_FWD_FRAME];
static size_t           s3_interop_agent_frame_sent;
static size_t           s3_interop_agent_frame_total;
static s3_event_t       s3_interop_agent_timer;

/*
 * the proxy jump (-j jump-addr:port): phase 1 dials the jump host and
 * opens the direct-udp channel to the inner server address (the -a
 * argument); a loopback udp socket pair bridges the channel to the
 * inner quic connection and phase 2 is the byte-for-byte normal
 * client run whose datagrams flow through the jump tunnel.  The
 * phases share one event loop, the jump conversation stays alive for
 * the whole run
 */
#define S3_INTEROP_JUMP_NONE   0
#define S3_INTEROP_JUMP_TUNNEL 1
#define S3_INTEROP_JUMP_INNER  2

/*
 * the inner quic packet cap: the tunnel datagram is the packet plus
 * the two varints of the prefix, so the jump peer must accept 1202
 * (-d 1352 is the harness number); the cap pins the inner path mtu
 * discovery the way the reference turns it off for the proxy jump
 */
#define S3_INTEROP_JUMP_INNER_MTU  1200
#define S3_INTEROP_JUMP_DGRAM_SIZE 1352
#define S3_INTEROP_JUMP_DGRAM_MIN  1202

static int                s3_interop_jump_phase;
static const char        *s3_interop_jump_text;
static struct sockaddr_in s3_interop_jump_sa;
static struct sockaddr_in s3_interop_inner_sa;

static s3_fd_t          s3_interop_jump_fd = -1;
static s3_connection_t *s3_interop_jump_cli;
static s3_quic_conf_t   s3_interop_jump_conf;
static s3_connection_t *s3_interop_jump_stream;  /* the CONNECT stream */
static s3_connection_t *s3_interop_jump_channel; /* the direct-udp one */
static uint64_t         s3_interop_jump_conv_id;
static uint64_t         s3_interop_jump_ch_id;
static unsigned         s3_interop_jump_req_sent;
static unsigned         s3_interop_jump_ch_sent;
static unsigned         s3_interop_jump_ch_confirmed;

/* the receive accumulator of the jump channel (the 91 confirmation) */
static u_char s3_interop_jump_ch_buf[64];
static size_t s3_interop_jump_ch_len;

/*
 * the loopback bridge: a is the inner quic fd, b is the tunnel side.
 * One parked datagram holds the backpressure, the read event sleeps
 * (del_event) until the channel drains; the buffers are static, the
 * hot path pays no allocation
 */
static s3_fd_t            s3_interop_bridge_a = -1;
static s3_fd_t            s3_interop_bridge_b = -1;
static s3_connection_t   *s3_interop_bridge_bc;
static struct sockaddr_in s3_interop_bridge_sa; /* the b address, the inner peer */
static u_char             s3_interop_bridge_frame[2048];
static size_t             s3_interop_bridge_parked;

/* the tunnel traffic counters of the verdict */
static unsigned long long s3_interop_jump_sent; /* b -> the channel */
static unsigned long long s3_interop_jump_recv; /* the channel -> b */

/*
 * the Authorization field: test-token by default, "Basic <b64>" with
 * -U (the static buffer is filled once at the option parse)
 */
static const char *s3_interop_h3_auth_value = "test-token";
static char        s3_interop_h3_basic[512];

/*
 * the OIDC mode (--oidc-issuer): the Bearer id_token replaces the
 * auth value once the flow answers (the reference OidcAuthMethod);
 * --oidc-token pins a raw token (the test negatives), the browser
 * spawn stops under S3_OIDC_NO_BROWSER=1
 */
static const char *s3_interop_oidc_issuer;
static const char *s3_interop_oidc_audience;
static const char *s3_interop_oidc_raw;
static char        s3_interop_oidc_bearer[256 + S3_SSH3_OIDC_CLI_TOKEN_MAX];

/*
 * the pubkey mode (-K privkey.pem): the client signs the Bearer JWT
 * itself and the CONNECT rides it instead of test-token.  The claim
 * set follows the reference BuildJWTBearerToken() (client_auth.go):
 * iss = the -U username, iat = now, exp = now + 10, sub = "ssh3",
 * aud = "unused", client_id = "ssh3-<user>", jti = the standard
 * base64 of the 32 EXPORTER-SSH3 exporter bytes (the conversation
 * id).  The key file is PEM (PKCS#8/PKCS#1/SEC1, the openssl
 * genpkey shape; the OpenSSH container format stays with the Go
 * client), the algorithm follows the key type: EdDSA (ed25519),
 * ES256 (P-256) or RS256 (RSA) — the server verifier allowlist.
 * The -K name mirrors the server side: the authorized_keys there,
 * the signing identity here
 */
static const char *s3_interop_pubkey_path;
static char        s3_interop_h3_bearer[2048];

/* the -U value, the identity of every auth mode (the Basic
 * user:pass, the pubkey username, the cm socket path) */
static const char *s3_interop_u_raw;

/* the std base64 lives below, the JWT jti borrows it */
static void s3_interop_base64(const u_char *src, size_t len, char *dst);

/*
 * the expired-exp negative (S3_JWT_EXP_PAST=<seconds>): the env
 * shifts exp into the past, the server verifier declines with 401
 */
#define S3_INTEROP_JWT_EXP_FRESH 10

/* the ES256 signature is the raw r||s pair, 32 bytes each */
#define S3_INTEROP_ES256_HALF 32

/*
 * the flow of the reference auth/oidc/openid_connect.go Connect():
 * the conversation nonce derives from the live TLS session (the
 * reference ConversationID), the loopback listener takes the
 * redirect, the code exchanges under PKCE, the id_token verifies
 * locally before it rides the CONNECT
 */

static int
s3_interop_oidc_acquire(SSL *ssl)
{
    char                    nonce[64], code[S3_SSH3_OIDC_CLI_CODE_MAX];
    char                    token[S3_SSH3_OIDC_CLI_TOKEN_MAX];
    const char             *ca_file, *no_browser;
    s3_ssh3_oidc_provider_t prov;
    s3_ssh3_oidc_flow_t     flow;
    int                     rc;

    if (s3_interop_oidc_raw != NULL) {

        /* the test negatives: the token rides as-is */

        snprintf(s3_interop_oidc_bearer, sizeof(s3_interop_oidc_bearer), "Bearer %s",
                 s3_interop_oidc_raw);
        s3_interop_h3_auth_value = s3_interop_oidc_bearer;

        return S3_OK;
    }

    if (s3_interop_oidc_issuer == NULL || s3_interop_oidc_audience == NULL || ssl == NULL) {
        return S3_ERROR;
    }

    if (s3_ssh3_oidc_conversation_nonce(ssl, nonce) != S3_OK) {
        fprintf(stderr, "interop-client: oidc: no conversation nonce\n");
        return S3_ERROR;
    }

    ca_file = getenv("S3_OIDC_CA_FILE");

    if (s3_ssh3_oidc_discover(s3_interop_oidc_issuer, ca_file, &prov) != S3_OK) {
        fprintf(stderr, "interop-client: oidc: discovery failed\n");
        return S3_ERROR;
    }

    if (s3_ssh3_oidc_flow_init(&flow, prov.authorization_endpoint, s3_interop_oidc_audience,
                               nonce) != S3_OK) {
        fprintf(stderr, "interop-client: oidc: flow init failed\n");
        return S3_ERROR;
    }

    printf("OIDC-AUTHORIZE-URL: %s\n", flow.authorize_url);
    fflush(stdout);

    no_browser = getenv("S3_OIDC_NO_BROWSER");

    if (no_browser == NULL) {

        /* the reference spawns the platform browser (xdg-open on
         * linux), the failure is fatal like the reference */

        pid_t pid = fork();

        if (pid == 0) {
            execlp("xdg-open", "xdg-open", flow.authorize_url, (char *)NULL);
            _exit(127);
        }

        if (pid < 0) {
            fprintf(stderr, "interop-client: oidc: browser spawn failed\n");
            return S3_ERROR;
        }
    }

    if (s3_ssh3_oidc_flow_wait_code(&flow, code, sizeof(code)) != S3_OK) {
        fprintf(stderr, "interop-client: oidc: no redirect code\n");
        return S3_ERROR;
    }

    rc = s3_ssh3_oidc_client_token(s3_interop_oidc_issuer, s3_interop_oidc_audience, ca_file, &flow,
                                   code, token, sizeof(token));

    if (rc != S3_OK) {
        fprintf(stderr, "interop-client: oidc: token exchange/verify failed rc=%d\n", (int)rc);
        return S3_ERROR;
    }

    snprintf(s3_interop_oidc_bearer, sizeof(s3_interop_oidc_bearer), "Bearer %s", token);
    s3_interop_h3_auth_value = s3_interop_oidc_bearer;

    return S3_OK;
}

/*
 * the base64url of RFC 4648 without the padding: the JWT segment
 * shape (RFC 7515), the server decoder accepts both alphabets
 */
static void
s3_interop_b64url(const u_char *src, size_t len, char *dst)
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

        /* the unpadded tail of RFC 4648: one byte keeps two chars */

        dst[o++] = tab[(v >> 18) & 0x3f];
        dst[o++] = tab[(v >> 12) & 0x3f];

    } else if (len - i == 2) {
        unsigned v = ((unsigned)src[i] << 16) | ((unsigned)src[i + 1] << 8);

        /* two bytes keep three chars */

        dst[o++] = tab[(v >> 18) & 0x3f];
        dst[o++] = tab[(v >> 12) & 0x3f];
        dst[o++] = tab[(v >> 6) & 0x3f];
    }

    dst[o] = '\0';
}

/*
 * the signature over the signing input, the key type decides the
 * shape: the ed25519 signs PureEdDSA one-shot, the P-256 signs
 * ECDSA-SHA256 into the raw r||s pair the server verifier expects
 * (no DER wrapper), the RSA signs RSASSA-PKCS1-v1_5-SHA256
 */
static s3_int_t
s3_interop_jwt_sign(EVP_PKEY *key, const char *alg, const u_char *msg, size_t msglen, u_char *sig,
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

        if (BN_bn2binpad(r, sig, S3_INTEROP_ES256_HALF) != S3_INTEROP_ES256_HALF ||
            BN_bn2binpad(s, sig + S3_INTEROP_ES256_HALF, S3_INTEROP_ES256_HALF) !=
                S3_INTEROP_ES256_HALF) {
            ECDSA_SIG_free(ec);
            goto done;
        }

        ECDSA_SIG_free(ec);
        *siglen = 2 * S3_INTEROP_ES256_HALF;
    }

    rc = S3_OK;

done:

    EVP_MD_CTX_free(md);

    return rc;
}

/*
 * the Bearer JWT of the pubkey mode, built once after the handshake
 * (the jti binds the live TLS exporter) and before the CONNECT: the
 * key loads from the -K PEM file, the algorithm follows the key
 * type, the claim set is the reference one (see the -K statics).
 * The verdict rides s3_interop_h3_auth_value like the Basic and the
 * OIDC modes
 */
static int
s3_interop_pubkey_jwt(SSL *ssl)
{
    static const char label[] = "EXPORTER-SSH3";

    char        header[64], payload[512], seg[1024], jti[64], tok[1200];
    u_char      conv[32], sig[1024];
    BIO        *bio;
    EVP_PKEY   *key = NULL;
    const char *alg, *skew;
    long long   iat, exp;
    long        past = 0;
    size_t      hlen, plen, tlen, siglen;
    size_t      i, ulen;

    bio = BIO_new_file(s3_interop_pubkey_path, "r");

    if (bio == NULL) {
        fprintf(stderr, "interop-client: pubkey jwt: cannot open %s\n", s3_interop_pubkey_path);
        return S3_ERROR;
    }

    key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (key == NULL) {
        fprintf(stderr, "interop-client: pubkey jwt: %s is not a PEM private key\n",
                s3_interop_pubkey_path);
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
            fprintf(stderr, "interop-client: pubkey jwt: the EC key wants P-256\n");
            EVP_PKEY_free(key);
            return S3_ERROR;
        }
    }

        alg = "ES256";
        break;

    default:
        fprintf(stderr, "interop-client: pubkey jwt: unsupported key type\n");
        EVP_PKEY_free(key);
        return S3_ERROR;
    }

    if ((size_t)EVP_PKEY_get_size(key) > sizeof(sig)) {
        fprintf(stderr, "interop-client: pubkey jwt: the key is too large\n");
        EVP_PKEY_free(key);
        return S3_ERROR;
    }

    ulen = strlen(s3_interop_u_raw);

    for (i = 0; i < ulen; i++) {

        u_char ch = (u_char)s3_interop_u_raw[i];

        /* the JSON-safe username: the claim set embeds it verbatim */

        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
              ch == '.' || ch == '_' || ch == '@' || ch == '-')) {
            fprintf(stderr, "interop-client: pubkey jwt: bad username byte %c\n", ch);
            EVP_PKEY_free(key);
            return S3_ERROR;
        }
    }

    if (ssl == NULL || SSL_export_keying_material(ssl, conv, sizeof(conv), label, sizeof(label) - 1,
                                                  NULL, 0, 0) != 1) {
        fprintf(stderr, "interop-client: pubkey jwt: exporter failed\n");
        EVP_PKEY_free(key);
        return S3_ERROR;
    }

    /* the jti of the reference: base64.StdEncoding of the conv id */

    s3_interop_base64(conv, sizeof(conv), jti);

    skew = getenv("S3_JWT_EXP_PAST");

    if (skew != NULL && atol(skew) > 0) {
        past = atol(skew);
    }

    iat = (long long)time(NULL);
    exp = iat + S3_INTEROP_JWT_EXP_FRESH - past;

    hlen = (size_t)snprintf(header, sizeof(header), "{\"alg\":\"%s\",\"typ\":\"JWT\"}", alg);
    plen = (size_t)snprintf(payload, sizeof(payload),
                            "{\"iss\":\"%s\",\"iat\":%lld,\"exp\":%lld,\"sub\":\"ssh3\","
                            "\"aud\":\"unused\",\"client_id\":\"ssh3-%s\",\"jti\":\"%s\"}",
                            s3_interop_u_raw, iat, exp, s3_interop_u_raw, jti);

    if (hlen >= sizeof(header) || plen >= sizeof(payload)) {
        fprintf(stderr, "interop-client: pubkey jwt: claim buffers overflow\n");
        EVP_PKEY_free(key);
        return S3_ERROR;
    }

    /* the signing input: the two url segments joined by the dot */

    s3_interop_b64url((const u_char *)header, hlen, seg);
    tlen = strlen(seg);
    seg[tlen++] = '.';

    s3_interop_b64url((const u_char *)payload, plen, seg + tlen);
    tlen += strlen(seg + tlen);

    siglen = sizeof(sig);

    if (s3_interop_jwt_sign(key, alg, (const u_char *)seg, tlen, sig, &siglen) != S3_OK) {
        fprintf(stderr, "interop-client: pubkey jwt: signing failed (%s)\n", alg);
        EVP_PKEY_free(key);
        return S3_ERROR;
    }

    EVP_PKEY_free(key);

    if (tlen + 1 + siglen * 4 / 3 + 4 >= sizeof(tok)) {
        fprintf(stderr, "interop-client: pubkey jwt: token buffer overflow\n");
        return S3_ERROR;
    }

    s3_memcpy((u_char *)tok, seg, tlen);
    tok[tlen++] = '.';
    s3_interop_b64url(sig, siglen, tok + tlen);

    /* the token dump for the e2e debugging, S3SFTPDBG style */

    if (getenv("S3_JWTDBG") != NULL) {
        fprintf(stderr, "jwtdbg alg=%s %s\n", alg, tok);
    }

    snprintf(s3_interop_h3_bearer, sizeof(s3_interop_h3_bearer), "Bearer %s", tok);
    s3_interop_h3_auth_value = s3_interop_h3_bearer;

    return S3_OK;
}

/*
 * the CONNECT target: "/ssh3-term" by default, the -U user rides in
 * the query (the reference auth chain takes the username from there,
 * docs/P4-WIRE.md 7 step 3)
 */
static const char *s3_interop_h3_path_value = "/ssh3-term";
static char        s3_interop_h3_path_buf[512];

/*
 * the username into the CONNECT target (?user=): the reference auth
 * chain takes the session username from there (docs/P4-WIRE.md 7
 * step 3); the Basic and the pubkey modes share the builder
 */
static s3_int_t
s3_interop_h3_path_user(const char *user)
{
    size_t ul = strlen(user);

    if (ul > sizeof(s3_interop_h3_path_buf) - sizeof("/ssh3-term?user=")) {
        fprintf(stderr, "interop-client: -U user too long\n");
        return S3_ERROR;
    }

    memcpy(s3_interop_h3_path_buf, "/ssh3-term?user=", sizeof("/ssh3-term?user=") - 1);
    memcpy(s3_interop_h3_path_buf + sizeof("/ssh3-term?user=") - 1, user, ul);
    s3_interop_h3_path_buf[sizeof("/ssh3-term?user=") - 1 + ul] = '\0';

    s3_interop_h3_path_value = s3_interop_h3_path_buf;

    return S3_OK;
}

static s3_h3_parse_headers_t s3_interop_h3_parse;
static u_char               *s3_interop_h3_buf;
static size_t                s3_interop_h3_cap;
static size_t                s3_interop_h3_len;

/* the receive accumulator of the session channel */
static u_char *s3_interop_h3_ch_buf;
static size_t  s3_interop_h3_ch_cap;
static size_t  s3_interop_h3_ch_len;

/*
 * the offline selftest (-T, TEMPORARY for the wave-B bridge, removed
 * after the uni port lands): encodes the request section and the
 * 200-status section, round-trips both through s3_h3_parse_headers
 * with a zeroed session and prints the hex for the byte-exact script
 * check; no network is touched
 */
static int s3_interop_h3_selftest_mode;

/*
 * the deterministic pattern: a constant 64-byte template with the
 * block offset in the first eight bytes; the writer fills whole
 * blocks with memcpy, the verifier compares them the same way, so
 * neither side pays per-byte arithmetic (the first profile showed
 * the per-byte generator eating 99% of the client cpu)
 */

static u_char s3_interop_ptemplate[64];

static void
s3_interop_pattern_init(void)
{
    size_t i;

    for (i = 0; i < sizeof(s3_interop_ptemplate); i++) {
        s3_interop_ptemplate[i] = (u_char)(i * 31 + 7);
    }
}

static void
s3_interop_log_init(void)
{
    s3_interop_log.log_level = S3_LOG_INFO;
    s3_interop_log.fd = S3_INVALID_FILE;
}

static void
s3_interop_le32(u_char *p, uint32_t v)
{
    p[0] = (u_char)(v & 0xff);
    p[1] = (u_char)((v >> 8) & 0xff);
    p[2] = (u_char)((v >> 16) & 0xff);
    p[3] = (u_char)((v >> 24) & 0xff);
}

static uint32_t
s3_interop_read_le32(const u_char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/*
 * the deterministic payload of the forward runs: a 64-bit LCG with a
 * fixed seed, the verifier holds its own copy (the echo services
 * return everything unchanged, no shared state is needed)
 */
static uint64_t s3_interop_lcg_state = 0x853c49e6748fea9bULL;

static u_char
s3_interop_lcg_byte(void)
{
    s3_interop_lcg_state = s3_interop_lcg_state * 6364136223846793005ULL + 1442695040888963407ULL;

    return (u_char)(s3_interop_lcg_state >> 33);
}

static void
s3_interop_fwd_payload_init(void)
{
    static const char hello[] = "s3-fwd-hello";
    size_t            i, hello_len = sizeof(hello) - 1;

    s3_interop_fwd_payload_len = hello_len + 65536;
    s3_interop_fwd_payload = malloc(s3_interop_fwd_payload_len);

    if (s3_interop_fwd_payload == NULL) {
        fprintf(stderr, "interop-client: forward payload alloc failed\n");
        exit(1);
    }

    s3_memcpy(s3_interop_fwd_payload, hello, hello_len);

    for (i = hello_len; i < s3_interop_fwd_payload_len; i++) {
        s3_interop_fwd_payload[i] = s3_interop_lcg_byte();
    }
}

static void
s3_interop_fwd_udp_init(void)
{
    unsigned i;

    for (i = 0; i < S3_INTEROP_FWD_UDP_COUNT; i++) {

        size_t j;

        s3_interop_le32(s3_interop_fwd_udp_expected[i], i);

        for (j = 4; j < S3_INTEROP_FWD_UDP_SIZE; j++) {
            s3_interop_fwd_udp_expected[i][j] = s3_interop_lcg_byte();
        }
    }
}

/*
 * the udp forward verifier (-F udp=@port): the echo datagrams carry
 * the same prefix (docs/P4-WIRE.md 3.2), the index opens the payload,
 * the verdict is the count of the byte-exact echoes
 */
static void
s3_interop_fwd_udp_datagram(s3_chain_t *data)
{
    u_char        flat[S3_INTEROP_FWD_UDP_SIZE + 16];
    u_char       *p;
    size_t        len = 0;
    s3_chain_t   *cl;
    const u_char *pos, *end;
    uint64_t      csid, chid;
    s3_str_t      payload;
    uint32_t      idx;

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

    if (csid != s3_interop_fwd_conv_id || chid != s3_interop_fwd_channel_id) {
        return;
    }

    if (payload.len != S3_INTEROP_FWD_UDP_SIZE) {
        return;
    }

    idx = s3_interop_read_le32(payload.data);

    if (idx >= S3_INTEROP_FWD_UDP_COUNT || s3_interop_fwd_udp_got[idx]) {
        return;
    }

    if (s3_memcmp(payload.data, s3_interop_fwd_udp_expected[idx], S3_INTEROP_FWD_UDP_SIZE) != 0) {
        fprintf(stderr, "interop-client: forward udp mismatch at %u\n", idx);
        printf("INTEROP-FWD-UDP-FAIL got=%zu\n", s3_interop_fwd_udp_recv);
        fflush(stdout);
        exit(1);
    }

    s3_interop_fwd_udp_got[idx] = 1;

    if (++s3_interop_fwd_udp_recv == S3_INTEROP_FWD_UDP_COUNT) {

        printf("INTEROP-FWD-UDP-OK count=%u\n", (unsigned)S3_INTEROP_FWD_UDP_COUNT);
        fflush(stdout);

        s3_interop_h3_ch_ok = 1;
    }
}

static void
s3_interop_client_datagram(s3_connection_t *c, s3_chain_t *data)
{
    u_char     *exp;
    uint32_t    idx;
    size_t      len, n;
    s3_chain_t *cl;

    if (s3_interop_fwd_mode == S3_INTEROP_FWD_UDP) {
        s3_interop_fwd_udp_datagram(data);
        return;
    }

    (void)c;

    len = 0;

    for (cl = data; cl != NULL; cl = cl->next) {
        len += s3_buf_size(cl->buf);
    }

    if (len < 4 || len != s3_interop_size) {
        return;
    }

    /* the index is the first four payload bytes, they open the chain */

    if (s3_buf_size(data->buf) < 4) {
        return;
    }

    idx = s3_interop_read_le32(data->buf->pos);

    if (idx >= s3_interop_count || s3_interop_got[idx]) {
        return;
    }

    /* compare link by link: no flattened copy of the payload needed */

    exp = s3_interop_expected + idx * s3_interop_size;

    for (cl = data; cl != NULL; cl = cl->next) {
        n = s3_buf_size(cl->buf);

        if (s3_memcmp(cl->buf->pos, exp, n) != 0) {
            return;
        }

        exp += n;
    }

    s3_interop_got[idx] = 1;
    s3_interop_received++;
}

/*
 * the -W stall: sleeping here shrinks the receive window the way a busy
 * machine does, which is the wedge ingredient the deadlock repro needs.
 * Set at runtime so the repro script drives it with a flag instead of
 * patching this file.
 */
static unsigned s3_interop_stall_usec;

/*
 * the stream echo verifier: the pattern is a function of the absolute
 * offset, so the reading side checks without sharing state with the
 * writer
 */
static void
s3_interop_stream_echo_read(s3_event_t *ev)
{
    s3_connection_t *sc;
    size_t           n;
    ssize_t          m;

    sc = ev->data;

    if (s3_interop_stall_usec) {
        struct timespec ts;

        ts.tv_sec = s3_interop_stall_usec / 1000000;
        ts.tv_nsec = (s3_interop_stall_usec % 1000000) * 1000;
        nanosleep(&ts, NULL);
    }

    for (;;) {

        m = sc->recv(sc, s3_interop_sbuf, sizeof(s3_interop_sbuf));

        if (m == (ssize_t)S3_AGAIN) {
            return;
        }

        if (m == 0) {
            /* the server fin: the echo is complete */
            s3_interop_sfin = 1;
            return;
        }

        if (m < 0) {
            s3_quic_stream_t *qs = sc->data;

            /* after the teardown the queued read events may arrive */
            if (s3_interop_srecv == s3_interop_stotal) {
                return;
            }

            fprintf(stderr,
                    "interop-client: stream recv error state=%d recv_offset=%llu recv_last=%llu "
                    "recv_final_size=%llu\n",
                    qs->recv_state, (unsigned long long)qs->recv_offset,
                    (unsigned long long)qs->recv_last, (unsigned long long)qs->recv_final_size);
            exit(1);
        }

        if (s3_interop_srecv + (size_t)m > s3_interop_stotal) {
            fprintf(stderr, "interop-client: stream echo overflow\n");
            exit(1);
        }

        for (n = 0; n < (size_t)m;) {
            size_t pos = s3_interop_srecv + n;
            size_t bstart = pos & ~(size_t)(sizeof(s3_interop_ptemplate) - 1);
            size_t r = pos - bstart;
            size_t k = sizeof(s3_interop_ptemplate) - r;
            u_char exp[sizeof(s3_interop_ptemplate)];

            if (k > (size_t)m - n) {
                k = (size_t)m - n;
            }

            /*
             * the expected block is the template with the first eight
             * bytes replaced by the little-endian block offset
             */

            s3_memcpy(exp, s3_interop_ptemplate, sizeof(exp));
            s3_memcpy(exp, &bstart, sizeof(bstart));

            if (s3_memcmp(s3_interop_sbuf + n, exp + r, k) != 0) {
                fprintf(stderr,
                        "DBG r=%zu k=%zu got %02x %02x %02x %02x want %02x %02x %02x %02x\n", r, k,
                        s3_interop_sbuf[n], s3_interop_sbuf[n + 1], s3_interop_sbuf[n + 2],
                        s3_interop_sbuf[n + 3], exp[r], exp[r + 1], exp[r + 2], exp[r + 3]);
                fprintf(stderr, "interop-client: stream mismatch at offset %zu\n", pos);
                exit(1);
            }

            n += k;
        }

        s3_interop_srecv += (size_t)m;
    }
}

/*
 * the standard base64 of RFC 4648 with padding; the Basic scheme of
 * RFC 7617 encodes "user:pass" verbatim (the colon included)
 */
static void
s3_interop_base64(const u_char *src, size_t len, char *dst)
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

/*
 * the h3 side (-3): the extended CONNECT request section is a zero
 * prefix plus six literal field lines, so it decodes against any
 * peer QPACK state and never references the dynamic table.  RFC 9114
 * 4.4 / RFC 9220: the extended CONNECT carries :scheme and
 * :authority next to :method, :protocol and :path
 */

static uintptr_t
s3_interop_h3_field_l(u_char *p, const char *name, const char *value)
{
    s3_str_t n, v;

    n.data = (u_char *)name;
    n.len = strlen(name);
    v.data = (u_char *)value;
    v.len = strlen(value);

    return s3_h3_encode_field_l(p, &n, &v);
}

static size_t
s3_interop_h3_request_section(u_char *p)
{
    u_char *start = p;
    size_t  n;

    if (p == NULL) {
        n = (size_t)s3_h3_encode_field_section_prefix(NULL, 0, 0, 0);
        n += (size_t)s3_interop_h3_field_l(NULL, ":method", "CONNECT");
        n += (size_t)s3_interop_h3_field_l(NULL, ":protocol", "ssh3");
        n += (size_t)s3_interop_h3_field_l(NULL, ":scheme", "https");
        n += (size_t)s3_interop_h3_field_l(NULL, ":authority", "example.lan");
        n += (size_t)s3_interop_h3_field_l(NULL, ":path", s3_interop_h3_path_value);
        n += (size_t)s3_interop_h3_field_l(NULL, "user-agent", S3_SSH3_VERSION_STRING);
        n += (size_t)s3_interop_h3_field_l(NULL, "authorization", s3_interop_h3_auth_value);
        return n;
    }

    p = (u_char *)s3_h3_encode_field_section_prefix(p, 0, 0, 0);
    p = (u_char *)s3_interop_h3_field_l(p, ":method", "CONNECT");
    p = (u_char *)s3_interop_h3_field_l(p, ":protocol", "ssh3");
    p = (u_char *)s3_interop_h3_field_l(p, ":scheme", "https");
    p = (u_char *)s3_interop_h3_field_l(p, ":authority", "example.lan");
    p = (u_char *)s3_interop_h3_field_l(p, ":path", s3_interop_h3_path_value);
    p = (u_char *)s3_interop_h3_field_l(p, "user-agent", S3_SSH3_VERSION_STRING);
    p = (u_char *)s3_interop_h3_field_l(p, "authorization", s3_interop_h3_auth_value);

    return (size_t)(p - start);
}

static s3_uint_t
s3_interop_h3_name_is(s3_str_t *name, const char *text, size_t len)
{
    return name->len == len && s3_memcmp(name->data, text, len) == 0;
}

static void
s3_interop_h3_hexdump(const char *tag, const u_char *p, size_t n)
{
    size_t i;

    printf("%s", tag);

    for (i = 0; i < n; i++) {
        printf("%02x", p[i]);
    }

    printf("\n");
}

/*
 * TEMPORARY (-T, removed after the uni port lands): the offline
 * encode/decode proof against the uni stubs.  The request section and
 * the 200-status section round-trip through s3_h3_parse_headers with a
 * zeroed session (the static-table references need no table state) and
 * the script compares the printed hex byte for byte
 */
static int
s3_interop_h3_selftest(void)
{
    static const struct {
        const char *name, *value;
    } want[7] = {{":method", "CONNECT"},         {":protocol", "ssh3"},
                 {":scheme", "https"},           {":authority", "example.lan"},
                 {":path", "/ssh3-term"},        {"user-agent", S3_SSH3_VERSION_STRING},
                 {"authorization", "test-token"}};

    s3_log_t              log = {0, S3_INVALID_FILE};
    s3_connection_t       c;
    s3_h3_session_t       h3c;
    s3_pool_t            *pool;
    s3_h3_parse_headers_t st;
    s3_h3_parse_field_t   rep[8];
    s3_buf_t              b;
    u_char                frame[512], resp[64], *p;
    size_t                sec_len, resp_len, total, i;
    s3_uint_t             nrep;
    s3_int_t              rc;

    pool = s3_create_pool((size_t)S3_DEFAULT_POOL_SIZE, &log);
    if (pool == NULL) {
        return 1;
    }

    /* the zeroed session: the static-table lookups need no table state */
    s3_memzero(&c, sizeof(s3_connection_t));
    s3_memzero(&h3c, sizeof(s3_h3_session_t));

    c.log = &log;
    c.pool = pool;
    c.data = &h3c;

    /* the request frame: HEADERS(type 0x01) + the literal section */

    sec_len = s3_interop_h3_request_section(NULL);

    p = frame;
    p = (u_char *)s3_h3_encode_varlen_int(p, S3_H3_FRAME_HEADERS);
    p = (u_char *)s3_h3_encode_varlen_int(p, sec_len);

    /* the section builder returns the length, the base stays in p */
    sec_len = (size_t)s3_interop_h3_request_section(p);
    total = (size_t)(p - frame) + sec_len;

    s3_interop_h3_hexdump("SELFTEST-REQ-HEX ", frame + total - sec_len, sec_len);

    b.pos = frame;
    b.last = frame + total;

    s3_memzero(&st, sizeof(s3_h3_parse_headers_t));

    nrep = 0;

    for (;;) {

        rc = s3_h3_parse_headers(&c, &st, &b);

        if (rc == S3_OK) {

            if (nrep >= 8) {
                fprintf(stderr, "selftest: too many request field lines\n");
                return 1;
            }

            rep[nrep++] = st.field_rep.field;
            continue;
        }

        if (rc == S3_DONE) {

            if (nrep >= 8) {
                fprintf(stderr, "selftest: too many request field lines\n");
                return 1;
            }

            rep[nrep++] = st.field_rep.field;
            break;
        }

        fprintf(stderr, "selftest: request section parse error %d\n", (int)rc);
        return 1;
    }

    if (nrep != 7) {
        fprintf(stderr, "selftest: request section has %u field lines, want 7\n", (unsigned)nrep);
        return 1;
    }

    for (i = 0; i < 7; i++) {

        if (rep[i].name.len != strlen(want[i].name) ||
            s3_memcmp(rep[i].name.data, want[i].name, rep[i].name.len) != 0 ||
            rep[i].value.len != strlen(want[i].value) ||
            s3_memcmp(rep[i].value.data, want[i].value, rep[i].value.len) != 0) {
            fprintf(stderr, "selftest: request field %zu mismatch\n", i);
            return 1;
        }
    }

    printf("SELFTEST-REQ-FIELDS :method=CONNECT :protocol=ssh3 :scheme=https"
           " :authority=example.lan :path=/ssh3-term user-agent=%s"
           " authorization=test-token\n",
           S3_SSH3_VERSION_STRING);

    /* the status frame: HEADERS(0x01) + the zero prefix + the static :status: 200 */

    p = resp;
    p = (u_char *)s3_h3_encode_field_section_prefix(p, 0, 0, 0);

    /* RFC 9204 static table: 25 = ":status: 200" */
    p = (u_char *)s3_h3_encode_field_ri(p, 0, 25);
    resp_len = p - resp;

    s3_interop_h3_hexdump("SELFTEST-RESP-HEX ", resp, resp_len);

    frame[0] = (u_char)S3_H3_FRAME_HEADERS;
    frame[1] = (u_char)resp_len;
    s3_memcpy(frame + 2, resp, resp_len);

    b.pos = frame;
    b.last = frame + 2 + resp_len;

    s3_memzero(&st, sizeof(s3_h3_parse_headers_t));

    rc = s3_h3_parse_headers(&c, &st, &b);

    /*
     * a one-field section carries its only field line with the
     * S3_DONE (the section end), the parser holds it in field_rep
     */

    if (rc != S3_OK && rc != S3_DONE) {
        fprintf(stderr, "selftest: status section parse error %d\n", (int)rc);
        s3_destroy_pool(pool);
        return 1;
    }

    if (!s3_interop_h3_name_is(&st.field_rep.field.name, ":status", 7) ||
        st.field_rep.field.value.len != 3 ||
        s3_memcmp(st.field_rep.field.value.data, "200", 3) != 0) {
        fprintf(stderr, "selftest: status field mismatch\n");
        s3_destroy_pool(pool);
        return 1;
    }

    /*
     * the S3_DONE above is the section end itself: the one-field
     * section is exhausted, no extra parse call after it
     */

    printf("SELFTEST-RESP-FIELDS :status=200\n");
    printf("SELFTEST-H3-OK\n");
    fflush(stdout);

    s3_destroy_pool(pool);

    return 0;
}

static void
s3_interop_h3_response_read(s3_event_t *ev)
{
    s3_connection_t  *sc;
    s3_quic_stream_t *qs;
    s3_connection_t  *pc;
    s3_buf_t          b;
    size_t            i;
    unsigned          code;
    s3_int_t          rc;
    ssize_t           n;

    if (s3_interop_h3_status_seen) {
        return;
    }

    sc = ev->data;
    qs = sc->data;
    pc = qs->parent;

    for (;;) {

        if (s3_interop_h3_len == s3_interop_h3_cap) {
            size_t  cap = s3_interop_h3_cap + 262144;
            u_char *grown = realloc(s3_interop_h3_buf, cap);

            if (grown == NULL) {
                fprintf(stderr, "interop-client: h3 buffer growth failed\n");
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
            /* the server fin without a status: the CONNECT was refused */
            fprintf(stderr, "interop-client: h3 response stream closed without :status\n");
            exit(1);
        }

        if (n < 0) {
            fprintf(stderr, "interop-client: h3 response recv error\n");
            exit(1);
        }

        s3_interop_h3_len += (size_t)n;

        b.pos = s3_interop_h3_buf;
        b.last = s3_interop_h3_buf + s3_interop_h3_len;

        for (;;) {

            /*
             * ssh3-c: the parent connection goes into the parser, the
             * frozen s3_h3_get_session() macro reads c->data and the
             * session hangs exactly there (s3_h3_init_session(cli)
             * put it on the parent at the handshake)
             */
            rc = s3_h3_parse_headers(pc, &s3_interop_h3_parse, &b);

            if (rc == S3_AGAIN || rc == S3_BUSY) {
                break;
            }

            if (rc == S3_OK || rc == S3_DONE) {

                /*
                 * s3_h3_parse_headers() reports S3_OK per field line and
                 * S3_DONE at the end of the section; the last field line
                 * of a section arrives with the S3_DONE, so the verdict
                 * field is looked at on both (a one-field section —
                 * ":status" alone — comes as S3_DONE only)
                 */

                if (s3_interop_h3_name_is(&s3_interop_h3_parse.field_rep.field.name, ":status",
                                          7)) {

                    code = 0;

                    for (i = 0; i < s3_interop_h3_parse.field_rep.field.value.len && i < 3; i++) {

                        if (s3_interop_h3_parse.field_rep.field.value.data[i] < '0' ||
                            s3_interop_h3_parse.field_rep.field.value.data[i] > '9') {
                            fprintf(stderr, "interop-client: h3 bad :status value\n");
                            exit(1);
                        }

                        code = code * 10 +
                               (unsigned)(s3_interop_h3_parse.field_rep.field.value.data[i] - '0');
                    }

                    s3_interop_h3_status = code;
                    s3_interop_h3_status_seen = 1;

                    printf("INTEROP-H3-STATUS %u\n", code);
                    fflush(stdout);

                    if (code != 200) {
                        exit(1);
                    }

                    return;
                }

                if (rc == S3_DONE) {
                    fprintf(stderr, "interop-client: h3 response headers without :status\n");
                    exit(1);
                }

                continue;
            }

            fprintf(stderr, "interop-client: h3 response parse error %d\n", (int)rc);
            exit(1);
        }

        /* the consumed bytes compact to the front of the receive buffer */
        s3_interop_h3_len = (size_t)(b.last - b.pos);
        s3_memmove(s3_interop_h3_buf, b.pos, s3_interop_h3_len);
    }
}

/*
 * the session channel reader: the first message must be the 91
 * confirmation, then the run completes on the 94 carrying the ping
 * back; anything else on the channel is a hard protocol error
 */
static void
s3_interop_h3_channel_read(s3_event_t *ev)
{
    s3_connection_t *sc;
    const u_char    *pos, *end;
    ssize_t          n;

    if (s3_interop_h3_ch_ok) {
        /* after the verdict the queued teardown read events may arrive */
        return;
    }

    sc = ev->data;

    for (;;) {

        if (s3_interop_h3_ch_len == s3_interop_h3_ch_cap) {
            size_t  cap = s3_interop_h3_ch_cap + 262144;
            u_char *grown = realloc(s3_interop_h3_ch_buf, cap);

            if (grown == NULL) {
                fprintf(stderr, "interop-client: channel buffer growth failed\n");
                exit(1);
            }

            s3_interop_h3_ch_buf = grown;
            s3_interop_h3_ch_cap = cap;
        }

        n = sc->recv(sc, s3_interop_h3_ch_buf + s3_interop_h3_ch_len,
                     s3_interop_h3_ch_cap - s3_interop_h3_ch_len);

        if (n == (ssize_t)S3_AGAIN) {
            return;
        }

        if (n == 0) {
            /* the server fin before the ping came back: no verdict */
            fprintf(stderr, "interop-client: channel closed before the ping echo\n");
            exit(1);
        }

        if (n < 0) {
            fprintf(stderr, "interop-client: channel recv error\n");
            exit(1);
        }

        s3_interop_h3_ch_len += (size_t)n;

        pos = s3_interop_h3_ch_buf;
        end = s3_interop_h3_ch_buf + s3_interop_h3_ch_len;

        while (pos < end) {

            uint64_t type;

            if (s3_ssh3_parse_varint(&pos, end, &type) != S3_OK) {
                /* a partial type varint, the next recv completes it */
                break;
            }

            if (type == S3_SSH3_MSG_CHANNEL_OPEN_CONFIRMATION) {

                s3_ssh3_msg_open_confirmation_t conf;

                if (s3_interop_h3_ch_confirmed) {
                    fprintf(stderr, "interop-client: duplicate channel confirmation\n");
                    exit(1);
                }

                if (s3_ssh3_msg_parse_open_confirmation(&pos, end, &conf) != S3_OK) {
                    break;
                }

                s3_interop_h3_ch_confirmed = 1;
                continue;
            }

            if (type == S3_SSH3_MSG_CHANNEL_DATA) {

                s3_ssh3_msg_data_t msg;

                if (!s3_interop_h3_ch_confirmed) {
                    fprintf(stderr, "interop-client: channel data before confirmation\n");
                    exit(1);
                }

                if (s3_ssh3_msg_parse_data(&pos, end, &msg) != S3_OK) {
                    break;
                }

                if (msg.data.len == 4 && s3_memcmp(msg.data.data, "ping", 4) == 0) {

                    printf("INTEROP-CHANNEL-OK len=%zu\n", msg.data.len);
                    fflush(stdout);

                    s3_interop_h3_ch_ok = 1;

                    return;
                }

                /* the other payloads are not expected, drained */
                continue;
            }

            fprintf(stderr, "interop-client: unexpected channel message %llu\n",
                    (unsigned long long)type);
            exit(1);
        }

        /* the consumed bytes compact to the front of the receive buffer */
        s3_interop_h3_ch_len = (size_t)(end - pos);
        s3_memmove(s3_interop_h3_ch_buf, pos, s3_interop_h3_ch_len);
    }
}

/*
 * the direct-tcp writer (-F tcp=@port): the hello plus the pattern go
 * out as 94 frames once the 91 came back; a partial send parks the
 * frame tail (the stream is a byte stream, the offset tracking rides
 * the static frame buffer), the main loop retries each pass
 */
static void
s3_interop_fwd_tcp_write(void)
{
    while (s3_interop_fwd_sent < s3_interop_fwd_payload_len ||
           s3_interop_fwd_frame_sent < s3_interop_fwd_frame_total) {

        ssize_t m;

        if (s3_interop_fwd_frame_sent == s3_interop_fwd_frame_total) {

            size_t  chunk, overhead;
            u_char *p;

            chunk = s3_ssh3_channel_chunk_size(S3_INTEROP_CHANNEL_MAX_PACKET, 0);

            if (chunk > s3_interop_fwd_payload_len - s3_interop_fwd_sent) {
                chunk = s3_interop_fwd_payload_len - s3_interop_fwd_sent;
            }

            p = s3_interop_fwd_frame;
            p = (u_char *)s3_ssh3_encode_varint(p, S3_SSH3_MSG_CHANNEL_DATA);
            p = (u_char *)s3_ssh3_encode_varint(p, chunk);
            s3_memcpy(p, s3_interop_fwd_payload + s3_interop_fwd_sent, chunk);

            overhead = (size_t)(p - s3_interop_fwd_frame);

            s3_interop_fwd_frame_total = overhead + chunk;
            s3_interop_fwd_frame_sent = 0;
            s3_interop_fwd_sent += chunk;
        }

        m = s3_quic_stream_send(s3_interop_h3_channel,
                                s3_interop_fwd_frame + s3_interop_fwd_frame_sent,
                                s3_interop_fwd_frame_total - s3_interop_fwd_frame_sent);

        if (m == (ssize_t)S3_AGAIN) {
            /* the window reopens, retried on the next pass */
            return;
        }

        if (m <= 0) {
            fprintf(stderr, "interop-client: forward channel send failed\n");
            exit(1);
        }

        s3_interop_fwd_frame_sent += (size_t)m;
    }

    /*
     * everything is out: the fin lets the server shut the write side
     * of the target socket, the echo keeps coming back
     */
    if (!s3_interop_fwd_fin_sent) {

        if (s3_quic_shutdown_stream(s3_interop_h3_channel, S3_WRITE_SHUTDOWN) != S3_OK) {
            fprintf(stderr, "interop-client: forward channel shutdown failed\n");
            exit(1);
        }

        s3_interop_fwd_fin_sent = 1;
    }
}

/*
 * the forward channel reader (-F tcp=@port|udp=@port): the first
 * message must be the 91 confirmation ("91 waits before anything
 * else"), then the 94 payloads of the tcp run verify against the
 * expected bytes; the udp run expects no stream data at all
 */
static void
s3_interop_h3_fwd_read(s3_event_t *ev)
{
    s3_connection_t *sc;
    const u_char    *pos, *end;
    ssize_t          n;

    if (s3_interop_h3_ch_ok) {
        /* after the verdict the queued teardown read events may arrive */
        return;
    }

    sc = ev->data;

    for (;;) {

        if (s3_interop_h3_ch_len == s3_interop_h3_ch_cap) {
            size_t  cap = s3_interop_h3_ch_cap + 262144;
            u_char *grown = realloc(s3_interop_h3_ch_buf, cap);

            if (grown == NULL) {
                fprintf(stderr, "interop-client: channel buffer growth failed\n");
                exit(1);
            }

            s3_interop_h3_ch_buf = grown;
            s3_interop_h3_ch_cap = cap;
        }

        n = sc->recv(sc, s3_interop_h3_ch_buf + s3_interop_h3_ch_len,
                     s3_interop_h3_ch_cap - s3_interop_h3_ch_len);

        if (n == (ssize_t)S3_AGAIN) {
            return;
        }

        if (n == 0) {
            /* the server fin before the echo came back: no verdict */
            fprintf(stderr, "interop-client: forward channel closed before the echo\n");
            printf("INTEROP-FWD-TCP-FAIL\n");
            fflush(stdout);
            exit(1);
        }

        if (n < 0) {
            fprintf(stderr, "interop-client: forward channel recv error\n");
            printf("INTEROP-FWD-TCP-FAIL\n");
            fflush(stdout);
            exit(1);
        }

        s3_interop_h3_ch_len += (size_t)n;

        pos = s3_interop_h3_ch_buf;
        end = s3_interop_h3_ch_buf + s3_interop_h3_ch_len;

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

            if (type == S3_SSH3_MSG_CHANNEL_OPEN_CONFIRMATION) {

                s3_ssh3_msg_open_confirmation_t conf;

                if (s3_interop_h3_ch_confirmed) {
                    fprintf(stderr, "interop-client: duplicate channel confirmation\n");
                    exit(1);
                }

                if (s3_ssh3_msg_parse_open_confirmation(&pos, end, &conf) != S3_OK) {
                    pos = msg;
                    break;
                }

                s3_interop_h3_ch_confirmed = 1;
                continue;
            }

            if (type == S3_SSH3_MSG_CHANNEL_DATA) {

                s3_ssh3_msg_data_t data;

                if (!s3_interop_h3_ch_confirmed) {
                    fprintf(stderr, "interop-client: channel data before confirmation\n");
                    exit(1);
                }

                if (s3_ssh3_msg_parse_data(&pos, end, &data) != S3_OK) {
                    pos = msg;
                    break;
                }

                if (s3_interop_fwd_mode == S3_INTEROP_FWD_UDP) {
                    fprintf(stderr, "interop-client: stream data on the udp channel\n");
                    exit(1);
                }

                if (s3_interop_fwd_recv + data.data.len > s3_interop_fwd_payload_len) {
                    fprintf(stderr, "interop-client: forward echo overflow\n");
                    printf("INTEROP-FWD-TCP-FAIL\n");
                    fflush(stdout);
                    exit(1);
                }

                if (s3_memcmp(s3_interop_fwd_payload + s3_interop_fwd_recv, data.data.data,
                              data.data.len) != 0) {
                    fprintf(stderr, "interop-client: forward echo mismatch at %zu\n",
                            s3_interop_fwd_recv);
                    printf("INTEROP-FWD-TCP-FAIL\n");
                    fflush(stdout);
                    exit(1);
                }

                s3_interop_fwd_recv += data.data.len;

                if (s3_interop_fwd_recv == s3_interop_fwd_payload_len) {

                    printf("INTEROP-FWD-TCP-OK bytes=%zu\n", s3_interop_fwd_payload_len);
                    fflush(stdout);

                    s3_interop_h3_ch_ok = 1;

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

                /* the stderr side is drained, nothing verifies on it */
                continue;
            }

            fprintf(stderr, "interop-client: unexpected channel message %llu\n",
                    (unsigned long long)type);
            exit(1);
        }

        /* the consumed bytes compact to the front of the receive buffer */
        s3_interop_h3_ch_len = (size_t)(end - pos);
        s3_memmove(s3_interop_h3_ch_buf, pos, s3_interop_h3_ch_len);
    }
}

/* the needle search over the accumulated stdout (no NUL terminator) */

static unsigned
s3_interop_h3_sess_has(const char *text, size_t n)
{
    size_t i;

    if (s3_interop_h3_sess_out_len < n) {
        return 0;
    }

    for (i = 0; i + n <= s3_interop_h3_sess_out_len; i++) {

        if (s3_memcmp(s3_interop_h3_sess_out + i, text, n) == 0) {
            return 1;
        }
    }

    return 0;
}

static void
s3_interop_h3_sess_append(const u_char *data, size_t len)
{
    if (len == 0) {
        return;
    }

    if (s3_interop_h3_sess_out_len + len > s3_interop_h3_sess_out_cap) {
        size_t  cap = s3_interop_h3_sess_out_cap + 262144;
        u_char *grown;

        while (cap < s3_interop_h3_sess_out_len + len) {
            cap += 262144;
        }

        grown = realloc(s3_interop_h3_sess_out, cap);

        if (grown == NULL) {
            fprintf(stderr, "interop-client: session output growth failed\n");
            exit(1);
        }

        s3_interop_h3_sess_out = grown;
        s3_interop_h3_sess_out_cap = cap;
    }

    s3_memcpy(s3_interop_h3_sess_out + s3_interop_h3_sess_out_len, data, len);
    s3_interop_h3_sess_out_len += len;
}

/* the verdict of the session scenarios, the 98 exit-status carries it */

static void
s3_interop_h3_session_verdict(uint64_t code)
{
    if (s3_interop_h3_session_mode == S3_INTEROP_SESSION_EXEC) {

        /*
         * the -e runs (the agent_probe) answer with their own marker,
         * the plain exec wants the printf marker
         */

        const char *needle = s3_interop_exec_cmd != NULL ? "SSH3_AGENT_PROBE_OK" : "s3-exec-ok";

        size_t needle_len = strlen(needle);

        if (code == 0 && s3_interop_h3_sess_has(needle, needle_len)) {
            printf("INTEROP-EXEC-OK exit=0\n");
            fflush(stdout);

            s3_interop_h3_ch_ok = 1;

            return;
        }

        printf("INTEROP-EXEC-FAIL exit=%llu\n", (unsigned long long)code);
        fflush(stdout);

        exit(1);
    }

    /*
     * the kill run: the exec-ed sleep 30 is shot with the KILL right
     * after the confirmation, the verdict is 137 = 128 + 9
     */

    if (s3_interop_h3_session_mode == S3_INTEROP_SESSION_KILL) {

        if (code == 137) {
            printf("INTEROP-KILL-OK exit=137\n");
            fflush(stdout);

            s3_interop_h3_ch_ok = 1;

            return;
        }

        printf("INTEROP-KILL-FAIL exit=%llu\n", (unsigned long long)code);
        fflush(stdout);

        exit(1);
    }

    /*
     * the pty run: KILL is the only signal an interactive shell may
     * not ignore (POSIX job control), the verdict is 137 = 128 + 9;
     * the exit-signal body is unused, the server sends exit-status
     */

    if (code == 137) {
        printf("INTEROP-PTY-SIGNAL-OK exit=137\n");
        fflush(stdout);

        s3_interop_h3_ch_ok = 1;

        return;
    }

    printf("INTEROP-PTY-SIGNAL-FAIL exit=%llu\n", (unsigned long long)code);
    fflush(stdout);

    exit(1);
}

/* === the sftp transfer mode (-3 -J, the wave 2) === */

static void s3_interop_sftp_pump_timer(s3_event_t *ev);

static void s3_interop_agent_read(s3_event_t *ev);

static void s3_interop_agent_pump_timer(s3_event_t *ev);

/* the pending driver bytes of the cli direction, the pool owns them */

static u_char *s3_interop_sftp_out;
static size_t  s3_interop_sftp_out_cap;
static size_t  s3_interop_sftp_out_len;

/* the flush parked on the stream window: the retry timer goes short */

static unsigned s3_interop_sftp_parked;

static s3_int_t
s3_interop_sftp_append(const u_char *data, size_t n)
{
    if (s3_interop_sftp_out_len + n > s3_interop_sftp_out_cap) {

        size_t  cap = s3_interop_sftp_out_cap ? s3_interop_sftp_out_cap : 65536;
        u_char *grown;

        while (cap < s3_interop_sftp_out_len + n) {
            cap += 65536;
        }

        grown = realloc(s3_interop_sftp_out, cap);

        if (grown == NULL) {
            return S3_ERROR;
        }

        s3_interop_sftp_out = grown;
        s3_interop_sftp_out_cap = cap;
    }

    s3_memcpy(s3_interop_sftp_out + s3_interop_sftp_out_len, data, n);
    s3_interop_sftp_out_len += n;

    return S3_OK;
}

/* the verdict of the finished driver, the loop reads ch_ok */

static void
s3_interop_sftp_finish(void)
{
    uint32_t status = s3_ssh3_sftp_cli_status(&s3_interop_sftp_cli);

    if (s3_ssh3_sftp_cli_finished(&s3_interop_sftp_cli) && status == S3_SSH3_SFTP_FX_OK) {
        printf("INTEROP-SFTP-OK mode=%s file=%s\n",
               s3_interop_sftp_mode == S3_INTEROP_SFTP_PUT ? "put" : "get",
               s3_interop_sftp_mode == S3_INTEROP_SFTP_PUT ? s3_interop_sftp_remote
                                                           : s3_interop_sftp_local);
        fflush(stdout);

        s3_interop_h3_ch_ok = 1;

        return;
    }

    printf("INTEROP-SFTP-FAIL status=%u\n", (unsigned)status);
    fflush(stdout);

    exit(1);
}

/*
 * the cli direction: the drained requests chunk into the 94 frames
 * under the channel maxPacketSize (a 32 KiB WRITE body overflows one
 * frame), a partial send parks the tail on the static frame buffer
 */

static void
s3_interop_sftp_pump(void)
{
    u_char  buf[65536];
    ssize_t n;
    ssize_t m;
    size_t  chunk;

    for (;;) {

        n = s3_ssh3_sftp_cli_output(&s3_interop_sftp_cli, buf, sizeof(buf));

        if (n <= 0) {
            break;
        }

        if (s3_interop_sftp_append(buf, (size_t)n) != S3_OK) {
            fprintf(stderr, "interop-client: sftp request buffer growth failed\n");
            exit(1);
        }
    }

    while (s3_interop_sftp_out_len > 0 ||
           s3_interop_sftp_frame_sent < s3_interop_sftp_frame_total) {

        if (s3_interop_sftp_frame_sent == s3_interop_sftp_frame_total) {

            u_char *p;

            chunk = s3_ssh3_channel_chunk_size(S3_INTEROP_CHANNEL_MAX_PACKET, 0);

            if (chunk > s3_interop_sftp_out_len) {
                chunk = s3_interop_sftp_out_len;
            }

            p = s3_interop_sftp_frame;
            p = (u_char *)s3_ssh3_encode_varint(p, S3_SSH3_MSG_CHANNEL_DATA);
            p = (u_char *)s3_ssh3_encode_varint(p, chunk);
            s3_memcpy(p, s3_interop_sftp_out, chunk);

            s3_interop_sftp_frame_total = (size_t)(p - s3_interop_sftp_frame) + chunk;
            s3_interop_sftp_frame_sent = 0;

            s3_memmove(s3_interop_sftp_out, s3_interop_sftp_out + chunk,
                       s3_interop_sftp_out_len - chunk);
            s3_interop_sftp_out_len -= chunk;
        }

        if (getenv("S3SFTPDBG") != NULL && s3_interop_sftp_frame_total <= 64) {

            size_t z;

            fprintf(stderr, "sftpdbg send:");

            for (z = s3_interop_sftp_frame_sent; z < s3_interop_sftp_frame_total; z++) {
                fprintf(stderr, " %02x", s3_interop_sftp_frame[z]);
            }

            fprintf(stderr, "\n");
        }

        m = s3_quic_stream_send(s3_interop_h3_channel,
                                s3_interop_sftp_frame + s3_interop_sftp_frame_sent,
                                s3_interop_sftp_frame_total - s3_interop_sftp_frame_sent);

        if (m == (ssize_t)S3_AGAIN) {

            /* the window is closed: the retry rides the short timer,
             * the reply events wake the pump earlier */

            s3_interop_sftp_parked = 1;

            return;
        }

        if (m <= 0) {
            fprintf(stderr, "interop-client: sftp send failed\n");
            exit(1);
        }

        s3_interop_sftp_frame_sent += (size_t)m;
    }

    s3_interop_sftp_parked = 0;
}

/*
 * the write readiness of the sftp channel: the quic layer posts this
 * when the peer reopens the stream window, the pump resumes there
 */

static void
s3_interop_sftp_write(s3_event_t *ev)
{
    ev->ready = 0;

    if (s3_interop_h3_ch_ok) {
        return;
    }

    s3_interop_sftp_pump();
}

static void
s3_interop_sftp_pump_timer(s3_event_t *ev)
{
    ev->timedout = 0;

    if (s3_interop_h3_channel == NULL || s3_interop_h3_ch_ok) {
        return;
    }

    s3_interop_sftp_pump();

    if (!s3_interop_h3_ch_ok) {

        /*
         * the parked flush of a closed stream window retries short,
         * the idle keepalive stays on the slow tick; the reply events
         * wake the pump through the read path meanwhile
         */

        s3_event_add_timer(ev, s3_interop_sftp_parked ? 2 : 50);
    }
}

static void
s3_interop_sftp_start(void)
{
    s3_int_t rc;

    s3_interop_sftp_pool = s3_create_pool(S3_DEFAULT_POOL_SIZE, &s3_interop_log);

    if (s3_interop_sftp_pool == NULL) {
        fprintf(stderr, "interop-client: sftp pool failed\n");
        exit(1);
    }

    if (s3_ssh3_sftp_cli_init(&s3_interop_sftp_cli, s3_interop_sftp_pool, NULL, NULL) != S3_OK) {
        fprintf(stderr, "interop-client: sftp cli init failed\n");
        exit(1);
    }

    /* the READ bound follows the channel maxPacketSize this side
     * announced: the DATA replies of the peer stay under it */

    s3_ssh3_sftp_cli_channel_max_packet(&s3_interop_sftp_cli, S3_INTEROP_CHANNEL_MAX_PACKET);

    if (s3_interop_sftp_mode == S3_INTEROP_SFTP_PUT) {
        rc = s3_ssh3_sftp_cli_put(&s3_interop_sftp_cli, s3_interop_sftp_local,
                                  s3_interop_sftp_remote, 0, 1);

    } else {
        rc = s3_ssh3_sftp_cli_get(&s3_interop_sftp_cli, s3_interop_sftp_remote,
                                  s3_interop_sftp_local, 0, 1);
    }

    if (rc != S3_OK) {
        fprintf(stderr, "interop-client: sftp op start failed rc=%d\n", (int)rc);
        exit(1);
    }

    s3_interop_sftp_started = 1;

    s3_interop_sftp_timer.data = &s3_interop_sftp_timer;
    s3_interop_sftp_timer.log = &s3_interop_log;
    s3_interop_sftp_timer.handler = s3_interop_sftp_pump_timer;

    s3_event_add_timer(&s3_interop_sftp_timer, 50);

    /* the header is already on the stream: the INIT rides at once */

    s3_interop_sftp_pump();
}

/*
 * the sftp channel reader: the 91 confirms, the 94 payloads feed the
 * driver; the verdict lands from the driver state
 */

static void
s3_interop_sftp_read(s3_event_t *ev)
{
    s3_connection_t *sc;
    const u_char    *pos, *end;
    ssize_t          n;

    if (s3_interop_h3_ch_ok) {
        return;
    }

    sc = ev->data;

    for (;;) {

        if (s3_interop_sftp_buf_len == s3_interop_sftp_buf_cap) {
            size_t  cap = s3_interop_sftp_buf_cap + 262144;
            u_char *grown = realloc(s3_interop_sftp_buf, cap);

            if (grown == NULL) {
                fprintf(stderr, "interop-client: sftp buffer growth failed\n");
                exit(1);
            }

            s3_interop_sftp_buf = grown;
            s3_interop_sftp_buf_cap = cap;
        }

        n = sc->recv(sc, s3_interop_sftp_buf + s3_interop_sftp_buf_len,
                     s3_interop_sftp_buf_cap - s3_interop_sftp_buf_len);

        if (n == (ssize_t)S3_AGAIN) {
            return;
        }

        if (n <= 0) {
            fprintf(stderr, "interop-client: sftp channel closed early\n");
            exit(1);
        }

        s3_interop_sftp_buf_len += (size_t)n;

        if (getenv("S3SFTPDBG") != NULL && s3_interop_sftp_buf_len < 128) {

            const u_char *d;

            fprintf(stderr, "sftpdbg recv %ld buf_len=%zu:", (long)n, s3_interop_sftp_buf_len);

            for (d = s3_interop_sftp_buf; d < s3_interop_sftp_buf + s3_interop_sftp_buf_len; d++) {
                fprintf(stderr, " %02x", *d);
            }

            fprintf(stderr, "\n");
        }

        pos = s3_interop_sftp_buf;
        end = s3_interop_sftp_buf + s3_interop_sftp_buf_len;

        while (pos < end) {

            const u_char *msg = pos;
            uint64_t      type;

            if (s3_ssh3_parse_varint(&pos, end, &type) != S3_OK) {
                pos = msg;
                break;
            }

            if (type == S3_SSH3_MSG_CHANNEL_OPEN_CONFIRMATION) {

                /* the 91 carries the maxPacketSize body, it consumes */

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

                if (s3_ssh3_sftp_cli_input(&s3_interop_sftp_cli, data.data.data, data.data.len) !=
                    S3_OK) {
                    fprintf(stderr, "interop-client: sftp cli input failed\n");
                    exit(1);
                }

                if (s3_ssh3_sftp_cli_finished(&s3_interop_sftp_cli)) {
                    s3_interop_sftp_finish();

                    continue;
                }

                /* the replies woke the driver: the next train rides
                 * out at once, not on the timer tick */

                s3_interop_sftp_pump();

                continue;
            }

            /* the other channel messages do not exist in this run */
            fprintf(stderr, "interop-client: sftp unexpected message %llu at offset %ld tail:",
                    (unsigned long long)type, (long)(pos - s3_interop_sftp_buf));

            {
                const u_char *d;

                for (d = pos; d < end && d < pos + 24; d++) {
                    fprintf(stderr, " %02x", *d);
                }
            }

            fprintf(stderr, "\n");
            exit(1);
        }

        s3_interop_sftp_buf_len = (size_t)(end - pos);
        s3_memmove(s3_interop_sftp_buf, pos, s3_interop_sftp_buf_len);

        if (s3_interop_h3_ch_ok) {
            return;
        }
    }
}

/* === the agent bridge (-3 -C -S exec -X, the wave 2) === */

/*
 * the stream side: the 91 of the server confirmation skips, the 94
 * payloads ride the local agent socket; the fin of the peer tears the
 * bridge down
 */

static void
s3_interop_agent_fd_flush(void)
{
    while (s3_interop_agent_in_len > 0) {

        ssize_t m = send(s3_interop_agent_fd, s3_interop_agent_in, s3_interop_agent_in_len, 0);

        if (m > 0) {
            s3_memmove(s3_interop_agent_in, s3_interop_agent_in + m,
                       s3_interop_agent_in_len - (size_t)m);
            s3_interop_agent_in_len -= (size_t)m;
            continue;
        }

        /* the retry rides the timer tick */
        return;
    }
}

static void
s3_interop_agent_teardown(const char *why)
{
    fprintf(stderr, "interop-client: agent bridge down: %s\n", why);

    if (s3_interop_agent_timer.timer_set) {
        s3_event_del_timer(&s3_interop_agent_timer);
    }

    if (s3_interop_agent_fd >= 0) {
        s3_ssh3_agent_close_fd(s3_interop_agent_fd);
        s3_interop_agent_fd = -1;
    }

    if (s3_interop_agent_sc != NULL) {
        (void)s3_quic_shutdown_stream(s3_interop_agent_sc, S3_RDWR_SHUTDOWN);
        s3_interop_agent_sc = NULL;
    }

    s3_interop_agent_in_len = 0;
    s3_interop_agent_frame_sent = s3_interop_agent_frame_total = 0;
    s3_interop_agent_hdr_len = 0;
}

/*
 * the shared payload accumulator of the bridge (the stream direction
 * and the socket direction both feed it)
 */

static s3_int_t
s3_interop_agent_append(const u_char *data, size_t n)
{
    if (s3_interop_agent_in_len + n > s3_interop_agent_in_cap) {

        size_t  cap = s3_interop_agent_in_cap ? s3_interop_agent_in_cap : 16384;
        u_char *grown;

        while (cap < s3_interop_agent_in_len + n) {
            cap += 16384;
        }

        grown = realloc(s3_interop_agent_in, cap);

        if (grown == NULL) {
            return S3_ERROR;
        }

        s3_interop_agent_in = grown;
        s3_interop_agent_in_cap = cap;
    }

    s3_memcpy(s3_interop_agent_in + s3_interop_agent_in_len, data, n);
    s3_interop_agent_in_len += n;

    return S3_OK;
}

static void
s3_interop_agent_read(s3_event_t *ev)
{
    s3_connection_t  *sc;
    s3_ssh3_channel_t hdr;
    const u_char     *pos, *end;
    ssize_t           n;
    u_char            out[32];
    u_char           *p;
    size_t            total;
    ssize_t           m;
    const char       *sock;
    s3_str_t          sock_str;

    sc = ev->data;

    /* the header phase: the frame type, the conversation, the type */

    if (s3_interop_agent_sc == NULL) {

        n = sc->recv(sc, s3_interop_agent_hdr + s3_interop_agent_hdr_len,
                     sizeof(s3_interop_agent_hdr) - s3_interop_agent_hdr_len);

        if (getenv("S3AGENTDBG") != NULL && n > 0) {
            fprintf(stderr, "agdbg stream recv %ld\n", (long)n);
        }

        if (n == (ssize_t)S3_AGAIN) {
            return;
        }

        if (n <= 0) {
            s3_interop_agent_teardown("closed before the header");
            return;
        }

        s3_interop_agent_hdr_len += (size_t)n;

        pos = s3_interop_agent_hdr;
        end = s3_interop_agent_hdr + s3_interop_agent_hdr_len;

        if (s3_ssh3_channel_parse_header(&pos, end, &hdr) != S3_OK) {

            if (s3_interop_agent_hdr_len == sizeof(s3_interop_agent_hdr)) {
                s3_interop_agent_teardown("bad agent channel header");
            }

            /* the header tail waits for the next recv */
            return;
        }

        if (hdr.conversation_stream_id != s3_interop_fwd_conv_id ||
            hdr.type.len != strlen(S3_SSH3_CHANNEL_TYPE_AGENT) ||
            s3_memcmp(hdr.type.data, S3_SSH3_CHANNEL_TYPE_AGENT, hdr.type.len) != 0) {
            s3_interop_agent_teardown("unexpected server channel");
            return;
        }

        /* the 91 with our maxPacketSize, the shape of the server */

        {
            s3_ssh3_msg_open_confirmation_t conf;

            s3_memzero(&conf, sizeof(conf));
            conf.max_packet_size = S3_INTEROP_CHANNEL_MAX_PACKET;

            p = out;
            p = (u_char *)s3_ssh3_encode_varint(p, S3_SSH3_MSG_CHANNEL_OPEN_CONFIRMATION);
            p = (u_char *)s3_ssh3_msg_encode_open_confirmation(p, &conf);
            total = (size_t)(p - out);

            m = s3_quic_stream_send(sc, out, total);

            if (m != (ssize_t)total) {
                s3_interop_agent_teardown("confirmation send failed");
                return;
            }
        }

        /* the local half: the SSH_AUTH_SOCK of this machine */

        sock = getenv("SSH_AUTH_SOCK");

        if (sock == NULL || *sock == '\0') {
            s3_interop_agent_teardown("SSH_AUTH_SOCK is unset");
            return;
        }

        if (s3_interop_agent_pool == NULL) {
            s3_interop_agent_pool = s3_create_pool(S3_DEFAULT_POOL_SIZE, &s3_interop_log);

            if (s3_interop_agent_pool == NULL) {
                s3_interop_agent_teardown("agent pool failed");
                return;
            }
        }

        sock_str.data = (u_char *)sock;
        sock_str.len = strlen(sock);

        s3_interop_agent_fd = s3_ssh3_agent_dial(s3_interop_agent_pool, &sock_str);

        if (s3_interop_agent_fd < 0) {
            s3_interop_agent_teardown("agent dial failed");
            return;
        }

        s3_interop_agent_sc = sc;

        printf("INTEROP-AGENT-BRIDGE\n");
        fflush(stdout);

        s3_interop_agent_timer.data = &s3_interop_agent_timer;
        s3_interop_agent_timer.log = &s3_interop_log;
        s3_interop_agent_timer.handler = s3_interop_agent_pump_timer;

        s3_event_add_timer(&s3_interop_agent_timer, 50);

        /* the header phase is over, the bridge loop reads below */

        s3_interop_agent_hdr_len = (size_t)(end - pos);
        s3_memmove(s3_interop_agent_hdr, pos, s3_interop_agent_hdr_len);
    }

    /*
     * the bridge phase: the 94 payloads ride the local socket; the
     * messages accumulate in the header buffer reused as the receive
     * accumulator (a 30 KiB frame splits over the 16 KiB recvs);
     * the leftover of the header phase parses before the next recv,
     * the peer bytes may all have landed with the header segment
     */

    for (;;) {

        if (s3_interop_agent_hdr_len > 0) {

            pos = s3_interop_agent_hdr;
            end = s3_interop_agent_hdr + s3_interop_agent_hdr_len;

            while (pos < end) {

                const u_char *msg = pos;
                uint64_t      type;

                if (s3_ssh3_parse_varint(&pos, end, &type) != S3_OK) {
                    pos = msg;
                    break;
                }

                if (type == S3_SSH3_MSG_CHANNEL_OPEN_CONFIRMATION) {

                    /* the defensive 91 of the server side, it consumes */

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

                    if (s3_interop_agent_append(data.data.data, data.data.len) != S3_OK) {
                        s3_interop_agent_teardown("buffer growth failed");
                        return;
                    }

                    continue;
                }

                s3_interop_agent_teardown("unexpected agent message");
                return;
            }

            /* the consumed prefix drops, the partial tail waits */

            s3_interop_agent_hdr_len = (size_t)(end - pos);
            s3_memmove(s3_interop_agent_hdr, pos, s3_interop_agent_hdr_len);

            s3_interop_agent_fd_flush();
        }

        if (s3_interop_agent_hdr_len >= sizeof(s3_interop_agent_hdr)) {
            s3_interop_agent_teardown("agent frame above the accumulator");
            return;
        }

        n = sc->recv(sc, s3_interop_agent_hdr + s3_interop_agent_hdr_len,
                     sizeof(s3_interop_agent_hdr) - s3_interop_agent_hdr_len);

        if (n == (ssize_t)S3_AGAIN) {
            return;
        }

        if (n == 0) {
            s3_interop_agent_teardown("stream fin");
            return;
        }

        if (n < 0) {
            s3_interop_agent_teardown("stream recv error");
            return;
        }

        s3_interop_agent_hdr_len += (size_t)n;
    }
}

/*
 * the socket side: the agent answers accumulate and chunk into the 94
 * frames under the channel maxPacketSize, a partial send parks the
 * frame tail (the static buffer holds it between the ticks)
 */

static void
s3_interop_agent_pump_timer(s3_event_t *ev)
{
    static u_char buf[16384];
    ssize_t       n;
    ssize_t       m;
    size_t        chunk;

    ev->timedout = 0;

    if (s3_interop_agent_fd < 0) {
        return;
    }

    for (;;) {

        n = recv(s3_interop_agent_fd, buf, sizeof(buf), 0);

        if (getenv("S3AGENTDBG") != NULL && n > 0) {
            fprintf(stderr, "agdbg sock recv %ld\n", (long)n);
        }

        if (n <= 0) {

            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                break;
            }

            s3_interop_agent_teardown("agent socket eof");
            return;
        }

        if (s3_interop_agent_append(buf, (size_t)n) != S3_OK) {
            s3_interop_agent_teardown("buffer growth failed");
            return;
        }

        while (s3_interop_agent_in_len > 0 ||
               s3_interop_agent_frame_sent < s3_interop_agent_frame_total) {

            if (s3_interop_agent_frame_sent == s3_interop_agent_frame_total) {

                u_char *p;

                chunk = s3_ssh3_channel_chunk_size(S3_INTEROP_CHANNEL_MAX_PACKET, 0);

                if (chunk > s3_interop_agent_in_len) {
                    chunk = s3_interop_agent_in_len;
                }

                p = s3_interop_agent_frame;
                p = (u_char *)s3_ssh3_encode_varint(p, S3_SSH3_MSG_CHANNEL_DATA);
                p = (u_char *)s3_ssh3_encode_varint(p, chunk);
                s3_memcpy(p, s3_interop_agent_in, chunk);

                s3_interop_agent_frame_total = (size_t)(p - s3_interop_agent_frame) + chunk;
                s3_interop_agent_frame_sent = 0;

                s3_memmove(s3_interop_agent_in, s3_interop_agent_in + chunk,
                           s3_interop_agent_in_len - chunk);
                s3_interop_agent_in_len -= chunk;
            }

            m = s3_quic_stream_send(s3_interop_agent_sc,
                                    s3_interop_agent_frame + s3_interop_agent_frame_sent,
                                    s3_interop_agent_frame_total - s3_interop_agent_frame_sent);

            if (m == (ssize_t)S3_AGAIN) {
                /* the window reopens on the next tick */
                s3_event_add_timer(ev, 50);
                return;
            }

            if (m <= 0) {
                s3_interop_agent_teardown("agent stream send failed");
                return;
            }

            s3_interop_agent_frame_sent += (size_t)m;
        }
    }

    s3_event_add_timer(ev, 50);
}

/*
 * the 98 builder: the message type varint, the envelope and the
 * encoded body of the request, appended at p; returns the past-the-end
 * pointer
 */
static u_char *
s3_interop_h3_session_request(u_char *p, s3_ssh3_request_kind_t kind, unsigned want_reply,
                              const s3_ssh3_request_t *body)
{
    s3_ssh3_msg_request_t env;
    u_char                enc[128];
    size_t                n;
    const char           *type;

    p = (u_char *)s3_ssh3_encode_varint(p, S3_SSH3_MSG_CHANNEL_REQUEST);

    type = s3_ssh3_request_type_str(kind);

    n = (size_t)s3_ssh3_request_encode_body(NULL, body);

    if (n > sizeof(enc)) {
        fprintf(stderr, "interop-client: session request body too large\n");
        exit(1);
    }

    (void)s3_ssh3_request_encode_body(enc, body);

    s3_memzero(&env, sizeof(env));

    env.request_type.data = (u_char *)type;
    env.request_type.len = strlen(type);
    env.want_reply = want_reply;
    env.body.data = enc;
    env.body.len = n;

    return (u_char *)s3_ssh3_msg_encode_request(p, &env);
}

/*
 * === the ControlMaster harness (the M2 wiring over the M1 codec) ===
 *
 * the master (-3 -C -M -U path): the UDS listener of ListenControlMaster
 * lives on the main event loop next to the shared quic connection; every
 * control or attach connection wraps one s3_ssh3_cm_srv_t and one pool,
 * the sessions the codec opens ride the session channels of the existing
 * h3 connection (the open_session callback) and the io and stderr
 * attachments bridge their sockets to the channel data path (bridge);
 * the exit status of the channel goes back over the control connection
 *
 * the slave (-U path -e cmd, no quic) and the control ops (-O) are the
 * strict sequential Call clients of protocol.go over poll(2); the frame
 * feed gives the cli state machine one complete frame at a time, so a
 * reply coalesced with the later exit status stays parseable
 */

#define S3_INTEROP_CM_BUF_INIT  4096
#define S3_INTEROP_CM_FRAME_CAP 33000 /* the 94 frame park, the sftp shape */
#define S3_INTEROP_CM_CMD_MAX   768
#define S3_INTEROP_CM_TICK_MS   250

enum { S3_INTEROP_CM_CONN_CONTROL = 0, S3_INTEROP_CM_CONN_IO = 1, S3_INTEROP_CM_CONN_STDERR = 2 };

typedef struct s3_interop_cm_conn_s s3_interop_cm_conn_t;
typedef struct s3_interop_cm_run_s  s3_interop_cm_run_t;

/* one control or attach connection of the master */

struct s3_interop_cm_conn_s {
    int                   fd;
    s3_pool_t            *pool;
    s3_connection_t      *c; /* sc->data points back here */
    s3_ssh3_cm_srv_t      srv;
    unsigned              kind;
    s3_interop_cm_run_t  *run; /* the owning session once the frames name it */
    u_char               *out; /* the parked bytes between the flushes */
    size_t                out_len;
    size_t                out_cap;
    s3_interop_cm_conn_t *next;
};

/* one slave-requested session awaiting or running its bridge */

struct s3_interop_cm_run_s {
    u_char                token[S3_SSH3_CM_TOKEN_LEN];
    unsigned              used : 1;
    unsigned              ch_confirmed : 1;
    unsigned              bridged : 1;
    unsigned              finalized : 1;
    uint64_t              exit_code;
    s3_connection_t      *chan;   /* the ssh3 session channel */
    u_char               *ch_buf; /* the channel parse accumulator */
    size_t                ch_len;
    size_t                ch_cap;
    u_char               *stdin_buf; /* the io bytes awaiting the 94 frames */
    size_t                stdin_len;
    size_t                stdin_cap;
    u_char                frame[S3_INTEROP_CM_FRAME_CAP];
    size_t                frame_sent;
    size_t                frame_total;
    s3_interop_cm_conn_t *control;
    s3_interop_cm_conn_t *io;
    s3_interop_cm_conn_t *err;
};

static unsigned    s3_interop_cm_master;
static const char *s3_interop_cm_path;
static const char *s3_interop_cm_op;
static long        s3_interop_cm_idle_ms = 5000;

static s3_ssh3_cm_sessions_t s3_interop_cm_table;
static s3_interop_cm_run_t   s3_interop_cm_runs[S3_SSH3_CM_SRV_SESSIONS];
static s3_interop_cm_conn_t *s3_interop_cm_conns;

static s3_fd_t          s3_interop_cm_listen_fd = -1;
static s3_connection_t *s3_interop_cm_listen_c;
static s3_event_ctx_t  *s3_interop_cm_ctx;
static s3_event_t       s3_interop_cm_timer;
static unsigned         s3_interop_cm_listening;
static unsigned         s3_interop_cm_stop;
static s3_msec_t        s3_interop_cm_started_ms;
static s3_msec_t        s3_interop_cm_activity;

static s3_connection_t      *s3_interop_main_cli;
static s3_interop_cm_conn_t *s3_interop_cm_cur; /* the conn whose srv_input runs */

static void s3_interop_cm_conn_close(s3_interop_cm_conn_t *conn);

static void s3_interop_cm_run_finalize(s3_interop_cm_run_t *run, uint64_t code);

static void
s3_interop_cm_run_free(s3_interop_cm_run_t *run)
{
    free(run->ch_buf);
    free(run->stdin_buf);

    s3_memzero(run, sizeof(*run));
}

static s3_interop_cm_run_t *
s3_interop_cm_run_alloc(void)
{
    uint32_t i;

    for (i = 0; i < S3_SSH3_CM_SRV_SESSIONS; i++) {

        if (!s3_interop_cm_runs[i].used) {
            s3_interop_cm_runs[i].used = 1;

            return &s3_interop_cm_runs[i];
        }
    }

    return NULL;
}

static s3_interop_cm_run_t *
s3_interop_cm_run_by_token(const u_char token[S3_SSH3_CM_TOKEN_LEN])
{
    uint32_t i;

    for (i = 0; i < S3_SSH3_CM_SRV_SESSIONS; i++) {

        if (s3_interop_cm_runs[i].used &&
            s3_memcmp(s3_interop_cm_runs[i].token, token, S3_SSH3_CM_TOKEN_LEN) == 0) {
            return &s3_interop_cm_runs[i];
        }
    }

    return NULL;
}

static s3_interop_cm_run_t *
s3_interop_cm_run_by_chan(s3_connection_t *chan)
{
    uint32_t i;

    for (i = 0; i < S3_SSH3_CM_SRV_SESSIONS; i++) {

        if (s3_interop_cm_runs[i].used && s3_interop_cm_runs[i].chan == chan) {
            return &s3_interop_cm_runs[i];
        }
    }

    return NULL;
}

static unsigned
s3_interop_cm_runs_live(void)
{
    unsigned n = 0;
    uint32_t i;

    for (i = 0; i < S3_SSH3_CM_SRV_SESSIONS; i++) {
        n += s3_interop_cm_runs[i].used && !s3_interop_cm_runs[i].finalized;
    }

    return n;
}

static void
s3_interop_cm_shutdown(void)
{
    if (s3_interop_cm_stop) {
        return;
    }

    s3_interop_cm_stop = 1;

    if (s3_interop_cm_timer.timer_set) {
        s3_event_del_timer(&s3_interop_cm_timer);
    }

    if (s3_interop_cm_listen_fd >= 0) {

        (void)s3_event_actions.del_event(s3_interop_cm_listen_c->read, S3_CLOSE_EVENT, 0);

        (void)close(s3_interop_cm_listen_fd);
        s3_interop_cm_listen_fd = -1;
    }

    /*
     * the clean teardown: no stale socket file; only the process that
     * owned the listening socket unlinks the path, the dup master that
     * refused the live path must leave its peer's file alone
     */

    if (s3_interop_cm_listening) {
        (void)unlink(s3_interop_cm_path);
    }
}

/* the append and flush of one connection, the growth pays per size
   class and the write event arms only while the park holds bytes */

static s3_int_t
s3_interop_cm_out_append(s3_interop_cm_conn_t *conn, const u_char *data, size_t n)
{
    u_char *grown;
    size_t  want;

    if (conn->out_cap - conn->out_len < n) {

        want = conn->out_cap != 0 ? conn->out_cap : S3_INTEROP_CM_BUF_INIT;

        while (want - conn->out_len < n) {
            want *= 2;
        }

        grown = s3_pnalloc(conn->pool, want);

        if (grown == NULL) {
            return S3_ERROR;
        }

        if (conn->out_len > 0) {
            s3_memcpy(grown, conn->out, conn->out_len);
        }

        conn->out = grown;
        conn->out_cap = want;
    }

    if (n > 0) {
        s3_memcpy(conn->out + conn->out_len, data, n);
        conn->out_len += n;
    }

    return S3_OK;
}

static s3_int_t
s3_interop_cm_conn_flush(s3_interop_cm_conn_t *conn)
{
    while (conn->out_len > 0) {

        ssize_t m = send(conn->fd, conn->out, conn->out_len, 0);

        if (m > 0) {
            s3_memmove(conn->out, conn->out + m, conn->out_len - (size_t)m);
            conn->out_len -= (size_t)m;
            continue;
        }

        if (m < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;
        }

        return S3_ERROR;
    }

    if (conn->out_len > 0) {

        if (!conn->c->write->active &&
            s3_event_actions.add_event(conn->c->write, S3_WRITE_EVENT, 0) != S3_OK) {
            return S3_ERROR;
        }

    } else if (conn->c->write->active) {
        (void)s3_event_actions.del_event(conn->c->write, S3_WRITE_EVENT, 0);
    }

    return S3_OK;
}

static s3_int_t
s3_interop_cm_conn_send(s3_interop_cm_conn_t *conn, const u_char *data, size_t n)
{
    if (conn == NULL || n == 0) {
        return S3_OK;
    }

    if (s3_interop_cm_out_append(conn, data, n) != S3_OK) {
        return S3_ERROR;
    }

    return s3_interop_cm_conn_flush(conn);
}

static void
s3_interop_cm_conn_write(s3_event_t *ev)
{
    s3_connection_t      *sc = ev->data;
    s3_interop_cm_conn_t *conn = sc->data;

    if (conn == NULL) {
        return;
    }

    if (s3_interop_cm_conn_flush(conn) != S3_OK) {
        s3_interop_cm_conn_close(conn);
        return;
    }

    if (conn->out_len == 0 && s3_ssh3_cm_srv_shutdown(&conn->srv)) {
        /* the stop reply drained, the master closes with it */
        s3_interop_cm_shutdown();
        s3_interop_cm_conn_close(conn);
    }
}

static void
s3_interop_cm_conn_close(s3_interop_cm_conn_t *conn)
{
    s3_connection_t       *sc;
    s3_interop_cm_conn_t **link;
    s3_interop_cm_run_t   *run = conn->run;

    for (link = &s3_interop_cm_conns; *link != NULL; link = &(*link)->next) {

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
                   status: the session slot frees, the bridge closes */
                s3_interop_cm_run_finalize(run, 255);
            }
        }

        if (run->io == conn) {
            run->io = NULL;
        }

        if (run->err == conn) {
            run->err = NULL;
        }
    }

    sc = conn->c;

    if (sc != NULL) {
        conn->c = NULL;
        conn->pool = NULL;

        /* closes the fd and destroys the pool the conn struct lives in */
        s3_close_connection(sc);
    }
}

/* the stdin direction: the io attachment bytes chunk into the 94
   frames under the channel max packet, a partial send parks the tail
   (the tick retries when the stream window was closed) */

static s3_int_t
s3_interop_cm_run_stdin_pump(s3_interop_cm_run_t *run)
{
    u_char *p;
    size_t  chunk;
    ssize_t m;

    while (run->stdin_len > 0 || run->frame_sent < run->frame_total) {

        if (run->frame_sent == run->frame_total) {

            chunk = s3_ssh3_channel_chunk_size(S3_INTEROP_CHANNEL_MAX_PACKET, 0);

            if (chunk > run->stdin_len) {
                chunk = run->stdin_len;
            }

            p = run->frame;
            p = (u_char *)s3_ssh3_encode_varint(p, S3_SSH3_MSG_CHANNEL_DATA);
            p = (u_char *)s3_ssh3_encode_varint(p, chunk);
            s3_memcpy(p, run->stdin_buf, chunk);

            run->frame_total = (size_t)(p - run->frame) + chunk;
            run->frame_sent = 0;

            s3_memmove(run->stdin_buf, run->stdin_buf + chunk, run->stdin_len - chunk);
            run->stdin_len -= chunk;
        }

        m = s3_quic_stream_send(run->chan, run->frame + run->frame_sent,
                                run->frame_total - run->frame_sent);

        if (m == (ssize_t)S3_AGAIN) {
            return S3_OK;
        }

        if (m <= 0) {
            return S3_ERROR;
        }

        run->frame_sent += (size_t)m;
    }

    return S3_OK;
}

static s3_int_t
s3_interop_cm_run_stdin(s3_interop_cm_run_t *run, const u_char *data, size_t len)
{
    u_char *grown;
    size_t  cap;

    if (run->stdin_cap - run->stdin_len < len) {

        cap = run->stdin_cap != 0 ? run->stdin_cap : S3_INTEROP_CM_BUF_INIT;

        while (cap - run->stdin_len < len) {
            cap *= 2;
        }

        grown = realloc(run->stdin_buf, cap);

        if (grown == NULL) {
            return S3_ERROR;
        }

        run->stdin_buf = grown;
        run->stdin_cap = cap;
    }

    s3_memcpy(run->stdin_buf + run->stdin_len, data, len);
    run->stdin_len += len;

    return s3_interop_cm_run_stdin_pump(run);
}

/* the session teardown: the attach data drains first, the exit status
   rides the control conn, the codec slot frees and the channel shuts */

static void
s3_interop_cm_run_finalize(s3_interop_cm_run_t *run, uint64_t code)
{
    u_char   es[8];
    u_char   fr[S3_SSH3_CM_HEADER_LEN + sizeof(es)];
    s3_str_t pl;
    u_char  *p;

    if (run->finalized) {
        return;
    }

    run->finalized = 1;
    run->exit_code = code;

    if (run->io != NULL && s3_interop_cm_conn_flush(run->io) != S3_OK) {
        s3_interop_cm_conn_close(run->io);
    }

    if (run->err != NULL && s3_interop_cm_conn_flush(run->err) != S3_OK) {
        s3_interop_cm_conn_close(run->err);
    }

    if (run->control != NULL) {

        pl.data = es;
        pl.len = sizeof(es);
        (void)s3_ssh3_cm_encode_exit_status(es, code);

        p = fr;
        p = (u_char *)s3_ssh3_cm_encode_frame(p, S3_SSH3_CM_MSG_EXIT_STATUS, &pl);

        if (s3_interop_cm_conn_send(run->control, fr, (size_t)(p - fr)) != S3_OK) {
            s3_interop_cm_conn_close(run->control);
        }
    }

    /* the codec slot clears for the reuse, the release is the lib's */

    (void)s3_ssh3_cm_sessions_release(&s3_interop_cm_table, run->token);

    if (run->chan != NULL) {

        /*
         * the drop runs the quic stream cleanup (fin + close): the
         * retire lifts the client open credit and queues MAX_STREAMS,
         * the next session channel opens without the 16-stream cap;
         * a fin the peer has not sent yet retires the stream later,
         * from the frame and ack paths (the connection is NULL then)
         */
        s3_close_connection(run->chan);
        run->chan = NULL;
    }

    if (run->control != NULL) {
        s3_interop_cm_conn_close(run->control);
    }

    if (run->io != NULL) {
        s3_interop_cm_conn_close(run->io);
    }

    if (run->err != NULL) {
        s3_interop_cm_conn_close(run->err);
    }

    printf("S3CM-MASTER-SESSION-DONE exit=%llu\n", (unsigned long long)code);
    fflush(stdout);

    s3_interop_cm_run_free(run);
}

/* the channel reader: the confirmation, the data dispatch to the
   attached sockets and the exit-status request of the server */

static void
s3_interop_cm_run_read(s3_event_t *ev)
{
    s3_connection_t     *chan = ev->data;
    s3_interop_cm_run_t *run = s3_interop_cm_run_by_chan(chan);
    const u_char        *pos, *end;
    ssize_t              n;

    if (run == NULL || run->finalized) {
        /* the tail events of a finished session are noise */
        return;
    }

    for (;;) {

        if (run->ch_len == run->ch_cap) {
            size_t  cap = run->ch_cap + 262144;
            u_char *grown = realloc(run->ch_buf, cap);

            if (grown == NULL) {
                s3_interop_cm_run_finalize(run, 255);
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
            s3_interop_cm_run_finalize(run, 255);

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
                    s3_interop_cm_run_finalize(run, 255);
                    return;
                }

                if (s3_ssh3_msg_parse_data(&pos, end, &msg) != S3_OK) {
                    break;
                }

                /* the session stdout rides the io attachment */

                if (s3_interop_cm_conn_send(run->io, msg.data.data, msg.data.len) != S3_OK) {
                    s3_interop_cm_run_finalize(run, 255);
                    return;
                }

                continue;
            }

            if (type == S3_SSH3_MSG_CHANNEL_EXTENDED_DATA) {

                s3_ssh3_msg_extended_data_t xmsg;

                if (s3_ssh3_msg_parse_extended_data(&pos, end, &xmsg) != S3_OK) {
                    break;
                }

                /* the session stderr rides the stderr attachment */

                if (s3_interop_cm_conn_send(run->err, xmsg.data.data, xmsg.data.len) != S3_OK) {
                    s3_interop_cm_run_finalize(run, 255);
                    return;
                }

                continue;
            }

            if (type == S3_SSH3_MSG_CHANNEL_REQUEST) {

                s3_ssh3_msg_request_t env;
                s3_ssh3_request_t     body;
                const u_char         *bpos;
                s3_int_t              rc;

                if (s3_ssh3_msg_parse_request_envelope(&pos, end, &env) != S3_OK) {
                    break;
                }

                bpos = pos;

                rc = s3_ssh3_request_parse_body(&bpos, end, &env.request_type, &body);

                if (rc == S3_OK) {

                    if (body.kind == S3_SSH3_REQ_EXIT_STATUS) {
                        s3_interop_cm_run_finalize(run, body.u.exit_status.status);
                        return;
                    }

                    /* the request replies without the verdict drain */
                    continue;
                }

                if (rc == S3_DECLINED) {

                    /* an unknown request type: its body has no length
                       prefix, the buffer tail drains */
                    pos = end;

                    continue;
                }

                break;
            }

            /* the open failure or the unknown message ends the session */
            s3_interop_cm_run_finalize(run, 255);

            return;
        }

        run->ch_len = (size_t)(end - pos);
        s3_memmove(run->ch_buf, pos, run->ch_len);
    }
}

/* the srv callbacks; the codec dispatch runs inside the read handler
   of the current connection, s3_interop_cm_cur names it */

static s3_int_t
s3_interop_cm_cb_open_session(void *ctx, const s3_ssh3_cm_open_session_t *req,
                              u_char token[S3_SSH3_CM_TOKEN_LEN], const char **err)
{
    s3_interop_cm_run_t *run;
    s3_connection_t     *chan;
    s3_ssh3_channel_t    hdr;
    s3_ssh3_request_t    exec;
    u_char               frame[2048];
    u_char              *p;
    char                 cmd[S3_INTEROP_CM_CMD_MAX];
    size_t               cl, total;
    ssize_t              m;
    uint32_t             j;

    (void)ctx;

    /* the codec allocs the slot after this callback, the room checks here */

    if (s3_interop_cm_table.count >= S3_SSH3_CM_SRV_SESSIONS) {
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

        s3_memcpy(cmd + cl, req->command[j].data, req->command[j].len);
        cl += req->command[j].len;
        cmd[cl++] = ' ';
    }

    cmd[cl - 1] = '\0';

    run = s3_interop_cm_run_alloc();

    if (run == NULL) {
        *err = "too many sessions";

        return S3_ERROR;
    }

    if (RAND_bytes(token, S3_SSH3_CM_TOKEN_LEN) != 1) {
        *err = "token generation failed";
        s3_interop_cm_run_free(run);

        return S3_ERROR;
    }

    /* the session channel of the shared connection, the shape the
       -C -S exec run uses: the header and the exec request in one send */

    chan = s3_quic_open_stream(s3_interop_main_cli, 1);

    if (chan == NULL) {
        *err = "channel open failed";
        s3_interop_cm_run_free(run);

        return S3_ERROR;
    }

    s3_memzero(&hdr, sizeof(hdr));

    hdr.conversation_stream_id = ((s3_quic_stream_t *)s3_interop_h3_stream->data)->id;
    hdr.max_packet_size = S3_INTEROP_CHANNEL_MAX_PACKET;
    hdr.type.data = (u_char *)S3_SSH3_CHANNEL_TYPE_SESSION;
    hdr.type.len = strlen(S3_SSH3_CHANNEL_TYPE_SESSION);

    s3_memzero(&exec, sizeof(exec));

    exec.kind = S3_SSH3_REQ_EXEC;
    exec.u.exec.command.data = (u_char *)cmd;
    exec.u.exec.command.len = strlen(cmd);

    p = frame;
    p = s3_ssh3_channel_build_header(p, &hdr);
    p = s3_interop_h3_session_request(p, S3_SSH3_REQ_EXEC, 1, &exec);
    total = (size_t)(p - frame);

    m = s3_quic_stream_send(chan, frame, total);

    if (m != (ssize_t)total) {
        (void)s3_quic_shutdown_stream(chan, S3_RDWR_SHUTDOWN);
        *err = "channel send failed";
        s3_interop_cm_run_free(run);

        return S3_ERROR;
    }

    chan->read->handler = s3_interop_cm_run_read;
    chan->read->data = chan;
    chan->read->active = 1;

    s3_memcpy(run->token, token, S3_SSH3_CM_TOKEN_LEN);
    run->chan = chan;
    run->control = s3_interop_cm_cur;

    if (run->control != NULL) {
        run->control->run = run;
        run->control->kind = S3_INTEROP_CM_CONN_CONTROL;
    }

    return S3_OK;
}

static void
s3_interop_cm_cb_bridge(void *ctx, const u_char token[S3_SSH3_CM_TOKEN_LEN])
{
    s3_interop_cm_run_t *run = s3_interop_cm_run_by_token(token);

    (void)ctx;

    if (run == NULL) {
        return;
    }

    run->bridged = 1;

    if (s3_interop_cm_cur != NULL) {
        run->io = s3_interop_cm_cur;
        s3_interop_cm_cur->run = run;
        s3_interop_cm_cur->kind = S3_INTEROP_CM_CONN_IO;
    }
}

static void
s3_interop_cm_cb_bridge_stderr(void *ctx, const u_char token[S3_SSH3_CM_TOKEN_LEN])
{
    s3_interop_cm_run_t *run = s3_interop_cm_run_by_token(token);

    (void)ctx;

    if (run == NULL) {
        return;
    }

    /* the attachment conns own no run yet, the control conns do */

    if (s3_interop_cm_cur != NULL && s3_interop_cm_cur->run == NULL) {
        run->err = s3_interop_cm_cur;
        s3_interop_cm_cur->run = run;
        s3_interop_cm_cur->kind = S3_INTEROP_CM_CONN_STDERR;
    }
}

static s3_int_t
s3_interop_cm_cb_status(void *ctx, s3_ssh3_cm_status_t *st)
{
    (void)ctx;

    st->path = s3_interop_cm_path;
    st->pid = (int)getpid();
    st->protocol = S3_SSH3_CM_VERSION;
    st->uptime_s = (double)(s3_current_msec - s3_interop_cm_started_ms) / 1000.0;
    st->sessions = (int)s3_interop_cm_table.count;
    st->forwards = 0;

    return S3_OK;
}

/* the per-connection read handler: the codec pumps until the io or
   the stderr bridge owns the attachment */

static void
s3_interop_cm_conn_read(s3_event_t *ev)
{
    s3_connection_t      *sc = ev->data;
    s3_interop_cm_conn_t *conn = sc->data;
    u_char                buf[16384];
    u_char                obuf[16384];
    ssize_t               n;

    for (;;) {

        n = recv(conn->fd, buf, sizeof(buf), 0);

        if (n < 0) {

            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            }

            s3_interop_cm_conn_close(conn);

            return;
        }

        if (n == 0) {
            break;
        }

        s3_interop_cm_activity = s3_current_msec;

        if (conn->kind != S3_INTEROP_CM_CONN_IO || conn->run == NULL || !conn->run->bridged) {

            s3_interop_cm_cur = conn;

            if (s3_ssh3_cm_srv_input(&conn->srv, buf, (size_t)n) != S3_OK) {
                s3_interop_cm_conn_close(conn);

                return;
            }

            s3_interop_cm_cur = NULL;

            for (;;) {

                ssize_t m = s3_ssh3_cm_srv_output(&conn->srv, obuf, sizeof(obuf));

                if (m <= 0) {
                    break;
                }

                if (s3_interop_cm_conn_send(conn, obuf, (size_t)m) != S3_OK) {
                    s3_interop_cm_conn_close(conn);

                    return;
                }
            }

            if (s3_ssh3_cm_srv_done(&conn->srv)) {

                if (s3_ssh3_cm_srv_shutdown(&conn->srv)) {
                    s3_interop_cm_shutdown();
                }

                s3_interop_cm_conn_close(conn);

                return;
            }

        } else {

            /* the bridged io attachment feeds the session stdin */

            if (s3_interop_cm_run_stdin(conn->run, buf, (size_t)n) != S3_OK) {
                s3_interop_cm_run_finalize(conn->run, 255);

                return;
            }
        }
    }

    /* the peer eof, half closes keep the write direction */

    if (conn->kind == S3_INTEROP_CM_CONN_IO && conn->run != NULL && conn->run->bridged) {

        (void)s3_event_actions.del_event(conn->c->read, S3_READ_EVENT, 0);
        (void)s3_quic_shutdown_stream(conn->run->chan, S3_WRITE_SHUTDOWN);

        return;
    }

    if (conn->kind == S3_INTEROP_CM_CONN_STDERR && conn->run != NULL) {
        (void)s3_event_actions.del_event(conn->c->read, S3_READ_EVENT, 0);

        return;
    }

    s3_interop_cm_conn_close(conn);
}

/* the accept handler of the control listener */

static void
s3_interop_cm_accept(s3_event_t *ev)
{
    static s3_ssh3_cm_srv_cbs_t cbs;
    s3_pool_t                  *pool;
    s3_interop_cm_conn_t       *conn;
    s3_connection_t            *sc;
    int                         cfd;

    (void)ev;

    if (cbs.open_session == NULL) {
        cbs.open_session = s3_interop_cm_cb_open_session;
        cbs.bridge = s3_interop_cm_cb_bridge;
        cbs.bridge_stderr = s3_interop_cm_cb_bridge_stderr;
        cbs.status = s3_interop_cm_cb_status;
    }

    for (;;) {

        cfd = accept(s3_interop_cm_listen_fd, NULL, NULL);

        if (cfd < 0) {
            return;
        }

        if (s3_nonblocking(cfd) != S3_OK) {
            (void)close(cfd);
            continue;
        }

        pool = s3_create_pool(S3_DEFAULT_POOL_SIZE, &s3_interop_log);

        if (pool == NULL) {
            (void)close(cfd);
            continue;
        }

        conn = (s3_interop_cm_conn_t *)s3_pcalloc(pool, sizeof(*conn));

        if (conn == NULL) {
            s3_destroy_pool(pool);
            (void)close(cfd);
            continue;
        }

        sc = s3_get_connection(s3_interop_cm_ctx, cfd);

        if (sc == NULL) {
            s3_destroy_pool(pool);
            (void)close(cfd);
            continue;
        }

        conn->fd = cfd;
        conn->pool = pool;
        conn->c = sc;
        conn->kind = S3_INTEROP_CM_CONN_CONTROL;

        sc->pool = pool;
        sc->data = conn;

        if (s3_ssh3_cm_srv_init(&conn->srv, pool, &s3_interop_cm_table, &cbs, NULL) != S3_OK) {
            s3_destroy_pool(pool);
            (void)close(cfd);
            continue;
        }

        sc->read->handler = s3_interop_cm_conn_read;
        sc->read->data = sc;

        sc->write->handler = s3_interop_cm_conn_write;
        sc->write->data = sc;

        if (s3_event_actions.add_connection(s3_interop_cm_ctx, sc) != S3_OK) {
            s3_destroy_pool(pool);
            (void)close(cfd);
            continue;
        }

        conn->next = s3_interop_cm_conns;
        s3_interop_cm_conns = conn;

        s3_interop_cm_activity = s3_current_msec;
    }
}

/* the master tick: the parked stdin frames retry, the idle check
   closes the master with no live sessions and no control traffic */

static void
s3_interop_cm_tick(s3_event_t *ev)
{
    uint32_t i;

    ev->timedout = 0;

    if (s3_interop_cm_stop) {
        return;
    }

    for (i = 0; i < S3_SSH3_CM_SRV_SESSIONS; i++) {

        s3_interop_cm_run_t *run = &s3_interop_cm_runs[i];

        if (run->used && run->bridged && !run->finalized &&
            (run->stdin_len > 0 || run->frame_sent < run->frame_total)) {

            if (s3_interop_cm_run_stdin_pump(run) != S3_OK) {
                s3_interop_cm_run_finalize(run, 255);
                continue;
            }
        }
    }

    if (s3_interop_cm_idle_ms > 0 && s3_interop_cm_runs_live() == 0 &&
        s3_current_msec - s3_interop_cm_activity >= (s3_msec_t)s3_interop_cm_idle_ms) {

        fprintf(stderr, "interop-client: control master idle for %ldms, closing\n",
                s3_interop_cm_idle_ms);

        s3_interop_cm_shutdown();

        return;
    }

    s3_event_add_timer(ev, S3_INTEROP_CM_TICK_MS);
}

/* the ListenControlMaster port: the dial probe tells a live master
   from the stale file of a killed one before the unlink */

static s3_int_t
s3_interop_cm_listen_open(s3_event_ctx_t *ctx)
{
    struct sockaddr_un sa;
    int                fd, probe;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);

    if (fd == -1) {
        fprintf(stderr, "interop-client: socket() failed\n");

        return S3_ERROR;
    }

    (void)s3_nonblocking(fd);

    s3_memzero(&sa, sizeof(sa));

    sa.sun_family = AF_UNIX;

    if (strlen(s3_interop_cm_path) >= sizeof(sa.sun_path)) {
        fprintf(stderr, "interop-client: control path too long\n");
        (void)close(fd);

        return S3_ERROR;
    }

    strcpy(sa.sun_path, s3_interop_cm_path);

    /* a connect that succeeds proves a live listener owns the path */

    probe = socket(AF_UNIX, SOCK_STREAM, 0);

    if (probe != -1) {

        (void)s3_nonblocking(probe);

        if (connect(probe, (struct sockaddr *)&sa, sizeof(sa)) == 0 || errno == EINTR) {
            fprintf(stderr, "interop-client: a control master is already running on %s\n",
                    s3_interop_cm_path);
            (void)close(probe);
            (void)close(fd);

            return S3_ERROR;
        }

        (void)close(probe);
    }

    (void)unlink(s3_interop_cm_path);

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
        fprintf(stderr, "interop-client: bind(%s) failed\n", s3_interop_cm_path);
        (void)close(fd);

        return S3_ERROR;
    }

    if (listen(fd, 16) == -1) {
        fprintf(stderr, "interop-client: listen() failed\n");
        (void)close(fd);
        (void)unlink(s3_interop_cm_path);

        return S3_ERROR;
    }

    if (chmod(s3_interop_cm_path, 0600) == -1) {
        fprintf(stderr, "interop-client: chmod(%s) failed\n", s3_interop_cm_path);
        (void)close(fd);
        (void)unlink(s3_interop_cm_path);

        return S3_ERROR;
    }

    s3_interop_cm_listen_c = s3_get_connection(ctx, fd);

    if (s3_interop_cm_listen_c == NULL) {
        (void)close(fd);
        (void)unlink(s3_interop_cm_path);

        return S3_ERROR;
    }

    s3_interop_cm_listen_c->read->handler = s3_interop_cm_accept;
    s3_interop_cm_listen_c->read->data = s3_interop_cm_listen_c;

    if (s3_event_actions.add_event(s3_interop_cm_listen_c->read, S3_READ_EVENT, 0) != S3_OK) {
        (void)close(fd);
        (void)unlink(s3_interop_cm_path);

        return S3_ERROR;
    }

    s3_interop_cm_listen_fd = fd;
    s3_interop_cm_ctx = ctx;
    s3_interop_cm_started_ms = s3_current_msec;
    s3_interop_cm_activity = s3_current_msec;

    s3_interop_cm_timer.data = &s3_interop_cm_timer;
    s3_interop_cm_timer.log = &s3_interop_log;
    s3_interop_cm_timer.handler = s3_interop_cm_tick;

    s3_event_add_timer(&s3_interop_cm_timer, S3_INTEROP_CM_TICK_MS);

    s3_interop_cm_listening = 1;

    printf("S3CM-MASTER-LISTEN path=%s\n", s3_interop_cm_path);
    fflush(stdout);

    return S3_OK;
}

/*
 * === the slave and the control ops: the sequential Call clients over
 * poll(2), no quic state ===
 */

typedef struct {
    int      fd;
    u_char  *in;
    size_t   in_len;
    size_t   in_cap;
    unsigned eof;
} s3_interop_cm_side_t;

static s3_msec_t
s3_interop_cm_now(void)
{
    struct timespec ts;

    (void)clock_gettime(CLOCK_MONOTONIC, &ts);

    return (s3_msec_t)((s3_msec_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

static int
s3_interop_cm_dial(const char *path)
{
    struct sockaddr_un sa;
    int                fd;

    if (strlen(path) >= sizeof(sa.sun_path)) {
        return -1;
    }

    fd = socket(AF_UNIX, SOCK_STREAM, 0);

    if (fd == -1) {
        return -1;
    }

    s3_memzero(&sa, sizeof(sa));

    sa.sun_family = AF_UNIX;
    strcpy(sa.sun_path, path);

    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
        (void)close(fd);

        return -1;
    }

    return fd;
}

/* one more received chunk or eof; the poll slice keeps the deadline
   check running */

static s3_int_t
s3_interop_cm_side_fill(s3_interop_cm_side_t *t, s3_msec_t deadline)
{
    struct pollfd pfd;
    s3_msec_t     now, left;
    int           r, wait;
    ssize_t       n;

    for (;;) {

        now = s3_interop_cm_now();
        left = deadline > now ? deadline - now : 0;

        if (left == 0) {
            return S3_DECLINED; /* the deadline */
        }

        pfd.fd = t->fd;
        pfd.events = POLLIN;
        pfd.revents = 0;

        wait = left > 200 ? 200 : (int)left;

        r = poll(&pfd, 1, wait);

        if (r < 0) {

            if (errno == EINTR) {
                continue;
            }

            return S3_ERROR;
        }

        if (r == 0) {
            continue;
        }

        n = recv(t->fd, t->in + t->in_len, t->in_cap - t->in_len, 0);

        if (n == 0) {
            t->eof = 1;

            return S3_DECLINED;
        }

        if (n < 0) {

            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }

            return S3_ERROR;
        }

        t->in_len += (size_t)n;

        return S3_OK;
    }
}

static s3_int_t
s3_interop_cm_side_in(s3_interop_cm_side_t *t, size_t need)
{
    u_char *grown;
    size_t  cap;

    if (t->in != NULL && t->in_cap - t->in_len >= need) {
        return S3_OK;
    }

    cap = t->in_cap != 0 ? t->in_cap : S3_INTEROP_CM_BUF_INIT;

    while (cap - t->in_len < need) {
        cap *= 2;
    }

    grown = realloc(t->in, cap);

    if (grown == NULL) {
        return S3_ERROR;
    }

    t->in = grown;
    t->in_cap = cap;

    return S3_OK;
}

/* the strict Call of protocol.go: the request drains out, the reply
   feeds the cli state machine one complete frame at a time so a
   coalesced tail (the later exit status) stays app-owned */

static s3_int_t
s3_interop_cm_call(s3_interop_cm_side_t *t, s3_ssh3_cm_cli_t *cli, uint8_t type,
                   const s3_str_t *payload, s3_str_t *reply, unsigned *is_error, s3_msec_t deadline,
                   const char *what)
{
    u_char             buf[4096];
    const u_char      *scan, *end;
    s3_ssh3_cm_frame_t f;
    s3_int_t           rc;
    size_t             flen;
    ssize_t            n, m;

    if (s3_ssh3_cm_cli_call(cli, type, payload) != S3_OK) {
        fprintf(stderr, "interop-client: %s: call failed\n", what);

        return S3_ERROR;
    }

    for (;;) {

        n = s3_ssh3_cm_cli_output(cli, buf, sizeof(buf));

        if (n <= 0) {
            break;
        }

        m = send(t->fd, buf, (size_t)n, 0);

        if (m != n) {
            fprintf(stderr, "interop-client: %s: send failed\n", what);

            return S3_ERROR;
        }
    }

    for (;;) {

        scan = t->in;
        end = t->in + t->in_len;

        rc = s3_ssh3_cm_frame(&scan, end, &f);

        if (rc == S3_AGAIN) {

            if (t->eof) {
                fprintf(stderr, "interop-client: %s: control conn closed\n", what);

                return S3_ERROR;
            }

            if (s3_interop_cm_side_in(t, 1) != S3_OK ||
                s3_interop_cm_side_fill(t, deadline) != S3_OK) {
                fprintf(stderr, "interop-client: %s: no reply\n", what);

                return S3_ERROR;
            }

            continue;
        }

        if (rc != S3_OK) {
            fprintf(stderr, "interop-client: %s: bad frame\n", what);

            return S3_ERROR;
        }

        flen = (size_t)(scan - t->in);

        if (s3_ssh3_cm_cli_input(cli, t->in, flen) != S3_OK || s3_ssh3_cm_cli_protocol_error(cli)) {
            fprintf(stderr, "interop-client: %s: protocol violation\n", what);

            return S3_ERROR;
        }

        t->in_len -= flen;
        s3_memmove(t->in, t->in + flen, t->in_len);

        rc = s3_ssh3_cm_cli_reply(cli, reply, is_error);

        if (rc == S3_OK) {
            return S3_OK;
        }

        if (rc != S3_AGAIN) {
            fprintf(stderr, "interop-client: %s: reply state failed\n", what);

            return S3_ERROR;
        }
    }
}

/* the attach dial of attachCM: hello, then the attach call */

static s3_int_t
s3_interop_cm_attach(s3_pool_t *pool, s3_interop_cm_side_t *t, const char *path,
                     const u_char token[S3_SSH3_CM_TOKEN_LEN], uint8_t kind, s3_msec_t deadline)
{
    s3_ssh3_cm_cli_t cli;
    u_char           enc[S3_SSH3_CM_TOKEN_LEN + 1];
    s3_str_t         pl, reply;
    unsigned         is_error;

    t->fd = s3_interop_cm_dial(path);

    if (t->fd < 0) {
        fprintf(stderr, "interop-client: attach: could not reach the control master\n");

        return S3_ERROR;
    }

    if (s3_ssh3_cm_cli_init(&cli, pool) != S3_OK) {
        return S3_ERROR;
    }

    if (s3_interop_cm_call(t, &cli, S3_SSH3_CM_MSG_HELLO, NULL, &reply, &is_error, deadline,
                           "attach hello") != S3_OK) {
        return S3_ERROR;
    }

    if (is_error) {
        fprintf(stderr, "interop-client: attach: master refused the hello\n");

        return S3_ERROR;
    }

    s3_memcpy(enc, token, S3_SSH3_CM_TOKEN_LEN);
    enc[S3_SSH3_CM_TOKEN_LEN] = kind;

    pl.data = enc;
    pl.len = sizeof(enc);

    if (s3_interop_cm_call(t, &cli, S3_SSH3_CM_MSG_ATTACH, &pl, &reply, &is_error, deadline,
                           "attach") != S3_OK) {
        return S3_ERROR;
    }

    if (is_error) {
        fprintf(stderr, "interop-client: attach refused: %.*s\n", (int)reply.len,
                (const char *)reply.data);

        return S3_ERROR;
    }

    return S3_OK;
}

/* the growable accumulators of the slave streams */

static s3_int_t
s3_interop_cm_acc(u_char **buf, size_t *len, size_t *cap, const u_char *data, size_t n)
{
    u_char *grown;
    size_t  want;

    if (*cap - *len < n) {

        want = *cap != 0 ? *cap : S3_INTEROP_CM_BUF_INIT;

        while (want - *len < n) {
            want *= 2;
        }

        grown = realloc(*buf, want);

        if (grown == NULL) {
            return S3_ERROR;
        }

        *buf = grown;
        *cap = want;
    }

    if (n > 0) {
        s3_memcpy(*buf + *len, data, n);
        *len += n;
    }

    return S3_OK;
}

static unsigned
s3_interop_cm_acc_has(const u_char *buf, size_t len, const char *text)
{
    size_t n = strlen(text), i;

    if (len < n) {
        return 0;
    }

    for (i = 0; i + n <= len; i++) {

        if (s3_memcmp(buf + i, text, n) == 0) {
            return 1;
        }
    }

    return 0;
}

/*
 * the slave (-U path -e cmd): the control conn carries the session
 * request and the exit status, the stderr and io attachments bridge on
 * their own connections (stderr first, like the reference); the pump
 * waits for the exit status AND the stream eofs, the master closes the
 * attachments only after the data drained
 */

static int
s3_interop_cm_slave(unsigned timeout_ms)
{
    s3_pool_t                *pool;
    s3_ssh3_cm_cli_t          cli;
    s3_interop_cm_side_t      control, io, err;
    s3_ssh3_cm_open_session_t req;
    s3_str_t                  payload, reply;
    u_char                   *enc;
    unsigned                  is_error;
    u_char                   *out_buf = NULL, *err_buf = NULL;
    size_t                    out_len = 0, out_cap = 0, err_len = 0, err_cap = 0;
    struct pollfd             pfd[3];
    s3_msec_t                 deadline;
    uint64_t                  code = 256;
    unsigned                  got_exit = 0, io_eof = 0, err_eof = 0, ok;
    const char               *cmd, *needle;
    const u_char             *scan, *end;
    s3_ssh3_cm_frame_t        fr;
    s3_int_t                  rc;
    uintptr_t                 size;
    ssize_t                   n;
    int                       rc_exit = 1;

    s3_memzero(&control, sizeof(control));
    s3_memzero(&io, sizeof(io));
    s3_memzero(&err, sizeof(err));

    pool = s3_create_pool(S3_DEFAULT_POOL_SIZE, &s3_interop_log);

    if (pool == NULL) {
        fprintf(stderr, "interop-client: slave pool failed\n");

        return 1;
    }

    deadline = s3_interop_cm_now() + (s3_msec_t)timeout_ms;

    control.fd = s3_interop_cm_dial(s3_interop_cm_path);

    if (control.fd < 0) {
        fprintf(stderr, "interop-client: no control master is listening on %s\n",
                s3_interop_cm_path);
        goto done;
    }

    if (s3_interop_cm_side_in(&control, 512) != S3_OK) {
        fprintf(stderr, "interop-client: slave buffer failed\n");
        goto done;
    }

    if (s3_ssh3_cm_cli_init(&cli, pool) != S3_OK) {
        goto done;
    }

    /* the version handshake */

    if (s3_interop_cm_call(&control, &cli, S3_SSH3_CM_MSG_HELLO, NULL, &reply, &is_error, deadline,
                           "hello") != S3_OK ||
        is_error) {
        fprintf(stderr, "interop-client: the peer on %s is not a control master\n",
                s3_interop_cm_path);
        goto done;
    }

    /* the session request: one command string, no env, no agent */

    cmd = s3_interop_exec_cmd != NULL ? s3_interop_exec_cmd : "printf s3-exec-ok";

    s3_memzero(&req, sizeof(req));

    req.ncommand = 1;
    req.command[0].data = (u_char *)cmd;
    req.command[0].len = strlen(cmd);

    size = s3_ssh3_cm_encode_open_session(NULL, &req);
    enc = s3_pnalloc(pool, size);

    if (enc == NULL) {
        goto done;
    }

    (void)s3_ssh3_cm_encode_open_session(enc, &req);

    payload.data = enc;
    payload.len = size;

    if (s3_interop_cm_call(&control, &cli, S3_SSH3_CM_MSG_OPEN_SESSION, &payload, &reply, &is_error,
                           deadline, "open_session") != S3_OK) {
        goto done;
    }

    if (is_error) {
        fprintf(stderr, "interop-client: session refused: %.*s\n", (int)reply.len,
                (const char *)reply.data);
        goto done;
    }

    if (reply.len != S3_SSH3_CM_TOKEN_LEN) {
        fprintf(stderr, "interop-client: malformed session token reply (%zu bytes)\n", reply.len);
        goto done;
    }

    if (s3_interop_cm_side_in(&io, 512) != S3_OK || s3_interop_cm_side_in(&err, 512) != S3_OK) {
        goto done;
    }

    /* the stderr stream attaches before the io stream (the reference order) */

    if (s3_interop_cm_attach(pool, &err, s3_interop_cm_path, reply.data, S3_SSH3_CM_STREAM_STDERR,
                             deadline) != S3_OK ||
        s3_interop_cm_attach(pool, &io, s3_interop_cm_path, reply.data, S3_SSH3_CM_STREAM_IO,
                             deadline) != S3_OK) {
        goto done;
    }

    /* the harness stdin is empty, the close tells the master the input is over */

    (void)shutdown(io.fd, SHUT_WR);

    while (!got_exit || !io_eof || !err_eof) {

        int r, nfds = 0;

        if (s3_interop_cm_now() >= deadline) {
            fprintf(stderr, "interop-client: slave timed out\n");
            goto done;
        }

        if (!control.eof && !got_exit) {
            pfd[nfds].fd = control.fd;
            pfd[nfds++].events = POLLIN;
        }

        if (!io_eof) {
            pfd[nfds].fd = io.fd;
            pfd[nfds++].events = POLLIN;
        }

        if (!err_eof) {
            pfd[nfds].fd = err.fd;
            pfd[nfds++].events = POLLIN;
        }

        if (nfds == 0) {
            break;
        }

        r = poll(pfd, (nfds_t)nfds, 200);

        if (r <= 0) {

            if (r < 0 && errno != EINTR) {
                fprintf(stderr, "interop-client: slave poll failed\n");
                goto done;
            }

            continue;
        }

        for (n = 0; n < nfds; n++) {

            u_char  buf[16384];
            int     cfd = pfd[n].fd;
            ssize_t m;

            if ((pfd[n].revents & POLLIN) == 0) {
                continue;
            }

            m = recv(cfd, buf, sizeof(buf), 0);

            if (m < 0) {
                continue;
            }

            if (m == 0) {

                if (cfd == io.fd) {
                    io_eof = 1;

                } else if (cfd == err.fd) {
                    err_eof = 1;

                } else {
                    control.eof = 1;

                    if (!got_exit) {

                        /* the master dropped the control conn: 255 */
                        code = 255;
                        got_exit = 1;
                    }
                }

                continue;
            }

            if (cfd == io.fd) {

                if (s3_interop_cm_acc(&out_buf, &out_len, &out_cap, buf, (size_t)m) != S3_OK) {
                    goto done;
                }

            } else if (cfd == err.fd) {

                if (s3_interop_cm_acc(&err_buf, &err_len, &err_cap, buf, (size_t)m) != S3_OK) {
                    goto done;
                }

            } else {

                /* the session tail: the exit status frame of the bridge */

                if (s3_interop_cm_acc(&control.in, &control.in_len, &control.in_cap, buf,
                                      (size_t)m) != S3_OK) {
                    goto done;
                }

                scan = control.in;
                end = control.in + control.in_len;

                while (scan < end) {

                    rc = s3_ssh3_cm_frame(&scan, end, &fr);

                    if (rc == S3_AGAIN) {
                        break;
                    }

                    if (rc != S3_OK) {
                        fprintf(stderr, "interop-client: slave: bad control frame\n");
                        goto done;
                    }

                    if (fr.type == S3_SSH3_CM_MSG_EXIT_STATUS &&
                        s3_ssh3_cm_decode_exit_status(&fr.payload, &code) == S3_OK) {
                        got_exit = 1;
                    }

                    /* the other tail frames of the session drain */
                }

                control.in_len = (size_t)(end - scan);
                s3_memmove(control.in, scan, control.in_len);
            }
        }
    }

    if (out_len > 0) {
        printf("S3CM-SLAVE-OUT %.*s\n", (int)(out_len > 4096 ? 4096 : out_len),
               (const char *)out_buf);
    }

    needle = s3_interop_exec_cmd != NULL ? NULL : "s3-exec-ok";

    ok = code == 0 && (needle == NULL || s3_interop_cm_acc_has(out_buf, out_len, needle));

    if (ok) {
        printf("INTEROP-EXEC-OK exit=0\n");

    } else {
        printf("INTEROP-EXEC-FAIL exit=%llu\n", (unsigned long long)code);
    }

    printf("S3CM-SLAVE-DONE exit=%llu\n", (unsigned long long)code);
    fflush(stdout);

    rc_exit = ok ? 0 : 1;

done:

    if (control.fd >= 0) {
        (void)close(control.fd);
    }

    if (io.fd >= 0) {
        (void)close(io.fd);
    }

    if (err.fd >= 0) {
        (void)close(err.fd);
    }

    free(out_buf);
    free(err_buf);
    free(control.in);
    free(io.in);
    free(err.in);

    if (pool != NULL) {
        s3_destroy_pool(pool);
    }

    return rc_exit;
}

/* the check reply parse: the flat JSON of MasterStatus, the values the
   CLI line reports */

static long
s3_interop_cm_json_long(const char *json, const char *key)
{
    char        pat[32];
    const char *p;

    snprintf(pat, sizeof(pat), "\"%s\":", key);

    p = strstr(json, pat);

    if (p == NULL) {
        return -1;
    }

    return strtol(p + strlen(pat), NULL, 10);
}

static double
s3_interop_cm_json_double(const char *json, const char *key)
{
    char        pat[32];
    const char *p;

    snprintf(pat, sizeof(pat), "\"%s\":", key);

    p = strstr(json, pat);

    if (p == NULL) {
        return -1;
    }

    return strtod(p + strlen(pat), NULL);
}

static int
s3_interop_cm_control_op(void)
{
    s3_pool_t           *pool = NULL;
    s3_ssh3_cm_cli_t     cli;
    s3_interop_cm_side_t side;
    s3_str_t             op, pl, reply;
    u_char              *enc;
    unsigned             is_error;
    s3_msec_t            deadline;
    uintptr_t            size;
    int                  rc = 1;

    s3_memzero(&side, sizeof(side));
    s3_memzero(&cli, sizeof(cli));

    side.fd = s3_interop_cm_dial(s3_interop_cm_path);

    if (side.fd < 0) {
        fprintf(stderr, "interop-client: no control master is listening on %s\n",
                s3_interop_cm_path);

        return 1;
    }

    if (s3_interop_cm_side_in(&side, 512) != S3_OK) {
        goto done;
    }

    pool = s3_create_pool(S3_DEFAULT_POOL_SIZE, &s3_interop_log);

    if (pool == NULL) {
        goto done;
    }

    if (s3_ssh3_cm_cli_init(&cli, pool) != S3_OK) {
        goto done;
    }

    deadline = s3_interop_cm_now() + 10000;

    if (s3_interop_cm_call(&side, &cli, S3_SSH3_CM_MSG_HELLO, NULL, &reply, &is_error, deadline,
                           "hello") != S3_OK ||
        is_error) {
        fprintf(stderr, "interop-client: the peer on %s is not a control master\n",
                s3_interop_cm_path);
        goto done;
    }

    /* the op payload carries the uint32 length prefix (encode_control_op) */

    op.data = (u_char *)s3_interop_cm_op;
    op.len = strlen(s3_interop_cm_op);

    size = s3_ssh3_cm_encode_control_op(NULL, &op);
    enc = s3_pnalloc(pool, size);

    if (enc == NULL) {
        goto done;
    }

    (void)s3_ssh3_cm_encode_control_op(enc, &op);

    pl.data = enc;
    pl.len = size;

    if (s3_interop_cm_call(&side, &cli, S3_SSH3_CM_MSG_CONTROL_OP, &pl, &reply, &is_error, deadline,
                           s3_interop_cm_op) != S3_OK) {
        goto done;
    }

    if (is_error) {
        fprintf(stderr, "interop-client: the control master refused %s: %.*s\n", s3_interop_cm_op,
                (int)reply.len, (const char *)reply.data);
        goto done;
    }

    if (strcmp(s3_interop_cm_op, S3_SSH3_CM_OP_CHECK) == 0) {

        char *json = s3_pnalloc(pool, reply.len + 1);

        if (json == NULL) {
            goto done;
        }

        s3_memcpy(json, reply.data, reply.len);
        json[reply.len] = '\0';

        printf("Master running (pid=%ld), uptime %.3fs, %ld session(s), %ld forward(s)\n",
               s3_interop_cm_json_long(json, "pid"), s3_interop_cm_json_double(json, "uptime_s"),
               s3_interop_cm_json_long(json, "sessions"),
               s3_interop_cm_json_long(json, "forwards"));

        fflush(stdout);

        rc = 0;

    } else {

        /* the master answered: wait for it to release the socket path */

        unsigned        released = 0;
        int             i;
        struct timespec pause = {0, 2 * 1000 * 1000};

        for (i = 0; i < 1000; i++) {

            int probe = s3_interop_cm_dial(s3_interop_cm_path);

            if (probe < 0) {
                released = 1;
                break;
            }

            (void)close(probe);
            (void)nanosleep(&pause, NULL);
        }

        if (!released) {
            fprintf(stderr, "interop-client: the control master has not released %s\n",
                    s3_interop_cm_path);

            goto done;
        }

        printf("Master stopped\n");
        fflush(stdout);

        rc = 0;
    }

done:

    if (side.fd >= 0) {
        (void)close(side.fd);
    }

    free(side.in);

    if (pool != NULL) {
        s3_destroy_pool(pool);
    }

    return rc;
}

/*
 * the session reader (-3 -C -S exec|pty|kill): the first message must be
 * the 91 confirmation, then the 94 payloads accumulate into the stdout
 * buffer and the 98 envelopes dispatch by the request kind; the
 * verdict is the 98 exit-status (the exec wants zero with the marker
 * printed, the pty and the kill want 137 = 128 + SIGKILL).  A request
 * body has no length prefix on the wire, it runs to the end of the
 * received data, so a truncated tail waits for the next recv
 */
static void
s3_interop_h3_session_read(s3_event_t *ev)
{
    s3_connection_t *sc;
    const u_char    *pos, *end;
    ssize_t          n;

    if (s3_interop_h3_ch_ok) {
        /* after the verdict the queued teardown read events may arrive */
        return;
    }

    sc = ev->data;

    for (;;) {

        if (s3_interop_h3_ch_len == s3_interop_h3_ch_cap) {
            size_t  cap = s3_interop_h3_ch_cap + 262144;
            u_char *grown = realloc(s3_interop_h3_ch_buf, cap);

            if (grown == NULL) {
                fprintf(stderr, "interop-client: channel buffer growth failed\n");
                exit(1);
            }

            s3_interop_h3_ch_buf = grown;
            s3_interop_h3_ch_cap = cap;
        }

        n = sc->recv(sc, s3_interop_h3_ch_buf + s3_interop_h3_ch_len,
                     s3_interop_h3_ch_cap - s3_interop_h3_ch_len);

        if (n == (ssize_t)S3_AGAIN) {
            return;
        }

        if (n == 0) {
            /* the server fin before the exit-status: no verdict */
            fprintf(stderr, "interop-client: channel closed before the session verdict\n");
            exit(1);
        }

        if (n < 0) {
            fprintf(stderr, "interop-client: channel recv error\n");
            exit(1);
        }

        s3_interop_h3_ch_len += (size_t)n;

        pos = s3_interop_h3_ch_buf;
        end = s3_interop_h3_ch_buf + s3_interop_h3_ch_len;

        while (pos < end) {

            uint64_t type;

            if (s3_ssh3_parse_varint(&pos, end, &type) != S3_OK) {
                /* a partial type varint, the next recv completes it */
                break;
            }

            if (type == S3_SSH3_MSG_CHANNEL_OPEN_CONFIRMATION) {

                s3_ssh3_msg_open_confirmation_t conf;

                if (s3_interop_h3_ch_confirmed) {
                    fprintf(stderr, "interop-client: duplicate channel confirmation\n");
                    exit(1);
                }

                if (s3_ssh3_msg_parse_open_confirmation(&pos, end, &conf) != S3_OK) {
                    break;
                }

                s3_interop_h3_ch_confirmed = 1;

                continue;
            }

            if (type == S3_SSH3_MSG_CHANNEL_DATA) {

                s3_ssh3_msg_data_t msg;

                if (!s3_interop_h3_ch_confirmed) {
                    fprintf(stderr, "interop-client: channel data before confirmation\n");
                    exit(1);
                }

                if (s3_ssh3_msg_parse_data(&pos, end, &msg) != S3_OK) {
                    break;
                }

                /* the stdout accumulates for the verdict */

                s3_interop_h3_sess_append(msg.data.data, msg.data.len);

                /*
                 * the pty run signals when the resized geometry came
                 * back ("40 100" = rows columns after window-change)
                 */

                if (s3_interop_h3_session_mode == S3_INTEROP_SESSION_PTY &&
                    !s3_interop_h3_sess_signal_pending && s3_interop_h3_sess_has("40 100", 6)) {
                    s3_interop_h3_sess_signal_pending = 1;
                }

                continue;
            }

            if (type == S3_SSH3_MSG_CHANNEL_EXTENDED_DATA) {

                s3_ssh3_msg_extended_data_t xmsg;

                if (s3_ssh3_msg_parse_extended_data(&pos, end, &xmsg) != S3_OK) {
                    break;
                }

                /* the stderr side is drained, nothing verdicts on it */
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
                        s3_interop_h3_session_verdict(body.u.exit_status.status);

                        return;
                    }

                    /* the replies without the verdict power are drained */
                    continue;
                }

                if (rc == S3_DECLINED) {

                    /*
                     * an unknown request type: its body has no length
                     * prefix on the wire, the buffer tail drains
                     */
                    pos = end;

                    continue;
                }

                /* S3_ERROR: a partial body, the next recv completes it */
                break;
            }

            fprintf(stderr, "interop-client: unexpected channel message %llu\n",
                    (unsigned long long)type);
            exit(1);
        }

        /* the consumed bytes compact to the front of the receive buffer */
        s3_interop_h3_ch_len = (size_t)(end - pos);
        s3_memmove(s3_interop_h3_ch_buf, pos, s3_interop_h3_ch_len);
    }
}

static void
s3_interop_h3_client_stream(s3_connection_t *c, s3_quic_stream_t *qs)
{
    s3_connection_t *pc;
    s3_event_t      *rev;

    /*
     * the h3 client side (-3): the server-initiated streams are the
     * uni control/encoder/decoder ones, they belong to the session
     * port; the port reads the stream connection's data as the
     * s3_quic_stream_t.  The CONNECT stream is opened locally
     *
     * the wave 2: the server-initiated BIDI streams are the ssh3
     * channels the server opens (the agent connections); the bridge
     * half of the forwarding lives in s3_interop_agent_read()
     */

    pc = qs->parent;

    if ((qs->id & 0x3) == 0x1) {

        if (!s3_interop_agent_mode || s3_interop_agent_sc != NULL) {

            /* one bridge at a time, the unexpected channels shut down */

            (void)s3_quic_cancelable_stream(c);
            (void)s3_quic_shutdown_stream(c, S3_RDWR_SHUTDOWN);
            return;
        }

        rev = c->read;
        rev->handler = s3_interop_agent_read;
        rev->data = c;
        rev->active = 1;

        /* the header may have landed before the arming, same as the
         * channel accept path reads right in the handler */

        if (rev->ready) {
            rev->handler(rev);
        }

        return;
    }

    /*
     * the quic layer may hand us a peer uni stream before the event
     * loop reached the session bring-up (the quic-go server opens its
     * control stream at once); the session is created once, from
     * whichever comes first, the same lazy bring-up the server does
     * in its accept path
     */

    if (s3_h3_get_session(pc) == NULL) {

        if (s3_h3_init_session(pc) != S3_OK) {
            fprintf(stderr, "interop-client: h3 init_session failed\n");
            return;
        }
    }

    s3_h3_init_stream(c);
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
    if (port == 0 || port > 65535) {
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
        fprintf(stderr, "interop-client: bad alpn name\n");
        exit(1);
    }

    wire[0] = (u_char)n;
    memcpy(wire + 1, name, n);
}

/* === the proxy jump (-j, the tunnel and the loopback bridge) === */

/*
 * the datagram handler of the jump conversation: the tunnel frames
 * carry the prefix of the direct-udp channel, the payloads are the
 * raw quic packets of the inner connection, one send() into the
 * bridge socket b delivers them; a dropped datagram stays a loss the
 * inner connection recovers from (RFC 768, RFC 9002)
 */
static void
s3_interop_jump_datagram(s3_connection_t *c, s3_chain_t *data)
{
    u_char        flat[S3_INTEROP_JUMP_INNER_MTU + 16];
    u_char       *p;
    size_t        len = 0;
    s3_chain_t   *cl;
    const u_char *pos, *end;
    uint64_t      csid, chid;
    s3_str_t      payload;
    ssize_t       n;

    (void)c;

    if (s3_interop_bridge_b < 0) {
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

    if (csid != s3_interop_jump_conv_id || chid != s3_interop_jump_ch_id) {
        return;
    }

    n = send(s3_interop_bridge_b, payload.data, payload.len, 0);

    if (n == (ssize_t)payload.len) {
        s3_interop_jump_recv++;
    }
}

/*
 * the tunnel side of the bridge: the quic packets of the inner
 * connection recv straight behind the prefix (the payload bytes never
 * move), one datagram per send; the congested channel parks the
 * frame and puts the read event to sleep until the flush drains it
 */
static void
s3_interop_bridge_read(s3_event_t *ev)
{
    size_t  pre;
    ssize_t n;

    if (s3_interop_bridge_parked > 0) {
        return;
    }

    pre = s3_ssh3_dgram_prefix_size(s3_interop_jump_conv_id, s3_interop_jump_ch_id);

    for (;;) {

        n = recv(s3_interop_bridge_b, s3_interop_bridge_frame + pre,
                 sizeof(s3_interop_bridge_frame) - pre, 0);

        if (n < 0) {

            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            }

            fprintf(stderr, "interop-client: bridge recv failed\n");
            exit(1);
        }

        if (n == 0) {
            /* a zero-length datagram carries nothing */
            continue;
        }

        if ((size_t)n > S3_INTEROP_JUMP_INNER_MTU) {
            /* the inner packets are pinned to the cap, the rest drops */
            continue;
        }

        {
            u_char *p = s3_interop_bridge_frame;
            size_t  len;

            p = (u_char *)s3_ssh3_encode_varint(p, s3_interop_jump_conv_id);
            p = (u_char *)s3_ssh3_encode_varint(p, s3_interop_jump_ch_id);

            len = (size_t)(p - s3_interop_bridge_frame) + (size_t)n;

            if (s3_quic_send_datagram(s3_interop_jump_cli, s3_interop_bridge_frame, len) != S3_OK) {

                /* the channel is full: park the frame, the read
                 * event sleeps until the flush drains the queue */

                s3_interop_bridge_parked = len;

                (void)s3_event_actions.del_event(ev, S3_READ_EVENT, 0);

                return;
            }

            s3_interop_jump_sent++;
        }
    }
}

/* the parked frame retries each pass, the read event wakes on success */

static void
s3_interop_bridge_flush(void)
{
    if (s3_interop_bridge_parked == 0) {
        return;
    }

    if (s3_quic_send_datagram(s3_interop_jump_cli, s3_interop_bridge_frame,
                              s3_interop_bridge_parked) != S3_OK) {
        /* still congested, the next pass retries */
        return;
    }

    s3_interop_jump_sent++;
    s3_interop_bridge_parked = 0;

    (void)s3_event_actions.add_event(s3_interop_bridge_bc->read, S3_READ_EVENT, 0);
}

/*
 * the loopback socket pair: two udp sockets bound to 127.0.0.1:0 and
 * connected to each other, a becomes the fd of the inner quic
 * connection, b is the tunnel side the bridge reads
 */
static s3_int_t
s3_interop_bridge_create(s3_event_ctx_t *ctx)
{
    struct sockaddr_in a, b;
    socklen_t          len;

    s3_memzero(&a, sizeof(a));
    s3_memzero(&b, sizeof(b));

    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    s3_interop_bridge_a = socket(AF_INET, SOCK_DGRAM, 0);
    s3_interop_bridge_b = socket(AF_INET, SOCK_DGRAM, 0);

    if (s3_interop_bridge_a == -1 || s3_interop_bridge_b == -1) {
        perror("socket");
        return S3_ERROR;
    }

    if (s3_nonblocking(s3_interop_bridge_a) != S3_OK ||
        s3_nonblocking(s3_interop_bridge_b) != S3_OK) {
        perror("fcntl(O_NONBLOCK)");
        return S3_ERROR;
    }

    if (bind(s3_interop_bridge_a, (struct sockaddr *)&a, sizeof(a)) == -1) {
        perror("bind");
        return S3_ERROR;
    }

    len = sizeof(a);

    if (getsockname(s3_interop_bridge_a, (struct sockaddr *)&a, &len) == -1) {
        perror("getsockname");
        return S3_ERROR;
    }

    b = a;
    b.sin_port = 0;

    if (bind(s3_interop_bridge_b, (struct sockaddr *)&b, sizeof(b)) == -1) {
        perror("bind");
        return S3_ERROR;
    }

    len = sizeof(b);

    if (getsockname(s3_interop_bridge_b, (struct sockaddr *)&b, &len) == -1) {
        perror("getsockname");
        return S3_ERROR;
    }

    s3_interop_bridge_sa = b;

    if (connect(s3_interop_bridge_a, (struct sockaddr *)&b, sizeof(b)) == -1 ||
        connect(s3_interop_bridge_b, (struct sockaddr *)&a, sizeof(a)) == -1) {
        perror("connect");
        return S3_ERROR;
    }

    s3_interop_bridge_bc = s3_get_connection(ctx, s3_interop_bridge_b);

    if (s3_interop_bridge_bc == NULL) {
        fprintf(stderr, "interop-client: bridge connection alloc failed\n");
        return S3_ERROR;
    }

    s3_interop_bridge_bc->read->handler = s3_interop_bridge_read;

    return s3_event_actions.add_event(s3_interop_bridge_bc->read, S3_READ_EVENT, 0);
}

/*
 * the jump channel reader: the direct-udp channel carries no stream
 * data, the run starts once the 91 confirmation came back
 */
static void
s3_interop_jump_ch_read(s3_event_t *ev)
{
    s3_connection_t *sc;
    const u_char    *pos, *end;
    ssize_t          n;

    if (s3_interop_jump_ch_confirmed) {
        return;
    }

    sc = ev->data;

    n = sc->recv(sc, s3_interop_jump_ch_buf + s3_interop_jump_ch_len,
                 sizeof(s3_interop_jump_ch_buf) - s3_interop_jump_ch_len);

    if (n == (ssize_t)S3_AGAIN) {
        return;
    }

    if (n <= 0) {
        fprintf(stderr, "interop-client: jump channel closed before the confirmation\n");
        exit(1);
    }

    s3_interop_jump_ch_len += (size_t)n;

    pos = s3_interop_jump_ch_buf;
    end = s3_interop_jump_ch_buf + s3_interop_jump_ch_len;

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

            s3_interop_jump_ch_confirmed = 1;
            continue;
        }

        fprintf(stderr, "interop-client: unexpected jump channel message %llu\n",
                (unsigned long long)type);
        exit(1);
    }

    /* the consumed bytes compact to the front of the accumulator */

    s3_interop_jump_ch_len = (size_t)(end - pos);
    s3_memmove(s3_interop_jump_ch_buf, pos, s3_interop_jump_ch_len);
}

/*
 * phase 1 of the proxy jump: the connection to the jump host runs the
 * byte-for-byte normal h3 bring-up, the CONNECT answers 200 and the
 * direct-udp channel to the inner server address confirms; the jump
 * connection stays open for the whole run, its events ride the same
 * loop the inner connection uses below
 */
static s3_int_t
s3_interop_jump_dial(s3_event_ctx_t *ctx, s3_msec_t start, s3_msec_t timeout)
{
    u_char                alpn_wire[256];
    s3_str_t              alpn;
    s3_quic_conf_t       *conf = &s3_interop_jump_conf;
    s3_fd_t               fd;
    unsigned              hs_reported = 0;
    s3_quic_connection_t *qc;
    s3_uint_t             i;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (fd == -1) {
        perror("socket");
        return S3_ERROR;
    }

    if (s3_nonblocking(fd) != S3_OK) {
        perror("fcntl(O_NONBLOCK)");
        return S3_ERROR;
    }

    s3_interop_jump_cli = s3_get_connection(ctx, fd);

    if (s3_interop_jump_cli == NULL) {
        fprintf(stderr, "interop-client: jump connection alloc failed\n");
        return S3_ERROR;
    }

    s3_interop_jump_fd = fd;

    s3_interop_jump_cli->pool = s3_create_pool((size_t)S3_DEFAULT_POOL_SIZE, &s3_interop_log);

    if (s3_interop_jump_cli->pool == NULL) {
        return S3_ERROR;
    }

    s3_interop_jump_cli->sockaddr =
        (struct sockaddr *)s3_palloc(s3_interop_jump_cli->pool, sizeof(s3_interop_jump_sa));

    if (s3_interop_jump_cli->sockaddr == NULL) {
        return S3_ERROR;
    }

    s3_memcpy(s3_interop_jump_cli->sockaddr, &s3_interop_jump_sa, sizeof(s3_interop_jump_sa));
    s3_interop_jump_cli->socklen = sizeof(s3_interop_jump_sa);

    s3_interop_alpn_wire(alpn_wire, "h3");

    alpn.data = alpn_wire;
    alpn.len = 1 + strlen("h3");

    s3_memzero(conf, sizeof(s3_quic_conf_t));

    conf->ssl = s3_ssl_client_create(&s3_interop_log, &alpn);

    if (conf->ssl == NULL) {
        fprintf(stderr, "interop-client: jump ssl init failed\n");
        return S3_ERROR;
    }

    conf->gso_enabled = 1;
    conf->ctx = ctx;
    conf->handshake_timeout = timeout;
    conf->idle_timeout = 60000;
    conf->stream_buffer_size = 16384;
    conf->max_concurrent_streams_bidi = 16;
    conf->max_concurrent_streams_uni = 16;
    conf->active_connection_id_limit = 8;

    /*
     * the tunnel frames carry the 1200-byte inner packets with the
     * prefix on top, the advertised acceptance must cover them
     */
    conf->max_datagram_frame_size = S3_INTEROP_JUMP_DGRAM_SIZE;

    conf->datagram_handler = s3_interop_jump_datagram;

    /* the server's uni streams go to the session port, like at home */
    conf->stream_handler = s3_interop_h3_client_stream;

    for (i = 0; i < S3_QUIC_AV_KEY_LEN; i++) {
        conf->av_token_key[i] = (u_char)(0xa0 + i);
        conf->sr_token_key[i] = (u_char)(0xb0 + i);
    }

    if (s3_event_actions.add_event(s3_interop_jump_cli->read, S3_READ_EVENT, 0) != S3_OK) {
        return S3_ERROR;
    }

    if (s3_quic_connect(s3_interop_jump_cli, conf) != S3_OK) {
        fprintf(stderr, "interop-client: jump connect failed\n");
        return S3_ERROR;
    }

    for (;;) {

        s3_event_process_posted(ctx, &ctx->posted_events);

        s3_process_events_and_timers(ctx);

        qc = s3_quic_get_connection(s3_interop_jump_cli);

        if (qc == NULL) {
            fprintf(stderr, "interop-client: jump connection is gone\n");
            return S3_ERROR;
        }

        if (!hs_reported && s3_interop_jump_cli->ssl != NULL &&
            s3_interop_jump_cli->ssl->handshaked) {

            hs_reported = 1;

            /*
             * the h3 session first, the same the main run does: the
             * SETTINGS go out on the control stream before the
             * request stream
             */
            if (s3_h3_get_session(s3_interop_jump_cli) == NULL &&
                s3_h3_init_session(s3_interop_jump_cli) != S3_OK) {
                fprintf(stderr, "interop-client: jump h3 init_session failed\n");
                return S3_ERROR;
            }

            s3_memzero(&s3_interop_h3_parse, sizeof(s3_h3_parse_headers_t));

            s3_interop_jump_stream = s3_quic_open_stream(s3_interop_jump_cli, 1);

            if (s3_interop_jump_stream == NULL) {
                fprintf(stderr, "interop-client: jump open_stream failed\n");
                return S3_ERROR;
            }

            s3_interop_jump_conv_id = ((s3_quic_stream_t *)s3_interop_jump_stream->data)->id;

            s3_interop_jump_stream->read->handler = s3_interop_h3_response_read;
            s3_interop_jump_stream->read->data = s3_interop_jump_stream;
            s3_interop_jump_stream->read->active = 1;

            /*
             * the transport parameters are final at the handshake: a
             * jump peer that cannot take the 1202-byte tunnel frames
             * is a configuration error, fail at once
             */
            if (qc->ctp.max_datagram_frame_size < S3_INTEROP_JUMP_DGRAM_MIN) {
                fprintf(stderr,
                        "interop-client: jump peer max_datagram_frame_size %u is below the tunnel "
                        "need %u, run the jump server with -d 1352\n",
                        (unsigned)qc->ctp.max_datagram_frame_size,
                        (unsigned)S3_INTEROP_JUMP_DGRAM_MIN);
                return S3_ERROR;
            }
        }

        if (hs_reported && !s3_interop_jump_req_sent) {
            u_char  frame[512];
            u_char *p;
            size_t  sec_len, total;
            ssize_t m;

            sec_len = s3_interop_h3_request_section(NULL);

            p = frame;
            p = (u_char *)s3_h3_encode_varlen_int(p, S3_H3_FRAME_HEADERS);
            p = (u_char *)s3_h3_encode_varlen_int(p, sec_len);
            sec_len = (size_t)s3_interop_h3_request_section(p);
            total = (size_t)(p - frame) + sec_len;

            m = s3_quic_stream_send(s3_interop_jump_stream, frame, total);

            if (m == (ssize_t)S3_AGAIN) {
                /* the window opens on the write event, retried next pass */
                ;
            }

            else if (m != (ssize_t)total) {
                fprintf(stderr, "interop-client: jump request send failed\n");
                return S3_ERROR;
            }

            else {
                s3_interop_jump_req_sent = 1;
            }
        }

        if (s3_interop_h3_status_seen && s3_interop_jump_channel == NULL) {

            /*
             * the direct-udp channel comes up right after the 200:
             * the target extension carries the inner server address
             * (the -a argument), the 91 confirmation completes the
             * tunnel
             */
            s3_interop_jump_channel = s3_quic_open_stream(s3_interop_jump_cli, 1);

            if (s3_interop_jump_channel == NULL) {
                fprintf(stderr, "interop-client: jump channel open_stream failed\n");
                return S3_ERROR;
            }

            s3_interop_jump_ch_id = ((s3_quic_stream_t *)s3_interop_jump_channel->data)->id;

            s3_interop_jump_channel->read->handler = s3_interop_jump_ch_read;
            s3_interop_jump_channel->read->data = s3_interop_jump_channel;
            s3_interop_jump_channel->read->active = 1;
        }

        if (s3_interop_h3_status_seen && !s3_interop_jump_ch_sent) {
            u_char                   frame[1024];
            u_char                  *p;
            s3_ssh3_channel_t        hdr;
            s3_ssh3_forward_target_t target;
            size_t                   total;
            ssize_t                  m;

            s3_memzero(&hdr, sizeof(hdr));

            hdr.conversation_stream_id = s3_interop_jump_conv_id;
            hdr.max_packet_size = S3_INTEROP_CHANNEL_MAX_PACKET;
            hdr.type.data = (u_char *)S3_SSH3_CHANNEL_TYPE_DIRECT_UDP;
            hdr.type.len = strlen(S3_SSH3_CHANNEL_TYPE_DIRECT_UDP);

            p = frame;
            p = (u_char *)s3_ssh3_channel_build_header(p, &hdr);

            target.family = 4;
            target.ip_len = 4;
            s3_memcpy(target.ip, &s3_interop_inner_sa.sin_addr, 4);
            target.port = ntohs(s3_interop_inner_sa.sin_port);

            p = s3_ssh3_forward_build_target(p, &target);

            total = (size_t)(p - frame);

            m = s3_quic_stream_send(s3_interop_jump_channel, frame, total);

            if (m == (ssize_t)S3_AGAIN) {
                /* the window opens on the write event, retried next pass */
                ;
            }

            else if (m != (ssize_t)total) {
                fprintf(stderr, "interop-client: jump channel send failed\n");
                return S3_ERROR;
            }

            else {
                s3_interop_jump_ch_sent = 1;
            }
        }

        if (s3_interop_jump_ch_confirmed) {
            return S3_OK;
        }

        if (s3_current_msec - start > timeout) {
            fprintf(stderr,
                    "interop-client: jump tunnel timeout hs=%u req=%u status=%u "
                    "ch_sent=%u ch_confirmed=%u\n",
                    hs_reported, s3_interop_jump_req_sent, s3_interop_h3_status_seen,
                    s3_interop_jump_ch_sent, s3_interop_jump_ch_confirmed);
            return S3_ERROR;
        }
    }
}

static void
s3_interop_usage(const char *prog)
{
    fprintf(stderr,
            "usage: %s -a addr:port [-3] [-C] [-S] [-F tcp=@port|udp=@port] [-n count] [-s size]"
            " [-m min] [-t ms] [-A alpn] [-U user:pass] [-K privkey.pem] [-X] [-e cmd]"
            " [-J put|get:local:remote (get too: local first)] [-j jump-addr:port]"
            " [-M [-i ms]] [-O op] (cm modes: -U is the socket path)\n"
            "     [--oidc-issuer url --oidc-audience id | --oidc-token raw]\n"
            "  -a  peer UDP address\n"
            "  -3  h3 mode: RFC 9220 extended CONNECT (ssh3), the verdict is :status\n"
            "  -C  h3 mode: after the 200 open the ssh3 session channel, send the\n"
            "      shell request and a ping, the verdict is the echoed ping\n"
            "  -S  stream echo mode: pump count*size pattern bytes through a stream;\n"
            "      with -3 -C: the session scenario, exec, pty or kill\n"
            "  -F  with -3 -C: the direct-tcp or direct-udp channel to the target\n"
            "      127.0.0.1@port on the server side; tcp verifies the echo of the\n"
            "      hello plus 64 KiB, udp the echo of 20 datagrams\n"
            "  -j  the proxy jump with -3 -C: the first connection dials the jump\n"
            "      host, a direct-udp channel tunnels the inner connection to the\n"
            "      -a target; the jump peer needs -d 1352 (the inner 1200-byte\n"
            "      datagrams), the verdict is INTEROP-PROXYJUMP-OK\n"
            "  -M  with -3 -C: the control master, the UDS listener at the -U path\n"
            "      (0600, a stale file unlinks, a live master refuses) serves the\n"
            "      control channel, the slave sessions run as session channels of\n"
            "      the shared connection, the verdict is S3CM-MASTER-LISTEN\n"
            "  -i  the master idle timeout in ms (no control traffic and no live\n"
            "      sessions), default 5000, 0 serves until the deadline\n"
            "  -O  the control op (check|stop|exit) against the master at the -U\n"
            "      path, no quic is dialed; check prints the status line and\n"
            "      exits 0 when alive, stop waits for the socket release\n"
            "      (the slave mode is -U path [-e cmd] without -3 and -a)\n"
            "  -X  with -3 -C -S exec: the agent forwarding, the forward-agent\n"
            "      marker rides the burst, the server-initiated agent-connection\n"
            "      channels bridge to the local SSH_AUTH_SOCK\n"
            "  -e  with -S exec: the exec command (the agent_probe of the Go\n"
            "      interop runs here), default printf s3-exec-ok; the slave runs\n"
            "      it through the master, the verdict is S3CM-SLAVE-DONE\n"
            "  -J  the sftp transfer mode: put|get:local:remote (get too: local first), the "
            "channel type\n"
            "      is sftp and the verdict is INTEROP-SFTP-OK (verify on)\n"
            "  -U  the Basic auth of the CONNECT (RFC 7617), user:pass;\n"
            "      without it the Authorization is test-token; in the cm modes\n"
            "      (-M, -O, the slave without -3) it is the control socket path\n"
            "  -K  the pubkey mode: sign the Bearer JWT with the PEM private\n"
            "      key (ed25519, P-256 or RSA), -U carries the bare username;\n"
            "      the claims follow the reference BuildJWTBearerToken(), the\n"
            "      server -K authorized_keys verifies (S3_JWT_EXP_PAST shifts\n"
            "      exp into the past for the negative runs)\n"
            "  -n  datagrams to send (stream: count chunks), default 8\n"
            "  -s  datagram payload size (stream: chunk size), default 512\n"
            "  -m  require at least this many echoes, default all (RFC 9221 loss runs)\n"
            "  -t  overall deadline in ms, default 20000\n"
            "  -A  ALPN name, default s3interop/1 (h3 in the -3 mode)\n"
            "  -W  sleep this many usec in the stream echo reader; shrinks the\n"
            "      receive window, the deadlock repro with stream_buffer_size >= 64K\n"
            "  -L  log level: 0..8 or \"all\", default 7 (info)\n"
            "  -T  offline h3 wire-format selftest, no network (TEMPORARY)\n",
            prog);
}

/*
 * the harness-owned streams keep their pools until an explicit
 * s3_close_connection(): the pool cleanup handler is the quic stream
 * cleanup, nobody else drops them - the exit teardown runs it for
 * every stream the client opened, the leak check at exit stays silent
 */
static void
s3_interop_client_stream_close(s3_connection_t *sc)
{
    if (sc != NULL) {
        s3_close_connection(sc);
    }
}

int
main(int argc, char **argv)
{
    char                  opt;
    const char           *peer_text = NULL, *alpn_name = "s3interop/1";
    unsigned              timeout = 20000, dg_size = 1200;
    long                  n_arg = 8, s_arg = 512, m_arg = -1;
    u_char                alpn_wire[256];
    s3_str_t              alpn;
    size_t                i, sent, required;
    s3_uint_t             hs_reported = 0, sfin_sent = 0;
    s3_msec_t             start;
    s3_fd_t               fd;
    int                   rc = 0;
    struct sockaddr_in    sa;
    s3_event_ctx_t        ctx;
    s3_connection_t      *cli;
    s3_quic_connection_t *qc;

    s3_interop_log_init();
    s3_interop_pattern_init();

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
                s3_interop_oidc_audience = argv[i + 1];
                value = argv[i + 1];

            } else if (strcmp(argv[i], "--oidc-token") == 0 && i + 1 < argc) {
                s3_interop_oidc_raw = argv[i + 1];
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

    while ((opt = (char)getopt(argc, argv, "a:n:s:m:t:A:d:W:L:U:K:F:e:J:S:j:O:i:3CMTSXh")) != -1) {

        switch (opt) {

        case 'X':
            s3_interop_agent_mode = 1;
            break;

        case 'j':
            s3_interop_jump_text = optarg;
            s3_interop_jump_phase = S3_INTEROP_JUMP_TUNNEL;
            break;

        case 'e':
            s3_interop_exec_cmd = optarg;
            break;

        case 'M':
            s3_interop_cm_master = 1;
            break;

        case 'O':
            s3_interop_cm_op = optarg;
            break;

        case 'i':
            s3_interop_cm_idle_ms = atol(optarg);
            break;

        case 'K':
            s3_interop_pubkey_path = optarg;
            break;

        case 'J':

            /*
             * put|get:local:remote (get too: local first): the paths do not carry colons in
             * the harness scenarios, the split is two memchr calls
             */
            {
                char *sep1 = strchr(optarg, ':');
                char *sep2;

                if (sep1 != NULL) {
                    sep2 = strchr(sep1 + 1, ':');
                } else {
                    sep2 = NULL;
                }

                if (sep1 == NULL || sep2 == NULL) {
                    s3_interop_usage(argv[0]);
                    return 1;
                }

                *sep1 = '\0';
                *sep2 = '\0';

                if (strcmp(optarg, "put") == 0) {
                    s3_interop_sftp_mode = S3_INTEROP_SFTP_PUT;

                } else if (strcmp(optarg, "get") == 0) {
                    s3_interop_sftp_mode = S3_INTEROP_SFTP_GET;

                } else {
                    s3_interop_usage(argv[0]);
                    return 1;
                }

                s3_interop_sftp_local = sep1 + 1;
                s3_interop_sftp_remote = sep2 + 1;
            }

            break;

        case 'F':

            /*
             * tcp=@port / udp=@port: the target is always 127.0.0.1 on
             * the server side (the harness shape of the direct-* run)
             */
            if (strncmp(optarg, "tcp=@", 5) == 0) {
                s3_interop_fwd_mode = S3_INTEROP_FWD_TCP;
                s3_interop_fwd_port = (unsigned)atoi(optarg + 5);

            } else if (strncmp(optarg, "udp=@", 5) == 0) {
                s3_interop_fwd_mode = S3_INTEROP_FWD_UDP;
                s3_interop_fwd_port = (unsigned)atoi(optarg + 5);

            } else {
                s3_interop_usage(argv[0]);
                return 1;
            }

            if (s3_interop_fwd_port == 0 || s3_interop_fwd_port > 65535) {
                s3_interop_usage(argv[0]);
                return 1;
            }

            break;

        case 'S':

            if (optarg != NULL && strcmp(optarg, "exec") == 0) {
                s3_interop_h3_session_mode = S3_INTEROP_SESSION_EXEC;
                break;
            }

            if (optarg != NULL && strcmp(optarg, "pty") == 0) {
                s3_interop_h3_session_mode = S3_INTEROP_SESSION_PTY;
                break;
            }

            if (optarg != NULL && strcmp(optarg, "kill") == 0) {
                s3_interop_h3_session_mode = S3_INTEROP_SESSION_KILL;
                break;
            }

            /*
             * the bare -S of the stream runs: the taken token, if any,
             * is the next option, it goes back for the parse
             */
            s3_interop_streams_mode = 1;

            if (optarg != NULL) {
                optind--;
            }

            break;

        case 'U':

            /*
             * the raw -U: the Basic auth of the CONNECT in the h3
             * runs, the control socket path in the cm modes; the
             * meaning is fixed after the parse below
             */
            s3_interop_u_raw = optarg;

            break;

        case '3':
            s3_interop_h3_mode = 1;
            break;

        case 'C':
            s3_interop_h3_channel_mode = 1;
            break;

        case 'T':
            s3_interop_h3_selftest_mode = 1;
            break;

        case 'a':
            peer_text = optarg;
            break;

        case 'n':
            n_arg = atol(optarg);
            break;

        case 'm':
            m_arg = atol(optarg);
            break;

        case 's':
            s_arg = atol(optarg);
            break;

        case 't':
            timeout = (unsigned)atol(optarg);
            break;

        case 'A':
            alpn_name = optarg;
            break;

        case 'd':
            dg_size = (unsigned)atoi(optarg);
            break;

        case 'W':
            s3_interop_stall_usec = (unsigned)atoi(optarg);
            break;

        case 'L':
            s3_interop_log.log_level =
                (strcmp(optarg, "all") == 0) ? S3_LOG_DEBUG_ALL : (s3_uint_t)atol(optarg);
            break;

        default:
            s3_interop_usage(argv[0]);
            return 1;
        }
    }

    if (s3_interop_h3_selftest_mode) {
        /* the offline wire-format proof, before any address parsing */
        return s3_interop_h3_selftest();
    }

    if (s3_interop_h3_mode && s3_interop_streams_mode) {
        s3_interop_usage(argv[0]);
        return 1;
    }

    /* the channel phase rides on the h3 mode */
    if (s3_interop_h3_channel_mode && !s3_interop_h3_mode) {
        s3_interop_usage(argv[0]);
        return 1;
    }

    /* the session scenarios ride on the channel phase */
    if (s3_interop_h3_session_mode && (!s3_interop_h3_channel_mode || !s3_interop_h3_mode)) {
        s3_interop_usage(argv[0]);
        return 1;
    }

    /* the forward modes ride on the channel phase and exclude the session ones */
    if (s3_interop_fwd_mode &&
        (!s3_interop_h3_channel_mode || !s3_interop_h3_mode || s3_interop_h3_session_mode)) {
        s3_interop_usage(argv[0]);
        return 1;
    }

    /* the agent marker rides an exec run, the bridge needs the local agent */
    if (s3_interop_agent_mode &&
        (!s3_interop_h3_mode || s3_interop_h3_session_mode != S3_INTEROP_SESSION_EXEC)) {
        s3_interop_usage(argv[0]);
        return 1;
    }

    /* the sftp mode rides the h3 mode and excludes the channel phases */
    if (s3_interop_sftp_mode &&
        (!s3_interop_h3_mode || s3_interop_h3_channel_mode || s3_interop_fwd_mode)) {
        s3_interop_usage(argv[0]);
        return 1;
    }

    if (s3_interop_sftp_mode &&
        (s3_interop_sftp_local == NULL || s3_interop_sftp_remote == NULL ||
         *s3_interop_sftp_local == '\0' || *s3_interop_sftp_remote == '\0')) {
        s3_interop_usage(argv[0]);
        return 1;
    }

    /*
     * the proxy jump rides the channel phase, the tunnel replaces the
     * forward and agent runs (the inner scenario stays the session one)
     */
    if (s3_interop_jump_phase &&
        (!s3_interop_h3_mode || !s3_interop_h3_channel_mode || s3_interop_fwd_mode ||
         s3_interop_sftp_mode || s3_interop_agent_mode)) {
        s3_interop_usage(argv[0]);
        return 1;
    }

    /*
     * the meanings of -U: the Basic auth of the CONNECT in the h3
     * runs, the bare username in the pubkey mode (-K), the control
     * socket path in the cm modes (the master, the control ops and
     * the slave that never touches quic)
     */
    if (s3_interop_u_raw != NULL) {

        if (s3_interop_cm_master || s3_interop_cm_op != NULL || !s3_interop_h3_mode) {
            s3_interop_cm_path = s3_interop_u_raw;

        } else if (s3_interop_pubkey_path != NULL) {

            /* the pubkey mode: -U is the bare username (the iss of
             * the JWT and the ?user= of the path), the Bearer JWT
             * replaces the Basic scheme */

            if (strchr(s3_interop_u_raw, ':') != NULL) {
                fprintf(stderr, "interop-client: -K wants the bare -U username\n");
                return 1;
            }

            if (s3_interop_h3_path_user(s3_interop_u_raw) != S3_OK) {
                return 1;
            }

        } else {

            /*
             * the Basic auth (RFC 7617): the base64 input is the
             * "user:pass" text verbatim, the colon included; the
             * split below only rejects a missing password
             */
            {
                const char *colon = strchr(s3_interop_u_raw, ':');
                size_t      ulen = strlen(s3_interop_u_raw);

                if (colon == NULL) {
                    fprintf(stderr, "interop-client: -U wants user:pass\n");
                    return 1;
                }

                if (ulen > 300) {
                    fprintf(stderr, "interop-client: -U credentials too long\n");
                    return 1;
                }

                memcpy(s3_interop_h3_basic, "Basic ", sizeof("Basic ") - 1);

                s3_interop_base64((const u_char *)s3_interop_u_raw, ulen,
                                  s3_interop_h3_basic + sizeof("Basic ") - 1);

                s3_interop_h3_auth_value = s3_interop_h3_basic;

                /* the username goes into the query for the auth chain */

                {
                    char user[512];

                    if ((size_t)(colon - s3_interop_u_raw) >= sizeof(user)) {
                        fprintf(stderr, "interop-client: -U user too long\n");
                        return 1;
                    }

                    memcpy(user, s3_interop_u_raw, (size_t)(colon - s3_interop_u_raw));
                    user[colon - s3_interop_u_raw] = '\0';

                    if (s3_interop_h3_path_user(user) != S3_OK) {
                        return 1;
                    }
                }
            }
        }
    }

    /*
     * the pubkey mode rides the h3 CONNECT: the JWT needs the live
     * TLS exporter and the -U username; the cm modes keep the other
     * meaning of -U and never mix, the OIDC owns the Bearer scheme
     * alone, the proxy jump would carry a token bound to the outer
     * exporter into the inner conversation
     */
    if (s3_interop_pubkey_path != NULL &&
        (!s3_interop_h3_mode || s3_interop_u_raw == NULL || s3_interop_cm_master ||
         s3_interop_cm_op != NULL || s3_interop_jump_phase || s3_interop_oidc_issuer != NULL ||
         s3_interop_oidc_raw != NULL)) {
        s3_interop_usage(argv[0]);
        return 1;
    }

    /* the master rides the channel phase of the h3 mode */

    if (s3_interop_cm_master &&
        (!s3_interop_h3_mode || !s3_interop_h3_channel_mode || s3_interop_cm_path == NULL ||
         s3_interop_h3_session_mode || s3_interop_fwd_mode || s3_interop_sftp_mode ||
         s3_interop_agent_mode || s3_interop_jump_phase || s3_interop_streams_mode ||
         s3_interop_cm_op != NULL || s3_interop_cm_idle_ms < 0)) {
        s3_interop_usage(argv[0]);
        return 1;
    }

    /* the control ops ride the socket alone */

    if (s3_interop_cm_op != NULL) {

        if (s3_interop_h3_mode || s3_interop_cm_master || s3_interop_cm_path == NULL ||
            s3_interop_h3_session_mode || s3_interop_fwd_mode || s3_interop_sftp_mode ||
            s3_interop_streams_mode ||
            (strcmp(s3_interop_cm_op, S3_SSH3_CM_OP_CHECK) != 0 &&
             strcmp(s3_interop_cm_op, S3_SSH3_CM_OP_STOP) != 0 &&
             strcmp(s3_interop_cm_op, S3_SSH3_CM_OP_EXIT) != 0)) {
            s3_interop_usage(argv[0]);
            return 1;
        }

        return s3_interop_cm_control_op();
    }

    /* the slave: -U path [-e cmd], no -3 and no -a, no quic state */

    if (!s3_interop_h3_mode && peer_text == NULL && s3_interop_cm_path != NULL) {

        if (s3_interop_h3_channel_mode || s3_interop_h3_session_mode || s3_interop_fwd_mode ||
            s3_interop_sftp_mode || s3_interop_agent_mode || s3_interop_jump_phase ||
            s3_interop_streams_mode) {
            s3_interop_usage(argv[0]);
            return 1;
        }

        return s3_interop_cm_slave(timeout);
    }

    if (s3_interop_fwd_mode == S3_INTEROP_FWD_TCP) {
        s3_interop_fwd_payload_init();

    } else if (s3_interop_fwd_mode == S3_INTEROP_FWD_UDP) {
        s3_interop_fwd_udp_init();
    }

    if (peer_text == NULL || n_arg < 1 || n_arg > 65536 || s_arg < 8) {
        s3_interop_usage(argv[0]);
        return 1;
    }

    /*
     * the datagrams must fit the advertised max_datagram_frame_size;
     * the streams have no such bound
     */

    if (!s3_interop_streams_mode && s_arg > 1100) {
        s3_interop_usage(argv[0]);
        return 1;
    }

    if (s3_interop_streams_mode && (s_arg > 1048576 || s_arg % 64 != 0)) {
        /* the block pattern requires 64-byte aligned chunk sizes */
        s3_interop_usage(argv[0]);
        return 1;
    }

    /*
     * RFC 9221: DATAGRAM frames are not retransmitted, so under netem
     * loss the run passes with -m when at least the required number
     * of echoes came back
     */

    required = (size_t)n_arg;

    if (m_arg >= 0) {
        if (m_arg > n_arg) {
            s3_interop_usage(argv[0]);
            return 1;
        }

        required = (size_t)m_arg;
    }

    if (s3_interop_parse_addr(peer_text, &sa) != S3_OK) {
        fprintf(stderr, "interop-client: bad peer address %s\n", peer_text);
        return 1;
    }

    if (s3_interop_jump_phase == S3_INTEROP_JUMP_TUNNEL) {

        /*
         * the -a address turns into the tunnel target and the inner
         * peer, the -j one is the phase 1 dial
         */
        if (s3_interop_parse_addr(s3_interop_jump_text, &s3_interop_jump_sa) != S3_OK) {
            fprintf(stderr, "interop-client: bad jump address %s\n", s3_interop_jump_text);
            return 1;
        }

        s3_interop_inner_sa = sa;
    }

    if (s3_event_ctx_init(&ctx, &s3_interop_log) != S3_OK) {
        fprintf(stderr, "interop-client: event ctx init failed\n");
        return 1;
    }

    s3_interop_count = (size_t)n_arg;
    s3_interop_size = (size_t)s_arg;

    if (s3_interop_streams_mode) {
        s3_interop_stotal = s3_interop_count * s3_interop_size;

    } else if (!s3_interop_fwd_mode) {

        s3_interop_expected = malloc(s3_interop_count * s3_interop_size);
        s3_interop_got = calloc(s3_interop_count, 1);

        if (s3_interop_expected == NULL || s3_interop_got == NULL) {
            return 1;
        }

        for (i = 0; i < s3_interop_count; i++) {
            u_char *p = s3_interop_expected + i * s3_interop_size;

            s3_interop_le32(p, (uint32_t)i);

            if (RAND_bytes(p + 4, s3_interop_size - 4) != 1) {
                fprintf(stderr, "interop-client: RAND_bytes failed\n");
                return 1;
            }
        }
    }

    start = s3_current_msec;
    sent = 0;

    if (s3_interop_jump_phase == S3_INTEROP_JUMP_TUNNEL) {

        /*
         * phase 1: the tunnel to the inner server comes up first, the
         * jump conversation then stays alive for the whole run
         */
        if (s3_interop_jump_dial(&ctx, start, (s3_msec_t)timeout) != S3_OK) {
            return 1;
        }

        s3_interop_jump_phase = S3_INTEROP_JUMP_INNER;

        /* the loopback bridge, a becomes the inner quic fd below */
        if (s3_interop_bridge_create(&ctx) != S3_OK) {
            fprintf(stderr, "interop-client: bridge create failed\n");
            return 1;
        }

        /*
         * the h3 globals the tunnel run touched: the inner connect
         * below replays the handshake phase clean
         */
        s3_interop_h3_req_sent = 0;
        s3_interop_h3_status_seen = 0;
        s3_interop_h3_status = 0;
        s3_interop_h3_len = 0;
    }

    if (s3_interop_jump_phase == S3_INTEROP_JUMP_INNER) {

        /*
         * the inner quic rides the bridge socket a, its peer is the
         * tunnel side b (the bridge_sa): the packets loop through the
         * kernel into b and the bridge wraps them into the jump
         * channel, the replies come back the same way
         */
        fd = s3_interop_bridge_a;
        s3_interop_bridge_a = -1;

    } else {

        fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd == -1) {
            perror("socket");
            return 1;
        }

        if (s3_nonblocking(fd) != S3_OK) {
            perror("fcntl(O_NONBLOCK)");
            return 1;
        }
    }

    cli = s3_get_connection(&ctx, fd);
    if (cli == NULL) {
        fprintf(stderr, "interop-client: connection alloc failed\n");
        return 1;
    }

    cli->pool = s3_create_pool((size_t)S3_DEFAULT_POOL_SIZE, &s3_interop_log);
    if (cli->pool == NULL) {
        rc = 1;
        goto teardown;
    }

    cli->sockaddr = (struct sockaddr *)s3_palloc(cli->pool, sizeof(sa));
    if (cli->sockaddr == NULL) {
        rc = 1;
        goto teardown;
    }

    s3_memcpy(cli->sockaddr,
              s3_interop_jump_phase == S3_INTEROP_JUMP_INNER ? &s3_interop_bridge_sa : &sa,
              sizeof(sa));
    cli->socklen = sizeof(sa);

    /*
     * ssh3-c: the h3 peers negotiate the h3 ALPN (the Go harness pins
     * http3.NextProtoH3); an explicit -A still wins
     */
    if (s3_interop_h3_mode && strcmp(alpn_name, "s3interop/1") == 0) {
        alpn_name = "h3";
    }

    s3_interop_alpn_wire(alpn_wire, alpn_name);

    alpn.data = alpn_wire;
    alpn.len = 1 + strlen(alpn_name);

    s3_quic_conf_t conf;

    s3_memzero(&conf, sizeof(conf));

    conf.ssl = s3_ssl_client_create(&s3_interop_log, &alpn);
    if (conf.ssl == NULL) {
        fprintf(stderr, "interop-client: ssl init failed\n");
        rc = 1;
        goto teardown;
    }

    conf.gso_enabled = 1;
    conf.ctx = &ctx;
    conf.handshake_timeout = (s3_msec_t)timeout;
    conf.idle_timeout = 60000;
    /*
     * the stream flow credit: the bulk sftp trains ride it, the
     * 16 KiB default stalls the window per one driver chunk
     */
    conf.stream_buffer_size = 1 << 20;
    conf.max_concurrent_streams_bidi = 16;
    conf.max_concurrent_streams_uni = 16;
    conf.active_connection_id_limit = 8;
    conf.max_datagram_frame_size = dg_size;
    conf.datagram_handler = s3_interop_client_datagram;

    if (s3_interop_h3_mode) {
        /* the server's uni streams go to the session port, see above */
        conf.stream_handler = s3_interop_h3_client_stream;
    }

    for (i = 0; i < S3_QUIC_AV_KEY_LEN; i++) {
        conf.av_token_key[i] = (u_char)(0xa0 + i);
        conf.sr_token_key[i] = (u_char)(0xb0 + i);
    }

    if (s3_event_actions.add_event(cli->read, S3_READ_EVENT, 0) != S3_OK) {
        rc = 1;
        goto teardown;
    }

    if (s3_quic_connect(cli, &conf) != S3_OK) {
        fprintf(stderr, "interop-client: connect failed\n");
        rc = 1;
        goto teardown;
    }

    qc = s3_quic_get_connection(cli);
    if (qc == NULL) {
        rc = 1;
        goto teardown;
    }

    /* the shared connection the master sessions open their channels on */
    s3_interop_main_cli = cli;

    if (s3_interop_jump_phase == S3_INTEROP_JUMP_INNER) {

        /*
         * the inner connection lives inside the jump tunnel: the path
         * mtu discovery pins at the 1200 floor, the escalating probes
         * would not fit the tunnel datagrams (the reference turns the
         * discovery off for its --proxy-jump the same way)
         */
        qc->path->max_mtu = S3_INTEROP_JUMP_INNER_MTU;
    }

    for (;;) {
        s3_event_process_posted(&ctx, &ctx.posted_events);

        s3_process_events_and_timers(&ctx);

        qc = s3_quic_get_connection(cli);

        if (qc == NULL) {
            fprintf(stderr, "interop-client: connection is gone\n");
            rc = 1;
            goto teardown;
        }

        if (!hs_reported && cli->ssl != NULL && cli->ssl->handshaked) {
            printf("INTEROP-HANDSHAKE-OK\n");
            fflush(stdout);

            hs_reported = 1;

            if ((s3_interop_oidc_issuer != NULL || s3_interop_oidc_raw != NULL) &&
                s3_interop_oidc_acquire(cli->ssl->connection) != S3_OK) {
                fprintf(stderr, "interop-client: oidc auth failed\n");
                rc = 1;
                goto teardown;
            }

            if (s3_interop_pubkey_path != NULL &&
                s3_interop_pubkey_jwt(cli->ssl->connection) != S3_OK) {
                fprintf(stderr, "interop-client: pubkey jwt failed\n");
                rc = 1;
                goto teardown;
            }

            if (s3_interop_h3_mode) {

                /*
                 * the h3 session first: SETTINGS go out on the control
                 * stream from inside s3_h3_init_session(), the quic-go
                 * server expects them before the request stream
                 */
                if (s3_h3_get_session(cli) == NULL && s3_h3_init_session(cli) != S3_OK) {
                    fprintf(stderr, "interop-client: h3 init_session failed\n");
                    rc = 1;
                    goto teardown;
                }

                s3_memzero(&s3_interop_h3_parse, sizeof(s3_h3_parse_headers_t));

                s3_interop_h3_stream = s3_quic_open_stream(cli, 1);
                if (s3_interop_h3_stream == NULL) {
                    fprintf(stderr, "interop-client: open_stream failed\n");
                    rc = 1;
                    goto teardown;
                }

                s3_interop_h3_stream->read->handler = s3_interop_h3_response_read;
                s3_interop_h3_stream->read->data = s3_interop_h3_stream;

                /*
                 * the app-level read arming, the s3 analog of the
                 * reference ngx_handle_read_event(): without it the quic
                 * layer raises ready but never posts the stream events
                 */
                s3_interop_h3_stream->read->active = 1;

            } else if (s3_interop_streams_mode) {
                /* open one bidirectional stream and verify the echo */
                s3_interop_stream = s3_quic_open_stream(cli, 1);
                if (s3_interop_stream == NULL) {
                    fprintf(stderr, "interop-client: open_stream failed\n");
                    rc = 1;
                    goto teardown;
                }

                s3_interop_stream->read->handler = s3_interop_stream_echo_read;
                s3_interop_stream->read->data = s3_interop_stream;

                s3_interop_stream->read->active = 1;

            } else if (qc->client_tp_done && qc->ctp.max_datagram_frame_size == 0) {
                fprintf(stderr, "interop-client: peer does not support datagrams\n");
                rc = 1;
                goto teardown;
            }
        }

        if (s3_interop_h3_mode) {

            if (s3_interop_jump_phase == S3_INTEROP_JUMP_INNER) {
                /* the parked tunnel frame retries, the bridge wakes */
                s3_interop_bridge_flush();
            }

            if (hs_reported && !s3_interop_h3_req_sent) {
                u_char  frame[512];
                u_char *p;
                size_t  sec_len, total;
                ssize_t m;

                sec_len = s3_interop_h3_request_section(NULL);

                p = frame;
                p = (u_char *)s3_h3_encode_varlen_int(p, S3_H3_FRAME_HEADERS);
                p = (u_char *)s3_h3_encode_varlen_int(p, sec_len);
                sec_len = (size_t)s3_interop_h3_request_section(p);
                total = (size_t)(p - frame) + sec_len;

                m = s3_quic_stream_send(s3_interop_h3_stream, frame, total);

                if (m == (ssize_t)S3_AGAIN) {
                    /* the window opens on the write event, retried next pass */
                    ;
                }

                else if (m != (ssize_t)total) {
                    fprintf(stderr, "interop-client: h3 request send failed\n");
                    rc = 1;
                    goto teardown;
                }

                else {
                    s3_interop_h3_req_sent = 1;
                }
            }

            if (s3_interop_cm_master) {

                /*
                 * the master serves on this loop once the CONNECT
                 * answered: the listener, the control connections and
                 * the session channels of the shared connection
                 */
                if (s3_interop_h3_status_seen && !s3_interop_cm_listening &&
                    s3_interop_cm_listen_open(&ctx) != S3_OK) {
                    rc = 1;
                    goto teardown;
                }

                if (s3_interop_cm_stop) {
                    break;
                }

            } else if (s3_interop_h3_status_seen && (s3_interop_h3_channel_mode ||
                                                     s3_interop_fwd_mode || s3_interop_sftp_mode)) {

                /*
                 * the channel comes up right after the 200: the next
                 * client bidi stream (ChannelID == its StreamID)
                 * carries the channel header and, for the forward
                 * modes, the target extension - one send
                 */
                if (s3_interop_h3_channel == NULL) {

                    s3_interop_h3_channel = s3_quic_open_stream(cli, 1);

                    if (s3_interop_h3_channel == NULL) {
                        fprintf(stderr, "interop-client: channel open_stream failed\n");
                        rc = 1;
                        goto teardown;
                    }

                    s3_interop_fwd_conv_id = ((s3_quic_stream_t *)s3_interop_h3_stream->data)->id;
                    s3_interop_fwd_channel_id =
                        ((s3_quic_stream_t *)s3_interop_h3_channel->data)->id;

                    s3_interop_h3_channel->read->handler =
                        s3_interop_fwd_mode          ? s3_interop_h3_fwd_read
                        : s3_interop_h3_session_mode ? s3_interop_h3_session_read
                        : s3_interop_sftp_mode       ? s3_interop_sftp_read
                                                     : s3_interop_h3_channel_read;
                    s3_interop_h3_channel->read->data = s3_interop_h3_channel;

                    /*
                     * the app-level read arming, the same the CONNECT
                     * stream got: without it the quic layer raises
                     * ready but never posts the stream events
                     */
                    s3_interop_h3_channel->read->active = 1;

                    if (s3_interop_sftp_mode) {

                        /*
                         * the sftp pump rides the write readiness: the
                         * quic layer posts the write event when the
                         * peer reopens the stream window (the
                         * MAX_STREAM_DATA/MAX_DATA handling), the pump
                         * resumes the parked frame there
                         */

                        s3_interop_h3_channel->write->handler = s3_interop_sftp_write;
                        s3_interop_h3_channel->write->data = s3_interop_h3_channel;
                        s3_interop_h3_channel->write->active = 1;
                    }
                }

                if (!s3_interop_h3_ch_sent) {
                    u_char                   frame[1024];
                    u_char                  *p;
                    s3_ssh3_channel_t        hdr;
                    s3_ssh3_forward_target_t target;
                    size_t                   total;
                    ssize_t                  m;

                    /* the header: the conversation is the CONNECT stream */
                    s3_memzero(&hdr, sizeof(hdr));

                    hdr.conversation_stream_id = s3_interop_fwd_conv_id;
                    hdr.max_packet_size = S3_INTEROP_CHANNEL_MAX_PACKET;

                    if (s3_interop_fwd_mode == S3_INTEROP_FWD_TCP) {
                        hdr.type.data = (u_char *)S3_SSH3_CHANNEL_TYPE_DIRECT_TCP;
                        hdr.type.len = strlen(S3_SSH3_CHANNEL_TYPE_DIRECT_TCP);

                    } else if (s3_interop_fwd_mode == S3_INTEROP_FWD_UDP) {
                        hdr.type.data = (u_char *)S3_SSH3_CHANNEL_TYPE_DIRECT_UDP;
                        hdr.type.len = strlen(S3_SSH3_CHANNEL_TYPE_DIRECT_UDP);

                    } else if (s3_interop_sftp_mode) {
                        hdr.type.data = (u_char *)S3_SSH3_CHANNEL_TYPE_SFTP;
                        hdr.type.len = strlen(S3_SSH3_CHANNEL_TYPE_SFTP);

                    } else {
                        hdr.type.data = (u_char *)S3_SSH3_CHANNEL_TYPE_SESSION;
                        hdr.type.len = strlen(S3_SSH3_CHANNEL_TYPE_SESSION);
                    }

                    p = frame;
                    p = (u_char *)s3_ssh3_channel_build_header(p, &hdr);

                    if (s3_interop_fwd_mode != S3_INTEROP_FWD_NONE) {

                        /*
                         * the target extension of the direct-* types
                         * (docs/P4-WIRE.md 2.1): family, the raw ip,
                         * the uint16be port - the harness target is
                         * the loopback service on the server side
                         */
                        target.family = 4;
                        target.ip_len = 4;

                        if (inet_pton(AF_INET, "127.0.0.1", target.ip) != 1) {
                            fprintf(stderr, "interop-client: inet_pton failed\n");
                            rc = 1;
                            goto teardown;
                        }

                        target.port = (uint16_t)s3_interop_fwd_port;

                        p = s3_ssh3_forward_build_target(p, &target);
                    }

                    else if (s3_interop_sftp_mode) {

                        /*
                         * the sftp channel: the driver starts behind
                         * the header (the start call moved below the
                         * send), its INIT rides the first pump pass
                         */
                    }

                    else if (s3_interop_h3_session_mode == S3_INTEROP_SESSION_EXEC ||
                             s3_interop_h3_session_mode == S3_INTEROP_SESSION_KILL) {

                        /*
                         * the exec: the marker command with the reply
                         * wanted; the kill run execs sleep 30 instead
                         * and signals KILL once the confirmation came
                         * back; the agent marker rides before the exec
                         * (the LARVAL trigger of the reference)
                         */
                        s3_ssh3_request_t exec;
                        const char       *command;

                        if (s3_interop_agent_mode &&
                            s3_interop_h3_session_mode == S3_INTEROP_SESSION_EXEC) {

                            static const s3_str_t trigger = s3_string(S3_SSH3_AGENT_TRIGGER);

                            s3_ssh3_msg_data_t marker;

                            s3_memzero(&marker, sizeof(marker));
                            marker.data = trigger;

                            p = (u_char *)s3_ssh3_encode_varint(p, S3_SSH3_MSG_CHANNEL_DATA);
                            p = (u_char *)s3_ssh3_msg_encode_data(p, &marker);
                        }

                        command = (s3_interop_h3_session_mode == S3_INTEROP_SESSION_KILL)
                                      ? "sleep 30"
                                  : s3_interop_exec_cmd != NULL ? s3_interop_exec_cmd
                                                                : "printf s3-exec-ok";

                        s3_memzero(&exec, sizeof(exec));

                        exec.kind = S3_SSH3_REQ_EXEC;
                        exec.u.exec.command.data = (u_char *)command;
                        exec.u.exec.command.len = strlen(command);

                        p = s3_interop_h3_session_request(p, S3_SSH3_REQ_EXEC, 1, &exec);
                    }

                    else if (s3_interop_h3_session_mode == S3_INTEROP_SESSION_PTY) {

                        /*
                         * the pty at 80x24, then the shell, then the
                         * resize to 100x40 with the size probe behind
                         * it, one send for all four
                         */
                        s3_ssh3_request_t  pty, shell, wc;
                        s3_ssh3_msg_data_t data;

                        s3_memzero(&pty, sizeof(pty));

                        pty.kind = S3_SSH3_REQ_PTY;
                        pty.u.pty.term.data = (u_char *)"xterm";
                        pty.u.pty.term.len = strlen("xterm");
                        pty.u.pty.width = 80;
                        pty.u.pty.height = 24;
                        pty.u.pty.pixel_width = 0;
                        pty.u.pty.pixel_height = 0;
                        pty.u.pty.modes.data = NULL;
                        pty.u.pty.modes.len = 0;

                        p = s3_interop_h3_session_request(p, S3_SSH3_REQ_PTY, 1, &pty);

                        /* the shell request: the body is empty by design */
                        s3_memzero(&shell, sizeof(shell));

                        shell.kind = S3_SSH3_REQ_SHELL;

                        p = s3_interop_h3_session_request(p, S3_SSH3_REQ_SHELL, 1, &shell);

                        s3_memzero(&wc, sizeof(wc));

                        wc.kind = S3_SSH3_REQ_WINDOW_CHANGE;
                        wc.u.window_change.width = 100;
                        wc.u.window_change.height = 40;
                        wc.u.window_change.pixel_width = 0;
                        wc.u.window_change.pixel_height = 0;

                        p = s3_interop_h3_session_request(p, S3_SSH3_REQ_WINDOW_CHANGE, 0, &wc);

                        /* the probe the resized pty answers with "40 100" */
                        s3_memzero(&data, sizeof(data));

                        data.data.data = (u_char *)"stty size\n";
                        data.data.len = strlen("stty size\n");

                        p = (u_char *)s3_ssh3_encode_varint(p, S3_SSH3_MSG_CHANNEL_DATA);
                        p = (u_char *)s3_ssh3_msg_encode_data(p, &data);
                    }

                    else {

                        /* the shell request: the body is empty by design */
                        s3_ssh3_request_t     body;
                        s3_ssh3_msg_data_t    data;
                        s3_ssh3_msg_request_t req;

                        s3_memzero(&body, sizeof(body));
                        body.kind = S3_SSH3_REQ_SHELL;

                        s3_memzero(&req, sizeof(req));
                        req.request_type.data =
                            (u_char *)s3_ssh3_request_type_str(S3_SSH3_REQ_SHELL);
                        req.request_type.len = strlen(s3_ssh3_request_type_str(S3_SSH3_REQ_SHELL));
                        req.want_reply = 1;

                        data.data.data = (u_char *)"ping";
                        data.data.len = 4;

                        p = (u_char *)s3_ssh3_encode_varint(p, S3_SSH3_MSG_CHANNEL_REQUEST);
                        p = (u_char *)s3_ssh3_msg_encode_request(p, &req);
                        p = (u_char *)s3_ssh3_encode_varint(p, S3_SSH3_MSG_CHANNEL_DATA);
                        p = (u_char *)s3_ssh3_msg_encode_data(p, &data);
                    }

                    total = (size_t)(p - frame);

                    m = s3_quic_stream_send(s3_interop_h3_channel, frame, total);

                    if (m == (ssize_t)S3_AGAIN) {
                        /* the window opens on the write event, retried next pass */
                        ;
                    }

                    else if (m != (ssize_t)total) {
                        fprintf(stderr, "interop-client: channel send failed\n");
                        rc = 1;
                        goto teardown;
                    }

                    else {
                        s3_interop_h3_ch_sent = 1;

                        if (s3_interop_sftp_mode) {

                            /*
                             * the driver rides behind the header: the
                             * INIT must not precede the channel open
                             * on the wire, the start drains on the
                             * first pump pass
                             */

                            s3_interop_sftp_start();
                        }

                        if (s3_interop_h3_session_mode == S3_INTEROP_SESSION_EXEC) {
                            /*
                             * the exec carries no stdin: the fin goes
                             * out at once.  The kill run keeps the
                             * stream writable, the KILL rides it
                             * right after the confirmation
                             */
                            if (s3_quic_shutdown_stream(s3_interop_h3_channel, S3_WRITE_SHUTDOWN) !=
                                S3_OK) {
                                fprintf(stderr, "interop-client: channel shutdown failed\n");
                                rc = 1;
                                goto teardown;
                            }
                        }
                    }
                }

                if (s3_interop_fwd_mode == S3_INTEROP_FWD_TCP && s3_interop_h3_ch_confirmed) {

                    /* the hello plus the pattern ride the 94 frames */
                    s3_interop_fwd_tcp_write();
                }

                if (s3_interop_fwd_mode == S3_INTEROP_FWD_UDP && s3_interop_h3_ch_confirmed &&
                    s3_interop_fwd_udp_sent < S3_INTEROP_FWD_UDP_COUNT) {

                    /*
                     * the numbered datagrams (docs/P4-WIRE.md 3.2):
                     * one per pass, the echoes verify in the datagram
                     * handler
                     */
                    u_char  dg[S3_INTEROP_FWD_UDP_SIZE + 16];
                    u_char *p;

                    p = s3_ssh3_dgram_encode(dg, s3_interop_fwd_conv_id, s3_interop_fwd_channel_id,
                                             s3_interop_fwd_udp_expected[s3_interop_fwd_udp_sent],
                                             S3_INTEROP_FWD_UDP_SIZE);

                    if (s3_quic_send_datagram(cli, dg, (size_t)(p - dg)) == S3_OK) {
                        s3_interop_fwd_udp_sent++;

                    } else {
                        fprintf(stderr, "interop-client: forward datagram send failed\n");
                        rc = 1;
                        goto teardown;
                    }
                }

                if (!s3_interop_h3_sess_signal_sent &&
                    ((s3_interop_h3_session_mode == S3_INTEROP_SESSION_PTY &&
                      s3_interop_h3_sess_signal_pending) ||
                     (s3_interop_h3_session_mode == S3_INTEROP_SESSION_KILL &&
                      s3_interop_h3_ch_confirmed))) {

                    /*
                     * the KILL goes out: the pty run waits for the
                     * resized geometry, the kill run only for the 91
                     */
                    u_char            frame[128];
                    u_char           *p;
                    s3_ssh3_request_t sig;
                    size_t            total;
                    ssize_t           m;

                    s3_memzero(&sig, sizeof(sig));

                    sig.kind = S3_SSH3_REQ_SIGNAL;
                    sig.u.signal.name.data = (u_char *)"KILL";
                    sig.u.signal.name.len = strlen("KILL");

                    p = frame;
                    p = s3_interop_h3_session_request(p, S3_SSH3_REQ_SIGNAL, 0, &sig);

                    total = (size_t)(p - frame);

                    m = s3_quic_stream_send(s3_interop_h3_channel, frame, total);

                    if (m == (ssize_t)S3_AGAIN) {
                        /* the window opens on the write event, retried next pass */
                        ;
                    }

                    else if (m != (ssize_t)total) {
                        fprintf(stderr, "interop-client: signal send failed\n");
                        rc = 1;
                        goto teardown;
                    }

                    else {
                        s3_interop_h3_sess_signal_sent = 1;
                    }
                }
            }

            /*
             * the plain -3 run completes on the 200; the -C, the sftp
             * and the forward runs go on until their verdict came back
             */
            if (!s3_interop_cm_master && s3_interop_h3_status_seen &&
                (!(s3_interop_h3_channel_mode || s3_interop_fwd_mode || s3_interop_sftp_mode) ||
                 s3_interop_h3_ch_ok)) {

                if (s3_interop_jump_phase == S3_INTEROP_JUMP_INNER) {

                    printf("INTEROP-PROXYJUMP-OK inner-sent=%llu inner-recv=%llu\n",
                           (unsigned long long)s3_interop_jump_sent,
                           (unsigned long long)s3_interop_jump_recv);
                    fflush(stdout);
                }

                break;
            }

        } else if (s3_interop_streams_mode) {

            if (hs_reported) {
                /*
                 * the writer: flow control may throttle, retried each
                 * pass.  The pattern blocks live at absolute stream
                 * offsets (a partial send leaves s3_interop_ssent
                 * unaligned), so the fill is driven by the absolute
                 * position: the offset field lands only on real block
                 * boundaries
                 */
                while (s3_interop_ssent < s3_interop_stotal) {
                    size_t  chunk = sizeof(s3_interop_sbuf);
                    ssize_t m;
                    size_t  j, r, k, pos, bstart;

                    if (s3_interop_ssent + chunk > s3_interop_stotal) {
                        chunk = s3_interop_stotal - s3_interop_ssent;
                    }

                    for (j = 0; j < chunk;) {
                        pos = s3_interop_ssent + j;
                        r = pos % sizeof(s3_interop_ptemplate);
                        k = chunk - j;

                        if (r < 8) {
                            /*
                             * the first eight bytes of a block carry
                             * the little-endian block offset; a chunk
                             * boundary may split the field
                             */

                            bstart = pos - r;

                            if (k > 8 - r) {
                                k = 8 - r;
                            }

                            s3_memcpy(s3_interop_sbuf + j, (u_char *)&bstart + r, k);
                            j += k;

                            continue;
                        }

                        k = s3_min(k, sizeof(s3_interop_ptemplate) - r);

                        s3_memcpy(s3_interop_sbuf + j, s3_interop_ptemplate + r, k);
                        j += k;
                    }

                    m = s3_quic_stream_send(s3_interop_stream, s3_interop_sbuf, chunk);

                    if (m == (ssize_t)S3_AGAIN) {
                        break;
                    }

                    if (m <= 0) {
                        fprintf(stderr, "interop-client: stream send failed\n");
                        rc = 1;
                        goto teardown;
                    }

                    s3_interop_ssent += (size_t)m;
                }

                /* everything written: the fin makes the server close its side */
                if (s3_interop_ssent == s3_interop_stotal && !sfin_sent) {
                    if (s3_quic_shutdown_stream(s3_interop_stream, S3_WRITE_SHUTDOWN) != S3_OK) {
                        fprintf(stderr, "interop-client: stream shutdown failed\n");
                        rc = 1;
                        goto teardown;
                    }

                    sfin_sent = 1;
                }
            }

            if (s3_interop_srecv == s3_interop_stotal) {
                printf("INTEROP-STREAM-OK sent=%zu recv=%zu\n", s3_interop_ssent, s3_interop_srecv);
                fflush(stdout);
                break;
            }

        } else {

            if (hs_reported && sent < s3_interop_count) {
                u_char *p = s3_interop_expected + sent * s3_interop_size;

                if (s3_quic_send_datagram(cli, p, s3_interop_size) == S3_OK) {
                    sent++;

                } else {
                    fprintf(stderr, "interop-client: send_datagram failed\n");
                    rc = 1;
                    goto teardown;
                }
            }

            if (s3_interop_received == required) {
                printf("INTEROP-DATAGRAM-OK sent=%zu recv=%zu (required %zu)\n", sent,
                       s3_interop_received, required);
                fflush(stdout);
                break;
            }
        }

        if (s3_current_msec - start > (s3_msec_t)timeout) {
            if (s3_interop_h3_mode) {
                fprintf(stderr,
                        "interop-client: h3 timeout sent=%u status_seen=%u ch_sent=%u "
                        "ch_confirmed=%u ch_ok=%u\n",
                        s3_interop_h3_req_sent, s3_interop_h3_status_seen, s3_interop_h3_ch_sent,
                        s3_interop_h3_ch_confirmed, s3_interop_h3_ch_ok);

                if (s3_interop_h3_session_mode) {
                    fprintf(stderr,
                            "interop-client: session state mode=%u signal_pending=%u "
                            "signal_sent=%u out_len=%zu\n",
                            s3_interop_h3_session_mode, s3_interop_h3_sess_signal_pending,
                            s3_interop_h3_sess_signal_sent, s3_interop_h3_sess_out_len);
                }

                if (s3_interop_fwd_mode == S3_INTEROP_FWD_TCP) {
                    fprintf(stderr, "interop-client: fwd state sent=%zu recv=%zu\n",
                            s3_interop_fwd_sent, s3_interop_fwd_recv);
                    printf("INTEROP-FWD-TCP-FAIL\n");
                    fflush(stdout);

                } else if (s3_interop_fwd_mode == S3_INTEROP_FWD_UDP) {
                    fprintf(stderr, "interop-client: fwd state sent=%u recv=%zu\n",
                            s3_interop_fwd_udp_sent, s3_interop_fwd_udp_recv);
                    printf("INTEROP-FWD-UDP-FAIL got=%zu\n", s3_interop_fwd_udp_recv);
                    fflush(stdout);
                }

                if (s3_interop_jump_phase == S3_INTEROP_JUMP_INNER) {
                    fprintf(stderr, "interop-client: jump tunnel sent=%llu recv=%llu parked=%zu\n",
                            (unsigned long long)s3_interop_jump_sent,
                            (unsigned long long)s3_interop_jump_recv, s3_interop_bridge_parked);
                }

                rc = 1;
                goto teardown;
            }

            if (s3_interop_streams_mode) {
                fprintf(stderr, "interop-client: timeout sent=%zu recv=%zu\n", s3_interop_ssent,
                        s3_interop_srecv);

                if (qc != NULL) {
                    s3_quic_stream_t *qs;

                    fprintf(stderr,
                            "DBG conn send_max_data=%llu send_offset=%llu recv_max_data=%llu\n",
                            (unsigned long long)qc->streams.send_max_data,
                            (unsigned long long)qc->streams.send_offset,
                            (unsigned long long)qc->streams.recv_max_data);

                    qs = s3_quic_find_stream(
                        &qc->streams.tree,
                        s3_interop_stream ? ((s3_quic_stream_t *)s3_interop_stream->data)->id : 0);

                    if (qs != NULL) {
                        fprintf(stderr,
                                "DBG stream sent=%llu acked=%llu send_max_data=%llu "
                                "recv_last=%llu recv_max_data=%llu\n",
                                (unsigned long long)qs->sent, (unsigned long long)qs->acked,
                                (unsigned long long)qs->send_max_data,
                                (unsigned long long)qs->recv_last,
                                (unsigned long long)qs->recv_max_data);
                    }
                }

            } else {
                fprintf(stderr, "interop-client: timeout sent=%zu received=%zu required=%zu\n",
                        sent, s3_interop_received, required);
            }

            rc = 1;
            goto teardown;
        }
    }

    /*
     * the common teardown: the success breaks and every error path
     * after the connection was created land here, the quic layer and
     * the harness-owned buffers die before the exit leak check
     */

teardown:

    /*
     * the harness-owned streams first: dropping them runs the quic
     * stream cleanup and removes them from the parent tree, so the
     * silent abort below completes in one pass and no stream pool
     * outlives the process
     */
    s3_interop_client_stream_close(s3_interop_h3_stream);
    s3_interop_client_stream_close(s3_interop_h3_channel);
    s3_interop_client_stream_close(s3_interop_stream);
    s3_interop_client_stream_close(s3_interop_jump_stream);
    s3_interop_client_stream_close(s3_interop_jump_channel);

    (void)s3_quic_close_connection(cli, S3_ABORT);

    if (s3_interop_jump_cli != NULL) {
        (void)s3_quic_close_connection(s3_interop_jump_cli, S3_ABORT);
    }

    /* the master leaves no stale socket file behind, also on a timeout */

    if (s3_interop_cm_master) {
        s3_interop_cm_shutdown();
    }

    /*
     * the posted drain: the force-reset streams run their teardown
     * handlers, the quic close reposts until the connection pools die
     */

    for (i = 0; i < 64; i++) {

        if (s3_quic_get_connection(cli) == NULL &&
            (s3_interop_jump_cli == NULL || s3_quic_get_connection(s3_interop_jump_cli) == NULL) &&
            s3_queue_empty(&ctx.posted_events)) {
            break;
        }

        s3_event_process_posted(&ctx, &ctx.posted_events);
    }

    s3_ssl_free(conf.ssl);

    if (s3_interop_jump_conf.ssl != NULL) {
        s3_ssl_free(s3_interop_jump_conf.ssl);
    }

    free(s3_interop_expected);
    free(s3_interop_got);
    free(s3_interop_fwd_payload);

    /* the mode-local accumulators grow by realloc, NULL free is fine */

    free(s3_interop_h3_buf);
    free(s3_interop_h3_ch_buf);
    free(s3_interop_h3_sess_out);
    free(s3_interop_sftp_out);
    free(s3_interop_sftp_buf);
    free(s3_interop_agent_in);

    (void)close(fd);

    if (s3_interop_jump_fd >= 0) {
        (void)close(s3_interop_jump_fd);
    }

    if (s3_interop_bridge_a >= 0) {
        (void)close(s3_interop_bridge_a);
    }

    if (s3_interop_bridge_b >= 0) {
        (void)close(s3_interop_bridge_b);
    }

    /* the event method data dies with the pool of the connections */

    s3_event_ctx_shutdown(&ctx);

    return rc;
}
