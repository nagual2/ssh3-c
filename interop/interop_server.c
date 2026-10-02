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
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/rand.h>

#include <s3_quic.h>
#include <s3_quic_connection.h>
#include <s3_quic_output.h>
#include <s3_quic_streams.h>
#include <s3_ssl.h>

#define S3_INTEROP_TRACKED 64

static s3_log_t s3_interop_log;

static s3_quic_conf_t s3_interop_conf;

/* the accepted connections watched for the handshake completion */
static s3_connection_t *s3_interop_conns[S3_INTEROP_TRACKED];
static unsigned         s3_interop_reported[S3_INTEROP_TRACKED];
static unsigned         s3_interop_idle_reported[S3_INTEROP_TRACKED];
static s3_uint_t        s3_interop_nconns;

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

static void
s3_interop_datagram_echo(s3_connection_t *c, const u_char *data, size_t len)
{
    (void)s3_quic_send_datagram(c, data, len);
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
 * send window, otherwise the two naive sides deadlock
 */
static u_char          *s3_interop_echo_buf;
static size_t           s3_interop_echo_cap;
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

        m = s3_quic_stream_send(sc, s3_interop_echo_buf, s3_interop_echo_len);

        if (m == (ssize_t)S3_AGAIN) {
            return;
        }

        if (m <= 0) {
            fprintf(stderr, "interop-server: stream send failed\n");
            s3_interop_echo_len = 0;
            return;
        }

        s3_memmove(s3_interop_echo_buf, s3_interop_echo_buf + m, s3_interop_echo_len - m);
        s3_interop_echo_len -= m;
    }

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

        free_len = s3_interop_echo_cap - s3_interop_echo_len;

        if (free_len == 0) {
            size_t  cap = s3_interop_echo_cap + 262144;
            u_char *grown = realloc(s3_interop_echo_buf, cap);

            if (grown == NULL) {
                fprintf(stderr, "interop-server: echo buffer growth failed\n");
                exit(1);
            }

            s3_interop_echo_buf = grown;
            s3_interop_echo_cap = cap;
            free_len = s3_interop_echo_cap - s3_interop_echo_len;
        }

        n = sc->recv(sc, s3_interop_echo_buf + s3_interop_echo_len, free_len);

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

        m = s3_quic_stream_send(sc, s3_interop_echo_buf, s3_interop_echo_len);

        if (m == (ssize_t)S3_AGAIN) {
            continue; /* the window is full, the tail flushes on wev */
        }

        if (m <= 0) {
            fprintf(stderr, "interop-server: stream send failed\n");
            s3_interop_echo_len = 0;
            break;
        }

        s3_memmove(s3_interop_echo_buf, s3_interop_echo_buf + m, s3_interop_echo_len - m);
        s3_interop_echo_len -= m;
    }

    if (s3_interop_echo_fin && s3_interop_echo_len == 0) {
        (void)s3_quic_shutdown_stream(sc, S3_WRITE_SHUTDOWN);
    }
}

static void
s3_interop_stream_accept(s3_connection_t *c, s3_quic_stream_t *qs)
{
    s3_event_t *rev, *wev;

    (void)c;

    s3_interop_echo_sc = qs->connection;
    s3_interop_echo_len = 0;
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
            "usage: %s -l addr:port -c cert.pem -k key.pem [-A alpn] [-d dg_size]\n"
            "  -l  UDP listen address, port 0 picks an ephemeral one\n"
            "  -c  certificate PEM file\n"
            "  -k  private key PEM file\n"
            "  -A  ALPN name, default s3interop/1\n"
            "  -d  max_datagram_frame_size transport parameter, default 1200\n",
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

    while ((opt = (char)getopt(argc, argv, "l:c:k:A:d:i:h")) != -1) {

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

        default:
            s3_interop_usage(argv[0]);
            return 1;
        }
    }

    if (listen_text == NULL || cert_path == NULL || key_path == NULL) {
        s3_interop_usage(argv[0]);
        return 1;
    }

    if (s3_interop_parse_addr(listen_text, &sa) != S3_OK) {
        fprintf(stderr, "interop-server: bad listen address %s\n", listen_text);
        return 1;
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

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        perror("socket");
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
