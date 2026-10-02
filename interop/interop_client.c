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
 * stdout carries the machine-readable protocol of the runner:
 *   INTEROP-HANDSHAKE-OK
 *   INTEROP-DATAGRAM-OK sent=N recv=N
 *   INTEROP-STREAM-OK sent=N recv=N
 * the exit code is 0 only when every echo came back
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <s3_quic.h>
#include <s3_quic_connection.h>
#include <s3_quic_output.h>
#include <s3_quic_streams.h>
#include <s3_ssl.h>

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

static void
s3_interop_client_datagram(s3_connection_t *c, const u_char *data, size_t len)
{
    uint32_t idx;

    (void)c;

    if (len < 4 || len != s3_interop_size) {
        return;
    }

    idx = s3_interop_read_le32(data);

    if (idx >= s3_interop_count || s3_interop_got[idx]) {
        return;
    }

    if (s3_memcmp(data, s3_interop_expected + idx * s3_interop_size, len) != 0) {
        return;
    }

    s3_interop_got[idx] = 1;
    s3_interop_received++;
}

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

static void
s3_interop_usage(const char *prog)
{
    fprintf(stderr,
            "usage: %s -a addr:port [-S] [-n count] [-s size] [-m min] [-t ms] [-A alpn]\n"
            "  -a  peer UDP address\n"
            "  -S  stream echo mode: pump count*size pattern bytes through a stream\n"
            "  -n  datagrams to send (stream: count chunks), default 8\n"
            "  -s  datagram payload size (stream: chunk size), default 512\n"
            "  -m  require at least this many echoes, default all (RFC 9221 loss runs)\n"
            "  -t  overall deadline in ms, default 20000\n"
            "  -A  ALPN name, default s3interop/1\n",
            prog);
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
    struct sockaddr_in    sa;
    s3_event_ctx_t        ctx;
    s3_connection_t      *cli;
    s3_quic_connection_t *qc;

    s3_interop_log_init();
    s3_interop_pattern_init();

    while ((opt = (char)getopt(argc, argv, "a:n:s:m:t:A:d:Sh")) != -1) {

        switch (opt) {

        case 'S':
            s3_interop_streams_mode = 1;
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

        default:
            s3_interop_usage(argv[0]);
            return 1;
        }
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

    if (s3_event_ctx_init(&ctx, &s3_interop_log) != S3_OK) {
        fprintf(stderr, "interop-client: event ctx init failed\n");
        return 1;
    }

    s3_interop_count = (size_t)n_arg;
    s3_interop_size = (size_t)s_arg;

    if (s3_interop_streams_mode) {
        s3_interop_stotal = s3_interop_count * s3_interop_size;

    } else {
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

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        perror("socket");
        return 1;
    }

    cli = s3_get_connection(&ctx, fd);
    if (cli == NULL) {
        fprintf(stderr, "interop-client: connection alloc failed\n");
        return 1;
    }

    cli->pool = s3_create_pool((size_t)S3_DEFAULT_POOL_SIZE, &s3_interop_log);
    if (cli->pool == NULL) {
        return 1;
    }

    cli->sockaddr = (struct sockaddr *)s3_palloc(cli->pool, sizeof(sa));
    if (cli->sockaddr == NULL) {
        return 1;
    }

    s3_memcpy(cli->sockaddr, &sa, sizeof(sa));
    cli->socklen = sizeof(sa);

    s3_interop_alpn_wire(alpn_wire, alpn_name);

    alpn.data = alpn_wire;
    alpn.len = 1 + strlen(alpn_name);

    s3_quic_conf_t conf;

    s3_memzero(&conf, sizeof(conf));

    conf.ssl = s3_ssl_client_create(&s3_interop_log, &alpn);
    if (conf.ssl == NULL) {
        fprintf(stderr, "interop-client: ssl init failed\n");
        return 1;
    }

    conf.gso_enabled = 1;
    conf.ctx = &ctx;
    conf.handshake_timeout = (s3_msec_t)timeout;
    conf.idle_timeout = 60000;
    conf.stream_buffer_size = 16384;
    conf.max_concurrent_streams_bidi = 16;
    conf.max_concurrent_streams_uni = 16;
    conf.active_connection_id_limit = 8;
    conf.max_datagram_frame_size = dg_size;
    conf.datagram_handler = s3_interop_client_datagram;

    for (i = 0; i < S3_QUIC_AV_KEY_LEN; i++) {
        conf.av_token_key[i] = (u_char)(0xa0 + i);
        conf.sr_token_key[i] = (u_char)(0xb0 + i);
    }

    if (s3_event_actions.add_event(cli->read, S3_READ_EVENT, 0) != S3_OK) {
        return 1;
    }

    if (s3_quic_connect(cli, &conf) != S3_OK) {
        fprintf(stderr, "interop-client: connect failed\n");
        return 1;
    }

    qc = s3_quic_get_connection(cli);
    if (qc == NULL) {
        return 1;
    }

    start = s3_current_msec;
    sent = 0;

    for (;;) {
        s3_event_process_posted(&ctx, &ctx.posted_events);

        s3_process_events_and_timers(&ctx);

        qc = s3_quic_get_connection(cli);

        if (qc == NULL) {
            fprintf(stderr, "interop-client: connection is gone\n");
            return 1;
        }

        if (!hs_reported && cli->ssl != NULL && cli->ssl->handshaked) {
            printf("INTEROP-HANDSHAKE-OK\n");
            fflush(stdout);

            hs_reported = 1;

            if (s3_interop_streams_mode) {
                /* open one bidirectional stream and verify the echo */
                s3_interop_stream = s3_quic_open_stream(cli, 1);
                if (s3_interop_stream == NULL) {
                    fprintf(stderr, "interop-client: open_stream failed\n");
                    return 1;
                }

                s3_interop_stream->read->handler = s3_interop_stream_echo_read;
                s3_interop_stream->read->data = s3_interop_stream;

            } else if (qc->client_tp_done && qc->ctp.max_datagram_frame_size == 0) {
                fprintf(stderr, "interop-client: peer does not support datagrams\n");
                return 1;
            }
        }

        if (s3_interop_streams_mode) {

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
                        return 1;
                    }

                    s3_interop_ssent += (size_t)m;
                }

                /* everything written: the fin makes the server close its side */
                if (s3_interop_ssent == s3_interop_stotal && !sfin_sent) {
                    if (s3_quic_shutdown_stream(s3_interop_stream, S3_WRITE_SHUTDOWN) != S3_OK) {
                        fprintf(stderr, "interop-client: stream shutdown failed\n");
                        return 1;
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
                    return 1;
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

            return 1;
        }
    }

    /*
     * the silent abort runs the full teardown: the ssl shutdown frees
     * the openssl object, the keys are cleansed and the connection
     * pool dies with the quic connection in it
     */
    (void)s3_quic_close_connection(cli, S3_ABORT);

    s3_event_process_posted(&ctx, &ctx.posted_events);

    s3_ssl_free(conf.ssl);

    free(s3_interop_expected);
    free(s3_interop_got);

    (void)close(fd);
    s3_destroy_pool(ctx.pool);

    return 0;
}
