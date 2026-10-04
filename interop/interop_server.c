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
 * (s3_h3_init_stream()), the bidi streams run the extended CONNECT
 * validator below.  In this mode stdout additionally carries:
 *   INTEROP-H3-CONNECT-OK authlen=<len>
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/rand.h>

#include <s3_h3.h>
#include <s3_h3_uni.h>
#include <s3_nonblocking.h>
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

/* the h3 mode (-3): RFC 9220 extended CONNECT instead of the echo */
static unsigned s3_interop_h3_mode;

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
s3_interop_datagram_echo(s3_connection_t *c, s3_chain_t *data)
{
    u_char     *buf;
    size_t      len;
    s3_chain_t *cl;

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
static unsigned         s3_interop_h3_responded;

static u_char s3_interop_h3_method[32];
static size_t s3_interop_h3_method_len;
static u_char s3_interop_h3_protocol[32];
static size_t s3_interop_h3_protocol_len;
static u_char s3_interop_h3_path[256];
static size_t s3_interop_h3_path_len;
static u_char s3_interop_h3_auth[256];
static size_t s3_interop_h3_auth_len;

/* the response tail pending on the send window */
static u_char s3_interop_h3_out[512];
static size_t s3_interop_h3_out_len;

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
    u_char *p;
    size_t  sec_len, total;
    ssize_t m;

    /*
     * the section is built first: the HEADERS frame header carries its
     * exact length.  Every status section here fits the two-byte
     * varlen frame header on top
     */
    p = s3_interop_h3_out + 2;
    p = s3_interop_h3_put_status(p, code);
    sec_len = p - (s3_interop_h3_out + 2);

    s3_interop_h3_out[0] = S3_H3_FRAME_HEADERS;
    s3_interop_h3_out[1] = (u_char)sec_len;

    total = 2 + sec_len;

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

static void
s3_interop_h3_respond(void)
{
    unsigned code;

    if (s3_interop_h3_responded) {
        return;
    }

    /* RFC 9220: :protocol marks an extended CONNECT, ssh3 is our route */
    if (s3_interop_h3_method_len == 7 && s3_memcmp(s3_interop_h3_method, "CONNECT", 7) == 0 &&
        s3_interop_h3_protocol_len == 4 && s3_memcmp(s3_interop_h3_protocol, "ssh3", 4) == 0 &&
        s3_interop_h3_path_len == 10 && s3_memcmp(s3_interop_h3_path, "/ssh3-term", 10) == 0) {
        code = s3_interop_h3_auth_len ? 200 : 401;

    } else {
        code = 400;
    }

    if (code == 200) {
        printf("INTEROP-H3-CONNECT-OK authlen=%zu\n", s3_interop_h3_auth_len);
        fflush(stdout);
    }

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
                s3_interop_h3_respond();
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

    if (s3_interop_h3_sc != NULL) {
        /* one request stream at a time in the harness */
        fprintf(stderr, "interop-server: extra h3 request stream ignored\n");
        return;
    }

    s3_interop_h3_sc = sc;
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
            "usage: %s -l addr:port -c cert.pem -k key.pem [-3] [-A alpn] [-d dg_size]\n"
            "  -l  UDP listen address, port 0 picks an ephemeral one\n"
            "  -c  certificate PEM file\n"
            "  -k  private key PEM file\n"
            "  -3  h3 mode: RFC 9220 extended CONNECT (ssh3) instead of the echo\n"
            "  -A  ALPN name, default s3interop/1 (h3 in the -3 mode)\n"
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

    while ((opt = (char)getopt(argc, argv, "l:c:k:A:d:i:3h")) != -1) {

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

    if (s3_nonblocking(fd) != S3_OK) {
        perror("fcntl(O_NONBLOCK)");
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
