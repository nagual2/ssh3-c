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
 * stdout carries the machine-readable protocol of the runner:
 *   INTEROP-HANDSHAKE-OK
 *   INTEROP-DATAGRAM-OK sent=N recv=N
 *   INTEROP-STREAM-OK sent=N recv=N
 *   INTEROP-H3-STATUS <code>
 *   INTEROP-CHANNEL-OK len=<payload length>
 * the exit code is 0 only when the mode's success line came back
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

#include <s3_h3.h>
#include <s3_h3_uni.h>
#include <s3_nonblocking.h>

#include <s3_quic.h>
#include <s3_quic_connection.h>
#include <s3_quic_output.h>
#include <s3_quic_streams.h>
#include <s3_ssh3_channel.h>
#include <s3_ssh3_message.h>
#include <s3_ssh3_request.h>
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

static void
s3_interop_client_datagram(s3_connection_t *c, s3_chain_t *data)
{
    u_char     *exp;
    uint32_t    idx;
    size_t      len, n;
    s3_chain_t *cl;

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
        n += (size_t)s3_interop_h3_field_l(NULL, ":path", "/ssh3-term");
        n += (size_t)s3_interop_h3_field_l(NULL, "user-agent", S3_SSH3_VERSION_STRING);
        n += (size_t)s3_interop_h3_field_l(NULL, "authorization", "test-token");
        return n;
    }

    p = (u_char *)s3_h3_encode_field_section_prefix(p, 0, 0, 0);
    p = (u_char *)s3_interop_h3_field_l(p, ":method", "CONNECT");
    p = (u_char *)s3_interop_h3_field_l(p, ":protocol", "ssh3");
    p = (u_char *)s3_interop_h3_field_l(p, ":scheme", "https");
    p = (u_char *)s3_interop_h3_field_l(p, ":authority", "example.lan");
    p = (u_char *)s3_interop_h3_field_l(p, ":path", "/ssh3-term");
    p = (u_char *)s3_interop_h3_field_l(p, "user-agent", S3_SSH3_VERSION_STRING);
    p = (u_char *)s3_interop_h3_field_l(p, "authorization", "test-token");

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

static void
s3_interop_h3_client_stream(s3_connection_t *c, s3_quic_stream_t *qs)
{
    s3_connection_t *pc;

    /*
     * the h3 client side (-3): the server-initiated streams are the
     * uni control/encoder/decoder ones, they belong to the session
     * port; the port reads the stream connection's data as the
     * s3_quic_stream_t.  The CONNECT stream is opened locally
     */

    pc = qs->parent;

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

static void
s3_interop_usage(const char *prog)
{
    fprintf(
        stderr,
        "usage: %s -a addr:port [-3] [-C] [-S] [-n count] [-s size] [-m min] [-t ms] [-A alpn]\n"
        "  -a  peer UDP address\n"
        "  -3  h3 mode: RFC 9220 extended CONNECT (ssh3), the verdict is :status\n"
        "  -C  h3 mode: after the 200 open the ssh3 session channel, send the\n"
        "      shell request and a ping, the verdict is the echoed ping\n"
        "  -S  stream echo mode: pump count*size pattern bytes through a stream\n"
        "  -n  datagrams to send (stream: count chunks), default 8\n"
        "  -s  datagram payload size (stream: chunk size), default 512\n"
        "  -m  require at least this many echoes, default all (RFC 9221 loss runs)\n"
        "  -t  overall deadline in ms, default 20000\n"
        "  -A  ALPN name, default s3interop/1 (h3 in the -3 mode)\n"
        "  -T  offline h3 wire-format selftest, no network (TEMPORARY)\n",
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

    while ((opt = (char)getopt(argc, argv, "a:n:s:m:t:A:d:3CTSCh")) != -1) {

        switch (opt) {

        case 'S':
            s3_interop_streams_mode = 1;
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

    if (s3_nonblocking(fd) != S3_OK) {
        perror("fcntl(O_NONBLOCK)");
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

    if (s3_interop_h3_mode) {
        /* the server's uni streams go to the session port, see above */
        conf.stream_handler = s3_interop_h3_client_stream;
    }

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

            if (s3_interop_h3_mode) {

                /*
                 * the h3 session first: SETTINGS go out on the control
                 * stream from inside s3_h3_init_session(), the quic-go
                 * server expects them before the request stream
                 */
                if (s3_h3_get_session(cli) == NULL && s3_h3_init_session(cli) != S3_OK) {
                    fprintf(stderr, "interop-client: h3 init_session failed\n");
                    return 1;
                }

                s3_memzero(&s3_interop_h3_parse, sizeof(s3_h3_parse_headers_t));

                s3_interop_h3_stream = s3_quic_open_stream(cli, 1);
                if (s3_interop_h3_stream == NULL) {
                    fprintf(stderr, "interop-client: open_stream failed\n");
                    return 1;
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
                    return 1;
                }

                s3_interop_stream->read->handler = s3_interop_stream_echo_read;
                s3_interop_stream->read->data = s3_interop_stream;

                s3_interop_stream->read->active = 1;

            } else if (qc->client_tp_done && qc->ctp.max_datagram_frame_size == 0) {
                fprintf(stderr, "interop-client: peer does not support datagrams\n");
                return 1;
            }
        }

        if (s3_interop_h3_mode) {

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
                    return 1;
                }

                else {
                    s3_interop_h3_req_sent = 1;
                }
            }

            if (s3_interop_h3_status_seen && s3_interop_h3_channel_mode) {

                /*
                 * the session channel comes up right after the 200:
                 * the next client bidi stream (ChannelID == its
                 * StreamID) carries the channel header, the shell
                 * request and the ping probe, one send for all three
                 */
                if (s3_interop_h3_channel == NULL) {

                    s3_interop_h3_channel = s3_quic_open_stream(cli, 1);

                    if (s3_interop_h3_channel == NULL) {
                        fprintf(stderr, "interop-client: channel open_stream failed\n");
                        return 1;
                    }

                    s3_interop_h3_channel->read->handler = s3_interop_h3_channel_read;
                    s3_interop_h3_channel->read->data = s3_interop_h3_channel;

                    /*
                     * the app-level read arming, the same the CONNECT
                     * stream got: without it the quic layer raises
                     * ready but never posts the stream events
                     */
                    s3_interop_h3_channel->read->active = 1;
                }

                if (!s3_interop_h3_ch_sent) {
                    u_char                frame[512];
                    u_char               *p;
                    s3_ssh3_channel_t     hdr;
                    s3_ssh3_msg_request_t req;
                    s3_ssh3_msg_data_t    data;
                    s3_ssh3_request_t     body;
                    size_t                total;
                    ssize_t               m;

                    /* the header: the conversation is the CONNECT stream */
                    s3_memzero(&hdr, sizeof(hdr));

                    hdr.conversation_stream_id =
                        ((s3_quic_stream_t *)s3_interop_h3_stream->data)->id;
                    hdr.type.data = (u_char *)S3_SSH3_CHANNEL_TYPE_SESSION;
                    hdr.type.len = strlen(S3_SSH3_CHANNEL_TYPE_SESSION);
                    hdr.max_packet_size = S3_INTEROP_CHANNEL_MAX_PACKET;

                    /* the shell request: the body is empty by design */
                    s3_memzero(&body, sizeof(body));
                    body.kind = S3_SSH3_REQ_SHELL;

                    s3_memzero(&req, sizeof(req));
                    req.request_type.data = (u_char *)s3_ssh3_request_type_str(S3_SSH3_REQ_SHELL);
                    req.request_type.len = strlen(s3_ssh3_request_type_str(S3_SSH3_REQ_SHELL));
                    req.want_reply = 1;

                    data.data.data = (u_char *)"ping";
                    data.data.len = 4;

                    p = frame;
                    p = (u_char *)s3_ssh3_channel_build_header(p, &hdr);
                    p = (u_char *)s3_ssh3_encode_varint(p, S3_SSH3_MSG_CHANNEL_REQUEST);
                    p = (u_char *)s3_ssh3_msg_encode_request(p, &req);
                    p = (u_char *)s3_ssh3_encode_varint(p, S3_SSH3_MSG_CHANNEL_DATA);
                    p = (u_char *)s3_ssh3_msg_encode_data(p, &data);

                    total = (size_t)(p - frame);

                    m = s3_quic_stream_send(s3_interop_h3_channel, frame, total);

                    if (m == (ssize_t)S3_AGAIN) {
                        /* the window opens on the write event, retried next pass */
                        ;
                    }

                    else if (m != (ssize_t)total) {
                        fprintf(stderr, "interop-client: channel send failed\n");
                        return 1;
                    }

                    else {
                        s3_interop_h3_ch_sent = 1;
                    }
                }
            }

            /*
             * the plain -3 run completes on the 200; the -C run goes
             * on until the ping came back echoed
             */
            if (s3_interop_h3_status_seen && (!s3_interop_h3_channel_mode || s3_interop_h3_ch_ok)) {
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
            if (s3_interop_h3_mode) {
                fprintf(stderr,
                        "interop-client: h3 timeout sent=%u status_seen=%u ch_sent=%u "
                        "ch_confirmed=%u ch_ok=%u\n",
                        s3_interop_h3_req_sent, s3_interop_h3_status_seen, s3_interop_h3_ch_sent,
                        s3_interop_h3_ch_confirmed, s3_interop_h3_ch_ok);
                return 1;
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
