/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the libFuzzer harness of the h3 parse layer (A3): the three parse
 * machines of the pre-auth CONNECT path (the request headers, the
 * request data and the control uni streams) are driven directly with
 * the buffer and the state of the API, so the mutated bytes meet the
 * machines without the session layer around them.
 *
 * the parse path itself allocates nothing: the machines keep their
 * state in the caller's structures and touch the connection only for
 * the log and for the session (the qpack table of the peer decoder) -
 * the scene is built once for the run, the machine states are on the
 * stack of the call.
 *
 * the input: the first byte picks the machine, the rest is the buffer
 * the machine reads.
 */

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

#include <s3_core.h>

#include <s3_h3.h>

#include "s3_fuzz.h"

/* the parse layer caps the field lines at 8k (the fixed
 * large_client_header_buffers size of s3_h3_parse.c) */
#define S3_FUZZ_H3_PARSE_MAX 8192

/* the rounds of the feed loop: a machine that wants more data gets
 * the buffer again, so the state machine walks its states */
#define S3_FUZZ_H3_PARSE_ROUNDS 4

static s3_log_t s3_fuzz_h3_parse_log = {0, S3_INVALID_FILE};

/* the scene of the run: the context, the request stream carrier, the
 * peer decoder and the session they share */

static s3_event_ctx_t   s3_fuzz_h3_ctx;
static s3_connection_t *s3_fuzz_h3_conn;
static s3_connection_t *s3_fuzz_h3_peer;
static s3_h3_session_t  s3_fuzz_h3_sess;
static s3_fd_t          s3_fuzz_h3_fd = -1;
static int              s3_fuzz_h3_ready;

static void
s3_fuzz_h3_dummy_read(s3_event_t *ev)
{
    (void)ev;
}

static s3_chain_t *
s3_fuzz_h3_dummy_send(s3_connection_t *c, s3_chain_t *in, long limit)
{
    (void)c;
    (void)in;
    (void)limit;

    return NULL;
}

static void
s3_fuzz_h3_inc_handler(s3_event_t *ev)
{
    (void)ev;
}

static void
s3_fuzz_h3_scene(void)
{
    struct sockaddr_in sa;

    if (s3_fuzz_h3_ready) {
        return;
    }

    s3_fuzz_h3_ready = 1;

    if (s3_event_ctx_init(&s3_fuzz_h3_ctx, &s3_fuzz_h3_parse_log) != S3_OK) {
        return;
    }

    s3_fuzz_h3_fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (s3_fuzz_h3_fd == -1) {
        return;
    }

    s3_memzero(&sa, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = 0;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(s3_fuzz_h3_fd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
        return;
    }

    /* the request stream carrier: the pool of the context, the
     * session on c->data (the unit-test scene of test_h3_qpack) */

    s3_fuzz_h3_conn = s3_get_connection(&s3_fuzz_h3_ctx, s3_fuzz_h3_fd);

    if (s3_fuzz_h3_conn == NULL) {
        return;
    }

    s3_fuzz_h3_conn->pool = s3_fuzz_h3_ctx.pool;
    s3_fuzz_h3_conn->read->handler = s3_fuzz_h3_dummy_read;

    s3_fuzz_h3_peer = s3_get_connection(&s3_fuzz_h3_ctx, s3_fuzz_h3_fd);

    if (s3_fuzz_h3_peer == NULL) {
        return;
    }

    s3_fuzz_h3_peer->pool = s3_fuzz_h3_ctx.pool;
    s3_fuzz_h3_peer->read->handler = s3_fuzz_h3_dummy_read;
    s3_fuzz_h3_peer->send_chain = s3_fuzz_h3_dummy_send;

    s3_queue_init(&s3_fuzz_h3_sess.blocked);
    s3_fuzz_h3_sess.ctx = &s3_fuzz_h3_ctx;

    s3_fuzz_h3_sess.table.send_insert_count.log = &s3_fuzz_h3_parse_log;
    s3_fuzz_h3_sess.table.send_insert_count.data = s3_fuzz_h3_peer;
    s3_fuzz_h3_sess.table.send_insert_count.handler = s3_fuzz_h3_inc_handler;

    s3_fuzz_h3_conn->data = &s3_fuzz_h3_sess;
    s3_fuzz_h3_peer->data = &s3_fuzz_h3_sess;

    s3_fuzz_h3_sess.known_streams[S3_H3_STREAM_SERVER_DECODER] = s3_fuzz_h3_peer;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    s3_h3_parse_headers_t hst;
    s3_h3_parse_data_t    dst;
    s3_h3_parse_uni_t     ust;
    s3_buf_t              b;
    u_char                buf[S3_FUZZ_H3_PARSE_MAX];
    size_t                n;
    int                   i, rc;

    if (size == 0) {
        return 0;
    }

    s3_fuzz_h3_scene();

    if (!s3_fuzz_h3_ready || s3_fuzz_h3_conn->read == NULL) {
        return 0;
    }

    s3_memzero(&hst, sizeof(hst));
    s3_memzero(&dst, sizeof(dst));
    s3_memzero(&ust, sizeof(ust));

    n = size - 1;

    if (n > sizeof(buf)) {
        n = sizeof(buf);
    }

    s3_memcpy(buf, data + 1, n);

    for (i = 0; i < S3_FUZZ_H3_PARSE_ROUNDS; i++) {

        s3_memzero(&b, sizeof(b));
        b.pos = buf;
        b.last = buf + n;

        switch (data[0] & 0x03) {

        case 0:
            rc = s3_h3_parse_headers(s3_fuzz_h3_conn, &hst, &b);
            break;

        case 1:
            rc = s3_h3_parse_data(s3_fuzz_h3_conn, &dst, &b);
            break;

        case 2:
            rc = s3_h3_parse_uni(s3_fuzz_h3_conn, &ust, &b);
            break;

        default:
            /* the three machines in turn over the same bytes */

            s3_memzero(&b, sizeof(b));
            b.pos = buf;
            b.last = buf + n;
            rc = s3_h3_parse_headers(s3_fuzz_h3_conn, &hst, &b);

            s3_memzero(&b, sizeof(b));
            b.pos = buf;
            b.last = buf + n;
            (void)s3_h3_parse_data(s3_fuzz_h3_conn, &dst, &b);

            s3_memzero(&b, sizeof(b));
            b.pos = buf;
            b.last = buf + n;
            (void)s3_h3_parse_uni(s3_fuzz_h3_conn, &ust, &b);

            break;
        }

        s3_fuzz_sink((size_t)rc + (size_t)(b.last - b.pos));
    }

    return 0;
}
