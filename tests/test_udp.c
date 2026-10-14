/*
 * Copyright (C) 2026 the ssh3-c authors
 */

/*
 * tests for the udp event path: pseudo connections on a listening
 * socket and the shared recv semantics, then two listeners on
 * different ports running in one context with the interleaved
 * datagrams (the per-listener receive holders)
 */

#include <s3_core.h>

#include <s3_nonblocking.h>
#include <s3_udp_sendmsg_chain.h>

#if (S3_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include <unistd.h>

#include "s3_test.h"

#define S3_TEST_DGRAM1 "hello"
#define S3_TEST_DGRAM2 "world"

static s3_connection_t *s3_test_udp_accepted;
static int              s3_test_udp_accepts;
static int              s3_test_udp_reads;
static ssize_t          s3_test_udp_read_n;
static u_char           s3_test_udp_read_buf[64];

/* the two-listener scenario tracks the listeners separately */

static s3_connection_t *s3_test_udp_accepted_a;
static s3_connection_t *s3_test_udp_accepted_b;
static int              s3_test_udp_accepts_a;
static int              s3_test_udp_accepts_b;
static int              s3_test_udp_reads_a;
static int              s3_test_udp_reads_b;
static ssize_t          s3_test_udp_read_n_a;
static ssize_t          s3_test_udp_read_n_b;
static u_char           s3_test_udp_read_buf_a[64];
static u_char           s3_test_udp_read_buf_b[64];

static void
s3_test_udp_read_handler(s3_event_t *ev)
{
    s3_connection_t *c = (s3_connection_t *)ev->data;

    s3_test_udp_read_n = c->recv(c, s3_test_udp_read_buf, sizeof(s3_test_udp_read_buf));
    s3_test_udp_reads++;
}

static void
s3_test_udp_read_handler_a(s3_event_t *ev)
{
    s3_connection_t *c = (s3_connection_t *)ev->data;

    s3_test_udp_read_n_a = c->recv(c, s3_test_udp_read_buf_a, sizeof(s3_test_udp_read_buf_a));
    s3_test_udp_reads_a++;
}

static void
s3_test_udp_read_handler_b(s3_event_t *ev)
{
    s3_connection_t *c = (s3_connection_t *)ev->data;

    s3_test_udp_read_n_b = c->recv(c, s3_test_udp_read_buf_b, sizeof(s3_test_udp_read_buf_b));
    s3_test_udp_reads_b++;
}

static void
s3_test_udp_accept_handler(s3_connection_t *c)
{
    s3_test_udp_accepted = c;
    s3_test_udp_accepts++;

    c->read->handler = s3_test_udp_read_handler;
}

static void
s3_test_udp_accept_handler_a(s3_connection_t *c)
{
    s3_test_udp_accepted_a = c;
    s3_test_udp_accepts_a++;

    c->read->handler = s3_test_udp_read_handler_a;
}

static void
s3_test_udp_accept_handler_b(s3_connection_t *c)
{
    s3_test_udp_accepted_b = c;
    s3_test_udp_accepts_b++;

    c->read->handler = s3_test_udp_read_handler_b;
}

static int
s3_test_udp_single(void)
{
    int                lsd, csd;
    ssize_t            n;
    socklen_t          slen;
    u_char             buf[64];
    s3_event_ctx_t     ctx;
    s3_connection_t   *lc, *c;
    s3_udp_listen_t    ul;
    struct sockaddr_in sa;

    S3_ASSERT(s3_event_ctx_init(&ctx, &s3_stderr_log) == S3_OK);

    /* the listening udp socket */

    lsd = socket(AF_INET, SOCK_DGRAM, 0);
    S3_ASSERT(lsd != -1);
    S3_ASSERT(s3_nonblocking(lsd) == S3_OK);

    s3_memzero(&sa, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;

    S3_ASSERT(bind(lsd, (struct sockaddr *)&sa, sizeof(sa)) == 0);

    slen = sizeof(sa);
    S3_ASSERT(getsockname(lsd, (struct sockaddr *)&sa, &slen) == 0);

    lc = s3_get_connection(&ctx, lsd);
    S3_ASSERT(lc != NULL);

    /* a real listening socket knows its local address */

    lc->sockaddr = (struct sockaddr *)s3_palloc(ctx.pool, slen);
    S3_ASSERT(lc->sockaddr != NULL);
    s3_memcpy(lc->sockaddr, &sa, slen);
    lc->socklen = slen;

    /* the client socket */

    csd = socket(AF_INET, SOCK_DGRAM, 0);
    S3_ASSERT(csd != -1);
    S3_ASSERT(s3_nonblocking(csd) == S3_OK);

    s3_memzero(&ul, sizeof(ul));
    ul.connection = lc;
    ul.ctx = &ctx;
    ul.handler = s3_test_udp_accept_handler;
    s3_rbtree_init(&ul.rbtree, &ul.sentinel, s3_udp_rbtree_insert_value);

    lc->data = &ul;
    lc->read->handler = s3_event_recvmsg;

    S3_ASSERT(s3_event_actions.add_event(lc->read, S3_READ_EVENT, 0) == S3_OK);

    /* two datagrams from the client */

    S3_ASSERT(sendto(csd, S3_TEST_DGRAM1, sizeof(S3_TEST_DGRAM1) - 1, 0, (struct sockaddr *)&sa,
                     slen) == (ssize_t)(sizeof(S3_TEST_DGRAM1) - 1));

    S3_ASSERT(sendto(csd, S3_TEST_DGRAM2, sizeof(S3_TEST_DGRAM2) - 1, 0, (struct sockaddr *)&sa,
                     slen) == (ssize_t)(sizeof(S3_TEST_DGRAM2) - 1));

    /* the first iteration accepts the pseudo connection */

    s3_process_events_and_timers(&ctx);

    S3_ASSERT(s3_test_udp_accepts == 1);

    c = s3_test_udp_accepted;
    S3_ASSERT(c != NULL);

    if (c == NULL) {
        /* avoid a cascade of failures after a broken accept */

        (void)s3_test_close(csd);
        (void)s3_test_close(lsd);
        s3_destroy_pool(ctx.pool);

        return s3_test_failures;
    }

    S3_ASSERT(c->recv == s3_udp_shared_recv);
    S3_ASSERT(c->send_chain == s3_udp_sendmsg_chain);
    S3_ASSERT(c->shared == 1);
    S3_ASSERT(c->read->active == 1);
    S3_ASSERT(c->udp != NULL);

    /* the first datagram is consumed via the shared recv */

    n = c->recv(c, buf, sizeof(buf));
    S3_ASSERT(n == (ssize_t)(sizeof(S3_TEST_DGRAM1) - 1));
    S3_ASSERT(s3_memcmp(buf, S3_TEST_DGRAM1, n) == 0);

    /* the buffer was consumed; the next read returns S3_AGAIN */

    S3_ASSERT(c->recv(c, buf, sizeof(buf)) == (ssize_t)S3_AGAIN);

    /* the second iteration delivers the second datagram through
       the read handler of the same pseudo connection */

    s3_process_events_and_timers(&ctx);

    S3_ASSERT(s3_test_udp_accepts == 1); /* no new pseudo connection */
    S3_ASSERT(s3_test_udp_reads == 1);
    S3_ASSERT(s3_test_udp_read_n == (ssize_t)(sizeof(S3_TEST_DGRAM2) - 1));
    S3_ASSERT(s3_memcmp(s3_test_udp_read_buf, S3_TEST_DGRAM2, s3_test_udp_read_n) == 0);

    /* closing the pseudo connection removes it from the rbtree */

    s3_close_connection(c);

    S3_ASSERT(ul.rbtree.root == &ul.sentinel);

    (void)s3_test_close(csd);
    (void)s3_test_close(lsd);

    s3_destroy_pool(ctx.pool);

    return s3_test_failures;
}

/*
 * the two listeners of one context: the datagrams arrive interleaved
 * on different ports, every listener delivers its own into its own
 * receive holder (the process-wide holder would cross them)
 */
static int
s3_test_udp_multi(void)
{
    int                lsd_a, lsd_b, csd;
    ssize_t            n;
    socklen_t          slen;
    u_char             buf[64];
    s3_event_ctx_t     ctx;
    s3_connection_t   *lc_a, *lc_b, *c_a, *c_b;
    s3_udp_listen_t    ul_a, ul_b;
    struct sockaddr_in sa_a, sa_b;

    s3_test_udp_accepts_a = 0;
    s3_test_udp_accepts_b = 0;
    s3_test_udp_reads_a = 0;
    s3_test_udp_reads_b = 0;

    S3_ASSERT(s3_event_ctx_init(&ctx, &s3_stderr_log) == S3_OK);

    /* the two listening udp sockets on different ports */

    lsd_a = socket(AF_INET, SOCK_DGRAM, 0);
    S3_ASSERT(lsd_a != -1);
    S3_ASSERT(s3_nonblocking(lsd_a) == S3_OK);

    lsd_b = socket(AF_INET, SOCK_DGRAM, 0);
    S3_ASSERT(lsd_b != -1);
    S3_ASSERT(s3_nonblocking(lsd_b) == S3_OK);

    s3_memzero(&sa_a, sizeof(sa_a));
    sa_a.sin_family = AF_INET;
    sa_a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa_a.sin_port = 0;

    S3_ASSERT(bind(lsd_a, (struct sockaddr *)&sa_a, sizeof(sa_a)) == 0);

    slen = sizeof(sa_a);
    S3_ASSERT(getsockname(lsd_a, (struct sockaddr *)&sa_a, &slen) == 0);

    s3_memzero(&sa_b, sizeof(sa_b));
    sa_b.sin_family = AF_INET;
    sa_b.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa_b.sin_port = 0;

    S3_ASSERT(bind(lsd_b, (struct sockaddr *)&sa_b, sizeof(sa_b)) == 0);

    slen = sizeof(sa_b);
    S3_ASSERT(getsockname(lsd_b, (struct sockaddr *)&sa_b, &slen) == 0);

    lc_a = s3_get_connection(&ctx, lsd_a);
    S3_ASSERT(lc_a != NULL);

    lc_b = s3_get_connection(&ctx, lsd_b);
    S3_ASSERT(lc_b != NULL);

    lc_a->sockaddr = (struct sockaddr *)s3_palloc(ctx.pool, sizeof(sa_a));
    S3_ASSERT(lc_a->sockaddr != NULL);
    s3_memcpy(lc_a->sockaddr, &sa_a, sizeof(sa_a));
    lc_a->socklen = sizeof(sa_a);

    lc_b->sockaddr = (struct sockaddr *)s3_palloc(ctx.pool, sizeof(sa_b));
    S3_ASSERT(lc_b->sockaddr != NULL);
    s3_memcpy(lc_b->sockaddr, &sa_b, sizeof(sa_b));
    lc_b->socklen = sizeof(sa_b);

    /* the client socket */

    csd = socket(AF_INET, SOCK_DGRAM, 0);
    S3_ASSERT(csd != -1);
    S3_ASSERT(s3_nonblocking(csd) == S3_OK);

    s3_memzero(&ul_a, sizeof(ul_a));
    ul_a.connection = lc_a;
    ul_a.ctx = &ctx;
    ul_a.handler = s3_test_udp_accept_handler_a;
    s3_rbtree_init(&ul_a.rbtree, &ul_a.sentinel, s3_udp_rbtree_insert_value);

    s3_memzero(&ul_b, sizeof(ul_b));
    ul_b.connection = lc_b;
    ul_b.ctx = &ctx;
    ul_b.handler = s3_test_udp_accept_handler_b;
    s3_rbtree_init(&ul_b.rbtree, &ul_b.sentinel, s3_udp_rbtree_insert_value);

    lc_a->data = &ul_a;
    lc_a->read->handler = s3_event_recvmsg;

    lc_b->data = &ul_b;
    lc_b->read->handler = s3_event_recvmsg;

    S3_ASSERT(s3_event_actions.add_event(lc_a->read, S3_READ_EVENT, 0) == S3_OK);
    S3_ASSERT(s3_event_actions.add_event(lc_b->read, S3_READ_EVENT, 0) == S3_OK);

    /* one datagram to each listener, the first iteration accepts both */

    S3_ASSERT(sendto(csd, "alpha", 5, 0, (struct sockaddr *)&sa_a, sizeof(sa_a)) == 5);
    S3_ASSERT(sendto(csd, "beta", 4, 0, (struct sockaddr *)&sa_b, sizeof(sa_b)) == 4);

    s3_process_events_and_timers(&ctx);

    S3_ASSERT(s3_test_udp_accepts_a == 1);
    S3_ASSERT(s3_test_udp_accepts_b == 1);

    c_a = s3_test_udp_accepted_a;
    c_b = s3_test_udp_accepted_b;

    S3_ASSERT(c_a != NULL && c_b != NULL && c_a != c_b);

    if (c_a == NULL || c_b == NULL) {
        /* avoid a cascade of failures after a broken accept */

        (void)s3_test_close(csd);
        (void)s3_test_close(lsd_a);
        (void)s3_test_close(lsd_b);
        s3_destroy_pool(ctx.pool);

        return s3_test_failures;
    }

    /* every listener parked its own datagram in its own holder */

    n = c_a->recv(c_a, buf, sizeof(buf));
    S3_ASSERT(n == 5);
    S3_ASSERT(n < 0 || s3_memcmp(buf, "alpha", 5) == 0);

    n = c_b->recv(c_b, buf, sizeof(buf));
    S3_ASSERT(n == 4);
    S3_ASSERT(n < 0 || s3_memcmp(buf, "beta", 4) == 0);

    /* the interleaved round: the read handlers carry the own payloads */

    S3_ASSERT(sendto(csd, "gamma", 5, 0, (struct sockaddr *)&sa_a, sizeof(sa_a)) == 5);

    s3_process_events_and_timers(&ctx);

    S3_ASSERT(s3_test_udp_accepts_a == 1); /* no new pseudo connection */
    S3_ASSERT(s3_test_udp_reads_a == 1);
    S3_ASSERT(s3_test_udp_read_n_a == 5);
    S3_ASSERT(s3_memcmp(s3_test_udp_read_buf_a, "gamma", 5) == 0);
    S3_ASSERT(s3_test_udp_reads_b == 0);

    S3_ASSERT(sendto(csd, "delta", 5, 0, (struct sockaddr *)&sa_b, sizeof(sa_b)) == 5);

    s3_process_events_and_timers(&ctx);

    S3_ASSERT(s3_test_udp_accepts_b == 1);
    S3_ASSERT(s3_test_udp_reads_b == 1);
    S3_ASSERT(s3_test_udp_read_n_b == 5);
    S3_ASSERT(s3_memcmp(s3_test_udp_read_buf_b, "delta", 5) == 0);
    S3_ASSERT(s3_test_udp_reads_a == 1);

    s3_close_connection(c_a);
    s3_close_connection(c_b);

    S3_ASSERT(ul_a.rbtree.root == &ul_a.sentinel);
    S3_ASSERT(ul_b.rbtree.root == &ul_b.sentinel);

    (void)s3_test_close(csd);
    (void)s3_test_close(lsd_a);
    (void)s3_test_close(lsd_b);

    s3_destroy_pool(ctx.pool);

    return s3_test_failures;
}

int
s3_test_udp(void)
{
    /* both scenarios count into the shared s3_test_failures */

    (void)s3_test_udp_single();
    (void)s3_test_udp_multi();

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_udp)
