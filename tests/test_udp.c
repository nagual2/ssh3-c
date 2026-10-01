/*
 * Copyright (C) 2026 the ssh3-c authors
 */

/*
 * tests for the udp event path: pseudo connections on a listening
 * socket and the shared recv semantics
 */

#include <s3_core.h>

#include <s3_udp_sendmsg_chain.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "s3_test.h"

#define S3_TEST_DGRAM1 "hello"
#define S3_TEST_DGRAM2 "world"

static s3_connection_t *s3_test_udp_accepted;
static int              s3_test_udp_accepts;
static int              s3_test_udp_reads;
static ssize_t          s3_test_udp_read_n;
static u_char           s3_test_udp_read_buf[64];

static void
s3_test_udp_read_handler(s3_event_t *ev)
{
    s3_connection_t *c = (s3_connection_t *)ev->data;

    s3_test_udp_read_n = c->recv(c, s3_test_udp_read_buf, sizeof(s3_test_udp_read_buf));
    s3_test_udp_reads++;
}

static void
s3_test_udp_accept_handler(s3_connection_t *c)
{
    s3_test_udp_accepted = c;
    s3_test_udp_accepts++;

    c->read->handler = s3_test_udp_read_handler;
}

int
s3_test_udp(void)
{
    int                failures, lsd, csd;
    ssize_t            n;
    socklen_t          slen;
    u_char             buf[64];
    s3_event_ctx_t     ctx;
    s3_connection_t   *lc, *c;
    s3_udp_listen_t    ul;
    struct sockaddr_in sa;

    failures = 0;

    S3_ASSERT(s3_event_ctx_init(&ctx, &s3_stderr_log) == S3_OK);

    /* the listening udp socket */

    lsd = socket(AF_INET, SOCK_DGRAM, 0);
    S3_ASSERT(lsd != -1);

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

        (void)close(csd);
        (void)close(lsd);
        s3_destroy_pool(ctx.pool);

        return failures;
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

    (void)close(csd);
    (void)close(lsd);

    s3_destroy_pool(ctx.pool);

    return failures;
}

S3_TEST_MAIN(s3_test_udp)
