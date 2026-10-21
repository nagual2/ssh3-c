/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#if (S3_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#endif

#include <string.h>
#include <time.h>

#include <s3_quic.h>
#include <s3_quic_tokens.h>

#include "s3_test.h"

static s3_log_t s3_test_log;

static void
make_addr(struct sockaddr_in *sin, in_port_t port)
{
    s3_memzero(sin, sizeof(struct sockaddr_in));

    sin->sin_family = AF_INET;
    sin->sin_port = htons(port);
    sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
}

static int
test_retry_token(void)
{
    s3_connection_t    c;
    s3_quic_header_t   pkt;
    s3_str_t           token, odcid, dcid;
    u_char             key[32], tokbuf[S3_QUIC_TOKEN_BUF_SIZE], cid[8] = "odcidcid";
    struct sockaddr_in sin, sin_other;
    size_t             i;
    int                rc;

    for (i = 0; i < 32; i++) {
        key[i] = (u_char)(0x20 + i);
    }

    make_addr(&sin, 8443);

    s3_memzero(&c, sizeof(s3_connection_t));
    c.log = &s3_test_log;
    c.sockaddr = (struct sockaddr *)&sin;
    c.socklen = sizeof(sin);

    odcid.len = 8;
    odcid.data = cid;

    token.len = sizeof(tokbuf);
    token.data = tokbuf;

    /* retry token binds the odcid */

    S3_ASSERT(s3_quic_new_token(&s3_test_log, c.sockaddr, c.socklen, key, &token, &odcid,
                                time(NULL) + 3600, 1) == S3_OK);
    S3_ASSERT(token.len == 12 + 20 + sizeof(time_t) + 1 + 1 + 8 + 16);

    s3_memzero(&pkt, sizeof(s3_quic_header_t));
    pkt.log = &s3_test_log;
    pkt.token = token;
    dcid.len = 8;
    dcid.data = (u_char *)"dcid1234";
    pkt.dcid = dcid;

    rc = s3_quic_validate_token(&c, key, &pkt);
    S3_ASSERT(rc == S3_OK);
    S3_ASSERT(pkt.validated == 1);
    S3_ASSERT(pkt.retried == 1);
    S3_ASSERT(pkt.odcid.len == 8);
    S3_ASSERT(s3_memcmp(pkt.odcid.data, cid, 8) == 0);

    /* the same token from another address is invalid */

    make_addr(&sin_other, 8444);

    c.sockaddr = (struct sockaddr *)&sin_other;
    c.socklen = sizeof(sin_other);

    s3_memzero(&pkt, sizeof(s3_quic_header_t));
    pkt.log = &s3_test_log;
    pkt.token = token;
    pkt.dcid = dcid;

    S3_ASSERT(s3_quic_validate_token(&c, key, &pkt) == S3_DECLINED);

    return s3_test_failures;
}

static int
test_address_token(void)
{
    s3_connection_t    c;
    s3_quic_header_t   pkt;
    s3_str_t           token, dcid;
    u_char             key[32], tokbuf[S3_QUIC_TOKEN_BUF_SIZE];
    struct sockaddr_in sin;
    size_t             i;
    int                rc;

    for (i = 0; i < 32; i++) {
        key[i] = (u_char)(0x50 + i);
    }

    make_addr(&sin, 8443);

    s3_memzero(&c, sizeof(s3_connection_t));
    c.log = &s3_test_log;
    c.sockaddr = (struct sockaddr *)&sin;
    c.socklen = sizeof(sin);

    token.len = sizeof(tokbuf);
    token.data = tokbuf;

    /* address validation token (no odcid, not a retry) */

    S3_ASSERT(s3_quic_new_token(&s3_test_log, c.sockaddr, c.socklen, key, &token, NULL,
                                time(NULL) + 3600, 0) == S3_OK);
    S3_ASSERT(token.len == 12 + 20 + sizeof(time_t) + 1 + 1 + 16);

    s3_memzero(&pkt, sizeof(s3_quic_header_t));
    pkt.log = &s3_test_log;
    pkt.token = token;
    dcid.len = 8;
    dcid.data = (u_char *)"dcid1234";
    pkt.dcid = dcid;

    rc = s3_quic_validate_token(&c, key, &pkt);
    S3_ASSERT(rc == S3_OK);
    S3_ASSERT(pkt.validated == 1);
    S3_ASSERT(pkt.retried == 0);
    S3_ASSERT(pkt.odcid.len == 8);

    /* the odcid is a copy, not an alias into the packet buffer */

    S3_ASSERT(pkt.odcid.data == pkt.odcid_buf);
    S3_ASSERT(s3_memcmp(pkt.odcid.data, dcid.data, 8) == 0);

    /* expired token */

    token.len = sizeof(tokbuf);
    token.data = tokbuf;

    S3_ASSERT(s3_quic_new_token(&s3_test_log, c.sockaddr, c.socklen, key, &token, NULL,
                                time(NULL) - 10, 0) == S3_OK);

    s3_memzero(&pkt, sizeof(s3_quic_header_t));
    pkt.log = &s3_test_log;
    pkt.token = token;
    pkt.dcid = dcid;

    S3_ASSERT(s3_quic_validate_token(&c, key, &pkt) == S3_DECLINED);

    /* corrupted ciphertext */

    token.len = sizeof(tokbuf);
    token.data = tokbuf;

    S3_ASSERT(s3_quic_new_token(&s3_test_log, c.sockaddr, c.socklen, key, &token, NULL,
                                time(NULL) + 3600, 0) == S3_OK);

    tokbuf[token.len - 2] ^= 0xff;

    s3_memzero(&pkt, sizeof(s3_quic_header_t));
    pkt.log = &s3_test_log;
    pkt.token = token;
    pkt.dcid = dcid;

    S3_ASSERT(s3_quic_validate_token(&c, key, &pkt) == S3_ABORT);

    /* garbage: shorter than iv + tag */

    s3_memzero(&pkt, sizeof(s3_quic_header_t));
    pkt.log = &s3_test_log;
    pkt.token.len = 20;
    pkt.token.data = tokbuf;
    pkt.dcid = dcid;

    S3_ASSERT(s3_quic_validate_token(&c, key, &pkt) == S3_ABORT);

    return s3_test_failures;
}

static int
test_sr_token(void)
{
    s3_connection_t    c;
    s3_str_t           cid;
    u_char             secret[32], token1[16], token2[16];
    struct sockaddr_in sin;
    size_t             i;

    for (i = 0; i < 32; i++) {
        secret[i] = (u_char)(0x70 + i);
    }

    make_addr(&sin, 8443);

    s3_memzero(&c, sizeof(s3_connection_t));
    c.log = &s3_test_log;
    c.sockaddr = (struct sockaddr *)&sin;
    c.socklen = sizeof(sin);

    cid.len = 8;
    cid.data = (u_char *)"sr-cid00";

    S3_ASSERT(s3_quic_new_sr_token(&c, &cid, secret, token1) == S3_OK);
    S3_ASSERT(s3_quic_new_sr_token(&c, &cid, secret, token2) == S3_OK);

    /* deterministic derivation from the same inputs */

    S3_ASSERT(s3_memcmp(token1, token2, 16) == 0);

    /* another connection id derives a different token */

    cid.data = (u_char *)"sr-cid01";

    S3_ASSERT(s3_quic_new_sr_token(&c, &cid, secret, token2) == S3_OK);
    S3_ASSERT(s3_memcmp(token1, token2, 16) != 0);

    return s3_test_failures;
}

static int
test_odcid_bound(void)
{
    s3_connection_t    c;
    s3_str_t           token, odcid;
    u_char             key[32], tokbuf[S3_QUIC_TOKEN_BUF_SIZE];
    u_char             cid[S3_QUIC_MAX_CID_LEN + 1];
    struct sockaddr_in sin;
    size_t             i;

    for (i = 0; i < 32; i++) {
        key[i] = (u_char)(0x30 + i);
    }

    make_addr(&sin, 8443);

    s3_memzero(&c, sizeof(s3_connection_t));
    c.log = &s3_test_log;
    c.sockaddr = (struct sockaddr *)&sin;
    c.socklen = sizeof(sin);

    s3_memzero(cid, sizeof(cid));

    token.len = sizeof(tokbuf);
    token.data = tokbuf;

    /* an odcid longer than the connection id bound must be refused */

    odcid.len = S3_QUIC_MAX_CID_LEN + 1;
    odcid.data = cid;

    S3_ASSERT(s3_quic_new_token(&s3_test_log, c.sockaddr, c.socklen, key, &token, &odcid,
                                time(NULL) + 3600, 1) == S3_ERROR);

    /* the bound itself is accepted */

    odcid.len = S3_QUIC_MAX_CID_LEN;

    S3_ASSERT(s3_quic_new_token(&s3_test_log, c.sockaddr, c.socklen, key, &token, &odcid,
                                time(NULL) + 3600, 1) == S3_OK);

    return s3_test_failures;
}

static int
s3_test_quic_tokens(void)
{
    s3_test_log.log_level = S3_LOG_ALERT;
    s3_test_log.fd = S3_INVALID_FILE;

    test_retry_token();
    test_address_token();
    test_sr_token();
    test_odcid_bound();

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_quic_tokens)
