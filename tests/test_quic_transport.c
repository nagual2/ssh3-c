/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <s3_quic.h>
#include <s3_quic_transport.h>
#include <s3_quic_protection.h>

#include "s3_test.h"

static s3_log_t s3_test_log;

static ssize_t
parse_one(s3_quic_header_t *pkt, uint8_t flags, u_char *start, u_char *end, s3_quic_frame_t *f)
{
    static s3_buf_t   b;
    static s3_chain_t cl;

    s3_memzero(&b, sizeof(s3_buf_t));

    cl.buf = &b;
    cl.next = NULL;

    f->data = &cl;

    pkt->log = &s3_test_log;
    pkt->flags = flags;
    pkt->level = S3_QUIC_ENCRYPTION_APPLICATION;

    return s3_quic_parse_frame(pkt, start, end, f);
}

static int
test_varint(void)
{
    struct {
        uint64_t      value;
        size_t        len;
        const uint8_t enc[8];
    } vectors[] = {
        /* RFC 9000, Appendix A.1 */
        {0, 1, {0x00}},
        {63, 1, {0x3f}},
        /* RFC 9000, Appendix A.2 */
        {15293, 2, {0x7b, 0xbd}},
        {624485, 4, {0x80, 0x09, 0x87, 0x65}},
        {494878333, 4, {0x9d, 0x7f, 0x3e, 0x7d}},
        {15293627, 4, {0x00}},
        {151288809941948553ULL, 8, {0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xd8, 0x89}},
    };

    size_t   i, j;
    ssize_t  n;
    u_char   buf[16];
    uint64_t gap, range;

    for (i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {

        /* encode: ack range [value, value] with a zero-length second varint */
        n = (ssize_t)s3_quic_create_ack_range(buf, vectors[i].value, 0);
        S3_ASSERT(n == (ssize_t)(vectors[i].len + 1));

        if (!vectors[i].enc[0] && vectors[i].value != 0) {
            /* roundtrip-only vector */
        } else {
            for (j = 0; j < vectors[i].len; j++) {
                S3_ASSERT(buf[j] == vectors[i].enc[j]);
            }
        }

        S3_ASSERT(buf[vectors[i].len] == 0x00);

        gap = range = (uint64_t)-1;
        n = s3_quic_parse_ack_range(&s3_test_log, buf, buf + vectors[i].len + 1, &gap, &range);
        S3_ASSERT(n == (ssize_t)(vectors[i].len + 1));
        S3_ASSERT(gap == vectors[i].value);
        S3_ASSERT(range == 0);
    }

    /* truncated varint fails */
    buf[0] = 0xc2;
    buf[1] = 0x19;
    n = s3_quic_parse_ack_range(&s3_test_log, buf, buf + 2, &gap, &range);
    S3_ASSERT(n == S3_ERROR);

    return s3_test_failures;
}

static int
test_frames_roundtrip(void)
{
    s3_quic_header_t pkt;
    s3_quic_frame_t  f, p;
    s3_buf_t         b;
    s3_chain_t       cl;
    u_char           buf[128];
    u_char           ranges[] = {0x01, 0x03, 0x00, 0x02};
    u_char           data[] = "hello world 1234";
    u_char           cid[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    u_char           srt[16] = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
                                0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf};
    u_char           pc[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    ssize_t          len, n;
    uint64_t         gap, range;

    s3_memzero(&pkt, sizeof(s3_quic_header_t));

    /* PING */

    s3_memzero(&f, sizeof(s3_quic_frame_t));
    f.type = S3_QUIC_FT_PING;

    len = s3_quic_create_frame(NULL, &f);
    S3_ASSERT(len == 1);

    n = s3_quic_create_frame(buf, &f);
    S3_ASSERT(n == len);
    S3_ASSERT(f.need_ack == 1);

    s3_memzero(&p, sizeof(s3_quic_frame_t));
    n = parse_one(&pkt, 0x43, buf, buf + n, &p);
    S3_ASSERT(n == 1);
    S3_ASSERT(p.type == S3_QUIC_FT_PING);
    S3_ASSERT(p.level == S3_QUIC_ENCRYPTION_APPLICATION);

    /* ACK with ranges */

    s3_memzero(&f, sizeof(s3_quic_frame_t));
    f.type = S3_QUIC_FT_ACK;
    f.u.ack.largest = 10;
    f.u.ack.delay = 100;
    f.u.ack.range_count = 2;
    f.u.ack.first_range = 5;
    f.u.ack.ranges_length = sizeof(ranges); /* the caller fills this in */

    s3_memzero(&b, sizeof(s3_buf_t));
    b.pos = ranges;
    b.last = ranges + sizeof(ranges);
    cl.buf = &b;
    cl.next = NULL;
    f.data = &cl;

    len = s3_quic_create_frame(NULL, &f);
    S3_ASSERT(len == 10); /* the delay 100 takes a 2-byte varint */

    n = s3_quic_create_frame(buf, &f);
    S3_ASSERT(n == len);
    S3_ASSERT(f.need_ack == 0);

    s3_memzero(&p, sizeof(s3_quic_frame_t));
    n = parse_one(&pkt, 0x43, buf, buf + n, &p);
    S3_ASSERT(n == 10);
    S3_ASSERT(p.type == S3_QUIC_FT_ACK);
    S3_ASSERT(p.u.ack.largest == 10);
    S3_ASSERT(p.u.ack.delay == 100);
    S3_ASSERT(p.u.ack.range_count == 2);
    S3_ASSERT(p.u.ack.first_range == 5);
    S3_ASSERT(p.u.ack.ranges_length == 4);

    n = s3_quic_parse_ack_range(&s3_test_log, p.data->buf->pos, p.data->buf->last, &gap, &range);
    S3_ASSERT(n == 2);
    S3_ASSERT(gap == 1 && range == 3);

    n = s3_quic_parse_ack_range(&s3_test_log, p.data->buf->pos + 2, p.data->buf->last, &gap,
                                &range);
    S3_ASSERT(n == 2);
    S3_ASSERT(gap == 0 && range == 2);

    /* CRYPTO */

    s3_memzero(&f, sizeof(s3_quic_frame_t));
    f.type = S3_QUIC_FT_CRYPTO;
    f.u.crypto.offset = 16;
    f.u.crypto.length = 5;

    s3_memzero(&b, sizeof(s3_buf_t));
    b.pos = data;
    b.last = data + 5;
    cl.buf = &b;
    cl.next = NULL;
    f.data = &cl;

    len = s3_quic_create_frame(NULL, &f);
    S3_ASSERT(len == 8);

    n = s3_quic_create_frame(buf, &f);
    S3_ASSERT(n == len);

    s3_memzero(&p, sizeof(s3_quic_frame_t));
    n = parse_one(&pkt, 0x43, buf, buf + n, &p);
    S3_ASSERT(n == 8);
    S3_ASSERT(p.type == S3_QUIC_FT_CRYPTO);
    S3_ASSERT(p.u.crypto.offset == 16);
    S3_ASSERT(p.u.crypto.length == 5);
    S3_ASSERT(s3_memcmp(p.data->buf->pos, data, 5) == 0);

    /* STREAM with length: create with the base type, the flags
       (off/len/fin) select the subtype byte like in nginx */

    s3_memzero(&f, sizeof(s3_quic_frame_t));
    f.type = S3_QUIC_FT_STREAM;
    f.u.stream.stream_id = 4;
    f.u.stream.off = 0;
    f.u.stream.len = 1;
    f.u.stream.fin = 0;
    f.u.stream.length = 5;

    s3_memzero(&b, sizeof(s3_buf_t));
    b.pos = data + 6;
    b.last = data + 11;
    cl.buf = &b;
    cl.next = NULL;
    f.data = &cl;

    len = s3_quic_create_frame(NULL, &f);
    S3_ASSERT(len == 8);

    n = s3_quic_create_frame(buf, &f);
    S3_ASSERT(n == len);
    S3_ASSERT(buf[0] == S3_QUIC_FT_STREAM2);

    s3_memzero(&p, sizeof(s3_quic_frame_t));
    n = parse_one(&pkt, 0x43, buf, buf + n, &p);
    S3_ASSERT(n == 8);
    S3_ASSERT(p.type == S3_QUIC_FT_STREAM);
    S3_ASSERT(p.u.stream.stream_id == 4);
    S3_ASSERT(p.u.stream.off == 0);
    S3_ASSERT(p.u.stream.len == 1);
    S3_ASSERT(p.u.stream.fin == 0);
    S3_ASSERT(p.u.stream.length == 5);
    S3_ASSERT(s3_memcmp(p.data->buf->pos, data + 6, 5) == 0);

    /* STREAM with offset and fin (0x0D) */

    s3_memzero(&f, sizeof(s3_quic_frame_t));
    f.type = S3_QUIC_FT_STREAM;
    f.u.stream.stream_id = 0x1234;
    f.u.stream.offset = 70000;
    f.u.stream.off = 1;
    f.u.stream.len = 1;
    f.u.stream.fin = 1;
    f.u.stream.length = 5;

    s3_memzero(&b, sizeof(s3_buf_t));
    b.pos = data;
    b.last = data + 5;
    cl.buf = &b;
    cl.next = NULL;
    f.data = &cl;

    len = s3_quic_create_frame(NULL, &f);
    S3_ASSERT(len == 1 + 2 + 4 + 1 + 5);

    n = s3_quic_create_frame(buf, &f);
    S3_ASSERT(n == len);

    s3_memzero(&p, sizeof(s3_quic_frame_t));
    n = parse_one(&pkt, 0x43, buf, buf + n, &p);
    S3_ASSERT(n == len);
    S3_ASSERT(p.type == S3_QUIC_FT_STREAM);
    S3_ASSERT(p.u.stream.stream_id == 0x1234);
    S3_ASSERT(p.u.stream.offset == 70000);
    S3_ASSERT(p.u.stream.fin == 1);
    S3_ASSERT(p.u.stream.length == 5);

    /* CONNECTION_CLOSE (application) */

    s3_memzero(&f, sizeof(s3_quic_frame_t));
    f.type = S3_QUIC_FT_CONNECTION_CLOSE_APP;
    f.u.close.error_code = S3_QUIC_ERR_APPLICATION_ERROR;
    f.u.close.reason.len = 3;
    f.u.close.reason.data = (u_char *)"bug";

    len = s3_quic_create_frame(NULL, &f);
    S3_ASSERT(len == 6);

    n = s3_quic_create_frame(buf, &f);
    S3_ASSERT(n == len);
    S3_ASSERT(f.need_ack == 0);

    s3_memzero(&p, sizeof(s3_quic_frame_t));
    n = parse_one(&pkt, 0x43, buf, buf + n, &p);
    S3_ASSERT(n == 6);
    S3_ASSERT(p.type == S3_QUIC_FT_CONNECTION_CLOSE_APP);
    S3_ASSERT(p.u.close.error_code == S3_QUIC_ERR_APPLICATION_ERROR);
    S3_ASSERT(p.u.close.reason.len == 3);
    S3_ASSERT(s3_memcmp(p.u.close.reason.data, "bug", 3) == 0);

    /* NEW_CONNECTION_ID */

    s3_memzero(&f, sizeof(s3_quic_frame_t));
    f.type = S3_QUIC_FT_NEW_CONNECTION_ID;
    f.u.ncid.seqnum = 1;
    f.u.ncid.retire = 0;
    f.u.ncid.len = 8;
    s3_memcpy(f.u.ncid.cid, cid, 8);
    s3_memcpy(f.u.ncid.srt, srt, 16);

    len = s3_quic_create_frame(NULL, &f);
    S3_ASSERT(len == 28);

    n = s3_quic_create_frame(buf, &f);
    S3_ASSERT(n == len);

    s3_memzero(&p, sizeof(s3_quic_frame_t));
    n = parse_one(&pkt, 0x43, buf, buf + n, &p);
    S3_ASSERT(n == 28);
    S3_ASSERT(p.type == S3_QUIC_FT_NEW_CONNECTION_ID);
    S3_ASSERT(p.u.ncid.seqnum == 1);
    S3_ASSERT(p.u.ncid.retire == 0);
    S3_ASSERT(p.u.ncid.len == 8);
    S3_ASSERT(s3_memcmp(p.u.ncid.cid, cid, 8) == 0);
    S3_ASSERT(s3_memcmp(p.u.ncid.srt, srt, 16) == 0);

    /* RETIRE_CONNECTION_ID */

    s3_memzero(&f, sizeof(s3_quic_frame_t));
    f.type = S3_QUIC_FT_RETIRE_CONNECTION_ID;
    f.u.retire_cid.sequence_number = 0x12345678;

    len = s3_quic_create_frame(NULL, &f);
    S3_ASSERT(len == 5);

    n = s3_quic_create_frame(buf, &f);
    S3_ASSERT(n == len);

    s3_memzero(&p, sizeof(s3_quic_frame_t));
    n = parse_one(&pkt, 0x43, buf, buf + n, &p);
    S3_ASSERT(n == 5);
    S3_ASSERT(p.type == S3_QUIC_FT_RETIRE_CONNECTION_ID);
    S3_ASSERT(p.u.retire_cid.sequence_number == 0x12345678);

    /* MAX_DATA */

    s3_memzero(&f, sizeof(s3_quic_frame_t));
    f.type = S3_QUIC_FT_MAX_DATA;
    f.u.max_data.max_data = 1000;

    len = s3_quic_create_frame(NULL, &f);
    S3_ASSERT(len == 3);

    n = s3_quic_create_frame(buf, &f);
    S3_ASSERT(n == len);

    s3_memzero(&p, sizeof(s3_quic_frame_t));
    n = parse_one(&pkt, 0x43, buf, buf + n, &p);
    S3_ASSERT(n == 3);
    S3_ASSERT(p.type == S3_QUIC_FT_MAX_DATA);
    S3_ASSERT(p.u.max_data.max_data == 1000);

    /* PATH_CHALLENGE */

    s3_memzero(&f, sizeof(s3_quic_frame_t));
    f.type = S3_QUIC_FT_PATH_CHALLENGE;
    s3_memcpy(f.u.path_challenge.data, pc, 8);

    len = s3_quic_create_frame(NULL, &f);
    S3_ASSERT(len == 9);

    n = s3_quic_create_frame(buf, &f);
    S3_ASSERT(n == len);

    s3_memzero(&p, sizeof(s3_quic_frame_t));
    n = parse_one(&pkt, 0x43, buf, buf + n, &p);
    S3_ASSERT(n == 9);
    S3_ASSERT(p.type == S3_QUIC_FT_PATH_CHALLENGE);
    S3_ASSERT(s3_memcmp(p.u.path_challenge.data, pc, 8) == 0);

    /* unknown frame type: varint 64 > S3_QUIC_FT_LAST */

    s3_memzero(&p, sizeof(s3_quic_frame_t));
    buf[0] = 0x40;
    buf[1] = 0x40;
    n = parse_one(&pkt, 0x43, buf, buf + 8, &p);
    S3_ASSERT(n == S3_ERROR);
    S3_ASSERT(pkt.error == S3_QUIC_ERR_FRAME_ENCODING_ERROR);

    return s3_test_failures;
}

static int
test_datagram_frames(void)
{
    s3_quic_header_t pkt;
    s3_quic_frame_t  f, p;
    s3_buf_t         b;
    s3_chain_t       cl;
    u_char           buf[64];
    u_char           data[3] = {'x', 'y', 'z'};
    ssize_t          len, n;

    s3_memzero(&pkt, sizeof(s3_quic_header_t));

    /* create DATAGRAM_WITH_LENGTH (0x31) */

    s3_memzero(&f, sizeof(s3_quic_frame_t));
    f.type = S3_QUIC_FT_DATAGRAM_WITH_LENGTH;
    f.u.datagram.length = 3;

    s3_memzero(&b, sizeof(s3_buf_t));
    b.pos = data;
    b.last = data + 3;
    cl.buf = &b;
    cl.next = NULL;
    f.data = &cl;

    len = s3_quic_create_frame(NULL, &f);
    S3_ASSERT(len == 5);

    n = s3_quic_create_frame(buf, &f);
    S3_ASSERT(n == len);
    S3_ASSERT(buf[0] == S3_QUIC_FT_DATAGRAM_WITH_LENGTH);
    S3_ASSERT(buf[1] == 0x03);
    S3_ASSERT(f.need_ack == 0);

    s3_memzero(&p, sizeof(s3_quic_frame_t));
    n = parse_one(&pkt, 0x43, buf, buf + n, &p);
    S3_ASSERT(n == 5);
    S3_ASSERT(p.type == S3_QUIC_FT_DATAGRAM_WITH_LENGTH);
    S3_ASSERT(p.u.datagram.length == 3);
    S3_ASSERT(s3_memcmp(p.data->buf->pos, data, 3) == 0);

    /* create bare DATAGRAM (0x30): length is implied by the packet end */

    s3_memzero(&f, sizeof(s3_quic_frame_t));
    f.type = S3_QUIC_FT_DATAGRAM;
    f.u.datagram.length = 3;
    f.data = &cl;

    len = s3_quic_create_frame(NULL, &f);
    S3_ASSERT(len == 4);

    n = s3_quic_create_frame(buf, &f);
    S3_ASSERT(n == len);
    S3_ASSERT(buf[0] == S3_QUIC_FT_DATAGRAM);
    S3_ASSERT(f.need_ack == 0);

    s3_memzero(&p, sizeof(s3_quic_frame_t));
    n = parse_one(&pkt, 0x43, buf, buf + n, &p);
    S3_ASSERT(n == 4);
    S3_ASSERT(p.type == S3_QUIC_FT_DATAGRAM);
    S3_ASSERT(p.u.datagram.length == 3);
    S3_ASSERT(s3_memcmp(p.data->buf->pos, data, 3) == 0);

    /* truncated 0x31 */

    buf[0] = S3_QUIC_FT_DATAGRAM_WITH_LENGTH;
    buf[1] = 0x05; /* length 5 > remaining 1 */
    buf[2] = 'a';

    s3_memzero(&p, sizeof(s3_quic_frame_t));
    n = parse_one(&pkt, 0x43, buf, buf + 3, &p);
    S3_ASSERT(n == S3_ERROR);
    S3_ASSERT(pkt.error == S3_QUIC_ERR_FRAME_ENCODING_ERROR);

    /* DATAGRAM is not allowed outside 1-RTT packets (RFC 9221, 4) */

    buf[0] = S3_QUIC_FT_DATAGRAM;
    buf[1] = 'a';

    s3_memzero(&p, sizeof(s3_quic_frame_t));
    n = parse_one(&pkt, 0xc0, buf, buf + 2, &p); /* initial packet */
    S3_ASSERT(n == S3_ERROR);
    S3_ASSERT(pkt.error == S3_QUIC_ERR_PROTOCOL_VIOLATION);

    s3_memzero(&p, sizeof(s3_quic_frame_t));
    n = parse_one(&pkt, 0xe3, buf, buf + 2, &p); /* handshake packet */
    S3_ASSERT(n == S3_ERROR);
    S3_ASSERT(pkt.error == S3_QUIC_ERR_PROTOCOL_VIOLATION);

    return s3_test_failures;
}

static int
test_headers(void)
{
    s3_quic_header_t pkt;
    u_char           buf[1300];
    u_char           dcid[8] = {0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4};
    u_char           scid[8] = {5, 6, 7, 8, 0x0a, 0x0b, 0x0c, 0x0d};
    u_char           payload[3] = {'a', 'b', 'c'};
    u_char           short_pkt[40];
    u_char           vn[32];
    s3_str_t         dcid_out;
    size_t           n;
    u_char          *pnp;
    ssize_t          rc;

    /* version negotiation: parse fails with version 0 */

    s3_memzero(&pkt, sizeof(s3_quic_header_t));
    pkt.log = &s3_test_log;
    pkt.flags = 0xc0;
    pkt.dcid.len = 2;
    pkt.dcid.data = dcid;
    pkt.scid.len = 2;
    pkt.scid.data = scid;

    n = s3_quic_create_version_negotiation(&pkt, vn);
    S3_ASSERT(n == 15);

    s3_memzero(&pkt, sizeof(s3_quic_header_t));
    pkt.log = &s3_test_log;
    pkt.flags = vn[0];
    pkt.raw = &(s3_buf_t){.pos = vn + 1, .last = vn + n};
    pkt.data = vn;
    pkt.len = n;

    rc = s3_quic_parse_packet(&pkt);
    S3_ASSERT(rc == S3_ERROR);

    /* long header (Handshake) create/parse roundtrip */

    s3_memzero(&pkt, sizeof(s3_quic_header_t));
    pkt.log = &s3_test_log;
    pkt.flags = 0xe3; /* long, fixed, handshake, pn len 4 */
    pkt.version = 1;
    pkt.level = S3_QUIC_ENCRYPTION_HANDSHAKE;
    pkt.dcid.len = 8;
    pkt.dcid.data = dcid;
    pkt.scid.len = 8;
    pkt.scid.data = scid;
    pkt.num_len = 1;
    pkt.trunc = 7;
    pkt.payload.len = 3;
    pkt.payload.data = payload;

    n = s3_quic_create_header(&pkt, buf, &pnp);
    S3_ASSERT(n == 25);

    /* pn + payload + the 16-byte tag placeholder the length counts */
    buf[n] = 7; /* packet number */
    s3_memcpy(buf + n + 1, payload, 3);
    s3_memset(buf + n + 4, 0xcc, S3_QUIC_TAG_LEN);

    s3_memzero(&pkt, sizeof(s3_quic_header_t));
    pkt.log = &s3_test_log;
    pkt.flags = buf[0];
    pkt.raw = &(s3_buf_t){.pos = buf + 1, .last = buf + 45};
    pkt.data = buf;
    pkt.len = 45;

    rc = s3_quic_parse_packet(&pkt);
    S3_ASSERT(rc == S3_OK);
    S3_ASSERT(pkt.level == S3_QUIC_ENCRYPTION_HANDSHAKE);
    S3_ASSERT(pkt.version == 1);
    S3_ASSERT(pkt.dcid.len == 8);
    S3_ASSERT(s3_memcmp(pkt.dcid.data, dcid, 8) == 0);
    S3_ASSERT(pkt.scid.len == 8);
    S3_ASSERT(s3_memcmp(pkt.scid.data, scid, 8) == 0);
    S3_ASSERT(pkt.raw->pos == buf + 24);

    /* Initial: datagram below 1200 bytes is declined */

    s3_memzero(&pkt, sizeof(s3_quic_header_t));
    pkt.log = &s3_test_log;
    pkt.flags = 0xc0;
    pkt.raw = &(s3_buf_t){.pos = buf + 1, .last = buf + 1199};
    pkt.data = buf;
    pkt.len = 1199;

    /* flags, version, dcid len+data, scid len+data */
    buf[0] = 0xc0;
    s3_memset(buf + 1, 0, 4); /* version 1 below */
    buf[1] = 0x00;
    buf[2] = 0x00;
    buf[3] = 0x00;
    buf[4] = 0x01;
    buf[5] = 8;
    s3_memcpy(buf + 6, dcid, 8);
    buf[14] = 8;
    s3_memcpy(buf + 15, scid, 8);
    buf[23] = 0x00; /* empty token */

    rc = s3_quic_parse_packet(&pkt);
    /*
     * parse_packet collapses the "too small" DECLINED of the Initial
     * v1 parser into S3_ERROR (nginx does the same)
     */
    S3_ASSERT(rc == S3_ERROR);

    /* restart from the datagram start: exactly 1200 bytes parses ok */

    buf[24] = 0x44; /* length 1174, 2-byte varint */
    buf[25] = 0x96;
    s3_memset(buf + 26, 0xaa, 1200 - 26);

    pkt.raw->pos = buf + 1;
    pkt.flags = buf[0];
    pkt.raw->last = buf + 1200;
    pkt.len = 1200;

    rc = s3_quic_parse_packet(&pkt);
    S3_ASSERT(rc == S3_OK);
    S3_ASSERT(pkt.level == S3_QUIC_ENCRYPTION_INITIAL);
    S3_ASSERT(pkt.token.len == 0);
    S3_ASSERT(pkt.len == 1200);

    /* short header: the dcid is S3_QUIC_SERVER_CID_LEN (20) bytes */

    short_pkt[0] = 0x41;
    s3_memcpy(short_pkt + 1, dcid, 8);
    s3_memcpy(short_pkt + 9, scid, 8);
    s3_memcpy(short_pkt + 17, dcid, 4);
    s3_memset(short_pkt + 21, 0, 5); /* pn + junk */

    s3_memzero(&pkt, sizeof(s3_quic_header_t));
    pkt.log = &s3_test_log;
    pkt.flags = short_pkt[0];
    pkt.raw = &(s3_buf_t){.pos = short_pkt + 1, .last = short_pkt + 26};
    pkt.data = short_pkt;
    pkt.len = 26;

    rc = s3_quic_parse_packet(&pkt);
    S3_ASSERT(rc == S3_OK);
    S3_ASSERT(pkt.level == S3_QUIC_ENCRYPTION_APPLICATION);
    S3_ASSERT(pkt.dcid.len == 20);
    S3_ASSERT(pkt.raw->pos == short_pkt + 21);

    /* dcid extraction (short and long forms) */

    rc = s3_quic_get_packet_dcid(&s3_test_log, short_pkt, 26, &dcid_out);
    S3_ASSERT(rc == S3_OK);
    S3_ASSERT(dcid_out.len == 20);
    S3_ASSERT(dcid_out.data == short_pkt + 1);

    buf[0] = 0xc0;
    buf[5] = 8;
    rc = s3_quic_get_packet_dcid(&s3_test_log, buf, 14, &dcid_out);
    S3_ASSERT(rc == S3_OK);
    S3_ASSERT(dcid_out.len == 8);
    S3_ASSERT(dcid_out.data == buf + 6);

    rc = s3_quic_get_packet_dcid(&s3_test_log, buf, 13, &dcid_out);
    S3_ASSERT(rc == S3_ERROR);

    /* payload size (short) */

    s3_memzero(&pkt, sizeof(s3_quic_header_t));
    pkt.flags = 0x41;
    pkt.dcid.len = 8;
    pkt.num_len = 1;

    n = s3_quic_payload_size(&pkt, 1200);
    S3_ASSERT(n == 1200 - (1 + 8 + 1 + 16));

    /* payload size (long, initial):
       flags+version+cid lens (5+2), dcid+scid (8+8), token len (1),
       length varint of 1176 (2), pn (1), tag (16) */
    pkt.flags = 0xc0;
    pkt.level = S3_QUIC_ENCRYPTION_INITIAL;
    pkt.scid.len = 8;

    n = s3_quic_payload_size(&pkt, 1200);
    S3_ASSERT(n == 1200 - (5 + 2 + 8 + 8 + 1 + 2 + 1 + 16));

    return s3_test_failures;
}

static int
test_transport_params(void)
{
    s3_quic_conf_t qcf;
    s3_quic_tp_t   tp, parsed;
    u_char         buf[512];
    u_char         orig[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    u_char         scid[8] = {9, 8, 7, 6, 5, 4, 3, 2};
    u_char         srt[16] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                              0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    size_t         clen, n;
    ssize_t        len;

    s3_memzero(&qcf, sizeof(s3_quic_conf_t));
    qcf.idle_timeout = 60000;
    qcf.stream_buffer_size = 4096;
    qcf.max_concurrent_streams_bidi = 128;
    qcf.max_concurrent_streams_uni = 16;
    qcf.active_connection_id_limit = 8;
    qcf.disable_active_migration = 1;
    qcf.max_datagram_frame_size = 1200;

    S3_ASSERT(s3_quic_init_transport_params(&tp, &qcf) == S3_OK);

    S3_ASSERT(tp.max_idle_timeout == 60000);
    S3_ASSERT(tp.max_udp_payload_size == S3_QUIC_MAX_UDP_PAYLOAD_SIZE);
    S3_ASSERT(tp.initial_max_data == (128 + 16) * 4096);
    S3_ASSERT(tp.initial_max_streams_bidi == 128);
    S3_ASSERT(tp.initial_max_streams_uni == 16);
    S3_ASSERT(tp.active_connection_id_limit == 8);
    S3_ASSERT(tp.disable_active_migration == 1);
    S3_ASSERT(tp.max_datagram_frame_size == 1200);
    S3_ASSERT(tp.max_ack_delay == S3_QUIC_DEFAULT_MAX_ACK_DELAY);
    S3_ASSERT(tp.ack_delay_exponent == S3_QUIC_DEFAULT_ACK_DELAY_EXPONENT);

    /* RFC vector values ride through the varint coder */
    tp.initial_max_streams_bidi = 151288809941952654ULL;
    tp.initial_max_data = 494878333;
    tp.max_ack_delay = 624485;
    tp.max_udp_payload_size = 15293627;
    tp.ack_delay_exponent = 15293;
    tp.active_connection_id_limit = 0;

    tp.original_dcid.len = 8;
    tp.original_dcid.data = orig;
    tp.initial_scid.len = 8;
    tp.initial_scid.data = scid;
    s3_memcpy(tp.sr_token, srt, 16);

    len = s3_quic_create_transport_params(NULL, NULL, &tp, &clen);
    S3_ASSERT(len > 0 && (size_t)len <= sizeof(buf));
    S3_ASSERT(clen > 0 && clen < (size_t)len);

    n = s3_quic_create_transport_params(buf, buf + len, &tp, &clen);
    S3_ASSERT(n == (size_t)len);

    /* the 0-RTT prefix must parse on its own */
    s3_memzero(&parsed, sizeof(s3_quic_tp_t));
    S3_ASSERT(s3_quic_parse_transport_params(buf, buf + clen, &parsed, &s3_test_log) == S3_OK);
    S3_ASSERT(parsed.initial_max_data == tp.initial_max_data);
    S3_ASSERT(parsed.max_idle_timeout == tp.max_idle_timeout);
    S3_ASSERT(parsed.max_datagram_frame_size == 0); /* not in the 0-RTT set */

    /*
     * the server blob carries original_dcid and sr_token; both are
     * forbidden in client transport parameters, the parser rejects it
     */
    S3_ASSERT(s3_quic_parse_transport_params(buf, buf + n, &parsed, &s3_test_log) == S3_ERROR);

    /*
     * the server-only tail of the blob: original_dcid TLV (1+1+8),
     * initial_scid TLV (1+1+8) and sr_token TLV (1+1+16) — 38 bytes
     * total.  original_dcid and sr_token are forbidden in client
     * transport parameters, so the parse range stops before the tail;
     * the tail bytes are verified directly
     */
    len = s3_quic_create_transport_params(NULL, NULL, &tp, NULL);
    n = s3_quic_create_transport_params(buf, buf + len, &tp, NULL);
    S3_ASSERT(n == (size_t)len);
    S3_ASSERT(n >= 38);

    S3_ASSERT(buf[n - 38] == S3_QUIC_TP_ORIGINAL_DCID);
    S3_ASSERT(buf[n - 37] == 8);
    S3_ASSERT(s3_memcmp(buf + n - 36, orig, 8) == 0);
    S3_ASSERT(buf[n - 28] == S3_QUIC_TP_INITIAL_SCID);
    S3_ASSERT(buf[n - 27] == 8);
    S3_ASSERT(s3_memcmp(buf + n - 26, scid, 8) == 0);
    S3_ASSERT(buf[n - 18] == S3_QUIC_TP_SR_TOKEN);
    S3_ASSERT(buf[n - 17] == S3_QUIC_SR_TOKEN_LEN);
    S3_ASSERT(s3_memcmp(buf + n - 16, srt, 16) == 0);

    s3_memzero(&parsed, sizeof(s3_quic_tp_t));
    S3_ASSERT(s3_quic_parse_transport_params(buf, buf + n - 38, &parsed, &s3_test_log) == S3_OK);
    S3_ASSERT(parsed.initial_max_streams_bidi == 151288809941952654ULL);
    S3_ASSERT(parsed.initial_max_data == 494878333);
    S3_ASSERT(parsed.max_ack_delay == 624485);
    S3_ASSERT(parsed.max_udp_payload_size == 15293627);
    S3_ASSERT(parsed.ack_delay_exponent == 15293);
    S3_ASSERT(parsed.active_connection_id_limit == 0);
    S3_ASSERT(parsed.disable_active_migration == 1);
    S3_ASSERT(parsed.max_datagram_frame_size == 1200);

    /* no datagram TP when disabled; init_transport_params() zeroes the
       dcid/token fields, so the tail shrinks to 22 bytes (2+2+18) */

    qcf.max_datagram_frame_size = 0;
    S3_ASSERT(s3_quic_init_transport_params(&tp, &qcf) == S3_OK);

    len = s3_quic_create_transport_params(buf, buf + sizeof(buf), &tp, NULL);

    S3_ASSERT(buf[len - 22] == S3_QUIC_TP_ORIGINAL_DCID);
    S3_ASSERT(buf[len - 21] == 0);
    S3_ASSERT(buf[len - 20] == S3_QUIC_TP_INITIAL_SCID);
    S3_ASSERT(buf[len - 19] == 0);
    S3_ASSERT(buf[len - 18] == S3_QUIC_TP_SR_TOKEN);
    S3_ASSERT(buf[len - 17] == S3_QUIC_SR_TOKEN_LEN);

    s3_memzero(&parsed, sizeof(s3_quic_tp_t));
    S3_ASSERT(s3_quic_parse_transport_params(buf, buf + len - 22, &parsed, &s3_test_log) == S3_OK);
    S3_ASSERT(parsed.max_datagram_frame_size == 0);

    /* forbidden client params */

    buf[0] = S3_QUIC_TP_ORIGINAL_DCID;
    buf[1] = 0x00;
    S3_ASSERT(s3_quic_parse_transport_params(buf, buf + 2, &parsed, &s3_test_log) == S3_ERROR);

    /* unknown and reserved params are skipped */

    buf[0] = 27; /* 27 % 31 == 27: reserved greasing */
    buf[1] = 0x01;
    buf[2] = 0x01;
    buf[3] = 0x40; /* unknown id 100 */
    buf[4] = 0x64;
    buf[5] = 0x00;
    S3_ASSERT(s3_quic_parse_transport_params(buf, buf + 6, &parsed, &s3_test_log) == S3_OK);

    /* trailing garbage */

    buf[0] = S3_QUIC_TP_MAX_IDLE_TIMEOUT;
    buf[1] = 0x01;
    buf[2] = 0x05;
    buf[3] = 0xff;
    S3_ASSERT(s3_quic_parse_transport_params(buf, buf + 4, &parsed, &s3_test_log) == S3_ERROR);

    /* declared length longer than data */

    buf[0] = S3_QUIC_TP_MAX_IDLE_TIMEOUT;
    buf[1] = 0x05;
    buf[2] = 0x01;
    S3_ASSERT(s3_quic_parse_transport_params(buf, buf + 3, &parsed, &s3_test_log) == S3_ERROR);

    return s3_test_failures;
}

static int
s3_test_quic_transport(void)
{
    s3_test_log.log_level = S3_LOG_ALERT;
    s3_test_log.fd = S3_INVALID_FILE;

    test_varint();
    test_frames_roundtrip();
    test_datagram_frames();
    test_headers();
    test_transport_params();

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_quic_transport)
