/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the sftp v3 codec: the literal vectors of the wire, the frame
 * layer, the encode/parse roundtrips and the strictness of every
 * parser (the truncated body and the trailing garbage are errors)
 */

#include <s3_core.h>

#include <s3_ssh3_sftp.h>
#include <s3_ssh3_sftp_codec.h>

#include "s3_test.h"

/*
 * the one-string encoders (realpath, stat, opendir, rmdir, remove,
 * close, readdir, handle) share the shape and the one-string body
 * parsers (path, handle) share the signature, the pair walks the
 * whole encode/parse circle
 */

typedef uintptr_t (*s3_test_encode_str_pt)(u_char *p, uint32_t id, const s3_str_t *s);

typedef s3_int_t (*s3_test_parse_str_pt)(const s3_str_t *body, s3_str_t *out);

static void s3_test_check_attrs(const s3_ssh3_sftp_attrs_t *in, const s3_ssh3_sftp_attrs_t *out);
static void s3_test_roundtrip_string(s3_test_encode_str_pt encode, s3_test_parse_str_pt parse,
                                     uint8_t type, uint32_t id, const s3_str_t *s);
static void s3_test_body_prefixes(s3_test_parse_str_pt parse, const s3_str_t *body);
static void s3_test_attr_combo(const s3_ssh3_sftp_attrs_t *a, uintptr_t size);

static int s3_test_codec_literals(void);
static int s3_test_codec_frame(void);
static int s3_test_codec_scalars(void);
static int s3_test_codec_attrs(void);
static int s3_test_codec_requests(void);
static int s3_test_codec_replies(void);
static int s3_test_codec_strict(void);

static void
s3_test_check_attrs(const s3_ssh3_sftp_attrs_t *in, const s3_ssh3_sftp_attrs_t *out)
{
    S3_ASSERT(out->flags == in->flags);
    S3_ASSERT(out->size == in->size);
    S3_ASSERT(out->uid == in->uid);
    S3_ASSERT(out->gid == in->gid);
    S3_ASSERT(out->perms == in->perms);
    S3_ASSERT(out->atime == in->atime);
    S3_ASSERT(out->mtime == in->mtime);

    if (in->flags & S3_SSH3_SFTP_ATTR_EXTENDED) {
        S3_ASSERT(out->extended.len == in->extended.len);
        S3_ASSERT(out->extended.data != NULL);
        S3_ASSERT(s3_memcmp(out->extended.data, in->extended.data, in->extended.len) == 0);

    } else {
        S3_ASSERT(out->extended.len == 0);
    }
}

static void
s3_test_roundtrip_string(s3_test_encode_str_pt encode, s3_test_parse_str_pt parse, uint8_t type,
                         uint32_t id, const s3_str_t *s)
{
    u_char             buf[128];
    u_char            *p;
    const u_char      *pos, *end;
    s3_str_t           out;
    s3_ssh3_sftp_pkt_t pkt;

    s3_memzero(buf, sizeof(buf));

    S3_ASSERT(encode(NULL, id, s) == 13 + s->len);

    p = (u_char *)encode(buf, id, s);

    S3_ASSERT(p == buf + 13 + s->len);

    pos = buf;
    end = p;

    S3_ASSERT(s3_ssh3_sftp_codec_frame(&pos, end, &pkt) == S3_OK);
    S3_ASSERT(pkt.type == type);
    S3_ASSERT(pkt.has_id == 1);
    S3_ASSERT(pkt.request_id == id);
    S3_ASSERT(pos == end);

    /* the body view sits exactly between the id and the frame end */

    S3_ASSERT(pkt.body.len == 4 + s->len);
    S3_ASSERT(pkt.body.data == buf + 9);

    S3_ASSERT(parse(&pkt.body, &out) == S3_OK);
    S3_ASSERT(out.len == s->len);
    S3_ASSERT(s3_memcmp(out.data, s->data, s->len) == 0);
}

/*
 * every proper prefix of the body must fail and the byte past the
 * complete body is the trailing garbage, also a failure
 */

static void
s3_test_body_prefixes(s3_test_parse_str_pt parse, const s3_str_t *body)
{
    s3_str_t bad, out;
    size_t   i;

    for (i = 0; i < body->len; i++) {
        bad.data = body->data;
        bad.len = i;

        S3_ASSERT(parse(&bad, &out) == S3_ERROR);
    }

    bad.data = body->data;
    bad.len = body->len + 1;

    S3_ASSERT(parse(&bad, &out) == S3_ERROR);
}

static void
s3_test_attr_combo(const s3_ssh3_sftp_attrs_t *a, uintptr_t size)
{
    u_char               buf[128];
    u_char              *p;
    const u_char        *pos, *end;
    s3_ssh3_sftp_pkt_t   pkt;
    s3_ssh3_sftp_attrs_t out;

    s3_memzero(buf, sizeof(buf));

    S3_ASSERT(s3_ssh3_sftp_encode_attrs(NULL, 0xabcd, a) == size);

    p = (u_char *)s3_ssh3_sftp_encode_attrs(buf, 0xabcd, a);

    S3_ASSERT(p == buf + size);

    pos = buf;
    end = p;

    S3_ASSERT(s3_ssh3_sftp_codec_frame(&pos, end, &pkt) == S3_OK);
    S3_ASSERT(pkt.type == S3_SSH3_SFTP_ATTRS);
    S3_ASSERT(pkt.has_id == 1);
    S3_ASSERT(pkt.request_id == 0xabcd);
    S3_ASSERT(pos == end);

    /* the body holds the attrs block alone, the id already came in
     * pkt.request_id */

    pos = pkt.body.data;
    end = pkt.body.data + pkt.body.len;

    S3_ASSERT(s3_ssh3_sftp_parse_attrs(&pos, end, &out) == S3_OK);
    S3_ASSERT(pos == end);

    s3_test_check_attrs(a, &out);
}

static int
s3_test_codec_literals(void)
{
    /* the init(3): the length 5, the type 1, the version 3 */

    static const u_char init3[] = {0x00, 0x00, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x03};

    /* the version(3): the same shape with the type 2 */

    static const u_char version3[] = {0x00, 0x00, 0x00, 0x05, 0x02, 0x00, 0x00, 0x00, 0x03};

    /* the status ok(5): the code 0 and the two empty strings */

    static const u_char status_ok5[] = {0x00, 0x00, 0x00, 0x11, 0x65, 0x00, 0x00,
                                        0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    /* the handle(7) of "abcd": the length 13, the 4-byte string */

    static const u_char handle7[] = {0x00, 0x00, 0x00, 0x0d, 0x66, 0x00, 0x00, 0x00, 0x07,
                                     0x00, 0x00, 0x00, 0x04, 'a',  'b',  'c',  'd'};

    /* the data(1) of "xy": the length 11 = 0x0b */

    static const u_char data1[] = {0x00, 0x00, 0x00, 0x0b, 0x67, 0x00, 0x00, 0x00,
                                   0x01, 0x00, 0x00, 0x00, 0x02, 0x78, 0x79};

    /* the realpath(9) of "/": the length 10, the 1-byte path */

    static const u_char realpath9[] = {0x00, 0x00, 0x00, 0x0a, 0x10, 0x00, 0x00,
                                       0x00, 0x09, 0x00, 0x00, 0x00, 0x01, 0x2f};

    u_char   buf[64];
    u_char  *p;
    s3_str_t handle = s3_string("abcd");
    s3_str_t data = s3_string("xy");
    s3_str_t path = s3_string("/");

    s3_memzero(buf, sizeof(buf));

    S3_ASSERT(s3_ssh3_sftp_encode_init(NULL, 3) == sizeof(init3));

    p = (u_char *)s3_ssh3_sftp_encode_init(buf, 3);

    S3_ASSERT(p == buf + sizeof(init3));
    S3_ASSERT(s3_memcmp(buf, init3, sizeof(init3)) == 0);

    s3_memzero(buf, sizeof(buf));

    S3_ASSERT(s3_ssh3_sftp_encode_version(NULL, 3) == sizeof(version3));

    p = (u_char *)s3_ssh3_sftp_encode_version(buf, 3);

    S3_ASSERT(p == buf + sizeof(version3));
    S3_ASSERT(s3_memcmp(buf, version3, sizeof(version3)) == 0);

    s3_memzero(buf, sizeof(buf));

    S3_ASSERT(s3_ssh3_sftp_encode_status_ok(NULL, 5) == sizeof(status_ok5));

    p = (u_char *)s3_ssh3_sftp_encode_status_ok(buf, 5);

    S3_ASSERT(p == buf + sizeof(status_ok5));
    S3_ASSERT(s3_memcmp(buf, status_ok5, sizeof(status_ok5)) == 0);

    s3_memzero(buf, sizeof(buf));

    S3_ASSERT(s3_ssh3_sftp_encode_handle(NULL, 7, &handle) == sizeof(handle7));

    p = (u_char *)s3_ssh3_sftp_encode_handle(buf, 7, &handle);

    S3_ASSERT(p == buf + sizeof(handle7));
    S3_ASSERT(s3_memcmp(buf, handle7, sizeof(handle7)) == 0);

    s3_memzero(buf, sizeof(buf));

    S3_ASSERT(s3_ssh3_sftp_encode_data(NULL, 1, &data) == sizeof(data1));

    p = (u_char *)s3_ssh3_sftp_encode_data(buf, 1, &data);

    S3_ASSERT(p == buf + sizeof(data1));
    S3_ASSERT(s3_memcmp(buf, data1, sizeof(data1)) == 0);

    s3_memzero(buf, sizeof(buf));

    S3_ASSERT(s3_ssh3_sftp_encode_realpath(NULL, 9, &path) == sizeof(realpath9));

    p = (u_char *)s3_ssh3_sftp_encode_realpath(buf, 9, &path);

    S3_ASSERT(p == buf + sizeof(realpath9));
    S3_ASSERT(s3_memcmp(buf, realpath9, sizeof(realpath9)) == 0);

    return s3_test_failures;
}

static int
s3_test_codec_frame(void)
{
    u_char             buf[64];
    u_char            *p;
    const u_char      *pos, *end;
    uint32_t           v;
    s3_str_t           handle = s3_string("abcd");
    s3_ssh3_sftp_pkt_t pkt;

    s3_memzero(buf, sizeof(buf));

    /* the two frames glued in one buffer decode back to back */

    p = (u_char *)s3_ssh3_sftp_encode_status_ok(buf, 1);
    p = (u_char *)s3_ssh3_sftp_encode_handle(p, 2, &handle);

    pos = buf;
    end = p;

    S3_ASSERT(s3_ssh3_sftp_codec_frame(&pos, end, &pkt) == S3_OK);
    S3_ASSERT(pkt.type == S3_SSH3_SFTP_STATUS);
    S3_ASSERT(pkt.has_id == 1);
    S3_ASSERT(pkt.request_id == 1);
    S3_ASSERT(pos == buf + 21);

    S3_ASSERT(s3_ssh3_sftp_codec_frame(&pos, end, &pkt) == S3_OK);
    S3_ASSERT(pkt.type == S3_SSH3_SFTP_HANDLE);
    S3_ASSERT(pkt.request_id == 2);
    S3_ASSERT(pos == end);

    /* the buffer ends inside the length prefix: again, no move */

    pos = buf;
    end = buf + 3;

    S3_ASSERT(s3_ssh3_sftp_codec_frame(&pos, end, &pkt) == S3_AGAIN);
    S3_ASSERT(pos == buf);

    /* the length prefix is whole but the frame is short: again */

    p = (u_char *)s3_ssh3_sftp_encode_status_ok(buf, 1);

    pos = buf;
    end = buf + 20;

    S3_ASSERT(s3_ssh3_sftp_codec_frame(&pos, end, &pkt) == S3_AGAIN);
    S3_ASSERT(pos == buf);

    /* the complete frame plus the stray two bytes: one frame, the
     * next attempt wants the continuation */

    p = (u_char *)s3_ssh3_sftp_encode_status_ok(buf, 1);
    p[0] = 0xde;
    p[1] = 0xad;

    pos = buf;
    end = p + 2;

    S3_ASSERT(s3_ssh3_sftp_codec_frame(&pos, end, &pkt) == S3_OK);
    S3_ASSERT(pos == p);

    S3_ASSERT(s3_ssh3_sftp_codec_frame(&pos, end, &pkt) == S3_AGAIN);
    S3_ASSERT(pos == p);

    /* the length above the cap is the error even before the data */

    buf[0] = 0x00;
    buf[1] = 0x04;
    buf[2] = 0x00;
    buf[3] = 0x01; /* 0x00040001 = S3_SSH3_SFTP_MAX_FRAME + 1 */

    pos = buf;
    end = buf + 4;

    S3_ASSERT(s3_ssh3_sftp_codec_frame(&pos, end, &pkt) == S3_ERROR);
    S3_ASSERT(pos == buf);

    /* the cap itself is a legal length, the frame is just short */

    buf[0] = 0x00;
    buf[1] = 0x04;
    buf[2] = 0x00;
    buf[3] = 0x00; /* exactly S3_SSH3_SFTP_MAX_FRAME */

    pos = buf;
    end = buf + 4;

    S3_ASSERT(s3_ssh3_sftp_codec_frame(&pos, end, &pkt) == S3_AGAIN);
    S3_ASSERT(pos == buf);

    /* the zero length carries no type byte: the error */

    s3_memzero(buf, sizeof(buf));

    pos = buf;
    end = buf + 8;

    S3_ASSERT(s3_ssh3_sftp_codec_frame(&pos, end, &pkt) == S3_ERROR);
    S3_ASSERT(pos == buf);

    /* the id-carrying type shorter than the id is corrupt: the error */

    s3_memcpy(buf,
              "\x00\x00\x00\x03"
              "\x03"
              "\x01\x02",
              7); /* open, length 3 */

    pos = buf;
    end = buf + 7;

    S3_ASSERT(s3_ssh3_sftp_codec_frame(&pos, end, &pkt) == S3_ERROR);
    S3_ASSERT(pos == buf);

    /* the init has no id, the body is the version alone */

    p = (u_char *)s3_ssh3_sftp_encode_init(buf, 3);

    pos = buf;
    end = p;

    S3_ASSERT(s3_ssh3_sftp_codec_frame(&pos, end, &pkt) == S3_OK);
    S3_ASSERT(pkt.type == S3_SSH3_SFTP_INIT);
    S3_ASSERT(pkt.has_id == 0);
    S3_ASSERT(pkt.request_id == 0);
    S3_ASSERT(pkt.body.len == 4);
    S3_ASSERT(pos == end);

    pos = pkt.body.data;
    end = pkt.body.data + pkt.body.len;

    S3_ASSERT(s3_ssh3_sftp_parse_u32(&pos, end, &v) == S3_OK);
    S3_ASSERT(v == 3);
    S3_ASSERT(pos == end);

    return s3_test_failures;
}

static int
s3_test_codec_scalars(void)
{
    u_char        buf[16];
    uint32_t      v32;
    uint64_t      v64;
    s3_str_t      s;
    const u_char *pos, *end;

    s3_memzero(buf, sizeof(buf));

    /* the u32 reader is strict at three bytes */

    s3_memcpy(buf, "\x01\x02\x03\x04\x05", 5);

    pos = buf;
    end = buf + 3;

    S3_ASSERT(s3_ssh3_sftp_parse_u32(&pos, end, &v32) == S3_ERROR);
    S3_ASSERT(pos == buf);

    pos = buf;
    end = buf + 4;

    S3_ASSERT(s3_ssh3_sftp_parse_u32(&pos, end, &v32) == S3_OK);
    S3_ASSERT(v32 == 0x01020304u);
    S3_ASSERT(pos == buf + 4);

    /* the u64 reader wants all eight bytes */

    s3_memcpy(buf, "\x01\x02\x03\x04\x05\x06\x07\x08\x09", 9);

    pos = buf;
    end = buf + 7;

    S3_ASSERT(s3_ssh3_sftp_parse_u64(&pos, end, &v64) == S3_ERROR);
    S3_ASSERT(pos == buf);

    pos = buf;
    end = buf + 8;

    S3_ASSERT(s3_ssh3_sftp_parse_u64(&pos, end, &v64) == S3_OK);
    S3_ASSERT(v64 == 0x0102030405060708ull);
    S3_ASSERT(pos == buf + 8);

    /* the string reader: the data short against the declared length */

    s3_memcpy(buf,
              "\x00\x00\x00\x03"
              "abc",
              7);

    pos = buf;
    end = buf + 6;

    S3_ASSERT(s3_ssh3_sftp_parse_string(&pos, end, &s) == S3_ERROR);
    S3_ASSERT(pos == buf);

    pos = buf;
    end = buf + 7;

    S3_ASSERT(s3_ssh3_sftp_parse_string(&pos, end, &s) == S3_OK);
    S3_ASSERT(s.len == 3);
    S3_ASSERT(s3_memcmp(s.data, "abc", 3) == 0);
    S3_ASSERT(pos == buf + 7);

    /* the empty string is legal and advances by its head only */

    s3_memcpy(buf,
              "\x00\x00\x00\x00"
              "z",
              5);

    pos = buf;
    end = buf + 4;

    S3_ASSERT(s3_ssh3_sftp_parse_string(&pos, end, &s) == S3_OK);
    S3_ASSERT(s.len == 0);
    S3_ASSERT(pos == buf + 4);

    return s3_test_failures;
}

static int
s3_test_codec_attrs(void)
{
    /* count 2, "foo" -> "bar", "baz" -> "", 29 bytes of raw pairs */

    static const u_char ext[] = {0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 'f',  'o',
                                 'o',  0x00, 0x00, 0x00, 0x03, 'b',  'a',  'r',  0x00, 0x00,
                                 0x00, 0x03, 'b',  'a',  'z',  0x00, 0x00, 0x00, 0x00};

    u_char               buf[128];
    u_char              *p, *block;
    const u_char        *pos, *end;
    size_t               blen, i;
    s3_ssh3_sftp_attrs_t a, out;

    s3_memzero(buf, sizeof(buf));

    /* the empty attrs, the size only, the full four, the extended */

    s3_memzero(&a, sizeof(a));

    s3_test_attr_combo(&a, 9 + 4);

    a.flags = S3_SSH3_SFTP_ATTR_SIZE;
    a.size = 0x0123456789abcdefull;

    s3_test_attr_combo(&a, 9 + 4 + 8);

    a.flags = S3_SSH3_SFTP_ATTR_SIZE | S3_SSH3_SFTP_ATTR_UIDGID | S3_SSH3_SFTP_ATTR_PERMISSION |
              S3_SSH3_SFTP_ATTR_ACMODTIME;
    a.size = 4096;
    a.uid = 1000;
    a.gid = 100;
    a.perms = 0100644;
    a.atime = 1000000000;
    a.mtime = 1700000000;

    s3_test_attr_combo(&a, 9 + 4 + 8 + 8 + 4 + 8);

    a.flags |= S3_SSH3_SFTP_ATTR_EXTENDED;
    a.extended.data = (u_char *)ext;
    a.extended.len = sizeof(ext);

    s3_test_attr_combo(&a, 9 + 4 + 8 + 8 + 4 + 8 + sizeof(ext));

    /* the unknown low bits ride along like the reference does, the
     * absent fields parse back as zeros */

    s3_memzero(&a, sizeof(a));

    a.flags = S3_SSH3_SFTP_ATTR_SIZE | 0x00008000;
    a.size = 7;

    s3_test_attr_combo(&a, 9 + 4 + 8);

    /* every proper prefix of the extended block is an error and the
     * cursor never moves */

    s3_memzero(&a, sizeof(a));

    a.flags = S3_SSH3_SFTP_ATTR_SIZE | S3_SSH3_SFTP_ATTR_PERMISSION | S3_SSH3_SFTP_ATTR_EXTENDED;
    a.size = 512;
    a.perms = 0755;
    a.extended.data = (u_char *)ext;
    a.extended.len = sizeof(ext);

    p = (u_char *)s3_ssh3_sftp_encode_attrs(buf, 1, &a);

    block = buf + 9; /* past the length, the type and the id */
    blen = p - block;

    S3_ASSERT(blen == 4 + 8 + 4 + sizeof(ext));

    for (i = 0; i < blen; i++) {
        pos = block;
        end = block + i;

        S3_ASSERT(s3_ssh3_sftp_parse_attrs(&pos, end, &out) == S3_ERROR);
        S3_ASSERT(pos == block);
    }

    /* the raw view starts at the count field of the pairs */

    pos = block;
    end = block + blen;

    S3_ASSERT(s3_ssh3_sftp_parse_attrs(&pos, end, &out) == S3_OK);
    S3_ASSERT(pos == end);
    S3_ASSERT(out.extended.len == sizeof(ext));
    S3_ASSERT(out.extended.data == block + blen - sizeof(ext));
    S3_ASSERT(s3_memcmp(out.extended.data, ext, sizeof(ext)) == 0);

    return s3_test_failures;
}

static int
s3_test_codec_requests(void)
{
    s3_str_t root = s3_string("/");
    s3_str_t passwd = s3_string("/etc/passwd");
    s3_str_t tmp = s3_string("/tmp");
    s3_str_t handle = s3_string("handle-0042");
    s3_str_t path = s3_string("/tmp/upload.bin");
    s3_str_t data = s3_string("hello, sftp world!");
    s3_str_t old = s3_string("/tmp/old name");
    s3_str_t new = s3_string("/tmp/new name");
    u_char               buf[256];
    u_char              *p;
    const u_char        *pos, *end;
    uint32_t             pflags, out_flags, out_len;
    uint64_t             offset, out_offset;
    s3_ssh3_sftp_pkt_t   pkt;
    s3_ssh3_sftp_attrs_t a, out_attrs;

    /* the path requests and the handle requests ride the shared shape */

    s3_test_roundtrip_string(s3_ssh3_sftp_encode_realpath, s3_ssh3_sftp_parse_path_body,
                             S3_SSH3_SFTP_REALPATH, 1, &root);

    s3_test_roundtrip_string(s3_ssh3_sftp_encode_stat, s3_ssh3_sftp_parse_path_body,
                             S3_SSH3_SFTP_STAT, 2, &passwd);

    s3_test_roundtrip_string(s3_ssh3_sftp_encode_opendir, s3_ssh3_sftp_parse_path_body,
                             S3_SSH3_SFTP_OPENDIR, 3, &tmp);

    s3_test_roundtrip_string(s3_ssh3_sftp_encode_rmdir, s3_ssh3_sftp_parse_path_body,
                             S3_SSH3_SFTP_RMDIR, 4, &tmp);

    s3_test_roundtrip_string(s3_ssh3_sftp_encode_remove, s3_ssh3_sftp_parse_path_body,
                             S3_SSH3_SFTP_REMOVE, 5, &passwd);

    s3_test_roundtrip_string(s3_ssh3_sftp_encode_close, s3_ssh3_sftp_parse_handle_body,
                             S3_SSH3_SFTP_CLOSE, 6, &handle);

    s3_test_roundtrip_string(s3_ssh3_sftp_encode_readdir, s3_ssh3_sftp_parse_handle_body,
                             S3_SSH3_SFTP_READDIR, 7, &handle);

    s3_memzero(buf, sizeof(buf));

    s3_memzero(&a, sizeof(a));
    a.flags = S3_SSH3_SFTP_ATTR_SIZE | S3_SSH3_SFTP_ATTR_PERMISSION;
    a.size = 4096;
    a.perms = 0100644;

    /* the open: the path, the pflags and the attrs in one body */

    pflags = S3_SSH3_SFTP_FXF_READ | S3_SSH3_SFTP_FXF_WRITE | S3_SSH3_SFTP_FXF_CREAT |
             S3_SSH3_SFTP_FXF_TRUNC;

    S3_ASSERT(s3_ssh3_sftp_encode_open(NULL, 0xcafe, &path, pflags, &a) ==
              9 + 4 + path.len + 4 + 4 + 8 + 4);

    p = (u_char *)s3_ssh3_sftp_encode_open(buf, 0xcafe, &path, pflags, &a);

    S3_ASSERT(p == buf + s3_ssh3_sftp_encode_open(NULL, 0xcafe, &path, pflags, &a));

    pos = buf;
    end = p;

    S3_ASSERT(s3_ssh3_sftp_codec_frame(&pos, end, &pkt) == S3_OK);
    S3_ASSERT(pkt.type == S3_SSH3_SFTP_OPEN);
    S3_ASSERT(pkt.request_id == 0xcafe);
    S3_ASSERT(pos == end);

    S3_ASSERT(s3_ssh3_sftp_parse_open_body(&pkt.body, &path, &out_flags, &out_attrs) == S3_OK);
    S3_ASSERT(path.len == sizeof("/tmp/upload.bin") - 1);
    S3_ASSERT(out_flags == pflags);

    s3_test_check_attrs(&a, &out_attrs);

    /* the read: the handle, the offset and the length */

    s3_memzero(buf, sizeof(buf));

    offset = 0x0123456789abcdefull;

    S3_ASSERT(s3_ssh3_sftp_encode_read(NULL, 0x00ff, &handle, offset, 32768) ==
              9 + 4 + handle.len + 8 + 4);

    p = (u_char *)s3_ssh3_sftp_encode_read(buf, 0x00ff, &handle, offset, 32768);

    S3_ASSERT(p == buf + 9 + 4 + handle.len + 8 + 4);

    pos = buf;
    end = p;

    S3_ASSERT(s3_ssh3_sftp_codec_frame(&pos, end, &pkt) == S3_OK);
    S3_ASSERT(pkt.type == S3_SSH3_SFTP_READ);
    S3_ASSERT(pkt.request_id == 0x00ff);

    S3_ASSERT(s3_ssh3_sftp_parse_read_body(&pkt.body, &handle, &out_offset, &out_len) == S3_OK);
    S3_ASSERT(handle.len == sizeof("handle-0042") - 1);
    S3_ASSERT(out_offset == offset);
    S3_ASSERT(out_len == 32768);

    /* the write: the handle, the offset and the data string */

    s3_memzero(buf, sizeof(buf));

    handle.data = (u_char *)"handle-0042";
    handle.len = sizeof("handle-0042") - 1;

    S3_ASSERT(s3_ssh3_sftp_encode_write(NULL, 0x0bad, &handle, 1, &data) ==
              9 + 4 + handle.len + 8 + 4 + data.len);

    p = (u_char *)s3_ssh3_sftp_encode_write(buf, 0x0bad, &handle, 1, &data);

    S3_ASSERT(p == buf + 9 + 4 + handle.len + 8 + 4 + data.len);

    pos = buf;
    end = p;

    S3_ASSERT(s3_ssh3_sftp_codec_frame(&pos, end, &pkt) == S3_OK);
    S3_ASSERT(pkt.type == S3_SSH3_SFTP_WRITE);
    S3_ASSERT(pkt.request_id == 0x0bad);

    S3_ASSERT(s3_ssh3_sftp_parse_write_body(&pkt.body, &handle, &out_offset, &data) == S3_OK);
    S3_ASSERT(out_offset == 1);
    S3_ASSERT(data.len == sizeof("hello, sftp world!") - 1);

    /* the mkdir carries the attrs; the setstat parser shares the
     * path plus attrs shape of the body */

    s3_memzero(buf, sizeof(buf));

    p = (u_char *)s3_ssh3_sftp_encode_mkdir(buf, 0x1111, &tmp, &a);

    S3_ASSERT(p == buf + s3_ssh3_sftp_encode_mkdir(NULL, 0x1111, &tmp, &a));

    pos = buf;
    end = p;

    S3_ASSERT(s3_ssh3_sftp_codec_frame(&pos, end, &pkt) == S3_OK);
    S3_ASSERT(pkt.type == S3_SSH3_SFTP_MKDIR);
    S3_ASSERT(pkt.request_id == 0x1111);

    S3_ASSERT(s3_ssh3_sftp_parse_setstat_body(&pkt.body, &tmp, &out_attrs) == S3_OK);
    S3_ASSERT(tmp.len == 4);

    s3_test_check_attrs(&a, &out_attrs);

    /* the rename: the old path and the new path */

    s3_memzero(buf, sizeof(buf));

    S3_ASSERT(s3_ssh3_sftp_encode_rename(NULL, 0x777, &old, &new) == 9 + 4 + old.len + 4 + new.len);

    p = (u_char *)s3_ssh3_sftp_encode_rename(buf, 0x777, &old, &new);

    S3_ASSERT(p == buf + 9 + 4 + old.len + 4 + new.len);

    pos = buf;
    end = p;

    S3_ASSERT(s3_ssh3_sftp_codec_frame(&pos, end, &pkt) == S3_OK);
    S3_ASSERT(pkt.type == S3_SSH3_SFTP_RENAME);
    S3_ASSERT(pkt.request_id == 0x777);

    S3_ASSERT(s3_ssh3_sftp_parse_rename_body(&pkt.body, &old, &new) == S3_OK);
    S3_ASSERT(old.len == sizeof("/tmp/old name") - 1);
    S3_ASSERT(new.len == sizeof("/tmp/new name") - 1);

    return s3_test_failures;
}

static int
s3_test_codec_replies(void)
{
    u_char               buf[256], buf2[64];
    u_char              *p, *q;
    const u_char        *pos, *end;
    uint32_t             code, count;
    s3_str_t             msg = s3_string("no such file");
    s3_str_t             data = s3_string("\x01\x02\x03\x04\xff");
    s3_str_t             handle = s3_string("handle-0042");
    s3_str_t             out_msg, lang, out_data;
    s3_str_t             fn0 = s3_string("a.txt");
    s3_str_t             ln0 = s3_string("-rw-r--r-- 1 u a.txt");
    s3_str_t             fn1 = s3_string("b");
    s3_str_t             ln1 = s3_string("b");
    s3_str_t             out_fn, out_ln;
    s3_ssh3_sftp_pkt_t   pkt;
    s3_ssh3_sftp_name_t  names[2];
    s3_ssh3_sftp_attrs_t out_attrs;

    s3_memzero(buf, sizeof(buf));
    s3_memzero(buf2, sizeof(buf2));
    s3_memzero(names, sizeof(names));

    /* the status with the message: the code, the msg, the empty lang */

    S3_ASSERT(s3_ssh3_sftp_encode_status(NULL, 9, S3_SSH3_SFTP_FX_NO_SUCH_FILE, &msg) ==
              21 + msg.len);

    p = (u_char *)s3_ssh3_sftp_encode_status(buf, 9, S3_SSH3_SFTP_FX_NO_SUCH_FILE, &msg);

    S3_ASSERT(p == buf + 21 + msg.len);

    pos = buf;
    end = p;

    S3_ASSERT(s3_ssh3_sftp_codec_frame(&pos, end, &pkt) == S3_OK);
    S3_ASSERT(pkt.type == S3_SSH3_SFTP_STATUS);
    S3_ASSERT(pkt.request_id == 9);
    S3_ASSERT(pos == end);

    pos = pkt.body.data;
    end = pkt.body.data + pkt.body.len;

    S3_ASSERT(s3_ssh3_sftp_parse_u32(&pos, end, &code) == S3_OK);
    S3_ASSERT(code == S3_SSH3_SFTP_FX_NO_SUCH_FILE);

    S3_ASSERT(s3_ssh3_sftp_parse_string(&pos, end, &out_msg) == S3_OK);
    S3_ASSERT(out_msg.len == msg.len);
    S3_ASSERT(s3_memcmp(out_msg.data, msg.data, msg.len) == 0);

    S3_ASSERT(s3_ssh3_sftp_parse_string(&pos, end, &lang) == S3_OK);
    S3_ASSERT(lang.len == 0);
    S3_ASSERT(pos == end);

    /* the NULL message is the byte-for-byte status_ok shape */

    q = (u_char *)s3_ssh3_sftp_encode_status(buf2, 9, S3_SSH3_SFTP_FX_OK, NULL);

    S3_ASSERT(q == buf2 + 21);

    p = (u_char *)s3_ssh3_sftp_encode_status_ok(buf2 + 32, 9);

    S3_ASSERT(p == buf2 + 32 + 21);
    S3_ASSERT(s3_memcmp(buf2, buf2 + 32, 21) == 0);

    /* the handle reply rides the shared one-string shape */

    s3_test_roundtrip_string(s3_ssh3_sftp_encode_handle, s3_ssh3_sftp_parse_handle_body,
                             S3_SSH3_SFTP_HANDLE, 0xa1, &handle);

    /* the data reply: the string body parsed by hand */

    s3_memzero(buf, sizeof(buf));

    S3_ASSERT(s3_ssh3_sftp_encode_data(NULL, 0x5a5a, &data) == 9 + 4 + data.len);

    p = (u_char *)s3_ssh3_sftp_encode_data(buf, 0x5a5a, &data);

    S3_ASSERT(p == buf + 9 + 4 + data.len);

    pos = buf;
    end = p;

    S3_ASSERT(s3_ssh3_sftp_codec_frame(&pos, end, &pkt) == S3_OK);
    S3_ASSERT(pkt.type == S3_SSH3_SFTP_DATA);
    S3_ASSERT(pkt.request_id == 0x5a5a);

    pos = pkt.body.data;
    end = pkt.body.data + pkt.body.len;

    S3_ASSERT(s3_ssh3_sftp_parse_string(&pos, end, &out_data) == S3_OK);
    S3_ASSERT(out_data.len == data.len);
    S3_ASSERT(s3_memcmp(out_data.data, data.data, data.len) == 0);
    S3_ASSERT(pos == end);

    /* the name: the count then the filename, the longname and the
     * attrs per entry; the first entry keeps the size and the
     * permissions, the second one the empty attrs */

    names[0].filename = fn0;
    names[0].longname = ln0;
    names[0].attrs.flags = S3_SSH3_SFTP_ATTR_SIZE | S3_SSH3_SFTP_ATTR_PERMISSION;
    names[0].attrs.size = 100;
    names[0].attrs.perms = 0100644;

    names[1].filename = fn1;
    names[1].longname = ln1;

    s3_memzero(buf, sizeof(buf));

    S3_ASSERT(s3_ssh3_sftp_encode_name(NULL, 0x77, names, 2) ==
              9 + 4 + 4 + fn0.len + 4 + ln0.len + 4 + 8 + 4 + 4 + fn1.len + 4 + ln1.len + 4);

    p = (u_char *)s3_ssh3_sftp_encode_name(buf, 0x77, names, 2);

    S3_ASSERT(p == buf + s3_ssh3_sftp_encode_name(NULL, 0x77, names, 2));

    pos = buf;
    end = p;

    S3_ASSERT(s3_ssh3_sftp_codec_frame(&pos, end, &pkt) == S3_OK);
    S3_ASSERT(pkt.type == S3_SSH3_SFTP_NAME);
    S3_ASSERT(pkt.request_id == 0x77);

    pos = pkt.body.data;
    end = pkt.body.data + pkt.body.len;

    S3_ASSERT(s3_ssh3_sftp_parse_u32(&pos, end, &count) == S3_OK);
    S3_ASSERT(count == 2);

    S3_ASSERT(s3_ssh3_sftp_parse_string(&pos, end, &out_fn) == S3_OK);
    S3_ASSERT(out_fn.len == fn0.len);
    S3_ASSERT(s3_memcmp(out_fn.data, fn0.data, fn0.len) == 0);

    S3_ASSERT(s3_ssh3_sftp_parse_string(&pos, end, &out_ln) == S3_OK);
    S3_ASSERT(out_ln.len == ln0.len);
    S3_ASSERT(s3_memcmp(out_ln.data, ln0.data, ln0.len) == 0);

    S3_ASSERT(s3_ssh3_sftp_parse_attrs(&pos, end, &out_attrs) == S3_OK);
    S3_ASSERT(out_attrs.flags == names[0].attrs.flags);
    S3_ASSERT(out_attrs.size == 100);
    S3_ASSERT(out_attrs.perms == 0100644);
    S3_ASSERT(out_attrs.extended.len == 0);

    S3_ASSERT(s3_ssh3_sftp_parse_string(&pos, end, &out_fn) == S3_OK);
    S3_ASSERT(out_fn.len == fn1.len);
    S3_ASSERT(out_fn.data[0] == 'b');

    S3_ASSERT(s3_ssh3_sftp_parse_string(&pos, end, &out_ln) == S3_OK);
    S3_ASSERT(out_ln.len == ln1.len);

    S3_ASSERT(s3_ssh3_sftp_parse_attrs(&pos, end, &out_attrs) == S3_OK);
    S3_ASSERT(out_attrs.flags == 0);
    S3_ASSERT(out_attrs.extended.len == 0);

    S3_ASSERT(pos == end);

    return s3_test_failures;
}

static int
s3_test_codec_strict(void)
{
    /*
     * the setstat body built by hand: the path then the attrs with
     * the full four flags (the codec keeps no client setstat
     * encoder, the server side parses the request only)
     */

    static const u_char setstat_body[] = {
        0x00, 0x00, 0x00, 0x06, '/',  't',  'm',  'p',  '/',  'f',  0x00, 0x00, 0x00, 0x0f,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0xe8, 0x00, 0x00,
        0x00, 0x64, 0x00, 0x00, 0x81, 0xa4, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

    u_char        buf[256];
    u_char       *p;
    const u_char *pos, *end;
    size_t        i;
    uint32_t      pflags, out_flags, out_len;
    uint64_t      out_offset;
    s3_str_t      path = s3_string("/tmp/upload.bin");
    s3_str_t      handle = s3_string("handle-0042");
    s3_str_t      old = s3_string("/tmp/old name");
    s3_str_t new = s3_string("/tmp/new name");
    s3_str_t             body, bad, out1, out2;
    s3_ssh3_sftp_pkt_t   pkt;
    s3_ssh3_sftp_attrs_t a, out_attrs;

    s3_memzero(buf, sizeof(buf));

    s3_memzero(&a, sizeof(a));
    a.flags = S3_SSH3_SFTP_ATTR_SIZE | S3_SSH3_SFTP_ATTR_ACMODTIME;
    a.size = 123456789;
    a.atime = 1000000000;
    a.mtime = 1700000000;

    /* the path body: every prefix and the trailing byte fail */

    p = (u_char *)s3_ssh3_sftp_encode_stat(buf, 1, &path);

    pos = buf;
    end = p;

    S3_ASSERT(s3_ssh3_sftp_codec_frame(&pos, end, &pkt) == S3_OK);

    s3_test_body_prefixes(s3_ssh3_sftp_parse_path_body, &pkt.body);

    /* the handle body: the same walk */

    s3_memzero(buf, sizeof(buf));

    p = (u_char *)s3_ssh3_sftp_encode_close(buf, 2, &handle);

    pos = buf;
    end = p;

    S3_ASSERT(s3_ssh3_sftp_codec_frame(&pos, end, &pkt) == S3_OK);

    s3_test_body_prefixes(s3_ssh3_sftp_parse_handle_body, &pkt.body);

    /* the open body: the attrs truncated anywhere is an error */

    s3_memzero(buf, sizeof(buf));

    pflags = S3_SSH3_SFTP_FXF_WRITE | S3_SSH3_SFTP_FXF_CREAT;

    p = (u_char *)s3_ssh3_sftp_encode_open(buf, 3, &path, pflags, &a);

    pos = buf;
    end = p;

    S3_ASSERT(s3_ssh3_sftp_codec_frame(&pos, end, &pkt) == S3_OK);

    for (i = 0; i < pkt.body.len; i++) {
        bad = pkt.body;
        bad.len = i;

        S3_ASSERT(s3_ssh3_sftp_parse_open_body(&bad, &out1, &out_flags, &out_attrs) == S3_ERROR);
    }

    bad = pkt.body;
    bad.len += 1;

    S3_ASSERT(s3_ssh3_sftp_parse_open_body(&bad, &out1, &out_flags, &out_attrs) == S3_ERROR);

    /* the read body: the same walk */

    s3_memzero(buf, sizeof(buf));

    p = (u_char *)s3_ssh3_sftp_encode_read(buf, 4, &handle, 0x0102030405060708ull, 4096);

    pos = buf;
    end = p;

    S3_ASSERT(s3_ssh3_sftp_codec_frame(&pos, end, &pkt) == S3_OK);

    for (i = 0; i < pkt.body.len; i++) {
        bad = pkt.body;
        bad.len = i;

        S3_ASSERT(s3_ssh3_sftp_parse_read_body(&bad, &out1, &out_offset, &out_len) == S3_ERROR);
    }

    bad = pkt.body;
    bad.len += 1;

    S3_ASSERT(s3_ssh3_sftp_parse_read_body(&bad, &out1, &out_offset, &out_len) == S3_ERROR);

    /* the write body: the same walk */

    s3_memzero(buf, sizeof(buf));

    p = (u_char *)s3_ssh3_sftp_encode_write(buf, 5, &handle, 1, &handle);

    pos = buf;
    end = p;

    S3_ASSERT(s3_ssh3_sftp_codec_frame(&pos, end, &pkt) == S3_OK);

    for (i = 0; i < pkt.body.len; i++) {
        bad = pkt.body;
        bad.len = i;

        S3_ASSERT(s3_ssh3_sftp_parse_write_body(&bad, &out1, &out_offset, &out2) == S3_ERROR);
    }

    bad = pkt.body;
    bad.len += 1;

    S3_ASSERT(s3_ssh3_sftp_parse_write_body(&bad, &out1, &out_offset, &out2) == S3_ERROR);

    /* the rename body: the same walk */

    s3_memzero(buf, sizeof(buf));

    p = (u_char *)s3_ssh3_sftp_encode_rename(buf, 6, &old, &new);

    pos = buf;
    end = p;

    S3_ASSERT(s3_ssh3_sftp_codec_frame(&pos, end, &pkt) == S3_OK);

    for (i = 0; i < pkt.body.len; i++) {
        bad = pkt.body;
        bad.len = i;

        S3_ASSERT(s3_ssh3_sftp_parse_rename_body(&bad, &out1, &out2) == S3_ERROR);
    }

    bad = pkt.body;
    bad.len += 1;

    S3_ASSERT(s3_ssh3_sftp_parse_rename_body(&bad, &out1, &out2) == S3_ERROR);

    /* the setstat literal vector parses, then walks the prefixes;
     * the sentinel byte past the body is inside the zeroed buf */

    s3_memcpy(buf, setstat_body, sizeof(setstat_body));

    body.data = buf;
    body.len = sizeof(setstat_body);

    S3_ASSERT(s3_ssh3_sftp_parse_setstat_body(&body, &out1, &out_attrs) == S3_OK);
    S3_ASSERT(out1.len == 6);
    S3_ASSERT(s3_memcmp(out1.data, "/tmp/f", 6) == 0);
    S3_ASSERT(out_attrs.flags == (S3_SSH3_SFTP_ATTR_SIZE | S3_SSH3_SFTP_ATTR_UIDGID |
                                  S3_SSH3_SFTP_ATTR_PERMISSION | S3_SSH3_SFTP_ATTR_ACMODTIME));
    S3_ASSERT(out_attrs.size == 256);
    S3_ASSERT(out_attrs.uid == 1000);
    S3_ASSERT(out_attrs.gid == 100);
    S3_ASSERT(out_attrs.perms == 0100644);
    S3_ASSERT(out_attrs.atime == 0x01020304);
    S3_ASSERT(out_attrs.mtime == 0x05060708);
    S3_ASSERT(out_attrs.extended.len == 0);

    for (i = 0; i < sizeof(setstat_body); i++) {
        bad.data = buf;
        bad.len = i;

        S3_ASSERT(s3_ssh3_sftp_parse_setstat_body(&bad, &out1, &out_attrs) == S3_ERROR);
    }

    bad.data = buf;
    bad.len = sizeof(setstat_body) + 1;

    S3_ASSERT(s3_ssh3_sftp_parse_setstat_body(&bad, &out1, &out_attrs) == S3_ERROR);

    return s3_test_failures;
}

static int
s3_test_ssh3_sftp_codec(void)
{
    (void)s3_test_codec_literals();
    (void)s3_test_codec_frame();
    (void)s3_test_codec_scalars();
    (void)s3_test_codec_attrs();
    (void)s3_test_codec_requests();
    (void)s3_test_codec_replies();
    (void)s3_test_codec_strict();

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_ssh3_sftp_codec)
