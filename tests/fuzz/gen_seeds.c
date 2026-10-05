/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the fuzz seed corpus generator: writes the hand-built valid frames
 * of the five parser targets, the same shapes the unit tests build
 * through the codec encoders; one directory per target under argv[1]
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <s3_core.h>

#include <s3_ssh3_cm.h>
#include <s3_ssh3_forward.h>
#include <s3_ssh3_message.h>
#include <s3_ssh3_sftp_codec.h>
#include <s3_ssh3_wire.h>

#define GS_BUF_SIZE 4096

static u_char   gs_buf[GS_BUF_SIZE];
static u_char   gs_body[GS_BUF_SIZE];
static unsigned gs_failures;

static void
gs_dir(const char *path)
{
    if (mkdir(path, 0755) != 0 && errno != EEXIST) {
        printf("gen_seeds: mkdir %s failed\n", path);
        gs_failures++;
    }
}

static void
gs_write(const char *dir, const char *name, size_t len)
{
    char  path[512];
    FILE *f;

    snprintf(path, sizeof(path), "%s/%s.bin", dir, name);

    f = fopen(path, "wb");

    if (f == NULL) {
        printf("gen_seeds: fopen %s failed\n", path);
        gs_failures++;

        return;
    }

    if (fwrite(gs_buf, 1, len, f) != len) {
        printf("gen_seeds: fwrite %s failed\n", path);
        gs_failures++;
    }

    (void)fclose(f);
}

/* the raw helpers of the seeds the codec encoders do not cover; the
 * sftp wire is big-endian everywhere, the frame length covers the
 * type byte, the id and the body */

static u_char *
gs_put_u32(u_char *p, uint32_t v)
{
    p[0] = (u_char)(v >> 24);
    p[1] = (u_char)(v >> 16);
    p[2] = (u_char)(v >> 8);
    p[3] = (u_char)v;

    return p + 4;
}

static u_char *
gs_put_string(u_char *p, const char *s)
{
    size_t n;

    n = strlen(s);
    p = gs_put_u32(p, (uint32_t)n);

    while (n != 0) {
        n--;
        *p++ = (u_char)s[0];
        s++;
    }

    return p;
}

static u_char *
gs_put_attrs(u_char *p, uint32_t flags, uint64_t size, uint32_t perms)
{
    p = gs_put_u32(p, flags);

    if (flags & S3_SSH3_SFTP_ATTR_SIZE) {
        p = gs_put_u32(p, (uint32_t)(size >> 32));
        p = gs_put_u32(p, (uint32_t)size);
    }

    if (flags & S3_SSH3_SFTP_ATTR_PERMISSION) {
        p = gs_put_u32(p, perms);
    }

    if (flags & S3_SSH3_SFTP_ATTR_ACMODTIME) {
        p = gs_put_u32(p, 1700000000);
        p = gs_put_u32(p, 1700000001);
    }

    return p;
}

static void
gs_sftp(const char *dir)
{
    u_char              *p, *body;
    s3_str_t             path, handle, data, msg, old_path, new_path;
    s3_str_t             name, longname;
    s3_ssh3_sftp_name_t  names[2];
    s3_ssh3_sftp_attrs_t attrs;

    path.data = (u_char *)"/tmp/a";
    path.len = 6;

    gs_write(dir, "init", (size_t)((u_char *)s3_ssh3_sftp_encode_init(gs_buf, 3) - gs_buf));
    gs_write(dir, "version", (size_t)((u_char *)s3_ssh3_sftp_encode_version(gs_buf, 3) - gs_buf));
    gs_write(dir, "realpath",
             (size_t)((u_char *)s3_ssh3_sftp_encode_realpath(gs_buf, 1, &path) - gs_buf));
    gs_write(dir, "stat", (size_t)((u_char *)s3_ssh3_sftp_encode_stat(gs_buf, 2, &path) - gs_buf));
    gs_write(dir, "opendir",
             (size_t)((u_char *)s3_ssh3_sftp_encode_opendir(gs_buf, 7, &path) - gs_buf));
    gs_write(dir, "rmdir",
             (size_t)((u_char *)s3_ssh3_sftp_encode_rmdir(gs_buf, 9, &path) - gs_buf));
    gs_write(dir, "remove",
             (size_t)((u_char *)s3_ssh3_sftp_encode_remove(gs_buf, 10, &path) - gs_buf));

    handle.data = (u_char *)"h-0001";
    handle.len = 6;

    gs_write(dir, "close",
             (size_t)((u_char *)s3_ssh3_sftp_encode_close(gs_buf, 4, &handle) - gs_buf));
    gs_write(
        dir, "read",
        (size_t)((u_char *)s3_ssh3_sftp_encode_read(gs_buf, 5, &handle, 8192, 32768) - gs_buf));
    gs_write(dir, "readdir",
             (size_t)((u_char *)s3_ssh3_sftp_encode_readdir(gs_buf, 8, &handle) - gs_buf));
    gs_write(dir, "handle",
             (size_t)((u_char *)s3_ssh3_sftp_encode_handle(gs_buf, 13, &handle) - gs_buf));

    data.data = (u_char *)"payload bytes";
    data.len = 13;

    gs_write(dir, "write",
             (size_t)((u_char *)s3_ssh3_sftp_encode_write(gs_buf, 6, &handle, 0, &data) - gs_buf));
    gs_write(dir, "data", (size_t)((u_char *)s3_ssh3_sftp_encode_data(gs_buf, 14, &data) - gs_buf));

    old_path = path;
    new_path.data = (u_char *)"b.txt";
    new_path.len = 5;

    gs_write(
        dir, "rename",
        (size_t)((u_char *)s3_ssh3_sftp_encode_rename(gs_buf, 11, &old_path, &new_path) - gs_buf));

    msg.data = (u_char *)"no such file";
    msg.len = 12;

    gs_write(dir, "status",
             (size_t)((u_char *)s3_ssh3_sftp_encode_status(gs_buf, 12, S3_SSH3_SFTP_FX_NO_SUCH_FILE,
                                                           &msg) -
                      gs_buf));

    s3_memzero(&attrs, sizeof(attrs));
    attrs.flags = S3_SSH3_SFTP_ATTR_SIZE | S3_SSH3_SFTP_ATTR_PERMISSION;
    attrs.size = 4096;
    attrs.perms = 0644;

    gs_write(
        dir, "open",
        (size_t)((u_char *)s3_ssh3_sftp_encode_open(
                     gs_buf, 3, &path, S3_SSH3_SFTP_FXF_READ | S3_SSH3_SFTP_FXF_CREAT, &attrs) -
                 gs_buf));
    gs_write(dir, "attrs",
             (size_t)((u_char *)s3_ssh3_sftp_encode_attrs(gs_buf, 16, &attrs) - gs_buf));

    s3_memzero(&attrs, sizeof(attrs));
    attrs.flags = S3_SSH3_SFTP_ATTR_ACMODTIME;

    gs_write(dir, "mkdir",
             (size_t)((u_char *)s3_ssh3_sftp_encode_mkdir(gs_buf, 15, &path, &attrs) - gs_buf));

    name.data = (u_char *)"a.txt";
    name.len = 5;
    longname.data = (u_char *)"-rw-r--r-- a.txt";
    longname.len = 16;

    s3_memzero(&names, sizeof(names));
    names[0].filename = name;
    names[0].longname = longname;
    names[0].attrs = attrs;
    names[1].filename = new_path;
    names[1].longname = longname;

    gs_write(dir, "name",
             (size_t)((u_char *)s3_ssh3_sftp_encode_name(gs_buf, 17, names, 2) - gs_buf));

    /* the setstat request, no dedicated encoder: the body is the
     * string plus the attribute block */

    body = gs_body;
    body = gs_put_string(body, "/tmp/a");
    body = gs_put_attrs(body, S3_SSH3_SFTP_ATTR_SIZE | S3_SSH3_SFTP_ATTR_ACMODTIME, 8192, 0);

    p = gs_buf;
    p = gs_put_u32(p, (uint32_t)(5 + (size_t)(body - gs_body)));
    *p++ = S3_SSH3_SFTP_SETSTAT;
    p = gs_put_u32(p, 18);

    s3_memcpy(p, gs_body, (size_t)(body - gs_body));
    p += body - gs_body;

    gs_write(dir, "setstat", (size_t)(p - gs_buf));

    /* the extended request: the name string and the argument string */

    body = gs_body;
    body = gs_put_string(body, "hardlink@openssh.com");
    body = gs_put_string(body, "b.txt");

    p = gs_buf;
    p = gs_put_u32(p, (uint32_t)(5 + (size_t)(body - gs_body)));
    *p++ = S3_SSH3_SFTP_EXTENDED;
    p = gs_put_u32(p, 19);

    s3_memcpy(p, gs_body, (size_t)(body - gs_body));
    p += body - gs_body;

    gs_write(dir, "extended", (size_t)(p - gs_buf));

    /* two frames in one chunk, the multi-frame walk */

    p = (u_char *)s3_ssh3_sftp_encode_realpath(gs_buf, 20, &path);
    p = (u_char *)s3_ssh3_sftp_encode_stat(p, 21, &path);

    gs_write(dir, "multi", (size_t)(p - gs_buf));
}

static void
gs_cm_frame(const char *dir, const char *name, uint8_t type, size_t body_len)
{
    u_char  *p;
    s3_str_t payload;

    payload.data = gs_body;
    payload.len = body_len;

    p = (u_char *)s3_ssh3_cm_encode_frame(gs_buf, type, body_len != 0 ? &payload : NULL);

    gs_write(dir, name, (size_t)(p - gs_buf));
}

static void
gs_cm(const char *dir)
{
    u_char                   *p;
    s3_ssh3_cm_open_session_t req;
    u_char                    token[S3_SSH3_CM_TOKEN_LEN];
    static const char *const  cmds[] = {"sleep 10", "tar cf - ."};
    static const char *const  envs[] = {"PATH=/bin"};
    uint32_t                  i;

    gs_cm_frame(dir, "hello", S3_SSH3_CM_MSG_HELLO, 0);
    gs_cm_frame(dir, "ok", S3_SSH3_CM_MSG_OK, 0);
    gs_cm_frame(dir, "exit", S3_SSH3_CM_MSG_EXIT, 0);

    s3_memcpy(gs_body, "malformed ATTACH", 16);
    gs_cm_frame(dir, "error", S3_SSH3_CM_MSG_ERROR, 16);

    /* the open session: two commands, one env, the agent flag on */

    s3_memzero(&req, sizeof(req));

    req.ncommand = 2;
    req.nenv = 1;
    req.forward_agent = 1;

    for (i = 0; i < req.ncommand; i++) {
        req.command[i].data = (u_char *)cmds[i];
        req.command[i].len = strlen(cmds[i]);
    }

    req.env[0].data = (u_char *)envs[0];
    req.env[0].len = strlen(envs[0]);

    p = (u_char *)s3_ssh3_cm_encode_open_session(gs_body, &req);

    gs_cm_frame(dir, "open_session", S3_SSH3_CM_MSG_OPEN_SESSION, (size_t)(p - gs_body));

    /* the attach frames: the stderr kind first, like the master
     * wants it, then the io kind */

    for (i = 0; i < S3_SSH3_CM_TOKEN_LEN; i++) {
        token[i] = (u_char)i;
    }

    p = (u_char *)s3_ssh3_cm_encode_attach(gs_body, token, S3_SSH3_CM_STREAM_STDERR);
    gs_cm_frame(dir, "attach_stderr", S3_SSH3_CM_MSG_ATTACH, (size_t)(p - gs_body));

    p = (u_char *)s3_ssh3_cm_encode_attach(gs_body, token, S3_SSH3_CM_STREAM_IO);
    gs_cm_frame(dir, "attach_io", S3_SSH3_CM_MSG_ATTACH, (size_t)(p - gs_body));

    /* the exit status */

    s3_memzero(gs_body, 8);
    gs_body[7] = 42;

    gs_cm_frame(dir, "exit_status", S3_SSH3_CM_MSG_EXIT_STATUS, 8);

    /* the control ops */

    s3_memcpy(gs_body, S3_SSH3_CM_OP_CHECK, 5);
    gs_cm_frame(dir, "control_op_check", S3_SSH3_CM_MSG_CONTROL_OP, 5);

    s3_memcpy(gs_body, S3_SSH3_CM_OP_STOP, 4);
    gs_cm_frame(dir, "control_op_stop", S3_SSH3_CM_MSG_CONTROL_OP, 4);

    /* two frames in one chunk: the handshake and the reply */

    p = (u_char *)s3_ssh3_cm_encode_frame(gs_buf, S3_SSH3_CM_MSG_HELLO, NULL);
    p = (u_char *)s3_ssh3_cm_encode_frame(p, S3_SSH3_CM_MSG_OK, NULL);

    gs_write(dir, "multi", (size_t)(p - gs_buf));
}

static void
gs_forward(const char *dir)
{
    u_char                  *p;
    s3_ssh3_forward_target_t t;

    s3_memzero(&t, sizeof(t));

    t.family = 4;
    t.ip_len = 4;
    t.ip[0] = 192;
    t.ip[1] = 0;
    t.ip[2] = 2;
    t.ip[3] = 1;
    t.port = 22;

    p = s3_ssh3_forward_build_target(gs_buf, &t);
    gs_write(dir, "v4", (size_t)(p - gs_buf));

    /* two targets in one chunk */

    p = s3_ssh3_forward_build_target(p, &t);
    gs_write(dir, "v4_tail", (size_t)(p - gs_buf));

    s3_memzero(&t, sizeof(t));

    t.family = 6;
    t.ip_len = 16;
    t.ip[0] = 0x20;
    t.ip[1] = 0x01;
    t.ip[2] = 0x0d;
    t.ip[3] = 0xb8;
    t.ip[15] = 1;
    t.port = 443;

    p = s3_ssh3_forward_build_target(gs_buf, &t);
    gs_write(dir, "v6", (size_t)(p - gs_buf));

    /* the truncated ipv6 tail: the ip cut short */

    gs_buf[0] = 6;
    s3_memzero(gs_buf + 1, 8);
    gs_write(dir, "v6_trunc", 9);
}

static void
gs_wire(const char *dir)
{
    static const u_char varints[][8] = {
        {0x00},
        {0x3f},
        {0x40, 0x40},
        {0x7f, 0xff},
        {0x80, 0x00, 0x40, 0x00},
        {0xbf, 0xff, 0xff, 0xff},
        {0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00},
        {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
    };
    static const size_t lens[] = {1, 1, 2, 2, 4, 4, 8, 8};
    char                name[32];
    u_char             *p;
    size_t              i;

    for (i = 0; i < sizeof(varints) / sizeof(varints[0]); i++) {
        snprintf(name, sizeof(name), "varint%u", (unsigned)i);

        s3_memcpy(gs_buf, varints[i], lens[i]);
        gs_write(dir, name, lens[i]);
    }

    /* the plain, the empty and the two-byte-length sshstring */

    p = s3_ssh3_encode_sshstring(gs_buf, "ssh3-c", 6);
    gs_write(dir, "sshstring", (size_t)(p - gs_buf));

    p = s3_ssh3_encode_sshstring(gs_buf, "", 0);
    gs_write(dir, "sshstring_empty", (size_t)(p - gs_buf));

    p = s3_ssh3_encode_varint(gs_buf, 300);

    for (i = 0; i < 300; i++) {
        *p++ = (u_char)i;
    }

    gs_write(dir, "sshstring_300", (size_t)(p - gs_buf));

    /* a string, then a varint, the mixed walk */

    p = s3_ssh3_encode_sshstring(gs_buf, "host", 4);
    p = s3_ssh3_encode_varint(p, 64);

    gs_write(dir, "mixed", (size_t)(p - gs_buf));
}

static void
gs_message(const char *dir)
{
    static const u_char             ls_body[] = "\x02"
                                                "ls";
    u_char                         *p;
    s3_ssh3_msg_open_confirmation_t oc;
    s3_ssh3_msg_open_failure_t      of;
    s3_ssh3_msg_data_t              d;
    s3_ssh3_msg_extended_data_t     ed;
    s3_ssh3_msg_request_t           rq;

    /* the open confirmation in the 4-byte and the 2-byte varint form */

    s3_memzero(&oc, sizeof(oc));

    oc.max_packet_size = 32768;
    p = (u_char *)s3_ssh3_msg_encode_open_confirmation(gs_buf, &oc);
    gs_write(dir, "openconf_32768", (size_t)(p - gs_buf));

    oc.max_packet_size = 64;
    p = (u_char *)s3_ssh3_msg_encode_open_confirmation(gs_buf, &oc);
    gs_write(dir, "openconf_64", (size_t)(p - gs_buf));

    /* the open failure with both strings and with the empty ones */

    s3_memzero(&of, sizeof(of));

    of.reason_code = 1;
    s3_str_set(&of.error_message, "denied");
    s3_str_set(&of.language_tag, "en");

    p = (u_char *)s3_ssh3_msg_encode_open_failure(gs_buf, &of);
    gs_write(dir, "openfailure", (size_t)(p - gs_buf));

    of.reason_code = 2;
    of.error_message.len = 0;
    of.language_tag.len = 0;

    p = (u_char *)s3_ssh3_msg_encode_open_failure(gs_buf, &of);
    gs_write(dir, "openfailure_empty", (size_t)(p - gs_buf));

    /* the data message, the plain and the empty payload */

    s3_memzero(&d, sizeof(d));

    s3_str_set(&d.data, "hello");
    p = (u_char *)s3_ssh3_msg_encode_data(gs_buf, &d);
    gs_write(dir, "data_hello", (size_t)(p - gs_buf));

    d.data.len = 0;
    p = (u_char *)s3_ssh3_msg_encode_data(gs_buf, &d);
    gs_write(dir, "data_empty", (size_t)(p - gs_buf));

    /* the extended data, the stderr payload */

    s3_memzero(&ed, sizeof(ed));

    ed.data_type = S3_SSH3_EXTENDED_DATA_STDERR;
    s3_str_set(&ed.data, "err");

    p = (u_char *)s3_ssh3_msg_encode_extended_data(gs_buf, &ed);
    gs_write(dir, "extdata_stderr", (size_t)(p - gs_buf));

    /* the shell request carries no body, the exec one the raw body
     * after wantReply */

    s3_memzero(&rq, sizeof(rq));

    s3_str_set(&rq.request_type, "shell");
    p = (u_char *)s3_ssh3_msg_encode_request(gs_buf, &rq);
    gs_write(dir, "request_shell", (size_t)(p - gs_buf));

    s3_str_set(&rq.request_type, "exec");
    rq.want_reply = 1;
    rq.body.data = (u_char *)ls_body;
    rq.body.len = sizeof(ls_body) - 1;

    p = (u_char *)s3_ssh3_msg_encode_request(gs_buf, &rq);
    gs_write(dir, "request_exec", (size_t)(p - gs_buf));

    /* the request envelope alone: the type string plus the wantReply
     * byte, the body the request module parses stays out; no
     * dedicated encoder rides this seed */

    p = s3_ssh3_encode_sshstring(gs_buf, "exec", 4);
    *p++ = 1;

    gs_write(dir, "request_envelope", (size_t)(p - gs_buf));

    /* two data bodies in one chunk, the multi-body walk */

    s3_str_set(&d.data, "hello");
    p = (u_char *)s3_ssh3_msg_encode_data(gs_buf, &d);
    p = (u_char *)s3_ssh3_msg_encode_data(p, &d);

    gs_write(dir, "multi", (size_t)(p - gs_buf));
}

/*
 * the QUIC varint of the frame fields, the same 2-bit length
 * discriminators the decoder reads
 */

static u_char *
gs_quic_varint(u_char *p, uint64_t v)
{
    if (v <= 0x3f) {
        *p++ = (u_char)v;

    } else if (v <= 0x3fff) {
        *p++ = (u_char)(0x40 | (v >> 8));
        *p++ = (u_char)v;

    } else if (v <= 0x3fffffff) {
        *p++ = (u_char)(0x80 | (v >> 24));
        *p++ = (u_char)(v >> 16);
        *p++ = (u_char)(v >> 8);
        *p++ = (u_char)v;

    } else {
        *p++ = (u_char)(0xc0 | (v >> 56));
        *p++ = (u_char)(v >> 48);
        *p++ = (u_char)(v >> 40);
        *p++ = (u_char)(v >> 32);
        *p++ = (u_char)(v >> 24);
        *p++ = (u_char)(v >> 16);
        *p++ = (u_char)(v >> 8);
        *p++ = (u_char)v;
    }

    return p;
}

/*
 * one fuzz_quic_state record: [meta][pn:2][len:2][payload], the meta
 * low bits pick the packet flags (0 short, 1 initial, 2 handshake,
 * 3 zero-rtt)
 */

static void
gs_quic_rec(u_char *dst, u_char sel, uint64_t pn, const u_char *body, size_t len)
{
    dst[0] = sel;
    dst[1] = (u_char)(pn >> 8);
    dst[2] = (u_char)pn;
    dst[3] = (u_char)(len >> 8);
    dst[4] = (u_char)len;

    s3_memcpy(dst + 5, body, len);
}

static size_t
gs_quic_rec_len(size_t len)
{
    return len + 5;
}

static void
gs_quic(const char *dir)
{
    /* the frame bodies, one per record */

    static const u_char ping[] = {0x01};
    static const u_char crypto[] = {0x06, 0x00, 0x06, 's', 's', 'h', '3', '-', 'c'};
    static const u_char ack_one[] = {
        0x02, 0x00, 0x00, 0x00, 0x00 /* largest 0, delay 0, no ranges, first 0 */
    };
    static const u_char ack_all[] = {
        0x02, 0x03, 0x08, 0x00, 0x03 /* the whole seeded 0..3 space */
    };
    static const u_char ack_gap[] = {
        0x02, 0x0a, 0x00, 0x01, 0x00, /* largest 10, one range */
        0x02, 0x01                    /* gap 2, range 1 */
    };
    static const u_char stream_hello[] = {
        0x0e, 0x00, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o' /* id 0, off 0, len 5 */
    };
    static const u_char stream_two[] = {
        0x0e, 0x00, 0x00, 0x03, 'a', 'b', 'c', /* stream 0 */
        0x0e, 0x04, 0x00, 0x03, 'd', 'e', 'f'  /* stream 4 */
    };
    static const u_char stream_fin_reset[] = {
        0x0f, 0x00, 0x00, 0x03, 'x', 'y', 'z', /* stream 0 with FIN */
        0x04, 0x00, 0x01, 0x03                 /* RESET_STREAM, final 3 */
    };
    static const u_char zrtt_stream[] = {
        0x0e, 0x0c, 0x00, 0x02, 'z', 'r' /* stream 12, off 0, len 2 */
    };
    static const u_char datagram[] = {0x31, 0x04, 'q', 'u', 'i', 'c'};
    static const u_char path[] = {
        0x1a, 1, 2, 3, 4, 5, 6, 7, 8, /* PATH_CHALLENGE */
        0x1b, 9, 8, 7, 6, 5, 4, 3, 2  /* PATH_RESPONSE */
    };
    static const u_char ncid[] = {
        0x18, 0x01, 0x00, 0x08,                         /* seq 1, retire 0, cid len 8 */
        0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, /* connection id */
        0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, /* stateless reset token */
        0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0};
    static const u_char close_ping[] = {
        0x01,                                 /* PING first, the walk goes on */
        0x1c, 0x0a, 0x01, 0x03, 'b', 'y', 'e' /* CONNECTION_CLOSE, reason "bye" */
    };
    u_char *b, *p;
    size_t  n;

    gs_quic_rec(gs_buf, 0, 0, ping, sizeof(ping));
    gs_write(dir, "ping", gs_quic_rec_len(sizeof(ping)));

    gs_quic_rec(gs_buf, 1, 0, ping, sizeof(ping));
    gs_write(dir, "ping_initial", gs_quic_rec_len(sizeof(ping)));

    gs_quic_rec(gs_buf, 2, 0, crypto, sizeof(crypto));
    gs_write(dir, "crypto_hs", gs_quic_rec_len(sizeof(crypto)));

    gs_quic_rec(gs_buf, 0, 1, ack_one, sizeof(ack_one));
    gs_write(dir, "ack_one", gs_quic_rec_len(sizeof(ack_one)));

    gs_quic_rec(gs_buf, 0, 2, ack_all, sizeof(ack_all));
    gs_write(dir, "ack_all", gs_quic_rec_len(sizeof(ack_all)));

    gs_quic_rec(gs_buf, 0, 3, ack_gap, sizeof(ack_gap));
    gs_write(dir, "ack_gap", gs_quic_rec_len(sizeof(ack_gap)));

    gs_quic_rec(gs_buf, 0, 4, stream_hello, sizeof(stream_hello));
    gs_write(dir, "stream_hello", gs_quic_rec_len(sizeof(stream_hello)));

    n = sizeof(stream_two);

    gs_quic_rec(gs_buf, 0, 5, stream_two, n);
    gs_write(dir, "stream_two", gs_quic_rec_len(n));

    gs_quic_rec(gs_buf, 0, 6, stream_fin_reset, sizeof(stream_fin_reset));
    gs_write(dir, "stream_fin_reset", gs_quic_rec_len(sizeof(stream_fin_reset)));

    /* the flow-control family, the limits through the varint writer */

    b = gs_body;

    *b++ = 0x10; /* MAX_DATA */
    b = gs_quic_varint(b, 1000000);
    *b++ = 0x12; /* MAX_STREAMS, bidi */
    b = gs_quic_varint(b, 288);
    *b++ = 0x14; /* DATA_BLOCKED */
    b = gs_quic_varint(b, 500000);
    *b++ = 0x16; /* STREAMS_BLOCKED, bidi */
    b = gs_quic_varint(b, 300);

    n = (size_t)(b - gs_body);

    gs_quic_rec(gs_buf, 0, 7, gs_body, n);
    gs_write(dir, "flow_control", gs_quic_rec_len(n));

    b = gs_body;

    *b++ = 0x11; /* MAX_STREAM_DATA */
    *b++ = 0x00; /* stream 0 */
    b = gs_quic_varint(b, 200000);
    *b++ = 0x15; /* STREAM_DATA_BLOCKED */
    *b++ = 0x00;
    b = gs_quic_varint(b, 100);
    *b++ = 0x05; /* STOP_SENDING */
    *b++ = 0x00;
    *b++ = 0x01;

    n = (size_t)(b - gs_body);

    gs_quic_rec(gs_buf, 0, 8, gs_body, n);
    gs_write(dir, "stream_blocked", gs_quic_rec_len(n));

    gs_quic_rec(gs_buf, 3, 0, zrtt_stream, sizeof(zrtt_stream));
    gs_write(dir, "zrtt_stream", gs_quic_rec_len(sizeof(zrtt_stream)));

    gs_quic_rec(gs_buf, 0, 9, datagram, sizeof(datagram));
    gs_write(dir, "datagram", gs_quic_rec_len(sizeof(datagram)));

    gs_quic_rec(gs_buf, 0, 10, path, sizeof(path));
    gs_write(dir, "path", gs_quic_rec_len(sizeof(path)));

    gs_quic_rec(gs_buf, 0, 11, ncid, sizeof(ncid));
    gs_write(dir, "ncid", gs_quic_rec_len(sizeof(ncid)));

    gs_quic_rec(gs_buf, 0, 12, close_ping, sizeof(close_ping));
    gs_write(dir, "close_ping", gs_quic_rec_len(sizeof(close_ping)));

    /* three records in one input: the ping, the ack of it, then the
     * stream data, the stateful sequence the harness keeps a context
     * across */

    p = gs_buf;
    n = 0;

    gs_quic_rec(p, 0, 0, ping, sizeof(ping));
    p += gs_quic_rec_len(sizeof(ping));
    n += gs_quic_rec_len(sizeof(ping));

    gs_quic_rec(p, 0, 1, ack_one, sizeof(ack_one));
    p += gs_quic_rec_len(sizeof(ack_one));
    n += gs_quic_rec_len(sizeof(ack_one));

    gs_quic_rec(p, 0, 4, stream_hello, sizeof(stream_hello));
    n += gs_quic_rec_len(sizeof(stream_hello));

    gs_write(dir, "multi_stateful", n);
}

int
main(int argc, char *const *argv)
{
    char        dir[512];
    const char *root;

    if (argc != 2) {
        printf("usage: gen_seeds <output-dir>\n");

        return EXIT_FAILURE;
    }

    root = argv[1];

    gs_dir(root);

    snprintf(dir, sizeof(dir), "%s/sftp", root);
    gs_dir(dir);
    gs_sftp(dir);

    snprintf(dir, sizeof(dir), "%s/cm", root);
    gs_dir(dir);
    gs_cm(dir);

    snprintf(dir, sizeof(dir), "%s/forward", root);
    gs_dir(dir);
    gs_forward(dir);

    snprintf(dir, sizeof(dir), "%s/wire", root);
    gs_dir(dir);
    gs_wire(dir);

    snprintf(dir, sizeof(dir), "%s/message", root);
    gs_dir(dir);
    gs_message(dir);

    snprintf(dir, sizeof(dir), "%s/quic_state", root);
    gs_dir(dir);
    gs_quic(dir);

    return gs_failures != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
