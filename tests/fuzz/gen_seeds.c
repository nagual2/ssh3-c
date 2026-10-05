/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the fuzz seed corpus generator: writes the hand-built valid frames
 * of the six parser targets, the same shapes the unit tests build
 * through the codec encoders; one directory per target under argv[1]
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <s3_core.h>

#include <s3_h3.h>

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
 * the h3 stateful steps: the op byte and the length byte wrap every
 * payload, the prefix integers carry the instruction flags in the
 * high bits over the codec output (the same shapes the h3 unit tests
 * and fuzz_h3_state.c drive)
 */

static u_char *
gs_h3_prefix(u_char *p, uint64_t value, u_char high, s3_uint_t prefix)
{
    u_char *end;

    end = (u_char *)s3_h3_encode_prefix_int(p, value, prefix);
    p[0] = (u_char)(p[0] | high);

    return end;
}

static u_char *
gs_h3_step(u_char *p, u_char op, const u_char *payload, size_t len)
{
    *p++ = op;
    *p++ = (u_char)len;

    if (len != 0) {
        s3_memcpy(p, payload, len);
    }

    return p + len;
}

static void
gs_h3_seed(const char *dir, const char *name, u_char op, const u_char *payload, size_t len)
{
    gs_buf[0] = op;
    gs_buf[1] = (u_char)len;

    if (len != 0) {
        s3_memcpy(gs_buf + 2, payload, len);
    }

    gs_write(dir, name, len + 2);
}

static void
gs_h3(const char *dir)
{
    /* the op codes of fuzz_h3_state.c */

    u_char  pay[64];
    u_char *p, *q;

    /* the encoder stream: capacity, inserts, duplicate */

    p = pay;
    p = gs_h3_prefix(p, 512, 0x20, 5); /* Set Dynamic Table Capacity 512 */
    *p++ = 0x43;                       /* Insert With Literal Name, len 3 */
    *p++ = 'a';
    *p++ = 'b';
    *p++ = 'c';
    *p++ = 0x02; /* plain value, len 2 */
    *p++ = 'x';
    *p++ = 'y';
    gs_h3_seed(dir, "enc_cap_insert", 0x00, pay, (size_t)(p - pay));

    p = pay;
    p = gs_h3_prefix(p, 512, 0x20, 5);
    *p++ = 0xd1; /* Insert With Name Reference, static :method GET (17) */
    *p++ = 0x02;
    *p++ = 'v';
    *p++ = '1';
    gs_h3_seed(dir, "enc_inr_static", 0x00, pay, (size_t)(p - pay));

    p = pay;
    p = gs_h3_prefix(p, 128, 0x20, 5);
    *p++ = 0x41; /* insert "k":"v" */
    *p++ = 'k';
    *p++ = 0x01;
    *p++ = 'v';
    *p++ = 0x00; /* Duplicate of the relative index 0 */
    gs_h3_seed(dir, "enc_dupe", 0x00, pay, (size_t)(p - pay));

    p = pay;
    *p++ = 0x20; /* capacity 0: the evict-all path */
    gs_h3_seed(dir, "enc_cap_zero", 0x00, pay, 1);

    p = pay;
    *p++ = 0x91; /* dynamic name reference on the empty table: the error path */
    *p++ = 0x02;
    *p++ = 'v';
    *p++ = '1';
    gs_h3_seed(dir, "enc_inr_dynamic_oob", 0x00, pay, (size_t)(p - pay));

    /* the decoder stream instructions */

    p = pay;
    *p++ = 0x40; /* Stream Cancellation, id 0 */
    *p++ = 0x00;
    gs_h3_seed(dir, "dec_cancel", 0x01, pay, (size_t)(p - pay));

    p = pay;
    *p++ = 0x02; /* Insert Count Increment 2 */
    gs_h3_seed(dir, "dec_ici", 0x01, pay, 1);

    p = pay;
    *p++ = 0xff; /* Section Acknowledgment 128 */
    *p++ = 0x80;
    *p++ = 0x01;
    gs_h3_seed(dir, "dec_ack", 0x01, pay, (size_t)(p - pay));

    /* the control stream: the settings ordering and the frame mix */

    p = pay;
    *p++ = 0x04; /* empty SETTINGS */
    *p++ = 0x00;
    gs_h3_seed(dir, "ctrl_settings_empty", 0x02, pay, (size_t)(p - pay));

    p = pay;
    *p++ = 0x04;
    *p++ = 0x06; /* two parameters: table capacity, blocked streams */
    *p++ = 0x01;
    *p++ = 0x40;
    *p++ = 0xc8;
    *p++ = 0x07;
    *p++ = 0x40;
    *p++ = 0x0a;
    gs_h3_seed(dir, "ctrl_settings_params", 0x02, pay, (size_t)(p - pay));

    p = pay;
    *p++ = 0x07; /* GOAWAY with a skipped payload */
    *p++ = 0x02;
    *p++ = 0xde;
    *p++ = 0xad;
    gs_h3_seed(dir, "ctrl_goaway", 0x02, pay, (size_t)(p - pay));

    p = pay;
    *p++ = 0x0d; /* MAX_PUSH_ID, empty */
    *p++ = 0x00;
    gs_h3_seed(dir, "ctrl_max_push_id", 0x02, pay, (size_t)(p - pay));

    p = pay;
    *p++ = 0x21; /* unknown frame skipped, then CANCEL_PUSH (the id error) */
    *p++ = 0x02;
    *p++ = 0xde;
    *p++ = 0xad;
    *p++ = 0x03;
    *p++ = 0x00;
    gs_h3_seed(dir, "ctrl_unknown_cancel", 0x02, pay, (size_t)(p - pay));

    /* the request-stream sections against the shared table */

    p = pay;
    *p++ = 0x00; /* section prefix: no inserts, base 0 */
    *p++ = 0x00;
    *p++ = 0x24; /* literal "x-h3":"v1" */
    *p++ = 'x';
    *p++ = '-';
    *p++ = 'h';
    *p++ = '3';
    *p++ = 0x02;
    *p++ = 'v';
    *p++ = '1';
    gs_h3_seed(dir, "hdrs_literal", 0x03, pay, (size_t)(p - pay));

    p = pay;
    *p++ = 0x00;
    *p++ = 0x00;
    *p++ = 0xc5; /* indexed static 5 ("cookie") */
    gs_h3_seed(dir, "hdrs_static_ri", 0x03, pay, (size_t)(p - pay));

    p = pay;
    *p++ = 0x00;
    *p++ = 0x00;
    *p++ = 0x5f; /* literal with the static name ref 17, overflow prefix */
    *p++ = 0x02;
    *p++ = 0x04;
    *p++ = 's';
    *p++ = 's';
    *p++ = 'h';
    *p++ = '3';
    gs_h3_seed(dir, "hdrs_lri_static", 0x03, pay, (size_t)(p - pay));

    /* the single-step probes */

    p = pay;
    *p++ = 0x00; /* dynamic reference to the oldest entry */
    gs_h3_seed(dir, "dynref", 0x04, pay, 1);

    p = pay;
    *p++ = 0x00; /* DATA len 2, then the empty HEADERS trailers */
    *p++ = 0x02;
    *p++ = 'A';
    *p++ = 'B';
    *p++ = 0x01;
    *p++ = 0x00;
    gs_h3_seed(dir, "data_frames", 0x05, pay, (size_t)(p - pay));

    p = pay;
    *p++ = 0x00; /* control stream type + empty SETTINGS, raw dispatch */
    *p++ = 0x04;
    *p++ = 0x00;
    gs_h3_seed(dir, "raw_control", 0x06, pay, (size_t)(p - pay));

    p = pay;
    *p++ = 0x02; /* encoder stream type + capacity 288 */
    *p++ = 0x3f;
    *p++ = 0x81;
    *p++ = 0x02;
    gs_h3_seed(dir, "raw_encoder", 0x06, pay, (size_t)(p - pay));

    p = pay;
    *p++ = 0x25; /* unknown uni stream type swallowed */
    *p++ = 0xaa;
    *p++ = 0xbb;
    gs_h3_seed(dir, "raw_unknown", 0x06, pay, (size_t)(p - pay));

    p = pay;
    *p++ = 0x00; /* capacity 512 */
    *p++ = 0x80;
    gs_h3_seed(dir, "capacity", 0x07, pay, (size_t)(p - pay));

    p = pay;
    *p++ = 0x01; /* park one blocked stream */
    gs_h3_seed(dir, "block", 0x08, pay, 1);

    p = pay;
    *p++ = 0x3f; /* the 1-byte varlen 63 */
    gs_h3_seed(dir, "varlen_63", 0x09, pay, 1);

    p = pay;
    *p++ = 0xc0; /* the 8-byte varlen */
    *p++ = 0x00;
    *p++ = 0x40;
    *p++ = 0x00;
    *p++ = 0x00;
    *p++ = 0x00;
    *p++ = 0x00;
    *p++ = 0x01;
    gs_h3_seed(dir, "varlen_big", 0x09, pay, 8);

    p = pay;
    *p++ = 0x11; /* static reference 17 */
    gs_h3_seed(dir, "static_ref", 0x0a, pay, 1);

    p = pay;
    s3_memcpy(p, "\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff", 12);
    gs_h3_seed(dir, "huff_www", 0x0b, pay, 12);

    /* the stateful sequences: the earlier steps build the table
     * state the later steps act on; p walks gs_buf, q builds the
     * payloads */

    p = gs_buf;

    /* the insert, then the section against it, then the reference */

    q = pay;
    q = gs_h3_prefix(q, 512, 0x20, 5);
    *q++ = 0x43;
    *q++ = 'a';
    *q++ = 'b';
    *q++ = 'c';
    *q++ = 0x02;
    *q++ = 'x';
    *q++ = 'y';
    p = gs_h3_step(p, 0x00, pay, (size_t)(q - pay));

    q = pay;
    q = gs_h3_prefix(q, 512, 0x20, 5);
    *q++ = 0xd1;
    *q++ = 0x02;
    *q++ = 'v';
    *q++ = '1';
    p = gs_h3_step(p, 0x00, pay, (size_t)(q - pay));

    q = pay;
    *q++ = 0x00;
    *q++ = 0x00;
    *q++ = 0xc5;
    p = gs_h3_step(p, 0x03, pay, (size_t)(q - pay));

    q = pay;
    *q++ = 0x00;
    p = gs_h3_step(p, 0x04, pay, 1);

    gs_write(dir, "seq_qpack_roundtrip", (size_t)(p - gs_buf));

    /* the control stream ordering, then a header block */

    p = gs_buf;

    q = pay;
    *q++ = 0x04;
    *q++ = 0x00;
    p = gs_h3_step(p, 0x02, pay, (size_t)(q - pay));

    q = pay;
    *q++ = 0x07;
    *q++ = 0x02;
    *q++ = 0xde;
    *q++ = 0xad;
    p = gs_h3_step(p, 0x02, pay, (size_t)(q - pay));

    q = pay;
    *q++ = 0x00;
    *q++ = 0x00;
    *q++ = 0x24;
    *q++ = 'x';
    *q++ = '-';
    *q++ = 'h';
    *q++ = '3';
    *q++ = 0x02;
    *q++ = 'v';
    *q++ = '1';
    p = gs_h3_step(p, 0x03, pay, (size_t)(q - pay));

    gs_write(dir, "seq_ctrl_then_headers", (size_t)(p - gs_buf));

    /* the mixed session: capacity, inserts, blocked stream, the
     * round-trips over the mutated state */

    p = gs_buf;

    q = pay;
    *q++ = 0x00;
    *q++ = 0x80;
    p = gs_h3_step(p, 0x07, pay, (size_t)(q - pay));

    q = pay;
    q = gs_h3_prefix(q, 512, 0x20, 5);
    *q++ = 0x43;
    *q++ = 'a';
    *q++ = 'b';
    *q++ = 'c';
    *q++ = 0x02;
    *q++ = 'x';
    *q++ = 'y';
    p = gs_h3_step(p, 0x00, pay, (size_t)(q - pay));

    q = pay;
    *q++ = 0x01;
    p = gs_h3_step(p, 0x08, pay, 1);

    q = pay;
    q = gs_h3_prefix(q, 128, 0x20, 5);
    *q++ = 0x41;
    *q++ = 'k';
    *q++ = 0x01;
    *q++ = 'v';
    *q++ = 0x00;
    p = gs_h3_step(p, 0x00, pay, (size_t)(q - pay));

    q = pay;
    *q++ = 0x00;
    p = gs_h3_step(p, 0x04, pay, 1);

    q = pay;
    *q++ = 0xc0;
    *q++ = 0x00;
    *q++ = 0x40;
    *q++ = 0x00;
    *q++ = 0x00;
    *q++ = 0x00;
    *q++ = 0x00;
    *q++ = 0x01;
    p = gs_h3_step(p, 0x09, pay, 8);

    q = pay;
    s3_memcpy(q, "\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff", 12);
    q += 12;
    p = gs_h3_step(p, 0x0b, pay, 12);

    gs_write(dir, "seq_mixed", (size_t)(p - gs_buf));
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

    snprintf(dir, sizeof(dir), "%s/h3", root);
    gs_dir(dir);
    gs_h3(dir);

    return gs_failures != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
