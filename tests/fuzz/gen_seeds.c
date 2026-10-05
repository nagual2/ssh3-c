/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the fuzz seed corpus generator: writes the hand-built valid frames
 * of the four parser targets, the same shapes the unit tests build
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

    return gs_failures != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
