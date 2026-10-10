/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the server side of the "sftp" channel: the INIT exchange, the
 * put/get roundtrip, the jail resolution, the directory listing, the
 * file commands and the hostile frames; every test drives the module
 * through input()/output() with the codec on both ends, the files
 * live in a mkdtemp jail wiped on the way out
 */

#include <s3_core.h>

#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <s3_ssh3_sftp_codec.h>

#include <s3_ssh3_sftp_srv.h>

#include "s3_test.h"

/* the jail of mkdtemp is short, the composite paths keep the headroom */

#define S3_TEST_JAIL_CAP 1024

#define S3_TEST_PATH_CAP (S3_TEST_JAIL_CAP + 256)

/* the reply accumulator, one file-scope buffer for every exchange */

static u_char s3_test_rep[256 * 1024];

static s3_str_t
s3_test_str(const char *text)
{
    s3_str_t s;

    s.data = (u_char *)text;
    s.len = strlen(text);

    return s;
}

/*
 * the build of one request frame: the encoder answers the
 * past-the-end pointer on the write, the difference to the start is
 * the frame size
 */

#define S3_TEST_BUILD(fn, buf, ...) ((size_t)((uintptr_t)fn(buf, __VA_ARGS__) - (uintptr_t)(buf)))

static int
s3_test_str_is(const s3_str_t *s, const char *text)
{
    size_t n = strlen(text);

    return s->len == n && (n == 0 || s3_memcmp(s->data, text, n) == 0);
}

static s3_pool_t *
s3_test_make_pool(s3_log_t *log)
{
    log->log_level = S3_LOG_ALERT;
    log->fd = S3_INVALID_FILE;

    return s3_create_pool(S3_DEFAULT_POOL_SIZE, log);
}

static int
s3_test_make_jail(char *jail)
{
    snprintf(jail, S3_TEST_JAIL_CAP, "/tmp/s3sftp-XXXXXX");

    return mkdtemp(jail) == NULL ? -1 : 0;
}

static int
s3_test_make_srv(s3_ssh3_sftp_srv_t *t, s3_pool_t *pool, const char *jail)
{
    s3_str_t home = s3_test_str(jail);

    return s3_ssh3_sftp_srv_init(t, pool, &home, (uint32_t)getuid(), (uint32_t)getgid());
}

/* the recursive wipe of the jail: opendir on a file fails, unlink it */

static void
s3_test_rmrec(char *path, size_t cap)
{
    size_t         base = strlen(path);
    DIR           *d = opendir(path);
    struct dirent *e;

    if (d == NULL) {
        (void)unlink(path);
        return;
    }

    while ((e = readdir(d)) != NULL) {

        if (e->d_name[0] == '.' &&
            (e->d_name[1] == '\0' || (e->d_name[1] == '.' && e->d_name[2] == '\0'))) {
            continue;
        }

        (void)snprintf(path + base, cap - base, "/%s", e->d_name);
        s3_test_rmrec(path, cap);
        path[base] = '\0';
    }

    (void)closedir(d);
    (void)rmdir(path);
}

static int
s3_test_write_file(const char *path, const char *data)
{
    FILE  *f = fopen(path, "wb");
    size_t n = strlen(data);

    if (f == NULL) {
        return -1;
    }

    if (fwrite(data, 1, n, f) != n) {
        (void)fclose(f);
        return -1;
    }

    return fclose(f) == 0 ? 0 : -1;
}

static size_t
s3_test_collect(s3_ssh3_sftp_srv_t *t, u_char *buf, size_t cap)
{
    size_t  len = 0;
    ssize_t n;

    while (len < cap) {

        n = s3_ssh3_sftp_srv_output(t, buf + len, cap - len);

        if (n <= 0) {
            break;
        }

        len += (size_t)n;
    }

    return len;
}

/* exactly one frame in the accumulated bytes, fully consumed */

static int
s3_test_reply(const u_char *buf, size_t len, s3_ssh3_sftp_pkt_t *pkt)
{
    const u_char *pos = buf;
    const u_char *end = buf + len;

    if (s3_ssh3_sftp_codec_frame(&pos, end, pkt) != S3_OK) {
        return -1;
    }

    return pos == end ? 0 : -1;
}

/* one request in, one parsed reply out, the type and the id checked */

static void
s3_test_rpc(s3_ssh3_sftp_srv_t *t, const u_char *req, size_t req_len, uint32_t want_id,
            u_char want_type, s3_ssh3_sftp_pkt_t *pkt)
{
    size_t rlen;

    S3_ASSERT(s3_ssh3_sftp_srv_input(t, req, req_len) == S3_OK);

    rlen = s3_test_collect(t, s3_test_rep, sizeof(s3_test_rep));
    S3_ASSERT(rlen > 0);
    S3_ASSERT(s3_test_reply(s3_test_rep, rlen, pkt) == 0);
    S3_ASSERT(pkt->type == want_type);
    S3_ASSERT(pkt->has_id);
    S3_ASSERT(pkt->request_id == want_id);
}

static uint32_t
s3_test_status_code(const s3_ssh3_sftp_pkt_t *pkt)
{
    const u_char *pos = pkt->body.data;
    const u_char *end = pos + pkt->body.len;
    uint32_t      code;

    if (s3_ssh3_sftp_parse_u32(&pos, end, &code) != S3_OK) {
        return 0xFFFFFFFF;
    }

    return code;
}

static void
s3_test_expect_status(s3_ssh3_sftp_srv_t *t, const u_char *req, size_t req_len, uint32_t want_id,
                      uint32_t want_code, s3_ssh3_sftp_pkt_t *pkt)
{
    s3_test_rpc(t, req, req_len, want_id, S3_SSH3_SFTP_STATUS, pkt);
    S3_ASSERT(s3_test_status_code(pkt) == want_code);
}

static int
s3_test_handle_of(const s3_ssh3_sftp_pkt_t *pkt, s3_str_t *h)
{
    const u_char *pos = pkt->body.data;
    const u_char *end = pos + pkt->body.len;

    if (s3_ssh3_sftp_parse_string(&pos, end, h) != S3_OK || pos != end) {
        return -1;
    }

    return 0;
}

/*
 * the HANDLE reply of one open: the eight bytes are copied out, the
 * shared reply buffer dies with the next request
 */

static void
s3_test_expect_handle(s3_ssh3_sftp_srv_t *t, const u_char *req, size_t req_len, uint32_t want_id,
                      u_char *out, s3_ssh3_sftp_pkt_t *pkt)
{
    s3_str_t h;

    s3_test_rpc(t, req, req_len, want_id, S3_SSH3_SFTP_HANDLE, pkt);
    S3_ASSERT(s3_test_handle_of(pkt, &h) == 0);
    S3_ASSERT(h.len == 8);
    s3_memcpy(out, h.data, 8);
}

/* the stable view over the copied handle bytes */

static s3_str_t
s3_test_handle_at(u_char *bytes)
{
    s3_str_t h;

    h.data = bytes;
    h.len = 8;

    return h;
}

static int
s3_test_data_of(const s3_ssh3_sftp_pkt_t *pkt, s3_str_t *data)
{
    const u_char *pos = pkt->body.data;
    const u_char *end = pos + pkt->body.len;

    if (s3_ssh3_sftp_parse_string(&pos, end, data) != S3_OK || pos != end) {
        return -1;
    }

    return 0;
}

/* the entries of one NAME reply, the count must match */

static int
s3_test_names_of(const s3_ssh3_sftp_pkt_t *pkt, uint32_t want, s3_str_t *names, s3_str_t *lnames,
                 s3_ssh3_sftp_attrs_t *attrs)
{
    const u_char *pos = pkt->body.data;
    const u_char *end = pos + pkt->body.len;
    uint32_t      count, i;

    if (s3_ssh3_sftp_parse_u32(&pos, end, &count) != S3_OK || count != want) {
        return -1;
    }

    for (i = 0; i < count; i++) {

        if (s3_ssh3_sftp_parse_string(&pos, end, &names[i]) != S3_OK ||
            s3_ssh3_sftp_parse_string(&pos, end, &lnames[i]) != S3_OK ||
            s3_ssh3_sftp_parse_attrs(&pos, end, &attrs[i]) != S3_OK) {
            return -1;
        }
    }

    return pos == end ? 0 : -1;
}

/* the one-entry NAME of the realpath answers */

static int
s3_test_name1_of(const s3_ssh3_sftp_pkt_t *pkt, s3_str_t *name)
{
    s3_ssh3_sftp_attrs_t attrs;
    s3_str_t             names[1], lnames[1];

    if (s3_test_names_of(pkt, 1, names, lnames, &attrs) != 0) {
        return -1;
    }

    /* the realpath entry: the empty longname, the flagless attrs */

    if (lnames[0].len != 0 || attrs.flags != 0) {
        return -1;
    }

    *name = names[0];

    return 0;
}

static int
s3_test_attrs_of(const s3_ssh3_sftp_pkt_t *pkt, s3_ssh3_sftp_attrs_t *a)
{
    const u_char *pos = pkt->body.data;
    const u_char *end = pos + pkt->body.len;

    if (s3_ssh3_sftp_parse_attrs(&pos, end, a) != S3_OK || pos != end) {
        return -1;
    }

    return 0;
}

/* the raw frame builder for the requests without a codec encoder */

static size_t
s3_test_frame(u_char *out, u_char type, uint32_t id, const u_char *body, size_t blen)
{
    uint32_t n = (uint32_t)(1 + 4 + blen);

    out[0] = (u_char)(n >> 24);
    out[1] = (u_char)(n >> 16);
    out[2] = (u_char)(n >> 8);
    out[3] = (u_char)n;
    out[4] = type;
    out[5] = (u_char)(id >> 24);
    out[6] = (u_char)(id >> 16);
    out[7] = (u_char)(id >> 8);
    out[8] = (u_char)id;

    if (blen > 0) {
        s3_memcpy(out + 9, body, blen);
    }

    return 9 + blen;
}

static size_t
s3_test_str_body(u_char *out, const char *text)
{
    size_t n = strlen(text);

    out[0] = (u_char)(n >> 24);
    out[1] = (u_char)(n >> 16);
    out[2] = (u_char)(n >> 8);
    out[3] = (u_char)n;
    s3_memcpy(out + 4, text, n);

    return 4 + n;
}

static int
s3_test_name_in(const s3_str_t *names, uint32_t count, const char *what)
{
    uint32_t i;

    for (i = 0; i < count; i++) {

        if (s3_test_str_is(&names[i], what)) {
            return 1;
        }
    }

    return 0;
}

static int
s3_test_sftp_srv(void)
{
    s3_log_t             log;
    s3_pool_t           *pool;
    s3_ssh3_sftp_srv_t   srv, srv2, srv3;
    s3_ssh3_sftp_pkt_t   pkt;
    s3_ssh3_sftp_attrs_t zero, tsa, ra, entry_attrs[8];
    s3_str_t             h, h2, data, path, names[8], lnames[8];
    u_char               hw[8], hr[8], hp[8], hd[8];
    u_char               req[8192], body[S3_TEST_PATH_CAP];
    char                 jail[S3_TEST_JAIL_CAP], p1[S3_TEST_PATH_CAP], p2[S3_TEST_PATH_CAP];
    char                 exp[S3_TEST_PATH_CAP];
    const u_char        *pos, *end;
    size_t               n, rlen, blen;
    uint32_t             id = 0, i;
    uint32_t             v, ts;
    mode_t               um;
    struct stat          st;
    FILE                *f;
    char                 disk[64];

    s3_memzero(&zero, sizeof(zero));

    /* the wire paths of the script, the views over the literals */

    s3_str_t s_hello = s3_test_str("hello.txt");
    s3_str_t s_dot = s3_test_str(".");
    s3_str_t s_subf = s3_test_str("/sub/../f");
    s3_str_t s_docsf = s3_test_str("docs/f");
    s3_str_t s_empty = s3_test_str("");
    s3_str_t s_passwd = s3_test_str("../etc/passwd");
    s3_str_t s_jpass = s3_test_str("etc/passwd");
    s3_str_t s_sub = s3_test_str("sub");
    s3_str_t s_deep = s3_test_str("deep/a/b");
    s3_str_t s_deepdir = s3_test_str("deep");
    s3_str_t s_moveme = s3_test_str("moveme");
    s3_str_t s_moved = s3_test_str("moved");
    s3_str_t s_gone = s3_test_str("gone.txt");
    s3_str_t s_missing = s3_test_str("missing");
    s3_str_t s_emptydir = s3_test_str("emptydir");

    /* ---------------- the setup ---------------- */

    pool = s3_test_make_pool(&log);
    S3_ASSERT(pool != NULL);

    if (pool == NULL) {
        return 0;
    }

    S3_ASSERT(s3_test_make_jail(jail) == 0);
    S3_ASSERT(s3_test_make_srv(&srv, pool, jail) == S3_OK);

    /* the empty output drains to nothing */

    S3_ASSERT(s3_test_collect(&srv, s3_test_rep, sizeof(s3_test_rep)) == 0);

    /* ---------------- 1. the INIT exchange ---------------- */

    n = S3_TEST_BUILD(s3_ssh3_sftp_encode_init, req, 3);
    S3_ASSERT(n > 0);

    S3_ASSERT(s3_ssh3_sftp_srv_input(&srv, req, n) == S3_OK);
    rlen = s3_test_collect(&srv, s3_test_rep, sizeof(s3_test_rep));
    S3_ASSERT(rlen > 0);
    S3_ASSERT(s3_test_reply(s3_test_rep, rlen, &pkt) == 0);
    S3_ASSERT(pkt.type == S3_SSH3_SFTP_VERSION);
    S3_ASSERT(!pkt.has_id);

    pos = pkt.body.data;
    end = pos + pkt.body.len;
    S3_ASSERT(s3_ssh3_sftp_parse_u32(&pos, end, &v) == S3_OK);
    S3_ASSERT(pos == end);
    S3_ASSERT(v == S3_SSH3_SFTP_PROTOCOL_VERSION);

    /* ---------------- 2. the put/get roundtrip ---------------- */

    um = umask(0);
    (void)umask(um);

    id++;
    n = S3_TEST_BUILD(s3_ssh3_sftp_encode_open, req, id, &s_hello,
                      S3_SSH3_SFTP_FXF_WRITE | S3_SSH3_SFTP_FXF_CREAT | S3_SSH3_SFTP_FXF_TRUNC,
                      &zero);
    s3_test_expect_handle(&srv, req, n, id, hw, &pkt);
    h = s3_test_handle_at(hw);

    data = s3_test_str("hello world");

    id++;
    n = S3_TEST_BUILD(s3_ssh3_sftp_encode_write, req, id, &h, 0, &data);
    s3_test_expect_status(&srv, req, n, id, S3_SSH3_SFTP_FX_OK, &pkt);

    id++;
    n = S3_TEST_BUILD(s3_ssh3_sftp_encode_close, req, id, &h);
    s3_test_expect_status(&srv, req, n, id, S3_SSH3_SFTP_FX_OK, &pkt);

    /* the bytes are on the disk under the jail */

    (void)snprintf(p1, sizeof(p1), "%s/hello.txt", jail);
    f = fopen(p1, "rb");
    S3_ASSERT(f != NULL);

    if (f != NULL) {
        s3_str_t from_disk;

        s3_memzero(disk, sizeof(disk));
        S3_ASSERT(fread(disk, 1, sizeof(disk) - 1, f) == 11);

        from_disk.data = (u_char *)disk;
        from_disk.len = 11;
        S3_ASSERT(s3_test_str_is(&from_disk, "hello world"));

        (void)fclose(f);
    }

    id++;
    n = S3_TEST_BUILD(s3_ssh3_sftp_encode_open, req, id, &s_hello, S3_SSH3_SFTP_FXF_READ, &zero);
    s3_test_expect_handle(&srv, req, n, id, hr, &pkt);
    h2 = s3_test_handle_at(hr);

    id++;
    n = S3_TEST_BUILD(s3_ssh3_sftp_encode_read, req, id, &h2, 0, 4096);
    s3_test_rpc(&srv, req, n, id, S3_SSH3_SFTP_DATA, &pkt);
    S3_ASSERT(s3_test_data_of(&pkt, &data) == 0);
    S3_ASSERT(s3_test_str_is(&data, "hello world"));

    /* the read past the end is the EOF status */

    id++;
    n = S3_TEST_BUILD(s3_ssh3_sftp_encode_read, req, id, &h2, 11, 4096);
    s3_test_expect_status(&srv, req, n, id, S3_SSH3_SFTP_FX_EOF, &pkt);

    id++;
    n = S3_TEST_BUILD(s3_ssh3_sftp_encode_close, req, id, &h2);
    s3_test_expect_status(&srv, req, n, id, S3_SSH3_SFTP_FX_OK, &pkt);

    /* ---------------- 3. the jail ---------------- */

    (void)snprintf(p1, sizeof(p1), "%s/etc", jail);
    S3_ASSERT(mkdir(p1, 0755) == 0);

    (void)snprintf(p2, sizeof(p2), "%s/etc/passwd", jail);
    S3_ASSERT(s3_test_write_file(p2, "jailpass\n") == 0);

    /* "../etc/passwd" lands inside the jail: the file written above
       is exactly what comes back (the reference resolveJailed maps
       the escape into the home instead of rejecting it) */

    id++;
    n = S3_TEST_BUILD(s3_ssh3_sftp_encode_open, req, id, &s_passwd, S3_SSH3_SFTP_FXF_READ, &zero);
    s3_test_expect_handle(&srv, req, n, id, hp, &pkt);
    h = s3_test_handle_at(hp);

    id++;
    n = S3_TEST_BUILD(s3_ssh3_sftp_encode_read, req, id, &h, 0, 4096);
    s3_test_rpc(&srv, req, n, id, S3_SSH3_SFTP_DATA, &pkt);
    S3_ASSERT(s3_test_data_of(&pkt, &data) == 0);
    S3_ASSERT(s3_test_str_is(&data, "jailpass\n"));

    id++;
    n = S3_TEST_BUILD(s3_ssh3_sftp_encode_close, req, id, &h);
    s3_test_expect_status(&srv, req, n, id, S3_SSH3_SFTP_FX_OK, &pkt);

    /* the realpath verdicts of the jail */

    id++;
    n = S3_TEST_BUILD(s3_ssh3_sftp_encode_realpath, req, id, &s_dot);
    s3_test_rpc(&srv, req, n, id, S3_SSH3_SFTP_NAME, &pkt);
    S3_ASSERT(s3_test_name1_of(&pkt, &path) == 0);
    S3_ASSERT(s3_test_str_is(&path, jail));

    id++;
    n = S3_TEST_BUILD(s3_ssh3_sftp_encode_realpath, req, id, &s_subf);
    s3_test_rpc(&srv, req, n, id, S3_SSH3_SFTP_NAME, &pkt);
    S3_ASSERT(s3_test_name1_of(&pkt, &path) == 0);
    (void)snprintf(exp, sizeof(exp), "%s/f", jail);
    S3_ASSERT(s3_test_str_is(&path, exp));

    id++;
    n = S3_TEST_BUILD(s3_ssh3_sftp_encode_realpath, req, id, &s_docsf);
    s3_test_rpc(&srv, req, n, id, S3_SSH3_SFTP_NAME, &pkt);
    S3_ASSERT(s3_test_name1_of(&pkt, &path) == 0);
    (void)snprintf(exp, sizeof(exp), "%s/docs/f", jail);
    S3_ASSERT(s3_test_str_is(&path, exp));

    id++;
    n = S3_TEST_BUILD(s3_ssh3_sftp_encode_realpath, req, id, &s_empty);
    s3_test_rpc(&srv, req, n, id, S3_SSH3_SFTP_NAME, &pkt);
    S3_ASSERT(s3_test_name1_of(&pkt, &path) == 0);
    S3_ASSERT(s3_test_str_is(&path, jail));

    /* the unreadable file is the permission verdict (never as root) */

    if (getuid() != 0) {
        S3_ASSERT(chmod(p2, 0000) == 0);

        id++;
        n = S3_TEST_BUILD(s3_ssh3_sftp_encode_open, req, id, &s_jpass, S3_SSH3_SFTP_FXF_READ,
                          &zero);
        s3_test_expect_status(&srv, req, n, id, S3_SSH3_SFTP_FX_PERMISSION_DENIED, &pkt);

        S3_ASSERT(chmod(p2, 0644) == 0);
    }

    /* ---------------- 4. the directory listing ---------------- */

    (void)snprintf(p1, sizeof(p1), "%s/sub", jail);
    S3_ASSERT(mkdir(p1, 0755) == 0);

    (void)snprintf(p2, sizeof(p2), "%s/sub/alpha", jail);
    S3_ASSERT(s3_test_write_file(p2, "a") == 0);
    (void)snprintf(p2, sizeof(p2), "%s/sub/beta", jail);
    S3_ASSERT(s3_test_write_file(p2, "bb") == 0);
    (void)snprintf(p2, sizeof(p2), "%s/sub/gamma", jail);
    S3_ASSERT(s3_test_write_file(p2, "ccc") == 0);

    id++;
    n = S3_TEST_BUILD(s3_ssh3_sftp_encode_opendir, req, id, &s_sub);
    s3_test_expect_handle(&srv, req, n, id, hd, &pkt);
    h = s3_test_handle_at(hd);

    id++;
    n = S3_TEST_BUILD(s3_ssh3_sftp_encode_readdir, req, id, &h);
    s3_test_rpc(&srv, req, n, id, S3_SSH3_SFTP_NAME, &pkt);
    S3_ASSERT(s3_test_names_of(&pkt, 3, names, lnames, entry_attrs) == 0);
    S3_ASSERT(s3_test_name_in(names, 3, "alpha"));
    S3_ASSERT(s3_test_name_in(names, 3, "beta"));
    S3_ASSERT(s3_test_name_in(names, 3, "gamma"));

    for (i = 0; i < 3; i++) {
        S3_ASSERT(entry_attrs[i].flags ==
                  (S3_SSH3_SFTP_ATTR_SIZE | S3_SSH3_SFTP_ATTR_UIDGID |
                   S3_SSH3_SFTP_ATTR_PERMISSION | S3_SSH3_SFTP_ATTR_ACMODTIME));
    }

    /* the drained handle answers EOF */

    id++;
    n = S3_TEST_BUILD(s3_ssh3_sftp_encode_readdir, req, id, &h);
    s3_test_expect_status(&srv, req, n, id, S3_SSH3_SFTP_FX_EOF, &pkt);

    id++;
    n = S3_TEST_BUILD(s3_ssh3_sftp_encode_close, req, id, &h);
    s3_test_expect_status(&srv, req, n, id, S3_SSH3_SFTP_FX_OK, &pkt);

    /* ---------------- 5. the nested mkdir ---------------- */

    id++;
    n = S3_TEST_BUILD(s3_ssh3_sftp_encode_mkdir, req, id, &s_deep, &zero);
    s3_test_expect_status(&srv, req, n, id, S3_SSH3_SFTP_FX_OK, &pkt);

    (void)snprintf(p1, sizeof(p1), "%s/deep/a/b", jail);
    S3_ASSERT(stat(p1, &st) == 0);
    S3_ASSERT(S_ISDIR(st.st_mode));
    S3_ASSERT(st.st_uid == getuid());

    /* the existing target is a failure */

    id++;
    n = S3_TEST_BUILD(s3_ssh3_sftp_encode_mkdir, req, id, &s_deep, &zero);
    s3_test_expect_status(&srv, req, n, id, S3_SSH3_SFTP_FX_FAILURE, &pkt);

    /* ---------------- 6. the rename ---------------- */

    (void)snprintf(p1, sizeof(p1), "%s/moveme", jail);
    S3_ASSERT(s3_test_write_file(p1, "x") == 0);
    (void)snprintf(p2, sizeof(p2), "%s/moved", jail);

    id++;
    n = S3_TEST_BUILD(s3_ssh3_sftp_encode_rename, req, id, &s_moveme, &s_moved);
    s3_test_expect_status(&srv, req, n, id, S3_SSH3_SFTP_FX_OK, &pkt);

    S3_ASSERT(stat(p1, &st) != 0 && errno == ENOENT);
    S3_ASSERT(stat(p2, &st) == 0);

    /* the existing target of the reference is os.ErrExist: failure */

    id++;
    n = S3_TEST_BUILD(s3_ssh3_sftp_encode_rename, req, id, &s_moved, &s_hello);
    s3_test_expect_status(&srv, req, n, id, S3_SSH3_SFTP_FX_FAILURE, &pkt);

    S3_ASSERT(stat(p2, &st) == 0);

    /* ---------------- 7. the stat and the lstat ---------------- */

    id++;
    n = S3_TEST_BUILD(s3_ssh3_sftp_encode_stat, req, id, &s_hello);
    s3_test_rpc(&srv, req, n, id, S3_SSH3_SFTP_ATTRS, &pkt);
    S3_ASSERT(s3_test_attrs_of(&pkt, &ra) == 0);
    S3_ASSERT(ra.flags == (S3_SSH3_SFTP_ATTR_SIZE | S3_SSH3_SFTP_ATTR_UIDGID |
                           S3_SSH3_SFTP_ATTR_PERMISSION | S3_SSH3_SFTP_ATTR_ACMODTIME));
    S3_ASSERT(ra.size == 11);
    S3_ASSERT(S_ISREG((mode_t)ra.perms));
    S3_ASSERT((ra.perms & 0777) == (0644 & ~um));
    S3_ASSERT(ra.uid == (uint32_t)getuid());
    S3_ASSERT(ra.gid == (uint32_t)getgid());

    /* the lstat of the missing file, the absolute in-jail spelling */

    (void)snprintf(exp, sizeof(exp), "%s/missing", jail);
    blen = s3_test_str_body(body, exp);
    id++;
    n = s3_test_frame(req, S3_SSH3_SFTP_LSTAT, id, body, blen);
    s3_test_expect_status(&srv, req, n, id, S3_SSH3_SFTP_FX_NO_SUCH_FILE, &pkt);

    /* ---------------- 8. the unsupported operations ---------------- */

    /* the setstat body: the path plus a flagless attribute block */

    blen = s3_test_str_body(body, "hello.txt");
    body[blen++] = 0;
    body[blen++] = 0;
    body[blen++] = 0;
    body[blen++] = 0;

    id++;
    n = s3_test_frame(req, S3_SSH3_SFTP_SETSTAT, id, body, blen);
    s3_test_expect_status(&srv, req, n, id, S3_SSH3_SFTP_FX_OP_UNSUPPORTED, &pkt);

    /* the timestamp form applies the source mtime, the R7 stamp of
     * the recursive-transfer client; the atime rides along like in
     * the reference Chtimes */

    ts = (uint32_t)time(NULL) - 7200;

    s3_memzero(&tsa, sizeof(tsa));
    tsa.flags = S3_SSH3_SFTP_ATTR_ACMODTIME;
    tsa.atime = ts;
    tsa.mtime = ts;

    id++;
    n = S3_TEST_BUILD(s3_ssh3_sftp_encode_setstat, req, id, &s_hello, &tsa);
    s3_test_expect_status(&srv, req, n, id, S3_SSH3_SFTP_FX_OK, &pkt);

    id++;
    n = S3_TEST_BUILD(s3_ssh3_sftp_encode_stat, req, id, &s_hello);
    s3_test_rpc(&srv, req, n, id, S3_SSH3_SFTP_ATTRS, &pkt);
    S3_ASSERT(s3_test_attrs_of(&pkt, &ra) == 0);
    S3_ASSERT(ra.mtime == ts);
    S3_ASSERT(ra.atime == ts);

    /* the times-only request dies on a missing path like the reference */

    tsa.mtime = (uint32_t)time(NULL);

    id++;
    n = S3_TEST_BUILD(s3_ssh3_sftp_encode_setstat, req, id, &s_missing, &tsa);
    s3_test_expect_status(&srv, req, n, id, S3_SSH3_SFTP_FX_NO_SUCH_FILE, &pkt);

    /* the unknown type dies as unsupported, the channel lives */

    id++;
    n = s3_test_frame(req, 250, id, NULL, 0);
    s3_test_expect_status(&srv, req, n, id, S3_SSH3_SFTP_FX_OP_UNSUPPORTED, &pkt);

    id++;
    n = S3_TEST_BUILD(s3_ssh3_sftp_encode_realpath, req, id, &s_dot);
    s3_test_rpc(&srv, req, n, id, S3_SSH3_SFTP_NAME, &pkt);
    S3_ASSERT(s3_test_name1_of(&pkt, &path) == 0);
    S3_ASSERT(s3_test_str_is(&path, jail));

    /* ---------------- 10. the remove and the rmdir ---------------- */

    (void)snprintf(p1, sizeof(p1), "%s/gone.txt", jail);
    S3_ASSERT(s3_test_write_file(p1, "bye") == 0);

    id++;
    n = S3_TEST_BUILD(s3_ssh3_sftp_encode_remove, req, id, &s_gone);
    s3_test_expect_status(&srv, req, n, id, S3_SSH3_SFTP_FX_OK, &pkt);
    S3_ASSERT(stat(p1, &st) != 0 && errno == ENOENT);

    id++;
    n = S3_TEST_BUILD(s3_ssh3_sftp_encode_remove, req, id, &s_missing);
    s3_test_expect_status(&srv, req, n, id, S3_SSH3_SFTP_FX_NO_SUCH_FILE, &pkt);

    /* the non-empty directory stays */

    id++;
    n = S3_TEST_BUILD(s3_ssh3_sftp_encode_rmdir, req, id, &s_deepdir);
    s3_test_expect_status(&srv, req, n, id, S3_SSH3_SFTP_FX_FAILURE, &pkt);

    id++;
    n = S3_TEST_BUILD(s3_ssh3_sftp_encode_mkdir, req, id, &s_emptydir, &zero);
    s3_test_expect_status(&srv, req, n, id, S3_SSH3_SFTP_FX_OK, &pkt);

    id++;
    n = S3_TEST_BUILD(s3_ssh3_sftp_encode_rmdir, req, id, &s_emptydir);
    s3_test_expect_status(&srv, req, n, id, S3_SSH3_SFTP_FX_OK, &pkt);

    (void)snprintf(p1, sizeof(p1), "%s/emptydir", jail);
    S3_ASSERT(stat(p1, &st) != 0 && errno == ENOENT);

    /* ---------------- 13. the unknown handle ---------------- */

    body[0] = 0xAA;
    body[1] = 0xAA;
    body[2] = 0xAA;
    body[3] = 0xAA;
    body[4] = 0xAA;
    body[5] = 0xAA;
    body[6] = 0xAA;
    body[7] = 0xAA;
    h.data = body;
    h.len = 8;

    id++;
    n = S3_TEST_BUILD(s3_ssh3_sftp_encode_close, req, id, &h);
    s3_test_expect_status(&srv, req, n, id, S3_SSH3_SFTP_FX_NO_SUCH_FILE, &pkt);

    id++;
    n = S3_TEST_BUILD(s3_ssh3_sftp_encode_read, req, id, &h, 0, 16);
    s3_test_expect_status(&srv, req, n, id, S3_SSH3_SFTP_FX_NO_SUCH_FILE, &pkt);

    /* ---------------- 11. the pre-INIT gate on a fresh server ---------------- */

    S3_ASSERT(s3_test_make_srv(&srv2, pool, jail) == S3_OK);

    blen = s3_test_str_body(body, "hello.txt");
    id++;
    n = s3_test_frame(req, S3_SSH3_SFTP_STAT, id, body, blen);
    s3_test_expect_status(&srv2, req, n, id, S3_SSH3_SFTP_FX_BAD_MESSAGE, &pkt);

    /* the INIT still goes through, the channel lives */

    n = S3_TEST_BUILD(s3_ssh3_sftp_encode_init, req, 3);
    S3_ASSERT(s3_ssh3_sftp_srv_input(&srv2, req, n) == S3_OK);
    rlen = s3_test_collect(&srv2, s3_test_rep, sizeof(s3_test_rep));
    S3_ASSERT(rlen > 0);
    S3_ASSERT(s3_test_reply(s3_test_rep, rlen, &pkt) == 0);
    S3_ASSERT(pkt.type == S3_SSH3_SFTP_VERSION);

    /* the crooked body of a valid frame is a status, not a teardown */

    id++;
    body[0] = 0x00;
    body[1] = 0x00;
    body[2] = 0x00;
    body[3] = 0x0A;
    n = s3_test_frame(req, S3_SSH3_SFTP_OPEN, id, body, 4);
    s3_test_expect_status(&srv2, req, n, id, S3_SSH3_SFTP_FX_BAD_MESSAGE, &pkt);

    id++;
    n = S3_TEST_BUILD(s3_ssh3_sftp_encode_realpath, req, id, &s_hello);
    s3_test_rpc(&srv2, req, n, id, S3_SSH3_SFTP_NAME, &pkt);
    S3_ASSERT(s3_test_name1_of(&pkt, &path) == 0);
    (void)snprintf(exp, sizeof(exp), "%s/hello.txt", jail);
    S3_ASSERT(s3_test_str_is(&path, exp));

    /* two requests in one chunk: the tail loop pulls both frames */

    n = S3_TEST_BUILD(s3_ssh3_sftp_encode_realpath, req, id + 1, &s_dot);

    blen = s3_test_str_body(body, "hello.txt");
    S3_ASSERT(9 + blen <= sizeof(req) - n);
    (void)s3_test_frame(req + n, S3_SSH3_SFTP_STAT, id + 2, body, blen);

    S3_ASSERT(s3_ssh3_sftp_srv_input(&srv2, req, n + 9 + blen) == S3_OK);
    rlen = s3_test_collect(&srv2, s3_test_rep, sizeof(s3_test_rep));
    S3_ASSERT(rlen > 0);

    pos = s3_test_rep;
    end = s3_test_rep + rlen;
    S3_ASSERT(s3_ssh3_sftp_codec_frame(&pos, end, &pkt) == S3_OK);
    S3_ASSERT(pkt.type == S3_SSH3_SFTP_NAME);
    S3_ASSERT(pkt.request_id == id + 1);
    S3_ASSERT(s3_ssh3_sftp_codec_frame(&pos, end, &pkt) == S3_OK);
    S3_ASSERT(pkt.type == S3_SSH3_SFTP_ATTRS);
    S3_ASSERT(pkt.request_id == id + 2);
    S3_ASSERT(pos == end);

    /* ---------------- 9. the hostile length prefix ---------------- */

    S3_ASSERT(s3_test_make_srv(&srv3, pool, jail) == S3_OK);

    /* the 1 MiB length prefix, above the wire cap */

    req[0] = 0x00;
    req[1] = 0x10;
    req[2] = 0x00;
    req[3] = 0x00;

    S3_ASSERT(s3_ssh3_sftp_srv_input(&srv3, req, 4) == S3_OK);
    S3_ASSERT(s3_ssh3_sftp_srv_protocol_error(&srv3) == 1);

    /* the input after the verdict tears down */

    S3_ASSERT(s3_ssh3_sftp_srv_input(&srv3, req, 4) == S3_ERROR);
    S3_ASSERT(s3_ssh3_sftp_srv_protocol_error(&srv3) == 1);

    /* ---------------- 10. the root jail of the chroot child ---------------- */

    /*
     * the chroot child serves home "/" (the F-04, the sshd model):
     * the kernel is the confinement, so every absolute spelling
     * lands inside and nothing is denied on the wire (the reference
     * withinRoot of the same commit)
     */

    {
        s3_ssh3_sftp_srv_t srv_root;
        s3_str_t           s_rfile, s_outside;

        S3_ASSERT(s3_test_make_srv(&srv_root, pool, "/") == S3_OK);

        n = S3_TEST_BUILD(s3_ssh3_sftp_encode_init, req, 3);
        S3_ASSERT(s3_ssh3_sftp_srv_input(&srv_root, req, n) == S3_OK);
        S3_ASSERT(s3_test_collect(&srv_root, s3_test_rep, sizeof(s3_test_rep)) > 0);

        (void)snprintf(p1, sizeof(p1), "%s/rf.txt", jail);
        S3_ASSERT(s3_test_write_file(p1, "rootjail\n") == 0);

        /* the absolute spelling outside the old home shape still
           opens: the root jail carries it */

        (void)snprintf(exp, sizeof(exp), "%s/rf.txt", jail);

        s_rfile = s3_test_str(exp);

        id++;
        n = S3_TEST_BUILD(s3_ssh3_sftp_encode_open, req, id, &s_rfile, S3_SSH3_SFTP_FXF_READ,
                          &zero);
        s3_test_expect_handle(&srv_root, req, n, id, hp, &pkt);
        h = s3_test_handle_at(hp);

        id++;
        n = S3_TEST_BUILD(s3_ssh3_sftp_encode_read, req, id, &h, 0, 4096);
        s3_test_rpc(&srv_root, req, n, id, S3_SSH3_SFTP_DATA, &pkt);
        S3_ASSERT(s3_test_data_of(&pkt, &data) == 0);
        S3_ASSERT(s3_test_str_is(&data, "rootjail\n"));

        id++;
        n = S3_TEST_BUILD(s3_ssh3_sftp_encode_close, req, id, &h);
        s3_test_expect_status(&srv_root, req, n, id, S3_SSH3_SFTP_FX_OK, &pkt);

        /* the .. walk is a plain mapping here, no wire denial: the
           kernel confines the child, the lexical check is done */

        s_outside = s3_test_str("../outside");

        id++;
        n = S3_TEST_BUILD(s3_ssh3_sftp_encode_realpath, req, id, &s_outside);
        s3_test_rpc(&srv_root, req, n, id, S3_SSH3_SFTP_NAME, &pkt);
        S3_ASSERT(s3_test_name1_of(&pkt, &path) == 0);
        S3_ASSERT(s3_test_str_is(&path, "/outside"));
    }

    /* ---------------- the cleanup ---------------- */

    s3_test_rmrec(jail, sizeof(jail));
    s3_destroy_pool(pool);

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_sftp_srv)
