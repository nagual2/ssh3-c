/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the client SFTP driver against the canned in-memory server: the
 * fake server parses the drained requests through the codec and
 * answers from an in-memory table of the files, the loopback round
 * trip is synchronous; the scenarios pin the round trips of put and
 * get, the resume, the checksum verification, the recursive walks
 * and the protocol pins of the one-request pipeline
 */

#include <s3_core.h>

#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

#include <s3_ssh3_sftp_cli.h>
#include <s3_ssh3_sftp_codec.h>

#include "s3_test.h"

/* the in-memory table limits of the fake server */

#define S3_TEST_MAX_NODES   64
#define S3_TEST_MAX_HANDLES 16
#define S3_TEST_NAME_MAX    256

#define S3_TEST_BIG_LEN (100 * 1024)

/* the payload offset the corruption test flips, inside chunk two */

#define S3_TEST_CORRUPT_AT 50000

typedef struct {
    char    name[S3_TEST_NAME_MAX];
    u_char *data;
    size_t  len;
    size_t  cap;
    int     is_dir;
} s3_test_node_t;

typedef struct {
    char id[16];
    int  used;
    int  node;
    int  is_dir;
    int  listed; /* the READDIR batch already served */
} s3_test_handle_t;

typedef struct {
    s3_test_node_t   nodes[S3_TEST_MAX_NODES];
    int              node_count;
    s3_test_handle_t handles[S3_TEST_MAX_HANDLES];
    long             corrupt; /* the WRITE byte to flip, -1 off */
} s3_test_fs_t;

typedef struct {
    unsigned calls;
    uint64_t sent;
    uint64_t total;
} s3_test_progress_t;

static uint32_t
s3_test_next_rand(uint32_t *state)
{
    *state = *state * 1103515245u + 12345u;

    return *state >> 16;
}

static s3_pool_t *
s3_test_make_pool(s3_log_t *log)
{
    log->log_level = S3_LOG_ALERT;
    log->fd = S3_INVALID_FILE;

    return s3_create_pool(S3_DEFAULT_POOL_SIZE, log);
}

static void
s3_test_progress(void *arg, uint64_t sent, uint64_t total)
{
    s3_test_progress_t *p = arg;

    p->calls++;
    p->sent = sent;
    p->total = total;
}

static void
s3_test_write_local(const char *path, const u_char *data, size_t len)
{
    FILE *f;

    f = fopen(path, "wb");
    S3_ASSERT(f != NULL);
    S3_ASSERT(fwrite(data, 1, len, f) == len);
    S3_ASSERT(fclose(f) == 0);
}

static void
s3_test_read_local(const char *path, u_char *buf, size_t len)
{
    FILE *f;

    f = fopen(path, "rb");
    S3_ASSERT(f != NULL);
    S3_ASSERT(fread(buf, 1, len, f) == len);
    S3_ASSERT(fgetc(f) == EOF);
    S3_ASSERT(fclose(f) == 0);
}

static void
s3_test_rm_rf(const char *path)
{
    struct dirent *de;
    struct stat    st;
    DIR           *dir;
    char           child[512];

    if (lstat(path, &st) != 0) {
        return;
    }

    if (!S_ISDIR(st.st_mode)) {
        (void)unlink(path);
        return;
    }

    dir = opendir(path);

    if (dir != NULL) {

        while ((de = readdir(dir)) != NULL) {

            if (de->d_name[0] == '.' &&
                (de->d_name[1] == '\0' || (de->d_name[1] == '.' && de->d_name[2] == '\0'))) {
                continue;
            }

            snprintf(child, sizeof(child), "%s/%s", path, de->d_name);
            s3_test_rm_rf(child);
        }

        (void)closedir(dir);
    }

    (void)rmdir(path);
}

static s3_test_node_t *
s3_test_node_find(s3_test_fs_t *fs, const char *name)
{
    int i;

    for (i = 0; i < fs->node_count; i++) {

        if (strcmp(fs->nodes[i].name, name) == 0) {
            return &fs->nodes[i];
        }
    }

    return NULL;
}

static s3_test_node_t *
s3_test_node_add(s3_test_fs_t *fs, const char *name, int is_dir)
{
    s3_test_node_t *n;

    if (fs->node_count >= S3_TEST_MAX_NODES) {
        return NULL;
    }

    n = &fs->nodes[fs->node_count++];
    s3_memzero(n, sizeof(*n));
    n->is_dir = is_dir;
    snprintf(n->name, sizeof(n->name), "%s", name);

    return n;
}

static int
s3_test_node_write(s3_test_node_t *n, uint64_t off, const u_char *data, size_t len)
{
    u_char *p;
    size_t  cap;
    size_t  need = (size_t)(off + len);

    if (need > n->cap) {

        cap = n->cap ? n->cap : 4096;

        while (cap < need) {
            cap *= 2;
        }

        p = realloc(n->data, cap);

        if (p == NULL) {
            return -1;
        }

        n->data = p;
        n->cap = cap;
    }

    s3_memcpy(n->data + off, data, len);

    if (need > n->len) {
        n->len = need;
    }

    return 0;
}

/* the seed of the remote side: the file node with the given bytes */

static s3_test_node_t *
s3_test_fs_seed(s3_test_fs_t *fs, const char *name, const u_char *data, size_t len)
{
    s3_test_node_t *n;

    n = s3_test_node_add(fs, name, 0);

    if (n == NULL || s3_test_node_write(n, 0, data, len) != 0) {
        return NULL;
    }

    return n;
}

/* releases the node payloads of the fake filesystem (the leak check
 * of the sanitizer runs counts every byte the tests allocated) */

static void
s3_test_fs_free(s3_test_fs_t *fs)
{
    int i;

    for (i = 0; i < fs->node_count; i++) {
        free(fs->nodes[i].data);
        fs->nodes[i].data = NULL;
        fs->nodes[i].len = 0;
        fs->nodes[i].cap = 0;
    }
}

static s3_test_handle_t *
s3_test_handle_open(s3_test_fs_t *fs, int node, int is_dir)
{
    s3_test_handle_t *h;
    int               i;

    for (i = 0; i < S3_TEST_MAX_HANDLES; i++) {

        if (!fs->handles[i].used) {
            break;
        }
    }

    if (i == S3_TEST_MAX_HANDLES) {
        return NULL;
    }

    h = &fs->handles[i];
    s3_memzero(h, sizeof(*h));
    h->used = 1;
    h->node = node;
    h->is_dir = is_dir;
    snprintf(h->id, sizeof(h->id), "h%d", i);

    return h;
}

static s3_test_handle_t *
s3_test_handle_find(s3_test_fs_t *fs, const s3_str_t *id)
{
    int i;

    for (i = 0; i < S3_TEST_MAX_HANDLES; i++) {

        if (fs->handles[i].used && strlen(fs->handles[i].id) == id->len &&
            s3_memcmp(fs->handles[i].id, id->data, id->len) == 0) {
            return &fs->handles[i];
        }
    }

    return NULL;
}

static void
s3_test_node_attrs(s3_ssh3_sftp_attrs_t *a, const s3_test_node_t *n)
{
    s3_memzero(a, sizeof(*a));

    a->flags = S3_SSH3_SFTP_ATTR_SIZE | S3_SSH3_SFTP_ATTR_PERMISSION;
    a->size = n->len;
    a->perms = n->is_dir ? 040755 : 0100644;
}

static u_char *
s3_test_srv_status(u_char *w, uint32_t id, uint32_t code)
{
    s3_str_t msg = s3_string("");

    return (u_char *)s3_ssh3_sftp_encode_status(w, id, code, &msg);
}

/* the parsed path lands NUL-terminated into a bounded stack buffer */

static int
s3_test_path_copy(const s3_str_t *s, char *out, size_t cap)
{
    if (s->len >= cap) {
        return -1;
    }

    s3_memcpy(out, s->data, s->len);
    out[s->len] = '\0';

    return 0;
}

static int
s3_test_child_of(const char *dir, const char *name)
{
    size_t dl = strlen(dir);

    if (strncmp(name, dir, dl) != 0 || name[dl] != '/') {
        return 0;
    }

    return strchr(name + dl + 1, '/') == NULL;
}

static u_char *
s3_test_srv_reply(s3_test_fs_t *fs, s3_ssh3_sftp_pkt_t *pkt, u_char *w)
{
    s3_ssh3_sftp_attrs_t attrs;
    s3_ssh3_sftp_name_t  names[S3_TEST_MAX_NODES];
    s3_test_handle_t    *h;
    s3_test_node_t      *n;
    s3_str_t             path, handle, data;
    char                 path_buf[S3_TEST_NAME_MAX];
    const char          *base;
    uint32_t             pflags, len, count, i;
    uint64_t             offset;
    size_t               avail;

    switch (pkt->type) {

    case S3_SSH3_SFTP_INIT:
        return (u_char *)s3_ssh3_sftp_encode_version(w, S3_SSH3_SFTP_PROTOCOL_VERSION);

    case S3_SSH3_SFTP_STAT:

        if (s3_ssh3_sftp_parse_path_body(&pkt->body, &path) != S3_OK ||
            s3_test_path_copy(&path, path_buf, sizeof(path_buf)) != 0) {
            S3_ASSERT(!"broken STAT");
            return w;
        }

        n = s3_test_node_find(fs, path_buf);

        if (n == NULL) {
            return s3_test_srv_status(w, pkt->request_id, S3_SSH3_SFTP_FX_NO_SUCH_FILE);
        }

        s3_test_node_attrs(&attrs, n);

        return (u_char *)s3_ssh3_sftp_encode_attrs(w, pkt->request_id, &attrs);

    case S3_SSH3_SFTP_MKDIR: {
        const u_char *mp = pkt->body.data, *mend = pkt->body.data + pkt->body.len;

        /* the mkdir body rides the path and the attribute block */

        if (s3_ssh3_sftp_parse_string(&mp, mend, &path) != S3_OK ||
            s3_ssh3_sftp_parse_attrs(&mp, mend, &attrs) != S3_OK || mp != mend ||
            s3_test_path_copy(&path, path_buf, sizeof(path_buf)) != 0) {
            S3_ASSERT(!"broken MKDIR");
            return w;
        }

        if (s3_test_node_find(fs, path_buf) != NULL) {
            return s3_test_srv_status(w, pkt->request_id, S3_SSH3_SFTP_FX_FAILURE);
        }

        if (s3_test_node_add(fs, path_buf, 1) == NULL) {
            return s3_test_srv_status(w, pkt->request_id, S3_SSH3_SFTP_FX_FAILURE);
        }

        return s3_test_srv_status(w, pkt->request_id, S3_SSH3_SFTP_FX_OK);
    }

    case S3_SSH3_SFTP_OPENDIR:

        if (s3_ssh3_sftp_parse_path_body(&pkt->body, &path) != S3_OK ||
            s3_test_path_copy(&path, path_buf, sizeof(path_buf)) != 0) {
            S3_ASSERT(!"broken OPENDIR");
            return w;
        }

        n = s3_test_node_find(fs, path_buf);

        if (n == NULL || !n->is_dir) {
            return s3_test_srv_status(w, pkt->request_id, S3_SSH3_SFTP_FX_NO_SUCH_FILE);
        }

        h = s3_test_handle_open(fs, (int)(n - fs->nodes), 1);

        if (h == NULL) {
            return s3_test_srv_status(w, pkt->request_id, S3_SSH3_SFTP_FX_FAILURE);
        }

        handle.len = strlen(h->id);
        handle.data = (u_char *)h->id;

        return (u_char *)s3_ssh3_sftp_encode_handle(w, pkt->request_id, &handle);

    case S3_SSH3_SFTP_OPEN:

        if (s3_ssh3_sftp_parse_open_body(&pkt->body, &path, &pflags, &attrs) != S3_OK ||
            s3_test_path_copy(&path, path_buf, sizeof(path_buf)) != 0) {
            S3_ASSERT(!"broken OPEN");
            return w;
        }

        n = s3_test_node_find(fs, path_buf);

        if (pflags & S3_SSH3_SFTP_FXF_WRITE) {

            if (n == NULL) {
                n = s3_test_node_add(fs, path_buf, 0);
            }

            if (n == NULL || n->is_dir) {
                return s3_test_srv_status(w, pkt->request_id, S3_SSH3_SFTP_FX_FAILURE);
            }

            if (pflags & S3_SSH3_SFTP_FXF_TRUNC) {
                n->len = 0;
            }

        } else {

            if (n == NULL || n->is_dir) {
                return s3_test_srv_status(w, pkt->request_id, S3_SSH3_SFTP_FX_NO_SUCH_FILE);
            }
        }

        h = s3_test_handle_open(fs, (int)(n - fs->nodes), 0);

        if (h == NULL) {
            return s3_test_srv_status(w, pkt->request_id, S3_SSH3_SFTP_FX_FAILURE);
        }

        handle.len = strlen(h->id);
        handle.data = (u_char *)h->id;

        return (u_char *)s3_ssh3_sftp_encode_handle(w, pkt->request_id, &handle);

    case S3_SSH3_SFTP_CLOSE:

        if (s3_ssh3_sftp_parse_handle_body(&pkt->body, &handle) != S3_OK) {
            S3_ASSERT(!"broken CLOSE");
            return w;
        }

        h = s3_test_handle_find(fs, &handle);

        if (h == NULL) {
            return s3_test_srv_status(w, pkt->request_id, S3_SSH3_SFTP_FX_FAILURE);
        }

        h->used = 0;

        return s3_test_srv_status(w, pkt->request_id, S3_SSH3_SFTP_FX_OK);

    case S3_SSH3_SFTP_READ:

        if (s3_ssh3_sftp_parse_read_body(&pkt->body, &handle, &offset, &len) != S3_OK) {
            S3_ASSERT(!"broken READ");
            return w;
        }

        h = s3_test_handle_find(fs, &handle);

        if (h == NULL || h->is_dir || h->node < 0) {
            return s3_test_srv_status(w, pkt->request_id, S3_SSH3_SFTP_FX_FAILURE);
        }

        n = &fs->nodes[h->node];

        if (offset >= n->len) {
            count = 0;

        } else {
            avail = n->len - (size_t)offset;
            count = avail < (size_t)len ? (uint32_t)avail : len;
        }

        data.len = count;
        data.data = n->data + offset;

        return (u_char *)s3_ssh3_sftp_encode_data(w, pkt->request_id, &data);

    case S3_SSH3_SFTP_WRITE:

        if (s3_ssh3_sftp_parse_write_body(&pkt->body, &handle, &offset, &data) != S3_OK) {
            S3_ASSERT(!"broken WRITE");
            return w;
        }

        h = s3_test_handle_find(fs, &handle);

        if (h == NULL || h->is_dir || h->node < 0) {
            return s3_test_srv_status(w, pkt->request_id, S3_SSH3_SFTP_FX_FAILURE);
        }

        n = &fs->nodes[h->node];

        if (s3_test_node_write(n, offset, data.data, data.len) != 0) {
            return s3_test_srv_status(w, pkt->request_id, S3_SSH3_SFTP_FX_FAILURE);
        }

        /* the corruption hook of the verification scenario */

        if (fs->corrupt >= 0 && (uint64_t)fs->corrupt >= offset &&
            (uint64_t)fs->corrupt < offset + data.len) {
            n->data[fs->corrupt] ^= 0xff;
        }

        return s3_test_srv_status(w, pkt->request_id, S3_SSH3_SFTP_FX_OK);

    case S3_SSH3_SFTP_READDIR:

        if (s3_ssh3_sftp_parse_handle_body(&pkt->body, &handle) != S3_OK) {
            S3_ASSERT(!"broken READDIR");
            return w;
        }

        h = s3_test_handle_find(fs, &handle);

        if (h == NULL || !h->is_dir || h->node < 0) {
            return s3_test_srv_status(w, pkt->request_id, S3_SSH3_SFTP_FX_FAILURE);
        }

        if (h->listed) {
            return s3_test_srv_status(w, pkt->request_id, S3_SSH3_SFTP_FX_EOF);
        }

        count = 0;

        for (i = 0; (int)i < fs->node_count; i++) {

            n = &fs->nodes[i];

            if (!s3_test_child_of(fs->nodes[h->node].name, n->name)) {
                continue;
            }

            base = strrchr(n->name, '/') + 1;

            names[count].filename.len = strlen(base);
            names[count].filename.data = (u_char *)base;
            names[count].longname.len = 0;
            names[count].longname.data = (u_char *)"";

            s3_test_node_attrs(&names[count].attrs, n);
            count++;
        }

        h->listed = 1;

        return (u_char *)s3_ssh3_sftp_encode_name(w, pkt->request_id, names, count);

    default:
        S3_ASSERT(!"the fake server got an unexpected packet type");
        return w;
    }
}

/* the fake server drains the requests and builds the reply batch */

static void
s3_test_srv_feed(s3_test_fs_t *fs, const u_char *data, size_t len, u_char *out, size_t *out_len)
{
    s3_ssh3_sftp_pkt_t pkt;
    const u_char      *p = data, *end = data + len;
    u_char            *w = out;

    while (p < end) {

        if (s3_ssh3_sftp_codec_frame(&p, end, &pkt) != S3_OK) {
            S3_ASSERT(!"the fake server got a broken frame");
            break;
        }

        w = s3_test_srv_reply(fs, &pkt, w);
    }

    *out_len = (size_t)(w - out);
}

/*
 * the loopback: the requests drain to the fake server, the replies
 * ride in, until the operation leaves the RUN state
 */

static void
s3_test_cli_run(s3_test_fs_t *fs, s3_ssh3_sftp_cli_t *cli)
{
    u_char  req[65536];
    u_char  rep[65536];
    size_t  rep_len;
    ssize_t n;

    rep_len = 0;

    while (!s3_ssh3_sftp_cli_finished(cli)) {

        n = s3_ssh3_sftp_cli_output(cli, req, sizeof(req));

        if (n > 0) {
            s3_test_srv_feed(fs, req, (size_t)n, rep, &rep_len);
        }

        if (rep_len > 0) {
            S3_ASSERT(s3_ssh3_sftp_cli_input(cli, rep, rep_len) == S3_OK);
            rep_len = 0;
            continue;
        }

        S3_ASSERT(!"the driver stalled with no request in flight");
        break;
    }
}

static void
s3_test_fill(u_char *buf, size_t len, uint32_t seed)
{
    size_t i;

    for (i = 0; i < len; i++) {
        buf[i] = (u_char)(s3_test_next_rand(&seed) & 0xff);
    }
}

/*
 * the init pins, the immediate local failures (the missing local
 * file, the -r over a plain file) and the BUSY of the running op
 */

static int
s3_test_cli_lifecycle(void)
{
    s3_log_t           log;
    s3_pool_t         *pool;
    s3_ssh3_sftp_cli_t cli;
    s3_test_fs_t       fs;
    char               dir[64], local[128];
    u_char             small[64];

    s3_test_fill(small, sizeof(small), 7);

    pool = s3_test_make_pool(&log);
    S3_ASSERT(pool != NULL);

    s3_memzero(&fs, sizeof(fs));
    fs.corrupt = -1;

    S3_ASSERT(s3_ssh3_sftp_cli_init(&cli, pool, NULL, NULL) == S3_OK);
    S3_ASSERT(cli.state == S3_SSH3_SFTP_CLI_IDLE);
    S3_ASSERT(cli.next_id == 0);
    S3_ASSERT(cli.pend == NULL && cli.pend_len == 0 && cli.pend_cap == 0);
    S3_ASSERT(cli.out == NULL && cli.out_len == 0 && cli.out_cap == 0);
    S3_ASSERT(cli.op == NULL);
    S3_ASSERT(s3_ssh3_sftp_cli_finished(&cli) == 0);
    S3_ASSERT(s3_ssh3_sftp_cli_status(&cli) == S3_SSH3_SFTP_FX_OK);

    /* the NULL operands decline */

    S3_ASSERT(s3_ssh3_sftp_cli_put(&cli, NULL, "/x", 0, 0) == S3_ERROR);
    S3_ASSERT(s3_ssh3_sftp_cli_put(&cli, local, NULL, 0, 0) == S3_ERROR);

    snprintf(dir, sizeof(dir), "/tmp/s3sftpcliXXXXXX");
    S3_ASSERT(mkdtemp(dir) != NULL);
    snprintf(local, sizeof(local), "%s/absent.bin", dir);

    /* the missing local file fails immediately, before the wire */

    S3_ASSERT(s3_ssh3_sftp_cli_put(&cli, local, "/absent.bin", 0, 0) == S3_ERROR);
    S3_ASSERT(cli.state == S3_SSH3_SFTP_CLI_FAIL);
    S3_ASSERT(s3_ssh3_sftp_cli_finished(&cli) == 1);
    S3_ASSERT(s3_ssh3_sftp_cli_status(&cli) == S3_SSH3_SFTP_FX_FAILURE);

    /* the -r over a plain file is the walk that cannot start */

    snprintf(local, sizeof(local), "%s/plain.bin", dir);
    s3_test_write_local(local, small, sizeof(small));

    S3_ASSERT(s3_ssh3_sftp_cli_init(&cli, pool, NULL, NULL) == S3_OK);
    S3_ASSERT(s3_ssh3_sftp_cli_put_r(&cli, local, "/tree", 0, 0) == S3_ERROR);
    S3_ASSERT(cli.state == S3_SSH3_SFTP_CLI_FAIL);
    S3_ASSERT(s3_ssh3_sftp_cli_status(&cli) == S3_SSH3_SFTP_FX_FAILURE);

    /* the running op refuses the second one */

    S3_ASSERT(s3_ssh3_sftp_cli_init(&cli, pool, NULL, NULL) == S3_OK);
    S3_ASSERT(s3_ssh3_sftp_cli_get(&cli, "/whatever", local, 0, 0) == S3_OK);
    S3_ASSERT(cli.state == S3_SSH3_SFTP_CLI_RUN);
    S3_ASSERT(s3_ssh3_sftp_cli_get(&cli, "/other", local, 0, 0) == S3_BUSY);
    S3_ASSERT(s3_ssh3_sftp_cli_put(&cli, local, "/other", 0, 0) == S3_BUSY);

    s3_test_fs_free(&fs);
    s3_test_rm_rf(dir);

    s3_destroy_pool(pool);

    return s3_test_failures;
}

/* the upload round trip: 100 KiB of random bytes through the chunks */

static int
s3_test_cli_put_roundtrip(void)
{
    s3_log_t           log;
    s3_pool_t         *pool;
    s3_ssh3_sftp_cli_t cli;
    s3_test_fs_t       fs;
    s3_test_progress_t prog;
    u_char             data[S3_TEST_BIG_LEN], back[S3_TEST_BIG_LEN];
    char               dir[64], local[160], local2[160];
    s3_test_node_t    *n;

    s3_test_fill(data, sizeof(data), 42);

    pool = s3_test_make_pool(&log);
    S3_ASSERT(pool != NULL);

    s3_memzero(&fs, sizeof(fs));
    fs.corrupt = -1;
    s3_memzero(&prog, sizeof(prog));

    S3_ASSERT(s3_ssh3_sftp_cli_init(&cli, pool, s3_test_progress, &prog) == S3_OK);

    snprintf(dir, sizeof(dir), "/tmp/s3sftpcliXXXXXX");
    S3_ASSERT(mkdtemp(dir) != NULL);
    snprintf(local, sizeof(local), "%s/big.bin", dir);
    s3_test_write_local(local, data, sizeof(data));

    S3_ASSERT(s3_ssh3_sftp_cli_put(&cli, local, "/big.bin", 0, 0) == S3_OK);
    S3_ASSERT(cli.state == S3_SSH3_SFTP_CLI_RUN);

    s3_test_cli_run(&fs, &cli);

    S3_ASSERT(cli.state == S3_SSH3_SFTP_CLI_DONE);
    S3_ASSERT(s3_ssh3_sftp_cli_finished(&cli) == 1);
    S3_ASSERT(s3_ssh3_sftp_cli_status(&cli) == S3_SSH3_SFTP_FX_OK);

    /* nothing waits in the out buffer after the verdict */

    S3_ASSERT(s3_ssh3_sftp_cli_output(&cli, back, 1) == 0);

    n = s3_test_node_find(&fs, "/big.bin");
    S3_ASSERT(n != NULL);
    S3_ASSERT(n->len == sizeof(data));
    S3_ASSERT(n->data != NULL && s3_memcmp(n->data, data, sizeof(data)) == 0);

    /* the progress rode every WRITE ack to the total */

    S3_ASSERT(prog.calls > 0);
    S3_ASSERT(prog.total == sizeof(data));
    S3_ASSERT(prog.sent == sizeof(data));

    /* the finished driver resets: the same instance downloads back */

    snprintf(local2, sizeof(local2), "%s/back.bin", dir);

    S3_ASSERT(s3_ssh3_sftp_cli_get(&cli, "/big.bin", local2, 0, 0) == S3_OK);

    s3_test_cli_run(&fs, &cli);

    S3_ASSERT(cli.state == S3_SSH3_SFTP_CLI_DONE);
    S3_ASSERT(s3_ssh3_sftp_cli_status(&cli) == S3_SSH3_SFTP_FX_OK);

    s3_test_read_local(local2, back, sizeof(back));
    S3_ASSERT(s3_memcmp(back, data, sizeof(data)) == 0);

    s3_test_fs_free(&fs);
    s3_test_rm_rf(dir);

    s3_destroy_pool(pool);

    return s3_test_failures;
}

/* the download round trip: the remote bytes land exactly */

static int
s3_test_cli_get_roundtrip(void)
{
    s3_log_t           log;
    s3_pool_t         *pool;
    s3_ssh3_sftp_cli_t cli;
    s3_test_fs_t       fs;
    u_char             data[S3_TEST_BIG_LEN], back[S3_TEST_BIG_LEN];
    char               dir[64], local[160];

    s3_test_fill(data, sizeof(data), 99);

    pool = s3_test_make_pool(&log);
    S3_ASSERT(pool != NULL);

    s3_memzero(&fs, sizeof(fs));
    fs.corrupt = -1;

    S3_ASSERT(s3_test_fs_seed(&fs, "/get.bin", data, sizeof(data)) != NULL);

    S3_ASSERT(s3_ssh3_sftp_cli_init(&cli, pool, NULL, NULL) == S3_OK);

    snprintf(dir, sizeof(dir), "/tmp/s3sftpcliXXXXXX");
    S3_ASSERT(mkdtemp(dir) != NULL);
    snprintf(local, sizeof(local), "%s/out.bin", dir);

    S3_ASSERT(s3_ssh3_sftp_cli_get(&cli, "/get.bin", local, 0, 0) == S3_OK);
    S3_ASSERT(cli.state == S3_SSH3_SFTP_CLI_RUN);

    s3_test_cli_run(&fs, &cli);

    S3_ASSERT(cli.state == S3_SSH3_SFTP_CLI_DONE);
    S3_ASSERT(s3_ssh3_sftp_cli_status(&cli) == S3_SSH3_SFTP_FX_OK);

    s3_test_read_local(local, back, sizeof(back));
    S3_ASSERT(s3_memcmp(back, data, sizeof(data)) == 0);

    s3_test_fs_free(&fs);
    s3_test_rm_rf(dir);

    s3_destroy_pool(pool);

    return s3_test_failures;
}

/* the resume: the remote prefix of 60K continues from the offset */

static int
s3_test_cli_resume_put(void)
{
    s3_log_t           log;
    s3_pool_t         *pool;
    s3_ssh3_sftp_cli_t cli;
    s3_test_fs_t       fs;
    u_char             data[S3_TEST_BIG_LEN];
    char               dir[64], local[160];
    s3_test_node_t    *n;

    s3_test_fill(data, sizeof(data), 7);

    pool = s3_test_make_pool(&log);
    S3_ASSERT(pool != NULL);

    s3_memzero(&fs, sizeof(fs));
    fs.corrupt = -1;

    S3_ASSERT(s3_test_fs_seed(&fs, "/cont.bin", data, 60000) != NULL);

    S3_ASSERT(s3_ssh3_sftp_cli_init(&cli, pool, NULL, NULL) == S3_OK);

    snprintf(dir, sizeof(dir), "/tmp/s3sftpcliXXXXXX");
    S3_ASSERT(mkdtemp(dir) != NULL);
    snprintf(local, sizeof(local), "%s/cont.bin", dir);
    s3_test_write_local(local, data, sizeof(data));

    S3_ASSERT(s3_ssh3_sftp_cli_put(&cli, local, "/cont.bin", 1, 0) == S3_OK);

    s3_test_cli_run(&fs, &cli);

    S3_ASSERT(cli.state == S3_SSH3_SFTP_CLI_DONE);
    S3_ASSERT(s3_ssh3_sftp_cli_status(&cli) == S3_SSH3_SFTP_FX_OK);

    /* the tail appended from the offset, the total matches */

    n = s3_test_node_find(&fs, "/cont.bin");
    S3_ASSERT(n != NULL);
    S3_ASSERT(n->len == sizeof(data));
    S3_ASSERT(n->data != NULL && s3_memcmp(n->data, data, sizeof(data)) == 0);

    s3_test_fs_free(&fs);
    s3_test_rm_rf(dir);

    s3_destroy_pool(pool);

    return s3_test_failures;
}

/* the resume over the equal sizes skips the write, the verify tail only */

static int
s3_test_cli_resume_put_equal(void)
{
    s3_log_t           log;
    s3_pool_t         *pool;
    s3_ssh3_sftp_cli_t cli;
    s3_test_fs_t       fs;
    u_char             data[S3_TEST_BIG_LEN];
    char               dir[64], local[160];
    s3_test_node_t    *n;

    s3_test_fill(data, sizeof(data), 11);

    pool = s3_test_make_pool(&log);
    S3_ASSERT(pool != NULL);

    s3_memzero(&fs, sizeof(fs));
    fs.corrupt = -1;

    S3_ASSERT(s3_test_fs_seed(&fs, "/cont.bin", data, sizeof(data)) != NULL);

    S3_ASSERT(s3_ssh3_sftp_cli_init(&cli, pool, NULL, NULL) == S3_OK);

    snprintf(dir, sizeof(dir), "/tmp/s3sftpcliXXXXXX");
    S3_ASSERT(mkdtemp(dir) != NULL);
    snprintf(local, sizeof(local), "%s/cont.bin", dir);
    s3_test_write_local(local, data, sizeof(data));

    S3_ASSERT(s3_ssh3_sftp_cli_put(&cli, local, "/cont.bin", 1, 0) == S3_OK);

    s3_test_cli_run(&fs, &cli);

    S3_ASSERT(cli.state == S3_SSH3_SFTP_CLI_DONE);
    S3_ASSERT(s3_ssh3_sftp_cli_status(&cli) == S3_SSH3_SFTP_FX_OK);

    n = s3_test_node_find(&fs, "/cont.bin");
    S3_ASSERT(n != NULL);
    S3_ASSERT(n->len == sizeof(data));
    S3_ASSERT(n->data != NULL && s3_memcmp(n->data, data, sizeof(data)) == 0);

    s3_test_fs_free(&fs);
    s3_test_rm_rf(dir);

    s3_destroy_pool(pool);

    return s3_test_failures;
}

/* the resume against the larger remote fails like in the reference */

static int
s3_test_cli_resume_put_larger(void)
{
    s3_log_t           log;
    s3_pool_t         *pool;
    s3_ssh3_sftp_cli_t cli;
    s3_test_fs_t       fs;
    u_char             data[S3_TEST_BIG_LEN], extra[8];
    char               dir[64], local[160];

    s3_test_fill(data, sizeof(data), 13);
    s3_test_fill(extra, sizeof(extra), 14);

    pool = s3_test_make_pool(&log);
    S3_ASSERT(pool != NULL);

    s3_memzero(&fs, sizeof(fs));
    fs.corrupt = -1;

    S3_ASSERT(s3_test_fs_seed(&fs, "/cont.bin", data, sizeof(data)) != NULL);
    S3_ASSERT(s3_test_node_write(s3_test_node_find(&fs, "/cont.bin"), sizeof(data), extra,
                                 sizeof(extra)) == 0);

    S3_ASSERT(s3_ssh3_sftp_cli_init(&cli, pool, NULL, NULL) == S3_OK);

    snprintf(dir, sizeof(dir), "/tmp/s3sftpcliXXXXXX");
    S3_ASSERT(mkdtemp(dir) != NULL);
    snprintf(local, sizeof(local), "%s/cont.bin", dir);
    s3_test_write_local(local, data, sizeof(data));

    S3_ASSERT(s3_ssh3_sftp_cli_put(&cli, local, "/cont.bin", 1, 0) == S3_OK);

    s3_test_cli_run(&fs, &cli);

    S3_ASSERT(cli.state == S3_SSH3_SFTP_CLI_FAIL);
    S3_ASSERT(s3_ssh3_sftp_cli_status(&cli) == S3_SSH3_SFTP_FX_FAILURE);

    s3_test_fs_free(&fs);
    s3_test_rm_rf(dir);

    s3_destroy_pool(pool);

    return s3_test_failures;
}

/*
 * the checksum verification: the corrupted WRITE byte must fail the
 * verify=1 run, ride unnoticed with verify=0 and pass the clean run
 */

static int
s3_test_cli_verify(void)
{
    s3_log_t           log;
    s3_pool_t         *pool;
    s3_ssh3_sftp_cli_t cli;
    s3_test_fs_t       fs;
    u_char             data[S3_TEST_BIG_LEN];
    char               dir[64], local[160];

    s3_test_fill(data, sizeof(data), 21);

    pool = s3_test_make_pool(&log);
    S3_ASSERT(pool != NULL);

    snprintf(dir, sizeof(dir), "/tmp/s3sftpcliXXXXXX");
    S3_ASSERT(mkdtemp(dir) != NULL);
    snprintf(local, sizeof(local), "%s/v.bin", dir);
    s3_test_write_local(local, data, sizeof(data));

    /* the corrupting server, the verify on: the mismatch must fail */

    s3_memzero(&fs, sizeof(fs));
    fs.corrupt = -1;
    fs.corrupt = S3_TEST_CORRUPT_AT;

    S3_ASSERT(s3_ssh3_sftp_cli_init(&cli, pool, NULL, NULL) == S3_OK);
    S3_ASSERT(s3_ssh3_sftp_cli_put(&cli, local, "/v1.bin", 0, 1) == S3_OK);

    s3_test_cli_run(&fs, &cli);

    S3_ASSERT(cli.state == S3_SSH3_SFTP_CLI_FAIL);
    S3_ASSERT(s3_ssh3_sftp_cli_status(&cli) == S3_SSH3_SFTP_FX_FAILURE);

    /* the same corruption with the verify off lands unnoticed */

    s3_test_fs_free(&fs);

    s3_memzero(&fs, sizeof(fs));
    fs.corrupt = -1;
    fs.corrupt = S3_TEST_CORRUPT_AT;

    S3_ASSERT(s3_ssh3_sftp_cli_init(&cli, pool, NULL, NULL) == S3_OK);
    S3_ASSERT(s3_ssh3_sftp_cli_put(&cli, local, "/v2.bin", 0, 0) == S3_OK);

    s3_test_cli_run(&fs, &cli);

    S3_ASSERT(cli.state == S3_SSH3_SFTP_CLI_DONE);
    S3_ASSERT(s3_ssh3_sftp_cli_status(&cli) == S3_SSH3_SFTP_FX_OK);

    /* the clean server with the verify on: the SHA-256 tails match */

    s3_test_fs_free(&fs);

    s3_memzero(&fs, sizeof(fs));
    fs.corrupt = -1;

    S3_ASSERT(s3_ssh3_sftp_cli_init(&cli, pool, NULL, NULL) == S3_OK);
    S3_ASSERT(s3_ssh3_sftp_cli_put(&cli, local, "/v3.bin", 0, 1) == S3_OK);

    s3_test_cli_run(&fs, &cli);

    S3_ASSERT(cli.state == S3_SSH3_SFTP_CLI_DONE);
    S3_ASSERT(s3_ssh3_sftp_cli_status(&cli) == S3_SSH3_SFTP_FX_OK);

    s3_test_fs_free(&fs);
    s3_test_rm_rf(dir);

    s3_destroy_pool(pool);

    return s3_test_failures;
}

/* the missing remote file: the FAIL carries the NO_SUCH_FILE code */

static int
s3_test_cli_get_missing(void)
{
    s3_log_t           log;
    s3_pool_t         *pool;
    s3_ssh3_sftp_cli_t cli;
    s3_test_fs_t       fs;
    char               dir[64], local[160];

    pool = s3_test_make_pool(&log);
    S3_ASSERT(pool != NULL);

    s3_memzero(&fs, sizeof(fs));
    fs.corrupt = -1;

    S3_ASSERT(s3_ssh3_sftp_cli_init(&cli, pool, NULL, NULL) == S3_OK);

    snprintf(dir, sizeof(dir), "/tmp/s3sftpcliXXXXXX");
    S3_ASSERT(mkdtemp(dir) != NULL);
    snprintf(local, sizeof(local), "%s/never.bin", dir);

    S3_ASSERT(s3_ssh3_sftp_cli_get(&cli, "/missing.bin", local, 0, 0) == S3_OK);

    s3_test_cli_run(&fs, &cli);

    S3_ASSERT(cli.state == S3_SSH3_SFTP_CLI_FAIL);
    S3_ASSERT(s3_ssh3_sftp_cli_status(&cli) == S3_SSH3_SFTP_FX_NO_SUCH_FILE);

    s3_test_fs_free(&fs);
    s3_test_rm_rf(dir);

    s3_destroy_pool(pool);

    return s3_test_failures;
}

/* the recursive upload: the local tree lands whole in the memory fs */

static void
s3_test_make_tree(const char *root)
{
    char   path[512];
    u_char a[1000], b[2000], c[3000];

    s3_test_fill(a, sizeof(a), 31);
    s3_test_fill(b, sizeof(b), 32);
    s3_test_fill(c, sizeof(c), 33);

    snprintf(path, sizeof(path), "%s/a", root);
    S3_ASSERT(mkdir(path, 0755) == 0 || errno == EEXIST);

    snprintf(path, sizeof(path), "%s/a/b", root);
    S3_ASSERT(mkdir(path, 0755) == 0 || errno == EEXIST);
    (void)errno;

    snprintf(path, sizeof(path), "%s/3.txt", root);
    s3_test_write_local(path, a, sizeof(a));

    snprintf(path, sizeof(path), "%s/a/1.txt", root);
    s3_test_write_local(path, b, sizeof(b));

    snprintf(path, sizeof(path), "%s/a/b/2.txt", root);
    s3_test_write_local(path, c, sizeof(c));
}

static int
s3_test_cli_put_r(void)
{
    s3_log_t           log;
    s3_pool_t         *pool;
    s3_ssh3_sftp_cli_t cli;
    s3_test_fs_t       fs;
    u_char             a[1000], b[2000], c[3000];
    char               dir[64], root[160];
    s3_test_node_t    *n;

    s3_test_fill(a, sizeof(a), 31);
    s3_test_fill(b, sizeof(b), 32);
    s3_test_fill(c, sizeof(c), 33);

    pool = s3_test_make_pool(&log);
    S3_ASSERT(pool != NULL);

    s3_memzero(&fs, sizeof(fs));
    fs.corrupt = -1;

    S3_ASSERT(s3_ssh3_sftp_cli_init(&cli, pool, NULL, NULL) == S3_OK);

    snprintf(dir, sizeof(dir), "/tmp/s3sftpcliXXXXXX");
    S3_ASSERT(mkdtemp(dir) != NULL);
    snprintf(root, sizeof(root), "%s/root", dir);
    S3_ASSERT(mkdir(root, 0755) == 0);

    s3_test_make_tree(root);

    S3_ASSERT(s3_ssh3_sftp_cli_put_r(&cli, root, "/tree", 0, 0) == S3_OK);
    S3_ASSERT(cli.state == S3_SSH3_SFTP_CLI_RUN);

    s3_test_cli_run(&fs, &cli);

    S3_ASSERT(cli.state == S3_SSH3_SFTP_CLI_DONE);
    S3_ASSERT(s3_ssh3_sftp_cli_status(&cli) == S3_SSH3_SFTP_FX_OK);

    /* the whole tree, the directories included */

    n = s3_test_node_find(&fs, "/tree");
    S3_ASSERT(n != NULL && n->is_dir);

    n = s3_test_node_find(&fs, "/tree/a");
    S3_ASSERT(n != NULL && n->is_dir);

    n = s3_test_node_find(&fs, "/tree/a/b");
    S3_ASSERT(n != NULL && n->is_dir);

    n = s3_test_node_find(&fs, "/tree/3.txt");
    S3_ASSERT(n != NULL && !n->is_dir);
    S3_ASSERT(n == NULL || n->len == sizeof(a));
    S3_ASSERT(n == NULL || (n->data != NULL && s3_memcmp(n->data, a, sizeof(a)) == 0));

    n = s3_test_node_find(&fs, "/tree/a/1.txt");
    S3_ASSERT(n != NULL && !n->is_dir);
    S3_ASSERT(n == NULL || n->len == sizeof(b));
    S3_ASSERT(n == NULL || (n->data != NULL && s3_memcmp(n->data, b, sizeof(b)) == 0));

    n = s3_test_node_find(&fs, "/tree/a/b/2.txt");
    S3_ASSERT(n != NULL && !n->is_dir);
    S3_ASSERT(n == NULL || n->len == sizeof(c));
    S3_ASSERT(n == NULL || (n->data != NULL && s3_memcmp(n->data, c, sizeof(c)) == 0));

    s3_test_fs_free(&fs);
    s3_test_rm_rf(dir);

    s3_destroy_pool(pool);

    return s3_test_failures;
}

/* the recursive download: the remote tree lands whole on the disk */

static void
s3_test_seed_tree(s3_test_fs_t *fs)
{
    u_char a[1000], b[2000], c[3000];

    s3_test_fill(a, sizeof(a), 31);
    s3_test_fill(b, sizeof(b), 32);
    s3_test_fill(c, sizeof(c), 33);

    S3_ASSERT(s3_test_node_add(fs, "/tree", 1) != NULL);
    S3_ASSERT(s3_test_node_add(fs, "/tree/a", 1) != NULL);
    S3_ASSERT(s3_test_node_add(fs, "/tree/a/b", 1) != NULL);
    S3_ASSERT(s3_test_fs_seed(fs, "/tree/3.txt", a, sizeof(a)) != NULL);
    S3_ASSERT(s3_test_fs_seed(fs, "/tree/a/1.txt", b, sizeof(b)) != NULL);
    S3_ASSERT(s3_test_fs_seed(fs, "/tree/a/b/2.txt", c, sizeof(c)) != NULL);
}

static void
s3_test_check_tree(const char *root)
{
    u_char      a[1000], b[2000], c[3000];
    char        path[512];
    struct stat st;

    s3_test_fill(a, sizeof(a), 31);
    s3_test_fill(b, sizeof(b), 32);
    s3_test_fill(c, sizeof(c), 33);

    snprintf(path, sizeof(path), "%s/a/b", root);
    S3_ASSERT(stat(path, &st) == 0 && S_ISDIR(st.st_mode));

    snprintf(path, sizeof(path), "%s/3.txt", root);
    S3_ASSERT(stat(path, &st) == 0 && S_ISREG(st.st_mode) && st.st_size == sizeof(a));
    {
        u_char got[sizeof(a)];
        s3_test_read_local(path, got, sizeof(got));
        S3_ASSERT(s3_memcmp(got, a, sizeof(a)) == 0);
    }

    snprintf(path, sizeof(path), "%s/a/1.txt", root);
    S3_ASSERT(stat(path, &st) == 0 && S_ISREG(st.st_mode) && st.st_size == sizeof(b));
    {
        u_char got[sizeof(b)];
        s3_test_read_local(path, got, sizeof(got));
        S3_ASSERT(s3_memcmp(got, b, sizeof(b)) == 0);
    }

    snprintf(path, sizeof(path), "%s/a/b/2.txt", root);
    S3_ASSERT(stat(path, &st) == 0 && S_ISREG(st.st_mode) && st.st_size == sizeof(c));
    {
        u_char got[sizeof(c)];
        s3_test_read_local(path, got, sizeof(got));
        S3_ASSERT(s3_memcmp(got, c, sizeof(c)) == 0);
    }
}

static int
s3_test_cli_get_r(void)
{
    s3_log_t           log;
    s3_pool_t         *pool;
    s3_ssh3_sftp_cli_t cli;
    s3_test_fs_t       fs;
    char               dir[64], root[160];

    pool = s3_test_make_pool(&log);
    S3_ASSERT(pool != NULL);

    s3_memzero(&fs, sizeof(fs));
    fs.corrupt = -1;
    s3_test_seed_tree(&fs);

    S3_ASSERT(s3_ssh3_sftp_cli_init(&cli, pool, NULL, NULL) == S3_OK);

    snprintf(dir, sizeof(dir), "/tmp/s3sftpcliXXXXXX");
    S3_ASSERT(mkdtemp(dir) != NULL);
    snprintf(root, sizeof(root), "%s/dl", dir);

    /* the local root does not exist: the walk creates the levels */

    S3_ASSERT(s3_ssh3_sftp_cli_get_r(&cli, "/tree", root, 0, 0) == S3_OK);
    S3_ASSERT(cli.state == S3_SSH3_SFTP_CLI_RUN);

    s3_test_cli_run(&fs, &cli);

    S3_ASSERT(cli.state == S3_SSH3_SFTP_CLI_DONE);
    S3_ASSERT(s3_ssh3_sftp_cli_status(&cli) == S3_SSH3_SFTP_FX_OK);

    s3_test_check_tree(root);

    s3_test_fs_free(&fs);
    s3_test_rm_rf(dir);

    s3_destroy_pool(pool);

    return s3_test_failures;
}

/*
 * the protocol pin: the reply id must match the last request, the
 * pipeline never retransmits, a foreign id is a protocol error
 */

static int
s3_test_cli_bad_id(void)
{
    s3_log_t             log;
    s3_pool_t           *pool;
    s3_ssh3_sftp_cli_t   cli;
    s3_test_fs_t         fs;
    s3_ssh3_sftp_attrs_t attrs;
    u_char               rep[128], req[65536];
    char                 dir[64], local[160];
    uintptr_t            len;
    ssize_t              n;

    pool = s3_test_make_pool(&log);
    S3_ASSERT(pool != NULL);

    s3_memzero(&fs, sizeof(fs));
    fs.corrupt = -1;

    s3_test_fill(rep, 16, 5);
    S3_ASSERT(s3_test_fs_seed(&fs, "/f.bin", rep, 16) != NULL);

    S3_ASSERT(s3_ssh3_sftp_cli_init(&cli, pool, NULL, NULL) == S3_OK);

    snprintf(dir, sizeof(dir), "/tmp/s3sftpcliXXXXXX");
    S3_ASSERT(mkdtemp(dir) != NULL);
    snprintf(local, sizeof(local), "%s/f.bin", dir);

    S3_ASSERT(s3_ssh3_sftp_cli_get(&cli, "/f.bin", local, 0, 0) == S3_OK);

    /* the STAT rode out, the reply answers a foreign id: the id of
     * the request that has not flown yet */

    n = s3_ssh3_sftp_cli_output(&cli, req, sizeof(req));
    S3_ASSERT(n > 0);

    s3_memzero(&attrs, sizeof(attrs));
    attrs.flags = S3_SSH3_SFTP_ATTR_SIZE | S3_SSH3_SFTP_ATTR_PERMISSION;
    attrs.size = 16;
    attrs.perms = 0100644;

    len = s3_ssh3_sftp_encode_attrs(NULL, cli.next_id, &attrs);
    S3_ASSERT(len <= sizeof(rep));
    (void)s3_ssh3_sftp_encode_attrs(rep, cli.next_id, &attrs);

    S3_ASSERT(s3_ssh3_sftp_cli_input(&cli, rep, (size_t)len) == S3_ERROR);

    /* the idle driver refuses every frame too */

    S3_ASSERT(s3_ssh3_sftp_cli_init(&cli, pool, NULL, NULL) == S3_OK);

    len = s3_ssh3_sftp_encode_attrs(NULL, 0, &attrs);
    (void)s3_ssh3_sftp_encode_attrs(rep, 0, &attrs);

    S3_ASSERT(s3_ssh3_sftp_cli_input(&cli, rep, (size_t)len) == S3_ERROR);

    s3_test_fs_free(&fs);
    s3_test_rm_rf(dir);

    s3_destroy_pool(pool);

    return s3_test_failures;
}

static int
s3_test_ssh3_sftp_cli(void)
{
    (void)s3_test_cli_lifecycle();
    (void)s3_test_cli_put_roundtrip();
    (void)s3_test_cli_get_roundtrip();
    (void)s3_test_cli_resume_put();
    (void)s3_test_cli_resume_put_equal();
    (void)s3_test_cli_resume_put_larger();
    (void)s3_test_cli_verify();
    (void)s3_test_cli_get_missing();
    (void)s3_test_cli_put_r();
    (void)s3_test_cli_get_r();
    (void)s3_test_cli_bad_id();

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_ssh3_sftp_cli)
