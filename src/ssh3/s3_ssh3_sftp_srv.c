/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the server side of the "sftp" channel, the port of the reference
 * cmd/sftp_subsystem.go over pkg/sftp: one server per channel, the
 * SFTP v3 request loop jailed to the session user's home directory;
 * the module owns the filesystem side only - the channel framing
 * stays in the caller (the same split as s3_ssh3_session_srv)
 *
 * the loop appends the received chunks to the receive tail, pulls
 * the whole frames with the codec and builds the replies inside the
 * output buffer; a length prefix above the wire cap marks the
 * protocol error, the caller tears the channel down
 */

#include <s3_core.h>

#include <s3_ssh3_sftp_srv.h>

#include <s3_ssh3_sftp_codec.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * one reply stays below this line; a READDIR with more entries cuts
 * the batch and serves the rest on the next request
 */
#define S3_SSH3_SFTP_SRV_REPLY_MAX (64 * 1024)

/* the read chunk of one READ, the reply cap minus the frame head */

#define S3_SSH3_SFTP_SRV_READ_MAX (S3_SSH3_SFTP_SRV_REPLY_MAX - 32)

/* the initial sizes of the receive tail and the reply buffer */

#define S3_SSH3_SFTP_SRV_PEND_INIT 4096

#define S3_SSH3_SFTP_SRV_OUT_INIT 8192

/* the reserved part of the READDIR budget, one entry never reaches it */

#define S3_SSH3_SFTP_SRV_ENTRY_MAX 1024

/* the longname line of one READDIR entry, OpenSSH ls -l shape */

#define S3_SSH3_SFTP_SRV_LONGNAME_MAX 256

/* the wire size of one attribute block without the extended pairs */

#define S3_SSH3_SFTP_SRV_ATTRS_LEN 32

static unsigned s3_srv_isspace(u_char c);
static size_t   s3_srv_clean(const u_char *src, size_t n, u_char *dst);
static unsigned s3_srv_inside(const s3_ssh3_sftp_srv_t *t, const u_char *p, size_t n);
static u_char  *s3_srv_resolve(s3_ssh3_sftp_srv_t *t, const s3_str_t *client, size_t *len,
                               unsigned *denied);
static uint32_t s3_srv_peek_len(const u_char *p);
static void     s3_srv_put_be64(u_char *p, uint64_t v);
static s3_int_t s3_srv_pend_append(s3_ssh3_sftp_srv_t *t, const u_char *data, size_t len);
static u_char  *s3_srv_out_reserve(s3_ssh3_sftp_srv_t *t, size_t need);
static s3_int_t s3_srv_reply_version(s3_ssh3_sftp_srv_t *t, uint32_t version);
static s3_int_t s3_srv_reply_status(s3_ssh3_sftp_srv_t *t, uint32_t id, uint32_t code);
static s3_int_t s3_srv_reply_handle(s3_ssh3_sftp_srv_t *t, uint32_t id, const s3_str_t *h);
static s3_int_t s3_srv_reply_data(s3_ssh3_sftp_srv_t *t, uint32_t id, const s3_str_t *data);
static s3_int_t s3_srv_reply_attrs(s3_ssh3_sftp_srv_t *t, uint32_t id,
                                   const s3_ssh3_sftp_attrs_t *a);
static s3_int_t s3_srv_reply_name1(s3_ssh3_sftp_srv_t *t, uint32_t id, const s3_str_t *name);
static uint32_t s3_srv_errno_status(int err);
static void     s3_srv_attrs_from_stat(s3_ssh3_sftp_attrs_t *a, const struct stat *st);
static size_t   s3_srv_longname(const struct stat *st, const char *name, u_char *dst, size_t cap);
static s3_ssh3_sftp_srv_handle_t *s3_srv_handle_alloc(s3_ssh3_sftp_srv_t *t);
static s3_ssh3_sftp_srv_handle_t *s3_srv_handle_find(s3_ssh3_sftp_srv_t *t, const s3_str_t *h);
static void                       s3_srv_handle_release(s3_ssh3_sftp_srv_handle_t *slot);
static s3_int_t s3_srv_jailed(s3_ssh3_sftp_srv_t *t, uint32_t id, const s3_str_t *path,
                              s3_str_t *jailed);
static s3_int_t s3_srv_open(s3_ssh3_sftp_srv_t *t, uint32_t id, const s3_str_t *body);
static s3_int_t s3_srv_read(s3_ssh3_sftp_srv_t *t, uint32_t id, const s3_str_t *body);
static s3_int_t s3_srv_write(s3_ssh3_sftp_srv_t *t, uint32_t id, const s3_str_t *body);
static s3_int_t s3_srv_close(s3_ssh3_sftp_srv_t *t, uint32_t id, const s3_str_t *body);
static s3_int_t s3_srv_stat(s3_ssh3_sftp_srv_t *t, uint32_t id, const s3_str_t *body,
                            unsigned follow);
static s3_int_t s3_srv_fstat(s3_ssh3_sftp_srv_t *t, uint32_t id, const s3_str_t *body);
static s3_int_t s3_srv_opendir(s3_ssh3_sftp_srv_t *t, uint32_t id, const s3_str_t *body);
static s3_int_t s3_srv_readdir(s3_ssh3_sftp_srv_t *t, uint32_t id, const s3_str_t *body);
static s3_int_t s3_srv_mkdir_one(s3_ssh3_sftp_srv_t *t, char *path, size_t at);
static s3_int_t s3_srv_mkdir_all(s3_ssh3_sftp_srv_t *t, char *path);
static s3_int_t s3_srv_mkdir(s3_ssh3_sftp_srv_t *t, uint32_t id, const s3_str_t *body);
static s3_int_t s3_srv_rmdir(s3_ssh3_sftp_srv_t *t, uint32_t id, const s3_str_t *body);
static s3_int_t s3_srv_remove(s3_ssh3_sftp_srv_t *t, uint32_t id, const s3_str_t *body);
static s3_int_t s3_srv_rename(s3_ssh3_sftp_srv_t *t, uint32_t id, const s3_str_t *body);
static s3_int_t s3_srv_realpath(s3_ssh3_sftp_srv_t *t, uint32_t id, const s3_str_t *body);
static s3_int_t s3_srv_dispatch(s3_ssh3_sftp_srv_t *t, s3_ssh3_sftp_pkt_t *pkt);

s3_int_t
s3_ssh3_sftp_srv_init(s3_ssh3_sftp_srv_t *t, s3_pool_t *pool, const s3_str_t *home, uint32_t uid,
                      uint32_t gid)
{
    u_char  *copy;
    uint32_t i;

    if (t == NULL || pool == NULL || home == NULL || home->data == NULL || home->len == 0 ||
        home->data[0] != '/') {
        return S3_ERROR;
    }

    s3_memzero(t, sizeof(*t));

    copy = s3_pnalloc(pool, home->len);

    if (copy == NULL) {
        return S3_ERROR;
    }

    s3_memcpy(copy, home->data, home->len);

    t->pool = pool;
    t->home.data = copy;
    t->home.len = home->len;

    /* the jail root without the trailing slash, only "/" keeps it */

    while (t->home.len > 1 && copy[t->home.len - 1] == '/') {
        t->home.len--;
    }

    t->uid = uid;
    t->gid = gid;

    for (i = 0; i < S3_SSH3_SFTP_SRV_HANDLES; i++) {
        t->handles[i].fd = -1;
    }

    return S3_OK;
}

s3_int_t
s3_ssh3_sftp_srv_input(s3_ssh3_sftp_srv_t *t, const u_char *data, size_t len)
{
    const u_char      *pos, *end;
    s3_ssh3_sftp_pkt_t pkt;
    size_t             consumed;
    s3_int_t           rc;

    if (t == NULL || t->pool == NULL || (len > 0 && data == NULL)) {
        return S3_ERROR;
    }

    /* the verdict is in: the channel goes down, nothing else parses */

    if (t->protocol_error) {
        return S3_ERROR;
    }

    if (len == 0) {
        return S3_OK;
    }

    if (s3_srv_pend_append(t, data, len) != S3_OK) {
        return S3_ERROR;
    }

    for (;;) {

        /* the hostile length prefix dies before its body arrives */

        if (t->pend_len >= 4 && s3_srv_peek_len(t->pend) > S3_SSH3_SFTP_MAX_FRAME) {
            t->protocol_error = 1;
            return S3_OK;
        }

        pos = t->pend;
        end = t->pend + t->pend_len;

        rc = s3_ssh3_sftp_codec_frame(&pos, end, &pkt);

        if (rc == S3_AGAIN) {
            return S3_OK;
        }

        if (rc != S3_OK) {
            t->protocol_error = 1;
            return S3_OK;
        }

        consumed = (size_t)(pos - t->pend);

        rc = s3_srv_dispatch(t, &pkt);

        /* the body views die with the shift of the tail */

        t->pend_len -= consumed;

        if (t->pend_len > 0) {
            s3_memmove(t->pend, t->pend + consumed, t->pend_len);
        }

        if (rc != S3_OK) {
            return S3_ERROR;
        }
    }
}

ssize_t
s3_ssh3_sftp_srv_output(s3_ssh3_sftp_srv_t *t, u_char *buf, size_t size)
{
    size_t n;

    if (t == NULL || buf == NULL || size == 0) {
        return 0;
    }

    n = t->out_len < size ? t->out_len : size;

    if (n > 0) {
        s3_memcpy(buf, t->out, n);
        t->out_len -= n;

        if (t->out_len > 0) {
            s3_memmove(t->out, t->out + n, t->out_len);
        }
    }

    return (ssize_t)n;
}

unsigned
s3_ssh3_sftp_srv_protocol_error(const s3_ssh3_sftp_srv_t *t)
{
    return t->protocol_error;
}

/* the space run of the reference TrimSpace, the ASCII members only */

static unsigned
s3_srv_isspace(u_char c)
{
    return c == ' ' || (c >= '\t' && c <= '\r');
}

/*
 * the POSIX clean, the port of the Go path.Clean: drops the repeated
 * separators and the . elements, resolves the inner .. elements, the
 * leading .. of a rooted path collapse into the root; the result of
 * an empty input is "."; dst may alias src, the write cursor never
 * passes the read cursor
 */

static size_t
s3_srv_clean(const u_char *src, size_t n, u_char *dst)
{
    size_t   r, w, dotdot;
    unsigned rooted;

    if (n == 0) {
        dst[0] = '.';
        return 1;
    }

    rooted = (src[0] == '/');

    r = 0;
    w = 0;
    dotdot = 0;

    if (rooted) {
        dst[w++] = '/';
        r = 1;
        dotdot = 1;
    }

    while (r < n) {

        if (src[r] == '/') {
            r++;
            continue;
        }

        if (src[r] == '.' && (r + 1 == n || src[r + 1] == '/')) {
            r++;
            continue;
        }

        if (src[r] == '.' && r + 1 < n && src[r + 1] == '.' && (r + 2 == n || src[r + 2] == '/')) {
            r += 2;

            if (w > dotdot) {

                /* the element before it goes away with the .. */

                w--;

                while (w > dotdot && dst[w - 1] != '/') {
                    w--;
                }

            } else if (!rooted) {

                if (w > 0) {
                    dst[w++] = '/';
                }

                dst[w++] = '.';
                dst[w++] = '.';
                dotdot = w;
            }

            continue;
        }

        /* the real element: the separator goes first, then the name */

        if ((rooted && w != 1) || (!rooted && w != 0)) {
            dst[w++] = '/';
        }

        while (r < n && src[r] != '/') {
            dst[w++] = src[r++];
        }
    }

    if (w == 0) {
        dst[w++] = '.';
    }

    return w;
}

/* the jail verdict: the root itself or anything below it */

static unsigned
s3_srv_inside(const s3_ssh3_sftp_srv_t *t, const u_char *p, size_t n)
{
    if (n == t->home.len && s3_memcmp(p, t->home.data, n) == 0) {
        return 1;
    }

    if (n > t->home.len && p[t->home.len] == '/' && s3_memcmp(p, t->home.data, t->home.len) == 0) {
        return 1;
    }

    return 0;
}

/*
 * the port of the reference resolveJailed: jail-relative paths go
 * under home, the absolute spelling already living inside is honored
 * verbatim, everything else joins under the root; the join result is
 * checked against the jail one last time; the result is a pool copy
 * with the NUL terminator, NULL with *denied on the escape verdict,
 * NULL without it on the pool exhaustion
 */

static u_char *
s3_srv_resolve(s3_ssh3_sftp_srv_t *t, const s3_str_t *client, size_t *len, unsigned *denied)
{
    const u_char *src;
    u_char       *tmp, *full;
    size_t        start, end, n, clen, flen, rl;

    *denied = 0;
    *len = 0;

    start = 0;
    end = client->len;
    src = client->data;

    while (start < end && s3_srv_isspace(src[start])) {
        start++;
    }

    while (end > start && s3_srv_isspace(src[end - 1])) {
        end--;
    }

    src += start;
    n = end - start;

    if (n == 0) {

        /* the empty path is the jail root itself */

        full = s3_pnalloc(t->pool, t->home.len + 1);

        if (full == NULL) {
            return NULL;
        }

        s3_memcpy(full, t->home.data, t->home.len);
        full[t->home.len] = '\0';

        *len = t->home.len;

        return full;
    }

    if (src[0] == '/') {

        /* the absolute spelling: honored verbatim when already inside */

        tmp = s3_pnalloc(t->pool, n + 2);

        if (tmp == NULL) {
            return NULL;
        }

        clen = s3_srv_clean(src, n, tmp);

        if (s3_srv_inside(t, tmp, clen)) {
            tmp[clen] = '\0';
            *len = clen;
            return tmp;
        }

        /* below, the join of the reference remaps it under the root */
    }

    /* the join: the rooted clean of the trimmed path plus the root */

    tmp = s3_pnalloc(t->pool, n + 2);

    if (tmp == NULL) {
        return NULL;
    }

    tmp[0] = '/';
    s3_memcpy(tmp + 1, src, n);

    clen = s3_srv_clean(tmp, n + 1, tmp);

    rl = t->home.len;

    /* the join of "." is the root itself: the verdict of the reference
       filepath.Join carries no trailing slash */

    if (clen == 1 && rl > 1) {
        flen = rl;

    } else if (rl == 1) {
        flen = clen; /* the "/" jail: the clean is the whole answer */

    } else {
        flen = rl + clen;
    }

    full = s3_pnalloc(t->pool, flen + 1);

    if (full == NULL) {
        return NULL;
    }

    if (clen == 1 && rl > 1) {
        s3_memcpy(full, t->home.data, rl);

    } else if (rl == 1) {
        s3_memcpy(full, tmp, clen);

    } else {
        s3_memcpy(full, t->home.data, rl);
        s3_memcpy(full + rl, tmp, clen);
    }

    full[flen] = '\0';

    if (!s3_srv_inside(t, full, flen)) {
        *denied = 1;
        return NULL;
    }

    *len = flen;

    return full;
}

static uint32_t
s3_srv_peek_len(const u_char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void
s3_srv_put_be64(u_char *p, uint64_t v)
{
    int i;

    for (i = 7; i >= 0; i--) {
        p[i] = (u_char)v;
        v >>= 8;
    }
}

/*
 * the receive tail: the growth goes through the pool, the abandoned
 * blocks die with it (the pend lives the life of the structure)
 */

static s3_int_t
s3_srv_pend_append(s3_ssh3_sftp_srv_t *t, const u_char *data, size_t len)
{
    u_char *grown;
    size_t  cap;

    if (t->pend_cap - t->pend_len < len) {

        cap = t->pend_cap ? t->pend_cap : S3_SSH3_SFTP_SRV_PEND_INIT;

        while (cap - t->pend_len < len) {
            cap *= 2;
        }

        grown = s3_pnalloc(t->pool, cap);

        if (grown == NULL) {
            return S3_ERROR;
        }

        if (t->pend_len > 0) {
            s3_memcpy(grown, t->pend, t->pend_len);
        }

        t->pend = grown;
        t->pend_cap = cap;
    }

    s3_memcpy(t->pend + t->pend_len, data, len);
    t->pend_len += len;

    return S3_OK;
}

static u_char *
s3_srv_out_reserve(s3_ssh3_sftp_srv_t *t, size_t need)
{
    u_char *grown;
    size_t  cap;

    if (t->out_cap - t->out_len < need) {

        cap = t->out_cap ? t->out_cap : S3_SSH3_SFTP_SRV_OUT_INIT;

        while (cap - t->out_len < need) {
            cap *= 2;
        }

        grown = s3_pnalloc(t->pool, cap);

        if (grown == NULL) {
            return NULL;
        }

        if (t->out_len > 0) {
            s3_memcpy(grown, t->out, t->out_len);
        }

        t->out = grown;
        t->out_cap = cap;
    }

    return t->out + t->out_len;
}

static s3_int_t
s3_srv_reply_version(s3_ssh3_sftp_srv_t *t, uint32_t version)
{
    u_char   *p;
    uintptr_t n;

    n = s3_ssh3_sftp_encode_version(NULL, version);
    p = s3_srv_out_reserve(t, n);

    if (p == NULL) {
        return S3_ERROR;
    }

    (void)s3_ssh3_sftp_encode_version(p, version);
    t->out_len += n;

    return S3_OK;
}

static s3_int_t
s3_srv_reply_status(s3_ssh3_sftp_srv_t *t, uint32_t id, uint32_t code)
{
    s3_str_t  msg;
    u_char   *p;
    uintptr_t n;

    s3_str_null(&msg);

    n = s3_ssh3_sftp_encode_status(NULL, id, code, &msg);
    p = s3_srv_out_reserve(t, n);

    if (p == NULL) {
        return S3_ERROR;
    }

    (void)s3_ssh3_sftp_encode_status(p, id, code, &msg);
    t->out_len += n;

    return S3_OK;
}

static s3_int_t
s3_srv_reply_handle(s3_ssh3_sftp_srv_t *t, uint32_t id, const s3_str_t *h)
{
    u_char   *p;
    uintptr_t n;

    n = s3_ssh3_sftp_encode_handle(NULL, id, h);
    p = s3_srv_out_reserve(t, n);

    if (p == NULL) {
        return S3_ERROR;
    }

    (void)s3_ssh3_sftp_encode_handle(p, id, h);
    t->out_len += n;

    return S3_OK;
}

static s3_int_t
s3_srv_reply_data(s3_ssh3_sftp_srv_t *t, uint32_t id, const s3_str_t *data)
{
    u_char   *p;
    uintptr_t n;

    n = s3_ssh3_sftp_encode_data(NULL, id, data);
    p = s3_srv_out_reserve(t, n);

    if (p == NULL) {
        return S3_ERROR;
    }

    (void)s3_ssh3_sftp_encode_data(p, id, data);
    t->out_len += n;

    return S3_OK;
}

static s3_int_t
s3_srv_reply_attrs(s3_ssh3_sftp_srv_t *t, uint32_t id, const s3_ssh3_sftp_attrs_t *a)
{
    u_char   *p;
    uintptr_t n;

    n = s3_ssh3_sftp_encode_attrs(NULL, id, a);
    p = s3_srv_out_reserve(t, n);

    if (p == NULL) {
        return S3_ERROR;
    }

    (void)s3_ssh3_sftp_encode_attrs(p, id, a);
    t->out_len += n;

    return S3_OK;
}

static s3_int_t
s3_srv_reply_name1(s3_ssh3_sftp_srv_t *t, uint32_t id, const s3_str_t *name)
{
    s3_ssh3_sftp_name_t entry;
    s3_str_t            empty;
    u_char             *p;
    uintptr_t           n;

    s3_str_null(&empty);
    s3_memzero(&entry, sizeof(entry));

    entry.filename = *name;
    entry.longname = empty;

    /* the realpath answer carries no attributes */

    entry.attrs.flags = 0;

    n = s3_ssh3_sftp_encode_name(NULL, id, &entry, 1);
    p = s3_srv_out_reserve(t, n);

    if (p == NULL) {
        return S3_ERROR;
    }

    (void)s3_ssh3_sftp_encode_name(p, id, &entry, 1);
    t->out_len += n;

    return S3_OK;
}

/* the errno verdicts of the brief, the rest is a plain failure */

static uint32_t
s3_srv_errno_status(int err)
{
    switch (err) {

    case ENOENT:
        return S3_SSH3_SFTP_FX_NO_SUCH_FILE;

    case EACCES:
    case EPERM:
    case EROFS:
        return S3_SSH3_SFTP_FX_PERMISSION_DENIED;
    }

    return S3_SSH3_SFTP_FX_FAILURE;
}

static void
s3_srv_attrs_from_stat(s3_ssh3_sftp_attrs_t *a, const struct stat *st)
{
    s3_memzero(a, sizeof(*a));

    a->flags = S3_SSH3_SFTP_ATTR_SIZE | S3_SSH3_SFTP_ATTR_UIDGID | S3_SSH3_SFTP_ATTR_PERMISSION |
               S3_SSH3_SFTP_ATTR_ACMODTIME;

    a->size = (uint64_t)st->st_size;
    a->uid = (uint32_t)st->st_uid;
    a->gid = (uint32_t)st->st_gid;
    a->perms = (uint32_t)st->st_mode;
    a->atime = (uint32_t)st->st_atime;
    a->mtime = (uint32_t)st->st_mtime;
}

/* the ls -l line of OpenSSH, the numeric uid and gid, no date */

static size_t
s3_srv_longname(const struct stat *st, const char *name, u_char *dst, size_t cap)
{
    char   type, rwx[10];
    mode_t m = st->st_mode;
    int    n;

    if (S_ISDIR(m)) {
        type = 'd';

    } else if (S_ISLNK(m)) {
        type = 'l';

    } else if (S_ISCHR(m)) {
        type = 'c';

    } else if (S_ISBLK(m)) {
        type = 'b';

    } else if (S_ISFIFO(m)) {
        type = 'p';

    } else if (S_ISSOCK(m)) {
        type = 's';

    } else {
        type = '-';
    }

    rwx[0] = (m & 0400) ? 'r' : '-';
    rwx[1] = (m & 0200) ? 'w' : '-';
    rwx[2] = (m & 0100) ? 'x' : '-';
    rwx[3] = (m & 0040) ? 'r' : '-';
    rwx[4] = (m & 0020) ? 'w' : '-';
    rwx[5] = (m & 0010) ? 'x' : '-';
    rwx[6] = (m & 0004) ? 'r' : '-';
    rwx[7] = (m & 0002) ? 'w' : '-';
    rwx[8] = (m & 0001) ? 'x' : '-';
    rwx[9] = '\0';

    n = snprintf((char *)dst, cap, "%c%s %4u %u %u %8llu %s", type, rwx, (unsigned)st->st_nlink,
                 (unsigned)st->st_uid, (unsigned)st->st_gid, (unsigned long long)st->st_size, name);

    if (n < 0) {
        return 0;
    }

    if ((size_t)n >= cap) {
        n = (int)(cap - 1);
    }

    return (size_t)n;
}

static s3_ssh3_sftp_srv_handle_t *
s3_srv_handle_alloc(s3_ssh3_sftp_srv_t *t)
{
    s3_ssh3_sftp_srv_handle_t *slot;
    uint32_t                   i;

    for (i = 0; i < S3_SSH3_SFTP_SRV_HANDLES; i++) {

        slot = &t->handles[i];

        if (slot->fd >= 0 || slot->dir != NULL) {
            continue;
        }

        s3_srv_put_be64(slot->id, t->next_handle++);

        return slot;
    }

    return NULL;
}

static s3_ssh3_sftp_srv_handle_t *
s3_srv_handle_find(s3_ssh3_sftp_srv_t *t, const s3_str_t *h)
{
    s3_ssh3_sftp_srv_handle_t *slot;
    uint32_t                   i;

    if (h->len != 8) {
        return NULL;
    }

    for (i = 0; i < S3_SSH3_SFTP_SRV_HANDLES; i++) {

        slot = &t->handles[i];

        if ((slot->fd >= 0 || slot->dir != NULL) && s3_memcmp(slot->id, h->data, 8) == 0) {
            return slot;
        }
    }

    return NULL;
}

static void
s3_srv_handle_release(s3_ssh3_sftp_srv_handle_t *slot)
{
    if (slot->dir != NULL) {
        (void)closedir((DIR *)slot->dir);

    } else if (slot->fd >= 0) {
        (void)close(slot->fd);
    }

    slot->fd = -1;
    slot->dir = NULL;
    s3_memzero(slot->id, 8);
}

/*
 * the jailed absolute path of one client path; S3_DECLINED is the
 * escape verdict (the caller answers PERMISSION_DENIED), S3_ERROR
 * the pool exhaustion
 */

static s3_int_t
s3_srv_jailed(s3_ssh3_sftp_srv_t *t, uint32_t id, const s3_str_t *path, s3_str_t *jailed)
{
    u_char  *p;
    size_t   len;
    unsigned denied = 0;

    p = s3_srv_resolve(t, path, &len, &denied);

    if (p == NULL) {

        if (denied) {
            (void)s3_srv_reply_status(t, id, S3_SSH3_SFTP_FX_PERMISSION_DENIED);
            return S3_DECLINED;
        }

        return S3_ERROR;
    }

    jailed->data = p;
    jailed->len = len;

    return S3_OK;
}

static s3_int_t
s3_srv_open(s3_ssh3_sftp_srv_t *t, uint32_t id, const s3_str_t *body)
{
    s3_ssh3_sftp_attrs_t       attrs;
    s3_ssh3_sftp_srv_handle_t *slot;
    s3_str_t                   path, jailed, h;
    uint32_t                   pflags;
    int                        fd, fl, rc;

    if (s3_ssh3_sftp_parse_open_body(body, &path, &pflags, &attrs) != S3_OK) {
        return s3_srv_reply_status(t, id, S3_SSH3_SFTP_FX_BAD_MESSAGE);
    }

    rc = s3_srv_jailed(t, id, &path, &jailed);

    if (rc != S3_OK) {
        return rc == S3_DECLINED ? S3_OK : S3_ERROR;
    }

    /* the flag mapping of the brief: the write bit wins the read one */

    fl = 0;

    if (pflags & S3_SSH3_SFTP_FXF_READ) {
        fl = O_RDONLY;
    }

    if (pflags & S3_SSH3_SFTP_FXF_WRITE) {
        fl = (pflags & S3_SSH3_SFTP_FXF_READ) ? O_RDWR : O_WRONLY;
    }

    if (pflags & S3_SSH3_SFTP_FXF_CREAT) {
        fl |= O_CREAT;
    }

    if (pflags & S3_SSH3_SFTP_FXF_TRUNC) {
        fl |= O_TRUNC;
    }

    if (pflags & S3_SSH3_SFTP_FXF_APPEND) {
        fl |= O_APPEND;
    }

    fd = open((const char *)jailed.data, fl, 0644);

    if (fd < 0) {
        return s3_srv_reply_status(t, id, s3_srv_errno_status(errno));
    }

    /* the reference chownToUser: the created inode belongs to the
       user, the verdict is best effort */

    if (pflags & S3_SSH3_SFTP_FXF_CREAT &&
        chown((const char *)jailed.data, (uid_t)t->uid, (gid_t)t->gid) != 0) {
        /* the reference logs and moves on */
    }

    slot = s3_srv_handle_alloc(t);

    if (slot == NULL) {
        (void)close(fd);
        return s3_srv_reply_status(t, id, S3_SSH3_SFTP_FX_FAILURE);
    }

    slot->fd = fd;

    h.data = slot->id;
    h.len = 8;

    return s3_srv_reply_handle(t, id, &h);
}

static s3_int_t
s3_srv_read(s3_ssh3_sftp_srv_t *t, uint32_t id, const s3_str_t *body)
{
    s3_ssh3_sftp_srv_handle_t *slot;
    s3_str_t                   h, data;
    u_char                    *buf;
    uint64_t                   offset;
    uint32_t                   len;
    ssize_t                    n;

    if (s3_ssh3_sftp_parse_read_body(body, &h, &offset, &len) != S3_OK) {
        return s3_srv_reply_status(t, id, S3_SSH3_SFTP_FX_BAD_MESSAGE);
    }

    slot = s3_srv_handle_find(t, &h);

    if (slot == NULL) {
        return s3_srv_reply_status(t, id, S3_SSH3_SFTP_FX_NO_SUCH_FILE);
    }

    if (slot->fd < 0) {
        return s3_srv_reply_status(t, id, S3_SSH3_SFTP_FX_FAILURE);
    }

    if (len > S3_SSH3_SFTP_SRV_READ_MAX) {
        len = S3_SSH3_SFTP_SRV_READ_MAX;
    }

    buf = s3_pnalloc(t->pool, len ? len : 1);

    if (buf == NULL) {
        return S3_ERROR;
    }

    n = pread(slot->fd, buf, len, (off_t)offset);

    if (n < 0) {
        return s3_srv_reply_status(t, id, s3_srv_errno_status(errno));
    }

    if (n == 0) {
        return s3_srv_reply_status(t, id, S3_SSH3_SFTP_FX_EOF);
    }

    /* the partial read goes out as it is, the client keeps reading */

    data.data = buf;
    data.len = (size_t)n;

    return s3_srv_reply_data(t, id, &data);
}

static s3_int_t
s3_srv_write(s3_ssh3_sftp_srv_t *t, uint32_t id, const s3_str_t *body)
{
    s3_ssh3_sftp_srv_handle_t *slot;
    s3_str_t                   h, data;
    uint64_t                   offset;
    ssize_t                    n;

    if (s3_ssh3_sftp_parse_write_body(body, &h, &offset, &data) != S3_OK) {
        return s3_srv_reply_status(t, id, S3_SSH3_SFTP_FX_BAD_MESSAGE);
    }

    slot = s3_srv_handle_find(t, &h);

    if (slot == NULL) {
        return s3_srv_reply_status(t, id, S3_SSH3_SFTP_FX_NO_SUCH_FILE);
    }

    if (slot->fd < 0) {
        return s3_srv_reply_status(t, id, S3_SSH3_SFTP_FX_FAILURE);
    }

    n = pwrite(slot->fd, data.data, data.len, (off_t)offset);

    if (n < 0) {
        return s3_srv_reply_status(t, id, s3_srv_errno_status(errno));
    }

    if ((size_t)n != data.len) {
        return s3_srv_reply_status(t, id, S3_SSH3_SFTP_FX_FAILURE);
    }

    return s3_srv_reply_status(t, id, S3_SSH3_SFTP_FX_OK);
}

static s3_int_t
s3_srv_close(s3_ssh3_sftp_srv_t *t, uint32_t id, const s3_str_t *body)
{
    s3_ssh3_sftp_srv_handle_t *slot;
    s3_str_t                   h;

    if (s3_ssh3_sftp_parse_handle_body(body, &h) != S3_OK) {
        return s3_srv_reply_status(t, id, S3_SSH3_SFTP_FX_BAD_MESSAGE);
    }

    slot = s3_srv_handle_find(t, &h);

    if (slot == NULL) {
        return s3_srv_reply_status(t, id, S3_SSH3_SFTP_FX_NO_SUCH_FILE);
    }

    s3_srv_handle_release(slot);

    return s3_srv_reply_status(t, id, S3_SSH3_SFTP_FX_OK);
}

static s3_int_t
s3_srv_stat(s3_ssh3_sftp_srv_t *t, uint32_t id, const s3_str_t *body, unsigned follow)
{
    s3_ssh3_sftp_attrs_t attrs;
    s3_str_t             path, jailed;
    struct stat          st;
    int                  rc;

    if (s3_ssh3_sftp_parse_path_body(body, &path) != S3_OK) {
        return s3_srv_reply_status(t, id, S3_SSH3_SFTP_FX_BAD_MESSAGE);
    }

    rc = s3_srv_jailed(t, id, &path, &jailed);

    if (rc != S3_OK) {
        return rc == S3_DECLINED ? S3_OK : S3_ERROR;
    }

    rc = follow ? stat((const char *)jailed.data, &st) : lstat((const char *)jailed.data, &st);

    if (rc != 0) {
        return s3_srv_reply_status(t, id, s3_srv_errno_status(errno));
    }

    s3_srv_attrs_from_stat(&attrs, &st);

    return s3_srv_reply_attrs(t, id, &attrs);
}

static s3_int_t
s3_srv_fstat(s3_ssh3_sftp_srv_t *t, uint32_t id, const s3_str_t *body)
{
    s3_ssh3_sftp_attrs_t       attrs;
    s3_ssh3_sftp_srv_handle_t *slot;
    s3_str_t                   h;
    struct stat                st;

    if (s3_ssh3_sftp_parse_handle_body(body, &h) != S3_OK) {
        return s3_srv_reply_status(t, id, S3_SSH3_SFTP_FX_BAD_MESSAGE);
    }

    slot = s3_srv_handle_find(t, &h);

    if (slot == NULL || slot->fd < 0) {
        return s3_srv_reply_status(t, id, S3_SSH3_SFTP_FX_NO_SUCH_FILE);
    }

    if (fstat(slot->fd, &st) != 0) {
        return s3_srv_reply_status(t, id, s3_srv_errno_status(errno));
    }

    s3_srv_attrs_from_stat(&attrs, &st);

    return s3_srv_reply_attrs(t, id, &attrs);
}

static s3_int_t
s3_srv_opendir(s3_ssh3_sftp_srv_t *t, uint32_t id, const s3_str_t *body)
{
    s3_ssh3_sftp_srv_handle_t *slot;
    s3_str_t                   path, jailed, h;
    DIR                       *d;
    int                        rc;

    if (s3_ssh3_sftp_parse_path_body(body, &path) != S3_OK) {
        return s3_srv_reply_status(t, id, S3_SSH3_SFTP_FX_BAD_MESSAGE);
    }

    rc = s3_srv_jailed(t, id, &path, &jailed);

    if (rc != S3_OK) {
        return rc == S3_DECLINED ? S3_OK : S3_ERROR;
    }

    d = opendir((const char *)jailed.data);

    if (d == NULL) {
        return s3_srv_reply_status(t, id, s3_srv_errno_status(errno));
    }

    slot = s3_srv_handle_alloc(t);

    if (slot == NULL) {
        (void)closedir(d);
        return s3_srv_reply_status(t, id, S3_SSH3_SFTP_FX_FAILURE);
    }

    slot->dir = d;

    h.data = slot->id;
    h.len = 8;

    return s3_srv_reply_handle(t, id, &h);
}

/*
 * the READDIR of the pkg/sftp shape: one NAME reply with the whole
 * remaining stream, the next request on the drained handle is EOF;
 * the batch cut keeps the reply below the cap, the rest of the stream
 * waits for the next request
 */

static s3_int_t
s3_srv_readdir(s3_ssh3_sftp_srv_t *t, uint32_t id, const s3_str_t *body)
{
    s3_ssh3_sftp_name_t       *names;
    s3_ssh3_sftp_srv_handle_t *slot;
    struct dirent             *e;
    struct stat                st;
    s3_str_t                   h;
    u_char                    *blob, ln[S3_SSH3_SFTP_SRV_LONGNAME_MAX];
    size_t                     budget, names_max, names_n, blob_len, nl, ll, est;
    uint32_t                   count;
    u_char                    *p;
    uintptr_t                  n;
    DIR                       *d;
    int                        dfd;

    if (s3_ssh3_sftp_parse_handle_body(body, &h) != S3_OK) {
        return s3_srv_reply_status(t, id, S3_SSH3_SFTP_FX_BAD_MESSAGE);
    }

    slot = s3_srv_handle_find(t, &h);

    if (slot == NULL) {
        return s3_srv_reply_status(t, id, S3_SSH3_SFTP_FX_NO_SUCH_FILE);
    }

    if (slot->dir == NULL) {
        return s3_srv_reply_status(t, id, S3_SSH3_SFTP_FX_FAILURE);
    }

    d = (DIR *)slot->dir;
    dfd = dirfd(d);

    budget = S3_SSH3_SFTP_SRV_REPLY_MAX - 16;

    /* the worst case bounds: no growth, the views stay stable */

    names_max = budget / 32;

    names = s3_alloc(names_max * sizeof(s3_ssh3_sftp_name_t), t->pool->log);
    blob = s3_alloc(budget, t->pool->log);

    if (names == NULL || blob == NULL) {
        s3_free(names);
        s3_free(blob);
        return S3_ERROR;
    }

    names_n = 0;
    blob_len = 0;
    est = 13 + 4;

    for (;;) {

        e = readdir(d);

        if (e == NULL) {
            break;
        }

        /* the reference ReadDir skips the dot entries */

        if (e->d_name[0] == '.' &&
            (e->d_name[1] == '\0' || (e->d_name[1] == '.' && e->d_name[2] == '\0'))) {
            continue;
        }

        /* the reference skips the entries raced out of the listing */

        if (fstatat(dfd, e->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
            continue;
        }

        nl = s3_strlen((const u_char *)e->d_name);
        ll = s3_srv_longname(&st, e->d_name, ln, sizeof(ln));

        if (names_n >= names_max || blob_len + nl + ll > budget) {
            break;
        }

        s3_memcpy(blob + blob_len, e->d_name, nl);
        names[names_n].filename.data = blob + blob_len;
        names[names_n].filename.len = nl;
        blob_len += nl;

        s3_memcpy(blob + blob_len, ln, ll);
        names[names_n].longname.data = blob + blob_len;
        names[names_n].longname.len = ll;
        blob_len += ll;

        s3_srv_attrs_from_stat(&names[names_n].attrs, &st);

        names_n++;
        est += 4 + nl + 4 + ll + S3_SSH3_SFTP_SRV_ATTRS_LEN;

        if (est + S3_SSH3_SFTP_SRV_ENTRY_MAX > budget) {
            break;
        }
    }

    if (names_n == 0) {
        s3_free(names);
        s3_free(blob);
        return s3_srv_reply_status(t, id, S3_SSH3_SFTP_FX_EOF);
    }

    count = (uint32_t)names_n;

    n = s3_ssh3_sftp_encode_name(NULL, id, names, count);
    p = s3_srv_out_reserve(t, n);

    if (p == NULL) {
        s3_free(names);
        s3_free(blob);
        return S3_ERROR;
    }

    (void)s3_ssh3_sftp_encode_name(p, id, names, count);
    t->out_len += n;

    s3_free(names);
    s3_free(blob);

    return S3_OK;
}

/* one parent level of the reference MkdirAll, the prefix [0, at) */

static s3_int_t
s3_srv_mkdir_one(s3_ssh3_sftp_srv_t *t, char *path, size_t at)
{
    char saved;
    int  rc;

    saved = path[at];
    path[at] = '\0';

    rc = mkdir(path, 0755);

    path[at] = saved;

    if (rc != 0) {

        /* the parents may exist already, the reference tolerates it */

        if (errno == EEXIST) {
            return S3_OK;
        }

        return S3_ERROR;
    }

    /* the created level belongs to the user (chownToUserRoot), best
       effort like the reference */

    if (chown(path, (uid_t)t->uid, (gid_t)t->gid) != 0) {
        /* the reference logs and moves on */
    }

    return S3_OK;
}

static s3_int_t
s3_srv_mkdir_all(s3_ssh3_sftp_srv_t *t, char *path)
{
    size_t base, i, len;

    len = strlen(path);
    base = t->home.len;

    if (base == 1) {
        base = 0; /* the "/" jail: only the leading slash is fixed */
    }

    if (base < len && path[base] == '/') {
        base++;
    }

    /* everything but the final level, the parents may exist already */

    for (i = base; i < len; i++) {

        if (path[i] != '/') {
            continue;
        }

        if (s3_srv_mkdir_one(t, path, i) != S3_OK) {
            return S3_ERROR;
        }
    }

    return S3_OK;
}

static s3_int_t
s3_srv_mkdir(s3_ssh3_sftp_srv_t *t, uint32_t id, const s3_str_t *body)
{
    const u_char *pos, *end;
    s3_str_t      path, jailed;
    int           rc;

    pos = body->data;
    end = pos + body->len;

    /* the path rides first, the attribute block after it is ignored */

    if (s3_ssh3_sftp_parse_string(&pos, end, &path) != S3_OK) {
        return s3_srv_reply_status(t, id, S3_SSH3_SFTP_FX_BAD_MESSAGE);
    }

    rc = s3_srv_jailed(t, id, &path, &jailed);

    if (rc != S3_OK) {
        return rc == S3_DECLINED ? S3_OK : S3_ERROR;
    }

    /* the missing parents go first (the reference MkdirAll) */

    if (s3_srv_mkdir_all(t, (char *)jailed.data) != S3_OK) {
        return s3_srv_reply_status(t, id, s3_srv_errno_status(errno));
    }

    /* the final level: every failure, EEXIST included, is an error
       (the brief verdict: the existing target is os.ErrExist) */

    if (mkdir((const char *)jailed.data, 0755) != 0) {
        return s3_srv_reply_status(t, id, s3_srv_errno_status(errno));
    }

    if (chown((const char *)jailed.data, (uid_t)t->uid, (gid_t)t->gid) != 0) {
        /* the reference logs and moves on */
    }

    return s3_srv_reply_status(t, id, S3_SSH3_SFTP_FX_OK);
}

static s3_int_t
s3_srv_rmdir(s3_ssh3_sftp_srv_t *t, uint32_t id, const s3_str_t *body)
{
    s3_str_t path, jailed;
    int      rc;

    if (s3_ssh3_sftp_parse_path_body(body, &path) != S3_OK) {
        return s3_srv_reply_status(t, id, S3_SSH3_SFTP_FX_BAD_MESSAGE);
    }

    rc = s3_srv_jailed(t, id, &path, &jailed);

    if (rc != S3_OK) {
        return rc == S3_DECLINED ? S3_OK : S3_ERROR;
    }

    if (rmdir((const char *)jailed.data) != 0) {
        return s3_srv_reply_status(t, id, s3_srv_errno_status(errno));
    }

    return s3_srv_reply_status(t, id, S3_SSH3_SFTP_FX_OK);
}

static s3_int_t
s3_srv_remove(s3_ssh3_sftp_srv_t *t, uint32_t id, const s3_str_t *body)
{
    s3_str_t path, jailed;
    int      rc;

    if (s3_ssh3_sftp_parse_path_body(body, &path) != S3_OK) {
        return s3_srv_reply_status(t, id, S3_SSH3_SFTP_FX_BAD_MESSAGE);
    }

    rc = s3_srv_jailed(t, id, &path, &jailed);

    if (rc != S3_OK) {
        return rc == S3_DECLINED ? S3_OK : S3_ERROR;
    }

    if (unlink((const char *)jailed.data) != 0) {
        return s3_srv_reply_status(t, id, s3_srv_errno_status(errno));
    }

    return s3_srv_reply_status(t, id, S3_SSH3_SFTP_FX_OK);
}

static s3_int_t
s3_srv_rename(s3_ssh3_sftp_srv_t *t, uint32_t id, const s3_str_t *body)
{
    s3_str_t    old_path, new_path, jold, jnew;
    struct stat st;
    int         rc;

    if (s3_ssh3_sftp_parse_rename_body(body, &old_path, &new_path) != S3_OK) {
        return s3_srv_reply_status(t, id, S3_SSH3_SFTP_FX_BAD_MESSAGE);
    }

    rc = s3_srv_jailed(t, id, &old_path, &jold);

    if (rc != S3_OK) {
        return rc == S3_DECLINED ? S3_OK : S3_ERROR;
    }

    rc = s3_srv_jailed(t, id, &new_path, &jnew);

    if (rc != S3_OK) {
        return rc == S3_DECLINED ? S3_OK : S3_ERROR;
    }

    /* the reference verdict: an existing target is os.ErrExist */

    if (lstat((const char *)jnew.data, &st) == 0) {
        return s3_srv_reply_status(t, id, S3_SSH3_SFTP_FX_FAILURE);
    }

    if (rename((const char *)jold.data, (const char *)jnew.data) != 0) {
        return s3_srv_reply_status(t, id, s3_srv_errno_status(errno));
    }

    return s3_srv_reply_status(t, id, S3_SSH3_SFTP_FX_OK);
}

static s3_int_t
s3_srv_realpath(s3_ssh3_sftp_srv_t *t, uint32_t id, const s3_str_t *body)
{
    s3_str_t path, jailed;
    int      rc;

    if (s3_ssh3_sftp_parse_path_body(body, &path) != S3_OK) {
        return s3_srv_reply_status(t, id, S3_SSH3_SFTP_FX_BAD_MESSAGE);
    }

    rc = s3_srv_jailed(t, id, &path, &jailed);

    if (rc != S3_OK) {
        return rc == S3_DECLINED ? S3_OK : S3_ERROR;
    }

    return s3_srv_reply_name1(t, id, &jailed);
}

static s3_int_t
s3_srv_dispatch(s3_ssh3_sftp_srv_t *t, s3_ssh3_sftp_pkt_t *pkt)
{
    uint32_t id = pkt->has_id ? pkt->request_id : 0;

    if (pkt->type == S3_SSH3_SFTP_INIT) {
        t->negotiated = 1;
        return s3_srv_reply_version(t, S3_SSH3_SFTP_PROTOCOL_VERSION);
    }

    /* nothing but the INIT talks before the version exchange */

    if (!t->negotiated) {
        return s3_srv_reply_status(t, id, S3_SSH3_SFTP_FX_BAD_MESSAGE);
    }

    switch (pkt->type) {

    case S3_SSH3_SFTP_OPEN:
        return s3_srv_open(t, id, &pkt->body);

    case S3_SSH3_SFTP_READ:
        return s3_srv_read(t, id, &pkt->body);

    case S3_SSH3_SFTP_WRITE:
        return s3_srv_write(t, id, &pkt->body);

    case S3_SSH3_SFTP_CLOSE:
        return s3_srv_close(t, id, &pkt->body);

    case S3_SSH3_SFTP_FSTAT:
        return s3_srv_fstat(t, id, &pkt->body);

    case S3_SSH3_SFTP_LSTAT:
        return s3_srv_stat(t, id, &pkt->body, 1);

    case S3_SSH3_SFTP_STAT:
        return s3_srv_stat(t, id, &pkt->body, 0);

    case S3_SSH3_SFTP_OPENDIR:
        return s3_srv_opendir(t, id, &pkt->body);

    case S3_SSH3_SFTP_READDIR:
        return s3_srv_readdir(t, id, &pkt->body);

    case S3_SSH3_SFTP_REMOVE:
        return s3_srv_remove(t, id, &pkt->body);

    case S3_SSH3_SFTP_MKDIR:
        return s3_srv_mkdir(t, id, &pkt->body);

    case S3_SSH3_SFTP_RMDIR:
        return s3_srv_rmdir(t, id, &pkt->body);

    case S3_SSH3_SFTP_REALPATH:
        return s3_srv_realpath(t, id, &pkt->body);

    case S3_SSH3_SFTP_RENAME:
        return s3_srv_rename(t, id, &pkt->body);

    case S3_SSH3_SFTP_SETSTAT:
    case S3_SSH3_SFTP_FSETSTAT:
    case S3_SSH3_SFTP_EXTENDED:
        return s3_srv_reply_status(t, id, S3_SSH3_SFTP_FX_OP_UNSUPPORTED);
    }

    return s3_srv_reply_status(t, id, S3_SSH3_SFTP_FX_OP_UNSUPPORTED);
}
