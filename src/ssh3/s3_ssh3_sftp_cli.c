/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the client driver of the "sftp" channel, the port of the reference
 * cmd/sftp_client.go (runFileTransfer/uploadFile/downloadFileTo/
 * copyWithOffset/verifyRemoteChecksum/uploadDir/downloadDir): the
 * scp-style transfer engine speaking SFTP v3 over the caller's
 * channel byte stream, the framing stays in the channel layer
 *
 * the driver never blocks: the requests accumulate in the out
 * buffer, the replies ride in through input(); the streaming phases
 * keep a window of S3_SSH3_SFTP_CLI_INFLIGHT requests in flight, the
 * SFTP server answers the byte stream sequentially, so every reply
 * must carry the id of the oldest outstanding request - anything
 * else after the retransmission-free pipeline is a protocol error,
 * like every unbounded frame shape
 *
 * one operation runs at a time: the single put/get or the -r walk
 * over the directory tree; the walk keeps the stack of the directory
 * frames in the op context, the per-file transfers reuse the single
 * file phases; a failed file inside the -r walk does not abort it,
 * the reference counts the failures and walks on (a failure under an
 * outstanding window kills the operation, the train cannot re-phase)
 *
 * the checksum verification re-reads the remote side through SHA-256
 * and compares it with the local file, on the verify flag or
 * automatically above S3_SSH3_SFTP_CLI_CHECKSUM_AUTO_THRESHOLD
 */

#include <s3_core.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <unistd.h>

#include <stdio.h>
#include <s3_ssh3_sftp_cli.h>
#include <s3_ssh3_sftp_codec.h>

#if (S3_WIN32)

/* the CRT descriptor surface of the win32 file arm (the
 * _open_osfhandle pair) and the struct timespec of the stamp */

#include <io.h>
#include <time.h>

#endif

/* the wchar scratch of the win32 path conversions (1024 wchars
 * cover the paths this driver works with, a longer one errors) */

#define S3_SSH3_SFTP_CLI_PATH_W 1024

/*
 * the local file surface: the POSIX-shaped helpers keep the driver
 * body identical on both sides; the win32 arm converts the UTF-8
 * paths to UTF-16 on every syscall (the ANSI argv and the narrow
 * CRT calls would mangle the non-ASCII names) and keeps the
 * transfer fd as the CRT descriptor of the file handle
 */

#if (S3_WIN32)

typedef struct s3_cli_fs_dir_s s3_cli_fs_dir_t;

#else

typedef DIR s3_cli_fs_dir_t;

#endif

typedef struct {
    char *d_name;
} s3_cli_fs_ent_t;

static int              s3_cli_fs_open_rd(const char *path);
static int              s3_cli_fs_open_rdwr(const char *path);
static int              s3_cli_fs_open_creat(const char *path, unsigned trunc);
static int              s3_cli_fs_pread(int fd, void *buf, size_t len, int64_t off);
static int              s3_cli_fs_pwrite(int fd, const void *buf, size_t len, int64_t off);
static int              s3_cli_fs_stat(const char *path, struct stat *st);
static int              s3_cli_fs_fstat(int fd, struct stat *st);
static int              s3_cli_fs_futimens(int fd, const struct timespec ts[2]);
static int              s3_cli_fs_mkdir(const char *path);
static s3_cli_fs_dir_t *s3_cli_fs_opendir(const char *path);
static s3_cli_fs_ent_t *s3_cli_fs_readdir(s3_cli_fs_dir_t *dir);
static void             s3_cli_fs_closedir(s3_cli_fs_dir_t *dir);

#if (S3_WIN32)

/* the win32 arm: io.h and fileapi.h ride the os layer headers
 * through windows.h (s3_base.h includes it first), every path
 * converts UTF-8 to UTF-16 before the syscall */

static int
s3_cli_fs_open_rd(const char *path)
{
    wchar_t w[S3_SSH3_SFTP_CLI_PATH_W];
    HANDLE  h;
    int     n;

    n = MultiByteToWideChar(CP_UTF8, 0, path, -1, w, S3_SSH3_SFTP_CLI_PATH_W);

    if (n <= 0) {
        return -1;
    }

    h = CreateFileW(w, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, NULL);

    if (h == INVALID_HANDLE_VALUE) {
        return -1;
    }

    return _open_osfhandle((intptr_t)h, _O_RDONLY);
}

static int
s3_cli_fs_open_rdwr(const char *path)
{
    wchar_t w[S3_SSH3_SFTP_CLI_PATH_W];
    HANDLE  h;
    int     n;

    n = MultiByteToWideChar(CP_UTF8, 0, path, -1, w, S3_SSH3_SFTP_CLI_PATH_W);

    if (n <= 0) {
        return -1;
    }

    h = CreateFileW(w, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, NULL);

    if (h == INVALID_HANDLE_VALUE) {
        return -1;
    }

    return _open_osfhandle((intptr_t)h, _O_RDWR);
}

static int
s3_cli_fs_open_creat(const char *path, unsigned trunc)
{
    wchar_t w[S3_SSH3_SFTP_CLI_PATH_W];
    HANDLE  h;
    DWORD   mode = trunc ? CREATE_ALWAYS : OPEN_ALWAYS;
    int     n;

    n = MultiByteToWideChar(CP_UTF8, 0, path, -1, w, S3_SSH3_SFTP_CLI_PATH_W);

    if (n <= 0) {
        return -1;
    }

    h = CreateFileW(w, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, mode,
                    FILE_ATTRIBUTE_NORMAL, NULL);

    if (h == INVALID_HANDLE_VALUE) {
        return -1;
    }

    return _open_osfhandle((intptr_t)h, _O_RDWR);
}

static int
s3_cli_fs_pread(int fd, void *buf, size_t len, int64_t off)
{
    HANDLE        h = (HANDLE)_get_osfhandle(fd);
    LARGE_INTEGER li, saved;
    DWORD         got = 0;
    BOOL          ok;

    if (h == INVALID_HANDLE_VALUE) {
        return -1;
    }

    li.QuadPart = 0;

    if (SetFilePointerEx(h, li, &saved, FILE_CURRENT) == 0) {
        return -1;
    }

    li.QuadPart = (LONGLONG)off;

    if (SetFilePointerEx(h, li, NULL, FILE_BEGIN) == 0) {
        return -1;
    }

    ok = ReadFile(h, buf, (DWORD)len, &got, NULL);

    (void)SetFilePointerEx(h, saved, NULL, FILE_BEGIN);

    return ok ? (int)got : -1;
}

static int
s3_cli_fs_pwrite(int fd, const void *buf, size_t len, int64_t off)
{
    HANDLE        h = (HANDLE)_get_osfhandle(fd);
    LARGE_INTEGER li, saved;
    DWORD         put = 0;
    BOOL          ok;

    if (h == INVALID_HANDLE_VALUE) {
        return -1;
    }

    li.QuadPart = 0;

    if (SetFilePointerEx(h, li, &saved, FILE_CURRENT) == 0) {
        return -1;
    }

    li.QuadPart = (LONGLONG)off;

    if (SetFilePointerEx(h, li, NULL, FILE_BEGIN) == 0) {
        return -1;
    }

    ok = WriteFile(h, buf, (DWORD)len, &put, NULL);

    (void)SetFilePointerEx(h, saved, NULL, FILE_BEGIN);

    return ok ? (int)put : -1;
}

static void
s3_cli_fs_stat_fill(struct stat *st, const WIN32_FILE_ATTRIBUTE_DATA *fa)
{
    int64_t ft;

    s3_memzero(st, sizeof(*st));

    ft = ((int64_t)fa->ftLastWriteTime.dwHighDateTime << 32) | fa->ftLastWriteTime.dwLowDateTime;

    st->st_size = (off_t)(((int64_t)fa->nFileSizeHigh << 32) | fa->nFileSizeLow);
    st->st_mtime = (time_t)(ft / 10000000 - 11644473600);
    st->st_mode = (fa->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? S_IFDIR : S_IFREG;
}

static int
s3_cli_fs_stat(const char *path, struct stat *st)
{
    wchar_t                   w[S3_SSH3_SFTP_CLI_PATH_W];
    WIN32_FILE_ATTRIBUTE_DATA fa;
    int                       n;

    n = MultiByteToWideChar(CP_UTF8, 0, path, -1, w, S3_SSH3_SFTP_CLI_PATH_W);

    if (n <= 0) {
        return -1;
    }

    if (GetFileAttributesExW(w, GetFileExInfoStandard, &fa) == 0) {
        return -1;
    }

    s3_cli_fs_stat_fill(st, &fa);

    return 0;
}

static int
s3_cli_fs_fstat(int fd, struct stat *st)
{
    HANDLE                     h = (HANDLE)_get_osfhandle(fd);
    BY_HANDLE_FILE_INFORMATION fi;
    WIN32_FILE_ATTRIBUTE_DATA  fa;

    if (h == INVALID_HANDLE_VALUE) {
        return -1;
    }

    if (GetFileInformationByHandle(h, &fi) == 0) {
        return -1;
    }

    fa.dwFileAttributes = fi.dwFileAttributes;
    fa.ftCreationTime = fi.ftCreationTime;
    fa.ftLastAccessTime = fi.ftLastAccessTime;
    fa.ftLastWriteTime = fi.ftLastWriteTime;
    fa.nFileSizeHigh = fi.nFileSizeHigh;
    fa.nFileSizeLow = fi.nFileSizeLow;

    s3_cli_fs_stat_fill(st, &fa);

    return 0;
}

static int
s3_cli_fs_futimens(int fd, const struct timespec ts[2])
{
    HANDLE   h = (HANDLE)_get_osfhandle(fd);
    FILETIME ft[2];
    int64_t  v;
    int      i;

    if (h == INVALID_HANDLE_VALUE) {
        return -1;
    }

    for (i = 0; i < 2; i++) {

        v = ((int64_t)ts[i].tv_sec + 11644473600) * 10000000;

        ft[i].dwLowDateTime = (DWORD)(v & 0xffffffff);
        ft[i].dwHighDateTime = (DWORD)((uint64_t)v >> 32);
    }

    return SetFileTime(h, NULL, &ft[0], &ft[1]) ? 0 : -1;
}

static int
s3_cli_fs_mkdir(const char *path)
{
    wchar_t w[S3_SSH3_SFTP_CLI_PATH_W];
    int     n;

    n = MultiByteToWideChar(CP_UTF8, 0, path, -1, w, S3_SSH3_SFTP_CLI_PATH_W);

    if (n <= 0) {
        return -1;
    }

    if (CreateDirectoryW(w, NULL) == 0) {

        if (GetLastError() == ERROR_ALREADY_EXISTS) {
            errno = EEXIST;
        }

        return -1;
    }

    return 0;
}

/* the -r walk over the wide enumeration, the names come back UTF-8 */

struct s3_cli_fs_dir_s {
    HANDLE           find;
    WIN32_FIND_DATAW fd;
    s3_cli_fs_ent_t  ent;
    char             name[S3_SSH3_SFTP_CLI_PATH_W];
    unsigned         first;
};

static s3_cli_fs_dir_t *
s3_cli_fs_opendir(const char *path)
{
    wchar_t          w[S3_SSH3_SFTP_CLI_PATH_W], pat[S3_SSH3_SFTP_CLI_PATH_W];
    s3_cli_fs_dir_t *d;
    int              n;

    n = MultiByteToWideChar(CP_UTF8, 0, path, -1, w, S3_SSH3_SFTP_CLI_PATH_W);

    if (n <= 0 || n + 2 >= S3_SSH3_SFTP_CLI_PATH_W) {
        return NULL;
    }

    _snwprintf(pat, S3_SSH3_SFTP_CLI_PATH_W - 1, L"%s\\*", w);
    pat[S3_SSH3_SFTP_CLI_PATH_W - 1] = L'\0';

    d = (s3_cli_fs_dir_t *)malloc(sizeof(*d));

    if (d == NULL) {
        return NULL;
    }

    d->first = 1;
    d->find = FindFirstFileW(pat, &d->fd);

    if (d->find == INVALID_HANDLE_VALUE) {
        free(d);
        return NULL;
    }

    return d;
}

static s3_cli_fs_ent_t *
s3_cli_fs_readdir(s3_cli_fs_dir_t *d)
{
    int n;

    if (!d->first) {

        if (FindNextFileW(d->find, &d->fd) == 0) {
            return NULL;
        }
    }

    d->first = 0;

    n = WideCharToMultiByte(CP_UTF8, 0, d->fd.cFileName, -1, d->name, (int)sizeof(d->name), NULL,
                            NULL);

    if (n <= 0) {
        return NULL;
    }

    d->ent.d_name = d->name;

    return &d->ent;
}

static void
s3_cli_fs_closedir(s3_cli_fs_dir_t *d)
{
    FindClose(d->find);
    free(d);
}

#else

/* the unix arm: the plain POSIX calls */

static int
s3_cli_fs_open_rd(const char *path)
{
    return open(path, O_RDONLY);
}

static int
s3_cli_fs_open_rdwr(const char *path)
{
    return open(path, O_RDWR);
}

static int
s3_cli_fs_open_creat(const char *path, unsigned trunc)
{
    return open(path, O_RDWR | O_CREAT | (trunc ? O_TRUNC : 0), 0644);
}

static int
s3_cli_fs_pread(int fd, void *buf, size_t len, int64_t off)
{
    return (int)pread(fd, buf, len, (off_t)off);
}

static int
s3_cli_fs_pwrite(int fd, const void *buf, size_t len, int64_t off)
{
    return (int)pwrite(fd, buf, len, (off_t)off);
}

static int
s3_cli_fs_stat(const char *path, struct stat *st)
{
    return stat(path, st);
}

static int
s3_cli_fs_fstat(int fd, struct stat *st)
{
    return fstat(fd, st);
}

static int
s3_cli_fs_futimens(int fd, const struct timespec ts[2])
{
    return futimens(fd, ts);
}

static int
s3_cli_fs_mkdir(const char *path)
{
    return mkdir(path, 0755);
}

static s3_cli_fs_dir_t *
s3_cli_fs_opendir(const char *path)
{
    return opendir(path);
}

static s3_cli_fs_ent_t *
s3_cli_fs_readdir(s3_cli_fs_dir_t *dir)
{
    static s3_cli_fs_ent_t ent;
    struct dirent         *de = readdir(dir);

    if (de == NULL) {
        return NULL;
    }

    ent.d_name = de->d_name;

    return &ent;
}

static void
s3_cli_fs_closedir(s3_cli_fs_dir_t *dir)
{
    (void)closedir(dir);
}

#endif

/* the transfer chunk lives in the header: the callers size their
 * drains against it (the reference copyWithOffset() buffer) */

/* the initial capacity of the pending and out buffers, doubled on demand */

#define S3_SSH3_SFTP_CLI_BUF_INIT 4096

/* the initial capacity of the -r frame stack, doubled on demand */

#define S3_SSH3_SFTP_CLI_FRAMES_INIT 4

/* the SHA-256 digest length of the verification tail */

#define S3_SSH3_SFTP_CLI_SHA256_LEN 32

/* the POSIX mode bits inside the v3 attrs permissions */

#define S3_SSH3_SFTP_CLI_S_IFMT  0170000
#define S3_SSH3_SFTP_CLI_S_IFDIR 0040000
#define S3_SSH3_SFTP_CLI_S_IFREG 0100000

/* the operation kinds */

#define S3_SSH3_SFTP_CLI_OP_PUT   0
#define S3_SSH3_SFTP_CLI_OP_GET   1
#define S3_SSH3_SFTP_CLI_OP_PUT_R 2
#define S3_SSH3_SFTP_CLI_OP_GET_R 3

/* the phases of the state machine, one request in flight per phase */

enum {
    PH_PUT_STAT = 1, /* the resume STAT of the remote file */
    PH_PUT_OPEN,     /* the OPEN of the remote file for writing */
    PH_PUT_WRITE,    /* the WRITE chunks of the payload */
    PH_PUT_CLOSE,    /* the CLOSE of the written file */
    PH_PUT_SETSTAT,  /* the mtime stamp of the written file (R7) */
    PH_GET_STAT,     /* the STAT of the remote file to download */
    PH_GET_OPEN,     /* the OPEN of the remote file for reading */
    PH_GET_READ,     /* the READ chunks of the payload */
    PH_GET_CLOSE,    /* the CLOSE of the read file */
    PH_VERIFY_STAT,  /* the size check before the checksum */
    PH_VERIFY_OPEN,  /* the re-OPEN for the checksum read */
    PH_VERIFY_READ,  /* the checksum read of the remote side */
    PH_VERIFY_CLOSE, /* the CLOSE and the digest compare */
    PH_MKDIR,        /* one level of the remote mkdir -p */
    PH_MKDIR_STAT,   /* the EEXIST tolerance: the STAT of the level */
    PH_PUT_R_WALK,   /* the synchronous readdir walk of uploadDir */
    PH_GET_R_WALK,   /* the entry processing of downloadDir */
    PH_GET_R_OPENDIR,
    PH_GET_R_READDIR,
    PH_GET_R_CLOSE
};

/*
 * one entry of the copied NAME batch: the parsed strings are views
 * into the receive buffer, the walk outlives many overwrites of it
 */

typedef struct {
    char    *name;
    uint64_t size;
    uint32_t mtime; /* the ACMODTIME mtime of the batch entry, 0 when absent */
    unsigned is_dir : 1;
    unsigned is_reg : 1;
} s3_ssh3_sftp_cli_entry_t;

/* one level of the -r walk: the local readdir or the remote OPENDIR */

typedef struct {
    char                     *local_dir;
    char                     *remote_dir;
    s3_cli_fs_dir_t          *dir;    /* the put_r side */
    u_char                   *handle; /* the get_r side */
    size_t                    handle_len;
    s3_ssh3_sftp_cli_entry_t *entries;
    uint32_t                  entry_count;
    uint32_t                  entry_pos;
} s3_ssh3_sftp_cli_frame_t;

/* the opaque operation context of the header */

typedef struct {
    int kind;
    int phase;

    char *local_path;
    char *remote_path;

    int      fd;        /* the local file of the transfer */
    uint32_t expect_id; /* the id of the oldest outstanding request */
    uint64_t file_size; /* the local size on put, the remote on get */
    uint32_t mtime;     /* the local mtime on put, the remote on get (R7) */
    uint64_t offset;    /* the receive cursor (the pwrite position, the progress) */
    uint64_t emit_off;  /* the wire offset of the next train request */
    uint32_t inflight;  /* the requests emitted without a reply */

    /*
     * the payload lens of the outstanding WRITE train, the replies
     * ride in order so the cursor adds the front entry per STATUS OK
     */

    uint32_t io_ring[S3_SSH3_SFTP_CLI_INFLIGHT];
    uint32_t io_head;
    uint32_t io_tail;

    u_char *handle;
    size_t  handle_len;

    u_char *io_buf;

    unsigned resume : 1;
    unsigned verify : 1;
    unsigned trunc : 1;
    unsigned stamp : 1; /* the transfer wrote data: the peer takes the mtime (R7) */

    /* the checksum tail */

    void    *md; /* EVP_MD_CTX */
    u_char   digest[EVP_MAX_MD_SIZE];
    uint64_t hash_len;

    /* the remote mkdir -p of the upload walk */

    char  *mkdir_path;
    size_t mkdir_len;
    char  *pending_local; /* the frame waiting for its levels */
    char  *pending_remote;

    /* the -r frame stack */

    s3_ssh3_sftp_cli_frame_t *frames;
    uint32_t                  frame_count;
    uint32_t                  frame_cap;

    /* the reference counts the per-file failures of the walk */

    unsigned failed : 1;
    uint32_t fail_status;
} s3_ssh3_sftp_cli_op_t;

typedef uintptr_t (*s3_cli_encode_path_pt)(u_char *p, uint32_t id, const s3_str_t *path);

typedef uintptr_t (*s3_cli_encode_handle_pt)(u_char *p, uint32_t id, const s3_str_t *handle);

static s3_int_t s3_cli_buf_grow(s3_pool_t *pool, u_char **buf, size_t len, size_t *cap,
                                size_t need);
static void     s3_cli_commit(s3_ssh3_sftp_cli_t *t, uintptr_t need, unsigned tracked);
static s3_int_t s3_cli_emit_path(s3_ssh3_sftp_cli_t *t, s3_cli_encode_path_pt encode,
                                 const char *path);
static s3_int_t s3_cli_emit_handle(s3_ssh3_sftp_cli_t *t, s3_cli_encode_handle_pt encode,
                                   const u_char *handle, size_t handle_len);
static s3_int_t s3_cli_emit_open(s3_ssh3_sftp_cli_t *t, const char *path, unsigned creat);
static s3_int_t s3_cli_emit_read(s3_ssh3_sftp_cli_t *t, uint64_t offset, size_t len);
static s3_int_t s3_cli_emit_write(s3_ssh3_sftp_cli_t *t, const u_char *data, size_t len);
static s3_int_t s3_cli_emit_mkdir(s3_ssh3_sftp_cli_t *t, const char *path, size_t len);
static s3_int_t s3_cli_emit_setstat(s3_ssh3_sftp_cli_t *t, const char *path);

static char    *s3_cli_strdup(s3_pool_t *pool, const char *s);
static char    *s3_cli_path_join(s3_pool_t *pool, const char *dir, const char *name);
static void     s3_cli_progress(s3_ssh3_sftp_cli_t *t, uint64_t sent, uint64_t total);
static void     s3_cli_close_file(s3_ssh3_sftp_cli_t *t);
static void     s3_cli_digest_final(s3_ssh3_sftp_cli_t *t);
static void     s3_cli_done_op(s3_ssh3_sftp_cli_t *t);
static void     s3_cli_fail_op(s3_ssh3_sftp_cli_t *t, uint32_t code);
static void     s3_cli_file_fail(s3_ssh3_sftp_cli_t *t, uint32_t code);
static void     s3_cli_transfer_fail(s3_ssh3_sftp_cli_t *t, uint32_t code);
static void     s3_cli_transfer_done(s3_ssh3_sftp_cli_t *t);
static void     s3_cli_stamp_done(s3_ssh3_sftp_cli_t *t);
static s3_int_t s3_cli_handle_copy(s3_ssh3_sftp_cli_t *t, u_char **dst, size_t *dst_len,
                                   const s3_str_t *handle);
static int      s3_cli_attrs_is_dir(const s3_ssh3_sftp_attrs_t *a);
static int      s3_cli_attrs_is_reg(const s3_ssh3_sftp_attrs_t *a);
static int      s3_cli_dot_name(const char *name);
static size_t   s3_cli_mkdir_next(const char *path, size_t prev_len);
static int      s3_cli_mkdir_local_all(const char *path);
static int      s3_cli_local_digest(s3_ssh3_sftp_cli_t *t, u_char *out);

static s3_ssh3_sftp_cli_frame_t *s3_cli_frame_push(s3_ssh3_sftp_cli_t *t, const char *local_dir,
                                                   const char *remote_dir);
static s3_int_t                  s3_cli_emit_init(s3_ssh3_sftp_cli_t *t);
static s3_int_t                  s3_cli_parse_status_body(const s3_str_t *body, uint32_t *code);
static s3_int_t s3_cli_on_status(s3_ssh3_sftp_cli_t *t, const s3_str_t *body, uint32_t *code);
static s3_int_t s3_cli_parse_handle_body(const s3_str_t *body, s3_str_t *handle);
static s3_int_t s3_cli_parse_data_body(const s3_str_t *body, s3_str_t *data);
static s3_int_t s3_cli_parse_attrs_body(const s3_str_t *body, s3_ssh3_sftp_attrs_t *a);
static s3_int_t s3_cli_parse_name_batch(s3_ssh3_sftp_cli_t *t, const s3_str_t *body);
static void     s3_cli_get_local_open(s3_ssh3_sftp_cli_t *t);
static s3_int_t s3_cli_put_r_walk(s3_ssh3_sftp_cli_t *t);
static s3_int_t s3_cli_get_r_walk(s3_ssh3_sftp_cli_t *t);
static s3_int_t s3_cli_step(s3_ssh3_sftp_cli_t *t);
static s3_int_t s3_cli_dispatch(s3_ssh3_sftp_cli_t *t, s3_ssh3_sftp_pkt_t *pkt);
static s3_int_t s3_cli_reset(s3_ssh3_sftp_cli_t *t);

static s3_int_t
s3_cli_buf_grow(s3_pool_t *pool, u_char **buf, size_t len, size_t *cap, size_t need)
{
    u_char *p;
    size_t  want;

    if (*cap - len >= need) {
        return S3_OK;
    }

    want = *cap ? *cap : S3_SSH3_SFTP_CLI_BUF_INIT;

    while (want - len < need) {

        if (want > SIZE_MAX / 2) {
            return S3_ERROR;
        }

        want *= 2;
    }

    p = s3_pnalloc(pool, want);

    if (p == NULL) {
        return S3_ERROR;
    }

    if (len > 0) {
        s3_memcpy(p, *buf, len);
    }

    *buf = p;
    *cap = want;

    return S3_OK;
}

static void
s3_cli_commit(s3_ssh3_sftp_cli_t *t, uintptr_t need, unsigned tracked)
{
    s3_ssh3_sftp_cli_op_t *op = t->op;

    t->out_len += need;

    /* the first request of a train pins the reply id, the rest ride
     * the byte stream in order behind it; the INIT carries no request
     * id and stays out of the window */

    if (tracked) {

        if (op->inflight == 0) {
            op->expect_id = t->next_id;
        }

        op->inflight++;
    }

    t->next_id++;
}

static s3_int_t
s3_cli_emit_path(s3_ssh3_sftp_cli_t *t, s3_cli_encode_path_pt encode, const char *path)
{
    s3_str_t  s;
    uintptr_t need;

    s.len = s3_strlen(path);
    s.data = (u_char *)path;

    need = encode(NULL, t->next_id, &s);

    if (s3_cli_buf_grow(t->pool, &t->out, t->out_len, &t->out_cap, need) != S3_OK) {
        return S3_ERROR;
    }

    (void)encode(t->out + t->out_len, t->next_id, &s);
    s3_cli_commit(t, need, 1);

    return S3_OK;
}

static s3_int_t
s3_cli_emit_handle(s3_ssh3_sftp_cli_t *t, s3_cli_encode_handle_pt encode, const u_char *handle,
                   size_t handle_len)
{
    s3_str_t  s;
    uintptr_t need;

    s.len = handle_len;
    s.data = (u_char *)handle;

    need = encode(NULL, t->next_id, &s);

    if (s3_cli_buf_grow(t->pool, &t->out, t->out_len, &t->out_cap, need) != S3_OK) {
        return S3_ERROR;
    }

    (void)encode(t->out + t->out_len, t->next_id, &s);
    s3_cli_commit(t, need, 1);

    return S3_OK;
}

static s3_int_t
s3_cli_emit_open(s3_ssh3_sftp_cli_t *t, const char *path, unsigned creat)
{
    s3_ssh3_sftp_cli_op_t *op = t->op;
    s3_ssh3_sftp_attrs_t   attrs;
    s3_str_t               s;
    uint32_t               pflags;
    uintptr_t              need;

    s.len = s3_strlen(path);
    s.data = (u_char *)path;

    s3_memzero(&attrs, sizeof(attrs));

    if (creat) {

        /* the resume reopens without the trunc, the fresh put clears */

        pflags = S3_SSH3_SFTP_FXF_WRITE | S3_SSH3_SFTP_FXF_CREAT;

        if (op->trunc) {
            pflags |= S3_SSH3_SFTP_FXF_TRUNC;
        }

        attrs.flags = S3_SSH3_SFTP_ATTR_PERMISSION;
        attrs.perms = 0644;

    } else {
        pflags = S3_SSH3_SFTP_FXF_READ;
    }

    need = s3_ssh3_sftp_encode_open(NULL, t->next_id, &s, pflags, &attrs);

    if (s3_cli_buf_grow(t->pool, &t->out, t->out_len, &t->out_cap, need) != S3_OK) {
        return S3_ERROR;
    }

    (void)s3_ssh3_sftp_encode_open(t->out + t->out_len, t->next_id, &s, pflags, &attrs);
    s3_cli_commit(t, need, 1);

    return S3_OK;
}

static s3_int_t
s3_cli_emit_read(s3_ssh3_sftp_cli_t *t, uint64_t offset, size_t len)
{
    s3_ssh3_sftp_cli_op_t *op = t->op;
    s3_str_t               handle;
    uintptr_t              need;

    handle.len = op->handle_len;
    handle.data = op->handle;

    need = s3_ssh3_sftp_encode_read(NULL, t->next_id, &handle, offset, len);

    if (s3_cli_buf_grow(t->pool, &t->out, t->out_len, &t->out_cap, need) != S3_OK) {
        return S3_ERROR;
    }

    /* the emission cursor moves here, ahead of the outstanding
     * window; the receive cursor rides the replies.  The requested
     * len rides the train ring like the WRITE one: the DATA reply is
     * checked against it */

    op->io_ring[op->io_tail] = (uint32_t)len;
    op->io_tail = (op->io_tail + 1) % S3_SSH3_SFTP_CLI_INFLIGHT;

    op->emit_off = offset + len;

    (void)s3_ssh3_sftp_encode_read(t->out + t->out_len, t->next_id, &handle, offset, len);
    s3_cli_commit(t, need, 1);

    return S3_OK;
}

static s3_int_t
s3_cli_emit_write(s3_ssh3_sftp_cli_t *t, const u_char *data, size_t len)
{
    s3_ssh3_sftp_cli_op_t *op = t->op;
    s3_str_t               handle, payload;
    uintptr_t              need;

    handle.len = op->handle_len;
    handle.data = op->handle;

    payload.len = len;
    payload.data = (u_char *)data;

    need = s3_ssh3_sftp_encode_write(NULL, t->next_id, &handle, op->emit_off, &payload);

    if (s3_cli_buf_grow(t->pool, &t->out, t->out_len, &t->out_cap, need) != S3_OK) {
        return S3_ERROR;
    }

    /* the payload len rides the train ring, the STATUS OK of this
     * request advances the receive cursor by it; the emission cursor
     * moves here, ahead of the outstanding window */

    op->io_ring[op->io_tail] = (uint32_t)len;
    op->io_tail = (op->io_tail + 1) % S3_SSH3_SFTP_CLI_INFLIGHT;

    (void)s3_ssh3_sftp_encode_write(t->out + t->out_len, t->next_id, &handle, op->emit_off,
                                    &payload);

    op->emit_off += len;

    s3_cli_commit(t, need, 1);

    return S3_OK;
}

static s3_int_t
s3_cli_emit_mkdir(s3_ssh3_sftp_cli_t *t, const char *path, size_t len)
{
    s3_ssh3_sftp_attrs_t attrs;
    s3_str_t             s;
    uintptr_t            need;

    s.len = len;
    s.data = (u_char *)path;

    s3_memzero(&attrs, sizeof(attrs));
    attrs.flags = S3_SSH3_SFTP_ATTR_PERMISSION;
    attrs.perms = 0755;

    need = s3_ssh3_sftp_encode_mkdir(NULL, t->next_id, &s, &attrs);

    if (s3_cli_buf_grow(t->pool, &t->out, t->out_len, &t->out_cap, need) != S3_OK) {
        return S3_ERROR;
    }

    (void)s3_ssh3_sftp_encode_mkdir(t->out + t->out_len, t->next_id, &s, &attrs);
    s3_cli_commit(t, need, 1);

    return S3_OK;
}

/* the R7 stamp: the ACMODTIME pair carries the source mtime, the
 * reference Chtimes shape (both times ride the same value) */

static s3_int_t
s3_cli_emit_setstat(s3_ssh3_sftp_cli_t *t, const char *path)
{
    s3_ssh3_sftp_cli_op_t *op = t->op;
    s3_ssh3_sftp_attrs_t   attrs;
    s3_str_t               s;
    uintptr_t              need;

    s.len = s3_strlen(path);
    s.data = (u_char *)path;

    s3_memzero(&attrs, sizeof(attrs));
    attrs.flags = S3_SSH3_SFTP_ATTR_ACMODTIME;
    attrs.atime = op->mtime;
    attrs.mtime = op->mtime;

    need = s3_ssh3_sftp_encode_setstat(NULL, t->next_id, &s, &attrs);

    if (s3_cli_buf_grow(t->pool, &t->out, t->out_len, &t->out_cap, need) != S3_OK) {
        return S3_ERROR;
    }

    (void)s3_ssh3_sftp_encode_setstat(t->out + t->out_len, t->next_id, &s, &attrs);
    s3_cli_commit(t, need, 1);

    return S3_OK;
}

static char *
s3_cli_strdup(s3_pool_t *pool, const char *s)
{
    size_t len;
    char  *p;

    len = strlen(s) + 1;
    p = s3_pnalloc(pool, len);

    if (p != NULL) {
        s3_memcpy(p, s, len);
    }

    return p;
}

/* the dir/name join of the walks, the slash kept single */

static char *
s3_cli_path_join(s3_pool_t *pool, const char *dir, const char *name)
{
    size_t dl, nl;
    char  *p;
    int    slash;

    dl = strlen(dir);
    nl = strlen(name);
    slash = (dl > 0 && dir[dl - 1] == '/') ? 1 : 0;

    p = s3_pnalloc(pool, dl + nl + (size_t)(slash ? 0 : 1) + 1);

    if (p == NULL) {
        return NULL;
    }

    s3_memcpy(p, dir, dl);

    if (!slash) {
        p[dl++] = '/';
    }

    s3_memcpy(p + dl, name, nl + 1);

    return p;
}

static void
s3_cli_progress(s3_ssh3_sftp_cli_t *t, uint64_t sent, uint64_t total)
{
    if (t->progress != NULL) {
        t->progress(t->progress_arg, sent, total);
    }
}

static void
s3_cli_close_file(s3_ssh3_sftp_cli_t *t)
{
    s3_ssh3_sftp_cli_op_t *op = t->op;

    if (op->fd >= 0) {
        (void)close(op->fd);
        op->fd = -1;
    }
}

static void
s3_cli_digest_final(s3_ssh3_sftp_cli_t *t)
{
    s3_ssh3_sftp_cli_op_t *op = t->op;
    unsigned               dlen;

    if (op->md != NULL) {
        (void)EVP_DigestFinal_ex(op->md, op->digest, &dlen);
        EVP_MD_CTX_free(op->md);
        op->md = NULL;
    }
}

static void
s3_cli_done_op(s3_ssh3_sftp_cli_t *t)
{
    s3_cli_close_file(t);
    s3_cli_digest_final(t);

    t->state = S3_SSH3_SFTP_CLI_DONE;
    t->status = S3_SSH3_SFTP_FX_OK;
}

static void
s3_cli_fail_op(s3_ssh3_sftp_cli_t *t, uint32_t code)
{
    s3_ssh3_sftp_cli_op_t *op = t->op;
    uint32_t               i;

    s3_cli_close_file(t);
    s3_cli_digest_final(t);

    for (i = 0; i < op->frame_count; i++) {

        if (op->frames[i].dir != NULL) {
            (void)s3_cli_fs_closedir(op->frames[i].dir);
            op->frames[i].dir = NULL;
        }
    }

    op->frame_count = 0;

    t->state = S3_SSH3_SFTP_CLI_FAIL;
    t->status = code;
}

/* the -r walk: one file down, the walk goes on (the reference counts) */

static void
s3_cli_file_fail(s3_ssh3_sftp_cli_t *t, uint32_t code)
{
    s3_ssh3_sftp_cli_op_t *op = t->op;

    s3_cli_close_file(t);
    s3_cli_digest_final(t);

    if (!op->failed) {
        op->failed = 1;
        op->fail_status = code;
    }

    t->status = code;

    if (op->frame_count == 0) {

        /*
         * the walk has not started (the root stat of the -r download
         * failed, or the root is not a directory): there are no
         * frames to resume, the op dies -- the WALK resume would
         * index the empty frame stack
         */

        t->state = S3_SSH3_SFTP_CLI_FAIL;

        return;
    }

    op->phase = (op->kind == S3_SSH3_SFTP_CLI_OP_PUT_R) ? PH_PUT_R_WALK : PH_GET_R_WALK;
}

/* the failure of a per-file transfer: a train in flight cannot
 * re-phase (the younger replies would ride into the new phase), so
 * an outstanding window kills the whole operation, the drained state
 * keeps the walk-alive semantics of the reference */

static void
s3_cli_transfer_fail(s3_ssh3_sftp_cli_t *t, uint32_t code)
{
    s3_ssh3_sftp_cli_op_t *op = t->op;

    if (op->inflight > 0) {
        s3_cli_fail_op(t, code);

    } else if (op->kind == S3_SSH3_SFTP_CLI_OP_PUT || op->kind == S3_SSH3_SFTP_CLI_OP_GET) {
        s3_cli_fail_op(t, code);

    } else {
        s3_cli_file_fail(t, code);
    }
}

/* the per-file success, single ops finish, the walk resumes */

static void
s3_cli_transfer_done(s3_ssh3_sftp_cli_t *t)
{
    s3_ssh3_sftp_cli_op_t *op = t->op;

    if (op->kind == S3_SSH3_SFTP_CLI_OP_PUT || op->kind == S3_SSH3_SFTP_CLI_OP_GET) {
        s3_cli_done_op(t);

    } else {
        s3_cli_close_file(t);
        s3_cli_digest_final(t);

        op->phase = (op->kind == S3_SSH3_SFTP_CLI_OP_PUT_R) ? PH_PUT_R_WALK : PH_GET_R_WALK;
    }
}

/*
 * the R7 tail of a verified transfer: the peer inherits the source
 * mtime so the next --continue skips by size+mtime, not by the size
 * alone. The put stamps the remote through SETSTAT (one more wire
 * turn), the get stamps the local file right here; the refusals are
 * not fatal, they cost one redundant transfer later, never data
 */

static void
s3_cli_stamp_done(s3_ssh3_sftp_cli_t *t)
{
    s3_ssh3_sftp_cli_op_t *op = t->op;
    struct timespec        ts[2];

    if (op->kind == S3_SSH3_SFTP_CLI_OP_PUT || op->kind == S3_SSH3_SFTP_CLI_OP_PUT_R) {

        if (op->stamp) {
            op->phase = PH_PUT_SETSTAT;
            return;
        }

    } else if (op->stamp && op->fd >= 0) {

        ts[0].tv_sec = (time_t)op->mtime;
        ts[0].tv_nsec = 0;
        ts[1] = ts[0];

        (void)s3_cli_fs_futimens(op->fd, ts);
    }

    s3_cli_transfer_done(t);
}

/*
 * the HANDLE reply carries a view into the receive buffer, the
 * handle outlives many overwrites of it
 */

static s3_int_t
s3_cli_handle_copy(s3_ssh3_sftp_cli_t *t, u_char **dst, size_t *dst_len, const s3_str_t *handle)
{
    u_char *p;

    p = s3_pnalloc(t->pool, handle->len ? handle->len : 1);

    if (p == NULL) {
        return S3_ERROR;
    }

    if (handle->len > 0) {
        s3_memcpy(p, handle->data, handle->len);
    }

    *dst = p;
    *dst_len = handle->len;

    return S3_OK;
}

static int
s3_cli_attrs_is_dir(const s3_ssh3_sftp_attrs_t *a)
{
    return (a->flags & S3_SSH3_SFTP_ATTR_PERMISSION) &&
           (a->perms & S3_SSH3_SFTP_CLI_S_IFMT) == S3_SSH3_SFTP_CLI_S_IFDIR;
}

static int
s3_cli_attrs_is_reg(const s3_ssh3_sftp_attrs_t *a)
{
    if (!(a->flags & S3_SSH3_SFTP_ATTR_PERMISSION)) {

        /* the permissions missing: the regular file is the default */

        return 1;
    }

    return (a->perms & S3_SSH3_SFTP_CLI_S_IFMT) == S3_SSH3_SFTP_CLI_S_IFREG;
}

static int
s3_cli_dot_name(const char *name)
{
    return name[0] == '.' && (name[1] == '\0' || (name[1] == '.' && name[2] == '\0'));
}

/*
 * the next prefix length of the remote mkdir -p: prev_len is the
 * length of the issued prefix (0 before the first), 0 when the walk
 * is over
 */

static size_t
s3_cli_mkdir_next(const char *path, size_t prev_len)
{
    const char *slash;
    size_t      len;

    len = s3_strlen(path);

    if (prev_len >= len) {
        return 0;
    }

    if (prev_len == 0) {
        slash = strchr(path + (path[0] == '/' ? 1 : 0), '/');

    } else {
        slash = strchr(path + prev_len + 1, '/');
    }

    return slash != NULL ? (size_t)(slash - path) : len;
}

/* the local mkdir -p of the download walk, EEXIST tolerated for dirs */

static int
s3_cli_mkdir_local_all(const char *path)
{
    struct stat st;
    size_t      len;
    char       *copy, *slash;

    len = strlen(path);
    copy = s3_alloc(len + 1, NULL);

    if (copy == NULL) {
        return -1;
    }

    s3_memcpy(copy, path, len + 1);

    for (slash = copy + 1; *slash != '\0'; slash++) {

        if (*slash != '/') {
            continue;
        }

        *slash = '\0';

        if (s3_cli_fs_mkdir(copy) != 0 && errno != EEXIST) {
            s3_free(copy);
            return -1;
        }

        *slash = '/';
    }

    if (s3_cli_fs_mkdir(copy) != 0 && errno != EEXIST) {
        s3_free(copy);
        return -1;
    }

    /* the EEXIST is fine only for the directory */

    if (s3_cli_fs_stat(copy, &st) != 0 || !S_ISDIR(st.st_mode)) {
        s3_free(copy);
        return -1;
    }

    s3_free(copy);

    return 0;
}

/* the SHA-256 of the local file through the transfer fd */

static int
s3_cli_local_digest(s3_ssh3_sftp_cli_t *t, u_char *out)
{
    s3_ssh3_sftp_cli_op_t *op = t->op;
    EVP_MD_CTX            *md;
    uint64_t               off = 0;
    unsigned               dlen;
    ssize_t                n;
    int                    rc = -1;

    md = EVP_MD_CTX_new();

    if (md == NULL || EVP_DigestInit_ex(md, EVP_sha256(), NULL) != 1) {
        goto done;
    }

    for (;;) {

        n = s3_cli_fs_pread(op->fd, op->io_buf, S3_SSH3_SFTP_CLI_CHUNK, off);

        if (n < 0) {
            goto done;
        }

        if (n == 0) {
            break;
        }

        if (EVP_DigestUpdate(md, op->io_buf, (size_t)n) != 1) {
            goto done;
        }

        off += (uint64_t)n;
    }

    if (EVP_DigestFinal_ex(md, out, &dlen) != 1) {
        goto done;
    }

    rc = 0;

done:

    if (md != NULL) {
        EVP_MD_CTX_free(md);
    }

    return rc;
}

/*
 * the frame stack grows by doubling, the old arrays are pool memory
 * and die with the pool; on the put_r side the opendir runs here, a
 * missing local subtree fails the whole walk
 */

static s3_ssh3_sftp_cli_frame_t *
s3_cli_frame_push(s3_ssh3_sftp_cli_t *t, const char *local_dir, const char *remote_dir)
{
    s3_ssh3_sftp_cli_op_t    *op = t->op;
    s3_ssh3_sftp_cli_frame_t *frames, *frame;
    uint32_t                  cap;

    if (op->frame_count == op->frame_cap) {

        cap = op->frame_cap ? op->frame_cap * 2 : S3_SSH3_SFTP_CLI_FRAMES_INIT;

        frames = s3_pcalloc(t->pool, (size_t)cap * sizeof(s3_ssh3_sftp_cli_frame_t));

        if (frames == NULL) {
            return NULL;
        }

        if (op->frame_count > 0) {
            s3_memcpy(frames, op->frames,
                      (size_t)op->frame_count * sizeof(s3_ssh3_sftp_cli_frame_t));
        }

        op->frames = frames;
        op->frame_cap = cap;
    }

    frame = &op->frames[op->frame_count++];
    s3_memzero(frame, sizeof(*frame));

    frame->local_dir = s3_cli_strdup(t->pool, local_dir);
    frame->remote_dir = s3_cli_strdup(t->pool, remote_dir);

    if (frame->local_dir == NULL || frame->remote_dir == NULL) {
        op->frame_count--;
        return NULL;
    }

    if (op->kind == S3_SSH3_SFTP_CLI_OP_PUT_R) {

        frame->dir = s3_cli_fs_opendir(local_dir);

        if (frame->dir == NULL) {
            op->frame_count--;
            return NULL;
        }
    }

    return frame;
}

static s3_int_t
s3_cli_parse_status_body(const s3_str_t *body, uint32_t *code)
{
    const u_char *p, *end;
    s3_str_t      msg, lang;

    p = body->data;
    end = body->data + body->len;

    if (s3_ssh3_sftp_parse_u32(&p, end, code) != S3_OK ||
        s3_ssh3_sftp_parse_string(&p, end, &msg) != S3_OK ||
        s3_ssh3_sftp_parse_string(&p, end, &lang) != S3_OK || p != end) {
        return S3_ERROR;
    }

    return S3_OK;
}

static s3_int_t
s3_cli_on_status(s3_ssh3_sftp_cli_t *t, const s3_str_t *body, uint32_t *code)
{
    if (s3_cli_parse_status_body(body, code) != S3_OK) {
        return S3_ERROR;
    }

    /* the last SSH_FX_* verdict rides in the status */

    t->status = *code;

    return S3_OK;
}

static s3_int_t
s3_cli_parse_handle_body(const s3_str_t *body, s3_str_t *handle)
{
    const u_char *p, *end;

    p = body->data;
    end = body->data + body->len;

    if (s3_ssh3_sftp_parse_string(&p, end, handle) != S3_OK || p != end) {
        return S3_ERROR;
    }

    return S3_OK;
}

static s3_int_t
s3_cli_parse_data_body(const s3_str_t *body, s3_str_t *data)
{
    return s3_cli_parse_handle_body(body, data);
}

static s3_int_t
s3_cli_parse_attrs_body(const s3_str_t *body, s3_ssh3_sftp_attrs_t *a)
{
    const u_char *p, *end;

    p = body->data;
    end = body->data + body->len;

    if (s3_ssh3_sftp_parse_attrs(&p, end, a) != S3_OK || p != end) {
        return S3_ERROR;
    }

    return S3_OK;
}

/*
 * the NAME batch of the READDIR reply: the entries copy out of the
 * receive buffer, the walk outlives many overwrites of it
 */

static s3_int_t
s3_cli_parse_name_batch(s3_ssh3_sftp_cli_t *t, const s3_str_t *body)
{
    s3_ssh3_sftp_cli_op_t    *op = t->op;
    s3_ssh3_sftp_cli_frame_t *frame;
    s3_ssh3_sftp_cli_entry_t *entries;
    s3_ssh3_sftp_name_t       name;
    const u_char             *p, *end;
    uint32_t                  count, i;

    frame = &op->frames[op->frame_count - 1];

    p = body->data;
    end = body->data + body->len;

    if (s3_ssh3_sftp_parse_u32(&p, end, &count) != S3_OK) {
        return S3_ERROR;
    }

    entries = s3_pcalloc(t->pool, (size_t)(count ? count : 1) * sizeof(s3_ssh3_sftp_cli_entry_t));

    if (entries == NULL) {
        return S3_ERROR;
    }

    for (i = 0; i < count; i++) {

        if (s3_ssh3_sftp_parse_string(&p, end, &name.filename) != S3_OK ||
            s3_ssh3_sftp_parse_string(&p, end, &name.longname) != S3_OK ||
            s3_ssh3_sftp_parse_attrs(&p, end, &name.attrs) != S3_OK) {
            return S3_ERROR;
        }

        entries[i].name = s3_pnalloc(t->pool, name.filename.len + 1);

        if (entries[i].name == NULL) {
            return S3_ERROR;
        }

        s3_memcpy(entries[i].name, name.filename.data, name.filename.len);
        entries[i].name[name.filename.len] = '\0';

        entries[i].size = (name.attrs.flags & S3_SSH3_SFTP_ATTR_SIZE) ? name.attrs.size : 0;
        entries[i].mtime = (name.attrs.flags & S3_SSH3_SFTP_ATTR_ACMODTIME) ? name.attrs.mtime : 0;
        entries[i].is_dir = (unsigned)s3_cli_attrs_is_dir(&name.attrs);
        entries[i].is_reg = (unsigned)s3_cli_attrs_is_reg(&name.attrs);
    }

    if (p != end) {
        return S3_ERROR;
    }

    frame->entries = entries;
    frame->entry_count = count;
    frame->entry_pos = 0;

    return S3_OK;
}

/*
 * the local side of a download: the resume checks against the remote
 * size and mtime, the equal pair skips straight to the verify tail,
 * the equal size with the differing mtime is the stale copy and
 * re-transfers (R7), the fresh download truncates
 */

static void
s3_cli_get_local_open(s3_ssh3_sftp_cli_t *t)
{
    s3_ssh3_sftp_cli_op_t *op = t->op;
    struct stat            st;
    uint64_t               start = 0;
    int                    trunc = 1;

    s3_cli_close_file(t);

    if (op->resume && s3_cli_fs_stat(op->local_path, &st) == 0 && !S_ISDIR(st.st_mode)) {

        if ((uint64_t)st.st_size > op->file_size) {

            /* the reference: the local side is the larger one */

            s3_cli_transfer_fail(t, S3_SSH3_SFTP_FX_FAILURE);
            return;
        }

        if ((uint64_t)st.st_size == op->file_size && (uint32_t)st.st_mtime == op->mtime) {

            /* fully downloaded, the inherited mtime agrees: the
             * verify tail only, keep the bytes (R7) */

            op->fd = s3_cli_fs_open_rdwr(op->local_path);

            if (op->fd < 0) {
                s3_cli_transfer_fail(t, S3_SSH3_SFTP_FX_FAILURE);
                return;
            }

            op->offset = 0;
            op->emit_off = 0;
            op->stamp = 0;
            op->phase = PH_VERIFY_STAT;

            return;
        }

        /* the size alone cannot prove the content: the equal size
         * with the differing mtime is the stale copy, it re-transfers
         * from zero (R7); the smaller local appends from its size */

        if ((uint64_t)st.st_size < op->file_size) {
            start = (uint64_t)st.st_size;
            trunc = 0;
        }

        op->stamp = 1;
    }

    op->fd = s3_cli_fs_open_creat(op->local_path, trunc);

    if (op->fd < 0) {
        s3_cli_transfer_fail(t, S3_SSH3_SFTP_FX_FAILURE);
        return;
    }

    op->offset = start;
    op->emit_off = start;
    op->phase = PH_GET_OPEN;
}

/*
 * the upload walk: the DFS over the local tree, the regular files
 * transfer, the directories build their remote levels first; the
 * special files skip like in the reference WalkDir
 */

static s3_int_t
s3_cli_put_r_walk(s3_ssh3_sftp_cli_t *t)
{
    s3_ssh3_sftp_cli_op_t    *op = t->op;
    s3_ssh3_sftp_cli_frame_t *frame;
    s3_cli_fs_ent_t          *de;
    struct stat               st;
    char                     *local_sub, *remote_sub;

    frame = &op->frames[op->frame_count - 1];

    for (;;) {

        errno = 0;
        de = s3_cli_fs_readdir(frame->dir);

        if (de == NULL) {

            if (errno != 0) {

                /* the read failed: the reference errors the walk */

                s3_cli_fail_op(t, S3_SSH3_SFTP_FX_FAILURE);
                return S3_OK;
            }

            /* the directory drained: pop, the parent walk resumes */

            (void)s3_cli_fs_closedir(frame->dir);
            frame->dir = NULL;
            op->frame_count--;

            if (op->frame_count == 0) {

                if (op->failed) {
                    t->state = S3_SSH3_SFTP_CLI_FAIL;
                    t->status = op->fail_status;

                } else {
                    s3_cli_done_op(t);
                }

                return S3_OK;
            }

            frame = &op->frames[op->frame_count - 1];
            continue;
        }

        if (s3_cli_dot_name(de->d_name)) {
            continue;
        }

        local_sub = s3_cli_path_join(t->pool, frame->local_dir, de->d_name);

        if (local_sub == NULL) {
            s3_cli_fail_op(t, S3_SSH3_SFTP_FX_FAILURE);
            return S3_ERROR;
        }

        if (s3_cli_fs_stat(local_sub, &st) != 0) {
            s3_cli_file_fail(t, S3_SSH3_SFTP_FX_FAILURE);
            continue;
        }

        if (S_ISDIR(st.st_mode)) {

            remote_sub = s3_cli_path_join(t->pool, frame->remote_dir, de->d_name);

            if (remote_sub == NULL) {
                s3_cli_fail_op(t, S3_SSH3_SFTP_FX_FAILURE);
                return S3_ERROR;
            }

            /* the remote levels build async, the frame descends after */

            op->pending_local = local_sub;
            op->pending_remote = remote_sub;
            op->mkdir_path = remote_sub;
            op->mkdir_len = 0;
            op->phase = PH_MKDIR;

            return S3_OK;
        }

        if (!S_ISREG(st.st_mode)) {
            continue;
        }

        remote_sub = s3_cli_path_join(t->pool, frame->remote_dir, de->d_name);

        if (remote_sub == NULL) {
            s3_cli_fail_op(t, S3_SSH3_SFTP_FX_FAILURE);
            return S3_ERROR;
        }

        s3_cli_close_file(t);

        op->fd = s3_cli_fs_open_rd(local_sub);

        if (op->fd < 0) {
            s3_cli_file_fail(t, S3_SSH3_SFTP_FX_FAILURE);
            continue;
        }

        if (s3_cli_fs_fstat(op->fd, &st) != 0) {
            s3_cli_close_file(t);
            s3_cli_file_fail(t, S3_SSH3_SFTP_FX_FAILURE);
            continue;
        }

        op->local_path = local_sub;
        op->remote_path = remote_sub;
        op->file_size = (uint64_t)st.st_size;
        op->mtime = (uint32_t)st.st_mtime;
        op->offset = 0;
        op->emit_off = 0;
        op->stamp = 1;

        if (op->resume) {
            op->phase = PH_PUT_STAT;

        } else {
            op->trunc = 1;
            op->phase = PH_PUT_OPEN;
        }

        return S3_OK;
    }
}

/* the download walk: the entry batch processing between the READDIRs */

static s3_int_t
s3_cli_get_r_walk(s3_ssh3_sftp_cli_t *t)
{
    s3_ssh3_sftp_cli_op_t    *op = t->op;
    s3_ssh3_sftp_cli_frame_t *frame;
    s3_ssh3_sftp_cli_entry_t *e;
    char                     *local_sub, *remote_sub;

    frame = &op->frames[op->frame_count - 1];

    while (frame->entry_pos < frame->entry_count) {

        e = &frame->entries[frame->entry_pos++];

        if (s3_cli_dot_name(e->name)) {
            continue;
        }

        local_sub = s3_cli_path_join(t->pool, frame->local_dir, e->name);
        remote_sub = s3_cli_path_join(t->pool, frame->remote_dir, e->name);

        if (local_sub == NULL || remote_sub == NULL) {
            s3_cli_fail_op(t, S3_SSH3_SFTP_FX_FAILURE);
            return S3_ERROR;
        }

        if (e->is_dir) {

            if (s3_cli_mkdir_local_all(local_sub) != 0) {
                s3_cli_file_fail(t, S3_SSH3_SFTP_FX_FAILURE);
                continue;
            }

            if (s3_cli_frame_push(t, local_sub, remote_sub) == NULL) {
                s3_cli_fail_op(t, S3_SSH3_SFTP_FX_FAILURE);
                return S3_OK;
            }

            op->remote_path = remote_sub;
            op->phase = PH_GET_R_OPENDIR;

            return S3_OK;
        }

        if (e->is_reg) {

            op->local_path = local_sub;
            op->remote_path = remote_sub;
            op->file_size = e->size;
            op->mtime = e->mtime;
            op->stamp = 1;

            s3_cli_get_local_open(t);

            return S3_OK;
        }

        /* the special entries skip */
    }

    /* the batch drained: the next READDIR */

    if (frame->handle == NULL) {
        s3_cli_fail_op(t, S3_SSH3_SFTP_FX_FAILURE);
        return S3_OK;
    }

    op->phase = PH_GET_R_READDIR;

    return S3_OK;
}

/*
 * the engine: the loop runs the synchronous phases (the walks, the
 * mkdir levels) and returns with exactly one request queued
 */

/* the first bytes of the first operation: the version exchange of
 * the wire, the reply re-enters through the dispatch */

static s3_int_t
s3_cli_emit_init(s3_ssh3_sftp_cli_t *t)
{
    uintptr_t need;

    need = s3_ssh3_sftp_encode_init(NULL, S3_SSH3_SFTP_PROTOCOL_VERSION);

    if (s3_cli_buf_grow(t->pool, &t->out, t->out_len, &t->out_cap, need) != S3_OK) {
        return S3_ERROR;
    }

    (void)s3_ssh3_sftp_encode_init(t->out + t->out_len, S3_SSH3_SFTP_PROTOCOL_VERSION);
    s3_cli_commit(t, need, 0);

    return S3_OK;
}

static s3_int_t
s3_cli_step(s3_ssh3_sftp_cli_t *t)
{
    s3_ssh3_sftp_cli_op_t    *op = t->op;
    s3_ssh3_sftp_cli_frame_t *frame;
    s3_int_t                  rc;
    ssize_t                   n;
    size_t                    next;

    for (;;) {

        if (t->state != S3_SSH3_SFTP_CLI_RUN) {
            return S3_OK;
        }

        /* the INIT of the first operation rides before any request,
         * the VERSION reply re-enters through the dispatch */

        if (!t->negotiated) {
            return s3_cli_emit_init(t);
        }

        switch (op->phase) {

        case PH_PUT_STAT:
        case PH_GET_STAT:
        case PH_VERIFY_STAT:
            return s3_cli_emit_path(t, s3_ssh3_sftp_encode_stat, op->remote_path);

        case PH_PUT_OPEN:
            return s3_cli_emit_open(t, op->remote_path, 1);

        case PH_GET_OPEN:
        case PH_VERIFY_OPEN:
            return s3_cli_emit_open(t, op->remote_path, 0);

        case PH_PUT_WRITE: {

            size_t len;

            /* the train: the window fills with the whole chunks of the
             * remaining payload, the replies top it up; the emission
             * cursor rides ahead of the outstanding window */

            while (op->emit_off < op->file_size && op->inflight < S3_SSH3_SFTP_CLI_INFLIGHT) {

                len = op->file_size - op->emit_off;

                if (len > S3_SSH3_SFTP_CLI_CHUNK) {
                    len = S3_SSH3_SFTP_CLI_CHUNK;
                }

                n = s3_cli_fs_pread(op->fd, op->io_buf, len, (int64_t)op->emit_off);

                if (n < 0) {
                    s3_cli_transfer_fail(t, S3_SSH3_SFTP_FX_FAILURE);
                    return s3_cli_step(t);
                }

                if (n == 0) {

                    /* the local file shrank under the transfer: the
                     * train drains first, then the transfer fails */

                    if (op->inflight > 0) {
                        return S3_OK;
                    }

                    s3_cli_transfer_fail(t, S3_SSH3_SFTP_FX_FAILURE);

                    return s3_cli_step(t);
                }

                if (s3_cli_emit_write(t, op->io_buf, (size_t)n) != S3_OK) {
                    return S3_ERROR;
                }
            }

            if (op->offset >= op->file_size) {

                /* the tail replies of the train ride out before the
                 * close (a phase switch under a window mis-frames) */

                if (op->inflight > 0) {
                    return S3_OK;
                }

                op->phase = PH_PUT_CLOSE;

                continue;
            }

            return S3_OK;
        }

        case PH_GET_READ: {

            size_t len;

            /* the train: the reads stay inside the stat size, the
             * replies cannot hit the EOF mid-window on a stable file;
             * the chunk rides the read bound (the channel
             * maxPacketSize minus the reply reserve), so the replies
             * of a dialect server never go short */

            while (op->emit_off < op->file_size && op->inflight < S3_SSH3_SFTP_CLI_INFLIGHT) {

                len = op->file_size - op->emit_off;

                if (len > t->read_bound) {
                    len = t->read_bound;
                }

                if (s3_cli_emit_read(t, op->emit_off, len) != S3_OK) {
                    return S3_ERROR;
                }
            }

            if (op->offset >= op->file_size) {

                if (op->inflight > 0) {
                    return S3_OK;
                }

                op->phase = PH_GET_CLOSE;

                continue;
            }

            return S3_OK;
        }

        case PH_VERIFY_READ: {

            size_t len;

            while (op->emit_off < op->file_size && op->inflight < S3_SSH3_SFTP_CLI_INFLIGHT) {

                len = op->file_size - op->emit_off;

                if (len > t->read_bound) {
                    len = t->read_bound;
                }

                if (s3_cli_emit_read(t, op->emit_off, len) != S3_OK) {
                    return S3_ERROR;
                }
            }

            if (op->hash_len >= op->file_size) {

                if (op->inflight > 0) {
                    return S3_OK;
                }

                s3_cli_digest_final(t);
                op->phase = PH_VERIFY_CLOSE;

                continue;
            }

            return S3_OK;
        }

        case PH_PUT_CLOSE:
        case PH_GET_CLOSE:
        case PH_VERIFY_CLOSE:
            return s3_cli_emit_handle(t, s3_ssh3_sftp_encode_close, op->handle, op->handle_len);

        case PH_PUT_SETSTAT:
            return s3_cli_emit_setstat(t, op->remote_path);

        case PH_MKDIR:

            next = s3_cli_mkdir_next(op->mkdir_path, op->mkdir_len);

            if (next == 0) {

                /* the levels exist: the pending frame joins the walk */

                if (s3_cli_frame_push(t, op->pending_local, op->pending_remote) == NULL) {
                    s3_cli_fail_op(t, S3_SSH3_SFTP_FX_FAILURE);
                    return S3_OK;
                }

                op->phase = PH_PUT_R_WALK;
                continue;
            }

            op->mkdir_len = next;

            return s3_cli_emit_mkdir(t, op->mkdir_path, next);

        case PH_MKDIR_STAT: {
            char *prefix;

            prefix = s3_pnalloc(t->pool, op->mkdir_len + 1);

            if (prefix == NULL) {
                s3_cli_fail_op(t, S3_SSH3_SFTP_FX_FAILURE);
                return S3_ERROR;
            }

            s3_memcpy(prefix, op->mkdir_path, op->mkdir_len);
            prefix[op->mkdir_len] = '\0';

            return s3_cli_emit_path(t, s3_ssh3_sftp_encode_stat, prefix);
        }

        case PH_PUT_R_WALK:

            /* the walker sets the next async phase, the loop goes on */

            rc = s3_cli_put_r_walk(t);

            if (rc != S3_OK) {
                return rc;
            }

            continue;

        case PH_GET_R_WALK:

            rc = s3_cli_get_r_walk(t);

            if (rc != S3_OK) {
                return rc;
            }

            continue;

        case PH_GET_R_OPENDIR:
            return s3_cli_emit_path(t, s3_ssh3_sftp_encode_opendir, op->remote_path);

        case PH_GET_R_READDIR:
            frame = &op->frames[op->frame_count - 1];
            return s3_cli_emit_handle(t, s3_ssh3_sftp_encode_readdir, frame->handle,
                                      frame->handle_len);

        case PH_GET_R_CLOSE:
            frame = &op->frames[op->frame_count - 1];
            return s3_cli_emit_handle(t, s3_ssh3_sftp_encode_close, frame->handle,
                                      frame->handle_len);

        default:
            return S3_ERROR;
        }
    }
}

static s3_int_t
s3_cli_dispatch(s3_ssh3_sftp_cli_t *t, s3_ssh3_sftp_pkt_t *pkt)
{
    s3_ssh3_sftp_cli_op_t    *op = t->op;
    s3_ssh3_sftp_cli_frame_t *frame;
    s3_ssh3_sftp_attrs_t      attrs;
    s3_str_t                  body;
    struct stat               st;
    u_char                    local[S3_SSH3_SFTP_CLI_SHA256_LEN];
    uint32_t                  code;
    ssize_t                   n;

    /* the VERSION of the handshake: the driver never negotiates twice,
     * anything else before it is a protocol violation */

    if (pkt->type == S3_SSH3_SFTP_VERSION) {

        if (t->negotiated) {
            return S3_ERROR;
        }

        t->negotiated = 1;

        return s3_cli_step(t);
    }

    if (!t->negotiated) {
        return S3_ERROR;
    }

    switch (op->phase) {

    case PH_PUT_STAT:

        if (pkt->type == S3_SSH3_SFTP_STATUS) {

            if (s3_cli_on_status(t, &pkt->body, &code) != S3_OK) {
                return S3_ERROR;
            }

            /* any miss reads as the missing remote: the fresh open */

            op->offset = 0;
            op->emit_off = 0;
            op->trunc = 1;
            op->stamp = 1;
            op->phase = PH_PUT_OPEN;

            return s3_cli_step(t);
        }

        if (pkt->type != S3_SSH3_SFTP_ATTRS) {
            return S3_ERROR;
        }

        if (s3_cli_parse_attrs_body(&pkt->body, &attrs) != S3_OK) {
            return S3_ERROR;
        }

        if (attrs.size > op->file_size) {

            /* the reference: the remote side is the larger one */

            s3_cli_transfer_fail(t, S3_SSH3_SFTP_FX_FAILURE);
            return s3_cli_step(t);
        }

        if (attrs.size == op->file_size) {

            if ((attrs.flags & S3_SSH3_SFTP_ATTR_ACMODTIME) && attrs.mtime == op->mtime) {

                /* fully uploaded, the stamped mtime agrees: the
                 * verify tail only (R7) */

                op->stamp = 0;
                op->phase = PH_VERIFY_STAT;

                return s3_cli_step(t);
            }

            /* the size alone cannot prove the content: the equal
             * size with the differing mtime is the stale remote, it
             * re-transfers from zero (R7) */

            op->offset = 0;
            op->emit_off = 0;
            op->trunc = 1;
            op->stamp = 1;
            op->phase = PH_PUT_OPEN;

            return s3_cli_step(t);
        }

        /* the younger remote: the resume appends from its size */

        op->offset = attrs.size;
        op->emit_off = attrs.size;
        op->trunc = 0;
        op->stamp = 1;
        op->phase = PH_PUT_OPEN;

        return s3_cli_step(t);

    case PH_PUT_OPEN:

        if (pkt->type == S3_SSH3_SFTP_HANDLE) {

            if (s3_cli_parse_handle_body(&pkt->body, &body) != S3_OK ||
                s3_cli_handle_copy(t, &op->handle, &op->handle_len, &body) != S3_OK) {
                return S3_ERROR;
            }

            op->phase = PH_PUT_WRITE;

            return s3_cli_step(t);
        }

        if (pkt->type != S3_SSH3_SFTP_STATUS) {
            return S3_ERROR;
        }

        if (s3_cli_on_status(t, &pkt->body, &code) != S3_OK) {
            return S3_ERROR;
        }

        s3_cli_transfer_fail(t, code);

        return s3_cli_step(t);

    case PH_PUT_WRITE:

        if (pkt->type != S3_SSH3_SFTP_STATUS) {
            return S3_ERROR;
        }

        if (s3_cli_on_status(t, &pkt->body, &code) != S3_OK) {
            return S3_ERROR;
        }

        if (code != S3_SSH3_SFTP_FX_OK) {
            s3_cli_transfer_fail(t, code);
            return s3_cli_step(t);
        }

        /* the cursor rides the train ring: the reply of the oldest
         * outstanding WRITE carries its payload len */

        op->offset += op->io_ring[op->io_head];
        op->io_head = (op->io_head + 1) % S3_SSH3_SFTP_CLI_INFLIGHT;

        s3_cli_progress(t, op->offset, op->file_size);

        return s3_cli_step(t);

    case PH_PUT_CLOSE:

        if (pkt->type != S3_SSH3_SFTP_STATUS) {
            return S3_ERROR;
        }

        if (s3_cli_on_status(t, &pkt->body, &code) != S3_OK) {
            return S3_ERROR;
        }

        if (code != S3_SSH3_SFTP_FX_OK) {
            s3_cli_transfer_fail(t, code);
            return s3_cli_step(t);
        }

        op->phase = PH_VERIFY_STAT;

        return s3_cli_step(t);

    case PH_PUT_SETSTAT:

        if (pkt->type != S3_SSH3_SFTP_STATUS) {
            return S3_ERROR;
        }

        if (s3_cli_on_status(t, &pkt->body, &code) != S3_OK) {
            return S3_ERROR;
        }

        /* the reference logs a refused stamp and moves on: an old
         * dialect server costs one redundant re-transfer later */

        s3_cli_transfer_done(t);

        return s3_cli_step(t);

    case PH_GET_STAT:

        if (pkt->type == S3_SSH3_SFTP_ATTRS) {

            if (s3_cli_parse_attrs_body(&pkt->body, &attrs) != S3_OK) {
                return S3_ERROR;
            }

            if (op->kind == S3_SSH3_SFTP_CLI_OP_GET_R) {

                /* the root of the download walk must be a directory:
                 * the local levels build, the frame descends */

                if (!s3_cli_attrs_is_dir(&attrs)) {
                    s3_cli_fail_op(t, S3_SSH3_SFTP_FX_FAILURE);
                    return S3_OK;
                }

                if (s3_cli_mkdir_local_all(op->local_path) != 0) {
                    s3_cli_fail_op(t, S3_SSH3_SFTP_FX_FAILURE);
                    return S3_OK;
                }

                if (s3_cli_frame_push(t, op->local_path, op->remote_path) == NULL) {
                    s3_cli_fail_op(t, S3_SSH3_SFTP_FX_FAILURE);
                    return S3_OK;
                }

                op->phase = PH_GET_R_OPENDIR;

                return s3_cli_step(t);
            }

            if (s3_cli_attrs_is_dir(&attrs)) {

                /* the reference: a directory needs the -r form */

                s3_cli_transfer_fail(t, S3_SSH3_SFTP_FX_FAILURE);
                return s3_cli_step(t);
            }

            op->file_size = attrs.size;
            op->mtime = (attrs.flags & S3_SSH3_SFTP_ATTR_ACMODTIME) ? attrs.mtime : 0;

            s3_cli_get_local_open(t);

            if (t->state == S3_SSH3_SFTP_CLI_RUN) {
                return s3_cli_step(t);
            }

            return S3_OK;
        }

        if (pkt->type != S3_SSH3_SFTP_STATUS) {
            return S3_ERROR;
        }

        if (s3_cli_on_status(t, &pkt->body, &code) != S3_OK) {
            return S3_ERROR;
        }

        s3_cli_transfer_fail(t, code);

        return s3_cli_step(t);

    case PH_GET_OPEN:

        if (pkt->type == S3_SSH3_SFTP_HANDLE) {

            if (s3_cli_parse_handle_body(&pkt->body, &body) != S3_OK ||
                s3_cli_handle_copy(t, &op->handle, &op->handle_len, &body) != S3_OK) {
                return S3_ERROR;
            }

            op->phase = PH_GET_READ;

            return s3_cli_step(t);
        }

        if (pkt->type != S3_SSH3_SFTP_STATUS) {
            return S3_ERROR;
        }

        if (s3_cli_on_status(t, &pkt->body, &code) != S3_OK) {
            return S3_ERROR;
        }

        s3_cli_transfer_fail(t, code);

        return s3_cli_step(t);

    case PH_GET_READ:

        if (pkt->type == S3_SSH3_SFTP_DATA) {

            /* the requested len of the served slot rides the train
             * ring: a reply shorter than it mis-phases the positional
             * window, the transfer fails honestly (the read bound
             * keeps a dialect server out of this path) */

            uint32_t want = op->io_ring[op->io_head];

            op->io_head = (op->io_head + 1) % S3_SSH3_SFTP_CLI_INFLIGHT;

            if (s3_cli_parse_data_body(&pkt->body, &body) != S3_OK) {
                return S3_ERROR;
            }

            if (body.len > 0 && (size_t)body.len < want) {

                s3_cli_transfer_fail(t, S3_SSH3_SFTP_FX_FAILURE);

                return s3_cli_step(t);
            }

            if (body.len > 0) {

                n = s3_cli_fs_pwrite(op->fd, body.data, body.len, (int64_t)op->offset);

                if (n < 0 || (size_t)n != body.len) {
                    s3_cli_transfer_fail(t, S3_SSH3_SFTP_FX_FAILURE);
                    return s3_cli_step(t);
                }

                op->offset += body.len;
                s3_cli_progress(t, op->offset, op->file_size);
            }

            /* the pkg/sftp dialect reads short at will: only the empty
             * payload or the explicit STATUS EOF end the stream, the
             * next READ keeps going otherwise; a mid-window end means
             * the remote size died under the outstanding train */

            if (body.len == 0) {

                if (op->inflight > 0) {
                    s3_cli_transfer_fail(t, S3_SSH3_SFTP_FX_FAILURE);
                    return s3_cli_step(t);
                }

                op->phase = PH_GET_CLOSE;
            }

            return s3_cli_step(t);
        }

        if (pkt->type != S3_SSH3_SFTP_STATUS) {
            return S3_ERROR;
        }

        if (s3_cli_on_status(t, &pkt->body, &code) != S3_OK) {
            return S3_ERROR;
        }

        if (code == S3_SSH3_SFTP_FX_EOF) {
            op->phase = PH_GET_CLOSE;
            return s3_cli_step(t);
        }

        s3_cli_transfer_fail(t, code);

        return s3_cli_step(t);

    case PH_GET_CLOSE:

        if (pkt->type != S3_SSH3_SFTP_STATUS) {
            return S3_ERROR;
        }

        if (s3_cli_on_status(t, &pkt->body, &code) != S3_OK) {
            return S3_ERROR;
        }

        if (code != S3_SSH3_SFTP_FX_OK) {
            s3_cli_transfer_fail(t, code);
            return s3_cli_step(t);
        }

        op->phase = PH_VERIFY_STAT;

        return s3_cli_step(t);

    case PH_VERIFY_STAT:

        if (pkt->type == S3_SSH3_SFTP_ATTRS) {

            if (s3_cli_parse_attrs_body(&pkt->body, &attrs) != S3_OK) {
                return S3_ERROR;
            }

            if (s3_cli_fs_fstat(op->fd, &st) != 0) {
                s3_cli_transfer_fail(t, S3_SSH3_SFTP_FX_FAILURE);
                return s3_cli_step(t);
            }

            if (attrs.size != (uint64_t)st.st_size) {

                /* the reference: the size mismatch fails the transfer */

                s3_cli_transfer_fail(t, S3_SSH3_SFTP_FX_FAILURE);
                return s3_cli_step(t);
            }

            if (op->verify || attrs.size > S3_SSH3_SFTP_CLI_CHECKSUM_AUTO_THRESHOLD) {

                op->md = EVP_MD_CTX_new();

                if (op->md == NULL || EVP_DigestInit_ex(op->md, EVP_sha256(), NULL) != 1) {

                    if (op->md != NULL) {
                        EVP_MD_CTX_free(op->md);
                        op->md = NULL;
                    }

                    s3_cli_transfer_fail(t, S3_SSH3_SFTP_FX_FAILURE);
                    return s3_cli_step(t);
                }

                op->hash_len = 0;
                op->emit_off = 0;
                op->phase = PH_VERIFY_OPEN;

                return s3_cli_step(t);
            }

            s3_cli_stamp_done(t);

            return s3_cli_step(t);
        }

        if (pkt->type != S3_SSH3_SFTP_STATUS) {
            return S3_ERROR;
        }

        if (s3_cli_on_status(t, &pkt->body, &code) != S3_OK) {
            return S3_ERROR;
        }

        s3_cli_transfer_fail(t, code);

        return s3_cli_step(t);

    case PH_VERIFY_OPEN:

        if (pkt->type == S3_SSH3_SFTP_HANDLE) {

            if (s3_cli_parse_handle_body(&pkt->body, &body) != S3_OK ||
                s3_cli_handle_copy(t, &op->handle, &op->handle_len, &body) != S3_OK) {
                return S3_ERROR;
            }

            op->phase = PH_VERIFY_READ;

            return s3_cli_step(t);
        }

        if (pkt->type != S3_SSH3_SFTP_STATUS) {
            return S3_ERROR;
        }

        if (s3_cli_on_status(t, &pkt->body, &code) != S3_OK) {
            return S3_ERROR;
        }

        s3_cli_transfer_fail(t, code);

        return s3_cli_step(t);

    case PH_VERIFY_READ:

        if (pkt->type == S3_SSH3_SFTP_DATA) {

            /* the same train-ring pin as the payload read: a reply
             * shorter than the requested chunk mis-phases the window,
             * the digest would lie, the transfer fails honestly */

            uint32_t want = op->io_ring[op->io_head];

            op->io_head = (op->io_head + 1) % S3_SSH3_SFTP_CLI_INFLIGHT;

            if (s3_cli_parse_data_body(&pkt->body, &body) != S3_OK) {
                return S3_ERROR;
            }

            if (body.len > 0 && (size_t)body.len < want) {

                s3_cli_transfer_fail(t, S3_SSH3_SFTP_FX_FAILURE);

                return s3_cli_step(t);
            }

            if (body.len > 0 && EVP_DigestUpdate(op->md, body.data, body.len) != 1) {
                return S3_ERROR;
            }

            op->hash_len += body.len;

            /* the pkg/sftp dialect reads short at will: only the empty
             * payload or the explicit STATUS EOF end the stream; the
             * size-capped train never ends it mid-window on a stable
             * file, an early end fails the digest honestly */

            if (body.len == 0) {

                if (op->inflight > 0) {
                    s3_cli_transfer_fail(t, S3_SSH3_SFTP_FX_FAILURE);
                    return s3_cli_step(t);
                }

                s3_cli_digest_final(t);
                op->phase = PH_VERIFY_CLOSE;
            }

            return s3_cli_step(t);
        }

        if (pkt->type != S3_SSH3_SFTP_STATUS) {
            return S3_ERROR;
        }

        if (s3_cli_on_status(t, &pkt->body, &code) != S3_OK) {
            return S3_ERROR;
        }

        if (code == S3_SSH3_SFTP_FX_EOF) {

            if (op->inflight > 0) {
                s3_cli_transfer_fail(t, S3_SSH3_SFTP_FX_FAILURE);
                return s3_cli_step(t);
            }

            s3_cli_digest_final(t);
            op->phase = PH_VERIFY_CLOSE;

            return s3_cli_step(t);
        }

        s3_cli_transfer_fail(t, code);

        return s3_cli_step(t);

    case PH_VERIFY_CLOSE:

        if (pkt->type != S3_SSH3_SFTP_STATUS) {
            return S3_ERROR;
        }

        if (s3_cli_on_status(t, &pkt->body, &code) != S3_OK) {
            return S3_ERROR;
        }

        if (code != S3_SSH3_SFTP_FX_OK) {
            s3_cli_transfer_fail(t, code);
            return s3_cli_step(t);
        }

        if (s3_cli_local_digest(t, local) != 0 ||
            s3_memcmp(local, op->digest, S3_SSH3_SFTP_CLI_SHA256_LEN) != 0) {
            s3_cli_transfer_fail(t, S3_SSH3_SFTP_FX_FAILURE);
            return s3_cli_step(t);
        }

        s3_cli_stamp_done(t);

        return s3_cli_step(t);

    case PH_MKDIR:

        if (pkt->type != S3_SSH3_SFTP_STATUS) {
            return S3_ERROR;
        }

        if (s3_cli_on_status(t, &pkt->body, &code) != S3_OK) {
            return S3_ERROR;
        }

        if (code != S3_SSH3_SFTP_FX_OK) {

            /* the reference tolerates the existing levels via STAT */

            op->phase = PH_MKDIR_STAT;
        }

        return s3_cli_step(t);

    case PH_MKDIR_STAT:

        if (pkt->type == S3_SSH3_SFTP_ATTRS) {

            if (s3_cli_parse_attrs_body(&pkt->body, &attrs) != S3_OK) {
                return S3_ERROR;
            }

            if (!s3_cli_attrs_is_dir(&attrs)) {
                s3_cli_fail_op(t, S3_SSH3_SFTP_FX_FAILURE);
                return S3_OK;
            }

            /* the level exists: the walk climbs to the next prefix */

            op->phase = PH_MKDIR;

            return s3_cli_step(t);
        }

        if (pkt->type != S3_SSH3_SFTP_STATUS) {
            return S3_ERROR;
        }

        if (s3_cli_on_status(t, &pkt->body, &code) != S3_OK) {
            return S3_ERROR;
        }

        s3_cli_fail_op(t, code);

        return S3_OK;

    case PH_GET_R_OPENDIR:

        if (pkt->type == S3_SSH3_SFTP_HANDLE) {

            frame = &op->frames[op->frame_count - 1];

            if (s3_cli_parse_handle_body(&pkt->body, &body) != S3_OK ||
                s3_cli_handle_copy(t, &frame->handle, &frame->handle_len, &body) != S3_OK) {
                return S3_ERROR;
            }

            op->phase = PH_GET_R_READDIR;

            return s3_cli_step(t);
        }

        if (pkt->type != S3_SSH3_SFTP_STATUS) {
            return S3_ERROR;
        }

        if (s3_cli_on_status(t, &pkt->body, &code) != S3_OK) {
            return S3_ERROR;
        }

        /* the walk error at the directory: the frame dies, the parent
         * walk counts the failure and goes on */

        s3_cli_file_fail(t, code);
        op->frame_count--;

        if (op->frame_count == 0) {
            t->state = S3_SSH3_SFTP_CLI_FAIL;
            t->status = op->fail_status;
            return S3_OK;
        }

        return s3_cli_step(t);

    case PH_GET_R_READDIR:

        if (pkt->type == S3_SSH3_SFTP_NAME) {

            if (s3_cli_parse_name_batch(t, &pkt->body) != S3_OK) {
                return S3_ERROR;
            }

            op->phase = PH_GET_R_WALK;

            return s3_cli_step(t);
        }

        if (pkt->type != S3_SSH3_SFTP_STATUS) {
            return S3_ERROR;
        }

        if (s3_cli_on_status(t, &pkt->body, &code) != S3_OK) {
            return S3_ERROR;
        }

        if (code == S3_SSH3_SFTP_FX_EOF) {

            /* the listing drained: the handle closes */

            op->phase = PH_GET_R_CLOSE;
            return s3_cli_step(t);
        }

        s3_cli_file_fail(t, code);
        op->frame_count--;

        if (op->frame_count == 0) {
            t->state = S3_SSH3_SFTP_CLI_FAIL;
            t->status = op->fail_status;
            return S3_OK;
        }

        return s3_cli_step(t);

    case PH_GET_R_CLOSE:

        if (pkt->type != S3_SSH3_SFTP_STATUS) {
            return S3_ERROR;
        }

        if (s3_cli_on_status(t, &pkt->body, &code) != S3_OK) {
            return S3_ERROR;
        }

        if (code != S3_SSH3_SFTP_FX_OK) {
            s3_cli_file_fail(t, code);
        }

        op->frame_count--;

        if (op->frame_count == 0) {

            if (op->failed) {
                t->state = S3_SSH3_SFTP_CLI_FAIL;
                t->status = op->fail_status;

            } else {
                s3_cli_done_op(t);
            }

            return S3_OK;
        }

        /* the frame died: the parent walk resumes */

        op->phase = PH_GET_R_WALK;

        return s3_cli_step(t);

    default:
        return S3_ERROR;
    }
}

/*
 * the op context resets between the operations: the pool holds the
 * per-op allocations until the pool dies, the freeing is not worth
 * the bookkeeping
 */

static s3_int_t
s3_cli_reset(s3_ssh3_sftp_cli_t *t)
{
    s3_ssh3_sftp_cli_op_t *op;

    if (t->op == NULL) {
        t->op = s3_pcalloc(t->pool, sizeof(s3_ssh3_sftp_cli_op_t));

        if (t->op == NULL) {
            return S3_ERROR;
        }
    }

    op = t->op;

    s3_cli_close_file(t);
    s3_cli_digest_final(t);

    while (op->frame_count > 0) {
        op->frame_count--;

        if (op->frames[op->frame_count].dir != NULL) {
            (void)s3_cli_fs_closedir(op->frames[op->frame_count].dir);
        }
    }

    s3_memzero(op, sizeof(*op));
    op->fd = -1;

    t->state = S3_SSH3_SFTP_CLI_IDLE;
    t->status = S3_SSH3_SFTP_FX_OK;
    t->out_len = 0;
    t->pend_len = 0;

    return S3_OK;
}

s3_int_t
s3_ssh3_sftp_cli_init(s3_ssh3_sftp_cli_t *t, s3_pool_t *pool, s3_ssh3_sftp_cli_progress_pt progress,
                      void *progress_arg)
{
    if (t == NULL || pool == NULL) {
        return S3_ERROR;
    }

    s3_memzero(t, sizeof(*t));

    t->pool = pool;
    t->state = S3_SSH3_SFTP_CLI_IDLE;
    t->status = S3_SSH3_SFTP_FX_OK;
    t->read_bound = S3_SSH3_SFTP_CLI_CHUNK;
    t->progress = progress;
    t->progress_arg = progress_arg;

    return S3_OK;
}

void
s3_ssh3_sftp_cli_channel_max_packet(s3_ssh3_sftp_cli_t *t, uint64_t max_packet)
{
    uint64_t bound;

    if (t == NULL || max_packet <= S3_SSH3_SFTP_CLI_PACKET_RESERVE) {
        return;
    }

    bound = max_packet - S3_SSH3_SFTP_CLI_PACKET_RESERVE;

    if (bound > S3_SSH3_SFTP_CLI_CHUNK) {
        bound = S3_SSH3_SFTP_CLI_CHUNK;
    }

    t->read_bound = (uint32_t)bound;
}

s3_int_t
s3_ssh3_sftp_cli_put(s3_ssh3_sftp_cli_t *t, const char *local_path, const char *remote_path,
                     unsigned resume, unsigned verify)
{
    s3_ssh3_sftp_cli_op_t *op;
    struct stat            st;

    if (t == NULL || local_path == NULL || remote_path == NULL) {
        return S3_ERROR;
    }

    if (t->state != S3_SSH3_SFTP_CLI_IDLE && t->state != S3_SSH3_SFTP_CLI_DONE) {
        return S3_BUSY;
    }

    if (s3_cli_reset(t) != S3_OK) {
        return S3_ERROR;
    }

    op = t->op;
    op->kind = S3_SSH3_SFTP_CLI_OP_PUT;
    op->resume = resume ? 1 : 0;
    op->verify = verify ? 1 : 0;
    op->local_path = s3_cli_strdup(t->pool, local_path);
    op->remote_path = s3_cli_strdup(t->pool, remote_path);
    op->io_buf = s3_pnalloc(t->pool, S3_SSH3_SFTP_CLI_CHUNK);

    if (op->local_path == NULL || op->remote_path == NULL || op->io_buf == NULL) {
        t->state = S3_SSH3_SFTP_CLI_FAIL;
        t->status = S3_SSH3_SFTP_FX_FAILURE;
        return S3_ERROR;
    }

    /* the immediate local failure: the missing (or directory) source */

    if (s3_cli_fs_stat(local_path, &st) != 0 || S_ISDIR(st.st_mode)) {
        t->state = S3_SSH3_SFTP_CLI_FAIL;
        t->status = S3_SSH3_SFTP_FX_FAILURE;
        return S3_ERROR;
    }

    op->fd = s3_cli_fs_open_rd(local_path);

    if (op->fd < 0) {
        t->state = S3_SSH3_SFTP_CLI_FAIL;
        t->status = S3_SSH3_SFTP_FX_FAILURE;
        return S3_ERROR;
    }

    op->file_size = (uint64_t)st.st_size;
    op->mtime = (uint32_t)st.st_mtime;
    op->stamp = 1;

    t->state = S3_SSH3_SFTP_CLI_RUN;
    op->phase = op->resume ? PH_PUT_STAT : PH_PUT_OPEN;

    if (!op->resume) {
        op->trunc = 1;
    }

    if (s3_cli_step(t) != S3_OK) {
        return S3_ERROR;
    }

    return S3_OK;
}

s3_int_t
s3_ssh3_sftp_cli_get(s3_ssh3_sftp_cli_t *t, const char *remote_path, const char *local_path,
                     unsigned resume, unsigned verify)
{
    s3_ssh3_sftp_cli_op_t *op;

    if (t == NULL || remote_path == NULL || local_path == NULL) {
        return S3_ERROR;
    }

    if (t->state != S3_SSH3_SFTP_CLI_IDLE && t->state != S3_SSH3_SFTP_CLI_DONE) {
        return S3_BUSY;
    }

    if (s3_cli_reset(t) != S3_OK) {
        return S3_ERROR;
    }

    op = t->op;
    op->kind = S3_SSH3_SFTP_CLI_OP_GET;
    op->resume = resume ? 1 : 0;
    op->verify = verify ? 1 : 0;
    op->local_path = s3_cli_strdup(t->pool, local_path);
    op->remote_path = s3_cli_strdup(t->pool, remote_path);
    op->io_buf = s3_pnalloc(t->pool, S3_SSH3_SFTP_CLI_CHUNK);

    if (op->local_path == NULL || op->remote_path == NULL || op->io_buf == NULL) {
        t->state = S3_SSH3_SFTP_CLI_FAIL;
        t->status = S3_SSH3_SFTP_FX_FAILURE;
        return S3_ERROR;
    }

    t->state = S3_SSH3_SFTP_CLI_RUN;
    op->stamp = 1; /* a download writes the bytes, it stamps them (R7) */
    op->phase = PH_GET_STAT;

    if (s3_cli_step(t) != S3_OK) {
        return S3_ERROR;
    }

    return S3_OK;
}

s3_int_t
s3_ssh3_sftp_cli_put_r(s3_ssh3_sftp_cli_t *t, const char *local_path, const char *remote_path,
                       unsigned resume, unsigned verify)
{
    s3_ssh3_sftp_cli_op_t *op;
    struct stat            st;

    if (t == NULL || local_path == NULL || remote_path == NULL) {
        return S3_ERROR;
    }

    if (t->state != S3_SSH3_SFTP_CLI_IDLE && t->state != S3_SSH3_SFTP_CLI_DONE) {
        return S3_BUSY;
    }

    if (s3_cli_reset(t) != S3_OK) {
        return S3_ERROR;
    }

    op = t->op;
    op->kind = S3_SSH3_SFTP_CLI_OP_PUT_R;
    op->resume = resume ? 1 : 0;
    op->verify = verify ? 1 : 0;
    op->local_path = s3_cli_strdup(t->pool, local_path);
    op->remote_path = s3_cli_strdup(t->pool, remote_path);
    op->io_buf = s3_pnalloc(t->pool, S3_SSH3_SFTP_CLI_CHUNK);

    if (op->local_path == NULL || op->remote_path == NULL || op->io_buf == NULL) {
        t->state = S3_SSH3_SFTP_CLI_FAIL;
        t->status = S3_SSH3_SFTP_FX_FAILURE;
        return S3_ERROR;
    }

    /* the immediate local failure: the walk cannot start */

    if (s3_cli_fs_stat(local_path, &st) != 0 || !S_ISDIR(st.st_mode)) {
        t->state = S3_SSH3_SFTP_CLI_FAIL;
        t->status = S3_SSH3_SFTP_FX_FAILURE;
        return S3_ERROR;
    }

    t->state = S3_SSH3_SFTP_CLI_RUN;

    /* the root frame waits for the mkdir -p of the remote root */

    op->mkdir_path = op->remote_path;
    op->mkdir_len = 0;
    op->pending_local = op->local_path;
    op->pending_remote = op->remote_path;
    op->phase = PH_MKDIR;

    if (s3_cli_step(t) != S3_OK) {
        return S3_ERROR;
    }

    return S3_OK;
}

s3_int_t
s3_ssh3_sftp_cli_get_r(s3_ssh3_sftp_cli_t *t, const char *remote_path, const char *local_path,
                       unsigned resume, unsigned verify)
{
    s3_ssh3_sftp_cli_op_t *op;

    if (t == NULL || remote_path == NULL || local_path == NULL) {
        return S3_ERROR;
    }

    if (t->state != S3_SSH3_SFTP_CLI_IDLE && t->state != S3_SSH3_SFTP_CLI_DONE) {
        return S3_BUSY;
    }

    if (s3_cli_reset(t) != S3_OK) {
        return S3_ERROR;
    }

    op = t->op;
    op->kind = S3_SSH3_SFTP_CLI_OP_GET_R;
    op->resume = resume ? 1 : 0;
    op->verify = verify ? 1 : 0;
    op->local_path = s3_cli_strdup(t->pool, local_path);
    op->remote_path = s3_cli_strdup(t->pool, remote_path);
    op->io_buf = s3_pnalloc(t->pool, S3_SSH3_SFTP_CLI_CHUNK);

    if (op->local_path == NULL || op->remote_path == NULL || op->io_buf == NULL) {
        t->state = S3_SSH3_SFTP_CLI_FAIL;
        t->status = S3_SSH3_SFTP_FX_FAILURE;
        return S3_ERROR;
    }

    t->state = S3_SSH3_SFTP_CLI_RUN;
    op->stamp = 1; /* a download writes the bytes, it stamps them (R7) */
    op->phase = PH_GET_STAT;

    if (s3_cli_step(t) != S3_OK) {
        return S3_ERROR;
    }

    return S3_OK;
}

s3_int_t
s3_ssh3_sftp_cli_input(s3_ssh3_sftp_cli_t *t, const u_char *data, size_t len)
{
    s3_ssh3_sftp_cli_op_t *op;
    s3_ssh3_sftp_pkt_t     pkt;
    const u_char          *p, *end, *msg;
    s3_int_t               rc;

    if (t == NULL || (data == NULL && len > 0)) {
        return S3_ERROR;
    }

    if (len == 0) {
        return S3_OK;
    }

    if (s3_cli_buf_grow(t->pool, &t->pend, t->pend_len, &t->pend_cap, len) != S3_OK) {
        return S3_ERROR;
    }

    s3_memcpy(t->pend + t->pend_len, data, len);
    t->pend_len += len;

    p = t->pend;
    end = t->pend + t->pend_len;
    msg = p;

    while (p < end) {

        if (t->state != S3_SSH3_SFTP_CLI_RUN) {

            /*
             * the verdict left the RUN state: the replies of the dead
             * train ride the drain, the frames outside an operation
             * stay unsolicited
             */

            if (t->state == S3_SSH3_SFTP_CLI_DONE || t->state == S3_SSH3_SFTP_CLI_FAIL) {
                break;
            }

            return S3_ERROR;
        }

        op = t->op;

        msg = p;

        rc = s3_ssh3_sftp_codec_frame(&p, end, &pkt);

        if (rc == S3_AGAIN) {
            break;
        }

        if (rc != S3_OK) {
            return S3_ERROR;
        }

        /* the VERSION of the handshake carries no id, it passes first */

        if (pkt.type == S3_SSH3_SFTP_VERSION) {

            t->pend_len = (size_t)(end - p);
            s3_memmove(t->pend, p, t->pend_len);

            t->negotiated = 1;

            if (s3_cli_step(t) != S3_OK) {
                return S3_ERROR;
            }

            continue;
        }

        /* the pin: the replies ride the byte stream in request order,
         * the id must match the oldest outstanding request; a reply
         * with nothing outstanding is a protocol violation too */

        if (op->inflight == 0 || !pkt.has_id || pkt.request_id != op->expect_id) {
            return S3_ERROR;
        }

        /* the reply consumes the oldest request before the dispatch:
         * the phase switches inside see the drained window */

        op->inflight--;
        op->expect_id++;

        if (s3_cli_dispatch(t, &pkt) != S3_OK) {
            return S3_ERROR;
        }
    }

    /* the clean drain empties the buffer, the AGAIN break keeps the
     * tail of the frame being parsed */

    t->pend_len = (p == end) ? 0 : (size_t)(end - msg);

    if (msg != t->pend && t->pend_len > 0) {
        s3_memmove(t->pend, msg, t->pend_len);
    }

    return S3_OK;
}

ssize_t
s3_ssh3_sftp_cli_output(s3_ssh3_sftp_cli_t *t, u_char *buf, size_t size)
{
    size_t n;

    if (t == NULL || buf == NULL || t->out_len == 0) {
        return 0;
    }

    n = s3_min(size, t->out_len);

    s3_memcpy(buf, t->out, n);
    t->out_len -= n;

    if (t->out_len > 0) {
        s3_memmove(t->out, t->out + n, t->out_len);
    }

    return (ssize_t)n;
}

unsigned
s3_ssh3_sftp_cli_finished(const s3_ssh3_sftp_cli_t *t)
{
    if (t == NULL) {
        return 0;
    }

    return t->state == S3_SSH3_SFTP_CLI_DONE || t->state == S3_SSH3_SFTP_CLI_FAIL;
}

uint32_t
s3_ssh3_sftp_cli_status(const s3_ssh3_sftp_cli_t *t)
{
    if (t == NULL) {
        return S3_SSH3_SFTP_FX_FAILURE;
    }

    return t->status;
}
