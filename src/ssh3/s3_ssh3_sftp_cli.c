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
 * buffer, the replies ride in through input(); every outstanding
 * request leaves a record in the train ring and the reply routes by
 * it (the SFTP server answers the byte stream sequentially, so every
 * reply must carry the id of the oldest outstanding request -
 * anything else after the retransmission-free pipeline is a protocol
 * error, like every unbounded frame shape)
 *
 * the streaming trains keep a window of S3_SSH3_SFTP_CLI_INFLIGHT
 * requests in flight; the -r walks pipeline the files of one
 * directory through a window of S3_SSH3_SFTP_CLI_FILES slots: while
 * the file N streams its chunks, the file N+1 is already OPEN - each
 * slot carries the local fd, the remote handle, the cursors and the
 * digest of its own file; the subtree recursion (the mkdir levels,
 * the OPENDIR/READDIR/CLOSEDIR of the walk) rides the same ring as
 * one-request records and stays serial - the pipeline is the file
 * window of one directory
 *
 * one operation runs at a time: the single put/get or the -r walk
 * over the directory tree; a failed file inside the -r walk does not
 * abort it, the reference counts the failures and walks on (the
 * failed slot drains its outstanding replies, closes its remote
 * handle and frees; the walk with no frames to resume - the failed
 * root stat of the -r download - is the terminal FAIL)
 *
 * the checksum verification re-reads the remote side through SHA-256
 * and compares it with the local file, on the verify flag or
 * automatically above S3_SSH3_SFTP_CLI_CHECKSUM_AUTO_THRESHOLD, the
 * digest rides the slot
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

/*
 * the file window of the -r walks: the files of one directory
 * transfer overlapped (while the file N streams its chunks the file
 * N+1 is already OPEN), the depth trades the round trips of the
 * per-file phases for the window state (one slot carries the local
 * fd, the remote handle and the digest)
 */

#define S3_SSH3_SFTP_CLI_FILES 4

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

/*
 * the phases: the op phase drives the walk machinery (the producer
 * side of the pump), the slot phase drives the per-file state machine
 * of the window; the per-file values ride both fields, the walk and
 * the pump values ride the op phase only
 */

enum {
    PH_PUT_STAT = 1,  /* the resume STAT of the remote file (slot) */
    PH_PUT_OPEN,      /* the OPEN of the remote file for writing (slot) */
    PH_PUT_WRITE,     /* the WRITE chunks of the payload (slot) */
    PH_PUT_CLOSE,     /* the CLOSE of the written file (slot) */
    PH_PUT_SETSTAT,   /* the mtime stamp of the written file (slot, R7) */
    PH_GET_STAT,      /* the STAT of the file to download (slot + the -r root) */
    PH_GET_OPEN,      /* the OPEN of the remote file for reading (slot) */
    PH_GET_READ,      /* the READ chunks of the payload (slot) */
    PH_GET_CLOSE,     /* the CLOSE of the read file (slot) */
    PH_VERIFY_STAT,   /* the size check before the checksum (slot) */
    PH_VERIFY_OPEN,   /* the re-OPEN for the checksum read (slot) */
    PH_VERIFY_READ,   /* the checksum read of the remote side (slot) */
    PH_VERIFY_CLOSE,  /* the CLOSE and the digest compare (slot) */
    PH_MKDIR,         /* one level of the remote mkdir -p (op) */
    PH_MKDIR_STAT,    /* the EEXIST tolerance: the STAT of the level (op) */
    PH_PUT_R_WALK,    /* the upload walk filling the file slots (op) */
    PH_GET_R_WALK,    /* the entry processing of downloadDir (op) */
    PH_GET_R_OPENDIR, /* the subtree OPENDIR of the download walk (op) */
    PH_GET_R_READDIR, /* the subtree READDIR (op) */
    PH_GET_R_CLOSE,   /* the CLOSE of the drained listing (op) */
    PH_PUMP           /* the window drives itself: the single ops, the drained walk (op) */
};

/*
 * the request kinds of the train ring: the reply routes by the record,
 * the slot phase picks the meaning of the shared shapes (the STAT,
 * the OPEN/CLOSE/READ of the payload and of the verify tail)
 */

enum {
    REQ_STAT = 1,   /* the remote STAT: the file slot or the -r root */
    REQ_OPEN,       /* the OPEN: the write or the read shape */
    REQ_WRITE,      /* the payload WRITE, the len rides the record */
    REQ_READ,       /* the payload/verify READ, the bound rides the record */
    REQ_CLOSE,      /* the CLOSE of the slot handle */
    REQ_SETSTAT,    /* the mtime stamp of the written file */
    REQ_MKDIR,      /* the walk: the remote mkdir level */
    REQ_MKDIR_STAT, /* the walk: the EEXIST tolerance STAT */
    REQ_OPENDIR,    /* the walk: the subtree OPENDIR */
    REQ_READDIR,    /* the walk: the subtree READDIR */
    REQ_CLOSEDIR    /* the walk: the CLOSE of the drained listing */
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

/*
 * one file of the transfer window: while the file streams its chunks
 * the walk already OPENs the next one; the slot carries everything
 * the per-file phases need, the free slot rides the zero phase
 */

typedef struct {
    char *local_path;
    char *remote_path;

    int      fd;        /* the local file of the transfer */
    uint64_t file_size; /* the local size on put, the remote on get */
    uint32_t mtime;     /* the local mtime on put, the remote on get (R7) */
    uint64_t offset;    /* the receive cursor (the pwrite position, the progress) */
    uint64_t emit_off;  /* the wire offset of the next train request */
    uint32_t inflight;  /* the requests of this file emitted without a reply */

    u_char *handle;
    size_t  handle_len;

    /* the checksum tail of the file */

    void    *md; /* EVP_MD_CTX */
    u_char   digest[EVP_MAX_MD_SIZE];
    uint64_t hash_len;

    unsigned trunc : 1;
    unsigned stamp : 1;         /* the transfer wrote data: the peer takes the mtime (R7) */
    unsigned dead : 1;          /* the file failed: the window drains it out */
    unsigned close_pending : 1; /* the dying handle waits for the window room */

    int phase; /* the per-file phase, 0 = the free slot */
} s3_cli_slot_t;

/*
 * the record of one outstanding request: the reply consumes the
 * oldest one and routes by it (the replies ride the byte stream in
 * request order)
 */

typedef struct {
    uint32_t len;  /* the WRITE payload len or the READ bound */
    uint8_t  kind; /* the request kind */
    int8_t   slot; /* the file slot, -1 = the walk request */
} s3_cli_req_t;

/* the opaque operation context of the header */

typedef struct {
    int kind;
    int phase; /* the walk producer phase of the op */

    char *local_path; /* the -r roots (the walk request surface) */
    char *remote_path;

    uint32_t expect_id; /* the id of the oldest outstanding request */
    uint32_t inflight;  /* the requests emitted without a reply */

    /* the file window: the pipelined files (one for the single ops) */

    s3_cli_slot_t slots[S3_SSH3_SFTP_CLI_FILES];

    u_char *io_buf; /* the shared chunk scratch of the emissions */

    /* the outstanding request ring: the reply routes by the record */

    s3_cli_req_t req_ring[S3_SSH3_SFTP_CLI_INFLIGHT];
    uint32_t     io_head;
    uint32_t     io_tail;

    unsigned resume : 1;
    unsigned verify : 1;
    unsigned walk_busy : 1; /* one walk request rides the ring */

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
static void     s3_cli_req_push(s3_ssh3_sftp_cli_t *t, uint8_t kind, int slot, uint32_t len);
static s3_int_t s3_cli_emit_path(s3_ssh3_sftp_cli_t *t, s3_cli_encode_path_pt encode, uint8_t kind,
                                 int slot, const char *path);
static s3_int_t s3_cli_emit_handle(s3_ssh3_sftp_cli_t *t, s3_cli_encode_handle_pt encode,
                                   uint8_t kind, int slot, const u_char *handle, size_t handle_len);
static s3_int_t s3_cli_emit_open(s3_ssh3_sftp_cli_t *t, uint8_t kind, int slot, const char *path,
                                 unsigned creat);
static s3_int_t s3_cli_emit_read(s3_ssh3_sftp_cli_t *t, uint8_t kind, int slot, uint64_t offset,
                                 size_t len);
static s3_int_t s3_cli_emit_write(s3_ssh3_sftp_cli_t *t, uint8_t kind, int slot, const u_char *data,
                                  size_t len);
static s3_int_t s3_cli_emit_mkdir(s3_ssh3_sftp_cli_t *t, const char *path, size_t len);
static s3_int_t s3_cli_emit_setstat(s3_ssh3_sftp_cli_t *t, int slot);

static char          *s3_cli_strdup(s3_pool_t *pool, const char *s);
static char          *s3_cli_path_join(s3_pool_t *pool, const char *dir, const char *name);
static void           s3_cli_progress(s3_ssh3_sftp_cli_t *t, uint64_t sent, uint64_t total);
static void           s3_cli_fail_count(s3_ssh3_sftp_cli_t *t, uint32_t code);
static void           s3_cli_file_fail(s3_ssh3_sftp_cli_t *t, uint32_t code);
static void           s3_cli_fail_op(s3_ssh3_sftp_cli_t *t, uint32_t code);
static void           s3_cli_settle(s3_ssh3_sftp_cli_t *t);
static void           s3_cli_maybe_settle(s3_ssh3_sftp_cli_t *t);
static s3_int_t       s3_cli_handle_copy(s3_ssh3_sftp_cli_t *t, u_char **dst, size_t *dst_len,
                                         const s3_str_t *handle);
static int            s3_cli_attrs_is_dir(const s3_ssh3_sftp_attrs_t *a);
static int            s3_cli_attrs_is_reg(const s3_ssh3_sftp_attrs_t *a);
static int            s3_cli_dot_name(const char *name);
static size_t         s3_cli_mkdir_next(const char *path, size_t prev_len);
static int            s3_cli_mkdir_local_all(const char *path);
static s3_cli_slot_t *s3_cli_slot_take(s3_ssh3_sftp_cli_t *t);
static void           s3_cli_slot_drop(s3_ssh3_sftp_cli_t *t, s3_cli_slot_t *s);
static void           s3_cli_slot_kill(s3_ssh3_sftp_cli_t *t, s3_cli_slot_t *s, uint32_t code);
static void           s3_cli_slot_digest_final(s3_cli_slot_t *s);
static int  s3_cli_slot_local_digest(s3_ssh3_sftp_cli_t *t, s3_cli_slot_t *s, u_char *out);
static void s3_cli_slot_stamp_done(s3_ssh3_sftp_cli_t *t, s3_cli_slot_t *s);
static void s3_cli_slot_get_local_open(s3_ssh3_sftp_cli_t *t, s3_cli_slot_t *s);

static s3_ssh3_sftp_cli_frame_t *s3_cli_frame_push(s3_ssh3_sftp_cli_t *t, const char *local_dir,
                                                   const char *remote_dir);
static s3_int_t                  s3_cli_emit_init(s3_ssh3_sftp_cli_t *t);
static s3_int_t                  s3_cli_parse_status_body(const s3_str_t *body, uint32_t *code);
static s3_int_t s3_cli_on_status(s3_ssh3_sftp_cli_t *t, const s3_str_t *body, uint32_t *code);
static s3_int_t s3_cli_parse_handle_body(const s3_str_t *body, s3_str_t *handle);
static s3_int_t s3_cli_parse_data_body(const s3_str_t *body, s3_str_t *data);
static s3_int_t s3_cli_parse_attrs_body(const s3_str_t *body, s3_ssh3_sftp_attrs_t *a);
static s3_int_t s3_cli_parse_name_batch(s3_ssh3_sftp_cli_t *t, const s3_str_t *body);
static int      s3_cli_put_r_fill(s3_ssh3_sftp_cli_t *t, int ix);
static int      s3_cli_get_r_fill(s3_ssh3_sftp_cli_t *t, int ix);
static s3_int_t s3_cli_walk_pump(s3_ssh3_sftp_cli_t *t, unsigned *moved);
static s3_int_t s3_cli_slot_pump(s3_ssh3_sftp_cli_t *t, int ix, unsigned *moved);
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

/* the train ring: the record of the request its reply routes by */

static void
s3_cli_req_push(s3_ssh3_sftp_cli_t *t, uint8_t kind, int slot, uint32_t len)
{
    s3_ssh3_sftp_cli_op_t *op = t->op;
    s3_cli_req_t          *r;

    r = &op->req_ring[op->io_tail];

    r->len = len;
    r->kind = kind;
    r->slot = (int8_t)slot;

    op->io_tail = (op->io_tail + 1) % S3_SSH3_SFTP_CLI_INFLIGHT;

    if (slot >= 0) {
        op->slots[slot].inflight++;
    }
}

static s3_int_t
s3_cli_emit_path(s3_ssh3_sftp_cli_t *t, s3_cli_encode_path_pt encode, uint8_t kind, int slot,
                 const char *path)
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

    s3_cli_req_push(t, kind, slot, 0);
    s3_cli_commit(t, need, 1);

    return S3_OK;
}

static s3_int_t
s3_cli_emit_handle(s3_ssh3_sftp_cli_t *t, s3_cli_encode_handle_pt encode, uint8_t kind, int slot,
                   const u_char *handle, size_t handle_len)
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

    s3_cli_req_push(t, kind, slot, 0);
    s3_cli_commit(t, need, 1);

    return S3_OK;
}

static s3_int_t
s3_cli_emit_open(s3_ssh3_sftp_cli_t *t, uint8_t kind, int slot, const char *path, unsigned creat)
{
    s3_ssh3_sftp_cli_op_t *op = t->op;
    s3_cli_slot_t         *s = &op->slots[slot];
    s3_ssh3_sftp_attrs_t   attrs;
    s3_str_t               path_s;
    uint32_t               pflags;
    uintptr_t              need;

    path_s.len = s3_strlen(path);
    path_s.data = (u_char *)path;

    s3_memzero(&attrs, sizeof(attrs));

    if (creat) {

        /* the resume reopens without the trunc, the fresh put clears */

        pflags = S3_SSH3_SFTP_FXF_WRITE | S3_SSH3_SFTP_FXF_CREAT;

        if (s->trunc) {
            pflags |= S3_SSH3_SFTP_FXF_TRUNC;
        }

        attrs.flags = S3_SSH3_SFTP_ATTR_PERMISSION;
        attrs.perms = 0644;

    } else {
        pflags = S3_SSH3_SFTP_FXF_READ;
    }

    need = s3_ssh3_sftp_encode_open(NULL, t->next_id, &path_s, pflags, &attrs);

    if (s3_cli_buf_grow(t->pool, &t->out, t->out_len, &t->out_cap, need) != S3_OK) {
        return S3_ERROR;
    }

    (void)s3_ssh3_sftp_encode_open(t->out + t->out_len, t->next_id, &path_s, pflags, &attrs);

    s3_cli_req_push(t, kind, slot, 0);
    s3_cli_commit(t, need, 1);

    return S3_OK;
}

static s3_int_t
s3_cli_emit_read(s3_ssh3_sftp_cli_t *t, uint8_t kind, int slot, uint64_t offset, size_t len)
{
    s3_ssh3_sftp_cli_op_t *op = t->op;
    s3_cli_slot_t         *s = &op->slots[slot];
    s3_str_t               handle;
    uintptr_t              need;

    handle.len = s->handle_len;
    handle.data = s->handle;

    need = s3_ssh3_sftp_encode_read(NULL, t->next_id, &handle, offset, len);

    if (s3_cli_buf_grow(t->pool, &t->out, t->out_len, &t->out_cap, need) != S3_OK) {
        return S3_ERROR;
    }

    /* the requested len rides the train ring: the DATA reply is
     * checked against it; the emission cursor moves here, ahead of
     * the outstanding window, the receive cursor rides the replies */

    s3_cli_req_push(t, kind, slot, (uint32_t)len);

    s->emit_off = offset + len;

    (void)s3_ssh3_sftp_encode_read(t->out + t->out_len, t->next_id, &handle, offset, len);
    s3_cli_commit(t, need, 1);

    return S3_OK;
}

static s3_int_t
s3_cli_emit_write(s3_ssh3_sftp_cli_t *t, uint8_t kind, int slot, const u_char *data, size_t len)
{
    s3_ssh3_sftp_cli_op_t *op = t->op;
    s3_cli_slot_t         *s = &op->slots[slot];
    s3_str_t               handle, payload;
    uintptr_t              need;

    handle.len = s->handle_len;
    handle.data = s->handle;

    payload.len = len;
    payload.data = (u_char *)data;

    need = s3_ssh3_sftp_encode_write(NULL, t->next_id, &handle, s->emit_off, &payload);

    if (s3_cli_buf_grow(t->pool, &t->out, t->out_len, &t->out_cap, need) != S3_OK) {
        return S3_ERROR;
    }

    /* the payload len rides the train ring, the STATUS OK of this
     * request advances the receive cursor by it; the emission cursor
     * moves here, ahead of the outstanding window */

    s3_cli_req_push(t, kind, slot, (uint32_t)len);

    (void)s3_ssh3_sftp_encode_write(t->out + t->out_len, t->next_id, &handle, s->emit_off,
                                    &payload);

    s->emit_off += len;

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

    s3_cli_req_push(t, REQ_MKDIR, -1, 0);
    s3_cli_commit(t, need, 1);

    return S3_OK;
}

/* the R7 stamp: the ACMODTIME pair carries the source mtime, the
 * reference Chtimes shape (both times ride the same value) */

static s3_int_t
s3_cli_emit_setstat(s3_ssh3_sftp_cli_t *t, int slot)
{
    s3_ssh3_sftp_cli_op_t *op = t->op;
    s3_cli_slot_t         *s = &op->slots[slot];
    s3_ssh3_sftp_attrs_t   attrs;
    s3_str_t               path_s;
    uintptr_t              need;

    path_s.len = s3_strlen(s->remote_path);
    path_s.data = (u_char *)s->remote_path;

    s3_memzero(&attrs, sizeof(attrs));
    attrs.flags = S3_SSH3_SFTP_ATTR_ACMODTIME;
    attrs.atime = s->mtime;
    attrs.mtime = s->mtime;

    need = s3_ssh3_sftp_encode_setstat(NULL, t->next_id, &path_s, &attrs);

    if (s3_cli_buf_grow(t->pool, &t->out, t->out_len, &t->out_cap, need) != S3_OK) {
        return S3_ERROR;
    }

    (void)s3_ssh3_sftp_encode_setstat(t->out + t->out_len, t->next_id, &path_s, &attrs);

    s3_cli_req_push(t, REQ_SETSTAT, slot, 0);
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

/* the failure bookkeeping of the walk: the first verdict rides out
 * with the op (the reference counts the per-file failures) */

static void
s3_cli_fail_count(s3_ssh3_sftp_cli_t *t, uint32_t code)
{
    s3_ssh3_sftp_cli_op_t *op = t->op;

    if (!op->failed) {
        op->failed = 1;
        op->fail_status = code;
    }

    t->status = code;
}

/* the -r walk: one file down, the walk goes on (the reference counts);
 * the walk with no frames to resume cannot re-phase (the WALK resume
 * would index the empty frame stack), the op dies there -- the
 * terminal FAIL of the failed root stat of the -r download */

static void
s3_cli_file_fail(s3_ssh3_sftp_cli_t *t, uint32_t code)
{
    s3_ssh3_sftp_cli_op_t *op = t->op;

    s3_cli_fail_count(t, code);

    if (op->frame_count == 0) {

        t->state = S3_SSH3_SFTP_CLI_FAIL;

        return;
    }

    op->phase = (op->kind == S3_SSH3_SFTP_CLI_OP_PUT_R) ? PH_PUT_R_WALK : PH_GET_R_WALK;
}

/* the terminal failure of the operation: the state leaves the RUN,
 * the outstanding replies ride the drain unparsed */

static void
s3_cli_fail_op(s3_ssh3_sftp_cli_t *t, uint32_t code)
{
    s3_ssh3_sftp_cli_op_t *op = t->op;
    uint32_t               i;

    for (i = 0; i < op->frame_count; i++) {

        if (op->frames[i].dir != NULL) {
            (void)s3_cli_fs_closedir(op->frames[i].dir);
            op->frames[i].dir = NULL;
        }
    }

    op->frame_count = 0;

    /* the local files of the window close with the op */

    for (i = 0; i < S3_SSH3_SFTP_CLI_FILES; i++) {

        if (op->slots[i].fd >= 0) {
            (void)close(op->slots[i].fd);
            op->slots[i].fd = -1;
        }

        if (op->slots[i].md != NULL) {
            EVP_MD_CTX_free(op->slots[i].md);
            op->slots[i].md = NULL;
        }
    }

    t->state = S3_SSH3_SFTP_CLI_FAIL;
    t->status = code;
}

/* the settle: the walk drained and the window is empty, the verdict
 * rides (the counted failures turn the walk into the FAIL) */

static void
s3_cli_settle(s3_ssh3_sftp_cli_t *t)
{
    s3_ssh3_sftp_cli_op_t *op = t->op;

    if (op->failed) {
        t->state = S3_SSH3_SFTP_CLI_FAIL;
        t->status = op->fail_status;

    } else {
        t->state = S3_SSH3_SFTP_CLI_DONE;
        t->status = S3_SSH3_SFTP_FX_OK;
    }
}

/* the settle check: the walk is done (the pump phase, no frames) and
 * every slot of the window is free */

static void
s3_cli_maybe_settle(s3_ssh3_sftp_cli_t *t)
{
    s3_ssh3_sftp_cli_op_t *op = t->op;
    uint32_t               i;

    if (t->state != S3_SSH3_SFTP_CLI_RUN || op->phase != PH_PUMP || op->frame_count != 0) {
        return;
    }

    for (i = 0; i < S3_SSH3_SFTP_CLI_FILES; i++) {

        if (op->slots[i].phase != 0) {
            return;
        }
    }

    s3_cli_settle(t);
}

/* the free slot of the window, NULL when the file window is full */

static s3_cli_slot_t *
s3_cli_slot_take(s3_ssh3_sftp_cli_t *t)
{
    s3_ssh3_sftp_cli_op_t *op = t->op;
    uint32_t               i;

    for (i = 0; i < S3_SSH3_SFTP_CLI_FILES; i++) {

        if (op->slots[i].phase == 0) {
            return &op->slots[i];
        }
    }

    return NULL;
}

/* the slot back to the free pool: the local file closes, the digest
 * ctx dies, the settle check runs (the last file of a drained walk
 * settles the op) */

static void
s3_cli_slot_drop(s3_ssh3_sftp_cli_t *t, s3_cli_slot_t *s)
{
    if (s->fd >= 0) {
        (void)close(s->fd);
    }

    if (s->md != NULL) {
        EVP_MD_CTX_free(s->md);
    }

    s3_memzero(s, sizeof(*s));
    s->fd = -1;

    s3_cli_maybe_settle(t);
}

/*
 * the death of one file: the failure counts, the walk goes on (the
 * walk-alive semantics of the reference); the remote handle closes
 * through the window room, the outstanding replies drain
 * uninterpreted, the last one drops the slot
 */

static void
s3_cli_slot_kill(s3_ssh3_sftp_cli_t *t, s3_cli_slot_t *s, uint32_t code)
{
    if (s->dead) {
        return;
    }

    s->dead = 1;

    if (s->fd >= 0) {
        (void)close(s->fd);
        s->fd = -1;
    }

    if (s->md != NULL) {
        EVP_MD_CTX_free(s->md);
        s->md = NULL;
    }

    s3_cli_fail_count(t, code);

    if (s->handle != NULL) {
        s->close_pending = 1;

        return;
    }

    if (s->inflight == 0) {
        s3_cli_slot_drop(t, s);
    }
}

static void
s3_cli_slot_digest_final(s3_cli_slot_t *s)
{
    unsigned dlen;

    if (s->md != NULL) {
        (void)EVP_DigestFinal_ex(s->md, s->digest, &dlen);
        EVP_MD_CTX_free(s->md);
        s->md = NULL;
    }
}

/* the SHA-256 of the local file through the slot fd */

static int
s3_cli_slot_local_digest(s3_ssh3_sftp_cli_t *t, s3_cli_slot_t *s, u_char *out)
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

        n = s3_cli_fs_pread(s->fd, op->io_buf, S3_SSH3_SFTP_CLI_CHUNK, off);

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
 * the R7 tail of a finished file: the peer inherits the source mtime
 * so the next --continue skips by size+mtime, not by the size alone.
 * The put stamps the remote through SETSTAT (one more wire turn),
 * the get stamps the local file right here; the refusals are not
 * fatal, they cost one redundant transfer later, never data
 */

static void
s3_cli_slot_stamp_done(s3_ssh3_sftp_cli_t *t, s3_cli_slot_t *s)
{
    s3_ssh3_sftp_cli_op_t *op = t->op;
    struct timespec        ts[2];

    if (op->kind == S3_SSH3_SFTP_CLI_OP_PUT || op->kind == S3_SSH3_SFTP_CLI_OP_PUT_R) {

        if (s->stamp) {
            s->phase = PH_PUT_SETSTAT;
            return;
        }

    } else if (s->stamp && s->fd >= 0) {

        ts[0].tv_sec = (time_t)s->mtime;
        ts[0].tv_nsec = 0;
        ts[1] = ts[0];

        (void)s3_cli_fs_futimens(s->fd, ts);
    }

    s3_cli_slot_drop(t, s);
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
 * the local side of a download slot: the resume checks against the
 * remote size and mtime, the equal pair skips straight to the verify
 * tail, the equal size with the differing mtime is the stale copy and
 * re-transfers (R7), the fresh download truncates
 */

static void
s3_cli_slot_get_local_open(s3_ssh3_sftp_cli_t *t, s3_cli_slot_t *s)
{
    s3_ssh3_sftp_cli_op_t *op = t->op;
    struct stat            st;
    uint64_t               start = 0;
    int                    trunc = 1;

    if (s->fd >= 0) {
        (void)close(s->fd);
        s->fd = -1;
    }

    if (op->resume && s3_cli_fs_stat(s->local_path, &st) == 0 && !S_ISDIR(st.st_mode)) {

        if ((uint64_t)st.st_size > s->file_size) {

            /* the reference: the local side is the larger one */

            s3_cli_slot_kill(t, s, S3_SSH3_SFTP_FX_FAILURE);
            return;
        }

        if ((uint64_t)st.st_size == s->file_size && (uint32_t)st.st_mtime == s->mtime) {

            /* fully downloaded, the inherited mtime agrees: the
             * verify tail only, keep the bytes (R7) */

            s->fd = s3_cli_fs_open_rdwr(s->local_path);

            if (s->fd < 0) {
                s3_cli_slot_kill(t, s, S3_SSH3_SFTP_FX_FAILURE);
                return;
            }

            s->offset = 0;
            s->emit_off = 0;
            s->stamp = 0;
            s->phase = PH_VERIFY_STAT;

            return;
        }

        /* the size alone cannot prove the content: the equal size
         * with the differing mtime is the stale copy, it re-transfers
         * from zero (R7); the smaller local appends from its size */

        if ((uint64_t)st.st_size < s->file_size) {
            start = (uint64_t)st.st_size;
            trunc = 0;
        }

        s->stamp = 1;
    }

    s->fd = s3_cli_fs_open_creat(s->local_path, trunc);

    if (s->fd < 0) {
        s3_cli_slot_kill(t, s, S3_SSH3_SFTP_FX_FAILURE);
        return;
    }

    s->offset = start;
    s->emit_off = start;
    s->phase = PH_GET_OPEN;
}

/*
 * the upload walk, one dirent per call into the given free slot: the
 * regular file fills the slot (the local fd opens here, the wire
 * side rides the slot phases), the directory descends through the
 * async mkdir levels, the drained frame pops; the special files skip
 * like in the reference WalkDir. Returns 1 when the walk moved, 0
 * when it waits (defensive, the caller checked the free slot), -1 on
 * the emission failure
 */

static int
s3_cli_put_r_fill(s3_ssh3_sftp_cli_t *t, int ix)
{
    s3_ssh3_sftp_cli_op_t    *op = t->op;
    s3_ssh3_sftp_cli_frame_t *frame;
    s3_cli_slot_t            *s = &op->slots[ix];
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
                return 1;
            }

            /* the directory drained: pop, the parent walk resumes */

            (void)s3_cli_fs_closedir(frame->dir);
            frame->dir = NULL;
            op->frame_count--;

            if (op->frame_count == 0) {

                /* the tree drained: the window settles the op */

                op->phase = PH_PUMP;
                s3_cli_maybe_settle(t);

                return 1;
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
            return -1;
        }

        if (s3_cli_fs_stat(local_sub, &st) != 0) {
            s3_cli_file_fail(t, S3_SSH3_SFTP_FX_FAILURE);
            continue;
        }

        if (S_ISDIR(st.st_mode)) {

            remote_sub = s3_cli_path_join(t->pool, frame->remote_dir, de->d_name);

            if (remote_sub == NULL) {
                s3_cli_fail_op(t, S3_SSH3_SFTP_FX_FAILURE);
                return -1;
            }

            /* the remote levels build async, the frame descends after */

            op->pending_local = local_sub;
            op->pending_remote = remote_sub;
            op->mkdir_path = remote_sub;
            op->mkdir_len = 0;
            op->phase = PH_MKDIR;

            return 1;
        }

        if (!S_ISREG(st.st_mode)) {
            continue;
        }

        remote_sub = s3_cli_path_join(t->pool, frame->remote_dir, de->d_name);

        if (remote_sub == NULL) {
            s3_cli_fail_op(t, S3_SSH3_SFTP_FX_FAILURE);
            return -1;
        }

        s->fd = s3_cli_fs_open_rd(local_sub);

        if (s->fd < 0) {
            s3_cli_file_fail(t, S3_SSH3_SFTP_FX_FAILURE);
            continue;
        }

        if (s3_cli_fs_fstat(s->fd, &st) != 0) {
            (void)close(s->fd);
            s->fd = -1;
            s3_cli_file_fail(t, S3_SSH3_SFTP_FX_FAILURE);
            continue;
        }

        s->local_path = local_sub;
        s->remote_path = remote_sub;
        s->file_size = (uint64_t)st.st_size;
        s->mtime = (uint32_t)st.st_mtime;
        s->offset = 0;
        s->emit_off = 0;
        s->stamp = 1;
        s->phase = op->resume ? PH_PUT_STAT : PH_PUT_OPEN;

        if (!op->resume) {
            s->trunc = 1;
        }

        return 1;
    }
}

/*
 * the download walk, one entry per call into the given free slot: the
 * regular file fills the slot (the local side opens here), the
 * directory builds its local levels first and descends through the
 * async OPENDIR/READDIR chain, the drained batch rides the next
 * READDIR. Returns 1 when the walk moved, 0 when it waits, -1 on the
 * emission failure
 */

static int
s3_cli_get_r_fill(s3_ssh3_sftp_cli_t *t, int ix)
{
    s3_ssh3_sftp_cli_op_t    *op = t->op;
    s3_ssh3_sftp_cli_frame_t *frame;
    s3_cli_slot_t            *s = &op->slots[ix];
    s3_ssh3_sftp_cli_entry_t *e;
    char                     *local_sub, *remote_sub;

    for (;;) {

        frame = &op->frames[op->frame_count - 1];

        if (frame->entry_pos >= frame->entry_count) {

            /* the batch drained: the next READDIR */

            if (frame->handle == NULL) {
                s3_cli_fail_op(t, S3_SSH3_SFTP_FX_FAILURE);
                return 1;
            }

            op->phase = PH_GET_R_READDIR;

            return 1;
        }

        e = &frame->entries[frame->entry_pos++];

        if (s3_cli_dot_name(e->name)) {
            continue;
        }

        local_sub = s3_cli_path_join(t->pool, frame->local_dir, e->name);
        remote_sub = s3_cli_path_join(t->pool, frame->remote_dir, e->name);

        if (local_sub == NULL || remote_sub == NULL) {
            s3_cli_fail_op(t, S3_SSH3_SFTP_FX_FAILURE);
            return -1;
        }

        if (e->is_dir) {

            if (s3_cli_mkdir_local_all(local_sub) != 0) {
                s3_cli_file_fail(t, S3_SSH3_SFTP_FX_FAILURE);
                continue;
            }

            if (s3_cli_frame_push(t, local_sub, remote_sub) == NULL) {
                s3_cli_fail_op(t, S3_SSH3_SFTP_FX_FAILURE);
                return 1;
            }

            op->phase = PH_GET_R_OPENDIR;

            return 1;
        }

        if (e->is_reg) {

            s->local_path = local_sub;
            s->remote_path = remote_sub;
            s->file_size = e->size;
            s->mtime = e->mtime;
            s->stamp = 1;

            /* the local side opens here, the remote side rides the
             * slot phases; the local failure kills the file only */

            s3_cli_slot_get_local_open(t, s);

            return 1;
        }

        /* the special entries skip */
    }
}

/*
 * the engine: the pump fills the free slots from the walk and drains
 * the ready slots into the window; the async walk requests (the mkdir
 * levels, the OPENDIR/READDIR/CLOSEDIR, the -r root stat) ride the
 * same ring one at a time and re-enter the pump on their replies
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

/* the walk side of the pump: one walk request at a time (the
 * walk_busy pin), the walk fills one free slot per pass */

static s3_int_t
s3_cli_walk_pump(s3_ssh3_sftp_cli_t *t, unsigned *moved)
{
    s3_ssh3_sftp_cli_op_t    *op = t->op;
    s3_ssh3_sftp_cli_frame_t *frame;
    s3_cli_slot_t            *s;
    char                     *prefix;
    size_t                    next;
    int                       filled, ix;
    s3_int_t                  rc;

    switch (op->phase) {

    case PH_MKDIR:

        next = s3_cli_mkdir_next(op->mkdir_path, op->mkdir_len);

        if (next == 0) {

            /* the levels exist: the pending frame joins the walk */

            if (s3_cli_frame_push(t, op->pending_local, op->pending_remote) == NULL) {
                s3_cli_fail_op(t, S3_SSH3_SFTP_FX_FAILURE);
                return S3_OK;
            }

            op->phase = PH_PUT_R_WALK;
            (*moved)++;

            return S3_OK;
        }

        if (op->walk_busy || op->inflight >= S3_SSH3_SFTP_CLI_INFLIGHT) {
            return S3_OK;
        }

        op->mkdir_len = next;

        rc = s3_cli_emit_mkdir(t, op->mkdir_path, next);

        if (rc != S3_OK) {
            return rc;
        }

        op->walk_busy = 1;
        (*moved)++;

        return S3_OK;

    case PH_MKDIR_STAT:

        if (op->walk_busy || op->inflight >= S3_SSH3_SFTP_CLI_INFLIGHT) {
            return S3_OK;
        }

        prefix = s3_pnalloc(t->pool, op->mkdir_len + 1);

        if (prefix == NULL) {
            s3_cli_fail_op(t, S3_SSH3_SFTP_FX_FAILURE);
            return S3_OK;
        }

        s3_memcpy(prefix, op->mkdir_path, op->mkdir_len);
        prefix[op->mkdir_len] = '\0';

        rc = s3_cli_emit_path(t, s3_ssh3_sftp_encode_stat, REQ_MKDIR_STAT, -1, prefix);

        if (rc != S3_OK) {
            return rc;
        }

        op->walk_busy = 1;
        (*moved)++;

        return S3_OK;

    case PH_GET_STAT:

        /* the root STAT of the download walk, one request at a time */

        if (op->walk_busy || op->inflight >= S3_SSH3_SFTP_CLI_INFLIGHT) {
            return S3_OK;
        }

        rc = s3_cli_emit_path(t, s3_ssh3_sftp_encode_stat, REQ_STAT, -1, op->remote_path);

        if (rc != S3_OK) {
            return rc;
        }

        op->walk_busy = 1;
        (*moved)++;

        return S3_OK;

    case PH_GET_R_OPENDIR:

        if (op->walk_busy || op->inflight >= S3_SSH3_SFTP_CLI_INFLIGHT) {
            return S3_OK;
        }

        frame = &op->frames[op->frame_count - 1];

        rc = s3_cli_emit_path(t, s3_ssh3_sftp_encode_opendir, REQ_OPENDIR, -1, frame->remote_dir);

        if (rc != S3_OK) {
            return rc;
        }

        op->walk_busy = 1;
        (*moved)++;

        return S3_OK;

    case PH_GET_R_READDIR:

        if (op->walk_busy || op->inflight >= S3_SSH3_SFTP_CLI_INFLIGHT) {
            return S3_OK;
        }

        frame = &op->frames[op->frame_count - 1];

        rc = s3_cli_emit_handle(t, s3_ssh3_sftp_encode_readdir, REQ_READDIR, -1, frame->handle,
                                frame->handle_len);

        if (rc != S3_OK) {
            return rc;
        }

        op->walk_busy = 1;
        (*moved)++;

        return S3_OK;

    case PH_GET_R_CLOSE:

        if (op->walk_busy || op->inflight >= S3_SSH3_SFTP_CLI_INFLIGHT) {
            return S3_OK;
        }

        frame = &op->frames[op->frame_count - 1];

        rc = s3_cli_emit_handle(t, s3_ssh3_sftp_encode_close, REQ_CLOSEDIR, -1, frame->handle,
                                frame->handle_len);

        if (rc != S3_OK) {
            return rc;
        }

        op->walk_busy = 1;
        (*moved)++;

        return S3_OK;

    case PH_PUT_R_WALK:
    case PH_GET_R_WALK:

        /* the walk fill: one dirent or entry per pass into a free
         * slot, the pipeline is the file window of one directory
         * (the subtree recursion rides the serial walk requests) */

        for (;;) {

            if (op->walk_busy) {
                return S3_OK;
            }

            s = s3_cli_slot_take(t);

            if (s == NULL) {
                return S3_OK; /* the file window is full */
            }

            ix = (int)(s - op->slots);

            filled = (op->kind == S3_SSH3_SFTP_CLI_OP_PUT_R) ? s3_cli_put_r_fill(t, ix)
                                                             : s3_cli_get_r_fill(t, ix);

            if (filled < 0) {
                return S3_ERROR;
            }

            if (filled == 0) {
                return S3_OK;
            }

            (*moved)++;

            if (op->phase != PH_PUT_R_WALK && op->phase != PH_GET_R_WALK) {
                return S3_OK; /* the walk descended, drained or failed */
            }

            if (t->state != S3_SSH3_SFTP_CLI_RUN) {
                return S3_OK;
            }
        }

    case PH_PUMP:
        return S3_OK;

    default:
        return S3_ERROR;
    }
}

/* the slot side of the pump: the per-file phases of one file emit
 * into the window (the trains fill it, the single phases ride the
 * replies), the dying slot only closes its remote handle */

static s3_int_t
s3_cli_slot_pump(s3_ssh3_sftp_cli_t *t, int ix, unsigned *moved)
{
    s3_ssh3_sftp_cli_op_t *op = t->op;
    s3_cli_slot_t         *s = &op->slots[ix];
    size_t                 len;
    ssize_t                n;
    s3_int_t               rc;

    if (s->phase == 0) {
        return S3_OK; /* the free slot */
    }

    if (s->dead) {

        /* the dying file: the handle closes with the window room,
         * the outstanding replies drain uninterpreted */

        if (s->close_pending && op->inflight < S3_SSH3_SFTP_CLI_INFLIGHT) {

            s->close_pending = 0;

            rc = s3_cli_emit_handle(t, s3_ssh3_sftp_encode_close, REQ_CLOSE, ix, s->handle,
                                    s->handle_len);

            if (rc != S3_OK) {
                return rc;
            }

            (*moved)++;
        }

        return S3_OK;
    }

    if (s->phase != PH_PUT_WRITE && s->phase != PH_GET_READ && s->phase != PH_VERIFY_READ &&
        s->inflight > 0) {

        /* the single request of the phase rides the replies (the
         * trains top the window up instead) */

        return S3_OK;
    }

    for (;;) {

        if (op->inflight >= S3_SSH3_SFTP_CLI_INFLIGHT) {
            return S3_OK; /* the window is full: the replies re-pump */
        }

        switch (s->phase) {

            /* the single-request phases: one request, the reply re-phases */

        case PH_PUT_STAT:
        case PH_GET_STAT:
        case PH_VERIFY_STAT:

            rc = s3_cli_emit_path(t, s3_ssh3_sftp_encode_stat, REQ_STAT, ix, s->remote_path);

            if (rc != S3_OK) {
                return rc;
            }

            (*moved)++;

            return S3_OK;

        case PH_PUT_OPEN:

            rc = s3_cli_emit_open(t, REQ_OPEN, ix, s->remote_path, 1);

            if (rc != S3_OK) {
                return rc;
            }

            (*moved)++;

            return S3_OK;

        case PH_GET_OPEN:
        case PH_VERIFY_OPEN:

            rc = s3_cli_emit_open(t, REQ_OPEN, ix, s->remote_path, 0);

            if (rc != S3_OK) {
                return rc;
            }

            (*moved)++;

            return S3_OK;

        case PH_PUT_CLOSE:
        case PH_GET_CLOSE:
        case PH_VERIFY_CLOSE:

            rc = s3_cli_emit_handle(t, s3_ssh3_sftp_encode_close, REQ_CLOSE, ix, s->handle,
                                    s->handle_len);

            if (rc != S3_OK) {
                return rc;
            }

            (*moved)++;

            return S3_OK;

        case PH_PUT_SETSTAT:

            rc = s3_cli_emit_setstat(t, ix);

            if (rc != S3_OK) {
                return rc;
            }

            (*moved)++;

            return S3_OK;

        case PH_PUT_WRITE: {

            /* the train: the window fills with the whole chunks of
             * the remaining payload, the replies top it up; the
             * emission cursor rides ahead of the outstanding window
             * of this file */

            while (s->emit_off < s->file_size && op->inflight < S3_SSH3_SFTP_CLI_INFLIGHT) {

                len = s->file_size - s->emit_off;

                if (len > S3_SSH3_SFTP_CLI_CHUNK) {
                    len = S3_SSH3_SFTP_CLI_CHUNK;
                }

                n = s3_cli_fs_pread(s->fd, op->io_buf, len, (int64_t)s->emit_off);

                if (n < 0) {
                    s3_cli_slot_kill(t, s, S3_SSH3_SFTP_FX_FAILURE);
                    return S3_OK;
                }

                if (n == 0) {

                    /* the local file shrank under the transfer: the
                     * file dies, its outstanding replies drain */

                    s3_cli_slot_kill(t, s, S3_SSH3_SFTP_FX_FAILURE);

                    return S3_OK;
                }

                if (s3_cli_emit_write(t, REQ_WRITE, ix, op->io_buf, (size_t)n) != S3_OK) {
                    return S3_ERROR;
                }

                (*moved)++;
            }

            if (s->offset >= s->file_size) {

                /* the tail replies of the train ride out before the
                 * close (the receive cursor must reach the size) */

                if (s->inflight > 0) {
                    return S3_OK;
                }

                s->phase = PH_PUT_CLOSE;

                continue;
            }

            return S3_OK;
        }

        case PH_GET_READ: {

            /* the train: the reads stay inside the stat size, the
             * replies cannot hit the EOF mid-window on a stable file;
             * the chunk rides the read bound (the channel
             * maxPacketSize minus the reply reserve), so the replies
             * of a dialect server never go short */

            while (s->emit_off < s->file_size && op->inflight < S3_SSH3_SFTP_CLI_INFLIGHT) {

                len = s->file_size - s->emit_off;

                if (len > t->read_bound) {
                    len = t->read_bound;
                }

                if (s3_cli_emit_read(t, REQ_READ, ix, s->emit_off, len) != S3_OK) {
                    return S3_ERROR;
                }

                (*moved)++;
            }

            if (s->offset >= s->file_size) {

                if (s->inflight > 0) {
                    return S3_OK;
                }

                s->phase = PH_GET_CLOSE;

                continue;
            }

            return S3_OK;
        }

        case PH_VERIFY_READ: {

            while (s->emit_off < s->file_size && op->inflight < S3_SSH3_SFTP_CLI_INFLIGHT) {

                len = s->file_size - s->emit_off;

                if (len > t->read_bound) {
                    len = t->read_bound;
                }

                if (s3_cli_emit_read(t, REQ_READ, ix, s->emit_off, len) != S3_OK) {
                    return S3_ERROR;
                }

                (*moved)++;
            }

            if (s->hash_len >= s->file_size) {

                if (s->inflight > 0) {
                    return S3_OK;
                }

                s3_cli_slot_digest_final(s);
                s->phase = PH_VERIFY_CLOSE;

                continue;
            }

            return S3_OK;
        }

        default:
            return S3_ERROR;
        }
    }
}

static s3_int_t
s3_cli_step(s3_ssh3_sftp_cli_t *t)
{
    s3_ssh3_sftp_cli_op_t *op = t->op;
    unsigned               moved;
    s3_int_t               rc;
    uint32_t               i;

    for (;;) {

        if (t->state != S3_SSH3_SFTP_CLI_RUN) {
            return S3_OK;
        }

        /* the INIT of the first operation rides before any request,
         * the VERSION reply re-enters through the dispatch */

        if (!t->negotiated) {
            return s3_cli_emit_init(t);
        }

        /* the drained walk with the empty window settles here */

        if (op->phase == PH_PUMP && op->frame_count == 0) {

            s3_cli_maybe_settle(t);

            if (t->state != S3_SSH3_SFTP_CLI_RUN) {
                return S3_OK;
            }
        }

        moved = 0;

        rc = s3_cli_walk_pump(t, &moved);

        if (rc != S3_OK) {
            return rc;
        }

        for (i = 0; i < S3_SSH3_SFTP_CLI_FILES && t->state == S3_SSH3_SFTP_CLI_RUN; i++) {

            rc = s3_cli_slot_pump(t, (int)i, &moved);

            if (rc != S3_OK) {
                return rc;
            }
        }

        if (!moved) {
            return S3_OK;
        }
    }
}

static s3_int_t
s3_cli_dispatch(s3_ssh3_sftp_cli_t *t, s3_ssh3_sftp_pkt_t *pkt)
{
    s3_ssh3_sftp_cli_op_t    *op = t->op;
    s3_ssh3_sftp_cli_frame_t *frame;
    s3_cli_slot_t            *s;
    s3_cli_req_t             *rec;
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

    /* the record of the oldest outstanding request routes the reply:
     * the phase switches inside see the request consumed */

    rec = &op->req_ring[op->io_head];
    op->io_head = (op->io_head + 1) % S3_SSH3_SFTP_CLI_INFLIGHT;

    if (rec->slot >= 0) {

        s = &op->slots[rec->slot];

        /* the reply consumes the request of this file before the
         * dispatch: the phase switches inside see the drained window */

        s->inflight--;

        if (s->dead) {

            /* the replies of the dying file ride out uninterpreted,
             * the last one drops the slot */

            if (s->inflight == 0) {
                s3_cli_slot_drop(t, s);
            }

            return s3_cli_step(t);
        }

    } else {
        s = NULL;
    }

    switch (rec->kind) {

    case REQ_STAT:

        if (s == NULL) {

            /* the root STAT of the download walk: the walk has no
             * frames yet, the failure is the terminal one */

            op->walk_busy = 0;

            if (pkt->type == S3_SSH3_SFTP_ATTRS) {

                if (s3_cli_parse_attrs_body(&pkt->body, &attrs) != S3_OK) {
                    return S3_ERROR;
                }

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

            if (pkt->type != S3_SSH3_SFTP_STATUS) {
                return S3_ERROR;
            }

            if (s3_cli_on_status(t, &pkt->body, &code) != S3_OK) {
                return S3_ERROR;
            }

            s3_cli_file_fail(t, code);

            return s3_cli_step(t);
        }

        /* the file STAT: the slot phase picks the meaning */

        switch (s->phase) {

        case PH_PUT_STAT:

            if (pkt->type == S3_SSH3_SFTP_STATUS) {

                if (s3_cli_on_status(t, &pkt->body, &code) != S3_OK) {
                    return S3_ERROR;
                }

                /* any miss reads as the missing remote: the fresh open */

                s->offset = 0;
                s->emit_off = 0;
                s->trunc = 1;
                s->stamp = 1;
                s->phase = PH_PUT_OPEN;

                return s3_cli_step(t);
            }

            if (pkt->type != S3_SSH3_SFTP_ATTRS) {
                return S3_ERROR;
            }

            if (s3_cli_parse_attrs_body(&pkt->body, &attrs) != S3_OK) {
                return S3_ERROR;
            }

            if (attrs.size > s->file_size) {

                /* the reference: the remote side is the larger one */

                s3_cli_slot_kill(t, s, S3_SSH3_SFTP_FX_FAILURE);
                return s3_cli_step(t);
            }

            if (attrs.size == s->file_size) {

                if ((attrs.flags & S3_SSH3_SFTP_ATTR_ACMODTIME) && attrs.mtime == s->mtime) {

                    /* fully uploaded, the stamped mtime agrees: the
                     * verify tail only (R7) */

                    s->stamp = 0;
                    s->phase = PH_VERIFY_STAT;

                    return s3_cli_step(t);
                }

                /* the size alone cannot prove the content: the equal
                 * size with the differing mtime is the stale remote,
                 * it re-transfers from zero (R7) */

                s->offset = 0;
                s->emit_off = 0;
                s->trunc = 1;
                s->stamp = 1;
                s->phase = PH_PUT_OPEN;

                return s3_cli_step(t);
            }

            /* the younger remote: the resume appends from its size */

            s->offset = attrs.size;
            s->emit_off = attrs.size;
            s->trunc = 0;
            s->stamp = 1;
            s->phase = PH_PUT_OPEN;

            return s3_cli_step(t);

        case PH_GET_STAT:

            if (pkt->type == S3_SSH3_SFTP_ATTRS) {

                if (s3_cli_parse_attrs_body(&pkt->body, &attrs) != S3_OK) {
                    return S3_ERROR;
                }

                if (s3_cli_attrs_is_dir(&attrs)) {

                    /* the reference: a directory needs the -r form */

                    s3_cli_slot_kill(t, s, S3_SSH3_SFTP_FX_FAILURE);
                    return s3_cli_step(t);
                }

                s->file_size = attrs.size;
                s->mtime = (attrs.flags & S3_SSH3_SFTP_ATTR_ACMODTIME) ? attrs.mtime : 0;

                s3_cli_slot_get_local_open(t, s);

                return s3_cli_step(t);
            }

            if (pkt->type != S3_SSH3_SFTP_STATUS) {
                return S3_ERROR;
            }

            if (s3_cli_on_status(t, &pkt->body, &code) != S3_OK) {
                return S3_ERROR;
            }

            s3_cli_slot_kill(t, s, code);

            return s3_cli_step(t);

        case PH_VERIFY_STAT:

            if (pkt->type == S3_SSH3_SFTP_ATTRS) {

                if (s3_cli_parse_attrs_body(&pkt->body, &attrs) != S3_OK) {
                    return S3_ERROR;
                }

                if (s3_cli_fs_fstat(s->fd, &st) != 0) {
                    s3_cli_slot_kill(t, s, S3_SSH3_SFTP_FX_FAILURE);
                    return s3_cli_step(t);
                }

                if (attrs.size != (uint64_t)st.st_size) {

                    /* the reference: the size mismatch fails the transfer */

                    s3_cli_slot_kill(t, s, S3_SSH3_SFTP_FX_FAILURE);
                    return s3_cli_step(t);
                }

                if (op->verify || attrs.size > S3_SSH3_SFTP_CLI_CHECKSUM_AUTO_THRESHOLD) {

                    s->md = EVP_MD_CTX_new();

                    if (s->md == NULL || EVP_DigestInit_ex(s->md, EVP_sha256(), NULL) != 1) {

                        if (s->md != NULL) {
                            EVP_MD_CTX_free(s->md);
                            s->md = NULL;
                        }

                        s3_cli_slot_kill(t, s, S3_SSH3_SFTP_FX_FAILURE);
                        return s3_cli_step(t);
                    }

                    s->hash_len = 0;
                    s->emit_off = 0;
                    s->phase = PH_VERIFY_OPEN;

                    return s3_cli_step(t);
                }

                s3_cli_slot_stamp_done(t, s);

                return s3_cli_step(t);
            }

            if (pkt->type != S3_SSH3_SFTP_STATUS) {
                return S3_ERROR;
            }

            if (s3_cli_on_status(t, &pkt->body, &code) != S3_OK) {
                return S3_ERROR;
            }

            s3_cli_slot_kill(t, s, code);

            return s3_cli_step(t);

        default:
            return S3_ERROR;
        }

    case REQ_OPEN:

        if (s == NULL) {
            return S3_ERROR;
        }

        if (pkt->type == S3_SSH3_SFTP_HANDLE) {

            if (s3_cli_parse_handle_body(&pkt->body, &body) != S3_OK ||
                s3_cli_handle_copy(t, &s->handle, &s->handle_len, &body) != S3_OK) {
                return S3_ERROR;
            }

            switch (s->phase) {

            case PH_PUT_OPEN:
                s->phase = PH_PUT_WRITE;
                break;

            case PH_GET_OPEN:
                s->phase = PH_GET_READ;
                break;

            case PH_VERIFY_OPEN:
                s->phase = PH_VERIFY_READ;
                break;

            default:
                return S3_ERROR;
            }

            return s3_cli_step(t);
        }

        if (pkt->type != S3_SSH3_SFTP_STATUS) {
            return S3_ERROR;
        }

        if (s3_cli_on_status(t, &pkt->body, &code) != S3_OK) {
            return S3_ERROR;
        }

        s3_cli_slot_kill(t, s, code);

        return s3_cli_step(t);

    case REQ_WRITE:

        if (s == NULL || s->phase != PH_PUT_WRITE || pkt->type != S3_SSH3_SFTP_STATUS) {
            return S3_ERROR;
        }

        if (s3_cli_on_status(t, &pkt->body, &code) != S3_OK) {
            return S3_ERROR;
        }

        if (code != S3_SSH3_SFTP_FX_OK) {
            s3_cli_slot_kill(t, s, code);
            return s3_cli_step(t);
        }

        /* the receive cursor rides the train ring: the reply of the
         * oldest outstanding WRITE carries its payload len */

        s->offset += rec->len;

        s3_cli_progress(t, s->offset, s->file_size);

        return s3_cli_step(t);

    case REQ_READ:

        if (s == NULL) {
            return S3_ERROR;
        }

        if (pkt->type == S3_SSH3_SFTP_DATA) {

            /* the requested len of the served slot rides the train
             * ring: a reply shorter than it mis-phases the positional
             * window, the file fails honestly (the read bound keeps a
             * dialect server out of this path) */

            if (s3_cli_parse_data_body(&pkt->body, &body) != S3_OK) {
                return S3_ERROR;
            }

            if (body.len > 0 && (size_t)body.len < rec->len) {

                s3_cli_slot_kill(t, s, S3_SSH3_SFTP_FX_FAILURE);

                return s3_cli_step(t);
            }

            if (s->phase == PH_GET_READ) {

                if (body.len > 0) {

                    n = s3_cli_fs_pwrite(s->fd, body.data, body.len, (int64_t)s->offset);

                    if (n < 0 || (size_t)n != body.len) {
                        s3_cli_slot_kill(t, s, S3_SSH3_SFTP_FX_FAILURE);
                        return s3_cli_step(t);
                    }

                    s->offset += body.len;
                    s3_cli_progress(t, s->offset, s->file_size);
                }

                /* the pkg/sftp dialect reads short at will: only the
                 * empty payload or the explicit STATUS EOF end the
                 * stream, the next READ keeps going otherwise; a
                 * mid-window end means the remote size died under the
                 * outstanding train of this file */

                if (body.len == 0) {

                    if (s->inflight > 0) {
                        s3_cli_slot_kill(t, s, S3_SSH3_SFTP_FX_FAILURE);
                        return s3_cli_step(t);
                    }

                    s->phase = PH_GET_CLOSE;
                }

                return s3_cli_step(t);
            }

            /* the verify read of the file: the digest rides the slot,
             * a reply shorter than the requested chunk would make the
             * digest lie, the file fails honestly */

            if (s->phase != PH_VERIFY_READ) {
                return S3_ERROR;
            }

            if (body.len > 0 && EVP_DigestUpdate(s->md, body.data, body.len) != 1) {
                return S3_ERROR;
            }

            s->hash_len += body.len;

            /* the pkg/sftp dialect reads short at will: only the empty
             * payload or the explicit STATUS EOF end the stream; the
             * size-capped train never ends it mid-window on a stable
             * file, an early end fails the digest honestly */

            if (body.len == 0) {

                if (s->inflight > 0) {
                    s3_cli_slot_kill(t, s, S3_SSH3_SFTP_FX_FAILURE);
                    return s3_cli_step(t);
                }

                s3_cli_slot_digest_final(s);
                s->phase = PH_VERIFY_CLOSE;
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

            if (s->inflight > 0) {

                /* the stream ended under the outstanding train: the
                 * remote size died, the file fails honestly */

                s3_cli_slot_kill(t, s, S3_SSH3_SFTP_FX_FAILURE);
                return s3_cli_step(t);
            }

            if (s->phase == PH_GET_READ) {
                s->phase = PH_GET_CLOSE;

                return s3_cli_step(t);
            }

            if (s->phase == PH_VERIFY_READ) {
                s3_cli_slot_digest_final(s);
                s->phase = PH_VERIFY_CLOSE;

                return s3_cli_step(t);
            }

            return S3_ERROR;
        }

        s3_cli_slot_kill(t, s, code);

        return s3_cli_step(t);

    case REQ_CLOSE:

        if (s == NULL) {
            return S3_ERROR;
        }

        if (pkt->type != S3_SSH3_SFTP_STATUS) {
            return S3_ERROR;
        }

        if (s3_cli_on_status(t, &pkt->body, &code) != S3_OK) {
            return S3_ERROR;
        }

        if (code != S3_SSH3_SFTP_FX_OK) {
            s3_cli_slot_kill(t, s, code);
            return s3_cli_step(t);
        }

        switch (s->phase) {

        case PH_PUT_CLOSE:
        case PH_GET_CLOSE:
            s->phase = PH_VERIFY_STAT;

            return s3_cli_step(t);

        case PH_VERIFY_CLOSE:

            if (s3_cli_slot_local_digest(t, s, local) != 0 ||
                s3_memcmp(local, s->digest, S3_SSH3_SFTP_CLI_SHA256_LEN) != 0) {
                s3_cli_slot_kill(t, s, S3_SSH3_SFTP_FX_FAILURE);
                return s3_cli_step(t);
            }

            s3_cli_slot_stamp_done(t, s);

            return s3_cli_step(t);

        default:
            return S3_ERROR;
        }

    case REQ_SETSTAT:

        if (s == NULL || s->phase != PH_PUT_SETSTAT || pkt->type != S3_SSH3_SFTP_STATUS) {
            return S3_ERROR;
        }

        if (s3_cli_on_status(t, &pkt->body, &code) != S3_OK) {
            return S3_ERROR;
        }

        /* the reference logs a refused stamp and moves on: an old
         * dialect server costs one redundant re-transfer later */

        s3_cli_slot_drop(t, s);

        return s3_cli_step(t);

    case REQ_MKDIR:

        op->walk_busy = 0;

        if (s != NULL || pkt->type != S3_SSH3_SFTP_STATUS) {
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

    case REQ_MKDIR_STAT:

        op->walk_busy = 0;

        if (s != NULL) {
            return S3_ERROR;
        }

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

    case REQ_OPENDIR:

        op->walk_busy = 0;

        if (s != NULL) {
            return S3_ERROR;
        }

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

    case REQ_READDIR:

        op->walk_busy = 0;

        if (s != NULL) {
            return S3_ERROR;
        }

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

    case REQ_CLOSEDIR:

        op->walk_busy = 0;

        if (s != NULL || pkt->type != S3_SSH3_SFTP_STATUS) {
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

            /* the tree drained: the window settles the op */

            op->phase = PH_PUMP;
            s3_cli_maybe_settle(t);

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
    uint32_t               i;

    if (t->op == NULL) {
        t->op = s3_pcalloc(t->pool, sizeof(s3_ssh3_sftp_cli_op_t));

        if (t->op == NULL) {
            return S3_ERROR;
        }
    }

    op = t->op;

    /* the local files of the window close, the digest ctx die */

    for (i = 0; i < S3_SSH3_SFTP_CLI_FILES; i++) {

        if (op->slots[i].fd >= 0) {
            (void)close(op->slots[i].fd);
        }

        if (op->slots[i].md != NULL) {
            EVP_MD_CTX_free(op->slots[i].md);
        }
    }

    while (op->frame_count > 0) {
        op->frame_count--;

        if (op->frames[op->frame_count].dir != NULL) {
            (void)s3_cli_fs_closedir(op->frames[op->frame_count].dir);
        }
    }

    s3_memzero(op, sizeof(*op));

    for (i = 0; i < S3_SSH3_SFTP_CLI_FILES; i++) {
        op->slots[i].fd = -1;
    }

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
    s3_cli_slot_t         *s;
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

    s = &op->slots[0];
    s->fd = s3_cli_fs_open_rd(local_path);

    if (s->fd < 0) {
        t->state = S3_SSH3_SFTP_CLI_FAIL;
        t->status = S3_SSH3_SFTP_FX_FAILURE;
        return S3_ERROR;
    }

    s->local_path = op->local_path;
    s->remote_path = op->remote_path;
    s->file_size = (uint64_t)st.st_size;
    s->mtime = (uint32_t)st.st_mtime;
    s->stamp = 1;
    s->phase = op->resume ? PH_PUT_STAT : PH_PUT_OPEN;

    if (!op->resume) {
        s->trunc = 1;
    }

    t->state = S3_SSH3_SFTP_CLI_RUN;
    op->phase = PH_PUMP;

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
    s3_cli_slot_t         *s;

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

    s = &op->slots[0];
    s->local_path = op->local_path;
    s->remote_path = op->remote_path;
    s->stamp = 1; /* a download writes the bytes, it stamps them (R7) */
    s->phase = PH_GET_STAT;

    t->state = S3_SSH3_SFTP_CLI_RUN;
    op->phase = PH_PUMP;

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
    op->phase = PH_GET_STAT; /* the root stat of the download walk */

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
