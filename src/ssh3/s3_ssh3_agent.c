/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the ssh-agent forwarding plumbing, the unix domain socket half of
 * the reference util/unix_util/agent.go (NewUnixSocketPath) and of
 * the dial halves of client/client.go (forwardAgent) and
 * cmd/ssh3-server.go (openAgentSocketAndForwardAgent)
 */

#include <s3_core.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <s3_nonblocking.h>

#include <s3_ssh3_agent.h>

/* the mkdtemp suffix, the six X are the random part it fills in */

#define S3_SSH3_AGENT_DIR_TEMPLATE "/s3ssh3-agent-XXXXXX"

/* the socket filename of the reference: fmt.Sprintf("agent.%d", pid) */

#define S3_SSH3_AGENT_SOCKET_FMT "/agent."

#define S3_SSH3_AGENT_BACKLOG SOMAXCONN

struct s3_ssh3_agent_listener_s {
    int     fd;
    u_char *dir;  /* the private mkdtemp directory, NUL-terminated, pool */
    u_char *name; /* the socket path, dir + /agent.<pid>, pool */
    size_t  len;  /* the socket path length, without the terminator */
};

static void s3_ssh3_agent_teardown(s3_ssh3_agent_listener_t *l);
static void s3_ssh3_agent_cleanup(void *data);

/* the best-effort destruction, idempotent: the failure paths of
 * s3_ssh3_agent_listen() run it by hand and the pool handler runs it
 * again at s3_destroy_pool() */

static void
s3_ssh3_agent_teardown(s3_ssh3_agent_listener_t *l)
{
    if (l->fd != -1) {
        (void)close(l->fd);
        l->fd = -1;
    }

    if (l->name != NULL) {
        (void)unlink((char *)l->name);
    }

    if (l->dir != NULL) {
        (void)rmdir((char *)l->dir);
    }
}

static void
s3_ssh3_agent_cleanup(void *data)
{
    s3_ssh3_agent_teardown(data);
}

s3_int_t
s3_ssh3_agent_listen(s3_pool_t *pool, s3_ssh3_agent_listener_t **listener, s3_str_t *path_out)
{
    int                       fd;
    size_t                    len;
    struct sockaddr_un        sa;
    s3_pool_cleanup_t        *cln;
    s3_ssh3_agent_listener_t *l;
    u_char                   *base, *buf, *p;

    *listener = NULL;
    path_out->len = 0;
    path_out->data = NULL;

    /* the mkdtemp template, $TMPDIR when set (without doubling the
     * separator), /tmp otherwise */

    base = (u_char *)getenv("TMPDIR");

    if (base == NULL || base[0] == '\0') {
        base = (u_char *)"/tmp";
    }

    len = s3_strlen(base);

    buf = s3_pnalloc(pool, len + sizeof(S3_SSH3_AGENT_DIR_TEMPLATE) + 1);

    if (buf == NULL) {
        return S3_ERROR;
    }

    p = s3_cpymem(buf, base, len);

    if (len != 0 && base[len - 1] != '/') {
        *p++ = '/';
    }

    p = s3_cpymem(p, S3_SSH3_AGENT_DIR_TEMPLATE, sizeof(S3_SSH3_AGENT_DIR_TEMPLATE));

    /* mkdtemp() edits the template in place and creates the
     * directory 0700, the private layout of os.MkdirTemp */

    if (mkdtemp((char *)buf) == NULL) {
        return S3_ERROR;
    }

    l = s3_pcalloc(pool, sizeof(s3_ssh3_agent_listener_t));

    if (l == NULL) {
        (void)rmdir((char *)buf);
        return S3_ERROR;
    }

    l->fd = -1;
    l->dir = buf;

    len = s3_strlen(buf);

    /* the socket path <dir>/agent.<pid>; a sun_path holds at most
     * 108 bytes with the terminator, a longer TMPDIR is refused
     * before the syscalls rather than at bind() */

    l->name = s3_pnalloc(pool, len + sizeof(S3_SSH3_AGENT_SOCKET_FMT) + S3_INT_T_LEN + 1);

    if (l->name == NULL) {
        (void)rmdir((char *)buf);
        return S3_ERROR;
    }

    p = s3_cpymem(l->name, buf, len);
    p = s3_cpymem(p, S3_SSH3_AGENT_SOCKET_FMT, sizeof(S3_SSH3_AGENT_SOCKET_FMT) - 1);
    p = s3_snprintf(p, S3_INT_T_LEN + 1, "%d", (int)getpid());
    *p = '\0';

    if ((size_t)(p - l->name) >= sizeof(sa.sun_path)) {
        (void)rmdir((char *)buf);
        return S3_ERROR;
    }

    l->len = (size_t)(p - l->name);

    cln = s3_pool_cleanup_add(pool, 0);

    if (cln == NULL) {
        (void)rmdir((char *)buf);
        return S3_ERROR;
    }

    cln->handler = s3_ssh3_agent_cleanup;
    cln->data = l;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);

    if (fd == -1) {
        s3_ssh3_agent_teardown(l);
        return S3_ERROR;
    }

    l->fd = fd;

    if (s3_nonblocking(fd) != S3_OK) {
        s3_ssh3_agent_teardown(l);
        return S3_ERROR;
    }

    s3_memzero(&sa, sizeof(sa));

    sa.sun_family = AF_UNIX;
    s3_memcpy(sa.sun_path, l->name, l->len);

    /* the zeroed sockaddr gives the terminator; the fresh directory
     * cannot hold a stale socket, no unlink-before-bind */

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
        s3_ssh3_agent_teardown(l);
        return S3_ERROR;
    }

    /* the reference relies on umask, this pins the socket to its
     * owner regardless of it */

    if (chmod((char *)l->name, 0600) == -1) {
        s3_ssh3_agent_teardown(l);
        return S3_ERROR;
    }

    if (listen(fd, S3_SSH3_AGENT_BACKLOG) == -1) {
        s3_ssh3_agent_teardown(l);
        return S3_ERROR;
    }

    /* the view into the pool copy, valid until s3_destroy_pool() */

    path_out->len = l->len;
    path_out->data = l->name;

    *listener = l;

    return S3_OK;
}

int
s3_ssh3_agent_listener_fd(const s3_ssh3_agent_listener_t *l)
{
    return l->fd;
}

int
s3_ssh3_agent_accept(s3_ssh3_agent_listener_t *l)
{
    int fd;

    fd = accept(l->fd, NULL, NULL);

    if (fd == -1) {
        return (errno == EAGAIN || errno == EWOULDBLOCK) ? S3_AGAIN : S3_ERROR;
    }

    /* accepted sockets inherit nothing: the flag is set by hand,
     * accept4() stays out of reach under _POSIX_C_SOURCE */

    if (s3_nonblocking(fd) != S3_OK) {
        (void)close(fd);

        return S3_ERROR;
    }

    return fd;
}

int
s3_ssh3_agent_dial(s3_pool_t *pool, const s3_str_t *sock_path)
{
    int                fd;
    struct sockaddr_un sa;

    (void)pool;

    if (sock_path == NULL || sock_path->len == 0 || sock_path->len >= sizeof(sa.sun_path)) {
        return S3_ERROR;
    }

    fd = socket(AF_UNIX, SOCK_STREAM, 0);

    if (fd == -1) {
        return S3_ERROR;
    }

    s3_memzero(&sa, sizeof(sa));

    sa.sun_family = AF_UNIX;
    s3_memcpy(sa.sun_path, sock_path->data, sock_path->len);

    /* the connect to a local agent completes in kernel order and the
     * non-blocking flag is set right after it: an EINPROGRESS dance
     * buys nothing over an AF_UNIX peer */

    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
        (void)close(fd);

        return S3_ERROR;
    }

    if (s3_nonblocking(fd) != S3_OK) {
        (void)close(fd);

        return S3_ERROR;
    }

    return fd;
}

void
s3_ssh3_agent_close_fd(int fd)
{
    if (fd >= 0) {
        (void)close(fd);
    }
}
