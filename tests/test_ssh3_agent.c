/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the unix domain socket half of the agent forwarding: the listener
 * lifecycle, the accept and dial halves, the pool cleanup
 */

#include <s3_core.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <s3_ssh3_agent.h>

#include "s3_test.h"

static int
s3_test_agent_listen(void)
{
    char                      saved[256];
    char                     *slash, suffix[32];
    u_char                   *suffix_end;
    size_t                    suffix_len;
    struct stat               st;
    s3_int_t                  rc;
    s3_log_t                  log;
    s3_pool_t                *pool;
    s3_str_t                  path;
    s3_ssh3_agent_listener_t *l;

    log.log_level = S3_LOG_ALERT;
    log.fd = S3_INVALID_FILE;

    pool = s3_create_pool((size_t)S3_DEFAULT_POOL_SIZE, &log);
    S3_ASSERT(pool != NULL);

    rc = s3_ssh3_agent_listen(pool, &l, &path);

    S3_ASSERT(rc == S3_OK);
    S3_ASSERT(l != NULL);
    S3_ASSERT(path.len > 0);
    S3_ASSERT(path.data != NULL);
    S3_ASSERT(s3_ssh3_agent_listener_fd(l) >= 0);

    /* the path is a pool view, everything below works on the copy
     * and the destroy at the end frees the original */

    S3_ASSERT(path.len < sizeof(saved));
    memcpy(saved, path.data, path.len);
    saved[path.len] = '\0';

    /* the reference layout: the socket lives in a fresh private
     * s3ssh3-agent-XXXXXX directory and is named agent.<pid> */

    slash = strrchr(saved, '/');
    S3_ASSERT(slash != NULL);
    S3_ASSERT(s3_strncmp(slash + 1, "agent.", 6) == 0);
    S3_ASSERT(strstr(saved, "/s3ssh3-agent-") != NULL);

    /* the s3_snprintf of the nginx shape does not terminate, the
     * return is the past-the-end pointer */

    suffix_end = s3_snprintf((u_char *)suffix, sizeof(suffix) - 1, "agent.%d", (int)getpid());
    *suffix_end = 0;
    suffix_len = (size_t)(suffix_end - (u_char *)suffix);

    S3_ASSERT(path.len >= suffix_len);
    S3_ASSERT(memcmp(path.data + path.len - suffix_len, suffix, suffix_len) == 0);

    S3_ASSERT(stat(saved, &st) == 0);
    S3_ASSERT(S_ISSOCK(st.st_mode));

    /* the listening fd is non-blocking */

    S3_ASSERT((fcntl(s3_ssh3_agent_listener_fd(l), F_GETFL, 0) & O_NONBLOCK) != 0);

    /* nothing dialed yet, the accept must report the empty backlog */

    S3_ASSERT(s3_ssh3_agent_accept(l) == S3_AGAIN);

    /* the cleanup handler unlinks the socket and removes the
     * directory when the pool dies */

    s3_destroy_pool(pool);

    S3_ASSERT(stat(saved, &st) == -1 && errno == ENOENT);

    *slash = '\0';

    S3_ASSERT(stat(saved, &st) == -1 && errno == ENOENT);

    return s3_test_failures;
}

static int
s3_test_agent_roundtrip(void)
{
    ssize_t                   n;
    int                       cfd, afd;
    char                      buf[16];
    s3_int_t                  rc;
    s3_log_t                  log;
    s3_pool_t                *pool;
    s3_str_t                  path;
    s3_ssh3_agent_listener_t *l;

    log.log_level = S3_LOG_ALERT;
    log.fd = S3_INVALID_FILE;

    pool = s3_create_pool((size_t)S3_DEFAULT_POOL_SIZE, &log);
    S3_ASSERT(pool != NULL);

    rc = s3_ssh3_agent_listen(pool, &l, &path);
    S3_ASSERT(rc == S3_OK);

    /* the client half dials the very path the server half announced */

    cfd = s3_ssh3_agent_dial(pool, &path);
    S3_ASSERT(cfd >= 0);
    S3_ASSERT((fcntl(cfd, F_GETFL, 0) & O_NONBLOCK) != 0);

    afd = s3_ssh3_agent_accept(l);
    S3_ASSERT(afd >= 0);
    S3_ASSERT((fcntl(afd, F_GETFL, 0) & O_NONBLOCK) != 0);

    /* the bytes cross both ways over the accepted pair */

    n = write(cfd, "ping", 4);
    S3_ASSERT(n == 4);

    n = read(afd, buf, sizeof(buf));
    S3_ASSERT(n == 4);
    S3_ASSERT(memcmp(buf, "ping", 4) == 0);

    n = write(afd, "pong!", 5);
    S3_ASSERT(n == 5);

    n = read(cfd, buf, sizeof(buf));
    S3_ASSERT(n == 5);
    S3_ASSERT(memcmp(buf, "pong!", 5) == 0);

    s3_ssh3_agent_close_fd(cfd);
    s3_ssh3_agent_close_fd(afd);

    /* -1 passes through silently */

    s3_ssh3_agent_close_fd(-1);

    s3_destroy_pool(pool);

    return s3_test_failures;
}

static int
s3_test_agent_dial_missing(void)
{
    int        cfd;
    u_char     long_path[256];
    s3_str_t   path = s3_string("/tmp/s3ssh3-agent-no-such-socket");
    s3_str_t   empty = s3_null_string;
    s3_str_t   too_long;
    s3_log_t   log;
    s3_pool_t *pool;

    log.log_level = S3_LOG_ALERT;
    log.fd = S3_INVALID_FILE;

    pool = s3_create_pool((size_t)S3_DEFAULT_POOL_SIZE, &log);
    S3_ASSERT(pool != NULL);

    cfd = s3_ssh3_agent_dial(pool, &path);
    S3_ASSERT(cfd == S3_ERROR);

    /* an unset variable is the empty path of the same failure */

    cfd = s3_ssh3_agent_dial(pool, &empty);
    S3_ASSERT(cfd == S3_ERROR);

    /* a path past the 108 bytes of sun_path is refused before the
     * socket even exists */

    memset(long_path, 'x', sizeof(long_path));
    long_path[0] = '/';

    too_long.len = sizeof(long_path);
    too_long.data = long_path;

    S3_ASSERT(too_long.len >= 108);

    cfd = s3_ssh3_agent_dial(pool, &too_long);
    S3_ASSERT(cfd == S3_ERROR);

    s3_destroy_pool(pool);

    return s3_test_failures;
}

static int
s3_test_ssh3_agent(void)
{
    (void)s3_test_agent_listen();
    (void)s3_test_agent_roundtrip();
    (void)s3_test_agent_dial_missing();

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_ssh3_agent)
