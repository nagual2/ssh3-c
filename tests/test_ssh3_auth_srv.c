/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the server auth verifiers (docs/P4-WIRE.md 7): the Basic
 * credentials decode, the ?user= extraction from the CONNECT target,
 * the harness password file and the sshd authorized_keys iterator
 */

#include <s3_core.h>

#include <pwd.h>
#include <string.h>
#include <unistd.h>

#include <s3_ssh3_auth_srv.h>

#include "s3_test.h"

static int
s3_test_expect_basic(const char *text, s3_int_t expect, const char *user, const char *pass)
{
    char     header[128];
    size_t   n;
    s3_str_t h, u, p;
    s3_int_t rc;

    n = strlen(text);

    S3_ASSERT(n < sizeof(header));

    s3_memcpy(header, text, n);

    h.data = (u_char *)header;
    h.len = n;

    s3_str_null(&u);
    s3_str_null(&p);

    rc = s3_ssh3_auth_basic_decode(&h, &u, &p);

    S3_ASSERT(rc == expect);

    if (rc != S3_OK) {
        return s3_test_failures;
    }

    S3_ASSERT(u.len == strlen(user));
    S3_ASSERT(s3_memcmp(u.data, user, u.len) == 0);
    S3_ASSERT(p.len == strlen(pass));
    S3_ASSERT(s3_memcmp(p.data, pass, p.len) == 0);

    /* the zero-copy views live inside the header buffer */

    S3_ASSERT(u.data >= (u_char *)header && u.data + u.len <= (u_char *)header + n);
    S3_ASSERT(p.data >= (u_char *)header && p.data + p.len <= (u_char *)header + n);

    return s3_test_failures;
}

static int
s3_test_basic_decode(void)
{
    /* "tester:secret123", the wire shape of the reference client */

    (void)s3_test_expect_basic("Basic dGVzdGVyOnNlY3JldDEyMw==", S3_OK, "tester", "secret123");

    /* the full quanta carry no padding, like base64.StdEncoding */

    (void)s3_test_expect_basic("Basic dXNlcjpwYXNz", S3_OK, "user", "pass");

    /* the scheme token is exact-case, one space */

    (void)s3_test_expect_basic("basic dGVzdGVyOnNlY3JldDEyMw==", S3_DECLINED, NULL, NULL);
    (void)s3_test_expect_basic("bearer dGVzdGVyOnNlY3JldDEyMw==", S3_DECLINED, NULL, NULL);
    (void)s3_test_expect_basic("BasicX dGVzdGVyOnNlY3JldDEyMw==", S3_DECLINED, NULL, NULL);
    (void)s3_test_expect_basic("dGVzdGVyOnNlY3JldDEyMw==", S3_DECLINED, NULL, NULL);

    /* "Basic" alone: the scheme is ours, the payload is missing */

    (void)s3_test_expect_basic("Basic", S3_ERROR, NULL, NULL);
    (void)s3_test_expect_basic("Basic ", S3_ERROR, NULL, NULL);

    /* the malformed payloads: no colon, ragged or broken base64 */

    (void)s3_test_expect_basic("Basic dGVzdGVyOg==", S3_ERROR, NULL, NULL); /* the empty pass */
    (void)s3_test_expect_basic("Basic OnNlY3JldA==", S3_ERROR, NULL, NULL); /* the empty user */
    (void)s3_test_expect_basic("Basic bm9jb2xvbg==", S3_ERROR, NULL, NULL); /* no colon */
    (void)s3_test_expect_basic("Basic dGVzdGVy", S3_ERROR, NULL, NULL);     /* no colon */
    (void)s3_test_expect_basic("Basic ###", S3_ERROR, NULL, NULL);
    (void)s3_test_expect_basic("Basic abc", S3_ERROR, NULL, NULL);
    (void)s3_test_expect_basic("Basic dGVzdGVy=xxx", S3_ERROR, NULL, NULL);
    (void)s3_test_expect_basic("Basic  dGVzdGVyOnNlY3JldDEyMw==", S3_ERROR, NULL, NULL);

    return s3_test_failures;
}

static int
s3_test_expect_user(const char *text, const char *user)
{
    s3_str_t path, u;
    s3_int_t rc;

    path.data = (u_char *)text;
    path.len = strlen(text);

    s3_str_null(&u);

    rc = s3_ssh3_auth_user_from_path(&path, &u);

    if (user == NULL) {
        S3_ASSERT(rc == S3_DECLINED);
        return s3_test_failures;
    }

    S3_ASSERT(rc == S3_OK);

    if (rc != S3_OK) {
        return s3_test_failures;
    }

    S3_ASSERT(u.len == strlen(user));
    S3_ASSERT(s3_memcmp(u.data, user, u.len) == 0);

    /* the view lives inside the path buffer */

    S3_ASSERT(u.data >= path.data && u.data + u.len <= path.data + path.len);

    return s3_test_failures;
}

static int
s3_test_user_from_path(void)
{
    (void)s3_test_expect_user("/ssh3-term?user=bob", "bob");
    (void)s3_test_expect_user("/ssh3-term?a=1&user=bob&c=2", "bob");
    (void)s3_test_expect_user("/ssh3-term?a=1&user=bob", "bob");

    /* the first user parameter wins, like the reference Query().Get() */

    (void)s3_test_expect_user("/ssh3-term?user=bob&user=alice", "bob");

    /* the value stays raw to the '&' or the path end */

    (void)s3_test_expect_user("/ssh3-term?user=bob=carol", "bob=carol");

    (void)s3_test_expect_user("/ssh3-term", NULL);
    (void)s3_test_expect_user("/ssh3-term?user=", NULL);
    (void)s3_test_expect_user("/ssh3-term?user=&a=1", NULL);
    (void)s3_test_expect_user("user=bob", NULL); /* no query */
    (void)s3_test_expect_user("/ssh3-term?xuser=bob", NULL);
    (void)s3_test_expect_user("/ssh3-term?USER=bob", NULL);
    (void)s3_test_expect_user("/ssh3-term?", NULL);
    (void)s3_test_expect_user("/ssh3-term?other=1", NULL);

    return s3_test_failures;
}

static int
s3_test_expect_pwfile(const char *content, const char *user, const char *pass, s3_int_t expect)
{
    char     tmpl[] = "/tmp/s3authXXXXXX";
    s3_str_t u, p;
    ssize_t  n;
    int      fd;
    s3_int_t rc;

    fd = mkstemp(tmpl);

    S3_ASSERT(fd >= 0);

    if (fd < 0) {
        return s3_test_failures;
    }

    n = (ssize_t)strlen(content);

    S3_ASSERT(write(fd, content, (size_t)n) == n);

    (void)close(fd);

    u.data = (u_char *)user;
    u.len = strlen(user);
    p.data = (u_char *)pass;
    p.len = strlen(pass);

    rc = s3_ssh3_auth_password_file_check(tmpl, &u, &p);

    S3_ASSERT(rc == expect);

    /* the fixture leaves no trace (ASan clean) */

    S3_ASSERT(unlink(tmpl) == 0);

    return s3_test_failures;
}

static int
s3_test_password_file(void)
{
    /* the CRLF lines, a comment, an empty line, a no-colon line */

    (void)s3_test_expect_pwfile("tester:secret123\r\n"
                                "# a comment\r\n"
                                "\r\n"
                                "brokenline\r\n"
                                "other:xyz\r\n",
                                "tester", "secret123", S3_OK);

    (void)s3_test_expect_pwfile("tester:secret123\r\n", "tester", "wrong", S3_DECLINED);
    (void)s3_test_expect_pwfile("tester:secret123\r\n", "nobody", "secret123", S3_DECLINED);

    /* the first line with the matching user decides the verdict */

    (void)s3_test_expect_pwfile("tester:wrong\ntester:secret123\n", "tester", "secret123",
                                S3_DECLINED);

    /* the readable empty file just has no match */

    (void)s3_test_expect_pwfile("", "tester", "secret123", S3_DECLINED);

    return s3_test_failures;
}

static int
s3_test_password_file_missing(void)
{
    s3_str_t u, p;

    u.data = (u_char *)"tester";
    u.len = 6;
    p.data = (u_char *)"secret123";
    p.len = 9;

    S3_ASSERT(s3_ssh3_auth_password_file_check("/tmp/s3auth-missing-file", &u, &p) == S3_ERROR);

    return s3_test_failures;
}

static int
s3_test_keys_next(char *block, const u_char **pos, const u_char *end, const char *keytype,
                  const char *b64)
{
    s3_str_t kt, bl;
    s3_int_t rc;

    rc = s3_ssh3_auth_authorized_keys_next(pos, end, &kt, &bl);

    S3_ASSERT(rc == S3_OK);

    if (rc != S3_OK) {
        return s3_test_failures;
    }

    S3_ASSERT(kt.len == strlen(keytype));
    S3_ASSERT(s3_memcmp(kt.data, keytype, kt.len) == 0);
    S3_ASSERT(bl.len == strlen(b64));
    S3_ASSERT(s3_memcmp(bl.data, b64, bl.len) == 0);

    /* the zero-copy views live inside the block */

    S3_ASSERT(kt.data >= (u_char *)block && kt.data + kt.len <= end);
    S3_ASSERT(bl.data >= (u_char *)block && bl.data + bl.len <= end);

    return s3_test_failures;
}

static int
s3_test_keys_error(const char *block)
{
    const u_char *pos, *end;
    s3_str_t      kt, bl;

    pos = (const u_char *)block;
    end = pos + strlen(block);

    S3_ASSERT(s3_ssh3_auth_authorized_keys_next(&pos, end, &kt, &bl) == S3_ERROR);

    return s3_test_failures;
}

static int
s3_test_authorized_keys(void)
{
    static char block[] = "# the comment line\n"
                          "\n"
                          "ssh-rsa AAAAB3NzaC1yc2E comment one\n"
                          "\r\n"
                          "command=\"x\",no-pty ssh-ed25519 AAAAC3NzaC1lZDI1 comment two\n"
                          "cert-authority ssh-ed25519 AAAAC3NzaC1lZDI2\n"
                          "ssh-ed25519 AAAAC3NzaC1lZDI3\n";

    static char crlf[] = "ssh-rsa AAAAB3NzaC1yc2E\r\n";

    static char empty[] = "# only comments\n\n";

    static char mixed[] = "ssh-rsa AAAAB3NzaC1yc2E\nssh-ed25519\n";

    const u_char *pos, *end;
    s3_str_t      kt, bl;

    pos = (u_char *)block;
    end = pos + strlen(block);

    (void)s3_test_keys_next(block, &pos, end, "ssh-rsa", "AAAAB3NzaC1yc2E");
    (void)s3_test_keys_next(block, &pos, end, "ssh-ed25519", "AAAAC3NzaC1lZDI1");
    (void)s3_test_keys_next(block, &pos, end, "ssh-ed25519", "AAAAC3NzaC1lZDI2");
    (void)s3_test_keys_next(block, &pos, end, "ssh-ed25519", "AAAAC3NzaC1lZDI3");

    S3_ASSERT(s3_ssh3_auth_authorized_keys_next(&pos, end, &kt, &bl) == S3_DONE);

    /* the CRLF line: the blob view stops before the carriage return */

    pos = (u_char *)crlf;
    end = pos + strlen(crlf);

    (void)s3_test_keys_next(crlf, &pos, end, "ssh-rsa", "AAAAB3NzaC1yc2E");

    S3_ASSERT(s3_ssh3_auth_authorized_keys_next(&pos, end, &kt, &bl) == S3_DONE);

    /* the comments-only block is done right away */

    pos = (u_char *)empty;
    end = pos + strlen(empty);

    S3_ASSERT(s3_ssh3_auth_authorized_keys_next(&pos, end, &kt, &bl) == S3_DONE);

    /* the malformed lines are S3_ERROR, the iteration stops */

    (void)s3_test_keys_error("command=\"x ssh-rsa AAAA\n"); /* unterminated quote */
    (void)s3_test_keys_error("ssh-ed25519\n");              /* the keytype without the blob */
    (void)s3_test_keys_error("ssh-ed25519 \n");
    (void)s3_test_keys_error("no-pty\n"); /* the options without the keytype */
    (void)s3_test_keys_error("command=\"x\",no-pty\n");

    /* a good line first, the malformed one behind it stops the run */

    pos = (u_char *)mixed;
    end = pos + strlen(mixed);

    (void)s3_test_keys_next(mixed, &pos, end, "ssh-rsa", "AAAAB3NzaC1yc2E");

    S3_ASSERT(s3_ssh3_auth_authorized_keys_next(&pos, end, &kt, &bl) == S3_ERROR);

    return s3_test_failures;
}

static int
s3_test_default_chain(void)
{
    char        buf[1024];
    const char *paths[S3_SSH3_AUTH_CHAIN_MAX];
    unsigned    n;
    s3_str_t    user;

    struct passwd *pw;
    char           want[2][512];
    unsigned       i;

    /*
     * the chain of the reference DefaultIdentitiesFileNames(): the
     * user database home joined with the two suffixes, in that order
     */

    pw = getpwuid(geteuid());

    S3_ASSERT(pw != NULL);

    if (pw == NULL) {
        return s3_test_failures;
    }

    snprintf(want[0], sizeof(want[0]), "%s/.ssh3/authorized_identities", pw->pw_dir);
    snprintf(want[1], sizeof(want[1]), "%s/.ssh/authorized_keys", pw->pw_dir);

    user.data = (u_char *)pw->pw_name;
    user.len = strlen(pw->pw_name);

    S3_ASSERT(s3_ssh3_auth_default_chain(&user, buf, sizeof(buf), paths, &n) == S3_OK);
    S3_ASSERT(n == 2);

    for (i = 0; i < n; i++) {

        S3_ASSERT(paths[i] != NULL);
        S3_ASSERT(strlen(paths[i]) == strlen(want[i]));
        S3_ASSERT(strcmp(paths[i], want[i]) == 0);
    }

    /* the names must not overlap: two zero-terminated strings */

    S3_ASSERT(paths[1] >= paths[0] + strlen(paths[0]) + 1);

    /* the unknown user does not resolve */

    user.data = (u_char *)"s3-no-such-user-9x7";
    user.len = strlen((char *)user.data);

    S3_ASSERT(s3_ssh3_auth_default_chain(&user, buf, sizeof(buf), paths, &n) == S3_ERROR);

    /* the plain-name guard: the chain never climbs or splits paths */

    user.data = (u_char *)"../etc";
    user.len = 6;
    S3_ASSERT(s3_ssh3_auth_default_chain(&user, buf, sizeof(buf), paths, &n) == S3_ERROR);

    user.data = (u_char *)".hidden";
    user.len = 7;
    S3_ASSERT(s3_ssh3_auth_default_chain(&user, buf, sizeof(buf), paths, &n) == S3_ERROR);

    user.data = (u_char *)"a/b";
    user.len = 3;
    S3_ASSERT(s3_ssh3_auth_default_chain(&user, buf, sizeof(buf), paths, &n) == S3_ERROR);

    user.data = (u_char *)"a b";
    user.len = 3;
    S3_ASSERT(s3_ssh3_auth_default_chain(&user, buf, sizeof(buf), paths, &n) == S3_ERROR);

    /* the empty user is rejected before the lookup */

    user.data = (u_char *)"root";
    user.len = 0;
    S3_ASSERT(s3_ssh3_auth_default_chain(&user, buf, sizeof(buf), paths, &n) == S3_ERROR);

    /* the output buffer that cannot hold both names is an error */

    user.data = (u_char *)pw->pw_name;
    user.len = strlen(pw->pw_name);

    S3_ASSERT(s3_ssh3_auth_default_chain(&user, buf, 8, paths, &n) == S3_ERROR);

    return s3_test_failures;
}

static int
s3_test_ssh3_auth_srv(void)
{
    (void)s3_test_basic_decode();
    (void)s3_test_user_from_path();
    (void)s3_test_password_file();
    (void)s3_test_password_file_missing();
    (void)s3_test_authorized_keys();
    (void)s3_test_default_chain();

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_ssh3_auth_srv)
