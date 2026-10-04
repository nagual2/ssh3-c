/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the ssh3 channel-request bodies: the type/kind maps, the known-bytes
 * pty-req vector, the round-trips over every kind with the measure
 * mode, the truncation matrix and the malformed-body verdicts, the
 * reference message/channel_request.go
 */

#include <s3_core.h>

#include <s3_ssh3_wire.h>

#include <s3_ssh3_request.h>

#include "s3_test.h"

static int
s3_test_request_type_map(void)
{
    static const struct {
        s3_ssh3_request_kind_t kind;
        const char            *name;
    } vec[] = {
        {S3_SSH3_REQ_PTY, "pty-req"},
        {S3_SSH3_REQ_SHELL, "shell"},
        {S3_SSH3_REQ_EXEC, "exec"},
        {S3_SSH3_REQ_SUBSYSTEM, "subsystem"},
        {S3_SSH3_REQ_WINDOW_CHANGE, "window-change"},
        {S3_SSH3_REQ_SIGNAL, "signal"},
        {S3_SSH3_REQ_EXIT_STATUS, "exit-status"},
        {S3_SSH3_REQ_EXIT_SIGNAL, "exit-signal"},
        {S3_SSH3_REQ_X11, "x11-req"},
    };

    const char            *name;
    s3_str_t               type;
    s3_ssh3_request_kind_t kind;
    size_t                 i;

    /* the canonical strings and the reverse mapping agree both ways */

    for (i = 0; i < sizeof(vec) / sizeof(vec[0]); i++) {

        name = s3_ssh3_request_type_str(vec[i].kind);

        S3_ASSERT(name != NULL);
        S3_ASSERT(s3_strcmp(name, vec[i].name) == 0);

        /* not s3_str_set: the operand is a pointer, not a literal */

        type.data = (u_char *)vec[i].name;
        type.len = s3_strlen(vec[i].name);

        S3_ASSERT(s3_ssh3_request_kind_of(&type, &kind) == S3_OK);
        S3_ASSERT(kind == vec[i].kind);
    }

    /* the set is closed: the reference "forward-port" has no kind here */

    s3_str_set(&type, "forward-port");
    S3_ASSERT(s3_ssh3_request_kind_of(&type, &kind) == S3_DECLINED);

    s3_str_set(&type, "");
    S3_ASSERT(s3_ssh3_request_kind_of(&type, &kind) == S3_DECLINED);

    s3_str_set(&type, "pty-re");
    S3_ASSERT(s3_ssh3_request_kind_of(&type, &kind) == S3_DECLINED);

    S3_ASSERT(s3_ssh3_request_kind_of(NULL, &kind) == S3_DECLINED);

    /* the out-of-range kinds have no string */

    S3_ASSERT(s3_ssh3_request_type_str((s3_ssh3_request_kind_t)9) == NULL);
    S3_ASSERT(s3_ssh3_request_type_str((s3_ssh3_request_kind_t)-1) == NULL);

    return s3_test_failures;
}

static int
s3_test_pty_known_vector(void)
{
    /* term "xterm", width 80 (the 2-byte varint form), height 24,
     * pixel 0, pixel 0 and an opaque 4-byte encoded-terminal-modes
     * blob */

    static const u_char body[] = "\x05"
                                 "xterm"
                                 "\x40\x50"
                                 "\x18\x00\x00"
                                 "\x04\x01\x02\x03\x04";

    u_char            out[32];
    u_char           *q;
    const u_char     *pos, *end;
    s3_str_t          type;
    s3_ssh3_request_t req;
    uintptr_t         n;

    s3_str_set(&type, "pty-req");

    pos = body;
    end = body + sizeof(body) - 1;

    S3_ASSERT(s3_ssh3_request_parse_body(&pos, end, &type, &req) == S3_OK);
    S3_ASSERT(pos == end);

    S3_ASSERT(req.kind == S3_SSH3_REQ_PTY);
    S3_ASSERT(req.u.pty.term.len == 5);
    S3_ASSERT(s3_memcmp(req.u.pty.term.data, "xterm", 5) == 0);
    S3_ASSERT(req.u.pty.width == 80);
    S3_ASSERT(req.u.pty.height == 24);
    S3_ASSERT(req.u.pty.pixel_width == 0);
    S3_ASSERT(req.u.pty.pixel_height == 0);
    S3_ASSERT(req.u.pty.modes.len == 4);
    S3_ASSERT(s3_memcmp(req.u.pty.modes.data, "\x01\x02\x03\x04", 4) == 0);

    /* the re-encode reproduces the exact input bytes */

    n = s3_ssh3_request_encode_body(NULL, &req);

    S3_ASSERT(n == sizeof(body) - 1);

    q = (u_char *)s3_ssh3_request_encode_body(out, &req);

    S3_ASSERT(q == out + sizeof(body) - 1);
    S3_ASSERT(s3_memcmp(out, body, sizeof(body) - 1) == 0);

    return s3_test_failures;
}

static int
s3_test_roundtrip(void)
{
    u_char            buf[256];
    u_char           *q;
    const u_char     *pos, *end;
    s3_str_t          type;
    s3_ssh3_request_t req, back;
    uintptr_t         n;

    /*
     * every kind: the measure mode announces the written size, the
     * decode inverts the encode, the parsed strings are views into
     * the buffer
     */

    /* shell: the empty body, the cursor does not move */

    s3_memzero(&req, sizeof(req));
    s3_memzero(&back, sizeof(back));

    req.kind = S3_SSH3_REQ_SHELL;
    s3_str_set(&type, "shell");

    n = s3_ssh3_request_encode_body(NULL, &req);

    S3_ASSERT(n == 0);

    q = (u_char *)s3_ssh3_request_encode_body(buf, &req);

    S3_ASSERT(q == buf);

    pos = buf;
    end = buf;

    S3_ASSERT(s3_ssh3_request_parse_body(&pos, end, &type, &back) == S3_OK);
    S3_ASSERT(pos == end);
    S3_ASSERT(back.kind == S3_SSH3_REQ_SHELL);

    /* exec */

    s3_memzero(&req, sizeof(req));
    s3_memzero(&back, sizeof(back));

    req.kind = S3_SSH3_REQ_EXEC;
    s3_str_set(&req.u.exec.command, "ls -la /tmp");
    s3_str_set(&type, "exec");

    n = s3_ssh3_request_encode_body(NULL, &req);

    S3_ASSERT(n == 12); /* the one-byte length plus the 11-byte command */

    q = (u_char *)s3_ssh3_request_encode_body(buf, &req);

    S3_ASSERT(q == buf + n);
    S3_ASSERT(buf[0] == 11);

    pos = buf;
    end = q;

    S3_ASSERT(s3_ssh3_request_parse_body(&pos, end, &type, &back) == S3_OK);
    S3_ASSERT(pos == end);
    S3_ASSERT(back.kind == S3_SSH3_REQ_EXEC);
    S3_ASSERT(back.u.exec.command.len == 11);
    S3_ASSERT(s3_memcmp(back.u.exec.command.data, "ls -la /tmp", 11) == 0);

    /* subsystem */

    s3_memzero(&req, sizeof(req));
    s3_memzero(&back, sizeof(back));

    req.kind = S3_SSH3_REQ_SUBSYSTEM;
    s3_str_set(&req.u.subsystem.name, "sftp");
    s3_str_set(&type, "subsystem");

    n = s3_ssh3_request_encode_body(NULL, &req);

    S3_ASSERT(n == 5);

    q = (u_char *)s3_ssh3_request_encode_body(buf, &req);

    S3_ASSERT(q == buf + n);

    pos = buf;
    end = q;

    S3_ASSERT(s3_ssh3_request_parse_body(&pos, end, &type, &back) == S3_OK);
    S3_ASSERT(pos == end);
    S3_ASSERT(back.kind == S3_SSH3_REQ_SUBSYSTEM);
    S3_ASSERT(back.u.subsystem.name.len == 4);
    S3_ASSERT(s3_memcmp(back.u.subsystem.name.data, "sftp", 4) == 0);

    /* pty: the wide fields ride in the multi-byte varint forms, the
     * empty modes blob is one zero byte */

    s3_memzero(&req, sizeof(req));
    s3_memzero(&back, sizeof(back));

    req.kind = S3_SSH3_REQ_PTY;
    s3_str_set(&req.u.pty.term, "xterm-256color");
    req.u.pty.width = 16384; /* the 4-byte varint form */
    req.u.pty.height = 24;
    req.u.pty.pixel_width = 0;
    req.u.pty.pixel_height = 0;
    s3_str_set(&req.u.pty.modes, "");
    s3_str_set(&type, "pty-req");

    n = s3_ssh3_request_encode_body(NULL, &req);

    S3_ASSERT(n == 23);

    q = (u_char *)s3_ssh3_request_encode_body(buf, &req);

    S3_ASSERT(q == buf + n);

    pos = buf;
    end = q;

    S3_ASSERT(s3_ssh3_request_parse_body(&pos, end, &type, &back) == S3_OK);
    S3_ASSERT(pos == end);
    S3_ASSERT(back.kind == S3_SSH3_REQ_PTY);
    S3_ASSERT(back.u.pty.term.len == 14);
    S3_ASSERT(s3_memcmp(back.u.pty.term.data, "xterm-256color", 14) == 0);
    S3_ASSERT(back.u.pty.width == 16384);
    S3_ASSERT(back.u.pty.height == 24);
    S3_ASSERT(back.u.pty.pixel_width == 0);
    S3_ASSERT(back.u.pty.pixel_height == 0);
    S3_ASSERT(back.u.pty.modes.len == 0);

    /* window-change: the varint forms from 1 to 8 bytes */

    s3_memzero(&req, sizeof(req));
    s3_memzero(&back, sizeof(back));

    req.kind = S3_SSH3_REQ_WINDOW_CHANGE;
    req.u.window_change.width = 80; /* above 63: the 2-byte varint form */
    req.u.window_change.height = 24;
    req.u.window_change.pixel_width = 16383; /* the 2-byte varint form */
    req.u.window_change.pixel_height = 4611686018427387903ULL;
    s3_str_set(&type, "window-change");

    n = s3_ssh3_request_encode_body(NULL, &req);

    S3_ASSERT(n == 13);

    q = (u_char *)s3_ssh3_request_encode_body(buf, &req);

    S3_ASSERT(q == buf + n);

    pos = buf;
    end = q;

    S3_ASSERT(s3_ssh3_request_parse_body(&pos, end, &type, &back) == S3_OK);
    S3_ASSERT(pos == end);
    S3_ASSERT(back.kind == S3_SSH3_REQ_WINDOW_CHANGE);
    S3_ASSERT(back.u.window_change.width == 80);
    S3_ASSERT(back.u.window_change.height == 24);
    S3_ASSERT(back.u.window_change.pixel_width == 16383);
    S3_ASSERT(back.u.window_change.pixel_height == 4611686018427387903ULL);

    /* signal: the name rides without the SIG prefix */

    s3_memzero(&req, sizeof(req));
    s3_memzero(&back, sizeof(back));

    req.kind = S3_SSH3_REQ_SIGNAL;
    s3_str_set(&req.u.signal.name, "INT");
    s3_str_set(&type, "signal");

    n = s3_ssh3_request_encode_body(NULL, &req);

    S3_ASSERT(n == 4);

    q = (u_char *)s3_ssh3_request_encode_body(buf, &req);

    S3_ASSERT(q == buf + n);

    pos = buf;
    end = q;

    S3_ASSERT(s3_ssh3_request_parse_body(&pos, end, &type, &back) == S3_OK);
    S3_ASSERT(pos == end);
    S3_ASSERT(back.kind == S3_SSH3_REQ_SIGNAL);
    S3_ASSERT(back.u.signal.name.len == 3);
    S3_ASSERT(s3_memcmp(back.u.signal.name.data, "INT", 3) == 0);

    /* exit-status: the 8-byte varint form */

    s3_memzero(&req, sizeof(req));
    s3_memzero(&back, sizeof(back));

    req.kind = S3_SSH3_REQ_EXIT_STATUS;
    req.u.exit_status.status = 1073741824;
    s3_str_set(&type, "exit-status");

    n = s3_ssh3_request_encode_body(NULL, &req);

    S3_ASSERT(n == 8);

    q = (u_char *)s3_ssh3_request_encode_body(buf, &req);

    S3_ASSERT(q == buf + n);

    pos = buf;
    end = q;

    S3_ASSERT(s3_ssh3_request_parse_body(&pos, end, &type, &back) == S3_OK);
    S3_ASSERT(pos == end);
    S3_ASSERT(back.kind == S3_SSH3_REQ_EXIT_STATUS);
    S3_ASSERT(back.u.exit_status.status == 1073741824);

    /* exit-signal */

    s3_memzero(&req, sizeof(req));
    s3_memzero(&back, sizeof(back));

    req.kind = S3_SSH3_REQ_EXIT_SIGNAL;
    s3_str_set(&req.u.exit_signal.name, "SEGV");
    req.u.exit_signal.core_dumped = 1;
    s3_str_set(&req.u.exit_signal.error_message, "segmentation fault");
    s3_str_set(&req.u.exit_signal.language_tag, "en-US");
    s3_str_set(&type, "exit-signal");

    n = s3_ssh3_request_encode_body(NULL, &req);

    S3_ASSERT(n == 31);

    q = (u_char *)s3_ssh3_request_encode_body(buf, &req);

    S3_ASSERT(q == buf + n);
    S3_ASSERT(buf[5] == 1); /* the coreDumped byte follows the name */

    pos = buf;
    end = q;

    S3_ASSERT(s3_ssh3_request_parse_body(&pos, end, &type, &back) == S3_OK);
    S3_ASSERT(pos == end);
    S3_ASSERT(back.kind == S3_SSH3_REQ_EXIT_SIGNAL);
    S3_ASSERT(back.u.exit_signal.name.len == 4);
    S3_ASSERT(s3_memcmp(back.u.exit_signal.name.data, "SEGV", 4) == 0);
    S3_ASSERT(back.u.exit_signal.core_dumped == 1);
    S3_ASSERT(back.u.exit_signal.error_message.len == 18);
    S3_ASSERT(s3_memcmp(back.u.exit_signal.error_message.data, "segmentation fault", 18) == 0);
    S3_ASSERT(back.u.exit_signal.language_tag.len == 5);
    S3_ASSERT(s3_memcmp(back.u.exit_signal.language_tag.data, "en-US", 5) == 0);

    /* exit-signal, the quiet variant: no core dump, empty strings */

    s3_memzero(&req, sizeof(req));
    s3_memzero(&back, sizeof(back));

    req.kind = S3_SSH3_REQ_EXIT_SIGNAL;
    s3_str_set(&req.u.exit_signal.name, "TERM");
    req.u.exit_signal.core_dumped = 0;
    s3_str_set(&req.u.exit_signal.error_message, "");
    s3_str_set(&req.u.exit_signal.language_tag, "");

    n = s3_ssh3_request_encode_body(NULL, &req);

    S3_ASSERT(n == 8);

    q = (u_char *)s3_ssh3_request_encode_body(buf, &req);

    S3_ASSERT(q == buf + n);

    pos = buf;
    end = q;

    S3_ASSERT(s3_ssh3_request_parse_body(&pos, end, &type, &back) == S3_OK);
    S3_ASSERT(pos == end);
    S3_ASSERT(back.u.exit_signal.core_dumped == 0);
    S3_ASSERT(back.u.exit_signal.error_message.len == 0);
    S3_ASSERT(back.u.exit_signal.language_tag.len == 0);

    /* x11-req */

    s3_memzero(&req, sizeof(req));
    s3_memzero(&back, sizeof(back));

    req.kind = S3_SSH3_REQ_X11;
    req.u.x11.single_connection = 1;
    s3_str_set(&req.u.x11.auth_proto, "MIT-MAGIC-COOKIE-1");
    s3_str_set(&req.u.x11.cookie, "0123456789abcdef0123456789abcdef");
    req.u.x11.screen = 4294967296; /* the 8-byte varint form */
    s3_str_set(&type, "x11-req");

    n = s3_ssh3_request_encode_body(NULL, &req);

    S3_ASSERT(n == 61);

    q = (u_char *)s3_ssh3_request_encode_body(buf, &req);

    S3_ASSERT(q == buf + n);
    S3_ASSERT(buf[0] == 1); /* the singleConnection byte leads */

    pos = buf;
    end = q;

    S3_ASSERT(s3_ssh3_request_parse_body(&pos, end, &type, &back) == S3_OK);
    S3_ASSERT(pos == end);
    S3_ASSERT(back.kind == S3_SSH3_REQ_X11);
    S3_ASSERT(back.u.x11.single_connection == 1);
    S3_ASSERT(back.u.x11.auth_proto.len == 18);
    S3_ASSERT(s3_memcmp(back.u.x11.auth_proto.data, "MIT-MAGIC-COOKIE-1", 18) == 0);
    S3_ASSERT(back.u.x11.cookie.len == 32);
    S3_ASSERT(back.u.x11.screen == 4294967296);

    /* x11-req, the shared variant: no single connection, empty cookie */

    s3_memzero(&req, sizeof(req));
    s3_memzero(&back, sizeof(back));

    req.kind = S3_SSH3_REQ_X11;
    req.u.x11.single_connection = 0;
    s3_str_set(&req.u.x11.auth_proto, "MIT-MAGIC-COOKIE-1");
    s3_str_set(&req.u.x11.cookie, "");
    req.u.x11.screen = 0;

    n = s3_ssh3_request_encode_body(NULL, &req);

    S3_ASSERT(n == 22);

    q = (u_char *)s3_ssh3_request_encode_body(buf, &req);

    S3_ASSERT(q == buf + n);

    pos = buf;
    end = q;

    S3_ASSERT(s3_ssh3_request_parse_body(&pos, end, &type, &back) == S3_OK);
    S3_ASSERT(pos == end);
    S3_ASSERT(back.u.x11.single_connection == 0);
    S3_ASSERT(back.u.x11.cookie.len == 0);
    S3_ASSERT(back.u.x11.screen == 0);

    return s3_test_failures;
}

static int
s3_test_malformed(void)
{
    u_char            buf[64];
    u_char           *q;
    const u_char     *pos, *end;
    s3_str_t          type, other;
    s3_ssh3_request_t back;
    s3_ssh3_request_t reqs[S3_SSH3_REQ_X11 + 1];
    uintptr_t         n, cut;
    size_t            k;

    /* one representative per kind, the wide fields where they exist */

    s3_memzero(reqs, sizeof(reqs));

    reqs[S3_SSH3_REQ_PTY].kind = S3_SSH3_REQ_PTY;
    s3_str_set(&reqs[S3_SSH3_REQ_PTY].u.pty.term, "xterm-256color");
    reqs[S3_SSH3_REQ_PTY].u.pty.width = 80;
    reqs[S3_SSH3_REQ_PTY].u.pty.height = 24;
    reqs[S3_SSH3_REQ_PTY].u.pty.pixel_width = 1920;
    reqs[S3_SSH3_REQ_PTY].u.pty.pixel_height = 1080;
    s3_str_set(&reqs[S3_SSH3_REQ_PTY].u.pty.modes, "\x01\x02\x03\x04");

    /* shell needs nothing but its kind: its empty body has no prefix
     * to cut */

    reqs[S3_SSH3_REQ_SHELL].kind = S3_SSH3_REQ_SHELL;

    reqs[S3_SSH3_REQ_EXEC].kind = S3_SSH3_REQ_EXEC;
    s3_str_set(&reqs[S3_SSH3_REQ_EXEC].u.exec.command, "systemctl status sshd");

    reqs[S3_SSH3_REQ_SUBSYSTEM].kind = S3_SSH3_REQ_SUBSYSTEM;
    s3_str_set(&reqs[S3_SSH3_REQ_SUBSYSTEM].u.subsystem.name, "sftp");

    reqs[S3_SSH3_REQ_WINDOW_CHANGE].kind = S3_SSH3_REQ_WINDOW_CHANGE;
    reqs[S3_SSH3_REQ_WINDOW_CHANGE].u.window_change.width = 16384;
    reqs[S3_SSH3_REQ_WINDOW_CHANGE].u.window_change.height = 24;
    reqs[S3_SSH3_REQ_WINDOW_CHANGE].u.window_change.pixel_width = 640;
    reqs[S3_SSH3_REQ_WINDOW_CHANGE].u.window_change.pixel_height = 480;

    reqs[S3_SSH3_REQ_SIGNAL].kind = S3_SSH3_REQ_SIGNAL;
    s3_str_set(&reqs[S3_SSH3_REQ_SIGNAL].u.signal.name, "WINCH");

    reqs[S3_SSH3_REQ_EXIT_STATUS].kind = S3_SSH3_REQ_EXIT_STATUS;
    reqs[S3_SSH3_REQ_EXIT_STATUS].u.exit_status.status = 1073741824;

    reqs[S3_SSH3_REQ_EXIT_SIGNAL].kind = S3_SSH3_REQ_EXIT_SIGNAL;
    s3_str_set(&reqs[S3_SSH3_REQ_EXIT_SIGNAL].u.exit_signal.name, "KILL");
    reqs[S3_SSH3_REQ_EXIT_SIGNAL].u.exit_signal.core_dumped = 1;
    s3_str_set(&reqs[S3_SSH3_REQ_EXIT_SIGNAL].u.exit_signal.error_message, "user killed");
    s3_str_set(&reqs[S3_SSH3_REQ_EXIT_SIGNAL].u.exit_signal.language_tag, "ru");

    reqs[S3_SSH3_REQ_X11].kind = S3_SSH3_REQ_X11;
    reqs[S3_SSH3_REQ_X11].u.x11.single_connection = 1;
    s3_str_set(&reqs[S3_SSH3_REQ_X11].u.x11.auth_proto, "MIT-MAGIC-COOKIE-1");
    s3_str_set(&reqs[S3_SSH3_REQ_X11].u.x11.cookie, "0123456789abcdef0123456789abcdef");
    reqs[S3_SSH3_REQ_X11].u.x11.screen = 0;

    /*
     * the truncation matrix: every proper prefix of every body is too
     * short, and a failed parse leaves the cursor at the start
     */

    for (k = 0; k < sizeof(reqs) / sizeof(reqs[0]); k++) {

        n = s3_ssh3_request_encode_body(NULL, &reqs[k]);

        if (n == 0) {
            continue;
        }

        q = (u_char *)s3_ssh3_request_encode_body(buf, &reqs[k]);

        S3_ASSERT(q == buf + n);

        type.data = (u_char *)s3_ssh3_request_type_str((s3_ssh3_request_kind_t)k);

        S3_ASSERT(type.data != NULL);

        type.len = s3_strlen(type.data);

        for (cut = 0; cut < n; cut++) {

            pos = buf;
            end = buf + cut;

            S3_ASSERT(s3_ssh3_request_parse_body(&pos, end, &type, &back) == S3_ERROR);
            S3_ASSERT(pos == buf);
        }

        /* the full body parses back */

        pos = buf;
        end = q;

        S3_ASSERT(s3_ssh3_request_parse_body(&pos, end, &type, &back) == S3_OK);
        S3_ASSERT(pos == end);
        S3_ASSERT(back.kind == (s3_ssh3_request_kind_t)k);
    }

    /* a valid body under an unknown type name is declined, not
     * broken ("signal" is a known type and would just misparse) */

    s3_str_set(&other, "forward-port");

    n = s3_ssh3_request_encode_body(NULL, &reqs[S3_SSH3_REQ_PTY]);
    q = (u_char *)s3_ssh3_request_encode_body(buf, &reqs[S3_SSH3_REQ_PTY]);

    pos = buf;
    end = q;

    S3_ASSERT(s3_ssh3_request_parse_body(&pos, end, &other, &back) == S3_DECLINED);
    S3_ASSERT(pos == buf);

    /* one trailing byte past the body is not part of any request */

    n = s3_ssh3_request_encode_body(NULL, &reqs[S3_SSH3_REQ_EXEC]);
    q = (u_char *)s3_ssh3_request_encode_body(buf, &reqs[S3_SSH3_REQ_EXEC]);

    S3_ASSERT(n > 0);

    *q = 0x7e;

    s3_str_set(&type, "exec");

    pos = buf;
    end = q + 1;

    S3_ASSERT(s3_ssh3_request_parse_body(&pos, end, &type, &back) == S3_ERROR);
    S3_ASSERT(pos == buf);

    return s3_test_failures;
}

static int
s3_test_ssh3_request(void)
{
    (void)s3_test_request_type_map();
    (void)s3_test_pty_known_vector();
    (void)s3_test_roundtrip();
    (void)s3_test_malformed();

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_ssh3_request)
