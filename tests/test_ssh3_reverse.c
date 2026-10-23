/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the reverse port forwarding (-R) payloads: the -R spec parser of the
 * reference cmd/reverse_forward.go parseReverseForwardSpec and the
 * wire codecs of message/reverse_forward.go (the request and its
 * reply travel as channel data on the "reverse-forward" control
 * channel)
 */

#include <s3_core.h>

#include <string.h>

#if (S3_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include <s3_ssh3_forward.h>
#include <s3_ssh3_reverse.h>
#include <s3_ssh3_wire.h>

#include "s3_test.h"

static int
s3_test_reverse_spec_parse(void)
{
    s3_ssh3_reverse_spec_t spec;

    /* the canonical three-part form: the empty bind defaults to the
     * server loopback, the protocol defaults to the tcp */

    S3_ASSERT(s3_ssh3_reverse_parse_spec("3000:127.0.0.1:80", &spec) == S3_OK);
    S3_ASSERT(spec.proto == S3_SSH3_REVERSE_PROTO_TCP);
    S3_ASSERT(spec.bind_host[0] == '\0');
    S3_ASSERT(spec.bind_port == 3000);
    S3_ASSERT(strcmp(spec.target_host, "127.0.0.1") == 0);
    S3_ASSERT(spec.target_port == 80);

    /* the /udp suffix after the bind port selects the udp, /tcp stays
     * the explicit tcp */

    S3_ASSERT(s3_ssh3_reverse_parse_spec("5353/udp:10.0.0.1:53", &spec) == S3_OK);
    S3_ASSERT(spec.proto == S3_SSH3_REVERSE_PROTO_UDP);
    S3_ASSERT(spec.bind_port == 5353);
    S3_ASSERT(spec.target_port == 53);

    S3_ASSERT(s3_ssh3_reverse_parse_spec("3000/tcp:127.0.0.1:80", &spec) == S3_OK);
    S3_ASSERT(spec.proto == S3_SSH3_REVERSE_PROTO_TCP);

    /* the four-part form carries the bind address; the "*" wildcard
     * maps to the "::" bind of the reference parser */

    S3_ASSERT(s3_ssh3_reverse_parse_spec("127.0.0.1:3000:192.0.2.10:80", &spec) == S3_OK);
    S3_ASSERT(strcmp(spec.bind_host, "127.0.0.1") == 0);
    S3_ASSERT(spec.bind_port == 3000);
    S3_ASSERT(strcmp(spec.target_host, "192.0.2.10") == 0);

    S3_ASSERT(s3_ssh3_reverse_parse_spec("*:3000:192.0.2.10:80", &spec) == S3_OK);
    S3_ASSERT(strcmp(spec.bind_host, "::") == 0);

    /* the empty bind host of the four-part form is the same server
     * default as the omitted bind (the reference unbracket("") "") */

    S3_ASSERT(s3_ssh3_reverse_parse_spec(":3000:192.0.2.10:80", &spec) == S3_OK);
    S3_ASSERT(spec.bind_host[0] == '\0');
    S3_ASSERT(spec.bind_port == 3000);

    /* the bracketed ipv6 literals ride both positions */

    S3_ASSERT(s3_ssh3_reverse_parse_spec("[2001:db8::1]:3000:[::1]:80", &spec) == S3_OK);
    S3_ASSERT(strcmp(spec.bind_host, "2001:db8::1") == 0);
    S3_ASSERT(strcmp(spec.target_host, "::1") == 0);

    /* the ephemeral bind port 0 is legal, the target port is not */

    S3_ASSERT(s3_ssh3_reverse_parse_spec("0:192.0.2.10:80", &spec) == S3_OK);
    S3_ASSERT(spec.bind_port == 0);

    /* the refusals: the part count, the suffixes, the ports, the
     * empty target */

    S3_ASSERT(s3_ssh3_reverse_parse_spec("3000:80", &spec) == S3_ERROR);
    S3_ASSERT(s3_ssh3_reverse_parse_spec("127.0.0.1:3000:192.0.2.10:80:extra", &spec) == S3_ERROR);
    S3_ASSERT(s3_ssh3_reverse_parse_spec("3000/sctp:192.0.2.10:80", &spec) == S3_ERROR);
    S3_ASSERT(s3_ssh3_reverse_parse_spec("3000/:192.0.2.10:80", &spec) == S3_ERROR);
    S3_ASSERT(s3_ssh3_reverse_parse_spec("3000:192.0.2.10:0", &spec) == S3_ERROR);
    S3_ASSERT(s3_ssh3_reverse_parse_spec("3000::80", &spec) == S3_ERROR);
    S3_ASSERT(s3_ssh3_reverse_parse_spec("3000:192.0.2.10:", &spec) == S3_ERROR);
    S3_ASSERT(s3_ssh3_reverse_parse_spec("abc:192.0.2.10:80", &spec) == S3_ERROR);
    S3_ASSERT(s3_ssh3_reverse_parse_spec("70000:192.0.2.10:80", &spec) == S3_ERROR);
    S3_ASSERT(s3_ssh3_reverse_parse_spec("3000:192.0.2.10:70000", &spec) == S3_ERROR);
    S3_ASSERT(s3_ssh3_reverse_parse_spec("-1:192.0.2.10:80", &spec) == S3_ERROR);

    return s3_test_failures;
}

/*
 * the host texts of the spec: the printable characters only.  the bind
 * address rides the wire verbatim and the server logs it as it stands
 * (the refusal reason rides the reply), so a control character in the
 * spec would reach the server log as a terminal escape - the parse
 * refuses it before anything is sent
 */

static int
s3_test_reverse_spec_printable(void)
{
    s3_ssh3_reverse_spec_t spec;

    /* the control characters of the target host: the c0 set and the
     * delete */

    S3_ASSERT(s3_ssh3_reverse_parse_spec("3000:127.0.0.1\x01:80", &spec) == S3_ERROR);
    S3_ASSERT(s3_ssh3_reverse_parse_spec("3000:127.0.0.1\n:80", &spec) == S3_ERROR);
    S3_ASSERT(s3_ssh3_reverse_parse_spec("3000:127.0.0.1\t:80", &spec) == S3_ERROR);
    S3_ASSERT(s3_ssh3_reverse_parse_spec("3000:127.0.0.1\x7f:80", &spec) == S3_ERROR);
    S3_ASSERT(s3_ssh3_reverse_parse_spec("3000:127.0.0.1\x1b[31m:80", &spec) == S3_ERROR);

    /* the raw 8-bit bytes refuse too: the ASCII printable is the
     * whole alphabet of a bind host (the B15 audit tail) */

    S3_ASSERT(s3_ssh3_reverse_parse_spec("3000:127.0.0.\x80:80", &spec) == S3_ERROR);
    S3_ASSERT(s3_ssh3_reverse_parse_spec("3000:h\xfcst.example:80", &spec) == S3_ERROR);
    S3_ASSERT(s3_ssh3_reverse_parse_spec("127.0.0.1\xff:3000:192.0.2.10:80", &spec) == S3_ERROR);

    /* the same rule on the bind host of the four-part form */

    S3_ASSERT(s3_ssh3_reverse_parse_spec("127.0.0.1\x02:3000:192.0.2.10:80", &spec) == S3_ERROR);
    S3_ASSERT(s3_ssh3_reverse_parse_spec("127.0.0.1\n:3000:192.0.2.10:80", &spec) == S3_ERROR);
    S3_ASSERT(s3_ssh3_reverse_parse_spec("127.0.0.1\x7f:3000:192.0.2.10:80", &spec) == S3_ERROR);

    /* the plain texts keep passing: the printable space is not a
     * control character */

    S3_ASSERT(s3_ssh3_reverse_parse_spec("3000:127.0.0.1:80", &spec) == S3_OK);
    S3_ASSERT(s3_ssh3_reverse_parse_spec("127.0.0.1:3000:192.0.2.10:80", &spec) == S3_OK);
    S3_ASSERT(s3_ssh3_reverse_parse_spec("3000:host.example:80", &spec) == S3_OK);
    S3_ASSERT(s3_ssh3_reverse_parse_spec("3000:host-example:80", &spec) == S3_OK);

    return s3_test_failures;
}

static int
s3_test_reverse_resolve(void)
{
    s3_ssh3_forward_target_t target;
    s3_ssh3_reverse_spec_t   spec;

    /* the client resolves the target locally, the wire carries the
     * canonical ip text of the resolution (the reference
     * resolveTarget) */

    S3_ASSERT(s3_ssh3_reverse_parse_spec("3000:127.0.0.1:80", &spec) == S3_OK);
    S3_ASSERT(s3_ssh3_reverse_resolve_target(&spec, &target) == S3_OK);
    S3_ASSERT(target.family == 4);
    S3_ASSERT(target.ip_len == 4);
    S3_ASSERT(target.ip[0] == 127 && target.ip[3] == 1);
    S3_ASSERT(target.port == 80);

    /* the ipv6 target rides the bracket form, the bare colons would
     * split into a wrong part count (the reference tokenizer); the
     * resolution answers the family 6, the caller owns the family
     * policy (the client refuses a non-ipv4 target before the
     * request is sent) */

    S3_ASSERT(s3_ssh3_reverse_parse_spec("3000/udp:[::1]:53", &spec) == S3_OK);
    S3_ASSERT(s3_ssh3_reverse_resolve_target(&spec, &target) == S3_OK);
    S3_ASSERT(target.family == 6);
    S3_ASSERT(target.ip_len == 16);
    S3_ASSERT(target.ip[15] == 1);
    S3_ASSERT(target.port == 53);

    /* the names resolve too (the OpenSSH shape), an unknown host does
     * not; the port 0 spec cannot appear (the parser refuses it), the
     * empty host the same */

    S3_ASSERT(s3_ssh3_reverse_parse_spec("3000:localhost:80", &spec) == S3_OK);
    S3_ASSERT(s3_ssh3_reverse_resolve_target(&spec, &target) == S3_OK);
    S3_ASSERT(target.family == 4);

    S3_ASSERT(s3_ssh3_reverse_parse_spec("3000:no-such-host.invalid.:80", &spec) == S3_OK);
    S3_ASSERT(s3_ssh3_reverse_resolve_target(&spec, &target) == S3_ERROR);

    /* the names resolve over AF_INET (the ipv4 canon of the direct
     * forward path): the udp leg resolves the same way, the socket
     * type of the hint does not touch the address */

    S3_ASSERT(s3_ssh3_reverse_parse_spec("5353/udp:localhost:53", &spec) == S3_OK);
    S3_ASSERT(spec.proto == S3_SSH3_REVERSE_PROTO_UDP);
    S3_ASSERT(s3_ssh3_reverse_resolve_target(&spec, &target) == S3_OK);
    S3_ASSERT(target.family == 4);
    S3_ASSERT(target.port == 53);

    /* the canonical text of the resolution rides the wire as the
     * target address of the bind request (the reference
     * addr.IP.String()) */

    S3_ASSERT(s3_ssh3_reverse_parse_spec("3000:127.0.0.1:80", &spec) == S3_OK);
    S3_ASSERT(s3_ssh3_reverse_resolve_target(&spec, &target) == S3_OK);

    {
        char text[64];

        S3_ASSERT(s3_ssh3_reverse_target_ntop(&target, text, sizeof(text)) == S3_OK);
        S3_ASSERT(strcmp(text, "127.0.0.1") == 0);
    }

    return s3_test_failures;
}

/*
 * the no-special-target invariant: the wire text of the target is the
 * canonical text of the local resolution, so the server re-parses it
 * into the very address the client resolved (the server gate is the
 * inet_pton of that text) - the client cannot hand the server a
 * target the two sides read differently
 */

static int
s3_test_reverse_target_text(void)
{
    s3_ssh3_reverse_spec_t   spec;
    s3_ssh3_forward_target_t target;
    char                     text[64];
    struct in_addr           a4;
    struct in6_addr          a6;

    /* the ipv4 literal: the canonical text reads back as the same
     * four bytes */

    S3_ASSERT(s3_ssh3_reverse_parse_spec("3000:127.0.0.1:80", &spec) == S3_OK);
    S3_ASSERT(s3_ssh3_reverse_resolve_target(&spec, &target) == S3_OK);
    S3_ASSERT(s3_ssh3_reverse_target_ntop(&target, text, sizeof(text)) == S3_OK);
    S3_ASSERT(strcmp(text, "127.0.0.1") == 0);
    S3_ASSERT(inet_pton(AF_INET, text, &a4) == 1);
    S3_ASSERT(s3_memcmp(&a4, target.ip, 4) == 0);

    /* the v4-mapped literal: the canonical text keeps the v6 form and
     * the server reads the same sixteen bytes (the fork sends the
     * target in this shape) */

    S3_ASSERT(s3_ssh3_reverse_parse_spec("3000:[::ffff:127.0.0.1]:80", &spec) == S3_OK);
    S3_ASSERT(s3_ssh3_reverse_resolve_target(&spec, &target) == S3_OK);
    S3_ASSERT(target.family == 6);
    S3_ASSERT(target.ip_len == 16);
    S3_ASSERT(s3_ssh3_reverse_target_ntop(&target, text, sizeof(text)) == S3_OK);
    S3_ASSERT(inet_pton(AF_INET6, text, &a6) == 1);
    S3_ASSERT(s3_memcmp(&a6, target.ip, 16) == 0);

    /* the port of the resolution rides the request as it stands */

    S3_ASSERT(s3_ssh3_reverse_parse_spec("3000:127.0.0.1:8080", &spec) == S3_OK);
    S3_ASSERT(s3_ssh3_reverse_resolve_target(&spec, &target) == S3_OK);
    S3_ASSERT(target.port == 8080);

    return s3_test_failures;
}

static int
s3_test_reverse_request_golden(void)
{
    /* the golden vector of the reference message test: varint(1) |
     * sshstring("127.0.0.1") | be16(8080) | sshstring("192.0.2.10") |
     * be16(80) */

    static const u_char golden[] = {0x01, 0x09, '1',  '2',  '7',  '.', '0',  '.', '0',
                                    '.',  '1',  0x1f, 0x90, 0x0a, '1', '9',  '2', '.',
                                    '0',  '.',  '2',  '.',  '1',  '0', 0x00, 0x50};

    u_char                    buf[64];
    u_char                   *p;
    const u_char             *pos, *end;
    s3_ssh3_reverse_request_t r, out;
    s3_str_t                  bind, target;

    bind.data = (u_char *)"127.0.0.1";
    bind.len = 9;
    target.data = (u_char *)"192.0.2.10";
    target.len = 10;

    r.proto = S3_SSH3_REVERSE_PROTO_TCP;
    r.bind_address = bind;
    r.bind_port = 8080;
    r.target_address = target;
    r.target_port = 80;

    S3_ASSERT(s3_ssh3_reverse_request_size(&r) == sizeof(golden));

    /* the size is the sum of the fields and nothing else: the request
     * carries no identity, so a client cannot ask for the budget of
     * another user (the attribution is the server's, the
     * authenticated CONNECT) */

    S3_ASSERT(s3_ssh3_reverse_request_size(&r) == 1 + (1 + 9) + 2 + (1 + 10) + 2);

    s3_memzero(buf, sizeof(buf));
    p = s3_ssh3_reverse_build_request(buf, &r);

    S3_ASSERT(p == buf + sizeof(golden));
    S3_ASSERT(p == buf + s3_ssh3_reverse_request_size(&r));
    S3_ASSERT(s3_memcmp(buf, golden, sizeof(golden)) == 0);

    /* the round trip: the strings come back as the buffer views */

    buf[sizeof(golden)] = 0xa5;

    pos = buf;
    end = buf + sizeof(golden);

    S3_ASSERT(s3_ssh3_reverse_parse_request(&pos, end, &out) == S3_OK);
    S3_ASSERT(out.proto == S3_SSH3_REVERSE_PROTO_TCP);
    S3_ASSERT(out.bind_address.len == 9);
    S3_ASSERT(s3_memcmp(out.bind_address.data, "127.0.0.1", 9) == 0);
    S3_ASSERT(out.bind_port == 8080);
    S3_ASSERT(out.target_address.len == 10);
    S3_ASSERT(s3_memcmp(out.target_address.data, "192.0.2.10", 10) == 0);
    S3_ASSERT(out.target_port == 80);
    S3_ASSERT(pos == buf + sizeof(golden));
    S3_ASSERT(buf[sizeof(golden)] == 0xa5);

    return s3_test_failures;
}

static int
s3_test_reverse_request_validate(void)
{
    u_char                    buf[64];
    u_char                   *p;
    const u_char             *pos, *end;
    s3_ssh3_reverse_request_t r, out;
    s3_str_t                  bind, target;

    /* the protocol number is the udp 0 or the tcp 1, anything else is
     * a refusal before the strings (the reference protocol gate) */

    bind.data = (u_char *)"";
    bind.len = 0;
    target.data = (u_char *)"127.0.0.1";
    target.len = 9;

    r.proto = 17;
    r.bind_address = bind;
    r.bind_port = 3000;
    r.target_address = target;
    r.target_port = 80;

    p = s3_ssh3_reverse_build_request(buf, &r);

    S3_ASSERT(p != NULL);

    pos = buf;
    end = p;

    S3_ASSERT(s3_ssh3_reverse_parse_request(&pos, end, &out) == S3_ERROR);
    S3_ASSERT(pos == buf);

    /* the truncations: every prefix shorter than the request refuses
     * and leaves the cursor put */

    r.proto = S3_SSH3_REVERSE_PROTO_TCP;
    r.bind_address.data = (u_char *)"127.0.0.1";
    r.bind_address.len = 9;

    p = s3_ssh3_reverse_build_request(buf, &r);

    S3_ASSERT(p != NULL);

    {
        size_t total = (size_t)(p - buf);
        size_t cut;

        for (cut = 0; cut < total; cut++) {

            pos = buf;
            end = buf + cut;

            S3_ASSERT(s3_ssh3_reverse_parse_request(&pos, end, &out) == S3_ERROR);
            S3_ASSERT(pos == buf);
        }
    }

    return s3_test_failures;
}

static int
s3_test_reverse_reply(void)
{
    /* the success reply: the bound port and the empty error string
     * (the reference writer always emits the string, the port-only
     * two-byte shape has no writer) */

    static const u_char ok[] = {0x0b, 0xb8, 0x00};

    /* the refusal carries the reason instead of the port echo */

    static const u_char bad[] = {0x00, 0x00, 0x03, 'n', 'o', 'p'};

    u_char                  buf[64];
    u_char                 *p;
    const u_char           *pos, *end;
    s3_ssh3_reverse_reply_t r, out;

    r.bound_port = 3000;
    r.error_utf8.data = (u_char *)"";
    r.error_utf8.len = 0;

    S3_ASSERT(s3_ssh3_reverse_reply_size(&r) == sizeof(ok));

    s3_memzero(buf, sizeof(buf));
    p = s3_ssh3_reverse_build_reply(buf, &r);

    S3_ASSERT(p == buf + sizeof(ok));
    S3_ASSERT(s3_memcmp(buf, ok, sizeof(ok)) == 0);

    pos = buf;
    end = p;

    S3_ASSERT(s3_ssh3_reverse_parse_reply(&pos, end, &out) == S3_OK);
    S3_ASSERT(out.bound_port == 3000);
    S3_ASSERT(out.error_utf8.len == 0);
    S3_ASSERT(pos == end);
    S3_ASSERT(s3_ssh3_reverse_reply_ok(&out));

    r.bound_port = 0;
    r.error_utf8.data = (u_char *)"nop";
    r.error_utf8.len = 3;

    p = s3_ssh3_reverse_build_reply(buf, &r);

    S3_ASSERT(p == buf + sizeof(bad));
    S3_ASSERT(s3_memcmp(buf, bad, sizeof(bad)) == 0);

    pos = buf;
    end = p;

    S3_ASSERT(s3_ssh3_reverse_parse_reply(&pos, end, &out) == S3_OK);
    S3_ASSERT(out.bound_port == 0);
    S3_ASSERT(out.error_utf8.len == 3);
    S3_ASSERT(s3_memcmp(out.error_utf8.data, "nop", 3) == 0);
    S3_ASSERT(!s3_ssh3_reverse_reply_ok(&out));

    /* the truncations refuse: the port alone is not a reply, the
     * error string may not cut inside its length */

    pos = buf;
    end = buf + 2;

    S3_ASSERT(s3_ssh3_reverse_parse_reply(&pos, end, &out) == S3_ERROR);
    S3_ASSERT(pos == buf);

    pos = buf;
    end = buf + 5;

    S3_ASSERT(s3_ssh3_reverse_parse_reply(&pos, end, &out) == S3_ERROR);
    S3_ASSERT(pos == buf);

    return s3_test_failures;
}

int
s3_test_ssh3_reverse(void)
{
    if (s3_test_reverse_spec_parse() != 0) {
        return s3_test_failures;
    }

    if (s3_test_reverse_spec_printable() != 0) {
        return s3_test_failures;
    }

    if (s3_test_reverse_resolve() != 0) {
        return s3_test_failures;
    }

    if (s3_test_reverse_target_text() != 0) {
        return s3_test_failures;
    }

    if (s3_test_reverse_request_golden() != 0) {
        return s3_test_failures;
    }

    if (s3_test_reverse_request_validate() != 0) {
        return s3_test_failures;
    }

    if (s3_test_reverse_reply() != 0) {
        return s3_test_failures;
    }

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_ssh3_reverse)
