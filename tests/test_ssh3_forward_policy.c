/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the forward target policy, the PermitOpen analog (F-05): the
 * sshd_config PermitOpen spec of the reference
 * cmd/forward_policy.go parsePermitOpen/allows
 */

#include <s3_core.h>

#include <stdio.h>
#include <string.h>

#include <s3_ssh3_forward_policy.h>

#include "s3_test.h"

static int
s3_test_policy_empty_is_unrestricted(void)
{
    s3_ssh3_forward_policy_t p;

    /* the empty spec and the nil policy keep the historical
     * unrestricted default (the OpenSSH shape: PermitOpen unset means
     * no restriction) */

    S3_ASSERT(s3_ssh3_forward_policy_check(NULL, "127.0.0.1", 22) == S3_OK);

    s3_ssh3_forward_policy_init(&p);
    S3_ASSERT(p.n == 0);
    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "127.0.0.1", 22) == S3_OK);

    S3_ASSERT(s3_ssh3_forward_policy_parse(&p, "") == S3_OK);
    S3_ASSERT(p.n == 0);
    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "192.0.2.1", 443) == S3_OK);

    /* the whitespace-only and the separator-only specs fold into the
     * same unrestricted policy (the Go FieldsFunc drops the empty
     * fields) */

    S3_ASSERT(s3_ssh3_forward_policy_parse(&p, "  \t ") == S3_OK);
    S3_ASSERT(p.n == 0);
    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "192.0.2.1", 443) == S3_OK);

    S3_ASSERT(s3_ssh3_forward_policy_parse(&p, ",,,") == S3_OK);
    S3_ASSERT(p.n == 0);
    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "192.0.2.1", 443) == S3_OK);

    return s3_test_failures;
}

static int
s3_test_policy_exact_entry(void)
{
    s3_ssh3_forward_policy_t p;

    /* the exact host:port entry allows only that pair */

    S3_ASSERT(s3_ssh3_forward_policy_parse(&p, "127.0.0.1:22") == S3_OK);
    S3_ASSERT(p.n == 1);
    S3_ASSERT(!p.entries[0].negated);
    S3_ASSERT(!p.entries[0].port_any);
    S3_ASSERT(p.entries[0].port == 22);

    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "127.0.0.1", 22) == S3_OK);
    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "127.0.0.1", 23) == S3_DECLINED);
    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "127.0.0.2", 22) == S3_DECLINED);
    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "127.0.0.2", 23) == S3_DECLINED);

    /* the host lowercases at the parse: the uppercase spec form and
     * the canonical lowercase target match */

    S3_ASSERT(s3_ssh3_forward_policy_parse(&p, "EXAMPLE.ORG:443") == S3_OK);
    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "example.org", 443) == S3_OK);
    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "a.example.org", 443) == S3_DECLINED);

    /* the leading zeros fold into the numeric port, like the Go
     * ParseUint does */

    S3_ASSERT(s3_ssh3_forward_policy_parse(&p, "example.org:00443") == S3_OK);
    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "example.org", 443) == S3_OK);

    /* the boundary ports of the uint16 range parse */

    S3_ASSERT(s3_ssh3_forward_policy_parse(&p, "example.org:65535") == S3_OK);
    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "example.org", 65535) == S3_OK);

    return s3_test_failures;
}

static int
s3_test_policy_wildcards(void)
{
    s3_ssh3_forward_policy_t p;

    /* the "*" port accepts everything, the host stays exact */

    S3_ASSERT(s3_ssh3_forward_policy_parse(&p, "example.org:*") == S3_OK);
    S3_ASSERT(p.entries[0].port_any);
    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "example.org", 1) == S3_OK);
    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "example.org", 65535) == S3_OK);
    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "other.example.org", 1) == S3_DECLINED);

    /* the "*" host accepts every target of the port */

    S3_ASSERT(s3_ssh3_forward_policy_parse(&p, "*:22") == S3_OK);
    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "127.0.0.1", 22) == S3_OK);
    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "2001:db8::1", 22) == S3_OK);
    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "127.0.0.1", 23) == S3_DECLINED);

    /* the full "*:*" form is the explicit allow-all */

    S3_ASSERT(s3_ssh3_forward_policy_parse(&p, "*:*") == S3_OK);
    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "anything.example", 40000) == S3_OK);

    /* the bare "*" is not an entry: the reference strings.Cut finds
     * no colon and answers "want host:port" */

    S3_ASSERT(s3_ssh3_forward_policy_parse(&p, "*") == S3_ERROR);

    /* the leading wildcard matches the subdomains but not the suffix
     * domain itself (the sshd_config PATTERNS shape) */

    S3_ASSERT(s3_ssh3_forward_policy_parse(&p, "*.example.org:443") == S3_OK);
    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "a.example.org", 443) == S3_OK);
    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "a.b.example.org", 443) == S3_OK);
    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "example.org", 443) == S3_DECLINED);
    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "badexample.org", 443) == S3_DECLINED);
    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "a.example.com", 443) == S3_DECLINED);

    return s3_test_failures;
}

static int
s3_test_policy_ipv6(void)
{
    s3_ssh3_forward_policy_t p;

    /* the bracketed ipv6 literal: the first-colon cut of the bare
     * form would land inside the address, the brackets fence it (the
     * reference spec cannot express ipv6 at all, this is the sshd
     * bracket shape) */

    S3_ASSERT(s3_ssh3_forward_policy_parse(&p, "[2001:db8::1]:443") == S3_OK);
    S3_ASSERT(p.n == 1);
    S3_ASSERT(p.entries[0].port == 443);
    S3_ASSERT(s3_memcmp(p.entries[0].host, "2001:db8::1", 11) == 0);

    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "2001:db8::1", 443) == S3_OK);
    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "2001:db8::1", 444) == S3_DECLINED);
    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "2001:db8::2", 443) == S3_DECLINED);

    /* the uppercase literal form folds into the canonical lowercase
     * one at the parse */

    S3_ASSERT(s3_ssh3_forward_policy_parse(&p, "[2001:DB8::1]:*") == S3_OK);
    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "2001:db8::1", 9) == S3_OK);

    /* the loopback and the wildcard port */

    S3_ASSERT(s3_ssh3_forward_policy_parse(&p, "[::1]:22") == S3_OK);
    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "::1", 22) == S3_OK);
    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "::2", 22) == S3_DECLINED);

    return s3_test_failures;
}

static int
s3_test_policy_negation(void)
{
    s3_ssh3_forward_policy_t p;

    /* the negated entry denies its own match no matter where it
     * stands; the reference allows() returns false the moment a
     * negated entry matches */

    S3_ASSERT(s3_ssh3_forward_policy_parse(&p, "!127.0.0.1:22,127.0.0.1:*") == S3_OK);
    S3_ASSERT(p.n == 2);
    S3_ASSERT(p.entries[0].negated);
    S3_ASSERT(!p.entries[1].negated);

    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "127.0.0.1", 22) == S3_DECLINED);
    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "127.0.0.1", 80) == S3_OK);
    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "192.0.2.1", 22) == S3_DECLINED);

    /* the allow first, the negation after: the negation still wins */

    S3_ASSERT(s3_ssh3_forward_policy_parse(&p, "127.0.0.1:22,!127.0.0.1:22") == S3_OK);
    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "127.0.0.1", 22) == S3_DECLINED);

    /* the negation-only policy: everything the negations do not name
     * stays allowed (the unmatched default allows while no allow
     * entry exists at all) */

    S3_ASSERT(s3_ssh3_forward_policy_parse(&p, "!10.0.0.1:1") == S3_OK);
    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "10.0.0.1", 1) == S3_DECLINED);
    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "10.0.0.1", 2) == S3_OK);
    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "192.0.2.1", 1) == S3_OK);

    /* the negated wildcard carves one suffix out of the allow list;
     * the unmatched default is policy-wide: the allow entry of
     * *.good.org denies every unmatched target, so x.bad.org:2 (the
     * negation names only the port 1) stays denied too */

    S3_ASSERT(s3_ssh3_forward_policy_parse(&p, "!*.bad.org:1,*.good.org:*") == S3_OK);
    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "x.good.org", 5) == S3_OK);
    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "x.bad.org", 1) == S3_DECLINED);
    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "x.bad.org", 2) == S3_DECLINED);
    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "other.org", 5) == S3_DECLINED);

    return s3_test_failures;
}

static int
s3_test_policy_parse_errors(void)
{
    static const char *bad[] = {
        "*",          /* no colon: want host:port */
        "host",       /* the same, the plain hostname */
        "host:",      /* the empty port */
        ":22",        /* the empty host */
        ":",          /* both empty */
        "!:22",       /* the negation alone does not fill the host */
        "!:*",        /* the same with the wildcard port */
        "::1:22",     /* the bare ipv6: the first colon cuts an empty host */
        "[::1",       /* the unclosed bracket */
        "[::1]",      /* the bracket without the port part */
        "[::1]:",     /* the empty port after the bracket */
        "[::1]22",    /* no colon after the bracket */
        "host:abc",   /* the non-numeric port */
        "host:1x",    /* the trailing garbage */
        "host:+22",   /* the sign is not a digit */
        "host:99999", /* above the uint16 range */
        "host:65536", /* the first port past the range */
    };

    s3_ssh3_forward_policy_t p;
    u_char                   longhost[512];
    u_char                   longspec[S3_SSH3_FORWARD_POLICY_SPEC_MAX + 64];
    size_t                   i;

    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        S3_ASSERT(s3_ssh3_forward_policy_parse(&p, bad[i]) == S3_ERROR);
    }

    /* the host over the bound: a 300-byte name does not fit the
     * entry, the parse refuses instead of clipping */

    s3_memzero(longhost, sizeof(longhost));
    memset(longhost, 'a', 300);
    longhost[300] = '\0';

    S3_ASSERT(strlen((const char *)longhost) > S3_SSH3_FORWARD_POLICY_HOST_MAX);
    S3_ASSERT(s3_ssh3_forward_policy_parse(&p, (const char *)longhost) == S3_ERROR);

    /* the exact-boundary host (255 bytes) still parses: the spec
     * rides in the bigger buffer, the entry host fills to the bound
     * exactly */

    s3_memzero(longhost, sizeof(longhost));
    memset(longhost, 'a', S3_SSH3_FORWARD_POLICY_HOST_MAX);
    longhost[S3_SSH3_FORWARD_POLICY_HOST_MAX] = '\0';

    s3_memcpy(longspec, longhost, S3_SSH3_FORWARD_POLICY_HOST_MAX + 1);
    s3_memcpy(longspec + S3_SSH3_FORWARD_POLICY_HOST_MAX, ":1", 2);

    S3_ASSERT(s3_ssh3_forward_policy_parse(&p, (const char *)longspec) == S3_OK);
    S3_ASSERT(s3_ssh3_forward_policy_check(&p, (const char *)longhost, 1) == S3_OK);

    S3_ASSERT(s3_ssh3_forward_policy_parse(&p, "example.org:1") == S3_OK);

    /* the spec itself over the bound is refused before any entry */

    memset(longspec, 'x', sizeof(longspec) - 1);
    longspec[sizeof(longspec) - 1] = '\0';

    S3_ASSERT(strlen((const char *)longspec) >= S3_SSH3_FORWARD_POLICY_SPEC_MAX);
    S3_ASSERT(s3_ssh3_forward_policy_parse(&p, (const char *)longspec) == S3_ERROR);

    /* the bound keeps the entries finite: one past the max is an
     * error, not a silent truncation */

    {
        u_char many[S3_SSH3_FORWARD_POLICY_MAX * 8 + 8];
        size_t n = 0;

        s3_memzero(many, sizeof(many));

        for (i = 0; i < S3_SSH3_FORWARD_POLICY_MAX + 1; i++) {
            n += (size_t)snprintf((char *)many + n, sizeof(many) - n, "h%zu:1,", i);
        }

        S3_ASSERT(s3_ssh3_forward_policy_parse(&p, (const char *)many) == S3_ERROR);
    }

    return s3_test_failures;
}

static int
s3_test_policy_multi_entry_spec(void)
{
    s3_ssh3_forward_policy_t p;

    /* the commas and the spaces mix freely in one spec */

    S3_ASSERT(s3_ssh3_forward_policy_parse(&p, " 127.0.0.1:22,\t192.0.2.1:53 , example.org:*") ==
              S3_OK);
    S3_ASSERT(p.n == 3);

    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "127.0.0.1", 22) == S3_OK);
    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "192.0.2.1", 53) == S3_OK);
    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "example.org", 8080) == S3_OK);
    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "192.0.2.1", 54) == S3_DECLINED);
    S3_ASSERT(s3_ssh3_forward_policy_check(&p, "192.0.2.2", 53) == S3_DECLINED);

    return s3_test_failures;
}

static int
s3_test_ssh3_forward_policy(void)
{
    (void)s3_test_policy_empty_is_unrestricted();
    (void)s3_test_policy_exact_entry();
    (void)s3_test_policy_wildcards();
    (void)s3_test_policy_ipv6();
    (void)s3_test_policy_negation();
    (void)s3_test_policy_parse_errors();
    (void)s3_test_policy_multi_entry_spec();

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_ssh3_forward_policy)
