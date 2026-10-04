/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the ssh3 version-string negotiation (the reference version.go):
 * format "SSH M.m impl X.Y.Z[ experimental_spec_version=V]", the
 * server verdict is 403 unless the peer version parses and is
 * supported
 */

#include <s3_core.h>

#include <string.h>

#include <s3_ssh3_version.h>

#include "s3_test.h"

static int
s3_test_parse_ok(const char *text, unsigned major, unsigned minor, const char *impl,
                 unsigned sw_major, unsigned sw_minor, unsigned sw_patch, const char *spec)
{
    s3_ssh3_version_t     v;
    size_t                n;
    s3_int_t              rc;
    static const s3_str_t empty = {0, NULL};

    n = strlen(text);

    s3_memzero(&v, sizeof(v));

    rc = s3_ssh3_version_parse((const u_char *)text, n, &v);

    S3_ASSERT(rc == S3_OK);

    if (rc != S3_OK) {
        /* the fields stay zeroed, the memcmp below would be bogus */
        return s3_test_failures;
    }

    S3_ASSERT(v.protocol_major == major);
    S3_ASSERT(v.protocol_minor == minor);
    S3_ASSERT(s3_memcmp(v.implementation.data, impl, strlen(impl)) == 0);
    S3_ASSERT(v.implementation.len == strlen(impl));
    S3_ASSERT(v.software_major == sw_major);
    S3_ASSERT(v.software_minor == sw_minor);
    S3_ASSERT(v.software_patch == sw_patch);

    if (spec != NULL) {
        S3_ASSERT(v.spec_version.len == strlen(spec));
        S3_ASSERT(s3_memcmp(v.spec_version.data, spec, strlen(spec)) == 0);
    } else {
        S3_ASSERT(v.spec_version.len == empty.len);
    }

    return s3_test_failures;
}

static int
s3_test_parse_bad(const char *text)
{
    s3_ssh3_version_t v;

    s3_memzero(&v, sizeof(v));

    S3_ASSERT(s3_ssh3_version_parse((const u_char *)text, strlen(text), &v) != S3_OK);

    return s3_test_failures;
}

static int
s3_test_version_parse(void)
{
    /* the reference client string (conversation.go User-Agent) */

    (void)s3_test_parse_ok("SSH 3.0 francoismichel/ssh3 0.1.25"
                           " experimental_spec_version=alpha-00",
                           3, 0, "francoismichel/ssh3", 0, 1, 25, "alpha-00");

    /* the legacy four-field form carries the spec nowhere */

    (void)s3_test_parse_ok("SSH 3.0 francoismichel/ssh3 0.1.5", 3, 0, "francoismichel/ssh3", 0, 1,
                           5, NULL);

    /* the spec may ride inside the protocol field (major.minor_spec) */

    (void)s3_test_parse_ok("SSH 3.0_alpha-00 ssh3-c 0.1.0", 3, 0, "ssh3-c", 0, 1, 0, "alpha-00");

    /* unrecognized key=value extras are skipped, like the reference */

    (void)s3_test_parse_ok("SSH 3.0 ssh3-c 0.1.0 experimental_spec_version=alpha-00"
                           " custom=thing",
                           3, 0, "ssh3-c", 0, 1, 0, "alpha-00");

    /* multi-digit components and arbitrary implementation names */

    (void)s3_test_parse_ok("SSH 10.20 some-impl 1.2.345", 10, 20, "some-impl", 1, 2, 345, NULL);

    /* malformed: not enough fields, bad numbers, wrong shapes */

    (void)s3_test_parse_bad("");
    (void)s3_test_parse_bad("SSH");
    (void)s3_test_parse_bad("SSH 3.0");
    (void)s3_test_parse_bad("SSH 3.0 impl");         /* no software version */
    (void)s3_test_parse_bad("SSH x.0 impl 0.1.0");   /* non-numeric major */
    (void)s3_test_parse_bad("SSH 3.x impl 0.1.0");   /* non-numeric minor */
    (void)s3_test_parse_bad("SSH 3 impl 0.1.0");     /* no minor */
    (void)s3_test_parse_bad("SSH 3.0.1 impl 0.1.0"); /* three components */
    (void)s3_test_parse_bad("SSH 3.0 impl 0.1");     /* two software parts */
    (void)s3_test_parse_bad("SSH 3.0 impl 0.1.2.3"); /* four software parts */
    (void)s3_test_parse_bad("SSH 3.0 impl a.b.c");   /* non-numeric patch */
    (void)s3_test_parse_bad("SSH -1.0 impl 0.1.0");  /* sign is not a digit */
    (void)s3_test_parse_bad("SSH 3.0_ impl 0.1.0");  /* empty spec after _ */

    return s3_test_failures;
}

static int
s3_test_version_supported(void)
{
    static const char *yes[] = {
        "SSH 3.0 ssh3-c 0.1.0 experimental_spec_version=alpha-00",
        "SSH 3.0 francoismichel/ssh3 0.1.25 experimental_spec_version=alpha-00",
        "SSH 3.0 francoismichel/ssh3 0.1.3", /* the legacy floor */
        "SSH 3.0 francoismichel/ssh3 0.1.5", /* the legacy ceiling */
    };

    static const char *no[] = {
        "SSH 3.1 ssh3-c 0.1.0 experimental_spec_version=alpha-00", /* protocol minor */
        "SSH 2.0 ssh3-c 0.1.0 experimental_spec_version=alpha-00", /* protocol major */
        "SSH 3.0 francoismichel/ssh3 0.1.2",                       /* legacy below floor */
        "SSH 3.0 francoismichel/ssh3 0.2.5",                       /* legacy minor drift */
        "SSH 3.0 ssh3-c 0.1.0 experimental_spec_version=beta-01",  /* unknown spec */
        "SSH 3.0 ssh3-c 0.1.0", /* no spec: only the legacy impl passes */
    };

    s3_ssh3_version_t v;
    size_t            i;

    for (i = 0; i < sizeof(yes) / sizeof(yes[0]); i++) {
        s3_memzero(&v, sizeof(v));

        S3_ASSERT(s3_ssh3_version_parse((const u_char *)yes[i], strlen(yes[i]), &v) == S3_OK);
        S3_ASSERT(s3_ssh3_version_supported(&v) == S3_OK);
    }

    for (i = 0; i < sizeof(no) / sizeof(no[0]); i++) {
        s3_memzero(&v, sizeof(v));

        S3_ASSERT(s3_ssh3_version_parse((const u_char *)no[i], strlen(no[i]), &v) == S3_OK);
        S3_ASSERT(s3_ssh3_version_supported(&v) != S3_OK);
    }

    /* the announced string parses and is supported by itself */

    s3_memzero(&v, sizeof(v));

    S3_ASSERT(s3_ssh3_version_parse((const u_char *)S3_SSH3_VERSION_STRING,
                                    s3_strlen(S3_SSH3_VERSION_STRING), &v) == S3_OK);
    S3_ASSERT(s3_ssh3_version_supported(&v) == S3_OK);

    /* the announced literal stays in sync with the documented numbers */

    S3_ASSERT(v.protocol_major == S3_SSH3_PROTOCOL_MAJOR);
    S3_ASSERT(v.protocol_minor == S3_SSH3_PROTOCOL_MINOR);
    S3_ASSERT(s3_memcmp(v.implementation.data, S3_SSH3_IMPLEMENTATION_NAME,
                        s3_strlen(S3_SSH3_IMPLEMENTATION_NAME)) == 0);
    S3_ASSERT(v.software_major == S3_SSH3_SOFTWARE_MAJOR);
    S3_ASSERT(v.software_minor == S3_SSH3_SOFTWARE_MINOR);
    S3_ASSERT(v.software_patch == S3_SSH3_SOFTWARE_PATCH);
    S3_ASSERT(v.spec_version.len == s3_strlen(S3_SSH3_SPEC_VERSION));

    return s3_test_failures;
}

static int
s3_test_ssh3_version(void)
{
    (void)s3_test_version_parse();
    (void)s3_test_version_supported();

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_ssh3_version)
