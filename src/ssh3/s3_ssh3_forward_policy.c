/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the forward target policy, the PermitOpen analog (F-05): the
 * sshd_config PermitOpen spec, the port of the reference
 * cmd/forward_policy.go parsePermitOpen/allows/matchForwardHost
 */

#include <s3_core.h>

#include <string.h>

#include <s3_ssh3_forward_policy.h>

static s3_int_t s3_policy_parse_port(s3_ssh3_forward_policy_entry_t *e, const char *f,
                                     const char *fend);
static s3_int_t s3_policy_parse_entry(s3_ssh3_forward_policy_t *p, const char *f, const char *fend);
static unsigned s3_policy_host_match(const s3_ssh3_forward_policy_entry_t *e, const char *h,
                                     size_t hl);

void
s3_ssh3_forward_policy_init(s3_ssh3_forward_policy_t *p)
{
    /* the zero policy is the unrestricted one: n == 0 short-circuits
     * the check, like the nil of the reference */

    s3_memzero(p, sizeof(*p));
}

s3_int_t
s3_ssh3_forward_policy_parse(s3_ssh3_forward_policy_t *p, const char *spec)
{
    const char *pos, *end;

    s3_memzero(p, sizeof(*p));

    if (spec == NULL) {
        return S3_OK;
    }

    if (strlen(spec) >= S3_SSH3_FORWARD_POLICY_SPEC_MAX) {
        return S3_ERROR;
    }

    pos = spec;
    end = spec + strlen(spec);

    /* the outer whitespace is noise; the fields split on the commas,
     * the spaces and the tabs, the empty fields drop (the Go
     * TrimSpace + FieldsFunc shape) */

    while (pos < end && (*pos == ' ' || *pos == '\t' || *pos == ',')) {
        pos++;
    }

    while (end > pos && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == ',')) {
        end--;
    }

    while (pos < end) {

        const char *f, *fend;

        f = pos;

        while (pos < end && *pos != ' ' && *pos != '\t' && *pos != ',') {
            pos++;
        }

        fend = pos;

        /* the separators between the fields drop, the skip below
         * lands the cursor on the next field start */

        while (pos < end && (*pos == ' ' || *pos == '\t' || *pos == ',')) {
            pos++;
        }

        if (s3_policy_parse_entry(p, f, fend) != S3_OK) {
            return S3_ERROR;
        }
    }

    return S3_OK;
}

s3_int_t
s3_ssh3_forward_policy_check(const s3_ssh3_forward_policy_t *p, const char *host, uint16_t port)
{
    size_t   hl;
    unsigned i, matched, allowed, has_allow;

    if (p == NULL || p->n == 0) {

        /* the empty spec keeps the historical unrestricted default */

        return S3_OK;
    }

    hl = (host != NULL) ? strlen(host) : 0;

    matched = 0;
    allowed = 0;
    has_allow = 0;

    for (i = 0; i < p->n; i++) {
        const s3_ssh3_forward_policy_entry_t *e = &p->entries[i];

        /* the unmatched default allows only while the policy is the
         * negation-only shape (the reference hasAllowEntry walk) */

        if (!e->negated) {
            has_allow = 1;
        }

        if (!s3_policy_host_match(e, host, hl)) {
            continue;
        }

        if (!e->port_any && e->port != port) {
            continue;
        }

        matched = 1;

        if (e->negated) {

            /* a negated entry denies its own match the moment it
             * comes up, wherever it stands in the list */

            return S3_DECLINED;
        }

        allowed = 1;
    }

    if (!matched) {

        /* nothing matched: deny once an allow entry exists (the
         * allow-list shape), allow the pure-negation carve-out list */

        allowed = !has_allow;
    }

    return allowed ? S3_OK : S3_DECLINED;
}

static unsigned
s3_policy_host_match(const s3_ssh3_forward_policy_entry_t *e, const char *h, size_t hl)
{
    size_t dot;

    /* both sides are the canonical lowercase forms: the entry folded
     * at the parse, the target rides in as the inet_ntop output */

    if (e->host_len == 1 && e->host[0] == '*') {
        return 1;
    }

    if (e->host_len == hl && s3_memcmp(e->host, h, hl) == 0) {
        return 1;
    }

    /* the leading wildcard: "*.example.org" matches "a.b.example.org"
     * but not "example.org" itself (the sshd_config PATTERNS shape);
     * the compared view is the ".suffix" tail, the HasSuffix of the
     * reference */

    if (e->host_len >= 2 && e->host[0] == '*' && e->host[1] == '.') {
        dot = e->host_len - 1;

        if (hl >= dot && s3_memcmp(e->host + 1, h + (hl - dot), dot) == 0) {
            return 1;
        }
    }

    return 0;
}

static s3_int_t
s3_policy_parse_port(s3_ssh3_forward_policy_entry_t *e, const char *f, const char *fend)
{
    size_t   n = (size_t)(fend - f);
    size_t   i;
    unsigned v = 0;

    if (n == 1 && f[0] == '*') {
        e->port_any = 1;
        return S3_OK;
    }

    /* the Go ParseUint(port, 10, 16): the digits only, the uint16
     * range, the leading zeros fold into the value */

    if (n == 0 || n > 5) {
        return S3_ERROR;
    }

    for (i = 0; i < n; i++) {

        if (f[i] < '0' || f[i] > '9') {
            return S3_ERROR;
        }

        v = v * 10 + (unsigned)(f[i] - '0');
    }

    if (v > 65535) {
        return S3_ERROR;
    }

    e->port = (uint16_t)v;

    return S3_OK;
}

static s3_int_t
s3_policy_parse_entry(s3_ssh3_forward_policy_t *p, const char *f, const char *fend)
{
    s3_ssh3_forward_policy_entry_t *e;
    const char                     *host, *host_end, *port;
    u_char                         *dst;
    size_t                          host_len;

    if (p->n >= S3_SSH3_FORWARD_POLICY_MAX) {
        return S3_ERROR;
    }

    e = &p->entries[p->n];

    s3_memzero(e, sizeof(*e));

    if (f < fend && *f == '!') {
        e->negated = 1;
        f++;
    }

    if (f < fend && *f == '[') {

        /* the bracketed ipv6 literal ([2001:db8::1]:443): the
         * first-colon cut of the bare form would land inside the
         * address, the brackets fence it (the reference spec cannot
         * express ipv6 at all, this is the sshd bracket shape) */

        host = f + 1;
        host_end = memchr(host, ']', (size_t)(fend - host));

        if (host_end == NULL || fend - host_end < 3 || host_end[1] != ':') {
            return S3_ERROR;
        }

        port = host_end + 2;

    } else {

        /* the plain host:port, the first colon cuts (the Go
         * strings.Cut shape) */

        host = f;
        host_end = memchr(f, ':', (size_t)(fend - f));

        if (host_end == NULL) {
            return S3_ERROR;
        }

        port = host_end + 1;
    }

    /* the host and the port must both be non-empty */

    if (host == host_end || port == fend) {
        return S3_ERROR;
    }

    host_len = (size_t)(host_end - host);

    if (host_len > S3_SSH3_FORWARD_POLICY_HOST_MAX) {
        return S3_ERROR;
    }

    for (dst = e->host; host < host_end; host++, dst++) {

        /* the ascii fold only: the spec is the config text, the
         * canonical forms (the inet_ntop output, the dns names) live
         * in the lowercase ascii anyway */

        *dst = (u_char)((*host >= 'A' && *host <= 'Z') ? *host + 32 : *host);
    }

    e->host_len = host_len;

    if (s3_policy_parse_port(e, port, fend) != S3_OK) {
        return S3_ERROR;
    }

    p->n++;

    return S3_OK;
}
