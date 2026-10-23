/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the reverse port forwarding (-R) wire, the port of the reference
 * cmd/reverse_forward.go parseReverseForwardSpec and
 * message/reverse_forward.go RequestReverseForward/ReverseForwardReply
 */

#include <s3_core.h>

#if (S3_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#endif

#include <stdio.h>

#include <s3_ssh3_reverse.h>
#include <s3_ssh3_wire.h>

/*
 * the part count of the -R spec: the three-part form carries the
 * bind in the first part, the four-part one names the bind address
 */

#define S3_SSH3_REVERSE_PARTS_BIND_PORT 3
#define S3_SSH3_REVERSE_PARTS_FULL      4

/*
 * the port parse sentinel: 65536 is outside the wire range, every
 * legal port parses below it
 */

#define S3_SSH3_REVERSE_PORT_BAD 0x10000u

static const char *s3_reverse_spec_part(const char **pos, const char *end, const char **fend,
                                        size_t *host_len);
static unsigned    s3_reverse_port_parse(const char *f, const char *fend);
static void        s3_reverse_spec_unbracket(const char **f, size_t *len);
static unsigned    s3_reverse_host_printable(const char *f, size_t len);

/*
 * one colon-separated part of the spec, the colons inside the ipv6
 * brackets stay in (the reference splitOutsideBrackets); *pos lands
 * past the separator (or end), the part rides [f, *fend)
 */

static const char *
s3_reverse_spec_part(const char **pos, const char *end, const char **fend, size_t *host_len)
{
    const char *f = *pos;
    const char *p = *pos;
    unsigned    in_brackets = 0;

    while (p < end) {

        if (*p == '[') {
            in_brackets = 1;

        } else if (*p == ']') {
            in_brackets = 0;

        } else if (*p == ':' && !in_brackets) {
            break;
        }

        p++;
    }

    *fend = p;
    *host_len = (size_t)(p - f);
    *pos = (p < end) ? p + 1 : end;

    return f;
}

/*
 * the port text of the reference parsePort: the decimal digits only,
 * the uint16 range, an empty or a signed text refuses
 */

static unsigned
s3_reverse_port_parse(const char *f, const char *fend)
{
    size_t   n = (size_t)(fend - f);
    size_t   i;
    unsigned v = 0;

    if (n == 0 || n > 5) {
        return S3_SSH3_REVERSE_PORT_BAD;
    }

    for (i = 0; i < n; i++) {

        if (f[i] < '0' || f[i] > '9') {
            return S3_SSH3_REVERSE_PORT_BAD;
        }

        v = v * 10 + (unsigned)(f[i] - '0');
    }

    if (v > 65535) {
        return S3_SSH3_REVERSE_PORT_BAD;
    }

    return v;
}

/*
 * the bracketed ipv6 literal drops its fences; the host copy is
 * bounded by the caller
 */

static void
s3_reverse_spec_unbracket(const char **f, size_t *len)
{
    if (*len >= 2 && (*f)[0] == '[' && (*f)[*len - 1] == ']') {
        (*f)++;
        *len -= 2;
    }
}

/*
 * the host text of the spec: the ASCII printable only.  the bind
 * address rides the wire verbatim and the server logs it as it
 * stands (the reason of a refusal rides the reply), so a control
 * character in the spec would reach the server log as a terminal
 * escape - and a raw 8-bit byte has no business in a bind address
 * either (the B15 audit tail) - the fail-closed rule refuses the
 * spec before anything is sent (the reference parser keeps the same
 * plain-text shape)
 */

static unsigned
s3_reverse_host_printable(const char *f, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {

        u_char c = (u_char)f[i];

        if (c < 0x20 || c > 0x7e) {
            return 0;
        }
    }

    return 1;
}

s3_int_t
s3_ssh3_reverse_parse_spec(const char *text, s3_ssh3_reverse_spec_t *out)
{
    const char *pos, *end;
    const char *parts[S3_SSH3_REVERSE_PARTS_FULL];
    size_t      lens[S3_SSH3_REVERSE_PARTS_FULL];
    unsigned    n_parts, proto;
    size_t      bind_len, target_len;
    const char *bind_f, *target_f, *port_f, *port_end;

    if (text == NULL || out == NULL) {
        return S3_ERROR;
    }

    s3_memzero(out, sizeof(*out));

    pos = text;
    end = text + strlen(text);

    n_parts = 0;

    while (n_parts < S3_SSH3_REVERSE_PARTS_FULL) {

        size_t len;

        parts[n_parts] = s3_reverse_spec_part(&pos, end, &port_f, &len);

        lens[n_parts] = len;
        n_parts++;

        if (pos == end) {
            break;
        }
    }

    if (pos != end ||
        (n_parts != S3_SSH3_REVERSE_PARTS_BIND_PORT && n_parts != S3_SSH3_REVERSE_PARTS_FULL)) {
        return S3_ERROR;
    }

    /* the bind host: the first part of the four-part form, the empty
     * host keeps the server default; the "*" wildcard maps to the "::"
     * bind (the reference parseReverseForwardSpec) */

    bind_f = parts[0];
    bind_len = lens[0];
    port_f = parts[0];

    if (n_parts == S3_SSH3_REVERSE_PARTS_FULL) {
        port_f = parts[1];
    }

    /* the /tcp|/udp suffix after the bind port selects the protocol,
     * the bare port is the tcp; the suffix may cut the port text
     * short */

    proto = S3_SSH3_REVERSE_PROTO_TCP;

    port_end = port_f + lens[n_parts == S3_SSH3_REVERSE_PARTS_FULL ? 1 : 0];

    {
        const char *q = port_f;

        while (q < port_end) {

            if (*q == '/') {
                break;
            }

            q++;
        }

        if (q < port_end) {

            size_t suffix_len = (size_t)(port_end - q - 1);

            if (suffix_len == 3 && s3_memcmp(q + 1, "udp", 3) == 0) {
                proto = S3_SSH3_REVERSE_PROTO_UDP;

            } else if (suffix_len != 3 || s3_memcmp(q + 1, "tcp", 3) != 0) {
                return S3_ERROR;
            }

            port_end = q;
        }
    }

    {
        unsigned v = s3_reverse_port_parse(port_f, port_end);

        if (v == S3_SSH3_REVERSE_PORT_BAD) {
            return S3_ERROR;
        }

        out->bind_port = (uint16_t)v;
    }

    /* the target: the last two parts, the host without the brackets */

    target_f = parts[n_parts - 2];
    target_len = lens[n_parts - 2];

    s3_reverse_spec_unbracket(&target_f, &target_len);

    if (target_len == 0 || target_len > S3_SSH3_REVERSE_HOST_MAX) {
        return S3_ERROR;
    }

    if (!s3_reverse_host_printable(target_f, target_len)) {
        return S3_ERROR;
    }

    s3_memcpy(out->target_host, target_f, target_len);
    out->target_host[target_len] = '\0';

    {
        unsigned v =
            s3_reverse_port_parse(parts[n_parts - 1], parts[n_parts - 1] + lens[n_parts - 1]);

        if (v == S3_SSH3_REVERSE_PORT_BAD || v == 0) {

            /* the target port may not be 0 (the reference gate) */

            return S3_ERROR;
        }

        out->target_port = (uint16_t)v;
    }

    /* the bind host: the unbracketed text rides the spec verbatim,
     * the "*" maps to the "::" wildcard, the empty host keeps the
     * server default */

    if (n_parts == S3_SSH3_REVERSE_PARTS_FULL) {
        s3_reverse_spec_unbracket(&bind_f, &bind_len);
    }

    if (n_parts == S3_SSH3_REVERSE_PARTS_FULL && bind_len > 0) {

        if (bind_len == 1 && bind_f[0] == '*') {
            out->bind_host[0] = ':';
            out->bind_host[1] = ':';
            out->bind_host[2] = '\0';

        } else {

            if (bind_len > S3_SSH3_REVERSE_HOST_MAX) {
                return S3_ERROR;
            }

            if (!s3_reverse_host_printable(bind_f, bind_len)) {
                return S3_ERROR;
            }

            s3_memcpy(out->bind_host, bind_f, bind_len);
            out->bind_host[bind_len] = '\0';
        }
    }

    out->proto = proto;

    return S3_OK;
}

s3_int_t
s3_ssh3_reverse_resolve_target(const s3_ssh3_reverse_spec_t *spec, s3_ssh3_forward_target_t *target)
{
    struct addrinfo hints, *res = NULL;
    struct in_addr  a4;
    struct in6_addr a6;
    char            port_text[6];

    if (spec == NULL || target == NULL || spec->target_host[0] == '\0' || spec->target_port == 0) {
        return S3_ERROR;
    }

    s3_memzero(target, sizeof(*target));

    /* the ip literals take the fast path, the names ride getaddrinfo
     * (the resolution of the reference client) */

    if (inet_pton(AF_INET, spec->target_host, &a4) == 1) {

        target->family = 4;
        target->ip_len = 4;
        s3_memcpy(target->ip, &a4, 4);
        target->port = spec->target_port;

        return S3_OK;
    }

    if (inet_pton(AF_INET6, spec->target_host, &a6) == 1) {

        target->family = 6;
        target->ip_len = 16;
        s3_memcpy(target->ip, &a6, 16);
        target->port = spec->target_port;

        return S3_OK;
    }

    s3_memzero(&hints, sizeof(hints));

    /*
     * the names resolve over AF_INET (the canon of the direct forward
     * path: the target of a forward is an ipv4 socket here): a name
     * that only carries an AAAA record refuses instead of resolving
     * into an address the ipv4-only bridge cannot dial
     */

    hints.ai_family = AF_INET;
    hints.ai_socktype = (spec->proto == S3_SSH3_REVERSE_PROTO_UDP) ? SOCK_DGRAM : SOCK_STREAM;

    if (snprintf(port_text, sizeof(port_text), "%u", (unsigned)spec->target_port) <= 0) {
        return S3_ERROR;
    }

    if (getaddrinfo(spec->target_host, port_text, &hints, &res) != 0 || res == NULL) {
        return S3_ERROR;
    }

    if (res->ai_family == AF_INET && res->ai_addrlen >= sizeof(struct sockaddr_in)) {

        const struct sockaddr_in *sa = (const struct sockaddr_in *)res->ai_addr;

        target->family = 4;
        target->ip_len = 4;
        s3_memcpy(target->ip, &sa->sin_addr, 4);

    } else if (res->ai_family == AF_INET6 && res->ai_addrlen >= sizeof(struct sockaddr_in6)) {

        const struct sockaddr_in6 *sa = (const struct sockaddr_in6 *)res->ai_addr;

        target->family = 6;
        target->ip_len = 16;
        s3_memcpy(target->ip, &sa->sin6_addr, 16);

    } else {
        freeaddrinfo(res);
        return S3_ERROR;
    }

    target->port = spec->target_port;

    freeaddrinfo(res);

    return S3_OK;
}

size_t
s3_ssh3_reverse_request_size(const s3_ssh3_reverse_request_t *r)
{
    return s3_ssh3_varint_size((uint64_t)r->proto) + s3_ssh3_sshstring_size(r->bind_address.len) +
           2 + s3_ssh3_sshstring_size(r->target_address.len) + 2;
}

u_char *
s3_ssh3_reverse_build_request(u_char *p, const s3_ssh3_reverse_request_t *r)
{
    if (p == NULL || r == NULL) {
        return NULL;
    }

    p = s3_ssh3_encode_varint(p, (uint64_t)r->proto);
    p = s3_ssh3_encode_sshstring(p, r->bind_address.data, r->bind_address.len);

    /* the two port fields are the uint16 big-endian */

    *p++ = (u_char)(r->bind_port >> 8);
    *p++ = (u_char)(r->bind_port & 0xff);

    p = s3_ssh3_encode_sshstring(p, r->target_address.data, r->target_address.len);

    *p++ = (u_char)(r->target_port >> 8);
    *p++ = (u_char)(r->target_port & 0xff);

    return p;
}

s3_int_t
s3_ssh3_reverse_parse_request(const u_char **pos, const u_char *end, s3_ssh3_reverse_request_t *out)
{
    const u_char *p = *pos;
    uint64_t      proto;

    if (s3_ssh3_parse_varint(&p, end, &proto) != S3_OK) {
        return S3_ERROR;
    }

    /* the protocol gate of the reference parser: only the udp 0 and
     * the tcp 1 exist */

    if (proto != S3_SSH3_REVERSE_PROTO_UDP && proto != S3_SSH3_REVERSE_PROTO_TCP) {
        return S3_ERROR;
    }

    if (s3_ssh3_parse_sshstring(&p, end, &out->bind_address) != S3_OK) {
        return S3_ERROR;
    }

    if (end - p < 2) {
        return S3_ERROR;
    }

    out->bind_port = (uint16_t)(((unsigned)p[0] << 8) | p[1]);
    p += 2;

    if (s3_ssh3_parse_sshstring(&p, end, &out->target_address) != S3_OK) {
        return S3_ERROR;
    }

    if (end - p < 2) {
        return S3_ERROR;
    }

    out->target_port = (uint16_t)(((unsigned)p[0] << 8) | p[1]);
    p += 2;

    out->proto = (unsigned)proto;
    *pos = p;

    return S3_OK;
}

size_t
s3_ssh3_reverse_reply_size(const s3_ssh3_reverse_reply_t *r)
{
    return 2 + s3_ssh3_sshstring_size(r->error_utf8.len);
}

u_char *
s3_ssh3_reverse_build_reply(u_char *p, const s3_ssh3_reverse_reply_t *r)
{
    if (p == NULL || r == NULL) {
        return NULL;
    }

    *p++ = (u_char)(r->bound_port >> 8);
    *p++ = (u_char)(r->bound_port & 0xff);

    /* the error string always rides (the empty string is the success
     * marker, the reference writer) */

    p = s3_ssh3_encode_sshstring(p, r->error_utf8.data, r->error_utf8.len);

    return p;
}

s3_int_t
s3_ssh3_reverse_parse_reply(const u_char **pos, const u_char *end, s3_ssh3_reverse_reply_t *out)
{
    const u_char *p = *pos;

    if (end - p < 2) {
        return S3_ERROR;
    }

    out->bound_port = (uint16_t)(((unsigned)p[0] << 8) | p[1]);
    p += 2;

    /* the error string may ride empty (the success) or as the reason;
     * the reference parser tolerates its absence (io.EOF), the
     * comment of the test keeps the strict form here: the writers of
     * both sides always emit it */

    if (s3_ssh3_parse_sshstring(&p, end, &out->error_utf8) != S3_OK) {
        return S3_ERROR;
    }

    *pos = p;

    return S3_OK;
}

unsigned
s3_ssh3_reverse_reply_ok(const s3_ssh3_reverse_reply_t *r)
{
    return (r->error_utf8.len == 0) ? 1 : 0;
}

s3_int_t
s3_ssh3_reverse_target_ntop(const s3_ssh3_forward_target_t *t, char *buf, size_t len)
{
    if (t == NULL || buf == NULL) {
        return S3_ERROR;
    }

    if (t->family == 4 && t->ip_len == 4) {

        if (len < INET_ADDRSTRLEN) {
            return S3_ERROR;
        }

        if (inet_ntop(AF_INET, t->ip, buf, (socklen_t)len) == NULL) {
            return S3_ERROR;
        }

        return S3_OK;
    }

    if (t->family == 6 && t->ip_len == 16) {

        if (len < INET6_ADDRSTRLEN) {
            return S3_ERROR;
        }

        if (inet_ntop(AF_INET6, t->ip, buf, (socklen_t)len) == NULL) {
            return S3_ERROR;
        }

        return S3_OK;
    }

    return S3_ERROR;
}
