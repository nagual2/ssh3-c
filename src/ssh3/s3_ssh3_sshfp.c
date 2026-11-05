/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the SSHFP (RFC 4255) verification of the host certificate, the
 * port of the reference sshfp.go (plus the resolver seams of
 * cmd/sshfp_resolver.go and cmd/sshfp_dns_windows.go): the raw UDP
 * DNS exchange, the wire building and parsing, and the verdict.
 *
 * the verdict is mismatch-only-fatal (the reference CheckSSHFP): a
 * missing answer -- no records, NXDOMAIN, a timeout, a truncated or
 * broken datagram, an unreachable resolver -- is a soft status and
 * never a rejection, only a published set of records with no match
 * reads as the MITM signal.
 *
 * the DNS server list resolves per call: the env S3_SSHFP_DNS first
 * (a comma-separated host[:port] list, the e2e test hook, the default
 * port 53), then the system configuration -- /etc/resolv.conf on unix
 * (the nameserver lines), GetAdaptersAddresses on windows (the
 * adapters are exactly what the Windows resolver itself uses).
 *
 * the winsock of this module expects the WSAStartup of s3_os_init()
 * (the tests bootstrap their own).
 */

#if (S3_WIN32)

/* GetAdaptersAddresses is an xp+ api, the headers gate it behind the
 * windows version macros; the tree leaves the mingw defaults in place */

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#endif

#include <s3_core.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include <stdio.h>

#if (S3_WIN32)

#include <iphlpapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#else

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#endif

#include <s3_sock_ntop.h>
#include <s3_ssh3_sshfp.h>

/* the answer records the verdict matches against; a set beyond the
 * cap only ever makes the verdict stricter (a dropped tail record can
 * turn a match into a mismatch, never the reverse) */

#define S3_SSHFP_RECORDS_MAX 16

/* the system resolver list of unix (no windows file carries it) */

#define S3_SSHFP_RESOLV_CONF "/etc/resolv.conf"

/* the GetAdaptersAddresses buffer of the first call, the windows
 * port of initialDNSServersBufferSize; the api reports the size it
 * needs on the overflow and the call retries */

#define S3_SSHFP_ADAPTER_BUF_MIN (15 * 1024)

/* the header flags the exchange cares about: the QR bit marks an
 * answer, the RD bit rides the query, the TC bit says the answer was
 * cut by the datagram size (no TCP retry here, the reference soft
 * path) */

#define S3_SSHFP_DNS_FLAG_RESPONSE 0x8000u
#define S3_SSHFP_DNS_FLAG_RD       0x0100u
#define S3_SSHFP_DNS_FLAG_TC       0x0200u

/* the query name buffer of the module (the reverse names of an ipv6
 * literal run to 73 octets, a host name to 255) */

#define S3_SSHFP_NAME_BUF 256

typedef struct {
    char   servers[S3_SSHFP_SERVERS_MAX][S3_SSHFP_SERVER_TEXT_MAX];
    size_t count;
} s3_sshfp_servers_t;

/* the exchange outcome: the records are in, the host publishes
 * nothing (authoritative, final), or this server must be left for
 * the next one (the reason text carries the last failure) */

#define S3_SSHFP_EXCH_RECORDS 0
#define S3_SSHFP_EXCH_NORECS  1
#define S3_SSHFP_EXCH_NEXT    2

static void     s3_sshfp_err(char *errbuf, size_t cap, const char *text);
static s3_int_t s3_sshfp_name_encode(const char *name, u_char *enc, size_t cap, size_t *len);
static s3_int_t s3_sshfp_name_skip(const u_char *msg, size_t len, size_t *offp);
static void     s3_sshfp_servers_add(s3_sshfp_servers_t *out, const char *addr, size_t len);
static void     s3_sshfp_servers_env(s3_sshfp_servers_t *out);
#if !S3_WIN32
static void s3_sshfp_servers_resolv_conf(s3_sshfp_servers_t *out);
static void s3_sshfp_resolv_line(const char *line, s3_sshfp_servers_t *out);
#else
static void s3_sshfp_servers_adapters(s3_pool_t *pool, s3_sshfp_servers_t *out);
#endif
static void     s3_sshfp_servers_system(s3_pool_t *pool, s3_sshfp_servers_t *out);
static s3_int_t s3_sshfp_server_split(const char *server, char *host, size_t host_cap,
                                      unsigned *port);
static int      s3_sshfp_exchange(const char *server, const u_char *query, size_t qlen, uint16_t id,
                                  s3_pool_t *pool, s3_sshfp_rec_t *recs, size_t *nrecs, char *reason,
                                  size_t reason_cap);
static void     s3_sshfp_close_fd(int fd);
static const char *s3_sshfp_reverse_name(const u_char *ip, unsigned v6, char *buf, size_t cap);

/*
 * the failure text of a lookup, a no-op when the caller passes no
 * buffer (the diagnostic is optional everywhere)
 */

static void
s3_sshfp_err(char *errbuf, size_t cap, const char *text)
{
    if (errbuf != NULL && cap > 0) {
        snprintf(errbuf, cap, "%s", text);
    }
}

/*
 * the dotted name into the length-prefixed label sequence with the
 * zero terminator (the reference encodeDNSName): the trailing dot
 * drops, an empty label, a label over 63 octets and a name over the
 * wire maximum refuse
 */

static s3_int_t
s3_sshfp_name_encode(const char *name, u_char *enc, size_t cap, size_t *len)
{
    const char *p, *end, *sep;
    size_t      n = 0;

    p = name;
    end = name + strlen(name);

    /* one trailing dot is the root form of a fqdn, not a label */

    if (end > p && end[-1] == '.') {
        end--;
    }

    if (p == end) {
        return S3_ERROR;
    }

    while (p < end) {

        sep = memchr(p, '.', (size_t)(end - p));

        if (sep == NULL) {
            sep = end;
        }

        {
            size_t label_len = (size_t)(sep - p);

            if (label_len == 0 || label_len > 63 || n + 1 + label_len + 1 > cap) {
                return S3_ERROR;
            }

            enc[n++] = (u_char)label_len;
            s3_memcpy(enc + n, p, label_len);
            n += label_len;
        }

        p = sep + 1;
    }

    enc[n++] = 0;

    if (n > S3_SSHFP_DNS_NAME_MAX) {
        return S3_ERROR;
    }

    *len = n;

    return S3_OK;
}

s3_int_t
s3_sshfp_query_build(uint16_t id, const char *name, u_char *buf, size_t cap, size_t *out_len)
{
    u_char  enc[S3_SSHFP_DNS_NAME_MAX + 2];
    size_t  enc_len, total;
    u_char *p;

    if (name == NULL || buf == NULL || out_len == NULL) {
        return S3_ERROR;
    }

    if (s3_sshfp_name_encode(name, enc, sizeof(enc), &enc_len) != S3_OK) {
        return S3_ERROR;
    }

    total = S3_SSHFP_DNS_HEADER_SIZE + enc_len + 4;

    if (cap < total) {
        return S3_ERROR;
    }

    p = buf;

    *p++ = (u_char)(id >> 8);
    *p++ = (u_char)(id & 0xff);
    *p++ = (u_char)(S3_SSHFP_DNS_FLAG_RD >> 8);
    *p++ = (u_char)(S3_SSHFP_DNS_FLAG_RD & 0xff);
    *p++ = 0; /* QDCOUNT = 1 */
    *p++ = 1;
    *p++ = 0; /* ANCOUNT */
    *p++ = 0;
    *p++ = 0; /* NSCOUNT */
    *p++ = 0;
    *p++ = 0; /* ARCOUNT */
    *p++ = 0;

    s3_memcpy(p, enc, enc_len);
    p += enc_len;

    *p++ = (u_char)(S3_SSHFP_DNS_TYPE_SSHFP >> 8);
    *p++ = (u_char)(S3_SSHFP_DNS_TYPE_SSHFP & 0xff);
    *p++ = (u_char)(S3_SSHFP_DNS_CLASS_IN >> 8);
    *p++ = (u_char)(S3_SSHFP_DNS_CLASS_IN & 0xff);

    *out_len = total;

    return S3_OK;
}

/*
 * one (possibly compressed) name of an answer: the walk follows the
 * labels and the compression pointers for the bounds only -- the
 * record selection matches on the type and the class, the name text
 * itself is never used (the reference decodes it and drops it); the
 * offset just past the name in the enclosing record lands back in
 * *offp.  the pointer count is capped, the reserved label types
 * refuse, everything past the message refuses
 */

static s3_int_t
s3_sshfp_name_skip(const u_char *msg, size_t len, size_t *offp)
{
    size_t   off = *offp;
    size_t   next = 0;
    unsigned jumps = 0;
    unsigned have_next = 0;

    for (;;) {

        unsigned length;

        if (off >= len) {
            return S3_ERROR;
        }

        length = msg[off];

        if ((length & 0xc0) == 0x00) {

            if (length == 0) {

                /* the root label ends the name */

                if (!have_next) {
                    next = off + 1;
                }

                *offp = next;

                return S3_OK;
            }

            off++;

            if (off + length > len) {
                return S3_ERROR;
            }

            off += length;

        } else if ((length & 0xc0) == 0xc0) {

            if (off + 1 >= len) {
                return S3_ERROR;
            }

            if (!have_next) {
                next = off + 2;
                have_next = 1;
            }

            jumps++;

            if (jumps > S3_SSHFP_DNS_POINTERS_MAX) {
                return S3_ERROR;
            }

            off = (size_t)(((unsigned)(msg[off] & 0x3f) << 8) | msg[off + 1]);

        } else {

            /* the 0x40 and 0x80 label types do not exist here */

            return S3_ERROR;
        }
    }
}

s3_int_t
s3_sshfp_response_parse(const u_char *msg, size_t len, s3_pool_t *pool, s3_sshfp_rec_t *recs,
                        size_t *nrecs, uint8_t *rcode)
{
    unsigned flags, qdcount, ancount, i;
    size_t   off, cap;

    if (msg == NULL || pool == NULL || recs == NULL || nrecs == NULL || rcode == NULL) {
        return S3_ERROR;
    }

    cap = *nrecs;
    *nrecs = 0;
    *rcode = 0;

    if (len < S3_SSHFP_DNS_HEADER_SIZE) {
        return S3_ERROR;
    }

    flags = ((unsigned)msg[2] << 8) | msg[3];
    *rcode = (uint8_t)(flags & 0x0f);

    qdcount = ((unsigned)msg[4] << 8) | msg[5];
    ancount = ((unsigned)msg[6] << 8) | msg[7];

    off = S3_SSHFP_DNS_HEADER_SIZE;

    /* the question section rides past: a name and the fixed pair of
     * the type and the class per question */

    for (i = 0; i < qdcount; i++) {

        if (s3_sshfp_name_skip(msg, len, &off) != S3_OK) {
            return S3_ERROR;
        }

        off += 4;
    }

    if (off > len) {
        return S3_ERROR;
    }

    for (i = 0; i < ancount; i++) {

        uint16_t rr_type, rr_class, rdlength;

        if (s3_sshfp_name_skip(msg, len, &off) != S3_OK) {
            return S3_ERROR;
        }

        if (off + 10 > len) {
            return S3_ERROR;
        }

        rr_type = (uint16_t)(((unsigned)msg[off] << 8) | msg[off + 1]);
        rr_class = (uint16_t)(((unsigned)msg[off + 2] << 8) | msg[off + 3]);
        rdlength = (uint16_t)(((unsigned)msg[off + 8] << 8) | msg[off + 9]);

        off += 10;

        if (off + rdlength > len) {
            return S3_ERROR;
        }

        if (rr_type == S3_SSHFP_DNS_TYPE_SSHFP && rr_class == S3_SSHFP_DNS_CLASS_IN &&
            rdlength >= 2) {
            if (*nrecs < cap) {

                s3_sshfp_rec_t *rec = &recs[*nrecs];

                rec->algorithm = msg[off];
                rec->digest_type = msg[off + 1];
                rec->fp_len = (size_t)rdlength - 2;
                rec->fingerprint = s3_pnalloc(pool, rec->fp_len);

                if (rec->fingerprint == NULL) {
                    return S3_ERROR;
                }

                s3_memcpy(rec->fingerprint, msg + off + 2, rec->fp_len);

                (*nrecs)++;
            }

            /* a record set beyond the cap is dropped: the verdict
             * stays fail-closed (see S3_SSHFP_RECORDS_MAX) */
        }

        off += rdlength;
    }

    return S3_OK;
}

/*
 * the hex digit of a reverse nibble, the lowercase form of the
 * reference strconv.FormatUint(nibble, 16)
 */

#define S3_SSHFP_HEX(c) ((u_char)((c) < 10 ? '0' + (c) : 'a' + (c) - 10))

/*
 * the reverse-mapping name of an ip literal (RFC 4255 3): the four
 * octets of the v4 in the wire order, the 32 nibbles of the v6 from
 * the last byte backwards
 */

static const char *
s3_sshfp_reverse_name(const u_char *ip, unsigned v6, char *buf, size_t cap)
{
    size_t n = 0;

    if (!v6) {
        int rc = snprintf(buf, cap, "%u.%u.%u.%u.in-addr.arpa", ip[3], ip[2], ip[1], ip[0]);

        return (rc > 0 && (size_t)rc < cap) ? buf : NULL;
    }

    {
        int i;

        for (i = 15; i >= 0; i--) {

            if (n + 4 >= cap) {
                return NULL;
            }

            buf[n++] = S3_SSHFP_HEX(ip[i] & 0x0f);
            buf[n++] = '.';
            buf[n++] = S3_SSHFP_HEX(ip[i] >> 4);
            buf[n++] = '.';
        }
    }

    if (n + sizeof("ip6.arpa") > cap) {
        return NULL;
    }

    s3_memcpy(buf + n, "ip6.arpa", sizeof("ip6.arpa"));

    return buf;
}

/*
 * the hostname charset of the derived name: the letters, the digits,
 * the hyphen, the dot and the underscore.  a leftover colon (a bare
 * "host:port" the split refused, an ipv6 the literal parse rejected),
 * a space or any control character is garbage the reference would
 * carry into the query verbatim -- the fail-closed rule refuses it
 * before the query is built
 */

static unsigned
s3_sshfp_name_charset(const char *name)
{
    const char *p;

    for (p = name; *p != '\0'; p++) {

        u_char c = (u_char)*p;

        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '-' || c == '.' || c == '_')) {
            return 0;
        }
    }

    return 1;
}

s3_int_t
s3_sshfp_query_name(const char *hostkey, char *buf, size_t cap)
{
    const char *p, *end;
    char        name[S3_SSHFP_NAME_BUF];
    size_t      n;

    if (hostkey == NULL || buf == NULL) {
        return S3_ERROR;
    }

    /* the leading and the trailing whitespace of the key */

    p = hostkey;

    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' || *p == '\v' || *p == '\f') {
        p++;
    }

    n = strlen(p);

    while (n > 0 && (p[n - 1] == ' ' || p[n - 1] == '\t' || p[n - 1] == '\r' || p[n - 1] == '\n' ||
                     p[n - 1] == '\v' || p[n - 1] == '\f')) {
        n--;
    }

    if (n == 0) {
        return S3_ERROR;
    }

    end = p + n;

    /* the url path and any query or fragment are not part of the host */

    {
        const char *cut = p;

        while (cut < end && *cut != '/' && *cut != '?' && *cut != '#') {
            cut++;
        }

        end = cut;
    }

    n = (size_t)(end - p);

    if (n >= sizeof(name)) {
        return S3_ERROR;
    }

    s3_memcpy(name, p, n);
    name[n] = '\0';

    if (name[0] == '[') {

        /* the bracketed ipv6 literal: everything up to the closing
         * fence, the port outside the brackets never enters */

        char *close = strchr(name + 1, ']');

        if (close == NULL) {
            return S3_ERROR;
        }

        *close = '\0';
        memmove(name, name + 1, (size_t)(close - name));

    } else {

        /* the host:port form: the split lands on the last colon when
         * both sides are colon-free (the reference SplitHostPort); a
         * bare ipv6 literal carries several colons and stays whole --
         * the literal parse below maps it */

        char *last = strrchr(name, ':');

        if (last != NULL && strchr(name, ':') == last && last > name) {
            *last = '\0';
        }
    }

    /* the trailing dot of a fqdn */

    n = strlen(name);

    if (n > 0 && name[n - 1] == '.') {
        name[n - 1] = '\0';
        n--;
    }

    if (n == 0) {
        return S3_ERROR;
    }

    {
        struct in_addr  a4;
        struct in6_addr a6;

        if (inet_pton(AF_INET, name, &a4) == 1) {

            if (s3_sshfp_reverse_name((const u_char *)&a4, 0, buf, cap) == NULL) {
                return S3_ERROR;
            }

            return S3_OK;
        }

        if (inet_pton(AF_INET6, name, &a6) == 1) {

            if (s3_sshfp_reverse_name((const u_char *)&a6, 1, buf, cap) == NULL) {
                return S3_ERROR;
            }

            return S3_OK;
        }
    }

    /* a plain host name rides lowercased */

    {
        char *q;

        for (q = name; *q != '\0'; q++) {

            if (*q >= 'A' && *q <= 'Z') {
                *q = (char)(*q - 'A' + 'a');
            }
        }
    }

    if (!s3_sshfp_name_charset(name)) {
        return S3_ERROR;
    }

    if (n + 1 > cap) {
        return S3_ERROR;
    }

    s3_memcpy(buf, name, n + 1);

    return S3_OK;
}

s3_int_t
s3_sshfp_digest(uint8_t digest_type, const u_char *der, size_t der_len, u_char *out,
                size_t *out_len)
{
    const EVP_MD *md;
    unsigned      n;

    if (der == NULL || out == NULL || out_len == NULL) {
        return S3_ERROR;
    }

    switch (digest_type) {

    case S3_SSHFP_DIGEST_SHA1:
        md = EVP_sha1();
        break;

    case S3_SSHFP_DIGEST_SHA256:
        md = EVP_sha256();
        break;

    default:
        return S3_ERROR;
    }

    if (EVP_Digest(der, der_len, out, &n, md, NULL) != 1) {
        return S3_ERROR;
    }

    *out_len = n;

    return S3_OK;
}

uint8_t
s3_sshfp_key_algorithm(X509 *cert)
{
    EVP_PKEY *pkey;

    if (cert == NULL) {
        return S3_SSHFP_ALGO_RESERVED;
    }

    pkey = X509_get0_pubkey(cert);

    if (pkey == NULL) {
        return S3_SSHFP_ALGO_RESERVED;
    }

    switch (EVP_PKEY_base_id(pkey)) {

    case EVP_PKEY_RSA:
        return S3_SSHFP_ALGO_RSA;

    case EVP_PKEY_EC:
        return S3_SSHFP_ALGO_ECDSA;

    case EVP_PKEY_ED25519:
        return S3_SSHFP_ALGO_ED25519;

    default:

        /* the dsa and the rest have no publishable sshfp number */

        return S3_SSHFP_ALGO_RESERVED;
    }
}

unsigned
s3_sshfp_rec_matches(const s3_sshfp_rec_t *rec, uint8_t algo, const u_char *der, size_t der_len)
{
    u_char digest[32];
    size_t dlen;

    if (rec == NULL || rec->algorithm != algo) {
        return 0;
    }

    /* the fingerprint must carry the length the digest type implies
     * (the reference Valid) */

    switch (rec->digest_type) {

    case S3_SSHFP_DIGEST_SHA1:
        if (rec->fp_len != 20) {
            return 0;
        }
        break;

    case S3_SSHFP_DIGEST_SHA256:
        if (rec->fp_len != 32) {
            return 0;
        }
        break;

    default:
        return 0;
    }

    if (s3_sshfp_digest(rec->digest_type, der, der_len, digest, &dlen) != S3_OK) {
        return 0;
    }

    if (dlen != rec->fp_len) {
        return 0;
    }

    return (s3_memcmp_ct(digest, rec->fingerprint, dlen) == 0) ? 1 : 0;
}

/*
 * the server list of one lookup, the reference resolver seams in
 * order: the S3_SSHFP_DNS env (the e2e hook), then the system
 * configuration
 */

static void
s3_sshfp_servers_add(s3_sshfp_servers_t *out, const char *addr, size_t len)
{
    /* the trailing dot and the whitespace of an entry go away */

    while (len > 0 && (addr[len - 1] == ' ' || addr[len - 1] == '\t' || addr[len - 1] == '\r' ||
                       addr[len - 1] == '\n')) {
        len--;
    }

    while (len > 0 && (*addr == ' ' || *addr == '\t')) {
        addr++;
        len--;
    }

    if (len == 0 || len >= S3_SSHFP_SERVER_TEXT_MAX) {
        return;
    }

    if (out->count >= S3_SSHFP_SERVERS_MAX) {
        return;
    }

    s3_memcpy(out->servers[out->count], addr, len);
    out->servers[out->count][len] = '\0';
    out->count++;
}

static void
s3_sshfp_servers_env(s3_sshfp_servers_t *out)
{
    const char *list = getenv("S3_SSHFP_DNS");
    const char *p, *sep;

    if (list == NULL) {
        return;
    }

    p = list;

    while (*p != '\0') {

        sep = strchr(p, ',');

        if (sep == NULL) {
            s3_sshfp_servers_add(out, p, strlen(p));
            break;
        }

        s3_sshfp_servers_add(out, p, (size_t)(sep - p));

        p = sep + 1;
    }
}

#if !S3_WIN32

/*
 * the resolv.conf line of the reference parseDNSServers: the '#'
 * comment strips before the trim, the ';' separates the trailing
 * comment after it, the first field must name the nameserver
 */

static void
s3_sshfp_resolv_line(const char *line, s3_sshfp_servers_t *out)
{
    char        buf[512];
    const char *hash, *semi, *f;
    size_t      n;

    hash = strchr(line, '#');

    n = (hash != NULL) ? (size_t)(hash - line) : strlen(line);

    if (n >= sizeof(buf)) {
        return;
    }

    s3_memcpy(buf, line, n);
    buf[n] = '\0';

    /* the trailing whitespace of the comment cut */

    f = buf;

    while (*f == ' ' || *f == '\t' || *f == '\r' || *f == '\n') {
        f++;
    }

    n = strlen(f);

    while (n > 0 && (f[n - 1] == ' ' || f[n - 1] == '\t' || f[n - 1] == '\r')) {
        n--;
    }

    /* the ';' comment form strips with its own trim (the reference
     * order: the '#' cut, the trim, the ';' cut, the trim again) */

    semi = memchr(f, ';', n);

    if (semi != NULL) {
        n = (size_t)(semi - f);
    }

    while (n > 0 && (f[n - 1] == ' ' || f[n - 1] == '\t')) {
        n--;
    }

    /* the first field is the literal "nameserver", the second the
     * address; everything else (search, options) is skipped */

    if (n < 11 || s3_memcmp(f, "nameserver", 10) != 0 || (f[10] != ' ' && f[10] != '\t')) {
        return;
    }

    s3_sshfp_servers_add(out, f + 11, n - 11);
}

static void
s3_sshfp_servers_resolv_conf(s3_sshfp_servers_t *out)
{
    FILE *f;
    char  line[512];

    f = fopen(S3_SSHFP_RESOLV_CONF, "r");

    if (f == NULL) {
        return;
    }

    while (fgets(line, sizeof(line), f) != NULL) {
        s3_sshfp_resolv_line(line, out);
    }

    fclose(f);
}

#else /* S3_WIN32 */

/*
 * the DNS servers of the local adapters, the port of the reference
 * cmd/sshfp_dns_windows.go: GetAdaptersAddresses over AF_UNSPEC with
 * the unicast/anycast/multicast lists skipped (the dns server list is
 * exactly what the call is made for), the duplicates dropped, the
 * order kept, the addresses as the plain ip text
 */

static void
s3_sshfp_servers_adapters(s3_pool_t *pool, s3_sshfp_servers_t *out)
{
    u_char               *buf;
    ULONG                 size = S3_SSHFP_ADAPTER_BUF_MIN;
    IP_ADAPTER_ADDRESSES *aa;
    int                   attempt;

    for (attempt = 0; attempt < 4; attempt++) {

        buf = s3_pnalloc(pool, size);

        if (buf == NULL) {
            return;
        }

        aa = (IP_ADAPTER_ADDRESSES *)buf;

        if (GetAdaptersAddresses(
                AF_UNSPEC, GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                NULL, aa, &size) == NO_ERROR) {
            break;
        }

        if (size <= S3_SSHFP_ADAPTER_BUF_MIN) {
            return;
        }

        /* the api answered the size it needs, the retry carries the
         * grown buffer (the fresh palloc, the arena keeps the small
         * first one -- a lookup-lifetime pool makes it irrelevant) */
    }

    if (attempt == 4) {
        return;
    }

    for (; aa != NULL; aa = aa->Next) {

        IP_ADAPTER_DNS_SERVER_ADDRESS *dsa;

        for (dsa = aa->FirstDnsServerAddress; dsa != NULL; dsa = dsa->Next) {

            u_char text[S3_SOCKADDR_STRLEN];
            size_t n;

            if (dsa->Address.lpSockaddr == NULL) {
                continue;
            }

            n = s3_sock_ntop(dsa->Address.lpSockaddr, (socklen_t)dsa->Address.iSockaddrLength, text,
                             sizeof(text) - 1, 0);

            if (n == 0) {
                continue;
            }

            text[n] = '\0';

            /* the dedup over the collected list, the order kept */

            {
                size_t i;

                for (i = 0; i < out->count; i++) {

                    if (s3_strcmp(out->servers[i], (char *)text) == 0) {
                        break;
                    }
                }

                if (i < out->count) {
                    continue;
                }
            }

            s3_sshfp_servers_add(out, (const char *)text, n);
        }
    }
}

#endif

static void
s3_sshfp_servers_system(s3_pool_t *pool, s3_sshfp_servers_t *out)
{
#if !S3_WIN32

    /* the resolv.conf list rides the file, the pool stays for the
     * adapter enumeration of the windows leg below */

    (void)pool;

    s3_sshfp_servers_resolv_conf(out);

#else
    s3_sshfp_servers_adapters(pool, out);
#endif
}

/*
 * the "host" and the "port" of a server entry, the reference
 * normalizeServerAddr: a bracketed literal carries its port after the
 * fence, a single-colon text splits, a bare ipv6 literal (several
 * colons) is the host with the default port
 */

static s3_int_t
s3_sshfp_server_split(const char *server, char *host, size_t host_cap, unsigned *port)
{
    const char *h, *p;
    size_t      n;
    unsigned    v = 53;

    if (server == NULL || server[0] == '\0') {
        return S3_ERROR;
    }

    h = server;
    n = strlen(server);

    if (h[0] == '[') {

        const char *close = strchr(h + 1, ']');

        if (close == NULL) {
            return S3_ERROR;
        }

        p = close + 1;

        if (*p != '\0') {

            if (*p != ':') {
                return S3_ERROR;
            }

            p++;

            if (*p == '\0') {
                return S3_ERROR;
            }

            v = 0;

            while (*p != '\0') {

                if (*p < '0' || *p > '9' || v > 65535) {
                    return S3_ERROR;
                }

                v = v * 10 + (unsigned)(*p - '0');
                p++;
            }
        }

        n = (size_t)(close - h - 1);
        h++;

    } else {

        const char *last = strrchr(h, ':');

        if (last != NULL && strchr(h, ':') == last) {

            /* the plain host:port */

            if (last == h || last[1] == '\0') {
                return S3_ERROR;
            }

            v = 0;

            for (p = last + 1; *p != '\0'; p++) {

                if (*p < '0' || *p > '9' || v > 65535) {
                    return S3_ERROR;
                }

                v = v * 10 + (unsigned)(*p - '0');
            }

            n = (size_t)(last - h);
        }

        /* the bare ipv6 literal keeps the default port */
    }

    if (n == 0 || n >= host_cap || v > 65535) {
        return S3_ERROR;
    }

    s3_memcpy(host, h, n);
    host[n] = '\0';
    *port = v;

    return S3_OK;
}

static void
s3_sshfp_close_fd(int fd)
{
#if (S3_WIN32)
    closesocket((SOCKET)fd);
#else
    close(fd);
#endif
}

/*
 * the socket timeouts of one exchange: the SO_RCVTIMEO of the unix
 * takes the timeval, the winsock twin takes the dword of msec
 */

static void
s3_sshfp_socket_timeout(int fd)
{
#if (S3_WIN32)

    DWORD tv = S3_SSHFP_TIMEOUT_MSEC;

    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));

#else

    struct timeval tv;

    tv.tv_sec = S3_SSHFP_TIMEOUT_MSEC / 1000;
    tv.tv_usec = (S3_SSHFP_TIMEOUT_MSEC % 1000) * 1000;

    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

#endif
}

/*
 * one query/response exchange against one server (the reference
 * querySSHFPOnce over the connected udp socket): the query goes out,
 * the first datagram back carries the verdict; an id mismatch, a
 * transport failure, a truncated answer, a malformed message or a
 * refusal rcode leaves this server for the next one, an authoritative
 * no-record answer is the final verdict
 */

static int
s3_sshfp_exchange(const char *server, const u_char *query, size_t qlen, uint16_t id,
                  s3_pool_t *pool, s3_sshfp_rec_t *recs, size_t *nrecs, char *reason,
                  size_t reason_cap)
{
    struct addrinfo hints, *res = NULL;
    char            host[128];
    char            port_text[16];
    unsigned        port;
    int             fd = -1;
    u_char          answer[S3_SSHFP_DNS_ANSWER_MAX];

    if (s3_sshfp_server_split(server, host, sizeof(host), &port) != S3_OK) {
        snprintf(reason, reason_cap, "bad DNS server address %.64s", server);
        return S3_SSHFP_EXCH_NEXT;
    }

    /* the split keeps the port in the uint16 range, the mask is what
     * the truncation analysis of the six-byte buffer can see */

    snprintf(port_text, sizeof(port_text), "%u", port & 0xffffu);

    s3_memzero(&hints, sizeof(hints));

    /* the udp datagram service, either family (the reference dials
     * both) */

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    if (getaddrinfo(host, port_text, &hints, &res) != 0 || res == NULL) {
        snprintf(reason, reason_cap, "the DNS server %.64s does not resolve", server);
        return S3_SSHFP_EXCH_NEXT;
    }

    fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

    if (fd < 0) {
        snprintf(reason, reason_cap, "socket() failed for %.64s", server);
        freeaddrinfo(res);
        return S3_SSHFP_EXCH_NEXT;
    }

    s3_sshfp_socket_timeout(fd);

    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        snprintf(reason, reason_cap, "could not reach the DNS server %.64s", server);
        freeaddrinfo(res);
        s3_sshfp_close_fd(fd);
        return S3_SSHFP_EXCH_NEXT;
    }

    freeaddrinfo(res);

    if (send(fd, (const char *)query, qlen, 0) != (int)qlen) {
        snprintf(reason, reason_cap, "could not send the DNS query to %.64s", server);
        s3_sshfp_close_fd(fd);
        return S3_SSHFP_EXCH_NEXT;
    }

    {
        int n = recv(fd, (char *)answer, sizeof(answer), 0);

        s3_sshfp_close_fd(fd);

        if (n < 2) {
            snprintf(reason, reason_cap, "no answer from %.64s", server);
            return S3_SSHFP_EXCH_NEXT;
        }

        if (((unsigned)answer[0] << 8 | answer[1]) != id) {
            snprintf(reason, reason_cap, "DNS response does not match the query");
            return S3_SSHFP_EXCH_NEXT;
        }

        if (n >= 4 && (((unsigned)answer[2] << 8 | answer[3]) & S3_SSHFP_DNS_FLAG_TC) != 0) {
            /* the answer was cut by the datagram size, a tcp retry is
             * out of scope here like in the reference (the soft path) */

            snprintf(reason, reason_cap, "truncated DNS response");
            return S3_SSHFP_EXCH_NEXT;
        }

        {
            uint8_t rcode;
            size_t  count = S3_SSHFP_RECORDS_MAX;

            if (s3_sshfp_response_parse(answer, (size_t)n, pool, recs, &count, &rcode) != S3_OK) {
                snprintf(reason, reason_cap, "malformed DNS message");
                return S3_SSHFP_EXCH_NEXT;
            }

            switch (rcode) {

            case S3_SSHFP_RCODE_OK:

                if (count == 0) {

                    /* the name exists and publishes nothing */

                    snprintf(reason, reason_cap, "no SSHFP record published");
                    return S3_SSHFP_EXCH_NORECS;
                }

                *nrecs = count;

                return S3_SSHFP_EXCH_RECORDS;

            case S3_SSHFP_RCODE_NXDOMAIN:

                snprintf(reason, reason_cap, "no SSHFP record published");
                return S3_SSHFP_EXCH_NORECS;

            default:

                /* the %.64s precision keeps the truncation warning of
                 * the fixed reason buffer quiet */

                snprintf(reason, reason_cap, "the DNS server %.64s answered with rcode %u", server,
                         (unsigned)rcode);
                return S3_SSHFP_EXCH_NEXT;
            }
        }
    }
}

s3_sshfp_status_t
s3_sshfp_check(const char *query_name, X509 *cert, const u_char *der, size_t der_len,
               s3_pool_t *pool, s3_sshfp_rec_t *matched, char *errbuf, size_t errbuf_cap)
{
    s3_sshfp_servers_t servers;
    s3_sshfp_rec_t     recs[S3_SSHFP_RECORDS_MAX];
    u_char             query[S3_SSHFP_DNS_NAME_MAX + S3_SSHFP_DNS_HEADER_SIZE + 4];
    u_char             idb[2];
    u_char            *der_own = NULL;
    char               reason[128] = "";
    size_t             qlen, nrecs, i;
    uint16_t           id;
    uint8_t            algo;
    s3_int_t           rc = S3_SSHFP_EXCH_NEXT;

    s3_sshfp_err(errbuf, errbuf_cap, "");

    if (cert == NULL) {

        /* no certificate, no verification attempt at all */

        return S3_SSHFP_NOT_CHECKED;
    }

    if (pool == NULL) {
        s3_sshfp_err(errbuf, errbuf_cap, "no pool for the SSHFP lookup");
        return S3_SSHFP_LOOKUP_FAILED;
    }

    if (der == NULL) {

        /* the der form of the leaf, the bytes the digests ride */

        int     n = i2d_X509(cert, NULL);
        u_char *p;

        if (n <= 0) {
            s3_sshfp_err(errbuf, errbuf_cap, "could not derive the certificate DER");
            return S3_SSHFP_LOOKUP_FAILED;
        }

        der_own = s3_pnalloc(pool, (size_t)n);

        if (der_own == NULL) {
            s3_sshfp_err(errbuf, errbuf_cap, "no pool memory for the certificate DER");
            return S3_SSHFP_LOOKUP_FAILED;
        }

        p = der_own;

        if (i2d_X509(cert, &p) != n) {
            s3_sshfp_err(errbuf, errbuf_cap, "could not derive the certificate DER");
            return S3_SSHFP_LOOKUP_FAILED;
        }

        der = der_own;
        der_len = (size_t)n;
    }

    s3_memzero(&servers, sizeof(servers));
    s3_memzero(recs, sizeof(recs));

    s3_sshfp_servers_env(&servers);

    if (servers.count == 0) {
        s3_sshfp_servers_system(pool, &servers);
    }

    if (servers.count == 0) {
        s3_sshfp_err(errbuf, errbuf_cap, "no DNS server available for the SSHFP lookup");
        return S3_SSHFP_LOOKUP_FAILED;
    }

    if (query_name == NULL || query_name[0] == '\0') {
        s3_sshfp_err(errbuf, errbuf_cap, "could not derive an SSHFP query name");
        return S3_SSHFP_LOOKUP_FAILED;
    }

    if (RAND_bytes(idb, sizeof(idb)) != 1) {

        /* a predictable id is a cache-poisoning nuisance on a lookup
         * the caller verifies the answer of anyway; the zero rides */

        idb[0] = 0;
        idb[1] = 0;
    }

    id = (uint16_t)(((unsigned)idb[0] << 8) | idb[1]);

    if (s3_sshfp_query_build(id, query_name, query, sizeof(query), &qlen) != S3_OK) {
        s3_sshfp_err(errbuf, errbuf_cap, "could not build the DNS query");
        return S3_SSHFP_LOOKUP_FAILED;
    }

    nrecs = 0;

    for (i = 0; i < servers.count; i++) {

        rc = s3_sshfp_exchange(servers.servers[i], query, qlen, id, pool, recs, &nrecs, reason,
                               sizeof(reason));

        if (rc == S3_SSHFP_EXCH_RECORDS) {
            break;
        }

        if (rc == S3_SSHFP_EXCH_NORECS) {

            /* an authoritative "no record" is the final verdict: no
             * further server can add one */

            return S3_SSHFP_NO_RECORDS;
        }

        /* the next server, the reason text already carries the why */
    }

    if (rc != S3_SSHFP_EXCH_RECORDS) {
        s3_sshfp_err(errbuf, errbuf_cap, reason);
        return S3_SSHFP_LOOKUP_FAILED;
    }

    algo = s3_sshfp_key_algorithm(cert);

    for (i = 0; i < nrecs; i++) {

        if (!s3_sshfp_rec_matches(&recs[i], algo, der, der_len)) {
            continue;
        }

        if (matched != NULL) {
            *matched = recs[i];
        }

        return S3_SSHFP_VERIFIED;
    }

    /* the records exist and none certifies the presented key: the
     * strongest possible MITM signal */

    return S3_SSHFP_MISMATCH;
}
