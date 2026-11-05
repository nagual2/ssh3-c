/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_SSH3_SSHFP_H_INCLUDED_
#define _S3_SSH3_SSHFP_H_INCLUDED_

#include <s3_core.h>

#include <openssl/x509.h>

/*
 * SSHFP (RFC 4255) verification of the host certificate -- the C port
 * of the Go fork's sshfp.go.  The "host key" is the DER of the leaf
 * certificate: the digests ride cert DER bytes, exactly what the
 * known_hosts pin compares.
 *
 * ssh3 pins X.509 certificates in its known_hosts file instead of raw
 * SSH public keys, so the fingerprint published in DNS is taken over
 * the DER form.  The DNS exchange rides a raw UDP client built on the
 * plain sockets of this tree (no libresolv, no dnsapi -- the Go
 * reference is self-contained the same way); the wire building and
 * parsing (s3_sshfp_query_build/s3_sshfp_response_parse) stay apart
 * from the network call (s3_sshfp_check), so the parser is exercised
 * on raw fixtures and stays a fuzz target.
 *
 * the module is client-side CLI context: every network call below is
 * blocking with a timeout and never runs on the event loop of the
 * server; the caller is expected to invoke s3_sshfp_check after the
 * handshake, opt-in.
 */

/* SSHFP algorithm numbers (RFC 4255 5, extended by RFC 7479) */

#define S3_SSHFP_ALGO_RESERVED 0
#define S3_SSHFP_ALGO_RSA      1
#define S3_SSHFP_ALGO_DSA      2
#define S3_SSHFP_ALGO_ECDSA    3
#define S3_SSHFP_ALGO_ED25519  4

/* SSHFP digest numbers (RFC 4255 5) */

#define S3_SSHFP_DIGEST_SHA1   1
#define S3_SSHFP_DIGEST_SHA256 2

/* the DNS rcode values the verdict distinguishes */

#define S3_SSHFP_RCODE_OK       0
#define S3_SSHFP_RCODE_NXDOMAIN 3

/* default UDP exchange timeout, msec (Go DefaultSSHFPTimeout = 2s) */

#define S3_SSHFP_TIMEOUT_MSEC 2000

/* the DNS message shape the module builds and accepts */

#define S3_SSHFP_DNS_HEADER_SIZE  12
#define S3_SSHFP_DNS_TYPE_SSHFP   44
#define S3_SSHFP_DNS_CLASS_IN     1
#define S3_SSHFP_DNS_NAME_MAX     255
#define S3_SSHFP_DNS_POINTERS_MAX 16
#define S3_SSHFP_DNS_ANSWER_MAX   1500

/* the DNS server list bound: the env hook carries host[:port] pairs */

#define S3_SSHFP_SERVERS_MAX     16
#define S3_SSHFP_SERVER_TEXT_MAX 64

/*
 * one SSHFP resource record: the algorithm of the host key, the
 * digest algorithm the fingerprint rides, and the fingerprint bytes.
 * the fingerprint is pool-allocated and dies with the pool
 */

typedef struct {
    uint8_t algorithm;   /* SSHFP algorithm number (RFC 4255 5, RFC 7479) */
    uint8_t digest_type; /* 1 = SHA-1, 2 = SHA-256 */
    u_char *fingerprint; /* pool-allocated bytes of the record */
    size_t  fp_len;
} s3_sshfp_rec_t;

/* verdict statuses (Go SSHFPStatus) */

typedef enum {
    S3_SSHFP_NOT_CHECKED = 0, /* disabled or no certificate */
    S3_SSHFP_VERIFIED,        /* a published record matches the DER */
    S3_SSHFP_NO_RECORDS,      /* NXDOMAIN / NODATA: soft, says nothing */
    S3_SSHFP_LOOKUP_FAILED,   /* transport failure: soft, never a rejection */
    S3_SSHFP_MISMATCH         /* records published, none matches: fatal */
} s3_sshfp_status_t;

/*
 * builds a recursive SSHFP query (type 44, class IN) for name into
 * buf (cap bytes), the written size comes back through out_len; the
 * dotted name is encoded into the length-prefixed label sequence, a
 * trailing dot is dropped, an empty label, a label over 63 octets, a
 * name over S3_SSHFP_DNS_NAME_MAX or a short cap refuse
 *
 * S3_OK fills buf and *out_len; S3_ERROR leaves them unspecified
 */

s3_int_t s3_sshfp_query_build(uint16_t id, const char *name, u_char *buf, size_t cap,
                              size_t *out_len);

/*
 * parses a DNS answer: the SSHFP records (type 44, class IN) land in
 * recs (cap *nrecs on entry, the actual count back), the message
 * rcode through rcode.  compression pointers are bounded
 * (S3_SSHFP_DNS_POINTERS_MAX), the reserved label types 0x40/0x80
 * refuse, a name or a record running past the message refuses.  the
 * fingerprint bytes of the returned records are pool-allocated.  the
 * irrelevant record types (A, TXT, CNAME, the CHAOS class, a short
 * rdata) are skipped, not errors
 *
 * S3_OK fills recs, *nrecs and *rcode; S3_ERROR (malformed) leaves
 * *nrecs at 0 and still fills *rcode when the header was readable
 */

s3_int_t s3_sshfp_response_parse(const u_char *msg, size_t len, s3_pool_t *pool,
                                 s3_sshfp_rec_t *recs, size_t *nrecs, uint8_t *rcode);

/*
 * derives the SSHFP query name from an ssh3 target key
 * ("host:port/path", bracket "[v6]:port", bare name, or an ip
 * literal): the path and any query/fragment are dropped, the port is
 * stripped outside the brackets, the brackets themselves go away, a
 * trailing dot is dropped, names are lowercased.  an ip literal maps
 * to the reverse name "<rev>.in-addr.arpa" / the nibble "ip6.arpa"
 * form (RFC 4255 3).  buf carries the terminator
 *
 * S3_OK fills buf; S3_ERROR (empty, unbalanced brackets, no host,
 * buf too small) leaves it unspecified
 */

s3_int_t s3_sshfp_query_name(const char *hostkey, char *buf, size_t cap);

/*
 * fingerprint of the DER with digest_type (SHA-1/SHA-256), out
 * carries at least 32 bytes, the digest length comes back through
 * out_len (20 or 32)
 *
 * S3_OK fills out and *out_len; S3_ERROR (unknown digest type)
 * leaves them unspecified
 */

s3_int_t s3_sshfp_digest(uint8_t digest_type, const u_char *der, size_t der_len, u_char *out,
                         size_t *out_len);

/*
 * SSHFP algorithm number of the leaf's public key: RSA=1, ECDSA=3,
 * Ed25519=4, else S3_SSHFP_ALGO_RESERVED (DSA included) -- no record
 * can ever match a reserved-algorithm key
 */

uint8_t s3_sshfp_key_algorithm(X509 *cert);

/*
 * record matches the DER: the algorithm number equal, the digest type
 * known and the fingerprint of the implied length, the digest
 * computable, the bytes equal (constant-time compare).  the DER is
 * the public input here (a certificate arrives in the clear), the
 * compare stays constant-time on principle, like the pins do
 */

unsigned s3_sshfp_rec_matches(const s3_sshfp_rec_t *rec, uint8_t algo, const u_char *der,
                              size_t der_len);

/*
 * the verdict of a live lookup: query_name comes from
 * s3_sshfp_query_name, cert and der describe the presented leaf (cert
 * may be NULL, the verdict is S3_SSHFP_NOT_CHECKED then).  the
 * resolver list resolves per call -- the env S3_SSHFP_DNS (a
 * comma-separated host[:port] list, the e2e test hook), then the
 * system configuration (/etc/resolv.conf on unix, GetAdaptersAddresses
 * on windows) -- and the UDP exchange runs across the servers in
 * order (an authoritative NXDOMAIN/NODATA is final, a response id
 * mismatch or a transport failure moves to the next server, a
 * truncated answer gives up without a TCP retry, like the Go
 * ErrDNSTruncated soft path).  the SHA-1 and SHA-256 digests of der
 * are computed once and matched against the records.  matched carries
 * the certifying record on S3_SSHFP_VERIFIED, errbuf (errbuf_cap
 * bytes, may be NULL) carries the failure text of a
 * S3_SSHFP_LOOKUP_FAILED.  the record store and the fingerprints die
 * with pool.  status only; never throws
 */

s3_sshfp_status_t s3_sshfp_check(const char *query_name, X509 *cert, const u_char *der,
                                 size_t der_len, s3_pool_t *pool, s3_sshfp_rec_t *matched,
                                 char *errbuf, size_t errbuf_cap);

#endif /* _S3_SSH3_SSHFP_H_INCLUDED_ */
