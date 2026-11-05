/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the SSHFP pins: the raw wire fixtures of the reference
 * sshfp_test.go (the answer parser, the query builder, the query
 * name, the record match against the presented key) and the
 * keygen-driven algorithm map; the live verdict rides the loopback
 * udp stub of the reference TestUDPSSHFPResolver (the fork and the
 * S3_SSHFP_DNS env hook, the unix legs -- the windows build keeps
 * the parser-level fixtures only)
 */

#include <s3_core.h>

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <stdio.h>
#include <string.h>
#include <time.h>

#if !S3_WIN32

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#endif

#include <s3_ssh3_sshfp.h>

#include "s3_test.h"

/* the certificate fixtures: one ec leaf the verdict rides (the der
 * bytes are the "host key") and one leaf per sshfp algorithm map */

static X509  *g_cert;
static u_char g_der[4096];
static size_t g_der_len;

static X509 *g_rsa_cert;
static X509 *g_ec_cert;
static X509 *g_ed_cert;
static X509 *g_x25519_cert;

/*
 * the answer record of a fixture message: the name rides as-is
 * unless ptr is set, in which case the compression pointer to ptr is
 * written instead (the shape of the reference dnsRRFixture)
 */

typedef struct {
    const char *name;
    size_t      ptr;
    uint16_t    type;
    uint16_t class;
    uint32_t      ttl;
    const u_char *rdata;
    size_t        rdlen;
} s3_tf_rr_t;

/*
 * the deterministic n-byte pattern of the reference bytesOf: the
 * first byte and the running index
 */

static void
s3_tf_bytes(u_char *out, u_char first, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        out[i] = (u_char)(first + i);
    }
}

/*
 * the dotted name into the wire labels, the shape the fixtures ride
 */

static size_t
s3_tf_name_encode(u_char *buf, size_t cap, const char *name)
{
    const char *p, *sep;
    size_t      n = 0;

    p = name;

    while (*p != '\0') {

        if (*p == '.') {
            p++;
            continue;
        }

        sep = strchr(p, '.');

        if (sep == NULL) {
            sep = p + strlen(p);
        }

        {
            size_t len = (size_t)(sep - p);

            if (len == 0 || len > 63 || n + 1 + len + 1 > cap) {
                return 0;
            }

            buf[n++] = (u_char)len;
            s3_memcpy(buf + n, p, len);
            n += len;
        }

        p = sep;
    }

    if (n + 1 > cap) {
        return 0;
    }

    buf[n++] = 0;

    return n;
}

/*
 * the DNS message of the reference buildDNSMessage: the 12-byte
 * header, one question and the answers; the question name starts at
 * offset 12, which fixes the compression pointer targets
 */

static size_t
s3_tf_msg(u_char *msg, size_t cap, uint16_t id, uint16_t flags, const char *qname,
          const s3_tf_rr_t *rrs, size_t nrrs)
{
    u_char namebuf[280];
    size_t n = 0, nlen, i;

    nlen = s3_tf_name_encode(namebuf, sizeof(namebuf), qname);

    if (nlen == 0) {
        return 0;
    }

    if (cap < S3_SSHFP_DNS_HEADER_SIZE + nlen + 4) {
        return 0;
    }

    msg[n++] = (u_char)(id >> 8);
    msg[n++] = (u_char)(id & 0xff);
    msg[n++] = (u_char)(flags >> 8);
    msg[n++] = (u_char)(flags & 0xff);
    msg[n++] = 0;
    msg[n++] = 1; /* QDCOUNT */
    msg[n++] = (u_char)(nrrs >> 8);
    msg[n++] = (u_char)(nrrs & 0xff); /* ANCOUNT */
    msg[n++] = 0;
    msg[n++] = 0;
    msg[n++] = 0;
    msg[n++] = 0;

    s3_memcpy(msg + n, namebuf, nlen);
    n += nlen;

    msg[n++] = (u_char)(S3_SSHFP_DNS_TYPE_SSHFP >> 8);
    msg[n++] = (u_char)(S3_SSHFP_DNS_TYPE_SSHFP & 0xff);
    msg[n++] = (u_char)(S3_SSHFP_DNS_CLASS_IN >> 8);
    msg[n++] = (u_char)(S3_SSHFP_DNS_CLASS_IN & 0xff);

    for (i = 0; i < nrrs; i++) {

        const s3_tf_rr_t *rr = &rrs[i];

        if (rr->ptr > 0) {

            if (cap - n < 2) {
                return 0;
            }

            msg[n++] = (u_char)(0xc0 | (rr->ptr >> 8));
            msg[n++] = (u_char)(rr->ptr & 0xff);

        } else {

            nlen = s3_tf_name_encode(namebuf, sizeof(namebuf), rr->name);

            if (nlen == 0 || cap - n < nlen) {
                return 0;
            }

            s3_memcpy(msg + n, namebuf, nlen);
            n += nlen;
        }

        if (cap - n < 10 + rr->rdlen) {
            return 0;
        }

        msg[n++] = (u_char)(rr->type >> 8);
        msg[n++] = (u_char)(rr->type & 0xff);
        msg[n++] = (u_char)(rr->class >> 8);
        msg[n++] = (u_char)(rr->class & 0xff);
        msg[n++] = (u_char)(rr->ttl >> 24);
        msg[n++] = (u_char)((rr->ttl >> 16) & 0xff);
        msg[n++] = (u_char)((rr->ttl >> 8) & 0xff);
        msg[n++] = (u_char)(rr->ttl & 0xff);
        msg[n++] = (u_char)(rr->rdlen >> 8);
        msg[n++] = (u_char)(rr->rdlen & 0xff);

        s3_memcpy(msg + n, rr->rdata, rr->rdlen);
        n += rr->rdlen;
    }

    return n;
}

/*
 * the sshfp rdata of the reference sshfpRdata: the two algorithm
 * bytes and the fingerprint
 */

static size_t
s3_tf_sshfp_rdata(u_char *rdata, uint8_t algorithm, uint8_t digest_type, const u_char *fp,
                  size_t fp_len)
{
    rdata[0] = algorithm;
    rdata[1] = digest_type;
    s3_memcpy(rdata + 2, fp, fp_len);

    return 2 + fp_len;
}

/* the key and certificate fixtures, the shape of the jwt test keys */

static EVP_PKEY *
s3_tf_gen_key(int id)
{
    EVP_PKEY_CTX *ctx;
    EVP_PKEY     *key = NULL;

    ctx = EVP_PKEY_CTX_new_id(id, NULL);

    if (ctx == NULL) {
        return NULL;
    }

    if (EVP_PKEY_keygen_init(ctx) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (id == EVP_PKEY_RSA && EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (id == EVP_PKEY_EC &&
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_generate(ctx, &key) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);

    return key;
}

/*
 * one self-signed leaf over the key; the ed25519 signature carries
 * no digest (the X509_sign contract), the rest ride sha-256.  the
 * signer may differ from the published key (a key-agreement key
 * cannot sign -- the certificate of the x25519 fixture is signed by
 * a fresh ec key, the algorithm map reads the published key only)
 */

static X509 *
s3_tf_cert(EVP_PKEY *key, EVP_PKEY *signer)
{
    X509      *x509;
    X509_NAME *name;
    unsigned   ed;

    if (key == NULL || signer == NULL) {
        return NULL;
    }

    ed = (EVP_PKEY_base_id(signer) == EVP_PKEY_ED25519);

    x509 = X509_new();

    if (x509 == NULL) {
        return NULL;
    }

    X509_set_version(x509, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_getm_notBefore(x509), 0);
    X509_gmtime_adj(X509_getm_notAfter(x509), 31536000);
    X509_set_pubkey(x509, key);

    name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)"s3-test", -1, -1,
                               0);
    X509_set_issuer_name(x509, name);

    if (X509_sign(x509, signer, ed ? NULL : EVP_sha256()) == 0) {
        X509_free(x509);
        return NULL;
    }

    return x509;
}

static int
s3_tf_fixtures(void)
{
    EVP_PKEY *k, *s;
    u_char   *p;
    int       n;

    /* the ec leaf the match and the verdict ride */

    k = s3_tf_gen_key(EVP_PKEY_EC);
    S3_ASSERT(k != NULL);
    g_cert = s3_tf_cert(k, k);
    S3_ASSERT(g_cert != NULL);
    EVP_PKEY_free(k);

    n = i2d_X509(g_cert, NULL);
    S3_ASSERT(n > 0 && (size_t)n <= sizeof(g_der));
    p = g_der;
    S3_ASSERT(i2d_X509(g_cert, &p) == n);
    g_der_len = (size_t)n;

    /* the algorithm map leaves */

    k = s3_tf_gen_key(EVP_PKEY_RSA);
    S3_ASSERT(k != NULL);
    g_rsa_cert = s3_tf_cert(k, k);
    S3_ASSERT(g_rsa_cert != NULL);
    EVP_PKEY_free(k);

    k = s3_tf_gen_key(EVP_PKEY_EC);
    S3_ASSERT(k != NULL);
    g_ec_cert = s3_tf_cert(k, k);
    S3_ASSERT(g_ec_cert != NULL);
    EVP_PKEY_free(k);

    k = s3_tf_gen_key(EVP_PKEY_ED25519);
    S3_ASSERT(k != NULL);
    g_ed_cert = s3_tf_cert(k, k);
    S3_ASSERT(g_ed_cert != NULL);
    EVP_PKEY_free(k);

    /* the reserved representative: a key type no sshfp number names
     * (the dsa of the reference stays out here -- the evp keygen of
     * this openssl build takes the paramgen down with it, the x25519
     * carries the same "reserved" shape reliably); the signing key
     * is a fresh ec key, a key-agreement key cannot sign */

    k = s3_tf_gen_key(EVP_PKEY_X25519);
    s = s3_tf_gen_key(EVP_PKEY_EC);
    S3_ASSERT(k != NULL && s != NULL);
    g_x25519_cert = s3_tf_cert(k, s);
    S3_ASSERT(g_x25519_cert != NULL);
    EVP_PKEY_free(k);
    EVP_PKEY_free(s);

    return s3_test_failures;
}

/*
 * the reference TestBuildSSHFPQuery: the id, the recursion-desired
 * flags, the QDCOUNT, the encoded name and the type 44 / class IN
 * pair -- the byte vector of the wire form
 */

static int
s3_tf_query_build(void)
{
    u_char query[320];
    u_char want[] = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 's',  's',  'h',  'f',  'p',  0x07, 'e',  'x',  'a',  'm',  'p',
        'l',  'e',  0x03, 'o',  'r',  'g',  0x00, 0x00, 0x2c, 0x00, 0x01,
    };
    char   bad[96];
    size_t n;

    S3_ASSERT(s3_sshfp_query_build(0x1234, "sshfp.example.org", query, sizeof(query), &n) == S3_OK);
    S3_ASSERT(n == sizeof(want));
    S3_ASSERT(s3_memcmp(query, want, sizeof(want)) == 0);

    /* the trailing dot of the fqdn encodes to the same bytes */

    S3_ASSERT(s3_sshfp_query_build(0x1234, "sshfp.example.org.", query, sizeof(query), &n) ==
              S3_OK);
    S3_ASSERT(n == sizeof(want));
    S3_ASSERT(s3_memcmp(query, want, sizeof(want)) == 0);

    /* the refusals of the reference builder: the empty name, the
     * empty label, the label over 63 octets */

    S3_ASSERT(s3_sshfp_query_build(1, "", query, sizeof(query), &n) == S3_ERROR);
    S3_ASSERT(s3_sshfp_query_build(1, "sshfp..example.org", query, sizeof(query), &n) == S3_ERROR);

    s3_memset(bad, 'a', 64);
    snprintf(bad + 64, sizeof(bad) - 64, ".example.org");
    S3_ASSERT(s3_sshfp_query_build(1, bad, query, sizeof(query), &n) == S3_ERROR);

    /* the short cap */

    S3_ASSERT(s3_sshfp_query_build(1, "sshfp.example.org", query, 10, &n) == S3_ERROR);

    return s3_test_failures;
}

/*
 * the reference TestParseSSHFPResponse: two sshfp answers over a
 * plain (uncompressed) encoding
 */

static int
s3_tf_parse(void)
{
    s3_log_t       log;
    s3_pool_t     *pool;
    u_char         msg[512], fp1[32], fp2[20], rd1[34], rd2[22];
    s3_tf_rr_t     rrs[2];
    s3_sshfp_rec_t recs[4];
    size_t         n, mlen;
    uint8_t        rcode;

    log.log_level = S3_LOG_ALERT;
    log.fd = S3_INVALID_FILE;
    pool = s3_create_pool(4096, &log);
    S3_ASSERT(pool != NULL);

    s3_tf_bytes(fp1, 0xa0, 32);
    s3_tf_bytes(fp2, 0xb0, 20);

    mlen = s3_tf_sshfp_rdata(rd1, S3_SSHFP_ALGO_RSA, S3_SSHFP_DIGEST_SHA256, fp1, 32);
    S3_ASSERT(mlen == 34);
    mlen = s3_tf_sshfp_rdata(rd2, S3_SSHFP_ALGO_ECDSA, S3_SSHFP_DIGEST_SHA1, fp2, 20);
    S3_ASSERT(mlen == 22);

    rrs[0].name = "sshfp.example.org";
    rrs[0].ptr = 0;
    rrs[0].type = 44;
    rrs[0].class = 1;
    rrs[0].ttl = 3600;
    rrs[0].rdata = rd1;
    rrs[0].rdlen = 34;

    rrs[1].name = "sshfp.example.org";
    rrs[1].ptr = 0;
    rrs[1].type = 44;
    rrs[1].class = 1;
    rrs[1].ttl = 3600;
    rrs[1].rdata = rd2;
    rrs[1].rdlen = 22;

    mlen = s3_tf_msg(msg, sizeof(msg), 0xbeef, 0x8000, "sshfp.example.org", rrs, 2);
    S3_ASSERT(mlen > 0);

    n = 4;
    S3_ASSERT(s3_sshfp_response_parse(msg, mlen, pool, recs, &n, &rcode) == S3_OK);
    S3_ASSERT(rcode == S3_SSHFP_RCODE_OK);
    S3_ASSERT(n == 2);

    S3_ASSERT(recs[0].algorithm == S3_SSHFP_ALGO_RSA);
    S3_ASSERT(recs[0].digest_type == S3_SSHFP_DIGEST_SHA256);
    S3_ASSERT(recs[0].fp_len == 32);
    S3_ASSERT(recs[0].fingerprint[0] == 0xa0);
    S3_ASSERT(recs[0].fingerprint[31] == (u_char)(0xa0 + 31));

    S3_ASSERT(recs[1].algorithm == S3_SSHFP_ALGO_ECDSA);
    S3_ASSERT(recs[1].digest_type == S3_SSHFP_DIGEST_SHA1);
    S3_ASSERT(recs[1].fp_len == 20);
    S3_ASSERT(recs[1].fingerprint[0] == 0xb0);

    s3_destroy_pool(pool);

    return s3_test_failures;
}

/*
 * the reference TestParseSSHFPResponseNameCompression: the pointers
 * to the full question name (offset 12) and to its "example.org"
 * suffix (offset 18) must not hide the records
 */

static int
s3_tf_parse_compression(void)
{
    s3_log_t       log;
    s3_pool_t     *pool;
    u_char         msg[512], fp[32], rd1[34], rd2[22], rd3[34];
    s3_tf_rr_t     rrs[3];
    s3_sshfp_rec_t recs[4];
    size_t         n, mlen, i;
    uint8_t        rcode;

    log.log_level = S3_LOG_ALERT;
    log.fd = S3_INVALID_FILE;
    pool = s3_create_pool(4096, &log);
    S3_ASSERT(pool != NULL);

    s3_tf_bytes(fp, 0x01, 32);
    S3_ASSERT(s3_tf_sshfp_rdata(rd1, S3_SSHFP_ALGO_RSA, S3_SSHFP_DIGEST_SHA256, fp, 32) == 34);

    s3_tf_bytes(fp, 0x02, 32);
    S3_ASSERT(s3_tf_sshfp_rdata(rd2, S3_SSHFP_ALGO_RSA, S3_SSHFP_DIGEST_SHA1, fp, 20) == 22);

    s3_tf_bytes(fp, 0x03, 32);
    S3_ASSERT(s3_tf_sshfp_rdata(rd3, S3_SSHFP_ALGO_ECDSA, S3_SSHFP_DIGEST_SHA256, fp, 32) == 34);

    rrs[0].name = NULL;
    rrs[0].ptr = 12;
    rrs[0].type = 44;
    rrs[0].class = 1;
    rrs[0].ttl = 60;
    rrs[0].rdata = rd1;
    rrs[0].rdlen = 34;

    rrs[1] = rrs[0];
    rrs[1].ptr = 12 + 5 + 1; /* the "example.org" suffix of the question name */
    rrs[1].rdata = rd2;
    rrs[1].rdlen = 22;

    rrs[2] = rrs[0];
    rrs[2].name = "sshfp.example.org";
    rrs[2].ptr = 0;
    rrs[2].rdata = rd3;

    mlen = s3_tf_msg(msg, sizeof(msg), 1, 0x8000, "sshfp.example.org", rrs, 3);
    S3_ASSERT(mlen > 0);

    n = 4;
    S3_ASSERT(s3_sshfp_response_parse(msg, mlen, pool, recs, &n, &rcode) == S3_OK);
    S3_ASSERT(rcode == S3_SSHFP_RCODE_OK);
    S3_ASSERT(n == 3);

    for (i = 0; i < 3; i++) {
        S3_ASSERT(recs[i].fingerprint[0] == (u_char)(0x01 + i));
    }

    s3_destroy_pool(pool);

    return s3_test_failures;
}

/*
 * the reference TestParseSSHFPResponseNoRecordsAndNXDomain: the
 * NOERROR without answers, the NXDOMAIN and the NODATA with the
 * unrelated record types (TXT, CNAME and an sshfp of the CHAOS
 * class) all come back with no sshfp record
 */

static int
s3_tf_parse_norecs(void)
{
    s3_log_t       log;
    s3_pool_t     *pool;
    u_char         msg[512], fp[32], rd[34], cname[32], txt[3];
    s3_tf_rr_t     rrs[3];
    s3_sshfp_rec_t recs[4];
    size_t         n, mlen;
    uint8_t        rcode;

    log.log_level = S3_LOG_ALERT;
    log.fd = S3_INVALID_FILE;
    pool = s3_create_pool(4096, &log);
    S3_ASSERT(pool != NULL);

    /* NOERROR without an answer */

    n = 4;
    mlen = s3_tf_msg(msg, sizeof(msg), 7, 0x8000, "sshfp.example.org", NULL, 0);
    S3_ASSERT(mlen > 0);

    S3_ASSERT(s3_sshfp_response_parse(msg, mlen, pool, recs, &n, &rcode) == S3_OK);
    S3_ASSERT(rcode == S3_SSHFP_RCODE_OK);
    S3_ASSERT(n == 0);

    /* NXDOMAIN */

    n = 4;
    mlen = s3_tf_msg(msg, sizeof(msg), 7, (uint16_t)(0x8000 | S3_SSHFP_RCODE_NXDOMAIN),
                     "sshfp.example.org", NULL, 0);
    S3_ASSERT(mlen > 0);

    S3_ASSERT(s3_sshfp_response_parse(msg, mlen, pool, recs, &n, &rcode) == S3_OK);
    S3_ASSERT(rcode == S3_SSHFP_RCODE_NXDOMAIN);
    S3_ASSERT(n == 0);

    /* NODATA with the unrelated types: the TXT, the CNAME and the
     * sshfp of the CHAOS class are all skipped */

    s3_tf_bytes(fp, 0x09, 32);
    mlen = s3_tf_sshfp_rdata(rd, S3_SSHFP_ALGO_RSA, S3_SSHFP_DIGEST_SHA256, fp, 32);

    txt[0] = 3;
    txt[1] = 'h';
    txt[2] = 'i';

    mlen = s3_tf_name_encode(cname, sizeof(cname), "elsewhere.example.org");
    S3_ASSERT(mlen > 0);

    rrs[0].name = "sshfp.example.org";
    rrs[0].ptr = 0;
    rrs[0].type = 16; /* TXT */
    rrs[0].class = 1;
    rrs[0].ttl = 60;
    rrs[0].rdata = txt;
    rrs[0].rdlen = 3;

    rrs[1].name = "sshfp.example.org";
    rrs[1].ptr = 0;
    rrs[1].type = 5; /* CNAME */
    rrs[1].class = 1;
    rrs[1].ttl = 60;
    rrs[1].rdata = cname;
    rrs[1].rdlen = mlen;

    rrs[2].name = "sshfp.example.org";
    rrs[2].ptr = 0;
    rrs[2].type = 44;
    rrs[2].class = 3; /* CHAOS */
    rrs[2].ttl = 60;
    rrs[2].rdata = rd;
    rrs[2].rdlen = 34;

    n = 4;
    mlen = s3_tf_msg(msg, sizeof(msg), 7, 0x8000, "sshfp.example.org", rrs, 3);
    S3_ASSERT(mlen > 0);

    S3_ASSERT(s3_sshfp_response_parse(msg, mlen, pool, recs, &n, &rcode) == S3_OK);
    S3_ASSERT(rcode == S3_SSHFP_RCODE_OK);
    S3_ASSERT(n == 0);

    s3_destroy_pool(pool);

    return s3_test_failures;
}

/*
 * the reference TestParseSSHFPResponseMalformed: the truncated
 * header, the truncated question, the truncated answer, the
 * compression pointer loop and the reserved label type all refuse
 */

static int
s3_tf_parse_malformed(void)
{
    s3_log_t       log;
    s3_pool_t     *pool;
    u_char         msg[512], valid[512], fp[32], rd[34];
    s3_tf_rr_t     rrs[1];
    s3_sshfp_rec_t recs[4];
    size_t         n, mlen, vlen;
    uint8_t        rcode;

    log.log_level = S3_LOG_ALERT;
    log.fd = S3_INVALID_FILE;
    pool = s3_create_pool(4096, &log);
    S3_ASSERT(pool != NULL);

    s3_tf_bytes(fp, 0x01, 32);
    mlen = s3_tf_sshfp_rdata(rd, S3_SSHFP_ALGO_RSA, S3_SSHFP_DIGEST_SHA256, fp, 32);

    rrs[0].name = "sshfp.example.org";
    rrs[0].ptr = 0;
    rrs[0].type = 44;
    rrs[0].class = 1;
    rrs[0].ttl = 60;
    rrs[0].rdata = rd;
    rrs[0].rdlen = 34;

    vlen = s3_tf_msg(valid, sizeof(valid), 3, 0x8000, "sshfp.example.org", rrs, 1);
    S3_ASSERT(vlen > 0);

    /* the truncated header */

    n = 4;
    S3_ASSERT(s3_sshfp_response_parse(valid, 3, pool, recs, &n, &rcode) == S3_ERROR);

    /* the truncated question */

    n = 4;
    S3_ASSERT(s3_sshfp_response_parse(valid, 15, pool, recs, &n, &rcode) == S3_ERROR);

    /* the truncated answer: the last five bytes of the rdata gone */

    n = 4;
    S3_ASSERT(s3_sshfp_response_parse(valid, vlen - 5, pool, recs, &n, &rcode) == S3_ERROR);

    /* the compression pointer loop of the reference fixture: the
     * question name points back to itself */

    s3_memzero(msg, S3_SSHFP_DNS_HEADER_SIZE);
    msg[4] = 0;
    msg[5] = 1; /* QDCOUNT */
    msg[6] = 0;
    msg[7] = 1; /* ANCOUNT */
    mlen = S3_SSHFP_DNS_HEADER_SIZE;

    /* the question: the pointer to offset 12 (itself) */

    msg[mlen++] = 0xc0;
    msg[mlen++] = 12;
    msg[mlen++] = (u_char)(S3_SSHFP_DNS_TYPE_SSHFP >> 8);
    msg[mlen++] = (u_char)(S3_SSHFP_DNS_TYPE_SSHFP & 0xff);
    msg[mlen++] = (u_char)(S3_SSHFP_DNS_CLASS_IN >> 8);
    msg[mlen++] = (u_char)(S3_SSHFP_DNS_CLASS_IN & 0xff);

    /* the answer: the same self pointer, the full record fields */

    msg[mlen++] = 0xc0;
    msg[mlen++] = 12;
    msg[mlen++] = (u_char)(S3_SSHFP_DNS_TYPE_SSHFP >> 8);
    msg[mlen++] = (u_char)(S3_SSHFP_DNS_TYPE_SSHFP & 0xff);
    msg[mlen++] = (u_char)(S3_SSHFP_DNS_CLASS_IN >> 8);
    msg[mlen++] = (u_char)(S3_SSHFP_DNS_CLASS_IN & 0xff);
    msg[mlen++] = 0;
    msg[mlen++] = 0;
    msg[mlen++] = 0;
    msg[mlen++] = 60; /* ttl */
    msg[mlen++] = (u_char)(34 >> 8);
    msg[mlen++] = (u_char)(34 & 0xff);
    s3_memcpy(msg + mlen, rd, 34);
    mlen += 34;

    n = 4;
    S3_ASSERT(s3_sshfp_response_parse(msg, mlen, pool, recs, &n, &rcode) == S3_ERROR);

    /* the reserved label type 0x40 of the reference badLabel */

    s3_memzero(msg, S3_SSHFP_DNS_HEADER_SIZE);
    msg[4] = 0;
    msg[5] = 1; /* QDCOUNT */
    mlen = S3_SSHFP_DNS_HEADER_SIZE;

    msg[mlen++] = 0x40;
    msg[mlen++] = 0x01;
    msg[mlen++] = 'a';
    msg[mlen++] = 0x00;
    msg[mlen++] = (u_char)(S3_SSHFP_DNS_TYPE_SSHFP >> 8);
    msg[mlen++] = (u_char)(S3_SSHFP_DNS_TYPE_SSHFP & 0xff);
    msg[mlen++] = (u_char)(S3_SSHFP_DNS_CLASS_IN >> 8);
    msg[mlen++] = (u_char)(S3_SSHFP_DNS_CLASS_IN & 0xff);

    n = 4;
    S3_ASSERT(s3_sshfp_response_parse(msg, mlen, pool, recs, &n, &rcode) == S3_ERROR);

    s3_destroy_pool(pool);

    return s3_test_failures;
}

/*
 * the reference TestSSHFPQueryName: the host key shapes, the ip
 * literals mapped to the reverse names, the case and the trailing
 * dot folded; the garbage the reference would carry verbatim is a
 * refusal here (the fail-closed charset gate)
 */

static int
s3_tf_query_name(void)
{
    char name[300];

    struct {
        const char *in;
        const char *want;
    } cases[] = {
        {"sshfp.example.org:443/ssh3-term", "sshfp.example.org"},
        {"sshfp.example.org:443", "sshfp.example.org"},
        {"sshfp.example.org/", "sshfp.example.org"},
        {"SSHFP.Example.ORG.:443/ssh3", "sshfp.example.org"},
        {"example.org", "example.org"},
        {"[2001:db8::1]:443/ssh3-term",
         "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"},
        {"192.0.2.1:443/", "1.2.0.192.in-addr.arpa"},
        {"192.0.2.7:443", "7.2.0.192.in-addr.arpa"},
    };

    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {

        S3_ASSERT(s3_sshfp_query_name(cases[i].in, name, sizeof(name)) == S3_OK);
        S3_ASSERT(s3_strcmp(name, cases[i].want) == 0);
    }

    /* the refusals: the empty key, the whitespace key, the unbalanced
     * brackets, the port-only garbage */

    S3_ASSERT(s3_sshfp_query_name("", name, sizeof(name)) == S3_ERROR);
    S3_ASSERT(s3_sshfp_query_name("   ", name, sizeof(name)) == S3_ERROR);
    S3_ASSERT(s3_sshfp_query_name("[2001:db8::1:443", name, sizeof(name)) == S3_ERROR);
    S3_ASSERT(s3_sshfp_query_name(":443", name, sizeof(name)) == S3_ERROR);
    S3_ASSERT(s3_sshfp_query_name("no such host", name, sizeof(name)) == S3_ERROR);

    return s3_test_failures;
}

/*
 * the digest vectors of "abc" (the FIPS 180 test vector, the same
 * value the reference digests of a certificate build on) and the
 * unknown digest type refusal
 */

static int
s3_tf_digest(void)
{
    u_char       out[32];
    size_t       n;
    const u_char sha1_want[20] = {0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
                                  0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d};
    const u_char sha256_want[32] = {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
                                    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
                                    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
                                    0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};

    S3_ASSERT(s3_sshfp_digest(S3_SSHFP_DIGEST_SHA1, (const u_char *)"abc", 3, out, &n) == S3_OK);
    S3_ASSERT(n == 20);
    S3_ASSERT(s3_memcmp(out, sha1_want, 20) == 0);

    S3_ASSERT(s3_sshfp_digest(S3_SSHFP_DIGEST_SHA256, (const u_char *)"abc", 3, out, &n) == S3_OK);
    S3_ASSERT(n == 32);
    S3_ASSERT(s3_memcmp(out, sha256_want, 32) == 0);

    S3_ASSERT(s3_sshfp_digest(9, (const u_char *)"abc", 3, out, &n) == S3_ERROR);

    return s3_test_failures;
}

/*
 * the algorithm map of the reference HostKeyAlgorithm: the rsa, the
 * ec and the ed25519 keys carry their sshfp numbers, the x25519 and
 * the missing key stay reserved
 */

static int
s3_tf_key_algorithm(void)
{
    S3_ASSERT(s3_sshfp_key_algorithm(g_rsa_cert) == S3_SSHFP_ALGO_RSA);
    S3_ASSERT(s3_sshfp_key_algorithm(g_ec_cert) == S3_SSHFP_ALGO_ECDSA);
    S3_ASSERT(s3_sshfp_key_algorithm(g_ed_cert) == S3_SSHFP_ALGO_ED25519);
    S3_ASSERT(s3_sshfp_key_algorithm(g_x25519_cert) == S3_SSHFP_ALGO_RESERVED);
    S3_ASSERT(s3_sshfp_key_algorithm(NULL) == S3_SSHFP_ALGO_RESERVED);

    return s3_test_failures;
}

/*
 * the reference record selection (SSHFP.Matches): the algorithm and
 * the digest type must agree, the fingerprint must carry the length
 * the digest implies, the bytes must compare equal in constant time
 */

static int
s3_tf_rec_matches(void)
{
    s3_sshfp_rec_t rec;
    u_char         fp[32];
    size_t         n;

    /* the matching sha-256 record */

    S3_ASSERT(s3_sshfp_digest(S3_SSHFP_DIGEST_SHA256, g_der, g_der_len, fp, &n) == S3_OK);
    S3_ASSERT(n == 32);

    s3_memzero(&rec, sizeof(rec));
    rec.algorithm = S3_SSHFP_ALGO_ECDSA;
    rec.digest_type = S3_SSHFP_DIGEST_SHA256;
    rec.fingerprint = fp;
    rec.fp_len = 32;

    S3_ASSERT(s3_sshfp_rec_matches(&rec, S3_SSHFP_ALGO_ECDSA, g_der, g_der_len) == 1);

    /* the matching sha-1 record */

    S3_ASSERT(s3_sshfp_digest(S3_SSHFP_DIGEST_SHA1, g_der, g_der_len, fp, &n) == S3_OK);
    S3_ASSERT(n == 20);

    rec.digest_type = S3_SSHFP_DIGEST_SHA1;
    rec.fp_len = 20;

    S3_ASSERT(s3_sshfp_rec_matches(&rec, S3_SSHFP_ALGO_ECDSA, g_der, g_der_len) == 1);

    /* the wrong algorithm number */

    rec.digest_type = S3_SSHFP_DIGEST_SHA256;
    rec.fp_len = 32;
    S3_ASSERT(s3_sshfp_digest(S3_SSHFP_DIGEST_SHA256, g_der, g_der_len, fp, &n) == S3_OK);
    S3_ASSERT(s3_sshfp_rec_matches(&rec, S3_SSHFP_ALGO_RSA, g_der, g_der_len) == 0);

    /* the wrong digest type for a matching value (the sha-1 label
     * over a 32-byte fingerprint) */

    rec.digest_type = S3_SSHFP_DIGEST_SHA1;
    S3_ASSERT(s3_sshfp_rec_matches(&rec, S3_SSHFP_ALGO_ECDSA, g_der, g_der_len) == 0);

    /* the truncated fingerprint */

    rec.digest_type = S3_SSHFP_DIGEST_SHA256;
    rec.fp_len = 16;
    S3_ASSERT(s3_sshfp_rec_matches(&rec, S3_SSHFP_ALGO_ECDSA, g_der, g_der_len) == 0);

    /* the unknown digest type */

    rec.digest_type = 9;
    rec.fp_len = 32;
    S3_ASSERT(s3_sshfp_rec_matches(&rec, S3_SSHFP_ALGO_ECDSA, g_der, g_der_len) == 0);

    /* the tampered byte and the reserved algorithm of the presented
     * key */

    rec.digest_type = S3_SSHFP_DIGEST_SHA256;
    fp[31] ^= 0x01;
    S3_ASSERT(s3_sshfp_rec_matches(&rec, S3_SSHFP_ALGO_ECDSA, g_der, g_der_len) == 0);
    fp[31] ^= 0x01;
    S3_ASSERT(s3_sshfp_rec_matches(&rec, S3_SSHFP_ALGO_RESERVED, g_der, g_der_len) == 0);

    /* the missing record */

    S3_ASSERT(s3_sshfp_rec_matches(NULL, S3_SSHFP_ALGO_ECDSA, g_der, g_der_len) == 0);

    return s3_test_failures;
}

#if !S3_WIN32

/*
 * @local: the live verdict over the loopback udp stub of the
 * reference TestUDPSSHFPResolver -- the socket binds before the
 * fork, the child answers the first datagram with the prepared
 * message (the id patched from the query), the parent runs
 * s3_sshfp_check over the S3_SSHFP_DNS hook.  the bounded cases
 * (the wrong id, the dead port) ride the same path.
 */

static int
s3_tf_stub_bind(int *sfd, int *port)
{
    struct sockaddr_in sa;
    socklen_t          slen = sizeof(sa);
    int                fd;
    struct timeval     tv;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    S3_ASSERT(fd >= 0);

    s3_memzero(&sa, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;

    S3_ASSERT(bind(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0);
    S3_ASSERT(getsockname(fd, (struct sockaddr *)&sa, &slen) == 0);

    /* the stub receive bound: a child that never sees the query
     * leaves after the timeout instead of hanging the test */

    tv.tv_sec = 2;
    tv.tv_usec = 0;
    S3_ASSERT(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0);

    *sfd = fd;
    *port = ntohs(sa.sin_port);

    return s3_test_failures;
}

/*
 * forks the answering child: the first datagram is the query, the
 * answer goes back with the echoed id (a wrong id when wrong_id is
 * set); the parent runs the lookup between the fork and the join
 */

static pid_t
s3_tf_stub_fork(int sfd, const u_char *answer, size_t alen, unsigned wrong_id)
{
    pid_t pid = fork();

    S3_ASSERT(pid >= 0);

    if (pid == 0) {

        u_char             qbuf[512], out[320];
        struct sockaddr_in cli;
        socklen_t          clen = sizeof(cli);
        ssize_t            n = recvfrom(sfd, qbuf, sizeof(qbuf), 0, (struct sockaddr *)&cli, &clen);

        if (n >= 12 && ((unsigned)qbuf[n - 4] << 8 | qbuf[n - 3]) == S3_SSHFP_DNS_TYPE_SSHFP &&
            alen <= sizeof(out) && alen >= 2) {
            s3_memcpy(out, answer, alen);

            if (wrong_id) {
                out[0] = (u_char)(qbuf[0] + 1);
                out[1] = qbuf[1];

            } else {
                out[0] = qbuf[0];
                out[1] = qbuf[1];
            }

            (void)sendto(sfd, out, alen, 0, (struct sockaddr *)&cli, clen);
        }

        _exit(0);
    }

    return pid;
}

static void
s3_tf_stub_join(pid_t pid)
{
    int st;

    S3_ASSERT(waitpid(pid, &st, 0) == pid);
    S3_ASSERT(WIFEXITED(st) && WEXITSTATUS(st) == 0);
}

static int
s3_tf_check_live(void)
{
    s3_log_t          log;
    s3_pool_t        *pool;
    s3_sshfp_rec_t    matched;
    u_char            answer[256], fp[32], rd[34];
    char              errbuf[256], env[64];
    size_t            alen, rlen, n;
    int               sfd = -1, port = 0;
    pid_t             pid;
    s3_sshfp_status_t status;
    time_t            start;

    log.log_level = S3_LOG_ALERT;
    log.fd = S3_INVALID_FILE;
    pool = s3_create_pool(4096, &log);
    S3_ASSERT(pool != NULL);

    (void)s3_tf_stub_bind(&sfd, &port);
    snprintf(env, sizeof(env), "127.0.0.1:%d", port);
    S3_ASSERT(setenv("S3_SSHFP_DNS", env, 1) == 0);

    /* the verified verdict: one ec/sha-256 record carrying the real
     * der digest of the fixture certificate */

    S3_ASSERT(s3_sshfp_digest(S3_SSHFP_DIGEST_SHA256, g_der, g_der_len, fp, &n) == S3_OK);
    rlen = s3_tf_sshfp_rdata(rd, S3_SSHFP_ALGO_ECDSA, S3_SSHFP_DIGEST_SHA256, fp, 32);
    S3_ASSERT(rlen == 34);

    {
        s3_tf_rr_t rr;

        rr.name = NULL;
        rr.ptr = 12;
        rr.type = 44;
        rr.class = 1;
        rr.ttl = 60;
        rr.rdata = rd;
        rr.rdlen = 34;

        alen = s3_tf_msg(answer, sizeof(answer), 0 /* the id rides from the query */, 0x8000,
                         "sshfp.example.org", &rr, 1);
    }

    S3_ASSERT(alen > 0);

    s3_memzero(&matched, sizeof(matched));
    errbuf[0] = '\0';

    pid = s3_tf_stub_fork(sfd, answer, alen, 0);

    status = s3_sshfp_check("sshfp.example.org", g_cert, g_der, g_der_len, pool, &matched, errbuf,
                            sizeof(errbuf));

    s3_tf_stub_join(pid);

    S3_ASSERT(status == S3_SSHFP_VERIFIED);
    S3_ASSERT(matched.algorithm == S3_SSHFP_ALGO_ECDSA);
    S3_ASSERT(matched.digest_type == S3_SSHFP_DIGEST_SHA256);
    S3_ASSERT(matched.fp_len == 32);
    S3_ASSERT(s3_memcmp(matched.fingerprint, fp, 32) == 0);
    S3_ASSERT(errbuf[0] == '\0');

    /* the NXDOMAIN verdict: authoritative no-records stays soft */

    alen = s3_tf_msg(answer, sizeof(answer), 0, (uint16_t)(0x8000 | S3_SSHFP_RCODE_NXDOMAIN),
                     "sshfp.example.org", NULL, 0);
    S3_ASSERT(alen > 0);

    errbuf[0] = '\0';

    pid = s3_tf_stub_fork(sfd, answer, alen, 0);

    status = s3_sshfp_check("sshfp.example.org", g_cert, g_der, g_der_len, pool, NULL, errbuf,
                            sizeof(errbuf));

    s3_tf_stub_join(pid);

    S3_ASSERT(status == S3_SSHFP_NO_RECORDS);
    S3_ASSERT(errbuf[0] == '\0');

    /* the wrong id: the answer does not belong to the query, the
     * server is left and the lookup fails soft */

    alen = s3_tf_msg(answer, sizeof(answer), 0, 0x8000, "sshfp.example.org", NULL, 0);
    S3_ASSERT(alen > 0);

    errbuf[0] = '\0';

    pid = s3_tf_stub_fork(sfd, answer, alen, 1);

    status = s3_sshfp_check("sshfp.example.org", g_cert, g_der, g_der_len, pool, NULL, errbuf,
                            sizeof(errbuf));

    s3_tf_stub_join(pid);

    S3_ASSERT(status == S3_SSHFP_LOOKUP_FAILED);
    S3_ASSERT(errbuf[0] != '\0');

    /* the dead port: nothing listens there, the failure is bounded */

    S3_ASSERT(setenv("S3_SSHFP_DNS", "127.0.0.1:1", 1) == 0);

    start = time(NULL);

    status = s3_sshfp_check("sshfp.example.org", g_cert, g_der, g_der_len, pool, NULL, errbuf,
                            sizeof(errbuf));

    S3_ASSERT(status == S3_SSHFP_LOOKUP_FAILED);
    S3_ASSERT(errbuf[0] != '\0');
    S3_ASSERT(time(NULL) - start <= 3);

    (void)s3_test_close(sfd);
    s3_destroy_pool(pool);

    return s3_test_failures;
}

#else /* S3_WIN32 */

/*
 * @local: the loopback stub rides fork(2), the windows legs of the
 * suite keep the parser-level fixtures and skip the live verdict
 * (the same shape the reference resolver test takes on a platform
 * without a fork)
 */

static int
s3_tf_check_live(void)
{
    return s3_test_failures;
}

#endif

/*
 * the reference TestCheckSSHFPPreconditions over the C seam: no
 * certificate is a not-checked verdict, no pool is a lookup failure,
 * and neither touches the caller's matched record.  the no-server
 * branch of the reference stays unexercised here: with the env unset
 * the system list of the test host decides, and a live query to the
 * host resolver is exactly what the unit pins avoid
 */

static int
s3_tf_check_preconditions(void)
{
    s3_log_t       log;
    s3_pool_t     *pool;
    s3_sshfp_rec_t matched;
    char           errbuf[64];

    log.log_level = S3_LOG_ALERT;
    log.fd = S3_INVALID_FILE;
    pool = s3_create_pool(4096, &log);
    S3_ASSERT(pool != NULL);

    /* the no-certificate precondition rides before any dns work */

    s3_memzero(&matched, sizeof(matched));
    errbuf[0] = '\0';

    S3_ASSERT(s3_sshfp_check("sshfp.example.org", NULL, g_der, g_der_len, pool, &matched, errbuf,
                             sizeof(errbuf)) == S3_SSHFP_NOT_CHECKED);
    S3_ASSERT(matched.fingerprint == NULL);
    S3_ASSERT(errbuf[0] == '\0');

    /* the missing pool: the records have nowhere to land, the
     * verdict is the lookup failure with the reason */

    s3_memzero(&matched, sizeof(matched));
    errbuf[0] = '\0';

    S3_ASSERT(s3_sshfp_check("sshfp.example.org", g_cert, g_der, g_der_len, NULL, &matched, errbuf,
                             sizeof(errbuf)) == S3_SSHFP_LOOKUP_FAILED);
    S3_ASSERT(errbuf[0] != '\0');
    S3_ASSERT(matched.fingerprint == NULL);

    s3_destroy_pool(pool);

    return s3_test_failures;
}

static int
s3_tf_all(void)
{
    (void)s3_tf_fixtures();

    if (s3_test_failures > 0) {
        return s3_test_failures;
    }

    (void)s3_tf_query_build();
    (void)s3_tf_parse();
    (void)s3_tf_parse_compression();
    (void)s3_tf_parse_norecs();
    (void)s3_tf_parse_malformed();
    (void)s3_tf_query_name();
    (void)s3_tf_digest();
    (void)s3_tf_key_algorithm();
    (void)s3_tf_rec_matches();
    (void)s3_tf_check_preconditions();
    (void)s3_tf_check_live();

    return s3_test_failures;
}

S3_TEST_MAIN(s3_tf_all)
