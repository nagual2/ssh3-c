/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_SSH3_OIDC_H_INCLUDED_
#define _S3_SSH3_OIDC_H_INCLUDED_

#include <openssl/evp.h>
#include <openssl/ssl.h>

#include <time.h>

#include <s3_core.h>

/*
 * the OIDC token verification of the reference server_auth/ chain
 * (the fork server_auth/authorized_identities.go OpenIDConnectIdentity
 * Verify on top of the vendored coreos/go-oidc): the provider
 * discovery, the JWKS fetch with the kid cache and the id_token
 * verification (the signature of the provider keys, iss, aud, exp and
 * the conversation nonce); the conversation nonce rides the
 * EXPORTER-SSH3 TLS exporter like the reference ConversationID
 */

/* the reject reasons of s3_ssh3_oidc_verify() beyond the s3 codes */

#define S3_SSH3_OIDC_EFORM  (-10) /* the malformed jwt envelope */
#define S3_SSH3_OIDC_EALG   (-11) /* the alg outside the allowlist or off the key */
#define S3_SSH3_OIDC_EKID   (-12) /* the kid unknown to the cached key set */
#define S3_SSH3_OIDC_ESIG   (-13) /* the signature mismatch */
#define S3_SSH3_OIDC_EISS   (-14) /* the issuer claim mismatch */
#define S3_SSH3_OIDC_EAUD   (-15) /* the audience claim misses the client id */
#define S3_SSH3_OIDC_EEXP   (-16) /* the exp (or nbf) time gate */
#define S3_SSH3_OIDC_ENONCE (-17) /* the nonce claim mismatch */

#define S3_SSH3_OIDC_URL_MAX  512
#define S3_SSH3_OIDC_KID_MAX  64
#define S3_SSH3_OIDC_ALG_MAX  8
#define S3_SSH3_OIDC_KEYS_MAX 8

/* the discovery document (the flat members the port speaks) */

typedef struct {
    char issuer[S3_SSH3_OIDC_URL_MAX];
    char authorization_endpoint[S3_SSH3_OIDC_URL_MAX];
    char token_endpoint[S3_SSH3_OIDC_URL_MAX];
    char jwks_uri[S3_SSH3_OIDC_URL_MAX];
} s3_ssh3_oidc_provider_t;

/* one provider key of the key set, the kid decides */

typedef struct s3_ssh3_oidc_key_s {
    char      kid[S3_SSH3_OIDC_KID_MAX];
    unsigned  ec; /* 1 = EC P-256 (ES256), 0 = RSA (RS256) */
    EVP_PKEY *pkey;
} s3_ssh3_oidc_key_t;

typedef struct {
    s3_ssh3_oidc_key_t keys[S3_SSH3_OIDC_KEYS_MAX];
    size_t             nkeys;
} s3_ssh3_oidc_jwks_t;

/*
 * the verifier of one issuer: the discovery and the JWKS fetch run on
 * the first verify, the unknown kid triggers one refresh (the provider
 * key rotation); the offline form skips the network - the tests parse
 * the key sets in by hand
 */

typedef struct {
    char                    issuer[S3_SSH3_OIDC_URL_MAX];
    char                    ca_file[S3_SSH3_OIDC_URL_MAX];
    s3_ssh3_oidc_provider_t provider;
    unsigned                provider_ready;
    s3_ssh3_oidc_jwks_t     jwks;
} s3_ssh3_oidc_verifier_t;

/*
 * the shared base64url (RFC 4648, the JWS alphabet, no padding on the
 * encode); the decode takes the padded and the unpadded forms and
 * returns the length in *dlen
 */

size_t   s3_ssh3_oidc_b64url_encode(const u_char *in, size_t len, u_char *out);
s3_int_t s3_ssh3_oidc_b64url_decode(const u_char *in, size_t len, u_char *out, size_t *dlen);

/*
 * the DER form of one ECDSA raw JWS signature (r||s, the coordinate
 * size halves the buffer): the verify path feeds the DER to OpenSSL;
 * exported for the test signer
 */

s3_int_t s3_ssh3_oidc_ecdsa_der_to_raw(const u_char *der, size_t der_len, u_char *raw,
                                       size_t coord_len);

/*
 * the flat-JSON members of the discovery document, the jwt claims and
 * the JWK objects: S3_OK fills the output, S3_DECLINED when the
 * member is absent (or the wrong shape), S3_ERROR on the broken JSON
 */

s3_int_t s3_ssh3_oidc_json_find(const s3_str_t *obj, const char *name, s3_str_t *value);
s3_int_t s3_ssh3_oidc_json_string(const s3_str_t *obj, const char *name, char *buf, size_t max);
s3_int_t s3_ssh3_oidc_json_int(const s3_str_t *obj, const char *name, int64_t *out);

/* the aud claim holds one string or an array of strings */

s3_int_t s3_ssh3_oidc_json_aud_contains(const s3_str_t *claims, const char *want);

/*
 * the provider discovery: GET {issuer}/.well-known/openid-configuration,
 * the returned issuer must match the requested one (the go-oidc
 * Provider check); the http:// form serves the loopback test issuers
 */

s3_int_t s3_ssh3_oidc_discover(const char *issuer_url, const char *ca_file,
                               s3_ssh3_oidc_provider_t *out);

/*
 * the key set: the parse adds the keys to the set (the same kid
 * replaces its key), the fetch replaces the whole set (the provider
 * rotation); both speak the RSA n/e and the EC P-256 crv/x/y JWKs
 */

s3_int_t s3_ssh3_oidc_jwks_parse(s3_ssh3_oidc_jwks_t *jwks, const u_char *json, size_t len);
s3_int_t s3_ssh3_oidc_jwks_fetch(const s3_ssh3_oidc_provider_t *provider, const char *ca_file,
                                 s3_ssh3_oidc_jwks_t *jwks);
void     s3_ssh3_oidc_jwks_clear(s3_ssh3_oidc_jwks_t *jwks);

/*
 * the id_token verification: the claims gates run first (the cheap
 * checks of the go-oidc Verify), the signature against the kid key
 * closes; nonce NULL or empty skips the nonce gate, like the
 * reference VerifyRawToken with the empty expected nonce
 */

s3_int_t s3_ssh3_oidc_verify(const s3_ssh3_oidc_jwks_t *jwks, const char *issuer,
                             const char *audience, const char *token, const char *nonce,
                             time_t now);

s3_int_t s3_ssh3_oidc_verifier_init(s3_ssh3_oidc_verifier_t *v, const char *issuer,
                                    const char *ca_file);
s3_int_t s3_ssh3_oidc_verifier_init_offline(s3_ssh3_oidc_verifier_t *v, const char *issuer);
s3_int_t s3_ssh3_oidc_verifier_verify(s3_ssh3_oidc_verifier_t *v, const char *audience,
                                      const char *token, const char *nonce, time_t now);
void     s3_ssh3_oidc_verifier_clear(s3_ssh3_oidc_verifier_t *v);

/*
 * the conversation nonce of the reference: base64(TLS exporter
 * "EXPORTER-SSH3", 32 bytes), the same string both sides derive from
 * the live TLS session (the fork ConversationID.String())
 */

s3_int_t s3_ssh3_oidc_conversation_nonce(SSL *ssl, char *out /* 45 bytes at least */);

#endif /* _S3_SSH3_OIDC_H_INCLUDED_ */
