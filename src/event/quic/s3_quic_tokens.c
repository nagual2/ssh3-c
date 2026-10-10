/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <s3_udp_msg.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <time.h>

#include <s3_quic.h>
#include <s3_quic_tokens.h>

/*
 * D1 has no realtime clock cache yet; the nginx ngx_time() seconds are
 * substituted with time(2)
 */
#define s3_quic_token_time() time(NULL)

void
s3_quic_address_hash(struct sockaddr *sockaddr, socklen_t socklen, s3_uint_t no_port, u_char *salt,
                     size_t saltlen, u_char buf[20])
{
    size_t              len;
    u_char             *data;
    unsigned int        mdlen;
    struct sockaddr_in *sin;
    EVP_MD_CTX         *ctx;
#if (S3_HAVE_INET6)
    struct sockaddr_in6 *sin6;
#endif

    len = (size_t)socklen;
    data = (u_char *)sockaddr;

    if (no_port) {
        switch (sockaddr->sa_family) {

#if (S3_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *)sockaddr;

            len = sizeof(struct in6_addr);
            data = sin6->sin6_addr.s6_addr;

            break;
#endif

        case AF_INET:
            sin = (struct sockaddr_in *)sockaddr;

            len = sizeof(in_addr_t);
            data = (u_char *)&sin->sin_addr;

            break;

        default:
            break;
        }
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL || EVP_DigestInit_ex(ctx, EVP_sha1(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, data, len) != 1 ||
        (salt && EVP_DigestUpdate(ctx, salt, saltlen) != 1) ||
        EVP_DigestFinal_ex(ctx, buf, &mdlen) != 1) {
        if (ctx) {
            EVP_MD_CTX_free(ctx);
        }

        s3_memzero(buf, 20);

        return;
    }

    EVP_MD_CTX_free(ctx);
}

s3_int_t
s3_quic_new_sr_token(s3_connection_t *c, s3_str_t *cid, u_char *secret, u_char *token)
{
    s3_str_t tmp;
    u_char   buf[S3_QUIC_SR_KEY_LEN + sizeof(s3_uint_t)];

    /*
     * ssh3-c is a single event loop, so there is no worker index to
     * mix into the secret (nginx appends ngx_worker)
     */
    s3_memcpy(buf, secret, S3_QUIC_SR_KEY_LEN);
    s3_memzero(buf + S3_QUIC_SR_KEY_LEN, sizeof(s3_uint_t));

    tmp.data = buf;
    tmp.len = sizeof(buf);

    if (s3_quic_derive_key(c->log, "sr_token_key", &tmp, cid, token, S3_QUIC_SR_TOKEN_LEN) !=
        S3_OK) {
        return S3_ERROR;
    }

    s3_log_debug2(S3_LOG_DEBUG_EVENT, c->log, 0, "quic stateless reset token %*xs",
                  (size_t)S3_QUIC_SR_TOKEN_LEN, token);

    return S3_OK;
}

s3_int_t
s3_quic_new_token(s3_log_t *log, struct sockaddr *sockaddr, socklen_t socklen, u_char *key,
                  s3_str_t *token, s3_str_t *odcid, time_t exp, s3_uint_t is_retry)
{
    int               len, iv_len;
    u_char           *p, *iv;
    EVP_CIPHER_CTX   *ctx;
    const EVP_CIPHER *cipher;

    u_char in[S3_QUIC_MAX_TOKEN_SIZE];

    s3_quic_address_hash(sockaddr, socklen, !is_retry, NULL, 0, in);

    p = in + 20;

    p = s3_cpymem(p, &exp, sizeof(time_t));

    *p++ = is_retry ? 1 : 0;

    if (odcid) {
        *p++ = odcid->len;
        p = s3_cpymem(p, odcid->data, odcid->len);

    } else {
        *p++ = 0;
    }

    len = p - in;

    cipher = EVP_aes_256_gcm();
    iv_len = S3_QUIC_AES_256_GCM_IV_LEN;

    if ((size_t)iv_len + (size_t)len + S3_QUIC_AES_256_GCM_TAG_LEN > token->len) {
        s3_log_error(S3_LOG_ALERT, log, 0, "quic token buffer is too small");
        return S3_ERROR;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return S3_ERROR;
    }

    iv = token->data;

    if (RAND_bytes(iv, iv_len) <= 0 || !EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return S3_ERROR;
    }

    token->len = iv_len;

    if (EVP_EncryptUpdate(ctx, token->data + token->len, &len, in, len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return S3_ERROR;
    }

    token->len += len;

    if (EVP_EncryptFinal_ex(ctx, token->data + token->len, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return S3_ERROR;
    }

    token->len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, S3_QUIC_AES_256_GCM_TAG_LEN,
                            token->data + token->len) == 0) {
        EVP_CIPHER_CTX_free(ctx);
        return S3_ERROR;
    }

    token->len += S3_QUIC_AES_256_GCM_TAG_LEN;

    EVP_CIPHER_CTX_free(ctx);

    return S3_OK;
}

s3_int_t
s3_quic_validate_token(s3_connection_t *c, u_char *key, s3_quic_header_t *pkt)
{
    int               len, tlen, iv_len;
    u_char           *iv, *p;
    time_t            now, exp;
    size_t            total;
    s3_str_t          odcid;
    EVP_CIPHER_CTX   *ctx;
    const EVP_CIPHER *cipher;

    u_char addr_hash[20];
    u_char tdec[S3_QUIC_MAX_TOKEN_SIZE];

    s3_str_null(&odcid);

    /* Retry token or NEW_TOKEN in a previous connection */

    cipher = EVP_aes_256_gcm();
    iv = pkt->token.data;
    iv_len = S3_QUIC_AES_256_GCM_IV_LEN;

    /* sanity checks */

    if (pkt->token.len < (size_t)iv_len + S3_QUIC_AES_256_GCM_TAG_LEN) {
        goto garbage;
    }

    if (pkt->token.len > (size_t)iv_len + S3_QUIC_MAX_TOKEN_SIZE + S3_QUIC_AES_256_GCM_TAG_LEN) {
        goto garbage;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return S3_ERROR;
    }

    if (!EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return S3_ERROR;
    }

    p = pkt->token.data + iv_len;
    len = pkt->token.len - iv_len - S3_QUIC_AES_256_GCM_TAG_LEN;

    if (EVP_DecryptUpdate(ctx, tdec, &tlen, p, len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        goto garbage;
    }
    total = tlen;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, S3_QUIC_AES_256_GCM_TAG_LEN, p + len) ==
        0) {
        EVP_CIPHER_CTX_free(ctx);
        goto garbage;
    }

    if (EVP_DecryptFinal_ex(ctx, tdec + tlen, &tlen) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        goto garbage;
    }
    total += tlen;

    EVP_CIPHER_CTX_free(ctx);

    if (total < (20 + sizeof(time_t) + 2)) {
        goto garbage;
    }

    p = tdec + 20;

    s3_memcpy(&exp, p, sizeof(time_t));
    p += sizeof(time_t);

    pkt->retried = (*p++ == 1);

    s3_quic_address_hash(c->sockaddr, c->socklen, !pkt->retried, NULL, 0, addr_hash);

    if (s3_memcmp(tdec, addr_hash, 20) != 0) {
        goto bad_token;
    }

    odcid.len = *p++;
    if (odcid.len) {
        if (odcid.len > S3_QUIC_MAX_CID_LEN) {
            goto bad_token;
        }

        if ((size_t)(tdec + total - p) < odcid.len) {
            goto bad_token;
        }

        odcid.data = p;
    }

    now = s3_quic_token_time();

    if (now > exp) {
        s3_log_error(S3_LOG_INFO, c->log, 0, "quic expired token");
        return S3_DECLINED;
    }

    if (odcid.len) {
        pkt->odcid.len = odcid.len;
        pkt->odcid.data = pkt->odcid_buf;
        s3_memcpy(pkt->odcid.data, odcid.data, odcid.len);

    } else {
        pkt->odcid = pkt->dcid;
    }

    pkt->validated = 1;

    return S3_OK;

garbage:

    s3_log_error(S3_LOG_INFO, c->log, 0, "quic garbage token");

    return S3_ABORT;

bad_token:

    s3_log_error(S3_LOG_INFO, c->log, 0, "quic invalid token");

    return S3_DECLINED;
}
