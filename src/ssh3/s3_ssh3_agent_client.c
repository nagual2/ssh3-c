/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the ssh agent protocol client (draft-miller-ssh-agent): the wire
 * codec and the unix socket flow, the reference is the agent signing
 * method of the Go fork (the SignatureFlagRsaSha256 pin)
 */

#include <s3_ssh3_agent_client.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !(S3_WIN32)
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#else
#include <windows.h>
#endif

/* the message codes of the agent protocol */

#define S3_AGENT_FAILURE            5u
#define S3_AGENT_REQUEST_IDENTITIES 11u
#define S3_AGENT_IDENTITIES_ANSWER  12u
#define S3_AGENT_SIGN_REQUEST       13u
#define S3_AGENT_SIGN_RESPONSE      14u

/* the signature flags: the rsa keys sign the sha-256 variant (the
 * SignatureFlagRsaSha256 of the reference, the legacy ssh-rsa hash
 * never rides) */

#define S3_AGENT_RSA_SHA2_256 2u

static void
s3_put_be32(u_char *p, uint32_t v)
{
    p[0] = (u_char)(v >> 24);
    p[1] = (u_char)(v >> 16);
    p[2] = (u_char)(v >> 8);
    p[3] = (u_char)v;
}

static uint32_t
s3_get_be32(const u_char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* the base64 decode of the authorized_keys body (the standard alphabet,
 * the padding optional) */

static int
s3_agent_b64dec(const char *src, u_char *dst, size_t cap, size_t *dlen)
{
    int      tbl[256];
    u_int    acc = 0;
    unsigned bits = 0, n = 0;
    size_t   out = 0;

    for (n = 0; n < 256; n++) {
        tbl[n] = -1;
    }

    for (n = 0; n < 64; n++) {
        tbl[(int)("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[n])] = (int)n;
    }

    for (; *src != '\0' && *src != '\n' && *src != '\r' && *src != ' ' && *src != '\t'; src++) {

        if (*src == '=') {
            break;
        }

        if (tbl[(u_char)*src] < 0) {
            return -1;
        }

        acc = (acc << 6) | (u_int)tbl[(u_char)*src];
        bits += 6;

        if (bits >= 8) {
            bits -= 8;

            if (out >= cap) {
                return -1;
            }

            dst[out++] = (u_char)(acc >> bits);
        }
    }

    *dlen = out;

    return 0;
}

s3_int_t
s3_ssh3_agent_cli_pubkey_file(const char *path, u_char *blob, size_t cap, size_t *blen)
{
    FILE  *f;
    char   line[8192], *sp;
    size_t out = 0;

    f = fopen(path, "rb");

    if (f == NULL) {
        return S3_ERROR;
    }

    while (fgets(line, sizeof(line), f) != NULL) {

        sp = strpbrk(line, " \t\r\n");

        if (sp == NULL) {
            continue;
        }

        /* the first field is the algo name, the base64 body follows
         * (the skip starts past the terminator the cut left) */

        *sp = '\0';

        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }

        sp++;

        while (*sp == ' ' || *sp == '\t') {
            sp++;
        }

        if (s3_agent_b64dec(sp, blob, cap, &out) != 0 || out == 0) {
            fclose(f);
            return S3_ERROR;
        }

        fclose(f);
        *blen = out;

        return S3_OK;
    }

    fclose(f);

    return S3_ERROR;
}

size_t
s3_ssh3_agent_cli_req_identities(u_char *p)
{
    s3_put_be32(p, 1);
    p[4] = (u_char)S3_AGENT_REQUEST_IDENTITIES;

    return 5;
}

size_t
s3_ssh3_agent_cli_req_sign(u_char *p, const u_char *blob, size_t blen, const u_char *data,
                           size_t dlen)
{
    u_char  *body = p + 4;
    u_char  *q = body;
    uint32_t flags = 0;
    size_t   n;

    /* the algo rides the head of the key blob: the rsa keys sign the
     * sha-256 variant, the rest take the default */

    if (blen >= 4 + 7 && memcmp(blob + 4, "ssh-rsa", 7) == 0) {
        flags = S3_AGENT_RSA_SHA2_256;
    }

    *q++ = (u_char)S3_AGENT_SIGN_REQUEST;
    s3_put_be32(q, (uint32_t)blen);
    q += 4;
    memcpy(q, blob, blen);
    q += blen;

    s3_put_be32(q, (uint32_t)dlen);
    q += 4;
    memcpy(q, data, dlen);
    q += dlen;

    s3_put_be32(q, flags);
    q += 4;

    n = (size_t)(q - body);
    s3_put_be32(p, (uint32_t)n);

    return n + 4;
}

s3_int_t
s3_ssh3_agent_cli_parse_identities(const u_char *reply, size_t len, s3_str_t *blobs, size_t *nblobs,
                                   size_t cap)
{
    const u_char *p, *end;
    uint32_t      n, i;

    if (len < 9 || reply[4] != (u_char)S3_AGENT_IDENTITIES_ANSWER) {
        return S3_ERROR;
    }

    n = s3_get_be32(reply + 5);

    if (n > cap) {
        return S3_ERROR;
    }

    p = reply + 9;
    end = reply + len;

    for (i = 0; i < n; i++) {

        if ((size_t)(end - p) < 4) {
            return S3_ERROR;
        }

        blobs[i].len = s3_get_be32(p);
        p += 4;

        if ((size_t)(end - p) < blobs[i].len + 4) {
            return S3_ERROR;
        }

        blobs[i].data = (u_char *)p;
        p += blobs[i].len;

        /* the comment string follows: skipped, the views ride */

        p += s3_get_be32(p) + 4;

        if (p > end) {
            return S3_ERROR;
        }
    }

    *nblobs = n;

    return S3_OK;
}

s3_int_t
s3_ssh3_agent_cli_parse_sign(const u_char *reply, size_t len, u_char *sig, size_t sig_cap,
                             size_t *sig_len, char *alg, size_t alg_cap)
{
    const u_char *p, *end;
    uint32_t      alen, slen;

    if (len < 5) {
        return S3_ERROR;
    }

    if (reply[4] == (u_char)S3_AGENT_FAILURE) {

        /* the agent does not hold the key or refused to sign */

        return S3_DECLINED;
    }

    if (reply[4] != (u_char)S3_AGENT_SIGN_RESPONSE || len < 14) {
        return S3_ERROR;
    }

    p = reply + 5;

    /* the flags of the reply: skipped (the request shaped them) */

    p += 4;

    /* the signature blob: the algo string + the raw bytes */

    alen = s3_get_be32(p);
    p += 4;

    if ((size_t)(len - (p - reply)) < alen + 4) {
        return S3_ERROR;
    }

    if (alen == 11 && memcmp(p, "ssh-ed25519", 11) == 0) {
        snprintf(alg, alg_cap, "EdDSA");

    } else if (alen == 12 && memcmp(p, "rsa-sha2-256", 12) == 0) {
        snprintf(alg, alg_cap, "RS256");

    } else {
        return S3_ERROR;
    }

    p += alen;

    slen = s3_get_be32(p);
    p += 4;

    if ((size_t)(len - (p - reply)) < slen || slen > sig_cap) {
        return S3_ERROR;
    }

    memcpy(sig, p, slen);
    *sig_len = slen;

    end = reply + len;

    if (p + slen != end) {
        return S3_ERROR;
    }

    return S3_OK;
}

#if (S3_WIN32)

/* the win agent rides the named pipe of OpenSSH for Windows: the sock
 * argument carries the pipe text when the caller resolved one, the
 * OpenSSH default pipe serves otherwise; the exchange is the same
 * u32-framed request/reply the unix socket flow speaks, the pipe is
 * byte-mode sync and closes after the exchange */

#define S3_AGENT_PIPE_DEFAULT "\\\\.\\pipe\\openssh-ssh-agent"

s3_int_t
s3_ssh3_agent_cli_sign(const char *sock, const u_char *blob, size_t blen, const u_char *data,
                       size_t dlen, u_char *sig, size_t sig_cap, size_t *sig_len, char *alg,
                       size_t alg_cap)
{
    const char *pipe_name = (sock != NULL && sock[0] != '\0') ? sock : S3_AGENT_PIPE_DEFAULT;
    wchar_t     wpipe[256];
    HANDLE      pipe;
    u_char      req[8192], reply[8192];
    size_t      req_len, got;
    uint32_t    rlen;
    DWORD       put, n;
    int         wn;

    wn = MultiByteToWideChar(CP_UTF8, 0, pipe_name, -1, wpipe, 256);

    if (wn <= 0) {
        return S3_ERROR;
    }

    pipe = CreateFileW(wpipe, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

    if (pipe == INVALID_HANDLE_VALUE) {
        return S3_ERROR;
    }

    req_len = s3_ssh3_agent_cli_req_sign(req, blob, blen, data, dlen);

    if (!WriteFile(pipe, req, (DWORD)req_len, &put, NULL) || put != (DWORD)req_len) {
        CloseHandle(pipe);
        return S3_ERROR;
    }

    got = 0;

    while (got < 4) {

        if (!ReadFile(pipe, reply + got, (DWORD)(4 - got), &n, NULL) || n == 0) {
            CloseHandle(pipe);
            return S3_ERROR;
        }

        got += n;
    }

    rlen = s3_get_be32(reply);

    if (rlen < 1 || rlen > sizeof(reply) - 4) {
        CloseHandle(pipe);
        return S3_ERROR;
    }

    while (got < (size_t)rlen + 4) {

        if (!ReadFile(pipe, reply + got, (DWORD)(rlen + 4 - got), &n, NULL) || n == 0) {
            CloseHandle(pipe);
            return S3_ERROR;
        }

        got += n;
    }

    CloseHandle(pipe);

    return s3_ssh3_agent_cli_parse_sign(reply, 4 + rlen, sig, sig_cap, sig_len, alg, alg_cap);
}

#else

s3_int_t
s3_ssh3_agent_cli_sign(const char *sock, const u_char *blob, size_t blen, const u_char *data,
                       size_t dlen, u_char *sig, size_t sig_cap, size_t *sig_len, char *alg,
                       size_t alg_cap)
{
    int                fd, n;
    struct sockaddr_un addr;
    u_char             req[8192], reply[8192];
    size_t             req_len;
    uint32_t           rlen;
    ssize_t            got;

    if (sock == NULL || sock[0] == '\0') {
        return S3_ERROR;
    }

    fd = socket(AF_UNIX, SOCK_STREAM, 0);

    if (fd < 0) {
        return S3_ERROR;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;

    if (strlen(sock) >= sizeof(addr.sun_path)) {
        close(fd);
        return S3_ERROR;
    }

    strcpy(addr.sun_path, sock);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return S3_ERROR;
    }

    req_len = s3_ssh3_agent_cli_req_sign(req, blob, blen, data, dlen);

    if (write(fd, req, req_len) != (ssize_t)req_len) {
        close(fd);
        return S3_ERROR;
    }

    /* the reply: the u32 framing first, then the payload */

    got = read(fd, reply, 4);

    if (got != 4) {
        close(fd);
        return S3_ERROR;
    }

    rlen = s3_get_be32(reply);

    if (rlen < 1 || rlen > sizeof(reply) - 4) {
        close(fd);
        return S3_ERROR;
    }

    got = 0;

    while ((size_t)got < rlen) {

        n = (int)read(fd, reply + 4 + got, rlen - got);

        if (n <= 0) {
            close(fd);
            return S3_ERROR;
        }

        got += (size_t)n;
    }

    close(fd);

    return s3_ssh3_agent_cli_parse_sign(reply, 4 + rlen, sig, sig_cap, sig_len, alg, alg_cap);
}

#endif
