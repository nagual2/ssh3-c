/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the ssh agent protocol client pins: the wire codec (the identities,
 * the sign request and response) and the pubkey file loader; the
 * socket flow rides the e2e stand with the live ssh-agent
 */

#include <s3_core.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <s3_ssh3_agent_client.h>

#include "s3_test.h"

/* the crafted key blob: ssh-ed25519 + the 32 bytes 00..1f */

static const char *ED_B64 =
    "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f";


static void
s3_test_agent_blob(u_char *blob, size_t blen)
{
    unsigned i;

    for (i = 0; i < blen; i++) {
        blob[i] = (u_char)i;
    }
}

static int
s3_test_agent_pubkey_file(void)
{
    char        path[256];
    FILE       *f;
    u_char      blob[1024];
    size_t      blen = 0;
    u_char      want[47];
    s3_int_t    rc;

    snprintf(path, sizeof(path), "/tmp/s3agent-test-%d.pub", (int)getpid());
    f = fopen(path, "wb");
    S3_ASSERT(f != NULL);
    fprintf(f, "# a comment line\n\nssh-ed25519 %s the comment\n", ED_B64);
    fclose(f);

    rc = s3_ssh3_agent_cli_pubkey_file(path, blob, sizeof(blob), &blen);
    S3_ASSERT(rc == S3_OK);
    S3_ASSERT(blen == 4 + 11 + 4 + 32);

    s3_test_agent_blob(want, 32);
    S3_ASSERT(memcmp(blob, "\000\000\000\013ssh-ed25519", 15) == 0);
    S3_ASSERT(memcmp(blob + 15, "\000\000\000 ", 4) == 0);
    S3_ASSERT(memcmp(blob + 19, want, 32) == 0);

    (void)unlink(path);

    return 0;
}

static int
s3_test_agent_req_sign(void)
{
    u_char   blob[64], req[256];
    u_char   data[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    size_t   blen, n;
    uint32_t flen;

    s3_test_agent_blob(blob + 19, 32);
    memcpy(blob, "\000\000\000\013ssh-ed25519", 15);
    memcpy(blob + 15, "\000\000\000 ", 4);
    blen = 47;

    /* the ed25519 request: no flag */

    n = s3_ssh3_agent_cli_req_sign(req, blob, blen, data, sizeof(data));
    S3_ASSERT(n == 4 + 1 + 4 + blen + 4 + sizeof(data) + 4);
    S3_ASSERT(req[4] == 13);
    S3_ASSERT(memcmp(req + 5, "\000\000\000\013ssh-ed25519", 15) == 0);
    flen = ((uint32_t)req[n - 4] << 24) | ((uint32_t)req[n - 3] << 16) |
           ((uint32_t)req[n - 2] << 8) | (uint32_t)req[n - 1];
    S3_ASSERT(flen == 0);

    /* the rsa request: the sha-256 flag rides */

    memcpy(blob, "\000\000\000\007ssh-rsa", 11);
    memcpy(blob + 11, "\000\000\000 ", 4);
    blen = 11 + 4 + 32;

    n = s3_ssh3_agent_cli_req_sign(req, blob, blen, data, sizeof(data));
    flen = ((uint32_t)req[n - 4] << 24) | ((uint32_t)req[n - 3] << 16) |
           ((uint32_t)req[n - 2] << 8) | (uint32_t)req[n - 1];
    S3_ASSERT(flen == 2);

    /* the identities request: five bytes */

    n = s3_ssh3_agent_cli_req_identities(req);
    S3_ASSERT(n == 5);
    S3_ASSERT(req[4] == 11);

    return 0;
}

static int
s3_test_agent_parse_identities(void)
{
    u_char   reply[512];
    size_t   len = 0, n = 0, i;
    u_char   blob[64];
    s3_str_t blobs[8];
    s3_int_t rc;

    s3_test_agent_blob(blob, 40);

    /* two identities with the comments */

    reply[len++] = 0;
    reply[len++] = 0;
    reply[len++] = 0;
    reply[len++] = 0; /* the framing patched below */
    reply[len++] = 12;
    reply[len++] = 0;
    reply[len++] = 0;
    reply[len++] = 0;
    reply[len++] = 2;

    for (i = 0; i < 2; i++) {

        u_char body[64];
        size_t blen = 0;

        body[blen++] = 0;
        body[blen++] = 0;
        body[blen++] = 0;
        body[blen++] = 40;
        memcpy(body + blen, blob, 40);
        blen += 40;
        body[blen++] = 0;
        body[blen++] = 0;
        body[blen++] = 0;
        body[blen++] = 4;
        memcpy(body + blen, "abcd", 4);
        blen += 4;

        memcpy(reply + len, body, blen);
        len += blen;
    }

    {
        uint32_t total = (uint32_t)(len - 4);
        reply[0] = (u_char)(total >> 24);
        reply[1] = (u_char)(total >> 16);
        reply[2] = (u_char)(total >> 8);
        reply[3] = (u_char)total;
    }

    rc = s3_ssh3_agent_cli_parse_identities(reply, len, blobs, &n, 8);
    S3_ASSERT(rc == S3_OK);
    S3_ASSERT(n == 2);
    S3_ASSERT(blobs[0].len == 40 && blobs[1].len == 40);
    S3_ASSERT(blobs[0].data == reply + 13);

    /* the truncated framing refuses */

    rc = s3_ssh3_agent_cli_parse_identities(reply, len - 10, blobs, &n, 8);
    S3_ASSERT(rc == S3_ERROR);

    return 0;
}

static int
s3_test_agent_parse_sign(void)
{
    u_char   reply[256], sig[256], want[64];
    size_t   len = 0, sig_len = 0;
    char     alg[16];
    s3_int_t rc;

    s3_test_agent_blob(want, 64);

    /* the ed25519 response: the flags, the algo string, the raw 64 */

    reply[len++] = 0;
    reply[len++] = 0;
    reply[len++] = 0;
    reply[len++] = 0; /* the framing patched below */
    reply[len++] = 14;
    reply[len++] = 0;
    reply[len++] = 0;
    reply[len++] = 0;
    reply[len++] = 0; /* the flags */
    reply[len++] = 0;
    reply[len++] = 0;
    reply[len++] = 0;
    reply[len++] = 11;
    memcpy(reply + len, "ssh-ed25519", 11);
    len += 11;
    reply[len++] = 0;
    reply[len++] = 0;
    reply[len++] = 1;
    reply[len++] = 0;
    memcpy(reply + len, want, 64);
    len += 64;

    {
        uint32_t total = (uint32_t)(len - 4);
        reply[0] = (u_char)(total >> 24);
        reply[1] = (u_char)(total >> 16);
        reply[2] = (u_char)(total >> 8);
        reply[3] = (u_char)total;
    }

    rc = s3_ssh3_agent_cli_parse_sign(reply, len, sig, sizeof(sig), &sig_len, alg,
                                      sizeof(alg));
    S3_ASSERT(rc == S3_OK);
    S3_ASSERT(sig_len == 64);
    S3_ASSERT(memcmp(sig, want, 64) == 0);
    S3_ASSERT(strcmp(alg, "EdDSA") == 0);

    /* the rsa-sha2-256 response names RS256 */

    len = 4;
    reply[len++] = 14;
    reply[len++] = 0;
    reply[len++] = 0;
    reply[len++] = 0;
    reply[len++] = 0;
    reply[len++] = 0;
    reply[len++] = 0;
    reply[len++] = 0;
    reply[len++] = 12;
    memcpy(reply + len, "rsa-sha2-256", 12);
    len += 12;
    reply[len++] = 0;
    reply[len++] = 0;
    reply[len++] = 0;
    reply[len++] = 4;
    memcpy(reply + len, want, 4);
    len += 4;

    {
        uint32_t total = (uint32_t)(len - 4);
        reply[0] = (u_char)(total >> 24);
        reply[1] = (u_char)(total >> 16);
        reply[2] = (u_char)(total >> 8);
        reply[3] = (u_char)total;
    }

    rc = s3_ssh3_agent_cli_parse_sign(reply, len, sig, sizeof(sig), &sig_len, alg,
                                      sizeof(alg));
    S3_ASSERT(rc == S3_OK);
    S3_ASSERT(sig_len == 4);
    S3_ASSERT(strcmp(alg, "RS256") == 0);

    /* the FAILURE reply: the agent does not hold the key */

    reply[4] = 5;
    rc = s3_ssh3_agent_cli_parse_sign(reply, len, sig, sizeof(sig), &sig_len, alg,
                                      sizeof(alg));
    S3_ASSERT(rc == S3_DECLINED);

    /* the truncated framing refuses */

    rc = s3_ssh3_agent_cli_parse_sign(reply, len - 4, sig, sizeof(sig), &sig_len, alg,
                                      sizeof(alg));
    S3_ASSERT(rc == S3_ERROR);

    return 0;
}

static int
s3_test_agent_client(void)
{
    int failures = 0;

    failures += s3_test_agent_pubkey_file();
    failures += s3_test_agent_req_sign();
    failures += s3_test_agent_parse_identities();
    failures += s3_test_agent_parse_sign();

    return failures;
}

S3_TEST_MAIN(s3_test_agent_client)
