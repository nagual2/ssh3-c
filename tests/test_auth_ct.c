/*
 * Copyright (C) 2026 the ssh3-c authors
 */

/*
 * the pin of the constant-time compares of the secrets (A2): the
 * password, its digest and the token id must not ride the plain
 * memcmp - the length of a secret may leak, its bytes may not.
 *
 * the check reads the sources: the compare is a call site, not a
 * behaviour a black-box test could time reliably
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <s3_core.h>

#include "s3_test.h"

#ifndef S3_TEST_SOURCE_DIR
#define S3_TEST_SOURCE_DIR "."
#endif

static char *
s3_test_read(const char *path)
{
    FILE  *f;
    char  *buf;
    long   size;

    f = fopen(path, "rb");

    if (f == NULL) {
        return NULL;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        (void)fclose(f);
        return NULL;
    }

    size = ftell(f);

    if (size <= 0 || fseek(f, 0, SEEK_SET) != 0) {
        (void)fclose(f);
        return NULL;
    }

    buf = (char *)malloc((size_t)size + 1);

    if (buf == NULL) {
        (void)fclose(f);
        return NULL;
    }

    if (fread(buf, 1, (size_t)size, f) != (size_t)size) {
        free(buf);
        (void)fclose(f);
        return NULL;
    }

    buf[size] = '\0';

    (void)fclose(f);

    return buf;
}

static int
s3_test_pins(const char *file, const char *must, const char *must_not)
{
    char *src;
    int   rc = 0;

    src = s3_test_read(file);

    if (src == NULL) {
        printf("FAIL %s:%d: cannot read %s\n", __FILE__, __LINE__, file);
        s3_test_failures++;
        return rc;
    }

    if (strstr(src, must) == NULL) {
        printf("FAIL %s:%d: %s does not carry %s\n", __FILE__, __LINE__, file, must);
        s3_test_failures++;
        rc = -1;
    }

    if (must_not != NULL && strstr(src, must_not) != NULL) {
        printf("FAIL %s:%d: %s still carries %s\n", __FILE__, __LINE__, file, must_not);
        s3_test_failures++;
        rc = -1;
    }

    free(src);

    return rc;
}

static int
test_auth_ct(void)
{
    char path[1024];

    /* the password of the authorized_keys-style passwd file */

    snprintf(path, sizeof(path), "%s/src/ssh3/s3_ssh3_auth_srv.c", S3_TEST_SOURCE_DIR);

    (void)s3_test_pins(path, "s3_memcmp_ct(colon + 1, pass->data", "s3_memcmp(colon + 1, pass->data");

    /* the digest of the system password */

    (void)s3_test_pins(path, "s3_memcmp_ct((const u_char *)got, (const u_char *)hash, n)",
                       "s3_memcmp(got, hash, n)");

    /* the token id of the verified jwt */

    snprintf(path, sizeof(path), "%s/src/ssh3/s3_ssh3_auth_jwt.c", S3_TEST_SOURCE_DIR);

    (void)s3_test_pins(path, "s3_memcmp_ct(cl.jti.data, jti", "s3_memcmp(cl.jti.data, jti");

    return s3_test_failures;
}

static int
s3_test_auth_ct(void)
{
    (void)test_auth_ct();

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_auth_ct)
