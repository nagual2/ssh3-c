/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_TEST_H_INCLUDED_
#define _S3_TEST_H_INCLUDED_

#include <stdio.h>
#include <stdlib.h>

static int s3_test_failures = 0;

#define S3_ASSERT(cond)                                                                            \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                                 \
            s3_test_failures++;                                                                    \
        }                                                                                          \
    } while (0)

/*
 * every test file defines a function int <name>(void) incrementing
 * s3_test_failures on each broken assertion and returning its count
 */
#define S3_TEST_MAIN(name)                                                                         \
    int main(void)                                                                                 \
    {                                                                                              \
        int failures;                                                                              \
        setvbuf(stdout, NULL, _IONBF, 0);                                                          \
        failures = name();                                                                         \
        if (failures == 0) {                                                                       \
            printf("OK\n");                                                                        \
            return EXIT_SUCCESS;                                                                   \
        }                                                                                          \
        printf("FAILED: %d assertion(s)\n", failures);                                             \
        return EXIT_FAILURE;                                                                       \
    }

#endif /* _S3_TEST_H_INCLUDED_ */
