/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <s3_core.h>
#include <string.h>

#if (S3_WIN32)
#include <process.h>
#endif

#include "s3_test.h"

/*
 * the MSVCRT tmpfile() creates files in the drive root and fails on a
 * locked-down system: on win32 a named temp file in the build tree
 * with the MSVC delete-on-close flag keeps the tmpfile() hygiene
 */
static FILE *
s3_test_tmpfile(void)
{
#if (S3_WIN32)
    char name[64];

    snprintf(name, sizeof(name), "test_log_%d.tmp", _getpid());

    return fopen(name, "w+bD");
#else
    return tmpfile();
#endif
}

static int
s3_test_log(void)
{
    int      n;
    size_t   len;
    char     rbuf[512];
    FILE    *f;
    s3_log_t log, log2;

    /*
     * log targets are tmpfile() descriptors: nothing is written outside
     * the build tree and the files are removed on close
     */

    /* the macro gate: messages below the threshold are silent */

    f = s3_test_tmpfile();
    S3_ASSERT(f != NULL);
    if (f == NULL) {
        return s3_test_failures;
    }

    log.log_level = S3_LOG_ERR;
    log.fd = fileno(f);

    s3_log_error(S3_LOG_INFO, &log, 0, "must not appear");

    fflush(f);
    rewind(f);
    n = (int)fread(rbuf, 1, sizeof(rbuf), f);
    S3_ASSERT(n == 0);

    s3_log_error(S3_LOG_EMERG, &log, 0, "emerg happened");

    fflush(f);
    rewind(f);
    n = (int)fread(rbuf, 1, sizeof(rbuf) - 1, f);
    rbuf[n] = '\0';
    S3_ASSERT(n > 0);
    S3_ASSERT(strstr(rbuf, "[emerg]") != NULL);
    S3_ASSERT(strstr(rbuf, "emerg happened") != NULL);
    S3_ASSERT(strstr(rbuf, "\n") != NULL);
    S3_ASSERT(strchr(rbuf, '\n') == rbuf + n - 1);

    fclose(f);

    /* errno formatting: " (%d: strerror)" is appended */

    f = s3_test_tmpfile();
    S3_ASSERT(f != NULL);
    if (f == NULL) {
        return s3_test_failures;
    }

    log.log_level = S3_LOG_CRIT;
    log.fd = fileno(f);

    s3_log_error(S3_LOG_CRIT, &log, S3_EACCES, "open failed");

    fflush(f);
    rewind(f);
    n = (int)fread(rbuf, 1, sizeof(rbuf) - 1, f);
    rbuf[n] = '\0';
    S3_ASSERT(strstr(rbuf, "[crit]") != NULL);
    S3_ASSERT(strstr(rbuf, "open failed") != NULL);

#if (S3_WIN32)
    /* the code is the EACCES mapping (ERROR_ACCESS_DENIED), the text
       comes back localized from FormatMessage */
    S3_ASSERT(strstr(rbuf, " (5: ") != NULL);
#else
    S3_ASSERT(strstr(rbuf, " (13: Permission denied)") != NULL);
#endif

    fclose(f);

    /* debug macros use the S3_LOG_DEBUG_EVENT mask */

    f = s3_test_tmpfile();
    S3_ASSERT(f != NULL);
    if (f == NULL) {
        return s3_test_failures;
    }

    log2.log_level = S3_LOG_DEBUG_EVENT;
    log2.fd = fileno(f);

    s3_log_debug1(S3_LOG_DEBUG_EVENT, &log2, 0, "event %d", 7);

    fflush(f);
    rewind(f);
    n = (int)fread(rbuf, 1, sizeof(rbuf) - 1, f);
    rbuf[n] = '\0';
    S3_ASSERT(strstr(rbuf, "[debug]") != NULL);
    S3_ASSERT(strstr(rbuf, "event 7") != NULL);

    /* foreign debug mask: silent */

    len = (size_t)n;
    rewind(f);
    s3_log_debug1(S3_LOG_DEBUG_ALLOC, &log2, 0, "alloc %d", 7);
    fflush(f);
    fseek(f, 0, SEEK_END);
    n = (int)(ftell(f));
    S3_ASSERT((size_t)n == len);

    fclose(f);

    /* the core function with fd = 2 (stderr) is usable directly */

    s3_log_error_core(S3_LOG_INFO, &s3_stderr_log, 0, "core fd=2 smoke");

    return s3_test_failures;
}

S3_TEST_MAIN(s3_test_log)
