/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_TEST_H_INCLUDED_
#define _S3_TEST_H_INCLUDED_

#include <stdio.h>
#include <stdlib.h>

#if (S3_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>

/* the win32 sockets are not close(fd)-able */

#define s3_test_close(fd) closesocket((SOCKET)(fd))

/*
 * the wave-14 mingw isolation: the raw stack of the fatal exception -
 * the return addresses resolve offline against the symbol table, the
 * module base prints next to them for the ASLR shift
 */

static LONG WINAPI
s3_test_crash_handler(EXCEPTION_POINTERS *ep)
{
    void  *stack[32];
    USHORT n, i;

    fprintf(stderr, "CRASH exc=0x%08lx addr=%p base=%p\n", (long)ep->ExceptionRecord->ExceptionCode,
            ep->ExceptionRecord->ExceptionAddress, (void *)(uintptr_t)GetModuleHandleA(NULL));

    n = CaptureStackBackTrace(0, 32, stack, NULL);

    for (i = 0; i < n; i++) {
        fprintf(stderr, "  #%02u %p\n", (unsigned)i, stack[i]);
    }

    fflush(stderr);

    return EXCEPTION_CONTINUE_SEARCH;
}

static void
s3_test_winsock_init(void)
{
    WSADATA wsd;

    SetUnhandledExceptionFilter(s3_test_crash_handler);

    WSAStartup(MAKEWORD(2, 2), &wsd);
}
#else
#define s3_test_close(fd) close(fd)

static void
s3_test_winsock_init(void)
{
}
#endif

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
                                                                                                   \
        s3_test_winsock_init();                                                                    \
                                                                                                   \
        failures = name();                                                                         \
        if (failures == 0) {                                                                       \
            printf("OK\n");                                                                        \
            return EXIT_SUCCESS;                                                                   \
        }                                                                                          \
        printf("FAILED: %d assertion(s)\n", failures);                                             \
        return EXIT_FAILURE;                                                                       \
    }

#endif /* _S3_TEST_H_INCLUDED_ */
