/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <winsock2.h>

#include <s3_base.h>
#include <s3_os_init.h>

s3_int_t
s3_os_init(void)
{
    WSADATA wsd;

    return (WSAStartup(MAKEWORD(2, 2), &wsd) != 0) ? S3_ERROR : S3_OK;
}

void
s3_os_done(void)
{
    (void)WSACleanup();
}
