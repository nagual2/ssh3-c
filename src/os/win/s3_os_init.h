/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_OS_INIT_H_INCLUDED_
#define _S3_OS_INIT_H_INCLUDED_

#include <s3_base.h>

/*
 * the process-global WinSock init, the win32 counterpart of the unix
 * no-op; every socket call fails with WSANOTINITIALISED before it
 */
s3_int_t s3_os_init(void);
void     s3_os_done(void);

#endif /* _S3_OS_INIT_H_INCLUDED_ */
