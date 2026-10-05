/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_FUZZ_H_INCLUDED_
#define _S3_FUZZ_H_INCLUDED_

#include <stddef.h>

/*
 * the shared harness plumbing: every parse result feeds the volatile
 * accumulator so the compiler cannot fold the work away, and a real
 * invariant violation (the re-encode/size contracts the callers rely
 * on) aborts the run through the trap, which is a finding exactly
 * like a sanitizer report
 */

static size_t s3_fuzz_acc;

static s3_inline void
s3_fuzz_sink(size_t v)
{
    s3_fuzz_acc += v;
}

static s3_inline void
s3_fuzz_trap(void)
{
    __builtin_trap();
}

#endif /* _S3_FUZZ_H_INCLUDED_ */
