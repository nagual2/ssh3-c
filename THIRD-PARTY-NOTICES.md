# Third-party notices

This project contains code adapted from nginx (https://nginx.org),
distributed under the BSD 2-clause license reproduced below.

## nginx license

```
Copyright (C) 2002-2021 Igor Sysoev
Copyright (C) 2011-2026 Nginx, Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
SUCH DAMAGE.
```

## Adapted files

The following ssh3-c files are adaptations of nginx `src/core/` sources
(`ngx_` renamed to `s3_`, `NGX_` renamed to `S3_`, simplifications where
noted in code):

| № | ssh3-c file | Adapted from |
|---|-------------|--------------|
| 1 | `src/core/s3_palloc.{c,h}` | `src/core/ngx_palloc.{c,h}` |
| 2 | `src/core/s3_buf.{c,h}` | `src/core/ngx_buf.{c,h}` |
| 3 | `src/core/s3_rbtree.{c,h}` | `src/core/ngx_rbtree.{c,h}` |
| 4 | `src/core/s3_queue.h` | `src/core/ngx_queue.{h,c}` |
| 5 | `src/core/s3_string.{c,h}` | `src/core/ngx_string.{c,h}` (vslprintf subset) |
| 6 | `src/core/s3_log.{c,h}` | `src/core/ngx_log.{c,h}` (simplified, no cycle) |
| 7 | `src/os/unix/s3_errno.{c,h}` | `src/os/unix/ngx_errno.{c,h}` |

Each adapted file retains the original `Copyright (C) Nginx, Inc.` header
followed by the ssh3-c project copyright line.
