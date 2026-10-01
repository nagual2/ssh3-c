/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <s3_core.h>

void
s3_event_process_posted(s3_event_ctx_t *ctx, s3_queue_t *posted)
{
    s3_queue_t *q;
    s3_event_t *ev;

    (void)ctx;

    while (!s3_queue_empty(posted)) {

        q = s3_queue_head(posted);
        ev = (s3_event_t *)((u_char *)q - offsetof(s3_event_t, queue));

        s3_delete_posted_event(ev);

        ev->handler(ev);
    }
}
