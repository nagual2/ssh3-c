/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <s3_core.h>

#include <s3_udp_sendmsg_chain.h>

static s3_chain_t *s3_udp_output_chain_to_iovec(s3_iovec_t *vec, s3_chain_t *in, s3_log_t *log);
static ssize_t     s3_sendmsg_vec(s3_connection_t *c, s3_iovec_t *vec);
static s3_chain_t *s3_chain_update_sent(s3_chain_t *in, off_t sent);

s3_chain_t *
s3_udp_sendmsg_chain(s3_connection_t *c, s3_chain_t *in, off_t limit)
{
    ssize_t      n;
    off_t        send;
    s3_chain_t  *cl;
    s3_event_t  *wev;
    s3_iovec_t   vec, one;
    struct iovec iovs[S3_IOVS_PREALLOCATE];

    wev = c->write;

    if (!wev->ready) {
        return in;
    }

    /* the maximum limit size is the maximum size_t value - the page size */

    if (limit == 0 || limit > (off_t)(S3_MAX_SIZE_T_VALUE - s3_pagesize)) {
        limit = (off_t)(S3_MAX_SIZE_T_VALUE - s3_pagesize);
    }

    send = 0;

    vec.iovs = iovs;
    vec.nalloc = S3_IOVS_PREALLOCATE;

    for (;;) {

        /* create the iovec and coalesce the neighbouring bufs */

        cl = s3_udp_output_chain_to_iovec(&vec, in, c->log);

        if (cl == S3_CHAIN_ERROR) {
            return S3_CHAIN_ERROR;
        }

        if (cl && cl->buf->in_file) {
            s3_log_error(S3_LOG_ALERT, c->log, 0, "file buf in sendmsg");
            return S3_CHAIN_ERROR;
        }

        if (cl == in) {
            return in;
        }

        send += (off_t)vec.size;

        n = s3_sendmsg_vec(c, &vec);

        if (n == (ssize_t)S3_ERROR) {
            return S3_CHAIN_ERROR;
        }

        if (n == (ssize_t)S3_DECLINED) {

            /*
             * EMSGSIZE: the coalesced datagram exceeded the path limit,
             * fall back to sending each part as an individual datagram
             */

            for (; vec.count; vec.iovs++, vec.count--) {
                one.iovs = vec.iovs;
                one.count = 1;
                one.nalloc = 1;
                one.size = vec.iovs->iov_len;

                n = s3_sendmsg_vec(c, &one);

                if (n == (ssize_t)S3_DECLINED) {

                    /* the datagram is too large for the path, drop it */

                    s3_log_error(S3_LOG_ALERT, c->log, 0,
                                 "sendmsg() dropped an oversized datagram");

                    in = s3_chain_update_sent(in, (off_t)one.size);
                    continue;
                }

                if (n == (ssize_t)S3_ERROR) {
                    return S3_CHAIN_ERROR;
                }

                if (n == (ssize_t)S3_AGAIN) {
                    wev->ready = 0;
                    return in;
                }

                c->sent += n;

                in = s3_chain_update_sent(in, n);
            }

            if (send >= limit || in == NULL) {
                return in;
            }

            continue;
        }

        if (n == (ssize_t)S3_AGAIN) {
            wev->ready = 0;
            return in;
        }

        c->sent += n;

        in = s3_chain_update_sent(in, n);

        if (send >= limit || in == NULL) {
            return in;
        }
    }
}

static s3_chain_t *
s3_udp_output_chain_to_iovec(s3_iovec_t *vec, s3_chain_t *in, s3_log_t *log)
{
    size_t        total, size;
    u_char       *prev;
    s3_uint_t     n, flush;
    s3_chain_t   *cl;
    struct iovec *iov;

    cl = in;
    iov = NULL;
    prev = NULL;
    total = 0;
    n = 0;
    flush = 0;

    for (; in && !flush; in = in->next) {

        if (in->buf->flush || in->buf->last_buf) {
            flush = 1;
        }

        if (s3_buf_special(in->buf)) {
            continue;
        }

        if (in->buf->in_file) {
            break;
        }

        if (!s3_buf_in_memory(in->buf)) {
            s3_log_error(S3_LOG_ALERT, log, 0, "bad buf in output chain");
            return S3_CHAIN_ERROR;
        }

        size = in->buf->last - in->buf->pos;

        if (n > 0 && prev == in->buf->pos) {
            iov->iov_len += size;

        } else {
            if (n == vec->nalloc) {
                s3_log_error(S3_LOG_ALERT, log, 0, "too many parts in a datagram");
                return S3_CHAIN_ERROR;
            }

            iov = &vec->iovs[n++];

            iov->iov_base = (void *)in->buf->pos;
            iov->iov_len = size;
        }

        prev = in->buf->pos + size;
        total += size;
    }

    if (!flush) {
        vec->count = 0;
        vec->size = 0;
        return cl;
    }

    /* zero-sized datagram; pretend to have at least 1 iov */

    if (n == 0) {
        iov = &vec->iovs[n++];
        iov->iov_base = NULL;
        iov->iov_len = 0;
    }

    vec->count = n;
    vec->size = total;

    return in;
}

static ssize_t
s3_sendmsg_vec(s3_connection_t *c, s3_iovec_t *vec)
{
    struct msghdr msg;

    s3_memzero(&msg, sizeof(struct msghdr));

    if (c->socklen) {
        msg.msg_name = c->sockaddr;
        msg.msg_namelen = c->socklen;
    }

    msg.msg_iov = vec->iovs;
    msg.msg_iovlen = vec->count;

    return s3_sendmsg(c, &msg, 0);
}

static s3_chain_t *
s3_chain_update_sent(s3_chain_t *in, off_t sent)
{
    off_t size;

    for (; in; in = in->next) {

        if (s3_buf_special(in->buf)) {
            continue;
        }

        if (sent == 0) {
            break;
        }

        size = s3_buf_size(in->buf);

        if (sent >= size) {
            sent -= size;
            in->buf->pos = in->buf->last;
            in->buf->file_pos = in->buf->file_last;
            continue;
        }

        in->buf->pos += sent;
        in->buf->file_pos += sent;

        break;
    }

    return in;
}

ssize_t
s3_sendmsg(s3_connection_t *c, struct msghdr *msg, int flags)
{
    ssize_t  n;
    s3_err_t err;

eintr:

    n = sendmsg(c->fd, msg, flags);

    if (n == -1) {
        err = s3_socket_errno;

        switch (err) {

        case S3_EAGAIN:
            s3_log_debug0(S3_LOG_DEBUG_EVENT, c->log, err, "sendmsg() not ready");
            return (ssize_t)S3_AGAIN;

        case S3_EINTR:
            s3_log_debug0(S3_LOG_DEBUG_EVENT, c->log, err, "sendmsg() was interrupted");
            goto eintr;

        case S3_EMSGSIZE:

            /*
             * the datagram is too large for the path; returned instead of
             * an error, so that the caller can fall back to sending the
             * chain as individual datagrams
             */

            s3_log_debug0(S3_LOG_DEBUG_EVENT, c->log, err, "sendmsg() datagram too large");
            return (ssize_t)S3_DECLINED;

        default:
            c->write->error = 1;
            s3_log_error(S3_LOG_ERR, c->log, err, "sendmsg() failed");
            return (ssize_t)S3_ERROR;
        }
    }

    return n;
}
