/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_EVENT_H_INCLUDED_
#define _S3_EVENT_H_INCLUDED_

#include <s3_base.h>
#include <s3_log.h>
#include <s3_palloc.h>
#include <s3_queue.h>
#include <s3_rbtree.h>

#define S3_TIMER_INFINITE (s3_msec_t) - 1

#define S3_TIMER_LAZY_DELAY 300

typedef struct s3_connection_s s3_connection_t;
typedef struct s3_event_s      s3_event_t;

#if (S3_WIN32)

/* the iocp event method flag, the NGX_USE_IOCP_EVENT port */
#define S3_USE_IOCP_EVENT 1

/*
 * the carrier of an overlapped operation: the WSAOVERLAPPED is passed
 * to the kernel and handed back by GetQueuedCompletionStatus(), the
 * event backlink resolves a completion to its event
 * (the reference ngx_event_ovlp_t).  data is the target of a posted
 * receive: the completion writes it long after the call, the callers
 * receive buffers are shared statics, so the carrier holds the buffer
 * (deviation from the reference, which posts into per-connection
 * c->buffer)
 */
typedef struct {
    WSAOVERLAPPED ovlp;
    s3_event_t   *event;
    s3_err_t      error;
    u_char       *data;
} s3_event_ovlp_t;

#endif

typedef void (*s3_event_handler_pt)(s3_event_t *ev);

struct s3_event_s {
    void *data;

    unsigned write : 1;

    unsigned accept : 1;

    /* used to detect the stale events in epoll */
    unsigned instance : 1;

    /* the event was passed or would be passed to a kernel */
    unsigned active : 1;

    unsigned ready : 1;

    unsigned eof : 1;
    unsigned error : 1;

    unsigned timedout : 1;
    unsigned timer_set : 1;

    unsigned posted : 1;

    unsigned closed : 1;

    /* the pending eof reported by epoll */
    unsigned pending_eof : 1;

    /* the posted overlapped operation completed (the iocp module) */
    unsigned complete : 1;

    /* the bytes transferred by the completed overlapped operation */
    ssize_t available;

    s3_event_handler_pt handler;

#if (S3_WIN32)

    /* the carrier of the posted overlapped operation */
    s3_event_ovlp_t ovlp;

#endif

    s3_log_t *log;

    /* the timer rbtree node; timer.data points back to the event */
    s3_rbtree_node_t timer;

    /* the posted queue */
    s3_queue_t queue;
};

typedef struct s3_event_ctx_s s3_event_ctx_t;

struct s3_event_ctx_s {
    s3_log_t *log;

    /* the pool connections and their events are allocated from */
    s3_pool_t *pool;

    s3_rbtree_t      timer_rbtree;
    s3_rbtree_node_t timer_sentinel;

    s3_queue_t posted_events;

    void *impl; /* the event method implementation data */
};

typedef struct {
    s3_int_t (*init)(s3_event_ctx_t *ctx);
    s3_int_t (*add_event)(s3_event_t *ev, s3_int_t event, s3_uint_t flags);
    s3_int_t (*del_event)(s3_event_t *ev, s3_int_t event, s3_uint_t flags);
    s3_int_t (*add_connection)(s3_event_ctx_t *ctx, s3_connection_t *c);
    s3_int_t (*del_connection)(s3_event_ctx_t *ctx, s3_connection_t *c);
    s3_int_t (*process_events)(s3_event_ctx_t *ctx, s3_msec_t timer, s3_uint_t flags);
    void (*done)(s3_event_ctx_t *ctx);
} s3_event_actions_t;

extern s3_event_actions_t s3_event_actions;

/*
 * the event method capabilities, set by the module init(): the
 * S3_USE_IOCP_EVENT bit marks the iocp backend, the overlapped
 * receives complete through the port
 */
extern s3_uint_t s3_event_flags;

/*
 * process_events() flags
 */
#define S3_UPDATE_TIME 1
#define S3_POST_EVENTS 2

/*
 * the event filter is deleted just before the closing file (del_event)
 */
#define S3_CLOSE_EVENT 1

/* the event types; the epoll values on Linux */
#define S3_READ_EVENT  0x001
#define S3_WRITE_EVENT 0x004

/* current monotonic time in milliseconds, updated by s3_time_update() */
extern s3_msec_t s3_current_msec;

void s3_time_update(void);

s3_int_t s3_event_ctx_init(s3_event_ctx_t *ctx, s3_log_t *log);

/*
 * the exit counterpart of ctx_init(): the event method drops its
 * implementation data and the pool the connections and their events
 * were allocated from dies; every connection must be closed by its
 * owner before the call, the pool destroy does not run the handlers
 */
void s3_event_ctx_shutdown(s3_event_ctx_t *ctx);

void s3_process_events_and_timers(s3_event_ctx_t *ctx);

/*
 * registers the timer rbtree of the context; s3_event_add_timer() and
 * s3_event_del_timer() have no context argument and use the registered
 * rbtree, like the nginx globals
 */
s3_int_t s3_event_timer_init(s3_event_ctx_t *ctx);

s3_msec_t s3_event_find_timer(s3_event_ctx_t *ctx);
void      s3_event_expire_timers(s3_event_ctx_t *ctx);
void      s3_event_add_timer(s3_event_t *ev, s3_msec_t timer);
void      s3_event_del_timer(s3_event_t *ev);

void s3_event_process_posted(s3_event_ctx_t *ctx, s3_queue_t *posted);

#define s3_post_event(ev, q)                                                                       \
                                                                                                   \
    if (!(ev)->posted) {                                                                           \
        (ev)->posted = 1;                                                                          \
        s3_queue_insert_tail(q, &(ev)->queue);                                                     \
    }

#define s3_delete_posted_event(ev)                                                                 \
                                                                                                   \
    (ev)->posted = 0;                                                                              \
    s3_queue_remove(&(ev)->queue);

typedef void (*s3_connection_handler_pt)(s3_connection_t *c);

/*
 * the per-listening-socket state of the udp shared-socket model; it is
 * attached to the listening connection (connection->data) by the user
 */
typedef struct {
    s3_connection_t         *connection; /* the listening socket */
    s3_event_ctx_t          *ctx;
    s3_connection_handler_pt handler; /* the new client handler */
    s3_rbtree_t              rbtree;  /* the pseudo connections */
    s3_rbtree_node_t         sentinel;
    unsigned                 wildcard : 1;

    /*
     * the quic listener: the rbtree is keyed by the packet dcid
     * (s3_quic_rbtree_insert_socket / s3_quic_lookup_connection) and
     * holds s3_quic_socket_t nodes instead of the sockaddr-keyed P1
     * pseudo connections (porting map 1.12.3)
     */
    unsigned quic : 1;
} s3_udp_listen_t;

void    s3_event_recvmsg(s3_event_t *ev);
ssize_t s3_udp_shared_recv(s3_connection_t *c, u_char *buf, size_t size);
void    s3_udp_rbtree_insert_value(s3_rbtree_node_t *temp, s3_rbtree_node_t *node,
                                   s3_rbtree_node_t *sentinel);
void    s3_delete_udp_connection(void *data);

#endif /* _S3_EVENT_H_INCLUDED_ */
