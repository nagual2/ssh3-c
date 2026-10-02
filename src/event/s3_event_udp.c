/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <s3_core.h>

#include <s3_udp_sendmsg_chain.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/uio.h>

/*
 * the quic listener branch keys the rbtree by the packet dcid and
 * hands the datagrams over through the quic sockets
 * (porting map 1.12.3)
 */
#include <s3_quic.h>
#include <s3_quic_connection.h>

#if (S3_HAVE_ADDRINFO_CMSG)
#include <s3_cmsg.h>
#endif

#define S3_UDP_DGRAM_SIZE 65535

/* the raw sockaddr fallback key is bounded by sockaddr_storage */
#define S3_UDP_KEY_MAX sizeof(struct sockaddr_storage)

#define S3_UDP_TEXT_KEY_MAX (INET6_ADDRSTRLEN + sizeof("[]:65535@65535"))

typedef struct s3_udp_connection_s s3_udp_connection_t;

struct s3_udp_connection_s {
    s3_rbtree_node_t node;
    s3_connection_t *connection;
    s3_udp_listen_t *listen;
    s3_str_t         key;
    u_char          *buffer;
    size_t           len;
};

static s3_int_t s3_quic_recvmsg(s3_event_t *ev, s3_connection_t *lc, s3_udp_listen_t *ul,
                                struct msghdr *msg, u_char *buffer, ssize_t n,
                                struct sockaddr *sockaddr, socklen_t socklen);
static void     s3_quic_deliver(s3_connection_t *c, u_char *buffer, ssize_t n,
                                struct sockaddr *sockaddr, socklen_t socklen);

static void             s3_close_accepted_udp_connection(s3_connection_t *c);
static s3_int_t         s3_insert_udp_connection(s3_udp_listen_t *ul, s3_connection_t *c);
static s3_connection_t *s3_lookup_udp_connection(s3_udp_listen_t *ul, s3_connection_t *lc,
                                                 struct sockaddr *sockaddr, socklen_t socklen);
static s3_int_t         s3_udp_key_text(u_char *buf, size_t max, s3_str_t *key, struct sockaddr *sa,
                                        socklen_t salen, struct sockaddr *local_sa, unsigned wildcard);
static s3_uint32_t      s3_udp_key_hash(s3_str_t *key);
static s3_int_t         s3_udp_key_cmp(s3_str_t *k1, s3_str_t *k2);

void
s3_event_recvmsg(s3_event_t *ev)
{
    ssize_t                 n;
    s3_log_t               *log;
    s3_err_t                err;
    socklen_t               socklen;
    s3_event_t             *rev, *wev;
    struct iovec            iov[1];
    struct msghdr           msg;
    struct sockaddr_storage sa;
    struct sockaddr        *sockaddr;
    s3_udp_listen_t        *ul;
    s3_event_ctx_t         *ctx;
    s3_connection_t        *c, *lc;
    static u_char           buffer[S3_UDP_DGRAM_SIZE];

#if (S3_HAVE_ADDRINFO_CMSG)
    /* the local address ancillary data of a wildcard listener */
    u_char msg_control[CMSG_SPACE(sizeof(struct in_pktinfo))
#if defined(IPV6_RECVPKTINFO)
                       + CMSG_SPACE(sizeof(struct in6_pktinfo))
#endif
    ];
#endif

    lc = (s3_connection_t *)ev->data;
    ul = (s3_udp_listen_t *)lc->data;
    ctx = ul->ctx;

    ev->ready = 0;

    s3_memzero(&msg, sizeof(struct msghdr));

    iov[0].iov_base = (void *)buffer;
    iov[0].iov_len = sizeof(buffer);

    msg.msg_name = &sa;
    msg.msg_namelen = sizeof(sa);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

#if (S3_HAVE_ADDRINFO_CMSG)
    if (ul->wildcard && ul->quic) {
        msg.msg_control = msg_control;
        msg.msg_controllen = sizeof(msg_control);
        s3_memzero(msg_control, sizeof(msg_control));
    }
#endif

    n = recvmsg(lc->fd, &msg, 0);

    if (n == -1) {
        err = s3_socket_errno;

        if (err == S3_EAGAIN) {
            s3_log_debug0(S3_LOG_DEBUG_EVENT, ev->log, err, "recvmsg() not ready");
            return;
        }

        s3_log_error(S3_LOG_ALERT, ev->log, err, "recvmsg() failed");

        return;
    }

    sockaddr = (struct sockaddr *)&sa;
    socklen = msg.msg_namelen;

    if (socklen > sizeof(sa)) {
        socklen = sizeof(sa);
    }

    if (socklen == 0) {

        /*
         * on Linux recvmsg() returns zero msg_namelen when receiving
         * packets from unbound sockets
         */

        socklen = sizeof(struct sockaddr);
        s3_memzero(&sa, sizeof(struct sockaddr));
        sa.ss_family = lc->sockaddr != NULL ? lc->sockaddr->sa_family : AF_INET;
    }

    if (ul->quic) {
        (void)s3_quic_recvmsg(ev, lc, ul, &msg, buffer, n, sockaddr, socklen);
        return;
    }

    c = s3_lookup_udp_connection(ul, lc, sockaddr, socklen);

    if (c != NULL) {

        /*
         * the datagram is delivered zero-copy as a view into the static
         * buffer; the handler must consume it via c->recv, which copies
         * it out, otherwise the datagram is dropped
         */

        rev = c->read;

        c->udp->buffer = buffer;
        c->udp->len = n;

        rev->ready = 1;
        rev->active = 0;

        rev->handler(rev);

        if (c->udp != NULL) {
            c->udp->buffer = NULL;
            c->udp->len = 0;
        }

        rev->ready = 0;
        rev->active = 1;

        return;
    }

    /* a new client */

    c = s3_get_connection(ctx, lc->fd);
    if (c == NULL) {
        return;
    }

    c->shared = 1;

    c->pool = s3_create_pool((size_t)S3_DEFAULT_POOL_SIZE, ev->log);
    if (c->pool == NULL) {
        s3_close_accepted_udp_connection(c);
        return;
    }

    c->sockaddr = (struct sockaddr *)s3_palloc(c->pool, socklen);
    if (c->sockaddr == NULL) {
        s3_close_accepted_udp_connection(c);
        return;
    }

    s3_memcpy(c->sockaddr, sockaddr, socklen);
    c->socklen = socklen;

    log = (s3_log_t *)s3_palloc(c->pool, sizeof(s3_log_t));
    if (log == NULL) {
        s3_close_accepted_udp_connection(c);
        return;
    }

    *log = *ev->log;

    c->log = log;
    c->pool->log = log;

    c->recv = s3_udp_shared_recv;
    c->send_chain = s3_udp_sendmsg_chain;

    if (lc->sockaddr != NULL) {
        c->local_sockaddr = (struct sockaddr *)s3_palloc(c->pool, lc->socklen);
        if (c->local_sockaddr == NULL) {
            s3_close_accepted_udp_connection(c);
            return;
        }

        s3_memcpy(c->local_sockaddr, lc->sockaddr, lc->socklen);
        c->local_socklen = lc->socklen;
    }

    if (s3_insert_udp_connection(ul, c) != S3_OK) {
        s3_close_accepted_udp_connection(c);
        return;
    }

    /* the first datagram is copied into the connection pool memory */

    c->udp->buffer = s3_palloc(c->pool, n);
    if (c->udp->buffer == NULL) {
        s3_close_accepted_udp_connection(c);
        return;
    }

    s3_memcpy(c->udp->buffer, buffer, n);
    c->udp->len = n;

    rev = c->read;
    wev = c->write;

    rev->active = 1;
    wev->ready = 1;

    rev->log = log;
    wev->log = log;

    ul->handler(c);
}

/*
 * the quic branch of the datagram delivery: the connection is looked
 * up by the dcid of the first packet; a known connection gets the
 * datagram through its quic socket, a new one is passed to the
 * listener handler with the datagram in c->buffer
 * (the reference ngx_event_quic_udp.c)
 */
static s3_int_t
s3_quic_recvmsg(s3_event_t *ev, s3_connection_t *lc, s3_udp_listen_t *ul, struct msghdr *msg,
                u_char *buffer, ssize_t n, struct sockaddr *sockaddr, socklen_t socklen)
{
    s3_log_t        *log;
    s3_str_t         key;
    s3_event_t      *rev, *wev;
    s3_buf_t        *b;
    s3_connection_t *c;

#if (S3_HAVE_ADDRINFO_CMSG)
    struct cmsghdr         *cmsg;
    struct sockaddr_storage lsa;
    socklen_t               local_socklen;
    s3_uint_t               have_lsa;

    have_lsa = 0;

    if (ul->wildcard && msg->msg_control != NULL) {

        s3_memzero(&lsa, sizeof(lsa));

        if (lc->sockaddr != NULL) {
            s3_memcpy(&lsa, lc->sockaddr, lc->socklen);

        } else {
            lsa.ss_family = sockaddr->sa_family;
        }

        for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL; cmsg = CMSG_NXTHDR(msg, cmsg)) {
            if (s3_get_srcaddr_cmsg(cmsg, (struct sockaddr *)&lsa) != 0) {
                have_lsa = 1;
                break;
            }
        }
    }

#else
    (void)msg;
    (void)lc;
#endif

    if (s3_quic_get_packet_dcid(ev->log, buffer, (size_t)n, &key) != S3_OK) {
        /* a malformed datagram cannot be routed to a connection */
        return S3_OK;
    }

    c = s3_quic_lookup_connection(ul, &key);

    if (c != NULL) {

        s3_quic_deliver(c, buffer, n, sockaddr, socklen);

        return S3_OK;
    }

    /* a new quic client */

    c = s3_get_connection(ul->ctx, lc->fd);
    if (c == NULL) {
        return S3_ERROR;
    }

    c->shared = 1;

    c->pool = s3_create_pool((size_t)S3_DEFAULT_POOL_SIZE, ev->log);
    if (c->pool == NULL) {
        s3_close_accepted_udp_connection(c);
        return S3_ERROR;
    }

    c->sockaddr = (struct sockaddr *)s3_palloc(c->pool, socklen);
    if (c->sockaddr == NULL) {
        s3_close_accepted_udp_connection(c);
        return S3_ERROR;
    }

    s3_memcpy(c->sockaddr, sockaddr, socklen);
    c->socklen = socklen;

    log = (s3_log_t *)s3_palloc(c->pool, sizeof(s3_log_t));
    if (log == NULL) {
        s3_close_accepted_udp_connection(c);
        return S3_ERROR;
    }

    *log = *ev->log;

    c->log = log;
    c->pool->log = log;

    c->send_chain = s3_udp_sendmsg_chain;
    /* c->recv is installed by s3_quic_run() (s3_quic_shared_recv) */

#if (S3_HAVE_ADDRINFO_CMSG)
    if (have_lsa) {

        c->local_sockaddr = (struct sockaddr *)s3_palloc(c->pool, socklen);
        if (c->local_sockaddr == NULL) {
            s3_close_accepted_udp_connection(c);
            return S3_ERROR;
        }

        local_socklen =
            (lsa.ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
        s3_memcpy(c->local_sockaddr, &lsa, local_socklen);
        c->local_socklen = local_socklen;

    } else
#endif
    {
        /* the local address of the listener */
        if (lc->sockaddr != NULL) {
            c->local_sockaddr = (struct sockaddr *)s3_palloc(c->pool, lc->socklen);
            if (c->local_sockaddr == NULL) {
                s3_close_accepted_udp_connection(c);
                return S3_ERROR;
            }

            s3_memcpy(c->local_sockaddr, lc->sockaddr, lc->socklen);
            c->local_socklen = lc->socklen;
        }
    }

    /* the first datagram is copied into the connection pool memory */

    b = s3_pcalloc(c->pool, sizeof(s3_buf_t));
    if (b == NULL) {
        s3_close_accepted_udp_connection(c);
        return S3_ERROR;
    }

    b->temporary = 1;
    b->start = s3_palloc(c->pool, n);
    if (b->start == NULL) {
        s3_close_accepted_udp_connection(c);
        return S3_ERROR;
    }

    b->pos = b->start;
    b->last = s3_cpymem(b->start, buffer, n);
    b->end = b->last;

    c->buffer = b;

    /* the listener backlink consumed by s3_quic_listen() */
    c->data = ul;

    rev = c->read;
    wev = c->write;

    rev->active = 1;
    wev->ready = 1;

    rev->log = log;
    wev->log = log;

    ul->handler(c);

    return S3_OK;
}

static void
s3_quic_deliver(s3_connection_t *c, u_char *buffer, ssize_t n, struct sockaddr *sockaddr,
                socklen_t socklen)
{
    s3_event_t       *rev;
    s3_quic_socket_t *qsock;

    qsock = (s3_quic_socket_t *)c->udp;

    s3_memcpy(&qsock->sockaddr, sockaddr, socklen);
    qsock->socklen = socklen;

    qsock->buffer = buffer;
    qsock->len = n;

    rev = c->read;

    rev->ready = 1;
    rev->active = 0;

    rev->handler(rev);

    if (c->udp != NULL) {
        qsock = (s3_quic_socket_t *)c->udp;
        qsock->buffer = NULL;
        qsock->len = 0;
    }

    rev->ready = 0;
    rev->active = 1;
}

static void
s3_close_accepted_udp_connection(s3_connection_t *c)
{
    /*
     * the connection itself lives in the context pool; the per
     * connection pool dies here and runs the cleanup handlers,
     * removing the pseudo connection from the rbtree
     */

    c->fd = -1;

    if (c->pool != NULL) {
        s3_destroy_pool(c->pool);
        c->pool = NULL;
    }
}

ssize_t
s3_udp_shared_recv(s3_connection_t *c, u_char *buf, size_t size)
{
    ssize_t n;

    if (c->udp == NULL || c->udp->buffer == NULL) {
        return (ssize_t)S3_AGAIN;
    }

    n = (ssize_t)s3_min(c->udp->len, size);

    s3_memcpy(buf, c->udp->buffer, n);

    c->udp->buffer = NULL;
    c->udp->len = 0;

    c->read->ready = 0;
    c->read->active = 1;

    return n;
}

void
s3_udp_rbtree_insert_value(s3_rbtree_node_t *temp, s3_rbtree_node_t *node,
                           s3_rbtree_node_t *sentinel)
{
    s3_int_t             rc;
    s3_rbtree_node_t   **p;
    s3_udp_connection_t *udp, *udpt;

    for (;;) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            udp = (s3_udp_connection_t *)node;
            udpt = (s3_udp_connection_t *)temp;

            rc = s3_udp_key_cmp(&udp->key, &udpt->key);

            p = (rc < 0) ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    s3_rbt_red(node);
}

void
s3_delete_udp_connection(void *data)
{
    s3_connection_t     *c = data;
    s3_udp_connection_t *udp;

    udp = c->udp;

    if (udp == NULL) {
        return;
    }

    s3_rbtree_delete(&udp->listen->rbtree, &udp->node);

    c->udp = NULL;
}

static s3_int_t
s3_insert_udp_connection(s3_udp_listen_t *ul, s3_connection_t *c)
{
    s3_pool_cleanup_t   *cln;
    s3_udp_connection_t *udp;
    u_char               text[S3_UDP_KEY_MAX];
    s3_str_t             key;

    udp = (s3_udp_connection_t *)s3_pcalloc(c->pool, sizeof(s3_udp_connection_t));
    if (udp == NULL) {
        return S3_ERROR;
    }

    udp->connection = c;
    udp->listen = ul;

    if (s3_udp_key_text(text, sizeof(text), &key, c->sockaddr, c->socklen, c->local_sockaddr,
                        ul->wildcard) != S3_OK) {
        return S3_ERROR;
    }

    udp->key.data = s3_pnalloc(c->pool, key.len);
    if (udp->key.data == NULL) {
        return S3_ERROR;
    }

    s3_memcpy(udp->key.data, key.data, key.len);
    udp->key.len = key.len;

    udp->node.key = s3_udp_key_hash(&udp->key);

    cln = s3_pool_cleanup_add(c->pool, 0);
    if (cln == NULL) {
        return S3_ERROR;
    }

    cln->data = c;
    cln->handler = s3_delete_udp_connection;

    s3_rbtree_insert(&ul->rbtree, &udp->node);

    c->udp = udp;

    return S3_OK;
}

static s3_connection_t *
s3_lookup_udp_connection(s3_udp_listen_t *ul, s3_connection_t *lc, struct sockaddr *sockaddr,
                         socklen_t socklen)
{
    s3_int_t             rc;
    s3_connection_t     *c;
    s3_rbtree_node_t    *node, *sentinel;
    s3_udp_connection_t *udp;
    u_char               text[S3_UDP_KEY_MAX];
    s3_str_t             key;

    if (s3_udp_key_text(text, sizeof(text), &key, sockaddr, socklen, lc->sockaddr, ul->wildcard) !=
        S3_OK) {
        return NULL;
    }

    node = ul->rbtree.root;
    sentinel = ul->rbtree.sentinel;

    while (node != sentinel) {

        if (s3_udp_key_hash(&key) < node->key) {
            node = node->left;
            continue;
        }

        if (s3_udp_key_hash(&key) > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        udp = (s3_udp_connection_t *)node;

        c = udp->connection;

        rc = s3_udp_key_cmp(&key, &udp->key);

        if (rc == 0) {
            return c;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}

static s3_int_t
s3_udp_key_text(u_char *buf, size_t max, s3_str_t *key, struct sockaddr *sa, socklen_t salen,
                struct sockaddr *local_sa, unsigned wildcard)
{
    size_t               len;
    struct sockaddr_in  *sin;
    struct sockaddr_in6 *sin6;
    u_char              *last;

    last = buf + max;

    switch (sa->sa_family) {

    case AF_INET:

        sin = (struct sockaddr_in *)sa;

        if (inet_ntop(AF_INET, &sin->sin_addr, (char *)buf, INET6_ADDRSTRLEN) == NULL) {
            return S3_ERROR;
        }

        len = s3_strlen(buf);

        len = s3_slprintf(buf + len, last, ":%uD", (s3_uint32_t)ntohs(sin->sin_port)) - buf;

        break;

    case AF_INET6:

        sin6 = (struct sockaddr_in6 *)sa;

        if (inet_ntop(AF_INET6, &sin6->sin6_addr, (char *)buf + 1, INET6_ADDRSTRLEN) == NULL) {
            return S3_ERROR;
        }

        buf[0] = '[';
        len = s3_strlen(buf);

        len = s3_slprintf(buf + len, last, "]:%uD", (s3_uint32_t)ntohs(sin6->sin6_port)) - buf;

        break;

    default:

        /* the raw sockaddr bytes as the key */

        if (salen > max) {
            return S3_ERROR;
        }

        s3_memcpy(buf, sa, salen);

        key->len = salen;
        key->data = buf;

        return S3_OK;
    }

    if (wildcard && local_sa != NULL && local_sa->sa_family == sa->sa_family) {

        if (sa->sa_family == AF_INET) {
            sin = (struct sockaddr_in *)local_sa;
            len = s3_slprintf(buf + len, last, "@%uD", (s3_uint32_t)ntohs(sin->sin_port)) - buf;

        } else {
            sin6 = (struct sockaddr_in6 *)local_sa;
            len = s3_slprintf(buf + len, last, "@%uD", (s3_uint32_t)ntohs(sin6->sin6_port)) - buf;
        }
    }

    key->len = len;
    key->data = buf;

    return S3_OK;
}

static s3_uint32_t
s3_udp_key_hash(s3_str_t *key)
{
    s3_uint32_t h;
    size_t      i;

    /* the fnv-1a hash */

    h = 2166136261u;

    for (i = 0; i < key->len; i++) {
        h ^= (s3_uint32_t)key->data[i];
        h *= 16777619u;
    }

    return h;
}

static s3_int_t
s3_udp_key_cmp(s3_str_t *k1, s3_str_t *k2)
{
    size_t   n;
    s3_int_t rc;

    n = (k1->len <= k2->len) ? k1->len : k2->len;

    rc = (s3_int_t)s3_memcmp(k1->data, k2->data, n);

    if (rc != 0 || k1->len == k2->len) {
        return rc;
    }

    return (k1->len < k2->len) ? -1 : 1;
}
