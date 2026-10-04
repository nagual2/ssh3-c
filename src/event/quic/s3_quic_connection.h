/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_QUIC_CONNECTION_H_INCLUDED_
#define _S3_QUIC_CONNECTION_H_INCLUDED_

#include <netinet/in.h>

#include <s3_sock_ntop.h>

#include <s3_quic.h>
#include <s3_quic_transport.h>
#include <s3_quic_protection.h>
#include <s3_quic_frames.h>
#include <s3_quic_streams.h>
#include <s3_quic_connid.h>
#include <s3_quic_migration.h>
#include <s3_ssl.h>
#include <s3_quic_ssl.h>
#include <s3_quic_tokens.h>

/* #define S3_QUIC_DEBUG_PACKETS */ /* dump packet contents */
/* #define S3_QUIC_DEBUG_FRAMES */  /* dump frames contents */
/* #define S3_QUIC_DEBUG_ALLOC */   /* log frames and bufs alloc */
/* #define S3_QUIC_DEBUG_CRYPTO */

#define s3_quic_init_rtt(qc)                                                                       \
    (qc)->avg_rtt = S3_QUIC_INITIAL_RTT;                                                           \
    (qc)->rttvar = S3_QUIC_INITIAL_RTT / 2;                                                        \
    (qc)->min_rtt = S3_TIMER_INFINITE;                                                             \
    (qc)->first_rtt = S3_TIMER_INFINITE;                                                           \
    (qc)->latest_rtt = 0;

#define s3_quic_get_send_ctx(qc, level)                                                            \
    ((level) == S3_QUIC_ENCRYPTION_INITIAL)                                                        \
        ? &((qc)->send_ctx[0])                                                                     \
        : (((level) == S3_QUIC_ENCRYPTION_HANDSHAKE) ? &((qc)->send_ctx[1])                        \
                                                     : &((qc)->send_ctx[2]))

/*
 * the QUIC connection and the send context are reached through the
 * pseudo udp connection pointer, which points to a s3_quic_socket_t
 * for accepted quic connections (porting map 4.3.3)
 */
#define s3_quic_get_connection(c) (((c)->udp) ? ((s3_quic_socket_t *)((c)->udp))->quic : NULL)

#define s3_quic_get_socket(c) ((s3_quic_socket_t *)((c)->udp))

typedef enum {
    S3_QUIC_PATH_IDLE = 0,
    S3_QUIC_PATH_VALIDATING,
    S3_QUIC_PATH_WAITING,
    S3_QUIC_PATH_MTUD
} s3_quic_path_state_e;

/* path->tag values, ported from ngx_event_quic_migration.h (D4) */
#define S3_QUIC_PATH_PROBE  0
#define S3_QUIC_PATH_ACTIVE 1
#define S3_QUIC_PATH_BACKUP 2

#define S3_QUIC_PATH_RETRIES 3

struct s3_quic_client_id_s {
    s3_queue_t queue;
    uint64_t   seqnum;
    size_t     len;
    u_char     id[S3_QUIC_CID_LEN_MAX];
    u_char     sr_token[S3_QUIC_SR_TOKEN_LEN];
    s3_uint_t  used; /* unsigned  used:1; */
};

struct s3_quic_server_id_s {
    uint64_t seqnum;
    size_t   len;
    u_char   id[S3_QUIC_CID_LEN_MAX];
};

/*
 * RFC 9000, 12.3.  Packet Numbers
 *
 * Conceptually, a packet number space is the context in which a packet
 * can be processed and acknowledged.  Initial packets can only be sent
 * with Initial packet protection keys and acknowledged in packets that
 * are also Initial packets.
 */
struct s3_quic_send_ctx_s {
    s3_uint_t level;

    s3_quic_buffer_t crypto;
    uint64_t         crypto_sent;

    uint64_t pnum;        /* to be sent */
    uint64_t largest_ack; /* received from peer */
    uint64_t largest_pn;  /* received from peer */

    s3_queue_t frames;  /* generated frames */
    s3_queue_t sending; /* frames assigned to pkt */
    s3_queue_t sent;    /* frames waiting ACK */

    uint64_t            pending_ack; /* non sent ack-eliciting */
    uint64_t            largest_range;
    uint64_t            first_range;
    s3_msec_t           largest_received;
    s3_msec_t           ack_delay_start;
    s3_uint_t           nranges;
    s3_quic_ack_range_t ranges[S3_QUIC_MAX_RANGES];
    s3_uint_t           send_ack;
};

struct s3_quic_path_s {
    s3_queue_t              queue;
    struct sockaddr        *sockaddr;
    struct sockaddr_storage sa;
    socklen_t               socklen;
    s3_quic_client_id_t    *cid;
    s3_quic_path_state_e    state;
    s3_msec_t               expires;
    s3_uint_t               tries;
    s3_uint_t               tag;
    size_t                  mtu;
    size_t                  mtud;
    size_t                  max_mtu;
    off_t                   sent;
    off_t                   received;
    u_char                  challenge[2][8];
    uint64_t                seqnum;
    uint64_t                mtu_pnum[S3_QUIC_PATH_RETRIES];
    s3_str_t                addr_text;
    u_char                  text[S3_SOCKADDR_STRLEN];

    unsigned validated : 1;
    unsigned mtu_unvalidated : 1;
};

/*
 * replaces the P1 pseudo connection node in the listener rbtree;
 * the leading node/connection pair matches s3_udp_connection_t, so
 * a quic socket can be found through c->udp like in nginx
 */
struct s3_quic_socket_s {
    s3_rbtree_node_t        node;
    s3_connection_t        *connection;
    s3_quic_connection_t   *quic;
    s3_queue_t              queue;
    s3_quic_server_id_t     sid;
    struct sockaddr_storage sockaddr;
    socklen_t               socklen;
    s3_udp_listen_t        *listen; /* set on the listener rbtree registration */
    s3_uint_t               used;   /* unsigned  used:1; */

    /* the datagram handed over by the listener, read through c->recv() */
    u_char *buffer;
    size_t  len;
};

/*
 * the stream pseudo connection and its flow control state (the
 * reference ngx_quic_stream_s); the connection of the stream lives in
 * connection->data, like the reference sc->quic (porting map 4.3.2)
 */
struct s3_quic_stream_s {
    s3_rbtree_node_t            node;
    s3_queue_t                  queue;
    s3_connection_t            *parent;
    s3_connection_t            *connection;
    uint64_t                    id;
    uint64_t                    sent;
    uint64_t                    acked;
    uint64_t                    send_max_data;
    uint64_t                    send_offset;
    uint64_t                    send_final_size;
    uint64_t                    recv_max_data;
    uint64_t                    recv_offset;
    uint64_t                    recv_window;
    uint64_t                    recv_last;
    uint64_t                    recv_final_size;
    s3_quic_buffer_t            send;
    s3_quic_buffer_t            recv;
    s3_quic_stream_send_state_e send_state;
    s3_quic_stream_recv_state_e recv_state;
    unsigned                    cancelable : 1;
    unsigned                    fin_acked : 1;
};

typedef struct {
    s3_rbtree_t      tree;
    s3_rbtree_node_t sentinel;

    s3_queue_t uninitialized;
    s3_queue_t free;

    uint64_t sent;
    uint64_t recv_offset;
    uint64_t recv_window;
    uint64_t recv_last;
    uint64_t recv_max_data;
    uint64_t send_offset;
    uint64_t send_max_data;

    uint64_t server_max_streams_uni;
    uint64_t server_max_streams_bidi;
    uint64_t server_streams_uni;
    uint64_t server_streams_bidi;

    uint64_t client_max_streams_uni;
    uint64_t client_max_streams_bidi;
    uint64_t client_streams_uni;
    uint64_t client_streams_bidi;

    s3_uint_t initialized;
    /* unsigned  initialized:1; */
} s3_quic_streams_t;

typedef struct {
    size_t    in_flight;
    size_t    window;
    size_t    ssthresh;
    size_t    w_max;
    size_t    w_est;
    size_t    w_prior;
    size_t    mtu;
    s3_msec_t recovery_start;
    s3_msec_t idle_start;
    s3_msec_t k;
    s3_uint_t idle; /* unsigned  idle:1; */
} s3_quic_congestion_t;

struct s3_quic_connection_s {
    uint32_t version;

    s3_quic_path_t *path;

    s3_queue_t sockets;
    s3_queue_t paths;
    s3_queue_t client_ids;
    s3_queue_t free_sockets;
    s3_queue_t free_paths;
    s3_queue_t free_client_ids;

    s3_uint_t nsockets;
    s3_uint_t nclient_ids;
    uint64_t  max_retired_seqnum;
    uint64_t  client_seqnum;
    uint64_t  server_seqnum;
    uint64_t  path_seqnum;

    s3_quic_tp_t tp;
    s3_quic_tp_t ctp;

    s3_quic_send_ctx_t send_ctx[S3_QUIC_SEND_CTX_LAST];

    s3_quic_keys_t *keys;

    s3_quic_conf_t *conf;

    /*
     * the event context the quic timers and the posted events belong
     * to; it replaces the nginx globals (porting map 4.1)
     */
    s3_event_ctx_t *ctx;

    /*
     * the listener backlink the udp layer parked in c->data at accept
     * time; the quic connection takes it over and leaves c->data to the
     * connection owner (the h3 session), like the reference keeps the
     * listening socket in the connection struct rather than in c->data
     */
    s3_udp_listen_t *listen;

    s3_event_t push;
    s3_event_t pto;
    s3_event_t close;
    s3_event_t path_validation;
    s3_event_t key_update;

    s3_msec_t last_cc;

    s3_msec_t first_rtt;
    s3_msec_t latest_rtt;
    s3_msec_t avg_rtt;
    s3_msec_t min_rtt;
    s3_msec_t rttvar;

    s3_uint_t pto_count;

    s3_queue_t free_frames;
    s3_buf_t  *free_bufs;
    s3_buf_t  *free_shadow_bufs;

    s3_uint_t nframes;
    s3_uint_t max_frames;
#ifdef S3_QUIC_DEBUG_ALLOC
    s3_uint_t nbufs;
    s3_uint_t nshadowbufs;
#endif

    s3_quic_streams_t    streams;
    s3_quic_congestion_t congestion;

    uint64_t rst_pnum; /* first on validated path */

    /* RFC 9221: datagrams sent, awaiting acknowledgement of neighbours */
    uint64_t datagrams_in_flight;

    off_t received;

    s3_uint_t   error;
    s3_uint_t   error_level;
    s3_uint_t   error_ftype;
    const char *error_reason;

    s3_uint_t   shutdown_code;
    const char *shutdown_reason;

    unsigned error_app : 1;
    unsigned send_timer_set : 1;
    unsigned closing : 1;
    unsigned shutdown : 1;
    unsigned draining : 1;
    unsigned key_phase : 1;
    unsigned validated : 1;
    unsigned client_tp_done : 1;

    /* RFC 9001, 4.1.2: a client confirms on HANDSHAKE_DONE */
    unsigned handshake_confirmed : 1;

    /* the nginx c->reusable flag, porting map 4.3.9 */
    unsigned reusable : 1;

    /* the client role created by s3_quic_connect() */
    unsigned client : 1;

#if (S3_QUIC_OPENSSL_API)
    unsigned read_level : 2;
    unsigned write_level : 2;
#endif
};

s3_int_t s3_quic_apply_transport_params(s3_connection_t *c, s3_quic_tp_t *ctp);
void     s3_quic_discard_ctx(s3_connection_t *c, s3_uint_t level);
void     s3_quic_close_connection(s3_connection_t *c, s3_int_t rc);
void     s3_quic_shutdown_quic(s3_connection_t *c);

/*
 * the socket functions (the reference ngx_event_quic_socket.c); the
 * path functions live in s3_quic_migration.h
 */
s3_int_t s3_quic_open_sockets(s3_connection_t *c, s3_quic_connection_t *qc, s3_quic_header_t *pkt);
void     s3_quic_close_sockets(s3_connection_t *c);
s3_quic_socket_t *s3_quic_create_socket(s3_connection_t *c, s3_quic_connection_t *qc);
s3_int_t s3_quic_listen(s3_connection_t *c, s3_quic_connection_t *qc, s3_quic_socket_t *qsock);
void     s3_quic_close_socket(s3_connection_t *c, s3_quic_socket_t *qsock);
s3_quic_socket_t *s3_quic_find_socket(s3_connection_t *c, uint64_t seqnum);

#endif /* _S3_QUIC_CONNECTION_H_INCLUDED_ */
