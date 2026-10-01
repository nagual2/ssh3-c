/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_QUIC_H_INCLUDED_
#define _S3_QUIC_H_INCLUDED_

#include <s3_base.h>
#include <s3_str.h>
#include <s3_string.h>
#include <s3_log.h>
#include <s3_palloc.h>
#include <s3_buf.h>
#include <s3_queue.h>
#include <s3_event.h>
#include <s3_connection.h>

/*
 * QUIC transport layer, adapted from nginx src/event/quic.
 *
 * Only the OpenSSL (>= 3.5) QUIC TLS API branch is carried over; the
 * CMake build enforces the version via find_package(OpenSSL 3.5).
 */
#define S3_QUIC_OPENSSL_API 1

/* the QUIC layer is Linux-first; the epoll event method implies IPv6 */
#define S3_HAVE_INET6 1

#define S3_QUIC_MAX_UDP_PAYLOAD_SIZE 65527

#define S3_QUIC_DEFAULT_ACK_DELAY_EXPONENT 3
#define S3_QUIC_DEFAULT_MAX_ACK_DELAY      25
#define S3_QUIC_DEFAULT_HOST_KEY_LEN       32
#define S3_QUIC_SR_KEY_LEN                 32
#define S3_QUIC_AV_KEY_LEN                 32

#define S3_QUIC_SR_TOKEN_LEN 16

#define S3_QUIC_MIN_INITIAL_SIZE 1200

#define S3_QUIC_STREAM_SERVER_INITIATED 0x01
#define S3_QUIC_STREAM_UNIDIRECTIONAL   0x02

#define S3_QUIC_MAX_CID_LEN    20
#define S3_QUIC_SERVER_CID_LEN S3_QUIC_MAX_CID_LEN

#define S3_QUIC_CID_LEN_MIN 8
#define S3_QUIC_CID_LEN_MAX 20

#define S3_QUIC_MAX_RANGES 10

typedef s3_int_t (*s3_quic_init_pt)(s3_connection_t *c);

typedef void (*s3_quic_shutdown_pt)(s3_connection_t *c);

/* RFC 9221, 5.  Datagram Handlers */
typedef void (*s3_quic_datagram_pt)(s3_connection_t *c, const u_char *data, size_t len);

typedef enum {
    S3_QUIC_STREAM_SEND_READY = 0,
    S3_QUIC_STREAM_SEND_SEND,
    S3_QUIC_STREAM_SEND_DATA_SENT,
    S3_QUIC_STREAM_SEND_DATA_RECVD,
    S3_QUIC_STREAM_SEND_RESET_SENT,
    S3_QUIC_STREAM_SEND_RESET_RECVD
} s3_quic_stream_send_state_e;

typedef enum {
    S3_QUIC_STREAM_RECV_RECV = 0,
    S3_QUIC_STREAM_RECV_SIZE_KNOWN,
    S3_QUIC_STREAM_RECV_DATA_RECVD,
    S3_QUIC_STREAM_RECV_DATA_READ,
    S3_QUIC_STREAM_RECV_RESET_RECVD,
    S3_QUIC_STREAM_RECV_RESET_READ
} s3_quic_stream_recv_state_e;

typedef struct {
    uint64_t    size;
    uint64_t    offset;
    uint64_t    last_offset;
    s3_chain_t *chain;
    s3_chain_t *last_chain;
} s3_quic_buffer_t;

/*
 * 0-RTT and 1-RTT data exist in the same packet number space,
 * so we have 3 packet number spaces:
 *
 * 0 - Initial
 * 1 - Handshake
 * 2 - 0-RTT and 1-RTT
 */
#define S3_QUIC_ENCRYPTION_INITIAL     0
#define S3_QUIC_ENCRYPTION_EARLY_DATA  1
#define S3_QUIC_ENCRYPTION_HANDSHAKE   2
#define S3_QUIC_ENCRYPTION_APPLICATION 3
#define S3_QUIC_ENCRYPTION_LAST        4

#define S3_QUIC_SEND_CTX_LAST (S3_QUIC_ENCRYPTION_LAST - 1)

/* RFC 9002, 6.2.2.  Handshakes and New Paths: kInitialRtt */
#define S3_QUIC_INITIAL_RTT 333 /* ms */

#define S3_QUIC_UNSET_PN (uint64_t) - 1

typedef struct s3_quic_keys_s       s3_quic_keys_t;
typedef struct s3_quic_connection_s s3_quic_connection_t;
typedef struct s3_quic_path_s       s3_quic_path_t;
typedef struct s3_quic_client_id_s  s3_quic_client_id_t;
typedef struct s3_quic_server_id_s  s3_quic_server_id_t;
typedef struct s3_quic_socket_s     s3_quic_socket_t;
typedef struct s3_quic_send_ctx_s   s3_quic_send_ctx_t;
typedef struct s3_ssl_s             s3_ssl_t;

typedef struct s3_quic_conf_s s3_quic_conf_t;

/*
 * filled by the ssh3-c configurator, the nginx directive parsers
 * are not ported
 */
struct s3_quic_conf_s {
    s3_ssl_t *ssl;

    unsigned retry : 1;
    unsigned gso_enabled : 1;
    unsigned disable_active_migration : 1;

    s3_msec_t handshake_timeout;
    s3_msec_t idle_timeout;

    s3_str_t host_key;

    size_t stream_buffer_size;

    s3_uint_t max_concurrent_streams_bidi;
    s3_uint_t max_concurrent_streams_uni;
    s3_uint_t active_connection_id_limit;

    /* RFC 9221: 0 disables datagrams, the TP is not sent then */
    s3_uint_t max_datagram_frame_size;

    s3_int_t stream_close_code;
    s3_int_t stream_reject_code_uni;
    s3_int_t stream_reject_code_bidi;

    s3_quic_init_pt     init;
    s3_quic_shutdown_pt shutdown;

    /* the datagram handler; called on an accepted DATAGRAM frame */
    s3_quic_datagram_pt datagram_handler;

    u_char av_token_key[S3_QUIC_AV_KEY_LEN];
    u_char sr_token_key[S3_QUIC_SR_KEY_LEN];
};

typedef struct {
    uint64_t gap;
    uint64_t range;
} s3_quic_ack_range_t;

/*
 * RFC 9000, 18.2.  Transport Parameters
 */
typedef struct {
    s3_msec_t max_idle_timeout;
    s3_msec_t max_ack_delay;

    size_t    max_udp_payload_size;
    size_t    initial_max_data;
    size_t    initial_max_stream_data_bidi_local;
    size_t    initial_max_stream_data_bidi_remote;
    size_t    initial_max_stream_data_uni;
    s3_uint_t initial_max_streams_bidi;
    s3_uint_t initial_max_streams_uni;
    s3_uint_t ack_delay_exponent;
    s3_uint_t active_connection_id_limit;
    s3_uint_t disable_active_migration;

    /* RFC 9221, 4.  Transport Parameter */
    s3_uint_t max_datagram_frame_size;

    s3_str_t original_dcid;
    s3_str_t initial_scid;
    s3_str_t retry_scid;
    u_char   sr_token[S3_QUIC_SR_TOKEN_LEN];

    /* TODO */
    void *preferred_address;
} s3_quic_tp_t;

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
 * D1 subset: the frame/buffer freelists, the packet number spaces and
 * the client id bookkeeping the clean modules (frames, connid) need.
 * D2 completes the structure with paths, sockets, keys, the stream
 * tree, congestion state, events and the lifecycle flags.
 */
struct s3_quic_connection_s {
    s3_queue_t free_frames;
    s3_buf_t  *free_bufs;
    s3_buf_t  *free_shadow_bufs;
    s3_uint_t  nframes;
    s3_uint_t  max_frames;

    s3_quic_send_ctx_t send_ctx[S3_QUIC_SEND_CTX_LAST];

    s3_queue_t client_ids;
    s3_queue_t free_client_ids;
    s3_uint_t  nclient_ids;
    uint64_t   client_seqnum;
    uint64_t   max_retired_seqnum;

    /* our and the peer transport parameters */
    s3_quic_tp_t tp;
    s3_quic_tp_t ctp;

    s3_uint_t   error;
    const char *error_reason;
};

#define s3_quic_get_send_ctx(qc, level)                                                            \
    ((level) == S3_QUIC_ENCRYPTION_INITIAL)                                                        \
        ? &((qc)->send_ctx[0])                                                                     \
        : (((level) == S3_QUIC_ENCRYPTION_HANDSHAKE) ? &((qc)->send_ctx[1])                        \
                                                     : &((qc)->send_ctx[2]))

/*
 * D1 placeholder: the QUIC connection is reached through c->data;
 * D2 replaces this with the socket-based lookup (c->udp -> qsock->quic)
 */
#define s3_quic_get_connection(c) ((s3_quic_connection_t *)((c)->data))

s3_int_t s3_quic_derive_key(s3_log_t *log, const char *label, s3_str_t *secret, s3_str_t *salt,
                            u_char *out, size_t len);

s3_int_t s3_quic_get_packet_dcid(s3_log_t *log, u_char *data, size_t len, s3_str_t *dcid);

#endif /* _S3_QUIC_H_INCLUDED_ */
