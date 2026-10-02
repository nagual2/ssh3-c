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

/* RFC 9000, 15.  Versions: QUIC v1 */
#define S3_QUIC_VERSION 1

#define S3_QUIC_MAX_RANGES 10

typedef s3_int_t (*s3_quic_init_pt)(s3_connection_t *c);

typedef void (*s3_quic_shutdown_pt)(s3_connection_t *c);

typedef struct s3_quic_stream_s s3_quic_stream_t;

/* RFC 9221, 5.  Datagram Handlers */
typedef void (*s3_quic_datagram_pt)(s3_connection_t *c, const u_char *data, size_t len);

/*
 * the new stream handler: the ssh3-c replacement of the nginx
 * c->listening->handler() call on an accepted stream
 * (porting map 4.3.6)
 */
typedef void (*s3_quic_stream_pt)(s3_connection_t *c, s3_quic_stream_t *qs);

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
    /* the event context for the quic timers and posted events */
    s3_event_ctx_t *ctx;

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

    /*
     * the new stream handler; called on an accepted stream, NULL
     * rejects new streams with conf->stream_reject_code_*
     */
    s3_quic_stream_pt stream_handler;

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
 * public API (the D2 core); the stream functions follow in D4
 */
void s3_quic_run(s3_connection_t *c, s3_quic_conf_t *conf);

/* the client role: initiates the handshake towards c->sockaddr */
s3_int_t s3_quic_connect(s3_connection_t *c, s3_quic_conf_t *conf);

void s3_quic_finalize_connection(s3_connection_t *c, s3_uint_t err, const char *reason);
void s3_quic_shutdown_connection(s3_connection_t *c, s3_uint_t err, const char *reason);

s3_int_t s3_quic_derive_key(s3_log_t *log, const char *label, s3_str_t *secret, s3_str_t *salt,
                            u_char *out, size_t len);

s3_int_t s3_quic_get_packet_dcid(s3_log_t *log, u_char *data, size_t len, s3_str_t *dcid);

/*
 * the listener services for the udp layer (porting map 4.3): the
 * rbtree of a quic listener holds s3_quic_socket_t nodes keyed by
 * the crc32 of the connection id (the reference ngx_event_quic_udp.c)
 */
void             s3_quic_rbtree_insert_socket(s3_rbtree_node_t *temp, s3_rbtree_node_t *node,
                                              s3_rbtree_node_t *sentinel);
s3_connection_t *s3_quic_lookup_connection(s3_udp_listen_t *ul, s3_str_t *key);

/* the shared-datagram recv installed as c->recv on the quic connections */
ssize_t s3_quic_shared_recv(s3_connection_t *c, u_char *buf, size_t size);

/*
 * the stream API (D4): open a stream initiated by the application,
 * mark it cancelable, reset the receiving part, shut down directions;
 * the accepted streams are handed over through conf->stream_handler
 */
s3_connection_t *s3_quic_open_stream(s3_connection_t *c, s3_uint_t bidi);
void             s3_quic_cancelable_stream(s3_connection_t *c);
s3_int_t         s3_quic_reset_stream(s3_connection_t *c, s3_uint_t err);
s3_int_t         s3_quic_shutdown_stream(s3_connection_t *c, int how);

#endif /* _S3_QUIC_H_INCLUDED_ */
