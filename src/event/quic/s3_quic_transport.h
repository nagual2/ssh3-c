/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_QUIC_TRANSPORT_H_INCLUDED_
#define _S3_QUIC_TRANSPORT_H_INCLUDED_

#include <s3_quic.h>

/*
 * RFC 9000, 17.2.  Long Header Packets
 *           17.3.  Short Header Packets
 *
 * QUIC flags in first byte
 */
#define S3_QUIC_PKT_LONG      0x80 /* header form */
#define S3_QUIC_PKT_FIXED_BIT 0x40
#define S3_QUIC_PKT_TYPE      0x30 /* in long packet */
#define S3_QUIC_PKT_KPHASE    0x04 /* in short packet */

#define s3_quic_long_pkt(flags)  ((flags) & S3_QUIC_PKT_LONG)
#define s3_quic_short_pkt(flags) (((flags) & S3_QUIC_PKT_LONG) == 0)

/* Long packet types */
#define S3_QUIC_PKT_INITIAL   0x00
#define S3_QUIC_PKT_ZRTT      0x10
#define S3_QUIC_PKT_HANDSHAKE 0x20
#define S3_QUIC_PKT_RETRY     0x30

#define s3_quic_pkt_in(flags)    (((flags) & S3_QUIC_PKT_TYPE) == S3_QUIC_PKT_INITIAL)
#define s3_quic_pkt_zrtt(flags)  (((flags) & S3_QUIC_PKT_TYPE) == S3_QUIC_PKT_ZRTT)
#define s3_quic_pkt_hs(flags)    (((flags) & S3_QUIC_PKT_TYPE) == S3_QUIC_PKT_HANDSHAKE)
#define s3_quic_pkt_retry(flags) (((flags) & S3_QUIC_PKT_TYPE) == S3_QUIC_PKT_RETRY)

#define s3_quic_pkt_rb_mask(flags) (s3_quic_long_pkt(flags) ? 0x0C : 0x18)
#define s3_quic_pkt_hp_mask(flags) (s3_quic_long_pkt(flags) ? 0x0F : 0x1F)

#define s3_quic_level_name(lvl)                                                                    \
    (lvl == S3_QUIC_ENCRYPTION_APPLICATION) ? "app"                                                \
    : (lvl == S3_QUIC_ENCRYPTION_INITIAL)   ? "init"                                               \
    : (lvl == S3_QUIC_ENCRYPTION_HANDSHAKE) ? "hs"                                                 \
                                            : "early"

/* 12.4.  Frames and Frame Types */
#define S3_QUIC_FT_PADDING              0x00
#define S3_QUIC_FT_PING                 0x01
#define S3_QUIC_FT_ACK                  0x02
#define S3_QUIC_FT_ACK_ECN              0x03
#define S3_QUIC_FT_RESET_STREAM         0x04
#define S3_QUIC_FT_STOP_SENDING         0x05
#define S3_QUIC_FT_CRYPTO               0x06
#define S3_QUIC_FT_NEW_TOKEN            0x07
#define S3_QUIC_FT_STREAM               0x08
#define S3_QUIC_FT_STREAM1              0x09
#define S3_QUIC_FT_STREAM2              0x0A
#define S3_QUIC_FT_STREAM3              0x0B
#define S3_QUIC_FT_STREAM4              0x0C
#define S3_QUIC_FT_STREAM5              0x0D
#define S3_QUIC_FT_STREAM6              0x0E
#define S3_QUIC_FT_STREAM7              0x0F
#define S3_QUIC_FT_MAX_DATA             0x10
#define S3_QUIC_FT_MAX_STREAM_DATA      0x11
#define S3_QUIC_FT_MAX_STREAMS          0x12
#define S3_QUIC_FT_MAX_STREAMS2         0x13
#define S3_QUIC_FT_DATA_BLOCKED         0x14
#define S3_QUIC_FT_STREAM_DATA_BLOCKED  0x15
#define S3_QUIC_FT_STREAMS_BLOCKED      0x16
#define S3_QUIC_FT_STREAMS_BLOCKED2     0x17
#define S3_QUIC_FT_NEW_CONNECTION_ID    0x18
#define S3_QUIC_FT_RETIRE_CONNECTION_ID 0x19
#define S3_QUIC_FT_PATH_CHALLENGE       0x1A
#define S3_QUIC_FT_PATH_RESPONSE        0x1B
#define S3_QUIC_FT_CONNECTION_CLOSE     0x1C
#define S3_QUIC_FT_CONNECTION_CLOSE_APP 0x1D
#define S3_QUIC_FT_HANDSHAKE_DONE       0x1E

/* RFC 9221, 4.  DATAGRAM Frame Types */
#define S3_QUIC_FT_DATAGRAM             0x30
#define S3_QUIC_FT_DATAGRAM_WITH_LENGTH 0x31

#define S3_QUIC_FT_LAST S3_QUIC_FT_DATAGRAM_WITH_LENGTH

/* 22.5.  QUIC Transport Error Codes Registry */
#define S3_QUIC_ERR_NO_ERROR                  0x00
#define S3_QUIC_ERR_INTERNAL_ERROR            0x01
#define S3_QUIC_ERR_CONNECTION_REFUSED        0x02
#define S3_QUIC_ERR_FLOW_CONTROL_ERROR        0x03
#define S3_QUIC_ERR_STREAM_LIMIT_ERROR        0x04
#define S3_QUIC_ERR_STREAM_STATE_ERROR        0x05
#define S3_QUIC_ERR_FINAL_SIZE_ERROR          0x06
#define S3_QUIC_ERR_FRAME_ENCODING_ERROR      0x07
#define S3_QUIC_ERR_TRANSPORT_PARAMETER_ERROR 0x08
#define S3_QUIC_ERR_CONNECTION_ID_LIMIT_ERROR 0x09
#define S3_QUIC_ERR_PROTOCOL_VIOLATION        0x0A
#define S3_QUIC_ERR_INVALID_TOKEN             0x0B
#define S3_QUIC_ERR_APPLICATION_ERROR         0x0C
#define S3_QUIC_ERR_CRYPTO_BUFFER_EXCEEDED    0x0D
#define S3_QUIC_ERR_KEY_UPDATE_ERROR          0x0E
#define S3_QUIC_ERR_AEAD_LIMIT_REACHED        0x0F
#define S3_QUIC_ERR_NO_VIABLE_PATH            0x10

#define S3_QUIC_ERR_CRYPTO_ERROR 0x100

#define S3_QUIC_ERR_CRYPTO(e) (S3_QUIC_ERR_CRYPTO_ERROR + (e))

/* 22.3.  QUIC Transport Parameters Registry */
#define S3_QUIC_TP_ORIGINAL_DCID                       0x00
#define S3_QUIC_TP_MAX_IDLE_TIMEOUT                    0x01
#define S3_QUIC_TP_SR_TOKEN                            0x02
#define S3_QUIC_TP_MAX_UDP_PAYLOAD_SIZE                0x03
#define S3_QUIC_TP_INITIAL_MAX_DATA                    0x04
#define S3_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL  0x05
#define S3_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE 0x06
#define S3_QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI         0x07
#define S3_QUIC_TP_INITIAL_MAX_STREAMS_BIDI            0x08
#define S3_QUIC_TP_INITIAL_MAX_STREAMS_UNI             0x09
#define S3_QUIC_TP_ACK_DELAY_EXPONENT                  0x0A
#define S3_QUIC_TP_MAX_ACK_DELAY                       0x0B
#define S3_QUIC_TP_DISABLE_ACTIVE_MIGRATION            0x0C
#define S3_QUIC_TP_PREFERRED_ADDRESS                   0x0D
#define S3_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT          0x0E
#define S3_QUIC_TP_INITIAL_SCID                        0x0F
#define S3_QUIC_TP_RETRY_SCID                          0x10

/* RFC 9221, 4.  max_datagram_frame_size */
#define S3_QUIC_TP_MAX_DATAGRAM_FRAME_SIZE 0x20

typedef struct {
    uint64_t length;
} s3_quic_datagram_frame_t;

typedef struct {
    uint64_t largest;
    uint64_t delay;
    uint64_t range_count;
    uint64_t first_range;
    uint64_t ect0;
    uint64_t ect1;
    uint64_t ce;
    uint64_t ranges_length;
} s3_quic_ack_frame_t;

typedef struct {
    uint64_t seqnum;
    uint64_t retire;
    uint8_t  len;
    u_char   cid[S3_QUIC_CID_LEN_MAX];
    u_char   srt[S3_QUIC_SR_TOKEN_LEN];
} s3_quic_new_conn_id_frame_t;

typedef struct {
    uint64_t length;
} s3_quic_new_token_frame_t;

/*
 * common layout for CRYPTO and STREAM frames;
 * conceptually, CRYPTO frame is also a stream
 * frame lacking some properties
 */
typedef struct {
    uint64_t offset;
    uint64_t length;
} s3_quic_ordered_frame_t;

typedef s3_quic_ordered_frame_t s3_quic_crypto_frame_t;

typedef struct {
    /* initial fields same as in s3_quic_ordered_frame_t */
    uint64_t offset;
    uint64_t length;

    uint64_t stream_id;
    unsigned off : 1;
    unsigned len : 1;
    unsigned fin : 1;
} s3_quic_stream_frame_t;

typedef struct {
    uint64_t max_data;
} s3_quic_max_data_frame_t;

typedef struct {
    uint64_t error_code;
    uint64_t frame_type;
    s3_str_t reason;
} s3_quic_close_frame_t;

typedef struct {
    uint64_t id;
    uint64_t error_code;
    uint64_t final_size;
} s3_quic_reset_stream_frame_t;

typedef struct {
    uint64_t id;
    uint64_t error_code;
} s3_quic_stop_sending_frame_t;

typedef struct {
    uint64_t  limit;
    s3_uint_t bidi; /* unsigned: bidi:1 */
} s3_quic_streams_blocked_frame_t;

typedef struct {
    uint64_t  limit;
    s3_uint_t bidi; /* unsigned: bidi:1 */
} s3_quic_max_streams_frame_t;

typedef struct {
    uint64_t id;
    uint64_t limit;
} s3_quic_max_stream_data_frame_t;

typedef struct {
    uint64_t limit;
} s3_quic_data_blocked_frame_t;

typedef struct {
    uint64_t id;
    uint64_t limit;
} s3_quic_stream_data_blocked_frame_t;

typedef struct {
    uint64_t sequence_number;
} s3_quic_retire_cid_frame_t;

typedef struct {
    u_char data[8];
} s3_quic_path_challenge_frame_t;

typedef struct s3_quic_frame_s s3_quic_frame_t;

struct s3_quic_frame_s {
    s3_uint_t  type;
    s3_uint_t  level;
    s3_queue_t queue;
    uint64_t   pnum;
    size_t     plen;
    s3_msec_t  send_time;
    ssize_t    len;
    unsigned   need_ack : 1;
    unsigned   pkt_need_ack : 1;
    unsigned   ignore_congestion : 1;
    unsigned   ignore_loss : 1;

    s3_chain_t *data;
    union {
        s3_quic_ack_frame_t                 ack;
        s3_quic_crypto_frame_t              crypto;
        s3_quic_ordered_frame_t             ord;
        s3_quic_new_conn_id_frame_t         ncid;
        s3_quic_new_token_frame_t           token;
        s3_quic_stream_frame_t              stream;
        s3_quic_max_data_frame_t            max_data;
        s3_quic_close_frame_t               close;
        s3_quic_reset_stream_frame_t        reset_stream;
        s3_quic_stop_sending_frame_t        stop_sending;
        s3_quic_streams_blocked_frame_t     streams_blocked;
        s3_quic_max_streams_frame_t         max_streams;
        s3_quic_max_stream_data_frame_t     max_stream_data;
        s3_quic_data_blocked_frame_t        data_blocked;
        s3_quic_stream_data_blocked_frame_t stream_data_blocked;
        s3_quic_retire_cid_frame_t          retire_cid;
        s3_quic_path_challenge_frame_t      path_challenge;
        s3_quic_path_challenge_frame_t      path_response;
        s3_quic_datagram_frame_t            datagram;
    } u;
};

typedef struct {
    s3_log_t       *log;
    s3_quic_path_t *path;

    s3_quic_keys_t *keys;

    s3_msec_t received;
    uint64_t  number;
    uint8_t   num_len;
    uint32_t  trunc;
    uint8_t   flags;
    uint32_t  version;
    s3_str_t  token;
    s3_uint_t level;
    s3_uint_t error;

    /* filled in by parser */
    s3_buf_t *raw; /* udp datagram */

    u_char *data; /* quic packet */
    size_t  len;

    /* cleartext fields */
    s3_str_t odcid; /* retry packet tag */
    u_char   odcid_buf[S3_QUIC_MAX_CID_LEN];
    s3_str_t dcid;
    s3_str_t scid;
    uint64_t pn;
    u_char  *plaintext;
    s3_str_t payload; /* decrypted data */

    unsigned need_ack : 1;
    unsigned key_phase : 1;
    unsigned key_update : 1;
    unsigned parsed : 1;
    unsigned decrypted : 1;
    unsigned validated : 1;
    unsigned retried : 1;
    unsigned first : 1;
    unsigned rebound : 1;
    unsigned path_challenged : 1;
} s3_quic_header_t;

s3_int_t s3_quic_parse_packet(s3_quic_header_t *pkt);

size_t s3_quic_create_version_negotiation(s3_quic_header_t *pkt, u_char *out);

size_t s3_quic_payload_size(s3_quic_header_t *pkt, size_t pkt_len);

size_t s3_quic_create_header(s3_quic_header_t *pkt, u_char *out, u_char **pnp);

size_t s3_quic_create_retry_itag(s3_quic_header_t *pkt, u_char *out, u_char **start);

ssize_t s3_quic_parse_frame(s3_quic_header_t *pkt, u_char *start, u_char *end,
                            s3_quic_frame_t *frame);
ssize_t s3_quic_create_frame(u_char *p, s3_quic_frame_t *f);

ssize_t s3_quic_parse_ack_range(s3_log_t *log, u_char *start, u_char *end, uint64_t *gap,
                                uint64_t *range);
size_t  s3_quic_create_ack_range(u_char *p, uint64_t gap, uint64_t range);

s3_int_t s3_quic_init_transport_params(s3_quic_tp_t *tp, s3_quic_conf_t *qcf);
s3_int_t s3_quic_parse_transport_params(u_char *p, u_char *end, s3_quic_tp_t *tp, s3_log_t *log);
ssize_t  s3_quic_create_transport_params(u_char *p, u_char *end, s3_quic_tp_t *tp, size_t *clen);

void s3_quic_dcid_encode_key(u_char *dcid, uint64_t key);

#endif /* _S3_QUIC_TRANSPORT_H_INCLUDED_ */
