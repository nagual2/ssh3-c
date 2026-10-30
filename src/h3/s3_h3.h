/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_H3_H_INCLUDED_
#define _S3_H3_H_INCLUDED_

#include <s3_core.h>
#include <s3_connection.h>

#include <s3_h3_parse.h>
#include <s3_h3_encode.h>
#include <s3_h3_table.h>

#define S3_H3_VARLEN_INT_LEN 8
#define S3_H3_PREFIX_INT_LEN 11

#define S3_H3_STREAM_CONTROL 0x00
#define S3_H3_STREAM_PUSH    0x01
#define S3_H3_STREAM_ENCODER 0x02
#define S3_H3_STREAM_DECODER 0x03

#define S3_H3_FRAME_DATA         0x00
#define S3_H3_FRAME_HEADERS      0x01
#define S3_H3_FRAME_CANCEL_PUSH  0x03
#define S3_H3_FRAME_SETTINGS     0x04
#define S3_H3_FRAME_PUSH_PROMISE 0x05
#define S3_H3_FRAME_GOAWAY       0x07
#define S3_H3_FRAME_MAX_PUSH_ID  0x0d

#define S3_H3_PARAM_MAX_TABLE_CAPACITY     0x01
#define S3_H3_PARAM_MAX_FIELD_SECTION_SIZE 0x06
#define S3_H3_PARAM_BLOCKED_STREAMS        0x07

#define S3_H3_MAX_TABLE_CAPACITY 4096

#define S3_H3_STREAM_CLIENT_CONTROL 0
#define S3_H3_STREAM_SERVER_CONTROL 1
#define S3_H3_STREAM_CLIENT_ENCODER 2
#define S3_H3_STREAM_SERVER_ENCODER 3
#define S3_H3_STREAM_CLIENT_DECODER 4
#define S3_H3_STREAM_SERVER_DECODER 5
#define S3_H3_MAX_KNOWN_STREAM      6
#define S3_H3_MAX_UNI_STREAMS       3

/* HTTP/3 errors */
#define S3_H3_ERR_NO_ERROR               0x100
#define S3_H3_ERR_GENERAL_PROTOCOL_ERROR 0x101
#define S3_H3_ERR_INTERNAL_ERROR         0x102
#define S3_H3_ERR_STREAM_CREATION_ERROR  0x103
#define S3_H3_ERR_CLOSED_CRITICAL_STREAM 0x104
#define S3_H3_ERR_FRAME_UNEXPECTED       0x105
#define S3_H3_ERR_FRAME_ERROR            0x106
#define S3_H3_ERR_EXCESSIVE_LOAD         0x107
#define S3_H3_ERR_ID_ERROR               0x108
#define S3_H3_ERR_SETTINGS_ERROR         0x109
#define S3_H3_ERR_MISSING_SETTINGS       0x10a
#define S3_H3_ERR_REQUEST_REJECTED       0x10b
#define S3_H3_ERR_REQUEST_CANCELLED      0x10c
#define S3_H3_ERR_REQUEST_INCOMPLETE     0x10d
#define S3_H3_ERR_CONNECT_ERROR          0x10f
#define S3_H3_ERR_VERSION_FALLBACK       0x110

/* QPACK errors */
#define S3_H3_ERR_DECOMPRESSION_FAILED 0x200
#define S3_H3_ERR_ENCODER_STREAM_ERROR 0x201
#define S3_H3_ERR_DECODER_STREAM_ERROR 0x202

/*
 * the h3 session hangs on the QUIC parent connection's data pointer;
 * the P3 integration wave wires the allocation and the uni streams
 */
#define s3_h3_get_session(c) ((s3_h3_session_t *)(c)->data)

typedef struct s3_h3_session_s s3_h3_session_t;

struct s3_h3_session_s {
    s3_h3_dynamic_table_t table;

    /*
     * ssh3-c (F2): the encoder side of QPACK - the table we insert
     * into and reference the acked entries from (the struct above is
     * the decoder side, what the peer inserts into).  the references
     * ride only the entries the peer acknowledged through the Insert
     * Count Increment, so no blocked streams and no BLOCKED_STREAMS
     * accounting; the peer capacity 0 (our own SETTINGS announce
     * zero) keeps the side dormant.  the table never evicts: the
     * relative indexes of the live entries stay stable for the
     * session life, the inserts stop at the capacity instead
     */
    s3_h3_dynamic_table_t encoder;
    uint64_t              peer_capacity;

    /*
     * ssh3-c: the event context of the parent connection; nginx posts
     * to the global ngx_posted_events queue, the kernel uses
     * per-context queues, so the table layer needs the ctx reference
     */
    s3_event_ctx_t *ctx;

    s3_queue_t blocked;
    s3_uint_t  nblocked;

    uint64_t next_request_id;

    off_t total_bytes;
    off_t payload_bytes;

    unsigned goaway : 1;
    unsigned created_streams : S3_H3_MAX_KNOWN_STREAM;

    s3_connection_t *known_streams[S3_H3_MAX_KNOWN_STREAM];
};

#endif /* _S3_H3_H_INCLUDED_ */
