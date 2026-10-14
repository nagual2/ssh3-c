/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <s3_quic.h>
#include <s3_quic_transport.h>
#include <s3_quic_protection.h>

#define S3_QUIC_LONG_DCID_LEN_OFFSET 5
#define S3_QUIC_LONG_DCID_OFFSET     6
#define S3_QUIC_SHORT_DCID_OFFSET    1

#define S3_QUIC_STREAM_FRAME_FIN 0x01
#define S3_QUIC_STREAM_FRAME_LEN 0x02
#define S3_QUIC_STREAM_FRAME_OFF 0x04

/*
 * byte-wise access is used unconditionally: packet buffers are not
 * guaranteed to be aligned
 */
#define s3_quic_parse_uint16(p) ((p)[0] << 8 | (p)[1])

#define s3_quic_parse_uint32(p) ((uint32_t)(p)[0] << 24 | (p)[1] << 16 | (p)[2] << 8 | (p)[3])

#define s3_quic_write_uint16(p, s)                                                                 \
    ((p)[0] = (u_char)((s) >> 8), (p)[1] = (u_char)(s), (p) + sizeof(uint16_t))

#define s3_quic_write_uint32(p, s)                                                                 \
    ((p)[0] = (u_char)((s) >> 24), (p)[1] = (u_char)((s) >> 16), (p)[2] = (u_char)((s) >> 8),      \
     (p)[3] = (u_char)(s), (p) + sizeof(uint32_t))

#define s3_quic_write_uint64(p, s)                                                                 \
    ((p)[0] = (u_char)((s) >> 56), (p)[1] = (u_char)((s) >> 48), (p)[2] = (u_char)((s) >> 40),     \
     (p)[3] = (u_char)((s) >> 32), (p)[4] = (u_char)((s) >> 24), (p)[5] = (u_char)((s) >> 16),     \
     (p)[6] = (u_char)((s) >> 8), (p)[7] = (u_char)(s), (p) + sizeof(uint64_t))

#define s3_quic_write_uint24(p, s)                                                                 \
    ((p)[0] = (u_char)((s) >> 16), (p)[1] = (u_char)((s) >> 8), (p)[2] = (u_char)(s), (p) + 3)

#define s3_quic_build_int_set(p, value, len, bits)                                                 \
    (*(p)++ = (((value) >> ((len) * 8)) & 0xff) | ((bits) << 6))

static u_char   *s3_quic_parse_int(u_char *pos, u_char *end, uint64_t *out);
static s3_uint_t s3_quic_varint_len(uint64_t value);
static void      s3_quic_build_int(u_char **pos, uint64_t value);

static u_char *s3_quic_read_uint8(u_char *pos, u_char *end, uint8_t *value);
static u_char *s3_quic_read_uint32(u_char *pos, u_char *end, uint32_t *value);
static u_char *s3_quic_read_bytes(u_char *pos, u_char *end, size_t len, u_char **out);
static u_char *s3_quic_copy_bytes(u_char *pos, u_char *end, size_t len, u_char *dst);

static s3_int_t s3_quic_parse_short_header(s3_quic_header_t *pkt, size_t dcid_len);
static s3_int_t s3_quic_parse_long_header(s3_quic_header_t *pkt);
static s3_int_t s3_quic_supported_version(uint32_t version);
static s3_int_t s3_quic_parse_long_header_v1(s3_quic_header_t *pkt);

static size_t s3_quic_create_long_header(s3_quic_header_t *pkt, u_char *out, u_char **pnp);
static size_t s3_quic_create_short_header(s3_quic_header_t *pkt, u_char *out, u_char **pnp);

static s3_int_t s3_quic_frame_allowed(s3_quic_header_t *pkt, s3_uint_t frame_type);
static size_t   s3_quic_create_ping(u_char *p);
static size_t   s3_quic_create_ack(u_char *p, s3_quic_ack_frame_t *ack, s3_chain_t *ranges);
static size_t   s3_quic_create_reset_stream(u_char *p, s3_quic_reset_stream_frame_t *rs);
static size_t   s3_quic_create_stop_sending(u_char *p, s3_quic_stop_sending_frame_t *ss);
static size_t   s3_quic_create_crypto(u_char *p, s3_quic_crypto_frame_t *crypto, s3_chain_t *data);
static size_t   s3_quic_create_hs_done(u_char *p);
static size_t   s3_quic_create_new_token(u_char *p, s3_quic_new_token_frame_t *token,
                                         s3_chain_t *data);
static size_t   s3_quic_create_stream(u_char *p, s3_quic_stream_frame_t *sf, s3_chain_t *data);
static size_t   s3_quic_create_max_streams(u_char *p, s3_quic_max_streams_frame_t *ms);
static size_t   s3_quic_create_max_stream_data(u_char *p, s3_quic_max_stream_data_frame_t *ms);
static size_t   s3_quic_create_max_data(u_char *p, s3_quic_max_data_frame_t *md);
static size_t   s3_quic_create_datagram(u_char *p, s3_quic_frame_t *f);
static size_t   s3_quic_create_path_challenge(u_char *p, s3_quic_path_challenge_frame_t *pc);

static s3_uint_t s3_quic_tp_sr_token_set(const s3_quic_tp_t *tp);
static size_t    s3_quic_create_path_response(u_char *p, s3_quic_path_challenge_frame_t *pc);
static size_t    s3_quic_create_new_connection_id(u_char *p, s3_quic_new_conn_id_frame_t *rcid);
static size_t    s3_quic_create_retire_connection_id(u_char *p, s3_quic_retire_cid_frame_t *rcid);
static size_t    s3_quic_create_close(u_char *p, s3_quic_frame_t *f);

static s3_int_t s3_quic_parse_transport_param(u_char *p, u_char *end, uint16_t id,
                                              s3_quic_tp_t *dst);

uint32_t s3_quic_versions[] = {
    /* QUICv1 */
    0x00000001,
};

#define S3_QUIC_NVERSIONS (sizeof(s3_quic_versions) / sizeof(s3_quic_versions[0]))

static s3_inline u_char *
s3_quic_parse_int(u_char *pos, u_char *end, uint64_t *out)
{
    u_char   *p;
    uint64_t  value;
    s3_uint_t len;

    if (pos >= end) {
        return NULL;
    }

    p = pos;
    len = 1 << (*p >> 6);

    value = *p++ & 0x3f;

    if ((size_t)(end - p) < (len - 1)) {
        return NULL;
    }

    while (--len) {
        value = (value << 8) + *p++;
    }

    *out = value;

    return p;
}

static s3_inline u_char *
s3_quic_read_uint8(u_char *pos, u_char *end, uint8_t *value)
{
    if ((size_t)(end - pos) < 1) {
        return NULL;
    }

    *value = *pos;

    return pos + 1;
}

static s3_inline u_char *
s3_quic_read_uint32(u_char *pos, u_char *end, uint32_t *value)
{
    if ((size_t)(end - pos) < sizeof(uint32_t)) {
        return NULL;
    }

    *value = s3_quic_parse_uint32(pos);

    return pos + sizeof(uint32_t);
}

static s3_inline u_char *
s3_quic_read_bytes(u_char *pos, u_char *end, size_t len, u_char **out)
{
    if ((size_t)(end - pos) < len) {
        return NULL;
    }

    *out = pos;

    return pos + len;
}

static u_char *
s3_quic_copy_bytes(u_char *pos, u_char *end, size_t len, u_char *dst)
{
    if ((size_t)(end - pos) < len) {
        return NULL;
    }

    s3_memcpy(dst, pos, len);

    return pos + len;
}

static s3_inline s3_uint_t
s3_quic_varint_len(uint64_t value)
{
    if (value < (1 << 6)) {
        return 1;
    }

    if (value < (1 << 14)) {
        return 2;
    }

    if (value < (1 << 30)) {
        return 4;
    }

    return 8;
}

static s3_inline void
s3_quic_build_int(u_char **pos, uint64_t value)
{
    u_char *p;

    p = *pos;

    if (value < (1 << 6)) {
        s3_quic_build_int_set(p, value, 0, 0);

    } else if (value < (1 << 14)) {
        s3_quic_build_int_set(p, value, 1, 1);
        s3_quic_build_int_set(p, value, 0, 0);

    } else if (value < (1 << 30)) {
        s3_quic_build_int_set(p, value, 3, 2);
        s3_quic_build_int_set(p, value, 2, 0);
        s3_quic_build_int_set(p, value, 1, 0);
        s3_quic_build_int_set(p, value, 0, 0);

    } else {
        s3_quic_build_int_set(p, value, 7, 3);
        s3_quic_build_int_set(p, value, 6, 0);
        s3_quic_build_int_set(p, value, 5, 0);
        s3_quic_build_int_set(p, value, 4, 0);
        s3_quic_build_int_set(p, value, 3, 0);
        s3_quic_build_int_set(p, value, 2, 0);
        s3_quic_build_int_set(p, value, 1, 0);
        s3_quic_build_int_set(p, value, 0, 0);
    }

    *pos = p;
}

s3_int_t
s3_quic_parse_packet(s3_quic_header_t *pkt)
{
    if (!s3_quic_long_pkt(pkt->flags)) {
        pkt->level = S3_QUIC_ENCRYPTION_APPLICATION;

        if (s3_quic_parse_short_header(pkt, S3_QUIC_SERVER_CID_LEN) != S3_OK) {
            return S3_ERROR;
        }

        return S3_OK;
    }

    if (s3_quic_parse_long_header(pkt) != S3_OK) {
        return S3_ERROR;
    }

    if (pkt->version == 0) {
        /* version negotiation */
        return S3_ERROR;
    }

    if (!s3_quic_supported_version(pkt->version)) {
        return S3_DECLINED;
    }

    if (s3_quic_parse_long_header_v1(pkt) != S3_OK) {
        return S3_ERROR;
    }

    return S3_OK;
}

static s3_int_t
s3_quic_parse_short_header(s3_quic_header_t *pkt, size_t dcid_len)
{
    u_char *p, *end;

    p = pkt->raw->pos;
    end = pkt->data + pkt->len;

    s3_log_debug1(S3_LOG_DEBUG_EVENT, pkt->log, 0, "quic packet rx short flags:%xd", pkt->flags);

    if (!(pkt->flags & S3_QUIC_PKT_FIXED_BIT)) {
        s3_log_error(S3_LOG_INFO, pkt->log, 0, "quic fixed bit is not set");
        return S3_ERROR;
    }

    pkt->dcid.len = dcid_len;

    p = s3_quic_read_bytes(p, end, dcid_len, &pkt->dcid.data);
    if (p == NULL) {
        s3_log_error(S3_LOG_INFO, pkt->log, 0, "quic packet is too small to read dcid");
        return S3_ERROR;
    }

    pkt->raw->pos = p;

    return S3_OK;
}

static s3_int_t
s3_quic_parse_long_header(s3_quic_header_t *pkt)
{
    u_char *p, *end;
    uint8_t idlen;

    p = pkt->raw->pos;
    end = pkt->data + pkt->len;

    p = s3_quic_read_uint32(p, end, &pkt->version);
    if (p == NULL) {
        s3_log_error(S3_LOG_INFO, pkt->log, 0, "quic packet is too small to read version");
        return S3_ERROR;
    }

    s3_log_debug2(S3_LOG_DEBUG_EVENT, pkt->log, 0, "quic packet rx long flags:%xd version:%xD",
                  pkt->flags, pkt->version);

    if (!(pkt->flags & S3_QUIC_PKT_FIXED_BIT)) {
        s3_log_error(S3_LOG_INFO, pkt->log, 0, "quic fixed bit is not set");
        return S3_ERROR;
    }

    p = s3_quic_read_uint8(p, end, &idlen);
    if (p == NULL) {
        s3_log_error(S3_LOG_INFO, pkt->log, 0, "quic packet is too small to read dcid len");
        return S3_ERROR;
    }

    if (idlen > S3_QUIC_CID_LEN_MAX) {
        s3_log_error(S3_LOG_INFO, pkt->log, 0, "quic packet dcid is too long");
        return S3_ERROR;
    }

    pkt->dcid.len = idlen;

    p = s3_quic_read_bytes(p, end, idlen, &pkt->dcid.data);
    if (p == NULL) {
        s3_log_error(S3_LOG_INFO, pkt->log, 0, "quic packet is too small to read dcid");
        return S3_ERROR;
    }

    p = s3_quic_read_uint8(p, end, &idlen);
    if (p == NULL) {
        s3_log_error(S3_LOG_INFO, pkt->log, 0, "quic packet is too small to read scid len");
        return S3_ERROR;
    }

    if (idlen > S3_QUIC_CID_LEN_MAX) {
        s3_log_error(S3_LOG_INFO, pkt->log, 0, "quic packet scid is too long");
        return S3_ERROR;
    }

    pkt->scid.len = idlen;

    p = s3_quic_read_bytes(p, end, idlen, &pkt->scid.data);
    if (p == NULL) {
        s3_log_error(S3_LOG_INFO, pkt->log, 0, "quic packet is too small to read scid");
        return S3_ERROR;
    }

    pkt->raw->pos = p;

    return S3_OK;
}

static s3_int_t
s3_quic_supported_version(uint32_t version)
{
    s3_uint_t i;

    for (i = 0; i < S3_QUIC_NVERSIONS; i++) {
        if (s3_quic_versions[i] == version) {
            return 1;
        }
    }

    return 0;
}

static s3_int_t
s3_quic_parse_long_header_v1(s3_quic_header_t *pkt)
{
    u_char  *p, *end;
    uint64_t varint;

    p = pkt->raw->pos;
    end = pkt->raw->last;

    if (s3_quic_pkt_in(pkt->flags)) {

        /*
         * RFC 9000, 14.1.  Initial Packet:
         *
         * A server MUST discard an Initial packet that is carried in a
         * UDP datagram with a payload that is smaller than 1200 bytes.
         * The same is not required of a client: only the amplification
         * limited side enforces the size, and a peer is free to answer
         * with a bare Initial ACK well below that limit
         */

        if (!pkt->client && pkt->len < S3_QUIC_MIN_INITIAL_SIZE) {
            s3_log_error(S3_LOG_INFO, pkt->log, 0,
                         "quic UDP datagram is too small for initial packet");
            return S3_DECLINED;
        }

        p = s3_quic_parse_int(p, end, &varint);
        if (p == NULL) {
            s3_log_error(S3_LOG_INFO, pkt->log, 0, "quic failed to parse token length");
            return S3_ERROR;
        }

        pkt->token.len = varint;

        p = s3_quic_read_bytes(p, end, pkt->token.len, &pkt->token.data);
        if (p == NULL) {
            s3_log_error(S3_LOG_INFO, pkt->log, 0, "quic packet too small to read token data");
            return S3_ERROR;
        }

        pkt->level = S3_QUIC_ENCRYPTION_INITIAL;

    } else if (s3_quic_pkt_zrtt(pkt->flags)) {
        pkt->level = S3_QUIC_ENCRYPTION_EARLY_DATA;

    } else if (s3_quic_pkt_hs(pkt->flags)) {
        pkt->level = S3_QUIC_ENCRYPTION_HANDSHAKE;

    } else {
        s3_log_error(S3_LOG_INFO, pkt->log, 0, "quic bad packet type");
        return S3_DECLINED;
    }

    p = s3_quic_parse_int(p, end, &varint);
    if (p == NULL) {
        s3_log_error(S3_LOG_INFO, pkt->log, 0, "quic bad packet length");
        return S3_ERROR;
    }

    s3_log_debug2(S3_LOG_DEBUG_EVENT, pkt->log, 0, "quic packet rx %s len:%uL",
                  s3_quic_level_name(pkt->level), varint);

    if (varint > (uint64_t)((pkt->data + pkt->len) - p)) {
        s3_log_error(S3_LOG_INFO, pkt->log, 0, "quic truncated %s packet",
                     s3_quic_level_name(pkt->level));
        return S3_ERROR;
    }

    pkt->raw->pos = p;
    pkt->len = p + varint - pkt->data;

    return S3_OK;
}

s3_int_t
s3_quic_get_packet_dcid(s3_log_t *log, u_char *data, size_t n, s3_str_t *dcid)
{
    size_t len, offset;

    if (n == 0) {
        goto failed;
    }

    if (s3_quic_long_pkt(*data)) {
        if (n < S3_QUIC_LONG_DCID_LEN_OFFSET + 1) {
            goto failed;
        }

        len = data[S3_QUIC_LONG_DCID_LEN_OFFSET];
        offset = S3_QUIC_LONG_DCID_OFFSET;

    } else {
        len = S3_QUIC_SERVER_CID_LEN;
        offset = S3_QUIC_SHORT_DCID_OFFSET;
    }

    if (n < len + offset) {
        goto failed;
    }

    dcid->len = len;
    dcid->data = &data[offset];

    return S3_OK;

failed:

    s3_log_debug0(S3_LOG_DEBUG_EVENT, log, 0, "quic malformed packet");

    return S3_ERROR;
}

size_t
s3_quic_create_version_negotiation(s3_quic_header_t *pkt, u_char *out)
{
    u_char   *p, *start;
    s3_uint_t i;

    p = start = out;

    *p++ = pkt->flags;

    /*
     * The Version field of a Version Negotiation packet
     * MUST be set to 0x00000000
     */
    p = s3_quic_write_uint32(p, 0);

    *p++ = pkt->dcid.len;
    p = s3_cpymem(p, pkt->dcid.data, pkt->dcid.len);

    *p++ = pkt->scid.len;
    p = s3_cpymem(p, pkt->scid.data, pkt->scid.len);

    for (i = 0; i < S3_QUIC_NVERSIONS; i++) {
        p = s3_quic_write_uint32(p, s3_quic_versions[i]);
    }

    return p - start;
}

/* returns the amount of payload quic packet of "pkt_len" size may fit or 0 */
size_t
s3_quic_payload_size(s3_quic_header_t *pkt, size_t pkt_len)
{
    size_t len;

    if (s3_quic_short_pkt(pkt->flags)) {

        len = 1 + pkt->dcid.len + pkt->num_len + S3_QUIC_TAG_LEN;
        if (len > pkt_len) {
            return 0;
        }

        return pkt_len - len;
    }

    /* flags, version, dcid and scid with lengths and zero-length token */
    len =
        5 + 2 + pkt->dcid.len + pkt->scid.len + (pkt->level == S3_QUIC_ENCRYPTION_INITIAL ? 1 : 0);

    if (len > pkt_len) {
        return 0;
    }

    /* (pkt_len - len) is 'remainder' packet length (see RFC 9000, 17.2) */
    len += s3_quic_varint_len(pkt_len - len) + pkt->num_len + S3_QUIC_TAG_LEN;

    if (len > pkt_len) {
        return 0;
    }

    return pkt_len - len;
}

size_t
s3_quic_create_header(s3_quic_header_t *pkt, u_char *out, u_char **pnp)
{
    return s3_quic_short_pkt(pkt->flags) ? s3_quic_create_short_header(pkt, out, pnp)
                                         : s3_quic_create_long_header(pkt, out, pnp);
}

static size_t
s3_quic_create_long_header(s3_quic_header_t *pkt, u_char *out, u_char **pnp)
{
    size_t  rem_len;
    u_char *p, *start;

    rem_len = pkt->num_len + pkt->payload.len + S3_QUIC_TAG_LEN;

    if (out == NULL) {
        return 5 + 2 + pkt->dcid.len + pkt->scid.len + s3_quic_varint_len(rem_len) + pkt->num_len +
               (pkt->level == S3_QUIC_ENCRYPTION_INITIAL ? 1 : 0);
    }

    p = start = out;

    *p++ = pkt->flags;

    p = s3_quic_write_uint32(p, pkt->version);

    *p++ = pkt->dcid.len;
    p = s3_cpymem(p, pkt->dcid.data, pkt->dcid.len);

    *p++ = pkt->scid.len;
    p = s3_cpymem(p, pkt->scid.data, pkt->scid.len);

    if (pkt->level == S3_QUIC_ENCRYPTION_INITIAL) {
        s3_quic_build_int(&p, 0);
    }

    s3_quic_build_int(&p, rem_len);

    *pnp = p;

    switch (pkt->num_len) {
    case 1:
        *p++ = pkt->trunc;
        break;
    case 2:
        p = s3_quic_write_uint16(p, pkt->trunc);
        break;
    case 3:
        p = s3_quic_write_uint24(p, pkt->trunc);
        break;
    case 4:
        p = s3_quic_write_uint32(p, pkt->trunc);
        break;
    default:
        break;
    }

    return p - start;
}

static size_t
s3_quic_create_short_header(s3_quic_header_t *pkt, u_char *out, u_char **pnp)
{
    u_char *p, *start;

    if (out == NULL) {
        return 1 + pkt->dcid.len + pkt->num_len;
    }

    p = start = out;

    *p++ = pkt->flags;

    p = s3_cpymem(p, pkt->dcid.data, pkt->dcid.len);

    *pnp = p;

    switch (pkt->num_len) {
    case 1:
        *p++ = pkt->trunc;
        break;
    case 2:
        p = s3_quic_write_uint16(p, pkt->trunc);
        break;
    case 3:
        p = s3_quic_write_uint24(p, pkt->trunc);
        break;
    case 4:
        p = s3_quic_write_uint32(p, pkt->trunc);
        break;
    default:
        break;
    }

    return p - start;
}

size_t
s3_quic_create_retry_itag(s3_quic_header_t *pkt, u_char *out, u_char **start)
{
    u_char *p;

    p = out;

    *p++ = pkt->odcid.len;
    p = s3_cpymem(p, pkt->odcid.data, pkt->odcid.len);

    *start = p;

    *p++ = 0xff;

    p = s3_quic_write_uint32(p, pkt->version);

    *p++ = pkt->dcid.len;
    p = s3_cpymem(p, pkt->dcid.data, pkt->dcid.len);

    *p++ = pkt->scid.len;
    p = s3_cpymem(p, pkt->scid.data, pkt->scid.len);

    p = s3_cpymem(p, pkt->token.data, pkt->token.len);

    return p - out;
}

ssize_t
s3_quic_parse_frame(s3_quic_header_t *pkt, u_char *start, u_char *end, s3_quic_frame_t *f)
{
    u_char   *p;
    uint64_t  varint;
    s3_buf_t *b;
    s3_uint_t i;

    b = f->data->buf;

    p = start;

    p = s3_quic_parse_int(p, end, &varint);
    if (p == NULL) {
        pkt->error = S3_QUIC_ERR_FRAME_ENCODING_ERROR;
        s3_log_error(S3_LOG_INFO, pkt->log, 0, "quic failed to obtain quic frame type");
        return S3_ERROR;
    }

    if (varint > S3_QUIC_FT_LAST) {
        pkt->error = S3_QUIC_ERR_FRAME_ENCODING_ERROR;
        s3_log_error(S3_LOG_INFO, pkt->log, 0, "quic unknown frame type 0x%xL", varint);
        return S3_ERROR;
    }

    f->type = varint;

    if (s3_quic_frame_allowed(pkt, f->type) != S3_OK) {
        pkt->error = S3_QUIC_ERR_PROTOCOL_VIOLATION;
        return S3_ERROR;
    }

    switch (f->type) {

    case S3_QUIC_FT_CRYPTO:

        p = s3_quic_parse_int(p, end, &f->u.crypto.offset);
        if (p == NULL) {
            goto error;
        }

        p = s3_quic_parse_int(p, end, &f->u.crypto.length);
        if (p == NULL) {
            goto error;
        }

        p = s3_quic_read_bytes(p, end, f->u.crypto.length, &b->pos);
        if (p == NULL) {
            goto error;
        }

        b->last = p;

        break;

    case S3_QUIC_FT_PADDING:

        while (p < end && *p == S3_QUIC_FT_PADDING) {
            p++;
        }

        break;

    case S3_QUIC_FT_ACK:
    case S3_QUIC_FT_ACK_ECN:

        p = s3_quic_parse_int(p, end, &f->u.ack.largest);
        if (p == NULL) {
            goto error;
        }

        p = s3_quic_parse_int(p, end, &f->u.ack.delay);
        if (p == NULL) {
            goto error;
        }

        p = s3_quic_parse_int(p, end, &f->u.ack.range_count);
        if (p == NULL) {
            goto error;
        }

        p = s3_quic_parse_int(p, end, &f->u.ack.first_range);
        if (p == NULL) {
            goto error;
        }

        b->pos = p;

        /* process all ranges to get bounds, values are ignored */
        for (i = 0; i < f->u.ack.range_count; i++) {

            p = s3_quic_parse_int(p, end, &varint);
            if (p == NULL) {
                goto error;
            }

            p = s3_quic_parse_int(p, end, &varint);
            if (p == NULL) {
                goto error;
            }
        }

        b->last = p;

        f->u.ack.ranges_length = b->last - b->pos;

        if (f->type == S3_QUIC_FT_ACK_ECN) {

            p = s3_quic_parse_int(p, end, &f->u.ack.ect0);
            if (p == NULL) {
                goto error;
            }

            p = s3_quic_parse_int(p, end, &f->u.ack.ect1);
            if (p == NULL) {
                goto error;
            }

            p = s3_quic_parse_int(p, end, &f->u.ack.ce);
            if (p == NULL) {
                goto error;
            }

            s3_log_debug3(S3_LOG_DEBUG_EVENT, pkt->log, 0,
                          "quic ACK ECN counters ect0:%uL ect1:%uL ce:%uL", f->u.ack.ect0,
                          f->u.ack.ect1, f->u.ack.ce);
        }

        break;

    case S3_QUIC_FT_PING:
        break;

    case S3_QUIC_FT_NEW_CONNECTION_ID:

        p = s3_quic_parse_int(p, end, &f->u.ncid.seqnum);
        if (p == NULL) {
            goto error;
        }

        p = s3_quic_parse_int(p, end, &f->u.ncid.retire);
        if (p == NULL) {
            goto error;
        }

        if (f->u.ncid.retire > f->u.ncid.seqnum) {
            goto error;
        }

        p = s3_quic_read_uint8(p, end, &f->u.ncid.len);
        if (p == NULL) {
            goto error;
        }

        if (f->u.ncid.len < 1 || f->u.ncid.len > S3_QUIC_CID_LEN_MAX) {
            goto error;
        }

        p = s3_quic_copy_bytes(p, end, f->u.ncid.len, f->u.ncid.cid);
        if (p == NULL) {
            goto error;
        }

        p = s3_quic_copy_bytes(p, end, S3_QUIC_SR_TOKEN_LEN, f->u.ncid.srt);
        if (p == NULL) {
            goto error;
        }

        break;

    case S3_QUIC_FT_RETIRE_CONNECTION_ID:

        p = s3_quic_parse_int(p, end, &f->u.retire_cid.sequence_number);
        if (p == NULL) {
            goto error;
        }

        break;

    case S3_QUIC_FT_CONNECTION_CLOSE:
    case S3_QUIC_FT_CONNECTION_CLOSE_APP:

        p = s3_quic_parse_int(p, end, &f->u.close.error_code);
        if (p == NULL) {
            goto error;
        }

        if (f->type == S3_QUIC_FT_CONNECTION_CLOSE) {
            p = s3_quic_parse_int(p, end, &f->u.close.frame_type);
            if (p == NULL) {
                goto error;
            }
        }

        p = s3_quic_parse_int(p, end, &varint);
        if (p == NULL) {
            goto error;
        }

        f->u.close.reason.len = varint;

        p = s3_quic_read_bytes(p, end, f->u.close.reason.len, &f->u.close.reason.data);
        if (p == NULL) {
            goto error;
        }

        break;

    case S3_QUIC_FT_STREAM:
    case S3_QUIC_FT_STREAM1:
    case S3_QUIC_FT_STREAM2:
    case S3_QUIC_FT_STREAM3:
    case S3_QUIC_FT_STREAM4:
    case S3_QUIC_FT_STREAM5:
    case S3_QUIC_FT_STREAM6:
    case S3_QUIC_FT_STREAM7:

        f->u.stream.fin = (f->type & S3_QUIC_STREAM_FRAME_FIN) ? 1 : 0;

        p = s3_quic_parse_int(p, end, &f->u.stream.stream_id);
        if (p == NULL) {
            goto error;
        }

        if (f->type & S3_QUIC_STREAM_FRAME_OFF) {
            f->u.stream.off = 1;

            p = s3_quic_parse_int(p, end, &f->u.stream.offset);
            if (p == NULL) {
                goto error;
            }

        } else {
            f->u.stream.off = 0;
            f->u.stream.offset = 0;
        }

        if (f->type & S3_QUIC_STREAM_FRAME_LEN) {
            f->u.stream.len = 1;

            p = s3_quic_parse_int(p, end, &f->u.stream.length);
            if (p == NULL) {
                goto error;
            }

        } else {
            f->u.stream.len = 0;
            f->u.stream.length = end - p; /* up to packet end */
        }

        p = s3_quic_read_bytes(p, end, f->u.stream.length, &b->pos);
        if (p == NULL) {
            goto error;
        }

        b->last = p;

        f->type = S3_QUIC_FT_STREAM;
        break;

    case S3_QUIC_FT_MAX_DATA:

        p = s3_quic_parse_int(p, end, &f->u.max_data.max_data);
        if (p == NULL) {
            goto error;
        }

        break;

    case S3_QUIC_FT_RESET_STREAM:

        p = s3_quic_parse_int(p, end, &f->u.reset_stream.id);
        if (p == NULL) {
            goto error;
        }

        p = s3_quic_parse_int(p, end, &f->u.reset_stream.error_code);
        if (p == NULL) {
            goto error;
        }

        p = s3_quic_parse_int(p, end, &f->u.reset_stream.final_size);
        if (p == NULL) {
            goto error;
        }

        break;

    case S3_QUIC_FT_STOP_SENDING:

        p = s3_quic_parse_int(p, end, &f->u.stop_sending.id);
        if (p == NULL) {
            goto error;
        }

        p = s3_quic_parse_int(p, end, &f->u.stop_sending.error_code);
        if (p == NULL) {
            goto error;
        }

        break;

    case S3_QUIC_FT_STREAMS_BLOCKED:
    case S3_QUIC_FT_STREAMS_BLOCKED2:

        p = s3_quic_parse_int(p, end, &f->u.streams_blocked.limit);
        if (p == NULL) {
            goto error;
        }

        if (f->u.streams_blocked.limit > 0x1000000000000000) {
            goto error;
        }

        f->u.streams_blocked.bidi = (f->type == S3_QUIC_FT_STREAMS_BLOCKED) ? 1 : 0;
        break;

    case S3_QUIC_FT_MAX_STREAMS:
    case S3_QUIC_FT_MAX_STREAMS2:

        p = s3_quic_parse_int(p, end, &f->u.max_streams.limit);
        if (p == NULL) {
            goto error;
        }

        if (f->u.max_streams.limit > 0x1000000000000000) {
            goto error;
        }

        f->u.max_streams.bidi = (f->type == S3_QUIC_FT_MAX_STREAMS) ? 1 : 0;

        break;

    case S3_QUIC_FT_MAX_STREAM_DATA:

        p = s3_quic_parse_int(p, end, &f->u.max_stream_data.id);
        if (p == NULL) {
            goto error;
        }

        p = s3_quic_parse_int(p, end, &f->u.max_stream_data.limit);
        if (p == NULL) {
            goto error;
        }

        break;

    case S3_QUIC_FT_DATA_BLOCKED:

        p = s3_quic_parse_int(p, end, &f->u.data_blocked.limit);
        if (p == NULL) {
            goto error;
        }

        break;

    case S3_QUIC_FT_STREAM_DATA_BLOCKED:

        p = s3_quic_parse_int(p, end, &f->u.stream_data_blocked.id);
        if (p == NULL) {
            goto error;
        }

        p = s3_quic_parse_int(p, end, &f->u.stream_data_blocked.limit);
        if (p == NULL) {
            goto error;
        }

        break;

    case S3_QUIC_FT_PATH_CHALLENGE:

        p = s3_quic_copy_bytes(p, end, 8, f->u.path_challenge.data);
        if (p == NULL) {
            goto error;
        }

        break;

    case S3_QUIC_FT_PATH_RESPONSE:

        p = s3_quic_copy_bytes(p, end, 8, f->u.path_response.data);
        if (p == NULL) {
            goto error;
        }

        break;

    case S3_QUIC_FT_DATAGRAM:

        /* the frame data extends to the end of the packet */
        f->u.datagram.length = end - p;

        b->pos = p;
        b->last = end;
        p = end;

        break;

    case S3_QUIC_FT_DATAGRAM_WITH_LENGTH:

        p = s3_quic_parse_int(p, end, &f->u.datagram.length);
        if (p == NULL) {
            goto error;
        }

        p = s3_quic_read_bytes(p, end, f->u.datagram.length, &b->pos);
        if (p == NULL) {
            goto error;
        }

        b->last = p;

        break;

    case S3_QUIC_FT_HANDSHAKE_DONE:

        /* the frame carries no payload; the reference never parses it */

        break;

    case S3_QUIC_FT_NEW_TOKEN: {

        /*
         * the token is accepted and dropped: it would be used for
         * address validation of a subsequent connection (D4)
         */

        u_char *token_data;

        p = s3_quic_parse_int(p, end, &varint);
        if (p == NULL) {
            pkt->error = S3_QUIC_ERR_FRAME_ENCODING_ERROR;
            s3_log_error(S3_LOG_INFO, pkt->log, 0, "quic failed to parse token length");
            return S3_ERROR;
        }

        p = s3_quic_read_bytes(p, end, varint, &token_data);
        if (p == NULL) {
            pkt->error = S3_QUIC_ERR_FRAME_ENCODING_ERROR;
            s3_log_error(S3_LOG_INFO, pkt->log, 0, "quic failed to parse token data");
            return S3_ERROR;
        }

        break;
    }

    default:
        s3_log_error(S3_LOG_INFO, pkt->log, 0, "quic unknown frame type 0x%xi", f->type);
        return S3_ERROR;
    }

    f->level = pkt->level;
    f->pnum = pkt->pn;

    return p - start;

error:

    pkt->error = S3_QUIC_ERR_FRAME_ENCODING_ERROR;

    s3_log_error(S3_LOG_INFO, pkt->log, 0, "quic failed to parse frame type:0x%xi", f->type);

    return S3_ERROR;
}

static s3_int_t
s3_quic_frame_allowed(s3_quic_header_t *pkt, s3_uint_t frame_type)
{
    uint8_t ptype;

    /*
     * RFC 9000, 12.4. Frames and Frame Types: Table 3
     *
     * Frame permissions per packet: 4 bits: IH01
     *
     * the table covers the whole frame type space up to
     * S3_QUIC_FT_LAST (0x31): the unassigned 0x1F..0x2F gap is
     * rejected (the varint bound above only filters types beyond
     * S3_QUIC_FT_LAST)
     */
    static uint8_t s3_quic_frame_masks[] = {
        /* PADDING  */ 0xF,
        /* PING */ 0xF,
        /* ACK */ 0xD,
        /* ACK_ECN */ 0xD,
        /* RESET_STREAM */ 0x3,
        /* STOP_SENDING */ 0x3,
        /* CRYPTO */ 0xD,
        /* NEW_TOKEN */ 0x0, /* only sent by server */
        /* STREAM */ 0x3,
        /* STREAM1 */ 0x3,
        /* STREAM2 */ 0x3,
        /* STREAM3 */ 0x3,
        /* STREAM4 */ 0x3,
        /* STREAM5 */ 0x3,
        /* STREAM6 */ 0x3,
        /* STREAM7 */ 0x3,
        /* MAX_DATA */ 0x3,
        /* MAX_STREAM_DATA */ 0x3,
        /* MAX_STREAMS */ 0x3,
        /* MAX_STREAMS2 */ 0x3,
        /* DATA_BLOCKED */ 0x3,
        /* STREAM_DATA_BLOCKED */ 0x3,
        /* STREAMS_BLOCKED */ 0x3,
        /* STREAMS_BLOCKED2 */ 0x3,
        /* NEW_CONNECTION_ID */ 0x3,
        /* RETIRE_CONNECTION_ID */ 0x3,
        /* PATH_CHALLENGE */ 0x3,
        /* PATH_RESPONSE */ 0x1,
        /* CONNECTION_CLOSE */ 0xF,
        /* CONNECTION_CLOSE2 */ 0x3,
        /* HANDSHAKE_DONE */ 0x0, /* only sent by server */
        /* 0x1F */ 0x0,
        /* 0x20 */ 0x0,
        /* 0x21 */ 0x0,
        /* 0x22 */ 0x0,
        /* 0x23 */ 0x0,
        /* 0x24 */ 0x0,
        /* 0x25 */ 0x0,
        /* 0x26 */ 0x0,
        /* 0x27 */ 0x0,
        /* 0x28 */ 0x0,
        /* 0x29 */ 0x0,
        /* 0x2A */ 0x0,
        /* 0x2B */ 0x0,
        /* 0x2C */ 0x0,
        /* 0x2D */ 0x0,
        /* 0x2E */ 0x0,
        /* 0x2F */ 0x0,
        /* DATAGRAM */ 0x1, /* RFC 9221: 1-RTT packets only */
        /* DATAGRAM_WITH_LENGTH */ 0x1,
    };

    if (s3_quic_long_pkt(pkt->flags)) {

        if (s3_quic_pkt_in(pkt->flags)) {
            ptype = 8; /* initial */

        } else if (s3_quic_pkt_hs(pkt->flags)) {
            ptype = 4; /* handshake */

        } else {
            ptype = 2; /* zero-rtt */
        }

    } else {
        ptype = 1; /* application data */
    }

    /*
     * RFC 9000, 19.20.  HANDSHAKE_DONE
     *
     * the table denies the frame to every packet type: it is defined
     * for the server only and the reference never has to check the
     * opposite direction, a client has to accept it exactly once in a
     * 1-RTT packet to confirm the handshake (RFC 9001, 4.1.2)
     */

    if (frame_type == S3_QUIC_FT_HANDSHAKE_DONE && pkt->client && ptype == 1) {
        return S3_OK;
    }

    /*
     * RFC 9000, 19.7.  NEW_TOKEN
     *
     * the same server-only situation: a client accepts NEW_TOKEN in a
     * 1-RTT packet; the token itself is not used until the client
     * needs address validation for a new connection
     */

    if (frame_type == S3_QUIC_FT_NEW_TOKEN && pkt->client && ptype == 1) {
        return S3_OK;
    }

    if (ptype & s3_quic_frame_masks[frame_type]) {
        return S3_OK;
    }

    s3_log_error(S3_LOG_INFO, pkt->log, 0,
                 "quic frame type 0x%xi is not "
                 "allowed in packet with flags 0x%xd",
                 frame_type, pkt->flags);

    return S3_DECLINED;
}

ssize_t
s3_quic_parse_ack_range(s3_log_t *log, u_char *start, u_char *end, uint64_t *gap, uint64_t *range)
{
    u_char *p;

    p = start;

    p = s3_quic_parse_int(p, end, gap);
    if (p == NULL) {
        s3_log_error(S3_LOG_INFO, log, 0, "quic failed to parse ack frame gap");
        return S3_ERROR;
    }

    p = s3_quic_parse_int(p, end, range);
    if (p == NULL) {
        s3_log_error(S3_LOG_INFO, log, 0, "quic failed to parse ack frame range");
        return S3_ERROR;
    }

    return p - start;
}

size_t
s3_quic_create_ack_range(u_char *p, uint64_t gap, uint64_t range)
{
    size_t  len;
    u_char *start;

    if (p == NULL) {
        len = s3_quic_varint_len(gap);
        len += s3_quic_varint_len(range);
        return len;
    }

    start = p;

    s3_quic_build_int(&p, gap);
    s3_quic_build_int(&p, range);

    return p - start;
}

ssize_t
s3_quic_create_frame(u_char *p, s3_quic_frame_t *f)
{
    /*
     *  RFC 9002, 2.  Conventions and Definitions
     *
     *  Ack-eliciting frames:  All frames other than ACK, PADDING, and
     *  CONNECTION_CLOSE are considered ack-eliciting.
     */
    f->need_ack = 1;

    switch (f->type) {
    case S3_QUIC_FT_PING:
        return s3_quic_create_ping(p);

    case S3_QUIC_FT_ACK:
        f->need_ack = 0;
        return s3_quic_create_ack(p, &f->u.ack, f->data);

    case S3_QUIC_FT_RESET_STREAM:
        return s3_quic_create_reset_stream(p, &f->u.reset_stream);

    case S3_QUIC_FT_STOP_SENDING:
        return s3_quic_create_stop_sending(p, &f->u.stop_sending);

    case S3_QUIC_FT_CRYPTO:
        return s3_quic_create_crypto(p, &f->u.crypto, f->data);

    case S3_QUIC_FT_HANDSHAKE_DONE:
        return s3_quic_create_hs_done(p);

    case S3_QUIC_FT_NEW_TOKEN:
        return s3_quic_create_new_token(p, &f->u.token, f->data);

    case S3_QUIC_FT_STREAM:
        return s3_quic_create_stream(p, &f->u.stream, f->data);

    case S3_QUIC_FT_CONNECTION_CLOSE:
    case S3_QUIC_FT_CONNECTION_CLOSE_APP:
        f->need_ack = 0;
        return s3_quic_create_close(p, f);

    case S3_QUIC_FT_MAX_STREAMS:
        return s3_quic_create_max_streams(p, &f->u.max_streams);

    case S3_QUIC_FT_MAX_STREAM_DATA:
        return s3_quic_create_max_stream_data(p, &f->u.max_stream_data);

    case S3_QUIC_FT_MAX_DATA:
        return s3_quic_create_max_data(p, &f->u.max_data);

    case S3_QUIC_FT_DATAGRAM:
    case S3_QUIC_FT_DATAGRAM_WITH_LENGTH:
        /* RFC 9221, 5.1: datagrams are never retransmitted */
        f->need_ack = 0;
        return s3_quic_create_datagram(p, f);

    case S3_QUIC_FT_PATH_CHALLENGE:
        return s3_quic_create_path_challenge(p, &f->u.path_challenge);

    case S3_QUIC_FT_PATH_RESPONSE:
        return s3_quic_create_path_response(p, &f->u.path_response);

    case S3_QUIC_FT_NEW_CONNECTION_ID:
        return s3_quic_create_new_connection_id(p, &f->u.ncid);

    case S3_QUIC_FT_RETIRE_CONNECTION_ID:
        return s3_quic_create_retire_connection_id(p, &f->u.retire_cid);

    default:
        /* BUG: unsupported frame type generated */
        return S3_ERROR;
    }
}

static size_t
s3_quic_create_ping(u_char *p)
{
    u_char *start;

    if (p == NULL) {
        return s3_quic_varint_len(S3_QUIC_FT_PING);
    }

    start = p;

    s3_quic_build_int(&p, S3_QUIC_FT_PING);

    return p - start;
}

static size_t
s3_quic_create_ack(u_char *p, s3_quic_ack_frame_t *ack, s3_chain_t *ranges)
{
    size_t    len;
    u_char   *start;
    s3_buf_t *b;

    if (p == NULL) {
        len = s3_quic_varint_len(S3_QUIC_FT_ACK);
        len += s3_quic_varint_len(ack->largest);
        len += s3_quic_varint_len(ack->delay);
        len += s3_quic_varint_len(ack->range_count);
        len += s3_quic_varint_len(ack->first_range);
        len += ack->ranges_length;

        return len;
    }

    start = p;

    s3_quic_build_int(&p, S3_QUIC_FT_ACK);
    s3_quic_build_int(&p, ack->largest);
    s3_quic_build_int(&p, ack->delay);
    s3_quic_build_int(&p, ack->range_count);
    s3_quic_build_int(&p, ack->first_range);

    while (ranges) {
        b = ranges->buf;
        p = s3_cpymem(p, b->pos, b->last - b->pos);
        ranges = ranges->next;
    }

    return p - start;
}

static size_t
s3_quic_create_reset_stream(u_char *p, s3_quic_reset_stream_frame_t *rs)
{
    size_t  len;
    u_char *start;

    if (p == NULL) {
        len = s3_quic_varint_len(S3_QUIC_FT_RESET_STREAM);
        len += s3_quic_varint_len(rs->id);
        len += s3_quic_varint_len(rs->error_code);
        len += s3_quic_varint_len(rs->final_size);
        return len;
    }

    start = p;

    s3_quic_build_int(&p, S3_QUIC_FT_RESET_STREAM);
    s3_quic_build_int(&p, rs->id);
    s3_quic_build_int(&p, rs->error_code);
    s3_quic_build_int(&p, rs->final_size);

    return p - start;
}

static size_t
s3_quic_create_stop_sending(u_char *p, s3_quic_stop_sending_frame_t *ss)
{
    size_t  len;
    u_char *start;

    if (p == NULL) {
        len = s3_quic_varint_len(S3_QUIC_FT_STOP_SENDING);
        len += s3_quic_varint_len(ss->id);
        len += s3_quic_varint_len(ss->error_code);
        return len;
    }

    start = p;

    s3_quic_build_int(&p, S3_QUIC_FT_STOP_SENDING);
    s3_quic_build_int(&p, ss->id);
    s3_quic_build_int(&p, ss->error_code);

    return p - start;
}

static size_t
s3_quic_create_crypto(u_char *p, s3_quic_crypto_frame_t *crypto, s3_chain_t *data)
{
    size_t    len;
    u_char   *start;
    s3_buf_t *b;

    if (p == NULL) {
        len = s3_quic_varint_len(S3_QUIC_FT_CRYPTO);
        len += s3_quic_varint_len(crypto->offset);
        len += s3_quic_varint_len(crypto->length);
        len += crypto->length;

        return len;
    }

    start = p;

    s3_quic_build_int(&p, S3_QUIC_FT_CRYPTO);
    s3_quic_build_int(&p, crypto->offset);
    s3_quic_build_int(&p, crypto->length);

    while (data) {
        b = data->buf;
        p = s3_cpymem(p, b->pos, b->last - b->pos);
        data = data->next;
    }

    return p - start;
}

static size_t
s3_quic_create_hs_done(u_char *p)
{
    u_char *start;

    if (p == NULL) {
        return s3_quic_varint_len(S3_QUIC_FT_HANDSHAKE_DONE);
    }

    start = p;

    s3_quic_build_int(&p, S3_QUIC_FT_HANDSHAKE_DONE);

    return p - start;
}

static size_t
s3_quic_create_new_token(u_char *p, s3_quic_new_token_frame_t *token, s3_chain_t *data)
{
    size_t    len;
    u_char   *start;
    s3_buf_t *b;

    if (p == NULL) {
        len = s3_quic_varint_len(S3_QUIC_FT_NEW_TOKEN);
        len += s3_quic_varint_len(token->length);
        len += token->length;

        return len;
    }

    start = p;

    s3_quic_build_int(&p, S3_QUIC_FT_NEW_TOKEN);
    s3_quic_build_int(&p, token->length);

    while (data) {
        b = data->buf;
        p = s3_cpymem(p, b->pos, b->last - b->pos);
        data = data->next;
    }

    return p - start;
}

static size_t
s3_quic_create_stream(u_char *p, s3_quic_stream_frame_t *sf, s3_chain_t *data)
{
    size_t    len;
    u_char   *start, type;
    s3_buf_t *b;

    type = S3_QUIC_FT_STREAM;

    if (sf->off) {
        type |= S3_QUIC_STREAM_FRAME_OFF;
    }

    if (sf->len) {
        type |= S3_QUIC_STREAM_FRAME_LEN;
    }

    if (sf->fin) {
        type |= S3_QUIC_STREAM_FRAME_FIN;
    }

    if (p == NULL) {
        len = s3_quic_varint_len(type);
        len += s3_quic_varint_len(sf->stream_id);

        if (sf->off) {
            len += s3_quic_varint_len(sf->offset);
        }

        if (sf->len) {
            len += s3_quic_varint_len(sf->length);
        }

        len += sf->length;

        return len;
    }

    start = p;

    s3_quic_build_int(&p, type);
    s3_quic_build_int(&p, sf->stream_id);

    if (sf->off) {
        s3_quic_build_int(&p, sf->offset);
    }

    if (sf->len) {
        s3_quic_build_int(&p, sf->length);
    }

    while (data) {
        b = data->buf;
        p = s3_cpymem(p, b->pos, b->last - b->pos);
        data = data->next;
    }

    return p - start;
}

static size_t
s3_quic_create_max_streams(u_char *p, s3_quic_max_streams_frame_t *ms)
{
    size_t    len;
    u_char   *start;
    s3_uint_t type;

    type = ms->bidi ? S3_QUIC_FT_MAX_STREAMS : S3_QUIC_FT_MAX_STREAMS2;

    if (p == NULL) {
        len = s3_quic_varint_len(type);
        len += s3_quic_varint_len(ms->limit);
        return len;
    }

    start = p;

    s3_quic_build_int(&p, type);
    s3_quic_build_int(&p, ms->limit);

    return p - start;
}

static size_t
s3_quic_create_max_stream_data(u_char *p, s3_quic_max_stream_data_frame_t *ms)
{
    size_t  len;
    u_char *start;

    if (p == NULL) {
        len = s3_quic_varint_len(S3_QUIC_FT_MAX_STREAM_DATA);
        len += s3_quic_varint_len(ms->id);
        len += s3_quic_varint_len(ms->limit);
        return len;
    }

    start = p;

    s3_quic_build_int(&p, S3_QUIC_FT_MAX_STREAM_DATA);
    s3_quic_build_int(&p, ms->id);
    s3_quic_build_int(&p, ms->limit);

    return p - start;
}

static size_t
s3_quic_create_max_data(u_char *p, s3_quic_max_data_frame_t *md)
{
    size_t  len;
    u_char *start;

    if (p == NULL) {
        len = s3_quic_varint_len(S3_QUIC_FT_MAX_DATA);
        len += s3_quic_varint_len(md->max_data);
        return len;
    }

    start = p;

    s3_quic_build_int(&p, S3_QUIC_FT_MAX_DATA);
    s3_quic_build_int(&p, md->max_data);

    return p - start;
}

static size_t
s3_quic_create_datagram(u_char *p, s3_quic_frame_t *f)
{
    size_t      len;
    u_char     *start;
    s3_buf_t   *b;
    s3_chain_t *data;

    if (p == NULL) {
        len = s3_quic_varint_len(f->type);

        if (f->type == S3_QUIC_FT_DATAGRAM_WITH_LENGTH) {
            len += s3_quic_varint_len(f->u.datagram.length);
        }

        len += f->u.datagram.length;

        return len;
    }

    start = p;

    s3_quic_build_int(&p, f->type);

    if (f->type == S3_QUIC_FT_DATAGRAM_WITH_LENGTH) {
        s3_quic_build_int(&p, f->u.datagram.length);
    }

    data = f->data;

    while (data) {
        b = data->buf;
        p = s3_cpymem(p, b->pos, b->last - b->pos);
        data = data->next;
    }

    return p - start;
}

static size_t
s3_quic_create_path_challenge(u_char *p, s3_quic_path_challenge_frame_t *pc)
{
    size_t  len;
    u_char *start;

    if (p == NULL) {
        len = s3_quic_varint_len(S3_QUIC_FT_PATH_CHALLENGE);
        len += sizeof(pc->data);
        return len;
    }

    start = p;

    s3_quic_build_int(&p, S3_QUIC_FT_PATH_CHALLENGE);
    p = s3_cpymem(p, &pc->data, sizeof(pc->data));

    return p - start;
}

static size_t
s3_quic_create_path_response(u_char *p, s3_quic_path_challenge_frame_t *pc)
{
    size_t  len;
    u_char *start;

    if (p == NULL) {
        len = s3_quic_varint_len(S3_QUIC_FT_PATH_RESPONSE);
        len += sizeof(pc->data);
        return len;
    }

    start = p;

    s3_quic_build_int(&p, S3_QUIC_FT_PATH_RESPONSE);
    p = s3_cpymem(p, &pc->data, sizeof(pc->data));

    return p - start;
}

static size_t
s3_quic_create_new_connection_id(u_char *p, s3_quic_new_conn_id_frame_t *ncid)
{
    size_t  len;
    u_char *start;

    if (p == NULL) {
        len = s3_quic_varint_len(S3_QUIC_FT_NEW_CONNECTION_ID);
        len += s3_quic_varint_len(ncid->seqnum);
        len += s3_quic_varint_len(ncid->retire);
        len++;
        len += ncid->len;
        len += S3_QUIC_SR_TOKEN_LEN;
        return len;
    }

    start = p;

    s3_quic_build_int(&p, S3_QUIC_FT_NEW_CONNECTION_ID);
    s3_quic_build_int(&p, ncid->seqnum);
    s3_quic_build_int(&p, ncid->retire);
    *p++ = ncid->len;
    p = s3_cpymem(p, ncid->cid, ncid->len);
    p = s3_cpymem(p, ncid->srt, S3_QUIC_SR_TOKEN_LEN);

    return p - start;
}

static size_t
s3_quic_create_retire_connection_id(u_char *p, s3_quic_retire_cid_frame_t *rcid)
{
    size_t  len;
    u_char *start;

    if (p == NULL) {
        len = s3_quic_varint_len(S3_QUIC_FT_RETIRE_CONNECTION_ID);
        len += s3_quic_varint_len(rcid->sequence_number);
        return len;
    }

    start = p;

    s3_quic_build_int(&p, S3_QUIC_FT_RETIRE_CONNECTION_ID);
    s3_quic_build_int(&p, rcid->sequence_number);

    return p - start;
}

static s3_int_t
s3_quic_parse_transport_param(u_char *p, u_char *end, uint16_t id, s3_quic_tp_t *dst)
{
    uint64_t varint;
    s3_str_t str;

    varint = 0;
    s3_str_null(&str);

    switch (id) {

    case S3_QUIC_TP_DISABLE_ACTIVE_MIGRATION:
        /* zero-length option */
        if (end - p != 0) {
            return S3_ERROR;
        }
        dst->disable_active_migration = 1;
        return S3_OK;

    case S3_QUIC_TP_MAX_IDLE_TIMEOUT:
    case S3_QUIC_TP_MAX_UDP_PAYLOAD_SIZE:
    case S3_QUIC_TP_INITIAL_MAX_DATA:
    case S3_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
    case S3_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
    case S3_QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI:
    case S3_QUIC_TP_INITIAL_MAX_STREAMS_BIDI:
    case S3_QUIC_TP_INITIAL_MAX_STREAMS_UNI:
    case S3_QUIC_TP_ACK_DELAY_EXPONENT:
    case S3_QUIC_TP_MAX_ACK_DELAY:
    case S3_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT:
    case S3_QUIC_TP_MAX_DATAGRAM_FRAME_SIZE:

        p = s3_quic_parse_int(p, end, &varint);
        if (p == NULL) {
            return S3_ERROR;
        }
        break;

    case S3_QUIC_TP_INITIAL_SCID:
    case S3_QUIC_TP_ORIGINAL_DCID:
    case S3_QUIC_TP_RETRY_SCID:

        str.len = end - p;
        str.data = p;
        break;

    case S3_QUIC_TP_SR_TOKEN:

        if (end - p != S3_QUIC_SR_TOKEN_LEN) {
            return S3_ERROR;
        }
        s3_memcpy(dst->sr_token, p, S3_QUIC_SR_TOKEN_LEN);
        return S3_OK;

    default:
        return S3_DECLINED;
    }

    switch (id) {

    case S3_QUIC_TP_MAX_IDLE_TIMEOUT:
        dst->max_idle_timeout = varint;
        break;

    case S3_QUIC_TP_MAX_UDP_PAYLOAD_SIZE:
        dst->max_udp_payload_size = varint;
        break;

    case S3_QUIC_TP_INITIAL_MAX_DATA:
        dst->initial_max_data = varint;
        break;

    case S3_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
        dst->initial_max_stream_data_bidi_local = varint;
        break;

    case S3_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
        dst->initial_max_stream_data_bidi_remote = varint;
        break;

    case S3_QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI:
        dst->initial_max_stream_data_uni = varint;
        break;

    case S3_QUIC_TP_INITIAL_MAX_STREAMS_BIDI:
        dst->initial_max_streams_bidi = varint;
        break;

    case S3_QUIC_TP_INITIAL_MAX_STREAMS_UNI:
        dst->initial_max_streams_uni = varint;
        break;

    case S3_QUIC_TP_ACK_DELAY_EXPONENT:
        dst->ack_delay_exponent = varint;
        break;

    case S3_QUIC_TP_MAX_ACK_DELAY:
        dst->max_ack_delay = varint;
        break;

    case S3_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT:
        dst->active_connection_id_limit = varint;
        break;

    case S3_QUIC_TP_MAX_DATAGRAM_FRAME_SIZE:
        dst->max_datagram_frame_size = varint;
        break;

    case S3_QUIC_TP_INITIAL_SCID:
        dst->initial_scid = str;
        break;

    case S3_QUIC_TP_ORIGINAL_DCID:
        dst->original_dcid = str;
        break;

    case S3_QUIC_TP_RETRY_SCID:
        dst->retry_scid = str;
        break;

    default:
        return S3_ERROR;
    }

    return S3_OK;
}

s3_int_t
s3_quic_parse_transport_params(u_char *p, u_char *end, s3_quic_tp_t *tp, s3_log_t *log,
                               s3_uint_t client)
{
    uint64_t id, len;
    s3_int_t rc;

    while (p < end) {
        p = s3_quic_parse_int(p, end, &id);
        if (p == NULL) {
            s3_log_error(S3_LOG_INFO, log, 0, "quic failed to parse transport param id");
            return S3_ERROR;
        }

        /*
         * RFC 9000, 7.3.  The reference is a server and so rejects the
         * server-only parameters in any peer; a client expects them
         * instead and validates the values in s3_quic_apply_transport_params()
         */

        switch (id) {
        case S3_QUIC_TP_ORIGINAL_DCID:
        case S3_QUIC_TP_PREFERRED_ADDRESS:
        case S3_QUIC_TP_RETRY_SCID:
        case S3_QUIC_TP_SR_TOKEN:

            if (client) {
                break;
            }

            s3_log_error(S3_LOG_INFO, log, 0,
                         "quic client sent forbidden transport param"
                         " id:0x%xL",
                         id);
            return S3_ERROR;

        default:
            break;
        }

        p = s3_quic_parse_int(p, end, &len);
        if (p == NULL) {
            s3_log_error(S3_LOG_INFO, log, 0,
                         "quic failed to parse"
                         " transport param id:0x%xL length",
                         id);
            return S3_ERROR;
        }

        if ((size_t)(end - p) < len) {
            s3_log_error(S3_LOG_INFO, log, 0,
                         "quic failed to parse"
                         " transport param id:0x%xL, data length %uL too long",
                         id, len);
            return S3_ERROR;
        }

        rc = s3_quic_parse_transport_param(p, p + len, id, tp);

        if (rc == S3_ERROR) {
            s3_log_error(S3_LOG_INFO, log, 0,
                         "quic failed to parse"
                         " transport param id:0x%xL data",
                         id);
            return S3_ERROR;
        }

        if (rc == S3_DECLINED) {
            s3_log_debug2(S3_LOG_DEBUG_EVENT, log, 0, "quic %s transport param id:0x%xL, skipped",
                          (id % 31 == 27) ? "reserved" : "unknown", id);
        }

        p += len;
    }

    if (p != end) {
        s3_log_error(S3_LOG_INFO, log, 0,
                     "quic trailing garbage in"
                     " transport parameters: bytes:%ui",
                     end - p);
        return S3_ERROR;
    }

    s3_log_debug0(S3_LOG_DEBUG_EVENT, log, 0, "quic transport parameters parsed ok");

    s3_log_debug1(S3_LOG_DEBUG_EVENT, log, 0, "quic tp disable active migration: %ui",
                  tp->disable_active_migration);

    s3_log_debug1(S3_LOG_DEBUG_EVENT, log, 0, "quic tp idle_timeout:%ui", tp->max_idle_timeout);

    s3_log_debug1(S3_LOG_DEBUG_EVENT, log, 0, "quic tp max_udp_payload_size:%ui",
                  tp->max_udp_payload_size);

    s3_log_debug1(S3_LOG_DEBUG_EVENT, log, 0, "quic tp max_data:%ui", tp->initial_max_data);

    s3_log_debug1(S3_LOG_DEBUG_EVENT, log, 0, "quic tp max_stream_data_bidi_local:%ui",
                  tp->initial_max_stream_data_bidi_local);

    s3_log_debug1(S3_LOG_DEBUG_EVENT, log, 0, "quic tp max_stream_data_bidi_remote:%ui",
                  tp->initial_max_stream_data_bidi_remote);

    s3_log_debug1(S3_LOG_DEBUG_EVENT, log, 0, "quic tp max_stream_data_uni:%ui",
                  tp->initial_max_stream_data_uni);

    s3_log_debug1(S3_LOG_DEBUG_EVENT, log, 0, "quic tp initial_max_streams_bidi:%ui",
                  tp->initial_max_streams_bidi);

    s3_log_debug1(S3_LOG_DEBUG_EVENT, log, 0, "quic tp initial_max_streams_uni:%ui",
                  tp->initial_max_streams_uni);

    s3_log_debug1(S3_LOG_DEBUG_EVENT, log, 0, "quic tp ack_delay_exponent:%ui",
                  tp->ack_delay_exponent);

    s3_log_debug1(S3_LOG_DEBUG_EVENT, log, 0, "quic tp max_ack_delay:%ui", tp->max_ack_delay);

    s3_log_debug1(S3_LOG_DEBUG_EVENT, log, 0, "quic tp active_connection_id_limit:%ui",
                  tp->active_connection_id_limit);

    s3_log_debug1(S3_LOG_DEBUG_EVENT, log, 0, "quic tp max_datagram_frame_size:%ui",
                  tp->max_datagram_frame_size);

    s3_log_debug2(S3_LOG_DEBUG_EVENT, log, 0, "quic tp initial source_connection_id len:%uz %xV",
                  tp->initial_scid.len, &tp->initial_scid);

    return S3_OK;
}

void
s3_quic_conf_conn_rx_window(s3_quic_conf_t *conf, size_t bytes)
{
    /* 0 restores the derived default, see s3_quic_init_transport_params() */

    conf->conn_rx_window = bytes;
}

void
s3_quic_conf_stream_rx_window(s3_quic_conf_t *conf, size_t bytes)
{
    conf->stream_rx_window = bytes;
}

s3_int_t
s3_quic_init_transport_params(s3_quic_tp_t *tp, s3_quic_conf_t *qcf)
{
    s3_uint_t nstreams;
    size_t    stream_rx;

    s3_memzero(tp, sizeof(s3_quic_tp_t));

    /*
     * set by s3_memzero():
     *
     *     tp->disable_active_migration = 0;
     *     tp->max_datagram_frame_size = 0; (datagrams disabled)
     *     tp->original_dcid = { 0, NULL };
     *     tp->initial_scid = { 0, NULL };
     *     tp->retry_scid = { 0, NULL };
     *     tp->sr_token = { 0 }
     *     tp->preferred_address = NULL
     */

    tp->max_idle_timeout = qcf->idle_timeout;

    tp->max_udp_payload_size = S3_QUIC_MAX_UDP_PAYLOAD_SIZE;

    nstreams = qcf->max_concurrent_streams_bidi + qcf->max_concurrent_streams_uni;

    /*
     * the client tuning (s3_quic_conf_*_rx_window): 0 keeps the
     * derived defaults
     */

    stream_rx = qcf->stream_rx_window ? qcf->stream_rx_window : qcf->stream_buffer_size;

    tp->initial_max_data =
        qcf->conn_rx_window ? qcf->conn_rx_window : nstreams * qcf->stream_buffer_size;
    tp->initial_max_stream_data_bidi_local = stream_rx;
    tp->initial_max_stream_data_bidi_remote = stream_rx;
    tp->initial_max_stream_data_uni = stream_rx;

    tp->initial_max_streams_bidi = qcf->max_concurrent_streams_bidi;
    tp->initial_max_streams_uni = qcf->max_concurrent_streams_uni;

    tp->max_ack_delay = S3_QUIC_DEFAULT_MAX_ACK_DELAY;
    tp->ack_delay_exponent = S3_QUIC_DEFAULT_ACK_DELAY_EXPONENT;

    tp->active_connection_id_limit = qcf->active_connection_id_limit;
    tp->disable_active_migration = qcf->disable_active_migration;

    tp->max_datagram_frame_size = qcf->max_datagram_frame_size;

    return S3_OK;
}

ssize_t
s3_quic_create_transport_params(u_char *pos, u_char *end, s3_quic_tp_t *tp, size_t *clen)
{
    u_char *p;
    size_t  len;

    /* the nginx signature keeps end; the buffer is sized by the caller */
    (void)end;

#define s3_quic_tp_len(id, value)                                                                  \
    s3_quic_varint_len(id) + s3_quic_varint_len(value) +                                           \
        s3_quic_varint_len(s3_quic_varint_len(value))

#define s3_quic_tp_vint(id, value)                                                                 \
    do {                                                                                           \
        s3_quic_build_int(&p, id);                                                                 \
        s3_quic_build_int(&p, s3_quic_varint_len(value));                                          \
        s3_quic_build_int(&p, value);                                                              \
    } while (0)

#define s3_quic_tp_strlen(id, value)                                                               \
    s3_quic_varint_len(id) + s3_quic_varint_len((value).len) + (value).len

#define s3_quic_tp_str(id, value)                                                                  \
    do {                                                                                           \
        s3_quic_build_int(&p, id);                                                                 \
        s3_quic_build_int(&p, (value).len);                                                        \
        if ((value).len) {                                                                         \
            p = s3_cpymem(p, (value).data, (value).len);                                           \
        }                                                                                          \
    } while (0)

    len = s3_quic_tp_len(S3_QUIC_TP_INITIAL_MAX_DATA, tp->initial_max_data);

    len += s3_quic_tp_len(S3_QUIC_TP_INITIAL_MAX_STREAMS_UNI, tp->initial_max_streams_uni);

    len += s3_quic_tp_len(S3_QUIC_TP_INITIAL_MAX_STREAMS_BIDI, tp->initial_max_streams_bidi);

    len += s3_quic_tp_len(S3_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
                          tp->initial_max_stream_data_bidi_local);

    len += s3_quic_tp_len(S3_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
                          tp->initial_max_stream_data_bidi_remote);

    len += s3_quic_tp_len(S3_QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI, tp->initial_max_stream_data_uni);

    len += s3_quic_tp_len(S3_QUIC_TP_MAX_IDLE_TIMEOUT, tp->max_idle_timeout);

    len += s3_quic_tp_len(S3_QUIC_TP_MAX_UDP_PAYLOAD_SIZE, tp->max_udp_payload_size);

    if (tp->disable_active_migration) {
        len += s3_quic_varint_len(S3_QUIC_TP_DISABLE_ACTIVE_MIGRATION);
        len += s3_quic_varint_len(0);
    }

    len += s3_quic_tp_len(S3_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT, tp->active_connection_id_limit);

    /* transport parameters listed above will be saved in 0-RTT context */
    if (clen) {
        *clen = len;
    }

    len += s3_quic_tp_len(S3_QUIC_TP_MAX_ACK_DELAY, tp->max_ack_delay);

    len += s3_quic_tp_len(S3_QUIC_TP_ACK_DELAY_EXPONENT, tp->ack_delay_exponent);

    if (tp->max_datagram_frame_size) {
        len += s3_quic_tp_len(S3_QUIC_TP_MAX_DATAGRAM_FRAME_SIZE, tp->max_datagram_frame_size);
    }

    /*
     * the original_dcid, retry_scid and sr_token parameters are only
     * sent by servers (RFC 9000, 18.2); the client role leaves them
     * empty and the encoder skips them
     */
    if (tp->original_dcid.len) {
        len += s3_quic_tp_strlen(S3_QUIC_TP_ORIGINAL_DCID, tp->original_dcid);
    }

    if (tp->initial_scid.len) {
        len += s3_quic_tp_strlen(S3_QUIC_TP_INITIAL_SCID, tp->initial_scid);
    }

    if (tp->retry_scid.len) {
        len += s3_quic_tp_strlen(S3_QUIC_TP_RETRY_SCID, tp->retry_scid);
    }

    if (s3_quic_tp_sr_token_set(tp)) {
        len += s3_quic_varint_len(S3_QUIC_TP_SR_TOKEN);
        len += s3_quic_varint_len(S3_QUIC_SR_TOKEN_LEN);
        len += S3_QUIC_SR_TOKEN_LEN;
    }

    if (pos == NULL) {
        return len;
    }

    p = pos;

    s3_quic_tp_vint(S3_QUIC_TP_INITIAL_MAX_DATA, tp->initial_max_data);

    s3_quic_tp_vint(S3_QUIC_TP_INITIAL_MAX_STREAMS_UNI, tp->initial_max_streams_uni);

    s3_quic_tp_vint(S3_QUIC_TP_INITIAL_MAX_STREAMS_BIDI, tp->initial_max_streams_bidi);

    s3_quic_tp_vint(S3_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
                    tp->initial_max_stream_data_bidi_local);

    s3_quic_tp_vint(S3_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
                    tp->initial_max_stream_data_bidi_remote);

    s3_quic_tp_vint(S3_QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI, tp->initial_max_stream_data_uni);

    s3_quic_tp_vint(S3_QUIC_TP_MAX_IDLE_TIMEOUT, tp->max_idle_timeout);

    s3_quic_tp_vint(S3_QUIC_TP_MAX_UDP_PAYLOAD_SIZE, tp->max_udp_payload_size);

    if (tp->disable_active_migration) {
        s3_quic_build_int(&p, S3_QUIC_TP_DISABLE_ACTIVE_MIGRATION);
        s3_quic_build_int(&p, 0);
    }

    s3_quic_tp_vint(S3_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT, tp->active_connection_id_limit);

    s3_quic_tp_vint(S3_QUIC_TP_MAX_ACK_DELAY, tp->max_ack_delay);

    s3_quic_tp_vint(S3_QUIC_TP_ACK_DELAY_EXPONENT, tp->ack_delay_exponent);

    if (tp->max_datagram_frame_size) {
        s3_quic_tp_vint(S3_QUIC_TP_MAX_DATAGRAM_FRAME_SIZE, tp->max_datagram_frame_size);
    }

    if (tp->original_dcid.len) {
        s3_quic_tp_str(S3_QUIC_TP_ORIGINAL_DCID, tp->original_dcid);
    }

    if (tp->initial_scid.len) {
        s3_quic_tp_str(S3_QUIC_TP_INITIAL_SCID, tp->initial_scid);
    }

    if (tp->retry_scid.len) {
        s3_quic_tp_str(S3_QUIC_TP_RETRY_SCID, tp->retry_scid);
    }

    if (s3_quic_tp_sr_token_set(tp)) {
        s3_quic_build_int(&p, S3_QUIC_TP_SR_TOKEN);
        s3_quic_build_int(&p, S3_QUIC_SR_TOKEN_LEN);
        p = s3_cpymem(p, tp->sr_token, S3_QUIC_SR_TOKEN_LEN);
    }

    return p - pos;
}

static s3_uint_t
s3_quic_tp_sr_token_set(const s3_quic_tp_t *tp)
{
    s3_uint_t i, v;

    v = 0;

    for (i = 0; i < S3_QUIC_SR_TOKEN_LEN; i++) {
        v |= tp->sr_token[i];
    }

    return v;
}

static size_t
s3_quic_create_close(u_char *p, s3_quic_frame_t *f)
{
    size_t                 len;
    u_char                *start;
    s3_quic_close_frame_t *cl;

    cl = &f->u.close;

    if (p == NULL) {
        len = s3_quic_varint_len(f->type);
        len += s3_quic_varint_len(cl->error_code);

        if (f->type != S3_QUIC_FT_CONNECTION_CLOSE_APP) {
            len += s3_quic_varint_len(cl->frame_type);
        }

        len += s3_quic_varint_len(cl->reason.len);
        len += cl->reason.len;

        return len;
    }

    start = p;

    s3_quic_build_int(&p, f->type);
    s3_quic_build_int(&p, cl->error_code);

    if (f->type != S3_QUIC_FT_CONNECTION_CLOSE_APP) {
        s3_quic_build_int(&p, cl->frame_type);
    }

    s3_quic_build_int(&p, cl->reason.len);

    if (cl->reason.len) {
        p = s3_cpymem(p, cl->reason.data, cl->reason.len);
    }

    return p - start;
}

void
s3_quic_dcid_encode_key(u_char *dcid, uint64_t key)
{
    (void)s3_quic_write_uint64(dcid, key);
}
