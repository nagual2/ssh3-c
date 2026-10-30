/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2026 the ssh3-c authors
 */

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <s3_quic.h>
#include <s3_quic_connection.h>
#include <s3_quic_frames.h>
#include <s3_quic_output.h>
#include <s3_quic_ssl.h>
#include <s3_quic_streams.h>

/*
 * RFC 9000, 7.5.  Cryptographic Message Buffering
 *
 * Implementations MUST support buffering at least 4096 bytes of data
 */
#define S3_QUIC_MAX_BUFFERED 65535

/*
 * only the OpenSSL (>= 3.5) QUIC TLS API branch of the reference is
 * carried over (porting map 1.13.2): the TLS handshake is driven by
 * SSL_do_handshake(), the CRYPTO records are pulled through the
 * crypto_recv_rcd/release_rcd callbacks and pushed through
 * crypto_send; the quictls/boringssl branches are not ported
 */

static int s3_quic_cbs_send(SSL *ssl_conn, const unsigned char *data, size_t len, size_t *consumed,
                            void *arg);
static int s3_quic_cbs_recv_rcd(SSL *ssl_conn, const unsigned char **data, size_t *bytes_read,
                                void *arg);
static int s3_quic_cbs_release_rcd(SSL *ssl_conn, size_t bytes_read, void *arg);
static int s3_quic_cbs_yield_secret(SSL *ssl_conn, uint32_t ssl_level, int direction,
                                    const unsigned char *secret, size_t secret_len, void *arg);
static int s3_quic_cbs_got_transport_params(SSL *ssl_conn, const unsigned char *params,
                                            size_t params_len, void *arg);
static int s3_quic_cbs_alert(SSL *ssl_conn, unsigned char alert, void *arg);

static s3_int_t s3_quic_ssl_tls_init(s3_connection_t *c);

static const OSSL_DISPATCH qtdis[] = {

    {OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND, (void (*)(void))s3_quic_cbs_send},

    {OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RECV_RCD, (void (*)(void))s3_quic_cbs_recv_rcd},

    {OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RELEASE_RCD, (void (*)(void))s3_quic_cbs_release_rcd},

    {OSSL_FUNC_SSL_QUIC_TLS_YIELD_SECRET, (void (*)(void))s3_quic_cbs_yield_secret},

    {OSSL_FUNC_SSL_QUIC_TLS_GOT_TRANSPORT_PARAMS, (void (*)(void))s3_quic_cbs_got_transport_params},

    {OSSL_FUNC_SSL_QUIC_TLS_ALERT, (void (*)(void))s3_quic_cbs_alert},

    {0, NULL}};

static int
s3_quic_cbs_send(SSL *ssl_conn, const unsigned char *data, size_t len, size_t *consumed, void *arg)
{
    s3_chain_t           *out;
    unsigned int          alpn_len;
    s3_quic_frame_t      *frame;
    const unsigned char  *alpn_data;
    s3_quic_send_ctx_t   *ctx;
    s3_connection_t      *c = arg;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "quic s3_quic_cbs_send len:%uz", len);

    *consumed = 0;

    SSL_get0_alpn_selected(ssl_conn, &alpn_data, &alpn_len);

    /*
     * the server sees the offered ALPN of the peer; the client learns
     * the negotiated ALPN only with the ServerHello, so the check is
     * deferred to the handshake completion
     */
    if (!qc->client && alpn_len == 0) {
        qc->error = S3_QUIC_ERR_CRYPTO(SSL_AD_NO_APPLICATION_PROTOCOL);
        qc->error_reason = "missing ALPN extension";

        s3_log_error(S3_LOG_INFO, c->log, 0, "quic missing ALPN extension");
        return 1;
    }

    /*
     * the server may not send before the client transport parameters
     * arrived (RFC 9001, 8.2); the client sends its own parameters
     * with SSL_set_quic_tls_transport_params() and may start at once
     */
    if (!qc->client && !qc->client_tp_done) {
        /* RFC 9001, 8.2.  QUIC Transport Parameters Extension */
        qc->error = S3_QUIC_ERR_CRYPTO(SSL_AD_MISSING_EXTENSION);
        qc->error_reason = "missing transport parameters";

        s3_log_error(S3_LOG_INFO, c->log, 0, "missing transport parameters");
        return 1;
    }

    ctx = s3_quic_get_send_ctx(qc, qc->write_level);

    out = s3_quic_copy_buffer(c, (u_char *)data, len);
    if (out == S3_CHAIN_ERROR) {
        qc->error = S3_QUIC_ERR_INTERNAL_ERROR;
        return 1;
    }

    frame = s3_quic_alloc_frame(c);
    if (frame == NULL) {
        qc->error = S3_QUIC_ERR_INTERNAL_ERROR;
        return 1;
    }

    frame->data = out;
    frame->level = qc->write_level;
    frame->type = S3_QUIC_FT_CRYPTO;
    frame->u.crypto.offset = ctx->crypto_sent;
    frame->u.crypto.length = len;

    ctx->crypto_sent += len;
    *consumed = len;

    s3_quic_queue_frame(qc, frame);

    return 1;
}

static int
s3_quic_cbs_recv_rcd(SSL *ssl_conn, const unsigned char **data, size_t *bytes_read, void *arg)
{
    s3_buf_t             *b;
    s3_chain_t           *cl;
    s3_quic_send_ctx_t   *ctx;
    s3_connection_t      *c = arg;
    s3_quic_connection_t *qc;

    (void)ssl_conn;

    qc = s3_quic_get_connection(c);

    s3_log_debug0(S3_LOG_DEBUG_EVENT, c->log, 0, "quic s3_quic_cbs_recv_rcd");

    ctx = s3_quic_get_send_ctx(qc, qc->read_level);

    cl = ctx->crypto.chain;

    if (cl == NULL || cl->buf->sync) {
        *data = NULL;
        *bytes_read = 0;

    } else {
        b = cl->buf;

        *data = b->pos;
        *bytes_read = b->last - b->pos;
    }

    return 1;
}

static int
s3_quic_cbs_release_rcd(SSL *ssl_conn, size_t bytes_read, void *arg)
{
    s3_chain_t           *cl;
    s3_quic_send_ctx_t   *ctx;
    s3_connection_t      *c = arg;
    s3_quic_connection_t *qc;

    (void)ssl_conn;

    s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "quic s3_quic_cbs_release_rcd len:%uz",
                  bytes_read);

    /* already closed on handshake failure */

    qc = s3_quic_get_connection(c);
    if (qc == NULL) {
        return 1;
    }

    ctx = s3_quic_get_send_ctx(qc, qc->read_level);

    cl = s3_quic_read_buffer(c, &ctx->crypto, bytes_read);
    if (cl == S3_CHAIN_ERROR) {
        qc->error = S3_QUIC_ERR_INTERNAL_ERROR;
        return 1;
    }

    s3_quic_free_chain(c, cl);

    return 1;
}

static int
s3_quic_cbs_yield_secret(SSL *ssl_conn, uint32_t ssl_level, int direction,
                         const unsigned char *secret, size_t secret_len, void *arg)
{
    s3_uint_t             level;
    const SSL_CIPHER     *cipher;
    s3_connection_t      *c = arg;
    s3_quic_connection_t *qc;

    (void)ssl_conn;

    s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "quic s3_quic_cbs_yield_secret() level:%uD",
                  ssl_level);
#ifdef S3_QUIC_DEBUG_CRYPTO
    s3_log_debug4(S3_LOG_DEBUG_EVENT, c->log, 0, "quic %s secret len:%uz %*xs",
                  direction ? "write" : "read", secret_len, secret_len, secret);
#endif

    qc = s3_quic_get_connection(c);
    cipher = SSL_get_current_cipher(ssl_conn);

    switch (ssl_level) {
    case OSSL_RECORD_PROTECTION_LEVEL_NONE:
        level = S3_QUIC_ENCRYPTION_INITIAL;
        break;

    case OSSL_RECORD_PROTECTION_LEVEL_EARLY:
        level = S3_QUIC_ENCRYPTION_EARLY_DATA;
        break;

    case OSSL_RECORD_PROTECTION_LEVEL_HANDSHAKE:
        level = S3_QUIC_ENCRYPTION_HANDSHAKE;
        break;

    default: /* OSSL_RECORD_PROTECTION_LEVEL_APPLICATION */
        level = S3_QUIC_ENCRYPTION_APPLICATION;
        break;
    }

    /*
     * SSL_CIPHER_get_id() returns the TLS cipher suite id with the
     * 0x03000000 prefix, like the TLS1_3_CK_* constants used by the
     * protection layer
     */

    /*
     * the OpenSSL direction flag follows nginx: 1 for the write
     * (transmit) secret and 0 for the read (receive) secret; the
     * protection layer slots the secrets by the tls direction against
     * the connection role (RFC 9001, 5.1)
     */
    if (s3_quic_keys_set_encryption_secret(c->log, direction, qc->keys, level,
                                           (uint32_t)SSL_CIPHER_get_id(cipher), secret,
                                           secret_len) != S3_OK) {
        qc->error = S3_QUIC_ERR_INTERNAL_ERROR;
        return 1;
    }

    if (direction) {
        qc->write_level = level;

    } else {
        /*
         * TLS 1.3 derives the peer application read secret before the
         * peer Finished is processed.  Moving read_level to APPLICATION
         * here would hide the handshake records still queued on the
         * handshake crypto stream from s3_quic_cbs_recv_rcd() and
         * deadlock the handshake (RFC 9001, 4.1.2); the level is
         * advanced once SSL_do_handshake() reports completion
         */

        if (!c->ssl->handshaked && level == S3_QUIC_ENCRYPTION_APPLICATION) {
            return 1;
        }

        qc->read_level = level;
    }

    return 1;
}

static int
s3_quic_cbs_got_transport_params(SSL *ssl_conn, const unsigned char *params, size_t params_len,
                                 void *arg)
{
    u_char               *p, *end;
    s3_quic_tp_t          ctp;
    s3_connection_t      *c = arg;
    s3_quic_connection_t *qc;

    (void)ssl_conn;

    s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "quic s3_quic_cbs_got_transport_params() len:%uz",
                  params_len);

    qc = s3_quic_get_connection(c);

    /* defaults for parameters not sent by client */
    ctp = qc->ctp;

    p = (u_char *)params;
    end = p + params_len;

    if (s3_quic_parse_transport_params(p, end, &ctp, c->log, qc->client) != S3_OK) {
        qc->error = S3_QUIC_ERR_TRANSPORT_PARAMETER_ERROR;
        qc->error_reason = "failed to process transport parameters";

        return 1;
    }

    if (s3_quic_apply_transport_params(c, &ctp) != S3_OK) {
        return 1;
    }

    qc->client_tp_done = 1;

    return 1;
}

static int
s3_quic_cbs_alert(SSL *ssl_conn, unsigned char alert, void *arg)
{
    s3_quic_connection_t *qc;
    s3_connection_t      *c = arg;

    (void)ssl_conn;

    s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "quic s3_quic_cbs_alert() alert:%d", (int)alert);

    /* already closed on regular shutdown */

    qc = s3_quic_get_connection(c);
    if (qc == NULL) {
        return 1;
    }

    qc->error = S3_QUIC_ERR_CRYPTO(alert);
    qc->error_reason = "handshake failed";

    return 1;
}

static s3_int_t s3_quic_post_handshake(s3_connection_t *c);

s3_int_t
s3_quic_handle_crypto_frame(s3_connection_t *c, s3_quic_header_t *pkt, s3_quic_frame_t *frame)
{
    uint64_t                last;
    s3_quic_send_ctx_t     *ctx;
    s3_quic_connection_t   *qc;
    s3_quic_crypto_frame_t *f;

    qc = s3_quic_get_connection(c);

    if (!s3_quic_keys_available(qc->keys, pkt->level, 0)) {
        return S3_OK;
    }

    if (c->ssl->handshaked && !qc->client) {
        /*
         * RFC 8446, 4.6.  Post-Handshake Messages
         *
         * a client never sends a post-handshake message, and a server
         * has nothing to hand over at this point: anything else is a
         * protocol violation (the reference only ever runs as a server
         * and so never sees the other direction)
         */

        qc->error = S3_QUIC_ERR_CRYPTO(SSL_AD_UNEXPECTED_MESSAGE);
        qc->error_reason = "unexpected CRYPTO frame";

        return S3_ERROR;
    }

    ctx = s3_quic_get_send_ctx(qc, pkt->level);
    f = &frame->u.crypto;

    /* no overflow since both values are 62-bit */
    last = f->offset + f->length;

    if (last > ctx->crypto.offset + S3_QUIC_MAX_BUFFERED) {
        qc->error = S3_QUIC_ERR_CRYPTO_BUFFER_EXCEEDED;
        return S3_ERROR;
    }

    if (last <= ctx->crypto.offset) {
        /*
         * duplicated crypto offsets speed the handshake up in the
         * reference by resending the queued crypto frames
         * (D3, s3_quic_ack.c: s3_quic_resend_frames()); until then
         * they are simply ignored
         */

        return S3_OK;
    }

    if (s3_quic_write_buffer(c, &ctx->crypto, frame->data, f->length, f->offset) ==
        S3_CHAIN_ERROR) {
        return S3_ERROR;
    }

    /*
     * the OpenSSL QUIC TLS API pulls the crypto records itself through
     * the crypto_recv_rcd callback; the reference feeds them explicitly
     * with SSL_provide_quic_data() on the quictls/boringssl branches
     */

    if (c->ssl->handshaked) {
        return s3_quic_post_handshake(c);
    }

    return s3_quic_handshake(c);
}

static s3_int_t
s3_quic_post_handshake(s3_connection_t *c)
{
    int      n, sslerr;
    SSL     *ssl_conn;
    s3_int_t rc;

    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    ssl_conn = c->ssl->connection;

    /*
     * RFC 9001, 4.6.  New Session Ticket
     *
     * a server delivers its tickets right after the handshake, so a
     * client keeps receiving CRYPTO frames in 1-RTT packets; the
     * records are pulled through the read callback as usual and
     * SSL_do_handshake() dispatches them
     */

    n = SSL_do_handshake(ssl_conn);

    s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "SSL_do_handshake (post): %d", n);

    if (n <= 0) {
        sslerr = SSL_get_error(ssl_conn, n);

        if (sslerr != SSL_ERROR_WANT_READ && sslerr != SSL_ERROR_WANT_WRITE) {
            s3_ssl_error(c->log, 0, "SSL_do_handshake() failed after handshake");
            return S3_ERROR;
        }

        return S3_OK;
    }

    if (qc->error) {
        return S3_ERROR;
    }

    /* a ticket may be followed by more of them in the same flight */

    rc = s3_quic_output(c);

    return rc;
}

s3_int_t
s3_quic_handshake(s3_connection_t *c)
{
    int                   n, sslerr;
    SSL                  *ssl_conn;
    s3_quic_frame_t      *frame;
    const unsigned char  *alpn_data;
    unsigned int          alpn_len;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    ssl_conn = c->ssl->connection;

    n = SSL_do_handshake(ssl_conn);

    s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "SSL_do_handshake: %d", n);

    if (n <= 0) {
        sslerr = SSL_get_error(ssl_conn, n);

        s3_log_debug1(S3_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d", sslerr);

        if (c->ssl->handshake_rejected) {
            s3_log_error(S3_LOG_INFO, c->log, 0, "handshake rejected");
            ERR_clear_error();
            return S3_ERROR;
        }

        if (qc->error) {
            s3_log_error(S3_LOG_INFO, c->log, 0, "SSL_do_handshake() failed");
            ERR_clear_error();
            return S3_ERROR;
        }

        if (sslerr != SSL_ERROR_WANT_READ) {
            s3_ssl_error(c->log, 0, "SSL_do_handshake() failed");
            return S3_ERROR;
        }
    }

    if (qc->error) {
        s3_log_error(S3_LOG_INFO, c->log, 0, "SSL_do_handshake() failed");
        return S3_ERROR;
    }

    if (!SSL_is_init_finished(ssl_conn)) {
        /*
         * the reference starts 0-RTT streams here when the early data
         * keys and the client transport parameters are ready
         * (ngx_quic_init_streams() in the early data branch)
         */

        if (s3_quic_keys_available(qc->keys, S3_QUIC_ENCRYPTION_EARLY_DATA, 0) &&
            qc->client_tp_done) {
            if (s3_quic_init_streams(c) != S3_OK) {
                return S3_ERROR;
            }
        }

        return S3_OK;
    }

    c->ssl->handshaked = 1;

    /* the handshake crypto stream is drained, read at 1-RTT from now on */

    qc->read_level = S3_QUIC_ENCRYPTION_APPLICATION;

    if (qc->client) {
        /* the negotiated ALPN of the server is visible by now */
        SSL_get0_alpn_selected(ssl_conn, &alpn_data, &alpn_len);

        if (alpn_len == 0) {
            qc->error = S3_QUIC_ERR_CRYPTO(SSL_AD_NO_APPLICATION_PROTOCOL);
            qc->error_reason = "missing ALPN extension";

            s3_log_error(S3_LOG_INFO, c->log, 0, "quic missing ALPN extension");
            return S3_ERROR;
        }
    }

    if (!qc->client) {
        /* the client must not send HANDSHAKE_DONE (RFC 9000, 19.20) */

        frame = s3_quic_alloc_frame(c);
        if (frame == NULL) {
            return S3_ERROR;
        }

        frame->level = S3_QUIC_ENCRYPTION_APPLICATION;
        frame->type = S3_QUIC_FT_HANDSHAKE_DONE;
        s3_quic_queue_frame(qc, frame);

        if (qc->conf->retry) {
            /* the session token lets the peer skip address validation */
            if (s3_quic_send_new_token(c, qc->path) != S3_OK) {
                return S3_ERROR;
            }
        }
    }

    /*
     * RFC 9001, 9.5.  Header Protection Timing Side Channels
     *
     * Generating next keys before a key update is received.
     */

    s3_post_event(&qc->key_update, &qc->ctx->posted_events);

    /*
     * RFC 9001, 4.9.2.  Discarding Handshake Keys
     *
     * An endpoint MUST discard its Handshake keys
     * when the TLS handshake is confirmed.
     *
     * a client confirms the handshake right after handing its Finished
     * over to the Handshake context, so the pending Handshake frames
     * have to leave the wire before that context is dropped; the
     * reference never has to flush here, it only runs as a server,
     * where the whole flight is already sent and waits for an ack
     */

    if (qc->client && s3_quic_output(c) != S3_OK) {
        return S3_ERROR;
    }

    s3_quic_discard_ctx(c, S3_QUIC_ENCRYPTION_HANDSHAKE);

    /* the reference starts the MTU discovery here */
    s3_quic_discover_path_mtu(c, qc->path);

    if (!qc->client) {
        /* start accepting clients on negotiated number of server ids */
        if (s3_quic_create_sockets(c) != S3_OK) {
            return S3_ERROR;
        }
    }

    /* the application is opened: the close (handshake) timer dies here */

    if (s3_quic_init_streams(c) != S3_OK) {
        return S3_ERROR;
    }

    return S3_OK;
}

static s3_int_t
s3_quic_ssl_tls_init(s3_connection_t *c)
{
    u_char               *p;
    size_t                clen;
    ssize_t               len;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    if (SSL_set_quic_tls_cbs(c->ssl->connection, qtdis, c) == 0) {
        s3_ssl_error(c->log, 0, "quic SSL_set_quic_tls_cbs() failed");
        return S3_ERROR;
    }

    len = s3_quic_create_transport_params(NULL, NULL, &qc->tp, &clen);
    /* always succeeds */

    p = s3_pnalloc(c->pool, len);
    if (p == NULL) {
        return S3_ERROR;
    }

    len = s3_quic_create_transport_params(p, p + len, &qc->tp, NULL);
    if (len < 0) {
        return S3_ERROR;
    }

#ifdef S3_QUIC_DEBUG_PACKETS
    s3_log_debug3(S3_LOG_DEBUG_EVENT, c->log, 0, "quic transport params len:%uz %*xs", len, len, p);
#endif

    if (SSL_set_quic_tls_transport_params(c->ssl->connection, p, len) == 0) {
        s3_ssl_error(c->log, 0, "quic SSL_set_quic_tls_transport_params() failed");
        return S3_ERROR;
    }

    return S3_OK;
}

s3_int_t
s3_quic_init_connection(s3_connection_t *c)
{
    s3_str_t              dcid;
    s3_quic_socket_t     *qsock;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    if (s3_ssl_create_connection(qc->conf->ssl, c) != S3_OK) {
        return S3_ERROR;
    }

    c->ssl->no_wait_shutdown = 1;

    if (SSL_CTX_get_max_early_data(qc->conf->ssl->ctx)) {
        SSL_set_quic_tls_early_data_enabled(c->ssl->connection, 1);
    }

    qsock = s3_quic_get_socket(c);

    dcid.data = qsock->sid.id;
    dcid.len = qsock->sid.len;

    if (s3_quic_new_sr_token(c, &dcid, qc->conf->sr_token_key, qc->tp.sr_token) != S3_OK) {
        return S3_ERROR;
    }

    return s3_quic_ssl_tls_init(c);
}

s3_int_t
s3_quic_client_init_connection(s3_connection_t *c)
{
    s3_ssl_conn_t        *ssl_conn;
    s3_quic_connection_t *qc;

    qc = s3_quic_get_connection(c);

    ssl_conn = s3_pcalloc(c->pool, sizeof(s3_ssl_conn_t));
    if (ssl_conn == NULL) {
        return S3_ERROR;
    }

    ssl_conn->connection = SSL_new(qc->conf->ssl->ctx);
    if (ssl_conn->connection == NULL) {
        s3_ssl_error(c->log, 0, "SSL_new() failed");
        return S3_ERROR;
    }

    /*
     * the session resumption of the 0-RTT stage 1: the stored ticket
     * rides the ClientHello, the early-data enable arms the early
     * keys (the early CONNECT flight is the stage 2 - the 425 gate
     * keeps the auth out of the replay window meanwhile)
     */

    SSL_set_app_data(ssl_conn->connection, qc->conf->ssl);

    if (qc->conf->ssl->stored_session != NULL) {
        SSL_set_session(ssl_conn->connection, qc->conf->ssl->stored_session);
        SSL_set_quic_tls_early_data_enabled(ssl_conn->connection, 1);
    }

    SSL_set_connect_state(ssl_conn->connection);

    if (qc->conf->ssl->alpn.len > 0 &&
        SSL_set_alpn_protos(ssl_conn->connection, qc->conf->ssl->alpn.data,
                            (unsigned int)qc->conf->ssl->alpn.len) != 0) {
        s3_ssl_error(c->log, 0, "SSL_set_alpn_protos() failed");
        return S3_ERROR;
    }

    c->ssl = ssl_conn;

    return s3_quic_ssl_tls_init(c);
}
