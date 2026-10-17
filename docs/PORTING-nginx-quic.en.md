# ssh3-c: porting map of the nginx QUIC layer (phase P2)
> Languages: [RU](PORTING-nginx-quic.md) · EN (this file) · [DE](PORTING-nginx-quic.de.md)

Date: 2026-10-01. Reference: `C:\Git\temp\ssh3-c\refs\nginx\src\event\quic\` (nginx 1.31.7, read-only).
ssh3-c base: P0 (`src/core`: `s3_pool_t`/`s3_buf_t`/`s3_chain_t`/`s3_rbtree_t`/`s3_queue_t`/`s3_log_t`/`s3_str_t`) and P1 (`src/event`: `s3_event_ctx_t` + epoll, rbtree timers, posted events, `s3_connection_t` with `recv`/`send_chain`, UDP pseudo-connections `s3_udp_listen_t` + `s3_event_recvmsg`/`s3_udp_shared_recv`; `src/os/unix`: `s3_udp_sendmsg_chain`, `s3_sendmsg`, `s3_udp_recv`) — both phases are closed (see `docs/PLAN.md` §7).

License: all adapted files keep `Copyright (C) Nginx, Inc.` + add `Copyright (C) 2026 the ssh3-c authors` (BSD-2, obligations in `docs/DEPS-QUIC.md` §6 and `THIRD-PARTY-NOTICES.md`).

Target placement: `src/event/quic/s3_quic_*.c|h` (prefix `s3_`, project style).

---

## 1. Dependency map by `src/event/quic/` files

Summary (.c+.h lines, classification — the dominant one; details below):

| № | File | Lines | Classification |
|---|------|-------|---------------|
| 1 | `ngx_event_quic_transport.c/.h` | 2215+398 | clean (type substitution) |
| 2 | `ngx_event_quic_frames.c/.h` | 895+45 | clean (type substitution + `num` in `s3_buf_t`) |
| 3 | `ngx_event_quic_protection.c/.h` | 1268+118 | clean (libcrypto) |
| 4 | `ngx_event_quic_tokens.c/.h` | 265+34 | clean (libcrypto) |
| 5 | `ngx_event_quic_connid.c/.h` | 501+29 | clean (guard BPF) |
| 6 | `ngx_event_quic_output.c/.h` | 1405+40 | needs s3_context + os helpers |
| 7 | `ngx_event_quic_ack.c/.h` | 1456+31 | needs s3_context (light) |
| 8 | `ngx_event_quic.c` + `.h` | 1523+151 | needs s3_context (central) |
| 9 | `ngx_event_quic_streams.c/.h` | 1824+44 | needs s3_context (heavy) |
| 10 | `ngx_event_quic_migration.c/.h` | 1007+45 | needs s3_context |
| 11 | `ngx_event_quic_socket.c/.h` | 237+28 | needs s3_context (listener rbtree) |
| 12 | `ngx_event_quic_udp.c` | 437 | needs s3_context (replaced by the P1 layer) |
| 13 | `ngx_event_quic_ssl.c/.h` | 996+19 | needs the ssl layer |
| 14 | `ngx_event_quic_connection.h` | 329 | needs s3_context (rewrite types) |
| 15 | `ngx_event_quic_openssl_compat.c/.h` | 657+52 | not ported |
| 16 | `ngx_event_quic_bpf.c/.h`, `ngx_event_quic_bpf_code.c`, `bpf/*` | 1257+20+212+3 | not ported in P2 |

Detailed dependencies — from the actual code (grep include/calls, reference line numbers):

### 1.1. `ngx_event_quic_transport.c` (2215) + `.h` (398)

| № | Dependency | Facts from the code |
|---|-------------|---------------|
| 1 | ngx_core types | `ngx_str_t` (TP dcid/scid/retry, `pkt->token`), `ngx_buf_t` (`pkt->raw`), `ngx_chain_t` (`frame->data`), `ngx_queue_t` (`frame->queue`), `ngx_msec_t`, `ngx_uint_t`, `ngx_log_t` |
| 2 | ngx_conf | none |
| 3 | ngx_connection_t | none (only `ngx_quic_header_t` and `frame`, `c->log` is not used — the log is taken from `pkt->log`) |
| 4 | event/timers/posted | none |
| 5 | ngx_log | `ngx_log_error/debug0..2` throughout the file; `log->action` is not touched |
| 6 | palloc | none (parser/encoder — without allocations, except `ngx_pnalloc` in ssl.c for TP) |
| 7 | crypto | none (keys are passed via `pkt->keys` — the type from protection.h) |
| 8 | quic-internal | `ngx_quic_conf_t` reads: `qcf->idle_timeout, stream_buffer_size, max_concurrent_streams_bidi/uni, active_connection_id_limit, disable_active_migration` (`ngx_quic_init_transport_params`, L1986); `NGX_QUIC_FT_LAST` — the upper bound of the varint frame type (L764) |
| 9 | DATAGRAM | integration point No.1 (§3) |

### 1.2. `ngx_event_quic_frames.c` (895) + `.h` (45)

| № | Dependency | Facts from the code |
|---|-------------|---------------|
| 1 | palloc | `ngx_palloc` ×3, `ngx_pnalloc` ×1 (`ngx_quic_alloc_buf`, L28), `ngx_alloc` ×2, `ngx_free` ×1; refcount of shadow buffers: `ngx_quic_buf_refs(b) = (b)->shadow->num` (L15) — **`s3_buf_t` has no `num` field**, add it |
| 2 | ngx_connection_t | `c->log` ×12, `c->pool` ×7 |
| 3 | queue | `s3_queue_t` API 1:1 (insert_head/after/tail, remove, empty, head/last, `ngx_queue_data` → `s3_queue_data`) |
| 4 | ngx_log | `NGX_QUIC_DEBUG_ALLOC/PACKETS/FRAMES` debug — behind `#ifdef`, ported as is |
| 5 | buf API | `ngx_quic_buffer_t` (quic.h:71) + `read/write/skip/free_buffer` — the core of reassembly/buffering; fully portable |
| 6 | the rest | `ngx_min` ×4, `ngx_memcpy`, `ngx_memzero` |

### 1.3. `ngx_event_quic_protection.c` (1268) + `.h` (118)

| № | Dependency | Facts from the code |
|---|-------------|---------------|
| 1 | OpenSSL | `#include <openssl/hkdf.h, chacha.h, kdf.h>`; `EVP_PKEY_HKDF` derive (expand/extract), `EVP_Cipher*` AEAD GCM, `EVP_aes_*`/`EVP_chacha*`, header protection `EVP_CIPHER_CTX_ctrl`; `HKDF_extract/expand` (quictls branch), `EVP_AEAD_*` + `CRYPTO_chacha_*` (BoringSSL branches) — **cut the branches**, keep `NGX_QUIC_OPENSSL_API`/OpenSSL 3.5 |
| 2 | ngx_conf/cycle/connection | no `c->` except `c->log` ×5 |
| 3 | quic-internal | `ngx_quic_keys_t` (protection.h:44), `ngx_quic_header_t` (decrypt/create packet), `ngx_str_t` |
| 4 | classification | clean: only `libcrypto` + type substitution; self-contained for unit tests (RFC 9001 vectors) |

### 1.4. `ngx_event_quic_tokens.c` (265) + `.h` (34)

| № | Dependency | Facts from the code |
|---|-------------|---------------|
| 1 | OpenSSL | `RAND_bytes`, `EVP_Encrypt/Decrypt*` (AES-GCM, `EVP_CTRL_AEAD_SET/GET_TAG`), `EVP_aes_*` — retry-token and address-token |
| 2 | ngx_connection_t | `c->log` ×5, `c->sockaddr/socklen` ×1 (validate_token: binding the token to the address) |
| 3 | quic-internal | `conf->av_token_key/sr_token_key` (keys from `s3_quic_conf_t`), `ngx_quic_header_t` (retry itag) |
| 4 | classification | clean (libcrypto) |

### 1.5. `ngx_event_quic_connid.c` (501) + `.h` (29)

| № | Dependency | Facts from the code |
|---|-------------|---------------|
| 1 | OpenSSL | `RAND_bytes` (L29, server CID generation) |
| 2 | palloc | `ngx_pcalloc` ×1 |
| 3 | ngx_connection_t | `c->log` ×4, `c->pool` ×1 |
| 4 | BPF | `ngx_quic_bpf_attach_id` (L16-56) — under `#if (NGX_QUIC_BPF)`, we don't define it |
| 5 | queue | client_ids/free-queues, `ngx_queue_data` |
| 6 | classification | clean |

### 1.6. `ngx_event_quic_output.c` (1405) + `.h` (40)

| № | Dependency | Facts from the code |
|---|-------------|---------------|
| 1 | os layer | `ngx_sendmsg(c, &msg, 0)` ×2 (L472, L754) — ssh3-c already has `s3_sendmsg` (`src/os/unix/s3_udp_sendmsg_chain.h:30`); GSO: cmsg `SOL_UDP`/`UDP_SEGMENT` (L455, `ngx_quic_send_segments` L420) + a static 65 KB buffer (`NGX_QUIC_MAX_UDP_SEGMENT_BUF` L13, `NGX_QUIC_MAX_SEGMENTS` 64 L14); `NGX_HAVE_ADDRINFO_CMSG`: `ngx_get/set_srcaddr_cmsg` (L432-446) — **no analog in src/os/unix**, add `s3_get/set_srcaddr_cmsg` |
| 2 | ngx_connection_t | `c->log` ×24, `c->sockaddr/socklen` ×6+6, `c->local_sockaddr` ×4, `c->listening` ×4 (`listening->wildcard` for the ADDRINFO cmsg), `c->sent` ×2, `c->read` ×2 |
| 3 | event/timers | `ngx_add_timer(&qc->push, ...)` ×4 (retry EAGAIN, L386 etc.), `ngx_current_msec` ×5 |
| 4 | congestion/flow | `cg->in_flight + (p - dst) < cg->window` (L411) — the send limit; `ngx_quic_commit_send` (L203): frames with `pkt_need_ack==0` **are released immediately**, do not get into `ctx->sent` and `in_flight` (L228-233) — the key to DATAGRAM (§3.3) |
| 5 | crypto | `RAND_bytes` ×4 (stateless reset, retry, token dcid) |
| 6 | classification | needs s3_context + 2 os helpers; the sendmsg/GSO mechanics is compatible with P1 |

### 1.7. `ngx_event_quic_ack.c` (1456) + `.h` (31)

| № | Dependency | Facts from the code |
|---|-------------|---------------|
| 1 | event/timers | `ngx_current_msec` ×13, `ngx_add_timer` ×3, `ngx_del_timer` ×1, `ngx_post_event(&qc->lost, &ngx_posted_events)` ×5 (the lost handler is deferred into posted) |
| 2 | ngx_connection_t | `c->log` ×29, `c->ssl->handshaked` ×2 (L231, L1076 — ignore ACK before the handshake) |
| 3 | queues | `ctx->sent/sending/frames` — only queue operations |
| 4 | retransmission | `ngx_quic_resend_frames` (L758, called from L663 only for crypto spaces) moves frames from `ctx->sent` back into `ctx->frames`; `ngx_quic_detect_lost` (L594) respects `f->ignore_loss` (L893); the PTO `ngx_quic_pto_handler` (L1103) only sends PING |
| 5 | math | `ngx_abs/min/max`, `ngx_memmove` (ranges) |
| 6 | classification | needs s3_context — but minimally: the posted queue and timers already exist in `s3_event_ctx_t`; `c->ssl->handshaked` is replaced by a field of the QUIC connection |

### 1.8. `ngx_event_quic.c` (1523) + `.h` (151)

| № | Dependency | Facts from the code |
|---|-------------|---------------|
| 1 | posted | global `ngx_posted_events` ×5 + `ngx_post_event` ×5 → replace with `ctx->posted_events` + `s3_post_event` (`src/event/s3_event.h:128`) |
| 2 | timers | `ngx_add_timer/del_timer` ×12, `ngx_current_msec` ×6 |
| 3 | connection lifecycle | `ngx_close_connection` (L620), `ngx_reusable_connection` (L349), `c->buffer` (the datagram at run), `c->read/read->handler`, `c->udp`, `c->ssl` (L3/`handle_payload`: `c->ssl == NULL` → init), `c->pool/log` |
| 4 | hash | `ngx_sha1_init/update/final` (`ngx_quic_address_hash` L1478, the salt for the address-token) → replacement: OpenSSL `SHA1()`/`EVP_Digest` (libcrypto is already there) or porting `ngx_sha1.c` |
| 5 | conf | `qc->conf->handshake_timeout`, `qc->conf->init` (the streams hook), `qc->conf->shutdown` |
| 6 | rbtree/queue | the streams tree init (L243-244), qc queues |
| 7 | classification | needs s3_context: the central orchestrator; the public API (`ngx_quic_run/open_stream/finalize_connection/reset_stream/...`) — the contract for the layers above |

### 1.9. `ngx_event_quic_streams.c` (1824) + `.h` (44)

| № | Dependency | Facts from the code |
|---|-------------|---------------|
| 1 | connection lifecycle | `ngx_get_connection(c->fd, log)` (L737), `ngx_close_connection` (L190, L804), `ngx_reusable_connection` ×5 (L735, 741, 807, 835, 1169), pool cleanup `ngx_pool_cleanup_add` (L811, handler `ngx_quic_stream_cleanup_handler`) |
| 2 | stream connection | `sc = qs->connection` — a full-fledged `ngx_connection_t` with `sc->recv/send/send_chain` (L762-764), `sc->read/write->handler`, `sc->data` (= `qs`); in ssh3-c `s3_connection_t.recv/send_chain` already exists (`src/event/s3_connection.h:26-27`), the role of `qs` will be played by `data` |
| 3 | posted | ×7 (init_stream_handler, push) |
| 4 | rbtree | `qc->streams.tree` + `ngx_quic_rbtree_insert_stream` (L109) |
| 5 | flow control | `ngx_quic_control_flow/update_flow/update_max_stream_data/update_max_data` (L37-41) — the MAX_DATA/MAX_STREAM_DATA frames |
| 6 | delivery | `ngx_quic_handle_stream_frame` → `ngx_quic_write_buffer(c, &qs->recv, ...)` (L1295) → `ngx_quic_set_event(qs->connection->read)` (L1329) — the sample for DATAGRAM delivery (§3.4) |
| 7 | conf | `qc->conf->init` (L625), `stream_buffer_size`, `stream_close_code`, `stream_reject_code_uni/bidi` |
| 8 | classification | needs s3_context — the heaviest file: lifecycle + flow control + two buffers per stream |

### 1.10. `ngx_event_quic_migration.c` (1007) + `.h` (45)

| № | Dependency | Facts from the code |
|---|-------------|---------------|
| 1 | timers | `ngx_current_msec` ×8, `ngx_add_timer/del_timer` (path_validation) |
| 2 | address text | `ngx_sock_ntop` ×2 (L266, L442), `c->addr_text` ×3, `c->listening->addr_text_max_len` (L444), `path->addr_text/text` — ssh3-c has no sock_ntop: add `s3_sock_ntop` to `src/os/unix` or keep the text in the path |
| 3 | ngx_connection_t | `c->log` ×18, `c->log_error` ×3 (the logging level of MTU messages — replace with the constant `S3_LOG_INFO`), `c->sockaddr/socklen`, `c->udp`, `c->listening`, `c->pool` |
| 4 | output API | `ngx_quic_frame_sendto` (path challenge/response, MTU probes) |
| 5 | classification | needs s3_context; the path validation/MTU logic is self-contained |

### 1.11. `ngx_event_quic_socket.c` (237) + `.h` (28)

| № | Dependency | Facts from the code |
|---|-------------|---------------|
| 1 | listener rbtree | `ngx_rbtree_delete(&c->listening->rbtree, &qsock->udp.node)` ×2 (L107, L158), `ngx_rbtree_insert` (L183) — qsock nodes live in the listener rbtree |
| 2 | types | `ngx_udp_connection_t` (embedded into `ngx_quic_socket_t`, connection.h:137), `ngx_listening_t` |
| 3 | palloc | `ngx_pcalloc` ×2, `ngx_pnalloc` ×1 |
| 4 | ngx_connection_t | `c->pool/log/listening/udp/sockaddr/socklen` |
| 5 | classification | needs s3_context: `ngx_udp_connection_t`+`ls->rbtree` → the own node in `s3_udp_listen_t.rbtree` (§4.3) |

### 1.12. `ngx_event_quic_udp.c` (437)

| № | Dependency | Facts from the code |
|---|-------------|---------------|
| 1 | cycle | `ngx_enable_accept_events((ngx_cycle_t *) ngx_cycle)` (L45), `ecf = ngx_event_get_conf(ngx_cycle->conf_ctx, ngx_event_core_module)` (L52, multi_accept), `ngx_cycle->log` (L125), `ngx_accept_disabled = ngx_cycle->connection_n / 8 - ngx_cycle->free_connection_n` (L220-221) — none of this is portable, ssh3-c has a different model |
| 2 | connection accept | `ngx_get_connection` (L231), `c->number = ngx_atomic_fetch_add(...)` (L309), `c->start_time` (L315), `c->addr_text` + `ls->addr_ntop/addr_text_max_len` (L321-332), `c->shared/type/listening/buffer` |
| 3 | lookup | **the key = the packet DCID**, not sockaddr: `ngx_quic_get_packet_dcid` (L171, transport.c:509) → `ngx_quic_lookup_connection(ls, &key, ...)` (L415): rbtree by `ngx_crc32_long(key)` + `ngx_memn2cmp` against `qsock->sid.id`; a new connection → `ls->handler(c)` → `ngx_quic_run(c, conf)` (http/v3/ngx_http_v3_request.c:75) |
| 4 | cmsg | `NGX_HAVE_ADDRINFO_CMSG` — wildcard: the local address from cmsg (L137-158) |
| 5 | classification | needs s3_context; the recvmsg loop skeleton already exists in P1 (`s3_event_recvmsg`, `src/event/s3_event_udp.c`), but there the key is sockaddr; the QUIC version requires **a second key strategy (DCID)** — see §4.3 |

### 1.13. `ngx_event_quic_ssl.c` (996) + `.h` (19)

| № | Dependency | Facts from the code |
|---|-------------|---------------|
| 1 | ngx_ssl layer | `ngx_ssl_create_connection(qc->conf->ssl, c, 0)` (L914), `c->ssl->connection/no_wait_shutdown/handshaked`, `ngx_ssl_error` (the ALERT log with the OpenSSL error string), `ngx_ssl_connection_error` (L728) |
| 2 | OpenSSL QUIC API | the `NGX_QUIC_OPENSSL_API` branch (OpenSSL ≥3.5): `OSSL_DISPATCH qtdis[]` with `OSSL_FUNC_SSL_QUIC_TLS_{CRYPTO_SEND,CRYPTO_RECV_RCD,CRYPTO_RELEASE_RCD,YIELD_SECRET,GOT_TRANSPORT_PARAMS,ALERT}` (L868-890), `SSL_set_quic_tls_cbs` (L906), `SSL_set_quic_tls_early_data_enabled` (L913), `SSL_set_quic_tls_transport_params` (L974); common: `SSL_do_handshake` (L705), `SSL_get_error` (L710), `SSL_is_init_finished` (L738), `SSL_provide_quic_data` (L839), `SSL_get_peer_quic_transport_params` (L511), `SSL_get0_alpn_selected` (L88, L497), `SSL_get_current_cipher` (L225, L433), `SSL_CTX_get_max_early_data` (L911); the quictls/boringssl branches (`SSL_set_quic_method` L930 etc.) — **cut** |
| 3 | quic-internal | the `ctx->crypto` buffer (`ngx_quic_handle_crypto_frame`, the ssl.h header), `ngx_quic_create_transport_params` + `SSL_set_quic_tls_transport_params`, the sr_token (`ngx_quic_new_sr_token`), the ALPN check |
| 4 | classification | needs the ssl layer: `s3_ssl_t` (an SSL_CTX wrapper) + the per-connection SSL state (§4.4) |

### 1.14. `ngx_event_quic_openssl_compat.c` (657) + `.h` (52)

Emulation of the QUIC interface for BoringSSL/wolfSSL/OpenSSL < 3.5 (an own SSL handshake driver, the TP extension via `SSL_extension_supported`, key records). Not ported into ssh3-c: we don't define `NGX_QUIC_OPENSSL_COMPAT` (OpenSSL ≥3.5 — the decision is fixed in `docs/DEPS-QUIC.md` §6). The only config touch is `ngx_quic_compat_ext_init(ngx_conf_t *cf, SSL_CTX *ctx)` (L81).

### 1.15. `ngx_event_quic_bpf.c` (1257), `.h` (20), `ngx_event_quic_bpf_code.c` (212), `bpf/*`

SO_ATTACH_REUSEPORT_EBPF socket groups for worker balancing: `ngx_cycle_t` ×29 (`ngx_quic_bpf_get_conf(cycle)`, `cycle->old_cycle`, `ngx_get_conf(cycle->conf_ctx, ngx_core_module)` — L18-26), an own nginx module with a conf structure, `ngx_listening_t` ×26, bpf syscalls. Depends entirely on the cycle/conf infrastructure. Not ported in P2; if desired later — an own mechanism on top of `s3_udp_listen_t` (a separate task, blocks nothing).

### 1.16. `ngx_event_quic_connection.h` (329) — the central header

Collects all quic headers (L40-50); the structures `ngx_quic_connection_t` (L225-312), `ngx_quic_send_ctx_t` (L200-222: the `frames/sending/sent` queues, ACK ranges, the crypto buffer), `ngx_quic_socket_t` (L136: embeds `ngx_udp_connection_t`), `ngx_quic_path_t` (L111), `ngx_quic_client_id_t/server_id_t`, `ngx_quic_streams_t` (L147: an rbtree + flow control counters/limits), `ngx_quic_congestion_t` (L177). The macros `ngx_quic_get_connection(c)` (L73: `(c)->udp` → socket → quic) and `ngx_quic_get_send_ctx` (L68). Rewritten to s3 types (see §4); the DATAGRAM fields are also added here (§3.5).

---

## 2. Recommended porting order

Topological: «clean» files → the ssl layer → the core → the network → streams → DATAGRAM. What P0/P1 already covers: pool/palloc (`s3_palloc*`), buf/chain/shadow (except `num`), rbtree/queue, log (`s3_log_*` + the `S3_LOG_*` levels in `s3_base.h:39-55`), string (`s3_str_t`, `s3_memcpy/cpymem/memzero`), the event ctx with epoll + timers + posted (`s3_event.h`), `s3_connection_t` with `recv`/`send_chain`, `s3_udp_sendmsg_chain` + `s3_sendmsg`, recvmsg + pseudo-connections.

| № | Increment | Contents | What must be ready |
|---|-----------|------------|------------------------|
| 1 | **D1: parser/crypto foundation** | `s3_quic_transport` (transport.c/.h), `s3_quic_frames` (frames.c/.h), `s3_quic_protection` (protection.c/.h), `s3_quic_tokens` (tokens.c/.h), `s3_quic_connid` (connid.c/.h) — «clean» files, ported by type substitution | P0/P1 — everything is there. One base change: the `num` (refcount) field in `s3_buf_t` (`src/core/s3_buf.h:16`); in CMake `find_package(OpenSSL 3.5 REQUIRED)` |
| 2 | **D2: ssl layer + QUIC core** | `s3_ssl` (an SSL_CTX/SSL wrapper), `s3_quic_ssl.c` (only the OpenSSL-API branch), `s3_quic.c` + `s3_quic_connection.h` + `s3_quic.h` (conf/structures/orchestration) | posted/timers in `s3_event_ctx_t` (present); `s3_connection_t.buffer` (the datagram buffer) and the `ssl` field — add; SHA1 — via libcrypto; lifecycle simplifications (§4.3) |
| 3 | **D3: network and reliability** | `s3_quic_output.c` (GSO/segments/padding/retry/stateless reset), `s3_quic_ack.c` (loss/congestion/PTO), the os helpers `s3_get_srcaddr_cmsg`/`s3_set_srcaddr_cmsg`, integration with `s3_udp_listen_t` (the DCID lookup instead of `ngx_event_quic_udp.c`) | `s3_sendmsg` (present), `s3_udp_listen_t.rbtree` (present, extend, §4.3); the decision on `addr_text` |
| 4 | **D4: streams and migration** | `s3_quic_streams.c` (flow control, open/close/reset/shutdown stream), `s3_quic_migration.c` (path validation, MTU discovery), idle-timeout | pool cleanup (`s3_pool_cleanup_t` is present), `s3_get_connection/s3_close_connection` (present), `s3_sock_ntop` (add) |
| 5 | **D5: DATAGRAM (RFC 9221)** | our own code on top of D1–D4 (§3) | the whole transport; the interop goal of the P2 phase |

Reverse dependencies to keep in mind: protection.h/frames.h need transport.h (the frame types), transport.c needs quic.h (`ngx_quic_conf_t`) — therefore `s3_quic.h` with the conf is ported in D1 (as a header) or the qcf fields are replaced by `s3_quic_conf_t` right away.

The entry contract: a listening UDP socket P1 → datagram → the QUIC lookup by DCID → new: `s3_quic_run(c, conf)` (an analog of `ngx_quic_run`, ngx_event_quic.c:201) → the application receives streams via `conf->init` and the stream handler.

---

## 3. DATAGRAM (RFC 9221) — the increment plan

nginx QUIC has no DATAGRAM. All integration points are determined from the code:

### 3.1. Transport parameter 0x0020 (max_datagram_frame_size)

| № | File | Location | Change |
|---|------|-------|--------|
| 1 | `ngx_event_quic_transport.h` | TP constants L117-133 | `#define NGX_QUIC_TP_MAX_DATAGRAM_FRAME_SIZE 0x20` |
| 2 | `ngx_event_quic_transport.h` | `ngx_quic_tp_t` L344-366 | the field `uint64_t max_datagram_frame_size;` |
| 3 | `ngx_event_quic_transport.c` | `ngx_quic_parse_transport_param` L1619 (the varint case branches L1638-1712) | case: varint → `tp->max_datagram_frame_size` (following the pattern of `NGX_QUIC_TP_MAX_IDLE_TIMEOUT` L1638/1668) |
| 4 | `ngx_event_quic_transport.c` | `ngx_quic_parse_transport_params` L1725 (the loop L1737-1766) | nothing: the id mask skips the server TPs — 0x0020 falls into the varint branch |
| 5 | `ngx_event_quic_transport.c` | `ngx_quic_init_transport_params` L1986 | fill from `s3_quic_conf_t.max_datagram_frame_size` (if 0 — DATAGRAM is disabled: we don't encode the TP) |
| 6 | `ngx_event_quic_transport.c` | `ngx_quic_create_transport_params` L2030 | TLV encoding: varint id 0x20 + varint value (following the pattern of the neighboring TPs) |
| 7 | `s3_quic.h` (ours) | the analog of `ngx_quic_conf_t` L80-102 | the field `ngx_uint_t max_datagram_frame_size;` (e.g. 1200…IPv6-MTU-6) |

### 3.2. Frames 0x30/0x31 (DATAGRAM, DATAGRAM_WITH_LENGTH)

| № | File | Location | Change |
|---|------|-------|--------|
| 1 | `ngx_event_quic_transport.h` | FT constants L58-90 | `#define NGX_QUIC_FT_DATAGRAM 0x30`, `#define NGX_QUIC_FT_DATAGRAM_WITH_LENGTH 0x31`; **mandatory** to raise `NGX_QUIC_FT_LAST` (L90) from `0x1E` to `0x31` — otherwise the varint bound `if (varint > NGX_QUIC_FT_LAST)` (transport.c:764) will discard the frame as unknown |
| 2 | `ngx_event_quic_transport.h` | the union `ngx_quic_frame_s.u` L277-296 | `ngx_quic_datagram_frame_t { uint64_t length; }` (0x30: length = the rest of the packet; 0x31: varint) |
| 3 | `ngx_event_quic_transport.c` | `ngx_quic_parse_frame` L744 (the switch L780-1158) | two cases: 0x30 — payload = `[pos, end)`, the length from the bounds; 0x31 — a varint length + a bounds-check; the data is put into `frame->data` (`ngx_quic_copy_bytes` L214) without offset/reassembly |
| 4 | `ngx_event_quic_transport.c` | `ngx_quic_frame_allowed` L1161, the mask table L1173-1204 | two entries `/* DATAGRAM */ 0x1` — 1-RTT only (RFC 9221 §4: the frame is forbidden in Initial/Handshake/0-RTT) |
| 5 | `ngx_event_quic_transport.c` | `ngx_quic_create_frame` L1281 | `f->need_ack = 0` for both types (following the pattern of ACK L1296 / CONNECTION_CLOSE L1319); the create helper `ngx_quic_create_datagram` (0x31 — with a varint length) |
| 6 | `ngx_event_quic.c` | `ngx_quic_handle_frames` L1176 (the switch L1221-1360) | case → a new handler `ngx_quic_handle_datagram_frame` (our code, §3.4) |

### 3.3. send_ctx, queues, ACK/PTO — where the «no retransmission» rule is already enforced structurally

| № | File | Location | Fact |
|---|------|-------|------|
| 1 | `ngx_event_quic_output.c` | `ngx_quic_commit_send` L203, L228-233 | a frame with `pkt_need_ack==0` after sending is **released immediately**: it does not get into `ctx->sent`, is not counted in `cg->in_flight` → no ACK accounting, no loss retransmission (`ngx_quic_detect_lost` L594 walks only over `ctx->sent`), no resend (`ngx_quic_resend_frames` L758 is called only for crypto spaces, ack.c:663). A DATAGRAM with `need_ack=0` inherits all this automatically — no separate code is needed |
| 2 | `ngx_event_quic_ack.c` | `ngx_quic_pto_handler` L1103 | the PTO sends only PING — a DATAGRAM retransmission does not arise |
| 3 | queues | `ctx->frames`/`sending` (connection.h:210-212) | DATAGRAM lives in the application space `send_ctx[2]`, a separate send_ctx is not needed |
| 4 | risk | `ngx_quic_create_segments`/`allow_segmentation` L336/L253 | the GSO segmentation computes `cg->in_flight + (p - dst) < cg->window` (L411) for all frames; DATAGRAM must not be blocked by a full CWND from non-ack traffic — check during the bench (§3.5) |

### 3.4. Delivery to the application (sending and receiving)

| № | Direction | Entry point | Implementation |
|---|-------------|-------------|------------|
| 1 | receiving | `ngx_quic_handle_datagram_frame` (new, called from ngx_event_quic.c:1176) | payload (the `frame.data` chain, `u.datagram.length`) → callback `conf->datagram_handler(c, data)` — a new field of `s3_quic_conf_t`. **Zero-copy (2026-10-03)**: the parser chain is passed as is, without flattening — the handler decides itself whether to copy. The chain points to the static decryption buffer (`pkt->plaintext`, as in nginx) and is valid only for the duration of the call. Without `ngx_quic_buffer_t`: DATAGRAM is not ordered and not reassembled (a frame ≤ MTU). A sample of the result — streams.c:1295-1329, but without the buffer and `set_event` |
| 2 | sending | a new public API `s3_quic_send_datagram(c, data, len)` (an analog of `ngx_quic_reset_stream` in quic.h:137) | `ngx_quic_alloc_frame` (frames.c:197) + `u.datagram` + `frame->data` = `ngx_quic_copy_buffer` (frames.c:393) + `ngx_quic_queue_frame` (frames.c:299) → it will go out through the ordinary `ngx_quic_output`; the size is limited to `min(TP_peer.max_datagram_frame_size, path->mtu - header)` — the check at enqueue time |
| 3 | cancel/closing | `ngx_quic_close_connection`/`discard_ctx` (ngx_event_quic.c:470/1096) | nothing: non-ack frames are released like the others |

### 3.5. DATAGRAM flow control and risks

| № | Item | Decision |
|---|-------|---------|
| 1 | Transport flow control | RFC 9221 **does not define** flow control for DATAGRAM (no MAX_DATAGRAM_DATA frames). The only transport limit — `max_datagram_frame_size` (the frame size) + the congestion window. The receiver limit — our addition |
| 2 | Sending | the counter `qc->datagrams_in_flight` (our field in `ngx_quic_connection_t`, connection.h:225-312) with a decrement by the PTO timer/ACKs of neighbors — or honest accounting in `cg->in_flight` with a manual return. The minimum for P2: a limit on the number of DATAGRAMs per one push (`qc->push`) and respecting CWND by the space in `dst` |
| 3 | Receiving | a per-connection queue limit in the ssh3 layer (the policy: drop + a counter, not CONNECTION_CLOSE — datagrams are allowed to be lost) |
| 4 | PTO/retransmission | forbidden by RFC 9221 §5; enforced structurally via `need_ack=0` (§3.3) — **do not** put DATAGRAM into the `ctx->sent` queue |
| 5 | Risk: quic-go | verify that the quic-go server/client sees the TP 0x0020 before the first frame; the client TP — before handshake-complete |
| 6 | Risk: MTU | 0x30 without a length requires `length = end - pos` — in a GSO segment (`ngx_quic_create_segments`) the frame must not be cut: `ngx_quic_split_frame` (frames.c:319) must not be applied to DATAGRAM (exclude by type) |
| 7 | Code isolation | everything DATAGRAM-specific goes into `s3_quic_transport.c` (parse/create), `s3_quic.c` (handler), `s3_quic.h` (conf/API); parser fuzzing starting with P2 (`PLAN.md` §4, P6) |

---

## 4. Replacements during porting (nginx → ssh3-c)

### 4.1. `ngx_cycle_t` / globals → `s3_event_ctx_t`

The actual set of cycle reads from the quic code is small:

| № | nginx | Reads | Replacement in ssh3-c |
|---|-------|--------|-----------------|
| 1 | `ngx_posted_events` (a global queue) | quic.c ×5, ack.c ×5, frames.c ×1, streams.c ×7 | `ctx->posted_events` + `s3_post_event`/`s3_event_process_posted` (`src/event/s3_event.h:126-138`); the `ngx_quic_process_posted` calls (streams.c:231) receive `ctx` |
| 2 | `ngx_add_timer/del_timer` (a global rbtree) | quic.c, ack.c, output.c, streams.c, migration.c | `s3_event_add_timer/del_timer` (`s3_event.h:123-124`) — the signatures match |
| 3 | `ngx_current_msec` | ack.c ×13, quic.c, migration.c, output.c | `s3_current_msec` (`s3_event.h:106`) |
| 4 | `ngx_cycle->log` (udp.c:125) | the recvmsg log | `lc->log` (present in the P1 version) |
| 5 | `ngx_cycle->connection_n/free_connection_n` + `ngx_accept_disabled` (udp.c:220-221) | accept-throttling | not portable: limit policies are the business of the ssh3 application; alternatively a counter in `s3_event_ctx_t` if necessary |
| 6 | `ngx_event_get_conf(cycle->conf_ctx, ngx_event_core_module)` (udp.c:52) | multi_accept | not needed: `s3_event_recvmsg` reads until EAGAIN |
| 7 | `ngx_enable_accept_events` (udp.c:45) | reactivation after timedout | not needed: P1 does not disable the listener |
| 8 | `ngx_cycle->conf_ctx` (bpf) | the bpf module | not portable (§1.15) |

Extending `s3_event_ctx_t` for QUIC is **not required** — the QUIC conf is passed via `s3_quic_run(c, conf)` and stored in `qc->conf`. If a global is more convenient — a `void *quic_conf` field, but explicit passing is cleaner.

### 4.2. `ngx_quic_conf_t` (ngx_event_quic.h:80-102) → `s3_quic_conf_t`

The fields actually read by the code (grep `qc->conf->`, `qcf->`):

| № | nginx field | Who reads | ssh3-c |
|---|------------|-----------|--------|
| 1 | `ssl` (ngx_ssl_t*) | ssl.c:914 | `s3_ssl_t *ssl` (§4.4) |
| 2 | `retry` | ssl.c (the stateless retry branch) | `unsigned retry : 1` |
| 3 | `gso_enabled` | output.c:289 | `unsigned gso_enabled : 1` |
| 4 | `disable_active_migration` | transport.c:1986 (TP 0x0C) | the same |
| 5 | `handshake_timeout` | quic.c (the close timer) | `s3_msec_t` |
| 6 | `idle_timeout` | transport.c:1986 (TP 0x01) | `s3_msec_t` |
| 7 | `host_key` | the http/v3 module (generation of the av/sr keys) | `s3_str_t host_key` + a generator in our code (nginx generates in `ngx_http_v3_module.c:310-372`, not in quic/) |
| 8 | `stream_buffer_size` | transport.c:1986 (TP initial_max_stream_data), streams.c | `size_t` |
| 9 | `max_concurrent_streams_bidi/uni` | transport.c:1986 | `s3_uint_t` |
| 10 | `active_connection_id_limit` | transport.c:1986 (TP 0x0E) | `s3_uint_t` |
| 11 | `stream_close_code`, `stream_reject_code_uni`, `stream_reject_code_bidi` | streams.c (reject/close) | `s3_int_t` |
| 12 | `init` (`ngx_quic_init_pt`) | streams.c:625 (the hook «streams ready») | `s3_quic_init_pt` |
| 13 | `shutdown` (`ngx_quic_shutdown_pt`) | quic.c | `s3_quic_shutdown_pt` |
| 14 | `av_token_key[32]`, `sr_token_key[32]` | output.c (stateless reset), ssl.c:956 (the sr_token), tokens.c | `u_char` arrays (filled by our code from `host_key`) |
| 15 | **new (DATAGRAM)** | — | `s3_uint_t max_datagram_frame_size; s3_quic_datagram_pt datagram_handler;` |

nginx directives (`quic_retry`, `quic_gso` etc.) are absent in quic/ — the http/v3 module parses them; ssh3-c fills `s3_quic_conf_t` from its own configurator (CLI/file), no directive parser needs to be written.

### 4.3. `ngx_connection_t` → `s3_connection_t`

The fields that the QUIC code actually reads/writes (a grep `c->` summary across all files):

| № | nginx field | Present in `s3_connection_t`? | Action |
|---|------------|---------------------------|----------|
| 1 | `log`, `read`, `write`, `fd`, `pool`, `sockaddr`, `socklen`, `local_sockaddr`, `local_socklen`, `sent` | yes (`s3_connection.h:18-46`) | unchanged |
| 2 | `data` | yes | for a stream-connection, `ngx_quic_stream_t` lives here (instead of the nginx field `sc->quic`) |
| 3 | `udp` | yes, but a different type: `struct s3_udp_connection_s *` | in nginx `c->udp` → `ngx_quic_socket_t` (the macro `ngx_quic_get_socket`, connection.h:76); in ssh3-c — a P1 node. Rewrite: `ngx_quic_socket_t` embeds `ngx_udp_connection_t{node, connection}` + a `quic` pointer + `sid` + `sockaddr` → make `s3_quic_socket_t` with `s3_rbtree_node_t node; s3_connection_t *connection; s3_quic_connection_t *quic; s3_quic_server_id_t sid;` and register it in `s3_udp_listen_t.rbtree` instead of the P1 node |
| 4 | `buffer` | no | add `s3_buf_t *buffer` — the input datagram (`ngx_quic_run` → `ngx_quic_handle_datagram(c, c->buffer, conf)`, ngx_event_quic.c:208; `c->udp->buffer` for the repeats, udp.c:222) |
| 5 | `ssl` | no | `s3_ssl_conn_t *ssl` (§4.4) — the handshake state + `handshaked` |
| 6 | `listening` | no | read for `rbtree` (socket.c:107/158/183), `wildcard` (output.c:446), `addr_text_max_len` (migration.c:444), `handler` (streams.c:574) → replacement: the QUIC socket has direct links (`s3_udp_listen_t *listen`), the application handler — in `s3_quic_conf_t` |
| 7 | `addr_text` | no | migration.c/udp.c — logging. Option: `u_char addr_text[S3_SOCKADDR_STRLEN]` in `s3_quic_path_t` (it already has `text/addr_text`, connection.h:129-130) and in the log config; alternatively add a field to the connection |
| 8 | `number`, `start_time` | no | only logs/statistics — drop or `uint64_t number` |
| 9 | `reusable`, `idle`, `destroyed`, `close`, `type`, `log_error` | no | the nginx worker lifecycle: `ngx_reusable_connection` ×6 (streams.c/quic.c) is replaced by a flag in `s3_quic_connection_t` (accounted in the shutdown condition `can_shutdown`); `log_error` → a constant level |
| 10 | `shared` | yes | ok |

### 4.4. `ngx_ssl_t` / `ngx_ssl_connection_t` → `s3_ssl_t` / `s3_ssl_conn_t`

ssl.c requires a minimum from the ssl layer (by calls):

| № | ssl.c function | What is needed in ssh3-c |
|---|---------------|---------------------|
| 1 | `ngx_ssl_create_connection(qc->conf->ssl, c, 0)` (L914) | `s3_ssl_t` = a holder of `SSL_CTX*` (+ the ALPN protocol, cert/key); `s3_ssl_conn_t` = `SSL *connection; unsigned handshaked:1; unsigned no_wait_shutdown:1;` + a binding to `s3_connection_t` |
| 2 | `SSL_set_quic_tls_cbs(ssl_conn, qtdis, c)` (L906) | OpenSSL ≥3.5: an `OSSL_DISPATCH` table with six callbacks (`OSSL_FUNC_SSL_QUIC_TLS_*`, L868-890) — the quic.c/ssl.c callbacks implement them via the `ctx->crypto` buffer and `ngx_quic_keys_*` |
| 3 | `SSL_set_quic_tls_transport_params` (L974), `SSL_get_peer_quic_transport_params` (L511) | without wrappers, a direct call |
| 4 | `SSL_do_handshake` (L705) + `SSL_get_error` (L710) + `SSL_is_init_finished` (L738) | a non-blocking handshake loop, `SSL_ERROR_WANT_READ/WRITE` → waiting for CRYPTO |
| 5 | `SSL_provide_quic_data` (L839) | feeding the `ctx->crypto` buffer level by level |
| 6 | `SSL_get0_alpn_selected` (L88/497) | the ALPN check of the ssh3 protocol |
| 7 | `SSL_get_current_cipher` (L225/433) | choosing the HP/AEAD parameters (ours are fixed in protection.c) |
| 8 | `SSL_CTX_get_max_early_data` (L911) + `SSL_set_quic_tls_early_data_enabled` (L913) | 0-RTT |
| 9 | `ngx_ssl_error` / `ngx_ssl_connection_error` | our own `s3_ssl_error(log, ...)` based on `ERR_get_error`/`ERR_error_string_n` |

The branch macros `NGX_QUIC_QUICTLS_API`/`NGX_QUIC_BORINGSSL_API`/`NGX_QUIC_OPENSSL_COMPAT` (ngx_event_quic.h:15-28) — keep only `NGX_QUIC_OPENSSL_API` (the CMake requirement: OpenSSL ≥3.5, see `docs/DEPS-QUIC.md` §7).

### 4.5. Other replacements

| № | nginx | ssh3-c |
|---|-------|--------|
| 1 | the `ngx_buf_t.shadow->num` refcount (frames.c:15) | add `int num;` to `s3_buf_t` (`src/core/s3_buf.h`) — the only P0-base change |
| 2 | `ngx_sendmsg(c, &msg, 0)` | `s3_sendmsg` (already present, `src/os/unix/s3_udp_sendmsg_chain.h:30`) |
| 3 | `ngx_get_srcaddr_cmsg` / `ngx_set_srcaddr_cmsg` (IP_PKTINFO/IPV6_RECVPKTINFO) | add to `src/os/unix/` (used by recvmsg-wildcard and GSO sending) |
| 4 | `ngx_sha1_*` (quic.c:1478 address-hash) | OpenSSL `SHA1()` from libcrypto (or porting `ngx_sha1.c` — a single file, BSD) |
| 5 | `RAND_bytes` | a direct call (libcrypto) — already so in nginx |
| 6 | `ngx_sock_ntop` | a new `s3_sock_ntop` in `src/os/unix` (needed by migration.c, udp.c) |
| 7 | `ngx_atomic_fetch_add` (udp.c:309 connection counter) | drop/replace with a regular `++` (a single-threaded event loop) |
| 8 | `ngx_crc32_long` + `ngx_memn2cmp` (udp.c:401/419 DCID-lookup) | `s3_crc32_long`/comparison — add to core or compare bytes with an rbtree comparator (the P1 model `s3_udp_key_cmp` changes to a sid comparison) |
| 9 | `ngx_socket_errno`, `NGX_EAGAIN` | `s3_socket_errno`, `S3_EAGAIN` (present, `src/os/unix/s3_errno.h`) |
| 10 | `c->log->action = "..."` (quic.c ×10, quic_ssl.c) | the simplified `s3_log_t` has no action — drop the lines or add `const char *action` to `s3_log_t` (decide in D2) |
| 11 | `NGX_HAVE_UDP_SEGMENT`/`NGX_HAVE_MSGHDR_MSG_CONTROL`/`NGX_HAVE_ADDRINFO_CMSG` | CMake feature tests (an analog of nginx auto/feature) → `S3_HAVE_*` |
| 12 | the prefixes `ngx_quic_*` → `s3_quic_*`, `NGX_QUIC_*` → `S3_QUIC_*` | a mechanical replacement, except the RFC constant names (TP/FT/ERR can be kept as `S3_QUIC_TP_*`…) |

### 4.6. Differences from nginx that appeared in D3 (the client role)

nginx is a server only, therefore four places in the ported code are «hardwired» for the server role and require an explicit change as soon as a client appears:

| № | Place | nginx | ssh3-c |
|---|-------|--------|--------|
| 1 | the key slots, `s3_quic_keys_set_encryption_secret()` / `s3_quic_keys_available()` | `is_write` = 1 → the server slot (there is no client one) | `is_write` — the TLS direction: the slot is selected as `is_write == keys->is_client`; otherwise the client reads the server secrets and vice versa |
| 2 | `s3_quic_keys_set_initial_secret()` / `s3_quic_keys_update()` | the client slot is always on reading, the server one on writing | the direction of `enc` is derived from `keys->is_client` |
| 3 | `HANDSHAKE_DONE` (0x1e) | the allowed frames table forbids the frame for all packet types: the server doesn't receive it | the client accepts it exactly once in 1-RTT, confirms the handshake and drops the handshake keys (`handshake_confirmed`) |
| 4 | `CRYPTO` after the handshake | rejected always | rejected by the server only; the client accepts the `NewSessionTicket` and runs `SSL_do_handshake()` in `s3_quic_post_handshake()` |
| 5 | the `direction` flag in `s3_quic_cbs_yield_secret()` | nginx passes `direction` to the kdf as is: **1 = write, 0 = read** | in D3 the inversion `!direction` gave a consistent, but mirrored C↔C — interop with quic-go exposed it; fixed to the nginx semantics, C↔C remained green |
| 6 | `NEW_TOKEN` (0x07) | mask 0x0: the server doesn't receive it | the client accepts it in 1-RTT, the token is parsed and dropped (address validation — D4) |
| 7 | `ngx_quic_open_stream()` | two branches: client- and server-initiated ids | only the server branch made it into the D4 port — the client opened id=1 (server uni) and got STREAM_STATE_ERROR from quic-go; the client branch was restored |
| 8 | `ngx_quic_handle_max_stream_data_frame()` | `ngx_quic_set_event(wev)` wakes the application writer | the port called only flush(); set_event(wev) was restored — otherwise the application doesn't learn about the window opening |
| 9 | reading the stream by the application | http3 arms `rev->active` via `ngx_handle_read_event()` and reads right in the accept path | `s3_quic_set_event()` posts only if `active`; ssh3 applications must arm active and do the first read in the stream_handler (see interop_server.c) |
| 10 | `ngx_queue_init(&qc->streams.uninitialized)` in new_connection | present | was missed in the D2 skeleton — the first init_streams call went over an uninitialized queue (UBSan: offset to null) |
| 11 | the listener backlink | nginx keeps the listener in connection fields (`c->listening`), `c->data` is free for the application | D3 set `c->data = ul` after registering the primary sockets; NEW_CONNECTION_IDs issued later were not registered in the listener rbtree → stateless reset on client CID rotation; the backlink started to live for the whole connection lifetime — but in `c->data`, which collided with the h3 session (P3): on the server `s3_h3_get_session()` read the stack address of `main()` and `init_session` was silently skipped → «stream already created» → a dangling posted-event on a destroyed pool → SEGV in `s3_event_process_posted`. Now the backlink at `open_sockets()` is moved into `qc->listen` (a field of the quic connection), `c->data` is free again for the owner of the connection (the h3 session), `s3_quic_listen()` reads `qc->listen` |
| 12 | `c->udp` = the socket of the current packet | delivery sets it per-packet | lookup returned only the connection; RETIRE_CONNECTION_ID compared seq with someone else's socket → PROTOCOL_VIOLATION on CID rotation; lookup now sets `c->udp` |
| 13 | `set_path()`, the first datagram of the path | the marker `c->udp->buffer == NULL` | the sign `qsock->socklen == 0`: shared_recv consumes the buffer, the per-datagram address is set only by `s3_quic_deliver()`; `NGX_DONE`→`S3_ABORT` |
| 14 | EMSGSIZE in an MTU probe | `c->write->error` / `c->log_error` | `s3_socket_errno == S3_EMSGSIZE`: send() (output.c) does not set the flag |
| 15 | `handle_max_stream_data` wakes the writer | `ngx_quic_set_event(wev)` | the port called only flush(); restored (see also item 8) |
| 16 | `handle_path_mtu` → MTU growth | a call from the ack loop (ack.c:248) | ported, but NOT wired in (ack.c is an optimization zone); probes go out and safely expire, MTU remains the starting one — one line later |
| 17 | the uni-stream states in `create_stream()` | reference is server-only: the peer's uni id is always a client one | in ssh3-c both roles open uni (h3 control/encoder/decoder): the direction is derived from `s3_quic_stream_is_own_uni()` — own: send-only (SEND_READY), peer's: read-only (RECV_RECV); mirrored to item 7 for `open_stream()` |
| 18 | the h3 session and early uni-streams | `ngx_http_v3_init()` creates a session on the first stream (including uni) | interop ports must do the same lazy `s3_h3_init_session()` in the stream handler before routing: quic-go opens the control stream right after the handshake, before the handshake event loop; without the guard the client read a NULL session (UBSan: member access within null) |

Separately: the short header does not carry the DCID length, so the parser reads exactly `S3_QUIC_SERVER_CID_LEN` bytes, and the client must generate a CID of the same length (otherwise the protection sample offset diverges for header protection — symptom: a TX offset of 21 vs RX 25).

## 5. Interop stand (quic-go)

| № | Component | Where |
|---|-----------|-----|
| 1 | the Go harness (server/client, DATAGRAM echo) | `interop/quic-go` (quic-go v0.63.0 — as in the Go fork) |
| 2 | the C runners: `s3interop_server`, `s3interop_client` | `interop/interop_server.c`, `interop/interop_client.c` |
| 3 | the PASS/FAIL matrix | `interop/run-quic-go.sh` (loopback, certs in `build/interop/`) |
| 4 | the TLS secrets of both sides for debugging | `S3_KEYLOG=1` (C, an NSS keylog on stderr), `-keylog file` (the harness) |

The result of 2026-10-02: both directions PASS (handshake + 8/8 DATAGRAM). Under `tc netem loss 5%` the handshake survives; the DATAGRAM phases lose some datagrams — this is the RFC 9221 semantics (unreliable, no retransmission), acceptance by losses must count «N of M passed + the connection is alive», not «all to the one».

---

## 5. Volume estimation

Lines (wc -l of the reference, total 17538, including bpf 1489):

| № | Class | Files | Lines (.c+.h) | Share |
|---|-------|-------|---------------|------|
| 1 | «Clean» (D1) | transport, frames, protection, tokens, connid | 5768 | 33 % |
| 2 | s3_context (D2–D4) | quic.c, ack.c, streams.c, migration.c, socket.c, connection.h, quic.h | 7112 | 41 % |
| 3 | s3_context + os (D3) | output.c, udp.c | 1882 | 11 % |
| 4 | the ssl layer (D2) | ssl.c/.h | 1015 | 6 % |
| 5 | Not ported | openssl_compat, bpf (.c/.h/code) | 2198 | 12 % |

Total adaptation: **≈ 15.3k lines** (85 % of the reference), of which one third is mechanical type substitution; plus the DATAGRAM add-on ≈ 400–600 lines of our code (§3) and os helpers ≈ 150 lines.

The P2 breakdown by sessions (the P0/P1 experience: an increment ≈ 1–2 sessions with tests):

| № | Increment | Sessions | Acceptance criterion |
|---|-----------|--------|------------------|
| 1 | D1 parser/crypto | 1–2 | unit tests: the varint/frames roundtrip; the HKDF/AEAD vectors of RFC 9001; the TP parse/create roundtrip; `ctest` release+asan clean |
| 2 | D2 ssl+core | 2–3 | a QUIC handshake C-client ↔ quic-go (Initial+Handshake+1-RTT), the keys switch, the TPs exchanged |
| 3 | D3 network/reliability | 2–3 | bulk 1 GiB loopback ≥ 250 MB/s (`PLAN.md` P2); 5 % packet loss — the connection survives (loss recovery); a GSO on/off comparison |
| 4 | D4 streams/migration | 2–3 | a stream echo quic-go ↔ C in both directions; flow control is blocked/expanded (MAX_DATA); an address change → path validation; idle-timeout |
| 5 | D5 DATAGRAM | 1–2 | a datagram roundtrip Go ↔ C (the interop of `PLAN.md` P2); the TP 0x0020 is visible to both sides; the frame 0x31 in Initial is rejected; a DATAGRAM retransmission is absent (the check by the pnum log) |
| — | **Total P2** | **8–13** | finally: ASan/UBSan clean, the parser fuzzing launched, the `memory_save` finalizations |

The largest volume risks: `ngx_event_quic_streams.c` (1824 lines — lifecycle + flow control, the densest integration with the connection lifecycle), `ngx_event_quic_transport.c` (2215 — but ported easily), and udp.c/socket.c — a rethink under the P1 rbtree model (a unique work, not a type substitution).
