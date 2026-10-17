# ssh3-c: Portierungskarte der QUIC-Schicht von nginx (Phase P2)
> Languages: [RU](PORTING-nginx-quic.md) · [EN](PORTING-nginx-quic.en.md) · DE (this file)

Datum: 2026-10-01. Referenz: `C:\Git\temp\ssh3-c\refs\nginx\src\event\quic\` (nginx 1.31.7, read-only).
Basis ssh3-c: P0 (`src/core`: `s3_pool_t`/`s3_buf_t`/`s3_chain_t`/`s3_rbtree_t`/`s3_queue_t`/`s3_log_t`/`s3_str_t`) und P1 (`src/event`: `s3_event_ctx_t` + epoll, Timer-rbtree, posted events, `s3_connection_t` mit `recv`/`send_chain`, UDP-Pseudo-Verbindungen `s3_udp_listen_t` + `s3_event_recvmsg`/`s3_udp_shared_recv`; `src/os/unix`: `s3_udp_sendmsg_chain`, `s3_sendmsg`, `s3_udp_recv`) — beide Phasen abgeschlossen (siehe `docs/PLAN.md` §7).

Lizenz: alle adaptierten Dateien behalten `Copyright (C) Nginx, Inc.` und ergänzen `Copyright (C) 2026 the ssh3-c authors` (BSD-2, Verpflichtungen in `docs/DEPS-QUIC.md` §6 und `THIRD-PARTY-NOTICES.md`).

Zielablage: `src/event/quic/s3_quic_*.c|h` (Präfix `s3_`, Stil des Projekts).

---

## 1. Abhängigkeitskarte der Dateien in `src/event/quic/`

Übersicht (Zeilen .c+.h, Klassifikation — dominierend; Details unten):

| Nr. | Datei | Zeilen | Klassifikation |
|---|------|-------|---------------|
| 1 | `ngx_event_quic_transport.c/.h` | 2215+398 | rein (Typenersetzung) |
| 2 | `ngx_event_quic_frames.c/.h` | 895+45 | rein (Typenersetzung + `num` in `s3_buf_t`) |
| 3 | `ngx_event_quic_protection.c/.h` | 1268+118 | rein (libcrypto) |
| 4 | `ngx_event_quic_tokens.c/.h` | 265+34 | rein (libcrypto) |
| 5 | `ngx_event_quic_connid.c/.h` | 501+29 | rein (guard BPF) |
| 6 | `ngx_event_quic_output.c/.h` | 1405+40 | benötigt s3_context + os-Helper |
| 7 | `ngx_event_quic_ack.c/.h` | 1456+31 | benötigt s3_context (leicht) |
| 8 | `ngx_event_quic.c` + `.h` | 1523+151 | benötigt s3_context (zentral) |
| 9 | `ngx_event_quic_streams.c/.h` | 1824+44 | benötigt s3_context (schwer) |
| 10 | `ngx_event_quic_migration.c/.h` | 1007+45 | benötigt s3_context |
| 11 | `ngx_event_quic_socket.c/.h` | 237+28 | benötigt s3_context (rbtree des listeners) |
| 12 | `ngx_event_quic_udp.c` | 437 | benötigt s3_context (Ersetzung durch die P1-schicht) |
| 13 | `ngx_event_quic_ssl.c/.h` | 996+19 | benötigt die ssl-schicht |
| 14 | `ngx_event_quic_connection.h` | 329 | benötigt s3_context (typen umschreiben) |
| 15 | `ngx_event_quic_openssl_compat.c/.h` | 657+52 | wird nicht portiert |
| 16 | `ngx_event_quic_bpf.c/.h`, `ngx_event_quic_bpf_code.c`, `bpf/*` | 1257+20+212+3 | wird in P2 nicht portiert |

Die detaillierten Abhängigkeiten — nach dem echten Code (grep include/aufrufe, die Zeilennummern der Referenz):

### 1.1. `ngx_event_quic_transport.c` (2215) + `.h` (398)

| Nr. | Abhängigkeit | Fakten zum Code |
|---|-------------|---------------|
| 1 | ngx_core-typen | `ngx_str_t` (TP dcid/scid/retry, `pkt->token`), `ngx_buf_t` (`pkt->raw`), `ngx_chain_t` (`frame->data`), `ngx_queue_t` (`frame->queue`), `ngx_msec_t`, `ngx_uint_t`, `ngx_log_t` |
| 2 | ngx_conf | nein |
| 3 | ngx_connection_t | nein (nur `ngx_quic_header_t` und `frame`, `c->log` wird nicht benutzt — das log kommt aus `pkt->log`) |
| 4 | event/timers/posted | nein |
| 5 | ngx_log | `ngx_log_error/debug0..2` in der ganzen datei; `log->action` wird nicht berührt |
| 6 | palloc | nein (parser/encoder — ohne allokationen, außer `ngx_pnalloc` in ssl.c für die TP) |
| 7 | crypto | nein (die schlüssel werden über `pkt->keys` übergeben — der typ aus protection.h) |
| 8 | quic-intern | `ngx_quic_conf_t` liest: `qcf->idle_timeout, stream_buffer_size, max_concurrent_streams_bidi/uni, active_connection_id_limit, disable_active_migration` (`ngx_quic_init_transport_params`, L1986); `NGX_QUIC_FT_LAST` — die obere grenze des varint des frame-typs (L764) |
| 9 | DATAGRAM | die einschnittstelle №1 (§3) |

### 1.2. `ngx_event_quic_frames.c` (895) + `.h` (45)

| Nr. | Abhängigkeit | Fakten zum Code |
|---|-------------|---------------|
| 1 | palloc | `ngx_palloc` ×3, `ngx_pnalloc` ×1 (`ngx_quic_alloc_buf`, L28), `ngx_alloc` ×2, `ngx_free` ×1; der refcount der shadow-buffer: `ngx_quic_buf_refs(b) = (b)->shadow->num` (L15) — **in `s3_buf_t` gibt es kein feld `num`**, ergänzen |
| 2 | ngx_connection_t | `c->log` ×12, `c->pool` ×7 |
| 3 | queue | `s3_queue_t` API 1:1 (insert_head/after/tail, remove, empty, head/last, `ngx_queue_data` → `s3_queue_data`) |
| 4 | ngx_log | die debug-ausgaben `NGX_QUIC_DEBUG_ALLOC/PACKETS/FRAMES` — hinter `#ifdef`, wird unverändert portiert |
| 5 | buf API | `ngx_quic_buffer_t` (quic.h:71) + `read/write/skip/free_buffer` — der kern von reassembly/buffering; vollständig portierbar |
| 6 | der rest | `ngx_min` ×4, `ngx_memcpy`, `ngx_memzero` |

### 1.3. `ngx_event_quic_protection.c` (1268) + `.h` (118)

| Nr. | Abhängigkeit | Fakten zum Code |
|---|-------------|---------------|
| 1 | OpenSSL | `#include <openssl/hkdf.h, chacha.h, kdf.h>`; `EVP_PKEY_HKDF` derive (expand/extract), `EVP_Cipher*` AEAD GCM, `EVP_aes_*`/`EVP_chacha*`, header protection `EVP_CIPHER_CTX_ctrl`; `HKDF_extract/expand` (der quictls-zweig), `EVP_AEAD_*` + `CRYPTO_chacha_*` (die boringssl-zweige) — **die zweige herauschneiden**, `NGX_QUIC_OPENSSL_API`/OpenSSL 3.5 belassen |
| 2 | ngx_conf/cycle/connection | kein `c->` außer `c->log` ×5 |
| 3 | quic-intern | `ngx_quic_keys_t` (protection.h:44), `ngx_quic_header_t` (decrypt/create packet), `ngx_str_t` |
| 4 | klassifikation | rein: nur `libcrypto` + typenersetzung; selbständig für die unit-tests (die RFC-9001-vektoren) |

### 1.4. `ngx_event_quic_tokens.c` (265) + `.h` (34)

| Nr. | Abhängigkeit | Fakten zum Code |
|---|-------------|---------------|
| 1 | OpenSSL | `RAND_bytes`, `EVP_Encrypt/Decrypt*` (AES-GCM, `EVP_CTRL_AEAD_SET/GET_TAG`), `EVP_aes_*` — der retry-token und der address-token |
| 2 | ngx_connection_t | `c->log` ×5, `c->sockaddr/socklen` ×1 (validate_token: die bindung des tokens an die adresse) |
| 3 | quic-intern | `conf->av_token_key/sr_token_key` (die schlüssel aus `s3_quic_conf_t`), `ngx_quic_header_t` (retry itag) |
| 4 | klassifikation | rein (libcrypto) |

### 1.5. `ngx_event_quic_connid.c` (501) + `.h` (29)

| Nr. | Abhängigkeit | Fakten zum Code |
|---|-------------|---------------|
| 1 | OpenSSL | `RAND_bytes` (L29, die erzeugung der server CID) |
| 2 | palloc | `ngx_pcalloc` ×1 |
| 3 | ngx_connection_t | `c->log` ×4, `c->pool` ×1 |
| 4 | BPF | `ngx_quic_bpf_attach_id` (L16-56) — unter `#if (NGX_QUIC_BPF)`, definieren wir nicht |
| 5 | queue | die client_ids/free-queues, `ngx_queue_data` |
| 6 | klassifikation | rein |

### 1.6. `ngx_event_quic_output.c` (1405) + `.h` (40)

| Nr. | Abhängigkeit | Fakten zum Code |
|---|-------------|---------------|
| 1 | os-schicht | `ngx_sendmsg(c, &msg, 0)` ×2 (L472, L754) — in ssh3-c gibt es bereits `s3_sendmsg` (`src/os/unix/s3_udp_sendmsg_chain.h:30`); GSO: die cmsg `SOL_UDP`/`UDP_SEGMENT` (L455, `ngx_quic_send_segments` L420) + ein statischer buffer von 65 KB (`NGX_QUIC_MAX_UDP_SEGMENT_BUF` L13, `NGX_QUIC_MAX_SEGMENTS` 64 L14); `NGX_HAVE_ADDRINFO_CMSG`: `ngx_get/set_srcaddr_cmsg` (L432-446) — **ein gegenstück in src/os/unix gibt es nicht**, `s3_get/set_srcaddr_cmsg` ergänzen |
| 2 | ngx_connection_t | `c->log` ×24, `c->sockaddr/socklen` ×6+6, `c->local_sockaddr` ×4, `c->listening` ×4 (`listening->wildcard` für die ADDRINFO cmsg), `c->sent` ×2, `c->read` ×2 |
| 3 | event/timers | `ngx_add_timer(&qc->push, ...)` ×4 (der retry EAGAIN, L386 u.a.), `ngx_current_msec` ×5 |
| 4 | congestion/flow | `cg->in_flight + (p - dst) < cg->window` (L411) — das sendlimit; `ngx_quic_commit_send` (L203): frames mit `pkt_need_ack==0` **werden sofort freigegeben**, gelangen nicht in `ctx->sent` und `in_flight` (L228-233) — der schlüssel zu DATAGRAM (§3.3) |
| 5 | crypto | `RAND_bytes` ×4 (stateless reset, retry, token dcid) |
| 6 | klassifikation | benötigt s3_context + 2 os-helper; die sendmsg/GSO-mechanik ist mit P1 kompatibel |

### 1.7. `ngx_event_quic_ack.c` (1456) + `.h` (31)

| Nr. | Abhängigkeit | Fakten zum Code |
|---|-------------|---------------|
| 1 | event/timers | `ngx_current_msec` ×13, `ngx_add_timer` ×3, `ngx_del_timer` ×1, `ngx_post_event(&qc->lost, &ngx_posted_events)` ×5 (der lost-handler wird in posted verschoben) |
| 2 | ngx_connection_t | `c->log` ×29, `c->ssl->handshaked` ×2 (L231, L1076 — das ignorieren des ACK vor dem handshake) |
| 3 | die queues | `ctx->sent/sending/frames` — nur queue-operationen |
| 4 | die retransmission | `ngx_quic_resend_frames` (L758, aufgerufen aus L663 nur für die crypto-räume) holt die frames aus `ctx->sent` in `ctx->frames` zurück; `ngx_quic_detect_lost` (L594) respektiert `f->ignore_loss` (L893); PTO `ngx_quic_pto_handler` (L1103) sendet nur ein PING |
| 5 | math | `ngx_abs/min/max`, `ngx_memmove` (ranges) |
| 6 | klassifikation | benötigt s3_context — aber minimal: die posted-queue und die timer gibt es bereits in `s3_event_ctx_t`; `c->ssl->handshaked` wird durch ein feld der QUIC-verbindung ersetzt |

### 1.8. `ngx_event_quic.c` (1523) + `.h` (151)

| Nr. | Abhängigkeit | Fakten zum Code |
|---|-------------|---------------|
| 1 | posted | die globale `ngx_posted_events` ×5 + `ngx_post_event` ×5 → ersetzen durch `ctx->posted_events` + `s3_post_event` (`src/event/s3_event.h:128`) |
| 2 | timers | `ngx_add_timer/del_timer` ×12, `ngx_current_msec` ×6 |
| 3 | connection lifecycle | `ngx_close_connection` (L620), `ngx_reusable_connection` (L349), `c->buffer` (das datagramm beim run), `c->read/read->handler`, `c->udp`, `c->ssl` (L3/`handle_payload`: `c->ssl == NULL` → init), `c->pool/log` |
| 4 | hash | `ngx_sha1_init/update/final` (`ngx_quic_address_hash` L1478, die salz für den address-token) → die ersatz: OpenSSL `SHA1()`/`EVP_Digest` (libcrypto ist vorhanden) oder der transfer von `ngx_sha1.c` |
| 5 | conf | `qc->conf->handshake_timeout`, `qc->conf->init` (der streams hook), `qc->conf->shutdown` |
| 6 | rbtree/queue | die streams tree init (L243-244), die queues des qc |
| 7 | klassifikation | benötigt s3_context: der zentrale orchestrator; die public API (`ngx_quic_run/open_stream/finalize_connection/reset_stream/...`) — der vertrag für die schichten darüber |

### 1.9. `ngx_event_quic_streams.c` (1824) + `.h` (44)

| Nr. | Abhängigkeit | Fakten zum Code |
|---|-------------|---------------|
| 1 | connection lifecycle | `ngx_get_connection(c->fd, log)` (L737), `ngx_close_connection` (L190, L804), `ngx_reusable_connection` ×5 (L735, 741, 807, 835, 1169), pool cleanup `ngx_pool_cleanup_add` (L811, der handler `ngx_quic_stream_cleanup_handler`) |
| 2 | stream connection | `sc = qs->connection` — eine vollwertige `ngx_connection_t` mit `sc->recv/send/send_chain` (L762-764), `sc->read/write->handler`, `sc->data` (= `qs`); in ssh3-c gibt es `s3_connection_t.recv/send_chain` bereits (`src/event/s3_connection.h:26-27`), die rolle von `qs` übernimmt `data` |
| 3 | posted | ×7 (init_streamHandler, push) |
| 4 | rbtree | `qc->streams.tree` + `ngx_quic_rbtree_insert_stream` (L109) |
| 5 | flow control | `ngx_quic_control_flow/update_flow/update_max_stream_data/update_max_data` (L37-41) — die frames MAX_DATA/MAX_STREAM_DATA |
| 6 | die zustellung | `ngx_quic_handle_stream_frame` → `ngx_quic_write_buffer(c, &qs->recv, ...)` (L1295) → `ngx_quic_set_event(qs->connection->read)` (L1329) — das vorbild für die DATAGRAM-zustellung (§3.4) |
| 7 | conf | `qc->conf->init` (L625), `stream_buffer_size`, `stream_close_code`, `stream_reject_code_uni/bidi` |
| 8 | klassifikation | benötigt s3_context — die schwerste datei: lifecycle + flow control + zwei buffer pro stream |

### 1.10. `ngx_event_quic_migration.c` (1007) + `.h` (45)

| Nr. | Abhängigkeit | Fakten zum Code |
|---|-------------|---------------|
| 1 | timers | `ngx_current_msec` ×8, `ngx_add_timer/del_timer` (path_validation) |
| 2 | der adresstext | `ngx_sock_ntop` ×2 (L266, L442), `c->addr_text` ×3, `c->listening->addr_text_max_len` (L444), `path->addr_text/text` — in ssh3-c gibt es kein sock_ntop: `s3_sock_ntop` in `src/os/unix` ergänzen oder den text im path speichern |
| 3 | ngx_connection_t | `c->log` ×18, `c->log_error` ×3 (das log-level der MTU-meldungen — durch die konstante `S3_LOG_INFO` ersetzen), `c->sockaddr/socklen`, `c->udp`, `c->listening`, `c->pool` |
| 4 | output API | `ngx_quic_frame_sendto` (path challenge/response, die MTU-sonden) |
| 5 | klassifikation | benötigt s3_context; die logik von path validation/MTU ist selbständig |

### 1.11. `ngx_event_quic_socket.c` (237) + `.h` (28)

| Nr. | Abhängigkeit | Fakten zum Code |
|---|-------------|---------------|
| 1 | rbtree des listeners | `ngx_rbtree_delete(&c->listening->rbtree, &qsock->udp.node)` ×2 (L107, L158), `ngx_rbtree_insert` (L183) — die qsock-knoten leben im rbtree des listeners |
| 2 | typen | `ngx_udp_connection_t` (in `ngx_quic_socket_t` eingebettet, connection.h:137), `ngx_listening_t` |
| 3 | palloc | `ngx_pcalloc` ×2, `ngx_pnalloc` ×1 |
| 4 | ngx_connection_t | `c->pool/log/listening/udp/sockaddr/socklen` |
| 5 | klassifikation | benötigt s3_context: `ngx_udp_connection_t`+`ls->rbtree` → ein eigener knoten in `s3_udp_listen_t.rbtree` (§4.3) |

### 1.12. `ngx_event_quic_udp.c` (437)

| Nr. | Abhängigkeit | Fakten zum Code |
|---|-------------|---------------|
| 1 | cycle | `ngx_enable_accept_events((ngx_cycle_t *) ngx_cycle)` (L45), `ecf = ngx_event_get_conf(ngx_cycle->conf_ctx, ngx_event_core_module)` (L52, multi_accept), `ngx_cycle->log` (L125), `ngx_accept_disabled = ngx_cycle->connection_n / 8 - ngx_cycle->free_connection_n` (L220-221) — all das ist nicht portierbar, ssh3-c hat ein anderes modell |
| 2 | connection accept | `ngx_get_connection` (L231), `c->number = ngx_atomic_fetch_add(...)` (L309), `c->start_time` (L315), `c->addr_text` + `ls->addr_ntop/addr_text_max_len` (L321-332), `c->shared/type/listening/buffer` |
| 3 | lookup | **der schlüssel = der DCID des pakets**, nicht sockaddr: `ngx_quic_get_packet_dcid` (L171, transport.c:509) → `ngx_quic_lookup_connection(ls, &key, ...)` (L415): rbtree nach `ngx_crc32_long(key)` + `ngx_memn2cmp` gegen `qsock->sid.id`; eine neue verbindung → `ls->handler(c)` → `ngx_quic_run(c, conf)` (http/v3/ngx_http_v3_request.c:75) |
| 4 | cmsg | `NGX_HAVE_ADDRINFO_CMSG` — wildcard: die lokale adresse aus der cmsg (L137-158) |
| 5 | klassifikation | benötigt s3_context; das gerüst der recvmsg-schleife ist in P1 bereits vorhanden (`s3_event_recvmsg`, `src/event/s3_event_udp.c`), aber dort ist der schlüssel die sockaddr; die QUIC-version verlangt **eine zweite schlüssel-strategie (DCID)** — siehe §4.3 |

### 1.13. `ngx_event_quic_ssl.c` (996) + `.h` (19)

| Nr. | Abhängigkeit | Fakten zum Code |
|---|-------------|---------------|
| 1 | die ngx_ssl-schicht | `ngx_ssl_create_connection(qc->conf->ssl, c, 0)` (L914), `c->ssl->connection/no_wait_shutdown/handshaked`, `ngx_ssl_error` (das ALERT-log mit der OpenSSL-fehlermeldung), `ngx_ssl_connection_error` (L728) |
| 2 | die OpenSSL QUIC API | der zweig `NGX_QUIC_OPENSSL_API` (OpenSSL ≥3.5): `OSSL_DISPATCH qtdis[]` mit `OSSL_FUNC_SSL_QUIC_TLS_{CRYPTO_SEND,CRYPTO_RECV_RCD,CRYPTO_RELEASE_RCD,YIELD_SECRET,GOT_TRANSPORT_PARAMS,ALERT}` (L868-890), `SSL_set_quic_tls_cbs` (L906), `SSL_set_quic_tls_early_data_enabled` (L913), `SSL_set_quic_tls_transport_params` (L974); die gemeinsamen: `SSL_do_handshake` (L705), `SSL_get_error` (L710), `SSL_is_init_finished` (L738), `SSL_provide_quic_data` (L839), `SSL_get_peer_quic_transport_params` (L511), `SSL_get0_alpn_selected` (L88, L497), `SSL_get_current_cipher` (L225, L433), `SSL_CTX_get_max_early_data` (L911); die quictls/boringssl-zweige (`SSL_set_quic_method` L930 u.a.) — **herauschneiden** |
| 3 | quic-intern | der `ctx->crypto`-buffer (`ngx_quic_handle_crypto_frame`, header ssl.h), `ngx_quic_create_transport_params` + `SSL_set_quic_tls_transport_params`, sr_token (`ngx_quic_new_sr_token`), die ALPN-prüfung |
| 4 | klassifikation | benötigt die ssl-schicht: `s3_ssl_t` (die SSL_CTX-hülle) + der SSL-zustand pro connection (§4.4) |

### 1.14. `ngx_event_quic_openssl_compat.c` (657) + `.h` (52)

Die emulation der QUIC-schnittstelle für BoringSSL/wolfSSL/OpenSSL < 3.5 (ein eigener SSL handshake-treiber, die TP-erweiterung über `SSL_extension_supported`, die schlüssel-aufzeichnung). In ssh3-c nicht portierbar: `NGX_QUIC_OPENSSL_COMPAT` definieren wir nicht (OpenSSL ≥3.5 — die entscheidung ist in `docs/DEPS-QUIC.md` §6 fixiert). Die einzige berührung des konfigs — `ngx_quic_compat_ext_init(ngx_conf_t *cf, SSL_CTX *ctx)` (L81).

### 1.15. `ngx_event_quic_bpf.c` (1257), `.h` (20), `ngx_event_quic_bpf_code.c` (212), `bpf/*`

Die SO_ATTACH_REUSEPORT_EBPF-gruppen der sockets für die worker-balancierung: `ngx_cycle_t` ×29 (`ngx_quic_bpf_get_conf(cycle)`, `cycle->old_cycle`, `ngx_get_conf(cycle->conf_ctx, ngx_core_module)` — L18-26), ein eigenes nginx-modul mit einer conf-struktur, `ngx_listening_t` ×26, die bpf-syscalls. Hängt von der cycle/conf-infrastructure vollständig ab. In P2 nicht portierbar; bei bedarf später — ein eigener mechanismus über `s3_udp_listen_t` (eine separate aufgabe, blockiert nichts).

### 1.16. `ngx_event_quic_connection.h` (329) — der zentrale header

Sammelt alle quic-header (L40-50); die strukturen `ngx_quic_connection_t` (L225-312), `ngx_quic_send_ctx_t` (L200-222: die queues `frames/sending/sent`, die ack-ranges, der crypto-buffer), `ngx_quic_socket_t` (L136: bettet `ngx_udp_connection_t` ein), `ngx_quic_path_t` (L111), `ngx_quic_client_id_t/server_id_t`, `ngx_quic_streams_t` (L147: rbtree + die zähler/limits des flow control), `ngx_quic_congestion_t` (L177). Die makros `ngx_quic_get_connection(c)` (L73: `(c)->udp` → socket → quic) und `ngx_quic_get_send_ctx` (L68). Wird auf die s3-typen umgeschrieben (siehe §4); hier kommen auch die DATAGRAM-felder hinzu (§3.5).

---

## 2. Die empfohlene reihenfolge des transfers

Topologisch: die „reinen“ dateien → die ssl-schicht → der kern → das netz → die streams → DATAGRAM. Was P0/P1 bereits abdecken: pool/palloc (`s3_palloc*`), buf/chain/shadow (außer `num`), rbtree/queue, log (`s3_log_*` + die level `S3_LOG_*` in `s3_base.h:39-55`), string (`s3_str_t`, `s3_memcpy/cpymem/memzero`), der event ctx mit epoll + die timer + posted (`s3_event.h`), `s3_connection_t` mit `recv`/`send_chain`, `s3_udp_sendmsg_chain` + `s3_sendmsg`, recvmsg + die pseudo-verbindungen.

| Nr. | Inkrement | Inhalt | Was fertig sein muss |
|---|-----------|------------|------------------------|
| 1 | **D1: parser/krypto-fundament** | `s3_quic_transport` (transport.c/.h), `s3_quic_frames` (frames.c/.h), `s3_quic_protection` (protection.c/.h), `s3_quic_tokens` (tokens.c/.h), `s3_quic_connid` (connid.c/.h) — die „reinen“ dateien, der transfer per typenersetzung | P0/P1 — alles vorhanden. Eine einzige Änderung der basis: das feld `num` (refcount) in `s3_buf_t` (`src/core/s3_buf.h:16`); im cmake `find_package(OpenSSL 3.5 REQUIRED)` |
| 2 | **D2: ssl-schicht + der QUIC-kern** | `s3_ssl` (die SSL_CTX/SSL-hülle), `s3_quic_ssl.c` (nur der OpenSSL-API-zweig), `s3_quic.c` + `s3_quic_connection.h` + `s3_quic.h` (conf/strukturen/orchestrierung) | posted/timers in `s3_event_ctx_t` (vorhanden); `s3_connection_t.buffer` (der datagram-buffer) und das feld `ssl` — ergänzen; SHA1 — über libcrypto; die lifecycle-vereinfachungen (§4.3) |
| 3 | **D3: netz und zuverlässigkeit** | `s3_quic_output.c` (GSO/segmente/padding/retry/stateless reset), `s3_quic_ack.c` (loss/congestion/PTO), die os-helper `s3_get_srcaddr_cmsg`/`s3_set_srcaddr_cmsg`, die integration mit `s3_udp_listen_t` (der DCID-lookup statt `ngx_event_quic_udp.c`) | `s3_sendmsg` (vorhanden), `s3_udp_listen_t.rbtree` (vorhanden, erweitern, §4.3); die entscheidung über `addr_text` |
| 4 | **D4: streams und migration** | `s3_quic_streams.c` (flow control, open/close/reset/shutdown stream), `s3_quic_migration.c` (path validation, MTU discovery), der idle-timeout | pool cleanup (`s3_pool_cleanup_t` vorhanden), `s3_get_connection/s3_close_connection` (vorhanden), `s3_sock_ntop` (ergänzen) |
| 5 | **D5: DATAGRAM (RFC 9221)** | unser eigener code auf D1–D4 (§3) | der gesamte transport; das interop-ziel der phase P2 |

Die rückwärts-abhängigkeiten, die man im kopf behalten muss: transport.h wird von protection.h/frames.h gebraucht (die frame-typen), quic.h (`ngx_quic_conf_t`) wird von transport.c gebraucht (`init_transport_params`) — deshalb wird `s3_quic.h` mit dem konfig in D1 (header-seitig) portiert oder die qcf-felder werden sofort durch `s3_quic_conf_t` ersetzt.

Der eingangs-vertrag: der lauschende UDP-socket von P1 → datagram → der QUIC-lookup nach DCID → neu: `s3_quic_run(c, conf)` (das analogon zu `ngx_quic_run`, ngx_event_quic.c:201) → die anwendung erhält die streams über `conf->init` und den stream-handler.

---

## 3. DATAGRAM (RFC 9221) — der plan des inkrements

nginx QUIC hat kein DATAGRAM. Alle einschnittpunkte sind nach dem code bestimmt:

### 3.1. Transport parameter 0x0020 (max_datagram_frame_size)

| Nr. | Datei | Die stelle | Die Änderung |
|---|------|-------|--------|
| 1 | `ngx_event_quic_transport.h` | die TP-konstanten L117-133 | `#define NGX_QUIC_TP_MAX_DATAGRAM_FRAME_SIZE 0x20` |
| 2 | `ngx_event_quic_transport.h` | `ngx_quic_tp_t` L344-366 | das feld `uint64_t max_datagram_frame_size;` |
| 3 | `ngx_event_quic_transport.c` | `ngx_quic_parse_transport_param` L1619 (die variant-cases des varint L1638-1712) | case: varint → `tp->max_datagram_frame_size` (nach dem muster `NGX_QUIC_TP_MAX_IDLE_TIMEOUT` L1638/1668) |
| 4 | `ngx_event_quic_transport.c` | `ngx_quic_parse_transport_params` L1725 (die schleife L1737-1766) | nichts: die id-maske überspringt die server-TP — 0x0020 fällt in den varint-zweig |
| 5 | `ngx_event_quic_transport.c` | `ngx_quic_init_transport_params` L1986 | aus `s3_quic_conf_t.max_datagram_frame_size` füllen (bei 0 — DATAGRAM ausgeschaltet: den TP kodieren wir nicht) |
| 6 | `ngx_event_quic_transport.c` | `ngx_quic_create_transport_params` L2030 | die TLV-kodierung: varint id 0x20 + varint value (nach dem muster der nebentp) |
| 7 | `s3_quic.h` (unser) | das analogon zu `ngx_quic_conf_t` L80-102 | das feld `ngx_uint_t max_datagram_frame_size;` (z.b. 1200…IPv6-MTU-6) |

### 3.2. Die frames 0x30/0x31 (DATAGRAM, DATAGRAM_WITH_LENGTH)

| Nr. | Datei | Die stelle | Die Änderung |
|---|------|-------|--------|
| 1 | `ngx_event_quic_transport.h` | die FT-konstanten L58-90 | `#define NGX_QUIC_FT_DATAGRAM 0x30`, `#define NGX_QUIC_FT_DATAGRAM_WITH_LENGTH 0x31`; **unbedingt** `NGX_QUIC_FT_LAST` (L90) von `0x1E` auf `0x31` anheben — sonst wirft die varint-grenze `if (varint > NGX_QUIC_FT_LAST)` (transport.c:764) den frame als unbekannt weg |
| 2 | `ngx_event_quic_transport.h` | die union `ngx_quic_frame_s.u` L277-296 | `ngx_quic_datagram_frame_t { uint64_t length; }` (0x30: length = der rest des pakets; 0x31: varint) |
| 3 | `ngx_event_quic_transport.c` | `ngx_quic_parse_frame` L744 (switch L780-1158) | zwei cases: 0x30 — payload = `[pos, end)`, die länge aus den grenzen; 0x31 — varint length + bounds-check; die daten kommen in `frame->data` (`ngx_quic_copy_bytes` L214) ohne offset/reassembly |
| 4 | `ngx_event_quic_transport.c` | `ngx_quic_frame_allowed` L1161, die tabelle der masken L1173-1204 | zwei einträge `/* DATAGRAM */ 0x1` — nur 1-RTT (RFC 9221 §4: der frame ist in Initial/Handshake/0-RTT verboten) |
| 5 | `ngx_event_quic_transport.c` | `ngx_quic_create_frame` L1281 | `f->need_ack = 0` für beide typen (nach dem muster ACK L1296 / CONNECTION_CLOSE L1319); der create-helper `ngx_quic_create_datagram` (0x31 — mit der varint-länge) |
| 6 | `ngx_event_quic.c` | `ngx_quic_handle_frames` L1176 (switch L1221-1360) | case → ein neuer handler `ngx_quic_handle_datagram_frame` (unser code, §3.4) |

### 3.3. send_ctx, queues, ACK/PTO — wo das „verbot der retransmission“ strukturell bereits erfüllt ist

| Nr. | Datei | Die stelle | Der fakt |
|---|------|-------|------|
| 1 | `ngx_event_quic_output.c` | `ngx_quic_commit_send` L203, L228-233 | ein frame mit `pkt_need_ack==0` wird nach dem senden **sofort freigegeben**: er gelangt nicht in `ctx->sent`, wird nicht in `cg->in_flight` gezählt → keine ACK-berücksichtigung, keine loss-retransmission (`ngx_quic_detect_lost` L594 geht nur über `ctx->sent`), kein resend (`ngx_quic_resend_frames` L758 wird nur für die crypto-räume aufgerufen, ack.c:663). DATAGRAM mit `need_ack=0` erbt all das automatisch — ein eigener code ist nicht nötig |
| 2 | `ngx_event_quic_ack.c` | `ngx_quic_pto_handler` L1103 | PTO sendet nur ein PING — eine retransmission von DATAGRAM entsteht nicht |
| 3 | die queues | `ctx->frames`/`sending` (connection.h:210-212) | DATAGRAM lebt im anwendungsraum `send_ctx[2]`, ein eigener send_ctx ist nicht nötig |
| 4 | risiko | `ngx_quic_create_segments`/`allow_segmentation` L336/L253 | die GSO-segmentierung rechnet `cg->in_flight + (p - dst) < cg->window` (L411) für alle frames; DATAGRAM darf nicht von einem vollen CWND des nicht-ack-verkehrs blockiert werden — beim bench prüfen (§3.5) |

### 3.4. Die zustellung an die anwendung (senden und empfangen)

| Nr. | Die richtung | Der einschnitt | Die implementierung |
|---|-------------|-------------|------------|
| 1 | empfang | `ngx_quic_handle_datagram_frame` (neu, der aufruf aus ngx_event_quic.c:1176) | payload (die `frame.data`-chain, `u.datagram.length`) → der callback `conf->datagram_handler(c, data)` — ein neues feld `s3_quic_conf_t`. **Zero-copy (2026-10-03)**: die parser-kette wird wie sie ist übergeben, ohne zusammenklappen — der handler entscheidet selbst, ob er kopiert. Die kette zeigt auf den statischen entschlüsselungs-buffer (`pkt->plaintext`, wie in nginx) und ist nur für die dauer des aufrufs gültig. Ohne `ngx_quic_buffer_t`: DATAGRAM wird nicht geordnet und nicht neu zusammengebaut (der frame ≤ MTU). Das muster des ergebnisses — streams.c:1295-1329, aber ohne buffer und `set_event` |
| 2 | sendung | die neue public API `s3_quic_send_datagram(c, data, len)` (das analogon zu `ngx_quic_reset_stream` in quic.h:137) | `ngx_quic_alloc_frame` (frames.c:197) + `u.datagram` + `frame->data` = `ngx_quic_copy_buffer` (frames.c:393) + `ngx_quic_queue_frame` (frames.c:299) → geht über das übliche `ngx_quic_output` raus; die größe ist begrenzt auf `min(TP_peer.max_datagram_frame_size, path->mtu - header)` — die prüfung im moment der einreihung |
| 3 | abbruch/schließung | `ngx_quic_close_connection`/`discard_ctx` (ngx_event_quic.c:470/1096) | nichts: die nicht-ack-frames werden wie die übrigen freigegeben |

### 3.5. Das flow control von DATAGRAM und die risiken

| Nr. | Der punkt | Die entscheidung |
|---|-------|---------|
| 1 | Das transport-flow-control | RFC 9221 **definiert** für DATAGRAM kein flow control (keine MAX_DATAGRAM_DATA-frames). Das einzige transport-limit — `max_datagram_frame_size` (die frame-größe) + das congestion window. Das empfangslimit — unsere zulage |
| 2 | Die sendung | der zähler `qc->datagrams_in_flight` (unser feld in `ngx_quic_connection_t`, connection.h:225-312) mit der verringerung über den PTO-timer/die acks der nachbarn — oder eine ehrliche zählung in `cg->in_flight` mit einer manuellen rückgabe. Das minimum für P2: die begrenzung der anzahl der DATAGRAM pro push (`qc->push`) und die respektierung des CWND nach der stelle in `dst` |
| 3 | Der empfang | das queue-limit pro connection in der ssh3-schicht (die politik: drop + zähler, kein CONNECTION_CLOSE — datagramme dürfen verlorengehen) |
| 4 | PTO/retransmission | durch RFC 9221 §5 verboten; wird strukturell über `need_ack=0` erfüllt (§3.3) — DATAGRAM **nicht** in die queue `ctx->sent` einreihen |
| 5 | Risiko: quic-go | prüfen, dass der server/client quic-go den TP 0x0020 vor dem ersten frame sieht; der client-TP — vor dem handshake-complete |
| 6 | Risiko: MTU | 0x30 ohne länge verlangt `length = end - pos` — im GSO-segment (`ngx_quic_create_segments`) darf der frame nicht zerschnitten werden: `ngx_quic_split_frame` (frames.c:319) darf auf DATAGRAM nicht angewandt werden (nach dem typ — ausschließen) |
| 7 | Die code-isolation | alles DATAGRAM-spezifische — in `s3_quic_transport.c` (parse/create), `s3_quic.c` (handler), `s3_quic.h` (conf/API); das fuzzing des parsers ab P2 (`PLAN.md` §4, P6) |

---

## 4. Die ersetzungen beim portieren (nginx → ssh3-c)

### 4.1. `ngx_cycle_t` / die globalen → `s3_event_ctx_t`

Der reale satz der cycle-lesungen aus dem quic-code ist klein:

| Nr. | nginx | Liest | Die ersatz in ssh3-c |
|---|-------|--------|-----------------|
| 1 | `ngx_posted_events` (die globale queue) | quic.c ×5, ack.c ×5, frames.c ×1, streams.c ×7 | `ctx->posted_events` + `s3_post_event`/`s3_event_process_posted` (`src/event/s3_event.h:126-138`); die aufrufe `ngx_quic_process_posted` (streams.c:231) erhalten `ctx` |
| 2 | `ngx_add_timer/del_timer` (das globale rbtree) | quic.c, ack.c, output.c, streams.c, migration.c | `s3_event_add_timer/del_timer` (`s3_event.h:123-124`) — die signaturen stimmen überein |
| 3 | `ngx_current_msec` | ack.c ×13, quic.c, migration.c, output.c | `s3_current_msec` (`s3_event.h:106`) |
| 4 | `ngx_cycle->log` (udp.c:125) | das recvmsg-log | `lc->log` (in der P1-version vorhanden) |
| 5 | `ngx_cycle->connection_n/free_connection_n` + `ngx_accept_disabled` (udp.c:220-221) | das accept-throttling | nicht portierbar: die limit-politiken sind eine sache der ssh3-anwendung; sonst ein zähler in `s3_event_ctx_t` bei bedarf |
| 6 | `ngx_event_get_conf(cycle->conf_ctx, ngx_event_core_module)` (udp.c:52) | multi_accept | nicht nötig: `s3_event_recvmsg` liest bis EAGAIN |
| 7 | `ngx_enable_accept_events` (udp.c:45) | die reaktivierung nach timedout | nicht nötig: P1 schaltet den listener nicht ab |
| 8 | `ngx_cycle->conf_ctx` (bpf) | das bpf-modul | nicht portierbar (§1.15) |

Die erweiterung von `s3_event_ctx_t` für QUIC ist **nicht zwingend** — der QUIC-konfig wird über `s3_quic_run(c, conf)` übergeben und in `qc->conf` gespeichert. Wenn es bequemer ist, global — das feld `void *quic_conf`, aber die explizite übergabe ist sauberer.

### 4.2. `ngx_quic_conf_t` (ngx_event_quic.h:80-102) → `s3_quic_conf_t`

Die felder, die der code wirklich liest (grep `qc->conf->`, `qcf->`):

| Nr. | Das nginx-feld | Wer liest | ssh3-c |
|---|------------|-----------|--------|
| 1 | `ssl` (ngx_ssl_t*) | ssl.c:914 | `s3_ssl_t *ssl` (§4.4) |
| 2 | `retry` | ssl.c (der stateless-retry-zweig) | `unsigned retry : 1` |
| 3 | `gso_enabled` | output.c:289 | `unsigned gso_enabled : 1` |
| 4 | `disable_active_migration` | transport.c:1986 (TP 0x0C) | dasselbe |
| 5 | `handshake_timeout` | quic.c (der close-timer) | `s3_msec_t` |
| 6 | `idle_timeout` | transport.c:1986 (TP 0x01) | `s3_msec_t` |
| 7 | `host_key` | das http/v3-modul (die erzeugung der av/sr-schlüssel) | `s3_str_t host_key` + der generator in unserem code (nginx erzeugt in `ngx_http_v3_module.c:310-372`, nicht in quic/) |
| 8 | `stream_buffer_size` | transport.c:1986 (TP initial_max_stream_data), streams.c | `size_t` |
| 9 | `max_concurrent_streams_bidi/uni` | transport.c:1986 | `s3_uint_t` |
| 10 | `active_connection_id_limit` | transport.c:1986 (TP 0x0E) | `s3_uint_t` |
| 11 | `stream_close_code`, `stream_reject_code_uni`, `stream_reject_code_bidi` | streams.c (reject/close) | `s3_int_t` |
| 12 | `init` (`ngx_quic_init_pt`) | streams.c:625 (der hook „streams ready“) | `s3_quic_init_pt` |
| 13 | `shutdown` (`ngx_quic_shutdown_pt`) | quic.c | `s3_quic_shutdown_pt` |
| 14 | `av_token_key[32]`, `sr_token_key[32]` | output.c (stateless reset), ssl.c:956 (sr_token), tokens.c | die `u_char`-arrays (unser code füllt sie aus `host_key`) |
| 15 | **neu (DATAGRAM)** | — | `s3_uint_t max_datagram_frame_size; s3_quic_datagram_pt datagram_handler;` |

Die nginx-direktiven (`quic_retry`, `quic_gso` usw.) gibt es in quic/ nicht — sie parst das http/v3-modul; ssh3-c füllt `s3_quic_conf_t` aus seinem eigenen konfigurator (CLI/datei), einen direktiven-parser zu schreiben ist nicht nötig.

### 4.3. `ngx_connection_t` → `s3_connection_t`

Die felder, die der QUIC-code wirklich liest/schreibt (die zusammenfassung des grep `c->` über alle dateien):

| Nr. | Das nginx-feld | In `s3_connection_t` vorhanden? | Die aktion |
|---|------------|---------------------------|----------|
| 1 | `log`, `read`, `write`, `fd`, `pool`, `sockaddr`, `socklen`, `local_sockaddr`, `local_socklen`, `sent` | ja (`s3_connection.h:18-46`) | ohne Änderungen |
| 2 | `data` | ja | für die stream-connection lebt hier `ngx_quic_stream_t` (statt des nginx-felds `sc->quic`) |
| 3 | `udp` | ja, aber der typ ist ein anderer: `struct s3_udp_connection_s *` | in nginx `c->udp` → `ngx_quic_socket_t` (das makro `ngx_quic_get_socket`, connection.h:76); bei ssh3-c — ein P1-knoten. Umschreiben: `ngx_quic_socket_t` bettet `ngx_udp_connection_t{node, connection}` + den `quic`-zeiger + `sid` + `sockaddr` ein → ein `s3_quic_socket_t` mit `s3_rbtree_node_t node; s3_connection_t *connection; s3_quic_connection_t *quic; s3_quic_server_id_t sid;` bauen und ihn statt des P1-knotens in `s3_udp_listen_t.rbtree` registrieren |
| 4 | `buffer` | nein | `s3_buf_t *buffer` ergänzen — das eingangs-datagramm (`ngx_quic_run` → `ngx_quic_handle_datagram(c, c->buffer, conf)`, ngx_event_quic.c:208; `c->udp->buffer` für die wiederholten, udp.c:222) |
| 5 | `ssl` | nein | `s3_ssl_conn_t *ssl` (§4.4) — der handshake-zustand + `handshaked` |
| 6 | `listening` | nein | wird um des `rbtree` willen gelesen (socket.c:107/158/183), `wildcard` (output.c:446), `addr_text_max_len` (migration.c:444), `handler` (streams.c:574) → die ersatz: beim QUIC-socket direkte referenzen (`s3_udp_listen_t *listen`), der handler der anwendung — in `s3_quic_conf_t` |
| 7 | `addr_text` | nein | migration.c/udp.c — das logging. Die variante: `u_char addr_text[S3_SOCKADDR_STRLEN]` in `s3_quic_path_t` (dort gibt es bereits `text/addr_text`, connection.h:129-130) und im log-konfig; oder das feld in der connection ergänzen |
| 8 | `number`, `start_time` | nein | nur logs/statistik — verwerfen oder `uint64_t number` |
| 9 | `reusable`, `idle`, `destroyed`, `close`, `type`, `log_error` | nein | der lifecycle des nginx-worker: `ngx_reusable_connection` ×6 (streams.c/quic.c) wird durch ein flag in `s3_quic_connection_t` ersetzt (die berücksichtigung in der shutdown-bedingung `can_shutdown`); `log_error` → ein konstantes level |
| 10 | `shared` | ja | ok |

### 4.4. `ngx_ssl_t` / `ngx_ssl_connection_t` → `s3_ssl_t` / `s3_ssl_conn_t`

ssl.c verlangt vom ssl-layer das minimum (nach den aufrufen):

| Nr. | Die funktion ssl.c | Was in ssh3-c gebraucht wird |
|---|---------------|---------------------|
| 1 | `ngx_ssl_create_connection(qc->conf->ssl, c, 0)` (L914) | `s3_ssl_t` = der halter des `SSL_CTX*` (+ das ALPN-protokoll, cert/key); `s3_ssl_conn_t` = `SSL *connection; unsigned handshaked:1; unsigned no_wait_shutdown:1;` + die bindung an `s3_connection_t` |
| 2 | `SSL_set_quic_tls_cbs(ssl_conn, qtdis, c)` (L906) | OpenSSL ≥3.5: eine `OSSL_DISPATCH`-tabelle mit sechs callbacks (`OSSL_FUNC_SSL_QUIC_TLS_*`, L868-890) — die callbacks quic.c/ssl.c implementieren über den `ctx->crypto`-buffer und `ngx_quic_keys_*` |
| 3 | `SSL_set_quic_tls_transport_params` (L974), `SSL_get_peer_quic_transport_params` (L511) | ohne hüllen, der direkte aufruf |
| 4 | `SSL_do_handshake` (L705) + `SSL_get_error` (L710) + `SSL_is_init_finished` (L738) | die nichtblockierende handshake-schleife, `SSL_ERROR_WANT_READ/WRITE` → das warten auf CRYPTO |
| 5 | `SSL_provide_quic_data` (L839) | die einspeisung des `ctx->crypto`-buffers nach den leveln |
| 6 | `SSL_get0_alpn_selected` (L88/497) | die ALPN-prüfung des protokolls ssh3 |
| 7 | `SSL_get_current_cipher` (L225/433) | die wahl der HP/AEAD-parameter (bei uns werden sie in protection.c fixiert) |
| 8 | `SSL_CTX_get_max_early_data` (L911) + `SSL_set_quic_tls_early_data_enabled` (L913) | 0-RTT |
| 9 | `ngx_ssl_error` / `ngx_ssl_connection_error` | ein eigenes `s3_ssl_error(log, ...)` auf `ERR_get_error`/`ERR_error_string_n` |

Die zweig-makros `NGX_QUIC_QUICTLS_API`/`NGX_QUIC_BORINGSSL_API`/`NGX_QUIC_OPENSSL_COMPAT` (ngx_event_quic.h:15-28) — nur `NGX_QUIC_OPENSSL_API` belassen (die cmake-forderung: OpenSSL ≥3.5, siehe `docs/DEPS-QUIC.md` §7).

### 4.5. Die übrigen ersetzungen

| Nr. | nginx | ssh3-c |
|---|-------|--------|
| 1 | `ngx_buf_t.shadow->num` refcount (frames.c:15) | `int num;` in `s3_buf_t` (`src/core/s3_buf.h`) ergänzen — die einzige Änderung der P0-basis |
| 2 | `ngx_sendmsg(c, &msg, 0)` | `s3_sendmsg` (bereits vorhanden, `src/os/unix/s3_udp_sendmsg_chain.h:30`) |
| 3 | `ngx_get_srcaddr_cmsg` / `ngx_set_srcaddr_cmsg` (IP_PKTINFO/IPV6_RECVPKTINFO) | in `src/os/unix/` ergänzen (werden vom recvmsg-wildcard und der GSO-sendung benutzt) |
| 4 | `ngx_sha1_*` (quic.c:1478 address-hash) | OpenSSL `SHA1()` aus libcrypto (oder der transfer von `ngx_sha1.c` — eine datei, BSD) |
| 5 | `RAND_bytes` | der direkte aufruf (libcrypto) — bereits so in nginx |
| 6 | `ngx_sock_ntop` | ein neues `s3_sock_ntop` in `src/os/unix` (gebraucht von migration.c, udp.c) |
| 7 | `ngx_atomic_fetch_add` (udp.c:309 der connection-zähler) | verwerfen/durch ein einfaches `++` ersetzen (eine single-threaded event-loop) |
| 8 | `ngx_crc32_long` + `ngx_memn2cmp` (udp.c:401/419 der DCID-lookup) | `s3_crc32_long`/der vergleich — im core ergänzen oder die bytes mit dem rbtree-komparator vergleichen (das P1-modell `s3_udp_key_cmp` wechselt auf den sid-vergleich) |
| 9 | `ngx_socket_errno`, `NGX_EAGAIN` | `s3_socket_errno`, `S3_EAGAIN` (vorhanden, `src/os/unix/s3_errno.h`) |
| 10 | `c->log->action = "..."` (quic.c ×10, quic_ssl.c) | das vereinfachte `s3_log_t` hat kein action — die zeilen verwerfen oder `const char *action` in `s3_log_t` ergänzen (in D2 entscheiden) |
| 11 | `NGX_HAVE_UDP_SEGMENT`/`NGX_HAVE_MSGHDR_MSG_CONTROL`/`NGX_HAVE_ADDRINFO_CMSG` | die cmake feature-tests (das analogon zu nginx auto/feature) → `S3_HAVE_*` |
| 12 | die präfixe `ngx_quic_*` → `s3_quic_*`, `NGX_QUIC_*` → `S3_QUIC_*` | die mechanische ersetzung, außer den namen der RFC-konstanten (TP/FT/ERR können `S3_QUIC_TP_*` bleiben…) |

### 4.6. Die abweichungen von nginx, die in D3 entstanden (die client-rolle)

nginx ist nur ein server, deshalb sind vier stellen im portierten code „eingegossen“ auf die server-rolle und verlangen eine explizite Änderung, sobald ein client auftaucht:

| Nr. | Die stelle | nginx | ssh3-c |
|---|-------|--------|--------|
| 1 | die schlüssel-slots, `s3_quic_keys_set_encryption_secret()` / `s3_quic_keys_available()` | `is_write` = 1 → der server-slot (einen client gibt es nicht) | `is_write` — die TLS-richtung: der slot wird als `is_write == keys->is_client` gewählt; sonst liest der client die server-secrets und umgekehrt |
| 2 | `s3_quic_keys_set_initial_secret()` / `s3_quic_keys_update()` | der client-slot immer zum lesen, der server-slot zum schreiben | die richtung `enc` wird aus `keys->is_client` abgeleitet |
| 3 | `HANDSHAKE_DONE` (0x1e) | die tabelle der erlaubten frames verbietet den frame allen pakettypen: der server erhält ihn nicht | der client nimmt ihn genau einmal in 1-RTT an, bestätigt den handshake und setzt die handshake-schlüssel zurück (`handshake_confirmed`) |
| 4 | `CRYPTO` nach dem handshake | wird immer abgelehnt | wird nur vom server abgelehnt; der client nimmt `NewSessionTicket` an und durchläuft `SSL_do_handshake()` in `s3_quic_post_handshake()` |
| 5 | das flag `direction` in `s3_quic_cbs_yield_secret()` | nginx übergibt `direction` an den kdf wie es ist: **1 = write, 0 = read** | in D3 ergab die inversion `!direction` ein konsistentes, aber gespiegeltes C↔C — das interop mit quic-go hat es aufgedeckt; korrigiert auf die nginx-semantik, C↔C blieb grün |
| 6 | `NEW_TOKEN` (0x07) | die maske 0x0: der server erhält ihn nicht | der client nimmt ihn in 1-RTT an, der token wird geparst und verworfen (die adress-validierung — D4) |
| 7 | `ngx_quic_open_stream()` | zwei zweige: die client- und server-initiierte id | in den D4-port gelangte nur der server-zweig — der client öffnete id=1 (server uni) und erhielt STREAM_STATE_ERROR von quic-go; der client-zweig ist wiederhergestellt |
| 8 | `ngx_quic_handle_max_stream_data_frame()` | `ngx_quic_set_event(wev)` weckt den anwendungs-schreiber | der port rief nur flush(); set_event(wev) wiederhergestellt — sonst erfährt die anwendung nichts vom öffnen des fensters |
| 9 | das lesen des streams durch die anwendung | http3 armt `rev->active` über `ngx_handle_read_event()` und liest sofort im accept-pfad | `s3_quic_set_event()` postet nur bei `active`; die ssh3-anwendungen sind verpflichtet, active zu armen und das erste lesen im stream_handler zu machen (siehe interop_server.c) |
| 10 | `ngx_queue_init(&qc->streams.uninitialized)` in new_connection | vorhanden | fehlte im D2-gerüst — der erste aufruf von init_streams lief über eine uninitialisierte queue (UBSan: offset to null) |
| 11 | der backlink des listeners | nginx hält den listener in den feldern der connection (`c->listening`), `c->data` ist frei für die anwendung | D3 löschte `c->data = ul` nach der registrierung der primären sockets; die später ausgegebenen NEW_CONNECTION_ID wurden nicht im rbtree des listeners registriert → stateless reset bei der CID-rotation des clients; der backlink lebte fortan das ganze leben der connection — aber in `c->data`, was mit der h3-session kollidierte (P3): auf dem server las `s3_h3_get_session()` die stack-adresse von `main()` und `init_session` wurde still übersprungen → „stream already created“ → ein hängendes posted-event auf dem zerstörten pool → SEGV in `s3_event_process_posted`. Jetzt wird der backlink bei `open_sockets()` nach `qc->listen` verlagert (das feld der quic-connection), `c->data` ist wieder frei für den besitzer der connection (die h3-session), `s3_quic_listen()` liest `qc->listen` |
| 12 | `c->udp` = der socket des aktuellen pakets | die zustellung setzt es pro paket | der lookup gab nur die connection zurück; RETIRE_CONNECTION_ID verglich die seq mit einem fremden socket → PROTOCOL_VIOLATION bei der CID-rotation; der lookup setzt jetzt `c->udp` |
| 13 | `set_path()`, das erste datagramm des pfads | der marker `c->udp->buffer == NULL` | das merkmals `qsock->socklen == 0`: shared_recv absorbiert den buffer, die adresse pro datagramm setzt nur `s3_quic_deliver()`; `NGX_DONE`→`S3_ABORT` |
| 14 | EMSGSIZE in der MTU-sonde | `c->write->error` / `c->log_error` | `s3_socket_errno == S3_EMSGSIZE`: send() (output.c) setzt das flag nicht |
| 15 | `handle_max_stream_data` weckt den schreiber | `ngx_quic_set_event(wev)` | der port rief nur flush(); wiederhergestellt (siehe auch p. 8) |
| 16 | `handle_path_mtu` → das wachstum des MTU | der aufruf aus der ack-schleife (ack.c:248) | übernommen, aber NICHT durchgeführt (ack.c — die zone der optimierung); die sonden gehen raus und laufen sicher ab, das MTU bleibt beim startwert — eine zeile später |
| 17 | die zustände des uni-streams in `create_stream()` | die referenz server-only: die uni id des peers ist immer client-seitig | in ssh3-c öffnen beide rollen uni (h3 control/encoder/decoder): die richtung wird aus `s3_quic_stream_is_own_uni()` abgeleitet — eigene: send-only (SEND_READY), fremde: read-only (RECV_RECV); gespiegelt zu p. 7 für `open_stream()` |
| 18 | die h3-session und die frühen uni-streams | `ngx_http_v3_init()` erzeugt die session beim ersten stream (auch uni) | die interop-ports sind verpflichtet, dasselbe lazy `s3_h3_init_session()` im stream-handler vor dem routing zu machen: quic-go öffnet den control-stream sofort nach dem handshake, früher als der zyklus des handshake-ereignisses; ohne guard las der client die NULL-session (UBSan: member access within null) |

Separat: der kurze header trägt nicht die länge des DCID, deshalb liest der parser genau `S3_QUIC_SERVER_CID_LEN` bytes, und der client muss einen CID derselben länge erzeugen (sonst weicht das verschiebe-offset für den header protection ab — das symptom: das TX-offset 21 gegen RX 25).

## 5. Der interop-stand (quic-go)

| Nr. | Komponente | Wo |
|---|-----------|-----|
| 1 | Das go-harness (server/client, das DATAGRAM echo) | `interop/quic-go` (quic-go v0.63.0 — wie im go-fork) |
| 2 | Die C-runner: `s3interop_server`, `s3interop_client` | `interop/interop_server.c`, `interop/interop_client.c` |
| 3 | Die matrix PASS/FAIL | `interop/run-quic-go.sh` (loopback, die zertifikate in `build/interop/`) |
| 4 | Die TLS-secrets beider seiten zum debuggen | `S3_KEYLOG=1` (C, NSS keylog auf stderr), `-keylog datei` (das harness) |

Das ergebnis 2026-10-02: beide richtungen PASS (handshake + 8/8 DATAGRAM). Unter `tc netem loss 5%` überlebt der handshake; die DATAGRAM-phase verliert einen teil der datagramme — das ist die semantik von RFC 9221 (unzuverlässig, ohne retransmission), die abnahme nach den verlusten muss „N von M sind durchgekommen + die verbindung lebt“ zählen, nicht „alle bis auf einen“.

---

## 5. Die einschätzung des umfangs

Die zeilen (wc -l der referenz, insgesamt 17538, bpf 1489 eingeschlossen):

| Nr. | Die klasse | Die dateien | Die zeilen (.c+.h) | Der anteil |
|---|-------|-------|---------------|------|
| 1 | „Reine“ (D1) | transport, frames, protection, tokens, connid | 5768 | 33 % |
| 2 | s3_context (D2–D4) | quic.c, ack.c, streams.c, migration.c, socket.c, connection.h, quic.h | 7112 | 41 % |
| 3 | s3_context + os (D3) | output.c, udp.c | 1882 | 11 % |
| 4 | die ssl-schicht (D2) | ssl.c/.h | 1015 | 6 % |
| 5 | nicht portierbar | openssl_compat, bpf (.c/.h/code) | 2198 | 12 % |

Insgesamt die adaption: **≈ 15.3k zeilen** (85 % der referenz), davon ein drittel mechanische typenersetzung; dazu die DATAGRAM-zulage ≈ 400–600 zeilen unseres codes (§3) und die os-helper ≈ 150 zeilen.

Die aufteilung von P2 auf sessions (die erfahrung P0/P1: ein inkrement ≈ 1–2 sessions mit tests):

| Nr. | Inkrement | Sessions | Das abnahme-kriterium |
|---|-----------|--------|------------------|
| 1 | D1 parser/krypto | 1–2 | die unit-tests: varint/frames roundtrip; die HKDF/AEAD-vektoren RFC 9001; der TP parse/create roundtrip; `ctest` release+asan sauber |
| 2 | D2 ssl+kern | 2–3 | der QUIC-handshake C-client ↔ quic-go (Initial+Handshake+1-RTT), die schlüssel wechseln, die TP ausgetauscht |
| 3 | D3 netz/zuverlässigkeit | 2–3 | bulk 1 GiB loopback ≥ 250 MB/s (`PLAN.md` P2); der verlust von 5 % der pakete — die verbindung überlebt (loss recovery); der vergleich GSO on/off |
| 4 | D4 streams/migration | 2–3 | der stream echo quic-go ↔ C in beide richtungen; das flow control blockiert/erweitert (MAX_DATA); der adresswechsel → path validation; der idle-timeout |
| 5 | D5 DATAGRAM | 1–2 | der datagram roundtrip go ↔ C (das interop `PLAN.md` P2); der TP 0x0020 ist beiden seiten sichtbar; der frame 0x31 in Initial wird abgelehnt; die retransmission von DATAGRAM fehlt (die prüfung über das pnum-log) |
| — | **Insgesamt P2** | **8–13** | final: ASan/UBSan sauber, das fuzzing der parser gestartet, `memory_save` der finalisierung |

Die größten umfangs-risiken: `ngx_event_quic_streams.c` (1824 zeilen — lifecycle + flow control, die dichteste integration mit dem connection-lifecycle), `ngx_event_quic_transport.c` (2215 — aber leicht portierbar), und udp.c/socket.c — das neudenken unter das P1-modell des rbtree (eine einmalige arbeit, keine typenersetzung).
