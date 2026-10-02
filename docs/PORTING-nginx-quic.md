# ssh3-c: карта портирования QUIC-слоя nginx (фаза P2)

Дата: 2026-10-01. Референс: `C:\Git\temp\ssh3-c\refs\nginx\src\event\quic\` (nginx 1.31.7, read-only).
База ssh3-c: P0 (`src/core`: `s3_pool_t`/`s3_buf_t`/`s3_chain_t`/`s3_rbtree_t`/`s3_queue_t`/`s3_log_t`/`s3_str_t`) и P1 (`src/event`: `s3_event_ctx_t` + epoll, таймеры-rbtree, posted events, `s3_connection_t` c `recv`/`send_chain`, UDP-псевдо-коннекции `s3_udp_listen_t` + `s3_event_recvmsg`/`s3_udp_shared_recv`; `src/os/unix`: `s3_udp_sendmsg_chain`, `s3_sendmsg`, `s3_udp_recv`) — обе фазы закрыты (см. `docs/PLAN.md` §7).

Лицензия: все адаптированные файлы сохраняют `Copyright (C) Nginx, Inc.` + добавляют `Copyright (C) 2026 the ssh3-c authors` (BSD-2, обязательства в `docs/DEPS-QUIC.md` §6 и `THIRD-PARTY-NOTICES.md`).

Целевое размещение: `src/event/quic/s3_quic_*.c|h` (префикс `s3_`, стиль проекта).

---

## 1. Зависимостная карта по файлам `src/event/quic/`

Сводка (строки .c+.h, классификация — доминирующая; подробности ниже):

| № | Файл | Строк | Классификация |
|---|------|-------|---------------|
| 1 | `ngx_event_quic_transport.c/.h` | 2215+398 | чистый (типозамена) |
| 2 | `ngx_event_quic_frames.c/.h` | 895+45 | чистый (типозамена + `num` в `s3_buf_t`) |
| 3 | `ngx_event_quic_protection.c/.h` | 1268+118 | чистый (libcrypto) |
| 4 | `ngx_event_quic_tokens.c/.h` | 265+34 | чистый (libcrypto) |
| 5 | `ngx_event_quic_connid.c/.h` | 501+29 | чистый (guard BPF) |
| 6 | `ngx_event_quic_output.c/.h` | 1405+40 | нужен s3_context + os-хелперы |
| 7 | `ngx_event_quic_ack.c/.h` | 1456+31 | нужен s3_context (лёгкий) |
| 8 | `ngx_event_quic.c` + `.h` | 1523+151 | нужен s3_context (центральный) |
| 9 | `ngx_event_quic_streams.c/.h` | 1824+44 | нужен s3_context (тяжёлый) |
| 10 | `ngx_event_quic_migration.c/.h` | 1007+45 | нужен s3_context |
| 11 | `ngx_event_quic_socket.c/.h` | 237+28 | нужен s3_context (rbtree слушателя) |
| 12 | `ngx_event_quic_udp.c` | 437 | нужен s3_context (замена P1-слоем) |
| 13 | `ngx_event_quic_ssl.c/.h` | 996+19 | нужен ssl-слой |
| 14 | `ngx_event_quic_connection.h` | 329 | нужен s3_context (переписать типы) |
| 15 | `ngx_event_quic_openssl_compat.c/.h` | 657+52 | не переносится |
| 16 | `ngx_event_quic_bpf.c/.h`, `ngx_event_quic_bpf_code.c`, `bpf/*` | 1257+20+212+3 | не переносится в P2 |

Детальные зависимости — по реальному коду (grep include/вызовы, номера строк референса):

### 1.1. `ngx_event_quic_transport.c` (2215) + `.h` (398)

| № | Зависимость | Факты по коду |
|---|-------------|---------------|
| 1 | ngx_core-типы | `ngx_str_t` (TP dcid/scid/retry, `pkt->token`), `ngx_buf_t` (`pkt->raw`), `ngx_chain_t` (`frame->data`), `ngx_queue_t` (`frame->queue`), `ngx_msec_t`, `ngx_uint_t`, `ngx_log_t` |
| 2 | ngx_conf | нет |
| 3 | ngx_connection_t | нет (только `ngx_quic_header_t` и `frame`, `c->log` не используется — лог берётся из `pkt->log`) |
| 4 | event/timers/posted | нет |
| 5 | ngx_log | `ngx_log_error/debug0..2` по всему файлу; `log->action` не трогает |
| 6 | palloc | нет (парсер/энкодер — без аллокаций, кроме `ngx_pnalloc` в ssl.c для TP) |
| 7 | crypto | нет (ключи передаются через `pkt->keys` — тип из protection.h) |
| 8 | quic-внутренние | `ngx_quic_conf_t` читает: `qcf->idle_timeout, stream_buffer_size, max_concurrent_streams_bidi/uni, active_connection_id_limit, disable_active_migration` (`ngx_quic_init_transport_params`, L1986); `NGX_QUIC_FT_LAST` — верхняя граница varint типа фрейма (L764) |
| 9 | DATAGRAM | точка врезки №1 (§3) |

### 1.2. `ngx_event_quic_frames.c` (895) + `.h` (45)

| № | Зависимость | Факты по коду |
|---|-------------|---------------|
| 1 | palloc | `ngx_palloc` ×3, `ngx_pnalloc` ×1 (`ngx_quic_alloc_buf`, L28), `ngx_alloc` ×2, `ngx_free` ×1; refcount shadow-буферов: `ngx_quic_buf_refs(b) = (b)->shadow->num` (L15) — **в `s3_buf_t` нет поля `num`**, добавить |
| 2 | ngx_connection_t | `c->log` ×12, `c->pool` ×7 |
| 3 | queue | `s3_queue_t` API 1:1 (insert_head/after/tail, remove, empty, head/last, `ngx_queue_data` → `s3_queue_data`) |
| 4 | ngx_log | `NGX_QUIC_DEBUG_ALLOC/PACKETS/FRAMES` отладка — за `#ifdef`, переносится как есть |
| 5 | buf API | `ngx_quic_buffer_t` (quic.h:71) + `read/write/skip/free_buffer` — ядро reassembly/буферизации; полностью переносимо |
| 6 | остальное | `ngx_min` ×4, `ngx_memcpy`, `ngx_memzero` |

### 1.3. `ngx_event_quic_protection.c` (1268) + `.h` (118)

| № | Зависимость | Факты по коду |
|---|-------------|---------------|
| 1 | OpenSSL | `#include <openssl/hkdf.h, chacha.h, kdf.h>`; `EVP_PKEY_HKDF` derive (expand/extract), `EVP_Cipher*` AEAD GCM, `EVP_aes_*`/`EVP_chacha*`, header protection `EVP_CIPHER_CTX_ctrl`; `HKDF_extract/expand` (quictls-ветка), `EVP_AEAD_*` + `CRYPTO_chacha_*` (BoringSSL-ветки) — **вырезать ветки**, оставить `NGX_QUIC_OPENSSL_API`/OpenSSL 3.5 |
| 2 | ngx_conf/cycle/connection | нет `c->` кроме `c->log` ×5 |
| 3 | quic-внутренние | `ngx_quic_keys_t` (protection.h:44), `ngx_quic_header_t` (decrypt/create packet), `ngx_str_t` |
| 4 | классификация | чистый: только `libcrypto` + типозамена; самодостаточен для юнит-тестов (RFC 9001 векторы) |

### 1.4. `ngx_event_quic_tokens.c` (265) + `.h` (34)

| № | Зависимость | Факты по коду |
|---|-------------|---------------|
| 1 | OpenSSL | `RAND_bytes`, `EVP_Encrypt/Decrypt*` (AES-GCM, `EVP_CTRL_AEAD_SET/GET_TAG`), `EVP_aes_*` — retry-token и address-token |
| 2 | ngx_connection_t | `c->log` ×5, `c->sockaddr/socklen` ×1 (validate_token: привязка токена к адресу) |
| 3 | quic-внутренние | `conf->av_token_key/sr_token_key` (ключи из `s3_quic_conf_t`), `ngx_quic_header_t` (retry itag) |
| 4 | классификация | чистый (libcrypto) |

### 1.5. `ngx_event_quic_connid.c` (501) + `.h` (29)

| № | Зависимость | Факты по коду |
|---|-------------|---------------|
| 1 | OpenSSL | `RAND_bytes` (L29, генерация server CID) |
| 2 | palloc | `ngx_pcalloc` ×1 |
| 3 | ngx_connection_t | `c->log` ×4, `c->pool` ×1 |
| 4 | BPF | `ngx_quic_bpf_attach_id` (L16-56) — под `#if (NGX_QUIC_BPF)`, не определяем |
| 5 | queue | client_ids/free-очереди, `ngx_queue_data` |
| 6 | классификация | чистый |

### 1.6. `ngx_event_quic_output.c` (1405) + `.h` (40)

| № | Зависимость | Факты по коду |
|---|-------------|---------------|
| 1 | os-слой | `ngx_sendmsg(c, &msg, 0)` ×2 (L472, L754) — в ssh3-c уже есть `s3_sendmsg` (`src/os/unix/s3_udp_sendmsg_chain.h:30`); GSO: cmsg `SOL_UDP`/`UDP_SEGMENT` (L455, `ngx_quic_send_segments` L420) + статический буфер 65 КБ (`NGX_QUIC_MAX_UDP_SEGMENT_BUF` L13, `NGX_QUIC_MAX_SEGMENTS` 64 L14); `NGX_HAVE_ADDRINFO_CMSG`: `ngx_get/set_srcaddr_cmsg` (L432-446) — **аналога в src/os/unix нет**, добавить `s3_get/set_srcaddr_cmsg` |
| 2 | ngx_connection_t | `c->log` ×24, `c->sockaddr/socklen` ×6+6, `c->local_sockaddr` ×4, `c->listening` ×4 (`listening->wildcard` для ADDRINFO cmsg), `c->sent` ×2, `c->read` ×2 |
| 3 | event/timers | `ngx_add_timer(&qc->push, ...)` ×4 (retry EAGAIN, L386 и др.), `ngx_current_msec` ×5 |
| 4 | congestion/flow | `cg->in_flight + (p - dst) < cg->window` (L411) — лимит отправки; `ngx_quic_commit_send` (L203): кадры с `pkt_need_ack==0` **освобождаются сразу**, не попадают в `ctx->sent` и `in_flight` (L228-233) — ключ к DATAGRAM (§3.3) |
| 5 | crypto | `RAND_bytes` ×4 (stateless reset, retry, token dcid) |
| 6 | классификация | нужен s3_context + 2 os-хелпера; sendmsg/GSO-механика совместима с P1 |

### 1.7. `ngx_event_quic_ack.c` (1456) + `.h` (31)

| № | Зависимость | Факты по коду |
|---|-------------|---------------|
| 1 | event/timers | `ngx_current_msec` ×13, `ngx_add_timer` ×3, `ngx_del_timer` ×1, `ngx_post_event(&qc->lost, &ngx_posted_events)` ×5 (lost-обработчик откладывается в posted) |
| 2 | ngx_connection_t | `c->log` ×29, `c->ssl->handshaked` ×2 (L231, L1076 — игнор ACK до handshake) |
| 3 | очереди | `ctx->sent/sending/frames` — только queue-операции |
| 4 | ретрансмиссия | `ngx_quic_resend_frames` (L758, вызывается из L663 только для crypto-пространств) возвращает кадры из `ctx->sent` в `ctx->frames`; `ngx_quic_detect_lost` (L594) уважает `f->ignore_loss` (L893); PTO `ngx_quic_pto_handler` (L1103) только шлёт PING |
| 5 | math | `ngx_abs/min/max`, `ngx_memmove` (ranges) |
| 6 | классификация | нужен s3_context — но минимально: posted-очередь и таймеры уже есть в `s3_event_ctx_t`; `c->ssl->handshaked` заменяется полем QUIC-соединения |

### 1.8. `ngx_event_quic.c` (1523) + `.h` (151)

| № | Зависимость | Факты по коду |
|---|-------------|---------------|
| 1 | posted | глобальный `ngx_posted_events` ×5 + `ngx_post_event` ×5 → заменить на `ctx->posted_events` + `s3_post_event` (`src/event/s3_event.h:128`) |
| 2 | timers | `ngx_add_timer/del_timer` ×12, `ngx_current_msec` ×6 |
| 3 | connection lifecycle | `ngx_close_connection` (L620), `ngx_reusable_connection` (L349), `c->buffer` (датаграмма при run), `c->read/read->handler`, `c->udp`, `c->ssl` (L3/`handle_payload`: `c->ssl == NULL` → init), `c->pool/log` |
| 4 | hash | `ngx_sha1_init/update/final` (`ngx_quic_address_hash` L1478, соль для address-token) → замена: OpenSSL `SHA1()`/`EVP_Digest` (libcrypto уже есть) или перенос `ngx_sha1.c` |
| 5 | conf | `qc->conf->handshake_timeout`, `qc->conf->init` (streams hook), `qc->conf->shutdown` |
| 6 | rbtree/queue | streams tree init (L243-244), очереди qc |
| 7 | классификация | нужен s3_context: центральный оркестратор; public API (`ngx_quic_run/open_stream/finalize_connection/reset_stream/...`) — контракт для слоёв выше |

### 1.9. `ngx_event_quic_streams.c` (1824) + `.h` (44)

| № | Зависимость | Факты по коду |
|---|-------------|---------------|
| 1 | connection lifecycle | `ngx_get_connection(c->fd, log)` (L737), `ngx_close_connection` (L190, L804), `ngx_reusable_connection` ×5 (L735, 741, 807, 835, 1169), pool cleanup `ngx_pool_cleanup_add` (L811, handler `ngx_quic_stream_cleanup_handler`) |
| 2 | stream connection | `sc = qs->connection` — полноценный `ngx_connection_t` с `sc->recv/send/send_chain` (L762-764), `sc->read/write->handler`, `sc->data` (= `qs`); в ssh3-c `s3_connection_t.recv/send_chain` уже есть (`src/event/s3_connection.h:26-27`), роль `qs` сыграет `data` |
| 3 | posted | ×7 (init_stream_handler, push) |
| 4 | rbtree | `qc->streams.tree` + `ngx_quic_rbtree_insert_stream` (L109) |
| 5 | flow control | `ngx_quic_control_flow/update_flow/update_max_stream_data/update_max_data` (L37-41) — MAX_DATA/MAX_STREAM_DATA кадры |
| 6 | доставка | `ngx_quic_handle_stream_frame` → `ngx_quic_write_buffer(c, &qs->recv, ...)` (L1295) → `ngx_quic_set_event(qs->connection->read)` (L1329) — образец для DATAGRAM-доставки (§3.4) |
| 7 | conf | `qc->conf->init` (L625), `stream_buffer_size`, `stream_close_code`, `stream_reject_code_uni/bidi` |
| 8 | классификация | нужен s3_context — самый тяжёлый файл: lifecycle + flow control + два буфера на стрим |

### 1.10. `ngx_event_quic_migration.c` (1007) + `.h` (45)

| № | Зависимость | Факты по коду |
|---|-------------|---------------|
| 1 | timers | `ngx_current_msec` ×8, `ngx_add_timer/del_timer` (path_validation) |
| 2 | адресный текст | `ngx_sock_ntop` ×2 (L266, L442), `c->addr_text` ×3, `c->listening->addr_text_max_len` (L444), `path->addr_text/text` — в ssh3-c нет sock_ntop: добавить `s3_sock_ntop` в `src/os/unix` или хранить текст в path |
| 3 | ngx_connection_t | `c->log` ×18, `c->log_error` ×3 (уровень логирования MTU-сообщений — заменить константой `S3_LOG_INFO`), `c->sockaddr/socklen`, `c->udp`, `c->listening`, `c->pool` |
| 4 | output API | `ngx_quic_frame_sendto` (path challenge/response, MTU probes) |
| 5 | классификация | нужен s3_context; логика path validation/MTU самодостаточна |

### 1.11. `ngx_event_quic_socket.c` (237) + `.h` (28)

| № | Зависимость | Факты по коду |
|---|-------------|---------------|
| 1 | rbtree слушателя | `ngx_rbtree_delete(&c->listening->rbtree, &qsock->udp.node)` ×2 (L107, L158), `ngx_rbtree_insert` (L183) — qsock-узлы живут в rbtree слушателя |
| 2 | типы | `ngx_udp_connection_t` (встраивается в `ngx_quic_socket_t`, connection.h:137), `ngx_listening_t` |
| 3 | palloc | `ngx_pcalloc` ×2, `ngx_pnalloc` ×1 |
| 4 | ngx_connection_t | `c->pool/log/listening/udp/sockaddr/socklen` |
| 5 | классификация | нужен s3_context: `ngx_udp_connection_t`+`ls->rbtree` → собственная нода в `s3_udp_listen_t.rbtree` (§4.3) |

### 1.12. `ngx_event_quic_udp.c` (437)

| № | Зависимость | Факты по коду |
|---|-------------|---------------|
| 1 | cycle | `ngx_enable_accept_events((ngx_cycle_t *) ngx_cycle)` (L45), `ecf = ngx_event_get_conf(ngx_cycle->conf_ctx, ngx_event_core_module)` (L52, multi_accept), `ngx_cycle->log` (L125), `ngx_accept_disabled = ngx_cycle->connection_n / 8 - ngx_cycle->free_connection_n` (L220-221) — всё это не переносится, у ssh3-c другая модель |
| 2 | connection accept | `ngx_get_connection` (L231), `c->number = ngx_atomic_fetch_add(...)` (L309), `c->start_time` (L315), `c->addr_text` + `ls->addr_ntop/addr_text_max_len` (L321-332), `c->shared/type/listening/buffer` |
| 3 | lookup | **ключ = DCID пакета**, не sockaddr: `ngx_quic_get_packet_dcid` (L171, transport.c:509) → `ngx_quic_lookup_connection(ls, &key, ...)` (L415): rbtree по `ngx_crc32_long(key)` + `ngx_memn2cmp` против `qsock->sid.id`; новое соединение → `ls->handler(c)` → `ngx_quic_run(c, conf)` (http/v3/ngx_http_v3_request.c:75) |
| 4 | cmsg | `NGX_HAVE_ADDRINFO_CMSG` — wildcard: локальный адрес из cmsg (L137-158) |
| 5 | классификация | нужен s3_context; каркас recvmsg-цикла в P1 уже есть (`s3_event_recvmsg`, `src/event/s3_event_udp.c`), но там ключ — sockaddr; QUIC-версия требует **вторую стратегию ключа (DCID)** — см. §4.3 |

### 1.13. `ngx_event_quic_ssl.c` (996) + `.h` (19)

| № | Зависимость | Факты по коду |
|---|-------------|---------------|
| 1 | ngx_ssl-слой | `ngx_ssl_create_connection(qc->conf->ssl, c, 0)` (L914), `c->ssl->connection/no_wait_shutdown/handshaked`, `ngx_ssl_error` (ALERT-лог с OpenSSL-строкой ошибки), `ngx_ssl_connection_error` (L728) |
| 2 | OpenSSL QUIC API | ветка `NGX_QUIC_OPENSSL_API` (OpenSSL ≥3.5): `OSSL_DISPATCH qtdis[]` c `OSSL_FUNC_SSL_QUIC_TLS_{CRYPTO_SEND,CRYPTO_RECV_RCD,CRYPTO_RELEASE_RCD,YIELD_SECRET,GOT_TRANSPORT_PARAMS,ALERT}` (L868-890), `SSL_set_quic_tls_cbs` (L906), `SSL_set_quic_tls_early_data_enabled` (L913), `SSL_set_quic_tls_transport_params` (L974); общие: `SSL_do_handshake` (L705), `SSL_get_error` (L710), `SSL_is_init_finished` (L738), `SSL_provide_quic_data` (L839), `SSL_get_peer_quic_transport_params` (L511), `SSL_get0_alpn_selected` (L88, L497), `SSL_get_current_cipher` (L225, L433), `SSL_CTX_get_max_early_data` (L911); quictls/boringssl-ветки (`SSL_set_quic_method` L930 и др.) — **вырезать** |
| 3 | quic-внутренние | `ctx->crypto`-буфер (`ngx_quic_handle_crypto_frame`, header ssl.h), `ngx_quic_create_transport_params` + `SSL_set_quic_tls_transport_params`, sr_token (`ngx_quic_new_sr_token`), ALPN-проверка |
| 4 | классификация | нужен ssl-слой: `s3_ssl_t` (обёртка SSL_CTX) + per-connection SSL-состояние (§4.4) |

### 1.14. `ngx_event_quic_openssl_compat.c` (657) + `.h` (52)

Эмуляция QUIC-интерфейса для BoringSSL/wolfSSL/OpenSSL < 3.5 (свой SSL handshake-драйвер, TP-расширение через `SSL_extension_supported`, записи ключей). В ssh3-c не переносится: `NGX_QUIC_OPENSSL_COMPAT` не определяем (OpenSSL ≥3.5 — решение зафиксировано в `docs/DEPS-QUIC.md` §6). Единственное касание конфига — `ngx_quic_compat_ext_init(ngx_conf_t *cf, SSL_CTX *ctx)` (L81).

### 1.15. `ngx_event_quic_bpf.c` (1257), `.h` (20), `ngx_event_quic_bpf_code.c` (212), `bpf/*`

SO_ATTACH_REUSEPORT_EBPF-группы сокетов для worker-балансировки: `ngx_cycle_t` ×29 (`ngx_quic_bpf_get_conf(cycle)`, `cycle->old_cycle`, `ngx_get_conf(cycle->conf_ctx, ngx_core_module)` — L18-26), собственный nginx-модуль с conf-структурой, `ngx_listening_t` ×26, bpf-сисколлы. Зависит от инфраструктуры cycle/conf целиком. В P2 не переносится; при желании позже — свой механизм поверх `s3_udp_listen_t` (отдельная задача, не блокирует ничего).

### 1.16. `ngx_event_quic_connection.h` (329) — центральный заголовок

Собирает все quic-заголовки (L40-50); структуры `ngx_quic_connection_t` (L225-312), `ngx_quic_send_ctx_t` (L200-222: очереди `frames/sending/sent`, ranges ACK, crypto-буфер), `ngx_quic_socket_t` (L136: встраивает `ngx_udp_connection_t`), `ngx_quic_path_t` (L111), `ngx_quic_client_id_t/server_id_t`, `ngx_quic_streams_t` (L147: rbtree + счётчики/лимиты flow control), `ngx_quic_congestion_t` (L177). Макросы `ngx_quic_get_connection(c)` (L73: `(c)->udp` → socket → quic) и `ngx_quic_get_send_ctx` (L68). Переписывается на s3-типы (см. §4); сюда же добавляются DATAGRAM-поля (§3.5).

---

## 2. Рекомендуемый порядок переноса

Топологический: «чистые» файлы → ssl-слой → ядро → сеть → стримы → DATAGRAM. Что уже закрывает P0/P1: pool/palloc (`s3_palloc*`), buf/chain/shadow (кроме `num`), rbtree/queue, log (`s3_log_*` + уровни `S3_LOG_*` в `s3_base.h:39-55`), string (`s3_str_t`, `s3_memcpy/cpymem/memzero`), event ctx с epoll + таймеры + posted (`s3_event.h`), `s3_connection_t` с `recv`/`send_chain`, `s3_udp_sendmsg_chain` + `s3_sendmsg`, recvmsg + псевдо-коннекции.

| № | Инкремент | Содержимое | Что должно быть готово |
|---|-----------|------------|------------------------|
| 1 | **D1: парсер/крипто-фундамент** | `s3_quic_transport` (transport.c/.h), `s3_quic_frames` (frames.c/.h), `s3_quic_protection` (protection.c/.h), `s3_quic_tokens` (tokens.c/.h), `s3_quic_connid` (connid.c/.h) — «чистые» файлы, перенос типозаменой | P0/P1 — всё есть. Одно изменение базы: поле `num` (refcount) в `s3_buf_t` (`src/core/s3_buf.h:16`); в CMake `find_package(OpenSSL 3.5 REQUIRED)` |
| 2 | **D2: ssl-слой + ядро QUIC** | `s3_ssl` (SSL_CTX/SSL-обёртка), `s3_quic_ssl.c` (только OpenSSL-API-ветка), `s3_quic.c` + `s3_quic_connection.h` + `s3_quic.h` (конф/структуры/оркестрация) | posted/timers в `s3_event_ctx_t` (есть); `s3_connection_t.buffer` (datagram-буфер) и `ssl`-поле — добавить; SHA1 — через libcrypto; lifecycle-упрощения (§4.3) |
| 3 | **D3: сеть и надёжность** | `s3_quic_output.c` (GSO/сегменты/padding/retry/stateless reset), `s3_quic_ack.c` (loss/congestion/PTO), os-хелперы `s3_get_srcaddr_cmsg`/`s3_set_srcaddr_cmsg`, интеграция с `s3_udp_listen_t` (DCID-lookup вместо `ngx_event_quic_udp.c`) | `s3_sendmsg` (есть), `s3_udp_listen_t.rbtree` (есть, расширить, §4.3); решение по `addr_text` |
| 4 | **D4: стримы и миграция** | `s3_quic_streams.c` (flow control, open/close/reset/shutdown stream), `s3_quic_migration.c` (path validation, MTU discovery), idle-timeout | pool cleanup (`s3_pool_cleanup_t` есть), `s3_get_connection/s3_close_connection` (есть), `s3_sock_ntop` (добавить) |
| 5 | **D5: DATAGRAM (RFC 9221)** | наш собственный код поверх D1–D4 (§3) | весь транспорт; interop-цель фазы P2 |

Обратные зависимости, которые надо помнить: transport.h нужен protection.h/frames.h (типы фреймов), quic.h (`ngx_quic_conf_t`) нужен transport.c (`init_transport_params`) — поэтому `s3_quic.h` с конфигом переносится в D1 (заголовочно) или qcf-поля заменяются на `s3_quic_conf_t` сразу.

Контракт входа: слушающий UDP-сокет P1 → datagram → QUIC-lookup по DCID → новое: `s3_quic_run(c, conf)` (аналог `ngx_quic_run`, ngx_event_quic.c:201) → приложение получает стримы через `conf->init` и хендлер стримов.

---

## 3. DATAGRAM (RFC 9221) — план инкремента

nginx QUIC не имеет DATAGRAM. Все точки врезки определены по коду:

### 3.1. Transport parameter 0x0020 (max_datagram_frame_size)

| № | Файл | Место | Правка |
|---|------|-------|--------|
| 1 | `ngx_event_quic_transport.h` | TP-константы L117-133 | `#define NGX_QUIC_TP_MAX_DATAGRAM_FRAME_SIZE 0x20` |
| 2 | `ngx_event_quic_transport.h` | `ngx_quic_tp_t` L344-366 | поле `uint64_t max_datagram_frame_size;` |
| 3 | `ngx_event_quic_transport.c` | `ngx_quic_parse_transport_param` L1619 (вариант-кейсы varint L1638-1712) | case: varint → `tp->max_datagram_frame_size` (по образцу `NGX_QUIC_TP_MAX_IDLE_TIMEOUT` L1638/1668) |
| 4 | `ngx_event_quic_transport.c` | `ngx_quic_parse_transport_params` L1725 (цикл L1737-1766) | ничего: id-маска пропуска серверных TP — 0x0020 входит в varint-ветку |
| 5 | `ngx_event_quic_transport.c` | `ngx_quic_init_transport_params` L1986 | заполнить из `s3_quic_conf_t.max_datagram_frame_size` (если 0 — DATAGRAM выключен: TP не кодируем) |
| 6 | `ngx_event_quic_transport.c` | `ngx_quic_create_transport_params` L2030 | TLV-кодирование: varint id 0x20 + varint value (по образцу соседних TP) |
| 7 | `s3_quic.h` (наш) | аналог `ngx_quic_conf_t` L80-102 | поле `ngx_uint_t max_datagram_frame_size;` (напр. 1200…IPv6-MTU-6) |

### 3.2. Фреймы 0x30/0x31 (DATAGRAM, DATAGRAM_WITH_LENGTH)

| № | Файл | Место | Правка |
|---|------|-------|--------|
| 1 | `ngx_event_quic_transport.h` | FT-константы L58-90 | `#define NGX_QUIC_FT_DATAGRAM 0x30`, `#define NGX_QUIC_FT_DATAGRAM_WITH_LENGTH 0x31`; **обязательно** поднять `NGX_QUIC_FT_LAST` (L90) с `0x1E` до `0x31` — иначе varint-граница `if (varint > NGX_QUIC_FT_LAST)` (transport.c:764) отбросит кадр как неизвестный |
| 2 | `ngx_event_quic_transport.h` | union `ngx_quic_frame_s.u` L277-296 | `ngx_quic_datagram_frame_t { uint64_t length; }` (0x30: length = остаток пакета; 0x31: varint) |
| 3 | `ngx_event_quic_transport.c` | `ngx_quic_parse_frame` L744 (switch L780-1158) | два case: 0x30 — payload = `[pos, end)`, длина из границ; 0x31 — varint length + bounds-check; данные кладутся в `frame->data` (`ngx_quic_copy_bytes` L214) без offset/reassembly |
| 4 | `ngx_event_quic_transport.c` | `ngx_quic_frame_allowed` L1161, таблица масок L1173-1204 | две записи `/* DATAGRAM */ 0x1` — только 1-RTT (RFC 9221 §4: кадр запрещён в Initial/Handshake/0-RTT) |
| 5 | `ngx_event_quic_transport.c` | `ngx_quic_create_frame` L1281 | `f->need_ack = 0` для обоих типов (по образцу ACK L1296 / CONNECTION_CLOSE L1319); create-хелпер `ngx_quic_create_datagram` (0x31 — с varint длиной) |
| 6 | `ngx_event_quic.c` | `ngx_quic_handle_frames` L1176 (switch L1221-1360) | case → новый обработчик `ngx_quic_handle_datagram_frame` (наш код, §3.4) |

### 3.3. send_ctx, очереди, ACK/PTO — где «запрет ретрансмиссии» уже структурно выполняется

| № | Файл | Место | Факт |
|---|------|-------|------|
| 1 | `ngx_event_quic_output.c` | `ngx_quic_commit_send` L203, L228-233 | кадр с `pkt_need_ack==0` после отправки **освобождается**: не попадает в `ctx->sent`, не учитывается в `cg->in_flight` → нет ACK-учёта, нет loss-ретрансмиссии (`ngx_quic_detect_lost` L594 ходит только по `ctx->sent`), нет resend (`ngx_quic_resend_frames` L758 вызывается только для crypto-пространств, ack.c:663). DATAGRAM с `need_ack=0` наследует всё это автоматически — отдельный код не нужен |
| 2 | `ngx_event_quic_ack.c` | `ngx_quic_pto_handler` L1103 | PTO шлёт только PING — ретрансмиссии DATAGRAM не возникает |
| 3 | очереди | `ctx->frames`/`sending` (connection.h:210-212) | DATAGRAM живёт в application-пространстве `send_ctx[2]`, отдельный send_ctx не нужен |
| 4 | риск | `ngx_quic_create_segments`/`allow_segmentation` L336/L253 | GSO-сегментация считает `cg->in_flight + (p - dst) < cg->window` (L411) для всех кадров; DATAGRAM не должен блокироваться полным CWND от не-ack-трафика — проверить при бенче (§3.5) |

### 3.4. Доставка приложению (отправка и приём)

| № | Направление | Точка входа | Реализация |
|---|-------------|-------------|------------|
| 1 | приём | `ngx_quic_handle_datagram_frame` (новый, вызов из ngx_event_quic.c:1176) | payload (`frame.data` chain, `u.datagram.length`) → callback `conf->datagram_handler(c, data, len)` — новое поле `s3_quic_conf_t`. Без `ngx_quic_buffer_t`: DATAGRAM не упорядочивается и не собирается заново (кадр ≤ MTU). Образец результата — streams.c:1295-1329, но без буфера и `set_event` |
| 2 | отправка | новый public API `s3_quic_send_datagram(c, data, len)` (аналог `ngx_quic_reset_stream` в quic.h:137) | `ngx_quic_alloc_frame` (frames.c:197) + `u.datagram` + `frame->data` = `ngx_quic_copy_buffer` (frames.c:393) + `ngx_quic_queue_frame` (frames.c:299) → уйдёт через обычный `ngx_quic_output`; размер ограничен `min(TP_peer.max_datagram_frame_size, path->mtu - header)` — проверка в момент постановки |
| 3 | отмена/закрытие | `ngx_quic_close_connection`/`discard_ctx` (ngx_event_quic.c:470/1096) | ничего: не-ack-кадры освобождаются как остальные |

### 3.5. Flow control DATAGRAM и риски

| № | Пункт | Решение |
|---|-------|---------|
| 1 | Транспортный flow control | RFC 9221 flow control для DATAGRAM **не определяет** (никаких MAX_DATAGRAM_DATA кадров). Единственный транспортный лимит — `max_datagram_frame_size` (размер кадра) + congestion window. Лимит получателя — наша надбавка |
| 2 | Отправка | счётчик `qc->datagrams_in_flight` (наше поле в `ngx_quic_connection_t`, connection.h:225-312) с уменьшением по PTO-таймеру/ACK соседей — либо честный учёт в `cg->in_flight` с ручным возвратом. Минимум для P2: ограничение числа DATAGRAM на один push (`qc->push`) и уважение CWND по месту в `dst` |
| 3 | Приём | per-connection лимит очереди в ssh3-слое (политика: drop + счётчик, не CONNECTION_CLOSE — датаграммы допустимо терять) |
| 4 | PTO/ретрансмиссия | запрещены RFC 9221 §5; выполняется структурно через `need_ack=0` (§3.3) — **не** ставить DATAGRAM в очередь `ctx->sent` |
| 5 | Риск: quic-go | проверять, что сервер/клиент quic-go видит TP 0x0020 до первого кадра; клиентский TP — до handshake-complete |
| 6 | Риск: MTU | 0x30 без длины требует `length = end - pos` — в GSO-сегменте (`ngx_quic_create_segments`) кадр не должен разрезаться: `ngx_quic_split_frame` (frames.c:319) применять к DATAGRAM нельзя (по типу — исключить) |
| 7 | Изоляция кода | всё DATAGRAM-специфичное — в `s3_quic_transport.c` (парс/креате), `s3_quic.c` (handler), `s3_quic.h` (conf/API); фаззинг парсера с P2 (`PLAN.md` §4, P6) |

---

## 4. Замены при портировании (nginx → ssh3-c)

### 4.1. `ngx_cycle_t` / глобали → `s3_event_ctx_t`

Реальный набор чтений cycle из quic-кода мал:

| № | nginx | Читает | Замена в ssh3-c |
|---|-------|--------|-----------------|
| 1 | `ngx_posted_events` (глобальная очередь) | quic.c ×5, ack.c ×5, frames.c ×1, streams.c ×7 | `ctx->posted_events` + `s3_post_event`/`s3_event_process_posted` (`src/event/s3_event.h:126-138`); `ngx_quic_process_posted`-вызовы (streams.c:231) получают `ctx` |
| 2 | `ngx_add_timer/del_timer` (глобальное rbtree) | quic.c, ack.c, output.c, streams.c, migration.c | `s3_event_add_timer/del_timer` (`s3_event.h:123-124`) — сигнатуры совпадают |
| 3 | `ngx_current_msec` | ack.c ×13, quic.c, migration.c, output.c | `s3_current_msec` (`s3_event.h:106`) |
| 4 | `ngx_cycle->log` (udp.c:125) | recvmsg-лог | `lc->log` (есть в P1-версии) |
| 5 | `ngx_cycle->connection_n/free_connection_n` + `ngx_accept_disabled` (udp.c:220-221) | accept-throttling | не переносится: политики лимитов — дело ssh3-приложения; либо счётчик в `s3_event_ctx_t` при необходимости |
| 6 | `ngx_event_get_conf(cycle->conf_ctx, ngx_event_core_module)` (udp.c:52) | multi_accept | не нужен: `s3_event_recvmsg` читает до EAGAIN |
| 7 | `ngx_enable_accept_events` (udp.c:45) | реактивация после timedout | не нужен: P1 не отключает слушателя |
| 8 | `ngx_cycle->conf_ctx` (bpf) | bpf-модуль | не переносится (§1.15) |

Расширение `s3_event_ctx_t` для QUIC **не обязательно** — конфиг QUIC передаётся через `s3_quic_run(c, conf)` и хранится в `qc->conf`. Если удобнее глобально — поле `void *quic_conf`, но явная передача чище.

### 4.2. `ngx_quic_conf_t` (ngx_event_quic.h:80-102) → `s3_quic_conf_t`

Поля, реально читаемые кодом (grep `qc->conf->`, `qcf->`):

| № | nginx-поле | Кто читает | ssh3-c |
|---|------------|-----------|--------|
| 1 | `ssl` (ngx_ssl_t*) | ssl.c:914 | `s3_ssl_t *ssl` (§4.4) |
| 2 | `retry` | ssl.c (stateless retry-ветка) | `unsigned retry : 1` |
| 3 | `gso_enabled` | output.c:289 | `unsigned gso_enabled : 1` |
| 4 | `disable_active_migration` | transport.c:1986 (TP 0x0C) | то же |
| 5 | `handshake_timeout` | quic.c (close-таймер) | `s3_msec_t` |
| 6 | `idle_timeout` | transport.c:1986 (TP 0x01) | `s3_msec_t` |
| 7 | `host_key` | http/v3 модуль (генерация av/sr ключей) | `s3_str_t host_key` + генератор в нашем коде (nginx генерит в `ngx_http_v3_module.c:310-372`, не в quic/) |
| 8 | `stream_buffer_size` | transport.c:1986 (TP initial_max_stream_data), streams.c | `size_t` |
| 9 | `max_concurrent_streams_bidi/uni` | transport.c:1986 | `s3_uint_t` |
| 10 | `active_connection_id_limit` | transport.c:1986 (TP 0x0E) | `s3_uint_t` |
| 11 | `stream_close_code`, `stream_reject_code_uni`, `stream_reject_code_bidi` | streams.c (reject/close) | `s3_int_t` |
| 12 | `init` (`ngx_quic_init_pt`) | streams.c:625 (hook «streams ready») | `s3_quic_init_pt` |
| 13 | `shutdown` (`ngx_quic_shutdown_pt`) | quic.c | `s3_quic_shutdown_pt` |
| 14 | `av_token_key[32]`, `sr_token_key[32]` | output.c (stateless reset), ssl.c:956 (sr_token), tokens.c | массивы `u_char` (заполняет наш код из `host_key`) |
| 15 | **новое (DATAGRAM)** | — | `s3_uint_t max_datagram_frame_size; s3_quic_datagram_pt datagram_handler;` |

nginx-директив (`quic_retry`, `quic_gso` и т.д.) в quic/ отсутствуют — их парсит http/v3-модуль; ssh3-c заполняет `s3_quic_conf_t` из своего конфигуратора (CLI/файл), парсер директив писать не нужно.

### 4.3. `ngx_connection_t` → `s3_connection_t`

Поля, которые QUIC-код реально читает/пишет (сводка grep `c->` по всем файлам):

| № | Поле nginx | Есть в `s3_connection_t`? | Действие |
|---|------------|---------------------------|----------|
| 1 | `log`, `read`, `write`, `fd`, `pool`, `sockaddr`, `socklen`, `local_sockaddr`, `local_socklen`, `sent` | да (`s3_connection.h:18-46`) | без изменений |
| 2 | `data` | да | для stream-connection здесь живёт `ngx_quic_stream_t` (вместо nginx-поля `sc->quic`) |
| 3 | `udp` | да, но тип другой: `struct s3_udp_connection_s *` | в nginx `c->udp` → `ngx_quic_socket_t` (макрос `ngx_quic_get_socket`, connection.h:76); у ssh3-c — узел P1. Переписать: `ngx_quic_socket_t` встраивает `ngx_udp_connection_t{node, connection}` + `quic`-указатель + `sid` + `sockaddr` → сделать `s3_quic_socket_t` с `s3_rbtree_node_t node; s3_connection_t *connection; s3_quic_connection_t *quic; s3_quic_server_id_t sid;` и регистрировать его в `s3_udp_listen_t.rbtree` вместо P1-ноды |
| 4 | `buffer` | нет | добавить `s3_buf_t *buffer` — входная датаграмма (`ngx_quic_run` → `ngx_quic_handle_datagram(c, c->buffer, conf)`, ngx_event_quic.c:208; `c->udp->buffer` для повторных, udp.c:222) |
| 5 | `ssl` | нет | `s3_ssl_conn_t *ssl` (§4.4) — handshake-стейт + `handshaked` |
| 6 | `listening` | нет | читается ради `rbtree` (socket.c:107/158/183), `wildcard` (output.c:446), `addr_text_max_len` (migration.c:444), `handler` (streams.c:574) → замена: у QUIC-сокета прямые ссылки (`s3_udp_listen_t *listen`), handler приложения — в `s3_quic_conf_t` |
| 7 | `addr_text` | нет | migration.c/udp.c — логирование. Вариант: `u_char addr_text[S3_SOCKADDR_STRLEN]` в `s3_quic_path_t` (там уже есть `text/addr_text`, connection.h:129-130) и в конфиге лога; либо добавить поле в connection |
| 8 | `number`, `start_time` | нет | только логи/статистика — дропнуть или `uint64_t number` |
| 9 | `reusable`, `idle`, `destroyed`, `close`, `type`, `log_error` | нет | lifecycle nginx-воркера: `ngx_reusable_connection` ×6 (streams.c/quic.c) заменяется флагом в `s3_quic_connection_t` (учёт в shutdown-условии `can_shutdown`); `log_error` → константный уровень |
| 10 | `shared` | да | ok |

### 4.4. `ngx_ssl_t` / `ngx_ssl_connection_t` → `s3_ssl_t` / `s3_ssl_conn_t`

ssl.c требует от ssl-слоя минимум (по вызовам):

| № | Функция ssl.c | Что нужно в ssh3-c |
|---|---------------|---------------------|
| 1 | `ngx_ssl_create_connection(qc->conf->ssl, c, 0)` (L914) | `s3_ssl_t` = держатель `SSL_CTX*` (+ ALPN-протокол, cert/key); `s3_ssl_conn_t` = `SSL *connection; unsigned handshaked:1; unsigned no_wait_shutdown:1;` + привязка к `s3_connection_t` |
| 2 | `SSL_set_quic_tls_cbs(ssl_conn, qtdis, c)` (L906) | OpenSSL ≥3.5: `OSSL_DISPATCH`-таблица c шестью колбэками (`OSSL_FUNC_SSL_QUIC_TLS_*`, L868-890) — колбэки quic.c/ssl.c реализуют через `ctx->crypto`-буфер и `ngx_quic_keys_*` |
| 3 | `SSL_set_quic_tls_transport_params` (L974), `SSL_get_peer_quic_transport_params` (L511) | без обёрток, прямой вызов |
| 4 | `SSL_do_handshake` (L705) + `SSL_get_error` (L710) + `SSL_is_init_finished` (L738) | неблокирующий handshake-луп, `SSL_ERROR_WANT_READ/WRITE` → ожидание CRYPTO |
| 5 | `SSL_provide_quic_data` (L839) | подача `ctx->crypto`-буфера по уровням |
| 6 | `SSL_get0_alpn_selected` (L88/497) | ALPN-проверка протокола ssh3 |
| 7 | `SSL_get_current_cipher` (L225/433) | выбор HP/AEAD-параметров (у нас фиксируются protection.c) |
| 8 | `SSL_CTX_get_max_early_data` (L911) + `SSL_set_quic_tls_early_data_enabled` (L913) | 0-RTT |
| 9 | `ngx_ssl_error` / `ngx_ssl_connection_error` | свой `s3_ssl_error(log, ...)` на `ERR_get_error`/`ERR_error_string_n` |

Веточные макросы `NGX_QUIC_QUICTLS_API`/`NGX_QUIC_BORINGSSL_API`/`NGX_QUIC_OPENSSL_COMPAT` (ngx_event_quic.h:15-28) — оставить только `NGX_QUIC_OPENSSL_API` (требование CMake: OpenSSL ≥3.5, см. `docs/DEPS-QUIC.md` §7).

### 4.5. Прочие замены

| № | nginx | ssh3-c |
|---|-------|--------|
| 1 | `ngx_buf_t.shadow->num` refcount (frames.c:15) | добавить `int num;` в `s3_buf_t` (`src/core/s3_buf.h`) — единственная правка P0-базы |
| 2 | `ngx_sendmsg(c, &msg, 0)` | `s3_sendmsg` (уже есть, `src/os/unix/s3_udp_sendmsg_chain.h:30`) |
| 3 | `ngx_get_srcaddr_cmsg` / `ngx_set_srcaddr_cmsg` (IP_PKTINFO/IPV6_RECVPKTINFO) | добавить в `src/os/unix/` (используются recvmsg-wildcard и GSO-отправка) |
| 4 | `ngx_sha1_*` (quic.c:1478 address-hash) | OpenSSL `SHA1()` из libcrypto (или перенос `ngx_sha1.c` — однофайловый, BSD) |
| 5 | `RAND_bytes` | прямой вызов (libcrypto) — уже так в nginx |
| 6 | `ngx_sock_ntop` | новый `s3_sock_ntop` в `src/os/unix` (нужен migration.c, udp.c) |
| 7 | `ngx_atomic_fetch_add` (udp.c:309 счётчик соединений) | дропнуть/заменить обычным `++` (однопоточный event-loop) |
| 8 | `ngx_crc32_long` + `ngx_memn2cmp` (udp.c:401/419 DCID-lookup) | `s3_crc32_long`/сравнение — добавить в core или сравнивать байты rbtree-компаратором (P1-модель `s3_udp_key_cmp` меняется на сравнение sid) |
| 9 | `ngx_socket_errno`, `NGX_EAGAIN` | `s3_socket_errno`, `S3_EAGAIN` (есть, `src/os/unix/s3_errno.h`) |
| 10 | `c->log->action = "..."` (quic.c ×10, quic_ssl.c) | упрощённый `s3_log_t` не имеет action — дропнуть строки или добавить `const char *action` в `s3_log_t` (решить в D2) |
| 11 | `NGX_HAVE_UDP_SEGMENT`/`NGX_HAVE_MSGHDR_MSG_CONTROL`/`NGX_HAVE_ADDRINFO_CMSG` | CMake feature-тесты (аналог nginx auto/feature) → `S3_HAVE_*` |
| 12 | префиксы `ngx_quic_*` → `s3_quic_*`, `NGX_QUIC_*` → `S3_QUIC_*` | механическая замена, кроме имён RFC-констант (TP/FT/ERR можно оставить `S3_QUIC_TP_*`…) |

### 4.6. Отличия от nginx, появившиеся в D3 (клиентская роль)

nginx — только сервер, поэтому четыре места в перенесённом коде «зашиты» под серверную роль и требуют явной правки, как только появляется клиент:

| № | Место | nginx | ssh3-c |
|---|-------|--------|--------|
| 1 | слоты ключей, `s3_quic_keys_set_encryption_secret()` / `s3_quic_keys_available()` | `is_write` = 1 → серверный слот (клиента не бывает) | `is_write` — направление TLS: слот выбирается как `is_write == keys->is_client`; иначе клиент читает серверные секреты и наоборот |
| 2 | `s3_quic_keys_set_initial_secret()` / `s3_quic_keys_update()` | клиентский слот всегда на чтение, серверный на запись | направление `enc` выводится из `keys->is_client` |
| 3 | `HANDSHAKE_DONE` (0x1e) | таблица разрешённых фреймов запрещает фрейм всем типам пакетов: сервер его не получает | клиент принимает ровно один раз в 1-RTT, подтверждает handshake и сбрасывает handshake-ключи (`handshake_confirmed`) |
| 4 | `CRYPTO` после handshake | отвергается всегда | отвергается только сервером; клиент принимает `NewSessionTicket` и прогоняет `SSL_do_handshake()` в `s3_quic_post_handshake()` |

Отдельно: короткий заголовок не несёт длину DCID, поэтому парсер читает ровно `S3_QUIC_SERVER_CID_LEN` байт, а клиент обязан генерировать CID той же длины (иначе расходится смещение выборки для header protection — симптом: TX-смещение 21 против RX 25).

---

## 5. Оценка объёма

Строки (wc -l референса, всего 17538, включая bpf 1489):

| № | Класс | Файлы | Строк (.c+.h) | Доля |
|---|-------|-------|---------------|------|
| 1 | «Чистые» (D1) | transport, frames, protection, tokens, connid | 5768 | 33 % |
| 2 | s3_context (D2–D4) | quic.c, ack.c, streams.c, migration.c, socket.c, connection.h, quic.h | 7112 | 41 % |
| 3 | s3_context + os (D3) | output.c, udp.c | 1882 | 11 % |
| 4 | ssl-слой (D2) | ssl.c/.h | 1015 | 6 % |
| 5 | Не переносится | openssl_compat, bpf (.c/.h/code) | 2198 | 12 % |

Итого адаптации: **≈ 15.3k строк** (85 % референса), из них механической типозамены — треть; плюс DATAGRAM-надбавка ≈ 400–600 строк нашего кода (§3) и os-хелперы ≈ 150 строк.

Разбивка P2 на сессии (опыт P0/P1: инкремент ≈ 1–2 сессии с тестами):

| № | Инкремент | Сессий | Критерий приёмки |
|---|-----------|--------|------------------|
| 1 | D1 парсер/крипто | 1–2 | юнит-тесты: varint/фреймы roundtrip; HKDF/AEAD-векторы RFC 9001; TP parse/create roundtrip; `ctest` release+asan чисто |
| 2 | D2 ssl+ядро | 2–3 | QUIC-handshake C-клиент ↔ quic-go (Initial+Handshake+1-RTT), ключи переключаются, TP обменяны |
| 3 | D3 сеть/надёжность | 2–3 | bulk 1 GiB loopback ≥ 250 MB/s (`PLAN.md` P2); потеря 5 % пакетов — соединение доживает (loss recovery); GSO on/off сравнение |
| 4 | D4 стримы/миграция | 2–3 | stream echo quic-go ↔ C в обе стороны; flow control блокируется/расширяется (MAX_DATA); смена адреса → path validation; idle-timeout |
| 5 | D5 DATAGRAM | 1–2 | datagram roundtrip Go ↔ C (интероп `PLAN.md` P2); TP 0x0020 виден обеим сторонам; кадр 0x31 в Initial отвергается; ретрансмиссия DATAGRAM отсутствует (проверка по логу pnum) |
| — | **Итого P2** | **8–13** | финально: ASan/UBSan чисто, фаззинг парсеров запущен, `memory_save` финализации |

Крупнейшие риски объёма: `ngx_event_quic_streams.c` (1824 строки — lifecycle + flow control, самая плотная интеграция с connection-lifecycle), `ngx_event_quic_transport.c` (2215 — но переносится легко), и udp.c/socket.c — переосмысление под P1-модель rbtree (уникальная работа, не типозамена).
