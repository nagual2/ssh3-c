# ssh3-c — архитектура (nginx-style, zero-copy)
> Languages: RU (this file) · [EN](ARCHITECTURE.en.md) · [DE](ARCHITECTURE.de.md)

Создан: 2026-10-01. Родительский трек: `project/ssh3/docs/ROADMAP.md`, профиль: `project/ssh3/docs/PROFILE-2026-09-29.md`.
Референс стиля: nginx 1.31.7 (`C:\Git\temp\ssh3-c\refs\nginx\` — read-only).

## 1. Цель и мотивация

Переписать SSH3-транспорт с Go на чистый C (C17) в архитектурном стиле nginx. Целевая позиция — занять в системах Linux место, аналогичное OpenSSH: базовые библиотеки, пермиссивная лицензия, пакетирование в дистрибутивы. Цели: **скорость** (bulk ≥ Go-версии, цель — сравняться с SSH2 365–488 MB/s) и **объём** бинарника (<5 MB против ~15 MB Go). Принцип — zero-copy на всём data-path.

Мотивация из профиля Go-версии (loopback, push 1 GiB):

| Точка потерь | Доля CPU | Что делает C-версия |
|---|---|---|
| UDP syscall-шторм (`sendQueue.Run→WritePacket`) | 39%/25% | GSO `UDP_SEGMENT` + sendmsg-chain поверх существующих буферов (как `ngx_quic_create_segments`) |
| `runtime.memmove` | 5–6.5% | вьюхи `s3_buf_t`/`s3_chain_t` вместо копий, парсер читает `pos/end` |
| GC/аллокации | 7–15% | арена-пулы per connection/stream, freelist буферов |
| goroutine-модель (`schedule` 13%, `selectgo` 4%) | ~17% | один event loop, posted events, без потоков на поток |
| AES-GCM | ~3% | невиновен, AES-NI |

Контрольные числа: raw quic-go 326 MB/s; Go ssh3 130→175 MB/s (после пулов); OpenSSH 365–488 MB/s.

## 2. Ключевые решения

| № | Решение | Обоснование |
|---|---------|-------------|
| 1 | Язык: **C17 (чистый C)**, как nginx и OpenSSH; коды возврата `S3_OK/S3_ERROR/S3_AGAIN`, префикс `s3_`/`S3_` | оба референса написаны на C; цель «место OpenSSH» исключает зависимость от libstdc++ (нет даже в базовом Alpine); C-ABI стабилен для пакетов. Заменил прежнее решение «C20» 2026-10-01 |
| 2 | QUIC-стек: адаптация `src/event/quic/` nginx (BSD-2) под наш core/event слой, не написание с нуля | nginx QUIC боепротестирован (v1, RFC 9000/9001/9002), стиль уже nginx; свой стек = месяцы протокольных багов |
| 3 | HTTP/3: минимум из `src/http/v3/` — extended CONNECT (`:protocol=ssh3`), QPACK (parse/encode/table), uni-стримы. Data-path каналов — сырые QUIC bidi-стримы, h3-фрейминг на данных отсутствует | карта протокола Go-версии: 1 HEADERS + N raw streams + QUIC datagrams |
| 4 | UDP I/O: `sendmsg`-chain + `UDP_SEGMENT` GSO на отправке; приём `recvmsg` по датаграмме + псевдо-коннекции в rbtree (модель `ngx_quic_recvmsg`) | паттерн `ngx_udp_sendmsg_chain.c` + `ngx_event_quic_output.c`; UDP_GRO — за фича-флагом (nginx его не использует) |
| 5 | Wire-совместимость с Go-форком v0.1.21 (протокол `SSH 3.0 alpha-00`): interop-тесты «C клиент ↔ Go сервер» и «Go клиент ↔ C сервер» — приёмочный критерий M4+ | транспорт — замена, протокол тот же |

## 3. Слои (проекция структуры nginx)

```
src/core/     s3_pool (арена, bump+large+cleanup), s3_str (len+data),
              s3_buf/s3_chain (вьюхи+флаги+freelist), rbtree/queue/log,
              s3_connection (полиморфизм I/O через указатели функций)
src/event/    event loop (find_timer→poll→posted_accept→timers→posted),
              backend epoll (Linux) [+kqueue за флагом], таймеры rbtree
src/os/unix/  recv/send, udp_sendmsg_chain (+GSO cmsg), errno-обёртки
src/quic/     адаптация nginx: transport (varint, frames, TP), frames
              (ordered, shadow-buf refcount), ack/loss/cc, connid, output
              (GSO segments), protection (keys, HKDF), ssl (OpenSSL 3.5
              QUIC API / quictls / boringssl), streams, tokens, migration
src/h3/       parse/encode (varint, frames, QPACK), table (static+dynamic),
              uni (control/encoder/decoder), CONNECT-обработка
src/ssh3/     conversation (control stream, accept-очередь каналов),
              channel (header, WriteData, datagrams), message (varint+SSHString),
              auth (Basic/Bearer-JWT/known_hosts TOFU)
src/app/      CLI клиент+сервер, PTY (.termios/ConPTY), sftp-канал, forwarding
```

Зависимости: OpenSSL 3.5+ (QUIC API) или quictls/boringssl; Linux первым (GSO, PTY), Windows — следом (ConPTY, без GSO → обычный sendmsg).

## 4. Zero-copy правила (обязательные)

1. Строка/поле протокола = вьюха (`s3_str_t{len,data}`) над приёмным буфером; владение переходит только явно.
2. Парсер: `u_char *pos, *end`, без промежуточных аллокаций (паттерн `ngx_quic_parse_int`).
3. Отправка: `s3_chain_t` поверх памяти протокольного слоя; `sendmsg` собирает `iovec` без копий (`ngx_output_chain_to_iovec` — склейка смежных).
4. QUIC-буферы: shadow-buf с refcount + freelist (`ngx_quic_alloc_buf/free_buf`, `buf_refs`).
5. Пул на соединение/канал; мелкие аллокации не освобождаются поштучно; cleanup-хендлеры для fd.
6. `ParseSSHString` из Go (2 alloc+2 copy на сообщение) запрещён по построению.

## 5. Wire-протокол (совместимость с Go-форком)

Транспорт: QUIC v1, `Allow0RTT`, datagrams включены; настройки из `cmd/ssh3-server.go`: `InitialPacketSize=1350`, окна stream 8/16 MiB, conn 16/32 MiB.

Control stream: extended CONNECT, `:protocol=ssh3`, путь `/ssh3-term?user=...`, `Authorization: Basic|Bearer`, `User-Agent: SSH 3.0 ...`; сервер: 403 — версия, 425 — 0-RTT anti-replay.

Канал = raw bidi QUIC stream, **ChannelID = QUIC Stream ID**. Заголовок канала:
`varint 0xaf3627e6 | varint controlStreamID | SSHString type | varint maxPacketSize` (+ для `direct-*`: `varint family, raw IP 4|16, uint16be port`). Типы: `session`, `direct-tcp`, `direct-udp`, `sftp`, `agent-connection`.

Сообщения канала (все целые — QUIC varint; SSHString = varint-len + байты):
`91 open_confirmation{varint maxPacketSize}`, `92 open_failure{varint reason, SSHString err, SSHString lang}`, `94 data{SSHString}`, `95 extended_data{varint dataType, SSHString}`, `98 request{SSHString type, u8 wantReply, тело}` — pty-req/shell/exec/subsystem/window-change/signal/exit-status/exit-signal (поля — см. `project/ssh3/message/channel_request.go`). Неизвестный тип = ошибка канала (не panic).

Датаграмма (QUIC DATAGRAM): `varint controlStreamID | varint channelID | payload`.

Fixed от Go-багов: `wantReply`-запросы без ответов (99/100 не реализованы) — не воспроизводить, поддержать приём обеих сторон; `-packet-size`/`-stream-rx-mb` на клиенте были мёртвыми — в C флаги либо работают, либо их нет.

## 6. Этапы разработки

План разработки клиента и сервера — фазы P0–P8 — живёт в [docs/PLAN.md](PLAN.md) (источник истины по плану; прежняя таблица M0–M6 поглощена им).

## 7. Риски

| № | Риск | Митигция |
|---|------|----------|
| 1 | Адаптация nginx QUIC тянет `ngx_cycle`-зависимости | переносить послойно, начиная с transport/frames/protection; cycle заменить на s3_context; держать список отличий в docs/PORTING-nginx-quic.md |
| 2 | OpenSSL 3.5 QUIC API ещё не везде; quictls — неапстримный бранч | ssl-слой как в nginx: 3 API-варианта за фича-флагами; по умолчанию quictls |
| 3 | 0-RTT и анти-реплей | скопировать модель Go (425 Too Early) + RFC 9002 |
| 4 | Windows-порт (ConPTY, отсутствие UDP_SEGMENT) | M0–M5 только Linux/WSL; Windows после паритета, sendmsg без GSO |
| 5 | Дрейф wire-формата между Go и C версиями | interop-тесты в CI обеих направлений на каждый релиз; wire-векторы из `wire_vectors_test.go` как фикстуры |
