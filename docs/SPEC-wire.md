# SPEC-wire: спецификация wire-протокола SSH3 — rev nagual2/1 (draft 1)
> Languages: RU (this file) · [EN](SPEC-wire.en.md) · [DE](SPEC-wire.de.md)

Дата: 2026-10-16. Статус: первая редакция волны P8-0, выверена по живому коду обеих реализаций.

## Источники и статус документа

Спека описывает **wire-протокол, который реально говорят две живые реализации SSH3**:

- эталон: форк `nagual2/ssh3` 0.1.35 (Go, поверх quic-go; форк апстрима `francoismichel/ssh3`);
- реализация: `ssh3-c` 0.3.0 (C17, nginx-стиль, поверх OpenSSL ≥3.5 QUIC API).

Принцип (решение владельца 2026-10-16): апстрим мёртв, IETF-трек закрыт; спека — документ проекта.
Остов — публичный текст истёкшего draft-michel-remote-terminal-http3-00 (с атрибуцией в §14);
где живой протокол расходится с драфтом — расхождения сведены в §14. Дистиллят жизненного
цикла каналов: `docs/P4-WIRE.md` (перенесён сюда; P4-WIRE остаётся историческим документом
волны 2). Формы записей: конвенции RFC 2119 (MUST/SHOULD/MAY); все целые — QUIC varint
(RFC 9000 §16, 1/2/4/8 байт, 2-битовый префикс длины); строки — SSHString: varint-длина +
сырые байты (в отличие от SSH2 — uint32-BE-длина).

## 1. Транспортная модель

Протокол живёт поверх QUIC (RFC 9000/9001) и HTTP/3 (RFC 9114). Роли:

| Слой | Содержание |
|------|------------|
| QUIC | Транспорт, TLS 1.3, надёжные стримы, flow control, ДАТАГРАММЫ RFC 9221 (TP `max_datagram_frame_size`, ID 0x0020) |
| HTTP/3 | Extended CONNECT (RFC 8441/9114 §4.4) для установления сессии; uni-стримы H3 (control/QPACK) — стандартные, в SSH3-семантике не участвуют |
| SSH3 | Каналы RFC 4254-семантики поверх bidi-стримов QUIC; датаграммный роутинг поверх QUIC DATAGRAM |

Правила диспетчеризации bidi-стримов:

| № | Сторона | Правило |
|---|---------|---------|
| 1 | Сервер | Первый принятый bidi-стрим коннекции — всегда HTTP/3 request-стрим (клиент шлёт CONNECT раньше каналов); все последующие bidi — SSH3-каналы, первый varint обязан быть `0xaf3627e6` |
| 2 | Сервер | Uni-стримы — всегда HTTP/3 (control/QPACK); SSH3 uni-стримов не имеет |
| 3 | Клиент | Все исходящие bidi после CONNECT-стрима — каналы; входящие bidi от сервера — всегда каналы (сервер открывает их только после 200) |

## 2. Установление сессии (CONNECT-запрос)

Клиент открывает первый bidi-стрим и отправляет HTTP/3 extended CONNECT:

| Элемент | Значение |
|---------|----------|
| `:method` | `CONNECT` (extended, с `:protocol`) |
| `:protocol` | `ssh3` — ssh3-c проверяет равенство, fork допускает любой `:protocol` (debug-log) |
| `:scheme` | `https` |
| `:authority` | хост:порт сервера |
| `:path` | `/ssh3-term` (параметры: `?user=<username>`, `?mux=1` для ControlMaster) |
| `User-Agent` | строка версии (§3) |
| `Authorization` | auth-материал (§7) |

Username берётся из `?user=` или userinfo URL. После 200 стрим остаётся открытым и служит
**control stream'ом conversation**; полезных SSH3-кадров по нему нет.

Ответы сервера:

| Код | Причина |
|-----|---------|
| 200 | Сессия установлена; заголовок `Server` несёт версию сервера (§3) |
| 401 | Нет `Authorization` или схема не поддержана |
| 403 | Версия не поддержана (`User-Agent` не парсится или protocol/spec не совпадают) |
| 425 | Запрос в 0-RTT до завершения хендшейка (RFC 8470) — клиент обязан повторить после handshake |
| 400 | Отсутствуют `:scheme`/`:authority` (RFC 9114 §4.4; гейт ssh3-c) |

Негативный ответ сопровождается заголовком версии сервера; клиент при 403, если серверная
protocol-version != текущей, ищет совпадение среди известных ему реализаций и повторяет
запрос совместимой версией (fallback-логика эталона).

## 3. Строка версии (User-Agent / Server)

Формат, whitespace-separated поля:

```
SSH <major>.<minor>[_<spec>] <impl-name> <sw-major>.<sw-minor>.<sw-patch>[ experimental_spec_version=<spec>] [key=value ...]
```

- Текущая спецификация: `SSH 3.0` + `experimental_spec_version=alpha-00`
  (fork: `SSH 3.0 francoismichel/ssh3 0.1.35 experimental_spec_version=alpha-00`;
  ssh3-c: `SSH 3.0 ssh3-c 0.3.0 experimental_spec_version=alpha-00`).
- Разбор: ≥4 полей; поле ≥5 со знаком `=` читается как extra (сейчас только
  `experimental_spec_version`); прочие extras игнорируются.
- Проверка поддержки: protocol major/minor обязаны совпадать (3.0); без
  `experimental_spec_version` принимаются только legacy-реализации апстрима 0.1.3–0.1.5;
  иначе spec обязан быть `alpha-00`.
- Spec-версия может также ехать внутри поля протокола: `3.0_alpha-00`.

## 4. Conversation и каналы

**Conversation** = пара (control stream, QUIC-коннекция). Идентификатор conversation —
32 байта из TLS-экспортера с label `EXPORTER-SSH3`; на wire не передаётся, используется
для auth-привязки (JWT nonce/анти-replay) и логов. Одна QUIC-коннection — одна conversation.

**Канал** = один bidi-стрим QUIC. **ChannelID == QUIC StreamID канала** — отдельного
нумератора нет. Первый блок стрима — заголовок канала:

```
Channel Header {
  frame_type (i) = 0xaf3627e6,
  conversation_stream_id (i),   # == StreamID control stream'а; получатель сверяет со своим
  channel_type (..),            # SSHString
  max_packet_size (i),
  [target_extension]            # только для forward-типов (§6)
}
```

Типы каналов (SSHString):

| Тип | Кто открывает | Смысл |
|-----|---------------|-------|
| `session` | клиент | интерактивная сессия/pty/exec/shell |
| `direct-tcp` | клиент | форвард TCP к цели через сервер |
| `direct-udp` | клиент | форвард UDP (датаграммный путь, §5) |
| `sftp` | клиент | файловая подсистема (fork; в ssh3-c отдельный модуль) |
| `agent-connection` | сервер | входящее соединение к ssh-agent клиента (fork; ssh3-c: принимает, тип через data-маркер `forward-agent`) |
| `reverse-forward` | клиент | контроль-канал `-R`: bind-запрос/ответ как channel data (§9) |
| `forwarded-tcp` | сервер | сервер-инициированный TCP-канал для reverse-форварда |
| `forwarded-udp` | сервер | сервер-инициированный UDP-канал для reverse-форварда |
| `dynamic-forward` | клиент | SOCKS-контроль (-D) (fork-only) |
| `dynamic-forward-tcp` | сервер | TCP-канал SOCKS-форварда (fork-only) |

**Target extension** (только `direct-*` и `forwarded-*`), сразу после `max_packet_size`:

```
Target Extension {
  address_family (i),   # 4 = IPv4, 6 = IPv6
  ip (bytes),           # 4 или 16 байт сырого адреса
  port (u16 BE)
}
```

**Подтверждение открытия**: открыватель ждёт на том же стриме 91 (open confirmation:
`varint 91, varint max_packet_size` — лимит принимающего) или 92 (open failure:
`varint 92, varint reason_code (i), SSHString error_message_utf8, SSHString language_tag`).
Любое другое сообщение до подтверждения — ошибка канала. Реализации в отказ-путь посылать
92 не обязаны: типовой отказ — `stream.CancelRead/CancelWrite(0)` или FIN.

## 5. Сообщения канала

Сообщения едут по стриму канала после заголовка. ChannelID в сообщениях отсутствует —
канал определяется самим стримом (расхождение с RFC 4254 и с draft-00, §14). Тела —
после varint номера типа:

| Тип | Номер | Тело |
|-----|-------|------|
| CHANNEL_OPEN_CONFIRMATION | 91 | `max_packet_size (i)` |
| CHANNEL_OPEN_FAILURE | 92 | `reason_code (i), error_message (..), language_tag (..)` |
| CHANNEL_DATA | 94 | `data (..)` — stdout/stdin/TCP-данные/тела control-каналов |
| CHANNEL_EXTENDED_DATA | 95 | `data_type (i) [1 = STDERR; 0 на сервере запрещён], data (..)` |
| CHANNEL_REQUEST | 98 | `request_type (..), want_reply (u8), body (..)` — §6 |

Константы 93 (WINDOW_ADJUST), 96 (EOF), 97 (CLOSE), 99 (SUCCESS), 100 (FAILURE) — **в живом
протоколе не реализованы**: flow control делегирован QUIC; EOF = QUIC FIN; ответы на
want_reply не шлются (поле парсится и игнорируется — интероп-контракт). Неизвестный тип
сообщения или request-тела — ошибка канала, не краш.

Чанкование DATA: отправитель режет на `min(max_packet_size − overhead, len)`; overhead — размер кадра с пустой строкой (3 байта для 94: varint 94 двухбайтный, 4 для 95).

## 6. Тела channel-request

| request_type | Тело | Семантика |
|--------------|------|-----------|
| `pty-req` | `term (..), width (i), height (i), pixel_width (i), pixel_height (i), modes (..)` | запрос PTY; modes — непрозрачный блок |
| `shell` | пустое | запуск login shell; процесс стартует, состояние LARVAL→OPEN |
| `exec` | `command (..)` | выполнение команды; всегда через шелл-исполнение |
| `subsystem` | `name (..)` | подсистема (зарезервировано) |
| `window-change` | `width (i), height (i), pixel_width (i), pixel_height (i)` | resize терминала (SIGWINCH) |
| `signal` | `name (..)` | доставка сигнала; имя без префикса `SIG` |
| `exit-status` | `status (i)` | код завершения; want_reply = 0 |
| `exit-signal` | `name (..), core_dumped (u8), error_message (..), language_tag (..)` | завершение по сигналу |
| `x11-req` | `single_connection (u8), auth_proto (..), auth_cookie (..), screen_number (i)` | парсится; ни одна реализация не обслуживает |

Спец-маркер: `CHANNEL_DATA` с payload `forward-agent` на session-канале в LARVAL — запрос
агент-форвардинга: сервер открывает `agent-connection` каналы к UDS-сокету агента клиента.

## 7. Датаграммный путь (QUIC DATAGRAM, RFC 9221)

Только каналы `direct-udp` и `forwarded-udp` едут датаграммами; всё остальное — stream-путь.
Транспортный параметр `max_datagram_frame_size` (TP ID 0x0020, RFC 9221 §4) обязан присутствовать у обеих сторон;
H3-датаграммный слой (RFC 9297) намеренно выключен — приём датаграмм один цикл на
QUIC-коннекцию, без двойного роутинга.

Формат payload одной дейтаграммы:

```
Datagram Payload {
  control_stream_id (i),   # сверяется с control stream'ом conversation; чужое — discard
  channel_id (i),          # == StreamID канала; поиск в карте каналов
  udp_payload (bytes)      # сырой UDP-пакет без рамки
}
```

Канал, ещё не зарегистрированный на приёме, держит датаграммы в dangling-очереди
(по 64 на channelID; после регистрации — пересадка в per-channel очередь). Очереди
неблокирующие: переполнение = дроп (QUIC DATAGRAM и так ненадёжен и не упорядочен).

## 8. Закрытие канала и conversation

| Механизм | Смысл |
|----------|-------|
| QUIC FIN на стриме | полузакрытие канала (канонический путь) |
| STOP_SENDING код 42 | сброс чтения канала |
| закрытие control stream / FIN conversation | разбор conversation; реализация дожидается закрытия каналов (drain grace ~3 с) |

Тайминги эталона: PTY-exit grace 1 с (клиент шлёт FIN после exit-status и ждёт);
drain conversation ≤ 3 с; server: после EOF ввода ждёт exit-status ≤ 1 с, затем FIN канала.

## 9. Reverse forwarding (-R) — надбавка rev nagual2/1

Клиент открывает контроль-канал `reverse-forward` и отправляет bind-запрос **как channel
data (94)** на нём — не новым типом сообщения: старый сервер трактует канал как неизвестную
session-переменную, отклоняет неожиданные данные и закрывает канал без краша (graceful
degradation).

**Bind-спека CLI**: `[bind_address:]bind_port[/tcp\|/udp]:target_host:target_port`
(пустой bind_address = loopback сервера; `*` = `::` wildcard; bind_port 0 = ephemeral).

**Запрос (channel data на `reverse-forward`)**:

```
RequestReverseForward {
  protocol (i),            # 0 = UDP, 1 = TCP
  bind_address (..),       # SSHString, текст как его назвал клиент
  bind_port (u16 BE),
  target_address (..),     # SSHString, канонический текст resolved цели
  target_port (u16 BE)
}
```

**Ответ (channel data на том же канале)**:

```
ReverseForwardReply {
  bound_port (u16 BE),
  error_utf8 (..)          # пустая строка = успех; иначе причина отказа
}
```

На каждый принятый сервером bind клиент/пиер получает сервер-инициированный канал
`forwarded-tcp`/`forwarded-udp` с target extension, несущим клиентскую цель (§4).
Цель резолвится на **клиентской** стороне. Совместимость с форком 0.1.35: fork шлёт
target как IPv4 в v4-mapped форме `::ffff:` — приёмник обязан допускать обе формы.

Гварды (SSH3-уровень, поверх QUIC): ≤ 10 reverse-слушателей на conversation, ≤ 64
forwarded-каналов на conversation, ≤ 8 UDP-пиров на слушатель; bind-политика
`permit-listen` (PermitOpen-семантика) гейтит бинд до его выполнения; non-loopback бинды
без явного `--gateway-ports` форсируются на 127.0.0.1.

## 10. Аутентификация

Auth-материал едет в `Authorization` CONNECT-запроса; conversation привязывается к
аутентифицированной личности через TLS-exporter (§4) — 0-RTT-запросы до завершения
handshake отклоняются 425 (анти-replay).

| Схема | Формат | Проверка |
|-------|--------|----------|
| `Basic` (RFC 7617) | `Authorization: Basic base64(user:password)` | fork: системные аккаунты, amd64 по умолчанию (opt-out `SSH3_ENABLE_PASSWORD_LOGIN=0`); ssh3-c: файл паролей `-P` или системные (`--password-system on`, fail-closed при euid≠0), password-login выключен до opt-in `--enable-password-login` |
| `Bearer` (pubkey) | `Authorization: Bearer <JWT>` — обе реализации едут Bearer'ом: fork-плагин `pubkey_authentication` (pubkey_auth.go:137) и ssh3-c `-i` (PEM-ключ: EdDSA/ES256/RS256) | подпись по authorized_keys/authorized_identities; клеймы: `iss = username`, `sub = "ssh3"`, `aud = "unused"`, `client_id = "ssh3-<username>"`, `jti` = base64 TLS-экспортера (32 байта `EXPORTER-SSH3`), `exp` обязателен и короток, `iat`/`nbf` — sanity |
| `Bearer` (OIDC) | `Authorization: Bearer <token>` от OIDC-провайдера | RS256/ES256, discovery, JWKS-кэш с ротацией kid, nonce = TLS-exporter |

Цепочка сервера (порядок): parse User-Agent → 425-гейт → username → верификаторы
(fork: плагины → Basic-если-включён → Bearer через список IdentityVerifier;
ssh3-c: Basic → Bearer-JWT pubkey/OIDC). Анти-flood: лимит неаутентифицированных
коннектов (default 100) и неудачных паролей (default 10) на username/peer.

## 11. Flow control и параметры

SSH-уровень flow control отсутствует (93 не реализован) — целиком QUIC. Информативные факты:

- advertised `max_packet_size` канала: fork шлёт 30000 обеими сторонами; кламп пиера
  `[minPeerMaxPacketSize = 4096 … local]` (channel.go:169); ssh3-c держит собственный
  потолок 16 МиБ (`S3_SSH3_CHANNEL_MAX_PACKET_LIMIT`).
- потолок длины SSHString — 2^24 (`MaxSSHStringLen`, fork util/wire.go:212).
- QUIC-дефолты fork (информативно): клиент `MaxIncomingStreams = 10`; сервер —
  stream-rx 8→16 МиБ, conn-rx 16→32 МиБ, `InitialPacketSize = 1350`.
- `maxPacketSize` в заголовке канала — лимит чанка DATA открывателя, не окон.

## 12. Интероп-матрица (факт, 2026-10-16)

Эталонные прогоны C↔Go: хендшейк/версии, session (pty/shell/exec/signal/exit-status),
TCP/UDP форвардинг, reverse-forward (bind + 64 КиБ byte-exact), sftp, agent, 0-RTT 425,
mux. Полная матрица — в отчётах фаз P2–P9 (`docs/PLAN.md` §7); отрицательный контроль —
`interop/run-quic-go.sh`.

## 13. Соображения безопасности

- TLS-exporter привязывает conversation к личности; 0-RTT отклоняется (425) — анти-replay.
- DoS-гварды: reverse-лимиты (§9), лимит каналов на conversation, budget соединений,
  username-букаут; серверные FAIL-пути на неизвестных типах — ошибка канала, не краш.
- Non-loopback бинды — только с явным opt-in (`gateway-ports`); permit-listen гейтит до bind.
- Серверный UDP-path:dataType=0 запрещён (95 с типом 0 сервер не шлёт).
- Полный R2-аудит — отдельный трек (замороженный код).

## 14. Расхождения с draft-michel-remote-terminal-http3-00

| № | Элемент | draft-00 | живой протокол (rev nagual2/1) |
|---|---------|----------|-------------------------------|
| 1 | `:protocol` | `remote-terminal` | `ssh3` |
| 2 | Путь | URI-шаблон `…/{?username}` | литерал `/ssh3-term?user=…[&mux=1]` |
| 3 | Версия | заголовок `remote-terminal-version` (список draft-файлов) | `User-Agent`/`Server` строка `SSH 3.0 … experimental_spec_version=alpha-00` |
| 4 | Session ID в заголовке канала | `session_id (i)` | нет; вместо него `conversation_stream_id` (== StreamID control stream'а) |
| 5 | Signal value канала | `0x5e67730e` | `0xaf3627e6` |
| 6 | Channel types | `session, x11, direct-tcp, reverse-tcp, direct-udp, reverse-udp` (строки) | `session, direct-tcp, direct-udp, sftp, agent-connection, reverse-forward, forwarded-tcp, forwarded-udp, dynamic-forward, dynamic-forward-tcp`; x11-типа нет |
| 7 | Сообщения | RFC 4254-подобные, Message Type — **строка** (`"exit-status"`), byte/uint32/uint64 → varint | Message Type — **числовой varint** (91/92/94/95/98), request type внутри 98 — строка; RFC 4254-номера сохранены |
| 8 | UDP-форвард | HTTP datagrams RFC 9297, quarter stream ID | QUIC DATAGRAM RFC 9221, префикс `control_stream_id + channel_id` (§7) |
| 9 | Auth | Basic (username обязателен в `?user=`), OAUTH2/JWT с клеймом `sub = remote-terminal-<user>`, Concealed | Basic (username из `?user=`/userinfo), pubkey — Bearer-JWT с клеймами `sub = "ssh3"`, `client_id = "ssh3-<user>"`, `aud = "unused"` (draft'овский `sub = remote-terminal-<user>` не используется); Concealed не реализован |
| 10 | Reverse-каналы | `reverse-tcp`/`reverse-udp` (payload на стриме канала) | контроль-канал `reverse-forward` + bind-запрос/ответ как channel data + сервер-инициированные `forwarded-tcp/forwarded-udp` с target extension |
| 11 | Отказ открытия | не специфицирован | 92 (редко) / QUIC cancel(0) / FIN |

Драфт публикуется как исторический остов (expired, 2024-07-31, individual); атрибуция:
draft-michel-remote-terminal-http3-00, François Michel (UCLouvain) et al. — заменяет
draft-michel-ssh3. Живой протокол — артефакт двух реализаций ниже.
