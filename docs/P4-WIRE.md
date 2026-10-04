# P4-WIRE: жизненный цикл каналов и дейтаграммный роутинг SSH3 (спецификация для C-порта, волна 2)

Дата: 2026-10-04.
Эталон: `C:\Git\project\ssh3` (Go-форк, протокол `SSH 3.0 alpha-00`, wire-совместимая база — см. `docs/ARCHITECTURE.md` §5). Все ссылки `file:line` — на файлы эталона. Документ самодостаточен для написания C-модулей волны 2 без чтения Go-кода; где факт в эталоне не найден — указано явно.

Примитивы кодирования (уже есть в `src/ssh3/s3_ssh3_wire.h`): все целые — QUIC varint (RFC 9000 §16, 1/2/4/8 байт, 2 старших бита первого байта = длина); SSHString = varint-длина + сырые байты (не uint32-be из SSH2).

---

## 1. Транспортная раскладка

| № | Элемент | Кто открывает | Идентификатор | Что по нему идёт |
|---|---------|---------------|---------------|------------------|
| 1 | Control stream (conversation) | Клиент, первый bidi-стрим QUIC-коннекции | QUIC StreamID (на практике 0); обе стороны называют его `conversationStreamID` / `controlStreamID` | HTTP/3 extended CONNECT `:protocol=ssh3`, auth-заголовки, ответ 200/403/401; после 200 — «просто открытый стрим», полезных SSH-фреймов по нему нет |
| 2 | Канал | Любая сторона: клиент после 200 (`Conversation.OpenChannel`, conversation.go:388), сервер — исходящие каналы (`agent-connection`, `forwarded-*`) через `streamCreator.OpenStream()` | **ChannelID == QUIC StreamID канала** (conversation.go:302, 393; server.go:167) | Заголовок канала (§2), затем сообщения канала (§3) |
| 3 | QUIC datagrams | Обе стороны, один приёмный цикл на QUIC-коннекцию | Префикс внутри датаграммы: `varint controlStreamID` | Роутинг дейтаграмм каналов (§3.2) |

Правила диспетчеризации bidi-стримов:

| № | Сторона | Правило | Эталон |
|---|---------|---------|--------|
| 1 | Сервер | Самый первый принятый bidi-стрим коннекции — всегда HTTP/3 request-стрим (клиент шлёт CONNECT раньше каналов), отдаётся http3 без чтения; все последующие bidi — SSH3-каналы (первый varint обязан быть `0xaf3627e6`) | `Server.ServeQUICConn`, server.go:80-106 |
| 2 | Сервер | Uni-стримы — всегда HTTP/3 (control/QPACK), в SSH3 не используются | server.go:82-90 |
| 3 | Клиент | Все исходящие bidi после CONNECT-стрима — каналы; входящие bidi от сервера — всегда каналы (сервер открывает их только после 200) | client.go:114-122, conversation.go:261 |
| 4 | Обе | Uni/прилож. нумерация — QUIC-овская: клиентские bidi 0,4,8…, серверные 1,5,9…; SSH3 ничего не перенумеровывает | следует из ChannelID == StreamID |

Control stream идентифицирует conversation: `ConversationID` — 32 байта из TLS-экспортера (`GenerateConversationID`, conversation.go:57-67, label `EXPORTER-SSH3`) — используется только для auth/JWT и логов, **в wire-префиксе датаграмм не участвует** (там controlStreamID). Сервер хранит conversations в `map[*quic.Conn]*conversationsManager` → `map[ControlStreamID]*Conversation` (resources_manager.go:17-44); несколько conversations на одном QUIC-соединении эталоном не поддерживаются (TODO в conversation.go:209-210, server.go:273-274).

Кто и когда открывает control stream: клиент — `EstablishClientConversation` (conversation.go:92-254): `OpenRequestStream` → `SendRequestHeader(CONNECT :protocol=ssh3)` → `ReadResponse`; стрим остаётся открытым и служит control stream (conversation.go:128-138). Сервер принимает его как request-стрим и в CONNECT-обработчике (`GetHTTPHandlerFunc`, server.go:242-320) после 200 регистрирует conversation и запускает datagram-приёмник.

---

## 2. Открытие канала

### 2.1. Первый блок нового стрима (заголовок канала)

Сборка: `buildHeader` (channel.go:130-142); разбор: `parseHeader` (channel.go:163-177). Порядок полей фиксированный:

| № | Поле | Кодирование | Значение |
|---|------|-------------|----------|
| 1 | frame type | varint | `0xaf3627e6` (`SSH_FRAME_TYPE`, conversation.go:23) |
| 2 | conversationStreamID | varint | StreamID control stream'а этой conversation; получатель обязан сверить со своим control stream (conversation.go:292-298, server.go:148-156) — не совпало → cancel стрима |
| 3 | channelType | SSHString | `"session"` \| `"direct-tcp"` \| `"direct-udp"` \| `"sftp"` \| `"agent-connection"` \| `"forwarded-tcp"` \| `"forwarded-udp"` \| `"reverse-forward"` \| `"dynamic-forward"` \| `"dynamic-forward-tcp"` (константы: message/reverse_forward.go:19-21, message/dynamic_forward.go:19-20, cmd/sftp_client.go:129) |
| 4 | maxPacketSize | varint | лимит чанка данных открывателя (см. §5) |
| 5 | (только direct-*/forwarded-*) addressFamily | varint | 4 = IPv4, 6 = IPv6 (`SSHAFIpv4/6`, util/types.go:23-26) |
| 6 | (только direct-*/forwarded-*) address | raw 4 или 16 байт | IP цели |
| 7 | (только direct-*/forwarded-*) port | uint16 big-endian | порт цели |

Расширение direct-* собирает `buildForwardingChannelAdditionalBytes` (channel.go:144-161), разбирает `parseForwardingHeader` (channel.go:179-207). Для `forwarded-tcp`/`forwarded-udp` (сервер → клиент, reverse -R) те же байты несут клиентский целевой адрес (`handleIncomingChannelStream`, conversation.go:310-331; серверный разбор — server.go:175-191).

Каналы остальных типов (session, sftp, agent-connection, reverse-forward, dynamic-*) никаких дополнительных полей не несут.

### 2.2. Семантика открытия и подтверждение

| № | Шаг | Открыватель | Принимающий | Эталон |
|---|-----|-------------|-------------|--------|
| 1 | Открыть bidi-стрим | `OpenStream()`; ChannelID = его StreamID | — | conversation.go:388-396 |
| 2 | Заголовок | Записывается **лениво**: `OpenChannel` строит header в памяти, отправка — при первой записи (`maybeSendHeader`, channel.go:300-309). Исключения: `OpenUDPForwardingChannel`/`OpenTCPForwardingChannel`/`openForwardedChannel` зовут `maybeSendHeader()` сразу (conversation.go:408, 422, 440) | — | channel.go:234-237 |
| 3 | Регистрация | `channelsManager.addChannel` — сразу при открытии | `channelsAcceptQueue.Add` (безлимитная очередь, util/util.go:89-128) — при парсинге заголовка; канал в рабочую карту попадёт на шаге 5 | conversation.go:394 / 332, server.go:192 |
| 4 | Подтверждение | Ждёт 91 на том же стриме: `NextMessage` перехватывает `ChannelOpenConfirmationMessage` (ставит `confirmReceived`) и `ChannelOpenFailureMessage` (возвращает `ChannelOpenFailure`); любое другое сообщение до подтверждения → ошибка `MessageOnNonConfirmedChannel` | `AcceptChannel` → `confirmChannel(maxPacketSize)` — пишет **91** в тот же стрим и только потом канал попадает в рабочую карту | channel.go:278-298; conversation.go:462-476 |
| 5 | Формат ответа | 91: `varint 91, varint maxPacketSize` (maxPacketSize — лимит принимающего). 92: `varint 92, varint reasonCode, SSHString errorMessageUTF8, SSHString languageTag` — оба на том же QUIC-стриме | отправка 91 — `sendMessage` (channel.go:352-364); **92 эталон никогда не отправляет** (конструктор `ChannelOpenFailureMessage` вызывается только парсером, message.go:101; отказ = `stream.CancelRead/CancelWrite(0)` в accept-цикле или FIN) | message.go:56-136 |

Флаги `NewChannel` (channel.go:231-255): открыватель — `sendHeader=true, confirmSent=true, confirmReceived=false`; принимающий — `sendHeader=false, confirmSent=false, confirmReceived=true`. То есть «подтверждённость» у сторон асимметрична: открыватель сразу может писать (заголовок+данные одним потоком байт), принимающий не читает до `AcceptChannel`.

Тайминг-ловушка эталона: клиент открывает канал сразу после 200, а сервер регистрирует conversation из другого гороутина — accept-цикл сервера ждёт регистрацию до 2 с поллингом по 200 мкс (`waitForConversationsManager`, server.go:25-29, 207-219). В C (однопоточный event loop) гонка исчезает, но сверку conversationStreamID и «канал до регистрации conversation → cancel(0)» сохранить (conversation.go:273-282).

---

## 3. Данные канала: сообщения на стриме против QUIC-датаграмм

### 3.1. Stream-путь (94/95)

Все байт-ориентированные каналы (session, direct-tcp, forwarded-tcp, sftp, agent-connection, control-каналы reverse-forward/dynamic-forward) гоняют данные сообщениями поверх своего QUIC-стрима. Разбор — `ssh3.ParseMessage` (message/message.go:212-233); **channelID в сообщениях отсутствует** — канал идентифицируется самим стримом.

| № | Тип | Формат | Назначение |
|---|-----|--------|------------|
| 1 | 94 `SSH_MSG_CHANNEL_DATA` | `varint 94, SSHString data` | stdout/stdin/TCP-данные |
| 2 | 95 `SSH_MSG_CHANNEL_EXTENDED_DATA` | `varint 95, varint dataType, SSHString data` | stderr: `dataType=1` (`SSH_EXTENDED_DATA_STDERR`); `dataType=0` запрещён на сервере (cmd/ssh3-server.go:750-755) |
| 3 | 98 `SSH_MSG_CHANNEL_REQUEST` | `varint 98, SSHString requestType, u8 wantReply, тело запроса` | pty-req/shell/exec/subsystem/window-change/signal/exit-status/exit-signal; `wantReply` — ровно 1 байт (binary.Read bool, message/channel_request.go:75); тела — §6 |

Чанкование отправки: `WriteData` (channel.go:311-342) режет буфер на `min(maxPacketSize - emptyMsgLen, len)`, где `emptyMsgLen` — длина кадра с пустой строкой (3 байта для 94 — varint 94 двухбайтный, 4 для 95); заголовок кадра и payload пишутся двумя `write` без копирования payload.

Датаграммный путь выбирается **по типу канала**: только `direct-udp` и `forwarded-udp` (`Client.ForwardUDP` client.go:462-510, серверный `forwardUDPInBackground` cmd/ssh3-server.go:154-198). Всё остальное — stream-путь, даже если `SendDatagram` вызвать (см. ниже).

### 3.2. Датаграммный путь (QUIC DATAGRAM)

Формат одной дейтаграммы (отправка `getDatagramSenderForChannel`, conversation.go:545-552):

| № | Поле | Кодирование |
|---|------|-------------|
| 1 | controlStreamID | varint (StreamID control stream'а conversation) |
| 2 | channelID | varint (== StreamID канала) |
| 3 | payload | сырые байты UDP-пакета, без рамки |

Приём: один цикл на QUIC-коннекцию на каждой стороне (клиент — conversation.go:208-236, сервер — server.go:272-304) читает `ReceiveDatagram`, парсит varint controlStreamID, сверяет со своим control stream (чужое — discard), остаток передаёт `Conversation.AddDatagram` (conversation.go:480-494): второй varint = channelID → `channelsManager.getChannel` → `waitAddDatagram` → очередь канала. QUIC DATAGRAM не надёжен и не упорядочен; H3-датаграммный слой намеренно выключен (иначе второй читатель крадёт половину датаграмм — комментарий cmd/ssh3-server.go:1026-1031).

Очереди датаграмм — `util.DatagramsQueue` (util/util.go:130-174), буферизованный канал Go:

| № | Очередь | Размер | Политика при переполнении |
|---|---------|--------|----------------------------|
| 1 | Per-channel очередь канала | аргумент `datagramsQueueSize` при создании; дефолт conversation = 10 (client.go:319 `NewClientConversation(30000, 10)`; cmd/ssh3-server.go:1050 `NewServer(30000, 10)`); фактически: `agent-connection` 10, `direct-*`/`forwarded-*` 10, `session`/`reverse-forward`/sftp-клиент — 0 → небуферизованный канал (session.go:48, ssh3-server.go:763, reverse_forward_server.go:210/247) | `Add` — неблокирующая, false → дроп; `waitAddDatagram` (путь из приёмного цикла) — блокирующая с ctx; `ReceiveDatagram` = блокирующее `WaitNext` |
| 2 | Dangling queue (датаграмма пришла раньше регистрации канала) | `danglingDatagramQueueSize = 64` на channelID (resources_manager.go:11-13); одна очередь на channelID, не новая на каждую датаграмму | `Add` неблокирующая (цикл приёма общий для всех каналов — блокировать нельзя); full → дроп + warn (resources_manager.go:84-86). `AddDatagram` при этом возвращает `ChannelNotFound` (сервер логирует warn и продолжает) |

Обмен dangling → channel: `addChannel` пересаживает готовую dangling-очередь в канал (`setDgramQueue`) и удаляет запись (resources_manager.go:56-64); двойная проверка «вдруг канал зарегистрировался между lookup и вставкой» — resources_manager.go:75-78.

Где канал ищется: единственная карта на conversation `channelsManager.channels map[ChannelID]Channel` (resources_manager.go:46-54). В неё попадают и исходящие (сразу при OpenChannel), и входящие (после `AcceptChannel`). **Удаления из карты нет**: `onChannelClose`/`removeChannel` определены (resources_manager.go:96-104), но ни одного вызова в эталоне не найдено — карта течёт; в C-порте удалить обязательно.

Установка `datagramSender` (кому разрешены датаграммы) несимметрична в эталоне: клиент ставит sender **всем** входящим каналам (conversation.go:308), сервер — только `direct-udp` (server.go:182) и `forwarded-udp` (conversation.go:458); исходяще `OpenChannel`/`OpenTCPForwardingChannel` — без sender. `SendDatagram` без sender → ошибка `SentDatagramOnNonDatagramChannel` (channel.go:380-386). Приём датаграмм работает на любом канале (очередь есть всегда).

---

## 4. Закрытие / EOF

| № | Механизм | Что делает | Эталон |
|---|----------|------------|--------|
| 1 | Полузакрытие (основной путь) | `channel.Close()` = `send.Close()` = QUIC FIN на send-стороне стрима; read-сторона живёт | channel.go:397-399 |
| 2 | Аварийный сброс чтения | `channel.CancelRead()` = QUIC STOP_SENDING с кодом **42**; пиер видит stream error 42 (клиент/сервер трактуют как «remote canceled») | channel.go:393-395; client.go:214-224 |
| 3 | Отказ в открытии | cancel read+write с кодом 0 на accept-цикле (bad frame type, неизвестная conversation) | server.go:118-120, 137-139 |
| 4 | 96 `SSH_MSG_CHANNEL_EOF`, 97 `SSH_MSG_CHANNEL_CLOSE` | **только константы** (message/message.go:32-33); нигде не отправляются и не парсятся (`ParseMessage` их не знает — panic на неизвестном типе, message.go:230-232). EOF = QUIC FIN, close = FIN + (опционально) закрытие conversation | не найдено в эталоне — воспроизводить не нужно, но парсер C должен отвечать ошибкой канала, не крахом |

Таймауты и порядок разборки:

| № | Таймаут | Где | Смысл |
|---|---------|-----|-------|
| 1 | `ptyExitGrace = 1 s` | client/session_pump.go:31 | после exit-status PTY-сессии клиент шлёт FIN и через 1 с `CancelRead` (сервер может молчать) |
| 2 | `truncationGrace = 2 s` | client/session_pump.go:28 | exit-status пришёл при незакрытом stdin → ждать stdin-pump; если ввод не ушёл — truncate, exit 255 |
| 3 | `exitStatusSent` wait ≤ 1 s | cmd/ssh3-server.go:1144-1149 | сервер: по EOF ввода ждёт goroutine exit-status до 1 с, затем FIN канала |
| 4 | `DrainAndClose(3 s)` | conversation.go:529-539, cmd/ssh3-server.go:1117-1124 | конец session-канала: FIN канала → ждать закрытия коннекции пиером до 3 с → `Conversation.Close()` (control stream + cancel ctx). Иначе финальный вывод+exit-status теряются |
| 5 | mux-исключение | conversation.go:505-521 | conversation control master'а (`?mux=1`) переживает отдельные session-каналы; teardown — при disconnect мастера |

Клиентское закрытие conversation целиком: `Client.Close` = `Conversation.Close()` + `qconn.CloseWithError(0)` (client.go:248-251) — без QUIC-close сервер держит -R-байнды до idle-таймаута.

---

## 5. Flow control

| № | Механизм | Статус в эталоне | Детали |
|---|----------|------------------|--------|
| 1 | `maxPacketSize` (заголовок канала, §2.1) | Используется только для чанкования `WriteData` (channel.go:317-340) и как размер read-буферов (client.go:127/200/437/…). Значения: 30000 на обеих сторонах всегда (client.go:319, session.go:48, cmd/ssh3-server.go:1050 и все Open*Channel) | 91 несёт maxPacketSize принимающего, но ни одна сторона полученное значение не применяет — применяется своё. Для C: интероп-наблюдаемое поведение = слать 30000, чанковать по своему limit минус оверхед кадра |
| 2 | 93 `SSH_MSG_CHANNEL_WINDOW_ADJUST` | **Не используется**: константа message/message.go:29, не парсится, не отправляется | SSH-level flow control делегирован QUIC. В C не портировать; парсер — «неизвестный тип → ошибка канала» |
| 3 | QUIC flow control | Реальный механизм: клиент `MaxIncomingStreams=10` (client.go:290); сервер: stream window 8→16 MiB, conn 16→32 MiB, `InitialPacketSize=1350` (cmd/ssh3-server.go:1025-1037, флаги -stream-rx-mb/-conn-rx-mb) | Настраивается на QUIC-слое, к SSH3-кадрам отношения не имеет |

---

## 6. Server-флоу session-канала

Регистрация хендлеров запросов: `ChannelRequestParseFuncs` (message/channel_request.go:14-24); тела запросов — там же (pty-req §6.2 RFC4254-подобный, exec, subsystem, window-change, signal, exit-status, exit-signal; shell — пустое тело; x11-req — парсится, сервером не реализован).

Последовательность (серверная петля — cmd/ssh3-server.go:1055-1214; состояния `LARVAL` → `OPEN`, ssh3-server.go:88-93, 109-120):

| № | Сообщение от клиента | Ответ сервера / действие | Эталон |
|---|---------------------|--------------------------|--------|
| 1 | (открытие канала + 91, §2) | `runningSession{LARVAL}` + goroutine-петля `NextMessage` | ssh3-server.go:1099-1105 |
| 2 | 94 data `"forward-agent"` (именно data, не request!) в LARVAL | unix-socket ssh-agent, входящие `agent-connection` каналы | ssh3-server.go:1196-1204, 820-852 |
| 3 | 98 `pty-req` wantReply=1 | `newPtyReq`: openpty, TIOCSWINSZ, term сохраняется; состояние остаётся LARVAL; **ответ не шлётся** | ssh3-server.go:458-488 |
| 4 | 98 `shell` wantReply=1 | banner (статистика системы) как 94, затем `newCommand(login_shell=true, $SHELL)` | ssh3-server.go:633-640 |
| 5 | 98 `exec` wantReply=1 | `newCommand(login_shell=false, $SHELL, "-c", cmd)` — команда всегда исполняется через шелл пользователя | ssh3-server.go:643-645 |
| 6 | — (шаги 4/5) | процесс стартует здесь: `execCmdInBackground` — pty → `StartWithSizeAndPty`, иначе три os.Pipe; state → OPEN | ssh3-server.go:304-330, 494-572 |
| 7 | 94 data (dataType=0) | stdin процесса (`runningCmd.stdinW`); только в OPEN; extended data → ошибка петли | ssh3-server.go:735-760 |
| 8 | 98 `window-change` wantReply=0 | TIOCSWINSZ на pty (только при наличии pty) | ssh3-server.go:651-675 |
| 9 | 98 `signal` wantReply=0 | `Process.Signal(SIG<name>)`; только в OPEN и при живом процессе | ssh3-server.go:677-701 |
| 10 | EOF ввода (FIN клиента) | закрыть stdin процесса, ждать завершения команды (`waitForRunningCommandAfterInputEOF`) | ssh3-server.go:292-302, 1135-1149 |
| 11 | ← stdout: 94; ← stderr: 95 dataType=1 | два goroutine-ридера на stdout/stderr pipes; PTY: stderr слит с pty (`stderrR=nil`), отдельно 95 не возникает | ssh3-server.go:389-430, 524-531 |
| 12 | ← 98 `exit-status` wantReply=0 | после Wait(): `varint 98, SSHString "exit-status", u8 0, varint code` | ssh3-server.go:431-452 |
| 13 | — | FIN канала (`channel.Close()`), затем `DrainAndClose(3 s)` (§4.4); mux-conversation — без per-session teardown | ssh3-server.go:1117-1124 |

Ответы 99 `SSH_MSG_CHANNEL_SUCCESS` / 100 `SSH_MSG_CHANNEL_FAILURE`: **не найдено в эталоне** — только константы (message/message.go:35-36). `wantReply` парсится во всех запросах и игнорируется: сервер никогда не отвечает, клиент `WantReply=true` для pty-req/shell/exec (client/session.go:73, 93, 108) ответа не ждёт (`SendRequest` — только запись, channel.go:388-391). ARCHITECTURE.md §5 фиксирует: не воспроизводить, но парсить 99/100 на приёме обеих сторон.

Клиентская сторона сессии (для симметрии): `Client.OpenSession` (client/session.go:47-115): OpenChannel("session", 30000, 0) → опционально data "forward-agent" → опционально pty-req → shell или exec → pump. Pump (`pumpSessionStreams`, client/session_pump.go:62-206): stdin → 94; stdin EOF → FIN; 94 → stdout, 95(1) → stderr (`writeSessionData`, session_pump.go:46-57); exit-status — терминальное событие с дренированием хвоста до EOF (§4.1-4.2); exit-signal — тоже терминальное. window-change клиент шлёт по SIGWINCH (wantReply=0, client.go:60-76).

---

## 7. Auth: выбор верификатора сервером (обзор для следующей волны)

Пайплайн `HandleAuths` (server_auth/auth.go:18-109), до всякого conversation-роутинга:

| № | Шаг | Провал | Эталон |
|---|-----|--------|--------|
| 1 | Парс `User-Agent` → версия | 403 | auth.go:24-35 |
| 2 | `HandshakeComplete`? (анти-replay 0-RTT) | 425 | auth.go:49-54 |
| 3 | username из userinfo URL или `?user=` | 401 | auth.go:70-78 |
| 4 | `GetAuthorizedIdentities`: `~/.ssh3/authorized_identities`, затем `~/.ssh/authorized_keys` (построчно, `#` — комментарий) | 401 при ошибке чтения | server_auth/authorized_identities.go:27-29, 146-165 |
| 5 | Сначала плагин-верификаторы (`WrappedPluginVerifier.Verify(request)`) — по всему HTTP-запросу | — | auth.go:87-96 |
| 6 | `Authorization: Basic` (если включён password login) → `HandleBasicAuth` (unix-проверка пароля); иначе `Bearer` → `HandleJWTAuth`: JWT-токен прогоняется через все `IdentityVerifier` из файла (pubkey/OIDC), первый успех — дальше | 401 | auth.go:100-107, handlers.go:44-58, authorized_identities.go:37-86 |

Conversation создаётся **до** auth (`NewServerConversation`, auth.go:61), но регистрируется в карте и получает datagram-цикл только в CONNECT-обработчике после успешной верификации (server.go:255-304). Детали JWT (подписи, claims) — вне скоупа волны 2; контракту нужен только список шагов выше и факт: 32-байтный conversationID (base64 в логах) доступен верификаторам.

---

## 8. Карта C-портов волны 2

Существующая база: `src/ssh3/s3_ssh3_wire.{h,c}` (varint/SSHString — готово), `s3_ssh3_version.{h,c}` (готово), заглушки `s3_ssh3_message.*`, `s3_ssh3_request.*`. Предлагаемая нарезка:

### 8.1. `s3_ssh3_channel` (`src/ssh3/s3_ssh3_channel.{h,c}`)

Структура канала: ChannelInfo (type, conversationStreamID, channelID==stream, maxPacketSize), флаги confirmSent/confirmReceived/headerSent, ссылка на QUIC-стрим, per-channel datagrams queue. Ответственность: сборка/разбор заголовка §2.1 (`buildHeader`/`parseHeader`), ленивая отправка header (maybeSendHeader), WriteData с чанкованием по maxPacketSize, приёмный парсер сообщений (91/92 фильтр, 94/95/98), SendRequest/exit-status сборка. Зависимости: s3_ssh3_wire, s3_ssh3_message, QUIC stream API. Прямой порт `channel.go` (417 строк).

### 8.2. `s3_ssh3_conversation` (`src/ssh3/s3_ssh3_conversation.{h,c}`)

Conversation: control stream, channelID→channel карта (rbtree/хеш), accept-очередь входящих каналов, сверка conversationStreamID. Ответственность: OpenChannel/OpenUDPForwardingChannel/OpenTCPForwardingChannel (открыватель), accept-путь (парсинг заголовка входящего стрима → очередь → 91 при accept), замена QUIC-dispatch из server.go:80-106 (первый bidi = CONNECT, остальные = каналы; входящие bidi на клиенте — всегда каналы), Close/DrainAndClose. Зависимости: s3_ssh3_channel, s3_h3 (CONNECT уже поднят волной 1 P3), QUIC open/accept stream.

### 8.3. `s3_ssh3_dgram` — дейтаграммный роутинг (`src/ssh3/s3_ssh3_dgram.{h,c}`)

Один приёмный путь на QUIC-коннекцию: varint controlStreamID → сверка → varint channelID → поиск канала → очередь; dangling-очереди по 64 с неблокирующим Add и пересадкой в канал при регистрации (resources_manager.go). Ответственность также sender: буфер `varint controlStreamID | varint channelID | payload` → QUIC `SendDatagram`. Зависимости: s3_ssh3_conversation (карта каналов), QUIC datagram API (`EnableDatagrams`, без H3-датаграмм).

### 8.4. `s3_ssh3_session_srv` — серверная сессия (`src/ssh3/s3_ssh3_session_srv.{h,c}`)

runningSession-автомат LARVAL→OPEN (§6): pty-req/shell/exec/window-change/signal, форк+pty (Linux termios; Windows ConPTY — позже), stdin/stdout/stderr насосы, 94/95 маршрутизация, exit-status (wantReply=0), banner, forward-agent по data-маркеру, EOF-обработка с ожиданием exit-status, teardown по §4. Зависимости: s3_ssh3_channel, s3_ssh3_request (уже есть каркас), os-слой (pty, pipes). Эталон: cmd/ssh3-server.go:88-852 (без -R/-D-частей).

### 8.5. `s3_ssh3_session_cli` — клиентский pump (`src/ssh3/s3_ssh3_session_cli.{h,c}`)

OpenSession-последовательность (session.go) + pumpSessionStreams: stdin-pump с FIN по EOF, stdout/stderr routing, truncation-детектор (grace 2 s, exit 255), PTY-grace (1 s), терминальные ExitStatus/ExitSignal. В event-модели C — без гороутин: два «направления» на posted events/файловых дескрипторах. Зависимости: s3_ssh3_channel, os/term.

### 8.6. `s3_ssh3_forward` — forwarding (`src/ssh3/s3_ssh3_forward.{h,c}`)

direct-tcp/direct-udp (клиентские исходящие), forwarded-tcp/forwarded-udp (приём с разбором расширенного заголовка), заглушка моста на локальный сокет. Reverse-forward/dynamic-forward-контроль-каналы (тела запросов message/reverse_forward.go, message/dynamic_forward.go) — отдельным инкрементом, волна 2 может ограничиться direct-*/forwarded-*: для interop-матрицы P4 (shell/exec/pty/signal) форвардинг не нужен. Зависимости: s3_ssh3_channel, s3_ssh3_dgram.

### 8.7. `s3_ssh3_auth_srv` — серверные верификаторы (обзор §7, полный порт — следующая волна)

Цепочка §7 без JWT-глубины: version/425-гейт уже в P3; добавить username-извлечение, чтение authorized_identities/authorized_keys, Basic-проверку, каркас IdentityVerifier с pubkey-веткой. Зависимости: s3_ssh3_conversation (conversationID), os/unix (passwd).

---

## 9. Отклонения от эталона, обязательные для C (сводка)

| № | Отклонение | Основание |
|---|------------|-----------|
| 1 | Не отправлять 92/93/96/97/99/100; на приёме — трактовать как ошибку канала/игнор, не краш | В эталоне не реализованы (§2.2, §4, §5, §6) |
| 2 | Удалять канал из карты при закрытии | В эталоне `onChannelClose` мёртвый код — утечка |
| 3 | Парсер 98: неизвестный requestType → ошибка канала, не panic | message.go:230-232 в эталоне паникует |
| 4 | reply-протокол для wantReply не изобретать: интероп = отсутствие ответов | §6;ARCHITECTURE.md §5 «Fixed от Go-багов» |
| 5 | Держать асимметрию datagramSender необязательной: в C разрешить SendDatagram на любом канале с установленным sender, sender ставить всем UDP-каналам обеих ролей | Наблюдаемая wire-семантика не меняется (§3.2) |
