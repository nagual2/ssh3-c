# P4-WIRE: Lebenszyklus von Kanälen und Datagramm-Routing in SSH3 (Spezifikation für den C-Port, Welle 2)
> Languages: [RU](P4-WIRE.md) · [EN](P4-WIRE.en.md) · DE (this file)

Datum: 2026-10-04.
Referenz: `C:\Git\project\ssh3` (Go-Fork, Protokoll `SSH 3.0 alpha-00`, wire-kompatible Basis — siehe `docs/ARCHITECTURE.md` §5). Alle `file:line`-Verweise beziehen sich auf die Dateien der Referenz. Das Dokument ist in sich geschlossen und reicht aus, um die C-Module der Welle 2 ohne Lektüre des Go-Codes zu schreiben; wo ein Sachverhalt in der Referenz nicht gefunden wurde, ist dies explizit vermerkt.

**NB 2026-10-16:** die aktuelle Protokollspezifikation ist `docs/SPEC-wire.md` (rev nagual2/1, draft 1); dieses Dokument ist ein historisches Destillat der Welle 2, seine Fakten sind in die Spezifikation überführt.

Kodierungsprimitive (bereits vorhanden in `src/ssh3/s3_ssh3_wire.h`): alle Ganzzahlen sind QUIC varint (RFC 9000 §16, 1/2/4/8 Bytes, die 2 höherwertigen Bits des ersten Bytes = Länge); SSHString = varint-Länge + rohe Bytes (nicht uint32-be aus SSH2).

---

## 1. Transport-Layout

| Nr. | Element | Wer öffnet | Bezeichner | Was darüber läuft |
|---|---------|---------------|---------------|------------------|
| 1 | Control stream (conversation) | Client, erster bidi-Stream der QUIC-Verbindung | QUIC StreamID (in der Praxis 0); beide Seiten nennen ihn `conversationStreamID` / `controlStreamID` | HTTP/3 extended CONNECT `:protocol=ssh3`, Auth-Header, Antwort 200/403/401; nach 200 — „einfach ein offener Stream", nützliche SSH-Frames laufen darüber nicht |
| 2 | Kanal | Jede Seite: der Client nach 200 (`Conversation.OpenChannel`, conversation.go:388), der Server — ausgehende Kanäle (`agent-connection`, `forwarded-*`) über `streamCreator.OpenStream()` | **ChannelID == QUIC StreamID des Kanals** (conversation.go:302, 393; server.go:167) | Kanal-Header (§2), danach Kanal-Nachrichten (§3) |
| 3 | QUIC datagrams | Beide Seiten, ein Empfangszyklus pro QUIC-Verbindung | Präfix innerhalb des Datagrams: `varint controlStreamID` | Routing der Kanal-Datagrams (§3.2) |

Regeln für das Dispatching der bidi-Streams:

| Nr. | Seite | Regel | Referenz |
|---|---------|---------|--------|
| 1 | Server | Der allererste akzeptierte bidi-Stream der Verbindung ist immer ein HTTP/3 request-Stream (der Client sendet CONNECT vor den Kanälen), er wird ohne Lesen an http3 durchgereicht; alle folgenden bidi-Streams sind SSH3-Kanäle (der erste varint muss `0xaf3627e6` sein) | `Server.ServeQUICConn`, server.go:80-106 |
| 2 | Server | Uni-Streams sind immer HTTP/3 (control/QPACK), in SSH3 werden sie nicht verwendet | server.go:82-90 |
| 3 | Client | Alle ausgehenden bidi-Streams nach dem CONNECT-Stream sind Kanäle; eingehende bidi-Streams vom Server sind immer Kanäle (der Server öffnet sie erst nach 200) | client.go:114-122, conversation.go:261 |
| 4 | Beide | Uni-/App-Nummerierung ist die QUIC-eigene: clientseitige bidi 0,4,8…, serverseitige 1,5,9…; SSH3 nummeriert nichts um | folgt aus ChannelID == StreamID |

Der Control stream identifiziert die conversation: `ConversationID` — 32 Bytes aus dem TLS-Exporter (`GenerateConversationID`, conversation.go:57-67, label `EXPORTER-SSH3`) — wird nur für auth/JWT und Logs verwendet, **im wire-Präfix der Datagrams kommt er nicht vor** (dort der controlStreamID). Der Server speichert conversations in `map[*quic.Conn]*conversationsManager` → `map[ControlStreamID]*Conversation` (resources_manager.go:17-44); mehrere conversations auf einer QUIC-Verbindung werden von der Referenz nicht unterstützt (TODO in conversation.go:209-210, server.go:273-274).

Wer und wann den control stream öffnet: der Client — `EstablishClientConversation` (conversation.go:92-254): `OpenRequestStream` → `SendRequestHeader(CONNECT :protocol=ssh3)` → `ReadResponse`; der Stream bleibt offen und dient als control stream (conversation.go:128-138). Der Server nimmt ihn als request-Stream entgegen und registriert im CONNECT-Handler (`GetHTTPHandlerFunc`, server.go:242-320) nach 200 die conversation und startet den datagram-Empfänger.

---

## 2. Öffnen eines Kanals

### 2.1. Erster Block eines neuen Streams (Kanal-Header)

Zusammenbau: `buildHeader` (channel.go:130-142); Parsen: `parseHeader` (channel.go:163-177). Die Reihenfolge der Felder ist fest:

| Nr. | Feld | Kodierung | Wert |
|---|------|-------------|----------|
| 1 | frame type | varint | `0xaf3627e6` (`SSH_FRAME_TYPE`, conversation.go:23) |
| 2 | conversationStreamID | varint | StreamID des control stream dieser conversation; der Empfänger muss ihn mit seinem eigenen control stream abgleichen (conversation.go:292-298, server.go:148-156) — bei Nichtübereinstimmung → cancel des Streams |
| 3 | channelType | SSHString | `"session"` \| `"direct-tcp"` \| `"direct-udp"` \| `"sftp"` \| `"agent-connection"` \| `"forwarded-tcp"` \| `"forwarded-udp"` \| `"reverse-forward"` \| `"dynamic-forward"` \| `"dynamic-forward-tcp"` (Konstanten: message/reverse_forward.go:19-21, message/dynamic_forward.go:19-20, cmd/sftp_client.go:129) |
| 4 | maxPacketSize | varint | Chunk-Limit für die Daten des Öffners (siehe §5) |
| 5 | (nur direct-*/forwarded-*) addressFamily | varint | 4 = IPv4, 6 = IPv6 (`SSHAFIpv4/6`, util/types.go:23-26) |
| 6 | (nur direct-*/forwarded-*) address | raw 4 oder 16 Bytes | IP des Ziels |
| 7 | (nur direct-*/forwarded-*) port | uint16 big-endian | Port des Ziels |

Die direct-*-Erweiterung baut `buildForwardingChannelAdditionalBytes` (channel.go:144-161) zusammen; das Parsen übernimmt `parseForwardingHeader` (channel.go:179-207). Für `forwarded-tcp`/`forwarded-udp` (Server → Client, reverse -R) tragen dieselben Bytes die Zieladresse des Clients (`handleIncomingChannelStream`, conversation.go:310-331; serverseitiges Parsen — server.go:175-191).

Kanäle der übrigen Typen (session, sftp, agent-connection, reverse-forward, dynamic-*) tragen keine zusätzlichen Felder.

### 2.2. Semantik des Öffnens und die Bestätigung

| Nr. | Schritt | Öffner | Empfänger | Referenz |
|---|-----|-------------|-------------|--------|
| 1 | bidi-Stream öffnen | `OpenStream()`; ChannelID = dessen StreamID | — | conversation.go:388-396 |
| 2 | Header | Wird **lazy** geschrieben: `OpenChannel` baut den header im Speicher, der Versand erfolgt bei der ersten Schreiboperation (`maybeSendHeader`, channel.go:300-309). Ausnahmen: `OpenUDPForwardingChannel`/`OpenTCPForwardingChannel`/`openForwardedChannel` rufen `maybeSendHeader()` sofort auf (conversation.go:408, 422, 440) | — | channel.go:234-237 |
| 3 | Registrierung | `channelsManager.addChannel` — sofort beim Öffnen | `channelsAcceptQueue.Add` (unbegrenzte Queue, util/util.go:89-128) — beim Parsen des Headers; in die Arbeits-Map kommt der Kanal erst bei Schritt 5 | conversation.go:394 / 332, server.go:192 |
| 4 | Bestätigung | Wartet auf 91 auf demselben Stream: `NextMessage` fängt `ChannelOpenConfirmationMessage` ab (setzt `confirmReceived`) und `ChannelOpenFailureMessage` (liefert `ChannelOpenFailure`); jede andere Nachricht vor der Bestätigung → Fehler `MessageOnNonConfirmedChannel` | `AcceptChannel` → `confirmChannel(maxPacketSize)` — schreibt **91** in denselben Stream, und erst danach kommt der Kanal in die Arbeits-Map | channel.go:278-298; conversation.go:462-476 |
| 5 | Antwortformat | 91: `varint 91, varint maxPacketSize` (maxPacketSize — Limit des Empfängers). 92: `varint 92, varint reasonCode, SSHString errorMessageUTF8, SSHString languageTag` — beide auf demselben QUIC-Stream | Versand von 91 — `sendMessage` (channel.go:352-364); **92 sendet die Referenz niemals** (der Konstruktor `ChannelOpenFailureMessage` wird nur vom Parser aufgerufen, message.go:101; Ablehnung = `stream.CancelRead/CancelWrite(0)` im accept-Zyklus oder FIN) | message.go:56-136 |

Flags von `NewChannel` (channel.go:231-255): Öffner — `sendHeader=true, confirmSent=true, confirmReceived=false`; Empfänger — `sendHeader=false, confirmSent=false, confirmReceived=true`. Das heißt, der Bestätigungszustand ist auf den Seiten asymmetrisch: der Öffner kann sofort schreiben (Header+Daten in einem Bytestrom), der Empfänger liest erst nach `AcceptChannel`.

Timing-Falle der Referenz: der Client öffnet den Kanal direkt nach 200, der Server registriert die conversation aber aus einer anderen Goroutine — der accept-Zyklus des Servers wartet bis zu 2 s auf die Registrierung, mit Polling im 200-µs-Takt (`waitForConversationsManager`, server.go:25-29, 207-219). In C (single-threaded event loop) entfällt die Race Condition, aber den Abgleich der conversationStreamID und „Kanal vor der Registrierung der conversation → cancel(0)" beibehalten (conversation.go:273-282).

---

## 3. Kanaldaten: Nachrichten auf dem Stream vs. QUIC-Datagrams

### 3.1. Stream-Pfad (94/95)

Alle byte-orientierten Kanäle (session, direct-tcp, forwarded-tcp, sftp, agent-connection, die control-Kanäle reverse-forward/dynamic-forward) transportieren Daten als Nachrichten über ihren QUIC-Stream. Das Parsen übernimmt `ssh3.ParseMessage` (message/message.go:212-233); **eine channelID fehlt in den Nachrichten** — der Kanal wird durch den Stream selbst identifiziert.

| Nr. | Typ | Format | Zweck |
|---|-----|--------|------------|
| 1 | 94 `SSH_MSG_CHANNEL_DATA` | `varint 94, SSHString data` | stdout/stdin/TCP-Daten |
| 2 | 95 `SSH_MSG_CHANNEL_EXTENDED_DATA` | `varint 95, varint dataType, SSHString data` | stderr: `dataType=1` (`SSH_EXTENDED_DATA_STDERR`); `dataType=0` ist auf dem Server verboten (cmd/ssh3-server.go:750-755) |
| 3 | 98 `SSH_MSG_CHANNEL_REQUEST` | `varint 98, SSHString requestType, u8 wantReply, тело запроса` | pty-req/shell/exec/subsystem/window-change/signal/exit-status/exit-signal; `wantReply` — genau 1 Byte (binary.Read bool, message/channel_request.go:75); Körper — §6 |

Chunking des Versands: `WriteData` (channel.go:311-342) zerlegt den Buffer in `min(maxPacketSize - emptyMsgLen, len)`, wobei `emptyMsgLen` die Länge eines Frames mit leerem String ist (3 Bytes für 94 — varint 94 ist zwei Bytes lang, 4 für 95); Frame-Header und payload werden mit zwei `write` ohne Kopieren des payload geschrieben.

Der Datagramm-Pfad wird **nach Kanaltyp** gewählt: nur `direct-udp` und `forwarded-udp` (`Client.ForwardUDP` client.go:462-510, serverseitig `forwardUDPInBackground` cmd/ssh3-server.go:154-198). Alles Übrige läuft über den stream-Pfad, selbst wenn `SendDatagram` aufgerufen wird (siehe unten).

### 3.2. Datagramm-Pfad (QUIC DATAGRAM)

Format eines einzelnen Datagrams (Versand `getDatagramSenderForChannel`, conversation.go:545-552):

| Nr. | Feld | Kodierung |
|---|------|-------------|
| 1 | controlStreamID | varint (StreamID des control stream der conversation) |
| 2 | channelID | varint (== StreamID des Kanals) |
| 3 | payload | rohe Bytes des UDP-Pakets, ohne Rahmen |

Empfang: ein Zyklus pro QUIC-Verbindung auf jeder Seite (Client — conversation.go:208-236, Server — server.go:272-304) liest `ReceiveDatagram`, parst den varint controlStreamID, gleicht ihn mit dem eigenen control stream ab (fremde — discard) und übergibt den Rest an `Conversation.AddDatagram` (conversation.go:480-494): der zweite varint = channelID → `channelsManager.getChannel` → `waitAddDatagram` → Queue des Kanals. QUIC DATAGRAM ist weder zuverlässig noch geordnet; die H3-Datagramm-Schicht ist absichtlich abgeschaltet (sonst stiehlt der zweite Leser die Hälfte der Datagrams — Kommentar cmd/ssh3-server.go:1026-1031).

Die Datagramm-Queues — `util.DatagramsQueue` (util/util.go:130-174), ein gepufferter Go-Kanal:

| Nr. | Queue | Größe | Politik bei Überlauf |
|---|---------|--------|----------------------------|
| 1 | Per-channel-Queue des Kanals | Argument `datagramsQueueSize` bei der Erzeugung; conversation-Default = 10 (client.go:319 `NewClientConversation(30000, 10)`; cmd/ssh3-server.go:1050 `NewServer(30000, 10)`); tatsächlich: `agent-connection` 10, `direct-*`/`forwarded-*` 10, `session`/`reverse-forward`/sftp-Client — 0 → ungepufferter Kanal (session.go:48, ssh3-server.go:763, reverse_forward_server.go:210/247) | `Add` — nicht blockierend, false → drop; `waitAddDatagram` (Weg aus dem Empfangszyklus) — blockierend mit ctx; `ReceiveDatagram` = blockierendes `WaitNext` |
| 2 | Dangling queue (Datagram trifft vor der Registrierung des Kanals ein) | `danglingDatagramQueueSize = 64` pro channelID (resources_manager.go:11-13); eine Queue pro channelID, nicht eine neue pro Datagramm | `Add` nicht blockierend (der Empfangszyklus ist allen Kanälen gemeinsam — blockieren ist nicht erlaubt); full → drop + warn (resources_manager.go:84-86). `AddDatagram` liefert in diesem Fall `ChannelNotFound` (der Server loggt warn und macht weiter) |

Übergang dangling → channel: `addChannel` verpflanzt die fertige dangling queue in den Kanal (`setDgramQueue`) und entfernt den Eintrag (resources_manager.go:56-64); doppelter Check „falls sich der Kanal zwischen lookup und Einfügen doch registriert hat" — resources_manager.go:75-78.

Wo der Kanal gesucht wird: die einzige Map pro conversation `channelsManager.channels map[ChannelID]Channel` (resources_manager.go:46-54). Sie enthält sowohl ausgehende Kanäle (sofort bei OpenChannel) als auch eingehende (nach `AcceptChannel`). **Keine Löschung aus der Map**: `onChannelClose`/`removeChannel` sind definiert (resources_manager.go:96-104), aber in der Referenz wurde kein einziger Aufruf gefunden — die Map leakt; im C-Port ist das Löschen zwingend.

Das Setzen von `datagramSender` (wem Datagrams erlaubt sind) ist in der Referenz asymmetrisch: der Client setzt den sender bei **allen** eingehenden Kanälen (conversation.go:308), der Server — nur bei `direct-udp` (server.go:182) und `forwarded-udp` (conversation.go:458); ausgehende `OpenChannel`/`OpenTCPForwardingChannel` — ohne sender. `SendDatagram` ohne sender → Fehler `SentDatagramOnNonDatagramChannel` (channel.go:380-386). Der Empfang von Datagrams funktioniert auf jedem Kanal (eine Queue existiert immer).

---

## 4. Schließen / EOF

| Nr. | Mechanismus | Was er tut | Referenz |
|---|----------|------------|--------|
| 1 | Halbschließen (Hauptweg) | `channel.Close()` = `send.Close()` = QUIC FIN auf der send-Seite des Streams; die read-Seite lebt weiter | channel.go:397-399 |
| 2 | Notabbruch des Lesens | `channel.CancelRead()` = QUIC STOP_SENDING mit Code **42**; der Peer sieht stream error 42 (Client/Server interpretieren das als „remote canceled") | channel.go:393-395; client.go:214-224 |
| 3 | Ablehnung des Öffnens | cancel read+write mit Code 0 im accept-Zyklus (bad frame type, unbekannte conversation) | server.go:118-120, 137-139 |
| 4 | 96 `SSH_MSG_CHANNEL_EOF`, 97 `SSH_MSG_CHANNEL_CLOSE` | **nur Konstanten** (message/message.go:32-33); werden nirgends gesendet und nicht geparst (`ParseMessage` kennt sie nicht — panic bei unbekanntem Typ, message.go:230-232). EOF = QUIC FIN, close = FIN + (optional) Schließen der conversation | nicht in der Referenz gefunden — muss nicht reproduziert werden, aber der C-Parser muss mit einem Kanalfehler antworten, nicht mit einem Absturz |

Timeouts und Abbausequenz:

| Nr. | Timeout | Wo | Bedeutung |
|---|---------|-----|-------|
| 1 | `ptyExitGrace = 1 s` | client/session_pump.go:31 | nach dem exit-status der PTY-Session sendet der Client FIN und nach 1 s `CancelRead` (der Server darf schweigen) |
| 2 | `truncationGrace = 2 s` | client/session_pump.go:28 | exit-status kam bei noch offenem stdin → auf den stdin-pump warten; ist die Eingabe nicht rausgegangen — truncate, exit 255 |
| 3 | `exitStatusSent` wait ≤ 1 s | cmd/ssh3-server.go:1144-1149 | Server: bei EOF der Eingabe wartet er bis zu 1 s auf die exit-status-Goroutine, dann FIN des Kanals |
| 4 | `DrainAndClose(3 s)` | conversation.go:529-539, cmd/ssh3-server.go:1117-1124 | Ende des session-Kanals: FIN des Kanals → auf Schließen der Verbindung durch den Peer bis zu 3 s warten → `Conversation.Close()` (control stream + cancel ctx). Sonst gehen endgültige Ausgabe + exit-status verloren |
| 5 | mux-Ausnahme | conversation.go:505-521 | die conversation des control master (`?mux=1`) überlebt einzelne session-Kanäle; teardown — beim disconnect des Masters |

Vollständiges clientseitiges Schließen der conversation: `Client.Close` = `Conversation.Close()` + `qconn.CloseWithError(0)` (client.go:248-251) — ohne QUIC-close hält der Server die -R-Binds bis zum idle-Timeout.

---

## 5. Flow control

| Nr. | Mechanismus | Status in der Referenz | Details |
|---|----------|------------------|--------|
| 1 | `maxPacketSize` (Kanal-Header, §2.1) | Wird nur für das Chunking von `WriteData` (channel.go:317-340) und als Größe der read-Buffer verwendet (client.go:127/200/437/…). Werte: 30000 auf beiden Seiten immer (client.go:319, session.go:48, cmd/ssh3-server.go:1050 und alle Open*Channel) | 91 trägt den maxPacketSize des Empfängers, aber keine Seite wendet den empfangenen Wert an — es gilt der eigene. Für C: interop-beobachtbares Verhalten = 30000 senden, nach dem eigenen limit minus Frame-Overhead chunken |
| 2 | 93 `SSH_MSG_CHANNEL_WINDOW_ADJUST` | **Wird nicht verwendet**: Konstante message/message.go:29, wird nicht geparst, nicht gesendet | SSH-level flow control ist an QUIC delegiert. In C nicht portieren; Parser — „unbekannter Typ → Kanalfehler" |
| 3 | QUIC flow control | Der reale Mechanismus: Client `MaxIncomingStreams=10` (client.go:290); Server: stream window 8→16 MiB, conn 16→32 MiB, `InitialPacketSize=1350` (cmd/ssh3-server.go:1025-1037, Flags -stream-rx-mb/-conn-rx-mb) | Wird auf der QUIC-Schicht konfiguriert, hat mit SSH3-Frames nichts zu tun |

---

## 6. Server-Fluss des session-Kanals

Registrierung der request-Handler: `ChannelRequestParseFuncs` (message/channel_request.go:14-24); die Anfragekörper stehen ebenda (pty-req §6.2, RFC4254-ähnlich, exec, subsystem, window-change, signal, exit-status, exit-signal; shell — leerer Körper; x11-req — wird geparst, vom Server nicht implementiert).

Ablauf (Serverschleife — cmd/ssh3-server.go:1055-1214; Zustände `LARVAL` → `OPEN`, ssh3-server.go:88-93, 109-120):

| Nr. | Nachricht vom Client | Antwort des Servers / Aktion | Referenz |
|---|---------------------|--------------------------|--------|
| 1 | (Öffnen des Kanals + 91, §2) | `runningSession{LARVAL}` + Goroutine-Schleife `NextMessage` | ssh3-server.go:1099-1105 |
| 2 | 94 data `"forward-agent"` (wirklich data, nicht request!) im LARVAL | unix-socket ssh-agent, eingehende `agent-connection`-Kanäle | ssh3-server.go:1196-1204, 820-852 |
| 3 | 98 `pty-req` wantReply=1 | `newPtyReq`: openpty, TIOCSWINSZ, term wird gesichert; Zustand bleibt LARVAL; **Antwort wird nicht gesendet** | ssh3-server.go:458-488 |
| 4 | 98 `shell` wantReply=1 | banner (Systemstatistik) als 94, danach `newCommand(login_shell=true, $SHELL)` | ssh3-server.go:633-640 |
| 5 | 98 `exec` wantReply=1 | `newCommand(login_shell=false, $SHELL, "-c", cmd)` — der Befehl wird immer über die Shell des Benutzers ausgeführt | ssh3-server.go:643-645 |
| 6 | — (Schritte 4/5) | hier startet der Prozess: `execCmdInBackground` — mit pty → `StartWithSizeAndPty`, sonst drei os.Pipe; state → OPEN | ssh3-server.go:304-330, 494-572 |
| 7 | 94 data (dataType=0) | stdin des Prozesses (`runningCmd.stdinW`); nur in OPEN; extended data → Fehler der Schleife | ssh3-server.go:735-760 |
| 8 | 98 `window-change` wantReply=0 | TIOCSWINSZ auf die pty (nur wenn eine pty vorhanden ist) | ssh3-server.go:651-675 |
| 9 | 98 `signal` wantReply=0 | `Process.Signal(SIG<name>)`; nur in OPEN und bei lebendigem Prozess | ssh3-server.go:677-701 |
| 10 | EOF der Eingabe (FIN des Clients) | stdin des Prozesses schließen, auf das Ende des Befehls warten (`waitForRunningCommandAfterInputEOF`) | ssh3-server.go:292-302, 1135-1149 |
| 11 | ← stdout: 94; ← stderr: 95 dataType=1 | zwei Goroutine-Reader auf den stdout/stderr pipes; PTY: stderr ist mit der pty verschmolzen (`stderrR=nil`), ein separates 95 tritt nicht auf | ssh3-server.go:389-430, 524-531 |
| 12 | ← 98 `exit-status` wantReply=0 | nach Wait(): `varint 98, SSHString "exit-status", u8 0, varint code` | ssh3-server.go:431-452 |
| 13 | — | FIN des Kanals (`channel.Close()`), danach `DrainAndClose(3 s)` (§4.4); mux-conversation — ohne per-session teardown | ssh3-server.go:1117-1124 |

Die Antworten 99 `SSH_MSG_CHANNEL_SUCCESS` / 100 `SSH_MSG_CHANNEL_FAILURE`: **in der Referenz nicht gefunden** — nur Konstanten (message/message.go:35-36). `wantReply` wird in allen Anfragen geparst und ignoriert: der Server antwortet nie, der Client mit `WantReply=true` für pty-req/shell/exec (client/session.go:73, 93, 108) wartet nicht auf eine Antwort (`SendRequest` — nur Schreiben, channel.go:388-391). ARCHITECTURE.md §5 hält fest: nicht reproduzieren, aber 99/100 beim Empfang beider Seiten parsen.

Clientseite der Session (der Symmetrie halber): `Client.OpenSession` (client/session.go:47-115): OpenChannel("session", 30000, 0) → optional data "forward-agent" → optional pty-req → shell oder exec → pump. Der pump (`pumpSessionStreams`, client/session_pump.go:62-206): stdin → 94; stdin EOF → FIN; 94 → stdout, 95(1) → stderr (`writeSessionData`, session_pump.go:46-57); exit-status — terminales Ereignis mit Draining des Rests bis zum EOF (§4.1-4.2); exit-signal — ebenfalls terminal. window-change sendet der Client bei SIGWINCH (wantReply=0, client.go:60-76).

---

## 7. Auth: Auswahl des Verifikators durch den Server (Überblick für die nächste Welle)

Pipeline `HandleAuths` (server_auth/auth.go:18-109), vor jedwedem conversation-Routing:

| Nr. | Schritt | Fehlschlag | Referenz |
|---|-----|--------|--------|
| 1 | `User-Agent` parsen → Version | 403 | auth.go:24-35 |
| 2 | `HandshakeComplete`? (Anti-replay 0-RTT) | 425 | auth.go:49-54 |
| 3 | username aus der userinfo der URL oder `?user=` | 401 | auth.go:70-78 |
| 4 | `GetAuthorizedIdentities`: `~/.ssh3/authorized_identities`, danach `~/.ssh/authorized_keys` (zeilenweise, `#` — Kommentar) | 401 bei Lesefehler | server_auth/authorized_identities.go:27-29, 146-165 |
| 5 | Zuerst die plugin-Verifikatoren (`WrappedPluginVerifier.Verify(request)`) — über die gesamte HTTP-Anfrage | — | auth.go:87-96 |
| 6 | `Authorization: Basic` (falls password login aktiviert ist) → `HandleBasicAuth` (unix-Passwortprüfung); sonst `Bearer` → `HandleJWTAuth`: das JWT-Token wird durch alle `IdentityVerifier` aus der Datei geschickt (pubkey/OIDC), der erste Erfolg — weiter | 401 | auth.go:100-107, handlers.go:44-58, authorized_identities.go:37-86 |

Die conversation wird **vor** auth erzeugt (`NewServerConversation`, auth.go:61), aber erst im CONNECT-Handler nach erfolgreicher Verifikation in die Map eingetragen und mit einem datagram-Zyklus versehen (server.go:255-304). JWT-Details (Signaturen, claims) — außerhalb des Scopes der Welle 2; der Vertrag braucht nur die obige Schrittfolge und den Fakt: die 32-Byte-conversationID (base64 in den Logs) ist den Verifikatoren zugänglich.

---

## 8. Übersicht der C-Ports der Welle 2

Bestehende Basis: `src/ssh3/s3_ssh3_wire.{h,c}` (varint/SSHString — fertig), `s3_ssh3_version.{h,c}` (fertig), Stubs `s3_ssh3_message.*`, `s3_ssh3_request.*`. Vorgeschlagene Aufteilung:

### 8.1. `s3_ssh3_channel` (`src/ssh3/s3_ssh3_channel.{h,c}`)

Kanalstruktur: ChannelInfo (type, conversationStreamID, channelID==stream, maxPacketSize), Flags confirmSent/confirmReceived/headerSent, Referenz auf den QUIC-Stream, per-channel datagrams queue. Verantwortung: Zusammenbau/Parsen des Headers §2.1 (`buildHeader`/`parseHeader`), lazy Versand des header (maybeSendHeader), WriteData mit Chunking nach maxPacketSize, Empfangs-Parser für Nachrichten (91/92-Filter, 94/95/98), SendRequest/exit-status-Zusammenbau. Abhängigkeiten: s3_ssh3_wire, s3_ssh3_message, QUIC stream API. Direkter Port von `channel.go` (417 Zeilen).

### 8.2. `s3_ssh3_conversation` (`src/ssh3/s3_ssh3_conversation.{h,c}`)

Conversation: control stream, channelID→channel-Map (rbtree/Hash), accept-Queue für eingehende Kanäle, Abgleich der conversationStreamID. Verantwortung: OpenChannel/OpenUDPForwardingChannel/OpenTCPForwardingChannel (Öffner), accept-Pfad (Parsen des Headers eines eingehenden Streams → Queue → 91 bei accept), Ersatz für das QUIC-dispatch aus server.go:80-106 (erster bidi = CONNECT, weitere = Kanäle; eingehende bidi beim Client — immer Kanäle), Close/DrainAndClose. Abhängigkeiten: s3_ssh3_channel, s3_h3 (CONNECT ist mit Welle 1 P3 bereits abgedeckt), QUIC open/accept stream.

### 8.3. `s3_ssh3_dgram` — Datagramm-Routing (`src/ssh3/s3_ssh3_dgram.{h,c}`)

Ein Empfangsweg pro QUIC-Verbindung: varint controlStreamID → Abgleich → varint channelID → Suche des Kanals → Queue; dangling queues mit je 64, nicht blockierendem Add und Verpflanzung in den Kanal bei der Registrierung (resources_manager.go). Verantwortung auch für den sender: Buffer `varint controlStreamID | varint channelID | payload` → QUIC `SendDatagram`. Abhängigkeiten: s3_ssh3_conversation (Kanal-Map), QUIC datagram API (`EnableDatagrams`, ohne H3-Datagrams).

### 8.4. `s3_ssh3_session_srv` — Server-Session (`src/ssh3/s3_ssh3_session_srv.{h,c}`)

runningSession-Automat LARVAL→OPEN (§6): pty-req/shell/exec/window-change/signal, fork+pty (Linux termios; Windows ConPTY — später), stdin/stdout/stderr-Pumps, 94/95-Routing, exit-status (wantReply=0), banner, forward-agent über den data-Marker, EOF-Behandlung mit Warten auf exit-status, teardown nach §4. Abhängigkeiten: s3_ssh3_channel, s3_ssh3_request (Grundgerüst ist bereits vorhanden), os-Schicht (pty, pipes). Referenz: cmd/ssh3-server.go:88-852 (ohne die -R/-D-Teile).

### 8.5. `s3_ssh3_session_cli` — clientseitiger pump (`src/ssh3/s3_ssh3_session_cli.{h,c}`)

OpenSession-Sequenz (session.go) + pumpSessionStreams: stdin-pump mit FIN bei EOF, stdout/stderr routing, truncation-Detektor (grace 2 s, exit 255), PTY-grace (1 s), terminale ExitStatus/ExitSignal. Im C-event-Modell — ohne Goroutines: zwei „Richtungen" über posted events/File-Deskriptoren. Abhängigkeiten: s3_ssh3_channel, os/term.

### 8.6. `s3_ssh3_forward` — forwarding (`src/ssh3/s3_ssh3_forward.{h,c}`)

direct-tcp/direct-udp (clientseitig ausgehend), forwarded-tcp/forwarded-udp (Empfang mit Parsen des erweiterten Headers), Stub der Brücke zum lokalen Socket. Die reverse-forward/dynamic-forward-control-Kanäle (Anfragekörper message/reverse_forward.go, message/dynamic_forward.go) — als eigener Inkrement; Welle 2 kann sich auf direct-*/forwarded-* beschränken: für die interop-Matrix von P4 (shell/exec/pty/signal) wird forwarding nicht benötigt. Abhängigkeiten: s3_ssh3_channel, s3_ssh3_dgram.

### 8.7. `s3_ssh3_auth_srv` — serverseitige Verifikatoren (Überblick §7, vollständiger Port — nächste Welle)

Kette von §7 ohne JWT-Tiefe: der version/425-Gate ist bereits in P3; hinzuzufügen sind username-Extraktion, Lesen von authorized_identities/authorized_keys, Basic-Prüfung, Grundgerüst des IdentityVerifier mit pubkey-Zweig. Abhängigkeiten: s3_ssh3_conversation (conversationID), os/unix (passwd).

---

## 9. Abweichungen von der Referenz, verpflichtend für C (Zusammenfassung)

| Nr. | Abweichung | Begründung |
|---|------------|-----------|
| 1 | 92/93/96/97/99/100 nicht senden; beim Empfang — als Kanalfehler behandeln/ignorieren, kein Crash | In der Referenz nicht implementiert (§2.2, §4, §5, §6) |
| 2 | Den Kanal beim Schließen aus der Map entfernen | In der Referenz ist `onChannelClose` toter Code — Leak |
| 3 | Parser 98: unbekannter requestType → Kanalfehler, kein panic | message.go:230-232 paniert in der Referenz |
| 4 | Kein reply-Protokoll für wantReply erfinden: interop = Abwesenheit von Antworten | §6;ARCHITECTURE.md §5 „Fixes für Go-Bugs" |
| 5 | Die Asymmetrie von datagramSender optional halten: in C SendDatagram auf jedem Kanal mit gesetztem sender erlauben, sender bei allen UDP-Kanälen beider Rollen setzen | Das beobachtbare wire-Verhalten ändert sich nicht (§3.2) |
