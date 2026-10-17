# ssh3-c — Architektur (nginx-style, zero-copy)

> Languages: [RU](ARCHITECTURE.md) · [EN](ARCHITECTURE.en.md) · DE (this file)

Erstellt: 2026-10-01. Übergeordneter Track: `project/ssh3/docs/ROADMAP.md`, Profil: `project/ssh3/docs/PROFILE-2026-09-29.md`.
Stilreferenz: nginx 1.31.7 (`C:\Git\temp\ssh3-c\refs\nginx\` — read-only).

## 1. Ziel und Motivation

Den SSH3-Transport von Go nach reinem C (C17) im Architekturstil von nginx umschreiben. Die Zielposition ist ein Platz in Linux-Systemen analog zu OpenSSH: Basisbibliotheken, permissive Lizenz, Paketierung in Distributionen. Ziele: **Geschwindigkeit** (bulk ≥ Go-Version, Ziel — mit SSH2 365–488 MB/s gleichziehen) und **Binärgröße** (<5 MB gegenüber ~15 MB bei Go). Prinzip — zero-copy auf dem gesamten data-path.

Motivation aus dem Profil der Go-Version (loopback, push 1 GiB):

| Verlustpunkt | CPU-Anteil | Was die C-Version macht |
|---|---|---|
| UDP-Syscall-Sturm (`sendQueue.Run→WritePacket`) | 39%/25% | GSO `UDP_SEGMENT` + sendmsg-chain über den vorhandenen Puffern (wie `ngx_quic_create_segments`) |
| `runtime.memmove` | 5–6.5% | `s3_buf_t`/`s3_chain_t`-Views statt Kopien, Parser liest `pos/end` |
| GC/Allokationen | 7–15% | Arena-Pools pro connection/stream, Freelist für Puffer |
| Goroutine-Modell (`schedule` 13%, `selectgo` 4%) | ~17% | ein einziger event loop, posted events, kein Thread pro Stream |
| AES-GCM | ~3% | unschuldig, AES-NI |

Referenzwerte: raw quic-go 326 MB/s; Go ssh3 130→175 MB/s (nach den Pools); OpenSSH 365–488 MB/s.

## 2. Kernentscheidungen

| Nr. | Entscheidung | Begründung |
|---|---------|-------------|
| 1 | Sprache: **C17 (reines C)**, wie nginx und OpenSSH; Rückgabecodes `S3_OK/S3_ERROR/S3_AGAIN`, Präfix `s3_`/`S3_` | beide Referenzen sind in C geschrieben; das Ziel „Platz von OpenSSH“ schließt eine Abhängigkeit von libstdc++ aus (selbst in basis-Alpine nicht vorhanden); das C-ABI ist für Pakete stabil. Ersetzte die frühere Entscheidung „C20“ am 2026-10-01 |
| 2 | QUIC-Stack: Anpassung von nginx `src/event/quic/` (BSD-2) an unsere core/event-Schicht, keine Neuentwicklung von Grund auf | nginx QUIC ist battle-tested (v1, RFC 9000/9001/9002), der Stil ist bereits nginx; eigener Stack = Monate voller Protokoll-Bugs |
| 3 | HTTP/3: das Minimum aus `src/http/v3/` — extended CONNECT (`:protocol=ssh3`), QPACK (parse/encode/table), uni-Streams. Der data-path der Kanäle ist raw QUIC-bidi-Streams, kein h3-Framing auf den Daten | Protokollkarte der Go-Version: 1 HEADERS + N raw streams + QUIC datagrams |
| 4 | UDP-I/O: `sendmsg`-chain + `UDP_SEGMENT` GSO beim Senden; Empfang per `recvmsg` je Datagramm + Pseudo-Connections im rbtree (Modell `ngx_quic_recvmsg`) | Muster `ngx_udp_sendmsg_chain.c` + `ngx_event_quic_output.c`; UDP_GRO — hinter einem Feature-Flag (nginx nutzt es nicht) |
| 5 | Wire-Kompatibilität mit dem Go-Fork v0.1.21 (Protokoll `SSH 3.0 alpha-00`): interop-Tests „C-Client ↔ Go-Server“ und „Go-Client ↔ C-Server“ — Abnahmekriterium ab M4+ | der Transport ist ein Ersatz, das Protokoll ist dasselbe |

## 3. Schichten (Projektion der nginx-Struktur)

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

Abhängigkeiten: OpenSSL 3.5+ (QUIC API) oder quictls/boringssl; Linux zuerst (GSO, PTY), Windows — danach (ConPTY, ohne GSO → normales sendmsg).

## 4. Zero-copy-Regeln (verpflichtend)

1. Protokoll-String/-Feld = View (`s3_str_t{len,data}`) über den Empfangspuffer; Ownership wird nur explizit übertragen.
2. Parser: `u_char *pos, *end`, ohne Zwischenallokationen (Muster `ngx_quic_parse_int`).
3. Senden: `s3_chain_t` über dem Speicher der Protokollschicht; `sendmsg` baut `iovec` ohne Kopien zusammen (`ngx_output_chain_to_iovec` — Zusammenfassung benachbarter Puffer).
4. QUIC-Puffer: shadow-buf mit refcount + freelist (`ngx_quic_alloc_buf/free_buf`, `buf_refs`).
5. Ein Pool pro Verbindung/Kanal; kleine Allokationen werden nicht einzeln freigegeben; cleanup-Handler für fds.
6. `ParseSSHString` aus Go (2 alloc+2 copy pro Nachricht) ist konstruktionsbedingt verboten.

## 5. Wire-Protokoll (Kompatibilität mit dem Go-Fork)

Transport: QUIC v1, `Allow0RTT`, datagrams aktiviert; Einstellungen aus `cmd/ssh3-server.go`: `InitialPacketSize=1350`, Stream-Fenster 8/16 MiB, conn 16/32 MiB.

Control stream: extended CONNECT, `:protocol=ssh3`, Pfad `/ssh3-term?user=...`, `Authorization: Basic|Bearer`, `User-Agent: SSH 3.0 ...`; Server: 403 — Version, 425 — 0-RTT anti-replay.

Ein Kanal = ein raw bidi QUIC stream, **ChannelID = QUIC Stream ID**. Kanal-Header:
`varint 0xaf3627e6 | varint controlStreamID | SSHString type | varint maxPacketSize` (+ für `direct-*`: `varint family, raw IP 4|16, uint16be port`). Typen: `session`, `direct-tcp`, `direct-udp`, `sftp`, `agent-connection`.

Kanal-Nachrichten (alle Ganzzahlen — QUIC varint; SSHString = varint-len + Bytes):
`91 open_confirmation{varint maxPacketSize}`, `92 open_failure{varint reason, SSHString err, SSHString lang}`, `94 data{SSHString}`, `95 extended_data{varint dataType, SSHString}`, `98 request{SSHString type, u8 wantReply, body}` — pty-req/shell/exec/subsystem/window-change/signal/exit-status/exit-signal (Felder — siehe `project/ssh3/message/channel_request.go`). Unbekannter Typ = Kanal-Fehler (kein panic).

Datagramm (QUIC DATAGRAM): `varint controlStreamID | varint channelID | payload`.

Fixes für Go-Bugs: `wantReply`-Requests ohne Antworten (99/100 nicht implementiert) — nicht reproduzieren, Empfang auf beiden Seiten unterstützen; `-packet-size`/`-stream-rx-mb` auf dem Client waren tot — in C funktionieren Flags entweder, oder es gibt sie nicht.

## 6. Entwicklungsphasen

Der Entwicklungsplan für Client und Server — Phasen P0–P8 — liegt in [docs/PLAN.md](PLAN.md) (Source of Truth für den Plan; die frühere Tabelle M0–M6 ist darin aufgegangen).

## 7. Risiken

| Nr. | Risiko | Mitigation |
|---|------|----------|
| 1 | Die Anpassung von nginx QUIC zieht `ngx_cycle`-Abhängigkeiten nach sich | schichtweise portieren, beginnend mit transport/frames/protection; cycle durch s3_context ersetzen; Liste der Unterschiede in docs/PORTING-nginx-quic.md pflegen |
| 2 | OpenSSL 3.5 QUIC API noch nicht überall verfügbar; quictls — kein Upstream-Branch | ssl-Schicht wie in nginx: 3 API-Varianten hinter Feature-Flags; standardmäßig quictls |
| 3 | 0-RTT und Anti-Replay | das Go-Modell kopieren (425 Too Early) + RFC 9002 |
| 4 | Windows-Port (ConPTY, Fehlen von UDP_SEGMENT) | M0–M5 nur Linux/WSL; Windows nach Parität, sendmsg ohne GSO |
| 5 | Drift des Wire-Formats zwischen Go- und C-Version | interop-Tests in CI in beide Richtungen bei jedem Release; wire-Vektoren aus `wire_vectors_test.go` als Fixtures |
