# SPEC-wire: Spezifikation des SSH3-Wire-Protokolls — rev nagual2/1 (draft 1)
> Languages: [RU](SPEC-wire.md) · [EN](SPEC-wire.en.md) · DE (this file)

Datum: 2026-10-16. Status: erste Fassung der Welle P8-0, abgeglichen mit dem tatsächlichen Code beider Implementierungen; Korrekturlesung 2026-10-18 (der Rest der Etappe P8-0).

## Quellen und Status des Dokuments

Die Spec beschreibt **das Wire-Protokoll, das zwei tatsächlich existierende SSH3-Implementierungen wirklich sprechen**:

- Referenz: Fork `nagual2/ssh3` 0.1.35 (Go, auf quic-go; Fork des Upstreams `francoismichel/ssh3`);
- Implementierung: `ssh3-c` 0.3.0 (C17, nginx-Stil, auf dem QUIC-API von OpenSSL ≥3.5).

Grundsatz (Entscheidung des Owners vom 2026-10-16): der Upstream ist tot, der IETF-Track geschlossen; die Spec ist ein Dokument des Projekts.
Gerüst ist der öffentliche Text des abgelaufenen draft-michel-remote-terminal-http3-00 (mit Attribution in §14);
wo das tatsächliche Protokoll vom Draft abweicht, sind die Abweichungen in §14 gesammelt. Destillat des Kanal-
Lebenszyklus: `docs/P4-WIRE.md` (hierher übertragen; P4-WIRE bleibt das historische Dokument
der Welle 2). Notationsformen: Konventionen von RFC 2119 (MUST/SHOULD/MAY); alle Ganzzahlen — QUIC varint
(RFC 9000 §16, 1/2/4/8 Byte, 2-Bit-Längenpräfix); Strings — SSHString: varint-Länge +
rohe Bytes (anders als bei SSH2 — uint32-BE-Länge).

## 1. Transportmodell

Das Protokoll läuft auf QUIC (RFC 9000/9001) und HTTP/3 (RFC 9114). Rollen:

| Schicht | Inhalt |
|---------|--------|
| QUIC | Transport, TLS 1.3, zuverlässige Streams, flow control, DATAGRAMME RFC 9221 (TP `max_datagram_frame_size`, ID 0x0020) |
| HTTP/3 | Extended CONNECT (RFC 8441/9114 §4.4) für den Aufbau der Session; uni-Streams von H3 (control/QPACK) — standardgemäß, nehmen an der SSH3-Semantik nicht teil |
| SSH3 | Kanäle mit RFC-4254-Semantik über QUIC-bidi-Streams; Datagramm-Routing über QUIC DATAGRAM |

Regeln für das Dispatching von bidi-Streams:

| № | Seite | Regel |
|---|-------|-------|
| 1 | Server | Der erste empfangene bidi-Stream der Verbindung ist immer ein HTTP/3-request-Stream (der Client sendet CONNECT vor den Kanälen); alle weiteren bidi-Streams sind SSH3-Kanäle, das erste varint muss `0xaf3627e6` sein |
| 2 | Server | uni-Streams sind immer HTTP/3 (control/QPACK); SSH3 hat keine uni-Streams |
| 3 | Client | Alle ausgehenden bidi-Streams nach dem CONNECT-Stream sind Kanäle; eingehende bidi-Streams vom Server sind immer Kanäle (der Server öffnet sie erst nach 200) |

## 2. Aufbau der Session (CONNECT-Request)

Der Client öffnet den ersten bidi-Stream und sendet einen HTTP/3 extended CONNECT:

| Element | Wert |
|---------|------|
| `:method` | `CONNECT` (extended, mit `:protocol`) |
| `:protocol` | `ssh3` — ssh3-c prüft auf Gleichheit, fork erlaubt jedes `:protocol` (debug-log) |
| `:scheme` | `https` |
| `:authority` | Host:Port des Servers |
| `:path` | `/ssh3-term` (Parameter: `?user=<username>`, `?mux=1` für ControlMaster) |
| `User-Agent` | Versionsstring (§3) |
| `Authorization` | auth-Material (§7) |

Der Username wird aus `?user=` oder aus dem userinfo des URLs übernommen. Nach 200 bleibt der Stream offen und dient
als **control stream der conversation**; über ihn laufen keine nutzbaren SSH3-Frames.

Antworten des Servers:

| Code | Grund |
|------|-------|
| 200 | Session aufgebaut; der Header `Server` trägt die Serverversion (§3) |
| 401 | Kein `Authorization` oder Schema nicht unterstützt |
| 403 | Version nicht unterstützt (`User-Agent` lässt sich nicht parsen oder protocol/spec stimmen nicht überein) |
| 425 | Request in 0-RTT vor Abschluss des Handshake (RFC 8470) — der Client muss nach dem Handshake wiederholen |
| 400 | `:scheme`/`:authority` fehlen (RFC 9114 §4.4; Gate von ssh3-c) |

Die negative Antwort wird vom Versionsheader des Servers begleitet; bei 403 sucht der Client, wenn die serverseitige
protocol-version != der aktuellen ist, eine Übereinstimmung unter den ihm bekannten Implementierungen und wiederholt
den Request mit einer kompatiblen Version (fallback-Logik der Referenz).

## 3. Versionsstring (User-Agent / Server)

Format, durch Whitespace getrennte Felder:

```
SSH <major>.<minor>[_<spec>] <impl-name> <sw-major>.<sw-minor>.<sw-patch>[ experimental_spec_version=<spec>] [key=value ...]
```

- Aktuelle Spezifikation: `SSH 3.0` + `experimental_spec_version=alpha-00`
  (fork: `SSH 3.0 francoismichel/ssh3 0.1.35 experimental_spec_version=alpha-00`;
  ssh3-c: `SSH 3.0 ssh3-c 0.3.0 experimental_spec_version=alpha-00`).
- Parsen: ≥4 Felder; Feld ≥5 mit dem Zeichen `=` wird als extra gelesen (derzeit nur
  `experimental_spec_version`); andere extras werden ignoriert.
- Unterstützung prüfen: protocol major/minor müssen übereinstimmen (3.0); ohne
  `experimental_spec_version` werden nur legacy-Implementierungen des Upstreams 0.1.3–0.1.5 akzeptiert;
  andernfalls muss spec `alpha-00` sein.
- Die Spec-Version kann auch innerhalb des Protokollfelds übertragen werden: `3.0_alpha-00`.

## 4. Conversation und Kanäle

**Conversation** = Paar (control stream, QUIC-Verbindung). Der Bezeichner der conversation —
32 Byte aus dem TLS-Exporter mit dem Label `EXPORTER-SSH3`; er wird nicht über den wire übertragen,
dient der auth-Bindung (JWT nonce/anti-replay) und den Logs. Eine QUIC-Verbindung ist eine conversation.

**Kanal** = ein einzelner bidi-Stream von QUIC. **ChannelID == QUIC StreamID des Kanals** —
einen separaten Zähler gibt es nicht. Der erste Block des Streams ist der Kanal-Header:

```
Channel Header {
  frame_type (i) = 0xaf3627e6,
  conversation_stream_id (i),   # == StreamID control stream'а; получатель сверяет со своим
  channel_type (..),            # SSHString
  max_packet_size (i),
  [target_extension]            # только для forward-типов (§6)
}
```

Kanaltypen (SSHString):

| Typ | Wer öffnet | Bedeutung |
|-----|------------|-----------|
| `session` | Client | interaktive Session/pty/exec/shell |
| `direct-tcp` | Client | TCP-Forward zum Ziel über den Server |
| `direct-udp` | Client | UDP-Forward (Datagramm-Pfad, §5) |
| `sftp` | Client | Datei-Subsystem (fork; in ssh3-c ein eigenes Modul) |
| `agent-connection` | Server | eingehende Verbindung zum ssh-agent des Clients (fork; ssh3-c: akzeptiert sie, Typ über den data-Marker `forward-agent`) |
| `reverse-forward` | Client | control-Kanal für `-R`: bind-Request/Antwort als channel data (§9) |
| `forwarded-tcp` | Server | serverseitig initiierter TCP-Kanal für das reverse-forwarding |
| `forwarded-udp` | Server | serverseitig initiierter UDP-Kanal für das reverse-forwarding |
| `dynamic-forward` | Client | SOCKS-control (-D) (fork-only) |
| `dynamic-forward-tcp` | Server | TCP-Kanal des SOCKS-Forwards (fork-only) |

**Target extension** (nur `direct-*` und `forwarded-*`), unmittelbar nach `max_packet_size`:

```
Target Extension {
  address_family (i),   # 4 = IPv4, 6 = IPv6
  ip (bytes),           # 4 или 16 байт сырого адреса
  port (u16 BE)
}
```

**Öffnungsbestätigung**: der Öffnende wartet auf demselben Stream auf 91 (open confirmation:
`varint 91, varint max_packet_size` — Limit des Empfängers) oder 92 (open failure:
`varint 92, varint reason_code (i), SSHString error_message_utf8, SSHString language_tag`).
Jede andere Nachricht vor der Bestätigung ist ein Kanalfehler. Implementierungen müssen im
Ablehnungspfad kein 92 senden: die typische Ablehnung ist `stream.CancelRead/CancelWrite(0)` oder FIN.

## 5. Kanalnachrichten

Die Nachrichten laufen nach dem Header über den Stream des Kanals. Eine ChannelID fehlt in den
Nachrichten — der Kanal wird durch den Stream selbst bestimmt (Abweichung von RFC 4254 und von
draft-00, §14). Die Bodies stehen nach der varint-Typnummer:

| Typ | Nummer | Body |
|-----|--------|------|
| CHANNEL_OPEN_CONFIRMATION | 91 | `max_packet_size (i)` |
| CHANNEL_OPEN_FAILURE | 92 | `reason_code (i), error_message (..), language_tag (..)` |
| CHANNEL_DATA | 94 | `data (..)` — stdout/stdin/TCP-Daten/Bodies von control-Kanälen |
| CHANNEL_EXTENDED_DATA | 95 | `data_type (i) [1 = STDERR; 0 на сервере запрещён], data (..)` |
| CHANNEL_REQUEST | 98 | `request_type (..), want_reply (u8), body (..)` — §6 |

Die Konstanten 93 (WINDOW_ADJUST), 96 (EOF), 97 (CLOSE), 99 (SUCCESS), 100 (FAILURE) sind
**im tatsächlichen Protokoll nicht implementiert**: flow control ist an QUIC delegiert;
EOF = QUIC FIN; Antworten auf want_reply werden nicht gesendet (das Feld wird geparst und
ignoriert — Interop-Kontrakt). Ein unbekannter Nachrichtentyp oder request-Body ist ein
Kanalfehler, kein Crash.

Chunking von DATA: der Sender schneidet auf `min(max_packet_size − overhead, len)` zu;
overhead ist die Framegröße bei leerem String (3 Byte für 94: das varint 94 ist zweibytig, 4 für 95).

## 6. Bodies der channel-requests

| request_type | Body | Semantik |
|--------------|------|----------|
| `pty-req` | `term (..), width (i), height (i), pixel_width (i), pixel_height (i), modes (..)` | PTY-Anfrage; modes ist ein opaker Block |
| `shell` | leer | Start eines login shell; der Prozess startet, Zustand LARVAL→OPEN |
| `exec` | `command (..)` | Ausführung eines Befehls; immer über shell-Ausführung |
| `subsystem` | `name (..)` | Subsystem (reserviert) |
| `window-change` | `width (i), height (i), pixel_width (i), pixel_height (i)` | resize des Terminals (SIGWINCH) |
| `signal` | `name (..)` | Zustellung eines Signals; Name ohne das Präfix `SIG` |
| `exit-status` | `status (i)` | Exit-Code; want_reply = 0 |
| `exit-signal` | `name (..), core_dumped (u8), error_message (..), language_tag (..)` | Beendigung durch Signal |
| `x11-req` | `single_connection (u8), auth_proto (..), auth_cookie (..), screen_number (i)` | wird geparst; keine Implementierung bedient es |

Spezial-Marker: `CHANNEL_DATA` mit dem payload `forward-agent` auf einem session-Kanal in LARVAL —
Anfrage nach agent-forwarding: der Server öffnet `agent-connection`-Kanäle zum UDS-Socket des
Client-Agenten.

## 7. Datagramm-Pfad (QUIC DATAGRAM, RFC 9221)

Nur die Kanäle `direct-udp` und `forwarded-udp` werden über Datagramme transportiert; alles Übrige läuft über
den stream-Pfad. Der transport parameter `max_datagram_frame_size` (TP ID 0x0020, RFC 9221 §4) muss auf beiden
Seiten vorhanden sein; die H3-Datagrammschicht (RFC 9297) ist bewusst deaktiviert — der Empfang der Datagramme
läuft in einem Loop pro QUIC-Verbindung, ohne doppeltes Routing.

Format des Payloads eines einzelnen Datagramms:

```
Datagram Payload {
  control_stream_id (i),   # сверяется с control stream'ом conversation; чужое — discard
  channel_id (i),          # == StreamID канала; поиск в карте каналов
  udp_payload (bytes)      # сырой UDP-пакет без рамки
}
```

Ein Kanal, der für den Empfang noch nicht registriert ist, hält die Datagramme in einer dangling-Queue
(je 64 pro channelID; nach der Registrierung Umsiedlung in die per-channel-Queue). Die Queues
blockieren nicht: Überlauf = Drop (QUIC DATAGRAM ist ohnehin unzuverlässig und nicht geordnet).

## 8. Schließen von Kanal und conversation

| Mechanismus | Bedeutung |
|-------------|-----------|
| QUIC FIN auf dem Stream | Half-close des Kanals (kanonischer Pfad) |
| STOP_SENDING mit Code 42 | Zurücksetzen des Kanal-Lesens (sendet nur der fork — `channelImpl.CancelRead(42)`; ssh3-c verwendet STOP_SENDING nie, sein Pfad ist FIN) |
| Schließen des control stream / FIN der conversation | Abbau der conversation; die Implementierung wartet das Schließen der Kanäle ab (drain grace ~3 s) |

Timings der Referenz: PTY-exit grace 1 s (der Client sendet FIN nach exit-status und wartet);
drain conversation ≤ 3 s; Server: nach EOF der Eingabe wird ≤ 1 s auf exit-status gewartet, dann FIN des Kanals.

## 9. Reverse forwarding (-R) — Erweiterung rev nagual2/1

Der Client öffnet den control-Kanal `reverse-forward` und sendet auf ihm den bind-Request **als channel
data (94)** — nicht als neuen Nachrichtentyp: ein alter Server behandelt den Kanal als eine unbekannte
session-Variable, weist unerwartete Daten ab und schließt den Kanal ohne Crash (graceful degradation).

**Bind-Spec der CLI**: `[bind_address:]bind_port[/tcp\|/udp]:target_host:target_port`
(leeres bind_address = loopback des Servers; `*` = `::`-Wildcard; bind_port 0 = ephemeral).

**Request (channel data auf `reverse-forward`)**:

```
RequestReverseForward {
  protocol (i),            # 0 = UDP, 1 = TCP
  bind_address (..),       # SSHString, текст как его назвал клиент
  bind_port (u16 BE),
  target_address (..),     # SSHString, канонический текст resolved цели
  target_port (u16 BE)
}
```

**Antwort (channel data auf demselben Kanal)**:

```
ReverseForwardReply {
  bound_port (u16 BE),
  error_utf8 (..)          # пустая строка = успех; иначе причина отказа
}
```

Für jeden vom Server akzeptierten bind erhält der Client/Peer einen serverseitig initiierten Kanal
`forwarded-tcp`/`forwarded-udp` mit einer target extension, die das clientseitige Ziel trägt (§4).
Das Ziel wird **clientseitig** aufgelöst. Kompatibilität mit dem Fork 0.1.35: der fork sendet
das target als IPv4 in der v4-mapped-Form `::ffff:` — der Empfänger muss beide Formen zulassen.

Guards (SSH3-Ebene, über QUIC): ≤ 10 reverse-Listener pro conversation, ≤ 64 forwarded-Kanäle pro
conversation, ≤ 8 UDP-Peers pro Listener; die bind-Richtlinie `permit-listen` (PermitOpen-Semantik)
gated den bind vor seiner Ausführung; non-loopback-binds ohne explizites `--gateway-ports` werden
auf 127.0.0.1 erzwungen.

## 10. Authentifizierung

Das auth-Material wird im `Authorization` des CONNECT-Requests übertragen; die conversation wird über den
TLS-exporter (§4) an die authentifizierte Identität gebunden — 0-RTT-Requests vor Abschluss des Handshake
werden mit 425 abgelehnt (anti-replay).

| Schema | Format | Prüfung |
|--------|--------|---------|
| `Basic` (RFC 7617) | `Authorization: Basic base64(user:password)` | fork: System-Accounts, amd64 standardmäßig (opt-out `SSH3_ENABLE_PASSWORD_LOGIN=0` / `-enable-password-login=false`); ssh3-c: Passwortdatei `-P` oder System-Accounts (`--password-system off` schaltet sie ab; fail-closed bei euid≠0), password-login ist standardmäßig an (opt-out `--enable-password-login off` / `SSH3_ENABLE_PASSWORD_LOGIN=0`). Beide Implementierungen: root per Passwort wird immer abgelehnt — PermitRootLogin prohibit-password (§13) |
| `Bearer` (pubkey) | `Authorization: Bearer <JWT>` — beide Implementierungen nutzen Bearer: das fork-Plugin `pubkey_authentication` (pubkey_auth.go:137) und ssh3-c `-i` (PEM-Schlüssel: EdDSA/ES256/RS256) | Signatur gegen authorized_keys/authorized_identities; Claims: `iss = username`, `sub = "ssh3"`, `aud = "unused"`, `client_id = "ssh3-<username>"`, `jti` = base64 des TLS-Exporters (32 Byte `EXPORTER-SSH3`), `exp` ist Pflicht und kurz, `iat`/`nbf` — sanity |
| `Bearer` (OIDC) | `Authorization: Bearer <token>` vom OIDC-Provider | RS256/ES256, discovery, JWKS-Cache mit kid-Rotation, nonce = TLS-exporter |

Kette des Servers (Reihenfolge): parse User-Agent → 425-Gate → username → Verifizierer
(fork: Plugins → Basic-wenn-aktiviert → Bearer über die IdentityVerifier-Liste;
ssh3-c: Basic → Bearer-JWT pubkey/OIDC). Anti-flood: Limit nicht authentifizierter
Verbindungen (default 100) und fehlgeschlagener Passwörter (default 10) pro username/peer.

## 11. Flow control und Parameter

Ein flow control auf SSH-Ebene fehlt (93 ist nicht implementiert) — er liegt vollständig bei QUIC. Informativ:

- advertised `max_packet_size` des Kanals: der fork sendet 30000 auf beiden Seiten; der Clamp des Peers
  `[minPeerMaxPacketSize = 4096 … local]` (channel.go:169); ssh3-c hält eine eigene Obergrenze von
  16 MiB (`S3_SSH3_CHANNEL_MAX_PACKET_LIMIT`).
- Obergrenze der SSHString-Länge — 2^24 (`MaxSSHStringLen`, fork util/wire.go:212).
- QUIC-Defaults des fork (informativ): Client `MaxIncomingStreams = 10`; Server —
  stream-rx 8→16 MiB, conn-rx 16→32 MiB, `InitialPacketSize = 1350`.
- `maxPacketSize` im Kanal-Header — Chunk-Limit des Öffnenden für DATA, kein Fenster.

## 12. Interop-Matrix (Stand 2026-10-16)

Referenzläufe C↔Go: Handshake/Versionen, session (pty/shell/exec/signal/exit-status),
TCP/UDP-Forwarding, reverse-forward (bind + 64 KiB byte-exact), sftp, agent, 0-RTT 425,
mux. Die vollständige Matrix — in den Phasenberichten P2–P9 (`docs/PLAN.md` §7);
negative Kontrolle — `interop/run-quic-go.sh`.

## 13. Sicherheitserwägungen

- Der TLS-exporter bindet die conversation an die Identität; 0-RTT wird abgelehnt (425) — anti-replay.
- Das root-gate: die Passwort-Authentifizierung von root wird immer abgelehnt (PermitRootLogin prohibit-password) — der fork `server_auth/root_gate.go`, ssh3-c — eine Ablehnung innerhalb des Basic-Verdikts; root per Schlüssel/JWT ist erlaubt.
- DoS-Guards: reverse-Limits (§9), Limit der Kanäle pro conversation, Budget der Verbindungen,
  Username-Lockout; die FAIL-Pfade des Servers bei unbekannten Typen — Kanalfehler, kein Crash.
- Non-loopback-binds — nur mit explizitem opt-in (`gateway-ports`); permit-listen gated vor dem bind.
- Serverseitig ist UDP-path:dataType=0 verboten (95 mit Typ 0 sendet der Server nicht).
- Das vollständige R2-Audit — ein eigener Track (eingefrorener Code).

## 14. Abweichungen von draft-michel-remote-terminal-http3-00

| № | Element | draft-00 | tatsächliches Protokoll (rev nagual2/1) |
|---|---------|----------|-----------------------------------------|
| 1 | `:protocol` | `remote-terminal` | `ssh3` |
| 2 | Pfad | URI-Template `…/{?username}` | Literal `/ssh3-term?user=…[&mux=1]` |
| 3 | Version | Header `remote-terminal-version` (Liste der draft-Dateien) | `User-Agent`/`Server`-String `SSH 3.0 … experimental_spec_version=alpha-00` |
| 4 | Session ID im Kanal-Header | `session_id (i)` | nein; stattdessen `conversation_stream_id` (== StreamID des control stream) |
| 5 | Signal value des Kanals | `0x5e67730e` | `0xaf3627e6` |
| 6 | Channel types | `session, x11, direct-tcp, reverse-tcp, direct-udp, reverse-udp` (Strings) | `session, direct-tcp, direct-udp, sftp, agent-connection, reverse-forward, forwarded-tcp, forwarded-udp, dynamic-forward, dynamic-forward-tcp`; kein x11-Typ |
| 7 | Nachrichten | RFC 4254-ähnlich, Message Type — **String** (`"exit-status"`), byte/uint32/uint64 → varint | Message Type — **numerisches varint** (91/92/94/95/98), request type innerhalb von 98 — String; RFC-4254-Nummern beibehalten |
| 8 | UDP-Forward | HTTP datagrams RFC 9297, quarter stream ID | QUIC DATAGRAM RFC 9221, Präfix `control_stream_id + channel_id` (§7) |
| 9 | Auth | Basic (username verpflichtend in `?user=`), OAUTH2/JWT mit dem Claim `sub = remote-terminal-<user>`, Concealed | Basic (username aus `?user=`/userinfo), pubkey — Bearer-JWT mit den Claims `sub = "ssh3"`, `client_id = "ssh3-<user>"`, `aud = "unused"` (das draft-seitige `sub = remote-terminal-<user>` wird nicht verwendet); Concealed ist nicht implementiert |
| 10 | reverse-Kanäle | `reverse-tcp`/`reverse-udp` (payload auf dem Stream des Kanals) | control-Kanal `reverse-forward` + bind-Request/Antwort als channel data + serverseitig initiierte `forwarded-tcp/forwarded-udp` mit target extension |
| 11 | Ablehnung des Öffnens | nicht spezifiziert | 92 (selten) / QUIC cancel(0) / FIN |

Der Draft wird als historisches Gerüst veröffentlicht (expired, 2024-07-31, individual); Attribution:
draft-michel-remote-terminal-http3-00, François Michel (UCLouvain) et al. — ersetzt
draft-michel-ssh3. Das tatsächliche Protokoll ist ein Artefakt der beiden Implementierungen weiter unten.
