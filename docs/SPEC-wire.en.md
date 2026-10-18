# SPEC-wire: SSH3 wire-protocol specification — rev nagual2/1 (draft 1)

> Languages: [RU](SPEC-wire.md) · EN (this file) · [DE](SPEC-wire.de.md)

Date: 2026-10-16. Status: first revision of the P8-0 wave, verified against the live code of both implementations; proofread 2026-10-18 (the P8-0 remainder).

## Sources and document status

The spec describes **the wire protocol actually spoken by two live SSH3 implementations**:

- reference: the `nagual2/ssh3` 0.1.35 fork (Go, on top of quic-go; a fork of upstream `francoismichel/ssh3`);
- implementation: `ssh3-c` 0.3.0 (C17, nginx style, on top of the OpenSSL ≥3.5 QUIC API).

Principle (owner's decision, 2026-10-16): upstream is dead, the IETF track is closed; the spec is a project document.
The skeleton is the public text of the expired draft-michel-remote-terminal-http3-00 (with attribution in §14);
wherever the live protocol diverges from the draft, the divergences are consolidated in §14. The distillation of the channel
lifecycle: `docs/P4-WIRE.md` (moved here; P4-WIRE remains a historical document
of wave 2). Notation: RFC 2119 conventions (MUST/SHOULD/MAY); all integers are QUIC varints
(RFC 9000 §16, 1/2/4/8 bytes, a 2-bit length prefix); strings are SSHString: varint length +
raw bytes (unlike SSH2, which uses a uint32-BE length).

## 1. Transport model

The protocol lives on top of QUIC (RFC 9000/9001) and HTTP/3 (RFC 9114). Roles:

| Layer | Content |
|------|------------|
| QUIC | Transport, TLS 1.3, reliable streams, flow control, RFC 9221 DATAGRAMS (TP `max_datagram_frame_size`, ID 0x0020) |
| HTTP/3 | Extended CONNECT (RFC 8441/9114 §4.4) for session establishment; H3 uni-streams (control/QPACK) are standard and play no part in SSH3 semantics |
| SSH3 | Channels with RFC 4254 semantics on top of QUIC bidi streams; datagram routing on top of QUIC DATAGRAM |

Bidi-stream dispatch rules:

| № | Side | Rule |
|---|---------|---------|
| 1 | Server | The first accepted bidi stream of a connection is always an HTTP/3 request stream (the client sends CONNECT before any channels); every subsequent bidi is an SSH3 channel, and its first varint must be `0xaf3627e6` |
| 2 | Server | Uni-streams are always HTTP/3 (control/QPACK); SSH3 has no uni-streams |
| 3 | Client | All outgoing bidi after the CONNECT stream are channels; incoming bidi from the server are always channels (the server opens them only after the 200) |

## 2. Session establishment (CONNECT request)

The client opens the first bidi stream and sends an HTTP/3 extended CONNECT:

| Element | Value |
|---------|----------|
| `:method` | `CONNECT` (extended, with `:protocol`) |
| `:protocol` | `ssh3` — ssh3-c checks for equality, the fork allows any `:protocol` (debug-log) |
| `:scheme` | `https` |
| `:authority` | server host:port |
| `:path` | `/ssh3-term` (parameters: `?user=<username>`, `?mux=1` for ControlMaster) |
| `User-Agent` | version string (§3) |
| `Authorization` | auth material (§7) |

The username is taken from `?user=` or from the URL userinfo. After the 200 the stream stays open and serves
as the **control stream of the conversation**; no useful SSH3 frames travel on it.

Server responses:

| Code | Reason |
|-----|---------|
| 200 | Session established; the `Server` header carries the server version (§3) |
| 401 | No `Authorization`, or the scheme is unsupported |
| 403 | Version not supported (the `User-Agent` does not parse, or protocol/spec do not match) |
| 425 | Request in 0-RTT before handshake completion (RFC 8470) — the client must repeat it after the handshake |
| 400 | Missing `:scheme`/`:authority` (RFC 9114 §4.4; the ssh3-c gate) |

A negative response is accompanied by the server version header; on a 403, if the server's
protocol-version is not the current one, the client looks for a match among the implementations it knows
and repeats the request with a compatible version (the reference's fallback logic).

## 3. Version string (User-Agent / Server)

Format, whitespace-separated fields:

```
SSH <major>.<minor>[_<spec>] <impl-name> <sw-major>.<sw-minor>.<sw-patch>[ experimental_spec_version=<spec>] [key=value ...]
```

- Current specification: `SSH 3.0` + `experimental_spec_version=alpha-00`
  (fork: `SSH 3.0 francoismichel/ssh3 0.1.35 experimental_spec_version=alpha-00`;
  ssh3-c: `SSH 3.0 ssh3-c 0.3.0 experimental_spec_version=alpha-00`).
- Parsing: ≥4 fields; a field at position ≥5 containing `=` is read as an extra (currently only
  `experimental_spec_version`); other extras are ignored.
- Support check: the protocol major/minor must match (3.0); without
  `experimental_spec_version` only legacy implementations of upstream 0.1.3–0.1.5 are accepted;
  otherwise the spec must be `alpha-00`.
- The spec version may also travel inside the protocol field: `3.0_alpha-00`.

## 4. Conversation and channels

**Conversation** = the pair (control stream, QUIC connection). The conversation identifier is
32 bytes from the TLS exporter with label `EXPORTER-SSH3`; it is not transmitted on the wire and is used
for auth binding (JWT nonce/anti-replay) and logs. One QUIC connection — one conversation.

**Channel** = one QUIC bidi stream. **ChannelID == the channel's QUIC StreamID** — there is no
separate numbering authority. The first block of the stream is the channel header:

```
Channel Header {
  frame_type (i) = 0xaf3627e6,
  conversation_stream_id (i),   # == StreamID control stream'а; получатель сверяет со своим
  channel_type (..),            # SSHString
  max_packet_size (i),
  [target_extension]            # только для forward-типов (§6)
}
```

Channel types (SSHString):

| Type | Opened by | Meaning |
|-----|---------------|-------|
| `session` | client | interactive session/pty/exec/shell |
| `direct-tcp` | client | TCP forward to a target through the server |
| `direct-udp` | client | UDP forward (datagram path, §5) |
| `sftp` | client | file subsystem (fork; a separate module in ssh3-c) |
| `agent-connection` | server | incoming connection to the client's ssh-agent (fork; ssh3-c: accepts it, the type is conveyed via the data marker `forward-agent`) |
| `reverse-forward` | client | control channel of `-R`: bind request/response as channel data (§9) |
| `forwarded-tcp` | server | server-initiated TCP channel for reverse forwarding |
| `forwarded-udp` | server | server-initiated UDP channel for reverse forwarding |
| `dynamic-forward` | client | SOCKS control (-D) (fork-only) |
| `dynamic-forward-tcp` | server | TCP channel of the SOCKS forward (fork-only) |

**Target extension** (`direct-*` and `forwarded-*` only), immediately after `max_packet_size`:

```
Target Extension {
  address_family (i),   # 4 = IPv4, 6 = IPv6
  ip (bytes),           # 4 или 16 байт сырого адреса
  port (u16 BE)
}
```

**Open confirmation**: the opener waits on the same stream for 91 (open confirmation:
`varint 91, varint max_packet_size` — the receiver's limit) or 92 (open failure:
`varint 92, varint reason_code (i), SSHString error_message_utf8, SSHString language_tag`).
Any other message before the confirmation is a channel error. Implementations are not required
to send 92 on the rejection path: a typical rejection is `stream.CancelRead/CancelWrite(0)` or FIN.

## 5. Channel messages

Messages travel on the channel stream after the header. The messages carry no ChannelID —
the channel is identified by the stream itself (a divergence from RFC 4254 and from draft-00, §14). Bodies follow
the varint type number:

| Type | Number | Body |
|-----|-------|------|
| CHANNEL_OPEN_CONFIRMATION | 91 | `max_packet_size (i)` |
| CHANNEL_OPEN_FAILURE | 92 | `reason_code (i), error_message (..), language_tag (..)` |
| CHANNEL_DATA | 94 | `data (..)` — stdout/stdin/TCP data/bodies of control channels |
| CHANNEL_EXTENDED_DATA | 95 | `data_type (i) [1 = STDERR; 0 на сервере запрещён], data (..)` |
| CHANNEL_REQUEST | 98 | `request_type (..), want_reply (u8), body (..)` — §6 |

The constants 93 (WINDOW_ADJUST), 96 (EOF), 97 (CLOSE), 99 (SUCCESS), 100 (FAILURE) are **not implemented in the live
protocol**: flow control is delegated to QUIC; EOF = QUIC FIN; replies to
want_reply are not sent (the field is parsed and ignored — an interop contract). An unknown message
type or request body is a channel error, not a crash.

DATA chunking: the sender cuts into `min(max_packet_size − overhead, len)` chunks; overhead is the frame size with an empty string (3 bytes for 94: the varint 94 is two bytes, 4 for 95).

## 6. Channel-request bodies

| request_type | Body | Semantics |
|--------------|------|-----------|
| `pty-req` | `term (..), width (i), height (i), pixel_width (i), pixel_height (i), modes (..)` | PTY request; modes is an opaque block |
| `shell` | empty | start a login shell; the process starts, state LARVAL→OPEN |
| `exec` | `command (..)` | command execution; always via shell execution |
| `subsystem` | `name (..)` | subsystem (reserved) |
| `window-change` | `width (i), height (i), pixel_width (i), pixel_height (i)` | terminal resize (SIGWINCH) |
| `signal` | `name (..)` | signal delivery; the name without the `SIG` prefix |
| `exit-status` | `status (i)` | exit code; want_reply = 0 |
| `exit-signal` | `name (..), core_dumped (u8), error_message (..), language_tag (..)` | termination by signal |
| `x11-req` | `single_connection (u8), auth_proto (..), auth_cookie (..), screen_number (i)` | parsed; no implementation serves it |

Special marker: `CHANNEL_DATA` with payload `forward-agent` on a session channel in LARVAL — a request
for agent forwarding: the server opens `agent-connection` channels to the UDS socket of the client's agent.

## 7. Datagram path (QUIC DATAGRAM, RFC 9221)

Only `direct-udp` and `forwarded-udp` channels travel as datagrams; everything else uses the stream path.
The transport parameter `max_datagram_frame_size` (TP ID 0x0020, RFC 9221 §4) must be present on both sides;
the H3 datagram layer (RFC 9297) is deliberately disabled — datagram reception is a single loop per
QUIC connection, with no double routing.

Payload format of a single datagram:

```
Datagram Payload {
  control_stream_id (i),   # сверяется с control stream'ом conversation; чужое — discard
  channel_id (i),          # == StreamID канала; поиск в карте каналов
  udp_payload (bytes)      # сырой UDP-пакет без рамки
}
```

A channel not yet registered for reception holds datagrams in a dangling queue
(64 per channelID; after registration they are moved over to a per-channel queue). The queues are
non-blocking: overflow = drop (QUIC DATAGRAM is unreliable and unordered anyway).

## 8. Closing a channel and the conversation

| Mechanism | Meaning |
|----------|-------|
| QUIC FIN on the stream | half-close of the channel (the canonical path) |
| STOP_SENDING code 42 | reset of channel reading (sent by the fork only — `channelImpl.CancelRead(42)`; ssh3-c never sends STOP_SENDING, its path is FIN) |
| control stream closure / conversation FIN | conversation teardown; the implementation waits for the channels to close (drain grace ~3 s) |

Reference timings: PTY-exit grace 1 s (the client sends FIN after exit-status and waits);
conversation drain ≤ 3 s; server: after input EOF it waits for exit-status for ≤ 1 s, then FINs the channel.

## 9. Reverse forwarding (-R) — a rev nagual2/1 addition

The client opens the `reverse-forward` control channel and sends the bind request **as channel
data (94)** on it — not as a new message type: an old server treats the channel as an unknown
session variable, rejects the unexpected data, and closes the channel without a crash (graceful
degradation).

**CLI bind spec**: `[bind_address:]bind_port[/tcp\|/udp]:target_host:target_port`
(an empty bind_address = the server's loopback; `*` = the `::` wildcard; bind_port 0 = ephemeral).

**Request (channel data on `reverse-forward`)**:

```
RequestReverseForward {
  protocol (i),            # 0 = UDP, 1 = TCP
  bind_address (..),       # SSHString, текст как его назвал клиент
  bind_port (u16 BE),
  target_address (..),     # SSHString, канонический текст resolved цели
  target_port (u16 BE)
}
```

**Response (channel data on the same channel)**:

```
ReverseForwardReply {
  bound_port (u16 BE),
  error_utf8 (..)          # пустая строка = успех; иначе причина отказа
}
```

For each bind accepted by the server, the client/peer receives a server-initiated
`forwarded-tcp`/`forwarded-udp` channel with a target extension carrying the client-side target (§4).
The target is resolved on the **client** side. Compatibility with fork 0.1.35: the fork sends
the target as IPv4 in the v4-mapped form `::ffff:` — the receiver must accept both forms.

Guards (SSH3 level, on top of QUIC): ≤ 10 reverse listeners per conversation, ≤ 64
forwarded channels per conversation, ≤ 8 UDP peers per listener; the `permit-listen`
bind policy (PermitOpen semantics) gates the bind before it is executed; non-loopback binds
without explicit `--gateway-ports` are forced to 127.0.0.1.

## 10. Authentication

The auth material travels in the `Authorization` of the CONNECT request; the conversation is bound to
the authenticated identity via the TLS exporter (§4) — 0-RTT requests before handshake
completion are rejected with 425 (anti-replay).

| Scheme | Format | Verification |
|-------|--------|----------|
| `Basic` (RFC 7617) | `Authorization: Basic base64(user:password)` | fork: system accounts, amd64 by default (opt-out `SSH3_ENABLE_PASSWORD_LOGIN=0` / `-enable-password-login=false`); ssh3-c: a password file `-P` or system accounts (`--password-system off` disables them; fail-closed when euid≠0), password-login is on by default (opt-out `--enable-password-login off` / `SSH3_ENABLE_PASSWORD_LOGIN=0`). Both implementations: root via password is always refused — PermitRootLogin prohibit-password (§13) |
| `Bearer` (pubkey) | `Authorization: Bearer <JWT>` — both implementations travel as Bearer: the fork plugin `pubkey_authentication` (pubkey_auth.go:137) and ssh3-c `-i` (PEM key: EdDSA/ES256/RS256) | signature verified against authorized_keys/authorized_identities; claims: `iss = username`, `sub = "ssh3"`, `aud = "unused"`, `client_id = "ssh3-<username>"`, `jti` = base64 of the TLS exporter (32 bytes of `EXPORTER-SSH3`), `exp` is mandatory and short, `iat`/`nbf` are sanity-checked |
| `Bearer` (OIDC) | `Authorization: Bearer <token>` from an OIDC provider | RS256/ES256, discovery, a JWKS cache with kid rotation, nonce = TLS exporter |

Server chain (order): parse User-Agent → the 425 gate → username → verifiers
(fork: plugins → Basic-if-enabled → Bearer via the IdentityVerifier list;
ssh3-c: Basic → Bearer-JWT pubkey/OIDC). Anti-flood: limits on unauthenticated
connections (default 100) and failed passwords (default 10) per username/peer.

## 11. Flow control and parameters

SSH-level flow control is absent (93 is not implemented) — it is entirely QUIC. Informative facts:

- the advertised `max_packet_size` of a channel: the fork sends 30000 on both sides; the peer clamp
  `[minPeerMaxPacketSize = 4096 … local]` (channel.go:169); ssh3-c keeps its own
  ceiling of 16 MiB (`S3_SSH3_CHANNEL_MAX_PACKET_LIMIT`).
- the SSHString length ceiling is 2^24 (`MaxSSHStringLen`, fork util/wire.go:212).
- QUIC defaults of the fork (informative): client `MaxIncomingStreams = 10`; server —
  stream-rx 8→16 MiB, conn-rx 16→32 MiB, `InitialPacketSize = 1350`.
- `maxPacketSize` in the channel header is the opener's DATA chunk limit, not a window.

## 12. Interop matrix (fact, 2026-10-16)

Reference C↔Go runs: handshake/versions, session (pty/shell/exec/signal/exit-status),
TCP/UDP forwarding, reverse-forward (bind + 64 KiB byte-exact), sftp, agent, 0-RTT 425,
mux. The full matrix is in the P2–P9 phase reports (`docs/PLAN.md` §7); the negative control is
`interop/run-quic-go.sh`.

## 13. Security considerations

- The TLS exporter binds the conversation to the identity; 0-RTT is rejected (425) — anti-replay.
- The root gate: password authentication of root is always refused (PermitRootLogin prohibit-password) — the fork `server_auth/root_gate.go`, ssh3-c — a refusal inside the Basic verdict; root via a key/JWT is allowed.
- DoS guards: the reverse limits (§9), the channel limit per conversation, the connection budget,
  the username lockout; server FAIL paths on unknown types are a channel error, not a crash.
- Non-loopback binds only with explicit opt-in (`gateway-ports`); permit-listen gates before the bind.
- Server-side UDP-path dataType=0 is forbidden (the server does not send 95 with type 0).
- The full R2 audit is a separate track (frozen code).

## 14. Divergences from draft-michel-remote-terminal-http3-00

| № | Element | draft-00 | live protocol (rev nagual2/1) |
|---|---------|----------|-------------------------------|
| 1 | `:protocol` | `remote-terminal` | `ssh3` |
| 2 | Path | URI template `…/{?username}` | the literal `/ssh3-term?user=…[&mux=1]` |
| 3 | Version | the `remote-terminal-version` header (a list of draft files) | a `User-Agent`/`Server` string `SSH 3.0 … experimental_spec_version=alpha-00` |
| 4 | Session ID in the channel header | `session_id (i)` | absent; instead `conversation_stream_id` (== the control stream's StreamID) |
| 5 | Channel signal value | `0x5e67730e` | `0xaf3627e6` |
| 6 | Channel types | `session, x11, direct-tcp, reverse-tcp, direct-udp, reverse-udp` (strings) | `session, direct-tcp, direct-udp, sftp, agent-connection, reverse-forward, forwarded-tcp, forwarded-udp, dynamic-forward, dynamic-forward-tcp`; there is no x11 type |
| 7 | Messages | RFC 4254-like, the Message Type is a **string** (`"exit-status"`), byte/uint32/uint64 → varint | the Message Type is a **numeric varint** (91/92/94/95/98), the request type inside 98 is a string; the RFC 4254 numbers are preserved |
| 8 | UDP forward | HTTP datagrams RFC 9297, quarter stream ID | QUIC DATAGRAM RFC 9221, the `control_stream_id + channel_id` prefix (§7) |
| 9 | Auth | Basic (the username is mandatory in `?user=`), OAUTH2/JWT with the claim `sub = remote-terminal-<user>`, Concealed | Basic (the username from `?user=`/userinfo), pubkey as a Bearer-JWT with the claims `sub = "ssh3"`, `client_id = "ssh3-<user>"`, `aud = "unused"` (the draft's `sub = remote-terminal-<user>` is not used); Concealed is not implemented |
| 10 | Reverse channels | `reverse-tcp`/`reverse-udp` (payload on the channel stream) | the `reverse-forward` control channel + bind request/response as channel data + server-initiated `forwarded-tcp/forwarded-udp` with a target extension |
| 11 | Open rejection | not specified | 92 (rare) / QUIC cancel(0) / FIN |

The draft is published as a historical skeleton (expired, 2024-07-31, individual); attribution:
draft-michel-remote-terminal-http3-00, François Michel (UCLouvain) et al. — it replaces
draft-michel-ssh3. The live protocol is the artifact of the two implementations below.
