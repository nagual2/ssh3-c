# ssh3-c — architecture (nginx-style, zero-copy)

> Languages: [RU](ARCHITECTURE.md) · EN (this file) · [DE](ARCHITECTURE.de.md)

Created: 2026-10-01. Parent track: `project/ssh3/docs/ROADMAP.md`, profile: `project/ssh3/docs/PROFILE-2026-09-29.md`.
Style reference: nginx 1.31.7 (`C:\Git\temp\ssh3-c\refs\nginx\` — read-only).

## 1. Goal and motivation

Rewrite the SSH3 transport from Go to pure C (C17) in the nginx architectural style. The target position is to occupy a place in Linux systems analogous to OpenSSH: base libraries, permissive license, packaging into distributions. Goals: **speed** (bulk ≥ the Go version, the target is to match SSH2 365–488 MB/s) and **binary size** (<5 MB versus ~15 MB for Go). The principle is zero-copy across the entire data-path.

Motivation from the Go-version profile (loopback, push 1 GiB):

| Loss point | CPU share | What the C version does |
|---|---|---|
| UDP syscall storm (`sendQueue.Run→WritePacket`) | 39%/25% | GSO `UDP_SEGMENT` + sendmsg-chain on top of existing buffers (like `ngx_quic_create_segments`) |
| `runtime.memmove` | 5–6.5% | `s3_buf_t`/`s3_chain_t` views instead of copies, parser reads `pos/end` |
| GC/allocations | 7–15% | arena pools per connection/stream, buffer freelist |
| goroutine model (`schedule` 13%, `selectgo` 4%) | ~17% | a single event loop, posted events, no thread per stream |
| AES-GCM | ~3% | not guilty, AES-NI |

Reference numbers: raw quic-go 326 MB/s; Go ssh3 130→175 MB/s (after pools); OpenSSH 365–488 MB/s.

## 2. Key decisions

| # | Decision | Rationale |
|---|---------|-------------|
| 1 | Language: **C17 (pure C)**, like nginx and OpenSSH; return codes `S3_OK/S3_ERROR/S3_AGAIN`, prefix `s3_`/`S3_` | both references are written in C; the "OpenSSH place" goal rules out a dependency on libstdc++ (absent even in base Alpine); the C ABI is stable for packaging. Replaced the earlier "C20" decision on 2026-10-01 |
| 2 | QUIC stack: adapting nginx `src/event/quic/` (BSD-2) to our core/event layer, not writing from scratch | nginx QUIC is battle-tested (v1, RFC 9000/9001/9002), the style is already nginx; an own stack = months of protocol bugs |
| 3 | HTTP/3: the minimum from `src/http/v3/` — extended CONNECT (`:protocol=ssh3`), QPACK (parse/encode/table), uni streams. The data-path of channels is raw QUIC bidi streams, no h3 framing on data | protocol map of the Go version: 1 HEADERS + N raw streams + QUIC datagrams |
| 4 | UDP I/O: `sendmsg`-chain + `UDP_SEGMENT` GSO on send; receive via `recvmsg` per datagram + pseudo-connections in an rbtree (the `ngx_quic_recvmsg` model) | pattern `ngx_udp_sendmsg_chain.c` + `ngx_event_quic_output.c`; UDP_GRO — behind a feature flag (nginx does not use it) |
| 5 | Wire compatibility with the Go fork v0.1.21 (protocol `SSH 3.0 alpha-00`): interop tests "C client ↔ Go server" and "Go client ↔ C server" — acceptance criterion from M4+ | the transport is a replacement, the protocol is the same |

## 3. Layers (projection of the nginx structure)

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

Dependencies: OpenSSL 3.5+ (QUIC API) or quictls/boringssl; Linux first (GSO, PTY), Windows — next (ConPTY, no GSO → plain sendmsg).

## 4. Zero-copy rules (mandatory)

1. A protocol string/field = a view (`s3_str_t{len,data}`) over the receive buffer; ownership is transferred only explicitly.
2. Parser: `u_char *pos, *end`, no intermediate allocations (the `ngx_quic_parse_int` pattern).
3. Send: `s3_chain_t` on top of protocol-layer memory; `sendmsg` assembles `iovec` without copies (`ngx_output_chain_to_iovec` — merging of adjacent buffers).
4. QUIC buffers: shadow-buf with refcount + freelist (`ngx_quic_alloc_buf/free_buf`, `buf_refs`).
5. A pool per connection/channel; small allocations are not freed individually; cleanup handlers for fds.
6. `ParseSSHString` from Go (2 alloc+2 copies per message) is forbidden by construction.

## 5. Wire protocol (compatibility with the Go fork)

Transport: QUIC v1, `Allow0RTT`, datagrams enabled; settings from `cmd/ssh3-server.go`: `InitialPacketSize=1350`, stream windows 8/16 MiB, conn 16/32 MiB.

Control stream: extended CONNECT, `:protocol=ssh3`, path `/ssh3-term?user=...`, `Authorization: Basic|Bearer`, `User-Agent: SSH 3.0 ...`; server: 403 — version, 425 — 0-RTT anti-replay.

A channel = a raw bidi QUIC stream, **ChannelID = QUIC Stream ID**. The channel header:
`varint 0xaf3627e6 | varint controlStreamID | SSHString type | varint maxPacketSize` (+ for `direct-*`: `varint family, raw IP 4|16, uint16be port`). Types: `session`, `direct-tcp`, `direct-udp`, `sftp`, `agent-connection`.

Channel messages (all integers — QUIC varint; SSHString = varint-len + bytes):
`91 open_confirmation{varint maxPacketSize}`, `92 open_failure{varint reason, SSHString err, SSHString lang}`, `94 data{SSHString}`, `95 extended_data{varint dataType, SSHString}`, `98 request{SSHString type, u8 wantReply, body}` — pty-req/shell/exec/subsystem/window-change/signal/exit-status/exit-signal (fields — see `project/ssh3/message/channel_request.go`). An unknown type = a channel error (not a panic).

Datagram (QUIC DATAGRAM): `varint controlStreamID | varint channelID | payload`.

Fixes for Go bugs: `wantReply` requests without replies (99/100 not implemented) — do not reproduce, support receiving on both sides; `-packet-size`/`-stream-rx-mb` on the client were dead — in C, flags either work or do not exist.

## 6. Development stages

The development plan for the client and server — phases P0–P8 — lives in [docs/PLAN.md](PLAN.md) (the source of truth for the plan; the former M0–M6 table has been absorbed by it).

## 7. Risks

| # | Risk | Mitigation |
|---|------|----------|
| 1 | Adapting nginx QUIC drags in `ngx_cycle` dependencies | port layer by layer, starting with transport/frames/protection; replace cycle with s3_context; maintain a list of differences in docs/PORTING-nginx-quic.md |
| 2 | The OpenSSL 3.5 QUIC API is not available everywhere yet; quictls — a non-upstream branch | the ssl layer as in nginx: 3 API variants behind feature flags; quictls by default |
| 3 | 0-RTT and anti-replay | copy the Go model (425 Too Early) + RFC 9002 |
| 4 | Windows port (ConPTY, no UDP_SEGMENT) | M0–M5 Linux/WSL only; Windows after parity, sendmsg without GSO |
| 5 | Wire-format drift between the Go and C versions | interop tests in CI in both directions on every release; wire vectors from `wire_vectors_test.go` as fixtures |
