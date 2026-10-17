# P4-WIRE: channel lifecycle and datagram routing of SSH3 (specification for the C port, wave 2)
> Languages: [RU](P4-WIRE.md) · EN (this file) · [DE](P4-WIRE.de.md)

Date: 2026-10-04.
Reference: `C:\Git\project\ssh3` (Go fork, protocol `SSH 3.0 alpha-00`, wire-compatible base — see `docs/ARCHITECTURE.md` §5). All `file:line` references point to the files of the reference. The document is self-sufficient for writing wave-2 C modules without reading the Go code; wherever a fact was not found in the reference, it is stated explicitly.

**NB 2026-10-16:** the current protocol specification is `docs/SPEC-wire.md` (rev nagual2/1, draft 1); this document is a historical wave-2 distillate, its facts have been carried over into the spec.

Encoding primitives (already present in `src/ssh3/s3_ssh3_wire.h`): all integers are QUIC varint (RFC 9000 §16, 1/2/4/8 bytes, the two high bits of the first byte = the length); SSHString = varint length + raw bytes (not the uint32-be of SSH2).

---

## 1. Transport layout

| № | Element | Who opens it | Identifier | What goes over it |
|---|---------|---------------|---------------|------------------|
| 1 | Control stream (conversation) | The client, the first bidi stream of the QUIC connection | QUIC StreamID (in practice 0); both sides call it `conversationStreamID` / `controlStreamID` | HTTP/3 extended CONNECT `:protocol=ssh3`, auth headers, the 200/403/401 response; after 200 — "just an open stream", no useful SSH frames travel over it |
| 2 | Channel | Either side: the client after 200 (`Conversation.OpenChannel`, conversation.go:388), the server — outgoing channels (`agent-connection`, `forwarded-*`) via `streamCreator.OpenStream()` | **ChannelID == the QUIC StreamID of the channel** (conversation.go:302, 393; server.go:167) | The channel header (§2), then channel messages (§3) |
| 3 | QUIC datagrams | Both sides, one receive loop per QUIC connection | The prefix inside the datagram: `varint controlStreamID` | Routing of channel datagrams (§3.2) |

Rules for dispatching bidi streams:

| № | Side | Rule | Reference |
|---|---------|---------|--------|
| 1 | Server | The very first accepted bidi stream of a connection is always an HTTP/3 request stream (the client sends CONNECT before any channels); it is handed to http3 without reading; all subsequent bidi streams are SSH3 channels (the first varint must be `0xaf3627e6`) | `Server.ServeQUICConn`, server.go:80-106 |
| 2 | Server | Uni streams are always HTTP/3 (control/QPACK), they are not used in SSH3 | server.go:82-90 |
| 3 | Client | All outgoing bidi streams after the CONNECT stream are channels; incoming bidi streams from the server are always channels (the server opens them only after 200) | client.go:114-122, conversation.go:261 |
| 4 | Both | Uni/application numbering is the QUIC one: client bidi 0,4,8…, server 1,5,9…; SSH3 renumbers nothing | follows from ChannelID == StreamID |

The control stream identifies the conversation: `ConversationID` — 32 bytes from the TLS exporter (`GenerateConversationID`, conversation.go:57-67, label `EXPORTER-SSH3`) — is used only for auth/JWT and logs, **it does not participate in the datagram wire prefix** (that is where controlStreamID is used). The server stores conversations in `map[*quic.Conn]*conversationsManager` → `map[ControlStreamID]*Conversation` (resources_manager.go:17-44); several conversations on one QUIC connection are not supported by the reference (TODO in conversation.go:209-210, server.go:273-274).

Who opens the control stream and when: the client — `EstablishClientConversation` (conversation.go:92-254): `OpenRequestStream` → `SendRequestHeader(CONNECT :protocol=ssh3)` → `ReadResponse`; the stream stays open and serves as the control stream (conversation.go:128-138). The server accepts it as a request stream and in the CONNECT handler (`GetHTTPHandlerFunc`, server.go:242-320), after 200, registers the conversation and starts the datagram receiver.

---

## 2. Channel opening

### 2.1. The first block of a new stream (channel header)

Assembly: `buildHeader` (channel.go:130-142); parsing: `parseHeader` (channel.go:163-177). The field order is fixed:

| № | Field | Encoding | Value |
|---|------|-------------|----------|
| 1 | frame type | varint | `0xaf3627e6` (`SSH_FRAME_TYPE`, conversation.go:23) |
| 2 | conversationStreamID | varint | The StreamID of the control stream of this conversation; the receiver must verify it against its own control stream (conversation.go:292-298, server.go:148-156) — mismatch → cancel the stream |
| 3 | channelType | SSHString | `"session"` \| `"direct-tcp"` \| `"direct-udp"` \| `"sftp"` \| `"agent-connection"` \| `"forwarded-tcp"` \| `"forwarded-udp"` \| `"reverse-forward"` \| `"dynamic-forward"` \| `"dynamic-forward-tcp"` (constants: message/reverse_forward.go:19-21, message/dynamic_forward.go:19-20, cmd/sftp_client.go:129) |
| 4 | maxPacketSize | varint | the data-chunk limit of the opener (see §5) |
| 5 | (direct-*/forwarded-* only) addressFamily | varint | 4 = IPv4, 6 = IPv6 (`SSHAFIpv4/6`, util/types.go:23-26) |
| 6 | (direct-*/forwarded-* only) address | raw 4 or 16 bytes | the IP of the target |
| 7 | (direct-*/forwarded-* only) port | uint16 big-endian | the target port |

The direct-* extension is assembled by `buildForwardingChannelAdditionalBytes` (channel.go:144-161) and parsed by `parseForwardingHeader` (channel.go:179-207). For `forwarded-tcp`/`forwarded-udp` (server → client, reverse -R) the same bytes carry the client's target address (`handleIncomingChannelStream`, conversation.go:310-331; the server-side parse — server.go:175-191).

Channels of the remaining types (session, sftp, agent-connection, reverse-forward, dynamic-*) carry no additional fields.

### 2.2. Opening semantics and confirmation

| № | Step | Opener | Acceptor | Reference |
|---|-----|-------------|-------------|--------|
| 1 | Open a bidi stream | `OpenStream()`; ChannelID = its StreamID | — | conversation.go:388-396 |
| 2 | Header | Written **lazily**: `OpenChannel` builds the header in memory, sending happens at the first write (`maybeSendHeader`, channel.go:300-309). Exceptions: `OpenUDPForwardingChannel`/`OpenTCPForwardingChannel`/`openForwardedChannel` call `maybeSendHeader()` immediately (conversation.go:408, 422, 440) | — | channel.go:234-237 |
| 3 | Registration | `channelsManager.addChannel` — immediately at opening | `channelsAcceptQueue.Add` (an unbounded queue, util/util.go:89-128) — at header parsing; the channel will get into the working map at step 5 | conversation.go:394 / 332, server.go:192 |
| 4 | Confirmation | Waits for 91 on the same stream: `NextMessage` intercepts `ChannelOpenConfirmationMessage` (sets `confirmReceived`) and `ChannelOpenFailureMessage` (returns `ChannelOpenFailure`); any other message before confirmation → the error `MessageOnNonConfirmedChannel` | `AcceptChannel` → `confirmChannel(maxPacketSize)` — writes **91** into the same stream and only then does the channel get into the working map | channel.go:278-298; conversation.go:462-476 |
| 5 | Response format | 91: `varint 91, varint maxPacketSize` (maxPacketSize — the limit of the acceptor). 92: `varint 92, varint reasonCode, SSHString errorMessageUTF8, SSHString languageTag` — both on the same QUIC stream | sending 91 — `sendMessage` (channel.go:352-364); **the reference never sends 92** (the `ChannelOpenFailureMessage` constructor is called only by the parser, message.go:101; refusal = `stream.CancelRead/CancelWrite(0)` in the accept loop or FIN) | message.go:56-136 |

The `NewChannel` flags (channel.go:231-255): opener — `sendHeader=true, confirmSent=true, confirmReceived=false`; acceptor — `sendHeader=false, confirmSent=false, confirmReceived=true`. That is, "confirmedness" is asymmetric between the sides: the opener can write right away (header+data as one stream of bytes), the acceptor does not read until `AcceptChannel`.

Timing trap of the reference: the client opens a channel right after 200, while the server registers the conversation from another goroutine — the server accept loop waits for the registration for up to 2 s, polling every 200 µs (`waitForConversationsManager`, server.go:25-29, 207-219). In C (a single-threaded event loop) the race disappears, but the conversationStreamID check and "a channel before the conversation registration → cancel(0)" must be preserved (conversation.go:273-282).

---

## 3. Channel data: messages on the stream versus QUIC datagrams

### 3.1. Stream path (94/95)

All byte-oriented channels (session, direct-tcp, forwarded-tcp, sftp, agent-connection, the control channels reverse-forward/dynamic-forward) carry data with messages over their own QUIC stream. Parsing — `ssh3.ParseMessage` (message/message.go:212-233); **channelID is absent from the messages** — the channel is identified by the stream itself.

| № | Type | Format | Purpose |
|---|-----|--------|------------|
| 1 | 94 `SSH_MSG_CHANNEL_DATA` | `varint 94, SSHString data` | stdout/stdin/TCP data |
| 2 | 95 `SSH_MSG_CHANNEL_EXTENDED_DATA` | `varint 95, varint dataType, SSHString data` | stderr: `dataType=1` (`SSH_EXTENDED_DATA_STDERR`); `dataType=0` is forbidden on the server (cmd/ssh3-server.go:750-755) |
| 3 | 98 `SSH_MSG_CHANNEL_REQUEST` | `varint 98, SSHString requestType, u8 wantReply, body` | pty-req/shell/exec/subsystem/window-change/signal/exit-status/exit-signal; `wantReply` — exactly 1 byte (binary.Read bool, message/channel_request.go:75); bodies — §6 |

Send chunking: `WriteData` (channel.go:311-342) cuts the buffer into chunks of `min(maxPacketSize - emptyMsgLen, len)`, where `emptyMsgLen` is the length of a frame with an empty string (3 bytes for 94 — the varint 94 is two-byte, 4 for 95); the frame header and the payload are written with two `write` calls without copying the payload.

The datagram path is chosen **by the channel type**: only `direct-udp` and `forwarded-udp` (`Client.ForwardUDP` client.go:462-510, the server-side `forwardUDPInBackground` cmd/ssh3-server.go:154-198). Everything else — the stream path, even if `SendDatagram` is called (see below).

### 3.2. Datagram path (QUIC DATAGRAM)

The format of a single datagram (sending — `getDatagramSenderForChannel`, conversation.go:545-552):

| № | Field | Encoding |
|---|------|-------------|
| 1 | controlStreamID | varint (the StreamID of the conversation's control stream) |
| 2 | channelID | varint (== the StreamID of the channel) |
| 3 | payload | the raw bytes of the UDP packet, without framing |

Reception: one loop per QUIC connection on each side (client — conversation.go:208-236, server — server.go:272-304) reads `ReceiveDatagram`, parses the varint controlStreamID, verifies it against its own control stream (a foreign one — discard), and passes the remainder to `Conversation.AddDatagram` (conversation.go:480-494): the second varint = channelID → `channelsManager.getChannel` → `waitAddDatagram` → the channel queue. QUIC DATAGRAM is unreliable and unordered; the H3 datagram layer is deliberately turned off (otherwise the second reader steals half of the datagrams — comment cmd/ssh3-server.go:1026-1031).

The datagram queues — `util.DatagramsQueue` (util/util.go:130-174), a buffered Go channel:

| № | Queue | Size | Policy on overflow |
|---|---------|--------|----------------------------|
| 1 | Per-channel queue of the channel | the `datagramsQueueSize` argument at creation; the conversation default = 10 (client.go:319 `NewClientConversation(30000, 10)`; cmd/ssh3-server.go:1050 `NewServer(30000, 10)`); in practice: `agent-connection` 10, `direct-*`/`forwarded-*` 10, `session`/`reverse-forward`/sftp client — 0 → an unbuffered channel (session.go:48, ssh3-server.go:763, reverse_forward_server.go:210/247) | `Add` — non-blocking, false → drop; `waitAddDatagram` (the path from the receive loop) — blocking with ctx; `ReceiveDatagram` = a blocking `WaitNext` |
| 2 | Dangling queue (a datagram arrived before the channel was registered) | `danglingDatagramQueueSize = 64` per channelID (resources_manager.go:11-13); one queue per channelID, not a new one per datagram | `Add` is non-blocking (the receive loop is shared by all channels — it must not block); full → drop + warn (resources_manager.go:84-86). `AddDatagram` in this case returns `ChannelNotFound` (the server logs a warn and continues) |

The dangling → channel handover: `addChannel` transplants the ready dangling queue into the channel (`setDgramQueue`) and deletes the entry (resources_manager.go:56-64); the double check "in case the channel got registered between the lookup and the insertion" — resources_manager.go:75-78.

Where a channel is looked up: the single map per conversation `channelsManager.channels map[ChannelID]Channel` (resources_manager.go:46-54). Both outgoing channels (immediately at OpenChannel) and incoming ones (after `AcceptChannel`) get into it. **There are no deletions from the map**: `onChannelClose`/`removeChannel` are defined (resources_manager.go:96-104), but not a single call to them has been found in the reference — the map leaks; deletion in the C port is mandatory.

Setting `datagramSender` (who is allowed datagrams) is asymmetric in the reference: the client sets the sender on **all** incoming channels (conversation.go:308), the server — only on `direct-udp` (server.go:182) and `forwarded-udp` (conversation.go:458); outgoing `OpenChannel`/`OpenTCPForwardingChannel` — without a sender. `SendDatagram` without a sender → the error `SentDatagramOnNonDatagramChannel` (channel.go:380-386). Datagram reception works on any channel (the queue always exists).

---

## 4. Close / EOF

| № | Mechanism | What it does | Reference |
|---|----------|------------|--------|
| 1 | Half-close (the main path) | `channel.Close()` = `send.Close()` = a QUIC FIN on the send side of the stream; the read side lives on | channel.go:397-399 |
| 2 | Emergency reset of reading | `channel.CancelRead()` = QUIC STOP_SENDING with code **42**; the peer sees stream error 42 (client/server treat it as "remote canceled") | channel.go:393-395; client.go:214-224 |
| 3 | Open refusal | cancel read+write with code 0 in the accept loop (bad frame type, unknown conversation) | server.go:118-120, 137-139 |
| 4 | 96 `SSH_MSG_CHANNEL_EOF`, 97 `SSH_MSG_CHANNEL_CLOSE` | **constants only** (message/message.go:32-33); they are sent and parsed nowhere (`ParseMessage` does not know them — a panic on an unknown type, message.go:230-232). EOF = a QUIC FIN, close = FIN + (optionally) closing the conversation | not found in the reference — there is no need to reproduce it, but the C parser must respond with a channel error, not a crash |

Timeouts and the teardown order:

| № | Timeout | Where | Meaning |
|---|---------|-----|-------|
| 1 | `ptyExitGrace = 1 s` | client/session_pump.go:31 | after the exit-status of a PTY session the client sends a FIN and after 1 s `CancelRead` (the server may stay silent) |
| 2 | `truncationGrace = 2 s` | client/session_pump.go:28 | exit-status arrived while stdin was not yet closed → wait for the stdin pump; if the input has not gone out — truncate, exit 255 |
| 3 | `exitStatusSent` wait ≤ 1 s | cmd/ssh3-server.go:1144-1149 | server: on EOF of input it waits for the exit-status goroutine for up to 1 s, then a FIN of the channel |
| 4 | `DrainAndClose(3 s)` | conversation.go:529-539, cmd/ssh3-server.go:1117-1124 | the end of a session channel: a FIN of the channel → wait for the peer to close the connection for up to 3 s → `Conversation.Close()` (control stream + cancel ctx). Otherwise the final output+exit-status are lost |
| 5 | mux exception | conversation.go:505-521 | the conversation control stream of the master (`?mux=1`) outlives individual session channels; teardown — at the master's disconnect |

Closing the conversation entirely on the client: `Client.Close` = `Conversation.Close()` + `qconn.CloseWithError(0)` (client.go:248-251) — without a QUIC close the server keeps the -R binds until the idle timeout.

---

## 5. Flow control

| № | Mechanism | Status in the reference | Details |
|---|----------|------------------|--------|
| 1 | `maxPacketSize` (the channel header, §2.1) | Used only for chunking `WriteData` (channel.go:317-340) and as the size of the read buffers (client.go:127/200/437/…). Values: 30000 on both sides always (client.go:319, session.go:48, cmd/ssh3-server.go:1050 and all Open*Channel) | 91 carries the maxPacketSize of the acceptor, but neither side applies the received value — each applies its own. For C: the interop-observable behavior = send 30000, chunk by one's own limit minus the frame overhead |
| 2 | 93 `SSH_MSG_CHANNEL_WINDOW_ADJUST` | **Not used**: the constant message/message.go:29, not parsed, not sent | SSH-level flow control is delegated to QUIC. Do not port to C; for the parser — "unknown type → a channel error" |
| 3 | QUIC flow control | The real mechanism: the client `MaxIncomingStreams=10` (client.go:290); the server: stream window 8→16 MiB, conn 16→32 MiB, `InitialPacketSize=1350` (cmd/ssh3-server.go:1025-1037, the flags -stream-rx-mb/-conn-rx-mb) | Configured at the QUIC layer, it has nothing to do with SSH3 frames |

---

## 6. Server flow of a session channel

Registration of the request handlers: `ChannelRequestParseFuncs` (message/channel_request.go:14-24); the request bodies are there as well (pty-req §6.2 RFC4254-like, exec, subsystem, window-change, signal, exit-status, exit-signal; shell — an empty body; x11-req — parsed, not implemented by the server).

The sequence (the server loop — cmd/ssh3-server.go:1055-1214; the states `LARVAL` → `OPEN`, ssh3-server.go:88-93, 109-120):

| № | Message from the client | Server response / action | Reference |
|---|---------------------|--------------------------|--------|
| 1 | (channel opening + 91, §2) | `runningSession{LARVAL}` + a goroutine loop `NextMessage` | ssh3-server.go:1099-1105 |
| 2 | 94 data `"forward-agent"` (data, not a request!) in LARVAL | the ssh-agent unix socket, incoming `agent-connection` channels | ssh3-server.go:1196-1204, 820-852 |
| 3 | 98 `pty-req` wantReply=1 | `newPtyReq`: openpty, TIOCSWINSZ, the term is preserved; the state remains LARVAL; **no reply is sent** | ssh3-server.go:458-488 |
| 4 | 98 `shell` wantReply=1 | a banner (system statistics) as 94, then `newCommand(login_shell=true, $SHELL)` | ssh3-server.go:633-640 |
| 5 | 98 `exec` wantReply=1 | `newCommand(login_shell=false, $SHELL, "-c", cmd)` — the command is always executed via the user's shell | ssh3-server.go:643-645 |
| 6 | — (steps 4/5) | the process starts here: `execCmdInBackground` — pty → `StartWithSizeAndPty`, otherwise three os.Pipe; state → OPEN | ssh3-server.go:304-330, 494-572 |
| 7 | 94 data (dataType=0) | the process stdin (`runningCmd.stdinW`); only in OPEN; extended data → a loop error | ssh3-server.go:735-760 |
| 8 | 98 `window-change` wantReply=0 | TIOCSWINSZ on the pty (only when a pty is present) | ssh3-server.go:651-675 |
| 9 | 98 `signal` wantReply=0 | `Process.Signal(SIG<name>)`; only in OPEN and while the process is alive | ssh3-server.go:677-701 |
| 10 | EOF of input (the client's FIN) | close the process stdin, wait for the command to finish (`waitForRunningCommandAfterInputEOF`) | ssh3-server.go:292-302, 1135-1149 |
| 11 | ← stdout: 94; ← stderr: 95 dataType=1 | two goroutine readers on the stdout/stderr pipes; PTY: stderr is merged with the pty (`stderrR=nil`), a separate 95 does not arise | ssh3-server.go:389-430, 524-531 |
| 12 | ← 98 `exit-status` wantReply=0 | after Wait(): `varint 98, SSHString "exit-status", u8 0, varint code` | ssh3-server.go:431-452 |
| 13 | — | a FIN of the channel (`channel.Close()`), then `DrainAndClose(3 s)` (§4.4); a mux-conversation — without per-session teardown | ssh3-server.go:1117-1124 |

The replies 99 `SSH_MSG_CHANNEL_SUCCESS` / 100 `SSH_MSG_CHANNEL_FAILURE`: **not found in the reference** — constants only (message/message.go:35-36). `wantReply` is parsed in all requests and ignored: the server never replies, the client with `WantReply=true` for pty-req/shell/exec (client/session.go:73, 93, 108) does not wait for a reply (`SendRequest` — a write only, channel.go:388-391). ARCHITECTURE.md §5 fixes: do not reproduce, but parse 99/100 on reception by both sides.

The client side of a session (for symmetry): `Client.OpenSession` (client/session.go:47-115): OpenChannel("session", 30000, 0) → optionally data "forward-agent" → optionally pty-req → shell or exec → a pump. The pump (`pumpSessionStreams`, client/session_pump.go:62-206): stdin → 94; stdin EOF → FIN; 94 → stdout, 95(1) → stderr (`writeSessionData`, session_pump.go:46-57); exit-status — a terminal event with draining of the tail until EOF (§4.1-4.2); exit-signal — terminal as well. The client sends window-change on SIGWINCH (wantReply=0, client.go:60-76).

---

## 7. Auth: the server's choice of a verifier (overview for the next wave)

The `HandleAuths` pipeline (server_auth/auth.go:18-109), before any conversation routing:

| № | Step | Failure | Reference |
|---|-----|--------|--------|
| 1 | Parse `User-Agent` → version | 403 | auth.go:24-35 |
| 2 | `HandshakeComplete`? (anti-replay of 0-RTT) | 425 | auth.go:49-54 |
| 3 | the username from the URL userinfo or `?user=` | 401 | auth.go:70-78 |
| 4 | `GetAuthorizedIdentities`: `~/.ssh3/authorized_identities`, then `~/.ssh/authorized_keys` (line by line, `#` — a comment) | 401 on a read error | server_auth/authorized_identities.go:27-29, 146-165 |
| 5 | First the plugin verifiers (`WrappedPluginVerifier.Verify(request)`) — over the whole HTTP request | — | auth.go:87-96 |
| 6 | `Authorization: Basic` (if password login is enabled) → `HandleBasicAuth` (a unix password check); otherwise `Bearer` → `HandleJWTAuth`: the JWT token is run through all `IdentityVerifier`s from the file (pubkey/OIDC), the first success — proceed | 401 | auth.go:100-107, handlers.go:44-58, authorized_identities.go:37-86 |

The conversation is created **before** auth (`NewServerConversation`, auth.go:61), but it is registered in the map and gets the datagram loop only in the CONNECT handler after successful verification (server.go:255-304). The JWT details (signatures, claims) — out of scope of wave 2; the contract needs only the list of steps above and the fact: the 32-byte conversationID (base64 in the logs) is available to the verifiers.

---

## 8. Map of the wave-2 C ports

The existing base: `src/ssh3/s3_ssh3_wire.{h,c}` (varint/SSHString — done), `s3_ssh3_version.{h,c}` (done), the stubs `s3_ssh3_message.*`, `s3_ssh3_request.*`. The proposed split:

### 8.1. `s3_ssh3_channel` (`src/ssh3/s3_ssh3_channel.{h,c}`)

The channel structure: ChannelInfo (type, conversationStreamID, channelID==stream, maxPacketSize), the confirmSent/confirmReceived/headerSent flags, a reference to the QUIC stream, the per-channel datagrams queue. Responsibilities: assembly/parsing of the §2.1 header (`buildHeader`/`parseHeader`), lazy header sending (maybeSendHeader), WriteData with chunking by maxPacketSize, the receive-side message parser (the 91/92 filter, 94/95/98), SendRequest/exit-status assembly. Dependencies: s3_ssh3_wire, s3_ssh3_message, the QUIC stream API. A direct port of `channel.go` (417 lines).

### 8.2. `s3_ssh3_conversation` (`src/ssh3/s3_ssh3_conversation.{h,c}`)

Conversation: the control stream, the channelID→channel map (rbtree/hash), the accept queue of incoming channels, the conversationStreamID check. Responsibilities: OpenChannel/OpenUDPForwardingChannel/OpenTCPForwardingChannel (opener), the accept path (parsing the header of an incoming stream → the queue → 91 on accept), replacing the QUIC dispatch from server.go:80-106 (the first bidi = CONNECT, the rest = channels; incoming bidi on the client — always channels), Close/DrainAndClose. Dependencies: s3_ssh3_channel, s3_h3 (CONNECT was already brought up by wave 1 P3), QUIC open/accept stream.

### 8.3. `s3_ssh3_dgram` — datagram routing (`src/ssh3/s3_ssh3_dgram.{h,c}`)

One receive path per QUIC connection: varint controlStreamID → check → varint channelID → a channel lookup → the queue; dangling queues of 64 each with a non-blocking Add and transplantation into the channel at registration (resources_manager.go). The responsibilities also include the sender: the buffer `varint controlStreamID | varint channelID | payload` → the QUIC `SendDatagram`. Dependencies: s3_ssh3_conversation (the channel map), the QUIC datagram API (`EnableDatagrams`, without H3 datagrams).

### 8.4. `s3_ssh3_session_srv` — the server-side session (`src/ssh3/s3_ssh3_session_srv.{h,c}`)

The runningSession state machine LARVAL→OPEN (§6): pty-req/shell/exec/window-change/signal, fork+pty (Linux termios; Windows ConPTY — later), the stdin/stdout/stderr pumps, 94/95 routing, exit-status (wantReply=0), a banner, forward-agent by the data marker, EOF handling with waiting for exit-status, the teardown per §4. Dependencies: s3_ssh3_channel, s3_ssh3_request (the skeleton already exists), the os layer (pty, pipes). Reference: cmd/ssh3-server.go:88-852 (without the -R/-D parts).

### 8.5. `s3_ssh3_session_cli` — the client pump (`src/ssh3/s3_ssh3_session_cli.{h,c}`)

The OpenSession sequence (session.go) + pumpSessionStreams: the stdin pump with a FIN on EOF, stdout/stderr routing, the truncation detector (grace 2 s, exit 255), the PTY grace (1 s), the terminal ExitStatus/ExitSignal. In the C event model — without goroutines: two "directions" on posted events/file descriptors. Dependencies: s3_ssh3_channel, os/term.

### 8.6. `s3_ssh3_forward` — forwarding (`src/ssh3/s3_ssh3_forward.{h,c}`)

direct-tcp/direct-udp (client outgoing), forwarded-tcp/forwarded-udp (reception with parsing of the extended header), a stub of the bridge to a local socket. The reverse-forward/dynamic-forward control channels (the request bodies message/reverse_forward.go, message/dynamic_forward.go) — a separate increment; wave 2 may limit itself to direct-*/forwarded-*: for the P4 interop matrix (shell/exec/pty/signal) forwarding is not needed. Dependencies: s3_ssh3_channel, s3_ssh3_dgram.

### 8.7. `s3_ssh3_auth_srv` — the server-side verifiers (overview §7, the full port — the next wave)

The §7 chain without JWT depth: the version/425 gate is already in P3; add username extraction, reading authorized_identities/authorized_keys, the Basic check, an IdentityVerifier skeleton with the pubkey branch. Dependencies: s3_ssh3_conversation (conversationID), os/unix (passwd).

---

## 9. Deviations from the reference, mandatory for C (summary)

| № | Deviation | Ground |
|---|------------|-----------|
| 1 | Do not send 92/93/96/97/99/100; on reception — treat as a channel error/ignore, not a crash | Not implemented in the reference (§2.2, §4, §5, §6) |
| 2 | Delete a channel from the map on close | In the reference `onChannelClose` is dead code — a leak |
| 3 | The 98 parser: an unknown requestType → a channel error, not a panic | message.go:230-232 panics in the reference |
| 4 | Do not invent a reply protocol for wantReply: interop = the absence of replies | §6;ARCHITECTURE.md §5 "Fixes for Go bugs" |
| 5 | Keep the datagramSender asymmetry optional: in C allow SendDatagram on any channel with a sender set, set the sender on all UDP channels of both roles | The observable wire semantics do not change (§3.2) |
