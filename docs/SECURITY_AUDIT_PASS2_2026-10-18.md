# Security audit — ssh3-c (C17) — PASS 2

- **Date (UTC):** 2026-10-18
- **Auditor:** team "Wasm Tunnel" (audit delegation, report-only)
- **Repository:** `nagual2/ssh3-c`
- **Baseline of pass 1:** `main @ 52ac293`
- **Audited HEAD (this pass):** `main @ 5bb540c` (tag `v0.4.0`)
- **Pass-1 report:** `docs/SECURITY_AUDIT_2026-10-17.md` (PR #1, merged as `682db6b` / `58cc748`)
- **Deliverable:** documentation only. No code, config or CI change is made by this audit.

## 1. Scope and method

Second pass on the C17 rewrite. Three jobs, in the order the lead set them:

1. **Fix verification** — grade the pass-1 findings (1 Low + 3 Info) at the audited HEAD,
   with `file:line` anchors.
2. **Regression hunt** on those fixes (floor applied before buffer sizing/chunking everywhere,
   no 1-byte chunk, no uint64 underflow, confirmation frames announcing what the endpoint accepts).
3. **Continuation of coverage** — pass 1's own top recommendation first (`src/h3/s3_h3_parse.c`),
   then the pre-auth HTTP/3+QPACK decoders, auth/JWT, session/PTY/exec, the SFTP server/jail,
   forwarding/gateway-ports, the DoS guard.

Plus a new-findings sweep over the 2026-10-15…18 feature wave, and probes on current code.

Method: static review of the audited HEAD tree (grep-directed reading with `file:line` anchors),
commit-level reading of the 76-commit change set, and behavioural reasoning about the identified
paths. Everything asserted below was read in the audited tree or in the named commit; nothing is
reproduced from pass 1 without a re-check, and every item I did **not** finish is listed as not
covered in §9 rather than guessed at.

## 2. Change set map: `52ac293..5bb540c` (76 commits)

The wave of 2026-10-15…18, grouped by area. Shipped-code areas are marked; the rest is CI, packaging
or test-only surface that does not run on the wire.

| # | Area | Representative commits | Security relevance |
|---|------|------------------------|--------------------|
| A | CLI canon to `ssh(1)` / `sshd(8)` (P8 1a–1d) | `b2b756b`, `2a9acd5`, `c413ed5`, `ed6daf3`, `9877fb9`, `9a36bcd`, `ce3ca4b`, `b0bd98c`, `53fb62c`, `c4efeb9`, `5fbd1f0`, `5124a5c`, `383fdf3`, `1c078c2`, `cce5095`, `9d5d056` | new option surface, bounded copies, login/bind policy defaults, DoS knobs — **shipped**, new attack surface |
| B | Pass-1 findings closure | `d2787f7`, `b7c3aff`, `fd9570b`, `9919d90`, `5a6a02c`, `5a77496`, `0ad93b2`, `e4b45e7`, `3a1229f` | the F-1 / I-1 / I-2 / I-3 work graded in §3 — **shipped** |
| C | Debian packaging wave | `566b109`, `b982659`, `21ac508`, `82fa2f6`, `93f5fab`, `4bae16f`, `7835642`, `facb423`, `cba24bf`, `638a8bf`, `5bb540c` | service unit, postinst/postrm account handling — not on the wire (not audited in this pass, §9) |
| D | Release | `e875ddd` | version 0.4.0 |
| E | Client mingw/CI fixes | `311fc5e`, `35f5c1f` | build shapes only |
| F | Interop / e2e legs | `cli-compat-e2e.sh`, `cli-compat-srv-e2e.sh`, `p8-defaults-e2e.sh`, gateway-ports / reverse-forward / permit-open / product-reverse legs | not shipped; behaviour evidence |

Shipped surface touched by the wave (`git diff --stat 52ac293..5bb540c`):
`app/ssh3_client.c` (9618 lines changed), `app/ssh3_server.c` (934), `src/ssh3/s3_ssh3_channel.{c,h}`,
`src/ssh3/s3_ssh3_cm.c`, `src/ssh3/s3_ssh3_session_srv.{c,h}`, `src/ssh3/s3_ssh3_version.h`,
plus `man/`, `packaging/`, `docs/` and `tests/`.
**No change** in this wave to `src/h3/*`, `src/event/quic/*`, `src/ssh3/s3_ssh3_auth_jwt.c`,
`s3_ssh3_auth_srv.c`, `s3_ssh3_sftp_srv.c`, `s3_ssh3_sftp_jail.c` — i.e. the pass-1 coverage gaps
did not move, and the fixes in B are the only security-relevant deltas in `src/`.

## 3. Fix verification (pass-1 findings)

All anchors are at the audited HEAD `5bb540c`.

| ID | Pass-1 item | Verdict | Evidence at HEAD |
|----|-------------|---------|------------------|
| F-1a | peer `maxPacketSize` has a 16 MiB ceiling but **no floor** | **FIXED** | `S3_SSH3_CHANNEL_MIN_PACKET_SIZE 4096u` next to the ceiling — `src/ssh3/s3_ssh3_channel.h:46` (ceiling `:31`); the header parse clamps a below-floor advertisement *up* (clamp, not refusal, ceiling refusal unchanged) — `src/ssh3/s3_ssh3_channel.c:74-87`; the value is stored at `:96` |
| F-1b | the floor is **never enforced** — read and ignored | **NOT FIXED (unchanged, deliberately deferred)** | the parsed value is still data-inert: the only writers/readers of `ch->max_packet_size` outside the codec are the header *build* paths (`app/ssh3_client.c:5468`, `6085`, `6627`, `7485`, `8043`, `8832`, `10127`, `13260`; `app/ssh3_server.c:4320`, `4721`, `5615`). No consumer feeds the peer advertisement to the sender (§4) |
| F-1c | `s3_ssh3_channel_chunk_size()` dead code, no callers | **FIXED** | 13 call sites now exist — `app/ssh3_client.c:4166, 5116, 7286, 8260, 9658`, `app/ssh3_server.c:3401`, `interop/interop_client.c:1834, 2322, 2965, 3948, 4792`, `interop/interop_server.c:2142`. It also self-clamps its input into `[4096 … 16 MiB]` — `src/ssh3/s3_ssh3_channel.c:110-116` |
| I-1 | tolerant control-op decode; exact match only by luck | **FIXED (documented + pinned)** | `s3_cm_op_is` is length-exact: `op->len == n && s3_memcmp(op->data, name, n) == 0` — `src/ssh3/s3_ssh3_cm.c:836-841`, contract comment `:829-835`; pin test `tests/test_ssh3_cm.c` (prefix neighbour `checkx`) |
| I-2 | env allow-list not centralised | **FIXED (single gate)** | `s3_ssh3_env_admit(name, value)` — `src/ssh3/s3_ssh3_session_srv.c:174`, declared `s3_ssh3_session_srv.h:45`; every env build rides it — the env quota path `:231`, the `LANG` fallback `:457`; corpus `tests/test_ssh3_session_srv.c:447-509` (LD_PRELOAD/LD_LIBRARY_PATH/… , value injection `TERM=/bin/sh`, case-shift, TERM bound 1..64) |
| I-3 | SFTP per-user budget absent from the codec layer | **VERIFIED (no code change needed)** | `s3_srv_sftp_budget_take(ch->sess_user)` is the first check of `s3_srv_sftp_start` — `app/ssh3_server.c:3721` (function `:3714`); the chroot child (and therefore the fork) starts deeper — `app/ssh3_server.c:3729` → `s3_srv_sftp_chroot_start` `:3943` |

Note on F-1b: the closure section of the pass-1 report (`docs/SECURITY_AUDIT_2026-10-17.md` §8) states
this explicitly ("the send/receive data-path enforcement stays deliberately unwired … the value remains
data-inert"). The grade above is therefore "as designed, not as the finding asked": the finding is only
half closed, and the second half is now a documented, **open** item rather than an oversight. The DoS
consequence the Low described is closed in practice (no 1-byte chunk is reachable — §4), but the parity
gap with the reference stays.

## 4. Regression hunt on the fixes

**4.1 The floor is applied before buffer sizing/chunking, everywhere the helper is reachable.**
`s3_ssh3_channel_chunk_size()` clamps *before* it subtracts (`src/ssh3/s3_ssh3_channel.c:110-116`
then `:132-136`), so no caller can lose the invariant; the header parse clamps before it stores
(`:85-96`). No other site computes a chunk from a peer value: the 13 call sites all pass a local
constant, and every one of them passes `30000` and `extended = 0`:

- `S3_CLI_CHANNEL_MAX_PACKET 30000` — `app/ssh3_client.c:160`, `S3_SRV_CHANNEL_MAX_PACKET 30000` —
  `app/ssh3_server.c:99`, `S3_INTEROP_CHANNEL_MAX_PACKET 30000` — `interop/interop_client.c:115`,
  `interop/interop_server.c:83`.
- Consequence: the chunk size is `30000 - 3 = 29997` bytes (plain data), `30000 - 4 = 29996`
  (extended). **No 1-byte chunk, and no 0-byte chunk, is reachable at HEAD** — the latent DoS class
  from pass 1 stays closed. Pass-1's `S3_CLI_CHANNEL_MAX_PACKET` sites existed *before* the wave
  (present at `52ac293` in `app/ssh3_client.c`), so this is not a wave regression either.
- The cost of that safety is the parity gap: a peer that advertises e.g. 8192 still receives 29997-byte
  data messages, where the reference `WriteData()` chunks to the advertised bound. That is a
  protocol/robustness divergence against a conforming peer, not a memory-safety defect — recorded as
  **P2-1** (Low).

**4.2 No uint64 arithmetic defect in the chunk path.**
`overhead` is `3` (plain) or `4` (extended) — `varint(94)=2 + varint(0)=1`, and
`varint(CHANNEL_EXTENDED_DATA)+varint(STDERR)+varint(0)`. The subtraction is guarded twice: the clamp
raises the input to ≥ 4096 first, and `if (max_packet_size <= overhead) { return 0; }` remains as
defence in depth (`:132-134`). With the floor in place the `return 0` branch is unreachable; the
computation stays in `uint64_t` and only the result is cast to `size_t` (`:136`), so no truncation on
32-bit or 64-bit. Worth keeping the branch: a future caller that passes `extended = 1` and a plate
below 4096 could otherwise get a 0-byte chunk — a 0-length send loop rather than a crash. No defect.

**4.3 "Confirmation frames announce what the endpoint actually accepts" — not satisfiable, and not
verifiable from the code that exists.** With the peer advertisement data-inert (§3, F-1b), the
endpoint accepts exactly its own `30000` constant, and the outgoing channel-open/-confirmation frames
announce the local constant (`S3_CLI_CHANNEL_MAX_PACKET` / `S3_SRV_CHANNEL_MAX_PACKET`, anchors in
§3). I could not independently confirm the pass-1 §8 claim that the `OPEN_CONFIRMATION`
max-packet field has zero readers: a symbol-name grep for `OUT_OPEN_CONFIRMATION` in `src/` and
`app/` returned nothing (the constant is spelled differently in this tree). Treat that half of the
claim as **not re-verified here**; the send-path anchors above stand on their own.

**4.4 I-1 / I-2 regressions: none found.** The op match has exactly one implementation and is
length-exact; the env gate has exactly two call sites and both are the ones the closure names. A
second env builder would have shown up in the same grep — it did not (the sftp child inherits via
`fork`, no `exec`).

## 5. Continuation of coverage

### 5.1 `src/h3/s3_h3_parse.c` (6027 lines) — the largest pre-auth surface

**Provenance first (this reframes the whole item):** the file is a port of nginx's
`ngx_http_v3_parse.c` plus the nginx Huffman decoder — stated at `src/h3/s3_h3_parse.c:10-12`, with
the nginx copyright retained at `:1-5`. The state machines, the error taxonomy (`S3_H3_ERR_*`) and
the QPACK prefix-int/insert-count logic follow the upstream shapes closely, which means the audit
question is *divergence from upstream*, not first-principles safety.

Attack-surface profile, measured rather than assumed: **2 `memcpy` calls in 6027 lines, 0 `malloc`,
0 `realloc`, 0 `alloca`** (`grep -c`). The layer is a validating decoder that hands out offsets into
the caller's buffer; the memory-safety risk therefore sits in the consumers of the parsed fields, not
in the decoder.

Checked line-by-line (read in full), with the reasons they hold:

| Area | Anchor | Verdict |
|------|--------|---------|
| Field-line size bound (per header name/value) | `:4810` (`S3_H3_MAX_FIELD_SIZE 8192`, defined `:30`, nginx's `large_client_header_buffers` default made fixed) | bounded; refusal is `S3_H3_ERR_EXCESSIVE_LOAD` |
| Huffman expansion overflow guard | `:4812-4816` (`n > S3_MAX_INT_T_VALUE / 8` before `n = n * 8 / 5`) | bounded — the multiplication cannot wrap |
| Per-field scratch buffer capacity | `:4831-4838` (`(size_t)(st->buf->end - st->buf->last) < n + 1` → error, `st->last = NULL`) | bounded, fails closed (the ssh3 callers leave `st->buf` unset → zero-copy into the receive buffer) |
| QPACK field-section prefix: "negative base" | `:5240+` — `if (st->insert_count <= st->delta_base) → S3_H3_ERR_DECOMPRESSION_FAILED`, then `base = insert_count - delta_base - 1` | **no underflow**; the guard is the nginx one |
| Required Insert Count wrap logic | `s3_h3_decode_insert_count`, `src/h3/s3_h3_table.c` — `max_entries = S3_H3_MAX_TABLE_CAPACITY / 32`, `full_range = 2 * max_entries`, `> full_range` refused, `max_wrapped`, `req_insert_count == 0` refused | mirrors nginx 4.5.1.1; no wrap or zero-base hole found |
| Dynamic-table lookup index | `s3_h3_lookup`, `src/h3/s3_h3_table.c`: `if (index < dt->base \|\| index - dt->base >= dt->nelts) → S3_ERROR` | **correct** — the `index < base` test comes first, so the subtraction cannot underflow |
| SETTINGS parsing side effects | `s3_h3_set_param`, `src/h3/s3_h3_table.c:715-737` — all three known params only log, `default` only logs | **no attacker-controlled allocation** from SETTINGS; response is bounded by `:5472` (`sw_length == 0` / `s3_h3_parse_end_local` logic) |
| Control-stream framing | `:5330-5336` — first frame must be `SETTINGS`, repeated `SETTINGS` refused, v2 frames / `DATA` / `HEADERS` / `PUSH_PROMISE` refused, `CANCEL_PUSH` → `ID_ERROR`, unknown frames skipped by length | matches upstream; unknown frame lengths are skipped, not buffered |
| Request-stream framing | parse_headers `sw_type`/`sw_length` — the same frame-type refusals plus zero-length `HEADERS` → `S3_H3_ERR_FRAME_ERROR`; `st->length == 0 && rc == S3_AGAIN` → `FRAME_ERROR` | truncated frames cannot be mistaken for a complete one |
| Field-name/value pool copy | `s3_h3_parse_lookup`, `:5280-5306` — `s3_pnalloc(len + 1)` then `memcpy` + NUL | correct; `len + 1` cannot wrap for a length that arrived from a QUIC stream |
| Zero-length literal hardening | comments at `:5637-5643` and `:5753-5759` — a zero-length value is parked on `""` instead of a NULL pointing at a nonnull `memcpy` | the trap is already defused; the comment names it explicitly |

**No memory-safety defect found in the examined h3 paths.** Not covered by this reading (see §9):
the Huffman decode tables themselves (`s3_h3_uni.c` / `s3_h3_table.c` static tables), the QPACK
*encoder* / dynamic-table insert-eviction path, the uni-stream parsers, and — most importantly — the
pre-auth **consumers** of the parsed header fields, whose `s3_str_t` values point *into* the receive
buffer and are only copied for the dynamic-table path (`:5292`, `:5303`). The lifetime of a
header-value pointer across an event-handler boundary is the one thing in this area that a static
pass cannot settle, and it should be the first target of a third pass.

### 5.2 HTTP/3 + QPACK — partial

Covered by §5.1: the field-section prefix, the required-insert-count wrap logic, the dynamic-table
lookup bounds, SETTINGS, control/request framing. **Not** covered: the encoder/eviction path, the
Huffman tables, `s3_h3_encode.c`, `s3_h3_uni.c`. No finding in what was read.

### 5.3 auth / JWT / OIDC

- **Signature verification** is OpenSSL: `EVP_DigestVerify` for Ed25519
  (`src/ssh3/s3_ssh3_auth_jwt.c:983-988`), `EVP_DigestVerify` + `EVP_sha256()` for ES256 (`:998-1031`)
  and RS256 (`:1044+`). No hand-rolled signature check found.
- **Algorithm is allow-listed before use** (`:1290-1292`: EdDSA/ES256/RS256 only) — no `none`/HS256
  confusion path.
- **Claims are exact and strict** (`:1296-1330`): `exp` must be *present* and fresh, `iat`/`nbf` must
  not be in the future, `iss == user`, `sub == required`, `aud == "unused"` (length and bytes),
  `client_id == "ssh3-<authenticated user>"` (`:1322-1326`, built with `snprintf` and checked for
  truncation), `jti` present and non-empty, and — when the exporter bytes are handed in — bound to the
  conversation id. The identity binding therefore rests on the *pubkey-authenticated* user, not on the
  token alone: a forged/duplicated claim in a self-signed token cannot name another user.
- **P2-3 (Info): no `jti` replay cache.** `jti` is required and non-empty (`:1332-1335`) and is bound
  to the conversation id only "when the harness hands the exporter bytes" (`convid != NULL`,
  `:1336+`). Without that binding a token captured inside its `exp` window has no replay guard.
  Parity with the reference is not established here — flagging the gap, not a break-in.
- **P2-2 (Info): no timing-safe comparison exists in the tree.** `s3_memcmp` is defined as plain
  `memcmp` — `src/core/s3_base.h:127` — and is what every claim/keyword comparison uses
  (`s3_ssh3_auth_jwt.c:483, 488, 554, 566, 579, 592, 605, 622, 703-708, 830, 942-950, 983, 998, 1044`,
  and the `client_id` compare at `:1324`). For the audited paths the compared values are public (claim
  names, claim values carried in the token) or ride OpenSSL's verify, so I found **no practical
  timing vector**; the concern is prospective — the same helper is the obvious choice for a
  password/HMAC/session-secret compare, and one of those was not audited (§9). Recommend adding a
  constant-time helper before any secret comparison lands on `s3_memcmp`.
- OIDC (`s3_ssh3_oidc.c`, `s3_ssh3_oidc_client.c`) and the password path were **not** audited (§9).

### 5.4 session / PTY / exec — partial

Covered indirectly: the env gate is the single admission point (§3, I-2), and the `TERM` bound
(1..64) is pinned by `tests/test_ssh3_session_srv.c:493-495` with the oversize probe riding the true
`pty-req` bound (`5a77496`). The pty-req/`exec` request handlers themselves, and the per-session
setuid gate (`app/ssh3_server.c:2015`, `:2265`), were **not** audited this pass.

### 5.5 SFTP server / jail

- **Per-user budget: verified before the fork** (§3, I-3) — the pass-1 Info is genuinely closed.
- **Mode:** chroot is the default (`app/ssh3_server.c:276`, `--sftp-jail chroot|lexical`), and an
  unprivileged server *folds to lexical at startup* (`:7541-7551`) — so the lexical jail is the mode
  that actually runs whenever the daemon is not root, which is the deployment this harness uses.
- **Lexical verdict — the classic escape is handled.** `s3_srv_inside` (`src/ssh3/s3_ssh3_sftp_srv.c:343-357`)
  is boundary-aware: `n == home.len` exact match, or `n > home.len && p[home.len] == '/'` — so
  `/home/user2` is *not* accepted for a `/home/user` jail. The `/` jail is special-cased to accept
  everything (`:344-346`), which is correct because that case only exists under a chroot.
- **`..` cannot escape.** `s3_srv_clean` (`:499+`) resolves dot-segments with a `dotdot` root marker
  and a `w > dotdot` guard, so a rooted path never keeps a leading `..`; and `s3_srv_resolve`
  (`:363+`) re-checks the *joined* result against the jail as its last step —
  `if (!s3_srv_inside(t, full, flen)) { *denied = 1; return NULL; }` (`:478-482`) — i.e. it fails
  closed after the join, which is the check that makes a `clean()` divergence non-exploitable.
  Only one `s3_pnalloc` per path, each `+1` for the NUL, each NULL-checked.
- **Symlink / TOCTOU:** not settled. The lexical mode follows symlinks by design (the `s3_ssh3_sftp_jail.h`
  preamble says exactly that, and cites it as the reason the chroot mode exists), so a symlink inside
  the home escapes the jail as far as the *user's own* permissions allow; that is only safe if the
  serving child has already dropped to the user's uid. The drop ordering inside the chroot child
  (`s3_srv_sftp_chroot_start`, `app/ssh3_server.c:3943+`) and the lexical mode's identity were **not**
  read to the end in this pass — this is the second most important open item after §5.1's pointer
  lifetime, and it is the one I would not ship an unprivileged-server release without.
- `O_NOFOLLOW`/`openat`-based confinement is **absent** from the SFTP server (no `O_NOFOLLOW`,
  no `openat` in `s3_ssh3_sftp_srv.c`); the design leans on chroot+drop instead. Consistent with the
  port's stated model, but it is why the drop path above matters.

### 5.6 forwarding, gateway-ports, `-R`/`-o` (the new features)

The wave's own fix `9d5d056` ("the reverse bind gates ride the user cap first") is **correct**, and I
re-derived the ordering at HEAD rather than trusting the message. Sequence in `s3_srv_reverse_request`
(`app/ssh3_server.c:5030+`): bind-text copy with a length check → GatewayPorts rewrite → `permit-listen`
policy check (post-rewrite) → **per-user budget gate** (`:5138-5149`, books, sets `booked = 1`) →
family/address validation → conversation re-anchor (`:5175-5181`) → per-conversation hard cap
(`:5183+`) → slot search → `socket()`/`bind()`/`listen()` → `getsockname()` bookkeeping.

What holds, with anchors:

| Property | Anchor | Verdict |
|----------|--------|---------|
| Refund on **every** refusal after the booking | `booked` set `:5145`; `refuse:` label gives it back — `:5307-5312` (`if (booked) s3_srv_reverse_budget_give(ch->sess_user, 1)`) | correct; no cap leak that I can see |
| Per-user cap table | `s3_srv_reverse_budget_take` `:4453+`: name clamped to `S3_SRV_SFTP_USER_MAX 127`, `b->user[127] = '\0'` into `char user[128]` (`:288`, struct `:409`) | **no off-by-one**; the "16 distinct users" table is fail-closed when full |
| Hard per-conversation cap stays on top | `:5183-5186` (`listeners >= S3_SRV_REVERSE_LISTENERS_MAX` → refuse) | present, refuses before any `socket()` |
| GatewayPorts rewrite | `s3_srv_reverse_bind_rewrite`: loopback v4 (`127/8`) and v6 loopback pass through verbatim; `clientspecified` passes the client spelling; the default maps every non-loopback request to `127.0.0.1` and flags `rewritten` | matches sshd's `GatewayPorts=no` intent — a client cannot expose a non-loopback bind unless the operator opted in |
| Policy sees the rewritten host | rewrite → `s3_ssh3_forward_policy_check(&s3_srv_listen_policy, bind_host, req.bind_port)` | correct order (post-rewrite, pre-`socket()`) |
| IPv6 binds | `:5151-5160` — any `:` form → refuse, fail-closed | safe (the listener machinery is v4-only) |
| socket/bind/getsockname failure | each closes the fd and jumps to `refuse` (`:5222-5245`) | no fd leak observed |
| Per-user bookkeeping ownership | `budget_user` stored at booking (`:5146-5148`), refunded from teardown `:4548` | consistent with the take path |
| Direct-dial (`-L`/`-D`) policy | `s3_srv_fwd_policy_gate` (`:5315-5330`) runs before every dial; IPv4-only enforced (`:5341-5345`) | present |

**P2-5 (Info, robustness):** `s3_srv_reverse_bind_rewrite` consumes `requested->data` through `%s`,
i.e. it assumes NUL-termination while its parameter type is the length-carrying `s3_str_t`. The single
current caller does pass a terminated copy (`bind_text[len] = '\0'`, `:5055`), so there is no bug
today — but the type contract invites a future caller to hand a view into a larger buffer and read
past it. Either take the length or document the termination requirement.

Not audited: the client-side `-R` target validation and the `-o`-config `RemoteForward`/`LocalForward`
two-token join (`53fb62c`) beyond what §6 notes, the UDP leg of the reverse path, and the
`--max-reverse-forwards-per-user` knob's interaction with `--run-as-user`.

### 5.7 DoS guard — **not audited**

The per-connection counts / early-drop logic (`s3_srv_dos_*`, `app/ssh3_server.c:1031`, `:1197`) and
the wave's "land the DoS knobs after the getopt loop" fix (`caee73b`) were not reviewed. Left open;
it stays the third item of the continuation order.

### 5.8 QUIC transport / protection (~11.7k LOC) — deliberately out of scope

Not read. Nothing in the change set touches `src/event/quic/*`, so a regression there is unlikely from
this wave; the layer remains the largest unread block in the tree and a full pass needs its own
session.

## 6. New-findings sweep on the 2026-10-15…18 wave

The wave is ~10.5k inserted lines of shipped code, most of it in `app/ssh3_client.c`. Its own commit
log is the most useful audit signal: the wave landed and then fixed, within hours, a series of defects
in code that had just been written — `ce3ca4b` (the `-D` getopt case segfaulted: a missing `:` in the
option string makes `optarg` NULL), `b0bd98c` (the `-L` bridge was dead code), `53fb62c` (the `-F`
two-token forward form), `c4efeb9` (the JWT assembly had lost a segment copy), `5fbd1f0` (`-X` dropped
from the getopt string), `5124a5c` (a bare `-l` address lost the host extraction), `9877fb9`/`ed6daf3`
(bounded copies of `ControlPath` and the `-o` values), `c413ed5` (build shapes), `383fdf3` (bool parse).
That is a **getopt-table / option-string class of defect**, and only one member of it (`-D`) is known
to be fixed. **P2-6 (Info, process):** the option string and the `switch` table in
`app/ssh3_client.c` were not compared entry-by-entry in this pass; a systematic check (every letter in
the `getopt` string has a case, every case that needs an argument has its `:`, every `optarg` use is
NULL-guarded) is cheap and should be run before the next release, because the observed failure mode is
a NULL dereference, i.e. reachable by simply invoking the client with that flag.

Specific wave code examined:

- **JWT builder, client side** (`s3_cli_jwt_build_user`, `app/ssh3_client.c:2004-2185`), because
  `c4efeb9` rewrote it inside the wave:
  - Buffer arithmetic is **safe** at HEAD: `header[64]`, `payload[512]`, `seg[1024]`, `jti[64]`,
    `tok[1200]`, `sig[1024]`; `hlen`/`plen` come from `snprintf` and are refused when truncated
    (`:2141-2150`); the worst-case payload (two 127-byte `user` copies + `jti` + the fixed template
    ≈ 418 bytes) stays inside 512; the base64url of ≤511 bytes is ≤683, so `seg` (needs ≤769) and
    `tok` are not overflowed; the `tok` capacity test `tlen + 1 + siglen * 4 / 3 + 4 >= sizeof(tok)`
    (`:2169`) is a valid upper bound for the `4·len/3 + 4` output for every `len % 3`.
  - **P2-4 (Info):** the login user is interpolated into the JSON claims **without escaping**
    (`:2141-2148`, twice — `iss` and the `ssh3-<user>` `client_id`). A username containing `"` or `\`
    yields malformed or duplicated claims. Impact is bounded: the server requires
    `client_id == "ssh3-<authenticated user>"` and `iss == user` exactly
    (`src/ssh3/s3_ssh3_auth_jwt.c:1303-1326`), so the realistic outcome is a refused login, not an
    identity transfer — unless a future server-side parser picks a duplicated key with last-wins
    semantics *and* stops binding identity to the authenticated key. Recommend JSON-escaping the
    value anyway; it is two lines.
  - Note: for a long username **plus an RSA key**, the `tok` bound test can trip and refuse the
    connection ("the token buffer overflow"). That is a clean refusal, not a memory defect — but it
    is a plausible user-visible bug worth a regression test.
- **I-1 pin** (`5a77496`/`fd9570b`): the added assertions match what the code does (§3, I-1).
- **`-Wformat-truncation` shapes** (`ed6daf3`) and the bounded `ControlPath` copy (`9877fb9`): the
  commits replace truncating copies with checked ones. Reviewed only at diff level; the resulting
  strings (ControlPath, `-o` values) are used as *paths* and *config*, not as credentials, and every
  truncation I saw is length-checked at the copy site. No defect claimed, none ruled out either —
  the *use* sites of the truncated values were not followed.
- **Server `sshd`-canon CLI** (`2a9acd5`, `caee73b`, `383fdf3`): the DoS knobs are landed after the
  getopt loop; the bool parse accepts `on|off`; the defaults move to the sshd canon. Behaviour, not
  memory — deferred to §5.7.
- **Packaging wave** (area C): not audited (§9). Two things a reviewer should still look at when
  someone audits it: the service unit's privileges/user and the `postinst`/`postrm` account handling
  (`b982659`). Not on the wire, so it does not affect the transport's threat model.

## 7. Probes

**Not run in this pass.** Pass 1's probe setup remains the reference: the parser subset builds with
ASan+UBSan (full CMake build still impossible on this host — the installed OpenSSL is below the
project's requirement), the in-tree libFuzzer harnesses (wire, message, cm_frame, sftp_frame) were
driven through a stand-in `main()` for ~160k inputs with zero sanitizer reports, and
`fuzz_forward_target` did not link. I did **not** re-run those, did not add an h3 harness, and did not
retry `fuzz_forward_target`'s link. Nothing in this report is backed by a sanitizer run — the
conclusions above are static. If a third pass runs, the highest-value probe would be an
`s3_h3_parse.c` harness driven with the pass-1 corpus shape (the file is allocation-free and takes a
buffer plus a state struct, which makes it an unusually clean fuzz target).

## 8. Findings

| ID | Severity | Item |
|----|----------|------|
| P2-1 | Low | Peer-advertised `maxPacketSize` is still not enforced on the send path (§3 F-1b, §4.1): all 13 `chunk_size` callers pass the local `30000` constant, so a conforming peer that advertises a smaller bound receives 29997-byte data messages — a parity/robustness divergence from the reference `WriteData()`. No DoS: no 1-byte or 0-byte chunk is reachable at HEAD. Owner: whoever wires the send path; the codec half is done and self-clamping. |
| P2-2 | Info | No timing-safe comparison exists in the tree — `s3_memcmp` is plain `memcmp` (`src/core/s3_base.h:127`) and every claim/keyword comparison uses it. No practical vector in the audited paths (public values, OpenSSL verify for signatures); flag it before any secret comparison lands on that helper. No password/HMAC path was audited. |
| P2-3 | Info | No `jti` replay cache: `jti` must be present and non-empty, and is bound to the exporter conversation id only when `convid != NULL` (`s3_ssh3_auth_jwt.c:1332+`). Without that binding, a token captured inside its `exp` window has no replay guard. |
| P2-4 | Info | Client JWT payload interpolates the login user into JSON without escaping (`app/ssh3_client.c:2141-2148`) → malformed/duplicated claims; bounded by the server's exact `client_id`/`iss` checks, so self-inflicted refusal in the realistic case. Two-line fix; add a test with a `"` in the username. |
| P2-5 | Info | `s3_srv_reverse_bind_rewrite` reads `requested->data` via `%s` while its parameter type is the length-carrying `s3_str_t`; today's single caller is NUL-terminated, but the contract is wrong for the next one. |
| P2-6 | Info (process) | The wave's own commit log shows a getopt option-string/table defect class (`-D` segfault, `-X`, missing argument handling) of which only `-D` is confirmed fixed. Run the systematic table-vs-option-string check before the next release. |

**No memory-safety defect was found in anything read in this pass** — no out-of-bounds access, no
underflow, no use-after-free, no missing bound in the h3 decoder, the fix code, the reverse-forward
path or the lexical jail. The two findings whose severity could rise on more reading are the
unverified items in §9 (h3 field-value pointer lifetime; the SFTP child's drop ordering in lexical
mode).

## 9. Coverage and limitations (honest)

**Verified in this pass (read at `5bb540c`, anchored in the text):** the F-1/I-1/I-2/I-3 closures;
the full chunk-size arithmetic and all 13 of its call sites; the h3 request/control/settings framing,
field-line bounds, Huffman overflow guard, QPACK prefix and insert-count logic, dynamic-table lookup
bounds, `set_param`, and the two `memcpy`/allocation sites in `s3_h3_parse.c`; the JWT verification
claim set, alg allow-list and identity binding; the SFTP budget-before-fork ordering and the lexical
jail's boundary-aware verdict, `..` clamp and post-join fail-closed re-check; the reverse-forward
gate order, budget take/refund/struct sizing, GatewayPorts rewrite, policy order and socket error
paths; and the client JWT builder's buffer arithmetic.

**Not covered — carried forward, in the order I would do it next:**

1. `src/h3/s3_h3_parse.c` consumers — the lifetime of a header-value `s3_str_t` that points into the
   receive buffer, across the event-handler boundary, for the *pre-auth* request path. The decoder is
   clean; this is where a bug would land. (`s3_h3_parse.c` hands out views; only the dynamic-table
   path copies.)
2. SFTP lexical mode — the serving child's drop/privilege ordering (`app/ssh3_server.c:3943+`) and
   whether a symlink inside the home can be used against a not-yet-dropped child. Lexical is the
   *default under an unprivileged server*, so this is the highest-consequence open item.
3. The Huffman decoder tables and the QPACK encoder/eviction path; `s3_h3_uni.c`; `s3_h3_encode.c`.
4. DoS guard (§5.7) — `s3_srv_dos_*` accounting and early-drop correctness.
5. Client-side `-R` target validation, the UDP leg of the reverse path, `--run-as-user` interaction.
6. Password / Basic-auth path and the OIDC internals (`s3_ssh3_oidc.c`, `s3_ssh3_oidc_client.c`) —
   the only place a non-public secret is compared, and therefore where P2-2 would matter.
7. `src/event/quic/*` (~11.7k LOC), unchanged by this wave, still the largest unread block.
8. The Debian/RPM packaging wave (service unit, postinst/postrm) — not on the wire, not audited.
9. **No probes were run** (§7) — no sanitizer or fuzz evidence in this report; all conclusions are
   static. The getopt option-string/table consistency check (P2-6) is untested.

**Known limitations of the method:** this is a grep-directed static read of a 44k-LOC C codebase, not
an exhaustive line-by-line pass; files were selected by attack-surface reachability (pre-auth first),
and within the pre-auth path the h3 decoder was read in full while the code that consumes its output
was not. Where a claim is inherited from pass 1 rather than re-derived here (the `OPEN_CONFIRMATION`
reader count), it is marked as not re-verified in the text rather than restated as fact.

---

Prepared as a report-only audit. No repository code was modified; the branch carries this document
and nothing else.
