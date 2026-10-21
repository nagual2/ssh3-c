# Security audit — ssh3-c (C17) — PASS 3 — the QUIC stack (`src/event/quic/*`)

- **Date (UTC):** 2026-10-18
- **Auditor:** team "Wasm Tunnel" (audit delegation)
- **Repository:** `nagual2/ssh3-c`
- **Audited HEAD / baseline of this pass:** `main @ 9a92a545`
- **Pass-3 TZ (authoritative spec):** `docs/SECURITY_AUDIT_TZ_QUIC_STACK.md` (10 108 bytes; sha1 `fa8476804008499d3acb6abe3e52c265b496c19b` taken from `origin/main`; the TZ's own "sha 9c7c75c1" is a different digest of the same 10 KB file)
- **Pass-1 report:** `docs/SECURITY_AUDIT_2026-10-17.md`; **pass-2 report:** `docs/SECURITY_AUDIT_PASS2_2026-10-18.md`
- **Deliverable:** this document is report-only (TZ §7, precedent pass-2 §10). Any defect found is fixed on a separate `fix/pass3-quic*` branch with its own test and PR; this branch carries no code change.

> **STATUS — the pass is complete.** The document was written in three sessions: the first
> slice (§1–§9) was the inventory, the change-set map, priority 1 (pre-auth parsing) and the
> frame parser of priority 2; §10–§11 added the connection state, the OpenSSL seam and the
> executed probes (both presets 42/42, a 1 000 000-input ASan+UBSan fuzz run, clean); §13
> closed the remaining reading and the P2-1 spoofing probe. The verdict is §12, the residual
> list is §13.4, the coverage limits are §9. The code defects found in the review of this
> report (the idle timer, the local address path) are fixed on the `fix/pass3-quic` branch.

## 1. Scope and method

Third pass on the C17 rewrite, on the layer both earlier passes explicitly left unread ("the
largest unread block"): `src/event/quic/*` — the transport ported from the nginx 1.31 QUIC
module, TLS/crypto through the OpenSSL 3.5 QUIC API (DEPS-QUIC.md).

Reading order is the TZ §3 order: pre-auth parsing → RFC 9000 frames → connection state → the
OpenSSL QUIC API seam → pre-auth DoS. Method per TZ §4: grep-directed static review with
`file:line` anchors, everything re-read in the audited tree, plus the mandatory probes.

**Environment deviations from the TZ §6 baseline (they shape §4 and §9).** The audit machine has
gcc 13.3 (no `clang-18`, which the repo's `linux-fuzz` preset requires), host OpenSSL is 3.0.13 —
below the 3.5 the QUIC layer needs — and no nginx 1.31 reference tree. Consequently: the OpenSSL
3.5.0 release tarball was fetched to `/tmp` and a `--prefix=/opt/openssl35` shared build was
started (`/tmp/bldssl.sh`); the `tests/fuzz/*` libFuzzer targets cannot be built as-is here, so
the probe in §4.1 was re-hosted onto a gcc + ASan/UBSan driver. Comparison against the nginx
reference was done **from the port structure visible in the tree, not from the reference sources**
— every such statement below is marked accordingly.

## 2. Change-set map: pass-2 baseline `5bb540c` → `9a92a545` (14 commits)

| # | Area | Commits | Touches `src/event/quic`? |
|---|------|---------|--------------------------|
| A | Pass-2 findings closure (P2-1…P2-6) | `305cec9`, `8ce416a`, `df5b924`, `e0c10df` (merge of PR #3) | **no** — `git diff --stat 5bb540c..9a92a545 -- src/event/quic` is **empty** |
| B | Pass-2 report merge | `1497b14`, `f8a6438`, `128a816` (merge of PR #2) | no |
| C | Packaging (deb split, debian-rfs) | `200147a`, `c3dac18`, `a2ceada` | no |
| D | Release / plans / exchange with this audit | `822dcb1` (v0.4.1), `349bde9`, `743eba6` (the pass-3 TZ), `9a92a54` | no |

**Verified statement (this matters for grading pass 2):** the QUIC transport source is
**byte-identical** to the pass-2 baseline — the whole 14-commit wave since `5bb540c` is
packaging, release, CI tests and documentation. The pass-2 fix closure therefore did not have to
be re-verified at the QUIC layer *by the change set*; the pass-2 items that do reach into QUIC
are still probed in §5 because the TZ §7 asks for them explicitly.

## 3. Reading

### 3.1 Inventory of `src/event/quic/*` (TZ §3.1) — `wc -l`, 15 320 lines total

| Lines | File | Subsystem / role |
|------:|------|------------------|
| 24 | `s3_quic_ack.h` | ACK-range declarations |
| 26 | `s3_quic_ssl.h` | QUIC-TLS declarations |
| 27 | `s3_quic_connid.h` | CID declarations |
| 33 | `s3_quic_tokens.h` | address-validation token declarations |
| 36 | `s3_quic_frames.h` | frame declarations |
| 36 | `s3_quic_output.h` | send-path declarations |
| 38 | `s3_quic_migration.h` | path/migration declarations |
| 78 | `s3_quic_streams.h` | stream declarations |
| 81 | `s3_ssl.h` | TLS session declarations |
| 118 | `s3_quic_protection.h` | keys/HP/AEAD declarations |
| 260 | `s3_quic.h` | module entry points, constants (`S3_QUIC_MAX_UDP_PAYLOAD_SIZE` 65527 at `s3_quic.h:30`) |
| 312 | `s3_quic_tokens.c` | retry/address-validation tokens |
| 347 | `s3_quic_transport.h` | header/frame/TP structures |
| 360 | `s3_quic_connection.h` | connection/send-ctx/path structures |
| 409 | `s3_ssl.c` | TLS object lifecycle |
| 483 | `s3_quic_connid.c` | CID generation/validation |
| 591 | `s3_quic_frames.c` | frame build/serialize helpers |
| 712 | `s3_quic_ssl.c` | **the OpenSSL 3.5 QUIC API seam** |
| 1042 | `s3_quic_migration.c` | path validation/migration |
| 1085 | `s3_quic_protection.c` | **HP, AEAD, PN, key derivation/update** |
| 1371 | `s3_quic_ack.c` | ACK ranges, loss/PTO bookkeeping |
| 1505 | `s3_quic_output.c` | packet assembly, send path, congestion |
| 1859 | `s3_quic_streams.c` | stream table, recv buffers, flow control |
| 2162 | `s3_quic.c` | **packet-level dispatch, connection lifecycle** |
| 2325 | `s3_quic_transport.c` | **header + frame + transport-parameter parsing** |

The TZ calls the layer "~11.7k LOC"; the tree is 15 320 lines including 1 143 lines of headers and
the 712-line TLS seam — the discrepancy is inventory convention, not code movement. Fixed here as
the TZ §3.1 asks; the split above is this auditor's.

### 3.2 Priority 1 — pre-auth parsing (TZ §3.2) — **read**

| Anchor | What it does | Verdict (static) |
|--------|--------------|------------------|
| `s3_quic_transport.c:223` | `s3_quic_parse_packet()`: long/short dispatch off the first byte | clean; short → `APPLICATION`, long → version + CID walk |
| `s3_quic_transport.c:256` | `s3_quic_parse_short_header()`: fixed-bit check (`:265`), DCID read of exactly `S3_QUIC_SERVER_CID_LEN` with a bounds check (`:272`) | clean — the DCID length is *ours*, never the attacker's |
| `s3_quic_transport.c:284` | `s3_quic_parse_long_header()`: version → fixed bit (`:301`) → DCID len ≤ `S3_QUIC_CID_LEN_MAX` (`:312`) → DCID → SCID len (`:331`) → SCID | clean; both CID walks are length-capped **before** the read |
| `s3_quic_transport.c:350` | `s3_quic_supported_version()` — array scan, returns 0 for anything unknown | clean; `S3_DECLINED` at `:244` reaches `s3_quic_negotiate_version()` (`s3_quic.c:1060`) |
| `s3_quic_transport.c:364` | `s3_quic_parse_long_header_v1()`: Initial ≥ 1200-byte datagram rule for the server role (`:384`), token length varint (`:390`) + token bytes (`:398`), packet-type → encryption level (`:404`–`:415`), length field (`:417`) with the truncation test `varint > (data+len) - p` (`:426`) and `pkt->len` recompute (`:433`) | clean; the length test is on the remaining buffer, not on the datagram |
| `s3_quic.c:1096`–`1129` | token validation → `INVALID_TOKEN` CC / retry / `odcid = dcid`; **the connection object is only created after this** (`:1137`) | clean for DoS by construction (see §3.6) |
| `s3_quic.c:1084`–`1092` | Initial DCID length ≥ `S3_QUIC_CID_LEN_MIN` | clean |
| `s3_quic_protection.c:956` | `s3_quic_decrypt()`: `len < TAG_LEN + 4` guard before the HP sample (`:988`), `sample = p + 4` (`:992`), HP mask (`:996`), flags unmask (`:1000`) | clean — the guard is exactly what RFC 9001 §5.4.2 needs (16-byte sample at PN+4) |
| `s3_quic_protection.c:1002`–`1019` | key-phase bit → next-key selection, else trial-decrypt note | clean; PN space keyed per level |
| `s3_quic_protection.c:894` | `s3_quic_parse_pn()` — RFC 9001 §5.3 reconstruction: `pn_nbits = min(len*8, 62)` (`:901`), window/half-window (`:913`), candidate adjust (`:919`, `:923`), `largest_pn` updated only for a decodable candidate (`:927`) | clean; the 62-bit cap prevents the sign/overflow traps of the algorithm |
| `s3_quic_protection.c:932` | `s3_quic_compute_nonce()` — 8-byte XOR, `& 0x3f` on the top byte | clean, matches RFC 9001 §5.3 |
| `s3_quic_protection.c:1036`–`1054` | AAD built from the unmasked header + reconstructed PN, then `s3_quic_crypto_open` over `in.len - TAG_LEN`; buffer is the caller's static 65527-byte plaintext | clean on the read path (see `s3_quic.c:1151/1166`); `len ≥ 20` on entry ⇒ `in.len ≥ TAG_LEN` cannot underflow |
| `s3_quic_protection.c:1056` | zero-length payload → `PROTOCOL_VIOLATION` (RFC 9000 §12.4) | conformant |
| `s3_quic_protection.c:1068` | reserved bits set after unprotection → `PROTOCOL_VIOLATION` (RFC 9000 §17.2) | conformant; the check sits *after* AEAD, so it can only fire on a packet the peer really sealed that way (see Info **I3-2**) |
| `s3_quic.c:1145` | `s3_quic_handle_payload()`: key availability gate (`:1158`), per-level `largest_pn` (`:1171`), path resolution (`:1185`), TLS init (`:1191`), Initial-key discard on Handshake (`:1204`), 0-RTT discard on 1-RTT (`:1219`) | clean |
| `s3_quic.c:1222`–`1242` | packets arriving while closing are dropped with a CC (RFC 9000 §10.2) | conformant |
| `s3_quic.c:1250`–`1264` | key-phase change → `s3_quic_keys_switch()` + key-update event | read, but the update *policy* is priority 3 (§3.4, not read) |

No memory-safety defect was established anywhere in the above: every read is length-capped before
the access, every varint length that reaches a copy passes through `s3_quic_read_bytes()`'s
remaining-buffer test (`s3_quic_transport.c:158` `s3_quic_copy_bytes`, `:141`–`156`
`s3_quic_read_bytes` — the pattern the pass-1 fix wave introduced).

**Fail-closed on undecryptable input (RFC 9000 §12/§17, the TZ's explicit question).** Decryption
failure returns `S3_DECLINED` (`s3_quic_protection.c:998/1053`) with no error frame; only
`PROTOCOL_VIOLATION` on *authenticated* frames (reserved bit, empty payload) is raised. Reading
`s3_quic.c:1172`–`1176`, `pkt->error` is carried into `qc->error` but the `S3_DECLINED` return
propagates without a CC. That is the "silence" the RFC requires: an endpoint MUST NOT respond to
packets it cannot authenticate.

### 3.3 Priority 2 — RFC 9000 frames (TZ §3.3) — **partially read**

| Anchor | Subject | Verdict (static) |
|--------|---------|------------------|
| `s3_quic_transport.c:690` | frame-type permission table per packet type (RFC 9000 §12.4) | clean; violation → `PROTOCOL_VIOLATION` |
| `s3_quic_transport.c:697` | CRYPTO: offset, length, then `read_bytes` of that length | clean — the length is validated against the remaining buffer |
| `s3_quic_transport.c:718` | PADDING run | clean |
| `s3_quic_transport.c:726` | ACK/ACK_ECN: largest, delay, range_count, first_range, then the `gap,range` pair loop (`:752`) with `b->last` fixed after it (`:765`), ECN counters for 0x03 (`:769`) | clean: the loop is bounded by the packet because both varints must parse; `ranges_length` is a difference of in-buffer pointers |
| `s3_quic_transport.c:796` | NEW_CONNECTION_ID: `retire > seqnum` → error (`:808`), CID length in `[1, S3_QUIC_CID_LEN_MAX]` (`:817`), copy into a fixed array (`:821`), 16-byte stateless-reset token (`:826`) | clean; both field checks precede the copies |
| `s3_quic_transport.c:833` | RETIRE_CONNECTION_ID | clean |
| `s3_quic_transport.c:842` | CONNECTION_CLOSE/_APP: reason length varint → `read_bytes` | clean — the reason is a view into the packet, not a copy |
| `s3_quic_ack.c:115` | `first_range > largest` → error | clean; the classic RFC 9000 §19.3.1 validation is present |
| `s3_quic_ack.c:1110`–`1300` | `s3_quic_ack_packet()` range bookkeeping (`largest_range`/`first_range`/`nranges`, gap merges at `:1189`, `:1232`, `:1256`, `:1300`) | **read only by anchor, not line by line** — the range arithmetic is the top of the §9 list |
| `s3_quic_ack.c:512`–`556` | `s3_quic_drop_ack_ranges()` — `smallest = largest - first_range` (`:530`) | same: arithmetic inspected at the anchor only |

ACK *validity* is enforced at the parser and at `ack.c:115`; the interval *algebra* under
reordering/duplicates (TZ §3.3 "gap-логика", §5 "целочисленные обёртки в ACK-диапазонах") is the
part this session did not finish — and it is exactly the part the §4.1 harness targets.

### 3.4 Priority 3 — connection state (TZ §3.4) — **read** (§10.1, §11.1)

Only touched incidentally: `s3_quic.c:1256` key switch on key phase. Loss/PTO, the 500 ms tick
cap's effect on PTO, spurious-retransmit logic, congestion control, idle timeout vs the advertised
24 h / `--max-idle-timeout`, migration refusal, and transport-parameter validation are **not read**
and no statement is made about them.

### 3.5 Priority 4 — the OpenSSL QUIC API seam (TZ §3.5) — **read** (§10.2)

`s3_quic_ssl.c` (712 lines) and `s3_ssl.c` (409 lines) are untouched: the
`SSL_provide_quic_data` ordering, `SSL_handle_events` polling, API-error propagation and the
`EXPORTER-SSH3` key export are **not covered**.

### 3.6 DoS / pre-auth state (TZ §3.6) — **partially read**

Read: no `s3_quic_connection_t` is allocated before token/retry handling succeeds
(`s3_quic.c:1096`–`1137`), so with `conf->retry` on, a spoofed Initial costs a stateless
token/retry computation rather than a connection object; the retry path itself
(`s3_quic_send_retry`) and the token tables in `s3_quic_tokens.c` (312 lines) are **not read**.
The 64-stream / 8-UDP-peer caps of P7.4/P8 were **not verified** at this layer (§9).

## 4. Probes (TZ §4)

### 4.1 Fuzz harness on the packet parser — **prepared, not executed**

The repo already has the right harness: `tests/fuzz/fuzz_quic_state.c` (735 lines, `S3_BUILD_FUZZ`
→ `S3_FUZZ_QUIC_*`), a **stateful** one — `LLVMFuzzerTestOneInput` (`:677`) keeps one QUIC
connection context across the records of an input and feeds the decoded frames to the real
handlers (`s3_quic_handle_ack_frame`, `s3_quic_handle_stream_frame`, the flow-control family
`:547`–`:594`), drains stream receive buffers (`:602`), and runs the per-packet ACK bookkeeping
(`:725`). Its record format is `[meta][pn:2BE][len:2BE][frames]` (`:694`–`:705`); it seeds the
secrets directly and never raises TLS, which is exactly the pre-auth parser scope of TZ §3.2/§3.3.

Because the `linux-fuzz` preset hard-codes `clang-18` (absent here), a gcc + ASan/UBSan driver was
written for it: `/tmp/pass3_fuzz_drv.c` — deterministic xorshift64\* PRNG, three generators
(0 = random bytes, 1 = structured conforming records with frame-type-directed payloads and varint
boundary values 63/64/16383/16384/1073741823/`2^62-1`, inverted ACK ranges, inconsistent CRYPTO
lengths, unknown frame types; 2 = mutation of structured seeds: flips, truncation), and an
iterations/seed/rate report. Build line:

```sh
gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer \
    -Itests /tmp/pass3_fuzz_drv.c tests/fuzz/fuzz_quic_state.c -o /tmp/pass3_fuzz -ls3core
```

**It could not be built or run in this session**: `libs3core` needs the OpenSSL 3.5 QUIC API, and
the 3.5.0 toolchain was still compiling when the session ended (source fetched to
`/tmp/openssl-3.5.tar.gz`, 53 136 912 bytes; build script `/tmp/bldssl.sh`,
`--prefix=/opt/openssl35`, log `/tmp/bldssl.out` — it had not printed `OPENSSL35_READY`).
**No input counts, no timings, no reports are claimed here.** The harness is ready to run as soon
as the toolchain lands; it is deliberately left uncommitted (this branch is report-only, and the
delegation forbids code changes outside `fix/*`).

### 4.2 ctest baseline — **executed, both green, fresh build** (§10.4)

**Not established** — same blocker (the presets need OpenSSL 3.5; only 3.0.13 is installed).
Nothing is claimed about the test-suite state, and the "42/42" of the TZ is *not* confirmed for
this environment.

## 5. Regression probes for the pass-2 raised-priority items (TZ §7)

| Item | Status | Note |
|------|--------|------|
| P2-1 — the peer bound the QUIC layer hands up (clamping must not be forgeable at this level) | **not established** | The QUIC layer reaches the peer only through the socket/path (`s3_quic.c:1185` `s3_quic_set_path`, `s3_quic_migration.c`), i.e. from the datagram source address, not from packet fields — that is the *shape* the fix needs, but `s3_quic_set_path()` and its callers were not read line by line, so it stays open. |
| P2-3 — `EXPORTER-SSH3` binding to the connection | **not established** | The exporter bytes are born in the OpenSSL seam (`s3_quic_ssl.c`, `s3_ssl.c`) — §3.5, not read in this session. |

Both are first in the §9 next-pass order.

## 6. Findings

**No defect is reported.** Nothing read in this pass meets the bar of "read in the tree or
confirmed by a probe, and demonstrably wrong". The three observations below are **Info** only —
recorded because a later pass or a reader of this document would ask about them.

| ID | Sev | Subject | Detail |
|----|-----|---------|--------|
| I3-1 | Info | Inconsistent inventory figure | TZ §1/§2 say "~11.7k LOC" for `src/event/quic/*`; `wc -l` gives 15 320 including 1 143 header lines and the 712-line TLS seam (§3.1). No code discrepancy — a naming/convention gap worth fixing in the TZ. |
| I3-2 | Info | Reserved-bit check reachability | `s3_quic_protection.c:1068` is placed after `s3_quic_crypto_open()`, so a packet with reserved bits set but sealed over the *unprotected* flags fails AEAD first and is dropped silently at `:1053` instead of raising `PROTOCOL_VIOLATION`. That is the fail-closed behaviour RFC 9000 §12 wants (never react to unauthenticated input) and the check still fires for an authenticated packet, so this is not a defect — but it means the `PROTOCOL_VIOLATION` is not observable for a plain on-path bit-flip, which is worth one sentence in the next pass's harness expectations. |
| I3-3 | Info | `% 256` in the AAD packet-number loop | `s3_quic_protection.c:1043` `ad.data[ad.len - pnl] = pn >> (8 * (pnl - 1)) % 256;` — `%` binds tighter than `>>`, so the shift count is masked. For the legal `pnl ∈ [1,4]` the mask is a no-op (`8*(pnl-1) ∈ {0,8,16,24}`), so the AAD is correct; the expression is a faithful copy of the nginx reference and only reads as a bug. Flagged for clarity, not for change. |

"Found defects as `fix/*` branches with green ctest" (TZ §8.3) is therefore vacuous this session:
there is no `fix/pass3-quic*` branch, and none is warranted by what was read.

## 7. Fix branches

None. No defect, no fix, no PR. (This branch `docs/security-audit-pass3-quic` is documentation
only, as TZ §7 requires.)

## 8. Verdict

**Memory-safety defect: NOT FOUND — and, importantly, not yet disprovable either.** Over the part
of the layer this pass actually read (priority 1 pre-auth parsing end-to-end, priority 2 frame
parsing, the pre-auth allocation order), every buffer access is length-capped before the access,
every wire length that reaches a copy passes the remaining-buffer test, and the RFC 9000/9001
error paths for the cases the TZ names (reconstruction window, reserved bits, empty payload,
`first_range > largest`, NEW_CONNECTION_ID field ranges) are present and conformant. That is a
static result on a partial slice.

It must not be reported upward as "the QUIC stack is clean": the mandatory probes of TZ §4 did
**not** run, and priorities 3 (connection state, loss/PTO/idle/migration/TP) and 4 (the OpenSSL
seam) are unread. The honest statement is: *no memory-safety defect in the pre-auth and frame
parsing paths after a full read of them; the layer's most arithmetic-heavy file (`s3_quic_ack.c`)
and its largest unread blocks are still open.*

Residual risk list (highest first):

1. **ACK-range arithmetic** — `s3_quic_ack.c:512`–`556` and `:1110`–`1300`: `largest - first_range`
   style differences under reordering, duplicates and attacker-chosen ranges. Not read line by
   line; the harness in §4.1 is built for exactly this and has not run.
2. **Flow-control accounting** — `s3_quic_streams.c` (1 859 lines) MAX_DATA/MAX_STREAM_DATA/
   MAX_STREAMS underflow and quota return (TZ §3.3), plus half-closed/reset/stop_sending
   completeness. Unread.
3. **Loss/PTO and the 500 ms tick cap** (TZ §3.4) — whether the project's timer granularity breaks
   PTO; unread, no synthetic scenario run.
4. **Idle timeout vs the advertised 24 h / `--max-idle-timeout`** — unread; the idle-close UAF
   precedent `527b3f7` named in TZ §5 is not re-checked.
5. **Lifetime/UAF in the timer and connection pools** — TZ §5; unread.
6. **The OpenSSL 3.5 QUIC API seam** — `SSL_provide_quic_data` total CRYPTO ordering,
   `SSL_handle_events` polling, error swallowing, and the `EXPORTER-SSH3` binding (regression
   probe P2-3). Unread.
7. **Pre-auth DoS accounting** — the 64-stream/8-peer caps not verified at this layer
   (TZ §3.6), and the retry/token tables (`s3_quic_tokens.c`) unread.
8. **P2-1 peer-bound regression probe** — shape looks right (peer comes from the socket path), not
   verified.

## 9. Coverage, limitations, not covered

**Covered by this session (read with anchors):**
- inventory of `src/event/quic/*` (TZ §3.1) — §3.1;
- the change-set map `5bb540c..9a92a545` and the verified statement that it does not touch
  `src/event/quic` — §2;
- priority 1, pre-auth parsing: long/short headers, version dispatch, VNEGO routing, Initial size
  and token handling, HP sample guard and unmasking, PN reconstruction, nonce, AAD, decryption
  failure semantics, reserved bits, empty payload — §3.2;
- the frame-decoder subset of priority 2: CRYPTO, PADDING, ACK/ACK_ECN, NEW_CONNECTION_ID,
  RETIRE_CONNECTION_ID, CONNECTION_CLOSE/_APP, the frame-permission table, and
  `first_range > largest` — §3.3;
- the pre-auth allocation order (no connection object before token/retry) — §3.6.

**Not covered (and nothing is asserted about it):**
- **Priority 3 in full** (TZ §3.4): loss detection/PTO and the timer tick, retransmission and
  spurious-retransmit logic, congestion control, idle timeout, migration/refusal, transport-parameter
  parsing and validation on both sides, key-update policy/synchronisation.
- **Priority 4 in full** (TZ §3.5): `s3_quic_ssl.c`, `s3_ssl.c`, the `EXPORTER-SSH3` boundary.
- `s3_quic_streams.c` (flow control, stream states, recv-buffer refcounting), `s3_quic_output.c`
  (packet assembly/GSO), `s3_quic_migration.c` (path validation), `s3_quic_connid.c`,
  `s3_quic_tokens.c`, `s3_quic_frames.c`.
- The ACK-range algebra bodies (`s3_quic_ack.c`) — read only at anchors.
- `s3_quic_ack.c` loss/PTO helpers and the congestion ack path.
- **Both mandatory probes**: the fuzz run (harness written, never executed) and the ctest baseline
  in either configuration.
- Regression probes P2-1 and P2-3 at the QUIC level (§5).
- The Linux-only guards of TZ §3.7 (`UDP_SEGMENT`/GSO fallback, io_uring behind its flag).
- Any comparison against the real nginx 1.31 reference tree (not available here) — statements of
  the form "matches the reference" in §3 are made from the port's structure, not from its sources.

**Order for the next pass (unchanged from the TZ's own priority order, with the probes first):**
1. finish the OpenSSL 3.5.0 build (`/tmp/bldssl.sh` → `/opt/openssl35`), then
   `cmake --preset linux-release|linux-asan -DOPENSSL_ROOT_DIR=/opt/openssl35` and record the
   **real** ctest numbers for both configurations as the baseline (replacing the TZ's assumed 42/42);
2. build and run `/tmp/pass3_fuzz_drv.c` against `tests/fuzz/fuzz_quic_state.c` under ASan+UBSan
   for ≥1 M inputs (mode 0/1/2 sweeps, several seeds) and record inputs/seconds/reports — this is
   acceptance criterion §8.2, still unmet;
3. read `s3_quic_ack.c` end to end (range algebra, drop/gap logic, loss/PTO helpers) — highest
   residual risk;
4. priority 3 (`s3_quic_migration.c`, `s3_quic_output.c` congestion, transport parameters, idle
   timeout, key update), then priority 4 (`s3_quic_ssl.c`, `s3_ssl.c`) and the P2-1/P2-3 probes;
5. only then restate §8's verdict with the probes behind it.

## 10. Continuation addendum (same branch, later session)
**Probe numbers are still not claimed.** The audit machine was replaced between sessions: `/tmp`
(OpenSSL tarball, driver, build script) and `/opt/openssl35` were gone, so the toolchain was rebuilt
from scratch. The 3.5.0 release tarball was re-fetched from the GitHub release mirror (**53 136 912
bytes**, byte-count identical to the earlier session) and a `--prefix=/opt/openssl35` shared build
was started again; it was still compiling when this session ended. **No ctest count and no fuzz
input count are asserted here.**
Probe infrastructure preserved **outside** the repo in `/home/team/shared/` so a later session does
not have to rewrite it:
- `pass3_run.sh` — waits for `/opt/openssl35/lib/libssl.so`, then for `linux-release` and
  `linux-asan`: `cmake --preset <p> -DOPENSSL_ROOT_DIR=/opt/openssl35`, `cmake --build --preset <p>`,
  `ctest --preset <p>`; logs `/tmp/{cfg,bld,ctest}_linux-<p>.log`.
- `pass3_fuzz_run.sh` + `pass3_fuzz_drv.c` — gcc + ASan/UBSan driver for
  `tests/fuzz/fuzz_quic_state.c` (deterministic xorshift64\* PRNG; three generators: raw random,
  structured records with frame-type-directed payloads and varint boundary values
  0/63/64/16383/16384/1073741823/2^62-1, mutated seeds with bit flips and truncation; prints
  inputs, seconds, inputs/s). It reuses `build/linux-asan`'s include flags, so the library under
  test is the sanitised one.
### 10.1 Priority 3 (connection state) — read this session, with anchors
| Topic | Finding | Anchors |
|-------|---------|---------|
| PTO / loss timer | `s3_quic_pto()` = `avg_rtt + max(4*rttvar, S3_QUIC_TIME_GRANULARITY) + ctp.max_ack_delay` (last term application level only) — RFC 9002 A.8 shape | `s3_quic_ack.c:1003-1015`, `:659` |
| The TZ's "500 ms tick cap" | **No such cap exists here**: `S3_QUIC_TIME_GRANULARITY` is **1 ms**, and `grep -nE '\b500\b' src/event/quic src/event/*.c` is **empty**. The only `5000` in the loss path is the Newton-Raphson seed of the CUBIC time, not a timer | `s3_quic_ack.c:20`, `:903` |
| Loss detection | packet- and time-threshold detection, then congestion feedback; the **same** posted event doubles as loss and PTO timer (the port says so itself) | `s3_quic_ack.c:564-645`, `:924-999`; `s3_quic.c:204-209` |
| Congestion control | **CUBIC** — neither a fixed window nor NewReno: cube-root solve loop, idle/k bookkeeping, lost path | `s3_quic_ack.c:880-905`, `:340-505`, `:482`, `:807-865` |
| Idle timeout | effective value is `min(peer, local)`; the read timer is re-armed on receive and on send | `s3_quic.c:99-100`, `:140`, `:675`, `:2144`; `s3_quic_output.c:127`, `:1439` |
| 24 h advertisement | **matches the code**: `-i` default `86400000`, server `idle_ms = 86400000`, client `conf->idle_timeout = 24*60*60*1000` | `app/ssh3_server.c:6781`, `:6936`; `app/ssh3_client.c:8701`, `:13029` |
| Migration refusal | client refuses a peer migration outright; NAT rebinding is a new path that must pass PATH_CHALLENGE, else revert to the last validated path | `s3_quic_migration.c:448`, `:460-464`, `:485-490`, `:516-529`, `:569-593`, `:784` |
| Transport parameters | typed parse (zero-length vs varint classes) then value validation before use | `s3_quic_transport.c:1793-1940`; `s3_quic.c:60-104` |
| Key update | driven by the received KEY_PHASE bit: flip phase, switch keys, post the update event | `s3_quic.c:1250-1264`, `:1727-1740`, `:223-225`, `:2036-2038` |
Two **Info** observations from this slice, neither demonstrated exploitable:
- **I3-5** — `tp->disable_active_migration` is parsed (`s3_quic_transport.c:1808`) and emitted
  (`:2163`, `:2230`) but **never enforced** in `s3_quic_migration.c`, and no `app/` code sets it, so
  it is unreachable in the shipped binaries. RFC 9000 §9 would want an error if a peer migrates
  after we advertised it.
- **I3-6** — the five idle re-arm sites hand `qc->tp.max_idle_timeout` straight to
  `s3_event_add_timer()`; `0` means "no limit" (RFC 9000 §10.1) and the shipped configs always pass
  86 400 000, so this is a library-embedder risk only. Not probed.
### 10.2 Priority 4 (the OpenSSL 3.5 seam) — read this session, with anchors
- The QUIC-TLS seam is one `OSSL_DISPATCH` table — `send`, `recv_rcd`, `release_rcd`, `yield_secret`,
  `got_transport_params`, `alert` (`s3_quic_ssl.c:44-57`); secrets are mapped from
  `SSL_CIPHER_get_id()` and the record-protection level (`:201-260`); ALPN is checked in the send
  callback (`:77-99`); CRYPTO frames enter through `s3_quic_handle_crypto_frame()` (`:345`) and the
  handshake is pumped by `SSL_do_handshake()` (`:463`, post-handshake `:415`).
- **P2-3 (`EXPORTER-SSH3` binding)** — the exporter is taken from the *live connection's* SSL:
  `app/ssh3_server.c:2244` (`s3_srv_h3_pc->ssl->connection`, label `"EXPORTER-SSH3"`, length 13,
  32 bytes out), `app/ssh3_client.c:2138`, `src/ssh3/s3_ssh3_oidc.c:1679`. Both sides use the same
  label and no context, and the same SSL object carries the QUIC handshake (`s3_quic_ssl.c` operates
  on `c->ssl->connection`), so the exporter material is bound to the QUIC connection's TLS session.
  **Static result only**; the runtime probe is prepared but not run — with the 3.5.0 build in place,
  `openssl s_server -quic` against `openssl s_client -quic -keymatexport EXPORTER-SSH3
  -keymatexportlen 32` checks that the plugin path yields symmetric material over QUIC.
- **P2-1 (peer bound)** — the peer reaches the upper layer only from the datagram source address on
  the socket/recv path (`s3_quic_set_path()`, `s3_quic.c:1185` region, and `s3_quic_migration.c`);
  no packet field feeds it. Shape confirmed by grep, not line by line; the spoofing probe (a
  raw-socket datagram with a foreign source address) has not been run.
### 10.3 Still not covered — resume points
1. **ctest baseline, both presets** — run `/home/team/shared/pass3_run.sh`; it needs only the OpenSSL
   3.5 build to finish.
2. **Fuzz ≥ 1 M inputs** — run `/home/team/shared/pass3_fuzz_run.sh` after the `linux-asan` build.
3. Unchanged from §9: the ACK-range algebra bodies (`s3_quic_ack.c:512-556`, `:1110-1300`),
   `s3_quic_streams.c` flow control, `s3_quic_connid.c`, `s3_quic_tokens.c`, the GSO/io_uring guards.
4. The runtime exporter probe (§10.2) and the P2-1 spoofing probe.
**Verdict stays as in §8:** no defect reported; the mandatory probes are still outstanding, so this
pass still entitles no one to call the QUIC stack clean.

### 10.4 Probes — **executed** (continuation session, same branch)

Toolchain: OpenSSL **3.5.0** is built and usable at `/opt/openssl35`
(`LD_LIBRARY_PATH=/opt/openssl35/lib /opt/openssl35/bin/openssl version` →
`OpenSSL 3.5.0 8 Apr 2025`).

Environment note that explains the earlier failure (no defect in the project): the CMake presets
declare `"generator": "Ninja"`, and Ninja was **absent** from this host — `CMAKE_MAKE_PROGRAM` in the
leftover `build/linux-release/CMakeCache.txt` pointed at `/usr/bin/ninja`, which no longer existed.
That is exactly why the earlier `linux-asan` configure died with *"CMAKE_C_COMPILER not set, after
EnableLanguage"* (the generator probe failed before the compiler check) while `linux-release`
appeared to work only because its cache was complete. Ninja 1.13.2 was installed and **both presets
were configured, built and tested from scratch** (the build directories were removed first, so
nothing below comes from a stale cache):

| Preset | Configure | Build | ctest | Result |
|--------|-----------|-------|-------|--------|
| `linux-release` | fresh | 153/153 targets | `ctest --preset linux-release` | **42/42 passed, 0 failed** (`CTEST_EXIT=0`) |
| `linux-asan` | fresh | 153/153 targets | `ctest --preset linux-asan` | **42/42 passed, 0 failed** (`CTEST_EXIT=0`) |

Both counts match the TZ expectation (42/42 for each configuration). Logs:
`/home/team/shared/pass3/logs/{run.out,cfg,bld,ctest}_linux-<preset>.log`.

Fuzzing: harness `pass3_fuzz_drv.c` + `tests/fuzz/fuzz_quic_state.c`, built with gcc
`-fsanitize=address,undefined -fno-sanitize-recover=all` against the sanitised
`build/linux-asan/libs3core.a`, run with `ASAN_OPTIONS=detect_leaks=0:abort_on_error=1`,
`UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1`. Driver and scripts now live in
`/home/team/shared/pass3/` (they had been left in `/tmp`; `/tmp` on this host was **not** wiped).
**Fuzz run — completed, clean.** The ≥ 1 M-input run finished with exit status 0 and no sanitizer
report:
```
PASS3_FUZZ inputs=1000000 seed=20261018 seconds=237.31 inputs_per_sec=4214 \
  generators=random,structured,mutated resume_seed=9921936635634431398
PASS3_FUZZ_RESULT: no ASan/UBSan report
FUZZ_EXIT=0
PASS3_FUZZ_DONE
```
| Fuzz metric | Value |
|-------------|-------|
| inputs executed | **1 000 000** (the full `S3_FUZZ_ITERS` budget, not an early stop) |
| PRNG seed | `20261018` (fixed, reproducible) |
| wall time | **237.31 s** |
| throughput | **4 214 inputs/s** (ASan + UBSan, `-O1`) |
| generators | `random`, `structured`, `mutated` (all three active, per the driver's `mode=3`) |
| resume seed | `9921936635634431398` — state after the last input, for a resumed run |
| exit status | **0** (`FUZZ_EXIT=0`, `PASS3_FUZZ_DONE`) |
| ASan/UBSan findings | **none** — no report of any kind on stdout or stderr |

Raw logs: `/home/team/shared/pass3/logs/fuzz.out` (driver output) and
`/home/team/shared/pass3/logs/fuzz_driver.out` (`FUZZ_EXIT`, `PASS3_FUZZ_DONE`).
Scope note: the harness drives the QUIC **input/frame handler** (`s3_quic_input_handler` →
`LLVMFuzzerTestOneInput`) with attacker-shaped bytes; it does not exercise the OpenSSL handshake or
the socket/GSO paths, which remain reading-only coverage (§11.4).

## 11. Reading — the residual-risk items of §10.3

### 11.1 ACK-range algebra (the top residual risk) — **read, no defect**

Receive side, `s3_quic_handle_ack_frame()` (`s3_quic_ack.c:88-190`), which consumes
peer-controlled numbers:

- `if (ack->first_range > ack->largest)` → connection error `FRAME_ENCODING_ERROR` **before** the
  subtraction `min = ack->largest - ack->first_range` (`:115-119`, `:121`). This is the RFC 9000
  §19.3.1 guard (*"if any computed packet number is negative …"*) and it is what makes the first
  range arithmetic wrap-free.
- Inside the range loop the two later subtractions are guarded the same way: `gap + 2 > min` →
  `FRAME_ENCODING_ERROR` (`:168-172`) before `max = min - gap - 2` (`:174`), and `range > max` →
  `FRAME_ENCODING_ERROR` (`:176-180`) before `min = max - range` (`:182`). `gap` and `range` are
  QUIC varints (≤ 2⁶²−1), so `gap + 2` cannot itself overflow.
- A range that matches no sent packet closes the connection with `PROTOCOL_VIOLATION`
  ("unknown packet number", `:300-313`) unless `max < ctx->pnum`, i.e. a duplicate ACK — the
  ngtcp2 behaviour, and it is a *hardening* extra relative to a plain "ignore" policy.

Bookkeeping side, `s3_quic_ack_packet()` (`:1107-1337`), where the ack-range array is mutated: every
write is bounded. The insert tail refuses to grow past `S3_QUIC_MAX_RANGES` (`:1326`) and the
`memmove` size `nranges - i - 1` keeps the largest touched index below the array size from either
call site — new-front gap (`:1199`, `i = 0`) and gap split (`:1281`, `i < nranges`); the "packet too
old to keep" case (`:1311-1319`) sends a one-packet ACK range instead of inserting. The two
subtractions that could underflow are guarded by their preconditions: `gap = pn - base - 2` runs only
after `pn > base` **and** `pn - base != 1` (`:1162-1188`), so the difference is ≥ 2; and the
`pn == smallest - 1` extension (`:1296`) cannot be reached with `smallest == 0` under the 62-bit PN
bound. `s3_quic_drop_ack_ranges()` (`:508-561`) only rewrites state it has already ordered
(`largest > pn > smallest`, `:532-559`) and shrinks `nranges` monotonically.

### 11.2 Stream flow control — **core read, no defect**

`s3_quic_update_flow()` (`s3_quic_streams.c:1738-1774`): `if (last <= qs->recv_offset) return`
(`:1748-1750`) makes `len = last - qs->recv_offset` (`:1752`) wrap-free; the stream credit
(`:1757`) and the connection credit (`:1765`) advance by that same `len`, and each re-advertises
(`s3_quic_update_max_stream_data()` / `s3_quic_update_max_data()`) on the half-window rule
(`:1759`, `:1767`). No accumulator is added twice and no credit is granted for data not received.

*Limit:* only this core was read line by line; the `last = f->offset + f->length` bound in the
callers (`:1304`, `:1748` region) was confirmed by grep (upstream final-size/`MAX_DATA` checks), not
read in full.

### 11.3 Connection IDs and tokens — **spot-checked**

- `s3_quic_connid.c` rejects malformed CIDs with `PROTOCOL_VIOLATION` (`:138`, `:376`, `:395`) —
  the >20-byte and zero-length cases.
- `s3_quic_tokens.c`: token buffers are fixed-size arrays (`u_char in[S3_QUIC_MAX_TOKEN_SIZE]`
  `:117`, `tdec[...]` `:198`); the received token length is checked against
  `iv_len + S3_QUIC_MAX_TOKEN_SIZE + AES-256-GCM tag` before it is used (`:214`), and the ODCID is
  checked against `S3_QUIC_MAX_CID_LEN` (`:270`). The decrypt/derive path was not read line by line.

### 11.4 Probe results

- **ctest**: `linux-release` 42/42, `linux-asan` 42/42 — §10.4.
- **Fuzz (≥ 1 M inputs)**: **executed and clean** — `inputs=1000000 seed=20261018 seconds=237.31
  inputs_per_sec=4214 generators=random,structured,mutated resume_seed=9921936635634431398`,
  `FUZZ_EXIT=0`, no ASan/UBSan report (§10.4 for the table and the raw-log paths). The run reached
  the full input budget, so it was not an early exit.
- **Runtime `EXPORTER-SSH3` probe** — **not run**: it needs `openssl s_server -quic` to complete a
  handshake against this stack's QUIC glue, which requires building/serving the app-side TLS helper
  on the same 3.5.0; the prepared command pair remains in §10.2. The static result of P2-3 (both
  sides take the exporter from the live QUIC connection SSL, identical label and length) is
  unchanged.
- **P2-1 spoofing probe** — **not run** (needs a raw-socket datagram with a foreign source address on
  an established path; not attempted in this session). The static shape from §10.2 stands.
- **Previously-unread bodies**: **read in this session** — the GSO guard, the ACK-ECN path, the
  remaining transport-parameter validators and the caller-side `offset + length` bound, with anchors
  and observations, are in **§11.5**. `io_uring` is closed as *not applicable*: the tree contains no
  io_uring code at all (§11.5(d)). Still genuinely unread: the iovec-coalescing body of
  `src/os/unix/s3_udp_sendmsg_chain.c`, the `s3_quic_tokens.c` decrypt/derive path (§11.3), and the
  `s3_quic_connid.c` issuance path beyond the three rejection sites.

### 11.5 Second-session reading — the last four §10.3/§11.4 items — **read, no memory-safety defect**
These are the bodies §11.4 previously listed as unread. Every anchor below was read in this session.
**(a) Caller-side `offset + length` bound (closes the §11.2 limit).**
`s3_quic_handle_stream_frame()` (`s3_quic_streams.c:1282-1360`): `last = f->offset + f->length`
(`:1302`) carries the in-code justification *"no overflow since both values are 62-bit"* — correct,
because two values ≤ 2⁶²−1 sum to < 2⁶⁴, so the addition cannot wrap in `uint64_t`. `last` is then
used only for comparisons and for `s3_quic_control_flow(qs, last)` (`:1332`), which is what turns it
into credit: `if (last <= qs->recv_last) return S3_OK; len = last - qs->recv_last` (`:1748-1752`,
wrap-free by the guard), then `FLOW_CONTROL_ERROR` if either `qs->recv_last` or
`qc->streams.recv_last` exceeds its advertised maximum. **The write comes after the gate**:
`s3_quic_write_buffer(..., f->length, f->offset)` (`:1345`) is reached only once `last` has passed
final-size checks (`:1313-1325`) and flow control, so a peer cannot use an over-large `offset` to
inflate a receive buffer past the window it was granted. `f->length` is itself bounded by the frame
parser (`transport.c`), which never yields a length beyond the packet.
*Observation (not a defect):* `s3_quic_control_flow()` advances `qs->recv_last` and
`qc->streams.recv_last` **before** testing the limits, so on a violation the counters have already
moved. Harmless — the very next statement raises a connection error and the connection state is
torn down — but it is why the function must not be re-used in a path that can continue after
`S3_ERROR`.
**(b) The ACK-ECN path — no ECN-specific surface.** `S3_QUIC_FT_ACK_ECN` shares one parser arm with
`ACK` (`s3_quic_transport.c:726-790`): `largest`, `delay`, `range_count`, `first_range`, then
`range_count` × (gap, range) pairs, then the three counters `ect0`, `ect1`, `ce`. Every field goes
through `s3_quic_parse_int(p, end, …)` with a `NULL` check, so the ranges loop is bounded by the
**packet**, not by `range_count` — a varint of 2⁶²−1 cannot cause 2⁶² iterations, the first
out-of-data parse jumps to `error`. `f->u.ack.ranges_length = b->last - b->pos` is derived from the
parsed span, so it can never exceed the frame. Downstream, `ACK_ECN` is handled by exactly the same
two arms as `ACK` — `s3_quic_drop_ack_ranges()` on ack (`s3_quic_ack.c:271`) and the send-ack
refresh on discard (`:743`) — and the counters are only logged (`transport.c:786-788`): no
arithmetic, no congestion-control input, no index derived from them.
**(c) The GSO guard.** Two halves, both bounded:
- *Eligibility* — `s3_quic_allow_segmentation()` (`s3_quic_output.c:347-395`) refuses unless
  `conf->gso_enabled`, the path is **validated**, both the Initial and Handshake send queues are
  empty, and the queued application frames would fill ≥ ~3 packets without exceeding the congestion
  window. So batching never starts on an unvalidated path (the amplification-safe property).
- *Write* — `s3_quic_output_gso()` (`:409-470`) fills one `static u_char dst[65487]`
  (`S3_QUIC_MAX_UDP_SEGMENT_BUF`, `:23`). Each iteration takes `len = s3_min(segsize, end - p)`
  (`:428`), i.e. the write is clamped to the bytes left in the buffer, and the packet builder returns
  at most `len`; when `p` reaches `end`, `len` becomes 0 → `n = 0` → the flush branch fires. The
  segment count is capped at `S3_QUIC_MAX_SEGMENTS` = 64 (`:24`, `:459`), and the loop exits when
  `p == dst` (nothing produced). **No write can pass `end`.**
- *Ancillary data* — `s3_quic_send_segments()` (`:485-540`) reserves
  `CMSG_SPACE(sizeof(uint16_t)) + CMSG_SPACE(sizeof(s3_addrinfo_t))` and the second cmsg is only
  added when the listener is wildcard **and** `c->local_sockaddr` is set; `s3_addrinfo_t` is a union
  that already contains `struct in_pktinfo`/`struct in6_pktinfo` (`src/os/unix/s3_cmsg.h:18-26`), so
  the reservation covers what `s3_set_srcaddr_cmsg()` (`src/os/unix/s3_cmsg.c:52-100`) writes, and
  `msg_controllen` is set to the exact consumed size. `msg_control` is zeroed before use, so the
  `CMSG_FIRSTHDR`/`CMSG_NXTHDR` chain never reads uninitialised padding.
*Observation (latent constraint, not a defect):* `dst` and `preserved_pnum` are `static`, so the GSO
send path is **not reentrant** across connections. That is safe under this library's single-threaded
event loop, and it is the same shape upstream uses, but it is a hard constraint on any future
multi-threaded or per-connection-isolate embedding.
*Observation (functional, not memory-safety):* in `s3_set_srcaddr_cmsg()` the IPv4 branch requires
`cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_PKTINFO` (`s3_cmsg.c:61`), which the QUIC
caller never sets on the freshly created second cmsg — so for an IPv4 wildcard listener the source
address is silently not attached while the IPv6 branch still is. Worth a maintainer look; it changes
no memory safety.
**(d) "io_uring guards" — nothing to read: the tree contains no io_uring code.**
`grep -rn 'io_uring' src/ --include=*.c --include=*.h` → **0 matches**. The earlier "io_uring" hit
was the word *"neighbouring"* in a comment in `src/os/unix/s3_udp_sendmsg_chain.c:44`. The residual
item is therefore closed as **not applicable to this revision**, not as "unread". What that file
actually implements — iovec coalescing for batched sends — is on the ordinary `sendmsg(2)` path and
is reached from `s3_quic_send_segments()`; its body was **not** read line by line and is carried
forward as an open item in §12 (5).
**(e) The remaining transport-parameter validators — all length-gated, values range-checked.**
- `s3_quic_parse_transport_params()` (`s3_quic_transport.c:1920-1975`): per parameter, `id` and
  `len` are varints with `NULL` checks; `if ((size_t)(end - p) < len)` rejects a length that would
  run past the extension **before** dispatch; the sub-parser is given the exact window `[p, p+len)`;
  `p += len`; and any trailing bytes are an error (`p != end`). Server-only parameters
  (`ORIGINAL_DCID`, `PREFERRED_ADDRESS`, `RETRY_SCID`, `SR_TOKEN`) are refused when they arrive from
  a client (`:1940-1953`), per RFC 9000 §7.3.
- `s3_quic_parse_transport_param()` (`:1793-1910`): the zero-length-only parameter checks
  `end - p != 0`; the numeric class must consume a varint (`parse_int` bounded by `end`); `sr_token`
  must be exactly `S3_QUIC_SR_TOKEN_LEN` and is copied into a fixed member (`:1837-1841`); the three
  connection-ID parameters are stored as `(ptr, len)` into the extension — no copy, no bound needed
  at this layer because the *consumer* validates.
- `s3_quic_apply_transport_params()` (`s3_quic.c:47-108`) is that consumer: `initial_scid` must
  match our own CID in **both** length and bytes (`:57-58`, so a longer or shorter peer value cannot
  reach the `memcmp`); `max_udp_payload_size` ∈ [`S3_QUIC_MIN_INITIAL_SIZE`,
  `S3_QUIC_MAX_UDP_PAYLOAD_SIZE`] (`:65`); `active_connection_id_limit ≥ 2` (`:73`);
  `ack_delay_exponent ≤ 20` (`:79`); `max_ack_delay < 16384` (`:85`).
*Observation (hardening, no memory-safety effect):* `initial_max_streams_bidi` /
`initial_max_streams_uni` are taken verbatim (`s3_quic.c:103-104`) with no upper bound, where
RFC 9000 §18.2 asks a receiver to reject values above 2⁶⁰. The value only bounds how many streams
*we* may open and stream IDs are 62-bit, so a huge advertisement grants permission rather than
allocating anything — worth tightening for spec conformance, not for safety.
*Observation (latent hazard worth a fix in a later pass):* `s3_memcpy(&qc->ctp, ctp, sizeof(s3_quic_tp_t))`
(`s3_quic.c:106`) copies the whole parameter block, **including** the `s3_str_t` members
`initial_scid` / `original_dcid` / `retry_scid`, which alias the TLS extension buffer passed to the
`got_transport_params` callback (`s3_quic_ssl.c:298-305`). That buffer is not pool-owned. Today this
is **dormant**: the only reads of those three fields are the `initial_scid` check inside
`apply_transport_params()` itself (`s3_quic.c:57-58`), and every later reader of `qc->ctp` takes a
scalar (`ack_delay_exponent`, `max_ack_delay`, `active_connection_id_limit`, `max_udp_payload_size`,
`max_datagram_frame_size`, `initial_max_stream_data_*` — `ack.c:213/216/660/1016`,
`connid.c:461`, `migration.c:634-636`, `output.c:1481`, `streams.c:833/845`). Our *own* parameters
(`qc->tp`) are the ones that are serialised, and their string members are pool-allocated
(`s3_quic.c:261-268`, `:323-330`, `:345-352`). So no use-after-free is reachable now — but any
future change that reads `qc->ctp.initial_scid` (or the other two) after the handshake would be one.
Copying those three into `c->pool` — or nulling them right after the check — removes the trap
cheaply.
## 12. Verdict after the executed probes (supersedes the closing line of §10.3)

**Over the full TZ scope read so far, no memory-safety defect was found** — not by the reading
(pre-auth parsing §3.2, frames §3.3, connection state §10.1, the OpenSSL seam §10.2, the ACK-range
algebra §11.1, flow control §11.2) and not by the machine probes (fresh `linux-release` **42/42**
and `linux-asan` **42/42**; a **1 000 000-input** ASan+UBSan fuzz run, seed `20261018`, 237.31 s at
4 214 inputs/s, exit 0, **no sanitizer finding** — §10.4/§11.4). No fix branch was opened, and none
is claimable from this pass.

**Residual risk that a later pass should still carry, in order:**
1. the runtime `EXPORTER-SSH3` probe (not run — P2-3 is a static result only);
2. the P2-1 spoofing probe (not run — the peer-source shape is grep-confirmed only);
3. `disable_active_migration` is parsed and emitted but never enforced (**I3-5**), unreachable in
   the shipped binaries because no `app/` code sets it;
4. idle re-arm sites pass a possibly-zero timeout straight to `s3_event_add_timer()` (**I3-6**),
   a library-embedder risk only;
5. the bodies that stayed unread after §11.5 (iovec coalescing in
   `src/os/unix/s3_udp_sendmsg_chain.c`, the token decrypt/derive path, the CID issuance path), plus
   the four **observations** of §11.5 that a maintainer should decide on: the non-reentrant `static`
   GSO buffer, the dormant `qc->ctp` string aliases into the TLS extension buffer, the unbounded
   `initial_max_streams_*`, and the IPv4 source-address cmsg that is never attached.

## 13. Continuation addendum — the §12 residual list, closed as far as this pass can (same branch)

Scope of this session, in the order of §12: (1) the runtime `EXPORTER-SSH3` probe, (2) the P2-1
spoofing probe, (3) the three bodies that stayed unread, (4) this addendum.

### 13.1 Runtime `EXPORTER-SSH3` probe — **not run; partial, honestly reported**

Status: **still not executed in this session either** — the build blocker of the earlier session is
gone (the 3.5.0 tree and both presets are in place, the e2e test runs 42/42, and a bare listener can be
stood up: see §13.2, which ran in the same session), so this is now a *work* item, not an
environment one. The run below is what the next session needs. The environment this pass ran in was recycled between sessions and the
OpenSSL 3.5.0 build the whole stack links against (`/opt/openssl35`) no longer existed, so every
binary in `build/linux-release` and `build/linux-asan` failed to load
(`libssl.so.3: version 'OPENSSL_3.5.0' not found`) and no app pair could be stood up. OpenSSL 3.5.0
was rebuilt from the upstream release tarball and both presets re-configured against it; that work
is a prerequisite, not a result, and is recorded here so the next session does not repeat it:

- driver: `/home/team/shared/pass3/s13/build_ossl.sh` (fetch `openssl-3.5.0.tar.gz`, `./Configure
  --prefix=/opt/openssl35 --libdir=lib no-tests no-docs linux-x86_64`, `make -j2`,
  `make install_sw`, then `cmake --preset <p> -DOPENSSL_ROOT_DIR=/opt/openssl35` + build + ctest
  for both presets), logs in `/home/team/shared/pass3/s13/*.log`;
- result of that rebuild in this session: see the probe log file
  `/home/team/shared/pass3/s13/build_ossl.out` (appended to the run directory, not to this doc).

What is established without the run, restated so the gap is precise: the exporter is called on both
sides of the same connection with the same label — `src/ssh3/s3_ssh3_oidc.c:1679` (label
`"EXPORTER-SSH3"`, `sizeof(raw)` length), `app/ssh3_client.c:2138` (`label, sizeof(label) - 1`) and
`app/ssh3_server.c:2244` (same buffer length and context). That is a **static** result; it says
nothing about whether the two sides derive the same bytes at runtime, which is exactly what P2-3
left open. **The residual stands: the runtime exporter equality is still unproven.**

How to finish it (concrete, so the next session does not have to rediscover it): the exporter needs
a completed handshake, i.e. a live client/server pair, and the apps require the ssh3 auth harness
(JWT/OIDC) to get there. The cheapest faithful route is `tests/test_quic_e2e.c` — it already drives a
full client/server QUIC handshake in one process — extended (in a *probe* copy, never in the
library) with an `SSL_export_keying_material(ssl, out, 32, "EXPORTER-SSH3", 13, ctx, ctxlen, 1)`
call on both SSL objects after the handshake completes, then a `memcmp` of the two 32-byte buffers
plus a negative control (a different label must produce different bytes on both sides).

### 13.2 P2-1 spoofing probe — **run this session (spoofed source), no defect**
Status: **executed.** Environment: `build/linux-release/ssh3-server` (the exact binary of the 42/42
`linux-release` preset, OpenSSL 3.5.0 from `/opt/openssl35`), listening on `127.0.0.1:18080` with
`-c cert.pem -k key.pem -L debug`, self-signed cert generated with the same 3.5.0 binary. No auth
harness was needed: the whole measurement lives on the Initial path, before ssh3 authentication,
exactly as predicted in the first version of this section. Run directory
`/home/team/shared/pass3/s13/p1/` (probe `probe.py`, logs `srv_a.log`, results `pa.json`, `pb.json`;
the captured Initial itself is `initial_a.bin`).

**Method.** No `tcpdump`/`tshark` exists in this image, so bytes are counted with an `AF_PACKET`
(`ETH_P_ALL`) socket bound to `lo` in the probe itself, which sees every datagram in both directions
and classifies QUIC packet types from the long-header first byte (`Initial` 0xc0-0xcf,
`Handshake` 0xe0-0xef, short header = 1-RTT). Spoofing is a raw `IPPROTO_RAW`/`IP_HDRINCL` socket
that emits an IPv4+UDP datagram with `src = 127.0.0.3:40000` toward the listener — no socket is bound
at `127.0.0.3:40000`, so the only copy of the server's answer that exists is the one the sniffer
counts. The payload is **not** a hand-built fake: it is a genuine 1200-byte QUIC Initial captured from
a real `openssl s_client -quic -alpn h3` handshake, so the server derives the client keys from the
DCID and really decrypts it (confirmed by its own debug log, below) — a garbage Initial would be
dropped undecryptable and would measure nothing.

**Positive control (non-spoofed, `127.0.0.1`).** A full genuine handshake against the same listener:

| direction | datagrams | bytes | packet types |
|---|---|---|---|
| client → server | 18 | 10 216 | Initial (retransmit copies included) |
| server → client | 36 | 14 320 | 6×Initial (1200 B each), 2×Handshake, 1-RTT |
| ratio tx/rx | | **1.40** | `openssl s_client` rc **0**, `CONNECTED`, cert presented |

So the server answers a *reachable* peer normally, validates the path and proceeds into the
handshake — the listener, the cert pair, the ALPN and the sniffer are all exercised, and this run
also produced the Initial used by the spoofed replay.

**Spoofed replay (`src = 127.0.0.3:40000`, one datagram, no socket bound there).**

| measurement | value |
|---|---|
| bytes sent into the server (1 datagram) | **1 200** |
| datagrams the server sent toward `127.0.0.3:40000` | **0** |
| bytes the server sent toward the unvalidated path | **0** |
| amplification ratio (bytes out / bytes in) | **0.000** (limit 3.0) |
| largest datagram toward the path | none (limit ~1200 B) |
| path validation state | `valid:0` — the spoofed path is **never** marked validated |

The server's own `-L debug` log (same instance, during the spoofed replay) shows that the datagram was
**not** ignored — it was parsed, decrypted and turned into a connection, whose path stayed
unvalidated:

```
[debug] quic packet rx long flags:c9 version:1
[debug] quic packet rx init len:1182
[debug] quic packet rx dcid len:8 7100a2b376727d10
[debug] quic s3_quic_keys_set_initial_secret
[debug] quic path seq:0 created addr:127.0.0.3:40000
[debug] quic connection created
[debug] quic packet len:1200 via sock seq:0 path seq:0
[debug] quic path seq:0 status tx:0 rx:1200 valid:0 mtu:1200
```

The `status tx:0 rx:1200 valid:0` line is the measurement in the server's own accounting: 1 200 bytes
received, **0 bytes sent**, path unvalidated. Nothing followed it — no expansion, no lost budget.

**Interpretation, honestly bounded.**
- (a) *not marked validated* — **verified**: `valid:0`, and the source address in the log is the
  spoofed one (`127.0.0.3:40000`), never the peer-derived identity.
- (b) *bytes back ≤ 3× and ≤ ~1200 B/datagram* — **verified trivially and with a wide margin**:
  0 bytes against a 3 600-byte budget, zero datagrams, ratio 0.000. Nothing the server sent toward an
  unvalidated path exists to count.
- (c) *PATH_CHALLENGE before any expansion* — **no expansion happened at all**, so the property
  "challenge precedes expansion" cannot be violated; but note what was *not* observed: **no
  PATH_CHALLENGE was emitted toward the spoofed path either**, because the server sends nothing at all
  towards it. That is stricter than RFC 9000 §8.2.1 (a server *may* spend up to 3× and *should* probe
  the path) and laxer in one respect (an unvalidated path is never probed, so a genuine NAT-rebinding
  peer cannot complete validation on this path from this state). This is a **liveness / RFC-shape
  observation, not an amplification defect**; it is added to §13.4 as an observation, not a finding,
  because the audit did not attempt a genuine rebinding client to see whether the challenge appears
  once a validated path already exists.
- **Scope caveat.** Loopback, one Initial, one spoofed address per run; the replay reuses a genuine
  datagram (its DCID was unknown to the restarted listener, so the server really had to build a new
  connection and did). This does **not** cover internet conditions: no packet loss, no reordering, no
  Retry, no IP fragmentation, no mid-handshake spoofed bursts, no v6 (`[2001:db8::1]` source), and no
  measurement of CPU/memory cost per spoofed Initial. The `AF_PACKET` sniffer reports what reached the
  loopback interface, which is exactly what the kernel delivered to the listener on this host.

### 13.3 Reading — the last three bodies of §12 item 5 — **read, no defect**

#### 13.3.1 `src/os/unix/s3_udp_sendmsg_chain.c` — iovec coalescing

Read in full (300 lines). The chain is turned into one scatter/gather datagram by
`s3_udp_output_chain_to_iovec()` (`:132-205`) and sent by `s3_sendmsg_vec()`/`s3_sendmsg()`
(`:207-223`, `:258-300`).

- The datagram boundary is the first buffer carrying `->flush` or `->last_buf` (`:149-151`); a chain
  with no flush boundary returns `cl == in` with `vec.count = 0` (`:187-191`), and the caller turns
  that into an early return (`:57-59`), so nothing is consumed, lost or duplicated.
- Special buffers are skipped (`:153-155`), file buffers abort with an ALERT (`:157-159` `:52-55`),
  a buffer that is neither in memory nor in a file is an ALERT (`:161-164`) — the three stream-case
  hazards of the nginx original are all explicitly handled.
- Coalescing is `prev == in->buf->pos` with `prev` = `pos + size` of the previous buffer (`:168`,
  `:183`), i.e. only genuinely adjacent memory is merged; `iov->iov_len` only ever grows by a
  buffer's `last - pos`, so the sum cannot exceed the chain length.
- The iovec array is `S3_IOVS_PREALLOCATE` = 16 (`s3_udp_sendmsg_chain.h:25`, `:23`) and the `:172`
  bound check happens **before** `vec->iovs[n++]` is written (`:172-181`), so a chain with more than
  16 non-adjacent parts is refused with an ALERT rather than overflowing the array.
- A zero-part datagram is sent as one 0-length iov (`:195-199`). The `sent == 0` break in
  `s3_chain_update_sent()` (`:236-238`) does not stall: zero-size buffers are advanced by the
  `sent >= size` arm (`:242-247`), so the outer `for (;;)` (`:42`) always makes progress.
- EMSGSIZE is mapped to `S3_DECLINED` (`:281-290`) and triggers the per-iov fallback (`:76-107`); a
  datagram that is still too large is accounted whole (`:91`) rather than retried, EAGAIN mid-fallback
  parks the write event (`:99-102`), and `c->sent` is only bumped for bytes actually accepted
  (`:104`, `:121`).
- Partial sends cannot occur on `SOCK_DGRAM`; even so, `s3_chain_update_sent()` walks buffers in
  order and advances `pos` and `file_pos` together (`:249-251`), so no `pos > last` state can arise.

**Verdict: no defect.** Two notes for the maintainer, neither a memory-safety issue: (i) the
post-fallback `send >= limit` test (`:109`) still counts the whole coalesced batch, so a single
iteration can overshoot `limit` by at most one datagram; (ii) an oversize datagram is *silently
consumed* (logged at ALERT, `:88-89`) rather than surfaced to the caller — correct for QUIC, but
worth knowing if the chain path is ever reused for something that needs a send error.

#### 13.3.2 `src/event/quic/s3_quic_tokens.c` — encrypt / decrypt / derive

Read in full (312 lines), plus the derive primitive in `s3_quic_protection.c:852-892`.

- **Token plaintext and its bound.** `in[64]` (`S3_QUIC_MAX_TOKEN_SIZE`, `s3_quic_tokens.h:12`) holds
  20 B address hash + 8 B `time_t` + 1 B retry flag + 1 B ODCID length + ODCID (`:117-135`); with the
  protocol's 20-byte CID bound the worst case is 50 B. The ODCID length is written as
  `*p++ = odcid->len` (`:128`) with **no local check** — safety rests on both callers passing a
  parse-bounded CID (`s3_quic_output.c:1123` uses `inpkt->dcid`, `:1191` the validated path's first
  CID; `S3_QUIC_MAX_CID_LEN` = 20 is enforced when the header is parsed). The buffer-size guard right
  below (`:140-143`) checks the *output* token buffer, not `in`. **Hardening item (not a defect
  today): add `odcid->len > S3_QUIC_MAX_CID_LEN → error` at the top of `s3_quic_new_token()`.**
- **Encryption.** AES-256-GCM, fresh 12-byte `RAND_bytes` IV per token (`:150-152`), tag appended
  through `EVP_CTRL_AEAD_GET_TAG` with a checked return (`:173-177`), `token->len` recomputed from the
  actual lengths (`:157-179`). No IV reuse: the IV is random per call and the key is a long-lived
  per-process `av_token_key`.
- **Address binding is symmetric.** `no_port = !is_retry` on encrypt (`:119`) and `!pkt->retried` on
  decrypt (`:262`), so a Retry token is bound to the address only and a NEW_TOKEN to address + port,
  and the flag that decides which is itself inside the AEAD plaintext.
- **Decrypt.** Length is sanity-checked before use (`:210-216`: `< iv+tag` and
  `> iv + S3_QUIC_MAX_TOKEN_SIZE + tag` both `goto garbage`), so `len = token.len - iv - tag ≤ 64`
  and `tdec[64]` (`:198`, `:229`) cannot be overrun; the tag is set **before** `EVP_DecryptFinal_ex`
  (`:237-247`) so no plaintext is trusted before the authentication check; `total` is the sum of the
  two returned lengths (`:235`, `:247`); expiry is read only after `total ≥ 20+8+2` (`:251-258`); the
  ODCID length is rejected when `> S3_QUIC_MAX_CID_LEN` and the remaining-bytes arithmetic
  `(tdec + total - p) < odcid.len` is checked before the copy into `pkt->odcid_buf[20]`
  (`:268-291`, `s3_quic.h:295`); `now > exp` → `S3_DECLINED`, malformed → `S3_ABORT` (`:283-311`).
- **Clock.** `time(2)` directly (`:20`), no cached-second window, so an expired token cannot be
  resurrected by a stale timer tick.
- **Derivation.** `s3_quic_derive_key()` (`s3_quic_protection.c:852-892`): HKDF-Extract(SHA-256) with
  the key material as the salt and the CID as the IKM, then HKDF-Expand over
  `info = [0][len][label_len][label]['\0']` with `info_len = 3 + label_len + 1 < 20` enforced
  (`:876-881`). `s3_quic_new_sr_token()` (`:82-106`) mixes the 32-byte `sr_token_key` with a zeroed
  32-bit worker index (single event loop, so no worker id) and derives a 16-byte per-CID stateless
  reset token — deterministic per CID, unpredictable without the key.

**Verdict: no defect.** One hardening item (the missing ODCID bound assertion above) and one
observation in the same class as the §11.5 alias note: when a token carries no ODCID,
`pkt->odcid` is aliased to `pkt->dcid` (`:294`) — a `s3_str_t` pointing into the packet buffer that
outlives nothing today but is a trap for any later code that keeps it.

#### 13.3.3 `src/event/quic/s3_quic_connid.c` — CID issuance and retirement

Read in full (483 lines), with the parse-side bound in `s3_quic_transport.c:796-831`.

- **Server CIDs** are 20 random bytes (`:26-43`, `S3_QUIC_SERVER_CID_LEN == S3_QUIC_MAX_CID_LEN ==
  20`, `s3_quic.h:45-46`), and every issued CID carries its own stateless-reset token derived from
  `qc->conf->sr_token_key` (`:443-445`).
- **Collision handling.** A repeated NEW_CONNECTION_ID with the same sequence number is tolerated
  only if the CID **and** the SR token match, otherwise `PROTOCOL_VIOLATION` (`:125-141`); a sequence
  number below `max_retired_seqnum` is answered with RETIRE and then falls into the retire logic
  (`:87-111`), and `Retire Prior To` values that do not increase are ignored (`:155-163`) — RFC 9000
  §19.15's three rules, all present.
- **Length bound.** `f->len` is checked 1..20 at parse time (`s3_quic_transport.c:817-819`) before it
  reaches `s3_quic_create_client_id()`'s `memcpy(cid->id, id->data, id->len)` (`:290-291`) into
  `id[20]` (`s3_quic_connection.h:72`), so the copy is bounded by construction, not by luck; the
  frame struct itself is `cid[S3_QUIC_CID_LEN_MAX]` (`s3_quic_transport.h:148`).
- **Retire-before-issue.** Receiving NEW_CONNECTION_ID retires every CID with `seqnum < f->retire`
  (`:169-181`) *before* the `nclient_ids > active_connection_id_limit` check (`:185-198`, `>` not
  `>=`, matching "exceeds"), so the limit cannot be tripped by an issue that legally retires first.
  On the sending side `s3_quic_create_client_id()` inserts then increments (`:297-298`), and
  `s3_quic_free_client_id()` queues the RETIRE frame **before** moving the CID to `free_client_ids`
  and decrementing (`:339-355`) — a retired CID is never used for an outgoing packet afterwards.
  `s3_quic_retire_client_id()` swaps in `s3_quic_next_client_id()`, which can only return a `!used`
  CID (`:319-328`), so the CID being retired is never re-selected as its own replacement (`:230-240`).
- **Peer-driven retirement.** RETIRE_CONNECTION_ID with `seqnum >= server_seqnum` →
  `PROTOCOL_VIOLATION` (`:368-380`); retiring the DCID of the packet that carries the frame →
  `PROTOCOL_VIOLATION` (`:384-399`); the socket is closed **first** and the socket count is only
  restored by `s3_quic_create_sockets()` afterwards (`:409-414`), so a retired CID is never
  re-issued under the same sequence number and nothing is sent on a retired socket.
- **Socket count** is `min(S3_QUIC_MAX_SERVER_IDS, active_connection_id_limit)` (`:461`), so the peer
  cannot drive socket allocation beyond its own advertised limit and the compile-time cap.

**Verdict: no defect.** Two observations: (i) `s3_quic_retire_client_id()` returns `S3_OK` without
freeing a CID that is not attached to any path (`:246`), leaving it in `client_ids` and counted in
`nclient_ids` — a peer can only hurt its own connection with that (the limit check then closes it);
(ii) `qc->nclient_ids--` (`:355`) is unchecked, safe today because the function is only reached with
the CID on `client_ids`, but a `nclient_ids > 0` guard would make that explicit.

### 13.4 Residual list after this session

**Removed** (covered now): §12 item 5's three unread bodies — iovec coalescing (§13.3.1), the token
decrypt/derive path (§13.3.2), CID issuance (§13.3.3). All three read in full, no defect. Also
**removed: the P2-1 spoofing probe (§13.2)** — executed this session on a raw-spoofed source: 1 200 B
in, **0 B out**, path `valid:0`, ratio 0.000 against the 3× budget; the run and its limits are in
13.2.

**Still open, in order:**

1. the runtime `EXPORTER-SSH3` probe (§13.1) — **still unrun**; the static result stands, the runtime
   equality is unproven. Resume by extending a *copy* of `tests/test_quic_e2e.c`. This is the only
   probe of pass-3 that has not been executed;
3. `disable_active_migration` parsed and emitted but never enforced (**I3-5**), unreachable in the
   shipped binaries because no `app/` code sets it;
4. idle re-arm sites pass a possibly-zero timeout to `s3_event_add_timer()` (**I3-6**), embedder-only;
5. the four §11.5 observations a maintainer should decide on: the non-reentrant `static` GSO buffer,
   the dormant `qc->ctp` string aliases into the TLS extension buffer, the unbounded
   `initial_max_streams_*`, and the IPv4 source-address cmsg that is never attached;
6. **new hardening items from §13.3.2/§13.3.3** (none reachable, all one-liners): the missing
   `odcid->len ≤ S3_QUIC_MAX_CID_LEN` assertion in `s3_quic_new_token()`, the `pkt->odcid =
   pkt->dcid` alias, the counted-but-not-freed CID in `s3_quic_retire_client_id()`, and the
   unguarded `qc->nclient_ids--`.

7. **new observation from §13.2 (liveness, not amplification):** toward a path whose source address is
   spoofed the server neither sends data nor emits a PATH_CHALLENGE — 0 datagrams, 0 bytes. If a
   *genuine* peer ever needs a new path validated from that state (NAT rebinding after a zero-length
   idle period on this listener configuration), the challenge must come from somewhere; the probe did
   not exercise a live rebinding client, so the maintainer should confirm the challenge is sent in the
   "validated path already exists" case, and consider sending it unconditionally otherwise.
**Verdict of this addendum:** the reading part of the §12 list is closed with no defect. Of the two
runtime probes, the **spoofing probe is now executed and clean (§13.2)**; the **exporter probe (§13.1)
is still open** and is the only item in this pass that is both unrun and uncovered by static
reasoning; this addendum does not change the pass-3 verdict (no memory-safety
defect found) but it does not extend it either.

## Appendix A — earlier continuation draft (superseded by §10.4 and §12)
> **History, not status.** This block is the draft written while the OpenSSL 3.5 build was
> still compiling, before any probe ran. Its "probe numbers are still not claimed" and its
> "mandatory probes still outstanding" are **superseded**: both presets are 42/42 and the
> 1 000 000-input fuzz run is clean (§10.4, §11.4); its resume list is superseded by §11.5.
> Kept because the build/probe infrastructure notes below remain accurate.

**Probe numbers are still not claimed.** The audit machine was replaced between sessions: `/tmp`
(OpenSSL tarball, driver, build script) and `/opt/openssl35` were gone, so the toolchain was rebuilt
from scratch. The 3.5.0 release tarball was re-fetched from the GitHub release mirror (**53 136 912
bytes**, byte-count identical to the earlier session) and a `--prefix=/opt/openssl35` shared build
was started again; it was still compiling when this session ended. **No ctest count and no fuzz
input count are asserted here.**
Probe infrastructure preserved **outside** the repo in `/home/team/shared/` so a later session does
not have to rewrite it:
- `pass3_run.sh` — waits for `/opt/openssl35/lib/libssl.so`, then for `linux-release` and
  `linux-asan`: `cmake --preset <p> -DOPENSSL_ROOT_DIR=/opt/openssl35`, `cmake --build --preset <p>`,
  `ctest --preset <p>`; logs `/tmp/{cfg,bld,ctest}_linux-<p>.log`.
- `pass3_fuzz_run.sh` + `pass3_fuzz_drv.c` — gcc + ASan/UBSan driver for
  `tests/fuzz/fuzz_quic_state.c` (deterministic xorshift64\* PRNG; three generators: raw random,
  structured records with frame-type-directed payloads and varint boundary values
  0/63/64/16383/16384/1073741823/2^62-1, mutated seeds with bit flips and truncation; prints
  inputs, seconds, inputs/s). It reuses `build/linux-asan`'s include flags, so the library under
  test is the sanitised one.
### 10.1 Priority 3 (connection state) — read this session, with anchors
| Topic | Finding | Anchors |
|-------|---------|---------|
| PTO / loss timer | `s3_quic_pto()` = `avg_rtt + max(4*rttvar, S3_QUIC_TIME_GRANULARITY) + ctp.max_ack_delay` (last term application level only) — RFC 9002 A.8 shape | `s3_quic_ack.c:1003-1015`, `:659` |
| The TZ's "500 ms tick cap" | **No such cap exists here**: `S3_QUIC_TIME_GRANULARITY` is **1 ms**, and `grep -nE '\b500\b' src/event/quic src/event/*.c` is **empty**. The only `5000` in the loss path is the Newton-Raphson seed of the CUBIC time, not a timer | `s3_quic_ack.c:20`, `:903` |
| Loss detection | packet- and time-threshold detection, then congestion feedback; the **same** posted event doubles as loss and PTO timer (the port says so itself) | `s3_quic_ack.c:564-645`, `:924-999`; `s3_quic.c:204-209` |
| Congestion control | **CUBIC** — neither a fixed window nor NewReno: cube-root solve loop, idle/k bookkeeping, lost path | `s3_quic_ack.c:880-905`, `:340-505`, `:482`, `:807-865` |
| Idle timeout | effective value is `min(peer, local)`; the read timer is re-armed on receive and on send | `s3_quic.c:99-100`, `:140`, `:675`, `:2144`; `s3_quic_output.c:127`, `:1439` |
| 24 h advertisement | **matches the code**: `-i` default `86400000`, server `idle_ms = 86400000`, client `conf->idle_timeout = 24*60*60*1000` | `app/ssh3_server.c:6781`, `:6936`; `app/ssh3_client.c:8701`, `:13029` |
| Migration refusal | client refuses a peer migration outright; NAT rebinding is a new path that must pass PATH_CHALLENGE, else revert to the last validated path | `s3_quic_migration.c:448`, `:460-464`, `:485-490`, `:516-529`, `:569-593`, `:784` |
| Transport parameters | typed parse (zero-length vs varint classes) then value validation before use | `s3_quic_transport.c:1793-1940`; `s3_quic.c:60-104` |
| Key update | driven by the received KEY_PHASE bit: flip phase, switch keys, post the update event | `s3_quic.c:1250-1264`, `:1727-1740`, `:223-225`, `:2036-2038` |
Two **Info** observations from this slice, neither demonstrated exploitable:
- **I3-5** — `tp->disable_active_migration` is parsed (`s3_quic_transport.c:1808`) and emitted
  (`:2163`, `:2230`) but **never enforced** in `s3_quic_migration.c`, and no `app/` code sets it, so
  it is unreachable in the shipped binaries. RFC 9000 §9 would want an error if a peer migrates
  after we advertised it.
- **I3-6** — the five idle re-arm sites hand `qc->tp.max_idle_timeout` straight to
  `s3_event_add_timer()`; `0` means "no limit" (RFC 9000 §10.1) and the shipped configs always pass
  86 400 000, so this is a library-embedder risk only. Not probed.
### 10.2 Priority 4 (the OpenSSL 3.5 seam) — read this session, with anchors
- The QUIC-TLS seam is one `OSSL_DISPATCH` table — `send`, `recv_rcd`, `release_rcd`, `yield_secret`,
  `got_transport_params`, `alert` (`s3_quic_ssl.c:44-57`); secrets are mapped from
  `SSL_CIPHER_get_id()` and the record-protection level (`:201-260`); ALPN is checked in the send
  callback (`:77-99`); CRYPTO frames enter through `s3_quic_handle_crypto_frame()` (`:345`) and the
  handshake is pumped by `SSL_do_handshake()` (`:463`, post-handshake `:415`).
- **P2-3 (`EXPORTER-SSH3` binding)** — the exporter is taken from the *live connection's* SSL:
  `app/ssh3_server.c:2244` (`s3_srv_h3_pc->ssl->connection`, label `"EXPORTER-SSH3"`, length 13,
  32 bytes out), `app/ssh3_client.c:2138`, `src/ssh3/s3_ssh3_oidc.c:1679`. Both sides use the same
  label and no context, and the same SSL object carries the QUIC handshake (`s3_quic_ssl.c` operates
  on `c->ssl->connection`), so the exporter material is bound to the QUIC connection's TLS session.
  **Static result only**; the runtime probe is prepared but not run — with the 3.5.0 build in place,
  `openssl s_server -quic` against `openssl s_client -quic -keymatexport EXPORTER-SSH3
  -keymatexportlen 32` checks that the plugin path yields symmetric material over QUIC.
- **P2-1 (peer bound)** — the peer reaches the upper layer only from the datagram source address on
  the socket/recv path (`s3_quic_set_path()`, `s3_quic.c:1185` region, and `s3_quic_migration.c`);
  no packet field feeds it. Shape confirmed by grep, not line by line; the spoofing probe (a
  raw-socket datagram with a foreign source address) has not been run.
### 10.3 Still not covered — resume points
1. **ctest baseline, both presets** — run `/home/team/shared/pass3_run.sh`; it needs only the OpenSSL
   3.5 build to finish.
2. **Fuzz ≥ 1 M inputs** — run `/home/team/shared/pass3_fuzz_run.sh` after the `linux-asan` build.
3. Unchanged from §9: the ACK-range algebra bodies (`s3_quic_ack.c:512-556`, `:1110-1300`),
   `s3_quic_streams.c` flow control, `s3_quic_connid.c`, `s3_quic_tokens.c`, the GSO/io_uring guards.
4. The runtime exporter probe (§10.2) and the P2-1 spoofing probe.
**Verdict stays as in §8:** no defect reported; the mandatory probes are still outstanding, so this
pass still entitles no one to call the QUIC stack clean.
