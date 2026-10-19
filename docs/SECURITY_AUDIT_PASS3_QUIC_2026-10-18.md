# Security audit — ssh3-c (C17) — PASS 3 — the QUIC stack (`src/event/quic/*`)

- **Date (UTC):** 2026-10-18
- **Auditor:** team "Wasm Tunnel" (audit delegation)
- **Repository:** `nagual2/ssh3-c`
- **Audited HEAD / baseline of this pass:** `main @ 9a92a545`
- **Pass-3 TZ (authoritative spec):** `docs/SECURITY_AUDIT_TZ_QUIC_STACK.md` (10 108 bytes; sha1 `fa8476804008499d3acb6abe3e52c265b496c19b` taken from `origin/main`; the TZ's own "sha 9c7c75c1" is a different digest of the same 10 KB file)
- **Pass-1 report:** `docs/SECURITY_AUDIT_2026-10-17.md`; **pass-2 report:** `docs/SECURITY_AUDIT_PASS2_2026-10-18.md`
- **Deliverable:** this document is report-only (TZ §7, precedent pass-2 §10). Any defect found is fixed on a separate `fix/pass3-quic*` branch with its own test and PR; this branch carries no code change.

> **STATUS — PARTIAL, and deliberately so.** This is the first slice of pass 3: the inventory,
> the change-set map, priority 1 (pre-auth parsing) read to the end with anchors, the frame
> parser of priority 2, and the probes *prepared*. The probes could **not be executed** in this
> session (reason in §4) and priority 3/4 plus the DoS accounting are **not read** (§9). The
> verdict in §8 says what that does and does not entitle anyone to claim.

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

### 3.4 Priority 3 — connection state (TZ §3.4) — **not read** (§9)

Only touched incidentally: `s3_quic.c:1256` key switch on key phase. Loss/PTO, the 500 ms tick
cap's effect on PTO, spurious-retransmit logic, congestion control, idle timeout vs the advertised
24 h / `--max-idle-timeout`, migration refusal, and transport-parameter validation are **not read**
and no statement is made about them.

### 3.5 Priority 4 — the OpenSSL QUIC API seam (TZ §3.5) — **not read** (§9)

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

### 4.2 ctest baseline (TZ §6: 42/42 `linux-release` and 42/42 `linux-asan`)

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
