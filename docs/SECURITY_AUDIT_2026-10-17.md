# Security audit — ssh3-c (C17 rewrite)

Date (UTC): 2026-10-17
Audited revision: `52ac29339e797bee869dfe283f8163f17efe3c41` (`main`, "docs(plan): P8(1) — канон ключей запуска ssh2, матрица CLI-COMPAT, волны приведения")
Audit type: vulnerability-focused source review + local dynamic probes (gcc, ASan/UBSan).
**Report-only:** no source file in this repository was modified by this audit; the only change is this document.

## 1. Executive summary

This is a first, deliberately partial pass over a large C codebase (~50.5k LOC under `src/`, ~111k LOC including tests,
plus a vendored-style Go interop harness under `interop/quic-go/`). The review concentrated on the **wire path** because
that is where unauthenticated, peer-controlled bytes are first consumed:

* QUIC varint / SSHString primitives (`src/ssh3/s3_ssh3_wire.c`)
* channel message codecs (`src/ssh3/s3_ssh3_message.c`, `src/ssh3/s3_ssh3_channel.c`)
* control-master framing and payload decoders (`src/ssh3/s3_ssh3_cm.c`)
* SFTP frame codec (`src/ssh3/s3_ssh3_sftp_codec.c`)
* request envelope (`src/ssh3/s3_ssh3_request.c`)

**Result in the reviewed surfaces: no memory-safety defect was found.** The parsers in scope are written in a
consistently defensive style — bounds are checked before every read, the cursor is mutated only after a successful
parse, length prefixes are validated against the remaining buffer *before* any pointer arithmetic, and every decoder
that copies peer bytes into a fixed-size object validates the length first. Dynamic probing (four parser harnesses
under ASan+UBSan, ~160k inputs total) produced **no** sanitizer report in repository code.

What this report does contain is one **low-severity protocol-hardening gap** (§3, F-1) and a set of **informational
observations** (§3, I-1…I-3), all about invariants that the Go/Rust implementations in this project family enforce and
that the C port currently parses but does not act on. This is a conformance/robustness matter, not an exploitable
memory-safety issue.

The honest headline is therefore: **the wire parser is in good shape; the uncovered majority of the tree is not
covered by this pass** (see §6). The surfaces with the largest unexamined share of attacker-reachable code are the
HTTP/3 + QPACK stack (`src/h3/`, ~7.9k LOC), the JWT/OIDC auth paths (`src/ssh3/s3_ssh3_auth_jwt.c`,
`s3_ssh3_oidc.c`, ~3.0k LOC) and the QUIC transport/protection layer (`src/event/quic/`, ~11.7k LOC).

## 2. What was audited

### 2.1 Shape of the target

| Item | Value |
|---|---|
| Language / standard | C17 (`CMAKE_C_STANDARD 17`, `CMAKE_C_EXTENSIONS OFF`) |
| Build system | CMake ≥ 3.20 (`CMakeLists.txt`, `CMakePresets.json`); no Makefile |
| Binaries | `ssh3-server` (`app/ssh3_server.c`), `ssh3` client (`app/ssh3_client.c`), interop runners (`interop/interop_server.c`, `interop/interop_client.c`), `s3gso_bench`, 8 libFuzzer harnesses under `tests/fuzz/` |
| Roles | Both client and server (daemon + product client) |
| Tests | 30 unit-test binaries under `tests/` (~20k LOC) + `interop/*.sh` scenario scripts |
| QUIC/TLS stack | Own implementation on top of **system OpenSSL** (`find_package(OpenSSL 3.5 REQUIRED)`, `S3_HAVE_QUIC=1`); no vendored TLS and no vendored QUIC library |
| Crypto | OpenSSL only: HKDF/AEAD in `src/event/quic/s3_quic_protection.c`, TLS glue in `s3_quic_ssl.c` / `s3_ssl.c` |
| Third-party | `interop/quic-go/` is a separate Go module (`go.mod`, `module s3interop`) used only as an ietf-interop peer; not part of the C build |
| Maturity signals | Extensive `docs/` (wire spec `docs/SPEC-wire.md`, port plan `docs/PLAN.md`, dependency notes `docs/DEPS-QUIC.md`), dedicated DoS guard (`s3_ssh3_dos_guard.c`), jail tests, fuzz harnesses in-tree, `-Wall -Wextra -Werror` on the core target |

LOC inventory (`src/`, C only): 50 525. Largest files: `src/h3/s3_h3_parse.c` (6 027), `src/ssh3/s3_ssh3_sftp_cli.c`
(3 792), `src/event/quic/s3_quic_transport.c` (2 325), `src/event/quic/s3_quic.c` (2 162),
`src/event/quic/s3_quic_streams.c` (1 859), `src/ssh3/s3_ssh3_oidc.c` (1 693), `src/ssh3/s3_ssh3_sftp_srv.c` (1 651),
`src/ssh3/s3_ssh3_session_srv.c` (1 507), `src/event/quic/s3_quic_output.c` (1 505),
`src/ssh3/s3_ssh3_auth_jwt.c` (1 353), `src/ssh3/s3_ssh3_cm.c` (1 316).

### 2.2 Attack-surface map and what this pass actually read

Reachability order is taken from the code itself (not assumed): the SSH3 messages and the control-master (`S3CM`)
frames travel **inside** an HTTP/3 request/response body, i.e. they are only reachable after the QUIC handshake and the
HTTP/3 CONNECT has been established. The authenticator (`s3_ssh3_auth_srv.c` / `s3_ssh3_auth_jwt.c`) runs *before* the
session/channel layers. The order used for prioritisation was:

1. wire primitives — **reviewed**
2. channel/message codecs — **reviewed**
3. control-master framing + decoders — **reviewed**
4. SFTP frame codec — **reviewed** (frame layer and attrs codec only)
5. request envelope — **reviewed**
6. HTTP/3 + QPACK — **not reviewed** (spot-read only)
7. auth (password/pubkey/JWT/OIDC) — **not reviewed** (spot-read: `snprintf` sinks, `crypt` use)
8. session/PTY/exec — **spot-read** (env array build, exec argv build, exit-status path)
9. forwarding / SFTP server policy — **not reviewed**
10. QUIC transport, protection, migration, tokens — **not reviewed**
11. build / supply chain — **inspected** (OpenSSL ≥ 3.5 requirement, no vendored crypto, no network fetch at build time)

C-specific checks applied to every reviewed function: bounds on each `memcpy`/`memmove`/`cpymem`; peer-controlled
length fields before allocation or copy; signed/unsigned and `int`/`size_t` truncation in size arithmetic; use-after-free
in channel/conversation teardown; uninitialised reads; fixed buffers in wire parsing; non-literal format strings;
allocator-failure handling; unsafe-libc inventory.

## 3. Findings

| ID | Severity | Surface | Summary |
|---|---|---|---|
| F-1 | Low | channel handshake / data framing | Peer-advertised `maxPacketSize` is parsed and range-capped but never enforced on either the send or the receive path; no minimum floor, and `s3_ssh3_channel_chunk_size()` is currently dead code |
| I-1 | Info | control-master | `decode_control_op` accepts trailing bytes by design; op matching is length-exact, so a future opcode with a shared prefix is a footgun |
| I-2 | Info | session/exec | Environment and command strings are copied with correct bounds, but the env allow-list decision lives entirely in `s3_ssh3_session_srv.c`; there is no central "wire string → privileged sink" helper, so a future call site can bypass it |
| I-3 | Info | SFTP | Frame layer is well-bounded; per-user transfer budgets are not enforced in the codec layer, so any budget must exist in `s3_ssh3_sftp_srv.c` (not verified in this pass) |

### F-1 — `maxPacketSize` is parsed, capped, and then ignored (no floor, no enforcement)

**Where.** `src/ssh3/s3_ssh3_channel.c:74` (upper cap), `src/ssh3/s3_ssh3_channel.c:91-114`
(`s3_ssh3_channel_chunk_size`), `src/ssh3/s3_ssh3_message.c:93-100` (OPEN_CONFIRMATION `max_packet_size`).

**What.** The channel header decoder rejects a `max_packet_size` above `S3_SSH3_CHANNEL_MAX_PACKET_LIMIT`
(16 MiB, `src/ssh3/s3_ssh3_channel.h:31`) — that part is correct and is exactly the fix the Go port needed. But:

```c
size_t
s3_ssh3_channel_chunk_size(uint64_t max_packet_size, unsigned extended)
{
    ...
    if (max_packet_size <= overhead) {
        return 0;
    }
    return (size_t)(max_packet_size - overhead);
}
```

* there is **no floor**: a peer advertising `max_packet_size = 4` yields a chunk size of **1 byte** for plain data
  (3 bytes of frame overhead) and **0** for extended data;
* `grep -rn chunk_size src/ --include=*.c` returns **only the definition** — nothing in `src/` calls it, and
  `ch->max_packet_size` is written by the parser and never read again;
* the same is true of the OPEN_CONFIRMATION field (`s3_ssh3_msg_parse_open_confirmation` stores it; no consumer).

So today the value is inert: the sender never chunks to the peer's advertised size, and the receiver never rejects a
data message that exceeds it.

**Impact.** No memory-safety consequence at this revision. Two real consequences remain:

1. **Conformance/interop:** a peer that legitimately advertises a small `maxPacketSize` will receive data frames larger
   than its advertised limit; a strict peer may reset the stream. Conversely the local side will accept arbitrarily
   large data frames (up to the 1 MiB SSH3 frame cap) regardless of what it advertised.
2. **Latent DoS:** the moment `chunk_size()` is wired into the send loop as-is, any peer — including one only past the
   QUIC/HTTP-3 layer, before authentication is complete, since the channel header arrives on the handshake stream — can
   advertise `max_packet_size = 4` and force the sender to emit one-byte data frames. That is the same "peer-picked
   buffer size without clamp+floor" class that the Go implementation had to fix with `minPeerMaxPacketSize = 4096`.
   The C port kept the clamp (ceiling) but dropped the floor, and the floor is exactly what protects the sender.

**Exploit conditions.** None at HEAD (dead code). Post-wiring: any network peer that completes a QUIC handshake and
reaches the channel-open stage; no credentials required for the header itself. Who controls the bytes: the peer, in
`CHANNEL_OPEN`/`OPEN_CONFIRMATION` `maxPacketSize`.

**Recommendation.** Add the floor next to the ceiling, so both properties travel together with the parsed value:

```c
#define S3_SSH3_CHANNEL_MIN_PACKET_SIZE 4096u   /* parity with minPeerMaxPacketSize */

/* in s3_ssh3_channel_parse_header(), after the upper-bound check: */
if (max_packet_size < S3_SSH3_CHANNEL_MIN_PACKET_SIZE) {
    max_packet_size = S3_SSH3_CHANNEL_MIN_PACKET_SIZE;   /* or S3_ERROR, if strictness is preferred */
}
```

and clamp inside `s3_ssh3_channel_chunk_size()` itself (`if (max_packet_size < MIN) max_packet_size = MIN;`) so the
guarantee cannot be lost by a future caller. When the send path is wired, also reject inbound data messages whose
payload exceeds the value *we* advertised.

### I-1 — `decode_control_op` tolerates trailing bytes

`s3_ssh3_cm.c:299-320` reads a `u32` length, validates it against the remaining body and then ignores everything after
`op`. The comment says this mirrors the Go `decodeControlOp` contract, and the op comparison (`s3_cm_op_is`,
`s3_ssh3_cm.c:48`) is length-exact, so this is not exploitable. It is listed because it makes opcode dispatch
prefix-sensitive only by accident: any future switch on the first byte of `op` would accept `"check" + garbage`.
Recommendation: keep the tolerant read but document the exact-match requirement at the comparison helper, and prefer
a length+`s3_strncmp` table over a prefix test if the op set grows.

### I-2 — env/command handling is correct but the allow-list is not centralised

Spot-read of `src/ssh3/s3_ssh3_session_srv.c` (env array build around lines 150-200 and 360-395, exec argv build
around lines 790-810) shows correct size arithmetic (`n + 1`, `len + 1`, checked allocations, `NULL` termination of the
env vector) and a whitelist-style env filter rather than a negative list — this is the right shape and avoids the
`LD_PRELOAD`-style class entirely. The residual risk is structural: the decision "which env names may pass" is inline
in the session server, so a second consumer of `open_session` would have to re-implement it. Recommendation: lift the
allow-list into one function (e.g. `s3_ssh3_env_admit(name, value)`) used by every consumer, and unit-test it against a
`LD_*`/`BASH_ENV`/`PYTHONSTARTUP` corpus.

### I-3 — SFTP budgets are not in the codec layer

`s3_ssh3_sftp_codec.c:168-200` bounds every frame by `S3_SSH3_SFTP_MAX_FRAME` and refuses `length == 0` before reading
the type byte. Nothing in the codec enforces a per-user transfer budget, which means any such budget must live in
`s3_ssh3_sftp_srv.c`; that file was not reviewed here, so the "per-user budget no-op" class from the Go sibling
remains **unverified**, not cleared.

## 4. Verified clean (in scope, by reading)

* **QUIC varint decode** — `s3_ssh3_parse_varint` (`s3_ssh3_wire.c:44-76`): rejects a truncated prefix
  (`end - p < form`), reads exactly `form` bytes, and **enforces canonical encoding** (`form > varint_size(v)` →
  error), which also removes the "hostile over-long encoding" ambiguity class. The shift loop cannot overflow:
  `form ≤ 8` and the first byte contributes only 6 bits.
* **SSHString decode** — `s3_ssh3_parse_sshstring` (`s3_ssh3_wire.c:100-116`): length is compared against the remaining
  buffer **as `uint64_t` before** the pointer is advanced; no allocation is performed from the length; the resulting
  `s3_str_t` aliases the receive buffer (no copy, no borrow-after-free, because the frame buffer outlives the decode).
* **Channel header** — `s3_ssh3_channel_parse_header` (`s3_ssh3_channel.c:32-87`): frame type checked first, all values
  parsed into locals and committed only at the end (a failed parse leaves both cursor and channel untouched — the
  documented fix for the Go F-01 tail), `max_packet_size` capped at 16 MiB.
* **Message codecs** — `s3_ssh3_message.c`: `data`/`extended_data`/`open_failure`/`request` decoders are strict —
  a truncated payload is an error rather than a short success, and `parse_request` bounds `want_reply` with
  `end - p < 1` before dereferencing.
* **Control-master frame layer** — `s3_ssh3_cm_frame` (`s3_ssh3_cm.c:162-205`): magic (`S3CM`) and version checked
  before the length is read; `len > S3_SSH3_CM_MAX_FRAME` (1 MiB) rejected; the `S3_AGAIN` path (incomplete frame)
  runs **after** the magic check, so a hostile peer cannot make the server buffer unbounded garbage before validation;
  the subtraction `(end - p) - HEADER_LEN` is guarded by the preceding `>= HEADER_LEN` check, so no size_t underflow.
* **Control-master payload decoders** — `s3_cm_get_count` (`s3_ssh3_cm.c:116-128`) rejects a count larger than
  `remaining/4` *before* the loop, and `s3_ssh3_cm_decode_open_session` additionally enforces
  `n > S3_SSH3_CM_LIST_MAX` (64) against two `s3_str_t[64]` arrays — count-vs-capacity is consistent (no off-by-one:
  `n == 64` indexes `0..63`). `s3_ssh3_cm_decode_attach` (`:266-283`) requires `body->len == TOKEN_LEN + 1` before its
  `memcpy`, and validates the stream kind against an **allow-list** of two values, not a negative list.
* **Allocator-failure handling** in the reviewed paths is checked (`s3_palloc`/`s3_cm_buf_reserve` return `NULL` and
  are tested before use; `s3_cm_buf_reserve` re-derives `cap` from `len + need`).
* **Unsafe-libc inventory:** no `gets`, no `strcpy`, no `strcat`, no `alloca` anywhere in `src/`. `sprintf`-family use is
  limited to Nginx-derived `s3_sprintf`/`s3_snprintf` (bounded `last` pointer arithmetic, `src/core/s3_string.c`) and
  three `snprintf` sinks (`src/ssh3/s3_ssh3_auth_srv.c:322`, `src/ssh3/s3_ssh3_auth_jwt.c:1321`,
  `src/os/unix/s3_https_fetch.c:81,345,363`) — all with a literal format string and a size argument; the `%.*s` at
  `auth_jwt.c:1321` is guarded by `(int)user->len` on an SSHString bound far below `INT_MAX`.
* **`memmove` sites** audited for direction and length: `s3_ssh3_cm.c:692,1117,1275` (pending-buffer compaction after
  consuming `n` bytes, `*len` remaining), `s3_h3_table.c:373` (dynamic table eviction), `s3_quic_ack.c:1240,1330`
  (range-array insert/remove). Each length is derived from an already-validated count, not from a raw peer field.
* **Build/supply chain:** no vendored crypto, no code generation from network input at build time, OpenSSL ≥ 3.5 is a
  hard requirement (see §6 for the operational consequence), `-Wall -Wextra -Werror` on `s3core`.

## 5. Dynamic probes — exactly what was run

Environment: gcc (no clang/libFuzzer), OpenSSL **3.0.13** on the host.

1. **Full CMake build: not possible here.** `cmake -DCMAKE_BUILD_TYPE=Debug` fails at
   `CMakeLists.txt:361`: `find_package(OpenSSL 3.5 REQUIRED)` → *"Found unsuitable version 3.0.13, but required is at
   least 3.5"*. The QUIC crypto layer needs the OpenSSL 3.5 QUIC TLS API, which this host does not have. This is an
   environment limitation, not a defect; it is recorded because it bounds every dynamic claim below.
2. **Parser-subset build under sanitizers (succeeded).** Compiled with
   `gcc -std=c17 -D_POSIX_C_SOURCE=200809L -fsanitize=address,undefined -fno-omit-frame-pointer -g`:
   `src/core/{s3_string,s3_palloc,s3_buf,s3_log,s3_rbtree}.c`, `src/os/unix/s3_errno.c`,
   `src/ssh3/{s3_ssh3_wire,s3_ssh3_message,s3_ssh3_cm,s3_ssh3_channel,s3_ssh3_sftp_codec,s3_ssh3_forward_policy,s3_ssh3_request}.c`
   — 14 objects, zero compile errors/warnings of note.
3. **The repository's own fuzz harnesses, driven by a stand-in driver.** Four in-tree libFuzzer targets
   (`tests/fuzz/fuzz_wire.c`, `fuzz_message.c`, `fuzz_cm_frame.c`, `fuzz_sftp_frame.c`) were linked against the above
   objects plus a small local `main()` that feeds pseudo-random and semi-structured buffers
   (`ASAN_OPTIONS=detect_leaks=0`, `UBSAN_OPTIONS=print_stacktrace=1`). 40 000 iterations per harness
   (≈160 000 inputs; input sizes 0…4096, plus 0…63-byte structured `S3CM`-prefixed buffers).
   **Result: no AddressSanitizer or UndefinedBehaviorSanitizer report in repository code; all four exited 0.** The single
   UBSan line present in every log (`drv.c:17: index 35 out of bounds for type 'char [23]'`) is a bug in the *auditor's*
   driver (an index over a 23-byte literal), not in the target; it is reported here for completeness.
   `fuzz_forward_target` could not be linked (`s3_ssh3_forward_parse_target` unresolved — `s3_ssh3_forward.c` was not in
   the subset) and was **not** run.
4. **Not run:** the in-tree unit-test suite (blocked by the same OpenSSL 3.5 requirement), any live client/server
   session, any libFuzzer campaign (no clang), any ASan run of the QUIC/HTTP-3 paths, and any network interaction with a
   real peer. No live attacks were attempted.

## 6. Coverage and limitations

**Reviewed by reading (functional, line-by-line):** `s3_ssh3_wire.c` (full), `s3_ssh3_message.c` (full),
`s3_ssh3_channel.c` (header + chunk size), `s3_ssh3_cm.c` (frame layer, all payload decoders, dispatch skeleton,
session-table helpers), `s3_ssh3_sftp_codec.c` (frame layer + attrs codec), `s3_ssh3_request.c` (dispatch guard).
That is roughly **2.5k of 50.5k LOC** — about 5 % of `src/`, chosen to be the 100 % of the pre-auth-to-late-handshake
byte path that this session could actually justify.

**Spot-read only:** `s3_ssh3_session_srv.c` (env/exec/exit-status), `s3_ssh3_auth_srv.c` and `s3_ssh3_auth_jwt.c`
(format-string and buffer sinks), `s3_ssh3_sftp_codec.c` encode side, `CMakeLists.txt`.

**Not reviewed at all (the honest gap):**

* `src/h3/` — 7.9k LOC of HTTP/3 + QPACK parsing (`s3_h3_parse.c` alone is 6k). This is the **largest pre-auth
  attacker-controlled surface in the codebase** (HEADERS/QPACK decode happens before the SSH3 conversation exists) and
  it received no line-by-line review here.
* `src/event/quic/` — ~11.7k LOC: transport, frames, protection (AEAD/nonce), ack ranges, migration, conn-id, tokens.
  The AEAD/nonce handling and key-zeroization requirements of this audit were **not** verified.
* `src/ssh3/s3_ssh3_auth_jwt.c` (1.3k), `s3_ssh3_oidc.c` (1.7k), `s3_ssh3_oidc_client.c` (0.45k) — JWT/OIDC claim
  parsing (attacker-supplied base64/JSON) and the timing-safety of credential comparison / lockout policy.
* `src/ssh3/s3_ssh3_session_srv.c` (1.5k) and `s3_ssh3_session_cli.c` — PTY allocation, `window-change`, signal
  forwarding, fd lifecycle (`s3_ssh3_session_close_fds` was read but its aliasing argument not proven).
* `src/ssh3/s3_ssh3_sftp_srv.c` (1.65k) and `s3_ssh3_sftp_cli.c` (3.8k) — path resolution/jail, symlink handling,
  per-user budgets.
* `src/ssh3/s3_ssh3_forward.c`, `s3_ssh3_forward_policy.c`, `s3_ssh3_reverse.c` — forward-target policy, unrestricted
  target class.
* `src/ssh3/s3_ssh3_dos_guard.c` — the guard itself (its integration points were seen, not its logic).
* `app/`, `interop/`, `packaging/`, `bench/`.

**Consequences of the gaps.** Nothing in §3 or §4 should be read as a statement about the QUIC crypto layer, the
HTTP/3 stack, or the auth paths. In particular, the classes that bit the Go/Rust siblings most often — unbounded
allocation from peer length fields, unknown-message-type UB, slot leaks at auth/session boundaries, lexical+symlink
jail TOCTOU, unrestricted forward targets, timing-unsafe credential comparison — were **not** searched for in the files
listed above, and their status is unknown.

**Suggested order for a continuation:** (1) `src/h3/s3_h3_parse.c` QPACK header-block decode with the in-tree
`fuzz_h3_state` harness under ASan (needs clang, or a stand-in driver as used here); (2) `s3_quic_protection.c` AEAD
nonce construction + `s3_quic_tokens.c` address-token validation; (3) `s3_ssh3_auth_jwt.c` claim/length handling;
(4) `s3_ssh3_sftp_srv.c` jail resolution; (5) `s3_ssh3_forward_policy.c` allow-list semantics.

## 7. Notes for the maintainers (non-security)

* The OpenSSL ≥ 3.5 requirement makes sanitizer builds of the full tree (and therefore the `tests/` suite and the
  in-tree fuzzers) unreachable on mainstream distro toolchains today. A `S3_BUILD_PARSERS_ONLY`-style CMake option that
  builds the core + codecs without the QUIC/TLS link would make the existing fuzz harnesses usable under gcc + ASan and
  is the single highest-value change for future audits.
* `s3_ssh3_channel_chunk_size()` and the two `max_packet_size` fields are dead code at this revision. Either wire them
  (with the floor from F-1) or drop them; dead protocol invariants are indistinguishable from missing ones at review
  time.

## 8. Findings closure (2026-10-18)

Closed on `main` by the `fix/security-audit-1` wave (commits `d2787f7`…`0ad93b2`, merge `e4b45e7`), TDD (red first — 21 falling assertions — then green):

| ID | Disposition |
|----|-------------|
| F-1 | **Closed (hardened).** `S3_SSH3_CHANNEL_MIN_PACKET_SIZE 4096` now sits next to the 16 MiB ceiling (`s3_ssh3_channel.h`), the parity of the Go `minPeerMaxPacketSize` (`channel.go:168`). `s3_ssh3_channel_parse_header()` clamps a below-floor advertisement up to the floor (a clamp, not a refusal — the fork semantics; the ceiling refusal is unchanged), and `s3_ssh3_channel_chunk_size()` clamps its input into `[4096 … 16 MiB]` internally, so the guarantee cannot be lost by a future caller. Tests: seven below-floor advertisements (4095…0) parse to 4096, `chunk_size(4)` yields 4093/4092 (plain/extended), the ceiling case stays green (`tests/test_ssh3_channel.c`). The send/receive data-path enforcement stays deliberately unwired — exactly as this report defers it; the value remains data-inert, so the latent one-byte-chunk DoS class is closed at the source. Readers audit at closure time: no consumer of the peer-advertised value exists in `src/` (the header build paths only), and the OPEN_CONFIRMATION field has zero readers — dead by design until the send-path wiring lands (see §7). |
| I-1 | **Closed (documented + pinned).** The length-exact contract is now written at `s3_cm_op_is` (`s3_ssh3_cm.c`): the comparison must stay length-exact, a dispatcher must not evolve into a prefix switch, a growing op-set takes a (length, `s3_strncmp`) table. The pin test feeds the prefix-neighbour op `checkx` and asserts the ERROR verdict with no status dispatch (`tests/test_ssh3_cm.c`). |
| I-2 | **Closed (centralised).** `s3_ssh3_env_admit(name, value)` is the single allow-list decision point (`s3_ssh3_session_srv.{c,h}`); every environment build rides it — the `s3_ssh3_session_srv_env` quota path (the run-as block, the pty-req TERM, the SSH_AUTH_SOCK injection) and the LANG fallback envp. There is no second env builder in the tree: the sftp child inherits via fork without exec. The unit corpus refuses LD_PRELOAD/LD_LIBRARY_PATH/LD_AUDIT/BASH_ENV/ENV/PYTHONSTARTUP/PERL5OPT/GLIBC_TUNABLES/GCONV_PATH/IFS and their neighbours (including value-injection and case-shift shapes) and pins the TERM bound (1..64). LC_* intentionally ride the wholesale environ (documented at the gate). |
| I-3 | **Verified, no code change.** The per-user sftp budget is taken before the child fork: `s3_srv_sftp_budget_take` is the first check of `s3_srv_sftp_start` (`app/ssh3_server.c`), the refusal carries `SFTP-SRV-CAP-DENIED`, and the fork lives deeper in `s3_srv_sftp_chroot_start`; the knob is `--max-sftp-sessions-per-user` (S2-02). The e2e leg (`interop/security-pass2-e2e.sh`) drives two parallel 128 MiB puts under the cap of 1 and greps the marker. A per-transfer byte budget has no sshd analog — parity not required (PLAN). |

Closure evidence: ctest 42/42 on `linux-release` and `linux-asan`; `fuzz_wire` 5.6M runs and `fuzz_message` 2.2M runs on `linux-fuzz` — zero findings; e2e `s3cm` / `cli-compat` / `security-pass2` green. The §6 coverage gaps (HTTP/3 + QPACK, the QUIC transport/protection layer, the JWT/OIDC internals) remain the R2 scope on frozen code.

---
Prepared as a report-only audit. No repository code was modified.
