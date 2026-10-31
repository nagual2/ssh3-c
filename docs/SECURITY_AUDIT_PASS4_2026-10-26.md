# Security audit — ssh3-c (C17) — PASS 4 — the protocol delta (`98010768` → `53baa2e`, v0.5.6)

- **Date (UTC):** 2026-10-26
- **Auditor:** team "Wasm Tunnel" (audit delegation A of the pass-4 sequence)
- **Repository:** `nagual2/ssh3-c`
- **Baseline of this pass:** `98010768` (2026-10-18, the commit the pass-3 report's closure wave starts from — `docs/plan`: F3 unfrozen)
- **Audited HEAD:** `53baa2e` (2026-10-31, tag `v0.5.6`, `origin/main`)
- **Delta:** 119 commits, **129 files, +15 522 / −1 048**
- **Previous reports:** pass-1 `docs/SECURITY_AUDIT_2026-10-17.md`, pass-2 `docs/SECURITY_AUDIT_PASS2_2026-10-18.md`, pass-3 `docs/SECURITY_AUDIT_PASS3_QUIC_2026-10-18.md` (HEAD `9a92a545`)
- **Deliverable:** this document. Pass-4 is ordered by the owner as a **full** security check of the updated tree ("the protocol changed"); the delegation is split — this session is **(A) the audited baseline: delta recon, probe plan, and the executed probes (§3)**. The line-by-line protocol-delta review and the runtime/app-layer review are the later delegations and read §1 as their map. A defect found here is fixed on a `fix/pass4-*` branch with its own test and PR; this branch carries no code change.

> **STATUS — the baseline half of pass 4 is complete.** §1 is the classified inventory of the
> whole delta, §2 the probe plan, §3 the executed probes (both ctest presets, the nightly repro,
> the pass-3 QUIC-state driver re-pointed at the new tree, the new in-tree `fuzz_h3_parse`
> target). The verdict, the residual-risk list and the per-area line-by-line review are the
> later delegations' sections and are deliberately not written here.

---

## 1. The delta inventory, classified by security relevance

### 1.1 The wave in one paragraph

The 119 commits are not a refactor: they **change the wire and the trust model**. Four new
protocol mechanisms land (TLS session resumption with early-data advertisement, the QPACK
encoder-side dynamic table, channel-body compression with its own message type and its own
version-string capability token, per-hop OIDC for the jump chain), two CLI trust switches land
(`-insecure`, `-strict-host-key-checking`), one RFC conformance bug is fixed by *removing* a
gate (unknown peer uni streams), and the sftp jail is rebuilt around a descriptor-pinned
`chroot` with a permanent privilege drop. Around that, the packaging story is finished
(deb/rpm/apk/openwrt), a nightly fuzz workflow appears, and the test tree roughly doubles
(7 new test files, 10 new interop scripts). `src/h3/s3_h3_parse.c` is the one file where the
nightly fuzzer has already found a live defect (**FZ1**, §1.3) — it is open at HEAD.

Counting by classification:

| Class | Commits | Files | Lines (+/−) |
|---|---:|---:|---:|
| (a) protocol changes | ~28 | 34 | ~+5 100 / −260 |
| (b) memory-safety-adjacent | ~12 | 18 | ~+1 500 / −180 |
| (c) packaging / CI / portability / docs | ~60 | 55 | ~+6 700 / −400 |
| (d) tests (unit + interop + fuzz) | ~19 | 22 | ~+2 200 / −200 |

The classes overlap by design (a test commit carries protocol tests); the split below is by
**what a reviewer must read**, not by commit.

### 1.2 (a) Protocol changes — read first

#### (a1) TLS session resumption and early data, stage 1 — `4e42d5b`

| File | What changed |
|---|---|
| `src/event/quic/s3_ssl.c:160-161` | server: `SSL_CTX_set_session_cache_mode(SSL_SESS_CACHE_SERVER)` + `SSL_CTX_set_max_early_data(16384)` — tickets ride the internal server cache, 16 KiB of early data is advertised |
| `src/event/quic/s3_ssl.c:195-215` | client: new-session callback stores the **newest** ticket in `s3_ssl_t::stored_session` (per process, no host key, no expiry) |
| `src/event/quic/s3_ssl.c:263-264` | client ctx: `SSL_SESS_CACHE_CLIENT \| SSL_SESS_CACHE_NO_INTERNAL_STORE` + the callback |
| `src/event/quic/s3_ssl.h:49-56` | the new `SSL_SESSION *stored_session` field (ownership: the conf, freed where?) |
| `src/event/quic/s3_quic_ssl.c:665-666` | server: any ctx with `max_early_data` arms `SSL_set_quic_tls_early_data_enabled(c, 1)` on **every** connection |
| `src/event/quic/s3_quic_ssl.c:709-711` | client: with a stored ticket, `SSL_set_session()` + early-data enable before `SSL_set_connect_state` |
| `app/ssh3_server.c:2656-2664` | the **425 gate**: a CONNECT that arrives before `pc->ssl->handshaked` is answered `425 Too Early` (RFC 8470) |

**Security questions this raises.**

1. **Replay window.** `SSL_OP_NO_ANTI_REPLAY` appears nowhere and there is no application-side
   replay store (`grep -rn "anti_replay\|NO_ANTI_REPLAY"` → only the `max_early_data` lines).
   The only replay defence is the 425 gate at `app/ssh3_server.c:2656`: no CONNECT is *processed*
   before the handshake completes. That is a correct posture **for stage 1** (the client does not
   put a CONNECT in the early flight yet), but it means the property "auth never rides early
   data" is enforced by a single `if` in the app layer, not by the transport. Any later stage-2
   commit that lets a CONNECT ride the early flight must not lose it. **Question for the
   reviewer:** is `pc->ssl->handshaked` provably false for every early-data request, on every
   path (including the request-data and uni-stream machines, not only the CONNECT handler)?
2. **Anti-replay store.** OpenSSL's internal replay filter is only effective while the ticket is
   in the *internal* cache; the server ctx now uses `SSL_SESS_CACHE_SERVER` (internal store on),
   so the filter exists, but its bound (`SSL_CTX_sess_set_cache_size`, default 20 480) and its
   lifetime are unexamined in this tree. **Question:** with the default cache size, what is the
   memory ceiling of a ticket flood, and does eviction *re-open* the replay window?
3. **Early-data bound.** 16 384 is advertised and `SSL_CTX_get_max_early_data()` gates the
   enable; the read path's enforcement (`SSL_get_early_data_status`, the QUIC-level
   `max_early_data_size` transport parameter) is not visible in this delta. **Question:** where is
   the *received* early-data volume bounded — TLS layer, QUIC 0-RTT packets, or nowhere?
4. **Ticket scope.** The client store is per-process and **not keyed by host**. A jump chain
   (`-J`) dials several hosts through one `s3_ssl_t` conf; the ticket of hop *N* can be offered
   to hop *N+1*. A server will reject a foreign ticket, so this is not a compromise, but it is a
   **privacy** question (a resumption attempt reveals "this client talked to host X") and a
   correctness question (the newest-ticket-wins policy is last-hop-wins).
5. **The callback's ownership.** `s3_ssl_client_new_session_cb` frees `stored_session` then
   stores the new one. If OpenSSL ever hands back the same `SSL_SESSION *` (it does not today),
   that is a use-after-free. More concretely: **who frees `stored_session` at shutdown?** The
   delta adds no free in `s3_ssl_free()` — a leak per process, and a dangling pointer if the
   conf outlives the sessions.

#### (a2) QPACK encoder-side dynamic table (F2) — `6a0451e`

| File | What changed |
|---|---|
| `src/h3/s3_h3_table.c:860-905` | `s3_h3_enc_capacity()`: peer `SETTINGS_QPACK_MAX_TABLE_CAPACITY` sizes the encoder table (`capacity/32 + 1` pointers, pool) |
| `src/h3/s3_h3_table.c:910-965` | `s3_h3_enc_insert()`: emits the capacity instruction on the first insert + an Insert-With-Literal-Name instruction, then copies the entry into the pool and bumps `insert_count` |
| `src/h3/s3_h3_table.c:967-1012` | `s3_h3_enc_lookup()`: the ack gate — only entries covered by `ack_insert_count` are referenceable; the relative index is measured from the ack top |
| `src/h3/s3_h3_table.c:1014-1040` | `s3_h3_enc_field()`: reference an acked entry, else insert + send a literal |
| `src/h3/s3_h3_table.c:408-460` | `s3_h3_ack_section()` no longer errors; `s3_h3_inc_insert_count()` now advances the encoder ack count and **clamps** an over-ack to `insert_count` and returns `DECODER_STREAM_ERROR` |
| `src/h3/s3_h3_encode.c:581-643` | the four new instruction encoders (capacity / insert-with-name-ref / insert-with-literal / duplicate) |
| `src/h3/s3_h3.h:79-93` | the session carries a second table (`encoder`) and `peer_capacity` |
| `app/ssh3_server.c:1962` | the response `Server:` field now rides `s3_h3_enc_field()` |

**Security questions this raises.**

1. **Unbounded write into a fixed stack buffer.** `s3_h3_enc_insert()` builds the instruction in
   `u_char buf[1024]` (`s3_h3_table.c:912`) and only afterwards checks
   `if (n > sizeof(buf))` (`s3_h3_table.c:952`). The primitives it calls
   (`s3_h3_encode_insert_literal` → `s3_cpymem`, `s3_h3_encode_string`) do **no** bounds
   checking; they support a `p == NULL` *measure* mode which the caller does not use. A field
   name+value pair over ~1 015 bytes therefore writes past `buf` on the stack **before** the
   check runs. Reachability: `s3_h3_enc_field()` is called from the server for the `Server:`
   field (constant) and from the client for its request fields — the client-side values are
   local (CLI) input, so this is a local-crash / potential code-execution primitive rather than a
   remote one, **unless** a later stage routes peer-influenced values through it. Class: memory
   safety, latent. **This is the first thing the line-by-line delegation should confirm and fix.**
2. **Table capacity can only grow.** `s3_h3_enc_capacity()` returns early when
   `capacity <= et->capacity` (`s3_h3_table.c:884`) but still updates `h3c->peer_capacity`. A
   second, smaller capacity (a second SETTINGS is a protocol error, so this is defence in depth)
   would leave entries the peer's decoder has evicted, and the relative-index math would then
   point at the wrong entry. **Question:** is SETTINGS-once enforced before this call?
3. **Entry-array bound.** `elts` is sized `capacity/32 + 1`; `nelts` grows one per insert and each
   insert is gated on `capacity - size >= entry_size` where `entry_size = name+value+32`. The
   arithmetic therefore holds **only if** the 32-byte overhead constant matches the accounting
   used by `s3_h3_enc_insert()` — verify by reading both.
4. **The ack gate.** The claim "no blocked streams, no BLOCKED_STREAMS accounting" rests on
   never referencing an unacked entry. `s3_h3_enc_lookup(..., acked_only=1, ...)` skips
   `k + 1 > ack_insert_count`; `s3_h3_inc_insert_count()` clamps an over-ack. **Question:** can a
   *stale* ack (from a previous connection's session state) survive into a new connection?
5. **`s3_h3_ack_section()` returning `S3_OK`** replaces a hard error. A Section Acknowledgment
   for a stream we never sent is now silently accepted — is that a state-confusion vector?

#### (a3) Unknown peer uni stream is discarded, not a connection error (B20) — `152ad9d`

| File | What changed |
|---|---|
| `src/h3/s3_h3_uni.c:146-160` | the **ordinal gate is gone** from `s3_h3_init_uni_stream()`: the `qs->id >> 2 >= S3_H3_MAX_UNI_STREAMS` check that finalized the connection is deleted (the macro `S3_H3_MAX_UNI_STREAMS` at `s3_h3.h:46` is now unused) |
| `src/h3/s3_h3_uni.c:252-268` | `s3_h3_register_uni_stream()` returns `S3_DECLINED` for an unknown type instead of `STREAM_CREATION_ERROR`, and the "mandatory trio first" order check for unknown types is dropped |
| `src/h3/s3_h3_uni.c:378-400` | the read handler switches to a discard handler and issues `STOP_SENDING` |
| `src/h3/s3_h3_uni.c:421-460` | `s3_h3_uni_discard_read_handler()`: drains into a 512-byte stack buffer in a `while (rev->ready)` loop |

**Security questions this raises.**

1. **Resource bound after the gate removal.** Nothing in the delta replaces the removed cap: the
   number of concurrent uni streams is now bounded only by the QUIC transport's
   `initial_max_streams_uni` (`S3_H3_MAX_UNI_STREAMS` is unused). **Question:** what is the
   advertised stream limit, and what does one discarded uni stream cost (connection object +
   pool) — is a `MAX_STREAMS`-driven churn loop a memory/CPU DoS?
2. **The drain loop.** `while (rev->ready) { recv(512) }` per read event, with the read event
   re-arming — is the loop bounded per event, and does `recv` returning `S3_AGAIN` clear
   `rev->ready`? An unbounded inner loop on a fast peer is a CPU pin.
3. **`us->discarded`** is set and never read again — dead state, or a missing guard in the
   close/free path?
4. **Conformance trade.** RFC 9114 §6.2 does forbid treating unknown types as a connection
   error; the fix is correct on its face. The question is purely the resource ceiling it removes.

#### (a4) Version-string negotiation — compression capability token

| File | What changed |
|---|---|
| `src/ssh3/s3_ssh3_version.c:159-232` | `s3_ssh3_version_parse()`: the extra-field loop is restructured; a `compress=<list>` field is parsed into `v->compress_mask` |
| `src/ssh3/s3_ssh3_version.c:233-270` | new `s3_ssh3_version_string()`: builds the base string plus the capability field, with a two-stage capacity check |
| `src/ssh3/s3_ssh3_version.h:54-63` | `s3_ssh3_version_t` gains `compress_mask`; the software version bumps to 0.5.6 |

**Security questions.** The parsed strings stay **zero-copy views** into the caller's buffer
(`spec_version`, and now the compress list) — the B1 lesson (field values must be pool copies)
was applied to the h3 parse path but *not* here. Is the version string buffer outlived by any
consumer? Also: the field-count cap `S3_SSH3_VERSION_FIELDS_MAX` and the `extra.len > key.len`
strictness (a bare `compress=` is now ignored rather than matching) — confirm both are
intentional.

#### (a5) OIDC jump chain — per-hop flows — `28109f4`

| File | What changed |
|---|---|
| `src/ssh3/s3_ssh3_oidc_client.c` (+52/−…) | the OIDC flow runs **per hop**, the `-J` gate is lifted |
| `src/os/unix/s3_https_fetch.c` (+20/−…) | the fetch seam for the per-hop token exchange |
| `app/ssh3_client.c` | the jump chain drives the per-hop auth |

**Security questions.** (1) **Token scoping:** is a token minted for hop *N* ever presented to
hop *N+1*, and is the *audience* of each token checked against the hop it is used on? (2)
**Redirect handling** in `s3_https_fetch.c`: does the fetch follow redirects (and to what
origins), and is the TLS peer of the token endpoint verified (it is a *different* trust anchor
from the ssh3 node)? (3) Where does the token live in memory (zeroised after use?).

#### (a6) `-insecure` and `-strict-host-key-checking` — `acfe83c`

| File | What changed |
|---|---|
| `app/ssh3_client.c:13149-13156` | the `-insecure` flag |
| `app/ssh3_client.c:3757-3850` | the `-o insecure` / `-o strict-host-key-checking=` forms (the `-o` mechanics beat `-F` config) |
| `app/ssh3_client.c:4044-4056` | `s3_cli_cert_check_conn()`: **`-insecure` returns `S3_OK` before any check** |
| `app/ssh3_client.c:4160-4180` | the unknown-host policy: `yes` refuses at once, `no` accepts without a pin write, `accept-new` is the TOFU default |
| `app/ssh3_client.c:1275,1311-1320` | usage text |

**Security questions.** **What `-insecure` actually bypasses:** the whole `s3_cli_cert_check_conn()`
— i.e. the TOFU pin store (`~/.ssh3/known_hosts`) *and* the "changed certificate" detection.
What it does **not** bypass: nothing else in the delta — the TLS chain was already unverified by
design (the pin *is* the trust anchor), so `-insecure` removes the only MITM barrier there is.
Two follow-ups: (1) `-o insecure yes` in a **config file** silently disables the barrier for
every subsequent session — is that reported to the user? (2) Does `-insecure` apply to **every
hop** of a jump chain (the global is process-wide), i.e. does it silently widen trust for hops
the user did not name?

#### (a7) Channel-body compression, the `--password` split, the positional `--sftp` — `906d73f`

| File | What changed |
|---|---|
| `src/ssh3/s3_ssh3_compress.c` (new, 832) | deflate/lz4/zstd one-shot and per-channel-context codecs, the capability parse/format, the algorithm chooser |
| `src/ssh3/s3_ssh3_compress.h` (new, 197) | the contract: `S3_SSH3_COMPRESS_MAX_OUTPUT` = 16 MiB (the "bomb limit"), per-frame independent units, the ZFS cutoff |
| `src/ssh3/s3_ssh3_frame.c` (new, 173) | the plain (94) and compressed (192) channel-data frame builder/parser; `decode_mask` = what *this* side announced, fail-closed on an unannounced id |
| `src/ssh3/s3_ssh3_message.c/.h` | the `S3_SSH3_MSG_CHANNEL_DATA_COMPRESSED` (192) encode/parse |
| `src/ssh3/s3_ssh3_version.c` | the capability token (a4) |
| `src/ssh3/s3_ssh3_session_cli.h:54-62` | the decode context and the 1 MiB decode scratch (pool) |
| `app/ssh3_client.c`, `app/ssh3_server.c` | compression **default in both directions**, `--password` split out of the positional, positional `--sftp` |

**Security questions.**

1. **Cross-request leakage posture.** The design claims per-frame independent units (a fresh
   deflate/zstd block per channel-data message, no shared dictionary), which removes the
   classic CRIME/BREACH "compression oracle across requests" surface *if* the per-frame reset is
   real. **Question:** does `s3_ssh3_compress_ctx_decode()`/`_encode()` fully reset the codec
   state between frames (`deflateReset` / `ZSTD_*_reset`), and is the *decompressor's* window
   (which is attacker-controllable state) reset too? A stale window is a data-leak vector even
   without an oracle.
2. **Bomb limit.** `cap > S3_SSH3_COMPRESS_MAX_OUTPUT` clamps to 16 MiB
   (`s3_ssh3_compress.c:551-552`, `:743-744`) — but the clamp is on the **caller's buffer
   capacity**, not on the decoder's output bound. If the caller's scratch is smaller than the
   expansion, is the codec told the true limit (`avail_out`) or is the truncation detected only
   afterwards?
3. **Negotiation downgrade.** The token rides the version string, which is unauthenticated in the
   pre-auth phase. An active attacker can strip `compress=` → both sides fall back to plain. That
   only costs ratio, not confidentiality — **unless** a later stage makes compression a
   precondition for something else.
4. **`--password` split.** The password now has its own option; is it still accepted positionally
   (argv is world-readable in `/proc/*/cmdline`), and is it zeroised after use?
5. **The 192 frame on a plain channel** must be a protocol error (the header says so) — confirm
   the server tears the channel down rather than ignoring it.

#### (a8) sftp: positional `--sftp` (same commit `906d73f`) — see also (b1)

The option parser moves `--sftp` to a positional form. **Question:** does the new form widen the
argument surface (an arbitrary path becoming a command), and does it preserve the
"no jail → refuse" fail-closed rule?

### 1.3 (b) Memory-safety-adjacent changes

#### (b1) The sftp jail delta — `6946c03` (+142/−…, `src/ssh3/s3_ssh3_sftp_jail.c`)

| Anchor | What changed |
|---|---|
| `s3_ssh3_sftp_jail.c:186-220` | `s3_ssh3_sftp_jail_fchroot()`: `chroot("/proc/self/fd/<n>")` so the chroot lands on the **inode** the descriptor names; a `/proc`-less fallback goes back to the path spelling |
| `s3_ssh3_sftp_jail.c:222-280` | `s3_ssh3_sftp_jail_enter()`: `open(jail, O_RDONLY\|O_DIRECTORY\|O_NOFOLLOW\|O_CLOEXEC)` pins the root, then `fchdir(fd)` → fchroot → `chdir("/")`, then the drop |
| `s3_ssh3_sftp_jail.c:283-330` | `s3_ssh3_sftp_jail_drop()`: `setresgid`/`setresuid` all three ids; the non-`SETRESUID` fallback re-probes with `seteuid(0)` (must fail) |
| `s3_ssh3_sftp_jail.c:334-350` | `s3_ssh3_sftp_jail_lexical_check()`: a root daemon may not serve the lexical (non-chroot) mode — `S3_DECLINED` |

**Security questions.** (1) The `/proc`-less fallback (`access("/proc/self/fd", X_OK)` → path
spelling) reintroduces the swap window — is the fallback reachable on a supported platform, and
is it logged? (2) `initgroups()` still runs **before** the chroot (it must, it reads
`/etc/group`) — the OpenSSH order; confirm no path resolution happens between the `open` and the
`chroot`. (3) The `seteuid(0)` re-probe is a *test*, and on a misconfigured kernel a failing
`seteuid(0)` is indistinguishable from a successful drop — acceptable, but record it. (4)
`lexical_check` returns `S3_DECLINED` for euid 0 — **who calls it, and does the caller fail
closed** on `DECLINED`? (5) The `_GNU_SOURCE`/`_DEFAULT_SOURCE` dance moved the TU's feature
surface; confirm no other file inherits it.

#### (b2) The cmsg / local-address path — `b0ceb9e`, `6472e4a` (+77/−…, `src/os/unix/s3_cmsg.c`)

| Anchor | What changed |
|---|---|
| `s3_cmsg.c:54-100` | `s3_set_srcaddr_cmsg()` now **sets** `cmsg_level`/`cmsg_type` itself and picks them from `sockaddr->sa_family` (the caller only reserves space) |
| `s3_cmsg.c:102-160` | new `s3_enable_pktinfo()`: sets `IP_PKTINFO`/`IPV6_RECVPKTINFO` on a wildcard listener |
| `src/event/quic/s3_quic_output.c:506-545`, `:797-825` | the two send paths, the reserve sizes |
| `src/event/s3_event_udp.c:106-130` | the receive path's control buffer |

**Security questions.** The reserve/emit contract is now split across two files. Checked during
recon: `s3_addrinfo_t` (`s3_cmsg.h:17-24`) is a struct of `in_pktinfo` (12 B) and `in6_pktinfo`
(20 B) → `sizeof = 20`; `s3_set_srcaddr_cmsg()` returns `CMSG_SPACE(12)` = 28 for v4 and
`CMSG_SPACE(20)` = 36 for v6, while the callers reserve `CMSG_SPACE(sizeof(s3_addrinfo_t))` = 36
plus, at `s3_quic_output.c:506`, an extra `CMSG_SPACE(sizeof(uint16_t))` = 18. **The sizes are
consistent** — but the invariant is now implicit (the caller's reserve must track the callee's
family choice). Note as an observation: the family is decided by `c->local_sockaddr`, which the
`6472e4a` fix populates from the pktinfo — a wrong family here means a silently dropped
ancillary message, not a corruption.

#### (b3) The h3 parse layer and the nightly finding (FZ1) — open at HEAD

| Anchor | What |
|---|---|
| `src/h3/s3_h3_parse.c:4784-4880` | `s3_h3_parse_literal()` — the raw write branch `*st->last++ = ch` with the `pnalloc(n + 1)` reserve at `:4841-4846`, the terminator `*st->last = '\0'` at `:4872` |
| `src/h3/s3_h3_parse.c:4705-4782` | `s3_h3_parse_field_rep()` — the state dispatcher; `s3_memzero(&st->field, ...)` at `:4717` is the only reset of the literal sub-machine |
| `src/h3/s3_h3_parse.c:5184+` | `s3_h3_parse_field_lpbi()` — the post-base literal path of the CI trace |
| `docs/PLAN-CURRENT.md:121` | the row: **FZ1 — heap-buffer-overflow WRITE size 1, `s3_h3_parse_literal` via the post-base/literal path, `s3_h3_parse.c:4864`, 0 bytes after a 16 KiB pool block; nightly red since 28.10; state = agent (open)** |
| `tests/fuzz/repro/h3-parse-pool-overflow-2026-10-30.bin` | the 8-byte crashing input (`0c 01 ff 00 2c 00 01 3b`) |
| `tests/fuzz/fuzz_h3_parse.c` (new, 217) | the in-tree libFuzzer harness of the three parse machines (A3) |

**Security question.** A one-byte write past a pool block from a **pre-auth, peer-controlled**
parse path is a security-class defect (the plan says so itself: "класс = безопасность,
1-байтовая запись с провода"). It is **open at HEAD** — no commit in the delta touches
`s3_h3_parse.c` after the artifact was added (`git log 98010768..origin/main -- src/h3/s3_h3_parse.c`
is empty; the h3 commits are `s3_h3_uni.c`, `s3_h3_table.c`, `s3_h3_encode.c`). §3.2 is the
executed probe.

#### (b4) QUIC hardening of the pass-3 review — `12becc4` and the pass-3 fix wave

| Anchor | What changed |
|---|---|
| `src/event/quic/s3_quic_tokens.c:119-137` | `s3_quic_new_token()` refuses an `odcid` longer than `S3_QUIC_MAX_CID_LEN` (the plaintext is a fixed buffer) |
| `src/event/quic/s3_quic_tokens.c:304-320` | `s3_quic_validate_token()`: a token with no odcid **copies** the dcid into `pkt->odcid_buf` instead of aliasing the packet buffer; an over-long dcid is `bad_token` |
| `src/event/quic/s3_quic_connid.c:352-358` | `s3_quic_free_client_id()` no longer underflows `nclient_ids` |
| `src/event/quic/s3_quic_transport.c:1805-1815`, `:1880-1890` | `disable_active_migration` and `initial_max_streams_bidi` are documented as parsed-not-enforced |

**Security questions.** These are the pass-3 findings' fixes; they read correctly. Two notes for
the reviewer: (1) `disable_active_migration` is *parsed and not enforced* — a peer that migrates
after advertising it is not answered with an error (the comment says nginx does the same). That
is a **residual risk**, not a defect: it means our own advertisement of the flag is advisory.
(2) `initial_max_streams_bidi` of 2^62 is accepted — the comment argues flow control bounds the
memory; the reviewer should confirm the stream-table growth is actually gated on flow control
credit and not on the peer's number.

#### (b5) Small quic deltas

`src/event/quic/s3_quic.c` (+72), `s3_quic_ack.c` (+19), `s3_quic_output.c` (+18),
`s3_quic_streams.c` (+15), `s3_quic_connection.h` (+7), `src/event/s3_event.h` (+7),
`src/event/s3_event_udp.c` (+22), `src/os/unix/s3_errno.c` (+39). Mostly the local-address path
(b2) and the pass-3 fixes (b4); `s3_errno.c` is the musl/`__GLIBC_PREREQ` portability shim
(c-class). The reviewer should read `s3_quic_streams.c` and `s3_quic_output.c` for the
`MAX_STREAMS`/`STOP_SENDING` plumbing that (a3) now depends on.

### 1.4 (c) Packaging, CI, portability, docs — low priority

| Group | Files |
|---|---|
| CI | `.github/workflows/build-release.yml` (180), `.github/workflows/debian-package.yml` (2), **`.github/workflows/fuzz.yml` (86, new — the nightly fuzz that found FZ1)** |
| Build system | `CMakeLists.txt` (107 — the `S3_BUILD_FUZZ` option and the harness targets), `CMakePresets.json` (15 — the `linux-fuzz` preset), `cmake/aarch64-linux-gnu.cmake` (51, new) |
| Packaging | `packaging/build.sh` (252), `packaging/apk/*` (APKBUILD, PKGINFO, initd/confd — new), `packaging/openwrt/*` (Makefile + files), `packaging/rpm/*` (the fedora spec, REVIEW.md, the debug-package fix `db4bd85`), `packaging/deb/*`, `packaging/debian/changelog` (+103) |
| Portability | `82ba1e4` (the `GLIBC_PREREQ` probe under musl), `docs/PORTING-illumos.md` (350, new), the arm64 cross preset |
| Docs | `SECURITY.md` (81, new — the disclosure policy), `docs/COEXISTENCE*.md`, `docs/BENCH-COMPRESS-*.md`, `docs/SPEC-wire.md` (+84 — **the wire spec of the new frame types, a review aid**), `docs/PLAN-CURRENT.md`, READMEs ×3, `man/ssh3-server.8` |
| Release | `8378ce9` (0.5.6), `f30948b`, `8285cf3`, `53baa2e` (the alpine tar), `d92063d` (0.5.1), `e0ff0a6` (0.5.0) |

**Security-relevant only in two places:** `.github/workflows/fuzz.yml` (what the nightly actually
runs, corpus handling, whether a finding fails the build — FZ1 shows the answer is "it went red
and stayed red") and the packaging **privilege** files: `packaging/openwrt/files/etc/init.d/ssh3-server`,
`packaging/apk/ssh3-server.initd`, `packaging/apk/ssh3-server.confd`, and the rpm/deb unit files —
these decide the daemon's user and its `-sftp` jail argument. Reviewers of the app layer should
read them; nothing in them is a protocol change.

### 1.5 (d) Test additions — the baseline's evidence

| File | Lines | What it pins |
|---|---:|---|
| `tests/test_ssh3_compress.c` | +731 (new) | the codecs, the capability token, the frame seam, the bomb limit |
| `tests/test_h3_qpack.c` | +326 | the encoder instructions, the ack gate, the roundtrip through the real parsers, the B1 copies |
| `tests/test_cmsg.c` | +313 (new) | the srcaddr cmsg for both families, `s3_enable_pktinfo` |
| `tests/test_ssh3_session_cli.c` | +205 (new) | the client session seams (compression decode, scratch) |
| `tests/test_quic_e2e.c` | +168 (new) | an end-to-end QUIC exchange |
| `tests/test_quic_idle.c` | +156 (new) | the idle timeout (the pass-3 fix `384a9a2`) |
| `tests/test_ssh3_dos_guard.c` | +143 (new) | the lockout table bounds (128-byte names, 4 096 records) |
| `tests/test_auth_ct.c` | +135 (new) | the constant-time compares |
| `tests/test_ssh3_reverse.c` | +133 | the reverse spec parse (printable gate, v6) |
| `tests/test_h3_parse.c` | +69 | the B1 field-lifetime pin |
| `tests/test_quic_tokens.c` | +51 | the odcid bound and the copy |
| `tests/test_event.c` | +43 | the pktinfo receive path |
| `tests/test_quic_ssl.c` | +16 | the resumption hooks |
| `tests/test_ssh3_sftp_jail.c` | +46 | the jail enter/drop/lexical |
| `tests/fuzz/fuzz_h3_parse.c` | +217 (new) | the harness of §3.2/§3.4 |
| `interop/*` | 10 new scripts | compress, conn-close, cross-reverse, go-server-channel, jump-chain-smoke, oidc, preauth-channel-gate, preauth-concurrent, sftp-halfclose, v6-target-smoke, client-opt |

**Note for the baseline:** the pass-3 report recorded **42/42** in both presets. The delta adds
14 test files/sections, so the pass-4 total is expected to be strictly larger — §3.1 records the
**actual** new totals, not the pass-3 baseline.

### 1.6 The five questions this pass exists to answer

1. **Does 0-RTT (a1) actually keep authentication out of the replay window** — is the 425 gate the
   only defence, and is it on every path?
2. **Is the QPACK encoder (a2) memory-safe on a long header value** — the check-after-write into
   `buf[1024]`?
3. **Does the B20 gate removal (a3) leave a bounded uni-stream resource ceiling?**
4. **Is the sftp jail (b1) confinement actually TOCTOU-free on the platforms we ship?**
5. **Is FZ1 (b3) fixed at HEAD** — and if not, what is the minimal fix that makes both presets and
   the fuzz target green?

---

## 2. Probe plan

The plan is fixed before the numbers, so §3 cannot quietly choose its own tests. Every probe runs
**detached** (`setsid nohup`, logs under `/home/team/shared/pass4/logs/`) and is polled — no probe
blocks the session (RULE A).

### 2.1 P-A — the ctest baseline, both presets

`cmake --preset linux-release|linux-asan -DOPENSSL_ROOT_DIR=/opt/openssl35`, build, then
`ctest --preset <p> --output-on-failure`. Record **per preset**: total, passed, failed, and the
names of any failures. The pass-3 baseline (42/42) is *not* assumed to hold.

### 2.2 P-B — the repro (the decisive probe)

`tests/fuzz/repro/h3-parse-pool-overflow-2026-10-30.bin` (8 bytes) through the h3 parse fuzz
target (`tests/fuzz/fuzz_h3_parse.c`), built per the repo's harness rules
(`CMakeLists.txt:500-509`: the harness is a libFuzzer target, `-fsanitize=fuzzer`, linked against
`s3core`). This machine has **gcc 13.3 and no clang**, so libFuzzer is unavailable; the harness is
re-hosted on a gcc + **ASan + UBSan** driver (`pass4_fuzz_drv.c`, the pass-3 pattern) that calls
`LLVMFuzzerTestOneInput()` — the harness body is unchanged.

Because `docs/PLAN-CURRENT.md:121` states the stand-reproducer needs the mutation history (the
table state accumulates across inputs), the probe runs in three escalating steps and records all
three honestly:

- **B1** the 8 bytes alone, fresh process;
- **B2** the 8 bytes repeated (the state the fuzzer had when it crashed — the harness keeps its
  session/table state across `LLVMFuzzerTestOneInput` calls within one process);
- **B3** a deterministic mutation loop seeded from the input (the pass-3 driver shape), 1 000 000
  iterations, ASan+UBSan, `abort_on_error=1`.

Verdict vocabulary: **FIXED at HEAD** / **STILL CRASHES**. A crash means DEFECT → `fix/pass4-h3pool`
with a failing ctest pin first, then the minimal fix, then green **both** presets, then a PR.
Also checked: whether the delta added a **ctest regression test** for the artifact
(`grep -rn "h3-parse-pool-overflow" tests/ CMakeLists.txt` → none at HEAD, which is itself a
finding: the artifact is committed but nothing pins it).

### 2.3 P-C — the pass-3 QUIC-state driver, re-pointed

`/home/team/shared/pass3/pass3_fuzz_run2.sh` + `pass3_fuzz_drv.c` against the new tree: rebuild
against `build/linux-asan`, `S3_FUZZ_ITERS=1000000`, ASan+UBSan. If the driver needs an API
update for the new `s3_h3_session_t` / encoder fields, the change is made **in the scratch copy**
under `/home/team/shared/pass4/`, never in `src/`. Record: inputs, wall time, inputs/s, findings.

### 2.4 P-D — the new in-tree `fuzz_h3_parse` target

The same harness, driven for ≥1 000 000 inputs (P-B/B3 supplies the count when the target is the
same binary); if the harness cannot take a count without libFuzzer, the maximum feasible run is
recorded with its exact iteration count.

### 2.5 Environment

Machine replaced again (the second time in this project): `/opt/openssl35` was gone, and
`/usr/local/bin/ninja` — pinned in the presets' cache — was **missing** (the first rebuild
attempt configured against a stale build tree and reported the *old* 42/42; that run is discarded
and not quoted). OpenSSL 3.5.0 is rebuilt from the upstream tarball with the proven
`build_ossl.sh` driver (`/home/team/shared/pass4/build_ossl.sh`), ninja is reinstalled
(`apt-get install ninja-build` + the `/usr/local/bin/ninja` symlink the preset expects), and both
build directories are wiped before the real configure. **A number produced against a stale build
tree is not a measurement** — this is why §3.1 quotes a fresh configure's totals.

---

## 3. Executed probes

### 3.1 P-A — ctest, both presets (the new totals)

**46 tests, 46 passed, 0 failed — in `linux-release` *and* in `linux-asan`.** The pass-3 baseline
was 42/42; the delta adds four ctest entries (the new test files fold into the existing binaries,
plus `test_quic_e2e` / `test_quic_idle` / `test_auth_ct` / `test_cmsg` / `test_ssh3_dos_guard` /
`test_ssh3_session_cli`). Logs: `logs/ctest2_linux-release.log`, `logs/ctest2_linux-asan.log`.

Codec detection on this build: `ssh3 compression codecs: zlib=1 lz4=1 zstd=1`
(`logs/cfg2_*.log`).

**Observation (test quality, not a defect):** the *first* run of this pass was **45/46 in both
presets**, `test_ssh3_session_cli` failing with
`FAIL tests/test_ssh3_session_cli.c:666: dec != NULL` /
`FAIL ...:623: enc != NULL`. The cause is environmental — this box shipped without
`libzstd-dev`/`liblz4-dev`, so `zstd=` was compiled out and
`s3_ssh3_compress_ctx_create(S3_SSH3_COMPRESS_ZSTD, ...)` correctly returned `NULL`. The test
**does not guard on `s3_ssh3_compress_available()`**, so any build without zstd fails ctest even
though the product is fine. Recorded as an observation: a portability pin
(`S3_ASSERT(s3_ssh3_compress_available() & S3_SSH3_COMPRESS_M_ZSTD) ? ... : skip`) would make the
suite honest on a codec-less build. After installing the codecs the same tree gives 46/46 with no
code change — the number quoted above is the real one.

### 3.2 P-B — the nightly repro (FZ1): **STILL CRASHES at HEAD**

The artifact `tests/fuzz/repro/h3-parse-pool-overflow-2026-10-30.bin` (8 bytes:
`0c 01 ff 00 2c 00 01 3b`) driven through `tests/fuzz/fuzz_h3_parse.c` on a gcc + ASan + UBSan
driver (`/home/team/shared/pass4/pass4_fuzz_drv.c`, the harness body unchanged — libFuzzer is
unavailable here, no clang on the box).

| Step | What | Result |
|---|---|---|
| **B1** | the artifact alone, fresh process, 1 call | **no report** — exit 0 (`logs/repro_b1.log`) |
| **B2** | the artifact replayed 1 000× in one process | **no report** — exit 0 (`logs/repro_b2.log`) |
| **B3** | the mutation campaign seeded from the artifact + generated HEADERS sections | **ASan abort**, exit 134, within the first 100 000 inputs (`logs/fuzz_h3_campaign.log`) |

**B1/B2 confirm the plan's own note**: the 8-byte artifact does *not* reproduce on its own — the
crash needs the parser/table state the fuzzer had accumulated (`docs/PLAN-CURRENT.md:121`). **B3
reproduces it, and the trace is byte-for-byte the one the plan recorded:**

```
==ERROR: AddressSanitizer: heap-buffer-overflow ... WRITE of size 1
    #0 s3_h3_parse_literal     src/h3/s3_h3_parse.c:4864   (*st->last++ = ch)
    #1 s3_h3_parse_field_lpbi  src/h3/s3_h3_parse.c:5244
    #2 s3_h3_parse_field_rep   src/h3/s3_h3_parse.c:4771
    #3 s3_h3_parse_headers     src/h3/s3_h3_parse.c:4583
0x... is located 0 bytes after 16384-byte region  (the pool's first block)
```

**Verdict: STILL CRASHES at `53baa2e`.** This is the **DEFECT** of pass 4 and it is fixed on
`fix/pass4-h3pool` (§3.3).

**Root cause (from the trace + the code).** `s3_h3_parse_literal()`'s `sw_start` reserves
`st->length + 1` bytes and then counts *down* in `sw_value`:

```c
if (--st->length) { break; }      /* s3_h3_parse.c:4861 */
```

`st->length` is unsigned. When the machine is entered with `st->length == 0` the pre-decrement
underflows to the type maximum, the loop never terminates on the countdown, and **every remaining
byte of the input is written past the one-byte reservation**. The callers each guard a zero
*field* length before calling, but the machine is re-entered with `st->length == 0` by a different
route: `s3_h3_parse_field_lpbi()` finishes the value literal (which resets the literal machine to
`sw_start` and leaves the countdown at 0), then the post-base table lookup fails
(`s3_h3_parse_lookup` → `S3_H3_ERR_DECOMPRESSION_FAILED`) **before** `st->state = sw_start` is
restored. The enclosing state therefore stays `sw_value`, and the next feed of the same buffer
(the fuzz harness's 4-round replay; in production, any reader that continues after a hard error)
re-enters the literal with a zero countdown. The write then walks to the end of the pool block.

**Why it is a security-class finding, and how far it reaches.** The write is pre-auth and
peer-driven *if* the reader ever re-enters the parser after a hard error. In the current product
the error tears the connection down, so the wire-reachability is bounded by that policy — but the
policy is a caller's promise, not an invariant of the machine, and the plan itself classifies the
item as security. The fix (§3.3) puts the invariant where it belongs: **a zero-length literal
completes at `sw_start`**, so no re-entry can underflow.

**Secondary finding:** the artifact is committed to the tree but **nothing pins it** —
`grep -rn "h3-parse-pool-overflow" tests/ CMakeLists.txt` finds no ctest regression test, and the
nightly fuzz job is the only thing that ever runs it. §3.3 adds the ctest pin.

### 3.3 The fix — `fix/pass4-h3pool`

*(TDD: the failing ctest first, then the minimal fix, then green both presets — see the branch.)*

### 3.4 P-C / P-D — the fuzz campaigns

| Campaign | Driver | Inputs | Result |
|---|---|---:|---|
| **P-D** `fuzz_h3_parse` (in-tree target, §3.2/B3) | `pass4_fuzz_drv.c` + `tests/fuzz/fuzz_h3_parse.c`, ASan+UBSan | died < 100 000 | **crash — FZ1** |
| **P-C** pass-3 QUIC-state driver, re-pointed at `53baa2e` | `pass4/pass3_fuzz_drv.c` + `tests/fuzz/fuzz_quic_state.c`, ASan+UBSan, `S3_FUZZ_ITERS=1000000` | see below | see below |

