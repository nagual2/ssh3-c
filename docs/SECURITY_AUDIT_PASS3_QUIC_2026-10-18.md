# Security audit — ssh3-c (C17) — PASS 3 — the QUIC stack (`src/event/quic/*`)

- **Date (UTC):** 2026-10-18
- **Auditor:** team "Wasm Tunnel" (audit delegation)
- **Repository:** `nagual2/ssh3-c`
- **Audited HEAD (baseline of this pass):** `main @ 9a92a545` (tag `v0.4.1` + the pass-3 TZ commit `743eba6` and `349bde9`/`9a92a54` docs)
- **Pass-3 TZ (authoritative spec):** `docs/SECURITY_AUDIT_TZ_QUIC_STACK.md` (10 108 bytes, sha1 `fa8476804008499d3acb6abe3e52c265b496c19b` on `origin/main`)
- **Pass-1 report:** `docs/SECURITY_AUDIT_2026-10-17.md`; **pass-2 report:** `docs/SECURITY_AUDIT_PASS2_2026-10-18.md`
- **Deliverable:** this document is report-only (TZ §7, precedent pass-2 §10). Every defect found here is fixed on a separate `fix/pass3-quic*` branch with its own test and PR; the report branch carries no code change.

> STATUS: work in progress. Sections are filled in and pushed incrementally (§ discipline of the delegation). Anything not finished is stated in §9 rather than guessed at.

## 1. Scope and method

Third pass on the C17 rewrite, on the layer both previous passes explicitly left unread
("the largest unread block"): `src/event/quic/*` — the transport ported from the nginx 1.31 QUIC
module, with TLS/crypto through the OpenSSL 3.5 QUIC API. Reading order is the TZ §3 priority
order: pre-auth parsing → RFC 9000 frames → connection state → the OpenSSL QUIC API seam →
pre-auth DoS state.

Method: static review with `file:line` anchors (grep-directed reading, nothing inherited from
pass 1/2 without a re-check) **plus the mandatory probes of TZ §4** — a stateful parser fuzz
harness under ASan+UBSan, and the `ctest` baseline in both configurations. Every claim below is
either read in the audited tree or confirmed by a probe; the report separates
"утверждено статикой" from "подтверждено пробами". Everything unread goes to §9.

## 2. Change-set map: pass-2 baseline `5bb540c` → `9a92a545`

<!-- TODO -->

## 3. Reading by priority (TZ §3.2–3.4)

### 3.1 Inventory of `src/event/quic/*` (TZ §3.1)

<!-- TODO -->

### 3.2 Priority 1 — pre-auth parsing

<!-- TODO -->

### 3.3 Priority 2 — RFC 9000 frames

<!-- TODO -->

### 3.4 Priority 3 — connection state

<!-- TODO -->

### 3.5 Priority 4 — the OpenSSL QUIC API seam

<!-- TODO -->

### 3.6 DoS / pre-auth state

<!-- TODO -->

## 4. Probes (TZ §4)

### 4.1 Fuzz harness on the packet parser (stateful, ASan+UBSan)

<!-- TODO -->

### 4.2 ctest baseline, both configurations

<!-- TODO -->

## 5. Regression probes for the pass-2 raised-priority items (TZ §7)

- P2-1 peer bound introduced from the QUIC layer (bound taken from the packet header).
- P2-3 replay / `EXPORTER-SSH3` binding to the connection.

<!-- TODO -->

## 6. Findings

<!-- TODO: F3-x / Info table, severity, subject -->

## 7. Fix branches

<!-- TODO: fix/pass3-quic*, TDD, ctest both configs, PR URLs -->

## 8. Verdict

<!-- TODO: memory-safety defect found / not found + residual risk list -->

## 9. Coverage, limitations, not covered

<!-- TODO: honest not-covered list with the order of the next pass -->
