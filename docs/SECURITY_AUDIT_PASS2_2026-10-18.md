# Security audit — ssh3-c (C17) — PASS 2

- **Date (UTC):** 2026-10-18
- **Auditor:** team "Wasm Tunnel" (audit delegation, report-only)
- **Repository:** `nagual2/ssh3-c`
- **Baseline of pass 1:** `main @ 52ac293`
- **Audited HEAD (this pass):** `main @ 5bb540c` (tag `v0.4.0`)
- **Pass-1 report:** `docs/SECURITY_AUDIT_2026-10-17.md` (PR #1, merged twice: `682db6b`, `58cc748`)
- **Deliverable:** documentation only. No code, config or CI change is made by this audit.

> STATUS: **skeleton, sections filled incrementally.** Commits in this branch carry the section that
> each one completes; the final commit closes the report. A section still marked `PENDING` was not
> completed before the audit session ended and is listed in §9 (Limitations).

## 1. Scope and method

PENDING

## 2. Change set map: `52ac293..5bb540c` (76 commits)

The wave of 2026-10-15..18 under audit. Grouped by area, with the security-relevant commits named.

| # | Area | Commits | Security relevance |
|---|------|---------|--------------------|
| A | CLI canon to `ssh(1)`/`sshd(8)` (P8 1a–1c) | `b2b756b`, `2a9acd5`, `c413ed5`, `ed6daf3`, `9877fb9`, `9a36bcd`, `ce3ca4b`, `b0bd98c`, `53fb62c`, `c4efeb9`, `5fbd1f0`, `caee73b`, `5124a5c`, `383fdf3`, `9d761d9`, `1c078c2`, `cce5095`, `9d5d056` | new option surface, bounded copies, login/bind policy defaults, DoS knobs |
| B | Security fixes from pass 1 | `d2787f7`, `b7c3aff`, `fd9570b`, `9919d90`, `5a6a02c`, `5a77496`, `0ad93b2`, `e4b45e7`, `3a1229f` | the F-1 / I-1 / I-2 / I-3 closures verified in §3 |
| C | Debian packaging wave | `566b109`, `b982659`, `21ac508`, `82fa2f6`, `93f5fab`, `4bae16f`, `7835642`, `facb423`, `cba24bf`, `638a8bf`, `35f5c1f`, `311fc5e`, `5bb540c` | service-unit privileges, postinst/postrm account handling, CI only |
| D | Release | `e875ddd` | version 0.4.0 |
| E | Interop/e2e | `interop/cli-compat-e2e.sh`, `interop/cli-compat-srv-e2e.sh`, `p8-defaults-e2e.sh`, gateway-ports/reverse-forward/permit-open/product-reverse legs | not shipped code; confirms behaviour |

Code surface touched (shipped): `app/ssh3_client.c` (+9618/−…), `app/ssh3_server.c`, `src/ssh3/s3_ssh3_channel.[ch]`,
`src/ssh3/s3_ssh3_cm.c`, `src/ssh3/s3_ssh3_session_srv.[ch]`, `src/ssh3/s3_ssh3_version.h`, `man/`, `packaging/`.

## 3. Fix verification (pass-1 findings)

PENDING

## 4. Regression hunt on the fixes

PENDING

## 5. Continuation of coverage

### 5.1 `src/h3/s3_h3_parse.c` — PENDING
### 5.2 HTTP/3 + QPACK — PENDING
### 5.3 auth / JWT / OIDC — PENDING
### 5.4 session / PTY / exec — PENDING
### 5.5 SFTP server / jail — PENDING
### 5.6 forwarding, gateway-ports, `-R`/`-o` — PENDING
### 5.7 DoS guard — PENDING

## 6. New-findings sweep on the 2026-10-15..18 wave

PENDING

## 7. Probes (sanitizers, harnesses)

PENDING

## 8. Findings

PENDING

## 9. Coverage and limitations (honest)

PENDING
