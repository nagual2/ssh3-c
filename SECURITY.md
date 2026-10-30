# Security Policy

Security policy for the `ssh3-c` C implementation of SSH3 (the wire
protocol of [docs/SPEC-wire.md](docs/SPEC-wire.md), rev nagual2/1).
Plan item P8(4) — the security contacts follow the R2 audit waves
(docs/SECURITY_AUDIT_2026-10-17.md and the pass-2/pass-3 reports).

## Supported versions

| Version line | Supported |
|--------------|-----------|
| the latest release line (0.5.x) and `main` | yes |
| older release lines (≤ 0.4.x) | no — upgrade |

## Reporting a vulnerability

Use **GitHub private vulnerability reporting** on this repository
(Security → Report a vulnerability). That channel is private by
default, keeps the whole thread in one place and allows a CVE to be
assigned through the GitHub CNA when warranted.

Do **not** open a public issue for a suspected vulnerability.

A useful report includes:

| № | Field | Notes |
|---|-------|-------|
| 1 | Version / commit | `ssh3-server -V` / `ssh3 -V` output, or the commit hash of a source build |
| 2 | Component | transport (QUIC, OpenSSL ≥ 3.5 QUIC TLS API), h3/QPACK framing, channel layer, auth (pubkey-JWT / Basic / system password / OIDC), sftp, forwards, packaging |
| 3 | Reproduction | a minimal command line or a patch to an `interop/` e2e script — the harness is public and runs from WSL |
| 4 | Impact | what an attacker gains, preconditions (auth state, listener flags) |

## Response and disclosure

| № | Commitment | Target |
|---|------------|--------|
| 1 | Acknowledgement of a report | ≤ 5 business days |
| 2 | Status update to the reporter | ≤ 14 days |
| 3 | Coordinated disclosure window | 90 days from the report (shorter for actively exploited issues) |
| 4 | Credit | the reporter is credited by name/handle on request |

Fixes land first on `main` (ctest 46/46 release+asan plus the affected
`interop/` e2e legs as the regression bar), then as a patch release of
the supported line; the advisory is published when the patch ships.

## CVE procedure

- **Before distro inclusion** (the current state): request the CVE
  through the GitHub CNA inside the private reporting thread.
- **After the Debian source package enters the archive**: Debian
  security team practice takes over — the `debian/security-contact`
  field points here, and reports against the archived package go to
  `team@security.debian.org` per the usual Debian flow.
- **Fedora / Alpine**: once the rpm review (Fedora) or the aports MR
  (Alpine) lands, the distro security teams follow their standard
  tracked-package procedure; the upstream advisory above stays the
  coordination point.

## Scope

In scope: the daemon and the CLI of this repository — the QUIC/h3
transport, the SSH3 wire layer (channels, datagrams, reverse-forward),
the authentication chain, the per-session setuid model, the DoS guards,
and the packaging payloads (what the packages install and enable).

Out of scope:

| № | Item | Where to report |
|---|------|-----------------|
| 1 | the bundled OpenSSL libraries (`ssh3c-libssl3`, the Debian 13 `libssl3t64` pair) | OpenSSL upstream / the Debian security team — this repo only repackages them |
| 2 | the Go implementation (nagual2/ssh3-go) | that repository's own channel |
| 3 | system-level misconfiguration of systemd/permissions on the target host | the host administrator |

## Known limitations

- The deb/rpm/apk artifacts are currently **unsigned** (no signing key
  in the tree); verify releases against the published checksums until
  package signing lands (tracked in the packaging backlog).
- The client's TOFU pin store is `~/.ssh3/known_hosts` (x509-certificate
  pins) — deliberately separate from OpenSSH's `~/.ssh/known_hosts`
  (ssh2 host keys); the two formats are not interchangeable.
