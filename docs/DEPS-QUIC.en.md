# ssh3-c: build dependencies and the QUIC question (report)

> Languages: [RU](DEPS-QUIC.md) · EN (this file) · [DE](DEPS-QUIC.de.md)

Date: 2026-10-01. Problem statement from the project owner: OpenSSH is part of the base Linux systems and builds against their libraries; ssh3-c should minimize third-party libraries. It is unclear what to do about QUIC. This report is an analysis and a recommendation.

## 1. Baseline: what OpenSSH actually links

OpenSSH portable requires exactly two external system libraries:

| # | Library | Role | Optionality |
|---|---------|------|-------------|
| 1 | `libcrypto` (OpenSSL/LibreSSL) | all TLS/SSH cryptography | mandatory |
| 2 | `libz` | channel compression | mandatory (but the channel barely uses compression) |

Optional and distribution-specific: `libedit` (sftp client), `libfido2` (FIDO keys), GSSAPI/kerberos, PAM/audit/selinux (distribution patches). The essence of the principle: **the protocol layer (SSH) itself is OpenSSH's own code; only the crypto stack is taken from system libraries**. The SSH protocol has never been a "library" — and that is exactly why OpenSSH builds everywhere.

Target conclusion for ssh3-c: **the only system dependency is `libcrypto`**. QUIC and HTTP/3 are our protocol layer, analogous to OpenSSH's SSH layer: our own code, not a library. A pleasant bonus: ssh3 does not need zlib at all (QUIC does not use DEFLATE).

## 2. Anatomy of the QUIC dependency

QUIC cannot be taken as "one library from the base" — it is a conglomerate of four layers:

| # | Layer | What it requires |
|---|-------|------------------|
| 1 | TLS 1.3 with QUIC API | handshake callbacks, transport parameters as a TLS extension, key phases. Available in: OpenSSL ≥3.5 (native API), BoringSSL, LibreSSL, wolfSSL, GnuTLS ≥3.8 |
| 2 | QUIC transport (RFC 9000/9002) | varint, frames, ACK/loss recovery, congestion control, flow control — a "monster" |
| 3 | HTTP/3 + QPACK (RFC 9110/9204) | ssh3 needs a minimum: extended CONNECT + QPACK sufficient for interop with quic-go |
| 4 | DATAGRAM (RFC 9221) | mandatory: ssh3's UDP forwarding is built on QUIC datagrams |

Key fact of 2025–2026: **OpenSSL 3.5 LTS (April 2025) delivered a native QUIC API — server + client + 0-RTT for third-party QUIC stacks**. Before that, QUIC-TLS required non-upstream forks (quictls) or BoringSSL — that is exactly why "minimal" QUIC solutions did not exist earlier. The ecosystem is consolidating: curl dropped its quictls backend in January 2026, and nginx recommends OpenSSL ≥3.5.1.

## 3. QUIC stack options

| # | Option | Language | TLS | License | In distributions | DATAGRAM/0-RTT/GSO | Comment |
|---|--------|----------|-----|---------|------------------|--------------------|---------|
| 1 | **Own QUIC (adaptation of nginx `src/event/quic/`) + system OpenSSL 3.5** | C | system libcrypto | BSD-2 (nginx), OpenSSL | the code is ours; TLS from the base | DATAGRAM **to be written** (nginx lacks it); 0-RTT available; GSO available | the QUIC layer becomes our own source, like the SSH layer in OpenSSH |
| 2 | **System ngtcp2 + nghttp3** + OpenSSL 3.5 or GnuTLS | C | libcrypto/gnutls | MIT | Debian 13 (1.11, backports newer), Fedora, Alpine (1.22–1.25) | both available, GSO API available | 2 extra libraries; QUIC is supported upstream |
| 3 | quiche (Cloudflare) | Rust+CAPI | BoringSSL **vendored** | BSD-2 | no | available | pulls in the Rust toolchain and BoringSSL — against the principle |
| 4 | lsquic (LiteSpeed) | C | BoringSSL (specific commits) | MIT | no | available | + libevent, zlib; BoringSSL vendoring |
| 5 | picoquic (Private Octopus) | C | picotls (its own) | MIT | no | available | its own TLS stack — not a "system" dependency |
| 6 | mvfst (Meta) | C++ | BoringSSL + fizz/folly | MIT | no | available | the heaviest; C++ with exceptions, alien style |

Options 3–6 are rejected by the same argument: **all of them drag in BoringSSL or picotls as a vendored dependency** — the build stops being "from base libraries"; a toolchain appears (Rust for quiche) or code that cannot be packaged into distributions. None of them is present in the base repositories of Debian/Fedora/Alpine.

## 4. Packaging of system OpenSSL 3.5 (for option 1)

| # | Distribution | OpenSSL | QUIC API | Comment |
|---|--------------|---------|----------|---------|
| 1 | Debian 13 trixie | 3.5.x | yes | current stable |
| 2 | Ubuntu 25.10 | 3.5.3 | yes | |
| 3 | Fedora 43 | 3.5.8 | yes | recent QUIC server fixes |
| 4 | Alpine 3.22 | 3.5.8 | yes | important for embedded/containers |
| 5 | Ubuntu 24.04 LTS | 3.0.x | **no** | support window until 2029 — a trough |
| 6 | RHEL 10 | 3.2.x | **no** | none, plus a strict policy on top |
| 7 | Windows | n/a (vcpkg OpenSSL 3.5) | yes | build via vcpkg — a documented exception |

Upstream OpenSSL publishes official .deb/.rpm packages (the openssl/packages repository) — for Ubuntu 24.04/RHEL there is a sanctioned workaround without vendoring.

For option 2: ngtcp2 is packaged in Debian 13 (but the package is built with the GnuTLS backend only; the OpenSSL backend requires ngtcp2 ≥1.12 — take it from backports); Fedora and Alpine ship current versions.

## 5. Decision matrix (project owner's criteria)

Criteria: minimum third-party libraries; build from the base system; zero-copy; DATAGRAM+0-RTT; maturity; style.

| # | Criterion | Opt. 1: own QUIC + OpenSSL 3.5 | Opt. 2: ngtcp2+nghttp3 |
|---|-----------|-------------------------------|------------------------|
| 1 | Third-party libraries | **1** (libcrypto — same as OpenSSH) | 3 (libcrypto + ngtcp2 + nghttp3) |
| 2 | Build from the base system | yes (Debian 13/Ubuntu 25.10/Fedora 43/Alpine 3.22) | yes, but versions/backends vary (Debian: GnuTLS backend in the base) |
| 3 | Zero-copy control | **maximum** (our code: shadow-buf, chain, GSO coalescing — nginx patterns) | good (writev API, GSO), but the buffers belong to the library |
| 4 | DATAGRAM | write it ourselves (RFC 9221: TP 0x0020, frames 0x30/0x31, queue, flow control) — **the main engineering addition** | available out of the box (`ngtcp2_conn_writev_datagram`) |
| 5 | QUIC maturity (loss/cc) | our responsibility (the nginx code is battle-proven, but the DATAGRAM addition is ours) | **upstream ngtcp2** (used by curl/Node) |
| 6 | Binary size | minimal (our own trim for ssh3) | larger (full QUIC+h3) |
| 7 | OpenSSL 3.5 freshness risk | the QUIC API is young: QUIC fixes up to 3.5.8 (double-free) — require the newest patch release | the same TLS layer, but less of our own code on top |
| 8 | Fit with the "like OpenSSH" principle | **full**: protocol = our code, TLS = system library | partial: protocol = someone else's library |

## 6. Recommendation

**Primary path — option 1**: system `libcrypto` (OpenSSL ≥3.5, required in CMake via `find_package(OpenSSL 3.5)`) + the QUIC transport as our own source (adaptation of nginx `src/event/quic/`, BSD-2) + a minimal h3 layer. One third-party library, exactly like OpenSSH; only instead of zlib we have nothing (it is not needed). This is already recorded in ARCHITECTURE.md (decision #2) — the report confirms the choice and rules out the alternatives.

**Fallback path — option 2** (document it, do not build it now): the `S3_USE_NGTCP2` build option for distributions without OpenSSL 3.5 (Ubuntu 24.04 LTS, RHEL 10), if demand ever appears. ngtcp2 is the only alternative packaged in distributions (MIT, C, DATAGRAM/0-RTT/GSO out of the box).

**Rejected**: quiche, lsquic, picoquic, mvfst — BoringSSL/picotls vendoring, absence from distributions; quiche additionally drags in the Rust toolchain. quictls is a non-upstream fork, not a "base" library (curl abandoned this path in 2026).

### License of the borrowed nginx code (verified against a 2026-10-01 clone)

nginx's `LICENSE` is **BSD 2-clause** ("Copyright (C) 2002-2021 Igor Sysoev, Copyright (C) 2011-2026 Nginx, Inc."). It permits copying, modification and use in any projects (including proprietary ones) under two conditions: (1) source distributions keep the copyright notice and disclaimer; (2) binary distributions reproduce the same notice and disclaimer in the documentation/distribution materials. No copyleft, no patent clause.

Borrowing scope: `src/event/quic/` ≈ 17.5k lines (31 of 32 files carry the `Copyright (C) Nginx, Inc.` header), `src/http/v3/` ≈ 7.4k lines, plus spot core primitives (pool/buf/string/rbtree).

ssh3-c obligations:
1. In adapted files, keep the nginx header and add our own (pattern: the nginx line + ours).
2. In the repo root — `LICENSE` (ours) + `THIRD-PARTY-NOTICES.md` with the text of nginx's BSD-2 and the list of adapted files.
3. Trademark: do not call the nginx/SSH3 product "nginx".
4. Compatible with the publication policy (dual-source): a public repository with these notices is legal.

Our own code (our copyright, no nginx obligations): DATAGRAM RFC 9221, the `ssh3/` layer (conversation/channel/message/auth) in full, `app/` (CLI, PTY, sftp, forwarding), the adaptation glue and the build.

## 7. Consequences for ARCHITECTURE.md and open questions

Consequences:
1. The ssl layer (risk #2 in ARCHITECTURE.md): three API options (OpenSSL 3.5 / quictls / boringssl) narrow down to **one** — the OpenSSL QUIC API; we do not design compat branches. For older distributions — official upstream OpenSSL packages or the S3_USE_NGTCP2 option.
2. A new increment in M2: **DATAGRAM (RFC 9221)** on top of the adapted nginx code — TP 0x0020, frames 0x30/0x31, a per-conn queue, datagram flow control. Estimate: medium; the code is contained in one place (frames + connection), but tests are mandatory (UDP forwarding depends on it entirely).
3. CMake: `find_package(OpenSSL 3.5 REQUIRED)` + a compile-time check for the presence of the QUIC API (analogous to nginx's `auto/feature`); a failure message with a hint about the official packages.

Open questions (to be resolved in M3):
1. **QPACK minimum vs interop with quic-go**: can quic-go/http3 be forced to encode with the static table only (SETTINGS_QPACK_MAX_TABLE_CAPACITY=0, blocked streams=0) — then our h3 layer has no dynamic table. Verify with an experiment in M3; if not, adapt nginx's QPACK table.
2. Maturity of the OpenSSL 3.5.x QUIC server: keep the CMake requirement for the newest patch release (≥3.5.8); a CI test for CERT fixes.
3. Windows: OpenSSL 3.5 via vcpkg — accept as an exception to "base libraries" (for Windows this is the equivalent of "system").

## 8. Sources

- [OpenSSL 3.5 Series Release Notes](https://openssl-library.org/news/openssl-3.5-notes) — QUIC server, 0-RTT, LTS
- [OpenSSL 3.5 Final Release](https://openssl-library.org/post/2025-04-08-openssl-35-final-release)
- [curl HTTP/3 docs](https://curl.se/docs/http3.html) — OpenSSL 3.5.0+ requires ngtcp2 ≥1.12
- [curl SSL libraries compared](https://curl.se/docs/ssl-compared.html)
- [More HTTP/3 focus, one backend less](https://daniel.haxx.se/blog/2026/01/17/more-http-3-focus-one-backend-less) — curl dropping the quictls backend
- [OpenSSL does a QUIC API](https://daniel.haxx.se/blog/2025/02/16/openssl-does-a-quic-api)
- [ngtcp2: writev_datagram (RFC 9221)](https://nghttp2.org/ngtcp2/ngtcp2_conn_writev_datagram.html), [programmer's guide: 0-RTT](https://nghttp2.org/ngtcp2/programmers-guide.html)
- [ngtcp2 in Debian trixie](https://packages.debian.org/source/trixie/ngtcp2) (1.11.0), [Fedora ngtcp2](https://packages.fedoraproject.org/pkgs/ngtcp2), [Alpine nghttp3](https://pkgs.alpinelinux.org/package/edge/main/x86_64/nghttp3)
- [openssl 3.5.8 in Alpine 3.22](https://pkgs.alpinelinux.org/package/v3.22/main/x86/openssl)
- [Ubuntu 25.10 openssl 3.5.3](https://www.ubuntuupdates.org/package/core/questing/main/security/openssl), [Fedora 43 openssl 3.5.8](https://packages.fedoraproject.org/pkgs/openssl/openssl/fedora-43-updates.html)
- [openssl/packages — official .deb/.rpm from upstream](https://github.com/openssl/packages)
- [lsquic](https://github.com/litespeedtech/lsquic) (BoringSSL mandatory), [quiche](https://github.com/cloudflare/quiche) (BoringSSL vendored), [picoquic build](https://www.privateoctopus.com/picoquic/building_picoquic.html) (picotls)
