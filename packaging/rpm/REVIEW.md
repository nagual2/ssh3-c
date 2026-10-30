# Fedora review materials (the P8(2) plan item)

Date: 2026-10-30. The submission is the owner's action (the Fedora
account, the Bugzilla review request, the koji scratch builds); this
file carries the prepared materials and the readiness notes. The
source-building spec is [ssh3-server.fedora.spec](ssh3-server.fedora.spec);
the self-hosted prebuilt channel ([ssh3-server.spec](ssh3-server.spec))
stays untouched.

## The OpenSSL question — resolved

The plan row asked: subpackage OpenSSL or wait for the repository 3.5?
**Wait — nothing to package.** Fedora 43 (and rawhide) ship
`openssl-libs 3.5.x` with the QUIC TLS API, so `BuildRequires:
openssl-devel >= 3.5` / `Requires: openssl-libs >= 3.5` resolve against
the system library. Older Fedora releases (≤ 42) refuse at the `%build`
stage (the cmake configure is the fail-closed gate) — the package
targets F43+.

## What the review spec changes against the house spec

| № | Difference | Why |
|---|------------|-----|
| 1 | `%build` from the source tarball (`%cmake` + `%cmake_build`), `%check` rides `%ctest` | the prebuilt-binary payload does not pass the Fedora review; the sources build clean (the release CI runs the same recipe) |
| 2 | `Source0` is the GitHub tag archive | the review requirement: the published source |
| 3 | `Conflicts`/`Obsoletes` against `ssh3-go-*` dropped | those packages do not exist in Fedora; the review guidance flags conflicts against not-provided names. The drop-in dance stays a property of the deb/rpm self-hosted channels (docs/COEXISTENCE.md) |
| 4 | the client man page installs from `packaging/debian/ssh3.1` (gzip at the `%install`) | the same source the deb channel uses |

## The readiness checklist

| № | Item | State |
|---|------|-------|
| 1 | License tag + the license files (`LICENSE`, `THIRD-PARTY-NOTICES.md`; the client subpackage carries its own license copy — a spec cannot list one file in two packages) | ready |
| 2 | The OpenSSL 3.5 floor (F43+) | ready (see above) |
| 3 | The upstream `-Werror` (`-Wall -Wextra -Werror` on s3core) | risk: the distro hardening flags may raise new warnings; if koji flags one, relax per-symbol, do not drop -Werror wholesale |
| 4 | `%ctest` in the sandbox | the suite binds loopback only; no root needed |
| 5 | rpmlint / fedora-review dry run | owner-side (needs the Fedora tooling or a container run) |
| 6 | koji scratch build (x86_64 + aarch64) | owner-side |
| 7 | The review request text | the draft below |

## The review request draft (Bugzilla, fedora-review)

```
Package name: ssh3-server
Short description: SSH3 server and client - SSH over the QUIC/HTTP3 transport
Owners: <the owner's FAS>
Upstream: https://github.com/nagual2/ssh3-c
Reason: a pure-C17 SSH3 implementation (server + client) over the
OpenSSL 3.5 QUIC TLS API; the ssh(1)/sshd(8) CLI canon (the launch
compatibility matrix in docs/CLI-COMPAT.md), the per-session setuid
model, sftp and the forwards; two independent implementations of the
wire protocol (this C port and the reference go fork) backed by the
rev nagual2/1 specification (docs/SPEC-wire.md).
SPEC: <the src.rpm with ssh3-server.fedora.spec>
SCRATCH: <the koji scratch links x86_64/aarch64>
Notes: F43+ only (openssl-libs >= 3.5 with the QUIC TLS API).
```

## The submission order

1. `fedora-review` in a container against the spec (the local dry run).
2. koji scratch x86_64/aarch64.
3. The Bugzilla review request with the draft above.
4. The maintainer sponsor loop (the owner's FAS account is the gate).
