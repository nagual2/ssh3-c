# ssh3 package coexistence
> Languages: [RU](COEXISTENCE.md) · EN (this file) · [DE](COEXISTENCE.de.md)

Date: 2026-10-30. Plan item P8(3) ([PLAN.md](PLAN.md) §4): ssh3 is a
separate package **alongside OpenSSH**, not a replacement; against
ssh3-go it is interchangeability through phase P8(1) (one package
replaces another, it does not sit next to it). This document is the
co-installation control matrix and its acceptance procedure.

## The principle

| № | Pair | Rule |
|---|------|------|
| 1 | ssh3 ↔ OpenSSH (ssh2) | always coexist: different binaries, configs, ports, key formats; nothing is overlaid on either side |
| 2 | ssh3 (C) ↔ ssh3-go (the fork) | package-level replacement: identical binary and unit-file names, so cohabitation of one role is excluded by `Conflicts`/`Obsoletes`, and replacement goes through `Replaces`/`Provides` — third-party programs calling `ssh3`/`ssh3-server` need no reconfiguration |

## What each package installs

| № | File | Package |
|---|------|---------|
| 1 | `/usr/sbin/ssh3-server` | ssh3-server (the build.sh deb; the debian/ source package installs `/usr/bin/ssh3-server`) |
| 2 | `/usr/bin/ssh3`, the `/usr/local/bin/ssh3` symlink | ssh3-client |
| 3 | `/etc/ssh3/cert.pem`, `/etc/ssh3/key.pem` (0640 root:ssh3), `/etc/ssh3/authorized_keys` | ssh3-server |
| 4 | `/etc/ssh3/ssh3-server.env` (conffile, `EnvironmentFile`) | the debian/ source package only |
| 5 | `/usr/lib/ssh3-c/lib/libssl.so.3`, `libcrypto.so.3` (RUNPATH bundle) | ssh3c-libssl3 (deb only) |
| 6 | `/usr/lib/systemd/system/ssh3-server.{socket,service}` | ssh3-server |
| 7 | `/usr/share/man/man8/ssh3-server.8`, `/usr/share/man/man1/ssh3.1.gz` | ssh3-server / ssh3-client |

Client-side state lives in the user's home and is never claimed by a
package: certificate pins in `~/.ssh3/known_hosts` (the
`x509-certificate` format), the config is read as an ssh2-compatible
subset via `-F` (default `~/.ssh/config`) — the file is **read**, never
written.

## The co-installation matrix

| № | Scenario | Result | Guaranteed by |
|---|----------|--------|---------------|
| 1 | `ssh3` (the C client) + OpenSSH `ssh` | coexist | no file overlap (`/usr/bin/ssh3` vs `/usr/bin/ssh`), configs (`~/.ssh3` vs `~/.ssh`), man pages (`man1/ssh3.1` vs `man1/ssh.1`) |
| 2 | `ssh3-server` (C) + `sshd` | coexist | transport: UDP/443 (socket activation, the daemon never calls `bind()`) vs TCP/22; `/etc/ssh3` vs `/etc/ssh`; the `ssh3-server.*` unit pair vs `sshd.service` |
| 3 | `ssh3-server` (C) + `ssh3-go-server` | excluded at the package level | deb `packaging/deb/control:8-9`, rpm `packaging/rpm/ssh3-server.spec:31-35` (`Obsoletes`), apk `packaging/apk/PKGINFO.in:22-25` |
| 4 | `ssh3-client` (C) + `ssh3-go-client` | excluded at the package level | deb `packaging/deb/client-control:8-9`, rpm `spec:47-49`, apk `PKGINFO-client.in:23-24` |
| 5 | the C client + the go server (no package conflict — different roles) | coexist, wire-compatible | no file overlap; the interop legs `interop/go-server-channel-e2e.sh`, `interop/go-compat-e2e.sh` |
| 6 | the C server + the go client | coexist, wire-compatible | the interop matrix `interop/run-h3.sh`, `interop/jump-chain-smoke.sh` (fork `1b6872a`) |
| 7 | the build.sh deb ↔ the debian/ source package | one channel at a time | the same package name `ssh3-server`: two build channels, not two packages; dpkg/apt installs only one (the paths differ: `/usr/sbin` vs `/usr/bin`) |

A historical note (why item 3 is a replacement and not a neighborship):
at the P7 integration the unit pair was renamed `ssh3-c-server.*` →
`ssh3-server.*` because of the file conflict with the already installed
`ssh3-go` package — the P8 coexistence principle applied as "one role —
one owner of the name".

Out of the matrix: the metapackages (`ssh3c`/`ssh3go` for rpm/apk) and
the rpm/apk signing — pending the owner's decision (PLAN-CURRENT.md,
"Waiting for the owner's decision").

## The control procedure

Matrix acceptance on a clean host (deb commands; rpm/apk at the end):

| № | Check | Command | Expected |
|---|-------|---------|----------|
| 1 | items 1-2: the binaries side by side | `command -v ssh ssh3 sshd ssh3-server; ssh -V; ssh3 -V` | all present, versions independent |
| 2 | items 1-2: the ports do not argue | `ss -lnt` / `ss -lun` | sshd: TCP/22; ssh3-server: UDP/443 (after enable) |
| 3 | items 1-2: the configs are separate | `dpkg -L ssh3-server \| grep -c /etc/ssh/` | `0` — the package writes nothing under `/etc/ssh` |
| 4 | item 3: a replacement, not a neighborship | `apt-get install -s ssh3-server` on a host with ssh3-go-server | the apt plan removes the go package (`Conflicts`), `/etc/ssh3` survives |
| 5 | item 4: likewise for the client | `apt-get install -s ssh3-client` on a host with ssh3-go-client | the apt plan removes the go client |
| 6 | items 5-6: a live cross leg | `sh interop/go-server-channel-e2e.sh` (the C client → the go server) | the e2e verdict `OK` |
| 7 | item 7: the channels do not mix | `dpkg -I` of both debs from `_build` and `_debian` | the name `ssh3-server` in both — installing the second displaces the first |

rpm: `rpm -q --conflicts ssh3-server`, `rpm -q --obsoletes ssh3-server`
(expected: both ssh3-go-* pairs); apk: the `conflicts`/`replaces` lines
of the installed package in `apk info`.

## See also

- The split canon and the file placement — `packaging/README.md`
  (§ The packages, § Debian source package).
- The CLI deviation matrix against ssh(1)/sshd(8) — `docs/CLI-COMPAT.md`.
- The security policy (where to report, the CVE procedure) — `SECURITY.md`.
