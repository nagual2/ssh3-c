# ssh3-c

**English** | [Русский](README.ru.md) | [Deutsch](README.de.md)

## Documentation

All project documents are trilingual (a `> Languages:` banner links the
versions in each file). The canonical text of the `docs/` documents is
Russian; EN/DE are faithful translations.

| № | Document | Contents | Languages |
|---|----------|----------|-----------|
| 1 | [docs/PLAN.md](docs/PLAN.md) | development plan: phases P0–P9, wave acceptance history, open backlog | RU · [EN](docs/PLAN.en.md) · [DE](docs/PLAN.de.md) |
| 2 | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | the layer architecture: core/event/quic/h3/ssh3/app, zero-copy conventions | RU · [EN](docs/ARCHITECTURE.en.md) · [DE](docs/ARCHITECTURE.de.md) |
| 3 | [docs/SPEC-wire.md](docs/SPEC-wire.md) | the SSH3 wire protocol specification (rev nagual2/1, draft 1) | RU · [EN](docs/SPEC-wire.en.md) · [DE](docs/SPEC-wire.de.md) |
| 4 | [docs/P4-WIRE.md](docs/P4-WIRE.md) | historical distillate: channel lifecycle and datagram routing (wave 2) | RU · [EN](docs/P4-WIRE.en.md) · [DE](docs/P4-WIRE.de.md) |
| 5 | [docs/PORTING-nginx-quic.md](docs/PORTING-nginx-quic.md) | porting journal: the nginx QUIC layer → ssh3-c | RU · [EN](docs/PORTING-nginx-quic.en.md) · [DE](docs/PORTING-nginx-quic.de.md) |
| 6 | [docs/DEPS-QUIC.md](docs/DEPS-QUIC.md) | QUIC-stack dependencies and licenses (OpenSSL ≥3.5 QUIC API) | RU · [EN](docs/DEPS-QUIC.en.md) · [DE](docs/DEPS-QUIC.de.md) |
| 7 | [docs/BENCH-METRICS.md](docs/BENCH-METRICS.md) | benchmark methodology and metrics (R3) | RU · [EN](docs/BENCH-METRICS.en.md) · [DE](docs/BENCH-METRICS.de.md) |
| 8 | [docs/BENCH-P7-2026-10-06.md](docs/BENCH-P7-2026-10-06.md) | benchmark report, phase P7 | RU · [EN](docs/BENCH-P7-2026-10-06.en.md) · [DE](docs/BENCH-P7-2026-10-06.de.md) |
| 9 | [docs/BENCH-V0.2.0-2026-10-13.md](docs/BENCH-V0.2.0-2026-10-13.md) | benchmark report, release v0.2.0 | RU · [EN](docs/BENCH-V0.2.0-2026-10-13.en.md) · [DE](docs/BENCH-V0.2.0-2026-10-13.de.md) |
| 10 | [docs/BENCH-V0.3.0-2026-10-15.md](docs/BENCH-V0.3.0-2026-10-15.md) | benchmark report, release v0.3.0 | RU · [EN](docs/BENCH-V0.3.0-2026-10-15.en.md) · [DE](docs/BENCH-V0.3.0-2026-10-15.de.md) |
| 11 | [packaging/README.md](packaging/README.md) | building the distribution packages (deb/rpm/apk/OpenWrt, bundled OpenSSL) | EN · [RU](packaging/README.ru.md) · [DE](packaging/README.de.md) |
| 12 | [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) | third-party copyright and license notices (legal text, not translated) | EN |

A pure-C17 SSH3 implementation in the nginx style: memory pools, buffer
views, a chain interface for all I/O, a zero-copy data path. The target
position is "OpenSSH among Linux systems" (see
[docs/PLAN.md](docs/PLAN.md)).

Current status: phases **P0–P1** are done (the core + the event/UDP
layer, the GSO bench); **P2** preparation is underway — adapting the
nginx QUIC layer (see [docs/PLAN.md](docs/PLAN.md)).

## Launch compatibility (drop-in)

ssh3-c is a drop-in replacement for ssh3-go (the OpenSSH-style fork)
and a peer of OpenSSH (ssh2): the binaries carry the same names
(`ssh3`, `ssh3-server`), the launch keys match where the functionality
is the same; the packages declare `Provides`/`Conflicts`/`Replaces`
against ssh3-go, so one package replaces another (e.g. when closing a
vulnerability) without reconfiguring third-party programs that work
over ssh3.

## Layout

| № | Directory | Contents |
|---|-----------|----------|
| 1 | `src/core/` | memory pool (`s3_palloc`), buffers and chains (`s3_buf`), strings (`s3_string`, `s3_str`), rbtree (`s3_rbtree`), intrusive list (`s3_queue`), logging (`s3_log`), the `s3_core.h` aggregator |
| 2 | `src/event/` | event loop, timers, posted events (`s3_event`), connections (`s3_connection`), UDP pseudo-connections (`s3_event_udp`), the epoll backend (`modules/s3_epoll_module`) |
| 3 | `src/os/unix/` | errno layer (`s3_errno`), UDP sendmsg chain (`s3_udp_sendmsg_chain`), UDP recv (`s3_udp_recv`) |
| 4 | `bench/` | `gso_bench` — a UDP GSO (`UDP_SEGMENT`) micro-benchmark against plain sendmsg |
| 5 | `tests/` | unit tests (the dependency-free `s3_test.h` micro-framework) |

## Build (from WSL)

```bash
cd /mnt/c/Git/project/ssh3-c
cmake --preset linux-release
cmake --build --preset linux-release
ctest --preset linux-release --output-on-failure
```

## Sanitizers (ASan + UBSan)

```bash
cmake --preset linux-asan
cmake --build --preset linux-asan
ctest --preset linux-asan --output-on-failure
```

## Installation

From the distribution packages (the `packaging/` sources build them for
deb/rpm/apk and OpenWrt ipk):

```bash
sudo apt install ssh3-server
```

The package layout:

| № | File | Purpose |
|---|------|---------|
| 1 | `/usr/sbin/ssh3-server` | the daemon |
| 2 | `/etc/ssh3/cert.pem` | TLS certificate (PEM) |
| 3 | `/etc/ssh3/key.pem` | private key (PEM, `0640 root:ssh3`) |
| 4 | `/etc/ssh3/authorized_keys` | keys for Bearer-JWT login (`-K`) |
| 5 | `/usr/share/man/man8/ssh3-server.8` | the man page |
| 6 | `/usr/lib/systemd/system/ssh3-server.{socket,service}` | systemd units |

From source (no install rule yet, the binary stays in the build tree):

```bash
cd /path/to/ssh3-c
cmake --preset linux-release && cmake --build --preset linux-release
# build/linux-release/ssh3-server
```

## systemd (socket activation)

The shipped pair splits the port privilege from the service: the
root-owned `ssh3-server.socket` binds UDP/443 and systemd hands the
ready datagram fd to `ssh3-server.service`.  Since P7.3 the service
runs as root with the **per-session setuid**: after authentication
every session with a resolvable CONNECT username drops onto that
identity (`initgroups`, `setgid`, `setuid`, the home `chdir`) before
the spawn — the OpenSSH/sshd shape; the daemon itself keeps a minimal
bounding set (`CAP_CHOWN CAP_DAC_READ_SEARCH CAP_SETGID CAP_SETUID`)
and needs **no** `CAP_NET_BIND_SERVICE` (the daemon takes the passed
fd, it never calls `bind()`):

```ini
# ssh3-server.socket (excerpt)
[Socket]
ListenDatagram=0.0.0.0:443
FreeBind=yes

# ssh3-server.service (excerpt)
[Service]
ExecStart=/usr/sbin/ssh3-server -c /etc/ssh3/cert.pem -k /etc/ssh3/key.pem
User=root
NoNewPrivileges=no
RestrictSUIDSGID=no
ProtectSystem=strict
ProtectHome=no
CapabilityBoundingSet=CAP_CHOWN CAP_DAC_READ_SEARCH CAP_SETGID CAP_SETUID
PrivateTmp=yes
```

A user without a passwd entry answers 401 at the CONNECT; a CONNECT
without a session username keeps the daemon identity.  The
single-identity unprivileged shape (`User=ssh3`, `--run-as-user off`,
the P7.2 hardening) is documented in the unit comments and
`man/ssh3-server.8` (`PRIVILEGE MODEL`).

```bash
sudo systemctl enable --now ssh3-server.socket
```

Port variation goes through a drop-in, not an edit of the unit:

```bash
sudo systemctl edit ssh3-server.socket
# [Socket]
# ListenDatagram=0.0.0.0:8443
```

## Configuration

CLI flags (defaults from `ssh3-server -h`):

| Flag | Default | Description |
|------|---------|-------------|
| `-l addr:port` | — | UDP listen (IPv4), port `0` — ephemeral; not needed under socket activation |
| `-c cert.pem` | — | TLS certificate (PEM), required |
| `-k key.pem` | — | private key (PEM), required |
| `-A alpn` | `h3` | the ALPN name |
| `-d dg_size` | `1200` | QUIC `max_datagram_frame_size` |
| `-i idle_ms` | `60000` | QUIC idle timeout, ms |
| `-L level` | `info` | log level: `debug\|info\|warn\|error\|all` or numeric |
| `-P pwfile` | — | the `user:secret` password file (Basic authentication) |
| `-K authorized_keys` | — | authorized_keys for Bearer-JWT (`%u` — the username in the path) |
| `-H dir` | the user home | the sftp-jail directory |
| `--oidc-issuer url` | — | the OIDC provider (id_token) |
| `--oidc-audience id` | — | the expected audience (client id) |
| `--oidc-jwks-ttl sec` | `3600` | the JWKS set lifetime |
| `--run-as-user on\|off` | `on` under euid 0 | per-session setuid: a session with a resolvable CONNECT user drops onto its identity before the spawn |
| `-v` / `-V` / `-h` | — | debug logging / version / usage |

Environment:

| Variable | Default | Description |
|----------|---------|-------------|
| `SSH3_LOG_LEVEL` | as `-L` | the log level |
| `SSH3_LOG_FILE` | stderr | the log file (ignored under systemd) |
| `SSH3_SHUTDOWN_DRAIN` | `5` s | the drain on SIGTERM, `0` — immediately |
| `SSH3C_PROTO=1` | off | the `INTEROP-*` runner markers on stdout |
| `S3_OIDC_CA_FILE` | the system store | the CA for OIDC discovery/JWKS |
| `LISTEN_PID`/`LISTEN_FDS` | — | the `sd_listen_fds(3)` protocol, read-only |

Full reference: `man 8 ssh3-server`.

## Code style

- `.clang-format` / `.clang-tidy` live in the root; the check:
  `clang-format --dry-run --Werror src/core/*.c src/core/*.h tests/*.c`.
- The build runs with `-Wall -Wextra -Werror`; the `linux-asan` preset
  adds `-fsanitize=address,undefined -fno-sanitize-recover=all`.

## The address of the replies (wildcard listener)

A listener bound to any local address (`[::]`, `0.0.0.0` — the default)
takes the packets of every local address, so the local address of an
arrived packet is unknown to the server until the kernel's ancillary
data names it. The server asks for it (`IP_PKTINFO` /
`IPV6_RECVPKTINFO`) and answers with **the address the client dialed**,
not with the one the routing table prefers. On a single-address host
the two are the same; on a multi-address host (a tunnel, a second IP)
the difference decides whether the client recognises its own answer —
QUIC drops a packet that arrives from an address the client did not
dial (RFC 9000, 8.1).

A spoofed path gets nothing: before the handshake the server answers a
datagram from an unknown address with no bytes at all, which is
stricter than RFC 9000, 8.2.1 allows and keeps the amplification at
zero. After the handshake a peer that changes its address (the NAT
rebinding) is handled per RFC 9000, 9.3.3: the previously active
path is validated with a PATH_CHALLENGE, and a path that fails the
validation is dropped in favour of the last validated one.

## Performance

Medians of the control benchmark (methodology R3, `bench/p7-compare.sh`):
WSL2 loopback, one ed25519 keypair for all three implementations,
sha-verified transfers, 7 rounds per cell (the first is the warmup).
The full tables and the environment notes —
[docs/BENCH-V0.3.0-2026-10-15.md](docs/BENCH-V0.3.0-2026-10-15.md).

| № | Metric | ssh3-c | Go fork 0.1.35 | OpenSSH 9.6 |
|---|--------|--------|----------------|-------------|
| 1 | 512 MiB sftp push / pull, MB/s | 353 / 354 | 28 / 33 | **358 / 421** |
| 2 | Handshake, cold connect+auth+exec, ms | **117** (min 15) | 172 | 221 |
| 3 | ControlMaster warm exec, ms | **7.6** | 9.0 | 13.8 |
| 4 | Server CPU / RSS peak, 512 MiB push | **75% / 81 MB** | 104% / 26 MB | 104% / 26 MB |
| 5 | Many-file directory 4000×4 KiB push / pull, files/s | **4667 / 4624** | 4103 / 3518 | 1175 / 1284 |
## License

The project's own code — BSD 2-clause (`LICENSE`). The code adapted
from nginx (BSD 2-clause) is listed in `THIRD-PARTY-NOTICES.md` — its
headers keep `Copyright (C) Nginx, Inc.`.
