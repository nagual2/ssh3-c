# ssh3-c

**English** | [Русский](README.ru.md) | [Deutsch](README.de.md)

A pure-C17 SSH3 implementation in the nginx style: memory pools, buffer
views, a chain interface for all I/O, a zero-copy data path. The target
position is "OpenSSH among Linux systems" (see
[docs/PLAN.md](docs/PLAN.md)).

Current status: phases **P0–P1** are done (the core + the event/UDP
layer, the GSO bench); **P2** preparation is underway — adapting the
nginx QUIC layer (see [docs/PLAN.md](docs/PLAN.md)).

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
root-owned `ssh3-c-server.socket` binds UDP/443 and systemd hands the
ready datagram fd to `ssh3-c-server.service`.  Since P7.3 the service
runs as root with the **per-session setuid**: after authentication
every session with a resolvable CONNECT username drops onto that
identity (`initgroups`, `setgid`, `setuid`, the home `chdir`) before
the spawn — the OpenSSH/sshd shape; the daemon itself keeps a minimal
bounding set (`CAP_CHOWN CAP_DAC_READ_SEARCH CAP_SETGID CAP_SETUID`)
and needs **no** `CAP_NET_BIND_SERVICE` (the daemon takes the passed
fd, it never calls `bind()`):

```ini
# ssh3-c-server.socket (excerpt)
[Socket]
ListenDatagram=0.0.0.0:443
FreeBind=yes

# ssh3-c-server.service (excerpt)
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
sudo systemctl enable --now ssh3-c-server.socket
```

Port variation goes through a drop-in, not an edit of the unit:

```bash
sudo systemctl edit ssh3-c-server.socket
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

## Performance

Medians of the control benchmark (methodology R3, `bench/p7-compare.sh`):
WSL2 loopback, one ed25519 keypair for all three implementations,
sha-verified transfers, 7 rounds per cell (the first is the warmup).
The full tables and the environment notes —
[docs/BENCH-V0.2.0-2026-10-13.md](docs/BENCH-V0.2.0-2026-10-13.md).

| № | Metric | ssh3-c | Go fork 0.1.34 | OpenSSH 9.6 |
|---|--------|--------|----------------|-------------|
| 1 | 512 MiB sftp push / pull, MB/s | 354 / 265 | 29 / 37 | **414 / 456** |
| 5 | Каталог 4000×4 КиБ push / pull, files/s | 1843 / 1887 | **4329 / 3565** | 1339 / 1251 |
| 2 | Handshake, cold connect+auth+exec, ms | **113** (min 12) | 180 | 220 |
| 3 | ControlMaster warm exec, ms | **7.5** | 8.8 | 12.9 |
| 4 | Server CPU / RSS peak, 512 MiB push | 80% / 526 MB \* | 96% / 21 MB | 106% / 28 MB |

\* the sftp server path buffers the whole inbound file — a known issue
(backlog §8.12 in [docs/PLAN.md](docs/PLAN.md)).

## License

The project's own code — BSD 2-clause (`LICENSE`). The code adapted
from nginx (BSD 2-clause) is listed in `THIRD-PARTY-NOTICES.md` — its
headers keep `Copyright (C) Nginx, Inc.`.
