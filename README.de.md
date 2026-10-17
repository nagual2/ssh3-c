# ssh3-c

[English](README.md) | [Русский](README.ru.md) | **Deutsch**

## Dokumentation

Alle Projektdokumente sind dreisprachig (ein `> Languages:`-Banner in
jeder Datei verweist auf die Versionen). Der kanonische Text der
`docs/`-Dokumente ist Russisch; EN/DE sind getreue Übersetzungen.

| № | Dokument | Inhalt | Sprachen |
|---|----------|--------|----------|
| 1 | [docs/PLAN.md](docs/PLAN.md) | Entwicklungsplan: Phasen P0–P9, Abnahme-Historie der Wellen, offener Backlog | RU · [EN](docs/PLAN.en.md) · [DE](docs/PLAN.de.md) |
| 2 | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | die Schichtarchitektur: core/event/quic/h3/ssh3/app, Zero-Copy-Konventionen | RU · [EN](docs/ARCHITECTURE.en.md) · [DE](docs/ARCHITECTURE.de.md) |
| 3 | [docs/SPEC-wire.md](docs/SPEC-wire.md) | die Spezifikation des SSH3-Wire-Protokolls (rev nagual2/1, draft 1) | RU · [EN](docs/SPEC-wire.en.md) · [DE](docs/SPEC-wire.de.md) |
| 4 | [docs/P4-WIRE.md](docs/P4-WIRE.md) | historisches Destillat: Kanal-Lebenszyklus und Datagram-Routing (Welle 2) | RU · [EN](docs/P4-WIRE.en.md) · [DE](docs/P4-WIRE.de.md) |
| 5 | [docs/PORTING-nginx-quic.md](docs/PORTING-nginx-quic.md) | Portierungs-Journal: die nginx-QUIC-Schicht → ssh3-c | RU · [EN](docs/PORTING-nginx-quic.en.md) · [DE](docs/PORTING-nginx-quic.de.md) |
| 6 | [docs/DEPS-QUIC.md](docs/DEPS-QUIC.md) | Abhängigkeiten und Lizenzen des QUIC-Stacks (OpenSSL ≥3.5 QUIC-API) | RU · [EN](docs/DEPS-QUIC.en.md) · [DE](docs/DEPS-QUIC.de.md) |
| 7 | [docs/BENCH-METRICS.md](docs/BENCH-METRICS.md) | Benchmark-Methodik und -Metriken (R3) | RU · [EN](docs/BENCH-METRICS.en.md) · [DE](docs/BENCH-METRICS.de.md) |
| 8 | [docs/BENCH-P7-2026-10-06.md](docs/BENCH-P7-2026-10-06.md) | Benchmark-Bericht, Phase P7 | RU · [EN](docs/BENCH-P7-2026-10-06.en.md) · [DE](docs/BENCH-P7-2026-10-06.de.md) |
| 9 | [docs/BENCH-V0.2.0-2026-10-13.md](docs/BENCH-V0.2.0-2026-10-13.md) | Benchmark-Bericht, Release v0.2.0 | RU · [EN](docs/BENCH-V0.2.0-2026-10-13.en.md) · [DE](docs/BENCH-V0.2.0-2026-10-13.de.md) |
| 10 | [docs/BENCH-V0.3.0-2026-10-15.md](docs/BENCH-V0.3.0-2026-10-15.md) | Benchmark-Bericht, Release v0.3.0 | RU · [EN](docs/BENCH-V0.3.0-2026-10-15.en.md) · [DE](docs/BENCH-V0.3.0-2026-10-15.de.md) |
| 11 | [packaging/README.md](packaging/README.md) | Bau der Distributionspakete (deb/rpm/apk/OpenWrt, gebündeltes OpenSSL) | EN · [RU](packaging/README.ru.md) · [DE](packaging/README.de.md) |
| 12 | [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) | Copyright- und Lizenzhinweise Dritter (juristischer Text, nicht übersetzt) | EN |

Eine SSH3-Implementierung in reinem C17 im nginx-Stil: Speicherpools,
Buffer-Sichten, ein Chain-Interface für sämtliche I/O, ein Zero-Copy-
Datenpfad. Die Zielpositionierung ist „OpenSSH unter den
Linux-Systemen" (siehe [docs/PLAN.md](docs/PLAN.md)).

Aktueller Stand: Die Phasen **P0–P1** sind fertig (der Core plus die
Event/UDP-Schicht, der GSO-Benchmark); die Vorbereitung von **P2**
läuft — die Anpassung der nginx-QUIC-Schicht (siehe
[docs/PLAN.md](docs/PLAN.md)).

## Aufbau

| № | Verzeichnis | Inhalt |
|---|-------------|--------|
| 1 | `src/core/` | Speicherpool (`s3_palloc`), Buffer und Chains (`s3_buf`), Strings (`s3_string`, `s3_str`), rbtree (`s3_rbtree`), intrusive Liste (`s3_queue`), Logging (`s3_log`), der Aggregator `s3_core.h` |
| 2 | `src/event/` | Event-Loop, Timer, posted Events (`s3_event`), Verbindungen (`s3_connection`), UDP-Pseudoverbindungen (`s3_event_udp`), das epoll-Backend (`modules/s3_epoll_module`) |
| 3 | `src/os/unix/` | errno-Schicht (`s3_errno`), UDP-sendmsg-Chain (`s3_udp_sendmsg_chain`), UDP-recv (`s3_udp_recv`) |
| 4 | `bench/` | `gso_bench` — ein UDP-GSO-Microbenchmark (`UDP_SEGMENT`) gegen plain sendmsg |
| 5 | `tests/` | Unit-Tests (das Mikro-Framework `s3_test.h`, ohne Abhängigkeiten) |

## Build (aus WSL)

```bash
cd /mnt/c/Git/project/ssh3-c
cmake --preset linux-release
cmake --build --preset linux-release
ctest --preset linux-release --output-on-failure
```

## Sanitizer (ASan + UBSan)

```bash
cmake --preset linux-asan
cmake --build --preset linux-asan
ctest --preset linux-asan --output-on-failure
```

## Installation

Aus den Distributionspaketen (die Quellen in `packaging/` bauen sie für
deb/rpm/apk und OpenWrt-ipk):

```bash
sudo apt install ssh3-server
```

Der Paketumfang:

| № | Datei | Zweck |
|---|-------|-------|
| 1 | `/usr/sbin/ssh3-server` | der Daemon |
| 2 | `/etc/ssh3/cert.pem` | TLS-Zertifikat (PEM) |
| 3 | `/etc/ssh3/key.pem` | privater Schlüssel (PEM, `0640 root:ssh3`) |
| 4 | `/etc/ssh3/authorized_keys` | Schlüssel für den Bearer-JWT-Login (`-K`) |
| 5 | `/usr/share/man/man8/ssh3-server.8` | die Manpage |
| 6 | `/usr/lib/systemd/system/ssh3-server.{socket,service}` | systemd-Units |

Aus den Quellen (eine Install-Rule gibt es noch nicht, das Binary
bleibt im Build-Baum):

```bash
cd /path/to/ssh3-c
cmake --preset linux-release && cmake --build --preset linux-release
# build/linux-release/ssh3-server
```

## systemd (Socket-Aktivierung)

Das Unit-Paar teilt die Port-Privilegie vom Dienst: das root-eigene
`ssh3-c-server.socket` bindet UDP/443, und systemd übergibt das
fertige Datagram-fd an `ssh3-c-server.service`.  Seit P7.3 läuft der
Dienst als root mit **per-session setuid**: nach der Authentifizierung
wechselt jede Sitzung mit einem auflösbaren CONNECT-Benutzernamen vor
dem Spawn auf diese Identität (`initgroups`, `setgid`, `setuid`,
`chdir` ins Home) — die OpenSSH/sshd-Form; der Daemon selbst behält
ein minimales Bounding-Set
(`CAP_CHOWN CAP_DAC_READ_SEARCH CAP_SETGID CAP_SETUID`) und braucht
**kein** `CAP_NET_BIND_SERVICE` (der Daemon übernimmt das übergebene
fd, er ruft `bind()` nie selbst auf):

```ini
# ssh3-c-server.socket (Ausschnitt)
[Socket]
ListenDatagram=0.0.0.0:443
FreeBind=yes

# ssh3-c-server.service (Ausschnitt)
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

Ein Benutzer ohne passwd-Eintrag erhält bereits beim CONNECT ein 401;
ein CONNECT ohne Sitzungsbenutzernamen belässt die Identität des
Daemons.  Die identitätseinfache unprivilegierte Variante
(`User=ssh3`, `--run-as-user off`, die P7.2-Härtung) ist in den
Unit-Kommentaren und `man/ssh3-server.8` (`PRIVILEGE MODEL`)
beschrieben.

```bash
sudo systemctl enable --now ssh3-c-server.socket
```

Die Port-Änderung läuft über einen Drop-in, nicht über eine Bearbeitung
des Units:

```bash
sudo systemctl edit ssh3-c-server.socket
# [Socket]
# ListenDatagram=0.0.0.0:8443
```

## Konfiguration

CLI-Flags (Standardwerte aus `ssh3-server -h`):

| Flag | Standard | Beschreibung |
|------|----------|--------------|
| `-l addr:port` | — | UDP-Listen (IPv4), Port `0` — ephemeral; bei Socket-Aktivierung nicht nötig |
| `-c cert.pem` | — | TLS-Zertifikat (PEM), erforderlich |
| `-k key.pem` | — | privater Schlüssel (PEM), erforderlich |
| `-A alpn` | `h3` | der ALPN-Name |
| `-d dg_size` | `1200` | QUIC `max_datagram_frame_size` |
| `-i idle_ms` | `60000` | QUIC-Idle-Timeout, ms |
| `-L level` | `info` | Log-Level: `debug\|info\|warn\|error\|all` oder numerisch |
| `-P pwfile` | — | die Passwortdatei `user:secret` (Basic-Authentifizierung) |
| `-K authorized_keys` | — | authorized_keys für Bearer-JWT (`%u` — der Benutzername im Pfad) |
| `-H dir` | das Benutzer-Home | das sftp-Jail-Verzeichnis |
| `--oidc-issuer url` | — | der OIDC-Provider (id_token) |
| `--oidc-audience id` | — | die erwartete Audience (Client-ID) |
| `--oidc-jwks-ttl sec` | `3600` | die Lebensdauer des JWKS-Satzes |
| `--run-as-user on\|off` | `on` unter euid 0 | per-session setuid: eine Sitzung mit auflösbarem CONNECT-Benutzer wechselt vor dem Spawn auf dessen Identität |
| `-v` / `-V` / `-h` | — | Debug-Logging / Version / Usage |

Umgebungsvariablen:

| Variable | Standard | Beschreibung |
|----------|----------|--------------|
| `SSH3_LOG_LEVEL` | wie `-L` | das Log-Level |
| `SSH3_LOG_FILE` | stderr | die Log-Datei (unter systemd ignoriert) |
| `SSH3_SHUTDOWN_DRAIN` | `5` s | der Drain bei SIGTERM, `0` — sofort |
| `SSH3C_PROTO=1` | aus | die `INTEROP-*`-Runner-Marker auf stdout |
| `S3_OIDC_CA_FILE` | der System-Store | die CA für OIDC-Discovery/JWKS |
| `LISTEN_PID`/`LISTEN_FDS` | — | das Protokoll `sd_listen_fds(3)`, read-only |

Vollständige Referenz: `man 8 ssh3-server`.

## Code-Stil

- `.clang-format` / `.clang-tidy` liegen im Wurzelverzeichnis; die
  Prüfung:
  `clang-format --dry-run --Werror src/core/*.c src/core/*.h tests/*.c`.
- Der Build läuft mit `-Wall -Wextra -Werror`; das Preset `linux-asan`
  ergänzt `-fsanitize=address,undefined -fno-sanitize-recover=all`.

## Leistung

Mediane der Kontrollbenchmarks (Methodik R3, `bench/p7-compare.sh`):
WSL2-Loopback, ein ed25519-Schlüsselpaar für alle drei
Implementierungen, sha-verifizierte Übertragungen, 7 Runden pro Zelle
(die erste ist die Aufwärmrunde). Die vollständigen Tabellen und die
Hinweise zur Umgebung —
[docs/BENCH-V0.3.0-2026-10-15.md](docs/BENCH-V0.3.0-2026-10-15.md).

| № | Metrik | ssh3-c | Go-Fork 0.1.35 | OpenSSH 9.6 |
|---|--------|--------|----------------|-------------|
| 1 | 512 MiB sftp push / pull, MB/s | 353 / 354 | 28 / 33 | **358 / 421** |
| 2 | Handshake, cold connect+auth+exec, ms | **117** (min 15) | 172 | 221 |
| 3 | ControlMaster warm exec, ms | **7.6** | 9.0 | 13.8 |
| 4 | Server-CPU / RSS-Spitze, 512-MiB-push | **75% / 81 MB** | 104% / 26 MB | 104% / 26 MB |
| 5 | Verzeichnis 4000×4 KiB push / pull, files/s | **4667 / 4624** | 4103 / 3518 | 1175 / 1284 |

## Lizenz

Eigener Code — BSD 2-clause (`LICENSE`). Der aus nginx adaptierte Code
(BSD 2-clause) ist in `THIRD-PARTY-NOTICES.md` aufgeführt — seine
Header behalten `Copyright (C) Nginx, Inc.`.
