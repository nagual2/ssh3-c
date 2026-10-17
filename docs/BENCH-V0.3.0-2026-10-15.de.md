# Referenz-Benchmark v0.3.0: ssh3-c vs Go-Fork vs OpenSSH (Methodik R3)

> Languages: [RU](BENCH-V0.3.0-2026-10-15.md) · [EN](BENCH-V0.3.0-2026-10-15.en.md) · DE (this file)

Datum: 2026-10-15. Lauf: `bench/p7-compare.sh` (`--stage all` + `--stage
manyfiles --files 4000 --rounds 7`), rohe CSVs unter `~/p7bench/results/`.
Vorgänger: [BENCH-V0.2.0-2026-10-13.md](BENCH-V0.2.0-2026-10-13.md),
[BENCH-P7-2026-10-06.md](BENCH-P7-2026-10-06.md). Erläuterung der Metriken:
[BENCH-METRICS.md](BENCH-METRICS.md).

## Umgebung

| № | Parameter | Wert |
|---|----------|----------|
| 1 | Testaufbau | WSL2, loopback 127.0.0.1, Payload/Ausgabe auf tmpfs `/dev/shm`, WORK unter `~/p7bench` |
| 2 | ssh3-c | **v0.3.0** (bestätigt via `ssh3-server -V`), clang `linux-release` — im Baum: per-file-sftp-Pipeline und READ-RSS-Fix |
| 3 | Go-Fork | nagual2/ssh3 **0.1.35**, `CGO_ENABLED=0 -tags disable_password_auth` |
| 4 | OpenSSH | 9.6p1 Ubuntu, dedizierter sshd auf :2222 (`aes128-gcm@openssh.com`) |
| 5 | Hintergrund | Box unter Last (ambient); Rotation A→B→C, Mediane |

## 1. Throughput, sftp/scp (MB/s, Median aus 7 Runden, sha-verifiziert)

| № | Implementierung | 512 MiB push | 512 MiB pull | 8 MiB push | 8 MiB pull |
|---|------------|-------------:|-------------:|-----------:|-----------:|
| 1 | OpenSSH (scp) | **357.6** | **421.1** | 20.5 | **29.6** |
| 2 | ssh3-c (sftp, Pipeline) | 353.4 | 353.6 | 16.6 | 16.6 |
| 3 | Go-Fork (sftp-Subsystem) | 27.8 | 33.0 | 19.1 | 25.7 |

Fazit: ssh3-c hat auf push zu scp aufgeschlossen (99%) und die Lücke auf
pull auf 84% verengt; die Richtungen haben sich einander angeglichen
(353/354 — Folge der Pipeline und des Write-Through-Fixes). 8 MiB bleibt ein
setup-dominiertes Szenario, wie zuvor.

## 2. Handshake, cold connect+auth+exec (ms, 30 Durchläufe)

| № | Implementierung | median | min | p95 | max |
|---|------------|-------:|----:|----:|----:|
| 1 | ssh3-c | **117.3** | 15.1 | 121.1 | 126.4 |
| 2 | Go-Fork | 171.6 | 156.4 | 243.2 | 245.2 |
| 3 | OpenSSH | 221.4 | 213.9 | 231.3 | 249.0 |

## 3. ControlMaster, warm exec `true` (ms, 300 Iterationen)

| № | Implementierung | median | min |
|---|------------|-------:|----:|
| 1 | ssh3-c | **7.6** | 5.8 |
| 2 | Go-Fork | 9.0 | 7.5 |
| 3 | OpenSSH | 13.8 | 11.6 |

## 4. CPU / RAM des Servers bei 512 MiB push (frischer Daemon, 50-ms-Samples)

| № | Implementierung | CPU (Prozessbaum) | RSS-Spitze |
|---|------------|-------------:|--------:|
| 1 | ssh3-c | **75.1%** | 81 MB |
| 2 | Go-Fork | 103.8% | **26 MB** |
| 3 | OpenSSH | 104.2% | 26 MB |

Der READ-Puffer-RSS-Fix (Backlog §8.12) ist im Live-Benchmark bestätigt:
81 MB gegenüber 526 MB vor dem Fix; CPU — der niedrigste Wert der drei.

## 5. Manyfiles: Verzeichnis 4000 × 4 KiB (files/s, Median aus 7/7 Runden)

| № | Implementierung | push | pull |
|---|------------|-----:|-----:|
| 1 | ssh3-c (`-J -r`, Pipeline) | **4667** | **4624** |
| 2 | Go-Fork (`-f -r`) | 4103 | 3518 |
| 3 | OpenSSH (`scp -r`) | 1175 | 1284 |

ssh3-c ist dem Go-Fork in beiden Richtungen voraus (×1.14 push, ×1.31 pull)
und schlägt scp um Faktor 4. Anmerkung: Im Parallel-Lauf des
2000er-Verzeichnisses hatte C 3 transiente Verwerfungen (seed/pull unter
ambient-Last) — bei 4000 sind die Runden 7/7 sauber.

## Anmerkungen zum Durchlauf

| № | Was | Details |
|---|-----|--------|
| 1 | Das Binary des ersten Durchlaufversuchs meldete sich als 0.2.0 | Messung gestoppt, Baum auf 0.3.0 neu gebaut (via `-V` bestätigt), Durchlauf wiederholt |
| 2 | 1 Verwerfung von c-pull in der 512m-Tabelle | sha-Gate griff, Runde neu gefahren — Endstand n=7 gültig |

## Reproduktion

```bash
# в WSL: go-бинарники в ~/p7bench/bin (CGO_ENABLED=0 -tags
# disable_password_auth из project/ssh3), WORK на ~/p7bench
bash bench/p7-compare.sh --stage all --work ~/p7bench \
    --c-build /mnt/c/Git/project/ssh3-c/build/linux-release \
    --go-bin ~/p7bench/bin
bash bench/p7-compare.sh --stage manyfiles --files 4000 --rounds 7 \
    --work ~/p7bench --c-build /mnt/c/Git/project/ssh3-c/build/linux-release \
    --go-bin ~/p7bench/bin
```
