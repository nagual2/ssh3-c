# Kontroll-Benchmark v0.2.0: ssh3-c vs Go-Fork vs OpenSSH (Methodik R3)
> Languages: [RU](BENCH-V0.2.0-2026-10-13.md) · [EN](BENCH-V0.2.0-2026-10-13.en.md) · DE (this file)

Datum: 2026-10-13. Lauf: `bench/p7-compare.sh` (Repo), rohe CSVs —
`/tmp/p7bench/results/` (landen nicht im Repo). Vorgänger:
[BENCH-P7-2026-10-06.md](BENCH-P7-2026-10-06.md) (v0.1.0, sftp kaputt).
Aufschlüsselung der Metriken und der Methodik-Prinzipien — [BENCH-METRICS.md](BENCH-METRICS.md).

## Umgebung

| № | Parameter | Wert |
|---|----------|----------|
| 1 | Teststand | WSL2, loopback 127.0.0.1, payload/Ausgabe auf tmpfs `/dev/shm` |
| 2 | Hardware | AMD Ryzen 5 4600H (AES-NI), 12 Threads, 7.6 GiB RAM |
| 3 | ssh3-c | v0.2.0, `linux-release` (clang), Daemon :8022/udp (JWT pubkey `-K`), Client `s3interop_client` |
| 4 | Go-Fork | nagual2/ssh3 **0.1.34**, `CGO_ENABLED=0 -tags disable_password_auth`, Server :8023/udp, Client `-insecure -privkey` |
| 5 | OpenSSH | 9.6p1 Ubuntu, dedizierter sshd :2222 (`aes128-gcm@openssh.com`, BatchMode) |
| 6 | Authentifizierung | ein ed25519-Schlüsselpaar: PKCS8 PEM (JWT-Clients C und Go), OpenSSH-Format (ssh/scp) |
| 7 | Hintergrund | auf dem Kasten läuft dauerhaft ein Dienst mit ~30% eines Kerns; die Rotation der Implementierungen A→B→C gleicht ambient aus |

Messung: `date +%s%N` um die Übertragung herum, jeder Transfer per
sha256 verifiziert (außerhalb des gemessenen Fensters), die erste Runde
ist Aufwärmen, Mediane.

## 1. Throughput, sftp/scp (MB/s, Median von 7 Runden, sha-verifiziert)

| № | Implementierung | 512 MiB push | 512 MiB pull | 8 MiB push | 8 MiB pull |
|---|------------|-------------:|-------------:|-----------:|-----------:|
| 1 | OpenSSH (scp, Dateikopie) | **413.6** | **456.0** | 20.8 | **35.4** |
| 2 | ssh3-c (sftp-Kanal, `-J`) | 353.9 | 265.2 | 16.6 | 16.6 |
| 3 | Go-Fork (sftp-Subsystem) | 29.4 | 37.2 | 21.5 | 28.2 |

Auswertung:

1. ssh3-c zum ersten Mal in der 512-MiB-Tabelle: nach P7.1 liegt push
   auf OpenSSH-Niveau (86%), pull 58%; der Go-Fork liegt beim push 12×
   zurück.
2. 8 MiB — die Tabelle wird vom Session-Setup dominiert (handshake +
   Öffnen der Kanäle + Verdict); die konstanten ~16.6 MB/s von C sind
   der Preis des Connects, nicht des Kanals; alle drei innerhalb von 2×.
3. Das Go-sftp-Subsystem ist langsamer als die eigene exec-Pipe des
   Forks (kanonische 130–365 MB/s, `BENCH-2026-09-29`) — wie schon im
   Oktober.

## 2. Handshake, cold connect+auth+exec (ms; drei unabhängige Läufe à 30)

| № | Implementierung | Lauf 1 | Lauf 2 | Lauf 3 | min |
|---|------------|---------:|---------:|---------:|----:|
| 1 | ssh3-c | 113.2 | 113.6 | 113.5 | 11.4 |
| 2 | Go-Fork | 165.4 | 185.0 | 179.9 | 157.6 |
| 3 | OpenSSH | 220.2 | 220.3 | 224.2 | 210.1 |

Auswertung:

1. ssh3-c — der Median ist reproduzierbar (±0.5 ms), min 11–12 ms. Die
   Verteilung von C ist bimodal (~12 ms und ~113 ms, der Sprung von
   ~100 ms liegt auf dem Verdict-Pfad des Harness-Clients; nicht der
   Transport), Go ebenfalls (160/250).
2. Die Ordnung c < go < os bleibt in allen Läufen erhalten; C ist nach
   Median ~2× schneller als OpenSSH.

## 3. Multiplexte Sessions (ControlMaster, warm exec `true`)

| № | Implementierung | median | p95 | gültige |
|---|------------|-------:|----:|----------|
| 1 | ssh3-c (`-3 -C -M`) | **7.5 ms** | 109.0 | 300/300 |
| 2 | Go-Fork (control-master) | 8.8 ms | 16.2 | 300/300 |
| 3 | OpenSSH (ControlMaster) | 12.9 ms | 16.2 | 300/300 |

C hat den besten Median (der p95 wird von derselben ~100-ms-Bimodalität
aufgebläht), 300/300 Sessions pro Master, das Limit von 15 ist weg
(P7.1).

## 4. Server-CPU/RAM bei 512 MiB sftp/scp push (frischer Daemon, 50-ms-Samples)

| № | Implementierung | CPU (Baum) | RSS-Spitze |
|---|------------|-------------:|--------:|
| 1 | OpenSSH (sshd) | 105.6% | 28 MB |
| 2 | Go-Fork | 95.6% | 21 MB |
| 3 | ssh3-c | 79.5% | **526 MB** |

**Befund**: der sftp-Pfad des ssh3-c-Servers hält ~die gesamte
eingehende Datei im Speicher (Spitze ≈ payload-Größe + Overhead,
High-Water nach einer Serie von 512-MiB-Transfers — 1.8 GB), während
die Erwartung aus dem pipeline-Fenster ~32 MiB beträgt (32 inflight ×
1 MiB Stream-Credit). In den Backlog PLAN.md §8.12 eingetragen. Die CPU
liegt dabei niedriger als bei beiden Konkurrenten.

## 5. Manyfiles: Verzeichnis 4000 × 4 KiB (files/s, Median von 7 Runden, Verifikation nach Anzahl und Volumen)

| № | Implementierung | push (Mechanismus) | pull |
|---|------------|----------------:|-----:|
| 1 | Go-Fork (`-f -r`) | **4329** | **3565** |
| 2 | ssh3-c (`-J -r`) | 1843 | 1887 |
| 3 | OpenSSH (`scp -r`) | 1339 | 1251 |

Auswertung:

1. Die Größe N=4000 wurde empirisch kalibriert: bei 500 Dateien
   näherten sich c/go innerhalb des Timer-Rauschens an, bei 4000 sind
   alle paarweisen Unterschiede ≥ 35% bei einer Streuung der Runden von
   ±10% (min/max im CSV-Bericht).
2. Der Go-Fork führt beim Baum aus kleinen Dateien (tiefe Pipeline aus
   per-file-Operationen); ssh3-c macht es seriell (OPEN/CLOSE pro
   Roundtrip pro Datei) — ~2.3× zurück, aber vor scp -r (~1.4×).
3. Der Lauf deckte zwei Defekte im Client-Pfad auf und behob sie
   (siehe §6): stiller Stack-Overflow in der h3-CONNECT-Sektion und ein
   downloadDir-Absturz beim Fehlschlag des root-STAT — get_r kam vor
   diesem Lauf weder in der Matrix noch bei der Windows-Abnahme zum
   Einsatz.

### Follow-up 2026-10-14: per-file-Fenster des Clients (Punkt geschlossen)

Per-Datei-Pipelining von put_r/get_r ist im Client-Treiber implementiert
(`s3_ssh3_sftp_cli.c`): ein Fenster von `S3_SSH3_SFTP_CLI_FILES = 4`
Slots für die Dateien eines Verzeichnisses (während Datei N Chunks
streamt, ist Datei N+1 bereits OPEN); jeder Slot trägt einen lokalen fd,
ein remote handle, Cursor (offset/emit_off) und einen SHA-256-Digest
(verify=1 — Digest pro Slot); das Dispatching der Antworten wurde von
der Phase des Ops auf Anfrage-Einträge im Ring umgestellt (`s3_cli_req_t
{kind, slot, len}` — eine Antwort wird über den Eintrag der ältesten
unvollendeten Anfrage geroutet); die Rekursion der Unterbäume
(mkdir-Ebenen, OPENDIR/READDIR/CLOSEDIR) blieb seriell und fährt im
selben Ring mit One-Request-Einträgen (walk_busy). Ein Datei-Fail wirft
die Operation nicht um: der Slot drainiert die outstanding-Antworten,
schließt das handle über das Fenster und wird freigegeben; die
walk-alive-Semantik der Referenz und das terminale FAIL bei leerem
Frame-Stack bleiben erhalten (Canned-Test `s3_test_cli_walk_missing`).

manyfiles 4000×4 KiB (Median von 3 Runden, derselbe Teststand): c push
5319 files/s (vorher 1843, ×2.9), c pull 5006 (vorher 1887, ×2.7) — der
Client überholt den Go-Fork (push 5031, pull 4206) und scp -r. Die
Annahmeschwelle (c push ≥ 3000) ist übertroffen; Tiefe 2 ergab 3646
push / 3367 pull — 4 blieb als Fenster-Kompromiss.

## 6. Durch den manyfiles-Lauf aufgedeckte Defekte (behoben)

| № | Defekt | Symptom | Fix |
|---|--------|---------|------|
| 1 | `u_char frame[512]` im Harness: die CONNECT-Sektion mit JWT-Autorisierung (~506+ B für ed25519) lief über den Puffer hinaus | stille Stack-Korruption im Release (SEGV in s3_cli_step), ASan fing es bei memcpy | `frame[1024]` + lauter Guard an der Stelle (total > sizeof → exit) |
| 2 | `s3_cli_file_fail` bei `frame_count == 0` (Fehlschlag des root-STAT von downloadDir) setzte die Phase auf WALK | `frames[-1]` → SEGV in get_r_walk | terminales FAIL des Ops bei leerem Frame-Stack |
| 3 | der Harness setzte die Rekursion nicht: die Bibliothek `put_r/get_r` existierte, `-J` rief die Einzeldatei-Formen auf | `-r` bei `-J` funktionierte nicht | `-r` in getopt, Aufruf von `put_r/get_r` |


## Skript-Korrekturen, die der Lauf aufdeckte

| № | Defekt | Fix |
|---|--------|------|
| 1 | `gen_payload`: `dd bs=4M count=512` erzeugte einen 2-GiB-payload statt der nominellen 512 MiB — die 512-Stufe scheiterte mit ENOSPC auf /dev/shm schon beim ersten Transfer | `bs=1M` |
| 2 | die 512-MiB-Tabelle und die cpu-Stufe trugen den Stand von vor P7.1 (C „auf Dutzende Minuten“ ausgeschlossen) | C nimmt gleichberechtigt teil |
| 3 | `--stage handshake` hob den Teststand nicht (die Stufe fehlte in der `start_servers`-Liste) — der Lauf lief gegen tote Server | Stufe ergänzt |
| 4 | `stop_servers` wartete nicht auf den Tod des Daemons — das graceful drain hielt den UDP-Port bis zu 5 s, die nächste Stufe scheiterte mit „bind busy“ | `wait_gone` + kill -9-Eskalation |

## Reproduktion

```bash
# в WSL: сборки C (build/linux-release) и Go-бинарники в /tmp/p7bench/bin
CGO_ENABLED=0 ~/opt/go1.27.1/bin/go build -tags disable_password_auth \
    -o /tmp/p7bench/bin/ssh3 ./cmd/ssh3
CGO_ENABLED=0 ~/opt/go1.27.1/bin/go build -tags disable_password_auth \
    -o /tmp/p7bench/bin/ssh3-server ./cmd/ssh3-server
bash bench/p7-compare.sh --stage all \
    --c-build /mnt/c/Git/project/ssh3-c/build/linux-release \
    --go-bin /tmp/p7bench/bin          # ~15 мин
```
