# Control bench v0.2.0: ssh3-c vs Go fork vs OpenSSH (R3 methodology)
> Languages: [RU](BENCH-V0.2.0-2026-10-13.md) · EN (this file) · [DE](BENCH-V0.2.0-2026-10-13.de.md)

Date: 2026-10-13. Run: `bench/p7-compare.sh` (repo), raw CSVs —
`/tmp/p7bench/results/` (not checked into the repo). Predecessor:
[BENCH-P7-2026-10-06.md](BENCH-P7-2026-10-06.md) (v0.1.0, sftp broken).
Metrics and methodology principles are broken down in [BENCH-METRICS.md](BENCH-METRICS.md).

## Environment

| № | Parameter | Value |
|---|----------|----------|
| 1 | Rig | WSL2, loopback 127.0.0.1, payload/output on tmpfs `/dev/shm` |
| 2 | Hardware | AMD Ryzen 5 4600H (AES-NI), 12 threads, 7.6 GiB RAM |
| 3 | ssh3-c | v0.2.0, `linux-release` (clang), daemon :8022/udp (JWT pubkey `-K`), client `s3interop_client` |
| 4 | Go fork | nagual2/ssh3 **0.1.34**, `CGO_ENABLED=0 -tags disable_password_auth`, server :8023/udp, client `-insecure -privkey` |
| 5 | OpenSSH | 9.6p1 Ubuntu, dedicated sshd :2222 (`aes128-gcm@openssh.com`, BatchMode) |
| 6 | Authentication | single ed25519 keypair: PKCS8 PEM (JWT clients C and Go), OpenSSH format (ssh/scp) |
| 7 | Background | a service runs constantly on the box at ~30% of one core; rotating implementations A→B→C evens out ambient |

Timing: `date +%s%N` around the transfer, every transfer sha256-verified
(outside the measured window), the first round is warm-up, medians.

## 1. Throughput, sftp/scp (MB/s, median of 7 rounds, sha-verified)

| № | Implementation | 512 MiB push | 512 MiB pull | 8 MiB push | 8 MiB pull |
|---|------------|-------------:|-------------:|-----------:|-----------:|
| 1 | OpenSSH (scp, file copy) | **413.6** | **456.0** | 20.8 | **35.4** |
| 2 | ssh3-c (sftp channel, `-J`) | 353.9 | 265.2 | 16.6 | 16.6 |
| 3 | Go fork (sftp subsystem) | 29.4 | 37.2 | 21.5 | 28.2 |

Reading:

1. ssh3-c in the 512 MiB table for the first time: after P7.1 push is at
   OpenSSH's level (86%), pull 58%; the Go fork is 12× behind on push.
2. 8 MiB — the table is dominated by session setup (handshake + opening
   channels + verdict); C's steady ~16.6 MB/s is the price of the
   connect, not of the channel; all three within 2× of one another.
3. The Go sftp subsystem is slower than the fork's own exec pipe
   (canonical 130–365 MB/s, `BENCH-2026-09-29`) — same as in October.

## 2. Handshake, cold connect+auth+exec (ms; three independent runs of 30)

| № | Implementation | run 1 | run 2 | run 3 | min |
|---|------------|---------:|---------:|---------:|----:|
| 1 | ssh3-c | 113.2 | 113.6 | 113.5 | 11.4 |
| 2 | Go fork | 165.4 | 185.0 | 179.9 | 157.6 |
| 3 | OpenSSH | 220.2 | 220.3 | 224.2 | 210.1 |

Reading:

1. ssh3-c — the median is reproducible (±0.5 ms), min 11–12 ms. C's
   distribution is bimodal (~12 ms and ~113 ms, the ~100 ms step sits on
   the harness client's verdict path; not the transport), Go's too
   (160/250).
2. The order c < go < os holds in all runs; C is ~2× faster than OpenSSH
   by median.

## 3. Multiplexed sessions (ControlMaster, warm exec `true`)

| № | Implementation | median | p95 | valid |
|---|------------|-------:|----:|----------|
| 1 | ssh3-c (`-3 -C -M`) | **7.5 ms** | 109.0 | 300/300 |
| 2 | Go fork (control-master) | 8.8 ms | 16.2 | 300/300 |
| 3 | OpenSSH (ControlMaster) | 12.9 ms | 16.2 | 300/300 |

C has the best median (p95 is inflated by the same ~100 ms bimodality),
300/300 sessions per master, the limit of 15 is gone (P7.1).

## 4. Server CPU/RAM on 512 MiB sftp/scp push (fresh daemon, 50 ms samples)

| № | Implementation | CPU (tree) | RSS peak |
|---|------------|-------------:|--------:|
| 1 | OpenSSH (sshd) | 105.6% | 28 MB |
| 2 | Go fork | 95.6% | 21 MB |
| 3 | ssh3-c | 79.5% | **526 MB** |

**Finding**: the ssh3-c server sftp path keeps ~the entire incoming file
in memory (peak ≈ payload size + overhead, high-water after a series of
512 MiB transfers — 1.8 GB), whereas the pipeline window's expectation
is ~32 MiB (32 inflight × 1 MiB stream credit). Logged to the PLAN.md
§8.12 backlog. CPU is lower than both competitors.

## 5. Manyfiles: directory 4000 × 4 KiB (files/s, median of 7 rounds, verified by count and volume)

| № | Implementation | push (mechanism) | pull |
|---|------------|----------------:|-----:|
| 1 | Go fork (`-f -r`) | **4329** | **3565** |
| 2 | ssh3-c (`-J -r`) | 1843 | 1887 |
| 3 | OpenSSH (`scp -r`) | 1339 | 1251 |

Reading:

1. The size N=4000 was calibrated empirically: at 500 files c/go
   converged within timer noise, at 4000 all pairwise differences are
   ≥ 35% with a round-to-round spread of ±10% (min/max in the CSV report).
2. The Go fork leads on the small-file tree (deep pipeline of per-file
   operations); ssh3-c does it serially (OPEN/CLOSE per roundtrip per
   file) — ~2.3× behind, but ahead of scp -r (~1.4×).
3. The run exposed and fixed two defects in the client path (see §6):
   a silent stack overflow in the h3 CONNECT section and a downloadDir
   crash on root STAT failure — get_r had been exercised neither in the
   matrix nor in Windows acceptance before this run.

### Follow-up 2026-10-14: per-file client window (item closed)

Per-file pipelining of put_r/get_r is implemented in the client driver
(`s3_ssh3_sftp_cli.c`): a window of `S3_SSH3_SFTP_CLI_FILES = 4` slots
for the files of one directory (while file N streams chunks, file N+1
is already OPEN); each slot carries a local fd, a remote handle, cursors
(offset/emit_off) and a SHA-256 digest (verify=1 — per-slot digest);
response dispatch was moved from the op's phase to request records in
the ring (`s3_cli_req_t {kind, slot, len}` — a response is routed by
the record of the oldest outstanding request); subtree recursion (mkdir
levels, OPENDIR/READDIR/CLOSEDIR) stayed serial and rides the same ring
with one-request records (walk_busy). A file failure does not bring the
operation down: the slot drains outstanding responses, closes the handle
through the window, and is freed; the reference's walk-alive semantics
and the terminal FAIL on an empty frame stack are preserved (canned test
`s3_test_cli_walk_missing`).

manyfiles 4000×4 KiB (median of 3 rounds, same rig): c push 5319
files/s (was 1843, ×2.9), c pull 5006 (was 1887, ×2.7) — the client
overtook the Go fork (push 5031, pull 4206) and scp -r. The acceptance
threshold (c push ≥ 3000) is exceeded; depth 2 gave 3646 push / 3367
pull — 4 was kept as the window compromise.

## 6. Defects exposed by the manyfiles run (fixed)

| № | Defect | Symptom | Fix |
|---|--------|---------|------|
| 1 | `u_char frame[512]` in the harness: the CONNECT section with JWT authorization (~506+ B for ed25519) overflowed the buffer | silent stack corruption in release (SEGV in s3_cli_step), ASan caught it at memcpy | `frame[1024]` + a loud guard at the site (total > sizeof → exit) |
| 2 | `s3_cli_file_fail` at `frame_count == 0` (root STAT failure of downloadDir) set the phase to WALK | `frames[-1]` → SEGV in get_r_walk | terminal FAIL of the op on an empty frame stack |
| 3 | the harness did not enable recursion: the `put_r/get_r` library existed, `-J` called the single-file forms | `-r` of `-J` did not work | `-r` in getopt, calls to `put_r/get_r` |


## Script fixes exposed by the run

| № | Defect | Fix |
|---|--------|------|
| 1 | `gen_payload`: `dd bs=4M count=512` created a 2 GiB payload instead of the nominal 512 MiB — the 512 stage failed with ENOSPC on /dev/shm from the first transfer | `bs=1M` |
| 2 | the 512 MiB table and the cpu stage carried pre-P7.1 state (C excluded 'for tens of minutes') | C participates on equal footing |
| 3 | `--stage handshake` did not bring up the rig (the stage was missing from the `start_servers` list) — the run went against dead servers | stage added |
| 4 | `stop_servers` did not wait for daemon death — graceful drain held the UDP port for up to 5 s, the next stage failed with 'bind busy' | `wait_gone` + kill -9 escalation |

## Reproduction

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
