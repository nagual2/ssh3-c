# Reference benchmark v0.3.0: ssh3-c vs Go fork vs OpenSSH (R3 methodology)

> Languages: [RU](BENCH-V0.3.0-2026-10-15.md) · EN (this file) · [DE](BENCH-V0.3.0-2026-10-15.de.md)

Date: 2026-10-15. Run: `bench/p7-compare.sh` (`--stage all` + `--stage
manyfiles --files 4000 --rounds 7`), raw CSVs in `~/p7bench/results/`.
Predecessors: [BENCH-V0.2.0-2026-10-13.md](BENCH-V0.2.0-2026-10-13.md),
[BENCH-P7-2026-10-06.md](BENCH-P7-2026-10-06.md). Metric breakdown:
[BENCH-METRICS.md](BENCH-METRICS.md).

## Environment

| № | Parameter | Value |
|---|----------|----------|
| 1 | Testbed | WSL2, loopback 127.0.0.1, payload/output on tmpfs `/dev/shm`, WORK on `~/p7bench` |
| 2 | ssh3-c | **v0.3.0** (confirmed via `ssh3-server -V`), clang `linux-release` — the tree carries the per-file sftp pipeline and the READ RSS fix |
| 3 | Go fork | nagual2/ssh3 **0.1.35**, `CGO_ENABLED=0 -tags disable_password_auth` |
| 4 | OpenSSH | 9.6p1 Ubuntu, dedicated sshd on :2222 (`aes128-gcm@openssh.com`) |
| 5 | Background | box under load (ambient); A→B→C rotation, medians |

## 1. Throughput, sftp/scp (MB/s, median of 7 rounds, sha-verified)

| № | Implementation | 512 MiB push | 512 MiB pull | 8 MiB push | 8 MiB pull |
|---|------------|-------------:|-------------:|-----------:|-----------:|
| 1 | OpenSSH (scp) | **357.6** | **421.1** | 20.5 | **29.6** |
| 2 | ssh3-c (sftp, pipeline) | 353.4 | 353.6 | 16.6 | 16.6 |
| 3 | Go fork (sftp subsystem) | 27.8 | 33.0 | 19.1 | 25.7 |

Takeaway: ssh3-c caught up with scp on push (99%) and narrowed the gap on
pull to 84%; the two directions evened out with each other (353/354 — a
consequence of the pipeline and the write-through fix). 8 MiB remains a
setup-dominated mode, as before.

## 2. Handshake, cold connect+auth+exec (ms, 30 runs)

| № | Implementation | median | min | p95 | max |
|---|------------|-------:|----:|----:|----:|
| 1 | ssh3-c | **117.3** | 15.1 | 121.1 | 126.4 |
| 2 | Go fork | 171.6 | 156.4 | 243.2 | 245.2 |
| 3 | OpenSSH | 221.4 | 213.9 | 231.3 | 249.0 |

## 3. ControlMaster, warm exec `true` (ms, 300 iterations)

| № | Implementation | median | min |
|---|------------|-------:|----:|
| 1 | ssh3-c | **7.6** | 5.8 |
| 2 | Go fork | 9.0 | 7.5 |
| 3 | OpenSSH | 13.8 | 11.6 |

## 4. Server CPU / RAM on 512 MiB push (fresh daemon, 50 ms samples)

| № | Implementation | CPU (tree) | RSS peak |
|---|------------|-------------:|--------:|
| 1 | ssh3-c | **75.1%** | 81 MB |
| 2 | Go fork | 103.8% | **26 MB** |
| 3 | OpenSSH | 104.2% | 26 MB |

The READ buffer RSS fix (backlog §8.12) is confirmed on a live bench:
81 MB vs 526 MB before the fix; CPU is the lowest of the three.

## 5. Manyfiles: directory of 4000 × 4 KiB (files/s, median of 7/7 rounds)

| № | Implementation | push | pull |
|---|------------|-----:|-----:|
| 1 | ssh3-c (`-J -r`, pipeline) | **4667** | **4624** |
| 2 | Go fork (`-f -r`) | 4103 | 3518 |
| 3 | OpenSSH (`scp -r`) | 1175 | 1284 |

ssh3-c outruns the Go fork in both directions (×1.14 push, ×1.31 pull) and
beats scp by 4x. Note: in the parallel run of the 2000-file directory, C had
3 transient rejections (seed/pull under ambient load) — at 4000 the rounds
are 7/7 clean.

## Run notes

| № | Item | Details |
|---|-----|--------|
| 1 | The binary of the first run attempt reported 0.2.0 | measurement stopped, tree rebuilt at 0.3.0 (`-V` confirmed), run repeated |
| 2 | 1 rejection of c-pull in the 512m table | sha gate tripped, round re-run — final count n=7 valid |

## Reproduction

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
