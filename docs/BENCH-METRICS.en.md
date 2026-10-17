# Reference bench metrics (R3 methodology) — explained

> Languages: [RU](BENCH-METRICS.md) · EN (this file) · [DE](BENCH-METRICS.de.md)

A reference for the metrics of `bench/p7-compare.sh`: what exactly is measured, how,
and how to read the numbers. Fresh results —
[BENCH-V0.2.0-2026-10-13.md](BENCH-V0.2.0-2026-10-13.md); the October
snapshot — [BENCH-P7-2026-10-06.md](BENCH-P7-2026-10-06.md).

## General methodology principles

| № | Technique | Why |
|---|-------|-------|
| 1 | **Median, not mean** | Timing distributions are long-tailed: one outlier drags the mean away, but not the median. Reports use median + min + p95 + max |
| 2 | **Warm-up** (first round is discarded) | The first pass carries cold caches: first handshake, code warm-up, file creation |
| 3 | **Rotation of implementations A→B→C** | Rounds go in a circle (c→go→os→c→…), not in blocks — the box's background load falls evenly on all implementations |
| 4 | **sha256 gate** | A transfer counts only if the sha256 matches the source; the check sits **outside** the measured window. A corrupt transfer = a rejected round, not a pretty number |
| 5 | **One rig for all** | One ed25519 key (in two formats), one loopback, payloads on tmpfs — implementations are compared, not environments |

## 1. Throughput

**Operation.** Transferring a file whole: `push` = client → server, `pull` = server → client. The mechanisms honestly differ, and that is part of the result: OpenSSH — `scp` (a copy over the exec channel), the Go fork — the sftp subsystem, ssh3-c — the sftp channel of its own client.

**Measurement.** `date +%s%N` (nanosecond wall clock) around the entire transfer; MB/s = actual size / seconds. Wall-clock of the “user experience”, not an internal byte counter.

| № | Size | What it shows |
|---|--------|----------------|
| 1 | 512 MiB | Steady state: windows are fully open, the session cost is amortized — the pure speed of the **data channel** |
| 2 | 8 MiB | Setup-dominated mode: the fixed session cost (handshake + channel opening + verdict) is smeared over a small file — measures the cost of the **connection**, not the channel |

**Reading.** The QUIC family (C, Go) runs TLS+QUIC **in user space**, OpenSSH — TCP+AES-NI in the kernel: a structural difference between classes, not a defect. The constant MB/s at 8 MiB — the session cost divided by 8 MiB.

## 2. Handshake (cold connect+auth+exec)

**Operation.** The full cold cycle: client process start → QUIC handshake (TLS 1.3 over QUIC, 1-RTT) → authentication (JWT signed with Ed25519) → HTTP/3 Extended CONNECT → opening the session channel → exec no-op → exit code.

**Measurement.** Wall clock around **the entire client invocation, including process start** — that is why min shows the almost pure protocol cost.

**Reading.** The structural advantage of the QUIC family: 1-RTT handshake + one authorization round versus the TCP handshake + multi-round SSH2 authentication. The stability of OpenSSH (narrow spread) — kernel TCP without user-space scheduling.

## 3. Mux warm exec (multiplexed sessions)

**Operation.** Latency of a command **on top of an established master connection** (ControlMaster): slave → local socket/pipe → token → attaching the channels → exec → verdict. Handshake and authentication are not repeated.

**Measurement.** 3 blocks × 100 execs per implementation (each block — a fresh master), median over 300.

**Reading.** The automation/MCP profile: hundreds of commands in a single session. Here the QUIC handshake is already paid for — what competes is the mechanics of “dispatching a command”. Valid 300/300 also serve as proof of the master's stability (session limits, refusals).

## 4. Server CPU / RAM

**CPU.** A sampler reads `/proc/<pid>/stat` every 50 ms: the jiffies delta (USER_HZ=100) / real time → % of **a single core** (>100% — a tree of several processes; for sshd the measurement covers the whole tree). The measurement is one dedicated verified transfer with a fresh daemon.

**RAM.** Peak VmRSS from the same samples.

**Reading.** CPU shows the cost of crypto+copies on a saturated channel; RSS — the buffering strategy (windows versus “the whole file at once”). High RSS with normal CPU — the bottleneck is in memory, not in the processor.

## 5. Manyfiles (directory of small files)

**Operation.** Recursive transfer of a directory of N files of 4 KiB each (`scp -r` / fork `-f -r` / harness `-J -r`): `push` = uploading the tree, `pull` = downloading (the tree on the remote side is seeded **outside** the measured window by the same mechanism).

**Measurement.** Wall clock around the entire transfer; the result — files/s and aggregate MB/s; verification — the file count and total size at the receiver.

**Reading.** A metric of the per-file/per-request overhead of the protocol and of the client driver: N small transfers instead of one stream. N is calibrated empirically so that the spread between implementations exceeds the measurement error (see the N values in the reports).

## Summary: which metric answers which question

| № | Metric | User question |
|---|---------|--------------------|
| 1 | Throughput 512 MiB | “How fast can I transfer files?” |
| 2 | Throughput 8 MiB | “Quickly grab something small?” (session cost) |
| 3 | Handshake | “How fast can I get onto a host?” |
| 4 | Mux warm exec | “How fast can I run hundreds of commands in a session?” |
| 5 | Manyfiles | “How fast can I copy a tree of small files?” |
| 6 | CPU/RAM | “How much does the server cost the machine?” |

## Limitations

- loopback only; WAN/losses — the netem leg of the fork's suite (`project/ssh3/bench/`, TESTPLAN R3).
- The mechanisms are not identical (scp versus the sftp subsystem versus the sftp channel) — the difference is recorded as part of the result.
- The bench box is not dedicated: ambient load is evened out by rotation, and the tails (p95/max) are published.
