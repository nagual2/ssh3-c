# Channel-body compression bench: the wire gain (B8, the R3 methodology)

> Languages: EN (this file) · [RU](BENCH-COMPRESS-2026-10-22.md) · [DE](BENCH-COMPRESS-2026-10-22.de.md)

Date: 2026-10-22. The owner's question (F2 → B8): how much traffic does the channel-body
compression actually save. Answered with a live capture: `tcpdump` on loopback, the sum of
the UDP payload lengths (the QUIC packets — everything that leaves the machine), rounds in
a leg rotation, the first round is the warmup and is discarded, the median; a transfer
counts only when the file comes back byte-exact (the cmp gate outside the timed window).
The stand and the script: `bench/p7-compress.sh`.

## The stand

| № | Parameter | Value |
|---|-----------|-------|
| 1 | Implementations | ssh3-c `852ddfd` (zlib+lz4+zstd build), the go fork `ce072f4` (deflate+lz4+zstd) |
| 2 | Payloads | `text` — 8 MiB of repeated lines, 8 388 608 bytes (compressible); `rand` — 8 MiB of urandom (incompressible, the cutoff) |
| 3 | Metric | the sum of `UDP, length N` from the pcap of the leg window (the put); the pull runs outside the window and is the gate |
| 4 | Legs | `c-plain` (no `-C`), `c-deflate`, `c-lz4`, `c-zstd` (the forced codec), `go-auto` (fork↔fork, negotiated) |
| 5 | Rounds | the script plan is 7 (ROUNDS=7); in fact the warmup and 3 measured rounds (the WSL restarts cut the runs, see the deviations); the median |

## Results (medians of the wire bytes, a leg = one put)

| № | Leg | text 8 MiB | gain | rand 8 MiB |
|---|-----|-------------:|-----:|-----------:|
| 1 | c-plain | 8 675 547 | 1× | 17 561 408 |
| 2 | c-deflate | 224 553 | **38.6×** | 17 136 933 |
| 3 | c-lz4 | 269 421 | **32.2×** | 16 956 385 |
| 4 | c-zstd | 210 644 | **41.2×** | 17 478 639 |
| 5 | go-auto (fork↔fork, the negotiation picked zstd) | 88 701 | — | 8 635 452 |

The run was repeated twice (the first died with the WSL distribution restart); the medians
of the two runs agree within ±3%.

## Reading

1. **The traffic economy is real and large**: a compressible stream shrinks on the wire by
   **30–40×**; at the frame level the client reports 8 398 212 → 43 862 B (zstd, ~191×),
   the honest wire number is lower because of the QUIC/TLS and handshake overhead — 41×.
2. **The cutoff works**: an incompressible payload does not grow — the rand legs of every
   codec equal plain within the noise. Compression costs nothing when it cannot win.
3. **The codec order is confirmed**: zstd > deflate > lz4 — by the ratio and in the
   negotiation (go-auto picked zstd).
4. **The rand legs of the C stack carry ~2.1× of the file size** (retransmissions of a
   full-speed loopback push); the go stack's quic-go pacing gives 1.03×. It lands on every
   leg equally — the codec comparison is fair; the observation itself is transport, not
   compression.
5. **The cross leg `c-zstd-go` (the C client → the fork server) never came up**: the fork
   server answers `could not find SSH3 conversation for new channel 4` to the C client's
   channel. A cross-implementation sftp defect, unrelated to compression — recorded in the
   plan (B13, the neighbour of B12).

## Deviations from the R3 methodology and the stand traps

| № | Item | The decision |
|---|------|--------------|
| 1 | 3 measured rounds instead of 7 | the cyclic restarts of the WSL distribution killed the long runs that day (signals to the process group); two independent runs produced agreeing medians |
| 2 | tcpdump without `--immediate-mode` | libpcap batches the packets in the kernel and delivers them by timeout: a fast (tens of ms) compressed transfer was discarded whole at the SIGINT — the capture came out empty. Only `--immediate-mode` makes the short legs measurable |
| 3 | The S2-02 sftp budget | the stand opens dozens of sftp sessions; the daemon runs with `--max-sftp-sessions-per-user 0` (the budget is a production guard, not a bench one) |
| 4 | `timeout` without `-k` | the C client stuck on a dead peer ignores SIGTERM — the stand calls `timeout -k 5` (a client robustness defect found along the way) |

## The raw data

`~/p7bench-c/results/compress.csv` and `~/p7bench-go/results/compress.csv` (WSL,
`max@`), the format: `leg,payload,round,wire_bytes,packets,app_plain,app_packed,sha_ok`.
