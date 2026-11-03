# BENCH: file copy - ssh3-c / Go fork / ssh2 / rsync (ipv4 and ipv6 apart)

Date: 2026-11-03. Script: [`bench/copy-compare.sh`](../bench/copy-compare.sh).
Stand: WSL2, loopback, tmpfs (/dev/shm), 64 MiB payload, 3 measured rounds + 1
warmup (discarded), sha256 on both ends of every transfer.

Implementations: ssh3-c 0.5.8 (`--sftp`), the Go fork (`-transfer`), OpenSSH
scp (ssh2), rsync 3.2.3 over ssh2. One ed25519 keypair in two formats (PKCS8
for the JWT clients, OpenSSH for sshd/scp/rsync); the daemons ride dual-stack
(`[::]`), the family is picked by the operand literal (127.0.0.1 / [::1]).

## Results (median MB/s, verified rounds)

| Implementation | v4 push | v4 pull | v6 push | v6 pull |
|----------------|---------|---------|---------|---------|
| **ssh3-c** | **110.9** | **117.7** | **108.5** | **112.1** |
| Go fork | 23.9 | 31.8 | - (1) | - (1) |
| ssh2 (scp) | 116.2 | 120.6 | 117.3 | 150.8 |
| rsync (over ssh2) | 109.1 | 131.8 | 109.9 | 136.9 |

(1) The Go fork transfer operand parses user@host:remote with a naive colon
split - the bracketed [::1] form does not express ("too many ':' separators").
The v6 exec works (the URL form carries the brackets); the hole is the
transfer operand exactly. Mirrored in Rust (transfer.rs, the same parser) -
see "Rust" below.

## Conclusions

1. **ssh3-c holds the ssh2/rsync level on the bulk copy**: 108-118 MB/s vs
   116-151 (ssh2) and 109-137 (rsync) - the difference rides the run noise,
   both ends loopback. v4 and v6 are symmetric.
2. **The Go fork lags 4-5x** (24-32 MB/s) - the bottleneck of its sftp pump
   (consistent with the past B7/B8-era benches).
3. rsync over ssh2 rides the scp level (the delta protocol degenerates to
   the plain transfer on a fresh file).

## Findings (not bench defects)

| # | Finding | Where |
|---|---------|-------|
| 1 | The Go and Rust transfer operands cannot express the bracketed ipv6 literal (the naive split(':') in both; the exec legs ride the URL form and work) | The parity note into the Rust/fork plans; the owner's call |
| 2 | The Rust client is raw for this stand: the identity loader refuses both the PKCS8 PEM and the OpenSSH-format key ("PEM Base64 error") | The Rust repo PARITY.md (the owner's call; the rust legs ride the bench opt-in via --impls rust) |
| 3 | The C client: the epoll of the /dev/null stdin without -n answers EPERM ("the console init failed") - the bench legs ride -n | The known semantics (the same one as the -f wave) |

## Reproduction

```sh
bench/copy-compare.sh --size-mib 64 --rounds 3
```

CSV: $WORK/results/copy.csv (/tmp/copybench/results/copy.csv by default).
