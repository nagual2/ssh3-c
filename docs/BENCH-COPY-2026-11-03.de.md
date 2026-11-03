# BENCH: Dateikopie - ssh3-c / Go-Fork / ssh2 / rsync (IPv4 und IPv6 getrennt)

Datum: 2026-11-03. Skript: [`bench/copy-compare.sh`](../bench/copy-compare.sh).
Stand: WSL2, Loopback, tmpfs (/dev/shm), 64-MiB-Payload, 3 gemessene Runden + 1
Warmup (verworfen), sha256 auf beiden Seiten jedes Transfers.

Implementierungen: ssh3-c 0.5.8 (`--sftp`), Go-Fork (`-transfer`), OpenSSH scp
(ssh2), rsync 3.2.3 ueber ssh2. Ein ed25519-Schluesselpaar in zwei Formaten
(PKCS8 fuer die JWT-Clients, OpenSSH fuer sshd/scp/rsync); die Daemons fahren
Dual-Stack (`[::]`), die Familie waehlt das Operanden-Literal (127.0.0.1 / [::1]).

## Ergebnisse (Median MB/s, verifizierte Runden)

| Implementierung | v4 push | v4 pull | v6 push | v6 pull |
|------------------|---------|---------|---------|---------|
| **ssh3-c** | **110.9** | **117.7** | **108.5** | **112.1** |
| Go-Fork | 23.9 | 31.8 | - (1) | - (1) |
| ssh2 (scp) | 116.2 | 120.6 | 117.3 | 150.8 |
| rsync (ueber ssh2) | 109.1 | 131.8 | 109.9 | 136.9 |

(1) Der Transfer-Operand des Go-Forks parst user@host:remote mit einem naiven
Doppelpunkt-Split - die eckige [::1]-Form laesst sich nicht ausdruecken
("too many ':' separators"). Das v6-exec funktioniert (die URL-Form traegt die
Klammern); das Loch liegt genau im Transfer-Operanden. Gespiegelt in Rust
(transfer.rs, derselbe Parser) - siehe "Rust" unten.

## Schlussfolgerungen

1. **ssh3-c haelt das ssh2/rsync-Niveau bei der Bulk-Kopie**: 108-118 MB/s
   gegen 116-151 (ssh2) und 109-137 (rsync) - der Unterschied faellt in das
   Laufrauschen, beide Enden Loopback. v4 und v6 sind symmetrisch.
2. **Der Go-Fork haengt 4-5x dahinter** (24-32 MB/s) - der Engpass seiner
   sftp-Pumpe (konsistent mit den alten B7/B8-Benches).
3. rsync ueber ssh2 faehrt auf dem scp-Niveau (das Delta-Protokoll artet bei
   einer frischen Datei zur reinen Uebertragung aus).

## Befunde (keine Bench-Defekte)

| # | Befund | Wohin |
|---|--------|-------|
| 1 | Die Transfer-Operanden von Go und Rust koennen das eckige IPv6-Literal nicht ausdruecken (der naive split(':') in beiden; die exec-Beine fahren die URL-Form und funktionieren) | Parity-Notiz in die Rust/Fork-Plaene; Entscheidung des Eigentuemers |
| 2 | Der Rust-Client ist fuer diesen Stand roh: der Identity-Loader lehnt sowohl PKCS8-PEM als auch den OpenSSH-Formatschluessel ab ("PEM Base64 error") | PARITY.md des Rust-Repos (Entscheidung des Eigentuemers; die Rust-Beine fahren den Bench-Opt-in ueber --impls rust) |
| 3 | Der C-Client: das epoll des /dev/null-stdin ohne -n antwortet EPERM ("the console init failed") - die Bench-Beine fahren -n | Die bekannte Semantik (dieselbe wie die -f-Welle) |

## Reproduktion

```sh
bench/copy-compare.sh --size-mib 64 --rounds 3
```

CSV: $WORK/results/copy.csv (/tmp/copybench/results/copy.csv standardmaessig).
