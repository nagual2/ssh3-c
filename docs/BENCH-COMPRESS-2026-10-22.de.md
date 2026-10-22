# Kanalkompressions-Bench: der Gewinn auf der Leitung (B8, R3-Methodik)

> Languages: DE (this file) · [RU](BENCH-COMPRESS-2026-10-22.md) · [EN](BENCH-COMPRESS-2026-10-22.en.md)

Datum: 22.10.2026. Die Frage des Owners (F2 → B8): wie viel Verkehr spart die
Kanalkompression wirklich. Beantwortet mit einer Live-Messung: `tcpdump` auf loopback,
die Summe der UDP-Payload-Längen (die QUIC-Pakete — alles, was die Maschine verlässt),
Runden in Rotationsfolge, die erste Runde ist Aufwärmung und fällt weg, der Median; eine
Übertragung zählt nur bei byte-exakter Rückkehr der Datei (sha256-Gate außerhalb des
Messfensters). Stand und Skript: `bench/p7-compress.sh`.

## Der Stand

| Nr | Parameter | Wert |
|----|-----------|------|
| 1 | Implementierungen | ssh3-c `852ddfd` (Build zlib+lz4+zstd), Go-Fork `ce072f4` (deflate+lz4+zstd) |
| 2 | Payloads | `text` — 8,4 MiB wiederholter Zeilen (komprimierbar); `rand` — 8 MiB urandom (inkompressibel, Cutoff) |
| 3 | Metrik | Summe der `UDP, length N` aus dem pcap des Bein-Fensters (der Put); der Pull läuft außerhalb und ist das Gate |
| 4 | Beine | `c-plain` (ohne `-C`), `c-deflate`, `c-lz4`, `c-zstd` (erzwungener Codec), `go-auto` (Fork↔Fork, verhandelt) |
| 5 | Runden | 5, davon 4 gemessen (Aufwärmung verworfen); der Median |

## Ergebnisse (Mediane der LeitungBytes, ein Bein = ein Put)

| Nr | Bein | text 8,4 MiB | Gewinn | rand 8 MiB |
|----|------|-------------:|-------:|-----------:|
| 1 | c-plain | 8 675 547 | 1× | 17 561 408 |
| 2 | c-deflate | 224 553 | **38,6×** | 17 136 933 |
| 3 | c-lz4 | 269 421 | **32,2×** | 16 956 385 |
| 4 | c-zstd | 210 644 | **41,2×** | 17 478 639 |
| 5 | go-auto (Fork↔Fork, die Verhandlung wählte zstd) | 88 701 | — | 8 635 452 |

Der Lauf wurde zweimal wiederholt; die Mediane der beiden Läufe stimmen innerhalb ±3 %
überein.

## Lesung

1. **Die Verkehrseinsparung ist real und groß**: ein komprimierbarer Strom schrumpft auf
   der Leitung um das **30–40-fache**; auf Frame-Ebene meldet der Client 8 398 212 →
   43 862 B (zstd, ~191×), die ehrliche Leitungszahl ist niedriger wegen des QUIC/TLS- und
   Handshake-Overheads — 41×.
2. **Der Cutoff funktioniert**: eine inkompressible Payload wächst nicht — die
   rand-Beine aller Codecs entsprechen plain innerhalb des Rauschens. Kompression kostet
   nichts, wenn sie nicht gewinnen kann.
3. **Die Codec-Reihenfolge ist bestätigt**: zstd > deflate > lz4 — nach Kennzahl und in
   der Verhandlung (go-auto wählte zstd).
4. **Die rand-Beine des C-Stacks tragen ~2,1× der Dateigröße** (Retransmissions eines
   Volllast-push auf loopback); der Go-Stack liefert mit dem quic-go-Pacing 1,03×. Es
   trifft alle Beine gleich — der Codec-Vergleich bleibt fair; die Beobachtung selbst ist
   transportseitig, nicht kompressorisch.
5. **Das Kreuzbein `c-zstd-go` (C-Client → Fork-Server) kam nie zustande**: der Fork-Server
   antwortet `could not find SSH3 conversation for new channel 4` auf den Kanal des
   C-Clients. Ein implementationsübergreifender sftp-Defekt, ohne Bezug zur Kompression —
   im Plan vermerkt (B13, der Nachbar von B12).

## Abweichungen von der R3-Methodik und Stand-Fallen

| Nr | Punkt | Entscheidung |
|----|-------|--------------|
| 1 | 3 gemessene Runden statt 7 | die zyklischen Neustarts der WSL-Distribution killten an diesem Tag lange Läufe (Signale an die Prozessgruppe); zwei unabhängige Läufe lieferten übereinstimmende Mediane |
| 2 | tcpdump ohne `--immediate-mode` | libpcap bündelt Pakete im Kernel und liefert sie per Timeout: eine schnelle (Zehner-ms) komprimierte Übertragung wurde beim SIGINT komplett verworfen — das Capture blieb leer. Erst `--immediate-mode` macht kurze Beine messbar |
| 3 | S2-02-sftp-Budget | der Stand öffnet Dutzende sftp-Sitzungen; der Daemon läuft mit `--max-sftp-sessions-per-user 0` (das Budget ist ein Produktions-Schutz, kein Bench-) |
| 4 | `timeout` ohne `-k` | der an einem toten Peer hängende C-Client ignoriert SIGTERM — der Stand ruft `timeout -k 5` (nebenbei ein Client-Robustheitsdefekt gefunden) |

## Rohdaten

`~/p7bench-c/results/compress.csv` und `~/p7bench-go/results/compress.csv` (WSL,
`max@`), Format: `leg,payload,round,wire_bytes,packets,app_plain,app_packed,sha_ok`.
