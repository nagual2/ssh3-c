# Metriken des Referenz-Bench (R3-Methodik) — erklärt

> Languages: [RU](BENCH-METRICS.md) · [EN](BENCH-METRICS.en.md) · DE (this file)

Referenz zu den Metriken von `bench/p7-compare.sh`: was genau gemessen wird, wie,
und wie man die Zahlen liest. Aktuelle Ergebnisse —
[BENCH-V0.2.0-2026-10-13.md](BENCH-V0.2.0-2026-10-13.md); der Oktober-Schnitt —
[BENCH-P7-2026-10-06.md](BENCH-P7-2026-10-06.md).

## Allgemeine Prinzipien der Methodik

| № | Verfahren | Wozu |
|---|-------|-------|
| 1 | **Median, nicht Mittelwert** | Timing-Verteilungen sind long-tail: ein einzelner Ausreißer verzieht den Mittelwert, den Median nicht. In den Berichten median + min + p95 + max |
| 2 | **Aufwärmen** (die erste Runde wird verworfen) | Der erste Durchlauf trägt kalte Caches: erster Handshake, Aufwärmen des Codes, Anlegen von Dateien |
| 3 | **Rotation der Implementierungen A→B→C** | Runden laufen im Kreis (c→go→os→c→…), nicht in Blöcken — die Hintergrundlast der Box fällt gleichmäßig auf alle Implementierungen |
| 4 | **sha256-Gate** | Eine Übertragung zählt nur, wenn der sha256 mit der Quelle übereinstimmt; die Prüfung steht **außerhalb** des gemessenen Fensters. Eine kaputte Übertragung = verworfene Runde, keine hübsche Zahl |
| 5 | **Ein Teststand für alle** | Ein ed25519-Schlüssel (in zwei Formaten), ein loopback, Payloads auf tmpfs — verglichen werden Implementierungen, nicht Umgebungen |

## 1. Durchsatz (Throughput)

**Operation.** Übertragung einer Datei als Ganzes: `push` = Client → Server, `pull` = Server → Client. Die Mechanismen unterscheiden sich ehrlich, und das ist Teil des Ergebnisses: OpenSSH — `scp` (Kopie über den exec-Kanal), der Go-Fork — das sftp-Subsystem, ssh3-c — der sftp-Kanal des eigenen Clients.

**Messung.** `date +%s%N` (Nanosekunden-Wanduhr) um die gesamte Übertragung; MB/s = tatsächliche Größe / Sekunden. Wall-clock des „Nutzererlebnisses“, kein interner Byte-Zähler.

| № | Größe | Was es zeigt |
|---|--------|----------------|
| 1 | 512 MiB | Stationärer Zustand: Fenster sind voll geöffnet, die Sitzungskosten sind amortisiert — die reine Geschwindigkeit des **Datenkanals** |
| 2 | 8 MiB | Setup-dominiert: die festen Sitzungskosten (Handshake + Kanalöffnung + Verdict) verteilen sich auf eine kleine Datei — gemessen wird der Preis der **Verbindung**, nicht des Kanals |

**Interpretation.** Die QUIC-Familie (C, Go) fährt TLS+QUIC **im User Space**, OpenSSH — TCP+AES-NI im Kernel: ein struktureller Unterschied der Klassen, kein Defekt. Konstante MB/s bei 8 MiB — Sitzungskosten geteilt durch 8 MiB.

## 2. Handshake (cold connect+auth+exec)

**Operation.** Der komplette kalte Zyklus: Start des Client-Prozesses → QUIC-Handshake (TLS 1.3 über QUIC, 1-RTT) → Authentifizierung (JWT mit Ed25519-Signatur) → HTTP/3 Extended CONNECT → Öffnen des Session-Kanals → exec no-op → Exit-Code.

**Messung.** Wanduhr um **den gesamten Client-Aufruf, inklusive Prozessstart** — deshalb zeigt min fast die reinen Protokollkosten.

**Interpretation.** Der strukturelle Vorteil der QUIC-Familie: 1-RTT-Handshake + eine Autorisierungsrunde gegenüber TCP-Handshake + mehrrundiger SSH2-Authentifizierung. Die Stabilität von OpenSSH (schmale Streuung) — Kernel-TCP ohne User-Space-Scheduling.

## 3. Mux warm exec (multiplexierte Sitzungen)

**Operation.** Latenz eines Befehls **über einer bestehenden Master-Verbindung** (ControlMaster): Slave → lokaler Socket/Pipe → Token → Anfügen der Kanäle → exec → Verdict. Handshake und Authentifizierung werden nicht wiederholt.

**Messung.** 3 Blöcke × 100 execs pro Implementierung (jeder Block — frischer Master), Median über 300.

**Interpretation.** Das Automatisierungs-/MCP-Profil: Hunderte Befehle in einer einzigen Sitzung. Der QUIC-Handshake ist hier bereits bezahlt — konkurriert wird die Mechanik des „Befehls-Durchreichens“. Gültige 300/300 sind zugleich der Nachweis der Master-Stabilität (Sitzungslimits, Ablehnungen).

## 4. CPU / RAM des Servers

**CPU.** Ein Sampler liest alle 50 ms `/proc/<pid>/stat`: jiffies-Delta (USER_HZ=100) / Realzeit → % **eines einzelnen Kerns** (>100% — ein Prozessbaum aus mehreren Prozessen; bei sshd Messung über den gesamten Baum). Die Messung — eine dedizierte verifizierte Übertragung mit einem frischen Daemon.

**RAM.** VmRSS-Peak aus denselben Samples.

**Interpretation.** CPU zeigt die Kosten von Krypto+Kopien auf einem gesättigten Kanal; RSS — die Pufferstrategie (Fenster gegen „die ganze Datei auf einmal“). Hohes RSS bei normaler CPU — der Engpass liegt im Speicher, nicht im Prozessor.

## 5. Manyfiles (Verzeichnis kleiner Dateien)

**Operation.** Rekursiver Transfer eines Verzeichnisses aus N Dateien à 4 KiB (`scp -r` / Fork `-f -r` / Harness `-J -r`): `push` = Hochladen des Baums, `pull` = Herunterladen (der Baum auf der Remote-Seite wird **außerhalb** des gemessenen Fensters mit demselben Mechanismus eingesät).

**Messung.** Wall-clock um die gesamte Übertragung; Ergebnis — files/s und aggregierte MB/s; Verifikation — Dateianzahl und Gesamtgröße beim Empfänger.

**Interpretation.** Eine Metrik für den per-file/per-request-Overhead des Protokolls und des Client-Treibers: N kleine Übertragungen statt eines einzigen Stroms. N wird empirisch so kalibriert, dass die Streuung zwischen den Implementierungen den Messfehler übersteigt (siehe die N-Werte in den Berichten).

## Zusammenfassung: welche Metrik welche Frage beantwortet

| № | Metrik | Nutzerfrage |
|---|---------|--------------------|
| 1 | Throughput 512 MiB | „Wie schnell Dateien übertragen?“ |
| 2 | Throughput 8 MiB | „Schnell was Kleines holen?“ (Sitzungskosten) |
| 3 | Handshake | „Wie schnell auf einen Host?“ |
| 4 | Mux warm exec | „Wie schnell Hunderte Befehle in einer Sitzung abarbeiten?“ |
| 5 | Manyfiles | „Wie schnell einen Baum kleiner Dateien kopieren?“ |
| 6 | CPU/RAM | „Wie viel kostet der Server die Maschine?“ |

## Einschränkungen

- Nur loopback; WAN/Verluste — das netem-Bein der Fork-Suite (`project/ssh3/bench/`, TESTPLAN R3).
- Die Mechanismen sind nicht identisch (scp gegen sftp-Subsystem gegen sftp-Kanal) — der Unterschied ist als Teil des Ergebnisses festgehalten.
- Die Bench-Box ist nicht dediziert: ambient-Last wird durch Rotation ausgeglichen, die Tails (p95/max) werden veröffentlicht.
