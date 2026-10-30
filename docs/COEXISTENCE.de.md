# Koexistenz der ssh3-Pakete
> Languages: [RU](COEXISTENCE.md) · [EN](COEXISTENCE.en.md) · DE (diese Datei)

Datum: 2026-10-30. Planpunkt P8(3) ([PLAN.md](PLAN.md) §4): ssh3 ist ein
eigenes Paket **neben OpenSSH**, kein Ersatz; gegenüber ssh3-go gilt die
Austauschbarkeit über die Phase P8(1) (ein Paket ersetzt das andere, es
liegt nicht daneben). Dieses Dokument ist die Kontrollmatrix der
gemeinsamen Installation samt Abnahmeprozedur.

## Das Prinzip

| № | Paar | Regel |
|---|------|-------|
| 1 | ssh3 ↔ OpenSSH (ssh2) | koexistieren stets: unterschiedliche Binärdateien, Konfigurationen, Ports, Schlüsselformate; nichts wird auf die andere Seite überlagert |
| 2 | ssh3 (C) ↔ ssh3-go (die Gabel) | Ersatz auf Paketebene: identische Binär- und Unit-Dateinamen, daher ist das Nebeneinander einer Rolle durch `Conflicts`/`Obsoletes` ausgeschlossen, der Austausch läuft über `Replaces`/`Provides` — fremde Programme, die `ssh3`/`ssh3-server` aufrufen, bleiben ohne Neukonfiguration |

## Was jedes Paket installiert

| № | Datei | Paket |
|---|-------|-------|
| 1 | `/usr/sbin/ssh3-server` | ssh3-server (das build.sh-deb; das debian/-Quellpaket installiert `/usr/bin/ssh3-server`) |
| 2 | `/usr/bin/ssh3`, der Symlink `/usr/local/bin/ssh3` | ssh3-client |
| 3 | `/etc/ssh3/cert.pem`, `/etc/ssh3/key.pem` (0640 root:ssh3), `/etc/ssh3/authorized_keys` | ssh3-server |
| 4 | `/etc/ssh3/ssh3-server.env` (conffile, `EnvironmentFile`) | nur das debian/-Quellpaket |
| 5 | `/usr/lib/ssh3-c/lib/libssl.so.3`, `libcrypto.so.3` (RUNPATH-Bündel) | ssh3c-libssl3 (nur deb) |
| 6 | `/usr/lib/systemd/system/ssh3-server.{socket,service}` | ssh3-server |
| 7 | `/usr/share/man/man8/ssh3-server.8`, `/usr/share/man/man1/ssh3.1.gz` | ssh3-server / ssh3-client |

Der Client-Zustand lebt im Benutzerverzeichnis und wird von keinem Paket
beansprucht: Zertifikats-Pins in `~/.ssh3/known_hosts` (das Format
`x509-certificate`), die Konfiguration wird als ssh2-kompatible Teilmenge
über `-F` gelesen (Standard `~/.ssh/config`) — die Datei wird nur
**gelesen**, nie geschrieben.

## Die Installationsmatrix

| № | Szenario | Ergebnis | Garantiert durch |
|---|----------|----------|------------------|
| 1 | `ssh3` (der C-Client) + OpenSSH `ssh` | koexistieren | keine Dateiüberschneidung (`/usr/bin/ssh3` gegen `/usr/bin/ssh`), Konfigurationen (`~/.ssh3` gegen `~/.ssh`), Manpages (`man1/ssh3.1` gegen `man1/ssh.1`) |
| 2 | `ssh3-server` (C) + `sshd` | koexistieren | Transport: UDP/443 (Socket-Aktivierung, der Daemon ruft nie `bind()`) gegen TCP/22; `/etc/ssh3` gegen `/etc/ssh`; das Unit-Paar `ssh3-server.*` gegen `sshd.service` |
| 3 | `ssh3-server` (C) + `ssh3-go-server` | auf Paketebene ausgeschlossen | deb `packaging/deb/control:8-9`, rpm `packaging/rpm/ssh3-server.spec:31-35` (`Obsoletes`), apk `packaging/apk/PKGINFO.in:22-25` |
| 4 | `ssh3-client` (C) + `ssh3-go-client` | auf Paketebene ausgeschlossen | deb `packaging/deb/client-control:8-9`, rpm `spec:47-49`, apk `PKGINFO-client.in:23-24` |
| 5 | C-Client + go-Server (kein Paketkonflikt — verschiedene Rollen) | koexistieren, wire-kompatibel | keine Dateiüberschneidung; die Interop-Beine `interop/go-server-channel-e2e.sh`, `interop/go-compat-e2e.sh` |
| 6 | C-Server + go-Client | koexistieren, wire-kompatibel | die Interop-Matrix `interop/run-h3.sh`, `interop/jump-chain-smoke.sh` (Gabel `1b6872a`) |
| 7 | das build.sh-deb ↔ das debian/-Quellpaket | ein Kanal gleichzeitig | derselbe Paketname `ssh3-server`: zwei Baukanäle, nicht zwei Pakete; dpkg/apt installiert nur einen (die Pfade unterscheiden sich: `/usr/sbin` gegen `/usr/bin`) |

Eine historische Notiz (warum Punkt 3 ein Ersatz und keine Nachbarschaft
ist): bei der P7-Integration wurde das Unit-Paar `ssh3-c-server.*` →
`ssh3-server.*` umbenannt wegen des Dateikonflikts mit dem bereits
installierten Paket `ssh3-go` — das P8-Koexistenzprinzip als „eine Rolle
— ein Besitzer des Namens“.

Außerhalb der Matrix: die Metapakete (`ssh3c`/`ssh3go` für rpm/apk) und
die rpm/apk-Signierung — warten auf die Entscheidung des Eigentümers
(PLAN-CURRENT.md, „Warten auf die Entscheidung des Eigentümers“).

## Die Kontrollprozedur

Matrixabnahme auf einem sauberen Host (deb-Befehle; rpm/apk am Ende):

| № | Prüfung | Befehl | Erwartung |
|---|---------|--------|-----------|
| 1 | Punkte 1-2: die Binärdateien nebeneinander | `command -v ssh ssh3 sshd ssh3-server; ssh -V; ssh3 -V` | alle vorhanden, Versionen unabhängig |
| 2 | Punkte 1-2: die Ports streiten nicht | `ss -lnt` / `ss -lun` | sshd: TCP/22; ssh3-server: UDP/443 (nach enable) |
| 3 | Punkte 1-2: die Konfigurationen getrennt | `dpkg -L ssh3-server \| grep -c /etc/ssh/` | `0` — das Paket schreibt nichts unter `/etc/ssh` |
| 4 | Punkt 3: ein Ersatz, keine Nachbarschaft | `apt-get install -s ssh3-server` auf einem Host mit ssh3-go-server | der apt-Plan entfernt das go-Paket (`Conflicts`), `/etc/ssh3` bleibt erhalten |
| 5 | Punkt 4: ebenso für den Client | `apt-get install -s ssh3-client` auf einem Host mit ssh3-go-client | der apt-Plan entfernt den go-Client |
| 6 | Punkte 5-6: ein lebendes Cross-Bein | `sh interop/go-server-channel-e2e.sh` (der C-Client → der go-Server) | das e2e-Urteil `OK` |
| 7 | Punkt 7: die Kanäle mischen sich nicht | `dpkg -I` beider debs aus `_build` und `_debian` | der Name `ssh3-server` in beiden — die Installation des zweiten verdrängt den ersten |

rpm: `rpm -q --conflicts ssh3-server`, `rpm -q --obsoletes ssh3-server`
(Erwartung: beide ssh3-go-*-Paare); apk: die `conflicts`/`replaces`-Zeilen
des installierten Pakets in `apk info`.

## Siehe auch

- Der Split-Kanon und die Dateiplatzierung — `packaging/README.md`
  (§ The packages, § Debian source package).
- Die CLI-Abweichungsmatrix gegen ssh(1)/sshd(8) — `docs/CLI-COMPAT.md`.
- Die Sicherheitsrichtlinie (wo melden, die CVE-Prozedur) — `SECURITY.md`.
