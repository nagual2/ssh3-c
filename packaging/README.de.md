# packaging — Distributionspakete für ssh3
> Languages: [EN](README.md) · [RU](README.ru.md) · DE (this file)

Baut die Distributionspakete für den `ssh3-server`-Daemon und den
`ssh3`-Client aus den Binaries in `build/linux-release/` (fehlen sie,
werden sie bei Bedarf über das Preset `linux-release` gebaut).

## Aufbau

| Path | Contents |
|------|----------|
| `build.sh` | the orchestrator: `bash packaging/build.sh [deb\|rpm\|apk\|all]` |
| `deb/` | debian control, postinst, copyright payloads |
| `rpm/` | rpm spec template: die Pakete `ssh3-server` und `ssh3-client` (`@VERSION@` substituted from the binary) |
| `apk/` | apk-tools-v2-`.PKGINFO`-Vorlagen: `PKGINFO.in` (Server) und `PKGINFO-client.in` (Client) |
| `openwrt/` | openwrt feed makefile (built inside the openwrt SDK, not here) |
| `_build/` | final packages (gitignored, never committed) |

## Verwendung

```
bash packaging/build.sh          # deb + rpm + apk
bash packaging/build.sh deb      # one format at a time
```

Das Staging geschieht unter `/tmp` und wird automatisch aufgeräumt:
dpkg-deb und rpm erzwingen echte POSIX-Dateimodi, die ein
windows-drvfs-Checkout (`/mnt/c`, alles 0777) nicht bieten kann. Nur die
fertigen Pakete landen in `packaging/_build/`.

Die Paketversion wird aus dem Daemon selbst gelesen (`ssh3-server -V`);
`deb/control` trägt die Version wörtlich und `build.sh` gleicht sie mit
dem Binary ab. Die rpm/apk-Vorlagen werden zur Build-Zeit substituiert.
Die Client-Hälfte wird ebenfalls geprüft: `ssh3 -V` nennt ihre eigene
Version (`ssh3 version SSH 3.0 ssh3-c X.Y.Z ...`), und `build.sh`
verweigert das Packen eines Clients, dessen Version von der des Daemons
abweicht — beide Hälften gehen als ein Release raus.

## Die Pakete

Der Split folgt der openssh-Kanon und dem debian-Quellpaket
(`debian/control`): Daemon und CLI sind zwei Pakete derselben Version;
der Client eines serverlosen Hosts braucht keinen Daemon und der Daemon
keinen Client.

| Format | Pakete | Inhalt der Client-Hälfte |
|--------|--------|---------------------------|
| deb | `ssh3-server`, `ssh3-client`, `ssh3c-libssl3` | `/usr/bin/ssh3`, `ssh3(1)` |
| rpm | `ssh3-server`, `ssh3-client` (eine Spec, zwei Pakete) | `/usr/bin/ssh3`, `/usr/share/man/man1/ssh3.1.gz` |
| apk | `ssh3-server`, `ssh3-client` (zwei `.PKGINFO`-Vorlagen) | `/usr/bin/ssh3`, `/usr/share/man/man1/ssh3.1.gz` |

Die rpm-Spec baut beide Pakete in einem `rpmbuild`-Durchgang: der Daemon
ist das Hauptpaket (`%{_sbindir}/ssh3-server`), der Client das Teilpaket
`%package -n ssh3-client` (`%{_bindir}/ssh3` plus die Man-Seite). Der
Drop-in-Tanz gegen den go-Fork folgt der deb-Seite: der Client konfligiert
mit (und obsoletiert) `ssh3-go-client`, der Daemon mit beiden,
`ssh3-go-client` und `ssh3-go-server`.

Die Man-Seite des Clients ist dieselbe Datei, die das debian-Quellpaket
installiert: `debian/ssh3.1` (mdoc). Für apk gibt es keine eigene
Vorlage — die Seite wird in den Payload gepackt.

Die Architektur von rpm und apk folgt dem `ARCH`-Schalter in `build.sh`
(`amd64` -> x86_64, `arm64` -> aarch64); die arm64-Binaries selbst sind
der B7-Punkt des Plans.

## Das apk-Paket (APKv2)

Das apk-Paket sind zwei aneinandergehängte gzip-Streams: das
Control-Segment (`.PKGINFO`) und das Data-Segment (der Payload). Zwei
Details sind nicht offensichtlich und wurden gegen das echte apk-tools
(2.14, alpine-3.22-Container) verifiziert:

1. das tar beider Segmente ist das POSIX-ustar (`tar --format=ustar`):
   apk-tools hat einen eigenen tar-Parser und weist das GNU-Format (die
   Magic `ustar  `) mit „BAD archive" ab;
2. das Control-Segment darf das tar-End-of-archive-Zeichen (die zwei
   leeren Header) NICHT tragen: apk-tools v2 parst ein Control-Segment
   mit diesem Zeichen falsch und weist das ganze Paket mit „BAD
   archive" ab — die alpine-Pakete schneiden das Zeichen genauso ab,
   ihr Segment endet direkt nach dem `.PKGINFO`-Eintrag. `build.sh`
   schneidet es mit `truncate` ab.

Das Data-Segment behält das Zeichen (dort toleriert apk es). Die
Control-Vorlage trägt auch den Platzhalter `@APKARCH@` — substituiert aus
demselben `ARCH`-Schalter wie im rpm.

## Zielmatrix (OpenSSL >= 3.5 mit der QUIC-TLS-API)

| Target | OpenSSL 3.5 in the base repo | Bundled? | Notes |
|--------|------------------------------|----------|-------|
| Debian 13 (trixie) | yes (3.5.x) | deb ships it | primary deb target; the bundle loads even here (RUNPATH wins) |
| Mint 22.x / Ubuntu 24.04 | no (3.0.13) | deb ships it | the bundle is the point - the deb installs as-is |
| Alpine 3.22 | yes | no | apk needs a musl build; bundle port is backlog |
| Fedora | <= 42: no (3.0/3.2), 43+: yes | no | rpm keeps the system-openssl scheme; bundle port is backlog |

## OpenSSL im Bundle (deb)

Der Daemon spricht die QUIC-TLS-API von OpenSSL 3.5, aber mint 22.x und
ubuntu 24.04 (die deb-Installationsziele) liefern weiterhin 3.0.x aus.
Das Paket bettet daher das Shared-Library-Paar ein:

- die Quelle ist das offizielle Debian-13-(trixie)-Paket `libssl3t64`
  (3.5.7 zum Zeitpunkt des Verfassens, die URL ist in `build.sh`
  fixiert), geholt mit curl/wget und entpackt mit `dpkg-deb -x`,
  gecacht unter `packaging/_build/cache/`;
- die beiden Bibliotheken (`libssl.so.3`, `libcrypto.so.3`, Mode 0644,
  root) werden im Zuge des Staging in das private
  `/usr/lib/ssh3-c/lib/` gelegt — unverändert; das System-`libssl` wird
  weder benötigt noch angetastet;
- das Binary nach dem Staging trägt `RUNPATH=/usr/lib/ssh3-c/lib`
  (patchelf, verpflichtend): RUNPATH wird vor den Standardpfaden
  aufgelöst, sodass das Bundle nur für dieses Binary gewinnt. Nichts
  gelangt in die globalen Linker-Pfade, und kein anderes Binary kann
  sich das private Paar greifen.

Auflösungsreihenfolge der Bundle-Quelle (der fetch-bundle-Schritt):

1. `LIBSSL_SRC` — ein Pfad zu einer `.deb`-Datei, einer deb-URL oder
   einem Verzeichnis mit einem lokalen OpenSSL-Build (im Verzeichnis
   selbst, in `lib/`, `lib64/` wird nach
   `libssl.so.3`/`libcrypto.so.3` gesucht);
2. `LOCAL_OPENSSL_DIR` — dasselbe Verzeichnis-Override, in der alten
   Schreibweise (bleibt als Fallback ohne Netzwerk);
3. der Cache (`packaging/_build/cache/`), dann die fixierte
   deb.debian.org-URL.

Ein fehlgeschlagener Fetch ist fatal — mit Anweisungen in der Meldung.
Ohne Netz `LIBSSL_SRC=<local deb, url or build dir>` übergeben (oder
`LOCAL_OPENSSL_DIR=<build dir>`). Ist das Override ein lokaler Build,
sind die Bibliotheken nicht Debian-gebaut — ihre Version und
Build-Optionen liegen dann in der Verantwortung des Aufrufers (der
Daemon braucht die 3.5-QUIC-TLS-API).

Warum ein Bundle und nicht statisches Linken oder eine
System-Abhängigkeit:

- statisches Linken wurde vom Design-Owner abgelehnt (größere
  Diff-/Rebuild-Oberfläche pro Release; die NSS-Modul-Geschichte bleibt
  in beiden Schemata unberührt, das Bundle ist schlicht einfacher);
- eine System-Abhängigkeit (`libssl3t64 (>= 3.5)`) kann „trixie hat es,
  noble nicht" nicht in einer einzigen `Depends`-Zeile ausdrücken, ohne
  ein apt-Repo zu betreiben — das Bundle schafft es mit null
  Repositories.

Hinweis: wenn das System bereits OpenSSL 3.5 hat (Debian 13), lädt das
Bundle trotzdem (RUNPATH schlägt die Standardpfade). Das ist Absicht —
das mitgelieferte Paar ist ein getestetes, known-good 3.5.x.

Die deb-`Depends` spiegeln die NEEDED-Liste des Bundle-Paars wider:
`libc6, zlib1g, libzstd1, adduser` (libcrypto braucht zlib und zstd;
libcrypt kommt mit libc6). Das System-`libssl3t64`/`libssl3` wird nicht
mehr referenziert.

Backlog: die Portierung desselben Schemas (privates Verzeichnis +
RUNPATH) auf die Payloads von rpm und apk wird separat verfolgt; beide
entfernen weiterhin den Build-RUNPATH und erwarten das System-OpenSSL
3.5.

## Bekannte Einschränkungen

1. Das Binary aus dem Build-Baum linkt gegen das Entwickler-OpenSSL 3.5
   (`~/opt/openssl-3.5`) und trägt dessen RUNPATH. Das deb ersetzt
   diesen RUNPATH durch den privaten Bundle-Pfad (patchelf,
   verpflichtend) und liefert das Bundle-Paar aus — siehe „OpenSSL im
   Bundle (deb)"; das rpm und das apk entfernen weiterhin den RUNPATH
   und verlangen das System-OpenSSL 3.5.
2. Das apk-Paket wird von Hand zusammengesetzt (zwei aneinandergehängte
   tar.gz-Streams, apk-tools v2); ein echtes alpine-Paket muss gegen
   musl in einer alpine-Umgebung gebaut werden — das ausgelieferte
   Binary ist gegen glibc gelinkt. Das Format selbst ist verifiziert:
   `apk verify` akzeptiert beide Pakete, `apk add --allow-untrusted`
   installiert sie (die Dateien landen an Ort und Stelle); die Abhängigkeit
   `so:libssl.so.3` ist in einem nackten alpine-Container nicht
   auflösbar (alpine 3.22 splittet die Bibliothek in `libssl3`/`libcrypto3`),
   also zählt apk eine unaufgelöste Abhängigkeit pro Paket — genau wie beim
   alten Serverpaket.
3. Weder das apk noch das rpm sind signiert (kein Signaturschlüssel im
   Baum); unsignierte apk-Pakete installieren mit
   `apk add --allow-untrusted`.
4. Das openwrt-ipk ist ein Feed-Makefile-Stub: es braucht das openwrt
   SDK mit einem OpenSSL >= 3.5 (openwrt main; die Branches
   24.10/23.05 führen 3.0.x).
5. Die systemd-Unit-Verdrahtung (der deb-postinst-Integrationsblock)
   kommt beim Integrationsschritt, bezogen aus `packaging/systemd/`.
