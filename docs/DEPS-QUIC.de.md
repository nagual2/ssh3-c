# ssh3-c: Build-Abhängigkeiten und die QUIC-Frage (Bericht)
> Languages: [RU](DEPS-QUIC.md) · [EN](DEPS-QUIC.en.md) · DE (this file)

Datum: 2026-10-01. Vorgabe des Projekteinhabers: OpenSSH gehört zu den Linux-Basissystemen und wird mit deren Bibliotheken gebaut; die Fremdbibliotheken von ssh3-c sind zu minimieren. Unklar ist, was mit QUIC zu tun ist. Dieser Bericht — Analyse und Empfehlung.

## 1. Basis: Wogegen OpenSSH tatsächlich linkt

OpenSSH portable benötigt von außen genau zwei Systembibliotheken:

| № | Bibliothek | Rolle | Optionalität |
|---|------------|------|----------------|
| 1 | `libcrypto` (OpenSSL/LibreSSL) | die gesamte TLS/SSH-Kryptografie | obligatorisch |
| 2 | `libz` | Kanalkomprimierung | obligatorisch (aber der Kanal nutzt Komprimierung so gut wie nie) |

Optional und distributionsspezifisch: `libedit` (sftp-Client), `libfido2` (FIDO-Schlüssel), GSSAPI/kerberos, PAM/audit/selinux (Distributions-Patches). Der Kern des Prinzips: **die Protokollschicht (SSH) selbst ist eigener Code von OpenSSH, aus den Systembibliotheken wird nur der Krypto-Stack bezogen**. Das SSH-Protokoll war nie eine „Bibliothek“ — und genau deshalb lässt sich OpenSSH überall bauen.

Zielfazit für ssh3-c: **die einzige Systemabhängigkeit ist `libcrypto`**. QUIC und HTTP/3 sind unsere Protokollschicht, analog zur SSH-Schicht von OpenSSH: eigener Code, keine Bibliothek. Angenehmer Bonus: zlib braucht ssh3 gar nicht (QUIC verwendet kein DEFLATE).

## 2. Anatomie der QUIC-Abhängigkeit

QUIC lässt sich nicht als „eine Bibliothek aus der Basis“ nehmen — es ist ein Konglomerat aus vier Schichten:

| № | Schicht | Erfordert |
|---|------|-------------|
| 1 | TLS 1.3 mit QUIC API | handshake-Callbacks, transport parameters in der TLS-Extension, key phases. Vorhanden in: OpenSSL ≥3.5 (natives API), BoringSSL, LibreSSL, wolfSSL, GnuTLS ≥3.8 |
| 2 | QUIC-Transport (RFC 9000/9002) | varint, Frames, ACK/loss recovery, congestion control, flow control — ein „Monster“ |
| 3 | HTTP/3 + QPACK (RFC 9110/9204) | für ssh3 genügt das Minimum: extended CONNECT + QPACK, ausreichend für Interop mit quic-go |
| 4 | DATAGRAM (RFC 9221) | obligatorisch: das UDP-Forwarding von ssh3 baut auf QUIC-datagrams auf |

Kernfakt 2025–2026: **OpenSSL 3.5 LTS (April 2025) brachte ein natives QUIC API — Server + Client + 0-RTT für QUIC-Stacks von Drittanbietern**. Davor erforderte QUIC-TLS nicht-upstream-Forks (quictls) oder BoringSSL — genau deshalb gab es „minimale“ QUIC-Lösungen früher nicht. Das Ökosystem konsolidiert sich: curl hat sein quictls-Backend im Januar 2026 entfernt, nginx empfiehlt OpenSSL ≥3.5.1.

## 3. Varianten des QUIC-Stacks

| № | Variante | Sprache | TLS | Lizenz | In Distributionen | DATAGRAM/0-RTT/GSO | Kommentar |
|---|---------|------|-----|----------|-----------------|--------------------|-------------|
| 1 | **Eigener QUIC (Adaption von nginx `src/event/quic/`) + System-OpenSSL 3.5** | C | System-libcrypto | BSD-2 (nginx), OpenSSL | Code unser; TLS — aus der Basis | DATAGRAM **zu ergänzen** (nginx besitzt es nicht); 0-RTT vorhanden; GSO vorhanden | die QUIC-Schicht wird zu unserem Quellcode, so wie die SSH-Schicht bei OpenSSH |
| 2 | **ngtcp2 + nghttp3 aus dem System** + OpenSSL 3.5 oder GnuTLS | C | libcrypto/gnutls | MIT | Debian 13 (1.11, backports aktueller), Fedora, Alpine (1.22–1.25) | beide vorhanden, GSO API vorhanden | 2 zusätzliche Bibliotheken; QUIC wird upstream unterstützt |
| 3 | quiche (Cloudflare) | Rust+CAPI | BoringSSL **vendored** | BSD-2 | nein | vorhanden | zieht eine Rust-Toolchain und BoringSSL nach sich — gegen das Prinzip |
| 4 | lsquic (LiteSpeed) | C | BoringSSL (bestimmte Commits) | MIT | nein | vorhanden | + libevent, zlib; Vendoring von BoringSSL |
| 5 | picoquic (Private Octopus) | C | picotls (eigenes) | MIT | nein | vorhanden | eigener TLS-Stack — keine „System“-Abhängigkeit |
| 6 | mvfst (Meta) | C++ | BoringSSL + fizz/folly | MIT | nein | vorhanden | das gewichtigste; C++ mit Exceptions, fremder Stil |

Varianten 3–6 werden mit ein und demselben Argument verworfen: **alle ziehen BoringSSL oder picotls als vendored-Abhängigkeit nach sich** — der Build ist dann nicht mehr „aus Basisbibliotheken“; es entsteht eine Toolchain (Rust bei quiche) oder Code, der sich nicht in Distributionen paketieren lässt. Keiner davon ist in den Basis-Repositories von Debian/Fedora/Alpine enthalten.

## 4. Paketierung von System-OpenSSL 3.5 (für Variante 1)

| № | Distribution | OpenSSL | QUIC API | Kommentar |
|---|-------------|---------|----------|-------------|
| 1 | Debian 13 trixie | 3.5.x | vorhanden | aktuelle stable |
| 2 | Ubuntu 25.10 | 3.5.3 | vorhanden | |
| 3 | Fedora 43 | 3.5.8 | vorhanden | frische Fixes des QUIC-Servers |
| 4 | Alpine 3.22 | 3.5.8 | vorhanden | wichtig für Embedded/Container |
| 5 | Ubuntu 24.04 LTS | 3.0.x | **nein** | Supportfenster bis 2029 — eine Sackgasse |
| 6 | RHEL 10 | 3.2.x | **nein** | fehlt, und obendrein gilt eine strenge Politik |
| 7 | Windows | n/a (vcpkg OpenSSL 3.5) | vorhanden | Build über vcpkg — dokumentierte Ausnahme |

Upstream OpenSSL veröffentlicht offizielle .deb/.rpm-Pakete (Repository openssl/packages) — für Ubuntu 24.04/RHEL gibt es einen sanktionierten Umgehungsweg ohne Vendoring.

Für Variante 2: ngtcp2 ist in Debian 13 paketiert (aber das Paket ist nur mit GnuTLS-Backend gebaut; das OpenSSL-Backend erfordert ngtcp2 ≥1.12 — aus backports zu beziehen), Fedora und Alpine — mit aktuellen Versionen.

## 5. Entscheidungsmatrix (Kriterien des Projekteinhabers)

Kriterien: minimale Fremdbibliotheken; Build aus dem Basissystem; zero-copy; DATAGRAM+0-RTT; Reife; Stil.

| № | Kriterium | V.1: eigener QUIC + OpenSSL 3.5 | V.2: ngtcp2+nghttp3 |
|---|----------|------------------------------|---------------------|
| 1 | Fremdbibliotheken | **1** (libcrypto — wie bei OpenSSH) | 3 (libcrypto + ngtcp2 + nghttp3) |
| 2 | Build aus dem Basissystem | ja (Debian 13/Ubuntu 25.10/Fedora 43/Alpine 3.22) | ja, aber Versionen/Backends variieren (Debian: GnuTLS-Backend in der Basis) |
| 3 | Zero-copy-Kontrolle | **maximal** (unser Code: shadow-buf, chain, GSO-Aggregation — nginx-Patterns) | gut (writev-API, GSO), aber die Buffer gehören der Bibliothek |
| 4 | DATAGRAM | selbst ergänzen (RFC 9221: TP 0x0020, Frames 0x30/0x31, Queue, flow control) — **der zentrale ingenieurtechnische Mehraufwand** | out of the box vorhanden (`ngtcp2_conn_writev_datagram`) |
| 5 | Reife von QUIC (loss/cc) | unsere Verantwortung (der nginx-Code ist battle-tested, aber der DATAGRAM-Zusatz ist unserer) | **upstream ngtcp2** (wird von curl/Node genutzt) |
| 6 | Binärgröße | minimal (eigene Kürzung auf ssh3) | größer (vollständiges QUIC+h3) |
| 7 | Risiko der Neuartigkeit von OpenSSL 3.5 | QUIC API ist jung: QUIC-Fixes bis 3.5.8 (double-free) — neuesten Patch-Release verlangen | dieselbe TLS-Schicht, aber weniger eigener Code obendrauf |
| 8 | Erfüllung des Prinzips „wie OpenSSH“ | **vollständig**: Protokoll = unser Code, TLS = Systembibliothek | teilweise: Protokoll = fremde Bibliothek |

## 6. Empfehlung

**Hauptweg — Variante 1**: System-`libcrypto` (OpenSSL ≥3.5, Anforderung in CMake `find_package(OpenSSL 3.5)`) + QUIC-Transport als unser Quellcode (Adaption von nginx `src/event/quic/`, BSD-2) + minimale h3-Schicht. Fremdbibliotheken: eine, exakt wie bei OpenSSH; nur dass es statt zlib bei uns nichts gibt (wird nicht gebraucht). Dies ist bereits in ARCHITECTURE.md festgehalten (Entscheidung Nr. 2) — der Bericht bestätigt die Wahl und räumt die Alternativen aus dem Weg.

**Reserveweg — Variante 2** (zu dokumentieren, jetzt nicht zu bauen): Build-Option `S3_USE_NGTCP2` für Distributionen ohne OpenSSL 3.5 (Ubuntu 24.04 LTS, RHEL 10), falls Nachfrage aufkommt. ngtcp2 ist die einzige in Distributionen paketierte Alternative (MIT, C, DATAGRAM/0-RTT/GSO out of the box).

**Verworfen**: quiche, lsquic, picoquic, mvfst — Vendoring von BoringSSL/picotls, Fehlen in den Distributionen, bei quiche eine Rust-Toolchain. quictls — ein Fork außerhalb des upstream, keine „Basis“-Bibliothek (curl hat diesen Weg 2026 aufgegeben).

### Lizenz des übernommenen nginx-Codes (geprüft am Klon vom 2026-10-01)

`LICENSE` von nginx — **BSD 2-clause** («Copyright (C) 2002-2021 Igor Sysoev, Copyright (C) 2011-2026 Nginx, Inc.»). Erlaubt das Kopieren, Modifizieren und Verwenden in beliebigen Projekten (einschließlich proprietärer) unter zwei Bedingungen: (1) in den Quellen bleiben Copyright-Hinweis und Disclaimer erhalten; (2) in binären Lieferungen werden derselbe Hinweis und derselbe Disclaimer in der Dokumentation/im Lieferungsmaterial reproduziert. Kein Copyleft, keine Patentklausel.

Umfang der Übernahme: `src/event/quic/` ≈ 17.5k Zeilen (31 von 32 Dateien mit dem Header `Copyright (C) Nginx, Inc.`), `src/http/v3/` ≈ 7.4k Zeilen, plus punktuelle Core-Primitiven (pool/buf/string/rbtree).

Verpflichtungen von ssh3-c:
1. In den adaptierten Dateien den nginx-Header bewahren und den eigenen ergänzen (Pattern: nginx-Zeile + unsere).
2. Ins Repo-Stammverzeichnis — `LICENSE` (unsere) + `THIRD-PARTY-NOTICES.md` mit dem BSD-2-Text von nginx und der Liste der adaptierten Dateien.
3. Warenzeichen: das Produkt nginx/SSH3 nicht als „nginx“ bezeichnen.
4. Kompatibel mit der Publikationspolitik (dual-source): das öffentliche Repository mit diesen Hinweisen ist zulässig.

Unser eigener Code (unser Copyright, ohne nginx-Verpflichtungen): DATAGRAM RFC 9221, die Schicht `ssh3/` (conversation/channel/message/auth) komplett, `app/` (CLI, PTY, sftp, forwarding), Glue-Code der Adaption und der Build.

## 7. Konsequenzen für ARCHITECTURE.md und offene Fragen

Konsequenzen:
1. ssl-Schicht (Risiko Nr. 2 in ARCHITECTURE.md): drei API-Varianten (OpenSSL 3.5 / quictls / boringssl) verengen sich auf **eine** — das OpenSSL QUIC API; compat-Zweige entwerfen wir nicht. Für ältere Distributionen — offizielle Pakete von upstream OpenSSL oder die Option S3_USE_NGTCP2.
2. Neues Inkrement in M2: **DATAGRAM (RFC 9221)** oberhalb des adaptierten nginx-Codes — TP 0x0020, Frames 0x30/0x31, per-conn-Queue, flow control der Datagramme. Schätzung: mittel; der Code bleibt an einer Stelle (frames + connection), aber Tests sind Pflicht (das UDP-Forwarding hängt vollständig davon ab).
3. CMake: `find_package(OpenSSL 3.5 REQUIRED)` + compile-time-Prüfung auf Vorhandensein des QUIC API (analog zu nginx `auto/feature`); Failure-Meldung mit Hinweis auf die offiziellen Pakete.

Offene Fragen (zu klären in M3):
1. **QPACK-Minimum vs. Interop mit quic-go**: lässt sich quic-go/http3 dazu bringen, ausschließlich mit der statischen Tabelle zu kodieren (SETTINGS_QPACK_MAX_TABLE_CAPACITY=0, blocked streams=0) — dann kommt unsere h3-Schicht ohne dynamic table aus. In M3 per Experiment prüfen; falls nein — die QPACK-Tabelle von nginx adaptieren.
2. Reife des QUIC-Servers von OpenSSL 3.5.x: in CMake die Forderung nach dem neuesten Patch-Release (≥3.5.8) durchhalten; Test auf CERT-Fixes in CI.
3. Windows: OpenSSL 3.5 über vcpkg — als Ausnahme von den „Basisbibliotheken“ akzeptieren (für Windows ist das das Äquivalent zu „System“).

## 8. Quellen

- [OpenSSL 3.5 Series Release Notes](https://openssl-library.org/news/openssl-3.5-notes) — QUIC-Server, 0-RTT, LTS
- [OpenSSL 3.5 Final Release](https://openssl-library.org/post/2025-04-08-openssl-35-final-release)
- [curl HTTP/3 docs](https://curl.se/docs/http3.html) — OpenSSL 3.5.0+ erfordert ngtcp2 ≥1.12
- [curl SSL libraries compared](https://curl.se/docs/ssl-compared.html)
- [More HTTP/3 focus, one backend less](https://daniel.haxx.se/blog/2026/01/17/more-http-3-focus-one-backend-less) — Verzicht von curl auf das quictls-Backend
- [OpenSSL does a QUIC API](https://daniel.haxx.se/blog/2025/02/16/openssl-does-a-quic-api)
- [ngtcp2: writev_datagram (RFC 9221)](https://nghttp2.org/ngtcp2/ngtcp2_conn_writev_datagram.html), [programmers guide: 0-RTT](https://nghttp2.org/ngtcp2/programmers-guide.html)
- [ngtcp2 in Debian trixie](https://packages.debian.org/source/trixie/ngtcp2) (1.11.0), [Fedora ngtcp2](https://packages.fedoraproject.org/pkgs/ngtcp2), [Alpine nghttp3](https://pkgs.alpinelinux.org/package/edge/main/x86_64/nghttp3)
- [openssl 3.5.8 in Alpine 3.22](https://pkgs.alpinelinux.org/package/v3.22/main/x86/openssl)
- [Ubuntu 25.10 openssl 3.5.3](https://www.ubuntuupdates.org/package/core/questing/main/security/openssl), [Fedora 43 openssl 3.5.8](https://packages.fedoraproject.org/pkgs/openssl/openssl/fedora-43-updates.html)
- [openssl/packages — offizielle .deb/.rpm vom upstream](https://github.com/openssl/packages)
- [lsquic](https://github.com/litespeedtech/lsquic) (BoringSSL erforderlich), [quiche](https://github.com/cloudflare/quiche) (BoringSSL vendored), [picoquic build](https://www.privateoctopus.com/picoquic/building_picoquic.html) (picotls)
