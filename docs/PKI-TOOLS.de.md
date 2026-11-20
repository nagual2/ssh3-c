# PKI-Werkzeuge: ssh3-cert und ssh3-ca — die ausführliche Anleitung mit Beispielen
> Sprachen: [RU](PKI-TOOLS.md) · [EN](PKI-TOOLS.en.md) · DE (diese Datei)

Datum: 2026-11-20. Die Welle 19 ([PLAN.md](PLAN.md) §19): `ssh3-cert`
trägt die Ein-Schritt-Operationen des PKI-Lebens außerhalb des
permanent laufenden Daemons, `ssh3-ca` betreibt die eigene
Zertifizierungsstelle einer Installation (der Root, die Ausstellung,
der Widerruf, die Rotation).  Beide Werkzeuge bauen aus denselben
Quellen wie Daemon und Client, die einzige Abhängigkeit ist
libcrypto/OpenSSL 3.5+.

## Überblick: welches Werkzeug wofür

| Nr | Werkzeug | Verantwortung |
|----|----------|---------------|
| 1 | `ssh3-cert` | die Ein-Schritt-Operationen: die Schlüsselerzeugung (`keygen`), die Zertifikatsanfrage (`csr`), das Trust-Bundle-Update (`trust-update`), der Sitzungs-Ticket-Schlüssel (`ticket-key`), der Diagnose-Schnappschuss (`probe`) |
| 2 | `ssh3-ca` | die Zertifizierungsstelle: die Root-Initialisierung (`init`), die Ausstellung der Server- (`sign-server`) und Client-Zertifikate (`sign-client`) aus den CSRs, der Widerruf mit der CRL (`revoke`), die Root-Rotation (`rotate`) |

Der typische Ablauf: `ssh3-cert keygen` → `ssh3-cert csr` → `ssh3-ca
sign-server` → der Daemon konsumiert die fertigen Dateien.  Die
Werkzeuge sprechen nicht über das Netz miteinander - das Dateisystem
ist ihr Vermittler.

## Der CA-Zustand: das Verzeichnis-Layout

`ssh3-ca` lebt in einem Verzeichnis - `SSH3_CA_DIR` oder `~/.ssh3/ca`:

| Nr | Datei | Inhalt | Modus |
|----|-------|--------|-------|
| 1 | `ca.key` | der private Root-Schlüssel (ed25519) | `0600` |
| 2 | `ca.pem` | das selbstsignierte Root-Zertifikat, 10 Jahre, `O=ssh3-c/CN=ssh3-ca` | `0644` |
| 3 | `index` | das flache Register der Ausstellungen: `serial|type|subject|notafter|status` (`V` lebendig, `R` widerrufen) | `0600` |
| 4 | `crl.pem` | die Widerrufsliste, vom Root signiert; erscheint nach dem ersten `revoke` | `0644` |

Das Beispiel nach der Ausstellung eines Paares von Zertifikaten:

```text
$ ls -la ~/.ssh3/ca/
-rw------- 1 max max  119 Nov 20 18:33 ca.key
-rw-r--r-- 1 max max  489 Nov 20 18:33 ca.pem
-rw------- 1 max max   82 Nov 20 18:33 index
$ cat ~/.ssh3/ca/index
1eea69181eb1b6c0|C|/CN=alice|1734765900|V
```

## Die Root-Initialisierung

```text
$ ssh3-ca init ~/.ssh3/ca
the CA state of ~/.ssh3/ca rides: ca.key + ca.pem + index
```

Ein wiederholtes `init` auf dem bestehenden Zustand **lehnt ab** - der
Root wird nie stillschweigend überschrieben:

```text
$ ssh3-ca init ~/.ssh3/ca
ssh3-ca: the state of ~/.ssh3/ca was not created (an existing ca.key declines)
```

Der Root ist ed25519, 10 Jahre, die Erweiterungen:
`basicConstraints=critical,CA:TRUE`,
`keyUsage=critical,keyCertSign,cRLSign`, `subjectKeyIdentifier`.

## Das Server-Zertifikat: der vollständige Ablauf

### Schritt 1 - der Server-Schlüssel und die CSR

```text
$ ssh3-cert keygen srv.key rsa
the key rides: srv.key (rsa2048)
$ ssh3-cert csr srv.key srv.csr myserver dns:myserver.lan,dns:alt.lan,ip:192.0.2.10
the csr rides: srv.csr (CN=myserver, SAN DNS:myserver.lan,IP:192.0.2.10)
```

Die SAN-Formen: `dns:` ein Name, `ip:` eine Adresse, `email:` ein
Postfach - durch Kommata getrennt.  `keygen` ohne Argument liefert
ed25519; das Wort `rsa` liefert RSA 2048.

### Schritt 2 - die Ausstellung

```text
$ ssh3-ca sign-server srv.csr srv.pem
sign-server issued: srv.pem (serial 0e7f224314e4235f)
```

`srv.pem` - die Kette (Blatt + Root), die der Daemon direkt konsumiert:
die SAN fährt mit der Anfrage, 825 Tage, der Aussteller ist der
CA-Root, die Erweiterungen `basicConstraints=critical,CA:FALSE`,
`keyUsage=digitalSignature`, `extendedKeyUsage=serverAuth`,
`authorityKeyIdentifier`.

### Schritt 3 - der Daemon

```text
$ ssh3-server -3 -l 0.0.0.0:443 -c srv.pem -k srv.key -K authorized_keys
[info] ssh3-server version 0.5.21 listening on :::443
```

Der Client vertraut dem Paar auf einem der Wege:

- **der Blatt-Pin** - der `known_hosts`-Kanal arbeitet immer (`-o
  StrictHostKeyKey=accept-new` beim ersten Kontakt und danach der
  gewöhnliche Pin);
- **das Root-Vertrauen** - der CA-Root im Trust-Store des Clients (die
  `system`-Politik mit `SSL_CERT_FILE`, oder die Overlay-Datei
  `~/.ssh3/ca-bundle.pem` der `own`-Politik - die Mechanik der Welle 14).

## Das Client-Zertifikat: der vollständige Ablauf

### Schritt 1 - der Benutzerschlüssel und die CSR

```text
$ ssh3-cert keygen alice.key
the key rides: alice.key (ed25519)
$ ssh3-cert csr alice.key alice.csr alice
the csr rides: alice.csr (CN=alice)
```

Die SAN der Anfrage ist optional: die Benutzer-Zuordnung liest den
**CN**; für die passwortlosen Konten ist die SAN nützlicher -
`email:alice@corp.test` oder `spki:...` (die Mechanik der Phase 3,
`s3_ssh3_auth_cert_user()`).

### Schritt 2 - die Ausstellung durch die CA

```text
$ ssh3-ca sign-client alice.csr alice.pem alice
sign-client issued: alice.pem (serial 072c89023b0b534b)
```

Der CN der Anfrage wird durch das Argument `user` ersetzt (das letzte),
398 Tage, `extendedKeyUsage=clientAuth`.

### Schritt 3 - der Daemon mit dem geforderten Client-Zertifikat

```text
$ ssh3-server -3 -l 0.0.0.0:8443 -c srv.pem -k srv.key \
    --run-as-user off \
    --client-cert-ca ca/ca.pem --client-cert require
```

- `--client-cert-ca` - die Anker-Datei für die Verifikation der
  Client-Kette (unser CA-Root);
- `--client-cert require|optional|none` - die Politik (der
  `none`-Default hält die Kompatibilität);
- `--run-as-user off` - der Spawn ohne lokales Konto: der Benutzer
  fährt mit dem Zertifikat (die Mechanik der Phase 3, die lebendige
  Abnahme in [PLAN.md](PLAN.md) §14).

### Schritt 4 - der Client-Dial

```text
$ ssh3 -insecure -o TrustStore=system --cert alice.pem --key alice.key \
    "alice@server.lan:8443/ssh3-term"
```

- `--cert`/`--key` - das Paar des Client-Zertifikats (die Kette
  `alice.pem`: Blatt + Root);
- `SSL_CERT_FILE=ca/ca.pem` statt `-o TrustStore=system` - derselbe
  Anker über die Variable (der Test-Haken und der explizite Pfad
  gleichzeitig);
- `-insecure` hier lässt nur die Prüfung des **selbstsignierten**
  Server-Zertifikats außerhalb des Roots fallen - der CA-Anker fährt
  mit der `system`-Politik nativ.

Das Urteil des Servers: das Zertifikat gültig → der Benutzer = CN
(alice) → die Sitzung.  Ohne das Zertifikat bei `require` - die
Ablehnung am Handshake.  Ein fremdes Zertifikat (nicht von unserem
Root) - `401`, das Journal-Urteil `err 18`.

## Der Widerruf: revoke und die CRL

```text
$ ssh3-ca revoke alice.pem
revoked: alice.pem (crl.pem regenerated)
```

Das Argument - die Datei des ausgestellten Zertifikats **oder** die
Seriennnummer aus der `sign-*`-Ausgabe (oder aus dem `index`).  Nach
dem Widerruf:

- die Zeile des `index` markiert `R`;
- `crl.pem` regeneriert und signiert mit dem Root.

Die Prüfung mit den OpenSSL-Mitteln (das unabhängige Instrument):

```text
$ openssl verify -crl_check -CAfile ca/ca.pem -CRLfile ca/crl.pem alice.pem
error 23 at 0 depth lookup: certificate revoked
error alice.pem: verification failed
```

**Die v1-Grenze:** der Server prüft die CRL am Dial noch nicht - der
Enforcement auf der Daemon-Seite und die CRL-Veröffentlichung über das
Netz fahren mit dem nächsten Inkrement ([PLAN.md](PLAN.md) §19,
dokumentiert).  Der Widerruf ist jetzt der Registereintrag und die
fertige CRL für die Infrastruktur.

Der Widerruf einer unbekannten Seriennummer lehnt ab, ohne den
Zustand zu berühren:

```text
$ ssh3-ca revoke ffffffffffffffff
ssh3-ca: the revoke of ffffffffffffffff declined (the serial is unknown or the state is frozen)
```

## Die Root-Rotation

```text
$ ssh3-ca rotate
the CA rotated: the old state backs aside, 2 cert(s) need the re-issuance
```

Das ganze alte Verzeichnis fährt zur Seite nach
`~/.ssh3/ca.old.<unix-epoch>`, der frische Root nimmt seinen Platz
ein.  Die Zertifikate des alten Roots brauchen eine Neu-Ausstellung
(der andere Aussteller) - das Werkzeug druckt den Zähler; das
`~/.ssh3/ca.old.*/` bleibt beim Betreiber als Archiv.  Das ist die
bewusste Form von v1: die sanfte Rotation mit zwei lebendigen Roots
fährt mit dem nächsten Inkrement.

## ssh3-cert: die restlichen Kommandos

### trust-update - das Trust-Bundle-Update

```text
$ ssh3-cert trust-update
```

Es lädt das Trust-Bundle still (der Mozilla-Satz von curl.se als
Default), prüft jeden PEM-Block und landet `~/.ssh3/trust-bundle.pem`
atomar über die eingebetteten Roots; das Manifest daneben trägt die
Quelle und die SHA-256; jeder Ausfall hält die frühere Kopie (der
Offline-Lauf des Schedulers ist die gewöhnliche Form).  Exit 0 - ein
frisches Bundle, 255 - das veraltete.  Der Scheduler: die systemd
User-Units `ssh3-trust-update.{service,timer}` (deb/openwrt) oder die
Scheduler-Aufgabe unter win (die Man-Seite).  Die Details fahren mit
[PLAN.md](PLAN.md) §14, Phase 1c.

### ticket-key - der Sitzungs-Ticket-Schlüssel vor dem ersten Start

```text
$ ssh3-cert ticket-key /etc/ssh3/session-ticket.key
```

Es erzeugt die 80-Byte-Datei (16 Name + 32 HMAC + 32 AES, `0600`) -
der vor-gesäte Schlüssel überlebt die erste Daemon-Lebenszeit und hält
den Reconnect-Ticket vom ersten Start an stabil.

### probe - der Diagnose-Schnappschuss

```text
$ ssh3-cert probe
[info] the embedded ISRG roots ride the store (109 added)
```

Es druckt die OpenSSL-Version und die Zähler der Trust-Stores
(own/system) - kein Dial, kein Netz.

## Die Umgebung und die Integration

| Nr | Variable | Inhalt |
|----|----------|--------|
| 1 | `SSH3_CA_DIR` | das CA-Zustandsverzeichnis (der Default `~/.ssh3/ca`) |
| 2 | `SSL_CERT_FILE` / `SSL_CERT_DIR` | die Anker der `system`-Politik (der Standard-OpenSSL-Haken, verifiziert) |
| 3 | `S3_TRUST_BUNDLE` | der Overlay-Pfad-Test-Haken (nur die Units) |

Die Pakete: der deb-Kanal `ssh3-client-bundle` trägt
`/usr/bin/ssh3-cert` und `/usr/bin/ssh3-ca` mit den Man-Seiten;
openwrt trägt die Wrapper `/usr/bin/ssh3-{cert,ca}` über dem
Bundle-Verzeichnis; Windows - `ssh3-cert.exe` in den Release-Assets
neben `ssh3.exe` (es aktualisiert zusammen mit dem Client seit der
Welle 19).

Die offenen Grenzen von v1 (dokumentiert in [PLAN.md](PLAN.md) §19):
der CRL-Enforcement auf dem Server, die CRL-Veröffentlichung, die
sanfte Rotation mit zwei lebendigen Roots, das Passwort auf `ca.key`.
Das Format des v1-Zustands ist stabil - die künftigen Inkremente
lesen dieselben Dateien.
