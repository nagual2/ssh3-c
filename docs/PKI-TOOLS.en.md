# PKI tools: ssh3-cert and ssh3-ca — the detailed guide with examples
> Languages: [RU](PKI-TOOLS.md) (this language's original) · EN (this file) · [DE](PKI-TOOLS.de.md)

Date: 2026-11-20. The wave 19 ([PLAN.md](PLAN.md) §19): `ssh3-cert`
carries the one-shot operations of the PKI life outside the
always-running daemon, `ssh3-ca` runs the own certification authority
of one installation (the root, the issuance, the revocation, the
rotation).  Both tools build from the same sources as the daemon and
the client, the only dependency is libcrypto/OpenSSL 3.5+.

## The overview: which tool for what

| № | Tool | The responsibility |
|---|------|--------------------|
| 1 | `ssh3-cert` | the one-shot operations: the key generation (`keygen`), the certificate request (`csr`), the trust bundle update (`trust-update`), the session ticket key (`ticket-key`), the diagnostic snapshot (`probe`) |
| 2 | `ssh3-ca` | the certification authority: the root init (`init`), the server (`sign-server`) and client (`sign-client`) certificate issuance from the CSRs, the revocation with the CRL (`revoke`), the root rotation (`rotate`) |

The typical flow: `ssh3-cert keygen` → `ssh3-cert csr` → `ssh3-ca
sign-server` → the daemon consumes the ready files.  The tools do not
talk to each other over the network - the filesystem is their
intermediary.

## The CA state: the directory layout

`ssh3-ca` lives in one directory - `SSH3_CA_DIR` or `~/.ssh3/ca`:

| № | File | What | Mode |
|---|------|------|------|
| 1 | `ca.key` | the root private key (ed25519) | `0600` |
| 2 | `ca.pem` | the self-signed root certificate, 10 years, `O=ssh3-c/CN=ssh3-ca` | `0644` |
| 3 | `index` | the flat ledger of the issuance: `serial|type|subject|notafter|status` (`V` live, `R` revoked) | `0600` |
| 4 | `crl.pem` | the revocation list, signed by the root; appears after the first `revoke` | `0644` |

The example after a pair of certs was issued:

```text
$ ls -la ~/.ssh3/ca/
-rw------- 1 max max  119 Nov 20 18:33 ca.key
-rw-r--r-- 1 max max  489 Nov 20 18:33 ca.pem
-rw------- 1 max max   82 Nov 20 18:33 index
$ cat ~/.ssh3/ca/index
1eea69181eb1b6c0|C|/CN=alice|1734765900|V
```

## The root init

```text
$ ssh3-ca init ~/.ssh3/ca
the CA state of ~/.ssh3/ca rides: ca.key + ca.pem + index
```

A repeated `init` on the existing state **declines** - the root never
overwrites silently:

```text
$ ssh3-ca init ~/.ssh3/ca
ssh3-ca: the state of ~/.ssh3/ca was not created (an existing ca.key declines)
```

The root is ed25519, 10 years, the extensions: `basicConstraints=critical,
CA:TRUE`, `keyUsage=critical,keyCertSign,cRLSign`, `subjectKeyIdentifier`.

## The server certificate: the full flow

### Step 1 - the server key and the CSR

```text
$ ssh3-cert keygen srv.key rsa
the key rides: srv.key (rsa2048)
$ ssh3-cert csr srv.key srv.csr myserver dns:myserver.lan,dns:alt.lan,ip:192.0.2.10
the csr rides: srv.csr (CN=myserver, SAN DNS:myserver.lan,IP:192.0.2.10)
```

The SAN forms: `dns:` a name, `ip:` an address, `email:` a mailbox -
comma separated.  `keygen` without the argument gives ed25519; the
word `rsa` gives RSA 2048.

### Step 2 - the issuance

```text
$ ssh3-ca sign-server srv.csr srv.pem
sign-server issued: srv.pem (serial 0e7f224314e4235f)
```

`srv.pem` - the chain (leaf + root) the daemon consumes directly: the
SAN rides the request, 825 days, the issuer is the CA root, the
extensions `basicConstraints=critical,CA:FALSE`,
`keyUsage=digitalSignature`, `extendedKeyUsage=serverAuth`,
`authorityKeyIdentifier`.

### Step 3 - the daemon

```text
$ ssh3-server -3 -l 0.0.0.0:443 -c srv.pem -k srv.key -K authorized_keys
[info] ssh3-server version 0.5.21 listening on :::443
```

The client trusts the pair one of the ways:

- **the leaf pin** - the `known_hosts` channel works always (`-o
  StrictHostKeyKey=accept-new` on the first contact and the ordinary
  pin after);
- **the root trust** - the CA root in the trust store of the client
  (the `system` policy with `SSL_CERT_FILE`, or the overlay file
  `~/.ssh3/ca-bundle.pem` of the `own` policy - the mechanics of the
  wave 14).

## The client certificate: the full flow

### Step 1 - the user key and the CSR

```text
$ ssh3-cert keygen alice.key
the key rides: alice.key (ed25519)
$ ssh3-cert csr alice.key alice.csr alice
the csr rides: alice.csr (CN=alice)
```

The SAN of the request is optional: the user mapping reads the **CN**;
for the password-less accounts the SAN is more useful -
`email:alice@corp.test` or `spki:...` (the mechanics of the phase 3,
`s3_ssh3_auth_cert_user()`).

### Step 2 - the issuance by the CA

```text
$ ssh3-ca sign-client alice.csr alice.pem alice
sign-client issued: alice.pem (serial 072c89023b0b534b)
```

The CN of the request is overridden by the `user` argument (the last
one), 398 days, `extendedKeyUsage=clientAuth`.

### Step 3 - the daemon with the client certificate required

```text
$ ssh3-server -3 -l 0.0.0.0:8443 -c srv.pem -k srv.key \
    --run-as-user off \
    --client-cert-ca ca/ca.pem --client-cert require
```

- `--client-cert-ca` - the anchor file for the client chain
  verification (our CA root);
- `--client-cert require|optional|none` - the policy (the `none`
  default keeps the compatibility);
- `--run-as-user off` - the spawn without a local account: the user
  rides the certificate (the phase 3 mechanics, the live acceptance
  in [PLAN.md](PLAN.md) §14).

### Step 4 - the client dial

```text
$ ssh3 -insecure -o TrustStore=system --cert alice.pem --key alice.key \
    "alice@server.lan:8443/ssh3-term"
```

- `--cert`/`--key` - the pair of the client certificate (the chain
  `alice.pem`: leaf + root);
- `SSL_CERT_FILE=ca/ca.pem` instead of `-o TrustStore=system` - the
  same anchor through the variable (the test hook and the explicit
  path at once);
- `-insecure` here drops only the check of the **self-signed** server
  cert outside the root - the CA anchor rides the `system` policy
  natively.

The server verdict: the certificate valid → the user = CN (alice) →
the session.  Without the certificate at `require` - the refusal on
the handshake.  A foreign certificate (not of our root) - `401`, the
journal verdict `err 18`.

## The revocation: revoke and the CRL

```text
$ ssh3-ca revoke alice.pem
revoked: alice.pem (crl.pem regenerated)
```

The argument - the file of the issued certificate **or** the serial
from the `sign-*` output (or from the `index`).  After the revocation:

- the line of the `index` marks `R`;
- `crl.pem` regenerates and signs with the root.

The check by the OpenSSL means (the independent instrument):

```text
$ openssl verify -crl_check -CAfile ca/ca.pem -CRLfile ca/crl.pem alice.pem
error 23 at 0 depth lookup: certificate revoked
error alice.pem: verification failed
```

**The v1 boundary:** the server does not check the CRL on the dial
yet - the enforcement on the daemon side and the CRL publication over
the network ride the next increment ([PLAN.md](PLAN.md) §19,
documented).  The revocation now is the ledger entry and the ready
CRL for the infrastructure.

The revocation of an unknown serial declines without touching the
state:

```text
$ ssh3-ca revoke ffffffffffffffff
ssh3-ca: the revoke of ffffffffffffffff declined (the serial is unknown or the state is frozen)
```

## The root rotation

```text
$ ssh3-ca rotate
the CA rotated: the old state backs aside, 2 cert(s) need the re-issuance
```

The whole old directory moves aside to `~/.ssh3/ca.old.<unix-epoch>`,
the fresh root takes its place.  The certs of the old root need a
re-issuance (the other issuer) - the tool prints the count; the
`~/.ssh3/ca.old.*/` stays with the operator as the archive.  This is
the deliberate shape of v1: the smooth rotation with two live roots
rides the next increment.

## ssh3-cert: the rest of the commands

### trust-update - the trust bundle update

```text
$ ssh3-cert trust-update
```

It fetches the trust bundle quietly (the Mozilla set of curl.se by
default), validates every PEM block and lands
`~/.ssh3/trust-bundle.pem` atomically over the embedded roots; the
manifest next to it carries the source and the SHA-256; any failure
keeps the previous copy (the offline scheduler run is the plain
shape).  Exit 0 - a fresh bundle, 255 - the stale one.  The
scheduler: the systemd user units `ssh3-trust-update.{service,timer}`
(deb/openwrt) or the scheduler task on win (the man page).  The
details ride [PLAN.md](PLAN.md) §14, phase 1c.

### ticket-key - the session ticket key before the first start

```text
$ ssh3-cert ticket-key /etc/ssh3/session-ticket.key
```

It generates the 80-byte file (16 name + 32 HMAC + 32 AES, `0600`) -
the pre-seeded key survives the first daemon lifetime and keeps the
reconnect ticket stable from the very first start.

### probe - the diagnostic snapshot

```text
$ ssh3-cert probe
[info] the embedded ISRG roots ride the store (109 added)
```

It prints the OpenSSL version and the trust store counters
(own/system) - no dial, no network.

## The environment and the integration

| № | Variable | What |
|---|----------|------|
| 1 | `SSH3_CA_DIR` | the CA state directory (the default `~/.ssh3/ca`) |
| 2 | `SSL_CERT_FILE` / `SSL_CERT_DIR` | the anchors of the `system` policy (the standard OpenSSL hook, verified) |
| 3 | `S3_TRUST_BUNDLE` | the overlay path test hook (the units only) |

The packages: the deb channel `ssh3-client-bundle` carries
`/usr/bin/ssh3-cert` and `/usr/bin/ssh3-ca` with the man pages; the
openwrt carries the wrappers `/usr/bin/ssh3-{cert,ca}` over the
bundle directory; Windows - `ssh3-cert.exe` in the release assets
next to `ssh3.exe` (it updates together with the client since the
wave 19).

The open boundaries of v1 (documented in [PLAN.md](PLAN.md) §19): the
CRL enforcement on the server, the CRL publication, the smooth
rotation with two live roots, the password on `ca.key`.  The format
of the v1 state is stable - the future increments read the same
files.
