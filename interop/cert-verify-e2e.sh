#!/bin/bash
#
# the host verification e2e (CERT-VERIFICATION-CANON.md 2.1-2.5, the B-ver
# wave): the CA-anchored first contact, the renewal re-pin, the self-signed
# accept-new auto pin, the ask decline on a pipe, the SSHFP verdicts against
# a stub resolver and the keylog gate of the release client
#
# the daemon rides the interop harness (the -3 session mode, the pubkey
# auth), the client rides the product build; the certificates generate in
# the work tree: the CA legs sign the leaves with a fresh EC CA and hand it
# to the client through SSL_CERT_FILE (the default verify paths read the
# env), the SSHFP legs answer through a python UDP stub picked up by the
# S3_SSHFP_DNS hook
#
# CLIENT-OPT-E2E.sh stays the pin-policy regression; this script owns the
# canon legs.  Verdict: CERT-VERIFY-E2E OK / FAILED

set -u

BIN=~/git/ssh3-c/build/linux-release/ssh3-server
BUILD=~/git/ssh3-c/build/linux-release

# the optional pin of the tree (the debug run): S3OPT_WORK + S3OPT_KEEP

if [ -n "${S3OPT_WORK:-}" ]; then
    WORK=$S3OPT_WORK
    rm -rf "$WORK"
    mkdir -p "$WORK"
else
    WORK=$(mktemp -d /tmp/s3verte2e.XXXXXX)
fi

FAILURES=0

pass() {
    echo "   PASS: $1"
}

fail() {
    echo "   FAIL: $1"
    FAILURES=$((FAILURES + 1))
}

die() {
    echo "cert-verify-e2e: $1" >&2
    exit 1
}

[ -x "$BIN" ] || die "the daemon is not built: $BIN"
[ -x "$BUILD/ssh3" ] || die "the product client is not built: $BUILD/ssh3"

SRVPID=
SRVPORT=

cleanup() {

    if [ -n "$SRVPID" ]; then
        kill "$SRVPID" 2>/dev/null
        wait "$SRVPID" 2>/dev/null
        SRVPID=
    fi

    if [ -n "${DNSPID:-}" ]; then
        kill "$DNSPID" 2>/dev/null
        wait "$DNSPID" 2>/dev/null
        DNSPID=
    fi

    [ -n "${S3OPT_KEEP:-}" ] || rm -rf "$WORK"
}

trap cleanup EXIT INT TERM

# the identity: the PKCS8 ed25519 of the C client (the same shape the
# client-opt ride), the authorized_keys line built by hand

openssl genpkey -algorithm ed25519 -out "$WORK/priv.pem" 2>/dev/null || die "openssl genpkey failed"

{
    printf '\000\000\000\013ssh-ed25519\000\000\000\040'
    openssl pkey -in "$WORK/priv.pem" -pubout -outform DER 2>/dev/null | tail -c 32
} | base64 | tr -d '\n' > "$WORK/blob.pub"

printf 'ssh-ed25519 %s cert-verify-e2e\n' "$(cat "$WORK/blob.pub")" > "$WORK/authorized_keys"

# the CA (EC, self-signed, CA:TRUE) and two leaves it signs; the leaves
# carry the SAN of the dial target (the IP literal 127.0.0.1 and the name
# localhost), cert-a rotates into cert-b in the renewal leg

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$WORK/ca.key" 2>/dev/null ||
    die "the ca key failed"

openssl req -x509 -key "$WORK/ca.key" -out "$WORK/ca.pem" -days 2 -subj /CN=cert-verify-e2e-ca \
    -addext basicConstraints=critical,CA:TRUE 2>/dev/null || die "the ca cert failed"

leaf() {

    local name=$1

    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
        -out "$WORK/$name.key" 2>/dev/null || die "the leaf key failed"

    openssl req -new -key "$WORK/$name.key" -out "$WORK/$name.csr" \
        -subj "/CN=cert-verify-e2e-$name" 2>/dev/null || die "the leaf csr failed"

    printf 'subjectAltName=IP:127.0.0.1,DNS:localhost\nbasicConstraints=CA:FALSE\n' > "$WORK/$name.ext"

    openssl x509 -req -in "$WORK/$name.csr" -CA "$WORK/ca.pem" -CAkey "$WORK/ca.key" \
        -CAcreateserial -out "$WORK/$name.pem" -days 2 -extfile "$WORK/$name.ext" 2>/dev/null ||
        die "the leaf cert failed"
}

leaf a
leaf b

selfcert() {
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/skey-$1.pem" \
        -out "$WORK/scert-$1.pem" -days 2 -subj /CN=cert-verify-e2e-self-$1 2>/dev/null ||
        die "the self cert failed"
}

selfcert s

# the daemon: the port scans up on a busy one, the readiness polls the
# INTEROP-LISTEN marker (the client-opt shape)

start_srv() {

    local cert=$1
    local key=$2

    SRVLOG="$WORK/srv-$3.log"

    local p=$((47400 + ($$ % 300)))
    local i=0

    while [ "$i" -lt 8 ]; do

        setsid nohup env SSH3C_PROTO=1 "$BIN" -3 -l "127.0.0.1:$p" -c "$cert" \
            -k "$key" -K "$WORK/authorized_keys" > "$SRVLOG" 2>&1 < /dev/null &
        SRVPID=$!

        local j=0

        while [ "$j" -lt 50 ]; do

            if grep -q INTEROP-LISTEN "$SRVLOG" 2>/dev/null; then
                SRVPORT=$p
                return 0
            fi

            if ! kill -0 "$SRVPID" 2>/dev/null; then
                break # the bind refused, the next port scans
            fi

            sleep 0.1
            j=$((j + 1))
        done

        kill "$SRVPID" 2>/dev/null
        wait "$SRVPID" 2>/dev/null
        SRVPID=

        p=$((p + 1))
        i=$((i + 1))
    done

    return 1
}

stop_srv() {

    if [ -n "$SRVPID" ]; then
        kill "$SRVPID" 2>/dev/null
        wait "$SRVPID" 2>/dev/null
        SRVPID=
    fi
}

# the plain (non-pty) client run: env rides first, the option text second

run_cli() {

    local home=$1
    shift

    env HOME="$WORK/$home" "$@" timeout 30 "$BUILD/ssh3" \
        -i "$WORK/priv.pem" "client@127.0.0.1:$SRVPORT/ssh3-term" \
        printf S3-CERT-OK < /dev/null > "$WORK/$home.out" 2>&1
}

# the kh pin text of a certificate: key + x509-certificate + base64 DER
# (the cert argument rides the path as given)

pin_line() {

    local cert=$1

    printf '127.0.0.1:%s/ssh3-term x509-certificate %s' \
        "$SRVPORT" "$(openssl x509 -in "$cert" -outform DER | base64 -w0)"
}

# --- the SSHFP stub resolver -------------------------------------------------
#
# the stub answers every question with one prebuilt A-record-free answer:
# the question echo + one SSHFP RR (pointer 0xc00c, type 44, class IN,
# ttl 60, rdata = algorithm + digest type + fingerprint bytes).  The
# fingerprint rides argv: the verified leg passes the real sha256 of the
# leaf DER, the mismatch leg passes a wrong one

DNSPID=
DNSPORT=

start_dns() {

    local fp_hex=$1
    local algo=$2

    DNSPORT=$((47800 + ($$ % 100)))

    cat > "$WORK/dns_stub.py" <<PYEOF
import socket
import sys

fp = bytes.fromhex("$fp_hex")
rdata = bytes([int(sys.argv[2]), 2]) + fp  # the leaf algorithm, the sha256 digest
rr = bytes([0xc0, 0x0c]) + (44).to_bytes(2, "big") + (1).to_bytes(2, "big")
rr += (60).to_bytes(4, "big") + len(rdata).to_bytes(2, "big") + rdata

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", int(sys.argv[1])))
sys.stdout.write("DNS-STUB-READY\\n")
sys.stdout.flush()

while True:
    q, peer = s.recvfrom(1500)
    if len(q) < 17:
        continue
    an = q[:2] + bytes([0x84, 0x00]) + q[4:6] + (1).to_bytes(2, "big") + q[10:12]
    s.sendto(an + q[12:] + rr, peer)
PYEOF

    setsid nohup python3 "$WORK/dns_stub.py" "$DNSPORT" "$algo" > "$WORK/dns.log" 2>&1 < /dev/null &
    DNSPID=$!

    local j=0

    while [ "$j" -lt 30 ]; do

        if grep -q DNS-STUB-READY "$WORK/dns.log" 2>/dev/null; then
            return 0
        fi

        if ! kill -0 "$DNSPID" 2>/dev/null; then
            return 1
        fi

        sleep 0.1
        j=$((j + 1))
    done

    return 1
}

stop_dns() {

    if [ -n "$DNSPID" ]; then
        kill "$DNSPID" 2>/dev/null
        wait "$DNSPID" 2>/dev/null
        DNSPID=
    fi
}

# --- leg 1: the CA-anchored first contact (canon 2.3) ------------------------
# the chain rides the CA handed through SSL_CERT_FILE, the SAN covers the
# dial literal; the default ask policy accepts without a prompt and without
# a pin record (the anchor is the CA, the pin writes only on accept-new)

echo "== leg 1: the CA-anchored first contact accepts without a pin (CA-FIRST-CONTACT)"

start_srv "$WORK/a.pem" "$WORK/a.key" a || die "the daemon start failed"

mkdir -p "$WORK/home-ca"

if env HOME="$WORK/home-ca" SSL_CERT_FILE="$WORK/ca.pem" timeout 30 "$BUILD/ssh3" \
    -i "$WORK/priv.pem" "client@127.0.0.1:$SRVPORT/ssh3-term" \
    printf S3-CERT-OK < /dev/null > "$WORK/home-ca.out" 2>&1; then

    if grep -q S3-CERT-OK "$WORK/home-ca.out"; then
        pass "the CA-anchored first contact rode through"
    else
        fail "the CA leg: the exec output missing ($(tail -1 "$WORK/home-ca.out"))"
    fi

    if [ ! -f "$WORK/home-ca/.ssh3/known_hosts" ]; then
        pass "no pin recorded for the CA-anchored host"
    else
        fail "the CA leg: the store wrote a pin ($(head -c 40 "$WORK/home-ca/.ssh3/known_hosts"))"
    fi
else
    fail "the CA leg: rc=$? ($(tail -2 "$WORK/home-ca.out"))"
fi

# --- leg 2: the renewal re-pin (canon 2.4) -----------------------------------
# the pin of leaf-a rides the store, the server rotates to leaf-b (the same
# CA, the same SAN); the chain verifies and the SAN covers, so the client
# re-pins and connects; the next run rides the fresh pin as a plain match

echo "== leg 2: the CA rotation re-pins and connects (RENEWAL-REPIN)"

mkdir -p "$WORK/home-ren/.ssh3"
pin_line "$WORK/a.pem" > "$WORK/home-ren/.ssh3/known_hosts"
printf '\n' >> "$WORK/home-ren/.ssh3/known_hosts"

if env HOME="$WORK/home-ren" SSL_CERT_FILE="$WORK/ca.pem" timeout 30 "$BUILD/ssh3" \
    -o strict-host-key-checking=yes -i "$WORK/priv.pem" \
    "client@127.0.0.1:$SRVPORT/ssh3-term" \
    printf S3-CERT-OK < /dev/null > "$WORK/home-ren-a.out" 2>&1; then
    pass "the pinned leaf-a host rides strict=yes"
else
    fail "the renewal leg: the pinned run refused ($(tail -1 "$WORK/home-ren-a.out"))"
fi

stop_srv
start_srv "$WORK/b.pem" "$WORK/b.key" b || die "the daemon restart failed"

if env HOME="$WORK/home-ren" SSL_CERT_FILE="$WORK/ca.pem" timeout 30 "$BUILD/ssh3" \
    -o strict-host-key-checking=yes -i "$WORK/priv.pem" \
    "client@127.0.0.1:$SRVPORT/ssh3-term" \
    printf S3-CERT-OK < /dev/null > "$WORK/home-ren-b.out" 2>&1; then

    if grep -q "certificate rotated, chain valid" "$WORK/home-ren-b.out"; then
        pass "the rotation logged the chain-valid re-pin"
    else
        fail "the renewal leg: the rotation log missing ($(tail -1 "$WORK/home-ren-b.out"))"
    fi

    if grep -q "$(openssl x509 -in "$WORK/b.pem" -outform DER | base64 -w0)" \
        "$WORK/home-ren/.ssh3/known_hosts" &&
        ! grep -q "$(openssl x509 -in "$WORK/a.pem" -outform DER | base64 -w0)" \
            "$WORK/home-ren/.ssh3/known_hosts"; then
        pass "the store holds leaf-b only after the re-pin"
    else
        fail "the renewal leg: the store rewrite wrong ($(wc -l < "$WORK/home-ren/.ssh3/known_hosts") lines)"
    fi
else
    fail "the renewal leg: the rotated run refused rc=$? ($(tail -2 "$WORK/home-ren-b.out"))"
fi

if env HOME="$WORK/home-ren" SSL_CERT_FILE="$WORK/ca.pem" timeout 30 "$BUILD/ssh3" \
    -o strict-host-key-checking=yes -i "$WORK/priv.pem" \
    "client@127.0.0.1:$SRVPORT/ssh3-term" \
    printf S3-CERT-OK < /dev/null > "$WORK/home-ren-c.out" 2>&1; then
    pass "the re-pinned host rides as a plain match"
else
    fail "the renewal leg: the follow-up run refused ($(tail -1 "$WORK/home-ren-c.out"))"
fi

stop_srv

# --- leg 3: the self-signed first contact auto-pins on accept-new ------------
# (canon 2.3: the pin rides accept-new with the out-of-band fingerprint in
# the log); a pipe session with the default ask refuses (leg 4)

echo "== leg 3: the self-signed first contact auto-pins on accept-new (SELF-ACCEPT-NEW)"

start_srv "$WORK/scert-s.pem" "$WORK/skey-s.pem" self || die "the daemon start failed"

mkdir -p "$WORK/home-acc"

if env HOME="$WORK/home-acc" timeout 30 "$BUILD/ssh3" -o strict-host-key-checking=accept-new \
    -i "$WORK/priv.pem" "client@127.0.0.1:$SRVPORT/ssh3-term" \
    printf S3-CERT-OK < /dev/null > "$WORK/home-acc.out" 2>&1; then

    if grep -q "accept-new: pinned the first-use certificate" "$WORK/home-acc.out" &&
        grep -q "S3-CERT-OK" "$WORK/home-acc.out"; then
        pass "the accept-new leg pinned and rode through"
    else
        fail "the accept-new leg: the pin log or the output missing"
    fi
else
    fail "the accept-new leg: rc=$? ($(tail -2 "$WORK/home-acc.out"))"
fi

echo "== leg 4: the self-signed first contact refuses on a pipe with the default ask (ASK-NONCONSOLE)"

mkdir -p "$WORK/home-ask"

if env HOME="$WORK/home-ask" timeout 30 "$BUILD/ssh3" -i "$WORK/priv.pem" \
    "client@127.0.0.1:$SRVPORT/ssh3-term" \
    printf S3-CERT-OK < /dev/null > "$WORK/home-ask.out" 2>&1; then
    fail "the ask leg: the pipe session connected"
else

    if grep -q "not interactive" "$WORK/home-ask.out"; then
        pass "the ask leg refused the non-interactive session"
    else
        fail "the ask leg: the refusal text missing ($(tail -1 "$WORK/home-ask.out"))"
    fi
fi

stop_srv

# --- legs 5-6: the SSHFP verdicts (canon 2.5) --------------------------------
# the stub resolver answers the in-addr.arpa question of the dial literal;
# the mismatch refuses (the strongest MITM signal), the verified pass rides
# accept-new and pins; strict-host-key-checking=no softens a mismatch

echo "== leg 5: the SSHFP mismatch refuses (SSHFP-MISMATCH-REJECT)"

start_srv "$WORK/scert-s.pem" "$WORK/skey-s.pem" self || die "the daemon start failed"

FP_REAL=$(openssl x509 -in "$WORK/scert-s.pem" -outform DER | sha256sum | cut -d' ' -f1)
FP_FAKE=0000000000000000000000000000000000000000000000000000000000000000

mkdir -p "$WORK/home-fp"
start_dns "$FP_FAKE" 1 || die "the dns stub start failed"

if env HOME="$WORK/home-fp" S3_SSHFP_DNS="127.0.0.1:$DNSPORT" timeout 30 "$BUILD/ssh3" \
    -o VerifyHostKeyDNS=yes -o strict-host-key-checking=accept-new \
    -i "$WORK/priv.pem" "client@127.0.0.1:$SRVPORT/ssh3-term" \
    printf S3-CERT-OK < /dev/null > "$WORK/home-fp.out" 2>&1; then
    fail "the sshfp mismatch leg: the run connected"
else

    if grep -q "SSHFP records published" "$WORK/home-fp.out"; then
        pass "the sshfp mismatch refused the run"
    else
        fail "the sshfp mismatch leg: the refusal text missing ($(tail -1 "$WORK/home-fp.out"))"
    fi
fi

stop_dns

echo "== leg 6: the SSHFP verified record rides the accept-new pin (SSHFP-VERIFIED-OK)"

mkdir -p "$WORK/home-fpv"
start_dns "$FP_REAL" 1 || die "the dns stub start failed"

if env HOME="$WORK/home-fpv" S3_SSHFP_DNS="127.0.0.1:$DNSPORT" timeout 30 "$BUILD/ssh3" \
    -o VerifyHostKeyDNS=yes -o strict-host-key-checking=accept-new \
    -i "$WORK/priv.pem" "client@127.0.0.1:$SRVPORT/ssh3-term" \
    printf S3-CERT-OK < /dev/null > "$WORK/home-fpv.out" 2>&1; then

    if grep -q "SSHFP verification of .* succeeded" "$WORK/home-fpv.out" &&
        grep -q "S3-CERT-OK" "$WORK/home-fpv.out"; then
        pass "the sshfp verified leg pinned and rode through"
    else
        fail "the sshfp verified leg: the log or the output missing"
    fi
else
    fail "the sshfp verified leg: rc=$? ($(tail -2 "$WORK/home-fpv.out"))"
fi

stop_dns

echo "== leg 6b: the sshfp mismatch softens under strict-host-key-checking=no (SSHFP-NO-SOFTEN)"

mkdir -p "$WORK/home-fpn"
start_dns "$FP_FAKE" 1 || die "the dns stub start failed"

if env HOME="$WORK/home-fpn" S3_SSHFP_DNS="127.0.0.1:$DNSPORT" timeout 30 "$BUILD/ssh3" \
    -o VerifyHostKeyDNS=yes -o strict-host-key-checking=no \
    -i "$WORK/priv.pem" "client@127.0.0.1:$SRVPORT/ssh3-term" \
    printf S3-CERT-OK < /dev/null > "$WORK/home-fpn.out" 2>&1; then
    pass "the no-policy softened the sshfp mismatch"
else
    fail "the sshfp soften leg: rc=$? ($(tail -2 "$WORK/home-fpn.out"))"
fi

stop_dns

echo "== leg 7: the release client carries no keylog without S3_KEYLOG (KEYLOG-GATE)"

mkdir -p "$WORK/home-kl"

env HOME="$WORK/home-kl" timeout 30 "$BUILD/ssh3" -o strict-host-key-checking=accept-new \
    -i "$WORK/priv.pem" "client@127.0.0.1:$SRVPORT/ssh3-term" \
    printf S3-CERT-OK < /dev/null > "$WORK/home-kl.out" 2>&1

if grep -q "^KEYLOG " "$WORK/home-kl.out"; then
    fail "the keylog leg: the release run printed the secrets"
else
    pass "no keylog lines without S3_KEYLOG"
fi

env HOME="$WORK/home-kl" S3_KEYLOG=1 timeout 30 "$BUILD/ssh3" -o strict-host-key-checking=accept-new \
    -i "$WORK/priv.pem" "client@127.0.0.1:$SRVPORT/ssh3-term" \
    printf S3-CERT-OK < /dev/null > "$WORK/home-kl2.out" 2>&1

if grep -q "^KEYLOG " "$WORK/home-kl2.out"; then
    pass "the S3_KEYLOG env rides the secrets"
else
    fail "the keylog leg: the env run printed no secrets"
fi

stop_srv

echo

if [ "$FAILURES" -eq 0 ]; then
    echo "CERT-VERIFY-E2E OK"
    exit 0
fi

echo "CERT-VERIFY-E2E FAILED: $FAILURES check(s)"
exit 1
