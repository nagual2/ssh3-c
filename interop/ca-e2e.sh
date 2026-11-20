#!/bin/sh
# the own-ca e2e of the wave 19 (PLAN.md 19): the ca state rides from
# init, the server cert issues from the CSR and lands on the daemon
# (the anchors ride the ca root), the client cert issues and dials
# with the phase 3 mapping (run-as off: the cert user needs no local
# account), the revoke regenerates the CRL the openssl confirms, the
# rotate retires the old root.
#
# usage: interop/ca-e2e.sh  (WSL; the binaries of the local release
# build; the daemon on the loopback ephemeral port)

set -u

BUILD=${S3CA_BUILD:-$(cd "$(dirname "$0")/.." && pwd)/build/linux-release}
SRV=$BUILD/ssh3-server
CLI=$BUILD/ssh3
CERT=$BUILD/ssh3-cert
CA=$BUILD/ssh3-ca

die() {
    echo "ca-e2e: $1" >&2
    exit 1
}

[ -x "$SRV" ] || die "the daemon is not built: $SRV"
[ -x "$CLI" ] || die "the client is not built: $CLI"
[ -x "$CERT" ] || die "the cert tool is not built: $CERT"
[ -x "$CA" ] || die "the ca tool is not built: $CA"

WORK=$(mktemp -d /tmp/s3ca-e2e.XXXXXX)
SRVPID=

cleanup() {

    if [ -n "$SRVPID" ]; then
        kill "$SRVPID" 2>/dev/null
        wait "$SRVPID" 2>/dev/null
        SRVPID=
    fi

    [ -n "${S3CA_KEEP:-}" ] || rm -rf "$WORK"
}

trap cleanup EXIT INT TERM

FAILURES=0

pass() {
    echo "   PASS: $1"
}

fail() {
    echo "   FAIL: $1"
    FAILURES=$((FAILURES + 1))
}

# the ca state: the init, the server pair, the client pair; the env
# pin rides every ca call below

export SSH3_CA_DIR="$WORK/ca"

"$CA" init "$SSH3_CA_DIR" >/dev/null || fail "the ca init broke"

"$CERT" keygen "$WORK/srv.key" rsa >/dev/null || fail "the server keygen broke"
"$CERT" csr "$WORK/srv.key" "$WORK/srv.csr" ca-e2e dns:ca-e2e.test,ip:127.0.0.1 >/dev/null || \
    fail "the server csr broke"
"$CA" sign-server "$WORK/srv.csr" "$WORK/srv.pem" >/dev/null || \
    fail "the server sign broke"

"$CERT" keygen "$WORK/alice.key" >/dev/null || fail "the client keygen broke"
"$CERT" csr "$WORK/alice.key" "$WORK/alice.csr" alice >/dev/null || \
    fail "the client csr broke"
"$CA" sign-client "$WORK/alice.csr" "$WORK/alice.pem" alice >/dev/null || \
    fail "the client sign broke"

[ -s "$WORK/srv.pem" ] && pass "the server chain issued" || fail "the server chain empty"
[ -s "$WORK/alice.pem" ] && pass "the client cert issued" || fail "the client cert empty"

# the daemon: the ca-issued server chain, the client certs required
# against the ca root, the run-as off (the cert user needs no local
# account)

SRVPORT=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')

SRVLOG="$WORK/srv.log"

setsid nohup env SSH3C_PROTO=1 SSH3_SESSION_PARK_SECONDS=30 \
    "$SRV" -3 -l "127.0.0.1:$SRVPORT" -c "$WORK/srv.pem" -k "$WORK/srv.key" \
    --run-as-user off \
    --client-cert-ca "$WORK/ca/ca.pem" --client-cert require \
    > "$SRVLOG" 2>&1 < /dev/null &
SRVPID=$!

i=0

while [ "$i" -lt 50 ]; do

    if grep -q INTEROP-LISTEN "$SRVLOG" 2>/dev/null; then
        break
    fi

    if ! kill -0 "$SRVPID" 2>/dev/null; then
        die "the daemon died on the start ($(tail -2 "$SRVLOG" | tr '\n' ' '))"
    fi

    sleep 0.1
    i=$((i + 1))
done

grep -q INTEROP-LISTEN "$SRVLOG" && pass "the daemon serves the ca-issued chain" ||
    fail "the daemon did not start"

# the leg: the client with the ca-issued client cert dials; the ca
# root rides the system policy via SSL_CERT_FILE (the trust hook)

out=$(SSL_CERT_FILE="$WORK/ca/ca.pem" timeout 20 "$CLI" -insecure \
    -o TrustStore=system --cert "$WORK/alice.pem" --key "$WORK/alice.key" \
    "client@127.0.0.1:$SRVPORT/ssh3-term" "echo CA-E2E-OK" 2>&1)

echo "$out" | grep -q "CA-E2E-OK" && pass "the client cert dial rides (the ca root trusts the pair)" ||
    fail "the client cert dial broke ($(echo "$out" | tail -1))"

# the leg: the client without the cert declines at the require gate

out=$(SSL_CERT_FILE="$WORK/ca/ca.pem" timeout 20 "$CLI" -insecure \
    -o TrustStore=system \
    "client@127.0.0.1:$SRVPORT/ssh3-term" "echo NO-CERT" 2>&1)

echo "$out" | grep -q "CA-E2E-OK" && fail "the no-cert dial rode (the require gate broke)" ||
    pass "the no-cert dial declines"

# the leg: the revoke regenerates the CRL the openssl confirms

ALIVE=$(grep -c '|V$' "$WORK/ca/index")

"$CA" revoke "$WORK/alice.pem" >/dev/null && pass "the revoke rode" || fail "the revoke broke"

[ "$(grep -c '|V$' "$WORK/ca/index")" -lt "$ALIVE" ] && \
    pass "the index marks the revocation" || fail "the index stayed live"

if [ -f "$WORK/ca/crl.pem" ]; then
    openssl verify -crl_check -CAfile "$WORK/ca/ca.pem" \
        -CRLfile "$WORK/ca/crl.pem" "$WORK/alice.pem" 2>&1 | \
        grep -q "certificate revoked" && \
        pass "the openssl confirms the revoked cert" || \
        fail "the CRL does not carry the revocation"
else
    fail "the crl.pem did not land"
fi

# the leg: the rotate retires the old root, the fresh root differs

"$CA" rotate >/dev/null && pass "the rotate rode" || fail "the rotate broke"

ls -d "$WORK"/ca.old.* >/dev/null 2>&1 && pass "the old state backs aside" ||
    fail "the backup is missing"

NEWROOT=$(openssl x509 -in "$WORK/ca/ca.pem" -noout -fingerprint -sha256 2>/dev/null)
OLDROOT=$(openssl x509 -in "$WORK/ca.old."*/ca.pem -noout -fingerprint -sha256 2>/dev/null)

[ "$NEWROOT" != "$OLDROOT" ] && pass "the fresh root differs from the retired one" ||
    fail "the rotate kept the old root"

if [ "$FAILURES" = "0" ]; then
    echo "CA-E2E OK"
else
    echo "CA-E2E FAILED: $FAILURES leg(s)"
    exit 1
fi
