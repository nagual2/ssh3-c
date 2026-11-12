#!/bin/sh
# the trust store e2e (PLAN.md 14, phase 1a): the policy surface of
# the product client
#
#   1. the unknown -o TrustStore value refuses with the hint (the
#      OPT-TRUST-REJECT marker), no dial rides
#   2. the --trust-store long form refuses the bad value (the
#      FLAG-TRUST-REJECT marker), no dial rides
#   3. the own policy dials the pinned host over the TOFU question
#      (the OWN-PIN-OK marker), the exec rides through
#   4. the system policy dials the same host the same way (the
#      SYSTEM-PIN-OK marker): the union contract - the system build
#      carries at least the own set, the dial never regresses on
#      the policy choice
#
# the verdict: TRUST-STORE-E2E OK / FAILED
#
# usage: interop/trust-store-e2e.sh   (WSL)
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD=${BUILD:-$ROOT/build/linux-release}
FAILURES=0

die() {
    echo "trust-store-e2e: $1" >&2
    exit 1
}

fail() {
    echo "   FAIL: $1"
    FAILURES=$((FAILURES + 1))
}

pass() {
    echo "   PASS: $1"
}

[ -x "$BUILD/ssh3" ] || die "the product client is not built: $BUILD/ssh3"

W=$(mktemp -d /tmp/s3trust.XXXXXX)
SRVPID=

cleanup() {
    if [ -n "$SRVPID" ]; then
        kill "$SRVPID" 2>/dev/null
        wait "$SRVPID" 2>/dev/null
    fi
    [ -n "${TRUST_KEEP:-}" ] || rm -rf "$W"
}
trap cleanup EXIT INT TERM

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/key.pem" \
    -out "$W/cert.pem" -days 2 -subj /CN=trust-store-e2e 2>/dev/null || die "openssl req failed"

openssl genpkey -algorithm ed25519 -out "$W/priv.pem" 2>/dev/null || die "openssl genpkey failed"

{
    printf '\000\000\000\013ssh-ed25519\000\000\000\040'
    openssl pkey -in "$W/priv.pem" -pubout -outform DER 2>/dev/null | tail -c 32
} | base64 | tr -d '\n' > "$W/blob.pub"

printf 'ssh-ed25519 %s trust-store-e2e\n' "$(cat "$W/blob.pub")" > "$W/authorized_keys"

p=47760
setsid nohup env SSH3C_PROTO=1 "$BUILD/ssh3-server" -3 -l "127.0.0.1:$p" \
    -c "$W/cert.pem" -k "$W/key.pem" -K "$W/authorized_keys" > "$W/srv.log" 2>&1 < /dev/null &
SRVPID=$!

i=0
while [ "$i" -lt 50 ]; do
    grep -q INTEROP-LISTEN "$W/srv.log" 2>/dev/null && break
    kill -0 "$SRVPID" 2>/dev/null || die "the daemon died: $(tail -2 "$W/srv.log")"
    sleep 0.1
    i=$((i + 1))
done
grep -q INTEROP-LISTEN "$W/srv.log" || die "the daemon did not come up"

mkdir -p "$W/home"

# the pty run: the TOFU question feeds the pin store (the accept-new
# canon), the exec rides after it

run_pty() { # $1 = policy option pair ("", "-o TrustStore=own"), $2 = marker
    printf 'yes\n' | timeout 30 script -qec \
        "env HOME=$W/home $BUILD/ssh3 $1 -i $W/priv.pem client@127.0.0.1:$p/ssh3-term printf $2" \
        /dev/null > "$W/$3.out" 2>&1
}

echo "== leg 1: the unknown -o TrustStore value refuses (OPT-TRUST-REJECT)"

if timeout 10 "$BUILD/ssh3" -o TrustStore=bogus bob@127.0.0.1:1/ssh3-term \
    > "$W/leg1.out" 2> "$W/leg1.err"; then
    fail "the value leg: the run exited 0"
else
    RC=$?

    if [ "$RC" -eq 255 ] && grep -q "TrustStore= wants own|system" "$W/leg1.err"; then
        pass "the unknown value refused 255 with the hint (rc 255)"
    else
        fail "the value leg: rc=$RC $(tail -1 "$W/leg1.err")"
    fi
fi

echo "== leg 2: the --trust-store long form refuses the bad value (FLAG-TRUST-REJECT)"

if timeout 10 "$BUILD/ssh3" --trust-store nonsense bob@127.0.0.1:1/ssh3-term \
    > "$W/leg2.out" 2> "$W/leg2.err"; then
    fail "the flag leg: the run exited 0"
else
    RC=$?

    if [ "$RC" -eq 255 ] && grep -q -- "--trust-store wants own|system" "$W/leg2.err"; then
        pass "the bad flag value refused 255 with the hint (rc 255)"
    else
        fail "the flag leg: rc=$RC $(tail -1 "$W/leg2.err")"
    fi
fi

echo "== leg 3: the own policy dials the pinned host (OWN-PIN-OK)"

run_pty "-o TrustStore=own" "S3-TRUST-OWN-OK" leg3

if grep -q "S3-TRUST-OWN-OK" "$W/leg3.out" &&
    grep -q "Pinned 127.0.0.1:" "$W/leg3.out"; then
    pass "the own dial pinned and the exec rode through"
else
    fail "the own leg: $(tail -2 "$W/leg3.out")"
fi

echo "== leg 4: the system policy dials the same host (SYSTEM-PIN-OK)"

run_pty "-o TrustStore=system" "S3-TRUST-SYS-OK" leg4

if grep -q "S3-TRUST-SYS-OK" "$W/leg4.out"; then
    pass "the system dial rode through on the union set"
else
    fail "the system leg: $(tail -2 "$W/leg4.out")"
fi

if [ "$FAILURES" -eq 0 ]; then
    echo "TRUST-STORE-E2E OK"
    exit 0
fi

echo "TRUST-STORE-E2E FAILED: $FAILURES check(s)"
exit 1
