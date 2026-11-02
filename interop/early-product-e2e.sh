#!/bin/sh
# the 0-RTT product e2e (the stage 2a+2b): the ticket cache of
# ~/.ssh3/tickets and the CONNECT flight inside the early-data window
#
#   1. the first product run (the cold cache) rides the plain 1-RTT:
#      the session lands 'SSH3-SESSION-REUSED 0' and the cache file
#   2. the second run (the warm cache) resumes: 'SSH3-SESSION-REUSED
#      1', the CONNECT flies in the early window, the server answers
#      425 (RFC 8470, the auth stays out of the replay window) and
#      the post-handshake retry carries the credentials - the exec
#      finishes clean
#
# usage: early-product-e2e.sh (WSL)
set -u

ROOT=${1:-$(cd "$(dirname "$0")/.." && pwd)}
BUILD=${BUILD:-$ROOT/build/linux-release}
BIN=$BUILD/ssh3
FAILURES=0

die() {
    echo "early-product-e2e: $1" >&2
    exit 1
}

fail() {
    echo "   FAIL: $1"
    FAILURES=$((FAILURES + 1))
}

pass() {
    echo "   PASS: $1"
}

[ -x "$BIN" ] || die "the product client is not built ($BIN)"

W=$(mktemp -d /tmp/early-product-e2e.XXXXXX)
SRVLOG=$W/srv.log

openssl genpkey -algorithm ed25519 -out "$W/priv.pem" 2>/dev/null ||
    die "openssl genpkey failed"

{
    printf '\000\000\000\013ssh-ed25519\000\000\000\040'
    openssl pkey -in "$W/priv.pem" -pubout -outform DER 2>/dev/null | tail -c 32
} | base64 | tr -d '\n' > "$W/blob.pub"

printf 'ssh-ed25519 %s early-product-e2e\n' "$(cat "$W/blob.pub")" > "$W/authorized_keys"

openssl req -x509 -sha256 -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout "$W/key.pem" -days 2 -out "$W/cert.pem" -subj /CN=early-product-e2e \
    -addext "subjectAltName=IP:127.0.0.1" 2>/dev/null || die "openssl req failed"

p=47910

setsid nohup env SSH3C_PROTO=1 "$BUILD/ssh3-server" -3 -l "127.0.0.1:$p" \
    -c "$W/cert.pem" -k "$W/key.pem" -K "$W/authorized_keys" \
    > "$SRVLOG" 2>&1 < /dev/null &

SRVPID=$!
sleep 1

grep -q INTEROP-LISTEN "$SRVLOG" || die "the daemon did not come up: $(tail -2 "$SRVLOG")"

run_cli() { # $1 = the log prefix
    HOME="$W/home" "$BIN" -v -n -i "$W/priv.pem" -insecure \
        "max@127.0.0.1:$p/ssh3-term" true \
        > "$W/$1.out" 2> "$W/$1.err"
}

echo "== 1: the cold cache rides the plain 1-RTT"

run_cli r1

RC=$?

if [ "$RC" -eq 0 ] && grep -q "SSH3-SESSION-REUSED 0" "$W/r1.err"; then
    pass "the cold run rode the 1-RTT (rc 0, reused 0)"
else
    fail "the cold run: rc=$RC $(tail -3 "$W/r1.err")"
fi

if [ -f "$W/home/.ssh3/tickets" ]; then
    pass "the ticket cache file landed"
else
    fail "no ~/.ssh3/tickets after the cold run"
fi

echo "== 2: the warm cache flies the CONNECT in the early window"

run_cli r2

RC=$?

if [ "$RC" -eq 0 ] && grep -q "SSH3-SESSION-REUSED 1" "$W/r2.err"; then
    pass "the warm run resumed the session (rc 0, reused 1)"
else
    fail "the warm run: rc=$RC $(tail -3 "$W/r2.err")"
fi

# the refusal of the early flight rides either the 425 (the request
# processed pre-handshake) or the 401 (the loopback race: the early
# CONNECT lands when the server handshake is done, the auth-less
# request draws the plain refusal) - both codes take the same retry

if grep -q "INTEROP-EARLY-425" "$SRVLOG"; then
    pass "the early CONNECT drew the 425 and the retry carried the auth"
elif grep -q "INTEROP-H3-REJECT code=401" "$SRVLOG"; then
    pass "the early CONNECT drew the loopback 401 and the retry carried the auth"
else
    fail "no early-flight refusal (425/401) in the daemon log"
fi

kill "$SRVPID" 2>/dev/null
wait "$SRVPID" 2>/dev/null

rm -rf "$W"

if [ "$FAILURES" -gt 0 ]; then
    echo "early-product-e2e: FAILED ($FAILURES)"
    exit 1
fi

echo "early-product-e2e: OK"
