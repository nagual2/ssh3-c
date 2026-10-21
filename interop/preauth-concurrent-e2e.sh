#!/bin/sh
# the concurrent pre-auth e2e (PLAN.md 9, B9): the pre-auth state of
# the CONNECT is per connection, so a second client that connects
# between the halves of the first request must not touch its fields
#
#   1. client A: the CONNECT split in two halves (the knob
#      S3INTEROP_SPLIT_CONNECT), the Bearer JWT of alice
#   2. client B: a whole CONNECT in the pause of A, the Basic auth of
#      bob
#   3. both must be served: A as alice, B as bob
#
# the verdict: PREAUTH-CONCURRENT-E2E OK / FAILED
#
# usage: interop/preauth-concurrent-e2e.sh   (WSL)
# requires: the C runners (cmake --build build/linux-release)
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD=${BUILD:-$ROOT/build/linux-release}
BIN=${SSH3C_SERVER_BIN:-$BUILD/ssh3-server}
CLI=${SSH3C_CLIENT_BIN:-$BUILD/s3interop_client}

die() {
    echo "preauth-concurrent-e2e: $1" >&2
    exit 1
}

[ -x "$BIN" ] || die "the daemon is not built: $BIN"
[ -x "$CLI" ] || die "the interop client is not built: $CLI"

WORK=$(mktemp -d /tmp/s3preauth.XXXXXX)
SRVPIDS=""

cleanup() {
    for p in $SRVPIDS; do
        kill "$p" 2>/dev/null
        wait "$p" 2>/dev/null
    done

    rm -rf "$WORK"
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

# the identities: alice by key (the Bearer JWT), bob by password (the
# Basic auth) - two different backends, so a mixed verdict shows up as
# a refused request

openssl genpkey -algorithm ed25519 -out "$WORK/alice.pem" 2>/dev/null ||
    die "openssl genpkey failed"

{
    printf '\000\000\000\013ssh-ed25519\000\000\000\040'
    openssl pkey -in "$WORK/alice.pem" -pubout -outform DER 2>/dev/null | tail -c 32
} | base64 | tr -d '\n' > "$WORK/alice.pub"

printf 'ssh-ed25519 %s preauth-concurrent-e2e\n' "$(cat "$WORK/alice.pub")" > "$WORK/authorized_keys"

printf 'bob:bobpassword\n' > "$WORK/passfile"

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/key.pem" -out "$WORK/cert.pem" \
    -days 2 -subj /CN=preauth-concurrent-e2e 2>/dev/null || die "openssl req failed"

mkdir -p "$WORK/.ssh3"

# the daemon: the pubkey backend for alice, the password file for bob

S_LOG="$WORK/srv.log"
S_P=$((47950 + ($$ % 40)))
S_PID=

setsid nohup env SSH3C_PROTO=1 "$BIN" -3 -l "127.0.0.1:$S_P" \
    -c "$WORK/cert.pem" -k "$WORK/key.pem" \
    -K "$WORK/authorized_keys" -P "$WORK/passfile" > "$S_LOG" 2>&1 < /dev/null &
S_PID=$!
SRVPIDS="$SRVPIDS $S_PID"

PORT=""

S_J=0

while [ "$S_J" -lt 50 ]; do

    if grep -q INTEROP-LISTEN "$S_LOG" 2>/dev/null; then
        PORT=$(grep -oE 'port=[0-9]+' "$S_LOG" | head -1 | cut -d= -f2)
        break
    fi

    if ! kill -0 "$S_PID" 2>/dev/null; then
        break
    fi

    sleep 0.1
    S_J=$((S_J + 1))
done

[ -n "$PORT" ] || die "the daemon did not come up: $(tail -3 "$S_LOG")"

printf '127.0.0.1:%s/ssh3-term x509-certificate %s\n' "$PORT" \
    "$(openssl x509 -in "$WORK/cert.pem" -outform DER | base64 -w0)" \
    > "$WORK/.ssh3/known_hosts"

echo "== leg 1: the split CONNECT of alice and the whole CONNECT of bob in its pause"

# client A: the request goes out in two halves, the pause in between
# lets the second client land on the server

HOME="$WORK" S3INTEROP_SPLIT_CONNECT=5000 timeout 30 "$CLI" -3 -C -S exec \
    -K "$WORK/alice.pem" -U alice -a "127.0.0.1:$PORT" -t 20000 \
    > "$WORK/a.out" 2>"$WORK/a.err" &
APID=$!

sleep 0.4

# client B: a whole CONNECT, in the pause of A

HOME="$WORK" timeout 30 "$CLI" -3 -C -S exec -U bob:bobpassword \
    -a "127.0.0.1:$PORT" -t 20000 \
    > "$WORK/b.out" 2>"$WORK/b.err"
BRC=$?

wait $APID
ARC=$?

if [ "$ARC" -eq 0 ]; then
    pass "the split CONNECT of alice was served (rc 0)"
else
    fail "the split CONNECT of alice: rc=$ARC $(tail -1 "$WORK/a.err")"
fi

if [ "$BRC" -eq 0 ]; then
    pass "the concurrent CONNECT of bob was served (rc 0)"
else
    fail "the concurrent CONNECT of bob: rc=$BRC $(tail -1 "$WORK/b.err")"
fi

if grep -q "INTEROP-AUTH-OK user=alice" "$S_LOG"; then
    pass "the server authenticated alice"
else
    fail "no alice in the daemon log: $(grep -c INTEROP-AUTH-OK "$S_LOG") verdicts"
fi

if grep -q "INTEROP-AUTH-OK user=bob" "$S_LOG"; then
    pass "the server authenticated bob"
else
    fail "no bob in the daemon log: $(grep -c INTEROP-AUTH-OK "$S_LOG") verdicts"
fi

if grep -q "INTEROP-H3-REJECT" "$S_LOG"; then
    fail "the daemon refused a request: $(grep -m1 INTEROP-H3-REJECT "$S_LOG")"
else
    pass "the daemon refused nobody"
fi

if [ "$FAILURES" -eq 0 ]; then
    echo "PREAUTH-CONCURRENT-E2E OK"
    exit 0
fi

echo "PREAUTH-CONCURRENT-E2E FAILED ($FAILURES)"
exit 1
