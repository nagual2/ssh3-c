#!/bin/sh
# the 0-RTT negative e2e (RFC 8470, the 425 gate, the P6 debts wave):
#
#   1. one plain s3interop_server -3 started with S3_H3_FORCE_EARLY=1:
#      the synthetic probe makes the RFC 8470 branch fire once (no
#      shipped client sends TLS 0-RTT early data yet — the server
#      never advertises max_early_data, the session resumption is not
#      wired — so the !handshaked gate has no natural trigger; the
#      knob exercises the same verdict the real early-data request
#      takes)
#   2. the first client run (-3 -C) reads INTEROP-H3-STATUS 425 and
#      fails, the server logs INTEROP-H3-REJECT code=425
#   3. the retry (a fresh connection, the probe spent) rides the
#      normal chain: the channel opens, the ping echo returns
#
# usage: early-data-e2e.sh [worktree]
set -u

ROOT=${1:-/mnt/c/Git/project/ssh3-c}
BUILD=$ROOT/build/linux-release
SERVER=$BUILD/s3interop_server
FAILURES=0

die() {
    echo "early-data-e2e: $1" >&2
    exit 1
}

fail() {
    echo "   FAIL: $1"
    FAILURES=$((FAILURES + 1))
}

pass() {
    echo "   PASS: $1"
}

[ -x "$SERVER" ] || die "the server binary is not built ($SERVER)"
[ -x "$BUILD/s3interop_client" ] || die "the C client binary is not built"

W=$(mktemp -d /tmp/early-data-e2e.XXXXXX)
SRV=$W/srv.log

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/key.pem" -out "$W/cert.pem" \
    -days 30 -subj /CN=early-data-e2e 2>/dev/null || die "openssl req failed"

wait_for() {
    i=0
    while [ "$i" -lt "${3:-50}" ]; do
        if grep -q "$2" "$1" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
        i=$((i + 1))
    done

    return 1
}

setsid nohup env S3_H3_FORCE_EARLY=1 "$SERVER" -3 -l 127.0.0.1:0 \
    -c "$W/cert.pem" -k "$W/key.pem" > "$SRV" 2>&1 < /dev/null &

SRVPID=$!

if ! wait_for "$SRV" INTEROP-LISTEN; then
    die "the server did not come up"
fi

PORT=$(grep -oE 'port=[0-9]+' "$SRV" | cut -d= -f2)

echo "== 1: the request in the synthetic early data draws the 425"

timeout 30 "$BUILD/s3interop_client" -3 -C -a "127.0.0.1:$PORT" -t 20000 \
    > "$W/early-cli.log" 2>&1
RC=$?

if [ "$RC" -ne 0 ] && grep -q "INTEROP-H3-STATUS 425" "$W/early-cli.log"; then
    pass "the client read the 425 Too Early"
else
    fail "the early run: rc=$RC $(tail -3 "$W/early-cli.log")"
fi

if grep -q "INTEROP-H3-REJECT code=425" "$SRV"; then
    pass "the server logged the 425 reject"
else
    fail "no INTEROP-H3-REJECT code=425 in the server log"
fi

echo "== 2: the retry after the gate rides the normal chain"

timeout 30 "$BUILD/s3interop_client" -3 -C -a "127.0.0.1:$PORT" -t 20000 \
    > "$W/retry-cli.log" 2>&1
RC=$?

if [ "$RC" -eq 0 ] && grep -q "INTEROP-CHANNEL-OK" "$W/retry-cli.log"; then
    pass "the retry ran the channel phase (the ping echo came back)"
else
    fail "the retry run: rc=$RC $(tail -3 "$W/retry-cli.log")"
fi

kill "$SRVPID" 2>/dev/null
wait "$SRVPID" 2>/dev/null

rm -rf "$W"

if [ "$FAILURES" -gt 0 ]; then
    echo "early-data-e2e: FAILED ($FAILURES)"
    exit 1
fi

echo "early-data-e2e: OK"
