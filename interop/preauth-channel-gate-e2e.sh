#!/bin/sh
# the pre-auth channel gate e2e (the audit fix wave of the 2026-10-22
# review, the critical of the wave):
#
#   the client opens the CONNECT stream but never sends the request,
#   so the conversation never reaches a verdict - then it opens a
#   session channel anyway (S3INTEROP_BAD_CHANNEL=session rides the
#   S3INTEROP_PREAUTH_CHANNEL knob).  with the funnel gate of
#   s3_srv_h3_channel_confirm the probe dies without the 91
#   (BAD-CHANNEL-VERDICT confirmed=0) and the daemon logs the funnel
#   refusal; without the gate the channel confirmed and the session
#   was served pre-auth (the exec spawned with the daemon identity)
#
# the verdict: PREAUTH-CHANNEL-GATE-E2E OK / FAILED
#
# usage: interop/preauth-channel-gate-e2e.sh   (WSL, unprivileged)
# requires: the C runners (cmake --build build/linux-release)
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD=${BUILD:-$ROOT/build/linux-release}
BIN=${SSH3C_SERVER_BIN:-$BUILD/ssh3-server}
CLI=${SSH3C_CLIENT_BIN:-$BUILD/s3interop_client}

die() {
    echo "preauth-channel-gate-e2e: $1" >&2
    exit 1
}

FAILURES=0

pass() {
    echo "   PASS: $1"
}

fail() {
    echo "   FAIL: $1"
    FAILURES=$((FAILURES + 1))
}

[ -x "$BIN" ] || die "the daemon is not built: $BIN"
[ -x "$CLI" ] || die "the interop client is not built: $CLI"

WORK=$(mktemp -d /tmp/s3gate.XXXXXX)
SRVPID=""

cleanup() {
    if [ -n "$SRVPID" ]; then
        kill -TERM "$SRVPID" >/dev/null 2>&1
    fi
    rm -rf "$WORK"
}

trap cleanup EXIT INT TERM

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/key.pem" -out "$WORK/cert.pem" \
    -days 2 -subj /CN=preauth-channel-gate-e2e 2>/dev/null || die "openssl req failed"

S_LOG="$WORK/srv.log"

setsid nohup env SSH3C_PROTO=1 "$BIN" -3 -l "127.0.0.1:0" \
    -c "$WORK/cert.pem" -k "$WORK/key.pem" --password-system off > "$S_LOG" 2>&1 < /dev/null &
SRVPID=$!

i=0
while [ "$i" -lt 50 ]; do
    grep -q INTEROP-LISTEN "$S_LOG" 2>/dev/null && break
    sleep 0.1
    i=$((i + 1))
done

grep -q INTEROP-LISTEN "$S_LOG" || die "the daemon did not start: $(tail -3 "$S_LOG")"
PORT=$(grep -oE 'port=[0-9]+' "$S_LOG" | tail -1 | cut -d= -f2)

echo "== the session channel probe into the never-authenticated conversation"

S3INTEROP_PREAUTH_CHANNEL=1 S3INTEROP_BAD_CHANNEL=session timeout 30 "$CLI" -3 -C \
    -a "127.0.0.1:$PORT" -t 8000 > "$WORK/cli.log" 2>&1

if grep -q "BAD-CHANNEL-VERDICT mode=session confirmed=0 OK" "$WORK/cli.log"; then
    pass "the probe died without the 91 (confirmed=0)"
else
    fail "want BAD-CHANNEL-VERDICT confirmed=0, got $(tail -1 "$WORK/cli.log")"
fi

if grep -q "the channel wants an authenticated conversation" "$S_LOG"; then
    pass "the daemon logged the funnel refusal"
else
    fail "no funnel refusal in the daemon log"
fi

if grep -q "INTEROP-CHANNEL-ACCEPT" "$S_LOG"; then
    fail "a channel was served pre-auth: $(grep -m1 INTEROP-CHANNEL-ACCEPT "$S_LOG")"
else
    pass "no channel reached the acceptance"
fi

if grep -q "INTEROP-AUTH-OK" "$S_LOG"; then
    fail "a verdict answered without a request"
else
    pass "no verdict ran"
fi

if [ "$FAILURES" -eq 0 ]; then
    echo "PREAUTH-CHANNEL-GATE-E2E OK"
    exit 0
fi

echo "PREAUTH-CHANNEL-GATE-E2E FAILED ($FAILURES)"
exit 1
