#!/bin/sh
# the security pass-3 e2e (the P3 wave over the Go pass-3 audit,
# docs/SECURITY_AUDIT_PASS3_2026-10-09.md):
#
#   1. the channel-type allow-list (P3-03): the client opening an
#      unknown channel-type string is refused without the 91
#      confirmation (CHROLE-UNKNOWN-DENIED on the server, the client
#      sees the teardown); the pass-2 table refused the two
#      forwarded-* names only, every other string fell through to
#      the acceptance
#   2. the sanity leg: the ordinary session channel is still
#      accepted and served (the allow-list must not overblock)
#
# the verdicts: the BAD-CHANNEL-VERDICT and INTEROP-* markers of the
# runners, the PASS3-E2E OK / FAILED summary
#
# usage: interop/security-pass3-e2e.sh   (WSL, unprivileged)
# requires: the C runners (cmake --build build/linux-release)
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD=${BUILD:-$ROOT/build/linux-release}
BIN=${SSH3C_SERVER_BIN:-$BUILD/ssh3-server}

die() {
    echo "pass3-e2e: $1" >&2
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
[ -x "$BUILD/s3interop_client" ] || die "s3interop_client is not built ($BUILD/s3interop_client)"

WORK=$(mktemp -d /tmp/pass3-e2e.XXXXXX)
SRVPID=""
SRVLOG=""

cleanup() {
    if [ -n "$SRVPID" ]; then
        kill -TERM "$SRVPID" >/dev/null 2>&1
    fi
    rm -rf "$WORK"
}

trap cleanup EXIT INT TERM

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/key.pem" -out "$WORK/cert.pem" \
    -days 30 -subj /CN=pass3-e2e 2>/dev/null || die "openssl req failed"

start_server() {
    # $1 the log file, the rest the daemon argv; SSH3C_PROTO=1 rides
    # the env for the markers

    SRVLOG=$1
    shift

    setsid nohup env SSH3C_PROTO=1 "$@" > "$SRVLOG" 2>&1 < /dev/null &
    SRVPID=$!

    i=0
    while [ "$i" -lt 50 ]; do
        grep -q INTEROP-LISTEN "$SRVLOG" 2>/dev/null && break
        sleep 0.1
        i=$((i + 1))
    done

    grep -q INTEROP-LISTEN "$SRVLOG" || die "the daemon did not start: $(tail -3 "$SRVLOG")"
    PORT=$(grep -oE 'port=[0-9]+' "$SRVLOG" | tail -1 | cut -d= -f2)
}

stop_server() {
    kill -TERM "$SRVPID" >/dev/null 2>&1
    SRVPID=""
    sleep 0.3
}

echo "== 1: the allow-list refuses the unknown channel type"

start_server "$WORK/srv1.log" "$BIN" -3 -l 127.0.0.1:0 -c "$WORK/cert.pem" -k "$WORK/key.pem" \
    --password-system off

S3INTEROP_BAD_CHANNEL=raw:evil-type timeout 30 "$BUILD/s3interop_client" -3 -C \
    -a "127.0.0.1:$PORT" -t 20000 > "$WORK/cli-raw.log" 2>&1

if grep -q "BAD-CHANNEL-VERDICT mode=raw:evil-type confirmed=0 OK" "$WORK/cli-raw.log"; then
    pass "the unknown type died without the 91"
else
    fail "raw: want BAD-CHANNEL-VERDICT confirmed=0, got $(tail -1 "$WORK/cli-raw.log")"
fi

if grep -q "CHROLE-UNKNOWN-DENIED id=[0-9]* type=evil-type" "$WORK/srv1.log"; then
    pass "the server denied the unknown type"
else
    fail "the server log has no CHROLE-UNKNOWN-DENIED"
fi

if grep -q "INTEROP-CHANNEL-ACCEPT type=evil-type" "$WORK/srv1.log"; then
    fail "the unknown type reached the acceptance"
fi

stop_server

echo "== 2: the sanity leg (the session channel is still served)"

start_server "$WORK/srv2.log" "$BIN" -3 -l 127.0.0.1:0 -c "$WORK/cert.pem" -k "$WORK/key.pem" \
    --password-system off

timeout 30 "$BUILD/s3interop_client" -3 -C \
    -a "127.0.0.1:$PORT" -t 20000 > "$WORK/cli-ok.log" 2>&1
RC=$?

if [ "$RC" -eq 0 ] && grep -q "INTEROP-CHANNEL-OK" "$WORK/cli-ok.log"; then
    pass "the session channel passed"
else
    fail "the session channel: rc=$RC $(tail -1 "$WORK/cli-ok.log")"
fi

if grep -q "INTEROP-CHANNEL-ACCEPT id=[0-9]* type=session" "$WORK/srv2.log"; then
    pass "the server accepted the session type"
else
    fail "the server log has no INTEROP-CHANNEL-ACCEPT type=session"
fi

stop_server

if [ "$FAILURES" -eq 0 ]; then
    echo "PASS3-E2E OK"
    exit 0
fi

echo "PASS3-E2E FAILED: $FAILURES check(s)"
exit 1
