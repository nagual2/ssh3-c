#!/bin/sh
# the security pass-2 e2e (the S2 waves over the Go pass-2 audit,
# docs/SECURITY_AUDIT_SERVER_PASS2_2026-10-07.md):
#
#   1. the channel role table (S2-03): the client opening the
#      server-to-client forwarded-tcp/forwarded-udp is refused
#      without the 91 confirmation (CHROLE-FORWARDED-DENIED on the
#      server, the client sees the teardown)
#   2. the receive bound (S2-01): a valid session channel followed
#      by a 94 data frame claiming a 4 GiB payload dies at the
#      buffer bound ("channel buffer overgrown"), the 91 was out
#   3. the connection cap (S2-06, --max-connections 1): the second
#      overlapping connection is closed at once (CONN-CAP-DENIED)
#   4. the sftp budget (S2-02, --max-sftp-sessions-per-user 1): two
#      concurrent puts of one user, one channel is refused
#      (SFTP-SRV-CAP-DENIED)
#
# the verdicts: the BAD-CHANNEL-VERDICT and INTEROP-* markers of the
# runners, the PASS2-E2E OK / FAILED summary
#
# usage: interop/security-pass2-e2e.sh   (WSL, unprivileged)
# requires: the C runners (cmake --build build/linux-release)
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD=${BUILD:-$ROOT/build/linux-release}
BIN=${SSH3C_SERVER_BIN:-$BUILD/ssh3-server}

die() {
    echo "pass2-e2e: $1" >&2
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

WORK=$(mktemp -d /tmp/pass2-e2e.XXXXXX)
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
    -days 30 -subj /CN=pass2-e2e 2>/dev/null || die "openssl req failed"

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

echo "== 1: the role table refuses the server-to-client channel types"

start_server "$WORK/srv1.log" "$BIN" -3 -l 127.0.0.1:0 -c "$WORK/cert.pem" -k "$WORK/key.pem" \
    --password-system off

for t in forwarded-tcp forwarded-udp; do

    S3INTEROP_BAD_CHANNEL=$t timeout 30 "$BUILD/s3interop_client" -3 -C \
        -a "127.0.0.1:$PORT" -t 20000 > "$WORK/cli-$t.log" 2>&1

    if grep -q "BAD-CHANNEL-VERDICT mode=$t confirmed=0 OK" "$WORK/cli-$t.log"; then
        pass "$t: the channel died without the 91"
    else
        fail "$t: want BAD-CHANNEL-VERDICT confirmed=0, got $(tail -1 "$WORK/cli-$t.log")"
    fi
done

if grep -q "CHROLE-FORWARDED-DENIED" "$WORK/srv1.log"; then
    pass "the server denied the role twice"
else
    fail "the server log has no CHROLE-FORWARDED-DENIED"
fi

stop_server

echo "== 2: the receive bound kills the endless frame"

start_server "$WORK/srv2.log" "$BIN" -3 -l 127.0.0.1:0 -c "$WORK/cert.pem" -k "$WORK/key.pem" \
    --password-system off

S3INTEROP_BAD_CHANNEL=overgrow timeout 30 "$BUILD/s3interop_client" -3 -C \
    -a "127.0.0.1:$PORT" -t 20000 > "$WORK/cli-og.log" 2>&1

if grep -q "BAD-CHANNEL-VERDICT mode=overgrow confirmed=1 OK" "$WORK/cli-og.log"; then
    pass "the overgrown channel died after the 91"
else
    fail "overgrow: want BAD-CHANNEL-VERDICT confirmed=1, got $(tail -1 "$WORK/cli-og.log")"
fi

if grep -q "channel buffer overgrown" "$WORK/srv2.log"; then
    pass "the server receive bound fired"
else
    fail "the server log has no channel buffer overgrown"
fi

stop_server

echo "== 3: the connection cap (--max-connections 1)"

start_server "$WORK/srv3.log" "$BIN" -3 -l 127.0.0.1:0 -c "$WORK/cert.pem" -k "$WORK/key.pem" \
    --password-system off --max-connections 1

# the first connection holds the only slot with the sleeping exec

timeout 30 "$BUILD/s3interop_client" -3 -C -S exec -e 'sleep 4' \
    -a "127.0.0.1:$PORT" -t 20000 > "$WORK/cli-hold.log" 2>&1 &
HOLD=$!
sleep 1

timeout 30 "$BUILD/s3interop_client" -3 -C -S exec -e 'true' \
    -a "127.0.0.1:$PORT" -t 20000 > "$WORK/cli-second.log" 2>&1
RC=$?

if grep -q "CONN-CAP-DENIED" "$WORK/srv3.log"; then
    pass "the server denied the second connection"
else
    fail "the server log has no CONN-CAP-DENIED"
fi

if [ "$RC" -ne 0 ] || ! grep -q "INTEROP-H3-STATUS 200" "$WORK/cli-second.log"; then
    pass "the second client got no conversation"
else
    fail "the second client passed under the cap"
fi

wait "$HOLD" 2>/dev/null

stop_server

echo "== 4: the sftp budget (--max-sftp-sessions-per-user 1)"

# the 128 MiB uploads overlap long enough for both channels to ask
# for the budget; the cap of one refuses the second (the window
# rides the transfer seconds, the LAN stands run it tight)

dd if=/dev/zero of="$WORK/sftp-big.bin" bs=1048576 count=128 2>/dev/null
mkdir -p "$WORK/jail"

start_server "$WORK/srv4.log" "$BIN" -3 -l 127.0.0.1:0 -c "$WORK/cert.pem" -k "$WORK/key.pem" \
    --password-system off -H "$WORK/jail" --max-sftp-sessions-per-user 1

timeout 60 "$BUILD/s3interop_client" -3 -J "put:$WORK/sftp-big.bin:p1.bin" \
    -a "127.0.0.1:$PORT" -t 55000 > "$WORK/put1.log" 2>&1 &
P1=$!

timeout 60 "$BUILD/s3interop_client" -3 -J "put:$WORK/sftp-big.bin:p2.bin" \
    -a "127.0.0.1:$PORT" -t 55000 > "$WORK/put2.log" 2>&1 &
P2=$!

wait "$P1"
RC1=$?
wait "$P2"
RC2=$?

if grep -q "SFTP-SRV-CAP-DENIED" "$WORK/srv4.log"; then
    pass "the budget refused the second sftp channel"
else
    fail "the server log has no SFTP-SRV-CAP-DENIED"
fi

OK1=$(grep -c "INTEROP-SFTP-OK mode=put" "$WORK/put1.log" || true)
OK2=$(grep -c "INTEROP-SFTP-OK mode=put" "$WORK/put2.log" || true)

if [ "$((OK1 + OK2))" -eq 1 ] && { [ "$RC1" -eq 0 ] || [ "$RC2" -eq 0 ]; }; then
    pass "exactly one put served"
else
    fail "the puts: served=$((OK1 + OK2)) rc=$RC1/$RC2"
fi

stop_server

if [ "$FAILURES" -eq 0 ]; then
    echo "PASS2-E2E OK"
    exit 0
fi

echo "PASS2-E2E FAILED: $FAILURES check(s)"
exit 1
