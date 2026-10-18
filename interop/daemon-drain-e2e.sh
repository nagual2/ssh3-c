#!/bin/sh
# the SIGTERM drain e2e of the ssh3-server daemon (P6.5)
#
#   case 1 (graceful): an exec session is live when SIGTERM lands;
#     the drain lets it finish - the command output and the 98
#     exit-status reach the client INSIDE the drain window, the
#     daemon exits 0 right after the conversation ends (the C
#     clients leave the quic connection to the idle timeout, the
#     drain counts the unfinished channels)
#   case 2 (timeout): a wedged exec holds the conversation, the
#     SSH3_SHUTDOWN_DRAIN window expires, the daemon force-closes
#     the connection, kills the session child and exits 0
#
# the verdicts: INTEROP-EXEC-OK / INTEROP-EXEC-FAIL on the client
# side, the shutdown one-liners of the daemon log, the exit codes
#
# usage: interop/daemon-drain-e2e.sh
# requires: the C runners (cmake --build build/linux-release), openssl
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD=${BUILD:-$ROOT/build/linux-release}
BIN=${SSH3C_SERVER_BIN:-$BUILD/ssh3-server}

die() {
    echo "daemon-drain-e2e: $1" >&2
    exit 1
}

[ -x "$BIN" ] || die "the daemon is not built: $BIN"
[ -x "$BUILD/s3interop_client" ] || die "s3interop_client is not built"

CERT=$BUILD/interop/cert.pem
KEY=$BUILD/interop/key.pem

mkdir -p "$BUILD/interop"

if [ ! -f "$CERT" ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$KEY" -out "$CERT" -days 30 \
        -subj "/CN=s3drain" 2>/dev/null || die "openssl req failed"
fi

WORK=$(mktemp -d /tmp/s3drain.XXXXXX)
FAILURES=0

wait_listen() {
    i=0
    while [ "$i" -lt 50 ]; do
        if grep -q INTEROP-LISTEN "$1" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
        i=$((i + 1))
    done

    return 1
}

port_of() {
    grep -oE 'port=[0-9]+' "$1" | cut -d= -f2
}

echo "== case 1: the exec session finishes inside the drain (8s window)"

SSH3C_PROTO=1 SSH3_SHUTDOWN_DRAIN=8 "$BIN" -3 -l 127.0.0.1:0 -c "$CERT" -k "$KEY" \
    --password-system off \
    > "$WORK/g-srv.log" 2>&1 < /dev/null &
SRV=$!

if wait_listen "$WORK/g-srv.log"; then
    PORT=$(port_of "$WORK/g-srv.log")

    # the session runs 2s, the SIGTERM lands at 1s - the drain holds
    # the conversation until the verdict is out

    "$BUILD/s3interop_client" -3 -C -S exec -e "sleep 2 && printf SSH3_AGENT_PROBE_OK" \
        -a "127.0.0.1:$PORT" -t 30000 > "$WORK/g-cli.log" 2>&1 < /dev/null &
    CLI=$!

    sleep 1

    T0=$(date +%s%N)

    kill -TERM "$SRV"

    wait "$CLI"
    CLI_RC=$?

    wait "$SRV"
    SRV_RC=$?

    T1=$(date +%s%N)
    DRAINED_MS=$(((T1 - T0) / 1000000))

    if [ "$CLI_RC" -eq 0 ] && grep -q "INTEROP-EXEC-OK exit=0" "$WORK/g-cli.log"; then
        echo "   PASS (the session verdict reached the client during the drain)"
    else
        echo "   FAIL (the client lost the session: rc=$CLI_RC)"
        tail -5 "$WORK/g-cli.log" | sed 's/^/   /'
        FAILURES=$((FAILURES + 1))
    fi

    if [ "$SRV_RC" -eq 0 ]; then
        echo "   PASS (the daemon exited 0)"
    else
        echo "   FAIL (the daemon exit code $SRV_RC)"
        FAILURES=$((FAILURES + 1))
    fi

    if [ "$DRAINED_MS" -lt 8000 ]; then
        echo "   PASS (the daemon exited after the session, ${DRAINED_MS}ms < the 8000ms window)"
    else
        echo "   FAIL (the daemon held the full drain: ${DRAINED_MS}ms)"
        FAILURES=$((FAILURES + 1))
    fi

    if grep -q "shutdown: the active channels finished" "$WORK/g-srv.log" &&
        grep -q "shutdown complete" "$WORK/g-srv.log"; then
        echo "   PASS (the shutdown one-liners: drain, channels finished, complete)"
    else
        echo "   FAIL (the shutdown log sequence is incomplete)"
        tail -8 "$WORK/g-srv.log" | sed 's/^/   /'
        FAILURES=$((FAILURES + 1))
    fi

else
    echo "   FAIL: the daemon did not start"
    FAILURES=$((FAILURES + 1))
fi

echo "== case 2: the drain timeout force-closes the wedged session (2s window)"

SSH3C_PROTO=1 SSH3_SHUTDOWN_DRAIN=2 "$BIN" -3 -l 127.0.0.1:0 -c "$CERT" -k "$KEY" \
    --password-system off \
    > "$WORK/t-srv.log" 2>&1 < /dev/null &
SRV=$!

if wait_listen "$WORK/t-srv.log"; then
    PORT=$(port_of "$WORK/t-srv.log")

    # the wedged session: exec sleep replaces the shell, the pid the
    # teardown kills IS the sleeper - no orphans after the force close

    "$BUILD/s3interop_client" -3 -C -S exec -e "exec sleep 60" \
        -a "127.0.0.1:$PORT" -t 30000 > "$WORK/t-cli.log" 2>&1 < /dev/null &
    CLI=$!

    sleep 1

    T0=$(date +%s%N)

    kill -TERM "$SRV"

    wait "$CLI"
    CLI_RC=$?

    wait "$SRV"
    SRV_RC=$?

    T1=$(date +%s%N)
    DRAINED_MS=$(((T1 - T0) / 1000000))

    if [ "$CLI_RC" -ne 0 ] && ! grep -q "INTEROP-EXEC-OK" "$WORK/t-cli.log"; then
        echo "   PASS (the wedged session did not finish: the client rc=$CLI_RC)"
    else
        echo "   FAIL (the wedged session finished: rc=$CLI_RC)"
        FAILURES=$((FAILURES + 1))
    fi

    if [ "$SRV_RC" -eq 0 ]; then
        echo "   PASS (the daemon exited 0)"
    else
        echo "   FAIL (the daemon exit code $SRV_RC)"
        FAILURES=$((FAILURES + 1))
    fi

    if [ "$DRAINED_MS" -ge 1800 ] && [ "$DRAINED_MS" -lt 5000 ]; then
        echo "   PASS (the daemon held the 2s window: ${DRAINED_MS}ms)"
    else
        echo "   FAIL (the drain window was not honored: ${DRAINED_MS}ms)"
        FAILURES=$((FAILURES + 1))
    fi

    if grep -q "shutdown: drain timeout" "$WORK/t-srv.log" &&
        grep -q "shutdown complete" "$WORK/t-srv.log"; then
        echo "   PASS (the shutdown one-liners: drain timeout, complete)"
    else
        echo "   FAIL (the timeout log sequence is incomplete)"
        tail -8 "$WORK/t-srv.log" | sed 's/^/   /'
        FAILURES=$((FAILURES + 1))
    fi

    sleep 0.3

    if pgrep -f "sleep 60" > /dev/null 2>&1; then
        echo "   FAIL (the session child survived the force close)"
        pkill -f "sleep 60" 2>/dev/null
        FAILURES=$((FAILURES + 1))
    else
        echo "   PASS (no session child left behind)"
    fi

else
    echo "   FAIL: the daemon did not start"
    FAILURES=$((FAILURES + 1))
fi

rm -rf "$WORK"

if [ "$FAILURES" -eq 0 ]; then
    echo "DAEMON-DRAIN-E2E OK"
    exit 0
fi

echo "DAEMON-DRAIN-E2E FAILED: $FAILURES check(s)"
exit 1
