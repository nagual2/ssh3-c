#!/bin/sh
# the connection close e2e (the zombie fix): the client teardown must
# send the QUIC CONNECTION_CLOSE, the daemon tears the connection down
# at once instead of riding the idle timeout; the dead client (killed
# -9, no CC ever) rides the PTO dead-path guard
#
#   1. seven finished sessions (a put, two execs, two plain gets, two
#      -C gets): the daemon reports INTEROP-CONN-CLOSE for each - the
#      close of the old code never came (the silent S3_ABORT teardown)
#   2. a killed -9 session: the guard closes the orphan within the
#      backoff window (~3 min), the marker rides the same line
#
# the verdicts: CONN-CLOSE-E2E OK / FAILED
#
# usage: interop/conn-close-e2e.sh   (WSL)
# requires: the daemon and the client built (build/linux-release)
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD=${BUILD:-$ROOT/build/linux-release}
BIN=${SSH3C_SERVER_BIN:-$BUILD/ssh3-server}

die() {
    echo "conn-close-e2e: $1" >&2
    exit 1
}

[ -x "$BIN" ] || die "the daemon is not built: $BIN"
[ -x "$BUILD/ssh3" ] || die "the product client is not built: $BUILD/ssh3"

FAILURES=0

pass() {
    echo "   PASS: $1"
}

fail() {
    echo "   FAIL: $1"
    FAILURES=$((FAILURES + 1))
}

SRVPIDS=

cleanup() {

    for p in $SRVPIDS; do
        kill "$p" 2>/dev/null
        wait "$p" 2>/dev/null
    done

    rm -rf "$WORK"
}

trap cleanup EXIT INT TERM

WORK=$(mktemp -d /tmp/s3cnc.XXXXXX)

# the log path rides the global scope: the $(start_srv) substitution
# below runs the function in a subshell, its locals die with it
S_LOG="$WORK/srv.log"

openssl genpkey -algorithm ed25519 -out "$WORK/priv.pem" 2>/dev/null || die "openssl genpkey failed"

{
    printf '\000\000\000\013ssh-ed25519\000\000\000\040'
    openssl pkey -in "$WORK/priv.pem" -pubout -outform DER 2>/dev/null | tail -c 32
} | base64 | tr -d '\n' > "$WORK/blob.pub"

printf 'ssh-ed25519 %s conn-close-e2e\n' "$(cat "$WORK/blob.pub")" > "$WORK/authorized_keys"

mkcert() {
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/key-$1.pem" \
        -out "$WORK/cert-$1.pem" -days 2 -subj /CN=conn-close-$1 2>/dev/null \
        || die "openssl req failed for $1"
}

mkcert 1

S_PID=

start_srv() {
    S_P=$((49500 + ($$ % 500)))

    setsid nohup env SSH3C_PROTO=1 "$BIN" -3 -l "127.0.0.1:$S_P" \
        -c "$WORK/cert-1.pem" -k "$WORK/key-1.pem" \
        -K "$WORK/authorized_keys" > "$S_LOG" 2>&1 < /dev/null &
    S_PID=$!
    SRVPIDS="$SRVPIDS $S_PID"

    S_J=0

    while [ "$S_J" -lt 50 ]; do

        if grep -q INTEROP-LISTEN "$S_LOG" 2>/dev/null; then
            grep -oE 'port=[0-9]+' "$S_LOG" | head -1 | cut -d= -f2
            return 0
        fi

        sleep 0.1
        S_J=$((S_J + 1))
    done

    return 1
}

PORT=$(start_srv) || die "the daemon did not start"

mkdir -p "$WORK/home/.ssh3"

printf '%s x509-certificate %s\n' "127.0.0.1:$PORT/ssh3-term" \
    "$(openssl x509 -in "$WORK/cert-1.pem" -outform DER | base64 -w0)" \
    > "$WORK/home/.ssh3/known_hosts"

# the close counter of the daemon log
closes() {
    grep -c "INTEROP-CONN-CLOSE" "$S_LOG" 2>/dev/null
}

wait_closes() { # $1 = the expected count, $2 = the seconds budget
    i=0

    while [ "$i" -lt "$(( $2 * 10 ))" ]; do

        if [ "$(closes)" -ge "$1" ]; then
            return 0
        fi

        sleep 0.1
        i=$((i + 1))
    done

    return 1
}

printf 'the close marker line: %d sessions ride the daemon\n' 7

echo "== leg 1: the finished sessions close on the daemon"

# the payload for the get legs (the put is a session of its own)
yes "S3-CONN-CLOSE-BODY" | head -n 2000 > "$WORK/body.txt"

HOME="$WORK/home" timeout -k 5 30 "$BUILD/ssh3" -i "$WORK/priv.pem" \
    --sftp "put:$WORK/body.txt:/cnc-body.txt" "client@127.0.0.1:$PORT/ssh3-term" \
    > /dev/null 2>"$WORK/put.err" || fail "the setup put failed: $(tail -1 "$WORK/put.err")"

HOME="$WORK/home" timeout -k 5 30 "$BUILD/ssh3" -T -i "$WORK/priv.pem" \
    "client@127.0.0.1:$PORT/ssh3-term" "printf S3-EXEC-1" > /dev/null 2>&1
HOME="$WORK/home" timeout -k 5 30 "$BUILD/ssh3" -T -i "$WORK/priv.pem" \
    "client@127.0.0.1:$PORT/ssh3-term" "printf S3-EXEC-2" > /dev/null 2>&1

HOME="$WORK/home" timeout -k 5 30 "$BUILD/ssh3" -i "$WORK/priv.pem" \
    --sftp "get:$WORK/g1:/cnc-body.txt" "client@127.0.0.1:$PORT/ssh3-term" \
    > /dev/null 2>&1
HOME="$WORK/home" timeout -k 5 30 "$BUILD/ssh3" -i "$WORK/priv.pem" \
    --sftp "get:$WORK/g2:/cnc-body.txt" "client@127.0.0.1:$PORT/ssh3-term" \
    > /dev/null 2>&1
HOME="$WORK/home" timeout -k 5 30 "$BUILD/ssh3" -C -i "$WORK/priv.pem" \
    --sftp "get:$WORK/g3:/cnc-body.txt" "client@127.0.0.1:$PORT/ssh3-term" \
    > /dev/null 2>&1
HOME="$WORK/home" timeout -k 5 30 "$BUILD/ssh3" -C -i "$WORK/priv.pem" \
    --sftp "get:$WORK/g4:/cnc-body.txt" "client@127.0.0.1:$PORT/ssh3-term" \
    > /dev/null 2>&1

if wait_closes 7 10; then
    pass "the daemon closed all the seven finished sessions (closes=$(closes))"
else
    fail "the daemon holds finished sessions (closes=$(closes) of 7 after 10s)"
fi

echo "== leg 2: the killed client leaves no orphan"

# a long session killed -9: on the loopback stand the kernel close of
# the client socket feeds the daemon at once (the ICMP unreachable of
# the next packet), so the orphan count must climb within seconds;
# the PTO dead-path guard of the ack layer covers the paths without
# the icmp feedback - its trigger is not reachable on the loopback,
# it rides the code review and the bench stands instead
BEFORE=$(closes)

HOME="$WORK/home" timeout -k 5 400 "$BUILD/ssh3" -T -i "$WORK/priv.pem" \
    "client@127.0.0.1:$PORT/ssh3-term" "sleep 300" > /dev/null 2>&1 &
KPID=$!

sleep 2
kill -9 "$KPID" 2>/dev/null
wait "$KPID" 2>/dev/null

if wait_closes $((BEFORE + 1)) 15; then
    pass "the orphan connection closed at once (closes=$(closes))"
else
    cp "$S_LOG" /tmp/conn-close-fail.log 2>/dev/null
    fail "the orphan still rides the daemon (closes=$(closes) of $((BEFORE + 1)) after 15s, the log saved to /tmp/conn-close-fail.log)"
fi

if [ "$FAILURES" -eq 0 ]; then
    echo "CONN-CLOSE-E2E OK"
    exit 0
fi

echo "CONN-CLOSE-E2E FAILED: $FAILURES check(s)"
exit 1
