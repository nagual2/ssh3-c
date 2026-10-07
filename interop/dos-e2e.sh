#!/bin/sh
# the DoS guard e2e (the auth-phase hardening, the port of the
# reference server_auth/dos_guard.go, CTO_TASK 4.1):
#
#   1. the cap wiring: the daemon with --max-unauth-conversations 0
#      refuses every CONNECT with 503 - including the one with the
#      valid password - which pins the acquire point before any auth
#      work (the reference F-06; the count mechanics live in the
#      unit test, the sequential traffic of this harness cannot
#      cross a live cap: the slot frees with every verdict inside
#      one event pass)
#   2. the default cap: the sequential CONNECTs pass with the
#      defaults, the guard adds nothing to the legitimate traffic
#   3. the lockout through the env knobs: three wrong passwords lock
#      the account (the correct password draws 429 next), the window
#      expires back to 200, the success clears the bookkeeping, and
#      the unknown user never books (the anti user-enumeration rule:
#      the correct password of the ghost keeps drawing 401, not 429)
#
# the verdicts: the INTEROP-H3-STATUS of the C client runs, the
# DOS-E2E OK / FAILED summary
#
# usage: interop/dos-e2e.sh   (WSL, unprivileged)
# requires: the C runners (cmake --build build/linux-release)
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD=${BUILD:-$ROOT/build/linux-release}
BIN=${SSH3C_SERVER_BIN:-$BUILD/ssh3-server}

die() {
    echo "dos-e2e: $1" >&2
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

WORK=$(mktemp -d /tmp/dos-e2e.XXXXXX)
SRVLOG=$WORK/srv.log
SRVPID=""

cleanup() {
    if [ -n "$SRVPID" ]; then
        kill -TERM "$SRVPID" >/dev/null 2>&1
    fi
    rm -rf "$WORK"
}

trap cleanup EXIT INT TERM

printf 'tester:secret\n' > "$WORK/passfile"

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/key.pem" -out "$WORK/cert.pem" \
    -days 30 -subj /CN=dos-e2e 2>/dev/null || die "openssl req failed"

start_server() {
    # the caller carries the knob env; the daemon markers ride stdout

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

# the CONNECT run of one identity: $1 the user:pass, $2 the expected
# :status, $3 the leg label (the exec body stays unreached on every
# refusal, the stream dies at the CONNECT verdict)

connect_expect() {
    timeout 30 "$BUILD/s3interop_client" -3 -C -S exec -e 'true' \
        -U "$1" -a "127.0.0.1:$PORT" -t 20000 > "$WORK/cli.log" 2>&1

    if grep -q "INTEROP-H3-STATUS $2" "$WORK/cli.log"; then
        pass "$3"
    else
        fail "$3: want status $2, got $(grep INTEROP-H3-STATUS "$WORK/cli.log" | tail -1)"
    fi
}

echo "== 1: the cap kill-switch refuses before the auth work"

start_server "$BIN" -3 -l 127.0.0.1:0 -c "$WORK/cert.pem" -k "$WORK/key.pem" \
    -P "$WORK/passfile" --enable-password-login --max-unauth-conversations 0

connect_expect "tester:secret" 503 "the valid password draws 503 under the zero cap"
connect_expect "tester:wrongpass" 503 "the wrong password draws the same 503"

stop_server

echo "== 2: the defaults serve the legitimate traffic"

start_server "$BIN" -3 -l 127.0.0.1:0 -c "$WORK/cert.pem" -k "$WORK/key.pem" \
    -P "$WORK/passfile" --enable-password-login

connect_expect "tester:secret" 200 "the first CONNECT passes"
connect_expect "tester:secret" 200 "the second CONNECT passes (the slot freed)"
connect_expect "tester:secret" 200 "the third CONNECT passes"

stop_server

echo "== 3: the password lockout (the env knobs, the window, the clear)"

# the knobs ride the env this time (the flags rode the cap above):
# three failures lock, two seconds of window keep the leg fast

start_server env SSH3_MAX_PASSWORD_FAILURES=3 SSH3_PASSWORD_LOCKOUT_SECONDS=2 \
    "$BIN" -3 -l 127.0.0.1:0 -c "$WORK/cert.pem" -k "$WORK/key.pem" \
    -P "$WORK/passfile" --enable-password-login

i=1
while [ "$i" -le 3 ]; do
    connect_expect "tester:wrongpass" 401 "wrong password $i draws 401"
    i=$((i + 1))
done

connect_expect "tester:secret" 429 "the correct password draws 429 under the lockout"

sleep 3

connect_expect "tester:secret" 200 "the lockout expired, the correct password passes"

connect_expect "tester:wrongpass" 401 "one wrong password after the success"
connect_expect "tester:secret" 200 "the success cleared the record, one failure locks nothing"

i=1
while [ "$i" -le 3 ]; do
    connect_expect "tester:wrongpass" 401 "wrong password again $i draws 401"
    i=$((i + 1))
done

connect_expect "tester:secret" 429 "the third failure of the fresh record locks again"

# the anti user-enumeration rule: the ghost has no line in the
# passfile, its failures book nothing, the correct password keeps
# drawing the plain 401 of the unknown user

i=1
while [ "$i" -le 3 ]; do
    connect_expect "ghost:wrongpass" 401 "ghost wrong password $i draws 401"
    i=$((i + 1))
done

connect_expect "ghost:secret" 401 "the ghost never books: 401, not 429"

stop_server

if [ "$FAILURES" -eq 0 ]; then
    echo "DOS-E2E OK"
    exit 0
fi

echo "DOS-E2E FAILED: $FAILURES leg(s)"
exit 1
