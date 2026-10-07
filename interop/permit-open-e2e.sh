#!/bin/sh
# the permit-open e2e (F-05): --permit-open bounds the direct-tcp and
# direct-udp dials the daemon performs on behalf of an authenticated
# client (the sshd_config PermitOpen semantics, the reference
# -permit-open)
#
#   1. the bad spec stops the daemon before the sockets open
#   2. the allow-list daemon (127.0.0.1:19999,127.0.0.1:19998):
#      the listed tcp target relays, the unlisted one is denied
#      before any socket (the INTEROP-FWD-TCP-DENIED marker), the
#      same pair on the udp side
#   3. the negation daemon (!127.0.0.1:19999,127.0.0.1:*): the
#      negated entry wins over the later wildcard, the other port
#      rides the wildcard
#   4. the default daemon (no flag): the dial behaves as before, no
#      denied markers anywhere
#
# the verdicts: PERMIT-OPEN-E2E OK / FAILED, the INTEROP-* markers of
# the C runners on the way
#
# usage: interop/permit-open-e2e.sh   (WSL)
# requires: the C runners (cmake --build build/linux-release), python3
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD=${BUILD:-$ROOT/build/linux-release}
BIN=${SSH3C_SERVER_BIN:-$BUILD/ssh3-server}

die() {
    echo "permit-open-e2e: $1" >&2
    exit 1
}

[ -x "$BIN" ] || die "the daemon is not built: $BIN"
[ -x "$BUILD/s3interop_client" ] || die "s3interop_client is not built"

FAILURES=0

pass() {
    echo "   PASS: $1"
}

fail() {
    echo "   FAIL: $1"
    FAILURES=$((FAILURES + 1))
}

SRVPID=

cleanup() {

    if [ -n "$SRVPID" ]; then
        kill "$SRVPID" 2>/dev/null
        wait "$SRVPID" 2>/dev/null
    fi

    stop_echo
    rm -rf "$WORK"
}

trap cleanup EXIT INT TERM

WORK=$(mktemp -d /tmp/s3permit.XXXXXX)

# the loopback echo services the allowed dials relay into (the
# run-h3.sh shape): tcp on 19999, udp on 19998

cat > "$WORK/echo_srv.py" <<'PYEOF'
import socket
import sys
import threading


def tcp_srv():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 19999))
    s.listen(8)
    print("ECHO-READY tcp", flush=True)

    def handle(c):
        try:
            while 1:
                d = c.recv(65536)
                if not d:
                    break
                c.sendall(d)
        finally:
            c.close()

    while 1:
        c, _ = s.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()


def udp_srv():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 19998))
    print("ECHO-READY udp", flush=True)
    while 1:
        d, a = s.recvfrom(65536)
        s.sendto(d, a)


{"tcp": tcp_srv, "udp": udp_srv}[sys.argv[1]]()
PYEOF

start_echo() {
    setsid nohup python3 "$WORK/echo_srv.py" "$1" > "$WORK/echo-$1.log" 2>&1 < /dev/null &
    echo "$!" > "$WORK/echo-$1.pid"
}

stop_echo() {
    if [ -f "$WORK/echo-tcp.pid" ]; then
        kill "$(cat "$WORK/echo-tcp.pid")" 2>/dev/null
    fi

    if [ -f "$WORK/echo-udp.pid" ]; then
        kill "$(cat "$WORK/echo-udp.pid")" 2>/dev/null
    fi
}

wait_echo() {
    i=0
    while [ "$i" -lt 50 ]; do
        if grep -q ECHO-READY "$WORK/echo-$1.log" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
        i=$((i + 1))
    done

    return 1
}

# the daemon leg: the fresh log, the flags after the fixed ones

start_srv() {
    env SSH3C_PROTO=1 "$BIN" -3 -l 127.0.0.1:0 -c "$WORK/cert.pem" -k "$WORK/key.pem" \
        "$@" > "$WORK/srv.log" 2>&1 < /dev/null &
    SRVPID=$!

    i=0

    while [ "$i" -lt 50 ]; do
        grep -q INTEROP-LISTEN "$WORK/srv.log" 2>/dev/null && return 0
        sleep 0.1
        i=$((i + 1))
    done

    return 1
}

stop_srv() {

    if [ -n "$SRVPID" ]; then
        kill "$SRVPID" 2>/dev/null
        wait "$SRVPID" 2>/dev/null
        SRVPID=
    fi
}

srv_port() {
    grep -oE 'port=[0-9]+' "$WORK/srv.log" | cut -d= -f2
}

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/key.pem" -out "$WORK/cert.pem" \
    -days 30 -subj /CN=permit-open-e2e 2>/dev/null || die "openssl req failed"

start_echo tcp
start_echo udp

wait_echo tcp || die "the tcp echo did not start"
wait_echo udp || die "the udp echo did not start"

echo "== leg 1: the bad spec stops the daemon before the sockets"

timeout 10 env SSH3C_PROTO=1 "$BIN" -3 -l 127.0.0.1:0 -c "$WORK/cert.pem" \
    -k "$WORK/key.pem" --permit-open garbage > "$WORK/leg0.log" 2>&1 </dev/null
RC=$?

if [ "$RC" -ne 0 ] && grep -q 'bad permit-open spec "garbage"' "$WORK/leg0.log" &&
    ! grep -q INTEROP-LISTEN "$WORK/leg0.log"; then
    pass "the bad spec refused, no listener opened"
else
    fail "the bad spec leg: rc=$RC $(tail -3 "$WORK/leg0.log")"
fi

echo "== run 1: the allow list 127.0.0.1:19999,127.0.0.1:19998"

start_srv --permit-open '127.0.0.1:19999,127.0.0.1:19998' ||
    die "the daemon did not start: $(tail -3 "$WORK/srv.log")"

PORT=$(srv_port)

echo "== leg 2: the listed tcp target relays"

HOME="$WORK" timeout 30 "$BUILD/s3interop_client" -3 -C -F tcp=@19999 \
    -a "127.0.0.1:$PORT" -t 20000 > "$WORK/leg2.log" 2>&1

if [ $? -eq 0 ] && grep -q "INTEROP-FWD-TCP-OK bytes=" "$WORK/leg2.log" &&
    grep -q "INTEROP-FWD-TCP-OPEN target=127.0.0.1:19999" "$WORK/srv.log"; then
    pass "the listed tcp target dialed and echoed"
else
    fail "the allowed tcp leg: $(tail -3 "$WORK/leg2.log")"
fi

echo "== leg 3: the unlisted tcp target is denied before any socket"

HOME="$WORK" timeout 30 "$BUILD/s3interop_client" -3 -C -F tcp=@19997 \
    -a "127.0.0.1:$PORT" -t 20000 > "$WORK/leg3.log" 2>&1

if [ $? -ne 0 ] &&
    grep -q "INTEROP-FWD-TCP-DENIED target=127.0.0.1:19997" "$WORK/srv.log"; then
    pass "the unlisted tcp target refused with the DENIED marker"
else
    fail "the denied tcp leg: $(tail -3 "$WORK/leg3.log")"
fi

echo "== leg 4: the listed udp target relays"

HOME="$WORK" timeout 30 "$BUILD/s3interop_client" -3 -C -F udp=@19998 \
    -a "127.0.0.1:$PORT" -t 20000 > "$WORK/leg4.log" 2>&1

if [ $? -eq 0 ] && grep -q "INTEROP-FWD-UDP-OK count=20" "$WORK/leg4.log" &&
    grep -q "INTEROP-FWD-UDP-OPEN target=127.0.0.1:19998" "$WORK/srv.log"; then
    pass "the listed udp target dialed and echoed"
else
    fail "the allowed udp leg: $(tail -3 "$WORK/leg4.log")"
fi

echo "== leg 5: the unlisted udp target is denied"

HOME="$WORK" timeout 20 "$BUILD/s3interop_client" -3 -C -F udp=@19997 \
    -a "127.0.0.1:$PORT" -t 8000 > "$WORK/leg5.log" 2>&1

if [ $? -ne 0 ] &&
    grep -q "INTEROP-FWD-UDP-DENIED target=127.0.0.1:19997" "$WORK/srv.log"; then
    pass "the unlisted udp target refused with the DENIED marker"
else
    fail "the denied udp leg: $(tail -3 "$WORK/leg5.log")"
fi

stop_srv

echo "== run 2: the negation carve-out !127.0.0.1:19999,127.0.0.1:*"

start_srv --permit-open '!127.0.0.1:19999,127.0.0.1:*' ||
    die "the daemon did not start: $(tail -3 "$WORK/srv.log")"

PORT=$(srv_port)

echo "== leg 6: the negated entry wins over the wildcard port"

HOME="$WORK" timeout 30 "$BUILD/s3interop_client" -3 -C -F tcp=@19999 \
    -a "127.0.0.1:$PORT" -t 20000 > "$WORK/leg6.log" 2>&1

if [ $? -ne 0 ] &&
    grep -q "INTEROP-FWD-TCP-DENIED target=127.0.0.1:19999" "$WORK/srv.log"; then
    pass "the negated target refused despite the wildcard"
else
    fail "the negation leg: $(tail -3 "$WORK/leg6.log")"
fi

echo "== leg 7: the other port rides the wildcard"

HOME="$WORK" timeout 30 "$BUILD/s3interop_client" -3 -C -F udp=@19998 \
    -a "127.0.0.1:$PORT" -t 20000 > "$WORK/leg7.log" 2>&1

if [ $? -eq 0 ] && grep -q "INTEROP-FWD-UDP-OK count=20" "$WORK/leg7.log"; then
    pass "the wildcard port allowed the udp dial"
else
    fail "the wildcard leg: $(tail -3 "$WORK/leg7.log")"
fi

stop_srv

echo "== run 3: the default daemon, no flag"

start_srv || die "the daemon did not start: $(tail -3 "$WORK/srv.log")"

PORT=$(srv_port)

echo "== leg 8: the dial behaves as before the policy existed"

HOME="$WORK" timeout 30 "$BUILD/s3interop_client" -3 -C -F tcp=@19999 \
    -a "127.0.0.1:$PORT" -t 20000 > "$WORK/leg8.log" 2>&1

if [ $? -eq 0 ] && grep -q "INTEROP-FWD-TCP-OK bytes=" "$WORK/leg8.log" &&
    ! grep -q DENIED "$WORK/srv.log"; then
    pass "the unrestricted default kept the historical dial"
else
    fail "the default leg: $(tail -3 "$WORK/leg8.log")"
fi

stop_srv

if [ "$FAILURES" -eq 0 ]; then
    echo "PERMIT-OPEN-E2E OK"
    exit 0
fi

echo "PERMIT-OPEN-E2E FAILED: $FAILURES check(s)"
exit 1
