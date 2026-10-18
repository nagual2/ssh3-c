#!/bin/sh
# the gateway-ports e2e (PLAN 8, the server flags of the reference):
# the --gateway-ports policy of the reverse (-R) binds and the
# --max-reverse-forwards cap, the shapes of the reference
# resolveReverseForwardBind and maxReverseForwardsPerUser
#
#   1. the default daemon ("no"): the wildcard -R bind lands on the
#      server loopback (the INTEROP-RFWD-OPEN bind=127.0.0.1, the
#      GatewayPorts=no rewrite line, the probe rides 127.0.0.1)
#   2. the "yes" daemon: the wildcard bind stays the wildcard
#      (bind=0.0.0.0, tcp and udp alike), the loopback still reaches
#      the wildcard listener (the probe)
#   3. the "clientspecified" daemon: the explicit 0.0.0.0 bind is
#      honored as-is (no rewrite line, bind=0.0.0.0)
#   4. the cap: --max-reverse-forwards 1, the second -R refuses with
#      the REVERSE-CAP-DENIED marker before any socket
#
# the verdict: GATEWAY-E2E OK / FAILED, the INTEROP-* markers of the
# C runners on the way
#
# usage: interop/gateway-ports-e2e.sh   (WSL)
# requires: the C runners (cmake --build build/linux-release), python3
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD=${BUILD:-$ROOT/build/linux-release}
BIN=${SSH3C_SERVER_BIN:-$BUILD/ssh3-server}

die() {
    echo "gateway-ports-e2e: $1" >&2
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
CLIPID=

cleanup() {

    if [ -n "$CLIPID" ]; then
        kill "$CLIPID" 2>/dev/null
        wait "$CLIPID" 2>/dev/null
        CLIPID=
    fi

    if [ -n "$SRVPID" ]; then
        kill "$SRVPID" 2>/dev/null
        wait "$SRVPID" 2>/dev/null
        SRVPID=
    fi

    stop_echo
    rm -rf "$WORK"
}

trap cleanup EXIT INT TERM

WORK=$(mktemp -d /tmp/s3gwp.XXXXXX)

# the local targets of the -R forwards (the client-side echo services,
# the tcp on 19111, the udp on 19112)

cat > "$WORK/echo_srv.py" <<'PYEOF'
import socket
import sys
import threading


def tcp_srv():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 19111))
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
    s.bind(("127.0.0.1", 19112))
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
    for k in tcp udp; do

        if [ -f "$WORK/echo-$k.pid" ]; then
            kill "$(cat "$WORK/echo-$k.pid")" 2>/dev/null
        fi
    done
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
    # the 1e password default rides off here: the legs exercise the
    # bind policy on the open harness shape, not the auth

    env SSH3C_PROTO=1 "$BIN" -3 -l 127.0.0.1:0 -c "$WORK/cert.pem" -k "$WORK/key.pem" \
        --password-system off \
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

# the listen marker lands in one write, but the daemon start under the
# drvfs-backed binary can lag whole seconds behind the fork: poll the
# port out instead of reading it once next to start_srv

wait_port() {
    i=0

    while [ "$i" -lt 50 ]; do
        PORT=$(srv_port)

        [ -n "$PORT" ] && return 0

        sleep 0.1
        i=$((i + 1))
    done

    return 1
}

# the -R client leg: the fresh log, the deadline exit reads out

CLI_RC=0

start_cli() {
    HOME="$WORK" env SSH3C_PROTO=1 "$BUILD/s3interop_client" -3 -a "127.0.0.1:$PORT" \
        -t "$CLI_T" "$@" > "$WORK/cli.log" 2>&1 < /dev/null &
    CLIPID=$!
    CLI_RC=0
}

wait_cli_exit() {
    i=0

    while [ "$i" -lt "$1" ]; do

        if ! kill -0 "$CLIPID" 2>/dev/null; then
            wait "$CLIPID"
            CLI_RC=$?
            CLIPID=
            return 0
        fi

        sleep 0.1
        i=$((i + 1))
    done

    return 1
}

kill_cli() {

    if [ -n "$CLIPID" ]; then
        kill "$CLIPID" 2>/dev/null
        wait "$CLIPID" 2>/dev/null
        CLIPID=
    fi
}

# the byte-exact tcp driver: 64 KiB through the bound port into the
# client-side echo (the LCG-free pattern, the index range repeated)

cat > "$WORK/tcp_probe.py" <<'PYEOF'
import socket
import sys

pattern = bytes(range(256)) * 256  # 64 KiB

s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=15)
s.sendall(pattern)

got = b""
while len(got) < len(pattern):
    d = s.recv(65536)
    if not d:
        break
    got += d

s.close()

if got == pattern:
    print("TCP-PROBE-OK bytes=%d" % len(got))
else:
    ok = sum(1 for a, b in zip(got, pattern) if a == b)
    print("TCP-PROBE-FAIL got=%d match=%d" % (len(got), ok))
    sys.exit(1)
PYEOF

# the numbered datagram driver (the 1024-byte payloads, the le32 idx)

cat > "$WORK/udp_probe.py" <<'PYEOF'
import socket
import struct
import sys
import time

n = 20
size = 1024

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(15)

msgs = [struct.pack("<I", i) + bytes(((i * 7 + j) % 256) for j in range(size - 4))
        for i in range(n)]

# the pacing: the first datagram of a peer opens its forwarded-udp
# channel (the channel-per-datagram shape), the burst would outrun
# the setup
for m in msgs:
    s.sendto(m, ("127.0.0.1", int(sys.argv[1])))
    time.sleep(0.02)

got = {}
try:
    while len(got) < n:
        d, _ = s.recvfrom(65536)
        idx = struct.unpack("<I", d[:4])[0]
        if idx < n and idx not in got:
            got[idx] = d
except socket.timeout:
    pass

s.close()

if len(got) == n and all(got[i] == msgs[i] for i in range(n)):
    print("UDP-PROBE-OK count=%d" % n)
else:
    print("UDP-PROBE-FAIL got=%d" % len(got))
    sys.exit(1)
PYEOF

# the bind port of the -R spec polls out of the client markers; the
# daemon-side bind text of the open marker rides the server log

wait_rport() {
    i=0

    while [ "$i" -lt 100 ]; do
        RPORT=$(grep -oE 'INTEROP-RFWD-OK spec=0 port=[0-9]+' "$WORK/cli.log" | cut -d= -f3)
        [ -n "$RPORT" ] && return 0
        sleep 0.1
        i=$((i + 1))
    done

    return 1
}

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/key.pem" -out "$WORK/cert.pem" \
    -days 30 -subj /CN=gateway-ports-e2e 2>/dev/null || die "openssl req failed"

start_echo tcp || true
start_echo udp || true

wait_echo tcp || die "the tcp echo did not start"
wait_echo udp || die "the udp echo did not start"

echo "== leg 1: the default daemon (no) forces the wildcard bind onto the loopback"

start_srv || die "the daemon did not start: $(tail -3 "$WORK/srv.log")"

wait_port || die "no listen port: $(tail -3 "$WORK/srv.log")"

CLI_T=15000
start_cli -R "*:0:127.0.0.1:19111" -t 15000

wait_rport

if grep -q "INTEROP-RFWD-OPEN kind=tcp bind=127.0.0.1:0" "$WORK/srv.log" &&
    grep -q "GatewayPorts=no policy restricted the bind :: to 127.0.0.1" "$WORK/srv.log"; then
    pass "the wildcard bind rode the no policy onto 127.0.0.1"
else
    fail "the no-policy bind: $(grep RFWD-OPEN "$WORK/srv.log" | tail -2)"
fi

if [ -n "$RPORT" ] &&
    timeout 30 python3 "$WORK/tcp_probe.py" "$RPORT" > "$WORK/tcp.log" 2>&1 &&
    grep -q "TCP-PROBE-OK bytes=65536" "$WORK/tcp.log"; then
    pass "the loopback bind served the 64 KiB echo byte-exact (port $RPORT)"
else
    fail "the no-policy probe: $(tail -3 "$WORK/tcp.log" 2>/dev/null) port=$RPORT"
fi

kill_cli
stop_srv

echo "== leg 2: the yes daemon keeps the wildcard bind (tcp and udp alike)"

start_srv --gateway-ports yes || die "the daemon did not start: $(tail -3 "$WORK/srv.log")"

wait_port || die "no listen port: $(tail -3 "$WORK/srv.log")"

CLI_T=15000
start_cli -R "*:0:127.0.0.1:19111" -t 15000

wait_rport

if grep -q "INTEROP-RFWD-OPEN kind=tcp bind=0.0.0.0:0" "$WORK/srv.log" &&
    grep -q "GatewayPorts=yes policy restricted the bind :: to 0.0.0.0" "$WORK/srv.log"; then
    pass "the wildcard bind stayed the wildcard under yes (tcp)"
else
    fail "the yes-policy tcp bind: $(grep RFWD-OPEN "$WORK/srv.log" | tail -2)"
fi

if [ -n "$RPORT" ] &&
    timeout 30 python3 "$WORK/tcp_probe.py" "$RPORT" > "$WORK/tcp.log" 2>&1 &&
    grep -q "TCP-PROBE-OK bytes=65536" "$WORK/tcp.log"; then
    pass "the wildcard listener still served the loopback probe (port $RPORT)"
else
    fail "the yes-policy tcp probe: $(tail -3 "$WORK/tcp.log" 2>/dev/null) port=$RPORT"
fi

kill_cli

CLI_T=15000
start_cli -R "*:0/udp:127.0.0.1:19112" -t 15000

wait_rport

if [ -n "$RPORT" ] &&
    timeout 30 python3 "$WORK/udp_probe.py" "$RPORT" > "$WORK/udp.log" 2>&1 &&
    grep -q "UDP-PROBE-OK count=20" "$WORK/udp.log" &&
    grep -q "INTEROP-RFWD-OPEN kind=udp bind=0.0.0.0:0" "$WORK/srv.log"; then
    pass "the udp wildcard bind echoed the 20 datagrams (port $RPORT)"
else
    fail "the yes-policy udp leg: $(tail -3 "$WORK/udp.log" 2>/dev/null) port=$RPORT srv:$(grep 'kind=udp' "$WORK/srv.log" | tail -1)"
fi

kill_cli
stop_srv

echo "== leg 3: the clientspecified daemon honors the explicit bind"

start_srv --gateway-ports clientspecified ||
    die "the daemon did not start: $(tail -3 "$WORK/srv.log")"

wait_port || die "no listen port: $(tail -3 "$WORK/srv.log")"

CLI_T=15000
start_cli -R "0.0.0.0:0:127.0.0.1:19111" -t 15000

wait_rport

if grep -q "INTEROP-RFWD-OPEN kind=tcp bind=0.0.0.0:0" "$WORK/srv.log" &&
    ! grep -q "policy restricted the bind" "$WORK/srv.log"; then
    pass "the explicit 0.0.0.0 bind was honored as-is (no rewrite line)"
else
    fail "the clientspecified bind: $(grep 'RFWD-OPEN\|GatewayPorts' "$WORK/srv.log" | tail -2)"
fi

if [ -n "$RPORT" ] &&
    timeout 30 python3 "$WORK/tcp_probe.py" "$RPORT" > "$WORK/tcp.log" 2>&1 &&
    grep -q "TCP-PROBE-OK bytes=65536" "$WORK/tcp.log"; then
    pass "the client-specified wildcard bind served the probe (port $RPORT)"
else
    fail "the clientspecified probe: $(tail -3 "$WORK/tcp.log" 2>/dev/null) port=$RPORT"
fi

kill_cli
stop_srv

echo "== leg 4: the cap of 1 refuses the second -R with the marker"

start_srv --max-reverse-forwards 1 ||
    die "the daemon did not start: $(tail -3 "$WORK/srv.log")"

wait_port || die "no listen port: $(tail -3 "$WORK/srv.log")"

CLI_T=6000
start_cli -R "0:127.0.0.1:19111" -R "0:127.0.0.1:19111" -t 6000

wait_cli_exit 300

OKN=$(grep -c "INTEROP-RFWD-OK" "$WORK/cli.log" || true)
DENN=$(grep -c "INTEROP-RFWD-DENIED" "$WORK/cli.log" || true)

if [ "$OKN" -eq 1 ] && [ "$DENN" -ge 1 ] && [ "$CLI_RC" -ne 0 ] &&
    grep -q "REVERSE-CAP-DENIED" "$WORK/srv.log" &&
    grep -q "too many reverse forwards for user" "$WORK/srv.log"; then
    pass "the second bind refused with the REVERSE-CAP-DENIED marker (ok=$OKN denied=$DENN)"
else
    fail "the cap leg: ok=$OKN denied=$DENN rc=$CLI_RC $(tail -3 "$WORK/cli.log") srv:$(grep 'REVERSE-CAP-DENIED\|refusing' "$WORK/srv.log" | tail -2)"
fi

stop_srv

if [ "$FAILURES" -eq 0 ]; then
    echo "GATEWAY-E2E OK"
    exit 0
fi

echo "GATEWAY-E2E FAILED: $FAILURES check(s)"
exit 1
