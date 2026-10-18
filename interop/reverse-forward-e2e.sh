#!/bin/sh
# the reverse forward e2e (PLAN 8.3, the -R of the reference): the
# server binds the client-requested port and mirrors every accepted
# connection or datagram back as a server-initiated forwarded-*
# channel, the harness client bridges it into the local target
#
#   1. the bad -R spec refuses before anything is sent
#   2. the tcp relay: the server binds 127.0.0.1:0 (ephemeral), the
#      driver pushes a byte-exact 64 KiB pattern through the bound
#      port into the client-side echo target
#   3. the udp relay: 20 numbered datagrams ride the same shape
#   4. the gateway-ports=no rewrite: the "*"-bind request lands on
#      the server loopback (the INTEROP-RFWD-OPEN bind=127.0.0.1)
#   5. the permit-listen denial: the allow-list without the loopback
#      refuses the bind before any socket (the DENIED marker, the
#      client exits nonzero)
#   6. the busy port: the pre-bound port refuses honestly (the bind
#      failure rides the reply reason)
#   7. the listener budget: 11 specs against the cap of 10, the
#      eleventh refuses (S2-04)
#
# the verdicts: RFWD-E2E OK / FAILED, the INTEROP-* markers of the C
# runners on the way
#
# usage: interop/reverse-forward-e2e.sh   (WSL)
# requires: the C runners (cmake --build build/linux-release), python3
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD=${BUILD:-$ROOT/build/linux-release}
BIN=${SSH3C_SERVER_BIN:-$BUILD/ssh3-server}

die() {
    echo "reverse-forward-e2e: $1" >&2
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

WORK=$(mktemp -d /tmp/s3rfwd.XXXXXX)

# the local targets of the -R forwards (the client-side echo services,
# the tcp on 19111, the udp on 19112) and the busy port of leg 6

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


def busy_srv():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 19113))
    s.listen(1)
    print("ECHO-READY busy", flush=True)
    while 1:
        s.accept()


{"tcp": tcp_srv, "udp": udp_srv, "busy": busy_srv}[sys.argv[1]]()
PYEOF

start_echo() {
    setsid nohup python3 "$WORK/echo_srv.py" "$1" > "$WORK/echo-$1.log" 2>&1 < /dev/null &
    echo "$!" > "$WORK/echo-$1.pid"
}

stop_echo() {
    for k in tcp udp busy; do

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
    # -R machinery on the open harness shape, not the auth

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

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/key.pem" -out "$WORK/cert.pem" \
    -days 30 -subj /CN=reverse-forward-e2e 2>/dev/null || die "openssl req failed"

start_echo tcp
start_echo udp
start_echo busy

wait_echo tcp || die "the tcp echo did not start"
wait_echo udp || die "the udp echo did not start"
wait_echo busy || die "the busy listener did not start"

echo "== leg 1: the bad spec refuses before anything is sent"

HOME="$WORK" timeout 10 "$BUILD/s3interop_client" -3 -R "garbage" \
    -a "127.0.0.1:19199" -t 3000 > "$WORK/leg1.log" 2>&1
RC=$?

if [ "$RC" -ne 0 ] && grep -q "invalid -R specification" "$WORK/leg1.log"; then
    pass "the bad spec refused at the parse"
else
    fail "the bad spec leg: rc=$RC $(tail -3 "$WORK/leg1.log")"
fi

echo "== run 1: the default daemon (no policy)"

start_srv || die "the daemon did not start: $(tail -3 "$WORK/srv.log")"

wait_port || die "no listen port: $(tail -3 "$WORK/srv.log")"

echo "== leg 2: the tcp relay relays 64 KiB byte-exact"

CLI_T=20000
start_cli -R "0:127.0.0.1:19111" -t 20000

# the bind result polls out of the client markers

i=0
RPORT=

while [ "$i" -lt 100 ]; do
    RPORT=$(grep -oE 'INTEROP-RFWD-OK spec=0 port=[0-9]+' "$WORK/cli.log" | cut -d= -f3)
    [ -n "$RPORT" ] && break
    sleep 0.1
    i=$((i + 1))
done

if [ -z "$RPORT" ]; then
    fail "the tcp leg: no bind port, $(tail -3 "$WORK/cli.log")"
else
    if timeout 30 python3 "$WORK/tcp_probe.py" "$RPORT" > "$WORK/tcp.log" 2>&1 &&
        grep -q "TCP-PROBE-OK bytes=65536" "$WORK/tcp.log"; then
        pass "the tcp relay carried the 64 KiB echo byte-exact (port $RPORT)"
    else
        fail "the tcp relay leg: $(tail -3 "$WORK/tcp.log") srv:$(grep RFWD "$WORK/srv.log" | tail -2)"
    fi
fi

kill "$CLIPID" 2>/dev/null
wait "$CLIPID" 2>/dev/null
CLIPID=

echo "== leg 3: the udp relay carries the numbered datagrams"

CLI_T=20000
start_cli -R "0/udp:127.0.0.1:19112" -t 20000

i=0
RPORT=

while [ "$i" -lt 100 ]; do
    RPORT=$(grep -oE 'INTEROP-RFWD-OK spec=0 port=[0-9]+' "$WORK/cli.log" | cut -d= -f3)
    [ -n "$RPORT" ] && break
    sleep 0.1
    i=$((i + 1))
done

if [ -z "$RPORT" ]; then
    fail "the udp leg: no bind port, $(tail -3 "$WORK/cli.log")"
else
    if timeout 30 python3 "$WORK/udp_probe.py" "$RPORT" > "$WORK/udp.log" 2>&1 &&
        grep -q "UDP-PROBE-OK count=20" "$WORK/udp.log"; then
        pass "the udp relay echoed the 20 datagrams byte-exact (port $RPORT)"
    else
        fail "the udp relay leg: $(tail -3 "$WORK/udp.log") srv:$(grep RFWD "$WORK/srv.log" | tail -2)"
    fi
fi

kill "$CLIPID" 2>/dev/null
wait "$CLIPID" 2>/dev/null
CLIPID=

echo "== leg 4: the gateway-ports=no rewrite lands the wildcard bind on the loopback"

CLI_T=15000
start_cli -R "*:0:127.0.0.1:19111" -t 15000

wait_cli_exit 200

if grep -q "INTEROP-RFWD-OK spec=0 port=" "$WORK/cli.log" &&
    grep -q "INTEROP-RFWD-OPEN kind=tcp bind=127.0.0.1:0" "$WORK/srv.log"; then
    pass "the wildcard bind rode the no policy onto 127.0.0.1"
else
    fail "the rewrite leg: $(tail -3 "$WORK/cli.log")"
fi

if [ -n "$CLIPID" ]; then
    kill "$CLIPID" 2>/dev/null
    wait "$CLIPID" 2>/dev/null
    CLIPID=
fi

stop_srv

echo "== run 2: the permit-listen allow-list without the loopback"

start_srv --permit-listen '192.0.2.1:*' || die "the daemon did not start: $(tail -3 "$WORK/srv.log")"

wait_port || die "no listen port: $(tail -3 "$WORK/srv.log")"

echo "== leg 5: the loopback bind refuses before any socket"

CLI_T=4000
start_cli -R "0:127.0.0.1:19111" -t 4000

wait_cli_exit 100

if [ "$CLI_RC" -ne 0 ] && grep -q "INTEROP-RFWD-DENIED spec=0" "$WORK/cli.log" &&
    grep -q "denied by -permit-listen policy" "$WORK/srv.log"; then
    pass "the permit-listen gate refused the bind (the client rc $CLI_RC)"
else
    fail "the permit-listen leg: rc=$CLI_RC $(tail -3 "$WORK/cli.log")"
fi

stop_srv

echo "== run 3: the default daemon again, the busy port leg"

start_srv || die "the daemon did not start: $(tail -3 "$WORK/srv.log")"

wait_port || die "no listen port: $(tail -3 "$WORK/srv.log")"

echo "== leg 6: the pre-bound port refuses honestly"

CLI_T=4000
start_cli -R "127.0.0.1:19113:127.0.0.1:19111" -t 4000

wait_cli_exit 100

if [ "$CLI_RC" -ne 0 ] && grep -q "INTEROP-RFWD-DENIED spec=0" "$WORK/cli.log" &&
    grep -qiE "bind 127.0.0.1:19113 failed" "$WORK/srv.log"; then
    pass "the busy port refusal rode the reply reason"
else
    fail "the busy port leg: rc=$CLI_RC $(tail -3 "$WORK/cli.log") srv:$(grep RFWD "$WORK/srv.log")"
fi

echo "== leg 7: the listener budget caps at 10 of 11"

RSPEC=""

for i in 1 2 3 4 5 6 7 8 9 10 11; do
    RSPEC="$RSPEC -R 0:127.0.0.1:19111"
done

CLI_T=6000
start_cli $RSPEC -t 6000

wait_cli_exit 200

OKN=$(grep -c "INTEROP-RFWD-OK" "$WORK/cli.log" || true)
DENN=$(grep -c "INTEROP-RFWD-DENIED" "$WORK/cli.log" || true)

if [ "$OKN" -eq 10 ] && [ "$DENN" -eq 1 ] && [ "$CLI_RC" -ne 0 ] &&
    grep -q "too many reverse forwards" "$WORK/srv.log"; then
    pass "the eleventh bind refused on the budget (ok=$OKN denied=$DENN)"
else
    fail "the budget leg: ok=$OKN denied=$DENN rc=$CLI_RC $(tail -3 "$WORK/cli.log")"
fi

stop_srv

if [ "$FAILURES" -eq 0 ]; then
    echo "RFWD-E2E OK"
    exit 0
fi

echo "RFWD-E2E FAILED: $FAILURES check(s)"
exit 1
