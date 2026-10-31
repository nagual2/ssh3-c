#!/bin/sh
# the product client reverse forward e2e (backlog 3 tail): the -R of
# the product app/ssh3_client.c against the ssh3-server daemon - the
# server binds the client-requested port and mirrors every accepted
# connection or datagram back as a server-initiated forwarded-*
# channel, the product client bridges it into the local target
#
#   1. the bad -R spec refuses at the parse (exit 255)
#   2. the tcp relay: the server binds 127.0.0.1:0 (ephemeral), the
#      driver pushes a byte-exact 64 KiB pattern through the bound
#      port into the client-side echo target
#      (the PRODUCT-REVERSE-TCP-OK marker)
#   3. the udp relay: 20 numbered datagrams ride the same shape, the
#      echo sends a zero-length datagram ahead of them and the bridge
#      must stay alive (an empty datagram is a datagram, RFC 768)
#      (the PRODUCT-REVERSE-UDP-OK marker)
#   4. the permit-listen denial: the allow-list without the loopback
#      refuses the bind before any socket (the SSH3-RFWD-DENIED
#      marker, the client exits 255)
#   5. the ipv6 target refuses at the parse: the reverse bridge dials
#      the ipv4 targets only, so the refusal rides the parse and the
#      server never binds a port that could not carry a byte
#   6. the ipv6 bind is refused by the server: the client spells the
#      bind, the server refuses it fail-closed (the v4-only listener
#      machinery) and the client fails closed
#   7. the per-user budget: the cap of one listener refuses the
#      second -R of the same conversation (the REVERSE-CAP-DENIED
#      marker) and the client fails closed
#   8. the run-as attribution (the root runs only): the daemon with
#      --run-as-user on books the budget under the authenticated user
#      (the marker carries the name, not the daemon placeholder)
#
# the client home pre-pins the daemon certificate (the hold run
# rides no console, the TOFU question cannot run): the pin line is
# built from the certificate DER, the store format of the client
#
# usage: interop/product-reverse-e2e.sh   (WSL)
# requires: the C runners (cmake --build build/linux-release), python3
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD=${BUILD:-$ROOT/build/linux-release}
BIN=${SSH3C_SERVER_BIN:-$BUILD/ssh3-server}

die() {
    echo "product-reverse-e2e: $1" >&2
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
    if [ "${S3PRREV_KEEP:-0}" != "1" ]; then
        rm -rf "$WORK"
    fi
}

trap cleanup EXIT INT TERM

WORK=$(mktemp -d /tmp/s3prrev.XXXXXX)

# the identity (the Bearer JWT of -i) and the authorized keys line

openssl genpkey -algorithm ed25519 -out "$WORK/priv.pem" 2>/dev/null || die "openssl genpkey failed"

{
    printf '\000\000\000\013ssh-ed25519\000\000\000\040'
    openssl pkey -in "$WORK/priv.pem" -pubout -outform DER 2>/dev/null | tail -c 32
} | base64 | tr -d '\n' > "$WORK/blob.pub"

printf 'ssh-ed25519 %s product-reverse-e2e\n' "$(cat "$WORK/blob.pub")" \
    > "$WORK/authorized_keys"

# the local targets of the -R forwards (the client-side echo
# services, the tcp on 19121, the udp on 19122)

cat > "$WORK/echo_srv.py" <<'PYEOF'
import socket
import sys
import threading


def tcp_srv():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 19121))
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
    s.bind(("127.0.0.1", 19122))
    print("ECHO-READY udp", flush=True)
    while 1:
        d, a = s.recvfrom(65536)

        # the zero-length datagram rides ahead of the echo: it is a
        # datagram (RFC 768), not a closed target - the client bridge
        # must stay alive and carry the numbered echo behind it

        s.sendto(b"", a)
        s.sendto(d, a)


def tcp6_srv():
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("::1", 19123))
    s.listen(8)
    print("ECHO-READY tcp6", flush=True)

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


{"tcp": tcp_srv, "udp": udp_srv, "tcp6": tcp6_srv}[sys.argv[1]]()
PYEOF

start_echo() {
    setsid nohup python3 "$WORK/echo_srv.py" "$1" > "$WORK/echo-$1.log" 2>&1 < /dev/null &
    echo "$!" > "$WORK/echo-$1.pid"
}

stop_echo() {

    for k in tcp udp tcp6; do

        if [ -f "$WORK/echo-$k.pid" ]; then
            kill "$(cat "$WORK/echo-$k.pid")" 2>/dev/null
        fi
    done
}

wait_echo() {
    i=0
    while [ "$i" -lt 100 ]; do
        if grep -q ECHO-READY "$WORK/echo-$1.log" 2>/dev/null; then
            return 0
        fi
        sleep 0.2
        i=$((i + 1))
    done

    return 1
}

# the daemon leg: the fixed port scan (the two runs share the port,
# the pre-pin rides the hostkey key), the INTEROP-LISTEN marker

SRVPORT=

start_srv() {
    p=$((49000 + ($$ % 2000)))

    i=0

    while [ "$i" -lt 8 ]; do

        SRVLOG="$WORK/srv.log"

        setsid nohup env SSH3C_PROTO=1 "$BIN" -3 -l "127.0.0.1:$p" -c "$WORK/cert.pem" \
            -k "$WORK/key.pem" -K "$WORK/authorized_keys" "$@" > "$SRVLOG" 2>&1 < /dev/null &
        SRVPID=$!

        j=0

        while [ "$j" -lt 50 ]; do

            if grep -q INTEROP-LISTEN "$SRVLOG" 2>/dev/null; then
                SRVPORT=$p
                return 0
            fi

            if ! kill -0 "$SRVPID" 2>/dev/null; then
                break # the bind refused, the next port scans
            fi

            sleep 0.1
            j=$((j + 1))
        done

        kill "$SRVPID" 2>/dev/null
        wait "$SRVPID" 2>/dev/null
        SRVPID=

        p=$((p + 1))
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

# the client home: the pre-pinned host of the daemon certificate
# (the hold run rides no console, the TOFU question cannot run)

pin_home() {
    rm -rf "$WORK/home"
    mkdir -p "$WORK/home/.ssh3"

    printf '%s x509-certificate %s\n' "127.0.0.1:$SRVPORT/ssh3-term" \
        "$(openssl x509 -in "$WORK/cert.pem" -outform DER | base64 -w0)" \
        > "$WORK/home/.ssh3/known_hosts"
}

# the -R client leg: the hold run in the background, the bound port
# polls out of the SSH3-RFWD-OK marker

start_cli() {
    pin_home
    S3CLILOG="${S3CLILOG:-$WORK/cli.log}"

    if [ "${S3CLI_V:-0}" = "1" ]; then
        set -- -vv "$@"
    fi

    setsid nohup env HOME="$WORK/home" "$BUILD/ssh3" "$@" \
        -i "$WORK/priv.pem" "${S3CLI_USER:-client}@127.0.0.1:$SRVPORT/ssh3-term" \
        > "$S3CLILOG" 2>&1 < /dev/null &
    CLIPID=$!
}

wait_bind() {
    i=0

    while [ "$i" -lt 50 ]; do
        RPORT=$(grep -oE 'SSH3-RFWD-OK spec=0 port=[0-9]+' "${S3CLILOG:-$WORK/cli.log}" | cut -d= -f3)
        [ -n "$RPORT" ] && return 0
        sleep 0.1
        i=$((i + 1))
    done

    return 1
}

stop_cli() {

    if [ -n "$CLIPID" ]; then
        kill "$CLIPID" 2>/dev/null
        wait "$CLIPID" 2>/dev/null
        CLIPID=
    fi
}

# the byte-exact tcp driver: 64 KiB through the bound port into the
# client-side echo (the index range repeated)

cat > "$WORK/tcp_probe.py" <<'PYEOF'
import socket
import sys

pattern = bytes(range(256)) * 256  # 64 KiB

host = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"

s = socket.create_connection((host, int(sys.argv[1])), timeout=15)
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
# channel (the channel-per-peer shape), the burst would outrun the
# setup
for m in msgs:
    s.sendto(m, ("127.0.0.1", int(sys.argv[1])))
    time.sleep(0.02)

got = {}
try:
    while len(got) < n:
        d, _ = s.recvfrom(65536)

        # the short datagrams carry no index (the empty one of the
        # echo probe): they do not count

        if len(d) < 4:
            continue

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

echo "== leg 1: the bad -R spec refuses at the parse"

if timeout 10 "$BUILD/ssh3" -R garbage bob@127.0.0.1:1/ssh3-term \
    > "$WORK/leg1.out" 2> "$WORK/leg1.err"; then
    fail "the bad spec leg: the run exited 0"
else
    RC=$?

    if [ "$RC" -eq 255 ] && grep -qE "bad -R spec|stdio forward is not supported" "$WORK/leg1.err"; then
        pass "the bad spec refused at the parse (rc $RC)"
    else
        fail "the bad spec leg: rc=$RC $(tail -1 "$WORK/leg1.err")"
    fi
fi

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/key.pem" -out "$WORK/cert.pem" \
    -days 2 -subj /CN=product-reverse-e2e 2>/dev/null || die "openssl req failed"

# the ports of a crashed earlier run hold the bind: the pre-kill
# makes the stand self-healing (once, before both echo starts)

pkill -f "echo_srv[.]py" 2>/dev/null
sleep 0.3

start_echo tcp
start_echo udp

wait_echo tcp || die "the tcp echo did not start"
wait_echo udp || die "the udp echo did not start"

start_srv --run-as-user off || die "the daemon did not start: $(tail -3 "$WORK/srv.log")"

echo "== leg 2: the tcp relay carries 64 KiB byte-exact (PRODUCT-REVERSE-TCP-OK)"

start_cli -R "0:127.0.0.1:19121"

if wait_bind; then
    if timeout 30 python3 "$WORK/tcp_probe.py" "$RPORT" > "$WORK/tcp.log" 2>&1 &&
        grep -q "TCP-PROBE-OK bytes=65536" "$WORK/tcp.log"; then
        pass "the tcp relay carried the 64 KiB echo byte-exact (PRODUCT-REVERSE-TCP-OK, port $RPORT)"
    else
        fail "the tcp relay leg: $(tail -2 "$WORK/tcp.log") srv:$(grep RFWD "$WORK/srv.log" | tail -2)"
    fi

else
    fail "the tcp relay leg: no bind port, $(tail -3 "$WORK/cli.log")"
fi

stop_cli

echo "== leg 3: the udp relay echoes 20 datagrams and survives the empty one (PRODUCT-REVERSE-UDP-OK)"

S3CLILOG="$WORK/cli-udp.log"
start_cli -R "0/udp:127.0.0.1:19122"

if wait_bind; then
    sleep 1

    if timeout 30 python3 "$WORK/udp_probe.py" "$RPORT" > "$WORK/udp.log" 2>&1 &&
        grep -q "UDP-PROBE-OK count=20" "$WORK/udp.log"; then
        pass "the udp relay echoed the 20 datagrams byte-exact past the empty one (PRODUCT-REVERSE-UDP-OK, port $RPORT)"
    else
        fail "the udp relay leg: $(tail -2 "$WORK/udp.log") srv:$(grep RFWD "$WORK/srv.log" | tail -2)"
    fi

else
    fail "the udp relay leg: no bind port, $(tail -3 "$S3CLILOG")"
fi

stop_cli
stop_srv

echo "== leg 4: the permit-listen denial refuses the bind"

S3CLILOG="$WORK/cli-deny.log"

start_srv --run-as-user off --permit-listen '192.0.2.1:*' \
    || die "the daemon did not start: $(tail -3 "$WORK/srv.log")"

start_cli -R "0:127.0.0.1:19121"

i=0
CLI_RC=

while [ "$i" -lt 60 ]; do

    if ! kill -0 "$CLIPID" 2>/dev/null; then
        wait "$CLIPID"
        CLI_RC=$?
        CLIPID=
        break
    fi

    sleep 0.1
    i=$((i + 1))
done

if [ -n "$CLI_RC" ] && [ "$CLI_RC" -ne 0 ] &&
    grep -q "SSH3-RFWD-DENIED spec=0" "$S3CLILOG" &&
    grep -q "denied by -permit-listen policy" "$WORK/srv.log"; then
    pass "the permit-listen gate refused the bind (the client rc $CLI_RC)"
else
    fail "the permit-listen leg: rc=${CLI_RC:-running} $(tail -2 "$S3CLILOG")"
fi

stop_srv

echo "== leg 5: the ipv6 target relay carries 64 KiB byte-exact (PRODUCT-REVERSE-V6TARGET-OK)"

start_srv --run-as-user off || die "the daemon did not start: $(tail -3 "$WORK/srv.log")"

start_echo tcp6
wait_echo tcp6 || die "the tcp6 echo did not start"

S3CLILOG="$WORK/cli-v6tgt.log"
start_cli -R "0:[::1]:19123"

if wait_bind; then
    if timeout 30 python3 "$WORK/tcp_probe.py" "$RPORT" > "$WORK/tcp6.log" 2>&1 &&
        grep -q "TCP-PROBE-OK" "$WORK/tcp6.log"; then
        pass "the v6 target relay carried 64 KiB byte-exact"
    else
        fail "the v6 target relay leg: $(tail -2 "$WORK/tcp6.log")"
    fi

else
    fail "the v6 target relay leg: no bind $(tail -2 "$S3CLILOG")"
fi

stop_cli
stop_srv

echo "== leg 6: the ipv6 bind serves the relay (PRODUCT-REVERSE-V6BIND-OK)"

start_srv --run-as-user off || die "the daemon did not start: $(tail -3 "$WORK/srv.log")"

# the tcp echo of the leg 2 still rides (the stops land at the exit):
# the wait suffices
wait_echo tcp || die "the tcp echo did not start"

S3CLILOG="$WORK/cli-v6bind.log"
start_cli -R "[::1]:0:127.0.0.1:19121"

if wait_bind; then
    if timeout 30 python3 "$WORK/tcp_probe.py" "$RPORT" "::1" > "$WORK/tcp-v6bind.log" 2>&1 &&
        grep -q "TCP-PROBE-OK" "$WORK/tcp-v6bind.log"; then
        pass "the ipv6 bind relay carried 64 KiB byte-exact"
    else
        fail "the ipv6 bind relay leg: $(tail -2 "$WORK/tcp-v6bind.log")"
    fi

else
    fail "the ipv6 bind leg: no bind $(tail -2 "$S3CLILOG")"
fi

if grep -q "bind=::1" "$WORK/srv.log"; then
    pass "the daemon logged the v6 bind address"
else
    fail "no bind=::1 in the daemon log"
fi

stop_cli
stop_srv

echo "== leg 7: the per-user budget refuses the second -R"

start_srv --run-as-user off --max-reverse-forwards 1 \
    || die "the daemon did not start: $(tail -3 "$WORK/srv.log")"

S3CLILOG="$WORK/cli-cap.log"
start_cli -R "0:127.0.0.1:19121" -R "0:127.0.0.1:19122"

i=0
CLI_RC=

while [ "$i" -lt 60 ]; do

    if ! kill -0 "$CLIPID" 2>/dev/null; then
        wait "$CLIPID"
        CLI_RC=$?
        CLIPID=
        break
    fi

    sleep 0.1
    i=$((i + 1))
done

if [ -n "$CLI_RC" ] && [ "$CLI_RC" -ne 0 ] &&
    grep -q "SSH3-RFWD-DENIED" "$S3CLILOG" &&
    grep -q "REVERSE-CAP-DENIED" "$WORK/srv.log"; then
    pass "the per-user budget refused the second bind (the client rc $CLI_RC)"
else
    fail "the budget leg: rc=${CLI_RC:-running} $(tail -2 "$S3CLILOG")"
fi

stop_cli
stop_srv

echo "== leg 8: the run-as budget rides the authenticated user"

if [ "$(id -u)" != "0" ]; then
    echo "   SKIP: the run-as leg needs the root privilege (the daemon is the one that drops the session identity)"

else
    RUNAS_USER=$(id -un)

    start_srv --run-as-user on --max-reverse-forwards 1 \
        || die "the daemon did not start: $(tail -3 "$WORK/srv.log")"

    S3CLILOG="$WORK/cli-runas.log"
    S3CLI_USER="$RUNAS_USER"
    start_cli -R "0:127.0.0.1:19121" -R "0:127.0.0.1:19122"

    i=0
    CLI_RC=

    while [ "$i" -lt 60 ]; do

        if ! kill -0 "$CLIPID" 2>/dev/null; then
            wait "$CLIPID"
            CLI_RC=$?
            CLIPID=
            break
        fi

        sleep 0.1
        i=$((i + 1))
    done

    if [ -n "$CLI_RC" ] && [ "$CLI_RC" -ne 0 ] &&
        grep -q "REVERSE-CAP-DENIED" "$WORK/srv.log" &&
        grep -q "user=$RUNAS_USER" "$WORK/srv.log"; then
        pass "the run-as budget booked the authenticated user $RUNAS_USER (the client rc $CLI_RC)"
    else
        fail "the run-as leg: rc=${CLI_RC:-running} $(grep RFWD "$WORK/srv.log" | tail -2)"
    fi

    stop_cli
    stop_srv
fi

if [ "$FAILURES" -eq 0 ]; then
    echo "PRODUCT-REVERSE-E2E OK"
    exit 0
fi

echo "PRODUCT-REVERSE-E2E FAILED: $FAILURES check(s)"
exit 1
