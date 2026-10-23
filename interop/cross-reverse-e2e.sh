#!/bin/sh
# the cross reverse-forward e2e (the B12/B13 aftermath): the -R rides
# between the implementations in both directions, plus the datagram
# legs over the same wires:
#
#   1. the fork client -R (tcp) against the C daemon: the connector
#      hits the bound port of the daemon, the relay dials the local
#      echo of the client machine, the bytes come back
#   2. the C client -R (tcp) against the fork server: the same shape
#      mirrored
#   3. the C client udp:// local forward (the datagrams) against the
#      fork server: the datagrams relay to the udp echo and back
#   4. the fork client -R/udp against the C daemon: the datagram
#      relay of the reverse side
#
# usage: interop/cross-reverse-e2e.sh   (WSL)
# requires: the C daemon and client (build/linux-release), the go
# fork sources (GOSSHSRC, default ~/git/ssh3) - the binaries build on
# the fly when absent
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD=${BUILD:-$ROOT/build/linux-release}
CSRV=${SSH3C_SERVER_BIN:-$BUILD/ssh3-server}
CCLI=${SSH3C_CLIENT_BIN:-$BUILD/ssh3}
GOSSHSRC=${GOSSHSRC:-$HOME/git/ssh3}
GOBIN=${GOSSHBIN:-/tmp/go-ssh3-cross}
IDENT_LABEL=cross-reverse-e2e

die() {
    echo "cross-reverse-e2e: $1" >&2
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

[ -x "$CSRV" ] || die "the C daemon is not built: $CSRV"
[ -x "$CCLI" ] || die "the C client is not built: $CCLI"
[ -d "$GOSSHSRC" ] || die "the go fork sources are missing: $GOSSHSRC"

mkdir -p "$GOBIN"

if [ ! -x "$GOBIN/ssh3-server" ] || [ ! -x "$GOBIN/ssh3" ]; then
    echo "   .. building the fork ($GOSSHSRC)"
    (cd "$GOSSHSRC" && go build -o "$GOBIN/ssh3-server" ./cmd/ssh3-server &&
        go build -o "$GOBIN/ssh3" ./cmd/ssh3) || die "the fork build failed"
fi

W=$(mktemp -d /tmp/cross-rev.XXXXXX)
REAL_IDENT="$HOME/.ssh3/authorized_identities"
SRVPIDS=""

cleanup() {
    for p in $SRVPIDS; do
        kill "$p" 2>/dev/null
        wait "$p" 2>/dev/null
    done

    if [ -f "$REAL_IDENT" ]; then
        sed -i "/$IDENT_LABEL/d" "$REAL_IDENT"
    fi

    rm -rf "$W"
}

trap cleanup EXIT INT TERM

# the identities: one ed25519 pair, the -K file of the C daemon and
# the labeled line of the real authorized_identities (the fork server
# resolves the user and reads its own home)

openssl genpkey -algorithm ed25519 -out "$W/key.pem" 2>/dev/null ||
    die "openssl genpkey failed"

{
    printf '\000\000\000\013ssh-ed25519\000\000\000\040'
    openssl pkey -in "$W/key.pem" -pubout -outform DER 2>/dev/null | tail -c 32
} | base64 | tr -d '\n' > "$W/blob.pub"

printf 'ssh-ed25519 %s %s\n' "$(cat "$W/blob.pub")" "$IDENT_LABEL" > "$W/authorized_keys"

mkdir -p "$HOME/.ssh3"
touch "$REAL_IDENT"
grep -q "$IDENT_LABEL" "$REAL_IDENT" || cat "$W/authorized_keys" >> "$REAL_IDENT"

openssl req -x509 -sha256 -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout "$W/key-cert.pem" -days 2 -out "$W/cert.pem" -subj /CN=cross-reverse-e2e \
    -addext "subjectAltName=IP:127.0.0.1" 2>/dev/null || die "openssl req failed"

# the cert and the key ride separate files: the C daemon takes -k as
# the key path and a certificate-only file leaves it dead at the
# startup (the ssl init fails before the listen)

# the echo targets: the tcp echo of the client machine and the udp
# echo for the datagram legs (the helpers ride the workdir files: a
# backgrounded heredoc-python is unreliable under dash)

cat > "$W/tcp_echo.py" <<'EOF'
import socket, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1])))
s.listen(8)
while True:
    c, _ = s.accept()
    try:
        while True:
            d = c.recv(4096)
            if not d:
                break
            c.sendall(d)
    except OSError:
        pass
    c.close()
EOF

cat > "$W/udp_echo.py" <<'EOF'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", int(sys.argv[1])))
while True:
    d, a = s.recvfrom(4096)
    s.sendto(d, a)
EOF

Q_TCP=$((47700 + ($$ % 20)))
Q_UDP=$((47740 + ($$ % 20)))

python3 "$W/tcp_echo.py" "$Q_TCP" > "$W/tcp_echo.log" 2>&1 &
TCPECHO=$!
SRVPIDS="$SRVPIDS $TCPECHO"

python3 "$W/udp_echo.py" "$Q_UDP" > "$W/udp_echo.log" 2>&1 &
UDPECHO=$!
SRVPIDS="$SRVPIDS $UDPECHO"

sleep 0.3

kill -0 "$TCPECHO" 2>/dev/null || die "the tcp echo died at once: $(cat "$W/tcp_echo.log")"
kill -0 "$UDPECHO" 2>/dev/null || die "the udp echo died at once: $(cat "$W/udp_echo.log")"

# the daemons: the C daemon and the fork server, distinct ports

P_C=$((47800 + ($$ % 20)))
P_GO=$((47840 + ($$ % 20)))

SSH3C_PROTO=1 "$CSRV" -3 -l "127.0.0.1:$P_C" \
    -c "$W/cert.pem" -k "$W/key-cert.pem" -K "$W/authorized_keys" \
    > "$W/c-srv.log" 2>&1 < /dev/null &
SRVPIDS="$SRVPIDS $!"

env SSH3_LOG_FILE="$W/go-srv.log" "$GOBIN/ssh3-server" \
    -bind "127.0.0.1:$P_GO" -cert "$W/cert.pem" -key "$W/key-cert.pem" \
    -url-path /ssh3-term > "$W/go-srv.out" 2>&1 < /dev/null &
SRVPIDS="$SRVPIDS $!"

sleep 1

for p in $SRVPIDS; do
    kill -0 "$p" 2>/dev/null || die "a daemon died at the startup"
done

kill -0 "$SRVPIDS" 2>/dev/null || true

mkdir -p "$W/home/.ssh3"
printf '127.0.0.1:0/ssh3-term x509-certificate placeholder\n' > "$W/home/.ssh3/known_hosts"
printf "127.0.0.1:%s/ssh3-term x509-certificate %s\n" "$P_C" \
    "$(openssl x509 -in "$W/cert.pem" -outform DER | base64 -w0)" >> "$W/home/.ssh3/known_hosts"
printf "127.0.0.1:%s/ssh3-term x509-certificate %s\n" "$P_GO" \
    "$(openssl x509 -in "$W/cert.pem" -outform DER | base64 -w0)" >> "$W/home/.ssh3/known_hosts"

# the relay check: the connector sends the numbered lines to the bound
# port and counts the echoed bytes back (retried while the bind
# settles)

relay_check() { # $1 = the bound port
    i=0
    while [ "$i" -lt 10 ]; do

        python3 - "$1" <<'EOF' && return 0
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=10)
s.settimeout(10)
payload = b"".join(b"line-%03d\n" % i for i in range(50))
s.sendall(payload)
got = b""
while len(got) < len(payload):
    d = s.recv(4096)
    if not d:
        break
    got += d
sys.exit(0 if got == payload else 1)
EOF
        sleep 0.5
        i=$((i + 1))
    done

    return 1
}

# the datagram check: the numbered datagrams to the bound udp port,
# the echo counted back (the loopback loses none, the bound settles
# with the retries)

dg_check() { # $1 = the bound udp port
    i=0
    while [ "$i" -lt 10 ]; do

        python3 - "$1" <<'EOF' && return 0
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(1)
ok = 0
for i in range(20):
    msg = b"dg-%03d" % i
    s.sendto(msg, ("127.0.0.1", int(sys.argv[1])))
    try:
        d, _ = s.recvfrom(4096)
        if d == msg:
            ok += 1
    except socket.timeout:
        break  # the bind is not settled (or the relay is dead): the retry decides
sys.exit(0 if ok == 20 else 1)
EOF
        sleep 0.5
        i=$((i + 1))
    done

    return 1
}

PB=$((47900 + ($$ % 20)))   # the bound port of the leg 1
PB2=$((47940 + ($$ % 20)))  # the bound port of the leg 2
PB3=$((47980 + ($$ % 20)))  # the udp port of the leg 3
PB4=$((48020 + ($$ % 20)))  # the udp port of the leg 4

echo "== leg 1: the fork client -R tcp against the C daemon"

env SSH3_LOG_LEVEL=debug "$GOBIN/ssh3" -insecure -o StrictHostKeyChecking=no -privkey "$W/key.pem" \
    -R "127.0.0.1:$PB:127.0.0.1:$Q_TCP" "max@127.0.0.1:$P_C/ssh3-term" sleep 15 < /dev/null \
    > "$W/r1.out" 2>"$W/r1.err" &
SRVPIDS="$SRVPIDS $!"

sleep 1

kill -0 "$TCPECHO" 2>/dev/null && echo "   dbg: tcp echo alive" || echo "   dbg: tcp echo DEAD"
ss -tln 2>/dev/null | grep -q ":$PB " && echo "   dbg: the daemon bound $PB" || echo "   dbg: $PB NOT bound"
echo "   dbg: Q_TCP=$Q_TCP, echo log: [$(cat "$W/tcp_echo.log" 2>/dev/null)]"

if relay_check "$PB"; then
    pass "the fork -R relayed the round-trip (tcp)"
else
    fail "the fork -R leg: the relay did not come back ($PB)"
    echo "   dbg: r1.err: $(tail -2 "$W/r1.err" 2>/dev/null)"
    echo "   dbg: echo alive after: $(pgrep -fc tcp_echo.py 2>/dev/null)"
    ss -tlnp 2>/dev/null | grep ":47715 " || echo "   dbg: the echo port is gone"
fi

echo "== leg 2: the C client -R tcp against the fork server"

HOME="$W/home" "$CCLI" -i "$W/key.pem" -R "$PB2:127.0.0.1:$Q_TCP" \
    "max@127.0.0.1:$P_GO/ssh3-term" \
    > "$W/r2.out" 2>"$W/r2.err" &
SRVPIDS="$SRVPIDS $!"

sleep 1

if relay_check "$PB2"; then
    pass "the C -R relayed the round-trip (tcp)"
else
    fail "the C -R leg: the relay did not come back ($PB2): $(tail -1 "$W/r2.err")"
fi

echo "== leg 3: the C client udp:// forward (the datagrams) against the fork server"

HOME="$W/home" "$CCLI" -i "$W/key.pem" -L "udp://127.0.0.1:$PB3/127.0.0.1/$Q_UDP" \
    "max@127.0.0.1:$P_GO/ssh3-term" \
    > "$W/r3.out" 2>"$W/r3.err" &
SRVPIDS="$SRVPIDS $!"

sleep 1

if dg_check "$PB3"; then
    pass "the datagram forward rode the fork server (20/20)"
else
    fail "the datagram forward leg ($PB3): $(tail -1 "$W/r3.err")"
fi

echo "== leg 4: the fork client -R/udp against the C daemon"

"$GOBIN/ssh3" -insecure -o StrictHostKeyChecking=no -privkey "$W/key.pem" \
    -R "127.0.0.1:$PB4/udp:127.0.0.1:$Q_UDP" "max@127.0.0.1:$P_C/ssh3-term" sleep 15 < /dev/null \
    > "$W/r4.out" 2>"$W/r4.err" &
SRVPIDS="$SRVPIDS $!"

sleep 1

if dg_check "$PB4"; then
    pass "the fork -R/udp relayed the datagrams (20/20)"
else
    fail "the fork -R/udp leg ($PB4): $(tail -1 "$W/r4.err")"
fi

if [ "$FAILURES" -eq 0 ]; then
    echo "CROSS-REVERSE-E2E OK"
    exit 0
fi

echo "CROSS-REVERSE-E2E FAILED ($FAILURES)"
exit 1
