#!/bin/sh
# the h3 interop runner: RFC 9220 extended CONNECT (ssh3) over HTTP/3
#
#   1. our client (-3) -> the quic-go harness h3-server
#   2. the quic-go harness h3-client -> our server (-3)
#   3. our client (-3) -> our server (-3) (sanity)
#   4. the harness h3-client with an unsupported version -> our server
#      (-3): the request is rejected with 403 (version negotiation)
#   8. the harness session-client -> our server (-3): exec session
#   9. our client (-3 -C -S exec) -> the harness session-server
#  10. our client (-3 -C -S kill) -> the harness session-server
#  11. our client (-U user:pass, Basic) -> our server (-P passfile)
#  12. our client (-F tcp=@port) -> our server: direct-tcp forward
#  13. our client (-F udp=@port) -> our server: direct-udp forward
#  14. our client (-F tcp) -> the harness forward-server
#  15. the harness forward-client -> our server: direct-tcp forward
#  16. our client (-3 -J put|get) -> our server (-H): the sftp put
#      and get round trips of a 3 MiB random file, byte-exact
#  17. our client (-3 -J) -> the harness sftp-server: the C driver
#      against the go sftp subsystem (the pkg/sftp dialect)
#  18. the harness sftp-client -> our server: the go client against
#      the C jail
#  19. our client (-3 -C -S exec -X -e agent_probe) -> our server:
#      the agent forwarding, the probe lists and signs through the
#      real ssh-agent of the client side
#  20. our client (-X -e agent_probe) -> the harness agent-server
#  21. the harness agent-client (-cmd agent_probe) -> our server
#   5. our client (-3) -> our server (-3): after the 200 the client
#      opens a session channel (header + shell request + ping in one
#      send), the server confirms (91) and echoes the data (94)
#   6. our client (-3 -C -S exec) -> our server (-3): the exec
#      session, the command output and the 98 exit-status 0
#   7. our client (-3 -C -S pty) -> our server (-3): the pty session,
#      the resize to 100x40 and the size probe, then the KILL
#      signal (an interactive shell ignores TERM), the
#      98 exit-status 137
#   8. the quic-go session-client -> our server (-3): the exec
#      session driven by the go side, the 98 exit-status 0
#   9. our client (-3 -C -S exec) -> the quic-go session-server:
#      the exec session on the go side, the 98 exit-status 0
#  10. our client (-3 -C -S kill) -> the quic-go session-server:
#      the KILL signal right after the confirmation, the
#      98 exit-status 137
#  12. our client (-3 -C -F tcp=@19999) -> our server (-3): the
#      direct-tcp channel to the loopback tcp echo service, the
#      "s3-fwd-hello" marker plus 64 KiB round trip byte for byte
#  13. our client (-3 -C -F udp=@19998) -> our server (-3): the
#      direct-udp channel to the loopback udp echo service, 20
#      numbered datagrams of 1024 bytes round trip
#
# the verdicts come from the stdout protocol of the runners:
#   INTEROP-H3-STATUS 200    (the client side)
#   INTEROP-H3-CONNECT-OK    (the C server side)
#   INTEROP-AUTH-OK          (the C server side, the Basic credentials)
#   INTEROP-FWD-TCP-OK       (the C client side, the TCP forward verdict)
#   INTEROP-FWD-UDP-OK       (the C client side, the UDP forward verdict)
#   INTEROP-FWD-TCP-OPEN     (the C server side, the target connected)
#   INTEROP-GO-FWD-TCP-OPEN  (the harness side, the target connected)
#   INTEROP-CHANNEL-OK       (the C client side, the echoed ping)
#   INTEROP-CHANNEL-ACCEPT   (the C server side, the channel accepted)
#   INTEROP-EXEC-OK          (the C client side, the exec verdict)
#   INTEROP-KILL-OK          (the C client side, the kill verdict)
#   INTEROP-SESSION-EXEC     (the C server side, the exec accepted)
#   INTEROP-SESSION-EXIT     (the C server side, the session exit code)
#   INTEROP-GO-EXEC-OK       (the go session-client side, the exec verdict)
#   INTEROP-GO-SESSION-EXEC  (the go session-server side, the exec accepted)
#   INTEROP-GO-SESSION-EXIT  (the go session-server side, the session exit code)
#   INTEROP-PTY-SIGNAL-OK    (the C client side, the pty verdict)
#   INTEROP-FWD-TCP-OK       (the C client side, the tcp forward echo)
#   INTEROP-FWD-UDP-OK       (the C client side, the udp forward echo)
#   INTEROP-FWD-TCP-OPEN     (the C server side, the tcp target connected)
#   INTEROP-FWD-UDP-OPEN     (the C server side, the udp target socket up)
#
# usage: interop/run-h3.sh
# requires: the C runners (cmake --build build/linux-release), a Go
# toolchain >= 1.26 (GO overrides $HOME/opt/go1.27.1/bin/go), openssl
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD=${BUILD:-$ROOT/build/linux-release}
GO=${GO:-$HOME/opt/go1.27.1/bin/go}
HARNESS=${HARNESS:-/tmp/h3harness}

die() {
    echo "run-h3: $1" >&2
    exit 1
}

[ -x "$BUILD/s3interop_server" ] || die "s3interop_server is not built (cmake --build $BUILD)"
[ -x "$BUILD/s3interop_client" ] || die "s3interop_client is not built"

mkdir -p "$BUILD/interop"

(cd "$ROOT/interop/quic-go" && "$GO" build -o "$HARNESS" .) || die "go build failed"

CERT=$BUILD/interop/cert.pem
KEY=$BUILD/interop/key.pem

if [ ! -f "$CERT" ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$KEY" -out "$CERT" -days 30 \
        -subj "/CN=s3interop" 2>/dev/null || die "openssl req failed"
fi

WORK=$(mktemp -d /tmp/s3h3.XXXXXX)
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

# the loopback echo services of the forward scenarios (12, 13): one
# python script, the mode argument picks tcp:19999 or udp:19998; the
# readiness line greps like the INTEROP-LISTEN one above

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

stop_echo() {
    if [ -f "$WORK/echo-tcp.pid" ]; then
        kill "$(cat "$WORK/echo-tcp.pid")" 2>/dev/null
    fi

    if [ -f "$WORK/echo-udp.pid" ]; then
        kill "$(cat "$WORK/echo-udp.pid")" 2>/dev/null
    fi
}

echo "== scenario 1: C client (-3) -> quic-go h3-server"

setsid nohup "$HARNESS" -h3-server -addr 127.0.0.1:0 -cert "$CERT" -key "$KEY" \
    > "$WORK/go-srv.log" 2>&1 < /dev/null &

if wait_listen "$WORK/go-srv.log"; then
    PORT=$(port_of "$WORK/go-srv.log")

    if timeout 30 "$BUILD/s3interop_client" -3 -a "127.0.0.1:$PORT" -t 20000 \
        > "$WORK/c-cli.log" 2>&1 \
        && grep -q "INTEROP-H3-STATUS 200" "$WORK/c-cli.log"; then
        echo "   PASS (extended CONNECT answered 200)"
    else
        echo "   FAIL"
        tail -5 "$WORK/c-cli.log" | sed 's/^/   /'
        FAILURES=$((FAILURES + 1))
    fi

else
    echo "   FAIL: the harness h3-server did not start"
    FAILURES=$((FAILURES + 1))
fi

pkill -f "h3harness -h3-server" 2>/dev/null

echo "== scenario 2: quic-go h3-client -> C server (-3)"

setsid nohup "$BUILD/s3interop_server" -3 -l 127.0.0.1:0 -c "$CERT" -k "$KEY" \
    > "$WORK/c-srv.log" 2>&1 < /dev/null &

if wait_listen "$WORK/c-srv.log"; then
    PORT=$(port_of "$WORK/c-srv.log")

    if timeout 30 "$HARNESS" -h3-client -a "127.0.0.1:$PORT" -timeout 10s \
        > "$WORK/go-cli.log" 2>&1 \
        && grep -q "INTEROP-H3-STATUS 200" "$WORK/go-cli.log" \
        && grep -q "INTEROP-H3-CONNECT-OK" "$WORK/c-srv.log"; then
        echo "   PASS (extended CONNECT answered 200)"
    else
        echo "   FAIL"
        tail -5 "$WORK/go-cli.log" | sed 's/^/   /'
        tail -5 "$WORK/c-srv.log" | sed 's/^/   /'
        FAILURES=$((FAILURES + 1))
    fi

else
    echo "   FAIL: the C server did not start"
    FAILURES=$((FAILURES + 1))
fi

pkill -f "s3interop_server -3" 2>/dev/null

echo "== scenario 3: C client (-3) -> C server (-3) (sanity)"

setsid nohup "$BUILD/s3interop_server" -3 -l 127.0.0.1:0 -c "$CERT" -k "$KEY" \
    > "$WORK/cc-srv.log" 2>&1 < /dev/null &

if wait_listen "$WORK/cc-srv.log"; then
    PORT=$(port_of "$WORK/cc-srv.log")

    if timeout 30 "$BUILD/s3interop_client" -3 -a "127.0.0.1:$PORT" -t 20000 \
        > "$WORK/cc-cli.log" 2>&1 \
        && grep -q "INTEROP-H3-STATUS 200" "$WORK/cc-cli.log" \
        && grep -q "INTEROP-H3-CONNECT-OK" "$WORK/cc-srv.log"; then
        echo "   PASS (extended CONNECT answered 200)"
    else
        echo "   FAIL"
        tail -5 "$WORK/cc-cli.log" | sed 's/^/   /'
        tail -5 "$WORK/cc-srv.log" | sed 's/^/   /'
        FAILURES=$((FAILURES + 1))
    fi

else
    echo "   FAIL: the C server did not start"
    FAILURES=$((FAILURES + 1))
fi

pkill -f "s3interop_server -3" 2>/dev/null

echo "== scenario 4: quic-go h3-client (unsupported version) -> C server (-3), expect 403"

setsid nohup "$BUILD/s3interop_server" -3 -l 127.0.0.1:0 -c "$CERT" -k "$KEY" \
    > "$WORK/cc-rej-srv.log" 2>&1 < /dev/null &

if wait_listen "$WORK/cc-rej-srv.log"; then
    PORT=$(port_of "$WORK/cc-rej-srv.log")

    if timeout 30 "$HARNESS" -h3-client -bad-ua -a "127.0.0.1:$PORT" -timeout 10s \
        > "$WORK/go-rej-cli.log" 2>&1 \
        && grep -q "INTEROP-H3-STATUS 403" "$WORK/go-rej-cli.log" \
        && grep -q "INTEROP-H3-REJECT code=403" "$WORK/cc-rej-srv.log"; then
        echo "   PASS (unsupported version rejected with 403)"
    else
        echo "   FAIL"
        tail -5 "$WORK/go-rej-cli.log" | sed 's/^/   /'
        tail -5 "$WORK/cc-rej-srv.log" | sed 's/^/   /'
        FAILURES=$((FAILURES + 1))
    fi

else
    echo "   FAIL: the C server did not start"
    FAILURES=$((FAILURES + 1))
fi

pkill -f "s3interop_server -3" 2>/dev/null

echo "== scenario 5: C client (-3) -> C server (-3), session channel echo"

setsid nohup "$BUILD/s3interop_server" -3 -l 127.0.0.1:0 -c "$CERT" -k "$KEY" \
    > "$WORK/ch-srv.log" 2>&1 < /dev/null &

if wait_listen "$WORK/ch-srv.log"; then
    PORT=$(port_of "$WORK/ch-srv.log")

    if timeout 30 "$BUILD/s3interop_client" -3 -C -a "127.0.0.1:$PORT" -t 20000 \
        > "$WORK/ch-cli.log" 2>&1 \
        && grep -q "INTEROP-CHANNEL-OK" "$WORK/ch-cli.log" \
        && grep -q "INTEROP-CHANNEL-ACCEPT" "$WORK/ch-srv.log"; then
        echo "   PASS (session channel confirmed and echoed)"
    else
        echo "   FAIL"
        tail -5 "$WORK/ch-cli.log" | sed 's/^/   /'
        tail -5 "$WORK/ch-srv.log" | sed 's/^/   /'
        FAILURES=$((FAILURES + 1))
    fi

else
    echo "   FAIL: the C server did not start"
    FAILURES=$((FAILURES + 1))
fi

pkill -f "s3interop_server -3" 2>/dev/null

echo "== scenario 6: C client (-3 -C -S exec) -> C server (-3), exec session"

setsid nohup "$BUILD/s3interop_server" -3 -l 127.0.0.1:0 -c "$CERT" -k "$KEY" \
    > "$WORK/exec-srv.log" 2>&1 < /dev/null &

if wait_listen "$WORK/exec-srv.log"; then
    PORT=$(port_of "$WORK/exec-srv.log")

    if timeout 30 "$BUILD/s3interop_client" -3 -C -S exec -a "127.0.0.1:$PORT" -t 20000 \
        > "$WORK/exec-cli.log" 2>&1 \
        && grep -q "INTEROP-EXEC-OK exit=0" "$WORK/exec-cli.log" \
        && grep -q "INTEROP-SESSION-EXIT code=0" "$WORK/exec-srv.log"; then
        echo "   PASS (exec session: command output and exit 0)"
    else
        echo "   FAIL"
        tail -5 "$WORK/exec-cli.log" | sed 's/^/   /'
        tail -5 "$WORK/exec-srv.log" | sed 's/^/   /'
        FAILURES=$((FAILURES + 1))
    fi

else
    echo "   FAIL: the C server did not start"
    FAILURES=$((FAILURES + 1))
fi

pkill -f "s3interop_server -3" 2>/dev/null

echo "== scenario 7: C client (-3 -C -S pty) -> C server (-3), pty + signal session"

setsid nohup "$BUILD/s3interop_server" -3 -l 127.0.0.1:0 -c "$CERT" -k "$KEY" \
    > "$WORK/pty-srv.log" 2>&1 < /dev/null &

if wait_listen "$WORK/pty-srv.log"; then
    PORT=$(port_of "$WORK/pty-srv.log")

    if timeout 30 "$BUILD/s3interop_client" -3 -C -S pty -a "127.0.0.1:$PORT" -t 20000 \
        > "$WORK/pty-cli.log" 2>&1 \
        && grep -q "INTEROP-PTY-SIGNAL-OK exit=137" "$WORK/pty-cli.log" \
        && grep -q "INTEROP-SESSION-EXIT code=137" "$WORK/pty-srv.log"; then
        echo "   PASS (pty session: resize, size probe, KILL, exit 137)"
    else
        echo "   FAIL"
        tail -5 "$WORK/pty-cli.log" | sed 's/^/   /'
        tail -5 "$WORK/pty-srv.log" | sed 's/^/   /'
        FAILURES=$((FAILURES + 1))
    fi

else
    echo "   FAIL: the C server did not start"
    FAILURES=$((FAILURES + 1))
fi

pkill -f "s3interop_server -3" 2>/dev/null

echo "== scenario 8: quic-go session-client -> C server (-3), exec session"

setsid nohup "$BUILD/s3interop_server" -3 -l 127.0.0.1:0 -c "$CERT" -k "$KEY" \
    > "$WORK/gc-srv.log" 2>&1 < /dev/null &

if wait_listen "$WORK/gc-srv.log"; then
    PORT=$(port_of "$WORK/gc-srv.log")

    if timeout 30 "$HARNESS" -h3-session-client -cmd "printf s3-exec-ok" \
        -a "127.0.0.1:$PORT" -timeout 10s \
        > "$WORK/gc-cli.log" 2>&1 \
        && grep -q "INTEROP-GO-EXEC-OK exit=0" "$WORK/gc-cli.log" \
        && grep -q "INTEROP-SESSION-EXIT code=0" "$WORK/gc-srv.log"; then
        echo "   PASS (exec session: the go client against the C server)"
    else
        echo "   FAIL"
        tail -5 "$WORK/gc-cli.log" | sed 's/^/   /'
        tail -5 "$WORK/gc-srv.log" | sed 's/^/   /'
        FAILURES=$((FAILURES + 1))
    fi

else
    echo "   FAIL: the C server did not start"
    FAILURES=$((FAILURES + 1))
fi

pkill -f "s3interop_server -3" 2>/dev/null

echo "== scenario 9: C client (-3 -C -S exec) -> quic-go session-server, exec session"

setsid nohup "$HARNESS" -h3-session-server -addr 127.0.0.1:0 -cert "$CERT" -key "$KEY" \
    > "$WORK/gs-srv.log" 2>&1 < /dev/null &

if wait_listen "$WORK/gs-srv.log"; then
    PORT=$(port_of "$WORK/gs-srv.log")

    if timeout 30 "$BUILD/s3interop_client" -3 -C -S exec -a "127.0.0.1:$PORT" -t 20000 \
        > "$WORK/cexec-cli.log" 2>&1 \
        && grep -q "INTEROP-EXEC-OK exit=0" "$WORK/cexec-cli.log" \
        && grep -q "INTEROP-GO-SESSION-EXIT code=0" "$WORK/gs-srv.log"; then
        echo "   PASS (exec session: the C client against the go server)"
    else
        echo "   FAIL"
        tail -5 "$WORK/cexec-cli.log" | sed 's/^/   /'
        tail -5 "$WORK/gs-srv.log" | sed 's/^/   /'
        FAILURES=$((FAILURES + 1))
    fi

else
    echo "   FAIL: the harness h3-session-server did not start"
    FAILURES=$((FAILURES + 1))
fi

pkill -f "h3-session-server" 2>/dev/null

echo "== scenario 10: C client (-3 -C -S kill) -> quic-go session-server, kill session"

setsid nohup "$HARNESS" -h3-session-server -addr 127.0.0.1:0 -cert "$CERT" -key "$KEY" \
    > "$WORK/gkill-srv.log" 2>&1 < /dev/null &

if wait_listen "$WORK/gkill-srv.log"; then
    PORT=$(port_of "$WORK/gkill-srv.log")

    if timeout 30 "$BUILD/s3interop_client" -3 -C -S kill -a "127.0.0.1:$PORT" -t 20000 \
        > "$WORK/ckill-cli.log" 2>&1 \
        && grep -q "INTEROP-KILL-OK exit=137" "$WORK/ckill-cli.log" \
        && grep -q "INTEROP-GO-SESSION-EXIT code=137" "$WORK/gkill-srv.log"; then
        echo "   PASS (kill session: KILL after the confirmation, exit 137)"
    else
        echo "   FAIL"
        tail -5 "$WORK/ckill-cli.log" | sed 's/^/   /'
        tail -5 "$WORK/gkill-srv.log" | sed 's/^/   /'
        FAILURES=$((FAILURES + 1))
    fi

else
    echo "   FAIL: the harness h3-session-server did not start"
    FAILURES=$((FAILURES + 1))
fi

pkill -f "h3-session-server" 2>/dev/null

echo "== scenario 11: C client (Basic auth) -> C server (-P passfile), exec session"

printf 'tester:secret123\n' > "$WORK/pwfile"

setsid nohup "$BUILD/s3interop_server" -3 -P "$WORK/pwfile" -l 127.0.0.1:0 -c "$CERT" -k "$KEY" \
    > "$WORK/auth-srv.log" 2>&1 < /dev/null &

if wait_listen "$WORK/auth-srv.log"; then
    PORT=$(port_of "$WORK/auth-srv.log")

    if timeout 30 "$BUILD/s3interop_client" -3 -C -S exec -U tester:secret123 \
        -a "127.0.0.1:$PORT" -t 20000 \
        > "$WORK/auth-cli.log" 2>&1 \
        && grep -q "INTEROP-AUTH-OK user=tester" "$WORK/auth-srv.log" \
        && grep -q "INTEROP-EXEC-OK exit=0" "$WORK/auth-cli.log"; then
        echo "   PASS (Basic credentials accepted, exec session ran)"
    else
        echo "   FAIL"
        tail -5 "$WORK/auth-cli.log" | sed 's/^/   /'
        tail -5 "$WORK/auth-srv.log" | sed 's/^/   /'
        FAILURES=$((FAILURES + 1))
    fi

else
    echo "   FAIL: the C server did not start"
    FAILURES=$((FAILURES + 1))
fi

pkill -f "s3interop_server -3" 2>/dev/null

echo "== scenario 12: C client (-3 -C -F tcp=@19999) -> C server (-3), direct-tcp forward"

start_echo tcp

if wait_echo tcp; then

    setsid nohup "$BUILD/s3interop_server" -3 -l 127.0.0.1:0 -c "$CERT" -k "$KEY" \
        > "$WORK/fwd-tcp-srv.log" 2>&1 < /dev/null &

    if wait_listen "$WORK/fwd-tcp-srv.log"; then
        PORT=$(port_of "$WORK/fwd-tcp-srv.log")

        if timeout 30 "$BUILD/s3interop_client" -3 -C -F tcp=@19999 -a "127.0.0.1:$PORT" -t 20000 \
            > "$WORK/fwd-tcp-cli.log" 2>&1 \
            && grep -q "INTEROP-FWD-TCP-OK bytes=65548" "$WORK/fwd-tcp-cli.log" \
            && grep -q "INTEROP-FWD-TCP-OPEN target=127.0.0.1:19999" "$WORK/fwd-tcp-srv.log"; then
            echo "   PASS (direct-tcp: hello + 64 KiB echoed through the tunnel)"
        else
            echo "   FAIL"
            tail -5 "$WORK/fwd-tcp-cli.log" | sed 's/^/   /'
            tail -5 "$WORK/fwd-tcp-srv.log" | sed 's/^/   /'
            FAILURES=$((FAILURES + 1))
        fi

    else
        echo "   FAIL: the C server did not start"
        FAILURES=$((FAILURES + 1))
    fi

    pkill -f "s3interop_server -3" 2>/dev/null

else
    echo "   FAIL: the tcp echo service did not start"
    cat "$WORK/echo-tcp.log" | sed 's/^/   /'
    FAILURES=$((FAILURES + 1))
fi

echo "== scenario 13: C client (-3 -C -F udp=@19998) -> C server (-3), direct-udp forward"

start_echo udp

if wait_echo udp; then

    setsid nohup "$BUILD/s3interop_server" -3 -l 127.0.0.1:0 -c "$CERT" -k "$KEY" \
        > "$WORK/fwd-udp-srv.log" 2>&1 < /dev/null &

    if wait_listen "$WORK/fwd-udp-srv.log"; then
        PORT=$(port_of "$WORK/fwd-udp-srv.log")

        if timeout 30 "$BUILD/s3interop_client" -3 -C -F udp=@19998 -a "127.0.0.1:$PORT" -t 20000 \
            > "$WORK/fwd-udp-cli.log" 2>&1 \
            && grep -q "INTEROP-FWD-UDP-OK count=20" "$WORK/fwd-udp-cli.log" \
            && grep -q "INTEROP-FWD-UDP-OPEN target=127.0.0.1:19998" "$WORK/fwd-udp-srv.log"; then
            echo "   PASS (direct-udp: 20 datagrams echoed through the tunnel)"
        else
            echo "   FAIL"
            tail -5 "$WORK/fwd-udp-cli.log" | sed 's/^/   /'
            tail -5 "$WORK/fwd-udp-srv.log" | sed 's/^/   /'
            FAILURES=$((FAILURES + 1))
        fi

    else
        echo "   FAIL: the C server did not start"
        FAILURES=$((FAILURES + 1))
    fi

    pkill -f "s3interop_server -3" 2>/dev/null

else
    echo "   FAIL: the udp echo service did not start"
    cat "$WORK/echo-udp.log" | sed 's/^/   /'
    FAILURES=$((FAILURES + 1))
fi

stop_echo

echo "== scenario 14: C client (-3 -C -F tcp=@19999) -> quic-go forward-server"

start_echo tcp

if wait_echo tcp; then

    setsid nohup "$HARNESS" -h3-forward-server -addr 127.0.0.1:0 -cert "$CERT" -key "$KEY" \
        > "$WORK/gfwd-srv.log" 2>&1 < /dev/null &

    if wait_listen "$WORK/gfwd-srv.log"; then
        PORT=$(port_of "$WORK/gfwd-srv.log")

        if timeout 30 "$BUILD/s3interop_client" -3 -C -F tcp=@19999 -a "127.0.0.1:$PORT" -t 20000 \
            > "$WORK/gfwd-cli.log" 2>&1 \
            && grep -q "INTEROP-FWD-TCP-OK bytes=65548" "$WORK/gfwd-cli.log" \
            && grep -q "INTEROP-GO-FWD-TCP-OPEN target=127.0.0.1:19999" "$WORK/gfwd-srv.log"; then
            echo "   PASS (direct-tcp: the C client through the go server)"
        else
            echo "   FAIL"
            tail -5 "$WORK/gfwd-cli.log" | sed 's/^/   /'
            tail -5 "$WORK/gfwd-srv.log" | sed 's/^/   /'
            FAILURES=$((FAILURES + 1))
        fi

    else
        echo "   FAIL: the harness forward-server did not start"
        FAILURES=$((FAILURES + 1))
    fi

    pkill -f "h3-forward-server" 2>/dev/null

else
    echo "   FAIL: the tcp echo service did not start"
    FAILURES=$((FAILURES + 1))
fi

stop_echo

echo "== scenario 15: quic-go forward-client -> C server (-3), direct-tcp forward"

start_echo tcp

if wait_echo tcp; then

    setsid nohup "$BUILD/s3interop_server" -3 -l 127.0.0.1:0 -c "$CERT" -k "$KEY" \
        > "$WORK/gfwd2-srv.log" 2>&1 < /dev/null &

    if wait_listen "$WORK/gfwd2-srv.log"; then
        PORT=$(port_of "$WORK/gfwd2-srv.log")

        setsid nohup "$HARNESS" -h3-forward-client -fwd-tcp "13456/127.0.0.1@19999" \
            -a "127.0.0.1:$PORT" -timeout 15s > "$WORK/gfwd2-cli.log" 2>&1 < /dev/null &

        sleep 2

        # the greeting rides the go listener through the tunnel to the echo

        if printf 's3-gofwd-hello\n' | timeout 10 nc -q 1 127.0.0.1 13456 \
            > "$WORK/gfwd2-pipe.out" 2>/dev/null \
            && grep -q "s3-gofwd-hello" "$WORK/gfwd2-pipe.out" \
            && grep -q "INTEROP-FWD-TCP-OPEN target=127.0.0.1:19999" "$WORK/gfwd2-srv.log"; then
            echo "   PASS (direct-tcp: the go client through the C server)"
        else
            echo "   FAIL"
            tail -5 "$WORK/gfwd2-pipe.out" 2>/dev/null | sed 's/^/   /'
            tail -5 "$WORK/gfwd2-cli.log" | sed 's/^/   /'
            tail -5 "$WORK/gfwd2-srv.log" | sed 's/^/   /'
            FAILURES=$((FAILURES + 1))
        fi

        pkill -f "h3-forward-client" 2>/dev/null

    else
        echo "   FAIL: the C server did not start"
        FAILURES=$((FAILURES + 1))
    fi

    pkill -f "s3interop_server -3" 2>/dev/null

else
    echo "   FAIL: the tcp echo service did not start"
    FAILURES=$((FAILURES + 1))
fi

stop_echo

# == the wave 2 scenarios: the sftp transfers and the agent forwarding ==
#
#  16. our client (-3 -J put|get) -> our server (-H jail): the sftp
#      put and get round trips of a 3 MiB random file, byte-exact
#  17. our client (-3 -J) -> the harness sftp-server: the C driver
#      against the go sftp subsystem (pkg/sftp wire dialect)
#  18. the harness sftp-client -> our server: the go sftp client
#      against the C jail
#  19. our client (-3 -C -S exec -X -e agent_probe) -> our server:
#      the agent forwarding, the probe lists and signs through the
#      real ssh-agent of the client side
#  20. our client (-X -e agent_probe) -> the harness agent-server
#  21. the harness agent-client (-cmd agent_probe) -> our server

# the ssh-agent probe binary of the Go fork (the ssh-agent protocol
# against the bridged socket: lists the identities and signs)

PROBE=$WORK/agent_probe

(cd "$ROOT/../ssh3" && "$GO" build -o "$PROBE" ./internal/interop/agent_probe) \
    || die "agent_probe build failed"

echo "== scenario 16: C client (-3 -J put|get) -> C server (-H), sftp round trip"

mkdir -p "$WORK/sftp-cc"

dd if=/dev/urandom of="$WORK/sftp-src.bin" bs=1048576 count=3 2>/dev/null

setsid nohup "$BUILD/s3interop_server" -3 -H "$WORK/sftp-cc" -l 127.0.0.1:0 -c "$CERT" -k "$KEY" \
    > "$WORK/sftp-srv.log" 2>&1 < /dev/null &

if wait_listen "$WORK/sftp-srv.log"; then
    PORT=$(port_of "$WORK/sftp-srv.log")

    if timeout 30 "$BUILD/s3interop_client" -3 -J "put:$WORK/sftp-src.bin:s3-p5-cc.bin" \
        -a "127.0.0.1:$PORT" -t 30000 \
        > "$WORK/sftp-put.log" 2>&1 \
        && cmp -s "$WORK/sftp-cc/s3-p5-cc.bin" "$WORK/sftp-src.bin" \
        && grep -q "INTEROP-SFTP-OK mode=put" "$WORK/sftp-put.log"; then
        echo "   PASS (put: 3 MiB uploaded byte-exact)"
    else
        echo "   FAIL (put)"
        tail -5 "$WORK/sftp-put.log" | sed 's/^/   /'
        FAILURES=$((FAILURES + 1))
    fi

    if timeout 30 "$BUILD/s3interop_client" -3 -J "get:$WORK/sftp-dst.bin:s3-p5-cc.bin" \
        -a "127.0.0.1:$PORT" -t 30000 \
        > "$WORK/sftp-get.log" 2>&1 \
        && cmp -s "$WORK/sftp-dst.bin" "$WORK/sftp-src.bin" \
        && grep -q "INTEROP-SFTP-OK mode=get" "$WORK/sftp-get.log"; then
        echo "   PASS (get: downloaded byte-exact, verify checksum on)"
    else
        echo "   FAIL (get)"
        tail -5 "$WORK/sftp-get.log" | sed 's/^/   /'
        FAILURES=$((FAILURES + 1))
    fi

else
    echo "   FAIL: the C server did not start"
    FAILURES=$((FAILURES + 1))
fi

pkill -f "s3interop_server -3" 2>/dev/null

echo "== scenario 17: C client (-3 -J put|get) -> harness sftp-server"

mkdir -p "$WORK/sftp-go"

cp "$WORK/sftp-src.bin" "$WORK/sftp-go-src.bin"

setsid nohup env HOME="$WORK/sftp-go" "$HARNESS" -h3-sftp-server -addr 127.0.0.1:0 \
    -cert "$CERT" -key "$KEY" > "$WORK/gsftp-srv.log" 2>&1 < /dev/null &

if wait_listen "$WORK/gsftp-srv.log"; then
    PORT=$(port_of "$WORK/gsftp-srv.log")

    if timeout 30 "$BUILD/s3interop_client" -3 -J "put:$WORK/sftp-src.bin:go-p5.bin" \
        -a "127.0.0.1:$PORT" -t 30000 \
        > "$WORK/gsftp-put.log" 2>&1 \
        && cmp -s "$WORK/sftp-go/go-p5.bin" "$WORK/sftp-src.bin" \
        && grep -q "INTEROP-SFTP-OK mode=put" "$WORK/gsftp-put.log"; then
        echo "   PASS (put: the C driver against the go sftp subsystem)"
    else
        echo "   FAIL (put)"
        tail -5 "$WORK/gsftp-put.log" | sed 's/^/   /'
        tail -5 "$WORK/gsftp-srv.log" | sed 's/^/   /'
        FAILURES=$((FAILURES + 1))
    fi

    if timeout 30 "$BUILD/s3interop_client" -3 -J "get:$WORK/gsftp-dst.bin:go-p5.bin" \
        -a "127.0.0.1:$PORT" -t 30000 \
        > "$WORK/gsftp-get.log" 2>&1 \
        && cmp -s "$WORK/gsftp-dst.bin" "$WORK/sftp-src.bin" \
        && grep -q "INTEROP-SFTP-OK mode=get" "$WORK/gsftp-get.log"; then
        echo "   PASS (get: downloaded byte-exact from the go subsystem)"
    else
        echo "   FAIL (get)"
        tail -5 "$WORK/gsftp-get.log" | sed 's/^/   /'
        FAILURES=$((FAILURES + 1))
    fi

else
    echo "   FAIL: the harness sftp-server did not start"
    FAILURES=$((FAILURES + 1))
fi

pkill -f "h3-sftp-server" 2>/dev/null

echo "== scenario 18: harness sftp-client -> C server (-H), sftp round trip"

mkdir -p "$WORK/sftp-gc"

dd if=/dev/urandom of="$WORK/sftp-gc-src.bin" bs=1048576 count=2 2>/dev/null

setsid nohup "$BUILD/s3interop_server" -3 -H "$WORK/sftp-gc" -l 127.0.0.1:0 -c "$CERT" -k "$KEY" \
    > "$WORK/gc-sftp-srv.log" 2>&1 < /dev/null &

if wait_listen "$WORK/gc-sftp-srv.log"; then
    PORT=$(port_of "$WORK/gc-sftp-srv.log")

    if timeout 30 "$HARNESS" -h3-sftp-client -sftp-op "put:$WORK/sftp-gc-src.bin:gc-p5.bin" \
        -a "127.0.0.1:$PORT" -timeout 20s \
        > "$WORK/gc-sftp-put.log" 2>&1 \
        && cmp -s "$WORK/sftp-gc/gc-p5.bin" "$WORK/sftp-gc-src.bin" \
        && grep -q "SFTP-GO-CLIENT-DONE op=put" "$WORK/gc-sftp-put.log"; then
        echo "   PASS (put: the go client against the C jail)"
    else
        echo "   FAIL (put)"
        tail -5 "$WORK/gc-sftp-put.log" | sed 's/^/   /'
        tail -5 "$WORK/gc-sftp-srv.log" | sed 's/^/   /'
        FAILURES=$((FAILURES + 1))
    fi

    if timeout 30 "$HARNESS" -h3-sftp-client -sftp-op "get:$WORK/sftp-gc-dst.bin:gc-p5.bin" \
        -a "127.0.0.1:$PORT" -timeout 20s \
        > "$WORK/gc-sftp-get.log" 2>&1 \
        && cmp -s "$WORK/sftp-gc-dst.bin" "$WORK/sftp-gc-src.bin" \
        && grep -q "SFTP-GO-CLIENT-DONE op=get" "$WORK/gc-sftp-get.log"; then
        echo "   PASS (get: downloaded byte-exact from the C jail)"
    else
        echo "   FAIL (get)"
        tail -5 "$WORK/gc-sftp-get.log" | sed 's/^/   /'
        FAILURES=$((FAILURES + 1))
    fi

else
    echo "   FAIL: the C server did not start"
    FAILURES=$((FAILURES + 1))
fi

pkill -f "s3interop_server -3" 2>/dev/null

echo "== scenario 19: C client (-X -e agent_probe) -> C server, agent forwarding"

if [ -S "${SSH_AUTH_SOCK:-}" ]; then
    AGENT_ENV_SOCK=$SSH_AUTH_SOCK
else
    # the throwaway agent of the scenario: one fresh ed25519 key

    ssh-keygen -t ed25519 -N "" -f "$WORK/agkey" -C s3interop 2>/dev/null \
        || die "ssh-keygen failed"

    eval "$(ssh-agent -s)" > /dev/null
    ssh-add "$WORK/agkey" 2>/dev/null || die "ssh-add failed"

    AGENT_ENV_SOCK=$SSH_AUTH_SOCK
fi

setsid nohup "$BUILD/s3interop_server" -3 -l 127.0.0.1:0 -c "$CERT" -k "$KEY" \
    > "$WORK/ag-srv.log" 2>&1 < /dev/null &

if wait_listen "$WORK/ag-srv.log"; then
    PORT=$(port_of "$WORK/ag-srv.log")

    if SSH_AUTH_SOCK="$AGENT_ENV_SOCK" timeout 30 \
        "$BUILD/s3interop_client" -3 -C -S exec -X -e "$PROBE" \
        -a "127.0.0.1:$PORT" -t 20000 \
        > "$WORK/ag-cli.log" 2>&1 \
        && grep -q "INTEROP-EXEC-OK exit=0" "$WORK/ag-cli.log" \
        && grep -q "INTEROP-AGENT-BRIDGE" "$WORK/ag-cli.log" \
        && grep -q "INTEROP-AGENT-READY sock=" "$WORK/ag-srv.log"; then
        echo "   PASS (agent: the probe listed and signed through the tunnel)"
    else
        echo "   FAIL"
        tail -8 "$WORK/ag-cli.log" | sed 's/^/   /'
        tail -5 "$WORK/ag-srv.log" | sed 's/^/   /'
        FAILURES=$((FAILURES + 1))
    fi

else
    echo "   FAIL: the C server did not start"
    FAILURES=$((FAILURES + 1))
fi

pkill -f "s3interop_server -3" 2>/dev/null

echo "== scenario 20: C client (-X -e agent_probe) -> harness agent-server"

setsid nohup "$HARNESS" -h3-agent-server -addr 127.0.0.1:0 -cert "$CERT" -key "$KEY" \
    > "$WORK/gag-srv.log" 2>&1 < /dev/null &

if wait_listen "$WORK/gag-srv.log"; then
    PORT=$(port_of "$WORK/gag-srv.log")

    if SSH_AUTH_SOCK="$AGENT_ENV_SOCK" timeout 30 \
        "$BUILD/s3interop_client" -3 -C -S exec -X -e "$PROBE" \
        -a "127.0.0.1:$PORT" -t 20000 \
        > "$WORK/gag-cli.log" 2>&1 \
        && grep -q "INTEROP-EXEC-OK exit=0" "$WORK/gag-cli.log" \
        && grep -q "AGENT-GO-SOCKET-READY sock=" "$WORK/gag-srv.log"; then
        echo "   PASS (agent: the C client through the go agent-server)"
    else
        echo "   FAIL"
        tail -8 "$WORK/gag-cli.log" | sed 's/^/   /'
        tail -5 "$WORK/gag-srv.log" | sed 's/^/   /'
        FAILURES=$((FAILURES + 1))
    fi

else
    echo "   FAIL: the harness agent-server did not start"
    FAILURES=$((FAILURES + 1))
fi

pkill -f "h3-agent-server" 2>/dev/null

echo "== scenario 21: harness agent-client (-cmd agent_probe) -> C server"

setsid nohup "$BUILD/s3interop_server" -3 -l 127.0.0.1:0 -c "$CERT" -k "$KEY" \
    > "$WORK/cag-srv.log" 2>&1 < /dev/null &

if wait_listen "$WORK/cag-srv.log"; then
    PORT=$(port_of "$WORK/cag-srv.log")

    if SSH_AUTH_SOCK="$AGENT_ENV_SOCK" timeout 30 \
        "$HARNESS" -h3-agent-client -cmd "$PROBE" \
        -a "127.0.0.1:$PORT" -timeout 15s \
        > "$WORK/cag-cli.log" 2>&1 \
        && grep -q "INTEROP-GO-EXEC-OK exit=0" "$WORK/cag-cli.log" \
        && grep -q "AGENT-GO-BRIDGE" "$WORK/cag-cli.log" \
        && grep -q "INTEROP-AGENT-READY sock=" "$WORK/cag-srv.log"; then
        echo "   PASS (agent: the go client through the C agent bridge)"
    else
        echo "   FAIL"
        tail -8 "$WORK/cag-cli.log" | sed 's/^/   /'
        tail -5 "$WORK/cag-srv.log" | sed 's/^/   /'
        FAILURES=$((FAILURES + 1))
    fi

else
    echo "   FAIL: the C server did not start"
    FAILURES=$((FAILURES + 1))
fi

pkill -f "s3interop_server -3" 2>/dev/null

if [ -n "${SSH_AGENT_PID:-}" ]; then
    kill "$SSH_AGENT_PID" 2>/dev/null
fi

rm -rf "$WORK"

if [ "$FAILURES" -eq 0 ]; then
    echo "INTEROP-MATRIX OK (h3 extended CONNECT, loopback)"
    exit 0
fi

echo "INTEROP-MATRIX FAILED: $FAILURES scenario(s)"
exit 1
