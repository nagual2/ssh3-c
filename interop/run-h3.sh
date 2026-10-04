#!/bin/sh
# the h3 interop runner: RFC 9220 extended CONNECT (ssh3) over HTTP/3
#
#   1. our client (-3) -> the quic-go harness h3-server
#   2. the quic-go harness h3-client -> our server (-3)
#   3. our client (-3) -> our server (-3) (sanity)
#   4. the harness h3-client with an unsupported version -> our server
#      (-3): the request is rejected with 403 (version negotiation)
#   5. our client (-3) -> our server (-3): after the 200 the client
#      opens a session channel (header + shell request + ping in one
#      send), the server confirms (91) and echoes the data (94)
#   6. our client (-3 -C -S exec) -> our server (-3): the exec
#      session, the command output and the 98 exit-status 0
#   7. our client (-3 -C -S pty) -> our server (-3): the pty session,
#      the resize to 100x40 and the size probe, then the KILL
#      signal (an interactive shell ignores TERM), the
#      98 exit-status 137
#
# the verdicts come from the stdout protocol of the runners:
#   INTEROP-H3-STATUS 200    (the client side)
#   INTEROP-H3-CONNECT-OK    (the C server side)
#   INTEROP-CHANNEL-OK       (the C client side, the echoed ping)
#   INTEROP-CHANNEL-ACCEPT   (the C server side, the channel accepted)
#   INTEROP-EXEC-OK          (the C client side, the exec verdict)
#   INTEROP-SESSION-EXEC     (the C server side, the exec accepted)
#   INTEROP-SESSION-EXIT     (the C server side, the session exit code)
#   INTEROP-PTY-SIGNAL-OK    (the C client side, the pty verdict)
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

rm -rf "$WORK"

if [ "$FAILURES" -eq 0 ]; then
    echo "INTEROP-MATRIX OK (h3 extended CONNECT, loopback)"
    exit 0
fi

echo "INTEROP-MATRIX FAILED: $FAILURES scenario(s)"
exit 1
