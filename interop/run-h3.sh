#!/bin/sh
# the h3 interop runner: RFC 9220 extended CONNECT (ssh3) over HTTP/3
#
#   1. our client (-3) -> the quic-go harness h3-server
#   2. the quic-go harness h3-client -> our server (-3)
#   3. our client (-3) -> our server (-3) (sanity)
#
# the verdicts come from the stdout protocol of the runners:
#   INTEROP-H3-STATUS 200    (the client side)
#   INTEROP-H3-CONNECT-OK    (the C server side)
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

rm -rf "$WORK"

if [ "$FAILURES" -eq 0 ]; then
    echo "INTEROP-MATRIX OK (h3 extended CONNECT, loopback)"
    exit 0
fi

echo "INTEROP-MATRIX FAILED: $FAILURES scenario(s)"
exit 1
