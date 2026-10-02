#!/bin/sh
# the quic-go interop runner: the D3 acceptance scenario (PLAN.md P2)
#
#   1. our client        -> the quic-go harness server
#   2. the quic-go harness client -> our server
#   3. datagrams under 5% netem loss (RFC 9221: N of M echoes)
#
# each scenario runs a QUIC handshake followed by N DATAGRAM
# round-trips; the verdict is printed per scenario as PASS/FAIL.
# the harness (interop/quic-go) pins the same quic-go version as the
# reference Go fork.
#
# usage: interop/run-quic-go.sh [count] [size]
# requires: the C runners (cmake --build build/linux-release), a Go
# toolchain >= 1.26 (GO overrides $HOME/opt/go1.27.1/bin/go), openssl,
# sudo -n tc for scenario 3
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD=${BUILD:-$ROOT/build/linux-release}
GO=${GO:-$HOME/opt/go1.27.1/bin/go}
COUNT=${1:-8}
SIZE=${2:-512}

die() {
    echo "run-quic-go: $1" >&2
    exit 1
}

[ -x "$BUILD/s3interop_server" ] || die "s3interop_server is not built (cmake --build $BUILD)"
[ -x "$BUILD/s3interop_client" ] || die "s3interop_client is not built"

HARNESS=$BUILD/interop-harness
mkdir -p "$BUILD/interop"

(cd "$ROOT/interop/quic-go" && "$GO" build -o "$HARNESS" .) || die "go build failed"

CERT=$BUILD/interop/cert.pem
KEY=$BUILD/interop/key.pem

if [ ! -f "$CERT" ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$KEY" -out "$CERT" -days 30 \
        -subj "/CN=s3interop" 2>/dev/null || die "openssl req failed"
fi

WORK=$(mktemp -d /tmp/s3interop.XXXXXX)
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

echo "== scenario 1: C client -> quic-go server"

setsid nohup "$HARNESS" -server -addr 127.0.0.1:0 -cert "$CERT" -key "$KEY" \
    > "$WORK/go-srv.log" 2>&1 < /dev/null &

if wait_listen "$WORK/go-srv.log"; then
    PORT=$(port_of "$WORK/go-srv.log")

    if timeout 30 "$BUILD/s3interop_client" -a "127.0.0.1:$PORT" -n "$COUNT" -s "$SIZE" \
        > "$WORK/c-cli.log" 2>&1; then
        echo "   PASS ($COUNT datagrams)"
    else
        echo "   FAIL"
        tail -5 "$WORK/c-cli.log" | sed 's/^/   /'
        FAILURES=$((FAILURES + 1))
    fi

else
    echo "   FAIL: the harness server did not start"
    FAILURES=$((FAILURES + 1))
fi

pkill -f "s3interop-harness -server" 2>/dev/null

echo "== scenario 2: quic-go client -> C server"
setsid nohup "$BUILD/s3interop_server" -l 127.0.0.1:0 -c "$CERT" -k "$KEY" \
    > "$WORK/c-srv.log" 2>&1 < /dev/null &

if wait_listen "$WORK/c-srv.log"; then
    PORT=$(port_of "$WORK/c-srv.log")

    if timeout 30 "$HARNESS" -client -addr "127.0.0.1:$PORT" -count "$COUNT" -size "$SIZE" \
        > "$WORK/go-cli.log" 2>&1; then
        echo "   PASS ($COUNT datagrams)"
    else
        echo "   FAIL"
        tail -5 "$WORK/go-cli.log" | sed 's/^/   /'
        FAILURES=$((FAILURES + 1))
    fi

else
    echo "   FAIL: the C server did not start"
    FAILURES=$((FAILURES + 1))
fi

pkill -f "s3interop_server -l" 2>/dev/null

echo "== scenario 4: stream echo C client -> quic-go server"

setsid nohup "$HARNESS" -server -addr 127.0.0.1:0 -cert "$CERT" -key "$KEY" \
    > "$WORK/st-srv.log" 2>&1 < /dev/null &

if wait_listen "$WORK/st-srv.log"; then
    PORT=$(port_of "$WORK/st-srv.log")

    # 4 MiB through one stream against the deterministic pattern
    if timeout 60 "$BUILD/s3interop_client" -a "127.0.0.1:$PORT" -S -n 64 -s 65536 \
        -t 45000 > "$WORK/st-cli.log" 2>&1; then
        echo "   PASS (64 x 64 KiB echoed)"
    else
        echo "   FAIL"
        tail -5 "$WORK/st-cli.log" | sed 's/^/   /'
        FAILURES=$((FAILURES + 1))
    fi

else
    echo "   FAIL: the harness server did not start"
    FAILURES=$((FAILURES + 1))
fi

pkill -f "s3interop-harness -server" 2>/dev/null

echo "== scenario 5: stream echo quic-go client -> C server"

setsid nohup "$BUILD/s3interop_server" -l 127.0.0.1:0 -c "$CERT" -k "$KEY" \
    > "$WORK/st2-srv.log" 2>&1 < /dev/null &

if wait_listen "$WORK/st2-srv.log"; then
    PORT=$(port_of "$WORK/st2-srv.log")

    if timeout 60 "$HARNESS" -client -streams -addr "127.0.0.1:$PORT" -count 64 -size 65536 \
        -timeout 45s > "$WORK/st2-cli.log" 2>&1; then
        echo "   PASS (64 x 64 KiB echoed)"
    else
        echo "   FAIL"
        tail -5 "$WORK/st2-cli.log" | sed 's/^/   /'
        FAILURES=$((FAILURES + 1))
    fi

else
    echo "   FAIL: the C server did not start"
    FAILURES=$((FAILURES + 1))
fi

pkill -f "s3interop_server -l" 2>/dev/null

echo "== scenario 3: datagrams under 5% netem loss (C client -> quic-go server)"

# RFC 9221 datagrams are not retransmitted: the run requires at least
# half of the echoes, not all of them
LOST=$((COUNT / 2))
REQUIRED=$((COUNT - LOST))

if sudo -n tc qdisc add dev lo root netem loss 5% 2>/dev/null; then

    setsid nohup "$HARNESS" -server -addr 127.0.0.1:0 -cert "$CERT" -key "$KEY" \
        > "$WORK/loss-srv.log" 2>&1 < /dev/null &

    if wait_listen "$WORK/loss-srv.log"; then
        PORT=$(port_of "$WORK/loss-srv.log")

        if timeout 60 "$BUILD/s3interop_client" -a "127.0.0.1:$PORT" -n "$COUNT" -s "$SIZE" \
            -m "$REQUIRED" -t 45000 > "$WORK/loss-cli.log" 2>&1; then
            echo "   PASS (>= $REQUIRED of $COUNT under 5% loss)"
        else
            echo "   FAIL (required $REQUIRED of $COUNT)"
            tail -5 "$WORK/loss-cli.log" | sed 's/^/   /'
            FAILURES=$((FAILURES + 1))
        fi

    else
        echo "   FAIL: the harness server did not start"
        FAILURES=$((FAILURES + 1))
    fi

    pkill -f "s3interop-harness -server" 2>/dev/null

    sudo -n tc qdisc del dev lo root

else
    echo "   SKIP (no sudo -n tc, the loss scenario needs root)"
fi

rm -rf "$WORK"

if [ "$FAILURES" -eq 0 ]; then
    echo "INTEROP-MATRIX OK (quic-go v0.63.0, loopback)"
    exit 0
fi

echo "INTEROP-MATRIX FAILED: $FAILURES scenario(s)"
exit 1
