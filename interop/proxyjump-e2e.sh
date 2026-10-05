#!/bin/sh
# the proxy jump end-to-end proof (the fix/j worktree): two C servers,
# the jump one (with the tunnel-size datagram acceptance) and the
# inner one; the client dials the jump, tunnels the inner connection
# through the direct-udp channel and runs the exec scenario.  The
# negative run points -j at a dead port and must refuse cleanly
# inside the -t deadline
set -u

ROOT=/mnt/c/Git/project/ssh3-c
BUILD=${BUILD:-$ROOT/build/linux-release}
WORK=$(mktemp -d /tmp/s3pj.XXXXXX)
FAILURES=0

die() {
    echo "proxyjump-e2e: $1" >&2
    exit 1
}

[ -x "$BUILD/s3interop_server" ] || die "s3interop_server is not built"
[ -x "$BUILD/s3interop_client" ] || die "s3interop_client is not built"

CERT=$BUILD/interop/cert.pem
KEY=$BUILD/interop/key.pem

if [ ! -f "$CERT" ]; then
    mkdir -p "$BUILD/interop"
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$KEY" -out "$CERT" -days 30 \
        -subj "/CN=s3interop" 2>/dev/null || die "openssl req failed"
fi

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

# the jump server: -d 1352, the tunnel frames carry the inner
# 1200-byte datagrams; the inner one runs the stock conf

setsid nohup "$BUILD/s3interop_server" -3 -d 1352 -l 127.0.0.1:0 -c "$CERT" -k "$KEY" \
    > "$WORK/jump.log" 2>&1 < /dev/null &

if ! wait_listen "$WORK/jump.log"; then
    die "the jump server did not start"
fi

JPORT=$(port_of "$WORK/jump.log")

setsid nohup "$BUILD/s3interop_server" -3 -l 127.0.0.1:0 -c "$CERT" -k "$KEY" \
    > "$WORK/inner.log" 2>&1 < /dev/null &

if ! wait_listen "$WORK/inner.log"; then
    die "the inner server did not start"
fi

IPORT=$(port_of "$WORK/inner.log")

echo "== positive: the exec session through the jump tunnel"

if timeout 30 "$BUILD/s3interop_client" -3 -C -S exec \
    -j "127.0.0.1:$JPORT" -a "127.0.0.1:$IPORT" -t 20000 \
    > "$WORK/cli.log" 2>&1 \
    && grep -q "INTEROP-PROXYJUMP-OK inner-sent=" "$WORK/cli.log"; then
    grep "INTEROP-PROXYJUMP-OK" "$WORK/cli.log"
else
    echo "   FAIL"
    tail -8 "$WORK/cli.log" | sed 's/^/   /'
    FAILURES=$((FAILURES + 1))
fi

echo "== negative: the wrong jump port refuses inside the deadline"

START=$(date +%s)

if timeout 30 "$BUILD/s3interop_client" -3 -C -S exec \
    -j "127.0.0.1:1" -a "127.0.0.1:$IPORT" -t 5000 \
    > "$WORK/bad.log" 2>&1; then
    echo "   FAIL: the wrong jump port passed"
    tail -5 "$WORK/bad.log" | sed 's/^/   /'
    FAILURES=$((FAILURES + 1))

else
    NOW=$(date +%s)

    if [ $((NOW - START)) -gt 15 ]; then
        echo "   FAIL: the wrong jump port hung past the deadline"
        FAILURES=$((FAILURES + 1))
    else
        echo "   PASS (clean refusal in $((NOW - START))s)"
    fi
fi

pkill -f "s3interop_server -3" 2>/dev/null

rm -rf "$WORK"

if [ "$FAILURES" -eq 0 ]; then
    echo "PROXYJUMP-E2E OK"
    exit 0
fi

echo "PROXYJUMP-E2E FAILED: $FAILURES check(s)"
exit 1
