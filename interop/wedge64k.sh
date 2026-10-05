#!/bin/bash
# Deadlock repro for stream_buffer_size >= 64 KiB, driven entirely by runtime
# flags: the client stalls its echo reader with -W and raises the log with -L,
# so nothing in the tracked sources is patched.  Safe to run from several
# worktrees at once (each run gets its own work dir under /tmp).
#
# usage: wedge64k.sh [root] [bufsize] [attempts] [stall_usec]
#   root         source tree (default the main checkout)
#   bufsize      stream_buffer_size arm, default 65536
#   attempts     tries before declaring "no wedge", default 4
#   stall_usec   -W reader stall, default 25000
#
# exit 0 = the arm completed every attempt (no deadlock)
# exit 2 = the arm wedged (deadlock reproduced, the bug is still present)

set -u

ROOT=${1:-/mnt/c/Git/project/ssh3-c}
BUF=${2:-65536}
ATTEMPTS=${3:-4}
STALL=${4:-25000}
BUILD=$ROOT/build/linux-release

cd "$ROOT" || exit 1

W=$(mktemp -d /tmp/s3wedge-XXXXXX)
# logs are kept on a wedge (the timeout DBG lines live there) and cleaned on success
cleanup() { [ "$1" = 0 ] && rm -rf "$W"; }

CERT=$BUILD/interop/cert.pem
KEY=$BUILD/interop/key.pem

if [ ! -x "$BUILD/s3interop_client" ] || [ ! -x "$BUILD/s3interop_server" ]; then
    echo "FAIL: no build in $BUILD (cmake --build --preset linux-release)"
    exit 3
fi

echo "wedge repro: root=$ROOT buf=$BUF stall=${STALL}us attempts=$ATTEMPTS"
echo "work dir: $W"

wedged=0

for attempt in $(seq 1 "$ATTEMPTS"); do

    setsid nohup "$BUILD/s3interop_server" -l 127.0.0.1:0 -c "$CERT" -k "$KEY" ${EXTRA_SERVER_ARGS:-} \
        > "$W/srv.log" 2>"$W/srv.err" < /dev/null &

    i=0
    while [ "$i" -lt 150 ]; do
        grep -q INTEROP-LISTEN "$W/srv.log" 2>/dev/null && break
        sleep 0.1
        i=$((i + 1))
    done

    PORT=$(grep -oE 'port=[0-9]+' "$W/srv.log" | cut -d= -f2)
    if [ -z "$PORT" ]; then
        echo "attempt $attempt FAIL: no listen port; logs kept: $W"
        pkill -9 -f "s3interop_server -l 127.0.0.1:0" 2>/dev/null
        exit 3
    fi

    # 16384 chunks x 64 KiB = 1 GiB; the deadlock lands near 660-700 MiB
    timeout 45 "$BUILD/s3interop_client" \
        -a "127.0.0.1:$PORT" -S -n 16384 -s "$BUF" -W "$STALL" -t 40000 ${EXTRA_CLIENT_ARGS:-} \
        > "$W/cli.out" 2>"$W/cli.err"
    rc=$?

    pkill -f "s3interop_server -l 127.0.0.1:0" 2>/dev/null
    sleep 0.3
    pkill -9 -f "s3interop_server -l 127.0.0.1:0" 2>/dev/null

    echo "attempt $attempt rc=$rc $(tail -n 1 "$W/cli.out")"

    if [ "$rc" -ne 0 ]; then
        wedged=1
        echo "WEDGED at attempt $attempt; grace ${GRACE:-0}s before killing the server"
        sleep "${GRACE:-0}"
        echo "--- client stderr tail"
        tail -n 8 "$W/cli.err"
        echo "--- client stdout tail"
        tail -n 4 "$W/cli.out"
        break
    fi

done

if [ "$wedged" -eq 0 ]; then
    echo "NO WEDGE: buf=$BUF completed $ATTEMPTS attempts clean"
    cleanup 0
    exit 0
fi

echo "BUG STILL PRESENT (buf=$BUF)"
exit 2