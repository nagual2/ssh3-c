#!/bin/bash
# sanity: path->received must be sane now (was pointer-magnitude garbage)
ROOT=/mnt/c/Git/project/ssh3-c
BUILD=$ROOT/build/linux-release
W=$(mktemp -d /tmp/s3rx-XXXXXX)
CERT=$BUILD/interop/cert.pem
KEY=$BUILD/interop/key.pem
cd $ROOT
setsid nohup "$BUILD/s3interop_server" -3 -l 127.0.0.1:0 -c "$CERT" -k "$KEY" \
    > "$W/srv.log" 2>"$W/srv.err" < /dev/null &
i=0
while [ $i -lt 100 ]; do grep -q INTEROP-LISTEN "$W/srv.log" 2>/dev/null && break; sleep 0.1; i=$((i+1)); done
PORT=$(grep -oE 'port=[0-9]+' "$W/srv.log" | cut -d= -f2)
timeout 15 "$BUILD/s3interop_client" -3 -a "127.0.0.1:$PORT" -n 512 -s 1024 -L all -t 10000 \
    > "$W/cli.out" 2>"$W/cli.err"
echo "client rc=$? $(tail -1 "$W/cli.out")"
pkill -f "s3interop_server -3 -l" 2>/dev/null
echo "=== client path status (rx sanity) ==="
grep -oE "path seq:0 status tx:[0-9]+ rx:[0-9]+" "$W/cli.err" | tail -2
echo "=== server path status (rx sanity) ==="
grep -oE "path seq:0 status tx:[0-9]+ rx:[0-9]+" "$W/srv.err" | tail -2
rm -rf "$W"
