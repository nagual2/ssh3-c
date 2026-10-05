#!/bin/bash
# run the ASan server under gdb (certs from the release build), fire the client
ROOT=/mnt/c/Git/project/ssh3-c
BUILD=$ROOT/build/linux-asan
CERT=$ROOT/build/linux-release/interop/cert.pem
KEY=$ROOT/build/linux-release/interop/key.pem
W=$(mktemp -d /tmp/s3gdb-XXXXXX)

cd $ROOT

LSAN_OPTIONS=detect_leaks=0 gdb -q -batch \
    -ex "set confirm off" \
    -ex "run -l 127.0.0.1:0 -c $CERT -k $KEY" \
    -ex "bt" \
    -ex "info locals" \
    --args "$BUILD/s3interop_server" -l 127.0.0.1:0 -c "$CERT" -k "$KEY" \
    > "$W/gdb.log" 2>&1 &

GPID=$!

i=0
while [ $i -lt 300 ]; do grep -q INTEROP-LISTEN "$W/gdb.log" 2>/dev/null && break; sleep 0.1; i=$((i + 1)); done
PORT=$(grep -oE 'port=[0-9]+' "$W/gdb.log" | head -1 | grep -oE 'port=[0-9]+' | cut -d= -f2)
echo "gdb pid=$GPID port=$PORT"

"$ROOT/build/linux-release/s3interop_client" -a "127.0.0.1:$PORT" -S -n 16384 -s 65536 -t 8000 \
    > "$W/cli.out" 2>&1
echo "client rc=$?"
sleep 2

if kill -0 $GPID 2>/dev/null; then
    echo "gdb still running (no crash?)"
    kill -9 $GPID
else
    wait $GPID 2>/dev/null
fi

echo "=== gdb tail ==="
grep -nE "SIGSEGV|Program received|^#0 |^#1 |^#2 |^#3 |^#4 " "$W/gdb.log" | tail -n 8
echo "=== frame locals ==="
awk '/^#0 /{f=1} f' "$W/gdb.log" | head -n 20
kill -9 $GPID 2>/dev/null
echo "logs: $W"