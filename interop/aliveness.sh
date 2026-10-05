#!/bin/bash
# is the server still alive when the client stalls?
ROOT=/mnt/c/Git/project/ssh3-c
BUILD=${BUILD:-$ROOT/build/linux-release}
W=$(mktemp -d /tmp/s3alive-XXXXXX)
CERT=$BUILD/interop/cert.pem
KEY=$BUILD/interop/key.pem

cd $ROOT
setsid "$BUILD/s3interop_server" -l 127.0.0.1:0 -c "$CERT" -k "$KEY" \
    > "$W/srv.log" 2>"$W/srv.err" < /dev/null &
SPID=$!
i=0
while [ $i -lt 100 ]; do grep -q INTEROP-LISTEN "$W/srv.log" 2>/dev/null && break; sleep 0.1; i=$((i+1)); done
PORT=$(grep -oE 'port=[0-9]+' "$W/srv.log" | cut -d= -f2)
echo "server pid=$SPID port=$PORT"

"$BUILD/s3interop_client" -a "127.0.0.1:$PORT" -S -n 16384 -s 65536 -t 8000 > "$W/cli.out" 2>&1
echo "client rc=$?"
sleep 0.3
echo "--- server alive?"
if kill -0 $SPID 2>/dev/null; then
    echo "ALIVE pid=$SPID"
    cat /proc/$SPID/status 2>/dev/null | grep -E "State|SigQ"
else
    DEAD=1; echo "DEAD"
    wait $SPID; echo "exit code: $?"
fi
dmesg 2>/dev/null | tail -3 | grep -i segfault
kill -9 $SPID 2>/dev/null
if [ "$DEAD" = 1 ]; then echo "logs kept: $W"; else rm -rf "$W"; fi