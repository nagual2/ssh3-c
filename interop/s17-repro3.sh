#!/bin/bash
# the scenario-17 repro pass 3: the qlog of the harness side plus the
# S3SFTPHDBG sftp-level sent counter, the put direction
set -u
WT=/mnt/c/Git/temp/wt-s17
BUILD=$WT/build/linux-release
GO=${GO:-$HOME/opt/go1.27.1/bin/go}
HARNESS=/tmp/s17-harness
WORK=/tmp/s17-work
OUT=/tmp/s17-out
QLOG=/tmp/s17-qlog

rm -rf "$WORK" "$QLOG"; mkdir -p "$WORK" "$QLOG"
cd "$WT/interop/quic-go" && "$GO" build -o "$HARNESS" . || exit 1

dd if=/dev/urandom of="$WORK/sftp-src.bin" bs=1048576 count=3 2>/dev/null
mkdir -p "$WORK/sftp-go"

setsid nohup env HOME="$WORK/sftp-go" QLOGDIR="$QLOG" S3SFTPHDBG=1 "$HARNESS" \
    -h3-sftp-server -addr 127.0.0.1:0 \
    -cert "$OUT/cert.pem" -key "$OUT/key.pem" > "$OUT/gsftp-srv3.log" 2>&1 < /dev/null &
SRV_PID=$!

i=0
while [ $i -lt 50 ]; do
    if grep -q INTEROP-LISTEN "$OUT/gsftp-srv3.log" 2>/dev/null; then break; fi
    sleep 0.1; i=$((i+1))
done
PORT=$(grep -oE 'port=[0-9]+' "$OUT/gsftp-srv3.log" | cut -d= -f2)
echo "harness on port $PORT"

S3SFTPDBG=1 timeout 25 "$BUILD/s3interop_client" -3 -L all \
    -J "put:$WORK/sftp-src.bin:go-p5.bin" \
    -a "127.0.0.1:$PORT" -t 12000 > "$OUT/gsftp-put3.log" 2>&1
echo "client rc=$?"

kill -QUIT "$SRV_PID" 2>/dev/null; sleep 1; kill "$SRV_PID" 2>/dev/null

echo "=== the harness sftp sent tail ==="
grep "harness-sftpdbg" "$OUT/gsftp-srv3.log" | tail -3
echo "=== the harness sftp sent total ==="
grep "harness-sftpdbg" "$OUT/gsftp-srv3.log" | tail -1 | grep -oE "sent=[0-9]+"
echo "=== qlog files ==="
ls -la "$QLOG"
