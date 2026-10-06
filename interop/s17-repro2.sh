#!/bin/bash
# the scenario-17 repro pass 2: the full client trace (-L all, S3SFTPDBG)
set -u
WT=/mnt/c/Git/temp/wt-s17
BUILD=$WT/build/linux-release
HARNESS=/tmp/s17-harness
WORK=/tmp/s17-work
OUT=/tmp/s17-out

rm -rf "$WORK"; mkdir -p "$WORK"
dd if=/dev/urandom of="$WORK/sftp-src.bin" bs=1048576 count=3 2>/dev/null
mkdir -p "$WORK/sftp-go"

setsid nohup env HOME="$WORK/sftp-go" "$HARNESS" -h3-sftp-server -addr 127.0.0.1:0 \
    -cert "$OUT/cert.pem" -key "$OUT/key.pem" > "$OUT/gsftp-srv2.log" 2>&1 < /dev/null &
SRV_PID=$!
echo "$SRV_PID" > "$OUT/srv.pid"

i=0
while [ $i -lt 50 ]; do
    if grep -q INTEROP-LISTEN "$OUT/gsftp-srv2.log" 2>/dev/null; then break; fi
    sleep 0.1; i=$((i+1))
done
PORT=$(grep -oE 'port=[0-9]+' "$OUT/gsftp-srv2.log" | cut -d= -f2)
echo "harness on port $PORT"

S3SFTPDBG=1 timeout 25 "$BUILD/s3interop_client" -3 -L all \
    -J "put:$WORK/sftp-src.bin:go-p5.bin" \
    -a "127.0.0.1:$PORT" -t 12000 > "$OUT/gsftp-put2.log" 2>&1
echo "client rc=$?"

kill -QUIT "$SRV_PID" 2>/dev/null; sleep 1; kill "$SRV_PID" 2>/dev/null

wc -l "$OUT/gsftp-put2.log"
grep -c "sftpdbg recv" "$OUT/gsftp-put2.log" || true
tail -30 "$OUT/gsftp-put2.log"
