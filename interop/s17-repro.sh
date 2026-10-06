#!/bin/bash
# the manual scenario-17 repro: the C client put against the go harness
# sftp-server, with the full quic/h3 logging and the goroutine dump
# of the harness at the stall moment
set -u
WT=/mnt/c/Git/temp/wt-s17
BUILD=$WT/build/linux-release
GO=${GO:-$HOME/opt/go1.27.1/bin/go}
HARNESS=/tmp/s17-harness
WORK=/tmp/s17-work
OUT=/tmp/s17-out

rm -rf "$WORK" "$OUT"
mkdir -p "$WORK" "$OUT"

(cd "$WT/interop/quic-go" && "$GO" build -o "$HARNESS" .) || { echo "go build failed"; exit 1; }

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$OUT/key.pem" -out "$OUT/cert.pem" \
    -days 30 -subj "/CN=s3interop" 2>/dev/null

dd if=/dev/urandom of="$WORK/sftp-src.bin" bs=1048576 count=3 2>/dev/null
mkdir -p "$WORK/sftp-go"

# the flow-control trace on the client side
export SSH3C_LOG=all
export SSH3C_LOG_LEVEL=debug

setsid nohup env HOME="$WORK/sftp-go" "$HARNESS" -h3-sftp-server -addr 127.0.0.1:0 \
    -cert "$OUT/cert.pem" -key "$OUT/key.pem" > "$OUT/gsftp-srv.log" 2>&1 < /dev/null &
SRV_PID=$!
echo "$SRV_PID" > "$OUT/srv.pid"

i=0
while [ $i -lt 50 ]; do
    if grep -q INTEROP-LISTEN "$OUT/gsftp-srv.log" 2>/dev/null; then break; fi
    sleep 0.1; i=$((i+1))
done
PORT=$(grep -oE 'port=[0-9]+' "$OUT/gsftp-srv.log" | cut -d= -f2)
echo "harness on port $PORT"

timeout 25 "$BUILD/s3interop_client" -3 -J "put:$WORK/sftp-src.bin:go-p5.bin" \
    -a "127.0.0.1:$PORT" -t 20000 > "$OUT/gsftp-put.log" 2>&1
PUT_RC=$?
echo "client put rc=$PUT_RC (124 = the timeout hit => the stall)"

ls -la "$WORK/sftp-go/" > "$OUT/ls-remote.txt" 2>&1
cmp -s "$WORK/sftp-go/go-p5.bin" "$WORK/sftp-src.bin"
echo "CMP_RC=$? (0 = byte-exact)"

# the goroutine dump of the harness at the stall moment
kill -QUIT "$SRV_PID" 2>/dev/null
sleep 1
kill "$SRV_PID" 2>/dev/null

echo "=== artifacts in $OUT ==="
ls -la "$OUT"
