#!/bin/bash
# the v6-target smoke of the stage 2: the direct-tcp and the
# direct-udp targets dial the ::1 loopback services through the
# daemon; the client rides the -L forwards
set -u

BUILD=/mnt/c/Git/project/ssh3-c/build/linux-release
WORK=/tmp/s3v6-$$
mkdir -p "$WORK/home/.ssh3"
CERT=$WORK/cert.pem
KEY=$WORK/key.pem
IKEY=$WORK/ikey.pem
PORT=17617
TPORT=17618

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$KEY" -out "$CERT" -days 2 \
    -subj "/CN=s3v6" 2>/dev/null
ssh-keygen -q -t ed25519 -N "" -C client -f "$IKEY" 2>/dev/null
chmod 600 "$IKEY"
cp "$IKEY.pub" "$WORK/authorized_keys" 2>/dev/null

python3 - <<EOF &
import socket

s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.bind(("::1", $PORT))
while True:
    d, a = s.recvfrom(2048)
    s.sendto(b"udp6:" + d, a)
EOF
UPID=$!

python3 - <<EOF &
import socket, threading

srv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("::1", $TPORT))
srv.listen(4)

def serve(c):
    try:
        d = c.recv(2048)
        c.sendall(b"tcp6:" + d)
    finally:
        c.close()

while True:
    c, _ = srv.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
EOF
TPID=$!

setsid nohup "$BUILD/ssh3-server" -3 -l "127.0.0.1:0" -c "$CERT" -k "$KEY" \
    -K "$WORK/authorized_keys" \
    > "$WORK/srv.log" 2>&1 < /dev/null &
sleep 0.6

SRV_PID=$(pgrep -f -- "ssh3-server -3 -l 127.0.0.1:0 -c $CERT" | head -1)
SPORT=$(grep -a -oE "port=[0-9]+" "$WORK/srv.log" | head -1 | cut -d= -f2)
echo "daemon pid $SRV_PID sport $SPORT"

printf '127.0.0.1:%s/ssh3-term x509-certificate %s\n' "$SPORT" \
    "$(openssl x509 -in "$CERT" -outform DER | base64 -w0)" > "$WORK/home/.ssh3/known_hosts"

HOME="$WORK/home" setsid nohup "$BUILD/ssh3" -N \
    -L "udp://127.0.0.1:17616/::1/$PORT" \
    -L "127.0.0.1:$TPORT:[::1]:$TPORT" \
    -i "$IKEY" \
    "client@127.0.0.1:$SPORT/ssh3-term" \
    > "$WORK/cli.log" 2>&1 < /dev/null &

sleep 2

python3 - <<EOF
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
s.sendto(b"ping", ("127.0.0.1", 17616))
try:
    d, _ = s.recvfrom(2048)
    print("UDP-RESULT:", d)
except socket.timeout:
    print("UDP-RESULT: timeout")
EOF

python3 - <<EOF
import socket

c = socket.create_connection(("127.0.0.1", 17618), timeout=5)
c.settimeout(5)
c.sendall(b"ping")
try:
    d = c.recv(2048)
    print("TCP-RESULT:", d)
except socket.timeout:
    print("TCP-RESULT: timeout")
EOF
echo "TPORT-BIND-CHECK: $(ss -tln 2>/dev/null | grep -c 17618 || echo 0)"

kill "$SRV_PID" 2>/dev/null
pkill -f "ssh3 -N -L udp" 2>/dev/null
kill $UPID $TPID 2>/dev/null
tail -4 "$WORK/cli.log"
echo KEPT:$WORK
