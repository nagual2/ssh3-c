#!/bin/sh
# the -f background canon (the ssh2 shape, the эталон cmd/background.go):
# the refusals ride the parent before the dial (nothing to keep, the
# OIDC browser flow, the control master, the TOFU ask on an unpinned
# host), the pinned run dials, the auth verdict lands and the parent
# exits 0 while the child holds the forwards - the proof rides the
# bytes through the -L tunnel of the detached child and the side
# effect of the detached exec
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD=${BUILD:-$ROOT/build/linux-release}
WORK=$(mktemp -d /tmp/s3fb.XXXXXX)
FAILURES=0

die() {
    echo "fork-bg-e2e: $1" >&2
    exit 1
}

[ -x "$BUILD/ssh3" ] || die "the product client is not built: $BUILD/ssh3"
[ -x "$BUILD/ssh3-server" ] || die "the daemon is not built: $BUILD/ssh3-server"

command -v python3 >/dev/null 2>&1 || die "python3 is not available"

# a hard-killed previous run leaves its setsid servers and children
# behind; sweep them by the tmp marker in their cmdline

pkill -f 's3fb\.' 2>/dev/null

cleanup() {
    pkill -f 's3fb\.' 2>/dev/null
    rm -rf "$WORK"
}

trap cleanup EXIT INT TERM

# the identity: the PKCS8 ed25519 of the C client, the authorized
# keys line built by hand (ssh-keygen reads no PKCS8 ed25519)

openssl genpkey -algorithm ed25519 -out "$WORK/priv.pem" 2>/dev/null || die "openssl genpkey failed"

{
    printf '\000\000\000\013ssh-ed25519\000\000\000\040'
    openssl pkey -in "$WORK/priv.pem" -pubout -outform DER 2>/dev/null | tail -c 32
} | base64 | tr -d '\n' > "$WORK/blob.pub"

printf 'ssh-ed25519 %s fork-bg-e2e\n' "$(cat "$WORK/blob.pub")" > "$WORK/authorized_keys"

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/key.pem" \
    -out "$WORK/cert.pem" -days 2 -subj /CN=fork-bg-e2e 2>/dev/null \
    || die "openssl req failed"

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

# the daemon and the forward target: the echo server holds the -L
# tail, the tunnel proof rides the bytes back

setsid nohup env SSH3C_PROTO=1 "$BUILD/ssh3-server" -3 \
    -l "127.0.0.1:0" -c "$WORK/cert.pem" -k "$WORK/key.pem" \
    -K "$WORK/authorized_keys" > "$WORK/srv.log" 2>&1 < /dev/null &

setsid nohup python3 -c '
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 0))
print("ECHO-PORT", s.getsockname()[1], flush=True)
s.listen(8)
while True:
    c, _ = s.accept()
    data = c.recv(65536)
    c.sendall(b"BG-ECHO:" + data)
    c.close()
' > "$WORK/echo.log" 2>&1 < /dev/null &

wait_listen "$WORK/srv.log" || die "the daemon did not start"

i=0
while [ "$i" -lt 50 ]; do
    if grep -q ECHO-PORT "$WORK/echo.log" 2>/dev/null; then
        break
    fi
    sleep 0.1
    i=$((i + 1))
done

EPORT=$(grep -oE 'ECHO-PORT [0-9]+' "$WORK/echo.log" | cut -d' ' -f2)
[ -n "$EPORT" ] || die "the echo server did not start"

SRVPORT=$(port_of "$WORK/srv.log")

# the bind port of the -L listener: the fixed probe (the free port
# rides the kernel pick, the collision retires)

FWDPORT=

i=0
while [ "$i" -lt 10 ]; do

    # the dash has no $RANDOM: the pid salts the pick, the collision
    # retires with the next candidate

    CAND=$((21500 + ($$ + i) % 30000))

    if ! ss -H -ltn 2>/dev/null | grep -q ":$CAND "; then
        FWDPORT=$CAND
        break
    fi

    i=$((i + 1))
done

[ -n "$FWDPORT" ] || die "no free bind port found"

# the pin store: the target pins before the run (the pinned run
# passes the ask gate, the unpinned one must refuse)

mkdir -p "$WORK/home/.ssh3"

printf '127.0.0.1:%s/ssh3-term x509-certificate %s\n' "$SRVPORT" \
    "$(openssl x509 -in "$WORK/cert.pem" -outform DER | base64 -w0)" \
    >> "$WORK/home/.ssh3/known_hosts"

echo "== leg 1: the -f parent exits 0 and the tunnel rides the child (BG-FORWARD-OK)"

HOME="$WORK/home" timeout 30 "$BUILD/ssh3" -f -N -i "$WORK/priv.pem" \
    -L "127.0.0.1:$FWDPORT:127.0.0.1:$EPORT" \
    "client@127.0.0.1:$SRVPORT/ssh3-term" \
    > "$WORK/leg1.out" 2>"$WORK/leg1.err"
BGRC=$?

if [ "$BGRC" -ne 0 ]; then
    echo "   FAIL: the -f parent exited $BGRC"
    tail -8 "$WORK/leg1.err" | sed 's/^/   /'
    FAILURES=$((FAILURES + 1))
else
    echo "   PASS: the -f parent exited 0"
fi

# the listener of the detached child: the bind lands on the first
# loop pass after the fork, the poll rides the socket table

i=0

while [ "$i" -lt 40 ]; do
    ss -H -ltn 2>/dev/null | grep -q ":$FWDPORT " && break
    sleep 0.2
    i=$((i + 1))
done

if ! ss -H -ltn 2>/dev/null | grep -q ":$FWDPORT "; then
    echo "   FAIL: the detached child holds no listener on $FWDPORT"
    FAILURES=$((FAILURES + 1))

else
    ANSWER=$(timeout 10 python3 -c "
import socket
c = socket.create_connection(('127.0.0.1', $FWDPORT), timeout=5)
c.sendall(b'ping-through-tunnel')
print(c.recv(65536).decode(), flush=True)
" 2>/dev/null)

    if [ "$ANSWER" = "BG-ECHO:ping-through-tunnel" ]; then
        echo "   PASS: the byte-exact pass rode the detached tunnel"
    else
        echo "   FAIL: the tunnel answer did not come: $ANSWER"
        FAILURES=$((FAILURES + 1))
    fi
fi

echo "== leg 2: the detached exec rides the child (BG-EXEC-OK)"

rm -f "$WORK/cmd-ran"

HOME="$WORK/home" timeout 30 "$BUILD/ssh3" -f -i "$WORK/priv.pem" \
    "client@127.0.0.1:$SRVPORT/ssh3-term" "touch $WORK/cmd-ran" \
    > /dev/null 2>"$WORK/leg2.err"
BGRC=$?

if [ "$BGRC" -ne 0 ]; then
    echo "   FAIL: the -f exec parent exited $BGRC"
    tail -8 "$WORK/leg2.err" | sed 's/^/   /'
    FAILURES=$((FAILURES + 1))
fi

i=0

while [ "$i" -lt 40 ]; do
    [ -f "$WORK/cmd-ran" ] && break
    sleep 0.2
    i=$((i + 1))
done

if [ -f "$WORK/cmd-ran" ]; then
    echo "   PASS: the detached exec landed its side effect"
else
    echo "   FAIL: the detached exec never ran"
    FAILURES=$((FAILURES + 1))
fi

echo "== leg 3: the bare -f refuses (nothing to keep) (BG-NOTHING-REJECT)"

if HOME="$WORK/home" timeout 20 "$BUILD/ssh3" -f -i "$WORK/priv.pem" \
    "client@127.0.0.1:$SRVPORT/ssh3-term" \
    > /dev/null 2>"$WORK/leg3.err"; then
    echo "   FAIL: the bare -f passed"
    FAILURES=$((FAILURES + 1))

elif grep -q "nothing to keep running" "$WORK/leg3.err"; then
    echo "   PASS: the bare -f refused with the nothing-to-keep reason"
else
    echo "   FAIL: the refusal rode another reason"
    tail -8 "$WORK/leg3.err" | sed 's/^/   /'
    FAILURES=$((FAILURES + 1))
fi

echo "== leg 4: the -f with the OIDC flow refuses (BG-OIDC-REJECT)"

if HOME="$WORK/home" timeout 20 "$BUILD/ssh3" -f -N \
    --oidc-issuer "http://127.0.0.1:1/op" --oidc-audience "fork-bg-e2e" \
    -L "127.0.0.1:$FWDPORT:127.0.0.1:$EPORT" \
    "client@127.0.0.1:$SRVPORT/ssh3-term" \
    > /dev/null 2>"$WORK/leg4.err"; then
    echo "   FAIL: the OIDC -f passed"
    FAILURES=$((FAILURES + 1))

elif grep -q "opens a browser" "$WORK/leg4.err"; then
    echo "   PASS: the OIDC browser flow refused"
else
    echo "   FAIL: the refusal rode another reason"
    tail -8 "$WORK/leg4.err" | sed 's/^/   /'
    FAILURES=$((FAILURES + 1))
fi

echo "== leg 5: the -f with the control master refuses (BG-CM-REJECT)"

if HOME="$WORK/home" timeout 20 "$BUILD/ssh3" -f -M -N -i "$WORK/priv.pem" \
    "client@127.0.0.1:$SRVPORT/ssh3-term" \
    > /dev/null 2>"$WORK/leg5.err"; then
    echo "   FAIL: the master -f passed"
    FAILURES=$((FAILURES + 1))

elif grep -q -e "drop -f" -e "no -M" "$WORK/leg5.err"; then
    echo "   PASS: the control master combination refuses -f"
else
    echo "   FAIL: the refusal rode another reason"
    tail -8 "$WORK/leg5.err" | sed 's/^/   /'
    FAILURES=$((FAILURES + 1))
fi

echo "== leg 6: the -f with the unpinned host refuses (BG-UNPINNED-REJECT)"

mkdir -p "$WORK/home-plain/.ssh3"

if HOME="$WORK/home-plain" timeout 20 "$BUILD/ssh3" -f -N -i "$WORK/priv.pem" \
    -L "127.0.0.1:$FWDPORT:127.0.0.1:$EPORT" \
    "client@127.0.0.1:$SRVPORT/ssh3-term" \
    > /dev/null 2>"$WORK/leg6.err"; then
    echo "   FAIL: the unpinned -f passed"
    FAILURES=$((FAILURES + 1))

elif grep -q "the host is not pinned" "$WORK/leg6.err"; then
    echo "   PASS: the unpinned host refused under the ask policy"
else
    echo "   FAIL: the refusal rode another reason"
    tail -8 "$WORK/leg6.err" | sed 's/^/   /'
    FAILURES=$((FAILURES + 1))
fi

if [ "$FAILURES" -eq 0 ]; then
    echo "FORK-BG-E2E OK"
    exit 0
fi

echo "FORK-BG-E2E FAILED: $FAILURES check(s)"
exit 1
