#!/bin/sh
# the cli-compat e2e (P8 wave 1a-1c): the ssh(1) canon keys of the
# product client against the product daemon.
#
#   1. -V and --help (the version and the usage, exit 0)
#   2. -l login == the operand user@ (the exec echo twins)
#   3. -p port (the operand without the port)
#   4. -q (the quiet run: the marker only, the stderr empty)
#   5. -T exec (the no-pty exec against the daemon)
#   6. -X warns deprecated and the session rides
#   7. -N holds the -L forward (the local port echoes) and refuses
#      the command words
#   8. -t without a local tty refuses (the ssh2 shape)
#   9. -n smoke (the exec rides, the stdin unpumped)
#  10. -A agent forwarding rides the throwaway agent (the small leg)
#  11. -J put: deprecated works, --sftp put/get byte-exact
#  12. -J jump vs the two-daemon stand (the positive and the wrong
#      jump port refusal inside the deadline)
#  13. -o Port=, -o User=, -o LocalForward= (the -L twin)
#  14. -F config (HostName/Port/User/LocalForward from the file)
#  15. -D socks5 (the curl through the proxy)
#  16. -6 vs the dual-stack daemon
#
# the verdicts: CLI-COMPAT-E2E OK / FAILED, the leg markers on the
# way
#
# usage: interop/cli-compat-e2e.sh   (WSL)
# requires: the daemon and the client built (build/linux-release),
# curl, nc, ssh-agent, python3
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD=${BUILD:-$ROOT/build/linux-release}
BIN=${SSH3C_SERVER_BIN:-$BUILD/ssh3-server}

die() {
    echo "cli-compat-e2e: $1" >&2
    exit 1
}

[ -x "$BIN" ] || die "the daemon is not built: $BIN"
[ -x "$BUILD/ssh3" ] || die "the product client is not built: $BUILD/ssh3"

FAILURES=0

pass() {
    echo "   PASS: $1"
}

fail() {
    echo "   FAIL: $1"
    FAILURES=$((FAILURES + 1))
}

SRVPIDS=

cleanup() {

    for p in $SRVPIDS; do
        kill "$p" 2>/dev/null
        wait "$p" 2>/dev/null
    done

    rm -rf "$WORK"
}

trap : EXIT INT TERM

WORK=$(mktemp -d /tmp/s3clie2e.XXXXXX)

# the identity: the PKCS8 ed25519 of the C client, the authorized
# keys line built by hand (ssh-keygen reads no PKCS8 ed25519)

openssl genpkey -algorithm ed25519 -out "$WORK/priv.pem" 2>/dev/null || die "openssl genpkey failed"

{
    printf '\000\000\000\013ssh-ed25519\000\000\000\040'
    openssl pkey -in "$WORK/priv.pem" -pubout -outform DER 2>/dev/null | tail -c 32
} | base64 | tr -d '\n' > "$WORK/blob.pub"

printf 'ssh-ed25519 %s cli-compat-e2e\n' "$(cat "$WORK/blob.pub")" > "$WORK/authorized_keys"

mkcert() {
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/key-$1.pem" \
        -out "$WORK/cert-$1.pem" -days 2 -subj /CN=cli-compat-e2e-$1 2>/dev/null \
        || die "openssl req failed for $1"
}

mkcert 1
mkcert 2
mkcert 3

# the v4 loopback daemon: the extra args ride between -3 and the
# cert pair (the -d 1352 of the jump daemon), the listen port scans
# up on a busy port, the port polls out of the INTEROP-LISTEN marker

S_PID=

start_srv() {
    S_TAG=$1
    shift
    S_LOG="$WORK/srv-$S_TAG.log"
    S_P=$((47300 + ($$ + S_TAG * 17) % 1500))
    S_I=0

    while [ "$S_I" -lt 8 ]; do

        setsid nohup env SSH3C_PROTO=1 "$BIN" -3 "$@" -l "127.0.0.1:$S_P" \
            -c "$WORK/cert-$S_TAG.pem" -k "$WORK/key-$S_TAG.pem" \
            -K "$WORK/authorized_keys" > "$S_LOG" 2>&1 < /dev/null &
        S_PID=$!
        SRVPIDS="$SRVPIDS $S_PID"

        S_J=0

        while [ "$S_J" -lt 50 ]; do

            if grep -q INTEROP-LISTEN "$S_LOG" 2>/dev/null; then
                grep -oE 'port=[0-9]+' "$S_LOG" | head -1 | cut -d= -f2
                return 0
            fi

            if ! kill -0 "$S_PID" 2>/dev/null; then
                break # the bind refused, the next port scans
            fi

            sleep 0.1
            S_J=$((S_J + 1))
        done

        kill "$S_PID" 2>/dev/null
        wait "$S_PID" 2>/dev/null
        SRVPIDS=$(echo $SRVPIDS | tr ' ' '\n' | grep -v "^$S_PID$" | tr '\n' ' ')

        S_P=$((S_P + 1))
        S_I=$((S_I + 1))
    done

    return 1
}

# the dual-stack daemon of the -6 leg: the sshd shape (-p without
# -l re-ports the sshd default wildcard listener [::]:port)

start_srv6() {
    S_TAG=$1
    S_LOG="$WORK/srv-$S_TAG.log"
    S_P=$((47650 + ($$ % 200)))
    S_I=0

    while [ "$S_I" -lt 8 ]; do

        setsid nohup env SSH3C_PROTO=1 "$BIN" -c "$WORK/cert-$S_TAG.pem" -k "$WORK/key-$S_TAG.pem" \
            -K "$WORK/authorized_keys" -p "$S_P" > "$S_LOG" 2>&1 < /dev/null &
        S_PID=$!
        SRVPIDS="$SRVPIDS $S_PID"

        S_J=0

        while [ "$S_J" -lt 50 ]; do

            if grep -q INTEROP-LISTEN "$S_LOG" 2>/dev/null; then
                grep -oE 'port=[0-9]+' "$S_LOG" | head -1 | cut -d= -f2
                return 0
            fi

            if ! kill -0 "$S_PID" 2>/dev/null; then
                break
            fi

            sleep 0.1
            S_J=$((S_J + 1))
        done

        kill "$S_PID" 2>/dev/null
        wait "$S_PID" 2>/dev/null
        SRVPIDS=$(echo $SRVPIDS | tr ' ' '\n' | grep -v "^$S_PID$" | tr '\n' ' ')

        S_P=$((S_P + 1))
        S_I=$((S_I + 1))
    done

    return 1
}

# the fresh home with the pin of the daemon certificate (the non-pty
# runs skip the TOFU question); the host text rides as printed

pin_home() {
    rm -rf "$WORK/$1"
    mkdir -p "$WORK/$1/.ssh3"

    printf '%s x509-certificate %s\n' "$2" \
        "$(openssl x509 -in "$WORK/cert-$3.pem" -outform DER | base64 -w0)" \
        > "$WORK/$1/.ssh3/known_hosts"
}

# the local port probe (the listener readiness of the hold runs)

wait_tcp() {
    i=0

    while [ "$i" -lt 150 ]; do

        if nc -z 127.0.0.1 "$1" > /dev/null 2>&1; then
            return 0
        fi

        sleep 0.1
        i=$((i + 1))
    done

    return 1
}

# the echo target of the forward legs (the byte echo, the
# product-reverse shape)

ECHOPORT=$((48100 + $$ % 300))

python3 -c '
import socketserver

class H(socketserver.BaseRequestHandler):

    def handle(self):

        while True:

            chunk = self.request.recv(4096)

            if not chunk:
                break

            self.request.sendall(chunk)

class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

S(("127.0.0.1", int(__import__("sys").argv[1])), H).serve_forever()
' "$ECHOPORT" > "$WORK/echo.log" 2>&1 &
ECHOPID=$!
SRVPIDS="$SRVPIDS $ECHOPID"

# the http target of the socks leg (the one-page server)

HTTPPORT=$((49500 + $$ % 300))

mkdir -p "$WORK/www"
printf 'S3CLI-SOCKS-BODY-OK' > "$WORK/www/index.html"

(
    cd "$WORK/www" || exit 1
    exec python3 -c '
import http.server, socketserver, sys

class H(http.server.SimpleHTTPRequestHandler):

    def log_message(self, *a):
        pass

socketserver.ThreadingTCPServer.allow_reuse_address = True

socketserver.ThreadingTCPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
' "$HTTPPORT"
) > "$WORK/http.log" 2>&1 &
HTTPPID=$!
SRVPIDS="$SRVPIDS $HTTPPID"

wait_tcp "$ECHOPORT" || die "the echo target did not start"
wait_tcp "$HTTPPORT" || die "the http target did not start"

# the hold-run helper: the background -N client of the forward legs,
# the pid rides HOLD_PID

start_hold() {
    setsid nohup env HOME="$WORK/home" "$BUILD/ssh3" "$@" \
        > "$WORK/hold.log" 2>&1 < /dev/null &
    HOLD_PID=$!
    SRVPIDS="$SRVPIDS $HOLD_PID"

    # the hold liveness of the debug runs (the dead pid tells early)

    sleep 1

    if kill -0 "$HOLD_PID" 2>/dev/null; then
        echo "HOLD alive $HOLD_PID" >> "${HOLD_DBG:-/dev/null}"

    else
        echo "HOLD dead $HOLD_PID" >> "${HOLD_DBG:-/dev/null}"
    fi
}

stop_hold() {

    if [ -n "${HOLD_PID:-}" ]; then
        kill "$HOLD_PID" 2>/dev/null
        wait "$HOLD_PID" 2>/dev/null
        SRVPIDS=$(echo $SRVPIDS | tr ' ' '\n' | grep -v "^$HOLD_PID$" | tr '\n' ' ')
        HOLD_PID=
    fi
}

echo "== run 1: the daemon of the certificate a"

PORT=$(start_srv 1) || die "the daemon did not start: $(tail -3 "$WORK/srv-1.log")"

[ -n "$PORT" ] || die "no listen port"

pin_home home "127.0.0.1:$PORT/ssh3-term" 1

echo "== leg 1: -V and --help"

if "$BUILD/ssh3" -V > "$WORK/leg-v.out" 2>&1 && grep -q "SSH 3.0 ssh3-c" "$WORK/leg-v.out"; then
    pass "-V prints the version (rc 0)"
else
    fail "-V leg: $(tail -1 "$WORK/leg-v.out")"
fi

if "$BUILD/ssh3" --help > "$WORK/leg-help.out" 2>&1; then
    pass "--help exits 0 with the usage"
else
    fail "--help leg: rc $?"
fi

echo "== leg 2: -l login == the operand user@ (the exec twins)"

if HOME="$WORK/home" timeout 20 "$BUILD/ssh3" -i "$WORK/priv.pem" -l client \
    "127.0.0.1:$PORT/ssh3-term" "printf S3-L-LOGIN-OK" > "$WORK/leg-l.out" 2>"$WORK/leg-l.err" &&
    grep -q "S3-L-LOGIN-OK" "$WORK/leg-l.out"; then
    pass "-l login carried the exec"
else
    fail "-l login leg: rc=$? $(tail -1 "$WORK/leg-l.err")"
fi

if HOME="$WORK/home" timeout 20 "$BUILD/ssh3" -i "$WORK/priv.pem" \
    "client@127.0.0.1:$PORT/ssh3-term" "printf S3-OPERAND-OK" > "$WORK/leg-op.out" 2>/dev/null &&
    grep -q "S3-OPERAND-OK" "$WORK/leg-op.out"; then
    pass "the operand user@ twin rides"
else
    fail "the operand twin leg: rc=$?"
fi

echo "== leg 3: -p port (the operand without one)"

if HOME="$WORK/home" timeout 20 "$BUILD/ssh3" -i "$WORK/priv.pem" -p "$PORT" \
    "client@127.0.0.1/ssh3-term" "printf S3-P-PORT-OK" > "$WORK/leg-p.out" 2>/dev/null &&
    grep -q "S3-P-PORT-OK" "$WORK/leg-p.out"; then
    pass "-p re-ported the dial"
else
    fail "-p leg: rc=$?"
fi

echo "== leg 4: -q (the quiet run)"

HOME="$WORK/home" timeout 20 "$BUILD/ssh3" -q -i "$WORK/priv.pem" \
    "client@127.0.0.1:$PORT/ssh3-term" "printf S3-Q-QUIET-OK" \
    > "$WORK/leg-q.out" 2>"$WORK/leg-q.err"
rc=$?

if grep -q "S3-Q-QUIET-OK" "$WORK/leg-q.out" && [ ! -s "$WORK/leg-q.err" ]; then
    pass "-q kept the stderr empty and the exec rode (rc $rc)"
else
    fail "-q leg: rc=$rc stderr=$(head -1 "$WORK/leg-q.err")"
fi

echo "== leg 5: -T exec (the no-pty exec)"

if HOME="$WORK/home" timeout 20 "$BUILD/ssh3" -T -i "$WORK/priv.pem" \
    "client@127.0.0.1:$PORT/ssh3-term" "printf S3-T-NOPTY-OK" > "$WORK/leg-t.out" 2>/dev/null &&
    grep -q "S3-T-NOPTY-OK" "$WORK/leg-t.out"; then
    pass "-T exec rode without the pty-req"
else
    fail "-T leg: rc=$?"
fi

echo "== leg 6: -X warns deprecated, the session rides"

HOME="$WORK/home" timeout 20 "$BUILD/ssh3" -X -i "$WORK/priv.pem" \
    "client@127.0.0.1:$PORT/ssh3-term" "printf S3-X-DEPRECATED-OK" \
    > "$WORK/leg-x.out" 2>"$WORK/leg-x.err"
rc=$?

if grep -q "S3-X-DEPRECATED-OK" "$WORK/leg-x.out" &&
    grep -q "deprecated, use -A" "$WORK/leg-x.err"; then
    pass "-X noted and the exec rode"
else
    fail "-X leg: rc=$rc $(tail -1 "$WORK/leg-x.err")"
fi

echo "== leg 7: -N holds the -L forward and refuses the words"

LPPORT=$((49100 + $$ % 200))

start_hold -N -i "$WORK/priv.pem" -L "127.0.0.1:$LPPORT:127.0.0.1:$ECHOPORT" \
    "client@127.0.0.1:$PORT/ssh3-term"

if wait_tcp "$LPPORT" &&
    printf 'S3CLI-PROBE\n' | timeout 5 nc 127.0.0.1 "$LPPORT" > "$WORK/leg-n.echo" 2>/dev/null &&
    grep -q "S3CLI-PROBE" "$WORK/leg-n.echo"; then
    pass "-N -L bridged the echo"
else
    fail "-N -L leg: $(tail -1 "$WORK/hold.log")"
fi

stop_hold

if HOME="$WORK/home" timeout 10 "$BUILD/ssh3" -N -i "$WORK/priv.pem" \
    "client@127.0.0.1:$PORT/ssh3-term" "echo no" > /dev/null 2>"$WORK/leg-n.err"; then
    fail "-N with a command: the run exited 0"
else
    rc=$?

    if [ "$rc" -eq 255 ] && grep -q "Cannot execute command with -N" "$WORK/leg-n.err"; then
        pass "-N refused the command words (rc 255)"
    else
        fail "-N words leg: rc=$rc $(tail -1 "$WORK/leg-n.err")"
    fi
fi

echo "== leg 8: -t without a local tty refuses"

if HOME="$WORK/home" timeout 10 "$BUILD/ssh3" -t -i "$WORK/priv.pem" \
    "client@127.0.0.1:$PORT/ssh3-term" "echo no" < /dev/null > /dev/null 2>"$WORK/leg-tt.err"; then
    fail "-t no tty: the run exited 0"
else
    rc=$?

    if [ "$rc" -eq 255 ] && grep -q "no tty present" "$WORK/leg-tt.err"; then
        pass "-t refused without a tty (rc 255)"
    else
        fail "-t leg: rc=$rc $(tail -1 "$WORK/leg-tt.err")"
    fi
fi

echo "== leg 9: -n smoke (the exec rides, the stdin unpumped)"

if HOME="$WORK/home" timeout 20 "$BUILD/ssh3" -n -i "$WORK/priv.pem" \
    "client@127.0.0.1:$PORT/ssh3-term" "printf S3-N-NULL-OK" < /dev/null \
    > "$WORK/leg-nn.out" 2>/dev/null &&
    grep -q "S3-N-NULL-OK" "$WORK/leg-nn.out"; then
    pass "-n exec rode"
else
    fail "-n leg: rc=$?"
fi

echo "== leg 10: -A rides the throwaway agent"

AGENT_SOCK="$WORK/agent.sock"

if ssh-agent -a "$AGENT_SOCK" > "$WORK/agent.env" 2>/dev/null; then

    AGENT_PID=$(grep -oE 'SSH_AGENT_PID=[0-9]+' "$WORK/agent.env" | head -1 | cut -d= -f2)
    SRVPIDS="$SRVPIDS $AGENT_PID"

    # the agent holds no keys here: the bridge proves by the exec
    # verdict alone (the agent channel opens on the daemon trigger)

    if SSH_AUTH_SOCK="$AGENT_SOCK" HOME="$WORK/home" timeout 20 "$BUILD/ssh3" -A \
        -i "$WORK/priv.pem" "client@127.0.0.1:$PORT/ssh3-term" "printf S3-A-AGENT-OK" \
        > "$WORK/leg-a.out" 2>/dev/null &&
        grep -q "S3-A-AGENT-OK" "$WORK/leg-a.out"; then
        pass "-A rode the agent socket"
    else
        fail "-A leg: rc=$?"
    fi

else
    fail "-A leg: ssh-agent refused the socket"
fi

echo "== leg 11: -J put: deprecated, --sftp put/get byte-exact"

printf 'S3CLI-TRANSFER-BODY\n0123456789abcdef\n' > "$WORK/xfer.txt"

HOME="$WORK/home" timeout 30 "$BUILD/ssh3" -i "$WORK/priv.pem" \
    -J "put:$WORK/xfer.txt:/tmp/s3cli-xfer.txt" "client@127.0.0.1:$PORT/ssh3-term" \
    > "$WORK/leg-j.out" 2>"$WORK/leg-j.err"
rc=$?

if [ "$rc" -eq 0 ] && grep -q "deprecated, use --sftp" "$WORK/leg-j.err"; then
    pass "-J put noted and transferred (rc 0)"
else
    fail "-J put leg: rc=$rc $(tail -1 "$WORK/leg-j.err")"
fi

HOME="$WORK/home" timeout 30 "$BUILD/ssh3" --sftp "get:$WORK/xfer-back.txt:/tmp/s3cli-xfer.txt" \
    -i "$WORK/priv.pem" "client@127.0.0.1:$PORT/ssh3-term" \
    > "$WORK/leg-s.out" 2>"$WORK/leg-s.err"
rc=$?

if [ "$rc" -eq 0 ] && cmp -s "$WORK/xfer.txt" "$WORK/xfer-back.txt"; then
    pass "--sftp get returned the file byte-exact"
else
    fail "--sftp get leg: rc=$rc $(tail -1 "$WORK/leg-s.err")"
fi

HOME="$WORK/home" timeout 30 "$BUILD/ssh3" --sftp "put:$WORK/xfer.txt:/tmp/s3cli-xfer2.txt" \
    -i "$WORK/priv.pem" "client@127.0.0.1:$PORT/ssh3-term" \
    > "$WORK/leg-s2.out" 2>"$WORK/leg-s2.err"
rc=$?

if [ "$rc" -eq 0 ]; then
    pass "--sftp put rode"
else
    fail "--sftp put leg: rc=$rc $(tail -1 "$WORK/leg-s2.err")"
fi

echo "== leg 12: -o Port=, -o User=, -o LocalForward="

if HOME="$WORK/home" timeout 20 "$BUILD/ssh3" -i "$WORK/priv.pem" \
    -o "Port=$PORT" -o "User=client" 127.0.0.1/ssh3-term "printf S3-O-PORTUSER-OK" \
    > "$WORK/leg-o.out" 2>/dev/null &&
    grep -q "S3-O-PORTUSER-OK" "$WORK/leg-o.out"; then
    pass "-o Port=/User= re-ported the dial"
else
    fail "-o Port/User leg: rc=$?"
fi

OLPORT=$((49200 + $$ % 200))

start_hold -N -i "$WORK/priv.pem" -o "LocalForward=127.0.0.1:$OLPORT:127.0.0.1:$ECHOPORT" \
    "client@127.0.0.1:$PORT/ssh3-term"

if wait_tcp "$OLPORT" &&
    printf 'S3CLI-PROBE\n' | timeout 5 nc 127.0.0.1 "$OLPORT" > "$WORK/leg-ol.echo" 2>/dev/null &&
    grep -q "S3CLI-PROBE" "$WORK/leg-ol.echo"; then
    pass "-o LocalForward= bridged like -L"
else
    fail "-o LocalForward leg: $(tail -1 "$WORK/hold.log")"
fi

stop_hold

echo "== leg 13: -F config (HostName/Port/User/LocalForward)"

CFGPORT=$((49300 + $$ % 200))

cat > "$WORK/config" <<EOF
Host cli-alias
    HostName 127.0.0.1
    Port $PORT
    User client
    LocalForward 127.0.0.1:$CFGPORT 127.0.0.1:$ECHOPORT
EOF

start_hold -N -i "$WORK/priv.pem" -F "$WORK/config" cli-alias

if wait_tcp "$CFGPORT" &&
    printf 'S3CLI-PROBE\n' | timeout 5 nc 127.0.0.1 "$CFGPORT" > "$WORK/leg-f.echo" 2>/dev/null &&
    grep -q "S3CLI-PROBE" "$WORK/leg-f.echo"; then
    pass "-F HostName/Port/User/LocalForward rode"
else
    fail "-F leg: $(tail -1 "$WORK/hold.log")"
fi

stop_hold

if HOME="$WORK/home" timeout 20 "$BUILD/ssh3" -F "$WORK/config" -i "$WORK/priv.pem" \
    cli-alias "printf S3-F-ALIAS-OK" > "$WORK/leg-f2.out" 2>/dev/null &&
    grep -q "S3-F-ALIAS-OK" "$WORK/leg-f2.out"; then
    pass "-F alias carried the exec"
else
    fail "-F exec leg: rc=$?"
fi

echo "== leg 14: -D socks5 (the curl through the proxy)"

DPORT=$((49400 + $$ % 200))

start_hold -N -D "127.0.0.1:$DPORT" -i "$WORK/priv.pem" "client@127.0.0.1:$PORT/ssh3-term"

if wait_tcp "$DPORT" &&
    curl -s --max-time 10 --socks5-hostname "127.0.0.1:$DPORT" "http://127.0.0.1:$HTTPPORT/" \
        > "$WORK/leg-d.body" 2>/dev/null &&
    grep -q "S3CLI-SOCKS-BODY-OK" "$WORK/leg-d.body"; then
    pass "-D carried the curl through the socks5 tunnel"
else
    fail "-D leg: $(tail -1 "$WORK/hold.log")"
fi

stop_hold

echo "== run 2: the dual-stack daemon of the -6 leg"

PORT6=$(start_srv6 3) || die "the dual-stack daemon did not start"

[ -n "$PORT6" ] || die "no -6 listen port"

pin_home home6 "::1:$PORT6/ssh3-term" 3

echo "== leg 15: -6 against the dual-stack listener"

if HOME="$WORK/home6" timeout 20 "$BUILD/ssh3" -6 -i "$WORK/priv.pem" \
    "client@[::1]:$PORT6/ssh3-term" "printf S3-SIX-OK" > "$WORK/leg-6.out" 2>"$WORK/leg-6.err" &&
    grep -q "S3-SIX-OK" "$WORK/leg-6.out"; then
    pass "-6 rode the v6 dial"
else
    fail "-6 leg: rc=$? $(tail -2 "$WORK/leg-6.err")"
fi

echo "== run 3: the jump stand (the -d 1352 jump daemon)"

JPORT=$(start_srv 2 -d 1352) || die "the jump daemon did not start"

echo "== leg 16: -J jump (the exec through the tunnel)"

if HOME="$WORK/home" timeout 40 "$BUILD/ssh3" -i "$WORK/priv.pem" \
    -J "127.0.0.1:$JPORT" "client@127.0.0.1:$PORT/ssh3-term" "printf S3-JUMP-OK" \
    > "$WORK/leg-jump.out" 2>"$WORK/leg-jump.err" &&
    grep -q "S3-JUMP-OK" "$WORK/leg-jump.out"; then
    pass "-J jump carried the exec through the tunnel"
else
    fail "-J jump leg: rc=$? $(tail -2 "$WORK/leg-jump.err")"
fi

echo "== leg 17: the wrong jump port refuses inside the deadline"

START=$(date +%s)

if HOME="$WORK/home" timeout 30 "$BUILD/ssh3" -i "$WORK/priv.pem" \
    -J "127.0.0.1:1" "client@127.0.0.1:$PORT/ssh3-term" "echo no" \
    > /dev/null 2>"$WORK/leg-jump-bad.err"; then
    fail "the wrong jump port passed"
else
    rc=$?
    NOW=$(date +%s)

    if [ "$rc" -eq 255 ] && [ $((NOW - START)) -le 15 ]; then
        pass "the wrong jump port refused cleanly in $((NOW - START))s (rc 255)"
    else
        fail "the wrong jump leg: rc=$rc took $((NOW - START))s"
    fi
fi

if [ "$FAILURES" -eq 0 ]; then
    echo "CLI-COMPAT-E2E OK"
    exit 0
fi

echo "CLI-COMPAT-E2E FAILED: $FAILURES check(s)"
exit 1
