#!/bin/sh
# the server CLI compat e2e (P8 1a-1c, the sshd(8) canon wave): the
# daemon speaks the sshd command-line shapes where the functionality
# matches
#
#   1. --help prints the usage on stdout and exits 0; the short -h
#      serves the host key now, a bare -h (and any unknown short)
#      draws the usage on stderr with exit 1
#   2. -h keyfile ≡ -k keyfile: the daemon comes up and serves
#   3. -p port re-ports the default listener ([::]:PORT, no -l at
#      all), the bare -l address (-l 127.0.0.1 + -p) and the explicit
#      port of -l addr:port wins over -p
#   4. -o PermitOpen=none refuses the dial (the DENIED marker),
#      -o PermitOpen=any overrides a restrictive SSH3_PERMIT_OPEN env
#      (the case-insensitive any)
#   5. -o GatewayPorts=y keeps the wildcard reverse bind (bind=0.0.0.0)
#   6. -o MaxStartups=3 serves under the cap, -o MaxStartups=0 (the
#      kill-switch) answers 503, the start:rate:full form stops the
#      daemon with the config error
#   7. -o AuthorizedKeysFile= serves the pubkey login (the plain
#      path, the %u token, and the %h token of a real account)
#   8. -o ChrootDirectory= jails the sftp into it (the root daemon,
#      the put/get roundtrip inside)
#   9. the root-only defaults: no -l no -p serves [::]:443, the bare
#      -l address serves the 443 port
#
# the verdicts: CLI-COMPAT-SRV-E2E OK / FAILED, the INTEROP-* markers
# of the C runners on the way
#
# usage: interop/cli-compat-srv-e2e.sh   (WSL; the sudo legs need the
# passwordless sudo, without it they SKIP)
# requires: the C runners (cmake --build build/linux-release), python3
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD=${BUILD:-$ROOT/build/linux-release}
BIN=${SSH3C_SERVER_BIN:-$BUILD/ssh3-server}

die() {
    echo "cli-compat-srv-e2e: $1" >&2
    exit 1
}

[ -x "$BIN" ] || die "the daemon is not built: $BIN"
[ -x "$BUILD/s3interop_client" ] || die "s3interop_client is not built"

FAILURES=0

pass() {
    echo "   PASS: $1"
}

fail() {
    echo "   FAIL: $1"
    FAILURES=$((FAILURES + 1))
}

skip() {
    echo "   SKIP: $1"
}

SRVPID=
CLIPID=

cleanup() {

    if [ -n "$CLIPID" ]; then
        kill "$CLIPID" 2>/dev/null
        wait "$CLIPID" 2>/dev/null
    fi

    if [ -n "$SRVPID" ]; then
        kill "$SRVPID" 2>/dev/null
        wait "$SRVPID" 2>/dev/null
    fi

    if [ -n "${SUDO_PID:-}" ]; then
        sudo -n kill -TERM "$SUDO_PID" >/dev/null 2>&1
    fi

    if [ -n "${ECHO1_PID:-}" ]; then
        kill "$ECHO1_PID" 2>/dev/null
    fi

    if [ -n "${ECHO2_PID:-}" ]; then
        kill "$ECHO2_PID" 2>/dev/null
    fi

    if [ -n "${AK_USER:-}" ]; then
        sudo -n userdel -r "$AK_USER" >/dev/null 2>&1
    fi

    rm -rf "$WORK"
}

trap cleanup EXIT INT TERM

WORK=$(mktemp -d /tmp/s3clicompat.XXXXXX)

# the loopback echo services: the server-side dial target on 19981
# (the PermitOpen legs) and the client-side relay target on 19181
# (the -R leg of GatewayPorts)

cat > "$WORK/echo_srv.py" <<'PYEOF'
import socket
import sys
import threading

port = int(sys.argv[1])

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
s.listen(8)
print("ECHO-READY tcp", flush=True)


def handle(c):
    try:
        while 1:
            d = c.recv(65536)
            if not d:
                break
            c.sendall(d)
    finally:
        c.close()


while 1:
    c, _ = s.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
PYEOF

setsid nohup python3 "$WORK/echo_srv.py" 19981 > "$WORK/echo1.log" 2>&1 < /dev/null &
ECHO1_PID=$!

setsid nohup python3 "$WORK/echo_srv.py" 19181 > "$WORK/echo2.log" 2>&1 < /dev/null &
ECHO2_PID=$!

wait_echo() {
    i=0

    while [ "$i" -lt 50 ]; do

        if grep -q ECHO-READY "$1" 2>/dev/null; then
            return 0
        fi

        sleep 0.1
        i=$((i + 1))
    done

    return 1
}

wait_echo "$WORK/echo1.log" || die "the dial echo did not start"
wait_echo "$WORK/echo2.log" || die "the relay echo did not start"

# the daemon leg: the fresh log, the flags after the fixed ones

start_srv() {
    env SSH3C_PROTO=1 "$BIN" -3 -c "$WORK/cert.pem" -h "$WORK/key.pem" \
        "$@" > "$WORK/srv.log" 2>&1 < /dev/null &
    SRVPID=$!

    i=0

    while [ "$i" -lt 50 ]; do

        if grep -q INTEROP-LISTEN "$WORK/srv.log" 2>/dev/null; then
            return 0
        fi

        sleep 0.1
        i=$((i + 1))
    done

    return 1
}

# the same under sudo (the root-only legs)

start_srv_sudo() {
    sudo -n env SSH3C_PROTO=1 "$BIN" -3 -c "$WORK/cert.pem" -h "$WORK/key.pem" \
        "$@" > "$WORK/srv.log" 2>&1 < /dev/null &
    SUDO_PID=$!
    SRVPID=$SUDO_PID

    i=0

    while [ "$i" -lt 50 ]; do

        if grep -q INTEROP-LISTEN "$WORK/srv.log" 2>/dev/null; then
            return 0
        fi

        sleep 0.1
        i=$((i + 1))
    done

    return 1
}

stop_srv() {

    if [ -n "$SRVPID" ]; then
        kill "$SRVPID" 2>/dev/null
        wait "$SRVPID" 2>/dev/null
        SRVPID=
        SUDO_PID=
    fi
}

srv_port() {
    grep -oE 'port=[0-9]+' "$WORK/srv.log" | cut -d= -f2
}

# the listen marker lands in one write, but the daemon start under
# the drvfs-backed binary can lag: poll the port out

wait_port() {
    i=0

    while [ "$i" -lt 50 ]; do
        PORT=$(srv_port)

        [ -n "$PORT" ] && return 0

        sleep 0.1
        i=$((i + 1))
    done

    return 1
}

# the plain exec run of one daemon: rc 0 and the verdict marker

run_exec() {
    HOME="$WORK" timeout 30 "$BUILD/s3interop_client" -3 -C -S exec -e 'true' \
        -a "127.0.0.1:$1" -t 20000 > "$WORK/cli.log" 2>&1
}

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/key.pem" -out "$WORK/cert.pem" \
    -days 30 -subj /CN=cli-compat-srv-e2e 2>/dev/null || die "openssl req failed"

echo "== leg 1: --help on stdout exits 0, the short keys keep the strict shape"

"$BIN" --help > "$WORK/help.out" 2> "$WORK/help.err"
RC=$?

if [ "$RC" -eq 0 ] && grep -q "usage: ssh3-server" "$WORK/help.out" &&
    grep -q -- "-h" "$WORK/help.out" && grep -q -- "-o" "$WORK/help.out" &&
    [ ! -s "$WORK/help.err" ]; then
    pass "--help printed the usage on stdout and exited 0"
else
    fail "--help leg: rc=$RC $(head -3 "$WORK/help.err")"
fi

"$BIN" -Z -c "$WORK/cert.pem" -h "$WORK/key.pem" > "$WORK/bad.out" 2> "$WORK/bad.err"
RC=$?

if [ "$RC" -eq 1 ] && grep -q "usage: ssh3-server" "$WORK/bad.err" &&
    [ ! -s "$WORK/bad.out" ]; then
    pass "the unknown short key draws the usage on stderr with exit 1"
else
    fail "the unknown key leg: rc=$RC"
fi

"$BIN" -h > "$WORK/badh.out" 2> "$WORK/badh.err"
RC=$?

if [ "$RC" -eq 1 ] && grep -q "usage: ssh3-server" "$WORK/badh.err"; then
    pass "the bare -h (no keyfile) refuses: the help moved off the short key"
else
    fail "the bare -h leg: rc=$RC"
fi

echo "== leg 2: -h keyfile raises the daemon (the -k alias)"

start_srv -l 127.0.0.1:0 || die "the daemon did not start: $(tail -3 "$WORK/srv.log")"

wait_port || die "no listen port: $(tail -3 "$WORK/srv.log")"

if run_exec "$PORT" && grep -q "INTEROP-EXEC-OK exit=0" "$WORK/cli.log"; then
    pass "the -h keyfile daemon serves the exec session"
else
    fail "the -h leg: $(tail -3 "$WORK/cli.log")"
fi

stop_srv

echo "== leg 3: -p PORT re-ports the default listener (no -l at all)"

start_srv -p 48511 || die "the daemon did not start: $(tail -3 "$WORK/srv.log")"

wait_port || die "no listen port: $(tail -3 "$WORK/srv.log")"

if [ "$PORT" = "48511" ] && run_exec "$PORT" &&
    grep -q "INTEROP-EXEC-OK exit=0" "$WORK/cli.log"; then
    pass "the daemon listens on [::]:48511, not the 443 default"
else
    fail "the -p default leg: port=$PORT $(tail -3 "$WORK/cli.log")"
fi

stop_srv

echo "== leg 4: -l addr + -p compose the port into the bare address"

start_srv -l 127.0.0.1 -p 48512 || die "the daemon did not start: $(tail -3 "$WORK/srv.log")"

wait_port || die "no listen port: $(tail -3 "$WORK/srv.log")"

if [ "$PORT" = "48512" ] && run_exec "$PORT" &&
    grep -q "INTEROP-EXEC-OK exit=0" "$WORK/cli.log"; then
    pass "the bare -l 127.0.0.1 listened on 127.0.0.1:48512"
else
    fail "the -l + -p leg: port=$PORT"
fi

stop_srv

echo "== leg 5: the explicit port of -l addr:port wins over -p"

start_srv -l 127.0.0.1:48513 -p 59999 || die "the daemon did not start: $(tail -3 "$WORK/srv.log")"

wait_port || die "no listen port: $(tail -3 "$WORK/srv.log")"

if [ "$PORT" = "48513" ]; then
    pass "the explicit 48513 stayed, the -p 59999 lost"
else
    fail "the explicit-port leg: port=$PORT want 48513"
fi

stop_srv

echo "== leg 6: the bad -p values stop the daemon (the sshd bad port)"

"$BIN" -3 -c "$WORK/cert.pem" -h "$WORK/key.pem" -l 127.0.0.1:0 -p 0 \
    > "$WORK/p0.log" 2>&1 </dev/null
RC=$?

if [ "$RC" -ne 0 ] && grep -q 'bad -p port "0"' "$WORK/p0.log"; then
    pass "-p 0 refused"
else
    fail "the -p 0 leg: rc=$RC"
fi

echo "== leg 7: the unknown -o option names the supported set"

"$BIN" -3 -c "$WORK/cert.pem" -h "$WORK/key.pem" -l 127.0.0.1:0 \
    -o PermitForward=yes > "$WORK/o-bad.log" 2>&1 </dev/null
RC=$?

if [ "$RC" -ne 0 ] && grep -q "unsupported -o option \"PermitForward\"" "$WORK/o-bad.log" &&
    grep -q "PermitOpen, PermitListen, GatewayPorts, MaxStartups" "$WORK/o-bad.log" &&
    ! grep -q INTEROP-LISTEN "$WORK/o-bad.log"; then
    pass "the unknown -o key refused with the supported list"
else
    fail "the unknown -o leg: rc=$RC $(tail -3 "$WORK/o-bad.log")"
fi

echo "== leg 8: -o PermitOpen=none refuses the dial (the DENIED marker)"

start_srv -o PermitOpen=none -l 127.0.0.1:0 ||
    die "the daemon did not start: $(tail -3 "$WORK/srv.log")"

wait_port || die "no listen port: $(tail -3 "$WORK/srv.log")"

HOME="$WORK" timeout 30 "$BUILD/s3interop_client" -3 -C -F tcp=@19981 \
    -a "127.0.0.1:$PORT" -t 20000 > "$WORK/leg8.log" 2>&1

if [ $? -ne 0 ] &&
    grep -q "INTEROP-FWD-TCP-DENIED target=127.0.0.1:19981" "$WORK/srv.log"; then
    pass "the none policy refused the dial before any socket"
else
    fail "the PermitOpen=none leg: $(tail -3 "$WORK/leg8.log")"
fi

stop_srv

echo "== leg 9: -o PermitOpen=any overrides the restrictive env (the ANY case)"

# the exported env default rides into the daemon, the stop unsets it

SSH3_PERMIT_OPEN='127.0.0.1:19982'
export SSH3_PERMIT_OPEN

start_srv -o PermitOpen=ANY -l 127.0.0.1:0 ||
    die "the daemon did not start: $(tail -3 "$WORK/srv.log")"

wait_port || die "no listen port: $(tail -3 "$WORK/srv.log")"

HOME="$WORK" timeout 30 "$BUILD/s3interop_client" -3 -C -F tcp=@19981 \
    -a "127.0.0.1:$PORT" -t 20000 > "$WORK/leg9.log" 2>&1

if [ $? -eq 0 ] && grep -q "INTEROP-FWD-TCP-OK bytes=" "$WORK/leg9.log" &&
    grep -q "INTEROP-FWD-TCP-OPEN target=127.0.0.1:19981" "$WORK/srv.log"; then
    pass "the any policy kept the dial unrestricted despite the env"
else
    fail "the PermitOpen=any leg: $(tail -3 "$WORK/leg9.log")"
fi

stop_srv

unset SSH3_PERMIT_OPEN

echo "== leg 10: -o GatewayPorts=y keeps the wildcard reverse bind"

start_srv -o GatewayPorts=y -l 127.0.0.1:0 ||
    die "the daemon did not start: $(tail -3 "$WORK/srv.log")"

wait_port || die "no listen port: $(tail -3 "$WORK/srv.log")"

HOME="$WORK" env SSH3C_PROTO=1 "$BUILD/s3interop_client" -3 -a "127.0.0.1:$PORT" \
    -R "*:0:127.0.0.1:19181" -t 15000 > "$WORK/leg10.log" 2>&1 < /dev/null &
CLIPID=$!

RPORT=

i=0

while [ "$i" -lt 100 ]; do
    RPORT=$(grep -oE 'INTEROP-RFWD-OK spec=0 port=[0-9]+' "$WORK/leg10.log" 2>/dev/null |
        cut -d= -f3)
    [ -n "$RPORT" ] && break
    sleep 0.1
    i=$((i + 1))
done

if grep -q "INTEROP-RFWD-OPEN kind=tcp bind=0.0.0.0:0" "$WORK/srv.log" &&
    [ -n "$RPORT" ]; then
    pass "the y policy bound the wildcard 0.0.0.0 (port $RPORT)"
else
    fail "the GatewayPorts=y leg: $(grep RFWD-OPEN "$WORK/srv.log" | tail -2)"
fi

kill "$CLIPID" 2>/dev/null
wait "$CLIPID" 2>/dev/null
CLIPID=

stop_srv

echo "== leg 11: -o MaxStartups=3 serves under the cap"

start_srv -o MaxStartups=3 -l 127.0.0.1:0 ||
    die "the daemon did not start: $(tail -3 "$WORK/srv.log")"

wait_port || die "no listen port: $(tail -3 "$WORK/srv.log")"

if run_exec "$PORT" && grep -q "INTEROP-EXEC-OK exit=0" "$WORK/cli.log"; then
    pass "the flat cap 3 keeps the exec session riding"
else
    fail "the MaxStartups=3 leg: $(tail -3 "$WORK/cli.log")"
fi

stop_srv

echo "== leg 12: -o MaxStartups=0 is the kill-switch (the 503)"

start_srv -o MaxStartups=0 -l 127.0.0.1:0 ||
    die "the daemon did not start: $(tail -3 "$WORK/srv.log")"

wait_port || die "no listen port: $(tail -3 "$WORK/srv.log")"

HOME="$WORK" timeout 30 "$BUILD/s3interop_client" -3 -C -S exec -e 'true' \
    -a "127.0.0.1:$PORT" -t 20000 > "$WORK/leg12.log" 2>&1

if grep -q "INTEROP-H3-STATUS 503" "$WORK/leg12.log"; then
    pass "the zero cap answered 503 before any auth work"
else
    fail "the MaxStartups=0 leg: $(tail -3 "$WORK/leg12.log")"
fi

stop_srv

echo "== leg 13: the start:rate:full form is the config error"

"$BIN" -3 -c "$WORK/cert.pem" -h "$WORK/key.pem" -l 127.0.0.1:0 \
    -o MaxStartups=10:30:60 > "$WORK/leg13.log" 2>&1 </dev/null
RC=$?

if [ "$RC" -ne 0 ] &&
    grep -q "start:rate:full form .* is not supported" "$WORK/leg13.log" &&
    ! grep -q INTEROP-LISTEN "$WORK/leg13.log"; then
    pass "the start:rate:full form named and refused, no listener"
else
    fail "the start:rate:full leg: rc=$RC $(tail -3 "$WORK/leg13.log")"
fi

echo "== leg 14: -o AuthorizedKeysFile= serves the pubkey login"

# the C client identity rides the PEM key, the authorized_keys line
# carries the ssh wire blob (the pubkey-e2e shape)

openssl genpkey -algorithm ed25519 -out "$WORK/id_c.pem" 2>/dev/null || die "openssl genpkey"

AK_BLOB=$(
    {
        printf '\000\000\000\013ssh-ed25519\000\000\000\040'
        openssl pkey -in "$WORK/id_c.pem" -pubout -outform DER 2>/dev/null | tail -c 32
    } | base64 | tr -d '\n'
)

printf 'ssh-ed25519 %s cli-compat\n' "$AK_BLOB" > "$WORK/authorized_keys"
cp "$WORK/authorized_keys" "$WORK/keys-bob"

start_srv -o AuthorizedKeysFile="$WORK/authorized_keys" -l 127.0.0.1:0 ||
    die "the daemon did not start: $(tail -3 "$WORK/srv.log")"

wait_port || die "no listen port: $(tail -3 "$WORK/srv.log")"

HOME="$WORK" timeout 30 "$BUILD/s3interop_client" -3 -C -S exec -e 'true' \
    -K "$WORK/id_c.pem" -U bob -a "127.0.0.1:$PORT" -t 20000 > "$WORK/leg14.log" 2>&1

if [ $? -eq 0 ] && grep -q "INTEROP-EXEC-OK exit=0" "$WORK/leg14.log"; then
    pass "the plain path of AuthorizedKeysFile served the pubkey verdict"
else
    fail "the AuthorizedKeysFile leg: $(tail -3 "$WORK/leg14.log")"
fi

stop_srv

start_srv -o AuthorizedKeysFile="$WORK/keys-%u" -l 127.0.0.1:0 ||
    die "the daemon did not start: $(tail -3 "$WORK/srv.log")"

wait_port || die "no listen port: $(tail -3 "$WORK/srv.log")"

HOME="$WORK" timeout 30 "$BUILD/s3interop_client" -3 -C -S exec -e 'true' \
    -K "$WORK/id_c.pem" -U bob -a "127.0.0.1:$PORT" -t 20000 > "$WORK/leg14b.log" 2>&1

if [ $? -eq 0 ] && grep -q "INTEROP-EXEC-OK exit=0" "$WORK/leg14b.log"; then
    pass "the %u token expanded to the keys-bob file"
else
    fail "the %u leg: $(tail -3 "$WORK/leg14b.log")"
fi

stop_srv

# the root-only legs: the %h token, the ChrootDirectory jail and the
# 443 defaults.  Without the passwordless sudo they SKIP

HAVE_SUDO=0

if sudo -n true 2>/dev/null; then
    HAVE_SUDO=1
fi

if [ "$HAVE_SUDO" -eq 1 ]; then

    AK_USER=s3clicompat

    sudo -n userdel -r "$AK_USER" >/dev/null 2>&1
    sudo -n useradd -m -s /bin/sh "$AK_USER" || die "useradd $AK_USER failed"

    AK_HOME=$(eval echo "~$AK_USER")

    echo "== leg 15: the %h token resolves the home of the session user"

    sudo -n mkdir -p "$AK_HOME/.ssh3"
    sudo -n cp "$WORK/authorized_keys" "$AK_HOME/.ssh3/authorized_keys"

    start_srv -o AuthorizedKeysFile='%h/.ssh3/authorized_keys' -l 127.0.0.1:0 ||
        die "the daemon did not start: $(tail -3 "$WORK/srv.log")"

    wait_port || die "no listen port: $(tail -3 "$WORK/srv.log")"

    HOME="$WORK" timeout 30 "$BUILD/s3interop_client" -3 -C -S exec -e 'true' \
        -K "$WORK/id_c.pem" -U "$AK_USER" -a "127.0.0.1:$PORT" -t 20000 \
        > "$WORK/leg15.log" 2>&1

    if [ $? -eq 0 ] && grep -q "INTEROP-EXEC-OK exit=0" "$WORK/leg15.log"; then
        pass "the %h token expanded to $AK_HOME/.ssh3/authorized_keys"
    else
        fail "the %h leg: $(tail -3 "$WORK/leg15.log")"
    fi

    stop_srv

    echo "== leg 16: -o ChrootDirectory= jails the sftp (the root daemon)"

    printf '%s:s3clicompat-pass\n' "$AK_USER" > "$WORK/passfile"
    chmod 644 "$WORK/passfile"

    mkdir -p "$WORK/jail/docs"
    printf 'jail-payload\n' > "$WORK/jail-docs-up.txt"
    cp "$WORK/jail-docs-up.txt" "$WORK/jail/docs/up.txt"
    chmod 755 "$WORK/jail" "$WORK/jail/docs"

    start_srv_sudo -l 127.0.0.1:0 -P "$WORK/passfile" --enable-password-login \
        -o ChrootDirectory="$WORK/jail" ||
        die "the daemon did not start: $(tail -3 "$WORK/srv.log")"

    wait_port || die "no listen port: $(tail -3 "$WORK/srv.log")"

    if grep -q "per-user Match is not supported" "$WORK/srv.log"; then
        pass "the one-time simplified warn is on the startup log"
    else
        fail "no ChrootDirectory simplified warn"
    fi

    printf 'jail-payload\n' > "$WORK/jail-put.txt"

    timeout 30 "$BUILD/s3interop_client" -3 -J "put:$WORK/jail-put.txt:docs/put.txt" \
        -U "$AK_USER:s3clicompat-pass" -a "127.0.0.1:$PORT" -t 20000 \
        > "$WORK/leg16.log" 2>&1

    if [ $? -eq 0 ] && grep -q "INTEROP-SFTP-OK mode=put" "$WORK/leg16.log" &&
        grep -q "INTEROP-SFTP-OPEN home=$WORK/jail" "$WORK/srv.log"; then
        pass "the put jailed into $WORK/jail"
    else
        fail "the ChrootDirectory put leg: $(tail -3 "$WORK/leg16.log")"
    fi

    timeout 30 "$BUILD/s3interop_client" -3 -J "get:$WORK/jail-get.txt:docs/up.txt" \
        -U "$AK_USER:s3clicompat-pass" -a "127.0.0.1:$PORT" -t 20000 \
        > "$WORK/leg16b.log" 2>&1

    if [ $? -eq 0 ] && grep -q "INTEROP-SFTP-OK mode=get" "$WORK/leg16b.log" &&
        cmp -s "$WORK/jail/docs/up.txt" "$WORK/jail-get.txt"; then
        pass "the get roundtrip stayed inside the jail"
    else
        fail "the ChrootDirectory get leg: $(tail -3 "$WORK/leg16b.log")"
    fi

    stop_srv

    echo "== leg 17: the root defaults - no -l no -p serves 443, the bare -l too"

    start_srv_sudo || die "the daemon did not start: $(tail -3 "$WORK/srv.log")"

    wait_port || die "no listen port: $(tail -3 "$WORK/srv.log")"

    if [ "$PORT" = "443" ]; then
        pass "the default listener bound [::]:443"
    else
        fail "the default-listener leg: port=$PORT want 443"
    fi

    stop_srv

    start_srv_sudo -l 127.0.0.1 ||
        die "the daemon did not start: $(tail -3 "$WORK/srv.log")"

    wait_port || die "no listen port: $(tail -3 "$WORK/srv.log")"

    if [ "$PORT" = "443" ]; then
        pass "the bare -l 127.0.0.1 took the 443 default port"
    else
        fail "the bare -l leg: port=$PORT want 443"
    fi

    stop_srv

else
    echo "== legs 15-17 (the %h token, the ChrootDirectory jail, the 443"
    echo "   defaults): SKIP, no passwordless sudo"
fi

if [ "$FAILURES" -eq 0 ]; then
    echo "CLI-COMPAT-SRV-E2E OK"
    exit 0
fi

echo "CLI-COMPAT-SRV-E2E FAILED: $FAILURES check(s)"
exit 1
