#!/bin/sh
# the session parking lot e2e (the wave 16): the interactive session
# of the first dial parks when the connection dies (the ~. escape
# disconnect rides the teardown CC), the re-dial with the same
# session token attaches the OLD shell - the output produced while
# parked replays through the ring, the fresh dial (no token) rides a
# fresh session.  Verdict: SESSION-PARK-E2E OK / FAILED

set -u

# the build rides the tree of the script (the S3SP_BUILD pin overrides
# for the debug runs against a foreign build)

BUILD=${S3SP_BUILD:-$(cd "$(dirname "$0")/.." && pwd)/build/linux-release}
BIN=$BUILD/ssh3-server
CLI=$BUILD/ssh3

# the optional pin of the tree (the debug run): S3OPT_WORK + S3OPT_KEEP

if [ -n "${S3OPT_WORK:-}" ]; then
    WORK=$S3OPT_WORK
    rm -rf "$WORK"
    mkdir -p "$WORK"
else
    WORK=$(mktemp -d /tmp/s3parke2e.XXXXXX)
fi

FAILURES=0

pass() {
    echo "   PASS: $1"
}

fail() {
    echo "   FAIL: $1"
    FAILURES=$((FAILURES + 1))
}

die() {
    echo "session-park-e2e: $1" >&2
    exit 1
}

[ -x "$BIN" ] || die "the daemon is not built: $BIN"
[ -x "$CLI" ] || die "the product client is not built: $CLI"

SRVPID=
SRVPORT=
SRVLOG=

CLI1PID=

cleanup() {

    if [ -n "$CLI1PID" ]; then
        kill -9 "$CLI1PID" 2>/dev/null
        CLI1PID=
    fi

    if [ -n "$SRVPID" ]; then
        kill "$SRVPID" 2>/dev/null
        wait "$SRVPID" 2>/dev/null
        SRVPID=
    fi

    [ -n "${S3OPT_KEEP:-}" ] || rm -rf "$WORK"
}

trap cleanup EXIT INT TERM

# the identity: the PKCS8 ed25519 of the client (the cert-verify
# shape), the authorized_keys line built by hand

openssl genpkey -algorithm ed25519 -out "$WORK/priv.pem" 2>/dev/null || die "openssl genpkey failed"

{
    printf '\000\000\000\013ssh-ed25519\000\000\000\040'
    openssl pkey -in "$WORK/priv.pem" -pubout -outform DER 2>/dev/null | tail -c 32
} | base64 | tr -d '\n' > "$WORK/blob.pub"

printf 'ssh-ed25519 %s session-park-e2e\n' "$(cat "$WORK/blob.pub")" > "$WORK/authorized_keys"

# the daemon certificate: the self-signed pair, the client legs ride
# -insecure (the park semantics need no trust)

# the daemon port: the free ephemeral pick (the bind race is the
# price of the one-shot run)

SRVPORT=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()') ||
    die "the free port pick failed"

SRVLOG="$WORK/srv.log"

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/srv.key" -out "$WORK/srv.pem" \
    -days 2 -subj //CN=session-park-e2e 2>/dev/null || die "the daemon cert failed"

setsid nohup env SSH3C_PROTO=1 SSH3_SESSION_PARK_SECONDS=30 "$BIN" -3 -l "127.0.0.1:$SRVPORT" \
    -c "$WORK/srv.pem" -k "$WORK/srv.key" -K "$WORK/authorized_keys" > "$SRVLOG" 2>&1 < /dev/null &
SRVPID=$!

i=0

while [ "$i" -lt 50 ]; do

    if grep -q INTEROP-LISTEN "$SRVLOG" 2>/dev/null; then
        break
    fi

    if ! kill -0 "$SRVPID" 2>/dev/null; then
        die "the daemon died on the start ($(tail -2 "$SRVLOG" | tr '\n' ' '))"
    fi

    sleep 0.1
    i=$((i + 1))
done

grep -q INTEROP-LISTEN "$SRVLOG" || die "the daemon did not announce the listener"

# the fifo of the first dial: the stdin lives (the shell stays open
# while the commands feed), the ~. escape disconnects

mkfifo "$WORK/in.fifo"

S3_SESSION_TOKEN=aabbccdd00112233445566778899aabb \
    setsid nohup "$CLI" -insecure -i "$WORK/priv.pem" \
    "client@127.0.0.1:$SRVPORT/ssh3-term" < "$WORK/in.fifo" > "$WORK/run1.out" 2>&1 &
CLI1PID=$!

# the fifo opens when the client reads it

exec 9> "$WORK/in.fifo"

i=0

while [ "$i" -lt 50 ]; do

    if grep -q INTEROP-LISTEN "$SRVLOG" 2>/dev/null && [ -n "$(cat "$WORK/run1.out" 2>/dev/null)" ]; then
        break
    fi

    sleep 0.1
    i=$((i + 1))
done

# the old session streams the marker series: the kill lands mid-run,
# the head of the series dies with the failed send, the tail flows
# into the parked ring (the parked pump drains the pty master)

printf "for i in 1 2 3 4 5 6 7 8 9 10; do echo PARK-M-\$i; sleep 1; done\n" >&9
sleep 1

# the disconnect: the client dies, the dead UDP port echoes the next
# server send - the fast close of the wave 12, the park rides under
# the token

kill -9 "$CLI1PID" 2>/dev/null
CLI1PID=

i=0

while [ "$i" -lt 100 ]; do

    if grep -q "INTEROP-SESSION-PARK" "$SRVLOG" 2>/dev/null; then
        break
    fi

    sleep 0.2
    i=$((i + 1))
done

grep -q "INTEROP-SESSION-PARK" "$SRVLOG" && pass "the session parked on the connection death" ||
    fail "the park did not ride ($(grep -cE 'PARK|CANCEL|ATTACH' "$SRVLOG") markers)"

# the re-dial: the same token, the interactive shape (the attach
# resumes the OLD shell - the exec cannot ride by design); the fifo
# stdin closes after the replay lands - the client sends the input
# EOF and the resumed shell exits with the verdict

mkfifo "$WORK/in2.fifo"

S3_SESSION_TOKEN=aabbccdd00112233445566778899aabb \
    setsid nohup "$CLI" -insecure -i "$WORK/priv.pem" \
    "client@127.0.0.1:$SRVPORT/ssh3-term" < "$WORK/in2.fifo" > "$WORK/run2.out" 2>&1 &
CLI2PID=$!

exec 8> "$WORK/in2.fifo"

i=0

while [ "$i" -lt 100 ]; do

    if grep -q "INTEROP-SESSION-ATTACH" "$SRVLOG" 2>/dev/null; then
        break
    fi

    sleep 0.1
    i=$((i + 1))
done

grep -q "INTEROP-SESSION-ATTACH" "$SRVLOG" && pass "the re-dial attached the parked session" ||
    fail "the attach did not ride"

sleep 2

exec 8>&-

i=0

while [ "$i" -lt 100 ]; do

    if ! kill -0 "$CLI2PID" 2>/dev/null; then
        break
    fi

    sleep 0.1
    i=$((i + 1))
done

grep -qE "PARK-M-[5-9]|PARK-M-10" "$WORK/run2.out" &&
    pass "the parked output replayed through the ring" ||
    fail "the ring replay is missing ($(tail -2 "$WORK/run2.out" | tr '\n' ' '))"

# the control: the fresh dial (no token) - the new session, no parked
# replay

timeout 30 "$CLI" -n -insecure -i "$WORK/priv.pem" \
    "client@127.0.0.1:$SRVPORT/ssh3-term" "echo FRESH-RIDE" < /dev/null > "$WORK/run3.out" 2>&1

grep -q "FRESH-RIDE" "$WORK/run3.out" && pass "the fresh dial rides a fresh session" ||
    fail "the fresh dial broke"

grep -q "PARKED-MARK" "$WORK/run3.out" && fail "the fresh dial replayed the parked ring" ||
    pass "the fresh dial carries no parked replay"

if [ "$FAILURES" = "0" ]; then
    echo "SESSION-PARK-E2E OK"
else
    echo "SESSION-PARK-E2E FAILED: $FAILURES leg(s)"
    exit 1
fi
