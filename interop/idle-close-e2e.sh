#!/bin/sh
# the idle close e2e (the 2026-10-15 client crash: 0xC0000005 in
# s3_event_expire_timers at offset 0xbbd3, twice in a row, ~60 s after
# the start; the client tick event rode the connection pool, the quic
# idle close destroyed the pool inside the event loop and the next
# expire pass walked the freed rbtree node):
#
#   1. the ssh3-server daemon (-i 4000 pins the idle window: the
#      negotiated max_idle_timeout is the smaller of the two sides)
#   2. the real ssh3 client, the stdin held open by the fifo holder —
#      the session channel lives, no traffic flows
#   3. at ~4 s the idle close fires: the client must report "the
#      connection is gone" and exit 255 — not die inside the expire
#      pass (the pre-fix run under the sanitizer reports
#      heap-use-after-free in s3_event_expire_timers)
#
# usage: idle-close-e2e.sh [worktree]
set -u

ROOT=${1:-/mnt/c/Git/project/ssh3-c}
BUILD=$ROOT/build/linux-asan
DAEMON=$BUILD/ssh3-server
CLI=$BUILD/ssh3
FAILURES=0

die() {
    echo "idle-close-e2e: $1" >&2
    exit 1
}

fail() {
    echo "   FAIL: $1"
    FAILURES=$((FAILURES + 1))
}

pass() {
    echo "   ok: $1"
}

[ -x "$DAEMON" ] || die "no daemon at $DAEMON (build linux-asan first)"
[ -x "$CLI" ] || die "no client at $CLI (build linux-asan first)"

W=$(mktemp -d /tmp/s3idle-XXXXXX) || die "mktemp"

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/key.pem" -out "$W/cert.pem" \
    -days 30 -subj /CN=idle-close-e2e 2>/dev/null || die "openssl req failed"

ssh-keygen -t ed25519 -N "" -C idle-close-good -f "$W/id_good" -q || die "ssh-keygen good"
cp "$W/id_good.pub" "$W/authorized_keys"

# the daemon: the 4000 ms idle pins the window (the client negotiates
# the smaller of the two max_idle_timeouts)

nohup env ASAN_OPTIONS=detect_leaks=0 "$DAEMON" -3 -c "$W/cert.pem" -k "$W/key.pem" \
    -l 127.0.0.1:0 -K "$W/authorized_keys" -i 4000 > "$W/srv.log" 2>&1 < /dev/null &
SRVPID=$!

i=0
while [ $i -lt 100 ]; do
    grep -q INTEROP-LISTEN "$W/srv.log" 2>/dev/null && break
    sleep 0.1
    i=$((i + 1))
done
if ! grep -q INTEROP-LISTEN "$W/srv.log" 2>/dev/null; then
    kill $SRVPID 2>/dev/null
    die "the daemon did not come up: $(tail -2 "$W/srv.log")"
fi
PORT=$(grep -oE 'port=[0-9]+' "$W/srv.log" | cut -d= -f2)

# the pin: the pipe session refuses the TOFU question, the fresh cert
# goes into the isolated HOME known_hosts up front (host:port/path,
# the DER compare is exact)

mkdir -p "$W/.ssh3" || die "mkdir .ssh3"
DER=$(openssl x509 -in "$W/cert.pem" -outform DER 2>/dev/null | base64 -w0) || die "der"
printf '%s:%s/ssh3-term x509-certificate %s\n' "127.0.0.1" "$PORT" "$DER" \
    > "$W/.ssh3/known_hosts" || die "pin"

# the stdin holder: the fifo keeps the client stdin open with no data
# (no EOF, no FIN, nothing flows — the idle window runs)

mkfifo "$W/in" || die "mkfifo"
sleep 40 > "$W/in" &
HOLDPID=$!

START=$(date +%s)

env ASAN_OPTIONS=detect_leaks=0 HOME="$W" "$CLI" -i "$W/id_good" \
    "bob@127.0.0.1:$PORT/ssh3-term" < "$W/in" > "$W/cli.out" 2>&1
RC=$?

TOOK=$(( $(date +%s) - START ))
kill "$HOLDPID" 2>/dev/null

if [ "$TOOK" -lt 2 ]; then
    fail "the client left too early (${TOOK}s, the idle window is 4s): $(tail -2 "$W/cli.out")"
elif grep -q "AddressSanitizer" "$W/cli.out"; then
    fail "the sanitizer trapped in the client (rc=$RC, ${TOOK}s): $(grep -m1 AddressSanitizer "$W/cli.out")"
elif [ "$RC" -eq 255 ] && grep -q "the connection is gone" "$W/cli.out"; then
    pass "the connection is gone, rc=255, ${TOOK}s"
else
    fail "unexpected client exit (rc=$RC, ${TOOK}s): $(tail -2 "$W/cli.out")"
fi

kill "$SRVPID" 2>/dev/null
wait "$SRVPID" 2>/dev/null

if [ "$FAILURES" -eq 0 ]; then
    rm -rf "$W"
    echo "idle-close-e2e: ok"
else
    echo "idle-close-e2e: $FAILURES failure(s), logs kept: $W"
    exit 1
fi
