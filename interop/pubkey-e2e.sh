#!/bin/sh
# the pubkey e2e (the -K Bearer JWT mode, P6.5 auth wave):
#
#   1. one s3interop_server (-3 -K authorized_keys), the Go fork
#      client signs the CONNECT with an ed25519 identity
#   2. the positive run: the key in the file, the exec rides through,
#      the marker comes back and INTEROP-AUTH-OK lands in the log
#   3. the negative run: a foreign key, the CONNECT is rejected 401
#   4. the negative run: no key at all, the CONNECT is rejected 401
#
# usage: pubkey-e2e.sh [worktree] [go-ssh3-binary]
set -u

ROOT=${1:-/mnt/c/Git/project/ssh3-c}
GOSSH3=${2:-/tmp/pubkey-e2e/ssh3}
BUILD=$ROOT/build/linux-release
# the server binary override (P6.5 wave 2): the ssh3-server daemon
# replaces the harness server; the daemon speaks the runner markers
# only under SSH3C_PROTO=1, the harness server ignores the variable
SERVER=${SSH3C_SERVER_BIN:-$BUILD/s3interop_server}
SRV_ENV=""
if [ "${SSH3C_SERVER_BIN:-}" != "" ]; then
    SRV_ENV="SSH3C_PROTO=1"
fi
FAILURES=0

die() {
    echo "pubkey-e2e: $1" >&2
    exit 1
}

fail() {
    echo "   FAIL: $1"
    FAILURES=$((FAILURES + 1))
}

pass() {
    echo "   PASS: $1"
}

[ -x "$SERVER" ] || die "the server binary is not built ($SERVER)"
[ -x "$GOSSH3" ] || die "the go ssh3 client is not built ($GOSSH3)"

W=$(mktemp -d /tmp/pubkey-e2e.XXXXXX)
SRV=$W/srv.log

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/key.pem" -out "$W/cert.pem" \
    -days 30 -subj /CN=pubkey-e2e 2>/dev/null || die "openssl req failed"

wait_for() {
    # wait_for <file> <pattern> [tries=50]
    i=0
    while [ "$i" -lt "${3:-50}" ]; do
        if grep -q "$2" "$1" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
        i=$((i + 1))
    done

    return 1
}

# the identities: the good key rides the authorized_keys file, the
# foreign key never does

ssh-keygen -t ed25519 -N "" -C pubkey-e2e-good -f "$W/id_good" -q || die "ssh-keygen good"
ssh-keygen -t ed25519 -N "" -C pubkey-e2e-foreign -f "$W/id_foreign" -q || die "ssh-keygen foreign"

{
    # the decoration exercises the comment and the options prefix of
    # the authorized_keys iterator

    echo "# the pubkey e2e fixture"
    echo
    echo "no-pty $(cat "$W/id_good.pub") pubkey-e2e"
} > "$W/authorized_keys"

echo "== 1: the server and the good key"

setsid nohup env $SRV_ENV "$SERVER" -3 -l 127.0.0.1:0 -c "$W/cert.pem" -k "$W/key.pem" \
    -K "$W/authorized_keys" > "$SRV" 2>&1 < /dev/null &

SRVPID=$!

if ! wait_for "$SRV" INTEROP-LISTEN; then
    die "the server did not come up"
fi

PORT=$(grep -oE 'port=[0-9]+' "$SRV" | cut -d= -f2)

# the HOME isolation keeps the client known_hosts out of the real one

export HOME=$W

OUT=$("$GOSSH3" -insecure -o StrictHostKeyChecking=no -privkey "$W/id_good" \
    "bob@127.0.0.1:$PORT/ssh3-term" printf s3-pubkey-e2e-ok < /dev/null 2>"$W/client.log")
RC=$?

if [ "$RC" -eq 0 ] && printf '%s' "$OUT" | grep -q s3-pubkey-e2e-ok; then
    pass "the exec rode through with the good key"
else
    fail "the good key exec failed rc=$RC out=$OUT $(cat "$W/client.log")"
fi

if grep -q "INTEROP-AUTH-OK user=bob" "$SRV"; then
    pass "INTEROP-AUTH-OK user=bob"
else
    fail "no INTEROP-AUTH-OK user=bob in the server log"
fi

echo "== 2: the foreign key"

"$GOSSH3" -insecure -o StrictHostKeyChecking=no -privkey "$W/id_foreign" \
    "bob@127.0.0.1:$PORT/ssh3-term" printf nope >"$W/foreign.out" 2>"$W/foreign.log"
RC=$?

if [ "$RC" -ne 0 ]; then
    pass "the foreign key was refused"
else
    fail "the foreign key exec unexpectedly succeeded"
fi

echo "== 3: no key"

"$GOSSH3" -insecure -o StrictHostKeyChecking=no \
    "bob@127.0.0.1:$PORT/ssh3-term" printf nope >"$W/nokey.out" 2>"$W/nokey.log"
RC=$?

if [ "$RC" -ne 0 ]; then
    pass "the missing key was refused"
else
    fail "the missing key exec unexpectedly succeeded"
fi

kill "$SRVPID" 2>/dev/null
wait "$SRVPID" 2>/dev/null

# the foreign key reaches the server and draws the 401; the no-key
# run may fail locally before the CONNECT goes out (no identity at
# all), so one server-side rejection is the floor

REJECTS=$(grep -c "INTEROP-H3-REJECT code=401" "$SRV")

if [ "$REJECTS" -ge 1 ]; then
    pass "the server rejected the foreign CONNECT (401 x$REJECTS)"
else
    fail "expected at least 1 rejection, got $REJECTS"
fi

rm -rf "$W"

if [ "$FAILURES" -gt 0 ]; then
    echo "pubkey-e2e: FAILED ($FAILURES)"
    exit 1
fi

echo "pubkey-e2e: OK"
