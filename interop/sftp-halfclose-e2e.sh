#!/bin/sh
# the sftp half-close e2e (PLAN.md 9, B12): the go fork client rides
# the C server - the transfer finishes and the client half-closes its
# side; the subsystem used to drop the child's pending replies on that
# EOF (SFTP-SRV-DONE freed the channel) and the client hung on its
# STAT/CLOSE until the deadline.  The server drains now: EOF means "no
# more requests", the replies ride back, the transfer completes.
#
#   1. the put: the payload rides up, the client exits cleanly
#   2. the get: the payload comes back byte-exact
#
# usage: interop/sftp-halfclose-e2e.sh   (WSL)
# requires: the C daemon (build/linux-release/ssh3-server), the go
# fork sources (GOSSHSRC, default ~/git/ssh3) - the client builds on
# the fly when absent
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD=${BUILD:-$ROOT/build/linux-release}
BIN=${SSH3C_SERVER_BIN:-$BUILD/ssh3-server}
GOSSHSRC=${GOSSHSRC:-$HOME/git/ssh3}
GOBIN=${GOSSHBIN:-/tmp/go-ssh3-b12}
IDENT_LABEL=sftp-halfclose-e2e

die() {
    echo "sftp-halfclose-e2e: $1" >&2
    exit 1
}

FAILURES=0

pass() {
    echo "   PASS: $1"
}

fail() {
    echo "   FAIL: $1"
    FAILURES=$((FAILURES + 1))
}

[ -x "$BIN" ] || die "the daemon is not built: $BIN"
[ -d "$GOSSHSRC" ] || die "the go fork sources are missing: $GOSSHSRC"

mkdir -p "$GOBIN"

if [ ! -x "$GOBIN/ssh3" ]; then
    echo "   .. building the fork client ($GOSSHSRC)"
    (cd "$GOSSHSRC" && go build -o "$GOBIN/ssh3" ./cmd/ssh3) ||
        die "the fork client build failed"
fi

W=$(mktemp -d /tmp/s3halfclose.XXXXXX)
REAL_IDENT="$HOME/.ssh3/authorized_identities"
SRVPID=""
HOME_FILE=""

cleanup() {
    if [ -n "$SRVPID" ]; then
        kill "$SRVPID" 2>/dev/null
        wait "$SRVPID" 2>/dev/null
    fi

    if [ -f "$REAL_IDENT" ]; then
        sed -i "/$IDENT_LABEL/d" "$REAL_IDENT"
    fi

    if [ -n "$HOME_FILE" ]; then
        rm -f "$HOME_FILE"
    fi

    rm -rf "$W"
}

trap cleanup EXIT INT TERM

# the identities: the same ed25519 line the fork client turns into its
# Bearer token; the C daemon takes -K, the fork server reads the real
# authorized_identities (the label marks the line for the teardown)

openssl genpkey -algorithm ed25519 -out "$W/key.pem" 2>/dev/null ||
    die "openssl genpkey failed"

{
    printf '\000\000\000\013ssh-ed25519\000\000\000\040'
    openssl pkey -in "$W/key.pem" -pubout -outform DER 2>/dev/null | tail -c 32
} | base64 | tr -d '\n' > "$W/blob.pub"

printf 'ssh-ed25519 %s %s\n' "$(cat "$W/blob.pub")" "$IDENT_LABEL" > "$W/authorized_keys"

mkdir -p "$HOME/.ssh3"
touch "$REAL_IDENT"
grep -q "$IDENT_LABEL" "$REAL_IDENT" || cat "$W/authorized_keys" >> "$REAL_IDENT"

openssl req -x509 -sha256 -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout "$W/cert.pem" -days 2 -out "$W/cert.pem" -subj /CN=sftp-halfclose-e2e \
    -addext "subjectAltName=IP:127.0.0.1" 2>/dev/null || die "openssl req failed"

mkdir -p "$W/home/.ssh3"
printf '127.0.0.1:0/ssh3-term x509-certificate placeholder\n' > "$W/home/.ssh3/known_hosts"

# the payload: compressible enough to ride fast, big enough to span
# several frames
python3 -c "open('$W/payload.bin', 'wb').write(b'the sftp-halfclose-e2e line\n' * 20000)"

S_LOG="$W/srv.log"
S_P=$((47500 + ($$ % 40)))

SSH3C_PROTO=1 "$BIN" -3 -l "127.0.0.1:$S_P" \
    -c "$W/cert.pem" -k "$W/cert.pem" -K "$W/authorized_keys" \
    > "$S_LOG" 2>&1 < /dev/null &
SRVPID=$!

i=0
while [ "$i" -lt 50 ]; do
    grep -q INTEROP-LISTEN "$S_LOG" 2>/dev/null && break
    kill -0 "$SRVPID" 2>/dev/null || break
    sleep 0.1
    i=$((i + 1))
done

kill -0 "$SRVPID" 2>/dev/null || die "the daemon did not start: $(tail -3 "$S_LOG")"

printf '127.0.0.1:%s/ssh3-term x509-certificate %s\n' "$S_P" \
    "$(openssl x509 -in "$W/cert.pem" -outform DER | base64 -w0)" \
    >> "$W/home/.ssh3/known_hosts"

URL="max@127.0.0.1:$S_P"

echo "== leg 1: the put - the transfer ends with the client's half-close"

timeout -k 5 60 "$GOBIN/ssh3" -transfer -insecure -strict-host-key-checking no \
    -privkey "$W/key.pem" -p "$S_P" "$W/payload.bin" "$URL:/sftp-halfclose-e2e.bin" \
    > "$W/put.out" 2>"$W/put.err"
rc=$?

if [ "$rc" -eq 0 ]; then
    pass "the put completed without the hang (rc 0)"
else
    fail "the put leg: rc=$rc $(tail -1 "$W/put.err") - the client hung on the half-close"
fi

HOME_FILE="$HOME/sftp-halfclose-e2e.bin"

if [ -f "$HOME_FILE" ] && cmp -s "$W/payload.bin" "$HOME_FILE"; then
    pass "the payload rode up byte-exact"
else
    fail "the uploaded payload is missing or differs: $HOME_FILE"
fi

echo "== leg 2: the get - the payload comes back byte-exact"

timeout -k 5 60 "$GOBIN/ssh3" -transfer -insecure -strict-host-key-checking no \
    -privkey "$W/key.pem" -p "$S_P" "$URL:/sftp-halfclose-e2e.bin" "$W/back.bin" \
    > "$W/get.out" 2>"$W/get.err"
rc=$?

if [ "$rc" -eq 0 ] && cmp -s "$W/payload.bin" "$W/back.bin"; then
    pass "the file came back byte-exact"
else
    fail "the get leg: rc=$rc $(tail -1 "$W/get.err")"
fi

if grep -q "SFTP-SRV-DRAIN" "$S_LOG"; then
    pass "the drain marker is in the daemon log"
else
    fail "no SFTP-SRV-DRAIN in the daemon log - the drain did not run"
fi

if [ "$FAILURES" -eq 0 ]; then
    echo "SFTP-HALFCLOSE-E2E OK"
    exit 0
fi

echo "SFTP-HALFCLOSE-E2E FAILED ($FAILURES)"
exit 1
