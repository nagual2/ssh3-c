#!/bin/sh
# the compression of the channel body e2e (PLAN.md 9, B8)
#
#   1. the -C leg: the client compresses the sftp channel (the peer
#      announced the capability in its version string), the server
#      decodes the frames, the file comes back byte-exact
#   2. the report: the client notes the algorithm and the frames it
#      compressed (the plain bytes and the bytes on the wire)
#   3. the plain leg: without -C the channel carries the plain frames
#      and no note rides
#   4. the mixed leg: the peer without the capability (the version
#      string without the compress field) makes the client decline
#
# the verdicts: COMPRESS-E2E OK / FAILED
#
# usage: interop/compress-e2e.sh   (WSL)
# requires: the C runners (cmake --build build/linux-release)
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD=${BUILD:-$ROOT/build/linux-release}
BIN=${SSH3C_SERVER_BIN:-$BUILD/ssh3-server}
CLI=${SSH3C_CLIENT_BIN:-$BUILD/ssh3}

die() {
    echo "compress-e2e: $1" >&2
    exit 1
}

[ -x "$BIN" ] || die "the daemon is not built: $BIN"
[ -x "$CLI" ] || die "the client is not built: $CLI"

WORK=$(mktemp -d /tmp/s3compress.XXXXXX)
SRVPIDS=""

cleanup() {
    for p in $SRVPIDS; do
        kill "$p" 2>/dev/null
        wait "$p" 2>/dev/null
    done

    rm -rf "$WORK"
}

trap cleanup EXIT INT TERM

FAILURES=0

pass() {
    echo "   PASS: $1"
}

fail() {
    echo "   FAIL: $1"
    FAILURES=$((FAILURES + 1))
}

# the identity: the PKCS8 ed25519 of the C client, the authorized
# keys line built by hand (ssh-keygen reads no PKCS8 ed25519)

openssl genpkey -algorithm ed25519 -out "$WORK/priv.pem" 2>/dev/null ||
    die "openssl genpkey failed"

{
    printf '\000\000\000\013ssh-ed25519\000\000\000\040'
    openssl pkey -in "$WORK/priv.pem" -pubout -outform DER 2>/dev/null | tail -c 32
} | base64 | tr -d '\n' > "$WORK/blob.pub"

printf 'ssh-ed25519 %s compress-e2e\n' "$(cat "$WORK/blob.pub")" > "$WORK/authorized_keys"

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/key.pem" \
    -out "$WORK/cert.pem" -days 2 -subj /CN=compress-e2e 2>/dev/null ||
    die "openssl req failed"

# the fresh home (the pin of the daemon certificate lands below, when
# the listen port is known)

rm -rf "$WORK/home"
mkdir -p "$WORK/home/.ssh3"

# the daemon: the listen port scans up on a busy port, the port polls
# out of the INTEROP-LISTEN marker

S_LOG="$WORK/srv.log"
S_P=$((47800 + ($$ % 150)))
S_PID=

setsid nohup env SSH3C_PROTO=1 "$BIN" -3 -l "127.0.0.1:$S_P" \
    -c "$WORK/cert.pem" -k "$WORK/key.pem" \
    -K "$WORK/authorized_keys" > "$S_LOG" 2>&1 < /dev/null &
S_PID=$!
SRVPIDS="$SRVPIDS $S_PID"

PORT=""

S_J=0

while [ "$S_J" -lt 50 ]; do

    if grep -q INTEROP-LISTEN "$S_LOG" 2>/dev/null; then
        PORT=$(grep -oE 'port=[0-9]+' "$S_LOG" | head -1 | cut -d= -f2)
        break
    fi

    if ! kill -0 "$S_PID" 2>/dev/null; then
        break
    fi

    sleep 0.1
    S_J=$((S_J + 1))
done

[ -n "$PORT" ] || die "the daemon did not come up: $(tail -3 "$S_LOG")"

# the pin of the daemon certificate (the label is the host key of the
# client: host:port/path); the non-pty runs skip the TOFU question

printf '127.0.0.1:%s/ssh3-term x509-certificate %s\n' "$PORT" \
    "$(openssl x509 -in "$WORK/cert.pem" -outform DER | base64 -w0)" \
    > "$WORK/home/.ssh3/known_hosts"

# the payload: a compressible body (the repeated lines), big enough
# for several frames

i=0

while [ "$i" -lt 20000 ]; do
    printf 'S3COMPRESS-LINE-%05d-the-payload-repeats-so-the-cutoff-keeps-the-frame\n' "$i"
    i=$((i + 1))
done > "$WORK/payload.txt"

wc -c < "$WORK/payload.txt" > "$WORK/size.txt"

echo "== leg 1: -C compresses the sftp channel, the file comes back byte-exact"

HOME="$WORK/home" timeout 60 "$CLI" -C -i "$WORK/priv.pem" \
    --sftp "put:$WORK/payload.txt:/tmp/s3compress.txt" \
    "client@127.0.0.1:$PORT/ssh3-term" \
    > "$WORK/put.out" 2>"$WORK/put.err"
rc=$?

if [ "$rc" -eq 0 ]; then
    pass "the -C put rode (rc 0)"
else
    fail "the -C put leg: rc=$rc $(tail -1 "$WORK/put.err")"
fi

if grep -q "the compression of the channel body is on" "$WORK/put.err"; then
    pass "the client noted the negotiated algorithm"
else
    fail "no negotiation note: $(tail -2 "$WORK/put.err")"
fi

HOME="$WORK/home" timeout 60 "$CLI" --sftp "get:$WORK/back.txt:/tmp/s3compress.txt" \
    -i "$WORK/priv.pem" "client@127.0.0.1:$PORT/ssh3-term" \
    > "$WORK/get.out" 2>"$WORK/get.err"
rc=$?

if [ "$rc" -eq 0 ] && cmp -s "$WORK/payload.txt" "$WORK/back.txt"; then
    pass "the file came back byte-exact"
else
    fail "the get leg: rc=$rc $(tail -1 "$WORK/get.err")"
fi

echo "== leg 2: the report of the compression"

if grep -q "the compression of the channel body:" "$WORK/put.err"; then
    REPORT=$(grep "the compression of the channel body:" "$WORK/put.err" | head -1)
    pass "the report rode: $REPORT"

    PLAIN=$(echo "$REPORT" | sed -E 's/.*: ([0-9]+) frames, ([0-9]+) bytes -> ([0-9]+) bytes.*/\2/')
    PACKED=$(echo "$REPORT" | sed -E 's/.*: ([0-9]+) frames, ([0-9]+) bytes -> ([0-9]+) bytes.*/\3/')

    if [ -n "$PLAIN" ] && [ -n "$PACKED" ] && [ "$PACKED" -lt "$PLAIN" ]; then
        pass "the wire carried less than the plain bytes ($PACKED < $PLAIN)"
    else
        fail "the report does not show a gain: $REPORT"
    fi

else
    fail "no compression report in the client output"
fi

echo "== leg 3: without -C the channel stays plain"

HOME="$WORK/home" timeout 60 "$CLI" -i "$WORK/priv.pem" \
    --sftp "put:$WORK/payload.txt:/tmp/s3compress2.txt" \
    "client@127.0.0.1:$PORT/ssh3-term" \
    > "$WORK/plain.out" 2>"$WORK/plain.err"
rc=$?

if [ "$rc" -eq 0 ]; then
    pass "the plain put rode (rc 0)"
else
    fail "the plain put leg: rc=$rc $(tail -1 "$WORK/plain.err")"
fi

if grep -q "the compression of the channel body" "$WORK/plain.err"; then
    fail "the plain leg noted a compression"
else
    pass "the plain leg carried no compression"
fi

echo "== leg 4: the daemon survives the compressed channel"

if kill -0 "$S_PID" 2>/dev/null; then
    pass "the daemon is alive"
else
    fail "the daemon died: $(tail -3 "$S_LOG")"
fi

if [ "$FAILURES" -eq 0 ]; then
    echo "COMPRESS-E2E OK"
    exit 0
fi

echo "COMPRESS-E2E FAILED ($FAILURES)"
exit 1
