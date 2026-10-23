#!/bin/sh
# the cross-server e2e (PLAN.md 9, B13): the C client rides the go fork
# server (project/ssh3) in both verdict shapes:
#
#   1. the valid identity: the sftp put+get come back byte-exact - the
#      conversation registration and the channel binding hold
#   2. the unknown user: the refusal lands as a clean 401 BEFORE the
#      response headers flush (the fork used to flush the implicit 200
#      at the HTTPStream() takeover, so the client saw a success, opened
#      the channel and hung until the teardown cancelled it - the fork
#      now resolves the user before any header rides)
#
# usage: interop/go-server-channel-e2e.sh   (WSL)
# requires: the C client (build/linux-release/ssh3), the go fork sources
# (GOSSHSRC, default ~/git/ssh3) - the binaries build on the fly when
# absent
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
CCLI=${SSH3C_CLIENT_BIN:-$ROOT/build/linux-release/ssh3}
GOSSHSRC=${GOSSHSRC:-$HOME/git/ssh3}
GOBIN=${GOSSHBIN:-/tmp/go-ssh3-b13}
IDENT_LABEL=go-server-channel-e2e

die() {
    echo "go-server-channel-e2e: $1" >&2
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

[ -x "$CCLI" ] || die "the C client is not built: $CCLI"
[ -d "$GOSSHSRC" ] || die "the go fork sources are missing: $GOSSHSRC"

mkdir -p "$GOBIN"

if [ ! -x "$GOBIN/ssh3-server" ]; then
    echo "   .. building the fork server ($GOSSHSRC)"
    (cd "$GOSSHSRC" && go build -o "$GOBIN/ssh3-server" ./cmd/ssh3-server) ||
        die "the fork server build failed"
fi

W=$(mktemp -d /tmp/go-srv-e2e.XXXXXX)
REAL_IDENT="$HOME/.ssh3/authorized_identities"
SRVPID=""

cleanup() {
    if [ -n "$SRVPID" ]; then
        kill "$SRVPID" 2>/dev/null
        wait "$SRVPID" 2>/dev/null
    fi

    # the e2e identity rides the real home (the fork resolves the user
    # through the passwd entry and reads its own home, the $HOME of the
    # daemon does not participate) - the label line comes back out
    if [ -f "$REAL_IDENT" ]; then
        sed -i "/$IDENT_LABEL/d" "$REAL_IDENT"
    fi

    rm -rf "$W"
}

trap cleanup EXIT INT TERM

# the identities: one ed25519 keypair, the openssh line into the real
# authorized_identities (the label marks it for the teardown)

openssl genpkey -algorithm ed25519 -out "$W/key.pem" 2>/dev/null ||
    die "openssl genpkey failed"

{
    printf '\000\000\000\013ssh-ed25519\000\000\000\040'
    openssl pkey -in "$W/key.pem" -pubout -outform DER 2>/dev/null | tail -c 32
} | base64 | tr -d '\n' > "$W/blob.pub"

printf 'ssh-ed25519 %s %s\n' "$(cat "$W/blob.pub")" "$IDENT_LABEL" > "$W/authorized_line"

mkdir -p "$HOME/.ssh3"
touch "$REAL_IDENT"
grep -q "$IDENT_LABEL" "$REAL_IDENT" || cat "$W/authorized_line" >> "$REAL_IDENT"

openssl req -x509 -sha256 -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout "$W/cert.pem" -days 2 -out "$W/cert.pem" -subj /CN=go-server-channel-e2e \
    -addext "subjectAltName=IP:127.0.0.1" 2>/dev/null || die "openssl req failed"

mkdir -p "$W/home/.ssh3"
printf '127.0.0.1:0/ssh3-term x509-certificate placeholder\n' > "$W/home/.ssh3/known_hosts"

# the payload
python3 -c "open('$W/payload.bin', 'wb').write(b'the go-server-channel-e2e line\n' * 4000)"

S_LOG="$W/srv.log"
S_P=$((47400 + ($$ % 40)))

env SSH3_LOG_LEVEL=info SSH3_LOG_FILE="$S_LOG" "$GOBIN/ssh3-server" \
    -bind "127.0.0.1:$S_P" -cert "$W/cert.pem" -key "$W/cert.pem" \
    -url-path /ssh3-term > "$W/srv.out" 2>&1 < /dev/null &
SRVPID=$!

i=0
while [ "$i" -lt 50 ]; do
    grep -q "Server started" "$W/srv.out" 2>/dev/null && break
    kill -0 "$SRVPID" 2>/dev/null || break
    sleep 0.1
    i=$((i + 1))
done

kill -0 "$SRVPID" 2>/dev/null || die "the fork server did not start: $(tail -3 "$W/srv.out")"

# the cert pin of the fork server (the label is the host key of the
# client: host:port/path)
printf '127.0.0.1:%s/ssh3-term x509-certificate %s\n' "$S_P" \
    "$(openssl x509 -in "$W/cert.pem" -outform DER | base64 -w0)" \
    >> "$W/home/.ssh3/known_hosts"

URL_MAX="max@127.0.0.1:$S_P/ssh3-term"

echo "== leg 1: the valid identity - the sftp put+get come back byte-exact"

HOME="$W/home" timeout -k 5 60 "$CCLI" -i "$W/key.pem" \
    --sftp "put:$W/payload.bin:/go-srv-e2e.bin" "$URL_MAX" \
    > "$W/put.out" 2>"$W/put.err"
rc=$?

if [ "$rc" -eq 0 ]; then
    pass "the put rode (rc 0)"
else
    fail "the put leg: rc=$rc $(tail -1 "$W/put.err")"
fi

HOME="$W/home" timeout -k 5 60 "$CCLI" -i "$W/key.pem" \
    --sftp "get:$W/back.bin:/go-srv-e2e.bin" "$URL_MAX" \
    > "$W/get.out" 2>"$W/get.err"
rc=$?

if [ "$rc" -eq 0 ] && cmp -s "$W/payload.bin" "$W/back.bin"; then
    pass "the file came back byte-exact"
else
    fail "the get leg: rc=$rc $(tail -1 "$W/get.err")"
fi

echo "== leg 2: the unknown user - a clean refusal, no channel hang"

T0=$(date +%s)
HOME="$W/home" timeout -k 5 30 "$CCLI" -i "$W/key.pem" \
    --sftp "put:$W/payload.bin:/go-srv-e2e-ghost.bin" "ghost@127.0.0.1:$S_P/ssh3-term" \
    > "$W/ghost.out" 2>"$W/ghost.err"
rc=$?
T1=$(date +%s)

if [ "$rc" -ne 0 ]; then
    pass "the unknown user is refused (rc $rc)"
else
    fail "the unknown user was served"
fi

if [ $((T1 - T0)) -lt 10 ]; then
    pass "the refusal came back at once ($((T1 - T0))s, no hang)"
else
    fail "the refusal hung for $((T1 - T0))s - the channel waited for the teardown"
fi

if grep -q "could not find SSH3 conversation" "$S_LOG"; then
    fail "the fork lost the channel again: $(grep -m1 "could not find SSH3" "$S_LOG")"
else
    pass "no lost-channel error in the fork log"
fi

echo "== leg 3: the valid user with a wrong key - the verdict rides before the flush (B11-3)"

openssl genpkey -algorithm ed25519 -out "$W/wrong.pem" 2>/dev/null ||
    die "openssl genpkey (wrong key) failed"

T0=$(date +%s)
HOME="$W/home" timeout -k 5 30 "$CCLI" -i "$W/wrong.pem" \
    --sftp "put:$W/payload.bin:/go-srv-e2e-wrong.bin" "$URL_MAX" \
    > "$W/wrong.out" 2>"$W/wrong.err"
rc=$?
T1=$(date +%s)

if [ "$rc" -ne 0 ]; then
    pass "the wrong key is refused (rc $rc)"
else
    fail "the wrong key was served"
fi

if [ $((T1 - T0)) -lt 10 ]; then
    pass "the verdict came back at once ($((T1 - T0))s, no hang)"
else
    fail "the verdict hung for $((T1 - T0))s - the client saw the phantom 200"
fi

if grep -q "refused the session (HTTP 401)" "$W/wrong.err"; then
    pass "the client saw the honest 401"
else
    fail "no 401 verdict on the client side: $(tail -1 "$W/wrong.err")"
fi

if grep -q "could not find SSH3 conversation" "$S_LOG"; then
    fail "the wrong key lost the channel: $(grep -m1 "could not find SSH3" "$S_LOG")"
else
    pass "no lost-channel error on the wrong key"
fi

echo "== leg 4: the exec session and the exit status (the C client)"

# the command args must not start with a dash: the client's getopt
# permutes the whole argv and eats the tokens of `sh -c ...`

HOME="$W/home" timeout -k 5 30 "$CCLI" -i "$W/key.pem" \
    "$URL_MAX" printf go-server-channel-e2e-exec-ok > "$W/exec.out" 2>"$W/exec.err"
rc=$?

if [ "$rc" -eq 0 ] && grep -q go-server-channel-e2e-exec-ok "$W/exec.out"; then
    pass "the exec rode (the marker came back)"
else
    fail "the exec leg: rc=$rc $(tail -1 "$W/exec.err")"
fi

HOME="$W/home" timeout -k 5 30 "$CCLI" -i "$W/key.pem" \
    "$URL_MAX" false > "$W/false.out" 2>"$W/false.err"
rc=$?

if [ "$rc" -eq 1 ]; then
    pass "the exit status propagated (rc 1)"
else
    fail "the exit-status leg: rc=$rc, want 1"
fi

if [ "$FAILURES" -eq 0 ]; then
    echo "GO-SERVER-CHANNEL-E2E OK"
    exit 0
fi

echo "GO-SERVER-CHANNEL-E2E FAILED ($FAILURES)"
exit 1
