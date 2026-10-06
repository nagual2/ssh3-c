#!/bin/sh
# the pubkey e2e (the -K Bearer JWT mode, P6.5 auth wave, the C client
# wave of the P6 debts):
#
#   1. one s3interop_server (-3 -K authorized_keys), the Go fork
#      client signs the CONNECT with an ed25519 identity
#   2. the positive run: the key in the file, the exec rides through,
#      the marker comes back and INTEROP-AUTH-OK lands in the log
#   3. the negative run: a foreign key, the CONNECT is rejected 401
#   4. the negative run: no key at all, the CONNECT is rejected 401
#   5. the C client run: s3interop_client (-K privkey.pem -U user)
#      signs the same claim set itself (EdDSA), the exec rides through
#   6. the negative run: the C client with a foreign key, 401
#   7. the negative run: the C client with exp shifted into the past
#      (S3_JWT_EXP_PAST), 401
#   8. the RSA round: the RS256 JWT of the Go client and of the C
#      client against the ssh-rsa line of the same keys file
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
[ -x "$BUILD/s3interop_client" ] || die "the C client binary is not built ($BUILD/s3interop_client)"
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
# foreign key never does.  The ssh-keygen keys (the OpenSSH container
# format) feed the Go client, the PEM keys (PKCS#8) feed the C client
# one; ssh-keygen reads no PKCS8 ed25519, so the pub line of the C
# identity is built by hand: the ssh wire blob is the algorithm
# string, its length, the key length and the raw key (printf keeps
# the octal escapes the POSIX sh printf understands)

ssh-keygen -t ed25519 -N "" -C pubkey-e2e-good -f "$W/id_good" -q || die "ssh-keygen good"
ssh-keygen -t ed25519 -N "" -C pubkey-e2e-foreign -f "$W/id_foreign" -q || die "ssh-keygen foreign"

openssl genpkey -algorithm ed25519 -out "$W/id_c.pem" 2>/dev/null || die "openssl genpkey c"
openssl genpkey -algorithm ed25519 -out "$W/id_c_foreign.pem" 2>/dev/null \
    || die "openssl genpkey c foreign"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$W/id_rsa.pem" 2>/dev/null \
    || die "openssl genpkey rsa"

ed25519_blob() {
    # ed25519_blob <pem>: the base64 of the ssh wire blob on one line
    {
        printf '\000\000\000\013ssh-ed25519\000\000\000\040'
        openssl pkey -in "$1" -pubout -outform DER 2>/dev/null | tail -c 32
    } | base64 | tr -d '\n'
}

GOOD_BLOB=$(ed25519_blob "$W/id_c.pem") || die "the good blob failed"
FOREIGN_BLOB=$(ed25519_blob "$W/id_c_foreign.pem") || die "the foreign blob failed"
RSA_PUB=$(ssh-keygen -y -f "$W/id_rsa.pem") || die "the rsa pub failed"

{
    # the decoration exercises the comment and the options prefix of
    # the authorized_keys iterator; both the Go and the C identity
    # live in one file (the walker picks the matching one), the rsa
    # line lands below so the multi-key walk gets its exercise too

    echo "# the pubkey e2e fixture"
    echo
    echo "no-pty $(cat "$W/id_good.pub") pubkey-e2e-go"
    echo "no-pty ssh-ed25519 $GOOD_BLOB pubkey-e2e-c"
} > "$W/authorized_keys"

echo "== 1: the server and the good key (the Go client)"

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

echo "== 2: the foreign key (the Go client)"

"$GOSSH3" -insecure -o StrictHostKeyChecking=no -privkey "$W/id_foreign" \
    "bob@127.0.0.1:$PORT/ssh3-term" printf nope >"$W/foreign.out" 2>"$W/foreign.log"
RC=$?

if [ "$RC" -ne 0 ]; then
    pass "the foreign key was refused"
else
    fail "the foreign key exec unexpectedly succeeded"
fi

echo "== 3: no key (the Go client)"

"$GOSSH3" -insecure -o StrictHostKeyChecking=no \
    "bob@127.0.0.1:$PORT/ssh3-term" printf nope >"$W/nokey.out" 2>"$W/nokey.log"
RC=$?

if [ "$RC" -ne 0 ]; then
    pass "the missing key was refused"
else
    fail "the missing key exec unexpectedly succeeded"
fi

AUTH_OK_BEFORE=$(grep -c "INTEROP-AUTH-OK user=bob" "$SRV" || true)

echo "== 4: the C client with the good key"

timeout 30 "$BUILD/s3interop_client" -3 -C -S exec -K "$W/id_c.pem" -U bob \
    -a "127.0.0.1:$PORT" -t 20000 > "$W/c-good.log" 2>&1
RC=$?

if [ "$RC" -eq 0 ] && grep -q "INTEROP-EXEC-OK exit=0" "$W/c-good.log"; then
    pass "the C client exec rode through with the good key"
else
    fail "the C client good key exec failed rc=$RC $(tail -3 "$W/c-good.log")"
fi

AUTH_OK_NOW=$(grep -c "INTEROP-AUTH-OK user=bob" "$SRV" || true)

if [ "$AUTH_OK_NOW" -gt "$AUTH_OK_BEFORE" ]; then
    pass "INTEROP-AUTH-OK user=bob (the C client)"
else
    fail "no fresh INTEROP-AUTH-OK after the C client run"
fi

echo "== 5: the C client with the foreign key"

timeout 30 "$BUILD/s3interop_client" -3 -C -S exec -K "$W/id_c_foreign.pem" -U bob \
    -a "127.0.0.1:$PORT" -t 20000 > "$W/c-foreign.log" 2>&1
RC=$?

if [ "$RC" -ne 0 ] && grep -q "INTEROP-H3-STATUS 401" "$W/c-foreign.log"; then
    pass "the C client foreign key was refused (401)"
else
    fail "the C client foreign key run: rc=$RC $(tail -3 "$W/c-foreign.log")"
fi

echo "== 6: the C client with the expired exp"

S3_JWT_EXP_PAST=60 timeout 30 "$BUILD/s3interop_client" -3 -C -S exec -K "$W/id_c.pem" -U bob \
    -a "127.0.0.1:$PORT" -t 20000 > "$W/c-expired.log" 2>&1
RC=$?

if [ "$RC" -ne 0 ] && grep -q "INTEROP-H3-STATUS 401" "$W/c-expired.log"; then
    pass "the expired exp was refused (401)"
else
    fail "the expired exp run: rc=$RC $(tail -3 "$W/c-expired.log")"
fi

echo "== 7: the RSA round (the Go client, then the C client)"

# the ssh-rsa line rides the same file, the walker picks it behind
# the ed25519 one

{
    cat "$W/authorized_keys"
    echo "$RSA_PUB pubkey-e2e-rsa"
} > "$W/authorized_keys.new"

mv "$W/authorized_keys.new" "$W/authorized_keys"

OUT=$("$GOSSH3" -insecure -o StrictHostKeyChecking=no -privkey "$W/id_rsa.pem" \
    "bob@127.0.0.1:$PORT/ssh3-term" printf s3-pubkey-e2e-rsa-ok < /dev/null 2>"$W/rsa-go.log")
RC=$?

if [ "$RC" -eq 0 ] && printf '%s' "$OUT" | grep -q s3-pubkey-e2e-rsa-ok; then
    pass "the RSA exec rode through (the Go client, RS256)"
else
    fail "the RSA exec failed (the Go client) rc=$RC $(cat "$W/rsa-go.log")"
fi

timeout 30 "$BUILD/s3interop_client" -3 -C -S exec -K "$W/id_rsa.pem" -U bob \
    -a "127.0.0.1:$PORT" -t 20000 > "$W/c-rsa.log" 2>&1
RC=$?

if [ "$RC" -eq 0 ] && grep -q "INTEROP-EXEC-OK exit=0" "$W/c-rsa.log"; then
    pass "the RSA exec rode through (the C client, RS256)"
else
    fail "the RSA exec failed (the C client) rc=$RC $(tail -3 "$W/c-rsa.log")"
fi

kill "$SRVPID" 2>/dev/null
wait "$SRVPID" 2>/dev/null

# the negatives draw the 401 every time: the Go foreign key reaches
# the server, the C foreign key and the expired exp do too; the
# no-key run may fail locally before the CONNECT goes out, so three
# server-side rejections are the floor

REJECTS=$(grep -c "INTEROP-H3-REJECT code=401" "$SRV" || true)

if [ "$REJECTS" -ge 3 ]; then
    pass "the server rejected the bad CONNECTs (401 x$REJECTS)"
else
    fail "expected at least 3 rejections, got $REJECTS"
fi

rm -rf "$W"

if [ "$FAILURES" -gt 0 ]; then
    echo "pubkey-e2e: FAILED ($FAILURES)"
    exit 1
fi

echo "pubkey-e2e: OK"
