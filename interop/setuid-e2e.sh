#!/bin/sh
# the per-session setuid e2e (P7.3): the root daemon drops every
# authenticated session onto the CONNECT username before the spawn
#
#   1. the users of the run: s3test (the Basic leg, NOPASSWD sudo)
#      and s3key (the pubkey JWT leg) - created here, removed after
#   2. the root server (-P passfile -K authorized_keys, the default
#      per-session setuid rides the euid 0)
#   3. the s3test leg: the exec `test "$(whoami)" = s3test` proves
#      the drop (the verdict exit=0 means the child identity is the
#      authenticated one, not the root of the daemon)
#   4. the s3test leg: `sudo -n true` - the session user carries its
#      own sudo rights (the whole point of the OpenSSH shape)
#   5. the negative gate: the unknown user answers 401 at the
#      CONNECT, before any spawn
#   6. the s3key leg: the pubkey JWT of the second user, the exec
#      `test "$(whoami)" = s3key` - the drop follows the auth
#      identity, not the first user
#
# the verdicts: SETUID-E2E OK / FAILED, the INTEROP-* markers of the
# C runners on the way
#
# usage: interop/setuid-e2e.sh   (WSL with the passwordless sudo)
# requires: the C runners (cmake --build build/linux-release), sudo
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD=${BUILD:-$ROOT/build/linux-release}
BIN=${SSH3C_SERVER_BIN:-$BUILD/ssh3-server}

die() {
    echo "setuid-e2e: $1" >&2
    exit 1
}

[ -x "$BIN" ] || die "the daemon is not built: $BIN"
[ -x "$BUILD/s3interop_client" ] || die "s3interop_client is not built"
sudo -n true 2>/dev/null || die "the passwordless sudo is required (the users and the root run)"

FAILURES=0

pass() {
    echo "   PASS: $1"
}

fail() {
    echo "   FAIL: $1"
    FAILURES=$((FAILURES + 1))
}

# the test users and the sudoers drop live for the run only (the
# test-infrastructure rule: everything goes away in the trap)

S3TEST=s3test
S3KEY=s3key
SUDOERS=/etc/sudoers.d/ssh3-setuid-e2e

cleanup() {
    sudo -n rm -f "$SUDOERS"
    sudo -n userdel -r "$S3TEST" >/dev/null 2>&1
    sudo -n userdel -r "$S3KEY" >/dev/null 2>&1

    if [ -n "${SRVPID:-}" ]; then
        sudo -n kill -TERM "$SRVPID" >/dev/null 2>&1
    fi

    rm -rf "$WORK"
}

trap cleanup EXIT INT TERM

WORK=$(mktemp -d /tmp/s3setuid.XXXXXX)

sudo -n userdel -r "$S3TEST" >/dev/null 2>&1
sudo -n userdel -r "$S3KEY" >/dev/null 2>&1

sudo -n useradd -m -s /bin/sh "$S3TEST" || die "useradd $S3TEST failed"
sudo -n useradd -m -s /bin/sh "$S3KEY" || die "useradd $S3KEY failed"

printf '%s ALL=(ALL) NOPASSWD: ALL\n' "$S3TEST" | sudo -n tee "$SUDOERS" >/dev/null
sudo -n chmod 440 "$SUDOERS"
sudo -n visudo -cf "$SUDOERS" >/dev/null || die "the sudoers drop is invalid"

# the auth fixtures: the Basic passfile (s3test and the s3ghost of
# the negative leg - the ghost passes the password check on purpose,
# so the 401 rides the passwd-resolution gate) and the
# authorized_keys of s3key (the %u pattern of the -K path)

{
    printf '%s:s3setuid-pass\n' "$S3TEST"
    printf 's3ghost:s3setuid-pass\n'
} > "$WORK/passfile"

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/key.pem" -out "$WORK/cert.pem" \
    -days 30 -subj /CN=setuid-e2e 2>/dev/null || die "openssl req failed"

openssl genpkey -algorithm ed25519 -out "$WORK/id_c.pem" 2>/dev/null || die "openssl genpkey"

# the pub line of the C identity, built by hand (ssh-keygen reads no
# PKCS8 ed25519): the ssh wire blob is the algorithm string, its
# length, the key length and the raw key

BLOB=$({
    printf '\000\000\000\013ssh-ed25519\000\000\000\040'
    openssl pkey -in "$WORK/id_c.pem" -pubout -outform DER 2>/dev/null | tail -c 32
} | base64 | tr -d '\n')

[ -n "$BLOB" ] || die "the ed25519 blob failed"

printf 'ssh-ed25519 %s setuid-e2e-c\n' "$BLOB" > "$WORK/authorized_keys"

# the root run: the per-session setuid is the default of the euid 0,
# the explicit flag rides to prove the wiring

sudo -n env SSH3C_PROTO=1 "$BIN" -3 -l 127.0.0.1:0 -c "$WORK/cert.pem" -k "$WORK/key.pem" \
    -P "$WORK/passfile" -K "$WORK/authorized_keys" --run-as-user on \
    > "$WORK/srv.log" 2>&1 < /dev/null &
SRVPID=$!

i=0

while [ "$i" -lt 50 ]; do
    grep -q INTEROP-LISTEN "$WORK/srv.log" 2>/dev/null && break
    sleep 0.1
    i=$((i + 1))
done

grep -q INTEROP-LISTEN "$WORK/srv.log" || die "the daemon did not start: $(tail -3 "$WORK/srv.log")"

PORT=$(grep -oE 'port=[0-9]+' "$WORK/srv.log" | cut -d= -f2)

if grep -q "per-session setuid enabled" "$WORK/srv.log"; then
    pass "the root run reports the per-session setuid"
else
    fail "no per-session setuid one-liner in the root run"
fi

echo "== leg 1: the Basic session of s3test runs as s3test (whoami)"

# the C client exec verdict needs the marker in the output, the exit
# status of the identity test drives the verdict code

HOME="$WORK" timeout 30 "$BUILD/s3interop_client" -3 -C -S exec \
    -e 'test "$(whoami)" = s3test && printf SSH3_AGENT_PROBE_OK' \
    -U "$S3TEST:s3setuid-pass" \
    -a "127.0.0.1:$PORT" -t 20000 > "$WORK/leg1.log" 2>&1

if [ $? -eq 0 ] && grep -q "INTEROP-EXEC-OK exit=0" "$WORK/leg1.log"; then
    pass "the child identity is s3test, not the root daemon"
else
    fail "the identity drop did not happen: $(tail -3 "$WORK/leg1.log")"
fi

echo "== leg 2: the session user carries the sudo rights"

HOME="$WORK" timeout 30 "$BUILD/s3interop_client" -3 -C -S exec \
    -e 'sudo -n true && printf SSH3_AGENT_PROBE_OK' -U "$S3TEST:s3setuid-pass" \
    -a "127.0.0.1:$PORT" -t 20000 > "$WORK/leg2.log" 2>&1

if [ $? -eq 0 ] && grep -q "INTEROP-EXEC-OK exit=0" "$WORK/leg2.log"; then
    pass "sudo -n true rode through as s3test"
else
    fail "the sudo leg failed: $(tail -3 "$WORK/leg2.log")"
fi

echo "== leg 3: the unknown user answers 401 at the CONNECT"

HOME="$WORK" timeout 30 "$BUILD/s3interop_client" -3 -C -S exec \
    -e "whoami" -U "s3ghost:s3setuid-pass" \
    -a "127.0.0.1:$PORT" -t 20000 > "$WORK/leg3.log" 2>&1

RC=$?

if [ "$RC" -ne 0 ] && grep -q "INTEROP-H3-STATUS 401" "$WORK/leg3.log" &&
    grep -q "run-as user=s3ghost does not resolve" "$WORK/srv.log"; then
    pass "the unknown user was refused before any spawn"
else
    fail "the unknown-user gate: rc=$RC $(tail -3 "$WORK/leg3.log")"
fi

echo "== leg 4: the second user s3key rides its own key"

HOME="$WORK" timeout 30 "$BUILD/s3interop_client" -3 -C -S exec \
    -e 'test "$(whoami)" = s3key && printf SSH3_AGENT_PROBE_OK' -K "$WORK/id_c.pem" -U "$S3KEY" \
    -a "127.0.0.1:$PORT" -t 20000 > "$WORK/leg4.log" 2>&1

if [ $? -eq 0 ] && grep -q "INTEROP-EXEC-OK exit=0" "$WORK/leg4.log"; then
    pass "the key-auth session runs as s3key"
else
    fail "the second-user leg failed: $(tail -3 "$WORK/leg4.log")"
fi

if [ "$FAILURES" -eq 0 ]; then
    echo "SETUID-E2E OK"
    exit 0
fi

echo "SETUID-E2E FAILED: $FAILURES check(s)"
exit 1
