#!/bin/sh
# the sftp chroot jail e2e (F-04): the root daemon jails every sftp
# channel behind the kernel (the sshd model, the default mode) - the
# lexical prefix jail followed symlinks while a root server did the
# file I/O, so ln -s /etc ~/etc + sftp get read root files
#
#   1. the user of the run: s3jail (created here, removed after),
#      the jail root is its real home (the getpwnam resolution leg)
#   2. the root server, the default --sftp-jail chroot rides
#   3. the positive legs: the sftp put and get inside the jail work
#      under the chroot + drop
#   4. the escape legs: the absolute symlink ~/etc -> /etc must not
#      serve get or put, the .. spelling must not walk out either
#      (the kernel refuses the walk: no lexical check is involved)
#   5. the writability gate: a group/world-writable jail root is
#      refused before the fork (the sshd rule, adapted)
#   6. the fallback leg: the unprivileged daemon folds to the
#      lexical jail at the startup and still serves the transfers
#
# the verdicts: SFTP-JAIL-E2E OK / FAILED, the INTEROP-* markers of
# the C runners on the way
#
# usage: interop/sftp-jail-e2e.sh   (WSL with the passwordless sudo)
# requires: the C runners (cmake --build build/linux-release), sudo
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD=${BUILD:-$ROOT/build/linux-release}
BIN=${SSH3C_SERVER_BIN:-$BUILD/ssh3-server}

die() {
    echo "sftp-jail-e2e: $1" >&2
    exit 1
}

[ -x "$BIN" ] || die "the daemon is not built: $BIN"
[ -x "$BUILD/s3interop_client" ] || die "s3interop_client is not built"
sudo -n true 2>/dev/null || die "the passwordless sudo is required (the user and the root run)"

FAILURES=0

pass() {
    echo "   PASS: $1"
}

fail() {
    echo "   FAIL: $1"
    FAILURES=$((FAILURES + 1))
}

# the wait for the INTEROP-LISTEN marker, the port parse rides it

wait_listen() {
    i=0

    while [ "$i" -lt 50 ]; do
        grep -q INTEROP-LISTEN "$1" 2>/dev/null && return 0
        sleep 0.1
        i=$((i + 1))
    done

    return 1
}

USER_NAME=s3jail

cleanup() {
    if [ -n "${SRVPID:-}" ]; then
        sudo -n kill -TERM "$SRVPID" >/dev/null 2>&1
    fi

    if [ -n "${SRV2PID:-}" ]; then
        kill -TERM "$SRV2PID" >/dev/null 2>&1
    fi

    if [ -n "${SRVPID3:-}" ]; then
        sudo -n kill -TERM "$SRVPID3" >/dev/null 2>&1
    fi

    sudo -n userdel -r "$USER_NAME" >/dev/null 2>&1
    rm -rf "$WORK"
}

trap cleanup EXIT INT TERM

WORK=$(mktemp -d /tmp/s3jail-e2e.XXXXXX)
chmod 755 "$WORK"

sudo -n userdel -r "$USER_NAME" >/dev/null 2>&1
sudo -n useradd -m -s /bin/sh "$USER_NAME" || die "useradd $USER_NAME failed"

# the tilde rides the local passwd lookup, no privilege involved

HOME_DIR=$(eval echo "~$USER_NAME")

[ -n "$HOME_DIR" ] || die "the home of $USER_NAME did not resolve"

# the jail content: a docs dir with one file, the escape symlink of
# the F-04 repro (the absolute symlink out of the jail); everything
# owned by the user, the home mode pinned to the lawful 0755

sudo -n chmod 755 "$HOME_DIR"
sudo -n mkdir -p "$HOME_DIR/docs"
printf 'inside-the-jail\n' | sudo -n tee "$HOME_DIR/docs/up.txt" >/dev/null
sudo -n ln -s /etc "$HOME_DIR/etc"
sudo -n chown -R "$USER_NAME:$USER_NAME" "$HOME_DIR/docs"

# the auth fixtures and the local payloads

printf '%s:s3jail-pass\n' "$USER_NAME" > "$WORK/passfile"

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/key.pem" -out "$WORK/cert.pem" \
    -days 30 -subj /CN=sftp-jail-e2e 2>/dev/null || die "openssl req failed"

chmod 644 "$WORK/passfile" "$WORK/cert.pem" "$WORK/key.pem"

printf 'upload-payload\n' > "$WORK/up.txt"

# the root run: the chroot jail is the default of the euid 0, no
# flag rides (the default leg)

sudo -n env SSH3C_PROTO=1 "$BIN" -3 -l 127.0.0.1:0 -c "$WORK/cert.pem" -k "$WORK/key.pem" \
    -P "$WORK/passfile" --enable-password-login \
    > "$WORK/srv.log" 2>&1 < /dev/null &
SRVPID=$!

wait_listen "$WORK/srv.log" || die "the daemon did not start: $(tail -3 "$WORK/srv.log")"

PORT=$(grep -oE 'port=[0-9]+' "$WORK/srv.log" | cut -d= -f2)

if grep -q "sftp chroot jail enabled" "$WORK/srv.log"; then
    pass "the root run reports the chroot jail by default"
else
    fail "no chroot jail one-liner in the root run"
fi

echo "== leg 1: the sftp put lands inside the jail (chroot + drop)"

timeout 30 "$BUILD/s3interop_client" -3 -J "put:$WORK/up.txt:docs/up.txt" \
    -U "$USER_NAME:s3jail-pass" -a "127.0.0.1:$PORT" -t 20000 > "$WORK/leg1.log" 2>&1

if [ $? -eq 0 ] && grep -q "INTEROP-SFTP-OK mode=put" "$WORK/leg1.log"; then
    pass "the put works under the chroot jail"
else
    fail "the put leg failed: $(tail -3 "$WORK/leg1.log")"
fi

if grep -q "INTEROP-SFTP-OPEN home=$HOME_DIR" "$WORK/srv.log"; then
    pass "the jail root is the session home (the getpwnam resolution)"
else
    fail "the sftp channel did not jail into $HOME_DIR"
fi

echo "== leg 2: the sftp get returns the content roundtrip"

timeout 30 "$BUILD/s3interop_client" -3 -J "get:$WORK/down.txt:docs/up.txt" \
    -U "$USER_NAME:s3jail-pass" -a "127.0.0.1:$PORT" -t 20000 > "$WORK/leg2.log" 2>&1

if [ $? -eq 0 ] && grep -q "INTEROP-SFTP-OK mode=get" "$WORK/leg2.log" &&
    cmp -s "$WORK/up.txt" "$WORK/down.txt"; then
    pass "the get roundtrip is byte-exact"
else
    fail "the get leg failed: $(tail -3 "$WORK/leg2.log")"
fi

echo "== leg 3: the absolute symlink ~/etc does not serve get"

# the F-04 repro: without the kernel jail the lexical engine opens
# /home/s3jail/etc/passwd -> /etc/passwd as root

timeout 30 "$BUILD/s3interop_client" -3 -J "get:$WORK/escape.txt:etc/passwd" \
    -U "$USER_NAME:s3jail-pass" -a "127.0.0.1:$PORT" -t 20000 > "$WORK/leg3.log" 2>&1

if [ $? -ne 0 ] && grep -q "INTEROP-SFTP-FAIL" "$WORK/leg3.log" &&
    [ ! -s "$WORK/escape.txt" ]; then
    pass "the symlinked get is refused by the kernel"
else
    fail "the symlink escape served: $(tail -3 "$WORK/leg3.log")"
fi

echo "== leg 4: the absolute symlink ~/etc does not serve put"

timeout 30 "$BUILD/s3interop_client" -3 -J "put:$WORK/up.txt:etc/s3jail-escape" \
    -U "$USER_NAME:s3jail-pass" -a "127.0.0.1:$PORT" -t 20000 > "$WORK/leg4.log" 2>&1

if [ $? -ne 0 ] && grep -q "INTEROP-SFTP-FAIL" "$WORK/leg4.log" &&
    [ ! -f /etc/s3jail-escape ]; then
    pass "the symlinked put is refused, nothing landed in /etc"
else
    fail "the symlinked put went through: $(tail -3 "$WORK/leg4.log")"
fi

echo "== leg 5: the .. spelling does not walk out"

timeout 30 "$BUILD/s3interop_client" -3 -J "get:$WORK/dotdot.txt:../../etc/passwd" \
    -U "$USER_NAME:s3jail-pass" -a "127.0.0.1:$PORT" -t 20000 > "$WORK/leg5.log" 2>&1

if [ $? -ne 0 ] && grep -q "INTEROP-SFTP-FAIL" "$WORK/leg5.log" &&
    [ ! -s "$WORK/dotdot.txt" ]; then
    pass "the .. walk stays inside the jail"
else
    fail "the .. walk served: $(tail -3 "$WORK/leg5.log")"
fi

echo "== leg 6: the group/world-writable jail root is refused"

sudo -n chmod 777 "$HOME_DIR"

timeout 30 "$BUILD/s3interop_client" -3 -J "put:$WORK/up.txt:docs/refused.txt" \
    -U "$USER_NAME:s3jail-pass" -a "127.0.0.1:$PORT" -t 20000 > "$WORK/leg6.log" 2>&1

RC=$?

sudo -n chmod 755 "$HOME_DIR"

if [ "$RC" -ne 0 ] &&
    grep -q "the jail root is group/world-writable, refused" "$WORK/srv.log"; then
    pass "the writability gate refused the channel before the fork"
else
    fail "the writability gate: rc=$RC $(tail -3 "$WORK/leg6.log")"
fi

echo "== leg 7: the unprivileged daemon folds to the lexical jail"

# the second run carries no privileges: the chroot folds at the
# startup (the one-time log) and the historical engine serves the
# same transfers - the unit shapes stay untouched.  The private
# openssl of the build tree (/home/USER/opt) is not traversable for
# the run user, the two libs ride the workdir copy

ldd "$BIN" 2>/dev/null | awk '/libssl\.so|libcrypto\.so/ {print $3}' |
    while read -r lib; do
        [ -n "$lib" ] && cp "$lib" "$WORK/"
    done

sudo -n -u "$USER_NAME" env HOME="$HOME_DIR" SSH3C_PROTO=1 LD_LIBRARY_PATH="$WORK" "$BIN" \
    -3 -l 127.0.0.1:0 -c "$WORK/cert.pem" -k "$WORK/key.pem" -P "$WORK/passfile" \
    --enable-password-login \
    > "$WORK/srv2.log" 2>&1 < /dev/null &
SRV2PID=$!

wait_listen "$WORK/srv2.log" || die "the fallback daemon did not start: $(tail -3 "$WORK/srv2.log")"

PORT2=$(grep -oE 'port=[0-9]+' "$WORK/srv2.log" | cut -d= -f2)

if grep -q "sftp chroot jail without the root privilege, the lexical jail serves" "$WORK/srv2.log"; then
    pass "the fallback logged the one-time fold"
else
    fail "no lexical fold one-liner in the unprivileged run"
fi

timeout 30 "$BUILD/s3interop_client" -3 -J "get:$WORK/fallback.txt:docs/up.txt" \
    -U "$USER_NAME:s3jail-pass" -a "127.0.0.1:$PORT2" -t 20000 > "$WORK/leg7.log" 2>&1

if [ $? -eq 0 ] && grep -q "INTEROP-SFTP-OK mode=get" "$WORK/leg7.log"; then
    pass "the lexical fallback still serves the transfers"
else
    fail "the lexical fallback leg failed: $(tail -3 "$WORK/leg7.log")"
fi

echo "== leg 8: the explicit --sftp-jail lexical keeps the in-process engine"

# the historical lexical shape: the root daemon without the override
# jails into its own home, the harness scenarios carry -H for that

sudo -n env SSH3C_PROTO=1 "$BIN" -3 -l 127.0.0.1:0 -c "$WORK/cert.pem" -k "$WORK/key.pem" \
    -P "$WORK/passfile" --enable-password-login --sftp-jail lexical -H "$HOME_DIR" \
    > "$WORK/srv3.log" 2>&1 < /dev/null &
SRVPID3=$!

wait_listen "$WORK/srv3.log" || die "the lexical daemon did not start: $(tail -3 "$WORK/srv3.log")"

PORT3=$(grep -oE 'port=[0-9]+' "$WORK/srv3.log" | cut -d= -f2)

timeout 30 "$BUILD/s3interop_client" -3 -J "get:$WORK/leg8.txt:docs/up.txt" \
    -U "$USER_NAME:s3jail-pass" -a "127.0.0.1:$PORT3" -t 20000 > "$WORK/leg8.log" 2>&1

RC=$?

if [ "$RC" -eq 0 ] && grep -q "INTEROP-SFTP-OK mode=get" "$WORK/leg8.log" &&
    ! grep -q "chroot jail" "$WORK/srv3.log"; then
    pass "the explicit lexical flag serves the historical engine under root"
else
    fail "the explicit lexical leg: rc=$RC $(tail -3 "$WORK/leg8.log")"
fi

if [ "$FAILURES" -eq 0 ]; then
    echo "SFTP-JAIL-E2E OK"
    exit 0
fi

echo "SFTP-JAIL-E2E FAILED: $FAILURES check(s)"
exit 1
