#!/bin/sh
# the system password verifier e2e (the shadow step, PLAN.md 8.2, the
# wave 1e default): the Basic method verifies against the unix
# accounts, on by default now (the sshd PasswordAuthentication yes
# canon)
#
#   1. the run user s3bench (created here, removed after): the shadow
#      entry carries the s3benchpw hash (chpasswd, the crypt form)
#   2. the root server with NO flag (the default shape,
#      --max-password-failures 3): the correct system password execs
#      and the per-session setuid drops onto s3bench (the whoami
#      leg), the wrong password answers 401 and books, the third
#      failure locks the account and even the correct password
#      answers 429 without touching shadow; the startup carries the
#      system verifier one-liner and the PermitRootLogin
#      prohibit-password one
#   3. the negative gate: the explicit --password-system off keeps
#      the closed shape - the same Basic attempt with the correct
#      system password answers 401
#   4. the env shape: SSH3_PASSWORD_SYSTEM=1 wires the verifier
#      without the flag
#   5. the fail-closed leg: the unprivileged daemon warns at the
#      startup and every system password attempt declines before the
#      lookup (the shadow is unreadable)
#   6. the login switch: --enable-password-login off closes both
#      backends at once - the correct password (the passfile line and
#      the system account alike) answers 401, the password file
#      serves nothing (the one-time warn)
#
# the verdicts: PASSWORD-SYSTEM-E2E OK / FAILED, the INTEROP-* markers
# of the C runners on the way
#
# usage: interop/password-system-e2e.sh   (WSL with the passwordless sudo)
# requires: the C runners (cmake --build build/linux-release), sudo
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD=${BUILD:-$ROOT/build/linux-release}
BIN=${SSH3C_SERVER_BIN:-$BUILD/ssh3-server}
CLI=${SSH3C_CLIENT_BIN:-$BUILD/s3interop_client}

die() {
    echo "password-system-e2e: $1" >&2
    exit 1
}

[ -x "$BIN" ] || die "the daemon is not built: $BIN"
[ -x "$CLI" ] || die "s3interop_client is not built: $CLI"
sudo -n true 2>/dev/null || die "the passwordless sudo is required (the user and the root run)"

FAILURES=0

pass() {
    echo "   PASS: $1"
}

fail() {
    echo "   FAIL: $1"
    FAILURES=$((FAILURES + 1))
}

# the run user and the servers live for the run only (the
# test-infrastructure rule: everything goes away in the trap)

S3BENCH=s3bench
S3BENCH_PW=s3benchpw
WORK=$(mktemp -d /tmp/s3pwsystem.XXXXXX)
SRVPID=""

cleanup() {
    if [ -n "$SRVPID" ]; then
        sudo -n kill -TERM "$SRVPID" >/dev/null 2>&1
    fi

    sudo -n userdel -r "$S3BENCH" >/dev/null 2>&1
    rm -rf "$WORK"
}

trap cleanup EXIT INT TERM

sudo -n userdel -r "$S3BENCH" >/dev/null 2>&1
sudo -n useradd -m -s /bin/sh "$S3BENCH" || die "useradd $S3BENCH failed"
printf '%s:%s\n' "$S3BENCH" "$S3BENCH_PW" | sudo -n chpasswd || die "chpasswd failed"

# the cert pair rides every stage (the client TOFU pin lives in the
# workdir home, one per stage client run)

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/key.pem" -out "$WORK/cert.pem" \
    -days 30 -subj /CN=password-system-e2e 2>/dev/null || die "openssl req failed"

# the authorized_keys of the negative stage: the pubkey-only shape -
# without any backend wired the CONNECT would ride the open harness
# mode, and the negative leg must prove the refusal, not the absence
# of the question

openssl genpkey -algorithm ed25519 -out "$WORK/id_c.pem" 2>/dev/null || die "openssl genpkey"

BLOB=$({
    printf '\000\000\000\013ssh-ed25519\000\000\000\040'
    openssl pkey -in "$WORK/id_c.pem" -pubout -outform DER 2>/dev/null | tail -c 32
} | base64 | tr -d '\n')

[ -n "$BLOB" ] || die "the ed25519 blob failed"

printf 'ssh-ed25519 %s password-system-e2e-c\n' "$BLOB" > "$WORK/authorized_keys"

# SRVENV carries the extra env words of the next start_server call
# (the single-token assignments, the word splitting is the shape)

SRVENV=""

# start_server <logfile> [flags...]: one root daemon, the ephemeral
# port, the INTEROP-LISTEN wait, the port lands in SRVPORT; the extra
# flags ride behind the daemon's own options (the env words go into
# SRVENV, `env` parses only the assignments before the program)

start_server() {
    SRVLOG="$1"
    shift

    # shellcheck disable=SC2086
    sudo -n env SSH3C_PROTO=1 $SRVENV "$BIN" -3 -l 127.0.0.1:0 -c "$WORK/cert.pem" \
        -k "$WORK/key.pem" "$@" > "$SRVLOG" 2>&1 < /dev/null &
    SRVPID=$!
    SRVENV=""

    i=0

    while [ "$i" -lt 50 ]; do
        grep -q INTEROP-LISTEN "$SRVLOG" 2>/dev/null && break
        sleep 0.1
        i=$((i + 1))
    done

    grep -q INTEROP-LISTEN "$SRVLOG" || die "the daemon did not start: $(tail -3 "$SRVLOG")"

    SRVPORT=$(grep -oE 'port=[0-9]+' "$SRVLOG" | cut -d= -f2)
}

stop_server() {
    sudo -n kill -TERM "$SRVPID" >/dev/null 2>&1
    wait "$SRVPID" 2>/dev/null
    SRVPID=""
}

# run_client <logfile> <pass> <exec>: one Basic exec attempt, the exit
# code and the log answer the legs

run_client() {
    HOME="$WORK" timeout 30 "$CLI" -3 -C -S exec -e "$3" -U "$S3BENCH:$2" \
        -a "127.0.0.1:$SRVPORT" -t 20000 > "$1" 2>&1
}

echo "== stage 1: the root daemon, the default shape (no flags)"

start_server "$WORK/srv1.log" --max-password-failures 3

if grep -q "system password auth enabled" "$WORK/srv1.log"; then
    pass "the default run reports the system verifier"
else
    fail "no system-password one-liner in the default run"
fi

if grep -q "PermitRootLogin prohibit-password: the root account authenticates" \
    "$WORK/srv1.log"; then
    pass "the startup carries the prohibit-password one-liner"
else
    fail "no prohibit-password one-liner in the startup"
fi

echo "== leg 1: the correct system password execs as s3bench"

# the h3 session runner verifies the marker of the -e run
# (SSH3_AGENT_PROBE_OK) in the exec output, the whoami test proves the
# per-session setuid drop on the way

if run_client "$WORK/leg1.log" "$S3BENCH_PW" \
    'test "$(whoami)" = '"$S3BENCH"' && printf SSH3_AGENT_PROBE_OK'; then
    if grep -q "INTEROP-EXEC-OK exit=0" "$WORK/leg1.log"; then
        pass "the system password opened the session, the drop is s3bench"
    else
        fail "no exec marker: $(tail -3 "$WORK/leg1.log")"
    fi
else
    fail "the correct system password was refused: $(tail -3 "$WORK/leg1.log")"
fi

echo "== leg 2: the wrong system password answers 401"

if run_client "$WORK/leg2.log" "wrong-pw" "whoami"; then
    fail "the wrong password passed"
else
    if grep -q "INTEROP-H3-STATUS 401" "$WORK/leg2.log"; then
        pass "the wrong password was refused with 401"
    else
        fail "no 401 on the wrong password: $(tail -3 "$WORK/leg2.log")"
    fi
fi

echo "== leg 3: the third failure locks the account (429 without shadow)"

run_client "$WORK/leg3a.log" "wrong-pw" "whoami" || true
run_client "$WORK/leg3b.log" "wrong-pw" "whoami" || true

if run_client "$WORK/leg3c.log" "$S3BENCH_PW" "whoami"; then
    fail "the correct password passed after the lockout"
else
    if grep -q "INTEROP-H3-STATUS 429" "$WORK/leg3c.log"; then
        pass "the locked account answers 429 (the correct password included)"
    else
        fail "no 429 on the locked account: $(tail -3 "$WORK/leg3c.log")"
    fi
fi

if grep -q "the account is locked out" "$WORK/srv1.log"; then
    pass "the lockout one-liner is in the server log"
else
    fail "no lockout one-liner in the server log"
fi

stop_server

echo "== stage 2: the explicit --password-system off keeps the closed shape"

start_server "$WORK/srv2.log" --password-system off -K "$WORK/authorized_keys"

if grep -q "system password auth" "$WORK/srv2.log"; then
    fail "the off flag still reports the verifier"
else
    pass "the off run reports nothing about the system verifier"
fi

if run_client "$WORK/leg4.log" "$S3BENCH_PW" "whoami"; then
    fail "the system password passed with the verifier off"
else
    if grep -q "INTEROP-H3-STATUS 401" "$WORK/leg4.log"; then
        pass "the correct system password is refused with the verifier off"
    else
        fail "no 401 with the verifier off: $(tail -3 "$WORK/leg4.log")"
    fi
fi

stop_server

echo "== stage 3: SSH3_PASSWORD_SYSTEM=1 wires the verifier"

SRVENV="SSH3_PASSWORD_SYSTEM=1"
start_server "$WORK/srv3.log" -K "$WORK/authorized_keys"

if grep -q "system password auth enabled" "$WORK/srv3.log"; then
    pass "the env opt-in reports the system verifier"
else
    fail "no system-password one-liner under SSH3_PASSWORD_SYSTEM=1"
fi

if run_client "$WORK/leg5.log" "$S3BENCH_PW" 'printf SSH3_AGENT_PROBE_OK'; then
    if grep -q "INTEROP-EXEC-OK exit=0" "$WORK/leg5.log"; then
        pass "the env opt-in opened the session"
    else
        fail "no exec marker under the env opt-in: $(tail -3 "$WORK/leg5.log")"
    fi
else
    fail "the env opt-in did not serve the system password: $(tail -3 "$WORK/leg5.log")"
fi

stop_server

echo "== stage 4: the unprivileged daemon fails closed (the default shape)"

(
    export SSH3C_PROTO=1
    exec "$BIN" -3 -l 127.0.0.1:0 -c "$WORK/cert.pem" -k "$WORK/key.pem" \
        > "$WORK/srv4.log" 2>&1 < /dev/null
) &
SRVPID=$!

i=0

while [ "$i" -lt 50 ]; do
    grep -q INTEROP-LISTEN "$WORK/srv4.log" 2>/dev/null && break
    sleep 0.1
    i=$((i + 1))
done

grep -q INTEROP-LISTEN "$WORK/srv4.log" || die "the daemon did not start: $(tail -3 "$WORK/srv4.log")"

SRVPORT=$(grep -oE 'port=[0-9]+' "$WORK/srv4.log" | cut -d= -f2)

if grep -q "system password auth without the root privilege" "$WORK/srv4.log"; then
    pass "the unprivileged run warns about the unreadable shadow"
else
    fail "no fail-closed warning in the unprivileged run"
fi

if run_client "$WORK/leg6.log" "$S3BENCH_PW" "whoami"; then
    fail "the unprivileged daemon answered a system password verdict"
else
    if grep -q "INTEROP-H3-STATUS 401" "$WORK/leg6.log"; then
        pass "the correct system password declines fail-closed (401)"
    else
        fail "no 401 from the fail-closed verifier: $(tail -3 "$WORK/leg6.log")"
    fi
fi

stop_server

echo "== stage 5: --enable-password-login off closes both backends"

# the passfile line for the same account: under the login off the
# correct secret (the file line and the system account alike) must
# draw 401 without either backend being consulted

printf '%s:%s\n' "$S3BENCH" "$S3BENCH_PW" > "$WORK/passfile"

start_server "$WORK/srv5.log" -P "$WORK/passfile" --enable-password-login off \
    -K "$WORK/authorized_keys"

if grep -q "the password file serves nothing" "$WORK/srv5.log"; then
    pass "the dead passfile draws the one-time warn"
else
    fail "no password-file warn under the login off"
fi

if run_client "$WORK/leg7.log" "$S3BENCH_PW" "whoami"; then
    fail "the login off still served the password"
else
    if grep -q "INTEROP-H3-STATUS 401" "$WORK/leg7.log"; then
        pass "the correct password answers 401 under the login off"
    else
        fail "no 401 under the login off: $(tail -3 "$WORK/leg7.log")"
    fi
fi

stop_server

if [ "$FAILURES" -eq 0 ]; then
    echo "PASSWORD-SYSTEM-E2E OK"
    exit 0
fi

echo "PASSWORD-SYSTEM-E2E FAILED ($FAILURES)"
exit 1
