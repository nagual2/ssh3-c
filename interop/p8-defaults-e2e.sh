#!/bin/sh
# the P8(1d)/(1e) defaults e2e: the behavioral ssh2/sshd canon of the
# waves, one leg per default the old shape would break
#
#   1. the root gate (the PermitRootLogin prohibit-password analog,
#      hardcoded): the Basic verdict for root refuses before any
#      backend and books nothing (the refusal one-liner carries the
#      marker), the root by key (the -K JWT verdict) opens the
#      session and the setuid drop proves the identity
#   2. the reverse cap 10 (the maxReverseForwardsPerUser mirror): 10
#      -R binds of one conversation come up, the 11th (the second
#      conversation of the same identity) refuses with the
#      REVERSE-CAP-DENIED limit=10 marker, the explicit
#      --max-reverse-forwards 20 takes the bind
#   3. the idle 24 h (the ssh2IdleTimeout mirror of both sides): the
#      silent session lives past the old 60 s default - the fifo
#      holder keeps the client stdin open for 70 s, the client alive
#      and 'connection is gone'-free at t=70s proves the window (the
#      post-EOF spin of the shell session is a pre-existing client
#      shape outside this wave, the run reaps it with a timeout)
#
# the client setup deadline is not armed anymore (the ConnectTimeout
# unset canon): nothing to prove in seconds, the coverage rides the
# conf code and the jump legs of cli-compat-srv
#
# the verdict: P8-DEFAULTS-E2E OK / FAILED, the INTEROP-* markers of
# the C runners on the way
#
# usage: interop/p8-defaults-e2e.sh   (WSL with the passwordless sudo)
# requires: the C runners (cmake --build build/linux-release), sudo
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD=${BUILD:-$ROOT/build/linux-release}
BIN=${SSH3C_SERVER_BIN:-$BUILD/ssh3-server}
CLI=${SSH3C_CLIENT_BIN:-$BUILD/s3interop_client}
PROD=${SSH3C_PROD_BIN:-$BUILD/ssh3}

die() {
    echo "p8-defaults-e2e: $1" >&2
    exit 1
}

[ -x "$BIN" ] || die "the daemon is not built: $BIN"
[ -x "$CLI" ] || die "s3interop_client is not built: $CLI"
[ -x "$PROD" ] || die "the product client is not built: $PROD"
sudo -n true 2>/dev/null || die "the passwordless sudo is required"

FAILURES=0

pass() {
    echo "   PASS: $1"
}

fail() {
    echo "   FAIL: $1"
    FAILURES=$((FAILURES + 1))
}

# everything lives for the run only (the test-infrastructure rule)

WORK=$(mktemp -d /tmp/s3p8def.XXXXXX)
SRVPID=""
ACLIPID=""
BCLIPID=""
HOLDPID=""

cleanup() {

    if [ -n "$BCLIPID" ]; then
        kill "$BCLIPID" 2>/dev/null
    fi

    if [ -n "$ACLIPID" ]; then
        kill "$ACLIPID" 2>/dev/null
    fi

    if [ -n "$HOLDPID" ]; then
        kill "$HOLDPID" 2>/dev/null
    fi

    if [ -n "$SRVPID" ]; then
        sudo -n kill -TERM "$SRVPID" 2>/dev/null
    fi

    rm -rf "$WORK"
}

trap cleanup EXIT INT TERM

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/key.pem" -out "$WORK/cert.pem" \
    -days 30 -subj /CN=p8-defaults-e2e 2>/dev/null || die "openssl req failed"

# the client identity of the root-by-key leg (the ed25519 pair, the
# authorized_keys line rides the raw blob)

openssl genpkey -algorithm ed25519 -out "$WORK/id_c.pem" 2>/dev/null || die "openssl genpkey"

BLOB=$({
    printf '\000\000\000\013ssh-ed25519\000\000\000\040'
    openssl pkey -in "$WORK/id_c.pem" -pubout -outform DER 2>/dev/null | tail -c 32
} | base64 | tr -d '\n')

[ -n "$BLOB" ] || die "the ed25519 blob failed"

printf 'ssh-ed25519 %s p8-defaults-e2e-c\n' "$BLOB" > "$WORK/authorized_keys"

# the passfile carries the root line the gate must refuse before any
# read

printf 'root:s3rootpw\n' > "$WORK/passfile"

# start_server <logfile> [flags...]: one root daemon, the ephemeral
# port, the INTEROP-LISTEN wait, the port lands in SRVPORT

start_server() {
    SRVLOG="$1"
    shift

    sudo -n env SSH3C_PROTO=1 "$BIN" -3 -l 127.0.0.1:0 -c "$WORK/cert.pem" \
        -k "$WORK/key.pem" "$@" > "$SRVLOG" 2>&1 < /dev/null &
    SRVPID=$!

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
    sudo -n kill -TERM "$SRVPID" 2>/dev/null
    wait "$SRVPID" 2>/dev/null
    SRVPID=""
}

# run_basic <logfile> <user:pass> [cmd]: one Basic exec attempt

run_basic() {
    HOME="$WORK" timeout 30 "$CLI" -3 -C -S exec -e "${3:-whoami}" -U "$2" \
        -a "127.0.0.1:$SRVPORT" -t 20000 > "$1" 2>&1
}

# run_pubkey <logfile> <user> [cmd]: one JWT exec attempt (-K signs,
# -U names the session user)

run_pubkey() {
    HOME="$WORK" timeout 30 "$CLI" -3 -C -S exec -e "${3:-whoami}" -K "$WORK/id_c.pem" -U "$2" \
        -a "127.0.0.1:$SRVPORT" -t 20000 > "$1" 2>&1
}

echo "== leg 1: the root gate (PermitRootLogin prohibit-password)"

start_server "$WORK/srv1.log" --password-system off -P "$WORK/passfile" \
    -K "$WORK/authorized_keys"

if grep -q "PermitRootLogin prohibit-password: the root account authenticates" \
    "$WORK/srv1.log"; then
    pass "the startup carries the prohibit-password one-liner"
else
    fail "no prohibit-password one-liner in the startup"
fi

if run_basic "$WORK/leg1a.log" "root:s3rootpw"; then
    fail "the root Basic verdict passed"
else
    if grep -q "INTEROP-H3-STATUS 401" "$WORK/leg1a.log"; then
        pass "the root password refused with 401"
    else
        fail "no 401 on the root password: $(tail -3 "$WORK/leg1a.log")"
    fi
fi

if grep -q "password auth for root refused: the root account authenticates by key only" \
    "$WORK/srv1.log"; then
    pass "the refusal one-liner names prohibit-password"
else
    fail "no root-refusal one-liner in the server log"
fi

if run_pubkey "$WORK/leg1b.log" "root" \
    'test "$(whoami)" = root && printf SSH3_AGENT_PROBE_OK'; then
    if grep -q "INTEROP-EXEC-OK exit=0" "$WORK/leg1b.log"; then
        pass "the root by key opened the session, the drop is root"
    else
        fail "no exec marker on the root key run: $(tail -3 "$WORK/leg1b.log")"
    fi
else
    fail "the root key verdict was refused: $(tail -3 "$WORK/leg1b.log")"
fi

stop_server

echo "== leg 2: the reverse cap 10 (the default), --max-reverse-forwards lifts"

start_server "$WORK/srv2.log" --password-system off

# client A books the whole default budget: 10 binds, the markers ride
# its log; the conversation constant allows exactly the same 10

HOME="$WORK" timeout 30 "$CLI" -3 -a "127.0.0.1:$SRVPORT" \
    -R "0:127.0.0.1:19931" -R "0:127.0.0.1:19931" -R "0:127.0.0.1:19931" \
    -R "0:127.0.0.1:19931" -R "0:127.0.0.1:19931" -R "0:127.0.0.1:19931" \
    -R "0:127.0.0.1:19931" -R "0:127.0.0.1:19931" -R "0:127.0.0.1:19931" \
    -R "0:127.0.0.1:19931" -t 15000 > "$WORK/cli-a.log" 2>&1 < /dev/null &
ACLIPID=$!

i=0

while [ "$i" -lt 100 ]; do
    [ "$(grep -c "INTEROP-RFWD-OK" "$WORK/cli-a.log" 2>/dev/null)" = "10" ] && break
    sleep 0.1
    i=$((i + 1))
done

OKN=$(grep -c "INTEROP-RFWD-OK" "$WORK/cli-a.log" 2>/dev/null || true)

if [ "$OKN" = "10" ]; then
    pass "the 10 binds of the first conversation came up"
else
    fail "only $OKN of 10 binds came up: $(tail -3 "$WORK/cli-a.log")"
fi

# client B rides the second conversation of the same (empty) identity:
# the per-user budget is full, the bind refuses before any socket

HOME="$WORK" timeout 20 "$CLI" -3 -a "127.0.0.1:$SRVPORT" \
    -R "0:127.0.0.1:19931" -t 5000 > "$WORK/cli-b.log" 2>&1 < /dev/null &
BCLIPID=$!

wait "$BCLIPID" 2>/dev/null
BCLIPID=""

DENN=$(grep -c "INTEROP-RFWD-DENIED" "$WORK/cli-b.log" 2>/dev/null || true)

if [ "$DENN" -ge 1 ] && grep -q "REVERSE-CAP-DENIED.*limit=10" "$WORK/srv2.log" &&
    grep -q "too many reverse forwards for user - (limit 10)" "$WORK/srv2.log"; then
    pass "the 11th bind refused with the cap marker (limit=10)"
else
    fail "no cap refusal: denied=$DENN $(grep -m1 'REVERSE-CAP\|refus' "$WORK/srv2.log")"
fi

kill "$ACLIPID" 2>/dev/null
wait "$ACLIPID" 2>/dev/null
ACLIPID=""

stop_server

# the explicit 20: the 10 binds of client C hold the budget, the
# fresh conversation of client D takes the 11th bind of the same
# identity (the re-anchor claims the conversation slot after the
# per-user gate passed)

start_server "$WORK/srv3.log" --password-system off --max-reverse-forwards 20

HOME="$WORK" timeout 30 "$CLI" -3 -a "127.0.0.1:$SRVPORT" \
    -R "0:127.0.0.1:19931" -R "0:127.0.0.1:19931" -R "0:127.0.0.1:19931" \
    -R "0:127.0.0.1:19931" -R "0:127.0.0.1:19931" -R "0:127.0.0.1:19931" \
    -R "0:127.0.0.1:19931" -R "0:127.0.0.1:19931" -R "0:127.0.0.1:19931" \
    -R "0:127.0.0.1:19931" -t 12000 > "$WORK/cli-c.log" 2>&1 < /dev/null &
ACLIPID=$!

i=0

while [ "$i" -lt 100 ]; do
    [ "$(grep -c "INTEROP-RFWD-OK" "$WORK/cli-c.log" 2>/dev/null)" = "10" ] && break
    sleep 0.1
    i=$((i + 1))
done

HOME="$WORK" timeout 20 "$CLI" -3 -a "127.0.0.1:$SRVPORT" \
    -R "0:127.0.0.1:19931" -t 5000 > "$WORK/cli-d.log" 2>&1 < /dev/null &
BCLIPID=$!

wait "$BCLIPID" 2>/dev/null
BCLIPID=""

kill "$ACLIPID" 2>/dev/null
wait "$ACLIPID" 2>/dev/null
ACLIPID=""

if grep -q "INTEROP-RFWD-OK" "$WORK/cli-d.log"; then
    pass "the explicit 20 takes the 11th bind of the user"
else
    fail "the cap-20 run refused the bind: $(tail -3 "$WORK/cli-d.log")"
fi

stop_server

echo "== leg 3: the idle 24 h (the silent session lives past the old 60 s)"

# the unprivileged daemon of the idle-close shape: the JWT verdict
# rides the -K file, the session keeps the daemon identity (bob
# resolves nowhere, the run-as stays off unprivileged)

env SSH3C_PROTO=1 "$BIN" -3 -l 127.0.0.1:0 -c "$WORK/cert.pem" -k "$WORK/key.pem" \
    -K "$WORK/idle_keys" > "$WORK/srv4.log" 2>&1 < /dev/null &
SRVPID=$!

i=0

while [ "$i" -lt 50 ]; do
    grep -q INTEROP-LISTEN "$WORK/srv4.log" 2>/dev/null && break
    sleep 0.1
    i=$((i + 1))
done

grep -q INTEROP-LISTEN "$WORK/srv4.log" || die "the daemon did not start: $(tail -3 "$WORK/srv4.log")"

SRVPORT=$(grep -oE 'port=[0-9]+' "$WORK/srv4.log" | cut -d= -f2)

mkdir -p "$WORK/.ssh3"
DER=$(openssl x509 -in "$WORK/cert.pem" -outform DER 2>/dev/null | base64 -w0)
printf '%s:%s/ssh3-term x509-certificate %s\n' "127.0.0.1" "$SRVPORT" "$DER" \
    > "$WORK/.ssh3/known_hosts"

# the ssh2-canon identity of the product client (the ed25519 pair)

ssh-keygen -t ed25519 -N "" -C p8-defaults-idle -f "$WORK/id_good" -q || die "ssh-keygen"
cp "$WORK/id_good.pub" "$WORK/idle_keys"

# the fifo holder keeps the client stdin open with no data (no EOF,
# no FIN, nothing flows - the idle window runs); the hold covers the
# old 60 s default with a margin, the timeout reaps the client after
# (the shell session rides a pre-existing post-EOF spin, the exit
# code of the reap carries no verdict)

mkfifo "$WORK/in" || die "mkfifo"
sleep 70 > "$WORK/in" &
HOLDPID=$!

START=$(date +%s)

HOME="$WORK" timeout 90 "$PROD" -i "$WORK/id_good" "bob@127.0.0.1:$SRVPORT/ssh3-term" \
    < "$WORK/in" > "$WORK/cli-idle.log" 2>&1 &
CLIPID=$!

# the proof window: at t=70s the old defaults (60 s both sides)
# would have torn the silent session down already

sleep 71

ALIVE=0

if kill -0 "$CLIPID" 2>/dev/null; then
    ALIVE=1
fi

kill "$CLIPID" 2>/dev/null
wait "$CLIPID" 2>/dev/null

TOOK=$(( $(date +%s) - START ))
kill "$HOLDPID" 2>/dev/null
HOLDPID=""

stop_server

if [ "$ALIVE" -eq 1 ] && ! grep -q "connection is gone" "$WORK/cli-idle.log" &&
    ! grep -q "the setup timed out" "$WORK/cli-idle.log"; then
    pass "the silent session lived past the old 60 s window (${TOOK}s, no idle close)"
else
    fail "the session died under the silence (alive=$ALIVE, ${TOOK}s): $(tail -2 "$WORK/cli-idle.log")"
fi

if [ "$FAILURES" -eq 0 ]; then
    echo "P8-DEFAULTS-E2E OK"
    exit 0
fi

echo "P8-DEFAULTS-E2E FAILED ($FAILURES)"
exit 1
