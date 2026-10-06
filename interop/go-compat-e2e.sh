#!/bin/sh
# the go-compat e2e (P7.3): the ssh3-server daemon serves the Go fork
# client (project/ssh3), the divergences of the infra migration:
#
#   1. the exec session rides through - the version header invariant:
#      the Server field rides EVERY verdict (the reference sets it
#      before any auth decision), so the client never reports
#      "Could not parse server version", not even on the refusals;
#      the positive run asserts the exact version string the client
#      parses out of the 200
#   2. the v6 client: the [::1] bind, and the dual-stack [::] bind
#      serving the v4 client through the same socket (the reference
#      -bind default "[::]:443")
#   3. the identities files: the authorized_identities format (the
#      non-key lines skip), the repeatable -K chain, and the default
#      chain consulted when no -K is given
#   4. the --url-path route (the reference -url-path) and the
#      password opt-in (the reference enablePasswordLogin default:
#      the -P file serves nothing until the login is opted into)
#
# usage: go-compat-e2e.sh [worktree] [go-ssh3-binary]
set -u

ROOT=${1:-/mnt/c/Git/project/ssh3-c}
GOSSH3=${2:-/tmp/go-ssh3}
BUILD=$ROOT/build/linux-release
DAEMON=$BUILD/ssh3-server
CLI=$BUILD/s3interop_client
FAILURES=0

die() {
    echo "go-compat-e2e: $1" >&2
    exit 1
}

fail() {
    echo "   FAIL: $1"
    FAILURES=$((FAILURES + 1))
}

pass() {
    echo "   PASS: $1"
}

[ -x "$DAEMON" ] || die "the daemon is not built ($DAEMON)"
[ -x "$CLI" ] || die "the C client binary is not built ($CLI)"
[ -x "$GOSSH3" ] || die "the go ssh3 client is not built ($GOSSH3)"

W=$(mktemp -d /tmp/go-compat-e2e.XXXXXX)
trap 'rm -rf "$W"' EXIT

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/key.pem" -out "$W/cert.pem" \
    -days 30 -subj /CN=go-compat-e2e 2>/dev/null || die "openssl req failed"

# the HOME isolation keeps the client known_hosts out of the real one
export HOME=$W

SRVPID=""
SRVENV="SSH3C_PROTO=1"

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

port_of() {
    grep -oE 'port=[0-9]+' "$1" | head -1 | cut -d= -f2
}

start_daemon() {
    # start_daemon <logfile> <extra daemon args...>
    LOG=$1
    shift

    # no setsid: the $! stays the daemon pid, the stop_daemon below
    # kills and reaps exactly this one (a setsid job would detach and
    # leak the listener); the $SRVENV word-splitting carries the
    # optional extra environment (the password opt-in probe)

    # shellcheck disable=SC2086
    nohup env $SRVENV "$DAEMON" -3 -c "$W/cert.pem" -k "$W/key.pem" "$@" \
        > "$LOG" 2>&1 < /dev/null &

    SRVPID=$!

    if ! wait_for "$LOG" INTEROP-LISTEN; then
        echo "   FAIL: the daemon did not come up ($*)"
        FAILURES=$((FAILURES + 1))
        return 1
    fi

    PORT=$(port_of "$LOG")

    return 0
}

stop_daemon() {
    kill "$SRVPID" 2>/dev/null
    wait "$SRVPID" 2>/dev/null
    SRVENV="SSH3C_PROTO=1"
}

# the identities: the OpenSSH keys feed the Go client, the good one
# is authorized everywhere, the foreign one nowhere

ssh-keygen -t ed25519 -N "" -C go-compat-good -f "$W/id_good" -q || die "ssh-keygen good"
ssh-keygen -t ed25519 -N "" -C go-compat-foreign -f "$W/id_foreign" -q || die "ssh-keygen foreign"

go_exec() {
    # go_exec <userhost:port/path> [extra client args...]
    TARGET=$1
    shift

    # the -v rides every run: the debug log carries the parsed server
    # version string the invariant asserts

    timeout 30 "$GOSSH3" -v -insecure -o StrictHostKeyChecking=no -privkey "$W/id_good" \
        "$TARGET" printf go-compat-e2e-ok < /dev/null 2>"$W/go.log"
}

foreign_exec() {
    # foreign_exec <userhost:port/path>
    timeout 30 "$GOSSH3" -v -insecure -o StrictHostKeyChecking=no -privkey "$W/id_foreign" \
        "$1" printf nope < /dev/null 2>"$W/go.log"
}

echo "== 1: the exec session and the version header invariant (the Go client)"

{
    echo "# the go-compat fixture"
    echo
    echo "no-pty $(cat "$W/id_good.pub") go-compat-e2e"
} > "$W/authorized_keys"

start_daemon "$W/srv1.log" -l 127.0.0.1:0 -K "$W/authorized_keys" || exit 1

OUT=$(go_exec "bob@127.0.0.1:$PORT/ssh3-term")

if [ "$OUT" = "go-compat-e2e-ok" ]; then
    pass "the exec rode through (the Go client)"
else
    fail "the exec failed out=$OUT $(cat "$W/go.log")"
fi

if grep -q 'server has valid version "SSH 3.0 ssh3-c 0.1.0 experimental_spec_version=alpha-00"' \
    "$W/go.log"; then
    pass 'the client parsed "SSH 3.0 ssh3-c 0.1.0 experimental_spec_version=alpha-00"'
else
    fail "no parsed server version in the client log $(grep -i version "$W/go.log" | head -2)"
fi

if grep -q "Could not parse server version" "$W/go.log"; then
    fail "the client reported a version parse error on the 200"
else
    pass "no version parse error on the 200"
fi

OUT=$(foreign_exec "bob@127.0.0.1:$PORT/ssh3-term")
RC=$?

if [ "$RC" -ne 0 ]; then
    pass "the foreign key was refused"
else
    fail "the foreign key exec unexpectedly succeeded"
fi

if grep -q "Could not parse server version" "$W/go.log"; then

    # the divergence of the migration: a refusal without the Server
    # field read as an empty version and masked the real verdict

    fail "the client reported a version parse error on the refusal"
else
    pass "no version parse error on the refusal (the Server field rides it)"
fi

stop_daemon

echo "== 2: the v6 client and the dual-stack bind"

start_daemon "$W/srv2.log" -l '[::1]:0' -K "$W/authorized_keys" || exit 1

OUT=$(go_exec "bob@[::1]:$PORT/ssh3-term")

if [ "$OUT" = "go-compat-e2e-ok" ]; then
    pass "the v6 client rode through ([::1] bind)"
else
    fail "the v6 client failed out=$OUT $(cat "$W/go.log")"
fi

stop_daemon

start_daemon "$W/srv3.log" -l '[::]:0' -K "$W/authorized_keys" || exit 1

OUT=$(go_exec "bob@[::1]:$PORT/ssh3-term")

if [ "$OUT" = "go-compat-e2e-ok" ]; then
    pass "the v6 client rode through (the dual [::] bind)"
else
    fail "the v6 client on the dual bind failed out=$OUT $(cat "$W/go.log")"
fi

OUT=$(go_exec "bob@127.0.0.1:$PORT/ssh3-term")

if [ "$OUT" = "go-compat-e2e-ok" ]; then
    pass "the v4 client rode through the same dual socket"
else
    fail "the v4 client on the dual bind failed out=$OUT $(cat "$W/go.log")"
fi

if grep -q "V6ONLY=0" "$W/srv3.log"; then
    pass "the dual mode logged (V6ONLY=0)"
else
    fail "no dual-mode log line in the daemon log"
fi

stop_daemon

echo "== 3: the identities files"

# the authorized_identities shape: the fork file carries the plugin
# and oidc directive lines beside the keys, the walker skips the
# non-key lines and picks the key

{
    echo "# the identities fixture"
    echo
    echo "plugin:some-plugin some-option"
    echo "oidc https://issuer.example client_id user@example.org"
    echo
    echo "no-pty $(cat "$W/id_good.pub") go-compat-identities"
} > "$W/authorized_identities"

start_daemon "$W/srv4.log" -l 127.0.0.1:0 -K "$W/authorized_identities" || exit 1

OUT=$(go_exec "bob@127.0.0.1:$PORT/ssh3-term")

if [ "$OUT" = "go-compat-e2e-ok" ]; then
    pass "the authorized_identities file served the key"
else
    fail "the identities file exec failed out=$OUT $(cat "$W/go.log")"
fi

stop_daemon

# the repeatable -K: the key lives in the second file, the walk goes
# past the first (the reference merges both files); the decoy key in
# the first file is neither of the two clients'

ssh-keygen -t ed25519 -N "" -C go-compat-decoy -f "$W/id_decoy" -q || die "ssh-keygen decoy"

echo "no-pty $(cat "$W/id_decoy.pub") decoy-only" > "$W/keys_a"
echo "no-pty $(cat "$W/id_good.pub") good-second" > "$W/keys_b"

start_daemon "$W/srv5.log" -l 127.0.0.1:0 -K "$W/keys_a" -K "$W/keys_b" || exit 1

OUT=$(go_exec "bob@127.0.0.1:$PORT/ssh3-term")

if [ "$OUT" = "go-compat-e2e-ok" ]; then
    pass "the second -K file served the key"
else
    fail "the repeatable -K exec failed out=$OUT $(cat "$W/go.log")"
fi

OUT=$(foreign_exec "bob@127.0.0.1:$PORT/ssh3-term")
RC=$?

if [ "$RC" -ne 0 ]; then
    pass "the foreign key was refused with the -K chain on"
else
    fail "the foreign key unexpectedly verified"
fi

stop_daemon

# the default chain: without any -K the daemon consults the user
# database files (~/.ssh3/authorized_identities, then
# ~/.ssh/authorized_keys); the session user is the operator running
# the daemon (getpwnam resolves the real home), the foreign key is in
# neither file, the verdict is the refusal - the path resolution
# itself rides the unit test

ME=$(id -un)

start_daemon "$W/srv6.log" -l 127.0.0.1:0 || exit 1

OUT=$(foreign_exec "$ME@127.0.0.1:$PORT/ssh3-term")
RC=$?

if [ "$RC" -ne 0 ]; then
    pass "the default chain refused the foreign key"
else
    fail "the default chain exec unexpectedly succeeded"
fi

if grep -qE "pubkey auth: user=$ME rejected|no default chain for user=$ME" "$W/srv6.log"; then
    pass "the daemon walked the default chain (the verdict logged)"
else
    fail "no default-chain verdict in the daemon log"
fi

stop_daemon

echo "== 4: the url-path route and the password opt-in"

start_daemon "$W/srv7.log" -l 127.0.0.1:0 -K "$W/authorized_keys" --url-path /custom-term || exit 1

OUT=$(go_exec "bob@127.0.0.1:$PORT/custom-term")

if [ "$OUT" = "go-compat-e2e-ok" ]; then
    pass "the custom --url-path route served the session"
else
    fail "the custom route exec failed out=$OUT $(cat "$W/go.log")"
fi

OUT=$(go_exec "bob@127.0.0.1:$PORT/ssh3-term")
RC=$?

if [ "$RC" -ne 0 ]; then
    pass "the default path is refused under the custom route"
else
    fail "the default path unexpectedly passed"
fi

if grep -q "Could not parse server version" "$W/go.log"; then
    fail "the wrong-path 400 lost the version header"
else
    pass "no version parse error on the wrong-path 400"
fi

stop_daemon

# the password opt-in: -P alone serves nothing (the reference
# enablePasswordLogin default), the opt-in (flag or env) turns it on;
# the Basic credentials ride the C client (the Go client builds with
# disable_password_auth)

printf 'bob:secret123\n' > "$W/pwfile"

start_daemon "$W/srv8.log" -l 127.0.0.1:0 -P "$W/pwfile" || exit 1

if timeout 30 "$CLI" -3 -C -S exec -U bob:secret123 -a "127.0.0.1:$PORT" -t 20000 \
    > "$W/pw-off.log" 2>&1; then
    fail "the Basic credentials passed without the opt-in"
else
    pass "the Basic credentials refused without the opt-in"
fi

stop_daemon

start_daemon "$W/srv9.log" -l 127.0.0.1:0 -P "$W/pwfile" --enable-password-login || exit 1

if timeout 30 "$CLI" -3 -C -S exec -U bob:secret123 -a "127.0.0.1:$PORT" -t 20000 \
    > "$W/pw-on.log" 2>&1 && grep -q "INTEROP-EXEC-OK exit=0" "$W/pw-on.log"; then
    pass "the Basic credentials passed with the opt-in (the flag)"
else
    fail "the opted-in password login refused $(tail -3 "$W/pw-on.log")"
fi

stop_daemon

start_daemon "$W/srv10.log" -l 127.0.0.1:0 -P "$W/pwfile" || exit 1

# the env form of the opt-in: the daemon-side environment (the
# reference env default for the systemd EnvironmentFile installs)

SRVENV="SSH3C_PROTO=1 SSH3_ENABLE_PASSWORD_LOGIN=1"

start_daemon "$W/srv10.log" -l 127.0.0.1:0 -P "$W/pwfile" || exit 1

timeout 30 "$CLI" -3 -C -S exec -U bob:secret123 \
    -a "127.0.0.1:$PORT" -t 20000 > "$W/pw-env.log" 2>&1
RC=$?

if [ "$RC" -eq 0 ] && grep -q "INTEROP-EXEC-OK exit=0" "$W/pw-env.log"; then
    pass "the Basic credentials passed with the opt-in (the env)"
else
    fail "the env opt-in refused rc=$RC $(tail -3 "$W/pw-env.log")"
fi

stop_daemon

echo
if [ "$FAILURES" -eq 0 ]; then
    echo "go-compat-e2e: OK"
    exit 0
fi

echo "go-compat-e2e: $FAILURES failure(s)"
exit 1
