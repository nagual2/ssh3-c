#!/bin/sh
# the agent auth e2e (the backlog row 13): the client signs its JWT
# with the ssh-agent key (--agent-key, SSH_AUTH_SOCK) against the C
# daemon; the live ssh-agent rides the stand (the socket in $WORK),
# the ed25519 key adds there; the negatives cover the foreign pubkey
# and the missing socket
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD=${BUILD:-$ROOT/build/linux-release}
WORK=$(mktemp -d /tmp/s3ag.XXXXXX)
FAILURES=0

die() {
    echo "agent-auth-e2e: $1" >&2
    exit 1
}

[ -x "$BUILD/ssh3" ] || die "the product client is not built: $BUILD/ssh3"
[ -x "$BUILD/ssh3-server" ] || die "the daemon is not built: $BUILD/ssh3-server"
[ -x /usr/bin/ssh-agent ] || die "ssh-agent is not available"

pkill -f 's3ag\.' 2>/dev/null

cleanup() {
    pkill -f 's3ag\.' 2>/dev/null
    [ -f "$WORK/agent.pid" ] && kill "$(cat "$WORK/agent.pid")" 2>/dev/null
    rm -rf "$WORK"
}

trap cleanup EXIT INT TERM

# the identity: the PKCS8 ed25519 of the C client (the same pair adds
# into the agent); the authorized keys line builds by hand

openssl genpkey -algorithm ed25519 -out "$WORK/priv.pem" 2>/dev/null || die "openssl genpkey failed"

{
    printf '\000\000\000\013ssh-ed25519\000\000\000\040'
    openssl pkey -in "$WORK/priv.pem" -pubout -outform DER 2>/dev/null | tail -c 32
} | base64 | tr -d '\n' > "$WORK/blob.pub"

printf 'ssh-ed25519 %s agent-auth-e2e\n' "$(cat "$WORK/blob.pub")" > "$WORK/authorized_keys"

# the public part for --agent-key: the OpenSSH pub line of the same
# key (the wire blob the agent matches on)

printf 'ssh-ed25519 %s\n' "$(cat "$WORK/blob.pub")" > "$WORK/agent.pub"

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/key.pem" \
    -out "$WORK/cert.pem" -days 2 -subj /CN=agent-auth-e2e 2>/dev/null || die "openssl req failed"

# the live ssh-agent: the socket in $WORK, the key added (ssh-add
# reads the OpenSSH container, the PKCS8 body converts)

CB_WORK="$WORK" python3 - <<'EOF'
import os
from cryptography.hazmat.primitives.serialization import (load_pem_private_key,
    Encoding, PrivateFormat, NoEncryption)
work = os.environ["CB_WORK"]
key = load_pem_private_key(open(work + "/priv.pem", "rb").read(), password=None)
open(work + "/priv-openssh", "wb").write(
    key.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()))
EOF
chmod 600 "$WORK/priv-openssh"

eval "$(ssh-agent -a "$WORK/agent.sock")" > /dev/null
echo $SSH_AGENT_PID > "$WORK/agent.pid"

ssh-add "$WORK/priv-openssh" > /dev/null 2>&1 || die "ssh-add failed"

# the daemon and the pin store

setsid nohup env SSH3C_PROTO=1 "$BUILD/ssh3-server" -3 \
    -l "127.0.0.1:0" -c "$WORK/cert.pem" -k "$WORK/key.pem" \
    -K "$WORK/authorized_keys" > "$WORK/srv.log" 2>&1 < /dev/null &

i=0
while [ "$i" -lt 50 ]; do
    grep -q INTEROP-LISTEN "$WORK/srv.log" 2>/dev/null && break
    sleep 0.1
    i=$((i + 1))
done

PORT=$(grep -oE 'port=[0-9]+' "$WORK/srv.log" | cut -d= -f2)
[ -n "$PORT" ] || die "the daemon did not start"

mkdir -p "$WORK/home/.ssh3"

printf '127.0.0.1:%s/ssh3-term x509-certificate %s\n' "$PORT" \
    "$(openssl x509 -in "$WORK/cert.pem" -outform DER | base64 -w0)" \
    >> "$WORK/home/.ssh3/known_hosts"

# the liveness gates: the daemon serves the exec, the agent holds the
# key - the dead stand would poison every leg with the timeout rows

HOME="$WORK/home" timeout 10 "$BUILD/ssh3" -i "$WORK/priv.pem" \
    "client@127.0.0.1:$PORT/ssh3-term" true > /dev/null 2>"$WORK/live.err" \
    || die "the daemon does not serve exec: $(tail -1 "$WORK/live.err")"

SSH_AUTH_SOCK="$WORK/agent.sock" ssh-add -l 2>/dev/null | grep -q . \
    || die "the agent holds no keys"

echo "== leg 1: the agent-signed JWT authenticates (AGENT-AUTH-OK)"

HOME="$WORK/home" SSH_AUTH_SOCK="$WORK/agent.sock" timeout 30 "$BUILD/ssh3" \
    --agent-key "$WORK/agent.pub" \
    "client@127.0.0.1:$PORT/ssh3-term" "printf AGENT-AUTH-OK" \
    > "$WORK/leg1.out" 2>"$WORK/leg1.err"

rc=$?

if [ "$rc" -eq 0 ] && grep -q "AGENT-AUTH-OK" "$WORK/leg1.out"; then
    echo "   PASS: the agent-signed JWT rode the session"
else
    echo "   FAIL: rc=$rc"
    tail -4 "$WORK/leg1.err" | sed 's/^/   /'
    FAILURES=$((FAILURES + 1))
fi

echo "== leg 2: the foreign pubkey refuses (AGENT-FOREIGN-REJECT)"

openssl genpkey -algorithm ed25519 -out "$WORK/foreign.pem" 2>/dev/null
{
    printf '\000\000\000\013ssh-ed25519\000\000\000\040'
    openssl pkey -in "$WORK/foreign.pem" -pubout -outform DER 2>/dev/null | tail -c 32
} | base64 | tr -d '\n' > "$WORK/foreign-blob.pub"
printf 'ssh-ed25519 %s foreign\n' "$(cat "$WORK/foreign-blob.pub")" > "$WORK/foreign.pub"

HOME="$WORK/home" SSH_AUTH_SOCK="$WORK/agent.sock" timeout 30 "$BUILD/ssh3" \
    --agent-key "$WORK/foreign.pub" \
    "client@127.0.0.1:$PORT/ssh3-term" "echo no" \
    > "$WORK/leg2.out" 2>"$WORK/leg2.err"

rc=$?

if [ "$rc" -ne 0 ] && grep -q "does not hold the key" "$WORK/leg2.err"; then
    echo "   PASS: the agent does not hold the foreign key, the clean refusal"
else
    echo "   FAIL: rc=$rc (the refusal shape missed)"
    tail -4 "$WORK/leg2.err" | sed 's/^/   /'
    FAILURES=$((FAILURES + 1))
fi

echo "== leg 3: the mix --agent-key with -i refuses (AGENT-MIX-REJECT)"

HOME="$WORK/home" SSH_AUTH_SOCK="$WORK/agent.sock" timeout 30 "$BUILD/ssh3" \
    --agent-key "$WORK/agent.pub" -i "$WORK/foreign.pem" \
    "client@127.0.0.1:$PORT/ssh3-term" "echo no" \
    > /dev/null 2>"$WORK/leg3.err"

rc=$?

if [ "$rc" -ne 0 ] && grep -q "excludes" "$WORK/leg3.err"; then
    echo "   PASS: the --agent-key and -i mix refused"
else
    echo "   FAIL: rc=$rc (the mix rode)"
    tail -4 "$WORK/leg3.err" | sed 's/^/   /'
    FAILURES=$((FAILURES + 1))
fi

echo "== leg 4: the missing SSH_AUTH_SOCK refuses before the dial (AGENT-NOSOCK-REJECT)"

HOME="$WORK/home" env -u SSH_AUTH_SOCK timeout 30 "$BUILD/ssh3" \
    --agent-key "$WORK/agent.pub" \
    "client@127.0.0.1:$PORT/ssh3-term" "echo no" \
    > /dev/null 2>"$WORK/leg4.err"

rc=$?

if [ "$rc" -ne 0 ] && grep -q "SSH_AUTH_SOCK" "$WORK/leg4.err"; then
    echo "   PASS: the missing socket refused before the dial"
else
    echo "   FAIL: rc=$rc (the gate missed)"
    tail -4 "$WORK/leg4.err" | sed 's/^/   /'
    FAILURES=$((FAILURES + 1))
fi

if [ "$FAILURES" -eq 0 ]; then
    echo "AGENT-AUTH-E2E OK"
    exit 0
fi

echo "AGENT-AUTH-E2E FAILED: $FAILURES check(s)"
exit 1
