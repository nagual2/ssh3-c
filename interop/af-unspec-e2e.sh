#!/bin/sh
# the af-unspec dial canon (the ssh(1) shape): without the -4/-6 pick
# the operand dials both families - the literal rides its own family
# (the inet_pton fast-path), the name takes the first resolver answer
# (the ssh order); -4/-6 force and refuse the foreign literal.  The
# v6-only daemon discriminates: a pass against [::1] proves the v6
# dial, a v4 dial cannot reach it
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD=${BUILD:-$ROOT/build/linux-release}
WORK=$(mktemp -d /tmp/s3af.XXXXXX)
FAILURES=0

die() {
    echo "af-unspec-e2e: $1" >&2
    exit 1
}

[ -x "$BUILD/ssh3" ] || die "the product client is not built: $BUILD/ssh3"
[ -x "$BUILD/ssh3-server" ] || die "the daemon is not built: $BUILD/ssh3-server"

# a hard-killed previous run leaves its setsid servers behind; sweep
# them by the tmp marker in their cmdline

pkill -f 's3af\.' 2>/dev/null

cleanup() {
    pkill -f 's3af\.' 2>/dev/null
    rm -rf "$WORK"
}

trap cleanup EXIT INT TERM

# the identity: the PKCS8 ed25519 of the C client, the authorized
# keys line built by hand (ssh-keygen reads no PKCS8 ed25519)

openssl genpkey -algorithm ed25519 -out "$WORK/priv.pem" 2>/dev/null || die "openssl genpkey failed"

{
    printf '\000\000\000\013ssh-ed25519\000\000\000\040'
    openssl pkey -in "$WORK/priv.pem" -pubout -outform DER 2>/dev/null | tail -c 32
} | base64 | tr -d '\n' > "$WORK/blob.pub"

printf 'ssh-ed25519 %s af-unspec-e2e\n' "$(cat "$WORK/blob.pub")" > "$WORK/authorized_keys"

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/key.pem" \
    -out "$WORK/cert.pem" -days 2 -subj /CN=af-unspec-e2e 2>/dev/null \
    || die "openssl req failed"

wait_listen() {
    i=0
    while [ "$i" -lt 50 ]; do
        if grep -q INTEROP-LISTEN "$1" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
        i=$((i + 1))
    done

    return 1
}

port_of() {
    grep -oE 'port=[0-9]+' "$1" | cut -d= -f2
}

# the stands: the v6-only daemon (the [::1] bind accepts the v6
# family only) and the v4 one; the cert rides both

setsid nohup env SSH3C_PROTO=1 "$BUILD/ssh3-server" -3 \
    -l "[::1]:0" -c "$WORK/cert.pem" -k "$WORK/key.pem" \
    -K "$WORK/authorized_keys" > "$WORK/srv6.log" 2>&1 < /dev/null &

setsid nohup env SSH3C_PROTO=1 "$BUILD/ssh3-server" -3 \
    -l "127.0.0.1:0" -c "$WORK/cert.pem" -k "$WORK/key.pem" \
    -K "$WORK/authorized_keys" > "$WORK/srv4.log" 2>&1 < /dev/null &

wait_listen "$WORK/srv6.log" || die "the v6 daemon did not start"
wait_listen "$WORK/srv4.log" || die "the v4 daemon did not start"

V6PORT=$(port_of "$WORK/srv6.log")
V4PORT=$(port_of "$WORK/srv4.log")

# the pin stores: the v6 literal rides the bracket form (the ssh2
# canon of the key text), the AAAA name rides the bare name form

mkdir -p "$WORK/home6/.ssh3"
mkdir -p "$WORK/home4/.ssh3"

printf '[::1]:%s/ssh3-term x509-certificate %s\n' "$V6PORT" \
    "$(openssl x509 -in "$WORK/cert.pem" -outform DER | base64 -w0)" \
    >> "$WORK/home6/.ssh3/known_hosts"

printf '127.0.0.1:%s/ssh3-term x509-certificate %s\n' "$V4PORT" \
    "$(openssl x509 -in "$WORK/cert.pem" -outform DER | base64 -w0)" \
    >> "$WORK/home4/.ssh3/known_hosts"

# the AAAA name for the name leg: the probe picks the candidate whose
# first sorted DGRAM answer (the ssh order, what the client takes) is
# a plain v6 address - the v6-only daemon would refuse the v4 dial,
# the pass proves the v6 family

V6NAME=

if command -v getent >/dev/null 2>&1; then
    for cand in ip6-localhost ip6-loopback; do
        first=$(getent ahosts "$cand" 2>/dev/null | awk '$2 == "DGRAM" {print $1; exit}')

        case "$first" in
            "" | ::ffff:*) ;;
            ::*) V6NAME=$cand ;;
        esac

        [ -n "$V6NAME" ] && break
    done
fi

echo "== leg 1: the v6 literal dials without -6 (AF-V6LITERAL-OK)"

if HOME="$WORK/home6" timeout 40 "$BUILD/ssh3" -i "$WORK/priv.pem" \
    "client@[::1]:$V6PORT/ssh3-term" "printf AF-V6LITERAL-OK" \
    > "$WORK/leg1.out" 2>"$WORK/leg1.err" &&
    grep -q "AF-V6LITERAL-OK" "$WORK/leg1.out"; then
    echo "   PASS: the v6 literal rode its own family unforced"
else
    echo "   FAIL: rc=$?"
    tail -8 "$WORK/leg1.err" | sed 's/^/   /'
    FAILURES=$((FAILURES + 1))
fi

echo "== leg 2: the AAAA name dials without -6 (AF-AAAA-OK)"

if [ -z "$V6NAME" ]; then
    echo "   SKIP: no pure AAAA name in the resolver (getent probe)"

else
    printf '%s:%s/ssh3-term x509-certificate %s\n' "$V6NAME" "$V6PORT" \
        "$(openssl x509 -in "$WORK/cert.pem" -outform DER | base64 -w0)" \
        >> "$WORK/home6/.ssh3/known_hosts"

    if HOME="$WORK/home6" timeout 40 "$BUILD/ssh3" -i "$WORK/priv.pem" \
        "client@$V6NAME:$V6PORT/ssh3-term" "printf AF-AAAA-OK" \
        > "$WORK/leg2.out" 2>"$WORK/leg2.err" &&
        grep -q "AF-AAAA-OK" "$WORK/leg2.out"; then
        echo "   PASS: the AAAA name $V6NAME rode the v6 family unforced"
    else
        echo "   FAIL: rc=$?"
        tail -8 "$WORK/leg2.err" | sed 's/^/   /'
        FAILURES=$((FAILURES + 1))
    fi
fi

echo "== leg 3: the -4 pick rides the v4 daemon (AF-V4FORCE-OK)"

if HOME="$WORK/home4" timeout 40 "$BUILD/ssh3" -4 -i "$WORK/priv.pem" \
    "client@127.0.0.1:$V4PORT/ssh3-term" "printf AF-V4FORCE-OK" \
    > "$WORK/leg3.out" 2>"$WORK/leg3.err" &&
    grep -q "AF-V4FORCE-OK" "$WORK/leg3.out"; then
    echo "   PASS: the -4 pick keeps the v4 dial"
else
    echo "   FAIL: rc=$?"
    tail -8 "$WORK/leg3.err" | sed 's/^/   /'
    FAILURES=$((FAILURES + 1))
fi

echo "== leg 4: the -4 pick refuses the v6 literal (AF-V4MISMATCH-REJECT)"

START=$(date +%s)

if HOME="$WORK/home6" timeout 40 "$BUILD/ssh3" -4 -i "$WORK/priv.pem" \
    "client@[::1]:$V6PORT/ssh3-term" "echo no" \
    > /dev/null 2>"$WORK/leg4.err"; then
    echo "   FAIL: the -4 pick passed the v6-only target"
    FAILURES=$((FAILURES + 1))

else
    NOW=$(date +%s)

    if [ $((NOW - START)) -gt 15 ]; then
        echo "   FAIL: the -4 refusal hung past the deadline"
        FAILURES=$((FAILURES + 1))
    else
        echo "   PASS (clean refusal in $((NOW - START))s)"
    fi
fi

if [ "$FAILURES" -eq 0 ]; then
    echo "AF-UNSPEC-E2E OK"
    exit 0
fi

echo "AF-UNSPEC-E2E FAILED: $FAILURES check(s)"
exit 1
