#!/bin/sh
# the jump chain smoke (the multi-hop wave): two jump daemons and the
# inner one; the prod client rides the comma chain -J h1,h2 toward
# the inner server and runs the exec scenario.  The negative leg
# points the first hop at a dead port and must refuse cleanly inside
# the deadline
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD=${BUILD:-$ROOT/build/linux-release}
WORK=$(mktemp -d /tmp/s3jc.XXXXXX)
FAILURES=0

die() {
    echo "jump-chain-smoke: $1" >&2
    exit 1
}

[ -x "$BUILD/ssh3" ] || die "the product client is not built: $BUILD/ssh3"
[ -x "$BUILD/ssh3-server" ] || die "the daemon is not built: $BUILD/ssh3-server"

# a hard-killed previous run leaves its setsid servers behind; sweep
# them by the tmp marker in their cmdline

pkill -f 's3jc\.' 2>/dev/null

cleanup() {
    pkill -f 's3jc\.' 2>/dev/null
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

printf 'ssh-ed25519 %s jump-chain-smoke\n' "$(cat "$WORK/blob.pub")" > "$WORK/authorized_keys"

mkcert() {
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/key-$1.pem" \
        -out "$WORK/cert-$1.pem" -days 2 -subj /CN=jump-chain-smoke-$1 2>/dev/null \
        || die "openssl req failed for $1"
}

mkcert 1
mkcert 2
mkcert 3

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

# the stand: the two jump daemons ride the -d 1352 tunnel-size
# datagram acceptance, the inner one runs the stock conf

start_srv() {
    TAG=$1
    shift

    setsid nohup env SSH3C_PROTO=1 "$BUILD/ssh3-server" -3 "$@" \
        -l 127.0.0.1:0 -c "$WORK/cert-$TAG.pem" -k "$WORK/key-$TAG.pem" \
        -K "$WORK/authorized_keys" > "$WORK/srv-$TAG.log" 2>&1 < /dev/null &

    if ! wait_listen "$WORK/srv-$TAG.log"; then
        die "the server $TAG did not start"
    fi
}

# the v6 form of the same stand: the bracketed listen of the daemon

start_srv6() {
    TAG=$1
    shift

    setsid nohup env SSH3C_PROTO=1 "$BUILD/ssh3-server" -3 "$@" \
        -l "[::1]:0" -c "$WORK/cert-$TAG.pem" -k "$WORK/key-$TAG.pem" \
        -K "$WORK/authorized_keys" > "$WORK/srv-$TAG.log" 2>&1 < /dev/null &

    if ! wait_listen "$WORK/srv-$TAG.log"; then
        die "the server $TAG did not start"
    fi
}

mkcert 4
mkcert 5

start_srv 1 -d 1352
start_srv 2 -d 1352
start_srv 3
start_srv6 4 -d 1352
start_srv6 5

J1PORT=$(port_of "$WORK/srv-1.log")
J2PORT=$(port_of "$WORK/srv-2.log")
IPORT=$(port_of "$WORK/srv-3.log")
J6PORT=$(port_of "$WORK/srv-4.log")
I6PORT=$(port_of "$WORK/srv-5.log")

# the pin store: both hops and the destination pin before the run

mkdir -p "$WORK/home/.ssh3"
mkdir -p "$WORK/home6/.ssh3"

for spec in "1 $J1PORT" "2 $J2PORT" "3 $IPORT"; do

    set -- $spec

    printf '%s x509-certificate %s\n' "127.0.0.1:$2/ssh3-term" \
        "$(openssl x509 -in "$WORK/cert-$1.pem" -outform DER | base64 -w0)" \
        >> "$WORK/home/.ssh3/known_hosts"
done

# the v6 pins ride the bracket form (the ssh2 canon of the key
# text): the -6 leg runs WITHOUT -insecure, the pins must match

for spec in "4 $J6PORT" "5 $I6PORT"; do

    set -- $spec

    printf '[::1]:%s/ssh3-term x509-certificate %s\n' "$2" \
        "$(openssl x509 -in "$WORK/cert-$1.pem" -outform DER | base64 -w0)" \
        >> "$WORK/home6/.ssh3/known_hosts"
done

echo "== positive: the exec through the two-hop chain"

if HOME="$WORK/home" timeout 40 "$BUILD/ssh3" -i "$WORK/priv.pem" \
    -J "127.0.0.1:$J1PORT,127.0.0.1:$J2PORT" \
    "client@127.0.0.1:$IPORT/ssh3-term" "printf S3-JUMP2-OK" \
    > "$WORK/chain.out" 2>"$WORK/chain.err" &&
    grep -q "S3-JUMP2-OK" "$WORK/chain.out"; then
    echo "   PASS: the exec rode the two-hop chain"
else
    echo "   FAIL: rc=$?"
    tail -8 "$WORK/chain.err" | sed 's/^/   /'
    FAILURES=$((FAILURES + 1))
fi

echo "== negative: the dead first hop refuses inside the deadline"

START=$(date +%s)

if HOME="$WORK/home" timeout 30 "$BUILD/ssh3" -i "$WORK/priv.pem" \
    -J "127.0.0.1:1,127.0.0.1:$J2PORT" \
    "client@127.0.0.1:$IPORT/ssh3-term" "echo no" \
    > /dev/null 2>"$WORK/bad.err"; then
    echo "   FAIL: the dead first hop passed"
    FAILURES=$((FAILURES + 1))

else
    NOW=$(date +%s)

    if [ $((NOW - START)) -gt 15 ]; then
        echo "   FAIL: the dead first hop hung past the deadline"
        FAILURES=$((FAILURES + 1))
    else
        echo "   PASS (clean refusal in $((NOW - START))s)"
    fi
fi

echo "== v6: the -6 chain rides the bracketed hop and destination (JUMP-V6-OK)"

if HOME="$WORK/home6" timeout 40 "$BUILD/ssh3" -6 -i "$WORK/priv.pem" \
    -J "[::1]:$J6PORT" \
    "client@[::1]:$I6PORT/ssh3-term" "printf S3-JUMP-V6-OK" \
    > "$WORK/v6.out" 2>"$WORK/v6.err" &&
    grep -q "S3-JUMP-V6-OK" "$WORK/v6.out"; then
    echo "   PASS: the -6 chain rode the v6 hop and destination"
else
    echo "   FAIL: rc=$?"
    tail -8 "$WORK/v6.err" | sed 's/^/   /'
    FAILURES=$((FAILURES + 1))
fi

if [ "$FAILURES" -eq 0 ]; then
    echo "JUMP-CHAIN-SMOKE OK"
    exit 0
fi

echo "JUMP-CHAIN-SMOKE FAILED: $FAILURES check(s)"
exit 1
