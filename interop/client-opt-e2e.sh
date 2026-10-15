#!/bin/sh
# the client options e2e (backlog 7, the -o Key=Value surface of the
# product client):
#
#   1. the unknown key refuses with the supported list (exit 255,
#      the OPT-REJECT-255 marker)
#   2. the strict-host-key-checking=yes against an unpinned host
#      refuses before any session (the STRICT-REJECT marker), no pin
#      rides the store
#   3. the accept-new (the default) runs the TOFU question on the
#      pty and records the pin (the ACCEPT-NEW-PINNED marker)
#   4. the pinned host passes strict=yes (the STRICT-PINNED-OK
#      marker), the case-insensitive spelling rides too
#   5. the daemon certificate rotates: the pinned host refuses on
#      the mismatch (the PIN-MISMATCH-REJECT marker, the MITM shape)
#   6. the -o insecure accepts the rotated certificate (the
#      INSECURE-OK marker), the pin store stays untouched
#
# the verdicts: CLIENT-OPT-E2E OK / FAILED, the leg markers on the
# way
#
# usage: interop/client-opt-e2e.sh   (WSL)
# requires: the C runners (cmake --build build/linux-release), the
# pty runner (script)
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD=${BUILD:-$ROOT/build/linux-release}
BIN=${SSH3C_SERVER_BIN:-$BUILD/ssh3-server}

die() {
    echo "client-opt-e2e: $1" >&2
    exit 1
}

[ -x "$BIN" ] || die "the daemon is not built: $BIN"
[ -x "$BUILD/ssh3" ] || die "the product client is not built: $BUILD/ssh3"

FAILURES=0

pass() {
    echo "   PASS: $1"
}

fail() {
    echo "   FAIL: $1"
    FAILURES=$((FAILURES + 1))
}

SRVPID=
SRVLOG=

cleanup() {

    if [ -n "$SRVPID" ]; then
        kill "$SRVPID" 2>/dev/null
        wait "$SRVPID" 2>/dev/null
        SRVPID=
    fi

    rm -rf "$WORK"
}

trap cleanup EXIT INT TERM

WORK=$(mktemp -d /tmp/s3opte2e.XXXXXX)

# the identity: the PKCS8 ed25519 of the C client, the authorized
# keys line built by hand (ssh-keygen reads no PKCS8 ed25519)

openssl genpkey -algorithm ed25519 -out "$WORK/priv.pem" 2>/dev/null || die "openssl genpkey failed"

{
    printf '\000\000\000\013ssh-ed25519\000\000\000\040'
    openssl pkey -in "$WORK/priv.pem" -pubout -outform DER 2>/dev/null | tail -c 32
} | base64 | tr -d '\n' > "$WORK/blob.pub"

printf 'ssh-ed25519 %s client-opt-e2e\n' "$(cat "$WORK/blob.pub")" > "$WORK/authorized_keys"

mkcert() {
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/key-$1.pem" \
        -out "$WORK/cert-$1.pem" -days 2 -subj /CN=client-opt-e2e-$1 2>/dev/null \
        || die "openssl req failed for $1"
}

mkcert a
mkcert b

# the daemon leg: the port stays fixed across the two runs (the
# known_hosts key carries host:port, the mismatch leg needs the same
# one), the candidates scan up on a busy port; the listen port polls
# out of the INTEROP-LISTEN marker

SRVPORT=

start_srv() {
    SRVLOG="$WORK/srv-$1.log"

    p=$((47000 + ($$ % 2000)))

    i=0

    while [ "$i" -lt 8 ]; do

        setsid nohup env SSH3C_PROTO=1 "$BIN" -3 -l "127.0.0.1:$p" -c "$WORK/cert-$1.pem" \
            -k "$WORK/key-$1.pem" -K "$WORK/authorized_keys" > "$SRVLOG" 2>&1 < /dev/null &
        SRVPID=$!

        j=0

        while [ "$j" -lt 50 ]; do

            if grep -q INTEROP-LISTEN "$SRVLOG" 2>/dev/null; then
                SRVPORT=$p
                return 0
            fi

            if ! kill -0 "$SRVPID" 2>/dev/null; then
                break # the bind refused, the next port scans
            fi

            sleep 0.1
            j=$((j + 1))
        done

        kill "$SRVPID" 2>/dev/null
        wait "$SRVPID" 2>/dev/null
        SRVPID=

        p=$((p + 1))
        i=$((i + 1))
    done

    return 1
}

stop_srv() {

    if [ -n "$SRVPID" ]; then
        kill "$SRVPID" 2>/dev/null
        wait "$SRVPID" 2>/dev/null
        SRVPID=
    fi
}

srv_port() {
    echo "$SRVPORT"
}

# one client run: the fresh home, the -o value rides the real argv
# (the empty value skips the option), the exec command rides last

run_cli() {
    HOME="$WORK/$1" timeout 30 "$BUILD/ssh3" \
        ${2:+-o "$2"} -i "$WORK/priv.pem" \
        "client@127.0.0.1:$(srv_port)/ssh3-term" "$3" \
        > "$WORK/$1.out" 2> "$WORK/$1.err"
}

# the pty run of the TOFU question: the answer feeds the pin store,
# the exec rides after it (the console shape of the reference)

run_cli_pty() {
    printf 'yes\n' | timeout 30 script -qec \
        "env HOME=$WORK/$1 $BUILD/ssh3 -o strict-host-key-checking=accept-new -i $WORK/priv.pem client@127.0.0.1:$(srv_port)/ssh3-term $2" \
        /dev/null > "$WORK/$1.out" 2>&1
}

echo "== leg 1: the unknown -o key refuses with the supported list"

# the parse exit rides before any connection: no server needed

if timeout 10 "$BUILD/ssh3" -o unknown-key=yes bob@127.0.0.1:1/ssh3-term \
    > "$WORK/leg1.out" 2> "$WORK/leg1.err"; then
    fail "the unknown key leg: the run exited 0"
else
    RC=$?

    if [ "$RC" -eq 255 ] && grep -q "insecure, strict-host-key-checking" "$WORK/leg1.err"; then
        pass "the unknown key refused 255 with the supported list (OPT-REJECT-255)"
    else
        fail "the unknown key leg: rc=$RC $(tail -1 "$WORK/leg1.err")"
    fi
fi

echo "== run 1: the daemon of the certificate a"

start_srv a || die "the daemon did not start: $(tail -3 "$SRVLOG")"

PORT=$(srv_port)

[ -n "$PORT" ] || die "no listen port"

echo "== leg 2: strict=yes refuses the unpinned host (STRICT-REJECT)"

if run_cli home-strict "strict-host-key-checking=yes" "printf no"; then
    fail "the strict leg: the run exited 0"
else
    RC=$?

    if [ "$RC" -eq 255 ] &&
        grep -q "strict-host-key-checking=yes refuses an unpinned host" "$WORK/home-strict.err"; then
        pass "the unpinned host refused before any session (rc $RC)"

        if grep -q x509-certificate "$WORK/home-strict/.ssh3/known_hosts" 2>/dev/null; then
            fail "the strict leg: the pin store gained a line"
        else
            pass "the pin store stayed empty"
        fi
    else
        fail "the strict leg: rc=$RC $(tail -1 "$WORK/home-strict.err")"
    fi
fi

echo "== leg 3: accept-new pins on the pty question (ACCEPT-NEW-PINNED)"

mkdir -p "$WORK/home-tofu"

run_cli_pty home-tofu "printf S3-ACCEPT-NEW-OK"

if grep -q "Pinned 127.0.0.1:$PORT/ssh3-term" "$WORK/home-tofu.out" &&
    grep -q "S3-ACCEPT-NEW-OK" "$WORK/home-tofu.out"; then
    pass "the TOFU question pinned and the exec rode through"

    if [ "$(grep -c x509-certificate "$WORK/home-tofu/.ssh3/known_hosts" 2>/dev/null)" -eq 1 ]; then
        pass "the pin store holds the one recorded line"
    else
        fail "the pin store leg: $(head -1 "$WORK/home-tofu/.ssh3/known_hosts" 2>/dev/null)"
    fi

else
    fail "the accept-new leg: $(tail -2 "$WORK/home-tofu.out")"
fi

echo "== leg 4: the pinned host passes strict=yes (STRICT-PINNED-OK)"

if run_cli home-tofu "strict-host-key-checking=yes" "printf S3-STRICT-PINNED-OK" &&
    grep -q "S3-STRICT-PINNED-OK" "$WORK/home-tofu.out"; then

    # the case-insensitive spelling rides the same store

    if run_cli home-tofu "STRICT-HOST-KEY-CHECKING=YES" "printf S3-STRICT-UPPER-OK" &&
        grep -q "S3-STRICT-UPPER-OK" "$WORK/home-tofu.out"; then
        pass "the pinned host passed strict=yes, the upper spelling too"
    else
        fail "the upper spelling leg: $(tail -1 "$WORK/home-tofu.err")"
    fi

else
    fail "the strict pinned leg: rc=$? $(tail -1 "$WORK/home-tofu.err")"
fi

stop_srv

echo "== run 2: the daemon of the rotated certificate b"

start_srv b || die "the daemon did not start: $(tail -3 "$SRVLOG")"

PORT=$(srv_port)

echo "== leg 5: the pin mismatch refuses (PIN-MISMATCH-REJECT)"

if run_cli home-tofu "" "printf no"; then
    fail "the mismatch leg: the run exited 0"
else
    RC=$?

    if [ "$RC" -eq 255 ] &&
        grep -q "does not match the pin in known_hosts" "$WORK/home-tofu.err"; then
        pass "the rotated certificate refused on the pin mismatch (rc $RC)"
    else
        fail "the mismatch leg: rc=$RC $(tail -1 "$WORK/home-tofu.err")"
    fi
fi

echo "== leg 6: -o insecure accepts the rotated certificate (INSECURE-OK)"

if run_cli home-tofu "insecure" "printf S3-INSECURE-ROTATED-OK" &&
    grep -q "S3-INSECURE-ROTATED-OK" "$WORK/home-tofu.out"; then
    pass "the insecure run crossed the pin mismatch"
else
    fail "the insecure pinned leg: rc=$? $(tail -1 "$WORK/home-tofu.err")"
fi

echo "== leg 7: -o insecure on the fresh home stays store-free"

if run_cli home-insec "insecure" "printf S3-INSECURE-FRESH-OK" &&
    grep -q "S3-INSECURE-FRESH-OK" "$WORK/home-insec.out"; then

    if [ -e "$WORK/home-insec/.ssh3/known_hosts" ]; then
        fail "the fresh insecure leg: the pin store appeared"
    else
        pass "the fresh home passed with no pin written"
    fi

else
    fail "the fresh insecure leg: rc=$? $(tail -1 "$WORK/home-insec.err")"
fi

stop_srv

if [ "$FAILURES" -eq 0 ]; then
    echo "CLIENT-OPT-E2E OK"
    exit 0
fi

echo "CLIENT-OPT-E2E FAILED: $FAILURES check(s)"
exit 1
