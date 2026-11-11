#!/bin/bash
#
# the AIA chase e2e (PLAN.md 10, T1 + T2, CERT-VERIFICATION-CANON.md 2.6):
# the leaf-only server chain, the caIssuers stub, the cache and the rogue
# shapes of the chase
#
# the daemon rides the product server (the -3 session mode, the pubkey
# auth), the client rides the product build; the certificates generate in
# the work tree: the root rides the client through SSH3_CA_BUNDLE (the T1
# bundle bootstrap), the leaf announces its issuer through the caIssuers
# URI of the loopback stub (the T2 chase), the chain rides leaf-only (the
# server presents no intermediate - the shape the chase exists for)
#
# the legs: the chase success (cold cache + stub), the stale-cache dial
# (no stub, the canon zero-network shape), the rogue answer refuse, the
# poisoned-cache offline refuse, the poisoned-cache network refresh and
# the refresh-offline dial.  Verdict: AIA-CHASE-E2E OK / FAILED

set -u

BUILD=${S3AIA_BUILD:-$HOME/git/ssh3-c/build/linux-release}
BIN=$BUILD/ssh3-server
CLI=$BUILD/ssh3

# the optional pin of the tree (the debug run): S3OPT_WORK + S3OPT_KEEP

if [ -n "${S3OPT_WORK:-}" ]; then
    WORK=$S3OPT_WORK
    rm -rf "$WORK"
    mkdir -p "$WORK"
else
    WORK=$(mktemp -d /tmp/s3aiae2e.XXXXXX)
fi

FAILURES=0

pass() {
    echo "   PASS: $1"
}

fail() {
    echo "   FAIL: $1"
    FAILURES=$((FAILURES + 1))
}

die() {
    echo "aia-chase-e2e: $1" >&2
    exit 1
}

[ -x "$BIN" ] || die "the daemon is not built: $BIN"
[ -x "$CLI" ] || die "the product client is not built: $CLI"

SRVPID=
STUBPID=
SRVPORT=

cleanup() {

    if [ -n "$SRVPID" ]; then
        kill "$SRVPID" 2>/dev/null
        wait "$SRVPID" 2>/dev/null
        SRVPID=
    fi

    if [ -n "$STUBPID" ]; then
        kill "$STUBPID" 2>/dev/null
        wait "$STUBPID" 2>/dev/null
        STUBPID=
    fi

    [ -n "${S3OPT_KEEP:-}" ] || rm -rf "$WORK"
}

trap cleanup EXIT INT TERM

# the identity: the PKCS8 ed25519 of the C client (the cert-verify shape),
# the authorized_keys line built by hand

openssl genpkey -algorithm ed25519 -out "$WORK/priv.pem" 2>/dev/null || die "openssl genpkey failed"

{
    printf '\000\000\000\013ssh-ed25519\000\000\000\040'
    openssl pkey -in "$WORK/priv.pem" -pubout -outform DER 2>/dev/null | tail -c 32
} | base64 | tr -d '\n' > "$WORK/blob.pub"

printf 'ssh-ed25519 %s aia-chase-e2e\n' "$(cat "$WORK/blob.pub")" > "$WORK/authorized_keys"

# the stub port of the caIssuers answers: the AIA of the leaf embeds it,
# so the pick rides before the certificates (a free ephemeral port, the
# bind race is the price of the one-shot stub)

if [ -n "${S3AIA_STUB_PORT:-}" ]; then
    APORT=$S3AIA_STUB_PORT
else
    APORT=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()') ||
        die "the free port pick failed"
fi

AURL="http://127.0.0.1:$APORT/inter.pem"
CACHE_KEY=$(printf '%s' "$AURL" | sha256sum | cut -d' ' -f1)

# the trust: the root (the T1 bundle anchor), the intermediate i1, the
# leaf (AIA -> the stub), the wrong certificate (signed by the root, not
# issuing the leaf - the rogue stub answer)

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$WORK/root.key" 2>/dev/null ||
    die "the root key failed"

openssl req -x509 -key "$WORK/root.key" -out "$WORK/root.pem" -days 2 -subj /CN=aia-e2e-root \
    -addext basicConstraints=critical,CA:TRUE 2>/dev/null || die "the root cert failed"

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$WORK/i1.key" 2>/dev/null ||
    die "the i1 key failed"

openssl req -new -key "$WORK/i1.key" -out "$WORK/i1.csr" -subj /CN=aia-e2e-i1 2>/dev/null ||
    die "the i1 csr failed"

printf 'basicConstraints=critical,CA:TRUE\n' > "$WORK/i1.ext"

openssl x509 -req -in "$WORK/i1.csr" -CA "$WORK/root.pem" -CAkey "$WORK/root.key" \
    -CAcreateserial -out "$WORK/i1.pem" -days 2 -extfile "$WORK/i1.ext" 2>/dev/null ||
    die "the i1 cert failed"

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$WORK/leaf.key" 2>/dev/null ||
    die "the leaf key failed"

openssl req -new -key "$WORK/leaf.key" -out "$WORK/leaf.csr" -subj /CN=aia-e2e-leaf 2>/dev/null ||
    die "the leaf csr failed"

printf 'subjectAltName=IP:127.0.0.1,DNS:localhost\nbasicConstraints=CA:FALSE\nauthorityInfoAccess=caIssuers;URI:%s\n' \
    "$AURL" > "$WORK/leaf.ext"

openssl x509 -req -in "$WORK/leaf.csr" -CA "$WORK/i1.pem" -CAkey "$WORK/i1.key" \
    -CAcreateserial -out "$WORK/leaf.pem" -days 2 -extfile "$WORK/leaf.ext" 2>/dev/null ||
    die "the leaf cert failed"

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$WORK/wrong.key" 2>/dev/null ||
    die "the wrong key failed"

openssl req -new -key "$WORK/wrong.key" -out "$WORK/wrong.csr" -subj /CN=aia-e2e-wrong \
    2>/dev/null || die "the wrong csr failed"

printf 'basicConstraints=critical,CA:TRUE\n' > "$WORK/wrong.ext"

openssl x509 -req -in "$WORK/wrong.csr" -CA "$WORK/root.pem" -CAkey "$WORK/root.key" \
    -CAcreateserial -out "$WORK/wrong.pem" -days 2 -extfile "$WORK/wrong.ext" 2>/dev/null ||
    die "the wrong cert failed"

# the cache file name of the leaf url: the SHA-256 of the string (the
# module cache key)

CACHE_KEY=$(printf '%s' "$AURL" | sha256sum | cut -d' ' -f1)

# the stub of the caIssuers answers (the plain http.server of the work
# tree, the PEM served by path); the body of the leg replaces the file

start_stub() {

    local body=$1
    local leg=$2

    mkdir -p "$WORK/www"

    printf '%s' "$body" > "$WORK/www/inter.pem"

    setsid nohup python3 -m http.server "$APORT" --bind 127.0.0.1 --directory "$WORK/www" \
        > "$WORK/stub-$leg.log" 2>&1 < /dev/null &
    STUBPID=$!

    sleep 0.3

    if kill -0 "$STUBPID" 2>/dev/null && curl -s -o /dev/null "http://127.0.0.1:$APORT/inter.pem"; then
        return 0
    fi

    kill "$STUBPID" 2>/dev/null
    wait "$STUBPID" 2>/dev/null
    STUBPID=

    return 1
}

stop_stub() {

    if [ -n "$STUBPID" ]; then
        kill "$STUBPID" 2>/dev/null
        wait "$STUBPID" 2>/dev/null
        STUBPID=
    fi
}

# the daemon: the leaf-only certificate (the shape the chase exists for)

start_srv() {

    local p=$((47700 + ($$ % 200)))
    local i=0

    while [ "$i" -lt 8 ]; do

        SRVLOG="$WORK/srv-$p.log"

        setsid nohup env SSH3C_PROTO=1 "$BIN" -3 -l "127.0.0.1:$p" -c "$WORK/leaf.pem" \
            -k "$WORK/leaf.key" -K "$WORK/authorized_keys" > "$SRVLOG" 2>&1 < /dev/null &
        SRVPID=$!

        local j=0

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

# the client run: the fresh HOME of the leg, the T1 bundle via the env,
# the accept-new policy (the first contact pins), the term session runs
# the marker printf; -n keeps the console pump off (the /dev/null stdin
# of the harness is not epoll-able everywhere, the e2e runs headless)

run_cli() {

    local home=$1
    local out=$2

    shift 2

    # the fresh home of the leg (the real user's profile always exists,
    # the harness mirrors it); the ticket line drops - the 0-RTT
    # resumption would skip the certificate path the legs test

    mkdir -p "$WORK/$home/.ssh3"
    rm -f "$WORK/$home/.ssh3/tickets"

    env -u SSL_CERT_FILE -u SSL_CERT_DIR HOME="$WORK/$home" SSH3_CA_BUNDLE="$WORK/root.pem" \
        timeout 30 "$CLI" -n \
        -o strict-host-key-checking=accept-new -i "$WORK/priv.pem" \
        "client@127.0.0.1:$SRVPORT/ssh3-term" printf S3-AIA-OK < /dev/null > "$out" 2>&1
}

# the legs run one daemon for the whole ride (the connections differ)

start_srv "$WORK/leaf.pem" || die "the daemon did not start"

echo "== leg 1: the chase success (cold cache, stub good)"

start_stub "$(cat "$WORK/i1.pem")" leg1 || die "the stub did not start"

run_cli home1 "$WORK/leg1.out"

if grep -q S3-AIA-OK "$WORK/leg1.out"; then
    pass "the chase completed the chain, auth rode"
else
    fail "the chase did not complete: $(tail -2 "$WORK/leg1.out" | tr '\n' ' ')"
fi

if [ -f "$WORK/home1/.ssh3/aia-cache/$CACHE_KEY.pem" ]; then
    pass "the caIssuers answer cached under ~/.ssh3/aia-cache"
else
    fail "the cache entry is missing ($CACHE_KEY.pem)"
fi

if grep -q "certificate rotated\|accept-new: pinned" "$WORK/leg1.out" 2>/dev/null ||
    grep -q "127.0.0.1:$SRVPORT" "$WORK/home1/.ssh3/known_hosts" 2>/dev/null; then
    pass "the first contact pinned (accept-new)"
else
    fail "the pin write of the first contact is missing"
fi

echo "== leg 2: the stale cache dial (stub dead, warm cache, zero network)"

stop_stub

run_cli home1 "$WORK/leg2.out"

if grep -q S3-AIA-OK "$WORK/leg2.out"; then
    pass "the warm cache carried the dial off the network"
else
    fail "the stale-cache dial failed: $(tail -2 "$WORK/leg2.out" | tr '\n' ' ')"
fi

echo "== leg 3: the rogue answer refuse (stub serves the wrong cert)"

start_stub "$(cat "$WORK/wrong.pem")" leg3 || die "the stub did not start"

run_cli home3 "$WORK/leg3.out"

if grep -q S3-AIA-OK "$WORK/leg3.out"; then
    fail "the rogue answer rode: the gate did not refuse"
else
    pass "the rogue answer refused (the gate held)"
fi

stop_stub

echo "== leg 4: the poisoned cache offline refuse (no stub)"

mkdir -p "$WORK/home4/.ssh3/aia-cache"
cp "$WORK/wrong.pem" "$WORK/home4/.ssh3/aia-cache/$CACHE_KEY.pem"

run_cli home4 "$WORK/leg4.out"

if grep -q S3-AIA-OK "$WORK/leg4.out"; then
    fail "the poisoned cache rode offline"
else
    pass "the poisoned cache refused offline (not wedging, not trusting)"
fi

echo "== leg 5: the poisoned cache network refresh (stub good)"

start_stub "$(cat "$WORK/i1.pem")" leg5 || die "the stub did not start"

run_cli home4 "$WORK/leg5.out"

if grep -q S3-AIA-OK "$WORK/leg5.out"; then
    pass "the network-forced pass refreshed the poisoned entry"
else
    fail "the poisoned cache did not refresh: $(tail -2 "$WORK/leg5.out" | tr '\n' ' ')"
fi

if openssl x509 -in "$WORK/home4/.ssh3/aia-cache/$CACHE_KEY.pem" -noout -subject 2>/dev/null |
    grep -q "aia-e2e-i1"; then
    pass "the cache rewritten behind the poisoned entry"
else
    fail "the cache entry still rides the poisoned answer"
fi

echo "== leg 6: the refresh-offline dial (stub dead, cache now good)"

stop_stub

run_cli home4 "$WORK/leg6.out"

if grep -q S3-AIA-OK "$WORK/leg6.out"; then
    pass "the refreshed cache carried the offline dial"
else
    fail "the refresh-offline dial failed: $(tail -2 "$WORK/leg6.out" | tr '\n' ' ')"
fi

if [ "$FAILURES" = "0" ]; then
    echo "AIA-CHASE-E2E OK"
else
    echo "AIA-CHASE-E2E FAILED: $FAILURES leg(s)"
    exit 1
fi
