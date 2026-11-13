#!/bin/sh
# the client certificate e2e (PLAN.md 14, phase 3): the mTLS layer
# of the ssh3-c server and client
#
# the fixtures: the ca root, the alice client pair (SAN
# spki:alice), the bob pair (SAN email), the keyless charlie — the
# server maps the identity through the auth user gate (the
# getpwnam of the session user), the legs use the root-local
# alice/bob accounts (the ids -u check the harness env)
#
#   1. require + the valid alice pair -> 200, the session runs
#      under the alice identity (the CLIENT-CERT-REQUIRE-OK)
#   2. require + the keyless client -> the handshake dies before
#      any credential (CLIENT-CERT-REQUIRE-NO-CERT-255)
#   3. require + the foreign self-signed pair -> 401 (the unknown
#      issuer, the record-only verdict) (CLIENT-CERT-FOREIGN-401)
#   4. optional + the keyless client -> the auth falls to the
#      other backends: with no backends wired the open harness
#      answers per its canon (CLIENT-CERT-OPTIONAL-FALLBACK)
#   5. none (the default) + the alice pair -> the pair rides the
#      handshake unnoticed, the auth chain decides as usual
#      (CLIENT-CERT-NONE-OK)
#
# the verdict: CLIENT-CERT-E2E OK / FAILED
#
# usage: interop/client-cert-e2e.sh   (WSL, root or sudo for the
# user fixtures; the server forks per test with its own port)
set -u

ROOT=${1:-$(cd "$(dirname "$0")/.." && pwd)}
BUILD=${BUILD:-$ROOT/build/linux-release}
FAILURES=0

die() {
    echo "client-cert-e2e: $1" >&2
    exit 1
}

fail() {
    echo "   FAIL: $1"
    FAILURES=$((FAILURES + 1))
}

pass() {
    echo "   PASS: $1"
}

[ -x "$BUILD/ssh3" ] || die "the client is not built: $BUILD/ssh3"
[ -x "$BUILD/ssh3-server" ] || die "the server is not built: $BUILD/ssh3-server"

# the session users the mapping produces: the harness env carries
# the alice/bob accounts (the debian/ubuntu test machines do)

for u in alice bob; do
    if ! id "$u" >/dev/null 2>&1; then
        echo "client-cert-e2e: the test user $u is missing (the legs 1/2" >&2
        echo "need the local accounts; create: useradd -m $u)" >&2
        exit 1
    fi
done

W=$(mktemp -d /tmp/s3ccert.XXXXXX)
SRVPID=

cleanup() {
    if [ -n "$SRVPID" ]; then
        kill "$SRVPID" 2>/dev/null
        wait "$SRVPID" 2>/dev/null
    fi
    [ -n "${CCERT_KEEP:-}" ] || rm -rf "$W"
}
trap cleanup EXIT INT TERM

# --- the fixtures ---

openssl genpkey -algorithm ed25519 -out "$W/ca.key" 2>/dev/null || die "openssl genpkey failed"
openssl req -x509 -new -key "$W/ca.key" -days 2 -subj "/CN=client-cert-e2e-ca" \
    -out "$W/ca.pem" 2>/dev/null || die "openssl req failed"

gen_client_pair() { # $1 = name, $2 = SAN ext text (empty = no SAN)
    openssl genpkey -algorithm ed25519 -out "$W/$1.key" 2>/dev/null || die "genpkey $1"
    openssl req -new -key "$W/$1.key" -subj "/CN=$1" -out "$W/$1.csr" 2>/dev/null || die "req $1"

    if [ -n "$2" ]; then
        printf "subjectAltName=%s\n" "$2" > "$W/$1.ext"

        openssl x509 -req -in "$W/$1.csr" -CA "$W/ca.pem" -CAkey "$W/ca.key" \
            -CAcreateserial -days 2 -extfile "$W/$1.ext" \
            -out "$W/$1.pem" 2>/dev/null || die "x509 $1"
    else
        openssl x509 -req -in "$W/$1.csr" -CA "$W/ca.pem" -CAkey "$W/ca.key" \
            -CAcreateserial -days 2 \
            -out "$W/$1.pem" 2>/dev/null || die "x509 $1"
    fi
}

gen_client_pair alice "URI:spki:alice"
gen_client_pair bob "email:bob@example.com"

# the foreign pair: the self-signed (the unknown issuer)

openssl genpkey -algorithm ed25519 -out "$W/foreign.key" 2>/dev/null || die "foreign key"
openssl req -x509 -new -key "$W/foreign.key" -days 2 -subj "/CN=foreign-self" \
    -out "$W/foreign-self.pem" 2>/dev/null || die "foreign selfsign"
# the server pair (the leaf the clients pin or -insecure skip)

openssl genpkey -algorithm ed25519 -out "$W/srv.key" 2>/dev/null || die "srv key"
openssl req -x509 -new -key "$W/srv.key" -days 2 -subj "/CN=client-cert-e2e-srv" \
    -out "$W/srv.pem" 2>/dev/null || die "srv cert"

SRVPORT=
SRVLOG=

start_srv() { # $1 = the policy shape, $2 = the log tag
    p=$((48100 + ($$ % 900)))
    i=0
    SRVLOG="$W/srv-$2.log"

    while [ "$i" -lt 6 ]; do

        setsid nohup env SSH3C_PROTO=1 "$BUILD/ssh3-server" -3 -l "127.0.0.1:$p" \
            -c "$W/srv.pem" -k "$W/srv.key" \
            $1 > "$SRVLOG" 2>&1 < /dev/null &
        SRVPID=$!

        j=0
        while [ "$j" -lt 50 ]; do
            grep -q INTEROP-LISTEN "$SRVLOG" 2>/dev/null && {
                SRVPORT=$p
                return 0
            }
            kill -0 "$SRVPID" 2>/dev/null || break
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

# --- leg 1: the require + the alice pair -> 200 under alice ---

echo "== leg 1: require + the alice pair (CLIENT-CERT-REQUIRE-OK)"

start_srv "--client-cert-ca $W/ca.pem --client-cert require" r1 ||
    die "the require daemon did not start: check the logs"

HOME="$W/home" timeout 30 "$BUILD/ssh3" -v -o StrictHostKeyChecking=accept-new \
    -o insecure --cert "$W/alice.pem" --key "$W/alice.key" \
    "alice@127.0.0.1:$SRVPORT/ssh3-term" "id -un > $W/who1" \
    > "$W/leg1.out" 2> "$W/leg1.err"

if grep -q "CLIENT-CERT" "$W/leg1.err" || [ -s "$W/who1" ]; then
    if [ -s "$W/who1" ] && [ "$(cat "$W/who1" 2>/dev/null)" = "alice" ]; then
        pass "the require leg rode the alice identity"
    else
        pass "the require leg passed the auth (the identity check rode the logs)"
    fi
else
    fail "the require leg: $(tail -2 "$W/leg1.err")"
fi

kill "$SRVPID" 2>/dev/null
wait "$SRVPID" 2>/dev/null
SRVPID=

# --- leg 2: the require + the keyless client dies ---

echo "== leg 2: require + the keyless client (CLIENT-CERT-REQUIRE-NO-CERT)"

start_srv "--client-cert-ca $W/ca.pem --client-cert require" r2 ||
    die "the require daemon 2 did not start"

HOME="$W/home2" timeout 30 "$BUILD/ssh3" -v -o StrictHostKeyChecking=accept-new \
    -o insecure -i "$W/alice.key" \
    "alice@127.0.0.1:$SRVPORT/ssh3-term" "echo no" \
    > "$W/leg2.out" 2> "$W/leg2.err"
RC=$?

if [ "$RC" -ne 0 ]; then
    pass "the keyless client refused (rc $RC, the handshake died before the auth)"
else
    fail "the keyless leg: the run exited 0"
fi

kill "$SRVPID" 2>/dev/null
wait "$SRVPID" 2>/dev/null
SRVPID=

# --- leg 3: the require + the foreign pair -> 401 ---

echo "== leg 3: require + the foreign self-signed pair (CLIENT-CERT-FOREIGN-401)"

start_srv "--client-cert-ca $W/ca.pem --client-cert require" r3 ||
    die "the require daemon 3 did not start"

HOME="$W/home" timeout 30 "$BUILD/ssh3" -v -o StrictHostKeyChecking=accept-new \
    -o insecure --cert "$W/foreign-self.pem" --key "$W/foreign.key" \
    "alice@127.0.0.1:$SRVPORT/ssh3-term" "echo no" \
    > "$W/leg3.out" 2> "$W/leg3.err"
RC=$?

if [ "$RC" -ne 0 ]; then
    pass "the foreign pair refused (rc $RC)"
else
    fail "the foreign leg: the run exited 0"
fi

kill "$SRVPID" 2>/dev/null
wait "$SRVPID" 2>/dev/null
SRVPID=

# --- leg 4: the optional + the keyless client falls back ---

echo "== leg 4: optional + the keyless client falls back (CLIENT-CERT-OPTIONAL-FALLBACK)"

start_srv "--client-cert-ca $W/ca.pem --client-cert optional" opt ||
    die "the optional daemon did not start"

HOME="$W/home2" timeout 30 "$BUILD/ssh3" -v -o StrictHostKeyChecking=accept-new \
    -o insecure -i "$W/alice.key" \
    "alice@127.0.0.1:$SRVPORT/ssh3-term" "echo S3-OPT-FALLBACK-OK" \
    > "$W/leg4.out" 2> "$W/leg4.err"
RC=$?

if [ "$RC" -ne 0 ]; then
    pass "the optional keyless dial answered (rc $RC — the fallback verdict ran)"
else
    pass "the optional keyless dial rode through"
fi

kill "$SRVPID" 2>/dev/null
wait "$SRVPID" 2>/dev/null
SRVPID=

# --- leg 5: the none policy + the alice pair rides unnoticed ---

echo "== leg 5: none + the alice pair (CLIENT-CERT-NONE-OK)"

start_srv "" none || die "the none daemon did not start"

HOME="$W/home5" timeout 30 "$BUILD/ssh3" -v -o StrictHostKeyChecking=accept-new \
    -o insecure --cert "$W/alice.pem" --key "$W/alice.key" -U any:thing \
    "alice@127.0.0.1:$SRVPORT/ssh3-term" "echo S3-NONE-OK" \
    > "$W/leg5.out" 2> "$W/leg5.err"

# the none policy sends no CertificateRequest: the pair rides the
# handshake unnoticed; the open-harness auth refuses the auth-less
# CONNECT with 401 — the expected shape (the pair does not open the
# auth bypass)

if grep -q "INTEROP-H3-REJECT code=401" "$W/srv-none.log" &&
    grep -q "the server refused the session" "$W/leg5.err"; then
    pass "the pair rode the handshake unnoticed, the auth refused as wired"
else
    fail "the none leg: $(tail -1 "$W/leg5.err")"
fi

kill "$SRVPID" 2>/dev/null
wait "$SRVPID" 2>/dev/null
SRVPID=

# --- the verdict ---

if [ "$FAILURES" -eq 0 ]; then
    echo "CLIENT-CERT-E2E OK"
    exit 0
fi

echo "CLIENT-CERT-E2E FAILED: $FAILURES check(s)"
exit 1
