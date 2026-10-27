#!/bin/bash
# the OIDC e2e of the P6.5 auth wave: the mock issuer (stdlib +
# openssl), the C server (--oidc-issuer, the Bearer id_token verdict
# with the conversation nonce) and the C client (S3_OIDC_NO_BROWSER):
#
#   1. the happy flow: the client browser-less PKCE loop, the token
#      exchange, the CONNECT accepted, the exec session runs
#   2. the tampered token (the client --oidc-token bypass): rejected,
#      the server names the signature
#   3. the expired token: rejected on the exp gate
#   4. the wrong nonce: rejected on the conversation binding
#
# everything rides the loopback; BUILD overrides the build dir

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD=${BUILD:-$ROOT/build/linux-release}
# the server binary override (P6.5 wave 2): the ssh3-server daemon
# replaces the harness server; the daemon speaks the runner markers
# only under SSH3C_PROTO=1, the harness server ignores the variable
SERVER=${SSH3C_SERVER_BIN:-$BUILD/s3interop_server}
SRV_ENV=""
if [ "${SSH3C_SERVER_BIN:-}" != "" ]; then
    SRV_ENV="SSH3C_PROTO=1"
fi
SRV_PATT="${SERVER##*/}.*--oidc-issuer"
CLIENT=$BUILD/s3interop_client
MOCK=$ROOT/scripts/mock-oidc-issuer.py

FAILURES=0

if [ ! -x "$CLIENT" ] || [ ! -x "$SERVER" ]; then
    echo "oidc-e2e: no binaries under $BUILD (cmake --preset linux-release first)"
    exit 1
fi

WORK=$(mktemp -d /tmp/s3oidc-XXXXXX)
CERT=$BUILD/interop/cert.pem
KEY=$BUILD/interop/key.pem

if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
    mkdir -p "$BUILD/interop"
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$KEY" -out "$CERT" -days 30 \
        -subj "/CN=s3interop" 2>/dev/null || { echo "oidc-e2e: openssl req failed"; exit 1; }
fi

cleanup() {
    pkill -f "$SRV_PATT" 2>/dev/null
    pkill -f "mock-oidc-issuer.py serv[e]" 2>/dev/null
}
trap cleanup EXIT

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
    # -a: a log may carry the sparse holes of a predecessor still
    # draining, grep would call the file binary and lose the port
    grep -a -oE 'port=[0-9]+' "$1" | cut -d= -f2
}

# wait_oidc_url LOG TIMEOUT_S: prints the authorize url once the
# client printed it (the flow waits on its loopback listener)
wait_oidc_url() {
    i=0
    while [ "$i" -lt $(( $2 * 10 )) ]; do
        if grep -q "OIDC-AUTHORIZE-URL:" "$1" 2>/dev/null; then
            grep -m1 "OIDC-AUTHORIZE-URL:" "$1" | sed 's/^OIDC-AUTHORIZE-URL: //'
            return 0
        fi
        sleep 0.1
        i=$((i + 1))
    done
    return 1
}

# wait_marker LOG MARKER TIMEOUT_S: polls the log for the marker
wait_marker() {
    i=0
    while [ "$i" -lt $(( $3 * 10 )) ]; do
        if grep -q "$2" "$1" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
        i=$((i + 1))
    done
    return 1
}

# the redirect driver: the e2e plays the browser, urllib follows the
# 302 into the client loopback listener which answers 200
drive_redirect() {
    python3 - "$1" <<'PYEOF'
import sys
import urllib.request

url = sys.argv[1]
with urllib.request.urlopen(url, timeout=15) as resp:
    body = resp.read().decode()
    sys.exit(0 if "close this tab" in body else 1)
PYEOF
}

echo "== oidc 1: the browser-less PKCE flow -> C server (--oidc-issuer), exec session"

setsid nohup python3 "$MOCK" serve --port 0 --keys "$WORK/keys" \
    > "$WORK/mock.log" 2>&1 < /dev/null &

i=0
while [ "$i" -lt 50 ]; do
    grep -q MOCK-OIDC-ISSUER "$WORK/mock.log" 2>/dev/null && break
    sleep 0.1
    i=$((i + 1))
done

if ! grep -q MOCK-OIDC-ISSUER "$WORK/mock.log"; then
    echo "   FAIL: the mock issuer did not start"
    tail -5 "$WORK/mock.log" | sed 's/^/   /'
    exit 1
fi

ISSUER=$(grep -m1 "MOCK-OIDC-ISSUER" "$WORK/mock.log" | cut -d' ' -f2)

setsid nohup env $SRV_ENV "$SERVER" -3 --oidc-issuer "$ISSUER" --oidc-audience ssh3-c-cli \
    -l 127.0.0.1:0 -c "$CERT" -k "$KEY" \
    > "$WORK/oidc-srv.log" 2>&1 < /dev/null &

if ! wait_listen "$WORK/oidc-srv.log"; then
    echo "   FAIL: the C server did not start"
    tail -5 "$WORK/oidc-srv.log" | sed 's/^/   /'
    exit 1
fi

PORT=$(port_of "$WORK/oidc-srv.log")

S3_OIDC_NO_BROWSER=1 setsid nohup "$CLIENT" -3 -C -S exec \
    --oidc-issuer "$ISSUER" --oidc-audience ssh3-c-cli \
    -a "127.0.0.1:$PORT" -t 20000 \
    > "$WORK/oidc-cli.log" 2>&1 < /dev/null &

URL=$(wait_oidc_url "$WORK/oidc-cli.log" 15)

if [ -z "$URL" ]; then
    echo "   FAIL: the client never printed the authorize url"
    tail -5 "$WORK/oidc-cli.log" | sed 's/^/   /'
    FAILURES=$((FAILURES + 1))
else
    if ! drive_redirect "$URL"; then
        echo "   FAIL: the redirect drive failed"
        tail -5 "$WORK/oidc-cli.log" | sed 's/^/   /'
        FAILURES=$((FAILURES + 1))
    fi

    if wait_marker "$WORK/oidc-cli.log" "INTEROP-EXEC-OK" 30 \
        && grep -q "INTEROP-EXEC-OK exit=0" "$WORK/oidc-cli.log" \
        && grep -q "INTEROP-AUTH-OK user=oidc" "$WORK/oidc-srv.log"; then
        echo "   PASS (the OIDC flow accepted, exec session ran)"
    else
        echo "   FAIL"
        tail -5 "$WORK/oidc-cli.log" | sed 's/^/   /'
        tail -5 "$WORK/oidc-srv.log" | sed 's/^/   /'
        FAILURES=$((FAILURES + 1))
    fi
fi

pkill -f "$SRV_PATT" 2>/dev/null
sleep 0.3

# the negatives: the raw-token bypass carries the minted token, the
# server must reject with the named gate

neg_case() {
    local name=$1 expect=$2 tok
    tok=$(python3 "$MOCK" mint --keys "$WORK/keys" --issuer "$ISSUER" \
        --audience ssh3-c-cli --nonce "$3" --ttl "$4")

    if [ "$name" = tampered ]; then

        # the signature flip on the first char of the segment: the
        # first decoded byte always changes, the claims stay valid

        tok=$(python3 - "$tok" <<'PYEOF'
import sys

t = sys.argv[1]
head, sep, rest = t.rpartition(".")
c = rest[0]
print(head + sep + ("B" if c != "B" else "C") + rest[1:])
PYEOF
)
    fi

    # the per-case logs: a predecessor still draining writes its tail
    # at its own offset, a shared name would grow the sparse holes
    # into the fresh log (grep turns binary, the port gets lost)

    SRV_LOG=$WORK/neg-srv-$name.log
    CLI_LOG=$WORK/neg-cli-$name.log

    setsid nohup env $SRV_ENV "$SERVER" -3 --oidc-issuer "$ISSUER" --oidc-audience ssh3-c-cli \
        -l 127.0.0.1:0 -c "$CERT" -k "$KEY" \
        > "$SRV_LOG" 2>&1 < /dev/null &

    if ! wait_listen "$SRV_LOG"; then
        echo "   FAIL ($name): the C server did not start"
        FAILURES=$((FAILURES + 1))
        return
    fi

    PORT=$(port_of "$SRV_LOG")

    timeout 30 "$CLIENT" -3 -C -S exec --oidc-token "$tok" \
        -a "127.0.0.1:$PORT" -t 20000 \
        > "$CLI_LOG" 2>&1

    if grep -qa "INTEROP-AUTH-OK" "$SRV_LOG"; then
        echo "   FAIL ($name): the server accepted the bad token"
        FAILURES=$((FAILURES + 1))

    elif ! grep -qa "INTEROP-H3-REJECT code=401" "$SRV_LOG"; then
        echo "   FAIL ($name): the expected 401 is missing"
        tail -5 "$SRV_LOG" | sed 's/^/   /'
        FAILURES=$((FAILURES + 1))

    elif ! grep -qa "rejected:$expect" "$SRV_LOG"; then
        echo "   FAIL ($name): the reject reason is not$expect"
        tail -5 "$SRV_LOG" | sed 's/^/   /'
        FAILURES=$((FAILURES + 1))

    elif grep -qa "INTEROP-EXEC-OK exit=0" "$CLI_LOG"; then
        echo "   FAIL ($name): the client ran the session over the rejection"
        FAILURES=$((FAILURES + 1))

    else
        echo "   PASS ($name: rejected:$expect, 401)"
    fi

    pkill -f "$SRV_PATT" 2>/dev/null
    sleep 0.3
}

echo "== oidc 2: the tampered token -> expect the hard reject"
#
# the claims gates run before the signature (the go-oidc order the
# port mirrors), the offline-minted nonce never matches the live
# conversation, so the case asserts the rejection itself; the
# signature gate rides the unit vectors (RS256/ES256 tamper)
neg_case tampered "" somenonce 600

echo "== oidc 3: the expired token -> expect the expiry reject"
neg_case expired " expiry" somenonce -120

echo "== oidc 4: the wrong nonce -> expect the nonce reject"
neg_case nonce " nonce" the-wrong-nonce 600

# the prod client (ssh3) legs: the full flow and the raw-token
# negative against the real daemon (the runner markers ride the
# daemon natively); the known_hosts pins the TOFU line the
# non-interactive run demands

echo "== oidc 5: the prod client full flow -> the daemon, exec session"

PROD=$BUILD/ssh3
PROD_HOME=$WORK/prod-home
mkdir -p "$PROD_HOME/.ssh3"

setsid nohup "$BUILD/ssh3-server" -3 --oidc-issuer "$ISSUER" --oidc-audience ssh3-c-cli \
    -l 127.0.0.1:0 -c "$CERT" -k "$KEY" \
    > "$WORK/prod-srv.log" 2>&1 < /dev/null &

if ! wait_listen "$WORK/prod-srv.log"; then
    echo "   FAIL: the daemon did not start"
    tail -5 "$WORK/prod-srv.log" | sed 's/^/   /'
    FAILURES=$((FAILURES + 1))
fi

PORT=$(port_of "$WORK/prod-srv.log")
printf '127.0.0.1:%s/ssh3-term x509-certificate %s\n' "$PORT" \
    "$(openssl x509 -in "$CERT" -outform DER | base64 -w0)" \
    >> "$PROD_HOME/.ssh3/known_hosts"

S3_OIDC_NO_BROWSER=1 HOME="$PROD_HOME" setsid nohup "$PROD" -n --oidc-issuer "$ISSUER" --oidc-audience ssh3-c-cli \
    -T "client@127.0.0.1:$PORT/ssh3-term" "echo oidc-prod-ok" \
    > "$WORK/prod-cli.out" 2> "$WORK/prod-cli.log" &

URL=$(wait_oidc_url "$WORK/prod-cli.log" 15)

if [ -z "$URL" ]; then
    echo "   FAIL: the prod client never printed the authorize url"
    tail -5 "$WORK/prod-cli.log" | sed 's/^/   /'
    FAILURES=$((FAILURES + 1))
else
    if ! drive_redirect "$URL"; then
        echo "   FAIL: the redirect drive failed"
        FAILURES=$((FAILURES + 1))
    fi

    if wait_marker "$WORK/prod-cli.out" "oidc-prod-ok" 30 \
        && grep -qa "INTEROP-AUTH-OK user=oidc" "$WORK/prod-srv.log"; then
        echo "   PASS (the prod flow accepted, the exec ran)"
    else
        echo "   FAIL"
        tail -5 "$WORK/prod-cli.log" | sed 's/^/   /'
        tail -5 "$WORK/prod-srv.log" | sed 's/^/   /'
        FAILURES=$((FAILURES + 1))
    fi
fi

pkill -f "ssh3-server.*--oidc-issuer" 2>/dev/null
sleep 0.3

echo "== oidc 6: the prod client raw token -> expect the 401 reject"

tok=$(python3 "$MOCK" mint --keys "$WORK/keys" --issuer "$ISSUER" \
    --audience ssh3-c-cli --nonce offline-nonce --ttl 600)

setsid nohup "$BUILD/ssh3-server" -3 --oidc-issuer "$ISSUER" --oidc-audience ssh3-c-cli \
    -l 127.0.0.1:0 -c "$CERT" -k "$KEY" \
    > "$WORK/prod2-srv.log" 2>&1 < /dev/null &

if wait_listen "$WORK/prod2-srv.log"; then
    PORT=$(port_of "$WORK/prod2-srv.log")
    printf '127.0.0.1:%s/ssh3-term x509-certificate %s\n' "$PORT" \
        "$(openssl x509 -in "$CERT" -outform DER | base64 -w0)" \
        >> "$PROD_HOME/.ssh3/known_hosts"

    HOME="$PROD_HOME" timeout 30 "$PROD" --oidc-token "$tok" \
        -T "client@127.0.0.1:$PORT/ssh3-term" "echo no" \
        > "$WORK/prod2-cli.out" 2> "$WORK/prod2-cli.log"

    if grep -qa "INTEROP-AUTH-OK" "$WORK/prod2-srv.log"; then
        echo "   FAIL: the daemon accepted the raw token"
        FAILURES=$((FAILURES + 1))
    elif ! grep -qa "rejected:" "$WORK/prod2-srv.log"; then
        echo "   FAIL: the reject reason is missing"
        tail -5 "$WORK/prod2-srv.log" | sed 's/^/   /'
        FAILURES=$((FAILURES + 1))
    elif grep -qa "oidc-prod-ok" "$WORK/prod2-cli.out"; then
        echo "   FAIL: the session ran over the rejection"
        FAILURES=$((FAILURES + 1))
    else
        echo "   PASS (the raw token rejected, 401)"
    fi
else
    echo "   FAIL: the daemon did not start"
    FAILURES=$((FAILURES + 1))
fi

pkill -f "ssh3-server.*--oidc-issuer" 2>/dev/null

if [ "$FAILURES" -eq 0 ]; then
    echo "OIDC-E2E PASS"
    rm -rf "$WORK"
    exit 0
fi

echo "OIDC-E2E FAILED: $FAILURES case(s), logs kept: $WORK"
exit 1
