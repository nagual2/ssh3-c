#!/bin/bash
# the cross-server oidc e2e (ROADMAP.local.md R10 p.2-3): the C client
# rides the go fork server (project/ssh3) on the oidc credential, the
# identity lives in the temp user's authorized_identities as the fork
# shape `oidc <clientID> <issuerURL> <email>`:
#
#   1. the happy flow: the browser-less PKCE loop against the mock
#      issuer, the fork verifies the bearer (signature, audience,
#      conversation nonce, email) and the exec session runs under the
#      temp user (the fork setuids into it); the exit status rides too
#   2. the tampered token (the client --oidc-token bypass): the
#      signature gate refuses, the verdict lands as a clean 401 before
#      any channel opens (the B11-3/B13 shape)
#   3. the token of the other session: the nonce of the leg-1
#      conversation replayed into a fresh conversation - the fork
#      names the nonce gate (`OIDC nonce mismatch`)
#   4. the email gate: the flow reruns with the same issuer/port/key
#      but a rival email - the authorized_identities email field is
#      enforced (`email should be` in the fork log)
#
# the email claims ride a runner over the base mock issuer (the go
# fork demands `email_verified` + the email match, the base mock mints
# without them); everything rides the loopback
#
# usage: bash interop/go-server-oidc-e2e.sh   (WSL, as root: the stand
# needs useradd and the fork's per-user setuid exec; `wsl -u root
# bash -lc 'bash interop/go-server-oidc-e2e.sh'` from windows)
# requires: the C client (build/linux-release/ssh3), the go fork
# sources (GOSSHSRC, default the sibling clone ../ssh3, else
# $HOME/git/ssh3) - the fork server builds on the fly when absent
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
CCLI=${SSH3C_CLIENT_BIN:-$ROOT/build/linux-release/ssh3}
MOCKBASE=$ROOT/scripts/mock-oidc-issuer.py
GOSSHSRC=${GOSSHSRC:-}
if [ -z "$GOSSHSRC" ]; then
    if [ -d "$ROOT/../ssh3" ]; then
        GOSSHSRC=$(cd "$ROOT/../ssh3" && pwd)
    else
        GOSSHSRC=$HOME/git/ssh3
    fi
fi
GOBIN=${GOSSHBIN:-/tmp/go-ssh3-r10}
E2E_USER=${GO_SERVER_OIDC_E2E_USER:-s3oidc-e2e}
E2E_AUD=${GO_SERVER_OIDC_E2E_AUDIENCE:-ssh3-c-cli}
E2E_EMAIL=${GO_SERVER_OIDC_E2E_EMAIL:-pilot@ssh3-e2e.local}
E2E_EMAIL_RIVAL=${GO_SERVER_OIDC_E2E_EMAIL_RIVAL:-rival@ssh3-e2e.local}
MOCK_PATT="go-server-oidc-e2e-mock.p[y]"

die() {
    echo "go-server-oidc-e2e: $1" >&2
    exit 1
}

FAILURES=0

pass() {
    echo "   PASS: $1"
}

fail() {
    echo "   FAIL: $1"
    FAILURES=$((FAILURES + 1))
}

[ "$(id -u)" -eq 0 ] || die "run as root: the stand needs useradd and the fork's per-user setuid exec"
[ -x "$CCLI" ] || die "the C client is not built: $CCLI"
[ -f "$MOCKBASE" ] || die "the base mock issuer is missing: $MOCKBASE"
command -v useradd >/dev/null 2>&1 || die "useradd is missing"
command -v python3 >/dev/null 2>&1 || die "python3 is missing"

mkdir -p "$GOBIN"

if [ ! -x "$GOBIN/ssh3-server" ]; then
    echo "   .. building the fork server ($GOSSHSRC)"
    (cd "$GOSSHSRC" && go build -buildvcs=false -o "$GOBIN/ssh3-server" ./cmd/ssh3-server) ||
        die "the fork server build failed"
fi

W=$(mktemp -d /tmp/go-oidc-e2e.XXXXXX)
SRVPID=""
CLIPID=""
TARGET_URL=""
FLOW_URL=""
FLOW_RC=0

cleanup() {
    if [ -n "$CLIPID" ]; then
        kill "$CLIPID" 2>/dev/null
        wait "$CLIPID" 2>/dev/null
    fi
    if [ -n "$SRVPID" ]; then
        kill "$SRVPID" 2>/dev/null
        wait "$SRVPID" 2>/dev/null
    fi
    pkill -f "$MOCK_PATT" 2>/dev/null

    # the temp user is the stand itself: it always comes down, only
    # the logs may stay (a failed run keeps them for the postmortem)
    userdel -r "$E2E_USER" 2>/dev/null

    if [ "$FAILURES" -eq 0 ]; then
        rm -rf "$W"
    else
        echo "   (the logs kept: $W)"
    fi
}

trap cleanup EXIT INT TERM

mkdir -p "$W/home/.ssh3"

# the email-aware runner over the base mock: it patches make_id_token
# with the email claims (the fork's oidc identity demands
# email_verified + the email match) and rides the base serve/mint
# verbs untouched
cat > "$W/go-server-oidc-e2e-mock.py" <<'PYEOF'
#!/usr/bin/env python3
"""the email-aware runner of the base mock issuer.

usage: <runner> <base-mock.py> <email> <base-args...>
the empty email keeps the base token shape"""
import importlib.util
import json
import sys
import time

BASE = sys.argv[1]
EMAIL = sys.argv[2]

# the bytecode cache of the base mock would litter the repo
sys.dont_write_bytecode = True

spec = importlib.util.spec_from_file_location("mock_oidc_issuer", BASE)
mock = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mock)

_base_make = mock.make_id_token


def _make_email_token(key_path, issuer, audience, nonce, ttl, subject="tester"):
    if not EMAIL:
        return _base_make(key_path, issuer, audience, nonce, ttl, subject)
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT", "kid": mock.KID}
    payload = {
        "iss": issuer,
        "sub": subject,
        "aud": audience,
        "exp": now + ttl,
        "iat": now,
        "nonce": nonce,
        "email": EMAIL,
        "email_verified": True,
    }
    head = mock.b64url(json.dumps(header, separators=(",", ":")).encode())
    body = mock.b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = head + "." + body
    return signing_input + "." + mock.rs256_sign(key_path, signing_input)


mock.make_id_token = _make_email_token
sys.argv = ["mock-oidc-issuer.py"] + sys.argv[3:]
mock.main()
PYEOF

# the mock issuer on a fixed port: leg 4 reruns the flow through the
# same issuer url and the same key with only the email swapped
MOCK_P=$((47600 + ($$ % 40)))

start_mock() {
    setsid nohup python3 "$W/go-server-oidc-e2e-mock.py" "$MOCKBASE" "$1" \
        serve --port "$MOCK_P" --keys "$W/keys" \
        > "$W/mock.log" 2>&1 < /dev/null &
    local i=0
    while [ "$i" -lt 50 ]; do
        grep -q MOCK-OIDC-ISSUER "$W/mock.log" 2>/dev/null && return 0
        sleep 0.1
        i=$((i + 1))
    done
    return 1
}

start_mock "$E2E_EMAIL" || die "the mock issuer did not start: $(tail -3 "$W/mock.log")"
ISSUER=$(grep -m1 "MOCK-OIDC-ISSUER" "$W/mock.log" | cut -d' ' -f2)

# the temp user: the oidc credential of an existing system user (the
# fork resolves the user through the passwd entry before any verdict)
userdel -r "$E2E_USER" 2>/dev/null
useradd -m -s /bin/bash "$E2E_USER" || die "useradd failed for $E2E_USER"
IDENT_FILE=$(getent passwd "$E2E_USER" | cut -d: -f6)/.ssh3/authorized_identities
mkdir -p "$(dirname "$IDENT_FILE")"
printf 'oidc %s %s %s\n' "$E2E_AUD" "$ISSUER" "$E2E_EMAIL" > "$IDENT_FILE"
chmod 644 "$IDENT_FILE"
echo "   .. the identity line ($IDENT_FILE): $(cat "$IDENT_FILE")"

# the cert and the fork server
openssl req -x509 -sha256 -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout "$W/cert.pem" -days 2 -out "$W/cert.pem" -subj /CN=go-server-oidc-e2e \
    -addext "subjectAltName=IP:127.0.0.1" 2>/dev/null || die "openssl req failed"

S_LOG="$W/srv.log"
S_P=$((47400 + ($$ % 40)))

env SSH3_LOG_LEVEL=debug SSH3_LOG_FILE="$S_LOG" "$GOBIN/ssh3-server" \
    -bind "127.0.0.1:$S_P" -cert "$W/cert.pem" -key "$W/cert.pem" \
    -url-path /ssh3-term > "$W/srv.out" 2>&1 < /dev/null &
SRVPID=$!

i=0
while [ "$i" -lt 50 ]; do
    grep -q "Server started" "$W/srv.out" 2>/dev/null && break
    kill -0 "$SRVPID" 2>/dev/null || break
    sleep 0.1
    i=$((i + 1))
done

kill -0 "$SRVPID" 2>/dev/null || die "the fork server did not start: $(tail -3 "$W/srv.out")"

TARGET_URL="$E2E_USER@127.0.0.1:$S_P/ssh3-term"

# the cert pin of the fork server (the label is the host key of the
# client: host:port/path)
printf '127.0.0.1:%s/ssh3-term x509-certificate %s\n' "$S_P" \
    "$(openssl x509 -in "$W/cert.pem" -outform DER | base64 -w0)" \
    >> "$W/home/.ssh3/known_hosts"

mint_token() {
    python3 "$W/go-server-oidc-e2e-mock.py" "$MOCKBASE" "$1" mint \
        --keys "$W/keys" --issuer "$ISSUER" --audience "$E2E_AUD" \
        --nonce "$2" --ttl 600
}

# wait_oidc_url LOG TIMEOUT_S: polls the log for the client's authorize
# url marker, the url lands in FLOW_URL
wait_oidc_url() {
    i=0
    while [ "$i" -lt $(( $2 * 10 )) ]; do
        if grep -q "OIDC-AUTHORIZE-URL:" "$1" 2>/dev/null; then
            FLOW_URL=$(grep -m1 "OIDC-AUTHORIZE-URL:" "$1" | sed 's/^OIDC-AUTHORIZE-URL: //')
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
        if grep -qa "$2" "$1" 2>/dev/null; then
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

# flow_run OUT ERR CMD...: one browser-less flow ride; the rc lands in
# FLOW_RC, the authorize url in FLOW_URL
flow_run() {
    local out=$1 err=$2
    shift 2
    FLOW_URL=""
    FLOW_RC=0
    S3_OIDC_NO_BROWSER=1 nohup env HOME="$W/home" timeout -k 5 90 "$CCLI" \
        -n -T --oidc-issuer "$ISSUER" --oidc-audience "$E2E_AUD" \
        "$TARGET_URL" "$@" > "$out" 2> "$err" < /dev/null &
    CLIPID=$!
    if ! wait_oidc_url "$err" 15; then
        kill "$CLIPID" 2>/dev/null
        wait "$CLIPID" 2>/dev/null
        CLIPID=""
        FLOW_RC=1
        return 1
    fi
    if ! drive_redirect "$FLOW_URL"; then
        kill "$CLIPID" 2>/dev/null
        wait "$CLIPID" 2>/dev/null
        CLIPID=""
        FLOW_RC=1
        return 1
    fi
    wait "$CLIPID" 2>/dev/null
    FLOW_RC=$?
    CLIPID=""
    return 0
}

echo "== go-oidc 1: the browser-less flow -> the fork, exec under the temp user"

flow_run "$W/leg1-cli.out" "$W/leg1-cli.err" printf go-server-oidc-e2e-exec-ok || true

if [ "$FLOW_RC" -eq 0 ]; then
    pass "the flow rode (rc 0)"
else
    fail "the flow leg: rc=$FLOW_RC $(tail -1 "$W/leg1-cli.err")"
fi

if grep -q go-server-oidc-e2e-exec-ok "$W/leg1-cli.out"; then
    pass "the exec marker came back through the channel"
else
    fail "the exec marker is missing: $(tail -1 "$W/leg1-cli.err")"
fi

if grep -qa "oidc identity parsing success" "$S_LOG" \
    && grep -qa "token signature verification successful" "$S_LOG"; then
    pass "the fork parsed the authorized_identities oidc line and verified the bearer"
else
    fail "no oidc parse/success verdict in the fork log"
fi

if grep -qa "cannot verify raw token" "$S_LOG"; then
    fail "the fork logged a token rejection on the happy flow: $(grep -am1 "cannot verify raw token" "$S_LOG")"
else
    pass "no token rejection in the fork log"
fi

NONCE_A=$(python3 -c 'import sys, urllib.parse
q = urllib.parse.parse_qs(urllib.parse.urlparse(sys.argv[1]).query)
print(q["nonce"][0])' "$FLOW_URL")

echo "== go-oidc 1b: the exit status of the temp user's session"

flow_run "$W/leg1b-cli.out" "$W/leg1b-cli.err" false || true

if [ "$FLOW_RC" -eq 1 ]; then
    pass "the exit status propagated under the setuid user (rc 1)"
else
    fail "the exit-status leg: rc=$FLOW_RC, want 1"
fi

echo "== go-oidc 2: the tampered token -> the signature gate, a clean 401"

TOK=$(mint_token "$E2E_EMAIL" offline-nonce)
TOK=$(python3 - "$TOK" <<'PYEOF'
import sys

# the signature flip on the first char of the segment: the first
# decoded byte always changes, the claims stay valid

t = sys.argv[1]
head, sep, rest = t.rpartition(".")
c = rest[0]
print(head + sep + ("B" if c != "B" else "C") + rest[1:])
PYEOF
)

T0=$(date +%s)
HOME="$W/home" timeout -k 5 30 "$CCLI" --oidc-token "$TOK" \
    "$TARGET_URL" printf go-server-oidc-e2e-never \
    > "$W/leg2-cli.out" 2> "$W/leg2-cli.err"
rc=$?
T1=$(date +%s)

if [ "$rc" -ne 0 ]; then
    pass "the tampered token is refused (rc $rc)"
else
    fail "the tampered token was served"
fi

if [ $((T1 - T0)) -lt 10 ]; then
    pass "the refusal came back at once ($((T1 - T0))s, no hang)"
else
    fail "the refusal hung for $((T1 - T0))s"
fi

if grep -q "refused the session (HTTP 401)" "$W/leg2-cli.err"; then
    pass "the client saw the honest 401"
else
    fail "no 401 verdict on the client side: $(tail -1 "$W/leg2-cli.err")"
fi

if grep -qa "cannot verify raw token" "$S_LOG"; then
    pass "the fork named the token rejection"
else
    fail "no token rejection in the fork log"
fi

if grep -qa "could not find SSH3 conversation" "$S_LOG"; then
    fail "the tampered leg lost the channel: $(grep -am1 "could not find SSH3" "$S_LOG")"
else
    pass "no lost-channel error on the tampered token"
fi

if grep -qa "go-server-oidc-e2e-never" "$W/leg2-cli.out"; then
    fail "the session ran over the rejection"
else
    pass "no exec output over the rejection"
fi

echo "== go-oidc 3: the token of the other session -> the nonce gate"

TOK=$(mint_token "$E2E_EMAIL" "$NONCE_A")

T0=$(date +%s)
HOME="$W/home" timeout -k 5 30 "$CCLI" --oidc-token "$TOK" \
    "$TARGET_URL" printf go-server-oidc-e2e-never \
    > "$W/leg3-cli.out" 2> "$W/leg3-cli.err"
rc=$?
T1=$(date +%s)

if [ "$rc" -ne 0 ]; then
    pass "the foreign-session token is refused (rc $rc)"
else
    fail "the foreign-session token was served"
fi

if [ $((T1 - T0)) -lt 10 ]; then
    pass "the refusal came back at once ($((T1 - T0))s, no hang)"
else
    fail "the refusal hung for $((T1 - T0))s"
fi

if grep -qa "cannot verify raw token: OIDC nonce mismatch" "$S_LOG"; then
    pass "the fork named the nonce gate"
else
    fail "no nonce verdict in the fork log"
fi

if grep -q "refused the session (HTTP 401)" "$W/leg3-cli.err"; then
    pass "the client saw the honest 401"
else
    fail "no 401 verdict on the client side: $(tail -1 "$W/leg3-cli.err")"
fi

if grep -qa "go-server-oidc-e2e-never" "$W/leg3-cli.out"; then
    fail "the session ran over the rejection"
else
    pass "no exec output over the rejection"
fi

echo "== go-oidc 4: the rival email -> the authorized_identities email gate"

# the mock comes back on the same port with the same key and a rival
# email: only the email claim swaps, the flow still completes (the
# client does not gate on the email), the fork must refuse on the
# identity line's email

pkill -f "$MOCK_PATT" 2>/dev/null
i=0
while [ "$i" -lt 30 ]; do
    pgrep -f "$MOCK_PATT" >/dev/null 2>&1 || break
    sleep 0.1
    i=$((i + 1))
done
pkill -9 -f "$MOCK_PATT" 2>/dev/null
sleep 0.3

start_mock "$E2E_EMAIL_RIVAL" || die "the rival mock did not start: $(tail -3 "$W/mock.log")"

if [ "$ISSUER" != "$(grep -m1 "MOCK-OIDC-ISSUER" "$W/mock.log" | cut -d' ' -f2)" ]; then
    die "the rival mock took another port - the issuer url must stay fixed"
fi

flow_run "$W/leg4-cli.out" "$W/leg4-cli.err" printf go-server-oidc-e2e-never || true

if [ "$FLOW_RC" -ne 0 ]; then
    pass "the rival-email token is refused (rc $FLOW_RC)"
else
    fail "the rival-email token was served"
fi

if grep -qa "invalid token: email should be" "$S_LOG"; then
    pass "the fork enforced the identity line's email"
else
    fail "no email verdict in the fork log"
fi

if grep -q "refused the session (HTTP 401)" "$W/leg4-cli.err"; then
    pass "the client saw the honest 401"
else
    fail "no 401 verdict on the client side: $(tail -1 "$W/leg4-cli.err")"
fi

if grep -qa "go-server-oidc-e2e-never" "$W/leg4-cli.out"; then
    fail "the session ran over the rejection"
else
    pass "no exec output over the rejection"
fi

if [ "$FAILURES" -eq 0 ]; then
    echo "GO-SERVER-OIDC-E2E OK"
    exit 0
fi

echo "GO-SERVER-OIDC-E2E FAILED ($FAILURES)"
exit 1
