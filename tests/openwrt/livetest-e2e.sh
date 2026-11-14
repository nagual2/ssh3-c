#!/bin/sh
# the OpenWrt dial-leg livetest (the wave-14 matrix): the cross-built
# client dials the igal and WSL servers over the LAN:
#   S1 system + LE (igal :8444, ClientCert=none)      -> ride
#   S2 own + TOFU (WSL :8443, self-signed)            -> ride
#   S3 system + client-cert (igal :8443, require)     -> ride as alice
#   S4 require, no cert (igal :8443)                  -> refused
#   S5 require, foreign pair (igal :8443)             -> refused
#
# the system leg validates the igal LE certificate through the
# bundled roots (the ISRG of the 1b bundle - the OpenWrt system store
# carries no ISRG: the «never worse than the system» canon of the
# decision #3)
#
# usage: /root/ssh3c-openwrt/livetest-e2e.sh (the run dir carries the
# client, the fixtures and the test identity)
set -u

IGAL=${IGAL:-192.168.35.154}
WSL=${WSL:-192.168.35.121}
D=${1:-/root/ssh3c-openwrt}
BIN=$D/ssh3
FIX=$D/fixtures

echo "== uname: $(uname -a)"

PASS=0
FAILED=0
pass() { echo "   PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "   FAIL: $1"; FAILED=$((FAILED + 1)); }

# --- S1: the system policy + the LE certificate ---

OUT=$("$BIN" -o TrustStore=system -o StrictHostKeyChecking=accept-new \
    -i "$D/test-id.pem" \
    "ai@$IGAL:8444/ssh3-term" "echo S1-OK; id -un" 2>&1)
if echo "$OUT" | grep -q S1-OK; then
    pass "S1: system policy + LE (igal:8444) rode"
else
    fail "S1: $(echo "$OUT" | tail -1)"
fi

# --- S2: the own policy + the TOFU pin ---

OUT=$("$BIN" -o StrictHostKeyChecking=accept-new \
    -i "$D/test-id.pem" \
    "max@$WSL:8443/ssh3-term" "echo S2-OK; id -un" 2>&1)
if echo "$OUT" | grep -q S2-OK; then
    pass "S2: own policy + TOFU (wsl:8443) rode"
else
    fail "S2: $(echo "$OUT" | tail -1)"
fi

# --- S3: the system policy + the client certificate ---

OUT=$("$BIN" -o TrustStore=system -o StrictHostKeyChecking=accept-new \
    --cert "$FIX/alice-cert.pem" --key "$FIX/alice-key.pem" \
    "alice@$IGAL:8443/ssh3-term" "echo S3-OK; id -un" 2>&1)
if echo "$OUT" | grep -q S3-OK; then
    pass "S3: client-cert alice rode (igal:8443 require)"
else
    fail "S3: $(echo "$OUT" | tail -1)"
fi

# --- S4: require, no cert -> refused ---

"$BIN" -o TrustStore=system -o StrictHostKeyChecking=accept-new \
    "alice@$IGAL:8443/ssh3-term" "echo no" > /dev/null 2>&1
if [ $? -ne 0 ]; then
    pass "S4: require refused the no-cert dial"
else
    fail "S4: exited 0"
fi

# --- S5: require + the foreign pair -> refused ---

"$BIN" -o TrustStore=system -o StrictHostKeyChecking=accept-new \
    --cert "$FIX/foreign-cert.pem" --key "$FIX/foreign-key.pem" \
    "alice@$IGAL:8443/ssh3-term" "echo no" > /dev/null 2>&1
if [ $? -ne 0 ]; then
    pass "S5: foreign pair refused"
else
    fail "S5: exited 0"
fi

echo "legs: $((PASS + FAILED)), $PASS passed, $FAILED failed"

if [ "$FAILED" -eq 0 ]; then
    echo "E2E-OPENWRT OK"
    exit 0
fi

echo "E2E-OPENWRT FAILED"
exit 1
