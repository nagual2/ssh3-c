#!/bin/sh
# tls303-repro.sh - the musl-TLS 303 (illegal_parameter) localization
# and repro (PLAN-CURRENT 3.4, closed 2026-11-11)
#
# The verdict of the diagnosis: the 303 is NOT the SDK openssl config
# and NOT musl - it is the ssh3-c 0-RTT stage-1 leak of
# SSL_CTX_set_max_early_data() (the v0.5.6 s3_ssl.c:161): OpenSSL
# rides early_data(max_early_data_size=16384) into every
# NewSessionTicket, and the RFC 9001 4.5 QUIC rule allows only 0 or
# 0xffffffff there.  The NST-reading client's OpenSSL 3.5.9 answers
# with SSL_AD_ILLEGAL_PARAMETER (extensions_clnt.c:2084,
# ssl/statem/extensions_clnt.c) = alert 47 = QUIC crypto error
# 0x12F = 303 - right after the CONNECT (the server side rides
# HANDSHAKE-OK+AUTH-OK+CONNECT-OK blind).  The fix rides main since
# f55b280 (B21, 2026-10-31 19:32) - after the 0.5.6 tag, so the
# 0.5.6-r1 SDK apk of the dev stand carried it and the row was
# written against that pair; 0.5.7+ artifacts are clean.
#
# The legs (each rides the WSL glibc client of the checkout):
#   1. glibc server  <-> glibc client  (the control)
#   2. alpine musl server (alpine 3.22 openssl 3.5.9)  <-> glibc
#   3. SDK-toolchain musl server (feed patches+options openssl build)
#                                                      <-> glibc
#   4. the SDK feed libopenssl3-3.5.9-r1 (the VM libs, runtime swap)
#                                                      <-> glibc
#   5. the v0.5.6 server (the incident artifact, the leak in)  <->
#      the current client - THE 303 REPRO (invalid max early data)
#
# usage: interop/tls303-repro.sh - the stand layout rides the
# environment (build the servers first, see docs/PLAN-CURRENT.md 3.4):
#   TLS303_STAND        the stand directory (created, cert/keys live)
#   TLS303_SDKMUSL_SRV  the SDK-toolchain musl ssh3-server binary
#   TLS303_SDKMUSL_LIB  the LD_LIBRARY_PATH of the SDK openssl build
#   TLS303_V056_SRV     the v0.5.6 musl ssh3-server (the leak in)
#   TLS303_ALPINE_LIB   the alpine musl lib dir (loader + libc)
#   TLS303_LOGS         the logs dir (default: $TLS303_STAND/logs)
set -u

die() {
    echo "tls303-repro: $*"
    exit 2
}

WT=$(cd "$(dirname "$0")/.." && pwd)
BUILD=$WT/build/linux-release
ALPINE_BIN=$WT/build/alpine/ssh3-server

: "${TLS303_STAND:?required}"
: "${TLS303_SDKMUSL_SRV:?required}"
: "${TLS303_SDKMUSL_LIB:?required}"
: "${TLS303_V056_SRV:?required}"
: "${TLS303_ALPINE_LIB:?required}"

SDKMUSL_BIN=$TLS303_SDKMUSL_SRV
SDKMUSL_LIB=$TLS303_SDKMUSL_LIB
V056_BIN=$TLS303_V056_SRV
ALPINE_LIB=$TLS303_ALPINE_LIB

STAND=$TLS303_STAND
LOGS=${TLS303_LOGS:-$STAND/logs}
PORT=${TLS303_PORT:-47479}

PRIV="$STAND/priv.pem"
PUB="$STAND/authorized_keys"
CERT="$STAND/cert.pem"
KEY="$STAND/key.pem"

SRVPID=""
cleanup() {
    [ -n "$SRVPID" ] && kill -9 "$SRVPID" 2>/dev/null
    wait 2>/dev/null
    true
}
trap cleanup EXIT INT TERM

mkstand() {
    mkdir -p "$STAND" "$LOGS"
    [ -f "$PRIV" ] || openssl genpkey -algorithm ed25519 -out "$PRIV" 2>/dev/null
    [ -f "$CERT" ] || openssl req -x509 -newkey rsa:2048 -nodes -keyout "$KEY" \
        -out "$CERT" -days 2 -subj /CN=tls303-repro 2>/dev/null
    {
        printf '\000\000\000\013ssh-ed25519\000\000\000\040'
        openssl pkey -in "$PRIV" -pubout -outform DER 2>/dev/null | tail -c 32
    } | base64 | tr -d '\n' > "$STAND/blob.pub"
    printf 'ssh-ed25519 %s tls303-repro\n' "$(cat "$STAND/blob.pub")" > "$PUB"
}

run_leg() {
    TAG=$1
    CLI=$2
    SRV=$3
    shift 3

    SLOG="$LOGS/srv-r-$TAG.log"
    COUT="$LOGS/cli-r-$TAG.out"
    CERR="$LOGS/cli-r-$TAG.err"
    HOME_LEG="$STAND/home-r-$TAG"
    rm -rf "$HOME_LEG"
    mkdir -p "$HOME_LEG"

    "$@" "$SRV" -c "$CERT" -k "$KEY" -K "$PUB" \
        -l "127.0.0.1:$PORT" -L debug > "$SLOG" 2>&1 < /dev/null &
    SRVPID=$!

    N=0
    while [ "$N" -lt 50 ]; do
        grep -q INTEROP-LISTEN "$SLOG" 2>/dev/null && break
        kill -0 "$SRVPID" 2>/dev/null || break
        sleep 0.1
        N=$((N + 1))
    done

    HOME="$HOME_LEG" timeout 20 "$CLI" -i "$PRIV" -o insecure -vv -4 \
        "root@127.0.0.1:$PORT/ssh3-term" "printf TLS303-LEG-$TAG-OK" \
        > "$COUT" 2> "$CERR"
    RC=$?
    kill -9 "$SRVPID" 2>/dev/null
    wait "$SRVPID" 2>/dev/null
    SRVPID=""

    if [ "$RC" -eq 0 ] && grep -q "TLS303-LEG-$TAG-OK" "$COUT"; then
        echo "LEG-$TAG-OK"
        return 0
    fi

    if grep -q "invalid max early data" "$CERR"; then
        echo "LEG-$TAG-303 (invalid max early data -> 303, the expected repro)"
        return 0
    fi

    echo "LEG-$TAG-FAIL (rc=$RC: $(tail -1 "$CERR" | head -c 200))"
    return 1
}

mkstand

run_leg glibc "$BUILD/ssh3" "$BUILD/ssh3-server" env
run_leg alpine "$BUILD/ssh3" "$ALPINE_BIN" env LD_LIBRARY_PATH="$ALPINE_LIB" "$ALPINE_LIB/ld-musl-x86_64.so.1"
run_leg sdkmusl "$BUILD/ssh3" "$SDKMUSL_BIN" env LD_LIBRARY_PATH="$SDKMUSL_LIB" "$ALPINE_LIB/ld-musl-x86_64.so.1"
run_leg sdklib "$BUILD/ssh3" "$ALPINE_BIN" env LD_LIBRARY_PATH="$SDKMUSL_LIB" "$ALPINE_LIB/ld-musl-x86_64.so.1"
run_leg v056repro "$BUILD/ssh3" "$V056_BIN" env LD_LIBRARY_PATH="$SDKMUSL_LIB" "$ALPINE_LIB/ld-musl-x86_64.so.1"
