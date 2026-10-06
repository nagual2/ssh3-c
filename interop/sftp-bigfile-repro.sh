#!/bin/sh
# the sftp big-file repro (the P7 bench defect, the wave P7.1):
#
# the 50 ms timer pump with the one-request pipeline moved under one
# driver chunk per round trip (~0.2 MB/s), so every transfer above
# the deadline died mid-flight and the sha gate rejected it; the
# matrix (the 3 MiB scenarios 16-18) passed - the failure started
# between 3 and 8 MiB (the 30 s verdict deadline burns at ~4 MiB,
# the bench measured the 8 MiB rows 0/7 valid)
#
# the run: one s3interop_server (-3 -H jail), the client (-3 -J)
# uploads and downloads an 8 MiB payload N rounds, every landed file
# verifies byte-exact against the payload (cmp, the sha256 of the
# landed file is printed); before the fix the rounds die on the
# verdict timeout with a short (killed mid-transfer) target file
#
# usage: sftp-bigfile-repro.sh [worktree] [size-mib] [rounds]

set -u

ROOT=${1:-/mnt/c/Git/temp/wt-sftp-fix}
MIB=${2:-8}
ROUNDS=${3:-5}
BUILD=$ROOT/build/linux-release
FAILURES=0

die() {
    echo "sftp-bigfile-repro: $1" >&2
    exit 1
}

[ -x "$BUILD/s3interop_client" ] || die "the client binary is not built ($BUILD)"
[ -x "$BUILD/s3interop_server" ] || die "the server binary is not built ($BUILD)"

W=$(mktemp -d /dev/shm/sftp-bigfile.XXXXXX)
JAIL=$W/jail
mkdir -p "$JAIL"

cleanup() {
    pkill -f "s3interop_server -3 -H $JAIL" 2>/dev/null
    rm -rf "$W"
}
trap cleanup EXIT

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/key.pem" -out "$W/cert.pem" \
    -days 2 -subj /CN=sftp-bigfile-repro 2>/dev/null || die "openssl req failed"

dd if=/dev/urandom of="$W/payload.bin" bs=1048576 count="$MIB" 2>/dev/null \
    || die "the payload dd failed"
REF=$(sha256sum "$W/payload.bin" | cut -d' ' -f1)

setsid nohup "$BUILD/s3interop_server" -3 -H "$JAIL" -l 127.0.0.1:0 \
    -c "$W/cert.pem" -k "$W/key.pem" > "$W/srv.log" 2>&1 < /dev/null &

i=0
while [ "$i" -lt 50 ]; do
    PORT=$(grep -o 'port=[0-9]*' "$W/srv.log" 2>/dev/null | head -1 | cut -d= -f2)
    [ -n "${PORT:-}" ] && break
    sleep 0.1
    i=$((i + 1))
done

[ -n "${PORT:-}" ] || die "the server did not start"

echo "== sftp-bigfile-repro: ${MIB} MiB x ${ROUNDS} rounds (build $BUILD)"

i=1
while [ "$i" -le "$ROUNDS" ]; do

    rm -f "$JAIL/round.bin"

    t0=$(date +%s%N)
    timeout 120 "$BUILD/s3interop_client" -3 -J "put:$W/payload.bin:round.bin" \
        -a "127.0.0.1:$PORT" -t 30000 > "$W/put.log" 2>&1
    rc=$?
    t1=$(date +%s%N)

    GOT=$(sha256sum "$JAIL/round.bin" 2>/dev/null | cut -d' ' -f1)
    V=$(grep -o 'INTEROP-SFTP-[A-Z]*' "$W/put.log" | head -1)

    if [ "$rc" = 0 ] && [ "$GOT" = "$REF" ] && [ "$V" = "INTEROP-SFTP-OK" ]; then
        echo "   PASS put#$i ($(awk -v ns=$((t1 - t0)) -v b=$((MIB * 1048576)) \
            'BEGIN{printf "%.0f ms, %.1f MB/s", ns/1e6, b/1048576/(ns/1e9)}'))"
    else
        echo "   FAIL put#$i rc=$rc verdict=${V:-none} sha=$([ "${GOT:-}" = "$REF" ] \
            && echo ok || echo bad)"
        FAILURES=$((FAILURES + 1))
    fi

    rm -f "$W/got.bin"

    t0=$(date +%s%N)
    timeout 120 "$BUILD/s3interop_client" -3 -J "get:$W/got.bin:round.bin" \
        -a "127.0.0.1:$PORT" -t 30000 > "$W/get.log" 2>&1
    rc=$?
    t1=$(date +%s%N)

    GOT=$(sha256sum "$W/got.bin" 2>/dev/null | cut -d' ' -f1)
    V=$(grep -o 'INTEROP-SFTP-[A-Z]*' "$W/get.log" | head -1)

    if [ "$rc" = 0 ] && [ "$GOT" = "$REF" ] && [ "$V" = "INTEROP-SFTP-OK" ]; then
        echo "   PASS get#$i ($(awk -v ns=$((t1 - t0)) -v b=$((MIB * 1048576)) \
            'BEGIN{printf "%.0f ms, %.1f MB/s", ns/1e6, b/1048576/(ns/1e9)}'))"
    else
        echo "   FAIL get#$i rc=$rc verdict=${V:-none} sha=$([ "${GOT:-}" = "$REF" ] \
            && echo ok || echo bad)"
        FAILURES=$((FAILURES + 1))
    fi

    i=$((i + 1))
done

if [ "$FAILURES" = 0 ]; then
    echo "== SFTP-BIGFILE-REPRO-OK"
    exit 0
fi

echo "== SFTP-BIGFILE-REPRO-FAIL failures=$FAILURES"
exit 1
