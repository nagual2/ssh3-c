#!/bin/sh
# the CM session churn repro (P7.1, the stream retire wave):
#
#   1. one s3interop_server, one control master (-3 -C -M)
#   2. N sequential slave sessions (-e true) ride the one connection;
#      the master opens one client bidi stream per session against the
#      initial_max_streams_bidi credit (16), the retire of the closed
#      channels must lift the credit - without the retire the 17th
#      session dies with "too many client bidi streams"
#   3. every slave must print S3CM-SLAVE-DONE exit=0, the master must
#      finalize every session with exit 0
#
# usage: cm-sessions-repro.sh [worktree] [sessions]
#   sessions defaults to 300; S3CM_REPRO_LATENCY=1 also prints the
#   median per-session wall time of the middle 100 sessions
set -u

ROOT=${1:-/mnt/c/Git/project/ssh3-c}
N=${2:-300}
BUILD=$ROOT/build/linux-release

# a bare build dir (binaries at the top) works too, e.g. a scratch
# build of the pre-fix tree for the red comparison

if [ ! -x "$BUILD/s3interop_server" ] && [ -x "$ROOT/s3interop_server" ]; then
    BUILD=$ROOT
fi

die() {
    echo "cm-sessions-repro: $1" >&2
    exit 1
}

[ -x "$BUILD/s3interop_server" ] || die "s3interop_server is not built"
[ -x "$BUILD/s3interop_client" ] || die "s3interop_client is not built"

W=$(mktemp -d /tmp/cm-sessions.XXXXXX)
SOCK=/tmp/cm-sessions.sock
trap 'rm -f "$SOCK"; rm -rf "$W"' EXIT

SRV=$W/srv.log
MASTER=$W/master.log

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/key.pem" -out "$W/cert.pem" \
    -days 30 -subj /CN=cm-sessions 2>/dev/null || die "openssl req failed"

wait_for() {
    # wait_for <file> <pattern> [tries=100]
    i=0
    while [ "$i" -lt "${3:-100}" ]; do
        if grep -q "$2" "$1" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
        i=$((i + 1))
    done

    return 1
}

rm -f "$SOCK"

setsid nohup "$BUILD/s3interop_server" -3 -l 127.0.0.1:0 -c "$W/cert.pem" -k "$W/key.pem" \
    > "$SRV" 2>&1 < /dev/null &

SRVPID=$!

if ! wait_for "$SRV" INTEROP-LISTEN; then
    die "the server did not start"
fi

PORT=$(grep -oE 'port=[0-9]+' "$SRV" | cut -d= -f2)

setsid nohup "$BUILD/s3interop_client" -3 -C -M -U "$SOCK" -a "127.0.0.1:$PORT" \
    -t 600000 > "$MASTER" 2>&1 < /dev/null &

MASTERPID=$!

if ! wait_for "$MASTER" "S3CM-MASTER-LISTEN" || ! wait_for "$MASTER" "INTEROP-H3-STATUS 200"; then
    kill "$SRVPID" 2>/dev/null
    die "the master did not come up"
fi

echo "server 127.0.0.1:$PORT, master pid $MASTERPID, $N sessions"

OK=0
FAIL=0
: > "$W/times.txt"

i=1
while [ "$i" -le "$N" ]; do

    T0=$(date +%s%N)

    if timeout 15 "$BUILD/s3interop_client" -U "$SOCK" -e true -t 10000 \
        > "$W/slave.log" 2>&1 && grep -q "S3CM-SLAVE-DONE exit=0" "$W/slave.log"; then
        OK=$((OK + 1))
    else
        FAIL=$((FAIL + 1))
        echo "session $i FAILED:" >&2
        cat "$W/slave.log" >&2
        cp "$W/slave.log" "$W/slave-fail-$i.log"
        cp "$MASTER" "$W/master-fail-$i.log"
    fi

    T1=$(date +%s%N)

    if [ "$i" -gt 100 ] && [ "$i" -le 200 ]; then
        echo $((T1 - T0)) >> "$W/times.txt"
    fi

    i=$((i + 1))
done

kill "$MASTERPID" "$SRVPID" 2>/dev/null
wait "$MASTERPID" 2>/dev/null

MASTER_OK=$(grep -c "S3CM-MASTER-SESSION-DONE exit=0" "$MASTER")
TOOMANY=$(grep -c "too many client bidi streams" "$MASTER")

echo "sessions ok=$OK fail=$FAIL; master finalized ok=$MASTER_OK; 'too many' hits=$TOOMANY"

if [ "${S3CM_REPRO_LATENCY:-0}" = 1 ]; then
    sort -n "$W/times.txt" | awk '{a[NR]=$1} END {
        if (NR == 0) { print "latency: no samples"; exit }
        print "latency: median=" a[int((NR + 1) / 2)] / 1000000 " ms (" NR " samples, p90=" a[int(NR * 9 / 10)] / 1000000 " ms)"
    }'
fi

if [ "$OK" -eq "$N" ] && [ "$FAIL" -eq 0 ]; then
    echo "CM-SESSIONS-OK $N/$N"
    exit 0
fi

echo "CM-SESSIONS-FAILED ok=$OK want=$N"
exit 1
