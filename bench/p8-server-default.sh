#!/usr/bin/env bash
# p8-server-default.sh — the wire cost/benefit of the server-side compression
# that rides by default (PLAN.md 9, B8)
#
#   The direction: server -> client.  The server picks the codec from the
#   capability the client announced in the CONNECT version string
#   (s3_srv_preauth_t.compress_alg), so the regular client without -C already
#   receives zstd-compressed channel bodies.  The question: what does that
#   default buy and cost, against an uncompressed server?
#
#   The legs (a get of the payloads, the wire rides the server -> client side):
#     get-plain     the client of the codec-less build: an empty capability,
#                   the server cannot compress towards it — the base
#     get-default   the regular client without -C: the server picks zstd —
#                   the default in question
#     get-C-auto    the client with -C: the same negotiation, both directions
#     get-C-lz4     the client with -C lz4: the pinned codec
#
#   The numbers (the R3 methodology of bench/p7-compress.sh):
#     - the wire: tcpdump on lo, the sum of the UDP payload lengths of the leg
#     - the CPU: the utime+stime delta of the daemon (/proc, the CLK_TCK
#       granularity) and the client (times -p, the second granularity)
#     - the session overhead: 30 exec runs of a tiny command, the wall time
#       and the daemon CPU delta
#   The gate: the sha256 of the landed file must match (a broken get is a
#   discarded round, not a pretty number).
#
#   usage: p8-server-default.sh [--main-build DIR] [--plain-build DIR]
#                               [--rounds N] [--size MB] [--work DIR]
set -euo pipefail

WORK=/tmp/p8default
MAIN_BUILD=/mnt/c/Git/project/ssh3-c/build/linux-release
PLAIN_BUILD=/mnt/c/Git/project/ssh3-c/build/no-codecs
ROUNDS=4
SIZE_MB=8
EXEC_N=30
CAPTURE=1

while [ $# -gt 0 ]; do
    case "$1" in
    --main-build) MAIN_BUILD="$2"; shift 2 ;;
    --plain-build) PLAIN_BUILD="$2"; shift 2 ;;
    --rounds) ROUNDS="$2"; shift 2 ;;
    --size) SIZE_MB="$2"; shift 2 ;;
    --work) WORK="$2"; shift 2 ;;
    --no-capture) CAPTURE=0; shift ;;
    *) echo "p8-server-default: unknown flag: $1" >&2; exit 2 ;;
    esac
done

MAIN_CLIENT=$MAIN_BUILD/ssh3
PLAIN_CLIENT=$PLAIN_BUILD/ssh3
C_SERVER=$MAIN_BUILD/ssh3-server

log() { echo "[p8-default $(date +%H:%M:%S)] $*"; }
die() { echo "p8-server-default: $*" >&2; exit 1; }

for f in "$MAIN_CLIENT" "$PLAIN_CLIENT" "$C_SERVER"; do
    [ -x "$f" ] || die "the binary is missing: $f"
done

LOGS=$WORK/logs
RES=$WORK/results
DEV_SHM=/dev/shm/p8default
mkdir -p "$LOGS" "$RES" "$DEV_SHM"

# the QUIC TLS API needs the OpenSSL 3.5: the deb channel ships it in
# /usr/lib/ssh3-c/lib (ssh3c-libssl3), the WSL stand keeps its own copy
# in ~/opt/openssl-3.5/lib64.  The path rides only the ssh3 processes
# (an env export would poison the system openssl: its 3.0-linked binary
# crashes on the 3.5 libcrypto)
S3_LD_PREFIX=""
if [ -z "${LD_LIBRARY_PATH:-}" ]; then
    if [ -d /usr/lib/ssh3-c/lib ]; then
        S3_LD_PREFIX="LD_LIBRARY_PATH=/usr/lib/ssh3-c/lib"
    elif [ -d "$HOME/opt/openssl-3.5/lib64" ]; then
        S3_LD_PREFIX="LD_LIBRARY_PATH=$HOME/opt/openssl-3.5/lib64"
    fi
fi

# --- the stand ---------------------------------------------------------------

setup_stand() {
    cd "$WORK"

    if [ ! -f bench_pkcs8.pem ]; then
        openssl genpkey -algorithm ed25519 -out bench_pkcs8.pem 2>/dev/null
        chmod 600 bench_pkcs8.pem
        {
            printf '\000\000\000\013ssh-ed25519\000\000\000\040'
            openssl pkey -in bench_pkcs8.pem -pubout -outform DER 2>/dev/null | tail -c 32
        } | base64 | tr -d '\n' > bench_blob.pub
        printf 'ssh-ed25519 %s p8default\n' "$(cat bench_blob.pub)" > authorized_keys
    fi

    if [ ! -f cert.pem ]; then
        openssl req -x509 -sha256 -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
            -keyout key.pem -days 30 -out cert.pem -subj /CN=127.0.0.1 \
            -addext "subjectAltName=IP:127.0.0.1" 2>/dev/null
    fi

    rm -rf "$WORK/home"
    mkdir -p "$WORK/home/.ssh3"

    if [ ! -f "$DEV_SHM/text.bin" ]; then
        python3 - "$DEV_SHM/text.bin" "$SIZE_MB" <<'EOF'
import sys
path, mb = sys.argv[1], int(sys.argv[2])
line = b"ssh3-compress-bench the log line repeats so the codec has something to eat\n"
with open(path, "wb") as f:
    written = 0
    target = mb * 1024 * 1024
    while written < target:
        f.write(line)
        written += len(line)
EOF
    fi
    if [ ! -f "$DEV_SHM/rand.bin" ]; then
        dd if=/dev/urandom of="$DEV_SHM/rand.bin" bs=1M count="$SIZE_MB" status=none
    fi
}

PORT_C=$((49000 + ($$ % 100)))

start_server() {
    local srv_cmd=("$C_SERVER" -3 -l "127.0.0.1:$PORT_C" -c "$WORK/cert.pem" -k "$WORK/key.pem" \
        -K "$WORK/authorized_keys" --max-sftp-sessions-per-user 0)

    # the death hunter: S8_STRACE=1 wraps the daemon into strace and
    # writes the signal trace next to the log (who sends the TERM?)
    if [ "${S8_STRACE:-0}" = "1" ] && command -v strace >/dev/null 2>&1; then
        SSH3_LOG_FILE="$LOGS/c-server.log" setsid nohup env "$S3_LD_PREFIX" strace -f -o "$LOGS/srv.strace" \
            -e trace=%signal,execve -qq "${srv_cmd[@]}" \
            > "$LOGS/c-server.out" 2>&1 < /dev/null &
    else
        SSH3_LOG_FILE="$LOGS/c-server.log" setsid nohup env "$S3_LD_PREFIX" "${srv_cmd[@]}" \
            > "$LOGS/c-server.out" 2>&1 < /dev/null &
    fi
    SRV_PID=$!
    sleep 0.3
    [ -d "/proc/$SRV_PID" ] || die "the C server died at startup"
    log "the daemon is up on 127.0.0.1:$PORT_C (pid $SRV_PID)"
}

stop_server() {
    [ -n "${SRV_PID:-}" ] || return 0
    kill "$SRV_PID" 2>/dev/null || true
    # the strace wrapper keeps the real daemon as its child: the port
    # shape catches it whatever the wrapper did
    pkill -f -- "-l 127.0.0.1:$PORT_C" 2>/dev/null || true
    wait "$SRV_PID" 2>/dev/null || true
}

pin_cert() {
    printf '127.0.0.1:%s/ssh3-term x509-certificate %s\n' "$PORT_C" \
        "$(openssl x509 -in "$WORK/cert.pem" -outform DER | base64 -w0)" \
        >> "$WORK/home/.ssh3/known_hosts"
}

# --- the capture (the R3 shape) ----------------------------------------------

pcap_bytes() {
    local pcap="$1"
    [ -s "$pcap" ] || { echo "0 0"; return 0; }
    sudo -n tcpdump -r "$pcap" -n -q 2>/dev/null |
        awk '/ UDP,? / { for (i = 1; i <= NF; i++) if ($i == "length") { s += $(i + 1); n++ } }
             END { printf "%d %d\n", s + 0, n + 0 }'
}

capture_start() {
    local pcap="$1"
    sudo -n rm -f "$pcap"
    sudo -n tcpdump --immediate-mode -U -i lo -n -w "$pcap" udp >/dev/null 2>&1 &
    sleep 0.8
}

capture_stop() {
    local pcap="$1"
    local pid
    pid=$(pgrep -f "tcpdump --immediate-mode -U -i lo -n -w $pcap" | head -1)
    if [ -n "$pid" ]; then
        sudo -n kill -INT "$pid" 2>/dev/null || true
        sleep 0.5
    fi
}

# --- the daemon CPU (the utime+stime ticks of /proc/PID/stat) ----------------

srv_cpu_ticks() {
    awk '{ print $14 + $15 }' "/proc/$SRV_PID/stat"
}

# --- the legs ----------------------------------------------------------------

# $1 = the client binary, $2 = the codec option ("", "C", "Clz4"), the get of
# the remote payload into the local out
get_file() {
    local bin="$1" opt="$2" out="$3" remote="$4"
    local flag=""

    # the opt is the codec name for a pin ("lz4") or "auto" (the bare
    # -C: the best codec of the intersection); "none" rides no flag
    case "$opt" in
    auto) flag="-C" ;;
    none) flag="" ;;
    *) flag="-C$opt" ;;
    esac

    if [ -n "$flag" ]; then
        HOME="$WORK/home" timeout -k 5 120 env "$S3_LD_PREFIX" "$bin" "$flag" -i "$WORK/bench_pkcs8.pem" \
            --sftp "get:$out:$remote" "client@127.0.0.1:$PORT_C/ssh3-term" \
            > "$LOGS/leg.out" 2>"$LOGS/leg.err"
    else
        HOME="$WORK/home" timeout -k 5 120 env "$S3_LD_PREFIX" "$bin" -i "$WORK/bench_pkcs8.pem" \
            --sftp "get:$out:$remote" "client@127.0.0.1:$PORT_C/ssh3-term" \
            > "$LOGS/leg.out" 2>"$LOGS/leg.err"
    fi
}

# the leg: one get inside the capture window, the wire + the daemon CPU
run_leg() { # $1 = leg, $2 = payload path, $3 = round
    local leg="$1" payload="$2" round="$3"
    local bin opt out remote pcap rc
    local cpu_before cpu_after t0 t1

    case "$leg" in
    get-plain) bin="$PLAIN_CLIENT"; opt="none" ;;
    get-default) bin="$MAIN_CLIENT"; opt="auto" ;;
    get-C-auto) bin="$MAIN_CLIENT"; opt="auto" ;;
    get-C-lz4) bin="$MAIN_CLIENT"; opt="lz4" ;;
    *) die "unknown leg: $leg" ;;
    esac

    remote="/p8-$round-${payload##*/}"
    out="$DEV_SHM/out-$round-${payload##*/}"
    rm -f "$out"

    # the self-healing stand: a daemon that died during the run is
    # restarted (a new port, a fresh pin), the round must not die with it
    if [ ! -d "/proc/$SRV_PID" ]; then
        log "round $round: the daemon is gone, restarting it"
        PORT_C=$((PORT_C + 1))
        start_server "r$round"
        pin_cert
    fi

    # the payload lands outside the capture window (the put is not the
    # measured direction; the bytes are the same however it travels)
    HOME="$WORK/home" timeout -k 5 120 env "$S3_LD_PREFIX" "$MAIN_CLIENT" -i "$WORK/bench_pkcs8.pem" \
        --sftp "put:$payload:$remote" "client@127.0.0.1:$PORT_C/ssh3-term" \
        > /dev/null 2>>"$LOGS/put.err" || log "the pre-leg put failed (rc=$?)"

    cpu_before=$(srv_cpu_ticks)
    pcap="$WORK/cap-$leg-$round-${payload##*/}.pcap"

    # the capture rides only with --no-capture off: the sudo-tcpdump
    # cycle destabilises some stands, and the wire question is already
    # answered by the p7/p8 runs (the time runs measure wall+cpu)
    if [ "$CAPTURE" = "1" ]; then
        capture_start "$pcap"
    fi

    rc=0
    t0=$(date +%s%N)
    get_file "$bin" "$opt" "$out" "$remote" || rc=$?
    t1=$(date +%s%N)

    if [ "$CAPTURE" = "1" ]; then
        capture_stop "$pcap"
        read -r wire packets <<<"$(pcap_bytes "$pcap")"
    else
        wire=0
        packets=0
    fi
    cpu_after=$(srv_cpu_ticks)

    if [ "$rc" -ne 0 ]; then
        log "round $round: the leg $leg failed: rc=$rc"
        echo "$leg,${payload##*/},$round,0,0,no,0,0,0" >> "$RES/p8.csv"
        return 0
    fi

    # the gate: the bytes came back identical
    local sha_ok=no
    if cmp -s "$payload" "$out"; then
        sha_ok=yes
    fi

    read -r wire packets <<<"$(pcap_bytes "$pcap")"
    echo "$leg,${payload##*/},$round,$wire,$packets,$sha_ok,$cpu_after,$cpu_before,$((t1 - t0))" >> "$RES/p8.csv"
    log "round $round: $leg (${payload##*/}): wire=$wire pkts=$packets sha=$sha_ok srv_cpu=$((cpu_after - cpu_before))t wall=$(( (t1 - t0) / 1000000 ))ms"
}

# the session overhead: EXEC_N tiny execs, the wall time and the daemon CPU
exec_leg() { # $1 = leg
    local leg="$1" bin n
    local t0 t1 cpu_before cpu_after

    case "$leg" in
    exec-plain) bin="$PLAIN_CLIENT" ;;
    exec-default) bin="$MAIN_CLIENT" ;;
    *) die "unknown exec leg: $leg" ;;
    esac

    # the self-healing stand (the same as the get legs)
    if [ ! -d "/proc/$SRV_PID" ]; then
        log "exec $leg: the daemon is gone, restarting it"
        PORT_C=$((PORT_C + 1))
        start_server
        pin_cert
    fi

    cpu_before=$(srv_cpu_ticks)
    t0=$(date +%s%N)

    for ((n = 1; n <= EXEC_N; n++)); do
        HOME="$WORK/home" timeout -k 2 15 env "$S3_LD_PREFIX" "$bin" -i "$WORK/bench_pkcs8.pem" \
            "client@127.0.0.1:$PORT_C/ssh3-term" "printf S8-OK" \
            > /dev/null 2>"$LOGS/exec.err" || { log "the exec leg $leg failed at $n: $(tail -1 "$LOGS/exec.err" 2>/dev/null)"; return 0; }
    done

    t1=$(date +%s%N)
    cpu_after=$(srv_cpu_ticks)
    echo "$leg,$EXEC_N,$t0,$t1,$((cpu_after - cpu_before))" >> "$RES/p8-exec.csv"
    log "exec $leg: ${EXEC_N} runs in $(((t1 - t0) / 1000000)) ms, daemon cpu +$((cpu_after - cpu_before))t"
}

# --- the run ------------------------------------------------------------------

setup_stand
start_server
pin_cert

trap 'stop_server' EXIT INT TERM

mkdir -p "$RES"
echo "leg,payload,round,wire_bytes,packets,sha_ok,cpu_after,cpu_before,wall_ns" > "$RES/p8.csv"
echo "leg,runs,t0_ns,t1_ns,srv_cpu_ticks" > "$RES/p8-exec.csv"

PAYLOADS="text rand"

for round in $(seq 1 "$ROUNDS"); do
    for leg in get-plain get-default get-C-auto get-C-lz4; do
        for pl in $PAYLOADS; do
            run_leg "$leg" "$DEV_SHM/$pl.bin" "$round"
        done
    done
    if [ "$round" -eq 1 ]; then
        log "the warmup round is done (the exec legs run once, after it)"
        exec_leg exec-plain
        exec_leg exec-default
    fi
done

echo
echo "== the medians (the warmup round 1 is discarded)"

awk -F, '
    NR == 1 { next }
    {
        leg = $1; pl = $2; r = $3
        if (r == 1) next
        if ($6 != "yes") { bad[leg" "pl]++; next }
        key = leg" "pl
        n[key]++
        v[key, n[key]] = $4 + 0
        c[key, n[key]] = $7 - $8
    }
    END {
        printf "%-14s %-8s %12s %10s %6s %6s\n", "leg", "payload", "wire_med", "srv_cpu", "rounds", "bad"
        for (k in n) {
            for (i = 1; i <= n[k]; i++) {
                val = v[k, i]
                j = i - 1
                while (j >= 1 && v[k, j] > val) { v[k, j + 1] = v[k, j]; j-- }
                v[k, j + 1] = val
            }
            med = (n[k] % 2) ? v[k, int(n[k] / 2) + 1] : int((v[k, n[k] / 2] + v[k, n[k] / 2 + 1]) / 2)
            for (i = 1; i <= n[k]; i++) {
                val = c[k, i]
                j = i - 1
                while (j >= 1 && c[k, j] > val) { c[k, j + 1] = c[k, j]; j-- }
                c[k, j + 1] = val
            }
            cmed = (n[k] % 2) ? c[k, int(n[k] / 2) + 1] : int((c[k, n[k] / 2] + c[k, n[k] / 2 + 1]) / 2)
            split(k, a, " ")
            printf "%-14s %-8s %12d %10d %6d %6d\n", a[1], a[2], med, cmed, n[k], bad[k] + 0
        }
    }
' "$RES/p8.csv" | sort

echo
echo "the raw rows: $RES/p8.csv, $RES/p8-exec.csv"
