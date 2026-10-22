#!/usr/bin/env bash
# p7-compress.sh — the wire gain of the channel-body compression (PLAN.md 9, B8)
#
#   The question: how many bytes does the traffic of a session cost on the
#   wire, and what do the codecs buy (the "economy of traffic" of F2)?
#
#   The method is the R3 methodology of bench/p7-compare.sh: one stand, one
#   keypair, one loopback, the payloads on tmpfs, the rounds in a rotation
#   (the ambient load lands on every leg equally), the first round is the
#   warmup and is discarded, the reported number is the median.
#
#   The wire number comes from a real capture: tcpdump on lo, the sum of
#   the UDP payload lengths of the packets of the leg.  The application
#   number comes from the client itself: the plain bytes and the bytes on
#   the wire of the compressed frames.
#
#   The gate: the transferred file must come back byte-exact (sha256), a
#   broken transfer is a discarded round, not a pretty number.
#
#   usage: p7-compress.sh [--c-build DIR] [--go-bin DIR] [--rounds N]
#                         [--size MB] [--work DIR] [--legs LIST]
set -euo pipefail

WORK=/tmp/p7compress
C_BUILD=/mnt/c/Git/temp/wt-bench/build/linux-release
GO_BIN=/tmp/p7compress/bin
ROUNDS=7
SIZE_MB=8
LEGS="c-plain,c-deflate,c-lz4,c-zstd,go-auto,c-zstd-go"
# the fork server serves the account of its own user (a non-root server
# refuses the others), so the bench user is the running one
BENCH_USER=$(id -un)

while [ $# -gt 0 ]; do
    case "$1" in
    --c-build) C_BUILD="$2"; shift 2 ;;
    --go-bin) GO_BIN="$2"; shift 2 ;;
    --rounds) ROUNDS="$2"; shift 2 ;;
    --size) SIZE_MB="$2"; shift 2 ;;
    --work) WORK="$2"; shift 2 ;;
    --legs) LEGS="$2"; shift 2 ;;
    *) echo "p7-compress: unknown flag: $1" >&2; exit 2 ;;
    esac
done

C_CLIENT=$C_BUILD/ssh3
C_SERVER=$C_BUILD/ssh3-server
GO_CLIENT=$GO_BIN/ssh3
GO_SERVER=$GO_BIN/ssh3-server

log() { echo "[p7-compress $(date +%H:%M:%S)] $*"; }
die() { echo "p7-compress: $*" >&2; exit 1; }

for f in "$C_CLIENT" "$C_SERVER"; do
    [ -x "$f" ] || die "the binary is missing: $f"
done

LOGS=$WORK/logs
RES=$WORK/results
DEV_SHM=/dev/shm
mkdir -p "$LOGS" "$RES" "$DEV_SHM/p7compress"

# --- the stand ---------------------------------------------------------------

setup_stand() {
    cd "$WORK"

    # one ed25519 keypair: the PKCS8 PEM for the JWT clients of both QUIC
    # implementations, the authorized_keys line built by hand (the C daemon
    # takes -K, the Go server reads ~/.ssh3/authorized_identities)
    if [ ! -f bench_pkcs8.pem ]; then
        openssl genpkey -algorithm ed25519 -out bench_pkcs8.pem 2>/dev/null
        chmod 600 bench_pkcs8.pem
        {
            printf '\000\000\000\013ssh-ed25519\000\000\000\040'
            openssl pkey -in bench_pkcs8.pem -pubout -outform DER 2>/dev/null | tail -c 32
        } | base64 | tr -d '\n' > bench_blob.pub
        printf 'ssh-ed25519 %s p7compress\n' "$(cat bench_blob.pub)" > authorized_keys
    fi

    # the QUIC servers share one self-signed P-256 certificate
    if [ ! -f cert.pem ]; then
        openssl req -x509 -sha256 -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
            -keyout key.pem -days 30 -out cert.pem -subj /CN=127.0.0.1 \
            -addext "subjectAltName=IP:127.0.0.1" 2>/dev/null
    fi

    # the fresh home of the C client: the pin of the daemon certificate
    rm -rf "$WORK/home"
    mkdir -p "$WORK/home/.ssh3"

    # the fork server reads ~/.ssh3/authorized_identities first (the real
    # ~/.ssh/authorized_keys stays untouched); its sftp paths are HOME
    # relative only, the symlink points them into tmpfs
    mkdir -p "$HOME/.ssh3"
    cp -f "$WORK/authorized_keys" "$HOME/.ssh3/authorized_identities"
    ln -sfn "$DEV_SHM/p7compress" "$HOME/p7compress"

    # the payloads: a compressible body (the repeated log lines) and an
    # incompressible one (the random bytes: the cutoff must not lose there)
    if [ ! -f "$DEV_SHM/p7compress/text.bin" ]; then
        python3 - "$DEV_SHM/p7compress/text.bin" "$SIZE_MB" <<'EOF'
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
    if [ ! -f "$DEV_SHM/p7compress/rand.bin" ]; then
        dd if=/dev/urandom of="$DEV_SHM/p7compress/rand.bin" bs=1M count="$SIZE_MB" status=none
    fi
}

PORT_C=0
PORT_GO=0

start_c_server() {
    local log_tag="$1" port=$2
    # the sftp budget (S2-02) is off: the bench opens dozens of sftp
    # sessions in minutes and the concurrent-16 cap would refuse the
    # legs of the later rounds
    SSH3_LOG_FILE="$LOGS/c-server$log_tag.log" nohup "$C_SERVER" \
        -3 -l "127.0.0.1:$port" -c "$WORK/cert.pem" -k "$WORK/key.pem" \
        -K "$WORK/authorized_keys" --max-sftp-sessions-per-user 0 \
        > "$LOGS/c-server$log_tag.out" 2>&1 < /dev/null &
    echo $! > "$WORK/c-server.pid"
    sleep 0.3
    [ -d "/proc/$(cat "$WORK/c-server.pid")" ] || die "the C server died at startup"
}

start_go_server() {
    local port=$1
    if [ ! -x "$GO_SERVER" ]; then
        log "the fork server is absent: $GO_SERVER (the go legs are skipped)"
        return 1
    fi
    SSH3_LOG_FILE="$LOGS/go-server.log" nohup "$GO_SERVER" \
        -bind "127.0.0.1:$port" -cert "$WORK/cert.pem" -key "$WORK/key.pem" \
        -url-path /ssh3-term > "$LOGS/go-server.out" 2>&1 < /dev/null &
    echo $! > "$WORK/go-server.pid"
    sleep 0.3
    [ -d "/proc/$(cat "$WORK/go-server.pid")" ] || die "the fork server died at startup"
    return 0
}

stop_servers() {
    local pidfile pid
    for pidfile in "$WORK/c-server.pid" "$WORK/go-server.pid"; do
        [ -f "$pidfile" ] || continue
        pid=$(cat "$pidfile")
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
}

# the pin of the daemon certificate (the label is the host key of the
# client: host:port/path); the non-pty runs skip the TOFU question.
# BOTH servers are pinned: the cross leg (the C client -> the fork
# server) aborts on a missing pin for the fork's port
pin_cert() {
    local port="$1"
    printf '127.0.0.1:%s/ssh3-term x509-certificate %s\n' "$port" \
        "$(openssl x509 -in "$WORK/cert.pem" -outform DER | base64 -w0)" \
        >> "$WORK/home/.ssh3/known_hosts"
}

# a dead server is restarted before the round: the run must not lose the
# remaining rounds to one died daemon (the cause is logged, the run goes on)
ensure_servers() {
    local round="$1"
    if [ ! -d "/proc/$(cat "$WORK/c-server.pid" 2>/dev/null)" ]; then
        log "round $round: the C server is gone, restarting it"
        PORT_C=$((PORT_C + 1))
        start_c_server "-r$round" "$PORT_C"
        : > "$WORK/home/.ssh3/known_hosts"
        pin_cert "$PORT_C"
        pin_cert "$PORT_GO"
    fi
    if [ "$GO_UP" -eq 1 ] && [ ! -d "/proc/$(cat "$WORK/go-server.pid" 2>/dev/null)" ]; then
        log "round $round: the fork server is gone, restarting it"
        PORT_GO=$((PORT_GO + 1))
        start_go_server "$PORT_GO" || { GO_UP=0; return 0; }
        : > "$WORK/home/.ssh3/known_hosts"
        pin_cert "$PORT_C"
        pin_cert "$PORT_GO"
    fi
}

# --- the capture ------------------------------------------------------------

# the sum of the UDP payload lengths of the capture: the wire number of the
# leg (the QUIC overhead is not counted: the payload of the UDP datagram is
# the QUIC packet, which is what the peer receives)
pcap_bytes() {
    local pcap="$1"
    [ -s "$pcap" ] || { echo "0 0"; return 0; }
    sudo -n tcpdump -r "$pcap" -n -q 2>/dev/null |
        awk '/ UDP,? / { for (i = 1; i <= NF; i++) if ($i == "length") { s += $(i + 1); n++ } }
             END { printf "%d %d\n", s + 0, n + 0 }'
}

# the capture needs the root (the packet socket on lo); the file belongs to
# tcpdump afterwards, so the cleanup of the round runs through sudo too.
# --immediate-mode is mandatory: without it libpcap batches the packets in
# the kernel ring and delivers them by timeout, so a transfer that ends in
# tens of milliseconds is discarded outright when the SIGINT arrives
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

# --- the legs ----------------------------------------------------------------

# $1 = leg, $2 = payload, $3 = remote path; the client of the leg is the
# C client or the fork client, the codec of the C client rides attached to
# the option (the attached form works with an optional and with a required
# option argument alike)
#
# the legs:
#   c-plain, c-deflate, c-lz4, c-zstd  the C client -> the C daemon
#   go-auto                           the fork client -> the fork server
#   c-zstd-go                         the C client -> the fork server
leg_client() {
    case "$1" in
    go-auto) echo go ;;
    c-plain|c-deflate|c-lz4|c-zstd|c-zstd-go) echo c ;;
    *) die "unknown leg: $1" ;;
    esac
}

leg_target_port() {
    case "$1" in
    c-plain|c-deflate|c-lz4|c-zstd) echo "$PORT_C" ;;
    go-auto|c-zstd-go) echo "$PORT_GO" ;;
    esac
}

leg_codec() {
    case "$1" in
    c-zstd-go) echo zstd ;;
    c-deflate|c-lz4|c-zstd) echo "${1#c-}" ;;
    *) echo "" ;;
    esac
}

# the path of the landed file: the fork client takes the HOME-relative path
# of its server (the symlink points it into tmpfs), the C client takes the
# path of the jail of the daemon
leg_spec() {
    local leg="$1" name="$2"
    case "$leg" in
    go-auto) echo "p7compress/$name" ;;
    c-zstd-go) echo "$name" ;;
    *) echo "/$name" ;;
    esac
}

run_leg() {
    local leg="$1" payload="$2" remote="$3"
    local client port codec spec

    client=$(leg_client "$leg")
    port=$(leg_target_port "$leg")
    codec=$(leg_codec "$leg")
    spec=$(leg_spec "$leg" "${remote#/}")

    case "$client" in
    c)
        if [ -n "$codec" ]; then
            HOME="$WORK/home" timeout -k 5 120 "$C_CLIENT" "-C$codec" -i "$WORK/bench_pkcs8.pem" \
                --sftp "put:$payload:$remote" "client@127.0.0.1:$port/ssh3-term" \
                > "$LOGS/leg.out" 2>"$LOGS/leg.err"
        else
            HOME="$WORK/home" timeout -k 5 120 "$C_CLIENT" -i "$WORK/bench_pkcs8.pem" \
                --sftp "put:$payload:$remote" "client@127.0.0.1:$port/ssh3-term" \
                > "$LOGS/leg.out" 2>"$LOGS/leg.err"
        fi
        ;;
    go)
        go_xfer "$port" put "$payload" "$spec" ""
        ;;
    esac
}

# the transfer of the fork client: -transfer SRC DST (exactly one operand
# in the user@host:remote_path form, uploads towards it); the sftp paths
# of the fork are HOME-relative, the symlink points them into tmpfs
go_xfer() { # $1 = port, $2 = put|pull, $3 = local, $4 = spec, $5 = local out (pull)
    local port="$1" dir="$2" local_path="$3" spec="$4" out="$5"

    if [ "$dir" = put ]; then
        timeout -k 5 120 "$GO_CLIENT" -transfer -insecure -strict-host-key-checking no \
            -privkey "$WORK/bench_pkcs8.pem" -p "$port" "$local_path" \
            "${BENCH_USER}@127.0.0.1:$spec" \
            < /dev/null > "$LOGS/leg.out" 2>"$LOGS/leg.err"
    else
        timeout -k 5 120 "$GO_CLIENT" -transfer -insecure -strict-host-key-checking no \
            -privkey "$WORK/bench_pkcs8.pem" -p "$port" \
            "${BENCH_USER}@127.0.0.1:$spec" "$out" \
            < /dev/null > /dev/null 2>"$LOGS/pull.err"
    fi
}

# the pull of the landed file and the sha gate: the transfer counts only
# when the bytes come back identical
verify_leg() {
    local leg="$1" payload="$2" remote="$3" out="$4" spec="$5"
    local client port

    client=$(leg_client "$leg")
    port=$(leg_target_port "$leg")

    case "$client" in
    go)
        go_xfer "$port" pull "" "$spec" "$out" || return 1
        ;;
    c)
        HOME="$WORK/home" timeout -k 5 120 "$C_CLIENT" -i "$WORK/bench_pkcs8.pem" \
            --sftp "get:$out:$remote" "client@127.0.0.1:$port/ssh3-term" \
            > /dev/null 2>"$LOGS/pull.err" || return 1
        ;;
    esac
    cmp -s "$payload" "$out"
}

# --- the run ------------------------------------------------------------------

setup_stand

# the ports: the C daemon scans up from a base (the busy port is skipped),
# the fork server takes a fixed port
PORT_C=$((48000 + ($$ % 100)))
PORT_GO=$((48100 + ($$ % 100)))

start_c_server "" "$PORT_C"

GO_UP=0
if [ -x "$GO_SERVER" ]; then
    start_go_server "$PORT_GO" && GO_UP=1 || true
fi

: > "$WORK/home/.ssh3/known_hosts"
pin_cert "$PORT_C"
if [ "$GO_UP" -eq 1 ]; then
    pin_cert "$PORT_GO"
fi

trap 'stop_servers' EXIT INT TERM

CSV=$RES/compress.csv
echo "leg,payload,round,wire_bytes,packets,app_plain,app_packed,sha_ok" > "$CSV"

PAYLOADS="text rand"

for round in $(seq 1 "$ROUNDS"); do
    ensure_servers "$round"
    for leg in $(echo "$LEGS" | tr ',' ' '); do
        for pl in $PAYLOADS; do
            payload=$DEV_SHM/p7compress/$pl.bin
            remote=/p7compress-$pl-$leg.bin
            out=$DEV_SHM/p7compress/back-$pl-$leg.bin
            rm -f "$out"

            pcap=$WORK/cap-$leg-$pl-$round.pcap
            capture_start "$pcap"

            rc=0
            run_leg "$leg" "$payload" "$remote" || rc=$?

            capture_stop "$pcap"

            if [ "$rc" -ne 0 ]; then
                log "round $round: the leg $leg ($pl) failed: rc=$rc"
                echo "$leg,$pl,$round,0,0,0,0,no" >> "$CSV"
                continue
            fi

            # the application number: the report of the client (the plain
            # bytes and the bytes of the compressed frames)
            app_plain=0
            app_packed=0
            if grep -q "the compression of the channel body:" "$LOGS/leg.err" 2>/dev/null; then
                report=$(grep "the compression of the channel body:" "$LOGS/leg.err" | head -1)
                app_plain=$(echo "$report" | sed -E 's/.*: ([0-9]+) frames, ([0-9]+) bytes -> ([0-9]+) bytes.*/\2/')
                app_packed=$(echo "$report" | sed -E 's/.*: ([0-9]+) frames, ([0-9]+) bytes -> ([0-9]+) bytes.*/\3/')
            fi

            # the gate: the bytes come back identical
            sha_ok=no
            if verify_leg "$leg" "$payload" "$remote" "$out" "$(leg_spec "$leg" "${remote#/}")"; then
                sha_ok=yes
            fi

            read -r wire packets <<<"$(pcap_bytes "$pcap")"
            echo "$leg,$pl,$round,$wire,$packets,$app_plain,$app_packed,$sha_ok" >> "$CSV"
            log "round $round: $leg ($pl): wire=$wire pkts=$packets plain=$app_plain packed=$app_packed sha=$sha_ok"
            : # keep for debug
        done
    done
done

echo
echo "== the medians (the warmup round is discarded)"

awk -F, '
    NR == 1 { next }
    {
        leg = $1; pl = $2; r = $3
        if (r == 1) next
        if ($8 != "yes") { bad[leg" "pl]++; next }
        key = leg" "pl
        n[key]++
        v[key, n[key]] = $4 + 0
    }
    END {
        printf "%-12s %-6s %12s %8s %6s\n", "leg", "payload", "wire_med", "rounds", "bad"
        for (k in n) {
            # the median of the leg (the values are few: the insertion sort
            # is enough and keeps the script free of gawk-only builtins)
            for (i = 1; i <= n[k]; i++) {
                val = v[k, i]
                j = i - 1
                while (j >= 1 && v[k, j] > val) { v[k, j + 1] = v[k, j]; j-- }
                v[k, j + 1] = val
            }
            med = (n[k] % 2) ? v[k, int(n[k] / 2) + 1] : int((v[k, n[k] / 2] + v[k, n[k] / 2 + 1]) / 2)
            split(k, a, " ")
            printf "%-12s %-6s %12d %8d %6d\n", a[1], a[2], med, n[k], bad[k] + 0
        }
    }
' "$CSV" | sort

echo
echo "the raw rows: $CSV"
