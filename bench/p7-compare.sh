#!/usr/bin/env bash
# P7 control bench: ssh3-c vs Go fork vs OpenSSH on one loopback stand (R3 metrics).
#
#   p7-compare.sh [--stage all|throughput|handshake|mux|cpu|manyfiles] [--rounds 7]
#                 [--handshake-runs 30] [--mux-iters 100] [--mux-blocks 3]
#                 [--files N] [--work /tmp/p7bench] [--c-build DIR] [--go-bin DIR]
#
# Stages (CSV rows land in $WORK/results/, logs in $WORK/logs/):
#   throughput: bulk transfers, sha256-verified, round-robin over the impls,
#               the first round is the warmup and is discarded.  The 512 MiB
#               table runs OpenSSH scp vs the Go sftp subsystem; the 8 MiB
#               table adds ssh3-c (-J): the C sftp path pumps on 50 ms
#               timers (the harness client and the daemon drain), 512 MiB is
#               a tens-of-minutes affair by design, see docs/BENCH-P7-*.md.
#   handshake:  cold exec round-robin, --handshake-runs measured runs each.
#   mux:        ControlMaster spawn + --mux-iters warm execs per impl,
#               --mux-blocks interleaved blocks.  The C master cannot
#               authenticate (its -U slot carries the socket path), the C
#               daemon restarts in the open mode for this stage (any
#               non-empty Authorization passes, see app/ssh3_server.c).
#   cpu:        /proc/<pid>/stat USER_HZ deltas + VmRSS peak sampled at
#               50 ms during one dedicated verified push per impl
#               (OpenSSH: the whole sshd process tree of the bench instance).
#
# The stand: ssh3-c daemon :8022/udp (JWT pubkey -K), Go fork server
# :8023/udp (JWT pubkey), sshd :2222/tcp (ed25519, a dedicated instance on a
# private host key and AuthorizedKeysFile, nothing in ~/.ssh is touched).
# One ed25519 keypair signs everywhere: PKCS8 PEM for the JWT clients, the
# OpenSSH format for ssh/scp.  Payloads and outputs live on tmpfs (/dev/shm).
set -euo pipefail

WORK=/tmp/p7bench
C_BUILD=/mnt/c/Git/temp/wt-bench/build/linux-release
GO_BIN=/tmp/p7bench/bin
STAGE=all ROUNDS=7 HS_RUNS=30 MUX_ITERS=100 MUX_BLOCKS=3
PORT_C=8022 PORT_GO=8023 PORT_SSH=2222
SIZE_BIG=512 SIZE_SMALL=8 FILES_N=2000

while [ $# -gt 0 ]; do
    case "$1" in
    --stage) STAGE="$2"; shift 2 ;;
    --rounds) ROUNDS="$2"; shift 2 ;;
    --handshake-runs) HS_RUNS="$2"; shift 2 ;;
    --mux-iters) MUX_ITERS="$2"; shift 2 ;;
    --mux-blocks) MUX_BLOCKS="$2"; shift 2 ;;
    --files) FILES_N="$2"; shift 2 ;;
    --work) WORK="$2"; shift 2 ;;
    --c-build) C_BUILD="$2"; shift 2 ;;
    --go-bin) GO_BIN="$2"; shift 2 ;;
    *) echo "p7-compare: unknown flag: $1" >&2; exit 1 ;;
    esac
done

LOGS=$WORK/logs RES=$WORK/results
SRC_C_CLIENT=$C_BUILD/s3interop_client
SRC_C_SERVER=$C_BUILD/ssh3-server
SRC_GO_CLIENT=$GO_BIN/ssh3
SRC_GO_SERVER=$GO_BIN/ssh3-server
# the servers run under neutral names: pkill sweeps of parallel build agents
# match the stock binary names (ssh3-server, s3interop_*) and would kill the
# stand mid-run, the copies under $WORK/bin are invisible to those patterns
C_CLIENT=$WORK/bin/p7c-client
C_SERVER=$WORK/bin/p7c-server
GO_CLIENT=$WORK/bin/p7go-client
GO_SERVER=$WORK/bin/p7go-server
CIPHER=aes128-gcm@openssh.com
DEV_SHM=/dev/shm

mkdir -p "$LOGS" "$RES" "$DEV_SHM/p7out"

log() { echo "[p7] $*" >&2; }
die() { echo "p7-compare: ERROR: $*" >&2; exit 1; }

for f in "$SRC_C_CLIENT" "$SRC_C_SERVER" "$SRC_GO_CLIENT" "$SRC_GO_SERVER" /usr/sbin/sshd; do
    [ -x "$f" ] || die "missing binary: $f"
done
command -v scp >/dev/null || die "scp not found"

# --- the stand artifacts (keys, certs, payloads), idempotent -----------------

gen_payload() { # $1 = MiB, $2 = path; an existing file of the right size stays
    local mb="$1" path="$2"
    if [ -f "$path" ] && [ "$(stat -c%s "$path")" -eq "$((mb * 1024 * 1024))" ]; then
        return 0
    fi
    dd if=/dev/urandom of="$path" bs=1M count="$mb" status=none
    chmod 644 "$path"
}

sha_of() { sha256sum "$1" | awk '{print $1}'; }

gen_manyfiles() { # the many-small-files tree: FILES_N x 4096 B under $DEV_SHM/many-src
    local src="$DEV_SHM/many-src/files" i
    if [ -d "$src" ] && [ "$(find "$src" -type f 2>/dev/null | wc -l)" -eq "$FILES_N" ]; then
        return 0
    fi
    rm -rf "$DEV_SHM/many-src"
    mkdir -p "$src"
    dd if=/dev/urandom of="$DEV_SHM/many-src/.tpl" bs=4096 count=1 status=none
    for i in $(seq 1 "$FILES_N"); do
        cp "$DEV_SHM/many-src/.tpl" "$src/f$(printf %05d "$i").bin"
    done
    rm -f "$DEV_SHM/many-src/.tpl"
    log "manyfiles: generated $FILES_N files ($(du -sh "$DEV_SHM/many-src" | cut -f1))"
}

setup_stand() {
    cd "$WORK"

    # the neutral binary copies of the stand (see the block comment above)
    mkdir -p "$WORK/bin"
    cp -f "$SRC_C_CLIENT" "$C_CLIENT"
    cp -f "$SRC_C_SERVER" "$C_SERVER"
    cp -f "$SRC_GO_CLIENT" "$GO_CLIENT"
    cp -f "$SRC_GO_SERVER" "$GO_SERVER"

    # one ed25519 keypair in two formats: PKCS8 PEM (the JWT clients) and
    # the OpenSSH format (ssh/scp); openssl generates, python converts
    if [ ! -f bench_pkcs8.pem ] || [ ! -f bench_ed25519 ]; then
        openssl genpkey -algorithm ed25519 -out bench_pkcs8.pem 2>/dev/null
        chmod 600 bench_pkcs8.pem
        python3 - <<'EOF'
from cryptography.hazmat.primitives.serialization import (load_pem_private_key,
    Encoding, PrivateFormat, NoEncryption)
key = load_pem_private_key(open("bench_pkcs8.pem", "rb").read(), password=None)
open("bench_ed25519", "wb").write(
    key.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()))
EOF
        chmod 600 bench_ed25519
        rm -f bench_ed25519.pub
        ssh-keygen -y -f bench_ed25519 > bench_ed25519.pub
    fi
    cp -f bench_ed25519.pub authorized_keys

    # the QUIC servers share one self-signed P-256 certificate
    if [ ! -f cert.pem ]; then
        openssl req -x509 -sha256 -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
            -keyout key.pem -days 30 -out cert.pem -subj /CN=127.0.0.1 \
            -addext "subjectAltName=IP:127.0.0.1" 2>/dev/null
    fi

    # the dedicated sshd host key
    if [ ! -f host_ed25519 ]; then
        ssh-keygen -t ed25519 -f host_ed25519 -N "" -C p7host -q
    fi

    # the Go server reads ~/.ssh3/authorized_identities first (the real
    # ~/.ssh/authorized_keys stays untouched); the sftp paths of the fork
    # are HOME-relative only, a symlink points them into tmpfs
    mkdir -p "$HOME/.ssh3"
    cp -f bench_ed25519.pub "$HOME/.ssh3/authorized_identities"
    ln -sfn "$DEV_SHM" "$HOME/p7shm"

    gen_payload "$SIZE_BIG" "$DEV_SHM/p7bench.bin"
    gen_payload "$SIZE_SMALL" "$DEV_SHM/p7bench8.bin"
    gen_manyfiles
    : > "$WORK/known_hosts"
}

# --- the servers -------------------------------------------------------------

start_c_server() { # $1 = extra flags (auth mode: "-K authorized_keys"), $2 = log tag
    # plain nohup &: $! must be the server pid itself, setsid forks and the
    # pidfile would hold the dead wrapper pid (the cleanup then misses)
    SSH3_LOG_FILE="$LOGS/c-server$2.log" nohup "$C_SERVER" \
        -l "127.0.0.1:$PORT_C" -c "$WORK/cert.pem" -k "$WORK/key.pem" \
        -H "$DEV_SHM" $1 > "$LOGS/c-server$2.out" 2>&1 < /dev/null &
    echo $! > "$WORK/c-server.pid"
    sleep 0.2
    [ -d "/proc/$(cat "$WORK/c-server.pid")" ] || die "c server died at startup (bind busy?)"
}

start_go_server() {
    SSH3_LOG_FILE="$LOGS/go-server.log" nohup "$GO_SERVER" \
        -bind "127.0.0.1:$PORT_GO" -cert "$WORK/cert.pem" -key "$WORK/key.pem" \
        -url-path /ssh3-term > "$LOGS/go-server.out" 2>&1 < /dev/null &
    echo $! > "$WORK/go-server.pid"
    sleep 0.2
    [ -d "/proc/$(cat "$WORK/go-server.pid")" ] || die "go server died at startup (bind busy?)"
}

start_sshd() {
    sudo -n /usr/sbin/sshd -p "$PORT_SSH" -h "$WORK/host_ed25519" \
        -o "AuthorizedKeysFile=$WORK/authorized_keys" -o StrictModes=no \
        -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no \
        -o UsePAM=no -o ListenAddress=127.0.0.1 \
        -o "PidFile=$WORK/sshd.pid" -o LogLevel=ERROR
    sleep 0.3
    [ -f "$WORK/sshd.pid" ] || die "sshd did not start"
}

stop_servers() {
    local pidfile pid
    for pidfile in "$WORK/c-server.pid" "$WORK/go-server.pid" "$WORK/sshd.pid"; do
        if [ -f "$pidfile" ]; then
            pid=$(cat "$pidfile")
            if [ "$pidfile" = "$WORK/sshd.pid" ]; then
                sudo -n kill "$pid" 2>/dev/null || true
            else
                kill "$pid" 2>/dev/null || true
            fi
            # the graceful drain keeps the udp port up to
            # SSH3_SHUTDOWN_DRAIN (5 s default): the next stage's bind
            # races the dying daemon without the wait (wait_gone
            # escalates to kill -9 at the deadline)
            wait_gone "$pid" 8 || {
                kill -9 "$pid" 2>/dev/null || true
                sleep 0.5
            }
            rm -f "$pidfile"
        fi
    done
    # the home artifacts of the stand (created by setup_stand)
    rm -f "$HOME/.ssh3/authorized_identities"
    rmdir "$HOME/.ssh3" 2>/dev/null || true
    rm -f "$HOME/p7shm"
}

# readiness probes: QUIC has no connect to wait for, exec until it answers
probe() { # $1 = impl
    local i
    for i in $(seq 1 40); do
        case "$1" in
        c) "$C_CLIENT" -a "127.0.0.1:$PORT_C" -3 -C -S exec \
               -K "$WORK/bench_pkcs8.pem" -U user -t 10000 \
               > /dev/null 2>&1 && return 0 ;;
        go) "$GO_CLIENT" -insecure -privkey "$WORK/bench_pkcs8.pem" \
                "user@127.0.0.1:$PORT_GO/ssh3-term" true \
                < /dev/null > /dev/null 2>&1 && return 0 ;;
        os) ssh -p "$PORT_SSH" -i "$WORK/bench_ed25519" -o BatchMode=yes \
                -o StrictHostKeyChecking=no -o "UserKnownHostsFile=$WORK/known_hosts" \
                -o IdentitiesOnly=yes user@127.0.0.1 true \
                < /dev/null > /dev/null 2>&1 && return 0 ;;
        esac
        sleep 0.25
    done
    die "impl $1 never became ready"
}

# --- the client operations ---------------------------------------------------

# liveness gate before every round: a server killed externally would poison
# the rest of the csv with timeout rows.  /proc, not kill -0: the sshd of the
# stand runs as root and kill -0 from the user id answers EPERM
assert_alive() {
    local pidfile pid
    for pidfile in c-server go-server sshd; do
        pid=""
        [ -f "$WORK/$pidfile.pid" ] && pid=$(cat "$WORK/$pidfile.pid")
        if [ -z "$pid" ] || [ ! -d "/proc/$pid" ]; then
            die "$pidfile died mid-run (killed externally?), rerun the stage"
        fi
    done
}

c_exec() { # cold exec, the verdict marker rides (printf s3-exec-ok)
    "$C_CLIENT" -a "127.0.0.1:$PORT_C" -3 -C -S exec \
        -K "$WORK/bench_pkcs8.pem" -U user -t 10000 > /dev/null 2>&1
}

go_exec() {
    "$GO_CLIENT" -insecure -privkey "$WORK/bench_pkcs8.pem" \
        "user@127.0.0.1:$PORT_GO/ssh3-term" true \
        < /dev/null > /dev/null 2>"$LOGS/go-client.log"
}

os_exec() {
    ssh -p "$PORT_SSH" -i "$WORK/bench_ed25519" -c "$CIPHER" -o BatchMode=yes \
        -o StrictHostKeyChecking=no -o "UserKnownHostsFile=$WORK/known_hosts" \
        -o IdentitiesOnly=yes user@127.0.0.1 true < /dev/null > /dev/null 2>&1
}

# bulk transfer: $1 = impl, $2 = payload path, $3 = push|pull, $4 = out path
xfer() {
    case "$1:$3" in
    os:push)
        scp -q -P "$PORT_SSH" -i "$WORK/bench_ed25519" -c "$CIPHER" -o BatchMode=yes \
            -o StrictHostKeyChecking=no -o "UserKnownHostsFile=$WORK/known_hosts" \
            -o IdentitiesOnly=yes "$2" "user@127.0.0.1:$4"
        ;;
    os:pull)
        scp -q -P "$PORT_SSH" -i "$WORK/bench_ed25519" -c "$CIPHER" -o BatchMode=yes \
            -o StrictHostKeyChecking=no -o "UserKnownHostsFile=$WORK/known_hosts" \
            -o IdentitiesOnly=yes "user@127.0.0.1:$2" "$4"
        ;;
    go:push)
        # the fork sftp paths are HOME-relative only, p7shm -> /dev/shm
        "$GO_CLIENT" -insecure -privkey "$WORK/bench_pkcs8.pem" -f "$2" \
            "user@127.0.0.1:$PORT_GO/ssh3-term:p7shm/${4#$DEV_SHM/}" \
            < /dev/null > /dev/null 2>"$LOGS/go-client.log"
        ;;
    go:pull)
        "$GO_CLIENT" -insecure -privkey "$WORK/bench_pkcs8.pem" -f \
            "user@127.0.0.1:$PORT_GO/ssh3-term:p7shm/${2#$DEV_SHM/}" "$4" \
            < /dev/null > /dev/null 2>"$LOGS/go-client.log"
        ;;
    c:push)
        "$C_CLIENT" -a "127.0.0.1:$PORT_C" -3 -K "$WORK/bench_pkcs8.pem" -U user \
            -J "put:$2:${4#$DEV_SHM/}" -t "$C_TIMEOUT" > /dev/null 2>&1
        ;;
    c:pull)
        "$C_CLIENT" -a "127.0.0.1:$PORT_C" -3 -K "$WORK/bench_pkcs8.pem" -U user \
            -J "get:$4:${2#$DEV_SHM/}" -t "$C_TIMEOUT" > /dev/null 2>&1
        ;;
    *) die "xfer: bad combination $1:$3" ;;
    esac
}

# the C sftp transfer with early landing detection: the put verdict never
# completes and the attempt would burn the whole deadline, so the client
# runs in the background and the poll watches the target file until every
# payload byte is there (sequential pwrites, size == payload size means the
# content is final); the client is killed then, the caller times the landing
c_xfer_timed() { # $1 = payload, $2 = push|pull, $3 = out; echoes landing ns
    local want t0 t1 land="" outfile="$3"
    want=$(stat -c%s "$1")
    t0=$(date +%s%N)
    case "$2" in
    push) "$C_CLIENT" -a "127.0.0.1:$PORT_C" -3 -K "$WORK/bench_pkcs8.pem" -U user \
              -J "put:$1:${3#$DEV_SHM/}" -t "$C_TIMEOUT" > /dev/null 2>&1 & ;;
    pull) "$C_CLIENT" -a "127.0.0.1:$PORT_C" -3 -K "$WORK/bench_pkcs8.pem" -U user \
              -J "get:$3:${1#$DEV_SHM/}" -t "$C_TIMEOUT" > /dev/null 2>&1 & ;;
    esac
    local cpid=$!
    while kill -0 "$cpid" 2>/dev/null; do
        if [ -f "$outfile" ] &&
           [ "$(stat -c%s "$outfile" 2>/dev/null || echo 0)" -ge "$want" ]; then
            land=$(date +%s%N)
            break
        fi
        sleep 0.5
    done
    kill "$cpid" 2>/dev/null || true
    wait "$cpid" 2>/dev/null || true
    [ -n "$land" ] || { echo "$(( $(date +%s%N) - t0 ))"; return 1; }
    echo "$(( land - t0 ))"
}

# one timed transfer with sha verification: $1..$4 as xfer, $5 = ref sha,
# $6 = csv, $7 = warmup flag, RUN_NO = round; appends impl,dir,run,sec,mbps.
# The sha of the landed file is the ground truth: the C put transfers the
# payload byte-exact but its verdict path never completes (the client waits
# for a channel confirmation that does not arrive), the rc alone would
# discard valid transfers — sha-verified rows with a non-zero rc stay, the
# log line keeps the distinction
run_xfer() {
    local impl="$1" payload="$2" dir="$3" out="$4" ref="$5" csv="$6" warm="$7"
    local t0 t1 ns rc=0 ok=0 sec mbps
    rm -f "$out"
    if [ "$impl" = c ]; then
        ns=$(c_xfer_timed "$payload" "$dir" "$out") || rc=1
    else
        t0=$(date +%s%N)
        xfer "$impl" "$payload" "$dir" "$out" || rc=1
        t1=$(date +%s%N)
        ns=$((t1 - t0))
    fi
    if [ -f "$out" ] && [ "$(sha_of "$out")" = "$ref" ]; then
        ok=1
        [ "$rc" = 0 ] || log "$impl $dir: rc=$rc but sha-verified, counted"
    fi
    if [ "$ok" = 1 ]; then
        sec=$(awk -v ns="$ns" 'BEGIN{printf "%.3f", ns/1e9}')
        mbps=$(awk -v b="$(stat -c%s "$payload")" -v ns="$ns" \
            'BEGIN{printf "%.2f", b/1e6/(ns/1e9)}')
    else
        sec=""
        mbps=""
        log "$impl $dir transfer failed (warmup=$warm), discarded"
    fi
    rm -f "$out"
    [ "$warm" = 1 ] && return 0
    echo "$impl,$dir,$RUN_NO,$sec,$mbps" >> "$csv"
}

# --- stages ------------------------------------------------------------------

stage_throughput() { # $1 = MiB, $2 = impl list, $3 = csv tag
    local mb="$1" impls="$2" tag="$3"
    local csv="$RES/throughput-$tag.csv"
    local payload ref impl dir round out
    [ "$mb" = "$SIZE_SMALL" ] && payload="$DEV_SHM/p7bench8.bin" || payload="$DEV_SHM/p7bench.bin"
    ref=$(sha_of "$payload")
    echo "impl,dir,run,sec,mbps" > "$csv"
    # the C sftp deadline cap: the post-P7.1 pipeline completes the put
    # verdict at 56-137 MB/s, the cap only guards a hung attempt
    C_TIMEOUT=60000
    log "throughput: ${mb} MiB, impls: $impls"
    for dir in push pull; do
        for round in $(seq 0 "$ROUNDS"); do
            assert_alive
            for impl in $impls; do
                case "$dir:$impl" in
                push:*) out="$DEV_SHM/p7out/out-$tag-$impl.bin" ;;
                pull:*) out="$DEV_SHM/p7out/in-$tag-$impl.bin" ;;
                esac
                RUN_NO=$round run_xfer "$impl" "$payload" "$dir" "$out" "$ref" "$csv" \
                    "$([ "$round" = 0 ] && echo 1 || echo 0)"
                sleep 0.2
            done
        done
    done
    log "throughput summary ($tag):"
    summary_throughput "$csv"
}

stage_handshake() {
    local csv="$RES/handshake.csv" round impl ms t0 t1 rc
    echo "impl,run,ms" > "$csv"
    log "handshake: $HS_RUNS rounds, impls: c go os"
    for round in $(seq 0 "$HS_RUNS"); do
        [ $((round % 10)) = 0 ] && assert_alive
        for impl in c go os; do
            t0=$(date +%s%N)
            case "$impl" in
            c) c_exec && rc=0 || rc=1 ;;
            go) go_exec && rc=0 || rc=1 ;;
            os) os_exec && rc=0 || rc=1 ;;
            esac
            t1=$(date +%s%N)
            ms=$(awk -v ns=$((t1 - t0)) 'BEGIN{printf "%.1f", ns/1e6}')
            [ "$rc" = 0 ] || log "handshake $impl round $round FAILED"
            [ "$round" = 0 ] && continue
            echo "$impl,$round,$ms" >> "$csv"
            sleep 0.05
        done
    done
    log "handshake summary:"
    summary_ms "$csv"
}

stage_mux() {
    local csv="$RES/mux.csv" blk it ms t0 t1 rc i
    local sock base
    echo "impl,blk,iter,ms" > "$csv"

    # the C cm master cannot authenticate (the -U slot carries the socket
    # path), the daemon restarts without -K: any non-empty Authorization
    # passes (the open mode of app/ssh3_server.c); the wait covers the
    # SIGTERM drain before the fresh bind
    oldpid=$(cat "$WORK/c-server.pid")
    kill "$oldpid" 2>/dev/null || true
    wait_gone "$oldpid" 8 || { kill -9 "$oldpid" 2>/dev/null || true; sleep 0.5; }
    start_c_server "" "-open"
    probe c

    log "mux: $MUX_BLOCKS x $MUX_ITERS warm execs, impls: c go os"
    for blk in $(seq 1 "$MUX_BLOCKS"); do
        for impl in c go os; do
            sock="$WORK/cm-$impl.sock"
            rm -f "$sock"
            case "$impl" in
            c)
                setsid nohup "$C_CLIENT" -3 -C -M -U "$sock" -a "127.0.0.1:$PORT_C" \
                    -t 600000 > "$LOGS/cm-c-master-$blk.log" 2>&1 < /dev/null &
                for i in $(seq 1 50); do
                    grep -q S3CM-MASTER-LISTEN "$LOGS/cm-c-master-$blk.log" 2>/dev/null && break
                    sleep 0.1
                done
                grep -q S3CM-MASTER-LISTEN "$LOGS/cm-c-master-$blk.log" ||
                    die "c master did not come up"
                for it in $(seq 1 "$MUX_ITERS"); do
                    t0=$(date +%s%N)
                    "$C_CLIENT" -U "$sock" -e true -t 10000 > /dev/null 2>&1 && rc=0 || rc=1
                    t1=$(date +%s%N)
                    ms=$(awk -v ns=$((t1 - t0)) 'BEGIN{printf "%.1f", ns/1e6}')
                    [ "$rc" = 0 ] || log "mux c $blk/$it FAILED"
                    echo "c,$blk,$it,$ms" >> "$csv"
                done
                "$C_CLIENT" -O stop -U "$sock" > /dev/null 2>&1 || true
                ;;
            go)
                base=(-insecure -privkey "$WORK/bench_pkcs8.pem"
                    -control-master yes -control-persist yes -control-path "$sock")
                "$GO_CLIENT" "${base[@]}" "user@127.0.0.1:$PORT_GO/ssh3-term" true \
                    < /dev/null > /dev/null 2>&1 || die "go master did not come up"
                for it in $(seq 1 "$MUX_ITERS"); do
                    t0=$(date +%s%N)
                    "$GO_CLIENT" "${base[@]}" "user@127.0.0.1:$PORT_GO/ssh3-term" true \
                        < /dev/null > /dev/null 2>&1 && rc=0 || rc=1
                    t1=$(date +%s%N)
                    ms=$(awk -v ns=$((t1 - t0)) 'BEGIN{printf "%.1f", ns/1e6}')
                    [ "$rc" = 0 ] || log "mux go $blk/$it FAILED"
                    echo "go,$blk,$it,$ms" >> "$csv"
                done
                "$GO_CLIENT" -O exit -control-path "$sock" dummy \
                    < /dev/null > /dev/null 2>&1 || true
                ;;
            os)
                ssh -p "$PORT_SSH" -i "$WORK/bench_ed25519" -o BatchMode=yes \
                    -o StrictHostKeyChecking=no -o "UserKnownHostsFile=$WORK/known_hosts" \
                    -o IdentitiesOnly=yes -o ControlMaster=auto -o ControlPath="$sock" \
                    -o ControlPersist=yes -fN user@127.0.0.1 < /dev/null 2> /dev/null
                for it in $(seq 1 "$MUX_ITERS"); do
                    t0=$(date +%s%N)
                    ssh -p "$PORT_SSH" -i "$WORK/bench_ed25519" -o BatchMode=yes \
                        -o "ControlPath=$sock" -o "UserKnownHostsFile=$WORK/known_hosts" \
                        -o IdentitiesOnly=yes user@127.0.0.1 true \
                        < /dev/null > /dev/null 2>&1 && rc=0 || rc=1
                    t1=$(date +%s%N)
                    ms=$(awk -v ns=$((t1 - t0)) 'BEGIN{printf "%.1f", ns/1e6}')
                    [ "$rc" = 0 ] || log "mux os $blk/$it FAILED"
                    echo "os,$blk,$it,$ms" >> "$csv"
                done
                ssh -O exit -o ControlPath="$sock" user@127.0.0.1 \
                    < /dev/null > /dev/null 2>&1 || true
                ;;
            esac
            sleep 0.5
        done
    done
    log "mux summary:"
    summary_ms "$csv"
}

# --- the cpu/ram sampler ------------------------------------------------------

CLK_TCK=$(getconf CLK_TCK)

tree_pids() { # $1 = root pid: the pid plus every descendant
    local p
    echo "$1"
    for p in $(pgrep -P "$1" 2>/dev/null); do
        tree_pids "$p"
    done
}

proc_load() { # $1 = pid; echoes "jiffies rsskb", "0 0" when gone
    local j r
    j=$(awk '{print $14 + $15}' "/proc/$1/stat" 2>/dev/null || echo 0)
    r=$(awk '/VmRSS/{print $2}' "/proc/$1/status" 2>/dev/null || echo 0)
    echo "${j:-0} ${r:-0}"
}

stage_cpu() {
    local csv="$RES/cpu.csv"
    echo "impl,sample,ts_ms,jiffies,rss_kb" > "$csv"
    log "cpu/ram: one dedicated verified push per impl"
    cpu_run c "$DEV_SHM/p7bench.bin" "sftp 512 MiB push"
    cpu_run go "$DEV_SHM/p7bench.bin" "sftp 512 MiB push"
    cpu_run os "$DEV_SHM/p7bench.bin" "scp 512 MiB push"
    log "cpu/ram summary:"
    summary_cpu "$csv"
}

cpu_run() { # $1 = impl, $2 = payload, $3 = note
    local impl="$1" payload="$2" note="$3"
    local spid marker out ref rc=0 samples n=0
    marker="$WORK/cpu-marker"
    samples="$WORK/cpu-samples-$impl"
    out="$DEV_SHM/p7out/cpu-$impl.bin"
    rm -f "$out" "$marker" "$samples"

    # the sampler walks the pid (or the sshd tree) every 50 ms until the marker
    (
        while [ ! -f "$marker" ]; do
            pids=""
            j=0
            r=0
            if [ "$impl" = os ]; then
                root=$(cat "$WORK/sshd.pid" 2>/dev/null || echo "")
                [ -n "$root" ] && pids=$(tree_pids "$root" 2>/dev/null)
            else
                case "$impl" in
                c) p=$(cat "$WORK/c-server.pid" 2>/dev/null || echo "") ;;
                go) p=$(cat "$WORK/go-server.pid" 2>/dev/null || echo "") ;;
                esac
                [ -n "${p:-}" ] && pids="$p"
            fi
            for p in $pids; do
                set -- $(proc_load "$p")
                j=$((j + $1))
                r=$((r + $2))
            done
            echo "$n,$(date +%s%3N),$j,$r" >> "$samples"
            sleep 0.05
            n=$((n + 1))
        done
    ) &
    spid=$!

    sleep 0.3
    case "$impl" in
    c)
        C_TIMEOUT=90000
        xfer c "$payload" push "$out" || rc=1
        ;;
    go)
        C_TIMEOUT=60000
        xfer go "$payload" push "$out" || rc=1
        ;;
    os)
        xfer os "$payload" push "$out" || rc=1
        ;;
    esac
    touch "$marker"
    wait "$spid" 2>/dev/null || true

    ref=$(sha_of "$payload")
    if [ "$rc" = 0 ] && [ -f "$out" ] && [ "$(sha_of "$out")" = "$ref" ]; then
        log "cpu/$impl: $note done (verified)"
        awk -v impl="$impl" -F, 'NR > 1 {print impl "," $0}' "$samples" >> "$csv"
    else
        log "cpu/$impl: $note FAILED, samples discarded"
    fi
    rm -f "$out" "$marker" "$samples"
}

# --- summaries (medians over the round-robin rounds) ---------------------------

summary_throughput() { # $1 = csv (impl,dir,run,sec,mbps)
    local impl dir vals
    for dir in push pull; do
        for impl in c go os; do
            vals=$(awk -F, -v i="$impl" -v d="$dir" \
                'NR > 1 && $1 == i && $2 == d && $5 != "" {print $5}' "$1" | sort -g)
            [ -n "$vals" ] || continue
            echo "$vals" | awk -v i="$impl" -v d="$dir" '
                {a[NR] = $1}
                END {
                    med = (NR % 2) ? a[(NR + 1) / 2] : (a[NR / 2] + a[NR / 2 + 1]) / 2
                    printf "  %-3s %-4s n=%d median=%.1f MB/s min=%.1f max=%.1f\n",
                        i, d, NR, med, a[1], a[NR]
                }'
        done
    done
}

summary_ms() { # $1 = csv (impl,...,ms)
    local impl vals
    for impl in c go os; do
        vals=$(awk -F, -v i="$impl" 'NR > 1 && $1 == i {print $NF}' "$1" | sort -g)
        [ -n "$vals" ] || continue
        echo "$vals" | awk -v i="$impl" '
            {a[NR] = $1}
            END {
                med = (NR % 2) ? a[(NR + 1) / 2] : (a[NR / 2] + a[NR / 2 + 1]) / 2
                printf "  %-3s n=%d median=%.1fms min=%.1f p95=%.1f max=%.1f\n",
                    i, NR, med, a[1], a[int(NR * 0.95 + 0.999)], a[NR]
            }'
    done
}

summary_cpu() { # $1 = csv (impl,sample,ts_ms,jiffies,rss_kb)
    local impl
    for impl in c go os; do
        grep -q "^$impl," "$1" || continue
        awk -F, -v i="$impl" -v hz="$CLK_TCK" '
            $1 == i {
                if (n == 0) { j0 = $4; t0 = $3 }
                n++
                # the end jiffies take the running maximum: the sshd session
                # child exits before the last sample and its ticks fold out
                # of the tree sum, the raw last row would read 0% cpu
                if ($4 > jmax) { jmax = $4; tmax = $3 }
                if ($5 > rssmax) rssmax = $5
            }
            END {
                if (n < 2) { printf "  %-3s insufficient samples\n", i; exit }
                printf "  %-3s cpu=%.1f%% rss_peak=%.0f MB (n=%d samples)\n",
                    i, (jmax - j0) / hz / ((tmax - t0) / 1000) * 100, rssmax / 1024, n
            }' "$1"
    done
}

# --- the many-small-files stage ------------------------------------------------

# the recursive directory transfer (scp -r / the fork -f -r / the
# harness -J -r): the per-file overhead of the protocol and the client
# driver, not the bulk stream.  the go remote paths stay HOME-relative
# (the fork -f rejects the absolute ones, the stand symlink ~/p7shm
# points into /dev/shm), the c remote paths are jail-relative (-H).
# the pull leg seeds the remote tree by the impl's own push OUTSIDE
# the clock, then measures the download only.
MANY_SRC="$DEV_SHM/many-src"

many_verify() { # $1 = destination dir: the count and the byte size must match
    [ "$(find "$1" -type f 2>/dev/null | wc -l)" -eq "$FILES_N" ] || return 1
    [ "$(du -sb "$1" 2>/dev/null | cut -f1)" -eq "$((FILES_N * 4096))" ] || return 1
}

many_cleanup() { # one attempt's remote tree and local pull dir
    rm -rf "$DEV_SHM/p7out/many-c" "$DEV_SHM/p7out/many-go" "$DEV_SHM/p7out/many-os"
    rm -rf "$WORK/many-c-pull" "$WORK/many-go-pull" "$WORK/many-os-pull"
}

many_push() { # $1 = impl: the measured push, verified, cleaned
    case "$1" in
    c)
        "$C_CLIENT" -a "127.0.0.1:$PORT_C" -3 -J "put:$MANY_SRC:p7out/many-c" -r \
            -K "$WORK/bench_pkcs8.pem" -U user -t 60000 > /dev/null 2>&1 || return 1
        many_verify "$DEV_SHM/p7out/many-c"
        ;;
    go)
        "$GO_CLIENT" -insecure -privkey "$WORK/bench_pkcs8.pem" \
            -f -r "$MANY_SRC" "user@127.0.0.1:$PORT_GO/ssh3-term:p7shm/p7out/many-go" \
            < /dev/null > /dev/null 2>&1 || return 1
        many_verify "$DEV_SHM/p7out/many-go"
        ;;
    os)
        scp -q -r -P "$PORT_SSH" -i "$WORK/bench_ed25519" -c "$CIPHER" \
            -o BatchMode=yes -o StrictHostKeyChecking=no \
            -o "UserKnownHostsFile=$WORK/known_hosts" -o IdentitiesOnly=yes \
            "$MANY_SRC" "user@127.0.0.1:$DEV_SHM/p7out/many-os" || return 1
        many_verify "$DEV_SHM/p7out/many-os"
        ;;
    esac
}

many_seed() { # $1 = impl: the unmeasured push that seeds the remote tree
    many_push "$1"
}

many_pull() { # $1 = impl: the measured download of the seeded tree
    case "$1" in
    c)
        "$C_CLIENT" -a "127.0.0.1:$PORT_C" -3 -J "get:$WORK/many-c-pull:p7out/many-c" -r \
            -K "$WORK/bench_pkcs8.pem" -U user -t 60000 > /dev/null 2>&1 || return 1
        many_verify "$WORK/many-c-pull"
        ;;
    go)
        "$GO_CLIENT" -insecure -privkey "$WORK/bench_pkcs8.pem" \
            -f -r "user@127.0.0.1:$PORT_GO/ssh3-term:p7shm/p7out/many-go" "$WORK/many-go-pull" \
            < /dev/null > /dev/null 2>&1 || return 1
        many_verify "$WORK/many-go-pull"
        ;;
    os)
        scp -q -r -P "$PORT_SSH" -i "$WORK/bench_ed25519" -c "$CIPHER" \
            -o BatchMode=yes -o StrictHostKeyChecking=no \
            -o "UserKnownHostsFile=$WORK/known_hosts" -o IdentitiesOnly=yes \
            "user@127.0.0.1:$DEV_SHM/p7out/many-os" "$WORK/many-os-pull" || return 1
        many_verify "$WORK/many-os-pull"
        ;;
    esac
}

stage_manyfiles() {
    local csv="$RES/manyfiles.csv" round impl dir t0 t1 sec rc
    echo "impl,dir,run,sec" > "$csv"
    log "manyfiles: $FILES_N files x 4096 B, impls: c go os"
    for dir in push pull; do
        for round in $(seq 0 "$ROUNDS"); do
            assert_alive
            for impl in c go os; do
                many_cleanup
                if [ "$dir" = pull ]; then
                    many_seed "$impl" || {
                        log "manyfiles $impl seed FAILED, round $round discarded"
                        continue
                    }
                fi
                t0=$(date +%s%N)
                if [ "$dir" = push ]; then
                    many_push "$impl" && rc=0 || rc=1
                else
                    many_pull "$impl" && rc=0 || rc=1
                fi
                t1=$(date +%s%N)
                sec=$(awk -v ns=$((t1 - t0)) 'BEGIN{printf "%.3f", ns/1e9}')
                [ "$rc" = 0 ] || log "manyfiles $impl $dir round $round FAILED, discarded"
                [ "$rc" = 0 ] || continue
                [ "$round" = 0 ] && continue
                echo "$impl,$dir,$round,$sec" >> "$csv"
                sleep 0.2
            done
        done
    done
    many_cleanup
    log "manyfiles summary ($FILES_N files):"
    summary_manyfiles "$csv"
}

summary_manyfiles() { # $1 = csv (impl,dir,run,sec)
    local impl dir vals
    for dir in push pull; do
        for impl in c go os; do
            vals=$(awk -F, -v i="$impl" -v d="$dir" 'NR > 1 && $1 == i && $2 == d {print $4}' "$1" | sort -g)
            [ -n "$vals" ] || continue
            echo "$vals" | awk -v i="$impl" -v d="$dir" -v n="$FILES_N" '
                {a[NR] = $1}
                END {
                    med = (NR % 2) ? a[(NR + 1) / 2] : (a[NR / 2] + a[NR / 2 + 1]) / 2
                    printf "  %-3s %-4s n=%d median=%.2fs files/s=%.0f MB/s=%.1f min=%.2f max=%.2f\n",
                        i, d, NR, med, n / med, n * 4096 / 1e6 / med, a[1], a[NR]
                }'
        done
    done
}

# --- main ----------------------------------------------------------------------
# --- main ----------------------------------------------------------------------

case "$STAGE" in
all | throughput | handshake | mux | cpu | manyfiles) ;;
*) die "bad stage: $STAGE" ;;
esac

setup_stand

wait_gone() { # $1 = pid, $2 = max seconds; the SIGTERM drain of the C daemon
              # keeps the port up to SSH3_SHUTDOWN_DRAIN (5 s default)
    local i
    for i in $(seq 1 "$(( $2 * 4 ))"); do
        [ -d "/proc/$1" ] || return 0
        sleep 0.25
    done
    return 1
}

# a previous aborted run may have left its stand behind: stop it by the
# pidfiles before fresh starts (the probes below would otherwise pass
# against the stale servers while the fresh ones die on the busy port)
cleanup_stale() {
    local pidfile pid
    for pidfile in c-server go-server sshd; do
        if [ -f "$WORK/$pidfile.pid" ]; then
            pid=$(cat "$WORK/$pidfile.pid")
            if [ -n "$pid" ] && [ -d "/proc/$pid" ]; then
                if [ "$pidfile" = sshd ]; then
                    sudo -n kill "$pid" 2>/dev/null || true
                else
                    kill "$pid" 2>/dev/null || true
                fi
                wait_gone "$pid" 8 || {
                    kill -9 "$pid" 2>/dev/null || true
                    sleep 0.5
                }
            fi
            rm -f "$WORK/$pidfile.pid"
        fi
    done
}

start_servers() {
    cleanup_stale
    start_c_server "-K $WORK/authorized_keys" ""
    start_go_server
    start_sshd
    probe c
    probe go
    probe os
}

if [ "$STAGE" = mux ] || [ "$STAGE" = handshake ] || [ "$STAGE" = manyfiles ]; then
    start_servers
elif [ "$STAGE" = all ] || [ "$STAGE" = throughput ] || [ "$STAGE" = cpu ]; then
    start_servers
fi

if [ "$STAGE" = all ] || [ "$STAGE" = throughput ]; then
    # 512 MiB: all three impls (the post-P7.1 C sftp pipeline holds
    # 56-137 MB/s, the 512 MiB round trip is seconds, not tens of minutes)
    stage_throughput "$SIZE_BIG" "c go os" "512m"
    stage_throughput "$SIZE_SMALL" "c go os" "8m"
fi

if [ "$STAGE" = all ] || [ "$STAGE" = handshake ]; then
    stage_handshake
fi

if [ "$STAGE" = all ] || [ "$STAGE" = cpu ]; then
    stage_cpu
fi

if [ "$STAGE" = all ] || [ "$STAGE" = mux ]; then
    stage_mux
fi

if [ "$STAGE" = all ] || [ "$STAGE" = manyfiles ]; then
    stage_manyfiles
fi

stop_servers
log "done, csv in $RES"
