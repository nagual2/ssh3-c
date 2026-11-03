#!/usr/bin/env bash
# copy-compare bench: the file-copy throughput of ssh3-c, the Go fork, the
# Rust client, OpenSSH (ssh2 scp) and rsync-over-ssh2 on one loopback stand,
# IPv4 and IPv6 dialed separately (the v4/v6 literals select the family).
#
#   copy-compare.sh [--size-mib 64] [--rounds 3] [--work /tmp/copybench]
#                   [--c-build DIR] [--go-src DIR] [--rust-bin DIR]
#                   [--impls c,go,rust,ssh2,rsync] [--families 4,6]
#                   [--push-only]
#
# Methodology (the p7-compare ritual): tmpfs payloads, sha256-verified on
# both ends, the first round is the warmup and is discarded, the wall time
# of the client process is the metric, the medians land in the summary.
#
# The stand (all daemons dual-stack, the [::] bind serves both families):
#   ssh3-c daemon   :8822/udp  (JWT pubkey -K)
#   Go fork server  :8823/udp  (~/.ssh3/authorized_identities)
#   Rust server     :8824/udp  (--authorized-identity)
#   sshd            :8922/tcp  (a dedicated instance, the private host key,
#                               nothing in ~/.ssh is touched)
# One ed25519 keypair in two formats signs everywhere: the PKCS8 PEM for
# the JWT clients, the OpenSSH format for sshd/scp/rsync.  The C client
# runs with the isolated HOME (the pins prewritten for both families), the
# Go and the Rust clients ride -insecure / --strict-host-key-checking=no
# (the transport TLS is the same, the pin store does not move the bytes),
# scp/rsync carry UserKnownHostsFile into the work dir.
#
# The Rust legs are opt-in (--impls rust): the client is raw for this
# stand as of 2026-11-03 - the identity loader refuses both the PKCS8 PEM
# and the OpenSSH-format key ("PEM Base64 error"), and the transfer
# operand cannot express the bracketed ipv6 literal (transfer.rs
# split(':'), the TooManySeparators error).  Both findings ride the rust
# parity report, the bench does not spend its time there by default.

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=/tmp/copybench
C_BUILD=${C_BUILD:-$ROOT/build/linux-release}
GO_SRC=${GO_SRC:-$HOME/git/ssh3}
RUST_BIN=${RUST_BIN:-$HOME/git/ssh3-rust/target/release}
SIZE_MIB=64 ROUNDS=3 PUSH_ONLY=0
PORT_C=8822 PORT_GO=8823 PORT_R=8824 PORT_SSH=8922
IMPLS="c go ssh2 rsync"
FAMILIES="4 6"
DEV_SHM=/dev/shm
BENCH_USER="${BENCH_USER:-$(id -un)}"
MARK=copybench

while [ $# -gt 0 ]; do
    case "$1" in
    --size-mib) SIZE_MIB="$2"; shift 2 ;;
    --rounds) ROUNDS="$2"; shift 2 ;;
    --work) WORK="$2"; shift 2 ;;
    --c-build) C_BUILD="$2"; shift 2 ;;
    --go-src) GO_SRC="$2"; shift 2 ;;
    --rust-bin) RUST_BIN="$2"; shift 2 ;;
    --impls) IMPLS=$(echo "$2" | tr ',' ' '); shift 2 ;;
    --families) FAMILIES=$(echo "$2" | tr ',' ' '); shift 2 ;;
    --push-only) PUSH_ONLY=1; shift ;;
    *) echo "copy-compare: unknown flag: $1" >&2; exit 1 ;;
    esac
done

LOGS=$WORK/logs RES=$WORK/results
C_CLIENT=$WORK/bin/ccb-client C_SERVER=$WORK/bin/ccb-server
GO_CLIENT=$WORK/bin/gob-client GO_SERVER=$WORK/bin/gob-server
RUST_CLIENT=$RUST_BIN/ssh3 RUST_SERVER=$RUST_BIN/ssh3-rust-server
DEV_SHM_SRC=$DEV_SHM/cb-src.bin
CIPHER=aes128-gcm@openssh.com

mkdir -p "$LOGS" "$RES" "$WORK/bin" "$WORK/home/.ssh3"

log() { echo "[copy] $*" >&2; }
die() { echo "copy-compare: ERROR: $*" >&2; exit 1; }
sha_of() { sha256sum "$1" | awk '{print $1}'; }

has_impl() { case " $IMPLS " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }
has_fam() { case " $FAMILIES " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

# --- the stand artifacts -----------------------------------------------------

if [ ! -x "$C_BUILD/ssh3-server" ]; then
    die "the C build is missing: $C_BUILD/ssh3-server (cmake --preset linux-release)"
fi
cp -f "$C_BUILD/ssh3" "$C_CLIENT"
cp -f "$C_BUILD/ssh3-server" "$C_SERVER"

if has_impl go || has_impl rsync; then
    if [ ! -x "$GO_CLIENT" ] || [ ! -x "$GO_SERVER" ]; then
        log "building the go fork binaries"
        (cd "$GO_SRC" && go build -o "$GO_CLIENT" ./cmd/ssh3 && go build -o "$GO_SERVER" ./cmd/ssh3-server)
    fi
fi

if has_impl rust && [ ! -x "$RUST_CLIENT" ]; then
    die "the rust client is missing: $RUST_CLIENT (cargo build --release)"
fi

# one ed25519 keypair in two formats: the PKCS8 PEM (the JWT clients) and
# the OpenSSH format (sshd/scp/rsync); openssl generates, python converts

if [ ! -f "$WORK/bench_pkcs8.pem" ] || [ ! -f "$WORK/bench_ed25519" ]; then
    openssl genpkey -algorithm ed25519 -out "$WORK/bench_pkcs8.pem" 2>/dev/null
    chmod 600 "$WORK/bench_pkcs8.pem"
    CB_WORK="$WORK" python3 - <<'EOF'
import os
from cryptography.hazmat.primitives.serialization import (load_pem_private_key,
    Encoding, PrivateFormat, NoEncryption)
work = os.environ["CB_WORK"]
key = load_pem_private_key(open(work + "/bench_pkcs8.pem", "rb").read(), password=None)
open(work + "/bench_ed25519", "wb").write(
    key.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()))
EOF
    chmod 600 "$WORK/bench_ed25519"
fi
ssh-keygen -y -f "$WORK/bench_ed25519" > "$WORK/bench_ed25519.pub"

# the home-relative sftp paths of the go fork (and possibly the rust):
# the symlink points the bench name into tmpfs
ln -sfn "$DEV_SHM" "$HOME/cbshm"

cp -f "$WORK/bench_ed25519.pub" "$WORK/authorized_keys"

# the self-signed P-256 certificate of the QUIC daemons

if [ ! -f "$WORK/cert.pem" ]; then
    openssl req -x509 -sha256 -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
        -keyout "$WORK/key.pem" -days 30 -out "$WORK/cert.pem" -subj /CN=127.0.0.1 \
        -addext "subjectAltName=IP:127.0.0.1,IP:0:0:0:0:0:0:0:1" 2>/dev/null
fi

# the sshd host key

if [ ! -f "$WORK/host_ed25519" ]; then
    ssh-keygen -t ed25519 -f "$WORK/host_ed25519" -N "" -C copybench -q
fi

# the go server reads the real ~/.ssh3/authorized_identities: the bench
# line appends with the marker, the cleanup removes the marker line only

if has_impl go; then
    mkdir -p "$HOME/.ssh3"
    B64=$(awk '{print $2}' "$WORK/bench_ed25519.pub")
    grep -q "$MARK" "$HOME/.ssh3/authorized_identities" 2>/dev/null ||
        printf 'ssh-ed25519 %s %s\n' "$B64" "$MARK" >> "$HOME/.ssh3/authorized_identities"
fi

# the rust server auth file: the OpenSSH pub line

printf 'ssh-ed25519 %s %s\n' "$(awk '{print $2}' "$WORK/bench_ed25519.pub")" "$MARK" \
    > "$WORK/rust-authorized"

# the payload of the run

if [ ! -f "$DEV_SHM_SRC" ] || [ "$(stat -c%s "$DEV_SHM_SRC")" -ne "$((SIZE_MIB * 1024 * 1024))" ]; then
    dd if=/dev/urandom of="$DEV_SHM_SRC" bs=1M count="$SIZE_MIB" status=none
fi
SRC_SHA=$(sha_of "$DEV_SHM_SRC")

# the C client pin store: the isolated HOME, the cert pinned for both
# family forms (the bracket shape of the v6)

CERT_B64=$(openssl x509 -in "$WORK/cert.pem" -outform DER | base64 -w0)
printf '127.0.0.1:%s/ssh3-term x509-certificate %s\n' "$PORT_C" "$CERT_B64" \
    > "$WORK/home/.ssh3/known_hosts"
printf '[::1]:%s/ssh3-term x509-certificate %s\n' "$PORT_C" "$CERT_B64" \
    >> "$WORK/home/.ssh3/known_hosts"
: > "$WORK/kh"

# --- the servers ---------------------------------------------------------------

start_servers() {
    SSH3_LOG_FILE="$LOGS/c-server.log" nohup "$C_SERVER" \
        -l "[::]:$PORT_C" -c "$WORK/cert.pem" -k "$WORK/key.pem" \
        -K "$WORK/authorized_keys" \
        > "$LOGS/c-server.out" 2>&1 < /dev/null &
    echo $! > "$WORK/c-server.pid"

    if has_impl go; then
        SSH3_LOG_FILE="$LOGS/go-server.log" nohup "$GO_SERVER" \
            -bind "[::]:$PORT_GO" -cert "$WORK/cert.pem" -key "$WORK/key.pem" \
            -url-path /ssh3-term > "$LOGS/go-server.out" 2>&1 < /dev/null &
        echo $! > "$WORK/go-server.pid"
    fi

    if has_impl rust; then
        nohup "$RUST_SERVER" --bind "[::]:$PORT_R" \
            --authorized-identity "$WORK/rust-authorized" --user "$BENCH_USER" \
            > "$LOGS/rust-server.out" 2>&1 < /dev/null &
        echo $! > "$WORK/rust-server.pid"
    fi

    sudo -n /usr/sbin/sshd -p "$PORT_SSH" -h "$WORK/host_ed25519" \
        -o "AuthorizedKeysFile=$WORK/authorized_keys" -o StrictModes=no \
        -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no \
        -o UsePAM=no -o ListenAddress=127.0.0.1 -o ListenAddress=::1 \
        -o "PidFile=$WORK/sshd.pid" -o LogLevel=ERROR
    sleep 0.3

    local pidfile pid
    for pidfile in c-server go-server rust-server sshd; do
        [ -f "$WORK/$pidfile.pid" ] || continue
        pid=$(cat "$WORK/$pidfile.pid")
        [ -d "/proc/$pid" ] || die "$pidfile died at startup (bind busy?)"
    done
}

stop_servers() {
    local pidfile pid
    for pidfile in c-server go-server rust-server sshd; do
        [ -f "$WORK/$pidfile.pid" ] || continue
        pid=$(cat "$WORK/$pidfile.pid")
        if [ "$pidfile" = sshd ]; then
            sudo -n kill "$pid" 2>/dev/null || true
        else
            kill "$pid" 2>/dev/null || true
        fi
        # the graceful drain rides SSH3_SHUTDOWN_DRAIN (5 s default): the
        # wait escalates to kill -9 at the deadline or the next run's bind
        # races the dying daemon
        for _ in $(seq 1 24); do
            [ -d "/proc/$pid" ] || break
            sleep 0.25
        done
        if [ -d "/proc/$pid" ]; then
            kill -9 "$pid" 2>/dev/null || true
            sleep 0.5
        fi
        rm -f "$WORK/$pidfile.pid"
    done
    if has_impl go; then
        sed -i "/$MARK/d" "$HOME/.ssh3/authorized_identities" 2>/dev/null || true
    fi
    rm -f "$DEV_SHM_SRC" "$HOME/cbshm"
}

# --- the client operations ---------------------------------------------------

host_of() { [ "$1" = 4 ] && echo "127.0.0.1" || echo "[::1]"; }
rm_dst() { rm -f "$DEV_SHM/cb-out.bin"; }

# xfer IMPL FAM DIR SRC DST: the timed transfer, the exit code decides the
# row; DIR = push|pull.  The rust v6 dies on the operand parse (the known
# shape) and reports SKIP.

xfer() {
    local impl=$1 fam=$2 dir=$3
    local host dst="$DEV_SHM/cb-out.bin"
    host=$(host_of "$fam")
    rm_dst

    case "$impl:$dir" in
    c:push)
        # the alias forms are symmetric: put:LOCAL:REMOTE,
        # get:LOCAL:REMOTE - the remote legs ride the cbshm symlink
        # (the server jail is the session user's home); -n keeps the
        # console init off the /dev/null stdin (the epoll of the plain
        # char device refuses, EPERM)
        HOME="$WORK/home" "$C_CLIENT" -n --sftp "put:$DEV_SHM_SRC:cbshm/cb-out.bin" \
            -i "$WORK/bench_pkcs8.pem" "$BENCH_USER@$host:$PORT_C/ssh3-term" \
            < /dev/null > /dev/null 2>"$LOGS/c-$fam-push.err"
        ;;
    c:pull)
        HOME="$WORK/home" "$C_CLIENT" -n --sftp "get:$dst:cbshm/cb-src.bin" \
            -i "$WORK/bench_pkcs8.pem" "$BENCH_USER@$host:$PORT_C/ssh3-term" \
            < /dev/null > /dev/null 2>"$LOGS/c-$fam-pull.err"
        ;;
    go:push)
        # the fork sftp paths are HOME-relative: cbshm -> tmpfs
        "$GO_CLIENT" -transfer -insecure -privkey "$WORK/bench_pkcs8.pem" \
            -p "$PORT_GO" -U /ssh3-term "$DEV_SHM_SRC" "$BENCH_USER@$host:cbshm/cb-out.bin" \
            < /dev/null > /dev/null 2>"$LOGS/go-$fam-push.err"
        ;;
    go:pull)
        "$GO_CLIENT" -transfer -insecure -privkey "$WORK/bench_pkcs8.pem" \
            -p "$PORT_GO" -U /ssh3-term "$BENCH_USER@$host:cbshm/cb-src.bin" "$dst" \
            < /dev/null > /dev/null 2>"$LOGS/go-$fam-pull.err"
        ;;
    rust:push)
        HOME="$WORK/home" "$RUST_CLIENT" --transfer -i "$WORK/bench_ed25519" \
            --strict-host-key-checking no \
            "$DEV_SHM_SRC" "$BENCH_USER@$host:$PORT_R/ssh3-term:cbshm/cb-out.bin" \
            < /dev/null > /dev/null 2>"$LOGS/rust-$fam-push.err"
        ;;
    rust:pull)
        HOME="$WORK/home" "$RUST_CLIENT" --transfer -i "$WORK/bench_ed25519" \
            --strict-host-key-checking no \
            "$BENCH_USER@$host:$PORT_R/ssh3-term:cbshm/cb-src.bin" "$dst" \
            < /dev/null > /dev/null 2>"$LOGS/rust-$fam-pull.err"
        ;;
    ssh2:push)
        scp -q -P "$PORT_SSH" -i "$WORK/bench_ed25519" -c "$CIPHER" -o BatchMode=yes \
            -o StrictHostKeyChecking=no -o "UserKnownHostsFile=$WORK/kh" \
            -o IdentitiesOnly=yes "$DEV_SHM_SRC" "$BENCH_USER@$host:$dst" \
            < /dev/null > /dev/null 2>&1
        ;;
    ssh2:pull)
        scp -q -P "$PORT_SSH" -i "$WORK/bench_ed25519" -c "$CIPHER" -o BatchMode=yes \
            -o StrictHostKeyChecking=no -o "UserKnownHostsFile=$WORK/kh" \
            -o IdentitiesOnly=yes "$BENCH_USER@$host:$DEV_SHM_SRC" "$dst" \
            < /dev/null > /dev/null 2>&1
        ;;
    rsync:push)
        rsync "$DEV_SHM_SRC" "$BENCH_USER@$host:$dst" \
            -e "ssh -p $PORT_SSH -i $WORK/bench_ed25519 -c $CIPHER -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=$WORK/kh -o IdentitiesOnly=yes" \
            < /dev/null > /dev/null 2>&1
        ;;
    rsync:pull)
        rsync "$BENCH_USER@$host:$DEV_SHM_SRC" "$dst" \
            -e "ssh -p $PORT_SSH -i $WORK/bench_ed25519 -c $CIPHER -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=$WORK/kh -o IdentitiesOnly=yes" \
            < /dev/null > /dev/null 2>&1
        ;;
    *) return 1 ;;
    esac
}

# the readiness probes: the exec per impl per family, the transfer legs
# ride the same session machinery

probe() {
    local impl=$1 fam=$2 i host
    host=$(host_of "$fam")
    case "$impl" in
    c)
        for i in $(seq 1 40); do
            HOME="$WORK/home" "$C_CLIENT" -n -o ConnectTimeout=8000 \
                -i "$WORK/bench_pkcs8.pem" "$BENCH_USER@$host:$PORT_C/ssh3-term" true \
                < /dev/null > /dev/null 2>"$LOGS/probe-c-$fam.err" && return 0
            sleep 0.25
        done ;;
    go)
        for i in $(seq 1 40); do
            "$GO_CLIENT" -insecure -privkey "$WORK/bench_pkcs8.pem" \
                "$BENCH_USER@$host:$PORT_GO/ssh3-term" true \
                < /dev/null > /dev/null 2>"$LOGS/probe-go-$fam.err" && return 0
            sleep 0.25
        done ;;
    rust)
        for i in $(seq 1 40); do
            HOME="$WORK/home" "$RUST_CLIENT" -i "$WORK/bench_ed25519" \
                --strict-host-key-checking no "$BENCH_USER@$host:$PORT_R/ssh3-term" true \
                < /dev/null > /dev/null 2>"$LOGS/probe-rust-$fam.err" && return 0
            sleep 0.25
        done ;;
    ssh2)
        for i in $(seq 1 40); do
            ssh -p "$PORT_SSH" -i "$WORK/bench_ed25519" -o BatchMode=yes \
                -o StrictHostKeyChecking=no -o "UserKnownHostsFile=$WORK/kh" \
                -o IdentitiesOnly=yes "$BENCH_USER@$(host_of "$fam" | tr -d '[]')" true \
                < /dev/null > /dev/null 2>"$LOGS/probe-ssh2-$fam.err" && return 0
            sleep 0.25
        done ;;
    rsync)
        probe ssh2 "$fam" && return 0 ;;
    esac
    return 1
}

# --- the run -----------------------------------------------------------------

CSV=$RES/copy.csv
echo "impl,family,dir,round,ms,mbs,ok" > "$CSV"

start_servers

# the probe matrix: the family the impl cannot dial skips its rows early

declare -A CAN
for impl in $IMPLS; do
    for fam in $FAMILIES; do
        if probe "$impl" "$fam"; then
            CAN[$impl$fam]=1
        else
            CAN[$impl$fam]=0
            log "probe $impl v$fam: no answer, the rows skip"
        fi
    done
done

# the known family shape: the go and the rust transfer operands parse
# user@host:remote with the naive colon split - the bracketed ipv6
# literal does not express (the exec legs ride the URL form and work);
# the rows skip with the reason instead of erroring the rounds

if [ "${CAN[go6]:-0}" = 1 ]; then
    CAN[go6]=0
    log "go v6: the transfer operand cannot carry the bracketed ipv6 (the parse gap), the rows skip"
fi

runs_for() { # the warmup round + the measured rounds
    seq 0 "$ROUNDS"
}

for impl in $IMPLS; do
    for fam in $FAMILIES; do
        [ "${CAN[$impl$fam]:-0}" = 1 ] || continue
        for dir in push pull; do
            [ "$dir" = pull ] && [ "$PUSH_ONLY" = 1 ] && continue
            for r in $(runs_for "$ROUNDS"); do
                t0=$(date +%s%N)
                if xfer "$impl" "$fam" "$dir"; then
                    t1=$(date +%s%N)
                else
                    echo "$impl,$fam,$dir,$r,,0,error" >> "$CSV"
                    log "$impl v$fam $dir round $r: TRANSFER FAILED, the dir retires"
                    break
                fi
                ms=$(((t1 - t0) / 1000000))
                if [ -f "$DEV_SHM/cb-out.bin" ] &&
                    [ "$(sha_of "$DEV_SHM/cb-out.bin")" = "$SRC_SHA" ]; then
                    ok=1
                else
                    ok=0
                    log "$impl v$fam $dir round $r: SHA MISMATCH"
                fi
                # mbs with one decimal, the awk carries the math
                mbs=$(awk -v b=$((SIZE_MIB * 1024 * 1024)) -v ns=$((t1 - t0)) \
                    'BEGIN { printf "%.1f", b / (ns / 1000000000.0) / 1048576 }')
                echo "$impl,$fam,$dir,$r,$ms,$mbs,$ok" >> "$CSV"
                rm_dst
            done
        done
    done
done

stop_servers

# --- the summary: the medians of the verified measured rounds ----------------

echo
echo "== copy-compare summary (median MB/s, verified rounds only) =="
printf '%-8s %-4s %-5s %10s %8s\n' IMPL FAM DIR MBPS ROUNDS
for impl in $IMPLS; do
    for fam in $FAMILIES; do
        for dir in push pull; do
            [ "$dir" = pull ] && [ "$PUSH_ONLY" = 1 ] && continue
            row=$(awk -F, -v i="$impl" -v f="$fam" -v d="$dir" \
                '$1==i && $2==f && $3==d && $4>0 && $7==1 {print $6}' "$CSV" | sort -n)
            n=$(echo "$row" | grep -c . || true)
            [ "$n" -eq 0 ] && continue
            med=$(echo "$row" | awk '{a[NR]=$1} END {print (NR%2) ? a[(NR+1)/2] : (a[NR/2]+a[NR/2+1])/2}')
            printf '%-8s %-4s %-5s %10.1f %8s\n' "$impl" "v$fam" "$dir" "$med" "$n"
        done
    done
done
echo "csv: $CSV"
