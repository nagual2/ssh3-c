#!/bin/sh
# the s3cm e2e (stage M2, the harness wiring of the ControlMaster):
#
#   1. one s3interop_server (release build), one master client
#      (-3 -C -M -U /tmp/s3cm-e2e.sock)
#   2. slave 1, the default exec (printf s3-exec-ok), the marker rides
#      the master bridge
#   3. slave 2, a different exec command, the same master connection
#   4. slave 3 in the background, a sleeping exec; -O check under it
#      reports the live session (sessions counting up)
#   5. -O stop: the master exits, the socket file is removed
#   6. -O check against the dead path fails cleanly
#   7. the stale socket file of a SIGKILLed master unlinks on the next
#      listen (the ListenControlMaster probe), the new master stops
#      clean
#   8. -P persist: the master detaches (S3CM-MASTER-PERSIST), the
#      client exits, -M auto reuses the detached master as the slave,
#      -O stop closes it; -M auto on the dead path becomes the master
#
# usage: s3cm-e2e.sh [worktree]
set -u

ROOT=${1:-$(cd "$(dirname "$0")/.." && pwd)}
# the BUILD override rides the valgrind harness (the wrapper dir), the
# default is the worktree release build
BUILD=${BUILD:-$ROOT/build/linux-release}
FAILURES=0

die() {
    echo "s3cm-e2e: $1" >&2
    exit 1
}

fail() {
    echo "   FAIL: $1"
    FAILURES=$((FAILURES + 1))
}

pass() {
    echo "   PASS: $1"
}

[ -x "$BUILD/s3interop_server" ] || die "s3interop_server is not built"
[ -x "$BUILD/s3interop_client" ] || die "s3interop_client is not built"

W=$(mktemp -d /tmp/s3cm-e2e.XXXXXX)
SOCK=/tmp/s3cm-e2e.sock

SRV=$W/srv.log
MASTER=$W/master.log

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/key.pem" -out "$W/cert.pem" \
    -days 30 -subj /CN=s3cm-e2e 2>/dev/null || die "openssl req failed"

wait_for() {
    # wait_for <file> <pattern> [tries=50]
    i=0
    while [ "$i" -lt "${3:-50}" ]; do
        if grep -q "$2" "$1" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
        i=$((i + 1))
    done

    return 1
}

master_alive() {
    kill -0 "$1" 2>/dev/null
}

rm -f "$SOCK"

echo "== 1: the server and the master"

setsid nohup "$BUILD/s3interop_server" -3 -l 127.0.0.1:0 -c "$W/cert.pem" -k "$W/key.pem" \
    > "$SRV" 2>&1 < /dev/null &

SRVPID=$!

if wait_for "$SRV" INTEROP-LISTEN; then
    PORT=$(grep -oE 'port=[0-9]+' "$SRV" | cut -d= -f2)

    setsid nohup "$BUILD/s3interop_client" -3 -C -M -U "$SOCK" -a "127.0.0.1:$PORT" \
        -t 20000 > "$MASTER" 2>&1 < /dev/null &

    MASTERPID=$!

    if wait_for "$MASTER" "S3CM-MASTER-LISTEN" && wait_for "$MASTER" "INTEROP-H3-STATUS 200"; then
        pass "the master serves on $SOCK (pid $MASTERPID)"

        # the 0600 of ListenControlMaster
        PERM=$(stat -c %a "$SOCK" 2>/dev/null)

        if [ "$PERM" = "600" ]; then
            pass "the socket file is 0600"
        else
            fail "the socket file mode is $PERM, want 600"
        fi

    else
        fail "the master did not come up"
        tail -8 "$MASTER" | sed 's/^/      /'
        FAILURES=$((FAILURES + 1))
    fi

else
    echo "   FAIL: the server did not start"
    tail -5 "$SRV" | sed 's/^/   /'
    die "the server is mandatory"
fi

echo "== 2: slave 1, the default exec through the master bridge"

if timeout 15 "$BUILD/s3interop_client" -U "$SOCK" -t 10000 > "$W/slave1.log" 2>&1; then

    if grep -q "S3CM-SLAVE-DONE exit=0" "$W/slave1.log" \
        && grep -q "INTEROP-EXEC-OK exit=0" "$W/slave1.log" \
        && grep -q "S3CM-SLAVE-OUT s3-exec-ok" "$W/slave1.log"; then
        pass "slave 1 ran (the s3-exec-ok marker rode the bridge)"
    else
        fail "slave 1 output incomplete"
        cat "$W/slave1.log" | sed 's/^/      /'
    fi

else
    fail "slave 1 exited non-zero"
    cat "$W/slave1.log" | sed 's/^/      /'
fi

echo "== 3: slave 2, a different exec command, the same master"

if timeout 15 "$BUILD/s3interop_client" -U "$SOCK" -e "printf s3cm-slave-two" \
    -t 10000 > "$W/slave2.log" 2>&1; then

    if grep -q "S3CM-SLAVE-DONE exit=0" "$W/slave2.log" \
        && grep -q "S3CM-SLAVE-OUT s3cm-slave-two" "$W/slave2.log"; then
        pass "slave 2 ran through the same master connection"
    else
        fail "slave 2 output incomplete"
        cat "$W/slave2.log" | sed 's/^/      /'
    fi

else
    fail "slave 2 exited non-zero"
    cat "$W/slave2.log" | sed 's/^/      /'
fi

if grep -c "S3CM-MASTER-SESSION-DONE exit=0" "$MASTER" | grep -q '^2$'; then
    pass "the master finalized both sessions with exit 0"
else
    fail "the master session count is not two"
    cat "$MASTER" | sed 's/^/      /'
fi

echo "== 4: slave 3 in the background, check under the live session"

timeout 15 "$BUILD/s3interop_client" -U "$SOCK" -e "printf s3cm-slave-three && sleep 2" \
    -t 10000 > "$W/slave3.log" 2>&1 &

SLAVE3PID=$!

sleep 0.8

CHECK=$("$BUILD/s3interop_client" -O check -U "$SOCK" 2>"$W/check.err")
CHECKRC=$?

if [ "$CHECKRC" -eq 0 ] && echo "$CHECK" | grep -q "Master running (pid=" \
    && echo "$CHECK" | grep -q "1 session(s)" && echo "$CHECK" | grep -q "0 forward(s)"; then
    pass "check under the live session: $CHECK"
else
    fail "check failed or shows no live session (rc=$CHECKRC): $CHECK"
    cat "$W/check.err" | sed 's/^/      /'
fi

wait "$SLAVE3PID" || fail "slave 3 exited non-zero"

if grep -q "S3CM-SLAVE-DONE exit=0" "$W/slave3.log" \
    && grep -q "S3CM-SLAVE-OUT s3cm-slave-three" "$W/slave3.log"; then
    pass "slave 3 completed after the check"
else
    fail "slave 3 output incomplete"
    cat "$W/slave3.log" | sed 's/^/      /'
fi

echo "== 5: stop op"

if "$BUILD/s3interop_client" -O stop -U "$SOCK" > "$W/stop.log" 2>&1; then
    pass "stop acknowledged and the socket released"
else
    fail "stop exited non-zero"
    cat "$W/stop.log" | sed 's/^/      /'
fi

sleep 0.5

if master_alive "$MASTERPID"; then
    fail "the master process still lives"
    kill "$MASTERPID" 2>/dev/null
else
    pass "the master process exited"
fi

if [ -e "$SOCK" ]; then
    fail "the socket file is still there"
    rm -f "$SOCK"
else
    pass "the socket file is removed"
fi

echo "== 6: check against the dead path"

if "$BUILD/s3interop_client" -O check -U "$SOCK" > "$W/dead.log" 2>&1; then
    fail "the dead path check exited zero"
else
    if grep -q "no control master is listening" "$W/dead.log"; then
        pass "the dead path check fails cleanly"
    else
        fail "the dead path check failed with noise"
        cat "$W/dead.log" | sed 's/^/      /'
    fi
fi

echo "== 7: the stale socket file of a killed master"

setsid nohup "$BUILD/s3interop_client" -3 -C -M -U "$SOCK" -a "127.0.0.1:$PORT" \
    -t 20000 > "$W/master2.log" 2>&1 < /dev/null &

MASTER2PID=$!

wait_for "$W/master2.log" "S3CM-MASTER-LISTEN" || fail "master 2 did not come up"

kill -9 "$MASTER2PID" 2>/dev/null
wait "$MASTER2PID" 2>/dev/null

if [ -S "$SOCK" ]; then
    pass "the killed master left its socket file"
else
    fail "no stale socket file to test"
fi

setsid nohup "$BUILD/s3interop_client" -3 -C -M -U "$SOCK" -a "127.0.0.1:$PORT" \
    -t 20000 > "$W/master3.log" 2>&1 < /dev/null &

MASTER3PID=$!

if wait_for "$W/master3.log" "S3CM-MASTER-LISTEN"; then
    pass "the new master took over the stale socket file"
else
    fail "the new master refused the stale path"
    tail -5 "$W/master3.log" | sed 's/^/      /'
fi

# a second master on a live path refuses (the dial probe)

if "$BUILD/s3interop_client" -3 -C -M -U "$SOCK" -a "127.0.0.1:$PORT" -t 3000 \
    > "$W/dup.log" 2>&1; then
    fail "a second master took the live path"
else
    if grep -q "already running" "$W/dup.log"; then
        pass "a second master refuses the live path"
    else
        fail "the dup master failed with noise"
        tail -3 "$W/dup.log" | sed 's/^/      /'
    fi
fi

"$BUILD/s3interop_client" -O stop -U "$SOCK" > "$W/stop3.log" 2>&1 || fail "stop 3 failed"

sleep 0.3

if master_alive "$MASTER3PID"; then
    fail "master 3 still lives"
    kill "$MASTER3PID" 2>/dev/null
else
    pass "master 3 exited on stop"
fi

echo "== 8: -P persist detaches, -M auto reuses the live master"

setsid nohup "$BUILD/s3interop_client" -3 -C -M yes -P yes -i 0 -U "$SOCK" \
    -a "127.0.0.1:$PORT" -t 60000 > "$W/masterp.log" 2>&1 < /dev/null &

MASTERP1PID=$!

if wait_for "$W/masterp.log" "S3CM-MASTER-PERSIST"; then
    MASTERPPID=$(grep -oE 'pid=[0-9]+' "$W/masterp.log" | head -1 | cut -d= -f2)

    if [ -n "$MASTERPPID" ] && master_alive "$MASTERPPID"; then
        pass "the detached master lives (pid $MASTERPPID)"
    else
        fail "the detached master is not alive"
    fi

    sleep 0.3

    if master_alive "$MASTERP1PID"; then
        fail "the client did not exit after the detach"
        kill "$MASTERP1PID" 2>/dev/null
    else
        pass "the client exited, the master carries on detached"
    fi

else
    fail "the persist master did not detach"
    tail -5 "$W/masterp.log" | sed 's/^/      /'
    MASTERPPID=""
fi

if timeout 15 "$BUILD/s3interop_client" -M auto -U "$SOCK" -e "printf s3cm-auto-slave" \
    -t 10000 > "$W/auto1.log" 2>&1; then

    if grep -q "S3CM-SLAVE-DONE exit=0" "$W/auto1.log" \
        && grep -q "S3CM-SLAVE-OUT s3cm-auto-slave" "$W/auto1.log"; then
        pass "-M auto reused the live master as the slave"
    else
        fail "the auto slave output incomplete"
        cat "$W/auto1.log" | sed 's/^/      /'
    fi

else
    fail "the auto slave exited non-zero"
    cat "$W/auto1.log" | sed 's/^/      /'
fi

if grep -q "S3CM-MASTER-SESSION-DONE exit=0" "$W/masterp.log"; then
    pass "the detached master served the auto session"
else
    fail "no session marker in the detached master log"
fi

if [ -n "$MASTERPPID" ]; then

    if "$BUILD/s3interop_client" -O stop -U "$SOCK" > "$W/stopp.log" 2>&1; then
        pass "stop acknowledged on the detached master"
    else
        fail "stop failed on the detached master"
        cat "$W/stopp.log" | sed 's/^/      /'
    fi

    sleep 0.5

    if master_alive "$MASTERPPID"; then
        fail "the detached master still lives"
        kill "$MASTERPPID" 2>/dev/null
    else
        pass "the detached master exited on stop"
    fi
fi

# -M auto on the dead path: no live master, no stale file, the client
# becomes the master itself

setsid nohup "$BUILD/s3interop_client" -3 -C -M auto -P yes -i 0 -U "$SOCK" \
    -a "127.0.0.1:$PORT" -t 60000 > "$W/mastera.log" 2>&1 < /dev/null &

MASTERAPID=$!

if wait_for "$W/mastera.log" "S3CM-MASTER-LISTEN"; then
    pass "-M auto became the master on the dead path"
else
    fail "-M auto did not become the master"
    tail -5 "$W/mastera.log" | sed 's/^/      /'
fi

"$BUILD/s3interop_client" -O stop -U "$SOCK" > "$W/stopa.log" 2>&1 || fail "stop auto failed"

sleep 0.3

if master_alive "$MASTERAPID"; then
    fail "the auto master still lives"
    kill "$MASTERAPID" 2>/dev/null
else
    pass "the auto master exited on stop"
fi

kill "$SRVPID" 2>/dev/null
pkill -f "s3interop_server -3" 2>/dev/null

rm -rf "$W"

if [ "$FAILURES" -eq 0 ]; then
    echo "S3CM-E2E OK (control master, two slaves, check, stop, persist, auto)"
    exit 0
fi

echo "S3CM-E2E FAILED: $FAILURES check(s)"
exit 1
