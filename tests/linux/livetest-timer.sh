#!/bin/sh
# the ssh3-trust-update timer livetest (PLAN.md 14, phase 1c): the
# user timer lands, the daily schedule rides, the service runs the
# real fetch against the default bundle URL, the bundle + the
# manifest land, the unit rolls back.
#
# the repo user units ride (packaging/systemd); the ExecStart pins
# to the local ssh3-cert (the user session PATH does not carry the
# build tree). A pre-existing ssh3-trust-update.timer (the real
# install) aborts the test - the livetest does not touch the
# production schedule.
#
# the rollback: disable --now, the unit files removed, the bundle
# artifacts restored to the pre-test state.
#
# the verdict: TRUST-TIMER OK / FAILED / SKIPPED
#
# usage: tests/linux/livetest-timer.sh [repo-root] [ssh3-cert-path]
#        (a linux host with a running systemd user manager)
set -u

ROOT=${1:-$(cd "$(dirname "$0")/../.." && pwd)}
UNITS_SRC=${UNITS_SRC:-$ROOT/packaging/systemd}
CERT=${2:-$(find "$ROOT/build" -name ssh3-cert -type f 2>/dev/null | head -1)}

echo "== uname: $(uname -a)"

USERD="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
HOME_D="$HOME/.ssh3"
BUNDLE="$HOME_D/trust-bundle.pem"

fail() { echo "TRUST-TIMER FAILED: $1"; exit 1; }

systemctl --user is-system-running 2>/dev/null | grep -q -E 'running|degraded' || {
    echo "TRUST-TIMER SKIPPED: no running systemd user manager"
    exit 2
}

[ -x "$CERT" ] || fail "ssh3-cert not found under $ROOT/build (pass the path)"
[ -f "$UNITS_SRC/ssh3-trust-update.service" ] || fail "the repo units missing: $UNITS_SRC"
[ -f "$USERD/ssh3-trust-update.timer" ] && {
    fail "a ssh3-trust-update.timer already installed (the production schedule) - the livetest aborts"
}

# the pre-test state of the bundle artifacts (the restore target)

PRE_BUNDLE=""
if [ -f "$BUNDLE" ]; then
    PRE_BUNDLE=$(mktemp) || fail "mktemp failed"
    cp "$BUNDLE" "$PRE_BUNDLE"
fi

cleanup() {
    systemctl --user disable --now ssh3-trust-update.timer 2>/dev/null
    rm -f "$USERD/ssh3-trust-update.service" "$USERD/ssh3-trust-update.timer"
    systemctl --user daemon-reload 2>/dev/null

    if [ -n "$PRE_BUNDLE" ]; then
        cp "$PRE_BUNDLE" "$BUNDLE"
        rm -f "$PRE_BUNDLE"
    else
        rm -f "$BUNDLE" "$BUNDLE.man"
    fi
}
trap cleanup EXIT INT TERM

mkdir -p "$USERD" "$HOME_D"

# the service with the pinned ExecStart (the build tree path)

sed "s|^ExecStart=.*|ExecStart=$CERT --trust-update|" \
    "$UNITS_SRC/ssh3-trust-update.service" > "$USERD/ssh3-trust-update.service"
cp "$UNITS_SRC/ssh3-trust-update.timer" "$USERD/ssh3-trust-update.timer"

systemctl --user daemon-reload

# --- 1. the enable + the schedule presence ---

systemctl --user enable --now ssh3-trust-update.timer || fail "enable --now failed"
systemctl --user is-enabled ssh3-trust-update.timer | grep -q enabled || fail "is-enabled"
systemctl --user list-timers ssh3-trust-update.timer --no-pager 2>/dev/null | grep -q ssh3-trust-update || {
    fail "list-timers carries no schedule"
}
echo "   PASS: the timer enabled + scheduled (daily + random delay)"

# --- 2. the service run: the real fetch ---

rm -f "$BUNDLE" "$BUNDLE.man"
systemctl --user start ssh3-trust-update.service || fail "the service run failed"
echo "   PASS: the service run passed (the fetch + the PEM walk + the atomic landing)"

# --- 3. the bundle artifacts ---

[ -f "$BUNDLE" ] || fail "the bundle did not land"
[ -f "$BUNDLE.man" ] || fail "the manifest did not land"

hash_now=$(sha256sum "$BUNDLE" | cut -d' ' -f1)
hash_man=$(sed -n '2p' "$BUNDLE.man")
[ -n "$hash_man" ] && [ "$hash_now" = "$hash_man" ] || fail "the manifest sha256 drift"

url_man=$(sed -n '1p' "$BUNDLE.man")
echo "   PASS: the bundle landed from $url_man (sha256 matches the manifest)"

echo "TRUST-TIMER OK"
exit 0
