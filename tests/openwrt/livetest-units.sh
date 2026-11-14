#!/bin/sh
# the OpenWrt unit livetest: every cross-built test binary rides the
# VM run (the musl binaries against the apk libopenssl), the verdict
# sums the failures
#
# the test_auth_ct leg reads the compiled-in S3_TEST_SOURCE_DIR (the
# WSL clone path): the mirror directory carries the two source files
# it reads
#
# usage: /root/ssh3c-openwrt/livetest-units.sh (the run dir carries
# the tests/ prefix)
set -u

echo "== uname: $(uname -a)"

D=${1:-/root/ssh3c-openwrt}
cd "$D" || exit 1

FAILED=0
TOTAL=0
FAILED_NAMES=""

for t in tests/test_*; do
    [ -x "$t" ] || continue
    TOTAL=$((TOTAL + 1))
    if "$t" > /dev/null 2>&1; then
        :
    else
        FAILED=$((FAILED + 1))
        FAILED_NAMES="$FAILED_NAMES ${t#tests/}"
        echo "   FAIL: ${t#tests/}"
    fi
done

echo "units: $TOTAL total, $FAILED failed"

if [ "$FAILED" -eq 0 ]; then
    echo "UNITS-OPENWRT OK"
    exit 0
fi

echo "UNITS-OPENWRT FAILED:$FAILED_NAMES"
exit 1
