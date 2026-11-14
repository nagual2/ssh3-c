#!/bin/sh
# the windows-core livetest (the mingw cross build gate): the preset
# configure + the build + the ctest of the windows-core suite, the
# .exe riders run through the WSL interop
#
# the verdict: WINDOWS-CORE OK / FAILED
#
# usage: tests/livetest-windows-core.sh [repo-root]   (WSL)
set -u

ROOT=${1:-$(cd "$(dirname "$0")/.." && pwd)}
BUILD=${BUILD:-$ROOT/build/windows-core}

echo "== uname: $(uname -a)"
echo "== preset: windows-core (the mingw-w64 cross)"

cd "$ROOT" || exit 1

cmake --preset windows-core > /dev/null 2>&1 || {
    echo "WINDOWS-CORE FAILED: the preset configure did not pass"
    exit 1
}

cmake --build "$BUILD" -j "$(nproc)" 2>&1 | tail -1

out=$(ctest --test-dir "$BUILD" -j 4 2>&1)
echo "$out" | grep -E 'tests passed|Total Test time' | head -2

failed=$(echo "$out" | sed -n 's/.* \([0-9][0-9]*\) tests failed.*/\1/p')
failed=${failed:-0}

if [ "$failed" = "0" ]; then
    echo "WINDOWS-CORE OK"
    exit 0
fi

echo "WINDOWS-CORE FAILED: $failed test(s)"
echo "rerun: ctest --test-dir $BUILD --rerun-failed --output-on-failure"
exit 1
