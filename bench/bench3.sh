#!/bin/bash
# bench three stream_buffer_size arms on the fixed tree, then restore the harness
cd /mnt/c/Git/project/ssh3-c || exit 1

for buf in 16384 65536 1048576; do
    sed -i -E "s/stream_buffer_size = [0-9]+;/stream_buffer_size = $buf;/" \
        interop/interop_client.c interop/interop_server.c
    cmake --build --preset linux-release -j4 > /dev/null 2>&1
    OUT=$( { time -p bash /mnt/c/Git/project/ssh3-c/interop/wedge64k.sh /mnt/c/Git/project/ssh3-c 65536 1 0; } 2>&1 )
    RES=$(echo "$OUT" | grep -E "attempt 1" | head -1)
    REAL=$(echo "$OUT" | grep -E "^real" | head -1)
    echo "[$buf] $RES | $REAL"
done

git -C /mnt/c/Git/project/ssh3-c checkout -- interop/
cmake --build --preset linux-release -j4 > /dev/null 2>&1
echo "harness restored: $(git status --porcelain interop/ | wc -l) dirty files"