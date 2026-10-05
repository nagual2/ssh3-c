#!/bin/bash
# flake hunt: 10 runs, full logs both sides; WEDGE dirs are kept by wedge64k
for i in $(seq 1 10); do
    EXTRA_CLIENT_ARGS="-L all" EXTRA_SERVER_ARGS="-L all" \
    bash /mnt/c/Git/project/ssh3-c/interop/wedge64k.sh /mnt/c/Git/project/ssh3-c 65536 1 0 \
        > /tmp/hunt-$i.out 2>&1
    echo "run $i: $(grep -E 'attempt 1' /tmp/hunt-$i.out)"
done
echo "HUNT DONE"
