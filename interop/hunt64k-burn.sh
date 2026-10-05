#!/bin/bash
# flake hunt under CPU pressure: 3 burners + full logs both sides
for i in $(seq 1 12); do
    nohup yes > /dev/null 2>&1 &
    nohup yes > /dev/null 2>&1 &
    nohup yes > /dev/null 2>&1 &
    EXTRA_CLIENT_ARGS="-L all" EXTRA_SERVER_ARGS="-L all" \
    bash /mnt/c/Git/project/ssh3-c/interop/wedge64k.sh /mnt/c/Git/project/ssh3-c 65536 1 0 \
        > /tmp/huntb-$i.out 2>&1
    pkill -x yes 2>/dev/null
    echo "run $i: $(grep -E 'attempt 1' /tmp/huntb-$i.out)"
done
echo "HUNT-BURN DONE"
