#!/bin/bash
# back-to-back 64K stress: keep full logs of every run, wedge or not
for i in 1 2 3 4 5; do
    EXTRA_CLIENT_ARGS="-L all" EXTRA_SERVER_ARGS="-L all" \
    bash /mnt/c/Git/project/ssh3-c/interop/wedge64k.sh /mnt/c/Git/project/ssh3-c 65536 1 0 \
        > /tmp/stress-$i.out 2>&1
    echo "run $i: $(grep -E 'attempt 1' /tmp/stress-$i.out)"
done
echo "STRESS DONE"
