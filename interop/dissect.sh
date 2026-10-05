#!/bin/bash
# dissect the newest wedged run: terminal state of both sides
W=$(ls -dt /tmp/s3wedge-* 2>/dev/null | head -1)
echo "DIR=$W"
for side in cli srv; do
    F=$W/$side.err
    echo "=== $side: size $(stat -c%s $F) ==="
    echo "--- last stream flow lines"
    grep -E "quic stream id:0x0 flow (control|update)" "$F" | tail -n 4
    echo "--- last tx/rx packets"
    grep -E "quic packet (tx|rx)" "$F" | tail -n 4
    echo "--- last PTO / lost timer"
    grep -cE "quic pto app" "$F"
    grep -E "quic (pto app|lost timer)" "$F" | tail -n 4
    echo "--- detect_lost tail (evaluations near the end)"
    grep -E "quic detect_lost pnum" "$F" | tail -n 3
    echo "--- last 12 raw lines"
    tail -n 12 "$F"
done
