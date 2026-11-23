#!/bin/bash
# Show only when signal classification changes per frequency
tail -f /opt/rf-edge/logs/monitor_*.log 2>/dev/null | awk '
{
    freq = $4
    sig = $10
    if (last[freq] != sig) {
        print
        last[freq] = sig
    }
}
'
