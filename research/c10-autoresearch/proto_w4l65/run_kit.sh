#!/usr/bin/env bash
# run_kit.sh [reps] — alternate draft 0.3 and w4l65 (both from the copy, generic v2 path) on the kit; flash-only.
set -u
D="$(cd "$(dirname "$0")/.." && pwd)"; cd "$D"; P=target/proto-w4l65
run() { SIGW=$5 timeout 400 bash $P/run_flash_sig.sh "$2" 0x30000000 96 60 > out/$1-run.log 2>&1
        echo "$1 $(python3 $P/evaluate_sig.py "$2.openocd.log" "$3" "$4")"; }
for i in $(seq 1 "${1:-3}"); do
  run d03-$i out/proto-d03.elf golden-v2.bin 4008 1002
  run w4l65-$i out/proto-w4l65.elf golden-v2-w4l65.bin 4712 1178
done
