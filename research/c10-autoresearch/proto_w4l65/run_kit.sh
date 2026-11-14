#!/usr/bin/env bash
# run_kit.sh [reps] — alternate draft 0.3 and w4l65 (both from the copy, generic v2 path) on the kit; flash-only.
# Any runner or evaluator failure stops the script non-zero; each repetition keeps its own OpenOCD log.
set -u
D="$(cd "$(dirname "$0")/.." && pwd)"; cd "$D"; P=target/proto-w4l65
run() { # name elf golden siglen sigwords
  local log="$2.openocd.log" res rc
  : > "$log"
  SIGW=$5 timeout 400 bash $P/run_flash_sig.sh "$2" 0x30000000 96 60 > "out/$1-run.log" 2>&1; rc=$?
  cp "$log" "out/$1.openocd.log"
  [ $rc -eq 0 ] || { echo "$1 RUNNER FAILED rc=$rc"; return 1; }
  res=$(python3 $P/evaluate_sig.py "out/$1.openocd.log" "$3" "$4"); rc=$?
  [ $rc -eq 0 ] || { echo "$1 EVALUATOR FAILED $res"; return 1; }
  echo "$1 $res"
}
for i in $(seq 1 "${1:-3}"); do
  run d03-$i out/proto-d03.elf golden-v2.bin 4008 1002 || exit 1
  run w4l65-$i out/proto-w4l65.elf golden-v2-w4l65.bin 4712 1178 || exit 1
done
