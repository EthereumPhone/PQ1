#!/usr/bin/env bash
# run_kit.sh — d3l46 against draft 0.3 on the generic v2 path (both from the proto-d3 copy), fixed messages with the
# golden byte-compare; flash-only. Runner failures are retried once and stop the script non-zero.
set -u
D="$(cd "$(dirname "$0")/.." && pwd)"; cd "$D"; P=target/proto-d3
run() { # name elf golden siglen
  local rc
  for attempt in 1 2; do
    : > "$2.openocd.log"
    SIGW=$(( $4 / 4 )) timeout 400 bash $P/run_flash_sig.sh "$2" 0x30000000 96 60 > "out/$1-run.log" 2>&1; rc=$?
    [ $rc -eq 0 ] && break
  done
  [ $rc -eq 0 ] || { echo "$1 RUNNER FAILED rc=$rc"; return 1; }
  cp "$2.openocd.log" "out/$1.openocd.log"
  res=$(python3 $P/evaluate_sig.py "out/$1.openocd.log" "$3" "$4") || { echo "$1 EVALUATOR FAILED $res"; return 1; }
  echo "$1 $res"
}
for i in 1 2; do
  run d3-d03-$i out/proto-d3-d03.elf golden-v2.bin 4008 || exit 1
  run d3-d3l46-$i out/proto-d3-d3l46.elf golden-v2-d3l46.bin 4844 || exit 1
done
