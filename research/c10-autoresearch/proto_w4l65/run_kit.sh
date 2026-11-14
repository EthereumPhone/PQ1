#!/usr/bin/env bash
# run_kit.sh [reps] [f] — alternate draft 0.3 and w4l65 (both from the copy; generic v2 path, or with `f` the fused
# one-block driver of the hw copy) on the kit; flash-only.
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
if [ "${2:-}" = c ]; then     # round 17 gate (c): wprf2b against draft 0.3, generic and fused (Rust key loop)
  run d03 out/proto-d03.elf golden-v2.bin 4008 1002 || exit 1
  run wprf2b out/proto-wprf2b.elf golden-v2-wprf2b.bin 4008 1002 || exit 1
  run f-rk-d03 out/proto-f-rk-d03.elf golden-v2.bin 4008 1002 || exit 1
  run f-wprf2b out/proto-f-wprf2b.elf golden-v2-wprf2b.bin 4008 1002 || exit 1
  run f-d03 out/proto-f-d03.elf golden-v2.bin 4008 1002 || exit 1
  run f-w4l65 out/proto-f-w4l65.elf golden-v2-w4l65.bin 4712 1178 || exit 1
  for v in rk-d03 wprf2b; do
    e=out/proto-avg-f-$v.elf; : > "$e.openocd.log"
    SIGW=1002 timeout 600 bash $P/run_flash_sig.sh "$e" 0x30000000 96 240 > "out/avg-f-$v-run.log" 2>&1; rc=$?
    cp "$e.openocd.log" "out/avg-f-$v.openocd.log"
    [ $rc -eq 0 ] || { echo "avg-f-$v RUNNER FAILED rc=$rc"; exit 1; }
    python3 "$D/proto_w4l65/avg_parse.py" "out/avg-f-$v.openocd.log" "avg-f-$v" || exit 1
  done
  exit 0
fi
if [ "${2:-}" = avg ]; then   # fused, 16 messages per run (grind luck averaged); all 16 must verify
  for i in $(seq 1 "${1:-1}"); do for v in d03 w4l65; do
    e=out/proto-avg-f-$v.elf; w=1002; [ $v = w4l65 ] && w=1178; : > "$e.openocd.log"
    SIGW=$w timeout 600 bash $P/run_flash_sig.sh "$e" 0x30000000 96 240 > "out/avg-f-$v-$i-run.log" 2>&1; rc=$?
    cp "$e.openocd.log" "out/avg-f-$v-$i.openocd.log"
    [ $rc -eq 0 ] || { echo "avg-f-$v-$i RUNNER FAILED rc=$rc"; exit 1; }
    python3 "$D/proto_w4l65/avg_parse.py" "out/avg-f-$v-$i.openocd.log" "avg-f-$v-$i" || exit 1
  done; done
  exit 0
fi
M=""; [ "${2:-}" = f ] && M="f-"
for i in $(seq 1 "${1:-3}"); do
  run ${M}d03-$i out/proto-${M}d03.elf golden-v2.bin 4008 1002 || exit 1
  run ${M}w4l65-$i out/proto-${M}w4l65.elf golden-v2-w4l65.bin 4712 1178 || exit 1
done
