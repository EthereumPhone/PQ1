#!/usr/bin/env bash
# run_set.sh SPEC... — round 18 kit runner (flash-only). SPEC = fix:NAME:ELF:GOLDEN:SIGLEN (fixed messages, golden
# byte-compare) or avg:NAME:ELF:SIGLEN (16 messages, all verified). A runner failure is retried once (host load
# from Track B's forge can starve probe-rs) before it counts; any failure stops the script non-zero.
set -u
D="$(cd "$(dirname "$0")/.." && pwd)"; cd "$D"; P=target/proto-w4l65
flash() { # elf sigw tmo log
  local rc
  for attempt in 1 2; do
    : > "$1.openocd.log"
    SIGW=$2 timeout 600 bash $P/run_flash_sig.sh "$1" 0x30000000 96 "$3" > "$4" 2>&1; rc=$?
    [ $rc -eq 0 ] && return 0
    echo "  (attempt $attempt rc=$rc; retrying)" >&2
  done
  return $rc
}
for s in "$@"; do
  IFS=: read -r kind name elf a b <<< "$s"
  if [ "$kind" = fix ]; then
    sl=$b; w=$(( sl / 4 ))
    flash "$elf" $w 60 "out/$name-run.log" || { echo "$name RUNNER FAILED"; exit 1; }
    cp "$elf.openocd.log" "out/$name.openocd.log"
    res=$(python3 $P/evaluate_sig.py "out/$name.openocd.log" "$a" "$sl") || { echo "$name EVALUATOR FAILED $res"; exit 1; }
    echo "$name $res"
  elif [ "$kind" = res ]; then   # res:NAME:ELF:CASES:MASK — residue suite: status DONE, stage 401, case count, mask
    flash "$elf" 1002 300 "out/$name-run.log" || { echo "$name RUNNER FAILED"; exit 1; }
    cp "$elf.openocd.log" "out/$name.openocd.log"
    python3 - "out/$name.openocd.log" "$name" "$a" "$b" <<'PY' || exit 1
import json, sys
L = open(sys.argv[1]).read().splitlines()
w = next(([int(x, 16) for x in l.split()[1:]] for l in L if l.startswith('RESULT_WORDS 0x')), None)
o = w[64:96] if w else [0] * 32
r = dict(run=sys.argv[2], status=hex(w[0]) if w else None, stage=o[1], cases=o[2], mask=hex(o[3]),
         want_cases=int(sys.argv[3]), want_mask=sys.argv[4])
r['ok'] = bool(w) and w[0] == 0x444F4E45 and o[1] == 401 and o[2] == int(sys.argv[3]) and o[3] == int(sys.argv[4], 0)
print(json.dumps(r)); sys.exit(0 if r['ok'] else 1)
PY
  elif [ "$kind" = chain ]; then # chain:NAME:ELF:SIGLEN:EXPECT_OK — the FI chain mirror over 16 messages
    flash "$elf" $(( a / 4 )) 600 "out/$name-run.log" || { echo "$name RUNNER FAILED"; exit 1; }
    cp "$elf.openocd.log" "out/$name.openocd.log"
    python3 - "out/$name.openocd.log" "$name" "$b" <<'PY' || exit 1
import json, sys
L = open(sys.argv[1]).read().splitlines()
w = next(([int(x, 16) for x in l.split()[1:]] for l in L if l.startswith('RESULT_WORDS 0x')), None)
r = {'run': sys.argv[2], 'ok': False}
if not w or w[0] != 0x444F4E45: r['why'] = 'status %s' % (hex(w[0]) if w else None); print(json.dumps(r)); sys.exit(1)
o = w[64:96]
names = ['rate_cfi', 'optrand', 'shuffle', 'sign_a', 'delay1', 'sign_b', 'ct_eq', 'delay2', 'verify', 'verify_gate', 'cfi_check', 'tail', 'release_copy']
r.update(keygen=o[2], chains_ok=o[3], want_ok=int(sys.argv[3]), phases=dict(zip(names, o[4:17])), chain_mean=o[17])
r['ok'] = o[0] == 0x43484E31 and o[1] == 100 and o[3] == int(sys.argv[3])
print(json.dumps(r)); sys.exit(0 if r['ok'] else 1)
PY
  else
    w=$(( a / 4 ))
    flash "$elf" $w 240 "out/$name-run.log" || { echo "$name RUNNER FAILED"; exit 1; }
    cp "$elf.openocd.log" "out/$name.openocd.log"
    python3 "$D/proto_w4l65/avg_parse.py" "out/$name.openocd.log" "$name" || exit 1
  fi
done
