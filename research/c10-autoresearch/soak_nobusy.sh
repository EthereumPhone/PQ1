#!/usr/bin/env bash
# Soak: N full bench runs with the measurement-only no-busy-wait feature; every run must be byte-identical
# to golden (both signatures, pk_root, pass A == pass B, both verifies).
cd "$(dirname "$0")"
N=${1:-10}; ok=0
for i in $(seq 1 $N); do
  r=$(BENCH_FEATURES=no-busy-wait ./experiment_flash.sh 2>&1)
  echo "$r" | grep -q '"ok": true' && ok=$((ok+1))
  echo "run $i: $(echo "$r" | python3 -c 'import json,sys;r=json.load(sys.stdin);print(r.get("ok"), r.get("cached_sign"), r.get("why",""))')"
done
echo "SOAK_DONE $ok/$N byte-identical runs (each ~1.7M digests)"
