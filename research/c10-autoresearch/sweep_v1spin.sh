#!/usr/bin/env bash
# sweep_v1spin.sh <const-name> <values...> — set `const <NAME>: u32 = <v>;` in hw/src/hash.rs, run the v1 microbench,
# print the v1 per-digest figures; restores the original value at the end.
set -u
N=$1; shift; D="$(cd "$(dirname "$0")" && pwd)"; H="$D/../../hw/src/hash.rs"
orig=$(grep -oP "const $N: u32 = \K[0-9]+" "$H")
for v in "$@"; do
  sed -i "s/const $N: u32 = [0-9]*;/const $N: u32 = $v;/" "$H"
  r=$("$D/experiment_v1micro.sh")
  echo "$N=$v $(echo "$r" | python3 -c 'import json,sys; r=json.load(sys.stdin); print({k: r.get(k) for k in ("ok","chains16_keygen_per_digest","chains16_prf_only_per_chain","chain16_x15_per_step","fors_subtree16_per_digest","search128_prednever_per_try","search128_205_per_try","searchcheck_fail")})')"
done
sed -i "s/const $N: u32 = [0-9]*;/const $N: u32 = $orig;/" "$H"
