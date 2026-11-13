#!/usr/bin/env bash
# gate.sh — all semantic gates for the C10 gas track (see program.md). Exit 0 iff green.
# Usage: research/c10-gas/gate.sh [fuzz-runs]   (default 256)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SW="$ROOT/contracts/smart-wallet"
FORGE="${FORGE:-$HOME/.foundry/bin/forge}"
RUNS="${1:-256}"
cd "$SW"

echo "== text pin: the digit-sum lines the unit test checks are, in order, the only tagged lines of each verifier"
TAG='// C10-SWAR-DIGITSUM$'
SNIP=$(grep -h "$TAG" test/gas/C10DigitSum.t.sol | sed 's/^ *//')
[ -n "$SNIP" ] || { echo "FAIL: no tagged lines in the unit test"; exit 1; }
for f in src/verifiers/SPHINCsC10v2Asm.sol src/verifiers/SPHINCsC10Asm.sol; do
  got=$(grep -h "$TAG" "$f" | sed 's/^ *//')
  [ "$got" = "$SNIP" ] || { echo "FAIL: $f digit-sum lines differ from (or are missing vs) the unit-tested ones"; exit 1; }
  echo "  ok $f"
done

echo "== generated blocks match their generators"
python3 "$ROOT/research/c10-gas/gen_v2_chains.py" --check src/verifiers/SPHINCsC10v2Asm.sol && echo "  ok v2 chains"
python3 "$ROOT/research/c10-gas/derive_v2_variants.py" --check && echo "  ok v2 variants derived from the 0.3 candidate"

echo "== equivalence + per-primitive + unit + gas bench (fuzz runs $RUNS)"
LOG="${GATE_LOG:-$(mktemp -t c10-gas-gate.XXXXXX)}"
rc=0
FOUNDRY_FUZZ_RUNS="$RUNS" "$FORGE" test --match-path 'test/gas/*.t.sol' -vv >"$LOG" 2>&1 || rc=$?
grep -E '(Suite result|GAS |SIZE |FAIL)' "$LOG" | sed 's/^ */  /'
[ "$rc" -eq 0 ] || { echo "FAIL: test/gas suites (log $LOG)"; exit 1; }

echo "== gas under the deploy profile (runs=999999; production build), separate build dir"
DB="${DEPLOY_BUILD:-$HOME/.cache/c10-gas-deploy}"
FOUNDRY_PROFILE=deploy "$FORGE" test --out "$DB/out" --cache-path "$DB/cache" \
  --match-path 'test/gas/C10GasBench.t.sol' --match-test 'test_gas_v|test_gas_variants' -vv | grep -E '(GAS .*callee-only|SIZE )' | sed 's/^ */  deploy: /'

if [ "${DEPLOY_EQUIV:-1}" = 1 ]; then
  echo "== equivalence + per-primitive + unit gates under the deploy profile (ref v1 anchored to the deploy pin)"
  FOUNDRY_PROFILE=deploy FOUNDRY_FUZZ_RUNS="$RUNS" "$FORGE" test --out "$DB/out" --cache-path "$DB/cache" \
    --match-path 'test/gas/C10*.t.sol' --no-match-path 'test/gas/C10GasBench.t.sol' >"$LOG.deploy" 2>&1 \
    || { grep -E 'FAIL' "$LOG.deploy" | head; echo "FAIL: deploy-profile gates (log $LOG.deploy)"; exit 1; }
  grep -E 'Suite result' "$LOG.deploy" | sed 's/^ */  deploy: /'
fi

echo "== existing verifier suites (minus the v1 codehash freeze, a pin)"
"$FORGE" test --match-path 'test/SPHINCsC10*.t.sol' --no-match-test 'test_verifierBytecodeFrozen' | grep -E '^Suite result'
"$FORGE" test --match-path 'test/C10PrimitiveKat.t.sol' | grep -E '^Suite result'
echo "GATE GREEN"
