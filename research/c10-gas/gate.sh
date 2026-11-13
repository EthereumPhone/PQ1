#!/usr/bin/env bash
# gate.sh — all semantic gates for the C10 gas track (see program.md). Exit 0 iff green.
# Usage: research/c10-gas/gate.sh [fuzz-runs]   (default 256)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SW="$ROOT/contracts/smart-wallet"
FORGE="${FORGE:-$HOME/.foundry/bin/forge}"
RUNS="${1:-256}"
cd "$SW"

echo "== text pin: the digit-sum snippet the unit test checks is in each verifier that uses it"
SNIP=$(grep -h 'C10-SWAR-DIGITSUM' test/gas/C10DigitSum.t.sol 2>/dev/null | sed 's/^ *//' | sort -u || true)
if [ -n "$SNIP" ]; then
  for f in src/verifiers/SPHINCsC10v2Asm.sol src/verifiers/SPHINCsC10Asm.sol; do
    if grep -q 'C10-SWAR-DIGITSUM' "$f"; then
      got=$(grep -h 'C10-SWAR-DIGITSUM' "$f" | sed 's/^ *//' | sort -u)
      [ "$got" = "$SNIP" ] || { echo "FAIL: $f digit-sum snippet differs from the unit-tested one"; exit 1; }
      echo "  ok $f"
    fi
  done
fi

echo "== equivalence + per-primitive + unit + gas bench (fuzz runs $RUNS)"
LOG="${GATE_LOG:-$(mktemp -t c10-gas-gate.XXXXXX)}"
rc=0
FOUNDRY_FUZZ_RUNS="$RUNS" "$FORGE" test --match-path 'test/gas/*.t.sol' -vv >"$LOG" 2>&1 || rc=$?
grep -E '(Suite result|GAS |SIZE |FAIL)' "$LOG" | sed 's/^ */  /'
[ "$rc" -eq 0 ] || { echo "FAIL: test/gas suites (log $LOG)"; exit 1; }

echo "== existing verifier suites (minus the v1 codehash freeze, a pin)"
"$FORGE" test --match-path 'test/SPHINCsC10*.t.sol' --no-match-test 'test_verifierBytecodeFrozen' | grep -E '^Suite result'
"$FORGE" test --match-path 'test/C10PrimitiveKat.t.sol' | grep -E '^Suite result'
echo "GATE GREEN"
