#!/usr/bin/env bash
# variant_controls.sh — #1155 format-variant security check (2026-11-13), mutation controls for the
# RESEARCH variant verifiers SPHINCsC10v2{Ts200,Split810,All3}Asm.sol (Solidity only; modelled on
# nearmiss_controls.sh). Each configuration copies nothing new into the tree except the probe test:
# it applies ONE exact-once textual mutation to one variant verifier (or a stated stack of them),
# runs the probe, and restores the file from a copy (and on exit, via trap).
#
# Probe line per configuration:
#   own=k/6   how many of the variant's own KATs (v0..v5) the verifier accepts
#   n0 n1 n2  1 = that +C-only near-miss is ACCEPTED (n0 breaks FORS+C, n1/n2 the WOTS digit sum)
#   x03=k/6   how many draft-0.3 KATs (c10v2_kat_vectors.json) it accepts
# A missing PROBE line (e.g. a mutation that does not compile) prints ERROR, never "rejected".
#
# Expected: unmutated own=6/6, no near-miss accepted, x03=0/6; no WOTS sum -> exactly n1 n2;
# no FORS+C -> exactly n0; target 200->205 -> own=0/6 (and for ts200, x03=6/6: the mutant IS 0.3);
# any split810 layout revert -> own=0/6; all layout reverts stacked -> own=0/6, x03=6/6 for split810.
set -u
D="$(cd "$(dirname "$0")" && pwd)"; R="$(cd "$D/../.." && pwd)"; T="$(mktemp -d)"
SW="$R/contracts/smart-wallet"; VD="$SW/src/verifiers"
declare -A F=([ts200]="$VD/SPHINCsC10v2Ts200Asm.sol" [split810]="$VD/SPHINCsC10v2Split810Asm.sol" [all3]="$VD/SPHINCsC10v2All3Asm.sol")
PS="$SW/test/ZzVariantCtlProbe.t.sol"
for k in ts200 split810 all3; do cp "${F[$k]}" "$T/$k"; done
sha() { sha256sum "${F[ts200]}" "${F[split810]}" "${F[all3]}" | awk '{print $1}' | tr '\n' ' '; }
BEFORE="$(sha)"
restore() { for k in ts200 split810 all3; do cp "$T/$k" "${F[$k]}"; done; rm -f "$PS"; }
trap restore EXIT
cat > "$PS" <<'SOL'
// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
import {Test, console2} from "forge-std/Test.sol";
import {SPHINCsC10v2Ts200Asm} from "../src/verifiers/SPHINCsC10v2Ts200Asm.sol";
import {SPHINCsC10v2Split810Asm} from "../src/verifiers/SPHINCsC10v2Split810Asm.sol";
import {SPHINCsC10v2All3Asm} from "../src/verifiers/SPHINCsC10v2All3Asm.sol";
contract ZzVariantCtlProbe is Test {
    function _acc(address v, string memory json, string memory k) internal view returns (bool) {
        bytes32 s = vm.parseJsonBytes32(json, string.concat(k, ".pkSeed"));
        bytes32 r = vm.parseJsonBytes32(json, string.concat(k, ".pkRoot"));
        bytes32 m = vm.parseJsonBytes32(json, string.concat(k, ".message"));
        bytes memory sig = vm.parseJsonBytes(json, string.concat(k, ".signature"));
        (bool ok, bytes memory ret) = v.staticcall(abi.encodeWithSignature("verify(bytes32,bytes32,bytes32,bytes)", s, r, m, sig));
        return ok && ret.length == 32 && abi.decode(ret, (bool));
    }
    function test_probe() public {
        bytes32 w = keccak256(bytes(vm.envString("PROBE_V")));
        address v; string memory path;
        if (w == keccak256("ts200")) { v = address(new SPHINCsC10v2Ts200Asm()); path = "test/c10v2_kat_vectors_ts200.json"; }
        else if (w == keccak256("split810")) { v = address(new SPHINCsC10v2Split810Asm()); path = "test/c10v2_kat_vectors_split810.json"; }
        else if (w == keccak256("all3")) { v = address(new SPHINCsC10v2All3Asm()); path = "test/c10v2_kat_vectors_all3.json"; }
        else revert("PROBE_V");
        require(v.code.length > 0, "not deployed");
        string memory own = vm.readFile(path);
        string memory x03 = vm.readFile("test/c10v2_kat_vectors.json");
        uint256 nOwn; uint256 nX;
        for (uint256 i = 0; i < 6; i++) {
            if (_acc(v, own, string.concat(".v", vm.toString(i)))) nOwn++;
            if (_acc(v, x03, string.concat(".v", vm.toString(i)))) nX++;
        }
        string memory nm = "";
        for (uint256 i = 0; i < 3; i++) {
            nm = string.concat(nm, " n", vm.toString(i), "=", _acc(v, own, string.concat(".n", vm.toString(i))) ? "1" : "0");
        }
        console2.log(string.concat("PROBE own=", vm.toString(nOwn), "/6", nm, " x03=", vm.toString(nX), "/6"));
    }
}
SOL
probe() {
  local out n
  out="$(cd "$SW" && PROBE_V="$1" PATH="$HOME/.foundry/bin:$PATH" forge test --match-contract ZzVariantCtlProbe -vv 2>&1)"
  n="$(printf '%s\n' "$out" | grep -c 'PROBE own=')"
  if [ "$n" != 1 ]; then echo "ERROR (no probe line: $(printf '%s\n' "$out" | grep -m1 -i 'error' | sed 's/^ *//'))"; return; fi
  printf '%s\n' "$out" | grep 'PROBE own=' | sed 's/^ *PROBE //'
}
SUBFAIL=0
sub() { python3 - "$1" "$2" "$3" <<'PY' || SUBFAIL=1
import sys; p, a, b = sys.argv[1:]; s = open(p).read(); assert s.count(a) == 1, (p, a, s.count(a)); open(p, 'w').write(s.replace(a, b))
PY
}
WOTS_A='if iszero(eq(digitSum, 200)) { revert(0, 0) }'; WOTS_B='if and(0, iszero(eq(digitSum, 200))) { revert(0, 0) }'
WOTS5_A='if iszero(eq(digitSum, 205)) { revert(0, 0) }'; WOTS5_B='if and(0, iszero(eq(digitSum, 205))) { revert(0, 0) }'
FORS_A='if and(shr(132, digest), 0x7FF) { revert(0, 0) }'; FORS_B='if and(0, and(shr(132, digest), 0x7FF)) { revert(0, 0) }'
# Each row asserts its expected result (Astra review, 2026-11-13: the controls used to print without checking).
BAD=0
row() { # $1 variant, $2 label, $3 expected probe result
  local got
  if [ "$SUBFAIL" = 1 ]; then printf '%-9s %-38s %s\n' "$1" "$2" "ERROR (mutation did not apply exactly once)"; SUBFAIL=0; BAD=$((BAD + 1)); return; fi
  got="$(probe "$1")"
  if [ "$got" = "$3" ]; then printf '%-9s %-38s %s  ok\n' "$1" "$2" "$got"
  else printf '%-9s %-38s %s  UNEXPECTED (want %s)\n' "$1" "$2" "$got" "$3"; BAD=$((BAD + 1)); fi
}
U='own=6/6 n0=0 n1=0 n2=0 x03=0/6'; WD='own=6/6 n0=0 n1=1 n2=1 x03=0/6'; FD='own=6/6 n0=1 n1=0 n2=0 x03=0/6'
DEAD='own=0/6 n0=0 n1=0 n2=0 x03=0/6'
layout_rows() { # $1 = split810 | all3
  local f="${F[$1]}"
  sub "$f" 'shl(23, i))' 'shl(24, i))';                 row "$1" "kp shift 23->24 (FORS addresses)" "$DEAD";   cp "$T/$1" "$f"
  sub "$f" 'shl(23, idxLeaf)' 'shl(24, idxLeaf)';       row "$1" "kp shift 23->24 (hypertree)" "$DEAD";        cp "$T/$1" "$f"
  sub "$f" 'shl(17, i)' 'shl(18, i)';                   row "$1" "ci shift 17->18" "$DEAD";                    cp "$T/$1" "$f"
  sub "$f" 'let hl := add(8, shl(1, layer))' 'let hl := 9'; row "$1" "layer heights (8,10)->(9,9)" "$DEAD";      cp "$T/$1" "$f"
  sub "$f" 'shl(23, i))' 'shl(24, i))'; sub "$f" 'shl(23, idxLeaf)' 'shl(24, idxLeaf)'
  sub "$f" 'shl(17, i)' 'shl(18, i)'; sub "$f" 'let hl := add(8, shl(1, layer))' 'let hl := 9'
  # all four reverted = the 0.3 layout: split810 then accepts 0.3 KATs; all3 still has target 200
  if [ "$1" = split810 ]; then row "$1" "ALL four layout reverts stacked" 'own=0/6 n0=0 n1=0 n2=0 x03=6/6'
  else row "$1" "ALL four layout reverts stacked" "$DEAD"; fi
  cp "$T/$1" "$f"
}
echo "variant   configuration                          result"
for k in ts200 all3; do
  f="${F[$k]}"
  # ts200 keeps 0.3's keys, so with its digit-sum check gone (or set to 205) it accepts the 0.3 KATs
  if [ "$k" = ts200 ]; then WX='own=6/6 n0=0 n1=1 n2=1 x03=6/6'; TX='own=0/6 n0=0 n1=0 n2=0 x03=6/6'; else WX="$WD"; TX="$DEAD"; fi
  row "$k" "unmutated" "$U"
  sub "$f" "$WOTS_A" "$WOTS_B";                         row "$k" "WOTS digit-sum revert deleted" "$WX";      cp "$T/$k" "$f"
  sub "$f" "$FORS_A" "$FORS_B";                         row "$k" "FORS+C revert deleted" "$FD";              cp "$T/$k" "$f"
  sub "$f" 'eq(digitSum, 200)' 'eq(digitSum, 205)';     row "$k" "target 200->205" "$TX";                    cp "$T/$k" "$f"
  [ "$k" = all3 ] && layout_rows all3
done
f="${F[split810]}"
row split810 "unmutated" "$U"
sub "$f" "$WOTS5_A" "$WOTS5_B";                         row split810 "WOTS digit-sum revert deleted" "$WD";  cp "$T/split810" "$f"
sub "$f" "$FORS_A" "$FORS_B";                           row split810 "FORS+C revert deleted" "$FD";          cp "$T/split810" "$f"
layout_rows split810
restore
AFTER="$(sha)"
if [ "$BEFORE" = "$AFTER" ] && [ ! -e "$PS" ]; then echo "restored: OK (sha256 of the 3 variant files unchanged, probe removed)"
else echo "restored: MISMATCH"; echo " before $BEFORE"; echo " after  $AFTER"; exit 1; fi
if [ "$BAD" != 0 ]; then echo "FAIL: $BAD configuration(s) not as expected"; exit 1; fi
echo "PASS: every configuration as expected"
