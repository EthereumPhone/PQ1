#!/usr/bin/env bash
# nearmiss_controls.sh — #1155 spec §7 gate 3, mutation controls for the +C-only near-miss vectors
# (c10v2/nearmiss-v2-draft03.txt, contracts/smart-wallet/test/c10v2_kat_vectors.json n0..n2).
# For Rust and Solidity: unmutated, all three are rejected; with the WOTS digit-sum check deleted exactly
# wots0/wots1 (n1/n2) are accepted; with the FORS+C check deleted exactly fors (n0) is. Each verifier file
# is restored from a copy after every run (and on exit). Prints one line per configuration.
set -u
D="$(cd "$(dirname "$0")" && pwd)"; R="$(cd "$D/../.." && pwd)"; T="$(mktemp -d)"
W="$R/sphincs-c10/src/wots.rs"; HT="$R/sphincs-c10/src/hypertree.rs"; Y="$R/contracts/smart-wallet/src/verifiers/SPHINCsC10v2Asm.sol"
cp "$W" "$T/w"; cp "$HT" "$T/h"; cp "$Y" "$T/y"
PR="$R/sphincs-c10/tests/zz_nm_probe.rs"; PS="$R/contracts/smart-wallet/test/ZzNmProbe.t.sol"
restore() { cp "$T/w" "$W"; cp "$T/h" "$HT"; cp "$T/y" "$Y"; rm -f "$PR" "$PS"; }
trap restore EXIT
cat > "$PR" <<'RS'
#![cfg(feature = "v2")]
use sphincs_c10::params::{N, SIGNATURE_LEN, VERIFYING_KEY_LEN};
use sphincs_c10::VerifyingKey;
fn hex(s: &str) -> Vec<u8> { (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect() }
#[test]
fn probe() {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../research/c10-autoresearch/c10v2/nearmiss-v2-draft03.txt")).unwrap();
    for line in text.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        let mut vk = [0u8; VERIFYING_KEY_LEN];
        vk[..N].copy_from_slice(&hex(f[1])); vk[N..].copy_from_slice(&hex(f[2]));
        let msg: [u8; 32] = hex(f[3]).try_into().unwrap();
        let sig: [u8; SIGNATURE_LEN] = hex(f[4]).try_into().unwrap();
        println!("PROBE {} accepted={}", f[0], VerifyingKey::from_bytes(&vk).verify(&msg, &sig));
    }
}
RS
cat > "$PS" <<'SOL'
// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
import {Test, console2} from "forge-std/Test.sol";
import {SPHINCsC10v2Asm} from "../src/verifiers/SPHINCsC10v2Asm.sol";
contract ZzNmProbe is Test {
    function test_probe() public {
        SPHINCsC10v2Asm v2 = new SPHINCsC10v2Asm();
        string memory json = vm.readFile("test/c10v2_kat_vectors.json");
        for (uint256 i = 0; i < 3; i++) {
            string memory k = string.concat(".n", vm.toString(i));
            bytes32 s = vm.parseJsonBytes32(json, string.concat(k, ".pkSeed"));
            bytes32 r = vm.parseJsonBytes32(json, string.concat(k, ".pkRoot"));
            bytes32 m = vm.parseJsonBytes32(json, string.concat(k, ".message"));
            bytes memory sig = vm.parseJsonBytes(json, string.concat(k, ".signature"));
            (bool ok, bytes memory ret) = address(v2).staticcall(abi.encodeWithSelector(v2.verify.selector, s, r, m, sig));
            bool acc = ok && ret.length == 32 && abi.decode(ret, (bool));
            console2.log(string.concat("PROBE n", vm.toString(i), " accepted=", acc ? "true" : "false"));
        }
    }
}
SOL
rust() { (cd "$R" && cargo test -p sphincs-c10 --features v2 --release --test zz_nm_probe -- --nocapture 2>&1 | grep PROBE | tr '\n' ' '); echo; }
sol() { (cd "$R/contracts/smart-wallet" && PATH="$HOME/.foundry/bin:$PATH" forge test --match-contract ZzNmProbe -vv 2>&1 | grep PROBE | sed 's/^ *//' | tr '\n' ' '); echo; }
sub() { python3 - "$1" "$2" "$3" <<'PY'
import sys; p, a, b = sys.argv[1:]; s = open(p).read(); assert s.count(a) == 1, a; open(p, 'w').write(s.replace(a, b))
PY
}
echo "rust unmutated:    $(rust)"
sub "$W" '    if sum != TARGET_SUM {' '    if false && sum != TARGET_SUM {'; echo "rust no WOTS sum:  $(rust)"; restore_one=; cp "$T/w" "$W"
sub "$HT" '    if fors_indices[K - 1] != 0 {' '    if false && fors_indices[K - 1] != 0 {'; echo "rust no FORS+C:    $(rust)"; cp "$T/h" "$HT"
echo "sol unmutated:     $(sol)"
sub "$Y" 'if iszero(eq(digitSum, 205)) { revert(0, 0) }' 'if and(0, iszero(eq(digitSum, 205))) { revert(0, 0) }'; echo "sol no WOTS sum:   $(sol)"; cp "$T/y" "$Y"
sub "$Y" 'if and(shr(132, digest), 0x7FF) { revert(0, 0) }' 'if and(0, and(shr(132, digest), 0x7FF)) { revert(0, 0) }'; echo "sol no FORS+C:     $(sol)"; cp "$T/y" "$Y"
