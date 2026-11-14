// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {ISPHINCSVerifier} from "../src/verifiers/ISPHINCSVerifier.sol";
import {SPHINCsC10v2All3Asm} from "../src/verifiers/SPHINCsC10v2All3Asm.sol";
import {SPHINCsC10v2Asm} from "../src/verifiers/SPHINCsC10v2Asm.sol";
import {SPHINCsC10v2Split810Asm} from "../src/verifiers/SPHINCsC10v2Split810Asm.sol";
import {SPHINCsC10v2Ts200Asm} from "../src/verifiers/SPHINCsC10v2Ts200Asm.sol";

/// RESEARCH (round 21): the no-prf2 candidate (v2 0.3 + ts200 + split810 + the unpaired two-block WOTS PRF; the
/// top cache and fmtKDF change no signature byte). Its verifier rules are ts200's target sum (200) and split810's
/// heights and A7 layout; wprf2b is signer-side. So the UNCHANGED all3 verifier is the right one and must accept its
/// KATs (c10v2_ref.py --variant ts200,split810,wprf2b) and refuse its +C-only near-misses and a corrupted signature;
/// the 0.3 (205; 9 + 9), split810 (205; 8 + 10) and ts200 (200; 9 + 9) verifiers must refuse them. Positive
/// controls: each refusing verifier accepts its own format's KATs, so a refusal is not a broken deployment.
contract NoPrf2All3Test is Test {
    address internal all3;
    address internal v03;
    address internal s810;
    address internal t200;

    function setUp() public {
        all3 = address(new SPHINCsC10v2All3Asm());
        v03 = address(new SPHINCsC10v2Asm());
        s810 = address(new SPHINCsC10v2Split810Asm());
        t200 = address(new SPHINCsC10v2Ts200Asm());
    }

    function _vec(string memory json, string memory k) internal pure returns (bytes32 s, bytes32 r, bytes32 m, bytes memory sig) {
        s = vm.parseJsonBytes32(json, string.concat(".", k, ".pkSeed"));
        r = vm.parseJsonBytes32(json, string.concat(".", k, ".pkRoot"));
        m = vm.parseJsonBytes32(json, string.concat(".", k, ".message"));
        sig = vm.parseJsonBytes(json, string.concat(".", k, ".signature"));
    }

    function _accepted(address v, bytes32 s, bytes32 r, bytes32 m, bytes memory sig) internal view returns (bool) {
        (bool ok, bytes memory ret) = v.staticcall(abi.encodeWithSelector(ISPHINCSVerifier.verify.selector, s, r, m, sig));
        return ok && ret.length == 32 && abi.decode(ret, (bool));
    }

    function test_all3_accepts_noprf2_kats_others_refuse() public view {
        string memory json = vm.readFile("test/c10v2_kat_vectors_ts200-split810-wprf2b.json");
        for (uint256 i = 0; i < 6; i++) {
            (bytes32 s, bytes32 r, bytes32 m, bytes memory sig) = _vec(json, string.concat("v", vm.toString(i)));
            assertEq(sig.length, 4008);
            assertTrue(_accepted(all3, s, r, m, sig), "all3 verifier refused a no-prf2 KAT");
            assertFalse(_accepted(v03, s, r, m, sig), "0.3 verifier accepted a no-prf2 KAT");
            assertFalse(_accepted(s810, s, r, m, sig), "split810 verifier accepted a no-prf2 KAT");
            assertFalse(_accepted(t200, s, r, m, sig), "ts200 verifier accepted a no-prf2 KAT");
            sig[2336 + 5] ^= 0x01;
            assertFalse(_accepted(all3, s, r, m, sig), "all3 verifier accepted a corrupted no-prf2 signature");
        }
    }

    function test_all3_refuses_noprf2_near_misses() public view {
        string memory json = vm.readFile("test/c10v2_kat_vectors_ts200-split810-wprf2b.json");
        for (uint256 i = 0; i < 3; i++) {
            (bytes32 s, bytes32 r, bytes32 m, bytes memory sig) = _vec(json, string.concat("n", vm.toString(i)));
            assertFalse(_accepted(all3, s, r, m, sig), "all3 verifier accepted a +C-only near-miss");
        }
    }

    function test_positive_controls_each_verifier_accepts_its_own_format() public view {
        string[3] memory files =
            ["test/c10v2_kat_vectors.json", "test/c10v2_kat_vectors_split810.json", "test/c10v2_kat_vectors_ts200.json"];
        address[3] memory vs = [v03, s810, t200];
        for (uint256 f = 0; f < 3; f++) {
            string memory json = vm.readFile(files[f]);
            for (uint256 i = 0; i < 6; i++) {
                (bytes32 s, bytes32 r, bytes32 m, bytes memory sig) = _vec(json, string.concat("v", vm.toString(i)));
                assertTrue(_accepted(vs[f], s, r, m, sig), "a verifier refused its own format's KAT");
            }
        }
    }
}
