// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {ISPHINCSVerifier} from "../src/verifiers/ISPHINCSVerifier.sol";
import {SPHINCsC10v2All3Asm} from "../src/verifiers/SPHINCsC10v2All3Asm.sol";
import {SPHINCsC10v2Asm} from "../src/verifiers/SPHINCsC10v2Asm.sol";

/// RESEARCH (round 20): the full v2 stack (ts200 + prf2 + split810 + the merged two-block paired WOTS PRF; the top
/// cache and fmtKDF change no signature byte) is signer-side over all3, so the UNCHANGED all3 verifier must accept
/// its KATs (research/c10-autoresearch/c10v2/c10v2_ref.py --variant ts200,prf2,split810,wprf2b) and refuse the
/// +C-only near-misses and a corrupted signature; the 0.3 verifier (target 205, 9 + 9) must refuse them.
contract FullStackAll3Test is Test {
    address internal all3;
    address internal v03;

    function setUp() public {
        all3 = address(new SPHINCsC10v2All3Asm());
        v03 = address(new SPHINCsC10v2Asm());
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

    function test_all3_accepts_full_stack_kats() public view {
        string memory json = vm.readFile("test/c10v2_kat_vectors_all3-wprf2b.json");
        for (uint256 i = 0; i < 6; i++) {
            (bytes32 s, bytes32 r, bytes32 m, bytes memory sig) = _vec(json, string.concat("v", vm.toString(i)));
            assertEq(sig.length, 4008);
            assertTrue(_accepted(all3, s, r, m, sig), "all3 verifier refused a full-stack KAT");
            assertFalse(_accepted(v03, s, r, m, sig), "0.3 verifier accepted a full-stack KAT");
            sig[2336 + 5] ^= 0x01;
            assertFalse(_accepted(all3, s, r, m, sig), "all3 verifier accepted a corrupted full-stack signature");
        }
    }

    function test_all3_refuses_full_stack_near_misses() public view {
        string memory json = vm.readFile("test/c10v2_kat_vectors_all3-wprf2b.json");
        for (uint256 i = 0; i < 3; i++) {
            (bytes32 s, bytes32 r, bytes32 m, bytes memory sig) = _vec(json, string.concat("n", vm.toString(i)));
            assertFalse(_accepted(all3, s, r, m, sig), "all3 verifier accepted a +C-only near-miss");
        }
    }

    /// positive control: the all3 KATs themselves still pass this harness
    function test_all3_accepts_all3_kats() public view {
        string memory json = vm.readFile("test/c10v2_kat_vectors_all3.json");
        for (uint256 i = 0; i < 6; i++) {
            (bytes32 s, bytes32 r, bytes32 m, bytes memory sig) = _vec(json, string.concat("v", vm.toString(i)));
            assertTrue(_accepted(all3, s, r, m, sig));
        }
    }
}
