// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, console2} from "forge-std/Test.sol";
import {SPHINCsC10v2Asm} from "../src/verifiers/SPHINCsC10v2Asm.sol";
import {SPHINCsC10Asm} from "../src/verifiers/SPHINCsC10Asm.sol";

/// RESEARCH (#1155): the v2 verifier against the Python reference KATs
/// (research/c10-autoresearch/c10v2/c10v2_ref.py, spec DRAFT 0.2), which the
/// Rust v2 signer reproduces byte for byte.
contract SPHINCsC10v2AsmTest is Test {
    SPHINCsC10v2Asm internal v2;
    SPHINCsC10Asm internal v1;
    string internal json;

    function setUp() public {
        v2 = new SPHINCsC10v2Asm();
        v1 = new SPHINCsC10Asm();
        json = vm.readFile("test/c10v2_kat_vectors.json");
    }

    function _vec(string memory k)
        internal
        view
        returns (bytes32 s, bytes32 r, bytes32 m, bytes memory sig)
    {
        s = vm.parseJsonBytes32(json, string.concat(".", k, ".pkSeed"));
        r = vm.parseJsonBytes32(json, string.concat(".", k, ".pkRoot"));
        m = vm.parseJsonBytes32(json, string.concat(".", k, ".message"));
        sig = vm.parseJsonBytes(json, string.concat(".", k, ".signature"));
    }

    function _rejected(bytes32 s, bytes32 r, bytes32 m, bytes memory sig) internal view returns (bool) {
        (bool ok, bytes memory ret) =
            address(v2).staticcall(abi.encodeWithSelector(v2.verify.selector, s, r, m, sig));
        if (!ok || ret.length != 32) return true;
        return !abi.decode(ret, (bool));
    }

    function test_v2_accepts_every_reference_kat() public view {
        for (uint256 i = 0; i < 6; i++) {
            (bytes32 s, bytes32 r, bytes32 m, bytes memory sig) = _vec(string.concat("v", vm.toString(i)));
            assertTrue(v2.verify(s, r, m, sig), string.concat("KAT v", vm.toString(i)));
        }
    }

    /// Spec 0.2 §7.3: these rebuild the correct root and break exactly one +C rule.
    function test_v2_rejects_plus_c_only_near_misses() public view {
        for (uint256 i = 0; i < 3; i++) {
            (bytes32 s, bytes32 r, bytes32 m, bytes memory sig) = _vec(string.concat("n", vm.toString(i)));
            assertTrue(_rejected(s, r, m, sig), string.concat("+C near-miss n", vm.toString(i)));
        }
    }

    /// One flipped bit in every region of the signature (R, FORS secrets, FORS
    /// auth, both WOTS layers' chains, counts and Merkle paths), a wrong root
    /// and a wrong message: all rejected. Control first: the untouched one passes.
    function test_v2_rejects_bit_flips_wrong_root_wrong_message() public view {
        (bytes32 s, bytes32 r, bytes32 m, bytes memory sig) = _vec("v0");
        assertTrue(v2.verify(s, r, m, sig), "control");
        uint16[12] memory offs =
            [uint16(0), 15, 16, 208, 224, 2335, 2336, 2336 + 687, 2336 + 690, 2336 + 700, 2336 + 836 + 100, 4007];
        for (uint256 j = 0; j < offs.length; j++) {
            bytes memory b = bytes.concat(sig);
            b[offs[j]] = bytes1(uint8(b[offs[j]]) ^ 1);
            assertTrue(_rejected(s, r, m, b), string.concat("bit flip at ", vm.toString(uint256(offs[j]))));
        }
        assertTrue(_rejected(s, r ^ bytes32(uint256(1) << 128), m, sig), "wrong root");
        assertTrue(_rejected(s, r, m ^ bytes32(uint256(1)), sig), "wrong message");
    }

    /// v2 must not accept a v1 signature or vice versa (different preimages).
    function test_versions_do_not_cross_verify() public view {
        (bytes32 s, bytes32 r, bytes32 m, bytes memory sig) = _vec("v0");
        assertTrue(_rejected(s, r, m, sig) == false, "control");
        (bool ok, bytes memory ret) = address(v1).staticcall(abi.encodeWithSelector(v1.verify.selector, s, r, m, sig));
        assertTrue(!ok || !abi.decode(ret, (bool)), "v1 accepted a v2 signature");
        string memory j1 = vm.readFile("test/c10_test_vectors.json");
        assertTrue(
            _rejected(
                vm.parseJsonBytes32(j1, ".pkSeed"),
                vm.parseJsonBytes32(j1, ".pkRoot"),
                vm.parseJsonBytes32(j1, ".message"),
                vm.parseJsonBytes(j1, ".signature")
            ),
            "v2 accepted a v1 signature"
        );
    }

    function test_gas_v1_vs_v2() public view {
        (bytes32 s, bytes32 r, bytes32 m, bytes memory sig) = _vec("v0");
        uint256 g = gasleft();
        assertTrue(v2.verify(s, r, m, sig));
        uint256 gv2 = g - gasleft();
        string memory j1 = vm.readFile("test/c10_test_vectors.json");
        bytes32 s1 = vm.parseJsonBytes32(j1, ".pkSeed");
        bytes32 r1 = vm.parseJsonBytes32(j1, ".pkRoot");
        bytes32 m1 = vm.parseJsonBytes32(j1, ".message");
        bytes memory sig1 = vm.parseJsonBytes(j1, ".signature");
        g = gasleft();
        assertTrue(v1.verify(s1, r1, m1, sig1));
        uint256 gv1 = g - gasleft();
        console2.log("verify gas v1", gv1);
        console2.log("verify gas v2", gv2);
        console2.log("runtime size v1", address(v1).code.length);
        console2.log("runtime size v2", address(v2).code.length);
    }
}
