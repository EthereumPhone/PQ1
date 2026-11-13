// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, console2} from "forge-std/Test.sol";
import {ISPHINCSVerifier} from "../src/verifiers/ISPHINCSVerifier.sol";
import {SPHINCsC10v2Asm} from "../src/verifiers/SPHINCsC10v2Asm.sol";
import {SPHINCsC10v2All3Asm} from "../src/verifiers/SPHINCsC10v2All3Asm.sol";
import {SPHINCsC10v2Split810Asm} from "../src/verifiers/SPHINCsC10v2Split810Asm.sol";
import {SPHINCsC10v2Ts200Asm} from "../src/verifiers/SPHINCsC10v2Ts200Asm.sol";

/// RESEARCH (#1155): security checks for three candidate format changes to C10 v2
/// DRAFT 0.3, against the Python reference KATs (research/c10-autoresearch/c10v2/c10v2_ref.py
/// `--variant`). NOT a spec decision; none of these verifiers is deployed.
///   ts200    : WOTS+C target digit sum 200 (verifier change)
///   prf2     : signer-side secret derivation only (the unchanged 0.3 verifier must accept)
///   split810 : hypertree layer heights (8, 10), A7 kp at 32..23 / ci at 22..17 (verifier change)
///   all3     : ts200 + prf2 + split810
///
/// Verifier index: 0 = 0.3 (`SPHINCsC10v2Asm`), 1 = ts200, 2 = split810, 3 = all3.
/// KAT file index: 0 = 0.3, 1 = ts200, 2 = prf2, 3 = split810, 4 = all3.
/// A verifier accepts a KAT file iff their (target sum, layer split) agree; prf2 has 0.3's.
contract SPHINCsC10v2VariantsTest is Test {
    uint256 internal constant NV = 4;
    uint256 internal constant NF = 5;

    address[NV] internal ver;
    string[NV] internal verName;
    uint256[NV] internal verTarget;
    uint256[NV] internal verH0; // layer-0 subtree height (9 = 9+9, 8 = 8+10)

    string[NF] internal fileName;
    string[NF] internal filePath;
    uint256[NF] internal fileTarget;
    uint256[NF] internal fileH0;

    function setUp() public {
        ver[0] = address(new SPHINCsC10v2Asm());
        ver[1] = address(new SPHINCsC10v2Ts200Asm());
        ver[2] = address(new SPHINCsC10v2Split810Asm());
        ver[3] = address(new SPHINCsC10v2All3Asm());
        verName = ["v2-0.3", "ts200", "split810", "all3"];
        verTarget = [uint256(205), 200, 205, 200];
        verH0 = [uint256(9), 9, 8, 8];

        fileName = ["0.3", "ts200", "prf2", "split810", "all3"];
        filePath = [
            "test/c10v2_kat_vectors.json",
            "test/c10v2_kat_vectors_ts200.json",
            "test/c10v2_kat_vectors_prf2.json",
            "test/c10v2_kat_vectors_split810.json",
            "test/c10v2_kat_vectors_all3.json"
        ];
        fileTarget = [uint256(205), 200, 205, 205, 200];
        fileH0 = [uint256(9), 9, 9, 8, 8];
    }

    // ── helpers ─────────────────────────────────────────────────────────────

    function _json(uint256 f) internal view returns (string memory) {
        return vm.readFile(filePath[f]);
    }

    function _vec(string memory json, string memory k)
        internal
        pure
        returns (bytes32 s, bytes32 r, bytes32 m, bytes memory sig)
    {
        s = vm.parseJsonBytes32(json, string.concat(".", k, ".pkSeed"));
        r = vm.parseJsonBytes32(json, string.concat(".", k, ".pkRoot"));
        m = vm.parseJsonBytes32(json, string.concat(".", k, ".message"));
        sig = vm.parseJsonBytes(json, string.concat(".", k, ".signature"));
    }

    function _call(uint256 v, bytes32 s, bytes32 r, bytes32 m, bytes memory sig)
        internal
        view
        returns (bool ok, bytes memory ret)
    {
        require(ver[v].code.length > 0, "verifier not deployed");
        (ok, ret) = ver[v].staticcall(abi.encodeWithSelector(ISPHINCSVerifier.verify.selector, s, r, m, sig));
    }

    /// True only for a successful call that returned exactly abi-encoded `true`.
    function _accepted(uint256 v, bytes32 s, bytes32 r, bytes32 m, bytes memory sig) internal view returns (bool) {
        (bool ok, bytes memory ret) = _call(v, s, r, m, sig);
        return ok && ret.length == 32 && abi.decode(ret, (bool));
    }

    function _compatible(uint256 v, uint256 f) internal view returns (bool) {
        return verTarget[v] == fileTarget[f] && verH0[v] == fileH0[f];
    }

    /// How many of the six KATs v0..v5 in file `f` verifier `v` accepts.
    function _acceptedKats(uint256 v, uint256 f) internal view returns (uint256 n) {
        string memory json = _json(f);
        for (uint256 i = 0; i < 6; i++) {
            (bytes32 s, bytes32 r, bytes32 m, bytes memory sig) = _vec(json, string.concat("v", vm.toString(i)));
            if (_accepted(v, s, r, m, sig)) n++;
        }
    }

    function _cellMsg(uint256 v, uint256 f) internal view returns (string memory) {
        return string.concat("verifier ", verName[v], " on KATs ", fileName[f]);
    }

    function _assertCell(uint256 v, uint256 f) internal view {
        uint256 n = _acceptedKats(v, f);
        if (_compatible(v, f)) {
            assertEq(n, 6, string.concat(_cellMsg(v, f), ": expected all 6 accepted"));
        } else {
            assertEq(n, 0, string.concat(_cellMsg(v, f), ": expected all 6 rejected"));
        }
    }

    /// All 6 KATs accepted; each +C-only near-miss (n0 FORS+C, n1/n2 WOTS digit sum at layer 0/1)
    /// rejected, and rejected by an empty revert: the only empty reverts in the verifier are the
    /// two +C checks, and these vectors rebuild the correct root otherwise.
    function _checkKatsAndNearMisses(uint256 v, uint256 f) internal view {
        assertTrue(_compatible(v, f), "test wiring");
        string memory json = _json(f);
        for (uint256 i = 0; i < 6; i++) {
            (bytes32 s, bytes32 r, bytes32 m, bytes memory sig) = _vec(json, string.concat("v", vm.toString(i)));
            assertTrue(_accepted(v, s, r, m, sig), string.concat(_cellMsg(v, f), ": KAT v", vm.toString(i)));
        }
        for (uint256 i = 0; i < 3; i++) {
            (bytes32 s, bytes32 r, bytes32 m, bytes memory sig) = _vec(json, string.concat("n", vm.toString(i)));
            (bool ok, bytes memory ret) = _call(v, s, r, m, sig);
            assertFalse(ok, string.concat(_cellMsg(v, f), ": +C near-miss n", vm.toString(i), " not rejected"));
            assertEq(ret.length, 0, string.concat(_cellMsg(v, f), ": n", vm.toString(i), " not a +C revert"));
        }
    }

    /// Signature regions for layer-0 height h0 (layer 1 = 18 - h0): R, FORS secrets, FORS last
    /// slot, FORS auth, then per layer the 43 chains, the 4-byte count and the Merkle path.
    function _regions(uint256 h0) internal pure returns (uint256[10] memory st, uint256[10] memory len) {
        uint256 h1 = 18 - h0;
        uint256 l0 = 2336;
        uint256 l1 = l0 + 688 + 4 + 16 * h0;
        st = [uint256(0), 16, 208, 224, l0, l0 + 688, l0 + 692, l1, l1 + 688, l1 + 692];
        len = [uint256(16), 192, 16, 2112, 688, 4, 16 * h0, 688, 4, 16 * h1];
        require(l1 + 692 + 16 * h1 == 4008, "layout");
    }

    /// Control (unflipped v0 accepted) first, then one flipped bit at the first, middle and last
    /// byte of every region, a wrong root and a wrong message: all rejected.
    function _checkFlips(uint256 v, uint256 f) internal view {
        assertTrue(_compatible(v, f), "test wiring");
        (bytes32 s, bytes32 r, bytes32 m, bytes memory sig) = _vec(_json(f), "v0");
        assertTrue(_accepted(v, s, r, m, sig), string.concat(_cellMsg(v, f), ": control"));
        (uint256[10] memory st, uint256[10] memory len) = _regions(fileH0[f]);
        for (uint256 j = 0; j < 10; j++) {
            uint256[3] memory at = [st[j], st[j] + len[j] / 2, st[j] + len[j] - 1];
            for (uint256 q = 0; q < 3; q++) {
                bytes memory b = bytes.concat(sig);
                b[at[q]] = bytes1(uint8(b[at[q]]) ^ 1);
                assertFalse(
                    _accepted(v, s, r, m, b),
                    string.concat(_cellMsg(v, f), ": bit flip at ", vm.toString(at[q]), " accepted")
                );
            }
        }
        assertFalse(_accepted(v, s, r ^ bytes32(uint256(1) << 128), m, sig), string.concat(_cellMsg(v, f), ": wrong root"));
        assertFalse(_accepted(v, s, r, m ^ bytes32(uint256(1)), sig), string.concat(_cellMsg(v, f), ": wrong message"));
    }

    // ── accepts own KATs, rejects own +C near-misses ────────────────────────

    function test_ts200_accepts_kats_rejects_near_misses() public view {
        _checkKatsAndNearMisses(1, 1);
    }

    /// prf2 changes signer-side derivation only: the UNCHANGED 0.3 verifier accepts it.
    function test_prf2_unchanged_v2_verifier_accepts_kats_rejects_near_misses() public view {
        _checkKatsAndNearMisses(0, 2);
    }

    function test_split810_accepts_kats_rejects_near_misses() public view {
        _checkKatsAndNearMisses(2, 3);
    }

    function test_all3_accepts_kats_rejects_near_misses() public view {
        _checkKatsAndNearMisses(3, 4);
    }

    // ── bit flips in every region, wrong root, wrong message ────────────────

    function test_ts200_rejects_bit_flips_wrong_root_wrong_message() public view {
        _checkFlips(1, 1);
    }

    function test_prf2_rejects_bit_flips_wrong_root_wrong_message() public view {
        _checkFlips(0, 2);
    }

    function test_split810_rejects_bit_flips_wrong_root_wrong_message() public view {
        _checkFlips(2, 3);
    }

    function test_all3_rejects_bit_flips_wrong_root_wrong_message() public view {
        _checkFlips(3, 4);
    }

    // ── cross-format ────────────────────────────────────────────────────────

    /// The KAT files share keys (pk_seed) and messages; ts200 does not change keys, so its
    /// cross-format rejections below are by the target-sum rule alone; prf2 and split810 do.
    function test_kat_files_share_seeds_and_messages() public view {
        string[NF] memory js;
        for (uint256 f = 0; f < NF; f++) {
            js[f] = _json(f);
        }
        for (uint256 i = 0; i < 6; i++) {
            string memory k = string.concat("v", vm.toString(i));
            (bytes32 s0, bytes32 r0, bytes32 m0,) = _vec(js[0], k);
            bytes32[NF] memory roots;
            for (uint256 f = 0; f < NF; f++) {
                (bytes32 s, bytes32 r, bytes32 m,) = _vec(js[f], k);
                assertEq(s, s0, string.concat(k, " pkSeed differs in ", fileName[f]));
                assertEq(m, m0, string.concat(k, " message differs in ", fileName[f]));
                roots[f] = r;
            }
            assertEq(roots[1], r0, string.concat(k, ": ts200 must not change pk_root"));
            for (uint256 a = 0; a < NF; a++) {
                for (uint256 b = a + 1; b < NF; b++) {
                    if (a == 0 && b == 1) continue;
                    assertTrue(roots[a] != roots[b], string.concat(k, ": pk_root collides ", fileName[a], "/", fileName[b]));
                }
            }
        }
    }

    function test_cross_draft03_kats_rejected_by_ts200_split810_all3() public view {
        for (uint256 v = 1; v < NV; v++) {
            assertEq(_acceptedKats(v, v == 1 ? 1 : v + 1), 6, string.concat("control ", verName[v]));
            assertEq(_acceptedKats(v, 0), 0, _cellMsg(v, 0));
        }
    }

    function test_cross_variant_kats_rejected_by_draft03_verifier() public view {
        assertEq(_acceptedKats(0, 0), 6, "control: 0.3 verifier on 0.3 KATs");
        uint256[3] memory fs = [uint256(1), 3, 4]; // ts200, split810, all3
        for (uint256 j = 0; j < 3; j++) {
            assertEq(_acceptedKats(0, fs[j]), 0, _cellMsg(0, fs[j]));
        }
    }

    function test_cross_ts200_and_split810_reject_each_other() public view {
        assertEq(_acceptedKats(1, 1), 6, "control: ts200 on ts200");
        assertEq(_acceptedKats(2, 3), 6, "control: split810 on split810");
        assertEq(_acceptedKats(2, 1), 0, _cellMsg(2, 1));
        assertEq(_acceptedKats(1, 3), 0, _cellMsg(1, 3));
    }

    /// Every verifier against every KAT file (the Python reference's 5x5 run, minus the prf2
    /// verifier, which is the 0.3 one): all 6 accepted iff compatible, else all 6 rejected.
    function test_cross_format_full_matrix() public view {
        uint256 accepts;
        for (uint256 v = 0; v < NV; v++) {
            for (uint256 f = 0; f < NF; f++) {
                _assertCell(v, f);
                if (_compatible(v, f)) accepts++;
            }
        }
        assertEq(accepts, 5, "matrix wiring: 0.3 accepts 0.3+prf2, each variant accepts its own");
    }

    // ── gas and size ────────────────────────────────────────────────────────

    /// Callee-only gas: calldata is encoded before the measurement and the output goes to scratch
    /// memory, so the caller's growing memory does not leak into the numbers. Includes the warm
    /// CALL (100) after one unmeasured warm-up call per verifier. Excludes tx calldata cost.
    function _gas(uint256 v, bytes32 s, bytes32 r, bytes32 m, bytes memory sig) internal view returns (uint256 used) {
        bytes memory cd = abi.encodeWithSelector(ISPHINCSVerifier.verify.selector, s, r, m, sig);
        address a = ver[v];
        bool ok;
        uint256 res;
        assembly {
            let g := gas()
            ok := staticcall(gas(), a, add(cd, 0x20), mload(cd), 0x00, 0x20)
            used := sub(g, gas())
            res := mload(0x00)
        }
        require(ok && res == 1, "gas run did not verify");
    }

    function test_gas_and_size_per_variant() public view {
        uint256[5] memory pv = [uint256(0), 0, 1, 2, 3];
        uint256[5] memory pf = [uint256(0), 2, 1, 3, 4];
        string[5] memory label = ["v2-0.3 (0.3 KATs)", "v2-0.3 (prf2 KATs)", "ts200", "split810", "all3"];
        for (uint256 v = 0; v < NV; v++) {
            // warm-up: makes every measured call a warm CALL
            (bytes32 s, bytes32 r, bytes32 m, bytes memory sig) = _vec(_json(v == 0 ? 0 : v == 1 ? 1 : v + 1), "v0");
            assertTrue(_accepted(v, s, r, m, sig), "warm-up");
        }
        uint256 base;
        for (uint256 p = 0; p < 5; p++) {
            string memory json = _json(pf[p]);
            uint256 sum;
            uint256 mn = type(uint256).max;
            uint256 mx;
            for (uint256 i = 0; i < 6; i++) {
                (bytes32 s, bytes32 r, bytes32 m, bytes memory sig) = _vec(json, string.concat("v", vm.toString(i)));
                uint256 g = _gas(pv[p], s, r, m, sig);
                sum += g;
                if (g < mn) mn = g;
                if (g > mx) mx = g;
            }
            uint256 mean = sum / 6;
            if (p == 0) base = mean;
            console2.log(string.concat("verify gas mean/6 ", label[p]), mean);
            console2.log("  min", mn);
            console2.log("  max", mx);
            console2.log("  delta vs 0.3", int256(mean) - int256(base));
        }
        for (uint256 v = 0; v < NV; v++) {
            console2.log(string.concat("runtime size ", verName[v]), ver[v].code.length);
        }
    }
}
