// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, console2} from "forge-std/Test.sol";
import {ISPHINCSVerifier} from "../../src/verifiers/ISPHINCSVerifier.sol";
import {SPHINCsC10Asm} from "../../src/verifiers/SPHINCsC10Asm.sol";
import {SPHINCsC10v2Asm} from "../../src/verifiers/SPHINCsC10v2Asm.sol";
import {RefSPHINCsC10Asm} from "../ref/RefSPHINCsC10Asm.sol";
import {RefSPHINCsC10v2Asm} from "../ref/RefSPHINCsC10v2Asm.sol";

/// RESEARCH (#1155 gas track): verify gas, reference vs candidate, two methods.
///
/// CALLEE-ONLY (the ledger's number): calldata is ABI-encoded before the measurement, the call
/// is a raw `staticcall` in assembly with the output written to scratch memory, after one
/// unmeasured warm-up call. Counts the warm CALL (100) plus everything the verifier executes,
/// including its own memory expansion and returndata. Excludes the transaction's calldata cost
/// and the caller's own encoding and memory growth. Same method as
/// SPHINCsC10v2Variants.t.sol `_gas`.
///
/// HIGH-LEVEL (for comparison with #1155's quoted 163,186 / 180,812): `gasleft()` around a
/// Solidity `verifier.verify(...)` call, so it also counts the caller's ABI encoding of the
/// 4,008-byte argument, its memory expansion and the return decoding.
///
/// Every valid signature runs the same number of SHA-256 calls (361) on the same preimage
/// lengths, so the per-vector gas is constant up to the calldata-dependent ABI checks.
contract C10GasBenchTest is Test {
    bytes4 internal constant SEL = ISPHINCSVerifier.verify.selector;

    struct Vec {
        bytes32 s;
        bytes32 r;
        bytes32 m;
        bytes sig;
    }

    function _calleeGas(address a, Vec memory v) internal view returns (uint256 used) {
        bytes memory cd = abi.encodeWithSelector(SEL, v.s, v.r, v.m, v.sig);
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

    function _highLevelGas(address a, Vec memory v) internal view returns (uint256 used) {
        uint256 g = gasleft();
        bool ok = ISPHINCSVerifier(a).verify(v.s, v.r, v.m, v.sig);
        used = g - gasleft();
        require(ok, "high-level run did not verify");
    }

    function _v1Vecs() internal view returns (Vec[] memory vs) {
        string memory j = vm.readFile("test/c10_test_vectors.json");
        vs = new Vec[](4);
        for (uint256 i = 0; i < 4; i++) {
            string memory p = string.concat(".vectors[", vm.toString(i), "]");
            vs[i] = Vec(
                vm.parseJsonBytes32(j, string.concat(p, ".pkSeed")),
                vm.parseJsonBytes32(j, string.concat(p, ".pkRoot")),
                vm.parseJsonBytes32(j, string.concat(p, ".message")),
                vm.parseJsonBytes(j, string.concat(p, ".signature"))
            );
        }
    }

    function _v2Vecs() internal view returns (Vec[] memory vs) {
        string memory j = vm.readFile("test/c10v2_kat_vectors.json");
        vs = new Vec[](6);
        for (uint256 i = 0; i < 6; i++) {
            string memory p = string.concat(".v", vm.toString(i));
            vs[i] = Vec(
                vm.parseJsonBytes32(j, string.concat(p, ".pkSeed")),
                vm.parseJsonBytes32(j, string.concat(p, ".pkRoot")),
                vm.parseJsonBytes32(j, string.concat(p, ".message")),
                vm.parseJsonBytes(j, string.concat(p, ".signature"))
            );
        }
    }

    function _bench(string memory name, address ref, address cand, Vec[] memory vs) internal view {
        _calleeGas(ref, vs[0]); // warm-up: every measured call is a warm CALL
        _calleeGas(cand, vs[0]);
        uint256 rmn = type(uint256).max;
        uint256 rmx;
        uint256 cmn = type(uint256).max;
        uint256 cmx;
        for (uint256 i = 0; i < vs.length; i++) {
            uint256 r = _calleeGas(ref, vs[i]);
            uint256 c = _calleeGas(cand, vs[i]);
            if (r < rmn) rmn = r;
            if (r > rmx) rmx = r;
            if (c < cmn) cmn = c;
            if (c > cmx) cmx = c;
        }
        console2.log(string.concat("GAS ", name, " callee-only ref min/max"), rmn, rmx);
        console2.log(string.concat("GAS ", name, " callee-only cand min/max"), cmn, cmx);
        console2.log(string.concat("GAS ", name, " callee-only saved (ref max - cand max)"), rmx - cmx);
        console2.log(string.concat("GAS ", name, " high-level ref"), _highLevelGas(ref, vs[0]));
        console2.log(string.concat("GAS ", name, " high-level cand"), _highLevelGas(cand, vs[0]));
        console2.log(string.concat("SIZE ", name, " runtime ref/cand"), ref.code.length, cand.code.length);
    }

    /// Gas by phase (v2): callee-only gas of the +C near-misses, which stop after H_MSG (n0),
    /// after FORS + the layer-0 digest (n1) and after layer 0 + the layer-1 digest (n2), and of a
    /// valid vector. Differences attribute the cost to FORS, layer 0 and layer 1.
    function _anyGas(address a, bytes memory cd) internal view returns (uint256 used) {
        assembly {
            let g := gas()
            pop(staticcall(gas(), a, add(cd, 0x20), mload(cd), 0x00, 0x20))
            used := sub(g, gas())
        }
    }

    function _phases(string memory name, address v) internal view {
        string memory j = vm.readFile("test/c10v2_kat_vectors.json");
        string[4] memory k = ["n0", "n1", "n2", "v0"];
        uint256[4] memory g;
        for (uint256 i = 0; i < 4; i++) {
            string memory p = string.concat(".", k[i]);
            bytes memory cd = abi.encodeWithSelector(
                SEL,
                vm.parseJsonBytes32(j, string.concat(p, ".pkSeed")),
                vm.parseJsonBytes32(j, string.concat(p, ".pkRoot")),
                vm.parseJsonBytes32(j, string.concat(p, ".message")),
                vm.parseJsonBytes(j, string.concat(p, ".signature"))
            );
            _anyGas(v, cd);
            g[i] = _anyGas(v, cd);
        }
        console2.log(string.concat("PHASE ", name, " to H_MSG+FORS+C check"), g[0]);
        console2.log(string.concat("PHASE ", name, " FORS + layer-0 digest/sum"), g[1] - g[0]);
        console2.log(string.concat("PHASE ", name, " layer 0 + layer-1 digest/sum"), g[2] - g[1]);
        console2.log(string.concat("PHASE ", name, " layer 1 rest + root compare"), g[3] - g[2]);
    }

    function test_gas_phases_v2() public {
        _phases("v2 ref", address(new RefSPHINCsC10v2Asm()));
        _phases("v2 cand", address(new SPHINCsC10v2Asm()));
    }

    function test_gas_v1() public {
        _bench("v1", address(new RefSPHINCsC10Asm()), address(new SPHINCsC10Asm()), _v1Vecs());
    }

    function test_gas_v2() public {
        _bench("v2", address(new RefSPHINCsC10v2Asm()), address(new SPHINCsC10v2Asm()), _v2Vecs());
    }
}
