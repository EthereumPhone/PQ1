// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, Vm} from "forge-std/Test.sol";
import {VmSafe} from "forge-std/Vm.sol";
import {ISPHINCSVerifier} from "../../src/verifiers/ISPHINCSVerifier.sol";
import {SPHINCsC10Asm} from "../../src/verifiers/SPHINCsC10Asm.sol";
import {SPHINCsC10v2Asm} from "../../src/verifiers/SPHINCsC10v2Asm.sol";
import {RefSPHINCsC10Asm} from "../ref/RefSPHINCsC10Asm.sol";
import {RefSPHINCsC10v2Asm} from "../ref/RefSPHINCsC10v2Asm.sol";

/// RESEARCH (#1155 gas track): per-primitive gate. The Python references (v2:
/// research/c10-autoresearch/c10v2/c10v2_ref.py, written from the spec; v1: the clean-room
/// contracts/verification/scripts/independent_c10_signer.py) record every SHA-256 input their
/// verify() hashes; research/c10-gas/v{1,2}_trace_export.py writes them to
/// test/gas/c10v{1,2}_trace_vectors.json with a label per call (role + decoded address).
/// Here the on-chain verifier's SHA-256 precompile inputs for the same vectors must equal that
/// list entry by entry, so a divergence names the exact primitive call (e.g. "H FORS_TREE
/// tree=104655 kp=3 cp=7 ha=12") instead of only a whole-signature reject.
/// Run against both the candidate (src/verifiers/) and the frozen reference (test/ref/).
/// v2 also covers the three +C near-misses, whose traces stop at the failing check.
contract C10PrimitiveTraceTest is Test {
    bytes4 internal constant SEL = ISPHINCSVerifier.verify.selector;

    function _trace(address v, bytes memory cd) internal returns (bool ok, bytes memory ret, bytes[] memory ins) {
        vm.startStateDiffRecording();
        (ok, ret) = v.staticcall(cd);
        Vm.AccountAccess[] memory a = vm.stopAndReturnStateDiff();
        uint256 n;
        for (uint256 i = 0; i < a.length; i++) {
            if (_isSha(a[i])) n++;
        }
        ins = new bytes[](n);
        n = 0;
        for (uint256 i = 0; i < a.length; i++) {
            if (_isSha(a[i])) ins[n++] = a[i].data;
        }
    }

    /// Only STATICCALLs into 0x02 count: the Python trace is of hash inputs, and the verifiers
    /// must reach the precompile by STATICCALL.
    function _isSha(Vm.AccountAccess memory x) internal pure returns (bool) {
        return x.account == address(2) && (x.kind == VmSafe.AccountAccessKind.Call
            || x.kind == VmSafe.AccountAccessKind.DelegateCall || x.kind == VmSafe.AccountAccessKind.CallCode
            || x.kind == VmSafe.AccountAccessKind.StaticCall);
    }

    function _match(address v, string memory who, string memory tj, string memory k, bytes memory cd) internal {
        bytes[] memory exp = vm.parseJsonBytesArray(tj, string.concat(".", k, ".inputs"));
        string[] memory lab = vm.parseJsonStringArray(tj, string.concat(".", k, ".labels"));
        bool accept = vm.parseJsonBool(tj, string.concat(".", k, ".accept"));
        (bool ok, bytes memory ret, bytes[] memory got) = _trace(v, cd);
        uint256 n = exp.length < got.length ? exp.length : got.length;
        for (uint256 i = 0; i < n; i++) {
            if (keccak256(exp[i]) != keccak256(got[i])) {
                emit log_named_bytes("expected", exp[i]);
                emit log_named_bytes("got     ", got[i]);
                revert(string.concat(who, " ", k, ": SHA-256 call #", vm.toString(i), " differs: ", lab[i]));
            }
        }
        assertEq(got.length, exp.length, string.concat(who, " ", k, ": SHA-256 call count"));
        bool accepted = ok && ret.length == 32 && abi.decode(ret, (uint256)) == 1;
        assertEq(accepted, accept, string.concat(who, " ", k, ": accept/reject differs from the Python reference"));
    }

    function _v2(address v, string memory who) internal {
        string memory tj = vm.readFile("test/gas/c10v2_trace_vectors.json");
        string memory kj = vm.readFile("test/c10v2_kat_vectors.json");
        string[] memory keys = vm.parseJsonStringArray(tj, ".keys");
        assertEq(keys.length, 9, "v2 trace keys");
        for (uint256 i = 0; i < keys.length; i++) {
            string memory p = string.concat(".", keys[i]);
            bytes memory cd = abi.encodeWithSelector(
                SEL,
                vm.parseJsonBytes32(kj, string.concat(p, ".pkSeed")),
                vm.parseJsonBytes32(kj, string.concat(p, ".pkRoot")),
                vm.parseJsonBytes32(kj, string.concat(p, ".message")),
                vm.parseJsonBytes(kj, string.concat(p, ".signature"))
            );
            _match(v, who, tj, keys[i], cd);
        }
    }

    function _v1(address v, string memory who) internal {
        string memory tj = vm.readFile("test/gas/c10v1_trace_vectors.json");
        string memory kj = vm.readFile("test/c10_test_vectors.json");
        string[] memory keys = vm.parseJsonStringArray(tj, ".keys");
        assertEq(keys.length, 4, "v1 trace keys");
        for (uint256 i = 0; i < keys.length; i++) {
            // key "vecN" is .vectors[N] of the vector file
            string memory p = string.concat(".vectors[", vm.toString(i), "]");
            assertEq(keys[i], string.concat("vec", vm.toString(i)), "v1 trace key order");
            bytes memory cd = abi.encodeWithSelector(
                SEL,
                vm.parseJsonBytes32(kj, string.concat(p, ".pkSeed")),
                vm.parseJsonBytes32(kj, string.concat(p, ".pkRoot")),
                vm.parseJsonBytes32(kj, string.concat(p, ".message")),
                vm.parseJsonBytes(kj, string.concat(p, ".signature"))
            );
            _match(v, who, tj, keys[i], cd);
        }
    }

    function test_v2_candidate_matches_python_reference_per_primitive() public {
        _v2(address(new SPHINCsC10v2Asm()), "candidate v2");
    }

    function test_v2_frozen_reference_matches_python_reference_per_primitive() public {
        _v2(address(new RefSPHINCsC10v2Asm()), "reference v2");
    }

    function test_v1_candidate_matches_python_reference_per_primitive() public {
        _v1(address(new SPHINCsC10Asm()), "candidate v1");
    }

    function test_v1_frozen_reference_matches_python_reference_per_primitive() public {
        _v1(address(new RefSPHINCsC10Asm()), "reference v1");
    }
}
