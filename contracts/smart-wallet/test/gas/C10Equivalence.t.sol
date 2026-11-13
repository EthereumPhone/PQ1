// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, Vm, console2} from "forge-std/Test.sol";
import {ISPHINCSVerifier} from "../../src/verifiers/ISPHINCSVerifier.sol";
import {SPHINCsC10Asm} from "../../src/verifiers/SPHINCsC10Asm.sol";
import {SPHINCsC10v2Asm} from "../../src/verifiers/SPHINCsC10v2Asm.sol";
import {RefSPHINCsC10Asm} from "../ref/RefSPHINCsC10Asm.sol";
import {RefSPHINCsC10v2Asm} from "../ref/RefSPHINCsC10v2Asm.sol";

/// RESEARCH (#1155 gas track): semantic-equivalence gate between the frozen reference verifiers
/// (test/ref/, byte-for-byte copies of src/verifiers/ at 0895dcc79 apart from the contract name)
/// and the gas-optimized candidates in src/verifiers/.
///
/// One observation of a `verify` call is the triple
///   (success flag, exact returndata, ordered list of SHA-256 precompile inputs).
/// The gate requires identical observations on every input it tries: the KATs and +C near-misses,
/// the v1 mutant corpus, deterministic mutation sweeps, fuzzed mutations of valid signatures,
/// non-canonical ABI encodings and raw calldata. Comparing the precompile trace and not only the
/// result means a candidate that hashes a different preimage on the way to a rejection fails the
/// gate even though the result (a revert or `false`) would be the same.
///
/// Out of scope by construction: gas. A candidate that needs less gas runs out of gas at a
/// different gas limit; every call here gets the full test gas.
contract C10EquivalenceTest is Test {
    bytes4 internal constant SEL = ISPHINCSVerifier.verify.selector;

    /// The deployed v1 runtime codehash pinned in SPHINCsC10Asm.t.sol (default profile). The frozen
    /// reference must still hash to it, so "reference" means the deployed bytecode.
    bytes32 internal constant V1_PINNED_RUNTIME_CODEHASH =
        0x8fa670d53df0fd63bc64505463f268256ffbb51e57f62d8a5a41f5bcec5cf2eb;
    /// The v2 DRAFT 0.3 runtime codehash at 0895dcc79 (default profile), captured when the
    /// reference copy was made.
    bytes32 internal constant V2_REF_RUNTIME_CODEHASH =
        0x07175f631ed2bc582aee631c0003401854a0c3051715e9ee30fc94adaddcf2e4;

    struct Vec {
        bytes32 s;
        bytes32 r;
        bytes32 m;
        bytes sig;
    }

    struct Obs {
        bool ok;
        bytes ret;
        bytes32[] trace; // keccak256 of each SHA-256 precompile input, in call order
    }

    address internal refV1;
    address internal candV1;
    address internal refV2;
    address internal candV2;

    Vec[] internal baseV1; // the 4 valid v1 vectors
    Vec[] internal baseV2; // the 6 valid v2 DRAFT 0.3 KATs

    // outcome tallies of the last sweep: accepted, returned false, reverted with data, reverted empty
    uint256[4] internal tally;

    function setUp() public {
        refV1 = address(new RefSPHINCsC10Asm());
        candV1 = address(new SPHINCsC10Asm());
        refV2 = address(new RefSPHINCsC10v2Asm());
        candV2 = address(new SPHINCsC10v2Asm());

        string memory j1 = vm.readFile("test/c10_test_vectors.json");
        for (uint256 i = 0; i < 4; i++) {
            string memory p = string.concat(".vectors[", vm.toString(i), "]");
            require(vm.parseJsonBool(j1, string.concat(p, ".expectValid")), "v1 base not valid");
            baseV1.push(
                Vec(
                    vm.parseJsonBytes32(j1, string.concat(p, ".pkSeed")),
                    vm.parseJsonBytes32(j1, string.concat(p, ".pkRoot")),
                    vm.parseJsonBytes32(j1, string.concat(p, ".message")),
                    vm.parseJsonBytes(j1, string.concat(p, ".signature"))
                )
            );
        }
        string memory j2 = vm.readFile("test/c10v2_kat_vectors.json");
        for (uint256 i = 0; i < 6; i++) {
            baseV2.push(_vecAt(j2, string.concat("v", vm.toString(i))));
        }
    }

    // ── observation ─────────────────────────────────────────────────────────

    function _observe(address v, bytes memory cd) internal returns (Obs memory o) {
        vm.startStateDiffRecording();
        (o.ok, o.ret) = v.staticcall(cd);
        Vm.AccountAccess[] memory a = vm.stopAndReturnStateDiff();
        uint256 n;
        for (uint256 i = 0; i < a.length; i++) {
            if (a[i].account == address(2)) n++;
        }
        o.trace = new bytes32[](n);
        n = 0;
        for (uint256 i = 0; i < a.length; i++) {
            if (a[i].account == address(2)) o.trace[n++] = keccak256(a[i].data);
        }
    }

    /// "" when the two observations are identical, else the first difference.
    function _compare(address a, address b, bytes memory cd) internal returns (string memory) {
        Obs memory x = _observe(a, cd);
        Obs memory y = _observe(b, cd);
        if (x.ok != y.ok) return "success flag differs";
        if (keccak256(x.ret) != keccak256(y.ret)) return "returndata differs";
        if (x.trace.length != y.trace.length) {
            return string.concat(
                "SHA-256 call count ", vm.toString(x.trace.length), " vs ", vm.toString(y.trace.length)
            );
        }
        for (uint256 i = 0; i < x.trace.length; i++) {
            if (x.trace[i] != y.trace[i]) return string.concat("SHA-256 input #", vm.toString(i), " differs");
        }
        if (!x.ok) tally[x.ret.length == 0 ? 3 : 2]++;
        else if (x.ret.length == 32 && abi.decode(x.ret, (uint256)) == 1) tally[0]++;
        else tally[1]++;
        return "";
    }

    function _check(bool v2, bytes memory cd, string memory what) internal {
        string memory d = v2 ? _compare(refV2, candV2, cd) : _compare(refV1, candV1, cd);
        if (bytes(d).length != 0) revert(string.concat("EQUIVALENCE FAIL [", v2 ? "v2" : "v1", " ", what, "]: ", d));
    }

    function _cd(Vec memory v) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(SEL, v.s, v.r, v.m, v.sig);
    }

    function _vecAt(string memory json, string memory k) internal pure returns (Vec memory v) {
        v.s = vm.parseJsonBytes32(json, string.concat(".", k, ".pkSeed"));
        v.r = vm.parseJsonBytes32(json, string.concat(".", k, ".pkRoot"));
        v.m = vm.parseJsonBytes32(json, string.concat(".", k, ".message"));
        v.sig = vm.parseJsonBytes(json, string.concat(".", k, ".signature"));
    }

    function _base(bool v2, uint256 i) internal view returns (Vec memory) {
        return v2 ? baseV2[i % baseV2.length] : baseV1[i % baseV1.length];
    }

    function _copy(bytes memory b) internal pure returns (bytes memory) {
        return bytes.concat(b);
    }

    function _rnd(uint256 seed, uint256 i) internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(seed, i)));
    }

    function _logTally(string memory what) internal view {
        console2.log(string.concat(what, " accept/false/revert-data/revert-empty"), tally[0], tally[1]);
        console2.log("   ", tally[2], tally[3]);
    }

    function _resetTally() internal {
        tally = [uint256(0), 0, 0, 0];
    }

    /// Region starts and lengths (same 4,008-byte layout in v1 and v2 DRAFT 0.3): R, FORS secrets,
    /// FORS last slot, FORS auth, then per layer the 43 chains, the 4-byte count and the auth path.
    function _regions() internal pure returns (uint256[10] memory st, uint256[10] memory len) {
        st = [uint256(0), 16, 208, 224, 2336, 3024, 3028, 3172, 3860, 3864];
        len = [uint256(16), 192, 16, 2112, 688, 4, 144, 688, 4, 144];
    }

    // ── anchors and recorder sanity ─────────────────────────────────────────

    /// The reference is the deployed v1 bytecode; the v2 reference is the 0895dcc79 draft.
    function test_reference_anchors() public view {
        if (keccak256(bytes(vm.envOr("FOUNDRY_PROFILE", string("default")))) == keccak256(bytes("default"))) {
            assertEq(refV1.codehash, V1_PINNED_RUNTIME_CODEHASH, "ref v1 is not the pinned deployed bytecode");
            console2.log("ref v2 runtime codehash");
            console2.logBytes32(refV2.codehash);
            if (V2_REF_RUNTIME_CODEHASH != bytes32(0)) {
                assertEq(refV2.codehash, V2_REF_RUNTIME_CODEHASH, "ref v2 drifted from the 0895dcc79 draft");
            }
        }
        console2.log("cand v1 runtime size", candV1.code.length, "ref", refV1.code.length);
        console2.log("cand v2 runtime size", candV2.code.length, "ref", refV2.code.length);
    }

    /// The recorder must see precompile calls made inside a frame that later reverts, or the
    /// trace comparison would be vacuous on every rejected input: the +C near-misses revert after
    /// 1 (FORS+C), 148 (layer-0 digit sum) and 255 (layer-1 digit sum) SHA-256 calls.
    function test_recorder_sees_calls_in_reverted_frames() public {
        string memory j2 = vm.readFile("test/c10v2_kat_vectors.json");
        uint256[3] memory expect = [uint256(1), 148, 255];
        for (uint256 i = 0; i < 3; i++) {
            Obs memory o = _observe(refV2, _cd(_vecAt(j2, string.concat("n", vm.toString(i)))));
            assertFalse(o.ok, "near-miss did not revert");
            assertEq(o.trace.length, expect[i], "recorder missed calls in a reverted frame");
        }
        Obs memory ok = _observe(refV2, _cd(baseV2[0]));
        assertTrue(ok.ok);
        assertEq(ok.trace.length, 361, "valid v2 verify makes 361 SHA-256 calls");
        Obs memory ok1 = _observe(refV1, _cd(baseV1[0]));
        assertTrue(ok1.ok);
        assertEq(ok1.trace.length, 361, "valid v1 verify makes 361 SHA-256 calls");
    }

    // ── fixed corpora ───────────────────────────────────────────────────────

    /// Every KAT file (0.3, prf2, ts200, split810, all3): 6 KATs + 3 +C near-misses each. Under
    /// the 0.3 verifier the variant files exercise the digit-sum revert and the root mismatch.
    function test_v2_all_kat_files() public {
        string[5] memory files = [
            "test/c10v2_kat_vectors.json",
            "test/c10v2_kat_vectors_prf2.json",
            "test/c10v2_kat_vectors_ts200.json",
            "test/c10v2_kat_vectors_split810.json",
            "test/c10v2_kat_vectors_all3.json"
        ];
        string[9] memory keys = ["v0", "v1", "v2", "v3", "v4", "v5", "n0", "n1", "n2"];
        _resetTally();
        for (uint256 f = 0; f < 5; f++) {
            string memory json = vm.readFile(files[f]);
            for (uint256 k = 0; k < 9; k++) {
                _check(true, _cd(_vecAt(json, keys[k])), string.concat(files[f], " ", keys[k]));
            }
        }
        _logTally("v2 KAT files");
        assertEq(tally[0], 12, "0.3 + prf2 KATs accepted");
    }

    /// The v1 vector file (top-level + 12 labelled vectors), the v1 vectors under the v2 verifier
    /// and vice versa, and the 246-entry v1 mutant corpus.
    function test_v1_vectors_and_mutant_corpus() public {
        string memory j1 = vm.readFile("test/c10_test_vectors.json");
        _resetTally();
        Vec memory top = Vec(
            vm.parseJsonBytes32(j1, ".pkSeed"),
            vm.parseJsonBytes32(j1, ".pkRoot"),
            vm.parseJsonBytes32(j1, ".message"),
            vm.parseJsonBytes(j1, ".signature")
        );
        _check(false, _cd(top), "top-level");
        for (uint256 i = 0; i < 12; i++) {
            string memory p = string.concat(".vectors[", vm.toString(i), "]");
            Vec memory v = Vec(
                vm.parseJsonBytes32(j1, string.concat(p, ".pkSeed")),
                vm.parseJsonBytes32(j1, string.concat(p, ".pkRoot")),
                vm.parseJsonBytes32(j1, string.concat(p, ".message")),
                vm.parseJsonBytes(j1, string.concat(p, ".signature"))
            );
            _check(false, _cd(v), p);
            _check(true, _cd(v), string.concat("v1 vector under v2 ", p));
        }
        for (uint256 i = 0; i < baseV2.length; i++) {
            _check(false, _cd(baseV2[i]), "v2 KAT under v1");
        }
        string memory jc = vm.readFile("test/c10_mutant_corpus.json");
        uint256 n = 246;
        for (uint256 i = 0; i < n; i++) {
            string memory p = string.concat(".entries[", vm.toString(i), "]");
            Vec memory v = Vec(
                vm.parseJsonBytes32(jc, string.concat(p, ".pkSeed")),
                vm.parseJsonBytes32(jc, string.concat(p, ".pkRoot")),
                vm.parseJsonBytes32(jc, string.concat(p, ".message")),
                vm.parseJsonBytes(jc, string.concat(p, ".signature"))
            );
            _check(false, _cd(v), p);
        }
        _logTally("v1 vectors + corpus");
        assertEq(tally[0], 1 + 4 + 4, "top-level + 4 valid vectors + 4 corpus positives accepted");
    }

    // ── deterministic sweeps (both versions) ────────────────────────────────

    /// One flipped bit at every 7th byte and at the first and last byte of every region.
    function _bitflipSweep(bool v2) internal {
        _resetTally();
        for (uint256 b = 0; b < 2; b++) {
            Vec memory v = _base(v2, b);
            for (uint256 pos = b; pos < 4008; pos += 7) {
                bytes memory s = _copy(v.sig);
                s[pos] = bytes1(uint8(s[pos]) ^ uint8(1 << (pos % 8)));
                _check(v2, abi.encodeWithSelector(SEL, v.s, v.r, v.m, s), string.concat("flip ", vm.toString(pos)));
            }
        }
        (uint256[10] memory st, uint256[10] memory len) = _regions();
        Vec memory v0 = _base(v2, 0);
        for (uint256 j = 0; j < 10; j++) {
            uint256[2] memory at = [st[j], st[j] + len[j] - 1];
            for (uint256 q = 0; q < 2; q++) {
                bytes memory s = _copy(v0.sig);
                s[at[q]] = bytes1(uint8(s[at[q]]) ^ 0x80);
                _check(v2, abi.encodeWithSelector(SEL, v0.s, v0.r, v0.m, s), "region edge flip");
            }
        }
        _logTally(v2 ? "v2 bit flips" : "v1 bit flips");
        assertEq(tally[0], 0, "a flip was accepted");
        assertGt(tally[1], 0, "no flip reached the root comparison");
        assertGt(tally[3], 0, "no flip hit a +C revert");
    }

    function test_v2_bitflip_sweep() public {
        _bitflipSweep(true);
    }

    function test_v1_bitflip_sweep() public {
        _bitflipSweep(false);
    }

    /// Lengths around and far from 4,008 (the Yul length check), short and long.
    function _lengthSweep(bool v2) internal {
        _resetTally();
        uint256[14] memory lens = [uint256(0), 1, 15, 16, 31, 32, 33, 2336, 4000, 4007, 4009, 4024, 4040, 8016];
        Vec memory v = _base(v2, 0);
        for (uint256 i = 0; i < lens.length; i++) {
            bytes memory s = new bytes(lens[i]);
            for (uint256 k = 0; k < lens[i]; k++) {
                s[k] = k < 4008 ? v.sig[k] : bytes1(uint8(k));
            }
            _check(v2, abi.encodeWithSelector(SEL, v.s, v.r, v.m, s), string.concat("len ", vm.toString(lens[i])));
        }
        _logTally(v2 ? "v2 lengths" : "v1 lengths");
        assertEq(tally[2], lens.length, "every wrong length reverts with the reason");
    }

    function test_v2_length_sweep() public {
        _lengthSweep(true);
    }

    function test_v1_length_sweep() public {
        _lengthSweep(false);
    }

    /// Key and message shape: unmasked low halves (the I-2 `false` path), single-bit changes in
    /// the masked halves, swapped and zero keys, wrong message.
    function _keySweep(bool v2) internal {
        _resetTally();
        Vec memory v = _base(v2, 0);
        bytes32[14] memory s;
        bytes32[14] memory r;
        bytes32[14] memory m;
        for (uint256 i = 0; i < 14; i++) {
            (s[i], r[i], m[i]) = (v.s, v.r, v.m);
        }
        s[0] = v.s | bytes32(uint256(1));
        r[1] = v.r | bytes32(uint256(1));
        s[2] = v.s | bytes32(uint256(1) << 127);
        r[3] = v.r | bytes32(uint256(1) << 127);
        (s[4], r[4]) = (v.s | bytes32(uint256(1)), v.r | bytes32(uint256(1)));
        s[5] = v.s ^ bytes32(uint256(1) << 128);
        r[6] = v.r ^ bytes32(uint256(1) << 128);
        s[7] = v.s ^ bytes32(uint256(1) << 255);
        r[8] = v.r ^ bytes32(uint256(1) << 255);
        (s[9], r[9]) = (v.r, v.s);
        (s[10], r[10]) = (bytes32(0), bytes32(0));
        m[11] = v.m ^ bytes32(uint256(1));
        m[12] = bytes32(0);
        m[13] = v.m ^ bytes32(uint256(1) << 255);
        for (uint256 i = 0; i < 14; i++) {
            _check(v2, abi.encodeWithSelector(SEL, s[i], r[i], m[i], v.sig), string.concat("key case ", vm.toString(i)));
        }
        _logTally(v2 ? "v2 keys" : "v1 keys");
        assertEq(tally[0], 0);
        assertGt(tally[1], 4, "I-2 false path not exercised");
    }

    function test_v2_key_sweep() public {
        _keySweep(true);
    }

    function test_v1_key_sweep() public {
        _keySweep(false);
    }

    /// WOTS+C count fields at both layers: boundary values and +-1.
    function _countSweep(bool v2) internal {
        _resetTally();
        uint256[2] memory off = [uint256(3024), 3860];
        for (uint256 b = 0; b < 2; b++) {
            Vec memory v = _base(v2, b);
            for (uint256 l = 0; l < 2; l++) {
                uint256 c = (uint256(uint8(v.sig[off[l]])) << 24) | (uint256(uint8(v.sig[off[l] + 1])) << 16)
                    | (uint256(uint8(v.sig[off[l] + 2])) << 8) | uint256(uint8(v.sig[off[l] + 3]));
                uint256[7] memory cs = [uint256(0), 1, (c + 1) & 0xFFFFFFFF, (c + 0xFFFFFFFF) & 0xFFFFFFFF, 0x80000000, 0xFFFFFFFF, c ^ 0x100];
                for (uint256 k = 0; k < cs.length; k++) {
                    bytes memory s = _copy(v.sig);
                    for (uint256 q = 0; q < 4; q++) {
                        s[off[l] + q] = bytes1(uint8(cs[k] >> (24 - 8 * q)));
                    }
                    _check(v2, abi.encodeWithSelector(SEL, v.s, v.r, v.m, s), "count");
                }
            }
        }
        _logTally(v2 ? "v2 counts" : "v1 counts");
    }

    function test_v2_count_sweep() public {
        _countSweep(true);
    }

    function test_v1_count_sweep() public {
        _countSweep(false);
    }

    /// Splices: each region of base b replaced by the same region of base a (other message or key),
    /// and every base signature under every other base key.
    function _spliceSweep(bool v2) internal {
        _resetTally();
        (uint256[10] memory st, uint256[10] memory len) = _regions();
        uint256 nb = v2 ? baseV2.length : baseV1.length;
        for (uint256 a = 0; a < nb; a++) {
            for (uint256 b = 0; b < nb; b++) {
                Vec memory va = _base(v2, a);
                Vec memory vb = _base(v2, b);
                _check(v2, abi.encodeWithSelector(SEL, va.s, va.r, va.m, vb.sig), "cross");
                if (a == b || b != (a + 1) % nb) continue;
                for (uint256 j = 0; j < 10; j++) {
                    bytes memory s = _copy(va.sig);
                    for (uint256 k = st[j]; k < st[j] + len[j]; k++) {
                        s[k] = vb.sig[k];
                    }
                    _check(v2, abi.encodeWithSelector(SEL, va.s, va.r, va.m, s), "splice");
                }
            }
        }
        _logTally(v2 ? "v2 splices" : "v1 splices");
    }

    function test_v2_splice_sweep() public {
        _spliceSweep(true);
    }

    function test_v1_splice_sweep() public {
        _spliceSweep(false);
    }

    // ── fuzzed mutations ────────────────────────────────────────────────────

    function _mutate(bool v2, uint256 seed) internal view returns (bytes memory cd) {
        Vec memory v = _base(v2, seed);
        bytes memory s = _copy(v.sig);
        uint256 kind = _rnd(seed, 0) % 12;
        (uint256[10] memory st, uint256[10] memory len) = _regions();
        if (kind == 0) {
            uint256 p = _rnd(seed, 1) % 32064;
            s[p / 8] = bytes1(uint8(s[p / 8]) ^ uint8(1 << (p % 8)));
        } else if (kind == 1) {
            uint256 n = 1 + _rnd(seed, 1) % 8;
            for (uint256 i = 0; i < n; i++) {
                uint256 p = _rnd(seed, 2 + i) % 32064;
                s[p / 8] = bytes1(uint8(s[p / 8]) ^ uint8(1 << (p % 8)));
            }
        } else if (kind == 2) {
            uint256 at = _rnd(seed, 1) % 3993;
            bytes32 x = bytes32(_rnd(seed, 2));
            for (uint256 i = 0; i < 16; i++) {
                s[at + i] = x[i];
            }
        } else if (kind == 3) {
            uint256 l = _rnd(seed, 1) % 8100;
            bytes memory t = new bytes(l);
            for (uint256 i = 0; i < l; i++) {
                t[i] = i < 4008 ? s[i] : bytes1(uint8(_rnd(seed, 2 + i / 32) >> (i % 32)));
            }
            s = t;
        } else if (kind == 4) {
            bytes32 x = bytes32(_rnd(seed, 1));
            v.s = _rnd(seed, 2) % 2 == 0 ? x & bytes32(type(uint256).max << 128) : x;
        } else if (kind == 5) {
            bytes32 x = bytes32(_rnd(seed, 1));
            v.r = _rnd(seed, 2) % 2 == 0 ? x & bytes32(type(uint256).max << 128) : x;
        } else if (kind == 6) {
            v.m = bytes32(_rnd(seed, 1));
        } else if (kind == 7) {
            uint256 o = _rnd(seed, 1) % 2 == 0 ? 3024 : 3860;
            uint256 c = _rnd(seed, 2);
            for (uint256 q = 0; q < 4; q++) {
                s[o + q] = bytes1(uint8(c >> (8 * q)));
            }
        } else if (kind == 8) {
            uint256 j = _rnd(seed, 1) % 10;
            uint256 p = st[j] + _rnd(seed, 2) % len[j];
            s[p] = bytes1(uint8(s[p]) ^ uint8(1 << (_rnd(seed, 3) % 8)));
        } else if (kind == 9) {
            for (uint256 i = 0; i < 4008; i++) {
                s[i] = bytes1(uint8(_rnd(seed, 1 + i / 32) >> (8 * (i % 32))));
            }
        } else if (kind == 10) {
            uint256 a = 16 * (_rnd(seed, 1) % 250);
            uint256 b = 16 * (_rnd(seed, 2) % 250);
            for (uint256 i = 0; i < 16; i++) {
                (s[a + i], s[b + i]) = (s[b + i], s[a + i]);
            }
        } else {
            Vec memory w = _base(v2, _rnd(seed, 1));
            uint256 j = _rnd(seed, 2) % 10;
            for (uint256 k = st[j]; k < st[j] + len[j]; k++) {
                s[k] = w.sig[k];
            }
        }
        cd = abi.encodeWithSelector(SEL, v.s, v.r, v.m, s);
    }

    function testFuzz_v2_mutations(uint256 seed) public {
        _check(true, _mutate(true, seed), string.concat("fuzz seed ", vm.toString(seed)));
    }

    function testFuzz_v1_mutations(uint256 seed) public {
        _check(false, _mutate(false, seed), string.concat("fuzz seed ", vm.toString(seed)));
    }

    /// Valid signatures under non-canonical ABI encodings: the `bytes` offset moved past junk
    /// words, a length word with high bits set, trailing junk, and calldata truncated inside the
    /// signature. The Solidity ABI decoder's accept/revert decisions must match too.
    function _abiVariant(bool v2, uint256 seed) internal view returns (bytes memory cd) {
        Vec memory v = _base(v2, seed);
        uint256 kind = _rnd(seed, 0) % 6;
        uint256 junk = _rnd(seed, 1) % 4;
        bytes memory pre = abi.encodePacked(SEL, v.s, v.r, v.m, uint256(0x80 + 32 * junk));
        for (uint256 i = 0; i < junk; i++) {
            pre = bytes.concat(pre, bytes32(_rnd(seed, 10 + i)));
        }
        uint256 lenWord = v.sig.length;
        if (kind == 1) lenWord |= uint256(1) << (64 + _rnd(seed, 2) % 192);
        if (kind == 2) lenWord = _rnd(seed, 2) % 4100;
        bytes memory body = bytes.concat(bytes32(lenWord), v.sig);
        if (kind == 3) body = bytes.concat(body, bytes32(_rnd(seed, 3)), bytes8(uint64(_rnd(seed, 4))));
        cd = bytes.concat(pre, body);
        if (kind == 4) {
            uint256 cut = _rnd(seed, 5) % cd.length;
            bytes memory t = new bytes(cut);
            for (uint256 i = 0; i < cut; i++) {
                t[i] = cd[i];
            }
            cd = t;
        }
        if (kind == 5) {
            // offset word itself non-canonical: arbitrary value
            uint256 off = _rnd(seed, 6) % 2 == 0 ? _rnd(seed, 7) : _rnd(seed, 7) % 0x200;
            for (uint256 i = 0; i < 32; i++) {
                cd[100 + i] = bytes1(uint8(off >> (8 * (31 - i))));
            }
        }
    }

    function testFuzz_v2_abi_encodings(uint256 seed) public {
        _check(true, _abiVariant(true, seed), "abi");
    }

    function testFuzz_v1_abi_encodings(uint256 seed) public {
        _check(false, _abiVariant(false, seed), "abi");
    }

    function testFuzz_raw_calldata(bytes memory raw, bool withSelector) public {
        bytes memory cd = withSelector ? bytes.concat(SEL, raw) : raw;
        _check(true, cd, "raw");
        _check(false, cd, "raw");
    }
}
