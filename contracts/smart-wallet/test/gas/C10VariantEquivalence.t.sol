// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, Vm, console2} from "forge-std/Test.sol";
import {VmSafe} from "forge-std/Vm.sol";
import {ISPHINCSVerifier} from "../../src/verifiers/ISPHINCSVerifier.sol";
import {SPHINCsC10v2Ts200Asm} from "../../src/verifiers/SPHINCsC10v2Ts200Asm.sol";
import {SPHINCsC10v2Split810Asm} from "../../src/verifiers/SPHINCsC10v2Split810Asm.sol";
import {SPHINCsC10v2All3Asm} from "../../src/verifiers/SPHINCsC10v2All3Asm.sol";
import {RefSPHINCsC10v2Ts200Asm} from "../ref/RefSPHINCsC10v2Ts200Asm.sol";
import {RefSPHINCsC10v2Split810Asm} from "../ref/RefSPHINCsC10v2Split810Asm.sol";
import {RefSPHINCsC10v2All3Asm} from "../ref/RefSPHINCsC10v2All3Asm.sol";

/// RESEARCH (#1155 gas track): equivalence gate for the three research variants (ts200, split810,
/// all3), whose optimized candidates are derived mechanically from the optimized draft-0.3
/// verifier (research/c10-gas/derive_v2_variants.py). Same observation as C10Equivalence.t.sol:
/// (success flag, exact returndata, ordered SHA-256 precompile inputs), reference (test/ref/,
/// frozen at 0895dcc79) vs candidate, over: every KAT file with its +C near-misses, bit-flip,
/// key/length (check order), count and trailing-junk sweeps, deep conditioned garbage (both
/// WOTS+C counts re-ground to the variant's target sum, all hashes run), fuzzed mutations and
/// non-canonical ABI encodings. Layout-aware: split810's layer sections are 820 and 852 bytes.
abstract contract C10VariantEquivalenceBase is Test {
    bytes4 internal constant SEL = ISPHINCSVerifier.verify.selector;

    struct Vec {
        bytes32 s;
        bytes32 r;
        bytes32 m;
        bytes sig;
    }

    struct Obs {
        bool ok;
        bytes ret;
        bytes32[] trace;
    }

    address internal ref;
    address internal cand;
    uint256 internal target; // WOTS+C digit sum
    uint256 internal h0; // layer-0 subtree height (9 or 8)
    string internal ownKats; // the KAT file this variant accepts
    Vec[] internal base;
    uint256[4] internal tally; // accepted, returned false, reverted with data, reverted empty

    function _deploy() internal virtual returns (address r, address c, uint256 t, uint256 h, string memory kats);

    function setUp() public {
        (ref, cand, target, h0, ownKats) = _deploy();
        string memory j = vm.readFile(ownKats);
        for (uint256 i = 0; i < 6; i++) {
            base.push(_vecAt(j, string.concat("v", vm.toString(i))));
        }
    }

    // ── observation ─────────────────────────────────────────────────────────

    function _isSha(Vm.AccountAccess memory x) internal pure returns (bool) {
        return x.account == address(2)
            && (x.kind == VmSafe.AccountAccessKind.Call || x.kind == VmSafe.AccountAccessKind.DelegateCall
                || x.kind == VmSafe.AccountAccessKind.CallCode || x.kind == VmSafe.AccountAccessKind.StaticCall);
    }

    function _observe(address v, bytes memory cd) internal returns (Obs memory o) {
        vm.startStateDiffRecording();
        (o.ok, o.ret) = v.staticcall(cd);
        Vm.AccountAccess[] memory a = vm.stopAndReturnStateDiff();
        uint256 n;
        for (uint256 i = 0; i < a.length; i++) {
            if (_isSha(a[i])) n++;
        }
        o.trace = new bytes32[](n);
        n = 0;
        for (uint256 i = 0; i < a.length; i++) {
            if (_isSha(a[i])) o.trace[n++] = keccak256(abi.encodePacked(uint8(a[i].kind), a[i].data));
        }
    }

    function _rawTrace(address v, bytes memory cd) internal returns (bytes[] memory ins) {
        vm.startStateDiffRecording();
        v.staticcall(cd);
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

    function _check(bytes memory cd, string memory what) internal {
        Obs memory x = _observe(ref, cd);
        Obs memory y = _observe(cand, cd);
        string memory d;
        if (x.ok != y.ok) d = "success flag differs";
        else if (keccak256(x.ret) != keccak256(y.ret)) d = "returndata differs";
        else if (x.trace.length != y.trace.length) {
            d = string.concat("SHA-256 call count ", vm.toString(x.trace.length), " vs ", vm.toString(y.trace.length));
        } else {
            for (uint256 i = 0; i < x.trace.length; i++) {
                if (x.trace[i] != y.trace[i]) {
                    d = string.concat("SHA-256 input #", vm.toString(i), " differs");
                    break;
                }
            }
        }
        if (bytes(d).length != 0) revert(string.concat("VARIANT EQUIVALENCE FAIL [", what, "]: ", d));
        if (!x.ok) tally[x.ret.length == 0 ? 3 : 2]++;
        else if (x.ret.length == 32 && abi.decode(x.ret, (uint256)) == 1) tally[0]++;
        else tally[1]++;
    }

    // ── helpers ─────────────────────────────────────────────────────────────

    function _vecAt(string memory json, string memory k) internal pure returns (Vec memory v) {
        v.s = vm.parseJsonBytes32(json, string.concat(".", k, ".pkSeed"));
        v.r = vm.parseJsonBytes32(json, string.concat(".", k, ".pkRoot"));
        v.m = vm.parseJsonBytes32(json, string.concat(".", k, ".message"));
        v.sig = vm.parseJsonBytes(json, string.concat(".", k, ".signature"));
    }

    function _cd(Vec memory v, bytes memory s) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(SEL, v.s, v.r, v.m, s);
    }

    function _rnd(uint256 seed, uint256 i) internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(seed, i)));
    }

    function _reset() internal {
        tally = [uint256(0), 0, 0, 0];
    }

    function _log(string memory what) internal view {
        console2.log(string.concat(what, " accept/false/revert-data/revert-empty"), tally[0], tally[1]);
        console2.log("   ", tally[2], tally[3]);
    }

    /// R, FORS secrets, FORS last slot, FORS auth, then per layer the 43 chains, the count and
    /// the auth path (layer heights h0 and 18 - h0).
    function _regions() internal view returns (uint256[10] memory st, uint256[10] memory len) {
        uint256 l1 = 2336 + 688 + 4 + 16 * h0;
        st = [uint256(0), 16, 208, 224, 2336, 3024, 3028, l1, l1 + 688, l1 + 692];
        len = [uint256(16), 192, 16, 2112, 688, 4, 16 * h0, 688, 4, 16 * (18 - h0)];
    }

    function _countOff(uint256 l) internal view returns (uint256) {
        return l == 0 ? 3024 : 2336 + 688 + 4 + 16 * h0 + 688;
    }

    /// Trace index of the layer-l WOTS_DIGEST call: H_MSG + 12*12 FORS + FORS_LAST + T_13 = 147;
    /// layer 1 adds the layer-0 digest, its 301 - target chain steps, T_43 and h0 Merkle nodes.
    function _digestIdx(uint256 l) internal view returns (uint256) {
        return l == 0 ? 147 : 147 + 1 + (301 - target) + 1 + h0;
    }

    function _fullTrace() internal view returns (uint256) {
        return 147 + 2 * (301 - target) + 4 + 18;
    }

    // ── tests ───────────────────────────────────────────────────────────────

    function test_all_kat_files() public {
        string[5] memory files = [
            "test/c10v2_kat_vectors.json",
            "test/c10v2_kat_vectors_prf2.json",
            "test/c10v2_kat_vectors_ts200.json",
            "test/c10v2_kat_vectors_split810.json",
            "test/c10v2_kat_vectors_all3.json"
        ];
        string[9] memory keys = ["v0", "v1", "v2", "v3", "v4", "v5", "n0", "n1", "n2"];
        _reset();
        for (uint256 f = 0; f < 5; f++) {
            string memory json = vm.readFile(files[f]);
            for (uint256 k = 0; k < 9; k++) {
                Vec memory v = _vecAt(json, keys[k]);
                _check(_cd(v, v.sig), string.concat(files[f], " ", keys[k]));
            }
        }
        _log("KAT files");
        assertEq(tally[0], 6, "exactly the variant's own six KATs accepted");
    }

    function test_trace_length_of_a_valid_signature() public {
        Obs memory o = _observe(ref, _cd(base[0], base[0].sig));
        assertTrue(o.ok);
        assertEq(o.trace.length, _fullTrace(), "layout parameters of this harness");
    }

    function test_bitflip_sweep() public {
        _reset();
        for (uint256 b = 0; b < 2; b++) {
            Vec memory v = base[b];
            for (uint256 pos = b; pos < 4008; pos += 7) {
                bytes memory s = bytes.concat(v.sig);
                s[pos] = bytes1(uint8(s[pos]) ^ uint8(1 << (pos % 8)));
                _check(_cd(v, s), string.concat("flip ", vm.toString(pos)));
            }
        }
        _log("bit flips");
        assertEq(tally[0], 0);
        assertGt(tally[1], 0);
        assertGt(tally[3], 0);
    }

    function test_key_and_length_cross() public {
        _reset();
        Vec memory v = base[0];
        uint256[5] memory lens = [uint256(0), 4007, 4008, 4009, 8016];
        for (uint256 i = 0; i < lens.length; i++) {
            bytes memory s = new bytes(lens[i]);
            for (uint256 k = 0; k < lens[i] && k < 4008; k++) {
                s[k] = v.sig[k];
            }
            for (uint256 j = 0; j < 4; j++) {
                bytes32 ks = j % 2 == 1 ? v.s | bytes32(uint256(1)) : v.s;
                bytes32 kr = j >= 2 ? v.r | bytes32(uint256(1)) : v.r;
                _check(abi.encodeWithSelector(SEL, ks, kr, v.m, s), "keys x length");
                _check(abi.encodeWithSelector(SEL, ks, kr, ~v.m, s), "keys x length, other message");
            }
        }
        _log("keys x lengths");
        assertEq(tally[2], 32, "every wrong length reverts with the reason");
        assertEq(tally[0], 1, "only the untouched signature is accepted");
    }

    function test_count_sweep() public {
        _reset();
        for (uint256 b = 0; b < 2; b++) {
            Vec memory v = base[b];
            for (uint256 l = 0; l < 2; l++) {
                uint256 o = _countOff(l);
                uint256 c = (uint256(uint8(v.sig[o])) << 24) | (uint256(uint8(v.sig[o + 1])) << 16)
                    | (uint256(uint8(v.sig[o + 2])) << 8) | uint256(uint8(v.sig[o + 3]));
                uint256[6] memory cs = [uint256(0), (c + 1) & 0xFFFFFFFF, (c + 0xFFFFFFFF) & 0xFFFFFFFF, 0x80000000, 0xFFFFFFFF, c ^ 0x100];
                for (uint256 k = 0; k < cs.length; k++) {
                    bytes memory s = bytes.concat(v.sig);
                    for (uint256 q = 0; q < 4; q++) {
                        s[o + q] = bytes1(uint8(cs[k] >> (24 - 8 * q)));
                    }
                    _check(_cd(v, s), "count");
                }
            }
        }
        _log("counts");
    }

    function test_trailing_junk() public {
        _reset();
        for (uint256 b = 0; b < base.length; b++) {
            Vec memory v = base[b];
            for (uint256 k = 0; k < 3; k++) {
                bytes memory cd = _cd(v, v.sig);
                uint256 dataEnd = 4 + 160 + 4008;
                bytes32 junk = k == 0 ? bytes32(type(uint256).max) : bytes32(_rnd(b, k));
                for (uint256 i = 0; i < 24; i++) {
                    cd[dataEnd + i] = junk[i];
                }
                if (k == 2) cd[dataEnd - 1] = bytes1(uint8(cd[dataEnd - 1]) ^ 1);
                _check(cd, "trailing junk");
            }
        }
        _log("trailing junk");
        assertEq(tally[0], 2 * base.length);
        assertEq(tally[1], base.length);
    }

    // ── deep conditioned garbage ────────────────────────────────────────────

    function _digitSum(bytes32 h) internal pure returns (uint256 sum) {
        uint256 d = uint256(h);
        for (uint256 i = 0; i < 43; i++) {
            sum += (d >> (3 * i)) & 7;
        }
    }

    function _grind(bytes memory pre, uint256 start) internal view returns (uint256 c) {
        for (c = start;; c++) {
            pre[32] = bytes1(uint8(c >> 24));
            pre[33] = bytes1(uint8(c >> 16));
            pre[34] = bytes1(uint8(c >> 8));
            pre[35] = bytes1(uint8(c));
            (, bytes memory h) = address(2).staticcall(pre);
            if (_digitSum(bytes32(h)) == target) return c;
        }
    }

    function _deep(uint256 seed, uint256 region) internal {
        Vec memory v = base[seed % base.length];
        (uint256[10] memory st, uint256[10] memory len) = _regions();
        bytes memory s = bytes.concat(v.sig);
        uint256 w = 16 + _rnd(seed, 1) % 49;
        if (w > len[region]) w = len[region];
        uint256 at = st[region] + _rnd(seed, 2) % (len[region] - w + 1);
        for (uint256 i = 0; i < w; i++) {
            s[at + i] = bytes1(uint8(_rnd(seed, 3 + i / 32) >> (8 * (i % 32))));
        }
        for (uint256 l = 0; l < 2; l++) {
            bytes[] memory tr = _rawTrace(ref, _cd(v, s));
            require(tr.length > _digestIdx(l), "conditioned input stopped before the digest");
            bytes memory pre = tr[_digestIdx(l)];
            require(pre.length == 43, "harness: not a WOTS_DIGEST preimage");
            if (_digitSum(sha256(pre)) == target) continue;
            uint256 c = _grind(pre, _rnd(seed, 100 + l) % 0x100000);
            uint256 o = _countOff(l);
            for (uint256 q = 0; q < 4; q++) {
                s[o + q] = bytes1(uint8(c >> (24 - 8 * q)));
            }
        }
        bytes memory cd = _cd(v, s);
        assertEq(_rawTrace(ref, cd).length, _fullTrace(), "conditioned input does not reach the root comparison");
        _check(cd, string.concat("deep region ", vm.toString(region)));
    }

    function test_deep_conditioned_garbage() public {
        _reset();
        uint256[7] memory regions = [uint256(1), 2, 3, 4, 6, 7, 9];
        for (uint256 j = 0; j < regions.length; j++) {
            for (uint256 k = 0; k < 2; k++) {
                _deep(1000 * j + k, regions[j]);
            }
        }
        _log("deep");
        assertEq(tally[1], 14, "every conditioned input runs all hashes and returns false");
    }

    /// forge-config: default.fuzz.runs = 16
    function testFuzz_deep(uint256 seed) public {
        uint256[7] memory regions = [uint256(1), 2, 3, 4, 6, 7, 9];
        _deep(seed, regions[seed % 7]);
    }

    // ── fuzzed mutations and ABI encodings ──────────────────────────────────

    function testFuzz_mutations(uint256 seed) public {
        Vec memory v = base[seed % base.length];
        bytes memory s = bytes.concat(v.sig);
        uint256 kind = _rnd(seed, 0) % 6;
        (uint256[10] memory st, uint256[10] memory len) = _regions();
        if (kind == 0) {
            uint256 p = _rnd(seed, 1) % 32064;
            s[p / 8] = bytes1(uint8(s[p / 8]) ^ uint8(1 << (p % 8)));
        } else if (kind == 1) {
            uint256 at = _rnd(seed, 1) % 3993;
            bytes32 x = bytes32(_rnd(seed, 2));
            for (uint256 i = 0; i < 16; i++) {
                s[at + i] = x[i];
            }
        } else if (kind == 2) {
            uint256 j = _rnd(seed, 1) % 10;
            uint256 p = st[j] + _rnd(seed, 2) % len[j];
            s[p] = bytes1(uint8(s[p]) ^ uint8(1 << (_rnd(seed, 3) % 8)));
        } else if (kind == 3) {
            Vec memory w = base[_rnd(seed, 1) % base.length];
            uint256 j = _rnd(seed, 2) % 10;
            for (uint256 k = st[j]; k < st[j] + len[j]; k++) {
                s[k] = w.sig[k];
            }
        } else if (kind == 4) {
            v.m = bytes32(_rnd(seed, 1));
        } else {
            bytes32 x = bytes32(_rnd(seed, 1));
            v.s = _rnd(seed, 2) % 2 == 0 ? x & bytes32(type(uint256).max << 128) : x;
        }
        _check(_cd(v, s), string.concat("fuzz seed ", vm.toString(seed)));
    }

    function testFuzz_abi_encodings(uint256 seed) public {
        Vec memory v = base[seed % base.length];
        uint256 junk = _rnd(seed, 1) % 4;
        bytes memory pre = abi.encodePacked(SEL, v.s, v.r, v.m, uint256(0x80 + 32 * junk));
        for (uint256 i = 0; i < junk; i++) {
            pre = bytes.concat(pre, bytes32(_rnd(seed, 10 + i)));
        }
        uint256 kind = _rnd(seed, 0) % 4;
        uint256 lenWord = kind == 1 ? _rnd(seed, 2) % 4100 : v.sig.length;
        bytes memory cd = bytes.concat(pre, bytes32(lenWord), v.sig);
        if (kind == 2) cd = bytes.concat(cd, bytes32(_rnd(seed, 3)));
        if (kind == 3) {
            uint256 cut = _rnd(seed, 5) % cd.length;
            bytes memory t = new bytes(cut);
            for (uint256 i = 0; i < cut; i++) {
                t[i] = cd[i];
            }
            cd = t;
        }
        _check(cd, "abi");
    }
}

contract C10VariantEquivalenceTs200Test is C10VariantEquivalenceBase {
    function _deploy() internal override returns (address, address, uint256, uint256, string memory) {
        return (address(new RefSPHINCsC10v2Ts200Asm()), address(new SPHINCsC10v2Ts200Asm()), 200, 9,
            "test/c10v2_kat_vectors_ts200.json");
    }
}

contract C10VariantEquivalenceSplit810Test is C10VariantEquivalenceBase {
    function _deploy() internal override returns (address, address, uint256, uint256, string memory) {
        return (address(new RefSPHINCsC10v2Split810Asm()), address(new SPHINCsC10v2Split810Asm()), 205, 8,
            "test/c10v2_kat_vectors_split810.json");
    }
}

contract C10VariantEquivalenceAll3Test is C10VariantEquivalenceBase {
    function _deploy() internal override returns (address, address, uint256, uint256, string memory) {
        return (address(new RefSPHINCsC10v2All3Asm()), address(new SPHINCsC10v2All3Asm()), 200, 8,
            "test/c10v2_kat_vectors_all3.json");
    }
}
