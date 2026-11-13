// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";

/// RESEARCH (#1155 gas track): unit gate for the branch-free WOTS+C digit sum.
///
/// The verifiers sum the 43 base-8 digits (d >> 3i) & 7, i = 0..42 (the low 129 bits of the
/// 256-bit WOTS digest) and require 205. The equivalence differential cannot validate a rewrite
/// of that sum: a random digest has digit sum 205 with probability ~3.3e-5, so a rewrite that is
/// wrong on rare digests passes every sweep. This test compares the full integer sum of the
/// rewrite against the original loop.
///
/// Every line tagged with the SWAR-digit-sum tag below must appear verbatim (same lines) in each verifier
/// that uses it; research/c10-gas/gate.sh checks that text pin.
///
/// Why it is exact: lane k (bits 9k..9k+8) of `lanes` holds digits 3k, 3k+1, 3k+2 (k <= 13) or
/// digit 42 alone (k = 14; the two shifted masks stop at lane 13, so bits 129..134 never enter),
/// each lane <= 21. Multiplying by C9 = sum_{j<15} 2^(9j) puts sum_{k<=14} lane_k in lane 14; every
/// product lane is a sum of at most 15 lanes <= 315 < 512, so no carry crosses a lane boundary,
/// and the bits lost to the 256-bit wrap (lanes >= 28) lie above lane 14.
contract C10DigitSumTest is Test {
    function _loop(uint256 d) internal pure returns (uint256 digitSum) {
        assembly {
            for { let ii := 0 } lt(ii, 43) { ii := add(ii, 1) } {
                digitSum := add(digitSum, and(shr(mul(ii, 3), d), 0x7))
            }
        }
    }

    function _swar(uint256 d) internal pure returns (uint256 s) {
        assembly {
                let lanes := add(add(and(d, 0x1c0e070381c0e070381c0e070381c0e07), and(shr(3, d), 0xe070381c0e070381c0e070381c0e07)), and(shr(6, d), 0xe070381c0e070381c0e070381c0e07)) // C10-SWAR-DIGITSUM
                let digitSum := and(shr(126, mul(lanes, 0x40201008040201008040201008040201)), 0x1FF) // C10-SWAR-DIGITSUM
            s := digitSum
        }
    }

    /// forge-config: default.fuzz.runs = 20000
    function testFuzz_swar_equals_loop(uint256 d) public pure {
        assertEq(_swar(d), _loop(d));
    }

    /// forge-config: default.fuzz.runs = 5000
    function testFuzz_swar_equals_loop_with_high_garbage(uint256 lo, uint256 hi) public pure {
        uint256 d = (lo & ((uint256(1) << 129) - 1)) | (hi << 129);
        assertEq(_swar(d), _loop(d));
        assertEq(_swar(d), _swar(lo & ((uint256(1) << 129) - 1)), "bits 129..255 must not count");
    }

    function test_swar_extremes() public pure {
        uint256 low129 = (uint256(1) << 129) - 1;
        assertEq(_swar(0), 0);
        assertEq(_swar(low129), 301, "all 43 digits 7");
        assertEq(_swar(type(uint256).max), 301, "garbage above bit 128 ignored");
        assertEq(_swar(~low129), 0, "only bits 129..255 set");
        assertEq(_loop(type(uint256).max), 301);
    }

    /// Every digit position and value alone, under every high-garbage pattern of bits 129..134
    /// (the would-be digits 43 and 44, which the shifted terms must exclude).
    function test_swar_single_digits() public pure {
        for (uint256 g = 0; g < 64; g++) {
            uint256 hi = g << 129;
            assertEq(_swar(hi), 0);
            for (uint256 i = 0; i < 43; i++) {
                for (uint256 v = 1; v < 8; v++) {
                    uint256 d = hi | (v << (3 * i));
                    assertEq(_swar(d), v);
                }
            }
        }
    }

    /// Constructed digests whose digit sum is exactly 205 (and 204/206, the near misses), with
    /// random high bits: the sum the verifier compares against must come out exact.
    function test_swar_constructed_target_sums() public pure {
        uint256[3] memory targets = [uint256(205), 204, 206];
        for (uint256 seed = 0; seed < 300; seed++) {
            for (uint256 t = 0; t < 3; t++) {
                uint8[43] memory dig;
                uint256 sum;
                for (uint256 i = 0; i < 43; i++) {
                    dig[i] = uint8(uint256(keccak256(abi.encode(seed, t, i))) % 8);
                    sum += dig[i];
                }
                // walk the sum to the target one digit step at a time
                uint256 j = uint256(keccak256(abi.encode(seed, "j"))) % 43;
                while (sum != targets[t]) {
                    if (sum < targets[t] && dig[j] < 7) {
                        dig[j]++;
                        sum++;
                    } else if (sum > targets[t] && dig[j] > 0) {
                        dig[j]--;
                        sum--;
                    }
                    j = (j + 1) % 43;
                }
                uint256 d = uint256(keccak256(abi.encode(seed, t, "hi"))) << 129;
                for (uint256 i = 0; i < 43; i++) {
                    d |= uint256(dig[i]) << (3 * i);
                }
                assertEq(_loop(d), targets[t]);
                assertEq(_swar(d), targets[t]);
            }
        }
    }
}
