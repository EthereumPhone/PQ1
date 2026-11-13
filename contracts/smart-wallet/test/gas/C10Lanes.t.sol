// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";

/// RESEARCH (#1155 gas track): exhaustive unit gate for the two per-walk words of the unrolled
/// FORS / hypertree auth walks (research/c10-gas/gen_v2_walks.py). For every leaf index
/// t < 2^11 (FORS trees have 11 levels, hypertree subtrees 8..10):
///   cpha:  the top 16 bits of shl(16(h-1), cpha) are A7 bytes 5..6 at height h = 1..11,
///          i.e. cp = h (bits 15..12) and ha = t >> h (bits 11..1), bit 0 zero;
///   slots: byte(2k+1, slots) is the slot of the node at height k = 0..10: 0x10 if bit k of t is 0,
///          else 0x20; byte(2k, slots) is its sibling's slot, 0x30 minus that.
/// Every line tagged C10-LANES must appear verbatim in the v2 verifiers (gate.sh text pin).
/// The lines below are the verifier's.
contract C10LanesTest is Test {
    function _words(uint256 t) internal pure returns (uint256 c, uint256 s) {
        assembly {
            let cpha := or(and(mul(t, 0x1000080004000200010000800040002000100008000400000000000000000), 0x7fe03fe01fe00fe007e003e001e000e00060002000000000000000000000000), 0x100020003000400050006000700080009000a000b00000000000000000000000) // C10-LANES
            let sbit := and(mul(t, 0x10000800040002000100008000400020001000080004000000000000000000), 0x10001000100010001000100010001000100010001000000000000000000000) // C10-LANES
            let slots := sub(add(sbit, 0x2010201020102010201020102010201020102010201000000000000000000000), shl(8, sbit)) // C10-LANES
            c := cpha
            s := slots
        }
    }

    function test_lanes_exhaustive() public pure {
        for (uint256 t = 0; t < 2048; t++) {
            (uint256 c, uint256 s) = _words(t);
            for (uint256 h = 1; h <= 11; h++) {
                assertEq((c << (16 * (h - 1))) >> 240, (h << 12) | ((t >> h) << 1), "cp/ha lane");
            }
            for (uint256 k = 0; k <= 10; k++) {
                uint256 b = (s >> (8 * (31 - (2 * k + 1)))) & 0xFF;
                assertEq(b, ((t >> k) & 1) == 0 ? 0x10 : 0x20, "slot byte");
                uint256 sib = (s >> (8 * (31 - 2 * k))) & 0xFF;
                assertEq(sib, 0x30 - b, "sibling slot byte");
            }
        }
    }
}
