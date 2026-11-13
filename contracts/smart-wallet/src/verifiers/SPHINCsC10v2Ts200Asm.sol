// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @notice RESEARCH (#1155) — C10 v2 verifier, VARIANT ts200: DRAFT 0.3
/// (research/c10-autoresearch/c10v2-spec.md) with the WOTS+C target digit sum 200 instead of 205.
/// Nothing else differs from `SPHINCsC10v2Asm`. Security-check candidate only; NOT deployed and
/// NOT a spec decision. KATs: test/c10v2_kat_vectors_ts200.json (c10v2_ref.py --variant ts200).
///
/// Base (0.3): same scheme and 4,008-byte signature as `SPHINCsC10Asm` (v1); every hash preimage
/// is the one-block v2 layout: 16-byte seed and values, the 7-byte compact address A7.
///
/// Memory: 0x00..0x4F scratch for one-block preimages (S at 0x00..0x10, never overwritten);
/// 0x60 the 32-byte H_MSG / WOTS_DIGEST outputs; 0x80.. the T_k buffer `S || A7 || 0x00 || v_0 ..`
/// (S written once). Every other hash writes its 16-byte output in place.
/// Packed 16-byte stores overlap (each mstore writes 32 bytes), so every preimage is written in
/// ascending address order with A7 last (`shl(200, a7)` puts its 7 bytes at the store address).
contract SPHINCsC10v2Ts200Asm {
    function verify(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes calldata sig)
        external
        view
        returns (bool valid)
    {
        assembly {
            let N_MASK := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000
            let OUT := 0x60
            let TB := 0x80
            if iszero(eq(sig.length, 4008)) {
                mstore(0x00, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                mstore(0x04, 0x20)
                mstore(0x24, 18)
                mstore(0x44, "Invalid sig length")
                revert(0x00, 0x64)
            }
            if iszero(eq(and(pkSeed, N_MASK), pkSeed)) {
                mstore(0x00, 0)
                return(0x00, 0x20)
            }
            if iszero(eq(and(pkRoot, N_MASK), pkRoot)) {
                mstore(0x00, 0)
                return(0x00, 0x20)
            }
            let sigBase := sig.offset

            // A7 = type<<52 | layer<<51 | tree<<33 | kp<<24 | ci<<18 | cp<<12 | ha<<1 (spec §1).

            // H_MSG: S || root || M || R || A7(8), 87 bytes.
            mstore(0x00, pkSeed)
            mstore(0x10, pkRoot)
            mstore(0x20, message)
            mstore(0x40, calldataload(sigBase)) // R; its low half is overwritten by the A7 store
            mstore(0x50, shl(200, shl(52, 8)))
            pop(staticcall(gas(), 0x02, 0x00, 87, OUT, 32))
            let digest := mload(OUT)
            let htIdx := and(shr(143, digest), 0x3FFFF)
            if and(shr(132, digest), 0x7FF) { revert(0, 0) } // FORS+C: last index must be 0

            // FORS roots straight into the T_13 buffer: S || A7(4, tree=ht) || 0x00 || r_0..r_12.
            mstore(TB, pkSeed)
            mstore(add(TB, 0x10), shl(200, or(shl(52, 4), shl(33, htIdx))))
            // Tree i = 0..11, strength-reduced: dg = digest >> 11 i (its low 11 bits are tree i's leaf
            // index), base = A7 of tree i at cp = ha = 0 (kp = i), secret / auth path / T_13 slot by
            // running pointers (16, 176 and 16 bytes per tree).
            let dg := digest
            let base := or(shl(52, 3), shl(33, htIdx))
            let secretPtr := add(sigBase, 16)
            let authPtr := add(sigBase, 224)
            let rootSlot := add(TB, 24)
            for { } lt(rootSlot, add(TB, 216)) {
                dg := shr(11, dg)
                base := add(base, shl(24, 1))
                secretPtr := add(secretPtr, 16)
                authPtr := add(authPtr, 176)
                rootSlot := add(rootSlot, 16)
            } {
                let treeIdx := and(dg, 0x7FF)
                // leaf F: S || secret || A7(3, ht, kp=i, ha=leaf)
                mstore(0x10, calldataload(secretPtr)) // low half: next store
                mstore(0x20, shl(200, or(base, shl(1, treeIdx))))
                // In-place auth walk: every node is written (16 bytes) straight into its half of
                // the next H preimage S || L16 || R16 || A7, left at 0x10 if its index is even,
                // else right at 0x20; the 16-byte sibling is copied into the other half. Unrolled
                // (generated); per-level slots and (cp, ha) come from `slots` / `cpha` (see
                // gen_v2_walks.py); A7 bytes 0..4 are stored once, bytes 5..6 per level.
                // BEGIN generated FORS walk (research/c10-gas/gen_v2_walks.py; do not edit by hand)
                let t := treeIdx
                let cpha := or(and(mul(t, 0x1000080004000200010000800040002000100008000400000000000000000), 0x7fe03fe01fe00fe007e003e001e000e00060002000000000000000000000000), 0x100020003000400050006000700080009000a000b00000000000000000000000) // C10-LANES
                let sbit := and(mul(t, 0x10000800040002000100008000400020001000080004000000000000000000), 0x10001000100010001000100010001000100010001000000000000000000000) // C10-LANES
                let slots := sub(add(sbit, 0x2010201020102010201020102010201020102010201000000000000000000000), shl(8, sbit)) // C10-LANES
                pop(staticcall(gas(), 0x02, 0x00, 39, byte(1, slots), 16)) // the leaf, at its slot
                mstore(0x30, shl(200, base)) // A7 bytes 0..4 for all 11 levels
                calldatacopy(byte(0, slots), add(authPtr, 0), 16)
                mstore(0x35, shl(0, cpha))
                pop(staticcall(gas(), 0x02, 0x00, 55, byte(3, slots), 16))
                calldatacopy(byte(2, slots), add(authPtr, 16), 16)
                mstore(0x35, shl(16, cpha))
                pop(staticcall(gas(), 0x02, 0x00, 55, byte(5, slots), 16))
                calldatacopy(byte(4, slots), add(authPtr, 32), 16)
                mstore(0x35, shl(32, cpha))
                pop(staticcall(gas(), 0x02, 0x00, 55, byte(7, slots), 16))
                calldatacopy(byte(6, slots), add(authPtr, 48), 16)
                mstore(0x35, shl(48, cpha))
                pop(staticcall(gas(), 0x02, 0x00, 55, byte(9, slots), 16))
                calldatacopy(byte(8, slots), add(authPtr, 64), 16)
                mstore(0x35, shl(64, cpha))
                pop(staticcall(gas(), 0x02, 0x00, 55, byte(11, slots), 16))
                calldatacopy(byte(10, slots), add(authPtr, 80), 16)
                mstore(0x35, shl(80, cpha))
                pop(staticcall(gas(), 0x02, 0x00, 55, byte(13, slots), 16))
                calldatacopy(byte(12, slots), add(authPtr, 96), 16)
                mstore(0x35, shl(96, cpha))
                pop(staticcall(gas(), 0x02, 0x00, 55, byte(15, slots), 16))
                calldatacopy(byte(14, slots), add(authPtr, 112), 16)
                mstore(0x35, shl(112, cpha))
                pop(staticcall(gas(), 0x02, 0x00, 55, byte(17, slots), 16))
                calldatacopy(byte(16, slots), add(authPtr, 128), 16)
                mstore(0x35, shl(128, cpha))
                pop(staticcall(gas(), 0x02, 0x00, 55, byte(19, slots), 16))
                calldatacopy(byte(18, slots), add(authPtr, 144), 16)
                mstore(0x35, shl(144, cpha))
                pop(staticcall(gas(), 0x02, 0x00, 55, byte(21, slots), 16))
                calldatacopy(byte(20, slots), add(authPtr, 160), 16)
                mstore(0x35, shl(160, cpha))
                pop(staticcall(gas(), 0x02, 0x00, 55, rootSlot, 16))
                // END generated FORS walk
            }
            {
                // the last slot: F(S, A7(FORS_LAST=9, tree=ht), slot)
                mstore(0x10, calldataload(add(sigBase, 208))) // low half: next store
                mstore(0x20, shl(200, or(shl(52, 9), shl(33, htIdx))))
                pop(staticcall(gas(), 0x02, 0x00, 39, add(TB, add(24, 192)), 16))
            }
            // T_13: the FORS pk lands at 0x10, the m16 field of the layer-0 WOTS_DIGEST preimage
            pop(staticcall(gas(), 0x02, TB, 232, 0x10, 16))

            let idxTree := htIdx
            let sigOff := 2336
            for { let layer := 0 } lt(layer, 2) { layer := add(layer, 1) } {
                let idxLeaf := and(idxTree, 0x1FF)
                idxTree := shr(9, idxTree)
                let kpBase := or(or(shl(51, layer), shl(33, idxTree)), shl(24, idxLeaf))
                let countOff := add(sigOff, 688)
                let count := shr(224, calldataload(add(sigBase, countOff)))
                // WOTS_DIGEST: S || m16 || be32(count) || A7(7, layer, tree, kp), 43 bytes; m16 (the
                // node being signed) is already at 0x10.
                mstore(0x20, shl(224, count))
                mstore(0x24, shl(200, or(shl(52, 7), kpBase)))
                pop(staticcall(gas(), 0x02, 0x00, 43, OUT, 32))
                let d := mload(OUT)
                // digits as v1 (spec 0.3): the LOW 129 bits, digit i = (d >> 3i) & 7, summed
                // branch-free (exactness argument and unit gate: test/gas/C10DigitSum.t.sol)
                let lanes := add(add(and(d, 0x1c0e070381c0e070381c0e070381c0e07), and(shr(3, d), 0xe070381c0e070381c0e070381c0e07)), and(shr(6, d), 0xe070381c0e070381c0e070381c0e07)) // C10-SWAR-DIGITSUM
                let digitSum := and(shr(126, mul(lanes, 0x40201008040201008040201008040201)), 0x1FF) // C10-SWAR-DIGITSUM
                if iszero(eq(digitSum, 200)) { revert(0, 0) } // WOTS+C target sum (variant ts200: 200)

                // chains into the T_43 buffer: S || A7(1, layer, tree, kp) || 0x00 || v_0..v_42 (S at
                // TB since the FORS roots: nothing writes TB..TB+15 after that)
                mstore(add(TB, 0x10), shl(200, or(shl(52, 1), kpBase)))
                let wotsPtr := add(sigBase, sigOff)
                // Chain i runs from position digit_i = (d >> 3i) & 7 to 7 in place: the value stays
                // at 0x10 of the F preimage S || v16 || A7 and each step's output (outsize 16)
                // overwrites it. A7 = chainA | i<<18 | p<<12 (type 0, WOTS_HASH): bytes 0..3 and 6
                // are those of chainA, written once per layer; byte 4 = ci<<2 is written per chain and
                // byte 5 = p<<4 per step, with mstore8. The end value is copied to T_43 slot i with a
                // 32-byte store: its trailing 16 bytes are overwritten by slot i+1, and for i = 42
                // they fall past the 712 bytes T_43 hashes. Unrolled over the 43 chains (generated);
                // chain i takes 7 - digit_i = bits 3i..3i+2 of nd steps, as blocks of 4, 2, 1.
                mstore(0x20, shl(200, kpBase)) // A7 of chain 0 at position 0
                let nd := not(d)
                // BEGIN generated chains (research/c10-gas/gen_v2_chains.py; do not edit by hand)
                calldatacopy(0x10, add(wotsPtr, 0), 16) // chain 0
                mstore8(0x24, 0) // A7 byte 4: ci
                {
                    let p := and(shl(4, d), 0x70)
                    if and(nd, shl(2, 1)) {
                        mstore8(0x25, p)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x20))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x30))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(1, 1)) {
                        mstore8(0x25, or(p, 0x40))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(or(p, 0x40), 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(0, 1)) {
                        mstore8(0x25, 0x60)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 24), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 16), 16) // chain 1
                mstore8(0x24, 4) // A7 byte 4: ci
                {
                    let p := and(shl(1, d), 0x70)
                    if and(nd, shl(5, 1)) {
                        mstore8(0x25, p)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x20))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x30))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(4, 1)) {
                        mstore8(0x25, or(p, 0x40))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(or(p, 0x40), 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(3, 1)) {
                        mstore8(0x25, 0x60)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 40), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 32), 16) // chain 2
                mstore8(0x24, 8) // A7 byte 4: ci
                {
                    let p := and(shr(2, d), 0x70)
                    if and(nd, shl(8, 1)) {
                        mstore8(0x25, p)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x20))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x30))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(7, 1)) {
                        mstore8(0x25, or(p, 0x40))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(or(p, 0x40), 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(6, 1)) {
                        mstore8(0x25, 0x60)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 56), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 48), 16) // chain 3
                mstore8(0x24, 12) // A7 byte 4: ci
                {
                    let p := and(shr(5, d), 0x70)
                    if and(nd, shl(11, 1)) {
                        mstore8(0x25, p)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x20))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x30))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(10, 1)) {
                        mstore8(0x25, or(p, 0x40))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(or(p, 0x40), 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(9, 1)) {
                        mstore8(0x25, 0x60)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 72), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 64), 16) // chain 4
                mstore8(0x24, 16) // A7 byte 4: ci
                {
                    let p := and(shr(8, d), 0x70)
                    if and(nd, shl(14, 1)) {
                        mstore8(0x25, p)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x20))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x30))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(13, 1)) {
                        mstore8(0x25, or(p, 0x40))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(or(p, 0x40), 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(12, 1)) {
                        mstore8(0x25, 0x60)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 88), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 80), 16) // chain 5
                mstore8(0x24, 20) // A7 byte 4: ci
                {
                    let p := and(shr(11, d), 0x70)
                    if and(nd, shl(17, 1)) {
                        mstore8(0x25, p)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x20))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x30))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(16, 1)) {
                        mstore8(0x25, or(p, 0x40))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(or(p, 0x40), 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(15, 1)) {
                        mstore8(0x25, 0x60)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 104), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 96), 16) // chain 6
                mstore8(0x24, 24) // A7 byte 4: ci
                {
                    let p := and(shr(14, d), 0x70)
                    if and(nd, shl(20, 1)) {
                        mstore8(0x25, p)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x20))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x30))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(19, 1)) {
                        mstore8(0x25, or(p, 0x40))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(or(p, 0x40), 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(18, 1)) {
                        mstore8(0x25, 0x60)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 120), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 112), 16) // chain 7
                mstore8(0x24, 28) // A7 byte 4: ci
                {
                    let p := and(shr(17, d), 0x70)
                    if and(nd, shl(23, 1)) {
                        mstore8(0x25, p)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x20))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x30))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(22, 1)) {
                        mstore8(0x25, or(p, 0x40))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(or(p, 0x40), 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(21, 1)) {
                        mstore8(0x25, 0x60)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 136), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 128), 16) // chain 8
                mstore8(0x24, 32) // A7 byte 4: ci
                {
                    let p := and(shr(20, d), 0x70)
                    if and(nd, shl(26, 1)) {
                        mstore8(0x25, p)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x20))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x30))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(25, 1)) {
                        mstore8(0x25, or(p, 0x40))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(or(p, 0x40), 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(24, 1)) {
                        mstore8(0x25, 0x60)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 152), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 144), 16) // chain 9
                mstore8(0x24, 36) // A7 byte 4: ci
                {
                    let p := and(shr(23, d), 0x70)
                    if and(nd, shl(29, 1)) {
                        mstore8(0x25, p)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x20))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x30))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(28, 1)) {
                        mstore8(0x25, or(p, 0x40))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(or(p, 0x40), 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(27, 1)) {
                        mstore8(0x25, 0x60)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 168), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 160), 16) // chain 10
                mstore8(0x24, 40) // A7 byte 4: ci
                {
                    let p := and(shr(26, d), 0x70)
                    if and(nd, shl(32, 1)) {
                        mstore8(0x25, p)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x20))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x30))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(31, 1)) {
                        mstore8(0x25, or(p, 0x40))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(or(p, 0x40), 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(30, 1)) {
                        mstore8(0x25, 0x60)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 184), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 176), 16) // chain 11
                mstore8(0x24, 44) // A7 byte 4: ci
                {
                    let p := and(shr(29, d), 0x70)
                    if and(nd, shl(35, 1)) {
                        mstore8(0x25, p)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x20))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x30))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(34, 1)) {
                        mstore8(0x25, or(p, 0x40))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(or(p, 0x40), 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(33, 1)) {
                        mstore8(0x25, 0x60)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 200), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 192), 16) // chain 12
                mstore8(0x24, 48) // A7 byte 4: ci
                {
                    let p := and(shr(32, d), 0x70)
                    if and(nd, shl(38, 1)) {
                        mstore8(0x25, p)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x20))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x30))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(37, 1)) {
                        mstore8(0x25, or(p, 0x40))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(or(p, 0x40), 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(36, 1)) {
                        mstore8(0x25, 0x60)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 216), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 208), 16) // chain 13
                mstore8(0x24, 52) // A7 byte 4: ci
                {
                    let p := and(shr(35, d), 0x70)
                    if and(nd, shl(41, 1)) {
                        mstore8(0x25, p)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x20))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x30))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(40, 1)) {
                        mstore8(0x25, or(p, 0x40))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(or(p, 0x40), 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(39, 1)) {
                        mstore8(0x25, 0x60)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 232), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 224), 16) // chain 14
                mstore8(0x24, 56) // A7 byte 4: ci
                {
                    let p := and(shr(38, d), 0x70)
                    if and(nd, shl(44, 1)) {
                        mstore8(0x25, p)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x20))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x30))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(43, 1)) {
                        mstore8(0x25, or(p, 0x40))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(or(p, 0x40), 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(42, 1)) {
                        mstore8(0x25, 0x60)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 248), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 240), 16) // chain 15
                mstore8(0x24, 60) // A7 byte 4: ci
                {
                    let p := and(shr(41, d), 0x70)
                    if and(nd, shl(47, 1)) {
                        mstore8(0x25, p)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x20))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x30))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(46, 1)) {
                        mstore8(0x25, or(p, 0x40))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(or(p, 0x40), 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(45, 1)) {
                        mstore8(0x25, 0x60)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 264), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 256), 16) // chain 16
                mstore8(0x24, 64) // A7 byte 4: ci
                {
                    let p := and(shr(44, d), 0x70)
                    if and(nd, shl(50, 1)) {
                        mstore8(0x25, p)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x20))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x30))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(49, 1)) {
                        mstore8(0x25, or(p, 0x40))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(or(p, 0x40), 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(48, 1)) {
                        mstore8(0x25, 0x60)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 280), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 272), 16) // chain 17
                mstore8(0x24, 68) // A7 byte 4: ci
                {
                    let p := and(shr(47, d), 0x70)
                    if and(nd, shl(53, 1)) {
                        mstore8(0x25, p)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x20))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x30))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(52, 1)) {
                        mstore8(0x25, or(p, 0x40))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(or(p, 0x40), 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(51, 1)) {
                        mstore8(0x25, 0x60)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 296), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 288), 16) // chain 18
                mstore8(0x24, 72) // A7 byte 4: ci
                {
                    let p := and(shr(50, d), 0x70)
                    if and(nd, shl(56, 1)) {
                        mstore8(0x25, p)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x20))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x30))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(55, 1)) {
                        mstore8(0x25, or(p, 0x40))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(or(p, 0x40), 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(54, 1)) {
                        mstore8(0x25, 0x60)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 312), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 304), 16) // chain 19
                mstore8(0x24, 76) // A7 byte 4: ci
                {
                    let p := and(shr(53, d), 0x70)
                    if and(nd, shl(59, 1)) {
                        mstore8(0x25, p)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x20))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x30))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(58, 1)) {
                        mstore8(0x25, or(p, 0x40))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(or(p, 0x40), 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(57, 1)) {
                        mstore8(0x25, 0x60)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 328), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 320), 16) // chain 20
                mstore8(0x24, 80) // A7 byte 4: ci
                {
                    let p := and(shr(56, d), 0x70)
                    if and(nd, shl(62, 1)) {
                        mstore8(0x25, p)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x20))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x30))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(61, 1)) {
                        mstore8(0x25, or(p, 0x40))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(or(p, 0x40), 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(60, 1)) {
                        mstore8(0x25, 0x60)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 344), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 336), 16) // chain 21
                mstore8(0x24, 84) // A7 byte 4: ci
                {
                    let p := and(shr(59, d), 0x70)
                    if and(nd, shl(65, 1)) {
                        mstore8(0x25, p)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x20))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x30))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(64, 1)) {
                        mstore8(0x25, or(p, 0x40))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(or(p, 0x40), 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(63, 1)) {
                        mstore8(0x25, 0x60)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 360), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 352), 16) // chain 22
                mstore8(0x24, 88) // A7 byte 4: ci
                {
                    let p := and(shr(62, d), 0x70)
                    if and(nd, shl(68, 1)) {
                        mstore8(0x25, p)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x20))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x30))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(67, 1)) {
                        mstore8(0x25, or(p, 0x40))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(or(p, 0x40), 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(66, 1)) {
                        mstore8(0x25, 0x60)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 376), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 368), 16) // chain 23
                mstore8(0x24, 92) // A7 byte 4: ci
                {
                    let p := and(shr(65, d), 0x70)
                    if and(nd, shl(71, 1)) {
                        mstore8(0x25, p)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x20))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x30))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(70, 1)) {
                        mstore8(0x25, or(p, 0x40))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(or(p, 0x40), 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(69, 1)) {
                        mstore8(0x25, 0x60)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 392), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 384), 16) // chain 24
                mstore8(0x24, 96) // A7 byte 4: ci
                {
                    let p := and(shr(68, d), 0x70)
                    if and(nd, shl(74, 1)) {
                        mstore8(0x25, p)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x20))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x30))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(73, 1)) {
                        mstore8(0x25, or(p, 0x40))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(or(p, 0x40), 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(72, 1)) {
                        mstore8(0x25, 0x60)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 408), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 400), 16) // chain 25
                mstore8(0x24, 100) // A7 byte 4: ci
                {
                    let p := and(shr(71, d), 0x70)
                    if and(nd, shl(77, 1)) {
                        mstore8(0x25, p)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x20))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x30))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(76, 1)) {
                        mstore8(0x25, or(p, 0x40))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(or(p, 0x40), 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(75, 1)) {
                        mstore8(0x25, 0x60)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 424), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 416), 16) // chain 26
                mstore8(0x24, 104) // A7 byte 4: ci
                {
                    let p := and(shr(74, d), 0x70)
                    if and(nd, shl(80, 1)) {
                        mstore8(0x25, p)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x20))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x30))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(79, 1)) {
                        mstore8(0x25, or(p, 0x40))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(or(p, 0x40), 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(78, 1)) {
                        mstore8(0x25, 0x60)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 440), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 432), 16) // chain 27
                mstore8(0x24, 108) // A7 byte 4: ci
                {
                    let p := and(shr(77, d), 0x70)
                    if and(nd, shl(83, 1)) {
                        mstore8(0x25, p)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x20))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x30))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(82, 1)) {
                        mstore8(0x25, or(p, 0x40))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(or(p, 0x40), 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(81, 1)) {
                        mstore8(0x25, 0x60)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 456), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 448), 16) // chain 28
                mstore8(0x24, 112) // A7 byte 4: ci
                {
                    let p := and(shr(80, d), 0x70)
                    if and(nd, shl(86, 1)) {
                        mstore8(0x25, p)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x20))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x30))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(85, 1)) {
                        mstore8(0x25, or(p, 0x40))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(or(p, 0x40), 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(84, 1)) {
                        mstore8(0x25, 0x60)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 472), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 464), 16) // chain 29
                mstore8(0x24, 116) // A7 byte 4: ci
                {
                    let p := and(shr(83, d), 0x70)
                    if and(nd, shl(89, 1)) {
                        mstore8(0x25, p)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x20))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x30))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(88, 1)) {
                        mstore8(0x25, or(p, 0x40))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(or(p, 0x40), 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(87, 1)) {
                        mstore8(0x25, 0x60)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 488), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 480), 16) // chain 30
                mstore8(0x24, 120) // A7 byte 4: ci
                {
                    let p := and(shr(86, d), 0x70)
                    if and(nd, shl(92, 1)) {
                        mstore8(0x25, p)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x20))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x30))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(91, 1)) {
                        mstore8(0x25, or(p, 0x40))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(or(p, 0x40), 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(90, 1)) {
                        mstore8(0x25, 0x60)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 504), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 496), 16) // chain 31
                mstore8(0x24, 124) // A7 byte 4: ci
                {
                    let p := and(shr(89, d), 0x70)
                    if and(nd, shl(95, 1)) {
                        mstore8(0x25, p)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x20))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x30))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(94, 1)) {
                        mstore8(0x25, or(p, 0x40))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(or(p, 0x40), 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(93, 1)) {
                        mstore8(0x25, 0x60)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 520), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 512), 16) // chain 32
                mstore8(0x24, 128) // A7 byte 4: ci
                {
                    let p := and(shr(92, d), 0x70)
                    if and(nd, shl(98, 1)) {
                        mstore8(0x25, p)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x20))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x30))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(97, 1)) {
                        mstore8(0x25, or(p, 0x40))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(or(p, 0x40), 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(96, 1)) {
                        mstore8(0x25, 0x60)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 536), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 528), 16) // chain 33
                mstore8(0x24, 132) // A7 byte 4: ci
                {
                    let p := and(shr(95, d), 0x70)
                    if and(nd, shl(101, 1)) {
                        mstore8(0x25, p)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x20))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x30))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(100, 1)) {
                        mstore8(0x25, or(p, 0x40))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(or(p, 0x40), 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(99, 1)) {
                        mstore8(0x25, 0x60)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 552), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 544), 16) // chain 34
                mstore8(0x24, 136) // A7 byte 4: ci
                {
                    let p := and(shr(98, d), 0x70)
                    if and(nd, shl(104, 1)) {
                        mstore8(0x25, p)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x20))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x30))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(103, 1)) {
                        mstore8(0x25, or(p, 0x40))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(or(p, 0x40), 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(102, 1)) {
                        mstore8(0x25, 0x60)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 568), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 560), 16) // chain 35
                mstore8(0x24, 140) // A7 byte 4: ci
                {
                    let p := and(shr(101, d), 0x70)
                    if and(nd, shl(107, 1)) {
                        mstore8(0x25, p)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x20))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x30))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(106, 1)) {
                        mstore8(0x25, or(p, 0x40))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(or(p, 0x40), 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(105, 1)) {
                        mstore8(0x25, 0x60)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 584), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 576), 16) // chain 36
                mstore8(0x24, 144) // A7 byte 4: ci
                {
                    let p := and(shr(104, d), 0x70)
                    if and(nd, shl(110, 1)) {
                        mstore8(0x25, p)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x20))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x30))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(109, 1)) {
                        mstore8(0x25, or(p, 0x40))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(or(p, 0x40), 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(108, 1)) {
                        mstore8(0x25, 0x60)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 600), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 592), 16) // chain 37
                mstore8(0x24, 148) // A7 byte 4: ci
                {
                    let p := and(shr(107, d), 0x70)
                    if and(nd, shl(113, 1)) {
                        mstore8(0x25, p)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x20))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x30))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(112, 1)) {
                        mstore8(0x25, or(p, 0x40))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(or(p, 0x40), 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(111, 1)) {
                        mstore8(0x25, 0x60)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 616), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 608), 16) // chain 38
                mstore8(0x24, 152) // A7 byte 4: ci
                {
                    let p := and(shr(110, d), 0x70)
                    if and(nd, shl(116, 1)) {
                        mstore8(0x25, p)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x20))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x30))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(115, 1)) {
                        mstore8(0x25, or(p, 0x40))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(or(p, 0x40), 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(114, 1)) {
                        mstore8(0x25, 0x60)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 632), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 624), 16) // chain 39
                mstore8(0x24, 156) // A7 byte 4: ci
                {
                    let p := and(shr(113, d), 0x70)
                    if and(nd, shl(119, 1)) {
                        mstore8(0x25, p)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x20))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x30))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(118, 1)) {
                        mstore8(0x25, or(p, 0x40))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(or(p, 0x40), 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(117, 1)) {
                        mstore8(0x25, 0x60)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 648), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 640), 16) // chain 40
                mstore8(0x24, 160) // A7 byte 4: ci
                {
                    let p := and(shr(116, d), 0x70)
                    if and(nd, shl(122, 1)) {
                        mstore8(0x25, p)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x20))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x30))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(121, 1)) {
                        mstore8(0x25, or(p, 0x40))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(or(p, 0x40), 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(120, 1)) {
                        mstore8(0x25, 0x60)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 664), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 656), 16) // chain 41
                mstore8(0x24, 164) // A7 byte 4: ci
                {
                    let p := and(shr(119, d), 0x70)
                    if and(nd, shl(125, 1)) {
                        mstore8(0x25, p)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x20))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x30))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(124, 1)) {
                        mstore8(0x25, or(p, 0x40))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(or(p, 0x40), 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(123, 1)) {
                        mstore8(0x25, 0x60)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 680), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 672), 16) // chain 42
                mstore8(0x24, 168) // A7 byte 4: ci
                {
                    let p := and(shr(122, d), 0x70)
                    if and(nd, shl(128, 1)) {
                        mstore8(0x25, p)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x20))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(p, 0x30))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(127, 1)) {
                        mstore8(0x25, or(p, 0x40))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore8(0x25, add(or(p, 0x40), 0x10))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    if and(nd, shl(126, 1)) {
                        mstore8(0x25, 0x60)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 696), mload(0x10))
                // END generated chains
                // T_43: the WOTS pk lands in its half of the first Merkle preimage; the walk is
                // the FORS one (generated); the root (index 0 at height 9) lands at 0x10, the next
                // layer's m16.
                let treeBase := or(or(shl(52, 2), shl(51, layer)), shl(33, idxTree))
                // BEGIN generated Merkle walk (research/c10-gas/gen_v2_walks.py; do not edit by hand)
                let t := idxLeaf
                let cpha := or(and(mul(t, 0x1000080004000200010000800040002000100008000400000000000000000), 0x7fe03fe01fe00fe007e003e001e000e00060002000000000000000000000000), 0x100020003000400050006000700080009000a000b00000000000000000000000) // C10-LANES
                let sbit := and(mul(t, 0x10000800040002000100008000400020001000080004000000000000000000), 0x10001000100010001000100010001000100010001000000000000000000000) // C10-LANES
                let slots := sub(add(sbit, 0x2010201020102010201020102010201020102010201000000000000000000000), shl(8, sbit)) // C10-LANES
                mstore(0x30, shl(200, treeBase)) // A7 bytes 0..4 for every level (the chains overwrote 0x30)
                pop(staticcall(gas(), 0x02, TB, 712, byte(1, slots), 16)) // T_43: the WOTS pk, at its slot
                let merklePtr := add(sigBase, add(countOff, 4))
                calldatacopy(byte(0, slots), add(merklePtr, 0), 16)
                mstore(0x35, shl(0, cpha))
                pop(staticcall(gas(), 0x02, 0x00, 55, byte(3, slots), 16))
                calldatacopy(byte(2, slots), add(merklePtr, 16), 16)
                mstore(0x35, shl(16, cpha))
                pop(staticcall(gas(), 0x02, 0x00, 55, byte(5, slots), 16))
                calldatacopy(byte(4, slots), add(merklePtr, 32), 16)
                mstore(0x35, shl(32, cpha))
                pop(staticcall(gas(), 0x02, 0x00, 55, byte(7, slots), 16))
                calldatacopy(byte(6, slots), add(merklePtr, 48), 16)
                mstore(0x35, shl(48, cpha))
                pop(staticcall(gas(), 0x02, 0x00, 55, byte(9, slots), 16))
                calldatacopy(byte(8, slots), add(merklePtr, 64), 16)
                mstore(0x35, shl(64, cpha))
                pop(staticcall(gas(), 0x02, 0x00, 55, byte(11, slots), 16))
                calldatacopy(byte(10, slots), add(merklePtr, 80), 16)
                mstore(0x35, shl(80, cpha))
                pop(staticcall(gas(), 0x02, 0x00, 55, byte(13, slots), 16))
                calldatacopy(byte(12, slots), add(merklePtr, 96), 16)
                mstore(0x35, shl(96, cpha))
                pop(staticcall(gas(), 0x02, 0x00, 55, byte(15, slots), 16))
                calldatacopy(byte(14, slots), add(merklePtr, 112), 16)
                mstore(0x35, shl(112, cpha))
                pop(staticcall(gas(), 0x02, 0x00, 55, byte(17, slots), 16))
                calldatacopy(byte(16, slots), add(merklePtr, 128), 16)
                mstore(0x35, shl(128, cpha))
                pop(staticcall(gas(), 0x02, 0x00, 55, 0x10, 16))
                // END generated Merkle walk
                sigOff := add(countOff, 148) // 4 + 9*16
            }
            valid := eq(and(mload(0x10), N_MASK), pkRoot)
            mstore(0x00, valid)
            return(0x00, 0x20)
        }
    }
}
