// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @notice RESEARCH (#1155) — C10 v2 verifier, research/c10-autoresearch/c10v2-spec.md DRAFT 0.3.
/// Same scheme and 4,008-byte signature as `SPHINCsC10Asm` (v1); every hash preimage is the
/// one-block v2 layout: 16-byte seed and values, the 7-byte compact address A7. NOT deployed.
///
/// Memory: 0x00.. scratch for one-block preimages (S at 0x00..0x10, never overwritten);
/// 0x800.. the T_k buffer `S || A7 || 0x00 || v_0 ..`; 0x780 the precompile output.
/// Packed 16-byte stores overlap (each mstore writes 32 bytes), so every preimage is written in
/// ascending address order with A7 last (`shl(200, a7)` puts its 7 bytes at the store address).
contract SPHINCsC10v2Asm {
    function verify(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes calldata sig)
        external
        view
        returns (bool valid)
    {
        assembly {
            let N_MASK := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000
            let OUT := 0x780
            let TB := 0x800
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
            mstore(0x40, and(calldataload(sigBase), N_MASK))
            mstore(0x50, shl(200, shl(52, 8)))
            pop(staticcall(gas(), 0x02, 0x00, 87, OUT, 32))
            let digest := mload(OUT)
            let htIdx := and(shr(143, digest), 0x3FFFF)
            if and(shr(132, digest), 0x7FF) { revert(0, 0) } // FORS+C: last index must be 0

            // FORS roots straight into the T_13 buffer: S || A7(4, tree=ht) || 0x00 || r_0..r_12.
            mstore(TB, pkSeed)
            mstore(add(TB, 0x10), shl(200, or(shl(52, 4), shl(33, htIdx))))
            for { let i := 0 } lt(i, 12) { i := add(i, 1) } {
                let treeIdx := and(shr(mul(i, 11), digest), 0x7FF)
                let base := or(or(shl(52, 3), shl(33, htIdx)), shl(24, i))
                // leaf F: S || secret || A7(3, ht, kp=i, ha=leaf)
                mstore(0x10, and(calldataload(add(sigBase, add(16, shl(4, i)))), N_MASK))
                mstore(0x20, shl(200, or(base, shl(1, treeIdx))))
                // In-place auth walk: every node is written (16 bytes) straight into its half of
                // the next H preimage S || L16 || R16 || A7, left at 0x10 if its index is even,
                // else right at 0x20; the 16-byte sibling is copied into the other half.
                // Unrolled: the node at height h-1 sits in the half given by bit h-1 of its index
                // (x = 16 * treeIdx, so and(shr(k, x), 0x10) = 16 * bit k); its sibling goes in the
                // other half; A7 = aw | cp<<212 | ha<<201 with cp = h and ha = treeIdx >> h; the
                // parent lands in the half given by bit h. Height 11 (the root) goes to T_13 slot i.
                let x := shl(4, treeIdx)
                let aw := shl(200, base)
                pop(staticcall(gas(), 0x02, 0x00, 39, add(0x10, and(x, 0x10)), 16))
                let authPtr := add(sigBase, add(224, mul(i, 176)))
                calldatacopy(sub(0x20, and(shr(0, x), 0x10)), add(authPtr, 0), 16)
                mstore(0x30, or(or(aw, shl(212, 1)), shl(201, shr(1, treeIdx))))
                pop(staticcall(gas(), 0x02, 0x00, 55, add(0x10, and(shr(1, x), 0x10)), 16))
                calldatacopy(sub(0x20, and(shr(1, x), 0x10)), add(authPtr, 16), 16)
                mstore(0x30, or(or(aw, shl(212, 2)), shl(201, shr(2, treeIdx))))
                pop(staticcall(gas(), 0x02, 0x00, 55, add(0x10, and(shr(2, x), 0x10)), 16))
                calldatacopy(sub(0x20, and(shr(2, x), 0x10)), add(authPtr, 32), 16)
                mstore(0x30, or(or(aw, shl(212, 3)), shl(201, shr(3, treeIdx))))
                pop(staticcall(gas(), 0x02, 0x00, 55, add(0x10, and(shr(3, x), 0x10)), 16))
                calldatacopy(sub(0x20, and(shr(3, x), 0x10)), add(authPtr, 48), 16)
                mstore(0x30, or(or(aw, shl(212, 4)), shl(201, shr(4, treeIdx))))
                pop(staticcall(gas(), 0x02, 0x00, 55, add(0x10, and(shr(4, x), 0x10)), 16))
                calldatacopy(sub(0x20, and(shr(4, x), 0x10)), add(authPtr, 64), 16)
                mstore(0x30, or(or(aw, shl(212, 5)), shl(201, shr(5, treeIdx))))
                pop(staticcall(gas(), 0x02, 0x00, 55, add(0x10, and(shr(5, x), 0x10)), 16))
                calldatacopy(sub(0x20, and(shr(5, x), 0x10)), add(authPtr, 80), 16)
                mstore(0x30, or(or(aw, shl(212, 6)), shl(201, shr(6, treeIdx))))
                pop(staticcall(gas(), 0x02, 0x00, 55, add(0x10, and(shr(6, x), 0x10)), 16))
                calldatacopy(sub(0x20, and(shr(6, x), 0x10)), add(authPtr, 96), 16)
                mstore(0x30, or(or(aw, shl(212, 7)), shl(201, shr(7, treeIdx))))
                pop(staticcall(gas(), 0x02, 0x00, 55, add(0x10, and(shr(7, x), 0x10)), 16))
                calldatacopy(sub(0x20, and(shr(7, x), 0x10)), add(authPtr, 112), 16)
                mstore(0x30, or(or(aw, shl(212, 8)), shl(201, shr(8, treeIdx))))
                pop(staticcall(gas(), 0x02, 0x00, 55, add(0x10, and(shr(8, x), 0x10)), 16))
                calldatacopy(sub(0x20, and(shr(8, x), 0x10)), add(authPtr, 128), 16)
                mstore(0x30, or(or(aw, shl(212, 9)), shl(201, shr(9, treeIdx))))
                pop(staticcall(gas(), 0x02, 0x00, 55, add(0x10, and(shr(9, x), 0x10)), 16))
                calldatacopy(sub(0x20, and(shr(9, x), 0x10)), add(authPtr, 144), 16)
                mstore(0x30, or(or(aw, shl(212, 10)), shl(201, shr(10, treeIdx))))
                pop(staticcall(gas(), 0x02, 0x00, 55, add(0x10, and(shr(10, x), 0x10)), 16))
                calldatacopy(sub(0x20, and(shr(10, x), 0x10)), add(authPtr, 160), 16)
                mstore(0x30, or(aw, shl(212, 11)))
                pop(staticcall(gas(), 0x02, 0x00, 55, add(TB, add(24, shl(4, i))), 16))
            }
            {
                // the last slot: F(S, A7(FORS_LAST=9, tree=ht), slot)
                mstore(0x10, and(calldataload(add(sigBase, 208)), N_MASK))
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
                if iszero(eq(digitSum, 205)) { revert(0, 0) } // WOTS+C target sum

                // chains into the T_43 buffer: S || A7(1, layer, tree, kp) || 0x00 || v_0..v_42
                mstore(TB, pkSeed)
                mstore(add(TB, 0x10), shl(200, or(shl(52, 1), kpBase)))
                let wotsPtr := add(sigBase, sigOff)
                for { let i := 0 } lt(i, 43) { i := add(i, 1) } {
                    let digit := and(shr(mul(i, 3), d), 0x7)
                    // Chain i from position `digit` to 7 in place: the value stays at 0x10 of the F
                    // preimage S || v16 || A7 and each step's output (outsize 16) overwrites it. The
                    // A7 word for position p is chainA + p<<212 (cp = bits 15..12 of A7; p < 7, no
                    // carry), so one add per step.
                    calldatacopy(0x10, add(wotsPtr, shl(4, i)), 16)
                    let chainA := shl(200, or(kpBase, shl(18, i))) // type 0 (WOTS_HASH), cp = 0
                    let aEnd := add(chainA, shl(212, 7))
                    for { let a := add(chainA, shl(212, digit)) } lt(a, aEnd) { a := add(a, shl(212, 1)) } {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                    // 32-byte copy of the 16-byte end value: its trailing 16 bytes are overwritten by
                    // slot i+1, and for i = 42 they fall past the 712 bytes T_43 hashes.
                    mstore(add(TB, add(24, shl(4, i))), mload(0x10))
                }
                // T_43: the WOTS pk lands in its half of the first Merkle preimage (in-place walk
                // as in FORS); the root (index 0 at height 9) lands at 0x10, the next layer's m16.
                pop(staticcall(gas(), 0x02, TB, 712, add(0x10, shl(4, and(idxLeaf, 1))), 16))

                // Unrolled as in FORS (x = 16 * idxLeaf; ha = idxLeaf >> h); the root (height 9,
                // index 0) lands at 0x10.
                let treeBase := or(or(shl(52, 2), shl(51, layer)), shl(33, idxTree))
                let aw := shl(200, treeBase)
                let x := shl(4, idxLeaf)
                let merklePtr := add(sigBase, add(countOff, 4))
                calldatacopy(sub(0x20, and(shr(0, x), 0x10)), add(merklePtr, 0), 16)
                mstore(0x30, or(or(aw, shl(212, 1)), shl(201, shr(1, idxLeaf))))
                pop(staticcall(gas(), 0x02, 0x00, 55, add(0x10, and(shr(1, x), 0x10)), 16))
                calldatacopy(sub(0x20, and(shr(1, x), 0x10)), add(merklePtr, 16), 16)
                mstore(0x30, or(or(aw, shl(212, 2)), shl(201, shr(2, idxLeaf))))
                pop(staticcall(gas(), 0x02, 0x00, 55, add(0x10, and(shr(2, x), 0x10)), 16))
                calldatacopy(sub(0x20, and(shr(2, x), 0x10)), add(merklePtr, 32), 16)
                mstore(0x30, or(or(aw, shl(212, 3)), shl(201, shr(3, idxLeaf))))
                pop(staticcall(gas(), 0x02, 0x00, 55, add(0x10, and(shr(3, x), 0x10)), 16))
                calldatacopy(sub(0x20, and(shr(3, x), 0x10)), add(merklePtr, 48), 16)
                mstore(0x30, or(or(aw, shl(212, 4)), shl(201, shr(4, idxLeaf))))
                pop(staticcall(gas(), 0x02, 0x00, 55, add(0x10, and(shr(4, x), 0x10)), 16))
                calldatacopy(sub(0x20, and(shr(4, x), 0x10)), add(merklePtr, 64), 16)
                mstore(0x30, or(or(aw, shl(212, 5)), shl(201, shr(5, idxLeaf))))
                pop(staticcall(gas(), 0x02, 0x00, 55, add(0x10, and(shr(5, x), 0x10)), 16))
                calldatacopy(sub(0x20, and(shr(5, x), 0x10)), add(merklePtr, 80), 16)
                mstore(0x30, or(or(aw, shl(212, 6)), shl(201, shr(6, idxLeaf))))
                pop(staticcall(gas(), 0x02, 0x00, 55, add(0x10, and(shr(6, x), 0x10)), 16))
                calldatacopy(sub(0x20, and(shr(6, x), 0x10)), add(merklePtr, 96), 16)
                mstore(0x30, or(or(aw, shl(212, 7)), shl(201, shr(7, idxLeaf))))
                pop(staticcall(gas(), 0x02, 0x00, 55, add(0x10, and(shr(7, x), 0x10)), 16))
                calldatacopy(sub(0x20, and(shr(7, x), 0x10)), add(merklePtr, 112), 16)
                mstore(0x30, or(or(aw, shl(212, 8)), shl(201, shr(8, idxLeaf))))
                pop(staticcall(gas(), 0x02, 0x00, 55, add(0x10, and(shr(8, x), 0x10)), 16))
                calldatacopy(sub(0x20, and(shr(8, x), 0x10)), add(merklePtr, 128), 16)
                mstore(0x30, or(aw, shl(212, 9)))
                pop(staticcall(gas(), 0x02, 0x00, 55, 0x10, 16))
                sigOff := add(countOff, 148) // 4 + 9*16
            }
            valid := eq(and(mload(0x10), N_MASK), pkRoot)
            mstore(0x00, valid)
            return(0x00, 0x20)
        }
    }
}
