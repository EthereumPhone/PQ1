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
            for { let i := 0 } lt(i, 12) { i := add(i, 1) } {
                let treeIdx := and(shr(mul(i, 11), digest), 0x7FF)
                let base := or(or(shl(52, 3), shl(33, htIdx)), shl(24, i))
                // leaf F: S || secret || A7(3, ht, kp=i, ha=leaf)
                mstore(0x10, calldataload(add(sigBase, add(16, shl(4, i))))) // low half: next store
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
                // overwrites it. The A7 word of chain i at position p is chainA | i<<218 | p<<212
                // (type 0, WOTS_HASH; ci = A7 bits 23..18, cp = bits 15..12; i < 43 and p < 7, so the
                // `add`s never carry). The end value is copied to T_43 slot i with a 32-byte store:
                // its trailing 16 bytes are overwritten by slot i+1, and for i = 42 they fall past
                // the 712 bytes T_43 hashes. Unrolled over the 43 chains (generated).
                let chainA := shl(200, kpBase)
                let nd := not(d) // chain i takes 7 - digit_i = bits 3i..3i+2 of nd steps: blocks of 4, 2, 1
                // BEGIN generated chains (research/c10-gas/gen_v2_chains.py; do not edit by hand)
                calldatacopy(0x10, add(wotsPtr, 0), 16) // chain 0
                {
                    let a := add(chainA, or(shl(218, 0), shl(212, and(shr(0, d), 7))))
                    if and(nd, shl(2, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 4))
                    }
                    if and(nd, shl(1, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 2))
                    }
                    if and(nd, shl(0, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 24), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 16), 16) // chain 1
                {
                    let a := add(chainA, or(shl(218, 1), shl(212, and(shr(3, d), 7))))
                    if and(nd, shl(5, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 4))
                    }
                    if and(nd, shl(4, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 2))
                    }
                    if and(nd, shl(3, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 40), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 32), 16) // chain 2
                {
                    let a := add(chainA, or(shl(218, 2), shl(212, and(shr(6, d), 7))))
                    if and(nd, shl(8, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 4))
                    }
                    if and(nd, shl(7, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 2))
                    }
                    if and(nd, shl(6, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 56), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 48), 16) // chain 3
                {
                    let a := add(chainA, or(shl(218, 3), shl(212, and(shr(9, d), 7))))
                    if and(nd, shl(11, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 4))
                    }
                    if and(nd, shl(10, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 2))
                    }
                    if and(nd, shl(9, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 72), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 64), 16) // chain 4
                {
                    let a := add(chainA, or(shl(218, 4), shl(212, and(shr(12, d), 7))))
                    if and(nd, shl(14, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 4))
                    }
                    if and(nd, shl(13, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 2))
                    }
                    if and(nd, shl(12, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 88), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 80), 16) // chain 5
                {
                    let a := add(chainA, or(shl(218, 5), shl(212, and(shr(15, d), 7))))
                    if and(nd, shl(17, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 4))
                    }
                    if and(nd, shl(16, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 2))
                    }
                    if and(nd, shl(15, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 104), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 96), 16) // chain 6
                {
                    let a := add(chainA, or(shl(218, 6), shl(212, and(shr(18, d), 7))))
                    if and(nd, shl(20, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 4))
                    }
                    if and(nd, shl(19, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 2))
                    }
                    if and(nd, shl(18, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 120), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 112), 16) // chain 7
                {
                    let a := add(chainA, or(shl(218, 7), shl(212, and(shr(21, d), 7))))
                    if and(nd, shl(23, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 4))
                    }
                    if and(nd, shl(22, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 2))
                    }
                    if and(nd, shl(21, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 136), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 128), 16) // chain 8
                {
                    let a := add(chainA, or(shl(218, 8), shl(212, and(shr(24, d), 7))))
                    if and(nd, shl(26, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 4))
                    }
                    if and(nd, shl(25, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 2))
                    }
                    if and(nd, shl(24, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 152), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 144), 16) // chain 9
                {
                    let a := add(chainA, or(shl(218, 9), shl(212, and(shr(27, d), 7))))
                    if and(nd, shl(29, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 4))
                    }
                    if and(nd, shl(28, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 2))
                    }
                    if and(nd, shl(27, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 168), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 160), 16) // chain 10
                {
                    let a := add(chainA, or(shl(218, 10), shl(212, and(shr(30, d), 7))))
                    if and(nd, shl(32, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 4))
                    }
                    if and(nd, shl(31, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 2))
                    }
                    if and(nd, shl(30, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 184), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 176), 16) // chain 11
                {
                    let a := add(chainA, or(shl(218, 11), shl(212, and(shr(33, d), 7))))
                    if and(nd, shl(35, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 4))
                    }
                    if and(nd, shl(34, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 2))
                    }
                    if and(nd, shl(33, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 200), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 192), 16) // chain 12
                {
                    let a := add(chainA, or(shl(218, 12), shl(212, and(shr(36, d), 7))))
                    if and(nd, shl(38, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 4))
                    }
                    if and(nd, shl(37, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 2))
                    }
                    if and(nd, shl(36, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 216), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 208), 16) // chain 13
                {
                    let a := add(chainA, or(shl(218, 13), shl(212, and(shr(39, d), 7))))
                    if and(nd, shl(41, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 4))
                    }
                    if and(nd, shl(40, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 2))
                    }
                    if and(nd, shl(39, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 232), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 224), 16) // chain 14
                {
                    let a := add(chainA, or(shl(218, 14), shl(212, and(shr(42, d), 7))))
                    if and(nd, shl(44, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 4))
                    }
                    if and(nd, shl(43, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 2))
                    }
                    if and(nd, shl(42, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 248), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 240), 16) // chain 15
                {
                    let a := add(chainA, or(shl(218, 15), shl(212, and(shr(45, d), 7))))
                    if and(nd, shl(47, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 4))
                    }
                    if and(nd, shl(46, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 2))
                    }
                    if and(nd, shl(45, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 264), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 256), 16) // chain 16
                {
                    let a := add(chainA, or(shl(218, 16), shl(212, and(shr(48, d), 7))))
                    if and(nd, shl(50, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 4))
                    }
                    if and(nd, shl(49, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 2))
                    }
                    if and(nd, shl(48, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 280), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 272), 16) // chain 17
                {
                    let a := add(chainA, or(shl(218, 17), shl(212, and(shr(51, d), 7))))
                    if and(nd, shl(53, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 4))
                    }
                    if and(nd, shl(52, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 2))
                    }
                    if and(nd, shl(51, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 296), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 288), 16) // chain 18
                {
                    let a := add(chainA, or(shl(218, 18), shl(212, and(shr(54, d), 7))))
                    if and(nd, shl(56, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 4))
                    }
                    if and(nd, shl(55, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 2))
                    }
                    if and(nd, shl(54, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 312), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 304), 16) // chain 19
                {
                    let a := add(chainA, or(shl(218, 19), shl(212, and(shr(57, d), 7))))
                    if and(nd, shl(59, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 4))
                    }
                    if and(nd, shl(58, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 2))
                    }
                    if and(nd, shl(57, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 328), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 320), 16) // chain 20
                {
                    let a := add(chainA, or(shl(218, 20), shl(212, and(shr(60, d), 7))))
                    if and(nd, shl(62, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 4))
                    }
                    if and(nd, shl(61, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 2))
                    }
                    if and(nd, shl(60, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 344), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 336), 16) // chain 21
                {
                    let a := add(chainA, or(shl(218, 21), shl(212, and(shr(63, d), 7))))
                    if and(nd, shl(65, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 4))
                    }
                    if and(nd, shl(64, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 2))
                    }
                    if and(nd, shl(63, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 360), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 352), 16) // chain 22
                {
                    let a := add(chainA, or(shl(218, 22), shl(212, and(shr(66, d), 7))))
                    if and(nd, shl(68, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 4))
                    }
                    if and(nd, shl(67, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 2))
                    }
                    if and(nd, shl(66, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 376), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 368), 16) // chain 23
                {
                    let a := add(chainA, or(shl(218, 23), shl(212, and(shr(69, d), 7))))
                    if and(nd, shl(71, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 4))
                    }
                    if and(nd, shl(70, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 2))
                    }
                    if and(nd, shl(69, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 392), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 384), 16) // chain 24
                {
                    let a := add(chainA, or(shl(218, 24), shl(212, and(shr(72, d), 7))))
                    if and(nd, shl(74, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 4))
                    }
                    if and(nd, shl(73, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 2))
                    }
                    if and(nd, shl(72, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 408), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 400), 16) // chain 25
                {
                    let a := add(chainA, or(shl(218, 25), shl(212, and(shr(75, d), 7))))
                    if and(nd, shl(77, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 4))
                    }
                    if and(nd, shl(76, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 2))
                    }
                    if and(nd, shl(75, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 424), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 416), 16) // chain 26
                {
                    let a := add(chainA, or(shl(218, 26), shl(212, and(shr(78, d), 7))))
                    if and(nd, shl(80, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 4))
                    }
                    if and(nd, shl(79, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 2))
                    }
                    if and(nd, shl(78, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 440), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 432), 16) // chain 27
                {
                    let a := add(chainA, or(shl(218, 27), shl(212, and(shr(81, d), 7))))
                    if and(nd, shl(83, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 4))
                    }
                    if and(nd, shl(82, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 2))
                    }
                    if and(nd, shl(81, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 456), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 448), 16) // chain 28
                {
                    let a := add(chainA, or(shl(218, 28), shl(212, and(shr(84, d), 7))))
                    if and(nd, shl(86, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 4))
                    }
                    if and(nd, shl(85, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 2))
                    }
                    if and(nd, shl(84, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 472), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 464), 16) // chain 29
                {
                    let a := add(chainA, or(shl(218, 29), shl(212, and(shr(87, d), 7))))
                    if and(nd, shl(89, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 4))
                    }
                    if and(nd, shl(88, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 2))
                    }
                    if and(nd, shl(87, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 488), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 480), 16) // chain 30
                {
                    let a := add(chainA, or(shl(218, 30), shl(212, and(shr(90, d), 7))))
                    if and(nd, shl(92, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 4))
                    }
                    if and(nd, shl(91, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 2))
                    }
                    if and(nd, shl(90, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 504), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 496), 16) // chain 31
                {
                    let a := add(chainA, or(shl(218, 31), shl(212, and(shr(93, d), 7))))
                    if and(nd, shl(95, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 4))
                    }
                    if and(nd, shl(94, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 2))
                    }
                    if and(nd, shl(93, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 520), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 512), 16) // chain 32
                {
                    let a := add(chainA, or(shl(218, 32), shl(212, and(shr(96, d), 7))))
                    if and(nd, shl(98, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 4))
                    }
                    if and(nd, shl(97, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 2))
                    }
                    if and(nd, shl(96, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 536), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 528), 16) // chain 33
                {
                    let a := add(chainA, or(shl(218, 33), shl(212, and(shr(99, d), 7))))
                    if and(nd, shl(101, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 4))
                    }
                    if and(nd, shl(100, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 2))
                    }
                    if and(nd, shl(99, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 552), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 544), 16) // chain 34
                {
                    let a := add(chainA, or(shl(218, 34), shl(212, and(shr(102, d), 7))))
                    if and(nd, shl(104, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 4))
                    }
                    if and(nd, shl(103, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 2))
                    }
                    if and(nd, shl(102, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 568), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 560), 16) // chain 35
                {
                    let a := add(chainA, or(shl(218, 35), shl(212, and(shr(105, d), 7))))
                    if and(nd, shl(107, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 4))
                    }
                    if and(nd, shl(106, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 2))
                    }
                    if and(nd, shl(105, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 584), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 576), 16) // chain 36
                {
                    let a := add(chainA, or(shl(218, 36), shl(212, and(shr(108, d), 7))))
                    if and(nd, shl(110, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 4))
                    }
                    if and(nd, shl(109, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 2))
                    }
                    if and(nd, shl(108, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 600), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 592), 16) // chain 37
                {
                    let a := add(chainA, or(shl(218, 37), shl(212, and(shr(111, d), 7))))
                    if and(nd, shl(113, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 4))
                    }
                    if and(nd, shl(112, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 2))
                    }
                    if and(nd, shl(111, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 616), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 608), 16) // chain 38
                {
                    let a := add(chainA, or(shl(218, 38), shl(212, and(shr(114, d), 7))))
                    if and(nd, shl(116, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 4))
                    }
                    if and(nd, shl(115, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 2))
                    }
                    if and(nd, shl(114, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 632), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 624), 16) // chain 39
                {
                    let a := add(chainA, or(shl(218, 39), shl(212, and(shr(117, d), 7))))
                    if and(nd, shl(119, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 4))
                    }
                    if and(nd, shl(118, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 2))
                    }
                    if and(nd, shl(117, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 648), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 640), 16) // chain 40
                {
                    let a := add(chainA, or(shl(218, 40), shl(212, and(shr(120, d), 7))))
                    if and(nd, shl(122, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 4))
                    }
                    if and(nd, shl(121, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 2))
                    }
                    if and(nd, shl(120, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 664), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 656), 16) // chain 41
                {
                    let a := add(chainA, or(shl(218, 41), shl(212, and(shr(123, d), 7))))
                    if and(nd, shl(125, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 4))
                    }
                    if and(nd, shl(124, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 2))
                    }
                    if and(nd, shl(123, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 680), mload(0x10))
                calldatacopy(0x10, add(wotsPtr, 672), 16) // chain 42
                {
                    let a := add(chainA, or(shl(218, 42), shl(212, and(shr(126, d), 7))))
                    if and(nd, shl(128, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 4))
                    }
                    if and(nd, shl(127, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        mstore(0x20, add(a, shl(212, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                        a := add(a, shl(212, 2))
                    }
                    if and(nd, shl(126, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))
                    }
                }
                mstore(add(TB, 696), mload(0x10))
                // END generated chains
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
