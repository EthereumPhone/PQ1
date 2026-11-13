// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @notice RESEARCH (#1155) — C10 v2 verifier, VARIANT all3 = ts200 + prf2 + split810: DRAFT 0.3
/// (research/c10-autoresearch/c10v2-spec.md) with the WOTS+C target digit sum 200, hypertree
/// layer heights (8, 10) with the matching A7 layout (kp 10 bits at 32..23, ci at 22..17, FORS
/// addresses included), and prf2 (signer-side only, no verifier change). Identical to
/// `SPHINCsC10v2Split810Asm` except the target sum. Security-check candidate only; NOT deployed
/// and NOT a spec decision. KATs: test/c10v2_kat_vectors_all3.json
/// (c10v2_ref.py --variant ts200,prf2,split810).
///
/// Base (0.3): same scheme and 4,008-byte signature as `SPHINCsC10Asm` (v1); every hash preimage
/// is the one-block v2 layout: 16-byte seed and values, the 7-byte compact address A7.
///
/// Memory: 0x00.. scratch for one-block preimages (S at 0x00..0x10, never overwritten);
/// 0x800.. the T_k buffer `S || A7 || 0x00 || v_0 ..`; 0x780 the precompile output.
/// Packed 16-byte stores overlap (each mstore writes 32 bytes), so every preimage is written in
/// ascending address order with A7 last (`shl(200, a7)` puts its 7 bytes at the store address).
contract RefSPHINCsC10v2All3Asm {
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

            // A7 (variant split810) = type<<52 | layer<<51 | tree<<33 | kp<<23 | ci<<17 | cp<<12 | ha<<1:
            // kp widens to 10 bits (32..23), ci moves to 22..17; every other field as spec §1.

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
                let base := or(or(shl(52, 3), shl(33, htIdx)), shl(23, i))
                // leaf F: S || secret || A7(3, ht, kp=i, ha=leaf)
                mstore(0x10, and(calldataload(add(sigBase, add(16, shl(4, i)))), N_MASK))
                mstore(0x20, shl(200, or(base, shl(1, treeIdx))))
                pop(staticcall(gas(), 0x02, 0x00, 39, OUT, 32))
                let node := and(mload(OUT), N_MASK)
                let pathIdx := treeIdx
                let authPtr := add(sigBase, add(224, mul(i, 176)))
                for { let h := 0 } lt(h, 11) { h := add(h, 1) } {
                    let sibling := and(calldataload(add(authPtr, shl(4, h))), N_MASK)
                    let parentIdx := shr(1, pathIdx)
                    let x := mul(and(pathIdx, 1), xor(node, sibling))
                    mstore(0x10, xor(node, x)) // left
                    mstore(0x20, xor(sibling, x)) // right
                    mstore(0x30, shl(200, or(base, or(shl(12, add(h, 1)), shl(1, parentIdx)))))
                    pop(staticcall(gas(), 0x02, 0x00, 55, OUT, 32))
                    node := and(mload(OUT), N_MASK)
                    pathIdx := parentIdx
                }
                mstore(add(TB, add(24, shl(4, i))), node)
            }
            {
                // the last slot: F(S, A7(FORS_LAST=9, tree=ht), slot)
                mstore(0x10, and(calldataload(add(sigBase, 208)), N_MASK))
                mstore(0x20, shl(200, or(shl(52, 9), shl(33, htIdx))))
                pop(staticcall(gas(), 0x02, 0x00, 39, OUT, 32))
                mstore(add(TB, add(24, 192)), and(mload(OUT), N_MASK))
            }
            pop(staticcall(gas(), 0x02, TB, 232, OUT, 32))
            let currentNode := and(mload(OUT), N_MASK)

            let idxTree := htIdx
            let sigOff := 2336
            for { let layer := 0 } lt(layer, 2) { layer := add(layer, 1) } {
                let hl := add(8, shl(1, layer)) // subtree height: 8 at layer 0, 10 at layer 1
                let idxLeaf := and(idxTree, sub(shl(hl, 1), 1))
                idxTree := shr(hl, idxTree)
                let kpBase := or(or(shl(51, layer), shl(33, idxTree)), shl(23, idxLeaf))
                let countOff := add(sigOff, 688)
                let count := shr(224, calldataload(add(sigBase, countOff)))
                // WOTS_DIGEST: S || m16 || be32(count) || A7(7, layer, tree, kp), 43 bytes.
                mstore(0x10, currentNode)
                mstore(0x20, shl(224, count))
                mstore(0x24, shl(200, or(shl(52, 7), kpBase)))
                pop(staticcall(gas(), 0x02, 0x00, 43, OUT, 32))
                let d := mload(OUT)
                // digits as v1 (spec 0.3): the LOW 129 bits, digit i = (d >> 3i) & 7
                let digitSum := 0
                for { let ii := 0 } lt(ii, 43) { ii := add(ii, 1) } {
                    digitSum := add(digitSum, and(shr(mul(ii, 3), d), 0x7))
                }
                if iszero(eq(digitSum, 200)) { revert(0, 0) } // WOTS+C target sum (variant ts200: 200)

                // chains into the T_43 buffer: S || A7(1, layer, tree, kp) || 0x00 || v_0..v_42
                mstore(TB, pkSeed)
                mstore(add(TB, 0x10), shl(200, or(shl(52, 1), kpBase)))
                let wotsPtr := add(sigBase, sigOff)
                for { let i := 0 } lt(i, 43) { i := add(i, 1) } {
                    let digit := and(shr(mul(i, 3), d), 0x7)
                    let val := and(calldataload(add(wotsPtr, shl(4, i))), N_MASK)
                    let chainBase := or(kpBase, shl(17, i)) // type 0 (WOTS_HASH)
                    for { let p := digit } lt(p, 7) { p := add(p, 1) } {
                        mstore(0x10, val)
                        mstore(0x20, shl(200, or(chainBase, shl(12, p))))
                        pop(staticcall(gas(), 0x02, 0x00, 39, OUT, 32))
                        val := and(mload(OUT), N_MASK)
                    }
                    mstore(add(TB, add(24, shl(4, i))), val)
                }
                pop(staticcall(gas(), 0x02, TB, 712, OUT, 32))
                let merkleNode := and(mload(OUT), N_MASK)

                let treeBase := or(or(shl(52, 2), shl(51, layer)), shl(33, idxTree))
                let mIdx := idxLeaf
                let merklePtr := add(sigBase, add(countOff, 4))
                for { let h := 0 } lt(h, hl) { h := add(h, 1) } {
                    let sibling := and(calldataload(add(merklePtr, shl(4, h))), N_MASK)
                    let parentIdx := shr(1, mIdx)
                    let x := mul(and(mIdx, 1), xor(merkleNode, sibling))
                    mstore(0x10, xor(merkleNode, x))
                    mstore(0x20, xor(sibling, x))
                    mstore(0x30, shl(200, or(treeBase, or(shl(12, add(h, 1)), shl(1, parentIdx)))))
                    pop(staticcall(gas(), 0x02, 0x00, 55, OUT, 32))
                    merkleNode := and(mload(OUT), N_MASK)
                    mIdx := parentIdx
                }
                currentNode := merkleNode
                sigOff := add(countOff, add(4, shl(4, hl))) // 4 + hl*16: 132 (layer 0), 164 (layer 1)
            }
            valid := eq(currentNode, pkRoot)
            mstore(0x00, valid)
            return(0x00, 0x20)
        }
    }
}
