// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title SPHINCsC10Asm — Stateless SPHINCS+ C10 verifier (Yul-optimised, SHA-256)
/// @notice C10: W+C_F+C h=18 d=2 a=11 k=13 w=8 l=43 target_sum=205 sig=4008
/// @dev C10 is used both for the **bootstrap** (master) identity of the
///      PQSigner OS wallet and for every per-slot signing key. The hypertree
///      holds 2^18 signing positions, and `PQSmartWallet.bootstrapUses` /
///      `slotUses` cap actual on-chain Type 1 / Type 2 usage at 65,536 per
///      chain (per slot).
///
///      Domain-separated H_msg (160 bytes). Branchless Merkle swap, hoisted
///      chain address. SHA-256 variant: every tweakable hash is computed by
///      the precompile at address 0x02 so firmware running on STM32U585's
///      HASH peripheral produces byte-identical outputs.
///
///      Memory layout (each hash call):
///        [0x00..len]   input buffer (seed, adrs, data, ...)
///        [0x600..0x620] scratch for precompile output, then AND-masked
///                      to N=16 bytes when the caller wants a truncated value.
contract SPHINCsC10Asm {

    function verify(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes calldata sig)
        external view returns (bool valid)
    {
        assembly ("memory-safe") {
            let N_MASK := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000
            // Scratch slot for SHA-256 precompile output. Sits above every
            // other memory region the verifier touches (WOTS endpoints at
            // 0x80 + 42*32 = 0x5C0 is the highest legitimate write).
            let OUT := 0x600

            if iszero(eq(sig.length, 4008)) {
                mstore(0x00, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                mstore(0x04, 0x20)
                mstore(0x24, 18)
                mstore(0x44, "Invalid sig length")
                revert(0x00, 0x64)
            }

            let seed := pkSeed
            let root := pkRoot
            mstore(0x00, seed)

            // H_msg (domain-separated, 160 bytes)
            let R := and(calldataload(sig.offset), N_MASK)
            mstore(0x20, root)
            mstore(0x40, R)
            mstore(0x60, message)
            mstore(0x80, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
            pop(staticcall(gas(), 0x02, 0x00, 0xA0, OUT, 32))
            let digest := mload(OUT)

            // htIdx = (digest >> 143) & (2^18-1)
            let htIdx := and(shr(143, digest), 0x3FFFF)

            // FORS+C (K=13, A=11)
            let dVal := digest
            // Forced-zero: last index (i=12) at bits 132..142
            if and(shr(132, dVal), 0x7FF) { revert(0, 0) }

            let sigBase := sig.offset
            // K-1=12 normal trees
            for { let i := 0 } lt(i, 12) { i := add(i, 1) } {
                let treeIdx := and(shr(mul(i, 11), dVal), 0x7FF) // 11-bit indices
                let secretVal := and(calldataload(add(sigBase, add(16, shl(4, i)))), N_MASK)
                let leafAdrs := or(shl(128, 3), or(shl(96, i), treeIdx))
                mstore(0x20, leafAdrs)
                mstore(0x40, secretVal)
                pop(staticcall(gas(), 0x02, 0x00, 0x60, OUT, 32))
                let node := and(mload(OUT), N_MASK)

                let treeAdrsBase := or(shl(128, 3), shl(96, i))
                let pathIdx := treeIdx
                // AUTH_START=224, auth per tree = 11*16 = 176
                let authPtr := add(sigBase, add(224, mul(i, 176)))

                // Walk A=11 auth path levels
                for { let h := 0 } lt(h, 11) { h := add(h, 1) } {
                    let sibling := and(calldataload(add(authPtr, shl(4, h))), N_MASK)
                    let parentIdx := shr(1, pathIdx)
                    mstore(0x20, or(treeAdrsBase, or(shl(32, add(h, 1)), parentIdx)))
                    // Branchless Merkle swap
                    let s := shl(5, and(pathIdx, 1))
                    mstore(xor(0x40, s), node)
                    mstore(xor(0x60, s), sibling)
                    pop(staticcall(gas(), 0x02, 0x00, 0x80, OUT, 32))
                    node := and(mload(OUT), N_MASK)
                    pathIdx := parentIdx
                }
                mstore(add(0x80, shl(5, i)), node)
            }

            // Last tree (forced-zero)
            {
                let lastSecret := and(calldataload(add(sigBase, add(16, shl(4, 12)))), N_MASK) // 16+12*16=208
                mstore(0x20, or(shl(128, 3), shl(96, 12)))
                mstore(0x40, lastSecret)
                // 0x80 + 12*0x20 = 0x80 + 0x180 = 0x200
                pop(staticcall(gas(), 0x02, 0x00, 0x60, OUT, 32))
                mstore(0x200, and(mload(OUT), N_MASK))
            }

            // Compress 13 roots: sha256(seed || rootsAdrs || 13 roots)
            // = 32 + 32 + 13*32 = 480 = 0x1E0
            mstore(0x20, shl(128, 4))
            for { let i := 0 } lt(i, 13) { i := add(i, 1) } {
                mstore(add(0x40, shl(5, i)), mload(add(0x80, shl(5, i))))
            }
            pop(staticcall(gas(), 0x02, 0x00, 0x1E0, OUT, 32))
            let forsPk := and(mload(OUT), N_MASK)

            // Hypertree (D=2, subtree_h=9, w=8, l=43, target_sum=205)
            let currentNode := forsPk
            let idxTree := htIdx
            let sigOff := 2336 // HT_START

            for { let layer := 0 } lt(layer, 2) { layer := add(layer, 1) } {
                let idxLeaf := and(idxTree, 0x1FF) // 2^9 - 1
                idxTree := shr(9, idxTree)

                let wotsAdrs := or(shl(224, layer), or(shl(160, idxTree), shl(96, idxLeaf)))
                // countOff = sigOff + l*N = sigOff + 688
                let countOff := add(sigOff, 688)
                let count := shr(224, calldataload(add(sigBase, countOff)))

                mstore(0x00, seed)
                mstore(0x20, wotsAdrs)
                mstore(0x40, currentNode)
                mstore(0x60, count)
                pop(staticcall(gas(), 0x02, 0x00, 0x80, OUT, 32))
                let d := mload(OUT)

                // Validate digit sum = 205 (43 base-8 digits, 3 bits each)
                let digitSum := 0
                for { let ii := 0 } lt(ii, 43) { ii := add(ii, 1) } {
                    digitSum := add(digitSum, and(shr(mul(ii, 3), d), 0x7))
                }
                if iszero(eq(digitSum, 205)) { revert(0, 0) }

                // 43 WOTS chains (w=8: max 7 steps per chain)
                let wotsPtr := add(sigBase, sigOff)
                for { let i := 0 } lt(i, 43) { i := add(i, 1) } {
                    let digit := and(shr(mul(i, 3), d), 0x7)
                    let steps := sub(7, digit)
                    let val := and(calldataload(add(wotsPtr, shl(4, i))), N_MASK)
                    let chainBase := and(
                        or(wotsAdrs, shl(64, i)),
                        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFF
                    )

                    for { let step := 0 } lt(step, steps) { step := add(step, 1) } {
                        mstore(0x20, or(chainBase, shl(32, add(digit, step))))
                        mstore(0x40, val)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, OUT, 32))
                        val := and(mload(OUT), N_MASK)
                    }
                    mstore(add(0x80, shl(5, i)), val)
                }

                // PK compression: sha256(seed || pkAdrs || 43 endpoints)
                // = 32 + 32 + 43*32 = 1440 = 0x5A0
                let pkAdrs := or(shl(224, layer), or(shl(160, idxTree), or(shl(128, 1), shl(96, idxLeaf))))
                mstore(0x20, pkAdrs)
                for { let i := 0 } lt(i, 43) { i := add(i, 1) } {
                    mstore(add(0x40, shl(5, i)), mload(add(0x80, shl(5, i))))
                }
                pop(staticcall(gas(), 0x02, 0x00, 0x5A0, OUT, 32))
                let wotsPk := and(mload(OUT), N_MASK)

                // Merkle auth path (9 levels)
                let authOff := add(countOff, 4)
                let treeAdrs := or(shl(224, layer), or(shl(160, idxTree), shl(128, 2)))
                let merkleNode := wotsPk
                let mIdx := idxLeaf
                let merklePtr := add(sigBase, authOff)

                for { let h := 0 } lt(h, 9) { h := add(h, 1) } {
                    let sibling := and(calldataload(add(merklePtr, shl(4, h))), N_MASK)
                    let parentIdx := shr(1, mIdx)
                    mstore(0x20, or(
                        and(treeAdrs, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000000000000000),
                        or(shl(32, add(h, 1)), parentIdx)
                    ))
                    let s := shl(5, and(mIdx, 1))
                    mstore(xor(0x40, s), merkleNode)
                    mstore(xor(0x60, s), sibling)
                    pop(staticcall(gas(), 0x02, 0x00, 0x80, OUT, 32))
                    merkleNode := and(mload(OUT), N_MASK)
                    mIdx := parentIdx
                }

                currentNode := merkleNode
                sigOff := add(authOff, 144) // 9*16
            }

            valid := eq(currentNode, root)
            mstore(0x00, valid)
            return(0x00, 0x20)
        }
    }
}
