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
        // Audit M-2: this block writes the Solidity free-memory pointer
        // slot (0x40), the zero slot (0x60), and the region above the
        // FMP without updating the FMP. That violates the `memory-safe`
        // contract. It is currently *latent* — the block `return`s from
        // within Yul before any Solidity epilogue can observe the
        // corrupted FMP — but a future refactor that wraps `verify` in
        // additional Solidity logic, or inlines it into a caller that
        // allocates memory afterwards, would silently break. Drop the
        // annotation so the compiler is no longer free to reorder under
        // assumptions that don't hold.
        assembly {
            let N_MASK := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000
            // T_k buffer for the two multi-value hashes, laid out as their
            // preimage seed || adrs || v_0 .. v_{k-1} (32-byte words), so the
            // FORS roots and WOTS endpoints are written in place and hashed
            // without a copy: TB .. TB + 0x5A0 = 0x620, above the 0x00..0x7F
            // single-hash scratch.
            let TB := 0x80
            // Scratch slot for SHA-256 precompile output, above the T_k buffer.
            let OUT := 0x620

            if iszero(eq(sig.length, 4008)) {
                mstore(0x00, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                mstore(0x04, 0x20)
                mstore(0x24, 18)
                mstore(0x44, "Invalid sig length")
                revert(0x00, 0x64)
            }

            // Audit I-2: enforce the N-mask layout (top 16 bytes set,
            // bottom 16 bytes zero) on `pkSeed` / `pkRoot` directly in
            // the verifier, instead of relying on every caller (today
            // only `PQMultiOwnable._addOwnerAtIndex`) to pre-validate.
            // Returning `false` rather than reverting keeps the
            // existing "verifier never reverts on key-shape" contract
            // intact for upstream wrappers that use `try / catch`.
            if iszero(eq(and(pkSeed, N_MASK), pkSeed)) {
                mstore(0x00, 0)
                return(0x00, 0x20)
            }
            if iszero(eq(and(pkRoot, N_MASK), pkRoot)) {
                mstore(0x00, 0)
                return(0x00, 0x20)
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
            mstore(TB, seed) // after H_msg: TB held its all-ones word
            // In-place hashing (below) writes only the top 16 bytes of the value words at 0x40
            // and 0x60; their low halves (0x50..0x5F, 0x70..0x7F) must be and stay zero. 0x40 is
            // rewritten whole by every leaf/digest/chain start; 0x60 still holds H_msg's message.
            mstore(0x60, 0)
            // K-1=12 normal trees
            for { let i := 0 } lt(i, 12) { i := add(i, 1) } {
                let treeIdx := and(shr(mul(i, 11), dVal), 0x7FF) // 11-bit indices
                let secretVal := and(calldataload(add(sigBase, add(16, shl(4, i)))), N_MASK)
                // FORS forest bound to hypertree leaf position: htIdx in the
                // ADRS tree field (bits 160..223). Mirrors the Rust signer's
                // make_adrs(0, ht_idx, FORS_TREE, ...). Without it the FORS
                // forest is shared across all 2^18 positions and forgeable.
                let leafAdrs := or(shl(160, htIdx), or(shl(128, 3), or(shl(96, i), treeIdx)))
                mstore(0x20, leafAdrs)
                mstore(0x40, secretVal)
                // In-place walk: each node's 16 bytes are written by the precompile (outsize 16)
                // straight into its value word of the next preimage seed || adrs || L || R, L at
                // 0x40 if its index is even, else R at 0x60; the sibling's 16 bytes are copied into
                // the other word. The root goes to its T_13 slot (fresh zero memory below).
                pop(staticcall(gas(), 0x02, 0x00, 0x60, add(0x40, shl(5, and(treeIdx, 1))), 16))

                let treeAdrsBase := or(shl(160, htIdx), or(shl(128, 3), shl(96, i)))
                // AUTH_START=224, auth per tree = 11*16 = 176
                let authPtr := add(sigBase, add(224, mul(i, 176)))

                // Walk A=11 auth path levels, unrolled: with x = 32 * treeIdx the node at height k
                // is in the word 0x40 + and(shr(k, x), 0x20) and its sibling in the other; ADRS =
                // treeAdrsBase | h<<32 | treeIdx>>h. Height 11 (the root) goes to its T_13 slot.
                let x := shl(5, treeIdx)
                calldatacopy(sub(0x60, and(shr(0, x), 0x20)), add(authPtr, 0), 16)
                mstore(0x20, or(or(treeAdrsBase, shl(32, 1)), shr(1, treeIdx)))
                pop(staticcall(gas(), 0x02, 0x00, 0x80, add(0x40, and(shr(1, x), 0x20)), 16))
                calldatacopy(sub(0x60, and(shr(1, x), 0x20)), add(authPtr, 16), 16)
                mstore(0x20, or(or(treeAdrsBase, shl(32, 2)), shr(2, treeIdx)))
                pop(staticcall(gas(), 0x02, 0x00, 0x80, add(0x40, and(shr(2, x), 0x20)), 16))
                calldatacopy(sub(0x60, and(shr(2, x), 0x20)), add(authPtr, 32), 16)
                mstore(0x20, or(or(treeAdrsBase, shl(32, 3)), shr(3, treeIdx)))
                pop(staticcall(gas(), 0x02, 0x00, 0x80, add(0x40, and(shr(3, x), 0x20)), 16))
                calldatacopy(sub(0x60, and(shr(3, x), 0x20)), add(authPtr, 48), 16)
                mstore(0x20, or(or(treeAdrsBase, shl(32, 4)), shr(4, treeIdx)))
                pop(staticcall(gas(), 0x02, 0x00, 0x80, add(0x40, and(shr(4, x), 0x20)), 16))
                calldatacopy(sub(0x60, and(shr(4, x), 0x20)), add(authPtr, 64), 16)
                mstore(0x20, or(or(treeAdrsBase, shl(32, 5)), shr(5, treeIdx)))
                pop(staticcall(gas(), 0x02, 0x00, 0x80, add(0x40, and(shr(5, x), 0x20)), 16))
                calldatacopy(sub(0x60, and(shr(5, x), 0x20)), add(authPtr, 80), 16)
                mstore(0x20, or(or(treeAdrsBase, shl(32, 6)), shr(6, treeIdx)))
                pop(staticcall(gas(), 0x02, 0x00, 0x80, add(0x40, and(shr(6, x), 0x20)), 16))
                calldatacopy(sub(0x60, and(shr(6, x), 0x20)), add(authPtr, 96), 16)
                mstore(0x20, or(or(treeAdrsBase, shl(32, 7)), shr(7, treeIdx)))
                pop(staticcall(gas(), 0x02, 0x00, 0x80, add(0x40, and(shr(7, x), 0x20)), 16))
                calldatacopy(sub(0x60, and(shr(7, x), 0x20)), add(authPtr, 112), 16)
                mstore(0x20, or(or(treeAdrsBase, shl(32, 8)), shr(8, treeIdx)))
                pop(staticcall(gas(), 0x02, 0x00, 0x80, add(0x40, and(shr(8, x), 0x20)), 16))
                calldatacopy(sub(0x60, and(shr(8, x), 0x20)), add(authPtr, 128), 16)
                mstore(0x20, or(or(treeAdrsBase, shl(32, 9)), shr(9, treeIdx)))
                pop(staticcall(gas(), 0x02, 0x00, 0x80, add(0x40, and(shr(9, x), 0x20)), 16))
                calldatacopy(sub(0x60, and(shr(9, x), 0x20)), add(authPtr, 144), 16)
                mstore(0x20, or(or(treeAdrsBase, shl(32, 10)), shr(10, treeIdx)))
                pop(staticcall(gas(), 0x02, 0x00, 0x80, add(0x40, and(shr(10, x), 0x20)), 16))
                calldatacopy(sub(0x60, and(shr(10, x), 0x20)), add(authPtr, 160), 16)
                mstore(0x20, or(treeAdrsBase, shl(32, 11)))
                pop(staticcall(gas(), 0x02, 0x00, 0x80, add(add(TB, 0x40), shl(5, i)), 16))
            }

            // Last tree (forced-zero)
            {
                let lastSecret := and(calldataload(add(sigBase, add(16, shl(4, 12)))), N_MASK) // 16+12*16=208
                mstore(0x20, or(shl(160, htIdx), or(shl(128, 3), shl(96, 12))))
                mstore(0x40, lastSecret)
                pop(staticcall(gas(), 0x02, 0x00, 0x60, add(TB, 0x1C0), 16)) // TB + 0x40 + 12*0x20
            }

            // Compress 13 roots: sha256(seed || rootsAdrs || 13 roots)
            // = 32 + 32 + 13*32 = 480 = 0x1E0
            // rootsAdrs also carries htIdx in the tree field (position binding).
            mstore(add(TB, 0x20), or(shl(160, htIdx), shl(128, 4)))
            // the FORS pk lands on the node word (0x40) of the layer-0 WOTS digest preimage
            pop(staticcall(gas(), 0x02, TB, 0x1E0, 0x40, 16))

            // Hypertree (D=2, subtree_h=9, w=8, l=43, target_sum=205)
            let idxTree := htIdx
            let sigOff := 2336 // HT_START

            for { let layer := 0 } lt(layer, 2) { layer := add(layer, 1) } {
                let idxLeaf := and(idxTree, 0x1FF) // 2^9 - 1
                idxTree := shr(9, idxTree)

                let wotsAdrs := or(shl(224, layer), or(shl(160, idxTree), shl(96, idxLeaf)))
                // countOff = sigOff + l*N = sigOff + 688
                let countOff := add(sigOff, 688)
                let count := shr(224, calldataload(add(sigBase, countOff)))

                // digest preimage seed || wotsAdrs || node || count; the node (16 bytes, low
                // half zero) is already at 0x40
                mstore(0x00, seed)
                mstore(0x20, wotsAdrs)
                mstore(0x60, count)
                pop(staticcall(gas(), 0x02, 0x00, 0x80, OUT, 32))
                let d := mload(OUT)
                mstore(0x60, 0) // restore the zero low half of the R word for the Merkle walk

                // Validate digit sum = 205 (43 base-8 digits (d >> 3i) & 7, 3 bits each), summed
                // branch-free (exactness argument and unit gate: test/gas/C10DigitSum.t.sol)
                let lanes := add(add(and(d, 0x1c0e070381c0e070381c0e070381c0e07), and(shr(3, d), 0xe070381c0e070381c0e070381c0e07)), and(shr(6, d), 0xe070381c0e070381c0e070381c0e07)) // C10-SWAR-DIGITSUM
                let digitSum := and(shr(126, mul(lanes, 0x40201008040201008040201008040201)), 0x1FF) // C10-SWAR-DIGITSUM
                if iszero(eq(digitSum, 205)) { revert(0, 0) }

                // 43 WOTS chains (w=8: max 7 steps per chain)
                let wotsPtr := add(sigBase, sigOff)
                // Chain i from position digit_i = (d >> 3i) & 7 to 7 in place: the value word at
                // 0x40 (low half zero) is overwritten by each step's 16-byte output; the ADRS word
                // for chain i at position p is wotsAdrs | i<<64 | p<<32 (ci = bits 64..95, cp =
                // bits 32..63, both zero in wotsAdrs; i < 43, p < 7, so the adds never carry).
                // Unrolled over the 43 chains (generated); 7 - digit_i = bits 3i..3i+2 of nd selects
                // straight-line blocks of 4, 2 and 1 steps at consecutive positions.
                let nd := not(d)
                // BEGIN generated chains (research/c10-gas/gen_v2_chains.py v1; do not edit by hand)
                mstore(0x40, and(calldataload(add(wotsPtr, 0)), N_MASK)) // chain 0
                {
                    let a := add(wotsAdrs, or(shl(64, 0), shl(32, and(shr(0, d), 7))))
                    if and(nd, shl(2, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 4))
                    }
                    if and(nd, shl(1, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 2))
                    }
                    if and(nd, shl(0, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                    }
                }
                mstore(add(TB, 64), mload(0x40))
                mstore(0x40, and(calldataload(add(wotsPtr, 16)), N_MASK)) // chain 1
                {
                    let a := add(wotsAdrs, or(shl(64, 1), shl(32, and(shr(3, d), 7))))
                    if and(nd, shl(5, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 4))
                    }
                    if and(nd, shl(4, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 2))
                    }
                    if and(nd, shl(3, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                    }
                }
                mstore(add(TB, 96), mload(0x40))
                mstore(0x40, and(calldataload(add(wotsPtr, 32)), N_MASK)) // chain 2
                {
                    let a := add(wotsAdrs, or(shl(64, 2), shl(32, and(shr(6, d), 7))))
                    if and(nd, shl(8, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 4))
                    }
                    if and(nd, shl(7, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 2))
                    }
                    if and(nd, shl(6, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                    }
                }
                mstore(add(TB, 128), mload(0x40))
                mstore(0x40, and(calldataload(add(wotsPtr, 48)), N_MASK)) // chain 3
                {
                    let a := add(wotsAdrs, or(shl(64, 3), shl(32, and(shr(9, d), 7))))
                    if and(nd, shl(11, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 4))
                    }
                    if and(nd, shl(10, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 2))
                    }
                    if and(nd, shl(9, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                    }
                }
                mstore(add(TB, 160), mload(0x40))
                mstore(0x40, and(calldataload(add(wotsPtr, 64)), N_MASK)) // chain 4
                {
                    let a := add(wotsAdrs, or(shl(64, 4), shl(32, and(shr(12, d), 7))))
                    if and(nd, shl(14, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 4))
                    }
                    if and(nd, shl(13, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 2))
                    }
                    if and(nd, shl(12, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                    }
                }
                mstore(add(TB, 192), mload(0x40))
                mstore(0x40, and(calldataload(add(wotsPtr, 80)), N_MASK)) // chain 5
                {
                    let a := add(wotsAdrs, or(shl(64, 5), shl(32, and(shr(15, d), 7))))
                    if and(nd, shl(17, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 4))
                    }
                    if and(nd, shl(16, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 2))
                    }
                    if and(nd, shl(15, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                    }
                }
                mstore(add(TB, 224), mload(0x40))
                mstore(0x40, and(calldataload(add(wotsPtr, 96)), N_MASK)) // chain 6
                {
                    let a := add(wotsAdrs, or(shl(64, 6), shl(32, and(shr(18, d), 7))))
                    if and(nd, shl(20, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 4))
                    }
                    if and(nd, shl(19, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 2))
                    }
                    if and(nd, shl(18, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                    }
                }
                mstore(add(TB, 256), mload(0x40))
                mstore(0x40, and(calldataload(add(wotsPtr, 112)), N_MASK)) // chain 7
                {
                    let a := add(wotsAdrs, or(shl(64, 7), shl(32, and(shr(21, d), 7))))
                    if and(nd, shl(23, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 4))
                    }
                    if and(nd, shl(22, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 2))
                    }
                    if and(nd, shl(21, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                    }
                }
                mstore(add(TB, 288), mload(0x40))
                mstore(0x40, and(calldataload(add(wotsPtr, 128)), N_MASK)) // chain 8
                {
                    let a := add(wotsAdrs, or(shl(64, 8), shl(32, and(shr(24, d), 7))))
                    if and(nd, shl(26, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 4))
                    }
                    if and(nd, shl(25, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 2))
                    }
                    if and(nd, shl(24, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                    }
                }
                mstore(add(TB, 320), mload(0x40))
                mstore(0x40, and(calldataload(add(wotsPtr, 144)), N_MASK)) // chain 9
                {
                    let a := add(wotsAdrs, or(shl(64, 9), shl(32, and(shr(27, d), 7))))
                    if and(nd, shl(29, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 4))
                    }
                    if and(nd, shl(28, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 2))
                    }
                    if and(nd, shl(27, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                    }
                }
                mstore(add(TB, 352), mload(0x40))
                mstore(0x40, and(calldataload(add(wotsPtr, 160)), N_MASK)) // chain 10
                {
                    let a := add(wotsAdrs, or(shl(64, 10), shl(32, and(shr(30, d), 7))))
                    if and(nd, shl(32, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 4))
                    }
                    if and(nd, shl(31, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 2))
                    }
                    if and(nd, shl(30, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                    }
                }
                mstore(add(TB, 384), mload(0x40))
                mstore(0x40, and(calldataload(add(wotsPtr, 176)), N_MASK)) // chain 11
                {
                    let a := add(wotsAdrs, or(shl(64, 11), shl(32, and(shr(33, d), 7))))
                    if and(nd, shl(35, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 4))
                    }
                    if and(nd, shl(34, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 2))
                    }
                    if and(nd, shl(33, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                    }
                }
                mstore(add(TB, 416), mload(0x40))
                mstore(0x40, and(calldataload(add(wotsPtr, 192)), N_MASK)) // chain 12
                {
                    let a := add(wotsAdrs, or(shl(64, 12), shl(32, and(shr(36, d), 7))))
                    if and(nd, shl(38, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 4))
                    }
                    if and(nd, shl(37, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 2))
                    }
                    if and(nd, shl(36, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                    }
                }
                mstore(add(TB, 448), mload(0x40))
                mstore(0x40, and(calldataload(add(wotsPtr, 208)), N_MASK)) // chain 13
                {
                    let a := add(wotsAdrs, or(shl(64, 13), shl(32, and(shr(39, d), 7))))
                    if and(nd, shl(41, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 4))
                    }
                    if and(nd, shl(40, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 2))
                    }
                    if and(nd, shl(39, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                    }
                }
                mstore(add(TB, 480), mload(0x40))
                mstore(0x40, and(calldataload(add(wotsPtr, 224)), N_MASK)) // chain 14
                {
                    let a := add(wotsAdrs, or(shl(64, 14), shl(32, and(shr(42, d), 7))))
                    if and(nd, shl(44, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 4))
                    }
                    if and(nd, shl(43, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 2))
                    }
                    if and(nd, shl(42, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                    }
                }
                mstore(add(TB, 512), mload(0x40))
                mstore(0x40, and(calldataload(add(wotsPtr, 240)), N_MASK)) // chain 15
                {
                    let a := add(wotsAdrs, or(shl(64, 15), shl(32, and(shr(45, d), 7))))
                    if and(nd, shl(47, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 4))
                    }
                    if and(nd, shl(46, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 2))
                    }
                    if and(nd, shl(45, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                    }
                }
                mstore(add(TB, 544), mload(0x40))
                mstore(0x40, and(calldataload(add(wotsPtr, 256)), N_MASK)) // chain 16
                {
                    let a := add(wotsAdrs, or(shl(64, 16), shl(32, and(shr(48, d), 7))))
                    if and(nd, shl(50, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 4))
                    }
                    if and(nd, shl(49, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 2))
                    }
                    if and(nd, shl(48, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                    }
                }
                mstore(add(TB, 576), mload(0x40))
                mstore(0x40, and(calldataload(add(wotsPtr, 272)), N_MASK)) // chain 17
                {
                    let a := add(wotsAdrs, or(shl(64, 17), shl(32, and(shr(51, d), 7))))
                    if and(nd, shl(53, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 4))
                    }
                    if and(nd, shl(52, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 2))
                    }
                    if and(nd, shl(51, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                    }
                }
                mstore(add(TB, 608), mload(0x40))
                mstore(0x40, and(calldataload(add(wotsPtr, 288)), N_MASK)) // chain 18
                {
                    let a := add(wotsAdrs, or(shl(64, 18), shl(32, and(shr(54, d), 7))))
                    if and(nd, shl(56, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 4))
                    }
                    if and(nd, shl(55, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 2))
                    }
                    if and(nd, shl(54, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                    }
                }
                mstore(add(TB, 640), mload(0x40))
                mstore(0x40, and(calldataload(add(wotsPtr, 304)), N_MASK)) // chain 19
                {
                    let a := add(wotsAdrs, or(shl(64, 19), shl(32, and(shr(57, d), 7))))
                    if and(nd, shl(59, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 4))
                    }
                    if and(nd, shl(58, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 2))
                    }
                    if and(nd, shl(57, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                    }
                }
                mstore(add(TB, 672), mload(0x40))
                mstore(0x40, and(calldataload(add(wotsPtr, 320)), N_MASK)) // chain 20
                {
                    let a := add(wotsAdrs, or(shl(64, 20), shl(32, and(shr(60, d), 7))))
                    if and(nd, shl(62, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 4))
                    }
                    if and(nd, shl(61, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 2))
                    }
                    if and(nd, shl(60, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                    }
                }
                mstore(add(TB, 704), mload(0x40))
                mstore(0x40, and(calldataload(add(wotsPtr, 336)), N_MASK)) // chain 21
                {
                    let a := add(wotsAdrs, or(shl(64, 21), shl(32, and(shr(63, d), 7))))
                    if and(nd, shl(65, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 4))
                    }
                    if and(nd, shl(64, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 2))
                    }
                    if and(nd, shl(63, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                    }
                }
                mstore(add(TB, 736), mload(0x40))
                mstore(0x40, and(calldataload(add(wotsPtr, 352)), N_MASK)) // chain 22
                {
                    let a := add(wotsAdrs, or(shl(64, 22), shl(32, and(shr(66, d), 7))))
                    if and(nd, shl(68, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 4))
                    }
                    if and(nd, shl(67, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 2))
                    }
                    if and(nd, shl(66, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                    }
                }
                mstore(add(TB, 768), mload(0x40))
                mstore(0x40, and(calldataload(add(wotsPtr, 368)), N_MASK)) // chain 23
                {
                    let a := add(wotsAdrs, or(shl(64, 23), shl(32, and(shr(69, d), 7))))
                    if and(nd, shl(71, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 4))
                    }
                    if and(nd, shl(70, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 2))
                    }
                    if and(nd, shl(69, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                    }
                }
                mstore(add(TB, 800), mload(0x40))
                mstore(0x40, and(calldataload(add(wotsPtr, 384)), N_MASK)) // chain 24
                {
                    let a := add(wotsAdrs, or(shl(64, 24), shl(32, and(shr(72, d), 7))))
                    if and(nd, shl(74, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 4))
                    }
                    if and(nd, shl(73, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 2))
                    }
                    if and(nd, shl(72, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                    }
                }
                mstore(add(TB, 832), mload(0x40))
                mstore(0x40, and(calldataload(add(wotsPtr, 400)), N_MASK)) // chain 25
                {
                    let a := add(wotsAdrs, or(shl(64, 25), shl(32, and(shr(75, d), 7))))
                    if and(nd, shl(77, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 4))
                    }
                    if and(nd, shl(76, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 2))
                    }
                    if and(nd, shl(75, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                    }
                }
                mstore(add(TB, 864), mload(0x40))
                mstore(0x40, and(calldataload(add(wotsPtr, 416)), N_MASK)) // chain 26
                {
                    let a := add(wotsAdrs, or(shl(64, 26), shl(32, and(shr(78, d), 7))))
                    if and(nd, shl(80, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 4))
                    }
                    if and(nd, shl(79, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 2))
                    }
                    if and(nd, shl(78, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                    }
                }
                mstore(add(TB, 896), mload(0x40))
                mstore(0x40, and(calldataload(add(wotsPtr, 432)), N_MASK)) // chain 27
                {
                    let a := add(wotsAdrs, or(shl(64, 27), shl(32, and(shr(81, d), 7))))
                    if and(nd, shl(83, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 4))
                    }
                    if and(nd, shl(82, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 2))
                    }
                    if and(nd, shl(81, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                    }
                }
                mstore(add(TB, 928), mload(0x40))
                mstore(0x40, and(calldataload(add(wotsPtr, 448)), N_MASK)) // chain 28
                {
                    let a := add(wotsAdrs, or(shl(64, 28), shl(32, and(shr(84, d), 7))))
                    if and(nd, shl(86, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 4))
                    }
                    if and(nd, shl(85, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 2))
                    }
                    if and(nd, shl(84, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                    }
                }
                mstore(add(TB, 960), mload(0x40))
                mstore(0x40, and(calldataload(add(wotsPtr, 464)), N_MASK)) // chain 29
                {
                    let a := add(wotsAdrs, or(shl(64, 29), shl(32, and(shr(87, d), 7))))
                    if and(nd, shl(89, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 4))
                    }
                    if and(nd, shl(88, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 2))
                    }
                    if and(nd, shl(87, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                    }
                }
                mstore(add(TB, 992), mload(0x40))
                mstore(0x40, and(calldataload(add(wotsPtr, 480)), N_MASK)) // chain 30
                {
                    let a := add(wotsAdrs, or(shl(64, 30), shl(32, and(shr(90, d), 7))))
                    if and(nd, shl(92, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 4))
                    }
                    if and(nd, shl(91, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 2))
                    }
                    if and(nd, shl(90, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                    }
                }
                mstore(add(TB, 1024), mload(0x40))
                mstore(0x40, and(calldataload(add(wotsPtr, 496)), N_MASK)) // chain 31
                {
                    let a := add(wotsAdrs, or(shl(64, 31), shl(32, and(shr(93, d), 7))))
                    if and(nd, shl(95, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 4))
                    }
                    if and(nd, shl(94, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 2))
                    }
                    if and(nd, shl(93, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                    }
                }
                mstore(add(TB, 1056), mload(0x40))
                mstore(0x40, and(calldataload(add(wotsPtr, 512)), N_MASK)) // chain 32
                {
                    let a := add(wotsAdrs, or(shl(64, 32), shl(32, and(shr(96, d), 7))))
                    if and(nd, shl(98, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 4))
                    }
                    if and(nd, shl(97, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 2))
                    }
                    if and(nd, shl(96, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                    }
                }
                mstore(add(TB, 1088), mload(0x40))
                mstore(0x40, and(calldataload(add(wotsPtr, 528)), N_MASK)) // chain 33
                {
                    let a := add(wotsAdrs, or(shl(64, 33), shl(32, and(shr(99, d), 7))))
                    if and(nd, shl(101, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 4))
                    }
                    if and(nd, shl(100, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 2))
                    }
                    if and(nd, shl(99, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                    }
                }
                mstore(add(TB, 1120), mload(0x40))
                mstore(0x40, and(calldataload(add(wotsPtr, 544)), N_MASK)) // chain 34
                {
                    let a := add(wotsAdrs, or(shl(64, 34), shl(32, and(shr(102, d), 7))))
                    if and(nd, shl(104, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 4))
                    }
                    if and(nd, shl(103, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 2))
                    }
                    if and(nd, shl(102, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                    }
                }
                mstore(add(TB, 1152), mload(0x40))
                mstore(0x40, and(calldataload(add(wotsPtr, 560)), N_MASK)) // chain 35
                {
                    let a := add(wotsAdrs, or(shl(64, 35), shl(32, and(shr(105, d), 7))))
                    if and(nd, shl(107, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 4))
                    }
                    if and(nd, shl(106, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 2))
                    }
                    if and(nd, shl(105, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                    }
                }
                mstore(add(TB, 1184), mload(0x40))
                mstore(0x40, and(calldataload(add(wotsPtr, 576)), N_MASK)) // chain 36
                {
                    let a := add(wotsAdrs, or(shl(64, 36), shl(32, and(shr(108, d), 7))))
                    if and(nd, shl(110, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 4))
                    }
                    if and(nd, shl(109, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 2))
                    }
                    if and(nd, shl(108, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                    }
                }
                mstore(add(TB, 1216), mload(0x40))
                mstore(0x40, and(calldataload(add(wotsPtr, 592)), N_MASK)) // chain 37
                {
                    let a := add(wotsAdrs, or(shl(64, 37), shl(32, and(shr(111, d), 7))))
                    if and(nd, shl(113, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 4))
                    }
                    if and(nd, shl(112, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 2))
                    }
                    if and(nd, shl(111, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                    }
                }
                mstore(add(TB, 1248), mload(0x40))
                mstore(0x40, and(calldataload(add(wotsPtr, 608)), N_MASK)) // chain 38
                {
                    let a := add(wotsAdrs, or(shl(64, 38), shl(32, and(shr(114, d), 7))))
                    if and(nd, shl(116, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 4))
                    }
                    if and(nd, shl(115, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 2))
                    }
                    if and(nd, shl(114, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                    }
                }
                mstore(add(TB, 1280), mload(0x40))
                mstore(0x40, and(calldataload(add(wotsPtr, 624)), N_MASK)) // chain 39
                {
                    let a := add(wotsAdrs, or(shl(64, 39), shl(32, and(shr(117, d), 7))))
                    if and(nd, shl(119, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 4))
                    }
                    if and(nd, shl(118, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 2))
                    }
                    if and(nd, shl(117, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                    }
                }
                mstore(add(TB, 1312), mload(0x40))
                mstore(0x40, and(calldataload(add(wotsPtr, 640)), N_MASK)) // chain 40
                {
                    let a := add(wotsAdrs, or(shl(64, 40), shl(32, and(shr(120, d), 7))))
                    if and(nd, shl(122, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 4))
                    }
                    if and(nd, shl(121, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 2))
                    }
                    if and(nd, shl(120, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                    }
                }
                mstore(add(TB, 1344), mload(0x40))
                mstore(0x40, and(calldataload(add(wotsPtr, 656)), N_MASK)) // chain 41
                {
                    let a := add(wotsAdrs, or(shl(64, 41), shl(32, and(shr(123, d), 7))))
                    if and(nd, shl(125, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 4))
                    }
                    if and(nd, shl(124, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 2))
                    }
                    if and(nd, shl(123, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                    }
                }
                mstore(add(TB, 1376), mload(0x40))
                mstore(0x40, and(calldataload(add(wotsPtr, 672)), N_MASK)) // chain 42
                {
                    let a := add(wotsAdrs, or(shl(64, 42), shl(32, and(shr(126, d), 7))))
                    if and(nd, shl(128, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 2)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 3)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 4))
                    }
                    if and(nd, shl(127, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        mstore(0x20, add(a, shl(32, 1)))
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                        a := add(a, shl(32, 2))
                    }
                    if and(nd, shl(126, 1)) {
                        mstore(0x20, a)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))
                    }
                }
                mstore(add(TB, 1408), mload(0x40))
                // END generated chains

                // PK compression: sha256(seed || pkAdrs || 43 endpoints)
                // = 32 + 32 + 43*32 = 1440 = 0x5A0
                let pkAdrs := or(shl(224, layer), or(shl(160, idxTree), or(shl(128, 1), shl(96, idxLeaf))))
                mstore(add(TB, 0x20), pkAdrs)
                // the WOTS pk lands in its value word of the first Merkle preimage
                pop(staticcall(gas(), 0x02, TB, 0x5A0, add(0x40, shl(5, and(idxLeaf, 1))), 16))

                // Merkle auth path (9 levels)
                let authOff := add(countOff, 4)
                let treeAdrs := or(shl(224, layer), or(shl(160, idxTree), shl(128, 2)))
                let merklePtr := add(sigBase, authOff)

                // in-place walk as in FORS, unrolled (x = 32 * idxLeaf; ha = idxLeaf >> h); the
                // root (height 9, index 0) lands on 0x40, the next layer's digest node word
                let tb := and(treeAdrs, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000000000000000)
                let x := shl(5, idxLeaf)
                calldatacopy(sub(0x60, and(shr(0, x), 0x20)), add(merklePtr, 0), 16)
                mstore(0x20, or(or(tb, shl(32, 1)), shr(1, idxLeaf)))
                pop(staticcall(gas(), 0x02, 0x00, 0x80, add(0x40, and(shr(1, x), 0x20)), 16))
                calldatacopy(sub(0x60, and(shr(1, x), 0x20)), add(merklePtr, 16), 16)
                mstore(0x20, or(or(tb, shl(32, 2)), shr(2, idxLeaf)))
                pop(staticcall(gas(), 0x02, 0x00, 0x80, add(0x40, and(shr(2, x), 0x20)), 16))
                calldatacopy(sub(0x60, and(shr(2, x), 0x20)), add(merklePtr, 32), 16)
                mstore(0x20, or(or(tb, shl(32, 3)), shr(3, idxLeaf)))
                pop(staticcall(gas(), 0x02, 0x00, 0x80, add(0x40, and(shr(3, x), 0x20)), 16))
                calldatacopy(sub(0x60, and(shr(3, x), 0x20)), add(merklePtr, 48), 16)
                mstore(0x20, or(or(tb, shl(32, 4)), shr(4, idxLeaf)))
                pop(staticcall(gas(), 0x02, 0x00, 0x80, add(0x40, and(shr(4, x), 0x20)), 16))
                calldatacopy(sub(0x60, and(shr(4, x), 0x20)), add(merklePtr, 64), 16)
                mstore(0x20, or(or(tb, shl(32, 5)), shr(5, idxLeaf)))
                pop(staticcall(gas(), 0x02, 0x00, 0x80, add(0x40, and(shr(5, x), 0x20)), 16))
                calldatacopy(sub(0x60, and(shr(5, x), 0x20)), add(merklePtr, 80), 16)
                mstore(0x20, or(or(tb, shl(32, 6)), shr(6, idxLeaf)))
                pop(staticcall(gas(), 0x02, 0x00, 0x80, add(0x40, and(shr(6, x), 0x20)), 16))
                calldatacopy(sub(0x60, and(shr(6, x), 0x20)), add(merklePtr, 96), 16)
                mstore(0x20, or(or(tb, shl(32, 7)), shr(7, idxLeaf)))
                pop(staticcall(gas(), 0x02, 0x00, 0x80, add(0x40, and(shr(7, x), 0x20)), 16))
                calldatacopy(sub(0x60, and(shr(7, x), 0x20)), add(merklePtr, 112), 16)
                mstore(0x20, or(or(tb, shl(32, 8)), shr(8, idxLeaf)))
                pop(staticcall(gas(), 0x02, 0x00, 0x80, add(0x40, and(shr(8, x), 0x20)), 16))
                calldatacopy(sub(0x60, and(shr(8, x), 0x20)), add(merklePtr, 128), 16)
                mstore(0x20, or(tb, shl(32, 9)))
                pop(staticcall(gas(), 0x02, 0x00, 0x80, 0x40, 16))

                sigOff := add(authOff, 144) // 9*16
            }

            valid := eq(and(mload(0x40), N_MASK), root)
            mstore(0x00, valid)
            return(0x00, 0x20)
        }
    }
}
