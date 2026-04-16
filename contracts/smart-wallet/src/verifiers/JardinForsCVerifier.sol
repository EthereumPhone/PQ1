// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title JardinForsCVerifier — Stateless JARDIN FORS+C verifier (shared, Yul-optimized)
/// @notice Variant 2: k=26 a=5 n=16 Q_MAX=95 sig=2452+q*16
///         Compact post-quantum signatures using FORS+C with an unbalanced
///         Merkle tree. Keccak256-based tweakable hashing, branchless Merkle swap.
/// @dev Gas: ~66K base + ~500 per unbalanced auth node.
///      Signature layout:
///        [0..32)      R (randomizer, full 32 bytes)
///        [32..36)     counter (BE u32)
///        [36..2436)   25 FORS openings (each: secret(16) + auth(5*16) = 96B)
///        [2436..2452) lastRoot (tree 25, forced-zero)
///        [2452..)     unbalanced auth path (q * 16 bytes)
contract JardinForsCVerifier {

    function verifyForsCUnbalanced(
        bytes32 pkSeed,
        bytes32 pkRoot,
        bytes32 message,
        bytes calldata sig
    ) external pure returns (bool valid) {
        assembly ("memory-safe") {
            let N_MASK := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000

            // ── Step 1: Parse signature length and derive q ──
            // authBytes = sig.length - 2452; q = authBytes / 16
            let FORSC_BODY := 2452
            if lt(sig.length, 2468) { revert(0, 0) }
            let authBytes := sub(sig.length, FORSC_BODY)
            if mod(authBytes, 16) { revert(0, 0) }
            let q := div(authBytes, 16)

            let seed := pkSeed
            let root := pkRoot
            let sigBase := sig.offset

            // ── Step 2: H_msg (192-byte domain-separated hash) ──
            // keccak256(pkSeed(32) || pkRoot(32) || R(32) || message(32) ||
            //           counter_u256(32) || 0xFF..FF(32)) = 192 bytes
            mstore(0x00, seed)
            mstore(0x20, root)
            // R = sig[0..32] — full 32 bytes, NOT N-masked
            let R := calldataload(sigBase)
            mstore(0x40, R)
            mstore(0x60, message)
            // counter = sig[32..36] as u256 (big-endian u32 in top bits of calldataload)
            let counterRaw := calldataload(add(sigBase, 32))
            let counterVal := shr(224, counterRaw) // extract top 4 bytes as u32
            mstore(0x80, counterVal) // counter as u256 (value in low bits)
            mstore(0xA0, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
            let digest := keccak256(0x00, 0xC0) // 192 bytes

            // ── Step 3: Forced-zero check ──
            // last_index = (digest >> 125) & 0x1F  — tree 25, bits 125-129
            if and(shr(125, digest), 0x1F) { revert(0, 0) }

            // ── Step 4: Verify 25 FORS tree openings (trees 0..24) ──
            // Re-store seed at 0x00 for tweakable hashes
            mstore(0x00, seed)

            for { let t := 0 } lt(t, 25) { t := add(t, 1) } {
                // Extract 5-bit FORS index for tree t
                let treeIdx := and(shr(mul(t, 5), digest), 0x1F)

                // Secret offset: 36 + t*96 (each opening = 16 secret + 80 auth = 96)
                let secretOff := add(36, mul(t, 96))
                let secretVal := and(calldataload(add(sigBase, secretOff)), N_MASK)

                // Hash secret into leaf: th(seed, adrs{atype=3, kp=t, ci=q, ha=treeIdx}, secret)
                let leafAdrs := or(shl(128, 3), or(shl(96, t), or(shl(64, q), treeIdx)))
                mstore(0x20, leafAdrs)
                mstore(0x40, secretVal)
                let node := and(keccak256(0x00, 0x60), N_MASK)

                // Walk 5-level auth path
                let treeAdrsBase := or(shl(128, 3), or(shl(96, t), shl(64, q)))
                let pathIdx := treeIdx
                // Auth path starts at: secretOff + 16
                let authPtr := add(sigBase, add(secretOff, 16))

                for { let h := 0 } lt(h, 5) { h := add(h, 1) } {
                    let sibling := and(calldataload(add(authPtr, shl(4, h))), N_MASK)
                    let parentIdx := shr(1, pathIdx)
                    // adrs = {atype=3, kp=t, ci=q, cp=h+1, ha=parentIdx}
                    mstore(0x20, or(treeAdrsBase, or(shl(32, add(h, 1)), parentIdx)))
                    // Branchless Merkle swap (Solady pattern)
                    let s := shl(5, and(pathIdx, 1))
                    mstore(xor(0x40, s), node)
                    mstore(xor(0x60, s), sibling)
                    node := and(keccak256(0x00, 0x80), N_MASK)
                    pathIdx := parentIdx
                }

                // Store root for this tree at 0x80 + t*32
                mstore(add(0x80, shl(5, t)), node)
            }

            // ── Step 5: Last tree (tree 25, forced-zero) ──
            {
                // lastRoot at offset 2436 (= 36 + 25*96)
                let lastRoot := and(calldataload(add(sigBase, 2436)), N_MASK)
                // Hash as leaf: th(seed, {atype=3, kp=25, ci=q, ha=0}, lastRoot)
                let lastAdrs := or(shl(128, 3), or(shl(96, 25), shl(64, q)))
                mstore(0x20, lastAdrs)
                mstore(0x40, lastRoot)
                // Store at 0x80 + 25*32 = 0x80 + 0x320 = 0x3A0
                mstore(0x3A0, and(keccak256(0x00, 0x60), N_MASK))
            }

            // ── Step 6: Compress 26 FORS roots into forsPk ──
            // keccak256(seed(32) || rootsAdrs(32) || 26 roots(26*32)) = 896 bytes
            // rootsAdrs = {atype=4, ci=q}
            mstore(0x20, or(shl(128, 4), shl(64, q)))
            // Roots are already at 0x80..0x3C0 (26 * 32 = 832 bytes)
            // We need: seed @ 0x00, adrs @ 0x20, roots @ 0x40..
            // Move roots from 0x80 to 0x40
            for { let i := 0 } lt(i, 26) { i := add(i, 1) } {
                mstore(add(0x40, shl(5, i)), mload(add(0x80, shl(5, i))))
            }
            // keccak256(0x00, 32 + 32 + 26*32) = keccak256(0x00, 896)
            let forsPk := and(keccak256(0x00, 0x380), N_MASK)

            // ── Step 7: Walk unbalanced tree auth path (q nodes) ──
            // Auth path starts at offset 2452 in sig
            let unbBase := add(sigBase, FORSC_BODY)

            // Step 0: auth[0] is LEFT, forsPk is RIGHT
            // adrs = {atype=6, cp=q-1}
            mstore(0x00, seed)
            {
                let auth0 := and(calldataload(unbBase), N_MASK)
                mstore(0x20, or(shl(128, 6), shl(32, sub(q, 1))))
                mstore(0x40, auth0)
                mstore(0x60, forsPk)
            }
            let unbNode := and(keccak256(0x00, 0x80), N_MASK)

            // Steps 1..q-1: node is LEFT, auth[j] is RIGHT
            for { let j := 1 } lt(j, q) { j := add(j, 1) } {
                let authJ := and(calldataload(add(unbBase, shl(4, j))), N_MASK)
                // adrs = {atype=6, cp=q-1-j}
                mstore(0x20, or(shl(128, 6), shl(32, sub(sub(q, 1), j))))
                mstore(0x40, unbNode)
                mstore(0x60, authJ)
                unbNode := and(keccak256(0x00, 0x80), N_MASK)
            }

            // ── Step 8: Compare ──
            valid := eq(unbNode, root)
            mstore(0x00, valid)
            return(0x00, 0x20)
        }
    }
}
