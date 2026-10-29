// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @notice MVP — NOT audited, NOT deployed, NOT pinned in any firmware.
///
/// The on-chain half of a cheaper ENS name check. The DEVICE verifies the
/// name: the companion hands it a block header and `eth_getProof` Merkle
/// proofs (ENS Registry + resolver storage), and the device checks
/// `keccak(header) -> stateRoot -> account -> storage -> address` itself.
/// The only thing the device cannot know offline is whether that header is
/// a real block. This contract settles that at execution time, as the first
/// record of the signed `executeBatchWithOffchainCount` batch:
///
///     [ anchor <- number || keccak(header), payment ]
///
/// A forged header (fake state root, so fake proofs) has a hash that is no
/// block's hash, so the whole batch reverts and nothing is paid.
///
/// Calldata (36 bytes, no selector):
///     [0:4]   block number, uint32 big-endian
///     [4:36]  block hash
///
/// BLOCKHASH answers only for the 256 most recent blocks and returns 0
/// otherwise (including for the current block), so a passing call also
/// proves the proven state is at most 256 blocks (~51 min on L1) old. One
/// anchor covers every name proven at that block.
///
/// There are deliberately NO external functions: the first four bytes are a
/// block number, which must never be able to hit a selector instead.
contract BlockHashAnchor {
    fallback() external {
        assembly ("memory-safe") {
            if iszero(eq(calldatasize(), 36)) { revert(0, 0) }
            let h := blockhash(shr(224, calldataload(0)))
            if or(iszero(h), iszero(eq(h, calldataload(4)))) { revert(0, 0) }
        }
    }
}
