// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @notice MVP — NOT audited, NOT deployed, NOT pinned in any firmware.
///
/// Same check as `ENSRecipientGuard`, cut to the gas floor: reverts unless,
/// in this transaction, the ENS Registry's resolver for `node` answers
/// `addr(node) == expected`. What remains is what any execution-time ENS
/// read must pay: three cold accounts (this contract, the registry, the
/// resolver) and four cold storage slots (registry owner + resolver,
/// resolver record version + address).
///
/// Differences from `ENSRecipientGuard`:
///  - calldata is packed, no selector: `node (32) || expected (20)` = 52 B;
///  - `addr(bytes32)` (coin type 60) instead of `addr(bytes32,uint256)`:
///    same storage reads, a 32-byte answer instead of an ABI `bytes`;
///  - no EXTCODESIZE: a resolver without code (or none at all) returns no
///    data, and anything but exactly 32 bytes refuses the batch.
///
/// There are deliberately NO external functions: with packed calldata, the
/// first four bytes of a node could equal some function's selector and
/// dispatch there instead of reaching the check.
contract ENSRecipientGuardPacked {
    fallback() external {
        assembly ("memory-safe") {
            if iszero(eq(calldatasize(), 52)) { revert(0, 0) }
            let node := calldataload(0)
            let expected := shr(96, calldataload(32))

            // ENS.resolver(node)
            mstore(0x00, shl(224, 0x0178b8bf))
            mstore(0x04, node)
            if iszero(staticcall(gas(), 0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e, 0x00, 0x24, 0x00, 0x20)) {
                revert(0, 0)
            }
            if iszero(eq(returndatasize(), 0x20)) { revert(0, 0) }
            let r := mload(0x00)

            // resolver.addr(node)
            mstore(0x00, shl(224, 0x3b3b57de))
            mstore(0x04, node)
            if iszero(staticcall(gas(), r, 0x00, 0x24, 0x00, 0x20)) { revert(0, 0) }
            if iszero(eq(returndatasize(), 0x20)) { revert(0, 0) }
            if or(iszero(expected), iszero(eq(mload(0x00), expected))) { revert(0, 0) }
        }
    }
}
