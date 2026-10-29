// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @notice MVP — NOT audited, NOT deployed, NOT pinned in any firmware.
///
/// A stateless, ownerless check that the wallet calls as the FIRST record of
/// an `executeBatchWithOffchainCount` batch, ahead of the payment it guards:
///
///     [ guard.check(namehash("alice.eth"), 60, X), token.transfer(X, amt) ]
///
/// `executeBatchWithOffchainCount` reverts the whole batch when any record
/// reverts, so the payment runs only if, in that same transaction, ENS
/// resolves the name to exactly `X`. That turns "the device showed
/// alice.eth" from a display claim into an execution-time precondition: the
/// device needs no proof, no clock and no oracle, only to check that the
/// guard's arguments match the name it shows and the recipient it decoded.
///
/// Scope of the MVP:
///  - forward resolution only (`name -> address`), which is the property a
///    payment needs; a reverse record proves nothing extra for the payer;
///  - the ENS Registry is read directly (immutable, no DAO upgrade path);
///  - the name's own resolver must answer `addr(bytes32,uint256)` (ENSIP-9).
///    Wildcard (ENSIP-10) and offchain (CCIP-Read, EIP-3668) names revert
///    here, so a companion must not attach a guard for them;
///  - Ethereum L1 only. Other chains have no code at the registry address
///    and every call reverts (fail-closed).
contract ENSRecipientGuard {
    /// ENSRegistryWithFallback, Ethereum mainnet (also Sepolia/Holesky).
    address public constant ENS_REGISTRY = 0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e;

    /// `addr(bytes32 node, uint256 coinType) returns (bytes)` — ENSIP-9.
    bytes4 private constant ADDR_MULTICOIN = 0xf1cb7e06;

    error ZeroExpected();
    error NoResolver(bytes32 node);
    error NameMismatch(bytes32 node, bytes resolved);

    function check(bytes32 node, uint256 coinType, address expected) external view {
        if (expected == address(0)) revert ZeroExpected();

        address r = IENSRegistry(ENS_REGISTRY).resolver(node);
        if (r.code.length == 0) revert NoResolver(node);

        (bool ok, bytes memory ret) = r.staticcall(abi.encodeWithSelector(ADDR_MULTICOIN, node, coinType));
        bytes memory a;
        // A malformed return makes abi.decode revert, which is the right
        // outcome: anything but a clean 20-byte answer refuses the batch.
        if (ok && ret.length >= 64) a = abi.decode(ret, (bytes));
        if (a.length != 20 || address(bytes20(a)) != expected) revert NameMismatch(node, a);
    }
}

interface IENSRegistry {
    function resolver(bytes32 node) external view returns (address);
}
