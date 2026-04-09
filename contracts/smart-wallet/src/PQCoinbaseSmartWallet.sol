// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {IAccount} from "account-abstraction/interfaces/IAccount.sol";
import {UserOperation, UserOperationLib} from "account-abstraction/interfaces/UserOperation.sol";
import {Receiver} from "solady/accounts/Receiver.sol";
import {UUPSUpgradeable} from "solady/utils/UUPSUpgradeable.sol";

import {ERC1271} from "./ERC1271.sol";
import {PQOwnable} from "./PQOwnable.sol";
import {ISLHDSAVerifier} from "./verifiers/ISLHDSAVerifier.sol";

/// @title PQCoinbaseSmartWallet
///
/// @notice ERC-4337-compatible smart account whose only authorised
///         signer is a SPHINCS+ (SLH-DSA-SHA2-128f) post-quantum key.
///
///         This is a fork of `coinbase/smart-wallet`'s
///         `CoinbaseSmartWallet.sol` with two surgical changes:
///
///           1. The {MultiOwnable} authentication scheme — which
///              accepted both secp256k1 EOA owners and WebAuthn / P-256
///              public-key owners — is replaced by {PQOwnable}, which
///              tolerates exactly one owner key, identified by
///              `sha256(slhdsa_pk)`. There is no fallback to a classical
///              curve, no add-owner / remove-owner path, no recovery via
///              guardian addresses. Once a quantum adversary appears, an
///              account that still accepts a classical signature is
///              indistinguishable from one that has no owner at all, so
///              the entire fallback surface is removed.
///
///           2. {_isValidSignature} no longer dispatches on owner type
///              or calls `SignatureCheckerLib`/`WebAuthn.verify`. It
///              hands the (msgHash, signature) pair to the
///              {ISLHDSAVerifier} configured at deploy time and accepts
///              the signature iff that returns `true`.
///
///         The signature wire format is:
///
///             abi.encode(bytes pk, bytes sigBytes)
///
///         where `pk` is the 32-byte SLH-DSA verifying key (rechecked
///         against the on-chain commitment via {PQOwnable.isOwnerKey})
///         and `sigBytes` is the 17,088-byte SLH-DSA signature.
///
/// @dev Cross-chain replayable nonces (`REPLAYABLE_NONCE_KEY` /
///      `executeWithoutChainIdValidation`) are intentionally KEPT from
///      the upstream design — they were never about classical signing,
///      they're a UX feature for syncing wallet state across chains
///      that share an address. The PQ rewrite preserves the same
///      replay-safe path with the same nonce key constant.
///
/// @author PQSigner OS (forked from coinbase/smart-wallet)
contract PQCoinbaseSmartWallet is ERC1271, IAccount, PQOwnable, UUPSUpgradeable, Receiver {
    /// @notice ABI-encoded `(bytes pk, bytes sig)` carried in
    ///         `UserOperation.signature`.
    struct PQSignatureWrapper {
        /// @dev The 32-byte SLH-DSA verifying key. Must hash to
        ///      {PQOwnable.ownerKeyHash}.
        bytes pk;
        /// @dev The 17,088-byte SLH-DSA-SHA2-128f signature.
        bytes signature;
    }

    /// @notice Represents a single call to make from the account.
    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    /// @notice Reserved nonce key for cross-chain replayable user operations.
    uint256 public constant REPLAYABLE_NONCE_KEY = 8453;

    /// @notice The verifier contract used to check SLH-DSA signatures.
    ///
    /// @dev Set at construction time and is read every `validateUserOp`
    ///      call. The verifier is intentionally split out into a
    ///      separate contract so a deployment can swap a Solidity
    ///      reference verifier for a Groth16-wrapped or precompile
    ///      version without redeploying the wallet.
    ISLHDSAVerifier public immutable verifier;

    /// @notice Thrown when initialisation is attempted twice.
    error Initialized();

    /// @notice Thrown when an `executeWithoutChainIdValidation` call
    ///         attempts a selector that isn't on the allow-list.
    error SelectorNotAllowed(bytes4 selector);

    /// @notice Thrown when the nonce key is inconsistent with the call.
    error InvalidNonceKey(uint256 key);

    /// @notice Thrown when an upgrade target has no code.
    error InvalidImplementation(address implementation);

    /// @notice Thrown when the signature wrapper carries a public key
    ///         that does not match the on-chain commitment.
    error WrongOwnerKey();

    /// @notice Reverts unless the caller is the EntryPoint.
    modifier onlyEntryPoint() virtual {
        if (msg.sender != entryPoint()) revert Unauthorized();
        _;
    }

    /// @notice Reverts unless the caller is either the EntryPoint or
    ///         the account itself.
    modifier onlyEntryPointOrSelf() virtual {
        if (msg.sender != entryPoint()) _checkOwner();
        _;
    }

    /// @notice Sends the EntryPoint the missing prefund, if any.
    modifier payPrefund(uint256 missingAccountFunds) virtual {
        _;
        assembly ("memory-safe") {
            if missingAccountFunds {
                pop(call(gas(), caller(), missingAccountFunds, codesize(), 0x00, codesize(), 0x00))
            }
        }
    }

    /// @param verifier_ The address of the {ISLHDSAVerifier} this
    ///                  implementation will use.
    constructor(ISLHDSAVerifier verifier_) {
        verifier = verifier_;
        // The implementation contract must never be initialised — only
        // proxies pointing at it can be. We initialise the implementation
        // with a sentinel hash so the slot is non-zero, blocking
        // re-initialisation through the implementation.
        _initializeOwner(bytes32(uint256(1)));
    }

    /// @notice Initialises a freshly cloned proxy with its single
    ///         SPHINCS+ owner.
    ///
    /// @param ownerKeyHash_ `sha256(slhdsa_pk)` for the wallet's owner.
    function initialize(bytes32 ownerKeyHash_) external payable virtual {
        if (isInitialized()) revert Initialized();
        _initializeOwner(ownerKeyHash_);
    }

    /// @inheritdoc IAccount
    function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        virtual
        onlyEntryPoint
        payPrefund(missingAccountFunds)
        returns (uint256 validationData)
    {
        uint256 key = userOp.nonce >> 64;

        if (bytes4(userOp.callData) == this.executeWithoutChainIdValidation.selector) {
            userOpHash = getUserOpHashWithoutChainId(userOp);
            if (key != REPLAYABLE_NONCE_KEY) revert InvalidNonceKey(key);

            // Validate any embedded `upgradeToAndCall` targets.
            bytes[] memory calls = abi.decode(userOp.callData[4:], (bytes[]));
            for (uint256 i; i < calls.length; ++i) {
                bytes memory cd = calls[i];
                bytes4 selector = bytes4(cd);
                if (selector == UUPSUpgradeable.upgradeToAndCall.selector) {
                    address newImplementation;
                    assembly {
                        newImplementation := mload(add(cd, 36))
                    }
                    if (newImplementation.code.length == 0) revert InvalidImplementation(newImplementation);
                }
            }
        } else {
            if (key == REPLAYABLE_NONCE_KEY) revert InvalidNonceKey(key);
        }

        // ERC-4337 returns 0 = success, 1 = signature failure. Anything
        // else is an aggregator/timestamp packed validationData; we
        // don't use those.
        return _isValidSignature(userOpHash, userOp.signature) ? 0 : 1;
    }

    /// @notice Executes a batch of self-calls without binding to a chain ID.
    function executeWithoutChainIdValidation(bytes[] calldata calls) external payable virtual onlyEntryPoint {
        for (uint256 i; i < calls.length; ++i) {
            bytes calldata cd = calls[i];
            bytes4 selector = bytes4(cd);
            if (!canSkipChainIdValidation(selector)) revert SelectorNotAllowed(selector);
            _call(address(this), 0, cd);
        }
    }

    /// @notice Executes a single call from the account.
    function execute(address target, uint256 value, bytes calldata data)
        external
        payable
        virtual
        onlyEntryPointOrSelf
    {
        _call(target, value, data);
    }

    /// @notice Executes a batch of calls from the account.
    function executeBatch(Call[] calldata calls) external payable virtual onlyEntryPointOrSelf {
        for (uint256 i; i < calls.length; ++i) {
            _call(calls[i].target, calls[i].value, calls[i].data);
        }
    }

    /// @notice Returns the EntryPoint v0.6 address.
    function entryPoint() public view virtual returns (address) {
        return 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    }

    /// @notice EntryPoint-style userOpHash that omits chain ID, for
    ///         cross-chain replayable user operations.
    function getUserOpHashWithoutChainId(UserOperation calldata userOp) public view virtual returns (bytes32) {
        return keccak256(abi.encode(UserOperationLib.hash(userOp), entryPoint()));
    }

    /// @notice Returns the implementation slot of the ERC-1967 proxy.
    function implementation() public view returns (address $) {
        assembly {
            $ := sload(_ERC1967_IMPLEMENTATION_SLOT)
        }
    }

    /// @notice Selectors permitted in `executeWithoutChainIdValidation`.
    ///
    /// @dev Owner-management selectors from upstream are removed (the
    ///      single SPHINCS+ owner is immutable). What remains is the
    ///      upgrade selector, which still needs cross-chain replay so a
    ///      single signed UserOp can roll out an implementation change
    ///      to every chain the wallet is deployed on.
    function canSkipChainIdValidation(bytes4 functionSelector) public pure returns (bool) {
        return functionSelector == UUPSUpgradeable.upgradeToAndCall.selector;
    }

    function _call(address target, uint256 value, bytes memory data) internal {
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            assembly ("memory-safe") {
                revert(add(result, 32), mload(result))
            }
        }
    }

    /// @inheritdoc ERC1271
    ///
    /// @dev The signature wire format is `abi.encode(bytes pk, bytes sig)`.
    ///      The verifier is the immutable {verifier}; the public key
    ///      must hash to the on-chain commitment.
    function _isValidSignature(bytes32 hash, bytes calldata signature)
        internal
        view
        virtual
        override
        returns (bool)
    {
        PQSignatureWrapper memory w = abi.decode(signature, (PQSignatureWrapper));
        if (sha256(w.pk) != ownerKeyHash()) return false;
        // Defensive: a malformed sig length would normally be caught by
        // the verifier itself, but checking here keeps gas predictable
        // and surfaces wrong-shape signatures faster.
        if (w.signature.length != 17_088) return false;
        if (w.pk.length != 32) return false;
        return verifier.verify(w.pk, hash, w.signature);
    }

    /// @inheritdoc UUPSUpgradeable
    function _authorizeUpgrade(address) internal view virtual override(UUPSUpgradeable) onlyOwner {}

    /// @inheritdoc ERC1271
    function _domainNameAndVersion() internal pure override(ERC1271) returns (string memory, string memory) {
        return ("PQ Coinbase Smart Wallet", "1");
    }
}
