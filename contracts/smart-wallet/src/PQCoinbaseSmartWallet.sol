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
/// @notice ERC-4337-compatible smart account with a two-tier post-quantum
///         signer architecture:
///
///         - **Bootstrap signer**: stateless PQ key (ML-DSA-44 recommended)
///           for administrative operations (deployment, emergency rotation).
///           Never rotates.
///         - **Main signer**: stateful hash-based PQ key (SPHINCS+ few-time
///           or XMSS) for day-to-day transactions. Rotates every ~1M
///           signatures. Per-chain and per-epoch.
///
///         This is a fork of `coinbase/smart-wallet` modified for the
///         two-tier PQ architecture described in the wallet design spec.
///
///         The signature wire format is:
///
///             abi.encode(PQSignatureWrapper)
///
///         where `PQSignatureWrapper` contains the signer type, key epoch,
///         OTS index, public key, and signature bytes.
///
/// @author PQSigner OS (forked from coinbase/smart-wallet)
contract PQCoinbaseSmartWallet is ERC1271, IAccount, PQOwnable, UUPSUpgradeable, Receiver {
    /// @notice Signer type discriminator for the dual-path validation.
    enum SignerType {
        MAIN,
        BOOTSTRAP
    }

    /// @notice ABI-encoded signature wrapper carried in
    ///         `UserOperation.signature`.
    struct PQSignatureWrapper {
        /// @dev Which signer path to use for validation.
        SignerType signerType;
        /// @dev The key epoch index. For MAIN signer, must match
        ///      `currentKeyIndex`. Ignored for BOOTSTRAP.
        uint32 keyIndex;
        /// @dev The OTS leaf index. For MAIN signer, must match
        ///      `currentOTSIndex`. Ignored for BOOTSTRAP.
        uint32 otsIndex;
        /// @dev The public key bytes. For MAIN, must hash (keccak256) to
        ///      `currentMainPubKeyHash`. For BOOTSTRAP, must hash (sha256)
        ///      to `bootstrapPubKeyHash`.
        bytes pk;
        /// @dev The PQ signature bytes.
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

    /// @notice The verifier contract used to check SLH-DSA signatures
    ///         (used for both main and bootstrap signers until ML-DSA
    ///         verifier is available).
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
        _initializeOwner(bytes32(uint256(1)), bytes32(uint256(1)));
    }

    /// @notice Initialises a freshly cloned proxy with its bootstrap
    ///         and initial main signer.
    ///
    /// @param bootstrapPubKey The raw bootstrap public key bytes.
    /// @param initialMainSigner The raw initial main signer public key bytes.
    function initialize(
        bytes calldata bootstrapPubKey,
        bytes calldata initialMainSigner
    ) external payable virtual {
        if (isInitialized()) revert Initialized();
        _initializeOwner(sha256(bootstrapPubKey), keccak256(initialMainSigner));
    }

    /// @notice Rotate the main signer to the next epoch. Can only be
    ///         called via `execute(self, ...)` which requires EntryPoint
    ///         validation (either main or bootstrap signer).
    ///
    /// @param newKeyIndex Must be `currentKeyIndex + 1`.
    /// @param newMainPubKey The raw public key of the new main signer.
    function rotateMainSigner(
        uint32 newKeyIndex,
        bytes calldata newMainPubKey
    ) external virtual onlyOwner {
        _rotateMainSigner(newKeyIndex, newMainPubKey);
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

        // State-mutating signature validation (OTS tracking for MAIN signer)
        return _validateUserOpSignature(userOpHash, userOp.signature) ? 0 : 1;
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

    /// @notice State-mutating signature validation for `validateUserOp`.
    ///         Handles OTS index consumption for MAIN signer path.
    function _validateUserOpSignature(bytes32 hash, bytes calldata signature)
        internal
        returns (bool)
    {
        PQSignatureWrapper memory w = abi.decode(signature, (PQSignatureWrapper));

        if (w.signerType == SignerType.MAIN) {
            // Validate main signer: check epoch, OTS, pubkey, then verify
            if (w.keyIndex != currentKeyIndex()) return false;
            if (w.otsIndex != currentOTSIndex()) return false;
            if (w.otsIndex > MAX_OTS_INDEX) return false;
            if (keccak256(w.pk) != currentMainPubKeyHash()) return false;
            if (w.signature.length != 17_088) return false;
            if (w.pk.length != 32) return false;

            if (!verifier.verify(w.pk, hash, w.signature)) return false;

            // Consume the OTS index atomically with validation success
            _consumeOTS(w.otsIndex);
            return true;

        } else if (w.signerType == SignerType.BOOTSTRAP) {
            // Bootstrap signer: stateless, no OTS tracking
            return _verifyBootstrapSig(hash, w);
        }

        return false;
    }

    /// @inheritdoc ERC1271
    ///
    /// @dev View-only signature validation for ERC-1271 (Safe/CowSwap).
    ///      Supports both MAIN (read-only key check, no OTS consumption)
    ///      and BOOTSTRAP signer paths. Since ERC-1271 is `view`, the
    ///      OTS index is NOT consumed here — ERC-1271 callers should use
    ///      pre-signature patterns (setPreSignature/signMessage) via
    ///      UserOps instead.
    function _isValidSignature(bytes32 hash, bytes calldata signature)
        internal
        view
        virtual
        override
        returns (bool)
    {
        PQSignatureWrapper memory w = abi.decode(signature, (PQSignatureWrapper));

        if (w.signerType == SignerType.MAIN) {
            // Read-only check: verify the sig is valid but don't consume OTS
            if (keccak256(w.pk) != currentMainPubKeyHash()) return false;
            if (w.signature.length != 17_088) return false;
            if (w.pk.length != 32) return false;
            return verifier.verify(w.pk, hash, w.signature);

        } else if (w.signerType == SignerType.BOOTSTRAP) {
            return _verifyBootstrapSig(hash, w);
        }

        return false;
    }

    /// @dev Shared bootstrap signature verification (view-safe).
    function _verifyBootstrapSig(bytes32 hash, PQSignatureWrapper memory w)
        internal
        view
        returns (bool)
    {
        if (sha256(w.pk) != bootstrapPubKeyHash()) return false;
        if (w.signature.length != 17_088) return false;
        if (w.pk.length != 32) return false;
        return verifier.verify(w.pk, hash, w.signature);
    }

    /// @inheritdoc UUPSUpgradeable
    function _authorizeUpgrade(address) internal view virtual override(UUPSUpgradeable) onlyOwner {}

    /// @inheritdoc ERC1271
    function _domainNameAndVersion() internal pure override(ERC1271) returns (string memory, string memory) {
        return ("PQ Coinbase Smart Wallet", "2");
    }
}
