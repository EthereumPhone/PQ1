// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IAccount} from "account-abstraction/interfaces/IAccount.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

import {PQMultiOwnable} from "./PQMultiOwnable.sol";
import {ISPHINCSVerifier} from "./verifiers/ISPHINCSVerifier.sol";

/// @title PQSmartWallet
///
/// @notice Pure post-quantum ERC-4337 v0.9 account. Forked from Coinbase
///         Smart Wallet's `CoinbaseSmartWallet` with every classical signer
///         path (EOA / ECDSA, WebAuthn / P-256) stripped out. The only
///         signature primitive is SPHINCS+C10 routed through the shared
///         `c10Verifier`.
///
///         Owners are stored in `PQMultiOwnable` as 64-byte blobs:
///         `pkSeed (32) || pkRoot (32)`. Both values use the N-mask layout
///         (top 16 bytes populated, bottom 16 zero) that the on-chain Yul
///         C10 verifier expects. A `SignatureWrapper` identifies which
///         owner index signed the UserOp.
///
///         Roles enforced in `_validateSignature`:
///           * **Bootstrap** (`ownerIndex == 0`) — immutable per wallet,
///             set at construction from `masterPkSeed || masterPkRoot`.
///             Only authorised to call `addOwnerBytes(bytes)`. Used to
///             rotate in new slot owners once the current slot hits its
///             cap. Bumps `bootstrapUses`, capped at `MAX_BOOTSTRAP_USES`.
///
///           * **Slot** (`ownerIndex >= 1`) — per-(chain, slot_index) C10
///             key derived from the seed. Only authorised to call
///             `execute`, `executeBatch`, or `removeOwnerAtIndex`. Bumps
///             `slotUses[ownerIndex]`, capped at `MAX_SLOT_USES`.
///
///         Index 0 (bootstrap) is always slot 0 of the factory. Slot
///         `slot_index = N` on chain X lives at `ownerIndex = N + 1`.
///
/// @author PQSigner OS
contract PQSmartWallet is IAccount, PQMultiOwnable {
    // ── Structs ─────────────────────────────────────────────────────

    /// @notice ABI-encoded wrapper around a C10 sig: `(ownerIndex, sig)`.
    struct SignatureWrapper {
        uint256 ownerIndex;
        bytes signatureData;
    }

    // ── Immutables (per-wallet) ─────────────────────────────────────

    IEntryPoint private immutable _entryPoint;
    ISPHINCSVerifier public immutable c10Verifier;

    /// @notice Bootstrap C10 public seed (N-mask layout).
    bytes32 public immutable masterPkSeed;

    /// @notice Bootstrap C10 hypertree root (N-mask layout).
    bytes32 public immutable masterPkRoot;

    /// @notice Address of the factory that CREATE2-deployed this wallet.
    ///         Only this address may call `initialize`.
    address public immutable factory;

    // ── Config constants ────────────────────────────────────────────

    /// @notice Exact length (bytes) of a SPHINCS+C10 signature.
    uint256 public constant C10_SIG_LEN = 4008;

    /// @notice Bootstrap (ownerIndex == 0) sig cap, per chain.
    uint256 public constant MAX_BOOTSTRAP_USES = 65_536;

    /// @notice Per-slot (ownerIndex >= 1) sig cap.
    uint256 public constant MAX_SLOT_USES = 65_536;

    /// @dev ERC-4337 v0.9 sentinel values for `validateUserOp`.
    uint256 private constant SIG_VALIDATION_FAILED = 1;
    uint256 private constant SIG_VALIDATION_SUCCESS = 0;

    // ── Errors ──────────────────────────────────────────────────────

    error NotFromEntryPoint();
    error NotFromSelf();
    error NotFromFactory();
    error AlreadyInitialized();
    error BootstrapCalldataMustBeAddOwner();
    error SlotCalldataNotAllowed();

    // ── Init ────────────────────────────────────────────────────────

    /// @dev Address dependency only on `(ep, c10, masterPkSeed, masterPkRoot)`.
    ///      Slot-0 is NOT a constructor arg — it is added by `initialize`
    ///      so the CREATE2 address stays identical across chains.
    constructor(
        IEntryPoint ep,
        ISPHINCSVerifier c10,
        bytes32 masterPkSeed_,
        bytes32 masterPkRoot_
    ) {
        _entryPoint = ep;
        c10Verifier = c10;
        masterPkSeed = masterPkSeed_;
        masterPkRoot = masterPkRoot_;
        factory = msg.sender;

        // Pre-register the bootstrap key at ownerIndex 0. The factory
        // will tack on slot-0 at ownerIndex 1 via `initialize` in the
        // same tx.
        bytes[] memory initOwners = new bytes[](1);
        initOwners[0] = abi.encodePacked(masterPkSeed_, masterPkRoot_);
        _initializeOwners(initOwners);
    }

    /// @notice Factory-only: append the per-chain slot-0 owner. Callable
    ///         once, directly after CREATE2, by the factory that already
    ///         verified the bootstrap C10 signature over the slot-0 bytes.
    function initialize(bytes calldata slot0OwnerBytes) external {
        if (msg.sender != factory) revert NotFromFactory();
        if (nextOwnerIndex() != 1) revert AlreadyInitialized();
        _addOwner(slot0OwnerBytes);
    }

    // ── IAccount ────────────────────────────────────────────────────

    function entryPoint() external view returns (IEntryPoint) {
        return _entryPoint;
    }

    /// @inheritdoc IAccount
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external override returns (uint256 validationData) {
        if (msg.sender != address(_entryPoint)) revert NotFromEntryPoint();

        validationData = _validateSignature(userOp, userOpHash);

        if (missingAccountFunds != 0) {
            (bool ok, ) = payable(msg.sender).call{value: missingAccountFunds}("");
            (ok); // EntryPoint handles failure.
        }
    }

    // ── Execution (slot-authorised) ─────────────────────────────────

    function execute(address target, uint256 value, bytes calldata data) external returns (bytes memory) {
        if (msg.sender != address(_entryPoint)) revert NotFromEntryPoint();
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(ret, 0x20), mload(ret))
            }
        }
        return ret;
    }

    function executeBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata datas
    ) external {
        if (msg.sender != address(_entryPoint)) revert NotFromEntryPoint();
        uint256 n = targets.length;
        require(values.length == n && datas.length == n, "length mismatch");
        for (uint256 i; i < n; ++i) {
            (bool ok, bytes memory ret) = targets[i].call{value: values[i]}(datas[i]);
            if (!ok) {
                assembly ("memory-safe") {
                    revert(add(ret, 0x20), mload(ret))
                }
            }
        }
    }

    // ── Owner management (self-only, i.e. via a validated UserOp) ───

    /// @notice Add a new slot owner at the next index. Only callable by
    ///         `this` — i.e. via a UserOp whose signature was validated
    ///         against `ownerIndex == 0` (bootstrap).
    function addOwnerBytes(bytes calldata newOwner) external {
        if (msg.sender != address(this)) revert NotFromSelf();
        _addOwner(newOwner);
    }

    /// @notice Remove a slot owner. Only callable by `this` — i.e. via a
    ///         UserOp whose signature was validated against `ownerIndex >= 1`.
    ///         Refuses to remove index 0 (see `PQMultiOwnable`).
    function removeOwnerAtIndex(uint256 index, bytes calldata owner) external {
        if (msg.sender != address(this)) revert NotFromSelf();
        _removeOwnerAtIndex(index, owner);
    }

    // ── Signature validation ────────────────────────────────────────

    /// @notice Compute the SHA-256 digest that the firmware signs.
    ///
    ///         The EntryPoint-supplied `userOpHash` is keccak256-based, which
    ///         would force the STM32U585 to fall back to a slow software
    ///         keccak implementation (there is no keccak accelerator on the
    ///         chip, only SHA-256 and SAES). By re-hashing the UserOp fields
    ///         under SHA-256 and signing THAT digest, firmware stays on the
    ///         fast path end-to-end. The digest still covers every field
    ///         that affects transaction semantics (sender, nonce,
    ///         initCode, callData, gas fields, paymaster, entryPoint, chainId),
    ///         so replay / re-binding attacks are identical to the standard
    ///         userOpHash model.
    function sphincsDigest(PackedUserOperation calldata userOp) public view returns (bytes32) {
        return sha256(
            abi.encodePacked(
                userOp.sender,
                userOp.nonce,
                sha256(userOp.initCode),
                sha256(userOp.callData),
                userOp.accountGasLimits,
                userOp.preVerificationGas,
                userOp.gasFees,
                sha256(userOp.paymasterAndData),
                address(_entryPoint),
                block.chainid
            )
        );
    }

    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 /* userOpHash — keccak-based, ignored in favour of sphincsDigest */
    ) internal returns (uint256) {
        bytes calldata sig = userOp.signature;

        // ── Manual parse of `abi.encode(uint256 ownerIndex, bytes sig)` ──
        //
        //   [0..32)    ownerIndex
        //   [32..64)   offset to bytes (MUST be 0x40)
        //   [64..96)   inner sig length (MUST be C10_SIG_LEN)
        //   [96..96+C10_SIG_LEN) inner C10 signature bytes
        //
        // Abi-decoding inside a try/catch turns out to consume ~40 KB of
        // memory on a 4008-byte payload (each decode materialises the
        // inner bytes twice), which trips the EVM's `msize` limit on
        // some bundler sims. Parsing inline sidesteps that and lets us
        // reject malformed sigs with SIG_VALIDATION_FAILED instead of a
        // revert.
        // ABI encoding pads the inner `bytes` up to a 32-byte boundary.
        uint256 paddedInner = ((C10_SIG_LEN + 31) / 32) * 32;
        uint256 expectedLen = 96 + paddedInner;
        if (sig.length != expectedLen) return SIG_VALIDATION_FAILED;

        uint256 ownerIndex;
        uint256 offsetField;
        uint256 innerLen;
        assembly ("memory-safe") {
            ownerIndex := calldataload(sig.offset)
            offsetField := calldataload(add(sig.offset, 32))
            innerLen := calldataload(add(sig.offset, 64))
        }
        if (offsetField != 0x40) return SIG_VALIDATION_FAILED;
        if (innerLen != C10_SIG_LEN) return SIG_VALIDATION_FAILED;

        bytes calldata innerSig = sig[96:96 + C10_SIG_LEN];

        bytes memory ownerBytes = ownerAtIndex(ownerIndex);
        if (ownerBytes.length != OWNER_BYTES_LEN) return SIG_VALIDATION_FAILED;

        bytes32 pkSeed;
        bytes32 pkRoot;
        assembly ("memory-safe") {
            pkSeed := mload(add(ownerBytes, 32))
            pkRoot := mload(add(ownerBytes, 64))
        }

        // ── Role split ──────────────────────────────────────────────
        bytes4 selector = _selectorOf(userOp.callData);
        if (ownerIndex == 0) {
            if (selector != this.addOwnerBytes.selector) {
                return SIG_VALIDATION_FAILED;
            }
            if (_getStorage().bootstrapUses >= MAX_BOOTSTRAP_USES) {
                return SIG_VALIDATION_FAILED;
            }
        } else {
            if (!_isSlotAllowedSelector(selector)) {
                return SIG_VALIDATION_FAILED;
            }
            if (_getStorage().slotUses[ownerIndex] >= MAX_SLOT_USES) {
                return SIG_VALIDATION_FAILED;
            }
        }

        // ── C10 verify against the SHA-256 sphincs digest ──────────
        bytes32 digest = sphincsDigest(userOp);
        try c10Verifier.verify(pkSeed, pkRoot, digest, innerSig) returns (bool ok) {
            if (!ok) return SIG_VALIDATION_FAILED;
        } catch {
            return SIG_VALIDATION_FAILED;
        }

        // ── Counter bumps after successful verify ───────────────────
        if (ownerIndex == 0) {
            _bumpBootstrapUses(MAX_BOOTSTRAP_USES);
        } else {
            _bumpSlotUses(ownerIndex, MAX_SLOT_USES);
        }
        return SIG_VALIDATION_SUCCESS;
    }

    /// @dev Read the first 4 bytes of `callData` as a selector. Returns
    ///      `0x00000000` when `callData` is shorter than 4 bytes.
    function _selectorOf(bytes calldata callData) private pure returns (bytes4 s) {
        if (callData.length < 4) return bytes4(0);
        assembly {
            s := calldataload(callData.offset)
        }
    }

    function _isSlotAllowedSelector(bytes4 s) private pure returns (bool) {
        return
            s == this.execute.selector ||
            s == this.executeBatch.selector ||
            s == this.removeOwnerAtIndex.selector;
    }

    receive() external payable {}
}
