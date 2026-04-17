// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IAccount} from "account-abstraction/interfaces/IAccount.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

import {PQOwnable} from "./PQOwnable.sol";
import {IJardinVerifier} from "./verifiers/IJardinVerifier.sol";
import {ISPHINCSVerifier} from "./verifiers/ISPHINCSVerifier.sol";

/// @title PQJardinWallet
///
/// @notice Pure post-quantum ERC-4337 v0.9 account with a single bootstrap
///         SPHINCS+C10 identity and on-chain-tracked JARDÍN FORS+C
///         sub-keys. Every UserOp carries one of two signature types:
///
///           * **Type 1** (`0x01`): bootstrap-key C10 signature + the raw
///             randomiser `r` and sub-key commitments `(subPkSeed,
///             subPkRoot)`. Validation side-effects: the wallet
///             increments `bootstrapUses` (capped at `MAX_BOOTSTRAP_USES
///             = 65,536` per chain) and records
///             `slots[sha256(r)] = sha256(subPkSeed || subPkRoot)`.
///
///           * **Type 2** (`0x02`): FORS+C signature against a previously
///             registered sub-key. `sig[1:33]` is `sha256(r)` — the
///             slotKey — and the wallet checks that the supplied
///             `(subPkSeed, subPkRoot)` matches what was registered.
///
///         The bootstrap C10 keypair is **immutable**: it is passed to the
///         constructor via the factory and cannot be changed. Seed
///         recovery produces the same bootstrap keys, so redeploying on a
///         lost device yields the same CREATE2 address.
///
///         Bootstrap-use accounting: the on-chain `bootstrapUses` counter
///         increments on every accepted Type 1. Once it reaches
///         `MAX_BOOTSTRAP_USES`, further Type 1s revert with
///         `"bootstrap exhausted"`; the currently-registered JARDÍN slot
///         can still sign Type 2 transactions until its own `Q_MAX`, but
///         no new slot rotations are possible on that chain.
///
///         No ECDSA. No classical signer. The whole multi-signer +
///         ZK clear-signing machinery from the pre-cutover wallet is gone.
///
/// @author PQSigner OS (post-C10 cutover)
contract PQJardinWallet is IAccount, PQOwnable {
    // ── Config (immutable) ──────────────────────────────────────────

    IEntryPoint private immutable _entryPoint;
    ISPHINCSVerifier public immutable c10Verifier;
    IJardinVerifier public immutable forscVerifier;

    /// @notice Bootstrap C10 public seed (N-masked: top 16 bytes populated,
    ///         bottom 16 zero). Immutable — rotating it would break the
    ///         recovery contract.
    bytes32 public immutable masterPkSeed;

    /// @notice Bootstrap C10 hypertree root commitment. Same N-mask layout.
    bytes32 public immutable masterPkRoot;

    // ── Signature types ────────────────────────────────────────────

    uint8 public constant TYPE_1_REGISTER = 0x01;
    uint8 public constant TYPE_2_COMPACT = 0x02;

    /// @dev 1 byte marker + 32 r + 16 subPkSeed + 16 subPkRoot + 4008 C10 sig.
    uint256 public constant TYPE_1_SIG_LEN = 1 + 32 + 16 + 16 + 4008;

    /// @dev 1 byte marker + 32 slotKey + 16 subPkSeed + 16 subPkRoot + 2452+q*16 FORS+C.
    uint256 public constant TYPE_2_HEADER_LEN = 1 + 32 + 16 + 16;
    uint256 public constant TYPE_2_MIN_SIG_LEN = 2452 + 16; // q=1
    uint256 public constant TYPE_2_MAX_SIG_LEN = 2452 + 95 * 16; // q=95

    // ── Bootstrap-use cap ───────────────────────────────────────────

    /// @notice Maximum number of Type 1 (bootstrap C10) signatures this
    ///         wallet will accept on this chain. Set deliberately below
    ///         the C10 hypertree's 2^18 = 262,144-signature capacity so
    ///         on-chain wear stays well inside the SPHINCS+ birthday-style
    ///         safety margin. Exceeding this cap bricks Type 1 on this
    ///         chain (the registered JARDÍN slot can still emit Type 2
    ///         until its own `Q_MAX`).
    uint256 public constant MAX_BOOTSTRAP_USES = 65_536;

    // ── Errors ────────────────────────────────────────────────────

    error NotFromEntryPoint();
    error InvalidSignatureType();
    error InvalidSignatureLength();
    error UnregisteredSlot();
    error BootstrapExhausted();

    /// @dev ERC-4337 v0.9 sentinel for failed validation.
    uint256 private constant SIG_VALIDATION_FAILED = 1;
    /// @dev ERC-4337 sentinel for successful validation.
    uint256 private constant SIG_VALIDATION_SUCCESS = 0;

    constructor(
        IEntryPoint ep,
        ISPHINCSVerifier c10,
        IJardinVerifier forsc,
        bytes32 masterPkSeed_,
        bytes32 masterPkRoot_
    ) {
        _entryPoint = ep;
        c10Verifier = c10;
        forscVerifier = forsc;
        masterPkSeed = masterPkSeed_;
        masterPkRoot = masterPkRoot_;
    }

    // ── IAccount ────────────────────────────────────────────────

    function entryPoint() public view returns (IEntryPoint) {
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

    /// @notice Execute an inner call, restricted to the EntryPoint.
    ///         Matches the canonical `execute(address,uint256,bytes)`
    ///         entrypoint used by the firmware's callData reconstruction.
    function execute(address target, uint256 value, bytes calldata data)
        external
        returns (bytes memory)
    {
        if (msg.sender != address(_entryPoint)) revert NotFromEntryPoint();
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(ret, 0x20), mload(ret))
            }
        }
        return ret;
    }

    /// @notice Revoke a registered JARDIN slot. Must be invoked by
    ///         `_entryPoint` — the UserOp carrying this calldata had
    ///         to pass Type 1 (master-C11) or Type 2 (registered
    ///         sub-key) validation, which is sufficient proof of
    ///         authority from the owner of the seed.
    ///
    ///         Typical recovery flow for a leaked sub-key:
    ///           1. User notices exfiltration.
    ///           2. Sign a Type 1 UserOp that registers a fresh sub-key
    ///              at a new slotKey.
    ///           3. Sign a Type 2 UserOp from the new slot whose
    ///              callData is `revokeJardinSlot(oldSlotKey)`.
    ///         After step 3, the leaked sub-key can no longer be used.
    /// @param slotKey Slot identifier to revoke.
    function revokeJardinSlot(bytes32 slotKey) external {
        if (msg.sender != address(_entryPoint)) revert NotFromEntryPoint();
        _revokeJardinSlot(slotKey);
    }

    /// @notice Batched execute for when a single UserOp must fan out
    ///         to multiple calls. Same EntryPoint-only gate.
    function executeBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata datas
    ) external {
        if (msg.sender != address(_entryPoint)) revert NotFromEntryPoint();
        uint256 n = targets.length;
        require(values.length == n && datas.length == n, "length mismatch");
        for (uint256 i = 0; i < n; ++i) {
            (bool ok, bytes memory ret) = targets[i].call{value: values[i]}(datas[i]);
            if (!ok) {
                assembly ("memory-safe") {
                    revert(add(ret, 0x20), mload(ret))
                }
            }
        }
    }

    // ── Signature validation ────────────────────────────────────

    /// @dev Dispatch on the first byte of `userOp.signature`:
    ///      0x01 → Type 1 (register sub-key via C11)
    ///      0x02 → Type 2 (FORS+C sign against registered sub-key)
    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal returns (uint256) {
        bytes calldata sig = userOp.signature;
        if (sig.length == 0) return SIG_VALIDATION_FAILED;

        uint8 sigType = uint8(sig[0]);

        if (sigType == TYPE_1_REGISTER) {
            if (sig.length != TYPE_1_SIG_LEN) return SIG_VALIDATION_FAILED;

            // Hard-cap on the number of Type 1 signatures this chain
            // will accept. Checked BEFORE calling the C10 verifier so a
            // griefing NS can't burn the wallet's gas attempting to
            // validate a sig that would be rejected anyway.
            //
            // Returning SIG_VALIDATION_FAILED (rather than reverting)
            // keeps the IAccount contract with bundler simulation: the
            // UserOp fails gracefully instead of tripping the EntryPoint's
            // banning heuristics.
            if (_getStorage().bootstrapUses >= MAX_BOOTSTRAP_USES) {
                return SIG_VALIDATION_FAILED;
            }

            bytes32 r = bytes32(sig[1:33]);
            bytes16 subSeed16 = bytes16(sig[33:49]);
            bytes16 subRoot16 = bytes16(sig[49:65]);
            bytes calldata c10Sig = sig[65:TYPE_1_SIG_LEN];

            // Verify the bootstrap C10 signature over userOpHash.
            try c10Verifier.verify(masterPkSeed, masterPkRoot, userOpHash, c10Sig)
                returns (bool ok)
            {
                if (!ok) return SIG_VALIDATION_FAILED;
            } catch {
                return SIG_VALIDATION_FAILED;
            }

            // HIGH-16 fix: `r == 0` must never be silently accepted.
            // A valid firmware-produced Type 1 always has r derived
            // from sha256(master || "jardin_r" || slot_index) which
            // has negligible probability of hitting zero, so this
            // branch is an attack path, not a legitimate flow. Reject.
            if (r == bytes32(0)) return SIG_VALIDATION_FAILED;

            // Register (or idempotently re-confirm) the slot.
            bytes32 slotKey = sha256(abi.encodePacked(r));
            bytes32 subVkHash = sha256(abi.encodePacked(subSeed16, subRoot16));
            _registerJardinSlot(slotKey, subVkHash);

            // Bump the bootstrap counter AFTER the slot registration so
            // an attacker who finds a way to make `_registerJardinSlot`
            // revert can't also burn the counter. The cap re-check here
            // is redundant with the pre-check above, but cheap — and the
            // pair forms a full pre/post invariant against any re-entry
            // into storage between the two points.
            _bumpBootstrapUses(MAX_BOOTSTRAP_USES);
            return SIG_VALIDATION_SUCCESS;
        }

        if (sigType == TYPE_2_COMPACT) {
            if (sig.length < TYPE_2_HEADER_LEN + TYPE_2_MIN_SIG_LEN) {
                return SIG_VALIDATION_FAILED;
            }
            if (sig.length > TYPE_2_HEADER_LEN + TYPE_2_MAX_SIG_LEN) {
                return SIG_VALIDATION_FAILED;
            }

            bytes32 slotKey = bytes32(sig[1:33]);
            bytes16 subSeed16 = bytes16(sig[33:49]);
            bytes16 subRoot16 = bytes16(sig[49:65]);

            // Slot must be registered and match the supplied sub-key.
            bytes32 subVkHash = sha256(abi.encodePacked(subSeed16, subRoot16));
            if (_getStorage().jardinSlots[slotKey] != subVkHash) {
                return SIG_VALIDATION_FAILED;
            }

            // The FORS+C verifier expects bytes32 arguments. Pad the
            // 16-byte N values into the high halves.
            bytes32 subPkSeed32;
            bytes32 subPkRoot32;
            assembly ("memory-safe") {
                subPkSeed32 := shl(128, shr(128, subSeed16))
                subPkRoot32 := shl(128, shr(128, subRoot16))
            }
            bytes calldata forscSig = sig[65:];
            try forscVerifier.verifyForsCUnbalanced(subPkSeed32, subPkRoot32, userOpHash, forscSig)
                returns (bool ok)
            {
                if (!ok) return SIG_VALIDATION_FAILED;
            } catch {
                return SIG_VALIDATION_FAILED;
            }
            return SIG_VALIDATION_SUCCESS;
        }

        // HIGH-15 fix: the IAccount spec says validateUserOp must
        // return `SIG_VALIDATION_FAILED` (1) on any signature problem
        // so bundlers can simulate with a placeholder signature
        // without reverting. The previous code was inconsistent —
        // empty sig returned FAILED, unknown sigType reverted. Align
        // both paths to a non-reverting failure return.
        return SIG_VALIDATION_FAILED;
    }

    receive() external payable {}
}
