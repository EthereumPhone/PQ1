//! pqsigner-proto — single source of truth for every protocol-level
//! constant, byte layout, and enum that crosses a TrustZone, on-chain,
//! or USB boundary.
//!
//! See `Cargo.toml` for the rationale and Phase-3 reference. The
//! `apdu_framing` and `db_format` modules stay in `sphincs-tz-shared`
//! because they are *implementation* (USB parsing + ERC-20 Merkle DB),
//! not *protocol* — `pqsigner-proto` is constants and enums only,
//! deliberately import-free so it can be the codegen source for the
//! Solidity `PqsignerProto` library in Phase 4.

#![no_std]

// ---------------------------------------------------------------------------
// SPHINCS+C10 (SHA-256-based) sizes — bootstrap (master) identity
// ---------------------------------------------------------------------------

pub const SIGNING_KEY_LEN: usize = 48; // sk_seed(32) + pk_seed(16)
pub const VERIFYING_KEY_LEN: usize = 32; // pk_seed(16) + pk_root(16)
pub const SIGNATURE_LEN: usize = 4_008;
pub const PIN_LEN: usize = 8;
pub const TX_HASH_LEN: usize = 32;
pub const MAX_ATTEMPTS: u8 = 10;

/// Maximum size of an unsigned EIP-1559 transaction envelope passed across
/// the gateway. The secure world copies the bytes into its own stack buffer
/// before parsing, so this also bounds that buffer.
pub const MAX_TX_LEN: usize = 4096;

// ---------------------------------------------------------------------------
// ZK clear signing constants (must match ZKlarity circuit parameters)
// ---------------------------------------------------------------------------

/// Maximum calldata size (ZKlarity circuit MAX_CALLDATA = 164 bytes).
/// This is the raw smart contract calldata (selector + ABI-encoded params).
pub const ZK_MAX_CALLDATA: usize = 164;

/// Human-readable string length (ZKlarity circuit STRING_LEN = 64 bytes).
pub const ZK_STRING_LEN: usize = 64;

/// Groth16 proof size: π.A (96) + π.B (192) + π.C (96) = 384 bytes.
pub const ZK_PROOF_LEN: usize = 384;

// ---------------------------------------------------------------------------
// Non-secure memory boundaries — used by secure world to validate NS pointers.
// ---------------------------------------------------------------------------

#[cfg(not(feature = "stm32u585"))]
mod mem_layout {
    /// mps2-an505: SSRAM-1 NS alias, offset 128KB
    pub const NS_SRAM_BASE: u32 = 0x2802_0000;
    pub const NS_SRAM_END: u32 = 0x2822_0000;
    /// mps2-an505: SSRAM-0 NS alias starting at offset 2 MB
    pub const NS_FLASH_BASE: u32 = 0x0020_0000;
    pub const NS_FLASH_END: u32 = 0x0040_0000;
    /// Shared-memory gateway mailbox (end of NS SRAM)
    pub const SHARED_MAILBOX_BASE: u32 = 0x2802_FF00;
    pub const SHARED_MAILBOX_END: u32 = 0x2802_FF18;
}

#[cfg(feature = "stm32u585")]
mod mem_layout {
    /// STM32U585: SRAM2 NS alias (64 KB)
    pub const NS_SRAM_BASE: u32 = 0x2003_0000;
    pub const NS_SRAM_END: u32 = 0x2004_0000;
    /// STM32U585: flash bank 2 NS alias (1 MB)
    pub const NS_FLASH_BASE: u32 = 0x0810_0000;
    pub const NS_FLASH_END: u32 = 0x0820_0000;
    /// Shared-memory gateway mailbox (end of SRAM2)
    pub const SHARED_MAILBOX_BASE: u32 = 0x2003_FF00;
    pub const SHARED_MAILBOX_END: u32 = 0x2003_FF18;
}

pub use mem_layout::*;

// ---------------------------------------------------------------------------
// Gateway command IDs
//
// Numeric ranges have grown organically; the documented blocks below
// are the convention going forward. New commands must claim a CMD ID
// in the range matching their concern. The `const _: () = { ... }`
// collision check at the bottom of this file catches accidental
// duplicates at compile time.
//
//   1..=13   core lifecycle (unlock, lock, status, deprecated v1 stubs)
//  14..=15   wallet identity (address, init-code preview)
//  16..=18   off-chain (EIP-1271) signing + status + sync
//  20..=24   firmware update state machine
//  30       UserOp batch signing
// 200..=    test/diagnostic (must be `mode != production`)
// ---------------------------------------------------------------------------

pub const CMD_NONE: u32 = 0;
pub const CMD_GET_REMAINING: u32 = 1;
pub const CMD_REQUEST_UNLOCK: u32 = 2;
pub const CMD_GET_PUBKEY: u32 = 3;
// CMD 4 reserved (was CMD_SIGN in v1)
pub const CMD_CLEAR_SIGN: u32 = 5;
// CMD 6 reserved (was CMD_CLEAR_SIGN_MSG — standalone EIP-712 typed-data
// signing; the only EIP-712 consumer is now the v3 trailer cross-check
// inside CMD_SIGN_USEROP, so the standalone path was removed).

/// CMD_SIGN_USEROP — ERC-4337 Account Abstraction UserOperation signing
/// against **EntryPoint v0.6**.
///
/// The non-secure world hands the secure world an inner EIP-1559 envelope
/// (the "intent" tx) plus the AA wrapper parameters that are needed to
/// reconstruct an EntryPoint v0.6 `getUserOpHash`. The secure world:
///
///   1. Re-builds the canonical `execute(target, value, data)` callData
///      from the inner tx (so a hostile NS cannot replace the callData
///      with something the user did not authorise via the trusted UI).
///   2. Computes the EntryPoint v0.6 `userOpHash` natively from the
///      caller-supplied `(sender, nonce, gas params, init code hash,
///      paymaster hash, entry point, chain id)` plus the reconstructed
///      callData hash.
///   3. Displays the *inner* EIP-1559 transaction on the trusted UI
///      (so the user sees the actual money flow, not the AA wrapper).
///   4. Signs `userOpHash` with SLH-DSA-SHA2-128f.
///
/// ## Mode byte (byte 0 of payload)
///
/// The first byte selects the deployment mode:
///
///   * `0` — deployed, no ERC-20 bundle
///   * `1` — deployed, with ERC-20 bundle
///   * `2` — **not deployed**: firmware generates initCode automatically
///           (bootstrap sig + factory calldata), no ERC-20 bundle
///   * `3` — **not deployed** + with ERC-20 bundle
///
/// When mode ≥ 2 (not-deployed), the firmware:
///   - Derives the bootstrap keypair internally
///   - Derives the main keypair for the AA chain_id + key_index
///   - Signs `keccak256("PQWALLET_INIT_V1" || mainPkSeed || mainPkRoot)`
///     with the bootstrap key to produce the factory authorization sig
///   - Builds the full initCode: `factory_address(20) || abi.encodeCall(
///     createAccount, (bPkSeed, bPkRoot, mPkSeed, mPkRoot, bootstrapSig))`
///   - Computes `keccak256(initCode)` and uses it as init_code_hash
///     (the host-supplied init_code_hash field is ignored)
///
/// ## Payload wire format (all integers big-endian unless noted)
///
/// ```text
///   [  0]                       mode u8              (0/1/2/3)
///   [  1.. 21)  sender                              (20 bytes)
///   [ 21.. 41)  entry_point                         (20 bytes)
///   [ 41.. 49)  aa_chain_id     u64 BE              (chainid hashed by EntryPoint)
///   [ 49.. 81)  nonce           u256 BE
///   [ 81..113)  call_gas_limit          u256 BE
///   [113..145)  verification_gas_limit  u256 BE
///   [145..177)  pre_verification_gas    u256 BE
///   [177..209)  max_fee_per_gas         u256 BE
///   [209..241)  max_priority_fee_per_gas u256 BE
///   [241..273)  init_code_hash          32 bytes (keccak256; ignored when mode≥2)
///   [273..305)  paymaster_and_data_hash 32 bytes (keccak256)
///   [305..309)  tx_len u32 LE
///   [309..309+tx_len)  inner unsigned EIP-1559 envelope
///   [309+tx_len..]     optional [bundle_len u32 LE][ERC20 metadata bundle]
/// ```
///
/// ## Response format
///
/// On success the secure world writes a structured UserOp response:
///
/// ```text
///   [0..4)           init_code_len   u32 BE  (0 when deployed)
///   [4..4+N)         initCode        N bytes (absent when deployed)
///   [4+N..8+N)       call_data_len   u32 BE
///   [8+N..8+N+M)     callData        M bytes (reconstructed execute(...))
///   [8+N+M..)        PQSignatureWrapper (WRAPPER_TOTAL_LEN bytes)
/// ```
pub const CMD_SIGN_USEROP: u32 = 7;

/// CMD_GET_BOOTSTRAP_PUBKEY — return the 32-byte bootstrap signer's
/// verifying key (derived from the global BIP-85 bootstrap path).
///
/// The bootstrap signer is a stateless PQ key used only for administrative
/// operations (initial deployment on new chains, emergency rotation).
///
/// Args: out_ptr, out_len (same as CMD_GET_PUBKEY).
pub const CMD_GET_BOOTSTRAP_PUBKEY: u32 = 8;

/// CMD_GET_MAIN_PUBKEY — return the 32-byte main signer's verifying key
/// for a specific chain and key epoch.
///
/// Args: out_ptr, out_len encoded in arg1/arg2; chain_id (u64 BE) and
/// key_index (u32 BE) are passed in the payload buffer at arg0.
///
/// Payload at arg0:
///   [0..8)   chain_id   (u64 BE)
///   [8..12)  key_index  (u32 BE)
///
/// On success the secure world writes the 32-byte verifying key to the
/// NS output buffer.
pub const CMD_GET_MAIN_PUBKEY: u32 = 9;

/// CMD_SIGN_BOOTSTRAP — **DEPRECATED**: bootstrap signing is now handled
/// automatically by CMD_SIGN_USEROP when mode byte ≥ 2 (not-deployed).
///
/// Kept for backward compatibility. New code should use CMD_SIGN_USEROP
/// with mode byte = 2 or 3 instead.
///
/// Legacy payload wire format:
///   [0..32)  message hash (the bytes32 to sign)
///
/// On success the secure world writes a 17,088-byte SLH-DSA signature
/// into the NS output buffer.
pub const CMD_SIGN_BOOTSTRAP: u32 = 10;

// CMDs 15/16/17 — the legacy slot-management commands are retired. With the
// all-C10 cutover, the firmware is stateless for slot selection: the
// companion drives `(chain_id, slot_index, flags)` per call via
// `CMD_SIGN_USEROP`, so no separate slot-info / registration commands exist.

/// CMD_IS_UNLOCKED — returns 1 if PIN-verified this session, 0 otherwise.
pub const CMD_IS_UNLOCKED: u32 = 11;

/// CMD_LOCK — zeroize all cached secrets and mark device as locked.
pub const CMD_LOCK: u32 = 12;

/// CMD_SIGN_MESSAGE — EIP-191 personal_sign. Computes
/// `keccak256("\x19Ethereum Signed Message:\n" || len || msg)`, displays
/// the message on the trusted UI, and signs the digest with SLH-DSA.
///
/// Payload wire format:
///   [0..4)    key_index   u32 BE
///   [4..8)    ots_index   u32 BE
///   [8..16)   chain_id    u64 BE  (for display only)
///   [16..18)  msg_len     u16 BE
///   [18..18+msg_len)  message bytes
///
/// On success the secure world writes a PQSignatureWrapper
/// (WRAPPER_TOTAL_LEN bytes) into the NS output buffer.
pub const CMD_SIGN_MESSAGE: u32 = 13;

/// CMD_GET_WALLET_ADDRESS — compute the CREATE2-predicted wallet
/// address from the bootstrap C10 pubkey + the firmware-embedded
/// `PQ_SMART_WALLET_FACTORY` / `PROXY_INIT_CODE_HASH` constants.
///
/// Requires an unlocked device (the bootstrap C10 keygen reads the
/// dual-SE entropy); first call after unlock takes <1 s, subsequent
/// calls reuse the cached bootstrap pubkey and return in <1 ms.
///
/// No input payload — everything the formula needs is either in
/// secure-world state (masterPkSeed / masterPkRoot) or a build-time
/// constant (factory / proxy init-code hash).
///
/// On success the secure world writes the 20-byte address to the NS
/// output buffer at `arg0`.
pub const CMD_GET_WALLET_ADDRESS: u32 = 14;

/// CMD_GET_INIT_CODE — return the 4280-byte ERC-4337 `initCode` that
/// `CMD_SIGN_USEROP` would emit when first-deploying the wallet for
/// `(account_index, chain_id)`.
///
/// The companion needs this for `eth_estimateUserOperationGas` on a
/// not-yet-deployed account: without a real SPHINCS+C10 factory
/// signature in the placeholder, the factory's on-chain
/// `createAccount` reverts during simulation (AA13), gas can't be
/// estimated, and the companion has to fall back to hard-coded
/// ceilings. Calling `CMD_GET_INIT_CODE` once after unlock yields a
/// valid initCode the companion can cache for every estimation on
/// that `(account_index, chain_id)` pair until the wallet is
/// actually deployed on-chain.
///
/// The signed message is
/// `sha256("pqwallet-factory-add-slot" || chain_id(8 BE) ||
/// slot0PkSeed(32) || slot0PkRoot(32))` — identical to what the
/// deploy path of `CMD_SIGN_USEROP` already signs. Because SPHINCS+
/// is stateless and the message depends only on
/// `(chain_id, slot0_keys)`, the result is safely reusable across
/// retries, re-estimates, and the final signed UserOp submission.
///
/// Requires an unlocked device. No OLED confirmation: this command
/// only pre-computes bytes the user will confirm later when they
/// approve the actual transaction in `CMD_SIGN_USEROP`.
///
/// Wire layout:
///   * `arg0` — NS read buffer (12 bytes):
///       [0..4)  `account_index` (u32 BE, 0..=255)
///       [4..12) `chain_id`      (u64 BE)
///   * `arg1` — NS write buffer, `PQ_INIT_CODE_LEN` bytes.
///   * `arg2` — input length, must equal 12.
pub const CMD_GET_INIT_CODE: u32 = 15;

/// CMD_SIGN_OFFCHAIN — produce a SPHINCS+C10 signature over an
/// EIP-1271 (off-chain) signing request.
///
/// Two signing modes, selected by the `kind` byte:
///
///   * **`OFFCHAIN_KIND_PERSONAL_SIGN` (1)** — companion sends the raw
///     message bytes that the dapp passed to `personal_sign` /
///     `eth_sign`. The firmware:
///       1. Computes `prefixed = keccak256("\x19Ethereum Signed
///          Message:\n" || itoa(len) || msg)` — the hash the dapp
///          would expose as `isValidSignature(hash, sig)`'s first arg.
///       2. Wraps that into Solady's nested EIP-712 (PersonalSign
///          workflow): `final = keccak256("\x19\x01" || domainSep ||
///          keccak256(_PERSONAL_SIGN_TYPEHASH || prefixed))` where the
///          domain separator is computed against this account's CREATE2
///          wallet address, the supplied `chain_id`, and the firmware-
///          baked `(name="PQSmartWallet", version="1")` constants.
///       3. Renders the message as printable ASCII on the trusted
///          display so the user can compare it against the dapp.
///       4. Signs `final` with the slot C10 key.
///     This is the mode that gives the user actual visibility into
///     what they're approving.
///
///   * **`OFFCHAIN_KIND_RAW32` (0)** — companion sends a 32-byte hash
///     directly (e.g. an EIP-712 typed-data digest the firmware can't
///     break apart). The firmware signs it as-is and renders the hash
///     in hex. Used as a fallback for cases where the message text is
///     unavailable.
///
/// In both modes, on-chain verification works because Solady's
/// `_erc1271IsValidSignatureViaNestedEIP712` first attempts the
/// TypedDataSign branch and falls back to PersonalSign when no
/// appended data is present in the signature — our companion-supplied
/// signature wrapper carries no appended data, so the wallet always
/// takes the PersonalSign path.
///
/// Combined budget: the slot's total signing budget is shared between
/// on-chain Type 2 sigs (`slotUses[i]`) and off-chain sigs
/// (`offchainSigCount[i]`). Firmware refuses if pre-sign budget would
/// exceed `MAX_SLOT_USES`. It also refuses if the per-slot
/// "unpublished" gap (sigs since the last UserOp) would exceed
/// `MAX_OFFCHAIN_GAP`, forcing the user to publish a UserOp first.
///
/// Recovery: a fresh-from-seed firmware has no flash record of slots
/// signed by a previous device. Firmware refuses `CMD_SIGN_OFFCHAIN`
/// for any slot it has no registered-flag for, and the companion
/// resolves this by registering a new slot index (Type 1 via
/// `CMD_SIGN_USEROP` with `FLAG_REGISTER_SLOT`) before retrying.
///
/// EIP-6492 (Signature Validation for Predeploy Contracts):
///
/// The companion sets `OFFCHAIN_FLAG_ACCOUNT_DEPLOYED` in the new
/// `flags` byte (offset 16) when the smart-wallet contract has already
/// been deployed at its CREATE2 address. When that flag is **clear**,
/// the firmware emits an [ERC-6492][eip6492]-wrapped signature that
/// carries the factory address + factory calldata in the sig itself, so
/// any EIP-6492-aware verifier (Solady `SignatureCheckerLib`, Ambire
/// `UniversalSigValidator`, viem `verifyMessage`, …) can deploy the
/// wallet and verify the inner EIP-1271 sig in a single `eth_call` —
/// before the user has ever paid for the deploy. Constraints:
///   * `slot_index` MUST be `0` when the deployed flag is clear: the
///     factory's `createAccount` only seeds bootstrap (ownerIndex 0) +
///     slot 0 (ownerIndex 1), so 6492-wrapping any other slot is
///     unverifiable.
///   * On a never-used wallet, slot 0 is unregistered. The 6492 path
///     auto-registers it (`local_offchain=0, last_userop=0`) before
///     bumping. Subsequent calls find it registered and follow the
///     normal gap/cap logic.
///
/// [eip6492]: https://eips.ethereum.org/EIPS/eip-6492
///
/// Wire layout:
///   * `arg0` — NS read buffer (`SIGN_OFFCHAIN_HEADER_LEN +
///     payload_len` bytes, capped at `SIGN_OFFCHAIN_INPUT_MAX_LEN`):
///       [ 0.. 1)  account_index  (u8)
///       [ 1.. 9)  chain_id       (u64 BE)
///       [ 9..13)  slot_index     (u32 BE)
///       [13..14)  kind           (u8: 0=raw32, 1=personal_sign)
///       [14..16)  payload_len    (u16 BE)
///       [16..17)  flags          (u8 — bit 0 = `OFFCHAIN_FLAG_ACCOUNT_DEPLOYED`;
///                                 other bits MUST be zero)
///       [17..)    payload (`payload_len` bytes — 32 for raw32, the
///                 raw message for personal_sign)
///   * `arg1` — NS write buffer. Length depends on the deployed flag:
///       - flag set (deployed): `SIGN_OFFCHAIN_OUTPUT_LEN` = 4016 bytes:
///           [ 0.. 8)  new_local_offchain_count (u64 BE, post-bump)
///           [ 8..4016) C10 sig (4008 bytes)
///       - flag clear (counterfactual): `SIGN_OFFCHAIN_OUTPUT_LEN_6492`
///         = 8616 bytes:
///           [ 0.. 8)            new_local_offchain_count (u64 BE)
///           [ 8.. 8+EIP6492_BLOB_LEN) ERC-6492 wrapped sig:
///             `abi.encode(address factory, bytes factoryCalldata,
///              bytes signatureWrapper) || EIP6492_MAGIC` where
///             `signatureWrapper = abi.encode(uint256 ownerIndex,
///              bytes c10Sig)` with `ownerIndex = slot_index + 1 = 1`.
///   * `arg2` — input length (must equal
///     `SIGN_OFFCHAIN_HEADER_LEN + payload_len`).
pub const CMD_SIGN_OFFCHAIN: u32 = 16;

/// CMD_SIGN_USEROP_BATCH — atomic multi-call UserOp signing.
///
/// Like [`CMD_SIGN_USEROP`] but the inner-tx block is replaced by a
/// `batch_count u8` followed by N `(to, value, data)` blocks. The
/// secure world:
///   1. Renders + confirms each inner tx independently on the trusted
///      UI (clear-signing preserved per-tx, plus a final "sign batch?"
///      gate).
///   2. Builds the canonical
///      `executeBatchWithOffchainCount(ownerIndex, newOffchainCount,
///      address[], uint256[], bytes[])` calldata.
///   3. Hashes the resulting UserOp under SHA-256 and signs as today.
///
/// Output bundle layout is byte-identical to [`CMD_SIGN_USEROP`]'s,
/// so the companion's transport / parser stays the same. Only the
/// resulting `callData` it submits via the EntryPoint is different
/// (`executeBatchWithOffchainCount` instead of
/// `executeWithOffchainCount`).
///
/// ## Wire format (all integers big-endian unless noted)
///
/// ```text
///   [  0..  8)  chain_id   u64 BE
///   [  8.. 12)  flags      u32 BE   (same layout as CMD_SIGN_USEROP)
///   [ 12.. 32)  sender              20 B
///   [ 32.. 52)  entry_point         20 B
///   [ 52.. 84)  nonce               u256 BE
///   [ 84..116)  call_gas_limit      u256 BE
///   [116..148)  verification_gas    u256 BE
///   [148..180)  pre_verification    u256 BE
///   [180..212)  max_fee_per_gas     u256 BE
///   [212..244)  max_prio_per_gas    u256 BE
///   [244..276)  paymaster_data_hash sha256 (SHA256_EMPTY when absent)
///   [276..277)  batch_count u8 (1..=MAX_BATCH_TXS)
///   [277..   )  repeat batch_count times:
///                 [20]                to_address
///                 [32]                value (u256 BE)
///                 [ 2]                data_len (u16 BE, ≤ MAX_TX_LEN)
///                 [data_len]          data
/// ```
///
/// No trailers. Batch txs render through the basic value/erc20-shape/
/// blind-sign ladder; ZK / Safe / ERC-20-metadata trailers are
/// single-tx-only by construction.
pub const CMD_SIGN_USEROP_BATCH: u32 = 30;

/// CMD_OFFCHAIN_STATUS — read per-slot off-chain signing state.
///
/// The companion uses this for two things:
///   1. UI hint: "X off-chain sigs remaining before forced UserOp"
///      where X = `MAX_OFFCHAIN_GAP - (local - last_userop)`.
///   2. Recovery probe: the `registered` byte flips to 0 after a
///      seed-restore on a device that has never signed Type 1 for
///      this slot, telling the companion to nudge the user toward
///      registering a fresh slot.
///
/// Wire layout:
///   * `arg0` — NS read buffer (`OFFCHAIN_STATUS_INPUT_LEN` bytes):
///       [ 0.. 1)  account_index  (u8)
///       [ 1.. 9)  chain_id       (u64 BE)
///       [ 9..13)  slot_index     (u32 BE)
///   * `arg1` — NS write buffer (`OFFCHAIN_STATUS_OUTPUT_LEN` bytes):
///       [ 0.. 8)  local_offchain_count (u64 BE)
///       [ 8..16)  last_userop_count    (u64 BE)
///       [16..17)  registered           (u8)
///       [17..24)  reserved
///   * `arg2` — input length (must equal `OFFCHAIN_STATUS_INPUT_LEN`).
pub const CMD_OFFCHAIN_STATUS: u32 = 17;

/// CMD_OFFCHAIN_SYNC — bump the firmware's `last_userop_count` for a
/// (account_index, chain_id, slot_index) tuple to at least `target`.
/// Idempotent and "set if greater" — never reduces. Used by the
/// companion after a firmware reflash (which wipes secure-flash
/// counters) so the next `CMD_SIGN_USEROP` emits a `newOffchainCount`
/// that's monotonic w.r.t. the on-chain `offchainSigCount[ownerIndex]`.
///
/// Wire layout:
///   * `arg0` — NS read buffer (`OFFCHAIN_SYNC_INPUT_LEN` bytes)
///   * `arg2` — input length (must equal `OFFCHAIN_SYNC_INPUT_LEN`)
///   * arg1 unused — response is SW only.
pub const CMD_OFFCHAIN_SYNC: u32 = 18;

// ---------------------------------------------------------------------------
// Firmware-update gateway commands
// ---------------------------------------------------------------------------

/// CMD_FW_BEGIN — initiate a firmware-update streaming session.
///
/// Payload at `arg0` is the 8 KB manifest page (see `fw_manifest::MANIFEST_SIZE`).
/// Secure world:
///   1. Rejects if `pin_verified == false` (update requires unlock).
///   2. Runs the full verify chain (magic, CRC, digest, vendor fpr,
///      C10 signature, rollback floor) on the supplied manifest.
///   3. Determines the inactive A/B slot.
///   4. Erases the inactive slot's secure + NS pages + target
///      manifest page.
///   5. Seeds an in-SRAM streaming context keyed on
///      `(inactive_slot, expected_s_len, expected_ns_len, running_hashes)`.
///   6. Resets the idle activity timer (update is user-consented).
///
/// Returns `NscStatus::Ok` on success, or a descriptive error.
pub const CMD_FW_BEGIN: u32 = 20;

/// CMD_FW_CHUNK — stream one image chunk into the inactive slot.
///
/// Payload at `arg0` is:
/// ```text
/// offset  size  field
///    0     4   chunk_offset  u32 BE (bytes within the target image)
///    4     1   image_kind    0 = secure, 1 = nonsecure
///    5     1   reserved
///    6     2   chunk_len     u16 BE, 1..=FW_MAX_CHUNK
///    8     N   chunk data
/// ```
/// The offset must monotonically increase within a given `image_kind`.
/// Secure world writes the data into the inactive slot's flash, updates
/// the running SHA-256, and returns `Ok`. Idle timer is NOT reset by
/// chunks (the BEGIN/COMMIT button presses frame the update window).
pub const CMD_FW_CHUNK: u32 = 21;

/// CMD_FW_COMMIT — finalise the staged update.
///
/// No payload (arg0 is ignored; the already-staged image + manifest in
/// flash is the input). Secure world:
///   1. Re-reads the inactive slot and re-hashes both images.
///   2. Compares against `manifest.secure_hash` + `manifest.nonsecure_hash`.
///   3. Verifies the C10 signature one more time.
///   4. Displays the new measurement (8 BIP-39 words) + "confirm
///      update?" prompt on the OLED.
///   5. On user confirm: writes the manifest page (with
///      `try_once = TRIED`), bumps the OTP rollback floor, writes the
///      boot-state page pointing at the new slot, and triggers a
///      system reset.
///   6. On cancel: rolls back (manifest + boot state untouched); the
///      inactive slot stays erased.
pub const CMD_FW_COMMIT: u32 = 22;

/// CMD_FW_STATUS — read update progress.
///
/// Returns `[state:u8 | received_s:u32 BE | received_ns:u32 BE]` into
/// the output buffer. Useful for the companion app's progress bar.
pub const CMD_FW_STATUS: u32 = 23;

/// CMD_FW_ABORT — discard a partial update.
///
/// Clears the in-SRAM streaming context. The inactive slot stays
/// erased (no-op rollback) — no harm done; a future `CMD_FW_BEGIN`
/// can start fresh.
pub const CMD_FW_ABORT: u32 = 24;

/// CMD_TEST_PIN_LOCKOUT — non-interactive PIN-lockout verification.
///
/// Test-only gateway command, compiled out unless `e2e-test` is set on
/// the secure build. Drives `nsc::gated_unlock` through `MAX_ATTEMPTS`
/// wrong-PIN attempts followed by one correct-PIN attempt and asserts
/// that the correct-PIN attempt is rejected (MCU gate already at max).
/// Returns `NscStatus::Ok` on the expected lockout outcome, or
/// `NscStatus::CryptoError` if the correct PIN is accepted — which
/// would mean brute-force protection is broken.
///
/// Destructive: leaves the SE050 user UserID silicon-locked and the
/// MCU attempt counter at MAX. Requires the admin-wipe install on
/// SE050 (i.e. NOT `e2e-skip-admin-wipe`) so the boot-time recovery
/// path can wipe + re-provision on the next boot.
pub const CMD_TEST_PIN_LOCKOUT: u32 = 200;

/// CMD_TZIC_STATUS — read the GTZC1 TZIC illegal-access counter.
///
/// Test-only gateway command, compiled out unless `e2e-test` is set on
/// the secure build. The counter increments inside the GTZC IRQ handler
/// (`hw::tzic::on_violation`) each time NS attempts to read or write a
/// peripheral marked SECURE in `TZSC_SECCFGRx`. Returning the counter
/// as the `u32` status word lets the NS-side `gtzc-test` validation
/// driver probe each protected NS-alias address and assert that the
/// secure-world IRQ fired the expected number of times.
///
/// No PIN unlock required: this is a pure side-channel into the IRQ
/// counter; no secret state is touched.
pub const CMD_TZIC_STATUS: u32 = 201;

// ---------------------------------------------------------------------------
// Prodtest commands (100-199) — only present in the `prodtest` build profile.
//
// Factory production-line test firmware. Replaces the wizard / unlock path
// with a USB-command server that the factory fixture drives to validate each
// hardware component before flashing the factory_provisioning firmware. See
// `docs/factory-prodtest.md` for the full command reference + fixture
// integration guide.
//
// Phase A (landed 2026-05-19): GET_ID + DISPLAY_PATTERN
// Phase B (landed 2026-05-19): SAES_SELFTEST + BHK_SELFTEST + FLASH_RW +
//                              TRNG_SAMPLE
// Phase C-G (deferred to work-todo §30): communication tests, button test,
//                              host-side fixture runner, operator manual.
// ---------------------------------------------------------------------------

/// CMD_PRODTEST_GET_ID — returns 24 bytes:
///   [0..12]   STM32 chip UID (`0x0BFA_0700`, 96 bits per RM0456)
///   [12..16]  Firmware version (u32 LE — host fixture's traceability DB)
///   [16..24]  Reserved (zeroes today; future: build-hash prefix)
/// Always succeeds; the response bytes are the canonical chip-ID for the
/// fixture's per-unit traceability database.
pub const CMD_PRODTEST_GET_ID: u32 = 100;

/// CMD_PRODTEST_DISPLAY_PATTERN — render a known full-screen OLED test
/// pattern for the fixture's camera (or operator) to verify.
///   in_ptr → 4 bytes pattern ID (u32 LE):
///     0 = all white (every pixel ON)
///     1 = all black (every pixel OFF)
///     2 = horizontal stripes (every other row ON)
///     3 = vertical stripes (every other column ON)
///     4 = checker (8×8 alternating)
///   out_ptr → ignored
/// Returns `NscStatus::Ok` on success, `NscStatus::InvalidParameter` if
/// pattern ID is out of range.
pub const CMD_PRODTEST_DISPLAY_PATTERN: u32 = 101;

/// CMD_PRODTEST_SAES_SELFTEST — runs the Tier-1 SAES self-test (round-
/// trip encrypt + decrypt under both software-key and DHUK key
/// selectors) and returns the per-die DHUK fingerprint.
///   in_ptr  → ignored
///   out_ptr → 8 bytes DHUK fingerprint (first 8 bytes of
///             `SAES-CBC(DHUK, [0u8; 32])`). Used by the fixture's
///             per-die-uniqueness check + factory traceability DB.
/// Returns `NscStatus::Ok` on success, `NscStatus::InternalError` if the
/// SAES round-trip fails (silicon defect or wrong RDP state).
pub const CMD_PRODTEST_SAES_SELFTEST: u32 = 102;

/// CMD_PRODTEST_BHK_SELFTEST — runs the Tier-2 BHK self-test (load,
/// TAMP-backup-register lock, AES round-trip under BHK key selector)
/// and returns the per-die BHK fingerprint.
///   in_ptr  → ignored
///   out_ptr → 8 bytes BHK fingerprint
/// Returns `NscStatus::Ok` on success, `NscStatus::InternalError` if the
/// BHK isn't provisioned yet (flash page 126 blank) or if the AES
/// round-trip fails.
pub const CMD_PRODTEST_BHK_SELFTEST: u32 = 103;

/// CMD_PRODTEST_FLASH_RW — write a known pattern to a designated test
/// page, read it back, verify integrity. Used to catch flash defects
/// before they wedge a customer wallet. **NEVER call against a
/// non-test-page** — would clobber wallet state.
///   in_ptr  → 4 bytes test pattern (u32 LE; 0xDEADBEEF is the canonical
///             value used by the fixture)
///   out_ptr → ignored
/// Returns `NscStatus::Ok` on round-trip success, `NscStatus::Internal-
/// Error` on readback mismatch.
pub const CMD_PRODTEST_FLASH_RW: u32 = 104;

/// CMD_PRODTEST_TRNG_SAMPLE — return raw bytes from the MCU TRNG (no SE
/// XOR mix) for the fixture's statistical entropy check (χ² / Shannon
/// estimator / etc.). Capped at 256 bytes per call to keep the USB HID
/// buffer bounded.
///   in_ptr  → 4 bytes byte count (u32 LE, must be 1..=256)
///   out_ptr → N bytes of TRNG output
/// Returns `NscStatus::Ok` on success, `NscStatus::InvalidParameter` if
/// count is 0 or > 256, `NscStatus::InternalError` on TRNG fault.
pub const CMD_PRODTEST_TRNG_SAMPLE: u32 = 105;

/// Maximum bytes of chunk data per CMD_FW_CHUNK payload. Chosen to fit
/// comfortably within the NS-side 8 KB chain accumulator with header
/// space; picked over the tighter 1024-ish USB HID MTU because chunks
/// arrive as APDU v2 payloads and the extra accumulator capacity lets
/// the companion batch up to 8 chunks per APDU if it wants.
pub const FW_MAX_CHUNK: usize = 1024;

/// Chunk header size preceding the data bytes.
pub const FW_CHUNK_HEADER_LEN: usize = 8;

/// Kind byte values used in the CHUNK header.
pub const FW_IMAGE_KIND_SECURE: u8 = 0;
pub const FW_IMAGE_KIND_NONSECURE: u8 = 1;

/// CMD_FW_STATUS response layout.
pub const FW_STATUS_RESPONSE_LEN: usize = 1 + 4 + 4 + 1;
pub const FW_STATUS_STATE_OFFSET: usize = 0;
pub const FW_STATUS_RECV_S_OFFSET: usize = 1;
pub const FW_STATUS_RECV_NS_OFFSET: usize = 5;
pub const FW_STATUS_SLOT_OFFSET: usize = 9;

/// FW update state-machine states reported by CMD_FW_STATUS.
pub const FW_STATE_IDLE: u8 = 0;
pub const FW_STATE_RECEIVING: u8 = 1;
pub const FW_STATE_STAGED: u8 = 2;

// ---------------------------------------------------------------------------
// CMD_SIGN_USEROP fixed-header layout offsets
// ---------------------------------------------------------------------------

/// Length of the fixed header that precedes the `tx_len` field.
pub const USEROP_HEADER_LEN: usize =
    1 + 20 + 20 + 8 + 32 + 32 + 32 + 32 + 32 + 32 + 32 + 32;

/// Total fixed prefix length (header + 4-byte `tx_len`).
pub const USEROP_PREFIX_LEN: usize = USEROP_HEADER_LEN + 4;

// ---------------------------------------------------------------------------
// EIP-712 clear signing constants (M4 — CowSwap GPv2Order, v3)
// ---------------------------------------------------------------------------

/// Canonical (packed) GPv2Order encoding length.
///
/// v3 layout (204 bytes):
///
///   [  0..  8)  chain_id          (u64 BE)         ← NEW in v3
///   [  8.. 28)  sellToken
///   [ 28.. 48)  buyToken
///   [ 48.. 68)  receiver
///   [ 68..100)  sellAmount        (uint256 BE)
///   [100..132)  buyAmount
///   [132..164)  feeAmount
///   [164..168)  validTo           (u32 BE)
///   [168]       kind
///   [169]       partiallyFillable
///   [170]       sellTokenBalance
///   [171]       buyTokenBalance
///   [172..204)  appData           (bytes32)        ← NEW in v3
pub const EIP712_CANONICAL_LEN: usize = 204;

/// Readable-string length (8 lines × 16 cols = 128). Wider than the
/// EIP-1559 clear-sign path because v3 splits the amount and symbol
/// onto separate lines, enabling MAX_INT_DIGITS=10 + 6-char symbols.
pub const EIP712_STRING_LEN: usize = 128;

/// Same Groth16 proof size as the EIP-1559 clear-sign path.
pub const EIP712_PROOF_LEN: usize = 384;

// ---------------------------------------------------------------------------
// USB APDU protocol v2 — PQSigner native
// ---------------------------------------------------------------------------

/// v2 class byte. Companion tries 0xF0 first; SW_CLA_NOT_SUPPORTED means
/// legacy firmware that only speaks CLA 0xE0.
pub const APDU_CLA_V2: u8 = 0xF0;

// -- Device info & status (0x01-0x0F) --
pub const INS_V2_GET_DEVICE_INFO: u8 = 0x01;
pub const INS_V2_GET_STATUS: u8 = 0x02;

// -- Session management (0x10-0x1F) --
pub const INS_V2_UNLOCK: u8 = 0x10;
pub const INS_V2_LOCK: u8 = 0x11;

// -- UserOp signing (0x30-0x3F) --
pub const INS_V2_SIGN_USEROP: u8 = 0x30;
/// INS_V2_SIGN_USEROP_BATCH — multi-call batch sign. Same semantics as
/// `INS_V2_SIGN_USEROP` but the payload is the
/// `CMD_SIGN_USEROP_BATCH` wire format (header + N inner-tx blocks)
/// and the resulting UserOp's callData is
/// `executeBatchWithOffchainCount(...)` instead of
/// `executeWithOffchainCount(...)`.
pub const INS_V2_SIGN_USEROP_BATCH: u8 = 0x32;

// -- Address & account helpers (0x60-0x6F) --
pub const INS_V2_GET_WALLET_ADDRESS: u8 = 0x60;
pub const INS_V2_GET_INIT_CODE: u8 = 0x61;
pub const INS_V2_SIGN_OFFCHAIN: u8 = 0x62;
pub const INS_V2_OFFCHAIN_STATUS: u8 = 0x63;
pub const INS_V2_OFFCHAIN_SYNC: u8 = 0x64;

// ---------------------------------------------------------------------------
// Firmware-update INS codes (companion → device)
// ---------------------------------------------------------------------------

/// INS_V2_FW_BEGIN — initiate update. Payload: 8 KB manifest.
/// Chained (P1=0x80 on non-final, P1=0x00 on final — the manifest is
/// 8 KB which exceeds the 253-byte APDU payload, so it MUST be chained).
pub const INS_V2_FW_BEGIN: u8 = 0x70;

/// INS_V2_FW_CHUNK — one image chunk. Payload: 8-byte header + data.
/// Not chained; each CMD_FW_CHUNK is one APDU.
pub const INS_V2_FW_CHUNK: u8 = 0x71;

/// INS_V2_FW_COMMIT — finalize. No payload.
pub const INS_V2_FW_COMMIT: u8 = 0x72;

/// INS_V2_FW_STATUS — read update progress. No payload.
pub const INS_V2_FW_STATUS: u8 = 0x73;

/// INS_V2_FW_ABORT — discard partial update. No payload.
pub const INS_V2_FW_ABORT: u8 = 0x74;

// -- Continuation --
pub const INS_V2_GET_RESPONSE: u8 = 0xC0;

// ---------------------------------------------------------------------------
// Unified Type 1 / Type 2 wire format (CMD_SIGN_USEROP)
// ---------------------------------------------------------------------------
//
// The unified sign command emits a bundle that the companion submits as
// up to two EntryPoint v0.6 UserOps. Byte layout MUST match the on-chain
// PQSmartWallet verifier exactly.

/// SPHINCS+C10 signature length (== `SIGNATURE_LEN` as of the C10 cutover).
pub const C10_SIG_LEN: usize = SIGNATURE_LEN;

/// `abi.encode(uint256 ownerIndex, bytes innerSig)` wrapper around a
/// SPHINCS+C10 signature, matching the on-chain `PQSmartWallet`
/// `SignatureWrapper` struct.
///
/// Solidity encodes this as:
///   * head: `uint256 ownerIndex` (32) + `bytes offset = 0x40` (32) = 64B
///   * tail: `uint256 len = 4008` (32) + `data` padded up to next 32-byte
///     boundary → `ceil(4008/32)*32 = 4032` bytes
///
/// So the wrapper is exactly 32 + 32 + 32 + 4032 = 4128 bytes.
pub const SIG_WRAPPER_LEN: usize = 32 + 32 + 32 + C10_SIG_LEN.next_multiple_of(32); // 4128

/// Type 1 = bootstrap-signed `addOwnerBytes` UserOp signature wrapper.
///
/// Emitted when the companion asks for slot rotation (`FLAG_REGISTER_SLOT`).
/// The firmware builds a synthetic addOwner UserOp internally, hashes it
/// with SHA-256, signs the hash with the bootstrap C10 key, and wraps the
/// sig as `(ownerIndex = 0, inner_sig = c10_sig)`.
pub const SIG_TYPE1_LEN: usize = SIG_WRAPPER_LEN;

/// Type 2 = slot-signed user-tx UserOp signature wrapper.
///
/// Emitted on every sign request. `ownerIndex = slot_index + 1` (slot 0 is
/// at on-chain ownerIndex 1 since ownerIndex 0 is the bootstrap key).
pub const SIG_TYPE2_LEN: usize = SIG_WRAPPER_LEN;

/// Back-compat constant: the abi.encode header that precedes the raw 4008-
/// byte C10 sig inside a SignatureWrapper (32 ownerIndex + 32 offset +
/// 32 length = 96 bytes). Surfaced over USB in GET_DEVICE_INFO so the
/// host companion can slice the wrapper without embedding the constant.
pub const SIG_TYPE2_HEADER_LEN: usize = 32 + 32 + 32;

// ---------------------------------------------------------------------------
// CMD_SIGN_OFFCHAIN / CMD_OFFCHAIN_STATUS wire-format and budget constants
// ---------------------------------------------------------------------------

/// Per-chain bootstrap-key (Type 1) sig cap, mirroring the on-chain
/// `PQSmartWallet.MAX_BOOTSTRAP_USES`. Bounds slot-registration
/// frequency. Combined with `MAX_SLOT_USES`, each chain can service up
/// to ~2³² user transactions before becoming permanently frozen — well
/// inside the SPHINCS+C10 birthday-style safety margin for `h=18`.
///
/// Sourced from this crate by both the firmware (pre-emptive refusal in
/// `cmd_sign_userop`) and the Solidity wallet (post-bump enforcement in
/// `validateUserOp`). Phase 4 codegens this into `PqsignerProto.sol`.
pub const MAX_BOOTSTRAP_USES: u64 = 65_536;

/// Per-slot SPHINCS+C10 sig cap, mirroring the on-chain
/// `PQSmartWallet.MAX_SLOT_USES`. The firmware enforces the same cap
/// pre-emptively over `slotUses + offchainSigCount` so a fault would
/// never produce a sig that exceeds the SPHINCS+ usage budget.
pub const MAX_SLOT_USES: u64 = 65_536;

/// Length in bytes of the per-slot owner-bytes record stored on chain
/// in `PQMultiOwnable.ownerAtIndex`. The 64 bytes are
/// `pkSeed (32) || pkRoot (32)`.
pub const OWNER_BYTES_LEN: usize = 64;

/// Domain-separation tag for the factory's bootstrap-signed digest
/// (`PQSmartWalletFactory.addSlot0Digest`). Mirrored on-chain as
/// `bytes constant FACTORY_ADD_SLOT_DOMAIN = "pqwallet-factory-add-slot"`.
/// Phase 4 codegens this into `PqsignerProto.sol`.
pub const FACTORY_ADD_SLOT_DOMAIN: &[u8] = b"pqwallet-factory-add-slot";

/// Selector for `executeWithOffchainCount(uint256,uint256,address,uint256,bytes)`
/// on `PQSmartWallet` — every Type 2 UserOp builds calldata against this
/// entry point, durably publishing the firmware's per-slot off-chain sig
/// count on chain so post-restore firmware can read `offchainSigCount[i]`
/// and reason correctly about remaining budget.
pub const EXECUTE_SELECTOR: [u8; 4] = [0x14, 0x44, 0x3c, 0x57];

/// Maximum number of off-chain (EIP-1271) signatures the firmware will
/// produce on a slot before refusing further off-chain sigs and forcing
/// the user to publish the count via a UserOp. Bounds the recovery
/// window: on a fresh-from-seed restore, the new firmware can assume at
/// most `MAX_OFFCHAIN_GAP` unbacked sigs were emitted by the previous
/// device, so the cap-budget calculation stays correct.
pub const MAX_OFFCHAIN_GAP: u64 = 100;

/// CMD_SIGN_OFFCHAIN payload layout. The input is variable-length:
/// fixed 17-byte header followed by `payload_len` bytes whose meaning
/// depends on the `kind` byte at `[13]` — see the doc on
/// [`CMD_SIGN_OFFCHAIN`] for the two supported modes. The `flags` byte
/// at `[16]` carries the EIP-6492 `account_deployed` bit.
pub const SIGN_OFFCHAIN_HEADER_LEN: usize = 1 + 8 + 4 + 1 + 2 + 1; // 17
pub const SIGN_OFFCHAIN_INPUT_ACCOUNT_OFF: usize = 0;
pub const SIGN_OFFCHAIN_INPUT_CHAIN_OFF: usize = 1;
pub const SIGN_OFFCHAIN_INPUT_SLOT_OFF: usize = 9;
pub const SIGN_OFFCHAIN_INPUT_KIND_OFF: usize = 13;
pub const SIGN_OFFCHAIN_INPUT_PAYLOAD_LEN_OFF: usize = 14;
pub const SIGN_OFFCHAIN_INPUT_FLAGS_OFF: usize = 16;
pub const SIGN_OFFCHAIN_INPUT_PAYLOAD_OFF: usize = 17;

/// Bit 0 of the `flags` byte at `SIGN_OFFCHAIN_INPUT_FLAGS_OFF`. When
/// **set**, the wallet is already deployed at its CREATE2 address and
/// firmware emits the legacy bare-sig wire (`SIGN_OFFCHAIN_OUTPUT_LEN`
/// bytes, byte-identical to pre-EIP-6492 builds). When **clear**,
/// firmware emits an ERC-6492 wrapped signature
/// (`SIGN_OFFCHAIN_OUTPUT_LEN_6492` bytes) that any 6492-aware verifier
/// can deploy-and-verify in one `eth_call`. The companion picks the
/// flag via `eth_getCode(predicted_address)`.
pub const OFFCHAIN_FLAG_ACCOUNT_DEPLOYED: u8 = 1 << 0;
/// Mask of currently-defined flag bits. Reserved bits MUST be zero.
pub const OFFCHAIN_FLAGS_MASK: u8 = OFFCHAIN_FLAG_ACCOUNT_DEPLOYED;

/// Maximum personal-sign message length the firmware is willing to
/// surface on the trusted display. 700 bytes covers a comfortable SIWE
/// (Sign-In With Ethereum) message; longer payloads are refused so the
/// secure-side TOCTOU snapshot stays bounded and the user is not
/// asked to scroll through page after page they cannot meaningfully
/// audit.
pub const MAX_OFFCHAIN_PERSONAL_SIGN_LEN: usize = 700;

/// Maximum input length the gateway will accept for `CMD_SIGN_OFFCHAIN`.
/// Sized for the largest valid `kind=PERSONAL_SIGN` request.
pub const SIGN_OFFCHAIN_INPUT_MAX_LEN: usize =
    SIGN_OFFCHAIN_HEADER_LEN + MAX_OFFCHAIN_PERSONAL_SIGN_LEN;

/// Off-chain sign request kinds. See [`CMD_SIGN_OFFCHAIN`] for the
/// hash-construction details of each.
pub const OFFCHAIN_KIND_RAW32: u8 = 0;
pub const OFFCHAIN_KIND_PERSONAL_SIGN: u8 = 1;

/// CMD_SIGN_OFFCHAIN response (deployed path): post-bump count then C10
/// sig. Selected when `OFFCHAIN_FLAG_ACCOUNT_DEPLOYED` is set in the
/// input `flags` byte. Byte-identical to the pre-EIP-6492 wire format.
pub const SIGN_OFFCHAIN_OUTPUT_LEN: usize = 8 + C10_SIG_LEN; // 4016
pub const SIGN_OFFCHAIN_OUTPUT_COUNT_OFF: usize = 0;
pub const SIGN_OFFCHAIN_OUTPUT_SIG_OFF: usize = 8;

/// Length of the `factoryCalldata` field that the firmware writes into
/// an ERC-6492 wrapped sig. Equal to the full `initCode` minus the
/// 20-byte factory address prefix — i.e. `selector || 5 static args ||
/// bytes(offset, len, padded sig)`.
pub const EIP6492_FACTORY_CALLDATA_LEN: usize = PQ_INIT_CODE_LEN - 20; // 4260

/// Padded length of `factoryCalldata` inside the ABI tuple (rounded up
/// to the next 32-byte boundary). The padding bytes are zero.
pub const EIP6492_FACTORY_CALLDATA_PADDED: usize =
    EIP6492_FACTORY_CALLDATA_LEN.next_multiple_of(32); // 4288

/// Length of the inner ERC-1271 signature carried inside an ERC-6492
/// wrapper. The firmware places the on-chain `SignatureWrapper`
/// `abi.encode(uint256 ownerIndex, bytes c10Sig)` here — already
/// 32-byte aligned, so no padding is added by the outer tuple encoder.
pub const EIP6492_INNER_WRAPPER_LEN: usize = SIG_WRAPPER_LEN; // 4128

/// Length of the ERC-6492 wrapped signature blob written into the
/// output buffer at offset 8 when `OFFCHAIN_FLAG_ACCOUNT_DEPLOYED` is
/// **clear**.
///
/// ABI encoding of `(address factory, bytes fc, bytes sig)`: `address`
/// is static and lives inline as the first 32-byte slot of the head;
/// the two `bytes` args contribute one 32-byte offset slot each. Total
/// head = 96 bytes.
///
/// ```text
///   tuple head:
///     [ 0..32)   factory (right-aligned, static — counts as one head slot)
///     [32..64)   offset to fc                  = 0x60
///     [64..96)   offset to sig                 = 0x60 + 32 + fc_padded
///   tuple tail:
///     [96..128)              fc length
///     [128..128+fc_padded)   fc bytes + zero pad
///     [..+32)                sig length
///     [..+inner)             sig bytes (already 32-aligned)
///   suffix:
///     [last 32)              EIP6492_MAGIC
/// ```
pub const EIP6492_BLOB_LEN: usize = 96
    + 32
    + EIP6492_FACTORY_CALLDATA_PADDED
    + 32
    + EIP6492_INNER_WRAPPER_LEN
    + 32; // 8608

/// CMD_SIGN_OFFCHAIN response (counterfactual / ERC-6492 path):
/// post-bump count then the wrapped sig blob.
pub const SIGN_OFFCHAIN_OUTPUT_LEN_6492: usize = 8 + EIP6492_BLOB_LEN; // 8616

/// ERC-6492 magic suffix — the 32 bytes that mark a wrapped signature.
/// Verifiers check `sig[sig.len()-32..] == EIP6492_MAGIC` to detect the
/// wrapping. Value: `0x6492 ... 6492` (16 repetitions).
pub const EIP6492_MAGIC: [u8; 32] = [
    0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92,
    0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92,
    0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92,
    0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92,
];

/// CMD_OFFCHAIN_STATUS payload layout (same prefix as SIGN_OFFCHAIN's
/// first 13 bytes).
pub const OFFCHAIN_STATUS_INPUT_LEN: usize = 1 + 8 + 4; // 13

/// CMD_OFFCHAIN_STATUS response layout.
pub const OFFCHAIN_STATUS_OUTPUT_LEN: usize = 8 + 8 + 1 + 7; // 24
pub const OFFCHAIN_STATUS_OUTPUT_LOCAL_OFF: usize = 0;
pub const OFFCHAIN_STATUS_OUTPUT_LAST_USEROP_OFF: usize = 8;
pub const OFFCHAIN_STATUS_OUTPUT_REGISTERED_OFF: usize = 16;

/// CMD_OFFCHAIN_SYNC payload layout.
///   [ 0.. 1)  account_index  (u8)
///   [ 1.. 9)  chain_id       (u64 BE)
///   [ 9..13)  slot_index     (u32 BE)
///   [13..21)  target_count   (u64 BE) — bump `last_userop_count` to at
///                                       least this value (idempotent).
/// Response: no body, SW only.
pub const OFFCHAIN_SYNC_INPUT_LEN: usize = 1 + 8 + 4 + 8; // 21

// ---------------------------------------------------------------------------
// PQSmartWalletFactory initCode (first-deploy UserOps)
// ---------------------------------------------------------------------------

/// Deployed address of the `PQSmartWalletFactory` contract.
///
/// Deployed via Arachnid's deterministic CREATE2 deployer at
/// `0x4e59…4956C` (pre-deployed via Nick's method on every EVM chain)
/// with `salt = bytes32(0)`, so this address is byte-identical on every
/// chain that has the Arachnid deployer and EntryPoint v0.6 live. Moving
/// to a different `salt`, tweaking the compiler settings, or changing
/// the constructor args will change this address everywhere.
pub const PQ_SMART_WALLET_FACTORY: [u8; 20] = [
    0x67, 0x94, 0x34, 0x87, 0xe9, 0xE4, 0x1a, 0x9E, 0xE5, 0xF5,
    0xF7, 0xA1, 0x0f, 0x18, 0xaa, 0x82, 0xfE, 0x19, 0xE0, 0x3B,
];

/// `keccak256(erc1967ProxyInitCode(impl))` where `impl` is the Coinbase-
/// Smart-Wallet-style `PQSmartWallet` implementation. Baked in because
/// the impl address is itself CREATE2-deterministic (same on every
/// chain), so this hash is a build-time constant rather than a chain
/// lookup.
///
/// Used by `cmd_get_wallet_address` to compute the CREATE2 sender
/// locally via
///   `addr = keccak256(0xff || factory || salt || PROXY_INIT_CODE_HASH)[12..]`
/// where `salt = sha256(masterPkSeed(32) || masterPkRoot(32))`.
pub const PROXY_INIT_CODE_HASH: [u8; 32] = [
    0x81, 0xbf, 0x5c, 0xe0, 0x6e, 0x60, 0xf7, 0x1c,
    0x41, 0xde, 0x86, 0x99, 0x1b, 0x75, 0x63, 0x9e,
    0x32, 0xd9, 0x67, 0xb8, 0xe9, 0xd4, 0x12, 0xb7,
    0x06, 0xa1, 0xc2, 0x4e, 0x25, 0xaa, 0xdc, 0x4c,
];

/// ABI selector for
/// `PQSmartWalletFactory.createAccount(bytes32,bytes32,bytes32,bytes32,uint64,bytes)`.
/// Equals `keccak256("createAccount(bytes32,bytes32,bytes32,bytes32,uint64,bytes)")[..4]`.
pub const PQ_CREATE_ACCOUNT_SELECTOR: [u8; 4] = [0xf6, 0x18, 0x2a, 0x73];

/// ABI selector for `PQSmartWallet.addOwnerBytes(bytes)`.
/// Equals `keccak256("addOwnerBytes(bytes)")[..4]`.
pub const PQ_ADD_OWNER_BYTES_SELECTOR: [u8; 4] = [0x10, 0x14, 0x90, 0xcb];

/// Length (bytes) of the `createAccount(...)` initCode produced by the
/// firmware when `FLAG_INCLUDE_INIT_CODE` is set.
///
/// Layout:
/// ```text
///   factory(20)
///     || selector(4)
///     || masterPkSeed(32)
///     || masterPkRoot(32)
///     || slot0PkSeed(32)
///     || slot0PkRoot(32)
///     || chainId (padded to uint256) (32)
///     || abi-encoded bytes offset = 0xC0 (32)   // = 6 × 32 (head size)
///     || bytes length = 4008 (32)
///     || bytes data padded to 32-byte boundary = 4032
/// ```
///
/// = 20 + 4 + (5 × 32) + 32 + 32 + 4032 = 4280 bytes.
pub const PQ_INIT_CODE_LEN: usize = 20 + 4 + 5 * 32 + 32 + 32 + 4032; // 4280

/// Maximum unified response from `CMD_SIGN_USEROP`:
///
/// ```text
///   [new_offchain_count(8 BE)]   -- firmware's post-bump local count
///                                  (must match the value the companion
///                                  is about to submit in the
///                                  `executeWithOffchainCount` calldata)
///   [init_code_len(4 BE)][init_code(0 or PQ_INIT_CODE_LEN)]
///   [type1_len(4 BE)][type1_wrapper(0 or SIG_WRAPPER_LEN)]
///   [type2_len(4 BE)][type2_wrapper(SIG_WRAPPER_LEN)]
/// ```
pub const MAX_SIGN_RESPONSE_LEN: usize =
    8 + 4 + PQ_INIT_CODE_LEN + 4 + SIG_TYPE1_LEN + 4 + SIG_TYPE2_LEN;

/// Flags bit 31 — set by the companion when the wallet has not yet been
/// deployed on this chain. Firmware synthesises `initCode` from its master
/// pubkey pair, folds the hash into the Type 1 `userOpHash`, and emits the
/// initCode bytes alongside the signature bundle so the companion can
/// populate `UserOperation06.initCode` without ever seeing the master
/// pubkey on its own. Requires `FLAG_REGISTER_SLOT` (init_code only rides
/// on a Type 1 frame).
pub const FLAG_INCLUDE_INIT_CODE: u32 = 0x8000_0000;

/// Flags bit 30 — set by the companion to ask the firmware to emit a Type 1
/// slot-registration frame before the Type 2 user-tx frame.
///
/// The firmware is stateless with respect to slot selection: it does not
/// track whether `(chain_id, slot_index)` has been registered on-chain. The
/// companion app keeps that bookkeeping and sets this flag on the first sign
/// for a new `(chain_id, slot_index)` pair, or when rotating to the next
/// slot after exhausting the on-chain `MAX_SLOT_USES` cap.
///
/// When clear, the firmware emits Type 2 only and the companion submits a
/// single UserOp.
pub const FLAG_REGISTER_SLOT: u32 = 0x4000_0000;

/// Bit mask + shift for the BIP-44-style account index encoded in flags.
///
/// Flags layout (MSB to LSB):
///   bit  31         30          29..22                     21..0
///       INIT_CODE  REG_SLOT    account_index (8 bits)     slot_index (22 bits)
///
/// 8 bits gives 256 accounts per seed — well beyond what any user will
/// realistically need. The remaining 22 bits leave room for ~4M slots
/// per (account, chain), several orders of magnitude above the on-chain
/// `MAX_SLOT_USES = 65_536` cap.
///
/// Account 0 is the legacy single-account derivation: its bootstrap C10
/// keys and slot master entropy stay byte-identical to the pre-multi-
/// account firmware so existing seeds still land at the same on-chain
/// address. Accounts 1..=255 use new domain-tagged KDFs (see
/// `secure/src/crypto.rs`).
pub const ACCOUNT_INDEX_MASK: u32 = 0x3FC0_0000;
pub const ACCOUNT_INDEX_SHIFT: u32 = 22;
/// Maximum representable account index (inclusive).
pub const MAX_ACCOUNT_INDEX: u32 = 0xFF;

/// Bit mask of the flags field reserved for the slot index. Narrowed to
/// 22 bits to make room for `ACCOUNT_INDEX_MASK`.
pub const SLOT_INDEX_MASK: u32 =
    !(FLAG_INCLUDE_INIT_CODE | FLAG_REGISTER_SLOT | ACCOUNT_INDEX_MASK);

/// Unified CMD_SIGN_USEROP v4 payload layout (EntryPoint v0.6, unpacked gas).
///
/// | off | size | field |
/// |-----|------|-------|
/// |  0  |  8  | chain_id (u64 BE) |
/// |  8  |  4  | flags (u32 BE: bit 31 = include initCode, bit 30 = register slot, bits 29..22 = account_index, bits 21..0 = slot_index) |
/// | 12  | 20  | sender (PQSmartWallet address — firmware does not recompute) |
/// | 32  | 20  | entry_point (EntryPoint v0.6 address) |
/// | 52  | 32  | nonce (u256 BE; base nonce for Type 1 if registration needed, else Type 2) |
/// | 84  | 32  | call_gas_limit (u256 BE) |
/// | 116 | 32  | verification_gas_limit (u256 BE) |
/// | 148 | 32  | pre_verification_gas (u256 BE) |
/// | 180 | 32  | max_fee_per_gas (u256 BE) |
/// | 212 | 32  | max_priority_fee_per_gas (u256 BE) |
/// | 244 | 32  | paymaster_and_data_hash (sha256; `SHA256_EMPTY` when empty) |
/// | 276 | 20  | to_address (inner tx recipient) |
/// | 296 | 32  | value (u256 BE) |
/// | 328 |  2  | data_len (u16 BE; 0..=MAX_TX_LEN) |
/// | 330 |  N  | data |
/// | 330+N | 2 | erc20_bundle_len (u16 BE; 0 = no bundle) |
/// | 332+N | B | erc20_bundle (Merkle-verified ERC-20 metadata, see `erc20::bundle`) |
/// | 332+N+B | 2 | zk_bundle_len (u16 BE; 0 = no ZK clear-sign) |
/// | 334+N+B | Z | zk_bundle (Groth16 proof + calldata + readable string + VK bundle) |
///
/// All three trailing sections are optional. When a section's length is
/// zero the next section immediately follows.
///
/// Layout math: 8 + 4 + 20 + 20 + 32 (nonce) + 5×32 (gas fields) + 32
/// (paymaster_and_data_hash) + 20 (to) + 32 (value) + 2 (data_len) = 330.
pub const SIGN_USEROP_HEADER_LEN: usize =
    8 + 4 + 20 + 20 + 32 + 5 * 32 + 32 + 20 + 32 + 2; // 330

/// Compile-time sanity check: header ends exactly at `data_len`.
const _: () = assert!(SIGN_USEROP_HEADER_LEN == 330);

/// ZK clear-sign bundle header layout (prepended to the variable-length
/// VK bundle bytes):
///
/// | off | size | field |
/// |-----|------|-------|
/// |  0  | 384  | Groth16 proof (π.A || π.B || π.C) |
/// | 384 | 164  | circuit-attested calldata (right-zero-padded) |
/// | 548 |  64  | readable UTF-8 string (null-padded) |
pub const ZK_CLEAR_SIGN_FIXED_LEN: usize = ZK_PROOF_LEN + ZK_MAX_CALLDATA + ZK_STRING_LEN;

/// Maximum size of the VK bundle tail supplied after the fixed
/// ZK_CLEAR_SIGN_FIXED_LEN prefix.
pub const ZK_VK_BUNDLE_MAX_LEN: usize = 2048;

// ═══════════════════════════════════════════════════════════════════════════
//   CoW Protocol / GPv2Settlement — EIP-712 clear-sign v3
// ═══════════════════════════════════════════════════════════════════════════
//
// All constants for the v3 "render the full GPv2Order on the trusted UI"
// flow live in this block. Three sub-groups:
//
//   1. Trailer layout          — ZK_V3_* shapes the SIGN_USEROP payload.
//   2. Trailer field offsets   — ZK_V3_OFF_* index into the fixed prefix.
//   3. Protocol-identity       — the setPreSignature selector, the real
//                                GPv2Settlement contract address, and the
//                                DB-lookup sentinel that keys the v3 VK.
//
// When the companion sends a CoW UserOp whose inner calldata is
// `setPreSignature(orderUid, true)` on GPv2Settlement, it attaches a
// third trailer section after the legacy `zk_bundle` slot:
//
//   [zk_v3_len u16 BE] [zk_v3_bundle]
//
// where `zk_v3_bundle` layout is:
//
//   [  0..  384) proof2     — 384-byte BLS12-381 Groth16 proof for
//                             the v3 `cowswap_eip712_order` circuit.
//   [384..  588) canonical  — 204-byte packed GPv2Order struct.
//   [588..  716) readable2  — 128-byte 8×16 ASCII readable. The
//                             firmware renders this byte-for-byte
//                             across the middle pages of the trusted
//                             UI flow.
//   [716..     ) vk_bundle2 — 3-pub VK bundle injected by the NS
//                             gateway (companion sends exactly
//                             716 bytes; NS appends the bundle).
//
// The v3 circuit binds `canonical` to `readable2` via Poseidon, and
// the secure world natively re-keccaks `canonical` → orderDigest →
// cross-checks against the calldata's `[100..132)` slice. Together
// these replace the legacy v1 proof entirely for CoW setPreSignature.

// ─── 1. Trailer layout ─────────────────────────────────────────────────────

/// Fixed prefix of the v3 trailer (proof2 + canonical + readable2).
/// The NS gateway appends the VK bundle; see
/// `nonsecure/src/usb/commands.rs::maybe_inject_vk_bundle_v3`.
pub const ZK_V3_FIXED_LEN: usize = EIP712_PROOF_LEN + EIP712_CANONICAL_LEN + EIP712_STRING_LEN;

// ─── 2. Trailer field offsets ──────────────────────────────────────────────

/// Offset of the 204-byte canonical GPv2Order within the fixed prefix.
pub const ZK_V3_OFF_CANONICAL: usize = EIP712_PROOF_LEN;
/// Offset of the 128-byte readable ASCII string within the fixed prefix.
pub const ZK_V3_OFF_READABLE: usize = ZK_V3_OFF_CANONICAL + EIP712_CANONICAL_LEN;

// ─── 3. Protocol-identity constants ────────────────────────────────────────

/// Function selector for `setPreSignature(bytes,bool)` on
/// `GPv2Settlement` — companion's calldata[0..4] match against this
/// triggers the mandatory-v3 gate in the secure world.
pub const SET_PRE_SIGNATURE_SELECTOR: [u8; 4] = [0xec, 0x6c, 0xb1, 0x3f];

/// DB-lookup sentinel address for the v3 `cowswap_eip712_order` VK.
///
/// Differs from the real `GPV2Settlement` contract address
/// (`0x9008...ab41`) by its last byte (`0x42`). Never appears on
/// Ethereum — it is a pure (chain_id, contract) → VK DB key that
/// distinguishes "v3 CoW EIP-712 VK" from "v1 setPreSignature calldata
/// VK" without bumping `VK_DB_VERSION`.
pub const COWSWAP_EIP712_SENTINEL: [u8; 20] = [
    0x90, 0x08, 0xd1, 0x9f, 0x58, 0xaa, 0xbd, 0x9e, 0xd0, 0xd6, 0x09, 0x71, 0x56, 0x5a, 0xa8,
    0x51, 0x05, 0x60, 0xab, 0x42,
];

/// Real `GPv2Settlement` contract address on every EVM chain CoW
/// Protocol supports (CREATE2-deployed, address-identical). Used by
/// the secure world as the `verifyingContract` field in the EIP-712
/// domain separator AND as the downgrade-mitigation gate: when
/// `parsed.tx.to == GPV2_SETTLEMENT_ADDRESS && selector == setPreSignature`,
/// a v3 trailer is MANDATORY.
pub const GPV2_SETTLEMENT_ADDRESS: [u8; 20] = [
    0x90, 0x08, 0xd1, 0x9f, 0x58, 0xaa, 0xbd, 0x9e, 0xd0, 0xd6, 0x09, 0x71, 0x56, 0x5a, 0xa8,
    0x51, 0x05, 0x60, 0xab, 0x41,
];

// ---------------------------------------------------------------------------
// Safe multisig (`approveHash`) clear-signing trailer — `safe_v1`
// ---------------------------------------------------------------------------
//
// Targets Safe contracts v1.3.0 and later (the dominant deployments on
// mainnet and L2s). Older Safes use a domain separator without
// `chainId` — they self-police: our recomputed safeTxHash will fail
// the calldata cross-check and the trailer is rejected. Companion is
// responsible for refusing to send a `safe_v1` trailer for a v1.1.x
// Safe.
//
// The `approveHash(bytes32)` selector puts the EIP-712 digest *in the
// calldata*, so unlike the CoW v3 path there is no Groth16 — the
// firmware natively keccaks (raw_data → data_hash) and (canonical →
// safeTxHash), then byte-compares safeTxHash against
// `inner_data[4..36]`.

/// Function selector for `approveHash(bytes32)` on Safe `Singleton`
/// contracts. Equals `keccak256("approveHash(bytes32)")[..4]`.
pub const APPROVE_HASH_SELECTOR: [u8; 4] = [0xd4, 0xd9, 0xbd, 0xcd];

/// Total length of the `approveHash(bytes32)` calldata: selector +
/// 32-byte hash argument.
pub const APPROVE_HASH_CALLDATA_LEN: usize = 4 + 32;

/// `keccak256("EIP712Domain(uint256 chainId,address verifyingContract)")`.
/// The Safe v1.3.0+ domain typehash. (Earlier Safes use a domain
/// without `chainId`, which produces a different hash and is naturally
/// rejected by the cross-check.)
pub const SAFE_DOMAIN_TYPEHASH: [u8; 32] = [
    0x47, 0xe7, 0x95, 0x34, 0xa2, 0x45, 0x95, 0x2e, 0x8b, 0x16, 0x89, 0x3a, 0x33, 0x6b, 0x85,
    0xa3, 0xd9, 0xea, 0x9f, 0xa8, 0xc5, 0x73, 0xf3, 0xd8, 0x03, 0xaf, 0xb9, 0x2a, 0x79, 0x46,
    0x92, 0x18,
];

/// `keccak256("SafeTx(address to,uint256 value,bytes data,uint8 operation,
/// uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,
/// address refundReceiver,uint256 nonce)")`.
pub const SAFE_TX_TYPEHASH: [u8; 32] = [
    0xbb, 0x83, 0x10, 0xd4, 0x86, 0x36, 0x8d, 0xb6, 0xbd, 0x6f, 0x84, 0x94, 0x02, 0xfd, 0xd7,
    0x3a, 0xd5, 0x3d, 0x31, 0x6b, 0x5a, 0x4b, 0x26, 0x44, 0xad, 0x6e, 0xfe, 0x0f, 0x94, 0x12,
    0x86, 0xd8,
];

/// Length of the packed canonical SafeTx encoding the `safe_v1` trailer
/// carries. Layout (big-endian, fixed offsets):
///
/// ```text
///   [  0..  8)  chain_id           u64 BE
///   [  8.. 28)  safe_address       20 B
///   [ 28.. 48)  to                 20 B
///   [ 48.. 80)  value              uint256 BE
///   [ 80..112)  data_hash          keccak256(data) — verified by firmware
///   [112]       operation          0=Call, 1=DelegateCall (refused in v1)
///   [113..145)  safe_tx_gas        uint256 BE
///   [145..177)  base_gas           uint256 BE
///   [177..209)  gas_price          uint256 BE
///   [209..229)  gas_token          20 B
///   [229..249)  refund_receiver    20 B
///   [249..281)  nonce              uint256 BE
/// ```
pub const SAFE_V1_CANONICAL_LEN: usize = 281;

/// Maximum size of the `raw_data` carried alongside the canonical in
/// the `safe_v1` trailer. Set to `MAX_TX_LEN` so any inner Safe call
/// the wallet would otherwise accept as a UserOp's inner data fits.
pub const SAFE_V1_RAW_DATA_MAX: usize = MAX_TX_LEN;

/// Maximum size of the full `safe_v1` trailer payload:
/// `canonical (281) + u16 raw_data_len (2) + raw_data (≤4096)`.
pub const SAFE_V1_PAYLOAD_MAX: usize = SAFE_V1_CANONICAL_LEN + 2 + SAFE_V1_RAW_DATA_MAX;

// Canonical SafeTx field offsets — used by both the firmware decoder
// and the host-side companion when assembling the trailer.
pub const SAFE_OFF_CHAIN_ID: usize = 0;
pub const SAFE_OFF_SAFE_ADDRESS: usize = 8;
pub const SAFE_OFF_TO: usize = 28;
pub const SAFE_OFF_VALUE: usize = 48;
pub const SAFE_OFF_DATA_HASH: usize = 80;
pub const SAFE_OFF_OPERATION: usize = 112;
pub const SAFE_OFF_SAFE_TX_GAS: usize = 113;
pub const SAFE_OFF_BASE_GAS: usize = 145;
pub const SAFE_OFF_GAS_PRICE: usize = 177;
pub const SAFE_OFF_GAS_TOKEN: usize = 209;
pub const SAFE_OFF_REFUND_RECEIVER: usize = 229;
pub const SAFE_OFF_NONCE: usize = 249;

// Sanity assertion: the canonical layout adds up to SAFE_V1_CANONICAL_LEN.
const _: () = assert!(SAFE_OFF_NONCE + 32 == SAFE_V1_CANONICAL_LEN);

/// Maximum reconstructed `executeWithOffchainCount(uint256 ownerIndex,
/// uint256 newOffchainCount, address target, uint256 value, bytes data)`
/// callData size: selector(4) + 5 fixed head slots(160) + bytes-offset(32)
/// + bytes-length(32) + data padded to 32-byte boundary. Bounded by
/// `MAX_TX_LEN` (4096) for the inner data.
pub const MAX_EXECUTE_CALLDATA_LEN: usize = 4 * 1024 + 256; // 4352

// ---------------------------------------------------------------------------
// Batch-sign constants (CMD_SIGN_USEROP_BATCH)
// ---------------------------------------------------------------------------

/// Maximum number of inner transactions the firmware will batch into a
/// single `executeBatchWithOffchainCount` UserOp. Bounded by the number
/// of clear-signing flows a user can realistically review on the OLED
/// in one session, AND by the SRAM snapshot buffer for the wire
/// payload. Pick 4 — covers approve+swap+transfer+settle multi-step
/// DeFi flows with headroom; the on-chain batch path itself imposes
/// no hard cap.
pub const MAX_BATCH_TXS: usize = 4;

/// Fixed-prefix length of the `CMD_SIGN_USEROP_BATCH` payload (header
/// up to and including `batch_count`). Inner-tx blocks follow.
///
/// Layout math: 8 (chain_id) + 4 (flags) + 20 (sender) + 20 (ep) + 32
/// (nonce) + 5×32 (gas) + 32 (paym hash) + 1 (batch_count) = 277.
pub const SIGN_USEROP_BATCH_HEADER_LEN: usize =
    8 + 4 + 20 + 20 + 32 + 5 * 32 + 32 + 1; // 277

const _: () = assert!(SIGN_USEROP_BATCH_HEADER_LEN == 277);

/// Per-tx fixed prefix inside the batch payload: `to(20) + value(32) +
/// data_len(2) = 54`.
pub const SIGN_USEROP_BATCH_TX_PREFIX_LEN: usize = 20 + 32 + 2; // 54

/// Worst-case `CMD_SIGN_USEROP_BATCH` payload length: header + every
/// inner tx running at `MAX_TX_LEN` data. The secure world's TOCTOU
/// snapshot is sized to this bound.
pub const SIGN_USEROP_BATCH_MAX_PAYLOAD_LEN: usize = SIGN_USEROP_BATCH_HEADER_LEN
    + MAX_BATCH_TXS * (SIGN_USEROP_BATCH_TX_PREFIX_LEN + MAX_TX_LEN);

/// ABI selector for
/// `PQSmartWallet.executeBatchWithOffchainCount(uint256,uint256,address[],uint256[],bytes[])`.
/// Equals
/// `keccak256("executeBatchWithOffchainCount(uint256,uint256,address[],uint256[],bytes[])")[..4]`.
/// Cross-checked by `contracts/smart-wallet/test/PQSmartWallet.t.sol::test_executeBatchSelector`.
pub const EXECUTE_BATCH_SELECTOR: [u8; 4] = [0x7a, 0x38, 0x99, 0x33];

/// Maximum reconstructed `executeBatchWithOffchainCount(...)` calldata
/// size for `MAX_BATCH_TXS` inner txs each at `MAX_TX_LEN` bytes of
/// data. Layout:
///
///   selector(4)
/// + head(5 × 32 = 160)         — ownerIndex, newOffchainCount, three offsets
/// + targets[](32 + N×32)
/// + values[](32 + N×32)
/// + datas[](32 + N×32 inner-offsets + N × (32 length + padded data))
///
/// For N = MAX_BATCH_TXS = 4 and per-tx data = MAX_TX_LEN = 4096 (already
/// 32-aligned): 4 + 160 + (32 + 128) + (32 + 128) + (32 + 128) + 4 ×
/// (32 + 4096) = 644 + 16,512 = 17,156. Round up to 18 KiB for safety.
pub const MAX_EXECUTE_BATCH_CALLDATA_LEN: usize = 18 * 1024; // 18,432

/// v2 protocol version reported in GET_DEVICE_INFO.
pub const PROTOCOL_VERSION: u16 = 0x0200;

/// ISO 7816-4 status words
pub const SW_OK: u16 = 0x9000;
pub const SW_MORE_DATA: u8 = 0x61; // SW1=0x61, SW2=remaining (0xFF if >255)
pub const SW_CONDITIONS_NOT_SATISFIED: u16 = 0x6985;
pub const SW_SECURITY_NOT_SATISFIED: u16 = 0x6982;
pub const SW_WRONG_DATA: u16 = 0x6A80;
pub const SW_WRONG_LENGTH: u16 = 0x6700;
pub const SW_INS_NOT_SUPPORTED: u16 = 0x6D00;
pub const SW_CLA_NOT_SUPPORTED: u16 = 0x6E00;
pub const SW_FEATURE_NOT_SUPPORTED: u16 = 0x6501;
pub const SW_INTERNAL_ERROR: u16 = 0x6F00;
/// Referenced data invalidated — idle timeout wipe occurred mid-operation.
pub const SW_REFERENCED_DATA_INVALIDATED: u16 = 0x6984;

/// Maximum response data per APDU (before SW bytes).
pub const APDU_MAX_RESP: usize = 253;

/// HID report size (USB Full-Speed interrupt endpoint).
pub const HID_REPORT_SIZE: usize = 64;

/// HID framing tag for APDU data (Ledger-compatible).
pub const HID_TAG_APDU: u8 = 0x05;

/// HID framing tag for PING echo.
pub const HID_TAG_PING: u8 = 0x02;

// ---------------------------------------------------------------------------
// NSC return status codes
// ---------------------------------------------------------------------------

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NscStatus {
    Ok = 0,
    PinIncorrect = 1,
    PinLocked = 2,
    CryptoError = 3,
    InvalidPointer = 4,
    NotInitialized = 5,
    UserRejected = 6,
    IdleWipe = 7,
    // 8 (was SlotExhausted) is retired — post-C10 slot cutover, per-slot
    // exhaustion is enforced on-chain by MAX_SLOT_USES, not by firmware.

    // Firmware-update status codes. These fire from the CMD_FW_*
    // handlers and surface to the companion app via the USB status-word
    // mapping.
    /// A chunk / commit arrived without a prior BEGIN, or BEGIN was
    /// called while another session was in progress.
    FwUpdateBadState = 10,
    /// The manifest failed structural / CRC / digest / vendor-fpr /
    /// signature verification. The supplied manifest is not a
    /// vendor-signed release for this device.
    FwUpdateBadManifest = 11,
    /// The manifest is structurally valid but its `fw_version` is
    /// below the OTP rollback floor.
    FwUpdateBadVersion = 12,
    /// A chunk's offset is non-monotonic, its length exceeds
    /// `FW_MAX_CHUNK`, or it would run past the image's declared
    /// length. The streaming session is left in `Receiving` — the
    /// companion can retry the chunk or abort.
    FwUpdateBadChunk = 13,
    /// Post-streaming, the re-hashed image bytes don't match the
    /// manifest's signed hashes. Either the companion sent a different
    /// image than the one it signed, or flash writes were torn.
    FwUpdateBadImage = 14,
    /// An internal flash program / erase operation failed. The inactive
    /// slot may be in an undefined state; retry a fresh BEGIN.
    FwUpdateFlashError = 15,
    /// OTP rollback budget exhausted — this device can no longer
    /// accept any further firmware updates. A tracked companion-side
    /// warning should have fired well before this.
    FwUpdateOtpExhausted = 16,

    // ── CMD_SIGN_OFFCHAIN errors ───────────────────────────────────
    /// Off-chain sign requested for a slot that this firmware has no
    /// flash record of. After a seed-restore on a fresh device, the
    /// companion must register the next slot via a Type 1 UserOp
    /// before off-chain sigs against it are accepted. Recoverable.
    OffchainSlotUnregistered = 17,
    /// Off-chain sign would push `local_offchain - last_userop` past
    /// `MAX_OFFCHAIN_GAP`. Recoverable: companion publishes a UserOp
    /// (which advances `last_userop_count`) and the next off-chain
    /// sign succeeds.
    OffchainGapExceeded = 18,
    /// Off-chain sign would push the per-slot combined cap
    /// `slotUses + offchainSigCount` past `MAX_SLOT_USES`. Recoverable
    /// only by rotating to a new slot.
    OffchainCapExceeded = 19,

    InternalError = 0xFFFF_FFFF,
}

impl From<u32> for NscStatus {
    fn from(v: u32) -> Self {
        match v {
            0 => Self::Ok,
            1 => Self::PinIncorrect,
            2 => Self::PinLocked,
            3 => Self::CryptoError,
            4 => Self::InvalidPointer,
            5 => Self::NotInitialized,
            6 => Self::UserRejected,
            7 => Self::IdleWipe,
            10 => Self::FwUpdateBadState,
            11 => Self::FwUpdateBadManifest,
            12 => Self::FwUpdateBadVersion,
            13 => Self::FwUpdateBadChunk,
            14 => Self::FwUpdateBadImage,
            15 => Self::FwUpdateFlashError,
            16 => Self::FwUpdateOtpExhausted,
            17 => Self::OffchainSlotUnregistered,
            18 => Self::OffchainGapExceeded,
            19 => Self::OffchainCapExceeded,
            _ => Self::InternalError,
        }
    }
}

// ---------------------------------------------------------------------------
// Wire-format layout tests (run with `cargo test -p pqsigner-proto`)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_userop_header_is_305() {
        // 1 (mode) + 20 (sender) + 20 (entry_point) + 8 (chain_id)
        // + 8 × 32 (nonce + 5 gas + init_code_hash + paymaster_hash) = 305
        assert_eq!(USEROP_HEADER_LEN, 305);
        assert_eq!(USEROP_PREFIX_LEN, USEROP_HEADER_LEN + 4);
    }

    #[test]
    fn unified_sign_userop_header_is_330() {
        // 8 (chain_id) + 4 (flags) + 20 (sender) + 20 (entry_point)
        // + 32 (nonce) + 5 × 32 (gas) + 32 (paymaster_hash)
        // + 20 (to) + 32 (value) + 2 (data_len) = 330
        assert_eq!(SIGN_USEROP_HEADER_LEN, 330);
    }

    #[test]
    fn pq_init_code_len_is_4280() {
        // factory(20) + selector(4) + 5 × bytes32(160) + offset(32)
        // + length(32) + padded_sig(4032) = 4280
        assert_eq!(PQ_INIT_CODE_LEN, 4_280);
    }

    #[test]
    fn signature_abi_padding_correct() {
        // 4008 % 32 = 8, so 24 bytes of zero-padding; padded = 4032
        let padded = SIGNATURE_LEN.next_multiple_of(32);
        assert_eq!(padded, 4_032);
        assert_eq!(padded % 32, 0);
    }

    #[test]
    fn sig_wrapper_len_matches_solidity_encoding() {
        // abi.encode(uint256 ownerIndex, bytes innerSig):
        //   head: ownerIndex(32) + bytes_offset(32) = 64
        //   tail: length(32) + data padded to 32-byte boundary = 32 + 4032
        // total = 4128
        assert_eq!(SIG_WRAPPER_LEN, 4_128);
        assert_eq!(SIG_TYPE1_LEN, SIG_WRAPPER_LEN);
        assert_eq!(SIG_TYPE2_LEN, SIG_WRAPPER_LEN);
    }

    #[test]
    fn flag_bitfields_partition_u32_cleanly() {
        // Every bit of u32 must belong to exactly one named region.
        let regions = FLAG_INCLUDE_INIT_CODE
            | FLAG_REGISTER_SLOT
            | ACCOUNT_INDEX_MASK
            | SLOT_INDEX_MASK;
        assert_eq!(regions, u32::MAX);

        // ACCOUNT_INDEX_MASK is 8 bits at the documented shift.
        assert_eq!(ACCOUNT_INDEX_MASK, (MAX_ACCOUNT_INDEX) << ACCOUNT_INDEX_SHIFT);
        // SLOT_INDEX_MASK is the 22 LSBs.
        assert_eq!(SLOT_INDEX_MASK, (1u32 << 22) - 1);
    }

    // ── CMD_SIGN_OFFCHAIN / EIP-6492 layout ───────────────────────────

    #[test]
    fn sign_offchain_header_includes_flags_byte() {
        // 17 bytes: account(1) + chain(8) + slot(4) + kind(1) + payload_len(2) + flags(1)
        assert_eq!(SIGN_OFFCHAIN_HEADER_LEN, 17);
        assert_eq!(SIGN_OFFCHAIN_INPUT_FLAGS_OFF, 16);
        assert_eq!(SIGN_OFFCHAIN_INPUT_PAYLOAD_OFF, 17);
    }

    #[test]
    fn sign_offchain_flags_mask_covers_defined_bits() {
        assert_eq!(OFFCHAIN_FLAGS_MASK, OFFCHAIN_FLAG_ACCOUNT_DEPLOYED);
        assert_eq!(OFFCHAIN_FLAG_ACCOUNT_DEPLOYED & 0b1111_1110, 0);
    }

    #[test]
    fn sign_offchain_output_lens() {
        assert_eq!(SIGN_OFFCHAIN_OUTPUT_LEN, 4016);
        assert_eq!(SIGN_OFFCHAIN_OUTPUT_LEN_6492, 8 + EIP6492_BLOB_LEN);
    }

    #[test]
    fn eip6492_sizes() {
        // initCode (4280) − factory(20) = 4260 bytes of calldata
        assert_eq!(EIP6492_FACTORY_CALLDATA_LEN, 4260);
        // 4260 → next multiple of 32 = 4288 (28 bytes zero pad)
        assert_eq!(EIP6492_FACTORY_CALLDATA_PADDED, 4288);
        // Inner wrapper already 32-aligned
        assert_eq!(EIP6492_INNER_WRAPPER_LEN, 4128);
        assert_eq!(EIP6492_INNER_WRAPPER_LEN % 32, 0);
        // 96 head (incl. inline factory slot) + 32 fc_len + 4288 fc + 32 sig_len
        // + 4128 sig + 32 magic
        assert_eq!(EIP6492_BLOB_LEN, 96 + 32 + 4288 + 32 + 4128 + 32);
        assert_eq!(EIP6492_BLOB_LEN, 8608);
    }

    #[test]
    fn eip6492_magic_is_repeating_6492() {
        for chunk in EIP6492_MAGIC.chunks(2) {
            assert_eq!(chunk, &[0x64, 0x92]);
        }
        // Spec value: 0x6492649264926492649264926492649264926492649264926492649264926492
        assert_eq!(EIP6492_MAGIC.len(), 32);
    }

    #[test]
    fn max_sign_response_bounds_eip6492_output() {
        // The USB SIG_BUF is sized to MAX_SIGN_RESPONSE_LEN; it must also
        // accommodate the largest possible CMD_SIGN_OFFCHAIN response.
        assert!(MAX_SIGN_RESPONSE_LEN >= SIGN_OFFCHAIN_OUTPUT_LEN_6492);
    }
}

// ---------------------------------------------------------------------------
// Compile-time CMD-collision check
//
// Phase 10 of the modularity refactor. Every gateway command ID must be
// unique. This `const _: () = { ... }` block runs at compile time and
// fails the build with a clear panic message if two `CMD_*` constants
// share the same u32 value. New CMDs must be added to the array below
// to be checked.
// ---------------------------------------------------------------------------

const _: () = {
    let cmds: &[u32] = &[
        CMD_NONE,
        CMD_GET_REMAINING,
        CMD_REQUEST_UNLOCK,
        CMD_GET_PUBKEY,
        CMD_CLEAR_SIGN,
        CMD_SIGN_USEROP,
        CMD_GET_BOOTSTRAP_PUBKEY,
        CMD_GET_MAIN_PUBKEY,
        CMD_SIGN_BOOTSTRAP,
        CMD_IS_UNLOCKED,
        CMD_LOCK,
        CMD_SIGN_MESSAGE,
        CMD_GET_WALLET_ADDRESS,
        CMD_GET_INIT_CODE,
        CMD_SIGN_OFFCHAIN,
        CMD_OFFCHAIN_STATUS,
        CMD_FW_BEGIN,
        CMD_FW_CHUNK,
        CMD_FW_COMMIT,
        CMD_FW_STATUS,
        CMD_FW_ABORT,
        CMD_SIGN_USEROP_BATCH,
        CMD_TEST_PIN_LOCKOUT,
        CMD_TZIC_STATUS,
    ];

    let mut i = 0;
    while i < cmds.len() {
        let mut j = i + 1;
        while j < cmds.len() {
            assert!(
                cmds[i] != cmds[j],
                "CMD constant collision — two gateway commands share the same u32 value. \
                 Check the recent additions to the CMD_* block in proto/src/lib.rs."
            );
            j += 1;
        }
        i += 1;
    }
};
