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
// CoW Swap on-device decode — canonical inner-calldata length.
// The native verifier length-checks the `setPreSignature` calldata directly.
// ---------------------------------------------------------------------------

/// Canonical `setPreSignature` inner-calldata length for the CoW v3 on-device
/// decode (selector + ABI-encoded params), 164 bytes.
pub const COW_PRESIGN_CALLDATA_LEN: usize = 164;

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

/// CMD_GET_PIN_ATTEMPT_LOG — why each PIN attempt was consumed.
///
/// `gated_unlock` PRE-CHARGES the page-124 counter before the secure element
/// judges the PIN, so the counter alone cannot distinguish a legitimate
/// wrong-PIN burn from a fault that burned an attempt without ever reaching a
/// verdict. This returns the reason for each recent attempt.
///
/// Motivated by #715: a pq1 unit displayed "PIN locked" after the operator
/// entered the CORRECT PIN, and nothing recorded how ten attempts had been
/// spent — shipping images omit `debug-log` because semihosting `BKPT`
/// hard-faults on a sealed unit, so the event left no trace at all.
///
/// RAM-resident: it explains a lockout on a device that is still powered, and
/// does NOT survive a reset. Read it BEFORE power-cycling a suspect unit.
///
/// Discloses reason codes and the pre-attempt counter value — no secret, no
/// PIN material. An attacker with USB access can already read the remaining
/// count via `CMD_GET_REMAINING`, so this grants no new capability.
///   in_ptr  → ignored
///   out_ptr → `PIN_ATTEMPT_LOG_LEN` bytes:
///     `[0]`     format version (1)
///     `[1]`     entry count
///     `[2..4]`  entries dropped since boot (u16 BE) — a non-zero value means
///               the ring wrapped and the earliest cause is gone
///     `[4..]`   `(reason, pre_count)` pairs, OLDEST FIRST, zero padded
///   Reason codes: 1 ok+reset, 2 ok-but-reset-FAILED, 3 wrong PIN,
///   4 already at max, 5 precharge failed, 6 no verdict, 7 counter unstable,
///   8 duress wipe.
/// Returns `NscStatus::Ok`, or `NscStatus::InvalidPointer` on validation
/// failure.
pub const CMD_GET_PIN_ATTEMPT_LOG: u32 = 4;

/// Byte count of the [`CMD_GET_PIN_ATTEMPT_LOG`] response. Mirrors
/// `secure/src/pin_attempt_log.rs::SERIALISED_LEN` (4 + 16 * 2).
pub const PIN_ATTEMPT_LOG_LEN: usize = 36;
// CMD 4 reserved (was CMD_SIGN in v1)
// CMD 5 reserved; do not reuse this frozen protocol value.
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
/// On success the secure world would write a 4,008-byte SPHINCS+C10
/// signature into the NS output buffer. (Historical note: pre-C10 this
/// produced a 17,088-byte generic SLH-DSA-128f signature; the all-C10
/// cutover replaced that with the custom 4,008-byte C10 parameter set.)
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
///   * **`OFFCHAIN_KIND_RAW32` (0)** — companion sends the dapp's RAW
///     32-byte hash `H` directly (e.g. an EIP-712 typed-data digest the
///     firmware can't break apart) — i.e. the exact value the dapp passes
///     to `isValidSignature`, NOT a pre-nested value. The firmware
///     applies the Solady replay-safe EIP-712 nesting to `H` itself
///     (`replay_safe_hash`) and signs that, then renders `H` in hex.
///     Fallback for when the message text is unavailable. The firmware —
///     never the companion — performs the nesting, so the signed value is
///     always keccak-bound to the wallet domain and can never collide
///     with the bare SHA-256 `sphincsDigest` the on-chain Type-1/Type-2
///     UserOp path verifies (raw32 UserOp-forgery fix, 2026-06-11).
///
/// In every mode, on-chain verification works because Solady's
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
///       [13..14)  kind           (u8: 0=raw32, 1=personal_sign,
///                                 2=eip712_typed)
///       [14..16)  payload_len    (u16 BE)
///       [16..17)  flags          (u8 — bit 0 = `OFFCHAIN_FLAG_ACCOUNT_DEPLOYED`;
///                                 other bits MUST be zero)
///       [17..)    payload (`payload_len` bytes — for raw32 the dapp's
///                 RAW 32-byte hash H (firmware nests it, does NOT sign
///                 it bare); for personal_sign the raw message; for
///                 eip712_typed the domain/type/encoded-data + bundle)
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
/// ## Wire format v2 (all integers big-endian unless noted)
///
/// ```text
///   [  0..  8)  chain_id            u64 BE
///   [  8.. 12)  flags               u32 BE   (same layout as CMD_SIGN_USEROP)
///   [ 12.. 32)  sender              20 B
///   [ 32.. 52)  entry_point         20 B
///   [ 52.. 84)  nonce               u256 BE
///   [ 84..116)  call_gas_limit      u256 BE
///   [116..148)  verification_gas    u256 BE
///   [148..180)  pre_verification    u256 BE
///   [180..212)  max_fee_per_gas     u256 BE
///   [212..244)  max_prio_per_gas    u256 BE
///   [244..276)  paymaster_data_hash sha256 (SHA256_EMPTY when absent)
///   [276..277)  wire_version        u8  == SIGN_USEROP_BATCH_WIRE_VERSION (2)
///   [277..278)  batch_count         u8 (1..=MAX_BATCH_TXS)
///   [278..   )  repeat batch_count times:
///                 [20]              to_address
///                 [32]              value (u256 BE)
///                 [ 2]              data_len (u16 BE, ≤ MAX_TX_LEN)
///                 [data_len]        data
///   [...     )  trailer_count u8 (0..=MAX_TRAILERS_PER_BATCH)
///   [...     )  repeat trailer_count times:
///                 [ 1]              kind   u8 (1..=8; see TRAILER_KIND_*)
///                 [ 1]              tx_idx u8 (0..batch_count-1 for live kinds 1, 3..=7;
///                                              TRAILER_TX_IDX_BATCH_WIDE (0xff) for kind 8)
///                 [ 2]              len    u16 BE  (bounded per-kind by the
///                                              secure-side dispatch table)
///                 [len]             trailer bytes
/// ```
///
/// Each live per-tx kind (ERC-20, native CoW order, Safe v1, selector curated,
/// selector self-attest, ERC-7730) routes to the inner-tx specified by
/// `tx_idx`; the firmware verifies, FI-cross-checks the binding, and
/// passes the result into `pick_sign_pages` for that inner-tx. Name
/// bundles (kind 8) are batch-wide and accumulate into a single
/// `NameResolver`. Reserved kind 2 is rejected at every length. Sum of all
/// `len` is bounded by `TRAILERS_TOTAL_MAX_LEN`.
/// Curated and self-attest are mutually exclusive per `tx_idx`.
///
/// Cutover from v1 (single optional ERC-7730 trailer at the tail): hard.
/// The firmware refuses `wire_version != 2` with `InvalidPointer`.
/// Companions must check device protocol version before sending.
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
// with a USB-command server that the fixture drives for reversible component
// acceptance. A pass does not authorize or precede any currently executable
// irreversible ceremony; factory_provisioning is quarantined. See
// `docs/provisioning/factory-prodtest.md` for the full command reference + fixture
// integration guide.
//
// Phase A (landed 2026-05-19): GET_ID + DISPLAY_PATTERN
// Supported profile: GET_ID, DISPLAY_PATTERN, SAES, TRNG, both SE
// handshakes, USB loopback, and buttons are required. BHK and FLASH_RW are
// stable negative-capability probes and remain unsupported.
// ---------------------------------------------------------------------------

/// Maximum prodtest command response data carried in the NS short-response
/// buffer. The buffer is 256 bytes and every response reserves two trailing
/// bytes for the ISO 7816 status word, leaving 254 bytes of command data.
pub const PRODTEST_MAX_RESPONSE_DATA_LEN: usize = 254;

/// CMD_PRODTEST_GET_ID — returns 24 bytes:
///   [0..12]   STM32 chip UID (`0x0BFA_0700`, 96 bits per RM0456)
///   [12..16]  Firmware version (u32 LE — host fixture's traceability DB)
///   [16..24]  Reserved (zeroes today; future: build-hash prefix)
/// Always succeeds; the response bytes are the canonical chip-ID for the
/// fixture's per-unit traceability database.
pub const CMD_PRODTEST_GET_ID: u32 = 100;

/// CMD_PRODTEST_DISPLAY_PATTERN — render a known full-screen NV3007 LCD test
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
///             `SAES-ECB(DHUK, b"PQSIGNER-SAES-v1")`). Used by the fixture's
///             per-die-uniqueness check + factory traceability DB.
/// Returns `NscStatus::Ok` on success, `NscStatus::InternalError` if the
/// SAES round-trip fails (silicon defect or wrong RDP state).
pub const CMD_PRODTEST_SAES_SELFTEST: u32 = 102;

/// CMD_PRODTEST_BHK_SELFTEST — reserved negative-capability check. The
/// reversible prodtest profile never enables or provisions BHK.
///   in_ptr  → ignored
///   out_ptr → 8 zero diagnostic bytes
/// Returns `NscStatus::InternalError`. A fixture records this exact result as
/// `SKIP_UNSUPPORTED`; `Ok` is a profile-drift failure, never a pass.
pub const CMD_PRODTEST_BHK_SELFTEST: u32 = 103;

/// CMD_PRODTEST_FLASH_RW — reserved negative-capability check. The reversible
/// profile has no writable test-page authority and performs no flash write.
///   in_ptr  → 4 bytes test pattern (u32 LE; 0xDEADBEEF is the canonical
///             value used by the fixture)
///   out_ptr → ignored
/// Returns `NscStatus::InternalError`. A fixture records this exact result as
/// `SKIP_UNSUPPORTED`; `Ok` is a profile-drift failure, never a pass.
pub const CMD_PRODTEST_FLASH_RW: u32 = 104;

/// CMD_PRODTEST_TRNG_SAMPLE — return raw bytes from the MCU TRNG (no SE
/// XOR mix) for the fixture's statistical entropy check (χ² / Shannon
/// estimator / etc.). Capped at `PRODTEST_MAX_RESPONSE_DATA_LEN` so the
/// 256-byte NS response buffer retains its two-byte status word.
///   in_ptr  → 4 bytes byte count (u32 LE, must be 1..=254)
///   out_ptr → N bytes of TRNG output
/// Returns `NscStatus::Ok` on success, `NscStatus::InvalidParameter` if
/// count is 0 or > 254, `NscStatus::InternalError` on TRNG fault.
pub const CMD_PRODTEST_TRNG_SAMPLE: u32 = 105;

/// CMD_PRODTEST_OPTIGA_HANDSHAKE — exercise the full IFX I²C + APDU
/// stack against the OPTIGA Trust M. Lazily runs OpenApplication (no
/// PBS, no shielded connection) then `GetRandom(16)`. Catches missing
/// chip / broken solder / I²C wiring / RST line / clock issues during
/// reversible acceptance. It does not select an E140 actor/order or authorize
/// any follow-on write; that lifecycle remains OPEN.
///   in_ptr  → ignored
///   out_ptr → 16 bytes of OPTIGA RNG output
/// Returns `NscStatus::Ok` on success, `NscStatus::InternalError` on
/// any step of the I²C / APDU / RNG roundtrip failing.
pub const CMD_PRODTEST_OPTIGA_HANDSHAKE: u32 = 106;

/// CMD_PRODTEST_SE050_HANDSHAKE — exercise the SE050 T=1' + APDU stack.
/// Runs `interface_reset` + `GetRandom(16)` over the default channel
/// (no SCP03, no UserID PIN). Catches missing chip / broken solder /
/// I²C wiring / ENA line / power-rail issues during reversible acceptance.
/// It does not authorize an SCP03 rotation or select the still-OPEN final
/// credential protocol.
///   in_ptr  → ignored
///   out_ptr → 16 bytes of SE050 RNG output
/// Returns `NscStatus::Ok` on success, `NscStatus::InternalError` on
/// any step of the I²C / T=1' / APDU / RNG roundtrip failing.
pub const CMD_PRODTEST_SE050_HANDSHAKE: u32 = 107;

/// CMD_PRODTEST_USB_LOOPBACK — echo N bytes back to the host. Catches
/// USB byte-corruption / HID fragmentation / buffer-overflow bugs in
/// the firmware's USB stack. The fact that the firmware RECEIVED the
/// command already proves USB RX works; this command proves TX +
/// round-trip integrity for non-trivial payloads.
///   in_ptr  → N bytes input (caller-allocated)
///   out_ptr → N bytes output (caller-allocated; byte-identical to input)
///   arg2    → N (length, 1..=254)
/// Returns `NscStatus::Ok` on success, `NscStatus::InvalidPointer` if
/// N is 0 or > 254 or pointer validation fails.
pub const CMD_PRODTEST_USB_LOOPBACK: u32 = 108;

/// CMD_PRODTEST_BUTTON_TEST — interactive 3-step button verification.
/// The firmware displays "PRESS LEFT" / "PRESS RIGHT" / "PRESS BOTH"
/// on the NV3007 LCD in sequence; the operator presses the indicated button
/// (or both) within `BUTTON_TEST_TIMEOUT_MS = 10_000` per step. Catches
/// mechanically dead buttons, broken solder joints, and L/R wires
/// swapped at the connector.
///   in_ptr  → ignored
///   out_ptr → 4 bytes (step_status:1 + reserved:3). Step status:
///     0x00 — all 3 steps passed
///     0x11 — step 1 (LEFT) timeout (no press within 10 s)
///     0x12 — step 1 (LEFT) wrong button (RIGHT pressed instead — swapped wires)
///     0x21 — step 2 (RIGHT) timeout
///     0x22 — step 2 (RIGHT) wrong button (LEFT pressed instead)
///     0x31 — step 3 (BOTH) timeout
/// Returns `NscStatus::Ok` if step_status == 0x00, `NscStatus::Internal-
/// Error` otherwise. Upper nibble = step (1/2/3); lower nibble = error
/// (1=timeout, 2=wrong button) so the fixture's error table is compact.
pub const CMD_PRODTEST_BUTTON_TEST: u32 = 109;

/// CMD_PRODTEST_RGB_TEST — light the `pq1` board's 9 RGB LEDs through the
/// AW21036 on I²C2 (`0x34`) and report what the part said back. Catches a
/// dead/unsoldered driver, a bad `RGB_EN` line, swapped R/G/B channels, and
/// dead individual LEDs (the operator sees the colour).
///
/// The response is deliberately self-localizing, because "the LEDs are dark"
/// otherwise has half a dozen causes: it carries a full bus scan (the AW99703
/// backlight at `0x36` is a positive control for the bus, and `0x1C` is the
/// AW21036 broadcast address answering as a second witness), both readable
/// identity registers, and an ACK tally over the 58 register writes.
///   in_ptr  → 6 bytes `[r, g, b, gcc, en, reserved]`
///     `r`/`g`/`b` — brightness written to every wired LED's R/G/B channel.
///       All-zero is the "off" case and still writes/ACKs every register.
///     `gcc`      — global current; `0` selects the driver's conservative
///                  default (full scale on 27 channels is ~0.46 A).
///     `en`       — `1` drives `RGB_EN` high (normal), `0` leaves it low as the
///                  negative control for that pin. Note the part's I²C stays
///                  accessible in standby, so an ACK with `en = 0` is expected
///                  and proves nothing; only the *functional* difference
///                  (identical writes, dark at `0`, lit at `1`) tests the pin.
///   out_ptr → 24 bytes
///     `[0..16]` — 7-bit address bitmap; address `a` is bit `a % 8` of byte `a / 8`
///     `[16]`    — `VER` (`0x7E`) readback, `0xA8` when healthy, `0xFF` if the
///                 addressing phase was not ACKed at all
///     `[17]`    — `RESET` (`0x7F`) readback, `0x18` when healthy, `0xFF` as above
///     `[18]`    — register writes ACKed
///     `[19]`    — register writes attempted
///     `[20]`    — `RGB_EN` read back from `IDR` (0/1)
///     `[21]`    — the `GCC` actually programmed
///     `[22..24]`— reserved, zero
/// Returns `NscStatus::Ok` when `VER == 0xA8` and every write was ACKed,
/// `NscStatus::InvalidPointer` if either buffer fails NS-pointer validation,
/// and `NscStatus::InternalError` otherwise — **with the output still
/// written**, so the fixture always gets the diagnostic instead of a bare
/// status. On a board with no RGB driver the output is all-zero and the status
/// is `InternalError` (there is no `NotSupported` code in this ABI).
pub const CMD_PRODTEST_RGB_TEST: u32 = 110;

/// Byte counts for [`CMD_PRODTEST_RGB_TEST`]'s two buffers.
pub const PRODTEST_RGB_IN_LEN: usize = 6;
pub const PRODTEST_RGB_OUT_LEN: usize = 24;

/// CMD_PRODTEST_RGB_OSD — run the AW21036's per-channel **open/short
/// detection** and return the raw status bitmaps. This is the machine-checkable
/// dead-LED test: it names the failing channel by index instead of relying on
/// an operator seeing a wrong colour, which is what a certification or
/// end-of-line fixture needs.
///
/// Two properties make the result trustworthy, and both matter more than the
/// measurement itself:
///
/// 1. **Both `OSDE` encodings are returned, because the datasheet contradicts
///    itself.** Its prose says `OSDE=10` enables open detection and `11` short;
///    the `OSDCR` register table says the opposite. Firmware does not guess.
/// 2. **The result is self-validating.** `LED28..LED36` have no LED attached on
///    this board, so they MUST read open. Whichever mode flags those channels is
///    the open-detect encoding; if *neither* does, detection did not run and the
///    only honest verdict is inconclusive — never a pass. A certification gate
///    that can pass vacuously is worse than no gate.
///
/// The response carries the wired/total channel counts so the host derives that
/// control set from the device instead of duplicating a board constant.
///   in_ptr  → 4 bytes `[gcc, en, reserved, reserved]`
///     `gcc` — bias current; `0` selects the driver's ~1 mA default. The
///             datasheet asks for ~1 mA per LED during detection.
///     `en`  — `1` drives `RGB_EN` high; `0` is the negative control.
///   out_ptr → 24 bytes
///     `[0..5]`   — `OSST0..4` after `OSDE=0b10`
///     `[5..10]`  — `OSST0..4` after `OSDE=0b11`
///                  In both, `LED(k)` is bit `(k-1) % 8` of byte `(k-1) / 8`.
///     `[10]`     — `VER` readback (`0xA8` healthy, `0xFF` if unreadable)
///     `[11]`     — register writes ACKed
///     `[12]`     — register writes attempted
///     `[13]`     — `RGB_EN` read back from `IDR`
///     `[14]`     — the `GCC` actually programmed
///     `[15]`     — wired channel count (LEDs physically present)
///     `[16]`     — total channel count the part drives
///     `[17..24]` — reserved, zero
/// The command leaves the board dark. Returns `NscStatus::Ok` when the part
/// identified itself and every write was ACKed, `NscStatus::InvalidPointer` on
/// buffer validation failure, `NscStatus::InternalError` otherwise — with the
/// output still written. Note `Ok` means *the scan ran*, not *the LEDs are
/// good*: the pass/fail over channels is the host's call from the bitmaps.
pub const CMD_PRODTEST_RGB_OSD: u32 = 111;

pub const PRODTEST_RGB_OSD_IN_LEN: usize = 4;
pub const PRODTEST_RGB_OSD_OUT_LEN: usize = 24;

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

// ---------------------------------------------------------------------------
// USB APDU protocol v2 — PQSigner native
// ---------------------------------------------------------------------------

/// v2 class byte. Companion tries 0xF0 first; SW_CLA_NOT_SUPPORTED means
/// legacy firmware that only speaks CLA 0xE0.
pub const APDU_CLA_V2: u8 = 0xF0;

// -- Device info & status (0x01-0x0F) --
pub const INS_V2_GET_DEVICE_INFO: u8 = 0x01;
pub const INS_V2_GET_STATUS: u8 = 0x02;
pub const INS_V2_GET_PIN_ATTEMPT_LOG: u8 = 0x03;

/// `GET_DEVICE_INFO.capabilities` bit 0: the unified UserOperation signing
/// command is available.
pub const CAP_SIGN_USEROP: u32 = 1 << 0;
/// `GET_DEVICE_INFO.capabilities` bit 2: contract-call ERC-7730 trailers may
/// use the versioned two-bundle proof-set envelope. Bit 1 is retired and MUST
/// remain clear. Companions must gate the envelope on this bit rather than the
/// placeholder firmware-version bytes.
pub const CAP_ERC7730_PROOF_SET: u32 = 1 << 2;
/// Capability bitmap emitted by the current firmware.
pub const DEVICE_CAPABILITIES: u32 = CAP_SIGN_USEROP | CAP_ERC7730_PROOF_SET;

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
/// GET_WALLET_ADDRESS — return the 20-byte CREATE2-predicted wallet
/// address for `account_index`. APDU body: empty (legacy, index 0),
/// 4 bytes (`account_index` u32 BE), or — PROTOCOL_VERSION 0x0202+ —
/// 5 bytes with a trailing `show` flag: `0` behaves as absent; `1`
/// makes the device paint the full EIP-55 address on its OLED behind a
/// physical confirm BEFORE returning it (#472; user cancel →
/// `NscStatus::UserRejected`, no address bytes). Any flag value above 1
/// is rejected with SW_WRONG_DATA.
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

// ---------------------------------------------------------------------------
// Prodtest INS codes (companion → device, prodtest builds only)
//
// One INS per `CMD_PRODTEST_*` so each command gets its own LC=255
// budget without a 4-byte cmd_id overhead inside the APDU body. The
// numeric mapping `INS = 0x80 + (CMD_PRODTEST_* - 100)` is mechanical
// — no code reads it that way, but the operator manual + factory DB
// reports keep it readable. These INSes are wired into the NS USB
// command dispatcher only under `#[cfg(feature = "prodtest")]`, so
// production firmware does not expose them on the wire.
// ---------------------------------------------------------------------------

pub const INS_V2_PRODTEST_GET_ID: u8 = 0x80;
pub const INS_V2_PRODTEST_DISPLAY_PATTERN: u8 = 0x81;
pub const INS_V2_PRODTEST_SAES_SELFTEST: u8 = 0x82;
pub const INS_V2_PRODTEST_BHK_SELFTEST: u8 = 0x83;
pub const INS_V2_PRODTEST_FLASH_RW: u8 = 0x84;
pub const INS_V2_PRODTEST_TRNG_SAMPLE: u8 = 0x85;
pub const INS_V2_PRODTEST_OPTIGA_HANDSHAKE: u8 = 0x86;
pub const INS_V2_PRODTEST_SE050_HANDSHAKE: u8 = 0x87;
pub const INS_V2_PRODTEST_USB_LOOPBACK: u8 = 0x88;
pub const INS_V2_PRODTEST_BUTTON_TEST: u8 = 0x89;
pub const INS_V2_PRODTEST_RGB_TEST: u8 = 0x8A;
pub const INS_V2_PRODTEST_RGB_OSD: u8 = 0x8B;

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
/// to ~2³² user transactions before becoming permanently frozen.
///
/// **CORRECTED 2026-07-26 (two claims here were false — external review,
/// verified at source):**
///
/// 1. **It is NOT enforced by the firmware.** This doc previously said the
///    constant was "Sourced from this crate by ... the firmware (pre-emptive
///    refusal in `cmd_sign_userop`)". There is no such refusal: every
///    occurrence of `MAX_BOOTSTRAP_USES` under `secure/` is a COMMENT, and
///    `cmd_sign_userop` maintains no bootstrap counter. Enforcement is
///    **on-chain only** (post-bump, `PQSmartWallet.validateUserOp` /
///    `PQMultiOwnable._bumpBootstrapUses`).
/// 2. **"Well inside the birthday margin" was a PER-CHAIN statement applied to
///    a PER-KEY question.** Slot keys are chain-bound, so 65,536 is a true
///    per-key cap. The **bootstrap key is chain-INDEPENDENT** (invariant #6,
///    for cross-chain address stability), so across `C` chains its per-key
///    budget is `C · 65,536` and its generic multi-target floor degrades as
///    `96 − 2·log₂ C` bits (94 at C=2, 88 at C=16). See the P14 caveat in
///    `contracts/verification/lean/.../Quantitative.lean`.
///
/// Note also that this cap bounds ACCEPTED ON-CHAIN SUBMISSIONS, not signatures
/// PRODUCED: the factory deploy signature, `CMD_GET_INIT_CODE`, and ERC-6492
/// counterfactual signatures all release bootstrap-key signatures that this
/// counter never sees. It was never a lifetime per-key signature bound.
/// Realistic bootstrap usage is tens of signatures (slot rotations only).
///
/// Sourced from this crate by the Solidity wallet (post-bump enforcement in
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

/// Maximum `encoded_data` length carried inside a
/// `OFFCHAIN_KIND_EIP712_TYPED` payload — bounded so the secure-side
/// hash construction never sees an unreasonable struct body. 512 B
/// covers every well-known typed-data envelope (Permit, OrderHash,
/// CowSwap GPv2Order, Safe SignMessage) with headroom; Phase 5
/// audits should revisit if a real use case needs more.
pub const MAX_OFFCHAIN_EIP712_ENCODED_DATA_LEN: usize = 512;

/// Maximum payload length for `OFFCHAIN_KIND_EIP712_TYPED`. Layout:
/// `domainSep_present(2) + domainSeparator(32) + primaryTypeHash(32) +
/// encoded_data_len(2) + encoded_data + erc7730_trailer(2 + payload)`.
pub const MAX_OFFCHAIN_EIP712_TYPED_LEN: usize =
    2 + 32 + 32 + 2 + MAX_OFFCHAIN_EIP712_ENCODED_DATA_LEN
        + 2 + ERC7730_LEGACY_BUNDLE_MAX_LEN;

/// Maximum length of the descriptor-selected display-witness stream carried in
/// the legacy-named `nested_blob` section of an
/// `OFFCHAIN_KIND_EIP712_TYPED_V3` payload. Authenticated IR traversal selects
/// each record grammar: nested EIP-712 structs use their existing DFS records,
/// while explicitly enrolled top-level strings use `[u16 len][exact bytes]`.
/// Nested records remain bounded by the pinned member count; strings are
/// independently bounded to 128 printable-ASCII bytes by the renderer. The
/// device reconciles both authenticated record counts and requires the shared
/// cursor to consume this section exactly. The 2 KiB wire cap is unchanged.
pub const MAX_OFFCHAIN_EIP712_NESTED_LEN: usize = 2048;

/// Maximum payload length for `OFFCHAIN_KIND_EIP712_TYPED_V3` — the v0x03
/// variant that inserts a descriptor-selected display-witness section between
/// `encoded_data` and the trailer. Layout:
/// `domainSep_present(2) + domainSeparator(32) + primaryTypeHash(32) +
/// encoded_data_len(2) + encoded_data +
/// nested_blob_len(2) + nested_blob + erc7730_trailer(2 + payload)`.
pub const MAX_OFFCHAIN_EIP712_TYPED_V3_LEN: usize =
    2 + 32 + 32 + 2 + MAX_OFFCHAIN_EIP712_ENCODED_DATA_LEN
        + 2 + MAX_OFFCHAIN_EIP712_NESTED_LEN
        + 2 + ERC7730_LEGACY_BUNDLE_MAX_LEN;

/// Maximum input length the gateway will accept for `CMD_SIGN_OFFCHAIN`.
/// Sized for the largest valid request across all kinds.
pub const SIGN_OFFCHAIN_INPUT_MAX_LEN: usize = SIGN_OFFCHAIN_HEADER_LEN
    + max_usize(
        MAX_OFFCHAIN_PERSONAL_SIGN_LEN,
        max_usize(MAX_OFFCHAIN_EIP712_TYPED_LEN, MAX_OFFCHAIN_EIP712_TYPED_V3_LEN),
    );

/// `const`-evaluable `max` over `usize`. Not in core::cmp yet.
const fn max_usize(a: usize, b: usize) -> usize {
    if a >= b { a } else { b }
}

/// Off-chain sign request kinds. See [`CMD_SIGN_OFFCHAIN`] for the
/// hash-construction details of each.
pub const OFFCHAIN_KIND_RAW32: u8 = 0;
pub const OFFCHAIN_KIND_PERSONAL_SIGN: u8 = 1;
/// EIP-712 typed-data with an ERC-7730 clear-signing descriptor trailer.
/// The companion supplies `domainSeparator || primaryTypeHash ||
/// encoded_data || erc7730_trailer`; the secure world cross-checks the
/// trailer's IR binding against the supplied domain and renders the
/// descriptor's clear-signing pages instead of a raw hex hash.
pub const OFFCHAIN_KIND_EIP712_TYPED: u8 = 2;
/// EIP-712 typed-data whose descriptor requires auxiliary authenticated-display
/// evidence (a nested struct or an explicitly enrolled top-level string
/// preimage). Wire-identical to
/// `OFFCHAIN_KIND_EIP712_TYPED` except it UNCONDITIONALLY inserts a
/// `nested_blob_len(2) || nested_blob` section between `encoded_data` and the
/// trailer (`nested_blob_len == 0` when the format needs no witness). The
/// signed digest is byte-identical to `OFFCHAIN_KIND_EIP712_TYPED`
/// (`keccak(0x1901 || domainSep || keccak(primaryTypeHash || encoded_data))`);
/// the `nested_blob` feeds the DISPLAY binding ONLY — the device verifies each
/// nested hashStruct record or string preimage against its exact committed word
/// before rendering it. A separate wire kind (not a trailer
/// flag) so the parser knows the post-`ed` `u16` is `nested_blob_len`, not
/// `trailer_len`, WITHOUT first reading the not-yet-reached trailer (design §10
/// E3). v0x02 companions stay on `OFFCHAIN_KIND_EIP712_TYPED` unchanged.
pub const OFFCHAIN_KIND_EIP712_TYPED_V3: u8 = 3;

// ─── ERC-7730 clear-signing descriptor trailer ───────────────────────
//
// A legacy trailer is the wire shape consumed by
// `pqsigner_erc7730::bundle::verify_erc7730_bundle`:
//   ir_len(2 BE) || ir || leaf_index(4 BE) || proof_depth(4 BE) || proof
// Contract-call signing may instead carry the proof-set envelope:
//   magic(0xe773) || version(1) || count(2) ||
//   2 * (legacy_bundle_len(u16 BE) || legacy_bundle)
// Framed by the dispatcher as `[u16 BE len][payload]` between the
// self-attest trailer and the names trailer on the sign-input wire.

/// Current ERC-7730 trailer version. Wire-bumpable; the on-device
/// parser keys off the IR `schema_ver` byte (1 today) rather than this
/// constant, but the constant is exposed so a companion can refuse to
/// emit a trailer the firmware will reject.
pub const ERC7730_TRAILER_VERSION: u8 = 0x01;
/// Cap on a single IR blob. Mirrors `pqsigner_erc7730::ir::MAX_IR_LEN`.
pub const ERC7730_IR_MAX: usize = 4096;
/// Cap on Merkle proof depth. Mirrors
/// `pqsigner_erc7730::bundle::MAX_PROOF_DEPTH`.
pub const ERC7730_PROOF_MAX_DEPTH: usize = 32;
/// Maximum length of one legacy descriptor bundle. Identical to
/// `pqsigner_erc7730::bundle::MAX_ERC7730_BUNDLE_LEN`.
pub const ERC7730_LEGACY_BUNDLE_MAX_LEN: usize =
    2                                  // ir_len prefix
    + ERC7730_IR_MAX
    + 4 + 4                            // leaf_index + proof_depth
    + ERC7730_PROOF_MAX_DEPTH * 32;
/// Versioned proof-set magic. This cannot prefix a valid legacy bundle because
/// `0xe773` is greater than [`ERC7730_IR_MAX`].
pub const ERC7730_PROOF_SET_MAGIC: u16 = 0xe773;
/// Proof-set envelope syntax version. Independent of
/// [`ERC7730_TRAILER_VERSION`].
pub const ERC7730_PROOF_SET_VERSION: u8 = 1;
/// The first envelope format carries exactly an outer and one distinct child.
pub const ERC7730_PROOF_SET_COUNT: usize = 2;
/// Maximum contract-call ERC-7730 trailer payload:
/// `magic(2) + version(1) + count(1) + 2 * (len(2) + legacy(5130))`.
pub const ERC7730_MAX_TRAILER_LEN: usize =
    4 + ERC7730_PROOF_SET_COUNT * (2 + ERC7730_LEGACY_BUNDLE_MAX_LEN);

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
    0xe8, 0xCE, 0x78, 0xCD, 0x97, 0x64, 0x97, 0x44, 0x7F, 0xF8,
    0xB7, 0x6c, 0x71, 0xb5, 0x9a, 0xE4, 0x2A, 0xf0, 0xd4, 0x52,
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
    0xac, 0x0c, 0x44, 0xb6, 0xd0, 0x6f, 0x67, 0x8e,
    0xb3, 0x50, 0x42, 0x6f, 0x4d, 0x0d, 0x7a, 0x89,
    0xcc, 0x72, 0x9d, 0xcb, 0x15, 0x6d, 0xe3, 0x03,
    0xfa, 0x77, 0xa7, 0x75, 0x2c, 0xcc, 0x22, 0xb6,
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
/// and slot-0 public keys, folds its hash into the slot-0 Type 2 `userOpHash`,
/// and emits the initCode so the companion can populate
/// `UserOperation06.initCode`. This is the first-deploy path:
/// `slot_index == 0` and `FLAG_REGISTER_SLOT` MUST be clear because the
/// factory installs slot 0 atomically. The two flags are mutually exclusive.
pub const FLAG_INCLUDE_INIT_CODE: u32 = 0x8000_0000;

/// Flags bit 30 — set by the companion to ask the firmware to emit a Type 1
/// slot-registration frame before the Type 2 user-tx frame.
///
/// The firmware is stateless with respect to slot selection: it does not
/// track whether `(chain_id, slot_index)` has been registered on-chain. The
/// companion app keeps that bookkeeping. After the reviewed wire-version bump
/// described below, this flag is intended for the first sign with a new
/// `(chain_id, slot_index)` pair or rotation after the current slot approaches
/// the on-chain `MAX_SLOT_USES` cap.
///
/// Wire-v2 caveat: the response does not yet expose the 64-byte new slot public
/// key required to reconstruct the signed `addOwnerBytes(bytes)` calldata.
/// Seedless production companions must therefore refuse this flag until a
/// reviewed protocol bump supplies that binding material; they must not submit
/// a no-op Type-1 UserOp or repeatedly harvest fresh bootstrap signatures.
///
/// When clear, firmware emits Type 2 only. A companion may submit that UserOp
/// only for slot 0 in the factory-deploy flow or a slot it has independently
/// established is already registered on-chain.
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
/// | 12  | 20  | sender (must equal `GET_WALLET_ADDRESS(account_index)`; firmware recomputes and hard-rejects mismatches) |
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
/// | 332+N+B | 2 | reserved_v1_len (u16 BE; MUST be 0) |
/// | 334+N+B | 0 | reserved compatibility slot (no bytes parsed) |
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

// Wire slot 1 is reserved for compatibility and its length MUST remain zero.

// ═══════════════════════════════════════════════════════════════════════════
//   CoW Protocol / GPv2Settlement — EIP-712 clear-sign (on-device decode)
// ═══════════════════════════════════════════════════════════════════════════
//
// When the companion sends a CoW UserOp whose inner calldata is
// `setPreSignature(orderUid, true)` on GPv2Settlement, it attaches a CoW
// order trailer (kind `TRAILER_KIND_COW_ORDER`, value 3) after the reserved
// zero-length compatibility slot:
//
//   [cow_len u16 BE] [cow_trailer]
//
// where `cow_trailer` layout is:
//
//   [  0.. 204)  canonical    — 204-byte packed GPv2Order struct.
//   [204.. 206)  sell_len u16 BE
//   [206.. 206+sell_len)  sell_bundle — ERC-20 metadata + Merkle proof
//                                       for the sell token (see
//                                       `pqsigner_tx::erc20::bundle`).
//   [..    +2 )  buy_len  u16 BE
//   [..      )   buy_bundle  — ERC-20 metadata + Merkle proof for the
//                              buy token.
//
// A `*_len == 0` leg carries no bundle: the firmware renders that leg
// as a raw token address + uint256 hex amount (the AddrOnly fallback),
// exactly as it did before any token was in the DB. A canonical-only
// trailer (204 B, no length-prefixed legs) renders both legs AddrOnly.
//
// The secure world natively re-keccaks `canonical` → orderDigest and byte-compares it
// against the calldata's `[100..132)` slice (`cross_check_setpresig_-
// calldata`); that binding is the WYSIWYS trust anchor.
// Each present leg's bundle is Merkle-verified on-device against
// `ERC20_DB_ROOT` (the same root the ERC-20 transfer path uses), and the
// bundle's `(contract, chain_id)` is cross-checked against the canonical
// leg token + chain before its symbol/decimals reach the OLED.

// ─── Trailer length cap ────────────────────────────────────────────────────

/// Per-leg ERC-20 bundle cap. Mirrors `pqsigner_tx::erc20::bundle::
/// MAX_ERC20_BUNDLE_LEN` (64 + 1024 + 32 = 1120); a compile-time assert
/// in `secure/src/nsc/batch_trailers.rs` trips if that constant drifts.
pub const COW_ORDER_BUNDLE_MAX: usize = 1120;

/// Maximum CoW order trailer payload: canonical + two length-prefixed
/// ERC-20 bundles.
pub const COW_ORDER_TRAILER_MAX_LEN: usize =
    EIP712_CANONICAL_LEN + 2 * (2 + COW_ORDER_BUNDLE_MAX);

// ─── Protocol-identity constants ───────────────────────────────────────────

/// Function selector for `setPreSignature(bytes,bool)` on
/// `GPv2Settlement` — companion's calldata[0..4] match against this
/// triggers the mandatory CoW-order gate in the secure world.
pub const SET_PRE_SIGNATURE_SELECTOR: [u8; 4] = [0xec, 0x6c, 0xb1, 0x3f];

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
// calldata*. The firmware natively keccaks (raw_data → data_hash) and (canonical →
// safeTxHash), then byte-compares safeTxHash against
// `inner_data[4..36]`.

/// Function selector for `approveHash(bytes32)` on Safe `Singleton`
/// contracts. Equals `keccak256("approveHash(bytes32)")[..4]`.
pub const APPROVE_HASH_SELECTOR: [u8; 4] = [0xd4, 0xd9, 0xbd, 0xcd];

/// Total length of the `approveHash(bytes32)` calldata: selector +
/// 32-byte hash argument.
pub const APPROVE_HASH_CALLDATA_LEN: usize = 4 + 32;

// ---------------------------------------------------------------------------
// Safe v1.3.0+ `execTransaction(...)` — clear-sign without a separate
// trailer
// ---------------------------------------------------------------------------
//
// `approveHash` carries an *opaque* 32-byte digest in its calldata, so the
// firmware needs a separate `safe_v1` trailer to bring the preimage on-device.
// `execTransaction` is structurally different: the SafeTx fields are encoded
// directly into the function's argument list, so the firmware can decode them
// straight out of `inner_data` and feed the existing Safe renderer — no
// trailer required. The cryptographic story is also different: the wallet is
// not "approving a hash for later", it is the EOA-equivalent that actually
// triggers the Safe to execute, carrying co-signers' approvals in the
// `signatures` argument. The clear-sign view shows what the Safe is about to
// run.

/// Function selector for
/// `execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)`
/// on Safe `Singleton` contracts. Equals
/// `keccak256(<text signature>)[..4] = 0x6a761202`.
pub const EXEC_TRANSACTION_SELECTOR: [u8; 4] = [0x6a, 0x76, 0x12, 0x02];

/// Minimum calldata length for `execTransaction`: selector(4) + 10 head
/// words(320) + two dynamic-length words(64) for `data` and `signatures`.
/// Real calls are at least this long; anything shorter is malformed.
pub const EXEC_TRANSACTION_MIN_CALLDATA_LEN: usize = 4 + 10 * 32 + 2 * 32;

// ---------------------------------------------------------------------------
// Safe `MultiSendCallOnly` — batched SafeTx via DELEGATECALL
// ---------------------------------------------------------------------------
//
// The Safe web UI does not emit a single-call SafeTx for flows that need
// more than one action (e.g. CoW order placement = ERC-20 approve +
// `setPreSignature`). It emits `SafeTx{to = MultiSendCallOnly,
// operation = 1 (DELEGATECALL), data = multiSend(transactions)}` where
// `transactions` is a packed list of records, each
// `operation(1) || to(20) || value(32) || dataLen(32) || data(dataLen)`.
//
// DELEGATECALL executes the target's code in the Safe's own storage
// context, so decoding the payload is only meaningful when the target is
// a known-good MultiSend implementation — hence the address allowlist
// below. The firmware additionally enforces `operation == 0` on every
// record (mirroring MultiSendCallOnly's on-chain revert), so no nested
// delegatecall can ride a record either.

/// Function selector for `multiSend(bytes)` on Safe `MultiSend` /
/// `MultiSendCallOnly` contracts. Equals
/// `keccak256("multiSend(bytes)")[..4]`.
pub const MULTI_SEND_SELECTOR: [u8; 4] = [0x8d, 0x80, 0xff, 0x0a];

/// Canonical `MultiSendCallOnly` deployments the firmware accepts as a
/// SafeTx DELEGATECALL target. CREATE2-deployed, address-identical on
/// every chain of each variant (source: safe-global/safe-deployments,
/// `src/assets/v1.3.0/multi_send_call_only.json` and
/// `v1.4.1/multi_send_call_only.json`, verified 2026-06-12):
///
/// ```text
///   [0]  v1.3.0 canonical  0x40A2aCCbd92BCA938b02010E17A5b8929b49130D
///   [1]  v1.3.0 eip155     0xA1dabEF33b3B82c7814B6D82A79e50F4AC44102B
///   [2]  v1.4.1 canonical  0x9641d764fc13c8B624c04430C7356C1C7C8102e2
/// ```
///
/// Plain `MultiSend` (which permits per-record DELEGATECALL) is
/// deliberately NOT listed: the Safe UI routes all-CALL batches through
/// `MultiSendCallOnly`, and a smaller allowlist fails closed. zkSync
/// variants are excluded (PQ1 does not target zkSync).
pub const MULTISEND_CALL_ONLY_ADDRESSES: [[u8; 20]; 3] = [
    [
        0x40, 0xa2, 0xac, 0xcb, 0xd9, 0x2b, 0xca, 0x93, 0x8b, 0x02, 0x01, 0x0e, 0x17, 0xa5,
        0xb8, 0x92, 0x9b, 0x49, 0x13, 0x0d,
    ],
    [
        0xa1, 0xda, 0xbe, 0xf3, 0x3b, 0x3b, 0x82, 0xc7, 0x81, 0x4b, 0x6d, 0x82, 0xa7, 0x9e,
        0x50, 0xf4, 0xac, 0x44, 0x10, 0x2b,
    ],
    [
        0x96, 0x41, 0xd7, 0x64, 0xfc, 0x13, 0xc8, 0xb6, 0x24, 0xc0, 0x44, 0x30, 0xc7, 0x35,
        0x6c, 0x1c, 0x7c, 0x81, 0x02, 0xe2,
    ],
];

/// Maximum number of packed records the firmware will decode out of one
/// `multiSend(bytes)` payload. The trusted-display page budget is the
/// real binding constraint (a record costs 1 divider page + 1..9 content
/// pages); this cap just bounds the decode loop and keeps the confirm
/// flow reviewable by a human.
pub const MULTISEND_MAX_RECORDS: usize = 6;

/// Real `GPv2VaultRelayer` address on every EVM chain CoW Protocol
/// supports (CREATE2-deployed, address-identical — the contract CoW
/// users grant ERC-20 allowances to). Display-only: when a multiSend
/// record is an ERC-20 `approve` whose spender equals this address, the
/// trusted UI labels the spender "CoW VaultRelayer". Never used as a
/// verification gate.
pub const GPV2_VAULT_RELAYER_ADDRESS: [u8; 20] = [
    0xc9, 0x2e, 0x8b, 0xdf, 0x79, 0xf0, 0x50, 0x7f, 0x65, 0xa3, 0x92, 0xb0, 0xab, 0x46, 0x67,
    0x71, 0x6b, 0xfe, 0x01, 0x10,
];

// ---------------------------------------------------------------------------
// Safe v1.3.0+ singleton management selectors (owner / module / guard /
// fallback). Rendered with per-op intent banners by the secure-side
// `safe_mgmt` decoder when the inner SafeTx targets the Safe itself
// (`canonical.to == canonical.safe_address`). The keccak self-check
// next to `SAFE_TX_TYPEHASH` (in `secure/src/tx/eip712/safe/mod.rs`)
// verifies each constant against its canonical text signature on every
// CI run.
// ---------------------------------------------------------------------------

/// `keccak256("addOwnerWithThreshold(address,uint256)")[..4]`.
pub const SAFE_MGMT_SELECTOR_ADD_OWNER_WITH_THRESHOLD: [u8; 4] = [0x0d, 0x58, 0x2f, 0x13];
/// `keccak256("removeOwner(address,address,uint256)")[..4]`.
pub const SAFE_MGMT_SELECTOR_REMOVE_OWNER: [u8; 4] = [0xf8, 0xdc, 0x5d, 0xd9];
/// `keccak256("swapOwner(address,address,address)")[..4]`.
pub const SAFE_MGMT_SELECTOR_SWAP_OWNER: [u8; 4] = [0xe3, 0x18, 0xb5, 0x2b];
/// `keccak256("changeThreshold(uint256)")[..4]`.
pub const SAFE_MGMT_SELECTOR_CHANGE_THRESHOLD: [u8; 4] = [0x69, 0x4e, 0x80, 0xc3];
/// `keccak256("enableModule(address)")[..4]`.
pub const SAFE_MGMT_SELECTOR_ENABLE_MODULE: [u8; 4] = [0x61, 0x0b, 0x59, 0x25];
/// `keccak256("disableModule(address,address)")[..4]`.
pub const SAFE_MGMT_SELECTOR_DISABLE_MODULE: [u8; 4] = [0xe0, 0x09, 0xcf, 0xde];
/// `keccak256("setGuard(address)")[..4]`.
pub const SAFE_MGMT_SELECTOR_SET_GUARD: [u8; 4] = [0xe1, 0x9a, 0x9d, 0xd9];
/// `keccak256("setFallbackHandler(address)")[..4]`.
pub const SAFE_MGMT_SELECTOR_SET_FALLBACK_HANDLER: [u8; 4] = [0xf0, 0x8a, 0x03, 0x23];

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

/// Wire-format version byte placed at offset 276 of every
/// `CMD_SIGN_USEROP_BATCH` payload. Bump in lockstep with the
/// secure-side parser when the wire format breaks compatibility.
///
/// v1: single optional `[u16 len][erc7730_bundle]` trailer at the tail.
///     Pre-batch-parity build; no longer accepted.
/// v2: TLV-tagged trailer list (every clear-signing kind, per-tx routed).
///     This file's documented format.
pub const SIGN_USEROP_BATCH_WIRE_VERSION: u8 = 2;

/// Fixed-prefix length of the `CMD_SIGN_USEROP_BATCH` payload (header
/// up to and including `batch_count`). Inner-tx blocks follow.
///
/// Layout math: 8 (chain_id) + 4 (flags) + 20 (sender) + 20 (ep) + 32
/// (nonce) + 5×32 (gas) + 32 (paym hash) + 1 (wire_version) +
/// 1 (batch_count) = 278.
pub const SIGN_USEROP_BATCH_HEADER_LEN: usize =
    8 + 4 + 20 + 20 + 32 + 5 * 32 + 32 + 1 + 1; // 278

const _: () = assert!(SIGN_USEROP_BATCH_HEADER_LEN == 278);

/// Per-tx fixed prefix inside the batch payload: `to(20) + value(32) +
/// data_len(2) = 54`.
pub const SIGN_USEROP_BATCH_TX_PREFIX_LEN: usize = 20 + 32 + 2; // 54

// ───────────────────────────────────────────────────────────────────────
// TLV trailer kinds (CMD_SIGN_USEROP_BATCH wire v2)
//
// Each trailer record carries `(kind: u8, tx_idx: u8, len: u16 BE, bytes)`.
// `tx_idx == TRAILER_TX_IDX_BATCH_WIDE (0xff)` is reserved for kind 8
// (name bundles), which apply to every inner tx; other kinds MUST set a
// concrete `tx_idx < batch_count`. Per-kind length caps live in the
// secure-side dispatch table (`secure/src/nsc/batch_trailers.rs`) since
// they reference `pqsigner-tx` types — proto stays dep-free.
// ───────────────────────────────────────────────────────────────────────

/// ERC-20 token metadata bundle. Verifier: `erc20::bundle::verify_erc20_bundle`.
pub const TRAILER_KIND_ERC20: u8 = 1;
/// Reserved compatibility kind. Secure parsing rejects this frozen wire value
/// at every payload length; companions must never emit it.
pub const TRAILER_KIND_RESERVED_V1: u8 = 2;
/// Native CoW order trailer (kind value 3):
/// canonical GPv2Order + two optional ERC-20 bundles, decoded + rendered
/// on-device. orderDigest is keccak-cross-checked against the
/// setPreSignature calldata.
pub const TRAILER_KIND_COW_ORDER: u8 = 3;
/// Safe v1 `approveHash` clear-sign bundle (281-byte canonical SafeTx).
pub const TRAILER_KIND_SAFE_V1: u8 = 4;
/// Verified-selector bundle (curated Merkle DB of selector → text-sig).
pub const TRAILER_KIND_SEL_CURATED: u8 = 5;
/// Self-attested selector bundle (no Merkle proof; keccak self-check only).
pub const TRAILER_KIND_SEL_SELFATTEST: u8 = 6;
/// ERC-7730 clear-signing descriptor.
pub const TRAILER_KIND_ERC7730: u8 = 7;
/// Address-name bundle (batch-wide, `tx_idx == TRAILER_TX_IDX_BATCH_WIDE`).
pub const TRAILER_KIND_NAME: u8 = 8;

/// Sentinel `tx_idx` for batch-wide trailers (currently only kind 8 names).
pub const TRAILER_TX_IDX_BATCH_WIDE: u8 = 0xff;

/// Maximum number of trailer records the firmware accepts in one batch.
/// Worst-case live use: `MAX_BATCH_TXS × 5` (kind 2 is rejected; curated
/// and self-attest are mutually exclusive) + `MAX_NAME_BUNDLES (4)` =
/// 24. Round up to 32 for headroom + power-of-two array alignment.
pub const MAX_TRAILERS_PER_BATCH: usize = 32;

/// Sum-of-lengths bound on the trailer payload bytes in a batch. Covers
/// a realistic full mix — e.g. ERC-7730 + Safe + ERC-20 across multiple
/// inner txs — without enabling the absolute pathological case (every
/// kind on every tx at max length, which would push the SRAM snapshot
/// past 90 KB). Trailer payloads exceeding this in aggregate are
/// refused at parse time with `NscStatus::InvalidPointer`.
pub const TRAILERS_TOTAL_MAX_LEN: usize = 24 * 1024; // 24,576

/// Per-record header overhead in the TLV trailer list:
/// `kind(1) + tx_idx(1) + len(u16 BE, 2) = 4`.
pub const SIGN_USEROP_BATCH_TRAILER_HEADER_LEN: usize = 1 + 1 + 2;

/// Worst-case `CMD_SIGN_USEROP_BATCH` v2 payload length:
///   header(278)
/// + N × (tx_prefix(54) + MAX_TX_LEN(4096))
/// + trailer_count u8 (1)
/// + MAX_TRAILERS_PER_BATCH × per-record header (4)
/// + TRAILERS_TOTAL_MAX_LEN
///
/// The secure-side TOCTOU snapshot (`SNAP_BUF` in
/// `cmd_sign_userop_batch.rs`) is sized to this bound; living in BSS
/// rather than the call stack so the 64 KB call-frame ceiling does not
/// apply. Lands ~41 KB which fits the 192 KB secure SRAM budget with
/// headroom.
pub const SIGN_USEROP_BATCH_MAX_PAYLOAD_LEN: usize = SIGN_USEROP_BATCH_HEADER_LEN
    + MAX_BATCH_TXS * (SIGN_USEROP_BATCH_TX_PREFIX_LEN + MAX_TX_LEN)
    + 1
    + MAX_TRAILERS_PER_BATCH * SIGN_USEROP_BATCH_TRAILER_HEADER_LEN
    + TRAILERS_TOTAL_MAX_LEN;

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
///
/// 0x0201: bumped for the GET_STATUS wire-layout change (the constant-1
/// `provisioned` byte was dropped — 5 → 4 bytes on the wire; X17-UC2 /
/// #143), which originally shipped at 0x0200 without a bump (#440).
/// 0x0201 guarantees the 2-byte `[locked][pin_remaining]` GET_STATUS
/// layout; a 0x0200 report is ambiguous vintage (pre-production only).
/// 0x0202: bumped for the GET_WALLET_ADDRESS optional trailing `show`
/// flag byte (#472): present and `1` routes the derived address through
/// the trusted-OLED confirm before it is returned. Older firmware
/// rejects the 5-byte body with SW_WRONG_LENGTH, so companions must
/// gate the flag on a >= 0x0202 report.
pub const PROTOCOL_VERSION: u16 = 0x0202;

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
    // 16 is RETIRED (FA-1.5, Draft 1.1 §14 L4375): `FwUpdateOtpExhausted`
    // disappeared with the removed legacy unary OTP floor writer
    // (`otp::bump_to`) — COMMIT now refuses fail-closed and never
    // reaches an OTP-budget condition. The code stays reserved: it
    // decodes to `InternalError`, and a future status must not reuse it
    // without a wire-format review (released companions parsed 16 as
    // "permanently out of OTP budget").

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
    /// The prodtest INS space is `0x80 + (CMD - 100)` by convention, and the
    /// factory runner mirrors both the map and the RGB buffer sizes by hand
    /// (`tools/factory-prodtest-runner.py`). This is the only place the two
    /// can be checked against each other in a test that actually runs: the
    /// firmware-side `nsc/prodtest.rs` test module sits inside
    /// `#![cfg(feature = "prodtest")]`, which never builds for the host.
    #[test]
    fn prodtest_ins_map_is_mechanical_and_collision_free() {
        let pairs = [
            (CMD_PRODTEST_GET_ID, INS_V2_PRODTEST_GET_ID),
            (CMD_PRODTEST_DISPLAY_PATTERN, INS_V2_PRODTEST_DISPLAY_PATTERN),
            (CMD_PRODTEST_SAES_SELFTEST, INS_V2_PRODTEST_SAES_SELFTEST),
            (CMD_PRODTEST_BHK_SELFTEST, INS_V2_PRODTEST_BHK_SELFTEST),
            (CMD_PRODTEST_FLASH_RW, INS_V2_PRODTEST_FLASH_RW),
            (CMD_PRODTEST_TRNG_SAMPLE, INS_V2_PRODTEST_TRNG_SAMPLE),
            (CMD_PRODTEST_OPTIGA_HANDSHAKE, INS_V2_PRODTEST_OPTIGA_HANDSHAKE),
            (CMD_PRODTEST_SE050_HANDSHAKE, INS_V2_PRODTEST_SE050_HANDSHAKE),
            (CMD_PRODTEST_USB_LOOPBACK, INS_V2_PRODTEST_USB_LOOPBACK),
            (CMD_PRODTEST_BUTTON_TEST, INS_V2_PRODTEST_BUTTON_TEST),
            (CMD_PRODTEST_RGB_TEST, INS_V2_PRODTEST_RGB_TEST),
            (CMD_PRODTEST_RGB_OSD, INS_V2_PRODTEST_RGB_OSD),
        ];
        for (cmd, ins) in pairs {
            assert_eq!(
                u32::from(ins),
                0x80 + (cmd - 100),
                "INS for CMD {cmd} breaks the 0x80 + (CMD - 100) convention"
            );
        }
        // No INS reused, and none collides with the continuation INS.
        for (i, (_, ins_a)) in pairs.iter().enumerate() {
            assert_ne!(*ins_a, INS_V2_GET_RESPONSE);
            for (_, ins_b) in pairs.iter().skip(i + 1) {
                assert_ne!(ins_a, ins_b, "duplicate prodtest INS");
            }
        }
    }

    /// The RGB response is decoded by fixed offsets on the host, so its size
    /// and the 16-byte scan prefix are part of the wire contract.
    #[test]
    fn prodtest_rgb_buffers_match_the_documented_layout() {
        assert_eq!(PRODTEST_RGB_IN_LEN, 6, "[r, g, b, gcc, en, reserved]");
        // 16 B scan bitmap + ver + reset_id + acks_ok + acks_total + en + gcc
        // + 2 reserved.
        assert_eq!(PRODTEST_RGB_OUT_LEN, 16 + 6 + 2);
        // A 128-bit bitmap is exactly the 7-bit address space.
        assert_eq!(16 * 8, 128);
        // Both buffers must survive the NS response buffer's status-word tail.
        assert!(PRODTEST_RGB_OUT_LEN <= PRODTEST_MAX_RESPONSE_DATA_LEN);
    }

    /// The OSD response packs two 5-byte bitmaps plus scalars; the host reads
    /// those windows by offset, and the 36 status bits must fit the 5 bytes.
    #[test]
    fn prodtest_rgb_osd_buffers_match_the_documented_layout() {
        assert_eq!(PRODTEST_RGB_OSD_IN_LEN, 4);
        assert_eq!(PRODTEST_RGB_OSD_OUT_LEN, 24);
        // 2 x 5 bitmap bytes + ver + 2 ack counters + en + gcc + 2 channel
        // counts + 7 reserved.
        assert_eq!(5 + 5 + 1 + 2 + 1 + 1 + 2 + 7, PRODTEST_RGB_OSD_OUT_LEN);
        // 5 bytes must cover all 36 channels, with room to spare in the last.
        assert!(5 * 8 >= 36);
        assert!(PRODTEST_RGB_OSD_OUT_LEN <= PRODTEST_MAX_RESPONSE_DATA_LEN);
    }

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

    #[test]
    fn prodtest_response_cap_reserves_status_word() {
        assert_eq!(PRODTEST_MAX_RESPONSE_DATA_LEN, 254);
        assert_eq!(PRODTEST_MAX_RESPONSE_DATA_LEN + 2, 256);
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
