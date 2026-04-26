#![no_std]

pub mod db_format;

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

/// Groth16 verification key size: alpha(96) + beta(192) + gamma(192) +
/// delta(192) + 3×IC(288) = 960 bytes.
/// The VK is protocol-specific — one VK per circuit under `circuits/`,
/// produced by the in-tree `tools/build_vks.sh` pipeline and folded
/// into the firmware DB by `dbgen`.
pub const ZK_VK_LEN: usize = 960;

/// Total size of the fixed portion of a clear-sign request payload.
///
/// Layout (v2 — includes AA header for UserOp signing):
///   [0..384)                               : Groth16 proof (π.A || π.B || π.C)
///   [384..548)                             : calldata (164 bytes, right-zero-padded)
///   [548..612)                             : readable string (64 bytes, null-padded)
///   [612..612+USEROP_HEADER_LEN)           : AA header (same as CMD_SIGN_USEROP)
///   [612+USEROP_HEADER_LEN..+4)            : tx_len (u32 little-endian)
///   [612+USEROP_HEADER_LEN+4..+tx_len)     : unsigned EIP-1559 transaction envelope
pub const ZK_HEADER_LEN: usize =
    ZK_PROOF_LEN + ZK_MAX_CALLDATA + ZK_STRING_LEN + USEROP_HEADER_LEN + 4;

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
// ---------------------------------------------------------------------------

pub const CMD_NONE: u32 = 0;
pub const CMD_GET_REMAINING: u32 = 1;
pub const CMD_REQUEST_UNLOCK: u32 = 2;
pub const CMD_GET_PUBKEY: u32 = 3;
// CMD 4 reserved (was CMD_SIGN in v1)
pub const CMD_CLEAR_SIGN: u32 = 5;
/// CMD_CLEAR_SIGN_MSG — EIP-712 typed-data clear signing (M4).
///
/// Unlike `CMD_CLEAR_SIGN` which signs an EIP-1559 tx envelope, this
/// command signs an EIP-712 message digest. There is no on-chain tx
/// to wrap; the wallet produces a signature over the EIP-712 digest
/// directly. The Groth16 proof binds a 164-byte canonical encoding of
/// the typed data (the order struct fields) to a 64-byte readable
/// string. The secure world independently keccak-hashes the same
/// canonical bytes (re-expanded into the 416-byte abi.encode of the
/// 12-field GPv2Order struct) to produce the EIP-712 digest that
/// actually gets signed with SLH-DSA.
///
/// Payload layout:
///   [0..384)         : Groth16 proof (π.A || π.B || π.C)
///   [384..548)       : canonical bytes (164 bytes, packed GPv2Order)
///   [548..612)       : readable string (64 bytes, null-padded)
///   [612..)          : [bundle_len u32 LE][VK bundle]
pub const CMD_CLEAR_SIGN_MSG: u32 = 6;

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
/// dual-SE entropy); first call after unlock takes ~6 s, subsequent
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
// CMD_GET_MAIN_PUBKEY wire format
// ---------------------------------------------------------------------------

/// Length of the CMD_GET_MAIN_PUBKEY payload: chain_id (8) + key_index (4).
pub const MAIN_PUBKEY_PAYLOAD_LEN: usize = 12;

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

/// Total fixed header length for the CMD_CLEAR_SIGN_MSG payload.
pub const EIP712_HEADER_LEN: usize =
    EIP712_PROOF_LEN + EIP712_CANONICAL_LEN + EIP712_STRING_LEN;

// ---------------------------------------------------------------------------
// USB APDU protocol constants (Keycard Shell compatible)
// ---------------------------------------------------------------------------

/// APDU class byte — matches Keycard Shell / Ledger convention.
pub const APDU_CLA: u8 = 0xE0;

/// APDU instruction codes — Keycard Shell compatible command set.
pub const INS_GET_PUBLIC: u8 = 0x02;
pub const INS_SIGN_ETH_TX: u8 = 0x04;
pub const INS_GET_APP_CONF: u8 = 0x06;
pub const INS_SIGN_ETH_MSG: u8 = 0x08;
pub const INS_SIGN_EIP712: u8 = 0x0C;
pub const INS_GET_RESPONSE: u8 = 0xC0;

/// PQSigner extensions (not in Keycard Shell)
pub const INS_GET_PIN_REMAINING: u8 = 0x10;
pub const INS_UNLOCK: u8 = 0x12;

/// APDU P1 values for command chaining (Keycard Shell convention).
/// Chain terminates when Lc < APDU_MAX_DATA (short last chunk).
pub const P1_FIRST: u8 = 0x00;
pub const P1_MORE: u8 = 0x01;

// ---------------------------------------------------------------------------
// USB APDU protocol v2 — PQSigner native (replaces Keycard Shell compat)
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

// -- Key queries (0x20-0x2F) --
pub const INS_V2_GET_BOOTSTRAP_VK: u8 = 0x20;
pub const INS_V2_GET_MAIN_VK: u8 = 0x21;

// -- UserOp signing (0x30-0x3F) --
pub const INS_V2_SIGN_USEROP: u8 = 0x30;
pub const INS_V2_SIGN_CLEAR_USEROP: u8 = 0x31;

// -- Message / typed-data signing (0x40-0x4F) --
pub const INS_V2_SIGN_MESSAGE: u8 = 0x40;
pub const INS_V2_SIGN_EIP712: u8 = 0x41;

// -- Bootstrap operations (0x50-0x5F) --
/// **DEPRECATED**: bootstrap signing is now handled automatically by
/// INS_V2_SIGN_USEROP when P2=0x01 (not-deployed). Kept for backward compat.
pub const INS_V2_SIGN_BOOTSTRAP: u8 = 0x50;

// -- Address & account helpers (0x60-0x6F) --
pub const INS_V2_GET_WALLET_ADDRESS: u8 = 0x60;
pub const INS_V2_GET_INIT_CODE: u8 = 0x61;

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

// INS range 0x70-0x7F (formerly compact-signing instructions — retired
// with the C10 slot cutover).

// -- Continuation (shared with v1) --
pub const INS_V2_GET_RESPONSE: u8 = 0xC0;

/// v2 P1: bit 7 = chaining flag (ISO 7816-4 standard).
/// 0x00 = last or only block, 0x80 = more blocks follow.
pub const P1_V2_LAST: u8 = 0x00;
pub const P1_V2_MORE: u8 = 0x80;

// ---------------------------------------------------------------------------
// PQSignatureWrapper — structured signing response (v2)
// ---------------------------------------------------------------------------

/// Signer type discriminator in the (legacy v2) PQSignatureWrapper.
pub const SIGNER_MAIN: u8 = 0x00;
pub const SIGNER_BOOTSTRAP: u8 = 0x01;

/// Fixed-size wrapper header written before the raw SPHINCS+C7 signature:
///   signer_type(1) + key_index(4) + ots_index(4) + pk_seed(32) + pk_root(32)
pub const WRAPPER_HEADER_LEN: usize = 1 + 4 + 4 + 32 + 32; // 73

/// Total PQSignatureWrapper size = header + raw signature.
pub const WRAPPER_TOTAL_LEN: usize = WRAPPER_HEADER_LEN + SIGNATURE_LEN; // 3777

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
pub const SIG_WRAPPER_LEN: usize = {
    let padded = ((C10_SIG_LEN + 31) / 32) * 32;
    32 + 32 + 32 + padded
}; // 4128

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

/// Type 1 / 2 markers are deprecated — dispatch now happens on-chain via
/// `SignatureWrapper.ownerIndex`, not a leading byte. Kept only as a
/// historic `0x01 = bootstrap` / `0x02 = slot` mnemonic for the companion
/// UI.
pub const SIG_TYPE1_MARKER: u8 = 0x01;
pub const SIG_TYPE2_MARKER: u8 = 0x02;

/// Back-compat constant: the abi.encode header that precedes the raw 4008-
/// byte C10 sig inside a SignatureWrapper (32 ownerIndex + 32 offset +
/// 32 length = 96 bytes). Surfaced over USB in GET_DEVICE_INFO so the
/// host companion can slice the wrapper without embedding the constant.
pub const SIG_TYPE2_HEADER_LEN: usize = 32 + 32 + 32;

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
    0x37, 0x5e, 0xBb, 0x4E, 0x50, 0x2B, 0x94, 0xF9, 0xe8, 0xb9,
    0x9F, 0xdd, 0x0b, 0x0e, 0x88, 0x2a, 0x9d, 0x9d, 0xD6, 0xfB,
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
    0xdb, 0xa8, 0xc2, 0x82, 0xfc, 0xb7, 0x9f, 0xd4,
    0x81, 0x30, 0x8d, 0xbb, 0x76, 0xfe, 0x14, 0xa6,
    0xe8, 0xb1, 0x19, 0x50, 0xc5, 0x4b, 0x10, 0x28,
    0xeb, 0x36, 0xb5, 0x65, 0x5a, 0x69, 0xe8, 0x5b,
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
///     || abi-encoded bytes offset = 0xE0 (32)
///     || bytes length = 4008 (32)
///     || bytes data padded to 32-byte boundary = 4032
/// ```
///
/// = 20 + 4 + (5 × 32) + 32 + 32 + 4032 = 4280 bytes.
pub const PQ_INIT_CODE_LEN: usize = 20 + 4 + 5 * 32 + 32 + 32 + 4032; // 4280

/// Maximum unified response from `CMD_SIGN_USEROP`:
///
/// ```text
///   [init_code_len(4 BE)][init_code(0 or PQ_INIT_CODE_LEN)]
///   [type1_len(4 BE)][type1_wrapper(0 or SIG_WRAPPER_LEN)]
///   [type2_len(4 BE)][type2_wrapper(SIG_WRAPPER_LEN)]
/// ```
pub const MAX_SIGN_RESPONSE_LEN: usize =
    4 + PQ_INIT_CODE_LEN + 4 + SIG_TYPE1_LEN + 4 + SIG_TYPE2_LEN;

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

/// Offset of the 384-byte Groth16 proof within the fixed prefix.
pub const ZK_V3_OFF_PROOF: usize = 0;
/// Offset of the 204-byte canonical GPv2Order within the fixed prefix.
pub const ZK_V3_OFF_CANONICAL: usize = ZK_V3_OFF_PROOF + EIP712_PROOF_LEN;
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

/// Bootstrap context tags for SIGN_BOOTSTRAP trusted-UI display.
/// **DEPRECATED** along with CMD_SIGN_BOOTSTRAP.
pub const CTX_DEPLOY: u8 = 0x00;
pub const CTX_ROTATE: u8 = 0x01;
pub const CTX_GENERIC: u8 = 0x02;

// ---------------------------------------------------------------------------
// initCode construction constants (first-deployment UserOps)
// ---------------------------------------------------------------------------

/// Placeholder factory address for initCode generation.
///
/// **MUST be replaced with the actual deployed PQCoinbaseSmartWalletFactory
/// address before production use.** The null address will produce a valid
/// initCode structure but the EntryPoint will revert because no factory
/// exists at address(0).
pub const FACTORY_ADDRESS: [u8; 20] = [0u8; 20];

/// ABI selector for `createAccount(bytes32,bytes32,bytes32,bytes32,bytes)`.
/// Equals `keccak256("createAccount(bytes32,bytes32,bytes32,bytes32,bytes)")[:4]`.
/// Verified against `cast sig` from Foundry.
pub const CREATE_ACCOUNT_SELECTOR: [u8; 4] = [0x19, 0x64, 0xc4, 0xdd];

/// Fixed initCode length for SPHINCS+C7:
///   factory(20) + selector(4) + 4 static bytes32(128) + offset(32)
///   + length(32) + padded_signature(3712) = 3,928
///
/// ABI layout of `createAccount(bytes32,bytes32,bytes32,bytes32,bytes)`:
/// ```text
///   [   0..  20)  factory address (NOT part of ABI, prepended per ERC-4337)
///   [  20..  24)  selector 0x1964c4dd
///   [  24..  56)  bootstrapPkSeed   (bytes32)
///   [  56..  88)  bootstrapPkRoot   (bytes32)
///   [  88.. 120)  mainPkSeed        (bytes32)
///   [ 120.. 152)  mainPkRoot        (bytes32)
///   [ 152.. 184)  offset to bytes   (= 0xA0 = 160)
///   [ 184.. 216)  length of bytes   (= 4008)
///   [ 216..4248)  bootstrapSig      (4008 bytes + 24 bytes zero-padding to 32-byte boundary)
/// ```
///
/// The signature is 4,008 bytes (not 32-byte aligned: 4008 % 32 = 8),
/// so 24 bytes of ABI zero-padding are appended to reach the next
/// 32-byte boundary (4,032 bytes padded).
pub const INIT_CODE_LEN: usize =
    20 + 4 + 4 * 32 + 32 + 32 + ((SIGNATURE_LEN + 31) / 32) * 32; // 4_248

/// Maximum reconstructed `execute(target, value, data)` callData size:
/// selector(4) + target(32) + value(32) + offset(32) + length(32)
/// + data padded to 32-byte boundary ≈ 132 + MAX_TX_LEN rounded up.
pub const MAX_EXECUTE_CALLDATA_LEN: usize = 4 * 1024 + 256; // 4352

/// Maximum full UserOp response size:
///   init_code_len(4) + initCode(INIT_CODE_LEN) + call_data_len(4)
///   + max callData(MAX_EXECUTE_CALLDATA_LEN) + signatureWrapper(WRAPPER_TOTAL_LEN)
///
/// For the not-deployed case. The deployed case is much smaller
/// (init_code_len=0, no initCode body).
pub const MAX_USEROP_RESPONSE_LEN: usize =
    4 + INIT_CODE_LEN + 4 + MAX_EXECUTE_CALLDATA_LEN + WRAPPER_TOTAL_LEN;

/// SIGN_USEROP v2 P2 values for deployment mode.
pub const P2_DEPLOYED: u8 = 0x00;
pub const P2_NOT_DEPLOYED: u8 = 0x01;

/// v2 SIGN_USEROP fixed header length (before tx_len):
///   key_index(4) + ots_index(4) + sender(20) + entry_point(20) +
///   chain_id(8) + nonce(32) + call_gas(32) + ver_gas(32) +
///   pre_gas(32) + max_fee(32) + max_prio(32) + init_code_hash(32) +
///   paymaster_hash(32) = 312
pub const USEROP_V2_HEADER_LEN: usize = 4 + 4 + 20 + 20 + 8 + 32 * 8;

// v2 AA payload (after key_index+ots_index) must equal v1 header minus has_bundle byte.
const _: () = assert!(
    USEROP_V2_HEADER_LEN - 8 == USEROP_HEADER_LEN - 1,
    "v2 AA header size must match v1 (minus has_bundle)"
);

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

/// Maximum data bytes per APDU (short form Lc, 1 byte).
pub const APDU_MAX_DATA: usize = 255;

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
            _ => Self::InternalError,
        }
    }
}

// ---------------------------------------------------------------------------
// Wire-format layout tests (run with `cargo test -p sphincs-tz-shared`)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn userop_v2_header_is_312() {
        // key_index(4) + ots_index(4) + sender(20) + entry_point(20) +
        // chain_id(8) + 8 × u256(32) = 312
        assert_eq!(USEROP_V2_HEADER_LEN, 312);
    }

    #[test]
    fn userop_v1_header_is_305() {
        // has_bundle(1) + sender(20) + entry_point(20) + chain_id(8) +
        // 8 × u256(32) = 305
        assert_eq!(USEROP_HEADER_LEN, 305);
    }

    #[test]
    fn v2_aa_matches_v1_minus_has_bundle() {
        // v2→v1 translation skips key_index(4)+ots_index(4), yielding
        // the same 304-byte AA blob that v1 stores after has_bundle.
        assert_eq!(USEROP_V2_HEADER_LEN - 8, USEROP_HEADER_LEN - 1);
    }

    #[test]
    fn zk_header_len_matches_components() {
        assert_eq!(
            ZK_HEADER_LEN,
            ZK_PROOF_LEN + ZK_MAX_CALLDATA + ZK_STRING_LEN + USEROP_HEADER_LEN + 4
        );
    }

    #[test]
    fn init_code_len_is_4248() {
        // factory(20) + selector(4) + 4*bytes32(128) + offset(32) + length(32) + padded_sig(4032)
        assert_eq!(INIT_CODE_LEN, 4_248);
    }

    #[test]
    fn signature_abi_padding_correct() {
        // 4008 % 32 = 8, so 24 bytes of zero-padding; padded = 4032
        let padded = ((SIGNATURE_LEN + 31) / 32) * 32;
        assert_eq!(padded, 4_032);
        assert_eq!(padded % 32, 0);
    }

    /// Simulate the v2 sign_userop payload layout and verify the
    /// firmware would read tx_len from the correct offset.
    #[test]
    fn v2_sign_userop_offsets() {
        const TX_LEN: usize = 50; // like the ETH transfer test vector
        const TOTAL: usize = USEROP_V2_HEADER_LEN + 2 + TX_LEN + 2;

        let mut buf = [0u8; TOTAL];
        let mut p = 0usize;

        p += 4; // key_index
        p += 4; // ots_index
        p += 20; // sender
        p += 20; // entry_point
        p += 8; // chain_id
        p += 32 * 8; // 8 u256 fields
        assert_eq!(p, USEROP_V2_HEADER_LEN, "header fields end at wrong offset");

        // tx_len u16 BE
        buf[p] = (TX_LEN >> 8) as u8;
        buf[p + 1] = (TX_LEN & 0xFF) as u8;
        p += 2;

        // tx data
        let mut i = 0;
        while i < TX_LEN {
            buf[p + i] = 0xAA;
            i += 1;
        }
        p += TX_LEN;

        // bundle_len = 0
        p += 2;

        assert_eq!(p, TOTAL);

        // Verify: firmware reads tx_len at USEROP_V2_HEADER_LEN
        let fw_tx_len = u16::from_be_bytes([
            buf[USEROP_V2_HEADER_LEN],
            buf[USEROP_V2_HEADER_LEN + 1],
        ]) as usize;
        assert_eq!(fw_tx_len, TX_LEN);
    }

    /// Simulate the v2 sign_clear_userop payload layout.
    #[test]
    fn v2_sign_clear_userop_offsets() {
        let zk_header_start = 8usize; // after key_index + ots_index
        let zk_len = ZK_PROOF_LEN + ZK_MAX_CALLDATA + ZK_STRING_LEN; // 612
        let aa_len = USEROP_V2_HEADER_LEN - 8; // 304
        let tx_len_off = zk_header_start + zk_len + aa_len;

        assert_eq!(zk_len, 612);
        assert_eq!(aa_len, 304);
        assert_eq!(tx_len_off, 8 + 612 + 304); // = 924

        const BUF_LEN: usize = 8 + 612 + 304 + 2 + 177 + 2 + 100;
        let mut buf = [0u8; BUF_LEN];

        let tx_len: usize = 177;
        let vk_len: usize = 100;

        // Write tx_len at expected offset
        buf[tx_len_off] = (tx_len >> 8) as u8;
        buf[tx_len_off + 1] = (tx_len & 0xFF) as u8;

        // Verify firmware reads it correctly
        let fw_tx_len = u16::from_be_bytes([buf[tx_len_off], buf[tx_len_off + 1]]) as usize;
        assert_eq!(fw_tx_len, tx_len);

        // Verify vk_bundle_len offset
        let tx_end = tx_len_off + 2 + tx_len;
        buf[tx_end] = (vk_len >> 8) as u8;
        buf[tx_end + 1] = (vk_len & 0xFF) as u8;
        let fw_vk_len =
            u16::from_be_bytes([buf[tx_end], buf[tx_end + 1]]) as usize;
        assert_eq!(fw_vk_len, vk_len);
    }
}
