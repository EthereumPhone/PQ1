#![no_std]

pub mod db_format;

// ---------------------------------------------------------------------------
// SLH-DSA-SHA2-128f sizes
// ---------------------------------------------------------------------------

pub const SIGNING_KEY_LEN: usize = 64;
pub const VERIFYING_KEY_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 17_088;
pub const PIN_LEN: usize = 8;
pub const TX_HASH_LEN: usize = 32;
pub const MAX_ATTEMPTS: u8 = 9;

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

/// CMD_SIGN_USEROP — ERC-4337 Account Abstraction UserOperation signing.
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
/// Payload wire format (all integers big-endian unless noted):
///
/// ```text
///   [  0]                       has_bundle u8        (0 or 1)
///   [  1.. 21)  sender                              (20 bytes)
///   [ 21.. 41)  entry_point                         (20 bytes)
///   [ 41.. 49)  aa_chain_id     u64 BE              (chainid hashed by EntryPoint)
///   [ 49.. 81)  nonce           u256 BE
///   [ 81..113)  call_gas_limit          u256 BE
///   [113..145)  verification_gas_limit  u256 BE
///   [145..177)  pre_verification_gas    u256 BE
///   [177..209)  max_fee_per_gas         u256 BE
///   [209..241)  max_priority_fee_per_gas u256 BE
///   [241..273)  init_code_hash          32 bytes (keccak256)
///   [273..305)  paymaster_and_data_hash 32 bytes (keccak256)
///   [305..309)  tx_len u32 LE
///   [309..309+tx_len)  inner unsigned EIP-1559 envelope
///   [309+tx_len..]     optional [bundle_len u32 LE][ERC20 metadata bundle]
/// ```
///
/// On success the secure world writes a 17,088-byte SLH-DSA signature
/// over `userOpHash` into the NS-supplied output buffer.
pub const CMD_SIGN_USEROP: u32 = 7;

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
            _ => Self::InternalError,
        }
    }
}
