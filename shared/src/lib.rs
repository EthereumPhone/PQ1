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

/// Total size of the fixed portion of a clear-sign request payload in NS SRAM.
///
/// The VK is no longer supplied by NS — the secure world looks it up
/// from its embedded VK DB by `(chain_id, to)` after parsing the tx
/// envelope. The trust anchor is the firmware-signing key: the release
/// reviewer diffs `secure/data/vks.review.txt` against the previous
/// release before signing. Fully offline — no on-chain lookups
/// anywhere in the project.
///
/// Layout:
///   [0..384)                     : Groth16 proof (π.A || π.B || π.C)
///   [384..548)                   : calldata (164 bytes, right-zero-padded)
///   [548..612)                   : readable string (64 bytes, null-padded)
///   [612..616)                   : tx_len (u32 little-endian)
///   [616..616+tx_len)            : unsigned EIP-1559 transaction envelope
pub const ZK_HEADER_LEN: usize =
    ZK_PROOF_LEN + ZK_MAX_CALLDATA + ZK_STRING_LEN + 4;

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
pub const CMD_SIGN: u32 = 4;
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

// ---------------------------------------------------------------------------
// EIP-712 clear signing constants (M4 — CowSwap GPv2Order)
// ---------------------------------------------------------------------------

/// Canonical (packed) GPv2Order encoding length, sized to match the
/// existing 164-byte calldata slot so the same `poseidon6` instance
/// can hash it without expanding the firmware Poseidon footprint.
pub const EIP712_CANONICAL_LEN: usize = 164;

/// Same readable-string length as the EIP-1559 clear-sign path.
pub const EIP712_STRING_LEN: usize = 64;

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
