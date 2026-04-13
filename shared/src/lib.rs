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

/// CMD_SIGN_BOOTSTRAP — sign a 32-byte message hash with the bootstrap
/// signer. Used for factory deployment authorization and emergency
/// rotation authorization.
///
/// Payload wire format:
///   [0..32)  message hash (the bytes32 to sign)
///
/// On success the secure world writes a 17,088-byte SLH-DSA signature
/// into the NS output buffer.
pub const CMD_SIGN_BOOTSTRAP: u32 = 10;

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

/// CMD_GET_WALLET_ADDRESS — compute CREATE2 wallet address from stored
/// bootstrap VK + caller-supplied factory parameters, display it on
/// the trusted OLED for independent verification.
///
/// Payload wire format:
///   [0..8)    chain_id         u64 BE  (displayed to user)
///   [8..28)   factory_address  20 bytes
///   [28..60)  init_code_hash   32 bytes
///
/// On success the secure world writes the 20-byte address to the NS
/// output buffer and displays it on the OLED.
pub const CMD_GET_WALLET_ADDRESS: u32 = 14;

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
pub const INS_V2_SIGN_BOOTSTRAP: u8 = 0x50;

// -- Address & account helpers (0x60-0x6F) --
pub const INS_V2_GET_WALLET_ADDRESS: u8 = 0x60;

// -- Continuation (shared with v1) --
pub const INS_V2_GET_RESPONSE: u8 = 0xC0;

/// v2 P1: bit 7 = chaining flag (ISO 7816-4 standard).
/// 0x00 = last or only block, 0x80 = more blocks follow.
pub const P1_V2_LAST: u8 = 0x00;
pub const P1_V2_MORE: u8 = 0x80;

// ---------------------------------------------------------------------------
// PQSignatureWrapper — structured signing response (v2)
// ---------------------------------------------------------------------------

/// Signer type discriminator in the PQSignatureWrapper.
pub const SIGNER_MAIN: u8 = 0x00;
pub const SIGNER_BOOTSTRAP: u8 = 0x01;

/// Fixed-size wrapper header written before the raw SLH-DSA signature:
///   signer_type(1) + key_index(4) + ots_index(4) + pk_seed(32) + pk_root(32)
pub const WRAPPER_HEADER_LEN: usize = 1 + 4 + 4 + 32 + 32; // 73

/// Total PQSignatureWrapper size = header + raw signature.
pub const WRAPPER_TOTAL_LEN: usize = WRAPPER_HEADER_LEN + SIGNATURE_LEN; // 17161

/// Bootstrap context tags for SIGN_BOOTSTRAP trusted-UI display.
pub const CTX_DEPLOY: u8 = 0x00;
pub const CTX_ROTATE: u8 = 0x01;
pub const CTX_GENERIC: u8 = 0x02;

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
