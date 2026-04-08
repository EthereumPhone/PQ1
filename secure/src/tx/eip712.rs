//! EIP-712 typed-data signing for CowSwap GPv2Order (M4).
//!
//! This module turns a 164-byte packed canonical encoding of a CowSwap
//! `GPv2Order` struct (the same buffer the Groth16 circuit binds via
//! `Poseidon(canonical, 164)`) into the EIP-712 digest the user signs:
//!
//! ```text
//!   digest = keccak256( 0x19 ‖ 0x01 ‖ domain_separator ‖ struct_hash )
//! ```
//!
//! where:
//!
//! ```text
//!   domain_separator = keccak256( abi.encode(
//!       EIP712_DOMAIN_TYPEHASH,
//!       keccak256("Gnosis Protocol"),
//!       keccak256("v2"),
//!       chainId,
//!       verifyingContract,
//!   ))
//!
//!   struct_hash = keccak256( abi.encode(
//!       ORDER_TYPEHASH,
//!       sellToken, buyToken, receiver,
//!       sellAmount, buyAmount, validTo,
//!       appData, feeAmount, kind,
//!       partiallyFillable, sellTokenBalance, buyTokenBalance,
//!   ))
//! ```
//!
//! ## Canonical layout (164 bytes)
//!
//! The 164-byte buffer is a tightly packed representation of the 12
//! `GPv2Order` fields the wallet exposes for v1, designed to fit in
//! exactly the same slot as the existing M3 `cowswap_set_pre_signature`
//! calldata so the firmware can reuse `poseidon_bytes(_, 164)`
//! (poseidon6) without adding a new Poseidon instance:
//!
//! ```text
//!   [  0..  20)  sellToken          (20 B address)
//!   [ 20..  40)  buyToken           (20 B address)
//!   [ 40..  60)  receiver           (20 B address)
//!   [ 60..  92)  sellAmount         (uint256 BE)
//!   [ 92.. 124)  buyAmount          (uint256 BE)
//!   [124.. 156)  feeAmount          (uint256 BE)
//!   [156.. 160)  validTo            (uint32 BE)
//!   [160]        kind               (0 = sell, 1 = buy)
//!   [161]        partiallyFillable  (0 = false, 1 = true)
//!   [162]        sellTokenBalance   (0 = erc20, 1 = external, 2 = internal)
//!   [163]        buyTokenBalance    (0 = erc20, 1 = internal)
//! ```
//!
//! `appData` is forced to `bytes32(0)` (the default empty-metadata
//! hash) for v1 because the canonical buffer cannot fit a 12th 32-byte
//! field without expanding past 164 bytes. v2 can either bump the
//! poseidon instance up to `poseidon7` and grow the buffer to 217 B,
//! or decode `appData` from a non-Poseidon-bound suffix and
//! cross-check it on the trusted UI.
//!
//! ## Domain separator
//!
//! `verifyingContract` is fixed at `0x9008D19f58AAbD9eD0D60971565AA8510560ab41`
//! across every EVM chain CowSwap is deployed on (CREATE2 deployment).
//! `chainId` is bound by the VK bundle: the secure world will only
//! accept a `(chain_id, contract)` pair that is present in the
//! Merkle-verified VK DB, and uses that same `chain_id` here to keep
//! the digest a function of the on-chain governance configuration.

use sha3::{Digest, Keccak256};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// CowSwap GPv2Settlement is deployed at this address on every chain
/// the project supports (Mainnet, Gnosis Chain, Arbitrum, Base). Used
/// as the `verifyingContract` field in the EIP-712 domain separator.
pub const GPV2_SETTLEMENT_ADDRESS: [u8; 20] = [
    0x90, 0x08, 0xd1, 0x9f, 0x58, 0xaa, 0xbd, 0x9e, 0xd0, 0xd6,
    0x09, 0x71, 0x56, 0x5a, 0xa8, 0x51, 0x05, 0x60, 0xab, 0x41,
];

/// Sentinel address that the M4 EIP-712 protocol uses as its lookup
/// key in the VK DB. The trailing `0xab42` differs from the real
/// `GPV2_SETTLEMENT_ADDRESS` (which ends in `0xab41`) so the
/// `(chain_id, contract)` lookup key remains unique across both the
/// M3 `setPreSignature` entries and the M4 EIP-712 entries — without
/// having to extend the VK DB on-disk format with a `protocol_id`
/// byte. The sentinel never makes it onto Ethereum: the firmware
/// hardcodes the real `GPV2_SETTLEMENT_ADDRESS` for the EIP-712
/// domain separator.
pub const COWSWAP_EIP712_SENTINEL: [u8; 20] = [
    0x90, 0x08, 0xd1, 0x9f, 0x58, 0xaa, 0xbd, 0x9e, 0xd0, 0xd6,
    0x09, 0x71, 0x56, 0x5a, 0xa8, 0x51, 0x05, 0x60, 0xab, 0x42,
];

/// Length of the canonical packed GPv2Order encoding the firmware
/// parses out of the NS payload (must match the EIP-712 circuit).
pub const CANONICAL_LEN: usize = 164;

/// Decoded GPv2Order fields. Borrows nothing — every field is owned.
#[derive(Clone, Copy, Debug)]
pub struct GpV2Order {
    pub sell_token: [u8; 20],
    pub buy_token: [u8; 20],
    pub receiver: [u8; 20],
    pub sell_amount: [u8; 32],
    pub buy_amount: [u8; 32],
    pub fee_amount: [u8; 32],
    pub valid_to: u32,
    pub kind: u8,
    pub partially_fillable: u8,
    pub sell_token_balance: u8,
    pub buy_token_balance: u8,
}

#[derive(Debug)]
pub enum Eip712Error {
    /// One of the byte-encoded enum fields was outside its valid range.
    EnumOutOfRange,
}

// ---------------------------------------------------------------------------
// Canonical decoding
// ---------------------------------------------------------------------------

/// Parse the 164-byte canonical packed encoding into structured fields.
/// Validates the small-enum byte ranges (kind, partiallyFillable,
/// balance kinds) so an out-of-range NS payload is rejected before it
/// can produce a digest.
pub fn decode_canonical(canonical: &[u8; CANONICAL_LEN]) -> Result<GpV2Order, Eip712Error> {
    let mut sell_token = [0u8; 20];
    sell_token.copy_from_slice(&canonical[0..20]);
    let mut buy_token = [0u8; 20];
    buy_token.copy_from_slice(&canonical[20..40]);
    let mut receiver = [0u8; 20];
    receiver.copy_from_slice(&canonical[40..60]);

    let mut sell_amount = [0u8; 32];
    sell_amount.copy_from_slice(&canonical[60..92]);
    let mut buy_amount = [0u8; 32];
    buy_amount.copy_from_slice(&canonical[92..124]);
    let mut fee_amount = [0u8; 32];
    fee_amount.copy_from_slice(&canonical[124..156]);

    let valid_to = u32::from_be_bytes([
        canonical[156],
        canonical[157],
        canonical[158],
        canonical[159],
    ]);

    let kind = canonical[160];
    let partially_fillable = canonical[161];
    let sell_token_balance = canonical[162];
    let buy_token_balance = canonical[163];

    if kind > 1
        || partially_fillable > 1
        || sell_token_balance > 2
        || buy_token_balance > 1
    {
        return Err(Eip712Error::EnumOutOfRange);
    }

    Ok(GpV2Order {
        sell_token,
        buy_token,
        receiver,
        sell_amount,
        buy_amount,
        fee_amount,
        valid_to,
        kind,
        partially_fillable,
        sell_token_balance,
        buy_token_balance,
    })
}

// ---------------------------------------------------------------------------
// Keccak helpers
// ---------------------------------------------------------------------------

#[inline]
fn keccak(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(data);
    let r = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&r);
    out
}

/// `keccak256("Order(address sellToken,address buyToken,address receiver,uint256 sellAmount,uint256 buyAmount,uint32 validTo,bytes32 appData,uint256 feeAmount,bytes32 kind,bool partiallyFillable,bytes32 sellTokenBalance,bytes32 buyTokenBalance)")`.
const ORDER_TYPEHASH_PREIMAGE: &[u8] = b"Order(address sellToken,address buyToken,address receiver,uint256 sellAmount,uint256 buyAmount,uint32 validTo,bytes32 appData,uint256 feeAmount,bytes32 kind,bool partiallyFillable,bytes32 sellTokenBalance,bytes32 buyTokenBalance)";

/// `keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")`.
const DOMAIN_TYPEHASH_PREIMAGE: &[u8] =
    b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";

const COWSWAP_DOMAIN_NAME: &[u8] = b"Gnosis Protocol";
const COWSWAP_DOMAIN_VERSION: &[u8] = b"v2";

// ---------------------------------------------------------------------------
// Domain separator
// ---------------------------------------------------------------------------

/// Compute the EIP-712 domain separator for `(chain_id, verifying_contract)`.
pub fn domain_separator(chain_id: u64, verifying_contract: &[u8; 20]) -> [u8; 32] {
    let domain_typehash = keccak(DOMAIN_TYPEHASH_PREIMAGE);
    let name_hash = keccak(COWSWAP_DOMAIN_NAME);
    let version_hash = keccak(COWSWAP_DOMAIN_VERSION);

    let mut buf = [0u8; 32 * 5];
    buf[0..32].copy_from_slice(&domain_typehash);
    buf[32..64].copy_from_slice(&name_hash);
    buf[64..96].copy_from_slice(&version_hash);
    // chainId as uint256: 24 zero bytes, then 8 BE bytes.
    buf[96 + 24..96 + 32].copy_from_slice(&chain_id.to_be_bytes());
    // verifyingContract as address (left-padded to 32 bytes).
    buf[128 + 12..128 + 32].copy_from_slice(verifying_contract);

    keccak(&buf)
}

// ---------------------------------------------------------------------------
// Struct hash
// ---------------------------------------------------------------------------

/// Compute `keccak256("sell")` / `keccak256("buy")` for the kind enum.
fn kind_hash(kind: u8) -> [u8; 32] {
    if kind == 0 {
        keccak(b"sell")
    } else {
        keccak(b"buy")
    }
}

/// Compute `keccak256("erc20" | "external" | "internal")` for a balance enum.
/// `is_sell_side` distinguishes the sell-side enum (0/1/2) from the
/// buy-side enum (0/1) — the buy-side never resolves to "external".
fn balance_hash(b: u8, is_sell_side: bool) -> [u8; 32] {
    match (is_sell_side, b) {
        (_, 0) => keccak(b"erc20"),
        (true, 1) => keccak(b"external"),
        (false, 1) => keccak(b"internal"),
        (true, 2) => keccak(b"internal"),
        _ => keccak(b"erc20"),
    }
}

/// Compute the GPv2Order EIP-712 struct hash from a decoded order.
///
/// `appData` is fixed at `bytes32(0)` for v1 (see module-level docs).
pub fn struct_hash(order: &GpV2Order) -> [u8; 32] {
    // 13 fields × 32 bytes = 416 bytes.
    let mut buf = [0u8; 32 * 13];

    // [0]   ORDER_TYPEHASH
    let typehash = keccak(ORDER_TYPEHASH_PREIMAGE);
    buf[0..32].copy_from_slice(&typehash);

    // [1]   sellToken (left-padded address)
    buf[32 + 12..32 + 32].copy_from_slice(&order.sell_token);
    // [2]   buyToken
    buf[64 + 12..64 + 32].copy_from_slice(&order.buy_token);
    // [3]   receiver
    buf[96 + 12..96 + 32].copy_from_slice(&order.receiver);
    // [4]   sellAmount (uint256 BE)
    buf[128..160].copy_from_slice(&order.sell_amount);
    // [5]   buyAmount
    buf[160..192].copy_from_slice(&order.buy_amount);
    // [6]   validTo (uint32 left-padded)
    buf[192 + 28..192 + 32].copy_from_slice(&order.valid_to.to_be_bytes());
    // [7]   appData = bytes32(0) → already zero in `buf`
    // [8]   feeAmount
    buf[256..288].copy_from_slice(&order.fee_amount);
    // [9]   kind
    let kh = kind_hash(order.kind);
    buf[288..320].copy_from_slice(&kh);
    // [10]  partiallyFillable (bool, 31 zero + 1 byte)
    buf[320 + 31] = order.partially_fillable;
    // [11]  sellTokenBalance
    let stb = balance_hash(order.sell_token_balance, true);
    buf[352..384].copy_from_slice(&stb);
    // [12]  buyTokenBalance
    let btb = balance_hash(order.buy_token_balance, false);
    buf[384..416].copy_from_slice(&btb);

    keccak(&buf)
}

// ---------------------------------------------------------------------------
// Final EIP-712 digest
// ---------------------------------------------------------------------------

/// Compute the EIP-712 digest the wallet signs:
/// `keccak256( 0x19 ‖ 0x01 ‖ domain_separator ‖ struct_hash )`.
pub fn eip712_digest(
    canonical: &[u8; CANONICAL_LEN],
    chain_id: u64,
) -> Result<[u8; 32], Eip712Error> {
    let order = decode_canonical(canonical)?;
    let dom = domain_separator(chain_id, &GPV2_SETTLEMENT_ADDRESS);
    let sh = struct_hash(&order);

    let mut buf = [0u8; 2 + 32 + 32];
    buf[0] = 0x19;
    buf[1] = 0x01;
    buf[2..34].copy_from_slice(&dom);
    buf[34..66].copy_from_slice(&sh);
    Ok(keccak(&buf))
}
