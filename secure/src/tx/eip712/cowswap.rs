//! CowSwap GPv2Order — EIP-712 typed-data clear-signing protocol.
//!
//! See `docs/m4-cowswap-eip712-impl.md` for the rationale behind the
//! 164-byte packed canonical encoding (which is shared with the
//! Groth16 circuit at `circuits/cowswap/eip712_order/circuit.circom`).
//!
//! ## Canonical layout (164 bytes — UNCHANGED across M4 v1/v2)
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
//!   [161]        partiallyFillable  (0 / 1)
//!   [162]        sellTokenBalance   (0 / 1 / 2)
//!   [163]        buyTokenBalance    (0 / 1)
//! ```
//!
//! `appData` is forced to `bytes32(0)` (the empty-metadata default
//! most CowSwap orders use). v3 can either grow the canonical buffer
//! to 217 B + add `poseidon7`, or shuttle `appData` over a separate
//! non-Poseidon-bound channel.

use super::{eip712_domain_separator, final_digest, keccak, Eip712Error};

// ---------------------------------------------------------------------------
// Public addresses
// ---------------------------------------------------------------------------

/// CowSwap GPv2Settlement is deployed at this CREATE2 address on
/// every chain CowSwap supports (Mainnet, Gnosis Chain, Arbitrum,
/// Base). Used as the `verifyingContract` field in the EIP-712
/// domain separator.
pub const GPV2_SETTLEMENT_ADDRESS: [u8; 20] = [
    0x90, 0x08, 0xd1, 0x9f, 0x58, 0xaa, 0xbd, 0x9e, 0xd0, 0xd6,
    0x09, 0x71, 0x56, 0x5a, 0xa8, 0x51, 0x05, 0x60, 0xab, 0x41,
];

/// Sentinel address that this protocol uses as its lookup key in
/// the VK DB. The trailing `0xab42` differs from the real
/// `GPV2_SETTLEMENT_ADDRESS` (which ends in `0xab41`) so the
/// `(chain_id, contract)` lookup key remains unique against the
/// existing M3 setPreSignature entries (which key on the real
/// address). The sentinel never makes it onto Ethereum: it is a
/// pure DB key. The firmware hardcodes the real
/// `GPV2_SETTLEMENT_ADDRESS` in the EIP-712 domain separator below.
pub const SENTINEL: [u8; 20] = [
    0x90, 0x08, 0xd1, 0x9f, 0x58, 0xaa, 0xbd, 0x9e, 0xd0, 0xd6,
    0x09, 0x71, 0x56, 0x5a, 0xa8, 0x51, 0x05, 0x60, 0xab, 0x42,
];

// ---------------------------------------------------------------------------
// EIP-712 typehashes (constant preimages, hashed lazily on first use).
// ---------------------------------------------------------------------------

/// `keccak256("Order(address sellToken,address buyToken,address receiver,uint256 sellAmount,uint256 buyAmount,uint32 validTo,bytes32 appData,uint256 feeAmount,bytes32 kind,bool partiallyFillable,bytes32 sellTokenBalance,bytes32 buyTokenBalance)")`.
const ORDER_TYPEHASH_PREIMAGE: &[u8] = b"Order(address sellToken,address buyToken,address receiver,uint256 sellAmount,uint256 buyAmount,uint32 validTo,bytes32 appData,uint256 feeAmount,bytes32 kind,bool partiallyFillable,bytes32 sellTokenBalance,bytes32 buyTokenBalance)";

const COWSWAP_DOMAIN_NAME: &[u8] = b"Gnosis Protocol";
const COWSWAP_DOMAIN_VERSION: &[u8] = b"v2";

// ---------------------------------------------------------------------------
// Decoded order
// ---------------------------------------------------------------------------

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

/// Parse the 164-byte canonical packed encoding into structured
/// fields. Validates the small-enum byte ranges (kind,
/// partiallyFillable, balance kinds) so an out-of-range NS payload
/// is rejected before it can produce a digest.
pub fn decode_canonical(canonical: &[u8; 164]) -> Result<GpV2Order, Eip712Error> {
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
// Struct hash
// ---------------------------------------------------------------------------

/// `keccak256("sell")` / `keccak256("buy")` for the kind enum.
fn kind_hash(kind: u8) -> [u8; 32] {
    if kind == 0 {
        keccak(b"sell")
    } else {
        keccak(b"buy")
    }
}

/// Balance enum: `keccak256("erc20" | "external" | "internal")`.
/// `is_sell_side` distinguishes the sell-side enum (0/1/2) from
/// the buy-side enum (0/1) — the buy-side never resolves to
/// `external`.
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
/// `appData` is fixed at `bytes32(0)` for v1.
pub fn struct_hash(order: &GpV2Order) -> [u8; 32] {
    // 13 fields × 32 bytes = 416 bytes.
    let mut buf = [0u8; 32 * 13];

    let typehash = keccak(ORDER_TYPEHASH_PREIMAGE);
    buf[0..32].copy_from_slice(&typehash);

    // [1] sellToken (left-padded address)
    buf[32 + 12..32 + 32].copy_from_slice(&order.sell_token);
    // [2] buyToken
    buf[64 + 12..64 + 32].copy_from_slice(&order.buy_token);
    // [3] receiver
    buf[96 + 12..96 + 32].copy_from_slice(&order.receiver);
    // [4] sellAmount
    buf[128..160].copy_from_slice(&order.sell_amount);
    // [5] buyAmount
    buf[160..192].copy_from_slice(&order.buy_amount);
    // [6] validTo (uint32 left-padded)
    buf[192 + 28..192 + 32].copy_from_slice(&order.valid_to.to_be_bytes());
    // [7] appData = bytes32(0) → already zero
    // [8] feeAmount
    buf[256..288].copy_from_slice(&order.fee_amount);
    // [9] kind
    buf[288..320].copy_from_slice(&kind_hash(order.kind));
    // [10] partiallyFillable (bool, 31 zero + 1 byte)
    buf[320 + 31] = order.partially_fillable;
    // [11] sellTokenBalance
    buf[352..384].copy_from_slice(&balance_hash(order.sell_token_balance, true));
    // [12] buyTokenBalance
    buf[384..416].copy_from_slice(&balance_hash(order.buy_token_balance, false));

    keccak(&buf)
}

// ---------------------------------------------------------------------------
// Top-level digest entrypoint (matches Eip712ProtocolEntry::compute)
// ---------------------------------------------------------------------------

/// Compute the EIP-712 digest the wallet signs for a CowSwap
/// GPv2Order, given the 164-byte canonical bytes the Groth16 proof
/// has already bound and the chain id from the verified VK bundle.
pub fn compute_digest(canonical: &[u8; 164], chain_id: u64) -> Result<[u8; 32], Eip712Error> {
    let order = decode_canonical(canonical)?;
    let name_hash = keccak(COWSWAP_DOMAIN_NAME);
    let version_hash = keccak(COWSWAP_DOMAIN_VERSION);
    let dom = eip712_domain_separator(&name_hash, &version_hash, chain_id, &GPV2_SETTLEMENT_ADDRESS);
    let sh = struct_hash(&order);
    Ok(final_digest(&dom, &sh))
}
