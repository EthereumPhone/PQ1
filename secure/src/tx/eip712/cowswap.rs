//! CowSwap GPv2Order — EIP-712 typed-data clear-signing protocol.
//!
//! See `docs/m4-cowswap-eip712-impl.md` for the rationale behind the
//! 204-byte packed canonical encoding (which is shared with the
//! Groth16 circuit at `circuits/cowswap/eip712_order/circuit.circom`).
//!
//! ## Canonical layout (204 bytes — v3)
//!
//! ```text
//!   [  0..  8 )  chain_id           (u64 BE)          ← NEW in v3
//!   [  8..  28)  sellToken          (20 B address)
//!   [ 28..  48)  buyToken           (20 B address)
//!   [ 48..  68)  receiver           (20 B address)
//!   [ 68..  100) sellAmount         (uint256 BE)
//!   [100.. 132)  buyAmount          (uint256 BE)
//!   [132.. 164)  feeAmount          (uint256 BE)
//!   [164.. 168)  validTo            (uint32 BE)
//!   [168]        kind               (0 = sell, 1 = buy)
//!   [169]        partiallyFillable  (0 / 1)
//!   [170]        sellTokenBalance   (0 / 1 / 2)
//!   [171]        buyTokenBalance    (0 / 1)
//!   [172.. 204)  appData            (bytes32)         ← NEW in v3
//! ```
//!
//! `chain_id` is bound via Poseidon so a single proof can't be
//! replayed across chains (the Merkle lookup in the circuit also
//! cross-checks that the resolved token entry came from the same
//! chain). `compute_digest` further verifies that `canonical.chain_id
//! === verified.chain_id` from the VK bundle before deriving the
//! EIP-712 digest, so NS can't supply a mismatched VK.
//!
//! `appData` is now genuinely bound — v2 pinned it to `bytes32(0)`.

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
    pub chain_id: u64,
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
    pub app_data: [u8; 32],
}

/// Parse the 204-byte canonical packed encoding into structured
/// fields. Validates the small-enum byte ranges (kind,
/// partiallyFillable, balance kinds) so an out-of-range NS payload
/// is rejected before it can produce a digest.
pub fn decode_canonical(canonical: &[u8; 204]) -> Result<GpV2Order, Eip712Error> {
    let chain_id = u64::from_be_bytes([
        canonical[0], canonical[1], canonical[2], canonical[3],
        canonical[4], canonical[5], canonical[6], canonical[7],
    ]);

    let mut sell_token = [0u8; 20];
    sell_token.copy_from_slice(&canonical[8..28]);
    let mut buy_token = [0u8; 20];
    buy_token.copy_from_slice(&canonical[28..48]);
    let mut receiver = [0u8; 20];
    receiver.copy_from_slice(&canonical[48..68]);

    let mut sell_amount = [0u8; 32];
    sell_amount.copy_from_slice(&canonical[68..100]);
    let mut buy_amount = [0u8; 32];
    buy_amount.copy_from_slice(&canonical[100..132]);
    let mut fee_amount = [0u8; 32];
    fee_amount.copy_from_slice(&canonical[132..164]);

    let valid_to = u32::from_be_bytes([
        canonical[164],
        canonical[165],
        canonical[166],
        canonical[167],
    ]);

    let kind = canonical[168];
    let partially_fillable = canonical[169];
    let sell_token_balance = canonical[170];
    let buy_token_balance = canonical[171];

    if kind > 1
        || partially_fillable > 1
        || sell_token_balance > 2
        || buy_token_balance > 1
    {
        return Err(Eip712Error::EnumOutOfRange);
    }

    let mut app_data = [0u8; 32];
    app_data.copy_from_slice(&canonical[172..204]);

    Ok(GpV2Order {
        chain_id,
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
        app_data,
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
/// `appData` is now bound from the canonical buffer (v3) — v2 pinned
/// it to `bytes32(0)`, which meant orders with non-empty appCode
/// couldn't be clear-signed.
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
    // [7] appData (bytes32) — bound verbatim from canonical in v3.
    buf[224..256].copy_from_slice(&order.app_data);
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
/// GPv2Order, given the 204-byte canonical bytes the Groth16 proof
/// has already bound and the chain id from the verified VK bundle.
///
/// Cross-checks that `canonical.chain_id === verified_chain_id`: the
/// Groth16 proof binds the chain_id inside the canonical buffer via
/// Poseidon, and this check prevents NS from pairing a legitimate
/// proof with a mismatched VK bundle (e.g. mainnet proof + Gnosis
/// bundle — the digest would otherwise be signed against the wrong
/// domain separator).
pub fn compute_digest(canonical: &[u8; 204], chain_id: u64) -> Result<[u8; 32], Eip712Error> {
    let order = decode_canonical(canonical)?;
    if order.chain_id != chain_id {
        return Err(Eip712Error::ChainIdMismatch);
    }
    let name_hash = keccak(COWSWAP_DOMAIN_NAME);
    let version_hash = keccak(COWSWAP_DOMAIN_VERSION);
    let dom = eip712_domain_separator(&name_hash, &version_hash, chain_id, &GPV2_SETTLEMENT_ADDRESS);
    let sh = struct_hash(&order);
    Ok(final_digest(&dom, &sh))
}
