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

// ---------------------------------------------------------------------------
// setPreSignature orderUid cross-check — the v3 security gate
// ---------------------------------------------------------------------------
//
// When a UserOp's inner calldata is `setPreSignature(orderUid, true)`
// and the companion attaches a v3 trailer (canonical GPv2Order), the
// secure world must prove that the canonical the user *saw* on the
// 8-page display is the order the *on-chain* settlement contract will
// act on. The only thing bridging those two worlds is the 56-byte
// `orderUid` in the setPreSignature calldata. So: compute the orderUid
// natively from the canonical bytes + the UserOp's sender, and
// byte-compare it against the calldata.

/// Extents of the 56-byte orderUid inside a 164-byte setPreSignature
/// calldata. The calldata ABI layout is
/// `selector(4) || bytes_offset(32)=0x40 || bool_signed(32)=1 ||
///  bytes_len(32)=56 || orderUid(56) || zero_pad(8)` — so the orderUid
/// starts at byte 100 and is 56 bytes wide.
pub const SETPRESIG_ORDERUID_OFFSET: usize = 100;
pub const SETPRESIG_ORDERUID_LEN: usize = 56;
/// Slice of `orderUid` that is the 32-byte EIP-712 order digest.
pub const SETPRESIG_ORDER_DIGEST_OFFSET: usize = SETPRESIG_ORDERUID_OFFSET;
pub const SETPRESIG_ORDER_DIGEST_LEN: usize = 32;
/// Slice of `orderUid` that is the 20-byte owner.
pub const SETPRESIG_OWNER_OFFSET: usize = SETPRESIG_ORDERUID_OFFSET + 32;
pub const SETPRESIG_OWNER_LEN: usize = 20;
/// Slice of `orderUid` that is the 4-byte BE validTo.
pub const SETPRESIG_VALID_TO_OFFSET: usize = SETPRESIG_OWNER_OFFSET + SETPRESIG_OWNER_LEN;
pub const SETPRESIG_VALID_TO_LEN: usize = 4;

/// Failure modes for the v3 `setPreSignature` cross-check. Kept as a
/// discriminated enum (rather than a `Result<(), ()>`) so the caller
/// can surface a precise error to telemetry + trusted UI even when the
/// outer return value is unit-valued rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderUidMismatch {
    /// Canonical bytes failed to decode (malformed enum byte).
    CanonicalDecode,
    /// `canonical.chain_id` did not equal the VK bundle's chain_id.
    ChainIdMismatch,
    /// `canonical.valid_to` ≠ calldata's validTo.
    ValidToMismatch,
    /// The 32-byte orderDigest derived from the canonical does not
    /// match the orderDigest in the calldata's orderUid.
    OrderDigestMismatch,
    /// The 20-byte owner in the calldata's orderUid does not match
    /// the UserOp's sender (the smart account address).
    OwnerMismatch,
}

/// Cross-check a v3-verified canonical GPv2Order against the
/// setPreSignature calldata + UserOp sender.
///
/// Invariants enforced (in order — first failure wins so the reject
/// reason maps cleanly to a user-facing error):
///
///  1. `canonical.chain_id == bundle_chain_id` (also enforced
///     internally by `compute_digest`, duplicated here so the caller
///     can distinguish this failure from a bad digest).
///  2. `canonical.valid_to` == `orderUid[52..56]` (byte-compare, no
///     integer parse — a zero-validTo attacker can't get a false pass
///     via endianness confusion).
///  3. `compute_digest(canonical)[..]` equals `orderUid[0..32]`. This
///     binds EVERY field of the GPv2Order struct (appData, fee, kind,
///     balance enums, amounts, both token addresses, receiver, …) —
///     struct_hash is a keccak over all 12 fields plus ORDER_TYPEHASH,
///     so equality here subsumes the per-field byte checks.
///  4. `orderUid[32..52]` == UserOp sender (the smart account
///     address). CoW's settlement contract requires
///     `msg.sender == uid.owner` for pre-signing; signing an
///     orderUid whose owner is someone else would either revert
///     on-chain (wasted gas) or, worse, pre-sign a third party's
///     order as ours. Either way: reject.
pub fn cross_check_setpresig_calldata(
    canonical: &[u8; 204],
    calldata: &[u8; 164],
    bundle_chain_id: u64,
    userop_sender: &[u8; 20],
) -> Result<(), OrderUidMismatch> {
    // (1) decode + chain_id match — compute_digest does both.
    let order_digest = match compute_digest(canonical, bundle_chain_id) {
        Ok(d) => d,
        Err(Eip712Error::ChainIdMismatch) => return Err(OrderUidMismatch::ChainIdMismatch),
        Err(_) => return Err(OrderUidMismatch::CanonicalDecode),
    };

    // (2) validTo — byte-for-byte.
    let canonical_valid_to = &canonical[164..168];
    let calldata_valid_to =
        &calldata[SETPRESIG_VALID_TO_OFFSET..SETPRESIG_VALID_TO_OFFSET + SETPRESIG_VALID_TO_LEN];
    if canonical_valid_to != calldata_valid_to {
        return Err(OrderUidMismatch::ValidToMismatch);
    }

    // (3) orderDigest — the heavy invariant. struct_hash covers every
    //     GPv2Order field, so byte equality here locks the entire
    //     order into the calldata the chain will see.
    let calldata_digest = &calldata
        [SETPRESIG_ORDER_DIGEST_OFFSET..SETPRESIG_ORDER_DIGEST_OFFSET + SETPRESIG_ORDER_DIGEST_LEN];
    if order_digest.as_slice() != calldata_digest {
        return Err(OrderUidMismatch::OrderDigestMismatch);
    }

    // (4) owner — must equal the UserOp sender.
    let calldata_owner = &calldata[SETPRESIG_OWNER_OFFSET..SETPRESIG_OWNER_OFFSET + SETPRESIG_OWNER_LEN];
    if calldata_owner != userop_sender.as_slice() {
        return Err(OrderUidMismatch::OwnerMismatch);
    }

    Ok(())
}

/// Check the structural shape of a setPreSignature calldata — the
/// selector, ABI encoding bytes, `signed == true` flag, bytes-length
/// prefix, and zero-padding tail. This replaces the bytes-level
/// guarantees that the v1 `cowswap_set_pre_signature` circuit used to
/// make; the firmware checks them natively now instead of running a
/// separate proof.
pub fn check_setpresig_calldata_shape(calldata: &[u8; 164]) -> Result<(), OrderUidMismatch> {
    // Selector.
    if &calldata[0..4] != &[0xec, 0x6c, 0xb1, 0x3f] {
        return Err(OrderUidMismatch::CanonicalDecode);
    }
    // ABI bytes offset = 0x40 at slot 0.
    for b in &calldata[4..35] {
        if *b != 0 {
            return Err(OrderUidMismatch::CanonicalDecode);
        }
    }
    if calldata[35] != 0x40 {
        return Err(OrderUidMismatch::CanonicalDecode);
    }
    // Bool signed == true at slot 1.
    for b in &calldata[36..67] {
        if *b != 0 {
            return Err(OrderUidMismatch::CanonicalDecode);
        }
    }
    if calldata[67] != 1 {
        return Err(OrderUidMismatch::CanonicalDecode);
    }
    // Bytes length = 56 at slot 2.
    for b in &calldata[68..99] {
        if *b != 0 {
            return Err(OrderUidMismatch::CanonicalDecode);
        }
    }
    if calldata[99] != 56 {
        return Err(OrderUidMismatch::CanonicalDecode);
    }
    // Zero padding at [156..164).
    for b in &calldata[156..164] {
        if *b != 0 {
            return Err(OrderUidMismatch::CanonicalDecode);
        }
    }
    Ok(())
}

#[cfg(test)]
mod cross_check_tests {
    use super::*;

    // 1000 USDC → ≥ 0.5 WETH fixture — matches companion e2e_vector.
    fn fixture_canonical() -> [u8; 204] {
        let mut c = [0u8; 204];
        c[0..8].copy_from_slice(&1u64.to_be_bytes()); // chain_id
        c[8..28].copy_from_slice(&[
            0xa0, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9d, 0x4a, 0x2e, 0x9e,
            0xb0, 0xce, 0x36, 0x06, 0xeb, 0x48,
        ]); // USDC
        c[28..48].copy_from_slice(&[
            0xc0, 0x2a, 0xaa, 0x39, 0xb2, 0x23, 0xfe, 0x8d, 0x0a, 0x0e, 0x5c, 0x4f, 0x27, 0xea,
            0xd9, 0x08, 0x3c, 0x75, 0x6c, 0xc2,
        ]); // WETH
        c[48..68].copy_from_slice(&[
            0x74, 0x2d, 0x35, 0xcc, 0x66, 0x34, 0xc0, 0x53, 0x29, 0x25, 0xa3, 0xb8, 0x44, 0xbc,
            0x45, 0x4e, 0x44, 0x38, 0xf4, 0x4e,
        ]); // receiver
            // sell_amount = 1_000_000_000 at [68..100]
        c[96..100].copy_from_slice(&1_000_000_000u32.to_be_bytes());
        // buy_amount = 0x06F05B59D3B20000 at [100..132]
        c[124..132].copy_from_slice(&0x06F05B59D3B20000u64.to_be_bytes());
        // fee_amount = 0 at [132..164]
        // valid_to = 0x68000000 at [164..168]
        c[164..168].copy_from_slice(&0x68000000u32.to_be_bytes());
        c[168] = 0; // kind = Sell
        c[169] = 0;
        c[170] = 0;
        c[171] = 0;
        c[172..204].copy_from_slice(&[
            0x83, 0xb9, 0xdc, 0xb2, 0x31, 0x6e, 0x54, 0xfc, 0x04, 0xc1, 0x0f, 0x74, 0xc9, 0xa3,
            0xd5, 0xdd, 0x66, 0xa9, 0xe4, 0xc4, 0x3c, 0x04, 0xcc, 0xef, 0xb9, 0xc0, 0xc0, 0x3e,
            0x61, 0xe5, 0xfb, 0x28,
        ]);
        c
    }

    fn fixture_owner() -> [u8; 20] {
        [0xfb, 0x3c, 0x7e, 0xb9, 0x36, 0xcA, 0xA1, 0x2B, 0x5A, 0x88, 0x4d, 0x61, 0x23, 0x93, 0x96, 0x9A, 0x55, 0x7d, 0x43, 0x07]
    }

    /// Hand-build a setPreSignature calldata for the fixture owner +
    /// canonical. Reuses `compute_digest` for the orderDigest slice.
    fn fixture_calldata() -> [u8; 164] {
        let canonical = fixture_canonical();
        let digest = compute_digest(&canonical, 1).unwrap();
        let owner = fixture_owner();
        let mut cd = [0u8; 164];
        cd[0..4].copy_from_slice(&[0xec, 0x6c, 0xb1, 0x3f]);
        cd[35] = 0x40;
        cd[67] = 1;
        cd[99] = 56;
        cd[100..132].copy_from_slice(&digest);
        cd[132..152].copy_from_slice(&owner);
        cd[152..156].copy_from_slice(&canonical[164..168]);
        cd
    }

    #[test]
    fn happy_path_passes() {
        let canonical = fixture_canonical();
        let calldata = fixture_calldata();
        let owner = fixture_owner();
        assert!(cross_check_setpresig_calldata(&canonical, &calldata, 1, &owner).is_ok());
        assert!(check_setpresig_calldata_shape(&calldata).is_ok());
    }

    #[test]
    fn chain_id_mismatch_rejected() {
        let canonical = fixture_canonical();
        let calldata = fixture_calldata();
        let owner = fixture_owner();
        assert_eq!(
            cross_check_setpresig_calldata(&canonical, &calldata, 137, &owner),
            Err(OrderUidMismatch::ChainIdMismatch)
        );
    }

    #[test]
    fn valid_to_mismatch_rejected() {
        let canonical = fixture_canonical();
        let mut calldata = fixture_calldata();
        calldata[152] = calldata[152].wrapping_add(1);
        let owner = fixture_owner();
        // The valid_to check runs before the digest check, so this
        // bubbles out as ValidToMismatch (digest would also fail).
        assert_eq!(
            cross_check_setpresig_calldata(&canonical, &calldata, 1, &owner),
            Err(OrderUidMismatch::ValidToMismatch)
        );
    }

    #[test]
    fn order_digest_flip_rejected() {
        let canonical = fixture_canonical();
        let mut calldata = fixture_calldata();
        calldata[100] ^= 0x01;
        let owner = fixture_owner();
        assert_eq!(
            cross_check_setpresig_calldata(&canonical, &calldata, 1, &owner),
            Err(OrderUidMismatch::OrderDigestMismatch)
        );
    }

    #[test]
    fn canonical_field_flip_rejected_via_digest() {
        // Flip any single byte of canonical that isn't chain_id or
        // valid_to and the orderDigest will diverge — catching the
        // attack "swap the appData silently behind a verified proof".
        let mut canonical = fixture_canonical();
        canonical[172] ^= 0xFF; // appData MSB
        let calldata = fixture_calldata();
        let owner = fixture_owner();
        assert_eq!(
            cross_check_setpresig_calldata(&canonical, &calldata, 1, &owner),
            Err(OrderUidMismatch::OrderDigestMismatch)
        );
    }

    #[test]
    fn owner_mismatch_rejected() {
        let canonical = fixture_canonical();
        let mut calldata = fixture_calldata();
        calldata[132] ^= 0x01;
        let owner = fixture_owner();
        assert_eq!(
            cross_check_setpresig_calldata(&canonical, &calldata, 1, &owner),
            Err(OrderUidMismatch::OwnerMismatch)
        );
    }

    #[test]
    fn shape_check_rejects_bad_selector() {
        let mut cd = fixture_calldata();
        cd[0] ^= 0xFF;
        assert_eq!(
            check_setpresig_calldata_shape(&cd),
            Err(OrderUidMismatch::CanonicalDecode)
        );
    }

    #[test]
    fn shape_check_rejects_signed_false() {
        let mut cd = fixture_calldata();
        cd[67] = 0;
        assert_eq!(
            check_setpresig_calldata_shape(&cd),
            Err(OrderUidMismatch::CanonicalDecode)
        );
    }

    #[test]
    fn shape_check_rejects_nonzero_tail_padding() {
        let mut cd = fixture_calldata();
        cd[163] = 1;
        assert_eq!(
            check_setpresig_calldata_shape(&cd),
            Err(OrderUidMismatch::CanonicalDecode)
        );
    }
}
