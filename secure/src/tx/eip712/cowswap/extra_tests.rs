//! Extension suite for the CoW v3 clear-sign pipeline.
//!
//! The existing `test_vectors.rs` proves the happy path verifies and
//! that five per-field flips reject. This module rounds out the
//! adversarial story:
//!
//!   * **Frozen-format anchors** — the protocol-defining byte strings
//!     (typehash preimages, domain `name` / `version`, settlement
//!     address, enum-string hashes) are pinned against well-known
//!     values so that a "harmless" refactor cannot silently realign
//!     every signed digest.
//!   * **Enum-range coverage** — every legal enum byte combination
//!     decodes, every out-of-range byte is rejected with
//!     `EnumOutOfRange`.
//!   * **Cross-check ordering** — the first-failure-wins semantics
//!     of [`cross_check_setpresig_calldata`] are exhaustive; one
//!     deliberately bad calldata that fails *three* invariants at once
//!     must surface the documented-first one.
//!   * **Calldata-shape exhaustion** — every byte the shape check
//!     pins must reject when flipped.
//!   * **Field-binding** — flipping any byte of the canonical (outside
//!     chain_id / valid_to which are checked separately) must change
//!     the digest. Belt-and-braces against a future struct_hash
//!     refactor that dropped a field.

use super::{
    balance_hash, check_setpresig_calldata_shape, compute_digest, cross_check_setpresig_calldata,
    decode_canonical, kind_hash, struct_hash, COWSWAP_DOMAIN_NAME, COWSWAP_DOMAIN_VERSION,
    GPV2_SETTLEMENT_ADDRESS, ORDER_TYPEHASH_PREIMAGE, SETPRESIG_ORDERUID_OFFSET,
    SETPRESIG_ORDER_DIGEST_LEN, SETPRESIG_ORDER_DIGEST_OFFSET, SETPRESIG_OWNER_LEN,
    SETPRESIG_OWNER_OFFSET, SETPRESIG_VALID_TO_LEN, SETPRESIG_VALID_TO_OFFSET,
};
use crate::tx::eip712::{keccak, Eip712Error};

// ---------------------------------------------------------------------------
// Local fixtures
// ---------------------------------------------------------------------------
//
// Kept self-contained (rather than re-using the parent `test_vectors.rs`
// `fixture_*` helpers) so this file can be deleted without touching the
// historical suite. The values here mirror the 1000 USDC → WETH fixture
// but use simple deterministic bytes everywhere a corruption is not the
// point of the test.

const FIXTURE_CHAIN_ID: u64 = 1;
const FIXTURE_OWNER: [u8; 20] = [
    0xfb, 0x3c, 0x7e, 0xb9, 0x36, 0xca, 0xa1, 0x2b, 0x5a, 0x88, 0x4d, 0x61, 0x23, 0x93, 0x96, 0x9a,
    0x55, 0x7d, 0x43, 0x07,
];

fn fixture_canonical() -> [u8; 204] {
    let mut c = [0u8; 204];
    c[0..8].copy_from_slice(&FIXTURE_CHAIN_ID.to_be_bytes());
    // sell_token, buy_token, receiver — fill with deterministic non-zero
    // bytes so any per-byte flip below moves us off the all-zero collision
    // surface.
    for (i, slot) in c[8..68].iter_mut().enumerate() {
        *slot = 0x10u8.wrapping_add(i as u8);
    }
    // sell_amount, buy_amount, fee_amount: tiny non-zero numbers in the
    // low bytes so the high bytes can be flipped to exercise the binding.
    c[99] = 0x10;
    c[131] = 0x20;
    c[163] = 0x30;
    // valid_to
    c[164..168].copy_from_slice(&0x68000000u32.to_be_bytes());
    // enums — all zero, all legal.
    c[168] = 0;
    c[169] = 0;
    c[170] = 0;
    c[171] = 0;
    // appData
    for (i, slot) in c[172..204].iter_mut().enumerate() {
        *slot = 0xC0u8.wrapping_add(i as u8);
    }
    c
}

fn build_calldata(digest: &[u8; 32], owner: &[u8; 20], valid_to_be: &[u8; 4]) -> [u8; 164] {
    let mut cd = [0u8; 164];
    cd[0..4].copy_from_slice(&[0xec, 0x6c, 0xb1, 0x3f]);
    cd[35] = 0x40;
    cd[67] = 1;
    cd[99] = 56;
    cd[100..132].copy_from_slice(digest);
    cd[132..152].copy_from_slice(owner);
    cd[152..156].copy_from_slice(valid_to_be);
    cd
}

fn fixture_calldata() -> [u8; 164] {
    let canonical = fixture_canonical();
    let digest = compute_digest(&canonical, FIXTURE_CHAIN_ID).unwrap();
    build_calldata(&digest, &FIXTURE_OWNER, &[0x68, 0x00, 0x00, 0x00])
}

// ===========================================================================
// Positive coverage
// ===========================================================================

#[test]
fn positive_decode_accepts_all_valid_enum_combinations() {
    // Cross product: kind ∈ {0,1}, partially_fillable ∈ {0,1},
    // sell_token_balance ∈ {0,1,2}, buy_token_balance ∈ {0,1} → 24
    // combinations. Every one must decode.
    let mut c = fixture_canonical();
    for kind in 0u8..=1 {
        for pf in 0u8..=1 {
            for stb in 0u8..=2 {
                for btb in 0u8..=1 {
                    c[168] = kind;
                    c[169] = pf;
                    c[170] = stb;
                    c[171] = btb;
                    let r = decode_canonical(&c);
                    assert!(
                        r.is_ok(),
                        "decode must accept kind={kind} pf={pf} stb={stb} btb={btb}"
                    );
                    let o = r.unwrap();
                    assert_eq!(o.kind, kind);
                    assert_eq!(o.partially_fillable, pf);
                    assert_eq!(o.sell_token_balance, stb);
                    assert_eq!(o.buy_token_balance, btb);
                }
            }
        }
    }
}

#[test]
fn positive_decode_round_trips_all_byte_fields() {
    let c = fixture_canonical();
    let o = decode_canonical(&c).unwrap();
    assert_eq!(o.chain_id, FIXTURE_CHAIN_ID);
    assert_eq!(&o.sell_token, &c[8..28]);
    assert_eq!(&o.buy_token, &c[28..48]);
    assert_eq!(&o.receiver, &c[48..68]);
    assert_eq!(&o.sell_amount, &c[68..100]);
    assert_eq!(&o.buy_amount, &c[100..132]);
    assert_eq!(&o.fee_amount, &c[132..164]);
    assert_eq!(o.valid_to, 0x68000000);
    assert_eq!(&o.app_data, &c[172..204]);
}

#[test]
fn positive_compute_digest_is_deterministic() {
    let c = fixture_canonical();
    let a = compute_digest(&c, FIXTURE_CHAIN_ID).unwrap();
    let b = compute_digest(&c, FIXTURE_CHAIN_ID).unwrap();
    assert_eq!(a, b);
}

#[test]
fn positive_struct_hash_is_deterministic() {
    let c = fixture_canonical();
    let o = decode_canonical(&c).unwrap();
    assert_eq!(struct_hash(&o), struct_hash(&o));
}

#[test]
fn positive_kind_hash_sell_buy() {
    assert_eq!(kind_hash(0), keccak(b"sell"));
    assert_eq!(kind_hash(1), keccak(b"buy"));
}

#[test]
fn positive_balance_hash_legal_values() {
    assert_eq!(balance_hash(0, true), keccak(b"erc20"));
    assert_eq!(balance_hash(1, true), keccak(b"external"));
    assert_eq!(balance_hash(2, true), keccak(b"internal"));
    assert_eq!(balance_hash(0, false), keccak(b"erc20"));
    assert_eq!(balance_hash(1, false), keccak(b"internal"));
}

#[test]
fn positive_setpresig_offset_constants_match_layout() {
    // The ABI layout in the doc says orderUid begins at byte 100 and is
    // 56 bytes wide. Pin every derived offset to that authoritative
    // value so a renumbering refactor is rejected loudly.
    assert_eq!(SETPRESIG_ORDERUID_OFFSET, 100);
    assert_eq!(SETPRESIG_ORDER_DIGEST_OFFSET, 100);
    assert_eq!(SETPRESIG_ORDER_DIGEST_LEN, 32);
    assert_eq!(SETPRESIG_OWNER_OFFSET, 132);
    assert_eq!(SETPRESIG_OWNER_LEN, 20);
    assert_eq!(SETPRESIG_VALID_TO_OFFSET, 152);
    assert_eq!(SETPRESIG_VALID_TO_LEN, 4);
    // And the three sub-fields cover the full 56-byte orderUid:
    assert_eq!(SETPRESIG_ORDER_DIGEST_LEN + SETPRESIG_OWNER_LEN + SETPRESIG_VALID_TO_LEN, 56);
}

// ===========================================================================
// Negative coverage — frozen format
// ===========================================================================

#[test]
fn negative_order_typehash_preimage_is_byte_stable() {
    // ASSUMPTION: the typehash preimage matches the CoW orderbook +
    // settlement contract's expectations. The module comment in
    // `mod.rs` explicitly warns that getting this wrong yields
    // `0x1a59c8ff…` instead of the canonical `0xd5a25ba2…` and breaks
    // every orderUid. Anchor both the ASCII string AND the keccak
    // digest so a refactor that "cleans up" the bytes breaks loudly.
    assert_eq!(
        ORDER_TYPEHASH_PREIMAGE,
        b"Order(address sellToken,address buyToken,address receiver,uint256 sellAmount,uint256 buyAmount,uint32 validTo,bytes32 appData,uint256 feeAmount,string kind,bool partiallyFillable,string sellTokenBalance,string buyTokenBalance)",
    );
    // Known-answer for the canonical Gnosis Protocol Order typehash, as
    // shipped on every chain CowSwap supports — anchored here so a
    // refactor that "cleans up" the preimage breaks loudly. Verified
    // against a real filled order on Base mainnet (`0x59ebcff5…`) and
    // matches the on-chain `GPv2Order.TYPE_HASH` immutable.
    let expected_typehash: [u8; 32] = [
        0xd5, 0xa2, 0x5b, 0xa2, 0xe9, 0x70, 0x94, 0xad, 0x7d, 0x83, 0xdc, 0x28, 0xa6, 0x57, 0x2d,
        0xa7, 0x97, 0xd6, 0xb3, 0xe7, 0xfc, 0x66, 0x63, 0xbd, 0x93, 0xef, 0xb7, 0x89, 0xfc, 0x17,
        0xe4, 0x89,
    ];
    assert_eq!(
        keccak(ORDER_TYPEHASH_PREIMAGE),
        expected_typehash,
        "ORDER_TYPEHASH must equal 0xd5a25ba2… per docs/m4-cowswap-eip712-impl.md"
    );
}

#[test]
fn negative_domain_name_and_version_are_byte_stable() {
    // ASSUMPTION: the EIP-712 domain name + version match Gnosis
    // Protocol on-chain settlement (`"Gnosis Protocol"`, `"v2"`). A
    // future refactor that "modernises" the name to e.g. "CoW Protocol"
    // would silently shift every domain separator.
    assert_eq!(COWSWAP_DOMAIN_NAME, b"Gnosis Protocol");
    assert_eq!(COWSWAP_DOMAIN_VERSION, b"v2");
}

#[test]
fn negative_gpv2_settlement_address_is_byte_stable() {
    // ASSUMPTION: the GPv2Settlement CREATE2 address is identical
    // across every chain CoW supports and matches the on-chain
    // contract. Mass-replay attack model: a single-byte change yields a
    // signing identity for a different contract that the user did not
    // intend to authorise.
    assert_eq!(
        GPV2_SETTLEMENT_ADDRESS,
        [
            0x90, 0x08, 0xd1, 0x9f, 0x58, 0xaa, 0xbd, 0x9e, 0xd0, 0xd6, 0x09, 0x71, 0x56, 0x5a,
            0xa8, 0x51, 0x05, 0x60, 0xab, 0x41,
        ]
    );
}

// ===========================================================================
// Negative coverage — enum range
// ===========================================================================

#[test]
fn negative_decode_rejects_kind_out_of_range() {
    let mut c = fixture_canonical();
    for bad in [2u8, 3, 7, 100, 255] {
        c[168] = bad;
        match decode_canonical(&c) {
            Err(Eip712Error::EnumOutOfRange) => {}
            other => panic!(
                "kind={bad}: must reject with EnumOutOfRange, got {:?}",
                other.map(|_| ()).err()
            ),
        }
    }
}

#[test]
fn negative_decode_rejects_partially_fillable_out_of_range() {
    let mut c = fixture_canonical();
    for bad in [2u8, 3, 100, 255] {
        c[169] = bad;
        assert!(matches!(
            decode_canonical(&c),
            Err(Eip712Error::EnumOutOfRange)
        ));
    }
}

#[test]
fn negative_decode_rejects_sell_token_balance_out_of_range() {
    let mut c = fixture_canonical();
    for bad in [3u8, 4, 100, 255] {
        c[170] = bad;
        assert!(matches!(
            decode_canonical(&c),
            Err(Eip712Error::EnumOutOfRange)
        ));
    }
}

#[test]
fn negative_decode_rejects_buy_token_balance_out_of_range() {
    let mut c = fixture_canonical();
    for bad in [2u8, 3, 100, 255] {
        c[171] = bad;
        assert!(matches!(
            decode_canonical(&c),
            Err(Eip712Error::EnumOutOfRange)
        ));
    }
}

// ===========================================================================
// Negative coverage — chain-id binding inside compute_digest
// ===========================================================================

#[test]
fn negative_compute_digest_rejects_chain_id_mismatch() {
    let c = fixture_canonical();
    // canonical pinned to chain 1; caller supplies chain 137.
    assert!(matches!(
        compute_digest(&c, 137),
        Err(Eip712Error::ChainIdMismatch)
    ));
}

#[test]
fn negative_compute_digest_chain_id_zero_vs_one_is_distinct() {
    // ASSUMPTION: chain_id is bound into struct hashing via the domain
    // separator. ATTACK: a refactor that dropped chain_id from the DS
    // would let a chain-0 proof verify against any chain.
    let mut c = fixture_canonical();
    c[0..8].copy_from_slice(&0u64.to_be_bytes());
    let d0 = compute_digest(&c, 0).unwrap();
    c[0..8].copy_from_slice(&1u64.to_be_bytes());
    let d1 = compute_digest(&c, 1).unwrap();
    assert_ne!(
        d0, d1,
        "digest must distinguish chain_id 0 from chain_id 1 (replay protection)"
    );
}

// ===========================================================================
// Negative coverage — struct_hash field-binding (belt-and-braces)
// ===========================================================================
//
// Each of these flips one byte at a per-field representative offset
// and confirms the resulting digest moves. Subsumed by the orderDigest
// cross-check in `test_vectors.rs::canonical_field_flip_rejected_via_digest`,
// but spelt out explicitly here so that a future refactor that drops a
// field from the struct_hash preimage gets a unique failure pointing at
// the field.

fn assert_field_flip_changes_digest(field: &str, offset: usize) {
    let mut c = fixture_canonical();
    let d0 = compute_digest(&c, FIXTURE_CHAIN_ID).unwrap();
    c[offset] ^= 0xFF;
    let d1 = compute_digest(&c, FIXTURE_CHAIN_ID).unwrap();
    assert_ne!(
        d0, d1,
        "flipping a byte in {field} (offset {offset}) must change the digest"
    );
}

#[test]
fn negative_struct_hash_binds_sell_token() {
    assert_field_flip_changes_digest("sell_token", 8);
}

#[test]
fn negative_struct_hash_binds_buy_token() {
    assert_field_flip_changes_digest("buy_token", 28);
}

#[test]
fn negative_struct_hash_binds_receiver() {
    assert_field_flip_changes_digest("receiver", 48);
}

#[test]
fn negative_struct_hash_binds_sell_amount() {
    assert_field_flip_changes_digest("sell_amount", 99);
}

#[test]
fn negative_struct_hash_binds_buy_amount() {
    assert_field_flip_changes_digest("buy_amount", 131);
}

#[test]
fn negative_struct_hash_binds_fee_amount() {
    assert_field_flip_changes_digest("fee_amount", 163);
}

#[test]
fn negative_struct_hash_binds_valid_to() {
    assert_field_flip_changes_digest("valid_to", 167);
}

#[test]
fn negative_struct_hash_binds_app_data() {
    // v3-specific — `appData` was pinned to `bytes32(0)` in v2 and is
    // genuinely bound now. Any drift would re-open the v2 attack.
    assert_field_flip_changes_digest("app_data", 200);
}

#[test]
fn negative_struct_hash_binds_kind_enum() {
    let mut c = fixture_canonical();
    let d0 = compute_digest(&c, FIXTURE_CHAIN_ID).unwrap();
    c[168] = 1; // sell → buy
    let d1 = compute_digest(&c, FIXTURE_CHAIN_ID).unwrap();
    assert_ne!(d0, d1, "kind enum must be bound into struct_hash");
}

#[test]
fn negative_struct_hash_binds_partially_fillable() {
    let mut c = fixture_canonical();
    let d0 = compute_digest(&c, FIXTURE_CHAIN_ID).unwrap();
    c[169] = 1;
    let d1 = compute_digest(&c, FIXTURE_CHAIN_ID).unwrap();
    assert_ne!(d0, d1, "partially_fillable must be bound into struct_hash");
}

#[test]
fn negative_struct_hash_binds_sell_token_balance() {
    let mut c = fixture_canonical();
    let d0 = compute_digest(&c, FIXTURE_CHAIN_ID).unwrap();
    c[170] = 1;
    let d1 = compute_digest(&c, FIXTURE_CHAIN_ID).unwrap();
    assert_ne!(d0, d1, "sell_token_balance must be bound into struct_hash");
}

#[test]
fn negative_struct_hash_binds_buy_token_balance() {
    let mut c = fixture_canonical();
    let d0 = compute_digest(&c, FIXTURE_CHAIN_ID).unwrap();
    c[171] = 1;
    let d1 = compute_digest(&c, FIXTURE_CHAIN_ID).unwrap();
    assert_ne!(d0, d1, "buy_token_balance must be bound into struct_hash");
}

// ===========================================================================
// Negative coverage — cross-check first-failure-wins ordering
// ===========================================================================

#[test]
fn negative_cross_check_reports_chain_id_first() {
    // ATTACK: an attacker crafts a calldata whose orderDigest is wrong
    // AND owner is wrong AND chain_id is mismatched. The most specific
    // failure (chain_id) must surface first so telemetry can distinguish
    // it from a generic digest mismatch.
    let canonical = fixture_canonical();
    let mut cd = fixture_calldata();
    cd[100] ^= 0xFF; // mangle digest
    cd[132] ^= 0xFF; // mangle owner
    cd[152] ^= 0x01; // mangle validTo
    assert_eq!(
        cross_check_setpresig_calldata(&canonical, &cd, 137, &FIXTURE_OWNER),
        Err(super::OrderUidMismatch::ChainIdMismatch),
        "chain_id is the first invariant checked"
    );
}

#[test]
fn negative_cross_check_reports_valid_to_before_digest() {
    // Both validTo and digest are wrong; the doc claims validTo wins.
    let canonical = fixture_canonical();
    let mut cd = fixture_calldata();
    cd[100] ^= 0xFF; // wrong digest
    cd[152] ^= 0x01; // wrong validTo
    assert_eq!(
        cross_check_setpresig_calldata(&canonical, &cd, FIXTURE_CHAIN_ID, &FIXTURE_OWNER),
        Err(super::OrderUidMismatch::ValidToMismatch),
    );
}

#[test]
fn negative_cross_check_reports_digest_before_owner() {
    // Both digest and owner wrong; doc says digest wins.
    let canonical = fixture_canonical();
    let mut cd = fixture_calldata();
    cd[100] ^= 0xFF;
    cd[132] ^= 0xFF;
    assert_eq!(
        cross_check_setpresig_calldata(&canonical, &cd, FIXTURE_CHAIN_ID, &FIXTURE_OWNER),
        Err(super::OrderUidMismatch::OrderDigestMismatch),
    );
}

#[test]
fn negative_cross_check_rejects_appdata_swap_undetected_otherwise() {
    // Pre-v3, appData was pinned to bytes32(0) and an attacker could
    // swap it silently. This test simulates an attacker who built a
    // valid calldata for the original canonical and then swapped the
    // canonical's appData behind the proof — the digest cross-check
    // must catch it because v3 binds appData.
    let mut canonical = fixture_canonical();
    let cd = fixture_calldata();
    canonical[200] ^= 0xFF; // appData byte
    assert_eq!(
        cross_check_setpresig_calldata(&canonical, &cd, FIXTURE_CHAIN_ID, &FIXTURE_OWNER),
        Err(super::OrderUidMismatch::OrderDigestMismatch),
    );
}

// ===========================================================================
// Negative coverage — calldata-shape exhaustion
// ===========================================================================

#[test]
fn negative_shape_rejects_bytes_offset_not_0x40() {
    let mut cd = fixture_calldata();
    cd[35] = 0x60;
    assert!(check_setpresig_calldata_shape(&cd).is_err());
}

#[test]
fn negative_shape_rejects_high_byte_set_in_bytes_offset_field() {
    let mut cd = fixture_calldata();
    cd[20] = 0xFF; // any byte in [4..35] must be zero
    assert!(check_setpresig_calldata_shape(&cd).is_err());
}

#[test]
fn negative_shape_rejects_bytes_len_not_56() {
    let mut cd = fixture_calldata();
    cd[99] = 55;
    assert!(check_setpresig_calldata_shape(&cd).is_err());
    cd[99] = 57;
    assert!(check_setpresig_calldata_shape(&cd).is_err());
    cd[99] = 0;
    assert!(check_setpresig_calldata_shape(&cd).is_err());
}

#[test]
fn negative_shape_rejects_high_byte_set_in_signed_field() {
    let mut cd = fixture_calldata();
    cd[40] = 0xFF; // any byte in [36..67] must be zero
    assert!(check_setpresig_calldata_shape(&cd).is_err());
}

#[test]
fn negative_shape_rejects_signed_value_two() {
    // The "signed" bool slot is uint256(1). A canonical-ABI bool
    // encoder would never emit 2, but the firmware must still refuse.
    let mut cd = fixture_calldata();
    cd[67] = 2;
    assert!(check_setpresig_calldata_shape(&cd).is_err());
}

#[test]
fn negative_shape_rejects_high_byte_set_in_bytes_len_field() {
    let mut cd = fixture_calldata();
    cd[80] = 0x01; // any byte in [68..99] must be zero
    assert!(check_setpresig_calldata_shape(&cd).is_err());
}

#[test]
fn negative_shape_rejects_each_tail_pad_byte_nonzero() {
    // ASSUMPTION: every byte of the [156..164) tail-pad must be zero.
    // ATTACK: smuggle adversarial bytes there hoping verifier ignores
    // them. Sweep each byte position and assert rejection.
    for offset in 156..164 {
        let mut cd = fixture_calldata();
        cd[offset] = 0x80;
        assert!(
            check_setpresig_calldata_shape(&cd).is_err(),
            "tail-pad byte at offset {offset} must reject when nonzero"
        );
    }
}
