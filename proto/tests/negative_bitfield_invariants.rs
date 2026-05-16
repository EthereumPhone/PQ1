//! Negative tests for bit-field non-overlap and reserved-bit hygiene
//! across the flag words this crate defines.
//!
//! **What's being attacked.** A future contributor sneaks in a new flag
//! by overlapping its bit with an existing region, or expands
//! `ACCOUNT_INDEX_MASK` and forgets to shrink `SLOT_INDEX_MASK`. Either
//! mistake corrupts a live UserOp's `(account_index, slot_index)`
//! decoding silently — the signature still verifies, but it signs for
//! the wrong key.

use pqsigner_proto::*;
use proptest::prelude::*;

// ───────────────────────────────────────────────────────────────────────
// CMD_SIGN_USEROP flags field — bits MUST partition u32 into exactly
// four non-overlapping regions.
// ───────────────────────────────────────────────────────────────────────

#[test]
fn negative_flag_regions_are_pairwise_disjoint() {
    let pairs: &[(&str, u32, &str, u32)] = &[
        ("FLAG_INCLUDE_INIT_CODE", FLAG_INCLUDE_INIT_CODE,
         "FLAG_REGISTER_SLOT", FLAG_REGISTER_SLOT),
        ("FLAG_INCLUDE_INIT_CODE", FLAG_INCLUDE_INIT_CODE,
         "ACCOUNT_INDEX_MASK", ACCOUNT_INDEX_MASK),
        ("FLAG_INCLUDE_INIT_CODE", FLAG_INCLUDE_INIT_CODE,
         "SLOT_INDEX_MASK", SLOT_INDEX_MASK),
        ("FLAG_REGISTER_SLOT", FLAG_REGISTER_SLOT,
         "ACCOUNT_INDEX_MASK", ACCOUNT_INDEX_MASK),
        ("FLAG_REGISTER_SLOT", FLAG_REGISTER_SLOT,
         "SLOT_INDEX_MASK", SLOT_INDEX_MASK),
        ("ACCOUNT_INDEX_MASK", ACCOUNT_INDEX_MASK,
         "SLOT_INDEX_MASK", SLOT_INDEX_MASK),
    ];
    for &(la, a, lb, b) in pairs {
        assert_eq!(
            a & b, 0,
            "{la} ({a:#010x}) and {lb} ({b:#010x}) share bits — a sign with both flag forms would silently mis-route a UserOp"
        );
    }
}

#[test]
fn negative_flag_regions_cover_every_bit() {
    // Union must be exactly u32::MAX. If a bit is unaccounted for, the
    // payload byte that decoded it doesn't survive a round-trip through
    // any (flag, account_index, slot_index) packing.
    let union =
        FLAG_INCLUDE_INIT_CODE | FLAG_REGISTER_SLOT | ACCOUNT_INDEX_MASK | SLOT_INDEX_MASK;
    assert_eq!(
        union,
        u32::MAX,
        "flag regions don't cover the full u32 — bits {:#010x} are unallocated and would be silently dropped by any decoder",
        u32::MAX ^ union
    );
}

#[test]
fn negative_account_index_mask_matches_documented_shift_and_width() {
    // ACCOUNT_INDEX_MASK is documented as 8 bits at ACCOUNT_INDEX_SHIFT (22).
    // MAX_ACCOUNT_INDEX is the value, not a mask.
    assert_eq!(ACCOUNT_INDEX_SHIFT, 22);
    assert_eq!(MAX_ACCOUNT_INDEX, 0xFF);
    assert_eq!(
        ACCOUNT_INDEX_MASK,
        (MAX_ACCOUNT_INDEX) << ACCOUNT_INDEX_SHIFT,
        "ACCOUNT_INDEX_MASK no longer equals MAX_ACCOUNT_INDEX << ACCOUNT_INDEX_SHIFT — encoding/decoding round-trips would silently corrupt the account_index"
    );
    assert_eq!(ACCOUNT_INDEX_MASK.count_ones(), 8);
}

#[test]
fn negative_slot_index_mask_is_lower_22_bits() {
    assert_eq!(
        SLOT_INDEX_MASK,
        (1u32 << 22) - 1,
        "SLOT_INDEX_MASK no longer occupies bits 21..0 — slot decoding would shift into the account_index region"
    );
    assert_eq!(SLOT_INDEX_MASK.count_ones(), 22);
    // Max slot ~4M; document explicitly so any future narrowing trips this.
    assert_eq!(SLOT_INDEX_MASK, 0x003F_FFFF);
}

#[test]
fn negative_flag_bits_are_top_two_bits() {
    // Documented as bits 31 and 30. Anything else means flag tests in
    // the rest of the codebase (e.g. `flags & FLAG_INCLUDE_INIT_CODE`)
    // would silently never fire if the constant moved.
    assert_eq!(FLAG_INCLUDE_INIT_CODE, 1u32 << 31);
    assert_eq!(FLAG_REGISTER_SLOT, 1u32 << 30);
}

// ───────────────────────────────────────────────────────────────────────
// Flag bit-pack round-trip (proptest)
//
// Construct a flags word from (include_init, register, account, slot)
// using the documented masks/shifts and assert decoding recovers each
// input. If a region were redefined incorrectly this property fails
// for random inputs.
// ───────────────────────────────────────────────────────────────────────

proptest! {
    #[test]
    fn negative_flags_pack_round_trip(
        include_init in any::<bool>(),
        register in any::<bool>(),
        account in 0u32..=MAX_ACCOUNT_INDEX,
        slot in 0u32..=SLOT_INDEX_MASK,
    ) {
        let mut f = 0u32;
        if include_init { f |= FLAG_INCLUDE_INIT_CODE; }
        if register     { f |= FLAG_REGISTER_SLOT; }
        f |= (account << ACCOUNT_INDEX_SHIFT) & ACCOUNT_INDEX_MASK;
        f |= slot & SLOT_INDEX_MASK;

        // Decode
        prop_assert_eq!(f & FLAG_INCLUDE_INIT_CODE != 0, include_init);
        prop_assert_eq!(f & FLAG_REGISTER_SLOT != 0, register);
        prop_assert_eq!((f & ACCOUNT_INDEX_MASK) >> ACCOUNT_INDEX_SHIFT, account);
        prop_assert_eq!(f & SLOT_INDEX_MASK, slot);
    }
}

// ───────────────────────────────────────────────────────────────────────
// OFFCHAIN_FLAGS_MASK — reserved bits MUST be zero
// ───────────────────────────────────────────────────────────────────────

#[test]
fn negative_offchain_flags_mask_covers_only_defined_bits() {
    // Today exactly one bit is defined. Reserved bits 1..=7 must be
    // outside the mask so the firmware can reject any payload that sets
    // them.
    assert_eq!(
        OFFCHAIN_FLAGS_MASK, OFFCHAIN_FLAG_ACCOUNT_DEPLOYED,
        "OFFCHAIN_FLAGS_MASK should equal the OR of all defined flag bits — adding a new bit without updating the mask means firmware silently accepts undefined flag values"
    );
    assert_eq!(OFFCHAIN_FLAG_ACCOUNT_DEPLOYED, 1);
    // Reserved bits 1..=7 must not be inside the mask.
    for bit in 1..=7 {
        let mask_bit = 1u8 << bit;
        assert_eq!(
            OFFCHAIN_FLAGS_MASK & mask_bit, 0,
            "bit {bit} is reserved but is set in OFFCHAIN_FLAGS_MASK"
        );
    }
}

// ───────────────────────────────────────────────────────────────────────
// CMD_SIGN_OFFCHAIN field offsets — strictly monotonic and the field
// widths must cover the header without gap or overlap.
// ───────────────────────────────────────────────────────────────────────

#[test]
fn negative_sign_offchain_header_field_widths_pack_without_gap() {
    // (offset, width, name) — sum of widths must equal SIGN_OFFCHAIN_HEADER_LEN,
    // and each offset must equal the previous offset + previous width.
    let fields: &[(usize, usize, &str)] = &[
        (SIGN_OFFCHAIN_INPUT_ACCOUNT_OFF, 1, "account_index"),
        (SIGN_OFFCHAIN_INPUT_CHAIN_OFF, 8, "chain_id"),
        (SIGN_OFFCHAIN_INPUT_SLOT_OFF, 4, "slot_index"),
        (SIGN_OFFCHAIN_INPUT_KIND_OFF, 1, "kind"),
        (SIGN_OFFCHAIN_INPUT_PAYLOAD_LEN_OFF, 2, "payload_len"),
        (SIGN_OFFCHAIN_INPUT_FLAGS_OFF, 1, "flags"),
    ];
    let mut cursor = 0_usize;
    for &(off, width, name) in fields {
        assert_eq!(
            off, cursor,
            "field {name} starts at offset {off} but previous field ended at {cursor} — gap or overlap"
        );
        cursor = off + width;
    }
    assert_eq!(
        cursor, SIGN_OFFCHAIN_HEADER_LEN,
        "sum of field widths ({cursor}) doesn't match SIGN_OFFCHAIN_HEADER_LEN ({})",
        SIGN_OFFCHAIN_HEADER_LEN
    );
    assert_eq!(
        cursor, SIGN_OFFCHAIN_INPUT_PAYLOAD_OFF,
        "payload offset must be exactly past the header"
    );
}
