//! ABI value leaf type + frozen container-field indices for ERC-7730.
//!
//! `AbiValue` is the leaf the display layer picks a formatter from; the
//! visibility evaluator (`render/visibility.rs`) takes it as its
//! (optional) already-walked value. The live path-resolution walker is
//! `display/render::resolve` — the Phase-3 `AbiView`/`AbiNode` interpreter
//! that used to live here was removed from the live path 2026-07 (review
//! 5.4) and the dead types were pruned 2026-08; nothing outside this file
//! referenced them.
//!
//! ## Field indexing convention
//!
//! `PathOp::FieldIdx` carries a `u16` field index. The host compiler
//! (`dbgen::erc7730::compile_path` → `resolve_field_index`) populates
//! this index in two distinct ways:
//!
//! * **Format-key positional names** (parameters of the function
//!   signature for contract context, or the typed-data top-level
//!   message fields for EIP-712): the index is the field's positional
//!   slot inside `parsed.top_names` / `parsed.inner_names`.
//! * **Container / fallback names** (`@.value`, `@.to`, EIP-712 message
//!   fields that aren't in the format key's `top_names`): the index is
//!   the first two bytes (big-endian) of `keccak256(name)`.
//!
//! Both cases collapse to the same wire shape: a `u16` lookup key. The
//! [`container_field`] constants below are the frozen keccak-prefix
//! indices for the well-known envelope fields.

/// Where a path resolves to once the walker has chased every opcode.
/// The display layer uses this enum to pick the formatter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbiValue<'a> {
    Uint { bits: u16, be32: &'a [u8; 32] },
    Int { bits: u16, be32: &'a [u8; 32] },
    Address(&'a [u8; 20]),
    Bool(bool),
    BytesN { width: u8, bytes: &'a [u8] },
    Bytes(&'a [u8]),
    String(&'a [u8]),
}

/// Pre-computed `keccak256(name)[..2]` field indices for the
/// well-known transaction-envelope (`@`) fields. The values are
/// frozen wire constants — host emitter (`dbgen::erc7730`) and
/// on-device walker MUST agree.
///
/// Verified by `dbgen/tests/erc7730_roundtrip.rs::container_indices`
/// against the live keccak256 implementation.
pub mod container_field {
    /// `@.value` — native-token amount being transferred (32 B uint).
    pub const VALUE: u16 = 0x81AF;
    /// `@.to` — destination contract address (20 B).
    pub const TO: u16 = 0x1B56;
    /// `@.from` — sender address; the AA wallet itself (20 B).
    pub const FROM: u16 = 0x45A9;
    /// `@.chainId` — EIP-155 chain id (u64).
    pub const CHAIN_ID: u16 = 0x8ED9;
    /// `@.nonce` — EIP-1559 / AA nonce (32 B uint).
    pub const NONCE: u16 = 0x7AB1;
}

#[cfg(test)]
mod tests {
    //! These tests pin only the LIVE surface of this module: the frozen
    //! `container_field` wire constants (consumed by `ir.rs`,
    //! `display/render/*`, and re-exported to the secure world) and the
    //! `AbiValue` discrimination the display layer's formatter choice
    //! relies on. The retired Phase-3 interpreter tests were removed with
    //! the code 2026-08; the live rendering path is covered by the
    //! display/render suites and the Miri leg.
    use super::*;

    static WORD_A: [u8; 32] = [0xAA; 32];
    static ADDR_A: [u8; 20] = [0x42; 20];
    static ADDR_B: [u8; 20] = [0x24; 20];

    #[test]
    fn container_field_constants_are_frozen_wire_values() {
        // Host emitter (`dbgen::erc7730`) and this walker MUST agree on these
        // — they are `keccak256(name)[..2]` and drift silently mis-resolves
        // envelope fields. Pin the exact values; dbgen's roundtrip test
        // re-derives them from live keccak256.
        assert_eq!(container_field::VALUE, 0x81AF);
        assert_eq!(container_field::TO, 0x1B56);
        assert_eq!(container_field::FROM, 0x45A9);
        assert_eq!(container_field::CHAIN_ID, 0x8ED9);
        assert_eq!(container_field::NONCE, 0x7AB1);
        let all = [
            container_field::VALUE,
            container_field::TO,
            container_field::FROM,
            container_field::CHAIN_ID,
            container_field::NONCE,
        ];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a, b, "envelope field indices must be collision-free");
            }
        }
    }

    // -----------------------------------------------------------------
    // AbiValue discrimination — the display layer picks the formatter from
    // the variant, so mis-tagged values must never compare equal.
    // -----------------------------------------------------------------

    #[test]
    fn abi_value_variants_are_not_interchangeable() {
        assert_ne!(
            AbiValue::Uint { bits: 256, be32: &WORD_A },
            AbiValue::Int { bits: 256, be32: &WORD_A },
            "same bits + word but different signedness must differ",
        );
        assert_ne!(
            AbiValue::Bytes(b"x"),
            AbiValue::String(b"x"),
            "same bytes but different type must differ",
        );
        assert_ne!(AbiValue::Bool(true), AbiValue::Bool(false));
        assert_ne!(
            AbiValue::BytesN { width: 1, bytes: b"\xaa" },
            AbiValue::BytesN { width: 2, bytes: b"\xaa" },
            "width is part of the value identity",
        );
        assert_ne!(AbiValue::Address(&ADDR_A), AbiValue::Address(&ADDR_B));
        assert_ne!(
            AbiValue::Uint { bits: 8, be32: &WORD_A },
            AbiValue::Uint { bits: 16, be32: &WORD_A },
        );
    }

    #[test]
    fn debug_impls_render_all_public_types() {
        // The error paths in consumers format these with {n:?}; keep a
        // direct smoke test so the derives stay honest.
        let _ = std::format!("{:?}", AbiValue::Uint { bits: 8, be32: &WORD_A });
        let _ = std::format!("{:?}", AbiValue::Bool(false));
    }
}
