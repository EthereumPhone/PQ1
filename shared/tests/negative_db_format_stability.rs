//! Negative: `db_format` byte-exact stability and adversarial readers.
//!
//! The on-disk DBs are firmware-signed: a single root hash binds the
//! entire layout into the secure-world image. **Any silent change to a
//! magic byte, header offset, or entry width corrupts every blob shipped
//! against the previous constant — instantly invalidating every Merkle
//! root the verifier already trusts.** These tests pin the layout down so
//! a refactor that "tidies up" the offsets must be a conscious breaking
//! change, not a slow drift.

use sphincs_tz_shared::db_format::*;

// ─── Magic-byte forgery resistance ────────────────────────────────────────

#[test]
fn negative_magic_bytes_are_distinct() {
    // Assumption attacked: if two DBs shared a magic, a tampered NS-side
    // blob could be presented to the wrong parser and the wrong Merkle
    // root used to "verify" it. Pin every magic to a distinct 4-byte
    // string.
    let magics = [
        ERC20_DB_MAGIC,
        VK_DB_MAGIC,
        NAMES_DB_MAGIC,
        SELECTOR_DB_MAGIC,
    ];
    for (i, a) in magics.iter().enumerate() {
        for (j, b) in magics.iter().enumerate() {
            if i != j {
                assert_ne!(
                    a, b,
                    "DB magics must be pairwise distinct — collision would let a tampered blob substitute one DB for another"
                );
            }
        }
    }
}

#[test]
fn negative_magic_byte_exact_values() {
    // Assumption: the deployed Solidity verifier and any pre-signed DB
    // blobs commit to these magic bytes verbatim. A "harmless" rename
    // (e.g. "ERC2" → "Erc2") would silently invalidate everything.
    assert_eq!(&ERC20_DB_MAGIC[..], b"ERC2");
    assert_eq!(&VK_DB_MAGIC[..], b"VKDB");
    assert_eq!(&NAMES_DB_MAGIC[..], b"NAMS");
    assert_eq!(&SELECTOR_DB_MAGIC[..], b"SEL4");
}

#[test]
fn negative_versions_all_one_currently() {
    // Frozen: incrementing to v2 must be a deliberate format break, not
    // a drift caused by some helper that "auto-bumps" on rebuild.
    assert_eq!(ERC20_DB_VERSION, 1);
    assert_eq!(VK_DB_VERSION, 1);
    assert_eq!(NAMES_DB_VERSION, 1);
    assert_eq!(SELECTOR_DB_VERSION, 1);
}

// ─── Header-layout stability ──────────────────────────────────────────────

#[test]
fn negative_all_headers_are_32_bytes() {
    // The four DBs share the same 32-byte header shape so the secure-side
    // verifier can dispatch by magic without learning each DB's header
    // length separately.
    assert_eq!(ERC20_DB_HEADER_LEN, 32);
    assert_eq!(VK_DB_HEADER_LEN, 32);
    assert_eq!(NAMES_DB_HEADER_LEN, 32);
    assert_eq!(SELECTOR_DB_HEADER_LEN, 32);
}

#[test]
fn negative_header_offsets_strictly_monotonic_erc20() {
    let offs = [
        ERC20_HDR_OFF_MAGIC,
        ERC20_HDR_OFF_VERSION,
        ERC20_HDR_OFF_FLAGS,
        ERC20_HDR_OFF_ENTRY_CNT,
        ERC20_HDR_OFF_POOL_OFF,
        ERC20_HDR_OFF_POOL_SIZE,
        ERC20_HDR_OFF_PROOF_DEPTH,
        ERC20_HDR_OFF_PROOFS_OFF,
    ];
    for w in offs.windows(2) {
        assert!(
            w[0] < w[1],
            "header offsets must be strictly increasing — reordering invalidates every signed blob"
        );
    }
    // u32 fields are tightly packed: each step is 4 bytes.
    for w in offs.windows(2) {
        assert_eq!(w[1] - w[0], 4);
    }
    // Last offset + 4 must fill exactly the 32-byte header.
    assert_eq!(ERC20_HDR_OFF_PROOFS_OFF + 4, ERC20_DB_HEADER_LEN);
}

#[test]
fn negative_header_offsets_strictly_monotonic_vk() {
    let offs = [
        VK_HDR_OFF_MAGIC,
        VK_HDR_OFF_VERSION,
        VK_HDR_OFF_FLAGS,
        VK_HDR_OFF_ENTRY_CNT,
        VK_HDR_OFF_VK_COUNT,
        VK_HDR_OFF_VK_POOL_OFF,
        VK_HDR_OFF_PROOF_DEPTH,
        VK_HDR_OFF_PROOFS_OFF,
    ];
    for w in offs.windows(2) {
        assert_eq!(w[1] - w[0], 4);
    }
    assert_eq!(VK_HDR_OFF_PROOFS_OFF + 4, VK_DB_HEADER_LEN);
}

#[test]
fn negative_header_offsets_strictly_monotonic_names() {
    let offs = [
        NAMES_HDR_OFF_MAGIC,
        NAMES_HDR_OFF_VERSION,
        NAMES_HDR_OFF_FLAGS,
        NAMES_HDR_OFF_ENTRY_CNT,
        NAMES_HDR_OFF_POOL_OFF,
        NAMES_HDR_OFF_POOL_SIZE,
        NAMES_HDR_OFF_PROOF_DEPTH,
        NAMES_HDR_OFF_PROOFS_OFF,
    ];
    for w in offs.windows(2) {
        assert_eq!(w[1] - w[0], 4);
    }
    assert_eq!(NAMES_HDR_OFF_PROOFS_OFF + 4, NAMES_DB_HEADER_LEN);
}

#[test]
fn negative_header_offsets_strictly_monotonic_selector() {
    let offs = [
        SELECTOR_HDR_OFF_MAGIC,
        SELECTOR_HDR_OFF_VERSION,
        SELECTOR_HDR_OFF_FLAGS,
        SELECTOR_HDR_OFF_ENTRY_CNT,
        SELECTOR_HDR_OFF_POOL_OFF,
        SELECTOR_HDR_OFF_POOL_SIZE,
        SELECTOR_HDR_OFF_PROOF_DEPTH,
        SELECTOR_HDR_OFF_PROOFS_OFF,
    ];
    for w in offs.windows(2) {
        assert_eq!(w[1] - w[0], 4);
    }
    assert_eq!(SELECTOR_HDR_OFF_PROOFS_OFF + 4, SELECTOR_DB_HEADER_LEN);
}

// ─── Entry-layout stability ───────────────────────────────────────────────

#[test]
fn negative_erc20_entry_fields_dont_overlap_and_fit_in_40b() {
    // Documented entry: chain_id(8) + contract(20) + name_off(4) +
    // symbol_off(4) + decimals(1) + flags(1) + pad(2) = 40.
    assert_eq!(ERC20_ENTRY_OFF_CHAIN_ID, 0);
    assert_eq!(ERC20_ENTRY_OFF_CONTRACT, ERC20_ENTRY_OFF_CHAIN_ID + 8);
    assert_eq!(ERC20_ENTRY_OFF_NAME_OFF, ERC20_ENTRY_OFF_CONTRACT + 20);
    assert_eq!(ERC20_ENTRY_OFF_SYMBOL_OFF, ERC20_ENTRY_OFF_NAME_OFF + 4);
    assert_eq!(ERC20_ENTRY_OFF_DECIMALS, ERC20_ENTRY_OFF_SYMBOL_OFF + 4);
    assert_eq!(ERC20_ENTRY_OFF_FLAGS, ERC20_ENTRY_OFF_DECIMALS + 1);
    // 2 bytes of trailing pad to reach the documented 40-byte stride.
    assert!(ERC20_ENTRY_OFF_FLAGS + 1 + 2 == ERC20_DB_ENTRY_LEN);
}

#[test]
fn negative_vk_entry_fields_dont_overlap_and_fit_in_32b() {
    // chain_id(8) + contract(20) + vk_id(1) + sha_pfx(3) = 32.
    assert_eq!(VK_ENTRY_OFF_CHAIN_ID, 0);
    assert_eq!(VK_ENTRY_OFF_CONTRACT, VK_ENTRY_OFF_CHAIN_ID + 8);
    assert_eq!(VK_ENTRY_OFF_VK_ID, VK_ENTRY_OFF_CONTRACT + 20);
    assert_eq!(VK_ENTRY_OFF_SHA_PFX, VK_ENTRY_OFF_VK_ID + 1);
    assert_eq!(VK_ENTRY_OFF_SHA_PFX + 3, VK_DB_ENTRY_LEN);
}

#[test]
fn negative_names_entry_fields_dont_overlap_and_fit_in_20b() {
    // short_key(16) + name_off(4) = 20.
    assert_eq!(NAMES_ENTRY_OFF_SHORT_KEY, 0);
    assert_eq!(NAMES_ENTRY_OFF_NAME_OFF, NAMES_ENTRY_OFF_SHORT_KEY + 16);
    assert_eq!(NAMES_ENTRY_OFF_NAME_OFF + 4, NAMES_DB_ENTRY_LEN);
}

#[test]
fn negative_selector_entry_fields_dont_overlap_and_fit_in_8b() {
    // selector(4) + text_off(4) = 8.
    assert_eq!(SELECTOR_ENTRY_OFF_SELECTOR, 0);
    assert_eq!(
        SELECTOR_ENTRY_OFF_TEXT_OFF,
        SELECTOR_ENTRY_OFF_SELECTOR + 4
    );
    assert_eq!(SELECTOR_ENTRY_OFF_TEXT_OFF + 4, SELECTOR_DB_ENTRY_LEN);
}

// ─── Domain-tag stability ─────────────────────────────────────────────────

#[test]
fn negative_names_short_key_tag_byte_exact() {
    // Assumption: this 20-byte ASCII tag is the input to a SHA-256 short
    // key. Every consumer (host writer, NS index, secure verifier)
    // recomputes the hash locally — drift across consumers would silently
    // mis-resolve names. Pin every byte.
    let want: &[u8; 20] = b"pqsigner-name-key-v1";
    assert_eq!(NAMES_SHORT_KEY_TAG, want);
    assert_eq!(NAMES_SHORT_KEY_TAG.len(), 20);
    assert_eq!(NAMES_SHORT_KEY_TAG[0], b'p');
    assert_eq!(NAMES_SHORT_KEY_TAG[19], b'1');
}

#[test]
fn negative_names_wildcard_is_eip155_reserved_value() {
    // CLAUDE.md & the doc comment: EIP-155 reserves chain_id=0; the
    // wildcard sentinel MUST stay at 0 so it can never collide with a
    // real EVM chain id.
    assert_eq!(NAMES_WILDCARD_CHAIN_ID, 0);
}

// ─── Cosmetic upper bounds (UI sizing) ────────────────────────────────────

#[test]
fn negative_text_sig_max_len_fits_in_u8() {
    // The text-sig length prefix in the pool is a single byte. If the
    // max were >= 256, the layout would silently lose information.
    assert!(SELECTOR_TEXT_SIG_MAX_LEN <= u8::MAX as usize);
    assert!(SELECTOR_TEXT_SIG_MAX_LEN >= 1);
}

#[test]
fn negative_names_max_len_fits_in_u8() {
    // Same reasoning — the pool encodes `[len: u8][bytes: len]`.
    assert!(NAMES_MAX_LEN <= u8::MAX as usize);
    assert!(NAMES_MAX_LEN >= 1);
}

// ─── Reader behaviour on hostile input ────────────────────────────────────

#[test]
#[should_panic]
fn negative_read_u32_le_panics_on_oob() {
    // The doc says "every call site reads from a firmware-signed DB blob
    // whose layout is fixed at build time, so an out-of-range read is
    // structurally impossible". Pin the failure mode: a runtime panic
    // (loud, audited) — *not* a silent zero or wrap. Anyone who changes
    // this to `Option<u32>` or `unwrap_or(0)` must update the contract
    // here.
    let buf = [1u8, 2, 3];
    let _ = read_u32_le(&buf, 0);
}

#[test]
#[should_panic]
fn negative_read_u32_le_panics_at_offset_overflow() {
    // Offset within length but offset+3 past end.
    let buf = [1u8, 2, 3, 4];
    let _ = read_u32_le(&buf, 2);
}

#[test]
#[should_panic]
fn negative_read_u64_le_panics_on_oob() {
    let buf = [1u8; 7];
    let _ = read_u64_le(&buf, 0);
}

#[test]
#[should_panic]
fn negative_read_u64_le_panics_at_offset_overflow() {
    let buf = [1u8; 10];
    let _ = read_u64_le(&buf, 4); // 4..12 exceeds buffer of 10
}

#[test]
fn negative_read_u32_le_is_little_endian_not_big_endian() {
    // Assumption attacked: a future "harmless" refactor swaps to BE
    // (matching network order, but wrong for our on-disk format).
    let buf = [0x12, 0x34, 0x56, 0x78];
    let got = read_u32_le(&buf, 0);
    let be = u32::from_be_bytes(buf);
    assert_ne!(
        got, be,
        "read_u32_le must NOT be big-endian — every shipped DB is LE-encoded"
    );
    assert_eq!(got, 0x7856_3412);
}

#[test]
fn negative_read_u64_le_is_little_endian_not_big_endian() {
    let buf = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
    let got = read_u64_le(&buf, 0);
    let be = u64::from_be_bytes(buf);
    assert_ne!(got, be);
    assert_eq!(got, 0xF0DE_BC9A_7856_3412);
}
