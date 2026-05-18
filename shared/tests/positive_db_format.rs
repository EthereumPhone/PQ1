//! Positive: `db_format` constants and little-endian readers.
//!
//! `db_format.rs` defines the on-disk layout of the four firmware-signed
//! lookup DBs (ERC20, VK, Names, Selectors). The constants are consumed
//! by both `dbgen` (host writer) and the secure-world Merkle verifier
//! — drift between writer and reader is an attack vector, so the
//! constants must match the doc comment exactly.

use sphincs_tz_shared::db_format::*;

// ─── ERC20 ────────────────────────────────────────────────────────────────

#[test]
fn positive_erc20_magic_and_version() {
    assert_eq!(ERC20_DB_MAGIC, *b"ERC2");
    assert_eq!(ERC20_DB_VERSION, 1);
}

#[test]
fn positive_erc20_header_offsets_in_order() {
    assert_eq!(ERC20_HDR_OFF_MAGIC, 0);
    assert_eq!(ERC20_HDR_OFF_VERSION, 4);
    assert_eq!(ERC20_HDR_OFF_FLAGS, 8);
    assert_eq!(ERC20_HDR_OFF_ENTRY_CNT, 12);
    assert_eq!(ERC20_HDR_OFF_POOL_OFF, 16);
    assert_eq!(ERC20_HDR_OFF_POOL_SIZE, 20);
    assert_eq!(ERC20_HDR_OFF_PROOF_DEPTH, 24);
    assert_eq!(ERC20_HDR_OFF_PROOFS_OFF, 28);
    assert_eq!(ERC20_DB_HEADER_LEN, 32);
}

#[test]
fn positive_erc20_entry_offsets_and_size() {
    assert_eq!(ERC20_ENTRY_OFF_CHAIN_ID, 0);
    assert_eq!(ERC20_ENTRY_OFF_CONTRACT, 8);
    assert_eq!(ERC20_ENTRY_OFF_NAME_OFF, 28);
    assert_eq!(ERC20_ENTRY_OFF_SYMBOL_OFF, 32);
    assert_eq!(ERC20_ENTRY_OFF_DECIMALS, 36);
    assert_eq!(ERC20_ENTRY_OFF_FLAGS, 37);
    // 38..40 padding
    assert_eq!(ERC20_DB_ENTRY_LEN, 40);
}

// ─── VK ───────────────────────────────────────────────────────────────────

#[test]
fn positive_vk_magic_and_version() {
    assert_eq!(VK_DB_MAGIC, *b"VKDB");
    assert_eq!(VK_DB_VERSION, 1);
}

#[test]
fn positive_vk_header_offsets() {
    assert_eq!(VK_HDR_OFF_MAGIC, 0);
    assert_eq!(VK_HDR_OFF_VERSION, 4);
    assert_eq!(VK_HDR_OFF_FLAGS, 8);
    assert_eq!(VK_HDR_OFF_ENTRY_CNT, 12);
    assert_eq!(VK_HDR_OFF_VK_COUNT, 16);
    assert_eq!(VK_HDR_OFF_VK_POOL_OFF, 20);
    assert_eq!(VK_HDR_OFF_PROOF_DEPTH, 24);
    assert_eq!(VK_HDR_OFF_PROOFS_OFF, 28);
    assert_eq!(VK_DB_HEADER_LEN, 32);
}

#[test]
fn positive_vk_entry_offsets_and_size() {
    assert_eq!(VK_ENTRY_OFF_CHAIN_ID, 0);
    assert_eq!(VK_ENTRY_OFF_CONTRACT, 8);
    assert_eq!(VK_ENTRY_OFF_VK_ID, 28);
    assert_eq!(VK_ENTRY_OFF_SHA_PFX, 29);
    assert_eq!(VK_DB_ENTRY_LEN, 32);
}

#[test]
fn positive_vk_blob_len_ordering() {
    // Documented in the module comment: 2-pub VK fits inside a 3-pub slot
    // and the fixed-stride slot is the 3-pub size.
    assert_eq!(VK_BLOB_LEN_2PUB, 960);
    assert_eq!(VK_BLOB_LEN_3PUB, 1056);
    assert_eq!(VK_BLOB_LEN, VK_BLOB_LEN_3PUB);
    assert!(VK_BLOB_LEN_2PUB < VK_BLOB_LEN_3PUB);
}

// ─── Names ────────────────────────────────────────────────────────────────

#[test]
fn positive_names_magic_and_version() {
    assert_eq!(NAMES_DB_MAGIC, *b"NAMS");
    assert_eq!(NAMES_DB_VERSION, 1);
}

#[test]
fn positive_names_header_offsets() {
    assert_eq!(NAMES_HDR_OFF_MAGIC, 0);
    assert_eq!(NAMES_HDR_OFF_VERSION, 4);
    assert_eq!(NAMES_HDR_OFF_FLAGS, 8);
    assert_eq!(NAMES_HDR_OFF_ENTRY_CNT, 12);
    assert_eq!(NAMES_HDR_OFF_POOL_OFF, 16);
    assert_eq!(NAMES_HDR_OFF_POOL_SIZE, 20);
    assert_eq!(NAMES_HDR_OFF_PROOF_DEPTH, 24);
    assert_eq!(NAMES_HDR_OFF_PROOFS_OFF, 28);
    assert_eq!(NAMES_DB_HEADER_LEN, 32);
}

#[test]
fn positive_names_entry_offsets_and_size() {
    assert_eq!(NAMES_ENTRY_OFF_SHORT_KEY, 0);
    assert_eq!(NAMES_ENTRY_OFF_NAME_OFF, 16);
    assert_eq!(NAMES_DB_ENTRY_LEN, 20);
}

#[test]
fn positive_names_misc_constants() {
    assert_eq!(NAMES_SHORT_KEY_TAG.len(), 20);
    assert_eq!(NAMES_SHORT_KEY_TAG, b"pqsigner-name-key-v1");
    assert_eq!(NAMES_MAX_LEN, 32);
    assert_eq!(NAMES_WILDCARD_CHAIN_ID, 0);
}

// ─── Selectors ────────────────────────────────────────────────────────────

#[test]
fn positive_selector_magic_and_version() {
    assert_eq!(SELECTOR_DB_MAGIC, *b"SEL4");
    assert_eq!(SELECTOR_DB_VERSION, 1);
}

#[test]
fn positive_selector_header_offsets() {
    assert_eq!(SELECTOR_HDR_OFF_MAGIC, 0);
    assert_eq!(SELECTOR_HDR_OFF_VERSION, 4);
    assert_eq!(SELECTOR_HDR_OFF_FLAGS, 8);
    assert_eq!(SELECTOR_HDR_OFF_ENTRY_CNT, 12);
    assert_eq!(SELECTOR_HDR_OFF_POOL_OFF, 16);
    assert_eq!(SELECTOR_HDR_OFF_POOL_SIZE, 20);
    assert_eq!(SELECTOR_HDR_OFF_PROOF_DEPTH, 24);
    assert_eq!(SELECTOR_HDR_OFF_PROOFS_OFF, 28);
    assert_eq!(SELECTOR_DB_HEADER_LEN, 32);
}

#[test]
fn positive_selector_entry_offsets_and_size() {
    assert_eq!(SELECTOR_ENTRY_OFF_SELECTOR, 0);
    assert_eq!(SELECTOR_ENTRY_OFF_TEXT_OFF, 4);
    assert_eq!(SELECTOR_DB_ENTRY_LEN, 8);
    assert_eq!(SELECTOR_TEXT_SIG_MAX_LEN, 63);
}

// ─── Readers ──────────────────────────────────────────────────────────────

#[test]
fn positive_read_u32_le_canonical() {
    // Little-endian: lowest byte first.
    let buf = [0x01, 0x02, 0x03, 0x04];
    assert_eq!(read_u32_le(&buf, 0), 0x0403_0201);
}

#[test]
fn positive_read_u32_le_with_offset() {
    let buf = [0xAA, 0xBB, 0x01, 0x02, 0x03, 0x04, 0xCC];
    assert_eq!(read_u32_le(&buf, 2), 0x0403_0201);
}

#[test]
fn positive_read_u32_le_zero() {
    let buf = [0, 0, 0, 0];
    assert_eq!(read_u32_le(&buf, 0), 0);
}

#[test]
fn positive_read_u32_le_max() {
    let buf = [0xFF, 0xFF, 0xFF, 0xFF];
    assert_eq!(read_u32_le(&buf, 0), u32::MAX);
}

#[test]
fn positive_read_u64_le_canonical() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    assert_eq!(read_u64_le(&buf, 0), 0x0807_0605_0403_0201);
}

#[test]
fn positive_read_u64_le_with_offset() {
    let mut buf = [0u8; 16];
    buf[4..12].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    assert_eq!(read_u64_le(&buf, 4), 0x0807_0605_0403_0201);
}

#[test]
fn positive_read_u64_le_zero_and_max() {
    let zero = [0u8; 8];
    assert_eq!(read_u64_le(&zero, 0), 0);
    let max = [0xFFu8; 8];
    assert_eq!(read_u64_le(&max, 0), u64::MAX);
}
