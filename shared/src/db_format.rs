//! On-disk binary format for the ERC20 metadata DB and ZK verification
//! key DB.
//!
//! Both DBs live in **non-secure rodata**, signed by the same hybrid
//! firmware-signing key as the rest of the firmware. The secure world
//! holds only the **Merkle root** of each DB (32 bytes each), embedded
//! into its own image. At lookup time, the non-secure world walks its
//! local index, builds a `(canonical_entry_bytes, merkle_proof)`
//! bundle, and sends it across the gateway. The secure world verifies
//! the bundle against its embedded root before trusting the metadata.
//!
//! These constants are shared between `dbgen` (the host-side writer)
//! and both the non-secure runtime lookup and the secure-world Merkle
//! verifier so any layout change is a single edit. Both DBs are
//! little-endian, 1-byte aligned, and parsed through `from_le_bytes`
//! — never transmuted to `&[Entry]` views, since the alignment
//! guarantee is 1 byte.
//!
//! ## ERC20 metadata DB layout (`b"ERC2"`)
//!
//! ```text
//! Header (32 B):
//!   magic        [u8; 4] = b"ERC2"
//!   version      u32 LE  = 1
//!   flags        u32 LE
//!   entry_cnt    u32 LE
//!   pool_off     u32 LE    // byte offset of string pool from blob start
//!   pool_size    u32 LE
//!   proof_depth  u32 LE    // sibling hashes per proof = log2(padded n)
//!   proofs_off   u32 LE    // byte offset of per-entry proofs array
//!
//! Entries (entry_cnt × 40 B, sorted by (chain_id, contract)):
//!   chain_id    u64 LE                (8)
//!   contract    [u8; 20]              (20)
//!   name_off    u32 LE                (4)   // offset into string pool
//!   symbol_off  u32 LE                (4)
//!   decimals    u8                    (1)
//!   flags       u8                    (1)
//!   _pad        [u8; 2]               (2)
//!                                     40
//!
//! String pool:
//!   Length-prefixed UTF-8 strings: [len: u8][bytes: len].
//!   Strings are interned at build time so identical name/symbol
//!   strings appear exactly once.
//!
//! Proofs:
//!   entry_cnt × (proof_depth × 32 B). Proof[i] is the list of
//!   sibling hashes from leaf `i` up to the root, ordered leaf-up.
//!   The direction at each level is implicit from the bits of `i`.
//! ```
//!
//! ## Canonical leaf encoding (ERC20)
//!
//! ```text
//!   chain_id  (8 LE) ‖
//!   contract  (20)   ‖
//!   decimals  (1)    ‖
//!   name_len  (1)    ‖ name_bytes ‖
//!   sym_len   (1)    ‖ symbol_bytes
//! ```
//!
//! Hashed as `sha256(0x00 || canonical_bytes)` to produce the leaf
//! hash. Internal nodes are `sha256(0x01 || left || right)`. The
//! `0x00`/`0x01` domain separation prefix prevents an attacker from
//! crafting an entry whose canonical bytes happen to look like an
//! internal-node concatenation.
//!
//! ## ZK clear-signing VK DB layout (`b"VKDB"`)
//!
//! ```text
//! Header (32 B):
//!   magic        [u8; 4] = b"VKDB"
//!   version      u32 LE  = 1
//!   flags        u32 LE
//!   entry_cnt    u32 LE     // (chain_id, contract) → vk_id rows
//!   vk_count     u32 LE     // unique VKs in pool
//!   vk_pool_off  u32 LE
//!   proof_depth  u32 LE
//!   proofs_off   u32 LE
//!
//! Entries (entry_cnt × 32 B, sorted by (chain_id, contract)):
//!   chain_id    u64 LE                (8)
//!   contract    [u8; 20]              (20)
//!   vk_id       u8                    (1)   // index into VK pool
//!   vk_sha_pfx  [u8; 3]               (3)   // first 3 bytes of SHA-256(VK)
//!                                     32
//!
//! VK pool (vk_count × 960 B):
//!   vk[vk_id] = [u8; 960] (uncompressed BLS12-381 G1/G2 points)
//!
//! Proofs:
//!   entry_cnt × (proof_depth × 32 B). Same structure as ERC20.
//! ```
//!
//! ## Canonical leaf encoding (VK)
//!
//! ```text
//!   chain_id  (8 LE) ‖
//!   contract  (20)   ‖
//!   vk_bytes  (960)
//! ```
//!
//! Hashed identically to the ERC20 leaves with the same `0x00` /
//! `0x01` domain separation.

// === ERC20 metadata DB =====================================================

pub const ERC20_DB_MAGIC: [u8; 4] = *b"ERC2";
pub const ERC20_DB_VERSION: u32 = 1;
pub const ERC20_DB_HEADER_LEN: usize = 32;
pub const ERC20_DB_ENTRY_LEN: usize = 40;

pub const ERC20_HDR_OFF_MAGIC: usize = 0;
pub const ERC20_HDR_OFF_VERSION: usize = 4;
pub const ERC20_HDR_OFF_FLAGS: usize = 8;
pub const ERC20_HDR_OFF_ENTRY_CNT: usize = 12;
pub const ERC20_HDR_OFF_POOL_OFF: usize = 16;
pub const ERC20_HDR_OFF_POOL_SIZE: usize = 20;
pub const ERC20_HDR_OFF_PROOF_DEPTH: usize = 24;
pub const ERC20_HDR_OFF_PROOFS_OFF: usize = 28;

pub const ERC20_ENTRY_OFF_CHAIN_ID: usize = 0;
pub const ERC20_ENTRY_OFF_CONTRACT: usize = 8;
pub const ERC20_ENTRY_OFF_NAME_OFF: usize = 28;
pub const ERC20_ENTRY_OFF_SYMBOL_OFF: usize = 32;
pub const ERC20_ENTRY_OFF_DECIMALS: usize = 36;
pub const ERC20_ENTRY_OFF_FLAGS: usize = 37;
// 38..40 padding

// === ZK VK DB ==============================================================

pub const VK_DB_MAGIC: [u8; 4] = *b"VKDB";
pub const VK_DB_VERSION: u32 = 1;
pub const VK_DB_HEADER_LEN: usize = 32;
pub const VK_DB_ENTRY_LEN: usize = 32;

/// Single VK size in bytes (BLS12-381 Groth16 verification key,
/// uncompressed). Matches `crate::ZK_VK_LEN`.
pub const VK_BLOB_LEN: usize = 960;

pub const VK_HDR_OFF_MAGIC: usize = 0;
pub const VK_HDR_OFF_VERSION: usize = 4;
pub const VK_HDR_OFF_FLAGS: usize = 8;
pub const VK_HDR_OFF_ENTRY_CNT: usize = 12;
pub const VK_HDR_OFF_VK_COUNT: usize = 16;
pub const VK_HDR_OFF_VK_POOL_OFF: usize = 20;
pub const VK_HDR_OFF_PROOF_DEPTH: usize = 24;
pub const VK_HDR_OFF_PROOFS_OFF: usize = 28;

pub const VK_ENTRY_OFF_CHAIN_ID: usize = 0;
pub const VK_ENTRY_OFF_CONTRACT: usize = 8;
pub const VK_ENTRY_OFF_VK_ID: usize = 28;
pub const VK_ENTRY_OFF_SHA_PFX: usize = 29;
// 32 done

// === Little-endian readers (shared by writer + reader) =====================

#[inline]
pub fn read_u32_le(slice: &[u8], offset: usize) -> u32 {
    let bytes: [u8; 4] = [
        slice[offset],
        slice[offset + 1],
        slice[offset + 2],
        slice[offset + 3],
    ];
    u32::from_le_bytes(bytes)
}

#[inline]
pub fn read_u64_le(slice: &[u8], offset: usize) -> u64 {
    let bytes: [u8; 8] = [
        slice[offset],
        slice[offset + 1],
        slice[offset + 2],
        slice[offset + 3],
        slice[offset + 4],
        slice[offset + 5],
        slice[offset + 6],
        slice[offset + 7],
    ];
    u64::from_le_bytes(bytes)
}
