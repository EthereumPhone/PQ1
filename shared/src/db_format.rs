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

/// Single VK pool slot size in bytes. Every pool entry is padded to
/// this width so the on-disk layout stays fixed-stride regardless of
/// which Groth16 protocol owns the slot:
///
///   960 bytes = legacy 2-public-signal VK (alpha + 3 G2 + 3 IC).
///               Used by Aave v3 and CowSwap setPreSignature.
///   1056 bytes = 3-public-signal VK (alpha + 3 G2 + 4 IC).
///               Used by CowSwap EIP-712 v3 (H_tx, H_str, H_root).
///
/// Pool slots larger than the real VK are zero-padded by `dbgen`; the
/// Merkle leaf hashes the full padded slot, so the trailing zeros are
/// bound into the firmware trust anchor just like the meaningful
/// bytes. The secure-side parser then dispatches by sentinel and
/// deserializes either the first 960 or all 1056 bytes.
pub const VK_BLOB_LEN: usize = 1056;

/// Size of a 2-public-signal VK (Aave v3, CowSwap setPreSignature).
/// First `VK_BLOB_LEN_2PUB` bytes of a pool slot for those protocols.
pub const VK_BLOB_LEN_2PUB: usize = 960;

/// Size of a 3-public-signal VK (CowSwap EIP-712 v3).
pub const VK_BLOB_LEN_3PUB: usize = 1056;

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

// === Address-name DB =======================================================
//
// Third DB, parallel to the ERC20 + VK DBs. Maps (chain_id, address) to a
// short display name like "Uniswap V3 Router" or "Lido stETH" so the
// trusted UI can render a friendly label in place of the raw 40-hex
// address. Same Merkle trust model as the others: NS holds the full
// blob, secure holds only the root, lookups cross as (canonical,
// proof) bundles.
//
// Storage optimisation: the in-blob sorted index uses a 16-byte
// `short_key = sha256("pqsigner-name-key-v1" || chain_id_be || addr)[..16]`
// instead of the 28 raw bytes of (chain_id, contract). That shaves
// 12 B per entry and lets the NS binary-search directly on the
// companion-supplied (chain_id, addr) hash. The Merkle leaf, by
// contrast, still binds to the full (chain_id, address, name) triple
// so short-key collisions cannot substitute names.
//
// ## Names DB layout (`b"NAMS"`)
//
// ```text
// Header (32 B):
//   magic        [u8; 4] = b"NAMS"
//   version      u32 LE  = 1
//   flags        u32 LE
//   entry_cnt    u32 LE
//   pool_off     u32 LE
//   pool_size    u32 LE
//   proof_depth  u32 LE
//   proofs_off   u32 LE
//
// Entries (entry_cnt × 20 B, sorted by short_key):
//   short_key  [u8; 16]   // sha256("pqsigner-name-key-v1"||chain_id_be||addr)[..16]
//   name_off   u32 LE     // offset into string pool
//                  = 20
//
// String pool:
//   [len: u8][bytes: len], interned.
//
// Proofs:
//   entry_cnt × (proof_depth × 32 B).
// ```
//
// ## Canonical leaf encoding (Names)
//
// ```text
//   chain_id  (8 LE) ‖
//   address   (20)   ‖
//   name_len  (1)    ‖ name_bytes
// ```
//
// Hashed as `sha256(0x00 || canonical_bytes)`; internal nodes
// `sha256(0x01 || left || right)` — identical scheme to ERC20 + VK.

pub const NAMES_DB_MAGIC: [u8; 4] = *b"NAMS";
pub const NAMES_DB_VERSION: u32 = 1;
pub const NAMES_DB_HEADER_LEN: usize = 32;
pub const NAMES_DB_ENTRY_LEN: usize = 20;

pub const NAMES_HDR_OFF_MAGIC: usize = 0;
pub const NAMES_HDR_OFF_VERSION: usize = 4;
pub const NAMES_HDR_OFF_FLAGS: usize = 8;
pub const NAMES_HDR_OFF_ENTRY_CNT: usize = 12;
pub const NAMES_HDR_OFF_POOL_OFF: usize = 16;
pub const NAMES_HDR_OFF_POOL_SIZE: usize = 20;
pub const NAMES_HDR_OFF_PROOF_DEPTH: usize = 24;
pub const NAMES_HDR_OFF_PROOFS_OFF: usize = 28;

pub const NAMES_ENTRY_OFF_SHORT_KEY: usize = 0;
pub const NAMES_ENTRY_OFF_NAME_OFF: usize = 16;
// 20 done

/// Domain tag used in the short-key hash. 20 bytes.
pub const NAMES_SHORT_KEY_TAG: &[u8; 20] = b"pqsigner-name-key-v1";

/// Cosmetic upper bound on the name string. Must fit across two
/// 16-column display rows.
pub const NAMES_MAX_LEN: usize = 32;

// The 16-byte short key is computed as:
//   short_key = sha256(NAMES_SHORT_KEY_TAG || chain_id_u64_be || addr_20)[..16]
// Each consumer computes it locally using its own sha2 impl — the
// `shared` crate has zero dependencies so we don't pull sha2 in just
// for this helper.
//
// ## Chain-agnostic entries (`chain_id == 0` sentinel)
//
// EIP-155 reserves chain_id=0 ("legacy / none"), so no real EVM chain
// uses it. The names DB uses `chain_id = 0` as a wildcard meaning
// "this address resolves to this name on every chain". At lookup time
// each layer performs a two-phase match:
//
//   1. exact `(chain_id, address)`
//   2. on miss, `(0, address)` — chain-agnostic fallback
//
// This keeps the on-disk format byte-identical to the keyed form;
// wildcard rows are stored just like any other, they simply happen
// to have `chain_id = 0` in their canonical leaf encoding.
pub const NAMES_WILDCARD_CHAIN_ID: u64 = 0;

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
