//! Wire format and verifier for the address-name bundle that the
//! non-secure world attaches to a `CMD_SIGN_USEROP` request when its
//! local names DB has hits on any address the trusted UI is about to
//! render.
//!
//! The trust model is identical to [`crate::erc20::bundle`]: NS reads
//! from a large embedded blob, the secure world holds only a 32-byte
//! Merkle root, and the bundle crosses the gateway carrying canonical
//! metadata + proof. The secure world re-derives the leaf hash and
//! walks the proof before letting any `name` byte near the OLED.
//!
//! ## Wire layout
//!
//! ```text
//!   chain_id    u64 LE                  ( 8 B)
//!   address     [u8; 20]                (20 B)
//!   name_len    u8                      ( 1 B)
//!   name        [u8; name_len]
//!   leaf_index  u32 LE                  ( 4 B)
//!   proof_depth u32 LE                  ( 4 B)
//!   proof       [u8; proof_depth * 32]
//! ```
//!
//! `name_len` is capped at [`sphincs_tz_shared::db_format::NAMES_MAX_LEN`]
//! and every byte must lie in printable ASCII (0x20..=0x7e). Control
//! bytes and Unicode homoglyphs are rejected — the OLED only renders
//! ASCII anyway, and anything else would be a spoofing foothold.
//!
//! ## Cross-checks before trusting the metadata
//!
//! Merkle verification proves the supplied `(chain_id, address, name)`
//! triple exists in the DB the secure firmware was built against. It
//! does NOT prove the supplied `(chain_id, address)` matches whatever
//! the secure world was about to display. That second check lives in
//! [`crate::names::resolver::NameResolver::lookup`], which keys on
//! `(chain_id, address)` and is called from the display layer with
//! values derived from the parsed tx — never from the bundle.

use crate::erc20::merkle::verify_proof;
use sphincs_tz_shared::db_format::NAMES_MAX_LEN;

/// Decoded + Merkle-verified address-name entry. Borrows from the
/// gateway buffer the bundle was copied into; the lifetime is tied to
/// that buffer's stack frame.
#[derive(Clone, Copy, Debug)]
pub struct NameMeta<'a> {
    pub chain_id: u64,
    pub address: [u8; 20],
    pub name: &'a [u8],
}

/// Maximum total bundle size, used to bound the secure-side stack
/// buffer that holds the copy. 8+20+1+32 + 4+4 + 32 levels of proof
/// = ~1.1 KB upper bound. Capped well below MAX_TX_LEN.
pub const MAX_NAME_BUNDLE_LEN: usize = 8 + 20 + 1 + NAMES_MAX_LEN + 4 + 4 + 32 * 32;

/// Verify a single bundle against `root`. On success returns the
/// decoded metadata; on any failure returns `None`. `bundle` must be
/// the exact bytes NS wrote — no outer length prefix. The caller
/// parses any length prefix at the gateway boundary.
pub fn verify_name_bundle<'a>(bundle: &'a [u8], root: &[u8; 32]) -> Option<NameMeta<'a>> {
    let mut off = 0usize;

    // Header fixed fields.
    if bundle.len() < off + 8 + 20 + 1 {
        return None;
    }
    let chain_id = read_u64_le(bundle, off)?;
    off += 8;
    let address: [u8; 20] = bundle.get(off..off + 20)?.try_into().ok()?;
    off += 20;

    // Name (length-prefixed).
    let name_len = *bundle.get(off)? as usize;
    off += 1;
    if name_len == 0 || name_len > NAMES_MAX_LEN {
        return None;
    }
    let name = bundle.get(off..off + name_len)?;
    off += name_len;
    if !is_clean_ascii(name) {
        return None;
    }

    // Merkle proof header.
    if bundle.len() < off + 4 + 4 {
        return None;
    }
    let leaf_index = read_u32_le(bundle, off)? as usize;
    off += 4;
    let proof_depth = read_u32_le(bundle, off)? as usize;
    off += 4;
    if proof_depth > 32 {
        return None;
    }

    let proof_size = proof_depth * 32;
    // Reject trailing bytes — the buffer must be exactly the bundle.
    if bundle.len() != off + proof_size {
        return None;
    }
    let proof = bundle.get(off..off + proof_size)?;

    // Re-derive the canonical leaf bytes from the supplied fields.
    // MUST match dbgen::names::canonical_names_leaf byte-for-byte.
    let canonical_len = 8 + 20 + 1 + name_len;
    let mut canonical = [0u8; 8 + 20 + 1 + NAMES_MAX_LEN];
    let mut p = 0usize;
    canonical[p..p + 8].copy_from_slice(&chain_id.to_le_bytes());
    p += 8;
    canonical[p..p + 20].copy_from_slice(&address);
    p += 20;
    canonical[p] = name_len as u8;
    p += 1;
    canonical[p..p + name_len].copy_from_slice(name);
    p += name_len;
    debug_assert_eq!(p, canonical_len);

    if !verify_proof(
        &canonical[..canonical_len],
        leaf_index,
        proof,
        proof_depth,
        root,
    ) {
        return None;
    }

    Some(NameMeta {
        chain_id,
        address,
        name,
    })
}

fn read_u32_le(buf: &[u8], off: usize) -> Option<u32> {
    let bytes: [u8; 4] = buf.get(off..off + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn read_u64_le(buf: &[u8], off: usize) -> Option<u64> {
    let bytes: [u8; 8] = buf.get(off..off + 8)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

fn is_clean_ascii(s: &[u8]) -> bool {
    s.iter().all(|&b| (0x20..0x7f).contains(&b))
}
