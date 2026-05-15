//! Non-secure-side address-name DB lookup.
//!
//! The full blob is `include_bytes!`d into NS rodata. At sign time NS
//! walks the sorted-by-`short_key` index, builds a
//! `(chain_id, addr, name, merkle_proof)` bundle, and forwards it to
//! the secure world via the gateway. The secure world re-derives the
//! leaf hash from its own (tx-supplied) `(chain_id, addr)` and verifies
//! the proof against the embedded `NAMES_DB_ROOT` before any name
//! reaches the trusted UI.
//!
//! This module is `#![no_std]`, no-alloc — bundles are written into
//! a caller-supplied buffer.

use sha2::{Digest, Sha256};
use sphincs_tz_shared::db_format::{
    read_u32_le, NAMES_DB_ENTRY_LEN, NAMES_DB_HEADER_LEN, NAMES_DB_MAGIC, NAMES_DB_VERSION,
    NAMES_ENTRY_OFF_NAME_OFF, NAMES_HDR_OFF_ENTRY_CNT, NAMES_HDR_OFF_POOL_OFF,
    NAMES_HDR_OFF_PROOFS_OFF, NAMES_HDR_OFF_PROOF_DEPTH, NAMES_HDR_OFF_VERSION, NAMES_SHORT_KEY_TAG,
    NAMES_WILDCARD_CHAIN_ID,
};

static NAMES_DB: &[u8] = include_bytes!("names_db.bin");

/// Mirror of `secure::names::MAX_NAME_BUNDLES`. The secure side caps
/// at this count, so NS must not exceed it or the extra bundles will
/// be rejected by the gateway parser.
pub const MAX_NAME_BUNDLES: usize = 4;

/// Compute the 16-byte short-key used to look up an address in the DB.
/// MUST match the host builder and the secure-world verifier
/// byte-for-byte.
pub fn short_key(chain_id: u64, address: &[u8; 20]) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(NAMES_SHORT_KEY_TAG);
    h.update(chain_id.to_be_bytes());
    h.update(address);
    let out = h.finalize();
    let mut k = [0u8; 16];
    k.copy_from_slice(&out[..16]);
    k
}

/// Write a name-bundle for `(chain_id, address)` into `out`. Returns
/// the number of bytes written, or `None` if no matching entry exists
/// or `out` is too small.
///
/// Wire layout (must match `secure/src/names/bundle.rs`):
///
/// ```text
///   chain_id    u64 LE       ( 8 B)
///   address     [u8; 20]     (20 B)
///   name_len    u8           ( 1 B)
///   name        [u8; name_len]
///   leaf_index  u32 LE       ( 4 B)
///   proof_depth u32 LE       ( 4 B)
///   proof       [u8; proof_depth * 32]
/// ```
pub fn build_bundle(chain_id: u64, address: &[u8; 20], out: &mut [u8]) -> Option<usize> {
    let view = open(NAMES_DB)?;
    // Two-phase match: chain-specific first, chain-agnostic fallback.
    // The emitted bundle carries whichever chain_id actually hit — a
    // `0` wildcard entry crosses the gateway as `chain_id = 0` and the
    // secure-side resolver's own two-phase lookup handles the match
    // against tx.chain_id.
    let (hit_chain_id, idx) = match view.find_index(&short_key(chain_id, address)) {
        Some(i) => (chain_id, i),
        None => {
            if chain_id == NAMES_WILDCARD_CHAIN_ID {
                return None;
            }
            let wc_key = short_key(NAMES_WILDCARD_CHAIN_ID, address);
            match view.find_index(&wc_key) {
                Some(i) => (NAMES_WILDCARD_CHAIN_ID, i),
                None => return None,
            }
        }
    };
    let entry_off = NAMES_DB_HEADER_LEN + idx * NAMES_DB_ENTRY_LEN;

    let name_off = read_u32_le(view.blob, entry_off + NAMES_ENTRY_OFF_NAME_OFF) as usize;
    let name = read_pool_string(view.blob, view.pool_off + name_off)?;

    let needed = 8 + 20 + 1 + name.len() + 4 + 4 + view.proof_depth * 32;
    if out.len() < needed {
        return None;
    }

    let mut p = 0usize;
    out[p..p + 8].copy_from_slice(&hit_chain_id.to_le_bytes());
    p += 8;
    out[p..p + 20].copy_from_slice(address);
    p += 20;
    out[p] = name.len() as u8;
    p += 1;
    out[p..p + name.len()].copy_from_slice(name);
    p += name.len();
    out[p..p + 4].copy_from_slice(&(idx as u32).to_le_bytes());
    p += 4;
    out[p..p + 4].copy_from_slice(&(view.proof_depth as u32).to_le_bytes());
    p += 4;

    let proof_base = view.proofs_off + idx * view.proof_depth * 32;
    let proof_size = view.proof_depth * 32;
    out[p..p + proof_size].copy_from_slice(&view.blob[proof_base..proof_base + proof_size]);
    p += proof_size;

    Some(p)
}

struct DbView {
    blob: &'static [u8],
    entry_cnt: usize,
    pool_off: usize,
    proof_depth: usize,
    proofs_off: usize,
}

fn open(blob: &'static [u8]) -> Option<DbView> {
    if blob.len() < NAMES_DB_HEADER_LEN {
        return None;
    }
    if blob[..4] != NAMES_DB_MAGIC {
        return None;
    }
    if read_u32_le(blob, NAMES_HDR_OFF_VERSION) != NAMES_DB_VERSION {
        return None;
    }
    let entry_cnt = read_u32_le(blob, NAMES_HDR_OFF_ENTRY_CNT) as usize;
    let pool_off = read_u32_le(blob, NAMES_HDR_OFF_POOL_OFF) as usize;
    let proof_depth = read_u32_le(blob, NAMES_HDR_OFF_PROOF_DEPTH) as usize;
    let proofs_off = read_u32_le(blob, NAMES_HDR_OFF_PROOFS_OFF) as usize;
    Some(DbView {
        blob,
        entry_cnt,
        pool_off,
        proof_depth,
        proofs_off,
    })
}

impl DbView {
    fn find_index(&self, short_key: &[u8; 16]) -> Option<usize> {
        let mut lo = 0usize;
        let mut hi = self.entry_cnt;
        while lo < hi {
            let mid = (lo + hi) / 2;
            let off = NAMES_DB_HEADER_LEN + mid * NAMES_DB_ENTRY_LEN;
            let mid_key = &self.blob[off..off + 16];
            let cmp = mid_key.cmp(&short_key[..]);
            match cmp {
                core::cmp::Ordering::Less => lo = mid + 1,
                core::cmp::Ordering::Greater => hi = mid,
                core::cmp::Ordering::Equal => return Some(mid),
            }
        }
        None
    }
}

fn read_pool_string(blob: &'static [u8], at: usize) -> Option<&'static [u8]> {
    let len = *blob.get(at)? as usize;
    blob.get(at + 1..at + 1 + len)
}
