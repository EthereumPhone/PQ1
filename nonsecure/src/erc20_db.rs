//! Non-secure-side ERC20 metadata DB lookup.
//!
//! The full DB blob is `include_bytes!`d into the NS firmware image
//! as static rodata. The non-secure world walks its sorted index by
//! `(chain_id, contract)`, builds a `(canonical_metadata,
//! merkle_proof, leaf_index)` bundle, and forwards it to the secure
//! world via the gateway. The secure world re-derives the leaf hash
//! and verifies the Merkle proof against an embedded root before
//! trusting any of it for trusted-UI display.
//!
//! This module is `#![no_std]`, no-alloc — bundles are written into
//! a caller-supplied buffer.

use sphincs_tz_shared::db_format::{
    read_u32_le, read_u64_le, ERC20_DB_ENTRY_LEN, ERC20_DB_HEADER_LEN, ERC20_DB_MAGIC,
    ERC20_DB_VERSION, ERC20_ENTRY_OFF_CHAIN_ID, ERC20_ENTRY_OFF_CONTRACT, ERC20_ENTRY_OFF_DECIMALS,
    ERC20_ENTRY_OFF_NAME_OFF, ERC20_ENTRY_OFF_SYMBOL_OFF, ERC20_HDR_OFF_ENTRY_CNT,
    ERC20_HDR_OFF_POOL_OFF, ERC20_HDR_OFF_PROOFS_OFF, ERC20_HDR_OFF_PROOF_DEPTH,
    ERC20_HDR_OFF_VERSION,
};

static ERC20_DB: &[u8] = include_bytes!("erc20_db.bin");

/// Build an ERC20 metadata bundle for `(chain_id, contract)`. Writes
/// into `out` and returns the number of bytes written, or `None` if
/// the entry isn't in the DB or `out` is too small.
///
/// Wire layout (must match `secure/src/erc20/bundle.rs`):
///
/// ```text
///   chain_id      u64 LE       ( 8 B)
///   contract      [u8; 20]     (20 B)
///   decimals      u8           ( 1 B)
///   name_len      u8           ( 1 B)
///   name          [u8; name_len]
///   symbol_len    u8           ( 1 B)
///   symbol        [u8; symbol_len]
///   leaf_index    u32 LE       ( 4 B)
///   proof_depth   u32 LE       ( 4 B)
///   proof         [u8; proof_depth * 32]
/// ```
pub fn build_bundle(chain_id: u64, contract: &[u8; 20], out: &mut [u8]) -> Option<usize> {
    let view = open(ERC20_DB)?;
    let idx = view.find_index(chain_id, contract)?;
    let entry_off = ERC20_DB_HEADER_LEN + idx * ERC20_DB_ENTRY_LEN;

    let name_off = read_u32_le(view.blob, entry_off + ERC20_ENTRY_OFF_NAME_OFF) as usize;
    let symbol_off = read_u32_le(view.blob, entry_off + ERC20_ENTRY_OFF_SYMBOL_OFF) as usize;
    let decimals = view.blob[entry_off + ERC20_ENTRY_OFF_DECIMALS];

    let name = read_pool_string(view.blob, view.pool_off + name_off)?;
    let symbol = read_pool_string(view.blob, view.pool_off + symbol_off)?;

    let needed = 8 + 20 + 1 + 1 + name.len() + 1 + symbol.len() + 4 + 4 + view.proof_depth * 32;
    if out.len() < needed {
        return None;
    }

    let mut p = 0usize;
    out[p..p + 8].copy_from_slice(&chain_id.to_le_bytes());
    p += 8;
    out[p..p + 20].copy_from_slice(contract);
    p += 20;
    out[p] = decimals;
    p += 1;
    out[p] = name.len() as u8;
    p += 1;
    out[p..p + name.len()].copy_from_slice(name);
    p += name.len();
    out[p] = symbol.len() as u8;
    p += 1;
    out[p..p + symbol.len()].copy_from_slice(symbol);
    p += symbol.len();
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
    if blob.len() < ERC20_DB_HEADER_LEN {
        return None;
    }
    if blob[..4] != ERC20_DB_MAGIC {
        return None;
    }
    if read_u32_le(blob, ERC20_HDR_OFF_VERSION) != ERC20_DB_VERSION {
        return None;
    }
    let entry_cnt = read_u32_le(blob, ERC20_HDR_OFF_ENTRY_CNT) as usize;
    let pool_off = read_u32_le(blob, ERC20_HDR_OFF_POOL_OFF) as usize;
    let proof_depth = read_u32_le(blob, ERC20_HDR_OFF_PROOF_DEPTH) as usize;
    let proofs_off = read_u32_le(blob, ERC20_HDR_OFF_PROOFS_OFF) as usize;
    Some(DbView {
        blob,
        entry_cnt,
        pool_off,
        proof_depth,
        proofs_off,
    })
}

impl DbView {
    fn find_index(&self, chain_id: u64, contract: &[u8; 20]) -> Option<usize> {
        let mut lo = 0usize;
        let mut hi = self.entry_cnt;
        while lo < hi {
            let mid = (lo + hi) / 2;
            let off = ERC20_DB_HEADER_LEN + mid * ERC20_DB_ENTRY_LEN;
            let mid_chain = read_u64_le(self.blob, off + ERC20_ENTRY_OFF_CHAIN_ID);
            let mid_contract: &[u8] =
                &self.blob[off + ERC20_ENTRY_OFF_CONTRACT..off + ERC20_ENTRY_OFF_CONTRACT + 20];
            let cmp = match mid_chain.cmp(&chain_id) {
                core::cmp::Ordering::Equal => mid_contract.cmp(&contract[..]),
                other => other,
            };
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
