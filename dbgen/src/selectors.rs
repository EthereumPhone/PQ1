//! Function-selector → text-signature DB writer + round-trip checker.
//!
//! Parallels [`crate::names`] but for the EVM 4-byte selector → canonical
//! Solidity text signature mapping. Two differences from the Names DB:
//!
//! 1. **The blob is a host-side artifact, not NS rodata.** `dbgen`
//!    writes it to `tools/companion-stub/selectors_db.bin`; the
//!    secure firmware embeds only the 32-byte Merkle root. The future
//!    companion app holds the blob and serves bundles through the USB
//!    HID gateway. NS does NOT `include_bytes!` it (except under the
//!    `e2e-test` build, which acts as a dev-only companion stub).
//!
//! 2. **Index key is the raw 4-byte selector, not a hash of it.**
//!    Selectors are themselves keccak-derived and therefore already
//!    uniform — the on-disk binary search keys directly on selector
//!    bytes, sorted lexicographically. The Merkle leaf binds the full
//!    `(selector, text_sig)` pair so a future colliding entry cannot
//!    substitute a different signature.

use crate::merkle::{leaf_hash, verify_proof, MerkleTree};
use crate::{write_u32_le, SelectorsRecord};
use sphincs_tz_shared::db_format::*;
use std::collections::HashMap;
use std::path::Path;

/// Byte-for-byte canonical leaf encoding consumed by the secure-world
/// verifier. MUST match `secure/src/selectors/bundle.rs`.
pub fn canonical_selector_leaf(selector: &[u8; 4], text_sig: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + 1 + text_sig.len());
    buf.extend_from_slice(selector);
    buf.push(text_sig.len() as u8);
    buf.extend_from_slice(text_sig);
    buf
}

pub struct SelectorsBuildResult {
    pub blob: Vec<u8>,
    pub root: [u8; 32],
}

pub fn build_db(json_path: &Path) -> Result<SelectorsBuildResult, String> {
    let records = crate::load_selectors_records(json_path)?;
    if records.is_empty() {
        return Err("selectors.json contains no entries".to_string());
    }

    // 1. Parse + validate.
    let mut prepared: Vec<PreparedRow> = Vec::with_capacity(records.len());
    for r in &records {
        let selector = parse_selector(&r.selector)?;
        if r.text_sig.is_empty() {
            return Err(format!(
                "empty text_sig for selector 0x{}",
                hex::encode(selector)
            ));
        }
        if r.text_sig.len() > SELECTOR_TEXT_SIG_MAX_LEN {
            return Err(format!(
                "text_sig too long (>{} bytes): {:?}",
                SELECTOR_TEXT_SIG_MAX_LEN, r.text_sig
            ));
        }
        if !r.text_sig.as_bytes().iter().all(|&b| (0x20..0x7f).contains(&b)) {
            return Err(format!(
                "text_sig contains non-printable-ASCII bytes: {:?}",
                r.text_sig
            ));
        }
        prepared.push(PreparedRow {
            selector,
            text_sig: r.text_sig.clone(),
        });
    }

    // 2. Sort by selector for runtime binary search.
    prepared.sort_by(|a, b| a.selector.cmp(&b.selector));

    // 3. Reject duplicate selectors. Curation should drop adversarial
    //    collisions before the JSON is written; a duplicate at this
    //    point is a curation bug.
    for w in prepared.windows(2) {
        if w[0].selector == w[1].selector {
            return Err(format!(
                "duplicate selector 0x{}: {:?} <-> {:?}",
                hex::encode(w[0].selector),
                w[0].text_sig,
                w[1].text_sig,
            ));
        }
    }

    // 4. Build interned text-sig pool.
    let mut pool: Vec<u8> = Vec::new();
    let mut intern: HashMap<String, u32> = HashMap::new();
    let mut text_offs: Vec<u32> = Vec::with_capacity(prepared.len());
    for r in &prepared {
        if let Some(off) = intern.get(&r.text_sig) {
            text_offs.push(*off);
            continue;
        }
        let off: u32 = pool
            .len()
            .try_into()
            .map_err(|_| "selectors pool > 4 GiB".to_string())?;
        pool.push(r.text_sig.len() as u8);
        pool.extend_from_slice(r.text_sig.as_bytes());
        intern.insert(r.text_sig.clone(), off);
        text_offs.push(off);
    }

    // 5. Build merkle tree from canonical leaves (binds the full
    //    (selector, text_sig) pair, not just the selector).
    let leaf_hashes: Vec<[u8; 32]> = prepared
        .iter()
        .map(|r| leaf_hash(&canonical_selector_leaf(&r.selector, r.text_sig.as_bytes())))
        .collect();
    let tree = MerkleTree::build(leaf_hashes);
    let root = tree.root();
    let proof_depth = tree.depth();

    // 6. Lay out: header | entries | pool | proofs
    let entry_cnt = prepared.len();
    let entries_size = entry_cnt * SELECTOR_DB_ENTRY_LEN;
    let pool_off = SELECTOR_DB_HEADER_LEN + entries_size;
    let proofs_off = pool_off + pool.len();
    let proofs_size = entry_cnt * proof_depth * 32;
    let total_size = proofs_off + proofs_size;

    let mut blob: Vec<u8> = Vec::with_capacity(total_size);

    // --- Header (32 B) ---
    blob.extend_from_slice(&SELECTOR_DB_MAGIC);
    write_u32_le(&mut blob, SELECTOR_DB_VERSION);
    write_u32_le(&mut blob, 0);
    write_u32_le(
        &mut blob,
        entry_cnt
            .try_into()
            .map_err(|_| "entry_cnt > u32::MAX".to_string())?,
    );
    write_u32_le(
        &mut blob,
        pool_off
            .try_into()
            .map_err(|_| "pool_off > u32::MAX".to_string())?,
    );
    write_u32_le(
        &mut blob,
        pool.len()
            .try_into()
            .map_err(|_| "pool_size > u32::MAX".to_string())?,
    );
    write_u32_le(
        &mut blob,
        proof_depth
            .try_into()
            .map_err(|_| "proof_depth > u32::MAX".to_string())?,
    );
    write_u32_le(
        &mut blob,
        proofs_off
            .try_into()
            .map_err(|_| "proofs_off > u32::MAX".to_string())?,
    );
    assert_eq!(blob.len(), SELECTOR_DB_HEADER_LEN);

    // --- Entries (8 B each) ---
    for (i, r) in prepared.iter().enumerate() {
        let start = blob.len();
        blob.extend_from_slice(&r.selector);
        write_u32_le(&mut blob, text_offs[i]);
        debug_assert_eq!(blob.len() - start, SELECTOR_DB_ENTRY_LEN);
    }
    assert_eq!(blob.len(), pool_off);

    // --- String pool ---
    blob.extend_from_slice(&pool);
    assert_eq!(blob.len(), proofs_off);

    // --- Merkle proofs ---
    for i in 0..entry_cnt {
        let proof = tree.proof(i);
        debug_assert_eq!(proof.len(), proof_depth);
        for sib in &proof {
            blob.extend_from_slice(sib);
        }
    }
    assert_eq!(blob.len(), total_size);

    Ok(SelectorsBuildResult { blob, root })
}

/// Round-trip every input row through a host-side mirror of the
/// runtime parser. Catches any format drift between dbgen / NS / S.
pub fn round_trip_check(
    blob: &[u8],
    json_path: &Path,
    expected_root: &[u8; 32],
) -> Result<(), String> {
    let records = crate::load_selectors_records(json_path)?;
    let parser = HostSelectorsDb::open(blob)?;

    for r in &records {
        let selector = parse_selector(&r.selector)?;
        let found = parser
            .lookup(&selector)
            .ok_or_else(|| format!("round-trip: missing entry for selector 0x{}", hex::encode(selector)))?;
        if found.text_sig != r.text_sig.as_bytes() {
            return Err(format!(
                "round-trip text_sig mismatch for 0x{}: wrote {:?} read {:?}",
                hex::encode(selector),
                r.text_sig,
                std::str::from_utf8(found.text_sig).unwrap_or("<invalid>")
            ));
        }

        let canonical = canonical_selector_leaf(&selector, r.text_sig.as_bytes());
        let proof = parser
            .proof(&selector)
            .ok_or_else(|| format!("round-trip: missing proof for 0x{}", hex::encode(selector)))?;
        if !verify_proof(&canonical, found.index, &proof, expected_root) {
            return Err(format!(
                "round-trip: Merkle proof failed for selector 0x{}",
                hex::encode(selector)
            ));
        }
    }

    Ok(())
}

#[derive(Debug)]
struct PreparedRow {
    selector: [u8; 4],
    text_sig: String,
}

/// Parse a `"0xa9059cbb"` (or `"a9059cbb"`) string into 4 bytes.
fn parse_selector(s: &str) -> Result<[u8; 4], String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != 8 {
        return Err(format!("selector must be 8 hex chars, got {}", s.len()));
    }
    let bytes = hex::decode(s).map_err(|e| format!("hex decode selector: {e}"))?;
    let mut out = [0u8; 4];
    out.copy_from_slice(&bytes);
    Ok(out)
}

// === Host-side parser mirror ================================================

struct HostSelectorsDb<'a> {
    blob: &'a [u8],
    entry_cnt: usize,
    pool_off: usize,
    proof_depth: usize,
    proofs_off: usize,
}

struct HostSelectorsMeta<'a> {
    text_sig: &'a [u8],
    index: usize,
}

impl<'a> HostSelectorsDb<'a> {
    fn open(blob: &'a [u8]) -> Result<Self, String> {
        if blob.len() < SELECTOR_DB_HEADER_LEN {
            return Err("selectors blob smaller than header".to_string());
        }
        if blob[..4] != SELECTOR_DB_MAGIC {
            return Err("selectors blob bad magic".to_string());
        }
        let version = read_u32_le(blob, SELECTOR_HDR_OFF_VERSION);
        if version != SELECTOR_DB_VERSION {
            return Err(format!(
                "selectors blob version {} != {}",
                version, SELECTOR_DB_VERSION
            ));
        }
        let entry_cnt = read_u32_le(blob, SELECTOR_HDR_OFF_ENTRY_CNT) as usize;
        let pool_off = read_u32_le(blob, SELECTOR_HDR_OFF_POOL_OFF) as usize;
        let expected_entries_end = SELECTOR_DB_HEADER_LEN + entry_cnt * SELECTOR_DB_ENTRY_LEN;
        if pool_off != expected_entries_end {
            return Err(format!(
                "selectors pool_off {} != expected {}",
                pool_off, expected_entries_end
            ));
        }
        let proof_depth = read_u32_le(blob, SELECTOR_HDR_OFF_PROOF_DEPTH) as usize;
        let proofs_off = read_u32_le(blob, SELECTOR_HDR_OFF_PROOFS_OFF) as usize;
        if proofs_off + entry_cnt * proof_depth * 32 > blob.len() {
            return Err("selectors proofs region out of bounds".to_string());
        }
        Ok(Self {
            blob,
            entry_cnt,
            pool_off,
            proof_depth,
            proofs_off,
        })
    }

    fn find_index(&self, selector: &[u8; 4]) -> Option<usize> {
        let mut lo = 0usize;
        let mut hi = self.entry_cnt;
        while lo < hi {
            let mid = (lo + hi) / 2;
            let off = SELECTOR_DB_HEADER_LEN + mid * SELECTOR_DB_ENTRY_LEN;
            let mid_sel = &self.blob[off..off + 4];
            match mid_sel.cmp(&selector[..]) {
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
                std::cmp::Ordering::Equal => return Some(mid),
            }
        }
        None
    }

    fn lookup(&self, selector: &[u8; 4]) -> Option<HostSelectorsMeta<'a>> {
        let idx = self.find_index(selector)?;
        let off = SELECTOR_DB_HEADER_LEN + idx * SELECTOR_DB_ENTRY_LEN;
        let text_off = read_u32_le(self.blob, off + SELECTOR_ENTRY_OFF_TEXT_OFF) as usize;
        let text_sig = read_pool_string(self.blob, self.pool_off + text_off)?;
        Some(HostSelectorsMeta { text_sig, index: idx })
    }

    fn proof(&self, selector: &[u8; 4]) -> Option<Vec<[u8; 32]>> {
        let idx = self.find_index(selector)?;
        let mut out = Vec::with_capacity(self.proof_depth);
        let base = self.proofs_off + idx * self.proof_depth * 32;
        for j in 0..self.proof_depth {
            let off = base + j * 32;
            let mut h = [0u8; 32];
            h.copy_from_slice(&self.blob[off..off + 32]);
            out.push(h);
        }
        Some(out)
    }
}

fn read_pool_string(blob: &[u8], at: usize) -> Option<&[u8]> {
    let len = *blob.get(at)? as usize;
    blob.get(at + 1..at + 1 + len)
}

#[allow(dead_code)]
fn _assert_record_shape(_: SelectorsRecord) {}
