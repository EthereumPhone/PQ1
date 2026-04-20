//! Address-name DB writer + round-trip checker.
//!
//! Parallel to [`crate::erc20`] but for the `(chain_id, address) -> name`
//! display lookup. Two differences worth noting:
//!
//! 1. **Index key is a hash.** The on-disk entry is keyed by a 16-byte
//!    `short_key = sha256(NAMES_SHORT_KEY_TAG || chain_id_be || addr)[..16]`
//!    instead of the raw 28 bytes of `(chain_id, address)`. That shaves
//!    12 B per entry and lets NS binary-search directly on the
//!    short-key form it receives from the companion. The merkle leaf
//!    still binds to the full `(chain_id, address, name)` triple so
//!    short-key collisions cannot substitute names.
//!
//! 2. **No string interning.** Most address names are unique in
//!    practice (Uniswap appears on many chains but the same router
//!    address on different chains has the same display name, which
//!    interning happens to catch; we still run it to shave a few KB).

use crate::merkle::{leaf_hash, verify_proof, MerkleTree};
use crate::{parse_hex_address, write_u32_le, NamesRecord};
use sha2::{Digest, Sha256};
use sphincs_tz_shared::db_format::*;
use std::collections::HashMap;
use std::path::Path;

/// Byte-for-byte canonical leaf encoding consumed by the secure-world
/// verifier. MUST match `secure/src/names/bundle.rs`.
pub fn canonical_names_leaf(chain_id: u64, address: &[u8; 20], name: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + 20 + 1 + name.len());
    buf.extend_from_slice(&chain_id.to_le_bytes());
    buf.extend_from_slice(address);
    buf.push(name.len() as u8);
    buf.extend_from_slice(name);
    buf
}

/// Host-side mirror of the runtime short-key derivation. MUST match
/// the NS + secure-world implementations byte-for-byte.
pub fn names_short_key(chain_id: u64, address: &[u8; 20]) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(NAMES_SHORT_KEY_TAG);
    h.update(chain_id.to_be_bytes());
    h.update(address);
    let out = h.finalize();
    let mut k = [0u8; 16];
    k.copy_from_slice(&out[..16]);
    k
}

pub struct NamesBuildResult {
    pub blob: Vec<u8>,
    pub root: [u8; 32],
}

pub fn build_db(json_path: &Path) -> Result<NamesBuildResult, String> {
    let records = crate::load_names_records(json_path)?;
    if records.is_empty() {
        return Err("names.json contains no entries".to_string());
    }

    // 1. Parse + validate. Enforce the display-width ceiling so
    //    `MAX_NAMES_LEN` stays truthful and so NS can't be tempted to
    //    inject bundles the trusted UI can't render anyway.
    let mut prepared: Vec<PreparedRow> = Vec::with_capacity(records.len());
    for r in &records {
        if r.name.is_empty() {
            return Err(format!(
                "empty name for chain_id={} address={}",
                r.chain_id, r.address
            ));
        }
        if r.name.len() > NAMES_MAX_LEN {
            return Err(format!(
                "name too long (>{} bytes): {:?}",
                NAMES_MAX_LEN, r.name
            ));
        }
        if !r.name.as_bytes().iter().all(|&b| (0x20..0x7f).contains(&b)) {
            return Err(format!(
                "name contains non-printable-ASCII bytes: {:?}",
                r.name
            ));
        }
        let address = parse_hex_address(&r.address)?;
        let short_key = names_short_key(r.chain_id, &address);
        prepared.push(PreparedRow {
            chain_id: r.chain_id,
            address,
            short_key,
            name: r.name.clone(),
        });
    }

    // 2. Sort by short_key for runtime binary search.
    prepared.sort_by(|a, b| a.short_key.cmp(&b.short_key));

    // 3. Reject duplicate short_keys. Truly-duplicate (chain, addr)
    //    rows resolve to the same short_key and are almost always a
    //    copy-paste error; genuine 128-bit collisions won't happen in
    //    a 256-entry curated dataset.
    for w in prepared.windows(2) {
        if w[0].short_key == w[1].short_key {
            return Err(format!(
                "duplicate short_key: ({}, 0x{}) <-> ({}, 0x{})",
                w[0].chain_id,
                hex::encode(w[0].address),
                w[1].chain_id,
                hex::encode(w[1].address),
            ));
        }
    }

    // 4. Build interned string pool.
    let mut pool: Vec<u8> = Vec::new();
    let mut intern: HashMap<String, u32> = HashMap::new();
    let mut name_offs: Vec<u32> = Vec::with_capacity(prepared.len());
    for r in &prepared {
        if let Some(off) = intern.get(&r.name) {
            name_offs.push(*off);
            continue;
        }
        let off: u32 = pool
            .len()
            .try_into()
            .map_err(|_| "names pool > 4 GiB".to_string())?;
        pool.push(r.name.len() as u8);
        pool.extend_from_slice(r.name.as_bytes());
        intern.insert(r.name.clone(), off);
        name_offs.push(off);
    }

    // 5. Build merkle tree from canonical leaves (binds full (chain,
    //    addr, name), not just short_key).
    let leaf_hashes: Vec<[u8; 32]> = prepared
        .iter()
        .map(|r| leaf_hash(&canonical_names_leaf(r.chain_id, &r.address, r.name.as_bytes())))
        .collect();
    let tree = MerkleTree::build(leaf_hashes);
    let root = tree.root();
    let proof_depth = tree.depth();

    // 6. Lay out: header | entries | pool | proofs
    let entry_cnt = prepared.len();
    let entries_size = entry_cnt * NAMES_DB_ENTRY_LEN;
    let pool_off = NAMES_DB_HEADER_LEN + entries_size;
    let proofs_off = pool_off + pool.len();
    let proofs_size = entry_cnt * proof_depth * 32;
    let total_size = proofs_off + proofs_size;

    let mut blob: Vec<u8> = Vec::with_capacity(total_size);

    // --- Header (32 B) ---
    blob.extend_from_slice(&NAMES_DB_MAGIC);
    write_u32_le(&mut blob, NAMES_DB_VERSION);
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
    assert_eq!(blob.len(), NAMES_DB_HEADER_LEN);

    // --- Entries (20 B each) ---
    for (i, r) in prepared.iter().enumerate() {
        let start = blob.len();
        blob.extend_from_slice(&r.short_key);
        write_u32_le(&mut blob, name_offs[i]);
        debug_assert_eq!(blob.len() - start, NAMES_DB_ENTRY_LEN);
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

    Ok(NamesBuildResult { blob, root })
}

/// Round-trip every input row through a host-side mirror of the
/// runtime parser. Catches any format drift between dbgen / NS / S.
pub fn round_trip_check(
    blob: &[u8],
    json_path: &Path,
    expected_root: &[u8; 32],
) -> Result<(), String> {
    let records = crate::load_names_records(json_path)?;
    let parser = HostNamesDb::open(blob)?;

    for r in &records {
        let address = parse_hex_address(&r.address)?;
        let key = names_short_key(r.chain_id, &address);
        let found = parser
            .lookup(&key)
            .ok_or_else(|| format!("round-trip: missing entry for {} {}", r.chain_id, r.address))?;
        if found.name != r.name.as_bytes() {
            return Err(format!(
                "round-trip name mismatch for {}: wrote {:?} read {:?}",
                r.address,
                r.name,
                std::str::from_utf8(found.name).unwrap_or("<invalid>")
            ));
        }

        let canonical = canonical_names_leaf(r.chain_id, &address, r.name.as_bytes());
        let proof = parser
            .proof(&key)
            .ok_or_else(|| format!("round-trip: missing proof for {}", r.address))?;
        if !verify_proof(&canonical, found.index, &proof, expected_root) {
            return Err(format!(
                "round-trip: Merkle proof failed for chain={} addr={}",
                r.chain_id, r.address
            ));
        }
    }

    Ok(())
}

#[derive(Debug)]
struct PreparedRow {
    chain_id: u64,
    address: [u8; 20],
    short_key: [u8; 16],
    name: String,
}

// === Host-side parser mirror ================================================

struct HostNamesDb<'a> {
    blob: &'a [u8],
    entry_cnt: usize,
    pool_off: usize,
    proof_depth: usize,
    proofs_off: usize,
}

struct HostNamesMeta<'a> {
    name: &'a [u8],
    index: usize,
}

impl<'a> HostNamesDb<'a> {
    fn open(blob: &'a [u8]) -> Result<Self, String> {
        if blob.len() < NAMES_DB_HEADER_LEN {
            return Err("names blob smaller than header".to_string());
        }
        if blob[..4] != NAMES_DB_MAGIC {
            return Err("names blob bad magic".to_string());
        }
        let version = read_u32_le(blob, NAMES_HDR_OFF_VERSION);
        if version != NAMES_DB_VERSION {
            return Err(format!(
                "names blob version {} != {}",
                version, NAMES_DB_VERSION
            ));
        }
        let entry_cnt = read_u32_le(blob, NAMES_HDR_OFF_ENTRY_CNT) as usize;
        let pool_off = read_u32_le(blob, NAMES_HDR_OFF_POOL_OFF) as usize;
        let expected_entries_end = NAMES_DB_HEADER_LEN + entry_cnt * NAMES_DB_ENTRY_LEN;
        if pool_off != expected_entries_end {
            return Err(format!(
                "names pool_off {} != expected {}",
                pool_off, expected_entries_end
            ));
        }
        let proof_depth = read_u32_le(blob, NAMES_HDR_OFF_PROOF_DEPTH) as usize;
        let proofs_off = read_u32_le(blob, NAMES_HDR_OFF_PROOFS_OFF) as usize;
        if proofs_off + entry_cnt * proof_depth * 32 > blob.len() {
            return Err("names proofs region out of bounds".to_string());
        }
        Ok(Self {
            blob,
            entry_cnt,
            pool_off,
            proof_depth,
            proofs_off,
        })
    }

    fn find_index(&self, short_key: &[u8; 16]) -> Option<usize> {
        let mut lo = 0usize;
        let mut hi = self.entry_cnt;
        while lo < hi {
            let mid = (lo + hi) / 2;
            let off = NAMES_DB_HEADER_LEN + mid * NAMES_DB_ENTRY_LEN;
            let mid_key = &self.blob[off..off + 16];
            match mid_key.cmp(&short_key[..]) {
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
                std::cmp::Ordering::Equal => return Some(mid),
            }
        }
        None
    }

    fn lookup(&self, short_key: &[u8; 16]) -> Option<HostNamesMeta<'a>> {
        let idx = self.find_index(short_key)?;
        let off = NAMES_DB_HEADER_LEN + idx * NAMES_DB_ENTRY_LEN;
        let name_off = read_u32_le(self.blob, off + NAMES_ENTRY_OFF_NAME_OFF) as usize;
        let name = read_pool_string(self.blob, self.pool_off + name_off)?;
        Some(HostNamesMeta { name, index: idx })
    }

    fn proof(&self, short_key: &[u8; 16]) -> Option<Vec<[u8; 32]>> {
        let idx = self.find_index(short_key)?;
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

// Silence the unused-import warning — `NamesRecord` is re-exported
// by the module for the loader signature in main.rs.
#[allow(dead_code)]
fn _assert_record_shape(_: NamesRecord) {}
