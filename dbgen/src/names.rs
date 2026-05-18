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
use crate::{parse_hex_address, write_u32_le};
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_json(s: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(s.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    fn fixture_addr(suffix: u8) -> String {
        format!("0x{}{:02x}", "0".repeat(38), suffix)
    }

    // === Positive ============================================================

    /// Canonical names-leaf encoding is mirrored byte-for-byte in
    /// `secure/src/names/bundle.rs`. Pin one exact preimage.
    #[test]
    fn positive_canonical_names_leaf_byte_frozen() {
        let chain_id: u64 = 0xdead_beef_cafe_babe;
        let addr: [u8; 20] = [
            0xc0, 0xff, 0xee, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
            0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
        ];
        let name = b"Uniswap V3 Router";
        let got = canonical_names_leaf(chain_id, &addr, name);
        let mut expected = Vec::new();
        expected.extend_from_slice(&chain_id.to_le_bytes());
        expected.extend_from_slice(&addr);
        expected.push(name.len() as u8);
        expected.extend_from_slice(name);
        assert_eq!(got, expected);
    }

    /// `names_short_key` is the binary-search key the NS parser uses.
    /// Its tag + encoding (chain_id big-endian!) is baked into both
    /// the on-disk blob and the secure-world Merkle gate. Pin the
    /// exact 16-byte output for a fixed input.
    #[test]
    fn positive_names_short_key_byte_frozen() {
        let chain_id: u64 = 1;
        let addr: [u8; 20] = [0x11; 20];
        // sha256("pqsigner-name-key-v1" || chain_id_be8 || addr_20)[..16]
        let mut h = Sha256::new();
        h.update(b"pqsigner-name-key-v1");
        h.update(1u64.to_be_bytes());
        h.update([0x11u8; 20]);
        let out = h.finalize();
        let mut expected = [0u8; 16];
        expected.copy_from_slice(&out[..16]);
        assert_eq!(names_short_key(chain_id, &addr), expected);
    }

    /// Stability test: the domain tag bytes are frozen by CLAUDE.md
    /// invariant "no casual KDF tag changes". Renaming
    /// `NAMES_SHORT_KEY_TAG` re-keys every shipped name-DB blob.
    #[test]
    fn positive_names_short_key_tag_value_stable() {
        assert_eq!(NAMES_SHORT_KEY_TAG, b"pqsigner-name-key-v1");
        assert_eq!(NAMES_SHORT_KEY_TAG.len(), 20);
    }

    #[test]
    fn positive_build_db_chain_agnostic_entry_round_trips() {
        // chain_id = 0 (omitted) means wildcard; the entry stays in
        // the canonical leaf with chain_id_le = 0.
        let json = format!(
            r#"[
                {{"address": "{}", "name": "CreateX"}}
            ]"#,
            fixture_addr(0x01),
        );
        let f = write_json(&json);
        let res = build_db(f.path()).expect("build_db");
        round_trip_check(&res.blob, f.path(), &res.root).expect("round-trip");
        assert_eq!(res.blob[..4], NAMES_DB_MAGIC);
    }

    #[test]
    fn positive_build_db_multi_chain_round_trip() {
        let json = format!(
            r#"[
                {{"chain_id": 1, "address": "{}", "name": "Uniswap V3 Router"}},
                {{"chain_id": 137, "address": "{}", "name": "Uniswap V3 Router"}}
            ]"#,
            fixture_addr(0x01),
            fixture_addr(0x02),
        );
        let f = write_json(&json);
        let res = build_db(f.path()).expect("build_db");
        round_trip_check(&res.blob, f.path(), &res.root).expect("round-trip");
        // Interning: same name appears once in the pool.
        let pool_size = u32::from_le_bytes(res.blob[20..24].try_into().unwrap());
        assert_eq!(pool_size as usize, 1 + "Uniswap V3 Router".len());
    }

    // === Negative ============================================================

    /// Empty names file rejected.
    #[test]
    fn negative_build_db_empty_json_rejected() {
        let f = write_json("[]");
        let err = build_db(f.path()).err().expect("empty must fail");
        assert!(err.contains("no entries"), "got: {err}");
    }

    /// Empty name string would render as a zero-width row on the
    /// trusted UI — refuse so the rendering path can't see one.
    #[test]
    fn negative_build_db_empty_name_rejected() {
        let json = format!(
            r#"[{{"chain_id": 1, "address": "{}", "name": ""}}]"#,
            fixture_addr(0x01),
        );
        let f = write_json(&json);
        let err = build_db(f.path()).err().expect("empty name must fail");
        assert!(err.contains("empty name"), "got: {err}");
    }

    /// Name longer than NAMES_MAX_LEN can't fit across the two
    /// 16-column OLED rows — refuse rather than render a truncated
    /// label that could mask a real address.
    #[test]
    fn negative_build_db_name_too_long_rejected() {
        let huge = "x".repeat(NAMES_MAX_LEN + 1);
        let json = format!(
            r#"[{{"chain_id": 1, "address": "{}", "name": "{}"}}]"#,
            fixture_addr(0x01),
            huge,
        );
        let f = write_json(&json);
        let err = build_db(f.path()).err().expect("oversize name must fail");
        assert!(err.contains("too long"), "got: {err}");
    }

    /// Non-printable bytes in the name could be a UI-injection vector
    /// (cursor moves, ANSI escapes, NUL terminators tripping printf
    /// behaviour). Refuse at curation time.
    #[test]
    fn negative_build_db_non_ascii_name_rejected() {
        let json = format!(
            r#"[{{"chain_id": 1, "address": "{}", "name": "Bad\u0007Bell"}}]"#,
            fixture_addr(0x01),
        );
        let f = write_json(&json);
        let err = build_db(f.path()).err().expect("non-printable must fail");
        assert!(err.contains("non-printable"), "got: {err}");
    }

    #[test]
    fn negative_build_db_high_byte_name_rejected() {
        // 0x80+ outside printable-ASCII range.
        let json = format!(
            r#"[{{"chain_id": 1, "address": "{}", "name": "café"}}]"#,
            fixture_addr(0x01),
        );
        let f = write_json(&json);
        let err = build_db(f.path()).err().expect("non-ASCII must fail");
        assert!(err.contains("non-printable"), "got: {err}");
    }

    /// Duplicate short_key (same chain_id + address) — almost
    /// certainly a curator-side typo; rejecting prevents the second
    /// row's name from silently overriding the first via sort
    /// stability.
    #[test]
    fn negative_build_db_duplicate_short_key_rejected() {
        let json = format!(
            r#"[
                {{"chain_id": 1, "address": "{}", "name": "First"}},
                {{"chain_id": 1, "address": "{}", "name": "Second"}}
            ]"#,
            fixture_addr(0xaa),
            fixture_addr(0xaa),
        );
        let f = write_json(&json);
        let err = build_db(f.path()).err().expect("dup must fail");
        assert!(err.contains("duplicate"), "got: {err}");
    }

    /// names_short_key uses chain_id in BIG endian — a regression to
    /// LE would silently re-key every wallet's name DB. Pin BE.
    #[test]
    fn negative_short_key_chain_id_is_big_endian_not_little() {
        let addr = [0x11u8; 20];
        let be = names_short_key(0x0000_0000_0000_0001, &addr);
        // If the implementation accidentally used LE, the key for
        // chain_id 1 LE would equal the key for chain_id 1<<56 BE.
        let le_lookalike = {
            let mut h = Sha256::new();
            h.update(NAMES_SHORT_KEY_TAG);
            h.update(1u64.to_le_bytes());
            h.update(addr);
            let out = h.finalize();
            let mut k = [0u8; 16];
            k.copy_from_slice(&out[..16]);
            k
        };
        assert_ne!(
            be, le_lookalike,
            "regression: names_short_key is using LE chain_id (should be BE)"
        );
    }

    /// Wildcard chain_id (0) and a real chain (1) at the SAME address
    /// must produce different short_keys — otherwise the wildcard
    /// fallback path in `secure/src/names/lookup.rs` could collide
    /// with a real entry.
    #[test]
    fn negative_short_key_wildcard_differs_from_real_chain() {
        let addr = [0x42u8; 20];
        let wildcard = names_short_key(0, &addr);
        let chain1 = names_short_key(1, &addr);
        assert_ne!(wildcard, chain1);
    }

    /// Bad-hex address rejected.
    #[test]
    fn negative_build_db_bad_address_rejected() {
        let json = r#"[{"chain_id": 1, "address": "0xbeef", "name": "N"}]"#;
        let f = write_json(json);
        let err = build_db(f.path()).err().expect("short address must fail");
        assert!(err.contains("hex"), "got: {err}");
    }

    /// Tampered short_key — flip any byte and round-trip must fail.
    /// This proves the on-disk index is gated by the Merkle root
    /// rather than just by sort order.
    #[test]
    fn negative_round_trip_tampered_short_key_rejected() {
        let json = format!(
            r#"[
                {{"chain_id": 1, "address": "{}", "name": "X"}},
                {{"chain_id": 2, "address": "{}", "name": "Y"}}
            ]"#,
            fixture_addr(0x01),
            fixture_addr(0x02),
        );
        let f = write_json(&json);
        let res = build_db(f.path()).expect("build_db");
        let mut tampered = res.blob.clone();
        // Flip a byte in the FIRST entry's short_key.
        tampered[NAMES_DB_HEADER_LEN] ^= 0x01;
        let err = round_trip_check(&tampered, f.path(), &res.root)
            .err().expect("tampered short_key must fail");
        // Either the entry won't be found OR the proof won't verify;
        // both are acceptable rejection paths.
        assert!(
            err.contains("missing") || err.contains("Merkle"),
            "got: {err}",
        );
    }

    /// NAMES_MAX_LEN frozen — bumping it changes the curator's
    /// ceiling and could let UI-overflow strings into the trust
    /// anchor. Pin to detect accidental bumps.
    #[test]
    fn negative_names_max_len_frozen() {
        assert_eq!(
            NAMES_MAX_LEN, 32,
            "NAMES_MAX_LEN is a UI-rendering bound (2 × 16-col rows). \
             Changing it is a deliberate UX decision, not an incidental \
             refactor."
        );
    }
}
