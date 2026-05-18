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
use crate::write_u32_le;
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

    // === Positive ============================================================

    /// Canonical selector-leaf encoding mirrors `secure/src/selectors/
    /// bundle.rs`. Format drift here would break every shipped
    /// SELECTOR_DB_ROOT.
    #[test]
    fn positive_canonical_selector_leaf_byte_frozen() {
        let sel: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
        let sig = b"transfer(address,uint256)";
        let got = canonical_selector_leaf(&sel, sig);
        let mut expected = Vec::new();
        expected.extend_from_slice(&sel);
        expected.push(sig.len() as u8);
        expected.extend_from_slice(sig);
        assert_eq!(got, expected);
        assert_eq!(got.len(), 4 + 1 + sig.len());
    }

    #[test]
    fn positive_parse_selector_with_and_without_0x_prefix() {
        let json_no_prefix = r#"[{"selector": "a9059cbb", "text_sig": "transfer(address,uint256)"}]"#;
        let f = write_json(json_no_prefix);
        build_db(f.path()).expect("bare hex accepted");
    }

    #[test]
    fn positive_build_db_round_trip() {
        let json = r#"[
            {"selector": "0xa9059cbb", "text_sig": "transfer(address,uint256)"},
            {"selector": "0x095ea7b3", "text_sig": "approve(address,uint256)"}
        ]"#;
        let f = write_json(json);
        let res = build_db(f.path()).expect("build_db");
        assert_eq!(res.blob[..4], SELECTOR_DB_MAGIC);
        round_trip_check(&res.blob, f.path(), &res.root).expect("round-trip");
    }

    #[test]
    fn positive_build_db_sorts_selectors() {
        // Provide selectors out of order; the on-disk array must be
        // sorted for binary search.
        let json = r#"[
            {"selector": "0xffffffff", "text_sig": "z()"},
            {"selector": "0x00000000", "text_sig": "a()"},
            {"selector": "0x80000000", "text_sig": "m()"}
        ]"#;
        let f = write_json(json);
        let res = build_db(f.path()).expect("build_db");
        // First entry's selector should be 0x00000000 (smallest).
        let off = SELECTOR_DB_HEADER_LEN + SELECTOR_ENTRY_OFF_SELECTOR;
        assert_eq!(&res.blob[off..off + 4], &[0, 0, 0, 0]);
        // Last entry's selector should be 0xffffffff.
        let last = SELECTOR_DB_HEADER_LEN + 2 * SELECTOR_DB_ENTRY_LEN;
        assert_eq!(&res.blob[last..last + 4], &[0xff, 0xff, 0xff, 0xff]);
    }

    /// Canonical text-sigs that map to the same selector are deduped
    /// in the string pool via interning.
    #[test]
    fn positive_build_db_interns_text_sigs() {
        let json = r#"[
            {"selector": "0x11111111", "text_sig": "same(uint256)"},
            {"selector": "0x22222222", "text_sig": "same(uint256)"}
        ]"#;
        let f = write_json(json);
        let res = build_db(f.path()).expect("build_db");
        let pool_size = u32::from_le_bytes(res.blob[20..24].try_into().unwrap());
        assert_eq!(pool_size as usize, 1 + "same(uint256)".len());
    }

    // === Negative ============================================================

    #[test]
    fn negative_build_db_empty_json_rejected() {
        let f = write_json("[]");
        let err = build_db(f.path()).err().expect("empty must fail");
        assert!(err.contains("no entries"), "got: {err}");
    }

    /// Selector must be exactly 4 bytes — a longer or shorter
    /// "selector" claim could let an attacker substitute the prefix
    /// bytes used by the calldata[0..4] cross-check.
    #[test]
    fn negative_build_db_short_selector_rejected() {
        let json = r#"[{"selector": "0xabcd", "text_sig": "f()"}]"#;
        let f = write_json(json);
        let err = build_db(f.path()).err().expect("short selector must fail");
        assert!(err.contains("8 hex"), "got: {err}");
    }

    #[test]
    fn negative_build_db_long_selector_rejected() {
        let json = r#"[{"selector": "0xa9059cbb00", "text_sig": "f()"}]"#;
        let f = write_json(json);
        let err = build_db(f.path()).err().expect("long selector must fail");
        assert!(err.contains("8 hex"), "got: {err}");
    }

    #[test]
    fn negative_build_db_non_hex_selector_rejected() {
        let json = r#"[{"selector": "0xZZZZZZZZ", "text_sig": "f()"}]"#;
        let f = write_json(json);
        let err = build_db(f.path()).err().expect("non-hex selector must fail");
        assert!(err.contains("hex decode") || err.contains("hex"), "got: {err}");
    }

    /// Empty text_sig — would render as blank in the trusted UI.
    #[test]
    fn negative_build_db_empty_text_sig_rejected() {
        let json = r#"[{"selector": "0xa9059cbb", "text_sig": ""}]"#;
        let f = write_json(json);
        let err = build_db(f.path()).err().expect("empty text_sig must fail");
        assert!(err.contains("empty"), "got: {err}");
    }

    /// text_sig past SELECTOR_TEXT_SIG_MAX_LEN can't fit across the
    /// trusted UI's three 16-column rows — refuse so a truncated
    /// signature can never reach the display.
    #[test]
    fn negative_build_db_text_sig_too_long_rejected() {
        let huge = "x".repeat(SELECTOR_TEXT_SIG_MAX_LEN + 1);
        let json = format!(
            r#"[{{"selector": "0xa9059cbb", "text_sig": "{}"}}]"#,
            huge
        );
        let f = write_json(&json);
        let err = build_db(f.path()).err().expect("oversize text_sig must fail");
        assert!(err.contains("too long"), "got: {err}");
    }

    /// Non-printable bytes in text_sig — UI-injection vector via
    /// terminal escapes / cursor codes. Refuse.
    #[test]
    fn negative_build_db_non_printable_text_sig_rejected() {
        let json = r#"[{"selector": "0xa9059cbb", "text_sig": "tab\there"}]"#;
        let f = write_json(json);
        let err = build_db(f.path()).err().expect("tab must fail");
        assert!(err.contains("non-printable"), "got: {err}");
    }

    /// Two rows claiming the same selector with different signatures
    /// — an adversarial 4byte collision. Curator gate so the Merkle
    /// root only commits to a single canonical signature.
    #[test]
    fn negative_build_db_duplicate_selector_rejected() {
        let json = r#"[
            {"selector": "0xa9059cbb", "text_sig": "transfer(address,uint256)"},
            {"selector": "0xa9059cbb", "text_sig": "evil(address,uint256)"}
        ]"#;
        let f = write_json(json);
        let err = build_db(f.path()).err().expect("dup must fail");
        assert!(err.contains("duplicate"), "got: {err}");
    }

    /// Tampered selector byte in the on-disk entry — round-trip must
    /// fail because the entry index is keyed by selector AND the
    /// leaf hash binds it.
    #[test]
    fn negative_round_trip_tampered_selector_rejected() {
        let json = r#"[
            {"selector": "0xa9059cbb", "text_sig": "transfer(address,uint256)"},
            {"selector": "0x095ea7b3", "text_sig": "approve(address,uint256)"}
        ]"#;
        let f = write_json(json);
        let res = build_db(f.path()).expect("build_db");
        let mut tampered = res.blob.clone();
        // Flip a bit in the first entry's selector field.
        tampered[SELECTOR_DB_HEADER_LEN] ^= 0xff;
        let err = round_trip_check(&tampered, f.path(), &res.root)
            .err().expect("tampered selector must fail");
        assert!(
            err.contains("missing") || err.contains("Merkle"),
            "got: {err}",
        );
    }

    /// SELECTOR_TEXT_SIG_MAX_LEN frozen at 63. UI assumes ≤63 chars
    /// fit across three 16-column rows plus a continuation marker.
    #[test]
    fn negative_text_sig_max_len_frozen() {
        assert_eq!(SELECTOR_TEXT_SIG_MAX_LEN, 63);
    }
}
