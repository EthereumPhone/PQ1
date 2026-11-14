//! ERC20 metadata DB writer + round-trip checker.

use crate::merkle::{leaf_hash, verify_proof, MerkleTree};
use crate::{load_erc20_records, parse_hex_address, write_u32_le, write_u64_le};
use pqsigner_tx::erc20::bundle::{
    metadata_shape_is_device_verifiable, MAX_DISPLAY_DECIMALS, MAX_DISPLAY_FIELD,
    MAX_ERC20_PROOF_DEPTH,
};
use sphincs_tz_shared::db_format::*;
use std::collections::HashMap;
use std::path::Path;

/// Build the canonical leaf-hash input bytes for one ERC20 entry.
/// MUST match the secure-world verifier's reconstruction byte-for-byte.
pub fn canonical_erc20_leaf(
    chain_id: u64,
    contract: &[u8; 20],
    decimals: u8,
    name: &[u8],
    symbol: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + 20 + 1 + 2 + name.len() + symbol.len());
    buf.extend_from_slice(&chain_id.to_le_bytes());
    buf.extend_from_slice(contract);
    buf.push(decimals);
    buf.push(name.len() as u8);
    buf.extend_from_slice(name);
    buf.push(symbol.len() as u8);
    buf.extend_from_slice(symbol);
    buf
}

pub struct Erc20BuildResult {
    pub blob: Vec<u8>,
    pub root: [u8; 32],
    pub entry_count: usize,
    /// Exact `(chain_id, contract)` set whose built metadata/proof shape passes
    /// the production device verifier. Since 2026-11-14 [`build_db`] refuses a
    /// DB holding any row that fails that verifier, so this is every committed
    /// row; it is still derived from the shared predicate (not assumed) and it
    /// is the set ERC-7730 interpolation enrollment and the descriptor
    /// constant-token gate consult.
    pub capabilities: Erc20Capabilities,
}

/// Why `metadata_shape_is_device_verifiable` refuses a row, for the build
/// error. The verdict itself always comes from that shared predicate (see
/// [`build_db`]); this only names the first failing gate for a human.
fn device_rule_violation(
    decimals: u8,
    name: &str,
    symbol: &str,
    proof_depth: usize,
) -> Option<String> {
    if metadata_shape_is_device_verifiable(
        decimals,
        name.as_bytes(),
        symbol.as_bytes(),
        proof_depth,
    ) {
        return None;
    }
    let field = |label: &str, value: &str| -> Option<String> {
        let len = value.len();
        if len == 0 {
            Some(format!("{label} is empty"))
        } else if len > MAX_DISPLAY_FIELD {
            Some(format!(
                "{label} too long ({len} bytes > {MAX_DISPLAY_FIELD}): {value:?}"
            ))
        } else if !value.bytes().all(|b| (0x20..0x7f).contains(&b)) {
            Some(format!("{label} is not printable ASCII: {value:?}"))
        } else {
            None
        }
    };
    Some(if decimals > MAX_DISPLAY_DECIMALS {
        format!("decimals {decimals} > {MAX_DISPLAY_DECIMALS}")
    } else if let Some(reason) = field("name", name) {
        reason
    } else if let Some(reason) = field("symbol", symbol) {
        reason
    } else if proof_depth > MAX_ERC20_PROOF_DEPTH {
        format!("Merkle proof depth {proof_depth} > {MAX_ERC20_PROOF_DEPTH}")
    } else {
        format!(
            "bundle for name {name:?} / symbol {symbol:?} at proof depth {proof_depth} \
             exceeds the device bundle limit"
        )
    })
}

fn device_rule_error(row: &PreparedRow, address: &str, reason: &str) -> String {
    format!(
        "ERC-20 row chain_id={} address={address} fails the device verifier \
         (tx/src/erc20/bundle.rs metadata_shape_is_device_verifiable): {reason}. \
         The device would refuse this Merkle-committed row; fix secure/data/erc20*.json \
         (python3 tools/build_erc20_db.py --normalize)",
        row.chain_id,
    )
}

/// Exact device-verifiable token identities in one authenticated ERC-20 DB.
///
/// Construction stays inside [`build_db`], after the Merkle proof depth is
/// known, so callers cannot derive enrollment authority from a looser corpus
/// or metadata shape the device will refuse.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Erc20Capabilities {
    keys: Vec<(u64, [u8; 20])>,
}

impl Erc20Capabilities {
    #[must_use]
    pub fn contains(&self, chain_id: u64, contract: &[u8; 20]) -> bool {
        self.keys.binary_search(&(chain_id, *contract)).is_ok()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn from_keys(mut keys: Vec<(u64, [u8; 20])>) -> Self {
        keys.sort();
        keys.dedup();
        Self { keys }
    }
}

pub fn build_db(json_path: &Path) -> Result<Erc20BuildResult, String> {
    let records = load_erc20_records(json_path)?;
    if records.is_empty() {
        return Err("erc20.json contains no entries".to_string());
    }

    // 1. Validate every row, parse addresses, build sortable records.
    //
    // HARD GATE (2026-11-14): every row must pass the production device
    // verifier's metadata policy. A row that fails it was previously committed
    // to the root anyway and could never render on the device (166 such rows
    // had crept in via on-chain Unicode names). Checked here with a zero-depth
    // proof (metadata only), and again below once the real proof depth is
    // known (the complete bundle-length bound).
    let mut prepared: Vec<PreparedRow> = Vec::with_capacity(records.len());
    for r in &records {
        let contract = parse_hex_address(&r.address)?;
        let row = PreparedRow {
            chain_id: r.chain_id,
            contract,
            name: r.name.clone(),
            symbol: r.symbol.clone(),
            decimals: r.decimals,
            flags: r.flags,
        };
        if let Some(reason) = device_rule_violation(row.decimals, &row.name, &row.symbol, 0) {
            return Err(device_rule_error(&row, &r.address, &reason));
        }
        prepared.push(row);
    }

    // 2. Sort by (chain_id, contract) for runtime binary search.
    prepared.sort_by(|a, b| {
        a.chain_id
            .cmp(&b.chain_id)
            .then_with(|| a.contract.cmp(&b.contract))
    });

    // 3. Reject duplicate (chain_id, contract) keys (typo catcher).
    for w in prepared.windows(2) {
        if w[0].chain_id == w[1].chain_id && w[0].contract == w[1].contract {
            return Err(format!(
                "duplicate (chain_id, contract): chain_id={} contract=0x{}",
                w[0].chain_id,
                hex::encode(w[0].contract)
            ));
        }
    }

    // 4. WARN (do not reject) when the same contract appears on multiple
    //    chains with different name/symbol. At hand-curated scale this was
    //    almost always a copy-paste typo and worth a hard stop. For a large
    //    multichain DB merged from authoritative sources it is frequently
    //    LEGITIMATE: an address can host genuinely different tokens on
    //    different chains (coincidental cross-chain address reuse — e.g.
    //    0x50c5..0cb is DAI on Optimism but LYRA on Base). Because every
    //    lookup is keyed by (chain_id, contract) and every Merkle leaf binds
    //    the chain_id, such entries are fully unambiguous and safe; rejecting
    //    them would silently drop real tokens (incl. blue chips like Optimism
    //    DAI/COMP, L2 XRP/DOGE). We keep the diagnostic as a build-time
    //    warning so a genuine curator typo is still visible on review.
    {
        let mut by_contract: HashMap<[u8; 20], (&str, &str)> = HashMap::new();
        let mut cross_chain_diffs = 0usize;
        for r in &prepared {
            if let Some((name, symbol)) = by_contract.get(&r.contract) {
                if *name != r.name || *symbol != r.symbol {
                    cross_chain_diffs += 1;
                    eprintln!(
                        "dbgen: note: contract 0x{} has different metadata across chains \
                         (`{} ({})` vs `{} ({})`) — allowed (chain-bound leaf), verify it \
                         is intentional",
                        hex::encode(r.contract),
                        name,
                        symbol,
                        r.name,
                        r.symbol
                    );
                }
            } else {
                by_contract.insert(r.contract, (&r.name, &r.symbol));
            }
        }
        if cross_chain_diffs > 0 {
            eprintln!(
                "dbgen: {cross_chain_diffs} shared-address cross-chain metadata \
                 difference(s) — see notes above"
            );
        }
    }

    // 5. Build the interned string pool.
    let mut pool: Vec<u8> = Vec::new();
    let mut intern: HashMap<String, u32> = HashMap::new();
    let mut intern_one = |pool: &mut Vec<u8>, s: &str| -> Result<u32, String> {
        if let Some(off) = intern.get(s) {
            return Ok(*off);
        }
        let off: u32 = pool.len().try_into().map_err(|_| "pool > 4 GiB".to_string())?;
        pool.push(s.len() as u8);
        pool.extend_from_slice(s.as_bytes());
        intern.insert(s.to_string(), off);
        Ok(off)
    };

    let mut interned: Vec<(u32, u32)> = Vec::with_capacity(prepared.len());
    for r in &prepared {
        let name_off = intern_one(&mut pool, &r.name)?;
        let symbol_off = intern_one(&mut pool, &r.symbol)?;
        interned.push((name_off, symbol_off));
    }

    // 6. Compute leaf hashes from the canonical encoding and build
    //    the Merkle tree. The tree is built before the blob layout
    //    so we know `proof_depth` for the header up front.
    let leaf_hashes: Vec<[u8; 32]> = prepared
        .iter()
        .map(|r| {
            let canonical = canonical_erc20_leaf(
                r.chain_id,
                &r.contract,
                r.decimals,
                r.name.as_bytes(),
                r.symbol.as_bytes(),
            );
            leaf_hash(&canonical)
        })
        .collect();
    let tree = MerkleTree::build(leaf_hashes);
    let root = tree.root();
    let proof_depth = tree.depth();

    // Second half of the hard gate: with the exact proof depth known, every
    // row's complete bundle must fit the device's bundle bound.
    for row in &prepared {
        if let Some(reason) =
            device_rule_violation(row.decimals, &row.name, &row.symbol, proof_depth)
        {
            let address = format!("0x{}", hex::encode(row.contract));
            return Err(device_rule_error(row, &address, &reason));
        }
    }

    // Derive ERC-7730 interpolation authority only after the exact proof shape
    // is known, using the production verifier's own policy predicate. After
    // the gate above this is every row; deriving it (rather than assuming it)
    // keeps the enrollment authority tied to the verifier's own predicate.
    let capabilities = Erc20Capabilities {
        keys: prepared
            .iter()
            .filter(|row| {
                metadata_shape_is_device_verifiable(
                    row.decimals,
                    row.name.as_bytes(),
                    row.symbol.as_bytes(),
                    proof_depth,
                )
            })
            .map(|row| (row.chain_id, row.contract))
            .collect(),
    };

    // 7. Lay out the binary blob:
    //   header | entries | pool | proofs
    let entry_cnt = prepared.len();
    let entries_size = entry_cnt * ERC20_DB_ENTRY_LEN;
    let pool_off = ERC20_DB_HEADER_LEN + entries_size;
    let proofs_off = pool_off + pool.len();
    let proofs_size = entry_cnt * proof_depth * 32;
    let total_size = proofs_off + proofs_size;

    let mut blob: Vec<u8> = Vec::with_capacity(total_size);

    // --- Header (32 B) ---
    blob.extend_from_slice(&ERC20_DB_MAGIC);
    write_u32_le(&mut blob, ERC20_DB_VERSION);
    write_u32_le(&mut blob, 0); // flags reserved
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

    assert_eq!(blob.len(), ERC20_DB_HEADER_LEN);

    // --- Entries (40 B each) ---
    for (i, r) in prepared.iter().enumerate() {
        let (name_off, symbol_off) = interned[i];
        let entry_start = blob.len();
        write_u64_le(&mut blob, r.chain_id);
        blob.extend_from_slice(&r.contract);
        write_u32_le(&mut blob, name_off);
        write_u32_le(&mut blob, symbol_off);
        blob.push(r.decimals);
        blob.push(r.flags);
        blob.extend_from_slice(&[0u8; 2]); // _pad
        debug_assert_eq!(blob.len() - entry_start, ERC20_DB_ENTRY_LEN);
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

    Ok(Erc20BuildResult {
        blob,
        root,
        entry_count: entry_cnt,
        capabilities,
    })
}

/// Round-trip every input row through a host-side mirror of the
/// runtime parser. Verifies:
///
/// 1. Each `(chain_id, contract)` from the JSON resolves to its
///    expected metadata in the parsed blob.
/// 2. The per-entry Merkle proof appended to the blob verifies
///    against the build-time-computed root.
///
/// This catches every shape of format drift between dbgen, the
/// non-secure-side parser, and the secure-side Merkle verifier.
pub fn round_trip_check(blob: &[u8], json_path: &Path, expected_root: &[u8; 32]) -> Result<(), String> {
    let records = load_erc20_records(json_path)?;
    let parser = HostErc20Db::open(blob)?;

    for r in &records {
        let contract = parse_hex_address(&r.address)?;
        let found = parser
            .lookup(r.chain_id, &contract)
            .ok_or_else(|| format!("round-trip: missing entry for chain={} addr={}", r.chain_id, r.address))?;
        if found.name != r.name.as_bytes() {
            return Err(format!(
                "round-trip name mismatch for {}: wrote {:?} read {:?}",
                r.address, r.name, std::str::from_utf8(found.name).unwrap_or("<invalid>")
            ));
        }
        if found.symbol != r.symbol.as_bytes() {
            return Err(format!(
                "round-trip symbol mismatch for {}: wrote {:?} read {:?}",
                r.address, r.symbol, std::str::from_utf8(found.symbol).unwrap_or("<invalid>")
            ));
        }
        if found.decimals != r.decimals {
            return Err(format!(
                "round-trip decimals mismatch for {}: wrote {} read {}",
                r.address, r.decimals, found.decimals
            ));
        }

        // Recompute the canonical leaf bytes the secure-world verifier
        // would reconstruct, then walk the proof attached to this row
        // up to the expected root.
        let canonical = canonical_erc20_leaf(
            r.chain_id,
            &contract,
            r.decimals,
            r.name.as_bytes(),
            r.symbol.as_bytes(),
        );
        let proof = parser
            .proof(r.chain_id, &contract)
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
    contract: [u8; 20],
    name: String,
    symbol: String,
    decimals: u8,
    flags: u8,
}

// === Host-side mirror of the runtime parser =================================
//
// This deliberately mirrors the structure that the non-secure runtime
// parser will use. Both consume the `db_format` constants from the
// shared crate.

struct HostErc20Db<'a> {
    blob: &'a [u8],
    entry_cnt: usize,
    pool_off: usize,
    proof_depth: usize,
    proofs_off: usize,
}

struct HostErc20Meta<'a> {
    name: &'a [u8],
    symbol: &'a [u8],
    decimals: u8,
    index: usize,
}

impl<'a> HostErc20Db<'a> {
    fn open(blob: &'a [u8]) -> Result<Self, String> {
        if blob.len() < ERC20_DB_HEADER_LEN {
            return Err("erc20 blob smaller than header".to_string());
        }
        if blob[..4] != ERC20_DB_MAGIC {
            return Err("erc20 blob bad magic".to_string());
        }
        let version = read_u32_le(blob, ERC20_HDR_OFF_VERSION);
        if version != ERC20_DB_VERSION {
            return Err(format!("erc20 blob version {} != {}", version, ERC20_DB_VERSION));
        }
        let entry_cnt = read_u32_le(blob, ERC20_HDR_OFF_ENTRY_CNT) as usize;
        let pool_off = read_u32_le(blob, ERC20_HDR_OFF_POOL_OFF) as usize;
        let expected_entries_end = ERC20_DB_HEADER_LEN + entry_cnt * ERC20_DB_ENTRY_LEN;
        if pool_off != expected_entries_end {
            return Err(format!(
                "erc20 pool_off {} != expected {}",
                pool_off, expected_entries_end
            ));
        }
        let proof_depth = read_u32_le(blob, ERC20_HDR_OFF_PROOF_DEPTH) as usize;
        let proofs_off = read_u32_le(blob, ERC20_HDR_OFF_PROOFS_OFF) as usize;
        if proofs_off + entry_cnt * proof_depth * 32 > blob.len() {
            return Err("erc20 proofs region out of bounds".to_string());
        }
        Ok(Self {
            blob,
            entry_cnt,
            pool_off,
            proof_depth,
            proofs_off,
        })
    }

    fn find_index(&self, chain_id: u64, contract: &[u8; 20]) -> Option<usize> {
        let mut lo = 0usize;
        let mut hi = self.entry_cnt;
        while lo < hi {
            let mid = (lo + hi) / 2;
            let off = ERC20_DB_HEADER_LEN + mid * ERC20_DB_ENTRY_LEN;
            let mid_chain = read_u64_le(self.blob, off + ERC20_ENTRY_OFF_CHAIN_ID);
            let mid_contract: [u8; 20] = self.blob
                [off + ERC20_ENTRY_OFF_CONTRACT..off + ERC20_ENTRY_OFF_CONTRACT + 20]
                .try_into()
                .unwrap();
            match (mid_chain, mid_contract).cmp(&(chain_id, *contract)) {
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
                std::cmp::Ordering::Equal => return Some(mid),
            }
        }
        None
    }

    fn lookup(&self, chain_id: u64, contract: &[u8; 20]) -> Option<HostErc20Meta<'a>> {
        let idx = self.find_index(chain_id, contract)?;
        let off = ERC20_DB_HEADER_LEN + idx * ERC20_DB_ENTRY_LEN;
        let name_off = read_u32_le(self.blob, off + ERC20_ENTRY_OFF_NAME_OFF) as usize;
        let symbol_off = read_u32_le(self.blob, off + ERC20_ENTRY_OFF_SYMBOL_OFF) as usize;
        let decimals = self.blob[off + ERC20_ENTRY_OFF_DECIMALS];
        let name = read_pool_string(self.blob, self.pool_off + name_off)?;
        let symbol = read_pool_string(self.blob, self.pool_off + symbol_off)?;
        Some(HostErc20Meta {
            name,
            symbol,
            decimals,
            index: idx,
        })
    }

    fn proof(&self, chain_id: u64, contract: &[u8; 20]) -> Option<Vec<[u8; 32]>> {
        let idx = self.find_index(chain_id, contract)?;
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

    fn fixture_addr(suffix: u8) -> String {
        format!("0x{}{:02x}", "0".repeat(38), suffix)
    }

    fn write_json(s: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(s.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    fn built_bundle(result: &Erc20BuildResult, chain_id: u64, contract: &[u8; 20]) -> Vec<u8> {
        let parser = HostErc20Db::open(&result.blob).expect("open built ERC20 DB");
        let metadata = parser
            .lookup(chain_id, contract)
            .expect("built row must be present");
        let proof = parser
            .proof(chain_id, contract)
            .expect("built row must have a proof");

        let mut bundle = canonical_erc20_leaf(
            chain_id,
            contract,
            metadata.decimals,
            metadata.name,
            metadata.symbol,
        );
        bundle.extend_from_slice(&(metadata.index as u32).to_le_bytes());
        bundle.extend_from_slice(&(proof.len() as u32).to_le_bytes());
        for sibling in proof {
            bundle.extend_from_slice(&sibling);
        }
        bundle
    }

    // === Positive ============================================================

    /// Canonical leaf encoding is a frozen wire format — its byte
    /// layout is mirrored in `secure/src/erc20/bundle.rs`. Any drift
    /// here changes every on-chain root for shipped firmware. Pin one
    /// exact preimage byte-by-byte.
    #[test]
    fn positive_canonical_erc20_leaf_byte_frozen() {
        let chain_id: u64 = 0x0102_0304_0506_0708;
        let contract: [u8; 20] = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
        ];
        let decimals = 18u8;
        let name = b"Tether USD";
        let symbol = b"USDT";
        let got = canonical_erc20_leaf(chain_id, &contract, decimals, name, symbol);
        let mut expected = Vec::new();
        // chain_id u64 LE
        expected.extend_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
        // contract 20 B
        expected.extend_from_slice(&contract);
        // decimals 1 B
        expected.push(18u8);
        // name_len 1 B + name
        expected.push(name.len() as u8);
        expected.extend_from_slice(name);
        // symbol_len 1 B + symbol
        expected.push(symbol.len() as u8);
        expected.extend_from_slice(symbol);
        assert_eq!(got, expected);
        assert_eq!(got.len(), 8 + 20 + 1 + 1 + name.len() + 1 + symbol.len());
    }

    #[test]
    fn positive_build_db_minimal_round_trip() {
        let json = r#"[
            {"chain_id": 1, "address": "0x1111111111111111111111111111111111111111",
             "name": "Token One", "symbol": "ONE", "decimals": 18}
        ]"#;
        let f = write_json(json);
        let res = build_db(f.path()).expect("build_db");
        assert_eq!(res.blob[..4], ERC20_DB_MAGIC);
        round_trip_check(&res.blob, f.path(), &res.root).expect("round-trip");
        // Single-entry tree => depth 0 => root == leaf hash.
        let canon = canonical_erc20_leaf(
            1,
            &[0x11; 20],
            18,
            b"Token One",
            b"ONE",
        );
        assert_eq!(res.root, crate::merkle::leaf_hash(&canon));
    }

    #[test]
    fn positive_build_db_sorts_and_interns_strings() {
        // Same name+symbol on two chains — interning must dedupe.
        let json = format!(
            r#"[
                {{"chain_id": 137, "address": "{}", "name": "USD Coin", "symbol": "USDC", "decimals": 6}},
                {{"chain_id": 1, "address": "{}", "name": "USD Coin", "symbol": "USDC", "decimals": 6}}
            ]"#,
            fixture_addr(0xa1),
            fixture_addr(0xa1),
        );
        let f = write_json(&json);
        let res = build_db(f.path()).expect("build_db");
        // 2 entries, but only 1 unique name string + 1 unique symbol string.
        let entry_cnt = u32::from_le_bytes(res.blob[12..16].try_into().unwrap());
        let pool_size = u32::from_le_bytes(res.blob[20..24].try_into().unwrap());
        assert_eq!(entry_cnt, 2);
        // Pool = [len][USD Coin] + [len][USDC] = 1+8 + 1+4 = 14
        assert_eq!(pool_size, 14);
        round_trip_check(&res.blob, f.path(), &res.root).expect("round-trip");
    }

    #[test]
    fn positive_build_db_accepts_address_without_0x() {
        let json = r#"[
            {"chain_id": 1, "address": "1111111111111111111111111111111111111111",
             "name": "N", "symbol": "S", "decimals": 0}
        ]"#;
        let f = write_json(json);
        build_db(f.path()).expect("build_db should accept bare hex");
    }

    #[test]
    fn positive_build_db_emits_correct_header_offsets() {
        let json = r#"[
            {"chain_id": 1, "address": "0x1111111111111111111111111111111111111111",
             "name": "A", "symbol": "B", "decimals": 0},
            {"chain_id": 1, "address": "0x2222222222222222222222222222222222222222",
             "name": "C", "symbol": "D", "decimals": 0}
        ]"#;
        let f = write_json(json);
        let res = build_db(f.path()).expect("build_db");
        let entry_cnt = u32::from_le_bytes(res.blob[12..16].try_into().unwrap()) as usize;
        let pool_off = u32::from_le_bytes(res.blob[16..20].try_into().unwrap()) as usize;
        let proof_depth = u32::from_le_bytes(res.blob[24..28].try_into().unwrap()) as usize;
        let proofs_off = u32::from_le_bytes(res.blob[28..32].try_into().unwrap()) as usize;
        assert_eq!(entry_cnt, 2);
        assert_eq!(pool_off, ERC20_DB_HEADER_LEN + entry_cnt * ERC20_DB_ENTRY_LEN);
        assert_eq!(proof_depth, 1); // log2(2)
        assert!(proofs_off > pool_off);
    }

    fn mixed_policy_cases() -> Vec<(u8, String, String, u8, bool)> {
        // The first two rows exercise every inclusive metadata boundary. The
        // remaining rows cross one gate at a time.
        vec![
            (0x01, " ".into(), "~".into(), 0, true),
            (0x02, "A".repeat(64), "Z".repeat(64), 36, true),
            (0x03, "Name".into(), "SYM".into(), 37, false),
            (0x04, String::new(), "SYM".into(), 18, false),
            (0x05, "Name".into(), String::new(), 18, false),
            (0x06, "A".repeat(65), "SYM".into(), 18, false),
            (0x07, "Name".into(), "S".repeat(65), 18, false),
            (0x08, "A\u{1f}".into(), "SYM".into(), 18, false),
            (0x09, "A\u{7f}".into(), "SYM".into(), 18, false),
            (0x0a, "Name".into(), "S\u{1f}".into(), 18, false),
            (0x0b, "Name".into(), "S\u{7f}".into(), 18, false),
            (0x0c, "Caf\u{e9}".into(), "SYM".into(), 18, false),
            (0x0d, "Name".into(), "USD\u{20ae}0".into(), 6, false),
        ]
    }

    fn case_json(cases: &[(u8, String, String, u8, bool)]) -> String {
        let rows: Vec<serde_json::Value> = cases
            .iter()
            .map(|(suffix, name, symbol, decimals, _)| {
                serde_json::json!({
                    "chain_id": 1,
                    "address": fixture_addr(*suffix),
                    "name": name,
                    "symbol": symbol,
                    "decimals": decimals,
                })
            })
            .collect();
        serde_json::to_string(&rows).expect("serialize fixture")
    }

    /// Every row the device verifier would refuse is a BUILD ERROR naming the
    /// row, never a silently Merkle-bound dead leaf (before 2026-11-14 such
    /// rows were built into the root and only withheld their capability).
    #[test]
    fn negative_build_db_rejects_every_row_failing_the_device_rule() {
        for case in mixed_policy_cases() {
            let (suffix, name, symbol, decimals, expected) = &case;
            assert_eq!(
                metadata_shape_is_device_verifiable(
                    *decimals,
                    name.as_bytes(),
                    symbol.as_bytes(),
                    0,
                ),
                *expected,
                "shared verifier predicate mismatch for suffix 0x{suffix:02x}",
            );
            if *expected {
                continue;
            }
            // Alone, and next to a valid row: either way the build fails.
            for input in [
                case_json(std::slice::from_ref(&case)),
                case_json(&[mixed_policy_cases()[0].clone(), case.clone()]),
            ] {
                let fixture = write_json(&input);
                let err = build_db(fixture.path())
                    .err()
                    .unwrap_or_else(|| panic!("suffix 0x{suffix:02x} must be rejected"));
                assert!(
                    err.contains("chain_id=1")
                        && err.contains(&fixture_addr(*suffix))
                        && err.contains("fails the device verifier"),
                    "error must name the row: {err}",
                );
            }
        }
    }

    #[test]
    fn negative_build_db_rejection_names_the_reason() {
        let expect = |suffix: u8, needle: &str| {
            let case = mixed_policy_cases()
                .into_iter()
                .find(|c| c.0 == suffix)
                .expect("case");
            let fixture = write_json(&case_json(&[case]));
            let err = build_db(fixture.path()).err().expect("must be rejected");
            assert!(err.contains(needle), "suffix 0x{suffix:02x}: {err}");
        };
        expect(0x03, "decimals 37 > 36");
        expect(0x04, "name is empty");
        expect(0x05, "symbol is empty");
        expect(0x06, "name too long");
        expect(0x07, "symbol too long");
        expect(0x08, "name is not printable ASCII");
        expect(0x0b, "symbol is not printable ASCII");
        expect(0x0c, "name is not printable ASCII");
        expect(0x0d, "symbol is not printable ASCII");
    }

    #[test]
    fn capabilities_are_every_row_of_a_device_verifiable_db() {
        let cases: Vec<_> = mixed_policy_cases().into_iter().filter(|c| c.4).collect();
        assert_eq!(cases.len(), 2);
        let fixture = write_json(&case_json(&cases));
        let result = build_db(fixture.path()).expect("build boundary DB");

        assert_eq!(result.entry_count, cases.len());
        assert_eq!(result.capabilities.len(), cases.len());
        round_trip_check(&result.blob, fixture.path(), &result.root).expect("round-trip");

        for (suffix, ..) in &cases {
            let contract = parse_hex_address(&fixture_addr(*suffix)).unwrap();
            assert!(result.capabilities.contains(1, &contract));
            // Non-vacuous cross-verifier control: every built row verifies on
            // the production parser.
            assert!(pqsigner_tx::erc20::bundle::verify_erc20_bundle(
                &built_bundle(&result, 1, &contract),
                &result.root,
            )
            .is_some());
        }
    }

    /// A row that fits the metadata rule but whose complete bundle would
    /// exceed the device bound at the DB's real proof depth is rejected by the
    /// second (post-tree) half of the gate. The reason helper names it.
    #[test]
    fn negative_device_rule_violation_names_bundle_bound() {
        let reason = device_rule_violation(36, &"A".repeat(28), &"B".repeat(30), 32)
            .expect("one byte over the bundle bound");
        assert!(
            reason.contains("exceeds the device bundle limit"),
            "{reason}"
        );
        let reason = device_rule_violation(0, "A", "B", 33).expect("proof too deep");
        assert!(reason.contains("proof depth 33"), "{reason}");
        assert!(device_rule_violation(36, &"A".repeat(28), &"~".repeat(29), 32).is_none());
    }

    #[test]
    fn capability_predicate_pins_proof_and_exact_wire_boundaries() {
        // 39 fixed bytes + 28-byte name + 29-byte symbol + 32*32 proof
        // bytes = exactly MAX_ERC20_BUNDLE_LEN (1120).
        assert!(metadata_shape_is_device_verifiable(
            36,
            &[b'A'; 28],
            &[b'~'; 29],
            32,
        ));
        // One additional individually-valid symbol byte exceeds the complete
        // production bundle budget.
        assert!(!metadata_shape_is_device_verifiable(
            36,
            &[b'A'; 28],
            &[b'B'; 30],
            32,
        ));
        assert!(!metadata_shape_is_device_verifiable(36, b"A", b"B", 33,));
    }

    // === Negative ============================================================

    /// build_db on an empty JSON array must reject — otherwise we'd
    /// ship a header claiming entry_cnt=0 with a root the secure-world
    /// would never produce for a real lookup.
    #[test]
    fn negative_build_db_empty_json_rejected() {
        let f = write_json("[]");
        let err = build_db(f.path()).err().expect("empty array must be rejected");
        assert!(err.contains("no entries"), "got: {err}");
    }

    /// Names beyond 255 bytes — the on-disk format encodes name_len as
    /// u8 (`buf.push(name.len() as u8)` would truncate silently and
    /// produce a leaf the secure-world cannot reconstruct).
    #[test]
    fn negative_build_db_name_too_long_rejected() {
        let huge = "x".repeat(256);
        let json = format!(
            r#"[{{"chain_id": 1, "address": "{}", "name": "{}", "symbol": "S", "decimals": 0}}]"#,
            fixture_addr(0x01),
            huge
        );
        let f = write_json(&json);
        let err = build_db(f.path()).err().expect("256-byte name must be rejected");
        assert!(err.contains("name too long"), "got: {err}");
    }

    #[test]
    fn negative_build_db_symbol_too_long_rejected() {
        let huge = "y".repeat(300);
        let json = format!(
            r#"[{{"chain_id": 1, "address": "{}", "name": "N", "symbol": "{}", "decimals": 0}}]"#,
            fixture_addr(0x01),
            huge
        );
        let f = write_json(&json);
        let err = build_db(f.path()).err().expect("oversize symbol must be rejected");
        assert!(err.contains("symbol too long"), "got: {err}");
    }

    /// Bad-hex address — invariant: every address is a parsed 20-byte
    /// blob. A `0x..` string of wrong length or non-hex chars must be
    /// rejected at build time so the on-chain leaf cannot drift.
    #[test]
    fn negative_build_db_bad_address_length_rejected() {
        let json = r#"[
            {"chain_id": 1, "address": "0xabcd", "name": "N", "symbol": "S", "decimals": 0}
        ]"#;
        let f = write_json(json);
        let err = build_db(f.path()).err().expect("short address must be rejected");
        assert!(err.contains("40 hex"), "got: {err}");
    }

    #[test]
    fn negative_build_db_non_hex_address_rejected() {
        let json = r#"[
            {"chain_id": 1, "address": "0xZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
             "name": "N", "symbol": "S", "decimals": 0}
        ]"#;
        let f = write_json(json);
        let err = build_db(f.path()).err().expect("non-hex address must be rejected");
        assert!(err.contains("hex decode") || err.contains("hex"), "got: {err}");
    }

    /// Duplicate `(chain_id, contract)` rows — almost always a typo
    /// and would let an attacker substitute the second entry's
    /// metadata at the first index. Curator gate.
    #[test]
    fn negative_build_db_duplicate_chain_contract_rejected() {
        let json = format!(
            r#"[
                {{"chain_id": 1, "address": "{}", "name": "A", "symbol": "AA", "decimals": 0}},
                {{"chain_id": 1, "address": "{}", "name": "B", "symbol": "BB", "decimals": 0}}
            ]"#,
            fixture_addr(0xaa),
            fixture_addr(0xaa),
        );
        let f = write_json(&json);
        let err = build_db(f.path()).err().expect("duplicate must be rejected");
        assert!(err.contains("duplicate"), "got: {err}");
    }

    /// Same contract on DIFFERENT chains may legitimately be DIFFERENT
    /// tokens (coincidental cross-chain address reuse — e.g. 0x50c5..0cb is
    /// DAI on Optimism but LYRA on Base). The DB is keyed by
    /// (chain_id, contract) and every leaf binds the chain_id, so this is
    /// unambiguous and safe. dbgen WARNS (for curator review) but MUST NOT
    /// reject — rejecting silently drops real tokens (Optimism DAI/COMP,
    /// L2 XRP/DOGE) from an exhaustive multichain DB.
    #[test]
    fn positive_build_db_same_contract_cross_chain_different_metadata_allowed() {
        let json = format!(
            r#"[
                {{"chain_id": 1, "address": "{}", "name": "USDC", "symbol": "USDC", "decimals": 6}},
                {{"chain_id": 137, "address": "{}", "name": "DAI", "symbol": "DAI", "decimals": 18}}
            ]"#,
            fixture_addr(0xbe),
            fixture_addr(0xbe),
        );
        let f = write_json(&json);
        let res = build_db(f.path()).expect(
            "same contract cross-chain with different metadata is allowed (chain-bound leaf)",
        );
        // Both entries must be present and Merkle-verifiable at their
        // respective (chain_id, contract) keys.
        round_trip_check(&res.blob, f.path(), &res.root)
            .expect("both cross-chain entries must round-trip");
    }

    /// A TRUE duplicate — same (chain_id, contract) twice — remains a hard
    /// error (genuine ambiguity at a single lookup key, unlike the
    /// cross-chain case above).
    #[test]
    fn negative_build_db_same_chain_same_contract_different_metadata_rejected() {
        let json = format!(
            r#"[
                {{"chain_id": 1, "address": "{}", "name": "USDC", "symbol": "USDC", "decimals": 6}},
                {{"chain_id": 1, "address": "{}", "name": "DAI", "symbol": "DAI", "decimals": 18}}
            ]"#,
            fixture_addr(0xbe),
            fixture_addr(0xbe),
        );
        let f = write_json(&json);
        let err = build_db(f.path())
            .err()
            .expect("same (chain, contract) duplicate must be rejected");
        assert!(err.contains("duplicate"), "got: {err}");
    }

    /// Tampered blob — if a single byte of the entries region flips,
    /// round_trip_check must fail. This is the same trust gate the
    /// runtime parser depends on.
    #[test]
    fn negative_round_trip_tampered_entry_decimals_rejected() {
        let json = format!(
            r#"[
                {{"chain_id": 1, "address": "{}", "name": "X", "symbol": "Y", "decimals": 18}}
            ]"#,
            fixture_addr(0x01),
        );
        let f = write_json(&json);
        let res = build_db(f.path()).expect("build_db");
        let mut tampered = res.blob.clone();
        let decimals_off = ERC20_DB_HEADER_LEN + ERC20_ENTRY_OFF_DECIMALS;
        tampered[decimals_off] = 6;
        let err = round_trip_check(&tampered, f.path(), &res.root)
            .err().expect("decimals tamper must fail round-trip");
        // decimals mismatch should surface as a "decimals mismatch" or
        // Merkle-proof failure depending on which check fires first.
        assert!(
            err.contains("decimals") || err.contains("Merkle"),
            "got: {err}",
        );
    }

    /// Substituted Merkle root — round_trip_check must reject when
    /// `expected_root` doesn't match the blob's reconstructed root.
    /// This is the trust-anchor gate; if it passes a bogus root, a
    /// future firmware build that loads the new root will accept a
    /// blob that doesn't match.
    #[test]
    fn negative_round_trip_wrong_root_rejected() {
        let json = format!(
            r#"[
                {{"chain_id": 1, "address": "{}", "name": "X", "symbol": "Y", "decimals": 18}},
                {{"chain_id": 2, "address": "{}", "name": "X", "symbol": "Y", "decimals": 18}}
            ]"#,
            fixture_addr(0x01),
            fixture_addr(0x02),
        );
        let f = write_json(&json);
        let res = build_db(f.path()).expect("build_db");
        let mut bogus_root = res.root;
        bogus_root[0] ^= 0x01;
        let err = round_trip_check(&res.blob, f.path(), &bogus_root)
            .err().expect("bogus root must fail round-trip");
        assert!(err.contains("Merkle"), "got: {err}");
    }

    /// Canonical leaf encoding length-prefix uses u8 — name + symbol
    /// must each be ≤ 255 bytes. The build_db caller checks that, but
    /// the canonical function itself silently truncates. Pin the
    /// length-prefix byte for a 255-byte name (boundary) to detect any
    /// change to the prefix width.
    #[test]
    fn negative_canonical_length_prefix_is_u8() {
        let name = vec![b'N'; 255];
        let symbol = b"S";
        let buf = canonical_erc20_leaf(1, &[0u8; 20], 0, &name, symbol);
        // Layout: 8 + 20 + 1 + 1(name_len) + 255 + 1(sym_len) + 1
        assert_eq!(buf[8 + 20 + 1], 255);
        // Symbol prefix is at 8+20+1+1+255 = 285
        assert_eq!(buf[8 + 20 + 1 + 1 + 255], 1);
    }

    /// Domain-separator coupling: the leaf binds (chain_id, contract,
    /// decimals, name, symbol). Shifting the LE-encoded chain_id
    /// boundary by changing any single field must change the hash.
    /// This proves there is no internal alignment gap an attacker can
    /// exploit to substitute one field for another.
    #[test]
    fn negative_canonical_fields_each_affect_hash() {
        let base = canonical_erc20_leaf(1, &[0u8; 20], 18, b"A", b"B");
        let h_base = crate::merkle::leaf_hash(&base);
        let cases: Vec<Vec<u8>> = vec![
            canonical_erc20_leaf(2, &[0u8; 20], 18, b"A", b"B"),
            canonical_erc20_leaf(1, &[1u8; 20], 18, b"A", b"B"),
            canonical_erc20_leaf(1, &[0u8; 20], 6, b"A", b"B"),
            canonical_erc20_leaf(1, &[0u8; 20], 18, b"B", b"B"),
            canonical_erc20_leaf(1, &[0u8; 20], 18, b"A", b"C"),
            canonical_erc20_leaf(1, &[0u8; 20], 18, b"AA", b"B"),
        ];
        for c in cases {
            assert_ne!(crate::merkle::leaf_hash(&c), h_base);
        }
    }
}
