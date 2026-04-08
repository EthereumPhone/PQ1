//! ERC20 metadata DB writer + round-trip checker.

use crate::merkle::{leaf_hash, verify_proof, MerkleTree};
use crate::{load_erc20_records, parse_hex_address, write_u32_le, write_u64_le};
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
    /// Poseidon-Merkle root over the same sorted entry set. Bound into
    /// the CowSwap EIP-712 v3 Groth16 circuit as a public input. Only
    /// entries with `symbol_len ≤ MAX_SYMBOL_LEN` (6) are included;
    /// longer-symbol tokens are absent from the Poseidon tree but still
    /// present in the SHA-256 tree for the ERC-20 transfer display path.
    pub poseidon_root: [u8; 32],
    /// The exported per-entry Poseidon Merkle proofs + root, as JSON,
    /// written verbatim to `circuits/generated/erc20_poseidon_tree.json`
    /// for consumption by the host-side witness generator.
    pub poseidon_tree_json: String,
}

pub fn build_db(json_path: &Path) -> Result<Erc20BuildResult, String> {
    let records = load_erc20_records(json_path)?;
    if records.is_empty() {
        return Err("erc20.json contains no entries".to_string());
    }

    // 1. Validate every row, parse addresses, build sortable records.
    let mut prepared: Vec<PreparedRow> = Vec::with_capacity(records.len());
    for r in &records {
        if r.name.len() > 255 {
            return Err(format!("name too long (>255 bytes): {:?}", r.name));
        }
        if r.symbol.len() > 255 {
            return Err(format!("symbol too long (>255 bytes): {:?}", r.symbol));
        }
        let contract = parse_hex_address(&r.address)?;
        prepared.push(PreparedRow {
            chain_id: r.chain_id,
            contract,
            name: r.name.clone(),
            symbol: r.symbol.clone(),
            decimals: r.decimals,
            flags: r.flags,
        });
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

    // 4. Reject the same contract on multiple chains pointing to different
    //    name/symbol — almost always a copy-paste typo. The same contract
    //    on multiple chains with the same name+symbol is fine and dedups
    //    via interning.
    {
        let mut by_contract: HashMap<[u8; 20], (&str, &str)> = HashMap::new();
        for r in &prepared {
            if let Some((name, symbol)) = by_contract.get(&r.contract) {
                if *name != r.name || *symbol != r.symbol {
                    return Err(format!(
                        "contract 0x{} appears on multiple chains with different metadata \
                         (`{} ({})` vs `{} ({})`) — likely a copy-paste error",
                        hex::encode(r.contract),
                        name,
                        symbol,
                        r.name,
                        r.symbol
                    ));
                }
            } else {
                by_contract.insert(r.contract, (&r.name, &r.symbol));
            }
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
            let canonical =
                canonical_erc20_leaf(r.chain_id, &r.contract, r.decimals, r.name.as_bytes(), r.symbol.as_bytes());
            leaf_hash(&canonical)
        })
        .collect();
    let tree = MerkleTree::build(leaf_hashes.clone());
    let root = tree.root();
    let proof_depth = tree.depth();

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

    // 8. Build the parallel Poseidon-Merkle tree over the same sorted
    //    entry set. Entries whose symbol is longer than
    //    `erc20_poseidon::MAX_SYMBOL_LEN` are excluded from the
    //    Poseidon tree (they stay in the SHA-256 tree and remain
    //    usable for the ERC-20 transfer display path, just not for
    //    CowSwap EIP-712 v3 clear-signing). The filter keeps the
    //    Poseidon tree's (chain_id, address) → leaf_idx mapping
    //    predictable for the witness generator.
    let (poseidon_root, poseidon_tree_json) = build_poseidon_side(&prepared)?;

    Ok(Erc20BuildResult {
        blob,
        root,
        poseidon_root,
        poseidon_tree_json,
    })
}

/// Build the parallel Poseidon-Merkle tree + export artifact.
///
/// Returns `(root_le_bytes, tree_json_string)`. The root is the
/// 32-byte little-endian canonical encoding of the top-level Poseidon
/// field element. The JSON string has the shape
/// `{ root, depth, entries: [{ chain_id, address, symbol, decimals,
/// leaf_idx, leaf, proof: [..] }] }` with all field elements rendered
/// as decimal bigint strings (what snarkjs's `input.json` expects).
fn build_poseidon_side(prepared: &[PreparedRow]) -> Result<([u8; 32], String), String> {
    use crate::erc20_poseidon::{
        canonical_erc20_poseidon_leaf, leaf_hash, scalar_to_dec, scalar_to_le32, ExportedEntry,
        ExportedTree, PoseidonMerkleTree, MAX_SYMBOL_LEN,
    };

    // Filter to entries whose symbol fits the circuit's fixed-width
    // leaf encoding. Anything longer gets dropped from the Poseidon
    // tree (and therefore can't be clear-signed via CowSwap EIP-712 v3).
    // The SHA-256 side still has them.
    let filtered: Vec<(usize, &PreparedRow)> = prepared
        .iter()
        .enumerate()
        .filter(|(_, r)| r.symbol.len() <= MAX_SYMBOL_LEN)
        .collect();

    if filtered.is_empty() {
        return Err("Poseidon tree build: no eligible ERC20 entries".to_string());
    }

    // Compute the 6-field leaf for every eligible row, then its
    // Poseidon leaf hash.
    let mut leaf_hashes: Vec<bls12_381::Scalar> = Vec::with_capacity(filtered.len());
    let mut leaves_fields: Vec<[bls12_381::Scalar; 6]> = Vec::with_capacity(filtered.len());
    for (_orig_idx, row) in filtered.iter() {
        let fields = canonical_erc20_poseidon_leaf(
            row.chain_id,
            &row.contract,
            row.decimals,
            row.symbol.as_bytes(),
        )?;
        leaf_hashes.push(leaf_hash(&fields));
        leaves_fields.push(fields);
    }

    // Build the tree.
    let tree = PoseidonMerkleTree::build(leaf_hashes.clone());
    let root_scalar = tree.root();
    let depth = tree.depth();

    // Host-side round-trip sanity check: every pre-padding leaf
    // should verify against the root via its proof.
    for (i, leaf) in leaf_hashes.iter().enumerate() {
        let proof = tree.proof(i);
        if !crate::erc20_poseidon::verify_proof(leaf, i, &proof, &root_scalar) {
            return Err(format!(
                "Poseidon tree round-trip failed for leaf {} (row {}, symbol {:?})",
                i,
                filtered[i].0,
                filtered[i].1.symbol,
            ));
        }
    }

    // Export entries for the witness generator.
    let mut entries: Vec<ExportedEntry> = Vec::with_capacity(filtered.len());
    for (leaf_idx, (_orig_idx, row)) in filtered.iter().enumerate() {
        let proof = tree.proof(leaf_idx);
        let proof_dec: Vec<String> = proof.iter().map(scalar_to_dec).collect();
        entries.push(ExportedEntry {
            chain_id: row.chain_id,
            address: hex::encode(row.contract),
            symbol: row.symbol.clone(),
            decimals: row.decimals,
            leaf_idx,
            leaf: scalar_to_dec(&leaf_hashes[leaf_idx]),
            proof: proof_dec,
        });
    }
    let _ = leaves_fields; // fields kept for symmetry; not serialized (circuit rebuilds them)

    let exported = ExportedTree {
        root: scalar_to_dec(&root_scalar),
        depth,
        entries,
    };

    let json = serde_json::to_string_pretty(&exported)
        .map_err(|e| format!("serialize erc20_poseidon_tree.json: {e}"))?;

    Ok((scalar_to_le32(&root_scalar), json))
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
