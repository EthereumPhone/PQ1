//! ZK clear-signing VK DB writer + round-trip checker.
//!
//! Reads `secure/data/vks.json` (the manifest) and the binary VK files
//! it points at, dedups by `sha256(vk_bytes)`, sorts (chain_id, contract)
//! mappings, and emits `secure/src/zk/vk_db.bin` plus a human-readable
//! `secure/data/vks.review.txt` for the firmware-signing reviewer.
//!
//! The release-review manifest is a pure build-traceability artifact:
//! it records which (chain_id, contract, sha256(vk)) triples were
//! folded into the VK_DB_ROOT for a given release, so a human reviewer
//! can diff successive releases and notice unexpected additions. There
//! is NO on-chain comparison anywhere — the trust chain is entirely
//! offline (firmware-signing key → VK_DB_ROOT → Merkle → Groth16).

use crate::merkle::{leaf_hash, verify_proof, MerkleTree};
use crate::{load_vk_protocols, parse_hex_address, sha256, write_u32_le, write_u64_le};
use sphincs_tz_shared::db_format::*;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Build the canonical leaf-hash input bytes for one VK entry. MUST
/// match the secure-world verifier's reconstruction byte-for-byte.
///
/// `vk` is always exactly `VK_BLOB_LEN` bytes (1056 B) — VKs shorter
/// than that are zero-padded on the right by the caller so the leaf
/// hash binds the padding too. Dispatch by protocol sentinel decides
/// how much of the slot is "real": 960 B for 2-pub, 1056 B for 3-pub.
pub fn canonical_vk_leaf(chain_id: u64, contract: &[u8; 20], vk: &[u8; VK_BLOB_LEN]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + 20 + VK_BLOB_LEN);
    buf.extend_from_slice(&chain_id.to_le_bytes());
    buf.extend_from_slice(contract);
    buf.extend_from_slice(vk);
    buf
}

pub struct VkBuildResult {
    pub blob: Vec<u8>,
    pub root: [u8; 32],
    pub review_text: String,
}

pub fn build_db(json_path: &Path, vks_dir: &Path) -> Result<VkBuildResult, String> {
    let protocols = load_vk_protocols(json_path)?;
    if protocols.is_empty() {
        return Err("vks.json contains no protocols".to_string());
    }

    // 1. Load each protocol's VK file. Dedup by sha256(vk_bytes); each
    //    unique VK gets a vk_id (u8). Build the per-deployment entry list.
    let mut unique_vks: Vec<[u8; VK_BLOB_LEN]> = Vec::new();
    let mut sha_to_id: HashMap<[u8; 32], u8> = HashMap::new();
    let mut entries: Vec<PreparedVkEntry> = Vec::new();
    let mut review_protocols: Vec<ReviewProtocol> = Vec::new();

    for proto in &protocols {
        let vk_path = vks_dir.join(&proto.vk_file);
        let vk_bytes = fs::read(&vk_path)
            .map_err(|e| format!("read {}: {e}", vk_path.display()))?;
        // A VK file can be either a 2-public-signal blob (960 B) or a
        // 3-public-signal blob (1056 B = VK_BLOB_LEN). Anything else is
        // malformed. Shorter blobs are zero-padded on the right into
        // the fixed-stride pool slot, and the trailing zeros are bound
        // into the leaf hash.
        if vk_bytes.len() != VK_BLOB_LEN_2PUB && vk_bytes.len() != VK_BLOB_LEN_3PUB {
            return Err(format!(
                "VK file {} is {} bytes, expected {} or {}",
                vk_path.display(),
                vk_bytes.len(),
                VK_BLOB_LEN_2PUB,
                VK_BLOB_LEN_3PUB,
            ));
        }
        let mut vk_arr = [0u8; VK_BLOB_LEN];
        vk_arr[..vk_bytes.len()].copy_from_slice(&vk_bytes);
        let vk_sha = sha256(&vk_arr);

        let vk_id = if let Some(id) = sha_to_id.get(&vk_sha) {
            *id
        } else {
            let id = unique_vks.len();
            if id > u8::MAX as usize {
                return Err("more than 256 unique VKs (vk_id u8 overflow)".to_string());
            }
            unique_vks.push(vk_arr);
            sha_to_id.insert(vk_sha, id as u8);
            id as u8
        };

        let mut review_entry = ReviewProtocol {
            protocol: proto.protocol.clone(),
            vk_sha_hex: hex::encode(vk_sha),
            deployments: Vec::new(),
        };

        for dep in &proto.deployments {
            let contract = parse_hex_address(&dep.address)?;
            entries.push(PreparedVkEntry {
                chain_id: dep.chain_id,
                contract,
                vk_id,
                vk_sha_pfx: [vk_sha[0], vk_sha[1], vk_sha[2]],
            });
            review_entry.deployments.push(ReviewDeployment {
                chain_id: dep.chain_id,
                address: dep.address.clone(),
                label: dep.label.clone(),
            });
        }

        review_protocols.push(review_entry);
    }

    // 2. Sort entries by (chain_id, contract) for runtime binary search.
    entries.sort_by(|a, b| {
        a.chain_id
            .cmp(&b.chain_id)
            .then_with(|| a.contract.cmp(&b.contract))
    });

    // 3. Reject duplicate (chain_id, contract) keys.
    for w in entries.windows(2) {
        if w[0].chain_id == w[1].chain_id && w[0].contract == w[1].contract {
            return Err(format!(
                "duplicate VK entry (chain_id, contract): chain_id={} contract=0x{}",
                w[0].chain_id,
                hex::encode(w[0].contract)
            ));
        }
    }

    // 4. Compute Merkle leaf hashes from canonical encodings, then
    //    build the tree. Each leaf binds (chain_id, contract, vk_bytes)
    //    so the secure verifier can reject any forged
    //    (contract, vk) substitution.
    let leaf_hashes: Vec<[u8; 32]> = entries
        .iter()
        .map(|e| {
            let vk = &unique_vks[e.vk_id as usize];
            let canonical = canonical_vk_leaf(e.chain_id, &e.contract, vk);
            leaf_hash(&canonical)
        })
        .collect();
    let tree = MerkleTree::build(leaf_hashes.clone());
    let root = tree.root();
    let proof_depth = tree.depth();

    // 5. Lay out the binary blob:
    //    header | entries | vk_pool | proofs
    let entry_cnt = entries.len();
    let vk_count = unique_vks.len();
    let entries_size = entry_cnt * VK_DB_ENTRY_LEN;
    let vk_pool_off = VK_DB_HEADER_LEN + entries_size;
    let proofs_off = vk_pool_off + vk_count * VK_BLOB_LEN;
    let proofs_size = entry_cnt * proof_depth * 32;
    let total_size = proofs_off + proofs_size;

    let mut blob: Vec<u8> = Vec::with_capacity(total_size);

    // --- Header (32 B) ---
    blob.extend_from_slice(&VK_DB_MAGIC);
    write_u32_le(&mut blob, VK_DB_VERSION);
    write_u32_le(&mut blob, 0); // flags reserved
    write_u32_le(
        &mut blob,
        entry_cnt
            .try_into()
            .map_err(|_| "entry_cnt > u32::MAX".to_string())?,
    );
    write_u32_le(
        &mut blob,
        vk_count
            .try_into()
            .map_err(|_| "vk_count > u32::MAX".to_string())?,
    );
    write_u32_le(
        &mut blob,
        vk_pool_off
            .try_into()
            .map_err(|_| "vk_pool_off > u32::MAX".to_string())?,
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

    assert_eq!(blob.len(), VK_DB_HEADER_LEN);

    // --- Entries (32 B each) ---
    for e in &entries {
        let start = blob.len();
        write_u64_le(&mut blob, e.chain_id);
        blob.extend_from_slice(&e.contract);
        blob.push(e.vk_id);
        blob.extend_from_slice(&e.vk_sha_pfx);
        debug_assert_eq!(blob.len() - start, VK_DB_ENTRY_LEN);
    }

    assert_eq!(blob.len(), vk_pool_off);

    // --- VK pool ---
    for vk in &unique_vks {
        blob.extend_from_slice(vk);
    }

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

    // --- Review manifest ---
    let review_text = render_review(&review_protocols, &root);

    Ok(VkBuildResult {
        blob,
        root,
        review_text,
    })
}

pub fn round_trip_check(
    blob: &[u8],
    json_path: &Path,
    vks_dir: &Path,
    expected_root: &[u8; 32],
) -> Result<(), String> {
    let protocols = load_vk_protocols(json_path)?;
    let parser = HostVkDb::open(blob)?;

    for proto in &protocols {
        let vk_path = vks_dir.join(&proto.vk_file);
        let vk_bytes = fs::read(&vk_path)
            .map_err(|e| format!("read {}: {e}", vk_path.display()))?;
        if vk_bytes.len() != VK_BLOB_LEN_2PUB && vk_bytes.len() != VK_BLOB_LEN_3PUB {
            return Err(format!(
                "VK file {} bad size ({} B, expected {} or {})",
                vk_path.display(),
                vk_bytes.len(),
                VK_BLOB_LEN_2PUB,
                VK_BLOB_LEN_3PUB,
            ));
        }
        let mut vk_arr = [0u8; VK_BLOB_LEN];
        vk_arr[..vk_bytes.len()].copy_from_slice(&vk_bytes);

        for dep in &proto.deployments {
            let contract = parse_hex_address(&dep.address)?;
            let found = parser.lookup_vk(dep.chain_id, &contract).ok_or_else(|| {
                format!(
                    "round-trip: missing VK for chain={} addr={}",
                    dep.chain_id, dep.address
                )
            })?;
            if found.vk != vk_arr.as_slice() {
                return Err(format!(
                    "round-trip: VK byte mismatch for chain={} addr={}",
                    dep.chain_id, dep.address
                ));
            }

            let canonical = canonical_vk_leaf(dep.chain_id, &contract, &vk_arr);
            let proof = parser.proof(dep.chain_id, &contract).ok_or_else(|| {
                format!("round-trip: missing VK proof for {}", dep.address)
            })?;
            if !verify_proof(&canonical, found.index, &proof, expected_root) {
                return Err(format!(
                    "round-trip: VK Merkle proof failed for chain={} addr={}",
                    dep.chain_id, dep.address
                ));
            }
        }
    }

    Ok(())
}

fn render_review(protocols: &[ReviewProtocol], root: &[u8; 32]) -> String {
    let mut s = String::new();
    s.push_str("=== ZK Clear-Signing VK Manifest (firmware build artifact) ===\n");
    s.push_str("Built from secure/data/vks.json by `cargo run -p dbgen`.\n");
    s.push_str("\n");
    s.push_str("The wallet's secure world holds only the Merkle ROOT below; the\n");
    s.push_str("full VK pool lives in non-secure firmware rodata. At sign time the\n");
    s.push_str("non-secure world supplies (vk_bytes, merkle_proof) and the secure\n");
    s.push_str("world re-derives the leaf hash from (chain_id, contract, vk_bytes)\n");
    s.push_str("and walks the proof up to this root.\n");
    s.push_str("\n");
    s.push_str(&format!("Merkle root (VK_DB_ROOT) = {}\n", hex::encode(root)));
    s.push_str("\n");
    s.push_str("This file is a build-traceability artifact. It records which\n");
    s.push_str("(chain_id, contract, sha256(vk)) triples were folded into the\n");
    s.push_str("VK_DB_ROOT above, so a release reviewer can diff it against the\n");
    s.push_str("previous release and confirm nothing unexpected was added.\n");
    s.push_str("The trust chain is entirely offline: firmware-signing key →\n");
    s.push_str("VK_DB_ROOT in secure flash → Merkle proof → Groth16 verification.\n");
    s.push_str("No on-chain comparison is performed, ever.\n");
    s.push_str("\n");
    for p in protocols {
        s.push_str(&format!("{}\n", p.protocol));
        s.push_str(&format!("  sha256(vk) = {}\n", p.vk_sha_hex));
        for d in &p.deployments {
            let label = if d.label.is_empty() {
                String::new()
            } else {
                format!(" ({})", d.label)
            };
            s.push_str(&format!(
                "  chain {:>6}, contract {}{}\n",
                d.chain_id, d.address, label
            ));
        }
        s.push_str("\n");
    }
    s
}

#[derive(Debug)]
struct PreparedVkEntry {
    chain_id: u64,
    contract: [u8; 20],
    vk_id: u8,
    vk_sha_pfx: [u8; 3],
}

#[derive(Debug)]
struct ReviewProtocol {
    protocol: String,
    vk_sha_hex: String,
    deployments: Vec<ReviewDeployment>,
}

#[derive(Debug)]
struct ReviewDeployment {
    chain_id: u64,
    address: String,
    label: String,
}

// === Host-side mirror of the runtime VK parser ===============================

struct HostVkDb<'a> {
    blob: &'a [u8],
    entry_cnt: usize,
    vk_pool_off: usize,
    proof_depth: usize,
    proofs_off: usize,
}

struct HostVkLookup<'a> {
    vk: &'a [u8],
    index: usize,
}

impl<'a> HostVkDb<'a> {
    fn open(blob: &'a [u8]) -> Result<Self, String> {
        if blob.len() < VK_DB_HEADER_LEN {
            return Err("vk blob smaller than header".to_string());
        }
        if blob[..4] != VK_DB_MAGIC {
            return Err("vk blob bad magic".to_string());
        }
        let version = read_u32_le(blob, VK_HDR_OFF_VERSION);
        if version != VK_DB_VERSION {
            return Err(format!("vk blob version {} != {}", version, VK_DB_VERSION));
        }
        let entry_cnt = read_u32_le(blob, VK_HDR_OFF_ENTRY_CNT) as usize;
        let vk_pool_off = read_u32_le(blob, VK_HDR_OFF_VK_POOL_OFF) as usize;
        let expected_entries_end = VK_DB_HEADER_LEN + entry_cnt * VK_DB_ENTRY_LEN;
        if vk_pool_off != expected_entries_end {
            return Err(format!(
                "vk vk_pool_off {} != expected {}",
                vk_pool_off, expected_entries_end
            ));
        }
        let proof_depth = read_u32_le(blob, VK_HDR_OFF_PROOF_DEPTH) as usize;
        let proofs_off = read_u32_le(blob, VK_HDR_OFF_PROOFS_OFF) as usize;
        if proofs_off + entry_cnt * proof_depth * 32 > blob.len() {
            return Err("vk proofs region out of bounds".to_string());
        }
        Ok(Self {
            blob,
            entry_cnt,
            vk_pool_off,
            proof_depth,
            proofs_off,
        })
    }

    fn find_index(&self, chain_id: u64, contract: &[u8; 20]) -> Option<usize> {
        let mut lo = 0usize;
        let mut hi = self.entry_cnt;
        while lo < hi {
            let mid = (lo + hi) / 2;
            let off = VK_DB_HEADER_LEN + mid * VK_DB_ENTRY_LEN;
            let mid_chain = read_u64_le(self.blob, off + VK_ENTRY_OFF_CHAIN_ID);
            let mid_contract: [u8; 20] = self.blob
                [off + VK_ENTRY_OFF_CONTRACT..off + VK_ENTRY_OFF_CONTRACT + 20]
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

    fn lookup_vk(&self, chain_id: u64, contract: &[u8; 20]) -> Option<HostVkLookup<'a>> {
        let idx = self.find_index(chain_id, contract)?;
        let off = VK_DB_HEADER_LEN + idx * VK_DB_ENTRY_LEN;
        let vk_id = self.blob[off + VK_ENTRY_OFF_VK_ID] as usize;
        let vk_off = self.vk_pool_off + vk_id * VK_BLOB_LEN;
        Some(HostVkLookup {
            vk: &self.blob[vk_off..vk_off + VK_BLOB_LEN],
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
