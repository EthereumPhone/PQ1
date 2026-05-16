// Each integration-test file uses a subset of these helpers; the
// per-target `dead_code` warning that results from sharing the module
// is not actionable. Allow it at the module level (not on individual
// tests).
#![allow(dead_code)]

//! Shared Merkle helpers for the integration-test suites.
//!
//! These mirror the on-disk DB layout pinned in
//! `dbgen::{erc20,names,selectors}::canonical_*_leaf` — leaf hash is
//! `sha256(0x00 || canonical)`, internal node is `sha256(0x01 || L || R)`,
//! padding duplicates the last leaf to the next power-of-two. The
//! production verifier (`tx::erc20::merkle::verify_proof`) walks this
//! exact scheme; if the helper drifts, the round-trip tests fail loudly.

use sha2::{Digest, Sha256};

pub fn leaf_hash(canonical: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00u8]);
    h.update(canonical);
    let out = h.finalize();
    let mut a = [0u8; 32];
    a.copy_from_slice(&out);
    a
}

pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01u8]);
    h.update(left);
    h.update(right);
    let out = h.finalize();
    let mut a = [0u8; 32];
    a.copy_from_slice(&out);
    a
}

/// Build a Merkle tree over `leaves` (padding to power-of-two by
/// duplicating the last leaf). Returns `(root, per-leaf-proofs)` where
/// each proof is a flat `[u8; 32]` sibling chain from bottom to top.
pub fn build_tree(mut leaves: Vec<[u8; 32]>) -> ([u8; 32], Vec<Vec<[u8; 32]>>) {
    assert!(!leaves.is_empty(), "tree must have ≥1 leaf");
    let n = leaves.len();
    let target = n.next_power_of_two();
    while leaves.len() < target {
        let last = *leaves.last().unwrap();
        leaves.push(last);
    }
    let mut levels = vec![leaves];
    while levels.last().unwrap().len() > 1 {
        let cur = levels.last().unwrap();
        let mut next = Vec::with_capacity(cur.len() / 2);
        for p in cur.chunks(2) {
            next.push(node_hash(&p[0], &p[1]));
        }
        levels.push(next);
    }
    let root = levels.last().unwrap()[0];
    let depth = levels.len() - 1;

    let mut proofs = Vec::with_capacity(n);
    for i in 0..n {
        let mut idx = i;
        let mut p = Vec::with_capacity(depth);
        for level in &levels[..depth] {
            let sib = idx ^ 1;
            p.push(level[sib]);
            idx >>= 1;
        }
        proofs.push(p);
    }
    (root, proofs)
}

pub fn flatten_proof(proof: &[[u8; 32]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(proof.len() * 32);
    for s in proof {
        out.extend_from_slice(s);
    }
    out
}

// ─── Canonical encoders — MUST match dbgen byte-for-byte ─────────────

pub fn canonical_erc20(
    chain_id: u64,
    contract: &[u8; 20],
    decimals: u8,
    name: &[u8],
    symbol: &[u8],
) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&chain_id.to_le_bytes());
    v.extend_from_slice(contract);
    v.push(decimals);
    v.push(name.len() as u8);
    v.extend_from_slice(name);
    v.push(symbol.len() as u8);
    v.extend_from_slice(symbol);
    v
}

pub fn canonical_name(chain_id: u64, address: &[u8; 20], name: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&chain_id.to_le_bytes());
    v.extend_from_slice(address);
    v.push(name.len() as u8);
    v.extend_from_slice(name);
    v
}

// ─── Bundle builders ─────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub fn build_erc20_bundle(
    chain_id: u64,
    contract: &[u8; 20],
    decimals: u8,
    name: &[u8],
    symbol: &[u8],
    leaf_index: u32,
    proof_depth: u32,
    proof: &[[u8; 32]],
) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&chain_id.to_le_bytes());
    b.extend_from_slice(contract);
    b.push(decimals);
    b.push(name.len() as u8);
    b.extend_from_slice(name);
    b.push(symbol.len() as u8);
    b.extend_from_slice(symbol);
    b.extend_from_slice(&leaf_index.to_le_bytes());
    b.extend_from_slice(&proof_depth.to_le_bytes());
    b.extend_from_slice(&flatten_proof(proof));
    b
}

#[allow(clippy::too_many_arguments)]
pub fn build_name_bundle(
    chain_id: u64,
    address: &[u8; 20],
    name: &[u8],
    leaf_index: u32,
    proof_depth: u32,
    proof: &[[u8; 32]],
) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&chain_id.to_le_bytes());
    b.extend_from_slice(address);
    b.push(name.len() as u8);
    b.extend_from_slice(name);
    b.extend_from_slice(&leaf_index.to_le_bytes());
    b.extend_from_slice(&proof_depth.to_le_bytes());
    b.extend_from_slice(&flatten_proof(proof));
    b
}

/// Standard address-word ABI encoding: 12 zero bytes + 20-byte address.
pub fn pad_address(addr: &[u8; 20]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(addr);
    out
}

/// Big-endian 32-byte word of `value`.
pub fn u256_word(value: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..].copy_from_slice(&value.to_be_bytes());
    out
}
