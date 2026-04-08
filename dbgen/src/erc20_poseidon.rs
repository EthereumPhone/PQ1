//! Parallel Poseidon-Merkle tree over the same ERC20 metadata entries
//! that `erc20.rs` already indexes via SHA-256.
//!
//! Why two trees: the secure-world ERC-20 transfer display path (used by
//! `cmd_sign`) already trusts the SHA-256 tree rooted at
//! `secure/src/db_roots.rs::ERC20_DB_ROOT`. The CowSwap EIP-712 v3 Groth16
//! circuit cannot efficiently verify SHA-256, so we build a second tree
//! with Poseidon hashes over the same sorted `(chain_id, contract)`
//! entry set and bake its root at `ERC20_POSEIDON_ROOT` alongside the
//! existing SHA-256 root. Both roots are signed by the firmware image so
//! they inherit the same trust anchor.
//!
//! Leaf encoding (6 field elements, fed to `Poseidon255(6)`):
//!
//!   f0 = chain_id               (u64, up to 64 bits)
//!   f1 = address                (20 bytes packed big-endian into u160)
//!   f2 = decimals               (u8)
//!   f3 = symbol_packed          (up to 6 ASCII chars packed big-endian)
//!   f4 = symbol_len             (u8)
//!   f5 = 0                      (reserved)
//!
//! Internal nodes: `Poseidon255(2)(left, right)`.
//!
//! The tree is padded to the next power of two by duplicating the last
//! real leaf hash (Bitcoin-style). This matches the existing SHA-256
//! Merkle tree shape (`dbgen/src/merkle.rs`) so we can reuse the same
//! leaf-index convention everywhere.

use crate::poseidon::poseidon_fields;
use bls12_381::Scalar;
use serde::Serialize;

/// Symbols longer than this can't be packed into a single field element,
/// so they're rejected when building the Poseidon tree. Tokens with
/// longer symbols remain in the SHA-256 path but can't be clear-signed
/// via the CowSwap EIP-712 circuit. Matches `SYMBOL_LEN` in the circuit.
pub const MAX_SYMBOL_LEN: usize = 6;

/// Build the 6-element leaf for a single ERC20 entry. Must match the
/// circuit-side `MerkleErc20Registry` leaf layout byte-for-byte.
pub fn canonical_erc20_poseidon_leaf(
    chain_id: u64,
    contract: &[u8; 20],
    decimals: u8,
    symbol: &[u8],
) -> Result<[Scalar; 6], String> {
    if symbol.is_empty() || symbol.len() > MAX_SYMBOL_LEN {
        return Err(format!(
            "poseidon leaf: symbol_len {} not in 1..={}",
            symbol.len(),
            MAX_SYMBOL_LEN
        ));
    }
    for (i, &b) in symbol.iter().enumerate() {
        if !(0x20..0x7f).contains(&b) {
            return Err(format!("poseidon leaf: symbol byte {} not printable ASCII", i));
        }
    }

    // f0: chain_id as a small scalar.
    let f0 = Scalar::from(chain_id);

    // f1: address packed big-endian into a 160-bit field element.
    let mut addr_acc = Scalar::zero();
    let s256 = Scalar::from(256u64);
    for &b in contract.iter() {
        addr_acc = addr_acc * s256 + Scalar::from(b as u64);
    }
    let f1 = addr_acc;

    // f2: decimals.
    let f2 = Scalar::from(decimals as u64);

    // f3: symbol packed big-endian, right-padded with 0x20 (ASCII space)
    // to MAX_SYMBOL_LEN. Matches the circuit's symbol witness layout.
    let mut sym_acc = Scalar::zero();
    for i in 0..MAX_SYMBOL_LEN {
        let b = if i < symbol.len() { symbol[i] } else { 0x20 };
        sym_acc = sym_acc * s256 + Scalar::from(b as u64);
    }
    let f3 = sym_acc;

    // f4: actual symbol length.
    let f4 = Scalar::from(symbol.len() as u64);

    // f5: reserved.
    let f5 = Scalar::zero();

    Ok([f0, f1, f2, f3, f4, f5])
}

/// Hash one leaf to its field-element Merkle leaf node.
pub fn leaf_hash(leaf: &[Scalar; 6]) -> Scalar {
    poseidon_fields(leaf)
}

/// Combine two child node hashes into their parent.
pub fn node_hash(left: &Scalar, right: &Scalar) -> Scalar {
    poseidon_fields(&[*left, *right])
}

/// All levels of the Poseidon Merkle tree, bottom-up.
pub struct PoseidonMerkleTree {
    pub levels: Vec<Vec<Scalar>>,
}

impl PoseidonMerkleTree {
    /// Build a Poseidon Merkle tree from a list of leaf hashes. Padded
    /// to the next power of two by duplicating the last element.
    pub fn build(mut leaves: Vec<Scalar>) -> Self {
        assert!(!leaves.is_empty(), "Poseidon Merkle tree needs ≥1 leaf");
        let target = leaves.len().next_power_of_two();
        while leaves.len() < target {
            let last = *leaves.last().unwrap();
            leaves.push(last);
        }

        let mut levels = vec![leaves];
        while levels.last().unwrap().len() > 1 {
            let cur = levels.last().unwrap();
            let mut next = Vec::with_capacity(cur.len() / 2);
            for pair in cur.chunks(2) {
                next.push(node_hash(&pair[0], &pair[1]));
            }
            levels.push(next);
        }

        Self { levels }
    }

    pub fn root(&self) -> Scalar {
        self.levels.last().unwrap()[0]
    }

    pub fn depth(&self) -> usize {
        self.levels.len() - 1
    }

    /// Build the inclusion proof for the leaf at the given index.
    /// Returns `depth` sibling hashes, leaf-up.
    pub fn proof(&self, mut index: usize) -> Vec<Scalar> {
        let mut out = Vec::with_capacity(self.depth());
        for level in &self.levels[..self.depth()] {
            let sib_idx = index ^ 1;
            out.push(level[sib_idx]);
            index >>= 1;
        }
        out
    }
}

/// Walk a Poseidon Merkle proof up to a root. Host-side mirror of the
/// circuit-side verifier. Used by `round_trip_check`.
pub fn verify_proof(leaf: &Scalar, mut index: usize, proof: &[Scalar], expected_root: &Scalar) -> bool {
    let mut h = *leaf;
    for sib in proof {
        if index & 1 == 0 {
            h = node_hash(&h, sib);
        } else {
            h = node_hash(sib, &h);
        }
        index >>= 1;
    }
    &h == expected_root
}

/// Convert a BLS12-381 scalar to its 32-byte little-endian canonical
/// encoding — matches the `Scalar::from_bytes` round-trip the secure
/// world uses for `ERC20_POSEIDON_ROOT`.
pub fn scalar_to_le32(s: &Scalar) -> [u8; 32] {
    s.to_bytes()
}

// ---------------------------------------------------------------------------
// JSON serialization for the companion artifact consumed by the witness
// generator (`circuits/generated/erc20_poseidon_tree.json`).
// ---------------------------------------------------------------------------

/// One entry in the exported Merkle tree JSON.
///
/// Fields use hex encoding for bytes and decimal for small ints, so
/// `gen_cowswap_eip712_e2e_vector.js` can feed them straight into snarkjs
/// without extra conversion logic.
#[derive(Serialize)]
pub struct ExportedEntry {
    pub chain_id: u64,
    /// Address as a lowercase hex string (no `0x` prefix).
    pub address: String,
    /// Symbol as a UTF-8 string (never longer than MAX_SYMBOL_LEN).
    pub symbol: String,
    pub decimals: u8,
    pub leaf_idx: usize,
    /// Leaf hash as a decimal string (BLS12-381 Fr, big int).
    pub leaf: String,
    /// Merkle path siblings as decimal strings, leaf-up.
    pub proof: Vec<String>,
}

/// Whole tree export — written to `circuits/generated/erc20_poseidon_tree.json`.
#[derive(Serialize)]
pub struct ExportedTree {
    /// Merkle root as a decimal string.
    pub root: String,
    /// Tree depth (number of sibling hashes in every proof).
    pub depth: usize,
    pub entries: Vec<ExportedEntry>,
}

/// Render a scalar as a decimal string (bigint) suitable for direct
/// feeding into snarkjs `input.json` witness inputs.
///
/// `v` is held in big-endian u32 limb order (most-significant first),
/// with one byte per limb. The long-division loop strips freshly-zeroed
/// HIGH-ORDER limbs after each division pass — popping low-order limbs
/// would lose real digits (silently drops ~10 decimal digits when the
/// LE-encoded LSB happens to be 0x00).
pub fn scalar_to_dec(s: &Scalar) -> String {
    let le = s.to_bytes();
    let mut v: Vec<u32> = le.iter().rev().map(|&b| b as u32).collect();
    while v.len() > 1 && v[0] == 0 {
        v.remove(0);
    }
    if v.len() == 1 && v[0] == 0 {
        return "0".to_string();
    }

    fn is_all_zero(v: &[u32]) -> bool {
        v.iter().all(|&x| x == 0)
    }

    let mut digits: Vec<u8> = Vec::new();
    while !is_all_zero(&v) {
        let mut rem: u32 = 0;
        for limb in v.iter_mut() {
            let cur = rem * 256 + *limb;
            *limb = cur / 10;
            rem = cur % 10;
        }
        digits.push(rem as u8);
        while v.len() > 1 && v[0] == 0 {
            v.remove(0);
        }
    }
    digits.iter().rev().map(|d| (b'0' + d) as char).collect()
}
