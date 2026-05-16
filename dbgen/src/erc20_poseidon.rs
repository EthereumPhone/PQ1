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

#[cfg(test)]
mod tests {
    use super::*;

    // === Positive ============================================================

    /// MAX_SYMBOL_LEN is a circuit-side constant — the Circom Poseidon
    /// circuit packs the symbol field into exactly 6 ASCII bytes. Any
    /// bump here changes the leaf encoding and invalidates every
    /// shipped ERC20_POSEIDON_ROOT.
    #[test]
    fn positive_max_symbol_len_frozen_at_six() {
        assert_eq!(MAX_SYMBOL_LEN, 6);
    }

    /// Poseidon leaf encoding is frozen — pin chain_id / address /
    /// decimals / symbol-packing / symbol-len / reserved field values
    /// for a known input. The circuit-side leaf MUST match this byte
    /// for byte (well, field for field).
    #[test]
    fn positive_canonical_poseidon_leaf_field_layout() {
        let chain_id = 1u64;
        let addr: [u8; 20] = [
            0xc0, 0xff, 0xee, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];
        let symbol = b"USDC";
        let fields =
            canonical_erc20_poseidon_leaf(chain_id, &addr, 6, symbol).expect("leaf builds");
        assert_eq!(fields[0], bls12_381::Scalar::from(1u64));
        // f1 = address packed big-endian into a single scalar.
        let mut expected_f1 = bls12_381::Scalar::zero();
        let s256 = bls12_381::Scalar::from(256u64);
        for &b in addr.iter() {
            expected_f1 = expected_f1 * s256 + bls12_381::Scalar::from(b as u64);
        }
        assert_eq!(fields[1], expected_f1);
        assert_eq!(fields[2], bls12_381::Scalar::from(6u64));
        // f3 = symbol packed big-endian, right-padded with 0x20.
        let mut expected_f3 = bls12_381::Scalar::zero();
        let padded = b"USDC  "; // pad with two ASCII spaces to width 6
        for &b in padded.iter() {
            expected_f3 = expected_f3 * s256 + bls12_381::Scalar::from(b as u64);
        }
        assert_eq!(fields[3], expected_f3);
        assert_eq!(fields[4], bls12_381::Scalar::from(4u64));
        assert_eq!(fields[5], bls12_381::Scalar::zero());
    }

    #[test]
    fn positive_canonical_symbol_at_max_length() {
        let res = canonical_erc20_poseidon_leaf(1, &[0u8; 20], 0, b"ABCDEF");
        assert!(res.is_ok());
    }

    #[test]
    fn positive_tree_round_trip_two_leaves() {
        let f0 =
            canonical_erc20_poseidon_leaf(1, &[0u8; 20], 18, b"ETH").expect("leaf0");
        let f1 =
            canonical_erc20_poseidon_leaf(137, &[0xffu8; 20], 6, b"USDC").expect("leaf1");
        let l0 = leaf_hash(&f0);
        let l1 = leaf_hash(&f1);
        let t = PoseidonMerkleTree::build(vec![l0, l1]);
        assert_eq!(t.depth(), 1);
        assert_eq!(t.root(), node_hash(&l0, &l1));
        assert!(verify_proof(&l0, 0, &t.proof(0), &t.root()));
        assert!(verify_proof(&l1, 1, &t.proof(1), &t.root()));
    }

    #[test]
    fn positive_tree_padded_three_leaves() {
        let leaves: Vec<bls12_381::Scalar> = (1..=3u64).map(bls12_381::Scalar::from).collect();
        let t = PoseidonMerkleTree::build(leaves.clone());
        assert_eq!(t.depth(), 2);
        assert_eq!(t.levels[0].len(), 4);
        assert_eq!(t.levels[0][3], leaves[2]); // duplicated last leaf
        for (i, leaf) in leaves.iter().enumerate() {
            assert!(verify_proof(leaf, i, &t.proof(i), &t.root()));
        }
    }

    #[test]
    fn positive_scalar_to_le32_round_trip() {
        let s = bls12_381::Scalar::from(0x1234_5678_9abc_def0u64);
        let bytes = scalar_to_le32(&s);
        let back = bls12_381::Scalar::from_bytes(&bytes);
        assert_eq!(bool::from(back.is_some()), true);
        assert_eq!(back.unwrap(), s);
    }

    // === Negative ============================================================

    /// Empty symbol — can't be packed into the field. Circuit-side
    /// would also fail; refuse at host build time.
    #[test]
    fn negative_empty_symbol_rejected() {
        let err = canonical_erc20_poseidon_leaf(1, &[0u8; 20], 0, b"")
            .err().expect("empty symbol must fail");
        assert!(err.contains("symbol_len"), "got: {err}");
    }

    /// Symbol > MAX_SYMBOL_LEN — bumping MAX_SYMBOL_LEN would change
    /// the circuit's witness layout; refuse the build instead.
    #[test]
    fn negative_oversize_symbol_rejected() {
        let err = canonical_erc20_poseidon_leaf(1, &[0u8; 20], 0, b"TOOLONG")
            .err().expect("7-byte symbol must fail");
        assert!(err.contains("symbol_len"), "got: {err}");
    }

    /// Non-printable / non-ASCII symbol byte — would break the trusted
    /// UI's display path and is not representable in the Circom-side
    /// 6-byte ASCII layout.
    #[test]
    fn negative_non_printable_symbol_rejected() {
        let bad = [b'A', b'B', 0x07, b'D'];
        let err = canonical_erc20_poseidon_leaf(1, &[0u8; 20], 0, &bad)
            .err().expect("BEL byte must fail");
        assert!(err.contains("printable ASCII"), "got: {err}");
    }

    #[test]
    fn negative_high_byte_symbol_rejected() {
        let bad = [b'A', b'B', 0x80, b'D'];
        let err = canonical_erc20_poseidon_leaf(1, &[0u8; 20], 0, &bad)
            .err().expect("0x80 byte must fail");
        assert!(err.contains("printable ASCII"), "got: {err}");
    }

    /// Tampered leaf — flipping any byte of the leaf hash must
    /// invalidate the proof. The Poseidon tree's trust property is
    /// the same as the SHA-256 tree's.
    #[test]
    fn negative_tampered_leaf_rejected() {
        let leaves: Vec<bls12_381::Scalar> = (1..=4u64).map(bls12_381::Scalar::from).collect();
        let t = PoseidonMerkleTree::build(leaves);
        let proof = t.proof(2);
        let real_leaf = bls12_381::Scalar::from(3u64);
        let tampered_leaf = bls12_381::Scalar::from(99u64);
        assert!(verify_proof(&real_leaf, 2, &proof, &t.root()));
        assert!(!verify_proof(&tampered_leaf, 2, &proof, &t.root()));
    }

    /// Tampered proof sibling — must reject.
    #[test]
    fn negative_tampered_sibling_rejected() {
        let leaves: Vec<bls12_381::Scalar> = (1..=4u64).map(bls12_381::Scalar::from).collect();
        let t = PoseidonMerkleTree::build(leaves);
        let mut proof = t.proof(1);
        proof[0] = bls12_381::Scalar::from(0xdeadu64);
        let real_leaf = bls12_381::Scalar::from(2u64);
        assert!(!verify_proof(&real_leaf, 1, &proof, &t.root()));
    }

    /// Wrong index — position binding for the Poseidon tree mirrors
    /// the SHA-256 tree.
    #[test]
    fn negative_wrong_index_rejected() {
        let leaves: Vec<bls12_381::Scalar> = (1..=4u64).map(bls12_381::Scalar::from).collect();
        let t = PoseidonMerkleTree::build(leaves);
        let proof = t.proof(0);
        let leaf0 = bls12_381::Scalar::from(1u64);
        assert!(verify_proof(&leaf0, 0, &proof, &t.root()));
        assert!(!verify_proof(&leaf0, 1, &proof, &t.root()));
    }

    /// Empty leaf vector — should panic. Same rationale as the
    /// SHA-256 tree.
    #[test]
    #[should_panic(expected = "Poseidon Merkle tree needs")]
    fn negative_empty_leaves_panics() {
        let _ = PoseidonMerkleTree::build(Vec::<bls12_381::Scalar>::new());
    }

    /// Symbol-packing must be sensitive to position — "AB    " and
    /// "  AB  " produce different f3 packings even though both are
    /// 6 bytes of mostly-spaces.
    #[test]
    fn negative_symbol_packing_position_matters() {
        // Both are 2-byte symbols (left-padded vs right-padded would
        // be a regression). Implementation does right-pad with space.
        let fab = canonical_erc20_poseidon_leaf(1, &[0u8; 20], 0, b"AB").unwrap();
        let fba = canonical_erc20_poseidon_leaf(1, &[0u8; 20], 0, b"BA").unwrap();
        assert_ne!(fab[3], fba[3]);
        // Differently sized symbols are also distinct (symbol_len f4
        // differs too).
        let fa = canonical_erc20_poseidon_leaf(1, &[0u8; 20], 0, b"A").unwrap();
        assert_ne!(fab[3], fa[3]);
        assert_ne!(fab[4], fa[4]);
    }
}
