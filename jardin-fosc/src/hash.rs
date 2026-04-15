//! Keccak256 tweakable hash primitives for JARDIN FORS+C.
//!
//! Every hash output is masked to 128 bits (top N bytes of the 32-byte
//! keccak256 output) unless noted otherwise. All 16-byte values are
//! left-aligned in 32-byte buffers (right-zero-padded) to match the
//! EVM uint256 representation.
//!
//! These match the Solidity `JardinForsCVerifier` exactly.

use sha3::{Digest, Keccak256};

use crate::params::{A, K, N};

/// Compute keccak256 of arbitrary data, returning full 32 bytes.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(data);
    h.finalize().into()
}

/// Mask a 32-byte value to the top N=16 bytes (zero out bytes [16..32]).
#[inline]
pub fn mask_n(mut val: [u8; 32]) -> [u8; 32] {
    val[N..].fill(0);
    val
}

/// Tweakable hash: th(seed, adrs, input) -> 128-bit
///
/// `keccak256(seed(32) || adrs(32) || input(32))[0..N]` padded to 32 bytes.
/// Total input: 96 bytes.
pub fn th(seed: &[u8; 32], adrs: &[u8; 32], input: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 96];
    buf[0..32].copy_from_slice(seed);
    buf[32..64].copy_from_slice(adrs);
    buf[64..96].copy_from_slice(input);
    mask_n(keccak256(&buf))
}

/// Tweakable hash pair: th_pair(seed, adrs, left, right) -> 128-bit
///
/// `keccak256(seed(32) || adrs(32) || left(32) || right(32))[0..N]` padded to 32 bytes.
/// Total input: 128 bytes.
pub fn th_pair(seed: &[u8; 32], adrs: &[u8; 32], left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 128];
    buf[0..32].copy_from_slice(seed);
    buf[32..64].copy_from_slice(adrs);
    buf[64..96].copy_from_slice(left);
    buf[96..128].copy_from_slice(right);
    mask_n(keccak256(&buf))
}

/// Compress multiple values: th_multi(seed, adrs, vals[K]) -> 128-bit
///
/// `keccak256(seed(32) || adrs(32) || pad(v0) || ... || pad(v_{K-1}))[0..N]`.
/// For K=26: total input = 32 + 32 + 26*32 = 896 bytes.
pub fn th_multi(seed: &[u8; 32], adrs: &[u8; 32], vals: &[[u8; 32]; K]) -> [u8; 32] {
    let mut buf = [0u8; 64 + K * 32]; // 896
    buf[0..32].copy_from_slice(seed);
    buf[32..64].copy_from_slice(adrs);
    for (i, v) in vals.iter().enumerate() {
        let off = 64 + i * 32;
        buf[off..off + 32].copy_from_slice(v);
    }
    mask_n(keccak256(&buf))
}

/// JARDIN H_msg: 192-byte domain-separated hash -> full 256-bit digest.
///
/// ```text
/// keccak256(
///     pkSeed(32) || pkRoot(32) || R(32) || message(32) ||
///     counter_as_u256(32) || 0xFF..FF(32)
/// )
/// ```
///
/// The domain mask `0xFF..FF` (32 bytes of all-ones) separates H_msg from
/// all other tweakable hashes (which are 96 or 128 bytes).
///
/// Returns the FULL 256-bit digest (NOT masked to N). The caller extracts
/// FORS indices and forced-zero check from this digest.
pub fn jardin_h_msg(
    seed: &[u8; 32],
    root: &[u8; 32],
    r: &[u8; 32],
    message: &[u8; 32],
    counter: u32,
) -> [u8; 32] {
    let mut buf = [0u8; 192];
    buf[0..32].copy_from_slice(seed);
    buf[32..64].copy_from_slice(root);
    buf[64..96].copy_from_slice(r);
    buf[96..128].copy_from_slice(message);
    // counter as u256 (big-endian, value in last 4 bytes of 32-byte field)
    buf[128..160].fill(0);
    buf[156..160].copy_from_slice(&counter.to_be_bytes());
    // Domain separator: 32 bytes of 0xFF
    buf[160..192].fill(0xFF);
    keccak256(&buf)
}

/// Derive FORS secret for a specific (q, tree_idx, leaf_idx).
///
/// `mask_n(keccak256(sk_seed || "jfors" || q.to_be || tree_idx.to_be || leaf_idx.to_be))`
///
/// Domain tag `"jfors"` (5 bytes) separates from C11's `"fors"` (4 bytes).
pub fn fors_secret(sk_seed: &[u8; 32], q: u32, tree_idx: u32, leaf_idx: u32) -> [u8; 32] {
    let mut buf = [0u8; 32 + 5 + 4 + 4 + 4]; // 49
    buf[0..32].copy_from_slice(sk_seed);
    buf[32..37].copy_from_slice(b"jfors");
    buf[37..41].copy_from_slice(&q.to_be_bytes());
    buf[41..45].copy_from_slice(&tree_idx.to_be_bytes());
    buf[45..49].copy_from_slice(&leaf_idx.to_be_bytes());
    mask_n(keccak256(&buf))
}

/// Sentinel value for the deepest left child of the unbalanced spine.
///
/// `mask_n(keccak256(seed || sk_seed || "jardin_sentinel"))`
pub fn jardin_sentinel(seed: &[u8; 32], sk_seed: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 32 + 32 + 15]; // 79
    buf[0..32].copy_from_slice(seed);
    buf[32..64].copy_from_slice(sk_seed);
    buf[64..79].copy_from_slice(b"jardin_sentinel");
    mask_n(keccak256(&buf))
}

/// Derive deterministic R (randomizer) for signing.
///
/// `keccak256(sk_seed || "jardin_R" || message || q.to_be_bytes())`
///
/// Returns full 32 bytes (not masked).
pub fn derive_r(sk_seed: &[u8; 32], message: &[u8; 32], q: u32) -> [u8; 32] {
    let mut buf = [0u8; 32 + 8 + 32 + 4]; // 76
    buf[0..32].copy_from_slice(sk_seed);
    buf[32..40].copy_from_slice(b"jardin_R");
    buf[40..72].copy_from_slice(message);
    buf[72..76].copy_from_slice(&q.to_be_bytes());
    keccak256(&buf)
}

/// Extract FORS indices from the H_msg digest.
///
/// Each index is A=5 bits wide. K=26 indices extracted from bits [0..130).
/// Bit extraction is LSB-first within each byte (big-endian byte order).
pub fn extract_fors_indices(digest: &[u8; 32]) -> [u32; K] {
    let mut indices = [0u32; K];

    // Convert digest to a big integer for bit extraction.
    // digest[0] is the most significant byte.
    // Bit position 0 means the LSB of the entire 256-bit value = bit 0 of digest[31].
    for t in 0..K {
        let bit_pos = t * A; // 0, 5, 10, ..., 125
        // Extract A bits starting at bit_pos from LSB
        let mut val: u32 = 0;
        for b in 0..A {
            let abs_bit = bit_pos + b;
            let by = 31 - (abs_bit / 8);
            let bi = abs_bit % 8;
            if by < 32 {
                val |= (((digest[by] >> bi) & 1) as u32) << b;
            }
        }
        indices[t] = val;
    }

    indices
}

/// Check the forced-zero constraint: tree K-1 (index 25) must have index 0.
///
/// The last FORS index is at bits [125..130) of the digest.
pub fn check_forced_zero(digest: &[u8; 32]) -> bool {
    let indices = extract_fors_indices(digest);
    indices[K - 1] == 0
}

// ---------------------------------------------------------------------------
// Key derivation helpers
// ---------------------------------------------------------------------------

/// Derive JARDIN sub-key pair from slot entropy.
///
/// Returns (pk_seed, sk_seed) where pk_seed is masked to N bytes.
pub fn jardin_derive_keys(entropy: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    // Intermediate sub-key: "jardin_sub_v1" (13 bytes) + entropy (32 bytes)
    let mut sub_buf = [0u8; 13 + 32]; // 45
    sub_buf[0..13].copy_from_slice(b"jardin_sub_v1");
    sub_buf[13..45].copy_from_slice(entropy);
    let sub = keccak256(&sub_buf);

    // pk_seed: masked to N bytes
    // "jardin_pk_seed" (14 bytes) + sub (32 bytes)
    let mut pk_buf = [0u8; 14 + 32]; // 46
    pk_buf[0..14].copy_from_slice(b"jardin_pk_seed");
    pk_buf[14..46].copy_from_slice(&sub);
    let pk_seed = mask_n(keccak256(&pk_buf));

    // sk_seed: full 32 bytes
    // "jardin_sk_seed" (14 bytes) + sub (32 bytes)
    let mut sk_buf = [0u8; 14 + 32]; // 46
    sk_buf[0..14].copy_from_slice(b"jardin_sk_seed");
    sk_buf[14..46].copy_from_slice(&sub);
    let sk_seed = keccak256(&sk_buf);

    (pk_seed, sk_seed)
}

/// Derive JARDIN slot entropy from master entropy and slot index.
pub fn jardin_slot_entropy(master_entropy: &[u8; 32], slot_index: u32) -> [u8; 32] {
    let mut buf = [0u8; 32 + 11 + 4]; // master + "jardin_slot" + index
    buf[0..32].copy_from_slice(master_entropy);
    buf[32..43].copy_from_slice(b"jardin_slot");
    buf[43..47].copy_from_slice(&slot_index.to_be_bytes());
    keccak256(&buf)
}

/// Derive slot randomizer r (for on-chain slot key H(r)).
pub fn jardin_slot_r(master_entropy: &[u8; 32], slot_index: u32) -> [u8; 32] {
    let mut buf = [0u8; 32 + 8 + 4]; // master + "jardin_r" + index
    buf[0..32].copy_from_slice(master_entropy);
    buf[32..40].copy_from_slice(b"jardin_r");
    buf[40..44].copy_from_slice(&slot_index.to_be_bytes());
    keccak256(&buf[..44])
}
