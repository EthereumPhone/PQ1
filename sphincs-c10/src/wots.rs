//! WOTS+C: Winternitz One-Time Signature with Count-grinding.
//!
//! Instead of a checksum (WOTS+ len2 chains), WOTS+C grinds a `count`
//! value until the base-w digit sum of the message digest equals exactly
//! `TARGET_SUM`. This eliminates checksum chains, saving signature space.

use crate::address::{make_adrs, set_chain_index};
use crate::hash::{chain_hash, pad16, th_multi, wots_digest, wots_secret};
use crate::params::*;

/// Extract L base-w digits from a 256-bit digest.
///
/// Digit `i` = `(digest >> (i * LOG_W)) & W_MASK`.
///
/// Matches Python: `extract_digits(d, cfg)`.
pub fn extract_digits(digest: &[u8; 32]) -> [u8; L] {
    // The digest is a 256-bit big-endian value. The Python code treats it
    // as an integer and extracts bits from the LSB upward:
    //   digit[i] = (d >> (i * log_w)) & w_mask
    //
    // In big-endian bytes, bit 0 is the LSB of byte[31].
    let mut digits = [0u8; L];
    // Convert to a bit-extraction view: work from the least significant byte
    let mut bit_offset = 0usize;
    for digit in digits.iter_mut() {
        let byte_idx = 31 - (bit_offset / 8);
        let bit_in_byte = bit_offset % 8;

        if bit_in_byte + LOG_W <= 8 {
            // All bits within one byte
            *digit = (digest[byte_idx] >> bit_in_byte) & W_MASK;
        } else {
            // Spans two bytes
            let lo = digest[byte_idx] >> bit_in_byte;
            let hi = if byte_idx > 0 {
                digest[byte_idx - 1] << (8 - bit_in_byte)
            } else {
                0
            };
            *digit = (lo | hi) & W_MASK;
        }
        bit_offset += LOG_W;
    }
    digits
}

/// Find a count value such that the digit sum equals TARGET_SUM.
///
/// Returns `(count, digest_bytes, digits)`.
///
/// Matches Python: `wots_find_count(seed, layer, tree, kp, msg_hash, cfg)`.
pub fn find_count(
    seed: &[u8; 32],
    layer: u32,
    tree: u64,
    kp: u32,
    msg_hash: &[u8; 32],
) -> (u32, [u8; 32], [u8; L]) {
    let wots_adrs = make_adrs(layer, tree, ADRS_WOTS, kp, 0, 0, 0);
    for count in 0..10_000_000u32 {
        let d = wots_digest(seed, &wots_adrs, msg_hash, count);
        let digits = extract_digits(&d);
        let sum: usize = digits.iter().map(|&d| d as usize).sum();
        if sum == TARGET_SUM {
            return (count, d, digits);
        }
    }
    // For C10 (L=43, w=8, TARGET_SUM=205) the grinder is expected to
    // succeed in ≪ 10M trials. Hitting this branch implies the digest
    // distribution is broken — fail loudly rather than emit an invalid
    // signature.
    panic!("WOTS+C count grinding failed after 10M iterations");
}

/// Compute the WOTS+C public key from (sk_seed, pk_seed) at a given
/// hypertree position. Used during keygen.
///
/// Generates all L secret chain values, hashes each to the end of its
/// chain (W-1 steps), and compresses via `th_multi`.
pub fn keygen_pk(
    seed: &[u8; 32],
    sk_seed: &[u8; 32],
    layer: u32,
    tree: u64,
    kp: u32,
) -> [u8; N] {
    let base_adrs = make_adrs(layer, tree, ADRS_WOTS, kp, 0, 0, 0);
    let mut pk_elements = [[0u8; N]; L];
    for i in 0..L {
        let sk_i = wots_secret(sk_seed, layer, tree, kp, i as u32);
        let chain_adrs = set_chain_index(&base_adrs, i as u32);
        pk_elements[i] = chain_hash(seed, &chain_adrs, &sk_i, 0, (W - 1) as u32);
    }
    let pk_adrs = make_adrs(layer, tree, ADRS_WOTS_PK, kp, 0, 0, 0);
    th_multi(seed, &pk_adrs, &pk_elements)
}

/// Sign a 16-byte node with WOTS+C at a given hypertree position with a
/// per-call shuffle seed that randomises the COMPUTATION order of the
/// L=43 WOTS chains. Output sigma (indexed by chain number, not
/// processing step) is byte-identical to the un-shuffled path — see
/// `crate::shuffle` for the correctness rationale. The `msg_hash` here
/// is the 16-byte Merkle node being authenticated, padded to 32 bytes
/// by the caller.
///
/// Returns `(chain_values[L], count)`.
pub fn sign_with_shuffle(
    seed: &[u8; 32],
    sk_seed: &[u8; 32],
    layer: u32,
    tree: u64,
    kp: u32,
    msg_hash: &[u8; N],
    shuffle_seed: &[u8; 32],
) -> ([[u8; N]; L], u32) {
    let padded = pad16(msg_hash);
    let (count, _digest, digits) = find_count(seed, layer, tree, kp, &padded);

    let base_adrs = make_adrs(layer, tree, ADRS_WOTS, kp, 0, 0, 0);
    let mut sigma = [[0u8; N]; L];

    let mut chain_order = [0u8; L];
    crate::shuffle::fisher_yates(shuffle_seed, L, &mut chain_order);

    for step in 0..L {
        let i = chain_order[step] as usize;
        let sk_i = wots_secret(sk_seed, layer, tree, kp, i as u32);
        let chain_adrs = set_chain_index(&base_adrs, i as u32);
        sigma[i] = chain_hash(seed, &chain_adrs, &sk_i, 0, digits[i] as u32);
    }
    (sigma, count)
}

/// Verify a WOTS+C signature and recover the public key.
///
/// Given the signature chain values and count, recompute the public key.
/// The caller compares this against the expected leaf in the Merkle tree.
pub fn pk_from_sig(
    seed: &[u8; 32],
    layer: u32,
    tree: u64,
    kp: u32,
    msg_hash: &[u8; N],
    sigma: &[[u8; N]; L],
    count: u32,
) -> [u8; N] {
    let padded = pad16(msg_hash);
    let wots_adrs = make_adrs(layer, tree, ADRS_WOTS, kp, 0, 0, 0);
    let d = wots_digest(seed, &wots_adrs, &padded, count);
    let digits = extract_digits(&d);

    // Verify digit sum
    let sum: usize = digits.iter().map(|&d| d as usize).sum();
    if sum != TARGET_SUM {
        return [0u8; N]; // Invalid: digit sum doesn't match
    }

    let base_adrs = make_adrs(layer, tree, ADRS_WOTS, kp, 0, 0, 0);
    let mut pk_elements = [[0u8; N]; L];
    for i in 0..L {
        let chain_adrs = set_chain_index(&base_adrs, i as u32);
        let remaining = (W - 1) as u32 - digits[i] as u32;
        pk_elements[i] = chain_hash(seed, &chain_adrs, &sigma[i], digits[i] as u32, remaining);
    }
    let pk_adrs = make_adrs(layer, tree, ADRS_WOTS_PK, kp, 0, 0, 0);
    th_multi(seed, &pk_adrs, &pk_elements)
}
