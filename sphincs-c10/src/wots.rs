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
    // Indexed form (bit_offset = i*LOG_W is the identical sequence the running
    // accumulator produced) so the Aeneas model is a Range loop + indexed
    // write — see contracts/verification §33 rank 4. Byte-identical; pinned by
    // extract_digits_matches_window_reference.
    for i in 0..L {
        let bit_offset = i * LOG_W;
        let byte_idx = 31 - (bit_offset / 8);
        let bit_in_byte = bit_offset % 8;

        if bit_in_byte + LOG_W <= 8 {
            // All bits within one byte
            digits[i] = (digest[byte_idx] >> bit_in_byte) & W_MASK;
        } else {
            // Spans two bytes
            let lo = digest[byte_idx] >> bit_in_byte;
            let hi = if byte_idx > 0 {
                digest[byte_idx - 1] << (8 - bit_in_byte)
            } else {
                0
            };
            digits[i] = (lo | hi) & W_MASK;
        }
    }
    digits
}

/// Trials between two progress reports inside [`find_count`] (a few ms of
/// digests on the STM32U585).
pub(crate) const GRIND_REPORT_EVERY: u32 = 4096;

/// Find a count value such that the digit sum equals TARGET_SUM.
///
/// Returns `(count, digest_bytes, digits)`.
///
/// Matches Python: `wots_find_count(seed, layer, tree, kp, msg_hash, cfg)`.
///
/// Reports `pct` to `progress` every [`GRIND_REPORT_EVERY`] trials. The
/// grind is message-dependent (tens of thousands of digests on average,
/// several times that in the tail), so without these a UI paced by the hook
/// stalls. The trial count is public: the found `count` is in the signature.
pub(crate) fn find_count(
    seed: &[u8; 32],
    layer: u32,
    tree: u64,
    kp: u32,
    msg_hash: &[u8; 32],
    progress: &crate::hypertree::ProgressSink,
    pct: u8,
) -> (u32, [u8; 32], [u8; L]) {
    let wots_adrs = make_adrs(layer, tree, ADRS_WOTS, kp, 0, 0, 0);
    let mut count = 0u32;
    while count < 10_000_000 {
        let d = wots_digest(seed, &wots_adrs, msg_hash, count);
        // Rejected trials (all but the last) need only the digit sum, not
        // the digits: `digit_sum(d)` is `Σ extract_digits(d)` (pinned by
        // `digit_sum_matches_extracted_digits`), and the digits are
        // extracted once, for the accepted count, so the returned count,
        // digest and digits are unchanged. (Line count kept: the extraction
        // annotates every function below with its source lines.)
        if digit_sum(&d) == TARGET_SUM {
            return (count, d, extract_digits(&d));
        }
        if count % GRIND_REPORT_EVERY == GRIND_REPORT_EVERY - 1 {
            crate::hypertree::report(progress, pct);
        }
        count += 1;
    }
    // For C10 (L=43, w=8, TARGET_SUM=205) the grinder is expected to
    // succeed in ≪ 10M trials. Exhaustion remains possible: fail loudly
    // rather than emit an invalid signature.
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
/// Returns `(chain_values[L], count)`. The count grind reports `pct` to
/// `progress` (see [`find_count`]).
#[allow(clippy::too_many_arguments)]
pub(crate) fn sign_with_shuffle(
    seed: &[u8; 32],
    sk_seed: &[u8; 32],
    layer: u32,
    tree: u64,
    kp: u32,
    msg_hash: &[u8; N],
    shuffle_seed: &[u8; 32],
    progress: &crate::hypertree::ProgressSink,
    pct: u8,
) -> ([[u8; N]; L], u32) {
    let padded = pad16(msg_hash);
    let (count, _digest, digits) = find_count(seed, layer, tree, kp, &padded, progress, pct);

    let base_adrs = make_adrs(layer, tree, ADRS_WOTS, kp, 0, 0, 0);
    let mut sigma = [[0u8; N]; L];

    let chain_order = crate::shuffle::fisher_yates(shuffle_seed, L);

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

    // Verify digit sum. Indexed form instead of iter().map().sum() so the
    // Aeneas model is a plain Range loop, not closure/iterator-adapter
    // axioms — see contracts/verification §33 rank 5. Identical sum.
    let mut sum: usize = 0;
    for i in 0..L {
        sum += digits[i] as usize;
    }
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

#[cfg(test)]
mod extract_digits_tests {
    use super::*;

    /// Independent reference: the digest is a 256-bit big-endian integer `D`;
    /// digit `k = (D >> (k*LOG_W)) & W_MASK`. Computed with a uniform 2-byte
    /// window — deliberately distinct from the branchy production impl, so the
    /// two agreeing is a real cross-check, not a tautology.
    fn digit_ref(digest: &[u8; 32], k: usize) -> u8 {
        let p = k * LOG_W;
        let q = p / 8; // byte index counted from the LSB end
        let lo = digest[31 - q] as u32;
        let hi = if q + 1 < 32 { digest[31 - q - 1] as u32 } else { 0 };
        let window = (lo | (hi << 8)) >> (p % 8);
        (window as u8) & W_MASK
    }

    #[test]
    fn extract_digits_matches_window_reference() {
        let mut patterned = [0u8; 32];
        let mut xored = [0u8; 32];
        for i in 0..32 {
            patterned[i] = (i as u8).wrapping_mul(37).wrapping_add(11);
            xored[i] = 0xA5u8 ^ (i as u8);
        }
        let digests: [[u8; 32]; 4] = [[0u8; 32], [0xFFu8; 32], patterned, xored];
        for d in &digests {
            let got = extract_digits(d);
            for k in 0..L {
                assert_eq!(got[k], digit_ref(d, k), "digit {k} mismatch");
                assert!((got[k] as usize) < W, "digit {k} out of range");
            }
        }
    }

    /// `find_count` accepts on `digit_sum`; it must equal the sum of the
    /// extracted digits for every digest. Each digit is a weighted sum of its
    /// bits with no carry, and so is `digit_sum` (field values stay below
    /// 64), so agreement on every single-bit digest, all-zero and all-ones
    /// covers the bit weights; the random digests cover the combination.
    #[test]
    fn digit_sum_matches_extracted_digits() {
        fn check(d: &[u8; 32]) {
            let want: usize = extract_digits(d).iter().map(|&x| x as usize).sum();
            assert_eq!(digit_sum(d), want, "digest {d:02x?}");
        }
        check(&[0u8; 32]);
        check(&[0xFFu8; 32]);
        for bit in 0..256 {
            let mut d = [0u8; 32];
            d[31 - bit / 8] = 1 << (bit % 8);
            check(&d);
        }
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        for _ in 0..20_000 {
            let mut d = [0u8; 32];
            for b in d.iter_mut() {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                *b = x as u8;
            }
            check(&d);
        }
    }
}

/// `Σ extract_digits(digest)`, without building the digit array. Eight 3-bit
/// digits are exactly three bytes, so the 129 digit bits are five 24-bit
/// groups plus the top three digits; a group's eight digits are summed
/// field-parallel (pairs side by side in 6-bit fields, at most 14 then 28,
/// so no carry crosses a field). Public data only: the grind digest of public
/// inputs, whose accepted count is in the signature.
pub(crate) fn digit_sum(digest: &[u8; 32]) -> usize {
    let mut sum: usize = 0;
    for g in 0..5 {
        // Bits 24g..24g+23 of the big-endian integer: bytes 31-3g (low)
        // down to 29-3g (high).
        let lo = 31 - 3 * g;
        let v = digest[lo] as u32 | (digest[lo - 1] as u32) << 8 | (digest[lo - 2] as u32) << 16;
        let s1 = (v & 0o07070707) + ((v >> 3) & 0o07070707);
        let s2 = s1 + (s1 >> 12);
        sum += ((s2 & 0o77) + ((s2 >> 6) & 0o77)) as usize;
    }
    // Digits 40..=42: bits 120..=128, all of byte 16 and bit 0 of byte 15.
    let v = digest[16] as u32 | ((digest[15] & 1) as u32) << 8;
    sum += ((v & 7) + ((v >> 3) & 7) + ((v >> 6) & 7)) as usize;
    sum
}
