//! C10 v2 hash layer (RESEARCH, #1155): `research/c10-autoresearch/c10v2-spec.md`.
//!
//! Same scheme as v1 (FORS+C, WOTS+C, hypertree, 4,008-byte signature); only
//! the preimages change. Each v1 hash function in `hash.rs` returns through
//! here when the `v2` feature is on, so `wots`, `fors` and `hypertree` are
//! unchanged and still pass v1-shaped 32-byte seeds, addresses and values.
//! The compact address `A7` is built from the same fields as the v1 ADRS.
//! Nothing here is shipped.

use crate::hash::{sha256_bytes, sha256_bytes16};
use crate::params::N;

pub const T_WOTS_HASH: u64 = 0;
pub const T_WOTS_PK: u64 = 1;
pub const T_TREE: u64 = 2;
pub const T_FORS_TREE: u64 = 3;
pub const T_FORS_ROOTS: u64 = 4;
pub const T_WOTS_PRF: u64 = 5;
pub const T_FORS_PRF: u64 = 6;
pub const T_WOTS_DIGEST: u64 = 7;
pub const T_H_MSG: u64 = 8;
/// The last FORS slot's F (spec 0.2: v1 reused FORS tree 12 leaf 0's tweak).
pub const T_FORS_LAST: u32 = 9;

/// `cp`'s place in A7 (bits 15..12: the top nibble of byte 5).
pub const CP_SHIFT: u32 = 12;
const CP_MASK: u64 = 0xF << CP_SHIFT;

/// A7 (spec §1): fixed field positions whatever the type.
#[inline(always)]
pub fn pack(ty: u64, layer: u64, tree: u64, kp: u64, ci: u64, cp: u64, ha: u64) -> u64 {
    debug_assert!(ty < 16 && layer < 2 && tree < (1 << 18) && kp < (1 << 9));
    debug_assert!(ci < (1 << 6) && cp < 16 && ha < (1 << 11));
    ty << 52 | layer << 51 | tree << 33 | kp << 24 | ci << 18 | cp << CP_SHIFT | ha << 1
}

#[inline(always)]
fn be4(b: &[u8; 32], o: usize) -> u64 {
    u64::from(u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]))
}

/// A7 of a v1 ADRS: `layer(4) ‖ tree(8) ‖ type(4) ‖ kp(4) ‖ ci(4) ‖ cp(4) ‖ ha(4)`.
#[inline(always)]
pub fn a7_of(adrs: &[u8; 32]) -> u64 {
    let mut t = [0u8; 8];
    t.copy_from_slice(&adrs[4..12]);
    pack(be4(adrs, 12), be4(adrs, 0), u64::from_be_bytes(t), be4(adrs, 16), be4(adrs, 20), be4(adrs, 24), be4(adrs, 28))
}

#[inline(always)]
fn put7(dst: &mut [u8], a: u64) {
    dst.copy_from_slice(&a.to_be_bytes()[1..8]);
}

/// F: `S ‖ v ‖ A7`, 39 bytes.
pub fn th(seed: &[u8; 32], adrs: &[u8; 32], val: &[u8; 32]) -> [u8; N] {
    let mut b = [0u8; 39];
    b[0..16].copy_from_slice(&seed[..16]);
    b[16..32].copy_from_slice(&val[..16]);
    put7(&mut b[32..39], a7_of(adrs));
    sha256_bytes16(&b)
}

/// H: `S ‖ L ‖ R ‖ A7`, 55 bytes.
pub fn th_pair(seed: &[u8; 32], adrs: &[u8; 32], left: &[u8; 32], right: &[u8; 32]) -> [u8; N] {
    let mut b = [0u8; 55];
    b[0..16].copy_from_slice(&seed[..16]);
    b[16..32].copy_from_slice(&left[..16]);
    b[32..48].copy_from_slice(&right[..16]);
    put7(&mut b[48..55], a7_of(adrs));
    sha256_bytes16(&b)
}

/// T_k, tweak-first (spec 0.2): `S ‖ A7 ‖ 0x00 ‖ v_0 ‖ … ‖ v_{k-1}`.
pub fn th_multi(seed: &[u8; 32], adrs: &[u8; 32], vals: &[[u8; N]]) -> [u8; N] {
    let mut b = [0u8; 24 + N * crate::hash::TH_MULTI_MAX];
    b[0..16].copy_from_slice(&seed[..16]);
    put7(&mut b[16..23], a7_of(adrs));
    for (i, v) in vals.iter().enumerate() {
        b[24 + N * i..24 + N * (i + 1)].copy_from_slice(v);
    }
    sha256_bytes16(&b[..24 + N * vals.len()])
}

/// H_MSG: `S ‖ root ‖ M ‖ R ‖ A7(type 8)`, 87 bytes, full digest.
pub fn h_msg(seed: &[u8; 32], root: &[u8; 32], r: &[u8; 32], message: &[u8; 32]) -> [u8; 32] {
    let mut b = [0u8; 87];
    b[0..16].copy_from_slice(&seed[..16]);
    b[16..32].copy_from_slice(&root[..16]);
    b[32..64].copy_from_slice(message);
    b[64..80].copy_from_slice(&r[..16]);
    put7(&mut b[80..87], pack(T_H_MSG, 0, 0, 0, 0, 0, 0));
    sha256_bytes(&b)
}

/// The chain: F at positions `start_pos..start_pos + steps`, over one
/// 39-byte buffer whose `cp` bits and value are rewritten per step.
pub fn chain_hash(seed: &[u8; 32], adrs: &[u8; 32], val: &[u8; N], start_pos: u32, steps: u32) -> [u8; N] {
    let base = a7_of(adrs) & !CP_MASK;
    let mut b = [0u8; 39];
    b[0..16].copy_from_slice(&seed[..16]);
    b[16..32].copy_from_slice(val);
    for step in 0..steps {
        put7(&mut b[32..39], base | u64::from(start_pos + step) << CP_SHIFT);
        let d = sha256_bytes16(&b);
        b[16..32].copy_from_slice(&d);
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&b[16..32]);
    out
}

/// WOTS_DIGEST: `S ‖ m16 ‖ be32(count) ‖ A7(type 7)`, 43 bytes, full digest.
/// `msg_hash` arrives v1-padded; its first 16 bytes are the node.
pub fn wots_digest(seed: &[u8; 32], wots_adrs: &[u8; 32], msg_hash: &[u8; 32], count: u32) -> [u8; 32] {
    let mut t = [0u8; 8];
    t.copy_from_slice(&wots_adrs[4..12]);
    let a = pack(T_WOTS_DIGEST, be4(wots_adrs, 0), u64::from_be_bytes(t), be4(wots_adrs, 16), 0, 0, 0);
    let mut b = [0u8; 43];
    b[0..16].copy_from_slice(&seed[..16]);
    b[16..32].copy_from_slice(&msg_hash[..16]);
    b[32..36].copy_from_slice(&count.to_be_bytes());
    put7(&mut b[36..43], a);
    sha256_bytes(&b)
}

/// The PRFs: `sk_seed ‖ A7`, 39 bytes; the sk_seed copy is wiped.
fn prf(sk_seed: &[u8; 32], a: u64) -> [u8; N] {
    let mut b = [0u8; 39];
    b[0..32].copy_from_slice(sk_seed);
    put7(&mut b[32..39], a);
    let out = sha256_bytes16(&b);
    for x in b.iter_mut() {
        // SAFETY: `x` is a valid, aligned, exclusive reference.
        unsafe { core::ptr::write_volatile(x, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    out
}

pub fn wots_secret(sk_seed: &[u8; 32], layer: u32, tree: u64, kp: u32, chain_idx: u32) -> [u8; N] {
    prf(sk_seed, pack(T_WOTS_PRF, u64::from(layer), tree, u64::from(kp), u64::from(chain_idx), 0, 0))
}

pub fn fors_secret(sk_seed: &[u8; 32], ht_idx: u32, tree_idx: u32, leaf_idx: u32) -> [u8; N] {
    prf(sk_seed, pack(T_FORS_PRF, 0, u64::from(ht_idx), u64::from(tree_idx), 0, 0, u64::from(leaf_idx)))
}

/// MEASUREMENT (#1155 A/B, `v2-lowdigits`): v1's digit position, digit i = (D >> 3i) & 7.
#[cfg(feature = "v2-lowdigits")]
pub fn digits(d: &[u8; 32]) -> [u8; crate::params::L] {
    let bit = |k: usize| (d[31 - k / 8] >> (k % 8)) & 1;
    core::array::from_fn(|i| bit(3 * i) | bit(3 * i + 1) << 1 | bit(3 * i + 2) << 2)
}
#[cfg(feature = "v2-lowdigits")]
pub fn digit_sum(d: &[u8; 32]) -> usize {
    digits(d).iter().map(|&x| x as usize).sum()
}

/// WOTS digits from the TOP 129 bits (spec 0.2): digit i = (D >> (253 − 3i)) & 7.
#[cfg(not(feature = "v2-lowdigits"))]
pub fn digits(d: &[u8; 32]) -> [u8; crate::params::L] {
    let mut hi = [0u8; 16];
    hi.copy_from_slice(&d[0..16]);
    let hi = u128::from_be_bytes(hi); // bits 255..128
    let mut out = [0u8; crate::params::L];
    for (i, o) in out.iter_mut().enumerate().take(crate::params::L - 1) {
        *o = ((hi >> (125 - 3 * i)) & 7) as u8;
    }
    // Digit 42: bits 129..127.
    out[crate::params::L - 1] = (((hi & 3) << 1) as u8) | (d[16] >> 7);
    out
}

/// Σ digits(d): bytes 0..15 are five 24-bit groups of eight 3-bit digits
/// (digits 0..39); digits 40..42 are byte 15 and the top bit of byte 16. 32-bit
/// SWAR only (the grind's predicate: it must stay under one block's engine time).
#[cfg(not(feature = "v2-lowdigits"))]
#[inline(always)]
pub fn digit_sum(d: &[u8; 32]) -> usize {
    let mut sum = 0u32;
    let mut g = 0;
    while g < 15 {
        let v = u32::from(d[g]) << 16 | u32::from(d[g + 1]) << 8 | u32::from(d[g + 2]);
        let s = (v & 0o07070707) + ((v >> 3) & 0o07070707); // four 6-bit fields, each <= 14
        let s = (s & 0o00770077) + ((s >> 6) & 0o00770077); // two 12-bit fields, each <= 28
        sum += (s & 0o7777) + (s >> 12);
        g += 3;
    }
    let t = u32::from(d[15]) << 1 | u32::from(d[16] >> 7); // digits 40, 41, 42
    sum += (t & 7) + ((t >> 3) & 7) + (t >> 6);
    sum as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bit-by-bit reference: digit i = bits (255 - 3i) .. (253 - 3i) of the big-endian digest.
    fn reference(d: &[u8; 32]) -> [u8; crate::params::L] {
        let bit = |k: usize| (d[31 - k / 8] >> (k % 8)) & 1; // k = 0 is the LSB of byte 31
        core::array::from_fn(|i| {
            let lsb = 253 - 3 * i;
            bit(lsb) | bit(lsb + 1) << 1 | bit(lsb + 2) << 2
        })
    }

    #[test]
    #[cfg(not(feature = "v2-lowdigits"))]
    fn digits_and_digit_sum_match_the_bitwise_reference() {
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let check = |d: &[u8; 32]| {
            let want = reference(d);
            assert_eq!(digits(d), want, "{d:02x?}");
            assert_eq!(digit_sum(d), want.iter().map(|&v| v as usize).sum::<usize>(), "{d:02x?}");
        };
        check(&[0u8; 32]);
        check(&[0xFFu8; 32]);
        for k in 0..256 {
            let mut d = [0u8; 32];
            d[31 - k / 8] = 1 << (k % 8);
            check(&d);
        }
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

// ---- fused driver entries (`v2-fused`: `pqsigner-hw/v2`) --------------------

/// A7's two DIN words in memory order: bytes 0..4, and bytes 4..7 plus a zero.
#[inline(always)]
pub fn words(a: u64) -> (u32, u32) {
    let b = a.to_be_bytes();
    (u32::from_le_bytes([b[1], b[2], b[3], b[4]]), u32::from_le_bytes([b[5], b[6], b[7], 0]))
}

#[cfg(feature = "v2-fused")]
extern "C" {
    fn pqsigner_v2_chain16(seed: *const u8, val: *mut u8, a0: u32, a1: u32, start: u32, steps: u32);
    fn pqsigner_v2_prf_chain16(sk: *const u8, p0: u32, p1: u32, seed: *const u8, a0: u32, a1: u32, steps: u32, out: *mut u8);
    fn pqsigner_v2_node16(seed: *const u8, l: *const u8, r: *const u8, a0: u32, a1: u32, out: *mut u8);
    fn pqsigner_v2_fors_leaf16(sk: *const u8, p0: u32, p1: u32, seed: *const u8, a0: u32, a1: u32, out: *mut u8);
    fn pqsigner_v2_search43(
        sm: *const u8, a0: u32, a1: u32, start: u32, n: u32, pred: unsafe extern "C" fn(*const u8) -> bool, out: *mut u8,
    ) -> u32;
    fn pqsigner_v2_search43_target(sm: *const u8, a0: u32, a1: u32, start: u32, n: u32, target: u32, out: *mut u8) -> u32;
}

#[cfg(feature = "v2-fused")]
pub fn chain_hash_fused(seed: &[u8; 32], adrs: &[u8; 32], val: &[u8; N], start_pos: u32, steps: u32) -> [u8; N] {
    let (a0, a1) = words(a7_of(adrs) & !CP_MASK);
    let mut v = *val;
    // SAFETY: 16 readable seed bytes, 16 readable and writable value bytes.
    unsafe { pqsigner_v2_chain16(seed.as_ptr(), v.as_mut_ptr(), a0, a1, start_pos, steps) };
    v
}

#[cfg(feature = "v2-fused")]
pub fn th_pair_fused(seed: &[u8; 32], adrs: &[u8; 32], left: &[u8; 32], right: &[u8; 32]) -> [u8; N] {
    let (a0, a1) = words(a7_of(adrs));
    let mut out = [0u8; N];
    // SAFETY: 16 readable bytes each (the first halves), 16 writable.
    unsafe { pqsigner_v2_node16(seed.as_ptr(), left.as_ptr(), right.as_ptr(), a0, a1, out.as_mut_ptr()) };
    out
}

#[cfg(feature = "v2-fused")]
#[allow(clippy::too_many_arguments)]
pub fn wots_secret_chain_fused(
    seed: &[u8; 32], sk_seed: &[u8; 32], base_adrs: &[u8; 32], layer: u32, tree: u64, kp: u32, ci: u32, steps: u32,
) -> [u8; N] {
    let (p0, p1) = words(pack(T_WOTS_PRF, u64::from(layer), tree, u64::from(kp), u64::from(ci), 0, 0));
    let (a0, a1) = words(a7_of(&crate::address::set_chain_index(base_adrs, ci)) & !CP_MASK);
    let mut out = [0u8; N];
    // SAFETY: 32 and 16 readable bytes, 16 writable.
    unsafe { pqsigner_v2_prf_chain16(sk_seed.as_ptr(), p0, p1, seed.as_ptr(), a0, a1, steps, out.as_mut_ptr()) };
    out
}

#[cfg(feature = "v2-fused")]
pub fn fors_leaf_fused(seed: &[u8; 32], sk_seed: &[u8; 32], leaf_adrs: &[u8; 32], ht_idx: u32, tree_idx: u32, leaf: u32) -> [u8; N] {
    let (p0, p1) = words(pack(T_FORS_PRF, 0, u64::from(ht_idx), u64::from(tree_idx), 0, 0, u64::from(leaf)));
    let (a0, a1) = words(a7_of(leaf_adrs));
    let mut out = [0u8; N];
    // SAFETY: 32 and 16 readable bytes, 16 writable.
    unsafe { pqsigner_v2_fors_leaf16(sk_seed.as_ptr(), p0, p1, seed.as_ptr(), a0, a1, out.as_mut_ptr()) };
    out
}

/// The WOTS+C grind on the fused search: the first count from `start` (at
/// most `n` tries) whose digest's digit sum is the target.
#[cfg(feature = "v2-fused")]
pub fn search_fused(seed: &[u8; 32], msg_hash: &[u8; 32], layer: u32, tree: u64, kp: u32, start: u32, n: u32, d: &mut [u8; 32]) -> u32 {
    unsafe extern "C" fn hits(d: *const u8) -> bool {
        // SAFETY: the driver passes its 32-byte digest.
        digit_sum(unsafe { &*d.cast::<[u8; 32]>() }) == crate::params::TARGET_SUM
    }
    let mut sm = [0u8; 32];
    sm[..16].copy_from_slice(&seed[..16]);
    sm[16..].copy_from_slice(&msg_hash[..16]);
    let (a0, a1) = words(pack(T_WOTS_DIGEST, u64::from(layer), tree, u64::from(kp), 0, 0, 0));
    let _ = hits;
    // SAFETY: 32 readable bytes, 32 writable; `start + n` does not overflow (caller).
    unsafe { pqsigner_v2_search43_target(sm.as_ptr(), a0, a1, start, n, crate::params::TARGET_SUM as u32, d.as_mut_ptr()) }
}

/// v2-native FORS tree (`v2-fused`): root and the auth path of `leaf_idx`, by
/// treehash, with A7 words computed from fields (no 32-byte ADRS, no padding).
#[cfg(feature = "v2-fused")]
pub fn fors_tree_fused(seed: &[u8; 32], sk_seed: &[u8; 32], ht_idx: u32, t: u32, leaf_idx: u32) -> ([u8; N], [[u8; N]; crate::params::A]) {
    use crate::params::{A, FORS_LEAVES};
    let (ht, tt) = (u64::from(ht_idx), u64::from(t));
    let mut auth = [[0u8; N]; A];
    let mut stack = [[0u8; N]; A + 1];
    let mut heights = [0u32; A + 1];
    let mut sp = 0usize;
    for j in 0..FORS_LEAVES as u32 {
        let (p0, p1) = words(pack(T_FORS_PRF, 0, ht, tt, 0, 0, u64::from(j)));
        let (a0, a1) = words(pack(T_FORS_TREE, 0, ht, tt, 0, 0, u64::from(j)));
        let mut node = [0u8; N];
        // SAFETY: 32 and 16 readable bytes, 16 writable.
        unsafe { pqsigner_v2_fors_leaf16(sk_seed.as_ptr(), p0, p1, seed.as_ptr(), a0, a1, node.as_mut_ptr()) };
        if j == leaf_idx ^ 1 {
            auth[0] = node;
        }
        let mut h = 0u32;
        while sp > 0 && heights[sp - 1] == h {
            sp -= 1;
            let parent = j >> (h + 1);
            let (a0, a1) = words(pack(T_FORS_TREE, 0, ht, tt, 0, u64::from(h + 1), u64::from(parent)));
            let mut up = [0u8; N];
            // SAFETY: 16 readable bytes each, 16 writable.
            unsafe { pqsigner_v2_node16(seed.as_ptr(), stack[sp].as_ptr(), node.as_ptr(), a0, a1, up.as_mut_ptr()) };
            node = up;
            h += 1;
            if (h as usize) < A && parent == (leaf_idx >> h) ^ 1 {
                auth[h as usize] = node;
            }
        }
        stack[sp] = node;
        heights[sp] = h;
        sp += 1;
    }
    (stack[0], auth)
}

/// v2 R grind (`v2-fused`): v1's R PRF (unchanged, spec §6) and H_MSG over two
/// prebuilt preimages through the one-shot, only the nonce and R rewritten.
#[cfg(feature = "v2-fused")]
pub fn grind_r_fused(sk_seed: &[u8; 32], pk_seed: &[u8; N], pk_root: &[u8; N], message: &[u8; 32], opt_rand: Option<&[u8; N]>) -> ([u8; N], [u8; 32]) {
    use crate::params::{A, K};
    let mut prf = [0u8; 32 + 7 + 16 + 32 + 32];
    prf[..32].copy_from_slice(sk_seed);
    prf[32..39].copy_from_slice(b"R_grind");
    let mut o = 39;
    if let Some(r) = opt_rand {
        prf[o..o + 16].copy_from_slice(r);
        o += 16;
    }
    prf[o..o + 32].copy_from_slice(message);
    o += 32;
    let len = o + 32; // nonce_b32: 28 zero bytes, then the nonce
    let mut hm = [0u8; 87];
    hm[0..16].copy_from_slice(pk_seed);
    hm[16..32].copy_from_slice(pk_root);
    hm[32..64].copy_from_slice(message);
    put7(&mut hm[80..87], pack(T_H_MSG, 0, 0, 0, 0, 0, 0));
    let last_shift = (K - 1) * A;
    let mut nonce = 0u32;
    while nonce < 10_000_000 {
        prf[len - 4..len].copy_from_slice(&nonce.to_be_bytes());
        let r = sha256_bytes16(&prf[..len]);
        hm[64..80].copy_from_slice(&r);
        let d = sha256_bytes(&hm);
        if crate::fors::read_bits_le(&d, last_shift, A) == 0 {
            for b in prf.iter_mut() {
                // SAFETY: `b` is a valid, aligned, exclusive reference.
                unsafe { core::ptr::write_volatile(b, 0) };
            }
            return (r, d);
        }
        nonce += 1;
    }
    panic!("R grinding failed after 10M iterations");
}
