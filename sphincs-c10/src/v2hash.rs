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

/// A7 (spec §1): fixed field positions whatever the type. A field that does
/// not fit its width is rejected in every build (spec §1; Astra 0.3 review:
/// `ha = 2048` would otherwise encode as `cp = 1, ha = 0`). Callers derive every
/// field from bounded indices, so this never fires on a valid path.
#[inline(always)]
pub fn pack(ty: u64, layer: u64, tree: u64, kp: u64, ci: u64, cp: u64, ha: u64) -> u64 {
    assert!(ty < 16 && layer < 2 && tree < (1 << 18) && kp < (1 << 9));
    assert!(ci < (1 << 6) && cp < 16 && ha < (1 << 11));
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

// WOTS digits are v1's (spec 0.3): `wots::extract_digits` and `wots::digit_sum`
// run unchanged under v2.

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
    fn pqsigner_v2_wots_pk16(
        sk: *const u8, p0: u32, p1: u32, seed: *const u8, a0: u32, a1: u32, k0: u32, k1: u32, steps: u32, out: *mut u8,
    );
    fn pqsigner_v2_fors_subtree16(
        sk: *const u8, seed: *const u8, p0: u32, p1: u32, a0: u32, a1: u32, j0: u32, h: u32, out: *mut u8,
    );
    fn pqsigner_v2_grind_r(prf: *const u8, len: u32, hm: *const u8, start: u32, n: u32, out_r: *mut u8, out_d: *mut u8) -> u32;
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
    let mut sm = [0u8; 32];
    sm[..16].copy_from_slice(&seed[..16]);
    sm[16..].copy_from_slice(&msg_hash[..16]);
    let (a0, a1) = words(pack(T_WOTS_DIGEST, u64::from(layer), tree, u64::from(kp), 0, 0, 0));
    // SAFETY: 32 readable bytes, 32 writable; `start + n` does not overflow (caller).
    unsafe { pqsigner_v2_search43_target(sm.as_ptr(), a0, a1, start, n, crate::params::TARGET_SUM as u32, d.as_mut_ptr()) }
}

/// WOTS public key of key pair `kp` (`v2-fused`): all 43 chains to the end and
/// the T_43 compression `S ‖ A7(WOTS_PK) ‖ 0x00 ‖ v_0 ‖ … ‖ v_42`, in one
/// driver call.
#[cfg(feature = "v2-fused")]
pub fn wots_pk_fused(seed: &[u8; 32], sk_seed: &[u8; 32], layer: u32, tree: u64, kp: u32) -> [u8; N] {
    let (l, k) = (u64::from(layer), u64::from(kp));
    let (p0, p1) = words(pack(T_WOTS_PRF, l, tree, k, 0, 0, 0));
    let (a0, a1) = words(pack(T_WOTS_HASH, l, tree, k, 0, 0, 0));
    let (k0, k1) = words(pack(T_WOTS_PK, l, tree, k, 0, 0, 0));
    let mut out = [0u8; N];
    // SAFETY: 32 and 16 readable bytes, 16 writable; steps = W - 1 = 7.
    unsafe {
        pqsigner_v2_wots_pk16(sk_seed.as_ptr(), p0, p1, seed.as_ptr(), a0, a1, k0, k1, (crate::params::W - 1) as u32, out.as_mut_ptr())
    };
    out
}

/// Root of the FORS subtree of height `h` over leaves `j0..j0 + 2^h` of FORS
/// tree `t` at `ht_idx`, in one driver call (`v2-fused`).
#[cfg(feature = "v2-fused")]
fn fors_subtree_fused(seed: &[u8; 32], sk_seed: &[u8; 32], ht_idx: u32, t: u32, j0: u32, h: u32) -> [u8; N] {
    let (ht, tt) = (u64::from(ht_idx), u64::from(t));
    let (p0, p1) = words(pack(T_FORS_PRF, 0, ht, tt, 0, 0, 0));
    let (a0, a1) = words(pack(T_FORS_TREE, 0, ht, tt, 0, 0, 0));
    let mut out = [0u8; N];
    // SAFETY: 32 and 16 readable bytes, 16 writable; `h <= A` and `j0` is a
    // multiple of `2^h` inside the tree (both callers below).
    unsafe { pqsigner_v2_fors_subtree16(sk_seed.as_ptr(), seed.as_ptr(), p0, p1, a0, a1, j0, h, out.as_mut_ptr()) };
    out
}

/// FORS tree root (`v2-fused`): the subtree of height `A` at leaf 0.
#[cfg(feature = "v2-fused")]
pub fn fors_root_fused(seed: &[u8; 32], sk_seed: &[u8; 32], ht_idx: u32, t: u32) -> [u8; N] {
    fors_subtree_fused(seed, sk_seed, ht_idx, t, 0, crate::params::A as u32)
}

/// Auth path of `leaf_idx` (`v2-fused`): `auth[h]` is the sibling at height
/// `h`, the root of the height-`h` subtree at leaf `((leaf_idx >> h) ^ 1) << h`.
/// Together with the leaf these subtrees cover the tree once, so the digest
/// count equals treehash's; the root is rebuilt from the path by the caller.
#[cfg(feature = "v2-fused")]
pub fn fors_auth_fused(seed: &[u8; 32], sk_seed: &[u8; 32], ht_idx: u32, t: u32, leaf_idx: u32) -> [[u8; N]; crate::params::A] {
    core::array::from_fn(|h| {
        let h = h as u32;
        fors_subtree_fused(seed, sk_seed, ht_idx, t, ((leaf_idx >> h) ^ 1) << h, h)
    })
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
    // The whole grind in one driver call (round 6 H7); the FORS+C rule is
    // re-checked here with this crate's bit reader before R is used.
    let (mut r, mut d) = ([0u8; N], [0u8; 32]);
    // SAFETY: `len` and 87 readable bytes, 16 and 32 writable; 0 + 10M fits.
    let nonce = unsafe { pqsigner_v2_grind_r(prf.as_ptr(), len as u32, hm.as_ptr(), 0, 10_000_000, r.as_mut_ptr(), d.as_mut_ptr()) };
    for b in prf.iter_mut() {
        // SAFETY: `b` is a valid, aligned, exclusive reference.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    assert!(nonce < 10_000_000, "R grinding failed after 10M iterations");
    assert!(crate::fors::read_bits_le(&d, (K - 1) * A, A) == 0, "v2 R grind: driver FORS+C check disagrees");
    (r, d)
}
