//! SHA-256-based tweakable hash primitives.
//!
//! Every function in this module must produce byte-identical output to the
//! corresponding Solidity/Yul code in `SPHINCsC10Asm.sol` (which calls the
//! SHA-256 precompile at address 0x02) and the host-side reference signer.
//!
//! Convention: all 16-byte (n=128-bit) values are stored in the **top**
//! 128 bits of a 32-byte buffer (left-aligned, right-zero-padded). This
//! matches the EVM uint256 big-endian representation where a 128-bit value
//! occupies bytes [0..16) and bytes [16..32) are zero.
//!
//! Default build uses software `sha2::Sha256`. With the `hw-sha256`
//! feature the crate calls three extern symbols the linked binary must
//! provide (`pqsigner_sha256_init / update / final`) — the secure firmware
//! routes these to the STM32U585 HASH peripheral for ~19x FORS+C keygen
//! speedup.

pub(crate) use inner::{Digest, Sha256};

use crate::params::N;

#[cfg(not(feature = "hw-sha256"))]
mod inner {
    pub use sha2::{Digest, Sha256};
}

#[cfg(feature = "hw-sha256")]
mod inner {
    extern "C" {
        fn pqsigner_sha256_init();
        fn pqsigner_sha256_update(ptr: *const u8, len: usize);
        fn pqsigner_sha256_final(out: *mut u8);
    }

    pub trait Digest: Sized {
        fn new() -> Self;
        fn update(&mut self, data: impl AsRef<[u8]>);
        fn finalize(self) -> [u8; 32];
    }

    pub struct Sha256;

    impl Digest for Sha256 {
        fn new() -> Self {
            unsafe { pqsigner_sha256_init() };
            Self
        }
        fn update(&mut self, data: impl AsRef<[u8]>) {
            let b = data.as_ref();
            unsafe { pqsigner_sha256_update(b.as_ptr(), b.len()) };
        }
        fn finalize(self) -> [u8; 32] {
            let mut out = [0u8; 32];
            unsafe { pqsigner_sha256_final(out.as_mut_ptr()) };
            out
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Pad a 16-byte value to 32 bytes (right-zero-padded, matching EVM uint256
/// for an n=128-bit value: the value sits in bytes [0..16)).
#[inline]
pub fn pad16(val: &[u8; N]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..N].copy_from_slice(val);
    out
}

/// Truncate a 32-byte SHA-256 digest to the top N=16 bytes.
#[inline]
pub fn truncate(digest: &[u8; 32]) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&digest[..N]);
    out
}

/// Encode a u64 as a 32-byte big-endian value (uint256 representation).
/// The value sits in bytes [24..32), matching Python's `int.to_bytes(32, "big")`.
#[inline]
fn u64_to_b32(v: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&v.to_be_bytes());
    out
}

/// Encode a u32 as a 32-byte big-endian value (uint256 representation).
/// The value sits in bytes [28..32), matching Python's `int.to_bytes(32, "big")`.
#[inline]
fn u32_to_b32(v: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[28..32].copy_from_slice(&v.to_be_bytes());
    out
}

// ---------------------------------------------------------------------------
// Tweakable hash primitives
// ---------------------------------------------------------------------------

/// `th(seed, adrs, val)` — tweakable hash with one 32-byte input.
///
/// `sha256(seed_b32 || adrs_b32 || val_b32)[0..N]`
///
/// Matches Solidity: `and(sha256_precompile(0x00, 0x60), N_MASK)` with
/// `mstore(0x00, seed)`, `mstore(0x20, adrs)`, `mstore(0x40, val)`.
pub fn th(seed: &[u8; 32], adrs: &[u8; 32], val: &[u8; 32]) -> [u8; N] {
    let mut h = Sha256::new();
    h.update(seed);
    h.update(adrs);
    h.update(val);
    truncate(&h.finalize().into())
}

/// `th_pair(seed, adrs, left, right)` — tweakable hash with two 32-byte inputs.
///
/// `sha256(seed_b32 || adrs_b32 || left_b32 || right_b32)[0..N]`
///
/// Matches Solidity: `and(sha256_precompile(0x00, 0x80), N_MASK)`.
pub fn th_pair(
    seed: &[u8; 32],
    adrs: &[u8; 32],
    left: &[u8; 32],
    right: &[u8; 32],
) -> [u8; N] {
    let mut h = Sha256::new();
    h.update(seed);
    h.update(adrs);
    h.update(left);
    h.update(right);
    truncate(&h.finalize().into())
}

/// `th_multi(seed, adrs, vals)` — tweakable hash with variable N-byte inputs.
///
/// `sha256(seed_b32 || adrs_b32 || pad(v0) || pad(v1) || ...)[0..N]`
///
/// Each value in `vals` is a 16-byte N-value that gets padded to 32 bytes.
pub fn th_multi(seed: &[u8; 32], adrs: &[u8; 32], vals: &[[u8; N]]) -> [u8; N] {
    let mut h = Sha256::new();
    h.update(seed);
    h.update(adrs);
    for v in vals {
        h.update(pad16(v));
    }
    truncate(&h.finalize().into())
}

/// `h_msg(seed, root, R, message)` — domain-separated message hash.
///
/// `sha256(seed_b32 || root_b32 || R_b32 || message_b32 || 0xFF..FF_b32)`
///
/// Returns the **full** 32-byte digest (not truncated), because the caller
/// needs all bits for FORS index extraction and hypertree path selection.
///
/// Matches Solidity 160-byte (0xA0) input:
/// ```text
///   mstore(0x00, seed)    // seed is already bytes32 (pk_seed padded)
///   mstore(0x20, root)
///   mstore(0x40, R)
///   mstore(0x60, message)
///   mstore(0x80, 0xFFFF...FF)
///   digest := sha256_precompile(0x00, 0xA0)
/// ```
pub fn h_msg(
    seed: &[u8; 32],
    root: &[u8; 32],
    r: &[u8; 32],
    message: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(seed);
    h.update(root);
    h.update(r);
    h.update(message);
    h.update([0xFFu8; 32]);
    h.finalize().into()
}

// ---------------------------------------------------------------------------
// WOTS chain hashing
// ---------------------------------------------------------------------------

/// Iterative chain hash: apply `th` for `steps` iterations, starting
/// from position `start_pos`.
///
/// ```text
/// for pos in start..start+steps:
///     adrs.chain_pos = pos
///     val = th(seed, adrs, val)
/// return val
/// ```
///
/// Returns the final 16-byte chain value.
pub fn chain_hash(
    seed: &[u8; 32],
    adrs: &[u8; 32],
    val: &[u8; N],
    start_pos: u32,
    steps: u32,
) -> [u8; N] {
    let mut current = pad16(val);
    let mut a = *adrs;
    for step in 0..steps {
        let pos = start_pos + step;
        // Set chain_pos field at adrs bytes [24..28)
        a[24..28].copy_from_slice(&pos.to_be_bytes());
        current = pad16(&th(seed, &a, &current));
    }
    truncate(&current)
}

// ---------------------------------------------------------------------------
// WOTS+C digest and secret derivation
// ---------------------------------------------------------------------------

/// WOTS digest for count-grinding.
///
/// `sha256(seed_b32 || wotsAdrs_b32 || msgHash_b32 || count_uint256)`
///
/// Returns the full 32-byte digest for base-w digit extraction.
pub fn wots_digest(
    seed: &[u8; 32],
    wots_adrs: &[u8; 32],
    msg_hash: &[u8; 32],
    count: u32,
) -> [u8; 32] {
    let count_b32 = u32_to_b32(count);
    let mut h = Sha256::new();
    h.update(seed);
    h.update(wots_adrs);
    h.update(msg_hash);
    h.update(&count_b32);
    h.finalize().into()
}

/// WOTS secret key derivation.
///
/// ```text
/// sha256(sk_seed_b32 || "wots" || to_b4(layer) || to_b32(tree)
///        || to_b4(kp) || to_b4(chain_idx))[0..N]
/// ```
///
/// Note the mixed widths: `layer`, `kp`, `chain_idx` are 4-byte (`to_b4`),
/// but `tree` is 32-byte (`to_b32`).
pub fn wots_secret(
    sk_seed: &[u8; 32],
    layer: u32,
    tree: u64,
    kp: u32,
    chain_idx: u32,
) -> [u8; N] {
    let tree_b32 = u64_to_b32(tree);
    let mut h = Sha256::new();
    h.update(sk_seed);
    h.update(b"wots");
    h.update(layer.to_be_bytes()); // to_b4(layer) — 4 bytes
    h.update(&tree_b32); // to_b32(tree) — 32 bytes
    h.update(kp.to_be_bytes()); // to_b4(kp) — 4 bytes
    h.update(chain_idx.to_be_bytes()); // to_b4(chain_idx) — 4 bytes
    truncate(&h.finalize().into())
}

// ---------------------------------------------------------------------------
// FORS secret derivation
// ---------------------------------------------------------------------------

/// FORS secret key derivation.
///
/// `sha256(sk_seed_b32 || "fors" || to_b4(tree_idx) || to_b4(leaf_idx))[0..N]`
pub fn fors_secret(sk_seed: &[u8; 32], tree_idx: u32, leaf_idx: u32) -> [u8; N] {
    let mut h = Sha256::new();
    h.update(sk_seed);
    h.update(b"fors");
    h.update(tree_idx.to_be_bytes()); // to_b4
    h.update(leaf_idx.to_be_bytes()); // to_b4
    truncate(&h.finalize().into())
}
