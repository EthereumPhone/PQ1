//! SPHINCS+C10 parameter set constants.
//!
//! C10: W+C_F+C  h=18  d=2  a=11  k=13  w=8  l=43  target_sum=205  sig=4008
//!
//! C10 is used both for the **bootstrap** (master) identity of the PQSigner
//! OS wallet and for every per-slot signing key. The hypertree holds
//! 2^18 = 262,144 signing positions; the on-chain `bootstrapUses` and
//! `slotUses` counters cap actual usage at 65,536 per chain (per slot) to
//! leave a conservative security margin on the SPHINCS+ birthday-style
//! bounds. After 65,536 slot-registration Type 1s on a given chain the
//! wallet freezes further rotations on that chain; the active slot keeps
//! signing until its own slotUses cap.
//!
//! Uses sha256 as the hash function. All 16-byte values are stored in
//! the top 128 bits of a 32-byte word (right-padded with zeros) to match
//! the Solidity/EVM uint256 representation.

/// Security parameter: n = 128 bits = 16 bytes.
pub const N: usize = 16;

/// Total hypertree height.
pub const H: usize = 18;

/// Number of hypertree layers.
pub const D: usize = 2;

/// Height of each subtree (H / D).
pub const SUBTREE_H: usize = H / D; // 9

/// Number of leaves in each subtree.
pub const SUBTREE_LEAVES: usize = 1 << SUBTREE_H; // 512

/// Largest per-layer subtree height (array bound). `SUBTREE_H` unless the
/// RESEARCH variant `v2-split810` (format-options check, 2026-11-13; not
/// adopted) splits the hypertree into layer heights (8, 10).
#[cfg(not(feature = "v2-split810"))]
pub const MAX_LAYER_H: usize = SUBTREE_H;
#[cfg(feature = "v2-split810")]
pub const MAX_LAYER_H: usize = 10;

/// Subtree height at hypertree layer `layer` (0 = bottom).
#[inline(always)]
#[must_use]
pub const fn layer_h(layer: u32) -> usize {
    #[cfg(feature = "v2-split810")]
    {
        if layer == 0 {
            8
        } else {
            10
        }
    }
    #[cfg(not(feature = "v2-split810"))]
    {
        let _ = layer;
        SUBTREE_H
    }
}
const _: () = assert!(layer_h(0) + layer_h(1) == H && layer_h(0) <= MAX_LAYER_H && layer_h(1) <= MAX_LAYER_H);

/// Number of FORS trees.
pub const K: usize = 13;

/// Height of each FORS tree.
pub const A: usize = 11;

/// Number of leaves in each FORS tree.
pub const FORS_LEAVES: usize = 1 << A; // 2048

/// Winternitz parameter.
pub const W: usize = 8;

/// log2(W).
pub const LOG_W: usize = 3;

/// WOTS chain count.
pub const L: usize = 43;

/// WOTS+C target digit sum for count-grinding.
#[cfg(not(feature = "v2-ts200"))]
pub const TARGET_SUM: usize = 205;
/// RESEARCH (format-options check, 2026-11-13): v2 with target sum 200. Not adopted.
#[cfg(feature = "v2-ts200")]
pub const TARGET_SUM: usize = 200;

/// Bit mask for extracting a single base-w digit.
pub const W_MASK: u8 = (W - 1) as u8; // 0x07

// ---------------------------------------------------------------------------
// Signature layout sizes
// ---------------------------------------------------------------------------

/// R (randomizer): N bytes.
const SIG_R: usize = N;

/// FORS secrets: K * N bytes.
const SIG_FORS_SECRETS: usize = K * N;

/// FORS auth paths: (K-1) trees * A levels * N bytes.
/// The last tree is forced-zero and emits only its secret (the root),
/// so it has no authentication path.
const SIG_FORS_AUTH: usize = (K - 1) * A * N;

/// Total FORS section: R + secrets + auth paths.
pub const SIG_FORS_TOTAL: usize = SIG_R + SIG_FORS_SECRETS + SIG_FORS_AUTH; // 2336

/// One hypertree layer: L chain values + 4-byte count + SUBTREE_H auth nodes.
/// (Under the research variant `v2-split810` the two layers differ, 820 and
/// 852 bytes; use `layer_h`. The total `SIGNATURE_LEN` is unchanged.)
pub const SIG_HT_LAYER: usize = L * N + 4 + SUBTREE_H * N; // 836

/// The layer-0 section of the signature (research tooling: equals
/// `SIG_HT_LAYER` unless the layer heights differ).
pub const SIG_HT_LAYER0: usize = L * N + 4 + layer_h(0) * N;

/// Total signature size.
pub const SIGNATURE_LEN: usize = SIG_FORS_TOTAL + D * SIG_HT_LAYER; // 4008

/// Signing key length: sk_seed(32) + pk_seed(16).
pub const SIGNING_KEY_SEED_LEN: usize = 32 + N;

/// Verifying key length: pk_seed(16) + pk_root(16).
pub const VERIFYING_KEY_LEN: usize = N + N;

// Compile-time sanity checks.
const _: () = assert!(SUBTREE_H * D == H);
const _: () = assert!(SIG_FORS_TOTAL == 2336);
const _: () = assert!(SIG_HT_LAYER == 836);
const _: () = assert!(SIGNATURE_LEN == 4008);

// ---------------------------------------------------------------------------
// ADRS type constants (match Solidity verifier)
// ---------------------------------------------------------------------------

pub const ADRS_WOTS: u32 = 0;
pub const ADRS_WOTS_PK: u32 = 1;
pub const ADRS_TREE: u32 = 2;
pub const ADRS_FORS_TREE: u32 = 3;
pub const ADRS_FORS_ROOTS: u32 = 4;
