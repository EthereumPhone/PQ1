//! SPHINCS+C7 parameter set constants.
//!
//! C7: W+C_F+C  h=24  d=2  a=16  k=8  w=8  l=43  target_sum=151  sig=3704
//!
//! Uses keccak256 as the hash function. All 16-byte values are stored in
//! the top 128 bits of a 32-byte word (right-padded with zeros) to match
//! the Solidity/EVM uint256 representation.

/// Security parameter: n = 128 bits = 16 bytes.
pub const N: usize = 16;

/// Total hypertree height.
pub const H: usize = 24;

/// Number of hypertree layers.
pub const D: usize = 2;

/// Height of each subtree (H / D).
pub const SUBTREE_H: usize = H / D; // 12

/// Number of leaves in each subtree.
pub const SUBTREE_LEAVES: usize = 1 << SUBTREE_H; // 4096

/// Number of FORS trees.
pub const K: usize = 8;

/// Height of each FORS tree.
pub const A: usize = 16;

/// Number of leaves in each FORS tree.
pub const FORS_LEAVES: usize = 1 << A; // 65536

/// Winternitz parameter.
pub const W: usize = 8;

/// log2(W).
pub const LOG_W: usize = 3;

/// WOTS chain count.
pub const L: usize = 43;

/// WOTS+C target digit sum for count-grinding.
pub const TARGET_SUM: usize = 151;

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
pub const SIG_FORS_TOTAL: usize = SIG_R + SIG_FORS_SECRETS + SIG_FORS_AUTH; // 1936

/// One hypertree layer: L chain values + 4-byte count + SUBTREE_H auth nodes.
pub const SIG_HT_LAYER: usize = L * N + 4 + SUBTREE_H * N; // 884

/// Total signature size.
pub const SIGNATURE_LEN: usize = SIG_FORS_TOTAL + D * SIG_HT_LAYER; // 3704

/// Signing key length: sk_seed(32) + pk_seed(16).
pub const SIGNING_KEY_SEED_LEN: usize = 32 + N;

/// Verifying key length: pk_seed(16) + pk_root(16).
pub const VERIFYING_KEY_LEN: usize = N + N;

// Compile-time sanity checks.
const _: () = assert!(SUBTREE_H * D == H);
const _: () = assert!(SIG_FORS_TOTAL == 1936);
const _: () = assert!(SIG_HT_LAYER == 884);
const _: () = assert!(SIGNATURE_LEN == 3704);

// ---------------------------------------------------------------------------
// ADRS type constants (match Solidity verifier)
// ---------------------------------------------------------------------------

pub const ADRS_WOTS: u32 = 0;
pub const ADRS_WOTS_PK: u32 = 1;
pub const ADRS_TREE: u32 = 2;
pub const ADRS_FORS_TREE: u32 = 3;
pub const ADRS_FORS_ROOTS: u32 = 4;
