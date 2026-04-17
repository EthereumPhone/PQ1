//! JARDIN FORS+C Variant 2 parameter constants.
//!
//! k=26 trees, a=5 height (32 leaves/tree), n=16 bytes (128-bit security),
//! Q_MAX=95 signatures per slot.
//!
//! Uses sha256 as the hash function. All 16-byte values are stored in
//! the top 128 bits of a 32-byte word (right-padded with zeros) to match
//! the Solidity/EVM uint256 representation.

/// Security parameter: n = 128 bits = 16 bytes.
pub const N: usize = 16;

/// Number of FORS trees.
pub const K: usize = 26;

/// Height of each FORS tree (2^5 = 32 leaves).
pub const A: usize = 5;

/// Bit mask for extracting a single A-bit FORS index.
pub const A_MASK: u32 = (1 << A) - 1; // 0x1F

/// Number of leaves in each FORS tree.
pub const FORS_LEAVES: usize = 1 << A; // 32

/// Maximum signatures per slot.
pub const Q_MAX: usize = 95;

// ---------------------------------------------------------------------------
// ADRS type constants (match Solidity verifier)
// ---------------------------------------------------------------------------

/// FORS tree leaf hash and internal nodes.
pub const ADRS_FORS_TREE: u32 = 3;

/// Compress K FORS roots into forsPk.
pub const ADRS_FORS_ROOTS: u32 = 4;

/// Unbalanced tree auth path nodes.
pub const ADRS_UNBALANCED: u32 = 6;

// ---------------------------------------------------------------------------
// Signature layout sizes
// ---------------------------------------------------------------------------

/// R (randomizer): full 32 bytes (not truncated to N).
const SIG_R: usize = 32;

/// Counter: 4 bytes big-endian u32.
const SIG_COUNTER: usize = 4;

/// Per-tree FORS opening: secret(N) + auth_path(A * N).
const SIG_FORS_OPENING: usize = N + A * N; // 16 + 80 = 96

/// 25 normal FORS tree openings (tree 25 is forced-zero, no auth path).
const SIG_FORS_OPENINGS: usize = (K - 1) * SIG_FORS_OPENING; // 25 * 96 = 2400

/// Last tree root (forced-zero optimization): just the root, no auth path.
const SIG_LAST_ROOT: usize = N; // 16

/// Fixed body: everything before the variable-length unbalanced auth path.
pub const FORSC_BODY: usize = SIG_R + SIG_COUNTER + SIG_FORS_OPENINGS + SIG_LAST_ROOT; // 2452

/// Minimum signature size (q=1): body + 1 unbalanced auth node.
pub const SIG_MIN: usize = FORSC_BODY + N; // 2468

/// Maximum signature size (q=Q_MAX): body + Q_MAX unbalanced auth nodes.
pub const SIG_MAX: usize = FORSC_BODY + Q_MAX * N; // 3972

// ---------------------------------------------------------------------------
// Compile-time sanity checks
// ---------------------------------------------------------------------------

const _: () = assert!(SIG_FORS_OPENING == 96);
const _: () = assert!(SIG_FORS_OPENINGS == 2400);
const _: () = assert!(FORSC_BODY == 2452);
const _: () = assert!(SIG_MIN == 2468);
const _: () = assert!(SIG_MAX == 3972);
const _: () = assert!(K * A == 130); // 130 bits of FORS security
