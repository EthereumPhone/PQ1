//! Poseidon hash over the BLS12-381 scalar field.
//!
//! Matches the `poseidon-bls12381` npm package used by the Circom circuits
//! (and byte-compatible with `poseidon-bls12381-circom`'s `Poseidon255`
//! template). The implementation follows the Hades design strategy:
//!
//!   state = [0, input_0, input_1, ..., input_{N-1}]   (capacity = 0 at index 0)
//!   for RF/2 full rounds:   ARK → S-box(all) → MDS
//!   for RP   partial rounds: ARK → S-box([0]) → MDS
//!   for RF/2 full rounds:   ARK → S-box(all) → MDS
//!   output = state[0]
//!
//! S-box: x^5 (alpha = 5)
//!
//! Supported arities (all the ones the v3 CowSwap EIP-712 stack needs):
//!
//!   - `poseidon2` (t=3) — binary Merkle internal-node hashing
//!   - `poseidon3` (t=4) — legacy 64 B Poseidon input (3 blocks)
//!   - `poseidon5` (t=6) — 128 B readable (v3) → 5 blocks → H_str
//!   - `poseidon6` (t=7) — 164 B canonical (v2) / 6-field Merkle leaf
//!   - `poseidon7` (t=8) — 204 B canonical (v3) → 7 blocks → H_tx

use bls12_381::Scalar;
use super::poseidon_constants::{
    poseidon2, poseidon3, poseidon5, poseidon6, poseidon7, ScalarBytes,
};

/// Maximum state width. `poseidon7` has t=8, so MAX_T=8.
const MAX_T: usize = 8;

/// Convert a 32-byte LE array to a Scalar.
fn scalar_from_le(bytes: &ScalarBytes) -> Scalar {
    Option::from(Scalar::from_bytes(bytes)).expect("invalid scalar")
}

/// x^5 in the scalar field.
#[inline(always)]
fn sbox(x: Scalar) -> Scalar {
    let x2 = x * x;
    let x4 = x2 * x2;
    x4 * x
}

/// Multiply state by the MDS matrix (in-place).
#[inline]
fn mds_mix(state: &mut [Scalar; MAX_T], mds: &[[Scalar; MAX_T]; MAX_T], t: usize) {
    let mut out = [Scalar::zero(); MAX_T];
    for i in 0..t {
        let mut acc = Scalar::zero();
        for k in 0..t {
            acc += mds[i][k] * state[k];
        }
        out[i] = acc;
    }
    for i in 0..t {
        state[i] = out[i];
    }
}

/// Run the Poseidon permutation for the given (RF, RP, RC, MDS) instance.
fn poseidon_perm(
    inputs: &[Scalar],
    t: usize,
    rf: usize,
    rp: usize,
    rc: &[ScalarBytes],
    mds_raw: &[[ScalarBytes; MAX_T]; MAX_T],
) -> Scalar {
    let rf_half = rf / 2;

    // Initialize state: [capacity=0, input_0, input_1, ...]
    let mut state = [Scalar::zero(); MAX_T];
    for (i, inp) in inputs.iter().enumerate() {
        state[i + 1] = *inp;
    }

    // Pre-load MDS matrix into Scalars.
    let mut mds = [[Scalar::zero(); MAX_T]; MAX_T];
    for i in 0..t {
        for j in 0..t {
            mds[i][j] = scalar_from_le(&mds_raw[i][j]);
        }
    }

    let mut rc_idx = 0;

    // Full rounds (first half).
    for _ in 0..rf_half {
        for j in 0..t {
            state[j] += scalar_from_le(&rc[rc_idx]);
            rc_idx += 1;
        }
        for j in 0..t {
            state[j] = sbox(state[j]);
        }
        mds_mix(&mut state, &mds, t);
    }

    // Partial rounds.
    for _ in 0..rp {
        for j in 0..t {
            state[j] += scalar_from_le(&rc[rc_idx]);
            rc_idx += 1;
        }
        state[0] = sbox(state[0]);
        mds_mix(&mut state, &mds, t);
    }

    // Full rounds (second half).
    for _ in 0..rf_half {
        for j in 0..t {
            state[j] += scalar_from_le(&rc[rc_idx]);
            rc_idx += 1;
        }
        for j in 0..t {
            state[j] = sbox(state[j]);
        }
        mds_mix(&mut state, &mds, t);
    }

    state[0]
}

/// Hash `inputs.len()` BLS12-381 scalar field elements using the matching
/// Poseidon instance. Supports arity ∈ {2, 3, 5, 6, 7} — the set of
/// instances the v3 CowSwap EIP-712 stack ever invokes.
pub fn poseidon_fields(inputs: &[Scalar]) -> Scalar {
    // Dispatch on input length. Each arm manually lifts the per-arity
    // MDS constants into the [[ScalarBytes; MAX_T]; MAX_T] shape the
    // permutation expects, filling the lower-right padding with zeros.
    let mut mds = [[[0u8; 32]; MAX_T]; MAX_T];
    match inputs.len() {
        2 => {
            for i in 0..poseidon2::T {
                for j in 0..poseidon2::T {
                    mds[i][j] = poseidon2::MDS[i][j];
                }
            }
            poseidon_perm(inputs, poseidon2::T, poseidon2::RF, poseidon2::RP, &poseidon2::RC, &mds)
        }
        3 => {
            for i in 0..poseidon3::T {
                for j in 0..poseidon3::T {
                    mds[i][j] = poseidon3::MDS[i][j];
                }
            }
            poseidon_perm(inputs, poseidon3::T, poseidon3::RF, poseidon3::RP, &poseidon3::RC, &mds)
        }
        5 => {
            for i in 0..poseidon5::T {
                for j in 0..poseidon5::T {
                    mds[i][j] = poseidon5::MDS[i][j];
                }
            }
            poseidon_perm(inputs, poseidon5::T, poseidon5::RF, poseidon5::RP, &poseidon5::RC, &mds)
        }
        6 => {
            for i in 0..poseidon6::T {
                for j in 0..poseidon6::T {
                    mds[i][j] = poseidon6::MDS[i][j];
                }
            }
            poseidon_perm(inputs, poseidon6::T, poseidon6::RF, poseidon6::RP, &poseidon6::RC, &mds)
        }
        7 => {
            for i in 0..poseidon7::T {
                for j in 0..poseidon7::T {
                    mds[i][j] = poseidon7::MDS[i][j];
                }
            }
            poseidon_perm(inputs, poseidon7::T, poseidon7::RF, poseidon7::RP, &poseidon7::RC, &mds)
        }
        _ => panic!("unsupported Poseidon arity"),
    }
}

/// Hash N bytes using Poseidon, matching the Circom circuit's
/// `PoseidonBytes(N)` template.
///
/// Bytes are packed into blocks of 31 (big-endian into field elements),
/// padded with zeros to fill the last block. Then Poseidon is applied
/// to the resulting field elements.
///
/// Supported block counts: 3 (N≤93), 5 (94..155), 6 (156..186), 7 (187..217).
/// For the v3 CowSwap EIP-712 circuit this resolves to:
///   - N=128 → 5 blocks (readable string, H_str)
///   - N=204 → 7 blocks (canonical order, H_tx)
/// Legacy callers still use N=64 (3 blocks) and N=164 (6 blocks).
pub fn poseidon_bytes(bytes: &[u8], n: usize) -> Scalar {
    let n_blocks = (n + 30) / 31; // ceil(n / 31)

    // Pack bytes into field elements (31 bytes per element, big-endian).
    // Stack-local buffer sized to cover the largest supported arity.
    let mut fields = [Scalar::zero(); MAX_T];
    let s256 = Scalar::from(256u64);
    for b in 0..n_blocks {
        let mut acc = Scalar::zero();
        for i in 0..31 {
            let idx = b * 31 + i;
            let byte_val = if idx < bytes.len() && idx < n {
                bytes[idx]
            } else {
                0u8
            };
            acc = acc * s256 + Scalar::from(byte_val as u64);
        }
        fields[b] = acc;
    }

    poseidon_fields(&fields[..n_blocks])
}
