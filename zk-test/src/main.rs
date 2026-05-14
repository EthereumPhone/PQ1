//! Host-side end-to-end test for ZK clear-signing verification.
//!
//! Exercises the same Poseidon hash + Groth16 pairing logic the TrustZone
//! secure world runs, but natively on the host CPU. This catches divergence
//! between the secure implementation and ZKlarity's circuit output without
//! waiting ~1 h for QEMU-emulated BLS12-381.
//!
//! Test vector: ZKlarity "Aave V3 supply 1000 USDC" proof (`proof_supply.json`).

use bls12_381::{miller_loop_4, pairing, G1Affine, G1Projective, G2Affine, Gt, Scalar};
use sha2::{Digest, Sha256};
use std::time::Instant;

// Include the same generated / committed constant files the secure world uses.
// `#[allow(dead_code)]`: the modules export several arities we don't exercise
// here (we only need Poseidon{3,6}) and a few sibling constants we don't read.
#[allow(dead_code)]
#[path = "../../secure/src/zk/generated/poseidon_constants.rs"]
mod poseidon_constants;

#[allow(dead_code)]
#[path = "../../secure/src/zk/test_vectors.rs"]
mod test_vectors;

#[allow(dead_code)]
#[path = "../../secure/src/zk/vk_data.rs"]
mod vk_data;

use poseidon_constants::{poseidon3, poseidon6, ScalarBytes};

// ── Poseidon (mirrors `secure/src/zk/poseidon.rs`) ───────────────────────────

/// Maximum state width across the arities this harness supports.
/// Sized for `poseidon6` (t=7); kept at 8 to match the secure side.
const MAX_T: usize = 8;

/// Bytes-per-block in the Poseidon byte-absorbing construction. Each block
/// packs 31 bytes into one scalar (≤ field modulus, no reduction needed).
const BYTES_PER_BLOCK: usize = 31;

fn scalar_from_le(bytes: &ScalarBytes) -> Scalar {
    Option::from(Scalar::from_bytes(bytes)).expect("invalid scalar in constant table")
}

#[inline(always)]
fn sbox(x: Scalar) -> Scalar {
    let x2 = x * x;
    x2 * x2 * x
}

fn mds_mix(state: &mut [Scalar; MAX_T], mds: &[[Scalar; MAX_T]; MAX_T], t: usize) {
    let mut out = [Scalar::zero(); MAX_T];
    for i in 0..t {
        let mut acc = Scalar::zero();
        for k in 0..t {
            acc += mds[i][k] * state[k];
        }
        out[i] = acc;
    }
    state[..t].copy_from_slice(&out[..t]);
}

fn poseidon_perm(
    inputs: &[Scalar],
    t: usize,
    rf: usize,
    rp: usize,
    rc: &[ScalarBytes],
    mds_raw: &[[ScalarBytes; MAX_T]; MAX_T],
) -> Scalar {
    let rf_half = rf / 2;

    // State: [capacity=0, input_0, input_1, ...].
    let mut state = [Scalar::zero(); MAX_T];
    for (i, inp) in inputs.iter().enumerate() {
        state[i + 1] = *inp;
    }

    // Pre-decode the MDS matrix.
    let mut mds = [[Scalar::zero(); MAX_T]; MAX_T];
    for i in 0..t {
        for j in 0..t {
            mds[i][j] = scalar_from_le(&mds_raw[i][j]);
        }
    }

    let mut rc_idx = 0;
    let full_round = |state: &mut [Scalar; MAX_T], rc_idx: &mut usize| {
        for j in 0..t {
            state[j] += scalar_from_le(&rc[*rc_idx]);
            *rc_idx += 1;
        }
        for j in 0..t {
            state[j] = sbox(state[j]);
        }
        mds_mix(state, &mds, t);
    };

    for _ in 0..rf_half {
        full_round(&mut state, &mut rc_idx);
    }
    for _ in 0..rp {
        for j in 0..t {
            state[j] += scalar_from_le(&rc[rc_idx]);
            rc_idx += 1;
        }
        state[0] = sbox(state[0]);
        mds_mix(&mut state, &mds, t);
    }
    for _ in 0..rf_half {
        full_round(&mut state, &mut rc_idx);
    }

    state[0]
}

/// Lift an arity-specific MDS table into the `MAX_T`-shaped buffer the
/// permutation expects, padding the lower-right corner with zeros.
fn pad_mds<const T: usize>(src: &[[ScalarBytes; T]; T]) -> [[ScalarBytes; MAX_T]; MAX_T] {
    let mut padded = [[[0u8; 32]; MAX_T]; MAX_T];
    for i in 0..T {
        for j in 0..T {
            padded[i][j] = src[i][j];
        }
    }
    padded
}

/// Poseidon hash of `n` bytes from `bytes` (zero-padded to a multiple of 31).
fn poseidon_bytes(bytes: &[u8], n: usize) -> Scalar {
    let n_blocks = n.div_ceil(BYTES_PER_BLOCK);
    let mut fields = [Scalar::zero(); 7];
    let base = Scalar::from(256u64);
    for b in 0..n_blocks {
        let mut acc = Scalar::zero();
        for i in 0..BYTES_PER_BLOCK {
            let idx = b * BYTES_PER_BLOCK + i;
            let byte = if idx < n && idx < bytes.len() { bytes[idx] } else { 0 };
            acc = acc * base + Scalar::from(u64::from(byte));
        }
        fields[b] = acc;
    }

    let inputs = &fields[..n_blocks];
    match n_blocks {
        3 => poseidon_perm(
            inputs,
            poseidon3::T,
            poseidon3::RF,
            poseidon3::RP,
            &poseidon3::RC,
            &pad_mds(&poseidon3::MDS),
        ),
        6 => poseidon_perm(
            inputs,
            poseidon6::T,
            poseidon6::RF,
            poseidon6::RP,
            &poseidon6::RC,
            &pad_mds(&poseidon6::MDS),
        ),
        other => panic!("unsupported Poseidon block count: {other}"),
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// `aabbccdd...wwxxyyzz` short fingerprint of a 32-byte digest.
fn hex_fingerprint(b: &[u8; 32]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}...{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[28], b[29], b[30], b[31],
    )
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// Uncompressed BLS12-381 G1 / G2 element lengths.
const G1_BYTES: usize = 96;
const G2_BYTES: usize = 192;

fn g1_from(label: &str, bytes: &[u8]) -> G1Affine {
    let arr: &[u8; G1_BYTES] = bytes.try_into().expect("g1 slice must be 96 bytes");
    Option::from(G1Affine::from_uncompressed(arr))
        .unwrap_or_else(|| panic!("failed to deserialize G1 point {label}"))
}

fn g2_from(label: &str, bytes: &[u8]) -> G2Affine {
    let arr: &[u8; G2_BYTES] = bytes.try_into().expect("g2 slice must be 192 bytes");
    Option::from(G2Affine::from_uncompressed(arr))
        .unwrap_or_else(|| panic!("failed to deserialize G2 point {label}"))
}

/// Verification key byte layout (alpha ‖ beta ‖ gamma ‖ delta ‖ IC[0..=2]).
struct VerificationKey {
    alpha: G1Affine,
    beta: G2Affine,
    gamma: G2Affine,
    delta: G2Affine,
    ic: [G1Affine; 3],
}

impl VerificationKey {
    fn parse(bytes: &[u8]) -> Self {
        // Offsets walk through the seven serialized points in order.
        let (mut o, g1, g2) = (0usize, G1_BYTES, G2_BYTES);
        let alpha = g1_from("VK.alpha", &bytes[o..o + g1]); o += g1;
        let beta  = g2_from("VK.beta",  &bytes[o..o + g2]); o += g2;
        let gamma = g2_from("VK.gamma", &bytes[o..o + g2]); o += g2;
        let delta = g2_from("VK.delta", &bytes[o..o + g2]); o += g2;
        let ic0   = g1_from("VK.IC[0]", &bytes[o..o + g1]); o += g1;
        let ic1   = g1_from("VK.IC[1]", &bytes[o..o + g1]); o += g1;
        let ic2   = g1_from("VK.IC[2]", &bytes[o..o + g1]); o += g1;
        debug_assert_eq!(o, bytes.len(), "VK byte stream not fully consumed");
        Self { alpha, beta, gamma, delta, ic: [ic0, ic1, ic2] }
    }
}

// ── Main test ────────────────────────────────────────────────────────────────

fn main() {
    println!("=== ZK Clear Signing End-to-End Test ===");
    println!("Test vector: Aave V3 supply(1000 USDC)\n");

    // [1/6] Poseidon hash of calldata.
    println!("[1/6] Computing H_tx = Poseidon(calldata, 164)...");
    let t0 = Instant::now();
    let h_tx = poseidon_bytes(&test_vectors::TEST_CALLDATA, 164);
    let h_tx_bytes = h_tx.to_bytes();
    println!("      H_tx = {}", hex_fingerprint(&h_tx_bytes));
    assert_eq!(
        h_tx_bytes, test_vectors::TEST_H_TX,
        "H_tx mismatch! Poseidon hash does not match ZKlarity's output"
    );
    println!("      MATCH — matches ZKlarity public_supply.json");
    println!("      ({:.1}ms)\n", t0.elapsed().as_secs_f64() * 1e3);

    // [2/6] Poseidon hash of readable string.
    println!("[2/6] Computing H_str = Poseidon(readable, 64)...");
    let t0 = Instant::now();
    let h_str = poseidon_bytes(&test_vectors::TEST_READABLE, 64);
    let h_str_bytes = h_str.to_bytes();
    println!("      H_str = {}", hex_fingerprint(&h_str_bytes));
    assert_eq!(
        h_str_bytes, test_vectors::TEST_H_STR,
        "H_str mismatch! Poseidon hash does not match ZKlarity's output"
    );
    println!("      MATCH — matches ZKlarity public_supply.json");
    let readable_str = std::str::from_utf8(&test_vectors::TEST_READABLE)
        .expect("TEST_READABLE is not valid UTF-8")
        .trim_end_matches('\0');
    println!("      Display: \"{readable_str}\"");
    println!("      ({:.1}ms)\n", t0.elapsed().as_secs_f64() * 1e3);

    // [3/6] VK authenticity (SHA-256 commitment).
    println!("[3/6] Verifying VK authenticity (SHA-256)...");
    let vk_hash = sha256(&vk_data::VK_BYTES);
    assert_eq!(vk_hash, vk_data::VK_HASH, "VK hash mismatch!");
    println!("      VK hash = {}", hex_fingerprint(&vk_hash));
    println!("      MATCH — VK authenticated\n");

    // [4/6] Deserialize proof and VK.
    println!("[4/6] Deserializing Groth16 proof and verification key...");
    let proof_a = g1_from("pi.A", &test_vectors::TEST_PROOF_A);
    let proof_b = g2_from("pi.B", &test_vectors::TEST_PROOF_B);
    let proof_c = g1_from("pi.C", &test_vectors::TEST_PROOF_C);
    let vk = VerificationKey::parse(&vk_data::VK_BYTES);
    println!("      Proof: pi.A, pi.B, pi.C — OK");
    println!("      VK: alpha, beta, gamma, delta, IC[0..2] — OK\n");

    // vk_x = IC[0] + h_tx · IC[1] + h_str · IC[2].
    let vk_x = G1Affine::from(
        G1Projective::from(vk.ic[0])
            + G1Projective::from(vk.ic[1]) * h_tx
            + G1Projective::from(vk.ic[2]) * h_str,
    );

    // [5/6] Groth16 verification — 4 individual pairings.
    println!("[5/6] Running Groth16 verification (4 individual pairings)...");
    println!("      e(pi.A, pi.B) . e(-alpha, beta) . e(-vk_x, gamma) . e(-pi.C, delta) == 1?");
    let t0 = Instant::now();
    let result = pairing(&proof_a, &proof_b)
        + pairing(&(-vk.alpha), &vk.beta)
        + pairing(&(-vk_x), &vk.gamma)
        + pairing(&(-proof_c), &vk.delta);
    let valid = result == Gt::identity();
    let time_individual = t0.elapsed();
    println!(
        "      Result: {} ({:.1}ms with 4 individual pairings)",
        if valid { "VALID" } else { "INVALID" },
        time_individual.as_secs_f64() * 1e3
    );
    assert!(valid, "Groth16 verification FAILED (individual pairings)!");

    // [6/6] Groth16 verification — multi-Miller loop + single final exp.
    println!("\n[6/6] Running Groth16 verification (multi-Miller loop, 1 final exp)...");
    let t0 = Instant::now();
    let neg_alpha = -vk.alpha;
    let neg_vk_x = -vk_x;
    let neg_c = -proof_c;
    let valid_multi = miller_loop_4([
        (&proof_a, &proof_b),
        (&neg_alpha, &vk.beta),
        (&neg_vk_x, &vk.gamma),
        (&neg_c, &vk.delta),
    ])
    .final_exponentiation()
        == Gt::identity();
    let time_multi = t0.elapsed();
    println!(
        "      Result: {} ({:.1}ms with multi-Miller loop)",
        if valid_multi { "VALID" } else { "INVALID" },
        time_multi.as_secs_f64() * 1e3
    );
    assert!(valid_multi, "Groth16 verification FAILED (multi-Miller loop)!");

    let speedup = time_individual.as_secs_f64() / time_multi.as_secs_f64().max(f64::EPSILON);
    println!("      Speedup: {speedup:.1}x");

    println!("\n=== ALL CHECKS PASSED ===");
    println!("  Poseidon(calldata)  matches ZKlarity circuit output");
    println!("  Poseidon(readable)  matches ZKlarity circuit output");
    println!("  VK hash             matches committed vk_data::VK_HASH");
    println!("  Groth16 proof       VALID — \"{readable_str}\" is a faithful");
    println!("                      representation of the Aave supply calldata");
    println!("\nThis is exactly what the secure world would execute for CMD_CLEAR_SIGN.");
}
