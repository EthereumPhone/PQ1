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

// ── Tests ────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::poseidon_constants::{poseidon3, poseidon6, ScalarBytes};
    use super::{
        g1_from, g2_from, hex_fingerprint, mds_mix, pad_mds, poseidon_bytes, sbox,
        scalar_from_le, sha256, test_vectors, vk_data, VerificationKey, BYTES_PER_BLOCK,
        G1_BYTES, G2_BYTES, MAX_T,
    };
    use bls12_381::{miller_loop_4, pairing, G1Affine, G1Projective, G2Affine, Gt, Scalar};

    // ── Positive: structural constants & primitives ─────────────────────────

    #[test]
    fn positive_g1_byte_constant() {
        assert_eq!(G1_BYTES, 96);
    }

    #[test]
    fn positive_g2_byte_constant() {
        assert_eq!(G2_BYTES, 192);
    }

    #[test]
    fn positive_max_t_constant() {
        assert_eq!(MAX_T, 8);
    }

    #[test]
    fn positive_bytes_per_block_constant() {
        assert_eq!(BYTES_PER_BLOCK, 31);
    }

    #[test]
    fn positive_sha256_known_abc() {
        // RFC 6234 / FIPS 180-4 KAT for "abc".
        let want: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(sha256(b"abc"), want);
    }

    #[test]
    fn positive_sha256_empty_string() {
        let want: [u8; 32] = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(sha256(b""), want);
    }

    #[test]
    fn positive_hex_fingerprint_format() {
        let mut b = [0u8; 32];
        for (i, v) in b.iter_mut().enumerate() {
            *v = u8::try_from(i).unwrap();
        }
        // First four: 00 01 02 03. Last four (indices 28..32): 1c 1d 1e 1f.
        assert_eq!(hex_fingerprint(&b), "00010203...1c1d1e1f");
    }

    #[test]
    fn positive_scalar_from_le_zero() {
        let z = [0u8; 32];
        assert_eq!(scalar_from_le(&z), Scalar::zero());
    }

    #[test]
    fn positive_scalar_from_le_one() {
        let mut b = [0u8; 32];
        b[0] = 1;
        assert_eq!(scalar_from_le(&b), Scalar::one());
    }

    #[test]
    fn positive_sbox_zero_is_zero() {
        assert_eq!(sbox(Scalar::zero()), Scalar::zero());
    }

    #[test]
    fn positive_sbox_one_is_one() {
        assert_eq!(sbox(Scalar::one()), Scalar::one());
    }

    #[test]
    fn positive_sbox_is_x_to_the_fifth() {
        // sbox = x^5 (alpha=5). Verify by direct multiplication.
        let x = Scalar::from(7u64);
        let want = x * x * x * x * x;
        assert_eq!(sbox(x), want);
    }

    #[test]
    fn positive_sbox_two_to_fifth_is_thirty_two() {
        assert_eq!(sbox(Scalar::from(2u64)), Scalar::from(32u64));
    }

    #[test]
    fn positive_pad_mds_copies_inner_and_zero_pads_corner() {
        let mut src = [[[0u8; 32]; 3]; 3];
        for i in 0..3 {
            for j in 0..3 {
                src[i][j][0] = u8::try_from(i * 3 + j + 1).unwrap();
            }
        }
        let out = pad_mds(&src);
        for i in 0..3 {
            for j in 0..3 {
                assert_eq!(out[i][j], src[i][j], "inner element ({i},{j}) must be preserved");
            }
        }
        for i in 0..MAX_T {
            for j in 0..MAX_T {
                if i >= 3 || j >= 3 {
                    assert_eq!(
                        out[i][j], [0u8; 32],
                        "pad_mds must zero-fill cell ({i},{j}) outside the source"
                    );
                }
            }
        }
    }

    #[test]
    fn positive_mds_mix_with_identity_matrix_is_noop() {
        let mut mds = [[Scalar::zero(); MAX_T]; MAX_T];
        for i in 0..MAX_T {
            mds[i][i] = Scalar::one();
        }
        let mut state = [Scalar::zero(); MAX_T];
        for i in 0..4 {
            state[i] = Scalar::from(u64::try_from(i + 1).unwrap());
        }
        let before = state;
        mds_mix(&mut state, &mds, 4);
        assert_eq!(state, before);
    }

    // ── Positive: Poseidon byte-sponge end-to-end vs ZKlarity ───────────────

    #[test]
    fn positive_poseidon_h_tx_matches_zklarity_vector() {
        let h = poseidon_bytes(&test_vectors::TEST_CALLDATA, 164);
        assert_eq!(
            h.to_bytes(),
            test_vectors::TEST_H_TX,
            "Poseidon(calldata, 164) must equal the ZKlarity-emitted H_tx"
        );
    }

    #[test]
    fn positive_poseidon_h_str_matches_zklarity_vector() {
        let h = poseidon_bytes(&test_vectors::TEST_READABLE, 64);
        assert_eq!(
            h.to_bytes(),
            test_vectors::TEST_H_STR,
            "Poseidon(readable, 64) must equal the ZKlarity-emitted H_str"
        );
    }

    #[test]
    fn positive_poseidon_is_deterministic() {
        let a = poseidon_bytes(&test_vectors::TEST_CALLDATA, 164);
        let b = poseidon_bytes(&test_vectors::TEST_CALLDATA, 164);
        assert_eq!(a.to_bytes(), b.to_bytes());
    }

    // ── Positive: VK & Groth16 ──────────────────────────────────────────────

    #[test]
    fn positive_vk_hash_matches_committed_value() {
        assert_eq!(sha256(&vk_data::VK_BYTES), vk_data::VK_HASH);
    }

    #[test]
    fn positive_vk_layout_matches_documented_length() {
        // alpha(G1) + beta(G2) + gamma(G2) + delta(G2) + IC[0..=2] (3*G1).
        assert_eq!(
            vk_data::VK_BYTES.len(),
            G1_BYTES + 3 * G2_BYTES + 3 * G1_BYTES
        );
    }

    #[test]
    fn positive_vk_parse_succeeds_end_to_end() {
        let _vk = VerificationKey::parse(&vk_data::VK_BYTES);
    }

    #[test]
    fn positive_proof_points_round_trip() {
        let _a = g1_from("pi.A", &test_vectors::TEST_PROOF_A);
        let _b = g2_from("pi.B", &test_vectors::TEST_PROOF_B);
        let _c = g1_from("pi.C", &test_vectors::TEST_PROOF_C);
    }

    fn build_vk_x(h_tx: Scalar, h_str: Scalar, vk: &VerificationKey) -> G1Affine {
        G1Affine::from(
            G1Projective::from(vk.ic[0])
                + G1Projective::from(vk.ic[1]) * h_tx
                + G1Projective::from(vk.ic[2]) * h_str,
        )
    }

    fn verify(
        proof_a: &G1Affine,
        proof_b: &G2Affine,
        proof_c: &G1Affine,
        vk_x: &G1Affine,
        vk: &VerificationKey,
    ) -> bool {
        let result = pairing(proof_a, proof_b)
            + pairing(&(-vk.alpha), &vk.beta)
            + pairing(&(-*vk_x), &vk.gamma)
            + pairing(&(-*proof_c), &vk.delta);
        result == Gt::identity()
    }

    #[test]
    fn positive_groth16_verifies_with_individual_pairings() {
        let h_tx = poseidon_bytes(&test_vectors::TEST_CALLDATA, 164);
        let h_str = poseidon_bytes(&test_vectors::TEST_READABLE, 64);
        let vk = VerificationKey::parse(&vk_data::VK_BYTES);
        let proof_a = g1_from("pi.A", &test_vectors::TEST_PROOF_A);
        let proof_b = g2_from("pi.B", &test_vectors::TEST_PROOF_B);
        let proof_c = g1_from("pi.C", &test_vectors::TEST_PROOF_C);
        let vk_x = build_vk_x(h_tx, h_str, &vk);
        assert!(verify(&proof_a, &proof_b, &proof_c, &vk_x, &vk));
    }

    #[test]
    fn positive_groth16_verifies_with_multi_miller_loop() {
        let h_tx = poseidon_bytes(&test_vectors::TEST_CALLDATA, 164);
        let h_str = poseidon_bytes(&test_vectors::TEST_READABLE, 64);
        let vk = VerificationKey::parse(&vk_data::VK_BYTES);
        let proof_a = g1_from("pi.A", &test_vectors::TEST_PROOF_A);
        let proof_b = g2_from("pi.B", &test_vectors::TEST_PROOF_B);
        let proof_c = g1_from("pi.C", &test_vectors::TEST_PROOF_C);
        let vk_x = build_vk_x(h_tx, h_str, &vk);
        let neg_alpha = -vk.alpha;
        let neg_vk_x = -vk_x;
        let neg_c = -proof_c;
        let valid = miller_loop_4([
            (&proof_a, &proof_b),
            (&neg_alpha, &vk.beta),
            (&neg_vk_x, &vk.gamma),
            (&neg_c, &vk.delta),
        ])
        .final_exponentiation()
            == Gt::identity();
        assert!(valid);
    }

    // ── Negative: structural & wire-format stability ────────────────────────
    //
    // These look "trivial" but lock invariants the rest of the system silently
    // depends on. A future refactor that bumps any of these constants would
    // diverge from ZKlarity's circuit output (poseidon scaffold) or from the
    // on-chain VK byte layout (Groth16 parser).

    #[test]
    fn negative_g1_byte_constant_must_stay_96() {
        // BLS12-381 uncompressed G1 is fixed at 96 bytes by the curve spec.
        // If a refactor shrinks this, VK::parse silently slices the wrong
        // ranges → reads garbage → either deserialization fails or
        // (worst case) accepts a wrong VK.
        assert_eq!(G1_BYTES, 96);
    }

    #[test]
    fn negative_g2_byte_constant_must_stay_192() {
        assert_eq!(G2_BYTES, 192);
    }

    #[test]
    fn negative_max_t_must_stay_at_widest_arity() {
        // poseidon7 has t=8; the state buffer is sized to MAX_T. Shrinking
        // MAX_T would index-out-of-bounds at runtime for legit inputs.
        assert_eq!(MAX_T, 8);
    }

    #[test]
    fn negative_bytes_per_block_must_stay_31() {
        // 31 B per block keeps each packed scalar below the BLS12-381 scalar
        // field modulus (~254 bits). Bumping to 32 risks non-canonical
        // encodings that diverge from the Circom PoseidonBytes template,
        // silently changing every H_tx / H_str ever produced.
        assert_eq!(BYTES_PER_BLOCK, 31);
    }

    #[test]
    fn negative_vk_bytes_length_locked_to_960() {
        // alpha + 3*G2 + 3*G1 = 96 + 576 + 288 = 960. Any other length means
        // the VK was regenerated with a different IC arity (circuit shape
        // change) — a breaking on-chain change, not a silent regression.
        assert_eq!(vk_data::VK_BYTES.len(), 960);
    }

    #[test]
    fn negative_test_calldata_length_locked_to_164() {
        assert_eq!(test_vectors::TEST_CALLDATA.len(), 164);
    }

    #[test]
    fn negative_test_readable_length_locked_to_64() {
        assert_eq!(test_vectors::TEST_READABLE.len(), 64);
    }

    #[test]
    fn negative_test_h_tx_length_locked_to_32() {
        assert_eq!(test_vectors::TEST_H_TX.len(), 32);
    }

    #[test]
    fn negative_test_h_str_length_locked_to_32() {
        assert_eq!(test_vectors::TEST_H_STR.len(), 32);
    }

    #[test]
    fn negative_test_proof_a_length_locked_to_g1() {
        assert_eq!(test_vectors::TEST_PROOF_A.len(), G1_BYTES);
    }

    #[test]
    fn negative_test_proof_b_length_locked_to_g2() {
        assert_eq!(test_vectors::TEST_PROOF_B.len(), G2_BYTES);
    }

    #[test]
    fn negative_test_proof_c_length_locked_to_g1() {
        assert_eq!(test_vectors::TEST_PROOF_C.len(), G1_BYTES);
    }

    // ── Negative: test-vector byte-level stability ──────────────────────────
    //
    // The committed H_tx / H_str / VK_HASH values are the contract between
    // the host harness and ZKlarity's circuit. Anyone regenerating with a
    // different fixture silently invalidates the cross-check; these tests
    // make that loud.

    #[test]
    fn negative_h_tx_byte_stability() {
        assert_eq!(
            test_vectors::TEST_H_TX,
            [
                0xd3, 0x9b, 0x3e, 0x8f, 0x1c, 0xd6, 0x33, 0xd0, 0x6b, 0xa7, 0xaa, 0xeb, 0x33,
                0xac, 0xb0, 0xab, 0x2b, 0x0d, 0x03, 0x91, 0x43, 0xcf, 0x74, 0x3d, 0xef, 0x56,
                0xd7, 0x15, 0x65, 0x99, 0x19, 0x68,
            ],
            "TEST_H_TX has drifted — Poseidon harness output no longer mirrors ZKlarity"
        );
    }

    #[test]
    fn negative_h_str_byte_stability() {
        assert_eq!(
            test_vectors::TEST_H_STR,
            [
                0x66, 0x5e, 0x7f, 0x35, 0x9b, 0x08, 0x2f, 0x78, 0xf2, 0x0e, 0xa8, 0x00, 0x21,
                0x94, 0x51, 0x1b, 0xb6, 0x28, 0x96, 0x16, 0xb3, 0x31, 0xdd, 0xd9, 0x2a, 0xa2,
                0x80, 0xbe, 0x64, 0xbf, 0x30, 0x28,
            ],
        );
    }

    #[test]
    fn negative_vk_hash_byte_stability() {
        assert_eq!(
            vk_data::VK_HASH,
            [
                0xf3, 0x6a, 0x73, 0xb5, 0xbb, 0x08, 0x4a, 0x98, 0x00, 0xce, 0xff, 0x63, 0xe3,
                0x3e, 0x06, 0x1d, 0x18, 0x2a, 0xf2, 0xb0, 0x9f, 0x6b, 0xce, 0xf2, 0x0d, 0x44,
                0x1c, 0x68, 0xfd, 0x80, 0x29, 0x2e,
            ],
            "VK_HASH has drifted from the committed value — VK_BYTES is no longer authenticated"
        );
    }

    // ── Negative: tampering must change the hash ────────────────────────────

    #[test]
    fn negative_poseidon_rejects_single_byte_calldata_flip() {
        // Assumption: H_tx is a collision-resistant commitment to calldata.
        // Without this property, the companion could swap calldata after
        // the trusted display.
        let mut tampered = test_vectors::TEST_CALLDATA;
        tampered[0] ^= 0x01;
        let h = poseidon_bytes(&tampered, 164);
        assert_ne!(
            h.to_bytes(),
            test_vectors::TEST_H_TX,
            "calldata mutation must change H_tx (collision-resistance assumption)"
        );
    }

    #[test]
    fn negative_poseidon_rejects_calldata_flip_at_last_signed_byte() {
        // Edge: tamper in the very last position that n=164 still covers
        // (index 100 — the last nonzero region of TEST_CALLDATA). This
        // guards against off-by-one in the byte-pack loop.
        let mut tampered = test_vectors::TEST_CALLDATA;
        tampered[100] ^= 0xff;
        let h = poseidon_bytes(&tampered, 164);
        assert_ne!(h.to_bytes(), test_vectors::TEST_H_TX);
    }

    #[test]
    fn negative_poseidon_rejects_readable_byte_flip() {
        let mut tampered = test_vectors::TEST_READABLE;
        tampered[5] ^= 0x40;
        let h = poseidon_bytes(&tampered, 64);
        assert_ne!(h.to_bytes(), test_vectors::TEST_H_STR);
    }

    #[test]
    fn negative_poseidon_n_argument_truncates_input() {
        // Assumption: poseidon_bytes(buf, n) hashes ONLY bytes [0..n), with
        // anything past n treated as the zero block. If `n` is silently
        // ignored, an attacker can append arbitrary unsigned bytes to a
        // signed payload without changing the public input.
        let mut buf = [0u8; 186];
        buf[..164].copy_from_slice(&test_vectors::TEST_CALLDATA);
        for b in &mut buf[164..] {
            *b = 0xaa;
        }
        let h = poseidon_bytes(&buf, 164);
        assert_eq!(
            h.to_bytes(),
            test_vectors::TEST_H_TX,
            "bytes past n must be ignored — otherwise a payload-extension attack is possible"
        );
    }

    #[test]
    fn negative_poseidon_distinguishes_different_n_in_same_block_bucket() {
        // Two distinct n values that map to the SAME block count (6) MUST
        // still produce different hashes when the bytes between them are
        // nonzero. Without this, the n parameter is effectively unused
        // inside a bucket and the wire format becomes ambiguous.
        let mut buf = [0u8; 200];
        for i in 155..186 {
            buf[i] = u8::try_from(i & 0xff).unwrap();
        }
        let h_164 = poseidon_bytes(&buf, 164);
        let h_170 = poseidon_bytes(&buf, 170);
        assert_ne!(
            h_164.to_bytes(),
            h_170.to_bytes(),
            "different n values within the same block bucket must yield different hashes"
        );
    }

    #[test]
    fn negative_vk_rejects_single_byte_flip() {
        // VK authenticity is anchored by sha256(VK_BYTES) == VK_HASH.
        // SHA-256 must catch any single-byte flip.
        let mut tampered = vk_data::VK_BYTES;
        tampered[100] ^= 0x80;
        assert_ne!(sha256(&tampered), vk_data::VK_HASH);
    }

    // ── Negative: Groth16 verifier rejects wrong inputs ─────────────────────

    #[test]
    fn negative_groth16_rejects_zeroed_h_tx_public_input() {
        // Soundness: a proof produced for (h_tx, h_str) MUST NOT verify
        // against (0, h_str). Otherwise an attacker substitutes a benign
        // calldata commitment after sign.
        let h_str = poseidon_bytes(&test_vectors::TEST_READABLE, 64);
        let vk = VerificationKey::parse(&vk_data::VK_BYTES);
        let proof_a = g1_from("pi.A", &test_vectors::TEST_PROOF_A);
        let proof_b = g2_from("pi.B", &test_vectors::TEST_PROOF_B);
        let proof_c = g1_from("pi.C", &test_vectors::TEST_PROOF_C);
        let vk_x = build_vk_x(Scalar::zero(), h_str, &vk);
        assert!(!verify(&proof_a, &proof_b, &proof_c, &vk_x, &vk));
    }

    #[test]
    fn negative_groth16_rejects_zeroed_h_str_public_input() {
        let h_tx = poseidon_bytes(&test_vectors::TEST_CALLDATA, 164);
        let vk = VerificationKey::parse(&vk_data::VK_BYTES);
        let proof_a = g1_from("pi.A", &test_vectors::TEST_PROOF_A);
        let proof_b = g2_from("pi.B", &test_vectors::TEST_PROOF_B);
        let proof_c = g1_from("pi.C", &test_vectors::TEST_PROOF_C);
        let vk_x = build_vk_x(h_tx, Scalar::zero(), &vk);
        assert!(!verify(&proof_a, &proof_b, &proof_c, &vk_x, &vk));
    }

    #[test]
    fn negative_groth16_rejects_swapped_public_inputs() {
        // The verifier MUST distinguish IC[1]·h_tx from IC[2]·h_str.
        // An attacker who could swap them could craft a proof under
        // "Supply N USDC" calldata that displays as a different amount.
        let h_tx = poseidon_bytes(&test_vectors::TEST_CALLDATA, 164);
        let h_str = poseidon_bytes(&test_vectors::TEST_READABLE, 64);
        assert_ne!(
            h_tx.to_bytes(),
            h_str.to_bytes(),
            "fixture invariant: H_tx ≠ H_str (otherwise the swap test is vacuous)"
        );
        let vk = VerificationKey::parse(&vk_data::VK_BYTES);
        let proof_a = g1_from("pi.A", &test_vectors::TEST_PROOF_A);
        let proof_b = g2_from("pi.B", &test_vectors::TEST_PROOF_B);
        let proof_c = g1_from("pi.C", &test_vectors::TEST_PROOF_C);
        let vk_x = build_vk_x(h_str, h_tx, &vk); // swapped
        assert!(!verify(&proof_a, &proof_b, &proof_c, &vk_x, &vk));
    }

    #[test]
    fn negative_groth16_rejects_substituted_proof_a() {
        // Replace pi.A with the G1 generator (a valid but unrelated point).
        let h_tx = poseidon_bytes(&test_vectors::TEST_CALLDATA, 164);
        let h_str = poseidon_bytes(&test_vectors::TEST_READABLE, 64);
        let vk = VerificationKey::parse(&vk_data::VK_BYTES);
        let proof_b = g2_from("pi.B", &test_vectors::TEST_PROOF_B);
        let proof_c = g1_from("pi.C", &test_vectors::TEST_PROOF_C);
        let vk_x = build_vk_x(h_tx, h_str, &vk);
        let fake_a = G1Affine::generator();
        assert!(!verify(&fake_a, &proof_b, &proof_c, &vk_x, &vk));
    }

    #[test]
    fn negative_groth16_rejects_substituted_proof_c() {
        let h_tx = poseidon_bytes(&test_vectors::TEST_CALLDATA, 164);
        let h_str = poseidon_bytes(&test_vectors::TEST_READABLE, 64);
        let vk = VerificationKey::parse(&vk_data::VK_BYTES);
        let proof_a = g1_from("pi.A", &test_vectors::TEST_PROOF_A);
        let proof_b = g2_from("pi.B", &test_vectors::TEST_PROOF_B);
        let vk_x = build_vk_x(h_tx, h_str, &vk);
        let fake_c = G1Affine::generator();
        assert!(!verify(&proof_a, &proof_b, &fake_c, &vk_x, &vk));
    }

    #[test]
    fn negative_groth16_rejects_identity_proof_a() {
        // Identity point (0) is the most-obvious free-pass candidate
        // because pairing(0, *) = 1_Gt. The verifier must still reject.
        let h_tx = poseidon_bytes(&test_vectors::TEST_CALLDATA, 164);
        let h_str = poseidon_bytes(&test_vectors::TEST_READABLE, 64);
        let vk = VerificationKey::parse(&vk_data::VK_BYTES);
        let proof_b = g2_from("pi.B", &test_vectors::TEST_PROOF_B);
        let proof_c = g1_from("pi.C", &test_vectors::TEST_PROOF_C);
        let vk_x = build_vk_x(h_tx, h_str, &vk);
        let id_a = G1Affine::identity();
        assert!(!verify(&id_a, &proof_b, &proof_c, &vk_x, &vk));
    }

    // ── Negative: parser / deserializer rejects malformed input ─────────────

    #[test]
    #[should_panic(expected = "g1 slice must be 96 bytes")]
    fn negative_g1_from_rejects_short_slice() {
        let _ = g1_from("short", &[0u8; 95]);
    }

    #[test]
    #[should_panic(expected = "g1 slice must be 96 bytes")]
    fn negative_g1_from_rejects_long_slice() {
        let _ = g1_from("long", &[0u8; 97]);
    }

    #[test]
    #[should_panic(expected = "g1 slice must be 96 bytes")]
    fn negative_g1_from_rejects_empty_slice() {
        let _ = g1_from("empty", &[]);
    }

    #[test]
    #[should_panic(expected = "g2 slice must be 192 bytes")]
    fn negative_g2_from_rejects_short_slice() {
        let _ = g2_from("short", &[0u8; 191]);
    }

    #[test]
    #[should_panic(expected = "g2 slice must be 192 bytes")]
    fn negative_g2_from_rejects_long_slice() {
        let _ = g2_from("long", &[0u8; 193]);
    }

    #[test]
    #[should_panic(expected = "failed to deserialize G1 point")]
    fn negative_g1_from_rejects_garbage_bytes() {
        // All-0xFF: leading byte sets compression+infinity+sort flags
        // simultaneously, and the unmasked x coordinate exceeds the
        // BLS12-381 base-field modulus. Library MUST refuse.
        let bad = [0xffu8; G1_BYTES];
        let _ = g1_from("garbage", &bad);
    }

    #[test]
    #[should_panic(expected = "failed to deserialize G2 point")]
    fn negative_g2_from_rejects_garbage_bytes() {
        let bad = [0xffu8; G2_BYTES];
        let _ = g2_from("garbage", &bad);
    }

    #[test]
    #[should_panic(expected = "invalid scalar in constant table")]
    fn negative_scalar_from_le_rejects_above_field_modulus() {
        // 0xFF…FF (LE) exceeds the BLS12-381 scalar modulus. A canonical-
        // safe Scalar::from_bytes must reject it; otherwise constants
        // could be supplied in non-canonical form, producing two valid
        // scalar values that hash differently across implementations.
        let bad: ScalarBytes = [0xffu8; 32];
        let _ = scalar_from_le(&bad);
    }

    #[test]
    #[should_panic(expected = "unsupported Poseidon block count")]
    fn negative_poseidon_bytes_rejects_unsupported_one_block() {
        // n=1 → 1 block; harness only supports {3, 6}. Hashing with an
        // unknown arity must NOT silently fall through to an arbitrary
        // permutation — that would produce wrong, irreproducible digests.
        let _ = poseidon_bytes(&[0u8; 32], 1);
    }

    #[test]
    #[should_panic(expected = "unsupported Poseidon block count")]
    fn negative_poseidon_bytes_rejects_unsupported_seven_blocks() {
        // n=187 → 7 blocks; not in the harness's {3, 6} dispatch.
        let _ = poseidon_bytes(&[0u8; 200], 187);
    }

    // ── Negative: poseidon3 vs poseidon6 are not aliased ────────────────────

    #[test]
    fn negative_poseidon3_and_poseidon6_have_distinct_parameters() {
        // A regression that aliases the two arities (e.g. someone copies a
        // constant table and forgets to rename it) would silently produce
        // wrong-but-consistent hashes that still "look" deterministic.
        // Lock both width and partial-round count.
        assert_eq!(poseidon3::T, 4, "poseidon3 t must be 4 (3 inputs + capacity)");
        assert_eq!(poseidon6::T, 7, "poseidon6 t must be 7 (6 inputs + capacity)");
        assert_ne!(
            poseidon3::RP, poseidon6::RP,
            "poseidon3/poseidon6 must have distinct partial-round counts"
        );
    }

    // ── Negative: VK substitution rejected end-to-end ───────────────────────

    #[test]
    fn negative_vk_substitution_rejected_end_to_end() {
        // Flipping VK[0] (high byte of alpha.x). Either parse fails (good —
        // caught at deserialize) or parse succeeds with a bogus alpha and
        // verification fails (also good). Both outcomes are acceptable;
        // what is NOT acceptable is "tampered VK silently verifies."
        let mut tampered = vk_data::VK_BYTES;
        tampered[0] ^= 0x01;
        assert_ne!(sha256(&tampered), vk_data::VK_HASH);
        let parsed = std::panic::catch_unwind(|| VerificationKey::parse(&tampered));
        match parsed {
            Err(_) => { /* parse rejected the tamper — good. */ }
            Ok(vk) => {
                let h_tx = poseidon_bytes(&test_vectors::TEST_CALLDATA, 164);
                let h_str = poseidon_bytes(&test_vectors::TEST_READABLE, 64);
                let proof_a = g1_from("pi.A", &test_vectors::TEST_PROOF_A);
                let proof_b = g2_from("pi.B", &test_vectors::TEST_PROOF_B);
                let proof_c = g1_from("pi.C", &test_vectors::TEST_PROOF_C);
                let vk_x = build_vk_x(h_tx, h_str, &vk);
                assert!(
                    !verify(&proof_a, &proof_b, &proof_c, &vk_x, &vk),
                    "tampered VK must NOT validate the genuine proof"
                );
            }
        }
    }
}
