//! Host-side end-to-end test for ZK clear signing verification.
//!
//! This exercises the exact same Poseidon hash + Groth16 pairing logic that
//! runs in the TrustZone secure world, but natively on the host CPU. This
//! verifies correctness without the ~hour wait of QEMU-emulated BLS12-381.
//!
//! Test vector: ZKlarity "supply 1000 USDC" proof (proof_supply.json).

use bls12_381::{miller_loop_4, pairing, G1Affine, G1Projective, G2Affine, Gt, Scalar};
use sha2::{Digest, Sha256};
use std::time::Instant;

// ── Include the same generated constant files used by the secure world ──

// Poseidon constants (auto-generated from poseidon-bls12381 npm package)
#[path = "../../secure/src/zk/poseidon_constants.rs"]
mod poseidon_constants;

// Test vectors (auto-generated from ZKlarity proof_supply.json)
#[path = "../../secure/src/zk/test_vectors.rs"]
mod test_vectors;

// VK test data (auto-generated from ZKlarity verification_key.json)
#[path = "../../secure/src/zk/vk_data.rs"]
mod vk_data;

use poseidon_constants::{poseidon3, poseidon6, ScalarBytes};

// ── Poseidon implementation (mirrors secure/src/zk/poseidon.rs exactly) ──

const MAX_T: usize = 8;

fn scalar_from_le(bytes: &ScalarBytes) -> Scalar {
    Option::from(Scalar::from_bytes(bytes)).expect("invalid scalar")
}

#[inline(always)]
fn sbox(x: Scalar) -> Scalar {
    let x2 = x * x;
    let x4 = x2 * x2;
    x4 * x
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
    for i in 0..t {
        state[i] = out[i];
    }
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
    let mut state = [Scalar::zero(); MAX_T];
    for (i, inp) in inputs.iter().enumerate() {
        state[i + 1] = *inp;
    }

    let mut mds = [[Scalar::zero(); MAX_T]; MAX_T];
    for i in 0..t {
        for j in 0..t {
            mds[i][j] = scalar_from_le(&mds_raw[i][j]);
        }
    }

    let mut rc_idx = 0;

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

    for _ in 0..rp {
        for j in 0..t {
            state[j] += scalar_from_le(&rc[rc_idx]);
            rc_idx += 1;
        }
        state[0] = sbox(state[0]);
        mds_mix(&mut state, &mds, t);
    }

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

fn poseidon_bytes(bytes: &[u8], n: usize) -> Scalar {
    let n_blocks = (n + 30) / 31;
    let mut fields = [Scalar::zero(); 7];
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

    let inputs = &fields[..n_blocks];
    match n_blocks {
        3 => {
            let mut mds = [[[0u8; 32]; MAX_T]; MAX_T];
            for i in 0..poseidon3::T {
                for j in 0..poseidon3::T {
                    mds[i][j] = poseidon3::MDS[i][j];
                }
            }
            poseidon_perm(inputs, poseidon3::T, poseidon3::RF, poseidon3::RP, &poseidon3::RC, &mds)
        }
        6 => {
            let mut mds = [[[0u8; 32]; MAX_T]; MAX_T];
            for i in 0..poseidon6::T {
                for j in 0..poseidon6::T {
                    mds[i][j] = poseidon6::MDS[i][j];
                }
            }
            poseidon_perm(inputs, poseidon6::T, poseidon6::RF, poseidon6::RP, &poseidon6::RC, &mds)
        }
        _ => panic!("unsupported block count"),
    }
}

// ── Main test ──────────────────────────────────────────────────────────

fn main() {
    println!("=== ZK Clear Signing End-to-End Test ===");
    println!("Test vector: Aave V3 supply(1000 USDC)\n");

    // ── Step 1: Poseidon hash of calldata ──
    println!("[1/5] Computing H_tx = Poseidon(calldata, 164)...");
    let t0 = Instant::now();
    let h_tx = poseidon_bytes(&test_vectors::TEST_CALLDATA, 164);
    let h_tx_bytes = h_tx.to_bytes();
    println!("      H_tx = {:02x}{:02x}{:02x}{:02x}...{:02x}{:02x}{:02x}{:02x}",
        h_tx_bytes[0], h_tx_bytes[1], h_tx_bytes[2], h_tx_bytes[3],
        h_tx_bytes[28], h_tx_bytes[29], h_tx_bytes[30], h_tx_bytes[31]);

    // Compare against known test vector
    assert_eq!(h_tx_bytes, test_vectors::TEST_H_TX,
        "H_tx mismatch! Poseidon hash does not match ZKlarity's output");
    println!("      MATCH — matches ZKlarity public_supply.json");
    println!("      ({:.1}ms)\n", t0.elapsed().as_secs_f64() * 1000.0);

    // ── Step 2: Poseidon hash of readable string ──
    println!("[2/5] Computing H_str = Poseidon(readable, 64)...");
    let t0 = Instant::now();
    let h_str = poseidon_bytes(&test_vectors::TEST_READABLE, 64);
    let h_str_bytes = h_str.to_bytes();
    println!("      H_str = {:02x}{:02x}{:02x}{:02x}...{:02x}{:02x}{:02x}{:02x}",
        h_str_bytes[0], h_str_bytes[1], h_str_bytes[2], h_str_bytes[3],
        h_str_bytes[28], h_str_bytes[29], h_str_bytes[30], h_str_bytes[31]);

    assert_eq!(h_str_bytes, test_vectors::TEST_H_STR,
        "H_str mismatch! Poseidon hash does not match ZKlarity's output");
    println!("      MATCH — matches ZKlarity public_supply.json");

    let readable_str = std::str::from_utf8(&test_vectors::TEST_READABLE)
        .unwrap().trim_end_matches('\0');
    println!("      Display: \"{}\"", readable_str);
    println!("      ({:.1}ms)\n", t0.elapsed().as_secs_f64() * 1000.0);

    // ── Step 3: VK hash verification ──
    println!("[3/5] Verifying VK authenticity (SHA-256)...");
    let vk_hash = {
        let mut h = Sha256::new();
        h.update(&vk_data::VK_BYTES);
        let r = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&r);
        out
    };
    assert_eq!(vk_hash, vk_data::VK_HASH, "VK hash mismatch!");
    println!("      VK hash = {:02x}{:02x}{:02x}{:02x}...{:02x}{:02x}{:02x}{:02x}",
        vk_hash[0], vk_hash[1], vk_hash[2], vk_hash[3],
        vk_hash[28], vk_hash[29], vk_hash[30], vk_hash[31]);
    println!("      MATCH — VK authenticated\n");

    // ── Step 4: Deserialize proof and VK ──
    println!("[4/5] Deserializing Groth16 proof and verification key...");
    let proof_a = G1Affine::from_uncompressed(&test_vectors::TEST_PROOF_A);
    assert!(bool::from(proof_a.is_some()), "Failed to deserialize pi.A");
    let proof_a = proof_a.unwrap();

    let proof_b = G2Affine::from_uncompressed(&test_vectors::TEST_PROOF_B);
    assert!(bool::from(proof_b.is_some()), "Failed to deserialize pi.B");
    let proof_b = proof_b.unwrap();

    let proof_c = G1Affine::from_uncompressed(&test_vectors::TEST_PROOF_C);
    assert!(bool::from(proof_c.is_some()), "Failed to deserialize pi.C");
    let proof_c = proof_c.unwrap();

    // Deserialize VK (960 bytes → 7 curve points)
    let vk_bytes = &vk_data::VK_BYTES;
    let alpha = G1Affine::from_uncompressed(vk_bytes[0..96].try_into().unwrap());
    assert!(bool::from(alpha.is_some()), "Failed to deserialize VK alpha");
    let alpha = alpha.unwrap();

    let beta = G2Affine::from_uncompressed(vk_bytes[96..288].try_into().unwrap());
    assert!(bool::from(beta.is_some()), "Failed to deserialize VK beta");
    let beta = beta.unwrap();

    let gamma = G2Affine::from_uncompressed(vk_bytes[288..480].try_into().unwrap());
    assert!(bool::from(gamma.is_some()), "Failed to deserialize VK gamma");
    let gamma = gamma.unwrap();

    let delta = G2Affine::from_uncompressed(vk_bytes[480..672].try_into().unwrap());
    assert!(bool::from(delta.is_some()), "Failed to deserialize VK delta");
    let delta = delta.unwrap();

    let ic0 = G1Affine::from_uncompressed(vk_bytes[672..768].try_into().unwrap()).unwrap();
    let ic1 = G1Affine::from_uncompressed(vk_bytes[768..864].try_into().unwrap()).unwrap();
    let ic2 = G1Affine::from_uncompressed(vk_bytes[864..960].try_into().unwrap()).unwrap();

    println!("      Proof: pi.A, pi.B, pi.C — OK");
    println!("      VK: alpha, beta, gamma, delta, IC[0..2] — OK\n");

    // ── Step 5: Groth16 pairing check ──
    println!("[5/6] Running Groth16 verification (4 individual pairings)...");
    println!("      e(pi.A, pi.B) . e(-alpha, beta) . e(-vk_x, gamma) . e(-pi.C, delta) == 1?");
    let t0 = Instant::now();

    // Compute vk_x = IC[0] + h_tx * IC[1] + h_str * IC[2]
    let vk_x = G1Affine::from(
        G1Projective::from(ic0) + G1Projective::from(ic1) * h_tx + G1Projective::from(ic2) * h_str,
    );

    let e1 = pairing(&proof_a, &proof_b);
    let e2 = pairing(&(-alpha), &beta);
    let e3 = pairing(&(-vk_x), &gamma);
    let e4 = pairing(&(-proof_c), &delta);

    let result = e1 + e2 + e3 + e4;
    let valid = result == Gt::identity();

    let time_individual = t0.elapsed();
    println!("      Result: {} ({:.1}ms with 4 individual pairings)",
        if valid { "VALID" } else { "INVALID" },
        time_individual.as_secs_f64() * 1000.0);
    assert!(valid, "Groth16 verification FAILED (individual pairings)!");

    // ── Step 6: Multi-Miller loop (2x optimization) ──
    println!("\n[6/6] Running Groth16 verification (multi-Miller loop, 1 final exp)...");
    let t0 = Instant::now();

    let neg_alpha = -alpha;
    let neg_vk_x = -vk_x;
    let neg_c = -proof_c;

    let result_multi = miller_loop_4([
        (&proof_a, &proof_b),
        (&neg_alpha, &beta),
        (&neg_vk_x, &gamma),
        (&neg_c, &delta),
    ])
    .final_exponentiation();

    let valid_multi = result_multi == Gt::identity();
    let time_multi = t0.elapsed();
    println!("      Result: {} ({:.1}ms with multi-Miller loop)",
        if valid_multi { "VALID" } else { "INVALID" },
        time_multi.as_secs_f64() * 1000.0);
    assert!(valid_multi, "Groth16 verification FAILED (multi-Miller loop)!");

    let speedup = time_individual.as_secs_f64() / time_multi.as_secs_f64();
    println!("      Speedup: {:.1}x", speedup);

    println!("\n=== ALL CHECKS PASSED ===");
    println!("  Poseidon(calldata)  matches ZKlarity circuit output");
    println!("  Poseidon(readable)  matches ZKlarity circuit output");
    println!("  VK hash             matches on-chain commitment");
    println!("  Groth16 proof       VALID — \"{}\" is a faithful", readable_str);
    println!("                      representation of the Aave supply calldata");
    println!("\nThis is exactly what the secure world would execute for CMD_CLEAR_SIGN.");
}
