//! Host-runnable positive + negative suite for the `secure-zk` slice.
//!
//! The positives exercise the BLS12-381 Groth16 verifier + Poseidon
//! byte-hasher + 1056-byte VK-bundle decoder against the committed
//! ZKlarity "Aave V3 supply 1000 USDC" reference vector (the same blob
//! `zk-test` exercises on host CPU, and that `make zk-test` re-runs
//! end-to-end on QEMU).
//!
//! The negatives are the load-bearing artefact of this pass. Each one
//! names a specific assumption that the verifier holds — wire-format
//! offset, public-input binding, Merkle-bundle bound, point-on-curve
//! invariant, Poseidon collision-resistance, padding-byte irrelevance —
//! and asserts the assumption is enforced by feeding the verifier the
//! violation and checking the rejection is total (Groth16 `false`,
//! `from_bytes` → `None`, `verify_vk_bundle` → `None`, top-level
//! `verify_clear_sign_proof` → `ClearSignError`). When a future
//! refactor weakens one of these guards the corresponding test fires.
//!
//! NB: a positive `verify_vk_bundle` test is deliberately absent — the
//! VK Merkle root (`crate::db_roots::VK_DB_ROOT`) is a baked-in
//! firmware constant produced by `dbgen`, and the matching bundle for
//! that root is not part of the in-repo fixtures. Every negative
//! `verify_vk_bundle_*` test below confirms the *structural* gate
//! rejects every malformed shape; the cryptographic Merkle walk is
//! covered by the cross-tree test in `pqsigner-tx/src/erc20/merkle.rs`
//! and by the on-target end-to-end run.

#![allow(clippy::needless_range_loop)]
#![allow(clippy::octal_escapes)]

use bls12_381::{G1Affine, G1Projective, G2Affine, Scalar};

use super::inner::{
    groth16::{
        verify_clear_signing_proof, verify_clear_signing_proof_v3, Groth16Proof,
        VerificationKey, VerificationKeyV3, VK_LEN, VK_V3_LEN,
    },
    poseidon::{poseidon_bytes, poseidon_fields},
    vk_bundle::verify_vk_bundle,
    verify_and_bind_trailer_v1, verify_clear_sign_proof, MAX_CALLDATA, PROOF_LEN, STRING_LEN,
};
use super::test_vectors as tv;
use super::vk_data;

use sphincs_tz_shared::db_format::{VK_BLOB_LEN, VK_BLOB_LEN_2PUB, VK_BLOB_LEN_3PUB};

// ──────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────

/// Assemble the 384-byte known-good proof from the three component arrays
/// in `test_vectors.rs`.
fn known_good_proof_bytes() -> [u8; 384] {
    let mut out = [0u8; 384];
    out[0..96].copy_from_slice(&tv::TEST_PROOF_A);
    out[96..288].copy_from_slice(&tv::TEST_PROOF_B);
    out[288..384].copy_from_slice(&tv::TEST_PROOF_C);
    out
}

/// Assemble a 1056-byte 3-pub VK by zero-padding the committed 960-byte
/// 2-pub VK. The structure shares the alpha/beta/gamma/delta layout,
/// only the IC array differs (3 G1 points + 1 padding G1). Padding the
/// 4th IC slot with zeros yields a G1Affine::from_uncompressed input
/// whose "infinity" bit is unset → not a valid encoding, which lets us
/// negative-test `from_bytes` (see below). For positives we use a
/// crafted 1056-byte buffer with a valid identity-point in the 4th slot.
fn vk_v3_with_zero_ic3() -> [u8; 1056] {
    let mut out = [0u8; 1056];
    out[..960].copy_from_slice(&vk_data::VK_BYTES);
    // 4th IC point is left as all-zeros: invalid uncompressed encoding.
    out
}

/// Same as `vk_v3_with_zero_ic3` but with a legitimate G1 identity in
/// the IC[3] slot (96 bytes; the BLS uncompressed identity sets the
/// "infinity" tag bit in byte 0).
fn vk_v3_with_identity_ic3() -> [u8; 1056] {
    let mut out = [0u8; 1056];
    out[..960].copy_from_slice(&vk_data::VK_BYTES);
    let id_bytes = G1Affine::identity().to_uncompressed();
    out[960..1056].copy_from_slice(&id_bytes);
    out
}

/// Smallest valid header for `verify_vk_bundle` — chain_id + contract +
/// VK + leaf_index + proof_depth, with proof_depth = 0 (i.e. an empty
/// Merkle proof tail). 1092 bytes.
const MIN_BUNDLE_LEN: usize = 8 + 20 + VK_BLOB_LEN + 4 + 4;

/// Build a structurally-valid bundle that is guaranteed to fail the
/// Merkle walk (because its canonical leaf bytes hash to something that
/// is not `VK_DB_ROOT`). Used by every "bundle parses, Merkle rejects"
/// negative test.
fn well_shaped_but_merkle_invalid_bundle() -> [u8; MIN_BUNDLE_LEN] {
    let mut bundle = [0u8; MIN_BUNDLE_LEN];
    // chain_id (LE) = 1, contract = 0x11..11
    bundle[0..8].copy_from_slice(&1u64.to_le_bytes());
    for b in &mut bundle[8..28] {
        *b = 0x11;
    }
    bundle[28..28 + VK_BLOB_LEN].copy_from_slice(&vk_v3_with_identity_ic3());
    // leaf_index = 0, proof_depth = 0 — both already zero.
    bundle
}

// ──────────────────────────────────────────────────────────────────────
// Positive: surface-area constants (frozen-format pins)
// ──────────────────────────────────────────────────────────────────────

#[test]
fn positive_const_proof_len_is_384() {
    assert_eq!(
        PROOF_LEN, 384,
        "PROOF_LEN = 96 (G1) + 192 (G2) + 96 (G1); circuits/verifiers depend on this"
    );
}

#[test]
fn positive_const_max_calldata_is_164() {
    assert_eq!(
        MAX_CALLDATA, 164,
        "MAX_CALLDATA must match the ZKlarity circuit constant"
    );
}

#[test]
fn positive_const_string_len_is_64() {
    assert_eq!(
        STRING_LEN, 64,
        "STRING_LEN must match the ZKlarity circuit constant"
    );
}

#[test]
fn positive_const_vk_len_is_960() {
    assert_eq!(
        VK_LEN, 960,
        "VK_LEN = 96+192+192+192+3*96 (alpha + beta + gamma + delta + 3*IC)"
    );
    assert_eq!(
        VK_LEN, VK_BLOB_LEN_2PUB,
        "2-pub VK byte size must equal the shared db_format constant"
    );
}

#[test]
fn positive_const_vk_v3_len_is_1056() {
    assert_eq!(
        VK_V3_LEN, 1056,
        "VK_V3_LEN = VK_LEN + extra 96-byte IC slot for the 3rd public input"
    );
    assert_eq!(
        VK_V3_LEN, VK_BLOB_LEN_3PUB,
        "3-pub VK byte size must equal the shared db_format constant"
    );
    assert_eq!(
        VK_V3_LEN, VK_BLOB_LEN,
        "VK pool slot is sized to fit both 2-pub and 3-pub VKs"
    );
}

#[test]
fn positive_const_zk_clear_sign_fixed_len_is_612() {
    use sphincs_tz_shared::ZK_CLEAR_SIGN_FIXED_LEN;
    assert_eq!(
        ZK_CLEAR_SIGN_FIXED_LEN,
        PROOF_LEN + MAX_CALLDATA + STRING_LEN,
        "trailer prefix = proof || calldata || readable"
    );
    assert_eq!(ZK_CLEAR_SIGN_FIXED_LEN, 612);
}

// ──────────────────────────────────────────────────────────────────────
// Positive: Poseidon — reference vectors
// ──────────────────────────────────────────────────────────────────────

#[test]
fn positive_poseidon_bytes_matches_known_h_tx() {
    let h = poseidon_bytes(&tv::TEST_CALLDATA, MAX_CALLDATA);
    assert_eq!(
        h.to_bytes(),
        tv::TEST_H_TX,
        "Poseidon(TEST_CALLDATA, 164) MUST equal the circuit-reported H_tx; \
         drift here means H_tx is no longer byte-compatible with the ZKlarity circuit"
    );
}

#[test]
fn positive_poseidon_bytes_matches_known_h_str() {
    let h = poseidon_bytes(&tv::TEST_READABLE, STRING_LEN);
    assert_eq!(
        h.to_bytes(),
        tv::TEST_H_STR,
        "Poseidon(TEST_READABLE, 64) MUST equal the circuit-reported H_str"
    );
}

#[test]
fn positive_poseidon_bytes_is_deterministic() {
    let a = poseidon_bytes(&tv::TEST_CALLDATA, MAX_CALLDATA);
    let b = poseidon_bytes(&tv::TEST_CALLDATA, MAX_CALLDATA);
    assert_eq!(a.to_bytes(), b.to_bytes());
}

#[test]
fn positive_poseidon_bytes_all_supported_arities_dispatch() {
    // 2 blocks (n in [32..=62]), 3 blocks (n in [63..=93]),
    // 5 blocks (n in [125..=155]), 6 blocks (n in [156..=186]),
    // 7 blocks (n in [187..=217]). All five branches MUST return
    // distinct hashes for an input that is identical in the byte
    // prefix — proves each arity uses its own permutation, not a
    // silently-shared one.
    let buf = [0xa5u8; 256];
    let h2 = poseidon_bytes(&buf, 50).to_bytes();
    let h3 = poseidon_bytes(&buf, 80).to_bytes();
    let h5 = poseidon_bytes(&buf, 140).to_bytes();
    let h6 = poseidon_bytes(&buf, MAX_CALLDATA).to_bytes();
    let h7 = poseidon_bytes(&buf, 204).to_bytes();
    let all = [h2, h3, h5, h6, h7];
    for i in 0..all.len() {
        for j in (i + 1)..all.len() {
            assert_ne!(
                all[i], all[j],
                "arity {i} and arity {j} produced identical digests — aliasing bug"
            );
        }
    }
}

#[test]
fn positive_poseidon_fields_arity_2_3_5_6_7_dispatch() {
    // poseidon_fields must accept exactly the five supported arities.
    // Different arities with the same prefix MUST produce different
    // outputs — same aliasing guard as the byte test above.
    let inputs: [Scalar; 8] = [
        Scalar::from(1u64),
        Scalar::from(2u64),
        Scalar::from(3u64),
        Scalar::from(4u64),
        Scalar::from(5u64),
        Scalar::from(6u64),
        Scalar::from(7u64),
        Scalar::from(8u64),
    ];
    let h2 = poseidon_fields(&inputs[..2]).to_bytes();
    let h3 = poseidon_fields(&inputs[..3]).to_bytes();
    let h5 = poseidon_fields(&inputs[..5]).to_bytes();
    let h6 = poseidon_fields(&inputs[..6]).to_bytes();
    let h7 = poseidon_fields(&inputs[..7]).to_bytes();
    let all = [h2, h3, h5, h6, h7];
    for i in 0..all.len() {
        for j in (i + 1)..all.len() {
            assert_ne!(all[i], all[j]);
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// Positive: Groth16 deserialization + end-to-end verify
// ──────────────────────────────────────────────────────────────────────

#[test]
fn positive_groth16_proof_from_bytes_known_good() {
    let bytes = known_good_proof_bytes();
    let proof = Groth16Proof::from_bytes(&bytes)
        .expect("known-good proof bytes MUST deserialize");
    // Re-serialise A/B/C round-trip via uncompressed encoding and
    // confirm the bytes are byte-identical — this proves the
    // 96/192/96 slice split is honoured.
    assert_eq!(proof.a.to_uncompressed(), tv::TEST_PROOF_A);
    assert_eq!(proof.b.to_uncompressed(), tv::TEST_PROOF_B);
    assert_eq!(proof.c.to_uncompressed(), tv::TEST_PROOF_C);
}

#[test]
fn positive_verification_key_from_bytes_known_good() {
    let vk = VerificationKey::from_bytes(&vk_data::VK_BYTES)
        .expect("committed Aave V3 VK MUST deserialize");
    // Re-serialise alpha + the three IC points and confirm bytes match
    // — this proves the [0..96), [672..768), ... offsets are honoured.
    assert_eq!(vk.alpha_g1.to_uncompressed(), vk_data::VK_BYTES[0..96]);
    assert_eq!(vk.ic[0].to_uncompressed(), vk_data::VK_BYTES[672..768]);
    assert_eq!(vk.ic[1].to_uncompressed(), vk_data::VK_BYTES[768..864]);
    assert_eq!(vk.ic[2].to_uncompressed(), vk_data::VK_BYTES[864..960]);
}

#[test]
fn positive_verification_key_v3_from_bytes_accepts_valid_padded_vk() {
    let bytes = vk_v3_with_identity_ic3();
    let vk = VerificationKeyV3::from_bytes(&bytes)
        .expect("VK_v3 with identity IC[3] MUST deserialize (identity is a valid G1 point)");
    assert!(bool::from(vk.ic[3].is_identity()));
}

#[test]
fn positive_verify_clear_signing_proof_known_good() {
    // The end-to-end positive: known calldata + readable + proof + VK
    // MUST pass the pairing check. This is the function the gateway
    // calls; if it ever returns false on the committed fixture, every
    // ZK clear-sign UserOp on every chain is broken.
    let proof = Groth16Proof::from_bytes(&known_good_proof_bytes())
        .expect("proof deser");
    let vk = VerificationKey::from_bytes(&vk_data::VK_BYTES).expect("vk deser");
    let ok = verify_clear_signing_proof(&tv::TEST_CALLDATA, &tv::TEST_READABLE, &proof, &vk);
    assert!(
        ok,
        "committed ZKlarity Aave V3 proof MUST verify against committed VK + calldata + readable"
    );
}

// ──────────────────────────────────────────────────────────────────────
// Positive: VK bundle structural decoder accessors
// ──────────────────────────────────────────────────────────────────────

#[test]
fn positive_min_bundle_len_is_1092() {
    assert_eq!(
        MIN_BUNDLE_LEN, 1092,
        "frozen wire-format minimum: 8 (chain_id) + 20 (contract) \
         + 1056 (vk) + 4 (leaf_index) + 4 (proof_depth)"
    );
}

#[test]
fn positive_vk_bundle_layout_offsets_are_frozen() {
    // Pin the byte offsets the decoder reads. Any future tweak that
    // shifts these would be a silent on-wire incompatibility with
    // every companion app + every dbgen-produced VK pool.
    let chain_off = 0usize;
    let contract_off = chain_off + 8;
    let vk_off = contract_off + 20;
    let leaf_index_off = vk_off + VK_BLOB_LEN;
    let proof_depth_off = leaf_index_off + 4;
    let proof_off = proof_depth_off + 4;
    assert_eq!(chain_off, 0);
    assert_eq!(contract_off, 8);
    assert_eq!(vk_off, 28);
    assert_eq!(leaf_index_off, 1084);
    assert_eq!(proof_depth_off, 1088);
    assert_eq!(proof_off, 1092);
}

// ──────────────────────────────────────────────────────────────────────
// Negative: Poseidon — collision/binding assumptions
// ──────────────────────────────────────────────────────────────────────

#[test]
#[should_panic(expected = "unsupported Poseidon arity")]
fn negative_poseidon_fields_rejects_arity_4() {
    // Assumption: only arities {2,3,5,6,7} are wired up. A silent
    // fall-through (e.g. routing arity 4 to arity 3 by mistake) would
    // produce reproducible-looking but cryptographically-broken digests.
    let inputs = [Scalar::zero(); 4];
    let _ = poseidon_fields(&inputs);
}

#[test]
#[should_panic(expected = "unsupported Poseidon arity")]
fn negative_poseidon_fields_rejects_arity_0() {
    let _ = poseidon_fields(&[]);
}

#[test]
#[should_panic(expected = "unsupported Poseidon arity")]
fn negative_poseidon_fields_rejects_arity_1() {
    let _ = poseidon_fields(&[Scalar::from(7u64)]);
}

#[test]
#[should_panic(expected = "unsupported Poseidon arity")]
fn negative_poseidon_bytes_rejects_1_block_input() {
    // n=1 → 1 block → arity 1 → not in the dispatch table.
    let _ = poseidon_bytes(&[0u8; 32], 1);
}

#[test]
#[should_panic(expected = "unsupported Poseidon arity")]
fn negative_poseidon_bytes_rejects_4_block_input() {
    // n=124 → 4 blocks → arity 4 → not in the dispatch table. The
    // gap between 3-block (≤93) and 5-block (≥125) MUST stay closed.
    let _ = poseidon_bytes(&[0u8; 256], 124);
}

#[test]
#[should_panic(expected = "unsupported Poseidon arity")]
fn negative_poseidon_bytes_rejects_8_block_input() {
    // n=218 → 8 blocks (poseidon8 not wired).
    let _ = poseidon_bytes(&[0u8; 256], 218);
}

#[test]
fn negative_poseidon_bytes_rejects_single_byte_calldata_flip() {
    // Assumption: H_tx is a binding commitment to calldata. Without
    // this, the companion could swap calldata bytes between the
    // trusted display and on-chain dispatch.
    let mut tampered = tv::TEST_CALLDATA;
    tampered[0] ^= 0x01;
    let h = poseidon_bytes(&tampered, MAX_CALLDATA);
    assert_ne!(
        h.to_bytes(),
        tv::TEST_H_TX,
        "calldata mutation MUST change H_tx (collision-resistance assumption)"
    );
}

#[test]
fn negative_poseidon_bytes_rejects_calldata_flip_at_last_signed_byte() {
    // Off-by-one guard on the byte-pack loop: tamper inside the
    // attested range, near the high end of the nonzero region.
    let mut tampered = tv::TEST_CALLDATA;
    tampered[100] ^= 0xff;
    let h = poseidon_bytes(&tampered, MAX_CALLDATA);
    assert_ne!(h.to_bytes(), tv::TEST_H_TX);
}

#[test]
fn negative_poseidon_bytes_rejects_readable_byte_flip() {
    let mut tampered = tv::TEST_READABLE;
    tampered[5] ^= 0x40;
    let h = poseidon_bytes(&tampered, STRING_LEN);
    assert_ne!(h.to_bytes(), tv::TEST_H_STR);
}

#[test]
fn negative_poseidon_bytes_ignores_bytes_past_n() {
    // Assumption: poseidon_bytes(buf, n) hashes ONLY bytes [0..n) —
    // anything past `n` is treated as the zero block. If `n` were
    // silently ignored and the full buffer hashed, an attacker could
    // append arbitrary unsigned bytes to a signed payload without
    // changing the public input.
    let mut buf = [0u8; 186];
    buf[..MAX_CALLDATA].copy_from_slice(&tv::TEST_CALLDATA);
    for b in &mut buf[MAX_CALLDATA..] {
        *b = 0xaa;
    }
    let h = poseidon_bytes(&buf, MAX_CALLDATA);
    assert_eq!(
        h.to_bytes(),
        tv::TEST_H_TX,
        "bytes past n MUST be ignored — otherwise a payload-extension attack is possible"
    );
}

#[test]
fn negative_poseidon_bytes_distinguishes_different_n_in_same_block_bucket() {
    // n=164 and n=170 both map to 6 blocks (ceil(170/31)=6). The
    // hashes MUST differ when the bytes between them are nonzero —
    // otherwise the `n` parameter is silently ignored within a bucket
    // and the wire format becomes ambiguous between two distinct
    // claimed-length payloads.
    let mut buf = [0u8; 200];
    for i in 155..186 {
        buf[i] = u8::try_from(i & 0xff).unwrap();
    }
    let h_164 = poseidon_bytes(&buf, MAX_CALLDATA).to_bytes();
    let h_170 = poseidon_bytes(&buf, 170).to_bytes();
    assert_ne!(
        h_164, h_170,
        "different n values in same block bucket MUST yield different hashes"
    );
}

#[test]
fn negative_poseidon_bytes_byte_order_matters() {
    // Assumption: each 31-byte block is packed big-endian into a field
    // element. Reversing the input bytes within a block MUST produce
    // a different scalar (otherwise the packing is BE-vs-LE-ambiguous
    // and would silently differ from the Circom side).
    let mut a = [0u8; 64];
    let mut b = [0u8; 64];
    for i in 0..62 {
        a[i] = u8::try_from(i + 1).unwrap();
        b[61 - i] = u8::try_from(i + 1).unwrap();
    }
    assert_ne!(
        poseidon_bytes(&a, 62).to_bytes(),
        poseidon_bytes(&b, 62).to_bytes()
    );
}

// ──────────────────────────────────────────────────────────────────────
// Negative: Groth16Proof::from_bytes — point-on-curve / encoding guards
// ──────────────────────────────────────────────────────────────────────

#[test]
fn negative_groth16_proof_from_bytes_rejects_all_ones() {
    // 0xFF…FF: leading byte sets compression+infinity+sort flags
    // simultaneously, and the unmasked x coordinate exceeds the
    // BLS12-381 base-field modulus. The library MUST refuse — silent
    // acceptance would let an attacker submit a proof of "anything".
    let bad = [0xffu8; PROOF_LEN];
    assert!(Groth16Proof::from_bytes(&bad).is_none());
}

#[test]
fn negative_groth16_proof_from_bytes_rejects_all_zeros() {
    // All-zero uncompressed encoding is NOT the canonical identity
    // (the BLS uncompressed identity has the infinity tag bit set in
    // byte 0). It is an off-curve point and MUST be rejected.
    let bad = [0u8; PROOF_LEN];
    assert!(Groth16Proof::from_bytes(&bad).is_none());
}

#[test]
fn negative_groth16_proof_from_bytes_rejects_corrupted_a_flag_bits() {
    // Flip a flag bit in pi.A's leading byte — should change the
    // declared encoding mode and either deserialize to a wrong point
    // (which would not satisfy the curve equation) or fail outright.
    let mut bad = known_good_proof_bytes();
    bad[0] ^= 0x80;
    assert!(Groth16Proof::from_bytes(&bad).is_none());
}

#[test]
fn negative_groth16_proof_from_bytes_rejects_corrupted_b_flag_bits() {
    let mut bad = known_good_proof_bytes();
    bad[96] ^= 0x80;
    assert!(Groth16Proof::from_bytes(&bad).is_none());
}

#[test]
fn negative_groth16_proof_from_bytes_rejects_corrupted_c_flag_bits() {
    let mut bad = known_good_proof_bytes();
    bad[288] ^= 0x80;
    assert!(Groth16Proof::from_bytes(&bad).is_none());
}

#[test]
fn negative_verification_key_from_bytes_rejects_all_ones() {
    let bad = [0xffu8; VK_LEN];
    assert!(VerificationKey::from_bytes(&bad).is_none());
}

#[test]
fn negative_verification_key_v3_from_bytes_rejects_zero_padding_in_ic3() {
    // The committed VK is 960 bytes (2-pub). A 3-pub decoder MUST
    // refuse to read the last 96 bytes as IC[3] when they are all
    // zero — that encoding is not on the curve. This is what protects
    // a 2-pub VK from accidentally being routed through the 3-pub
    // verifier (which would otherwise compute vk_x with a bogus IC[3]
    // contribution).
    let bad = vk_v3_with_zero_ic3();
    assert!(VerificationKeyV3::from_bytes(&bad).is_none());
}

// ──────────────────────────────────────────────────────────────────────
// Negative: Groth16 verifier — soundness against tampered inputs
// ──────────────────────────────────────────────────────────────────────

#[test]
fn negative_verify_clear_signing_proof_rejects_modified_calldata_byte() {
    let proof = Groth16Proof::from_bytes(&known_good_proof_bytes()).unwrap();
    let vk = VerificationKey::from_bytes(&vk_data::VK_BYTES).unwrap();
    let mut tampered_cd = tv::TEST_CALLDATA;
    tampered_cd[12] ^= 0x01;
    assert!(
        !verify_clear_signing_proof(&tampered_cd, &tv::TEST_READABLE, &proof, &vk),
        "a single-byte calldata change MUST invalidate the pairing equation"
    );
}

#[test]
fn negative_verify_clear_signing_proof_rejects_modified_readable_byte() {
    let proof = Groth16Proof::from_bytes(&known_good_proof_bytes()).unwrap();
    let vk = VerificationKey::from_bytes(&vk_data::VK_BYTES).unwrap();
    let mut tampered_rd = tv::TEST_READABLE;
    tampered_rd[3] ^= 0x01;
    assert!(!verify_clear_signing_proof(
        &tv::TEST_CALLDATA,
        &tampered_rd,
        &proof,
        &vk
    ));
}

#[test]
fn negative_verify_clear_signing_proof_rejects_substituted_proof_a_with_generator() {
    let proof_ok = Groth16Proof::from_bytes(&known_good_proof_bytes()).unwrap();
    let vk = VerificationKey::from_bytes(&vk_data::VK_BYTES).unwrap();
    let bogus = Groth16Proof {
        a: G1Affine::generator(),
        b: proof_ok.b,
        c: proof_ok.c,
    };
    assert!(!verify_clear_signing_proof(
        &tv::TEST_CALLDATA,
        &tv::TEST_READABLE,
        &bogus,
        &vk
    ));
}

#[test]
fn negative_verify_clear_signing_proof_rejects_identity_proof_a() {
    // Identity is the most-obvious free-pass candidate: pairing(0, *) =
    // 1_Gt. The verifier MUST reject — otherwise an attacker can
    // construct a "valid"-looking trivial proof.
    let proof_ok = Groth16Proof::from_bytes(&known_good_proof_bytes()).unwrap();
    let vk = VerificationKey::from_bytes(&vk_data::VK_BYTES).unwrap();
    let bogus = Groth16Proof {
        a: G1Affine::identity(),
        b: proof_ok.b,
        c: proof_ok.c,
    };
    assert!(!verify_clear_signing_proof(
        &tv::TEST_CALLDATA,
        &tv::TEST_READABLE,
        &bogus,
        &vk
    ));
}

#[test]
fn negative_verify_clear_signing_proof_rejects_identity_proof_c() {
    let proof_ok = Groth16Proof::from_bytes(&known_good_proof_bytes()).unwrap();
    let vk = VerificationKey::from_bytes(&vk_data::VK_BYTES).unwrap();
    let bogus = Groth16Proof {
        a: proof_ok.a,
        b: proof_ok.b,
        c: G1Affine::identity(),
    };
    assert!(!verify_clear_signing_proof(
        &tv::TEST_CALLDATA,
        &tv::TEST_READABLE,
        &bogus,
        &vk
    ));
}

#[test]
fn negative_verify_clear_signing_proof_rejects_modified_vk_alpha() {
    // Tamper alpha_g1 (byte 0 high half) — should either fail to
    // deserialize (good, caught early) OR deserialize to a different
    // point that breaks the pairing equation (also good). What is NOT
    // acceptable: tampered VK silently validates the genuine proof.
    let mut tampered_vk = vk_data::VK_BYTES;
    tampered_vk[0] ^= 0x10;
    let proof = Groth16Proof::from_bytes(&known_good_proof_bytes()).unwrap();
    match VerificationKey::from_bytes(&tampered_vk) {
        None => { /* parse rejected → good */ }
        Some(vk_bad) => {
            assert!(
                !verify_clear_signing_proof(
                    &tv::TEST_CALLDATA,
                    &tv::TEST_READABLE,
                    &proof,
                    &vk_bad
                ),
                "tampered VK MUST NOT validate the genuine proof"
            );
        }
    }
}

#[test]
fn negative_verify_clear_signing_proof_rejects_swapped_calldata_readable_pubs() {
    // Push TEST_READABLE bytes into the calldata slot (zero-padded
    // out to 164) and TEST_CALLDATA bytes into the readable slot
    // (truncated to 64). The pairs become two new public inputs not
    // attested by the proof and MUST fail.
    let proof = Groth16Proof::from_bytes(&known_good_proof_bytes()).unwrap();
    let vk = VerificationKey::from_bytes(&vk_data::VK_BYTES).unwrap();
    let mut cd_from_readable = [0u8; MAX_CALLDATA];
    cd_from_readable[..STRING_LEN].copy_from_slice(&tv::TEST_READABLE);
    let mut rd_from_calldata = [0u8; STRING_LEN];
    rd_from_calldata.copy_from_slice(&tv::TEST_CALLDATA[..STRING_LEN]);
    assert!(!verify_clear_signing_proof(
        &cd_from_readable,
        &rd_from_calldata,
        &proof,
        &vk
    ));
}

#[test]
fn negative_verify_clear_signing_proof_rejects_substituted_unrelated_vk() {
    // Construct a "VK" by reusing the SAME VK bytes but rotating one
    // IC point through a scalar mul — produces a syntactically-valid
    // VK that disagrees with the proof on the pairing equation.
    let mut vk_alt = vk_data::VK_BYTES;
    let ic1 = G1Affine::from_uncompressed(vk_alt[768..864].try_into().unwrap())
        .expect("known-good IC[1] parses");
    let rotated = G1Affine::from(G1Projective::from(ic1) * Scalar::from(3u64));
    vk_alt[768..864].copy_from_slice(&rotated.to_uncompressed());
    let vk = VerificationKey::from_bytes(&vk_alt).expect("rotated IC[1] is still on curve");
    let proof = Groth16Proof::from_bytes(&known_good_proof_bytes()).unwrap();
    assert!(!verify_clear_signing_proof(
        &tv::TEST_CALLDATA,
        &tv::TEST_READABLE,
        &proof,
        &vk
    ));
}

// ──────────────────────────────────────────────────────────────────────
// Negative: v3 verifier — pubs-binding to ERC20_POSEIDON_ROOT
// ──────────────────────────────────────────────────────────────────────

#[test]
fn negative_verify_clear_signing_proof_v3_rejects_wrong_root() {
    // The v3 entry point uses the rodata-pinned `erc20_poseidon_root`
    // as a third public input. Even with a syntactically-valid VK and
    // a (necessarily mismatched) proof, swapping in a different root
    // MUST NOT raise the chances of a false accept. The 2-pub Aave VK
    // is wrong shape for v3, but the v3 decoder still parses it (the
    // 4th IC slot is the identity point we crafted) and the pairing
    // equation will reject — same as any genuine v3 failure path.
    let canonical = [0xa5u8; 204];
    let readable = [0xb6u8; 128];
    let proof = Groth16Proof::from_bytes(&known_good_proof_bytes()).unwrap();
    let vk = VerificationKeyV3::from_bytes(&vk_v3_with_identity_ic3()).unwrap();
    let bogus_root = Scalar::from(42u64);
    let ok = verify_clear_signing_proof_v3(&canonical, &readable, &proof, &vk, bogus_root);
    assert!(!ok);
}

// ──────────────────────────────────────────────────────────────────────
// Negative: VK bundle parser — structural rejection
// ──────────────────────────────────────────────────────────────────────

#[test]
fn negative_verify_vk_bundle_rejects_empty_buffer() {
    assert!(verify_vk_bundle(&[]).is_none());
}

#[test]
fn negative_verify_vk_bundle_rejects_one_byte_short_of_header() {
    let bundle = vec![0u8; MIN_BUNDLE_LEN - 1];
    assert!(verify_vk_bundle(&bundle).is_none());
}

#[test]
fn negative_verify_vk_bundle_rejects_proof_depth_above_32() {
    // The decoder caps `proof_depth` at 32 to bound stack usage and
    // to keep `proof_depth * 32 ≤ 1024`. Any depth in (32, u32::MAX]
    // MUST be rejected without even attempting to slice the trailer.
    let depth = 33u32;
    let mut bundle = vec![0u8; MIN_BUNDLE_LEN + (depth as usize) * 32];
    bundle[28..28 + VK_BLOB_LEN].copy_from_slice(&vk_v3_with_identity_ic3());
    bundle[1088..1092].copy_from_slice(&depth.to_le_bytes());
    assert!(verify_vk_bundle(&bundle).is_none());
}

#[test]
fn negative_verify_vk_bundle_rejects_extreme_proof_depth() {
    // 0xFFFF_FFFF — would multiply to overflow + a multi-GB read.
    // Must be rejected at the cap check, never at the multiplication.
    let mut bundle = vec![0u8; MIN_BUNDLE_LEN];
    bundle[28..28 + VK_BLOB_LEN].copy_from_slice(&vk_v3_with_identity_ic3());
    bundle[1088..1092].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(verify_vk_bundle(&bundle).is_none());
}

#[test]
fn negative_verify_vk_bundle_rejects_trailing_bytes_after_proof() {
    // The decoder enforces `bundle.len() == off + proof_size`. A
    // bundle with a valid prefix but an extra trailing byte MUST be
    // rejected — otherwise the trailer length is malleable, and a
    // companion could append arbitrary bytes that an audit log would
    // not see.
    let mut bundle = well_shaped_but_merkle_invalid_bundle().to_vec();
    bundle.push(0x00);
    assert!(verify_vk_bundle(&bundle).is_none());
}

#[test]
fn negative_verify_vk_bundle_rejects_truncated_proof_tail() {
    // proof_depth = 2 but only 32 bytes of proof material — short by
    // one sibling hash. MUST be rejected.
    let mut bundle = vec![0u8; MIN_BUNDLE_LEN + 32];
    bundle[28..28 + VK_BLOB_LEN].copy_from_slice(&vk_v3_with_identity_ic3());
    bundle[1088..1092].copy_from_slice(&2u32.to_le_bytes());
    assert!(verify_vk_bundle(&bundle).is_none());
}

#[test]
fn negative_verify_vk_bundle_rejects_structurally_valid_but_wrong_root() {
    // Well-shaped bundle (depth=0, leaf canonical bytes are 1084-byte
    // sequence) — but its leaf hash is not VK_DB_ROOT. The Merkle walk
    // MUST reject; otherwise the trust chain ("we only run Groth16
    // on VKs anchored by firmware-signing key") collapses.
    let bundle = well_shaped_but_merkle_invalid_bundle();
    assert!(verify_vk_bundle(&bundle).is_none());
}

#[test]
fn negative_verify_vk_bundle_proof_depth_32_with_wrong_root_still_rejected() {
    // Depth = 32 (the cap) is structurally accepted — the rejection
    // here must come from the Merkle walk, not the cap check.
    let depth = 32u32;
    let mut bundle = vec![0u8; MIN_BUNDLE_LEN + (depth as usize) * 32];
    bundle[28..28 + VK_BLOB_LEN].copy_from_slice(&vk_v3_with_identity_ic3());
    bundle[1088..1092].copy_from_slice(&depth.to_le_bytes());
    // proof bytes = all zeros → hash walk converges on a deterministic
    // root that is NOT VK_DB_ROOT.
    assert!(verify_vk_bundle(&bundle).is_none());
}

// ──────────────────────────────────────────────────────────────────────
// Negative: top-level entry points (mod.rs wrappers)
// ──────────────────────────────────────────────────────────────────────

#[test]
fn negative_verify_clear_sign_proof_rejects_malformed_proof_bytes() {
    let bad_proof = [0xffu8; PROOF_LEN];
    let bundle = well_shaped_but_merkle_invalid_bundle();
    let res = verify_clear_sign_proof(
        &bad_proof,
        &tv::TEST_CALLDATA,
        &tv::TEST_READABLE,
        &bundle,
    );
    assert!(res.is_err(), "garbage proof bytes MUST yield ClearSignError");
}

#[test]
fn negative_verify_clear_sign_proof_rejects_malformed_bundle() {
    let good_proof = known_good_proof_bytes();
    let too_short = [0u8; 16];
    let res = verify_clear_sign_proof(
        &good_proof,
        &tv::TEST_CALLDATA,
        &tv::TEST_READABLE,
        &too_short,
    );
    assert!(res.is_err());
}

#[test]
fn negative_verify_and_bind_trailer_v1_rejects_too_short_bundle() {
    use sphincs_tz_shared::ZK_CLEAR_SIGN_FIXED_LEN;
    let bundle = vec![0u8; ZK_CLEAR_SIGN_FIXED_LEN - 1];
    let inner = [0u8; 16];
    assert!(verify_and_bind_trailer_v1(&bundle, &inner, 1, &[0u8; 20]).is_none());
}

#[test]
fn negative_verify_and_bind_trailer_v1_rejects_inner_data_too_long() {
    use sphincs_tz_shared::ZK_CLEAR_SIGN_FIXED_LEN;
    let bundle = vec![0u8; ZK_CLEAR_SIGN_FIXED_LEN + MIN_BUNDLE_LEN];
    let too_big_inner = vec![0u8; MAX_CALLDATA + 1];
    assert!(verify_and_bind_trailer_v1(&bundle, &too_big_inner, 1, &[0u8; 20]).is_none());
}

#[test]
fn negative_verify_and_bind_trailer_v1_rejects_malformed_proof_in_trailer() {
    // Trailer with the correct fixed-prefix length but garbage proof
    // bytes — `verify_clear_sign_proof` should fail and the wrapper
    // collapses to None.
    use sphincs_tz_shared::ZK_CLEAR_SIGN_FIXED_LEN;
    let mut bundle = vec![0xffu8; ZK_CLEAR_SIGN_FIXED_LEN];
    bundle.extend_from_slice(&well_shaped_but_merkle_invalid_bundle());
    let inner = [0u8; 16];
    assert!(verify_and_bind_trailer_v1(&bundle, &inner, 1, &[0u8; 20]).is_none());
}

// ──────────────────────────────────────────────────────────────────────
// Negative: VK-bundle accessors — slice-length invariants
// ──────────────────────────────────────────────────────────────────────

#[test]
fn negative_vk_blob_len_2pub_is_960_and_3pub_is_1056() {
    // The accessors `vk_as_2pub` / `vk_as_3pub` panic ("compile-time
    // constant") if these ever drift. Pinning the values here gives
    // a clear failure message at the test-time boundary instead of
    // a generic panic-in-prod failure.
    assert_eq!(VK_BLOB_LEN_2PUB, 960);
    assert_eq!(VK_BLOB_LEN_3PUB, 1056);
    assert_eq!(VK_BLOB_LEN, 1056);
    assert!(
        VK_BLOB_LEN_2PUB <= VK_BLOB_LEN,
        "the 2-pub view MUST fit inside the slot"
    );
    assert!(
        VK_BLOB_LEN_3PUB <= VK_BLOB_LEN,
        "the 3-pub view MUST fit inside the slot"
    );
}
