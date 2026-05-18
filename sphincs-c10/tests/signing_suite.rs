//! Positive + negative coverage for SPHINCS+C10 sign / verify.
//!
//! Designed as a single integration-test binary so the (multi-second)
//! `SigningKey::keygen` only runs ONCE — every test borrows a shared
//! `SigningKey` from a `OnceLock`. Without this discipline, a 30-test
//! file would do 30 keygens × ~1 s each in release mode.
//!
//! The negative cases are the load-bearing artefact: each one names the
//! assumption being attacked and asserts the rejection is enforced.

use sphincs_c10::params::{A, D, K, L, N, SIGNATURE_LEN, SIG_FORS_TOTAL, SIG_HT_LAYER, SUBTREE_H};
use sphincs_c10::shuffle::ShuffleSeed;
use sphincs_c10::{verify, SigningKey, VerifyingKey};
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// Shared fixture
// ---------------------------------------------------------------------------

const SK_SEED: [u8; 32] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
    0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01,
];
const PK_SEED: [u8; N] = [
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
];
const MSG: [u8; 32] = *b"PQSigner C10 signing-suite msg !";

fn sk() -> &'static SigningKey {
    static SK: OnceLock<SigningKey> = OnceLock::new();
    SK.get_or_init(|| SigningKey::keygen(SK_SEED, PK_SEED))
}

fn base_sig() -> &'static [u8; SIGNATURE_LEN] {
    static SIG: OnceLock<[u8; SIGNATURE_LEN]> = OnceLock::new();
    SIG.get_or_init(|| sk().sign(&MSG, None))
}

// ===========================================================================
// POSITIVE: golden-path coverage of every public API
// ===========================================================================

#[test]
fn positive_keygen_yields_consistent_pk() {
    let key = sk();
    // pk_seed reads back exactly what we passed in.
    assert_eq!(key.pk_seed(), &PK_SEED);
    // sk_seed reads back exactly what we passed in (Type 1 KDF needs it).
    assert_eq!(key.sk_seed(), &SK_SEED);
    // pk_root is derived; not zero (the all-zero root would mean keygen
    // never ran). Specifically: at least one nonzero byte.
    assert!(
        key.pk_root().iter().any(|&b| b != 0),
        "pk_root must be a derived hash, not all-zero"
    );
}

#[test]
fn positive_keygen_is_deterministic() {
    // Re-derive a fresh key from the same seeds; pk_root must match.
    let fresh = SigningKey::keygen(SK_SEED, PK_SEED);
    assert_eq!(fresh.pk_seed(), sk().pk_seed());
    assert_eq!(fresh.pk_root(), sk().pk_root());
}

#[test]
fn positive_verifying_key_round_trips_bytes() {
    let vk = sk().verifying_key();
    let bytes = vk.to_bytes();
    assert_eq!(bytes.len(), 32);
    // Layout: pk_seed[0..16] || pk_root[16..32]
    assert_eq!(&bytes[..N], sk().pk_seed());
    assert_eq!(&bytes[N..], sk().pk_root());
    let round = VerifyingKey::from_bytes(&bytes);
    assert_eq!(round, vk);
}

#[test]
fn positive_verifying_key_from_arbitrary_bytes() {
    // from_bytes must accept any 32-byte input (no validation by design)
    // and split it as pk_seed[..16] || pk_root[16..].
    let bytes = [0x42u8; 32];
    let vk = VerifyingKey::from_bytes(&bytes);
    assert_eq!(vk.pk_seed, [0x42u8; 16]);
    assert_eq!(vk.pk_root, [0x42u8; 16]);
}

#[test]
fn positive_sign_yields_4008_bytes() {
    assert_eq!(base_sig().len(), 4008);
    assert_eq!(base_sig().len(), SIGNATURE_LEN);
}

#[test]
fn positive_sign_then_verify_via_standalone_fn() {
    assert!(verify(sk().pk_seed(), sk().pk_root(), &MSG, base_sig()));
}

#[test]
fn positive_sign_then_verify_via_verifying_key() {
    let vk = sk().verifying_key();
    assert!(vk.verify(&MSG, base_sig()));
}

#[test]
fn positive_sign_no_opt_rand_is_deterministic() {
    let a = sk().sign(&MSG, None);
    let b = sk().sign(&MSG, None);
    assert_eq!(
        a.as_slice(),
        b.as_slice(),
        "sign(..., None) MUST be byte-stable — this is load-bearing for \
         c10_test_vectors.json reproducibility (see hypertree.rs)"
    );
}

#[test]
fn positive_sign_with_opt_rand_still_verifies() {
    let rand = [0x77u8; N];
    let sig = sk().sign(&MSG, Some(&rand));
    assert!(
        verify(sk().pk_seed(), sk().pk_root(), &MSG, &sig),
        "opt_rand must NOT break verification (it's mixed into R-grind only)"
    );
}

#[test]
fn positive_opt_rand_changes_sig_bytes() {
    // The F-9 fix premise: feeding different opt_rand changes the
    // R-grind iteration count and therefore the signature bytes — that's
    // exactly what makes the iteration count side-channel non-trivial.
    let sig_none = sk().sign(&MSG, None);
    let sig_a = sk().sign(&MSG, Some(&[0x01u8; N]));
    let sig_b = sk().sign(&MSG, Some(&[0x02u8; N]));
    assert_ne!(sig_none, sig_a);
    assert_ne!(sig_a, sig_b);
}

#[test]
fn positive_opt_rand_same_value_is_deterministic() {
    let rand = [0xC3u8; N];
    let a = sk().sign(&MSG, Some(&rand));
    let b = sk().sign(&MSG, Some(&rand));
    assert_eq!(a.as_slice(), b.as_slice());
}

#[test]
fn positive_sign_with_shuffle_zero_matches_plain_sign() {
    let plain = sk().sign(&MSG, None);
    let shuffled = sk()
        .sign_with_shuffle(&MSG, None, &ShuffleSeed::zero(), |_| {});
    assert_eq!(
        plain.as_slice(),
        shuffled.as_slice(),
        "ShuffleSeed::zero() MUST produce byte-identical output to \
         the no-shuffle path (see shuffle.rs invariant)"
    );
}

#[test]
fn positive_sign_with_shuffle_nonzero_still_byte_equal() {
    // The shuffle is a pure computational re-ordering; output bytes
    // must NOT depend on the shuffle seed. (Duplicate of
    // shuffle_byte_equality.rs but checked here against a different
    // message for breadth.)
    let s = ShuffleSeed([0xDEu8; 32]);
    let shuffled = sk().sign_with_shuffle(&MSG, None, &s, |_| {});
    let plain = sk().sign(&MSG, None);
    assert_eq!(plain.as_slice(), shuffled.as_slice());
}

#[test]
fn positive_progress_callback_invoked_monotonically_to_100() {
    use std::cell::RefCell;
    let observed: RefCell<Vec<u8>> = RefCell::new(Vec::new());
    // We have to use a fn pointer (not closure capturing env); use a
    // thread-local instead.
    thread_local!(static PROG: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) });

    fn cb(pct: u8) {
        PROG.with(|v| v.borrow_mut().push(pct));
    }
    PROG.with(|v| v.borrow_mut().clear());
    let _ = sk().sign_with_shuffle(&MSG, None, &ShuffleSeed::zero(), cb);
    let prog: Vec<u8> = PROG.with(|v| v.borrow().clone());

    assert!(!prog.is_empty(), "progress callback was never invoked");
    assert_eq!(prog[0], 0, "first progress tick should be 0%");
    assert_eq!(prog[prog.len() - 1], 100, "final progress tick should be 100%");
    // Monotonically non-decreasing.
    for w in prog.windows(2) {
        assert!(
            w[0] <= w[1],
            "progress must be monotone non-decreasing: got {} then {}",
            w[0], w[1]
        );
    }
    let _ = observed;
}

// ===========================================================================
// NEGATIVE: assumption-challenging tests
// ===========================================================================

// --- Family: message / key substitution ---

#[test]
fn negative_wrong_message_is_rejected() {
    // Assumption: the message hash is bound into the signature via h_msg
    // and the FORS index extraction. A different message MUST not verify.
    let wrong_msg = *b"This is definitely NOT the msg!!";
    assert_ne!(MSG, wrong_msg);
    assert!(
        !verify(sk().pk_seed(), sk().pk_root(), &wrong_msg, base_sig()),
        "a signature over MSG must NOT verify against a different message"
    );
}

#[test]
fn negative_wrong_pk_root_is_rejected() {
    // Assumption: the hypertree root pins the signing identity. A
    // different pk_root means a different on-chain wallet.
    let mut wrong = *sk().pk_root();
    wrong[0] ^= 0x01;
    assert!(
        !verify(sk().pk_seed(), &wrong, &MSG, base_sig()),
        "sig must not verify under a mutated pk_root"
    );
}

#[test]
fn negative_wrong_pk_seed_is_rejected() {
    // Assumption: pk_seed is mixed into every tweakable-hash call, so a
    // different pk_seed changes every internal hash → reconstruction
    // diverges from pk_root.
    let mut wrong = *sk().pk_seed();
    wrong[N - 1] ^= 0x80;
    assert!(
        !verify(&wrong, sk().pk_root(), &MSG, base_sig()),
        "sig must not verify under a mutated pk_seed"
    );
}

#[test]
fn negative_cross_key_sig_is_rejected() {
    // Assumption: a signature from key A cannot validate under key B's
    // pk_root, even with B's correct pk_seed. This is the foundational
    // C10 security property — without it any wallet could forge for any
    // other.
    let mut sk2_seed = SK_SEED;
    sk2_seed[0] ^= 0xFF;
    let sk2 = SigningKey::keygen(sk2_seed, PK_SEED);
    let sig_under_sk2 = sk2.sign(&MSG, None);

    // sig from sk2 must NOT verify under sk1's pk_root
    assert!(
        !verify(sk().pk_seed(), sk().pk_root(), &MSG, &sig_under_sk2),
        "cross-key forgery: sig from sk2 must NOT verify under sk1's key"
    );
    // Sanity: sig from sk2 verifies under sk2's own key.
    assert!(verify(sk2.pk_seed(), sk2.pk_root(), &MSG, &sig_under_sk2));
}

// --- Family: signature mutations at every offset region ---
//
// Each test corrupts ONE byte in a specific region of the wire format.
// `verify` MUST return false in every case (no panic, no accidental
// accept). The point is to catch any future "optimization" that
// short-circuits one of the verification stages.

fn assert_rejects_with_byte_flipped_at(offset: usize, region: &'static str) {
    let mut sig = *base_sig();
    sig[offset] ^= 0xFF;
    assert!(
        !verify(sk().pk_seed(), sk().pk_root(), &MSG, &sig),
        "mutating byte {offset} (region: {region}) MUST cause verify to fail \
         — otherwise the {region} portion of the signature is not being \
         checked, which is a forgery primitive."
    );
}

#[test]
fn negative_mutated_r_first_byte_rejected() {
    // R (randomiser, bytes [0..16)) is the only input the signer
    // controls that feeds h_msg directly. Changing it changes the
    // digest, which changes the FORS index for the last tree (which
    // MUST be zero by R-grinding). Verify catches it either via the
    // forced-zero check or via the full hypertree mismatch.
    assert_rejects_with_byte_flipped_at(0, "R[0]");
}

#[test]
fn negative_mutated_r_last_byte_rejected() {
    assert_rejects_with_byte_flipped_at(N - 1, "R[15]");
}

#[test]
fn negative_mutated_fors_first_secret_rejected() {
    // FORS secrets start at offset N (=16). Mutating the secret for
    // tree 0 changes the reconstructed root for tree 0 → fors_pk
    // changes → hypertree verify fails.
    assert_rejects_with_byte_flipped_at(N, "FORS secret tree 0 byte 0");
}

#[test]
fn negative_mutated_fors_last_secret_rejected() {
    // The K-1 FORS secret IS the root (forced-zero tree). Mutating it
    // poisons fors_pk directly.
    let last_secret_offset = N + (K - 1) * N;
    assert_rejects_with_byte_flipped_at(last_secret_offset, "FORS secret tree K-1");
}

#[test]
fn negative_mutated_fors_auth_path_first_byte_rejected() {
    // Auth paths start at N + K*N = 16 + 208 = 224.
    let auth_offset = N + K * N;
    assert_rejects_with_byte_flipped_at(auth_offset, "FORS auth path tree 0 level 0");
}

#[test]
fn negative_mutated_fors_auth_path_last_byte_rejected() {
    // Last byte of FORS auth section.
    let last = SIG_FORS_TOTAL - 1;
    assert_rejects_with_byte_flipped_at(last, "FORS auth path final byte");
}

#[test]
fn negative_mutated_ht_layer0_wots_sigma_first_byte_rejected() {
    // HT layer 0 starts at SIG_FORS_TOTAL = 2336; WOTS sigma is the
    // first L*N=688 bytes.
    assert_rejects_with_byte_flipped_at(SIG_FORS_TOTAL, "HT layer 0 WOTS sigma byte 0");
}

#[test]
fn negative_mutated_ht_layer0_wots_sigma_last_byte_rejected() {
    let last_sigma = SIG_FORS_TOTAL + L * N - 1;
    assert_rejects_with_byte_flipped_at(last_sigma, "HT layer 0 WOTS sigma last byte");
}

#[test]
fn negative_mutated_ht_layer0_count_rejected() {
    // The count is the WOTS+C target-sum witness. Flipping it makes the
    // digit sum miss TARGET_SUM=205. The Yul verifier reverts via
    // `eq(digitSum, 205)`; the Rust verifier returns false.
    let count_offset = SIG_FORS_TOTAL + L * N;
    assert_rejects_with_byte_flipped_at(count_offset, "HT layer 0 count[0]");
    assert_rejects_with_byte_flipped_at(count_offset + 3, "HT layer 0 count[3]");
}

#[test]
fn negative_mutated_ht_layer0_auth_path_rejected() {
    let auth_offset = SIG_FORS_TOTAL + L * N + 4;
    assert_rejects_with_byte_flipped_at(auth_offset, "HT layer 0 auth path byte 0");
    // And the last byte of layer 0 auth path.
    assert_rejects_with_byte_flipped_at(
        auth_offset + SUBTREE_H * N - 1,
        "HT layer 0 auth path last byte",
    );
}

#[test]
fn negative_mutated_ht_layer1_wots_sigma_rejected() {
    let l1_off = SIG_FORS_TOTAL + SIG_HT_LAYER;
    assert_rejects_with_byte_flipped_at(l1_off, "HT layer 1 WOTS sigma byte 0");
    assert_rejects_with_byte_flipped_at(l1_off + L * N - 1, "HT layer 1 WOTS sigma last");
}

#[test]
fn negative_mutated_ht_layer1_count_rejected() {
    let count_offset = SIG_FORS_TOTAL + SIG_HT_LAYER + L * N;
    assert_rejects_with_byte_flipped_at(count_offset, "HT layer 1 count");
}

#[test]
fn negative_mutated_ht_layer1_auth_path_last_byte_rejected() {
    // Last byte of the whole signature is the final auth path leaf for
    // layer 1. Catching this proves the verifier really walks all
    // SUBTREE_H levels of both layers.
    assert_rejects_with_byte_flipped_at(SIGNATURE_LEN - 1, "HT layer 1 auth path final byte");
}

// --- Family: trivial / degenerate signatures ---

#[test]
fn negative_all_zero_signature_is_rejected() {
    // Assumption: the verifier never accepts a trivial signature.
    let zero = [0u8; SIGNATURE_LEN];
    assert!(
        !verify(sk().pk_seed(), sk().pk_root(), &MSG, &zero),
        "all-zero signature must NOT verify (would be a trivial forgery)"
    );
}

#[test]
fn negative_all_ones_signature_is_rejected() {
    let ones = [0xFFu8; SIGNATURE_LEN];
    assert!(
        !verify(sk().pk_seed(), sk().pk_root(), &MSG, &ones),
        "all-0xFF signature must NOT verify"
    );
}

#[test]
fn negative_random_garbage_signature_is_rejected() {
    // Pseudo-random bytes (deterministic via xor pattern so the test
    // doesn't flake).
    let mut garbage = [0u8; SIGNATURE_LEN];
    for (i, b) in garbage.iter_mut().enumerate() {
        *b = ((i as u32).wrapping_mul(2654435761) >> 24) as u8;
    }
    assert!(
        !verify(sk().pk_seed(), sk().pk_root(), &MSG, &garbage),
        "pseudo-random signature must NOT verify"
    );
}

#[test]
fn negative_swapped_two_keys_sig_rejected() {
    // A signature from key A under msg, replayed against key B (with B's
    // own pk_seed) must be rejected even though both share the same
    // message format and the verifier code path.
    let mut sk2_seed = SK_SEED;
    sk2_seed[15] ^= 0xAA;
    let sk2 = SigningKey::keygen(sk2_seed, PK_SEED);
    assert_ne!(
        sk2.pk_root(),
        sk().pk_root(),
        "different sk_seed must produce different pk_root"
    );
    let sig_sk1 = base_sig();
    assert!(
        !verify(sk2.pk_seed(), sk2.pk_root(), &MSG, sig_sk1),
        "sig from sk1 must NOT verify under sk2's pk_root"
    );
}

#[test]
fn negative_different_pk_seed_yields_different_pk_root() {
    // Assumption: pk_seed is part of the master-key derivation; two
    // wallets with the same sk_seed but different pk_seed must produce
    // different addresses (otherwise the salt = sha256(pk_seed||pk_root)
    // collapses).
    let mut alt_pk_seed = PK_SEED;
    alt_pk_seed[0] ^= 0x01;
    let other = SigningKey::keygen(SK_SEED, alt_pk_seed);
    assert_ne!(other.pk_root(), sk().pk_root());
}

// --- Family: structural verifier invariants ---

#[test]
fn negative_forced_zero_fors_index_is_enforced_in_emitted_sig() {
    // Per hypertree::sign / fors::grind_r: R-grinding MUST find an R
    // such that the last FORS index is 0. If a future refactor breaks
    // R-grinding (e.g. caps iterations or skips the check), the emitted
    // signature will have a non-zero last index and the on-chain
    // verifier will reject it — losing all wallets. We assert the
    // property by running the verifier ourselves (which checks the
    // forced-zero constraint as a precondition) on every freshly signed
    // message.
    for msg_byte in [0x00u8, 0x55, 0xAA, 0xFF] {
        let msg = [msg_byte; 32];
        let sig = sk().sign(&msg, None);
        assert!(
            verify(sk().pk_seed(), sk().pk_root(), &msg, &sig),
            "freshly-signed message MUST verify (implies forced-zero \
             constraint held during R-grinding); msg=[{msg_byte:#04x}; 32]"
        );
    }
}

#[test]
fn negative_verify_does_not_panic_on_corrupt_count_field() {
    // The WOTS+C verifier multiplies count into the digest. A maliciously
    // chosen count must NOT cause an out-of-bounds access or a panic —
    // it must just produce a target_sum-mismatch and return false.
    // (Verified by exhaustive flipping of the 4 count bytes per layer.)
    let count0_offset = SIG_FORS_TOTAL + L * N;
    let count1_offset = SIG_FORS_TOTAL + SIG_HT_LAYER + L * N;
    for &offset in &[count0_offset, count1_offset] {
        for byte in 0..4 {
            let mut sig = *base_sig();
            sig[offset + byte] = 0xFF;
            // Must not panic; result is either false (most common) or true
            // (only if the original count happened to be `…FF` at that
            // byte). Either way: no panic, no UB.
            let _ = verify(sk().pk_seed(), sk().pk_root(), &MSG, &sig);
        }
    }
}

#[test]
fn negative_truncated_signature_type_is_statically_impossible() {
    // The verifier signature is typed `&[u8; SIGNATURE_LEN]`. A
    // truncated slice can't be passed at all — the compiler rejects it.
    // This test exists as living documentation: removing the fixed-size
    // array type and replacing with `&[u8]` would silently regress this
    // guarantee.
    //
    // Compile-only check:
    let f: fn(&[u8; N], &[u8; N], &[u8; 32], &[u8; SIGNATURE_LEN]) -> bool = verify;
    let _ = f;
}

#[test]
fn negative_swapped_sig_layers_rejected() {
    // Swap the two HT layer sections. Each layer's auth path is
    // position-bound (idx_tree is shifted differently), so swapping
    // them MUST be rejected. Without this check a layer-reuse attack
    // could in principle re-use a Type 2 sig segment.
    let mut sig = *base_sig();
    let l0_start = SIG_FORS_TOTAL;
    let l1_start = SIG_FORS_TOTAL + SIG_HT_LAYER;
    let l1_end = l1_start + SIG_HT_LAYER;

    // Save layer 0 and layer 1, then swap.
    let mut layer0 = [0u8; SIG_HT_LAYER];
    let mut layer1 = [0u8; SIG_HT_LAYER];
    layer0.copy_from_slice(&sig[l0_start..l1_start]);
    layer1.copy_from_slice(&sig[l1_start..l1_end]);
    sig[l0_start..l1_start].copy_from_slice(&layer1);
    sig[l1_start..l1_end].copy_from_slice(&layer0);

    assert!(
        !verify(sk().pk_seed(), sk().pk_root(), &MSG, &sig),
        "swapping HT layer 0 ⇔ HT layer 1 must be rejected (layer index \
         is bound into each WOTS adrs)"
    );
}

// --- Family: D=2 layer count consistency (sanity)

#[test]
fn negative_d_is_two_layers() {
    // The sign/verify code unrolls a loop `0..D as u32`. If anyone bumps
    // D without also updating the on-chain verifier (which hard-codes 2
    // layers), the firmware would produce signatures the wallet can't
    // verify. This is the single integer that ties firmware and contract
    // together; pin it.
    assert_eq!(D, 2, "D MUST be 2 (frozen per CLAUDE.md / SPHINCsC10Asm)");
}

#[test]
fn negative_a_times_k_plus_h_fits_in_digest() {
    // h_msg returns 32 bytes (256 bits). FORS index extraction reads
    // K * A bits from the LSB, then HT extraction reads H more. The
    // total MUST fit in 256 bits, or read_bits_le silently returns
    // zeros and the verifier produces meaningless results.
    let total_bits = K * A + H_PRIVATE;
    assert!(
        total_bits <= 256,
        "K*A + H = {total_bits} must fit in 256-bit digest"
    );
    // For C10 specifically: 13*11 + 18 = 161 bits used.
    assert_eq!(total_bits, 161);
}

// Local alias because `params::H` shadows nothing here but the name
// reads more clearly as `H_PRIVATE` in the bit-budget assertion.
const H_PRIVATE: usize = sphincs_c10::params::H;
