//! Regression test for the WOTS chain + FORS tree shuffling
//! introduced in F-16. The correctness invariant is:
//!
//!   sign_with_shuffle(sk, msg, opt_rand, ShuffleSeed::zero())
//!     == sign_with_shuffle(sk, msg, opt_rand, ShuffleSeed::random())
//!
//! Byte-for-byte. The shuffle is a pure computation re-ordering: any
//! seed produces the same output bytes; only the temporal ORDER of
//! internal hashes changes.
//!
//! If this regression test ever fails, the shuffle implementation
//! has a bug where the per-step iteration index is being used as a
//! VALUE (not just as a position) somewhere — which would break the
//! on-chain verifier compatibility. That bug class is exactly what
//! this oracle catches.

use sphincs_c10::{shuffle::ShuffleSeed, SigningKey};

const SK_SEED: [u8; 32] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
    0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01,
];
const PK_SEED: [u8; 16] = [
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
];
const MSG: [u8; 32] = *b"PQSigner C10 shuffle equality !1";

#[test]
fn shuffled_sig_byte_equal_to_unshuffled() {
    let sk = SigningKey::keygen(SK_SEED, PK_SEED);

    // Identity shuffle == pre-shuffle behaviour.
    let sig_unshuffled = sk.sign_with_shuffle(&MSG, None, &ShuffleSeed::zero(), |_| {});

    // Random non-zero shuffle.
    let mut seed = [0u8; 32];
    seed[0] = 0x42;
    seed[7] = 0xA9;
    seed[31] = 0xFE;
    let sig_shuffled = sk.sign_with_shuffle(&MSG, None, &ShuffleSeed(seed), |_| {});

    assert_eq!(
        sig_unshuffled.as_slice(),
        sig_shuffled.as_slice(),
        "shuffle must not change output bytes (would break on-chain verify)"
    );
}

#[test]
fn shuffled_sig_verifies() {
    let sk = SigningKey::keygen(SK_SEED, PK_SEED);
    let mut seed = [0u8; 32];
    seed[2] = 0xCD;
    let sig = sk.sign_with_shuffle(&MSG, None, &ShuffleSeed(seed), |_| {});
    assert!(
        sphincs_c10::verify(sk.pk_seed(), sk.pk_root(), &MSG, &sig),
        "shuffled sig must verify"
    );
}

#[test]
fn multiple_random_shuffles_all_equal() {
    let sk = SigningKey::keygen(SK_SEED, PK_SEED);
    let reference = sk.sign_with_shuffle(&MSG, None, &ShuffleSeed::zero(), |_| {});

    for byte in [0x01u8, 0x55, 0xAA, 0xFF, 0x42, 0x99] {
        let seed = [byte; 32];
        let sig = sk.sign_with_shuffle(&MSG, None, &ShuffleSeed(seed), |_| {});
        assert_eq!(
            sig.as_slice(),
            reference.as_slice(),
            "shuffle with seed=[{byte:#04x}; 32] diverged from identity-shuffle output"
        );
    }
}

#[test]
fn sign_wrapper_matches_zero_seed_shuffle() {
    let sk = SigningKey::keygen(SK_SEED, PK_SEED);
    let via_wrapper = sk.sign(&MSG, None);
    let via_zero_shuffle = sk.sign_with_shuffle(&MSG, None, &ShuffleSeed::zero(), |_| {});
    assert_eq!(
        via_wrapper.as_slice(),
        via_zero_shuffle.as_slice(),
        "the no-shuffle wrapper must produce identical bytes to ShuffleSeed::zero()"
    );
}
