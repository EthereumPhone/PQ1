//! Entropy-blob format negatives.  The stored blob layout is
//!
//!     nonce(12) || ciphertext(32) || tag(16) = 60 bytes
//!
//! and `decrypt_entropy_blob` is what runs every cold boot to unwrap
//! the user's BIP-39 entropy.  Any silent tolerance to a tampered blob
//! is a path to entropy substitution — the highest-severity attack on
//! a wallet.

use pqsigner_domain::{
    decrypt_entropy_blob, encrypt_entropy_blob, ENTROPY_BLOB_LEN, ENTROPY_LEN,
};

const MASTER: [u8; 32] = [0xC3u8; 32];
const ENTROPY: [u8; ENTROPY_LEN] = [0x7Du8; ENTROPY_LEN];

#[test]
fn negative_entropy_blob_layout_is_60_bytes() {
    // Frozen wire shape: callers store this in SE r-mem slot 0.
    // Length change without coordinated provisioning update would
    // corrupt every device in the field.
    assert_eq!(ENTROPY_BLOB_LEN, 60);
    let blob = encrypt_entropy_blob(&ENTROPY, &MASTER);
    assert_eq!(blob.len(), 60);
}

#[test]
fn negative_entropy_blob_rejects_short_blob_by_one() {
    let blob = encrypt_entropy_blob(&ENTROPY, &MASTER);
    let short = &blob[..ENTROPY_BLOB_LEN - 1];
    assert!(
        decrypt_entropy_blob(short, &MASTER).is_err(),
        "blob shorter than ENTROPY_BLOB_LEN must be rejected"
    );
}

#[test]
fn negative_entropy_blob_rejects_long_blob_by_one() {
    let blob = encrypt_entropy_blob(&ENTROPY, &MASTER);
    let mut long = [0u8; ENTROPY_BLOB_LEN + 1];
    long[..ENTROPY_BLOB_LEN].copy_from_slice(&blob);
    assert!(
        decrypt_entropy_blob(&long, &MASTER).is_err(),
        "blob longer than ENTROPY_BLOB_LEN must be rejected"
    );
}

#[test]
fn negative_entropy_blob_rejects_empty_blob() {
    assert!(decrypt_entropy_blob(&[], &MASTER).is_err());
}

#[test]
fn negative_entropy_blob_rejects_byte_flip_in_nonce() {
    // The nonce is part of the AEAD AD parameter and the GCM
    // J0/counter; flipping any nonce byte must cause tag mismatch.
    for pos in 0..12 {
        let mut blob = encrypt_entropy_blob(&ENTROPY, &MASTER);
        blob[pos] ^= 0x01;
        assert!(
            decrypt_entropy_blob(&blob, &MASTER).is_err(),
            "nonce byte flip at {pos} must be rejected"
        );
    }
}

#[test]
fn negative_entropy_blob_rejects_byte_flip_in_ciphertext() {
    for pos in 12..(12 + ENTROPY_LEN) {
        let mut blob = encrypt_entropy_blob(&ENTROPY, &MASTER);
        blob[pos] ^= 0x40;
        assert!(
            decrypt_entropy_blob(&blob, &MASTER).is_err(),
            "ciphertext byte flip at {pos} must be rejected"
        );
    }
}

#[test]
fn negative_entropy_blob_rejects_byte_flip_in_tag() {
    for pos in (ENTROPY_BLOB_LEN - 16)..ENTROPY_BLOB_LEN {
        let mut blob = encrypt_entropy_blob(&ENTROPY, &MASTER);
        blob[pos] ^= 0xFF;
        assert!(
            decrypt_entropy_blob(&blob, &MASTER).is_err(),
            "tag byte flip at {pos} must be rejected"
        );
    }
}

#[test]
fn negative_entropy_blob_rejects_blob_from_a_different_master() {
    let blob = encrypt_entropy_blob(&ENTROPY, &MASTER);
    let other_master = [0x00u8; 32];
    assert!(
        decrypt_entropy_blob(&blob, &other_master).is_err(),
        "blob authenticated under MASTER must not decrypt under another master"
    );
}

#[test]
fn negative_entropy_blob_nonce_is_master_bound_to_prevent_reuse() {
    // Encrypting the SAME entropy under TWO different masters must
    // produce different nonces — otherwise (nonce, key) collisions
    // across the user population become possible if any master ever
    // repeats by accident.
    let blob_a = encrypt_entropy_blob(&ENTROPY, &[0u8; 32]);
    let blob_b = encrypt_entropy_blob(&ENTROPY, &[1u8; 32]);
    assert_ne!(&blob_a[..12], &blob_b[..12], "nonce must derive from master");
}

#[test]
fn negative_entropy_blob_encryption_is_pure_function_of_master() {
    // Same (entropy, master) → byte-identical blob.  Otherwise the
    // SE r-mem path that re-encrypts on every unlock would churn the
    // blob with every boot, masking real corruption.
    let a = encrypt_entropy_blob(&ENTROPY, &MASTER);
    let b = encrypt_entropy_blob(&ENTROPY, &MASTER);
    assert_eq!(a, b, "entropy blob must be deterministic given (entropy, master)");
}
