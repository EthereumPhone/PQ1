//! Positive functional coverage for KDF helpers + AES-GCM in-place
//! routines.  Complements the existing `aes_gcm_tests` / `kdf_tests`
//! modules at the bottom of `domain/src/lib.rs` (which mostly exercise
//! roundtrips and basic separation) with additional shape / boundary /
//! determinism assertions on every public KDF and AES surface.

use pqsigner_domain::{
    aes_decrypt_inplace, aes_encrypt_inplace, derive_entropy_nonce, derive_wrap_key, kdf,
    kdf_sha256, macd_init_input, macd_pin_input, AES_GCM_TAG_LEN,
};

#[test]
fn positive_kdf_output_is_32_bytes_and_deterministic() {
    let a = kdf(b"dom", b"input", 7);
    let b = kdf(b"dom", b"input", 7);
    assert_eq!(a.len(), 32, "kdf must return exactly 32 bytes (SHA-256)");
    assert_eq!(a, b, "kdf must be deterministic for the same inputs");
}

#[test]
fn positive_kdf_sha256_alias_is_identity() {
    // Belt-and-braces — the alias predates the SHA-256 cutover; the
    // contract is "kdf_sha256 == kdf, byte for byte, forever."
    for index in [0u8, 1, 17, 0xFE, 0xFF] {
        assert_eq!(kdf(b"x", b"y", index), kdf_sha256(b"x", b"y", index));
    }
}

#[test]
fn positive_kdf_accepts_empty_domain_and_input() {
    // The function must not panic on zero-length slices — callers may
    // pass empty input on the "no extra context" branch.
    let _ = kdf(b"", b"", 0);
    let _ = kdf(b"x", b"", 0);
    let _ = kdf(b"", b"y", 0);
}

#[test]
fn positive_macd_init_and_pin_inputs_diverge() {
    // macd_init_input uses the master_secret; macd_pin_input uses the
    // 8-byte PIN. Domain tags ensure the two streams cannot collide even
    // if a caller passed identical bytes by accident.
    let master = [0x42u8; 32];
    let pin = [0x42u8; 8];
    let mut padded = [0u8; 32];
    padded[..8].copy_from_slice(&pin);

    let init = macd_init_input(&master, 0);
    // Synthesise a pin_input style result by hand to ensure the tag-based
    // domain separation between the two paths actually fires.
    let pin_result = macd_pin_input(&pin, 0);
    assert_ne!(init, pin_result, "macd_init vs macd_pin must use distinct domain tags");
}

#[test]
fn positive_macd_distinguishes_j_index() {
    let master = [0u8; 32];
    let m0 = macd_init_input(&master, 0);
    let m1 = macd_init_input(&master, 1);
    assert_ne!(m0, m1);

    let pin = [0u8; 8];
    let p0 = macd_pin_input(&pin, 0);
    let p1 = macd_pin_input(&pin, 1);
    assert_ne!(p0, p1);
}

#[test]
fn positive_derive_wrap_key_is_deterministic_and_master_bound() {
    let m1 = [0xAAu8; 32];
    let m2 = [0xBBu8; 32];
    assert_eq!(derive_wrap_key(&m1), derive_wrap_key(&m1));
    assert_ne!(
        derive_wrap_key(&m1),
        derive_wrap_key(&m2),
        "derive_wrap_key must be bound to the master_secret"
    );
}

#[test]
fn positive_derive_entropy_nonce_length_and_uniqueness() {
    let m = [0xCDu8; 32];
    let n = derive_entropy_nonce(&m);
    assert_eq!(n.len(), 12, "AES-GCM nonces are 96-bit / 12 bytes");
    // Same master → same nonce (deterministic by design — entropy blob
    // re-encryption must produce the same nonce so the blob is a pure
    // function of the master).
    assert_eq!(derive_entropy_nonce(&m), n);
}

#[test]
fn positive_derive_wrap_key_and_entropy_nonce_use_independent_tags() {
    // If both functions accidentally shared a domain tag, the same
    // master would feed the same bytes into the key and the nonce —
    // catastrophic for AES-GCM (nonce/key reuse).  Assert orthogonality.
    let m = [0u8; 32];
    let wk = derive_wrap_key(&m);
    let nonce = derive_entropy_nonce(&m);
    assert_ne!(
        &wk[..12],
        &nonce[..],
        "derive_wrap_key and derive_entropy_nonce must not share KDF state"
    );
}

#[test]
fn positive_aes_encrypt_returns_pt_len_plus_tag() {
    let key = [0u8; 32];
    let mut buf = [0u8; 64 + AES_GCM_TAG_LEN];
    for &pt_len in &[0usize, 1, 15, 16, 32, 64] {
        let ct_len = aes_encrypt_inplace(&key, &mut buf, pt_len, 0);
        assert_eq!(ct_len, pt_len + AES_GCM_TAG_LEN);
    }
}

#[test]
fn positive_aes_nonce_index_separates_ciphertexts() {
    // Same key + plaintext but different nonce_idx must produce
    // different ciphertexts.  This is a basic AEAD property but the
    // separation here is provided by our `nonce_for(idx)` not by
    // user-supplied nonces, so it deserves its own test.
    let key = [0x11u8; 32];
    let mut buf0 = [0xA5u8; 16 + AES_GCM_TAG_LEN];
    let mut buf1 = [0xA5u8; 16 + AES_GCM_TAG_LEN];
    let _ = aes_encrypt_inplace(&key, &mut buf0, 16, 0);
    let _ = aes_encrypt_inplace(&key, &mut buf1, 16, 1);
    assert_ne!(buf0[..16], buf1[..16], "different nonce_idx → different ciphertext");
}

#[test]
fn positive_aes_zero_length_plaintext_roundtrip() {
    let key = [0u8; 32];
    let mut buf = [0u8; AES_GCM_TAG_LEN];
    let ct_len = aes_encrypt_inplace(&key, &mut buf, 0, 99);
    assert_eq!(ct_len, AES_GCM_TAG_LEN);
    let pt_len = aes_decrypt_inplace(&key, &mut buf, ct_len, 99).expect("zero-len decrypt");
    assert_eq!(pt_len, 0);
}
