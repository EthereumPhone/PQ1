//! AES-256-GCM tampering negatives.  AEAD decryption must refuse any
//! ciphertext, tag, or nonce mutation.  These are the integrity
//! guarantees the entropy-blob storage path relies on; if any one of
//! them silently passed, an attacker who flips a bit in the SE r-mem
//! could either decrypt to attacker-chosen entropy or read out the
//! master via differential analysis on the tag.

use pqsigner_domain::{aes_decrypt_inplace, aes_encrypt_inplace, AES_GCM_TAG_LEN};

const KEY: [u8; 32] = [0x42u8; 32];
const PT_LEN: usize = 32;
const CT_LEN: usize = PT_LEN + AES_GCM_TAG_LEN;

fn encrypted_buf() -> [u8; CT_LEN] {
    let mut buf = [0u8; CT_LEN];
    for (i, b) in buf[..PT_LEN].iter_mut().enumerate() {
        *b = i as u8 ^ 0x55;
    }
    let n = aes_encrypt_inplace(&KEY, &mut buf, PT_LEN, 0);
    assert_eq!(n, CT_LEN);
    buf
}

#[test]
fn negative_aes_rejects_every_single_byte_flip_in_ciphertext() {
    // Cycle through every byte position of the ciphertext (not the tag)
    // and assert the AEAD rejects each flipped variant.
    for pos in 0..PT_LEN {
        let mut buf = encrypted_buf();
        buf[pos] ^= 0x01;
        assert!(
            aes_decrypt_inplace(&KEY, &mut buf, CT_LEN, 0).is_err(),
            "AEAD must reject ct byte flip at {pos}"
        );
    }
}

#[test]
fn negative_aes_rejects_every_single_byte_flip_in_tag() {
    for pos in PT_LEN..CT_LEN {
        let mut buf = encrypted_buf();
        buf[pos] ^= 0x80;
        assert!(
            aes_decrypt_inplace(&KEY, &mut buf, CT_LEN, 0).is_err(),
            "AEAD must reject tag byte flip at {pos}"
        );
    }
}

#[test]
fn negative_aes_rejects_zero_byte_ct_len_below_tag() {
    // ct_len < AES_GCM_TAG_LEN must return Err without panicking on
    // arithmetic underflow.
    let mut buf = [0u8; AES_GCM_TAG_LEN];
    for len in 0..AES_GCM_TAG_LEN {
        assert!(
            aes_decrypt_inplace(&KEY, &mut buf, len, 0).is_err(),
            "ct_len={len} (< tag) must be rejected"
        );
    }
}

#[test]
fn negative_aes_rejects_wrong_nonce_index_for_every_neighbour() {
    // Encrypt under one nonce_idx, attempt decryption under every other
    // u8 — none must succeed.
    let mut buf = [0u8; CT_LEN];
    let _ = aes_encrypt_inplace(&KEY, &mut buf, PT_LEN, 7);
    let original = buf;
    // Sample a handful of wrong indices including 0, 6, 8 and 0xFF.
    for &wrong in &[0u8, 1, 6, 8, 100, 255] {
        let mut b = original;
        assert!(
            aes_decrypt_inplace(&KEY, &mut b, CT_LEN, wrong).is_err(),
            "AEAD must reject nonce_idx mismatch (right=7, wrong={wrong})"
        );
    }
}

#[test]
fn negative_aes_swapping_two_ct_bytes_is_rejected() {
    // Two bit-flips in different positions must still fail (no
    // homomorphism that XORs to zero in the tag).
    let mut buf = encrypted_buf();
    buf.swap(0, 1);
    assert!(aes_decrypt_inplace(&KEY, &mut buf, CT_LEN, 0).is_err());
}
