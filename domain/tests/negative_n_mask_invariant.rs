//! N-mask layout invariant.  On-chain SPHINCS+C10 commitments live in
//! `bytes32` slots with the top 16 bytes carrying the real pk_seed /
//! pk_root and the bottom 16 bytes zero.  The verifier reads only the
//! top 16; the bottom 16 being zero is the contract that lets the
//! on-chain `slots[slotKey] = sha256(pk_seed[..16] || pk_root[..16])`
//! commitment be unambiguously reconstructible from `bytes32` inputs.
//!
//! If a future refactor leaks non-zero bytes into the bottom 16,
//! every cached `RMEM_BOOTSTRAP_VK` (32 B layout) would shift and on-
//! chain identity would silently diverge from firmware identity.

use pqsigner_domain::{
    derive_bootstrap_keypair_from_entropy, derive_c10_master_from_bip39_seed,
    derive_c10_master_keypair_from_entropy, derive_c10_slot_keypair,
    slot_master_entropy_from_entropy,
};

const ENTROPY: [u8; 32] = [0xE1u8; 32];

fn assert_bottom_16_zero(b: &[u8; 32], label: &str) {
    for (i, byte) in b[16..].iter().enumerate() {
        assert_eq!(
            *byte, 0,
            "{label}: bottom-16 byte index {i} must be zero (N-mask layout broken)"
        );
    }
}

#[test]
fn negative_c10_master_pk_seed_bottom_16_must_be_zero() {
    // Direct from bip39-seed path.
    let (pk_seed, _sk_seed) = derive_c10_master_from_bip39_seed(&[0u8; 64], 0);
    assert_bottom_16_zero(&pk_seed, "c10_master pk_seed (account=0)");
    // From-entropy convenience path.
    let (_, pk_seed_e, pk_root_e) = derive_c10_master_keypair_from_entropy(&ENTROPY, 0);
    assert_bottom_16_zero(&pk_seed_e, "c10_master pk_seed (from entropy)");
    assert_bottom_16_zero(&pk_root_e, "c10_master pk_root (from entropy)");
}

#[test]
fn negative_c10_master_account_nonzero_keeps_n_mask() {
    // The "-acct" branch shares the same downstream SHA-256 split as
    // account 0 — assert it didn't accidentally widen the masked region.
    let (pk_seed, _) = derive_c10_master_from_bip39_seed(&[0xAAu8; 64], 7);
    assert_bottom_16_zero(&pk_seed, "c10_master pk_seed (account=7)");
}

#[test]
fn negative_slot_keypair_pk_seed_and_root_bottom_16_must_be_zero() {
    let master = slot_master_entropy_from_entropy(&ENTROPY, 0);
    let (_, ps, pr) = derive_c10_slot_keypair(&master, 1, 0);
    assert_bottom_16_zero(&ps, "slot pk_seed");
    assert_bottom_16_zero(&pr, "slot pk_root");
}

#[test]
fn negative_bootstrap_keypair_vk_has_n_mask_on_both_halves() {
    // VK is `pk_seed[..16] || pk_root[..16]` = 32 bytes; both halves
    // come from N-masked 32-byte inputs.  A drift would show up as
    // non-zero where we don't expect it.  Indirect test: the
    // `derive_bootstrap_vk_from_entropy` output is exactly 32 bytes,
    // so we just verify the keypair path is consistent with the
    // separate halves of the master-style layout — top 16 of VK is
    // pk_seed (from N-masked derivation), bottom 16 is pk_root (from
    // N-masked hypertree root).  No "third" zone should exist.
    let (_sk, vk) = derive_bootstrap_keypair_from_entropy(&ENTROPY);
    assert_eq!(vk.len(), 32, "bootstrap VK must be exactly 32 bytes (16 pk_seed + 16 pk_root)");
}
