//! Cross-derivation independence negatives.  The crate exposes four
//! independent SPHINCS-derivation chains:
//!
//!   * slhdsa  (legacy single-key bridge — `slhdsa_seed_from_bip39`)
//!   * bootstrap (`bootstrap_seed_from_bip39`)
//!   * c10 master (`derive_c10_master_*`)
//!   * c10 slot   (`derive_c10_slot_*`)
//!
//! and the slot master entropy used to seed (4).  If any two of these
//! produced the same key for the same user seed, the role-split
//! security model would collapse: e.g. an attacker who learned a slot
//! key on chain A could impersonate the user on chain B, or a Type 2
//! user-tx signer could be coerced into producing a Type 1 slot
//! registration.  Each test below names the role pair being tested
//! and asserts the two derivations diverge.

use pqsigner_domain::{
    bootstrap_seed_from_bip39, derive_c10_master_from_entropy, derive_c10_slot_keypair,
    slhdsa_seed_from_bip39, slot_entropy, slot_master_entropy_from_entropy,
};
use sphincs_tz_bip39::Mnemonic;

const SEED: [u8; 32] = [0x99u8; 32];

#[test]
fn negative_slhdsa_seed_must_differ_from_bootstrap_seed() {
    let m = Mnemonic::from_entropy(&SEED);
    let bip = m.to_seed("");
    assert_ne!(
        slhdsa_seed_from_bip39(&bip),
        bootstrap_seed_from_bip39(&bip),
        "slhdsa and bootstrap derivations must use independent domain tags"
    );
}

#[test]
fn negative_c10_master_must_differ_per_account_index() {
    // CLAUDE.md "One seed → 256 wallets via account_index ∈ [0, 255]".
    // If two account_index values ever collided, two separate wallets
    // on the same seed would share an on-chain identity.
    let mut prev: Option<([u8; 32], [u8; 32])> = None;
    // Sample, not exhaustive (each call runs HMAC-SHA512 once → cheap).
    for idx in [0u32, 1, 2, 17, 200, 255] {
        let (pk, sk) = derive_c10_master_from_entropy(&SEED, idx);
        if let Some(prev) = prev {
            assert_ne!(prev, (pk, sk), "account_index collision detected near {idx}");
        }
        prev = Some((pk, sk));
    }
}

#[test]
fn negative_slot_keys_must_differ_across_chains() {
    // Cross-chain slot independence is the cryptographic underpinning
    // of the role-split design.  An attacker who exfiltrates a slot
    // key on chain A must not gain anything on chain B.
    let master = slot_master_entropy_from_entropy(&SEED, 0);
    let (_, ps_a, pr_a) = derive_c10_slot_keypair(&master, 1, 0);
    let (_, ps_b, pr_b) = derive_c10_slot_keypair(&master, 137, 0);
    assert_ne!(ps_a, ps_b, "slot pk_seed must vary by chain_id");
    assert_ne!(pr_a, pr_b, "slot pk_root must vary by chain_id");
}

#[test]
fn negative_slot_keys_must_differ_across_slot_indices() {
    let master = slot_master_entropy_from_entropy(&SEED, 0);
    let (_, ps_0, pr_0) = derive_c10_slot_keypair(&master, 1, 0);
    let (_, ps_1, pr_1) = derive_c10_slot_keypair(&master, 1, 1);
    assert_ne!(ps_0, ps_1, "slot pk_seed must vary by slot_index");
    assert_ne!(pr_0, pr_1, "slot pk_root must vary by slot_index");
}

#[test]
fn negative_slot_keys_must_differ_across_account_indices() {
    let m_a = slot_master_entropy_from_entropy(&SEED, 0);
    let m_b = slot_master_entropy_from_entropy(&SEED, 1);
    let (_, ps_a, pr_a) = derive_c10_slot_keypair(&m_a, 1, 0);
    let (_, ps_b, pr_b) = derive_c10_slot_keypair(&m_b, 1, 0);
    assert_ne!(ps_a, ps_b, "slot pk_seed must vary by account_index");
    assert_ne!(pr_a, pr_b, "slot pk_root must vary by account_index");
}

#[test]
fn negative_slot_entropy_is_not_master_entropy() {
    // A direct collapse to master would let an attacker who reads slot
    // entropy reconstruct everything else derived from the master.
    let master = [0xA1u8; 32];
    let s = slot_entropy(&master, 1, 0);
    assert_ne!(s, master, "slot_entropy must not be the raw master entropy");
}
