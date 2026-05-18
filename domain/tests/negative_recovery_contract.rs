//! Recovery-contract reference vectors for the secondary derivation
//! chains (slhdsa, bootstrap, slot master) and the per-account branch
//! of the c10 master.  The existing `c10_derivation_tests` module
//! covers the account-0 c10 master path; the helpers below extend that
//! coverage to every public derivation function so a future refactor
//! that quietly shifts a domain tag in any of them fails loudly.
//!
//! All vectors are computed via the SAME independent inline
//! implementation that `negative_kdf_tag_stability.rs` uses: a
//! parallel reconstruction of the production formula using literal
//! byte tags.  A failure here means either a tag was renamed or the
//! concatenation order / byte layout was reshuffled.

use hmac::{Hmac, Mac};
use pqsigner_domain::{
    bootstrap_seed_from_bip39, derive_c10_master_from_bip39_seed, slhdsa_seed_from_bip39,
    slot_entropy, slot_master_entropy_from_bip39, SEED_LEN,
};
use sha2::{Digest, Sha256, Sha512};
use sphincs_tz_bip39::Mnemonic;

const FAIL_HINT: &str =
    "Recovery contract drifted: same 24 words would now produce a different on-chain identity. \
     See CLAUDE.md 'No casual KDF tag changes'.";

fn known_bip39_seed() -> [u8; 64] {
    // Same fixture the in-crate `c10_derivation_tests` use.
    Mnemonic::from_entropy(&[0u8; 32]).to_seed("")
}

fn ref_two_sha256_chunks(tag_sk: &[u8], tag_pk: &[u8], input: &[u8]) -> [u8; SEED_LEN] {
    let chunk0: [u8; 32] =
        Sha256::new().chain_update(tag_sk).chain_update(input).chain_update([0u8]).finalize().into();
    let chunk1: [u8; 32] =
        Sha256::new().chain_update(tag_pk).chain_update(input).chain_update([0u8]).finalize().into();
    let mut out = [0u8; SEED_LEN];
    out[..32].copy_from_slice(&chunk0);
    out[32..].copy_from_slice(&chunk1[..16]);
    out
}

#[test]
fn negative_slhdsa_seed_recovery_vector() {
    let seed = known_bip39_seed();
    let expected = ref_two_sha256_chunks(b"sphincsc7-sk-seed", b"sphincsc7-pk-seed", &seed);
    let actual = slhdsa_seed_from_bip39(&seed);
    assert_eq!(actual, expected, "{FAIL_HINT}");
}

#[test]
fn negative_bootstrap_seed_recovery_vector() {
    let seed = known_bip39_seed();
    let expected = ref_two_sha256_chunks(
        b"pqwallet-c7-bootstrap-sk-seed",
        b"pqwallet-c7-bootstrap-pk-seed",
        &seed,
    );
    let actual = bootstrap_seed_from_bip39(&seed);
    assert_eq!(actual, expected, "{FAIL_HINT}");
}

#[test]
fn negative_slot_master_account0_recovery_vector() {
    let seed = known_bip39_seed();
    // sha256("pqwallet-slot-master" || seed || [0u8]).
    let expected: [u8; 32] = Sha256::new()
        .chain_update(b"pqwallet-slot-master")
        .chain_update(seed)
        .chain_update([0u8])
        .finalize()
        .into();
    assert_eq!(slot_master_entropy_from_bip39(&seed, 0), expected, "{FAIL_HINT}");
}

#[test]
fn negative_slot_master_account_nonzero_recovery_vector() {
    let seed = known_bip39_seed();
    // sha256("pqwallet-slot-master-acct" || seed || acct_be4).
    for &acct in &[1u32, 2, 0xFF, 0x0102_0304] {
        let expected: [u8; 32] = Sha256::new()
            .chain_update(b"pqwallet-slot-master-acct")
            .chain_update(seed)
            .chain_update(acct.to_be_bytes())
            .finalize()
            .into();
        assert_eq!(
            slot_master_entropy_from_bip39(&seed, acct),
            expected,
            "{FAIL_HINT} (account_index={acct})"
        );
    }
}

#[test]
fn negative_slot_entropy_recovery_vector() {
    let master = [0xA1u8; 32];
    let chain_id: u64 = 137;
    let slot_index: u32 = 1;
    let expected: [u8; 32] = Sha256::new()
        .chain_update(master)
        .chain_update(b"slot_entropy")
        .chain_update(chain_id.to_be_bytes())
        .chain_update(slot_index.to_be_bytes())
        .finalize()
        .into();
    assert_eq!(slot_entropy(&master, chain_id, slot_index), expected, "{FAIL_HINT}");
}

#[test]
fn negative_c10_master_account_nonzero_recovery_vector() {
    // The existing in-crate test covers account 0. Here we cover the
    // per-account branch end-to-end against an independent reference.
    let seed = known_bip39_seed();
    let account: u32 = 1;

    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(b"sphincs-c6-v1-acct").unwrap();
    mac.update(&seed);
    mac.update(&account.to_be_bytes());
    let master = mac.finalize().into_bytes();
    let lo = &master[..32];

    let pk_digest: [u8; 32] =
        Sha256::new().chain_update(b"pk_seed").chain_update(lo).finalize().into();
    let mut expected_pk = [0u8; 32];
    expected_pk[..16].copy_from_slice(&pk_digest[..16]);
    let expected_sk: [u8; 32] =
        Sha256::new().chain_update(b"sk_seed").chain_update(lo).finalize().into();

    let (pk, sk) = derive_c10_master_from_bip39_seed(&seed, account);
    assert_eq!(pk, expected_pk, "{FAIL_HINT}");
    assert_eq!(sk, expected_sk, "{FAIL_HINT}");
}
