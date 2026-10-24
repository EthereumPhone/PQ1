//! One BIP-39 stretch where a signing request needed two.
//!
//! The slot master and the bootstrap key's seeds both descend from the BIP-39
//! seed, a PBKDF2 of 2,048 HMAC-SHA512 rounds (92 M cycles, 0.57 s, measured
//! on the U585). After the confirmation, a deploy or a rotation needs both,
//! and each used to run its own stretch over the same entropy.
//! [`slot_master_and_bootstrap`] runs it once for both. (A cold sender-binding
//! or address derivation before the confirmation still runs its own.)
//!
//! Composed from the public `pqsigner_domain` derivations rather than added
//! there, because `domain/src/lib.rs` is Lean-extracted. The outputs are
//! byte-identical to `slot_master_entropy_from_entropy`,
//! `derive_c10_master_from_entropy` and
//! `derive_c10_master_keypair_from_entropy_with_progress`; the tests below pin
//! that for account 0 and for a non-zero account (the two KDF tag branches).
//!
//! The slot master's stretch also computes [`slot_master_check`], which binds
//! the master's bytes to its account for the session copy `state` keeps.
//!
//! Pure logic: the host scaffold `nsc_core_under_test` re-includes this file.

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Domain tag of [`slot_master_check`].
const SLOT_MASTER_CHECK_TAG: &[u8] = b"pqsigner-slot-master-check-v1";

/// `sha256(tag || account_index_be4 || entropy || master)`: what the
/// session's kept slot master must still hash to, with the requesting account
/// and the request's own entropy, before a request reuses it. The tag and the
/// flag alone say nothing about the 32 bytes behind them: one skipped copy
/// into the session state would leave zeros there (a publicly known master, so
/// an attacker-computable slot key) under a valid tag. Computed where the
/// master is derived, from the same account value, so an account corrupted
/// between the derivation and the tag's publication cannot label one account's
/// master as another's either. The entropy makes a master derived for another
/// wallet (the duress decoy and the real wallet both have an account 0)
/// unusable whatever a future unlock path forgets to wipe.
pub(super) fn slot_master_check(account_index: u32, entropy: &[u8; 32], master: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(SLOT_MASTER_CHECK_TAG);
    h.update(account_index.to_be_bytes());
    h.update(entropy);
    h.update(master);
    h.finalize().into()
}

/// The bootstrap key's two seeds, kept from their derivation to the keygen
/// that consumes them later in the same request. Both wipe on drop.
pub(super) struct BootstrapSeeds {
    pk_seed_32: Zeroizing<[u8; 32]>,
    sk_seed_32: Zeroizing<[u8; 32]>,
}

/// The slot master for `account_index`, its [`slot_master_check`], and, when
/// `with_bootstrap`, the bootstrap seeds, from one BIP-39 stretch of
/// `entropy`. The BIP-39 seed is wiped before this returns.
pub(super) fn slot_master_and_bootstrap(
    entropy: &[u8; 32],
    account_index: u32,
    with_bootstrap: bool,
) -> (Zeroizing<[u8; 32]>, [u8; 32], Option<BootstrapSeeds>) {
    // `Mnemonic`'s drop zeroes its 24 word indices.
    let mnemonic = sphincs_tz_bip39::Mnemonic::from_entropy(entropy);
    let bip39_seed = Zeroizing::new(mnemonic.to_seed(""));
    let slot_master = Zeroizing::new(pqsigner_domain::slot_master_entropy_from_bip39(
        &bip39_seed,
        account_index,
    ));
    let check = slot_master_check(account_index, entropy, &slot_master);
    let bootstrap = if with_bootstrap {
        let (pk_seed_32, sk_seed_32) =
            pqsigner_domain::derive_c10_master_from_bip39_seed(&bip39_seed, account_index);
        Some(BootstrapSeeds {
            pk_seed_32: Zeroizing::new(pk_seed_32),
            sk_seed_32: Zeroizing::new(sk_seed_32),
        })
    } else {
        None
    };
    (slot_master, check, bootstrap)
}

/// The bootstrap keypair from seeds [`slot_master_and_bootstrap`] produced:
/// `(signing_key, master_pk_seed_32, master_pk_root_32)`, as
/// `derive_c10_master_keypair_from_entropy_with_progress` returns, without its
/// BIP-39 stretch. Reports keygen progress 0..=100. `seeds` is consumed and
/// wiped here.
pub(super) fn bootstrap_keypair(
    seeds: BootstrapSeeds,
    progress: fn(u8),
) -> (sphincs_c10::SigningKey, [u8; 32], [u8; 32]) {
    progress(0);
    let mut pk_seed_16 = [0u8; 16];
    pk_seed_16.copy_from_slice(&seeds.pk_seed_32[..16]);
    let sk = sphincs_c10::SigningKey::keygen_with_progress(*seeds.sk_seed_32, pk_seed_16, progress, 0, 100);
    let mut pk_root_32 = [0u8; 32];
    pk_root_32[..16].copy_from_slice(sk.pk_root());
    let pk_seed_32 = *seeds.pk_seed_32;
    drop(seeds);
    progress(100);
    (sk, pk_seed_32, pk_root_32)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Account 0 takes the legacy KDF tags, every other account the `-acct`
    // ones, so both branches are compared.
    const CASES: [([u8; 32], u32); 3] = [([0x11; 32], 0), ([0x5A; 32], 1), ([0xC3; 32], 255)];

    #[test]
    fn slot_master_matches_the_two_stretch_derivation() {
        for (entropy, account) in CASES {
            for with_bootstrap in [false, true] {
                let (m, check, _) = slot_master_and_bootstrap(&entropy, account, with_bootstrap);
                assert_eq!(check, slot_master_check(account, &entropy, &m), "the check is the derived master's");
                assert_eq!(
                    *m,
                    pqsigner_domain::slot_master_entropy_from_entropy(&entropy, account),
                    "slot master for account {account} must not depend on sharing the stretch"
                );
            }
        }
    }

    #[test]
    fn bootstrap_seeds_only_when_asked_and_match_the_domain_derivation() {
        for (entropy, account) in CASES {
            assert!(slot_master_and_bootstrap(&entropy, account, false).2.is_none());
            let seeds = slot_master_and_bootstrap(&entropy, account, true).2.expect("asked for seeds");
            let (pk, sk) = pqsigner_domain::derive_c10_master_from_entropy(&entropy, account);
            assert_eq!(*seeds.pk_seed_32, pk, "bootstrap pk_seed, account {account}");
            assert_eq!(*seeds.sk_seed_32, sk, "bootstrap sk_seed, account {account}");
        }
    }

    #[test]
    fn bootstrap_keypair_matches_the_domain_keypair() {
        // One keygen per branch: each builds a 512-leaf tree.
        for (entropy, account) in [CASES[0], CASES[1]] {
            let seeds = slot_master_and_bootstrap(&entropy, account, true).2.expect("asked for seeds");
            let (sk, pk_seed, pk_root) = bootstrap_keypair(seeds, |_| {});
            let (want_sk, want_seed, want_root) =
                pqsigner_domain::derive_c10_master_keypair_from_entropy(&entropy, account);
            assert_eq!(pk_seed, want_seed, "master pk_seed, account {account}");
            assert_eq!(pk_root, want_root, "master pk_root, account {account}");
            assert_eq!(sk.sk_seed(), want_sk.sk_seed(), "master sk_seed, account {account}");
            assert_eq!(sk.pk_seed(), want_sk.pk_seed(), "master key pk_seed, account {account}");
        }
    }

    #[test]
    fn slot_master_check_binds_the_bytes_the_account_and_the_wallet() {
        let (e, m) = ([0x11u8; 32], [0x5Au8; 32]);
        let c = slot_master_check(3, &e, &m);
        assert_eq!(c, slot_master_check(3, &e, &m), "deterministic");
        assert_ne!(c, slot_master_check(4, &e, &m), "another account");
        assert_ne!(c, slot_master_check(3, &[0x12u8; 32], &m), "another wallet's entropy");
        assert_ne!(c, slot_master_check(3, &e, &[0u8; 32]), "zeroed bytes");
        let mut flipped = m;
        flipped[31] ^= 1;
        assert_ne!(c, slot_master_check(3, &e, &flipped), "one flipped bit");
    }
}
