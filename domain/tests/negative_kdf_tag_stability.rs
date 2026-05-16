//! **KDF tag stability** — the single highest-value safety net in this
//! crate.  CLAUDE.md "No casual KDF tag changes" lists every domain tag
//! the recovery contract depends on.  Renaming any one would silently
//! make every wallet already in the field unrecoverable: the same 24
//! words would produce a different SPHINCS+C10 keypair and therefore a
//! different on-chain wallet address.
//!
//! Each test below holds the production helper to a literal byte
//! sequence reproduced inline in the test.  A future refactor that
//! renames `b"sphincs-wrap-key"` to `b"sphincs_wrap_key"` (or any other
//! "harmless" cosmetic change) will fail the test with a message that
//! cites the assumption being violated.
//!
//! The HMAC-SHA512 step inside `derive_c10_master_*` is policed by
//! `c10_derivation_tests::derive_c10_master_from_bip39_seed_matches_reference`
//! already (frozen REF_PK_SEED / REF_SK_SEED for the 24-zero-byte
//! seed).  Here we add the same protection for the per-account branch.

use hmac::{Hmac, Mac};
use pqsigner_domain::{
    bootstrap_seed_from_bip39, derive_c10_master_from_bip39_seed, derive_entropy_nonce,
    derive_wrap_key, kdf, kdf_sha256, macd_init_input, macd_pin_input, slhdsa_seed_from_bip39,
    slot_entropy, slot_master_entropy_from_bip39,
};
use sha2::{Digest, Sha256, Sha512};

const FAIL_HINT: &str =
    "KDF/HMAC domain tag drifted — see CLAUDE.md 'No casual KDF tag changes': \
     same 24 words would now produce a different on-chain wallet address.";

#[test]
fn negative_kdf_uses_sha256_with_canonical_concatenation_order() {
    // kdf(domain, input, index) == sha256(domain || input || [index]).
    // If anyone reorders, length-prefixes, or domain-tags this anew,
    // every derivation in the crate silently breaks.
    let dom = b"some-domain";
    let inp = b"some-input";
    let idx = 0xA7u8;
    let mut h = Sha256::new();
    h.update(dom);
    h.update(inp);
    h.update([idx]);
    let expected: [u8; 32] = h.finalize().into();
    assert_eq!(kdf(dom, inp, idx), expected, "{FAIL_HINT}");
    assert_eq!(kdf_sha256(dom, inp, idx), expected, "{FAIL_HINT}");
}

#[test]
fn negative_derive_wrap_key_tag_is_literal_sphincs_wrap_key() {
    let m = [0x5Au8; 32];
    assert_eq!(
        derive_wrap_key(&m),
        kdf(b"sphincs-wrap-key", &m, 0),
        "{FAIL_HINT} (tag: sphincs-wrap-key)"
    );
}

#[test]
fn negative_derive_entropy_nonce_tag_is_literal_sphincs_entropy_nonce() {
    // Implementation: truncate_to_nonce(kdf(b"sphincs-entropy-nonce", m, 0)).
    let m = [0x77u8; 32];
    let full = kdf(b"sphincs-entropy-nonce", &m, 0);
    let mut expected = [0u8; 12];
    expected.copy_from_slice(&full[..12]);
    assert_eq!(derive_entropy_nonce(&m), expected, "{FAIL_HINT} (tag: sphincs-entropy-nonce)");
}

#[test]
fn negative_macd_init_input_tag_is_literal_sphincs_macd_init() {
    let m = [0x11u8; 32];
    for j in [0u8, 1, 9, 0xFE] {
        assert_eq!(
            macd_init_input(&m, j),
            kdf(b"sphincs-macd-init", &m, j),
            "{FAIL_HINT} (tag: sphincs-macd-init, j={j})"
        );
    }
}

#[test]
fn negative_macd_pin_input_tag_is_literal_sphincs_macd_pin() {
    let pin = [0xAAu8; 8];
    for j in [0u8, 1, 7, 0xFF] {
        assert_eq!(
            macd_pin_input(&pin, j),
            kdf(b"sphincs-macd-pin", &pin, j),
            "{FAIL_HINT} (tag: sphincs-macd-pin, j={j})"
        );
    }
}

#[test]
fn negative_slhdsa_seed_tags_are_literal_sphincsc7_sk_and_pk() {
    // Slh-DSA seed: full 32 B of sha256("sphincsc7-sk-seed" || s) ||
    // first 16 B of sha256("sphincsc7-pk-seed" || s).
    let bip39 = [0x42u8; 64];
    let actual = slhdsa_seed_from_bip39(&bip39);

    let chunk_sk: [u8; 32] = kdf(b"sphincsc7-sk-seed", &bip39, 0);
    let chunk_pk: [u8; 32] = kdf(b"sphincsc7-pk-seed", &bip39, 0);
    let mut expected = [0u8; 48];
    expected[..32].copy_from_slice(&chunk_sk);
    expected[32..].copy_from_slice(&chunk_pk[..16]);

    assert_eq!(actual, expected, "{FAIL_HINT} (tags: sphincsc7-sk-seed, sphincsc7-pk-seed)");
}

#[test]
fn negative_bootstrap_seed_tags_are_literal_pqwallet_c7_bootstrap() {
    let bip39 = [0x42u8; 64];
    let actual = bootstrap_seed_from_bip39(&bip39);

    let chunk_sk: [u8; 32] = kdf(b"pqwallet-c7-bootstrap-sk-seed", &bip39, 0);
    let chunk_pk: [u8; 32] = kdf(b"pqwallet-c7-bootstrap-pk-seed", &bip39, 0);
    let mut expected = [0u8; 48];
    expected[..32].copy_from_slice(&chunk_sk);
    expected[32..].copy_from_slice(&chunk_pk[..16]);
    assert_eq!(actual, expected, "{FAIL_HINT} (tags: pqwallet-c7-bootstrap-*)");
}

#[test]
fn negative_slot_master_account_0_tag_is_literal_pqwallet_slot_master() {
    let bip39 = [0x88u8; 64];
    assert_eq!(
        slot_master_entropy_from_bip39(&bip39, 0),
        kdf_sha256(b"pqwallet-slot-master", &bip39, 0),
        "{FAIL_HINT} (tag: pqwallet-slot-master, account 0)"
    );
}

#[test]
fn negative_slot_master_account_nonzero_tag_is_literal_pqwallet_slot_master_acct() {
    let bip39 = [0x88u8; 64];
    let account: u32 = 7;
    // Production implementation: sha256("pqwallet-slot-master-acct" || bip39_seed || account_be4).
    let mut h = Sha256::new();
    h.update(b"pqwallet-slot-master-acct");
    h.update(bip39);
    h.update(account.to_be_bytes());
    let expected: [u8; 32] = h.finalize().into();
    assert_eq!(
        slot_master_entropy_from_bip39(&bip39, account),
        expected,
        "{FAIL_HINT} (tag: pqwallet-slot-master-acct)"
    );
}

#[test]
fn negative_slot_entropy_uses_literal_slot_entropy_tag() {
    let master = [0x33u8; 32];
    let chain_id: u64 = 1;
    let slot_index: u32 = 5;
    let mut h = Sha256::new();
    h.update(master);
    h.update(b"slot_entropy");
    h.update(chain_id.to_be_bytes());
    h.update(slot_index.to_be_bytes());
    let expected: [u8; 32] = h.finalize().into();
    assert_eq!(
        slot_entropy(&master, chain_id, slot_index),
        expected,
        "{FAIL_HINT} (tag: slot_entropy)"
    );
}

#[test]
fn negative_slot_entropy_byte_order_for_chain_and_slot_is_be() {
    // Endianness drift would change per-chain key identity invisibly.
    // Force a value with distinguishable BE/LE shapes.
    let master = [0u8; 32];
    let chain_id: u64 = 0x0102_0304_0506_0708;
    let slot_index: u32 = 0x0A0B_0C0D;
    let mut h = Sha256::new();
    h.update(master);
    h.update(b"slot_entropy");
    h.update([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]); // BE
    h.update([0x0A, 0x0B, 0x0C, 0x0D]); // BE
    let expected: [u8; 32] = h.finalize().into();
    assert_eq!(
        slot_entropy(&master, chain_id, slot_index),
        expected,
        "slot_entropy must encode chain_id and slot_index as big-endian"
    );
}

#[test]
fn negative_c10_master_hmac_domain_account_0_is_literal_sphincs_c6_v1() {
    let bip39_seed = [0xC4u8; 64];

    // Reproduce the production HMAC-SHA512(domain, bip39_seed) → master.
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(b"sphincs-c6-v1").unwrap();
    mac.update(&bip39_seed);
    let master = mac.finalize().into_bytes();
    let lo = &master[..32];

    let pk_digest: [u8; 32] = Sha256::new()
        .chain_update(b"pk_seed")
        .chain_update(lo)
        .finalize()
        .into();
    let mut expected_pk = [0u8; 32];
    expected_pk[..16].copy_from_slice(&pk_digest[..16]);

    let expected_sk: [u8; 32] = Sha256::new()
        .chain_update(b"sk_seed")
        .chain_update(lo)
        .finalize()
        .into();

    let (pk, sk) = derive_c10_master_from_bip39_seed(&bip39_seed, 0);
    assert_eq!(pk, expected_pk, "{FAIL_HINT} (HMAC tag: sphincs-c6-v1)");
    assert_eq!(sk, expected_sk, "{FAIL_HINT} (sha256 tag: sk_seed)");
}

#[test]
fn negative_c10_master_hmac_domain_account_nonzero_is_literal_sphincs_c6_v1_acct() {
    let bip39_seed = [0xD7u8; 64];
    let account: u32 = 42;

    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(b"sphincs-c6-v1-acct").unwrap();
    mac.update(&bip39_seed);
    mac.update(&account.to_be_bytes());
    let master = mac.finalize().into_bytes();
    let lo = &master[..32];

    let pk_digest: [u8; 32] = Sha256::new()
        .chain_update(b"pk_seed")
        .chain_update(lo)
        .finalize()
        .into();
    let mut expected_pk = [0u8; 32];
    expected_pk[..16].copy_from_slice(&pk_digest[..16]);
    let expected_sk: [u8; 32] = Sha256::new()
        .chain_update(b"sk_seed")
        .chain_update(lo)
        .finalize()
        .into();

    let (pk, sk) = derive_c10_master_from_bip39_seed(&bip39_seed, account);
    assert_eq!(pk, expected_pk, "{FAIL_HINT} (HMAC tag: sphincs-c6-v1-acct)");
    assert_eq!(sk, expected_sk, "{FAIL_HINT} (sha256 tag: sk_seed under -acct)");
}

#[test]
fn negative_c10_master_account_index_is_be_encoded() {
    // If the account_index were ever encoded as little-endian, every
    // account>0 wallet would silently move on-chain.
    let bip39_seed = [0u8; 64];
    let account: u32 = 0x0102_0304;
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(b"sphincs-c6-v1-acct").unwrap();
    mac.update(&bip39_seed);
    mac.update(&[0x01, 0x02, 0x03, 0x04]); // BE
    let master = mac.finalize().into_bytes();
    let lo = &master[..32];
    let expected_sk: [u8; 32] = Sha256::new()
        .chain_update(b"sk_seed")
        .chain_update(lo)
        .finalize()
        .into();
    let (_pk, sk) = derive_c10_master_from_bip39_seed(&bip39_seed, account);
    assert_eq!(sk, expected_sk, "account_index must be encoded big-endian");
}
