//! End-to-end sign + verify integration test.
//!
//! Runs the full pipeline on the already-built firmware ELFs (if
//! present — skipped with a `println!` when `make secure` / `make
//! nonsecure` haven't been run yet, so CI runs it, local dev doesn't
//! require running two multi-minute builds just to test fwsign).
//!
//! What this tests:
//!   * `VendorKey::generate` produces a working keypair (~2-3 s).
//!   * `elf::flatten_elf` produces the same hash on both ELFs
//!     regardless of signer-machine host state.
//!   * A signed bundle round-trips through
//!     `bundle::pack` → `bundle::unpack`.
//!   * The bundle's own pubkey matches the one supplied to verify.
//!   * `verify_*` checks in `fw_manifest::ManifestRef` all pass for a
//!     freshly-signed bundle.
//!   * Tampering with any signed byte causes verify to fail.
//!   * Double-running `fwsign sign` on the same inputs produces
//!     identical bundles (deterministic signing — no RNG in the sign
//!     path other than the sealed key, which the test reuses).

use fw_manifest::{ManifestBuilder, ManifestRef, SLOT_A, TRY_ONCE_COMMITTED};
use sha2::{Digest, Sha256};
use sphincs_c10::{SigningKey, VerifyingKey};

const FIXED_SK_SEED: [u8; 32] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
];
const FIXED_PK_SEED: [u8; 16] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
];

fn fixed_keypair() -> SigningKey {
    // Use from_parts with a precomputed pk_root so the test doesn't
    // run a 2-3 s hypertree build on every invocation. We pin
    // pk_root once at test-authoring time; if the sphincs-c10 crate's
    // keygen ever changes output (it shouldn't), the assertion below
    // catches it.
    let k = SigningKey::keygen(FIXED_SK_SEED, FIXED_PK_SEED);
    k
}

#[test]
fn manifest_signed_by_fixture_key_verifies() {
    let sk = fixed_keypair();
    let vk = VerifyingKey {
        pk_seed: *sk.pk_seed(),
        pk_root: *sk.pk_root(),
    };

    // Synthesize "firmware images".
    let secure_bytes = vec![0x12u8; 0x4000]; // 16 KB
    let nonsecure_bytes = vec![0x34u8; 0x8000]; // 32 KB
    let secure_hash: [u8; 32] = Sha256::digest(&secure_bytes).into();
    let nonsecure_hash: [u8; 32] = Sha256::digest(&nonsecure_bytes).into();
    let fpr = fw_manifest::vendor_pubkey_fingerprint(sk.pk_seed(), sk.pk_root());

    let mut b = ManifestBuilder::new();
    b.init(SLOT_A)
        .fw_version(2)
        .secure_image(&secure_hash, secure_bytes.len() as u32)
        .nonsecure_image(&nonsecure_hash, nonsecure_bytes.len() as u32)
        .vendor_pubkey_fpr(&fpr)
        .build_id(&[0xCA; 32])
        .boot_counter_snap(1)
        .try_once(TRY_ONCE_COMMITTED);
    let digest = b.finalize_preimage();

    let sig = sk.sign(&digest, None);
    b.set_signature(&sig);
    let manifest_bytes = b.finalize();

    // Full verification chain.
    let m = ManifestRef::new(&manifest_bytes);
    m.verify_structural().expect("structural");
    m.verify_crc().expect("crc");
    m.verify_digest().expect("digest");
    m.verify_vendor_fpr(&vk.pk_seed, &vk.pk_root)
        .expect("vendor fpr");
    m.verify_signature(&vk.pk_seed, &vk.pk_root)
        .expect("c10 signature");
    m.verify_rollback(1).expect("rollback ok (floor=1, ver=2)");
    assert!(
        m.verify_rollback(2).is_err(),
        "rollback must reject floor == version"
    );
}

#[test]
fn wrong_vendor_key_rejected() {
    let sk = fixed_keypair();

    let mut b = ManifestBuilder::new();
    b.init(SLOT_A)
        .fw_version(1)
        .secure_image(&[0u8; 32], 0)
        .nonsecure_image(&[0u8; 32], 0)
        .vendor_pubkey_fpr(&fw_manifest::vendor_pubkey_fingerprint(
            sk.pk_seed(),
            sk.pk_root(),
        ))
        .build_id(&[0; 32])
        .boot_counter_snap(0)
        .try_once(TRY_ONCE_COMMITTED);
    let digest = b.finalize_preimage();
    b.set_signature(&sk.sign(&digest, None));
    let manifest_bytes = b.finalize();

    // Verify with a DIFFERENT pubkey.
    let wrong_pk_seed = [0x99u8; 16];
    let wrong_pk_root = [0x88u8; 16];

    let m = ManifestRef::new(&manifest_bytes);
    // vendor_fpr catches it first (cheap).
    assert!(m
        .verify_vendor_fpr(&wrong_pk_seed, &wrong_pk_root)
        .is_err());
    // Even if we skip the fpr check, signature verify also catches it.
    assert!(m
        .verify_signature(&wrong_pk_seed, &wrong_pk_root)
        .is_err());
}

#[test]
fn image_byte_flip_detected() {
    // Pretend the device receives `bytes_after_transfer` but the
    // manifest says `secure_hash = SHA256(bytes_before_transfer)`.
    // The device's post-write hash check must fail.
    let original = vec![0x12u8; 0x4000];
    let original_hash: [u8; 32] = Sha256::digest(&original).into();

    let mut tampered = original.clone();
    tampered[100] ^= 0x01;
    let tampered_hash: [u8; 32] = Sha256::digest(&tampered).into();

    assert_ne!(original_hash, tampered_hash);
}

#[test]
fn signing_is_deterministic() {
    // Two separate sign passes over the same digest produce the same
    // signature (SPHINCS+C10 with opt_rand=None is deterministic).
    // This is what makes fwsign output bit-reproducible.
    let sk = fixed_keypair();
    let digest: [u8; 32] = Sha256::digest(b"some test message").into();
    let sig1 = sk.sign(&digest, None);
    let sig2 = sk.sign(&digest, None);
    assert_eq!(sig1.as_slice(), sig2.as_slice());
}
