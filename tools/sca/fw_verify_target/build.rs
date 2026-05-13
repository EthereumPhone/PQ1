//! Generates the three manifest fixtures the thumbv8m target `include_bytes!`s:
//!   - `fixture_valid.bin`     — passes every `verify_*` check
//!   - `fixture_bad_sig.bin`   — signature replaced with all-zeros (CRC recomputed)
//!   - `fixture_bad_digest.bin`— manifest_digest mutated (CRC recomputed)
//!
//! Vendor keypair is derived from a fixed `sk_seed = [0x42; 16]` / `pk_seed = [0x77; 16]`
//! so the fixtures are bit-stable across machines and rebuilds. Also writes the
//! vendor `pk_seed` + `pk_root` and the chosen `rollback_floor`.
//!
//! Also copies `memory.x` so cortex-m-rt's `link.x` can find it. Host check
//! (non-thumb TARGET): no-op so plain `cargo check` from the workspace works.

use std::{env, fs, path::PathBuf};

use fw_manifest::{
    ManifestBuilder, OFF_CRC32, OFF_MANIFEST_DIGEST, OFF_SIGNATURE, SIGNATURE_LEN,
    crc32_ieee, vendor_pubkey_fingerprint,
};
use sphincs_c10::{SigningKey, params::N};

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=memory.x");

    // ---- linker setup (only on thumb*) ---------------------------------
    let target = env::var("TARGET").unwrap_or_default();
    if target.contains("thumb") {
        fs::copy("memory.x", out.join("memory.x")).expect("copying memory.x");
        println!("cargo:rustc-link-search={}", out.display());
    }

    // ---- vendor keypair (deterministic) --------------------------------
    // sk_seed is [u8; 32], pk_seed is [u8; N] (=16). Both fixed → bit-stable.
    let sk_seed = [0x42u8; 32];
    let pk_seed = [0x77u8; N];
    let sk = SigningKey::keygen(sk_seed, pk_seed);

    // sk.pk_seed() / pk_root() are the 16-byte halves.
    let pk_seed_arr: [u8; N] = *sk.pk_seed();
    let pk_root_arr: [u8; N] = *sk.pk_root();
    let vendor_fpr = vendor_pubkey_fingerprint(&pk_seed_arr, &pk_root_arr);

    // ---- valid manifest -------------------------------------------------
    // Dummy image hashes — they're not re-checked by `verify_*` itself
    // (the FSBL streams the image and hashes-on-the-fly *after* manifest
    // verification passes); the manifest's job is to commit to them.
    let secure_hash = [0x11u8; 32];
    let nonsecure_hash = [0x22u8; 32];
    let build_id = [0x33u8; 32];
    let fw_version: u32 = 100; // > rollback_floor (= 0) → passes verify_rollback

    let mut b = ManifestBuilder::new();
    b.init(0x00) // SLOT_A
        .fw_version(fw_version)
        .secure_image(&secure_hash, 0x10_000)
        .nonsecure_image(&nonsecure_hash, 0x20_000)
        .vendor_pubkey_fpr(&vendor_fpr)
        .build_id(&build_id)
        .boot_counter_snap(0)
        .try_once(0x00); // TRY_ONCE_COMMITTED

    let signed_digest = b.finalize_preimage();
    let signature = sk.sign(&signed_digest, None);
    b.set_signature(&signature);
    let valid: [u8; 8192] = b.finalize();

    fs::write(out.join("fixture_valid.bin"), &valid).expect("write valid");

    // ---- bad_sig: zero out signature, re-CRC ---------------------------
    let mut bad_sig = valid;
    for byte in &mut bad_sig[OFF_SIGNATURE..OFF_SIGNATURE + SIGNATURE_LEN] {
        *byte = 0x00;
    }
    let new_crc = crc32_ieee(&bad_sig[..OFF_CRC32]);
    bad_sig[OFF_CRC32..OFF_CRC32 + 4].copy_from_slice(&new_crc.to_be_bytes());
    fs::write(out.join("fixture_bad_sig.bin"), &bad_sig).expect("write bad_sig");

    // ---- bad_digest: flip manifest_digest, re-CRC ----------------------
    // Signature still verifies over the ORIGINAL digest, so the per-step
    // outcome is: verify_digest fails (computed != stored), but
    // verify_signature happens to PASS because it verifies over the
    // mutated stored digest using the original key — wait, no: the sig
    // was signed over the *original* digest, so verifying it over the
    // mutated digest fails. Both checks fail; this fixture exists to
    // sweep "what if the fault skips verify_digest only?"
    let mut bad_digest = valid;
    bad_digest[OFF_MANIFEST_DIGEST] ^= 0xFF;
    let new_crc = crc32_ieee(&bad_digest[..OFF_CRC32]);
    bad_digest[OFF_CRC32..OFF_CRC32 + 4].copy_from_slice(&new_crc.to_be_bytes());
    fs::write(out.join("fixture_bad_digest.bin"), &bad_digest)
        .expect("write bad_digest");

    // ---- vendor pubkey + rollback floor --------------------------------
    fs::write(out.join("vendor_pk_seed.bin"), &pk_seed_arr).expect("write pk_seed");
    fs::write(out.join("vendor_pk_root.bin"), &pk_root_arr).expect("write pk_root");
    // Sanity print (visible at -vv).
    println!("cargo:warning=fw_verify fixtures generated (valid+bad_sig+bad_digest)");
}
