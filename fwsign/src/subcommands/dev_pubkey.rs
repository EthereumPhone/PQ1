//! `fwsign dev-pubkey` — emit the built-in DEV vendor public key (32 bytes,
//! `pk_seed[16] || pk_root[16]`) derived from the fixed dev seed.
//!
//! Output is byte-identical to what `fsbl/build.rs` embeds when
//! `FSBL_VENDOR_PUBKEY` is unset — the "dev fixture" key used by every dev /
//! e2e build of the FSBL. The `make dev-pubkey-fixture` target points
//! `FSBL_VENDOR_PUBKEY` at this file so the *secure* world (which has no
//! `sphincs-c10` build-dep and so can't compute the dev key in `build.rs`)
//! embeds the same pubkey the FSBL does — and so that dev-signed manifests
//! (e.g. from `secure/src/fw_rollback_e2e.rs`) verify.
//!
//! Never use this key for a production release. There is no passphrase, no
//! keystore — anyone with the source tree has the corresponding signing key.

use anyhow::{Context, Result};
use std::path::Path;

use sphincs_c10::SigningKey;

/// Dev signing seed — MUST stay byte-identical to:
///   * `fsbl/build.rs` (the FSBL dev-fallback path)
///   * `fwsign/tests/sign_verify_roundtrip.rs`
///   * `secure/src/fw_rollback_e2e.rs`
/// Drift between any of these breaks the dev signature chain.
const DEV_SK: [u8; 32] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
];
const DEV_PS: [u8; 16] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
];

pub fn run(out_path: &Path) -> Result<()> {
    let sk = SigningKey::keygen(DEV_SK, DEV_PS);

    let mut out = [0u8; fw_manifest::VERIFYING_KEY_LEN];
    out[..sphincs_c10::params::N].copy_from_slice(sk.pk_seed());
    out[sphincs_c10::params::N..].copy_from_slice(sk.pk_root());

    std::fs::write(out_path, out)
        .with_context(|| format!("writing {}", out_path.display()))?;

    let fpr = fw_manifest::vendor_pubkey_fingerprint(sk.pk_seed(), sk.pk_root());
    eprintln!("==> Wrote 32-byte DEV vendor pubkey to {}", out_path.display());
    eprintln!("    fingerprint: {}", hex::encode(fpr));
    eprintln!();
    eprintln!("    DEV ONLY — derived from a public fixed seed; never use for production.");
    eprintln!("    Pass this to dev FSBL / secure / fw-rollback-hw builds:");
    eprintln!("      FSBL_VENDOR_PUBKEY={} cargo build ...", out_path.display());
    Ok(())
}
