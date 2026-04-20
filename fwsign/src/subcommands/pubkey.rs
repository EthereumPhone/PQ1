//! `fwsign pubkey` — export the 32-byte vendor public key.
//!
//! Output format: 32 raw bytes, `pk_seed[16] || pk_root[16]`. This is
//! the file `FSBL_VENDOR_PUBKEY` points at during FSBL builds; `build.rs`
//! there `include_bytes!`s it verbatim.

use anyhow::{Context, Result};
use std::path::Path;

use crate::keystore::{self, VendorKey};

pub fn run(key_path: &Path, out_path: &Path) -> Result<()> {
    let blob = std::fs::read(key_path)
        .with_context(|| format!("reading {}", key_path.display()))?;
    let passphrase = keystore::prompt_passphrase("Vendor key passphrase")?;
    let key = VendorKey::open(&blob, &passphrase)?;

    let mut out = [0u8; fw_manifest::VERIFYING_KEY_LEN];
    out[..sphincs_c10::params::N].copy_from_slice(key.pk_seed());
    out[sphincs_c10::params::N..].copy_from_slice(key.pk_root());

    std::fs::write(out_path, out)
        .with_context(|| format!("writing {}", out_path.display()))?;

    let fpr = fw_manifest::vendor_pubkey_fingerprint(key.pk_seed(), key.pk_root());
    eprintln!("==> Wrote 32-byte vendor pubkey to {}", out_path.display());
    eprintln!("    fingerprint: {}", hex::encode(fpr));
    eprintln!();
    eprintln!("    Pass this to the FSBL build:");
    eprintln!("      make fsbl FSBL_VENDOR_PUBKEY={}", out_path.display());
    Ok(())
}
