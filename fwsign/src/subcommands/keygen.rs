//! `fwsign keygen` — generate a fresh vendor signing key.
//!
//! The 32-byte sk_seed and 16-byte pk_seed are sampled from OsRng. We
//! then run full SPHINCS+C10 keygen (2-3 s on a laptop) to compute
//! pk_root, so subsequent `fwsign sign` invocations don't repeat that
//! work. The whole triple is encrypted under a user passphrase using
//! Argon2id + XChaCha20-Poly1305 (see `keystore.rs`).

use anyhow::{bail, Context, Result};
use std::path::Path;

use crate::keystore::{self, VendorKey};

pub fn run(out_path: &Path) -> Result<()> {
    if out_path.exists() {
        bail!(
            "refusing to overwrite existing file {} — move or delete it first",
            out_path.display()
        );
    }

    eprintln!("==> Generating vendor SPHINCS+C10 keypair");
    eprintln!("    This takes 2-3 seconds on a laptop (hypertree build).");

    let key = VendorKey::generate()?;
    let pk_seed = hex::encode(key.pk_seed());
    let pk_root = hex::encode(key.pk_root());
    let fpr = hex::encode(fw_manifest::vendor_pubkey_fingerprint(
        key.pk_seed(),
        key.pk_root(),
    ));

    eprintln!("==> Key generated:");
    eprintln!("    pk_seed: {pk_seed}");
    eprintln!("    pk_root: {pk_root}");
    eprintln!("    fingerprint (SHA-256(pk_seed || pk_root)):");
    eprintln!("      {fpr}");
    eprintln!();
    eprintln!("==> Choose a strong passphrase — losing it means the key is lost forever.");
    let passphrase = keystore::prompt_passphrase_twice()?;

    eprintln!("==> Deriving KDF + encrypting");
    let blob = key.seal(&passphrase)?;

    std::fs::write(out_path, blob)
        .with_context(|| format!("writing {}", out_path.display()))?;

    eprintln!("==> Encrypted vendor key written to {}", out_path.display());
    eprintln!("    Next: `fwsign pubkey --key {} --out vendor-pubkey.bin`", out_path.display());
    eprintln!("    Keep this file and the passphrase on separate offline media.");
    Ok(())
}
