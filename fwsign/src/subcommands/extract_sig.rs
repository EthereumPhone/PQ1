//! `fwsign extract-sig` — pull the raw 4008-byte SPHINCS+C10 signature out
//! of a `.pqfw` bundle.
//!
//! Auditors who want to run `verify-release` over a source-built firmware
//! only need this 4008-byte blob plus the vendor pubkey — not the whole
//! ~5 MB bundle. This subcommand makes that extraction a one-liner.

use anyhow::Result;
use fw_manifest::ManifestRef;
use std::path::Path;

use crate::bundle;

pub fn run(bundle_path: &Path, out_path: &Path) -> Result<()> {
    let unpacked = bundle::unpack(bundle_path)?;
    let m = ManifestRef::new(&unpacked.manifest_bytes);
    std::fs::write(out_path, m.signature())?;
    eprintln!(
        "==> Extracted {} bytes of SPHINCS+C10 signature to {}",
        sphincs_c10::params::SIGNATURE_LEN,
        out_path.display()
    );
    Ok(())
}
