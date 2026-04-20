//! `fwsign verify-release` — independent signature verification from
//! just the source-built firmware.
//!
//! This is the subcommand an auditor uses after rebuilding the
//! firmware from source:
//!
//! ```bash
//! # 1. Rebuild reproducibly (matches what the vendor published).
//! git checkout $RELEASE_COMMIT
//! make release RELEASE_FEATURES=stm32u585,se050,optiga-trust-m,dual-se,ui-oled
//!
//! # 2. Verify the vendor's signature against YOUR build.
//! fwsign verify-release \
//!     --version 42 \
//!     --secure target/release/secure.elf \
//!     --nonsecure target/release/nonsecure.elf \
//!     --signature release-v42.sig \
//!     --pubkey vendor-pubkey.bin
//! ```
//!
//! `release-v42.sig` is extracted from the `.pqfw` at release time
//! (it's the 4008-byte SPHINCS+C10 signature, nothing else). The
//! auditor does not need to parse the manifest, the `.pqfw` envelope,
//! or any device-specific metadata — just the published signature,
//! the published public key, and their own rebuilt firmware.
//!
//! The verification chain is **exactly** what FSBL runs on-device:
//!
//! ```text
//!   preimage = b"PQFW_V1"
//!           || version_be_u32
//!           || SHA-256(secure_flash_image)
//!           || SHA-256(nonsecure_flash_image)
//!   digest   = SHA-256(preimage)
//!   valid    = sphincs_c10::verify(pk_seed, pk_root, digest, signature)
//! ```
//!
//! If this passes, you know:
//!
//! 1. **Authenticity** — the signature was produced by the holder of
//!    the vendor SK. Anyone else would need to break SPHINCS+C10.
//! 2. **Integrity** — the firmware you built matches the firmware the
//!    vendor signed, byte-for-byte (post flatten). Any divergence
//!    would change the SHA-256 and break the signature.
//! 3. **Version binding** — the same hash with a different version
//!    number produces a different digest, so an attacker can't
//!    replay an old signed release with a higher version claim.
//!
//! It does **not** tell you:
//!
//! * Whether the vendor is trustworthy. That's social trust, not
//!   cryptography.
//! * Whether the firmware is bug-free. That's code review, not
//!   cryptography.
//! * Whether your specific device will accept this release — that
//!   depends on the OTP rollback floor on your specific chip, which
//!   this tool can't read.

use anyhow::{anyhow, Context, Result};
use fw_manifest::{compute_signed_digest, VERIFYING_KEY_LEN};
use sphincs_c10::params::{N, SIGNATURE_LEN};
use std::path::Path;

use crate::elf;

/// Run the `verify-release` subcommand.
pub fn run(
    version: u32,
    secure_elf: &Path,
    nonsecure_elf: &Path,
    signature: &Path,
    pubkey: &Path,
) -> Result<()> {
    // --- Load inputs -------------------------------------------------

    let pk_bytes = std::fs::read(pubkey)
        .with_context(|| format!("reading {}", pubkey.display()))?;
    if pk_bytes.len() != VERIFYING_KEY_LEN {
        return Err(anyhow!(
            "pubkey file wrong size: got {} bytes, want {VERIFYING_KEY_LEN}",
            pk_bytes.len()
        ));
    }
    let mut pk_seed = [0u8; N];
    let mut pk_root = [0u8; N];
    pk_seed.copy_from_slice(&pk_bytes[..N]);
    pk_root.copy_from_slice(&pk_bytes[N..]);

    let sig_bytes = std::fs::read(signature)
        .with_context(|| format!("reading {}", signature.display()))?;
    if sig_bytes.len() != SIGNATURE_LEN {
        return Err(anyhow!(
            "signature file wrong size: got {} bytes, want {SIGNATURE_LEN}",
            sig_bytes.len()
        ));
    }
    let mut sig = [0u8; SIGNATURE_LEN];
    sig.copy_from_slice(&sig_bytes);

    // --- Rebuild the signed preimage from source ---------------------

    eprintln!("==> Flattening {}", secure_elf.display());
    let secure = elf::flatten_elf(secure_elf)?;
    eprintln!(
        "    secure    : {} bytes, SHA-256 {}",
        secure.bytes.len(),
        hex::encode(secure.hash)
    );

    eprintln!("==> Flattening {}", nonsecure_elf.display());
    let nonsecure = elf::flatten_elf(nonsecure_elf)?;
    eprintln!(
        "    nonsecure : {} bytes, SHA-256 {}",
        nonsecure.bytes.len(),
        hex::encode(nonsecure.hash)
    );

    let digest = compute_signed_digest(version, &secure.hash, &nonsecure.hash);
    eprintln!("==> Signed preimage:");
    eprintln!("    domain tag : {:?}", core::str::from_utf8(fw_manifest::DOMAIN_TAG).unwrap());
    eprintln!("    version    : {version}");
    eprintln!("    digest     : {}", hex::encode(digest));

    // --- SPHINCS+C10 verify ------------------------------------------

    eprintln!("==> SPHINCS+C10 verify (post-quantum)");
    let ok = sphincs_c10::verify(&pk_seed, &pk_root, &digest, &sig);
    if !ok {
        return Err(anyhow!(
            "VERIFY FAILED: signature does not match (version, source-built hashes, pubkey)"
        ));
    }

    eprintln!();
    eprintln!("==> verify-release: PASS");
    eprintln!("    This release IS signed by the vendor holding the private key");
    eprintln!("    for pubkey {}.", hex::encode(pk_bytes));
    eprintln!("    The firmware you built matches the firmware the vendor signed.");
    Ok(())
}
