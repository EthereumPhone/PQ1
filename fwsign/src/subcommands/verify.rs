//! `fwsign verify` — independent bundle verification.
//!
//! Runs the same check chain FSBL runs at boot, in the same order:
//!
//! 1. Unpack the bundle and check required entries exist.
//! 2. Re-parse the vendor pubkey from `pubkey.bin`.
//! 3. `verify_structural` — magic + version + slot byte.
//! 4. `verify_crc` — trailing CRC-32 over the manifest.
//! 5. `verify_digest` — SHA-256 of preimage matches stored digest.
//! 6. `verify_vendor_fpr` — cheap reject before the expensive sig check.
//! 7. `verify_signature` — SPHINCS+C10 verify over the digest.
//! 8. Re-hash `secure.bin` + `nonsecure.bin` and compare against the
//!    manifest's stored hashes + lengths.
//!
//! Does **not** check anti-rollback — that's device-side only, since
//! this tool doesn't know the OTP floor of any particular device.

use anyhow::{anyhow, bail, Context, Result};
use fw_manifest::{ManifestRef, VerifyError, VERIFYING_KEY_LEN};
use sha2::{Digest, Sha256};
use sphincs_c10::params::N;
use std::path::Path;

use crate::bundle;

pub fn run(bundle_path: &Path, pubkey_path: &Path) -> Result<()> {
    let unpacked = bundle::unpack(bundle_path)?;

    // Optional cross-check: the pubkey.bin inside the bundle should
    // match the vendor pubkey the auditor supplied (otherwise the
    // bundle is claiming a different vendor than the auditor is
    // verifying against — abort loudly).
    let supplied_pubkey = std::fs::read(pubkey_path)
        .with_context(|| format!("reading {}", pubkey_path.display()))?;
    if supplied_pubkey.len() != VERIFYING_KEY_LEN {
        bail!(
            "supplied pubkey wrong size: got {} bytes, want {VERIFYING_KEY_LEN}",
            supplied_pubkey.len()
        );
    }
    if supplied_pubkey != unpacked.pubkey_bytes {
        bail!(
            "supplied --pubkey does not match pubkey.bin inside bundle — bundle claims a different vendor"
        );
    }

    let mut pk_seed = [0u8; N];
    let mut pk_root = [0u8; N];
    pk_seed.copy_from_slice(&unpacked.pubkey_bytes[..N]);
    pk_root.copy_from_slice(&unpacked.pubkey_bytes[N..]);

    let m = ManifestRef::new(&unpacked.manifest_bytes);

    eprintln!("==> verify_structural");
    m.verify_structural().map_err(stage_err)?;

    eprintln!("==> verify_crc");
    m.verify_crc().map_err(stage_err)?;

    eprintln!("==> verify_digest");
    m.verify_digest().map_err(stage_err)?;

    eprintln!("==> verify_vendor_fpr");
    m.verify_vendor_fpr(&pk_seed, &pk_root).map_err(stage_err)?;

    eprintln!("==> verify_signature (SPHINCS+C10)");
    m.verify_signature(&pk_seed, &pk_root).map_err(stage_err)?;

    eprintln!("==> Image hashes");
    check_image("secure", &unpacked.secure_bytes, m.secure_len(), m.secure_hash())?;
    check_image(
        "nonsecure",
        &unpacked.nonsecure_bytes,
        m.nonsecure_len(),
        m.nonsecure_hash(),
    )?;

    eprintln!();
    eprintln!("==> verify: PASS");
    eprintln!("    version  : {}", m.fw_version());
    eprintln!(
        "    slot     : {}",
        if m.slot() == fw_manifest::SLOT_A { "A" } else { "B" }
    );
    eprintln!("    secure   : {} bytes, {}", m.secure_len(), hex::encode(m.secure_hash()));
    eprintln!("    nonsecure: {} bytes, {}", m.nonsecure_len(), hex::encode(m.nonsecure_hash()));
    eprintln!("    build_id : {}", hex::encode(m.build_id()));
    Ok(())
}

fn stage_err(e: VerifyError) -> anyhow::Error {
    anyhow!("verification failed: {e:?}")
}

fn check_image(label: &str, bytes: &[u8], manifest_len: u32, manifest_hash: &[u8; 32]) -> Result<()> {
    if bytes.len() != manifest_len as usize {
        bail!(
            "{label}.bin length mismatch: bundle {} bytes, manifest {manifest_len}",
            bytes.len(),
        );
    }
    let hash: [u8; 32] = Sha256::digest(bytes).into();
    if &hash != manifest_hash {
        bail!("{label}.bin SHA-256 does not match manifest.{label}_hash");
    }
    Ok(())
}
