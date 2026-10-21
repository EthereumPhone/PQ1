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
//! 9. Only after those authentication checks, parse the ERC-7730 P73S/P73K
//!    sidecars and require their exact bytes to occur uniquely in `secure.bin`.
//!
//! Does **not** check anti-rollback — that's device-side only, since
//! this tool doesn't know the OTP floor of any particular device.

use anyhow::{anyhow, bail, Context, Result};
use fw_manifest::{ManifestRef, VerifyError, VERIFYING_KEY_LEN};
use sha2::{Digest, Sha256};
use sphincs_c10::params::N;
use std::path::Path;

use crate::bundle;

/// Fields retained only after the complete bundle authentication chain passes.
///
/// The legacy PQFW_V1 signature commits to `fw_version` and the two image
/// hashes.  `secure_len`/`nonsecure_len` below also equal the authenticated
/// image byte lengths because [`authenticate_bundle`] hashes and length-checks
/// the exact unpacked images.  Slot and build ID are retained for honest
/// reporting, but callers must not claim that legacy PQFW_V1 signed them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AuthenticatedBundle {
    pub(crate) manifest_version: u8,
    pub(crate) fw_version: u32,
    pub(crate) slot: u8,
    pub(crate) secure_len: u32,
    pub(crate) nonsecure_len: u32,
    pub(crate) secure_hash: [u8; 32],
    pub(crate) nonsecure_hash: [u8; 32],
    pub(crate) vendor_pubkey_fingerprint: [u8; 32],
    pub(crate) build_id: [u8; 32],
    pub(crate) manifest_digest: [u8; 32],
    pub(crate) manifest_sha256: [u8; 32],
    pub(crate) erc7730_status:
        Option<[u8; pqsigner_erc7730::catalogue_status::CATALOGUE_STATUS_V1_LEN]>,
    pub(crate) erc7730_forced_eligible: Option<Vec<u8>>,
}

/// Authenticate one complete bundle and return only fields derived from the
/// authenticated manifest/images/P73S/P73K binding.
///
/// This intentionally ignores `release.json` and `measurement.txt`. They are
/// presentation sidecars, not authority inputs. ERC-7730 status remains
/// optional here so the generic legacy `verify` command can continue to audit
/// old bundles; clear-signing readiness requires it in the dedicated command.
pub(crate) fn authenticate_bundle(
    bundle_path: &Path,
    pubkey_path: &Path,
) -> Result<AuthenticatedBundle> {
    authenticate_bundle_with_capacity(
        bundle_path,
        pubkey_path,
        fw_manifest::SLOT_SECURE_CAPACITY,
        fw_manifest::SLOT_NS_CAPACITY,
    )
}

/// [`authenticate_bundle`] against explicit slot capacities (the dev-unit
/// A/B layout has larger slots, `fw_manifest::devunit`).
pub(crate) fn authenticate_bundle_with_capacity(
    bundle_path: &Path,
    pubkey_path: &Path,
    secure_capacity: u32,
    ns_capacity: u32,
) -> Result<AuthenticatedBundle> {
    let unpacked = bundle::unpack(bundle_path)?;

    crate::elf::ensure_image_capacity("secure", unpacked.secure_bytes.len(), secure_capacity)?;
    crate::elf::ensure_image_capacity("nonsecure", unpacked.nonsecure_bytes.len(), ns_capacity)?;

    // Optional cross-check: the pubkey.bin inside the bundle should
    // match the vendor pubkey the auditor supplied (otherwise the
    // bundle is claiming a different vendor than the auditor is
    // verifying against — abort loudly).
    let supplied_pubkey =
        std::fs::read(pubkey_path).with_context(|| format!("reading {}", pubkey_path.display()))?;
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
    check_image(
        "secure",
        &unpacked.secure_bytes,
        m.secure_len(),
        m.secure_hash(),
    )?;
    check_image(
        "nonsecure",
        &unpacked.nonsecure_bytes,
        m.nonsecure_len(),
        m.nonsecure_hash(),
    )?;

    // The sidecar is optional only for legacy bundles. Never consult it until
    // the manifest signature and both image hashes above have authenticated
    // the flat image bytes. New `fwsign sign` bundles always include it.
    if let Some(status) = &unpacked.erc7730_status_bytes {
        eprintln!("==> ERC-7730 catalogue status binding");
        crate::artifact_key::verify_unique_erc7730_status_in_flat_image(
            status,
            &unpacked.secure_bytes,
        )?;
    } else {
        eprintln!(
            "==> ERC-7730 catalogue status: ABSENT (legacy bundle; clear-signing compatibility unavailable)"
        );
    }

    if let Some(forced_eligible) = &unpacked.erc7730_forced_eligible_bytes {
        let status = unpacked.erc7730_status_bytes.as_ref().ok_or_else(|| {
            anyhow!(
                "erc7730-forced-eligible.bin requires the companion erc7730-status.bin identity"
            )
        })?;
        eprintln!("==> ERC-7730 forced-eligible binding");
        crate::artifact_key::verify_unique_erc7730_forced_eligible_in_flat_image(
            forced_eligible,
            &unpacked.secure_bytes,
        )?;
        crate::artifact_key::verify_erc7730_sidecars_disjoint_in_flat_image(
            status,
            forced_eligible,
            &unpacked.secure_bytes,
        )?;
    } else {
        crate::artifact_key::verify_erc7730_forced_eligible_absent_from_flat_image(
            &unpacked.secure_bytes,
        )?;
        eprintln!(
            "==> ERC-7730 forced eligible: ABSENT (legacy/feature-off bundle; forced-blind compatibility unavailable)"
        );
    }

    Ok(AuthenticatedBundle {
        manifest_version: m.manifest_version(),
        fw_version: m.fw_version(),
        slot: m.slot(),
        secure_len: m.secure_len(),
        nonsecure_len: m.nonsecure_len(),
        secure_hash: *m.secure_hash(),
        nonsecure_hash: *m.nonsecure_hash(),
        vendor_pubkey_fingerprint: *m.vendor_pubkey_fpr(),
        build_id: *m.build_id(),
        manifest_digest: *m.manifest_digest(),
        manifest_sha256: Sha256::digest(unpacked.manifest_bytes).into(),
        erc7730_status: unpacked.erc7730_status_bytes,
        erc7730_forced_eligible: unpacked.erc7730_forced_eligible_bytes,
    })
}

pub fn run(bundle_path: &Path, pubkey_path: &Path, devunit_ab: bool) -> Result<()> {
    let authenticated = if devunit_ab {
        authenticate_bundle_with_capacity(
            bundle_path,
            pubkey_path,
            fw_manifest::devunit::SECURE_SLOT_CAPACITY,
            fw_manifest::devunit::NS_SLOT_CAPACITY,
        )?
    } else {
        authenticate_bundle(bundle_path, pubkey_path)?
    };

    eprintln!();
    eprintln!("==> verify: PASS");
    eprintln!("    version  : {}", authenticated.fw_version);
    eprintln!(
        "    slot     : {}",
        if authenticated.slot == fw_manifest::SLOT_A {
            "A"
        } else {
            "B"
        }
    );
    eprintln!(
        "    secure   : {} bytes, {}",
        authenticated.secure_len,
        hex::encode(authenticated.secure_hash)
    );
    eprintln!(
        "    nonsecure: {} bytes, {}",
        authenticated.nonsecure_len,
        hex::encode(authenticated.nonsecure_hash)
    );
    eprintln!("    build_id : {}", hex::encode(authenticated.build_id));
    eprintln!(
        "    erc7730   : {}",
        if authenticated.erc7730_status.is_some() {
            "authenticated status bound"
        } else {
            "unavailable (legacy/feature-off bundle)"
        }
    );
    eprintln!(
        "    forced    : {}",
        if authenticated.erc7730_forced_eligible.is_some() {
            "authenticated forced-eligible set bound"
        } else {
            "unavailable (legacy bundle)"
        }
    );
    Ok(())
}

fn stage_err(e: VerifyError) -> anyhow::Error {
    anyhow!("verification failed: {e:?}")
}

fn check_image(
    label: &str,
    bytes: &[u8],
    manifest_len: u32,
    manifest_hash: &[u8; 32],
) -> Result<()> {
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
