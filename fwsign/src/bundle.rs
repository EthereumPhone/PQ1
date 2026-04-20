//! `.pqfw` release bundle — pack and unpack.
//!
//! A `.pqfw` is a POSIX tar (uncompressed) containing:
//!
//! * `manifest.bin`    — exactly `MANIFEST_SIZE` bytes, flashable verbatim.
//! * `secure.bin`      — secure-image bytes, length `manifest.secure_len`.
//! * `nonsecure.bin`   — NS-image bytes, length `manifest.nonsecure_len`.
//! * `measurement.txt` — human-readable 8-word fingerprint + hashes.
//! * `pubkey.bin`      — 32-byte vendor pubkey for independent verify.
//! * `release.json`    — metadata (version, slot, build_id, timestamps).
//!
//! Tar is used over zip because:
//! * It's deterministic out-of-the-box (no central directory with
//!   timestamps to strip), modulo mtime normalization which we apply.
//! * It's streaming: the companion updater can unpack on the fly if
//!   needed (though in practice .pqfw is small enough to fit in memory).
//!
//! All entries are written with mode 0o644, uid/gid 0, mtime derived
//! from `SOURCE_DATE_EPOCH` (falls back to 0 if unset), so repeated
//! `fwsign sign` invocations produce byte-identical bundles.

use anyhow::{anyhow, bail, Context, Result};
use std::io::{Read, Write};
use std::path::Path;

/// Inputs to `pack`. All fields owned to keep the signing flow simple.
pub struct BundleInputs {
    pub manifest_bytes: [u8; fw_manifest::MANIFEST_SIZE],
    pub secure_bytes: Vec<u8>,
    pub nonsecure_bytes: Vec<u8>,
    pub measurement_txt: String,
    pub pubkey_bytes: [u8; fw_manifest::VERIFYING_KEY_LEN],
    pub release_json: String,
}

/// Pack a release bundle into `out_path`. Existing files are overwritten.
pub fn pack(inputs: &BundleInputs, out_path: &Path) -> Result<()> {
    let file = std::fs::File::create(out_path)
        .with_context(|| format!("creating {}", out_path.display()))?;
    let mut builder = tar::Builder::new(file);
    builder.mode(tar::HeaderMode::Deterministic);

    append(&mut builder, "manifest.bin", &inputs.manifest_bytes)?;
    append(&mut builder, "secure.bin", &inputs.secure_bytes)?;
    append(&mut builder, "nonsecure.bin", &inputs.nonsecure_bytes)?;
    append(&mut builder, "measurement.txt", inputs.measurement_txt.as_bytes())?;
    append(&mut builder, "pubkey.bin", &inputs.pubkey_bytes)?;
    append(&mut builder, "release.json", inputs.release_json.as_bytes())?;

    builder.finish().context("finalising tar")?;
    Ok(())
}

fn append<W: Write>(builder: &mut tar::Builder<W>, name: &str, data: &[u8]) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_path(name)?;
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    header.set_uid(0);
    header.set_gid(0);
    // SOURCE_DATE_EPOCH ensures deterministic mtimes across rebuilds.
    let mtime = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    header.set_mtime(mtime);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_cksum();

    builder
        .append(&header, data)
        .with_context(|| format!("appending {name}"))?;
    Ok(())
}

/// Contents of an unpacked `.pqfw`. Sizes are checked against
/// `fw_manifest` expectations at parse time.
pub struct UnpackedBundle {
    pub manifest_bytes: [u8; fw_manifest::MANIFEST_SIZE],
    pub secure_bytes: Vec<u8>,
    pub nonsecure_bytes: Vec<u8>,
    pub pubkey_bytes: [u8; fw_manifest::VERIFYING_KEY_LEN],
    pub measurement_txt: String,
    pub release_json: String,
}

/// Unpack a `.pqfw`. Missing required entries are an error.
pub fn unpack(path: &Path) -> Result<UnpackedBundle> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    let mut archive = tar::Archive::new(file);

    let mut manifest: Option<Vec<u8>> = None;
    let mut secure: Option<Vec<u8>> = None;
    let mut nonsecure: Option<Vec<u8>> = None;
    let mut pubkey: Option<Vec<u8>> = None;
    let mut measurement: Option<String> = None;
    let mut release: Option<String> = None;

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let name = path
            .to_str()
            .ok_or_else(|| anyhow!("non-utf8 bundle entry path"))?;
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf)?;
        match name {
            "manifest.bin" => manifest = Some(buf),
            "secure.bin" => secure = Some(buf),
            "nonsecure.bin" => nonsecure = Some(buf),
            "pubkey.bin" => pubkey = Some(buf),
            "measurement.txt" => measurement = Some(String::from_utf8(buf)?),
            "release.json" => release = Some(String::from_utf8(buf)?),
            // Tolerate unknown entries (future-compatible).
            _ => {}
        }
    }

    let manifest =
        manifest.ok_or_else(|| anyhow!("bundle missing manifest.bin"))?;
    let secure = secure.ok_or_else(|| anyhow!("bundle missing secure.bin"))?;
    let nonsecure = nonsecure.ok_or_else(|| anyhow!("bundle missing nonsecure.bin"))?;
    let pubkey = pubkey.ok_or_else(|| anyhow!("bundle missing pubkey.bin"))?;
    let measurement = measurement.unwrap_or_default();
    let release = release.unwrap_or_default();

    if manifest.len() != fw_manifest::MANIFEST_SIZE {
        bail!(
            "manifest.bin wrong size: got {} bytes, want {}",
            manifest.len(),
            fw_manifest::MANIFEST_SIZE
        );
    }
    if pubkey.len() != fw_manifest::VERIFYING_KEY_LEN {
        bail!(
            "pubkey.bin wrong size: got {} bytes, want {}",
            pubkey.len(),
            fw_manifest::VERIFYING_KEY_LEN
        );
    }

    let mut manifest_bytes = [0u8; fw_manifest::MANIFEST_SIZE];
    manifest_bytes.copy_from_slice(&manifest);
    let mut pubkey_bytes = [0u8; fw_manifest::VERIFYING_KEY_LEN];
    pubkey_bytes.copy_from_slice(&pubkey);

    Ok(UnpackedBundle {
        manifest_bytes,
        secure_bytes: secure,
        nonsecure_bytes: nonsecure,
        pubkey_bytes,
        measurement_txt: measurement,
        release_json: release,
    })
}
