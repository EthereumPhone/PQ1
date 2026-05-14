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

    let mtime = source_date_epoch();
    append(&mut builder, "manifest.bin", &inputs.manifest_bytes, mtime)?;
    append(&mut builder, "secure.bin", &inputs.secure_bytes, mtime)?;
    append(&mut builder, "nonsecure.bin", &inputs.nonsecure_bytes, mtime)?;
    append(
        &mut builder,
        "measurement.txt",
        inputs.measurement_txt.as_bytes(),
        mtime,
    )?;
    append(&mut builder, "pubkey.bin", &inputs.pubkey_bytes, mtime)?;
    append(
        &mut builder,
        "release.json",
        inputs.release_json.as_bytes(),
        mtime,
    )?;

    builder.finish().context("finalising tar")?;
    Ok(())
}

/// Honour `SOURCE_DATE_EPOCH` for reproducible-build mtimes (falls back to 0).
fn source_date_epoch() -> u64 {
    std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0)
}

fn append<W: Write>(
    builder: &mut tar::Builder<W>,
    name: &str,
    data: &[u8],
    mtime: u64,
) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_path(name)?;
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    header.set_uid(0);
    header.set_gid(0);
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

    let manifest = require(manifest, "manifest.bin")?;
    let secure = require(secure, "secure.bin")?;
    let nonsecure = require(nonsecure, "nonsecure.bin")?;
    let pubkey = require(pubkey, "pubkey.bin")?;

    let manifest_bytes = into_fixed::<{ fw_manifest::MANIFEST_SIZE }>(&manifest, "manifest.bin")?;
    let pubkey_bytes =
        into_fixed::<{ fw_manifest::VERIFYING_KEY_LEN }>(&pubkey, "pubkey.bin")?;

    Ok(UnpackedBundle {
        manifest_bytes,
        secure_bytes: secure,
        nonsecure_bytes: nonsecure,
        pubkey_bytes,
        measurement_txt: measurement.unwrap_or_default(),
        release_json: release.unwrap_or_default(),
    })
}

fn require<T>(entry: Option<T>, name: &str) -> Result<T> {
    entry.ok_or_else(|| anyhow!("bundle missing {name}"))
}

fn into_fixed<const N: usize>(bytes: &[u8], name: &str) -> Result<[u8; N]> {
    if bytes.len() != N {
        bail!("{name} wrong size: got {} bytes, want {N}", bytes.len());
    }
    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    Ok(out)
}
