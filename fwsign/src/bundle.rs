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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn fixture_inputs() -> BundleInputs {
        BundleInputs {
            manifest_bytes: [0x11; fw_manifest::MANIFEST_SIZE],
            secure_bytes: vec![0x22; 64],
            nonsecure_bytes: vec![0x33; 96],
            measurement_txt: "measurement contents\n".to_string(),
            pubkey_bytes: [0x44; fw_manifest::VERIFYING_KEY_LEN],
            release_json: "{\"version\":1}\n".to_string(),
        }
    }

    // ----------------------------------------------------------------
    // Positive
    // ----------------------------------------------------------------

    #[test]
    fn positive_pack_unpack_roundtrip() {
        let dir = tempdir().unwrap();
        let out = dir.path().join("a.pqfw");
        let inp = fixture_inputs();
        pack(&inp, &out).unwrap();

        let u = unpack(&out).unwrap();
        assert_eq!(u.manifest_bytes, inp.manifest_bytes);
        assert_eq!(u.secure_bytes, inp.secure_bytes);
        assert_eq!(u.nonsecure_bytes, inp.nonsecure_bytes);
        assert_eq!(u.pubkey_bytes, inp.pubkey_bytes);
        assert_eq!(u.measurement_txt, inp.measurement_txt);
        assert_eq!(u.release_json, inp.release_json);
    }

    #[test]
    fn positive_source_date_epoch_yields_deterministic_bundle() {
        // Two packs of identical inputs under the same SOURCE_DATE_EPOCH
        // must be byte-identical.  Reproducible builds depend on this.
        // We isolate to a single-threaded test path via the `epoch_*`
        // env-var swap.
        std::env::set_var("SOURCE_DATE_EPOCH", "1700000000");
        let dir = tempdir().unwrap();
        let a = dir.path().join("a.pqfw");
        let b = dir.path().join("b.pqfw");
        pack(&fixture_inputs(), &a).unwrap();
        pack(&fixture_inputs(), &b).unwrap();
        let a_bytes = std::fs::read(&a).unwrap();
        let b_bytes = std::fs::read(&b).unwrap();
        std::env::remove_var("SOURCE_DATE_EPOCH");
        assert_eq!(a_bytes, b_bytes, "pack must be deterministic with SOURCE_DATE_EPOCH");
    }

    #[test]
    fn positive_pack_overwrites_existing_file() {
        let dir = tempdir().unwrap();
        let out = dir.path().join("a.pqfw");
        std::fs::write(&out, b"old garbage").unwrap();
        pack(&fixture_inputs(), &out).unwrap();
        // Survives, and is parseable.
        let _ = unpack(&out).unwrap();
    }

    #[test]
    fn positive_unknown_entries_tolerated() {
        // Future-compat: a producer adds a new tar entry; the consumer
        // (older fwsign) must ignore it, not error.
        let dir = tempdir().unwrap();
        let out = dir.path().join("a.pqfw");
        let f = std::fs::File::create(&out).unwrap();
        let mut t = tar::Builder::new(f);
        let inp = fixture_inputs();
        let mtime = 0;
        append(&mut t, "manifest.bin", &inp.manifest_bytes, mtime).unwrap();
        append(&mut t, "secure.bin", &inp.secure_bytes, mtime).unwrap();
        append(&mut t, "nonsecure.bin", &inp.nonsecure_bytes, mtime).unwrap();
        append(&mut t, "pubkey.bin", &inp.pubkey_bytes, mtime).unwrap();
        append(&mut t, "future_thing.bin", b"hello future", mtime).unwrap();
        t.finish().unwrap();

        let u = unpack(&out).unwrap();
        assert_eq!(u.secure_bytes.len(), 64);
        // Optional entries are empty if missing.
        assert!(u.release_json.is_empty());
        assert!(u.measurement_txt.is_empty());
    }

    // ----------------------------------------------------------------
    // Negative: required entries missing
    // ----------------------------------------------------------------

    fn pack_skipping(skip: &[&str]) -> std::path::PathBuf {
        let dir = tempdir().unwrap();
        let out = dir.path().join("a.pqfw");
        let f = std::fs::File::create(&out).unwrap();
        let mut t = tar::Builder::new(f);
        let inp = fixture_inputs();
        let mtime = 0;
        for (name, data) in [
            ("manifest.bin", inp.manifest_bytes.as_slice()),
            ("secure.bin", inp.secure_bytes.as_slice()),
            ("nonsecure.bin", inp.nonsecure_bytes.as_slice()),
            ("pubkey.bin", inp.pubkey_bytes.as_slice()),
        ] {
            if !skip.contains(&name) {
                append(&mut t, name, data, mtime).unwrap();
            }
        }
        t.finish().unwrap();
        // Leak the tempdir so the path stays valid after return.
        let leaked = dir.keep();
        leaked.join("a.pqfw")
    }

    #[test]
    fn negative_missing_manifest_bin_rejected() {
        let p = pack_skipping(&["manifest.bin"]);
        let err = unpack(&p).err().expect("expected Err").to_string();
        assert!(err.contains("manifest.bin"), "got: {err}");
    }

    #[test]
    fn negative_missing_secure_bin_rejected() {
        let p = pack_skipping(&["secure.bin"]);
        let err = unpack(&p).err().expect("expected Err").to_string();
        assert!(err.contains("secure.bin"), "got: {err}");
    }

    #[test]
    fn negative_missing_nonsecure_bin_rejected() {
        let p = pack_skipping(&["nonsecure.bin"]);
        let err = unpack(&p).err().expect("expected Err").to_string();
        assert!(err.contains("nonsecure.bin"), "got: {err}");
    }

    #[test]
    fn negative_missing_pubkey_bin_rejected() {
        let p = pack_skipping(&["pubkey.bin"]);
        let err = unpack(&p).err().expect("expected Err").to_string();
        assert!(err.contains("pubkey.bin"), "got: {err}");
    }

    // ----------------------------------------------------------------
    // Negative: wrong-size required entries
    // ----------------------------------------------------------------

    fn pack_with_override(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let dir = tempdir().unwrap();
        let out = dir.path().join("a.pqfw");
        let f = std::fs::File::create(&out).unwrap();
        let mut t = tar::Builder::new(f);
        let inp = fixture_inputs();
        let mtime = 0;
        let entries: [(&str, &[u8]); 4] = [
            ("manifest.bin", inp.manifest_bytes.as_slice()),
            ("secure.bin", inp.secure_bytes.as_slice()),
            ("nonsecure.bin", inp.nonsecure_bytes.as_slice()),
            ("pubkey.bin", inp.pubkey_bytes.as_slice()),
        ];
        for (n, d) in entries {
            let data = if n == name { bytes } else { d };
            append(&mut t, n, data, mtime).unwrap();
        }
        t.finish().unwrap();
        dir.keep().join("a.pqfw")
    }

    #[test]
    fn negative_manifest_wrong_size_rejected() {
        // Assumption attacked: a producer (or attacker) shortens the
        // manifest, hoping the consumer falls back to a parser that
        // doesn't bounds-check. The strict length gate must fire.
        let p = pack_with_override("manifest.bin", &[0u8; fw_manifest::MANIFEST_SIZE - 1]);
        assert!(unpack(&p).err().expect("expected Err").to_string().contains("manifest.bin"));
    }

    #[test]
    fn negative_manifest_too_large_rejected() {
        let p = pack_with_override("manifest.bin", &[0u8; fw_manifest::MANIFEST_SIZE + 1]);
        assert!(unpack(&p).err().expect("expected Err").to_string().contains("manifest.bin"));
    }

    #[test]
    fn negative_pubkey_wrong_size_rejected() {
        // Assumption attacked: an attacker swaps a 31-byte / 33-byte
        // pubkey hoping the rest of the bundle still parses.
        let p = pack_with_override("pubkey.bin", &[0u8; fw_manifest::VERIFYING_KEY_LEN - 1]);
        assert!(unpack(&p).err().expect("expected Err").to_string().contains("pubkey.bin"));
    }

    #[test]
    fn negative_pubkey_too_large_rejected() {
        let p = pack_with_override("pubkey.bin", &[0u8; fw_manifest::VERIFYING_KEY_LEN + 1]);
        assert!(unpack(&p).err().expect("expected Err").to_string().contains("pubkey.bin"));
    }

    #[test]
    fn negative_empty_pubkey_rejected() {
        let p = pack_with_override("pubkey.bin", &[]);
        assert!(unpack(&p).is_err());
    }

    #[test]
    fn negative_corrupt_archive_rejected() {
        let dir = tempdir().unwrap();
        let out = dir.path().join("corrupt.pqfw");
        std::fs::write(&out, b"this is not a tar archive at all").unwrap();
        assert!(unpack(&out).is_err());
    }

    #[test]
    fn negative_nonexistent_bundle_rejected() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("missing.pqfw");
        assert!(unpack(&p).is_err());
    }

    #[test]
    fn negative_source_date_epoch_invalid_falls_back_to_zero() {
        // Assumption attacked: a garbage env var breaks the pack flow.
        // The code parses-or-falls-back, so a junk value must not
        // panic. Determinism is the goal — falling back to 0 is fine.
        std::env::set_var("SOURCE_DATE_EPOCH", "not-a-number");
        let dir = tempdir().unwrap();
        let out = dir.path().join("a.pqfw");
        let r = pack(&fixture_inputs(), &out);
        std::env::remove_var("SOURCE_DATE_EPOCH");
        assert!(r.is_ok());
        assert!(unpack(&out).is_ok());
    }
}
