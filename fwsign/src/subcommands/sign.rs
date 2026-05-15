//! `fwsign sign` — produce a `.pqfw` release bundle.
//!
//! Flow:
//! 1. Load + decrypt the vendor key.
//! 2. Flatten both ELFs to the same measurement regions `fwmeasure`
//!    covers.
//! 3. Assemble the 180-byte preimage in a [`ManifestBuilder`].
//! 4. SHA-256 the preimage → `manifest_digest`.
//! 5. SPHINCS+C10-sign the digest (deterministic, no hedging — so two
//!    sign runs on identical inputs produce identical bundles).
//! 6. Compute the CRC, write + commit the manifest bytes.
//! 7. Pack everything into a `.pqfw` tar.
//!
//! The manifest carries `fw_version`, hashes, lengths, vendor
//! fingerprint, build_id, and the signature. The secure + nonsecure
//! bytes in the bundle are the exact flat images the device will write
//! to flash — FSBL will re-hash them post-write and reject a mismatch.

use anyhow::{bail, Context, Result};
use fw_manifest::{ManifestBuilder, TRY_ONCE_COMMITTED};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::bundle::{self, BundleInputs};
use crate::elf::{self, FlatImage};
use crate::keystore::{self, VendorKey};

pub struct Args {
    pub key_path: PathBuf,
    pub version: u32,
    pub secure_elf: PathBuf,
    pub nonsecure_elf: PathBuf,
    pub slot: u8,
    pub build_id_hex: String,
    pub boot_counter_snap: Option<u32>,
    pub out_path: PathBuf,
}

pub fn run(args: Args) -> Result<()> {
    let build_id = parse_build_id(&args.build_id_hex)?;
    let boot_counter_snap = resolve_boot_counter_snap(args.version, args.boot_counter_snap)?;

    let key = load_vendor_key(&args.key_path)?;
    let vendor_fpr = fw_manifest::vendor_pubkey_fingerprint(key.pk_seed(), key.pk_root());
    eprintln!("==> Vendor fingerprint: {}", hex::encode(vendor_fpr));

    let secure = flatten_logged("secure", &args.secure_elf)?;
    let nonsecure = flatten_logged("nonsecure", &args.nonsecure_elf)?;

    let (manifest_bytes, digest) = build_signed_manifest(
        &key,
        args.slot,
        args.version,
        &secure,
        &nonsecure,
        &vendor_fpr,
        &build_id,
        boot_counter_snap,
    )?;
    eprintln!("==> Manifest complete: {} bytes", manifest_bytes.len());

    let measurement_txt = build_measurement_txt(
        args.version,
        args.slot,
        &secure.hash,
        &nonsecure.hash,
        &args.build_id_hex,
        &vendor_fpr,
    );
    let release_json = build_release_json(
        &args,
        &secure,
        &nonsecure,
        &vendor_fpr,
        &digest,
        boot_counter_snap,
    );

    let mut pubkey_bytes = [0u8; fw_manifest::VERIFYING_KEY_LEN];
    pubkey_bytes[..sphincs_c10::params::N].copy_from_slice(key.pk_seed());
    pubkey_bytes[sphincs_c10::params::N..].copy_from_slice(key.pk_root());

    let inputs = BundleInputs {
        manifest_bytes,
        secure_bytes: secure.bytes,
        nonsecure_bytes: nonsecure.bytes,
        measurement_txt,
        pubkey_bytes,
        release_json,
    };

    eprintln!("==> Packing {}", args.out_path.display());
    bundle::pack(&inputs, &args.out_path)?;

    // Record in the per-user signing ledger so accidental double-sign is
    // caught. Tampering with this file defeats the check but does not
    // defeat FSBL's OTP rollback floor — the ledger is convenience, not
    // security.
    record_signing(&args.out_path, args.version, &vendor_fpr)?;

    eprintln!("==> Done.");
    Ok(())
}

fn parse_build_id(hex_str: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str).context("--build-id must be hex")?;
    if bytes.len() != 32 {
        bail!(
            "--build-id must be 32 hex-encoded bytes (64 chars), got {} bytes",
            bytes.len()
        );
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn resolve_boot_counter_snap(version: u32, override_value: Option<u32>) -> Result<u32> {
    if version == 0 {
        bail!("--version must be >= 1 (0 reserved for \"no firmware yet\")");
    }
    let snap = override_value.unwrap_or(version.saturating_sub(1));
    if snap >= version {
        bail!("--boot-counter-snap ({snap}) must be < --version ({version})");
    }
    Ok(snap)
}

fn load_vendor_key(key_path: &Path) -> Result<VendorKey> {
    let blob = std::fs::read(key_path)
        .with_context(|| format!("reading {}", key_path.display()))?;
    let passphrase = keystore::prompt_passphrase("Vendor key passphrase")?;
    VendorKey::open(&blob, &passphrase)
}

fn flatten_logged(label: &str, path: &Path) -> Result<FlatImage> {
    eprintln!("==> Flattening {label} ELF    {}", path.display());
    let img = elf::flatten_elf(path)?;
    eprintln!(
        "    base {:#010x}, {} bytes, hash {}",
        img.base,
        img.bytes.len(),
        hex::encode(img.hash)
    );
    Ok(img)
}

/// Build the manifest preimage, sign it, self-verify the signature, and
/// return the finalised bytes plus the digest (the digest is reused in
/// `release.json` for traceability).
fn build_signed_manifest(
    key: &VendorKey,
    slot: u8,
    version: u32,
    secure: &FlatImage,
    nonsecure: &FlatImage,
    vendor_fpr: &[u8; 32],
    build_id: &[u8; 32],
    boot_counter_snap: u32,
) -> Result<([u8; fw_manifest::MANIFEST_SIZE], [u8; 32])> {
    let mut b = ManifestBuilder::new();
    b.init(slot)
        .fw_version(version)
        .secure_image(&secure.hash, secure.len())
        .nonsecure_image(&nonsecure.hash, nonsecure.len())
        .vendor_pubkey_fpr(vendor_fpr)
        .build_id(build_id)
        .boot_counter_snap(boot_counter_snap)
        .try_once(TRY_ONCE_COMMITTED);
    let digest = b.finalize_preimage();

    eprintln!("==> Signing manifest digest (SPHINCS+C10, ~1 s)");
    let sig = key.sign(&digest);
    b.set_signature(&sig);

    // Cheap (~5 ms) self-verify: guards against a logic bug shipping a
    // bundle that no FSBL would accept.
    let vk = sphincs_c10::VerifyingKey {
        pk_seed: *key.pk_seed(),
        pk_root: *key.pk_root(),
    };
    if !vk.verify(&digest, &sig) {
        bail!("internal: freshly-signed signature failed self-verify");
    }

    Ok((b.finalize(), digest))
}

fn slot_letter(slot: u8) -> &'static str {
    if slot == fw_manifest::SLOT_A {
        "A"
    } else {
        "B"
    }
}

fn build_measurement_txt(
    version: u32,
    slot: u8,
    secure_hash: &[u8; 32],
    nonsecure_hash: &[u8; 32],
    build_id_hex: &str,
    vendor_fpr: &[u8; 32],
) -> String {
    use sphincs_tz_bip39::{hash_to_word_indices, WORDLIST};

    let mut out = String::new();
    let _ = writeln!(
        out,
        "PQSigner firmware release v{version} (Slot {})\n",
        slot_letter(slot)
    );

    for (label, hash) in [("Secure", secure_hash), ("Nonsecure", nonsecure_hash)] {
        let _ = writeln!(out, "{label} image measurement (8 BIP-39 words):");
        for (i, &idx) in hash_to_word_indices(hash).iter().enumerate() {
            let _ = writeln!(out, "  {} {}", i + 1, WORDLIST[idx as usize]);
        }
        let _ = writeln!(out, "  SHA-256: {}\n", hex::encode(hash));
    }

    let _ = writeln!(out, "build_id:   {build_id_hex}");
    let _ = writeln!(out, "vendor fpr: {}", hex::encode(vendor_fpr));
    out
}

// Minimal, hand-formatted release.json so we don't pull in serde_json just
// for this. All embedded values are either u32, hex (validated), or a
// single 'A'/'B' letter — no JSON-escaping hazards.
fn build_release_json(
    args: &Args,
    secure: &FlatImage,
    nonsecure: &FlatImage,
    vendor_fpr: &[u8; 32],
    digest: &[u8; 32],
    boot_counter_snap: u32,
) -> String {
    format!(
        concat!(
            "{{\n",
            "  \"version\": {version},\n",
            "  \"slot\": \"{slot}\",\n",
            "  \"build_id\": \"{build_id}\",\n",
            "  \"secure_hash\": \"{secure_hash}\",\n",
            "  \"nonsecure_hash\": \"{nonsecure_hash}\",\n",
            "  \"secure_len\": {secure_len},\n",
            "  \"nonsecure_len\": {nonsecure_len},\n",
            "  \"vendor_fingerprint\": \"{vendor_fpr}\",\n",
            "  \"manifest_digest\": \"{digest}\",\n",
            "  \"boot_counter_snap\": {boot_counter_snap}\n",
            "}}\n",
        ),
        version = args.version,
        slot = slot_letter(args.slot),
        build_id = args.build_id_hex,
        secure_hash = hex::encode(secure.hash),
        nonsecure_hash = hex::encode(nonsecure.hash),
        secure_len = secure.len(),
        nonsecure_len = nonsecure.len(),
        vendor_fpr = hex::encode(vendor_fpr),
        digest = hex::encode(digest),
        boot_counter_snap = boot_counter_snap,
    )
}

fn record_signing(bundle_path: &Path, version: u32, vendor_fpr: &[u8; 32]) -> Result<()> {
    use std::io::Write;

    let Some(data_dir) = dirs_local::data_dir() else {
        eprintln!("warning: could not find XDG_DATA_HOME; skipping ledger update");
        return Ok(());
    };
    let ledger_dir = data_dir.join("fwsign");
    std::fs::create_dir_all(&ledger_dir).ok();
    let ledger = ledger_dir.join("ledger.jsonl");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let line = format!(
        "{{\"ts\":{now},\"version\":{version},\"bundle\":\"{}\",\"vendor_fpr\":\"{}\"}}\n",
        bundle_path.display(),
        hex::encode(vendor_fpr),
    );
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&ledger)
        .with_context(|| format!("opening ledger {}", ledger.display()))?;
    f.write_all(line.as_bytes())?;
    Ok(())
}

// Minimal replacement for the `dirs` crate — we don't want the
// dependency just for one path lookup.
mod dirs_local {
    pub fn data_dir() -> Option<std::path::PathBuf> {
        if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
            return Some(std::path::PathBuf::from(xdg));
        }
        if let Ok(home) = std::env::var("HOME") {
            return Some(std::path::PathBuf::from(home).join(".local/share"));
        }
        None
    }
}
