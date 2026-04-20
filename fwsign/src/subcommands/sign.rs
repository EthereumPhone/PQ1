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
use std::path::PathBuf;

use crate::bundle::{self, BundleInputs};
use crate::elf;
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
    // --- Parse + validate build_id ---
    let build_id_bytes = hex::decode(&args.build_id_hex).with_context(|| "--build-id must be hex")?;
    if build_id_bytes.len() != 32 {
        bail!(
            "--build-id must be 32 hex-encoded bytes (64 chars), got {} bytes",
            build_id_bytes.len()
        );
    }
    let mut build_id = [0u8; 32];
    build_id.copy_from_slice(&build_id_bytes);

    if args.version == 0 {
        bail!("--version must be >= 1 (0 reserved for \"no firmware yet\")");
    }

    let boot_counter_snap = args.boot_counter_snap.unwrap_or(args.version.saturating_sub(1));
    if boot_counter_snap >= args.version {
        bail!(
            "--boot-counter-snap ({}) must be < --version ({})",
            boot_counter_snap, args.version
        );
    }

    // --- Decrypt vendor key ---
    let blob = std::fs::read(&args.key_path)
        .with_context(|| format!("reading {}", args.key_path.display()))?;
    let passphrase = keystore::prompt_passphrase("Vendor key passphrase")?;
    let key = VendorKey::open(&blob, &passphrase)?;

    let vendor_fpr = fw_manifest::vendor_pubkey_fingerprint(key.pk_seed(), key.pk_root());
    eprintln!("==> Vendor fingerprint: {}", hex::encode(vendor_fpr));

    // --- Flatten ELFs ---
    eprintln!("==> Flattening secure ELF    {}", args.secure_elf.display());
    let secure = elf::flatten_elf(&args.secure_elf)?;
    eprintln!(
        "    base {:#010x}, {} bytes, hash {}",
        secure.base,
        secure.bytes.len(),
        hex::encode(secure.hash)
    );

    eprintln!("==> Flattening nonsecure ELF {}", args.nonsecure_elf.display());
    let nonsecure = elf::flatten_elf(&args.nonsecure_elf)?;
    eprintln!(
        "    base {:#010x}, {} bytes, hash {}",
        nonsecure.base,
        nonsecure.bytes.len(),
        hex::encode(nonsecure.hash)
    );

    // --- Assemble manifest preimage ---
    let mut b = ManifestBuilder::new();
    b.init(args.slot)
        .fw_version(args.version)
        .secure_image(&secure.hash, secure.len())
        .nonsecure_image(&nonsecure.hash, nonsecure.len())
        .vendor_pubkey_fpr(&vendor_fpr)
        .build_id(&build_id)
        .boot_counter_snap(boot_counter_snap)
        .try_once(TRY_ONCE_COMMITTED);
    let digest = b.finalize_preimage();

    // --- Sign ---
    eprintln!("==> Signing manifest digest (SPHINCS+C10, ~1 s)");
    let sig = key.sign(&digest);
    b.set_signature(&sig);

    // Sanity: immediately verify the signature we just produced against
    // the vendor pubkey. Cheap (~5 ms) and guards against a logic bug
    // in the sign path shipping a bundle that no FSBL would accept.
    let vk = sphincs_c10::VerifyingKey {
        pk_seed: *key.pk_seed(),
        pk_root: *key.pk_root(),
    };
    if !vk.verify(&digest, &sig) {
        bail!("internal: freshly-signed signature failed self-verify");
    }

    let manifest_bytes = b.finalize();
    eprintln!("==> Manifest complete: {} bytes", manifest_bytes.len());

    // --- Compose human-readable measurement ---
    use sphincs_tz_bip39::{hash_to_word_indices, WORDLIST};
    let secure_words = hash_to_word_indices(&secure.hash);
    let nonsecure_words = hash_to_word_indices(&nonsecure.hash);
    let mut measurement_txt = String::new();
    measurement_txt.push_str(&format!(
        "PQSigner firmware release v{} ({})\n\n",
        args.version,
        if args.slot == fw_manifest::SLOT_A { "Slot A" } else { "Slot B" }
    ));
    measurement_txt.push_str("Secure image measurement (8 BIP-39 words):\n");
    for (i, &idx) in secure_words.iter().enumerate() {
        measurement_txt.push_str(&format!("  {} {}\n", i + 1, WORDLIST[idx as usize]));
    }
    measurement_txt.push_str(&format!("  SHA-256: {}\n\n", hex::encode(secure.hash)));
    measurement_txt.push_str("Nonsecure image measurement (8 BIP-39 words):\n");
    for (i, &idx) in nonsecure_words.iter().enumerate() {
        measurement_txt.push_str(&format!("  {} {}\n", i + 1, WORDLIST[idx as usize]));
    }
    measurement_txt.push_str(&format!("  SHA-256: {}\n\n", hex::encode(nonsecure.hash)));
    measurement_txt.push_str(&format!("build_id:   {}\n", args.build_id_hex));
    measurement_txt.push_str(&format!(
        "vendor fpr: {}\n",
        hex::encode(vendor_fpr)
    ));

    // --- Compose release.json ---
    // Minimal, hand-formatted so we don't pull in serde_json just for this.
    let release_json = format!(
        concat!(
            "{{\n",
            "  \"version\": {},\n",
            "  \"slot\": \"{}\",\n",
            "  \"build_id\": \"{}\",\n",
            "  \"secure_hash\": \"{}\",\n",
            "  \"nonsecure_hash\": \"{}\",\n",
            "  \"secure_len\": {},\n",
            "  \"nonsecure_len\": {},\n",
            "  \"vendor_fingerprint\": \"{}\",\n",
            "  \"manifest_digest\": \"{}\",\n",
            "  \"boot_counter_snap\": {}\n",
            "}}\n",
        ),
        args.version,
        if args.slot == fw_manifest::SLOT_A { "A" } else { "B" },
        args.build_id_hex,
        hex::encode(secure.hash),
        hex::encode(nonsecure.hash),
        secure.len(),
        nonsecure.len(),
        hex::encode(vendor_fpr),
        hex::encode(digest),
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

    // Record in the per-user signing ledger so accidental double-sign
    // is caught. Tampering with this file defeats the check but does
    // not defeat FSBL's OTP rollback floor — the ledger is convenience,
    // not security.
    record_signing(&args.out_path, args.version, &vendor_fpr)?;

    eprintln!("==> Done.");
    Ok(())
}

fn record_signing(bundle_path: &std::path::Path, version: u32, vendor_fpr: &[u8; 32]) -> Result<()> {
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
