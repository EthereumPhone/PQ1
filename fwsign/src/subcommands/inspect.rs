//! `fwsign inspect` — decode a `.pqfw` bundle's manifest fields.
//!
//! No cryptographic claims — this is a debug convenience. Use `verify`
//! to actually prove the bundle is signed correctly.

use anyhow::Result;
use fw_manifest::ManifestRef;
use std::path::Path;

use crate::bundle;

pub fn run(bundle_path: &Path) -> Result<()> {
    let unpacked = bundle::unpack(bundle_path)?;
    let m = ManifestRef::new(&unpacked.manifest_bytes);

    println!("bundle      : {}", bundle_path.display());
    println!("magic       : {:?}", core::str::from_utf8(&m.magic()).unwrap_or("?"));
    println!("manifest_ver: {}", m.manifest_version());
    println!(
        "slot        : {}",
        if m.slot() == fw_manifest::SLOT_A { "A" } else { "B" }
    );
    println!("fw_version  : {}", m.fw_version());
    println!("secure_len  : {}", m.secure_len());
    println!("ns_len      : {}", m.nonsecure_len());
    println!("secure_hash : {}", hex::encode(m.secure_hash()));
    println!("ns_hash     : {}", hex::encode(m.nonsecure_hash()));
    println!("vendor_fpr  : {}", hex::encode(m.vendor_pubkey_fpr()));
    println!("build_id    : {}", hex::encode(m.build_id()));
    println!("digest      : {}", hex::encode(m.manifest_digest()));
    println!("boot_ctr_snap: {}", m.boot_counter_snap());
    println!(
        "try_once    : {:#04x} ({})",
        m.try_once_flag(),
        try_once_name(m.try_once_flag())
    );
    println!("crc32       : {:#010x}", m.crc32());

    if !unpacked.release_json.is_empty() {
        println!("\nrelease.json:");
        println!("{}", unpacked.release_json);
    }
    if !unpacked.measurement_txt.is_empty() {
        println!("\nmeasurement.txt:");
        println!("{}", unpacked.measurement_txt);
    }

    Ok(())
}

fn try_once_name(flag: u8) -> &'static str {
    match flag {
        fw_manifest::TRY_ONCE_COMMITTED => "committed",
        fw_manifest::TRY_ONCE_COMMITTING => "committing",
        fw_manifest::TRY_ONCE_TRIED => "tried",
        _ => "unknown",
    }
}
