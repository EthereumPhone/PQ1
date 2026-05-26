//! Narrower fuzz target — structural + CRC only. No SPHINCS verify,
//! so iteration is ~1000x faster than the full chain. Catches parser
//! bugs (manifest layout, magic, slot byte, manifest_version) and the
//! CRC routine in isolation.
//!
//! Run:
//!   cargo +nightly fuzz run fuzz_target_structural_crc

#![no_main]

use libfuzzer_sys::fuzz_target;
use fw_manifest::{ManifestRef, MANIFEST_SIZE};

fuzz_target!(|data: &[u8]| {
    let mut buf = [0u8; MANIFEST_SIZE];
    let take = data.len().min(MANIFEST_SIZE);
    buf[..take].copy_from_slice(&data[..take]);

    let m = ManifestRef::new(&buf);
    let _ = m.verify_structural();
    let _ = m.verify_crc();
});
