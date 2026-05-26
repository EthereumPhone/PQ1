//! Full verify-chain fuzz target — the highest-value target.
//!
//! Feeds attacker-controlled bytes into `ManifestRef::new` and runs the
//! complete verify chain (structural -> CRC -> digest -> vendor_fpr ->
//! signature -> rollback). The vendor key is the fixed DEV seed (same
//! one `fsbl/build.rs` falls back to), so the fuzzer drives manifest
//! bytes, not keys.
//!
//! Anything that panics, OOB-reads, integer-overflows, or fails an
//! `unsafe` invariant on any 8 KB input is a bug.
//!
//! Run:
//!   cargo +nightly fuzz run fuzz_target_verify_manifest
//! or:
//!   make fuzz-manifest

#![no_main]

use libfuzzer_sys::fuzz_target;
use fw_manifest::{ManifestRef, MANIFEST_SIZE};
use sphincs_c10::SigningKey;

/// Dev signing seed — MUST stay byte-identical to:
///   * `fsbl/build.rs` (the FSBL dev-fallback path)
///   * `fwsign/src/subcommands/dev_pubkey.rs`
///   * `fwsign/tests/sign_verify_roundtrip.rs`
///   * `secure/src/fw_rollback_e2e.rs`
const DEV_SK: [u8; 32] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
];
const DEV_PS: [u8; 16] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
];

fuzz_target!(|data: &[u8]| {
    // We require a full 8 KB so the fuzzer drives the whole manifest layout.
    // (Shorter inputs would always fail `verify_structural` on the magic
    // bytes, wasting CPU.) Pad with zeros if the input is shorter so
    // mutations still drive interesting paths.
    let mut buf = [0u8; MANIFEST_SIZE];
    let take = data.len().min(MANIFEST_SIZE);
    buf[..take].copy_from_slice(&data[..take]);

    let m = ManifestRef::new(&buf);
    let sk = SigningKey::keygen(DEV_SK, DEV_PS);

    // Each verify_* call must return cleanly on ANY input — Ok or a
    // typed Err. A panic / OOB / overflow / UB is the bug we're hunting.
    let _ = m.verify_structural();
    let _ = m.verify_crc();
    let _ = m.verify_digest();
    let _ = m.verify_vendor_fpr(sk.pk_seed(), sk.pk_root());
    let _ = m.verify_signature(sk.pk_seed(), sk.pk_root());

    // Drive the rollback floor too — host can pick any u32.
    if data.len() >= MANIFEST_SIZE + 4 {
        let floor = u32::from_le_bytes(
            data[MANIFEST_SIZE..MANIFEST_SIZE + 4].try_into().unwrap(),
        );
        let _ = m.verify_rollback(floor);
    }
});
