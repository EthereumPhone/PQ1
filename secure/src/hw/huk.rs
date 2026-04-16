//! Device-bound key derivation for sealing secrets to flash.
//!
//! Produces a per-die, per-firmware wrap key suitable for encrypting
//! secrets that live in secure flash (e.g. the OPTIGA Platform Binding
//! Secret). The key is deterministic across boots — it has to be, so
//! that `load_pbs` can reproduce it — but distinct for every STM32U585
//! die and every firmware image.
//!
//! ## Properties
//!
//! * **Per-die unique.** Mixes the chip's 96-bit UID (factory-
//!   programmed at 0x0BFA_0700, read-only, distinct per silicon die).
//!   A flash dump carried to a different device does not decrypt.
//! * **Per-firmware unique.** Mixes the measured-boot SHA-256 of the
//!   secure-world firmware image. A firmware swap — including
//!   rolling back to a vulnerable version — produces a different
//!   wrap key and makes the old sealed data unreadable.
//! * **Domain-separated.** Callers pass a short static tag so
//!   multiple purposes (PBS wrap, admin-PIN wrap, future uses) all
//!   get independent keys from the same base material.
//!
//! ## Caveat vs. SAES/HUK
//!
//! This is NOT the STM32U585 Hardware Unique Key. The real HUK is
//! accessible only via the SAES peripheral and never appears in
//! firmware-readable memory. A software attacker with secure-world
//! execution can read the UID and compute the firmware hash, so they
//! can regenerate this key — which means this scheme protects
//! against "stolen flash" attacks but not "compromised running
//! firmware" attacks. Migrating to a true SAES-bound key is a follow-
//! up item once the STM32U585 SAES driver is brought up; the wire
//! format (domain tag → 32 B) stays identical so no flash format
//! migration is required.

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// STM32U585 unique device identifier: 96 bits at 0x0BFA_0700.
const UID_BASE: u32 = 0x0BFA_0700;

/// Read the 12-byte unique device ID from system memory.
fn read_uid() -> [u8; 12] {
    let mut out = [0u8; 12];
    for i in 0..3 {
        let w =
            unsafe { core::ptr::read_volatile((UID_BASE + (i * 4) as u32) as *const u32) };
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    out
}

/// Derive a 32-byte wrap key scoped to the running firmware on the
/// running die.
///
/// `domain_tag` separates purposes: pass `b"pqsigner-pbs-wrap-v1"` for
/// the OPTIGA PBS, a different tag for any other sealed secret.
pub fn derive_device_key(domain_tag: &[u8]) -> [u8; 32] {
    let uid = read_uid();
    let fw_hash = crate::measured_boot::firmware_hash();

    // Single-pass Keccak/SHA domain: SHA-256(domain || uid || fw_hash)
    // is deterministic, requires no alloc, and the output is
    // indistinguishable from random for every well-formed domain.
    let mut h = Sha256::new();
    h.update(b"pqsigner-device-key-v1");
    h.update(&(domain_tag.len() as u32).to_le_bytes());
    h.update(domain_tag);
    h.update(&uid);
    h.update(&fw_hash);
    let digest = h.finalize();

    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);

    // Wipe intermediate copies; the caller Zeroizes `key` when done.
    let mut uid_z = uid;
    uid_z.zeroize();
    let mut fw_z = fw_hash;
    fw_z.zeroize();

    key
}
