//! Device-bound key derivation for sealing secrets to flash.
//!
//! Produces a per-die, per-device-provisioning wrap key suitable for
//! encrypting data that lives in secure flash. The key is
//! deterministic across boots — required for any "seal at write time,
//! unseal at read time" flow — but distinct for every STM32U585 die
//! and every physically-provisioned board.
//!
//! ## Properties
//!
//! * **Per-die unique.** Mixes the chip's 96-bit UID (factory-
//!   programmed at 0x0BFA_0700, read-only, distinct per silicon die).
//!   A flash dump carried to a different device does not decrypt.
//! * **Per-device unique beyond UID.** Also mixes the 32-byte OTP
//!   master key (`hw::otp::read_device_master`) — self-burned on
//!   first boot from the STM32 TRNG. Adds a second independent layer
//!   of per-device uniqueness beyond the UID, so an adversary who
//!   could somehow reuse or predict a UID would still need the OTP
//!   master bytes for that specific board.
//! * **Survives firmware updates.** Both UID and OTP master are
//!   immutable silicon state; neither changes across firmware
//!   revisions. Secrets sealed under this key remain decryptable
//!   through any legitimate reflash — the property that closed the
//!   OPTIGA brick scenario (`docs/optiga-brick-postmortem.md`).
//! * **Domain-separated.** Callers pass a short static tag so
//!   multiple purposes (e.g. future at-rest sealing of companion
//!   objects) all get independent keys from the same base material.
//!
//! ## Relationship to `hw::secret_keys`
//!
//! `hw::secret_keys` provides the canonical per-purpose subkey API
//! (OPTIGA PBS, SE050 SCP03, TROPIC01 pairing). That layer is what
//! the SE drivers actually call. `huk::derive_device_key` is the
//! lower-level helper for the hypothetical case where we need to
//! seal arbitrary MCU-side flash data bound to the device — for
//! example, an at-rest wrap of a cached companion object. New code
//! should prefer adding a labeled helper to `secret_keys.rs` over
//! calling this directly.
//!
//! ## Caveat vs. SAES/HUK
//!
//! This is NOT the STM32U585 Hardware Unique Key (DHUK). The real
//! DHUK is accessible only via the SAES peripheral and never appears
//! in firmware-readable memory. A software attacker with secure-world
//! execution can read the UID and the OTP master, so they can
//! regenerate this key. This scheme protects against:
//!
//! - "Stolen flash" / "chip transplant" attacks (UID + OTP master
//!   don't follow the flash to a different chip).
//! - "Firmware update breaks old seals" reliability bugs (both inputs
//!   are stable across rebuilds).
//!
//! It does NOT protect against "compromised running firmware" — the
//! defence for that is secure boot (work-todo #13, OEMiROT signed
//! images) + RDP level 2. A future migration to the real SAES-bound
//! DHUK (work-todo #7) will additionally prevent even S-world RCE
//! from reading the underlying key bytes; the `derive_device_key`
//! API shape (domain tag → 32 B) stays identical so callers don't
//! need to change.

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::hw::otp::{self, OtpError};

/// STM32U585 unique device identifier: 96 bits at 0x0BFA_0700.
const UID_BASE: u32 = 0x0BFA_0700;

/// Read the 12-byte unique device ID from system memory.
fn read_uid() -> [u8; 12] {
    let mut out = [0u8; 12];
    for i in 0..3 {
        // SAFETY: UID register is memory-mapped, readable from secure
        // world, and aligned to 32 bits.
        let w =
            unsafe { core::ptr::read_volatile((UID_BASE + (i * 4) as u32) as *const u32) };
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    out
}

/// Derive a 32-byte wrap key scoped to the running device.
///
/// `domain_tag` separates purposes. Pass a distinct tag per
/// independent use; tags should be versioned (`-v1`) so future
/// rotations can bump the version and migrate seals.
///
/// # Errors
///
/// Propagates `OtpError` from `ensure_device_master`. On the first
/// boot of a blank MCU this triggers the one-time 32-TRNG-byte OTP
/// master burn; every subsequent boot it is a pure OTP read.
pub fn derive_device_key(domain_tag: &[u8]) -> Result<[u8; 32], OtpError> {
    let uid = read_uid();
    // SAFETY: may program OTP on the first call of a blank MCU; same
    // flash-controller-exclusivity contract as `secret_keys`. In
    // practice `secret_keys` runs first during SE provisioning, so
    // by the time any caller lands here the burn has already
    // completed.
    let mut otp_master = unsafe { otp::ensure_device_master()? };

    let mut h = Sha256::new();
    h.update(b"pqsigner-device-key-v1");
    h.update(&(domain_tag.len() as u32).to_le_bytes());
    h.update(domain_tag);
    h.update(&uid);
    h.update(&otp_master);
    let digest = h.finalize();

    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);

    // Wipe intermediate copies; the caller Zeroizes `key` when done.
    let mut uid_z = uid;
    uid_z.zeroize();
    otp_master.zeroize();

    Ok(key)
}
