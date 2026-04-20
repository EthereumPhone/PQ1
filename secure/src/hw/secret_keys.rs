//! Domain-separated per-purpose subkeys derived from the device OTP
//! master key.
//!
//! This is the PQSigner parallel to Trezor's
//! `core/embed/sec/secret_keys/stm32u5/secret_keys.c`: every SE pairing
//! secret, storage salt, or authenticator key that would otherwise live
//! as a hardcoded constant or a per-provisioning random is derived on
//! demand from the per-device OTP master via a domain-labelled HMAC-
//! SHA256 expansion.
//!
//! ## Properties
//!
//! - **Deterministic per device.** Same board, same domain label →
//!   same bytes every boot. Survives firmware updates because the
//!   master lives in OTP; survives flash mass-erase because OTP does
//!   not erase.
//! - **Unique per device.** Different boards → different OTP masters
//!   → different derived bytes, so a flash dump of one device cannot
//!   decrypt another (even if the firmware is byte-identical).
//! - **Domain-separated.** HMAC's PRF security property means each
//!   label produces an independent-looking output; an attacker who
//!   learns one derived key (e.g. via an SE pairing compromise) learns
//!   nothing about the others.
//!
//! ## HKDF vs raw HMAC
//!
//! For 32-byte output a single HMAC-SHA256(master, label) call is the
//! inner loop of HKDF-Expand (counter byte = 0x01, no prev) and is
//! equivalent for our use. We avoid pulling in the `hkdf` crate to
//! keep the dep footprint narrow. For 16-byte SE050 SCP03 keys we
//! compute the full 32-byte HMAC and truncate — that's HKDF-Expand
//! with `L=16` produced by the same single-block inner call.
//!
//! ## Label hygiene
//!
//! Labels are versioned (`-v1`). Changing a label without a matching
//! on-chip rotation is a silent data-corruption bug — the SE would
//! still be paired with the old derived key. If we ever need to
//! rotate a derivation (e.g. to upgrade the underlying primitive),
//! bump the version suffix and accept a coordinated re-pairing step
//! for affected SEs as part of the migration.

use hmac::Mac;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::hw::otp::{self, OtpError};

type HmacSha256 = hmac::Hmac<Sha256>;

/// RFC 5869 HKDF-Expand with SHA-256. Writes `output.len()` derived bytes
/// into `output`. Caller supplies `prk` (pseudo-random key; here the OTP
/// master serves as a PRK directly, which is safe because the master is
/// either uniformly-random TRNG output or a clearly-tagged test constant).
///
/// Construction (per RFC 5869 §2.3):
///     T(0) = empty
///     T(i) = HMAC-SHA256(prk, T(i-1) || info || counter_byte_i)
///     OKM  = T(1) || T(2) || ... truncated to L bytes
///
/// Supports up to 255 output blocks (255 × 32 = 8160 bytes), well past
/// anything we need here.
fn hkdf_expand(prk: &[u8; 32], info: &[u8], output: &mut [u8]) {
    let n = output.len().div_ceil(32);
    debug_assert!(n <= 255, "HKDF-Expand output must be ≤ 255 × HashLen");

    let mut prev_t = [0u8; 32];
    let mut have_prev = false;

    for i in 1..=n as u8 {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(prk)
            .expect("HMAC-SHA256 accepts any key length");
        if have_prev {
            mac.update(&prev_t);
        }
        mac.update(info);
        mac.update(&[i]);
        let t_i = mac.finalize().into_bytes();
        prev_t.copy_from_slice(&t_i);
        have_prev = true;

        let start = (i as usize - 1) * 32;
        let end = core::cmp::min(start + 32, output.len());
        output[start..end].copy_from_slice(&t_i[..end - start]);
    }

    prev_t.zeroize();
}

/// Common path: pull the OTP master, run HKDF-Expand with `label` into
/// `output`, zeroize the master-key scratch on the way out.
///
/// On the first boot of a blank MCU the inner `ensure_device_master`
/// call triggers the one-time 32-TRNG-byte OTP burn. Every subsequent
/// call is a pure OTP read + HKDF-Expand.
fn derive_into(label: &[u8], output: &mut [u8]) -> Result<(), OtpError> {
    // SAFETY: `ensure_device_master` may program OTP on the very first
    // invocation of a blank MCU. Callers (SE provisioning, main's
    // boot-time warm-up) run single-threaded before SE init, so no
    // other flash op races with this write.
    let mut master = unsafe { otp::ensure_device_master()? };
    hkdf_expand(&master, label, output);
    master.zeroize();
    Ok(())
}

/// 64-byte OPTIGA Trust M Platform Binding Secret.
///
/// Consumed by `setup_pbs_no_handshake` to populate OID `E140` before
/// the PRL handshake runs. Byte-for-byte deterministic across firmware
/// rebuilds of the same device — the property that closes the update-
/// brick scenario.
///
/// Size is 64 bytes per the OPTIGA Trust M Solution Reference Manual §
/// "Platform Binding Secret" ("It shall be 64 bytes …"). Derived via
/// two-block HKDF-Expand (`T(1) || T(2)`, RFC 5869).
pub fn optiga_pairing_secret() -> Result<[u8; 64], OtpError> {
    let mut out = [0u8; 64];
    derive_into(b"pqsigner/optiga-pbs-v1", &mut out)?;
    Ok(out)
}

/// 16-byte SE050 SCP03 encryption key. Rotated per device (replaces
/// the published AN12436 default) once we wire this into the SE050
/// SCP03 channel — see work-todo #20.
pub fn se050_scp03_enc_key() -> Result<[u8; 16], OtpError> {
    let mut out = [0u8; 16];
    derive_into(b"pqsigner/se050-scp03-enc-v1", &mut out)?;
    Ok(out)
}

/// 16-byte SE050 SCP03 MAC key. Paired with `se050_scp03_enc_key`.
pub fn se050_scp03_mac_key() -> Result<[u8; 16], OtpError> {
    let mut out = [0u8; 16];
    derive_into(b"pqsigner/se050-scp03-mac-v1", &mut out)?;
    Ok(out)
}

/// 32-byte TROPIC01 pairing key. Consumed by the Tropic driver's
/// Noise_KK handshake once we wire it through — today the Tropic
/// driver uses a hardcoded pairing key; migrating to this derivation
/// is tracked alongside work-todo #20.
pub fn tropic01_pairing_key() -> Result<[u8; 32], OtpError> {
    let mut out = [0u8; 32];
    derive_into(b"pqsigner/tropic01-pair-v1", &mut out)?;
    Ok(out)
}
