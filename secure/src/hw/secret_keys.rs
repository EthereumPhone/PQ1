//! Domain-separated per-purpose subkeys derived from a hardware-bound
//! root key.
//!
//! This is the PQSigner parallel to Trezor's
//! `core/embed/sec/secret_keys/stm32u5/secret_keys.c`: every SE pairing
//! secret, storage salt, or authenticator key that would otherwise live
//! as a hardcoded constant or a per-provisioning random is derived on
//! demand from a device-bound root via a domain-labelled expansion.
//!
//! ## Two derivation paths
//!
//! The root depends on the build configuration:
//!
//! 1. **Production / post-Tier-1 — `saes-dhuk` feature ON:** the root
//!    is the silicon DHUK, accessed only via the SAES peripheral's
//!    `KEYSEL=001` selector. DHUK bytes never appear in CPU-visible
//!    memory. Each 16-byte output block is produced by
//!    `SAES-CMAC(DHUK, label || counter)` where `counter` is a single
//!    byte starting at 1 and incrementing per block. This is a
//!    simplified SP 800-108-style CMAC-based counter KDF (we don't
//!    emit the `0x00 || Context || L_be` suffix SP 800-108 §5.1
//!    specifies; safe here because each label is fixed-purpose and
//!    produces a single fixed-length output, so each counter value
//!    gives a domain-separated block).
//!
//! 2. **Dev / bench — `otp-hardcoded-master-key` feature ON:** the
//!    root is the 32-byte OTP-master-shaped ASCII constant, and
//!    outputs come from `HKDF-Expand-HMAC-SHA256(constant, label)`.
//!    This preserves the derivation byte-for-byte across every dev
//!    board that uses the feature — swap chips, re-flash, power
//!    cycle, and the admin UserID / SCP03 / PBS from the previous
//!    run is still usable.
//!
//! The caller API (e.g. `optiga_pairing_secret()`) is identical for
//! both paths — callers cannot tell which derivation is in use.
//!
//! ## Properties
//!
//! - **Deterministic per device.** Same board, same domain label →
//!   same bytes every boot.
//! - **Unique per die (production).** Different STM32U585 silicon →
//!   different DHUK → different derived bytes at RDP ≥ 1. (At RDP0
//!   DHUK is a shared ST-substituted constant; all dev boards
//!   produce the same derivations. See `docs/work-todo.md §7 Tier 1`
//!   for the RDP/DHUK semantics.)
//! - **Domain-separated.** CMAC / HMAC as PRFs give independent-
//!   looking outputs per label.
//! - **Root-key-invisible (production).** Secure-world RCE can still
//!   *call* SAES-CMAC(DHUK, ...) to reproduce the same outputs, but
//!   cannot dump DHUK bytes to exfiltrate or replay on a different
//!   chip or in emulation.
//!
//! ## Label hygiene
//!
//! Labels are versioned (`-v1`). The SAES-CMAC path yields DIFFERENT
//! values from the HKDF-over-constant path for the same label — that
//! is expected and handled by the Tier-1 rollout plan (re-pair SEs
//! during production provisioning). Within a single build config the
//! labels are stable; changing a label without an on-chip rotation
//! is a silent data-corruption bug — bump the version suffix.

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

/// Common path: derive `output.len()` domain-separated bytes from the
/// device root key, using `label` as the domain tag. Dispatches on the
/// compile-time feature set (see module docstring).
///
/// Under `otp-hardcoded-master-key` the root is the compile-time ASCII
/// constant and the derivation is HKDF-Expand-HMAC-SHA256 (unchanged
/// from pre-Tier-1 behaviour — byte-for-byte compatible for bench
/// boards). Otherwise the root is the silicon DHUK and the derivation
/// is `SAES-CMAC(DHUK, label || counter)` with a single-byte counter
/// starting at 1, RFC-5869-KDF-Expand-shaped.
fn derive_into(label: &[u8], output: &mut [u8]) -> Result<(), OtpError> {
    #[cfg(feature = "otp-hardcoded-master-key")]
    {
        // Dev-path: HKDF over the hardcoded master. Preserves every
        // bench board's existing derivation byte-for-byte.
        // SAFETY: `ensure_device_master` is a const-return under this
        // feature — no OTP side effects.
        let mut master = unsafe { otp::ensure_device_master()? };
        hkdf_expand(&master, label, output);
        master.zeroize();
        Ok(())
    }
    #[cfg(all(not(feature = "otp-hardcoded-master-key"), feature = "saes-dhuk"))]
    {
        derive_into_saes_kdf(label, output)
    }
    #[cfg(all(not(feature = "otp-hardcoded-master-key"), not(feature = "saes-dhuk")))]
    {
        // Legacy path: neither feature enabled. Keeps the historical
        // OTP-master + HKDF path available so existing hardware test
        // builds don't regress until they opt into `saes-dhuk`. Remove
        // this arm once every caller is building with `saes-dhuk`.
        let mut master = unsafe { otp::ensure_device_master()? };
        hkdf_expand(&master, label, output);
        master.zeroize();
        Ok(())
    }
}

/// SAES-DHUK adaptor for the generic `kdf_cmac_counter_generic` KDF.
/// All the counter/packing logic lives in `crate::cmac`; this file
/// just supplies the SAES closure and maps errors to `OtpError`.
#[cfg(all(not(feature = "otp-hardcoded-master-key"), feature = "saes-dhuk"))]
fn derive_into_saes_kdf(label: &[u8], output: &mut [u8]) -> Result<(), OtpError> {
    use crate::cmac::{kdf_cmac_counter_generic, KdfError};
    use crate::hw::saes::{self, KeySel};

    // No heap — use a stack buffer big enough for any label we
    // currently define (`pqsigner/*-v1`, ≤ 32 bytes). Bump the
    // constant if a future label exceeds this; the labels themselves
    // are known at compile time.
    const MAX_LABEL: usize = 64;
    let mut info = [0u8; MAX_LABEL + 1];

    let result = kdf_cmac_counter_generic(
        label,
        &mut info,
        |block| saes::encrypt_ecb_block(KeySel::Dhuk, None, block),
        output,
    );

    // Zeroize the info buffer — label is not secret, but the last-
    // counter variant of it was used as CMAC input.
    info.zeroize();

    match result {
        Ok(()) => Ok(()),
        Err(KdfError::LabelTooLong | KdfError::OutputTooLong) => Err(OtpError::ProgramError),
        Err(KdfError::Backend(_)) => Err(OtpError::ProgramError),
    }
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

/// 16-byte SE050 admin-wipe PIN. Backs `ADMIN_WIPE_OBJ` (the admin
/// UserID that holds `DELETE` authority on every user object via the
/// two-entry TAG_POLICY). Being OTP-derived means:
///
/// - **Stable across power cycles.** No flash pairing — page 125's
///   admin-PIN slot becomes redundant. Previous design stored a
///   TRNG-generated PIN in page 125 and mirrored it against the
///   on-chip admin UserID; any operation that erased the flash PIN
///   while the on-chip admin survived desynchronised the two, which
///   retired OID ranges v3 (0x7B06), v4 (0x7B0C), and v5 (0x7B0E).
///   OTP is one-way and survives flash mass-erase, so the derivation
///   is the one credential the chip can always reproduce.
/// - **Deterministic under `dev-testkey`.** The `otp-hardcoded-master-
///   key` feature (which `dev-testkey` pulls in) substitutes the
///   32-byte ASCII test master for the real OTP read, so every dev
///   board + fresh-flashed firmware combination yields the same
///   admin PIN — swap chips, reflash, power-cycle, and the admin
///   UserID from the previous run is still delete-able.
/// - **Per-device in production.** Without `otp-hardcoded-master-key`
///   the OTP master is a per-board TRNG burn, so the admin PIN is
///   unique per device. A flash dump of one device cannot admin-wipe
///   another.
pub fn se050_admin_pin() -> Result<[u8; 16], OtpError> {
    let mut out = [0u8; 16];
    derive_into(b"pqsigner/se050-admin-pin-v1", &mut out)?;
    Ok(out)
}
