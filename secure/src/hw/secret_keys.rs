//! Domain-separated per-purpose subkeys derived from a hardware-bound
//! root key.
//!
//! This is the PQSigner parallel to Trezor's
//! `core/embed/sec/secret_keys/stm32u5/secret_keys.c`: every SE pairing
//! secret, storage salt, or authenticator key that would otherwise live
//! as a hardcoded constant or a per-provisioning random is derived on
//! demand from a device-bound root via a domain-labelled expansion.
//!
//! ## Root selection in the current implementation
//!
//! The root depends on both the caller and build configuration:
//!
//! 1. **OPTIGA/common path — `saes-dhuk` feature ON:** the root
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
//! 2. **SE050 path — `bhk` feature ON:** `derive_into_bhk` selects the
//!    BHK, so SE050 SCP03/admin credentials do not collapse onto the OPTIGA
//!    DHUK axis.
//! 3. **Dev / bench — `otp-hardcoded-master-key` feature ON:** the
//!    root is the 32-byte OTP-master-shaped ASCII constant, and
//!    outputs come from `HKDF-Expand-HMAC-SHA256(constant, label)`.
//!    This preserves the derivation byte-for-byte across every dev
//!    board that uses the feature — swap chips, re-flash, power
//!    cycle, and the admin UserID / SCP03 / PBS from the previous
//!    run is still usable.
//!
//! Callers use purpose-specific APIs, but those APIs do not expose root bytes.
//! In the `rdp2-self-lock` candidate this module also supplies factory
//! transport credentials and the persisted-salt final OPTIGA PBS resolver.
//! Production approval still depends on the external handoff/recovery/E140
//! and silicon gates; this module alone is not a ceremony.
//!
//! ## Properties
//!
//! - **Deterministic per device (current helpers).** Same board, same domain label →
//!   same bytes every boot.
//! - **Unique per die after the required RDP transition.** Different STM32U585 silicon →
//!   different DHUK → different derived bytes at RDP ≥ 1. (At RDP0
//!   DHUK is a shared ST-substituted constant; all dev boards
//!   produce the same derivations. See `docs/archive/work-todo-retired-2026-07-19.md §7 Tier 1`
//!   for the RDP/DHUK semantics.)
//! - **Domain-separated.** CMAC / HMAC as PRFs give independent-
//!   looking outputs per label.
//! - **Root-key-invisible.** Secure-world RCE can still
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
use zeroize::{Zeroize, Zeroizing};

use crate::hw::otp::{self, OtpError};

// `bhk` + `otp-hardcoded-master-key` is a broken feature combo: `bhk`
// routes the SE050 derivations through `cmac_bhk` (`KeySel::Bhk`), which
// requires the BHK lifecycle (`hw::bhk::load_and_lock`) to have run at
// boot — but `main.rs`'s BHK boot wiring is gated `not(otp-hardcoded-
// master-key)`, so under that combo the BHK is never loaded and the
// first `se050_admin_pin()` call fails with `KeyInvalid`. There is no
// legitimate use for it now that the bench OPTIGA is paired to its DHUK
// PBS (`make dual-se-bhk-e2e` is the real-roots config). If you ever
// need "real BHK / stable dev PBS for OPTIGA" again, the fix is to drop
// `not(feature = "otp-hardcoded-master-key")` from that boot-wiring cfg
// (the OTP-hardcoded axis governs `derive_into`/DHUK; the BHK axis is
// orthogonal) — then remove this fence.
#[cfg(all(feature = "bhk", feature = "otp-hardcoded-master-key"))]
compile_error!(
    "feature `bhk` is incompatible with `otp-hardcoded-master-key`: the BHK \
     boot-load wiring in main.rs is `not(otp-hardcoded-master-key)`-gated, so \
     BHK derivations would fail at runtime with KeyInvalid. Use `saes-dhuk` + \
     `bhk` (no hardcoded keys) — see `make dual-se-bhk-e2e`."
);

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

/// 32-byte BHK test constant used under `bhk-hardcoded-master-key`.
/// Distinctive ASCII so it can never be mistaken for a real BHK and so
/// HKDF outputs differ from the DHUK-path test constant (defense-in-
/// depth shape preserved even in dev builds). NEVER ship.
#[cfg(feature = "bhk-hardcoded-master-key")]
const BHK_TEST_CONSTANT: [u8; 32] = *b"PQSIGNER-TEST-BHK-DHUK-WRAP-v1!!";

/// Tier-2 BHK derivation entry point. Same shape as `derive_into` but
/// resolves through the BHK SAES KEYSEL instead of DHUK, providing
/// independent key material for the SE050 axis (see
/// `docs/archive/work-todo-retired-2026-07-19.md` §"Tier 2 — BHK").
///
/// Three cfg branches mirror `derive_into`:
///
/// 1. **`bhk-hardcoded-master-key` ON (dev/bench):** HKDF-Expand over
///    the compile-time `BHK_TEST_CONSTANT`. Distinct constant from the
///    OTP-master test constant so outputs differ between the two
///    paths even under dev — this preserves the "two independent key
///    sources" property for any host-side analysis.
/// 2. **`bhk` ON (current candidate hardware phase 2B+):** SP 800-108-style CMAC-based
///    counter KDF driven by `KeySel::Bhk` via `cmac_bhk`. Requires
///    silicon-side BHK provisioning + boot-load + TAMP-lock to have
///    run; otherwise output is stable-but-zero-keyed.
/// 3. **Neither feature (pre-Tier-2 default):** Falls back to
///    `derive_into` (DHUK path) so callers compile and produce stable
///    output. The output is keyed on DHUK rather than BHK, so the
///    defense-in-depth shape is degenerate until phase 2B lands —
///    this is intentional: it lets us add BHK call sites
///    incrementally without breaking pre-Tier-2 builds. Candidate hardware
///    builds enable `bhk` to flip to the real silicon path; #36 uses this as
///    the final SE050 root after the journaled transport rotation. Production
///    approval still depends on handoff/recovery and silicon evidence.
fn derive_into_bhk(label: &[u8], output: &mut [u8]) -> Result<(), OtpError> {
    #[cfg(feature = "bhk-hardcoded-master-key")]
    {
        let mut k = BHK_TEST_CONSTANT;
        hkdf_expand(&k, label, output);
        k.zeroize();
        Ok(())
    }
    #[cfg(all(not(feature = "bhk-hardcoded-master-key"), feature = "bhk"))]
    {
        derive_into_saes_bhk_kdf(label, output)
    }
    #[cfg(all(not(feature = "bhk-hardcoded-master-key"), not(feature = "bhk")))]
    {
        // Pre-Tier-2 fallback: BHK callers route through the DHUK
        // derivation. Output is keyed on DHUK, not BHK — the
        // defense-in-depth split is degenerate until `bhk` (phase 2B)
        // lands. Document this as a known regression in any caller's
        // doc.
        derive_into(label, output)
    }
}

/// SAES-BHK adaptor — parallel to `derive_into_saes_kdf` but routes
/// through `cmac_bhk` instead of `cmac_dhuk`. Only compiled when the
/// hardware `bhk` feature is on (and `bhk-hardcoded-master-key` is off).
/// Feature selection alone is not production-final pairing closure.
#[cfg(all(not(feature = "bhk-hardcoded-master-key"), feature = "bhk"))]
fn derive_into_saes_bhk_kdf(label: &[u8], output: &mut [u8]) -> Result<(), OtpError> {
    use crate::cmac::{kdf_cmac_counter_generic, KdfError};
    use crate::hw::saes::{self, KeySel};

    const MAX_LABEL: usize = 64;
    let mut info = [0u8; MAX_LABEL + 1];

    let result = kdf_cmac_counter_generic(
        label,
        &mut info,
        |block| saes::encrypt_ecb_block(KeySel::Bhk, None, block),
        output,
    );

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
/// "Platform Binding Secret" ("It shall be 64 bytes …"). `derive_into`
/// selects the configured current-helper backend: four 16-byte
/// `SAES-CMAC(DHUK, label || counter)` blocks under `saes-dhuk`, or two
/// RFC-5869 HKDF-Expand blocks in explicit dev/legacy configurations.
pub fn optiga_pairing_secret() -> Result<[u8; 64], OtpError> {
    let mut out = [0u8; 64];
    derive_into(b"pqsigner/optiga-pbs-v1", &mut out)?;
    Ok(out)
}

/// 64-byte ML-KEM-1024 keypair seed (`d‖z`, the FIPS-203 `from_seed` input)
/// for the dual-SE hybrid inner wrap. Device-bound, deterministic across
/// boots, never stored in plaintext — same DHUK / dev-OTP axis as the OPTIGA
/// PBS. See `docs/security/ml-kem-inner-wrap.md`.
pub fn mlkem_seed() -> Result<[u8; 64], OtpError> {
    let mut out = [0u8; 64];
    derive_into(b"pqsigner/mlkem-seed-v1", &mut out)?;
    Ok(out)
}

/// 32-byte hybrid HUK secret for the inner wrap's KDF
/// (`K = HMAC-SHA256(huk_secret, mlkem_ss ‖ aad ‖ tag)`). A SEPARATE label
/// from `mlkem_seed`, so the AEAD-key floor binds an independent device
/// secret — a future ML-KEM break alone can't recover a half without it.
pub fn mlkem_wrap_secret() -> Result<[u8; 32], OtpError> {
    let mut out = [0u8; 32];
    derive_into(b"pqsigner/mlkem-wrap-huk-v1", &mut out)?;
    Ok(out)
}

/// 16-byte SE050 SCP03 encryption key. Rotated per device (replaces
/// the published AN12436 default) once we wire this into the SE050
/// SCP03 channel — see work-todo #20.
///
/// **Tier-2 split:** SE050 secrets derive from `derive_into_bhk` (the
/// BHK SAES axis), so a DHUK compromise alone doesn't expose the
/// SE050 channel. With the `bhk` feature off (the current default)
/// `derive_into_bhk` falls through to `derive_into` (DHUK) — same
/// bytes as before Phase 2C; the split only takes effect once `bhk`
/// is enabled and the BHK lifecycle (`hw::bhk`) has provisioned.
///
/// Returns [`Zeroizing`] so the per-device static key auto-wipes on every
/// return path in the caller (finding F12); the buffer is derived in place, so
/// no un-wiped `[u8; 16]` (`Copy`) stack temp is left behind.
pub fn se050_scp03_enc_key() -> Result<Zeroizing<[u8; 16]>, OtpError> {
    let mut out = Zeroizing::new([0u8; 16]);
    derive_into_bhk(b"pqsigner/se050-scp03-enc-v1", &mut out[..])?;
    Ok(out)
}

/// 16-byte SE050 SCP03 MAC key. Paired with `se050_scp03_enc_key`.
/// Same BHK-axis derivation (Tier-2 split — see `se050_scp03_enc_key`).
/// [`Zeroizing`] for the same reason (finding F12).
pub fn se050_scp03_mac_key() -> Result<Zeroizing<[u8; 16]>, OtpError> {
    let mut out = Zeroizing::new([0u8; 16]);
    derive_into_bhk(b"pqsigner/se050-scp03-mac-v1", &mut out[..])?;
    Ok(out)
}

/// 16-byte SE050 SCP03 Data Encryption Key (DEK).
///
/// SCP03 always installs all three static keys (S-ENC, S-MAC, DEK) — a
/// `PUT KEY` that rotates ENC+MAC must rotate DEK too (GP 2.3 §11.8 /
/// AN12436 §5.2.3). We never *use* the DEK after rotation (it only
/// encrypts key values during a *future* `PUT KEY`), but it must still
/// be derived rather than left as a known/zero value. Same BHK-axis
/// derivation as the other two SCP03 keys + the admin PIN — see
/// `se050_scp03_enc_key` and `docs/archive/work-todo-retired-2026-07-19.md` #20 for why the SCP03
/// keys are on the BHK axis (recoverable keyset + RDP2-stable BHK ⇒ no
/// brick mode) while the OPTIGA PBS stays on DHUK (immutable E140).
/// [`Zeroizing`] so the DEK auto-wipes on every caller return path (finding
/// F12) — it carries the same secret weight as ENC/MAC even though `establish`
/// never uses it.
pub fn se050_scp03_dek_key() -> Result<Zeroizing<[u8; 16]>, OtpError> {
    let mut out = Zeroizing::new([0u8; 16]);
    derive_into_bhk(b"pqsigner/se050-scp03-dek-v1", &mut out[..])?;
    Ok(out)
}

/// 16-byte SE050 admin-wipe PIN. Backs `ADMIN_WIPE_OBJ` (the admin
/// UserID that holds `DELETE` authority on every user object via the
/// two-entry TAG_POLICY). Derived (never persisted to flash), so:
///
/// - **Stable across power cycles + reflashes + flash mass-erase.**
///   The derivation root is a silicon HUK (DHUK via SAES, or — Tier 2
///   — the BHK; or the OTP master on the legacy fallback), none of
///   which a system reset / reflash / bank mass-erase touches.
///   (Exception: the BHK itself lives in mass-erasable flash page
///   126, so a *RDP regression* loses it → SE050 needs re-pairing
///   afterward. OPTIGA's PBS, on the DHUK directly, survives that.)
///   Earlier designs stored a TRNG PIN in flash page 125 and mirrored
///   it against the on-chip admin UserID; any op that erased the
///   flash PIN while the on-chip admin survived desynchronised the
///   two — that's gone now (no `write_admin_pin` / `read_admin_pin`).
/// - **Deterministic under the dev hardcoded-key features** (`otp-
///   hardcoded-master-key` / `bhk-hardcoded-master-key`): the
///   compile-time constant substitutes for the silicon HUK, so every
///   dev board + fresh-flashed firmware combination yields the same
///   admin PIN — swap chips, reflash, power-cycle, and the admin
///   UserID from the previous run is still delete-able.
/// - **Per-die in the current hardware-root helper.** The HUK is per-die
///   (DHUK at RDP ≥ 1, or the per-board TRNG OTP master), so the derived admin
///   PIN is unique per device — a flash dump of one device cannot admin-wipe
///   another. This property alone does not approve the journaled first-boot
///   migration or its factory handoff/recovery contract.
///
/// **Tier-2 split:** routes through `derive_into_bhk` (BHK axis) — see
/// `se050_scp03_enc_key`. Inert until `bhk` is enabled (falls through
/// to the DHUK `derive_into` otherwise).
pub fn se050_admin_pin() -> Result<[u8; 16], OtpError> {
    let mut out = [0u8; 16];
    derive_into_bhk(b"pqsigner/se050-admin-pin-v1", &mut out)?;
    Ok(out)
}

// ===========================================================================
// work-todo #36 — first-boot self-provisioning key material.
//
// The factory (at RDP-0) provisions the SEs onto per-device **transport**
// keysets and burns the OTP master. On the first field boot the device
// self-locks RDP-2 and rotates those transport keysets to the FINAL secrets
// above (SE050 → BHK axis; OPTIGA PBS → DHUK + a fresh persisted TRNG salt).
//
// The transport keysets MUST be reproducible at BOTH factory-time (RDP-0) and
// post-lock (RDP-2), so they root in the **real burned OTP master** (S-world-
// readable at every RDP level) via HKDF — NOT `derive_into` (whose `saes-dhuk`
// arm changes value across the RDP-0 → RDP-1 transition) and NOT the BHK
// (mass-erased on regression, not per-die at RDP-0). Transport keys are
// public-by-assumption: at RDP-0 anyone can read the OTP master and recompute
// them — that is the whole trustless-supply-chain premise (#36).
// ===========================================================================

/// Domain tag prefix for the transport keysets (distinct from every final
/// label so a transport secret can never collide with a final one).
const TRANSPORT_PREFIX: &[u8] = b"pqsigner/transport/";

/// HKDF the transport keyset for `suffix` from the **real** OTP master. Uses
/// `read_device_master` (never `ensure_` — first boot must NOT trigger a burn;
/// the factory already burned it) so a blank master surfaces `NotBurned`
/// rather than a half-burn attempt.
fn transport_derive_into(suffix: &[u8], output: &mut [u8]) -> Result<(), OtpError> {
    // Assemble the full label `pqsigner/transport/<suffix>` on the stack.
    const MAX_LABEL: usize = 64;
    debug_assert!(TRANSPORT_PREFIX.len() + suffix.len() <= MAX_LABEL);
    let mut label = [0u8; MAX_LABEL];
    let plen = TRANSPORT_PREFIX.len();
    label[..plen].copy_from_slice(TRANSPORT_PREFIX);
    label[plen..plen + suffix.len()].copy_from_slice(suffix);
    let full = &label[..plen + suffix.len()];

    let mut master = otp::read_device_master()?;
    hkdf_expand(&master, full, output);
    master.zeroize();
    Ok(())
}

/// Transport SE050 SCP03 S-ENC (factory-installed; rotated at first boot).
pub fn transport_se050_scp03_enc() -> Result<[u8; 16], OtpError> {
    let mut out = [0u8; 16];
    transport_derive_into(b"se050-scp03-enc-v1", &mut out)?;
    Ok(out)
}
/// Transport SE050 SCP03 S-MAC.
pub fn transport_se050_scp03_mac() -> Result<[u8; 16], OtpError> {
    let mut out = [0u8; 16];
    transport_derive_into(b"se050-scp03-mac-v1", &mut out)?;
    Ok(out)
}
/// Transport SE050 SCP03 DEK (wraps the new key blocks during the first-boot
/// `PUT KEY` transport → final rotation).
pub fn transport_se050_scp03_dek() -> Result<[u8; 16], OtpError> {
    let mut out = [0u8; 16];
    transport_derive_into(b"se050-scp03-dek-v1", &mut out)?;
    Ok(out)
}
/// Transport SE050 admin PIN (the admin UserID the factory installs; re-keyed
/// to `se050_admin_pin()` at first boot).
pub fn transport_se050_admin_pin() -> Result<[u8; 16], OtpError> {
    let mut out = [0u8; 16];
    transport_derive_into(b"se050-admin-pin-v1", &mut out)?;
    Ok(out)
}
/// Transport OPTIGA PBS (E140; rotated to the salted-final PBS at first boot).
pub fn transport_optiga_pbs() -> Result<[u8; 64], OtpError> {
    let mut out = [0u8; 64];
    transport_derive_into(b"optiga-pbs-v1", &mut out)?;
    Ok(out)
}

/// Domain tag for the FINAL, salted OPTIGA PBS (distinct `-v2` from the
/// unsalted `-v1`). The salt is appended as HKDF/CMAC `info`.
const OPTIGA_PBS_V2_LABEL: &[u8] = b"pqsigner/optiga-pbs-v2";

// The salted label (`OPTIGA_PBS_V2_LABEL ‖ salt`) must fit the KDF's stack
// info buffer (`MAX_LABEL = 64` in `derive_into_saes_kdf`).
const _: () = assert!(OPTIGA_PBS_V2_LABEL.len() + 32 <= 64, "salted PBS label overflows KDF info buffer");

/// The FINAL OPTIGA PBS: `derive_into("pqsigner/optiga-pbs-v2" ‖ salt)`. The
/// salt (32 B fresh TRNG, persisted in the RDP-2-hidden page-127 journal for
/// device life) is mixed in as domain-separating info, so a transit attacker
/// who learned the deterministic DHUK ladder pre-lock cannot predict it (#36
/// forbids the bare `SAES-CMAC(DHUK, label)` ladder). Byte-for-byte
/// deterministic across boots given the same persisted salt — the property
/// that keeps `load_pbs` matching the value written to E140.
pub fn optiga_pairing_secret_salted(salt: &[u8; 32]) -> Result<[u8; 64], OtpError> {
    let mut info = [0u8; 22 + 32];
    info[..OPTIGA_PBS_V2_LABEL.len()].copy_from_slice(OPTIGA_PBS_V2_LABEL);
    info[OPTIGA_PBS_V2_LABEL.len()..].copy_from_slice(salt);
    let mut out = [0u8; 64];
    let r = derive_into(&info, &mut out);
    info.zeroize();
    r?;
    Ok(out)
}

/// The PBS the OPTIGA driver should currently pair with — the SINGLE source of
/// truth shared by `load_pbs`, `setup_pbs_no_handshake`, and
/// `pair_for_first_boot`. After the first-boot rotation completes
/// (journal `ALL_DONE`) it returns the SALTED-final PBS keyed on the persisted
/// salt; otherwise (dev/legacy, or before rotation) it returns the unsalted
/// `optiga_pairing_secret()` — byte-identical to pre-#36 behaviour.
///
/// This is the fix for the brick-class hazard where the seed wizard's
/// `store_objects` would otherwise rewrite E140 back to the unsalted value
/// after rotation, so the next boot's `load_pbs(salted)` would mismatch.
pub fn current_pbs() -> Result<[u8; 64], OtpError> {
    #[cfg(feature = "rdp2-self-lock")]
    {
        use crate::first_boot::FinalPbs;
        match crate::first_boot::final_pbs_state() {
            // Rotation completed: the salted-final PBS is the ONLY correct
            // credential for this device.
            FinalPbs::Rotated(salt) => return optiga_pairing_secret_salted(&salt),
            // Rotation completed but the salt is gone. Falling through to the
            // unsalted secret would silently select a DIFFERENT credential
            // than the one E140 holds — exactly the failure this branch exists
            // to prevent. Report the damage instead.
            FinalPbs::RotatedSaltMissing => return Err(OtpError::FinalPbsSaltMissing),
            // Not rotated yet: the unsalted value below is correct, and is
            // byte-identical to pre-#36 behaviour.
            FinalPbs::PreRotation => {}
        }
    }
    optiga_pairing_secret()
}
