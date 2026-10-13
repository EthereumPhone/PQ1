//! Firmware glue for the die-bound PIN credentials (issue #855).
//!
//! Ties the two pure modules to the hardware:
//!
//! - [`crate::pin_credential`] derives what each secure element is shown,
//!   given a PRF. Here the PRF is `hw::secret_keys::pin_credential_prf`,
//!   keyed by the device hardware key.
//! - [`crate::pin_salt`] keeps the per-provisioning salt, given a flash
//!   region. Here the region is the page-125 log in `hw::flash`.
//!
//! The secure-element backends call this module and nothing else to turn a
//! PIN into something a chip may see. No product path hands a PIN to an
//! OPTIGA or SE050 APDU builder, and the SE050 builders cannot be handed one
//! typed in at run time (`se050::apdu::UserIdValue`). The one exception is
//! the `se050-factory-reset` bench tool, which presents ONE value the
//! operator bakes into that image at build time, to delete an object
//! written by firmware older than #912. Nothing guesses a PIN (#912).
//!
//! Every decision here (which salt, whether to derive, what a wipe does) is
//! made by a pure function in one of those two modules and is host-tested
//! there. This file only reads the hardware state and performs the writes.

use crate::pin_credential::{self, MintPolicy, PinCredentialSet, PinSalt, WalletRole, PIN_LEN};
use crate::pin_salt::{self, ProvisionSalt, SaltPolicy};

/// Why a credential set could not be produced.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PinGateError {
    /// Page 125 holds no usable salt. Either the device was never
    /// provisioned, the wallet was wiped, or it was provisioned by firmware
    /// from before this scheme. The stored credentials cannot be recomputed;
    /// the wallet has to be wiped and restored from its 24 words.
    NoSalt,
    /// Writing a new salt failed.
    SaltStore,
    /// The random draw for a new salt failed.
    Rng,
    /// A production build is not at RDP level 2, so the device key is not
    /// yet the final per-die key.
    DeviceKeyNotFinal,
    /// The device-key PRF failed or returned implausible output.
    Derive,
}

// ---------------------------------------------------------------------------
// Build policy
// ---------------------------------------------------------------------------

/// The public, fixed salt of bench builds. See [`SaltPolicy::FixedBench`]
/// for why bench builds have one. It is not a secret and gives no
/// protection; a build that uses it must never ship. Bench builds also use a
/// fixed public PRF key (`hw::secret_keys::pin_credential_bench_prf`), so on
/// a bench build the credential is a public function of the PIN alone.
#[cfg(any(feature = "e2e-test", feature = "otp-hardcoded-master-key"))]
static BENCH_FIXED_SALT: [u8; pin_credential::SALT_LEN] = *b"PQSIGNER-BENCH-PIN-SALT-NOT-SHIP";

// Both features that select the bench salt are already rejected for
// production by the `nsc/mod.rs` ship fences and the CI feature gate. This
// states the same rule next to the constant it protects.
#[cfg(all(
    feature = "mode-production",
    any(feature = "e2e-test", feature = "otp-hardcoded-master-key")
))]
compile_error!(
    "BENCH_FIXED_SALT_IN_PRODUCTION: `e2e-test` / `otp-hardcoded-master-key` select a fixed, \
     public PIN-credential salt and PRF key (#855). A production image must use a \
     per-provisioning random salt and the device-key PRF."
);

/// The salt policy of this build.
const fn salt_policy() -> SaltPolicy {
    #[cfg(any(feature = "e2e-test", feature = "otp-hardcoded-master-key"))]
    {
        SaltPolicy::FixedBench(&BENCH_FIXED_SALT)
    }
    #[cfg(not(any(feature = "e2e-test", feature = "otp-hardcoded-master-key")))]
    {
        SaltPolicy::PerProvisioning
    }
}

/// The mint policy of this build.
///
/// Evaluated with `cfg!` rather than `#[cfg]` so the production arm is
/// type-checked in every build, including the ones that can be compiled
/// today (a `mode-production` image is currently blocked by other fences).
const fn mint_policy() -> MintPolicy {
    if cfg!(any(feature = "mode-production", feature = "rdp2-self-lock")) {
        MintPolicy::RequireRdp2
    } else {
        MintPolicy::AnyLevel
    }
}

// ---------------------------------------------------------------------------
// Derivation
// ---------------------------------------------------------------------------
//
// THE RULE (#855, found twice in review). Deriving a credential for a PIN
// under the salt that is on flash is exactly one guess against whatever was
// read out of a chip while that salt was live. So a derivation under a salt
// that existed before this boot may only happen inside an attempt that
// `nsc::gated_unlock` has already charged to page 124. There are three ways
// in, and no fourth should be added without that argument being made:
//
// - `unlock_credentials`: an unlock. Callers are `WalletStore::unlock`,
//   `unlock_duress` and `duress_pad`, reached through `gated_unlock` after
//   the charge (and once, uncharged, for the auto-unlock straight after
//   provisioning, which derives under the salt minted moments earlier).
// - `load_or_create_salt` + `credentials`: a new wallet. On a shippable
//   build the salt is always minted here and any older one destroyed first,
//   so nothing derived can be compared with an earlier read-out.
// - `decoy_provisioning_credentials`: the decoy of that new wallet. Refused
//   unless a salt was minted during this boot.

/// Set once a salt has been minted in this boot; cleared when one is
/// destroyed. Single-threaded secure world, so a relaxed atomic is only a
/// way to have a `static` without `unsafe`.
static SALT_MINTED_THIS_BOOT: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Derive the credentials and half masks of `role` for `pin` under `salt`.
///
/// # Errors
/// [`PinGateError::DeviceKeyNotFinal`] in a production build below RDP-2;
/// [`PinGateError::Derive`] when the PRF fails.
pub fn credentials(
    role: WalletRole,
    salt: &PinSalt,
    pin: &[u8; PIN_LEN],
) -> Result<PinCredentialSet, PinGateError> {
    let rdp_is_level2 = matches!(
        crate::hw::flash::rdp_level(),
        crate::hw::flash::RdpLevel::L2
    );
    if !pin_credential::mint_allowed(mint_policy(), rdp_is_level2) {
        return Err(PinGateError::DeviceKeyNotFinal);
    }
    // Every non-bench build: the device-key PRF. Its root is the DHUK under
    // `saes-dhuk`, which the `nsc/mod.rs` ship fence forces for shipping
    // images; a bring-up build without `saes-dhuk` falls back to the OTP
    // device master through HKDF (per-device, but software-visible).
    #[cfg(not(any(feature = "e2e-test", feature = "otp-hardcoded-master-key")))]
    let prf = crate::hw::secret_keys::pin_credential_prf;
    // Bench builds: the fixed public PRF (see `pin_credential_bench_prf`).
    #[cfg(any(feature = "e2e-test", feature = "otp-hardcoded-master-key"))]
    let prf = crate::hw::secret_keys::pin_credential_bench_prf;
    pin_credential::derive_set(role, salt, pin, prf).map_err(|_| PinGateError::Derive)
}

/// Whether the credentials of the provisioned wallet can be recomputed at
/// all. `gated_unlock` asks this before it charges an attempt or lets any
/// command reach a chip.
///
/// False on a shippable build whose page 125 holds no valid salt: a wallet
/// that was wiped, or one provisioned by firmware from before this scheme.
/// Trying a PIN against such a wallet could only present wrong credentials
/// and burn the chips' own attempt counters.
#[must_use]
#[inline(never)]
pub fn credentials_recomputable() -> bool {
    pin_salt::credentials_recomputable(salt_policy(), &crate::hw::flash::pin_salt_load())
}

/// The salt to unlock with.
///
/// # Errors
/// [`PinGateError::NoSalt`] when the stored credentials cannot be
/// recomputed.
pub fn load_salt() -> Result<PinSalt, PinGateError> {
    pin_salt::salt_for_unlock(salt_policy(), crate::hw::flash::pin_salt_load())
        .ok_or(PinGateError::NoSalt)
}

/// Return the salt to provision under. On a shippable build that is always a
/// fresh random salt, persisted before it is returned; a salt already on
/// flash is destroyed first and never reused. `draw` supplies the random
/// bytes.
///
/// # Safety
/// May program secure flash page 125. The caller must hold exclusive access
/// to the secure flash controller (single-threaded secure world, not inside
/// an interrupt handler).
///
/// # Errors
/// [`PinGateError::Rng`] when `draw` fails or keeps returning unusable
/// bytes; [`PinGateError::SaltStore`] when the record cannot be written or
/// the log is in a state provisioning must not build on.
pub unsafe fn load_or_create_salt<R>(mut draw: R) -> Result<PinSalt, PinGateError>
where
    R: FnMut(&mut [u8; pin_credential::SALT_LEN]) -> Result<(), ()>,
{
    let decision =
        pin_salt::salt_for_provisioning(salt_policy(), crate::hw::flash::pin_salt_load());

    // A shippable build never provisions under a salt that was already on
    // flash (see `ProvisionSalt::ReplaceRandom`). Retire it in place — no
    // page erase, so the duress-mode flag the wizard has just programmed and
    // the wipe flag are untouched. If the overwrite does not take, fail: the
    // caller's failure path wipes, and the wipe has the erase fallback.
    if matches!(decision, ProvisionSalt::ReplaceRandom) {
        // SAFETY: forwarded contract — exclusive secure-flash access.
        let mut region = unsafe { crate::hw::flash::PinSaltRegion::new() };
        pin_salt::destroy_in_place(&mut region).map_err(|_| PinGateError::SaltStore)?;
    }

    let salt = match decision {
        ProvisionSalt::Use(salt) => return Ok(salt),
        ProvisionSalt::Refuse => return Err(PinGateError::SaltStore),
        ProvisionSalt::CreateFixed(salt) => salt,
        ProvisionSalt::CreateRandom | ProvisionSalt::ReplaceRandom => {
            // A draw whose half happens to read as erased or destroyed
            // flash is rejected by `PinSalt::new`. With a working generator
            // that has probability 2^-126 per draw; the retry bound only
            // stops a stuck one.
            let mut fresh = None;
            for _ in 0..3 {
                let mut bytes = [0u8; pin_credential::SALT_LEN];
                if draw(&mut bytes).is_err() {
                    use zeroize::Zeroize;
                    bytes.zeroize();
                    return Err(PinGateError::Rng);
                }
                if let Some(salt) = PinSalt::new(bytes) {
                    fresh = Some(salt);
                    break;
                }
            }
            fresh.ok_or(PinGateError::Rng)?
        }
    };

    // SAFETY: forwarded contract — exclusive secure-flash access.
    let mut region = unsafe { crate::hw::flash::PinSaltRegion::new() };
    pin_salt::create(&mut region, &salt).map_err(|_| PinGateError::SaltStore)?;
    SALT_MINTED_THIS_BOOT.store(true, core::sync::atomic::Ordering::Relaxed);
    Ok(salt)
}

/// Credentials for the decoy wallet that is provisioned straight after the
/// real one, under the same (new) salt.
///
/// Refused unless a salt was minted during this boot: a decoy is never
/// provisioned on its own, so a call without a fresh salt would be a
/// derivation under a salt an attacker may already hold credentials for,
/// with no attempt charged. (Bench builds, whose salt is fixed, skip the
/// check so the e2e flows can re-provision a decoy without a wipe.)
///
/// # Errors
/// [`PinGateError::NoSalt`] when no salt was minted in this boot or none is
/// on flash; otherwise as [`credentials`].
pub fn decoy_provisioning_credentials(
    duress_pin: &[u8; PIN_LEN],
) -> Result<PinCredentialSet, PinGateError> {
    let minted = SALT_MINTED_THIS_BOOT.load(core::sync::atomic::Ordering::Relaxed);
    if !pin_salt::decoy_provisioning_allowed(salt_policy(), minted) {
        return Err(PinGateError::NoSalt);
    }
    let salt = load_salt()?;
    credentials(WalletRole::Duress, &salt, duress_pin)
}

/// Salt bytes for a store that drives ONE secure element.
///
/// The product store is `DualSecureElement`, which draws the salt from the
/// strict three-source generator (`rng_strong::fill_with_store`). A
/// single-chip store cannot use it: that generator requires both chips.
/// Single-chip builds are bench-only, so here the salt comes from the
/// platform TRNG alone, which fails loudly. A shipping build refuses
/// instead of minting a one-source salt; "shipping" is decided by
/// [`mint_policy`], the same predicate as the RDP-2 mint rule, so the two
/// cannot disagree. This is the only direct platform-RNG call the
/// PIN-credential path makes; it is on the `scripts/rng_consumer_audit.py`
/// allowlist with this fence.
fn single_chip_salt_draw(out: &mut [u8; pin_credential::SALT_LEN]) -> Result<(), ()> {
    if matches!(mint_policy(), MintPolicy::RequireRdp2) {
        return Err(());
    }
    crate::rng::fill(out)
}

/// Credentials for a single-chip `WalletStore::provision` shim: mint the
/// salt (from the platform TRNG, see [`single_chip_salt_draw`]) and derive
/// under it.
///
/// The dual-SE product path does not use this; `DualSecureElement` calls
/// [`load_or_create_salt`] with the three-source generator and
/// [`credentials`] itself.
///
/// # Safety
/// Same contract as [`load_or_create_salt`].
///
/// # Errors
/// As [`load_or_create_salt`] and [`credentials`].
pub unsafe fn provisioning_credentials(
    role: WalletRole,
    pin: &[u8; PIN_LEN],
) -> Result<PinCredentialSet, PinGateError> {
    // SAFETY: forwarded contract.
    let salt = unsafe { load_or_create_salt(single_chip_salt_draw) }?;
    credentials(role, &salt, pin)
}

/// Credentials for an unlock: the salt must already exist.
///
/// **Callers must be inside an attempt that `nsc::gated_unlock` has charged**
/// (see THE RULE above). The one exception is the auto-unlock straight after
/// provisioning, which derives under the salt minted in the same boot.
///
/// # Errors
/// [`PinGateError::NoSalt`] when the stored credentials cannot be
/// recomputed; otherwise as [`credentials`].
pub fn unlock_credentials(
    role: WalletRole,
    pin: &[u8; PIN_LEN],
) -> Result<PinCredentialSet, PinGateError> {
    let salt = load_salt()?;
    credentials(role, &salt, pin)
}

// ---------------------------------------------------------------------------
// Wipe
// ---------------------------------------------------------------------------

/// Destroy the salt record. Called first by every `factory_reset_admin`,
/// before any secure-element command. Idempotent.
///
/// # Safety
/// Programs (and, on the fallback path, erases) secure flash page 125. Same
/// exclusivity contract as [`load_or_create_salt`].
///
/// # Errors
/// `Err(())` when a valid salt record survives. The caller must then not
/// reset the page-124 attempt counter;
/// `hw::flash::pin_attempts_reset_after_wipe` enforces that independently.
pub unsafe fn destroy_salt() -> Result<(), ()> {
    SALT_MINTED_THIS_BOOT.store(false, core::sync::atomic::Ordering::Relaxed);
    // SAFETY: forwarded contract — exclusive secure-flash access.
    let mut region = unsafe { crate::hw::flash::PinSaltRegion::new() };
    pin_salt::destroy(&mut region).map_err(|_| ())
}

/// Arm the wipe-in-progress flag (if it is not armed already), then destroy
/// the salt. This is the opening step of every wipe.
///
/// Order matters: with the flag armed first, a power loss right after the
/// salt is gone still resumes the wipe at the next boot.
///
/// # Safety
/// Same contract as [`destroy_salt`].
///
/// # Errors
/// `Err(())` when the salt could not be destroyed.
pub unsafe fn begin_wipe() -> Result<(), ()> {
    if !crate::hw::flash::is_wipe_armed() {
        // Best effort: a failure to arm must not stop the salt from being
        // destroyed, which is the step that matters.
        // SAFETY: forwarded contract; single quad-word program in page 125.
        let _ = unsafe { crate::hw::flash::arm_wipe_flag() };
    }
    // SAFETY: forwarded contract.
    unsafe { destroy_salt() }
}
