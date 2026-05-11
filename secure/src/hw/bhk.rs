//! Tier-2 BHK (Boot Hardware Key) lifecycle for STM32U585.
//!
//! The BHK is a second, independent SAES key axis layered on top of the
//! silicon DHUK (Tier 1). Unlike the DHUK — which is silicon-fused and
//! never touches flash — the BHK is 32 bytes of TRNG output generated
//! once at first-boot provisioning, DHUK-ECB-wrapped, and stored in a
//! dedicated bank-1 flash page. On every subsequent boot the wrapped
//! bytes are unwrapped with the DHUK into the STM32 TAMP backup
//! registers, then `TAMP_SECCFGR.BHKLOCK` is set so software can no
//! longer read those registers but the SAES peripheral still can (via
//! `KeySel::Bhk`).
//!
//! ## Why two key axes
//!
//! Defense in depth. A hypothetical compromise of the DHUK alone (SAES
//! glitch, ST errata disclosing DHUK semantics) leaves BHK-keyed
//! operations sealed — the attacker would also need to dump flash
//! *before* `BHKLOCK` completes at boot. A compromise of the BHK alone
//! (flash dump of the wrapped bytes + offline DHUK-ECB crack) does not
//! unlock DHUK-keyed derivations. See `docs/work-todo.md` §"Tier 2 —
//! BHK" for the SE-to-axis split (DHUK → OPTIGA PBS; BHK → SE050 SCP03 +
//! admin PIN, TROPIC01 pairing).
//!
//! ## Reversibility
//!
//! Nothing here is a permanent silicon commit:
//! - The wrapped-BHK flash page (bank-1 page 126, `0x0C0F_C000`) is
//!   ordinary flash — erasable.
//! - The TAMP backup registers are RAM-like (battery-backed in the
//!   backup domain, but we regenerate from flash on every boot anyway).
//! - `BHKLOCK` is cleared by hardware on a tamper event or when RDP is
//!   disabled (RM0456 §"TAMP"), and is unset again after any cold boot
//!   that re-runs `load_and_lock`.
//!
//! However: once any SE channel has been paired with a `secret_keys::*`
//! derivation that consumed *this* BHK (Tier-2 phase 2C caller
//! migration), regenerating the BHK invalidates that pairing — the same
//! brick class as a lost OPTIGA PBS. Treat the first BHK write as a
//! per-device one-way event even though the storage is erasable. The
//! firmware-update path MUST NOT touch page 126 (it lives in bank 1; the
//! update region is bank 2 only).
//!
//! ## Feature gate
//!
//! Compiled only under the `bhk` feature, which is OFF by default. When
//! OFF this module is not built and `secret_keys::derive_into_bhk` falls
//! back to the DHUK path (degenerate defense-in-depth — see that
//! function's docstring). Turning `bhk` ON in a build that has not yet
//! run `provision()` + `load_and_lock()` would produce stable-but-zero-
//! keyed derivations (BHK backup registers read as zero at reset on
//! STM32U5), defeating the security claim — so the production gate is
//! deliberately distinct from the always-on Tier-1 `saes-dhuk` gate.
//!
//! ## Register sources
//!
//! TAMP layout cross-checked against the `stm32u5-0.16.0` PAC: TAMP
//! secure-alias base `0x5600_7C00`; `SECCFGR` at offset `0x20`;
//! `BHKLOCK` = bit 30 of `SECCFGR`; `BKP0R..BKP31R` at `0x100..0x17F`
//! (we use BKP0R..BKP7R = 8 × u32 = 32 bytes). Flash helpers
//! (`erase_secure_page`, `write_quadword_verified`) come from
//! `hw::flash`.

#![cfg(feature = "bhk")]

use core::ptr::{read_volatile, write_volatile};
use zeroize::Zeroize;

use crate::hw::flash;
use crate::hw::saes::{self, KeySel, SaesError};

// ---------------------------------------------------------------------------
// Wrapped-BHK flash page — bank-1 page 126 (0x0C0F_C000), 8 KB.
// Freed by work-todo #24 (former OPTIGA-PBS seal page). Lives in bank 1
// so the bank-2-only firmware-update path can never touch it.
// ---------------------------------------------------------------------------

/// Base address of the wrapped-BHK page.
const BHK_PAGE_ADDR: u32 = 0x0C0F_C000;
/// Bank-1 page number, for `flash::erase_secure_page`.
const BHK_PAGE_NUM: u32 = 126;
/// Size of the (un)wrapped BHK in bytes.
const BHK_LEN: usize = 32;

// ---------------------------------------------------------------------------
// TAMP — secure alias.
// ---------------------------------------------------------------------------

const TAMP_S: u32 = 0x5600_7C00;
const TAMP_SECCFGR: *mut u32 = (TAMP_S + 0x20) as *mut u32;
const TAMP_BKP0R: u32 = TAMP_S + 0x100; // BKP0R; BKPnR = +4n
const TAMP_BHKLOCK: u32 = 1 << 30;

// ---------------------------------------------------------------------------
// RCC / PWR — enabling the RTC/TAMP APB clock so the TAMP BKPR are
// reachable, and clearing backup-domain write protection (PWR_DBPR.DBP)
// so they're writable. Both via the secure alias to match `hw::rcc` /
// `hw::flash` convention on STM32U5 with TZEN=1. Offsets cross-checked
// against the `stm32u5-0.16.0` PAC.
// ---------------------------------------------------------------------------

// RCC secure alias 0x5602_0C00.
const RCC_S: u32 = 0x5602_0C00;
// RCC_APB3ENR at offset 0xA8 (PAC `rcc.rs:249`); RTCAPBEN = bit 21
// (PAC `rcc/apb3enr.rs:229`) — "RTC and TAMP APB clock enable".
const RCC_APB3ENR: *mut u32 = (RCC_S + 0xA8) as *mut u32;
const RCC_APB3ENR_RTCAPBEN: u32 = 1 << 21;

// PWR secure alias 0x5602_0800. PWR_DBPR at offset 0x28 (PAC
// `pwr.rs:98-100` — "PWR disable Backup domain register"); DBP = bit 0
// (PAC `pwr/dbpr.rs:65`) — "Disable Backup domain write protection ...
// must be set to enable the write access to these registers".
const PWR_S: u32 = 0x5602_0800;
const PWR_DBPR: *mut u32 = (PWR_S + 0x28) as *mut u32;
const PWR_DBPR_DBP: u32 = 1 << 0;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from the BHK lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BhkError {
    /// `load_and_lock` was called but the flash page is blank — no BHK
    /// has been provisioned. Caller must run `provision()` first (the
    /// first-boot path).
    NotProvisioned,
    /// `provision()` was called but the flash page already holds a
    /// non-blank value. Re-provisioning would invalidate any existing
    /// SE pairing (see module docs); refused.
    AlreadyProvisioned,
    /// Flash erase or program failed (PROGERR / WRPERR / readback
    /// mismatch). The page may be partially written; caller should
    /// surface the failure and not proceed.
    Flash,
    /// A SAES ECB op failed during wrap/unwrap — usually `CcfTimeout`
    /// (peripheral wedged) or `BusError` (GTZC access denied). `saes::
    /// init()` must have run first.
    Saes(SaesError),
    /// The TRNG could not produce 32 bytes during `provision()`.
    Rng,
}

impl From<SaesError> for BhkError {
    fn from(e: SaesError) -> Self {
        BhkError::Saes(e)
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Returns `true` if the wrapped-BHK page has been provisioned (any of
/// the first `BHK_LEN` bytes is non-`0xFF`). Blank flash reads all-
/// `0xFF`; a DHUK-ECB ciphertext is statistically certain to contain
/// non-`0xFF` bytes.
#[must_use]
pub fn is_provisioned() -> bool {
    let src = BHK_PAGE_ADDR as *const u8;
    for i in 0..BHK_LEN {
        // SAFETY: BHK_PAGE_ADDR..+BHK_LEN is inside the reserved bank-1
        // page 126; reads are always safe.
        if unsafe { read_volatile(src.add(i)) } != 0xFF {
            return true;
        }
    }
    false
}

/// First-boot provisioning: generate 32 TRNG bytes, DHUK-ECB-wrap them,
/// write the wrapped bytes to the flash page. Refuses (`AlreadyProvisioned`)
/// if the page is non-blank — re-provisioning would invalidate any SE
/// channel paired against the previous BHK.
///
/// The plaintext BHK never leaves this function — it is wrapped under
/// the DHUK and zeroized before return. The wrapped bytes in flash are
/// useless without the silicon DHUK of *this* die.
///
/// # Errors
///
/// `AlreadyProvisioned` if the page is non-blank; `Rng` if the TRNG
/// stalls; `Saes` if a wrap block fails; `Flash` if the erase/program
/// fails.
///
/// # Safety
///
/// Programs a flash page — no other flash op may be in flight on this
/// core. Callers run this single-threaded at first-boot provisioning,
/// before any SE init. `saes::init()` must have run first.
pub unsafe fn provision() -> Result<(), BhkError> {
    if is_provisioned() {
        return Err(BhkError::AlreadyProvisioned);
    }

    // 32 TRNG bytes.
    let mut bhk = [0u8; BHK_LEN];
    if crate::rng::fill(&mut bhk).is_err() {
        bhk.zeroize();
        return Err(BhkError::Rng);
    }

    // DHUK-ECB wrap, block by block. ECB is unauthenticated, but the
    // confidentiality property is all we need: an attacker who reads the
    // wrapped bytes from flash still has to break AES-256 under the
    // per-die DHUK to recover the BHK.
    let mut wrapped = [0u8; BHK_LEN];
    {
        let b0: [u8; 16] = bhk[..16].try_into().expect("16-byte slice");
        let b1: [u8; 16] = bhk[16..].try_into().expect("16-byte slice");
        let c0 = saes::encrypt_ecb_block(KeySel::Dhuk, None, &b0)?;
        let c1 = saes::encrypt_ecb_block(KeySel::Dhuk, None, &b1)?;
        wrapped[..16].copy_from_slice(&c0);
        wrapped[16..].copy_from_slice(&c1);
    }
    bhk.zeroize();

    // Erase + program the flash page (2 quad-words).
    let res = (|| -> Result<(), ()> {
        flash::erase_secure_page(BHK_PAGE_NUM)?;
        let qw0: [u8; 16] = wrapped[..16].try_into().expect("16-byte slice");
        let qw1: [u8; 16] = wrapped[16..].try_into().expect("16-byte slice");
        flash::write_quadword_verified(BHK_PAGE_ADDR, &qw0)?;
        flash::write_quadword_verified(BHK_PAGE_ADDR + 16, &qw1)?;
        Ok(())
    })();
    wrapped.zeroize();
    res.map_err(|()| BhkError::Flash)
}

/// Subsequent-boot path: read the wrapped BHK from flash, DHUK-ECB-
/// unwrap it, write the 32 plaintext bytes into the TAMP backup
/// registers BKP0R..BKP7R, then set `TAMP_SECCFGR.BHKLOCK` so software
/// can no longer read those registers — only the SAES peripheral can,
/// via `KeySel::Bhk`. Must be called once at boot, before any
/// `KeySel::Bhk` operation, and after `saes::init()`.
///
/// Idempotent within a boot only in the trivial sense that once
/// `BHKLOCK` is set, a second call will fail to re-write BKPR (the lock
/// also write-protects them) — callers should invoke this exactly once.
///
/// # Errors
///
/// `NotProvisioned` if the flash page is blank (caller must `provision()`
/// first); `Saes` if an unwrap block fails.
///
/// # Safety
///
/// Touches RCC / PWR / TAMP registers. Single-threaded boot context.
/// `saes::init()` must have run first.
pub unsafe fn load_and_lock() -> Result<(), BhkError> {
    if !is_provisioned() {
        return Err(BhkError::NotProvisioned);
    }

    // Read the 32 wrapped bytes from flash.
    let mut wrapped = [0u8; BHK_LEN];
    {
        let src = BHK_PAGE_ADDR as *const u8;
        for i in 0..BHK_LEN {
            wrapped[i] = read_volatile(src.add(i));
        }
    }

    // DHUK-ECB unwrap.
    let mut bhk = [0u8; BHK_LEN];
    {
        let c0: [u8; 16] = wrapped[..16].try_into().expect("16-byte slice");
        let c1: [u8; 16] = wrapped[16..].try_into().expect("16-byte slice");
        let p0 = match saes::decrypt_ecb_block(KeySel::Dhuk, None, &c0) {
            Ok(v) => v,
            Err(e) => {
                wrapped.zeroize();
                bhk.zeroize();
                return Err(BhkError::Saes(e));
            }
        };
        let p1 = match saes::decrypt_ecb_block(KeySel::Dhuk, None, &c1) {
            Ok(v) => v,
            Err(e) => {
                wrapped.zeroize();
                bhk.zeroize();
                return Err(BhkError::Saes(e));
            }
        };
        bhk[..16].copy_from_slice(&p0);
        bhk[16..].copy_from_slice(&p1);
    }
    wrapped.zeroize();

    // --- enable the RTC/TAMP APB clock + disable backup-domain WP ---
    let apb3 = read_volatile(RCC_APB3ENR);
    write_volatile(RCC_APB3ENR, apb3 | RCC_APB3ENR_RTCAPBEN);
    let _ = read_volatile(RCC_APB3ENR); // propagation barrier
    cortex_m::asm::dsb();

    let dbpr = read_volatile(PWR_DBPR);
    write_volatile(PWR_DBPR, dbpr | PWR_DBPR_DBP);
    // Bounded poll for DBP to settle — don't hang the boot if the
    // register doesn't behave as expected.
    {
        let mut t: u32 = 1_000_000;
        while read_volatile(PWR_DBPR) & PWR_DBPR_DBP == 0 {
            t -= 1;
            if t == 0 {
                break;
            }
        }
    }

    // --- write the 32 BHK bytes into BKP0R..BKP7R (8 × u32, LE) ---
    for i in 0..8usize {
        let w = u32::from_le_bytes([
            bhk[i * 4],
            bhk[i * 4 + 1],
            bhk[i * 4 + 2],
            bhk[i * 4 + 3],
        ]);
        write_volatile((TAMP_BKP0R + (i as u32) * 4) as *mut u32, w);
    }
    bhk.zeroize();

    // --- lock BHKLOCK: SAES can still read BKPR, software cannot ---
    let seccfgr = read_volatile(TAMP_SECCFGR);
    write_volatile(TAMP_SECCFGR, seccfgr | TAMP_BHKLOCK);
    cortex_m::asm::dsb();
    cortex_m::asm::isb();

    Ok(())
}

/// Returns `true` if `TAMP_SECCFGR.BHKLOCK` is currently set — i.e.
/// `load_and_lock` has run this boot and the BHK is sealed away from
/// software. Diagnostic only.
#[must_use]
pub fn is_locked() -> bool {
    // SAFETY: pure read of a memory-mapped register.
    unsafe { read_volatile(TAMP_SECCFGR) & TAMP_BHKLOCK != 0 }
}

// ---------------------------------------------------------------------------
// Self-test (bench bring-up only — gated behind `saes-self-test`)
// ---------------------------------------------------------------------------

/// One-shot bench self-test for the BHK lifecycle. Provisions the BHK
/// if blank, loads + locks it, then runs a wrap/unwrap consistency
/// check via `KeySel::Bhk`: encrypt a fixed block, decrypt it back,
/// verify equality, and return the first 8 ciphertext bytes as a per-
/// die BHK fingerprint (analogous to the DHUK fingerprint).
///
/// Like the DHUK self-test, the fingerprint at RDP0 is NOT per-die
/// (the DHUK that wrapped the BHK is the ST-substituted constant, so
/// the wrapped bytes — and hence the unwrapped BHK — are constant
/// across boards too). Per-die BHK uniqueness only holds at RDP ≥ 1.
///
/// # Errors
///
/// Propagates `BhkError` from `provision` / `load_and_lock`, or
/// `SaesError` from the consistency check.
#[cfg(feature = "saes-self-test")]
pub fn self_test() -> Result<[u8; 8], BhkError> {
    // SAFETY: single-threaded bench bring-up; `saes::init()` is the
    // caller's responsibility (main.rs runs it before this).
    unsafe {
        if !is_provisioned() {
            provision()?;
        }
        load_and_lock()?;
    }

    let pt: [u8; 16] = *b"PQSIGNER-BHK-v01";
    let ct = saes::encrypt_ecb_block(KeySel::Bhk, None, &pt)?;
    let pt_back = saes::decrypt_ecb_block(KeySel::Bhk, None, &ct)?;
    if pt_back != pt {
        // Reuse the SAES round-trip-failure variant — it's the closest
        // fit, and a BHK that can't round-trip is the same class of
        // problem as a DHUK that can't.
        return Err(BhkError::Saes(SaesError::SelfTestRoundTrip));
    }

    Ok([ct[0], ct[1], ct[2], ct[3], ct[4], ct[5], ct[6], ct[7]])
}
