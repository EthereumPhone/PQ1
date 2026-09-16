//! tz-1 — FSBL-resident option-byte read-back tripwire (issue #366 row `tz-1`).
//!
//! Decided KEEP on 2026-07-23 (recorded in
//! `docs/security/fw-rollback-draft12-candidate-2026-07-21.md`, UPDATE
//! 2026-07-23 item 1) and specified by that draft's §3 row 2: the FSBL reads
//! the option bytes back before every slot branch, compares them against the
//! phase-appropriate expected profile, and halts on a PERSISTENT mismatch. The
//! asymmetry that settled it: including the check costs ~200 B of the FSBL
//! budget, while omitting it is irreversible once the FSBL freezes, because the
//! FSBL is the only code that survives a firmware update.
//!
//! **Never writes an option byte.** The FSBL has no option-byte write path and
//! must not grow one (Draft 1.2 §1 corollary C1: the only on-device option-byte
//! write permitted anywhere is the confirm-gated RDP burn in the secure world's
//! first-boot ceremony). This module only reads.
//!
//! ## What it checks, and what it cannot
//!
//! Scope is the CONFIRMED subset — `TZEN`, `RDP` for the current lifecycle
//! phase, both secure watermarks, and the secure boot address — via
//! `lockdown::verify_confirmed_fields`, so this stage and the secure world's
//! first-boot Phase A share ONE profile definition instead of two that drift.
//!
//! It deliberately does NOT act on `WRP1A` or the OEM locks. Their predicates
//! fail closed while `WRP1A_MASK_PINNED` / `OEM_LOCK_MASK_PINNED` are `false`,
//! so halting on them would brick every genuine board today (bench units carry
//! no WRP at all). Consequence, stated plainly: a unit whose WRP was cleared
//! before RDP-2 passes this tripwire. Closing issue #46's layout pin is what
//! buys that detection.
//!
//! ## Why "persistent"
//!
//! Each pass is sentinel-gated through `fi::check_true_into_sentinel`, with
//! `scrub_sentinel_register` between them (the stale-`r0` defence). A mismatch
//! halts only when BOTH passes report one, per the 2026-07-23 coordinator
//! refinement: a transient read fault must not brick a good device. The
//! trade-off that buys: a single-fault attacker who forces one pass to read
//! "match" suppresses the trip. That is accepted because this is a post-lock FI
//! tripwire, not an authorization gate — after RDP-2 the option bytes are frozen
//! in silicon, and what actually authorizes a boot is the manifest verify chain.

use core::ptr::read_volatile;

use sphincs_tz_shared::lockdown;

use crate::fi;

/// Secure alias of the FLASH controller register block (RM0456 §7.11). The FSBL
/// runs secure, and unlike `NSCR` the option registers are readable here.
const FLASH_S: u32 = 0x5002_2000;
/// Offsets confirmed against `STM32CubeProgrammer/SVD/STM32U585.svd` (the
/// on-box authority) and mirrored by `secure/src/hw/flash.rs`.
const OPTR_OFF: u32 = 0x40;
const SECBOOTADD0R_OFF: u32 = 0x4C;
const SECWM1R1_OFF: u32 = 0x50;
const SECWM2R1_OFF: u32 = 0x60;

fn reg(off: u32) -> u32 {
    // SAFETY: 4-byte-aligned read-only MMIO inside the secure FLASH register
    // block; a pure read with no side effects, single-threaded at boot.
    unsafe { read_volatile((FLASH_S + off) as *const u32) }
}

/// One independent pass: read the four registers and compare them against the
/// profile the live `RDP` byte selects.
fn confirmed_fields_match() -> bool {
    let optr = reg(OPTR_OFF);
    lockdown::verify_confirmed_fields(
        optr,
        reg(SECWM1R1_OFF),
        reg(SECWM2R1_OFF),
        reg(SECBOOTADD0R_OFF),
        lockdown::phase_profile(optr),
    )
    .is_ok()
}

/// `true` if the option bytes match the phase profile on EITHER of two
/// independent sentinel-gated passes; `false` only on a persistent mismatch.
pub fn persistent_confirmed_match() -> bool {
    let first = fi::check_true_into_sentinel(confirmed_fields_match);
    fi::scrub_sentinel_register();
    let second = fi::check_true_into_sentinel(confirmed_fields_match);
    first == fi::OK_SENTINEL || second == fi::OK_SENTINEL
}
