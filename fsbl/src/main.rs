//! PQSigner first-stage bootloader.
//!
//! **Production status:** this is the legacy V1 selector retained for bench
//! diagnosis. Its unary OTP floor and single-candidate try-once behavior do
//! not satisfy the required rollback contract, so production builds fail in
//! both `build.rs` and this crate. Draft 1.1 proposes replacement
//! manifest-v6/typed-marker/typed-floor interfaces but does not approve an
//! implementation, physical backend, or this selector.
//!
//! Runs at power-on from `0x0C00_0000`. Selects one of two A/B
//! firmware slots based on the manifests FSBL finds at `0x0C00_8000`
//! (slot A) and `0x0C00_A000` (slot B), verifies both the manifest
//! signature and the slot's image hash, and branches into the winning
//! slot's reset handler.
//!
//! Never returns except via the branch; panics on catastrophic failure
//! (no valid slot) and halts. The intended fail-safe in that case is
//! that the user sees no NV3007 LCD output and contacts the vendor for a
//! device replacement. The eventual production design requires a separately
//! approved RDP/WRP ceremony; this legacy bench image does not claim that
//! immutable state.
//!
//! ## Slot selection algorithm
//!
//! 1. Read both manifest pages. Run the full `ManifestRef::verify_*`
//!    chain on each (magic, CRC, digest, vendor fingerprint, C10
//!    signature, rollback floor).
//! 2. Re-hash each candidate's secure + NS images from flash and
//!    compare against the signed hashes. A mismatch means the update
//!    was torn mid-stream (the manifest hash never matches a partial
//!    write) and the candidate is rejected.
//! 3. Among surviving candidates, pick the highest `fw_version`.
//! 4. The legacy two-valid-candidate path consults `try_once_flag` and the
//!    boot-state page. This does **not** recover once the floor has excluded
//!    the old slot: the single-candidate fast path skips the check.
//! 5. Branch.
//!
//! ## Non-goals for this first cut
//!
//! * **HASH peripheral acceleration.** We use `sha2::Sha256` in
//!   software. MEASURED on pq1 at HSI16: **1.167 s** for the 385,568 B
//!   secure image and 0.023 s for the 7,488 B NS image (4.67 s / 0.09 s
//!   before the clock switch). Porting the HASH peripheral would save
//!   ~1.5 s of a boot that measured 12.932 s at the old 10 s fingerprint
//!   hold; the hold is 4 s since 2026-09-24, so the expected boot is
//!   ~6.93 s. Still 1-2 KB in a WRP-frozen range. See `crate::marker` for
//!   the full budget.
//! * **LCD error screen.** On catastrophic failure FSBL halts silently.
//! * **Reviewed probation/rollback.** The legacy `TRIED` logic is not a
//!   production safety net. Draft 1.1 proposes typed
//!   PENDING/ATTEMPTED/CONFIRMED transitions and FSBL-owned floor
//!   establishment after health finalization.

#![no_std]
#![no_main]

// Production quarantine for the rejected unary OTP rollback reader.  The
// build-script mirrors these gates so the intended error appears before key
// and linker policy; keeping a Rust-side fence prevents a custom build-script
// bypass from silently producing a shipping image.  The fence keys on a
// REACHABLE epoch-bump success path (FA-1.5, Draft 1.1 §14 L4375).
//
// CARVE-OUT (issue #541; see `fsbl/build.rs` for the full statement): the
// named §5 warning-build measurement profile links conservative reservation
// stubs that fail closed at runtime and has NO reachable epoch-bump success
// path — it is explicitly not a target of this quarantine.
#[cfg(feature = "mode-production")]
compile_error!(
    "FW_ROLLBACK_FSBL_PRODUCTION_BLOCKED: the Draft-1.1 rollback candidate is not implementation-approved or implemented"
);
#[cfg(not(any(feature = "mode-production", feature = "legacy-fw-rollback-unsafe")))]
compile_error!(
    "FW_ROLLBACK_FSBL_UNSAFE_OPT_IN_REQUIRED: bench FSBL builds must enable legacy-fw-rollback-unsafe"
);

use panic_halt as _;

use cortex_m_rt::entry;
use fw_manifest::{ManifestRef, TRY_ONCE_COMMITTED, TRY_ONCE_TRIED};

/// AW99703 backlight driver (#705). pq1 only — iota2's backlight is
/// hard-wired, so the module compiles to nothing there.
#[cfg(feature = "board-pq1")]
mod aw99703;
mod board;
mod boot_state;
mod branch;
mod clock;
mod fi;
mod glyphs;
mod manifest;
#[cfg(feature = "stage-marker")]
mod marker;
mod nv3007;
mod optbytes;
mod otp;
mod render;
mod sau;
mod slot;
mod vendor_pubkey;
mod verify;

use slot::Slot;

/// Top-level boot entry.
#[entry]
// Under `lcd-test` the boot body below is intentionally dead (the LCD self-test
// diverges first), so suppress the expected unreachable-code warning for that
// build only — the normal build stays warning-clean.
#[cfg_attr(feature = "lcd-test", allow(unreachable_code))]
fn main() -> ! {
    // Bench-only NV3007 LCD bring-up self-test (`make fsbl-lcd-test-hw`):
    // short-circuit the entire boot path into the LCD driver loop so the
    // display port is validated on real silicon WITHOUT a signed slot. Never
    // returns; the slot-verification body below is dead under this feature
    // (DCE'd) so the lcd-test image stays inside the FSBL FLASH region.
    #[cfg(feature = "lcd-test")]
    nv3007::lcd_test_loop();

    // Raise SYSCLK from the 4 MHz MSIS reset clock to HSI16 before anything
    // else. This is the first thing in the boot because it must happen before
    // any cycle-counted delay is calibrated and before the DWT timestamps
    // below, so the whole boot is measured in ONE clock domain.
    //
    // Bounded and fail-safe by construction: on failure the part stays on
    // MSIS, and `clock::achieved_hz()` reads that back from `CFGR1.SWS` so
    // `nv3007::delay_ms` scales to the real clock — a clock that does not come
    // up costs boot time rather than under-satisfying an NV3007 vendor
    // minimum. See `clock` for why 16 MHz needs no VOS or flash-latency work,
    // and why this module holds no state.
    clock::init();

    // Bench diagnostic (`stage-marker`): prove the FSBL executes at all. It
    // halts silently on rejection and has no logging, so this is the only
    // evidence available for the silent-rejection bug.
    //
    // Start the cycle counter after the clock switch so every stage below
    // carries a timestamp in the same domain. `MainEntered`'s own value
    // excludes whatever ran before this point (reset vector, `cortex_m_rt`
    // pre-main init, and the clock switch itself) — small, but it means the
    // table measures from here, not from reset.
    #[cfg(feature = "stage-marker")]
    marker::init_cycle_counter();
    #[cfg(feature = "stage-marker")]
    marker::record(marker::Stage::MainEntered, clock::achieved_hz());

    // Borrow both manifest pages directly from memory-mapped flash — NO RAM
    // copy. Copying both into stack-local `[u8; MANIFEST_SIZE]` (8 KB each)
    // buffers held 16 KB live across the multi-KB-stack SPHINCS+C10 verify and
    // peaked `main`'s frame at ~24.7 KB against a 16 KB RAM budget with no
    // MSPLIM — a silent stack overflow / HardFault of the legacy bench
    // bootloader (and therefore a required resource gate for its replacement).
    // The pages are stable, readable flash throughout boot (verify_images
    // already streams the image regions straight from flash), so borrowing
    // them costs no stack. See `manifest::at`.
    // Make the bank-2 NS alias readable by the core BEFORE any admission step
    // touches it. Without this, `verify_images` hashes ZEROS for the NS image
    // (secure access to an NS-watermarked page reads as zero with the SAU
    // disabled), every candidate is rejected, and the FSBL halts silently.
    // Measured root cause of the 2026-09-16 boot-proof failure; see sau.rs.
    sau::init();

    #[cfg(feature = "stage-marker")]
    marker::record(marker::Stage::SauConfigured, 0);

    let m_a = manifest::at(Slot::A);
    let m_b = manifest::at(Slot::B);

    let floor = otp::rollback_floor();

    #[cfg(feature = "stage-marker")]
    marker::record(marker::Stage::FloorRead, floor);

    // Check each manifest through the full verify chain. A candidate
    // is `Some(&ManifestRef)` if it passes every step.
    let valid_a = filter_valid(&m_a, floor);
    let valid_b = filter_valid(&m_b, floor);

    #[cfg(feature = "stage-marker")]
    marker::record(
        marker::Stage::SlotAAdmitted,
        valid_a.map_or(0, ManifestRef::fw_version),
    );

    // Check image hashes. A manifest can pass signature verification
    // but still fail if the actual slot contents were torn. On success
    // we also capture the secure-image digest so the FSBL can render
    // the firmware fingerprint on the LCD from the same trusted bytes
    // it just verified — without re-hashing.
    let img_ok_a = valid_a.and_then(|m| verify::verify_images(Slot::A, m).map(|d| (m, d)));
    let img_ok_b = valid_b.and_then(|m| verify::verify_images(Slot::B, m).map(|d| (m, d)));

    #[cfg(feature = "stage-marker")]
    marker::record(
        marker::Stage::SlotAImagesOk,
        u32::from(img_ok_a.is_some()),
    );

    let Some((slot, secure_digest)) = pick_slot(img_ok_a, img_ok_b) else {
        halt();
    };

    #[cfg(feature = "stage-marker")]
    marker::record(marker::Stage::SlotPicked, slot as u32);

    // tz-1 (#366; KEEP decided 2026-07-23; Draft 1.2 §3 row 2): read the option
    // bytes back before the slot branch and halt on a PERSISTENT mismatch —
    // never write one (Draft 1.2 §1 C1). Scope is the CONFIRMED subset (TZEN /
    // phase-appropriate RDP / both watermarks / secure boot address); `WRP1A`
    // and the OEM locks stay read-only-advisory while their layouts are
    // unpinned, because a fail-closed arm there would halt every genuine board.
    // Placed before the fingerprint render so a tripped board shows nothing at
    // all rather than words implying a good boot. See `optbytes` for the
    // single-fault trade-off this accepts.
    #[cfg(feature = "stage-marker")]
    marker::record(marker::Stage::Tz1Entering, 0);
    #[cfg(feature = "stage-marker")]
    {
        // Record the verdict BEFORE acting on it: a halt here is invisible
        // otherwise, and mistaking a tz-1 rejection for an LCD stall already
        // cost one wrong diagnosis.
        let ok = optbytes::persistent_confirmed_match();
        marker::record(marker::Stage::Tz1Verdict, u32::from(ok));
        if !ok {
            halt();
        }
    }
    #[cfg(not(feature = "stage-marker"))]
    if !optbytes::persistent_confirmed_match() {
        halt();
    }

    // Render the 8-BIP-39-word firmware fingerprint on the LCD before
    // branching. This is the trust root for the "subsequent updates
    // can't fake the words" property: the slot we are about to enter
    // never gets to display anything before the user has already seen
    // FSBL's verdict for THESE bytes. See `docs/security/measured-boot.md`.
    #[cfg(feature = "stage-marker")]
    marker::record(marker::Stage::RenderEntered, 0);

    // #705 RECOVERABLE FAIL-CLOSED. The verdict is a control input, not a
    // diagnostic: if any SPI transfer timed out, the words on the panel are
    // incomplete or absent, and handing off anyway would let the FIRST screen
    // the user ever sees come from the updatable firmware this stage exists to
    // check — the forged-fingerprint hole invariant #10 closes.
    //
    // Refuse instead. `halt()` is the same primitive the option-byte tripwire
    // uses, and it is `-> !`, so the type system forbids falling through to
    // `into_slot` even if this `if` were ever edited wrong.
    //
    // RECOVERABLE means exactly this: nothing here writes flash, OTP, option
    // bytes, the boot-state page or the marker page, so a transient fault
    // blocks ONE boot and a power-cycle retries from an identical state. It is
    // deliberately NOT a latch — a permanent brick from a marginal pull-up or
    // an aging part would be worse than the plain halt this policy replaced,
    // and unfixable once the RDP-2 self-lock freezes this code.
    //
    // ACCEPTED RESIDUAL, stated here because this is where it bites: the
    // signalling channel IS the thing that failed. A user facing a dark, silent
    // device cannot tell this refusal from a flat battery or a dead unit. No
    // other channel exists at this point — the RGB driver shares both the I2C
    // bus and the display connector, so it is dark in common mode with the most
    // likely failure. The policy prevents a forged fingerprint; it cannot
    // explain itself.
    let display_verdict = render::render_fingerprint(&secure_digest);
    if display_verdict != fi::OK_SENTINEL {
        #[cfg(feature = "stage-marker")]
        marker::record(marker::Stage::RenderFlushed, u32::MAX);
        halt();
    }

    // SAFETY: we verified the slot's manifest signature and image
    // hash. Branching is the last thing FSBL does; control passes to
    // the slot's reset handler.
    #[cfg(feature = "stage-marker")]
    marker::record(marker::Stage::Branching, 0);

    unsafe { branch::into_slot(slot) }
}

/// Run the full manifest verify chain. Returns Some iff all steps
/// pass. The `fpr` and `signature` checks dominate runtime: the whole chain
/// (CRC + digest + fpr + C10 signature + rollback) is **0.375 s** MEASURED on
/// pq1 at HSI16 (`stage-marker` DWT timestamps); it was 1.50 s on the 4 MHz
/// reset clock.
///
/// This comment previously said "a few ms each", then "~10 ms each" after I
/// rescaled it for the 4 MHz clock without questioning whether the original
/// was ever credible. It was not — a software SPHINCS+C10 verify at 4 MHz
/// cannot be milliseconds. Do not re-derive a figure here by scaling; measure.
///
/// F-7 defense-in-depth hardening (matches secure-world's `verify_manifest`):
/// the `verify_signature` call is wrapped in `fi::check_true_into_sentinel`,
/// which double-evaluates with a wait-random invariant loop between, sentinel-
/// commits the verdict to a volatile local, and the caller compares the
/// returned `u32` to `OK_SENTINEL` rather than handling a bare `Result`.
/// Bypassing the gate now requires ~2 coordinated faults instead of 1.
/// See `tools/sca/README.md` §F-7 for the bypass evidence this defends
/// against.
fn filter_valid<'a>(m: &'a ManifestRef<'a>, floor: u32) -> Option<&'a ManifestRef<'a>> {
    m.verify_structural().ok()?;
    m.verify_crc().ok()?;
    // F15 hardening: the digest-binding and anti-rollback verdicts run pre-PIN
    // on every boot and are the only things that give the signature meaning —
    // `verify_digest` is the sole binding of `(fw_version, secure_hash,
    // nonsecure_hash)` to the signed digest, and `verify_rollback` blocks a
    // validly-signed *downgrade*. Pre-F15 they were bare `.ok()?`
    // single-conditional rejects (one instruction-skip from falling through),
    // while only `verify_signature` was sentinel-gated. Route both through the
    // same `check_true_into_sentinel` discipline, with `scrub_sentinel_register`
    // between paired sentinel callsites to defeat the stale-r0 branch-skip.
    if fi::check_true_into_sentinel(|| m.verify_digest().is_ok()) != fi::OK_SENTINEL {
        return None;
    }
    let (vendor_pk_seed, vendor_pk_root) = vendor_pubkey::key_parts();
    let fpr_verdict = fi::check_true_into_sentinel(|| {
        m.verify_vendor_fpr(vendor_pk_seed, vendor_pk_root).is_ok()
    });
    if fpr_verdict != fi::OK_SENTINEL {
        return None;
    }
    fi::scrub_sentinel_register();
    let sig_verdict = fi::check_true_into_sentinel(|| {
        m.verify_signature(vendor_pk_seed, vendor_pk_root).is_ok()
    });
    if sig_verdict != fi::OK_SENTINEL {
        return None;
    }
    fi::scrub_sentinel_register();
    if fi::check_true_into_sentinel(|| m.verify_rollback(floor).is_ok()) != fi::OK_SENTINEL {
        return None;
    }
    Some(m)
}

/// Pick a slot using the legacy V1 selection rules.
/// Returns `None` if neither slot is valid. On success returns the
/// chosen slot AND the secure-image SHA-256 that `verify_images`
/// already computed for that slot — so the caller can drive the LCD
/// fingerprint render from the same trusted bytes without re-hashing.
///
/// `a` / `b` carry `(manifest, secure_digest)` pairs (None if that
/// slot didn't pass `verify_images`). The pick logic operates on the
/// manifest; the digest tags along untouched until we return.
type Candidate<'a> = (&'a ManifestRef<'a>, [u8; 32]);
fn pick_slot(a: Option<Candidate>, b: Option<Candidate>) -> Option<(Slot, [u8; 32])> {
    // Quick single-candidate cases.
    let (Some(a), Some(b)) = (a, b) else {
        return match (a, b) {
            (Some((_, d)), None) => Some((Slot::A, d)),
            (None, Some((_, d))) => Some((Slot::B, d)),
            _ => None,
        };
    };

    // Both valid — highest fw_version wins.
    let (winner, winner_slot, loser, loser_slot) = if a.0.fw_version() > b.0.fw_version() {
        (a, Slot::A, b, Slot::B)
    } else {
        (b, Slot::B, a, Slot::A)
    };

    let winner_flag = winner.0.try_once_flag();

    // Legacy two-candidate try-once guard. It cannot run when the old slot is
    // floor-ineligible and only the new candidate survives `filter_valid`;
    // therefore this is not the reviewed A/B rollback contract.
    //
    // Treat the TRIED + no-boot-state case as "go ahead and try" —
    // either it's the first attempt or the boot-state page is
    // unreadable. The secure firmware writes the page before FSBL
    // sees it on the next reboot.
    if winner_flag == TRY_ONCE_TRIED {
        if let Some(bs) = boot_state::read() {
            if bs.active_slot == winner_slot {
                return Some((loser_slot, loser.1));
            }
        }
    }

    // TRY_ONCE_COMMITTING is a torn-commit marker: the device was
    // interrupted mid-commit, and the signed bytes on flash don't
    // represent a finished state. Reject and fall back to the other
    // slot.
    if winner_flag != TRY_ONCE_COMMITTED && winner_flag != TRY_ONCE_TRIED {
        return Some((loser_slot, loser.1));
    }

    Some((winner_slot, winner.1))
}

/// No valid slot to boot — halt the CPU. A future iteration will
/// light an LED or render an error code to the LCD; for now we
/// simply loop.
fn halt() -> ! {
    loop {
        cortex_m::asm::wfe();
    }
}
