//! Dev-unit A/B updates (`devunit-ab`): the device half of
//! `fw_manifest::devunit`.
//!
//! **Dev units only** — pre-production DVTs handed to outside testers. Not the
//! production rollback design (Draft 1.1 stays unapproved); `nsc/mod.rs` and
//! the build scripts refuse this feature together with `mode-production`.
//!
//! What it adds to the legacy update handlers:
//!
//! * **Anti-downgrade without OTP.** A release must be strictly newer than the
//!   running one ([`rollback_floor`]); the FSBL boots the higher valid version.
//! * **A COMMIT that activates.** [`commit`] checks the streamed images are
//!   linked for the inactive slot, restarts the boot log with a confirmation
//!   of the running slot, writes the new manifest as `TRIED`, re-verifies it
//!   from flash, locks the wallet and schedules a reset into the FSBL.
//! * **Probation.** [`note_boot_attempt`] (early in every boot) and
//!   [`confirm_running`] (once the wallet unlocks) keep the boot log the FSBL
//!   reads: an unconfirmed new release gets three boots, then the FSBL falls
//!   back to the previous slot.

use core::ptr::read_volatile;
use core::sync::atomic::{AtomicU32, Ordering};

use fw_manifest::devunit::{self as layout, Tally, KIND_ATTEMPT, KIND_CONFIRM, RECORD_LEN};
use fw_manifest::{ManifestRef, MANIFEST_SIZE, TRY_ONCE_TRIED};
use sphincs_tz_shared::NscStatus;

use crate::hw::flash::{self, Slot};

/// The slot this image was linked for (`PQSIGNER_SECURE_SLOT` at build time).
/// It cannot diverge from the slot the FSBL booted: the FSBL refuses an image
/// whose vector table points outside its own slot.
#[cfg(not(devunit_slot_b))]
pub const LINKED_SLOT: Slot = Slot::A;
#[cfg(devunit_slot_b)]
pub const LINKED_SLOT: Slot = Slot::B;

/// Delay between a successful COMMIT and the reset, so the non-secure world
/// can return the APDU status to the host first.
const RESET_DELAY_MS: u32 = 400;

const fn slot_id(slot: Slot) -> u8 {
    match slot {
        Slot::A => fw_manifest::SLOT_A,
        Slot::B => fw_manifest::SLOT_B,
    }
}

/// The manifest page of `slot`, straight from flash.
fn manifest_at(slot: Slot) -> ManifestRef<'static> {
    // SAFETY: `manifest_addr` is an always-mapped, 8 KiB, alignment-1 flash
    // page in secure bank 1; it is only ever reprogrammed by `commit` below
    // for the INACTIVE slot, after its erase in BEGIN.
    let bytes: &'static [u8; MANIFEST_SIZE] =
        unsafe { &*(flash::manifest_addr(slot) as *const [u8; MANIFEST_SIZE]) };
    ManifestRef::new(bytes)
}

/// The running release's manifest, if it still reads back intact. The FSBL
/// verified it (signature included) before branching here; this re-checks
/// the cheap structural/CRC/digest layer only.
fn running_manifest() -> Option<ManifestRef<'static>> {
    let m = manifest_at(LINKED_SLOT);
    (m.verify_structural().is_ok() && m.verify_crc().is_ok() && m.verify_digest().is_ok())
        .then_some(m)
}

/// Version of the running release, if its manifest reads back intact.
pub fn running_version() -> Option<u32> {
    running_manifest().map(|m| m.fw_version())
}

/// The rollback floor BEGIN and the install dialog use: a new release must be
/// strictly newer than the running one (`verify_rollback` is `version >
/// floor`). Fails closed: with no readable running manifest every release is
/// refused rather than guessed at.
pub fn rollback_floor() -> u32 {
    running_version().unwrap_or(u32::MAX)
}

fn read_record(i: usize) -> [u8; RECORD_LEN] {
    let base = layout::BOOT_LOG_ADDR as *const u8;
    let mut r = [0u8; RECORD_LEN];
    for (j, b) in r.iter_mut().enumerate() {
        // SAFETY: `i < LOG_CAPACITY` (both callers bound it), so the read is
        // inside the always-mapped 8 KiB boot-log page.
        *b = unsafe { read_volatile(base.add(i * RECORD_LEN + j)) };
    }
    r
}

fn tally(slot: u8, version: u32) -> Tally {
    let mut t = Tally::default();
    for i in 0..layout::LOG_CAPACITY {
        t.observe(&read_record(i), slot, version);
    }
    t
}

/// Append one record at the log's free frontier.
fn append(kind: u8, slot: u8, version: u32) -> Result<(), ()> {
    let i = layout::next_free(read_record).ok_or(())?;
    let rec = layout::encode_record(kind, slot, version);
    let addr = layout::BOOT_LOG_ADDR + (i * RECORD_LEN) as u32;
    // SAFETY: `next_free` returns an index whose quad-word, and every one
    // after it, reads erased; the boot log is bank-1 page 6, owned by this
    // module (it never overlaps a slot, a manifest or a per-device page).
    unsafe { flash::write_quadword_verified(addr, &rec) }
}

/// Log `kind` for the running release if it is still on probation.
fn settle(kind: u8) {
    let Some(m) = running_manifest() else { return };
    let (slot, version) = (slot_id(LINKED_SLOT), m.fw_version());
    if layout::needs_settling(m.try_once_flag(), tally(slot, version)) {
        let ok = append(kind, slot, version).is_ok();
        secure_log!("[S][devunit] boot log: kind {} for v{} ok={}", kind, version, ok);
        let _ = ok;
    }
}

/// Early in every boot: count this boot against a release that has not been
/// confirmed yet. No-op for a factory-flashed or already confirmed release.
pub fn note_boot_attempt() {
    settle(KIND_ATTEMPT);
}

/// The wallet unlocked on this release: confirm it, so the FSBL keeps
/// booting it and never falls back to the previous slot.
pub fn confirm_running() {
    settle(KIND_CONFIRM);
}

/// Both streamed images must be linked for `slot` (see
/// `fw_manifest::devunit::vectors_in_slot`): otherwise the FSBL would refuse
/// the slot, so do not stage it.
fn images_linked_for(slot: Slot, m: &ManifestRef) -> bool {
    let s = flash::slot_secure_addr(slot) as *const u32;
    let n = flash::slot_ns_addr(slot) as *const u32;
    // SAFETY: both bases are always-mapped flash; `verify_images` has just
    // re-hashed at least a vector table's worth of bytes at each.
    let (s_sp, s_reset, n_sp, n_reset) =
        unsafe { (read_volatile(s), read_volatile(s.add(1)), read_volatile(n), read_volatile(n.add(1))) };
    layout::vectors_in_slot(
        s_sp,
        s_reset,
        flash::slot_secure_addr(slot),
        m.secure_len(),
        layout::SECURE_SRAM_BASE,
        layout::SECURE_SRAM_END,
    ) && layout::vectors_in_slot(
        n_sp,
        n_reset,
        flash::slot_ns_addr(slot),
        m.nonsecure_len(),
        layout::NS_SRAM_BASE,
        layout::NS_SRAM_END,
    )
}

/// The dev-unit COMMIT tail, run after `verify_images` proved the streamed
/// bytes match the signed manifest. On `Ok` the wallet is locked and the
/// device resets into the FSBL [`RESET_DELAY_MS`] later.
///
/// # Safety
/// Programs flash. `inactive` must be the slot BEGIN erased (not the running
/// one) and `manifest_bytes` the manifest BEGIN verified and confirmed.
pub unsafe fn commit(inactive: Slot, manifest_bytes: &[u8; MANIFEST_SIZE]) -> NscStatus {
    if inactive == LINKED_SLOT {
        return NscStatus::FwUpdateBadState;
    }
    let manifest = ManifestRef::new(manifest_bytes);
    if !images_linked_for(inactive, &manifest) {
        secure_log!("[S][devunit] COMMIT: images are not linked for the inactive slot");
        return NscStatus::FwUpdateBadImage;
    }
    let Some(running) = running_version() else {
        return NscStatus::FwUpdateBadState;
    };
    let new_version = manifest.fw_version();
    if new_version <= running {
        return NscStatus::FwUpdateBadVersion;
    }

    // 1. A fresh boot log that starts by confirming the running release, so
    //    the fallback the FSBL may need is settled. A power loss from here on
    //    leaves the running slot the only (or the settled) candidate.
    // SAFETY: page 6 is the boot log, owned by this module.
    if unsafe { flash::erase_secure_page(layout::BOOT_LOG_PAGE) }.is_err()
        || append(KIND_CONFIRM, slot_id(LINKED_SLOT), running).is_err()
    {
        return NscStatus::FwUpdateFlashError;
    }

    // 2. The new manifest, marked TRIED (probation) with its CRC recomputed.
    //    BEGIN erased this page; until the last quad-word lands the CRC fails
    //    and the FSBL ignores the slot.
    let mut copy = *manifest_bytes;
    copy[fw_manifest::OFF_TRY_ONCE] = TRY_ONCE_TRIED;
    let crc = fw_manifest::crc32_ieee(&copy[..fw_manifest::OFF_CRC32]);
    copy[fw_manifest::OFF_CRC32..].copy_from_slice(&crc.to_be_bytes());
    let base = flash::manifest_addr(inactive);
    for qw in 0..(MANIFEST_SIZE / 16) {
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&copy[qw * 16..qw * 16 + 16]);
        // SAFETY: the inactive slot's manifest page, erased by BEGIN, written
        // front to back exactly once.
        if unsafe { flash::write_quadword_verified(base + (qw * 16) as u32, &buf) }.is_err() {
            return NscStatus::FwUpdateFlashError;
        }
    }

    // 3. Re-verify what is now in flash, sentinel-gated: the bytes the FSBL
    //    will read must be the manifest the user confirmed, in probation.
    crate::fi::wait_random();
    let staged = manifest_at(inactive);
    let gate = crate::fi::check_true_into_sentinel(|| {
        core::hint::black_box(staged.as_bytes()[..] == copy[..])
            && core::hint::black_box(staged.verify_structural().is_ok())
            && core::hint::black_box(staged.verify_crc().is_ok())
            && core::hint::black_box(staged.verify_digest().is_ok())
            && core::hint::black_box(staged.try_once_flag() == TRY_ONCE_TRIED)
            && core::hint::black_box(staged.verify_rollback(running).is_ok())
    });
    if gate != crate::fi::OK_SENTINEL {
        return NscStatus::FwUpdateFlashError;
    }

    // 4. Lock the wallet now; the reset follows once the status is out.
    crate::nsc::zeroize_sensitive_state();
    crate::ui::show_status("Update installed", "Restarting...");
    secure_log!("[S][devunit] COMMIT: v{} staged in the inactive slot; resetting", new_version);
    schedule_reset();
    NscStatus::Ok
}

/// Deadline (SysTick ms) of a pending post-COMMIT reset; 0 = none.
static RESET_AT: AtomicU32 = AtomicU32::new(0);

fn schedule_reset() {
    let at = crate::timeout::now().wrapping_add(RESET_DELAY_MS).max(1);
    RESET_AT.store(at, Ordering::SeqCst);
}

/// Polled from SysTick: is a post-COMMIT reset due?
pub fn reset_due() -> bool {
    let at = RESET_AT.load(Ordering::SeqCst);
    at != 0 && (crate::timeout::now().wrapping_sub(at) as i32) >= 0
}
