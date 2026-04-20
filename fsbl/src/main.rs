//! PQSigner first-stage bootloader.
//!
//! Runs at power-on from `0x0C00_0000`. Selects one of two A/B
//! firmware slots based on the manifests FSBL finds at `0x0C00_8000`
//! (slot A) and `0x0C00_A000` (slot B), verifies both the manifest
//! signature and the slot's image hash, and branches into the winning
//! slot's reset handler.
//!
//! Never returns except via the branch; panics on catastrophic failure
//! (no valid slot) and halts. The intended fail-safe in that case is
//! that the user sees no OLED output and contacts the vendor for a
//! device replacement. Production RDP-2 prevents SWD recovery.
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
//! 4. If the winner's `try_once_flag` is `TRIED` *and* the boot-state
//!    page says we already tried this same slot, **revert**: pick the
//!    highest-version other candidate. This catches watchdog-fired
//!    reboots mid-boot of a just-installed bad release.
//! 5. Branch.
//!
//! ## Non-goals for this first cut
//!
//! * **HASH peripheral acceleration.** We use `sha2::Sha256` in
//!   software. At 16 MHz this is ~200 ms per 512 KB image, ~400 ms
//!   total, which is an acceptable boot delay.
//! * **OLED error screen.** On catastrophic failure FSBL halts
//!   silently. A future addition can initialize I2C and render an
//!   error code to the OLED.
//! * **IWDG-backed try-once enforcement.** The `TRIED` → revert logic
//!   relies on the secure-world firmware to re-enter FSBL after a
//!   watchdog reset (which it will, since reset always branches to
//!   `SECBOOTADD0`). This first cut doesn't arm IWDG from FSBL; the
//!   slot must arm it itself. A later version will arm IWDG in FSBL
//!   so a crashed slot gets reverted even if it never reaches IWDG
//!   init.

#![no_std]
#![no_main]

use panic_halt as _;

use cortex_m_rt::entry;
use fw_manifest::{ManifestRef, TRY_ONCE_COMMITTED, TRY_ONCE_TRIED};

mod boot_state;
mod branch;
mod manifest;
mod otp;
mod slot;
mod vendor_pubkey;
mod verify;

use slot::Slot;

/// Top-level boot entry.
#[entry]
fn main() -> ! {
    // Read both manifest pages into stack-local 8 KB buffers. 16 KB
    // of our 16 KB RAM budget — we'll zero these out before branch,
    // and the slot's reset handler will re-init RAM anyway.
    let buf_a = manifest::read(Slot::A);
    let buf_b = manifest::read(Slot::B);
    let m_a = manifest::as_ref(&buf_a);
    let m_b = manifest::as_ref(&buf_b);

    let floor = otp::rollback_floor();

    // Check each manifest through the full verify chain. A candidate
    // is `Some(&ManifestRef)` if it passes every step.
    let valid_a = filter_valid(&m_a, floor);
    let valid_b = filter_valid(&m_b, floor);

    // Check image hashes. A manifest can pass signature verification
    // but still fail if the actual slot contents were torn.
    let img_ok_a = valid_a.and_then(|m| {
        if verify::verify_images(Slot::A, m) {
            Some(m)
        } else {
            None
        }
    });
    let img_ok_b = valid_b.and_then(|m| {
        if verify::verify_images(Slot::B, m) {
            Some(m)
        } else {
            None
        }
    });

    let chosen = pick_slot(img_ok_a, img_ok_b);
    let slot = match chosen {
        Some(s) => s,
        None => halt(),
    };

    // SAFETY: we verified the slot's manifest signature and image
    // hash. Branching is the last thing FSBL does; control passes to
    // the slot's reset handler.
    unsafe { branch::into_slot(slot) }
}

/// Run the full manifest verify chain. Returns Some iff all steps
/// pass. The `fpr` and `signature` checks dominate runtime — they
/// take a few ms each at 16 MHz with software SHA-256.
fn filter_valid<'a>(m: &'a ManifestRef<'a>, floor: u32) -> Option<&'a ManifestRef<'a>> {
    m.verify_structural().ok()?;
    m.verify_crc().ok()?;
    m.verify_digest().ok()?;
    m.verify_vendor_fpr(&vendor_pubkey::VENDOR_PK_SEED, &vendor_pubkey::VENDOR_PK_ROOT)
        .ok()?;
    m.verify_signature(&vendor_pubkey::VENDOR_PK_SEED, &vendor_pubkey::VENDOR_PK_ROOT)
        .ok()?;
    m.verify_rollback(floor).ok()?;
    Some(m)
}

/// Pick the highest-version valid slot, honouring try-once semantics.
/// Returns `None` if neither slot is valid.
fn pick_slot(a: Option<&ManifestRef>, b: Option<&ManifestRef>) -> Option<Slot> {
    // Quick single-candidate cases.
    let (Some(a), Some(b)) = (a, b) else {
        return match (a, b) {
            (Some(_), None) => Some(Slot::A),
            (None, Some(_)) => Some(Slot::B),
            _ => None,
        };
    };

    // Both valid — highest fw_version wins.
    let (winner, loser, winner_slot, loser_slot) = if a.fw_version() > b.fw_version() {
        (a, b, Slot::A, Slot::B)
    } else {
        (b, a, Slot::B, Slot::A)
    };

    // Try-once guard. If the winner is in TRIED state and the boot-
    // state page says we already attempted this slot, revert to the
    // runner-up. This catches watchdog-reset loops after a committed
    // update that doesn't successfully confirm alive.
    //
    // Treat the TRIED + no-boot-state case as "go ahead and try" —
    // either it's the first attempt or the boot-state page is
    // unreadable. The secure firmware will be responsible for
    // writing the page before FSBL sees it on the next reboot.
    if winner.try_once_flag() == TRY_ONCE_TRIED {
        if let Some(bs) = boot_state::read() {
            if bs.active_slot == winner_slot {
                // Already attempted this exact slot and didn't confirm
                // alive → revert to the loser which we know is valid.
                let _ = loser; // retained for clarity
                return Some(loser_slot);
            }
        }
    }

    // TRY_ONCE_COMMITTING is a torn-commit marker: the device was
    // interrupted mid-commit, and the signed bytes on flash don't
    // represent a finished state. Reject and fall back to the other
    // slot if possible.
    if winner.try_once_flag() != TRY_ONCE_COMMITTED
        && winner.try_once_flag() != TRY_ONCE_TRIED
    {
        return Some(loser_slot);
    }

    Some(winner_slot)
}

/// No valid slot to boot — halt the CPU. A future iteration will
/// light an LED or render an error code to the OLED; for now we
/// simply loop.
fn halt() -> ! {
    loop {
        cortex_m::asm::wfe();
    }
}
