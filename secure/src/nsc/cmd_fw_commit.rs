//! CMD_FW_COMMIT — finalize a staged update.
//!
//! Runs the heavyweight checks that BEGIN could only partially do:
//!
//!   1. Drain the context (or bail if there isn't one).
//!   2. Confirm `received_*_len == expected_*_len`.
//!   3. Re-hash the written images from flash and compare against the
//!      manifest's signed hashes. Any mismatch → abort.
//!   4. Display the new measurement (8 BIP-39 words) + "Confirm
//!      update?" prompt on the OLED. Wait for long-right.
//!   5. On confirm: bump OTP rollback floor, write the target
//!      manifest page with `try_once = TRIED`, update the boot-state
//!      page to point at the new slot, trigger a system reset.
//!   6. On cancel: drop the context; the inactive slot stays erased.

use fw_manifest::{ManifestRef, MANIFEST_SIZE, TRY_ONCE_TRIED};
use sphincs_tz_shared::NscStatus;

use super::state::{peek_state, FW_UPDATE};
use super::{GatewayArgs, HandlerGuard};
use crate::fw_update::{self, verify::ImageCheckError};
use crate::hw::{boot_state, flash, otp};
use crate::ui;

pub(super) unsafe fn run(_args: &GatewayArgs) -> u32 {
    let _busy = HandlerGuard::enter();

    if peek_state(|s| s.pin_verified.check_sentinel()) != crate::fi::OK_SENTINEL {
        return NscStatus::NotInitialized as u32;
    }

    // SAFETY: single-threaded dispatcher; exclusive access.
    let ctx_ref = unsafe { (*core::ptr::addr_of!(FW_UPDATE)).as_ref() };
    let Some(ctx) = ctx_ref else {
        return NscStatus::FwUpdateBadState as u32;
    };

    // Re-hash + compare.
    let manifest = ManifestRef::new(&ctx.manifest_bytes);
    match fw_update::verify::verify_images(ctx, &manifest) {
        Ok(()) => {}
        Err(ImageCheckError::LengthMismatch)
        | Err(ImageCheckError::StreamingHashMismatch) => {
            return NscStatus::FwUpdateBadChunk as u32;
        }
        Err(ImageCheckError::SecureMismatch)
        | Err(ImageCheckError::NonsecureMismatch) => {
            return NscStatus::FwUpdateBadImage as u32;
        }
    }

    // Render the measurement + confirm dialog. Implementation lives
    // in `fw_update::confirm_ui` once the user WIP in secure/src/ui/
    // lands; for now we call a simplified placeholder.
    let confirmed = fw_update::confirm_commit(ctx, &manifest);
    if !confirmed {
        // User cancelled. Drop the context; leave flash alone.
        unsafe {
            *core::ptr::addr_of_mut!(FW_UPDATE) = None;
        }
        return NscStatus::UserRejected as u32;
    }

    // -- Commit -----------------------------------------------------

    let inactive: flash::Slot = ctx.inactive.into();
    let new_version = manifest.fw_version();

    // 1. Bump OTP rollback floor. Do this BEFORE writing the new
    //    manifest so a reset between these steps still prevents an
    //    attacker from downgrading to an older signed release.
    if let Err(e) = unsafe { otp::bump_to(new_version) } {
        match e {
            otp::OtpError::OutOfBudget => return NscStatus::FwUpdateOtpExhausted as u32,
            _ => return NscStatus::FwUpdateFlashError as u32,
        }
    }

    // 2. Write the target manifest page. The try_once_flag in the
    //    signed manifest should have been COMMITTED; we re-write it
    //    as TRIED here because the slot has not yet confirmed it
    //    boots cleanly. FSBL on the next reset sees TRIED + our
    //    matching boot-state entry and can revert if the slot fails
    //    to set "committed".
    let mut manifest_copy = ctx.manifest_bytes;
    manifest_copy[fw_manifest::OFF_TRY_ONCE] = TRY_ONCE_TRIED;
    // Recompute CRC since we mutated a byte.
    let new_crc = fw_manifest::crc32_ieee(&manifest_copy[..fw_manifest::OFF_CRC32]);
    manifest_copy[fw_manifest::OFF_CRC32..].copy_from_slice(&new_crc.to_be_bytes());

    // Program the manifest as 512 consecutive QWs (8 KB / 16 B).
    let manifest_addr = flash::manifest_addr(inactive);
    for qw in 0..(MANIFEST_SIZE / 16) {
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&manifest_copy[qw * 16..qw * 16 + 16]);
        if unsafe {
            flash::write_quadword_verified((manifest_addr + (qw * 16) as u32), &buf)
        }
        .is_err()
        {
            return NscStatus::FwUpdateFlashError as u32;
        }
    }

    // 3. Update boot-state page to point at the new (tried) slot.
    let new_boot_state = boot_state::BootState {
        active_slot: inactive,
        last_good_version: new_version,
    };
    if unsafe { boot_state::write(&new_boot_state) }.is_err() {
        return NscStatus::FwUpdateFlashError as u32;
    }

    // 4. Drop the context (zeroize manifest bytes + running hashes).
    unsafe {
        *core::ptr::addr_of_mut!(FW_UPDATE) = None;
    }

    // 5. System reset. Doesn't return.
    ui::show_status("Updating...", "rebooting");
    cortex_m::peripheral::SCB::sys_reset();
}
