//! Boot-state page (flash page 6, 0x0C00_C000).
//!
//! Holds the try-once / committed markers that FSBL reads at power-on
//! to decide whether the last-tried slot is safe to boot again.
//!
//! Unlike the manifest, this page is written by the runtime firmware
//! (from the secure-world `CMD_FW_COMMIT` handler and by the slot
//! itself on first-successful-unlock), *not* signed. It's integrity-
//! protected by a CRC-32 + redundant copies so a torn write doesn't
//! confuse FSBL, but tampering with it only changes which slot FSBL
//! picks — every candidate slot still goes through full manifest
//! signature verification, so a tampered boot-state page cannot cause
//! the device to boot unsigned firmware.
//!
//! ## Layout
//!
//! We keep two redundant copies at offset 0 and 4 KB. Each copy is:
//!
//! ```text
//! offset  size  field
//!   0      4   magic "BSTE"
//!   4      1   active_slot        0x00 = A, 0x01 = B
//!   5      1   reserved
//!   6      2   reserved
//!   8      4   last_good_version  u32 BE — last slot that set itself
//!                                  `committed` on a clean boot
//!  12      4   crc32              CRC-32 of bytes [0..12)
//! ```
//!
//! Each copy is exactly 16 bytes = 1 QW = one atomic flash write.
//! Copy A at `0x0C00_C000`, Copy B at `0x0C00_D000`. After any write
//! we update both — a torn write leaves one copy consistent and the
//! other potentially corrupt, and FSBL picks the valid one.
//!
//! We deliberately do NOT put the try-once flag in here — that lives
//! in the manifest itself (`OFF_TRY_ONCE`) because it's per-slot. The
//! boot-state page is for slot-selection metadata that doesn't belong
//! in a per-manifest field.

use core::ptr::read_volatile;

use super::flash::{self, Slot, BOOT_STATE_ADDR, BOOT_STATE_PAGE};

const BSTATE_MAGIC: [u8; 4] = *b"BSTE";
pub const BSTATE_COPY_A_ADDR: u32 = BOOT_STATE_ADDR;
pub const BSTATE_COPY_B_ADDR: u32 = BOOT_STATE_ADDR + 0x1000;
pub const BSTATE_SIZE: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootState {
    pub active_slot: Slot,
    pub last_good_version: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootStateError {
    /// Both copies are unparseable (blank or bad CRC). FSBL should
    /// fall back to the default "Slot A, floor 0" state in that case.
    Unavailable,
    /// A flash program/erase sequence failed.
    FlashError,
}

/// Read the effective boot state. Tries copy A first; if invalid,
/// falls back to copy B. Returns `Unavailable` if neither is valid
/// (typical on a freshly-provisioned device where the page is still
/// all-0xFF).
pub fn read() -> Result<BootState, BootStateError> {
    if let Some(b) = parse_copy(BSTATE_COPY_A_ADDR) {
        return Ok(b);
    }
    if let Some(b) = parse_copy(BSTATE_COPY_B_ADDR) {
        return Ok(b);
    }
    Err(BootStateError::Unavailable)
}

fn parse_copy(addr: u32) -> Option<BootState> {
    let src = addr as *const u8;
    let mut buf = [0u8; BSTATE_SIZE];
    // SAFETY: `addr` is one of BSTATE_COPY_{A,B}_ADDR — both are 16-byte
    // regions inside the memory-mapped flash boot-state page, which is
    // always readable from the secure world. Volatile prevents the
    // compiler from caching across flash-write commits.
    for i in 0..BSTATE_SIZE {
        buf[i] = unsafe { read_volatile(src.add(i)) };
    }

    if buf[0..4] != BSTATE_MAGIC {
        return None;
    }
    let slot_byte = buf[4];
    let active_slot = match slot_byte {
        0x00 => Slot::A,
        0x01 => Slot::B,
        _ => return None,
    };
    let last_good_version = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
    let stored_crc = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
    let actual_crc = fw_manifest::crc32_ieee(&buf[..12]);
    if stored_crc != actual_crc {
        return None;
    }
    Some(BootState {
        active_slot,
        last_good_version,
    })
}

fn encode(state: &BootState) -> [u8; BSTATE_SIZE] {
    let mut buf = [0xFFu8; BSTATE_SIZE];
    buf[0..4].copy_from_slice(&BSTATE_MAGIC);
    buf[4] = match state.active_slot {
        Slot::A => 0x00,
        Slot::B => 0x01,
    };
    buf[5] = 0x00;
    buf[6] = 0x00;
    buf[7] = 0x00;
    buf[8..12].copy_from_slice(&state.last_good_version.to_be_bytes());
    let crc = fw_manifest::crc32_ieee(&buf[..12]);
    buf[12..16].copy_from_slice(&crc.to_be_bytes());
    buf
}

/// Erase the boot-state page and write the new state to both copies.
/// Used at commit-time and at first-successful-unlock after boot.
pub unsafe fn write(state: &BootState) -> Result<(), BootStateError> {
    unsafe { flash::erase_secure_page(BOOT_STATE_PAGE) }.map_err(|_| BootStateError::FlashError)?;
    let buf = encode(state);

    // Write copy A at page offset 0. Write copy B at +0x1000 (inside
    // the same 8 KB page, but far enough apart that a partial program
    // sequence can't corrupt both in a single brown-out window).
    unsafe { flash::write_quadword_verified(BSTATE_COPY_A_ADDR, &buf) }
        .map_err(|_| BootStateError::FlashError)?;
    unsafe { flash::write_quadword_verified(BSTATE_COPY_B_ADDR, &buf) }
        .map_err(|_| BootStateError::FlashError)?;
    Ok(())
}
