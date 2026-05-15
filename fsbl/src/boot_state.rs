//! Boot-state reader for the FSBL.
//!
//! Mirrors the layout in `secure/src/hw/boot_state.rs`. FSBL reads
//! only — it does not write the boot-state page. The secure firmware
//! updates the page on successful commits and on first-post-update
//! confirmations; FSBL's own tracking of "which slot was last tried"
//! is also stored here, but **written by the secure firmware during
//! commit**, not by FSBL itself. This keeps FSBL's flash-write path
//! out of the way of the runtime's own flash hardening — FSBL stays
//! as close to read-only as possible.

use core::ptr::read_volatile;

use crate::slot::Slot;

const BSTATE_COPY_A_ADDR: usize = 0x0C00_C000;
const BSTATE_COPY_B_ADDR: usize = 0x0C00_D000;
const BSTATE_SIZE: usize = 16;
const BSTATE_MAGIC: [u8; 4] = *b"BSTE";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootState {
    pub active_slot: Slot,
    pub last_good_version: u32,
}

pub fn read() -> Option<BootState> {
    // SAFETY: flash is memory-mapped.
    if let Some(b) = unsafe { parse(BSTATE_COPY_A_ADDR) } {
        return Some(b);
    }
    unsafe { parse(BSTATE_COPY_B_ADDR) }
}

unsafe fn parse(addr: usize) -> Option<BootState> {
    let src = addr as *const u8;
    let mut buf = [0u8; BSTATE_SIZE];
    for (i, byte) in buf.iter_mut().enumerate() {
        // SAFETY: caller guarantees `addr .. addr + BSTATE_SIZE` is a
        // valid mapped flash region; `i < BSTATE_SIZE` by the loop bound.
        *byte = unsafe { read_volatile(src.add(i)) };
    }
    if buf[0..4] != BSTATE_MAGIC {
        return None;
    }
    let active_slot = match buf[4] {
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
