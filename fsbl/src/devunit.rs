//! Dev-unit A/B slot choice (`devunit-ab`, pre-production DVTs only).
//!
//! The policy is the pure [`fw_manifest::devunit::choose`]; this module feeds
//! it from flash: each slot that already passed `filter_valid` and
//! `verify_images` must also carry a vector table linked for that slot, and
//! its probation state comes from the boot log on page 6. The FSBL only reads
//! the log — the secure world is its only writer.
//!
//! A quad-word whose program was cut by a power loss can fail its ECC check.
//! On STM32U585 that raises an NMI (`FLASH_ECCR.ECCD`), and cortex-m-rt's
//! default NMI handler parks the core, which would turn one torn boot-log
//! record into a unit that never boots again. [`NonMaskableInt`] clears the
//! flag and returns instead: the read yields garbage, which the record CRC (or
//! the image hash) then rejects.

use core::ptr::{read_volatile, write_volatile};

use fw_manifest::devunit::{self, Candidate, Tally, RECORD_LEN};
use fw_manifest::ManifestRef;

use crate::slot::{self, slot_ns_addr, slot_secure_addr, Slot};

/// A slot that passed the manifest and image checks, with the secure-image
/// digest the fingerprint render reuses.
pub type Verified<'a> = (&'a ManifestRef<'a>, [u8; 32]);

/// Pick the slot to boot, or `None` when neither is bootable.
pub fn pick(a: Option<Verified>, b: Option<Verified>) -> Option<(Slot, [u8; 32])> {
    let a = a.filter(|(m, _)| vectors_ok(Slot::A, m));
    let b = b.filter(|(m, _)| vectors_ok(Slot::B, m));
    let chosen = devunit::choose(
        a.map(|(m, _)| candidate(Slot::A, m)),
        b.map(|(m, _)| candidate(Slot::B, m)),
    )?;
    if chosen == fw_manifest::SLOT_B {
        b.map(|(_, d)| (Slot::B, d))
    } else {
        a.map(|(_, d)| (Slot::A, d))
    }
}

fn candidate(slot: Slot, m: &ManifestRef) -> Candidate {
    Candidate {
        fw_version: m.fw_version(),
        try_once: m.try_once_flag(),
        tally: tally(slot::id(slot), m.fw_version()),
    }
}

/// Both images of `slot` must be linked for it: the secure world's stack in
/// secure SRAM1 and its reset handler inside the secure image, the same for
/// the non-secure image in SRAM2. The bytes are already hash-verified, so
/// this binds the SIGNED image to the slot it sits in.
fn vectors_ok(slot: Slot, m: &ManifestRef) -> bool {
    let s = slot_secure_addr(slot) as *const u32;
    let n = slot_ns_addr(slot) as *const u32;
    // SAFETY: both bases are always-mapped flash in this layout, read-only
    // during boot, and their images were just hash-verified to be at least
    // as long as a vector table.
    let (s_sp, s_reset, n_sp, n_reset) =
        unsafe { (read_volatile(s), read_volatile(s.add(1)), read_volatile(n), read_volatile(n.add(1))) };
    devunit::vectors_in_slot(
        s_sp,
        s_reset,
        slot_secure_addr(slot) as u32,
        m.secure_len(),
        devunit::SECURE_SRAM_BASE,
        devunit::SECURE_SRAM_END,
    ) && devunit::vectors_in_slot(
        n_sp,
        n_reset,
        slot_ns_addr(slot) as u32,
        m.nonsecure_len(),
        devunit::NS_SRAM_BASE,
        devunit::NS_SRAM_END,
    )
}

/// Fold the whole boot-log page into the tally for `(slot, version)`.
fn tally(slot: u8, version: u32) -> Tally {
    let mut t = Tally::default();
    let base = devunit::BOOT_LOG_ADDR as *const u8;
    let mut rec = [0u8; RECORD_LEN];
    for i in 0..devunit::LOG_CAPACITY {
        for (j, byte) in rec.iter_mut().enumerate() {
            // SAFETY: page 6 is always-mapped secure flash; `i * 16 + j` stays
            // inside its 8 KiB.
            *byte = unsafe { read_volatile(base.add(i * RECORD_LEN + j)) };
        }
        t.observe(&rec, slot, version);
    }
    t
}

/// `FLASH_ECCR` (secure alias of the FLASH register block, RM0456 / SVD
/// offset 0x30). `ECCD` (bit 31) is write-1-to-clear; `ECCC` (bit 30) too, so
/// it is written back as 0 and keeps its state.
const FLASH_ECCR: *mut u32 = 0x5002_2030 as *mut u32;
const ECCD: u32 = 1 << 31;
const ECCIE: u32 = 1 << 24;

/// Flash double-ECC NMI: clear it and resume (see the module docs). Any other
/// NMI source keeps cortex-m-rt's behaviour and parks the core.
#[cortex_m_rt::exception]
unsafe fn NonMaskableInt() {
    // SAFETY: fixed, always-present FLASH register; single-threaded boot code.
    let eccr = unsafe { read_volatile(FLASH_ECCR) };
    if eccr & ECCD != 0 {
        // SAFETY: as above; writing ECCD clears it, ECCIE keeps its value.
        unsafe { write_volatile(FLASH_ECCR, ECCD | (eccr & ECCIE)) };
        return;
    }
    loop {
        cortex_m::asm::wfe();
    }
}
