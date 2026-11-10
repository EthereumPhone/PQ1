//! Flash double-ECC NMI handler, built into EVERY FSBL (#1137).
//!
//! A quad-word whose program was cut short (a power loss, or the non-secure
//! world tearing a word in its own slot on purpose) can fail its ECC check.
//! On STM32U585 reading it raises an NMI (`FLASH_ECCR.ECCD`); the flag has no
//! enable bit. cortex-m-rt's default NMI handler parks the core, so one torn
//! word in a manifest, a slot image or the boot log would hang every boot,
//! with no way back in at RDP-2. Until 2026-11-10 only the dev-unit build had
//! this handler. It clears the flag and returns: the read yields garbage,
//! which the manifest CRC and signature, the image hash or the record CRC
//! then reject. Pages 0..=3 hold the FSBL in both the legacy and the dev-unit
//! layout (manifests start at page 4).

use core::ptr::{read_volatile, write_volatile};

/// `FLASH_ECCR` (secure alias of the FLASH register block, RM0456 / SVD
/// offset 0x30). `ECCD` (bit 31) is write-1-to-clear; `ECCC` (bit 30) too, so
/// it is written back as 0 and keeps its state.
const FLASH_ECCR: *mut u32 = 0x5002_2030 as *mut u32;
const ECCD: u32 = 1 << 31;
const ECCIE: u32 = 1 << 24;

/// `FLASH_ECCR.BK_ECC` (bit 21, error in bank 2) and `SYSF_ECC` (bit 22,
/// error in system flash); `ADDR_ECC` (bits 19:0) is the byte offset in the
/// bank.
const BK_ECC: u32 = 1 << 21;
const SYSF_ECC: u32 = 1 << 22;
const ADDR_MASK: u32 = 0xF_FFFF;
/// The FSBL's own pages (bank 1, 0..=3): an ECC error there is in the code
/// this core is executing, which no checksum downstream re-verifies.
const FSBL_END_OFF: u32 = 4 * 0x2000;

/// Flash double-ECC NMI on DATA the FSBL reads (see the module docs above): clear
/// it and resume. Excused anywhere the read is re-checked downstream — the
/// boot log (record CRC), a manifest torn by a power cut during COMMIT
/// (manifest CRC + signature), a slot image (image hash). NOT excused in the
/// FSBL's own pages or in system flash, and any other NMI source: those keep
/// cortex-m-rt's behaviour and park the core.
#[cortex_m_rt::exception]
unsafe fn NonMaskableInt() {
    // SAFETY: fixed, always-present FLASH register; single-threaded boot code.
    let eccr = unsafe { read_volatile(FLASH_ECCR) };
    let in_fsbl = eccr & (BK_ECC | SYSF_ECC) == 0 && eccr & ADDR_MASK < FSBL_END_OFF;
    if eccr & ECCD != 0 && eccr & SYSF_ECC == 0 && !in_fsbl {
        // SAFETY: as above; writing ECCD clears it, ECCIE keeps its value.
        unsafe { write_volatile(FLASH_ECCR, ECCD | (eccr & ECCIE)) };
        return;
    }
    loop {
        cortex_m::asm::wfe();
    }
}
