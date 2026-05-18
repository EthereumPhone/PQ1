//! GTZC1 TZIC + wipe escalation demo (NS side).
//!
//! Slice 2 of the GTZC hardening. Builds with `tzic-wipe` ON in the
//! secure crate; the SECURE `on_violation()` handler runs the wipe
//! sequence (zeroize SRAM secrets → arm page-125 wipe flag →
//! `SCB::sys_reset`). NS does *one* probe of a SECURE peripheral via
//! its NS alias, then would log a `SURVIVED` marker if the wipe path
//! had not fired.
//!
//! Pass criteria (host-side in the Makefile target):
//!
//!   * `[NS][gtzc-wipe] probing` appears ≥ 2 times — proves the
//!     chip rebooted at least once after the first probe.
//!   * `[NS][gtzc-wipe] SURVIVED` appears 0 times — proves the
//!     IRQ-triggered wipe always preempts the post-probe code.
//!
//! With `tzic-wipe` OFF (sanity-check variant) the inverse holds.

use cortex_m_rt::entry;
use cortex_m_semihosting::hprintln;

#[entry]
fn main() -> ! {
    // One probe of HASH_CR NS alias. HASH is clocked by the boot
    // path's `hw::hash::init_clock` (we see "HW SHA-256 self-test
    // PASS" in the secure log), so the access reaches the bus
    // matrix and trips GTZC.
    const HASH_CR_NS: u32 = 0x420C_0400;

    let _ = hprintln!("[NS][gtzc-wipe] probing 0x{:08x} (HASH_CR_NS)", HASH_CR_NS);

    // SAFETY: 4-byte-aligned MMIO. GTZC1 TZSC has HASH marked
    // SECURE; the AHB bridge RAZ-gates the read and TZIC raises
    // IRQ 8. With `tzic-wipe` ON, the IRQ handler never returns
    // — it zeroizes, arms the wipe flag, and resets.
    let v: u32 = unsafe { core::ptr::read_volatile(HASH_CR_NS as *const u32) };

    // If we get here, the wipe path did NOT fire. Either the
    // secure crate was built without `tzic-wipe`, or the IRQ
    // didn't reach `trigger_tzic_wipe`. Either way, the
    // production gate is broken.
    let _ = hprintln!("[NS][gtzc-wipe] SURVIVED — read=0x{:08x}", v);
    let _ = hprintln!("[NS][gtzc-wipe] === FAIL: wipe did not preempt ===");

    // Spin so the SURVIVED line stays visible to the harness;
    // probe-rs `run` keeps the channel open until timeout.
    loop {
        cortex_m::asm::wfe();
    }
}
