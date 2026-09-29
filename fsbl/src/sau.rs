//! Minimal SAU configuration: make the bank-2 non-secure alias readable.
//!
//! **This is a fix, not a diagnostic — it belongs in every build.**
//!
//! With `TZEN=1` and the SAU *disabled*, the whole address space defaults to
//! Secure. The FSBL then reads the non-secure slot image through the bank-2 NS
//! alias (`0x0810_0000`, watermarked non-secure by `SECWM2`) as a SECURE
//! access, and the flash controller returns **zeros**. `verify::verify_images`
//! duly hashes zeros, the NS hash mismatches the vendor-signed manifest, no
//! candidate is admissible, and `main` halts in `loop { wfe() }` — silently,
//! because the FSBL has no logging by construction.
//!
//! That was the whole reason the first non-monolithic boot proof never booted
//! (2026-09-16). It was measured, not guessed: an instrumented build recorded
//! the NS hash the core actually computed as the SHA-256 of 7,488 zero bytes,
//! while SWD read the same address as the correct image. Note the trap for
//! anyone re-deriving this from the ARM manual: architecturally the IDAU marks
//! `0x08…` non-secure and secure code *may* read non-secure memory, so the
//! access looks legal — on this silicon the watermark plus a secure access
//! yields read-as-zero instead.
//!
//! One region is enough. The FSBL only ever *reads* NS flash: it has no NS
//! SRAM, no NS peripherals and no NSC veneers of its own. The secure world
//! reconfigures the SAU completely in `secure/src/sau.rs` right after the
//! branch, so this configuration is transient and deliberately minimal.
//!
//! Encoding mirrors `secure/src/sau.rs::configure_sau_region`: `RBAR` takes the
//! base, `RLAR` the **inclusive** limit, both 32-byte aligned, with bit 0 of
//! `RLAR` enabling the region (bit 1 would mark it NSC, which this never does).

use core::ptr::write_volatile;

const SAU_CTRL: usize = 0xE000_EDD0;
const SAU_RNR: usize = 0xE000_EDD8;
const SAU_RBAR: usize = 0xE000_EDDC;
const SAU_RLAR: usize = 0xE000_EDE0;

/// Bank-2 non-secure alias — the NS slot images live here. Same bounds as
/// `secure/src/sau.rs`'s `SAU_NS_FLASH_{BASE,END}` for `stm32u585`.
const NS_FLASH_BASE: u32 = 0x0810_0000;
/// Inclusive limit, per SAU `RLAR` semantics.
const NS_FLASH_END: u32 = 0x081F_FFFF;

#[inline(always)]
fn wr(addr: usize, val: u32) {
    // SAFETY: fixed 4-byte-aligned SAU registers in the ARMv8-M System Control
    // Space. The FSBL is single-threaded and nothing else touches the SAU
    // before the branch.
    unsafe { write_volatile(addr as *mut u32, val) }
}

/// Mark bank-2 NS flash as Non-Secure so the core can read the NS slot image.
///
/// Must be called before [`crate::verify::verify_images`]; without it that
/// function hashes zeros for the NS region and every candidate is rejected.
pub fn init() {
    // Disable the SAU while programming it, exactly as the secure world does.
    wr(SAU_CTRL, 0);

    wr(SAU_RNR, 0);
    wr(SAU_RBAR, NS_FLASH_BASE & 0xFFFF_FFE0);
    // Bit 0 = ENABLE. Bit 1 (NSC) stays clear: this is plain Non-Secure, not a
    // non-secure callable veneer window.
    wr(SAU_RLAR, (NS_FLASH_END & 0xFFFF_FFE0) | 1);

    wr(SAU_CTRL, 1);
    cortex_m::asm::dsb();
    cortex_m::asm::isb();
}
