//! Host stub of the `cortex-m` crate for the secure-miri-tests mount crate.
//!
//! The mounted production files (`secure/src/ui/lcd.rs`) reference
//! `cortex_m::asm::nop()` (the `delay_ms` spin) and `cortex_m::asm::wfe()`
//! (the headless `wait_button` idle loop) via the extern prelude. On the host
//! both are pure pacing hints with no observable effect, so they are no-ops
//! here. Nothing else of the real `cortex-m` API is provided on purpose: if a
//! future mounted file needs more of it, extend this stub — never reach for
//! the real crate (it is `no_std` ARM-only and will not build for the host).
#![no_std]

pub mod asm {
    /// No-op on host: the firmware's timing loops are wall-clock-free here.
    #[inline(always)]
    pub fn nop() {}

    /// No-op on host: tests never call the blocking `wait_button` arm that
    /// contains this, and even if they did there is nothing to wait for.
    #[inline(always)]
    pub fn wfe() {}
}
