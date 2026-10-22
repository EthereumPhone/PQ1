//! Secure-world stack-overflow guard (MSPLIM_S), armed first thing in `main`.
//!
//! The secure stack grows down from `_stack_start` toward the end of
//! `.bss`/`.uninit` (`_stack_end`). Without a limit, running past `_stack_end`
//! silently overwrites static data: that happened twice (the deep register-slot
//! sign path zeroed `state::SLOT_CACHE`; on QEMU with `ui-px` it broke the
//! first Type-2 self-verify). ARMv8-M's stack limit register turns the same
//! event into a synchronous fault: any instruction that would move SP below
//! `MSPLIM` raises a UsageFault (STKOF) instead of executing. No UsageFault
//! handler is enabled, so it escalates to the secure `HardFault`, which wipes
//! every secret cache, scrubs the dead stack and resets.
//!
//! The limit is not `_stack_end` itself but `_stack_guard`, a linker-reserved
//! band above it (`secure/memory*.x`). `CCR.STKOFHFNMIGN` makes HardFault and
//! NMI ignore the limit, so the handler can push its frame and run the wipe
//! inside that band. With the limit at `_stack_end` and the bit clear, the
//! handler would fault again on entry; a fault inside HardFault cannot escalate
//! and the core locks up with the secrets still in SRAM.
//!
//! Only the secure MSP is limited: secure code never runs on PSP_S, and the
//! non-secure stacks have their own banked limit registers (not set here).

#[cfg(target_arch = "arm")]
extern "C" {
    /// Lowest address the secure stack may reach (`secure/memory*.x`).
    static _stack_guard: u32;
}

/// `CCR` (System Control Block, secure view at the architectural address).
#[cfg(target_arch = "arm")]
const SCB_CCR: *mut u32 = 0xE000_ED14 as *mut u32;
/// `CCR.STKOFHFNMIGN`: HardFault and NMI handlers ignore the stack limit.
pub(crate) const CCR_STKOFHFNMIGN: u32 = 1 << 10;

/// Program MSPLIM_S and let the fault handlers run below it. Idempotent.
///
/// Call once, as early in `main` as possible: frames pushed before this runs
/// are not checked, but `main`'s entry frame is shallow.
#[cfg(target_arch = "arm")]
pub fn arm() {
    let limit = core::ptr::addr_of!(_stack_guard) as u32;
    // SAFETY: `CCR` is a word-aligned architectural register always present on
    // ARMv8-M Mainline; a read-modify-write that only sets STKOFHFNMIGN leaves
    // every other configuration bit as reset/boot code left it. Done before
    // the limit is armed, so a fault can never be taken with the bit clear.
    unsafe {
        let ccr = core::ptr::read_volatile(SCB_CCR);
        core::ptr::write_volatile(SCB_CCR, ccr | CCR_STKOFHFNMIGN);
    }
    cortex_m::asm::dsb();
    cortex_m::asm::isb();
    // SAFETY: MSPLIM_S only bounds how low the secure main stack pointer may
    // go. `_stack_guard` lies below the current SP (we are at the top of
    // `main`; the linker asserts `_stack_guard < _stack_start`), so the write
    // cannot fault the instruction stream that performs it.
    unsafe {
        core::arch::asm!(
            "msr MSPLIM, {limit}",
            "isb",
            limit = in(reg) limit,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Host builds have no secure stack to limit.
#[cfg(not(target_arch = "arm"))]
pub fn arm() {}

/// Read back MSPLIM_S for the test-only overflow probe's log line.
#[cfg(all(target_arch = "arm", feature = "stack-overflow-probe"))]
#[must_use]
pub fn limit() -> u32 {
    let v: u32;
    // SAFETY: reading the stack limit register has no side effects.
    unsafe {
        core::arch::asm!("mrs {v}, MSPLIM", v = out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

/// Test-only negative control: log the armed limit, overflow, and report a
/// FAIL if control ever comes back. A passing image never prints the FAIL
/// line: the guard fires, HardFault wipes and resets (QEMU: exits non-zero).
#[cfg(all(target_arch = "arm", feature = "stack-overflow-probe"))]
pub fn run_overflow_probe() -> ! {
    secure_log!("[S] stack-overflow-probe: MSPLIM={:#010x}, recursing", limit());
    let r = overflow_probe(0);
    secure_log!("[S] stack-overflow-probe: FAIL - returned {} (guard did not fire)", r);
    loop {
        cortex_m::asm::wfe();
    }
}

/// Test-only negative control (`stack-overflow-probe`, never in production):
/// recurse with a large frame until the guard fires. A correct guard ends in
/// the HardFault wipe-and-reset; reaching the end of this function, or
/// corrupting `.bss` on the way, is the failure the guard exists to prevent.
#[cfg(all(target_arch = "arm", feature = "stack-overflow-probe"))]
#[inline(never)]
pub fn overflow_probe(depth: u32) -> u32 {
    let mut frame = [0u8; 512];
    // SAFETY: volatile write keeps the frame from being optimised away.
    unsafe { core::ptr::write_volatile(&mut frame[depth as usize % 512], depth as u8) };
    let next = overflow_probe(depth.wrapping_add(1));
    // Use the frame after the call so it cannot become a tail call.
    next.wrapping_add(u32::from(core::hint::black_box(frame[0])))
}
