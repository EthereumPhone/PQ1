//! Zero the secure stack below the live frames (DVT1 checklist row 5.5).
//!
//! Every secret type here zeroizes on drop, but a by-value move leaves the
//! moved-from bytes behind in the caller's frame, and LOCK never touched the
//! stack. The DVT1 run (2026-10-15) found 48-byte key seeds on the secure
//! stack after CMD_LOCK and after the 120 s idle wipe.
//!
//! [`scrub_dead_stack`] zeroes `[_stack_end, SP)`: every byte below the
//! current stack pointer is dead in every context it is called from, because
//! a preempted frame always sits above the preempting one. It is written in
//! assembly so the loop itself needs no stack below the SP it reads. An
//! exception taken mid-loop stacks below SP, returns, and is popped before
//! the loop resumes; zeroing those popped bytes afterwards is harmless.
//!
//! [`boot_ns`](crate::boot_ns::boot) goes further at the hand-off: `main`
//! never returns, so its frame is dead once the non-secure world starts.
//! It moves MSP back to `_stack_start` and zeroes the whole stack region,
//! including the provisioning and unlock temporaries `main` left there.

#[cfg(target_arch = "arm")]
extern "C" {
    /// Lowest stack address (cortex-m-rt `link.x`: `_stack_end = __euninit`).
    static _stack_end: u32;
}

/// Zero every word of the secure stack below the current stack pointer.
///
/// Costs one store per dead word: about 35 k stores (< 1 ms at 160 MHz)
/// with a shallow stack.
#[cfg(target_arch = "arm")]
#[inline(never)]
pub fn scrub_dead_stack() {
    // SAFETY: writes only to `[_stack_end, SP)`, which is inside the RAM
    // region the linker reserved for the stack and holds no live data in any
    // calling context (see the module docs). `_stack_end` is word-aligned
    // (cortex-m-rt asserts `_stack_end % 4 == 0`), and SP is 8-aligned at
    // any instruction boundary we can reach here.
    unsafe {
        core::arch::asm!(
            "mov {end}, sp",
            "movs {zero}, #0",
            "2:",
            "cmp {p}, {end}",
            "bhs 3f",
            "str {zero}, [{p}], #4",
            "b 2b",
            "3:",
            p = inout(reg) core::ptr::addr_of!(_stack_end) as u32 => _,
            end = out(reg) _,
            zero = out(reg) _,
            options(nostack),
        );
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Runs [`scrub_dead_stack`] when dropped: put one at the top of a handler
/// with several return paths (the PendSV re-unlock dialog) and every path
/// scrubs the frames that handler's callees left below it.
pub struct ScrubOnDrop;

impl Drop for ScrubOnDrop {
    fn drop(&mut self) {
        scrub_dead_stack();
    }
}

/// Host and QEMU-model builds have no linker-provided secure stack to scrub.
#[cfg(not(target_arch = "arm"))]
pub fn scrub_dead_stack() {}
