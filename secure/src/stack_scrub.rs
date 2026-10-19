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
    #[cfg(feature = "stack-hwm")]
    hwm::scan_below_sp();
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
    #[cfg(feature = "stack-hwm")]
    hwm::paint_below_sp();
}

/// DVT checklist row 5.9 (test-only `stack-hwm`): secure-stack high-water
/// mark. The dead stack is painted with [`hwm::PATTERN`] at `main` entry and
/// after every scrub (the NS hand-off fills with it too, `boot_ns.rs`); each
/// scrub first records the lowest word below SP that no longer holds it.
/// `STACK_HWM_LOW` is read over SWD. A frame word that happens to equal the
/// pattern hides that word only, so the result is exact to within one frame
/// of such words.
#[cfg(all(feature = "stack-hwm", target_arch = "arm"))]
pub mod hwm {
    use core::sync::atomic::{AtomicU32, Ordering};

    pub const PATTERN: u32 = 0xC5AC_E5A5;

    #[used]
    #[no_mangle]
    pub static STACK_HWM_LOW: AtomicU32 = AtomicU32::new(u32::MAX);
    #[used]
    #[no_mangle]
    pub static STACK_HWM_SCANS: AtomicU32 = AtomicU32::new(0);

    fn sp() -> u32 {
        let sp: u32;
        // SAFETY: reads SP only.
        unsafe { core::arch::asm!("mov {}, sp", out(reg) sp, options(nomem, nostack)) };
        sp
    }

    fn bottom() -> u32 {
        // SAFETY: address of a linker symbol, never dereferenced here.
        unsafe { core::ptr::addr_of!(super::_stack_end) as u32 }
    }

    /// Record the lowest non-pattern word in `[_stack_end, SP)`.
    #[inline(never)]
    pub fn scan_below_sp() {
        let top = sp();
        let mut p = bottom();
        while p < top {
            // SAFETY: word-aligned read of dead stack inside the RAM region.
            if unsafe { core::ptr::read_volatile(p as *const u32) } != PATTERN {
                STACK_HWM_LOW.fetch_min(p, Ordering::Relaxed);
                break;
            }
            p += 4;
        }
        STACK_HWM_SCANS.fetch_add(1, Ordering::Relaxed);
    }

    /// Fill `[_stack_end, SP)` with the pattern.
    #[inline(never)]
    pub fn paint_below_sp() {
        let top = sp();
        let mut p = bottom();
        while p < top {
            // SAFETY: word-aligned write to dead stack inside the RAM region.
            unsafe { core::ptr::write_volatile(p as *mut u32, PATTERN) };
            p += 4;
        }
    }
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

/// Dev bench (`ui-px-film-bench`): bytes at the bottom of the secure stack
/// still zero since the last [`scrub_dead_stack`], i.e. the headroom the
/// deepest frame since then (exceptions included) left. Exact up to the zero
/// words a frame may itself have stored at its lowest addresses.
#[cfg(all(target_arch = "arm", feature = "ui-px-film-bench"))]
pub fn untouched_since_scrub() -> u32 {
    let start = core::ptr::addr_of!(_stack_end) as usize;
    let sp = cortex_m::register::msp::read() as usize;
    let mut p = start;
    // SAFETY: reads only `[_stack_end, SP)`, word-aligned RAM reserved for
    // the stack (see `scrub_dead_stack`).
    while p < sp && unsafe { core::ptr::read_volatile(p as *const u32) } == 0 {
        p += 4;
    }
    (p - start) as u32
}

/// Dev bench: the secure stack region's size in bytes.
#[cfg(all(target_arch = "arm", feature = "ui-px-film-bench"))]
pub fn stack_size() -> u32 {
    extern "C" {
        static _stack_start: u32;
    }
    (core::ptr::addr_of!(_stack_start) as usize - core::ptr::addr_of!(_stack_end) as usize) as u32
}

/// Host and QEMU-model builds have no linker-provided secure stack to scrub.
#[cfg(not(target_arch = "arm"))]
pub fn scrub_dead_stack() {}
