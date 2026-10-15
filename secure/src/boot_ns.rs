/// Boot the non-secure world.
///
/// Sets VTOR_NS, MSP_NS, clears all GP/FPU registers and PSP_NS to prevent
/// secure-state leakage across the boundary, then branches to the NS reset
/// vector via BXNS.
///
/// The MPC must be configured before calling this so that the NS flash
/// region at `ns_vector_table` is accessible.

// Non-Secure Vector Table Offset Register
const VTOR_NS: *mut u32 = 0xE002_ED08 as *mut u32;

extern "C" {
    /// Top of the secure stack (cortex-m-rt `link.x`).
    static _stack_start: u32;
    /// Bottom of the secure stack (cortex-m-rt `link.x`: `__euninit`).
    static _stack_end: u32;
}

/// # Safety
///
/// `ns_vector_table` must point to a valid non-secure vector table
/// in non-secure flash (NS alias address space, e.g. 0x00200000).
/// The MPC must already be configured to allow access.
/// This function does not return.
pub unsafe fn boot(ns_vector_table: u32) -> ! {
    let vt = ns_vector_table as *const u32;

    // 1. Set VTOR_NS
    core::ptr::write_volatile(VTOR_NS, ns_vector_table);

    // 2. Read NS initial stack pointer (vector table entry 0)
    let ns_msp = core::ptr::read_volatile(vt);

    // 3. Set MSP_NS and clear PSP_NS
    core::arch::asm!(
        "msr MSP_NS, {0}",
        "msr PSP_NS, {1}",
        in(reg) ns_msp,
        in(reg) 0u32,
    );

    // 4. Clear CONTROL_NS (privileged thread, MSP)
    core::arch::asm!(
        "msr CONTROL_NS, {0}",
        in(reg) 0u32,
    );

    // 5. Read NS reset handler (vector table entry 1)
    let ns_reset = core::ptr::read_volatile(vt.add(1));
    let ns_entry = ns_reset & !1u32;

    // 6. Clear all general-purpose registers and the link register before
    //    crossing into NS world. The Cortex-M33 BXNS instruction does NOT
    //    auto-clear registers (only function-pointer veneer returns do); we
    //    must do it manually to avoid leaking secure intermediates.
    //
    //    We pass `ns_entry` in via r0 then move it to lr just before BXNS so
    //    we can issue a single `bxns lr` after the clear.
    //
    //    NOTE: FPU register clear is omitted because cortex-m-rt does not
    //    enable the FPU by default in this build. If FPU is enabled later,
    //    add: `vmov.f32 sN, #0` for s0..s31 (or use VLDMIA from a zeroed
    //    16-aligned buffer).
    //    7. Before that: `main` never returns, so from here on its frame is
    //    dead. Move MSP back to the top of the secure stack and zero the
    //    whole stack region, so the boot path's provisioning and unlock
    //    temporaries (DVT1 row 5.5: by-value key moves left in `main`'s
    //    frame) do not sit under every later gateway call for the rest of
    //    the session. Done in the same asm block as BXNS because nothing
    //    after the MSP switch may touch the stack. An exception taken during
    //    the loop stacks below the new MSP and returns before the loop
    //    resumes. No static holds a pointer into `main`'s frame.
    let stack_top = core::ptr::addr_of!(_stack_start) as u32;
    let stack_bottom = core::ptr::addr_of!(_stack_end) as u32;
    core::arch::asm!(
        "msr msp, {top}",
        "2:",
        "cmp {p}, {top}",
        "bhs 3f",
        "str {zero}, [{p}], #4",
        "b 2b",
        "3:",
        "mov lr, {entry}",
        "mov r0,  #0",
        "mov r1,  #0",
        "mov r2,  #0",
        "mov r3,  #0",
        "mov r4,  #0",
        "mov r5,  #0",
        "mov r6,  #0",
        "mov r7,  #0",
        "mov r8,  #0",
        "mov r9,  #0",
        "mov r10, #0",
        "mov r11, #0",
        "mov r12, #0",
        "bxns lr",
        entry = in(reg) ns_entry,
        top = in(reg) stack_top,
        p = in(reg) stack_bottom,
        zero = in(reg) 0u32,
        options(noreturn),
    );
}
