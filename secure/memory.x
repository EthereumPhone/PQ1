/* Secure world linker script for QEMU mps2-an505 (Cortex-M33 TrustZone)
 *
 * cortex-m-rt's link.x INCLUDEs this file.
 *
 * QEMU 8.2.2 workaround: SG instruction verification reads through the
 * NS alias, so the MPC block containing the veneers must be marked NS.
 * We place the NSC veneers at SSRAM-0 offset 0x3FC000 (block ~4080,
 * in NS MPC territory) via a separate NSC memory region.
 */

MEMORY
{
    /* Secure flash: SSRAM-0 S alias, first ~2MB (MPC blocks 0-63 = secure).
     * The 512K envelope is retained pending a separate measured layout review. */
    FLASH : ORIGIN = 0x10000000, LENGTH = 512K

    /* NSC region: SSRAM-0 S alias at offset 0x3FF000 (near end of 4MB).
     * Must be in NS MPC blocks (64+) so QEMU's SG check can read via NS alias.
     * Offset 0x3FF000 = block 4092 = LUT word 127, well into NS territory.
     * NS flash is at offset 0x200000-0x23FFFF, so no collision. */
    NSC   : ORIGIN = 0x103FF000, LENGTH = 4K

    /* Secure SRAM: SSRAM-1 S alias */
    RAM   : ORIGIN = 0x38000000, LENGTH = 128K
}

/* Stack grows downward from top of secure SRAM */
_stack_start = ORIGIN(RAM) + LENGTH(RAM);

/* Secure stack-overflow guard (`secure/src/stack_guard.rs`, 2026-10-22).
 * `main` programs MSPLIM_S = `_stack_guard`, so a stack pointer that would go
 * below it faults (UsageFault STKOF, escalated to HardFault) instead of
 * silently overwriting `.bss` (it once clobbered `SLOT_CACHE`). The band
 * [`_stack_end`, `_stack_guard`) is left for the HardFault handler itself,
 * which runs with the limit ignored (CCR.STKOFHFNMIGN) to wipe secrets and
 * reset; size it from that handler's measured stack use. `_stack_end` is
 * cortex-m-rt's `__euninit` (end of `.bss`/`.uninit`). */
_stack_guard_size = 2K;
_stack_guard = ALIGN(_stack_end + _stack_guard_size, 8);
ASSERT(_stack_guard % 8 == 0, "secure stack guard must be 8-byte aligned");
ASSERT(_stack_guard < _stack_start, "secure stack guard band leaves no stack");
