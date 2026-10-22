/* Secure world linker script for real STM32U585 (Cortex-M33 TrustZone)
 *
 * cortex-m-rt's link.x INCLUDEs this file.
 *
 * Memory layout:
 *   Flash bank 1 (1 MB) → secure (S alias 0x0C000000)
 *   Flash bank 2 (1 MB) → non-secure (NS alias 0x08100000)
 *   SRAM1 (192 KB)      → secure (S alias 0x30000000)
 *   SRAM2 (64 KB)       → non-secure (NS alias 0x20030000)
 *
 * The secure watermark (SECWM1) covers all 128 pages of bank 1.
 * NSC veneers are placed at the end of secure flash; the SAU marks
 * that sub-region as Non-Secure Callable.
 */

MEMORY
{
    /* Secure flash: bank 1 via S alias.
     * Last 40 KB (pages 123-127, 0x0C0F6000-0x0C0FFFFF) reserved for
     * persistent secure data:
     *   page 127 (0x0C0FE000) = first-boot provisioning journal
     *                            (KEY_PAGE, `rdp2-self-lock`; otherwise reserved)
     *   page 126 (0x0C0FC000) = wrapped SE050 BHK (`bhk` only; otherwise reserved)
     *   page 125 (0x0C0FA000) = SE050 admin-wipe state (PIN at QW0, flag at QW1)
     *   page 124 (0x0C0F8000) = MCU PIN-attempt counter
     *   page 123 (0x0C0F6000) = per-slot off-chain/UserOp signature journal
     * See hw/flash.rs. */
    FLASH : ORIGIN = 0x0C000000, LENGTH = 984K

    /* Secure SRAM: SRAM1 via S alias */
    RAM   : ORIGIN = 0x30000000, LENGTH = 192K
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
