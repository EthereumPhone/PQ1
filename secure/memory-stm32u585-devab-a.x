/* Secure-world linker script: DEV-UNIT A/B layout, SLOT A (`devunit-ab`).
 *
 * Dev units only (pre-production DVTs handed to testers) — not the production
 * geometry. The single source of truth for the map is `fw_manifest::devunit`:
 *
 *   bank 1  pages 0-3     FSBL
 *           page  4/5     manifest A / B
 *           page  6       boot log
 *           pages 7-86    secure slot A, 640 KiB   <-- THIS SCRIPT
 *           pages 123-127 per-device pages (unchanged)
 *   bank 2  pages 0-23    non-secure slot A
 *           pages 24-47   non-secure slot B
 *           pages 48-127  secure slot B (SECWM2 48..127)
 *
 * RAM is the monolithic secure SRAM1 window; the FSBL scrubs its own 16 KiB
 * before branching.
 */

MEMORY
{
    FLASH : ORIGIN = 0x0C00E000, LENGTH = 640K
    RAM   : ORIGIN = 0x30000000, LENGTH = 192K
}

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
