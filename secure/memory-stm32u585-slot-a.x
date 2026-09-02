/* Secure-world linker script for A/B SLOT A — bench boot proof only.
 *
 * The default `memory-stm32u585.x` links the secure world MONOLITHICALLY at
 * 0x0C000000 + 984K, i.e. on top of where the FSBL lives. That is how every
 * bench flow has always run: SECBOOTADD0 points at 0x0C000000 and the secure
 * world IS the boot image. The FSBL's slot-selection code has consequently
 * never executed on silicon — no make target even flashes it.
 *
 * This script links the same secure world at LEGACY slot A instead, so the
 * FSBL can verify a manifest and branch into it. It is the missing half of a
 * non-monolithic image.
 *
 *   0x0C000000  FSBL            32 KB  (pages 0-3)
 *   0x0C008000  Manifest A       8 KB  (page 4)
 *   0x0C00A000  Manifest B       8 KB  (page 5)   erased for this proof
 *   0x0C00C000  Boot state       8 KB  (page 6)   erased for this proof
 *   0x0C00E000  Secure slot A  464 KB  (pages 7-64)  <-- THIS SCRIPT
 *
 * LEGACY, DELIBERATELY. `pqsigner-geometry` freezes a different map (FSBL
 * pages 0-4, manifests 5/6, secure slot A pages 7-63) and the cutover is
 * tracked in issue #540 as FA-1.1 consumer rewiring. This script matches the
 * layout `fsbl/src/slot.rs` actually implements, because the point of the
 * proof is to exercise the existing FSBL, not to pre-empt the geometry
 * decision. Two things make that safe to do now: nothing here is irreversible
 * (no WRP, no RDP-2), and the handoff machinery being proved is needed by
 * BOTH layouts.
 *
 * Do NOT derive a WRP range or any option-byte value from this file.
 *
 * RAM is unchanged from the monolithic script: the FSBL owns the first 16 KB
 * of SRAM1 for its own stack and scrubs it before branching, after which the
 * slot image reuses the whole of SRAM1.
 */

MEMORY
{
    /* Legacy secure slot A: pages 7-64 inclusive = 58 * 8 KB = 464 KB. */
    FLASH : ORIGIN = 0x0C00E000, LENGTH = 464K

    /* Secure SRAM: SRAM1 via S alias — same as the monolithic link. */
    RAM   : ORIGIN = 0x30000000, LENGTH = 192K
}

/* Stack grows downward from top of secure SRAM */
_stack_start = ORIGIN(RAM) + LENGTH(RAM);
