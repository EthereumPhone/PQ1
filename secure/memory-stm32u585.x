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
     * Last 8 KB (page 127, 0x0C0FE000) reserved for persistent
     * secure data (pairing key, intent log). See hw/flash.rs. */
    FLASH : ORIGIN = 0x0C000000, LENGTH = 1016K

    /* Secure SRAM: SRAM1 via S alias */
    RAM   : ORIGIN = 0x30000000, LENGTH = 192K
}

/* Stack grows downward from top of secure SRAM */
_stack_start = ORIGIN(RAM) + LENGTH(RAM);
