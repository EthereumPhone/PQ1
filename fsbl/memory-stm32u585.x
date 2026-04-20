/* First-stage bootloader linker script for STM32U585.
 *
 * The FSBL occupies the first 32 KB of bank 1 (pages 0–3). These
 * four pages are WRP1A-locked as the final step of factory
 * provisioning, so even a compromised runtime firmware cannot
 * overwrite the FSBL in place.
 *
 * Flash layout (bank 1, secure alias):
 *   0x0C00_0000  FSBL           32 KB   (this file — pages 0–3, WRP-locked)
 *   0x0C00_8000  Manifest A      8 KB   (page 4)
 *   0x0C00_A000  Manifest B      8 KB   (page 5)
 *   0x0C00_C000  Boot state      8 KB   (page 6)
 *   0x0C00_E000  Slot A secure 464 KB   (pages 7–64)
 *   0x0C08_2000  Slot B secure 464 KB   (pages 65–122)
 *   0x0C0F_A000  Reserved (SE050 admin, OPTIGA PBS, etc.)
 *
 * RAM: the first 16 KB of SRAM1 (0x3000_0000) is reserved for the
 * FSBL's stack. The runtime slot reuses the full SRAM1 from 0x0 on
 * branch (FSBL clears its own stack + variables before leaving).
 */

MEMORY
{
    FLASH : ORIGIN = 0x0C000000, LENGTH = 32K
    RAM   : ORIGIN = 0x30000000, LENGTH = 16K
}

_stack_start = ORIGIN(RAM) + LENGTH(RAM);
