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
