/* OB configurator: runs in secure mode when TZEN=1.
 * Page 0 of bank 1 is secure (SECWM1 default), so we fit in 8KB.
 * Use S aliases for flash and SRAM. */
MEMORY
{
    FLASH : ORIGIN = 0x0C000000, LENGTH = 8K
    RAM   : ORIGIN = 0x30000000, LENGTH = 192K
}
_stack_start = ORIGIN(RAM) + LENGTH(RAM);
