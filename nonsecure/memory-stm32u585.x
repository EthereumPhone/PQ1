/* Non-secure world linker script for real STM32U585 */

MEMORY
{
    /* Non-secure flash: bank 2 via NS alias */
    FLASH : ORIGIN = 0x08100000, LENGTH = 1024K

    /* Non-secure SRAM: SRAM2 via NS alias */
    RAM   : ORIGIN = 0x20030000, LENGTH = 64K
}

_stack_start = ORIGIN(RAM) + LENGTH(RAM);
