/* Arbitrary, conventional STM32-ish layout. The exact addresses are irrelevant
   to the fault-injection logic test — rainbow maps whatever PT_LOAD segments the
   ELF declares; this file just satisfies cortex-m-rt's link.x. */
MEMORY
{
    FLASH : ORIGIN = 0x08000000, LENGTH = 256K
    RAM   : ORIGIN = 0x20000000, LENGTH = 64K
}

_stack_start = ORIGIN(RAM) + LENGTH(RAM);
