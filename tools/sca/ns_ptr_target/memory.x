/* Arbitrary STM32-ish layout. The actual NS/S boundaries the validator
   defends are constants compiled in from `sphincs-tz-shared`; this file
   just satisfies cortex-m-rt's link.x. */
MEMORY
{
    FLASH : ORIGIN = 0x08000000, LENGTH = 256K
    RAM   : ORIGIN = 0x20000000, LENGTH = 64K
}

_stack_start = ORIGIN(RAM) + LENGTH(RAM);
