/* BLS12-381 pairing computation needs a bigger stack than C10 verify —
   the per-pairing curve constants + Miller loop intermediates push RAM
   use into the ~16 KB range. 256 KB RAM keeps the headroom comfortable
   under rainbow emulation. */
MEMORY
{
    FLASH : ORIGIN = 0x08000000, LENGTH = 1024K
    RAM   : ORIGIN = 0x20000000, LENGTH = 256K
}

_stack_start = ORIGIN(RAM) + LENGTH(RAM);
