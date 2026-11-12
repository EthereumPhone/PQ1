/* harness v3: production-like placement. Vector table, code and rodata in flash bank 1 at the SECURE alias
 * 0x0C000000 (bank 1 is fully secure on this kit: SECWM1R1 = 0xffffff80); .data copied from flash to SRAM by
 * startup_flash.c; .bss, stack and the results block in SRAM (S-bus). The clock code (clk.c, -DFLASHRUN) sets
 * FLASH_ACR latency 4 before 160 MHz and enables ICACHE as secure/src/hw/rcc.rs does (ICACHE_CR = 1: EN,
 * WAYSEL = 0, 1-way). Only flash pages are written (OpenOCD flash write_image erase); never option bytes. */
MEMORY {
  FLASH   : ORIGIN = 0x0C000000, LENGTH = 0x40000
  RESULTS : ORIGIN = 0x30000000, LENGTH = 0x100
  RAM     : ORIGIN = 0x30000400, LENGTH = 0xC0000 - 0x400
}
STACK_SIZE = DEFINED(STACK_SIZE) ? STACK_SIZE : 0x20000;
ENTRY(_start)
SECTIONS {
  .results (NOLOAD) : { . = . + 0x100; } > RESULTS
  .vtable  : { KEEP(*(.vtable)) } > FLASH
  .text    : { KEEP(*(.entry)) . = . + (DEFINED(PAD) ? PAD : 0); *(.text*) *(.rodata*) . = ALIGN(8); } > FLASH
  .data    : { __data_start__ = .; *(.data*) . = ALIGN(8); __data_end__ = .; } > RAM AT > FLASH
  __data_load__ = LOADADDR(.data);
  .bss (NOLOAD) : { . = ALIGN(8); __bss_start__ = .; *(.bss*) *(COMMON) . = ALIGN(8); __bss_end__ = .; } > RAM
  __stack_top = ORIGIN(RAM) + LENGTH(RAM);
  __stack_limit = __stack_top - STACK_SIZE;
  ASSERT(__bss_end__ <= __stack_limit, "image + bss overlaps the stack")
  /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) }
}
