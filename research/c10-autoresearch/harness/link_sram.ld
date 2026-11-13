/* SRAM-only image for the STM32U585 secure SRAM alias (SRAM1+SRAM2+SRAM3 = 0x30000000..0x300BFFFF, 768 KiB).
 * 0x30000000..0x300000FF: results block (bench.h), NOT loaded (NOLOAD), poisoned by run_on_board.sh.
 * Everything else (vector table, code, rodata, data, bss) follows; stack at the top with MSPLIM guard.
 * Nothing is placed in flash. .data needs no copy (load_image writes it in place); .bss is zeroed by startup.c.
 * Note: SRAM2 (0x30030000..0x3003FFFF) is erased by every system reset with this board's option bytes;
 * irrelevant here because the image is loaded after the reset. */
MEMORY {
  RESULTS : ORIGIN = 0x30000000, LENGTH = 0x100
  RAM     : ORIGIN = 0x30000400, LENGTH = 0xC0000 - 0x400
}
STACK_SIZE = DEFINED(STACK_SIZE) ? STACK_SIZE : 0x20000;
ENTRY(_start)
SECTIONS {
  .results (NOLOAD) : { . = . + 0x100; } > RESULTS
  .vtable  : { KEEP(*(.vtable)) } > RAM
  .text    : { KEEP(*(.entry)) *(.text*) *(.rodata*) . = ALIGN(8); } > RAM
  .data    : { __data_start__ = .; *(.data*) . = ALIGN(8); __data_end__ = .; } > RAM
  .bss (NOLOAD) : { . = ALIGN(8); __bss_start__ = .; *(.bss*) *(COMMON) . = ALIGN(8); __bss_end__ = .; } > RAM
  __stack_top = ORIGIN(RAM) + LENGTH(RAM);
  __stack_limit = __stack_top - STACK_SIZE;
  ASSERT(__bss_end__ <= __stack_limit, "image + bss overlaps the stack")
  /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) }
}
