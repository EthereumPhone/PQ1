/* harness v2: code fetched over the Cortex-M33 C-bus. SRAM1 is aliased in the code region at 0x0E000000
 * (secure; RM0456 Rev 7 memory map, "Cortex-M33 Fast C-bus ... to the internal SRAMs and flash memory
 * through ICACHE"). .text (code, rodata, literal pools) has its VMA in that alias and its LMA in the S-bus
 * alias 0x30000000 of the SAME physical SRAM1 bytes; OpenOCD load_image writes the LMA. Data, bss, stack and
 * the vector table stay on the S-bus alias. This mimics production (code over C-bus via ICACHE, data and
 * peripherals over S-bus) without writing flash. ICACHE stays at its reset state (disabled = bypass). */
MEMORY {
  RESULTS : ORIGIN = 0x30000000, LENGTH = 0x100
  RAM     : ORIGIN = 0x30000400, LENGTH = 0xC0000 - 0x400
}
STACK_SIZE = DEFINED(STACK_SIZE) ? STACK_SIZE : 0x20000;
ENTRY(_start)
SECTIONS {
  .results (NOLOAD) : { . = . + 0x100; } > RESULTS
  .vtable 0x30000400 : { KEEP(*(.vtable)) }
  .text 0x0E000C00 : AT(0x30000C00) { KEEP(*(.entry)) *(.text*) *(.rodata*) . = ALIGN(8); }
  __text_lma_end = 0x30000C00 + SIZEOF(.text);
  .data ALIGN(__text_lma_end, 8) : AT(ADDR(.data)) { __data_start__ = .; *(.data*) . = ALIGN(8); __data_end__ = .; }
  .bss (NOLOAD) : { . = ALIGN(8); __bss_start__ = .; *(.bss*) *(COMMON) . = ALIGN(8); __bss_end__ = .; }
  __stack_top = 0x300C0000;
  __stack_limit = __stack_top - STACK_SIZE;
  ASSERT(SIZEOF(.vtable) <= 0x800, "vector table overlaps .text")
  ASSERT(0x30000C00 + SIZEOF(.text) <= 0x30030000, "code must stay in SRAM1 (C-bus alias 0x0E000000..0x0E030000)")
  ASSERT(__bss_end__ <= __stack_limit, "image + bss overlaps the stack")
  /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) }
}
