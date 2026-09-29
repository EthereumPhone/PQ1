/* Non-secure world linker script for real STM32U585 WITH the pixel-UI atlas
 * (`ui-px-atlas`): identical MEMORY to memory-stm32u585.x, plus the `.pq1a`
 * output section parked at a fixed slot-relative offset. The secure world
 * reads the container at `slot_base + 0x1000` (secure/src/ui/px/assets.rs
 * ATLAS_SLOT_OFFSET) and reserves 0x13000 for it (ATLAS_SPAN); keep the two
 * numbers in step with those constants. `.text` is pinned after the window
 * so the code never moves into it. Keeping the blob low in the image keeps
 * the NS image (and the FSBL's boot-time hash of it) compact. */

MEMORY
{
    /* Non-secure flash: bank 2 via NS alias */
    FLASH : ORIGIN = 0x08100000, LENGTH = 1024K

    /* Non-secure SRAM: SRAM2 via NS alias */
    RAM   : ORIGIN = 0x20030000, LENGTH = 64K
}

_stack_start = ORIGIN(RAM) + LENGTH(RAM);

/* Atlas window: [ORIGIN + 0x1000, ORIGIN + 0x14000). */
_pq1a_start = ORIGIN(FLASH) + 0x1000;
_pq1a_span  = 0x13000;
_stext      = _pq1a_start + _pq1a_span;

SECTIONS
{
  .pq1a _pq1a_start :
  {
    KEEP(*(.pq1a));
    . = ALIGN(4);
  } > FLASH
}
INSERT AFTER .vector_table;

ASSERT(SIZEOF(.vector_table) <= 0x1000, "NS vector table overlaps the pixel-UI atlas window");
ASSERT(SIZEOF(.pq1a) > 0, "ui-px-atlas: the .pq1a section is empty (nonsecure/src/ui_px_atlas.rs not linked?)");
ASSERT(SIZEOF(.pq1a) <= _pq1a_span, "ui-px-atlas: atlas.pq1a exceeds the reserved 0x13000 window");
