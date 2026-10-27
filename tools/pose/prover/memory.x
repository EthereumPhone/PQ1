/* The prover owns bank-1 pages 0..PROVER_PAGES (secure alias, the
 * SECBOOTADD0 boot address). Keep LENGTH == PROVER_PAGES * 8K in
 * src/main.rs. Everything else in flash is the host's to fill. */
MEMORY
{
  FLASH : ORIGIN = 0x0C000000, LENGTH = 16K
  RAM   : ORIGIN = 0x30000000, LENGTH = 64K
}
