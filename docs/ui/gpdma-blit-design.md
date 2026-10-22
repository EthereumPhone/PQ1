# GPDMA for the pixel-UI blit — design notes and findings

Status: **researched, not implemented.** Everything below is established from
RM0456 / ES0499 / the datasheet and from reading the current driver. Written
down so the next attempt starts from facts rather than repeating the search.

Goal: overlap render and blit. Today a frame is serial — render then blit,
nine strips. Measured on the EVT panel 2026-10-05 at 40 MHz: render 11 ms,
blit 19 ms, period 31 ms against a 16 ms pacing target (`FRAME_PERIOD_MS`,
`ui/px/lcd.rs:47`). With the SPI stream on DMA the frame becomes
`max(render, blit)` instead of `render + blit`, i.e. ~20 ms — better, but NOT
under target. Note also that the 19 ms blit is a PARTIAL repaint: a full
428x142 frame at 40 MHz has a 24.31 ms wire floor, so DMA cannot take a full
repaint below that however well it overlaps. Only the render half can hide.

## What the hardware gives us

| fact | source |
|---|---|
| GPDMA1, 16 channels; LPDMA1, 4 | DS13086 §3 |
| `spi1_tx_dma` = **request 7** (`spi1_rx_dma` = 6) | RM0456 Table 137, p687 |

> **CORRECTED 2026-10-06.** This table said request **8**, which is
> `spi2_rx_dma`. Table 137 reads `6 spi1_rx_dma / 7 spi1_tx_dma / 8 spi2_rx_dma`.
> Two independent extractions caught it before any register was written; a
> `REQSEL` of 8 would have armed a channel that never fired, with no compile
> error and nothing on the glass. This is why the bit fields were extracted
> from the manual rather than recalled.
| GPDMA is TrustZone-aware: secure/non-secure **per channel**, plus a TrustZone-aware slave port protecting secure channels from NS access | RM0456 GPDMA §, "TrustZone support" |
| GPDMA is **not** TZSC-attributable — it is "self-governed" via its own per-channel `SECCFGR` | already documented in `secure/src/sau.rs:615-619` |
| DMA2D also exists on this part (AHB1 @160 MHz; corrected 2026-10-22, it is not on AHB2) — separate question, see below | DS13086 "Graphic features" |

Channel register map (`x` = channel, each `+ 0x80 * x`):

| offset | register |
|---|---|
| 0x50 | `CxLBAR` linked-list base address |
| 0x5C | `CxFCR` flag clear |
| 0x60 | `CxSR` status |
| 0x64 | `CxCR` control (EN, RESET, SUSP, TCIE…) |
| 0x90 | `CxTR1` transfer 1 (source/dest width, increment, burst) |
| 0x94 | `CxTR2` transfer 2 (REQSEL, SWREQ, trigger) |
| 0x98 | `CxBR1` block register 1 (BNDT = byte count) |
| 0x9C | `CxSAR` source address |
| 0xA0 | `CxDAR` destination address |

Global registers at 0x00/0x04/0x08/0x0C/0x10 include `SECCFGR` and `PRIVCFGR`.

**Errata: clear.** ES0499 has no GPDMA erratum affecting SRAM -> peripheral
transfers. The DMA entries that exist concern PSRAM byte bursts, OCTOSPI 32-bit
reads, and masters reading Flash during low-power entry — none apply (our source
is a BSS strip buffer in SRAM, our destination is `SPI1->TXDR`).

## The obstacle nobody had hit yet

`ui/px/lcd.rs::blit_strip` does **not** stream a buffer. It calls
`lcd_nv3007::write_pixels_with(n, closure)` and the closure **transposes on the
fly**: the panel is mounted rotated, so native rows are landscape x. DMA needs a
contiguous source, so the transpose has to happen somewhere first.

Two options, and the obvious one is wrong:

- **MADCTL (0x36) — do NOT use.** The panel could in principle do the rotation
  itself. But MADCTL is never issued today (`run_init_sequence` sets COLMOD
  0x3A, not 0x36; the `0x36` hits in that file are data bytes for other
  registers), it is **global panel state** that the 16x4 renderers
  (`measured_boot`, `pin_entry`) also depend on, and the NV3007 datasheet is not
  in this repo, so MV-bit behaviour is unverified. Changing global orientation to
  speed up one path risks every other path.
- **Transpose in software into a second strip buffer.** ~13.7 KB more BSS (the
  existing strip buffer is 13,696 B). This is RAM, not flash — we are 14,432 B
  over on *flash*, and secure SRAM is 192 KB, so it is affordable. Double-buffer:
  DMA strip k while rendering strip k+1.

## Things that will bite

1. **Byte order.** `write_pixels_with` sends the high byte then the low byte.
   A DMA of little-endian `u16` at 8-bit DSIZE reverses them. Swap during the
   transpose pass (free, it is already touching every pixel) or use 16-bit
   frames for RAMWR only.
2. **Keep the per-strip digest skip and `force`.** Secret frames must stream
   every strip so SPI timing cannot reveal which strips changed — that is the
   F-24 stage-E property. A DMA path that "optimises" by skipping unchanged
   strips on a secret frame breaks it.
3. **SPI side.** `CFG1.TXDMAEN` enables TX DMA requests. The existing
   `spi_begin`/`spi_end` framing (SPE/TSIZE/CSTART, then EOT + the ES0499
   16-cycle delay before dropping SPE) must be preserved — that delay exists
   because of a real erratum we already hit once.
4. **Security.** Set the channel secure in GPDMA `SECCFGR` (and privileged in
   `PRIVCFGR`). No GTZC/TZSC change is possible or needed — see `sau.rs`.
   **UPDATE 2026-10-18 (#982):** secure boot now claims and LOCKS all 16
   channels (`sau::stm32::secure_dma_masters`) before NS runs, because a
   non-secure channel could read the OTP and UID. `hw::gpdma::init`'s own
   `SECCFGR`/`PRIVCFGR` writes are therefore no-ops on se050 builds and only
   matter on non-se050 builds whose `ui::init` runs before SAU. The blit is
   unaffected: it is secure code driving a secure channel.
5. **The overlay changes meaning.** Once the blit is asynchronous, the `blit`
   field of `<render>/<blit>/<period>` measures *wait* time, not work. Only
   `period` stays comparable across builds. Say so wherever numbers are quoted.

## Open question worth checking before coding

RM0456 describes 2D-addressing channels with burst/block address offsets
(`CxTR3`, `CxBR2`). If a strided source read is expressible there, the DMA could
do the transpose itself and the second buffer disappears. Worth ten minutes;
not worth a long detour.

## After it lands

Re-run `bench-z` vs `bench-s`. If the render now hides behind the blit, then
`ui-px` at `opt-level = "z"` is free again and the 5,728 B rejected on
2026-10-05 can be retaken — that decision was made on a serial frame.

## Not this, separately: DMA2D

Chrom-ART can do fills and **4-bit alpha** glyph blends — our atlas is 4-bit, so
font compositing is exactly its use case. It has no geometry engine, so discs,
rings, capsules and chevrons stay on the CPU. Whether it is worth a driver
depends on how the 11 ms render splits between shapes and glyphs, which is
unmeasured.

**Hard constraint:** `Item::Secret` / `font::blit_secret_run` must NEVER route
through DMA2D. Its source address would be the glyph of a secret seed letter —
a secret-dependent access performed by a bus master, which is precisely what the
constant-time cell path exists to prevent, and which `make checkct` does not
cover (its drivers are kdf/fors/th/saes/ct_eq only).

**UPDATE 2026-10-22 — measured; not worth a driver for the busy film.** On the
EVT screen unit, one real sign with the dev recorder (`ui-px-film-gaps`) and the
DMA2D bench (`ui-px-dma2d-bench`, `secure/src/ui/px/dma2d_bench.rs`; see
`pixel-ui-pilot.md` § Busy-film measurement):

- A signing-film frame rendered 4.7 ms, of which **shapes 4.3 ms** (the orbit
  is 12 anti-aliased discs of r = 13 px) and glyphs 0.1 ms. DMA2D could take
  the glyphs and the band clear, ~0.2 ms of the frame.
- One 48-column band: A4 blend 812 us on the CPU against 69 us on DMA2D
  (~12x). DMA2D's blend differs from `blend_over` by up to 2/255 per channel
  on most blended pixels, so any golden-covered screen drawn through it needs
  a re-bless. A4 sources must have an even line length and offset and are low
  nibble first (RM0456 Table 159 and the CEIF rules): our atlas is high nibble
  first and not pre-rotated, so glyphs would need a re-bake.
- Register-to-memory fill reports completion (TCIF, no error flag) yet leaves
  the buffer untouched, as the first transfer after the clock enable and
  after blends alike; the disassembly shows real loads and stores, and
  neither RM0456 nor ES0499 explains it. Unresolved.
- The CPU work went to pixel-identical rasteriser fixes instead (band clamp
  for disc/ring rows, row-by-row disc runs skipping what a later disc covers,
  seeded rim roots: shapes 4.3 -> 3.3 ms per frame).
- The one route where DMA2D would pay: pre-rendered disc sprites (the orbit's
  radius is constant) blitted by DMA2D, a redesign of the film's drawing with
  a golden re-bless.
- Besides `Item::Secret`, the dialed PIN digit and the typed seed letters
  (`status_map::pin_row` / `letter_row`, drawn as ordinary text) must stay
  off DMA2D too: its source address would be their glyph (#784).
