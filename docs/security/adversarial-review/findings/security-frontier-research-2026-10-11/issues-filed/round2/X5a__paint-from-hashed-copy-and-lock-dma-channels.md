TITLE: Pixel UI reads glyphs from non-secure flash between two hash checks of it: paint from the hashed copy, and make all DMA channels secure and locked at boot
LABELS: enhancement,priority:medium,surface:trusted-ui,surface:trustzone,surface:clear-signing,source:frontier-research-2026-10
---
## Summary

The pixel UI (`ui-px`) keeps its glyph atlas in non-secure (NS) flash. That placement is an owner decision and is not reopened here. The secure world hashes the atlas before a dialog and again after it, and refuses to sign if either hash is wrong. Between the two hashes, every frame of the dialog reads glyph rows straight from NS flash. If NS code could change a glyph page after the first hash and restore it before the second, both checks would pass and the user would have confirmed a screen whose digits were not the ones signed. This needs a hostile NS image, which is measured by the bootloader and vendor-signed, and nobody has shown the swap on silicon. The proposal is to close the ways NS could write during that window (in particular direct-memory-access, DMA, channels that NS code can program), and then to make "the bytes that were hashed are the bytes that are painted" true by construction. No issue tracks the atlas window. `ui-px` is outside the shipping feature set today, so this gates the pixel-UI port, not a release image.

## What the code does today

Lines at master `c2fab970`.

The read after the hash:

- `secure/src/ui/px/assets.rs:55`: `window()` returns a `'static` slice that points into NS flash (`secure/src/ui/px/assets.rs:64`).
- `secure/src/ui/px/assets.rs:131`: the atlas is hashed and compared with the pinned root. `secure/src/ui/px/assets.rs:135`: the atlas is then parsed from `window()` again, which is a second read of NS flash. The returned view borrows NS flash for the whole dialog.
- `secure/src/ui/px/lcd.rs:1458`: the dialog loop parses the font and marks once and then reads glyph data from that view on every frame.
- `secure/src/nsc/mod.rs:1106` (hash before), `secure/src/nsc/mod.rs:1118` (the dialog), `secure/src/nsc/mod.rs:1125` (hash after). Nothing between them restricts what NS can do.

Paints that have a check before and none after:

- `secure/src/ui/px/screens.rs:111` then `secure/src/ui/px/screens.rs:115`: every status screen, the seed pages and the PIN row (`secure/src/ui/pin_entry.rs:184`).
- `secure/src/ui/px/lcd.rs:847`: `paint_legacy`, which is where the 16x4 confirm pages land when `ui-px` is on.
- `secure/src/ui/px/lcd.rs:1011` (the ending of the signing film) and `secure/src/ui/px/lcd.rs:1109` (the busy screen).
- `secure/src/ui/px/assets.rs:178`: the in-between frames of the signing film use a view with no hash at all, by design.

Comments that overstate the check:

- `secure/src/ui/px/assets.rs:18`: says a glyph swap during the dialog "is caught before release". That holds only if the swap is still in place at the second hash.
- `secure/src/ui/px/assets.rs:20`: describes a "once-verified cached view" named `atlas`. That function no longer exists; `atlas_verified` at `secure/src/ui/px/assets.rs:158` re-hashes on every call.

DMA channels (GPDMA1 and LPDMA1 are the two general DMA controllers on this chip):

- `secure/src/hw/gpdma.rs:36` and `secure/src/hw/gpdma.rs:175`: channel 0 of GPDMA1 is the only channel ever marked secure, and `secure/src/hw/gpdma.rs:176` marks it privileged.
- `secure/src/hw/lcd_nv3007.rs:1110`: that setup runs only in `ui-px-dma` builds (the `cfg` is on the line above). In every other build, including today's shipping feature set, no DMA attribution register is written at all.
- A search of `secure/src`, `fsbl/src` and `nonsecure/src` for the configuration-lock register (`RCFGLOCKR`) finds nothing. The same search finds no use of LPDMA1 or DMA2D.
- The vendor's register description file for the part (`STM32U585.svd`) gives a reset value of `0x00000000` for `GPDMA_SECCFGR` and for `LPDMA_SECCFGR`, and places `GPDMA_RCFGLOCKR` at offset `0x08`. Read from that file, not from the reference manual: all channels start non-secure and unlocked.
- `nonsecure/src` contains no DMA use, so NS firmware loses nothing if the channels are taken away.
- `secure/src/hw/flash.rs:47`: programming and erasing NS flash is driven through the NS alias of the flash controller, which NS code can also reach. That is by design; it is the reason an NS image can rewrite its own pages.

Material for the fix:

- `secure/src/fw_update/verify.rs:120`: `hash_flash` already streams the region through a 256-byte buffer on the secure stack (`secure/src/fw_update/verify.rs:122`), which is the natural point to capture what is being hashed.
- `secure/src/ui/px/atlas_root.rs:14`: the container is 75,176 bytes. `secure/memory-stm32u585.x:31`: secure RAM is 192 K.

## What is already tracked elsewhere

- #846 has an open box on raising the secure base-priority mask in gateway handlers. That is the answer to an NS interrupt handler running while the dialog is parked, and it is not repeated here. Note for that work: the mask does nothing against a DMA transfer or a fault on the flash read.
- #53 asks for a silicon check that an NS DMA master cannot read secure RAM. That is the opposite direction (reading secure memory). This issue is about NS-controlled DMA channels existing at all.
- #792 and #261 cover the secure DMA blit driver. A channel lock has to be ordered after that driver's own channel setup.
- #760 records an earlier defect on this path (a cached verdict that was not re-checked), which is fixed.
- #374 is the secure stack bound. A RAM copy of the atlas cannot be sized without it.

So this issue is only about the hash-to-use window of the atlas and about DMA channel attribution.

## Proposed work

Close the write paths first (small):

- [ ] Read the reference manual sections for `GPDMA_SECCFGR`, `GPDMA_PRIVCFGR` and `GPDMA_RCFGLOCKR`, the LPDMA1 equivalents and DMA2D, and record what a locked channel can and cannot be changed to.
- [ ] At boot, in every build and not only `ui-px-dma`: mark all GPDMA1 and LPDMA1 channels secure and privileged, lock the configuration, read it back and fail closed on a mismatch. Order it after the blit channel's own setup. Decide DMA2D from the manual.
- [ ] Test, on the bench board, whether an NS DMA channel can drive a flash program sequence at all. This is a hypothesis from the research; nobody has checked it.

Then make the painted bytes the hashed bytes:

- [ ] Evaluate a whole-container copy first: copy the 75,176 bytes into a secure static buffer once, hash the copy, and parse and paint only from the copy. This keeps the `'static` lifetimes, covers every paint site including those with no second check, and removes the 75 KB re-hash on every text page. It needs a measured stack high-water mark under the double signature (#374), which does not exist yet.
- [ ] If the whole copy does not fit, capture a per-dialog subset during the hashing pass. That subset must include the chrome, the `Confirm?` beat, the film captions, all ten digits for the PIN row and all of a to z for the constant-time secret run, and the dialog must refuse if the cache overflows. This is the larger design.
- [ ] Keep the second hash after the dialog as a tamper detector.
- [ ] Correct the two comments in `assets.rs` listed above.
- [ ] Tests: a host test in a workspace crate that the painter never touches the source slice after capture (`secure/src/ui` is compiled out of host tests). A silicon test with a hostile NS fixture that rewrites and restores one glyph page during a held-open dialog, asserting that a hash of the glyph bytes actually blitted is unchanged.

## What it needs

Firmware only. The silicon test needs a board with a debug port. The open bench board has one and has no panel, which is fine if the test compares a hash of the blitted glyph bytes and not the glass.

## Limits

- The whole scenario presupposes a compromised NS image. Such an image has simpler ways to mislead a user, for example lying to the companion app.
- The swap itself is demanding: an 8 KB page erase and reprogram, twice, while the secure frame loop runs. It has not been attempted.
- "An NS DMA channel can write the flash control registers" is an unconfirmed hypothesis. Locking the channels is cheap enough to do without settling it.
- Secure RAM headroom is unmeasured, and the secure image with `ui-px` is already over its flash slot. The subset design adds code to that slot.
- A RAM copy does not help against a malicious secure image, and it does not replace the interrupt mask in #846.
- Nothing here was run on silicon.

## Related

#846, #53, #792, #261, #760, #374, #779, #700.

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item X5a, section 12). Report priority P2 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>
