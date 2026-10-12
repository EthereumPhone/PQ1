TITLE: Seed words stay in stack buffers after the 16x4 seed pages are drawn, and no executed test covers either display wipe (pixel-UI half already landed)
LABELS: enhancement,priority:medium,surface:trusted-ui,surface:runtime,source:frontier-research-2026-10
---
## Summary

The seed wizard copies seed words into plain byte arrays so it can draw them, and on the shipping 16x4 text display path those arrays are not wiped after the page is on the glass. The pixel UI (`ui-px`) twins of the same functions do wipe theirs, and since the research was written master also wipes the pixel band buffers after every frame. So the remaining work is on the 16x4 path (`ui-lcd` without `ui-px`, which is what a release image uses today), plus a test that actually runs for either wipe. This is defence in depth: it shortens how long seed material sits in secure RAM after the screen has moved on, against a later physical read of that RAM or a future secure-world memory bug. Non-secure code cannot read secure RAM, and no attack is shown here. No issue tracks it: the existing residue issues cover secure-element driver buffers only.

## What the code does today

Lines at master `c2fab970`.

Not wiped (16x4 path):

- `secure/src/ui/seed_wizard.rs:618`: `secret_rows_storage` holds up to three seed words as ASCII rows. `secure/src/ui/seed_wizard.rs:625`: `wb` holds one word. They are handed to the constant-time flush at `secure/src/ui/seed_wizard.rs:648` and the function returns with both still filled.
- `secure/src/ui/seed_wizard.rs:1061` and `secure/src/ui/seed_wizard.rs:1066`: the same two buffers in the restore candidate list.
- `secure/src/ui/lcd.rs:104`: `cell`, a 720-byte pixel scratch inside the display singleton. Every glyph is expanded into it at `secure/src/ui/lcd.rs:264` and streamed at `secure/src/ui/lcd.rs:277`. Nothing clears it. Today it ends up holding a blank glyph after a seed page, but only by layout: the secret pass draws all 16 columns (`secure/src/ui/lcd.rs:205`), words are at most 8 letters and start at column 2 or 3, so the last glyph drawn is always padding. Nothing enforces that.
- `secure/src/ui/lcd.rs:102`: `rows`, the 16x4 character grid, also in the singleton. The letter-entry screen writes the typed seed letters into it (`secure/src/ui/seed_wizard.rs:972`) and the PIN screen writes the live digit (`secure/src/ui/pin_entry.rs:210`). They stay there until a later screen overwrites the grid.

Already wiped:

- `secure/src/ui/seed_wizard.rs:111` and `secure/src/ui/seed_wizard.rs:1041`: the pixel twins zeroize their word cells after the paint.
- `secure/src/ui/px/lcd.rs:494` and `secure/src/ui/px/lcd.rs:710`: the pixel band buffers are zeroized on every exit from the frame function, through a drop guard. This is new on master since the research. The comment at `secure/src/ui/px/lcd.rs:676` explains why: an earlier review had judged the band residue safe "by layout accident" and the layout then changed.
- `secure/src/ui/px/lcd.rs:117`: the per-band digest table, which used to keep a hash of secret pixels after the frame, is deleted.

Tests:

- `secure/src/main.rs:286`: the `ui` module is compiled out of host tests (`#[cfg(not(test))]` on the line above), so a test written next to these buffers never runs.
- `secure/src/hw_io_under_test/pure_tests.rs:2210`: the only test near the pixel wipe checks that the source text contains the drop guard. It does not check that the guard calls the wipe, or that a buffer is zero afterwards.

Lock paths, for context:

- `secure/src/nsc/cmd_lock.rs:12` wipes the key material and `secure/src/nsc/cmd_lock.rs:13` paints "Locked". On the idle timeout the wipe runs from the 1 kHz timer interrupt, SysTick (`secure/src/main.rs:4414`), and the PIN prompt is then drawn from a low-priority handler (PendSV). Each of those repaints every text cell (16x4 path) or the whole frame (pixel path), and the bootloader clears the panel at every boot (`fsbl/src/render.rs:95`). So as long as the device stays on one display path, the cells that held a secret are overwritten. The research asked for an extra panel fill inside `zeroize_sensitive_state` (`secure/src/nsc/mod.rs:1750`); that function is reached from interrupt and fault context, where driving the display bus could collide with a paint in progress, so it is not proposed here.

## What is already tracked elsewhere

- #124 and #108 cover secret residue in the secure-element drivers. They do not mention display buffers.
- #858 covers routing the 16x4 letter row and PIN digit through the constant-time glyph path. It changes the same rows this issue wipes, so the two should land together.
- #784 covers the pixel-UI letter row. Its point about a digest of letter pixels outliving the frame no longer applies on master (the digest table is gone); its routing point still does.
- #848 covers erasing secure RAM on reset (the `SRAM_RST` option byte), which is what handles stack residue across a reset.

So this issue is only about wiping the 16x4 wizard buffers after paint, and about a test that executes.

## Proposed work

- [ ] Zeroize `secret_rows_storage` and `wb` in both functions after the flush, followed by the existing barrier (`secure/src/fi.rs:290`) so the compiler cannot drop the stores.
- [ ] Refill `cell` with the background colour at the end of `flush_with_secret_rows`, with a comment that the refill value must stay equal to the background.
- [ ] Clear the character grid when a screen that showed typed seed letters or a live PIN digit exits.
- [ ] Sweep `seed_wizard.rs` and `pin_entry.rs` for any other seed-derived or PIN-derived local that can leave scope without a wipe on some exit path (cancel, idle timeout, mismatch). Two are already known, both on the shipping restore path: `enter_mnemonic` returns on the idle timeout (`secure/src/ui/seed_wizard.rs:805`) without zeroizing `indices`, the word indices typed so far, although its two other exits do zeroize it (`secure/src/ui/seed_wizard.rs:811`, `secure/src/ui/seed_wizard.rs:815`); and the typed-letter buffer in `enter_single_word` (`secure/src/ui/seed_wizard.rs:851`) is never wiped.
- [ ] Pixel UI only: the full-panel clear at `secure/src/ui/px/lcd.rs:864` ("before the legacy glyph blitter paints again") has no caller. If the atlas stops verifying after a pixel frame was shown, the 16x4 fallback repaints only its glyph cells, so the previous pixel frame, which can be a seed page, would stay visible between them. Reasoned from the code, not run. Call the clear on that fallback.
- [ ] Put the wipe logic where a host test can reach it: a function in `pqsigner-ui-px` (or another workspace crate) for the band buffers, and a pure helper for the 16x4 rows. Assert "all zero after a frame that carried a secret run", with a negative control that fails when the wipe call is removed.
- [ ] Keep display traffic out of `zeroize_sensitive_state`. If a blank frame at lock is wanted on top of the existing repaints, add it at the thread-context call sites only.
- [ ] Owner question, not work: switch the backlight off at lock. It hides the panel content and does not erase it.

## What it needs

Firmware only. The host tests need no hardware. Seeing the result on glass needs a unit with a panel (#700).

## Limits

- Defence in depth. Reading secure RAM after a lock needs physical access to the chip or a separate secure-world bug.
- Source-level wipes do not reach copies the compiler makes (moves, register spills). Reset-time erase is #848.
- The panel keeps its last frame in its own memory until it is overwritten. The board has no read-back line to the panel, so that memory can only be read by tapping the panel connector.
- The research rated this P1 when the pixel band residue was still open. That part is done, so this issue is labelled medium.
- Nothing here was run on silicon or in emulation.

## Related

#124, #108, #858, #784, #848, #700.

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item D-07, section 2). Report priority P1 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>
