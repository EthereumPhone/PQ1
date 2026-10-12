COMMENT_ON: 237
---
**This issue still describes the SSD1306 OLED, which was removed on 2026-06-30. Proposed re-scope to the NV3007 panel, from the 2026-10-11 security frontier research (its item on secret-frame display hardening).** Lines are at master `c2fab970`.

What changed since this issue was written:

- The only display is the NV3007 SPI panel. It has no read-back line (`secure/src/board/pq1.rs:121`) and holds the frame in its own memory, so nothing re-sends a page continuously. On the 16x4 path each secret cell goes over the bus once per paint. On the pixel path the secret cells are added to every frame that the screen player paints (`secure/src/ui/px/lcd.rs:1148`), so the count there depends on whether the seed-page record animates (see Limits).
- The 16x4 path draws secret rows with a constant-time glyph fetch and writes every pixel of every cell. The pixel UI now streams every frame in full under one window and ignores the old "force" flag (`secure/src/ui/px/lcd.rs:468`), so which bands go on the wire no longer depends on content.
- The processor-side gaps on the entry screens are filed: #858 (16x4 letter row, live PIN digit, fixed start letter) and #784 with its comment (pixel letter row and live PIN digit).
- `tools/sca/README.md:1280` and `tools/sca/README.md:1385` still describe the SSD1306 and a file, `secure/src/ui/oled.rs`, that no longer exists.
- `docs/security/threat-model.md:323` (the side-channel section) still has no display row, which this issue already asks for.

What the research adds, in order:

1. **Measure before picking a mitigation.** Nothing is known about what the NV3007 leaks. The only measurement behind the constant-time glyph work is an emulated memory-address trace. The candidates in this issue's first box (dim mode, random pad pixels, one word at a time, scrambled reveal) were picked for an OLED whose current follows lit pixels; a backlit TFT is a different device. The research asks for a fixed-versus-random leakage capture on the real panel: near-field on the display bus and flex, and the panel supply rail, with a sweep of the receiver centre frequency. Needs an enclosed engineering-validation (EVT) unit with a panel, a near-field probe, an oscilloscope, and one opened unit for a shunt in the panel supply. The open bench board has no panel.
2. **A colour-pair encoding only if the measurement supports it.** If the capture shows a leak that follows the number of set bits on the bus, a secret foreground and background colour with equal bit weight and equal transitions can remove that first-order signal. It must be judged for contrast on glass, and it does not hide the bit pattern from a receiver that resolves individual bits, or from a logic tap. Kuhn's 2004 paper reports an equal-transition pair that became readable at another centre frequency ([paper](https://www.cl.cam.ac.uk/~mgk25/pet2004-fpd.pdf)). Do not build this before the capture.
3. **#260 rests on a precondition that failed.** It waits for the decoy-frame defence to validate, and #258 records that decoys were visible at every hold time at 20 MHz. Whether a constant lit-pixel count per row is worth doing should be decided from the capture in point 1. #258 itself should end with one re-test at 40 MHz or with the feature (`secure/Cargo.toml:568`) removed.
4. **Two ceremony choices for the owner, with no leakage claim attached.** One word per page (the 16x4 path shows 3 per page, `secure/src/ui/seed_wizard.rs:328`, and the pixel path 8, `secure/src/ui/seed_wizard.rs:79`), and a "never store your backup digitally" line before the words. The research records both on Trezor's Safe 5 and Safe 7, from its reading of the Trezor source; I did not re-check that. These change the setup ceremony, so they need a decision, as in #772.
5. **Mitigations the research examined and dropped,** so they are not re-proposed here: random glyph offsets and colour jitter (the font is public, a correlator removes them), a random delay before the page (a tap triggers on the bus itself), backlight dimming (by the research's reading of the backlight driver its current does not depend on content), shuffled band order (the order is sent in clear), and decoy frames as a default.

Suggested replacement for the checklist:

- [ ] Rewrite the title and first paragraph for the NV3007.
- [ ] Leakage capture on the NV3007 as in point 1, with the raw traces kept.
- [ ] Decide #260 and the colour pair from that capture. Close #258 with one 40 MHz re-test or by deleting the feature.
- [ ] Owner decision on one word per page and the never-digital line.
- [ ] Replace the SSD1306 text in `tools/sca/README.md`.
- [ ] Add the display row to the threat model (already here).

Limits. No encoding hides the frame from a logic-level tap on the display bus; that is a physical problem. Whether the pixel UI sends a seed page more than once per paint on master was not re-measured: at the research commit a host replay gave one frame per call, and the presenter has been reworked since. Nothing in this comment was measured.

<sub>**Provenance.** Security frontier research, 2026-10-11 (report item M03, section 2). Report priority P2 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>
